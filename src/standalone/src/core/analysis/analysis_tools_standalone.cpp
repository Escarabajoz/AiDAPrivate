
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>

#include "standalone_compat.hpp"
#include "../disasm/ghidra_decompiler.hpp"
#include "../disasm/zydis_disasm.hpp"
#include "benchmark/benchmark_runner.hpp"
#include "benchmark/benchmark_scorecard.hpp"
#include "crypto_scanner.hpp"
#include "aob_generator.hpp"
#include "struct_recon_engine.hpp"
#include "fuzzer_engine.hpp"
#include "decrypt_oracle.hpp"
#include "integrity_hunter.hpp"
#include "struct_monitor.hpp"
#include "symbolic_engine.hpp"
#include "deobfuscation_engine.hpp"
#include "stealth_engine.hpp"
#include "pe_parser.hpp"
#include "symbol_store.hpp"
#include "xref_db.hpp"
#include "binary_map.hpp"
#include "workspace/analysis_workspace.hpp"
#include "workspace/search_index.hpp"
#include "standalone_driver.hpp"
#include "../debugger/page_guard_engine.hpp"
#include "../disasm/function_index.hpp"
#include "../helpers/globals.h"
#include "../../helpers/diag_log.hpp"
#include "../mcp/downstream_producer_governor.hpp"

#include <algorithm>
#include <atomic>
#include <charconv>
#include <cctype>
#include <cinttypes>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <sstream>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <vector>
#include <chrono>

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

namespace analysis_tools {

static bool parse_hex_u64(std::string_view text, uint64_t& value)
{
	if (text.empty())
		return false;
	if (text.size() >= 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X'))
		text.remove_prefix(2);
	if (text.empty())
		return false;
	const auto* first = text.data();
	const auto* last = first + text.size();
	const auto parsed = std::from_chars(first, last, value, 16);
	return parsed.ec == std::errc{} && parsed.ptr == last;
}

struct toolhelp_handle_closer_t {
	void operator()(void* value) const noexcept
	{
		if (value)
			CloseHandle(static_cast<HANDLE>(value));
	}
};

using unique_toolhelp_handle_t = std::unique_ptr<void, toolhelp_handle_closer_t>;

static size_t bounded_size_param(const json& params, const char* name, size_t fallback, size_t minimum, size_t maximum)
{
	size_t value = fallback;
	auto it = params.find(name);
	if (it != params.end()) {
		if (it->is_number_unsigned()) {
			value = it->get<size_t>();
		} else if (it->is_number_integer()) {
			int64_t signed_value = it->get<int64_t>();
			if (signed_value >= 0)
				value = static_cast<size_t>(signed_value);
		}
	}
	if (value < minimum)
		return minimum;
	if (value > maximum)
		return maximum;
	return value;
}

static uint32_t bounded_u32_param(const json& params, const char* name, uint32_t fallback, uint32_t minimum, uint32_t maximum)
{
	uint32_t value = fallback;
	auto it = params.find(name);
	if (it != params.end()) {
		if (it->is_number_unsigned()) {
			uint64_t unsigned_value = it->get<uint64_t>();
			value = unsigned_value > maximum ? maximum : static_cast<uint32_t>(unsigned_value);
		} else if (it->is_number_integer()) {
			int64_t signed_value = it->get<int64_t>();
			if (signed_value >= 0)
				value = signed_value > static_cast<int64_t>(maximum) ? maximum : static_cast<uint32_t>(signed_value);
		}
	}
	if (value < minimum)
		return minimum;
	if (value > maximum)
		return maximum;
	return value;
}

static std::string lower_ascii(std::string value)
{
	std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
		return static_cast<char>(std::tolower(c));
	});
	return value;
}

static std::string analysis_hex_u64(uint64_t value)
{
	char buf[32] = {};
	_snprintf_s(buf, sizeof(buf), _TRUNCATE, "0x%llX", static_cast<unsigned long long>(value));
	return std::string(buf);
}

static bool mcp_call_deadline_expired() noexcept
{
	const std::uint64_t deadline = mcp_standalone::current_call_deadline_ms();
	return deadline != 0 && static_cast<std::uint64_t>(GetTickCount64()) >= deadline;
}

static bool mcp_call_interrupted() noexcept
{
	return mcp_standalone::current_call_cancelled() || mcp_call_deadline_expired();
}

static tool_result_t mcp_call_interrupted_result(const char* operation)
{
	const bool deadline = mcp_call_deadline_expired();
	return tool_result_t::error(
		std::string(operation) + (deadline ? " deadline expired" : " cancelled"),
		deadline ? "DEADLINE_EXCEEDED" : "CANCELLED",
		json{{"disposition", "cancel_requested"}});
}

static json page_guard_install_failure_json()
{
	const auto f = page_guard_engine::g_pg_engine.last_install_failure();
	json result;
	result["reason"] = f.reason;
	result["detail"] = f.detail;
	result["driver_status"] = f.driver_status;
	result["driver_last_error"] = f.driver_last_error;
	result["remote_call_driver_status"] = f.remote_call_driver_status;
	result["remote_call_driver_last_error"] = f.remote_call_driver_last_error;
	result["pid"] = f.pid;
	result["active_pid"] = f.active_pid;
	result["win32_error"] = f.win32_error;
	result["requested_addr"] = analysis_hex_u64(f.requested_addr);
	result["requested_size"] = f.requested_size;
	result["guard_addr"] = analysis_hex_u64(f.guard_addr);
	result["guard_size"] = f.guard_size;
	result["region_base"] = analysis_hex_u64(f.region_base);
	result["region_size"] = f.region_size;
	result["region_state"] = f.region_state;
	result["region_protect"] = f.region_protect;
	result["region_type"] = f.region_type;
	result["attempted_protect"] = f.attempted_protect;
	result["original_protect"] = f.original_protect;
	result["proposed_protect"] = f.proposed_protect;
	result["ring_addr"] = analysis_hex_u64(f.ring_addr);
	result["shellcode_addr"] = analysis_hex_u64(f.shellcode_addr);
	result["context_addr"] = analysis_hex_u64(f.context_addr);
	result["ntdll_base"] = analysis_hex_u64(f.ntdll_base);
	result["ntdll_size"] = f.ntdll_size;
	result["rtl_add_veh"] = analysis_hex_u64(f.rtl_add_veh);
	result["rtl_remove_veh"] = analysis_hex_u64(f.rtl_remove_veh);
	result["veh_result"] = analysis_hex_u64(f.veh_result);
	result["cleanup_shellcode_ok"] = f.cleanup_shellcode_ok != 0;
	result["cleanup_ring_ok"] = f.cleanup_ring_ok != 0;
	result["install_elapsed_ms"] = f.install_elapsed_ms;
	result["install_generation"] = f.install_generation;
	result["current_generation"] = f.current_generation;
	result["mitigation_open_ok"] = f.mitigation_open_ok != 0;
	result["mitigation_open_error"] = f.mitigation_open_error;
	result["mitigation_dynamic_ok"] = f.mitigation_dynamic_ok != 0;
	result["mitigation_dynamic_error"] = f.mitigation_dynamic_error;
	result["mitigation_dynamic_flags"] = f.mitigation_dynamic_flags;
	result["mitigation_cfg_ok"] = f.mitigation_cfg_ok != 0;
	result["mitigation_cfg_error"] = f.mitigation_cfg_error;
	result["mitigation_cfg_flags"] = f.mitigation_cfg_flags;
	result["remote_call"] = json{
		{"id", f.remote_call_id},
		{"function", analysis_hex_u64(f.remote_call_function)},
		{"result", analysis_hex_u64(f.remote_call_result)},
		{"gle", f.remote_call_gle},
		{"active_pid_entry", f.remote_call_active_pid_entry},
		{"active_pid_after", f.remote_call_active_pid_after},
		{"timeout_ms", f.remote_call_timeout_ms},
		{"deadline_ms", f.remote_call_deadline_ms},
		{"deadline_remaining_ms", f.remote_call_deadline_remaining_ms},
		{"elapsed_ms", f.remote_call_elapsed_ms},
		{"completed", f.remote_call_completed != 0},
		{"ok", f.remote_call_ok != 0},
		{"cancelled_before", f.remote_call_cancelled_before != 0},
		{"cancelled_after", f.remote_call_cancelled_after != 0},
		{"deadline_expired_before", f.remote_call_deadline_expired_before != 0},
		{"deadline_expired_after", f.remote_call_deadline_expired_after != 0},
		{"stale_pid", f.remote_call_stale_pid != 0},
		{"late_completion", f.remote_call_late_completion != 0}
	};
	result["remote_call_id"] = f.remote_call_id;
	result["remote_call_gle"] = f.remote_call_gle;
	result["remote_call_stale_pid"] = f.remote_call_stale_pid != 0;
	result["remote_call_deadline_expired_after"] = f.remote_call_deadline_expired_after != 0;
	result["remote_call_cancelled_after"] = f.remote_call_cancelled_after != 0;
	result["remote_call_late_completion"] = f.remote_call_late_completion != 0;
	return result;
}

static const driver_bridge::module_info_t* select_module_by_name(const std::vector<driver_bridge::module_info_t>& modules, const std::string& requested)
{
	if (modules.empty())
		return nullptr;
	if (requested.empty())
		return &modules.front();
	const std::string want = lower_ascii(requested);
	for (const auto& mod : modules) {
		if (lower_ascii(mod.name) == want)
			return &mod;
	}
	for (const auto& mod : modules) {
		const std::string path = lower_ascii(mod.path);
		if (path.size() >= want.size() && path.compare(path.size() - want.size(), want.size(), want) == 0)
			return &mod;
	}
	for (const auto& mod : modules) {
		if (lower_ascii(mod.name).find(want) != std::string::npos || lower_ascii(mod.path).find(want) != std::string::npos)
			return &mod;
	}
	return nullptr;
}

static std::string wide_to_utf8_lossy(const wchar_t* text)
{
	if (!text || !*text)
		return {};
	const int len = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
	if (len <= 1)
		return {};
	std::string out(static_cast<size_t>(len), '\0');
	const int written = WideCharToMultiByte(CP_UTF8, 0, text, -1, out.data(), len, nullptr, nullptr);
	if (written <= 1)
		return {};
	out.resize(static_cast<size_t>(written - 1));
	return out;
}

static std::vector<driver_bridge::module_info_t> enumerate_modules_toolhelp(uint32_t pid)
{
	std::vector<driver_bridge::module_info_t> result;
	if (pid == 0)
		return result;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (snapshot == INVALID_HANDLE_VALUE)
		return result;
	unique_toolhelp_handle_t snapshot_guard(snapshot);
	MODULEENTRY32W me{};
	me.dwSize = sizeof(me);
	if (Module32FirstW(snapshot, &me)) {
		do {
			driver_bridge::module_info_t mod;
			mod.base = reinterpret_cast<uint64_t>(me.modBaseAddr);
			mod.size = me.modBaseSize;
			mod.name = wide_to_utf8_lossy(me.szModule);
			mod.path = wide_to_utf8_lossy(me.szExePath);
			result.push_back(std::move(mod));
			me.dwSize = sizeof(me);
		} while (Module32NextW(snapshot, &me));
	}
	std::sort(result.begin(), result.end(), [](const auto& a, const auto& b) {
		return a.base < b.base;
	});
	return result;
}

static tool_result_t fuzzer_manage_start(const json& params)
{
	const uint64_t handler_start_ms = GetTickCount64();
	std::string target = params.value("target_address", "");
	std::string end = params.value("end_address", "");
	std::string input = params.value("input_address", "");
	diag::log_tagged_fmt("analysis", "fuzzer_manage start tick=%llu target=%s end=%s input=%s",
		static_cast<unsigned long long>(handler_start_ms),
		target.c_str(), end.c_str(), input.c_str());
	if (target.empty())
		return tool_result_t::error("target_address is required");

	fuzzer_engine::fuzz_config_t cfg;
	if (!parse_hex_u64(target, cfg.target_address))
		return tool_result_t::error("invalid target_address");
	if (cfg.target_address == 0)
		return tool_result_t::error("invalid target_address");
	if (!end.empty()) {
		if (!parse_hex_u64(end, cfg.end_address))
			return tool_result_t::error("invalid end_address");
		if (cfg.end_address <= cfg.target_address)
			return tool_result_t::error("end_address must be greater than target_address");
	} else {
		if (cfg.target_address == UINT64_MAX)
			return tool_result_t::error("target_address cannot be the maximum 64-bit address without end_address");
		cfg.end_address = cfg.target_address + 1;
	}
	if (!input.empty()) {
		if (!parse_hex_u64(input, cfg.input_address))
			return tool_result_t::error("invalid input_address");
	}
	cfg.input_size = static_cast<int>(bounded_u32_param(params, "input_size", 256, 1, 1024 * 1024));
	cfg.max_iterations = bounded_u32_param(params, "max_iterations", 10000, 1, 1000000);
	cfg.pid = driver_bridge::attached_pid();
	auto threads_snap = driver_bridge::enumerate_threads();
	cfg.tid = threads_snap.empty() ? 0 : threads_snap.front().tid;
	if (cfg.pid == 0 || cfg.tid == 0)
		return tool_result_t::error("fuzzer requires an attached process and at least one thread for snapshotting");

	{
		std::lock_guard<std::mutex> lk(fuzzer_engine::g_state.mutex);
		fuzzer_engine::g_state.config = cfg;
	}
	if (!fuzzer_engine::start_fuzzing())
		return tool_result_t::error("fuzzer is already running or worker queue is unavailable");

	char end_buf[32];
	char input_buf[32];
	std::snprintf(end_buf, sizeof(end_buf), "0x%llX", static_cast<unsigned long long>(cfg.end_address));
	std::snprintf(input_buf, sizeof(input_buf), "0x%llX", static_cast<unsigned long long>(cfg.input_address));
	json result;
	result["status"] = "started";
	result["worker_posted"] = true;
	result["pid"] = cfg.pid;
	result["tid"] = cfg.tid;
	result["thread_count"] = threads_snap.size();
	result["target_address"] = target;
	result["end_address"] = end_buf;
	result["input_address"] = input_buf;
	result["input_size"] = cfg.input_size;
	result["max_iterations"] = cfg.max_iterations;
	result["setup_complete"] = fuzzer_engine::g_state.setup_complete.load();
	result["setup_success"] = fuzzer_engine::g_state.setup_success.load();
	result["handler_start_tick_ms"] = handler_start_ms;
	result["handler_end_tick_ms"] = GetTickCount64();
	diag::log_tagged_fmt("analysis",
		"fuzzer_manage start_done start_tick=%llu end_tick=%llu pid=%u tid=%u max_iterations=%u setup_complete=%d setup_success=%d",
		static_cast<unsigned long long>(handler_start_ms),
		static_cast<unsigned long long>(GetTickCount64()),
		static_cast<unsigned>(cfg.pid),
		static_cast<unsigned>(cfg.tid),
		static_cast<unsigned>(cfg.max_iterations),
		fuzzer_engine::g_state.setup_complete.load() ? 1 : 0,
		fuzzer_engine::g_state.setup_success.load() ? 1 : 0);
	return tool_result_t::ok(result);
}

static uint64_t fuzzer_computed_eps(uint64_t total_executions, double elapsed_seconds)
{
	if (total_executions == 0 || elapsed_seconds <= 0.0)
		return 0;
	uint64_t computed = static_cast<uint64_t>(static_cast<double>(total_executions) / elapsed_seconds);
	return computed == 0 ? 1 : computed;
}

static uint64_t fuzzer_effective_eps(uint64_t total_executions, double elapsed_seconds, uint64_t stored_eps)
{
	return stored_eps != 0 ? stored_eps : fuzzer_computed_eps(total_executions, elapsed_seconds);
}

static std::string fuzzer_exit_reason(bool running, bool worker_active, bool cancel_requested, bool setup_success, const std::string& setup_error, uint64_t total_executions, uint32_t max_iterations)
{
	if (running || worker_active)
		return "worker_active";
	if (!setup_error.empty())
		return "setup_or_worker_error";
	if (cancel_requested)
		return "stop_requested";
	if (setup_success && max_iterations != 0 && total_executions >= max_iterations)
		return "max_iterations_reached";
	if (setup_success && total_executions != 0)
		return "completed";
	return "idle";
}

static tool_result_t fuzzer_manage_stop(const json&)
{
	const uint64_t start_tick = GetTickCount64();
	const bool running_before = fuzzer_engine::g_state.running.load();
	const bool worker_before = fuzzer_engine::g_state.worker_active.load();
	diag::log_tagged_fmt("analysis", "fuzzer_manage stop_start tick=%llu running=%d worker_active=%d cancel=%d",
		static_cast<unsigned long long>(start_tick),
		running_before ? 1 : 0,
		worker_before ? 1 : 0,
		fuzzer_engine::g_state.cancel.load() ? 1 : 0);
	fuzzer_engine::stop_fuzzing();
	const uint64_t end_tick = GetTickCount64();
	std::lock_guard<std::mutex> lk(fuzzer_engine::g_state.mutex);
	auto& stats = fuzzer_engine::g_state.stats;
	const uint64_t computed_eps = fuzzer_computed_eps(stats.total_executions, stats.elapsed_seconds);
	const uint64_t effective_eps = fuzzer_effective_eps(stats.total_executions, stats.elapsed_seconds, stats.executions_per_second);
	const bool running_after = fuzzer_engine::g_state.running.load();
	const bool worker_after = fuzzer_engine::g_state.worker_active.load();
	const std::string reason = fuzzer_exit_reason(running_after, worker_after, fuzzer_engine::g_state.cancel.load(),
		fuzzer_engine::g_state.setup_success.load(), fuzzer_engine::g_state.setup_error,
		stats.total_executions, fuzzer_engine::g_state.config.max_iterations);
	json result;
	result["status"] = "stop_requested";
	result["handler_start_tick_ms"] = start_tick;
	result["handler_end_tick_ms"] = end_tick;
	result["running_before"] = running_before;
	result["worker_active_before"] = worker_before;
	result["running"] = running_after;
	result["worker_active"] = worker_after;
	result["cancel_requested"] = fuzzer_engine::g_state.cancel.load();
	result["total_executions"] = stats.total_executions;
	result["stored_executions_per_second"] = stats.executions_per_second;
	result["computed_executions_per_second"] = computed_eps;
	result["executions_per_second"] = effective_eps;
	result["elapsed_seconds"] = stats.elapsed_seconds;
	result["total_crashes"] = stats.total_crashes;
	result["unique_crashes"] = stats.total_unique_crashes;
	result["setup_complete"] = fuzzer_engine::g_state.setup_complete.load();
	result["setup_success"] = fuzzer_engine::g_state.setup_success.load();
	result["setup_error"] = fuzzer_engine::g_state.setup_error;
	result["worker_exit_reason"] = reason;
	diag::log_tagged_fmt("analysis",
		"fuzzer_manage stop_done start_tick=%llu end_tick=%llu running_before=%d worker_before=%d running_after=%d worker_after=%d total_exec=%llu stored_eps=%llu computed_eps=%llu effective_eps=%llu elapsed_s=%.3f worker_exit_reason=%s",
		static_cast<unsigned long long>(start_tick),
		static_cast<unsigned long long>(end_tick),
		running_before ? 1 : 0,
		worker_before ? 1 : 0,
		running_after ? 1 : 0,
		worker_after ? 1 : 0,
		static_cast<unsigned long long>(stats.total_executions),
		static_cast<unsigned long long>(stats.executions_per_second),
		static_cast<unsigned long long>(computed_eps),
		static_cast<unsigned long long>(effective_eps),
		stats.elapsed_seconds,
		reason.c_str());
	return tool_result_t::ok("Fuzzer stop requested.", result);
}

static tool_result_t fuzzer_manage_results(const json&)
{
	const uint64_t start_tick = GetTickCount64();
	diag::log_tagged_fmt("analysis", "fuzzer_manage results_start tick=%llu", static_cast<unsigned long long>(start_tick));
	std::lock_guard<std::mutex> lk(fuzzer_engine::g_state.mutex);
	auto& stats = fuzzer_engine::g_state.stats;
	const uint64_t computed_eps = fuzzer_computed_eps(stats.total_executions, stats.elapsed_seconds);
	const uint64_t effective_eps = fuzzer_effective_eps(stats.total_executions, stats.elapsed_seconds, stats.executions_per_second);
	const bool running = fuzzer_engine::g_state.running.load();
	const bool worker_active = fuzzer_engine::g_state.worker_active.load();
	const std::string reason = fuzzer_exit_reason(running, worker_active, fuzzer_engine::g_state.cancel.load(),
		fuzzer_engine::g_state.setup_success.load(), fuzzer_engine::g_state.setup_error,
		stats.total_executions, fuzzer_engine::g_state.config.max_iterations);
	json result;
	result["running"] = running;
	result["total_executions"] = stats.total_executions;
	result["executions_per_second"] = effective_eps;
	result["stored_executions_per_second"] = stats.executions_per_second;
	result["computed_executions_per_second"] = computed_eps;
	result["total_crashes"] = stats.total_crashes;
	result["unique_crashes"] = stats.total_unique_crashes;
	result["edge_coverage"] = stats.edge_coverage;
	result["new_coverage_finds"] = stats.new_coverage_finds;
	result["corpus_size"] = stats.corpus_size;
	result["elapsed_seconds"] = stats.elapsed_seconds;
	result["setup_error"] = fuzzer_engine::g_state.setup_error;
	result["worker_active"] = worker_active;
	result["cancel_requested"] = fuzzer_engine::g_state.cancel.load();
	result["setup_complete"] = fuzzer_engine::g_state.setup_complete.load();
	result["setup_success"] = fuzzer_engine::g_state.setup_success.load();
	result["worker_exit_reason"] = reason;
	result["handler_start_tick_ms"] = start_tick;
	result["handler_end_tick_ms"] = GetTickCount64();
	json crashes_arr = json::array();
	for (auto& c : fuzzer_engine::g_state.unique_crashes) {
		json cobj;
		cobj["type"] = fuzzer_engine::crash_type_name(c.type);
		char abuf[32];
		std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(c.instruction_address));
		cobj["instruction_address"] = abuf;
		cobj["description"] = c.description;
		crashes_arr.push_back(cobj);
	}
	result["crashes"] = crashes_arr;
	diag::log_tagged_fmt("analysis",
		"fuzzer_manage results_done start_tick=%llu end_tick=%llu running=%d worker_active=%d total_exec=%llu stored_eps=%llu computed_eps=%llu effective_eps=%llu elapsed_s=%.3f crashes=%llu unique=%llu worker_exit_reason=%s",
		static_cast<unsigned long long>(start_tick),
		static_cast<unsigned long long>(GetTickCount64()),
		running ? 1 : 0,
		worker_active ? 1 : 0,
		static_cast<unsigned long long>(stats.total_executions),
		static_cast<unsigned long long>(stats.executions_per_second),
		static_cast<unsigned long long>(computed_eps),
		static_cast<unsigned long long>(effective_eps),
		stats.elapsed_seconds,
		static_cast<unsigned long long>(stats.total_crashes),
		static_cast<unsigned long long>(stats.total_unique_crashes),
		reason.c_str());
	return tool_result_t::ok(result);
}

static tool_result_t live_monitor_manage_start(const json& params)
{
	std::string addr_str = params.value("address", "");
	const int size = static_cast<int>(bounded_size_param(params, "size", 256, 1, 1024 * 1024));
	std::string name = params.value("name", "struct_t");
	std::string backend = params.value("backend", "auto");
	uint32_t timeout_ms = bounded_u32_param(params, "timeout_ms", 3000, 100, 3500);
	diag::log_tagged_fmt("analysis", "live_monitor_manage start addr=%s size=%d backend=%s",
		addr_str.c_str(), size, backend.c_str());
	if (addr_str.empty())
		return tool_result_t::error("address parameter is required");
	uint64_t addr = 0;
	if (!parse_hex_u64(addr_str, addr))
		return tool_result_t::error("invalid address");
	if (addr == 0)
		return tool_result_t::error("invalid address");
	if (struct_monitor::g_state.active.load())
		return tool_result_t::error("Live monitor already active. Stop it first.");
	struct_monitor::start(addr, size, name, backend);
	int max_wait = static_cast<int>((timeout_ms + 49) / 50);
	for (int wait = 0; wait < max_wait; ++wait) {
		if (mcp_call_interrupted()) {
			struct_monitor::stop();
			for (int stop_wait = 0; stop_wait < 10 && struct_monitor::g_state.active.load(); ++stop_wait)
				Sleep(50);
			return mcp_call_interrupted_result("Live monitor startup");
		}
		if (!struct_monitor::g_state.active.load())
			break;
		if (struct_monitor::g_state.session.using_page_guard ||
		    struct_monitor::g_state.session.using_hwbp ||
		    struct_monitor::g_state.session.using_polling)
			break;
		Sleep(50);
	}

	bool active = struct_monitor::g_state.active.load();
	bool page_guard = struct_monitor::g_state.session.using_page_guard;
	bool hwbp = struct_monitor::g_state.session.using_hwbp;
	bool polling = struct_monitor::g_state.session.using_polling;
	char abuf[32];
	std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(addr));
	json result;
	result["address"] = abuf;
	result["size"] = size;
	result["active"] = active;
	result["backend"] = page_guard ? "page_guard" : (hwbp ? "hardware_breakpoint" : (polling ? "polling" : "none"));
	result["page_guard"] = page_guard;
	result["hardware_breakpoint"] = hwbp;
	result["polling"] = polling;
	result["total_captures"] = struct_monitor::g_state.total_captures.load();
	result["positive_capture_count"] = struct_monitor::g_state.total_captures.load();
	result["stimulus_required"] = true;
	result["pre_stimulus"] = struct_monitor::g_state.total_captures.load() == 0;
	result["ready_for_stimulus"] = active && (page_guard || hwbp || polling);
	if (!active || (!page_guard && !hwbp && !polling)) {
		struct_monitor::stop();
		for (int wait = 0; wait < 10 && struct_monitor::g_state.active.load(); ++wait)
			Sleep(50);
		return tool_result_t::error("live monitor backend did not become active", result);
	}
	return tool_result_t::ok(result);
}

static tool_result_t live_monitor_snapshot(bool require_captures)
{
	auto accesses = struct_monitor::get_access_snapshot();
	json arr = json::array();
	for (auto& a : accesses) {
		json obj;
		char obuf[16];
		std::snprintf(obuf, sizeof(obuf), "0x%04llX", static_cast<unsigned long long>(a.field_offset));
		obj["offset"] = obuf;
		obj["access_size"] = a.access_size;
		obj["is_write"] = a.is_write;
		obj["inferred_type"] = struct_recon::field_type_name(a.inferred_type);
		obj["hit_count"] = a.hit_count;
		obj["disasm"] = a.disasm;
		char rbuf[32];
		std::snprintf(rbuf, sizeof(rbuf), "0x%llX", static_cast<unsigned long long>(a.rip));
		obj["rip"] = rbuf;
		arr.push_back(obj);
	}
	json result;
	result["active"] = struct_monitor::g_state.active.load();
	result["total_captures"] = struct_monitor::g_state.total_captures.load();
	result["positive_capture_count"] = struct_monitor::g_state.total_captures.load();
	result["unique_offsets"] = accesses.size();
	result["page_guard"] = struct_monitor::g_state.session.using_page_guard;
	result["hardware_breakpoint"] = struct_monitor::g_state.session.using_hwbp;
	result["polling"] = struct_monitor::g_state.session.using_polling;
	result["accesses"] = arr;
	result["functional_monitor_evidence"] = !accesses.empty();
	if (require_captures && accesses.empty())
		return tool_result_t::error("live monitor captured no accesses", result);
	return tool_result_t::ok(result);
}

static tool_result_t live_monitor_manage_stop(const json& params)
{
	diag::log_tagged("analysis", "live_monitor_manage stop");
	if (!struct_monitor::g_state.active.load())
		return tool_result_t::error("No active live monitor session.");
	struct_monitor::stop();
	for (int wait = 0; struct_monitor::g_state.active.load() && wait < 10; ++wait)
		Sleep(50);
	if (mcp_call_interrupted())
		return mcp_call_interrupted_result("Live monitor shutdown");
	return live_monitor_snapshot(params.value("require_captures", false));
}

static tool_result_t symbolic_manage_deobfuscate(const json& params)
{
	std::string addr_str = params.value("entry_address", "");
	if (addr_str.empty())
		return tool_result_t::error("entry_address is required");
	uint64_t entry = 0;
	if (!parse_hex_u64(addr_str, entry))
		return tool_result_t::error("invalid entry_address");
	if (entry == 0)
		return tool_result_t::error("invalid entry_address");
	const uint32_t max_insns = bounded_u32_param(params, "max_instructions", 10000, 1, 1000000);
	auto result = deobfuscation_engine::deobfuscate_function(entry, max_insns);
	json out;
	out["statistics"] = {
		{"total_instructions", result.total_original},
		{"clean_instructions", result.total_clean},
		{"junk_removed", result.removed_junk},
		{"opaque_predicates", result.opaque_predicates_found},
		{"constants_resolved", result.constants_resolved}
	};
	json insns = json::array();
	for (auto& ci : result.clean_instructions) {
		json obj;
		char abuf[32];
		std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(ci.address));
		obj["address"] = abuf;
		obj["disasm"] = ci.disasm;
		obj["is_original"] = !ci.was_junk;
		obj["was_constant_folded"] = ci.was_constant_folded;
		insns.push_back(obj);
	}
	out["clean_instructions"] = insns;
	json opaques = json::array();
	for (auto& op : result.opaques) {
		json obj;
		char abuf[32];
		std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(op.address));
		obj["address"] = abuf;
		obj["condition_str"] = op.condition_ast;
		obj["always_true"] = op.always_taken;
		opaques.push_back(obj);
	}
	out["opaque_predicates"] = opaques;
	json constants = json::array();
	for (auto& cf : result.constants) {
		json obj;
		char abuf[32];
		std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(cf.address));
		obj["address"] = abuf;
		obj["original_expression"] = cf.original_ast;
		char vbuf[32];
		std::snprintf(vbuf, sizeof(vbuf), "0x%llX", static_cast<unsigned long long>(cf.concrete_value));
		obj["resolved_value"] = vbuf;
		constants.push_back(obj);
	}
	out["constants"] = constants;
	return tool_result_t::ok(out);
}

static tool_result_t symbolic_manage_slice(const json& params)
{
	std::string start_str = params.value("start_address", "");
	std::string end_str = params.value("end_address", "");
	std::string reg = params.value("target_register", "");
	if (start_str.empty() || end_str.empty() || reg.empty())
		return tool_result_t::error("start_address, end_address, and target_register are required");
	uint64_t start = 0;
	uint64_t end = 0;
	if (!parse_hex_u64(start_str, start) || !parse_hex_u64(end_str, end))
		return tool_result_t::error("invalid address range");
	const uint32_t max_insns = bounded_u32_param(params, "max_instructions", 5000, 1, 1000000);
	auto result = symbolic_engine::slice_to_register(start, end, max_insns, reg);
	json out;
	out["target_register"] = reg;
	out["total_instructions"] = result.total_instructions;
	out["effective_instructions"] = result.effective_count;
	out["removed_count"] = result.total_instructions - result.effective_count;
	json insns = json::array();
	for (auto& ti : result.effective_instructions) {
		json obj;
		char abuf[32];
		std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(ti.address));
		obj["address"] = abuf;
		obj["disasm"] = ti.disasm;
		insns.push_back(obj);
	}
	out["instructions"] = insns;
	return tool_result_t::ok(out);
}

static tool_result_t symbolic_manage_solve_path(const json& params)
{
	std::string start_str = params.value("start_address", "");
	std::string target_str = params.value("target_address", "");
	std::string regs_str = params.value("symbolic_registers", "");
	if (start_str.empty() || target_str.empty() || regs_str.empty())
		return tool_result_t::error("start_address, target_address, and symbolic_registers are required");
	uint64_t start = 0;
	uint64_t target = 0;
	if (!parse_hex_u64(start_str, start) || !parse_hex_u64(target_str, target))
		return tool_result_t::error("invalid address range");
	const uint32_t max_insns = bounded_u32_param(params, "max_instructions", 5000, 1, 1000000);
	std::vector<std::string> sym_regs;
	std::istringstream iss(regs_str);
	std::string tok;
	while (std::getline(iss, tok, ',')) {
		while (!tok.empty() && tok.front() == ' ') tok.erase(tok.begin());
		while (!tok.empty() && tok.back() == ' ') tok.pop_back();
		if (!tok.empty())
			sym_regs.push_back(tok);
	}
	auto result = symbolic_engine::solve_for_path(start, target, max_insns, sym_regs);
	json out;
	out["satisfiable"] = result.satisfiable;
	out["solving_time_ms"] = result.solving_time_ms;
	if (result.satisfiable) {
		json vars = json::object();
		for (auto& kv : result.variable_values) {
			char vbuf[32];
			std::snprintf(vbuf, sizeof(vbuf), "0x%llX", static_cast<unsigned long long>(kv.second));
			vars[kv.first] = vbuf;
		}
		out["solution"] = vars;
	}
	return tool_result_t::ok(out);
}

using workspace_ptr_t = std::shared_ptr<aida::analysis::analysis_workspace_t>;

static uint64_t query_workspace_va(const aida::analysis::address_t& address,
                                   const aida::analysis::pe_image_t& image)
{
	return address.space == aida::analysis::address_space_id_t::relative_virtual
		? image.image_base() + address.value : address.value;
}

static std::string query_hex(uint64_t value)
{
	char buffer[32];
	std::snprintf(buffer, sizeof(buffer), "0x%llX", static_cast<unsigned long long>(value));
	return buffer;
}

static tool_result_t workspace_query_error(std::string message, std::string code)
{
	return tool_result_t::error(message, code, json::object());
}

static tool_result_t workspace_analysis_query(const json& params, const workspace_ptr_t& workspace)
{
	const std::string action = compat_action_name(params);
	const json payload = compat_action_payload(params);
	auto image = workspace->image();
	if (!image)
		return workspace_query_error("Workspace image metadata is unavailable", "WORKSPACE_NOT_READY");
	const bool live = workspace->target_kind() == aida::analysis::target_kind_t::live_snapshot;
	const size_t limit = bounded_size_param(payload, "limit", 512, 1, 4096);

	if (action == "imports") {
		const size_t max_entries = bounded_size_param(payload, "max_entries", 512, 1, 4096);
		json imports = json::array();
		const size_t returned = (std::min)(max_entries, image->imports().size());
		for (size_t index = 0; index < returned; ++index) {
			const auto& value = image->imports()[index];
			imports.push_back(json{{"module", value.library},
				{"function", value.name ? *value.name : std::string()},
				{"ordinal", value.ordinal ? json(*value.ordinal) : json(nullptr)},
				{"hint", value.hint ? json(*value.hint) : json(nullptr)},
				{"iat_address", query_hex(image->image_base() + value.iat_rva)},
				{"bound_address", query_hex(0)}, {"delayed", value.delayed}});
		}
		return tool_result_t::ok(json{{"module", workspace->identity().bin_name()},
			{"count", imports.size()}, {"truncated", returned < image->imports().size()},
			{"parse_complete", true}, {"max_entries", max_entries},
			{"timeout_ms", bounded_u32_param(payload, "timeout_ms", 2500, 100, 10000)},
			{"imports", std::move(imports)}});
	}

	if (action == "exports") {
		const size_t max_entries = bounded_size_param(payload, "max_entries", 512, 1, 4096);
		json exports = json::array();
		const size_t returned = (std::min)(max_entries, image->exports().size());
		for (size_t index = 0; index < returned; ++index) {
			const auto& value = image->exports()[index];
			json entry{{"ordinal", value.ordinal},
				{"name", value.name ? *value.name : std::string()},
				{"rva", query_hex(value.rva)},
				{"address", query_hex(image->image_base() + value.rva)}};
			if (value.forwarder) {
				entry["forwarded"] = true;
				entry["forward_to"] = *value.forwarder;
			}
			exports.push_back(std::move(entry));
		}
		return tool_result_t::ok(json{{"module", workspace->identity().bin_name()},
			{"module_path", workspace->identity().normalized_source_path()},
			{"module_base", query_hex(image->image_base())}, {"count", exports.size()},
			{"truncated", returned < image->exports().size()}, {"parse_complete", true},
			{"max_entries", max_entries}, {"requested_max_entries", max_entries},
			{"timeout_ms", bounded_u32_param(payload, "timeout_ms", 2500, 100, 10000)},
			{"requested_timeout_ms", bounded_u32_param(payload, "timeout_ms", 2500, 100, 10000)},
			{"is_testtarget_fixture", false}, {"exports", std::move(exports)}});
	}

	if (live)
		return workspace_query_error("This query requires a complete static workspace index",
			"LIVE_TARGET_BULK_ANALYSIS_UNSUPPORTED");
	auto snapshot = workspace->snapshot();
	if (!snapshot)
		return workspace_query_error("Workspace analysis is not ready", "WORKSPACE_NOT_READY");
	auto search = workspace->search_index();

	if (action == "types" || action == "type_definition") {
		if (!search)
			return workspace_query_error("Workspace type index is not ready", "WORKSPACE_NOT_READY");
		const std::string filter = lower_ascii(payload.value("filter", payload.value("name", std::string())));
		json types = json::array();
		size_t visited = 0;
		for (const auto& type : search->types()) {
			if ((visited++ & 0x3FFu) == 0) {
				if (workspace->cancellation_token().stop_requested())
					return workspace_query_error("Workspace type query was cancelled", "CANCELLED");
				if (mcp_call_interrupted())
					return mcp_call_interrupted_result("Workspace type query");
			}
			if (!filter.empty() && lower_ascii(type.display_name).find(filter) == std::string::npos)
				continue;
			json entry{{"name", type.display_name}, {"definition", type.canonical_type},
				{"address", query_hex(query_workspace_va(type.address, *image))},
				{"kind", static_cast<unsigned>(type.kind)}, {"confidence", type.confidence},
				{"provenance", static_cast<unsigned>(type.provenance)},
				{"explicitly_unknown", type.explicitly_unknown}};
			if (action == "type_definition")
				return tool_result_t::ok(entry);
			if (types.size() < limit) types.push_back(std::move(entry));
		}
		if (action == "type_definition")
			return workspace_query_error("Type definition was not found", "TYPE_NOT_FOUND");
		return tool_result_t::ok(json{{"count", types.size()}, {"limit", limit},
			{"types", std::move(types)}});
	}

	if (action == "pdb_symbols") {
		const std::string filter = lower_ascii(payload.value("filter", std::string()));
		const bool functions_only = payload.value("functions_only", false);
		json symbols = json::array();
		size_t total = 0;
		size_t visited = 0;
		for (const auto& symbol : snapshot->symbols) {
			if ((visited++ & 0x3FFu) == 0) {
				if (workspace->cancellation_token().stop_requested())
					return workspace_query_error("Workspace symbol query was cancelled", "CANCELLED");
				if (mcp_call_interrupted())
					return mcp_call_interrupted_result("Workspace symbol query");
			}
			if ((functions_only && symbol.kind != aida::analysis::symbol_kind_t::function) ||
				(!functions_only && symbol.kind != aida::analysis::symbol_kind_t::debug_symbol &&
				 symbol.kind != aida::analysis::symbol_kind_t::function) ||
				(!filter.empty() && lower_ascii(symbol.name).find(filter) == std::string::npos))
				continue;
			++total;
			if (symbols.size() < limit)
				symbols.push_back(json{{"name", symbol.name},
					{"address", query_hex(query_workspace_va(symbol.address, *image))},
					{"kind", static_cast<unsigned>(symbol.kind)}, {"confidence", symbol.confidence}});
		}
		return tool_result_t::ok(json{{"count", symbols.size()}, {"total", total},
			{"truncated", symbols.size() < total}, {"symbols", std::move(symbols)}});
	}

	if (action == "xref_db_stats") {
		return tool_result_t::ok(json{{"module_count", 1}, {"modules_built", 1},
			{"total_xrefs", snapshot->xrefs.size()}, {"building", false}, {"progress", 1.0},
			{"modules", json::array({json{{"module", workspace->identity().bin_name()},
				{"base", image->image_base()}, {"size", image->image_size()},
				{"total_xrefs", snapshot->xrefs.size()}, {"built", true}}})}});
	}

	if (action == "binary_map_overview") {
		aida::binary_map::map_options_t options;
		options.max_functions = static_cast<int>(bounded_size_param(payload, "max_functions", 24, 1, 256));
		options.max_globals = static_cast<int>(bounded_size_param(payload, "max_globals", 12, 1, 256));
		options.max_callees_per_function = static_cast<int>(
			bounded_size_param(payload, "max_callees_per_function", 5, 1, 256));
		options.max_chars = bounded_size_param(payload, "max_chars", 4096, 256, 1u << 20);
		options.include_imports = payload.value("include_imports", false);
		options.include_exports = payload.value("include_exports", false);
		options.include_xrefs = payload.value("include_xrefs", true);
		options.include_entropy = payload.value("include_entropy", true);
		aida::binary_map::map_t map;
		const auto started = std::chrono::steady_clock::now();
		if (!aida::binary_map::generate(workspace, options, map)) {
			if (workspace->cancellation_token().stop_requested())
				return workspace_query_error("Workspace binary-map generation was cancelled", "CANCELLED");
			if (mcp_call_interrupted())
				return mcp_call_interrupted_result("Workspace binary-map generation");
			return workspace_query_error("Workspace binary-map generation failed", "BINARY_MAP_FAILED");
		}
		const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::steady_clock::now() - started).count();
		json sections = json::array();
		for (const auto& section : map.sections)
			sections.push_back(json{{"name", section.name},
				{"va", query_hex(section.va)}, {"size", section.size},
				{"executable", section.executable}, {"readable", section.readable},
				{"writable", section.writable}, {"entropy", section.entropy},
				{"entropy_sampled_bytes", section.sampled_bytes}});
		json functions = json::array();
		for (const auto& function : map.functions) {
			functions.push_back(json{{"va", query_hex(function.va)}, {"name", function.name},
				{"xref_count", function.xref_count}, {"callee_count", function.callee_count},
				{"top_callees", function.top_callees}, {"section", function.section_name},
				{"pinned", function.pinned}, {"score", function.score}});
		}
		json globals = json::array();
		for (const auto& global : map.globals) {
			globals.push_back(json{{"va", query_hex(global.va)}, {"name", global.name},
				{"xref_count", global.xref_count}, {"writable", global.writable},
				{"section", global.section_name}});
		}
		json result{{"module_name", map.module_name}, {"module_path", map.module_path},
			{"architecture", map.architecture}, {"format", map.format},
			{"image_base", query_hex(map.image_base)}, {"image_size", map.image_size},
			{"sections", std::move(sections)}, {"functions", std::move(functions)},
			{"globals", std::move(globals)}, {"fast_summary", payload.value("fast_summary", false)},
			{"phase_timings_ms", json{{"generate", elapsed}}},
			{"phase_details", json{{"sections", map.sections.size()}, {"functions", map.functions.size()},
				{"globals", map.globals.size()}, {"imports", map.imports.size()}, {"exports", map.exports.size()}}},
			{"elapsed_ms", elapsed}, {"generated_unix", map.generated_unix}, {"cancelled", false},
			{"imports", std::move(map.imports)}, {"exports", std::move(map.exports)}};
		return tool_result_t::ok(result);
	}

	return compat_unknown_action("analysis_query", action);
}

void register_analysis_tools(mcp_standalone::server_t& srv)
{
	srv.register_tool({
		"scan_crypto_constants",
		"Scan the attached process memory for well-known cryptographic constants (AES S-Box, SHA-256, MD5, CRC32, Blowfish, DES, ChaCha20, Base64, etc).",
		{
			{"module_filter", "string", "Optional case-insensitive module name substring to scan", false},
			{"max_regions", "integer", "Maximum committed readable regions to scan (default 4096)", false},
			{"max_bytes", "integer", "Maximum bytes to scan before stopping (0 = unlimited)", false},
			{"max_hits", "integer", "Maximum hits before stopping (0 = unlimited)", false},
			{"range_base", "string", "Optional hex base address limiting the scan to a target range", false},
			{"range_size", "integer", "Optional byte size for range_base-limited scans", false},
			{"timeout_ms", "integer", "Maximum scan time before cancellation (default 4500, max 60000)", false}
		},
		true,
		[](const json& params) -> tool_result_t {
			crypto_scanner::process_scan_config_t cfg;
			cfg.module_filter = params.value("module_filter", std::string());
			cfg.max_regions = params.value("max_regions", static_cast<size_t>(4096));
			cfg.max_bytes = params.value("max_bytes", static_cast<uint64_t>(0));
			cfg.max_hits = params.value("max_hits", static_cast<size_t>(0));
			cfg.timeout_ms = bounded_u32_param(params, "timeout_ms", 4500, 100, 60000);
			std::string range_base_str = params.value("range_base", std::string());
			if (!range_base_str.empty() && !parse_hex_u64(range_base_str, cfg.range_base))
				return tool_result_t::error("invalid range_base");
			cfg.range_size = static_cast<uint64_t>(bounded_size_param(params, "range_size", 0, 0, 64ULL * 1024ULL * 1024ULL));
			if ((!range_base_str.empty() && cfg.range_base == 0) || (cfg.range_size != 0 && cfg.range_base == 0))
				return tool_result_t::error("invalid range_base");
			if (cfg.range_base != 0 && cfg.range_size == 0)
				return tool_result_t::error("range_size must be non-zero when range_base is provided");
			cfg.label_references = false;
			diag::log_tagged_fmt("analysis", "scan_crypto_constants entry module_filter='%s' max_regions=%zu max_bytes=%llu max_hits=%zu timeout_ms=%u range=0x%llX+0x%llX",
				cfg.module_filter.c_str(),
				cfg.max_regions,
				static_cast<unsigned long long>(cfg.max_bytes),
				cfg.max_hits,
				cfg.timeout_ms,
				static_cast<unsigned long long>(cfg.range_base),
				static_cast<unsigned long long>(cfg.range_size));
			if (crypto_scanner::g_state.scanning.load()) {
				diag::log_tagged("analysis", "scan_crypto_constants refused already_scanning");
				return tool_result_t::error("A crypto scan is already in progress.");
			}
			crypto_scanner::scan_process(cfg);
			diag::log_tagged("analysis", "scan_crypto_constants scan_process called waiting");

			int wait = 0;
			int max_wait = static_cast<int>((cfg.timeout_ms + 49) / 50);
			bool interrupted = false;
			while (crypto_scanner::g_state.scanning.load() && wait < max_wait) {
				if (mcp_call_interrupted()) {
					interrupted = true;
					crypto_scanner::cancel();
					break;
				}
				Sleep(50);
				++wait;
			}
			bool timed_out = crypto_scanner::g_state.scanning.load();
			if (timed_out) {
				crypto_scanner::cancel();
				for (int stop_wait = 0; crypto_scanner::g_state.scanning.load() && stop_wait < 10; ++stop_wait)
					Sleep(50);
			}

			std::lock_guard<std::mutex> lk(crypto_scanner::g_state.mutex);
			auto& results = crypto_scanner::g_state.results;
			diag::log_tagged_fmt("analysis", "scan_crypto_constants complete count=%zu timed_out=%d still_running=%d",
				results.size(), timed_out ? 1 : 0, crypto_scanner::g_state.scanning.load() ? 1 : 0);

			json arr = json::array();
			for (auto& r : results) {
				json obj;
				obj["signature"] = r.signature_name;
				obj["algorithm"] = r.algorithm;
				obj["category"] = crypto_scanner::category_name(r.category);
				char addr_buf[32];
				std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX", static_cast<unsigned long long>(r.address));
				obj["address"] = addr_buf;
				obj["module"] = r.module_name;
				char off_buf[32];
				std::snprintf(off_buf, sizeof(off_buf), "0x%llX", static_cast<unsigned long long>(r.module_offset));
				obj["module_offset"] = off_buf;
				arr.push_back(obj);
			}

			json result;
			result["count"] = results.size();
			result["results"] = arr;
			result["status"] = crypto_scanner::g_state.scanning.load() ? "cancel_requested" : (timed_out ? "cancelled_by_timeout" : "complete");
			result["timed_out"] = timed_out;
			if (interrupted)
				return mcp_call_interrupted_result("Crypto scan");
			if (timed_out)
				return tool_result_t{false, "Crypto scan did not complete within the timeout.", result};
			return tool_result_t::ok(result);
		}
	});

	srv.register_tool({
		"generate_aob_signature",
		"Generate an AOB (Array of Bytes) signature from a given address. Automatically wildcards RIP-relative and large immediate bytes.",
		{
			{"address", "string", "Hex address to generate signature from (e.g. '0x7FF6A1234567')", true},
			{"instruction_count", "integer", "Number of instructions to include (default: 16)", false}
		},
		true,
		{}},
		[](const json& params, const workspace_ptr_t& workspace) -> tool_result_t {
			std::string addr_str = params.value("address", "");
			const int count = static_cast<int>(bounded_size_param(params, "instruction_count", 16, 1, 256));
			diag::log_tagged_fmt("analysis", "generate_aob_signature entry addr=%s count=%d",
				addr_str.c_str(), count);

			if (addr_str.empty()) {
				diag::log_tagged("analysis", "generate_aob_signature refused no_address");
				return tool_result_t::error("address parameter is required");
			}

			uint64_t addr = 0;
			if (!parse_hex_u64(addr_str, addr))
				return tool_result_t::error("invalid address");
			if (addr == 0) {
				diag::log_tagged("analysis", "generate_aob_signature refused invalid_address");
				return tool_result_t::error("invalid address");
			}

			diag::log_tagged_fmt("analysis", "generate_aob_signature generating addr=0x%llX count=%d",
				static_cast<unsigned long long>(addr), count);
			auto context = disasm_view::capture_workspace(workspace);
			auto state = aob_generator::state_for(context);
			if (!context || !state)
				return workspace_query_error("Workspace disassembly context is unavailable", "WORKSPACE_NOT_READY");
			aob_generator::generate_from_address(context, addr, count, true);

			int wait = 0;
			while (state->generating.load() && wait < 100) {
				if (mcp_call_interrupted())
					return mcp_call_interrupted_result("AOB signature generation");
				Sleep(100);
				++wait;
			}

			aob_generator::signature_t sig;
			std::string tool_last_error;
			{
				std::lock_guard<std::mutex> lk(state->mutex);
				sig = state->current;
				tool_last_error = state->last_error;
			}

			if (sig.bytes.empty() || sig.address != addr) {
				std::string err_msg = tool_last_error.empty()
					? std::string("Failed to generate signature (could not read memory or decode instructions)")
					: tool_last_error;
				diag::log_tagged_fmt("analysis", "generate_aob_signature failed addr=0x%llX err=%s",
					static_cast<unsigned long long>(addr), err_msg.c_str());
				return tool_result_t::error(err_msg);
			}

			json result;
			char abuf[32];
			std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(sig.address));
			result["address"] = abuf;
			result["module"] = sig.module_name;
			result["byte_count"] = sig.bytes.size();
			diag::log_tagged_fmt("analysis", "generate_aob_signature complete addr=0x%llX bytes=%zu module=%s",
				static_cast<unsigned long long>(sig.address), sig.bytes.size(), sig.module_name.c_str());
			result["standard"] = aob_generator::format_signature(sig);
			result["ida_style"] = aob_generator::format_ida_signature(sig);
			result["code_pattern"] = aob_generator::format_code_signature(sig);

			int wc = 0;
			for (auto& b : sig.bytes) if (b.wildcard) ++wc;
			result["wildcard_bytes"] = wc;

			return tool_result_t::ok(result);
		});

	srv.register_tool({
		"reconstruct_struct",
		"Reconstruct a C++ struct/class layout from a memory address by analyzing memory contents, detecting VTables, and inferring field types.",
		{
			{"address", "string", "Base address of the struct instance in hex", true},
			{"size", "integer", "Size in bytes to analyze (default: 256)", false},
			{"name", "string", "Name for the struct (default: 'struct_t')", false},
			{"timeout_ms", "integer", "Maximum wait time before returning the current partial layout (default: 4500, max 4500)", false}
		},
		true,
		[](const json& params) -> tool_result_t {
			std::string addr_str = params.value("address", "");
			const int size = static_cast<int>(bounded_size_param(params, "size", 256, 1, 1024 * 1024));
			std::string name = params.value("name", "struct_t");
			uint32_t timeout_ms = bounded_u32_param(params, "timeout_ms", 4500, 100, 4500);
			diag::log_tagged_fmt("analysis", "reconstruct_struct entry addr=%s size=%d name=%s",
				addr_str.c_str(), size, name.c_str());

			if (addr_str.empty()) {
				diag::log_tagged("analysis", "reconstruct_struct refused no_address");
				return tool_result_t::error("address parameter is required");
			}

			uint64_t addr = 0;
			if (!parse_hex_u64(addr_str, addr))
				return tool_result_t::error("invalid address");
			if (addr == 0) {
				diag::log_tagged("analysis", "reconstruct_struct refused invalid_address");
				return tool_result_t::error("invalid address");
			}

			diag::log_tagged_fmt("analysis", "reconstruct_struct starting addr=0x%llX size=%d name=%s",
				static_cast<unsigned long long>(addr), size, name.c_str());
			struct_recon::reconstruct_from_snapshot(addr, size, name);

			int wait = 0;
			int max_wait = static_cast<int>((timeout_ms + 49) / 50);
			while (struct_recon::g_state.monitoring.load() && wait < max_wait) {
				if (mcp_call_interrupted()) {
					struct_recon::cancel();
					break;
				}
				Sleep(50);
				++wait;
			}
			bool timed_out = struct_recon::g_state.monitoring.load();
			if (timed_out)
				struct_recon::cancel();

			struct_recon::reconstructed_struct_t result_struct;
			{
				std::lock_guard<std::mutex> lk(struct_recon::g_state.mutex);
				result_struct = struct_recon::g_state.current;
			}

			diag::log_tagged_fmt("analysis", "reconstruct_struct complete addr=0x%llX name=%s fields=%zu size=%u has_vtable=%d",
				static_cast<unsigned long long>(result_struct.base_address),
				result_struct.name.c_str(), result_struct.fields.size(),
				result_struct.total_size, result_struct.has_vtable ? 1 : 0);
			std::string cpp_output = struct_recon::export_as_cpp(result_struct);

			json result;
			result["name"] = result_struct.name;
			char abuf[32];
			std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(result_struct.base_address));
			result["base_address"] = abuf;
			result["total_size"] = result_struct.total_size;
			result["field_count"] = result_struct.fields.size();
			result["has_vtable"] = result_struct.has_vtable;
			result["cpp_definition"] = cpp_output;
			result["timed_out"] = timed_out;
			result["timeout_ms"] = timeout_ms;

			json fields_arr = json::array();
			for (auto& f : result_struct.fields) {
				json fobj;
				char off_buf[16];
				std::snprintf(off_buf, sizeof(off_buf), "0x%04llX", static_cast<unsigned long long>(f.offset));
				fobj["offset"] = off_buf;
				fobj["size"] = f.size;
				fobj["type"] = struct_recon::field_type_name(f.type);
				fobj["name"] = f.name;
				if (f.type == struct_recon::field_type_t::vtable_ptr) {
					fobj["vtable_entries"] = static_cast<int>(f.vtable_entries.size());
				}
				fields_arr.push_back(fobj);
			}
			result["fields"] = fields_arr;

			return tool_result_t::ok(result);
		}
	});




	srv.register_tool({
		"auto_decrypt_strings",
		"Automatically decrypt obfuscated strings by emulating functions that reference a suspected encrypted region. Finds xrefs to the region, emulates each referencing function, and captures memory writes that produce printable strings.",
		{
			{"region_address", "string", "Hex address of the encrypted string region", true},
			{"region_size", "integer", "Size of the region in bytes (default: 4096)", false},
			{"timeout_ms", "integer", "Maximum wait time before cancellation (default: 4500, max 4500)", false},
			{"search_start", "string", "Optional hex address limiting xref search to a specific range", false},
			{"search_size", "integer", "Optional xref search range size in bytes", false}
		},
		false,
		[](const json& params) -> tool_result_t {
			std::string addr_str = params.value("region_address", "");
			const uint64_t size = static_cast<uint64_t>(bounded_size_param(params, "region_size", 4096, 1, 64ULL * 1024ULL * 1024ULL));
			uint32_t timeout_ms = bounded_u32_param(params, "timeout_ms", 4500, 100, 4500);
			std::string search_start_str = params.value("search_start", "");
			uint64_t search_start = 0;
			if (!search_start_str.empty() && !parse_hex_u64(search_start_str, search_start))
				return tool_result_t::error("invalid search_start");
			uint64_t search_size = static_cast<uint64_t>(bounded_size_param(params, "search_size", 0, 0, 64ULL * 1024ULL * 1024ULL));
			diag::log_tagged_fmt("analysis", "auto_decrypt_strings entry addr=%s size=%llu",
				addr_str.c_str(), static_cast<unsigned long long>(size));

			if (addr_str.empty()) {
				diag::log_tagged("analysis", "auto_decrypt_strings refused no_region_address");
				return tool_result_t::error("region_address parameter is required");
			}

			uint64_t addr = 0;
			if (!parse_hex_u64(addr_str, addr))
				return tool_result_t::error("invalid region_address");
			if (addr == 0) {
				diag::log_tagged("analysis", "auto_decrypt_strings refused invalid_region_address");
				return tool_result_t::error("invalid region_address");
			}

			diag::log_tagged_fmt("analysis", "auto_decrypt_strings scanning addr=0x%llX size=%llu",
				static_cast<unsigned long long>(addr), static_cast<unsigned long long>(size));
			decrypt_oracle::scan_and_decrypt(addr, size, timeout_ms, search_start, search_size);

			int wait = 0;
			int max_wait = static_cast<int>((timeout_ms + 99) / 100);
			while (decrypt_oracle::g_state.scanning.load() && wait < max_wait) {
				if (mcp_call_interrupted()) {
					decrypt_oracle::g_state.cancel.store(true, std::memory_order_release);
					xref_engine::cancel_scan();
					break;
				}
				Sleep(100);
				++wait;
			}

			bool timed_out = decrypt_oracle::g_state.scanning.load() ||
				decrypt_oracle::g_state.timed_out.load();
			if (timed_out) {
				decrypt_oracle::g_state.timed_out.store(true, std::memory_order_release);
				decrypt_oracle::g_state.cancel.store(true, std::memory_order_release);
				xref_engine::cancel_scan();
				for (int stop_wait = 0; decrypt_oracle::g_state.scanning.load() && stop_wait < 10; ++stop_wait)
					Sleep(50);
			}

			std::lock_guard<std::mutex> lk(decrypt_oracle::g_state.mutex);
			auto& results = decrypt_oracle::g_state.results;
			diag::log_tagged_fmt("analysis", "auto_decrypt_strings complete count=%zu total_xrefs=%d processed_xrefs=%d timed_out=%d status=%s",
				results.size(),
				decrypt_oracle::g_state.total_xrefs.load(std::memory_order_acquire),
				decrypt_oracle::g_state.processed_xrefs.load(std::memory_order_acquire),
				timed_out ? 1 : 0,
				decrypt_oracle::g_state.status_text.c_str());

			json arr = json::array();
			for (auto& r : results) {
				json obj;
				char fbuf[32];
				std::snprintf(fbuf, sizeof(fbuf), "0x%llX", static_cast<unsigned long long>(r.source_function));
				obj["source_function"] = fbuf;
				char obuf[32];
				std::snprintf(obuf, sizeof(obuf), "0x%llX", static_cast<unsigned long long>(r.encrypted_offset));
				obj["encrypted_offset"] = obuf;
				obj["decrypted_string"] = r.decrypted;
				obj["length"] = r.length;
				obj["confidence"] = r.confidence;
				obj["is_utf16"] = r.is_utf16;
				arr.push_back(obj);
			}

			json result;
			result["count"] = results.size();
			result["results"] = arr;
			result["timed_out"] = timed_out;
			result["total_xrefs"] = decrypt_oracle::g_state.total_xrefs.load(std::memory_order_acquire);
			result["processed_xrefs"] = decrypt_oracle::g_state.processed_xrefs.load(std::memory_order_acquire);
			result["status_text"] = decrypt_oracle::g_state.status_text;
			if (timed_out) {
				result["status"] = "timeout";
				result["cancelled"] = true;
				result["message"] = "auto_decrypt_strings timed out and cancellation was requested";
				return tool_result_t{false, "auto_decrypt_strings timed out and cancellation was requested", result};
			}
			return tool_result_t::ok(result);
		}
	});

	srv.register_tool({
		"hunt_integrity_checkers",
		"Find integrity checker threads by monitoring reads on a code region using page guards. Returns discovered checker RIPs, their read frequency, and associated hash comparison addresses.",
		{
			{"target_address", "string", "Hex address of the code region to protect", true},
			{"target_size", "integer", "Size of the region to monitor (default: 4096)", false},
			{"duration_ms", "integer", "How long to monitor in milliseconds (default: 1000, max 4500)", false}
		},
		false,
		[](const json& params) -> tool_result_t {
			std::string addr_str = params.value("target_address", "");
			uint64_t size = bounded_u32_param(params, "target_size", 4096, 1, 1024 * 1024);
			int duration = static_cast<int>(bounded_u32_param(params, "duration_ms", 1000, 100, 4500));

			if (addr_str.empty()) {
				return tool_result_t::error("target_address parameter is required");
			}

			uint64_t addr = 0;
			if (!parse_hex_u64(addr_str, addr))
				return tool_result_t::error("invalid address");
			if (addr == 0) {
				return tool_result_t::error("invalid target_address");
			}

			diag::log_tagged_fmt("integrity_hunter",
				"mcp_hunt_request addr=0x%llX size=%llu duration_ms=%d",
				static_cast<unsigned long long>(addr),
				static_cast<unsigned long long>(size), duration);

			const auto request_start = std::chrono::steady_clock::now();
			auto make_failure_payload = [&](const char* status, uint64_t generation, const integrity_hunter::idle_result_t& idle_state) {
				const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
					std::chrono::steady_clock::now() - request_start).count();
				json result;
				result["status"] = status ? status : "failed";
				result["generation"] = generation;
				result["install_generation"] = idle_state.install_generation;
				result["pid"] = idle_state.target_pid;
				result["active_pid"] = driver_bridge::attached_pid();
				result["address"] = addr_str;
				result["target_address"] = addr_str;
				result["size"] = size;
				result["target_size"] = size;
				result["install_complete"] = integrity_hunter::install_complete_for_generation(generation);
				result["install_success"] = integrity_hunter::install_success_for_generation(generation);
				result["raw_install_complete"] = idle_state.install_complete;
				result["raw_install_success"] = idle_state.install_success;
				result["worker_idle"] = idle_state.idle;
				result["hunting"] = idle_state.hunting;
				result["worker_active"] = idle_state.worker_active;
				result["session"] = idle_state.session_id;
				result["nodes"] = idle_state.nodes;
				result["events"] = idle_state.events;
				result["node_count"] = idle_state.nodes;
				result["event_count"] = idle_state.events;
				result["read_count"] = idle_state.total_reads;
				result["total_reads"] = idle_state.total_reads;
				result["elapsed_ms"] = elapsed;
				result["cleanup_elapsed_ms"] = idle_state.elapsed_ms;
				result["status_text"] = idle_state.status_text;
				result["last_error"] = driver_bridge::last_error();
				result["page_guard_failure"] = page_guard_install_failure_json();
				return result;
			};

			if (!integrity_hunter::start_hunt(addr, size)) {
				diag::log_tagged("integrity_hunter", "mcp_hunt_start_failed");
				const uint64_t generation = integrity_hunter::g_state.generation.load(std::memory_order_acquire);
				const auto idle_state = integrity_hunter::snapshot_idle_state();
				auto result = make_failure_payload("start_failed", generation, idle_state);
				return tool_result_t::error("integrity hunter could not start", result);
			}

			const uint64_t generation = integrity_hunter::g_state.generation.load(std::memory_order_acquire);
			const auto install_start = std::chrono::steady_clock::now();
			while (!integrity_hunter::install_complete_for_generation(generation) &&
			       (integrity_hunter::g_state.hunting.load() || integrity_hunter::g_state.worker_active.load())) {
				if (mcp_call_interrupted()) {
					integrity_hunter::stop_hunt();
					const auto idle_state = integrity_hunter::wait_until_idle_result(12000);
					auto result = make_failure_payload("cancelled", generation, idle_state);
					return tool_result_t::error("integrity hunter cancelled during install", result);
				}
				const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
					std::chrono::steady_clock::now() - install_start).count();
				if (elapsed >= 6500) {
					diag::log_tagged_fmt("integrity_hunter",
						"mcp_hunt_install_timeout addr=0x%llX size=%llu elapsed_ms=%lld hunting=%d worker=%d",
						static_cast<unsigned long long>(addr),
						static_cast<unsigned long long>(size),
						static_cast<long long>(elapsed),
						integrity_hunter::g_state.hunting.load() ? 1 : 0,
						integrity_hunter::g_state.worker_active.load() ? 1 : 0);
					integrity_hunter::stop_hunt();
					const auto idle_state = integrity_hunter::wait_until_idle_result(12000);
					auto result = make_failure_payload(idle_state.idle ? "page_guard_install_timeout" : "page_guard_install_timeout_cleanup_exceeded", generation, idle_state);
					const std::string status = result.value("status", std::string());
					const long long elapsed_ms = result.value("elapsed_ms", 0LL);
					const json& failure = result["page_guard_failure"];
					diag::log_tagged_fmt("integrity_hunter",
						"mcp_hunt_install_timeout_idle gen=%llu idle=%d pid=%u active_pid=%u install_complete=%d install_success=%d nodes=%zu events=%zu reads=%llu elapsed_ms=%lld cleanup_elapsed_ms=%lld status=%s pg_reason=%s remote_call_id=%llu remote_gle=%lu stale_pid=%d deadline_expired=%d cancelled=%d late_completion=%d last_error=%s",
						static_cast<unsigned long long>(generation),
						idle_state.idle ? 1 : 0,
						idle_state.target_pid,
						driver_bridge::attached_pid(),
						result.value("install_complete", false) ? 1 : 0,
						result.value("install_success", false) ? 1 : 0,
						idle_state.nodes,
						idle_state.events,
						static_cast<unsigned long long>(idle_state.total_reads),
						elapsed_ms,
						static_cast<long long>(idle_state.elapsed_ms),
						status.c_str(),
						failure.value("reason", std::string()).c_str(),
						static_cast<unsigned long long>(failure.value("remote_call_id", 0ull)),
						static_cast<unsigned long>(failure.value("remote_call_gle", 0u)),
						failure.value("remote_call_stale_pid", false) ? 1 : 0,
						failure.value("remote_call_deadline_expired_after", false) ? 1 : 0,
						failure.value("remote_call_cancelled_after", false) ? 1 : 0,
						failure.value("remote_call_late_completion", false) ? 1 : 0,
						driver_bridge::last_error().c_str());
					return tool_result_t::error(idle_state.idle ? "integrity hunter page guard install timed out" : "integrity hunter worker did not stop after install timeout", result);
				}
				Sleep(25);
			}

			if (!integrity_hunter::install_success_for_generation(generation)) {
				diag::log_tagged_fmt("integrity_hunter",
					"mcp_hunt_install_failed gen=%llu addr=0x%llX size=%llu install_complete=%d install_success=%d raw_install_complete=%d raw_install_success=%d",
					static_cast<unsigned long long>(generation),
					static_cast<unsigned long long>(addr),
					static_cast<unsigned long long>(size),
					integrity_hunter::install_complete_for_generation(generation) ? 1 : 0,
					integrity_hunter::install_success_for_generation(generation) ? 1 : 0,
					integrity_hunter::g_state.install_complete.load() ? 1 : 0,
					integrity_hunter::g_state.install_success.load() ? 1 : 0);
				integrity_hunter::stop_hunt();
				const auto idle_state = integrity_hunter::wait_until_idle_result(12000);
				auto result = make_failure_payload(idle_state.idle ? "page_guard_install_failed" : "page_guard_install_failed_cleanup_exceeded", generation, idle_state);
				const std::string status = result.value("status", std::string());
				const long long elapsed_ms = result.value("elapsed_ms", 0LL);
				const json& failure = result["page_guard_failure"];
				diag::log_tagged_fmt("integrity_hunter",
					"mcp_hunt_install_failed_idle gen=%llu idle=%d pid=%u active_pid=%u address=0x%llX size=%llu install_complete=%d install_success=%d nodes=%zu events=%zu reads=%llu elapsed_ms=%lld cleanup_elapsed_ms=%lld status=%s pg_reason=%s remote_call_id=%llu remote_gle=%lu stale_pid=%d deadline_expired=%d cancelled=%d late_completion=%d last_error=%s",
					static_cast<unsigned long long>(generation),
					idle_state.idle ? 1 : 0,
					idle_state.target_pid,
					driver_bridge::attached_pid(),
					static_cast<unsigned long long>(addr),
					static_cast<unsigned long long>(size),
					result.value("install_complete", false) ? 1 : 0,
					result.value("install_success", false) ? 1 : 0,
					idle_state.nodes,
					idle_state.events,
					static_cast<unsigned long long>(idle_state.total_reads),
					elapsed_ms,
					static_cast<long long>(idle_state.elapsed_ms),
					status.c_str(),
					failure.value("reason", std::string()).c_str(),
					static_cast<unsigned long long>(failure.value("remote_call_id", 0ull)),
					static_cast<unsigned long>(failure.value("remote_call_gle", 0u)),
					failure.value("remote_call_stale_pid", false) ? 1 : 0,
					failure.value("remote_call_deadline_expired_after", false) ? 1 : 0,
					failure.value("remote_call_cancelled_after", false) ? 1 : 0,
					failure.value("remote_call_late_completion", false) ? 1 : 0,
					driver_bridge::last_error().c_str());
				return tool_result_t::error(idle_state.idle ? "integrity hunter page guard install failed" : "integrity hunter worker did not stop after install failure", result);
			}

			const auto monitor_start = std::chrono::steady_clock::now();
			while (integrity_hunter::g_state.hunting.load()) {
				if (mcp_call_interrupted())
					break;
				const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
					std::chrono::steady_clock::now() - monitor_start).count();
				if (elapsed >= duration)
					break;
				Sleep(50);
			}

			integrity_hunter::stop_hunt();
			const auto idle_state = integrity_hunter::wait_until_idle_result(12000);
			if (!idle_state.idle) {
				diag::log_tagged_fmt("integrity_hunter",
					"mcp_hunt_stop_timeout addr=0x%llX size=%llu hunting=%d worker=%d session=%u",
					static_cast<unsigned long long>(addr),
					static_cast<unsigned long long>(size),
					integrity_hunter::g_state.hunting.load() ? 1 : 0,
					integrity_hunter::g_state.worker_active.load() ? 1 : 0,
					integrity_hunter::g_state.pg_session_id.load());
				auto result = make_failure_payload("stop_cleanup_exceeded", generation, idle_state);
				return tool_result_t::error("integrity hunter worker did not stop cleanly", result);
			}

			std::lock_guard<std::mutex> lk(integrity_hunter::g_state.mutex);
			auto& nodes = integrity_hunter::g_state.nodes;
			auto& events = integrity_hunter::g_state.event_log;

			json arr = json::array();
			for (size_t i = 0; i < nodes.size(); ++i) {
				auto& n = nodes[i];
				json obj;
				obj["index"] = static_cast<int>(i);
				char rbuf[32];
				std::snprintf(rbuf, sizeof(rbuf), "0x%llX", static_cast<unsigned long long>(n.reader_rip));
				obj["reader_rip"] = rbuf;
				obj["module"] = n.module_name;
				obj["read_count"] = n.read_count;
				obj["reads_per_second"] = n.reads_per_second;
				if (n.hash_compare_addr != 0) {
					char cbuf[32];
					std::snprintf(cbuf, sizeof(cbuf), "0x%llX", static_cast<unsigned long long>(n.hash_compare_addr));
					obj["hash_compare_addr"] = cbuf;
				}
				obj["disasm"] = n.disasm_text;
				obj["neutralized"] = n.neutralized;
				arr.push_back(obj);
			}

			json event_samples = json::array();
			std::map<uint64_t, uint64_t> rip_counts;
			for (size_t i = 0; i < events.size(); ++i) {
				const auto& ev = events[i];
				++rip_counts[ev.rip];
				if (event_samples.size() < 16) {
					char rbuf[32];
					char fbuf[32];
					std::snprintf(rbuf, sizeof(rbuf), "0x%llX", static_cast<unsigned long long>(ev.rip));
					std::snprintf(fbuf, sizeof(fbuf), "0x%llX", static_cast<unsigned long long>(ev.fault_addr));
					event_samples.push_back(json{{"index", static_cast<int>(i)},
						{"rip", rbuf},
						{"fault_addr", fbuf},
						{"timestamp", ev.timestamp},
						{"access_type", ev.access_type}});
				}
			}
			std::vector<std::pair<uint64_t, uint64_t>> top_rips(rip_counts.begin(), rip_counts.end());
			std::sort(top_rips.begin(), top_rips.end(), [](const auto& a, const auto& b) {
				if (a.second != b.second)
					return a.second > b.second;
				return a.first < b.first;
			});
			json top_reader_samples = json::array();
			for (size_t i = 0; i < top_rips.size() && i < 16; ++i) {
				char rbuf[32];
				std::snprintf(rbuf, sizeof(rbuf), "0x%llX", static_cast<unsigned long long>(top_rips[i].first));
				json sample{{"reader_rip", rbuf}, {"capture_count", top_rips[i].second}};
				for (const auto& n : nodes) {
					if (n.reader_rip == top_rips[i].first) {
						sample["module"] = n.module_name;
						sample["disasm"] = n.disasm_text;
						sample["node_read_count"] = n.read_count;
						break;
					}
				}
				top_reader_samples.push_back(std::move(sample));
			}

			const uint64_t total_reads = integrity_hunter::g_state.total_reads.load();
			const bool stimulus_observed = total_reads != 0 || !events.empty();
			json result;
			result["count"] = nodes.size();
			result["total_reads"] = total_reads;
			result["capture_event_count"] = events.size();
			result["read_capture_count"] = events.size();
			result["unique_reader_count"] = rip_counts.size();
			result["node_threshold_min_reads"] = 2;
			result["stimulus_observed"] = stimulus_observed;
			result["stimulus_state"] = stimulus_observed ? (nodes.empty() ? "captures_below_node_threshold" : "captures_promoted_to_nodes") : "no_read_stimulus_captured";
			if (!stimulus_observed)
				result["no_stimulus_reason"] = "page guard installed but no read/access captures were observed during duration_ms";
			if (stimulus_observed && nodes.empty())
				result["node_suppression_reason"] = "captured readers did not reach the repeated-read threshold required for integrity nodes";
			result["generation"] = generation;
			result["install_generation"] = integrity_hunter::g_state.install_generation.load(std::memory_order_acquire);
			result["install_complete"] = integrity_hunter::install_complete_for_generation(generation);
			result["install_success"] = integrity_hunter::install_success_for_generation(generation);
			result["worker_idle"] = idle_state.idle;
			result["target_address"] = addr_str;
			result["target_size"] = size;
			result["duration_ms"] = duration;
			result["top_event_samples"] = std::move(event_samples);
			result["top_reader_samples"] = std::move(top_reader_samples);
			result["nodes"] = arr;
			return tool_result_t::ok(result);
		}
	});

	srv.register_tool({
		"neutralize_integrity_node",
		"Neutralize a discovered integrity checker by patching its conditional branch to always pass. Use hunt_integrity_checkers first to discover nodes.",
		{
			{"node_index", "integer", "Index of the integrity node to neutralize (from hunt_integrity_checkers results)", true}
		},
		false,
		[](const json& params) -> tool_result_t {
			int index = params.value("node_index", -1);
			diag::log_tagged_fmt("analysis", "neutralize_integrity_node entry index=%d", index);
			if (index < 0) {
				diag::log_tagged("analysis", "neutralize_integrity_node refused invalid_index");
				return tool_result_t::error("node_index parameter is required");
			}

			bool ok = integrity_hunter::neutralize(index);
			diag::log_tagged_fmt("analysis", "neutralize_integrity_node result=%s index=%d",
				ok ? "ok" : "failed", index);

			json result;
			result["neutralized"] = ok;
			result["node_index"] = index;
			if (ok) {
				std::lock_guard<std::mutex> lk(integrity_hunter::g_state.mutex);
				if (index < static_cast<int>(integrity_hunter::g_state.nodes.size())) {
					auto& n = integrity_hunter::g_state.nodes[static_cast<size_t>(index)];
					char rbuf[32];
					std::snprintf(rbuf, sizeof(rbuf), "0x%llX", static_cast<unsigned long long>(n.reader_rip));
					result["reader_rip"] = rbuf;
					result["status"] = "neutralized";
				}
			} else {
				return tool_result_t::error("No conditional branch was found near the node RIP.");
			}
			return tool_result_t::ok(result);
		}
	});






	srv.register_tool({
		"taint_trace_register",
		"Perform taint analysis starting from specified registers or memory addresses. Traces taint propagation through all instructions to identify every instruction that touches the tainted data.",
		{{"start_address", "string", "Start address for taint tracing (hex)", true},
		 {"end_address", "string", "End address for taint tracing (hex)", true},
		 {"taint_registers", "string", "Comma-separated register names to taint initially (e.g. rdi,rsi)", false},
		 {"taint_memory", "string", "Comma-separated memory addresses to taint initially (hex)", false},
		 {"max_instructions", "number", "Maximum instructions to process (default 5000)", false}},
		true,
		[](const json& params) -> tool_result_t {
			std::string start_str = params.value("start_address", "");
			std::string end_str = params.value("end_address", "");
			diag::log_tagged_fmt("analysis", "taint_trace_register entry start=%s end=%s",
				start_str.c_str(), end_str.c_str());
			if (start_str.empty() || end_str.empty()) {
				diag::log_tagged("analysis", "taint_trace_register refused missing_params");
				return tool_result_t::error("start_address and end_address are required");
			}

			uint64_t start = 0;
			uint64_t end = 0;
			if (!parse_hex_u64(start_str, start) || !parse_hex_u64(end_str, end))
				return tool_result_t::error("invalid address range");
			const uint32_t max_insns = bounded_u32_param(params, "max_instructions", 5000, 1, 1000000);

			std::vector<std::string> taint_regs;
			{
				std::string regs_str = params.value("taint_registers", "");
				std::istringstream iss(regs_str);
				std::string tok;
				while (std::getline(iss, tok, ',')) {
					while (!tok.empty() && tok.front() == ' ') tok.erase(tok.begin());
					while (!tok.empty() && tok.back() == ' ') tok.pop_back();
					if (!tok.empty())
						taint_regs.push_back(tok);
				}
			}

			std::vector<std::pair<uint64_t, uint32_t>> taint_mem;
			{
				std::string mem_str = params.value("taint_memory", "");
				std::istringstream iss(mem_str);
				std::string tok;
				while (std::getline(iss, tok, ',')) {
					while (!tok.empty() && tok.front() == ' ') tok.erase(tok.begin());
					while (!tok.empty() && tok.back() == ' ') tok.pop_back();
					if (!tok.empty()) {
						uint64_t address = 0;
						if (!parse_hex_u64(tok, address))
							return tool_result_t::error("invalid taint_memory address");
						taint_mem.push_back({address, 1});
					}
				}
			}

			diag::log_tagged_fmt("analysis", "taint_trace_register running start=0x%llX end=0x%llX taint_regs=%zu taint_mem=%zu max_insns=%u",
				static_cast<unsigned long long>(start), static_cast<unsigned long long>(end),
				taint_regs.size(), taint_mem.size(), max_insns);
			auto result = symbolic_engine::taint_trace(start, end, max_insns, taint_regs, taint_mem);
			diag::log_tagged_fmt("analysis", "taint_trace_register complete total=%u tainted=%u",
				result.total_processed, result.tainted_count);

			json out;
			out["total_instructions"] = result.total_processed;
			out["tainted_instructions"] = result.tainted_count;

			json insns = json::array();
			for (auto& ti : result.tainted_instructions) {
				json obj;
				char abuf[32];
				std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(ti.address));
				obj["address"] = abuf;
				obj["disasm"] = ti.disasm;

				json src = json::array();
				for (auto& r : ti.read_regs) src.push_back(r);
				obj["source_regs"] = src;

				json dst = json::array();
				for (auto& r : ti.written_regs) dst.push_back(r);
				obj["dest_regs"] = dst;

				insns.push_back(obj);
			}
			out["instructions"] = insns;

			json tainted_regs_out = json::array();
			for (auto& r : result.tainted_registers)
				tainted_regs_out.push_back(r);
			out["final_tainted_registers"] = tainted_regs_out;

			json tainted_mem_out = json::array();
			for (auto addr : result.tainted_memory_addresses) {
				char abuf[32];
				std::snprintf(abuf, sizeof(abuf), "0x%llX", static_cast<unsigned long long>(addr));
				tainted_mem_out.push_back(abuf);
			}
			out["final_tainted_memory"] = tainted_mem_out;

			return tool_result_t::ok(out);
		}
	});

	srv.register_tool({
		"fuzzer_manage",
		"Manage snapshot-based function fuzzing. Actions: start, stop, results.",
		{{"action", "string", "start|stop|results", true},
		 {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false},
		 {"target_address", "string", "Hex address of the function to fuzz", false},
		 {"end_address", "string", "Hex address where execution should stop", false},
		 {"input_address", "string", "Hex address of the input buffer in target memory", false},
		 {"input_size", "integer", "Size of input buffer in bytes", false},
		 {"max_iterations", "integer", "Maximum fuzzing iterations", false}},
		false,
		[](const json& params) -> tool_result_t {
			const std::string action = compat_action_name(params);
			const json p = compat_action_payload(params);
			if (action == "start") return fuzzer_manage_start(p);
			if (action == "stop") return fuzzer_manage_stop(p);
			if (action == "results") return fuzzer_manage_results(p);
			return compat_unknown_action("fuzzer_manage", action);
		}
	});

	srv.register_tool({
		"live_monitor_manage",
		"Manage live struct monitoring. Actions: start, stop, status.",
		{{"action", "string", "start|stop|status", true},
		 {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false},
		 {"address", "string", "Base address of the struct in hex", false},
		 {"size", "integer", "Size of the struct in bytes", false},
		 {"name", "string", "Name for the struct", false},
		 {"backend", "string", "Backend preference: auto, page_guard, polling, hardware_breakpoint", false},
		 {"timeout_ms", "integer", "Maximum backend startup wait in milliseconds", false},
		 {"require_captures", "boolean", "Return an error if no accesses were captured", false}},
		false,
		[](const json& params) -> tool_result_t {
			const std::string action = compat_action_name(params);
			const json p = compat_action_payload(params);
			if (action == "start") return live_monitor_manage_start(p);
			if (action == "stop") return live_monitor_manage_stop(p);
			if (action == "status") return live_monitor_snapshot(false);
			return compat_unknown_action("live_monitor_manage", action);
		}
	});

	srv.register_tool({
		"symbolic_execution",
		"Run symbolic analysis actions. Actions: deobfuscate, slice_function, solve_path.",
		{{"action", "string", "deobfuscate|slice_function|solve_path", true},
		 {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false},
		 {"entry_address", "string", "Entry address for deobfuscation", false},
		 {"start_address", "string", "Start address for slicing or path solving", false},
		 {"end_address", "string", "End address for slicing", false},
		 {"target_address", "string", "Target address for path solving", false},
		 {"target_register", "string", "Target register for slicing", false},
		 {"symbolic_registers", "string", "Comma-separated symbolic registers", false},
		 {"max_instructions", "number", "Maximum instructions to process", false}},
		true,
		[](const json& params) -> tool_result_t {
			const std::string action = compat_action_name(params);
			const json p = compat_action_payload(params);
			if (action == "deobfuscate") return symbolic_manage_deobfuscate(p);
			if (action == "slice_function") return symbolic_manage_slice(p);
			if (action == "solve_path") return symbolic_manage_solve_path(p);
			return compat_unknown_action("symbolic_execution", action);
		}
	});

	srv.register_tool({
		"analysis_query",
		"Query binary analysis metadata. Actions: imports, exports, types, type_definition, pdb_symbols, binary_map_overview, xref_db_stats.",
		{{"action", "string", "imports|exports|types|type_definition|pdb_symbols|binary_map_overview|xref_db_stats", true},
		 {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false},
		 {"module_name", "string", "Optional loaded module name or path suffix", false},
		 {"name", "string", "Type name for type_definition", false},
		 {"module", "string", "Optional module filter", false},
		 {"filter", "string", "Optional substring filter", false},
		 {"limit", "number", "Maximum rows to return", false},
		 {"max_entries", "integer", "Maximum import/export rows to return", false},
		 {"timeout_ms", "integer", "Maximum parse time before returning partial results", false},
		 {"functions_only", "boolean", "Return only function PDB symbols", false},
		 {"max_functions", "number", "Maximum binary-map functions", false},
		 {"max_globals", "number", "Maximum binary-map globals", false},
		 {"max_imports", "number", "Maximum binary-map imports on fast summary", false},
		 {"max_exports", "number", "Maximum binary-map exports on fast summary", false},
		 {"fast_summary", "boolean", "Use cheap binary-map summary without xref generation", false},
		 {"include_imports", "boolean", "Include imports in binary-map overview", false},
		 {"include_exports", "boolean", "Include exports in binary-map overview", false},
		 {"include_xrefs", "boolean", "Include xref summaries in binary-map overview", false}},
		true,
		{}},
		workspace_analysis_query);

	srv.register_tool({
		"analysis_benchmark_manage",
		"Manage hyper-performance benchmark runs against synthetic or real artifacts. Actions: run_synthetic, run_real, status, last_result, compare.",
		{{"action", "string", "run_synthetic|run_real|status|last_result|compare", true},
		 {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false},
		 {"code_mb", "integer", "Synthetic code size in MiB (8..320) for run_synthetic", false},
		 {"seed", "string", "Hex seed for the deterministic synthetic generator", false},
		 {"lanes", "integer", "Decode worker lanes (0 = engine default)", false},
		 {"path", "string", "Real fixture path for run_real (300..500 MB program gate)", false},
		 {"sla_relaxed", "boolean", "Record the measurement without failing SLA verdicts", false},
		 {"batch_lanes", "integer", "Requested parallel decompile batch lane budget (0 = engine default)", false},
		 {"sample_ms", "integer", "Runtime memory/worker sampler interval in ms (50..10000)", false},
		 {"baseline", "string", "Baseline report JSON path: run_synthetic/run_real compare against it; compare action baseline", false},
		 {"record_baseline", "string", "Record the scorecard as a named baseline under benchmark_results/baselines", false},
		 {"candidate", "string", "Candidate report JSON path for the compare action", false},
		 {"run_scaling_stage", "boolean", "Run the worker-budget scaling stage", false},
		 {"run_determinism_stage", "boolean", "Run the snapshot determinism stage", false},
		 {"scaling_worker_budgets", "string", "Comma-separated worker budgets for the scaling stage", false},
		 {"determinism_runs", "integer", "Determinism repetitions at the tail budget (1..8)", false},
		 {"run_cancellation_stage", "boolean", "Run the cancellation p95 measurement stage (real mode; on by default)", false},
		 {"cancellation_samples", "integer", "Cancellation measurement samples (1..8)", false}},
		false,
		[](const json& params) -> tool_result_t {
			const std::string action = compat_action_name(params);
			const json p = compat_action_payload(params);
			if (action == "compare") {
				const std::string baseline_path = p.value("baseline", std::string());
				const std::string candidate_path = p.value("candidate", std::string());
				if (baseline_path.empty() || candidate_path.empty())
					return tool_result_t::error("compare requires baseline and candidate report paths");
				const auto load_report = [](const std::string& path, json& out) -> bool {
					std::ifstream stream(std::filesystem::u8path(path), std::ios::binary);
					if (!stream)
						return false;
					try {
						stream >> out;
					} catch (const json::exception&) {
						return false;
					}
					return stream.good() || stream.eof();
				};
				json baseline_report;
				json candidate_report;
				if (!load_report(baseline_path, baseline_report))
					return tool_result_t::error("compare baseline report is unavailable or invalid: " + baseline_path);
				if (!load_report(candidate_path, candidate_report))
					return tool_result_t::error("compare candidate report is unavailable or invalid: " + candidate_path);
				auto verdict = aida::analysis::benchmark::compare_scorecards(
					baseline_report, candidate_report);
				verdict["baseline"] = baseline_path;
				verdict["candidate"] = candidate_path;
				diag::log_tagged_fmt("analysis",
					"analysis_benchmark_manage compare overall=%s baseline=%s candidate=%s",
					verdict.value("overall", std::string()).c_str(),
					baseline_path.c_str(), candidate_path.c_str());
				return tool_result_t::ok(verdict);
			}
			if (action == "run_synthetic" || action == "run_real") {
				aida::analysis::benchmark::benchmark_run_request_t request;
				if (action == "run_synthetic") {
					request.mode = aida::analysis::benchmark::benchmark_mode_t::synthetic;
					if (p.contains("code_mb") && p["code_mb"].is_number()) {
						const auto code_mb = p["code_mb"].get<std::uint64_t>();
						if (code_mb < 8 || code_mb > 320)
							return tool_result_t::error("code_mb must be within 8..320");
						request.synthetic_code_bytes = code_mb * 1024ULL * 1024ULL;
					}
					if (p.contains("seed") && p["seed"].is_string()) {
						const std::string seed_text = p["seed"].get<std::string>();
						std::string_view seed_view(seed_text);
						if (seed_view.size() > 2 && seed_view[0] == '0' &&
							(seed_view[1] == 'x' || seed_view[1] == 'X'))
							seed_view.remove_prefix(2);
						if (seed_view.empty())
							return tool_result_t::error("seed must be a hexadecimal integer");
						std::size_t consumed = 0;
						const std::string narrowed(seed_view);
						unsigned long long seed_value = 0;
						try {
							seed_value = std::stoull(narrowed, &consumed, 16);
						} catch (const std::exception&) {
							return tool_result_t::error("seed must be a hexadecimal integer");
						}
						if (consumed != narrowed.size())
							return tool_result_t::error("seed must be a hexadecimal integer");
						request.synthetic_seed = static_cast<std::uint64_t>(seed_value);
					}
				} else {
					request.mode = aida::analysis::benchmark::benchmark_mode_t::real;
					request.real_path = p.value("path", std::string());
					if (request.real_path.empty())
						return tool_result_t::error("path is required for run_real");
				}
				if (p.contains("lanes") && p["lanes"].is_number()) {
					const auto lanes = p["lanes"].get<std::uint64_t>();
					if (lanes > 64)
						return tool_result_t::error("lanes must be within 0..64");
					request.lanes = static_cast<std::uint32_t>(lanes);
				}
				if (p.contains("sla_relaxed") && p["sla_relaxed"].is_boolean())
					request.sla_relaxed = p["sla_relaxed"].get<bool>();
				if (p.contains("batch_lanes") && p["batch_lanes"].is_number()) {
					const auto batch_lanes = p["batch_lanes"].get<std::uint64_t>();
					if (batch_lanes > 64)
						return tool_result_t::error("batch_lanes must be within 0..64");
					request.decompile_batch_lanes = static_cast<std::uint32_t>(batch_lanes);
				}
				if (p.contains("sample_ms") && p["sample_ms"].is_number()) {
					const auto sample_ms = p["sample_ms"].get<std::uint64_t>();
					if (sample_ms < 50 || sample_ms > 10000)
						return tool_result_t::error("sample_ms must be within 50..10000");
					request.memory_sample_interval_ms = static_cast<std::uint32_t>(sample_ms);
				}
				if (p.contains("baseline") && p["baseline"].is_string())
					request.baseline_report_path = p["baseline"].get<std::string>();
				if (p.contains("record_baseline") && p["record_baseline"].is_string())
					request.record_baseline_name = p["record_baseline"].get<std::string>();
				if (p.contains("run_scaling_stage") && p["run_scaling_stage"].is_boolean())
					request.run_scaling_stage = p["run_scaling_stage"].get<bool>();
				if (p.contains("run_determinism_stage") && p["run_determinism_stage"].is_boolean())
					request.run_determinism_stage = p["run_determinism_stage"].get<bool>();
				if (p.contains("scaling_worker_budgets") && p["scaling_worker_budgets"].is_string()) {
					const std::string csv = p["scaling_worker_budgets"].get<std::string>();
					std::vector<std::uint32_t> budgets;
					std::size_t offset = 0;
					bool parse_failed = csv.empty();
					while (!parse_failed && offset <= csv.size()) {
						const auto comma = csv.find(',', offset);
						const std::string token = csv.substr(offset,
							comma == std::string::npos ? std::string::npos : comma - offset);
						if (token.empty()) {
							parse_failed = true;
							break;
						}
						std::size_t consumed = 0;
						unsigned long value = 0;
						try {
							value = std::stoul(token, &consumed, 10);
						} catch (const std::exception&) {
							parse_failed = true;
							break;
						}
						if (consumed != token.size() || value > 64) {
							parse_failed = true;
							break;
						}
						budgets.push_back(static_cast<std::uint32_t>(value));
						if (comma == std::string::npos)
							break;
						offset = comma + 1;
					}
					if (parse_failed || budgets.empty())
						return tool_result_t::error(
							"scaling_worker_budgets must be a comma-separated list of integers within 0..64");
					request.scaling_worker_budgets = std::move(budgets);
				}
				if (p.contains("determinism_runs") && p["determinism_runs"].is_number()) {
					const auto runs = p["determinism_runs"].get<std::uint64_t>();
					if (runs < 1 || runs > 8)
						return tool_result_t::error("determinism_runs must be within 1..8");
					request.determinism_runs = static_cast<std::uint32_t>(runs);
				}
				if (p.contains("run_cancellation_stage") && p["run_cancellation_stage"].is_boolean())
					request.run_cancellation_stage = p["run_cancellation_stage"].get<bool>();
				if (p.contains("cancellation_samples") && p["cancellation_samples"].is_number()) {
					const auto samples = p["cancellation_samples"].get<std::uint64_t>();
					if (samples < 1 || samples > 8)
						return tool_result_t::error("cancellation_samples must be within 1..8");
					request.cancellation_samples = static_cast<std::uint32_t>(samples);
				}
				diag::log_tagged_fmt("analysis",
					"analysis_benchmark_manage submit action=%s code_bytes=%llu seed=0x%llX lanes=%u path=%s relaxed=%d batch_lanes=%u sample_ms=%u baseline=%s record_baseline=%s scaling=%d determinism=%d cancellation=%d cancellation_samples=%u",
					action.c_str(),
					static_cast<unsigned long long>(request.synthetic_code_bytes),
					static_cast<unsigned long long>(request.synthetic_seed),
					static_cast<unsigned>(request.lanes),
					request.real_path.c_str(),
					request.sla_relaxed ? 1 : 0,
					static_cast<unsigned>(request.decompile_batch_lanes),
					static_cast<unsigned>(request.memory_sample_interval_ms),
					request.baseline_report_path.c_str(),
					request.record_baseline_name.c_str(),
					request.run_scaling_stage ? 1 : 0,
					request.run_determinism_stage ? 1 : 0,
					request.run_cancellation_stage ? 1 : 0,
					static_cast<unsigned>(request.cancellation_samples));
				if (!aida::analysis::benchmark::start_benchmark_async(request)) {
					diag::log_tagged("analysis", "analysis_benchmark_manage refused already_active");
					return tool_result_t::error("a benchmark run is already active");
				}
				json result{{"accepted", true},
					{"mode", action == "run_synthetic" ? "synthetic" : "real"}};
				return tool_result_t::ok(result);
			}
			if (action == "status")
				return tool_result_t::ok(aida::analysis::benchmark::benchmark_run_status());
			if (action == "last_result")
				return tool_result_t::ok(aida::analysis::benchmark::benchmark_last_result());
			return compat_unknown_action("analysis_benchmark_manage", action);
		}
	});

}

}
