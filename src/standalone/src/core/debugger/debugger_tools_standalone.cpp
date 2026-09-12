

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "standalone_compat.hpp"
#include "debugger_engine.hpp"
#include "comm.h"
#include "pro.h"
#include "../runtime/standalone_driver.hpp"
#include "../runtime/standalone_driver_identity.hpp"
#include "zydis_disasm.hpp"
#include "xref_engine.hpp"
#include "cfg_view.hpp"
#include "seh_view.hpp"
#include "module_view.hpp"
#include "pe_parser.hpp"
#include "code_patcher.hpp"
#include "stealth_engine.hpp"
#include "../editor/expression_eval.hpp"
#include "../../helpers/diag_log.hpp"
#include "../diagnostics/metadata_ring.hpp"
#include "../mcp/downstream_producer_governor.hpp"

#include <algorithm>
#include <atomic>
#include <array>
#include <chrono>
#include <memory>
#include <cctype>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

namespace debugger_tools
{


struct driver_debugger_quota_guard_t
{
    std::uint64_t token = 0;
    std::string tool_name;
    std::uint32_t target_pid = 0;

    driver_debugger_quota_guard_t() = default;
    driver_debugger_quota_guard_t(const driver_debugger_quota_guard_t&) = delete;
    driver_debugger_quota_guard_t& operator=(const driver_debugger_quota_guard_t&) = delete;
    driver_debugger_quota_guard_t(driver_debugger_quota_guard_t&& o) noexcept
        : token(o.token), tool_name(std::move(o.tool_name)), target_pid(o.target_pid)
    { o.token = 0; }
    driver_debugger_quota_guard_t& operator=(driver_debugger_quota_guard_t&& o) noexcept
    {
        if (this != &o) { release(); token = o.token; tool_name = std::move(o.tool_name); target_pid = o.target_pid; o.token = 0; }
        return *this;
    }
    ~driver_debugger_quota_guard_t() { release(); }
    void release()
    {
        if (token == 0) return;
        if (mcp_standalone::downstream::governor_t::instance().is_admitted(token))
        {
            diag::log_tagged_fmt("dbg_tools",
                "DRIVER-DEBUGGER-QUOTA-RELEASE tool=%s target_pid=%u token=%llu",
                tool_name.c_str(), target_pid, static_cast<unsigned long long>(token));
            aida::diagnostics::breadcrumb_options_t opts{};
            opts.category = aida::diagnostics::breadcrumb_category_t::driver_debugger;
            opts.label = "driver_debugger_release";
            opts.reason = "scope_exit";
            opts.owner_subsystem = "debugger_tools";
            opts.tool_or_request_id = tool_name.c_str();
            opts.lease_token = token;
            opts.status_code = 0;
            aida::diagnostics::emit_breadcrumb(std::move(opts));
            mcp_standalone::downstream::governor_t::instance().release(token, "driver_debugger_scope_exit");
        }
        else
        {
            diag::log_tagged_fmt("dbg_tools",
                "DRIVER-DEBUGGER-QUOTA-STALE-RESULT tool=%s target_pid=%u token=%llu",
                tool_name.c_str(), target_pid, static_cast<unsigned long long>(token));
            aida::diagnostics::breadcrumb_options_t opts{};
            opts.category = aida::diagnostics::breadcrumb_category_t::driver_debugger;
            opts.label = "driver_debugger_stale_result";
            opts.reason = "stale_result";
            opts.owner_subsystem = "debugger_tools";
            opts.tool_or_request_id = tool_name.c_str();
            opts.lease_token = token;
            opts.status_code = 1;
            aida::diagnostics::emit_breadcrumb(std::move(opts));
        }
        token = 0;
    }
};

static std::optional<tool_result_t> acquire_driver_debugger_quota(
    const char* tool_name, std::uint32_t target_pid,
    driver_debugger_quota_guard_t& guard)
{
    mcp_standalone::downstream::producer_identity_t id;
    id.kind = mcp_standalone::downstream::producer_kind_t::driver_debugger;
    id.tool_name = tool_name ? tool_name : "";
    id.target_pid = target_pid;
    id.target_id = target_pid != 0 ? ("pid:" + std::to_string(target_pid)) : "";
    id.principal_id = "standalone";
    const char* diag_id = mcp_standalone::current_call_diag_id();
    if (diag_id) id.diagnostic_id = diag_id;
    const char* req_id = mcp_standalone::current_call_request_id();
    if (req_id) id.request_id = req_id;
    id.deadline_ms = mcp_standalone::current_call_deadline_ms();

    auto result = mcp_standalone::downstream::governor_t::instance().try_admit(id);
    if (!result.admitted)
    {
        diag::log_tagged_fmt("dbg_tools",
            "DRIVER-DEBUGGER-QUOTA-REJECT tool=%s target_pid=%u reason=%s quota=%s scope=%s observed=%zu limit=%zu",
            id.tool_name.c_str(), id.target_pid,
            result.reason.c_str(), result.quota_name.c_str(),
            result.quota_scope.c_str(), result.observed, result.limit);
        aida::diagnostics::breadcrumb_options_t opts{};
        opts.category = aida::diagnostics::breadcrumb_category_t::driver_debugger;
        opts.label = "driver_debugger_reject";
        opts.reason = "capacity_rejected";
        opts.owner_subsystem = "debugger_tools";
        opts.tool_or_request_id = id.tool_name.c_str();
        opts.status_code = 1;
        aida::diagnostics::emit_breadcrumb(std::move(opts));
        return tool_result_t::error(
            "Downstream driver/debugger capacity exhausted; work was not started.",
            "MCP_DOWNSTREAM_CAPACITY_REJECT",
            mcp_standalone::downstream::rejection_json(result, id));
    }

    diag::log_tagged_fmt("dbg_tools",
        "DRIVER-DEBUGGER-QUOTA-ADMIT tool=%s target_pid=%u token=%llu",
        id.tool_name.c_str(), id.target_pid,
        static_cast<unsigned long long>(result.admission_token));

    aida::diagnostics::breadcrumb_options_t admit_opts{};
    admit_opts.category = aida::diagnostics::breadcrumb_category_t::driver_debugger;
    admit_opts.label = "driver_debugger_admit";
    admit_opts.reason = "operation_start";
    admit_opts.owner_subsystem = "debugger_tools";
    admit_opts.tool_or_request_id = id.tool_name.c_str();
    admit_opts.session_or_target = id.target_id.c_str();
    admit_opts.lease_token = result.admission_token;
    admit_opts.status_code = 0;
    aida::diagnostics::emit_breadcrumb(std::move(admit_opts));

    guard.token = result.admission_token;
    guard.tool_name = id.tool_name;
    guard.target_pid = id.target_pid;
    return std::nullopt;
}


static bool is_process_alive(std::uint32_t pid)
{
    if (pid == 0)
        return false;
    struct process_handle_closer_t {
        void operator()(void* value) const noexcept {
            if (value) ::CloseHandle(static_cast<HANDLE>(value));
        }
    };
    using unique_process_handle_t = std::unique_ptr<void, process_handle_closer_t>;
    unique_process_handle_t process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!process)
        return false;
    DWORD exit_code = 0;
    const bool ok = GetExitCodeProcess(static_cast<HANDLE>(process.get()), &exit_code) != FALSE;
    return ok && exit_code == STILL_ACTIVE;
}

static std::optional<tool_result_t> ensure_attached(const json& params)
{
    diag::log_tagged_fmt("dbg_tools", "ensure_attached: entry");
    if (!device->is_connected()) {
        diag::log_tagged_fmt("dbg_tools", "ensure_attached: driver not connected");
        return tool_result_t::error(std::string("Driver bridge is not connected. Attach with sessions_manage action=attach_pid first."));
    }
    std::string kernel_reason;
    const bool kernel_ready = driver_bridge::using_kernel_driver() &&
        driver_bridge::kernel_session_available(&kernel_reason);
    if (!kernel_ready) {
        diag::log_tagged_fmt("dbg_tools", "ensure_attached: kernel path unavailable loaded=%d kernel=%d reason=%s status=%s last_error=%s",
            driver_bridge::is_loaded() ? 1 : 0,
            driver_bridge::using_kernel_driver() ? 1 : 0,
            kernel_reason.empty() ? "<empty>" : kernel_reason.c_str(),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        std::string detail = kernel_reason.empty() ? driver_bridge::last_error() : kernel_reason;
        if (detail.empty())
            detail = "kernel_driver_unavailable";
        return tool_result_t::error(std::string("Kernel driver path is unavailable for debugger target operations: ") +
            detail);
    }

    std::uint32_t requested_pid = 0;
    for (const char* key : {"target_pid", "process_id", "pid"})
    {
        if (!params.contains(key))
            continue;
        const auto& v = params[key];
        if (v.is_number_unsigned())
            requested_pid = static_cast<std::uint32_t>(v.get<std::uint64_t>());
        else if (v.is_number_integer())
            requested_pid = static_cast<std::uint32_t>(v.get<std::int64_t>());
        else if (v.is_string())
        {
            auto addr = sa_parse_address(v.get<std::string>());
            if (addr) requested_pid = static_cast<std::uint32_t>(*addr);
        }
        if (requested_pid != 0)
            break;
    }

    const std::uint32_t current_pid = driver_bridge::attached_pid();
    if (requested_pid != 0 && requested_pid != current_pid)
    {
        diag::log_tagged_fmt("dbg_tools", "ensure_attached: switching active pid from %u to %u", current_pid, requested_pid);
        if (!is_process_alive(requested_pid)) {
            diag::log_tagged_fmt("dbg_tools", "ensure_attached: target_pid %u not alive", requested_pid);
            return tool_result_t::error(std::string("target_pid ") + std::to_string(requested_pid) + std::string(" is not alive."));
        }

        const auto attached = driver_bridge::attached_pids();
        bool in_map = false;
        for (auto p : attached) { if (p == requested_pid) { in_map = true; break; } }
        if (!in_map)
        {
            diag::log_tagged_fmt("dbg_tools", "ensure_attached: calling attach_additional for pid %u", requested_pid);
            if (!driver_bridge::attach_additional(requested_pid))
            {
                diag::log_tagged_fmt("dbg_tools", "ensure_attached: attach_additional failed for pid %u", requested_pid);
                return tool_result_t::error(
                    std::string("attach_additional failed for target_pid ") + std::to_string(requested_pid) +
                    std::string(": ") + driver_bridge::last_error());
            }
        }

        if (current_pid != 0)
            stealth_engine::disable_for_detach(current_pid, "debugger_tools.ensure_attached.replace");

        if (!driver_bridge::set_active_pid(requested_pid)) {
            if (current_pid != 0 && driver_bridge::attached_pid() == current_pid)
                (void)stealth_engine::ensure_default_enabled(current_pid, "debugger_tools.ensure_attached.restore_failed_switch");
            diag::log_tagged_fmt("dbg_tools", "ensure_attached: set_active_pid failed for pid %u", requested_pid);
            return tool_result_t::error(
                std::string("set_active_pid failed for target_pid ") + std::to_string(requested_pid) +
                std::string(": ") + driver_bridge::last_error());
        }

        (void)stealth_engine::ensure_default_enabled(requested_pid, "debugger_tools.ensure_attached");

        if (device->get_dtb() == 0)
        {
            device->solve_dtb();
            if (device->get_dtb() == 0) {
                diag::log_tagged_fmt("dbg_tools", "ensure_attached: DTB solve failed for pid %u", requested_pid);
                return tool_result_t::error(
                    std::string("Failed to solve DTB for target_pid ") +
                    std::to_string(requested_pid) + std::string("."));
            }
        }
        diag::log_tagged_fmt("dbg_tools", "ensure_attached: switched to pid %u ok", requested_pid);
    }

    if (driver_bridge::attached_pid() == 0) {
        diag::log_tagged_fmt("dbg_tools", "ensure_attached: not attached");
        return tool_result_t::error(std::string("Not attached. Use sessions_manage action=attach_pid or pass target_pid."));
    }

    if (!is_process_alive(driver_bridge::attached_pid()))
    {
        const std::uint32_t dead_pid = driver_bridge::attached_pid();
        diag::log_tagged_fmt("dbg_tools", "ensure_attached: attached pid %u is dead", dead_pid);
        device->clear_process_context();
        return tool_result_t::error(
            std::string("Attached process PID ") + std::to_string(dead_pid) +
            std::string(" is no longer alive. Reattach with sessions_manage action=attach_pid."));
    }

    if (device->get_dtb() == 0)
    {
        device->solve_dtb();
        if (device->get_dtb() == 0) {
            diag::log_tagged_fmt("dbg_tools", "ensure_attached: DTB solve failed for attached pid");
            return tool_result_t::error(std::string("Failed to solve DTB for the attached process."));
        }
    }
    diag::log_tagged_fmt("dbg_tools", "ensure_attached: ok pid=%u", driver_bridge::attached_pid());

    return std::nullopt;
}

struct cfg_publication_binding_t
{
    driver_bridge::identity::live_target_identity_t target;
    std::uint64_t model_generation = 0;
    std::uint64_t entry_addr = 0;
    bool valid = false;
};

static std::mutex g_cfg_request_mutex;
static std::mutex g_cfg_binding_mutex;
static cfg_publication_binding_t g_cfg_binding;

enum class cfg_wait_result_t : std::uint8_t
{
    completed,
    cancelled,
    deadline,
    timeout
};

static cfg_wait_result_t wait_for_cfg_publication_idle(std::uint64_t timeout_ms)
{
    const std::uint64_t started = GetTickCount64();
    const std::uint64_t timeout_at = started >
        (std::numeric_limits<std::uint64_t>::max)() - timeout_ms
        ? (std::numeric_limits<std::uint64_t>::max)()
        : started + timeout_ms;
    while (cfg_view::building())
    {
        if (mcp_standalone::current_call_cancelled())
            return cfg_wait_result_t::cancelled;
        const std::uint64_t now = GetTickCount64();
        const std::uint64_t call_deadline = mcp_standalone::current_call_deadline_ms();
        if (call_deadline != 0 && now >= call_deadline)
            return cfg_wait_result_t::deadline;
        if (now >= timeout_at)
            return cfg_wait_result_t::timeout;
        Sleep(10);
    }
    return cfg_wait_result_t::completed;
}

static std::optional<tool_result_t> cfg_wait_error(cfg_wait_result_t result,
                                                   const char* operation)
{
    switch (result)
    {
    case cfg_wait_result_t::completed:
        return std::nullopt;
    case cfg_wait_result_t::cancelled:
        diag::log_tagged_fmt("dbg_tools", "%s: cancelled while waiting for CFG publication", operation);
        return tool_result_t::error("Tool cancelled during CFG build.");
    case cfg_wait_result_t::deadline:
        diag::log_tagged_fmt("dbg_tools", "%s: call deadline expired while waiting for CFG publication", operation);
        return tool_result_t::error("Tool deadline expired during CFG build.");
    case cfg_wait_result_t::timeout:
        diag::log_tagged_fmt("dbg_tools", "%s: timed out waiting for CFG publication", operation);
        return tool_result_t::error("CFG build did not complete within 3000 ms.");
    }
    return tool_result_t::error("CFG publication wait failed.");
}

static void invalidate_cfg_binding()
{
    std::lock_guard<std::mutex> lock(g_cfg_binding_mutex);
    g_cfg_binding = {};
}

static std::optional<tool_result_t> capture_cfg_target_identity(
    driver_bridge::identity::live_target_identity_t& identity)
{
    std::string error;
    const std::uint32_t pid = driver_bridge::attached_pid();
    if (pid == 0 || !driver_bridge::identity::capture_live_target_identity(
        pid, 0, identity, &error))
    {
        if (error.empty())
            error = "live_target_identity_unavailable";
        diag::log_tagged_fmt("dbg_tools",
            "CFG target identity capture failed pid=%u error=%s", pid, error.c_str());
        return tool_result_t::error(
            "Unable to capture the attached CFG target identity: " + error);
    }
    return std::nullopt;
}

static std::optional<tool_result_t> validate_cfg_target_identity(
    const driver_bridge::identity::live_target_identity_t& identity,
    const char* operation)
{
    const auto validation =
        driver_bridge::identity::validate_attached_target_identity(identity);
    if (validation.matches)
        return std::nullopt;
    const char* code = driver_bridge::identity::staleness_code(validation.staleness);
    const std::string detail = validation.detail.empty()
        ? std::string(code ? code : "live_target_identity_changed")
        : validation.detail;
    diag::log_tagged_fmt("dbg_tools",
        "%s: CFG target identity validation failed pid=%u reason=%s detail=%s",
        operation, identity.process.pid, code ? code : "unknown", detail.c_str());
    return tool_result_t::error(
        "Attached CFG target identity changed during the operation: " + detail);
}

static std::optional<std::uint32_t> parse_tid(const json& params)
{
    if (!params.contains("tid")) {
        diag::log_tagged_fmt("dbg_tools", "parse_tid: no tid param");
        return std::nullopt;
    }
    const auto& v = params["tid"];
    std::uint32_t tid = 0;
    if (v.is_number_unsigned())
        tid = static_cast<std::uint32_t>(v.get<std::uint64_t>());
    else if (v.is_number_integer())
        tid = static_cast<std::uint32_t>(v.get<std::int64_t>());
    else if (v.is_string())
    {
        auto addr = sa_parse_address(v.get<std::string>());
        if (addr) tid = static_cast<std::uint32_t>(*addr);
    }
    if (tid != 0)
        diag::log_tagged_fmt("dbg_tools", "parse_tid: resolved tid=%u", tid);
    else
        diag::log_tagged_fmt("dbg_tools", "parse_tid: failed to parse tid");
    return (tid != 0) ? std::optional<std::uint32_t>{tid} : std::nullopt;
}

static int int_param_clamped(const json& params, const char* key, int fallback, int lo, int hi)
{
    int value = fallback;
    if (params.contains(key)) {
        const auto& v = params[key];
        if (v.is_number_unsigned()) {
            auto raw = v.get<std::uint64_t>();
            value = raw > static_cast<std::uint64_t>(hi) ? hi : static_cast<int>(raw);
        } else if (v.is_number_integer()) {
            auto raw = v.get<std::int64_t>();
            if (raw < static_cast<std::int64_t>(lo))
                value = lo;
            else if (raw > static_cast<std::int64_t>(hi))
                value = hi;
            else
                value = static_cast<int>(raw);
        }
        else if (v.is_string()) {
            auto parsed = sa_parse_address(v.get<std::string>());
            if (parsed)
                value = static_cast<int>(*parsed);
        }
    }
    return std::clamp(value, lo, hi);
}

static bool deadline_expired(const std::chrono::steady_clock::time_point& deadline)
{
    return std::chrono::steady_clock::now() >= deadline || mcp_standalone::current_call_cancelled();
}

static bool modules_detail_deadline_expired(const std::chrono::steady_clock::time_point* deadline)
{
    return deadline && deadline_expired(*deadline);
}

static bool read_target_memory_exact(std::uint64_t addr, void* buf, std::size_t size)
{
    std::vector<std::uint8_t> tmp;
    if (!driver_bridge::read_memory(addr, size, tmp))
        return false;
    if (tmp.size() < size)
        return false;
    std::memcpy(buf, tmp.data(), size);
    return true;
}

static bool read_target_c_string(std::uint64_t addr, std::size_t max_len, std::string& out)
{
    out.clear();
    constexpr std::size_t chunk = 256;
    std::size_t total = 0;
    while (total < max_len) {
        std::size_t to_read = chunk;
        if (total + to_read > max_len)
            to_read = max_len - total;
        std::vector<std::uint8_t> tmp;
        if (!driver_bridge::read_memory(addr + total, to_read, tmp) || tmp.empty())
            break;
        for (std::uint8_t b : tmp) {
            if (b == 0)
                return true;
            out.push_back(static_cast<char>(b));
            if (out.size() >= max_len)
                return true;
        }
        if (tmp.size() < to_read)
            break;
        total += tmp.size();
    }
    return !out.empty();
}

static bool image_range_available(const std::vector<std::uint8_t>& image, std::uint64_t rva, std::uint64_t size)
{
    const std::uint64_t image_size = static_cast<std::uint64_t>(image.size());
    return rva <= image_size && size <= image_size - rva;
}

template <typename T>
static bool image_read_value(const std::vector<std::uint8_t>& image, std::uint64_t rva, T& out)
{
    if (!image_range_available(image, rva, sizeof(T)))
        return false;
    std::memcpy(&out, image.data() + static_cast<std::size_t>(rva), sizeof(T));
    return true;
}

static bool image_read_bytes(const std::vector<std::uint8_t>& image, std::uint64_t rva, void* out, std::size_t size)
{
    if (out == nullptr || !image_range_available(image, rva, size))
        return false;
    std::memcpy(out, image.data() + static_cast<std::size_t>(rva), size);
    return true;
}

static bool image_read_c_string(const std::vector<std::uint8_t>& image, std::uint64_t rva, std::size_t max_len, std::string& out)
{
    out.clear();
    if (!image_range_available(image, rva, 1))
        return false;
    const std::size_t start = static_cast<std::size_t>(rva);
    const std::size_t available = image.size() - start;
    const std::size_t limit = std::min<std::size_t>(available, max_len);
    out.reserve(std::min<std::size_t>(limit, 128));
    for (std::size_t i = 0; i < limit; ++i) {
        const std::uint8_t b = image[start + i];
        if (b == 0)
            return true;
        out.push_back(static_cast<char>(b));
    }
    return !out.empty();
}

static bool read_module_image_for_modules_detail(const driver_bridge::module_info_t& module,
                                                 std::vector<std::uint8_t>& image,
                                                 std::string& status)
{
    image.clear();
    status.clear();
    constexpr std::uint64_t max_image_bytes = 64ull * 1024ull * 1024ull;
    if (module.base == 0 || module.size == 0) {
        status = "invalid_module_range";
        return false;
    }
    if (static_cast<std::uint64_t>(module.size) > max_image_bytes) {
        status = "module_too_large_for_fast_image";
        return false;
    }
    if (!driver_bridge::read_memory(module.base, static_cast<std::size_t>(module.size), image)) {
        status = "read_memory_failed";
        return false;
    }
    if (image.size() < 0x1000) {
        status = "image_read_too_small";
        return false;
    }
    status = image.size() < static_cast<std::size_t>(module.size) ? "partial_image_read" : "complete_image_read";
    return true;
}

static bool parse_pe_from_module_image(std::uint64_t module_base,
                                       const std::vector<std::uint8_t>& image,
                                       pe_parser::pe_info_t& out)
{
    out = {};
    std::uint16_t dos_magic = 0;
    if (!image_read_value(image, 0, dos_magic) || dos_magic != IMAGE_DOS_SIGNATURE)
        return false;
    std::uint32_t e_lfanew = 0;
    if (!image_read_value(image, 0x3C, e_lfanew) || e_lfanew > 0x1000)
        return false;
    std::uint32_t nt_sig = 0;
    if (!image_read_value(image, e_lfanew, nt_sig) || nt_sig != IMAGE_NT_SIGNATURE)
        return false;

    const std::uint64_t file_header_rva = static_cast<std::uint64_t>(e_lfanew) + sizeof(std::uint32_t);
    std::uint16_t num_sections = 0;
    std::uint16_t opt_header_size = 0;
    if (!image_read_value(image, file_header_rva + 2, num_sections) ||
        !image_read_value(image, file_header_rva + 4, out.timestamp) ||
        !image_read_value(image, file_header_rva + 16, opt_header_size) ||
        !image_read_value(image, file_header_rva + 18, out.characteristics))
        return false;

    const std::uint64_t opt_rva = file_header_rva + IMAGE_SIZEOF_FILE_HEADER;
    std::uint16_t opt_magic = 0;
    if (!image_read_value(image, opt_rva, opt_magic))
        return false;
    out.is_64bit = opt_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    if (!out.is_64bit && opt_magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        return false;

    std::uint32_t ep_rva = 0;
    if (!image_read_value(image, opt_rva + 16, ep_rva) ||
        !image_read_value(image, opt_rva + 56, out.size_of_image))
        return false;
    out.entry_point = module_base + ep_rva;
    if (image_range_available(image, opt_rva + 68, sizeof(out.subsystem)))
        image_read_value(image, opt_rva + 68, out.subsystem);

    if (out.is_64bit) {
        if (!image_read_value(image, opt_rva + 24, out.image_base))
            return false;
        if (opt_header_size >= 128 && image_range_available(image, opt_rva + 124, 4)) {
            image_read_value(image, opt_rva + 112, out.export_dir_rva);
            image_read_value(image, opt_rva + 116, out.export_dir_size);
            image_read_value(image, opt_rva + 120, out.import_dir_rva);
            image_read_value(image, opt_rva + 124, out.import_dir_size);
        }
    } else {
        std::uint32_t image_base32 = 0;
        if (!image_read_value(image, opt_rva + 28, image_base32))
            return false;
        out.image_base = image_base32;
        if (opt_header_size >= 112 && image_range_available(image, opt_rva + 108, 4)) {
            image_read_value(image, opt_rva + 96, out.export_dir_rva);
            image_read_value(image, opt_rva + 100, out.export_dir_size);
            image_read_value(image, opt_rva + 104, out.import_dir_rva);
            image_read_value(image, opt_rva + 108, out.import_dir_size);
        }
    }

    if (num_sections > 96)
        num_sections = 96;
    const std::uint64_t section_start = opt_rva + opt_header_size;
    for (std::uint16_t i = 0; i < num_sections; ++i) {
        const std::uint64_t sec_rva = section_start + static_cast<std::uint64_t>(i) * IMAGE_SIZEOF_SECTION_HEADER;
        if (!image_range_available(image, sec_rva, IMAGE_SIZEOF_SECTION_HEADER))
            break;
        pe_parser::section_info_t sec;
        char sec_name[9] = {};
        std::memcpy(sec_name, image.data() + static_cast<std::size_t>(sec_rva), 8);
        sec.name = sec_name;
        image_read_value(image, sec_rva + 8, sec.virtual_size);
        image_read_value(image, sec_rva + 12, sec.virtual_address);
        image_read_value(image, sec_rva + 16, sec.raw_size);
        image_read_value(image, sec_rva + 36, sec.characteristics);
        out.sections.push_back(std::move(sec));
    }
    return true;
}

static bool parse_exports_for_modules_detail_from_image(std::uint64_t module_base,
                                                        const pe_parser::pe_info_t& pe,
                                                        const std::vector<std::uint8_t>& image,
                                                        std::vector<pe_parser::export_entry_t>& out,
                                                        std::size_t max_entries,
                                                        const std::chrono::steady_clock::time_point* deadline,
                                                        bool* truncated,
                                                        bool* deadline_hit)
{
    out.clear();
    if (truncated)
        *truncated = false;
    if (deadline_hit)
        *deadline_hit = false;
    auto hit_deadline = [&]() {
        if (truncated)
            *truncated = true;
        if (deadline_hit)
            *deadline_hit = true;
    };
    if (pe.export_dir_rva == 0 || pe.export_dir_size == 0)
        return true;
    if (max_entries == 0) {
        if (truncated)
            *truncated = true;
        return true;
    }
    if (modules_detail_deadline_expired(deadline)) {
        hit_deadline();
        return false;
    }

    std::uint8_t dir_buf[40] = {};
    if (!image_read_bytes(image, pe.export_dir_rva, dir_buf, sizeof(dir_buf)))
        return false;
    std::uint32_t ordinal_base = 0;
    std::uint32_t num_functions = 0;
    std::uint32_t num_names = 0;
    std::uint32_t addr_table_rva = 0;
    std::uint32_t name_table_rva = 0;
    std::uint32_t ordinal_table_rva = 0;
    std::memcpy(&ordinal_base, dir_buf + 16, sizeof(ordinal_base));
    std::memcpy(&num_functions, dir_buf + 20, sizeof(num_functions));
    std::memcpy(&num_names, dir_buf + 24, sizeof(num_names));
    std::memcpy(&addr_table_rva, dir_buf + 28, sizeof(addr_table_rva));
    std::memcpy(&name_table_rva, dir_buf + 32, sizeof(name_table_rva));
    std::memcpy(&ordinal_table_rva, dir_buf + 36, sizeof(ordinal_table_rva));
    if (num_functions == 0 || num_functions > 0x10000)
        return true;
    if (num_names > num_functions)
        num_names = num_functions;
    if (addr_table_rva == 0)
        return false;

    const std::uint64_t addr_table_bytes = static_cast<std::uint64_t>(num_functions) * sizeof(std::uint32_t);
    if (!image_range_available(image, addr_table_rva, addr_table_bytes))
        return false;
    std::vector<std::uint32_t> addr_table(num_functions);
    std::memcpy(addr_table.data(), image.data() + addr_table_rva, static_cast<std::size_t>(addr_table_bytes));

    std::uint32_t exp_start = pe.export_dir_rva;
    std::uint32_t exp_end = pe.export_dir_rva + pe.export_dir_size;
    if (exp_end < exp_start)
        exp_end = (std::numeric_limits<std::uint32_t>::max)();
    out.reserve(std::min<std::size_t>(static_cast<std::size_t>(num_functions), max_entries));
    std::vector<std::int32_t> ordinal_to_output(num_functions, -1);
    for (std::uint32_t i = 0; i < num_functions; ++i) {
        if (out.size() >= max_entries) {
            if (truncated)
                *truncated = true;
            break;
        }
        if (modules_detail_deadline_expired(deadline)) {
            hit_deadline();
            return true;
        }
        if (addr_table[i] == 0)
            continue;
        pe_parser::export_entry_t entry;
        entry.ordinal = static_cast<std::uint16_t>(ordinal_base + i);
        entry.rva = addr_table[i];
        entry.address = module_base + addr_table[i];
        entry.is_forwarded = addr_table[i] >= exp_start && addr_table[i] < exp_end;
        ordinal_to_output[i] = static_cast<std::int32_t>(out.size());
        out.push_back(std::move(entry));
    }
    if (num_names == 0 || out.empty() || name_table_rva == 0 || ordinal_table_rva == 0)
        return true;
    const std::uint64_t name_table_bytes = static_cast<std::uint64_t>(num_names) * sizeof(std::uint32_t);
    const std::uint64_t ordinal_table_bytes = static_cast<std::uint64_t>(num_names) * sizeof(std::uint16_t);
    if (!image_range_available(image, name_table_rva, name_table_bytes) ||
        !image_range_available(image, ordinal_table_rva, ordinal_table_bytes)) {
        if (truncated)
            *truncated = true;
        return true;
    }
    std::vector<std::uint32_t> name_ptrs(num_names);
    std::vector<std::uint16_t> ordinals(num_names);
    std::memcpy(name_ptrs.data(), image.data() + name_table_rva, static_cast<std::size_t>(name_table_bytes));
    std::memcpy(ordinals.data(), image.data() + ordinal_table_rva, static_cast<std::size_t>(ordinal_table_bytes));

    std::size_t unnamed = 0;
    for (const auto& entry : out) {
        if (entry.name.empty())
            ++unnamed;
    }
    for (std::uint32_t i = 0; i < num_names && unnamed > 0; ++i) {
        if (modules_detail_deadline_expired(deadline)) {
            hit_deadline();
            return true;
        }
        const std::uint16_t ord = ordinals[i];
        if (ord >= num_functions)
            continue;
        const std::int32_t out_index = ordinal_to_output[ord];
        if (out_index < 0)
            continue;
        auto& entry = out[static_cast<std::size_t>(out_index)];
        if (!entry.name.empty())
            continue;
        std::string name;
        if (image_read_c_string(image, name_ptrs[i], 512, name) && !name.empty()) {
            entry.name = std::move(name);
            --unnamed;
        }
    }
    for (auto& entry : out) {
        if (!entry.is_forwarded)
            continue;
        if (modules_detail_deadline_expired(deadline)) {
            hit_deadline();
            return true;
        }
        image_read_c_string(image, entry.rva, 512, entry.forward_name);
    }
    return true;
}

static bool parse_imports_for_modules_detail_from_image(std::uint64_t module_base,
                                                        const pe_parser::pe_info_t& pe,
                                                        const std::vector<std::uint8_t>& image,
                                                        std::vector<pe_parser::import_entry_t>& out,
                                                        std::size_t max_entries,
                                                        const std::chrono::steady_clock::time_point* deadline,
                                                        bool* truncated)
{
    out.clear();
    if (truncated)
        *truncated = false;
    if (pe.import_dir_rva == 0 || pe.import_dir_size == 0)
        return true;
    if (max_entries == 0) {
        if (truncated)
            *truncated = true;
        return true;
    }

    const std::uint32_t descriptor_count = std::min<std::uint32_t>(4096u, pe.import_dir_size / 20u + 1u);
    for (std::uint32_t desc_idx = 0; desc_idx < descriptor_count; ++desc_idx) {
        if (out.size() >= max_entries) {
            if (truncated)
                *truncated = true;
            break;
        }
        if (modules_detail_deadline_expired(deadline)) {
            if (truncated)
                *truncated = true;
            break;
        }
        const std::uint64_t desc_rva = static_cast<std::uint64_t>(pe.import_dir_rva) + static_cast<std::uint64_t>(desc_idx) * 20u;
        std::uint8_t desc_buf[20] = {};
        if (!image_read_bytes(image, desc_rva, desc_buf, sizeof(desc_buf)))
            break;
        std::uint32_t ilt_rva = 0;
        std::uint32_t name_rva = 0;
        std::uint32_t iat_rva = 0;
        std::memcpy(&ilt_rva, desc_buf + 0, 4);
        std::memcpy(&name_rva, desc_buf + 12, 4);
        std::memcpy(&iat_rva, desc_buf + 16, 4);
        if (ilt_rva == 0 && iat_rva == 0)
            break;
        std::string mod_name;
        if (name_rva != 0)
            image_read_c_string(image, name_rva, 256, mod_name);
        const std::uint32_t lookup_rva = ilt_rva != 0 ? ilt_rva : iat_rva;
        const std::uint32_t stride = pe.is_64bit ? 8u : 4u;
        for (std::uint32_t thunk_idx = 0; thunk_idx < 0x10000; ++thunk_idx) {
            if (out.size() >= max_entries) {
                if (truncated)
                    *truncated = true;
                break;
            }
            if (modules_detail_deadline_expired(deadline)) {
                if (truncated)
                    *truncated = true;
                break;
            }
            const std::uint64_t thunk_rva = static_cast<std::uint64_t>(lookup_rva) + static_cast<std::uint64_t>(thunk_idx) * stride;
            std::uint64_t thunk_val = 0;
            if (pe.is_64bit) {
                if (!image_read_value(image, thunk_rva, thunk_val))
                    break;
            } else {
                std::uint32_t thunk32 = 0;
                if (!image_read_value(image, thunk_rva, thunk32))
                    break;
                thunk_val = thunk32;
            }
            if (thunk_val == 0)
                break;

            pe_parser::import_entry_t entry;
            entry.module_name = mod_name;
            entry.iat_address = module_base + iat_rva + static_cast<std::uint64_t>(thunk_idx) * stride;
            const std::uint64_t iat_entry_rva = static_cast<std::uint64_t>(iat_rva) + static_cast<std::uint64_t>(thunk_idx) * stride;
            if (pe.is_64bit) {
                image_read_value(image, iat_entry_rva, entry.bound_address);
            } else {
                std::uint32_t bound32 = 0;
                if (image_read_value(image, iat_entry_rva, bound32))
                    entry.bound_address = bound32;
            }
            const bool is_ordinal = pe.is_64bit
                ? (thunk_val & 0x8000000000000000ULL) != 0
                : (thunk_val & 0x80000000ULL) != 0;
            if (is_ordinal) {
                entry.ordinal = static_cast<std::uint16_t>(thunk_val & 0xFFFFu);
                char ord_buf[32];
                std::snprintf(ord_buf, sizeof(ord_buf), "Ordinal#%u", entry.ordinal);
                entry.function_name = ord_buf;
            } else {
                const std::uint32_t hint_name_rva = static_cast<std::uint32_t>(thunk_val & 0x7FFFFFFFULL);
                image_read_value(image, hint_name_rva, entry.hint);
                image_read_c_string(image, static_cast<std::uint64_t>(hint_name_rva) + 2u, 512, entry.function_name);
            }
            out.push_back(std::move(entry));
        }
    }
    return true;
}

static bool parse_exports_for_modules_detail(std::uint64_t module_base,
                                             const pe_parser::pe_info_t& pe,
                                             std::vector<pe_parser::export_entry_t>& out,
                                             std::size_t max_entries,
                                             const std::chrono::steady_clock::time_point* deadline,
                                             bool* truncated,
                                             bool* deadline_hit)
{
    out.clear();
    if (truncated)
        *truncated = false;
    if (deadline_hit)
        *deadline_hit = false;
    auto hit_deadline = [&]() {
        if (truncated)
            *truncated = true;
        if (deadline_hit)
            *deadline_hit = true;
    };

    if (pe.export_dir_rva == 0 || pe.export_dir_size == 0)
        return true;
    if (max_entries == 0) {
        if (truncated)
            *truncated = true;
        return true;
    }
    if (modules_detail_deadline_expired(deadline)) {
        hit_deadline();
        return false;
    }

    std::uint8_t dir_buf[40] = {};
    if (!read_target_memory_exact(module_base + pe.export_dir_rva, dir_buf, sizeof(dir_buf)))
        return false;

    std::uint32_t ordinal_base = 0;
    std::uint32_t num_functions = 0;
    std::uint32_t num_names = 0;
    std::uint32_t addr_table_rva = 0;
    std::uint32_t name_table_rva = 0;
    std::uint32_t ordinal_table_rva = 0;
    std::memcpy(&ordinal_base, dir_buf + 16, sizeof(ordinal_base));
    std::memcpy(&num_functions, dir_buf + 20, sizeof(num_functions));
    std::memcpy(&num_names, dir_buf + 24, sizeof(num_names));
    std::memcpy(&addr_table_rva, dir_buf + 28, sizeof(addr_table_rva));
    std::memcpy(&name_table_rva, dir_buf + 32, sizeof(name_table_rva));
    std::memcpy(&ordinal_table_rva, dir_buf + 36, sizeof(ordinal_table_rva));

    if (num_functions == 0 || num_functions > 0x10000)
        return true;
    if (num_names > num_functions)
        num_names = num_functions;
    if (addr_table_rva == 0)
        return false;

    std::vector<std::uint32_t> addr_table(num_functions);
    if (!read_target_memory_exact(module_base + addr_table_rva, addr_table.data(), addr_table.size() * sizeof(std::uint32_t)))
        return false;

    std::uint32_t exp_start = pe.export_dir_rva;
    std::uint32_t exp_end = pe.export_dir_rva + pe.export_dir_size;
    if (exp_end < exp_start)
        exp_end = (std::numeric_limits<std::uint32_t>::max)();

    out.reserve(std::min<std::size_t>(static_cast<std::size_t>(num_functions), max_entries));
    std::vector<std::int32_t> ordinal_to_output(num_functions, -1);
    for (std::uint32_t i = 0; i < num_functions; ++i) {
        if (out.size() >= max_entries) {
            if (truncated)
                *truncated = true;
            break;
        }
        if (modules_detail_deadline_expired(deadline)) {
            hit_deadline();
            return true;
        }
        if (addr_table[i] == 0)
            continue;

        pe_parser::export_entry_t entry;
        entry.ordinal = static_cast<std::uint16_t>(ordinal_base + i);
        entry.rva = addr_table[i];
        entry.address = module_base + addr_table[i];
        entry.is_forwarded = addr_table[i] >= exp_start && addr_table[i] < exp_end;
        ordinal_to_output[i] = static_cast<std::int32_t>(out.size());
        out.push_back(std::move(entry));
    }

    if (num_names == 0 || out.empty() || name_table_rva == 0 || ordinal_table_rva == 0)
        return true;
    if (modules_detail_deadline_expired(deadline)) {
        hit_deadline();
        return true;
    }

    std::vector<std::uint32_t> name_ptrs(num_names);
    std::vector<std::uint16_t> ordinals(num_names);
    if (!read_target_memory_exact(module_base + name_table_rva, name_ptrs.data(), name_ptrs.size() * sizeof(std::uint32_t))) {
        if (truncated)
            *truncated = true;
        return true;
    }
    if (!read_target_memory_exact(module_base + ordinal_table_rva, ordinals.data(), ordinals.size() * sizeof(std::uint16_t))) {
        if (truncated)
            *truncated = true;
        return true;
    }

    std::size_t unnamed = 0;
    for (const auto& entry : out) {
        if (entry.name.empty())
            ++unnamed;
    }

    for (std::uint32_t i = 0; i < num_names && unnamed > 0; ++i) {
        if (modules_detail_deadline_expired(deadline)) {
            hit_deadline();
            return true;
        }
        const std::uint16_t ord = ordinals[i];
        if (ord >= num_functions)
            continue;
        const std::int32_t out_index = ordinal_to_output[ord];
        if (out_index < 0)
            continue;
        auto& entry = out[static_cast<std::size_t>(out_index)];
        if (!entry.name.empty())
            continue;
        std::string name;
        if (read_target_c_string(module_base + name_ptrs[i], 512, name) && !name.empty()) {
            entry.name = std::move(name);
            --unnamed;
        }
    }

    for (auto& entry : out) {
        if (!entry.is_forwarded)
            continue;
        if (modules_detail_deadline_expired(deadline)) {
            hit_deadline();
            return true;
        }
        read_target_c_string(module_base + entry.rva, 512, entry.forward_name);
    }

    return true;
}

static std::string lower_ascii(std::string s)
{
    for (char& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

static bool full_test_mode_active()
{
    char buf[8]{};
    DWORD n = GetEnvironmentVariableA("AIDA_FULL_TEST_RUNNING", buf, static_cast<DWORD>(sizeof(buf)));
    return n > 0 && (buf[0] == '1' || buf[0] == 't' || buf[0] == 'T' || buf[0] == 'y' || buf[0] == 'Y');
}

static bool ranges_overlap(std::uint64_t a_start, std::uint64_t a_size, std::uint64_t b_start, std::uint64_t b_size)
{
    if (a_size == 0 || b_size == 0)
        return false;
    std::uint64_t a_end = a_start + a_size - 1;
    std::uint64_t b_end = b_start + b_size - 1;
    if (a_end < a_start)
        a_end = std::numeric_limits<std::uint64_t>::max();
    if (b_end < b_start)
        b_end = std::numeric_limits<std::uint64_t>::max();
    return a_start <= b_end && b_start <= a_end;
}

static bool range_intersects_system_module(std::uint64_t address, std::uint64_t size, std::string& module_name, std::string& module_path)
{
    const std::uint32_t pid = driver_bridge::attached_pid();
    if (pid == 0)
        return false;
    for (const auto& mod : driver_bridge::enumerate_modules_for(pid))
    {
        const std::uint64_t start = mod.base;
        const std::uint64_t mod_size = static_cast<std::uint64_t>(mod.size);
        if (start == 0 || mod_size == 0 || !ranges_overlap(address, size, start, mod_size))
            continue;
        module_name = mod.name;
        module_path = mod.path;
        const std::string name = lower_ascii(mod.name);
        const std::string path = lower_ascii(mod.path);
        if (path.find("\\windows\\") != std::string::npos ||
            path.find("/windows/") != std::string::npos ||
            name == "ntdll.dll" ||
            name == "kernel32.dll" ||
            name == "kernelbase.dll" ||
            name == "apphelp.dll" ||
            name == "win32u.dll")
            return true;
        return false;
    }
    return false;
}

static std::optional<tool_result_t> reject_full_test_system_mutation(std::uint64_t address, std::uint64_t size, const char* tool_name)
{
    if (!full_test_mode_active())
        return std::nullopt;
    std::string module_name;
    std::string module_path;
    if (!range_intersects_system_module(address, size, module_name, module_path))
        return std::nullopt;
    diag::log_tagged_fmt("dbg_tools",
        "%s: rejected full-test system module mutation addr=0x%llX size=%llu module=%s path=%s",
        tool_name ? tool_name : "patch_tool",
        static_cast<unsigned long long>(address),
        static_cast<unsigned long long>(size),
        module_name.c_str(),
        module_path.c_str());
    return tool_result_t::error(
        std::string("Full Test Lab refuses to mutate system module memory. Use a private target fixture address instead."));
}

static bool is_hardware_breakpoint(debugger_engine::bp_type_t type)
{
    return type == debugger_engine::bp_type_t::hardware_execute ||
           type == debugger_engine::bp_type_t::hardware_write ||
           type == debugger_engine::bp_type_t::hardware_read;
}

static const char* breakpoint_type_name(debugger_engine::bp_type_t type)
{
    switch (type) {
    case debugger_engine::bp_type_t::software: return "software";
    case debugger_engine::bp_type_t::hardware_execute: return "hardware_execute";
    case debugger_engine::bp_type_t::hardware_write: return "hardware_write";
    case debugger_engine::bp_type_t::hardware_read: return "hardware_read";
    case debugger_engine::bp_type_t::memory_access: return "memory_access";
    default: return "unknown";
    }
}

static const char* breakpoint_state_name(debugger_engine::bp_state_t state)
{
    switch (state) {
    case debugger_engine::bp_state_t::disabled: return "disabled";
    case debugger_engine::bp_state_t::enabled: return "enabled";
    case debugger_engine::bp_state_t::one_shot: return "one_shot";
    default: return "unknown";
    }
}

static const char* debugger_status_name(debugger_engine::dbg_status_t status)
{
    switch (status) {
    case debugger_engine::dbg_status_t::idle: return "idle";
    case debugger_engine::dbg_status_t::running: return "running";
    case debugger_engine::dbg_status_t::paused: return "paused";
    case debugger_engine::dbg_status_t::stepping: return "stepping";
    case debugger_engine::dbg_status_t::terminated: return "terminated";
    default: return "unknown";
    }
}

static json breakpoint_entry_json(const debugger_engine::breakpoint_t& bp, std::size_t index)
{
    const bool hardware = is_hardware_breakpoint(bp.type);
    const bool enabled = bp.state != debugger_engine::bp_state_t::disabled;
    json e;
    e["index"] = static_cast<int>(index);
    e["address"] = sa_format_address(bp.address);
    e["type"] = static_cast<int>(bp.type);
    e["type_name"] = breakpoint_type_name(bp.type);
    e["state"] = static_cast<int>(bp.state);
    e["state_name"] = breakpoint_state_name(bp.state);
    e["enabled"] = enabled;
    e["one_shot"] = bp.state == debugger_engine::bp_state_t::one_shot;
    e["hardware"] = hardware;
    e["hw_slot"] = bp.hw_slot;
    e["hw_slot_active"] = hardware && enabled && bp.hw_slot >= 0;
    e["size"] = bp.size;
    e["hit_count"] = bp.hit_count;
    e["byte_written"] = bp.byte_written;
    e["original_byte"] = static_cast<unsigned>(bp.original_byte);
    e["name"] = bp.name;
    if (!bp.condition.empty()) e["condition"] = bp.condition;
    if (!bp.log_text.empty()) e["log_text"] = bp.log_text;
    e["auto_continue"] = bp.auto_continue;
    e["internal"] = bp.is_internal;
    return e;
}

static std::size_t breakpoint_count()
{
    std::lock_guard<std::mutex> lk(debugger_engine::g_state.bp_mutex);
    return debugger_engine::g_state.breakpoints.size();
}

static bool breakpoint_entry_by_index(int index, json& out)
{
    std::lock_guard<std::mutex> lk(debugger_engine::g_state.bp_mutex);
    if (index < 0 || index >= static_cast<int>(debugger_engine::g_state.breakpoints.size()))
        return false;
    out = breakpoint_entry_json(debugger_engine::g_state.breakpoints[static_cast<std::size_t>(index)], static_cast<std::size_t>(index));
    return true;
}

static std::size_t watch_count()
{
    std::lock_guard<std::mutex> lk(debugger_engine::g_state.watch_mutex);
    return debugger_engine::g_state.watches.size();
}

static bool watch_entry_by_index(int index, json& out)
{
    std::lock_guard<std::mutex> lk(debugger_engine::g_state.watch_mutex);
    if (index < 0 || index >= static_cast<int>(debugger_engine::g_state.watches.size()))
        return false;
    const auto& w = debugger_engine::g_state.watches[static_cast<std::size_t>(index)];
    out["index"] = index;
    out["expression"] = w.expression;
    out["value"] = w.value;
    out["type"] = w.type;
    out["valid"] = w.valid;
    out["error"] = w.error;
    return true;
}

static std::size_t bookmark_count()
{
    std::lock_guard<std::mutex> lk(debugger_engine::g_state.anno_mutex);
    return debugger_engine::g_state.bookmarks.size();
}

static bool bookmark_present(std::uint64_t address)
{
    std::lock_guard<std::mutex> lk(debugger_engine::g_state.anno_mutex);
    const auto& bookmarks = debugger_engine::g_state.bookmarks;
    return std::find(bookmarks.begin(), bookmarks.end(), address) != bookmarks.end();
}

static std::size_t patch_count()
{
    std::lock_guard<std::mutex> lk(code_patcher::g_state.mtx);
    return code_patcher::g_state.patches.size();
}

static std::size_t active_patch_count()
{
    std::lock_guard<std::mutex> lk(code_patcher::g_state.mtx);
    std::size_t count = 0;
    for (const auto& p : code_patcher::g_state.patches)
        if (p.active)
            ++count;
    return count;
}

static bool patch_entry_by_index(int index, json& out)
{
    std::lock_guard<std::mutex> lk(code_patcher::g_state.mtx);
    if (index < 0 || index >= static_cast<int>(code_patcher::g_state.patches.size()))
        return false;
    const auto& p = code_patcher::g_state.patches[static_cast<std::size_t>(index)];
    out["index"] = index;
    out["address"] = sa_format_address(p.address);
    out["description"] = p.description;
    out["active"] = p.active;
    out["timestamp"] = p.timestamp;
    out["original_bytes"] = code_patcher::format_bytes(p.original_bytes);
    out["patched_bytes"] = code_patcher::format_bytes(p.patched_bytes);
    out["size"] = p.patched_bytes.size();
    return true;
}

static void add_debugger_action_context(json& result, const char* action)
{
    result["action"] = action;
    result["target_pid"] = driver_bridge::attached_pid();
    result["active_tid"] = debugger_engine::g_state.active_tid;
}

static std::string trim_ascii(std::string s)
{
    auto is_ws = [](char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n';
    };
    while (!s.empty() && is_ws(s.front()))
        s.erase(s.begin());
    while (!s.empty() && is_ws(s.back()))
        s.pop_back();
    return s;
}

static std::optional<std::uint64_t> parse_u64_json(const json& value)
{
    if (value.is_number_unsigned())
        return value.get<std::uint64_t>();
    if (value.is_number_integer()) {
        const auto raw = value.get<std::int64_t>();
        if (raw < 0)
            return std::nullopt;
        return static_cast<std::uint64_t>(raw);
    }
    if (value.is_string())
        return sa_parse_address(value.get<std::string>());
    if (value.is_object() && value.contains("value"))
        return parse_u64_json(value["value"]);
    return std::nullopt;
}

static std::optional<std::uint64_t> parse_u64_param(const json& params, const char* key)
{
    if (!params.contains(key))
        return std::nullopt;
    return parse_u64_json(params[key]);
}

static std::string bytes_to_hex(const std::vector<std::uint8_t>& bytes, std::size_t limit = std::numeric_limits<std::size_t>::max())
{
    const std::size_t count = std::min(bytes.size(), limit);
    std::string hex;
    hex.reserve(count * 3);
    char buf[4] = {};
    for (std::size_t i = 0; i < count; ++i) {
        if (i != 0)
            hex.push_back(' ');
        std::snprintf(buf, sizeof(buf), "%02X", static_cast<unsigned>(bytes[i]));
        hex.append(buf, 2);
    }
    return hex;
}

static std::string bytes_to_hex(const std::uint8_t* bytes, std::size_t size)
{
    std::vector<std::uint8_t> tmp(bytes, bytes + size);
    return bytes_to_hex(tmp);
}

static bool parse_protection_value(const json& params, std::uint32_t& protect, std::string& normalized, std::string& error)
{
    protect = PAGE_EXECUTE_READWRITE;
    normalized = std::string("PAGE_EXECUTE_READWRITE");

    if (!params.contains("protection"))
        return true;

    const auto& value = params["protection"];
    if (auto numeric = parse_u64_json(value)) {
        if (*numeric == 0 || *numeric > 0xFFFFFFFFULL) {
            error = std::string("Invalid PAGE_* protection value.");
            return false;
        }
        protect = static_cast<std::uint32_t>(*numeric);
        normalized = debugger_engine::format_protect(protect);
        return true;
    }

    if (!value.is_string()) {
        error = std::string("'protection' must be a PAGE_* string or numeric Win32 constant.");
        return false;
    }

    std::string text = lower_ascii(trim_ascii(value.get<std::string>()));
    if (text.empty()) {
        error = std::string("'protection' cannot be empty.");
        return false;
    }

    for (char& c : text) {
        if (c == '|' || c == '+' || c == ',')
            c = ' ';
    }

    std::uint32_t base = 0;
    std::uint32_t modifiers = 0;
    std::istringstream iss(text);
    std::string token;
    while (iss >> token) {
        if (token.rfind("page_", 0) == 0)
            token.erase(0, 5);

        std::uint32_t token_value = 0;
        bool is_modifier = false;
        if (token == "noaccess" || token == "none") token_value = PAGE_NOACCESS;
        else if (token == "readonly" || token == "read" || token == "r") token_value = PAGE_READONLY;
        else if (token == "readwrite" || token == "rw") token_value = PAGE_READWRITE;
        else if (token == "writecopy" || token == "wc") token_value = PAGE_WRITECOPY;
        else if (token == "execute" || token == "x") token_value = PAGE_EXECUTE;
        else if (token == "execute_read" || token == "executeread" || token == "rx" || token == "xr") token_value = PAGE_EXECUTE_READ;
        else if (token == "execute_readwrite" || token == "executereadwrite" || token == "rwx" || token == "xrw") token_value = PAGE_EXECUTE_READWRITE;
        else if (token == "execute_writecopy" || token == "executewritecopy") token_value = PAGE_EXECUTE_WRITECOPY;
        else if (token == "guard") { token_value = PAGE_GUARD; is_modifier = true; }
        else if (token == "nocache") { token_value = PAGE_NOCACHE; is_modifier = true; }
        else if (token == "writecombine") { token_value = PAGE_WRITECOMBINE; is_modifier = true; }
        else if (auto parsed = sa_parse_address(token)) token_value = static_cast<std::uint32_t>(*parsed);
        else {
            error = std::string("Unsupported protection token: ") + token;
            return false;
        }

        if (is_modifier)
            modifiers |= token_value;
        else {
            if (base != 0 && token_value != base) {
                error = std::string("Specify only one base PAGE_* protection.");
                return false;
            }
            base = token_value;
        }
    }

    if (base == 0) {
        error = std::string("Missing base PAGE_* protection.");
        return false;
    }

    protect = base | modifiers;
    normalized = debugger_engine::format_protect(protect);
    return true;
}

static std::optional<std::string> canonical_mutable_register(std::string name)
{
    name = lower_ascii(trim_ascii(std::move(name)));
    static const std::array<const char*, 18> regs = {
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "rip", "rflags"
    };
    if (name == "eflags")
        return std::string("rflags");
    for (const char* reg : regs) {
        if (name == reg)
            return name;
    }
    return std::nullopt;
}

static bool read_register_value(const debugger_engine::register_set_t& regs, const std::string& name, std::uint64_t& out)
{
    const std::string lower = lower_ascii(name);
    if      (lower == "rax") out = regs.rax;
    else if (lower == "rbx") out = regs.rbx;
    else if (lower == "rcx") out = regs.rcx;
    else if (lower == "rdx") out = regs.rdx;
    else if (lower == "rsi") out = regs.rsi;
    else if (lower == "rdi") out = regs.rdi;
    else if (lower == "rbp") out = regs.rbp;
    else if (lower == "rsp") out = regs.rsp;
    else if (lower == "r8")  out = regs.r8;
    else if (lower == "r9")  out = regs.r9;
    else if (lower == "r10") out = regs.r10;
    else if (lower == "r11") out = regs.r11;
    else if (lower == "r12") out = regs.r12;
    else if (lower == "r13") out = regs.r13;
    else if (lower == "r14") out = regs.r14;
    else if (lower == "r15") out = regs.r15;
    else if (lower == "rip") out = regs.rip;
    else if (lower == "rflags" || lower == "eflags") out = regs.rflags;
    else return false;
    return true;
}

static json registers_to_json(const debugger_engine::register_set_t& regs)
{
    json r;
    r["rax"] = sa_format_address(regs.rax);
    r["rbx"] = sa_format_address(regs.rbx);
    r["rcx"] = sa_format_address(regs.rcx);
    r["rdx"] = sa_format_address(regs.rdx);
    r["rsi"] = sa_format_address(regs.rsi);
    r["rdi"] = sa_format_address(regs.rdi);
    r["rbp"] = sa_format_address(regs.rbp);
    r["rsp"] = sa_format_address(regs.rsp);
    r["r8"]  = sa_format_address(regs.r8);
    r["r9"]  = sa_format_address(regs.r9);
    r["r10"] = sa_format_address(regs.r10);
    r["r11"] = sa_format_address(regs.r11);
    r["r12"] = sa_format_address(regs.r12);
    r["r13"] = sa_format_address(regs.r13);
    r["r14"] = sa_format_address(regs.r14);
    r["r15"] = sa_format_address(regs.r15);
    r["rip"] = sa_format_address(regs.rip);
    r["rflags"] = sa_format_address(regs.rflags);
    r["flags_decoded"] = debugger_engine::format_flags(regs.rflags);
    r["cs"] = sa_format_address(regs.cs);
    r["ss"] = sa_format_address(regs.ss);
    r["dr0"] = sa_format_address(regs.dr0);
    r["dr1"] = sa_format_address(regs.dr1);
    r["dr2"] = sa_format_address(regs.dr2);
    r["dr3"] = sa_format_address(regs.dr3);
    r["dr6"] = sa_format_address(regs.dr6);
    r["dr7"] = sa_format_address(regs.dr7);
    return r;
}

static expression_eval::context_t trace_eval_context(const debugger_engine::register_set_t& regs)
{
    expression_eval::context_t ctx;
    ctx.rax = regs.rax; ctx.rbx = regs.rbx; ctx.rcx = regs.rcx; ctx.rdx = regs.rdx;
    ctx.rsi = regs.rsi; ctx.rdi = regs.rdi; ctx.rbp = regs.rbp; ctx.rsp = regs.rsp;
    ctx.r8  = regs.r8;  ctx.r9  = regs.r9;  ctx.r10 = regs.r10; ctx.r11 = regs.r11;
    ctx.r12 = regs.r12; ctx.r13 = regs.r13; ctx.r14 = regs.r14; ctx.r15 = regs.r15;
    ctx.rip = regs.rip; ctx.rflags = regs.rflags;
    ctx.read_mem = [](std::uint64_t addr, std::size_t size, void* out) -> bool {
        if (!out || size == 0)
            return false;
        std::vector<std::uint8_t> buf;
        if (!driver_bridge::read_memory(addr, size, buf) || buf.size() < size)
            return false;
        std::memcpy(out, buf.data(), size);
        return true;
    };
    return ctx;
}

static bool evaluate_trace_condition(const std::string& condition,
                                     const debugger_engine::register_set_t& regs,
                                     bool& matched,
                                     std::string& error)
{
    matched = false;
    if (condition.empty())
        return true;
    auto ctx = trace_eval_context(regs);
    auto er = expression_eval::evaluate(condition, ctx);
    if (!er.ok) {
        error = er.error;
        return false;
    }
    matched = er.value != 0;
    return true;
}

static std::string zydis_reg_name(std::uint16_t reg)
{
    if (reg == static_cast<std::uint16_t>(ZYDIS_REGISTER_NONE))
        return {};
    const char* name = ZydisRegisterGetString(static_cast<ZydisRegister>(reg));
    return name ? std::string(name) : std::string();
}

static bool zydis_gpr_value(std::uint16_t reg, const debugger_engine::register_set_t& regs, std::uint64_t& out)
{
    switch (static_cast<ZydisRegister>(reg)) {
    case ZYDIS_REGISTER_RAX: case ZYDIS_REGISTER_EAX: out = regs.rax; return true;
    case ZYDIS_REGISTER_RBX: case ZYDIS_REGISTER_EBX: out = regs.rbx; return true;
    case ZYDIS_REGISTER_RCX: case ZYDIS_REGISTER_ECX: out = regs.rcx; return true;
    case ZYDIS_REGISTER_RDX: case ZYDIS_REGISTER_EDX: out = regs.rdx; return true;
    case ZYDIS_REGISTER_RSI: case ZYDIS_REGISTER_ESI: out = regs.rsi; return true;
    case ZYDIS_REGISTER_RDI: case ZYDIS_REGISTER_EDI: out = regs.rdi; return true;
    case ZYDIS_REGISTER_RBP: case ZYDIS_REGISTER_EBP: out = regs.rbp; return true;
    case ZYDIS_REGISTER_RSP: case ZYDIS_REGISTER_ESP: out = regs.rsp; return true;
    case ZYDIS_REGISTER_R8:  case ZYDIS_REGISTER_R8D:  out = regs.r8;  return true;
    case ZYDIS_REGISTER_R9:  case ZYDIS_REGISTER_R9D:  out = regs.r9;  return true;
    case ZYDIS_REGISTER_R10: case ZYDIS_REGISTER_R10D: out = regs.r10; return true;
    case ZYDIS_REGISTER_R11: case ZYDIS_REGISTER_R11D: out = regs.r11; return true;
    case ZYDIS_REGISTER_R12: case ZYDIS_REGISTER_R12D: out = regs.r12; return true;
    case ZYDIS_REGISTER_R13: case ZYDIS_REGISTER_R13D: out = regs.r13; return true;
    case ZYDIS_REGISTER_R14: case ZYDIS_REGISTER_R14D: out = regs.r14; return true;
    case ZYDIS_REGISTER_R15: case ZYDIS_REGISTER_R15D: out = regs.r15; return true;
    case ZYDIS_REGISTER_RIP: case ZYDIS_REGISTER_EIP: out = regs.rip; return true;
    default: break;
    }
    return false;
}

static bool decode_trace_instruction(std::uint64_t address, AsmInstr& ins)
{
    std::vector<std::uint8_t> code;
    if (!driver_bridge::read_memory(address, 16, code) || code.empty())
        return false;
    ins = zydis_decode_one(code.data(), static_cast<int>(code.size()), address);
    return true;
}

static bool compute_effective_address(const AsmInstr& ins,
                                      const debugger_engine::register_set_t& regs,
                                      std::uint64_t& out)
{
    if (!ins.has_mem_op)
        return false;

    std::uint64_t total = 0;
    bool has_component = false;

    if (ins.mem_op.base_reg != static_cast<std::uint16_t>(ZYDIS_REGISTER_NONE)) {
        std::uint64_t base = 0;
        if (ins.mem_op.base_reg == static_cast<std::uint16_t>(ZYDIS_REGISTER_RIP) ||
            ins.mem_op.base_reg == static_cast<std::uint16_t>(ZYDIS_REGISTER_EIP)) {
            base = regs.rip + static_cast<std::uint64_t>(std::max(ins.len, 0));
        } else if (!zydis_gpr_value(ins.mem_op.base_reg, regs, base)) {
            return false;
        }
        total += base;
        has_component = true;
    }

    if (ins.mem_op.index_reg != static_cast<std::uint16_t>(ZYDIS_REGISTER_NONE)) {
        std::uint64_t index = 0;
        if (!zydis_gpr_value(ins.mem_op.index_reg, regs, index))
            return false;
        const std::uint8_t scale = ins.mem_op.scale == 0 ? 1 : ins.mem_op.scale;
        total += index * static_cast<std::uint64_t>(scale);
        has_component = true;
    }

    if (ins.mem_op.has_disp || has_component) {
        total += static_cast<std::uint64_t>(ins.mem_op.disp);
        out = total;
        return true;
    }

    return false;
}

static json trace_record_to_json(const debugger_engine::trace_record_t& tr)
{
    json tj;
    tj["index"] = tr.index;
    tj["address"] = sa_format_address(tr.address);
    tj["rip"] = sa_format_address(tr.regs.rip);
    tj["disasm"] = tr.disasm_text;
    tj["instruction"] = tr.disasm_text;
    tj["registers"] = registers_to_json(tr.regs);

    AsmInstr ins{};
    if (decode_trace_instruction(tr.address, ins)) {
        tj["size"] = ins.len;
        tj["bytes"] = bytes_to_hex(ins.raw, static_cast<std::size_t>(std::clamp(ins.len, 0, 16)));
        if (ins.has_mem_op) {
            json mem;
            mem["has_memory_operand"] = true;
            mem["base_register"] = zydis_reg_name(ins.mem_op.base_reg);
            mem["index_register"] = zydis_reg_name(ins.mem_op.index_reg);
            mem["scale"] = ins.mem_op.scale;
            mem["displacement"] = ins.mem_op.disp;
            mem["size_bits"] = ins.mem_op.size;
            mem["segment"] = zydis_reg_name(ins.mem_op.segment);
            std::uint64_t effective = 0;
            if (compute_effective_address(ins, tr.regs, effective)) {
                mem["effective_address"] = sa_format_address(effective);
                const std::size_t sample_size = std::min<std::size_t>(16, std::max<std::size_t>(1, (static_cast<std::size_t>(ins.mem_op.size) + 7) / 8));
                std::vector<std::uint8_t> sample;
                if (driver_bridge::read_memory(effective, sample_size, sample) && !sample.empty()) {
                    mem["sample_size"] = sample.size();
                    mem["sample_hex"] = bytes_to_hex(sample);
                }
            }
            tj["memory_access"] = std::move(mem);
        }
    }

    return tj;
}

struct trace_session_t
{
    std::string id;
    std::uint32_t pid = 0;
    std::uint32_t tid = 0;
    std::string condition;
    std::string stop_reason;
    std::string error;
    int max_instructions = 0;
    int executed_instructions = 0;
    std::uint32_t timeout_ms = 0;
    std::uint64_t duration_ms = 0;
    bool completed = false;
    bool condition_met = false;
    bool cancelled = false;
    bool timed_out = false;
    std::vector<debugger_engine::trace_record_t> entries;
};

static std::mutex& trace_session_mutex()
{
    static std::mutex m;
    return m;
}

static std::map<std::string, trace_session_t>& trace_sessions()
{
    static std::map<std::string, trace_session_t> sessions;
    return sessions;
}

static std::string next_trace_id_locked()
{
    static std::uint64_t next_id = 1;
    char buf[32] = {};
    std::snprintf(buf, sizeof(buf), "trace-%06llu", static_cast<unsigned long long>(next_id++));
    return std::string(buf);
}

static std::string store_trace_session(trace_session_t session)
{
    std::lock_guard<std::mutex> lk(trace_session_mutex());
    session.id = next_trace_id_locked();
    const std::string id = session.id;
    auto& sessions = trace_sessions();
    sessions[id] = std::move(session);
    while (sessions.size() > 16)
        sessions.erase(sessions.begin());
    return id;
}

static bool load_trace_session(const std::string& id, trace_session_t& out)
{
    std::lock_guard<std::mutex> lk(trace_session_mutex());
    auto& sessions = trace_sessions();
    auto it = sessions.find(id);
    if (it == sessions.end())
        return false;
    out = it->second;
    return true;
}

static tool_result_t handle_debugger_set_register(const json& params, bool allow_value_alias)
{
    diag::log_tagged_fmt("dbg_tools", "debugger_set_register: entry");
    if (auto err = ensure_attached(params))
        return *err;

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_err = acquire_driver_debugger_quota("debugger_set_register", driver_bridge::attached_pid(), quota_guard))
        return *quota_err;

    auto tid = parse_tid(params);
    if (!tid)
        return tool_result_t::error(std::string("'tid' is required."));
    if (!params.contains("register") || !params["register"].is_string())
        return tool_result_t::error(std::string("'register' is required."));

    const char* value_key = nullptr;
    if (params.contains("hex_value"))
        value_key = "hex_value";
    else if (allow_value_alias && params.contains("value"))
        value_key = "value";
    if (!value_key)
        return tool_result_t::error(allow_value_alias ? std::string("'hex_value' or 'value' is required.") : std::string("'hex_value' is required."));

    auto value = parse_u64_json(params[value_key]);
    if (!value)
        return tool_result_t::error(std::string("Invalid register value."));

    auto reg = canonical_mutable_register(params["register"].get<std::string>());
    if (!reg)
        return tool_result_t::error(std::string("Unsupported register. Use a 64-bit general register, RIP, RSP, RBP, or RFLAGS."));

    debugger_engine::g_state.active_tid = *tid;
    auto before_regs = debugger_engine::get_registers();
    std::uint64_t before_value = 0;
    read_register_value(before_regs, *reg, before_value);

    diag::log_tagged_fmt("dbg_tools", "debugger_set_register: tid=%u reg=%s value=0x%llX",
        *tid, reg->c_str(), static_cast<unsigned long long>(*value));
    if (!debugger_engine::set_register(*reg, *value)) {
        const std::string detail = debugger_engine::last_error().empty()
            ? std::string("debugger_engine::set_register failed.")
            : debugger_engine::last_error();
        diag::log_tagged_fmt("dbg_tools", "debugger_set_register: failed tid=%u reg=%s detail=%s",
            *tid, reg->c_str(), detail.c_str());
        return tool_result_t::error(detail);
    }

    auto after_regs = debugger_engine::get_registers();
    std::uint64_t after_value = 0;
    read_register_value(after_regs, *reg, after_value);

    json result;
    result["tid"] = *tid;
    result["register"] = *reg;
    result["before"] = sa_format_address(before_value);
    result["after"] = sa_format_address(after_value);
    result["requested"] = sa_format_address(*value);
    result["registers"] = registers_to_json(after_regs);
    return tool_result_t::ok(std::string("Register updated."), result);
}





static tool_result_t handle_debugger_start_trace(const json& params)
{
    diag::log_tagged_fmt("dbg_tools", "debugger_start_trace: entry");
    if (auto err = ensure_attached(params))
        return *err;

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_err = acquire_driver_debugger_quota("debugger_start_trace", driver_bridge::attached_pid(), quota_guard))
        return *quota_err;

    auto tid = parse_tid(params);
    if (!tid)
        return tool_result_t::error(std::string("'tid' is required."));

    int max_instructions = int_param_clamped(params, "max_instructions", 256, 1, 4096);
    if (!params.contains("max_instructions") && params.contains("max_records"))
        max_instructions = int_param_clamped(params, "max_records", max_instructions, 1, 4096);
    const int timeout_ms_i = int_param_clamped(params, "timeout_ms", 30000, 100, 120000);
    const std::uint32_t timeout_ms = static_cast<std::uint32_t>(timeout_ms_i);

    std::string condition;
    if (params.contains("condition")) {
        if (!params["condition"].is_string())
            return tool_result_t::error(std::string("'condition' must be a string expression."));
        condition = trim_ascii(params["condition"].get<std::string>());
        if (condition.size() > 512)
            return tool_result_t::error(std::string("'condition' is too long."));
    }

    debugger_engine::g_state.active_tid = *tid;
    diag::log_tagged_fmt("dbg_tools",
        "debugger_start_trace: begin pid=%u tid=%u max_instructions=%d timeout_ms=%u condition_len=%zu",
        static_cast<unsigned>(driver_bridge::attached_pid()),
        static_cast<unsigned>(*tid),
        max_instructions,
        static_cast<unsigned>(timeout_ms),
        condition.size());
    bool initial_matched = false;
    std::string condition_error;
    if (!condition.empty()) {
        auto initial_regs = debugger_engine::get_registers();
        if (!evaluate_trace_condition(condition, initial_regs, initial_matched, condition_error))
            return tool_result_t::error(std::string("Invalid trace condition: ") + condition_error);
    }

    if (!debugger_engine::start_trace(max_instructions))
        return tool_result_t::error(std::string("Trace is already active."));

    trace_session_t session;
    session.pid = driver_bridge::attached_pid();
    session.tid = *tid;
    session.condition = condition;
    session.max_instructions = max_instructions;
    session.timeout_ms = timeout_ms;
    session.stop_reason = std::string("max_instructions");

    const auto started = std::chrono::steady_clock::now();
    const auto deadline = started + std::chrono::milliseconds(timeout_ms);

    if (initial_matched) {
        session.completed = true;
        session.condition_met = true;
        session.stop_reason = std::string("condition");
        diag::log_tagged_fmt("dbg_tools",
            "debugger_start_trace: initial_condition_matched tid=%u",
            static_cast<unsigned>(*tid));
    } else {
        for (int i = 0; i < max_instructions; ++i) {
            if (mcp_standalone::current_call_cancelled()) {
                session.cancelled = true;
                session.stop_reason = std::string("cancelled");
                diag::log_tagged_fmt("dbg_tools",
                    "debugger_start_trace: cancelled tid=%u step=%d executed=%d",
                    static_cast<unsigned>(*tid), i, session.executed_instructions);
                break;
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                session.timed_out = true;
                session.stop_reason = std::string("timeout");
                diag::log_tagged_fmt("dbg_tools",
                    "debugger_start_trace: timeout_before_step tid=%u step=%d executed=%d",
                    static_cast<unsigned>(*tid), i, session.executed_instructions);
                break;
            }

            const auto step_started = std::chrono::steady_clock::now();
            diag::log_tagged_fmt("dbg_tools",
                "debugger_start_trace: step_begin tid=%u step=%d max=%d executed=%d",
                static_cast<unsigned>(*tid), i + 1, max_instructions, session.executed_instructions);
            if (!debugger_engine::step_into()) {
                session.error = debugger_engine::last_error().empty()
                    ? std::string("step_into failed.")
                    : debugger_engine::last_error();
                session.stop_reason = std::string("step_failed");
                const auto step_elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - step_started).count();
                diag::log_tagged_fmt("dbg_tools",
                    "debugger_start_trace: step_failed tid=%u step=%d executed=%d elapsed_ms=%lld error=%s",
                    static_cast<unsigned>(*tid), i + 1, session.executed_instructions,
                    static_cast<long long>(step_elapsed_ms), session.error.c_str());
                break;
            }

            ++session.executed_instructions;
            const auto step_elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - step_started).count();
            diag::log_tagged_fmt("dbg_tools",
                "debugger_start_trace: step_ok tid=%u step=%d executed=%d elapsed_ms=%lld",
                static_cast<unsigned>(*tid), i + 1, session.executed_instructions,
                static_cast<long long>(step_elapsed_ms));

            if (std::chrono::steady_clock::now() >= deadline) {
                session.timed_out = true;
                session.stop_reason = std::string("timeout");
                diag::log_tagged_fmt("dbg_tools",
                    "debugger_start_trace: timeout_after_step tid=%u step=%d executed=%d",
                    static_cast<unsigned>(*tid), i + 1, session.executed_instructions);
                break;
            }

            if (!condition.empty()) {
                bool matched = false;
                auto regs = debugger_engine::get_registers();
                if (!evaluate_trace_condition(condition, regs, matched, condition_error)) {
                    session.error = std::string("Trace condition evaluation failed: ") + condition_error;
                    session.stop_reason = std::string("condition_error");
                    diag::log_tagged_fmt("dbg_tools",
                        "debugger_start_trace: condition_error tid=%u step=%d error=%s",
                        static_cast<unsigned>(*tid), i + 1, session.error.c_str());
                    break;
                }
                if (matched) {
                    session.condition_met = true;
                    session.completed = true;
                    session.stop_reason = std::string("condition");
                    diag::log_tagged_fmt("dbg_tools",
                        "debugger_start_trace: condition_matched tid=%u step=%d executed=%d",
                        static_cast<unsigned>(*tid), i + 1, session.executed_instructions);
                    break;
                }
            }
        }

        if (session.executed_instructions >= max_instructions) {
            session.completed = true;
            session.stop_reason = std::string("max_instructions");
        }
    }

    debugger_engine::stop_trace();

    {
        std::lock_guard<std::mutex> lk(debugger_engine::g_state.trace_mutex);
        session.entries = debugger_engine::g_state.trace_log;
    }

    session.duration_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count());

    const std::string trace_id = store_trace_session(std::move(session));
    trace_session_t stored;
    load_trace_session(trace_id, stored);

    diag::log_tagged_fmt("dbg_tools", "debugger_start_trace: id=%s tid=%u entries=%zu reason=%s duration_ms=%llu",
        trace_id.c_str(), *tid, stored.entries.size(), stored.stop_reason.c_str(),
        static_cast<unsigned long long>(stored.duration_ms));

    json result;
    result["trace_id"] = trace_id;
    result["pid"] = stored.pid;
    result["tid"] = stored.tid;
    result["entries"] = stored.entries.size();
    result["executed_instructions"] = stored.executed_instructions;
    result["max_instructions"] = stored.max_instructions;
    result["stop_reason"] = stored.stop_reason;
    result["completed"] = stored.completed;
    result["condition_met"] = stored.condition_met;
    result["cancelled"] = stored.cancelled;
    result["timed_out"] = stored.timed_out;
    result["duration_ms"] = stored.duration_ms;
    if (!stored.condition.empty())
        result["condition"] = stored.condition;
    if (!stored.error.empty())
        result["error"] = stored.error;
    const bool failed = !stored.error.empty() || stored.timed_out || stored.cancelled || !stored.completed;
    if (failed) {
        std::string detail = stored.error.empty()
            ? (std::string("Trace stopped before completion: ") + stored.stop_reason)
            : stored.error;
        diag::log_tagged_fmt("dbg_tools",
            "debugger_start_trace: failed id=%s tid=%u reason=%s entries=%zu executed=%d completed=%d timed_out=%d cancelled=%d",
            trace_id.c_str(),
            static_cast<unsigned>(*tid),
            stored.stop_reason.c_str(),
            stored.entries.size(),
            stored.executed_instructions,
            stored.completed ? 1 : 0,
            stored.timed_out ? 1 : 0,
            stored.cancelled ? 1 : 0);
        return tool_result_t{false, detail, result};
    }
    return tool_result_t::ok(std::string("Trace recorded."), result);
}

static tool_result_t handle_debugger_get_trace(const json& params)
{
    diag::log_tagged_fmt("dbg_tools", "debugger_get_trace: entry");
    if (!params.contains("trace_id") || !params["trace_id"].is_string())
        return tool_result_t::error(std::string("'trace_id' is required."));

    const std::string trace_id = params["trace_id"].get<std::string>();
    trace_session_t session;
    if (!load_trace_session(trace_id, session))
        return tool_result_t::error(std::string("Trace ID not found."));

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_err = acquire_driver_debugger_quota("debugger_get_trace", driver_bridge::attached_pid(), quota_guard))
        return *quota_err;

    const int offset = int_param_clamped(params, "offset", 0, 0, static_cast<int>(std::min<std::size_t>(session.entries.size(), 1000000)));
    const int limit = int_param_clamped(params, "limit", 200, 1, 1000);

    json entries = json::array();
    const int end = std::min<int>(static_cast<int>(session.entries.size()), offset + limit);
    for (int i = offset; i < end; ++i)
        entries.push_back(trace_record_to_json(session.entries[static_cast<std::size_t>(i)]));

    json result;
    result["trace_id"] = session.id;
    result["pid"] = session.pid;
    result["tid"] = session.tid;
    result["total"] = session.entries.size();
    result["offset"] = offset;
    result["returned"] = entries.size();
    result["executed_instructions"] = session.executed_instructions;
    result["max_instructions"] = session.max_instructions;
    result["timeout_ms"] = session.timeout_ms;
    result["duration_ms"] = session.duration_ms;
    result["stop_reason"] = session.stop_reason;
    result["completed"] = session.completed;
    result["condition_met"] = session.condition_met;
    result["cancelled"] = session.cancelled;
    result["timed_out"] = session.timed_out;
    if (!session.condition.empty())
        result["condition"] = session.condition;
    if (!session.error.empty())
        result["error"] = session.error;
    result["entries"] = std::move(entries);
    diag::log_tagged_fmt("dbg_tools", "debugger_get_trace: id=%s total=%zu returned=%zu",
        trace_id.c_str(), session.entries.size(), result["returned"].get<std::size_t>());
    return tool_result_t::ok(std::string("Trace returned."), result);
}

static bool callstack_source_contains(const std::string& source, const char* needle)
{
    return needle != nullptr && source.find(needle) != std::string::npos;
}

static void apply_callstack_resolution(json& frame,
                                       const debugger_engine::call_stack_symbol_resolution_t& r,
                                       std::uint32_t pid,
                                       std::uint32_t tid,
                                       const char* unwind_status)
{
    frame["pid"] = pid;
    frame["tid"] = tid;
    frame["address"] = sa_format_address(r.address);
    if (!r.module_name.empty()) {
        frame["module"] = r.module_name;
        frame["module_name"] = r.module_name;
        frame["symbol_owner"] = r.module_name;
    }
    if (!r.module_path.empty())
        frame["module_path"] = r.module_path;
    if (r.module_base != 0) {
        frame["module_base"] = sa_format_address(r.module_base);
        frame["module_end"] = sa_format_address(r.module_base + r.module_size);
    }
    if (r.module_size != 0) {
        frame["module_size"] = r.module_size;
        frame["module_size_hex"] = sa_format_address(r.module_size);
    }
    frame["module_offset"] = sa_format_address(r.module_offset);
    if (!r.function_name.empty()) {
        frame["function"] = r.function_name;
        frame["function_name"] = r.function_name;
        frame["symbol"] = r.function_name;
        if (callstack_source_contains(r.source, "nearest")) {
            frame["nearest_symbol"] = r.function_name;
            frame["nearest_symbol_address"] = sa_format_address(r.symbol_address);
            frame["nearest_symbol_displacement"] = sa_format_address(r.symbol_offset);
        }
        if (callstack_source_contains(r.source, "exact"))
            frame["exact_symbol"] = r.function_name;
    }
    if (r.symbol_address != 0)
        frame["symbol_address"] = sa_format_address(r.symbol_address);
    frame["symbol_offset"] = sa_format_address(r.symbol_offset);
    frame["symbol_source"] = r.source;
    frame["symbol_status"] = r.status;
    frame["resolution_source"] = r.source;
    frame["resolution_status"] = r.status;
    frame["unwind_status"] = unwind_status != nullptr ? unwind_status : "unknown";
    frame["symbol_resolution"] = json{
        {"source", r.source},
        {"status", r.status},
        {"module", r.module_name},
        {"module_path", r.module_path},
        {"module_base", sa_format_address(r.module_base)},
        {"module_size", r.module_size},
        {"module_offset", sa_format_address(r.module_offset)},
        {"function", r.function_name},
        {"symbol_address", sa_format_address(r.symbol_address)},
        {"symbol_offset", sa_format_address(r.symbol_offset)},
        {"nearest_symbol", callstack_source_contains(r.source, "nearest") ? r.function_name : std::string()},
        {"nearest_symbol_address", callstack_source_contains(r.source, "nearest") ? sa_format_address(r.symbol_address) : std::string()},
        {"nearest_symbol_displacement", callstack_source_contains(r.source, "nearest") ? sa_format_address(r.symbol_offset) : std::string()},
        {"elapsed_us", r.elapsed_us},
        {"nearest", callstack_source_contains(r.source, "nearest")},
        {"exact", callstack_source_contains(r.source, "exact")},
        {"module_rva_fallback", r.source == "module_rva"}
    };
}

static json make_callstack_failure(std::uint32_t pid,
                                   std::uint32_t tid,
                                   const char* reason,
                                   const std::string& detail,
                                   DWORD gle,
                                   bool did_suspend)
{
    return json{
        {"available", false},
        {"failure_reason", reason != nullptr ? reason : "unknown"},
        {"detail", detail},
        {"pid", pid},
        {"target_pid", pid},
        {"tid", tid},
        {"win32_error", static_cast<std::uint64_t>(gle)},
        {"did_suspend", did_suspend},
        {"kernel_backend", driver_bridge::using_kernel_driver()},
        {"driver_status", driver_bridge::status()},
        {"driver_last_error", driver_bridge::last_error()}
    };
}

static tool_result_t handle_debugger_get_callstack_impl(const json& params)
{
    diag::log_tagged_fmt("dbg_tools", "debugger_get_callstack_impl: entry");
    if (auto err = ensure_attached(params)) {
        json details = make_callstack_failure(
            driver_bridge::attached_pid(),
            0,
            "attach_unavailable",
            err->text,
            GetLastError(),
            false);
        return tool_result_t::error(err->text, "callstack_attach_unavailable", details);
    }

    auto tid_opt = parse_tid(params);
    if (!tid_opt) {
        diag::log_tagged_fmt("dbg_tools", "debugger_get_callstack_impl: missing tid param");
        json details = make_callstack_failure(
            driver_bridge::attached_pid(),
            0,
            "missing_tid",
            std::string("'tid' (thread ID) is required."),
            ERROR_INVALID_PARAMETER,
            false);
        return tool_result_t::error(
            std::string("'tid' (thread ID) is required."),
            "callstack_missing_tid",
            details);
    }
    const std::uint32_t tid = *tid_opt;

    int max_depth = 64;
    if (params.contains("max_depth") && params["max_depth"].is_number())
        max_depth = std::clamp(params["max_depth"].get<int>(), 1, 256);

    diag::log_tagged_fmt("dbg_tools", "debugger_get_callstack_impl: tid=%u max_depth=%d", tid, max_depth);

    std::uint32_t prev_count = 0;
    const bool did_suspend = device->suspend_thread(tid, &prev_count);
    diag::log_tagged_fmt("dbg_tools", "debugger_get_callstack_impl: suspend_thread did_suspend=%d", (int)did_suspend);

    voyager::device_t::thread_context ctx{};
    if (!device->get_thread_context(tid, ctx))
    {
        const DWORD gle = GetLastError();
        diag::log_tagged_fmt("dbg_tools", "debugger_get_callstack_impl: kernel get_thread_context failed tid=%u gle=%lu kernel=%d attached_pid=%u status=%s last_error=%s",
            tid,
            static_cast<unsigned long>(gle),
            driver_bridge::using_kernel_driver() ? 1 : 0,
            driver_bridge::attached_pid(),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        if (did_suspend) device->resume_thread(tid);
        SetLastError(gle);
        json details = make_callstack_failure(
            driver_bridge::attached_pid(),
            tid,
            "thread_context_unavailable",
            std::string("Failed to get thread context for TID ") + std::to_string(tid),
            gle,
            did_suspend);
        return tool_result_t::error(
            std::string("Failed to get thread context for TID ") + std::to_string(tid),
            "callstack_thread_context_unavailable",
            details);
    }
    diag::log_tagged_fmt("dbg_tools", "debugger_get_callstack_impl: thread context RIP=0x%llX RSP=0x%llX RBP=0x%llX", (unsigned long long)ctx.rip, (unsigned long long)ctx.rsp, (unsigned long long)ctx.rbp);

    json frames = json::array();
    std::vector<std::uint64_t> frame_addresses;
    frame_addresses.reserve(static_cast<std::size_t>(max_depth));


    {
        json f;
        f["depth"]   = 0;
        f["rip"]     = sa_format_address(static_cast<uint64_t>(ctx.rip));
        f["rsp"]     = sa_format_address(static_cast<uint64_t>(ctx.rsp));
        f["rbp"]     = sa_format_address(static_cast<uint64_t>(ctx.rbp));


        uint8_t code[16] = {};
        if (device->read_raw(ctx.rip, code, sizeof(code)) >= 1)
        {
            AsmInstr ins = zydis_decode_one(code, 16, ctx.rip);
            f["instruction"] = std::string(ins.mnem) + " " + std::string(ins.ops);
        }
        frames.push_back(f);
        frame_addresses.push_back(static_cast<std::uint64_t>(ctx.rip));
    }


    std::uint64_t rbp = ctx.rbp;
    std::uint64_t rsp = ctx.rsp;


    const bool rbp_looks_valid =
        rbp > 0x10000 && rbp < 0x7FFFFFFFFFFF0000ULL &&
        rbp > rsp && (rbp - rsp) < 0x100000;

    if (rbp_looks_valid)
    {

        for (int depth = 1; depth < max_depth; ++depth)
        {

            if (rbp == 0 || rbp < 0x10000 || rbp > 0x7FFFFFFFFFFF0000ULL)
                break;


            std::uint64_t saved_rbp = 0;
            std::uint64_t ret_addr  = 0;
            if (device->read_raw(rbp, &saved_rbp, 8) < 8)
                break;
            if (device->read_raw(rbp + 8, &ret_addr, 8) < 8)
                break;


            if (ret_addr == 0 || ret_addr < 0x10000)
                break;

            json f;
            f["depth"]      = depth;
            f["rip"]        = sa_format_address(ret_addr);
            f["rbp"]        = sa_format_address(saved_rbp);
            f["frame_addr"] = sa_format_address(rbp);


            uint8_t code[16] = {};
            if (device->read_raw(ret_addr, code, sizeof(code)) >= 1)
            {
                AsmInstr ins = zydis_decode_one(code, 16, ret_addr);
                f["instruction"] = std::string(ins.mnem) + " " + std::string(ins.ops);
            }

            frames.push_back(f);
            frame_addresses.push_back(ret_addr);


            if (saved_rbp == rbp || saved_rbp <= rbp)
                break;
            rbp = saved_rbp;
        }
    }
    else
    {


        constexpr std::size_t SCAN_SIZE = 0x800;
        std::vector<std::uint8_t> stack_data(SCAN_SIZE);
        std::size_t read = device->read_raw(rsp, stack_data.data(), SCAN_SIZE);
        int depth = 1;

        for (std::size_t off = 0; off + 8 <= read && depth < max_depth; off += 8)
        {
            std::uint64_t candidate = 0;
            std::memcpy(&candidate, stack_data.data() + off, 8);


            if (candidate < 0x10000 || candidate > 0x7FFFFFFFFFFF0000ULL)
                continue;


            voyager::device_t::memory_region_info region{};
            if (!device->query_memory(candidate, region))
                continue;
            if (region.state != 0x1000)
                continue;
            if (!(region.protect & 0xF0))
                continue;


            uint8_t code[16] = {};
            if (device->read_raw(candidate, code, sizeof(code)) < 1)
                continue;
            AsmInstr ins = zydis_decode_one(code, 16, candidate);

            if (ins.len <= 0)
                continue;

            json f;
            f["depth"]        = depth;
            f["rip"]          = sa_format_address(candidate);
            f["stack_offset"] = sa_format_address(rsp + off);
            f["instruction"]  = std::string(ins.mnem) + " " + std::string(ins.ops);
            f["method"]       = "stack_scan";
            frames.push_back(f);
            frame_addresses.push_back(candidate);
            ++depth;
        }
    }


    if (did_suspend)
        device->resume_thread(tid);

    const std::uint32_t pid = driver_bridge::attached_pid();
    auto resolutions = debugger_engine::resolve_call_stack_frames(frame_addresses);
    std::size_t resolved_symbols = 0;
    std::size_t nearest_symbols = 0;
    std::size_t exact_symbols = 0;
    std::size_t module_rva_fallbacks = 0;
    std::size_t unresolved_frames = 0;
    const std::string unwind_method = rbp_looks_valid ? "rbp_chain" : "stack_scan";
    for (std::size_t i = 0; i < frames.size() && i < resolutions.size(); ++i) {
        auto& r = resolutions[i];
        const char* frame_unwind_status = i == 0 ? "context" : unwind_method.c_str();
        apply_callstack_resolution(frames[i], r, pid, tid, frame_unwind_status);
        const bool has_symbol = !r.function_name.empty();
        const bool has_module = !r.module_name.empty();
        if (has_symbol)
            ++resolved_symbols;
        if (callstack_source_contains(r.source, "nearest"))
            ++nearest_symbols;
        if (callstack_source_contains(r.source, "exact"))
            ++exact_symbols;
        if (r.source == "module_rva")
            ++module_rva_fallbacks;
        if (!has_symbol || !has_module)
            ++unresolved_frames;
    }
    if (resolutions.size() < frames.size())
        unresolved_frames += frames.size() - resolutions.size();

    const bool top_available = !frames.empty() &&
        !resolutions.empty() &&
        !resolutions.front().module_name.empty() &&
        !resolutions.front().function_name.empty() &&
        resolutions.front().address != 0;

    diag::log_tagged_fmt("dbg_tools",
        "debugger_get_callstack_impl: tid=%u pid=%u method=%s frames=%zu resolved=%zu nearest=%zu exact=%zu module_rva=%zu unresolved=%zu top_available=%d",
        tid,
        pid,
        unwind_method.c_str(),
        frames.size(),
        resolved_symbols,
        nearest_symbols,
        exact_symbols,
        module_rva_fallbacks,
        unresolved_frames,
        top_available ? 1 : 0);
    json result;
    result["available"] = top_available;
    result["pid"] = pid;
    result["target_pid"] = pid;
    result["tid"] = tid;
    result["requested_tid"] = tid;
    result["frame_count"] = static_cast<int>(frames.size());
    result["method"] = unwind_method;
    result["unwind_method"] = unwind_method;
    result["unwind_status"] = top_available ? "ok" : (frames.empty() ? "no_frames" : "top_frame_symbol_unavailable");
    result["top_frame_address"] = (!resolutions.empty() && resolutions.front().address != 0)
        ? json(sa_format_address(resolutions.front().address))
        : json(nullptr);
    result["top_frame_module"] = (!resolutions.empty() ? resolutions.front().module_name : std::string());
    result["top_frame_function"] = (!resolutions.empty() ? resolutions.front().function_name : std::string());
    result["symbol_resolution"] = json{
        {"attempted", resolutions.size()},
        {"resolved_symbols", resolved_symbols},
        {"nearest_symbols", nearest_symbols},
        {"exact_symbols", exact_symbols},
        {"module_rva_fallbacks", module_rva_fallbacks},
        {"unresolved_frames", unresolved_frames}
    };
    result["frames"] = frames;
    if (!top_available) {
        result["failure"] = make_callstack_failure(
            pid,
            tid,
            frames.empty() ? "no_frames" : "top_frame_symbol_unavailable",
            frames.empty() ? "No callstack frames were produced." : "Top callstack frame could not be tied to module and symbol evidence.",
            ERROR_NOT_FOUND,
            did_suspend);
        return tool_result_t::error(
            std::string("Call stack evidence is unavailable for TID ") + std::to_string(tid),
            "callstack_evidence_unavailable",
            result);
    }
    result["failure"] = nullptr;
    return tool_result_t::ok(
        std::string("Call stack for TID ") + std::to_string(tid) +
        std::string(": ") + std::to_string(frames.size()) + std::string(" frame(s)"),
        result);
}


struct memory_snapshot_region
{
    std::uint64_t             address = 0;
    std::vector<std::uint8_t> data;
};

struct execution_snapshot
{
    std::string                          name;
    std::uint32_t                        tid = 0;
    voyager::device_t::thread_context    ctx{};
    std::vector<memory_snapshot_region>  memory;
    std::chrono::steady_clock::time_point timestamp;
};

static std::mutex                                   s_snap_mutex;
static std::map<std::string, execution_snapshot>    s_snapshots;

static tool_result_t dbg_snapshot_state(const json& params)
{
    diag::log_tagged_fmt("dbg_tools", "dbg_snapshot_state: entry");
    if (auto err = ensure_attached(params))
        return *err;

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_err = acquire_driver_debugger_quota("dbg_snapshot_state", driver_bridge::attached_pid(), quota_guard))
        return *quota_err;

    auto tid_opt = parse_tid(params);
    if (!tid_opt) {
        diag::log_tagged_fmt("dbg_tools", "dbg_snapshot_state: missing tid param");
        return tool_result_t::error(std::string("'tid' (thread ID) is required."));
    }
    const std::uint32_t tid = *tid_opt;

    std::string snap_name = "default";
    if (params.contains("name") && params["name"].is_string())
        snap_name = params["name"].get<std::string>();
    if (snap_name.empty()) {
        diag::log_tagged_fmt("dbg_tools", "dbg_snapshot_state: empty snapshot name");
        return tool_result_t::error(std::string("Snapshot name cannot be empty."));
    }
    diag::log_tagged_fmt("dbg_tools", "dbg_snapshot_state: capturing snapshot '%s' tid=%u", snap_name.c_str(), tid);


    std::uint32_t prev_count = 0;
    const bool did_suspend = device->suspend_thread(tid, &prev_count);

    voyager::device_t::thread_context ctx{};
    if (!device->get_thread_context(tid, ctx))
    {
        const DWORD gle = GetLastError();
        diag::log_tagged_fmt("dbg_tools", "dbg_snapshot_state: kernel get_thread_context failed tid=%u gle=%lu kernel=%d attached_pid=%u status=%s last_error=%s",
            tid,
            static_cast<unsigned long>(gle),
            driver_bridge::using_kernel_driver() ? 1 : 0,
            driver_bridge::attached_pid(),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        if (did_suspend) device->resume_thread(tid);
        SetLastError(gle);
        return tool_result_t::error(
            std::string("Failed to get thread context for TID ") + std::to_string(tid));
    }

    execution_snapshot snap;
    snap.name      = snap_name;
    snap.tid       = tid;
    snap.ctx       = ctx;
    snap.timestamp = std::chrono::steady_clock::now();


    if (params.contains("memory_regions") && params["memory_regions"].is_array())
    {
        for (const auto& region : params["memory_regions"])
        {
            if (!region.contains("address") || !region["address"].is_string())
                continue;
            auto addr = sa_parse_address(region["address"].get<std::string>());
            if (!addr || *addr == 0)
                continue;

            std::size_t size = 256;
            if (region.contains("size") && region["size"].is_number())
                size = static_cast<std::size_t>(
                    std::clamp(region["size"].get<int>(), 1, 65536));

            memory_snapshot_region mem;
            mem.address = *addr;
            mem.data.resize(size);
            std::size_t read = device->read_raw(*addr, mem.data.data(), size);
            mem.data.resize(read);
            snap.memory.push_back(std::move(mem));
        }
    }

    if (did_suspend)
        device->resume_thread(tid);


    json result;
    result["name"]           = snap_name;
    result["tid"]            = tid;
    result["rip"]            = sa_format_address(static_cast<uint64_t>(ctx.rip));
    result["rsp"]            = sa_format_address(static_cast<uint64_t>(ctx.rsp));
    result["memory_regions"] = static_cast<int>(snap.memory.size());


    {
        std::lock_guard<std::mutex> lock(s_snap_mutex);
        s_snapshots[snap_name] = std::move(snap);
    }

    diag::log_tagged_fmt("dbg_tools", "dbg_snapshot_state: snapshot '%s' captured tid=%u RIP=0x%llX memory_regions=%zu", snap_name.c_str(), tid, (unsigned long long)ctx.rip, snap.memory.size());
    return tool_result_t::ok(
        std::string("Snapshot '") + snap_name + std::string("' captured"), result);
}

static tool_result_t dbg_compare_snapshots(const json& params)
{
    diag::log_tagged_fmt("dbg_tools", "dbg_compare_snapshots: entry");
    if (!params.contains("snapshot_a") || !params["snapshot_a"].is_string()) {
        diag::log_tagged_fmt("dbg_tools", "dbg_compare_snapshots: missing snapshot_a");
        return tool_result_t::error(std::string("'snapshot_a' name is required."));
    }
    if (!params.contains("snapshot_b") || !params["snapshot_b"].is_string()) {
        diag::log_tagged_fmt("dbg_tools", "dbg_compare_snapshots: missing snapshot_b");
        return tool_result_t::error(std::string("'snapshot_b' name is required."));
    }

    const std::string name_a = params["snapshot_a"].get<std::string>();
    const std::string name_b = params["snapshot_b"].get<std::string>();
    diag::log_tagged_fmt("dbg_tools", "dbg_compare_snapshots: comparing '%s' vs '%s'", name_a.c_str(), name_b.c_str());

    std::lock_guard<std::mutex> lock(s_snap_mutex);

    auto it_a = s_snapshots.find(name_a);
    auto it_b = s_snapshots.find(name_b);
    if (it_a == s_snapshots.end()) {
        diag::log_tagged_fmt("dbg_tools", "dbg_compare_snapshots: snapshot '%s' not found", name_a.c_str());
        return tool_result_t::error(std::string("Snapshot '") + name_a + std::string("' not found."));
    }
    if (it_b == s_snapshots.end()) {
        diag::log_tagged_fmt("dbg_tools", "dbg_compare_snapshots: snapshot '%s' not found", name_b.c_str());
        return tool_result_t::error(std::string("Snapshot '") + name_b + std::string("' not found."));
    }

    const auto& a = it_a->second;
    const auto& b = it_b->second;


    json reg_diffs = json::array();
    auto cmp_reg = [&](const char* name, std::uint64_t va, std::uint64_t vb) {
        if (va != vb)
        {
            json d;
            d["register"] = name;
            d["before"]   = sa_format_address(va);
            d["after"]    = sa_format_address(vb);
            reg_diffs.push_back(d);
        }
    };

    cmp_reg("rax", a.ctx.rax, b.ctx.rax);
    cmp_reg("rbx", a.ctx.rbx, b.ctx.rbx);
    cmp_reg("rcx", a.ctx.rcx, b.ctx.rcx);
    cmp_reg("rdx", a.ctx.rdx, b.ctx.rdx);
    cmp_reg("rsi", a.ctx.rsi, b.ctx.rsi);
    cmp_reg("rdi", a.ctx.rdi, b.ctx.rdi);
    cmp_reg("rbp", a.ctx.rbp, b.ctx.rbp);
    cmp_reg("rsp", a.ctx.rsp, b.ctx.rsp);
    cmp_reg("r8",  a.ctx.r8,  b.ctx.r8);
    cmp_reg("r9",  a.ctx.r9,  b.ctx.r9);
    cmp_reg("r10", a.ctx.r10, b.ctx.r10);
    cmp_reg("r11", a.ctx.r11, b.ctx.r11);
    cmp_reg("r12", a.ctx.r12, b.ctx.r12);
    cmp_reg("r13", a.ctx.r13, b.ctx.r13);
    cmp_reg("r14", a.ctx.r14, b.ctx.r14);
    cmp_reg("r15", a.ctx.r15, b.ctx.r15);
    cmp_reg("rip", a.ctx.rip, b.ctx.rip);
    cmp_reg("rflags", a.ctx.rflags, b.ctx.rflags);
    cmp_reg("dr0", a.ctx.dr0, b.ctx.dr0);
    cmp_reg("dr1", a.ctx.dr1, b.ctx.dr1);
    cmp_reg("dr2", a.ctx.dr2, b.ctx.dr2);
    cmp_reg("dr3", a.ctx.dr3, b.ctx.dr3);
    cmp_reg("dr6", a.ctx.dr6, b.ctx.dr6);
    cmp_reg("dr7", a.ctx.dr7, b.ctx.dr7);


    json mem_diffs = json::array();
    for (const auto& mem_a : a.memory)
    {
        for (const auto& mem_b : b.memory)
        {
            if (mem_a.address != mem_b.address)
                continue;

            const std::size_t cmp_len =
                (std::min)(mem_a.data.size(), mem_b.data.size());
            json byte_diffs = json::array();

            for (std::size_t i = 0; i < cmp_len; ++i)
            {
                if (mem_a.data[i] != mem_b.data[i])
                {
                    json bd;
                    bd["offset"] = static_cast<int>(i);
                    bd["address"] = sa_format_address(mem_a.address + i);
                    bd["before"]  = sa_format_address(
                        static_cast<uint64_t>(mem_a.data[i]));
                    bd["after"]   = sa_format_address(
                        static_cast<uint64_t>(mem_b.data[i]));
                    byte_diffs.push_back(bd);
                    if (byte_diffs.size() >= 256)
                        break;
                }
            }

            if (!byte_diffs.empty())
            {
                json rd;
                rd["address"]    = sa_format_address(mem_a.address);
                rd["diff_count"] = static_cast<int>(byte_diffs.size());
                rd["diffs"]      = byte_diffs;
                if (mem_a.data.size() != mem_b.data.size())
                {
                    rd["size_a"] = static_cast<int>(mem_a.data.size());
                    rd["size_b"] = static_cast<int>(mem_b.data.size());
                }
                mem_diffs.push_back(rd);
            }
            break;
        }
    }

    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        b.timestamp - a.timestamp).count();

    json result;
    result["snapshot_a"]       = name_a;
    result["snapshot_b"]       = name_b;
    result["tid_a"]            = a.tid;
    result["tid_b"]            = b.tid;
    result["elapsed_ms"]       = static_cast<int>(elapsed_ms);
    result["register_changes"] = static_cast<int>(reg_diffs.size());
    result["register_diffs"]   = reg_diffs;
    result["memory_changes"]   = static_cast<int>(mem_diffs.size());
    result["memory_diffs"]     = mem_diffs;

    diag::log_tagged_fmt("dbg_tools", "dbg_compare_snapshots: '%s' vs '%s' => %zu reg diffs, %zu mem diffs, elapsed_ms=%lld", name_a.c_str(), name_b.c_str(), reg_diffs.size(), mem_diffs.size(), (long long)elapsed_ms);
    return tool_result_t::ok(
        std::string("Diff: ") + std::to_string(reg_diffs.size()) +
        std::string(" register(s), ") + std::to_string(mem_diffs.size()) +
        std::string(" memory region(s) changed"),
        result);
}


static tool_result_t dbg_detect_vm_handler(const json& params)
{
    diag::log_tagged_fmt("dbg_tools", "dbg_detect_vm_handler: entry");
    if (auto err = ensure_attached(params))
        return *err;

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_err = acquire_driver_debugger_quota("dbg_detect_vm_handler", driver_bridge::attached_pid(), quota_guard))
        return *quota_err;

    if (!params.contains("address") || !params["address"].is_string()) {
        diag::log_tagged_fmt("dbg_tools", "dbg_detect_vm_handler: missing address param");
        return tool_result_t::error(std::string("'address' (hex string) is required."));
    }

    auto addr_opt = sa_parse_address(params["address"].get<std::string>());
    if (!addr_opt || *addr_opt == 0) {
        diag::log_tagged_fmt("dbg_tools", "dbg_detect_vm_handler: invalid address");
        return tool_result_t::error(std::string("Invalid address."));
    }
    const std::uint64_t addr = *addr_opt;

    int scan_size = 512;
    if (params.contains("size") && params["size"].is_number())
        scan_size = std::clamp(params["size"].get<int>(), 64, 16384);
    diag::log_tagged_fmt("dbg_tools", "dbg_detect_vm_handler: analyzing 0x%llX size=%d", (unsigned long long)addr, scan_size);


    std::vector<uint8_t> code(static_cast<std::size_t>(scan_size));
    std::size_t read = device->read_raw(addr, code.data(), code.size());
    if (read < 16) {
        diag::log_tagged_fmt("dbg_tools", "dbg_detect_vm_handler: only %zu bytes read at 0x%llX", read, (unsigned long long)addr);
        return tool_result_t::error(
            std::string("Insufficient bytes read at ") + sa_format_address(addr));
    }
    diag::log_tagged_fmt("dbg_tools", "dbg_detect_vm_handler: read %zu bytes", read);
    code.resize(read);

    zydis_detail::ensure_init();


    json indicators = json::array();
    int indirect_jumps      = 0;
    int scaled_jumps        = 0;
    int memory_reads        = 0;
    int dispatch_candidates = 0;
    std::uint64_t likely_dispatch_addr = 0;

    std::size_t offset = 0;
    std::uint64_t va = addr;
    int instr_count = 0;

    ZydisDecodedInstruction instr;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    while (offset + 1 <= code.size() && instr_count < 2000)
    {
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
                &zydis_detail::decoder(),
                code.data() + offset,
                code.size() - offset,
                &instr, operands)))
        {
            offset++;
            va++;
            continue;
        }

        ++instr_count;


        if (instr.mnemonic == ZYDIS_MNEMONIC_JMP)
        {
            for (int i = 0; i < static_cast<int>(instr.operand_count_visible); ++i)
            {
                const auto& op = operands[i];
                if (op.type == ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    ++indirect_jumps;
                    json ind;
                    ind["type"]    = "indirect_jmp_reg";
                    ind["address"] = sa_format_address(va);
                    char buf[128] = {};
                    ZydisFormatterFormatInstruction(
                        &zydis_detail::formatter(), &instr, operands,
                        instr.operand_count_visible, buf, sizeof(buf),
                        va, ZYAN_NULL);
                    ind["instruction"] = buf;
                    indicators.push_back(ind);
                    if (likely_dispatch_addr == 0)
                        likely_dispatch_addr = va;
                }
                else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    if (op.mem.scale > 1)
                    {
                        ++scaled_jumps;
                        json ind;
                        ind["type"]    = "scaled_table_jmp";
                        ind["address"] = sa_format_address(va);
                        ind["scale"]   = op.mem.scale;
                        char buf[128] = {};
                        ZydisFormatterFormatInstruction(
                            &zydis_detail::formatter(), &instr, operands,
                            instr.operand_count_visible, buf, sizeof(buf),
                            va, ZYAN_NULL);
                        ind["instruction"] = buf;
                        indicators.push_back(ind);
                        ++dispatch_candidates;
                        if (likely_dispatch_addr == 0)
                            likely_dispatch_addr = va;
                    }
                    else
                    {
                        ++indirect_jumps;
                        json ind;
                        ind["type"]    = "indirect_jmp_mem";
                        ind["address"] = sa_format_address(va);
                        char buf[128] = {};
                        ZydisFormatterFormatInstruction(
                            &zydis_detail::formatter(), &instr, operands,
                            instr.operand_count_visible, buf, sizeof(buf),
                            va, ZYAN_NULL);
                        ind["instruction"] = buf;
                        indicators.push_back(ind);
                    }
                }
            }
        }


        if (instr.mnemonic == ZYDIS_MNEMONIC_MOVZX ||
            instr.mnemonic == ZYDIS_MNEMONIC_MOVSX)
        {
            for (int i = 0; i < static_cast<int>(instr.operand_count_visible); ++i)
            {
                if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    ++memory_reads;
                    break;
                }
            }
        }

        offset += instr.length;
        va     += instr.length;
    }


    double score = 0.0;
    if (indirect_jumps > 0)  score += 20.0;
    if (scaled_jumps > 0)    score += 40.0;
    if (memory_reads > 3)    score += 15.0;
    if (dispatch_candidates > 0) score += 25.0;
    score = (std::min)(score, 100.0);

    std::string verdict;
    if (score >= 60.0)      verdict = "HIGH — likely VM dispatcher";
    else if (score >= 30.0) verdict = "MEDIUM — possible VM handler region";
    else                    verdict = "LOW — unlikely VM code";

    json result;
    result["address"]              = sa_format_address(addr);
    result["bytes_analyzed"]       = static_cast<int>(read);
    result["instructions_decoded"] = instr_count;
    result["indirect_jumps"]       = indirect_jumps;
    result["scaled_table_jumps"]   = scaled_jumps;
    result["memory_reads"]         = memory_reads;
    result["dispatch_candidates"]  = dispatch_candidates;
    result["vm_score"]             = static_cast<int>(score);
    result["verdict"]              = verdict;
    result["indicators"]           = indicators;
    if (likely_dispatch_addr != 0)
        result["likely_dispatch"] = sa_format_address(likely_dispatch_addr);

    diag::log_tagged_fmt("dbg_tools", "dbg_detect_vm_handler: addr=0x%llX score=%d verdict=%s indirect_jmps=%d scaled_jmps=%d", (unsigned long long)addr, (int)score, verdict.c_str(), indirect_jumps, scaled_jumps);
    return tool_result_t::ok(
        std::string("VM analysis at ") + sa_format_address(addr) +
        std::string(": ") + verdict, result);
}

static tool_result_t dbg_map_vm_handlers(const json& params)
{
    diag::log_tagged_fmt("dbg_tools", "dbg_map_vm_handlers: entry");
    if (auto err = ensure_attached(params))
        return *err;

    driver_debugger_quota_guard_t quota_guard;
    if (auto quota_err = acquire_driver_debugger_quota("dbg_map_vm_handlers", driver_bridge::attached_pid(), quota_guard))
        return *quota_err;

    if (!params.contains("table_address") || !params["table_address"].is_string()) {
        diag::log_tagged_fmt("dbg_tools", "dbg_map_vm_handlers: missing table_address param");
        return tool_result_t::error(
            std::string("'table_address' (hex string of handler table base) is required."));
    }

    auto table_addr_opt = sa_parse_address(
        params["table_address"].get<std::string>());
    if (!table_addr_opt || *table_addr_opt == 0) {
        diag::log_tagged_fmt("dbg_tools", "dbg_map_vm_handlers: invalid table_address");
        return tool_result_t::error(std::string("Invalid table_address."));
    }
    const std::uint64_t table_base = *table_addr_opt;

    int entry_count = 256;
    if (params.contains("count") && params["count"].is_number())
        entry_count = std::clamp(params["count"].get<int>(), 1, 4096);
    diag::log_tagged_fmt("dbg_tools", "dbg_map_vm_handlers: table=0x%llX count=%d", (unsigned long long)table_base, entry_count);

    int entry_size = 8;
    if (params.contains("entry_size") && params["entry_size"].is_number())
        entry_size = std::clamp(params["entry_size"].get<int>(), 1, 8);

    int preview_instructions = 5;
    if (params.contains("preview_instructions") && params["preview_instructions"].is_number())
        preview_instructions = std::clamp(
            params["preview_instructions"].get<int>(), 0, 32);


    bool relative = false;
    if (params.contains("relative") && params["relative"].is_boolean())
        relative = params["relative"].get<bool>();

    std::uint64_t image_base = 0;
    if (relative)
    {
        if (params.contains("image_base") && params["image_base"].is_string())
        {
            auto ib = sa_parse_address(params["image_base"].get<std::string>());
            if (ib) image_base = *ib;
        }
        if (image_base == 0)
            image_base = device->get_base_address();
    }

    zydis_detail::ensure_init();


    const std::size_t table_byte_size =
        static_cast<std::size_t>(entry_count) * static_cast<std::size_t>(entry_size);
    std::vector<uint8_t> table_data(table_byte_size);
    std::size_t table_read = device->read_raw(
        table_base, table_data.data(), table_byte_size);
    if (table_read < static_cast<std::size_t>(entry_size)) {
        diag::log_tagged_fmt("dbg_tools", "dbg_map_vm_handlers: failed to read table at 0x%llX read=%zu", (unsigned long long)table_base, table_read);
        return tool_result_t::error(
            std::string("Failed to read handler table at ") +
            sa_format_address(table_base));
    }
    diag::log_tagged_fmt("dbg_tools", "dbg_map_vm_handlers: read %zu bytes from table", table_read);

    const int actual_entries =
        static_cast<int>(table_read) / entry_size;

    json handlers = json::array();
    int valid_count = 0;
    int null_count  = 0;

    for (int i = 0; i < actual_entries; ++i)
    {
        if (mcp_standalone::current_call_cancelled())
            return tool_result_t::error("Tool cancelled during VM handler mapping.");
        std::uint64_t raw_value = 0;
        std::memcpy(&raw_value,
                     table_data.data() + static_cast<std::size_t>(i) * static_cast<std::size_t>(entry_size),
                     static_cast<std::size_t>(entry_size));


        if (entry_size == 4)
            raw_value = static_cast<std::uint64_t>(
                static_cast<std::int32_t>(raw_value & 0xFFFFFFFF));


        std::uint64_t handler_addr = raw_value;
        if (relative)
            handler_addr = image_base + raw_value;

        if (handler_addr == 0 || handler_addr < 0x10000)
        {
            ++null_count;
            continue;
        }

        json entry;
        entry["index"]        = i;
        entry["table_offset"] = sa_format_address(
            table_base + static_cast<uint64_t>(i) * static_cast<uint64_t>(entry_size));
        entry["raw_value"]    = sa_format_address(raw_value);
        entry["handler_addr"] = sa_format_address(handler_addr);


        if (preview_instructions > 0)
        {
            const int preview_bytes = preview_instructions * 15;
            std::vector<uint8_t> code(static_cast<std::size_t>(preview_bytes));
            std::size_t code_read = device->read_raw(
                handler_addr, code.data(), code.size());

            if (code_read >= 1)
            {
                json disasm_arr = json::array();
                std::size_t off = 0;
                std::uint64_t pc = handler_addr;
                int decoded = 0;

                while (off < code_read && decoded < preview_instructions)
                {
                    AsmInstr ins = zydis_decode_one(
                        code.data() + off,
                        static_cast<int>(code_read - off),
                        pc);

                    json dj;
                    dj["address"]     = sa_format_address(pc);
                    dj["instruction"] = std::string(ins.mnem) + " " + std::string(ins.ops);
                    dj["size"]        = ins.len;
                    disasm_arr.push_back(dj);

                    off += static_cast<std::size_t>(ins.len);
                    pc  += static_cast<uint64_t>(ins.len);
                    ++decoded;
                }
                entry["disassembly"] = disasm_arr;
            }
        }

        handlers.push_back(entry);
        ++valid_count;
    }

    json result;
    result["table_address"]  = sa_format_address(table_base);
    result["entry_size"]     = entry_size;
    result["entries_read"]   = actual_entries;
    result["valid_handlers"] = valid_count;
    result["null_entries"]   = null_count;
    result["relative"]       = relative;
    if (relative)
        result["image_base"] = sa_format_address(image_base);
    result["handlers"]       = handlers;

    diag::log_tagged_fmt("dbg_tools", "dbg_map_vm_handlers: table=0x%llX valid=%d null=%d", (unsigned long long)table_base, valid_count, null_count);
    return tool_result_t::ok(
        std::string("Mapped ") + std::to_string(valid_count) +
        std::string(" handlers from table at ") + sa_format_address(table_base),
        result);
}


void register_debugger_tools(mcp_standalone::server_t& srv)
{
    diag::log_tagged_fmt("dbg_tools", "register_debugger_tools: registering all debugger MCP tools");







    register_compat(srv, {
        std::string("dbg_snapshot_state"), std::string("debugger"),
        std::string("Capture the full execution state (all registers + optional memory regions) of a "
               "thread into a named snapshot. Snapshots can be compared with dbg_compare_snapshots "
               "to see exactly which registers and bytes changed between two points in execution."),
        {{std::string("tid"), std::string("string"), std::string("Thread ID"), true},
         {std::string("name"), std::string("string"), std::string("Snapshot name (default 'default'). Use descriptive names like 'before_call', 'after_decrypt'."), false},
         {std::string("memory_regions"), std::string("array"),
          std::string("Optional array of {address, size} objects specifying memory regions to capture."), false, {},
          json::object({{"type", "object"},
                        {"properties", json::object({
                            {"address", json::object({{"type", "string"}})},
                            {"size", json::object({{"type", "number"}})}
                        })}
          })},
         {std::string("process_id"), std::string("number"), std::string("Optional PID override (alias: target_pid). Switches the active attach context for the duration of this call."), false}},
        dbg_snapshot_state, false});

    register_compat(srv, {
        std::string("dbg_compare_snapshots"), std::string("debugger"),
        std::string("Compare two previously captured execution snapshots. Shows all register "
               "differences and byte-level memory diffs. Useful for tracing exactly what a "
               "function call modified, detecting encryption/decryption state changes, or "
               "verifying that a code patch had the expected effect."),
        {{std::string("snapshot_a"), std::string("string"), std::string("Name of the 'before' snapshot"), true},
         {std::string("snapshot_b"), std::string("string"), std::string("Name of the 'after' snapshot"), true}},
        dbg_compare_snapshots, true});


    register_compat(srv, {
        std::string("dbg_detect_vm_handler"), std::string("debugger"),
        std::string("Analyze code at an address to detect virtual machine (VM) obfuscation patterns. "
               "Reads code bytes from the target process and uses Zydis disassembly to identify "
               "VM dispatcher indicators: indirect jumps through registers, scaled table dispatches "
               "(jmp [reg*8+table]), opcode fetch patterns (movzx/movsx from memory), and other "
               "common VM handler idioms. Returns a confidence score and detailed indicators."),
        {{std::string("address"), std::string("string"), std::string("Address to analyze (hex)"), true},
         {std::string("size"), std::string("number"), std::string("Bytes to analyze (default 512, max 16384)"), false},
         {std::string("process_id"), std::string("number"), std::string("Optional PID override (alias: target_pid). Switches the active attach context for the duration of this call."), false}},
        dbg_detect_vm_handler, true});

    register_compat(srv, {
        std::string("dbg_map_vm_handlers"), std::string("debugger"),
        std::string("Read a VM handler dispatch table from target memory and disassemble each handler entry. "
               "Reads an array of handler pointers (or relative offsets) from a table address, resolves "
               "each to a handler address, and provides a Zydis disassembly preview of each handler. "
               "Use dbg_detect_vm_handler first to locate the dispatch table, then use this tool to "
               "map all handler entries."),
        {{std::string("table_address"), std::string("string"), std::string("Base address of the handler table (hex)"), true},
         {std::string("count"), std::string("number"), std::string("Number of entries to read (default 256, max 4096)"), false},
         {std::string("entry_size"), std::string("number"), std::string("Size of each table entry in bytes: 4 or 8 (default 8)"), false},
         {std::string("relative"), std::string("boolean"), std::string("If true, entries are relative offsets from image_base (default false = absolute pointers)"), false},
         {std::string("image_base"), std::string("string"), std::string("Base address for resolving relative offsets (default: attached process image base)"), false},
         {std::string("preview_instructions"), std::string("number"), std::string("Instructions to disassemble per handler (default 5, max 32)"), false},
         {std::string("process_id"), std::string("number"), std::string("Optional PID override (alias: target_pid). Switches the active attach context for the duration of this call."), false}},
        dbg_map_vm_handlers, true});







    register_compat(srv, {
        std::string("dbg_run_to_address"), std::string("debugger"),
        std::string("Run until execution reaches a specific address."),
        {{std::string("address"), std::string("string"), std::string("Target address (hex)"), true},
         {std::string("wait_for_completion"), std::string("boolean"), std::string("Wait until the address is reached before returning."), false},
         {std::string("timeout_ms"), std::string("number"), std::string("Maximum wait time in milliseconds when wait_for_completion is true."), false},
         {std::string("process_id"), std::string("number"), std::string("Optional PID override (alias: target_pid). Switches the active attach context for the duration of this call."), false}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_run_to_address: entry");
            if (mcp_standalone::current_call_cancelled())
                return tool_result_t::error("Tool cancelled before operation.");
            if (auto err = ensure_attached(params)) return *err;

            driver_debugger_quota_guard_t quota_guard;
            if (auto quota_err = acquire_driver_debugger_quota("dbg_run_to_address", driver_bridge::attached_pid(), quota_guard))
                return *quota_err;

            if (!params.contains("address") || !params["address"].is_string())
                return tool_result_t::error(std::string("'address' is required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(std::string("Invalid address."));

            bool wait = false;
            if (params.contains("wait_for_completion") && params["wait_for_completion"].is_boolean())
                wait = params["wait_for_completion"].get<bool>();
            else if (params.contains("wait") && params["wait"].is_boolean())
                wait = params["wait"].get<bool>();
            uint32_t timeout_ms = static_cast<uint32_t>(int_param_clamped(params, "timeout_ms", 30000, 1, 300000));
            const uint64_t started_ms = GetTickCount64();
            const uint32_t pid_before = driver_bridge::attached_pid();
            const uint32_t tid_before = debugger_engine::g_state.active_tid;
            const auto status_before = debugger_engine::g_state.status.load(std::memory_order_acquire);
            debugger_engine::register_set_t regs_before{};
            bool regs_before_valid = false;
            if (wait && tid_before != 0) {
                regs_before = debugger_engine::get_registers();
                regs_before_valid = true;
            }
            const bool already_reached = wait && regs_before_valid &&
                (regs_before.rip == *addr || regs_before.rip == (*addr + 1));
            diag::log_tagged_fmt("dbg_tools", "dbg_run_to_address: running to 0x%llX wait=%d timeout_ms=%u attached_pid=%u active_tid=%u",
                (unsigned long long)*addr,
                wait ? 1 : 0,
                static_cast<unsigned>(timeout_ms),
                static_cast<unsigned>(driver_bridge::attached_pid()),
                static_cast<unsigned>(debugger_engine::g_state.active_tid));
            if (mcp_standalone::current_call_cancelled())
                return tool_result_t::error("Tool cancelled before run_to_address.");
            bool ok = debugger_engine::run_to_address(*addr, wait, timeout_ms);
            const uint64_t elapsed_ms = GetTickCount64() - started_ms;
            const uint32_t pid_after = driver_bridge::attached_pid();
            const uint32_t tid_after = debugger_engine::g_state.active_tid;
            const auto status_after = debugger_engine::g_state.status.load(std::memory_order_acquire);
            debugger_engine::register_set_t regs_after{};
            bool regs_after_valid = false;
            if (wait && tid_after != 0) {
                regs_after = debugger_engine::get_registers();
                regs_after_valid = true;
            }
            diag::log_tagged_fmt("dbg_tools", "dbg_run_to_address: run_to_address returned ok=%d attached_pid=%u active_tid=%u last_error=%s",
                (int)ok,
                static_cast<unsigned>(driver_bridge::attached_pid()),
                static_cast<unsigned>(debugger_engine::g_state.active_tid),
                debugger_engine::last_error().empty() ? "(empty)" : debugger_engine::last_error().c_str());
            if (!ok)
                return tool_result_t::error(debugger_engine::last_error().empty() ? std::string("run_to_address failed.") : debugger_engine::last_error());
            json result;
            result["pid"] = pid_after;
            result["pid_before"] = pid_before;
            result["address"] = sa_format_address(*addr);
            result["tid"] = tid_after;
            result["tid_before"] = tid_before;
            result["status"] = debugger_status_name(status_after);
            result["status_before"] = debugger_status_name(status_before);
            result["already_reached"] = already_reached;
            result["wait_for_completion"] = wait;
            result["timeout_ms"] = timeout_ms;
            result["elapsed_ms"] = elapsed_ms;
            if (regs_before_valid)
                result["rip_before"] = sa_format_address(regs_before.rip);
            if (regs_after_valid)
                result["rip_after"] = sa_format_address(regs_after.rip);
            result["success"] = true;
            result["engine_status"] = wait ? (already_reached ? "already_reached" : "reached") : "armed";
            diag::log_tagged_fmt("dbg_tools",
                "dbg_run_to_address: success pid=%u tid=%u status=%s already_reached=%d elapsed_ms=%llu rip_before=0x%llX rip_after=0x%llX",
                static_cast<unsigned>(pid_after),
                static_cast<unsigned>(tid_after),
                debugger_status_name(status_after),
                already_reached ? 1 : 0,
                static_cast<unsigned long long>(elapsed_ms),
                static_cast<unsigned long long>(regs_before_valid ? regs_before.rip : 0),
                static_cast<unsigned long long>(regs_after_valid ? regs_after.rip : 0));
            return tool_result_t::ok(std::string("Running to ") + sa_format_address(*addr), result);
        }, false});

    srv.register_tool({
        "debugger_get_attached",
        "Report whether a process is currently attached, its PID, name, image base and image size.",
        {},
        true,
        [](const json&) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_get_attached: entry");
            json result;
            result["driver_connected"] = device->is_connected();
            uint32_t pid = device->is_connected() ? device->get_process_id() : 0u;
            result["is_attached"] = (pid != 0);
            result["pid"] = pid;
            if (pid != 0) {
                uint64_t base = device->find_image();
                result["name"] = driver_bridge::attached_process_name();
                result["base_address"] = sa_format_address(base);
                diag::log_tagged_fmt("dbg_tools", "debugger_get_attached: pid=%u name=%s base=0x%llX", pid, driver_bridge::attached_process_name().c_str(), (unsigned long long)base);
                auto mods = driver_bridge::enumerate_modules();
                uint64_t image_size = 0;
                for (const auto& m : mods) {
                    if (m.base == base) { image_size = m.size; break; }
                }
                if (image_size == 0 && !mods.empty()) image_size = mods.front().size;
                result["image_size"] = image_size;
            }
            return tool_result_t::ok(result);
        }
    });

    srv.register_tool({
        "debugger_get_registers",
        "Snapshot the cached register set for the active debugger thread (RAX..R15, RIP, RFLAGS, segment regs, DR0..DR7).",
        {},
        true,
        [](const json&) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_get_registers: entry");
            auto regs = debugger_engine::get_registers();
            diag::log_tagged_fmt("dbg_tools", "debugger_get_registers: RIP=0x%llX RAX=0x%llX RSP=0x%llX", (unsigned long long)regs.rip, (unsigned long long)regs.rax, (unsigned long long)regs.rsp);
            json result;
            result["rax"] = sa_format_address(regs.rax);
            result["rbx"] = sa_format_address(regs.rbx);
            result["rcx"] = sa_format_address(regs.rcx);
            result["rdx"] = sa_format_address(regs.rdx);
            result["rsi"] = sa_format_address(regs.rsi);
            result["rdi"] = sa_format_address(regs.rdi);
            result["rbp"] = sa_format_address(regs.rbp);
            result["rsp"] = sa_format_address(regs.rsp);
            result["r8"]  = sa_format_address(regs.r8);
            result["r9"]  = sa_format_address(regs.r9);
            result["r10"] = sa_format_address(regs.r10);
            result["r11"] = sa_format_address(regs.r11);
            result["r12"] = sa_format_address(regs.r12);
            result["r13"] = sa_format_address(regs.r13);
            result["r14"] = sa_format_address(regs.r14);
            result["r15"] = sa_format_address(regs.r15);
            result["rip"] = sa_format_address(regs.rip);
            result["rflags"] = sa_format_address(regs.rflags);
            result["flags_decoded"] = debugger_engine::format_flags(regs.rflags);
            result["dr0"] = sa_format_address(regs.dr0);
            result["dr1"] = sa_format_address(regs.dr1);
            result["dr2"] = sa_format_address(regs.dr2);
            result["dr3"] = sa_format_address(regs.dr3);
            result["dr6"] = sa_format_address(regs.dr6);
            result["dr7"] = sa_format_address(regs.dr7);
            return tool_result_t::ok(result);
        }
    });

    register_compat(srv, {
        std::string("debugger_get_memory_map"), std::string("debugger"),
        std::string("Enumerate the attached process memory map with base, end, size, protection, state, type, module, and region info."),
        {{std::string("limit"), std::string("number"), std::string("Maximum regions to return, default 2048, cap 4096"), false},
         {std::string("executable_only"), std::string("boolean"), std::string("Return only executable regions."), false},
         {std::string("target_pid"), std::string("number"), std::string("Optional PID override. Switches the active attach context for this call."), false}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_get_memory_map: entry");
            if (auto err = ensure_attached(params)) return *err;

            driver_debugger_quota_guard_t quota_guard;
            if (auto quota_err = acquire_driver_debugger_quota("debugger_get_memory_map", driver_bridge::attached_pid(), quota_guard))
                return *quota_err;

            const int limit = int_param_clamped(params, "limit", 2048, 1, 4096);
            const bool executable_only = params.value("executable_only", false);
            auto regions = debugger_engine::get_memory_map();
            if (regions.empty()) {
                uint32_t exit_code = 0;
                bool alive = driver_bridge::attached_process_alive(&exit_code);
                if (alive) {
                    json err;
                    err["count"] = 0;
                    err["regions"] = json::array();
                    err["total_regions"] = 0;
                    err["diagnostic"] = "Memory region enumeration returned 0 regions for a live attached process";
                    err["attached_pid"] = driver_bridge::attached_pid();
                    err["driver_status"] = driver_bridge::status();
                    err["driver_last_error"] = driver_bridge::last_error();
                    diag::log_tagged_fmt("dbg_tools", "debugger_get_memory_map: 0 regions for live process pid=%u",
                        driver_bridge::attached_pid());
                    return tool_result_t::error(std::string("Memory map enumeration returned 0 regions for attached process"), err);
                }
            }
            json arr = json::array();
            bool truncated = false;
            uint64_t total_bytes = 0;
            for (const auto& r : regions) {
                const DWORD page_protect = r.protect & 0xffu;
                const bool executable =
                    page_protect == PAGE_EXECUTE ||
                    page_protect == PAGE_EXECUTE_READ ||
                    page_protect == PAGE_EXECUTE_READWRITE ||
                    page_protect == PAGE_EXECUTE_WRITECOPY;
                if (executable_only && !executable)
                    continue;
                if (static_cast<int>(arr.size()) >= limit) {
                    truncated = true;
                    break;
                }
                total_bytes += r.size;
                json o;
                o["base"] = sa_format_address(r.base);
                o["end"] = sa_format_address(r.base + r.size);
                o["size"] = r.size;
                o["protect"] = r.protect;
                o["protect_text"] = debugger_engine::format_protect(r.protect);
                o["state"] = r.state;
                o["type"] = r.type;
                if (!r.module_name.empty()) o["module"] = r.module_name;
                if (!r.info.empty()) o["info"] = r.info;
                arr.push_back(std::move(o));
            }
            json result;
            result["count"] = arr.size();
            result["total_regions"] = regions.size();
            result["total_returned_bytes"] = total_bytes;
            result["truncated"] = truncated;
            result["executable_only"] = executable_only;
            result["regions"] = std::move(arr);
            diag::log_tagged_fmt("dbg_tools", "debugger_get_memory_map: returning count=%zu total=%zu truncated=%d",
                result["count"].get<size_t>(),
                regions.size(),
                truncated ? 1 : 0);
            return tool_result_t::ok(result);
        }, true});

    register_compat(srv, {
        std::string("debugger_execution_manage"), std::string("debugger"),
        std::string("Manage debugger execution state. Actions: continue, pause, status."),
        {{std::string("action"), std::string("string"), std::string("continue|pause|status"), true},
         {std::string("payload"), std::string("object"), std::string("Action-specific parameters; top-level action-specific fields are also accepted."), false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            auto status_name = [](debugger_engine::dbg_status_t s) -> const char* {
                switch (s) {
                    case debugger_engine::dbg_status_t::idle: return "idle";
                    case debugger_engine::dbg_status_t::running: return "running";
                    case debugger_engine::dbg_status_t::paused: return "paused";
                    case debugger_engine::dbg_status_t::stepping: return "stepping";
                    case debugger_engine::dbg_status_t::terminated: return "terminated";
                    default: return "unknown";
                }
            };
            auto make_status = [&]() -> json {
                json result;
                result["driver_connected"] = device->is_connected();
                result["pid"] = driver_bridge::attached_pid();
                result["active_tid"] = debugger_engine::g_state.active_tid;
                result["status"] = status_name(debugger_engine::g_state.status.load(std::memory_order_acquire));
                uint32_t exit_code = 0;
                result["alive"] = driver_bridge::attached_process_alive(&exit_code);
                result["exit_code"] = exit_code;
                return result;
            };
            diag::log_tagged_fmt("dbg_tools", "debugger_execution_manage: action=%s", action.c_str());
            if (action == "status")
                return tool_result_t::ok(make_status());
            if (auto err = ensure_attached(p)) return *err;

            driver_debugger_quota_guard_t quota_guard;
            if (auto quota_err = acquire_driver_debugger_quota("debugger_execution_manage", driver_bridge::attached_pid(), quota_guard))
                return *quota_err;

            if (action == "continue") {
                const bool ok = debugger_engine::run_target();
                json result = make_status();
                result["operation_ok"] = ok;
                if (!ok)
                    return tool_result_t::error(debugger_engine::last_error().empty() ? std::string("continue failed.") : debugger_engine::last_error());
                return tool_result_t::ok(std::string("Target continued."), result);
            }
            if (action == "pause") {
                const bool ok = debugger_engine::pause_target();
                json result = make_status();
                result["operation_ok"] = ok;
                if (!ok)
                    return tool_result_t::error(debugger_engine::last_error().empty() ? std::string("pause failed.") : debugger_engine::last_error());
                return tool_result_t::ok(std::string("Target paused."), result);
            }
            return compat_unknown_action("debugger_execution_manage", action);
        }, false});

    register_compat(srv, {
        std::string("debugger_set_register"), std::string("debugger"),
        std::string("Set a CPU register for a specific target thread. Accepts 64-bit GPR names, RIP, RSP, RBP, and RFLAGS."),
        {{std::string("tid"), std::string("string"), std::string("Thread ID"), true},
         {std::string("register"), std::string("string"), std::string("Register name such as RAX, RCX, RIP, RSP, or RFLAGS"), true},
         {std::string("hex_value"), std::string("string"), std::string("New register value as hex or decimal"), true},
         {std::string("target_pid"), std::string("number"), std::string("Optional PID override. Switches the active attach context for this call."), false}},
        [](const json& params) -> tool_result_t {
            return handle_debugger_set_register(params, false);
        }, false});



    register_compat(srv, {
        std::string("debugger_start_trace"), std::string("debugger"),
        std::string("Record a bounded synchronous single-step trace for a thread until max_instructions, timeout, cancellation, or a condition expression is reached."),
        {{std::string("tid"), std::string("string"), std::string("Thread ID"), true},
         {std::string("max_instructions"), std::string("number"), std::string("Maximum instructions to single-step, default 256, cap 4096"), false},
         {std::string("condition"), std::string("string"), std::string("Optional expression such as 'rip == 0x140001000' or 'rax == 0'"), false},
         {std::string("timeout_ms"), std::string("number"), std::string("Overall trace timeout, default 30000, cap 120000"), false},
         {std::string("target_pid"), std::string("number"), std::string("Optional PID override. Switches the active attach context for this call."), false}},
        handle_debugger_start_trace, false});

    register_compat(srv, {
        std::string("debugger_get_trace"), std::string("debugger"),
        std::string("Return a recorded debugger_start_trace log with registers, flags, disassembly, and practical memory operand metadata."),
        {{std::string("trace_id"), std::string("string"), std::string("Trace ID returned by debugger_start_trace"), true},
         {std::string("offset"), std::string("number"), std::string("Start entry offset, default 0"), false},
         {std::string("limit"), std::string("number"), std::string("Maximum entries to return, default 200, cap 1000"), false}},
        handle_debugger_get_trace, true});

    srv.register_tool({
        "debugger_get_breakpoints",
        "List every breakpoint tracked by the debugger engine, including disabled and one-shot entries.",
        {},
        true,
        [](const json&) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_get_breakpoints: entry");
            std::lock_guard<std::mutex> lk(debugger_engine::g_state.bp_mutex);
            json arr = json::array();
            for (size_t i = 0; i < debugger_engine::g_state.breakpoints.size(); ++i) {
                const auto& bp = debugger_engine::g_state.breakpoints[i];
                arr.push_back(breakpoint_entry_json(bp, i));
            }
            diag::log_tagged_fmt("dbg_tools", "debugger_get_breakpoints: returning %zu breakpoints", arr.size());
            json result;
            result["target_pid"] = driver_bridge::attached_pid();
            result["active_tid"] = debugger_engine::g_state.active_tid;
            result["count"]       = arr.size();
            result["breakpoints"] = std::move(arr);
            return tool_result_t::ok(
                std::to_string(result["count"].get<std::size_t>()) + std::string(" breakpoint(s)."), result);
        }
    });


    srv.register_tool({
        "debugger_get_callstack",
        "Return the cached call stack of the active debugger thread (each frame: address, return_addr, module, function_name, module_offset).",
        {{"tid", "string", "Optional thread ID. Defaults to the active debugger thread.", false},
         {"max_depth", "number", "Maximum stack frames to unwind (default 64, max 256)", false},
         {"target_pid", "number", "Optional PID override. Switches the active attach context for this call.", false}},
        true,
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_get_callstack: entry");
            if (auto err = ensure_attached(params))
                return *err;

            driver_debugger_quota_guard_t quota_guard;
            if (auto quota_err = acquire_driver_debugger_quota("debugger_get_callstack", driver_bridge::attached_pid(), quota_guard))
                return *quota_err;

            json call_params = params.is_object() ? params : json::object();
            if (!parse_tid(call_params)) {
                std::uint32_t tid = debugger_engine::g_state.active_tid;
                if (tid == 0) {
                    const std::uint32_t pid = driver_bridge::attached_pid();
                    for (const auto& th : driver_bridge::enumerate_threads()) {
                        if (th.owner_pid == pid && th.tid != 0) {
                            tid = th.tid;
                            break;
                        }
                    }
                }
                if (tid == 0) {
                    diag::log_tagged_fmt("dbg_tools", "debugger_get_callstack: no live thread");
                    return tool_result_t::error(std::string("No live target thread available."));
                }
                call_params["tid"] = std::to_string(tid);
            }

            auto result = handle_debugger_get_callstack_impl(call_params);
            diag::log_tagged_fmt("dbg_tools", "debugger_get_callstack: delegated success=%d", result.success ? 1 : 0);
            return result;
        }
    });


    srv.register_tool({
        "debugger_get_handles",
        "Enumerate kernel handles owned by the attached process via the debugger engine's handle table.",
        {},
        true,
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_get_handles: entry");
            if (auto err = ensure_attached(params)) return *err;

            driver_debugger_quota_guard_t quota_guard;
            if (auto quota_err = acquire_driver_debugger_quota("debugger_get_handles", driver_bridge::attached_pid(), quota_guard))
                return *quota_err;

            debugger_engine::enumerate_handles();
            std::lock_guard<std::mutex> lk(debugger_engine::g_state.handle_mutex);
            json arr = json::array();
            for (const auto& h : debugger_engine::g_state.handles) {
                json o;
                o["handle"]     = sa_format_address(h.handle);
                o["type_index"] = h.type_index;
                if (!h.type_name.empty()) o["type"] = h.type_name;
                if (!h.name.empty())      o["name"] = h.name;
                o["access"]     = sa_format_address(static_cast<uint64_t>(h.access));
                arr.push_back(std::move(o));
            }
            diag::log_tagged_fmt("dbg_tools", "debugger_get_handles: returning %zu handles", arr.size());
            json result;
            result["count"]   = arr.size();
            result["handles"] = std::move(arr);
            return tool_result_t::ok(result);
        }
    });


    srv.register_tool({
        "debugger_get_seh_chain",
        "Refresh and return the SEH exception handler chain for the active thread of the attached process.",
        {},
        true,
        [](const json& params) -> tool_result_t {
            const DWORD entry_tid = GetCurrentThreadId();
            const std::uint64_t entry_tick = GetTickCount64();
            diag::log_tagged_fmt("dbg_tools", "debugger_get_seh_chain: entry tid=%lu tick=%llu",
                static_cast<unsigned long>(entry_tid),
                static_cast<unsigned long long>(entry_tick));
            if (auto err = ensure_attached(params)) return *err;

            driver_debugger_quota_guard_t quota_guard;
            if (auto quota_err = acquire_driver_debugger_quota("debugger_get_seh_chain", driver_bridge::attached_pid(), quota_guard))
                return *quota_err;

            auto refresh_and_wait = [&](const char* phase) {
                const std::uint64_t phase_start = GetTickCount64();
                seh_view::refresh();
                for (int i = 0; i < 100; ++i) {
                    if (!seh_view::g_ui.refreshing.load()) break;
                    if (mcp_standalone::current_call_cancelled()) break;
                    Sleep(20);
                }
                diag::log_tagged_fmt("dbg_tools",
                    "seh_refresh_wait phase=%s tid=%lu elapsed_ms=%llu",
                    phase ? phase : "<empty>",
                    static_cast<unsigned long>(GetCurrentThreadId()),
                    static_cast<unsigned long long>(GetTickCount64() - phase_start));
            };
            diag::log_tagged_fmt("dbg_tools", "debugger_get_seh_chain: calling seh_view::refresh");
            refresh_and_wait("primary");
            {
                std::lock_guard<std::mutex> probe_lk(seh_view::g_ui.mutex);
                const auto probe_diag = seh_view::g_ui.diagnostics;
                const bool teb_zero = !probe_diag.teb_query_ok || probe_diag.teb_query_returned == 0;
                if (teb_zero) {
                    const DWORD gle_before_retry = GetLastError();
                    diag::log_tagged_fmt("dbg_tools",
                        "seh_teb_query_retry attempt=1 ok=%d teb=0x%llX gle=%lu reason=%s active_tid=%lu target_pid=%u caller_pid=%lu caller_tid=%lu elapsed_ms=%llu",
                        probe_diag.teb_query_ok ? 1 : 0,
                        static_cast<unsigned long long>(probe_diag.teb_query_returned),
                        static_cast<unsigned long>(gle_before_retry),
                        probe_diag.empty_reason.c_str(),
                        static_cast<unsigned long>(probe_diag.active_tid),
                        static_cast<unsigned>(probe_diag.target_pid),
                        static_cast<unsigned long>(GetCurrentProcessId()),
                        static_cast<unsigned long>(entry_tid),
                        static_cast<unsigned long long>(GetTickCount64() - entry_tick));
                }
            }
            {
                std::lock_guard<std::mutex> probe_lk(seh_view::g_ui.mutex);
                const auto probe_diag = seh_view::g_ui.diagnostics;
                const bool teb_zero = !probe_diag.teb_query_ok || probe_diag.teb_query_returned == 0;
                if (teb_zero) {
                    Sleep(5);
                }
            }
            {
                bool teb_zero_retry = false;
                seh_view::seh_diagnostics_t probe_diag_retry;
                {
                    std::lock_guard<std::mutex> probe_lk(seh_view::g_ui.mutex);
                    probe_diag_retry = seh_view::g_ui.diagnostics;
                    teb_zero_retry = !probe_diag_retry.teb_query_ok || probe_diag_retry.teb_query_returned == 0;
                }
                if (teb_zero_retry) {
                    refresh_and_wait("retry_1");
                    std::lock_guard<std::mutex> after_lk(seh_view::g_ui.mutex);
                    const auto after_diag = seh_view::g_ui.diagnostics;
                    diag::log_tagged_fmt("dbg_tools",
                        "seh_teb_query_retry attempt=2 ok=%d teb=0x%llX gle=%lu reason=%s active_tid=%lu target_pid=%u caller_pid=%lu caller_tid=%lu elapsed_ms=%llu",
                        after_diag.teb_query_ok ? 1 : 0,
                        static_cast<unsigned long long>(after_diag.teb_query_returned),
                        static_cast<unsigned long>(GetLastError()),
                        after_diag.empty_reason.c_str(),
                        static_cast<unsigned long>(after_diag.active_tid),
                        static_cast<unsigned>(after_diag.target_pid),
                        static_cast<unsigned long>(GetCurrentProcessId()),
                        static_cast<unsigned long>(entry_tid),
                        static_cast<unsigned long long>(GetTickCount64() - entry_tick));
                }
            }
            std::lock_guard<std::mutex> lk(seh_view::g_ui.mutex);
            json arr = json::array();
            for (const auto& e : seh_view::g_ui.entries) {
                json o;
                o["index"]         = e.index;
                o["frame_addr"]    = sa_format_address(e.frame_addr);
                o["handler_addr"]  = sa_format_address(e.handler_addr);
                o["filter_addr"]   = sa_format_address(e.filter_addr);
                if (!e.module_name.empty())  o["module"]       = e.module_name;
                if (!e.handler_name.empty()) o["handler_name"] = e.handler_name;
                arr.push_back(std::move(o));
            }
            const auto seh_diag = seh_view::g_ui.diagnostics;
            diag::log_tagged_fmt("dbg_tools",
                "debugger_get_seh_chain: returning %zu SEH entries teb_ok=%d exception_list_ok=%d sentinel=%d empty_proven=%d reason=%s stack_attempted=%d stack_read_ok=%d stack_candidates=%u",
                arr.size(),
                seh_diag.teb_read_succeeded ? 1 : 0,
                seh_diag.exception_list_read_ok ? 1 : 0,
                seh_diag.sentinel_reached ? 1 : 0,
                seh_diag.x64_empty_chain_proven ? 1 : 0,
                seh_diag.empty_reason.c_str(),
                seh_diag.stack_scan_attempted ? 1 : 0,
                seh_diag.stack_scan_read_ok ? 1 : 0,
                seh_diag.stack_scan_candidates);
            json result;
            result["count"]   = arr.size();
            result["entries"] = std::move(arr);
            result["target_pid"] = seh_diag.target_pid;
            result["active_tid"] = seh_diag.active_tid;
            result["teb_va"] = sa_format_address(seh_diag.teb_va);
            result["raw_exception_list"] = sa_format_address(seh_diag.raw_exception_list);
            result["teb_query_attempted"] = seh_diag.teb_query_attempted;
            result["teb_query_ok"] = seh_diag.teb_query_ok;
            result["teb_query_returned"] = seh_diag.teb_query_returned;
            result["teb_read_ok"] = seh_diag.teb_read_ok;
            result["teb_read_succeeded"] = seh_diag.teb_read_succeeded;
            result["exception_list_read_ok"] = seh_diag.exception_list_read_ok;
            result["sentinel_reached"] = seh_diag.sentinel_reached;
            result["x64_empty_chain_proven"] = seh_diag.x64_empty_chain_proven;
            result["empty_reason"] = seh_diag.empty_reason;
            result["chain_stop_reason"] = seh_diag.chain_stop_reason;
            result["stack_scan"] = json{
                {"attempted", seh_diag.stack_scan_attempted},
                {"read_ok", seh_diag.stack_scan_read_ok},
                {"start", sa_format_address(seh_diag.stack_scan_start)},
                {"rsp", sa_format_address(seh_diag.rsp)},
                {"size", seh_diag.stack_scan_size},
                {"bytes", seh_diag.stack_scan_bytes},
                {"candidate_count", seh_diag.stack_scan_candidates},
                {"candidate_found", seh_diag.stack_scan_candidate_found},
                {"candidate_frame", sa_format_address(seh_diag.stack_scan_candidate_frame)},
                {"candidate_handler", sa_format_address(seh_diag.stack_scan_candidate_handler)},
                {"reason", seh_diag.stack_scan_reason}
            };
            return tool_result_t::ok(result);
        }
    });

    srv.register_tool({
        "debugger_get_patches",
        "List active byte-patches tracked by the code patcher (address, description, original/patched bytes, active flag, timestamp).",
        {},
        true,
        [](const json&) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_get_patches: entry");
            std::lock_guard<std::mutex> lk(code_patcher::g_state.mtx);
            json arr = json::array();
            std::size_t active_count = 0;
            for (size_t i = 0; i < code_patcher::g_state.patches.size(); ++i) {
                const auto& p = code_patcher::g_state.patches[i];
                if (p.active)
                    ++active_count;
                json o;
                o["index"]          = static_cast<int>(i);
                o["address"]        = sa_format_address(p.address);
                o["description"]    = p.description;
                o["active"]         = p.active;
                o["timestamp"]      = p.timestamp;
                o["original_bytes"] = code_patcher::format_bytes(p.original_bytes);
                o["patched_bytes"]  = code_patcher::format_bytes(p.patched_bytes);
                o["size"]           = p.patched_bytes.size();
                arr.push_back(std::move(o));
            }
            json result;
            result["target_pid"] = driver_bridge::attached_pid();
            result["active_tid"] = debugger_engine::g_state.active_tid;
            result["count"]   = arr.size();
            result["active_count"] = active_count;
            result["patches"] = std::move(arr);
            return tool_result_t::ok(
                std::to_string(result["count"].get<std::size_t>()) + std::string(" patch(es)."), result);
        }
    });

    srv.register_tool({
        "debugger_set_breakpoint",
        "Install a breakpoint via the debugger engine. type=exec (software int3), read/write (hardware DR breakpoint), size=1/2/4/8.",
        {{"address", "string", "Breakpoint address (hex)", true},
         {"type",    "string", "exec (software), read, write, access (default exec)", false},
         {"size",    "number", "Breakpoint size 1/2/4/8 (default 1)", false},
         {"name",    "string", "Optional label", false},
         {"condition", "string", "Optional condition expression", false},
         {"target_pid", "number", "Optional PID override. Switches the active attach context for this call.", false}},
        false,
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_set_breakpoint: entry");
            if (auto err = ensure_attached(params)) return *err;

            driver_debugger_quota_guard_t quota_guard;
            if (auto quota_err = acquire_driver_debugger_quota("debugger_set_breakpoint", driver_bridge::attached_pid(), quota_guard))
                return *quota_err;

            uint64_t addr = 0;
            if (params.contains("address") && params["address"].is_string()) {
                auto p = sa_parse_address(params["address"].get<std::string>());
                if (!p) return tool_result_t::error("Invalid address.");
                addr = *p;
            } else {
                return tool_result_t::error("'address' is required.");
            }

            std::string type_str = "exec";
            if (params.contains("type") && params["type"].is_string())
                type_str = params["type"].get<std::string>();
            debugger_engine::bp_type_t bp_type = debugger_engine::bp_type_t::software;
            if (type_str == "exec" || type_str == "software")          bp_type = debugger_engine::bp_type_t::software;
            else if (type_str == "hw_exec" || type_str == "hardware") bp_type = debugger_engine::bp_type_t::hardware_execute;
            else if (type_str == "read")   bp_type = debugger_engine::bp_type_t::hardware_read;
            else if (type_str == "write")  bp_type = debugger_engine::bp_type_t::hardware_write;
            else if (type_str == "access") bp_type = debugger_engine::bp_type_t::memory_access;
            else return tool_result_t::error("Unknown 'type': use exec, read, write, access, or hw_exec.");
            int size = 1;
            if (params.contains("size") && params["size"].is_number_integer())
                size = params["size"].get<int>();
            std::string name;
            if (params.contains("name") && params["name"].is_string())
                name = params["name"].get<std::string>();
            std::string cond;
            if (params.contains("condition") && params["condition"].is_string())
                cond = params["condition"].get<std::string>();
            const std::size_t before_count = breakpoint_count();
            diag::log_tagged_fmt("dbg_tools", "debugger_set_breakpoint: addr=0x%llX type=%s size=%d", (unsigned long long)addr, type_str.c_str(), size);
            int idx = debugger_engine::add_breakpoint(addr, bp_type, name, cond, size);
            if (idx < 0) {
                diag::log_tagged_fmt("dbg_tools", "debugger_set_breakpoint: add_breakpoint failed: %s", debugger_engine::last_error().c_str());
                return tool_result_t::error("debugger_engine::add_breakpoint failed: " +
                                            debugger_engine::last_error());
            }
            diag::log_tagged_fmt("dbg_tools", "debugger_set_breakpoint: BP set at 0x%llX idx=%d", (unsigned long long)addr, idx);
            json result;
            add_debugger_action_context(result, "debugger_set_breakpoint");
            result["success"] = true;
            result["index"]   = idx;
            result["address"] = sa_format_address(addr);
            result["type"]    = type_str;
            result["type_name"] = breakpoint_type_name(bp_type);
            result["size"]    = size;
            result["breakpoint_count_before"] = before_count;
            result["breakpoint_count_after"] = breakpoint_count();
            json entry;
            if (breakpoint_entry_by_index(idx, entry)) {
                result["enabled"] = entry.value("enabled", true);
                result["hardware"] = entry.value("hardware", false);
                result["hw_slot"] = entry.value("hw_slot", -1);
                result["hw_slot_active"] = entry.value("hw_slot_active", false);
                result["breakpoint"] = std::move(entry);
            }
            return tool_result_t::ok(
                std::string("Breakpoint set at ") + sa_format_address(addr), result);
        }
    });

    srv.register_tool({
        "debugger_remove_breakpoint",
        "Remove a breakpoint tracked by the debugger engine by index OR by address.",
        {{"index",   "number", "Breakpoint index from debugger_get_breakpoints", false},
         {"address", "string", "Breakpoint address (hex). Used when index is absent.", false},
         {"target_pid", "number", "Optional PID override. Switches the active attach context for this call.", false}},
        false,
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_remove_breakpoint: entry");
            if (auto err = ensure_attached(params)) return *err;

            driver_debugger_quota_guard_t quota_guard;
            if (auto quota_err = acquire_driver_debugger_quota("debugger_remove_breakpoint", driver_bridge::attached_pid(), quota_guard))
                return *quota_err;

            int idx = -1;
            if (params.contains("index") && params["index"].is_number_integer()) {
                idx = params["index"].get<int>();
            } else if (params.contains("address") && params["address"].is_string()) {
                auto p = sa_parse_address(params["address"].get<std::string>());
                if (!p) return tool_result_t::error("Invalid address.");
                std::lock_guard<std::mutex> lk(debugger_engine::g_state.bp_mutex);
                for (size_t i = 0; i < debugger_engine::g_state.breakpoints.size(); ++i) {
                    if (debugger_engine::g_state.breakpoints[i].address == *p) {
                        idx = static_cast<int>(i);
                        break;
                    }
                }
                if (idx < 0) return tool_result_t::error("No breakpoint exists at that address.");
            } else {
                return tool_result_t::error("Provide 'index' or 'address'.");
            }
            const std::size_t before_count = breakpoint_count();
            json removed_entry;
            if (!breakpoint_entry_by_index(idx, removed_entry))
                return tool_result_t::error("Breakpoint index is out of range.");
            diag::log_tagged_fmt("dbg_tools", "debugger_remove_breakpoint: removing idx=%d", idx);
            if (!debugger_engine::remove_breakpoint(idx)) {
                diag::log_tagged_fmt("dbg_tools", "debugger_remove_breakpoint: remove failed: %s", debugger_engine::last_error().c_str());
                return tool_result_t::error("debugger_engine::remove_breakpoint failed: " +
                                            debugger_engine::last_error());
            }
            diag::log_tagged_fmt("dbg_tools", "debugger_remove_breakpoint: removed idx=%d", idx);
            json result;
            add_debugger_action_context(result, "debugger_remove_breakpoint");
            result["success"] = true;
            result["index"] = idx;
            result["address"] = removed_entry.value("address", std::string{});
            result["enabled"] = removed_entry.value("enabled", false);
            result["hardware"] = removed_entry.value("hardware", false);
            result["hw_slot"] = removed_entry.value("hw_slot", -1);
            result["hw_slot_active"] = false;
            result["breakpoint_count_before"] = before_count;
            result["breakpoint_count_after"] = breakpoint_count();
            result["removed"] = std::move(removed_entry);
            result["status"] = "removed";
            return tool_result_t::ok(std::string("Breakpoint removed."), result);
        }
    });

    srv.register_tool({
        "debugger_step_over",
        "Step over the next instruction for an explicit thread.",
        {{"tid", "string", "Thread ID", true}},
        false,
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_step_over: entry");
            if (auto err = ensure_attached(params)) return *err;

            driver_debugger_quota_guard_t quota_guard;
            if (auto quota_err = acquire_driver_debugger_quota("debugger_step_over", driver_bridge::attached_pid(), quota_guard))
                return *quota_err;

            auto tid = parse_tid(params);
            if (!tid) return tool_result_t::error(std::string("'tid' is required."));
            debugger_engine::g_state.active_tid = *tid;
            bool ok = debugger_engine::step_over();
            diag::log_tagged_fmt("dbg_tools", "debugger_step_over: step_over returned ok=%d", (int)ok);
            if (!ok)
                return tool_result_t::error(debugger_engine::last_error().empty() ? std::string("step_over failed.") : debugger_engine::last_error());
            json result;
            result["status"] = "stepped";
            return tool_result_t::ok(result);
        }
    });

    srv.register_tool({
        "debugger_step_into",
        "Single-step into the next instruction for an explicit thread.",
        {{"tid", "string", "Thread ID", true}},
        false,
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_step_into: entry");
            if (auto err = ensure_attached(params)) return *err;

            driver_debugger_quota_guard_t quota_guard;
            if (auto quota_err = acquire_driver_debugger_quota("debugger_step_into", driver_bridge::attached_pid(), quota_guard))
                return *quota_err;

            auto tid = parse_tid(params);
            if (!tid) return tool_result_t::error(std::string("'tid' is required."));
            debugger_engine::g_state.active_tid = *tid;
            bool ok = debugger_engine::step_into();
            diag::log_tagged_fmt("dbg_tools", "debugger_step_into: step_into returned ok=%d", (int)ok);
            if (!ok)
                return tool_result_t::error(debugger_engine::last_error().empty() ? std::string("step_into failed.") : debugger_engine::last_error());
            json result;
            result["status"] = "stepped";
            return tool_result_t::ok(result);
        }
    });

    srv.register_tool({
        "debugger_step_out",
        "Run until the current function returns for an explicit thread.",
        {{"tid", "string", "Thread ID", true}},
        false,
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "debugger_step_out: entry");
            if (auto err = ensure_attached(params)) return *err;

            driver_debugger_quota_guard_t quota_guard;
            if (auto quota_err = acquire_driver_debugger_quota("debugger_step_out", driver_bridge::attached_pid(), quota_guard))
                return *quota_err;

            auto tid = parse_tid(params);
            if (!tid) return tool_result_t::error(std::string("'tid' is required."));
            debugger_engine::g_state.active_tid = *tid;
            bool ok = debugger_engine::step_out();
            diag::log_tagged_fmt("dbg_tools", "debugger_step_out: step_out returned ok=%d", (int)ok);
            if (!ok)
                return tool_result_t::error(debugger_engine::last_error().empty() ? std::string("step_out failed.") : debugger_engine::last_error());
            json result;
            result["status"] = "stepped";
            return tool_result_t::ok(result);
        }
    });











    register_compat(srv, {
        std::string("dbg_add_watch"), std::string("debugger"),
        std::string("Add a watch expression. Supports register names (rax, rsp, etc.) and hex addresses."),
        {{std::string("expression"), std::string("string"), std::string("Watch expression"), true}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_add_watch: entry");
            if (!params.contains("expression") || !params["expression"].is_string())
                return tool_result_t::error(std::string("'expression' is required."));
            const std::string expr = params["expression"].get<std::string>();
            diag::log_tagged_fmt("dbg_tools", "dbg_add_watch: expr=%s", expr.c_str());
            const std::size_t before_count = watch_count();
            const int idx = debugger_engine::add_watch(expr);
            debugger_engine::refresh_watches();
            diag::log_tagged_fmt("dbg_tools", "dbg_add_watch: watch added and refreshed");
            json result;
            add_debugger_action_context(result, "dbg_add_watch");
            result["success"] = idx >= 0;
            result["index"] = idx;
            result["expression"] = expr;
            result["watch_count_before"] = before_count;
            result["watch_count_after"] = watch_count();
            json entry;
            if (idx >= 0 && watch_entry_by_index(idx, entry))
                result["watch"] = std::move(entry);
            return tool_result_t::ok(std::string("Watch added."), result);
        }, false});

    register_compat(srv, {
        std::string("dbg_remove_watch"), std::string("debugger"),
        std::string("Remove a watch by index."),
        {{std::string("index"), std::string("number"), std::string("Watch index"), true}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_remove_watch: entry");
            if (!params.contains("index") || !params["index"].is_number())
                return tool_result_t::error(std::string("'index' required."));
            int idx = params["index"].get<int>();
            diag::log_tagged_fmt("dbg_tools", "dbg_remove_watch: removing watch idx=%d", idx);
            const std::size_t before_count = watch_count();
            json removed_entry;
            const bool had_entry = watch_entry_by_index(idx, removed_entry);
            if (!debugger_engine::remove_watch(idx))
                return tool_result_t::error(std::string("Watch index is out of range."));
            diag::log_tagged_fmt("dbg_tools", "dbg_remove_watch: removed");
            json result;
            add_debugger_action_context(result, "dbg_remove_watch");
            result["success"] = true;
            result["index"] = idx;
            result["watch_count_before"] = before_count;
            result["watch_count_after"] = watch_count();
            if (had_entry)
                result["removed"] = std::move(removed_entry);
            return tool_result_t::ok(std::string("Watch removed."), result);
        }, false});

    register_compat(srv, {
        std::string("dbg_get_watches"), std::string("debugger"),
        std::string("Get all watch expressions and their current values."),
        {},
        [](const json& ) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_get_watches: entry");
            debugger_engine::refresh_watches();
            auto& st = debugger_engine::g_state;
            std::lock_guard<std::mutex> lk(st.watch_mutex);
            json arr = json::array();
            for (size_t i = 0; i < st.watches.size(); ++i) {
                json wj;
                wj["index"] = i;
                wj["expression"] = st.watches[i].expression;
                wj["value"] = st.watches[i].value;
                wj["valid"] = st.watches[i].valid;
                wj["error"] = st.watches[i].error;
                arr.push_back(wj);
            }
            diag::log_tagged_fmt("dbg_tools", "dbg_get_watches: returning %zu watches", arr.size());
            return tool_result_t::ok(
                std::to_string(arr.size()) + std::string(" watches."), arr);
        }, true});






    register_compat(srv, {
        std::string("dbg_toggle_bookmark"), std::string("debugger"),
        std::string("Toggle a bookmark at an address."),
        {{std::string("address"), std::string("string"), std::string("Address (hex)"), true}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_toggle_bookmark: entry");
            if (!params.contains("address"))
                return tool_result_t::error(std::string("'address' is required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(std::string("Invalid address."));
            diag::log_tagged_fmt("dbg_tools", "dbg_toggle_bookmark: addr=0x%llX", (unsigned long long)*addr);
            const std::size_t before_count = bookmark_count();
            const bool enabled_before = bookmark_present(*addr);
            debugger_engine::toggle_bookmark(*addr);
            const bool enabled_after = bookmark_present(*addr);
            diag::log_tagged_fmt("dbg_tools", "dbg_toggle_bookmark: toggled");
            json result;
            add_debugger_action_context(result, "dbg_toggle_bookmark");
            result["success"] = true;
            result["address"] = sa_format_address(*addr);
            result["enabled_before"] = enabled_before;
            result["enabled"] = enabled_after;
            result["bookmark_count_before"] = before_count;
            result["bookmark_count_after"] = bookmark_count();
            return tool_result_t::ok(std::string("Bookmark toggled at ") + sa_format_address(*addr), result);
        }, false});

    register_compat(srv, {
        std::string("dbg_find_strings"), std::string("debugger"),
        std::string("Find ASCII strings in the memory of the attached process. Results include address, "
               "string value, and containing module."),
        {{std::string("min_length"), std::string("number"), std::string("Minimum string length (default 4)"), false},
         {std::string("process_id"), std::string("number"), std::string("Optional PID override (alias: target_pid). Switches the active attach context for the duration of this call."), false}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_find_strings: entry");
            if (mcp_standalone::current_call_cancelled())
                return tool_result_t::error("Tool cancelled before operation.");
            if (auto err = ensure_attached(params)) return *err;

            driver_debugger_quota_guard_t quota_guard;
            if (auto quota_err = acquire_driver_debugger_quota("dbg_find_strings", driver_bridge::attached_pid(), quota_guard))
                return *quota_err;

            int min_len = params.value("min_length", 4);
            diag::log_tagged_fmt("dbg_tools", "dbg_find_strings: min_length=%d", min_len);
            debugger_engine::find_strings(min_len);
            auto& st = debugger_engine::g_state;
            std::lock_guard<std::mutex> lk(st.strings_mutex);
            json arr = json::array();
            int count = 0;
            for (const auto& s : st.strings) {
                if (count++ >= 500) break;
                json sj;
                sj["address"] = sa_format_address(s.address);
                sj["value"] = s.value;
                if (!s.module_name.empty()) sj["module"] = s.module_name;
                arr.push_back(sj);
            }
            json result;
            result["total"] = st.strings.size();
            result["returned"] = arr.size();
            result["strings"] = arr;
            diag::log_tagged_fmt("dbg_tools", "dbg_find_strings: total=%zu returned=%d", st.strings.size(), count < 500 ? count : 500);
            return tool_result_t::ok(
                std::to_string(st.strings.size()) + std::string(" strings found."), result);
        }, true});


    register_compat(srv, {
        std::string("dbg_add_hw_breakpoint"), std::string("debugger"),
        std::string("Set a hardware breakpoint using debug registers (DR0-DR3). "
               "Does not modify code bytes, so it is transparent to anti-tamper. "
               "Limited to 4 active hardware breakpoints."),
        {{std::string("address"), std::string("string"), std::string("Address (hex)"), true},
         {std::string("type"), std::string("string"), std::string("Type: 'execute', 'write', 'read' (default 'execute')"), false},
         {std::string("size"), std::string("number"), std::string("Watch granularity in bytes: 1, 2, 4, or 8 (default 1; ignored for 'execute')"), false},
         {std::string("process_id"), std::string("number"), std::string("Optional PID override (alias: target_pid). Switches the active attach context for the duration of this call."), false}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_add_hw_breakpoint: entry");
            if (auto err = ensure_attached(params)) return *err;

            driver_debugger_quota_guard_t quota_guard;
            if (auto quota_err = acquire_driver_debugger_quota("dbg_add_hw_breakpoint", driver_bridge::attached_pid(), quota_guard))
                return *quota_err;

            if (!params.contains("address") || !params["address"].is_string())
                return tool_result_t::error(std::string("'address' required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(std::string("Invalid address."));

            std::string type_str = params.value("type", "execute");
            debugger_engine::bp_type_t bpt = debugger_engine::bp_type_t::hardware_execute;
            if (type_str == "write") bpt = debugger_engine::bp_type_t::hardware_write;
            else if (type_str == "read") bpt = debugger_engine::bp_type_t::hardware_read;
            int size = 1;
            if (params.contains("size") && params["size"].is_number())
                size = params["size"].get<int>();
            if (size != 1 && size != 2 && size != 4 && size != 8)
                return tool_result_t::error(std::string("'size' must be 1, 2, 4, or 8."));
            diag::log_tagged_fmt("dbg_tools", "dbg_add_hw_breakpoint: addr=0x%llX type=%s size=%d", (unsigned long long)*addr, type_str.c_str(), size);
            const std::size_t before_count = breakpoint_count();
            int idx = debugger_engine::add_breakpoint(*addr, bpt, "", "", size);
            if (idx < 0) {
                diag::log_tagged_fmt("dbg_tools", "dbg_add_hw_breakpoint: add_breakpoint failed: %s", debugger_engine::last_error().c_str());
                return tool_result_t::error(debugger_engine::last_error());
            }
            diag::log_tagged_fmt("dbg_tools", "dbg_add_hw_breakpoint: HW BP set at 0x%llX idx=%d", (unsigned long long)*addr, idx);
            json result;
            add_debugger_action_context(result, "dbg_add_hw_breakpoint");
            result["success"] = true;
            result["index"] = idx;
            result["address"] = sa_format_address(*addr);
            result["type"] = type_str;
            result["type_name"] = breakpoint_type_name(bpt);
            result["size"] = size;
            result["breakpoint_count_before"] = before_count;
            result["breakpoint_count_after"] = breakpoint_count();
            json entry;
            if (breakpoint_entry_by_index(idx, entry)) {
                result["enabled"] = entry.value("enabled", true);
                result["hardware"] = entry.value("hardware", true);
                result["hw_slot"] = entry.value("hw_slot", -1);
                result["hw_slot_active"] = entry.value("hw_slot_active", false);
                result["breakpoint"] = std::move(entry);
            }
            return tool_result_t::ok(std::string("Hardware breakpoint set at ") + sa_format_address(*addr), result);
        }, false});


    register_compat(srv, {
        std::string("dbg_clear_all_breakpoints"), std::string("debugger"),
        std::string("Remove all breakpoints (software and hardware)."),
        {},
        [](const json&) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_clear_all_breakpoints: entry");
            const std::size_t before_count = breakpoint_count();
            const bool cleared = debugger_engine::clear_all_breakpoints();
            const std::size_t after_count = breakpoint_count();
            json result;
            add_debugger_action_context(result, "dbg_clear_all_breakpoints");
            result["success"] = cleared && after_count == 0;
            result["breakpoint_count_before"] = before_count;
            result["breakpoint_count_after"] = after_count;
            result["engine_verified"] = cleared;
            if (!cleared || after_count != 0) {
                const std::string detail = debugger_engine::last_error().empty()
                    ? std::string("Breakpoint restoration or removal did not verify completely.")
                    : debugger_engine::last_error();
                result["diagnostic"] = detail;
                diag::log_tagged_fmt("dbg_tools",
                    "dbg_clear_all_breakpoints: failed before=%zu after=%zu engine_verified=%d detail='%s'",
                    before_count, after_count, static_cast<int>(cleared), detail.c_str());
                return tool_result_t::error(
                    std::string("Failed to clear every breakpoint without leaving target state uncertain."),
                    "debugger_breakpoint_clear_failed", result);
            }
            diag::log_tagged_fmt("dbg_tools", "dbg_clear_all_breakpoints: all breakpoints cleared");
            return tool_result_t::ok(std::string("All breakpoints cleared."), result);
        }, false});



    register_compat(srv, {
        std::string("dbg_get_bookmarks"), std::string("debugger"),
        std::string("Get all bookmarked addresses."),
        {},
        [](const json&) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_get_bookmarks: entry");
            auto& st = debugger_engine::g_state;
            std::lock_guard<std::mutex> lk(st.anno_mutex);
            json arr = json::array();
            for (auto addr : st.bookmarks)
                arr.push_back(sa_format_address(addr));
            json result;
            result["count"] = arr.size();
            result["bookmarks"] = arr;
            diag::log_tagged_fmt("dbg_tools", "dbg_get_bookmarks: returning %zu bookmarks", arr.size());
            return tool_result_t::ok(
                std::to_string(arr.size()) + std::string(" bookmark(s)."), result);
        }, true});




    register_compat(srv, {
        std::string("dbg_build_cfg"), std::string("debugger"),
        std::string("Build a control flow graph starting from an address. Disassembles and splits into basic blocks with edges."),
        {{std::string("address"), std::string("string"), std::string("Entry address to build CFG from (hex)"), true}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_build_cfg: entry");
            if (auto err = ensure_attached(params)) return *err;

            driver_debugger_quota_guard_t quota_guard;
            if (auto quota_err = acquire_driver_debugger_quota("dbg_build_cfg", driver_bridge::attached_pid(), quota_guard))
                return *quota_err;

            if (!params.contains("address") || !params["address"].is_string())
                return tool_result_t::error(std::string("'address' is required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(std::string("Invalid address."));
            std::lock_guard<std::mutex> request_lock(g_cfg_request_mutex);
            if (mcp_standalone::current_call_cancelled())
                return tool_result_t::error("Tool cancelled before CFG build.");
            const std::uint64_t call_deadline = mcp_standalone::current_call_deadline_ms();
            if (call_deadline != 0 && GetTickCount64() >= call_deadline)
                return tool_result_t::error("Tool deadline expired before CFG build.");
            if (auto wait_error = cfg_wait_error(
                wait_for_cfg_publication_idle(3000), "dbg_build_cfg.preflight"))
                return *wait_error;
            driver_bridge::identity::live_target_identity_t target_identity;
            if (auto identity_error = capture_cfg_target_identity(target_identity))
                return *identity_error;
            const auto previous_model = cfg_view::capture_model();
            const std::uint64_t previous_generation = previous_model
                ? previous_model->generation : 0;
            invalidate_cfg_binding();
            diag::log_tagged_fmt("dbg_tools", "dbg_build_cfg: building CFG from 0x%llX pid=%u previous_generation=%llu",
                (unsigned long long)*addr, target_identity.process.pid,
                static_cast<unsigned long long>(previous_generation));
            cfg_view::build_cfg(disasm_view::workspace_context_t{}, *addr);
            if (auto wait_error = cfg_wait_error(
                wait_for_cfg_publication_idle(3000), "dbg_build_cfg.publication"))
                return *wait_error;
            const auto model = cfg_view::capture_model();
            if (!model || model->blocks.empty() || model->generation <= previous_generation ||
                model->entry_addr != *addr)
            {
                diag::log_tagged_fmt("dbg_tools",
                    "dbg_build_cfg: publication rejected requested_entry=0x%llX model=%d blocks=%zu generation=%llu previous_generation=%llu model_entry=0x%llX",
                    static_cast<unsigned long long>(*addr), model ? 1 : 0,
                    model ? model->blocks.size() : 0,
                    static_cast<unsigned long long>(model ? model->generation : 0),
                    static_cast<unsigned long long>(previous_generation),
                    static_cast<unsigned long long>(model ? model->entry_addr : 0));
                return tool_result_t::error(
                    "CFG build failed to publish a complete graph for the requested entry.");
            }
            if (auto identity_error = validate_cfg_target_identity(
                target_identity, "dbg_build_cfg.publication"))
                return *identity_error;
            {
                std::lock_guard<std::mutex> binding_lock(g_cfg_binding_mutex);
                g_cfg_binding.target = target_identity;
                g_cfg_binding.model_generation = model->generation;
                g_cfg_binding.entry_addr = model->entry_addr;
                g_cfg_binding.valid = true;
            }
            json result;
            result["entry"] = sa_format_address(*addr);
            result["blocks"] = model->blocks.size();
            result["built"] = true;
            diag::log_tagged_fmt("dbg_tools", "dbg_build_cfg: CFG built for 0x%llX with %zu blocks generation=%llu pid=%u",
                (unsigned long long)*addr, model->blocks.size(),
                static_cast<unsigned long long>(model->generation),
                target_identity.process.pid);
            return tool_result_t::ok(
                std::string("CFG built: ") + std::to_string(model->blocks.size()) + std::string(" blocks."), result);
        }, true});

    register_compat(srv, {
        std::string("dbg_get_cfg"), std::string("debugger"),
        std::string("Get the current control flow graph state, including all basic blocks, instructions, and edges."),
        {},
        [](const json&) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_get_cfg: entry");
            const json empty_params = json::object();
            if (auto err = ensure_attached(empty_params)) return *err;
            if (mcp_standalone::current_call_cancelled())
                return tool_result_t::error("Tool cancelled before CFG read.");
            const std::uint64_t call_deadline = mcp_standalone::current_call_deadline_ms();
            if (call_deadline != 0 && GetTickCount64() >= call_deadline)
                return tool_result_t::error("Tool deadline expired before CFG read.");
            if (cfg_view::building())
                return tool_result_t::error("CFG publication is being rebuilt. Retry after the build completes.");
            cfg_publication_binding_t binding;
            {
                std::lock_guard<std::mutex> binding_lock(g_cfg_binding_mutex);
                binding = g_cfg_binding;
            }
            const auto model = cfg_view::capture_model();
            if (!binding.valid || !model || model->blocks.empty() ||
                model->generation != binding.model_generation ||
                model->entry_addr != binding.entry_addr ||
                binding.target.process.pid != driver_bridge::attached_pid())
            {
                diag::log_tagged_fmt("dbg_tools",
                    "dbg_get_cfg: no current target-bound CFG binding_valid=%d model=%d blocks=%zu model_generation=%llu binding_generation=%llu model_entry=0x%llX binding_entry=0x%llX binding_pid=%u attached_pid=%u",
                    binding.valid ? 1 : 0, model ? 1 : 0,
                    model ? model->blocks.size() : 0,
                    static_cast<unsigned long long>(model ? model->generation : 0),
                    static_cast<unsigned long long>(binding.model_generation),
                    static_cast<unsigned long long>(model ? model->entry_addr : 0),
                    static_cast<unsigned long long>(binding.entry_addr),
                    binding.target.process.pid, driver_bridge::attached_pid());
                return tool_result_t::error(std::string("No CFG built. Call dbg_build_cfg first."));
            }
            if (auto identity_error = validate_cfg_target_identity(
                binding.target, "dbg_get_cfg.preflight"))
                return *identity_error;
            json blocks_arr = json::array();
            for (size_t bi = 0; bi < model->blocks.size(); ++bi) {
                if (mcp_standalone::current_call_cancelled())
                    return tool_result_t::error("Tool cancelled during CFG read.");
                if (call_deadline != 0 && GetTickCount64() >= call_deadline)
                    return tool_result_t::error("Tool deadline expired during CFG read.");
                const auto& blk = model->blocks[bi];
                json bj;
                bj["index"] = bi;
                bj["start"] = sa_format_address(blk.start_addr);
                bj["end"] = sa_format_address(blk.end_addr);
                bj["is_entry"] = blk.is_entry;
                json insns = json::array();
                for (const auto& ins : blk.instructions) {
                    json ij;
                    ij["addr"] = sa_format_address(ins.addr);
                    ij["text"] = ins.text;
                    insns.push_back(std::move(ij));
                }
                bj["instructions"] = std::move(insns);
                bj["successors"] = blk.successors;
                blocks_arr.push_back(std::move(bj));
            }
            if (cfg_view::building())
                return tool_result_t::error("CFG publication changed during the read.");
            const auto current_model = cfg_view::capture_model();
            if (!current_model || current_model->generation != model->generation)
                return tool_result_t::error("CFG publication changed during the read.");
            if (auto identity_error = validate_cfg_target_identity(
                binding.target, "dbg_get_cfg.completion"))
                return *identity_error;
            json result;
            result["entry"] = sa_format_address(model->entry_addr);
            result["block_count"] = model->blocks.size();
            result["blocks"] = std::move(blocks_arr);
            diag::log_tagged_fmt("dbg_tools", "dbg_get_cfg: returning %zu blocks entry=0x%llX generation=%llu pid=%u",
                model->blocks.size(), (unsigned long long)model->entry_addr,
                static_cast<unsigned long long>(model->generation),
                binding.target.process.pid);
            return tool_result_t::ok(
                std::string("CFG: ") + std::to_string(model->blocks.size()) + std::string(" blocks."), result);
        }, true});


    register_compat(srv, {
        std::string("dbg_get_modules_detail"), std::string("debugger"),
        std::string("Get detailed module information with PE analysis including exports and imports."),
        {{std::string("module_name"), std::string("string"), std::string("Optional module name filter"), false},
         {std::string("module_filter"), std::string("string"), std::string("Alias for module_name"), false},
         {std::string("filter"), std::string("string"), std::string("Alias for module_name"), false},
         {std::string("max_modules"), std::string("number"), std::string("Maximum modules to inspect deeply"), false},
         {std::string("include_pe"), std::string("boolean"), std::string("Parse PE headers/sections for broad requests; focused module requests include PE details by default"), false},
         {std::string("max_exports"), std::string("number"), std::string("Maximum exports per module"), false},
         {std::string("max_imports"), std::string("number"), std::string("Maximum imports per module"), false},
         {std::string("timeout_ms"), std::string("number"), std::string("Maximum elapsed time before returning partial results"), false},
         {std::string("allow_partial"), std::string("boolean"), std::string("Return partial results without marking the payload as timed out"), false}},
        [](const json& params) -> tool_result_t {
            const auto handler_start = std::chrono::steady_clock::now();
            auto elapsed_ms = [&]() -> long long {
                return std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - handler_start).count();
            };
            auto deadline_remaining_ms = [](const std::chrono::steady_clock::time_point& point) -> long long {
                const auto now = std::chrono::steady_clock::now();
                if (now >= point)
                    return 0;
                return std::chrono::duration_cast<std::chrono::milliseconds>(point - now).count();
            };
            diag::log_tagged_fmt("dbg_tools", "dbg_get_modules_detail: entry");
            if (auto err = ensure_attached(params)) return *err;

            driver_debugger_quota_guard_t quota_guard;
            if (auto quota_err = acquire_driver_debugger_quota("dbg_get_modules_detail", driver_bridge::attached_pid(), quota_guard))
                return *quota_err;

            std::string filter;
            if (params.contains("module_name") && params["module_name"].is_string())
                filter = params["module_name"].get<std::string>();
            else if (params.contains("module_filter") && params["module_filter"].is_string())
                filter = params["module_filter"].get<std::string>();
            else if (params.contains("filter") && params["filter"].is_string())
                filter = params["filter"].get<std::string>();
            else if (params.contains("name") && params["name"].is_string())
                filter = params["name"].get<std::string>();
            filter = trim_ascii(filter);
            const int timeout_ms = int_param_clamped(params, "timeout_ms", filter.empty() ? 5000 : 15000, 500, 60000);
            const int default_modules = filter.empty() ? 256 : 1;
            const int max_modules = int_param_clamped(params, "max_modules", default_modules, 1, 256);
            const int max_exports = int_param_clamped(params, "max_exports", filter.empty() ? 0 : 50, 0, 1000);
            const int max_imports = int_param_clamped(params, "max_imports", filter.empty() ? 0 : 50, 0, 1000);
            const bool allow_partial = params.value("allow_partial", false);
            const bool include_pe = params.value("include_pe", !filter.empty());
            const bool focused_single = !filter.empty() && max_modules == 1;
            auto deadline = handler_start + std::chrono::milliseconds(timeout_ms);

            std::vector<driver_bridge::module_info_t> mods;
            size_t cached_count = 0;
            size_t direct_count = 0;
            bool direct_used = false;
            long long enumeration_ms = 0;
            long long refresh_ms = 0;
            bool loading_after_refresh = module_view::g_ui.loading.load(std::memory_order_acquire);
            bool refresh_skipped = false;
            const char* refresh_skip_reason = "none";

            if (!include_pe || focused_single) {
                const auto enum_start = std::chrono::steady_clock::now();
                auto direct = driver_bridge::enumerate_modules();
                enumeration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - enum_start).count();
                direct_count = direct.size();
                if (!direct.empty()) {
                    mods = std::move(direct);
                    direct_used = true;
                    refresh_skipped = true;
                    refresh_skip_reason = focused_single ? "focused_direct" : "summary_direct";
                    deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
                }
            }

            if (!refresh_skipped) {
                const auto refresh_start = std::chrono::steady_clock::now();
                diag::log_tagged_fmt("dbg_tools",
                    "dbg_get_modules_detail: refresh_begin filter=%s max_modules=%d max_exports=%d max_imports=%d timeout_ms=%d",
                    filter.empty() ? "<none>" : filter.c_str(),
                    max_modules,
                    max_exports,
                    max_imports,
                    timeout_ms);
                module_view::refresh();
                while (module_view::g_ui.loading.load(std::memory_order_acquire) && !deadline_expired(deadline))
                    Sleep(25);
                refresh_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - refresh_start).count();
                loading_after_refresh = module_view::g_ui.loading.load(std::memory_order_acquire);
                diag::log_tagged_fmt("dbg_tools",
                    "dbg_get_modules_detail: refresh_done elapsed_ms=%lld loading=%d deadline_hit=%d total_ms=%lld",
                    refresh_ms,
                    loading_after_refresh ? 1 : 0,
                    deadline_expired(deadline) ? 1 : 0,
                    elapsed_ms());
                {
                    std::lock_guard<std::mutex> lk(module_view::g_ui.modules_mutex);
                    mods = module_view::g_ui.modules;
                }
                cached_count = mods.size();
            } else {
                {
                    std::lock_guard<std::mutex> lk(module_view::g_ui.modules_mutex);
                    cached_count = module_view::g_ui.modules.size();
                }
                diag::log_tagged_fmt("dbg_tools",
                    "dbg_get_modules_detail: refresh_skipped reason=%s filter=%s direct=%zu loading=%d enum_ms=%lld total_ms=%lld",
                    refresh_skip_reason,
                    filter.c_str(),
                    direct_count,
                    loading_after_refresh ? 1 : 0,
                    enumeration_ms,
                    elapsed_ms());
            }

            if (!direct_used && (mods.empty() || loading_after_refresh)) {
                const auto enum_start = std::chrono::steady_clock::now();
                auto direct = driver_bridge::enumerate_modules();
                enumeration_ms += std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - enum_start).count();
                direct_count = direct.size();
                if (!direct.empty()) {
                    mods = std::move(direct);
                    direct_used = true;
                    deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
                }
            }
            if (direct_used) {
                diag::log_tagged_fmt("dbg_tools",
                    "dbg_get_modules_detail: using direct module enumeration cached=%zu direct=%zu loading=%d focused=%d",
                    cached_count,
                    direct_count,
                    loading_after_refresh ? 1 : 0,
                    focused_single ? 1 : 0);
            }
            const size_t prefilter_count = mods.size();
            if (!filter.empty()) {
                std::vector<driver_bridge::module_info_t> filtered;
                filtered.reserve(std::min<size_t>(mods.size(), static_cast<size_t>(max_modules)));
                const std::string lower_filter = lower_ascii(filter);
                for (const auto& m : mods) {
                    const std::string lower_name = lower_ascii(m.name);
                    const std::string lower_path = lower_ascii(m.path);
                    if (lower_name.find(lower_filter) == std::string::npos &&
                        lower_path.find(lower_filter) == std::string::npos)
                        continue;
                    filtered.push_back(m);
                    if (focused_single)
                        break;
                }
                mods = std::move(filtered);
            }
            diag::log_tagged_fmt("dbg_tools",
                "dbg_get_modules_detail: enumeration_done cached=%zu direct=%zu direct_used=%d prefilter=%zu filtered=%zu enum_ms=%lld deadline_hit=%d total_ms=%lld",
                cached_count,
                direct_count,
                direct_used ? 1 : 0,
                prefilter_count,
                mods.size(),
                enumeration_ms,
                deadline_expired(deadline) ? 1 : 0,
                elapsed_ms());

            json arr = json::array();
            bool request_truncated = false;
            bool module_limit_truncated = false;
            bool deadline_hit = false;
            bool deadline_prevented_result = false;
            bool detail_deadline_hit = false;
            bool detail_omitted_by_deadline = false;
            bool detail_parse_incomplete = false;
            json phase_timings = json::array();
            for (const auto& m : mods) {
                if (arr.size() >= static_cast<size_t>(max_modules)) {
                    module_limit_truncated = true;
                    break;
                }
                if (deadline_expired(deadline)) {
                    deadline_hit = true;
                    if (arr.empty() || !focused_single)
                        deadline_prevented_result = true;
                    break;
                }
                const auto module_start = std::chrono::steady_clock::now();
                json mj;
                mj["name"] = m.name;
                mj["base"] = sa_format_address(m.base);
                mj["size"] = m.size;
                mj["max_exports"] = max_exports;
                mj["max_imports"] = max_imports;
                mj["exports_requested"] = max_exports > 0;
                mj["imports_requested"] = max_imports > 0;
                mj["exports_omitted_by_request"] = false;
                mj["imports_omitted_by_request"] = false;
                diag::log_tagged_fmt("dbg_tools",
                    "dbg_get_modules_detail: module_begin name=%s base=0x%llX size=%llu focused=%d detail_order=%s remaining_ms=%lld total_ms=%lld",
                    m.name.c_str(),
                    static_cast<unsigned long long>(m.base),
                    static_cast<unsigned long long>(m.size),
                    focused_single ? 1 : 0,
                    "exports_first",
                    deadline_remaining_ms(deadline),
                    elapsed_ms());
                if (!include_pe) {
                    mj["pe_parsed"] = false;
                    mj["pe_omitted_by_request"] = true;
                    mj["pe_omitted_reason"] = "summary_only";
                    mj["entry_point"] = nullptr;
                    mj["is_64bit"] = nullptr;
                    mj["sections"] = json::array();
                    mj["export_count"] = 0;
                    mj["import_count"] = 0;
                    mj["exports_truncated"] = false;
                    mj["imports_truncated"] = false;
                    mj["exports_omitted_by_request"] = true;
                    mj["imports_omitted_by_request"] = true;
                    mj["exports_omitted_by_deadline"] = false;
                    mj["imports_omitted_by_deadline"] = false;
                    mj["exports_parse_ok"] = true;
                    mj["imports_parse_ok"] = true;
                    mj["exports_detail_complete"] = true;
                    mj["imports_detail_complete"] = true;
                    mj["exports_omitted_reason"] = "include_pe_false";
                    mj["imports_omitted_reason"] = "include_pe_false";
                    mj["exports"] = json::array();
                    mj["imports"] = json::array();
                    const long long module_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - module_start).count();
                    json phase;
                    phase["module"] = m.name;
                    phase["base"] = sa_format_address(m.base);
                    phase["pe_ms"] = 0;
                    phase["export_ms"] = 0;
                    phase["import_ms"] = 0;
                    phase["module_ms"] = module_ms;
                    phase["export_count"] = 0;
                    phase["import_count"] = 0;
                    phase["exports_parse_ok"] = true;
                    phase["imports_parse_ok"] = true;
                    phase["exports_detail_complete"] = true;
                    phase["imports_detail_complete"] = true;
                    phase["exports_truncated"] = false;
                    phase["imports_truncated"] = false;
                    phase["exports_deadline"] = false;
                    phase["imports_deadline"] = false;
                    phase["exports_omitted_by_deadline"] = false;
                    phase["imports_omitted_by_deadline"] = false;
                    phase["deadline_after_module"] = false;
                    phase_timings.push_back(std::move(phase));
                    diag::log_tagged_fmt("dbg_tools",
                        "dbg_get_modules_detail: module_summary_only name=%s base=0x%llX size=%llu include_pe=0 total_ms=%lld",
                        m.name.c_str(),
                        static_cast<unsigned long long>(m.base),
                        static_cast<unsigned long long>(m.size),
                        elapsed_ms());
                    arr.push_back(std::move(mj));
                    continue;
                }
                pe_parser::pe_info_t pe;
                std::vector<std::uint8_t> module_image;
                bool module_image_ok = false;
                long long module_image_ms = 0;
                std::string module_image_status = "not_attempted";
                std::string pe_source = "remote_reader";
                const auto pe_start = std::chrono::steady_clock::now();
                diag::log_tagged_fmt("dbg_tools",
                    "dbg_get_modules_detail: pe_parse_begin name=%s base=0x%llX remaining_ms=%lld focused=%d",
                    m.name.c_str(),
                    static_cast<unsigned long long>(m.base),
                    deadline_remaining_ms(deadline),
                    focused_single ? 1 : 0);
                bool pe_ok = false;
                if (focused_single) {
                    const auto image_start = std::chrono::steady_clock::now();
                    module_image_ok = read_module_image_for_modules_detail(m, module_image, module_image_status);
                    module_image_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - image_start).count();
                    if (module_image_ok && parse_pe_from_module_image(m.base, module_image, pe)) {
                        pe_ok = true;
                        pe_source = "local_mapped_image";
                    } else if (module_image_ok) {
                        pe_source = "local_mapped_image_parse_failed";
                    }
                    diag::log_tagged_fmt("dbg_tools",
                        "dbg_get_modules_detail: module_image_read name=%s ok=%d status=%s bytes=%zu requested=%llu elapsed_ms=%lld pe_local_ok=%d total_ms=%lld",
                        m.name.c_str(),
                        module_image_ok ? 1 : 0,
                        module_image_status.c_str(),
                        module_image.size(),
                        static_cast<unsigned long long>(m.size),
                        module_image_ms,
                        pe_ok ? 1 : 0,
                        elapsed_ms());
                }
                if (!pe_ok) {
                    pe_ok = pe_parser::parse(m.base, pe, false);
                    pe_source = pe_ok ? "remote_reader" : pe_source + "_remote_parse_failed";
                }
                const long long pe_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - pe_start).count();
                long long export_ms = 0;
                long long import_ms = 0;
                bool exports_truncated = false;
                bool imports_truncated = false;
                bool exports_deadline = false;
                bool imports_deadline = false;
                bool exports_parse_ok = false;
                bool imports_parse_ok = false;
                bool exports_omitted_by_deadline = false;
                bool imports_omitted_by_deadline = false;
                bool exports_detail_complete = max_exports == 0;
                bool imports_detail_complete = max_imports == 0;
                std::size_t export_count_value = 0;
                std::size_t import_count_value = 0;
                const bool use_local_detail = pe_source == "local_mapped_image";
                mj["pe_source"] = pe_source;
                mj["detail_source"] = use_local_detail ? "local_mapped_image" : "remote_reader";
                mj["module_image_fast_path"] = module_image_ok;
                mj["module_image_status"] = module_image_status;
                mj["module_image_bytes"] = module_image.size();
                mj["module_image_read_ms"] = module_image_ms;
                diag::log_tagged_fmt("dbg_tools",
                    "dbg_get_modules_detail: pe_parse_done name=%s base=0x%llX ok=%d source=%s image_ok=%d image_status=%s image_bytes=%zu image_ms=%lld pe_ms=%lld remaining_ms=%lld sections=%zu export_rva=0x%X import_rva=0x%X",
                    m.name.c_str(),
                    static_cast<unsigned long long>(m.base),
                    pe_ok ? 1 : 0,
                    pe_source.c_str(),
                    module_image_ok ? 1 : 0,
                    module_image_status.c_str(),
                    module_image.size(),
                    module_image_ms,
                    pe_ms,
                    deadline_remaining_ms(deadline),
                    pe.sections.size(),
                    pe.export_dir_rva,
                    pe.import_dir_rva);
                if (pe_ok) {
                    mj["pe_parsed"] = true;
                    mj["entry_point"] = sa_format_address(pe.entry_point);
                    mj["is_64bit"] = pe.is_64bit;
                    json sections = json::array();
                    for (const auto& s : pe.sections) {
                        json sj;
                        sj["name"] = s.name;
                        sj["virtual_address"] = s.virtual_address;
                        sj["virtual_size"] = s.virtual_size;
                        sj["characteristics"] = pe_parser::format_characteristics(s.characteristics);
                        sections.push_back(std::move(sj));
                    }
                    mj["sections"] = std::move(sections);
                    json exp_arr = json::array();
                    json imp_arr = json::array();
                    auto run_export_phase = [&]() {
                        if (max_exports <= 0) {
                            mj["export_count"] = 0;
                            mj["exports_truncated"] = false;
                            mj["exports_parse_ok"] = true;
                            mj["exports_detail_complete"] = true;
                            mj["exports_omitted_by_request"] = true;
                            mj["exports_omitted_by_deadline"] = false;
                            mj["exports_omitted_reason"] = "max_exports_zero";
                            diag::log_tagged_fmt("dbg_tools",
                                "dbg_get_modules_detail: export_omitted name=%s reason=max_exports_zero total_ms=%lld",
                                m.name.c_str(),
                                elapsed_ms());
                            return;
                        }
                        if (deadline_expired(deadline)) {
                            exports_deadline = true;
                            exports_truncated = true;
                            exports_omitted_by_deadline = true;
                            detail_deadline_hit = true;
                            detail_omitted_by_deadline = true;
                            detail_parse_incomplete = true;
                            mj["export_count"] = 0;
                            mj["exports_truncated"] = true;
                            mj["exports_parse_ok"] = false;
                            mj["exports_detail_complete"] = false;
                            mj["exports_omitted_by_deadline"] = true;
                            mj["exports_omitted_reason"] = "deadline_before_exports";
                            diag::log_tagged_fmt("dbg_tools",
                                "dbg_get_modules_detail: export_omitted name=%s reason=deadline_before_exports remaining_ms=0 total_ms=%lld",
                                m.name.c_str(),
                                elapsed_ms());
                            return;
                        }

                        std::vector<pe_parser::export_entry_t> exports;
                        const auto export_start = std::chrono::steady_clock::now();
                        bool export_phase_deadline = false;
                        diag::log_tagged_fmt("dbg_tools",
                            "dbg_get_modules_detail: export_phase_begin name=%s parser=%s max_exports=%d remaining_ms=%lld",
                            m.name.c_str(),
                            use_local_detail ? "local_mapped_image" : (focused_single ? "bounded" : "pe_parser"),
                            max_exports,
                            deadline_remaining_ms(deadline));
                        if (use_local_detail) {
                            exports_parse_ok = parse_exports_for_modules_detail_from_image(
                                m.base,
                                pe,
                                module_image,
                                exports,
                                static_cast<std::size_t>(max_exports),
                                &deadline,
                                &exports_truncated,
                                &export_phase_deadline);
                        } else if (focused_single) {
                            exports_parse_ok = parse_exports_for_modules_detail(
                                m.base,
                                pe,
                                exports,
                                static_cast<std::size_t>(max_exports),
                                &deadline,
                                &exports_truncated,
                                &export_phase_deadline);
                        } else {
                            exports_parse_ok = pe_parser::parse_exports(
                                m.base,
                                pe,
                                exports,
                                static_cast<std::size_t>(max_exports),
                                &deadline,
                                &exports_truncated);
                            export_phase_deadline = deadline_expired(deadline);
                        }
                        export_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - export_start).count();
                        exports_deadline = export_phase_deadline || deadline_expired(deadline);
                        export_count_value = exports.size();
                        if (exports_truncated)
                            request_truncated = true;
                        if (exports_deadline) {
                            detail_deadline_hit = true;
                            detail_omitted_by_deadline = true;
                            detail_parse_incomplete = true;
                            exports_omitted_by_deadline = true;
                        } else if (!exports_parse_ok) {
                            detail_parse_incomplete = true;
                        }
                        exports_detail_complete = exports_parse_ok && !exports_deadline;
                        mj["export_count"] = exports.size();
                        mj["exports_truncated"] = exports_truncated;
                        mj["exports_parse_ok"] = exports_parse_ok;
                        mj["exports_detail_complete"] = exports_detail_complete;
                        mj["exports_omitted_by_deadline"] = exports_omitted_by_deadline;
                        if (exports_omitted_by_deadline)
                            mj["exports_omitted_reason"] = exports.empty() ? "deadline_before_export_rows" : "deadline_during_exports";
                        else if (!exports_parse_ok)
                            mj["exports_omitted_reason"] = "export_parse_failed";
                        size_t exp_limit = std::min<size_t>(exports.size(), static_cast<size_t>(max_exports));
                        for (size_t ei = 0; ei < exp_limit; ++ei) {
                            json ej;
                            ej["ordinal"] = exports[ei].ordinal;
                            ej["name"] = exports[ei].name;
                            ej["address"] = sa_format_address(exports[ei].address);
                            if (exports[ei].is_forwarded) ej["forward"] = exports[ei].forward_name;
                            exp_arr.push_back(std::move(ej));
                        }
                        diag::log_tagged_fmt("dbg_tools",
                            "dbg_get_modules_detail: export_phase_done name=%s ok=%d count=%zu json_count=%zu truncated=%d deadline=%d omitted_deadline=%d complete=%d export_ms=%lld remaining_ms=%lld total_ms=%lld",
                            m.name.c_str(),
                            exports_parse_ok ? 1 : 0,
                            exports.size(),
                            exp_arr.size(),
                            exports_truncated ? 1 : 0,
                            exports_deadline ? 1 : 0,
                            exports_omitted_by_deadline ? 1 : 0,
                            exports_detail_complete ? 1 : 0,
                            export_ms,
                            deadline_remaining_ms(deadline),
                            elapsed_ms());
                    };
                    auto run_import_phase = [&]() {
                        if (max_imports <= 0) {
                            mj["import_count"] = 0;
                            mj["imports_truncated"] = false;
                            mj["imports_parse_ok"] = true;
                            mj["imports_detail_complete"] = true;
                            mj["imports_omitted_by_request"] = true;
                            mj["imports_omitted_by_deadline"] = false;
                            mj["imports_omitted_reason"] = "max_imports_zero";
                            diag::log_tagged_fmt("dbg_tools",
                                "dbg_get_modules_detail: import_omitted name=%s reason=max_imports_zero total_ms=%lld",
                                m.name.c_str(),
                                elapsed_ms());
                            return;
                        }
                        if (deadline_expired(deadline)) {
                            imports_deadline = true;
                            imports_truncated = true;
                            imports_omitted_by_deadline = true;
                            detail_deadline_hit = true;
                            detail_omitted_by_deadline = true;
                            detail_parse_incomplete = true;
                            mj["import_count"] = 0;
                            mj["imports_truncated"] = true;
                            mj["imports_parse_ok"] = false;
                            mj["imports_detail_complete"] = false;
                            mj["imports_omitted_by_deadline"] = true;
                            mj["imports_omitted_reason"] = "deadline_before_imports";
                            diag::log_tagged_fmt("dbg_tools",
                                "dbg_get_modules_detail: import_omitted name=%s reason=deadline_before_imports remaining_ms=0 total_ms=%lld",
                                m.name.c_str(),
                                elapsed_ms());
                            return;
                        }

                        std::vector<pe_parser::import_entry_t> imports;
                        const auto import_start = std::chrono::steady_clock::now();
                        diag::log_tagged_fmt("dbg_tools",
                            "dbg_get_modules_detail: import_phase_begin name=%s parser=%s max_imports=%d remaining_ms=%lld",
                            m.name.c_str(),
                            use_local_detail ? "local_mapped_image" : "pe_parser",
                            max_imports,
                            deadline_remaining_ms(deadline));
                        if (use_local_detail) {
                            imports_parse_ok = parse_imports_for_modules_detail_from_image(
                                m.base,
                                pe,
                                module_image,
                                imports,
                                static_cast<std::size_t>(max_imports),
                                &deadline,
                                &imports_truncated);
                        } else {
                            imports_parse_ok = pe_parser::parse_imports(
                                m.base,
                                pe,
                                imports,
                                static_cast<std::size_t>(max_imports),
                                &deadline,
                                &imports_truncated);
                        }
                        import_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - import_start).count();
                        imports_deadline = deadline_expired(deadline);
                        import_count_value = imports.size();
                        if (imports_truncated)
                            request_truncated = true;
                        if (imports_deadline) {
                            detail_deadline_hit = true;
                            detail_omitted_by_deadline = true;
                            detail_parse_incomplete = true;
                            imports_omitted_by_deadline = true;
                        } else if (!imports_parse_ok) {
                            detail_parse_incomplete = true;
                        }
                        imports_detail_complete = imports_parse_ok && !imports_deadline;
                        mj["import_count"] = imports.size();
                        mj["imports_truncated"] = imports_truncated;
                        mj["imports_parse_ok"] = imports_parse_ok;
                        mj["imports_detail_complete"] = imports_detail_complete;
                        mj["imports_omitted_by_deadline"] = imports_omitted_by_deadline;
                        if (imports_omitted_by_deadline)
                            mj["imports_omitted_reason"] = imports.empty() ? "deadline_before_import_rows" : "deadline_during_imports";
                        else if (!imports_parse_ok)
                            mj["imports_omitted_reason"] = "import_parse_failed";
                        size_t imp_limit = std::min<size_t>(imports.size(), static_cast<size_t>(max_imports));
                        for (size_t ii = 0; ii < imp_limit; ++ii) {
                            json ij;
                            ij["module"] = imports[ii].module_name;
                            ij["function"] = imports[ii].function_name;
                            ij["iat_address"] = sa_format_address(imports[ii].iat_address);
                            imp_arr.push_back(std::move(ij));
                        }
                        diag::log_tagged_fmt("dbg_tools",
                            "dbg_get_modules_detail: import_phase_done name=%s ok=%d count=%zu json_count=%zu truncated=%d deadline=%d omitted_deadline=%d complete=%d import_ms=%lld remaining_ms=%lld total_ms=%lld",
                            m.name.c_str(),
                            imports_parse_ok ? 1 : 0,
                            imports.size(),
                            imp_arr.size(),
                            imports_truncated ? 1 : 0,
                            imports_deadline ? 1 : 0,
                            imports_omitted_by_deadline ? 1 : 0,
                            imports_detail_complete ? 1 : 0,
                            import_ms,
                            deadline_remaining_ms(deadline),
                            elapsed_ms());
                    };
                    run_export_phase();
                    run_import_phase();
                    mj["exports"] = std::move(exp_arr);
                    mj["imports"] = std::move(imp_arr);
                } else {
                    mj["pe_parsed"] = false;
                    mj["export_count"] = 0;
                    mj["import_count"] = 0;
                    mj["exports_truncated"] = false;
                    mj["imports_truncated"] = false;
                    mj["exports_omitted_by_request"] = max_exports == 0;
                    mj["imports_omitted_by_request"] = max_imports == 0;
                    mj["exports_omitted_by_deadline"] = false;
                    mj["imports_omitted_by_deadline"] = false;
                    mj["exports_parse_ok"] = false;
                    mj["imports_parse_ok"] = false;
                    mj["exports_detail_complete"] = max_exports == 0;
                    mj["imports_detail_complete"] = max_imports == 0;
                    mj["exports_omitted_reason"] = max_exports == 0 ? "max_exports_zero" : "pe_parse_failed";
                    mj["imports_omitted_reason"] = max_imports == 0 ? "max_imports_zero" : "pe_parse_failed";
                    mj["exports"] = json::array();
                    mj["imports"] = json::array();
                    if (max_exports > 0 || max_imports > 0)
                        detail_parse_incomplete = true;
                    diag::log_tagged_fmt("dbg_tools",
                        "dbg_get_modules_detail: detail_omitted name=%s reason=pe_parse_failed exports_requested=%d imports_requested=%d pe_ms=%lld total_ms=%lld",
                        m.name.c_str(),
                        max_exports > 0 ? 1 : 0,
                        max_imports > 0 ? 1 : 0,
                        pe_ms,
                        elapsed_ms());
                }
                const long long module_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - module_start).count();
                const bool module_deadline = deadline_expired(deadline);
                if (module_deadline || exports_deadline || imports_deadline)
                    deadline_hit = true;
                json phase;
                phase["module"] = m.name;
                phase["base"] = sa_format_address(m.base);
                phase["pe_ms"] = pe_ms;
                phase["export_ms"] = export_ms;
                phase["import_ms"] = import_ms;
                phase["module_ms"] = module_ms;
                phase["export_count"] = export_count_value;
                phase["import_count"] = import_count_value;
                phase["exports_parse_ok"] = exports_parse_ok;
                phase["imports_parse_ok"] = imports_parse_ok;
                phase["exports_detail_complete"] = exports_detail_complete;
                phase["imports_detail_complete"] = imports_detail_complete;
                phase["exports_truncated"] = exports_truncated;
                phase["imports_truncated"] = imports_truncated;
                phase["exports_deadline"] = exports_deadline;
                phase["imports_deadline"] = imports_deadline;
                phase["exports_omitted_by_deadline"] = exports_omitted_by_deadline;
                phase["imports_omitted_by_deadline"] = imports_omitted_by_deadline;
                phase["deadline_after_module"] = module_deadline;
                phase_timings.push_back(phase);
                diag::log_tagged_fmt("dbg_tools",
                    "dbg_get_modules_detail: module_done name=%s base=0x%llX pe_ok=%d pe_ms=%lld export_ms=%lld import_ms=%lld module_ms=%lld export_count=%zu import_count=%zu exports_ok=%d imports_ok=%d exports_complete=%d imports_complete=%d exports_truncated=%d imports_truncated=%d exports_deadline=%d imports_deadline=%d exports_omitted_deadline=%d imports_omitted_deadline=%d deadline_after=%d total_ms=%lld",
                    m.name.c_str(),
                    static_cast<unsigned long long>(m.base),
                    pe_ok ? 1 : 0,
                    pe_ms,
                    export_ms,
                    import_ms,
                    module_ms,
                    export_count_value,
                    import_count_value,
                    exports_parse_ok ? 1 : 0,
                    imports_parse_ok ? 1 : 0,
                    exports_detail_complete ? 1 : 0,
                    imports_detail_complete ? 1 : 0,
                    exports_truncated ? 1 : 0,
                    imports_truncated ? 1 : 0,
                    exports_deadline ? 1 : 0,
                    imports_deadline ? 1 : 0,
                    exports_omitted_by_deadline ? 1 : 0,
                    imports_omitted_by_deadline ? 1 : 0,
                    module_deadline ? 1 : 0,
                    elapsed_ms());
                if (detail_parse_incomplete && export_count_value == 0 && max_exports > 0)
                    mj["parse_failure"] = true;
                arr.push_back(std::move(mj));
                if (focused_single)
                    break;
            }
            json result;
            const std::size_t count = arr.size();
            const bool focused_complete = focused_single && count == 1;
            const bool deadline_incomplete = deadline_prevented_result || detail_omitted_by_deadline || (detail_deadline_hit && detail_parse_incomplete);
            const bool effective_timed_out = deadline_incomplete || (deadline_hit && !focused_complete);
            const bool truncated = request_truncated || module_limit_truncated || effective_timed_out;
            result["count"] = count;
            result["truncated"] = truncated;
            result["timed_out"] = effective_timed_out && !allow_partial;
            result["partial"] = effective_timed_out;
            result["deadline_hit"] = deadline_hit;
            result["deadline_prevented_result"] = deadline_prevented_result;
            result["deadline_incomplete"] = deadline_incomplete;
            result["detail_deadline_hit"] = detail_deadline_hit;
            result["detail_omitted_by_deadline"] = detail_omitted_by_deadline;
            result["detail_parse_incomplete"] = detail_parse_incomplete;
            result["focused_complete"] = focused_complete;
            result["request_truncated"] = request_truncated;
            result["module_limit_truncated"] = module_limit_truncated;
            result["max_modules"] = max_modules;
            result["max_exports"] = max_exports;
            result["max_imports"] = max_imports;
            result["timeout_ms"] = timeout_ms;
            result["elapsed_ms"] = elapsed_ms();
            result["timings"] = {
                {"refresh_ms", refresh_ms},
                {"enumeration_ms", enumeration_ms},
                {"handler_ms", elapsed_ms()},
                {"modules", phase_timings}
            };
            result["request"] = {
                {"module_name", filter},
                {"max_modules", max_modules},
                {"include_pe", include_pe},
                {"max_exports", max_exports},
                {"max_imports", max_imports},
                {"timeout_ms", timeout_ms},
                {"allow_partial", allow_partial}
            };
            result["modules"] = std::move(arr);
            diag::log_tagged_fmt("dbg_tools",
                "dbg_get_modules_detail: deadline_summary count=%zu focused=%d focused_complete=%d request_truncated=%d module_limit_truncated=%d deadline_hit=%d deadline_prevented=%d deadline_incomplete=%d detail_deadline_hit=%d detail_omitted_by_deadline=%d detail_parse_incomplete=%d effective_timed_out=%d allow_partial=%d elapsed_ms=%lld",
                count,
                focused_single ? 1 : 0,
                focused_complete ? 1 : 0,
                request_truncated ? 1 : 0,
                module_limit_truncated ? 1 : 0,
                deadline_hit ? 1 : 0,
                deadline_prevented_result ? 1 : 0,
                deadline_incomplete ? 1 : 0,
                detail_deadline_hit ? 1 : 0,
                detail_omitted_by_deadline ? 1 : 0,
                detail_parse_incomplete ? 1 : 0,
                effective_timed_out ? 1 : 0,
                allow_partial ? 1 : 0,
                elapsed_ms());
            if (effective_timed_out && !allow_partial)
                return tool_result_t{false, std::string("Module detail collection did not complete within the timeout."), result};
            return tool_result_t::ok(
                std::to_string(result["count"].get<size_t>()) + std::string(" module(s)."), result);
        }, true});

    register_compat(srv, {
        std::string("dbg_add_patch"), std::string("debugger"),
        std::string("Apply a code patch at an address. Overwrites bytes and saves original for reverting."),
        {{std::string("address"), std::string("string"), std::string("Address to patch (hex)"), true},
         {std::string("bytes"), std::string("string"), std::string("Hex bytes to write (e.g. '90 90 90')"), true},
         {std::string("label"), std::string("string"), std::string("Optional description for this patch"), false}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_add_patch: entry");
            if (auto err = ensure_attached(params)) return *err;

            driver_debugger_quota_guard_t quota_guard;
            if (auto quota_err = acquire_driver_debugger_quota("dbg_add_patch", driver_bridge::attached_pid(), quota_guard))
                return *quota_err;

            if (!params.contains("address") || !params["address"].is_string())
                return tool_result_t::error(std::string("'address' is required."));
            if (!params.contains("bytes") || !params["bytes"].is_string())
                return tool_result_t::error(std::string("'bytes' is required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(std::string("Invalid address."));
            auto patched = code_patcher::parse_bytes(params["bytes"].get<std::string>());

            if (patched.empty()) {
                diag::log_tagged_fmt("dbg_tools", "dbg_add_patch: invalid hex bytes");
                return tool_result_t::error(std::string("Invalid hex bytes."));
            }
            std::string label;
            if (params.contains("label") && params["label"].is_string())
                label = params["label"].get<std::string>();
            if (auto reject = reject_full_test_system_mutation(*addr, static_cast<std::uint64_t>(patched.size()), "dbg_add_patch"))
                return *reject;
            const std::size_t before_count = patch_count();
            const std::size_t before_active_count = active_patch_count();
            diag::log_tagged_fmt("dbg_tools", "dbg_add_patch: addr=0x%llX size=%zu label=%s", (unsigned long long)*addr, patched.size(), label.c_str());
            int idx = code_patcher::create_patch(*addr, patched, label);
            if (idx < 0) {
                diag::log_tagged_fmt("dbg_tools", "dbg_add_patch: create_patch failed");
                return tool_result_t::error(std::string("Failed to create patch."));
            }
            if (!code_patcher::apply_patch(idx)) {
                diag::log_tagged_fmt("dbg_tools", "dbg_add_patch: apply_patch failed for idx=%d", idx);
                return tool_result_t::error(std::string("Patch created but failed to apply."));
            }
            diag::log_tagged_fmt("dbg_tools", "dbg_add_patch: patch applied at 0x%llX idx=%d", (unsigned long long)*addr, idx);
            std::vector<std::uint8_t> readback;
            const bool readback_ok = driver_bridge::read_memory(*addr, patched.size(), readback) && readback.size() >= patched.size();
            if (readback.size() > patched.size())
                readback.resize(patched.size());
            const bool verified = readback_ok && readback == patched;
            json result;
            add_debugger_action_context(result, "dbg_add_patch");
            result["success"] = !readback_ok || verified;
            result["index"] = idx;
            result["address"] = sa_format_address(*addr);
            result["size"] = patched.size();
            result["bytes"] = code_patcher::format_bytes(patched);
            result["bytes_written"] = patched.size();
            result["patch_count_before"] = before_count;
            result["patch_count_after"] = patch_count();
            result["active_patch_count_before"] = before_active_count;
            result["active_patch_count_after"] = active_patch_count();
            result["readback_ok"] = readback_ok;
            result["verified"] = verified;
            if (readback_ok)
                result["readback"] = code_patcher::format_bytes(readback);
            json entry;
            if (patch_entry_by_index(idx, entry)) {
                result["active"] = entry.value("active", true);
                result["patch"] = std::move(entry);
            }
            const std::string summary = std::string("Patch applied at ") + sa_format_address(*addr) + std::string(" (") + std::to_string(patched.size()) + std::string(" bytes).");
            if (readback_ok && !verified)
                return tool_result_t{false, std::string("Patch write verification failed."), result};
            return tool_result_t::ok(summary, result);
        }, false});

    register_compat(srv, {
        std::string("dbg_remove_patch"), std::string("debugger"),
        std::string("Remove a code patch by index. Reverts original bytes before removing."),
        {{std::string("index"), std::string("number"), std::string("Patch index to remove"), true}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_remove_patch: entry");
            if (!params.contains("index") || !params["index"].is_number())
                return tool_result_t::error(std::string("'index' is required."));
            int idx = params["index"].get<int>();
            diag::log_tagged_fmt("dbg_tools", "dbg_remove_patch: reverting and removing idx=%d", idx);
            const std::size_t before_count = patch_count();
            const std::size_t before_active_count = active_patch_count();
            std::uint64_t patch_address = 0;
            std::vector<std::uint8_t> original_bytes;
            std::vector<std::uint8_t> patched_bytes;
            json removed_entry;
            {
                std::lock_guard<std::mutex> lk(code_patcher::g_state.mtx);
                if (idx < 0 || idx >= static_cast<int>(code_patcher::g_state.patches.size()))
                    return tool_result_t::error(std::string("Patch index is out of range."));
                const auto& p = code_patcher::g_state.patches[static_cast<std::size_t>(idx)];
                patch_address = p.address;
                original_bytes = p.original_bytes;
                patched_bytes = p.patched_bytes;
                removed_entry["index"] = idx;
                removed_entry["address"] = sa_format_address(p.address);
                removed_entry["description"] = p.description;
                removed_entry["active"] = p.active;
                removed_entry["timestamp"] = p.timestamp;
                removed_entry["original_bytes"] = code_patcher::format_bytes(p.original_bytes);
                removed_entry["patched_bytes"] = code_patcher::format_bytes(p.patched_bytes);
                removed_entry["size"] = p.patched_bytes.size();
            }
            driver_debugger_quota_guard_t quota_guard;
            if (auto quota_err = acquire_driver_debugger_quota("dbg_remove_patch", driver_bridge::attached_pid(), quota_guard))
                return *quota_err;

            if (!code_patcher::revert_patch(idx)) {
                diag::log_tagged_fmt("dbg_tools", "dbg_remove_patch: revert_patch failed for idx=%d", idx);
                return tool_result_t::error(std::string("Failed to revert patch."));
            }
            std::vector<std::uint8_t> readback;
            const bool readback_ok = !original_bytes.empty() &&
                driver_bridge::read_memory(patch_address, original_bytes.size(), readback) &&
                readback.size() >= original_bytes.size();
            if (readback.size() > original_bytes.size())
                readback.resize(original_bytes.size());
            const bool verified = readback_ok && readback == original_bytes;
            if (readback_ok && !verified) {
                json result;
                add_debugger_action_context(result, "dbg_remove_patch");
                result["success"] = false;
                result["index"] = idx;
                result["address"] = sa_format_address(patch_address);
                result["bytes_written"] = original_bytes.size();
                result["readback_ok"] = readback_ok;
                result["verified"] = false;
                result["readback"] = code_patcher::format_bytes(readback);
                result["expected"] = code_patcher::format_bytes(original_bytes);
                result["patch_count_before"] = before_count;
                result["patch_count_after"] = patch_count();
                result["active_patch_count_before"] = before_active_count;
                result["active_patch_count_after"] = active_patch_count();
                result["removed"] = std::move(removed_entry);
                return tool_result_t{false, std::string("Patch revert verification failed."), result};
            }
            if (!code_patcher::remove_patch(idx)) {
                diag::log_tagged_fmt("dbg_tools", "dbg_remove_patch: remove_patch failed for idx=%d", idx);
                return tool_result_t::error(std::string("Failed to remove patch."));
            }
            diag::log_tagged_fmt("dbg_tools", "dbg_remove_patch: patch removed idx=%d", idx);
            json result;
            add_debugger_action_context(result, "dbg_remove_patch");
            result["success"] = true;
            result["index"] = idx;
            result["address"] = sa_format_address(patch_address);
            result["size"] = patched_bytes.size();
            result["bytes_written"] = original_bytes.size();
            result["patch_count_before"] = before_count;
            result["patch_count_after"] = patch_count();
            result["active_patch_count_before"] = before_active_count;
            result["active_patch_count_after"] = active_patch_count();
            result["readback_ok"] = readback_ok;
            result["verified"] = verified;
            if (readback_ok)
                result["readback"] = code_patcher::format_bytes(readback);
            result["removed"] = std::move(removed_entry);
            return tool_result_t::ok(std::string("Patch removed."), result);
        }, false});


    register_compat(srv, {
        std::string("dbg_nop_fill"), std::string("debugger"),
        std::string("NOP-fill a range of bytes at the given address."),
        {{std::string("address"), std::string("string"), std::string("Address to start NOP fill (hex)"), true},
         {std::string("size"), std::string("number"), std::string("Number of bytes to NOP"), true}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_nop_fill: entry");
            if (auto err = ensure_attached(params)) return *err;

            driver_debugger_quota_guard_t quota_guard;
            if (auto quota_err = acquire_driver_debugger_quota("dbg_nop_fill", driver_bridge::attached_pid(), quota_guard))
                return *quota_err;

            if (!params.contains("address") || !params["address"].is_string())
                return tool_result_t::error(std::string("'address' is required."));
            if (!params.contains("size") || !params["size"].is_number())
                return tool_result_t::error(std::string("'size' is required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(std::string("Invalid address."));
            int size = params["size"].get<int>();
            if (size <= 0 || size > 4096)
                return tool_result_t::error(std::string("Size must be between 1 and 4096."));

            if (auto reject = reject_full_test_system_mutation(*addr, static_cast<std::uint64_t>(size), "dbg_nop_fill"))
                return *reject;
            diag::log_tagged_fmt("dbg_tools", "dbg_nop_fill: addr=0x%llX size=%d", (unsigned long long)*addr, size);
            const std::size_t before_count = patch_count();
            const std::size_t before_active_count = active_patch_count();
            std::vector<std::uint8_t> nops(static_cast<std::size_t>(size), 0x90);
            int idx = code_patcher::create_patch(*addr, nops, std::string("NOP fill"));
            if (idx < 0) {
                diag::log_tagged_fmt("dbg_tools", "dbg_nop_fill: nop_region failed at 0x%llX", (unsigned long long)*addr);
                return tool_result_t::error(std::string("Failed to NOP-fill region."));
            }
            if (!code_patcher::apply_patch(idx))
                return tool_result_t::error(std::string("NOP patch created but failed to apply."));
            std::vector<std::uint8_t> readback;
            const bool readback_ok = driver_bridge::read_memory(*addr, nops.size(), readback) && readback.size() >= nops.size();
            if (readback.size() > nops.size())
                readback.resize(nops.size());
            const bool verified = readback_ok && readback == nops;
            json result;
            add_debugger_action_context(result, "dbg_nop_fill");
            result["success"] = !readback_ok || verified;
            result["index"] = idx;
            result["address"] = sa_format_address(*addr);
            result["size"] = size;
            result["bytes"] = code_patcher::format_bytes(nops);
            result["bytes_written"] = nops.size();
            result["patch_count_before"] = before_count;
            result["patch_count_after"] = patch_count();
            result["active_patch_count_before"] = before_active_count;
            result["active_patch_count_after"] = active_patch_count();
            result["readback_ok"] = readback_ok;
            result["verified"] = verified;
            if (readback_ok)
                result["readback"] = code_patcher::format_bytes(readback);
            json entry;
            if (patch_entry_by_index(idx, entry)) {
                result["active"] = entry.value("active", true);
                result["patch"] = std::move(entry);
            }
            diag::log_tagged_fmt("dbg_tools", "dbg_nop_fill: NOP-filled %d bytes at 0x%llX", size, (unsigned long long)*addr);
            const std::string summary = std::string("NOP-filled ") + std::to_string(size) + std::string(" bytes at ") + sa_format_address(*addr);
            if (readback_ok && !verified)
                return tool_result_t{false, std::string("NOP fill verification failed."), result};
            return tool_result_t::ok(summary, result);
        }, false});

    register_compat(srv, {
        std::string("dbg_find_code_caves"), std::string("debugger"),
        std::string("Find regions of unused bytes (code caves) near a given address. Searches for consecutive 0x00 or 0xCC bytes."),
        {{std::string("address"), std::string("string"), std::string("Module base or search start address (hex)"), true},
         {std::string("size"), std::string("number"), std::string("Size of region to scan (default 0x1000)"), false},
         {std::string("min_cave_size"), std::string("number"), std::string("Minimum cave size in bytes (default 16)"), false}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_find_code_caves: entry");
            if (auto err = ensure_attached(params)) return *err;

            driver_debugger_quota_guard_t quota_guard;
            if (auto quota_err = acquire_driver_debugger_quota("dbg_find_code_caves", driver_bridge::attached_pid(), quota_guard))
                return *quota_err;

            if (!params.contains("address") || !params["address"].is_string())
                return tool_result_t::error(std::string("'address' is required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(std::string("Invalid address."));
            uint32_t size = static_cast<uint32_t>(params.value("size", 0x1000));
            bool inferred_size = false;
            if (!params.contains("size") || size == 0 || size == 0x1000) {
                auto modules = driver_bridge::enumerate_modules();
                for (const auto& m : modules) {
                    if (*addr == m.base && m.size > 0) {
                        size = m.size;
                        inferred_size = true;
                        break;
                    }
                }
            }
            if (size == 0) size = 0x1000;
            size_t min_size = static_cast<size_t>(params.value("min_cave_size", 16));
            if (min_size == 0) min_size = 16;
            diag::log_tagged_fmt("dbg_tools", "dbg_find_code_caves: addr=0x%llX size=0x%X min_size=%zu inferred_size=%d", (unsigned long long)*addr, size, min_size, inferred_size ? 1 : 0);
            auto caves = code_patcher::find_code_caves(*addr, size, min_size);
            json arr = json::array();
            for (const auto& c : caves) {
                json cj;
                cj["address"] = sa_format_address(c.address);
                cj["size"] = c.size;
                if (!c.module_name.empty()) cj["module"] = c.module_name;
                arr.push_back(std::move(cj));
            }
            json result;
            const std::size_t count = arr.size();
            result["count"] = count;
            result["caves"] = std::move(arr);
            diag::log_tagged_fmt("dbg_tools", "dbg_find_code_caves: found %zu caves", caves.size());
            return tool_result_t::ok(
                std::to_string(count) + std::string(" code cave(s) found."), result);
        }, true});

    register_compat(srv, {
        std::string("dbg_conditional_breakpoint"), std::string("debugger"),
        std::string("Set a breakpoint with a condition expression. The breakpoint will only trigger when the condition is met."),
        {{std::string("address"), std::string("string"), std::string("Address for breakpoint (hex)"), true},
         {std::string("condition"), std::string("string"), std::string("Condition expression (e.g. 'rax == 0x1234')"), true}},
        [](const json& params) -> tool_result_t {
            diag::log_tagged_fmt("dbg_tools", "dbg_conditional_breakpoint: entry");
            if (auto err = ensure_attached(params)) return *err;

            driver_debugger_quota_guard_t quota_guard;
            if (auto quota_err = acquire_driver_debugger_quota("dbg_conditional_breakpoint", driver_bridge::attached_pid(), quota_guard))
                return *quota_err;

            if (!params.contains("address") || !params["address"].is_string())
                return tool_result_t::error(std::string("'address' is required."));
            if (!params.contains("condition") || !params["condition"].is_string())
                return tool_result_t::error(std::string("'condition' is required."));
            auto addr = sa_parse_address(params["address"].get<std::string>());
            if (!addr) return tool_result_t::error(std::string("Invalid address."));
            std::string cond = params["condition"].get<std::string>();

            diag::log_tagged_fmt("dbg_tools", "dbg_conditional_breakpoint: addr=0x%llX cond=%s", (unsigned long long)*addr, cond.c_str());
            const std::size_t before_count = breakpoint_count();
            int bp_idx = debugger_engine::add_breakpoint(*addr, debugger_engine::bp_type_t::software, "", cond);
            if (bp_idx < 0) {
                diag::log_tagged_fmt("dbg_tools", "dbg_conditional_breakpoint: add_breakpoint failed: %s", debugger_engine::last_error().c_str());
                return tool_result_t::error(std::string("Failed to add breakpoint."));
            }
            json result;
            add_debugger_action_context(result, "dbg_conditional_breakpoint");
            result["success"] = true;
            result["index"] = bp_idx;
            result["address"] = sa_format_address(*addr);
            result["condition"] = cond;
            result["type"] = "software";
            result["type_name"] = breakpoint_type_name(debugger_engine::bp_type_t::software);
            result["breakpoint_count_before"] = before_count;
            result["breakpoint_count_after"] = breakpoint_count();
            json entry;
            if (breakpoint_entry_by_index(bp_idx, entry)) {
                result["enabled"] = entry.value("enabled", true);
                result["hardware"] = entry.value("hardware", false);
                result["hw_slot"] = entry.value("hw_slot", -1);
                result["hw_slot_active"] = entry.value("hw_slot_active", false);
                result["breakpoint"] = std::move(entry);
            }
            diag::log_tagged_fmt("dbg_tools", "dbg_conditional_breakpoint: BP set at 0x%llX idx=%d cond=%s", (unsigned long long)*addr, bp_idx, cond.c_str());
            return tool_result_t::ok(
                std::string("Conditional breakpoint set at ") + sa_format_address(*addr) + std::string(" [condition: ") + cond + std::string("]"), result);
        }, false});

}

}
