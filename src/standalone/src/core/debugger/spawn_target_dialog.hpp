#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <shellapi.h>
#include <objbase.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <utility>

#include "../helpers/diag_log.hpp"
#include "../runtime/run_target.hpp"
#include "../runtime/vm_guest_bridge.hpp"
#include "../ui/toast_notification.hpp"
#include "../ui/task_center.hpp"
#include "../ui/ui_thread_dispatcher.hpp"
#include "../infra/executor.hpp"
#include "../auth/auth_browser_launch.hpp"
#include "debugger_engine.hpp"
#include "debugger_view.hpp"

namespace spawn_target_dialog {

// Qt-free spawn/launch backend. The Qt dialog
// (qt/debugger/dialogs/spawn_target_dialog_qt.*) owns the form; this module
// owns the launch consume (debugger.spawn_attach executor body), the custom
// VM bridge operation, the custom VM guide lookup, and the shared helpers.

struct launch_consume_result_t {
	std::wstring sandbox_dir;
};

inline std::wstring& last_sandbox_dir() {
	static std::wstring v;
	return v;
}

inline std::wstring& last_custom_bridge_dir() {
	static std::wstring v;
	return v;
}

inline std::wstring widen_utf8(const char* utf8) {
	if (!utf8 || !*utf8) return std::wstring();
	int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, nullptr, 0);
	if (needed <= 1) return std::wstring();
	std::wstring out(static_cast<size_t>(needed), L'\0');
	if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, out.data(), needed) != needed)
		return {};
	out.resize(static_cast<size_t>(needed - 1));
	return out;
}

inline std::string narrow_utf8(const wchar_t* w) {
	if (!w || !*w) return std::string();
	int needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, w, -1, nullptr, 0, nullptr, nullptr);
	if (needed <= 1) return std::string();
	std::string out(static_cast<size_t>(needed), '\0');
	if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, w, -1, out.data(), needed, nullptr, nullptr) != needed)
		return {};
	out.resize(static_cast<size_t>(needed - 1));
	return out;
}

inline std::string parent_dir(const std::string& path) {
	if (path.empty()) return std::string();
	size_t pos = path.find_last_of("\\/");
	if (pos == std::string::npos) return std::string();
	return path.substr(0, pos);
}

inline std::string trim(const char* s) {
	if (!s) return std::string();
	std::string out(s);
	while (!out.empty()) {
		char c = out.back();
		if (c == ' ' || c == '\t' || c == '\r' || c == '\n') out.pop_back();
		else break;
	}
	size_t i = 0;
	while (i < out.size()) {
		char c = out[i];
		if (c == ' ' || c == '\t' || c == '\r' || c == '\n') ++i;
		else break;
	}
	if (i > 0) out.erase(0, i);
	return out;
}

inline std::wstring resolve_guest_agent_exe() {
	wchar_t module_path[MAX_PATH] = {};
	DWORD n = GetModuleFileNameW(nullptr, module_path, MAX_PATH);
	if (n == 0 || n >= MAX_PATH) return {};
	std::filesystem::path p(module_path);
	std::filesystem::path agent = p.parent_path() / L"AiDAGuestAgent.exe";
	std::error_code ec;
	if (!std::filesystem::exists(agent, ec) || ec) return {};
	return agent.wstring();
}

inline std::string join_guest_path(std::string base, const std::string& leaf) {
	if (base.empty()) return leaf;
	while (!base.empty() && (base.back() == '\\' || base.back() == '/')) base.pop_back();
	return base + "\\" + leaf;
}

inline std::string quote_arg(std::string value) {
	std::string out;
	out.reserve(value.size() + 2);
	out.push_back('"');
	for (char c : value) {
		if (c == '"') out += "\\\"";
		else out.push_back(c);
	}
	out.push_back('"');
	return out;
}

inline std::string custom_guest_command(const std::string& guest_bridge) {
	const std::string guest_bridge_trim = trim(guest_bridge.c_str());
	if (guest_bridge_trim.empty()) return {};
	std::string agent = join_guest_path(guest_bridge_trim, "agent\\AiDAGuestAgent.exe");
	return quote_arg(agent) + " --bridge " + quote_arg(guest_bridge_trim);
}

inline void open_url_external(const wchar_t* url) {
	if (!url || !*url) return;
	const int len = WideCharToMultiByte(CP_UTF8, 0, url, -1, nullptr, 0, nullptr, nullptr);
	if (len <= 1) return;
	std::string utf8(static_cast<size_t>(len), '\0');
	WideCharToMultiByte(CP_UTF8, 0, url, -1, utf8.data(), len, nullptr, nullptr);
	if (!utf8.empty() && utf8.back() == '\0') utf8.pop_back();
	const auto submitted = aida::auth::submit_open_url_external(std::move(utf8));
	if (!submitted.submitted) {
		toast_notification::push("Camoufox could not queue the requested page",
			toast_notification::toast_type_t::error, 5.0f);
	}
}

// The launch consume path (debugger.spawn_attach): sandbox cleanup + the
// verbatim completion toasts on the UI thread.
inline bool submit_spawn_launch(run_target::launch_options_t options) {
	aida::infra::executor::submission_t submission;
	submission.owner_subsystem = "debugger";
	submission.label = "debugger.spawn_attach";
	submission.thread_class = "debugger_launch";
	submission.domain = aida::infra::executor::domain_t::feature_worker;
	submission.priority = 2;
	submission.body = [options]() {
		uint32_t new_pid = 0;
		run_target::launch_result_t result{};
		const bool ok = debugger_engine::spawn_and_attach_target(options, &new_pid,
			&result);
		const std::wstring sandbox_dir = result.sandbox_dir;
		if (options.isolation == run_target::isolation_t::windows_sandbox)
			run_target::cleanup(result);
		else if (result.thread_handle != 0) {
			CloseHandle(reinterpret_cast<HANDLE>(result.thread_handle));
			result.thread_handle = 0;
		}
		std::string error;
		if (!ok) {
			error = debugger_engine::last_error();
			if (error.empty())
				error = "(no detail)";
		}
		const std::string task_error = error;
		const auto isolation = options.isolation;
		const bool posted = aida::ui_thread::post(
			[sandbox_dir, ok, error, new_pid, isolation] {
				if (!sandbox_dir.empty())
					last_sandbox_dir() = sandbox_dir;
				if (!ok) {
					toast_notification::push("Launch failed: " + error,
						toast_notification::toast_type_t::error);
				} else if (isolation == run_target::isolation_t::windows_sandbox) {
					toast_notification::push("Launched interactive malware lab VM.",
						toast_notification::toast_type_t::success);
				} else {
					char message[160];
					std::snprintf(message, sizeof(message),
						"Host launch started PID %u (iso=%d)",
						static_cast<unsigned>(new_pid), static_cast<int>(isolation));
					toast_notification::push(message,
						toast_notification::toast_type_t::success);
				}
			}, "spawn_target_dialog", "spawn_attach_completion", "worker_completion");
		if (!posted)
			throw std::runtime_error(
				"Debugger launch completion could not be published to the UI thread");
		if (!ok)
			throw std::runtime_error("Debugger launch or attach failed: " + task_error);
	};
	const auto submitted = debugger_view::submit_owned_debugger_task(
		std::move(submission), "view.debug.cpu", "debugger.launch",
		"Launch and attach debugger target", false);
	if (!submitted.submitted) {
		toast_notification::push("Launch queue rejected the task.",
			toast_notification::toast_type_t::error);
		return false;
	}
	diag::log_tagged_critical_fmt("spawn",
		"spawn_dialog_launch_submitted iso=%d block_net=%d kill_on_exit=%d",
		static_cast<int>(options.isolation), options.block_network ? 1 : 0,
		options.kill_on_host_exit ? 1 : 0);
	return true;
}

inline void open_custom_vm_guide() {
	static std::atomic<std::uint64_t> sequence{1};
	const std::uint64_t serial = sequence.fetch_add(1, std::memory_order_relaxed);
	const std::string task_id = "debugger.custom_vm_guide." + std::to_string(serial);
	aida::ui::task_center::task_registration_t registration;
	registration.id = task_id;
	registration.source = "debugger.spawn_target";
	registration.owner = "Run Target";
	registration.owner_view = "view.debug.cpu";
	registration.owner_action = "Open custom VM guide";
	registration.target = "custom-vm-bridge-guide.md";
	registration.label = "Locate and open custom VM guide";
	registration.stage = "Queued";
	registration.affected_entity = "custom-vm-bridge-guide.md";
	if (!aida::ui::task_center::register_task(std::move(registration))) {
		toast_notification::push("Task Center rejected the guide lookup.",
			toast_notification::toast_type_t::error, 4.0f);
		return;
	}
	aida::infra::executor::submission_t submission;
	submission.owner_subsystem = "debugger";
	submission.label = "debugger.custom_vm_guide.open";
	submission.thread_class = "bounded_file_io";
	submission.domain = aida::infra::executor::domain_t::external_tool;
	submission.priority = 1;
	submission.generation = serial;
	submission.diagnostic_id = task_id.c_str();
	submission.ui_access_policy = "ui_dispatch_only";
	submission.failure_policy = "typed_diagnostic";
	submission.shutdown_policy = "drain";
	submission.body = [task_id]() {
		static_cast<void>(aida::ui::task_center::update_task(task_id,
			aida::ui::task_center::task_state_t::running, -1.0f,
			"Resolving bounded guide candidates"));
		bool opened = false;
		std::string error;
		try {
			const std::filesystem::path relative = L"docs\\custom-vm-bridge-guide.md";
			std::error_code filesystem_error;
			std::array<std::filesystem::path, 4> candidates{};
			candidates[0] = std::filesystem::current_path(filesystem_error) / relative;
			wchar_t module_path[MAX_PATH] = {};
			const DWORD length = GetModuleFileNameW(nullptr, module_path, MAX_PATH);
			if (length > 0 && length < MAX_PATH) {
				const std::filesystem::path module_directory =
					std::filesystem::path(module_path).parent_path();
				candidates[1] = module_directory / relative;
				candidates[2] = module_directory.parent_path() / relative;
				candidates[3] = module_directory.parent_path().parent_path() / relative;
			}
			for (const auto& candidate : candidates) {
				filesystem_error.clear();
				if (candidate.empty() || !std::filesystem::is_regular_file(candidate,
						filesystem_error) || filesystem_error)
					continue;
				const auto result = reinterpret_cast<std::intptr_t>(ShellExecuteW(nullptr,
					L"open", candidate.c_str(), nullptr, nullptr, SW_SHOWNORMAL));
				opened = result > 32;
				if (!opened)
					error = "Windows rejected the guide open request.";
				break;
			}
			if (!opened && error.empty())
				error = "The guide was not found in any approved installation or repository location.";
		} catch (const std::exception& exception) {
			error = exception.what();
		} catch (...) {
			error = "Unknown guide lookup failure.";
		}
		auto publish = [task_id, opened, error] {
			static_cast<void>(aida::ui::task_center::update_task(task_id,
				opened ? aida::ui::task_center::task_state_t::completed :
					aida::ui::task_center::task_state_t::failed,
				1.0f, opened ? "Guide opened" : "Guide unavailable",
				opened ? "Opened custom VM bridge guide" : error,
				opened ? std::string() : "diagnostic." + task_id));
			if (!opened)
				toast_notification::push(error, toast_notification::toast_type_t::error, 6.0f);
		};
		if (!aida::ui_thread::post(std::move(publish), "spawn_target_dialog",
				"publish_custom_vm_guide", "worker_completion")) {
			static_cast<void>(aida::ui::task_center::update_task(task_id,
				aida::ui::task_center::task_state_t::failed, 1.0f,
				"UI publication rejected", opened ?
					"The guide opened, but its UI receipt could not be published" :
					"The guide result could not be published",
				"diagnostic." + task_id));
		}
	};
	const auto submitted = aida::infra::executor::submit(std::move(submission));
	if (!submitted.submitted) {
		static_cast<void>(aida::ui::task_center::update_task(task_id,
			aida::ui::task_center::task_state_t::failed, 1.0f,
			"Executor rejected guide lookup", submitted.reject_reason,
			"diagnostic." + task_id));
		toast_notification::push("The guide lookup could not be queued; see Task Center.",
			toast_notification::toast_type_t::error, 5.0f);
	}
}

// Custom VM bridge operation. The worker stays on the executor; phase and
// completion cross to the caller's UI hop (ui_post), completion runs on the
// UI thread.
enum class custom_bridge_status_t : std::uint8_t {
	idle,
	queued,
	running,
	succeeded,
	failed,
	cancelled
};

struct custom_bridge_operation_t {
	std::atomic<bool> cancel_requested{false};
	std::atomic<unsigned> phase{0};
	std::atomic<unsigned> irreversible_gate{0};
	std::uint64_t serial = 0;
};

struct custom_bridge_fields_t {
	std::string host_bridge;
	std::string guest_bridge;
	std::string executable;
	std::string arguments;
	std::string guest_sample;
};

struct custom_bridge_result_t {
	bool activated = false;
	bool cancelled = false;
	std::string error;
	std::string status_text;
	std::string guest_sample_result;
	std::wstring host_bridge;
};

inline custom_bridge_status_t& custom_bridge_status() {
	static custom_bridge_status_t value = custom_bridge_status_t::idle;
	return value;
}

inline std::string& custom_bridge_status_text() {
	static std::string value;
	return value;
}

inline std::shared_ptr<custom_bridge_operation_t>& custom_bridge_operation() {
	static std::shared_ptr<custom_bridge_operation_t> value;
	return value;
}

inline std::atomic<std::uint64_t>& custom_bridge_sequence() {
	static std::atomic<std::uint64_t> value{1};
	return value;
}

inline bool custom_bridge_pending() {
	return custom_bridge_status() == custom_bridge_status_t::queued ||
		custom_bridge_status() == custom_bridge_status_t::running;
}

inline const char* custom_bridge_phase_text(unsigned phase) {
	switch (phase) {
	case 1: return "Validating bridge directories.";
	case 2: return "Staging the reviewed sample.";
	case 3: return "Staging AiDAGuestAgent.exe.";
	case 4: return "Preparing bridge metadata.";
	case 5: return "Activating the custom VM bridge.";
	default: return "";
	}
}

inline bool request_custom_bridge_cancel() {
	const auto operation = custom_bridge_operation();
	if (!operation || !custom_bridge_pending())
		return false;
	unsigned expected_gate = 0;
	if (!operation->irreversible_gate.compare_exchange_strong(expected_gate, 1,
			std::memory_order_acq_rel))
		return false;
	operation->cancel_requested.store(true, std::memory_order_release);
	const std::string task_id = "debugger.custom_vm_bridge." +
		std::to_string(operation->serial);
	static_cast<void>(aida::ui::task_center::update_task(task_id,
		aida::ui::task_center::task_state_t::cancellation_requested, -1.0f,
		"Cancellation requested before activation"));
	custom_bridge_status_text() = "Cancellation requested; waiting for the current reversible step.";
	return true;
}

using custom_bridge_ui_post_t =
	std::function<bool(std::function<void()>)>;
using custom_bridge_completion_t =
	std::function<void(const custom_bridge_result_t&)>;
using custom_bridge_phase_t = std::function<void(int)>;

inline bool activate_custom_bridge(custom_bridge_fields_t fields,
	custom_bridge_ui_post_t ui_post,
	custom_bridge_completion_t completion,
	custom_bridge_phase_t phase_post) {
	if (custom_bridge_pending())
		return false;
	const std::string host_bridge_text = trim(fields.host_bridge.c_str());
	const std::string guest_bridge_text = trim(fields.guest_bridge.c_str());
	const std::string executable_text = trim(fields.executable.c_str());
	const std::string arguments_text = trim(fields.arguments.c_str());
	const std::string guest_sample_text = trim(fields.guest_sample.c_str());
	if (host_bridge_text.empty()) {
		custom_bridge_status() = custom_bridge_status_t::failed;
		custom_bridge_status_text() = "Choose a host bridge folder first.";
		return false;
	}
	if (guest_bridge_text.empty()) {
		custom_bridge_status() = custom_bridge_status_t::failed;
		custom_bridge_status_text() = "Enter the guest path for the shared bridge folder.";
		return false;
	}
	const std::uint64_t serial = custom_bridge_sequence().fetch_add(1,
		std::memory_order_relaxed);
	auto operation = std::make_shared<custom_bridge_operation_t>();
	operation->serial = serial;
	custom_bridge_operation() = operation;
	custom_bridge_status() = custom_bridge_status_t::queued;
	custom_bridge_status_text() = "Queued bridge staging and activation.";
	const std::string task_id = "debugger.custom_vm_bridge." + std::to_string(serial);
	aida::ui::task_center::task_registration_t registration;
	registration.id = task_id;
	registration.source = "debugger.spawn_target";
	registration.owner = "Run Target";
	registration.owner_view = "view.debug.cpu";
	registration.owner_action = "Activate custom VM bridge";
	registration.target = "Custom VM bridge";
	registration.label = "Stage and activate custom VM bridge";
	registration.stage = "Queued";
	registration.affected_entity = "Custom VM bridge";
	registration.cancellation_is_safe = true;
	registration.callbacks.cancel = [operation] {
		unsigned expected_gate = 0;
		if (!operation->irreversible_gate.compare_exchange_strong(expected_gate, 1,
				std::memory_order_acq_rel))
			return false;
		operation->cancel_requested.store(true, std::memory_order_release);
		return true;
	};
	if (!aida::ui::task_center::register_task(std::move(registration))) {
		custom_bridge_status() = custom_bridge_status_t::failed;
		custom_bridge_status_text() = "Task Center rejected ownership of the bridge operation.";
		custom_bridge_operation().reset();
		return false;
	}
	aida::infra::executor::submission_t submission;
	submission.owner_subsystem = "debugger";
	submission.label = "debugger.custom_vm_bridge.activate";
	submission.thread_class = "bounded_file_io";
	submission.domain = aida::infra::executor::domain_t::external_tool;
	submission.priority = 2;
	submission.generation = serial;
	submission.diagnostic_id = task_id.c_str();
	submission.ui_access_policy = "ui_dispatch_only";
	submission.failure_policy = "retain_review_and_report";
	submission.shutdown_policy = "drain";
	submission.cancel_hook = [operation] {
		unsigned expected_gate = 0;
		if (operation->irreversible_gate.compare_exchange_strong(expected_gate, 1,
				std::memory_order_acq_rel))
			operation->cancel_requested.store(true, std::memory_order_release);
	};
	submission.body = [operation, task_id, host_bridge_text, guest_bridge_text,
		executable_text, arguments_text, guest_sample_text, ui_post, completion,
		phase_post]() {
		const auto publish_phase = [&operation, &ui_post, &phase_post](unsigned phase) {
			operation->phase.store(phase, std::memory_order_release);
			if (ui_post && phase_post) {
				static_cast<void>(ui_post([phase_post, phase]() mutable {
					phase_post(static_cast<int>(phase));
				}));
			}
		};
		publish_phase(1);
		static_cast<void>(aida::ui::task_center::update_task(task_id,
			aida::ui::task_center::task_state_t::running, 0.05f,
			"Validating reviewed bridge paths"));
		bool activated = false;
		bool cancelled = false;
		std::string error;
		std::wstring host_bridge = widen_utf8(host_bridge_text.c_str());
		std::wstring guest_sample = widen_utf8(guest_sample_text.c_str());
		const std::wstring arguments = widen_utf8(arguments_text.c_str());
		try {
			const auto cancellation_requested = [&] {
				cancelled = operation->cancel_requested.load(std::memory_order_acquire);
				if (cancelled && error.empty())
					error = "Bridge activation was cancelled before its irreversible phase.";
				return cancelled;
			};
			std::filesystem::path host_bridge_path(host_bridge);
			std::error_code filesystem_error;
			if (host_bridge.empty() || guest_bridge_text.empty())
				error = "The reviewed host or guest bridge path is invalid.";
			else if (cancellation_requested()) {
			} else {
				std::filesystem::create_directories(host_bridge_path / L"samples", filesystem_error);
				if (!filesystem_error)
					std::filesystem::create_directories(host_bridge_path / L"agent", filesystem_error);
				if (filesystem_error)
					error = "Could not create the bridge directories: " + filesystem_error.message();
			}
			publish_phase(2);
			if (error.empty() && !cancellation_requested() && !executable_text.empty()) {
				const std::filesystem::path host_sample(widen_utf8(executable_text.c_str()));
				filesystem_error.clear();
				const auto size = std::filesystem::file_size(host_sample, filesystem_error);
				const auto modified = filesystem_error ? std::filesystem::file_time_type{} :
					std::filesystem::last_write_time(host_sample, filesystem_error);
				if (filesystem_error || size == 0 || size > 2ULL * 1024ULL * 1024ULL * 1024ULL)
					error = "The reviewed host sample is unavailable, empty, or exceeds 2 GiB.";
				else if (std::filesystem::is_directory(host_sample, filesystem_error) || filesystem_error)
					error = "The reviewed host sample is not a regular file.";
				else {
					const std::filesystem::path staged_sample =
						host_bridge_path / L"samples" / host_sample.filename();
					std::filesystem::copy_file(host_sample, staged_sample,
						std::filesystem::copy_options::overwrite_existing, filesystem_error);
					if (filesystem_error)
						error = "Could not stage the reviewed sample: " + filesystem_error.message();
					else {
						filesystem_error.clear();
						const auto source_size_after = std::filesystem::file_size(host_sample,
							filesystem_error);
						const auto source_modified_after = filesystem_error ?
							std::filesystem::file_time_type{} :
							std::filesystem::last_write_time(host_sample, filesystem_error);
						const auto staged_size = filesystem_error ? std::uintmax_t{0} :
							std::filesystem::file_size(staged_sample, filesystem_error);
						if (filesystem_error || source_size_after != size || staged_size != size ||
							source_modified_after != modified)
							error = "The reviewed host sample changed during staging or the copy was not exact.";
					}
					if (error.empty() && guest_sample.empty()) {
						const std::string filename = narrow_utf8(host_sample.filename().wstring().c_str());
						const std::string generated = join_guest_path(
							join_guest_path(guest_bridge_text, "samples"), filename);
						guest_sample = widen_utf8(generated.c_str());
					}
				}
			}
			publish_phase(3);
			if (error.empty() && !cancellation_requested()) {
				const std::wstring agent_source = resolve_guest_agent_exe();
				if (agent_source.empty())
					error = "AiDAGuestAgent.exe is missing beside AiDAStandalone.exe.";
				else {
					filesystem_error.clear();
					const std::filesystem::path agent_source_path(agent_source);
					const auto agent_size = std::filesystem::file_size(agent_source_path, filesystem_error);
					const auto agent_modified = filesystem_error ? std::filesystem::file_time_type{} :
						std::filesystem::last_write_time(agent_source_path, filesystem_error);
					if (filesystem_error || agent_size == 0 || agent_size > 512ULL * 1024ULL * 1024ULL)
						error = "AiDAGuestAgent.exe is invalid or exceeds 512 MiB.";
					else {
						const std::filesystem::path staged_agent =
							host_bridge_path / L"agent" / L"AiDAGuestAgent.exe";
						std::filesystem::copy_file(agent_source_path, staged_agent,
							std::filesystem::copy_options::overwrite_existing, filesystem_error);
						if (filesystem_error)
							error = "Could not stage AiDAGuestAgent.exe: " + filesystem_error.message();
						else {
							filesystem_error.clear();
							const auto source_size_after = std::filesystem::file_size(agent_source_path,
								filesystem_error);
							const auto source_modified_after = filesystem_error ?
								std::filesystem::file_time_type{} :
								std::filesystem::last_write_time(agent_source_path, filesystem_error);
							const auto staged_size = filesystem_error ? std::uintmax_t{0} :
								std::filesystem::file_size(staged_agent, filesystem_error);
							if (filesystem_error || source_size_after != agent_size ||
								staged_size != agent_size || source_modified_after != agent_modified)
								error = "AiDAGuestAgent.exe changed during staging or the copy was not exact.";
						}
					}
				}
			}
			publish_phase(4);
			if (error.empty() && !cancellation_requested()) {
				static_cast<void>(aida::ui::task_center::update_task(task_id,
					aida::ui::task_center::task_state_t::running, 0.65f,
					"Preparing bridge metadata and launch contract"));
				if (!vm_guest_bridge::prepare_bridge_directory(host_bridge, guest_sample,
						arguments, &error) && error.empty())
					error = "Bridge preparation failed.";
			}
			if (error.empty()) {
				unsigned expected_gate = 0;
				if (!operation->irreversible_gate.compare_exchange_strong(expected_gate, 2,
						std::memory_order_acq_rel)) {
					cancelled = expected_gate == 1;
					error = cancelled ? "Bridge activation was cancelled before its irreversible phase." :
						"Bridge activation could not acquire its irreversible-phase gate.";
				}
			}
			if (error.empty()) {
				publish_phase(5);
				static_cast<void>(aida::ui::task_center::update_task(task_id,
					aida::ui::task_center::task_state_t::running, 0.9f,
					"Activating reviewed custom VM bridge"));
				if (!vm_guest_bridge::activate_bridge(host_bridge, host_bridge, guest_sample,
						"custom_vm", &error) && error.empty())
					error = "Bridge activation failed.";
				else if (error.empty())
					activated = true;
			}
		} catch (const std::exception& exception) {
			error = exception.what();
		} catch (...) {
			error = "Unknown bridge activation failure.";
		}
		publish_phase(6);
		custom_bridge_result_t result;
		result.activated = activated;
		result.cancelled = cancelled;
		result.error = error;
		result.host_bridge = host_bridge;
		result.guest_sample_result = narrow_utf8(guest_sample.c_str());
		if (activated) {
			last_custom_bridge_dir() = host_bridge;
			custom_bridge_status() = custom_bridge_status_t::succeeded;
			custom_bridge_status_text() = "Bridge activated. Start the displayed guest command inside the VM.";
			result.status_text = custom_bridge_status_text();
			diag::log_tagged_critical_fmt("spawn",
				"custom_vm_bridge_activated host_bridge='%s' guest_bridge='%s' guest_sample='%s' args_len=%zu",
				host_bridge_text.c_str(), guest_bridge_text.c_str(),
				result.guest_sample_result.c_str(), arguments_text.size());
		} else if (cancelled) {
			custom_bridge_status() = custom_bridge_status_t::cancelled;
			custom_bridge_status_text() = error.empty() ? "Bridge activation was cancelled." : error;
			result.status_text = custom_bridge_status_text();
		} else {
			custom_bridge_status() = custom_bridge_status_t::failed;
			custom_bridge_status_text() = error.empty() ? "Bridge activation failed." : error;
			result.status_text = custom_bridge_status_text();
		}
		static_cast<void>(aida::ui::task_center::update_task(task_id,
			activated ? aida::ui::task_center::task_state_t::completed :
				cancelled ? aida::ui::task_center::task_state_t::cancelled :
					aida::ui::task_center::task_state_t::failed,
			1.0f, activated ? "Bridge activated" : cancelled ? "Cancelled" : "Activation failed",
			activated ? "Custom VM bridge activation verified" : custom_bridge_status_text(),
			activated ? std::string() : "diagnostic." + task_id));
		const bool posted = ui_post
			? ui_post([completion, result]() mutable { completion(result); })
			: false;
		if (!posted) {
			static_cast<void>(aida::ui::task_center::update_task(task_id,
				activated ? aida::ui::task_center::task_state_t::partial :
					aida::ui::task_center::task_state_t::failed,
				1.0f, "UI publication rejected",
				activated ? "Bridge activation succeeded but UI publication was rejected" :
					"Bridge activation result could not be published",
				"diagnostic." + task_id));
			if (activated)
				toast_notification::push(
					"The bridge was activated, but its detailed UI receipt could not be published.",
					toast_notification::toast_type_t::warning, 5.0f);
			else
				toast_notification::push(
					"The bridge operation finished, but its result could not be published. Retry after reviewing Task Center.",
					toast_notification::toast_type_t::error, 6.0f);
		}
	};
	const auto submitted = aida::infra::executor::submit(std::move(submission));
	if (!submitted.submitted) {
		custom_bridge_status() = custom_bridge_status_t::failed;
		custom_bridge_status_text() = "The executor rejected bridge activation: " +
			submitted.reject_reason;
		custom_bridge_operation().reset();
		static_cast<void>(aida::ui::task_center::update_task(task_id,
			aida::ui::task_center::task_state_t::failed, 1.0f,
			"Executor rejected activation", submitted.reject_reason,
			"diagnostic." + task_id));
		return false;
	}
	return true;
}

}
