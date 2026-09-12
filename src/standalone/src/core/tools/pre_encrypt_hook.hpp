#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <deque>
#include <mutex>
#include <atomic>
#include <thread>
#include <chrono>
#include <cstddef>
#include <windows.h>
#include <tlhelp32.h>
#include "../infra/executor.hpp"
#include "../infra/taskflow_runtime.hpp"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <cstdio>
#include <utility>

#include "helpers/diag_log.hpp"
#include "standalone_driver.hpp"

namespace pre_encrypt_hook {

enum class buffer_kind_t : uint32_t {
    linear = 0,
    wsabuf_array = 1,
    sec_buffer_desc = 2
};

struct dr_arm_result_t {
    uint64_t timestamp = 0;
    uint32_t tid = 0;
    uint32_t bp_index = 0;
    uint64_t address = 0;
    bool ok = false;
    DWORD win32_error = ERROR_SUCCESS;
    std::string driver_error;
};

struct hook_target_t {
    std::string library_name;
    std::string function_name;
    uint64_t address = 0;
    uint32_t buffer_reg = 1;
    uint32_t size_reg = 2;
    bool active = false;
    uint32_t bp_index = 0;
    buffer_kind_t kind = buffer_kind_t::linear;
    std::vector<uint32_t> armed_tids;
    std::vector<dr_arm_result_t> arm_results;
};

struct plaintext_capture_t {
    uint64_t timestamp = 0;
    uint32_t tid = 0;
    std::string function_name;
    std::vector<uint8_t> buffer;
    uint64_t rip = 0;
    std::string module_name;
    uint64_t module_offset = 0;
};

struct auto_hook_process_report_t {
    uint32_t pid = 0;
    uint32_t parent_pid = 0;
    std::string process_name;
    bool root = false;
    bool alive = false;
    bool module_enum_ok = false;
    size_t module_count = 0;
    bool has_nss3 = false;
    bool has_pr_write = false;
    uint32_t resolved_count = 0;
    uint32_t hook_count = 0;
    int score = 0;
    bool selected = false;
    bool set_active_ok = false;
    DWORD win32_error = ERROR_SUCCESS;
    std::string driver_error;
    std::vector<std::string> module_hits;
    std::vector<std::string> resolved_targets;
    std::vector<std::string> resolve_misses;
};

struct state_t {
    std::vector<hook_target_t> targets;
    std::deque<plaintext_capture_t> captures;
    std::mutex mutex;
    std::atomic<bool> active{false};
    std::atomic<bool> polling{false};
    std::atomic<bool> debug_attached{false};
    std::atomic<bool> debug_loop_running{false};
    std::atomic<DWORD> debugger_error{0};
    std::atomic<DWORD> debug_loop_tid{0};
    size_t max_captures = 4096;
    uint32_t attached_pid = 0;
    std::vector<driver_bridge::module_info_t> cached_modules;
    uint32_t last_auto_hook_root_pid = 0;
    uint32_t last_auto_hook_selected_pid = 0;
    DWORD last_auto_hook_snapshot_error = ERROR_SUCCESS;
    std::string last_auto_hook_error;
    std::vector<auto_hook_process_report_t> last_auto_hook_candidates;
};

inline state_t g_state;

struct known_target_t {
    const char* module_pattern;
    const char* export_name;
    uint32_t buffer_reg;
    uint32_t size_reg;
    buffer_kind_t kind;
};

inline const known_target_t g_known_targets[] = {
    { "nss3",      "PR_Write",         1, 2, buffer_kind_t::linear },
    { "libssl",    "SSL_write",        1, 2, buffer_kind_t::linear },
    { "ssleay32",  "SSL_write",        1, 2, buffer_kind_t::linear },
    { "sspicli",   "EncryptMessage",   2, 0, buffer_kind_t::sec_buffer_desc },
    { "secur32",   "EncryptMessage",   2, 0, buffer_kind_t::sec_buffer_desc },
    { "ncrypt",    "SslEncryptPacket", 1, 2, buffer_kind_t::linear },
    { "ws2_32",    "send",             1, 2, buffer_kind_t::linear },
    { "ws2_32",    "WSASend",          1, 2, buffer_kind_t::wsabuf_array },
};

inline bool ci_contains(const std::string& haystack, const char* needle) {
    std::string lower_h = haystack;
    std::string lower_n = needle;
    std::transform(lower_h.begin(), lower_h.end(), lower_h.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    std::transform(lower_n.begin(), lower_n.end(), lower_n.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return lower_h.find(lower_n) != std::string::npos;
}

inline std::string wide_to_utf8_local(const wchar_t* text) {
    if (!text || !*text)
        return {};
    int needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text, -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 1)
        return {};
    std::string out(static_cast<size_t>(needed), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text, -1, out.data(), needed,
                            nullptr, nullptr) != needed)
        return {};
    out.resize(static_cast<size_t>(needed - 1));
    return out;
}

struct process_tree_entry_t {
    uint32_t pid = 0;
    uint32_t parent_pid = 0;
    std::string name;
};

inline bool pid_in_entries(const std::vector<process_tree_entry_t>& entries, uint32_t pid) {
    for (const auto& entry : entries) {
        if (entry.pid == pid)
            return true;
    }
    return false;
}

inline bool process_alive(uint32_t pid, DWORD& out_error) {
    out_error = ERROR_SUCCESS;
    if (pid == 0 || pid == 4) {
        out_error = ERROR_INVALID_PARAMETER;
        return false;
    }
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) {
        out_error = GetLastError();
        return false;
    }
    DWORD exit_code = 0;
    const BOOL got_exit = GetExitCodeProcess(process, &exit_code);
    out_error = got_exit ? ERROR_SUCCESS : GetLastError();
    CloseHandle(process);
    return got_exit && exit_code == STILL_ACTIVE;
}

inline std::vector<process_tree_entry_t> enumerate_process_tree(uint32_t root_pid, DWORD& snapshot_error) {
    snapshot_error = ERROR_SUCCESS;
    std::vector<process_tree_entry_t> result;
    if (root_pid == 0) {
        snapshot_error = ERROR_INVALID_PARAMETER;
        return result;
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        snapshot_error = GetLastError();
        result.push_back({root_pid, 0, {}});
        diag::log_tagged_fmt("pre_encrypt_hook",
            "process_tree_snapshot_failed root_pid=%u gle=%lu",
            root_pid,
            static_cast<unsigned long>(snapshot_error));
        return result;
    }

    std::vector<process_tree_entry_t> all;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snapshot, &pe)) {
        do {
            process_tree_entry_t entry;
            entry.pid = pe.th32ProcessID;
            entry.parent_pid = pe.th32ParentProcessID;
            entry.name = wide_to_utf8_local(pe.szExeFile);
            all.push_back(std::move(entry));
        } while (Process32NextW(snapshot, &pe));
    } else {
        snapshot_error = GetLastError();
        diag::log_tagged_fmt("pre_encrypt_hook",
            "process_tree_first_failed root_pid=%u gle=%lu",
            root_pid,
            static_cast<unsigned long>(snapshot_error));
    }
    CloseHandle(snapshot);

    for (const auto& entry : all) {
        if (entry.pid == root_pid) {
            result.push_back(entry);
            break;
        }
    }
    if (result.empty())
        result.push_back({root_pid, 0, {}});

    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto& entry : all) {
            if (entry.pid == 0 || pid_in_entries(result, entry.pid))
                continue;
            if (pid_in_entries(result, entry.parent_pid)) {
                result.push_back(entry);
                changed = true;
            }
        }
    }

    diag::log_tagged_fmt("pre_encrypt_hook",
        "process_tree_enumerated root_pid=%u count=%zu snapshot_error=%lu",
        root_pid,
        result.size(),
        static_cast<unsigned long>(snapshot_error));
    return result;
}

inline void reset_auto_hook_report(uint32_t root_pid, DWORD snapshot_error, const std::string& error) {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    g_state.last_auto_hook_root_pid = root_pid;
    g_state.last_auto_hook_selected_pid = 0;
    g_state.last_auto_hook_snapshot_error = snapshot_error;
    g_state.last_auto_hook_error = error;
    g_state.last_auto_hook_candidates.clear();
}

inline void store_auto_hook_report(uint32_t root_pid, uint32_t selected_pid, DWORD snapshot_error,
                                   const std::string& error,
                                   const std::vector<auto_hook_process_report_t>& reports) {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    g_state.last_auto_hook_root_pid = root_pid;
    g_state.last_auto_hook_selected_pid = selected_pid;
    g_state.last_auto_hook_snapshot_error = snapshot_error;
    g_state.last_auto_hook_error = error;
    g_state.last_auto_hook_candidates = reports;
}

inline uint64_t register_value(const driver_bridge::thread_context_t& ctx, uint32_t reg_index) {
    switch (reg_index) {
    case 0: return ctx.rcx;
    case 1: return ctx.rdx;
    case 2: return ctx.r8;
    case 3: return ctx.r9;
    default: return 0;
    }
}

inline uint64_t register_value(const CONTEXT& ctx, uint32_t reg_index) {
    switch (reg_index) {
    case 0: return ctx.Rcx;
    case 1: return ctx.Rdx;
    case 2: return ctx.R8;
    case 3: return ctx.R9;
    default: return 0;
    }
}

inline size_t bounded_capture_size(uint64_t requested_size) {
    constexpr size_t max_capture_bytes = 2048;
    if (requested_size == 0)
        return 0;
    if (requested_size > max_capture_bytes)
        return max_capture_bytes;
    return static_cast<size_t>(requested_size);
}

inline DWORD query_remote_protection(uint32_t pid, uint64_t address, size_t size, uint64_t& region_base, uint64_t& region_size, DWORD& state) {
    region_base = 0;
    region_size = 0;
    state = 0;
    if (pid == 0 || address == 0 || size == 0)
        return 0;
    driver_bridge::memory_region_t region{};
    if (!driver_bridge::query_memory_for(pid, address, region)) {
        diag::log_tagged_fmt("pre_encrypt_hook",
            "buffer_query_driver_failed pid=%u va=0x%llX size=%zu driver_status=%s driver_error=%s",
            pid,
            static_cast<unsigned long long>(address),
            size,
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        return 0;
    }
    region_base = region.base;
    region_size = region.size;
    state = region.state;
    return region.protect;
}

inline buffer_kind_t infer_kind_from_name(const std::string& name) {
    if (ci_contains(name, "WSASend"))
        return buffer_kind_t::wsabuf_array;
    if (ci_contains(name, "EncryptMessage"))
        return buffer_kind_t::sec_buffer_desc;
    return buffer_kind_t::linear;
}

inline void append_bounded(std::vector<uint8_t>& dst, const std::vector<uint8_t>& src) {
    constexpr size_t max_capture_bytes = 2048;
    if (dst.size() >= max_capture_bytes || src.empty())
        return;
    const size_t remaining = max_capture_bytes - dst.size();
    const size_t take = (std::min)(remaining, src.size());
    dst.insert(dst.end(), src.begin(), src.begin() + static_cast<ptrdiff_t>(take));
}

inline bool read_target_bytes(uint32_t pid, uint64_t address, size_t size, std::vector<uint8_t>& out) {
    out.clear();
    const size_t copy_size = bounded_capture_size(size);
    if (pid == 0 || address == 0 || copy_size == 0) {
        diag::log_tagged_fmt("pre_encrypt_hook",
            "read_target_bytes_skipped pid=%u va=0x%llX requested=%zu bounded=%zu",
            pid,
            static_cast<unsigned long long>(address),
            size,
            copy_size);
        return false;
    }
    uint64_t region_base = 0;
    uint64_t region_size = 0;
    DWORD state = 0;
    const DWORD protection = query_remote_protection(pid, address, copy_size, region_base, region_size, state);
    diag::log_tagged_fmt("pre_encrypt_hook",
        "read_target_bytes_begin pid=%u va=0x%llX requested=%zu bounded=%zu region_base=0x%llX region_size=%llu protection=0x%08lX state=0x%08lX",
        pid,
        static_cast<unsigned long long>(address),
        size,
        copy_size,
        static_cast<unsigned long long>(region_base),
        static_cast<unsigned long long>(region_size),
        protection,
        state);
    const bool ok = driver_bridge::read_memory_for(pid, address, copy_size, out);
    const std::string driver_error = driver_bridge::last_error();
    diag::log_tagged_fmt("pre_encrypt_hook",
        "read_target_bytes_end pid=%u va=0x%llX ok=%d captured_bytes=%zu requested=%zu bounded=%zu driver_error=%s",
        pid,
        static_cast<unsigned long long>(address),
        ok ? 1 : 0,
        out.size(),
        size,
        copy_size,
        driver_error.c_str());
    if (!ok || out.empty())
        return false;
    if (out.size() > copy_size)
        out.resize(copy_size);
    return true;
}

inline bool capture_linear(uint32_t pid, const driver_bridge::thread_context_t& ctx, const hook_target_t& target, std::vector<uint8_t>& out) {
    const uint64_t buffer_address = register_value(ctx, target.buffer_reg);
    const uint64_t requested_size = register_value(ctx, target.size_reg);
    return read_target_bytes(pid, buffer_address, bounded_capture_size(requested_size), out);
}

inline bool capture_wsabuf_array(uint32_t pid, const driver_bridge::thread_context_t& ctx, const hook_target_t& target, std::vector<uint8_t>& out) {
    struct remote_wsabuf_t {
        uint32_t len;
        uint32_t pad;
        uint64_t buf;
    };

    out.clear();
    const uint64_t array_address = register_value(ctx, target.buffer_reg);
    uint64_t count = register_value(ctx, target.size_reg);
    if (array_address == 0 || count == 0)
        return false;
    if (count > 16)
        count = 16;

    std::vector<uint8_t> raw;
    if (!driver_bridge::read_memory_for(pid, array_address, static_cast<size_t>(count) * sizeof(remote_wsabuf_t), raw))
        return false;
    if (raw.size() < sizeof(remote_wsabuf_t))
        return false;

    const size_t parsed = raw.size() / sizeof(remote_wsabuf_t);
    for (size_t i = 0; i < parsed; ++i) {
        remote_wsabuf_t entry{};
        std::memcpy(&entry, raw.data() + i * sizeof(remote_wsabuf_t), sizeof(entry));
        std::vector<uint8_t> chunk;
        if (read_target_bytes(pid, entry.buf, bounded_capture_size(entry.len), chunk))
            append_bounded(out, chunk);
    }
    return !out.empty();
}

inline bool capture_sec_buffer_desc(uint32_t pid, const driver_bridge::thread_context_t& ctx, const hook_target_t& target, std::vector<uint8_t>& out) {
    struct remote_sec_buffer_desc_t {
        uint32_t ulVersion;
        uint32_t cBuffers;
        uint64_t pBuffers;
    };
    struct remote_sec_buffer_t {
        uint32_t cbBuffer;
        uint32_t BufferType;
        uint64_t pvBuffer;
    };

    out.clear();
    const uint64_t desc_address = register_value(ctx, target.buffer_reg);
    if (desc_address == 0)
        return false;

    std::vector<uint8_t> desc_raw;
    if (!driver_bridge::read_memory_for(pid, desc_address, sizeof(remote_sec_buffer_desc_t), desc_raw) ||
        desc_raw.size() < sizeof(remote_sec_buffer_desc_t))
        return false;

    remote_sec_buffer_desc_t desc{};
    std::memcpy(&desc, desc_raw.data(), sizeof(desc));
    if (desc.cBuffers == 0 || desc.pBuffers == 0)
        return false;
    if (desc.cBuffers > 16)
        desc.cBuffers = 16;

    std::vector<uint8_t> buffers_raw;
    if (!driver_bridge::read_memory_for(pid, desc.pBuffers, static_cast<size_t>(desc.cBuffers) * sizeof(remote_sec_buffer_t), buffers_raw))
        return false;
    if (buffers_raw.size() < sizeof(remote_sec_buffer_t))
        return false;

    const size_t parsed = buffers_raw.size() / sizeof(remote_sec_buffer_t);
    for (size_t i = 0; i < parsed; ++i) {
        remote_sec_buffer_t entry{};
        std::memcpy(&entry, buffers_raw.data() + i * sizeof(remote_sec_buffer_t), sizeof(entry));
        if ((entry.BufferType & 0xFFFFu) != 1u)
            continue;
        std::vector<uint8_t> chunk;
        if (read_target_bytes(pid, entry.pvBuffer, bounded_capture_size(entry.cbBuffer), chunk))
            append_bounded(out, chunk);
    }
    return !out.empty();
}

inline bool capture_target_buffer(uint32_t pid, const driver_bridge::thread_context_t& ctx, const hook_target_t& target, std::vector<uint8_t>& out) {
    if (target.kind == buffer_kind_t::wsabuf_array)
        return capture_wsabuf_array(pid, ctx, target, out);
    if (target.kind == buffer_kind_t::sec_buffer_desc)
        return capture_sec_buffer_desc(pid, ctx, target, out);
    return capture_linear(pid, ctx, target, out);
}

inline std::string resolve_module_from_rip(uint64_t rip, uint64_t& offset_out) {
    offset_out = 0;
    for (const auto& mod : g_state.cached_modules) {
        if (rip >= mod.base && rip < mod.base + mod.size) {
            offset_out = rip - mod.base;
            return mod.name;
        }
    }
    return {};
}

inline void record_capture(uint32_t tid, const std::string& function_name,
                           std::vector<uint8_t>&& buffer, uint64_t rip) {
    if (buffer.empty())
        return;

    plaintext_capture_t cap;
    cap.timestamp = static_cast<uint64_t>(GetTickCount64());
    cap.tid = tid;
    cap.function_name = function_name;
    cap.buffer = std::move(buffer);
    cap.rip = rip;

    std::lock_guard<std::mutex> lock(g_state.mutex);
    uint64_t mod_offset = 0;
    cap.module_name = resolve_module_from_rip(cap.rip, mod_offset);
    cap.module_offset = mod_offset;
    g_state.captures.push_back(std::move(cap));

    while (g_state.captures.size() > g_state.max_captures)
        g_state.captures.pop_front();
    diag::log_tagged_fmt("pre_encrypt_hook",
        "record_capture tid=%u function=%s rip=0x%llX captured_bytes=%zu queue_count=%zu",
        tid,
        function_name.c_str(),
        static_cast<unsigned long long>(rip),
        g_state.captures.empty() ? 0 : g_state.captures.back().buffer.size(),
        g_state.captures.size());
}

inline std::vector<hook_target_t> targets_snapshot() {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    std::vector<hook_target_t> result;
    for (const auto& target : g_state.targets) {
        if (target.active)
            result.push_back(target);
    }
    return result;
}

inline void mark_thread_armed(uint64_t address, uint32_t tid) {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    for (auto& target : g_state.targets) {
        if (target.address != address)
            continue;
        if (std::find(target.armed_tids.begin(), target.armed_tids.end(), tid) == target.armed_tids.end())
            target.armed_tids.push_back(tid);
        return;
    }
}

inline void record_thread_arm_result(uint64_t address, uint32_t tid, uint32_t bp_index, bool ok, DWORD win32_error, const std::string& driver_error) {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    for (auto& target : g_state.targets) {
        if (target.address != address)
            continue;
        dr_arm_result_t result;
        result.timestamp = GetTickCount64();
        result.tid = tid;
        result.bp_index = bp_index;
        result.address = address;
        result.ok = ok;
        result.win32_error = ok ? ERROR_SUCCESS : win32_error;
        result.driver_error = driver_error;
        target.arm_results.push_back(std::move(result));
        if (target.arm_results.size() > 256)
            target.arm_results.erase(target.arm_results.begin(), target.arm_results.begin() + static_cast<std::ptrdiff_t>(target.arm_results.size() - 256));
        return;
    }
}

inline void remove_thread_armed(uint32_t tid) {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    for (auto& target : g_state.targets) {
        auto& tids = target.armed_tids;
        tids.erase(std::remove(tids.begin(), tids.end(), tid), tids.end());
    }
}

inline bool arm_breakpoints_for_thread(uint32_t tid) {
    if (tid == 0 || !driver_bridge::using_kernel_driver()) {
        diag::log_tagged_fmt("pre_encrypt_hook",
            "arm_thread_skipped tid=%u driver=%d",
            tid,
            driver_bridge::using_kernel_driver() ? 1 : 0);
        return false;
    }

    bool armed = false;
    auto targets = targets_snapshot();
    for (const auto& target : targets) {
        SetLastError(ERROR_SUCCESS);
        const bool ok = driver_bridge::set_hardware_breakpoint(tid, static_cast<int>(target.bp_index), target.address, 0, 0);
        const DWORD gle = GetLastError();
        const std::string driver_error = driver_bridge::last_error();
        record_thread_arm_result(target.address, tid, target.bp_index, ok, gle, driver_error);
        diag::log_tagged_fmt("pre_encrypt_hook",
            "arm_thread_dr_result tid=%u slot=%u address=0x%llX function=%s ok=%d gle=%lu driver_error=%s",
            tid,
            target.bp_index,
            static_cast<unsigned long long>(target.address),
            target.function_name.c_str(),
            ok ? 1 : 0,
            static_cast<unsigned long>(gle),
            driver_error.c_str());
        if (ok) {
            mark_thread_armed(target.address, tid);
            armed = true;
        }
    }
    return armed;
}

inline uint32_t target_pid_snapshot() {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    return g_state.attached_pid;
}

inline uint32_t arm_existing_threads() {
    const uint32_t pid = target_pid_snapshot();
    if (pid == 0)
        return 0;
    auto threads = driver_bridge::enumerate_threads_for(pid);
    diag::log_tagged_fmt("pre_encrypt_hook",
        "enumerate_threads pid=%u count=%zu driver_error=%s",
        pid,
        threads.size(),
        driver_bridge::last_error().c_str());
    uint32_t armed = 0;
    for (const auto& thread : threads) {
        const bool ok = arm_breakpoints_for_thread(thread.tid);
        diag::log_tagged_fmt("pre_encrypt_hook",
            "enumerate_threads_arm pid=%u tid=%u ok=%d",
            pid,
            thread.tid,
            ok ? 1 : 0);
        if (ok)
            ++armed;
    }
    diag::log_tagged_fmt("pre_encrypt_hook",
        "enumerate_threads_done pid=%u count=%zu armed=%u",
        pid,
        threads.size(),
        armed);
    return armed;
}

inline uint32_t clear_armed_breakpoints() {
    struct clear_request_t {
        uint32_t tid;
        uint32_t slot;
    };

    std::vector<clear_request_t> clear_requests;
    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        for (auto& target : g_state.targets) {
            for (uint32_t tid : target.armed_tids)
                clear_requests.push_back({tid, target.bp_index});
            target.armed_tids.clear();
        }
    }

    if (!driver_bridge::using_kernel_driver()) {
        diag::log_tagged_fmt("pre_encrypt_hook",
            "clear_armed_breakpoints skipped driver=0 requests=%zu",
            clear_requests.size());
        return 0;
    }

    uint32_t cleared = 0;
    for (const auto& req : clear_requests) {
        const bool ok = driver_bridge::clear_hardware_breakpoint(req.tid, static_cast<int>(req.slot));
        diag::log_tagged_fmt("pre_encrypt_hook",
            "clear_dr_result tid=%u slot=%u ok=%d driver_error=%s",
            req.tid,
            req.slot,
            ok ? 1 : 0,
            driver_bridge::last_error().c_str());
        if (ok)
            ++cleared;
    }
    diag::log_tagged_fmt("pre_encrypt_hook",
        "clear_armed_breakpoints done requests=%zu cleared=%u",
        clear_requests.size(),
        cleared);
    return cleared;
}

inline uint32_t armed_thread_count() {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    uint32_t count = 0;
    for (const auto& target : g_state.targets)
        count += static_cast<uint32_t>(target.armed_tids.size());
    return count;
}

inline uint64_t context_dr_address(const driver_bridge::thread_context_t& ctx, uint32_t slot) {
    switch (slot) {
    case 0: return ctx.dr0;
    case 1: return ctx.dr1;
    case 2: return ctx.dr2;
    case 3: return ctx.dr3;
    default: return 0;
    }
}

inline bool context_matches_target(const driver_bridge::thread_context_t& ctx, const hook_target_t& target) {
    if (target.bp_index > 3 || target.address == 0)
        return false;
    const uint64_t slot_address = context_dr_address(ctx, target.bp_index);
    const bool slot_matches = slot_address == target.address;
    const bool dr6_hit = (ctx.dr6 & (1ull << target.bp_index)) != 0;
    if (dr6_hit && slot_matches)
        return true;
    return slot_matches && ctx.rip == target.address;
}

inline bool find_target_for_context(const driver_bridge::thread_context_t& ctx, hook_target_t& out) {
    auto targets = targets_snapshot();
    for (const auto& target : targets) {
        if (context_matches_target(ctx, target)) {
            out = target;
            return true;
        }
    }
    return false;
}

inline bool capture_breakpoint_hit(uint32_t pid, uint32_t tid, const driver_bridge::thread_context_t& ctx) {
    hook_target_t target;
    if (!find_target_for_context(ctx, target)) {
        if ((ctx.dr6 & 0xFull) != 0)
            diag::log_tagged_fmt("pre_encrypt_hook",
                "breakpoint_hit_unmatched pid=%u tid=%u rip=0x%llX dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX",
                pid,
                tid,
                static_cast<unsigned long long>(ctx.rip),
                static_cast<unsigned long long>(ctx.dr0),
                static_cast<unsigned long long>(ctx.dr1),
                static_cast<unsigned long long>(ctx.dr2),
                static_cast<unsigned long long>(ctx.dr3),
                static_cast<unsigned long long>(ctx.dr6),
                static_cast<unsigned long long>(ctx.dr7));
        return false;
    }
    const uint64_t buffer_address = register_value(ctx, target.buffer_reg);
    const uint64_t requested_size = register_value(ctx, target.size_reg);
    diag::log_tagged_fmt("pre_encrypt_hook",
        "breakpoint_hit pid=%u tid=%u function=%s rip=0x%llX rcx=0x%llX rdx=0x%llX r8=0x%llX r9=0x%llX rsp=0x%llX dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX buffer_reg=%u size_reg=%u buffer_va=0x%llX requested_size=%llu",
        pid,
        tid,
        target.function_name.c_str(),
        static_cast<unsigned long long>(ctx.rip),
        static_cast<unsigned long long>(ctx.rcx),
        static_cast<unsigned long long>(ctx.rdx),
        static_cast<unsigned long long>(ctx.r8),
        static_cast<unsigned long long>(ctx.r9),
        static_cast<unsigned long long>(ctx.rsp),
        static_cast<unsigned long long>(ctx.dr0),
        static_cast<unsigned long long>(ctx.dr1),
        static_cast<unsigned long long>(ctx.dr2),
        static_cast<unsigned long long>(ctx.dr3),
        static_cast<unsigned long long>(ctx.dr6),
        static_cast<unsigned long long>(ctx.dr7),
        target.buffer_reg,
        target.size_reg,
        static_cast<unsigned long long>(buffer_address),
        static_cast<unsigned long long>(requested_size));

    std::vector<uint8_t> buffer;
    const bool captured = capture_target_buffer(pid, ctx, target, buffer);
    driver_bridge::thread_context_t next = ctx;
    next.rflags |= 0x10000ull;
    next.dr6 = 0;
    SetLastError(ERROR_SUCCESS);
    const bool set_ok = driver_bridge::set_thread_context(tid, next, (1ull << 17) | (1ull << 22));
    const DWORD gle = set_ok ? ERROR_SUCCESS : GetLastError();
    diag::log_tagged_fmt("pre_encrypt_hook",
        "breakpoint_hit_resume pid=%u tid=%u function=%s captured=%d captured_bytes=%zu set_context=%d gle=%lu",
        pid,
        tid,
        target.function_name.c_str(),
        captured ? 1 : 0,
        buffer.size(),
        set_ok ? 1 : 0,
        static_cast<unsigned long>(gle));
    if (captured)
        record_capture(tid, target.function_name, std::move(buffer), ctx.rip);
    return true;
}

inline std::vector<uint32_t> armed_threads_snapshot() {
    std::vector<uint32_t> tids;
    std::lock_guard<std::mutex> lock(g_state.mutex);
    for (const auto& target : g_state.targets) {
        for (uint32_t tid : target.armed_tids) {
            if (tid != 0 && std::find(tids.begin(), tids.end(), tid) == tids.end())
                tids.push_back(tid);
        }
    }
    return tids;
}

inline void poll_kernel_contexts(uint32_t pid) {
    for (uint32_t target_tid : armed_threads_snapshot()) {
        driver_bridge::thread_context_t ctx{};
        SetLastError(ERROR_SUCCESS);
        if (!driver_bridge::get_thread_context(target_tid, ctx)) {
            const DWORD gle = GetLastError();
            diag::log_tagged_fmt("pre_encrypt_hook",
                "kernel_context_poll_get_failed pid=%u tid=%u gle=%lu driver_error=%s",
                pid,
                target_tid,
                static_cast<unsigned long>(gle),
                driver_bridge::last_error().c_str());
            if (gle == ERROR_INVALID_PARAMETER || gle == ERROR_NOT_FOUND || gle == ERROR_INVALID_HANDLE)
                remove_thread_armed(target_tid);
            continue;
        }
        capture_breakpoint_hit(pid, target_tid, ctx);
    }
}

inline void kernel_context_loop() {
    const DWORD tid = GetCurrentThreadId();
    const ULONGLONG start_ms = GetTickCount64();
    g_state.debug_loop_tid.store(tid, std::memory_order_release);
    uint32_t pid = 0;
    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        pid = g_state.attached_pid;
    }
    diag::log_tagged_fmt("pre_encrypt_hook",
        "kernel_context_loop_enter pid=%u tid=%lu polling=%d attached=%d",
        pid,
        static_cast<unsigned long>(tid),
        g_state.polling.load() ? 1 : 0,
        g_state.debug_attached.load() ? 1 : 0);

    if (pid == 0 || !driver_bridge::using_kernel_driver()) {
        g_state.polling.store(false);
        g_state.debug_loop_running.store(false);
        g_state.active.store(false);
        g_state.debugger_error.store(ERROR_INVALID_PARAMETER);
        g_state.debug_loop_tid.store(0, std::memory_order_release);
        diag::log_tagged_fmt("pre_encrypt_hook",
            "kernel_context_loop_exit_invalid pid=%u tid=%lu elapsed_ms=%llu driver=%d",
            pid,
            static_cast<unsigned long>(tid),
            static_cast<unsigned long long>(GetTickCount64() - start_ms),
            driver_bridge::using_kernel_driver() ? 1 : 0);
        return;
    }

    g_state.debug_attached.store(true);
    g_state.debugger_error.store(0);
    const uint32_t initial_armed = arm_existing_threads();
    diag::log_tagged_fmt("pre_encrypt_hook",
        "kernel_context_loop_armed pid=%u tid=%lu initial_armed=%u",
        pid,
        static_cast<unsigned long>(tid),
        initial_armed);

    uint64_t poll_count = 0;
    while (g_state.polling.load()) {
        if (!driver_bridge::using_kernel_driver()) {
            g_state.debugger_error.store(ERROR_INVALID_HANDLE);
            g_state.active.store(false);
            g_state.polling.store(false);
            break;
        }
        if (targets_snapshot().empty()) {
            g_state.active.store(false);
            g_state.polling.store(false);
            break;
        }
        if ((poll_count % 20) == 0)
            arm_existing_threads();
        poll_kernel_contexts(pid);
        ++poll_count;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    const uint32_t cleared = clear_armed_breakpoints();
    g_state.debug_attached.store(false);
    g_state.polling.store(false);
    g_state.debug_loop_running.store(false);
    g_state.debug_loop_tid.store(0, std::memory_order_release);
    diag::log_tagged_fmt("pre_encrypt_hook",
        "kernel_context_loop_exit pid=%u tid=%lu elapsed_ms=%llu active=%d error=%lu polls=%llu cleared=%u",
        pid,
        static_cast<unsigned long>(tid),
        static_cast<unsigned long long>(GetTickCount64() - start_ms),
        g_state.active.load() ? 1 : 0,
        static_cast<unsigned long>(g_state.debugger_error.load()),
        static_cast<unsigned long long>(poll_count),
        cleared);
}

inline bool hook_address_with_kind(uint64_t address, const std::string& name,
                                   uint32_t buffer_reg, uint32_t size_reg,
                                   buffer_kind_t kind) {
    diag::log_tagged_fmt("pre_encrypt_hook",
        "hook_address_begin address=0x%llX name=%s buffer_reg=%u size_reg=%u driver=%d attached_pid=%u",
        static_cast<unsigned long long>(address),
        name.c_str(),
        buffer_reg,
        size_reg,
        driver_bridge::using_kernel_driver() ? 1 : 0,
        driver_bridge::attached_pid());
    if (!driver_bridge::using_kernel_driver())
        return false;

    if (address == 0 || buffer_reg > 3 || size_reg > 3) {
        diag::log_tagged_fmt("pre_encrypt_hook",
            "hook_address_rejected address=0x%llX buffer_reg=%u size_reg=%u",
            static_cast<unsigned long long>(address),
            buffer_reg,
            size_reg);
        return false;
    }

    uint32_t attached_pid = driver_bridge::attached_pid();
    if (attached_pid == 0) {
        diag::log_tagged_fmt("pre_encrypt_hook",
            "hook_address_rejected_no_attached address=0x%llX name=%s",
            static_cast<unsigned long long>(address),
            name.c_str());
        return false;
    }

    std::lock_guard<std::mutex> lock(g_state.mutex);
    if (g_state.attached_pid != 0 && g_state.attached_pid != attached_pid) {
        diag::log_tagged_fmt("pre_encrypt_hook",
            "hook_address_rejected_pid_mismatch state_pid=%u attached_pid=%u",
            g_state.attached_pid,
            attached_pid);
        return false;
    }

    uint32_t bp_slot = 0;
    bool found_slot = false;
    for (uint32_t i = 0; i < 4; ++i) {
        bool used = false;
        for (const auto& t : g_state.targets) {
            if (t.active && t.bp_index == i) {
                used = true;
                break;
            }
        }
        if (!used) {
            bp_slot = i;
            found_slot = true;
            break;
        }
    }
    if (!found_slot) {
        diag::log_tagged_fmt("pre_encrypt_hook",
            "hook_address_rejected_no_slot address=0x%llX active_targets=%zu",
            static_cast<unsigned long long>(address),
            g_state.targets.size());
        return false;
    }

    for (const auto& t : g_state.targets) {
        if (t.active && t.address == address) {
            diag::log_tagged_fmt("pre_encrypt_hook",
                "hook_address_existing address=0x%llX slot=%u name=%s",
                static_cast<unsigned long long>(address),
                t.bp_index,
                t.function_name.c_str());
            return true;
        }
    }

    hook_target_t target;
    target.library_name = {};
    target.function_name = name;
    target.address = address;
    target.buffer_reg = buffer_reg;
    target.size_reg = size_reg;
    target.active = true;
    target.bp_index = bp_slot;
    target.kind = kind;
    g_state.attached_pid = attached_pid;
    g_state.targets.push_back(std::move(target));
    g_state.active.store(true);
    diag::log_tagged_fmt("pre_encrypt_hook",
        "hook_address_done address=0x%llX name=%s pid=%u slot=%u hook_count=%zu",
        static_cast<unsigned long long>(address),
        name.c_str(),
        attached_pid,
        bp_slot,
        g_state.targets.size());

    return true;
}

inline bool hook_address(uint64_t address, const std::string& name,
                         uint32_t buffer_reg, uint32_t size_reg) {
    return hook_address_with_kind(address, name, buffer_reg, size_reg, infer_kind_from_name(name));
}

inline bool auto_hook(uint32_t pid) {
    diag::log_tagged_fmt("pre_encrypt_hook",
        "auto_hook_begin pid=%u driver=%d loaded=%d active=%d state_pid=%u attached_pid=%u",
        pid,
        driver_bridge::using_kernel_driver() ? 1 : 0,
        driver_bridge::is_loaded() ? 1 : 0,
        g_state.active.load() ? 1 : 0,
        target_pid_snapshot(),
        driver_bridge::attached_pid());

    if (!driver_bridge::using_kernel_driver()) {
        reset_auto_hook_report(pid, ERROR_SUCCESS, "kernel_driver_not_connected");
        return false;
    }
    if (!driver_bridge::is_loaded()) {
        reset_auto_hook_report(pid, ERROR_SUCCESS, "driver_bridge_not_loaded");
        return false;
    }

    DWORD snapshot_error = ERROR_SUCCESS;
    auto process_tree = enumerate_process_tree(pid, snapshot_error);
    std::vector<auto_hook_process_report_t> reports;
    reports.reserve(process_tree.size());

    auto score_for_target = [](const known_target_t& known) -> int {
        if (_stricmp(known.module_pattern, "nss3") == 0 && _stricmp(known.export_name, "PR_Write") == 0)
            return 120;
        if (ci_contains(known.module_pattern, "libssl") || ci_contains(known.module_pattern, "ssleay32"))
            return 70;
        if (ci_contains(known.module_pattern, "sspicli") || ci_contains(known.module_pattern, "secur32"))
            return 45;
        if (ci_contains(known.module_pattern, "ncrypt"))
            return 35;
        if (ci_contains(known.module_pattern, "ws2_32"))
            return 10;
        return 1;
    };

    for (const auto& proc : process_tree) {
        auto_hook_process_report_t report;
        report.pid = proc.pid;
        report.parent_pid = proc.parent_pid;
        report.process_name = proc.name;
        report.root = proc.pid == pid;
        DWORD alive_error = ERROR_SUCCESS;
        report.alive = process_alive(proc.pid, alive_error);
        report.win32_error = alive_error;
        if (!report.alive) {
            diag::log_tagged_fmt("pre_encrypt_hook",
                "auto_hook_candidate_dead pid=%u parent=%u name=%s gle=%lu",
                report.pid,
                report.parent_pid,
                report.process_name.c_str(),
                static_cast<unsigned long>(alive_error));
            reports.push_back(std::move(report));
            continue;
        }

        auto modules = driver_bridge::enumerate_modules_for(proc.pid);
        report.module_count = modules.size();
        report.module_enum_ok = !modules.empty();
        report.driver_error = driver_bridge::last_error();
        diag::log_tagged_fmt("pre_encrypt_hook",
            "auto_hook_candidate_modules pid=%u parent=%u name=%s count=%zu driver_error=%s",
            report.pid,
            report.parent_pid,
            report.process_name.c_str(),
            modules.size(),
            report.driver_error.c_str());

        for (const auto& mod : modules) {
            if (ci_contains(mod.name, "nss3"))
                report.has_nss3 = true;
            for (const auto& known : g_known_targets) {
                if (!ci_contains(mod.name, known.module_pattern))
                    continue;

                std::string target_name = mod.name + "!" + known.export_name;
                report.module_hits.push_back(target_name);
                uint64_t func_addr = driver_bridge::resolve_export_for(proc.pid, mod.base, known.export_name);
                if (func_addr == 0) {
                    report.resolve_misses.push_back(target_name);
                    diag::log_tagged_fmt("pre_encrypt_hook",
                        "auto_hook_candidate_resolve_miss pid=%u module=%s export=%s base=0x%llX driver_error=%s",
                        proc.pid,
                        mod.name.c_str(),
                        known.export_name,
                        static_cast<unsigned long long>(mod.base),
                        driver_bridge::last_error().c_str());
                    continue;
                }

                char resolved[128] = {};
                std::snprintf(resolved, sizeof(resolved), "%s@0x%llX", target_name.c_str(), static_cast<unsigned long long>(func_addr));
                report.resolved_targets.push_back(resolved);
                ++report.resolved_count;
                report.score += score_for_target(known);
                if (_stricmp(known.module_pattern, "nss3") == 0 && _stricmp(known.export_name, "PR_Write") == 0)
                    report.has_pr_write = true;
            }
        }
        if (!report.root && report.resolved_count != 0)
            report.score += 8;
        reports.push_back(std::move(report));
    }

    int best_score = -1;
    size_t best_index = static_cast<size_t>(-1);
    for (size_t i = 0; i < reports.size(); ++i) {
        if (!reports[i].alive || reports[i].resolved_count == 0)
            continue;
        if (reports[i].score > best_score) {
            best_score = reports[i].score;
            best_index = i;
        }
    }

    if (best_index == static_cast<size_t>(-1)) {
        store_auto_hook_report(pid, 0, snapshot_error, "no_supported_pre_encrypt_exports_resolved", reports);
        diag::log_tagged_fmt("pre_encrypt_hook",
            "auto_hook_no_candidate pid=%u candidates=%zu snapshot_error=%lu",
            pid,
            reports.size(),
            static_cast<unsigned long>(snapshot_error));
        return false;
    }

    const uint32_t selected_pid = reports[best_index].pid;
    reports[best_index].selected = true;

    uint32_t active_hook_pid = 0;
    if (g_state.active.load()) {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        active_hook_pid = g_state.attached_pid;
    }
    if (active_hook_pid != 0 && active_hook_pid != selected_pid) {
        store_auto_hook_report(pid, selected_pid, snapshot_error, "selected_child_differs_from_active_hook_pid", reports);
        return false;
    }

    bool already_attached = driver_bridge::attached_pid() == selected_pid;
    if (!already_attached) {
        const auto attached = driver_bridge::attached_pids();
        for (uint32_t attached_pid : attached) {
            if (attached_pid == selected_pid) {
                already_attached = true;
                break;
            }
        }
    }

    bool active_ok = false;
    if (already_attached) {
        active_ok = driver_bridge::set_active_pid(selected_pid);
    } else if (driver_bridge::attached_pid() == 0) {
        active_ok = driver_bridge::attach(selected_pid);
    } else if (driver_bridge::attach_additional(selected_pid)) {
        active_ok = driver_bridge::set_active_pid(selected_pid);
    }

    reports[best_index].set_active_ok = active_ok;
    reports[best_index].driver_error = driver_bridge::last_error();
    if (!active_ok) {
        store_auto_hook_report(pid, selected_pid, snapshot_error, "set_active_selected_pid_failed", reports);
        diag::log_tagged_fmt("pre_encrypt_hook",
            "auto_hook_set_active_failed root_pid=%u selected_pid=%u driver_error=%s",
            pid,
            selected_pid,
            driver_bridge::last_error().c_str());
        return false;
    }

    auto modules = driver_bridge::enumerate_modules();
    diag::log_tagged_fmt("pre_encrypt_hook",
        "auto_hook_selected_modules root_pid=%u selected_pid=%u count=%zu driver_error=%s",
        pid,
        selected_pid,
        modules.size(),
        driver_bridge::last_error().c_str());
    if (modules.empty()) {
        store_auto_hook_report(pid, selected_pid, snapshot_error, "selected_pid_module_enumeration_empty", reports);
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        g_state.cached_modules = modules;
        g_state.attached_pid = selected_pid;
    }

    uint32_t hooked = 0;
    constexpr uint32_t max_hooks = 4;

    for (const auto& known : g_known_targets) {
        if (hooked >= max_hooks)
            break;

        for (const auto& mod : modules) {
            if (hooked >= max_hooks)
                break;

            if (!ci_contains(mod.name, known.module_pattern))
                continue;

            uint64_t func_addr = driver_bridge::resolve_export(mod.base, known.export_name);
            if (func_addr == 0) {
                diag::log_tagged_fmt("pre_encrypt_hook",
                    "auto_hook_resolve_miss pid=%u module=%s export=%s base=0x%llX driver_error=%s",
                    selected_pid,
                    mod.name.c_str(),
                    known.export_name,
                    static_cast<unsigned long long>(mod.base),
                    driver_bridge::last_error().c_str());
                continue;
            }

            std::string hook_name = mod.name + "!" + known.export_name;
            const bool ok = hook_address_with_kind(func_addr, hook_name, known.buffer_reg, known.size_reg, known.kind);
            diag::log_tagged_fmt("pre_encrypt_hook",
                "auto_hook_target root_pid=%u selected_pid=%u module=%s export=%s address=0x%llX ok=%d hooked_before=%u",
                pid,
                selected_pid,
                mod.name.c_str(),
                known.export_name,
                static_cast<unsigned long long>(func_addr),
                ok ? 1 : 0,
                hooked);
            if (ok)
                ++hooked;
        }
    }

    reports[best_index].hook_count = hooked;
    store_auto_hook_report(pid, selected_pid, snapshot_error, hooked > 0 ? std::string() : "hook_installation_failed", reports);
    diag::log_tagged_fmt("pre_encrypt_hook",
        "auto_hook_done root_pid=%u selected_pid=%u candidates=%zu hooked=%u selected_score=%d has_pr_write=%d",
        pid,
        selected_pid,
        reports.size(),
        hooked,
        reports[best_index].score,
        reports[best_index].has_pr_write ? 1 : 0);
    return hooked > 0;
}

inline uint32_t unhook_all() {
    g_state.polling.store(false);
    const ULONGLONG wait_start = GetTickCount64();
    for (int i = 0; i < 120 && g_state.debug_loop_running.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    if (g_state.debug_loop_running.load()) {
        diag::log_tagged_fmt("pre_encrypt_hook", "kernel_context_loop_join_timeout pid=%u attached=%d running=%d error=%lu",
            g_state.attached_pid,
            g_state.debug_attached.load() ? 1 : 0,
            g_state.debug_loop_running.load() ? 1 : 0,
            static_cast<unsigned long>(g_state.debugger_error.load()));
    }
    diag::log_tagged_fmt("pre_encrypt_hook",
        "unhook_wait_complete running=%d attached=%d waited_ms=%llu",
        g_state.debug_loop_running.load() ? 1 : 0,
        g_state.debug_attached.load() ? 1 : 0,
        static_cast<unsigned long long>(GetTickCount64() - wait_start));
    const uint32_t cleared = clear_armed_breakpoints();

    std::lock_guard<std::mutex> lock(g_state.mutex);

    const uint32_t removed = static_cast<uint32_t>(g_state.targets.size());
    for (auto& t : g_state.targets)
        t.active = false;
    g_state.targets.clear();
    g_state.active.store(false);
    g_state.attached_pid = 0;
    if (!g_state.polling.load() && !g_state.debug_attached.load())
        g_state.debug_loop_running.store(false);
    diag::log_tagged_fmt("pre_encrypt_hook",
        "unhook_all_done removed=%u cleared_breakpoints=%u captures=%zu",
        removed,
        cleared,
        g_state.captures.size());
    return removed;
}

inline bool start_polling() {
    if (!g_state.active.load())
        return false;

    if (g_state.debug_loop_running.load() && !g_state.debug_attached.load() && !g_state.polling.load())
        g_state.debug_loop_running.store(false);

    if (g_state.debug_loop_running.exchange(true)) {
        if (g_state.debug_attached.load())
            arm_existing_threads();
        return g_state.debug_attached.load();
    }

    g_state.polling.store(true);

    bool posted = false;
    try {
        aida::infra::executor::submission_t sub;
        sub.owner_subsystem = "pre_encrypt_hook";
        sub.label = "pre_encrypt_hook.kernel_context_loop";
        sub.thread_class = "long_lived_service";
        sub.domain = aida::infra::executor::domain_t::service;
        sub.priority = 3;
        sub.body = []() { kernel_context_loop(); };
        posted = aida::infra::executor::submit(std::move(sub)).submitted;
    } catch (...) {
        posted = false;
    }
    if (!posted) {
        const auto qs = aida::infra::taskflow_runtime::active_snapshot();
        diag::log_tagged_fmt("pre_encrypt_hook",
            "kernel_context_loop_post_failed runtime_accepting=%d runtime_shutdown=%d service_pending=%llu service_active=%u total_submitted=%llu total_rejected=%llu",
            qs.accepting ? 1 : 0,
            qs.shutting_down ? 1 : 0,
            static_cast<unsigned long long>(qs.service_queue_pending),
            static_cast<unsigned>(qs.service_queue_active),
            static_cast<unsigned long long>(qs.total_submitted),
            static_cast<unsigned long long>(qs.total_rejected));
        g_state.polling.store(false);
        g_state.debug_loop_running.store(false);
        g_state.debugger_error.store(ERROR_NOT_ENOUGH_MEMORY);
        return false;
    }
    const auto qs = aida::infra::taskflow_runtime::active_snapshot();
    diag::log_tagged_fmt("pre_encrypt_hook",
        "kernel_context_loop_posted runtime_accepting=%d runtime_shutdown=%d service_pending=%llu service_active=%u total_submitted=%llu total_failed=%llu",
        qs.accepting ? 1 : 0,
        qs.shutting_down ? 1 : 0,
        static_cast<unsigned long long>(qs.service_queue_pending),
        static_cast<unsigned>(qs.service_queue_active),
        static_cast<unsigned long long>(qs.total_submitted),
        static_cast<unsigned long long>(qs.total_failed));

    for (int i = 0; i < 40; ++i) {
        if (g_state.debug_attached.load())
            return true;
        if (!g_state.debug_loop_running.load())
            return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }

    return g_state.debug_attached.load();
}

inline void stop_polling() {
    g_state.polling.store(false);
}

inline std::vector<plaintext_capture_t> get_captures(size_t max_count = 64) {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    std::vector<plaintext_capture_t> result;

    size_t count = (std::min)(max_count, g_state.captures.size());
    auto it = g_state.captures.end();
    if (count <= g_state.captures.size())
        it = g_state.captures.end() - static_cast<ptrdiff_t>(count);
    else
        it = g_state.captures.begin();

    for (; it != g_state.captures.end(); ++it)
        result.push_back(*it);

    return result;
}

inline size_t clear_captures() {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    const size_t cleared = g_state.captures.size();
    g_state.captures.clear();
    diag::log_tagged_fmt("pre_encrypt_hook",
        "clear_captures cleared=%zu hook_count=%zu",
        cleared,
        g_state.targets.size());
    return cleared;
}

inline bool is_active() {
    return g_state.active.load();
}

}
