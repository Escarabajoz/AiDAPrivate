#include "re_common.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <limits>
#include <memory>
#include <sstream>
#include <system_error>

#include <shlobj.h>

#include "../../helpers/diag_log.hpp"

namespace re
{
namespace
{
struct process_handle_closer_t
{
    void operator()(void* value) const noexcept
    {
        if (value)
            CloseHandle(static_cast<HANDLE>(value));
    }
};

using unique_process_handle_t = std::unique_ptr<void, process_handle_closer_t>;

bool is_self_pid(std::uint32_t pid)
{
    return pid != 0 && pid == static_cast<std::uint32_t>(GetCurrentProcessId());
}

bool parse_hex_byte(const std::string& token, std::uint8_t& out)
{
    if (token.size() != 2)
        return false;
    auto hex_value = [](char ch) -> int {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'a' && ch <= 'f') return 10 + ch - 'a';
        if (ch >= 'A' && ch <= 'F') return 10 + ch - 'A';
        return -1;
    };
    int hi = hex_value(token[0]);
    int lo = hex_value(token[1]);
    if (hi < 0 || lo < 0)
        return false;
    out = static_cast<std::uint8_t>((hi << 4) | lo);
    return true;
}

std::uint32_t normalized_protect(std::uint32_t protect)
{
    return protect & 0xFFu;
}
}

active_process_scope_t::active_process_scope_t(const json& params)
{
    std::uint32_t requested = 0;
    parse_pid_param(params, requested);
    enter(requested);
}

active_process_scope_t::active_process_scope_t(std::uint32_t requested_pid)
{
    enter(requested_pid);
}

active_process_scope_t::~active_process_scope_t()
{
    if (!switched_)
        return;
    if (driver_bridge::attached_pid() != active_pid_)
        return;
    if (previous_pid_ != 0)
        driver_bridge::set_active_pid(previous_pid_);
    else
        driver_bridge::clear_active_pid();
}

bool active_process_scope_t::ok() const noexcept
{
    return ok_;
}

std::uint32_t active_process_scope_t::pid() const noexcept
{
    return active_pid_;
}

const std::string& active_process_scope_t::error() const noexcept
{
    return error_;
}

void active_process_scope_t::enter(std::uint32_t requested_pid)
{
    const std::uint64_t enter_started_ms = GetTickCount64();
    previous_pid_ = driver_bridge::attached_pid();
    if (!driver_bridge::is_loaded())
    {
        error_ = "Driver bridge is not connected. Attach with sessions_manage action=attach_pid first.";
        diag::log_tagged_fmt("re",
                             "active_scope_enter pid=0 requested=%u previous=%u attached_count=%zu switched=0 ok=0 elapsed_ms=%llu reason=driver_not_loaded",
                             requested_pid,
                             previous_pid_,
                             driver_bridge::attached_pids().size(),
                             static_cast<unsigned long long>(GetTickCount64() - enter_started_ms));
        return;
    }

    if (requested_pid != 0 && is_self_pid(requested_pid))
    {
        error_ = "Cannot target AiDA's own process.";
        diag::log_tagged_fmt("re",
                             "active_scope_enter pid=0 requested=%u previous=%u caller_pid=%lu caller_tid=%lu attached_count=%zu switched=0 ok=0 elapsed_ms=%llu reason=self_pid_rejected",
                             requested_pid,
                             previous_pid_,
                             static_cast<unsigned long>(GetCurrentProcessId()),
                             static_cast<unsigned long>(GetCurrentThreadId()),
                             driver_bridge::attached_pids().size(),
                             static_cast<unsigned long long>(GetTickCount64() - enter_started_ms));
        return;
    }

    if (requested_pid != 0 && !process_alive(requested_pid))
    {
        const DWORD process_alive_gle = GetLastError();
        error_ = "target_pid " + std::to_string(requested_pid) + " is not alive.";
        diag::log_tagged_fmt("re",
                             "active_scope_enter pid=0 requested=%u previous=%u caller_pid=%lu caller_tid=%lu attached_count=%zu switched=0 ok=0 elapsed_ms=%llu gle=%lu reason=target_not_alive",
                             requested_pid,
                             previous_pid_,
                             static_cast<unsigned long>(GetCurrentProcessId()),
                             static_cast<unsigned long>(GetCurrentThreadId()),
                             driver_bridge::attached_pids().size(),
                             static_cast<unsigned long long>(GetTickCount64() - enter_started_ms),
                             static_cast<unsigned long>(process_alive_gle));
        return;
    }

    if (requested_pid != 0 && requested_pid != previous_pid_)
    {
        const auto attached = driver_bridge::attached_pids();
        bool already_attached = false;
        for (auto pid : attached)
        {
            if (pid == requested_pid)
            {
                already_attached = true;
                break;
            }
        }
        if (!already_attached && !driver_bridge::attach_additional(requested_pid))
        {
            const DWORD attach_gle = GetLastError();
            error_ = "attach_additional failed for target_pid " + std::to_string(requested_pid) + ": " + driver_bridge::last_error();
            diag::log_tagged_fmt("re",
                                 "active_scope_enter pid=0 requested=%u previous=%u caller_pid=%lu caller_tid=%lu attached_count=%zu already_attached=%d switched=0 ok=0 elapsed_ms=%llu gle=%lu last_error=%s reason=attach_additional_failed",
                                 requested_pid,
                                 previous_pid_,
                                 static_cast<unsigned long>(GetCurrentProcessId()),
                                 static_cast<unsigned long>(GetCurrentThreadId()),
                                 attached.size(),
                                 already_attached ? 1 : 0,
                                 static_cast<unsigned long long>(GetTickCount64() - enter_started_ms),
                                 static_cast<unsigned long>(attach_gle),
                                 driver_bridge::last_error().c_str());
            return;
        }
        if (!driver_bridge::set_active_pid(requested_pid))
        {
            const DWORD set_active_gle = GetLastError();
            error_ = "set_active_pid failed for target_pid " + std::to_string(requested_pid) + ": " + driver_bridge::last_error();
            diag::log_tagged_fmt("re",
                                 "active_scope_enter pid=0 requested=%u previous=%u caller_pid=%lu caller_tid=%lu attached_count=%zu already_attached=%d switched=0 ok=0 elapsed_ms=%llu gle=%lu last_error=%s reason=set_active_pid_failed",
                                 requested_pid,
                                 previous_pid_,
                                 static_cast<unsigned long>(GetCurrentProcessId()),
                                 static_cast<unsigned long>(GetCurrentThreadId()),
                                 attached.size(),
                                 already_attached ? 1 : 0,
                                 static_cast<unsigned long long>(GetTickCount64() - enter_started_ms),
                                 static_cast<unsigned long>(set_active_gle),
                                 driver_bridge::last_error().c_str());
            return;
        }
        switched_ = true;
    }

    active_pid_ = requested_pid != 0 ? requested_pid : driver_bridge::attached_pid();
    if (active_pid_ == 0)
    {
        error_ = "Not attached. Use sessions_manage action=attach_pid or pass process_id.";
        diag::log_tagged_fmt("re",
                             "active_scope_enter pid=0 requested=%u previous=%u caller_pid=%lu caller_tid=%lu attached_count=%zu switched=%d ok=0 elapsed_ms=%llu reason=not_attached",
                             requested_pid,
                             previous_pid_,
                             static_cast<unsigned long>(GetCurrentProcessId()),
                             static_cast<unsigned long>(GetCurrentThreadId()),
                             driver_bridge::attached_pids().size(),
                             switched_ ? 1 : 0,
                             static_cast<unsigned long long>(GetTickCount64() - enter_started_ms));
        return;
    }
    if (!process_alive(active_pid_))
    {
        error_ = "Attached process PID " + std::to_string(active_pid_) + " is no longer alive.";
        diag::log_tagged_fmt("re",
                             "active_scope_enter pid=%u requested=%u previous=%u attached_count=%zu switched=%d ok=0 elapsed_ms=%llu reason=process_not_alive",
                             active_pid_,
                             requested_pid,
                             previous_pid_,
                             driver_bridge::attached_pids().size(),
                             switched_ ? 1 : 0,
                             static_cast<unsigned long long>(GetTickCount64() - enter_started_ms));
        return;
    }
    ok_ = true;
    diag::log_tagged_fmt("re",
                         "active_scope_enter pid=%u requested=%u previous=%u attached_count=%zu switched=%d ok=1 elapsed_ms=%llu",
                         active_pid_,
                         requested_pid,
                         previous_pid_,
                         driver_bridge::attached_pids().size(),
                         switched_ ? 1 : 0,
                         static_cast<unsigned long long>(GetTickCount64() - enter_started_ms));
}

std::string lower_ascii(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::string trim_ascii(std::string value)
{
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos)
        return {};
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

bool process_alive(std::uint32_t pid)
{
    if (pid == 0)
        return false;
    unique_process_handle_t process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!process)
        return false;
    DWORD exit_code = 0;
    const bool ok = GetExitCodeProcess(static_cast<HANDLE>(process.get()), &exit_code) != FALSE;
    return ok && exit_code == STILL_ACTIVE;
}

bool parse_u64_value(const json& value, std::uint64_t& out)
{
    if (value.is_number_unsigned())
    {
        out = value.get<std::uint64_t>();
        return true;
    }
    if (value.is_number_integer())
    {
        const auto signed_value = value.get<std::int64_t>();
        if (signed_value < 0)
            return false;
        out = static_cast<std::uint64_t>(signed_value);
        return true;
    }
    if (value.is_string())
    {
        const auto parsed = sa_parse_address(trim_ascii(value.get<std::string>()));
        if (!parsed)
            return false;
        out = *parsed;
        return true;
    }
    return false;
}

bool parse_u32_value(const json& value, std::uint32_t& out)
{
    std::uint64_t wide = 0;
    if (!parse_u64_value(value, wide) || wide > 0xFFFFFFFFULL)
        return false;
    out = static_cast<std::uint32_t>(wide);
    return true;
}

bool parse_address_param(const json& params, const char* key, std::uint64_t& out)
{
    if (!params.contains(key))
        return false;
    return parse_u64_value(params[key], out);
}

bool parse_pid_param(const json& params, std::uint32_t& out)
{
    for (const char* key : {"target_pid", "process_id", "pid"})
    {
        if (!params.contains(key))
            continue;
        if (!parse_u32_value(params[key], out))
            return false;
        if (out != 0)
            return true;
    }
    out = 0;
    return false;
}

std::uint64_t numeric_param(const json& params, const char* key, std::uint64_t fallback, std::uint64_t min_value, std::uint64_t max_value)
{
    std::uint64_t value = fallback;
    if (params.contains(key))
        parse_u64_value(params[key], value);
    if (value < min_value)
        value = min_value;
    if (value > max_value)
        value = max_value;
    return value;
}

double number_param(const json& params, const char* key, double fallback, double min_value, double max_value)
{
    double value = fallback;
    if (params.contains(key) && params[key].is_number())
        value = params[key].get<double>();
    if (value < min_value)
        value = min_value;
    if (value > max_value)
        value = max_value;
    return value;
}

bool bool_param(const json& params, const char* key, bool fallback)
{
    if (!params.contains(key) || !params[key].is_boolean())
        return fallback;
    return params[key].get<bool>();
}

std::string string_param(const json& params, const char* key, const std::string& fallback)
{
    if (!params.contains(key) || !params[key].is_string())
        return fallback;
    return params[key].get<std::string>();
}

bool unsafe_confirmed(const json& params)
{
    return bool_param(params, "confirm_unsafe", false) ||
           bool_param(params, "allow_unsafe", false) ||
           bool_param(params, "unsafe", false);
}

tool_result_t unsafe_required(const char* operation)
{
    return tool_result_t::error(std::string(operation ? operation : "operation") +
        " mutates target state. Re-run with confirm_unsafe=true or allow_unsafe=true.");
}

bool is_committed(const driver_bridge::memory_region_t& region)
{
    return (region.state & MEM_COMMIT) != 0;
}

bool is_guarded(const driver_bridge::memory_region_t& region)
{
    return (region.protect & PAGE_GUARD) != 0;
}

bool is_readable(const driver_bridge::memory_region_t& region)
{
    if (!is_committed(region) || is_guarded(region))
        return false;
    const std::uint32_t p = normalized_protect(region.protect);
    return p == PAGE_READONLY || p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
           p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
}

bool is_writable(const driver_bridge::memory_region_t& region)
{
    if (!is_committed(region) || is_guarded(region))
        return false;
    const std::uint32_t p = normalized_protect(region.protect);
    return p == PAGE_READWRITE || p == PAGE_WRITECOPY || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
}

bool is_executable(const driver_bridge::memory_region_t& region)
{
    if (!is_committed(region) || is_guarded(region))
        return false;
    const std::uint32_t p = normalized_protect(region.protect);
    return p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
}

std::vector<driver_bridge::module_info_t> modules_for(std::uint32_t pid)
{
    return pid != 0 ? driver_bridge::enumerate_modules_for(pid) : driver_bridge::enumerate_modules();
}

std::vector<driver_bridge::memory_region_t> regions_for(std::uint32_t pid, std::size_t max_regions)
{
    return pid != 0 ? driver_bridge::enumerate_memory_regions_for(pid, max_regions) : driver_bridge::enumerate_memory_regions(max_regions);
}

std::vector<driver_bridge::thread_info_t> threads_for(std::uint32_t pid)
{
    return pid != 0 ? driver_bridge::enumerate_threads_for(pid) : driver_bridge::enumerate_threads();
}

std::optional<driver_bridge::module_info_t> find_module_by_name(std::uint32_t pid, const std::string& name)
{
    const std::string wanted = lower_ascii(name);
    for (const auto& module : modules_for(pid))
    {
        if (lower_ascii(module.name) == wanted)
            return module;
        if (!module.path.empty())
        {
            std::filesystem::path p(module.path);
            if (lower_ascii(p.filename().string()) == wanted)
                return module;
        }
    }
    return std::nullopt;
}

std::optional<driver_bridge::module_info_t> find_module_for_address(std::uint32_t pid, std::uint64_t address)
{
    for (const auto& module : modules_for(pid))
    {
        const std::uint64_t end = module.base + static_cast<std::uint64_t>(module.size);
        if (module.base != 0 && address >= module.base && address < end)
            return module;
    }
    return std::nullopt;
}

bool query_region(std::uint32_t pid, std::uint64_t address, driver_bridge::memory_region_t& out)
{
    return pid != 0 ? driver_bridge::query_memory_for(pid, address, out) : driver_bridge::query_memory(address, out);
}

bool read_bytes(std::uint32_t pid, std::uint64_t address, std::size_t size, std::vector<std::uint8_t>& out)
{
    out.clear();
    if (address == 0 || size == 0)
        return false;
    constexpr std::size_t max_read = 64u * 1024u * 1024u;
    if (size > max_read)
        size = max_read;
    return pid != 0 ? driver_bridge::read_memory_for(pid, address, size, out) : driver_bridge::read_memory(address, size, out);
}

bool write_bytes(std::uint32_t pid, std::uint64_t address, const std::vector<std::uint8_t>& data)
{
    if (address == 0 || data.empty())
        return false;
    return pid != 0 ? driver_bridge::write_memory_for(pid, address, data) : driver_bridge::write_memory(address, data);
}

bool read_u64(std::uint32_t pid, std::uint64_t address, std::uint64_t& out)
{
    std::vector<std::uint8_t> bytes;
    if (!read_bytes(pid, address, sizeof(out), bytes) || bytes.size() < sizeof(out))
        return false;
    std::memcpy(&out, bytes.data(), sizeof(out));
    return true;
}

bool read_u32(std::uint32_t pid, std::uint64_t address, std::uint32_t& out)
{
    std::vector<std::uint8_t> bytes;
    if (!read_bytes(pid, address, sizeof(out), bytes) || bytes.size() < sizeof(out))
        return false;
    std::memcpy(&out, bytes.data(), sizeof(out));
    return true;
}

bool read_u16(std::uint32_t pid, std::uint64_t address, std::uint16_t& out)
{
    std::vector<std::uint8_t> bytes;
    if (!read_bytes(pid, address, sizeof(out), bytes) || bytes.size() < sizeof(out))
        return false;
    std::memcpy(&out, bytes.data(), sizeof(out));
    return true;
}

bool write_u64(std::uint32_t pid, std::uint64_t address, std::uint64_t value)
{
    std::vector<std::uint8_t> bytes(sizeof(value));
    std::memcpy(bytes.data(), &value, sizeof(value));
    return write_bytes(pid, address, bytes);
}

std::uint64_t allocate_remote(std::uint32_t pid, std::size_t size)
{
    active_process_scope_t scope(pid);
    if (!scope.ok())
        return 0;
    return driver_bridge::allocate_memory(size);
}

bool free_remote(std::uint32_t pid, std::uint64_t address)
{
    active_process_scope_t scope(pid);
    if (!scope.ok())
        return false;
    return driver_bridge::free_memory(address);
}

bool protect_remote(std::uint32_t pid, std::uint64_t address, std::uint64_t size, std::uint32_t protect, std::uint32_t* old_protect)
{
    if (pid != 0)
        return driver_bridge::protect_memory_for(pid, address, size, protect, old_protect);
    return driver_bridge::protect_memory(address, size, protect, old_protect);
}

std::string bytes_to_hex(const std::vector<std::uint8_t>& data, std::size_t max_bytes)
{
    const std::size_t n = std::min(data.size(), max_bytes);
    std::string out;
    out.reserve(n * 3);
    char buf[4] = {};
    for (std::size_t i = 0; i < n; ++i)
    {
        if (i)
            out.push_back(' ');
        std::snprintf(buf, sizeof(buf), "%02X", static_cast<unsigned>(data[i]));
        out.append(buf, 2);
    }
    return out;
}

std::vector<std::uint8_t> u64_to_le(std::uint64_t value)
{
    std::vector<std::uint8_t> out(sizeof(value));
    std::memcpy(out.data(), &value, sizeof(value));
    return out;
}

bool parse_pattern(const std::string& text, std::vector<parsed_pattern_byte_t>& out, std::string* error)
{
    out.clear();
    std::string compact;
    compact.reserve(text.size());
    for (char ch : text)
    {
        if (std::isxdigit(static_cast<unsigned char>(ch)) || ch == '?')
            compact.push_back(ch);
        else if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == ',' || ch == '\\' || ch == 'x' || ch == 'X')
            continue;
        else
        {
            if (error) *error = "pattern contains an invalid character";
            return false;
        }
    }
    if (compact.empty() || (compact.size() % 2) != 0)
    {
        if (error) *error = "pattern must contain whole bytes";
        return false;
    }
    for (std::size_t i = 0; i < compact.size(); i += 2)
    {
        std::string token = compact.substr(i, 2);
        parsed_pattern_byte_t b;
        if (token == "??" || token == "?")
        {
            b.wildcard = true;
        }
        else
        {
            if (!parse_hex_byte(token, b.value))
            {
                if (error) *error = "pattern contains an invalid byte";
                return false;
            }
        }
        out.push_back(b);
    }
    return !out.empty();
}

bool pattern_matches(const std::uint8_t* data, std::size_t len, const std::vector<parsed_pattern_byte_t>& pattern)
{
    if (!data || pattern.empty() || len < pattern.size())
        return false;
    for (std::size_t i = 0; i < pattern.size(); ++i)
    {
        if (!pattern[i].wildcard && data[i] != pattern[i].value)
            return false;
    }
    return true;
}

std::vector<std::uint64_t> scan_pattern(std::uint32_t pid,
                                        const std::vector<parsed_pattern_byte_t>& pattern,
                                        const std::string& module_hint,
                                        bool executable_only,
                                        std::size_t max_results)
{
    std::vector<std::uint64_t> results;
    if (pattern.empty() || max_results == 0)
        return results;

    std::vector<driver_bridge::memory_region_t> scan_regions;
    if (!module_hint.empty())
    {
        if (auto module = find_module_by_name(pid, module_hint))
        {
            driver_bridge::memory_region_t region{};
            region.base = module->base;
            region.size = module->size;
            region.state = MEM_COMMIT;
            region.protect = executable_only ? PAGE_EXECUTE_READ : PAGE_READONLY;
            scan_regions.push_back(region);
        }
    }
    if (scan_regions.empty())
        scan_regions = regions_for(pid, 8192);

    constexpr std::uint64_t max_region_read = 64ull * 1024ull * 1024ull;
    for (const auto& region : scan_regions)
    {
        if (results.size() >= max_results)
            break;
        if (region.base == 0 || region.size < pattern.size() || region.size > max_region_read)
            continue;
        if (!module_hint.empty())
        {
        }
        else
        {
            if (!is_readable(region))
                continue;
            if (executable_only && !is_executable(region))
                continue;
        }
        std::vector<std::uint8_t> bytes;
        if (!read_bytes(pid, region.base, static_cast<std::size_t>(region.size), bytes) || bytes.size() < pattern.size())
            continue;
        for (std::size_t i = 0; i + pattern.size() <= bytes.size(); ++i)
        {
            if (pattern_matches(bytes.data() + i, bytes.size() - i, pattern))
            {
                results.push_back(region.base + i);
                if (results.size() >= max_results)
                    break;
            }
        }
    }
    return results;
}

AsmInstr decode_one(std::uint32_t pid, std::uint64_t address)
{
    std::vector<std::uint8_t> bytes;
    if (!read_bytes(pid, address, 16, bytes) || bytes.empty())
        return zydis_decode_one(nullptr, 0, address);
    return zydis_decode_one(bytes.data(), static_cast<int>(std::min<std::size_t>(bytes.size(), 16)), address);
}

std::string disasm_text(const AsmInstr& ins)
{
    std::string out = ins.mnem;
    if (ins.ops[0] != '\0')
    {
        out.push_back(' ');
        out += ins.ops;
    }
    return out;
}

std::vector<json> disasm_preview(std::uint32_t pid, std::uint64_t address, std::size_t max_instructions)
{
    std::vector<json> out;
    std::uint64_t cursor = address;
    for (std::size_t i = 0; i < max_instructions; ++i)
    {
        AsmInstr ins = decode_one(pid, cursor);
        json row;
        row["va"] = sa_format_address(ins.addr);
        row["text"] = disasm_text(ins);
        row["len"] = ins.len;
        out.push_back(std::move(row));
        if (ins.len <= 0)
            break;
        cursor += static_cast<std::uint64_t>(ins.len);
    }
    return out;
}

std::string classify_instruction_hint(const AsmInstr& ins)
{
    const std::string m = lower_ascii(ins.mnem);
    const std::string ops = lower_ascii(ins.ops);
    if (ins.is_ret)
        return "return";
    if (ins.is_call)
        return "call";
    if (ins.is_branch)
        return "branch";
    if (m == "mov" && ops.find("[rcx") != std::string::npos)
        return "member_access";
    if ((m == "mov" || m == "lea") && ops.find("rcx") != std::string::npos)
        return "this_pointer_setup";
    if (m.find("vmov") == 0 || m.find("movaps") == 0 || m.find("movups") == 0)
        return "vector_or_matrix_access";
    if (m == "xor" && ops.find(',') != std::string::npos)
        return "xor_transform";
    if (m == "add" || m == "sub" || m == "rol" || m == "ror")
        return "arithmetic_transform";
    return "unknown";
}

std::string classify_function_hint(std::uint32_t pid, std::uint64_t address)
{
    AsmInstr first = decode_one(pid, address);
    const std::string m = lower_ascii(first.mnem);
    const std::string ops = lower_ascii(first.ops);
    if (m == "jmp")
        return "thunk";
    if (m == "mov" && ops.find("rax") != std::string::npos && ops.find("[rcx") != std::string::npos)
        return "getter";
    if (m == "sub" && ops.find("rsp") != std::string::npos)
        return "stack_frame";
    if (m == "push")
        return "prologue";
    if (m == "mov" && ops.find("[rcx") != std::string::npos)
        return "setter_or_virtual_method";
    return classify_instruction_hint(first);
}

bool load_module_layout(std::uint32_t pid, const driver_bridge::module_info_t& module, module_layout_t& out)
{
    out = {};
    out.module = module;
    std::vector<std::uint8_t> headers;
    if (!read_bytes(pid, module.base, 0x1000, headers) || headers.size() < sizeof(IMAGE_DOS_HEADER))
        return false;
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(headers.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
        return false;
    const std::size_t nt_off = static_cast<std::size_t>(dos->e_lfanew);
    const std::size_t nt_common_size = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(WORD);
    if (nt_off + nt_common_size > headers.size())
        return false;
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(headers.data() + nt_off);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.SizeOfOptionalHeader < sizeof(WORD))
        return false;
    const std::uint16_t optional_magic = nt->OptionalHeader.Magic;
    if (optional_magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC && optional_magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        return false;
    out.machine = nt->FileHeader.Machine;
    out.optional_magic = optional_magic;
    out.is_pe32_plus = optional_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    out.pointer_size = out.is_pe32_plus ? 8u : 4u;
    const std::size_t section_off = nt_off + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader;
    const std::size_t section_bytes = static_cast<std::size_t>(nt->FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
    if (section_off + section_bytes > headers.size())
        return false;
    auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(headers.data() + section_off);
    for (std::uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i)
    {
        module_section_t sec;
        char name[9] = {};
        std::memcpy(name, sections[i].Name, 8);
        sec.name = name;
        sec.va = module.base + sections[i].VirtualAddress;
        sec.size = std::max<std::uint32_t>(sections[i].Misc.VirtualSize, sections[i].SizeOfRawData);
        sec.characteristics = sections[i].Characteristics;
        if (sec.size != 0)
            out.sections.push_back(sec);
    }
    return !out.sections.empty();
}

std::string sanitize_identifier(std::string value, const std::string& fallback)
{
    std::string out;
    out.reserve(value.size());
    for (char ch : value)
    {
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_')
            out.push_back(ch);
        else
            out.push_back('_');
    }
    while (!out.empty() && out.front() == '_')
        out.erase(out.begin());
    if (out.empty())
        out = fallback;
    if (out.front() >= '0' && out.front() <= '9')
        out.insert(out.begin(), '_');
    return out;
}

std::filesystem::path appdata_re_dir()
{
    PWSTR appdata = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata)) && appdata)
    {
        std::filesystem::path path = std::filesystem::path(appdata) / L"AiDA" / L"Standalone" / L"re";
        CoTaskMemFree(appdata);
        std::error_code ec;
        std::filesystem::create_directories(path, ec);
        return path;
    }
    auto path = std::filesystem::current_path() / "aida_re";
    std::error_code ec;
    std::filesystem::create_directories(path, ec);
    return path;
}

bool read_json_file(const std::filesystem::path& path, json& out)
{
    out = json::object();
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open())
        return false;
    try
    {
        f >> out;
        return true;
    }
    catch (...)
    {
        out = json::object();
        return false;
    }
}

bool write_json_file_atomic(const std::filesystem::path& path, const json& value)
{
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    const auto tmp = path.string() + ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f.is_open())
            return false;
        f << value.dump(2);
        if (!f.good())
            return false;
    }
    std::filesystem::rename(tmp, path, ec);
    if (!ec)
        return true;
    std::filesystem::remove(path, ec);
    ec.clear();
    std::filesystem::rename(tmp, path, ec);
    return !ec;
}

std::uint64_t unix_time_ms()
{
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

json region_json(const driver_bridge::memory_region_t& region)
{
    json out;
    out["base"] = sa_format_address(region.base);
    out["size"] = region.size;
    out["state"] = sa_format_address(region.state);
    out["protect"] = sa_format_address(region.protect);
    out["type"] = sa_format_address(region.type);
    return out;
}

json module_json(const driver_bridge::module_info_t& module)
{
    json out;
    out["base"] = sa_format_address(module.base);
    out["size"] = module.size;
    out["name"] = module.name;
    out["path"] = module.path;
    return out;
}
}
