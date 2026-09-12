#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <TlHelp32.h>
#include <dbghelp.h>
#include <shobjidl.h>

#include <QByteArray>
#include <QCoreApplication>
#include <QIcon>
#include <QObject>
#include <QScreen>
#include <QSettings>
#include <QString>

#include <DockManager.h>

#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <exception>
#include <functional>
#include <string>
#include <utility>
#include <vector>
#if defined(_M_X64)
#include <intrin.h>
#endif

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "dbghelp.lib")

extern "C" {
#include <openssl/applink.c>
}

#include "helpers/diag_log.hpp"
#include "core/runtime/diagnostic_exception_scope.hpp"
#include "core/tools/command_sessions.hpp"
#include "core/infra/executor.hpp"
#include "core/infra/taskflow_runtime.hpp"
#include "core/infra/taskflow_evaluation.hpp"
#include "core/infra/event_bus.hpp"
#include "core/diagnostics/metadata_ring.hpp"
#include "core/diagnostics/wer_correlation.hpp"
#include "core/diagnostics/crash_snapshot.hpp"
#include "core/diagnostics/window_hung_snapshot.hpp"
#include "core/diagnostics/observer.hpp"
#include "core/analysis/pdb_parser.hpp"
#include "core/mcp/mcp_standalone.hpp"
#include "core/runtime/standalone_driver.hpp"
#include "core/testlab/test_all_features.hpp"
#include "core/settings/standalone_settings.hpp"
#include "core/auth/auth_http.hpp"
#include "core/tools/script_engine.hpp"
#include "core/tools/standalone_tools_fwd.hpp"
#include "core/network/burp/camoufox_bridge.hpp"
#include "core/ai/standalone_chat.hpp"
#include "core/ui/ui_thread_dispatcher.hpp"
#include "qt/analysis_bridge/gui_post.hpp"
#include "qt/qt_early_startup.hpp"
#include "qt/bridge/ui_dispatcher.hpp"
#include "qt/qt_shell_application.hpp"
#include "qt/qt_main_window.hpp"
#include "qt/qt_startup_orchestrator.hpp"
#include "qt/qt_single_instance.hpp"
#include "qt/qt_eventloop_monitor.hpp"
#include "qt/qt_session_bridge.hpp"
#include "qt/programming/programming_host_hooks.hpp"
#include "qt/theme/aida_theme_controller.hpp"
#include "qt/chrome/aida_chrome_composer.hpp"
#include "qt/chrome/aida_exit_review.hpp"
#include "qt/chrome/aida_legacy_chrome_bridge.hpp"
#include "qt/boot/aida_boot_screen.hpp"
#include "qt/docking/dock_host.hpp"
#include "qt/explorer/exchange/open_dispatch.hpp"
#include "qt/network/network_domain_install.hpp"

namespace test_all_features {
    void format_ui_phase_snapshot(char* out, std::size_t cap);
}

namespace aida::qt::crash_integration {
    PVOID install_diagnostic_veh();
    void install_unhandled_exception_filter();
    bool safe_read_qword(const void* p, std::uintptr_t& out);
    void format_taskflow_runtime_crash_snapshot(char* out, std::size_t cap);
    void format_taskflow_runtime_hung_snapshot(char* out, std::size_t cap);
}

extern std::uint64_t g_last_input_event_tick_ms;

static void format_message_pump_stall_context(char* out, size_t cap);
static void emit_window_hung_snapshot(
    uint64_t stall_streak,
    uint64_t frame,
    uint64_t age_ms,
    uint64_t phase_id,
    const char* phase_name,
    const char* render_section,
    DWORD render_tid,
    DWORD peek_status,
    DWORD peek_error,
    const char* dispatch_stage,
    UINT dispatch_msg,
    UINT_PTR dispatch_hwnd,
    const char* wndproc_stage,
    UINT wndproc_msg,
    UINT_PTR wndproc_hwnd);

static void crash_log_write(const char* msg)
{
    diag::log_tagged("main", msg);
}

static void crash_log_fmt(const char* fmt, ...)
{
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    diag::log_tagged("main", buf);
}

static void startup_log_critical(const char* detail)
{
    diag::log_tagged_critical("startup", detail ? detail : "<null>");
}

static void startup_log_critical_fmt(const char* fmt, ...)
{
    char buf[2048] = {};
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    startup_log_critical(buf);
}

static aida::infra::executor::submit_result_t submit_main_executor_task(
    const char* owner_subsystem,
    const char* label,
    aida::infra::executor::domain_t domain,
    const char* thread_class,
    std::function<void()> body,
    int priority = 3)
{
    aida::infra::executor::submission_t submission;
    submission.owner_subsystem = owner_subsystem;
    submission.label = label;
    submission.thread_class = thread_class;
    submission.domain = domain;
    submission.priority = priority;
    submission.body = std::move(body);
    return aida::infra::executor::submit(std::move(submission));
}

static bool aida_key_down(int vk)
{
    return (::GetAsyncKeyState(vk) & 0x8000) != 0;
}

static bool aida_ctrl_shift_t_chord_down()
{
    return aida_key_down(VK_CONTROL) && aida_key_down(VK_SHIFT) && aida_key_down('T');
}

static constexpr int kAidaFullTestHotkeyId = 0xA1DA;
static constexpr DWORD kAidaQueueStatusUnavailable = 0;

struct render_section_state_t
{
    render_section_state_t() noexcept : value("idle") {}
    render_section_state_t(const render_section_state_t&) = delete;
    render_section_state_t& operator=(const render_section_state_t&) = delete;
    render_section_state_t& operator=(const char* section) noexcept
    {
        value.store(section ? section : "<null>", std::memory_order_release);
        return *this;
    }
    const char* c_str() const noexcept
    {
        const char* section = value.load(std::memory_order_acquire);
        return section ? section : "<null>";
    }
    operator const char*() const noexcept
    {
        return c_str();
    }
private:
    std::atomic<const char*> value;
};

static render_section_state_t g_render_section;

static void format_phase0_utc_timestamp(char* out, size_t cap)
{
    if (!out || cap == 0)
        return;
    out[0] = '\0';
    SYSTEMTIME st{};
    GetSystemTime(&st);
    _snprintf_s(out, cap, _TRUNCATE,
        "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
        static_cast<unsigned>(st.wYear),
        static_cast<unsigned>(st.wMonth),
        static_cast<unsigned>(st.wDay),
        static_cast<unsigned>(st.wHour),
        static_cast<unsigned>(st.wMinute),
        static_cast<unsigned>(st.wSecond),
        static_cast<unsigned>(st.wMilliseconds));
}

static void phase0_copy_diag_text(char* out, size_t cap, const char* value)
{
    if (!out || cap == 0)
        return;
    _snprintf_s(out, cap, _TRUNCATE, "%s", value ? value : "");
}

static void phase0_sanitize_log_field(char* value)
{
    if (!value)
        return;
    for (char* p = value; *p; ++p) {
        unsigned char ch = static_cast<unsigned char>(*p);
        if (ch < 0x20 || ch == 0x7F)
            *p = '_';
    }
}

static void phase0_wide_to_diag_utf8(const wchar_t* in, char* out, size_t cap)
{
    aida_early_startup::wide_to_utf8(in, out, cap);
    phase0_sanitize_log_field(out);
}

struct phase0_registry_string_result_t {
    bool present = false;
    bool read_ok = false;
    bool expand_ok = false;
    DWORD gle = ERROR_FILE_NOT_FOUND;
    DWORD type = 0;
    DWORD bytes = 0;
    DWORD expand_gle = ERROR_FILE_NOT_FOUND;
    char value[768] = {};
    char expanded[768] = {};
};

struct phase0_registry_dword_result_t {
    bool present = false;
    bool read_ok = false;
    DWORD gle = ERROR_FILE_NOT_FOUND;
    DWORD type = 0;
    DWORD bytes = 0;
    DWORD value = 0;
};

static phase0_registry_string_result_t phase0_query_registry_string(HKEY key, const wchar_t* value_name, DWORD unavailable_gle)
{
    phase0_registry_string_result_t result{};
    result.gle = unavailable_gle;
    result.expand_gle = unavailable_gle;
    phase0_copy_diag_text(result.value, sizeof(result.value), "<key_unavailable>");
    phase0_copy_diag_text(result.expanded, sizeof(result.expanded), "<key_unavailable>");
    if (!key)
        return result;

    DWORD type = 0;
    DWORD bytes = 0;
    LONG rc = RegQueryValueExW(key, value_name, nullptr, &type, nullptr, &bytes);
    if (rc != ERROR_SUCCESS) {
        result.gle = static_cast<DWORD>(rc);
        result.expand_gle = static_cast<DWORD>(rc);
        if (rc == ERROR_FILE_NOT_FOUND) {
            phase0_copy_diag_text(result.value, sizeof(result.value), "<missing>");
            phase0_copy_diag_text(result.expanded, sizeof(result.expanded), "<missing>");
        } else {
            phase0_copy_diag_text(result.value, sizeof(result.value), "<unreadable>");
            phase0_copy_diag_text(result.expanded, sizeof(result.expanded), "<unreadable>");
        }
        return result;
    }

    result.present = true;
    result.type = type;
    result.bytes = bytes;
    if (bytes > 32768u) {
        result.gle = ERROR_MORE_DATA;
        result.expand_gle = ERROR_MORE_DATA;
        phase0_copy_diag_text(result.value, sizeof(result.value), "<too_large>");
        phase0_copy_diag_text(result.expanded, sizeof(result.expanded), "<too_large>");
        return result;
    }
    std::vector<wchar_t> buffer((bytes / sizeof(wchar_t)) + 2u, L'\0');
    DWORD read_bytes = bytes;
    rc = RegQueryValueExW(key, value_name, nullptr, &type, reinterpret_cast<LPBYTE>(buffer.data()), &read_bytes);
    if (rc == ERROR_MORE_DATA) {
        if (read_bytes > 32768u) {
            result.type = type;
            result.bytes = read_bytes;
            result.gle = ERROR_MORE_DATA;
            result.expand_gle = ERROR_MORE_DATA;
            phase0_copy_diag_text(result.value, sizeof(result.value), "<too_large>");
            phase0_copy_diag_text(result.expanded, sizeof(result.expanded), "<too_large>");
            return result;
        }
        buffer.assign((read_bytes / sizeof(wchar_t)) + 2u, L'\0');
        rc = RegQueryValueExW(key, value_name, nullptr, &type, reinterpret_cast<LPBYTE>(buffer.data()), &read_bytes);
    }
    result.type = type;
    result.bytes = read_bytes;
    if (rc != ERROR_SUCCESS) {
        result.gle = static_cast<DWORD>(rc);
        result.expand_gle = static_cast<DWORD>(rc);
        phase0_copy_diag_text(result.value, sizeof(result.value), "<unreadable>");
        phase0_copy_diag_text(result.expanded, sizeof(result.expanded), "<unreadable>");
        return result;
    }
    if (type != REG_SZ && type != REG_EXPAND_SZ) {
        result.gle = ERROR_INVALID_DATA;
        result.expand_gle = ERROR_INVALID_DATA;
        phase0_copy_diag_text(result.value, sizeof(result.value), "<non_string>");
        phase0_copy_diag_text(result.expanded, sizeof(result.expanded), "<non_string>");
        return result;
    }

    const size_t char_count = read_bytes / sizeof(wchar_t);
    if (char_count < buffer.size())
        buffer[char_count] = L'\0';
    else
        buffer.back() = L'\0';

    phase0_wide_to_diag_utf8(buffer.data(), result.value, sizeof(result.value));
    result.read_ok = true;
    result.gle = 0;
    if (type == REG_EXPAND_SZ) {
        wchar_t expanded_stack[1024] = {};
        constexpr DWORD expanded_stack_count = static_cast<DWORD>(sizeof(expanded_stack) / sizeof(expanded_stack[0]));
        DWORD expanded_count = ExpandEnvironmentStringsW(buffer.data(), expanded_stack, expanded_stack_count);
        if (expanded_count != 0 && expanded_count <= expanded_stack_count) {
            result.expand_ok = true;
            result.expand_gle = 0;
            phase0_wide_to_diag_utf8(expanded_stack, result.expanded, sizeof(result.expanded));
        } else if (expanded_count > expanded_stack_count && expanded_count <= 32768u) {
            std::vector<wchar_t> expanded(static_cast<size_t>(expanded_count) + 1u, L'\0');
            DWORD expanded_retry = ExpandEnvironmentStringsW(buffer.data(), expanded.data(), expanded_count);
            if (expanded_retry != 0 && expanded_retry <= expanded_count) {
                result.expand_ok = true;
                result.expand_gle = 0;
                phase0_wide_to_diag_utf8(expanded.data(), result.expanded, sizeof(result.expanded));
            } else {
                result.expand_gle = GetLastError();
                phase0_copy_diag_text(result.expanded, sizeof(result.expanded), "<expand_failed>");
            }
        } else if (expanded_count > 32768u) {
            result.expand_gle = ERROR_MORE_DATA;
            phase0_copy_diag_text(result.expanded, sizeof(result.expanded), "<expand_too_large>");
        } else {
            result.expand_gle = GetLastError();
            phase0_copy_diag_text(result.expanded, sizeof(result.expanded), "<expand_failed>");
        }
    } else {
        result.expand_ok = true;
        result.expand_gle = 0;
        phase0_copy_diag_text(result.expanded, sizeof(result.expanded), result.value);
    }
    return result;
}

static phase0_registry_dword_result_t phase0_query_registry_dword(HKEY key, const wchar_t* value_name, DWORD unavailable_gle)
{
    phase0_registry_dword_result_t result{};
    result.gle = unavailable_gle;
    if (!key)
        return result;
    DWORD type = 0;
    DWORD value = 0;
    DWORD bytes = sizeof(value);
    LONG rc = RegQueryValueExW(key, value_name, nullptr, &type, reinterpret_cast<LPBYTE>(&value), &bytes);
    result.type = type;
    result.bytes = bytes;
    if (rc == ERROR_FILE_NOT_FOUND) {
        result.gle = static_cast<DWORD>(rc);
        return result;
    }
    result.present = true;
    if (rc != ERROR_SUCCESS) {
        result.gle = static_cast<DWORD>(rc);
        return result;
    }
    if (type != REG_DWORD || bytes < sizeof(DWORD)) {
        result.gle = ERROR_INVALID_DATA;
        return result;
    }
    result.read_ok = true;
    result.gle = 0;
    result.value = value;
    return result;
}

static void phase0_log_wer_registry_scope(const char* phase, HKEY root, const char* root_name, const wchar_t* subkey, const char* scope)
{
    char utc[48] = {};
    char key_utf8[512] = {};
    format_phase0_utc_timestamp(utc, sizeof(utc));
    phase0_wide_to_diag_utf8(subkey, key_utf8, sizeof(key_utf8));
    HKEY key = nullptr;
    LONG open_rc = RegOpenKeyExW(root, subkey, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key);
    const bool open_ok = open_rc == ERROR_SUCCESS;
    const DWORD open_gle = static_cast<DWORD>(open_rc);
    phase0_registry_string_result_t dump_folder = phase0_query_registry_string(key, L"DumpFolder", open_gle);
    phase0_registry_dword_result_t dump_type = phase0_query_registry_dword(key, L"DumpType", open_gle);
    phase0_registry_dword_result_t dump_count = phase0_query_registry_dword(key, L"DumpCount", open_gle);
    phase0_registry_dword_result_t custom_flags = phase0_query_registry_dword(key, L"CustomDumpFlags", open_gle);
    char msg[3600] = {};
    _snprintf_s(msg, sizeof(msg), _TRUNCATE,
        "record=localdumps_registry phase=%s pid=%lu tid=%lu utc=%s tick_ms=%llu app=AiDAStandalone.exe root=%s view=64 scope=%s key=%s open_ok=%d open_gle=%lu dump_folder_present=%d dump_folder_read_ok=%d dump_folder_gle=%lu dump_folder_type=%lu dump_folder_bytes=%lu dump_folder=%s dump_folder_expand_ok=%d dump_folder_expand_gle=%lu dump_folder_expanded=%s dump_type_present=%d dump_type_read_ok=%d dump_type_gle=%lu dump_type_type=%lu dump_type_bytes=%lu dump_type_value=%lu dump_count_present=%d dump_count_read_ok=%d dump_count_gle=%lu dump_count_type=%lu dump_count_bytes=%lu dump_count_value=%lu custom_dump_flags_present=%d custom_dump_flags_read_ok=%d custom_dump_flags_gle=%lu custom_dump_flags_type=%lu custom_dump_flags_bytes=%lu custom_dump_flags_value=%lu",
        phase ? phase : "<null>",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        utc,
        static_cast<unsigned long long>(GetTickCount64()),
        root_name ? root_name : "<root>",
        scope ? scope : "<scope>",
        key_utf8,
        open_ok ? 1 : 0,
        open_gle,
        dump_folder.present ? 1 : 0,
        dump_folder.read_ok ? 1 : 0,
        dump_folder.gle,
        dump_folder.type,
        dump_folder.bytes,
        dump_folder.value,
        dump_folder.expand_ok ? 1 : 0,
        dump_folder.expand_gle,
        dump_folder.expanded,
        dump_type.present ? 1 : 0,
        dump_type.read_ok ? 1 : 0,
        dump_type.gle,
        dump_type.type,
        dump_type.bytes,
        dump_type.value,
        dump_count.present ? 1 : 0,
        dump_count.read_ok ? 1 : 0,
        dump_count.gle,
        dump_count.type,
        dump_count.bytes,
        dump_count.value,
        custom_flags.present ? 1 : 0,
        custom_flags.read_ok ? 1 : 0,
        custom_flags.gle,
        custom_flags.type,
        custom_flags.bytes,
        custom_flags.value);
    diag::log_tagged_critical("WER-CONFIG", msg);
    if (key)
        RegCloseKey(key);
}

static void phase0_log_wer_configuration(const char* phase)
{
    const uint64_t start_ms = static_cast<uint64_t>(GetTickCount64());
    char utc[48] = {};
    char module[MAX_PATH] = {};
    format_phase0_utc_timestamp(utc, sizeof(utc));
    GetModuleFileNameA(nullptr, module, static_cast<DWORD>(sizeof(module)));
    diag::log_tagged_critical_fmt("WER-CONFIG",
        "record=localdumps_scan_start phase=%s pid=%lu tid=%lu utc=%s tick_ms=%llu app=AiDAStandalone.exe module=%s",
        phase ? phase : "<null>",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        utc,
        static_cast<unsigned long long>(GetTickCount64()),
        module);
    constexpr const wchar_t* default_subkey = L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps";
    constexpr const wchar_t* exe_subkey = L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\AiDAStandalone.exe";
    phase0_log_wer_registry_scope(phase, HKEY_CURRENT_USER, "HKCU", exe_subkey, "per_exe");
    phase0_log_wer_registry_scope(phase, HKEY_CURRENT_USER, "HKCU", default_subkey, "default");
    phase0_log_wer_registry_scope(phase, HKEY_LOCAL_MACHINE, "HKLM", exe_subkey, "per_exe");
    phase0_log_wer_registry_scope(phase, HKEY_LOCAL_MACHINE, "HKLM", default_subkey, "default");
    format_phase0_utc_timestamp(utc, sizeof(utc));
    diag::log_tagged_critical_fmt("WER-CONFIG",
        "record=localdumps_scan_end phase=%s pid=%lu tid=%lu utc=%s tick_ms=%llu elapsed_ms=%llu app=AiDAStandalone.exe",
        phase ? phase : "<null>",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        utc,
        static_cast<unsigned long long>(GetTickCount64()),
        static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - start_ms));
}

static void phase0_post_wer_configuration_logging(const char* phase)
{
    std::string phase_copy = phase && phase[0] ? phase : "startup";
    const auto submit_result = submit_main_executor_task(
        "startup",
        "phase0.wer_config",
        aida::infra::executor::domain_t::diagnostics,
        "startup_diagnostics",
        [phase_copy]() {
            phase0_log_wer_configuration(phase_copy.c_str());
    });
    const bool posted = submit_result.submitted;
    char utc[48] = {};
    format_phase0_utc_timestamp(utc, sizeof(utc));
    diag::log_tagged_critical_fmt("WER-CONFIG",
        "record=localdumps_scan_post phase=%s posted=%d pid=%lu tid=%lu utc=%s tick_ms=%llu worker=executor_diagnostics",
        phase_copy.c_str(),
        posted ? 1 : 0,
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        utc,
        static_cast<unsigned long long>(GetTickCount64()));
    if (!posted) {
        diag::log_tagged_critical_fmt("WER-CONFIG",
            "record=localdumps_scan_post_failed phase=%s reason=%.180s pid=%lu tid=%lu utc=%s tick_ms=%llu worker=executor_diagnostics",
            phase_copy.c_str(),
            submit_result.reject_reason.empty() ? "<none>" : submit_result.reject_reason.c_str(),
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            utc,
            static_cast<unsigned long long>(GetTickCount64()));
    }
}

static void log_disk_backed_startup_state(const char* phase)
{
    char module[MAX_PATH] = {};
    char cwd[MAX_PATH] = {};
    char camoufox_exe[MAX_PATH] = {};
    char camoufox_python[MAX_PATH] = {};
    char camoufox_setup[32] = {};
    GetModuleFileNameA(nullptr, module, static_cast<DWORD>(sizeof(module)));
    GetCurrentDirectoryA(static_cast<DWORD>(sizeof(cwd)), cwd);
    GetEnvironmentVariableA("AIDA_CAMOUFOX_EXECUTABLE", camoufox_exe, static_cast<DWORD>(sizeof(camoufox_exe)));
    GetEnvironmentVariableA("AIDA_CAMOUFOX_PYTHON", camoufox_python, static_cast<DWORD>(sizeof(camoufox_python)));
    GetEnvironmentVariableA("AIDA_CAMOUFOX_ALLOW_SETUP_BOOTSTRAP", camoufox_setup, static_cast<DWORD>(sizeof(camoufox_setup)));

    std::uintptr_t teb = 0;
    std::uintptr_t peb = 0;
    std::uintptr_t tls_vector = 0;
    std::uintptr_t tls_slot51 = 0;
#if defined(_M_X64)
    teb = static_cast<std::uintptr_t>(__readgsqword(0x30));
    peb = static_cast<std::uintptr_t>(__readgsqword(0x60));
    tls_vector = static_cast<std::uintptr_t>(__readgsqword(0x58));
#endif
    if (tls_vector)
        aida::qt::crash_integration::safe_read_qword(reinterpret_cast<const void*>(tls_vector + 51u * sizeof(void*)), tls_slot51);

    HMODULE image = GetModuleHandleA(nullptr);
    MEMORY_BASIC_INFORMATION mbi{};
    if (image)
        VirtualQuery(image, &mbi, sizeof(mbi));

    diag::log_tagged_critical_fmt("main",
        "disk_backed_startup_state phase=%s pid=%lu tid=%lu module=%s cwd=%s camoufox_exe=%s camoufox_python=%s camoufox_setup=%s image_base=0x%016llX alloc_base=0x%016llX mbi_base=0x%016llX mbi_size=0x%llX mbi_state=0x%08lX mbi_protect=0x%08lX teb=0x%016llX peb=0x%016llX tls_vector=0x%016llX tls_slot51=0x%016llX",
        phase ? phase : "",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        module,
        cwd,
        camoufox_exe,
        camoufox_python,
        camoufox_setup,
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(image)),
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(mbi.AllocationBase)),
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(mbi.BaseAddress)),
        static_cast<unsigned long long>(mbi.RegionSize),
        mbi.State,
        mbi.Protect,
        static_cast<unsigned long long>(teb),
        static_cast<unsigned long long>(peb),
        static_cast<unsigned long long>(tls_vector),
        static_cast<unsigned long long>(tls_slot51));
}

namespace aida_tracer {
    inline std::atomic<uint64_t> g_render_frame{0};
    inline std::atomic<uint64_t> g_render_last_tick_ms{0};
    inline std::atomic<uint64_t> g_render_phase_id{0};
    inline std::atomic<const char*> g_render_phase_name{"<startup>"};
    inline std::atomic<DWORD> g_render_thread_id{0};
    inline std::atomic<uint64_t> g_attach_phase_id{0};
    inline std::atomic<const char*> g_attach_phase_name{"<idle>"};
    inline std::atomic<const char*> g_dispatch_stage{"<idle>"};
    inline std::atomic<UINT> g_dispatch_msg{0};
    inline std::atomic<UINT_PTR> g_dispatch_hwnd{0};
    inline std::atomic<UINT_PTR> g_dispatch_wparam{0};
    inline std::atomic<LONG_PTR> g_dispatch_lparam{0};
    inline std::atomic<DWORD> g_peek_queue_status{0};
    inline std::atomic<DWORD> g_peek_last_error{0};
    inline std::atomic<UINT> g_peek_remove_flags{0};
    inline std::atomic<UINT_PTR> g_peek_filter_hwnd{0};
    inline std::atomic<uint64_t> g_peek_send_only_defers{0};
    inline std::atomic<uint64_t> g_peek_send_only_flushes{0};
    inline std::atomic<const char*> g_wndproc_stage{"<idle>"};
    inline std::atomic<UINT> g_wndproc_msg{0};
    inline std::atomic<UINT_PTR> g_wndproc_hwnd{0};
    inline std::atomic<UINT_PTR> g_wndproc_wparam{0};
    inline std::atomic<LONG_PTR> g_wndproc_lparam{0};
    inline std::atomic<uint64_t> g_wndproc_enter_count{0};
    inline std::atomic<uint64_t> g_wndproc_exit_count{0};
    inline std::atomic<uint64_t> g_peek_call_count{0};
    inline std::atomic<uint64_t> g_peek_return_count{0};
    inline std::atomic<uint64_t> g_dispatch_enter_count{0};
    inline std::atomic<uint64_t> g_dispatch_exit_count{0};
    inline std::atomic<uint64_t> g_last_thread_snapshot_ms{0};
    inline std::atomic<bool> g_stop{false};

    const char* message_name(UINT msg) {
        switch (msg) {
        case WM_NULL: return "WM_NULL";
        case WM_CREATE: return "WM_CREATE";
        case WM_DESTROY: return "WM_DESTROY";
        case WM_MOVE: return "WM_MOVE";
        case WM_SIZE: return "WM_SIZE";
        case WM_ACTIVATE: return "WM_ACTIVATE";
        case WM_SETFOCUS: return "WM_SETFOCUS";
        case WM_KILLFOCUS: return "WM_KILLFOCUS";
        case WM_ENABLE: return "WM_ENABLE";
        case WM_SETREDRAW: return "WM_SETREDRAW";
        case WM_SETTEXT: return "WM_SETTEXT";
        case WM_GETTEXT: return "WM_GETTEXT";
        case WM_GETTEXTLENGTH: return "WM_GETTEXTLENGTH";
        case WM_PAINT: return "WM_PAINT";
        case WM_CLOSE: return "WM_CLOSE";
        case WM_QUIT: return "WM_QUIT";
        case WM_ERASEBKGND: return "WM_ERASEBKGND";
        case WM_SYSCOLORCHANGE: return "WM_SYSCOLORCHANGE";
        case WM_SHOWWINDOW: return "WM_SHOWWINDOW";
        case WM_SETTINGCHANGE: return "WM_SETTINGCHANGE";
        case WM_DEVMODECHANGE: return "WM_DEVMODECHANGE";
        case WM_ACTIVATEAPP: return "WM_ACTIVATEAPP";
        case WM_FONTCHANGE: return "WM_FONTCHANGE";
        case WM_TIMECHANGE: return "WM_TIMECHANGE";
        case WM_CANCELMODE: return "WM_CANCELMODE";
        case WM_SETCURSOR: return "WM_SETCURSOR";
        case WM_MOUSEACTIVATE: return "WM_MOUSEACTIVATE";
        case WM_CHILDACTIVATE: return "WM_CHILDACTIVATE";
        case WM_QUEUESYNC: return "WM_QUEUESYNC";
        case WM_GETMINMAXINFO: return "WM_GETMINMAXINFO";
        case WM_WINDOWPOSCHANGING: return "WM_WINDOWPOSCHANGING";
        case WM_WINDOWPOSCHANGED: return "WM_WINDOWPOSCHANGED";
        case WM_CONTEXTMENU: return "WM_CONTEXTMENU";
        case WM_STYLECHANGING: return "WM_STYLECHANGING";
        case WM_STYLECHANGED: return "WM_STYLECHANGED";
        case WM_DISPLAYCHANGE: return "WM_DISPLAYCHANGE";
        case WM_GETICON: return "WM_GETICON";
        case WM_SETICON: return "WM_SETICON";
        case WM_NCCREATE: return "WM_NCCREATE";
        case WM_NCDESTROY: return "WM_NCDESTROY";
        case WM_NCCALCSIZE: return "WM_NCCALCSIZE";
        case WM_NCHITTEST: return "WM_NCHITTEST";
        case WM_NCPAINT: return "WM_NCPAINT";
        case WM_NCACTIVATE: return "WM_NCACTIVATE";
        case WM_GETDLGCODE: return "WM_GETDLGCODE";
        case WM_SYNCPAINT: return "WM_SYNCPAINT";
        case WM_NCMOUSEMOVE: return "WM_NCMOUSEMOVE";
        case WM_NCLBUTTONDOWN: return "WM_NCLBUTTONDOWN";
        case WM_NCLBUTTONUP: return "WM_NCLBUTTONUP";
        case WM_NCLBUTTONDBLCLK: return "WM_NCLBUTTONDBLCLK";
        case WM_KEYDOWN: return "WM_KEYDOWN";
        case WM_KEYUP: return "WM_KEYUP";
        case WM_CHAR: return "WM_CHAR";
        case WM_SYSKEYDOWN: return "WM_SYSKEYDOWN";
        case WM_SYSKEYUP: return "WM_SYSKEYUP";
        case WM_SYSCHAR: return "WM_SYSCHAR";
        case WM_INITDIALOG: return "WM_INITDIALOG";
        case WM_COMMAND: return "WM_COMMAND";
        case WM_SYSCOMMAND: return "WM_SYSCOMMAND";
        case WM_TIMER: return "WM_TIMER";
        case WM_HSCROLL: return "WM_HSCROLL";
        case WM_VSCROLL: return "WM_VSCROLL";
        case WM_INITMENU: return "WM_INITMENU";
        case WM_INITMENUPOPUP: return "WM_INITMENUPOPUP";
        case WM_MENUSELECT: return "WM_MENUSELECT";
        case WM_MENUCHAR: return "WM_MENUCHAR";
        case WM_ENTERIDLE: return "WM_ENTERIDLE";
        case WM_MOUSEMOVE: return "WM_MOUSEMOVE";
        case WM_LBUTTONDOWN: return "WM_LBUTTONDOWN";
        case WM_LBUTTONUP: return "WM_LBUTTONUP";
        case WM_LBUTTONDBLCLK: return "WM_LBUTTONDBLCLK";
        case WM_RBUTTONDOWN: return "WM_RBUTTONDOWN";
        case WM_RBUTTONUP: return "WM_RBUTTONUP";
        case WM_RBUTTONDBLCLK: return "WM_RBUTTONDBLCLK";
        case WM_MBUTTONDOWN: return "WM_MBUTTONDOWN";
        case WM_MBUTTONUP: return "WM_MBUTTONUP";
        case WM_MOUSEWHEEL: return "WM_MOUSEWHEEL";
        case WM_XBUTTONDOWN: return "WM_XBUTTONDOWN";
        case WM_XBUTTONUP: return "WM_XBUTTONUP";
        case WM_MOUSELEAVE: return "WM_MOUSELEAVE";
        case WM_MOUSEHOVER: return "WM_MOUSEHOVER";
        case WM_MOUSEHWHEEL: return "WM_MOUSEHWHEEL";
        case WM_PARENTNOTIFY: return "WM_PARENTNOTIFY";
        case WM_ENTERMENULOOP: return "WM_ENTERMENULOOP";
        case WM_EXITMENULOOP: return "WM_EXITMENULOOP";
        case WM_NEXTMENU: return "WM_NEXTMENU";
        case WM_SIZING: return "WM_SIZING";
        case WM_CAPTURECHANGED: return "WM_CAPTURECHANGED";
        case WM_MOVING: return "WM_MOVING";
        case WM_POWERBROADCAST: return "WM_POWERBROADCAST";
        case WM_DEVICECHANGE: return "WM_DEVICECHANGE";
        case WM_ENTERSIZEMOVE: return "WM_ENTERSIZEMOVE";
        case WM_EXITSIZEMOVE: return "WM_EXITSIZEMOVE";
        case WM_DROPFILES: return "WM_DROPFILES";
        case WM_DPICHANGED: return "WM_DPICHANGED";
        default: return "WM_UNKNOWN";
        }
    }

    inline void set_dispatch_state(const char* stage, const MSG& msg) {
        g_dispatch_msg.store(msg.message, std::memory_order_release);
        g_dispatch_hwnd.store(reinterpret_cast<UINT_PTR>(msg.hwnd), std::memory_order_release);
        g_dispatch_wparam.store(static_cast<UINT_PTR>(msg.wParam), std::memory_order_release);
        g_dispatch_lparam.store(static_cast<LONG_PTR>(msg.lParam), std::memory_order_release);
        g_dispatch_stage.store(stage, std::memory_order_release);
    }

    inline void clear_dispatch_state() {
        g_dispatch_stage.store("<idle>", std::memory_order_release);
    }

    inline void set_peek_state(DWORD queue_status, DWORD last_error) {
        g_peek_queue_status.store(queue_status, std::memory_order_release);
        g_peek_last_error.store(last_error, std::memory_order_release);
    }

    inline void set_peek_call_shape(UINT remove_flags, HWND filter_hwnd) {
        g_peek_remove_flags.store(remove_flags, std::memory_order_release);
        g_peek_filter_hwnd.store(reinterpret_cast<UINT_PTR>(filter_hwnd), std::memory_order_release);
    }

    inline bool should_log_wndproc_input_message(UINT) {
        return false;
    }

    inline bool should_log_wndproc_completion(UINT msg, uint64_t elapsed_ms) {
        if (elapsed_ms >= 32)
            return true;
        switch (msg) {
        case WM_CLOSE:
        case WM_DESTROY:
        case WM_NCDESTROY:
        case WM_QUERYENDSESSION:
        case WM_ENDSESSION:
        case WM_SYSCOMMAND:
        case WM_DPICHANGED:
        case WM_SETTINGCHANGE:
            return true;
        default:
            return should_log_wndproc_input_message(msg);
        }
    }

    inline bool is_shutdown_stall_context(const char* phase_name, UINT dispatch_msg, UINT wndproc_msg) {
        if (phase_name && std::strncmp(phase_name, "shutdown", 8) == 0)
            return true;
        switch (dispatch_msg) {
        case WM_QUIT:
        case WM_CLOSE:
        case WM_DESTROY:
        case WM_NCDESTROY:
            return true;
        default:
            break;
        }
        switch (wndproc_msg) {
        case WM_CLOSE:
        case WM_DESTROY:
        case WM_NCDESTROY:
            return true;
        default:
            return false;
        }
    }

    inline void set_wndproc_state(const char* stage, HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        g_wndproc_msg.store(msg, std::memory_order_release);
        g_wndproc_hwnd.store(reinterpret_cast<UINT_PTR>(hwnd), std::memory_order_release);
        g_wndproc_wparam.store(static_cast<UINT_PTR>(wParam), std::memory_order_release);
        g_wndproc_lparam.store(static_cast<LONG_PTR>(lParam), std::memory_order_release);
        g_wndproc_stage.store(stage, std::memory_order_release);
        if (stage && strcmp(stage, "enter") == 0)
            g_wndproc_enter_count.fetch_add(1, std::memory_order_acq_rel);
    }

    inline void clear_wndproc_state() {
        g_wndproc_stage.store("<idle>", std::memory_order_release);
        g_wndproc_exit_count.fetch_add(1, std::memory_order_acq_rel);
    }

    inline void capture_render_thread_snapshot(DWORD render_tid, uint64_t age_ms) {
        const uint64_t now = static_cast<uint64_t>(GetTickCount64());
        uint64_t prev = g_last_thread_snapshot_ms.load(std::memory_order_acquire);
        if (prev != 0 && now >= prev && now - prev < 30000)
            return;
        g_last_thread_snapshot_ms.store(now, std::memory_order_release);

        HANDLE th = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, render_tid);
        DWORD open_gle = th ? 0 : GetLastError();
        DWORD exit_code = 0;
        DWORD exit_gle = 0;
        BOOL exit_ok = FALSE;
        FILETIME create_time{};
        FILETIME exit_time{};
        FILETIME kernel_time{};
        FILETIME user_time{};
        DWORD times_gle = 0;
        BOOL times_ok = FALSE;
        if (th) {
            SetLastError(0);
            exit_ok = GetExitCodeThread(th, &exit_code);
            exit_gle = exit_ok ? 0 : GetLastError();
            SetLastError(0);
            times_ok = GetThreadTimes(th, &create_time, &exit_time, &kernel_time, &user_time);
            times_gle = times_ok ? 0 : GetLastError();
            CloseHandle(th);
        }

        diag::log_tagged_critical_fmt("tracer",
            "render_thread_snapshot_no_suspend tid=%lu age_ms=%llu open_ok=%d open_gle=%lu exit_ok=%d exit_code=0x%08lX exit_gle=%lu times_ok=%d times_gle=%lu kernel_time_low=0x%08lX kernel_time_high=0x%08lX user_time_low=0x%08lX user_time_high=0x%08lX peek_calls=%llu peek_returns=%llu dispatch_enter=%llu dispatch_exit=%llu wnd_enter=%llu wnd_exit=%llu",
            render_tid,
            static_cast<unsigned long long>(age_ms),
            th ? 1 : 0,
            static_cast<unsigned long>(open_gle),
            exit_ok ? 1 : 0,
            static_cast<unsigned long>(exit_code),
            static_cast<unsigned long>(exit_gle),
            times_ok ? 1 : 0,
            static_cast<unsigned long>(times_gle),
            static_cast<unsigned long>(kernel_time.dwLowDateTime),
            static_cast<unsigned long>(kernel_time.dwHighDateTime),
            static_cast<unsigned long>(user_time.dwLowDateTime),
            static_cast<unsigned long>(user_time.dwHighDateTime),
            static_cast<unsigned long long>(g_peek_call_count.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_peek_return_count.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_dispatch_enter_count.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_dispatch_exit_count.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_wndproc_enter_count.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_wndproc_exit_count.load(std::memory_order_acquire)));

        HANDLE stack_th = OpenThread(
            THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_LIMITED_INFORMATION,
            FALSE,
            render_tid);
        const DWORD stack_open_gle = stack_th ? 0 : GetLastError();
        if (!stack_th) {
            diag::log_tagged_critical_fmt("tracer",
                "render_thread_stack_open_fail tid=%lu gle=%lu",
                render_tid,
                static_cast<unsigned long>(stack_open_gle));
            return;
        }

        DWORD suspend_count = static_cast<DWORD>(-1);
        unsigned frames_walked = 0;
        const char* abort_reason = nullptr;
        const uint64_t suspend_t0 = static_cast<uint64_t>(GetTickCount64());
        diag::log_tagged_critical_fmt("tracer",
            "render_thread_stack_begin tid=%lu age_ms=%llu",
            render_tid,
            static_cast<unsigned long long>(age_ms));

        __try {
            suspend_count = SuspendThread(stack_th);
            if (suspend_count == static_cast<DWORD>(-1)) {
                abort_reason = "suspend_failed";
            } else {
                CONTEXT ctx{};
                ctx.ContextFlags = CONTEXT_FULL;
                if (!GetThreadContext(stack_th, &ctx)) {
                    abort_reason = "get_thread_context_failed";
                } else {
                    STACKFRAME64 frame{};
#if defined(_M_X64)
                    frame.AddrPC.Offset = ctx.Rip;
                    frame.AddrPC.Mode = AddrModeFlat;
                    frame.AddrFrame.Offset = ctx.Rbp;
                    frame.AddrFrame.Mode = AddrModeFlat;
                    frame.AddrStack.Offset = ctx.Rsp;
                    frame.AddrStack.Mode = AddrModeFlat;
                    const DWORD machine = IMAGE_FILE_MACHINE_AMD64;
#else
                    frame.AddrPC.Offset = ctx.Eip;
                    frame.AddrPC.Mode = AddrModeFlat;
                    frame.AddrFrame.Offset = ctx.Ebp;
                    frame.AddrFrame.Mode = AddrModeFlat;
                    frame.AddrStack.Offset = ctx.Esp;
                    frame.AddrStack.Mode = AddrModeFlat;
                    const DWORD machine = IMAGE_FILE_MACHINE_I386;
#endif
                    HANDLE proc = GetCurrentProcess();
                    constexpr unsigned kMaxFrames = 64;
                    for (unsigned i = 0; i < kMaxFrames; ++i) {
                        const uint64_t walk_now = static_cast<uint64_t>(GetTickCount64());
                        if (walk_now - suspend_t0 >= 50ULL) {
                            abort_reason = "suspend_budget_exceeded";
                            break;
                        }
                        if (!StackWalk64(
                                machine,
                                proc,
                                stack_th,
                                &frame,
                                machine == IMAGE_FILE_MACHINE_AMD64 ? &ctx : nullptr,
                                nullptr,
                                SymFunctionTableAccess64,
                                SymGetModuleBase64,
                                nullptr)) {
                            abort_reason = "stack_walk_end_or_fail";
                            break;
                        }
                        if (frame.AddrPC.Offset == 0)
                            break;
                        char module_path[MAX_PATH] = {};
                        unsigned long long module_base = 0;
                        unsigned long long module_off = frame.AddrPC.Offset;
                        HMODULE mod = nullptr;
                        if (GetModuleHandleExA(
                                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                reinterpret_cast<LPCSTR>(static_cast<UINT_PTR>(frame.AddrPC.Offset)),
                                &mod) &&
                            mod) {
                            module_base = static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(mod));
                            module_off = frame.AddrPC.Offset - module_base;
                            GetModuleFileNameA(mod, module_path, sizeof(module_path));
                        }
                        const char* short_name = module_path;
                        for (const char* p = module_path; *p; ++p) {
                            if (*p == '\\' || *p == '/')
                                short_name = p + 1;
                        }
                        diag::log_tagged_critical_fmt("tracer",
                            "render_thread_stack idx=%u rip=0x%llX module=%s base=0x%llX offset=0x%llX frame_rbp=0x%llX frame_rsp=0x%llX",
                            i,
                            static_cast<unsigned long long>(frame.AddrPC.Offset),
                            short_name[0] ? short_name : "<unknown>",
                            module_base,
                            module_off,
                            static_cast<unsigned long long>(frame.AddrFrame.Offset),
                            static_cast<unsigned long long>(frame.AddrStack.Offset));
                        ++frames_walked;
                    }
                }
                ResumeThread(stack_th);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            aida::diagnostics::crash::emit_crash_breadcrumb(GetExceptionCode(), nullptr, "stall_watcher_stack_walk");
            if (suspend_count != static_cast<DWORD>(-1))
                ResumeThread(stack_th);
            abort_reason = "seh_exception";
        }

        const uint64_t suspend_elapsed = static_cast<uint64_t>(GetTickCount64()) - suspend_t0;
        diag::log_tagged_critical_fmt("tracer",
            "render_thread_stack_end tid=%lu frames=%u suspend_count=%lu elapsed_ms=%llu reason=%s",
            render_tid,
            frames_walked,
            static_cast<unsigned long>(suspend_count),
            static_cast<unsigned long long>(suspend_elapsed),
            abort_reason ? abort_reason : "ok");

        CloseHandle(stack_th);
    }

    inline void mark_render_phase(const char* name) {
        g_render_phase_name.store(name, std::memory_order_release);
        g_render_phase_id.fetch_add(1, std::memory_order_acq_rel);
    }
    inline void mark_attach_phase(const char* name) {
        g_attach_phase_name.store(name, std::memory_order_release);
        g_attach_phase_id.fetch_add(1, std::memory_order_acq_rel);
        diag::log_tagged_critical_fmt("attach", "phase=%s", name);
    }
    inline void render_pulse(uint64_t frame) {
        g_render_thread_id.store(GetCurrentThreadId(), std::memory_order_release);
        g_render_frame.store(frame, std::memory_order_release);
        g_render_last_tick_ms.store(static_cast<uint64_t>(GetTickCount64()), std::memory_order_release);
    }

    const char* crash_render_phase_name() {
        return g_render_phase_name.load(std::memory_order_acquire);
    }
    std::uint64_t crash_render_last_tick_ms() {
        return g_render_last_tick_ms.load(std::memory_order_acquire);
    }
    const char* crash_wndproc_stage() {
        return g_wndproc_stage.load(std::memory_order_acquire);
    }
    const char* crash_dispatch_stage() {
        return g_dispatch_stage.load(std::memory_order_acquire);
    }
    UINT crash_dispatch_msg() {
        return g_dispatch_msg.load(std::memory_order_acquire);
    }
    UINT crash_wndproc_msg() {
        return g_wndproc_msg.load(std::memory_order_acquire);
    }

    inline void run_tracer_thread() {
        uint64_t prev_frame = 0;
        uint64_t prev_render_phase_id = 0;
        uint64_t stall_streak = 0;
        uint64_t last_peek_rescue_ms = 0;
        const uint64_t kStallThresholdMs = 2000;
        while (!g_stop.load(std::memory_order_acquire)) {
            ::Sleep(250);

            uint64_t now = static_cast<uint64_t>(GetTickCount64());
            uint64_t frame = g_render_frame.load(std::memory_order_acquire);
            uint64_t last_tick = g_render_last_tick_ms.load(std::memory_order_acquire);
            uint64_t phase_id = g_render_phase_id.load(std::memory_order_acquire);
            const char* phase_name = g_render_phase_name.load(std::memory_order_acquire);
            const char* render_section = g_render_section.c_str();
            uint64_t attach_phase_id = g_attach_phase_id.load(std::memory_order_acquire);
            const char* attach_phase = g_attach_phase_name.load(std::memory_order_acquire);
            DWORD render_tid = g_render_thread_id.load(std::memory_order_acquire);
            const char* dispatch_stage = g_dispatch_stage.load(std::memory_order_acquire);
            UINT dispatch_msg = g_dispatch_msg.load(std::memory_order_acquire);
            UINT_PTR dispatch_hwnd = g_dispatch_hwnd.load(std::memory_order_acquire);
            UINT_PTR dispatch_wparam = g_dispatch_wparam.load(std::memory_order_acquire);
            LONG_PTR dispatch_lparam = g_dispatch_lparam.load(std::memory_order_acquire);
            DWORD peek_status = g_peek_queue_status.load(std::memory_order_acquire);
            DWORD peek_error = g_peek_last_error.load(std::memory_order_acquire);
            const char* wndproc_stage = g_wndproc_stage.load(std::memory_order_acquire);
            UINT wndproc_msg = g_wndproc_msg.load(std::memory_order_acquire);
            UINT_PTR wndproc_hwnd = g_wndproc_hwnd.load(std::memory_order_acquire);
            UINT_PTR wndproc_wparam = g_wndproc_wparam.load(std::memory_order_acquire);
            LONG_PTR wndproc_lparam = g_wndproc_lparam.load(std::memory_order_acquire);

            uint64_t age_ms = (last_tick > 0 && now >= last_tick) ? (now - last_tick) : 0;
            bool render_stalled = (last_tick > 0 && age_ms > kStallThresholdMs && frame == prev_frame
                                   && phase_id == prev_render_phase_id);

            if (render_stalled) {
                stall_streak++;
                const uint64_t peek_calls = g_peek_call_count.load(std::memory_order_acquire);
                const uint64_t peek_returns = g_peek_return_count.load(std::memory_order_acquire);
                const bool stuck_in_peek =
                    phase_name && std::strcmp(phase_name, "peek_message_call") == 0 &&
                    peek_calls > peek_returns;
                if (stuck_in_peek && now - last_peek_rescue_ms >= 1000) {
                    last_peek_rescue_ms = now;
                    ::SetLastError(0);
                    BOOL thread_posted = render_tid ? ::PostThreadMessageW(render_tid, WM_NULL, 0, 0) : FALSE;
                    DWORD thread_gle = ::GetLastError();
                    BOOL hwnd_posted = FALSE;
                    DWORD hwnd_gle = 0;
                    HWND rescue_hwnd = aida::qt::main_window_handle();
                    if (rescue_hwnd && ::IsWindow(rescue_hwnd)) {
                        ::SetLastError(0);
                        hwnd_posted = ::PostMessageW(rescue_hwnd, WM_NULL, 0, 0);
                        hwnd_gle = ::GetLastError();
                        ::InvalidateRect(rescue_hwnd, nullptr, FALSE);
                    }
                    diag::log_tagged_critical_fmt("tracer",
                        "peek_rescue frame=%llu age_ms=%llu render_tid=%lu calls=%llu returns=%llu thread_posted=%d thread_gle=%lu hwnd=0x%llX hwnd_posted=%d hwnd_gle=%lu qs=0x%08lX flags=0x%08X",
                        static_cast<unsigned long long>(frame),
                        static_cast<unsigned long long>(age_ms),
                        render_tid,
                        static_cast<unsigned long long>(peek_calls),
                        static_cast<unsigned long long>(peek_returns),
                        thread_posted ? 1 : 0,
                        static_cast<unsigned long>(thread_gle),
                        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(rescue_hwnd)),
                        hwnd_posted ? 1 : 0,
                        static_cast<unsigned long>(hwnd_gle),
                        static_cast<unsigned long>(peek_status),
                        g_peek_remove_flags.load(std::memory_order_acquire));
                }
                if (stall_streak == 1 || (stall_streak % 20ULL) == 0ULL) {
                    aida::diagnostics::metadata_ring::emit_breadcrumb(
                        aida::diagnostics::metadata_ring::breadcrumb_category_t::render,
                        "render_stall_detected", nullptr, false);
                    char stall_context[4600] = {};
                    format_message_pump_stall_context(stall_context, sizeof(stall_context));
                    diag::log_tagged_critical_fmt("tracer",
                        "RENDER_STALL streak=%llu frame=%llu age_ms=%llu phase=%s section=%s phase_id=%llu render_tid=%lu attach=%s attach_id=%llu peek_qs=0x%08lX peek_gle=%lu peek_flags=0x%08X peek_filter=0x%llX send_only_defers=%llu send_only_flushes=%llu dispatch=%s msg=%s(0x%04X) hwnd=0x%llX wp=0x%llX lp=0x%llX wndproc=%s msg=%s(0x%04X) hwnd=0x%llX wp=0x%llX lp=0x%llX tracer_tid=%lu ctx={%.3600s}",
                        (unsigned long long)stall_streak,
                        (unsigned long long)frame,
                        (unsigned long long)age_ms,
                        phase_name ? phase_name : "<null>",
                        render_section ? render_section : "<null>",
                        (unsigned long long)phase_id,
                        render_tid,
                        attach_phase ? attach_phase : "<null>",
                        (unsigned long long)attach_phase_id,
                        static_cast<unsigned long>(peek_status),
                        static_cast<unsigned long>(peek_error),
                        g_peek_remove_flags.load(std::memory_order_acquire),
                        static_cast<unsigned long long>(g_peek_filter_hwnd.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_peek_send_only_defers.load(std::memory_order_acquire)),
                        static_cast<unsigned long long>(g_peek_send_only_flushes.load(std::memory_order_acquire)),
                        dispatch_stage ? dispatch_stage : "<null>",
                        message_name(dispatch_msg),
                        dispatch_msg,
                        (unsigned long long)dispatch_hwnd,
                        (unsigned long long)dispatch_wparam,
                        (unsigned long long)dispatch_lparam,
                        wndproc_stage ? wndproc_stage : "<null>",
                        message_name(wndproc_msg),
                        wndproc_msg,
                        (unsigned long long)wndproc_hwnd,
                        (unsigned long long)wndproc_wparam,
                        (unsigned long long)wndproc_lparam,
                        GetCurrentThreadId(),
                        stall_context[0] ? stall_context : "<empty>");
                    ::emit_window_hung_snapshot(
                        stall_streak,
                        frame,
                        age_ms,
                        phase_id,
                        phase_name,
                        render_section,
                        render_tid,
                        peek_status,
                        peek_error,
                        dispatch_stage,
                        dispatch_msg,
                        dispatch_hwnd,
                        wndproc_stage,
                        wndproc_msg,
                        wndproc_hwnd);
                    const bool shutdown_context = is_shutdown_stall_context(phase_name, dispatch_msg, wndproc_msg);
                    const bool sustained_hang = age_ms >= 2500ULL && (stall_streak == 1ULL || (stall_streak % 20ULL) == 0ULL);
                    if (render_tid != 0 && sustained_hang && !shutdown_context)
                        capture_render_thread_snapshot(render_tid, age_ms);
                }
                static uint64_t s_last_dbghelp_recovery_ms = 0;
                const bool render_disasm_section = render_section &&
                    std::strcmp(render_section, "center_view_disassembly") == 0;
                const bool dbghelp_in_progress = pdb_parser::g_dbghelp_load_state.in_progress;
                const uint64_t dbghelp_started_ms = pdb_parser::g_dbghelp_load_state.started_ms;
                const uint64_t dbghelp_owner_age_ms = (dbghelp_in_progress && dbghelp_started_ms != 0 && now >= dbghelp_started_ms)
                    ? (now - dbghelp_started_ms)
                    : 0ULL;
                const bool dbghelp_actually_stuck = dbghelp_in_progress && dbghelp_owner_age_ms > 30000ULL;
                const bool dbghelp_recovery_eligible = age_ms > 60000ULL && render_disasm_section && dbghelp_actually_stuck &&
                    !is_shutdown_stall_context(phase_name, dispatch_msg, wndproc_msg);
                if (dbghelp_recovery_eligible && (s_last_dbghelp_recovery_ms == 0 ||
                                                  now - s_last_dbghelp_recovery_ms >= 30000ULL)) {
                    s_last_dbghelp_recovery_ms = now;
                    const bool quarantined_before = pdb_parser::dbghelp_is_quarantined();
                    bool quarantine_triggered = false;
                    if (!quarantined_before) {
                        pdb_parser::quarantine_dbghelp_and_recycle();
                        quarantine_triggered = true;
                    }
                    HWND rescue_hwnd = aida::qt::main_window_handle();
                    BOOL nudge_posted = FALSE;
                    DWORD nudge_gle = 0;
                    if (rescue_hwnd && ::IsWindow(rescue_hwnd)) {
                        ::SetLastError(0);
                        nudge_posted = ::PostMessageW(rescue_hwnd, WM_NULL, 0, 0);
                        nudge_gle = ::GetLastError();
                        ::InvalidateRect(rescue_hwnd, nullptr, FALSE);
                    }
                    diag::log_tagged_critical_fmt("tracer",
                        "render_stall_recovery_attempt age_ms=%llu phase=%s section=%s render_tid=%lu dbghelp_in_progress=%d dbghelp_owner_age_ms=%llu quarantine_triggered=%d quarantined_before=%d nudge_posted=%d nudge_gle=%lu",
                        static_cast<unsigned long long>(age_ms),
                        phase_name ? phase_name : "<null>",
                        render_section ? render_section : "<null>",
                        render_tid,
                        dbghelp_in_progress ? 1 : 0,
                        static_cast<unsigned long long>(dbghelp_owner_age_ms),
                        quarantine_triggered ? 1 : 0,
                        quarantined_before ? 1 : 0,
                        nudge_posted ? 1 : 0,
                        static_cast<unsigned long>(nudge_gle));
                } else if (age_ms > 60000ULL && render_disasm_section &&
                           !is_shutdown_stall_context(phase_name, dispatch_msg, wndproc_msg) &&
                           (s_last_dbghelp_recovery_ms == 0 ||
                            now - s_last_dbghelp_recovery_ms >= 30000ULL)) {
                    s_last_dbghelp_recovery_ms = now;
                    diag::log_tagged_critical_fmt("tracer",
                        "render_stall_recovery_skipped age_ms=%llu phase=%s section=%s render_tid=%lu reason=dbghelp_not_in_flight dbghelp_in_progress=%d dbghelp_owner_age_ms=%llu",
                        static_cast<unsigned long long>(age_ms),
                        phase_name ? phase_name : "<null>",
                        render_section ? render_section : "<null>",
                        render_tid,
                        dbghelp_in_progress ? 1 : 0,
                        static_cast<unsigned long long>(dbghelp_owner_age_ms));
                }
            } else {
                stall_streak = 0;
            }

            prev_frame = frame;
            prev_render_phase_id = phase_id;
        }
    }

    inline void start() {
        diag::log_tagged_critical("tracer", "tracer_thread_starting");
        startup_log_critical_fmt("tracer_thread_post_pre pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(GetTickCount64()));
        const auto submit_result = submit_main_executor_task(
            "render",
            "render_tracer",
            aida::infra::executor::domain_t::diagnostics,
            "render_tracer",
            []() {
            startup_log_critical_fmt("tracer_thread_entry pid=%lu tid=%lu tick=%llu",
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(GetTickCount64()));
            run_tracer_thread();
            startup_log_critical_fmt("tracer_thread_exit pid=%lu tid=%lu tick=%llu",
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(GetTickCount64()));
        });
        bool posted = submit_result.submitted;
        startup_log_critical_fmt("tracer_thread_post_post posted=%d pid=%lu tid=%lu tick=%llu",
            posted ? 1 : 0,
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(GetTickCount64()));
        diag::log_tagged_critical("tracer", "tracer_thread_started");
    }

    void format_tracer_crash_snapshot(char* out, size_t cap)
    {
        if (!out || cap == 0)
            return;
        out[0] = 0;
        POINT cursor{};
        GetCursorPos(&cursor);
        const char* render_phase = g_render_phase_name.load(std::memory_order_acquire);
        const char* render_section = g_render_section.c_str();
        const char* dispatch_stage = g_dispatch_stage.load(std::memory_order_acquire);
        const char* wndproc_stage = g_wndproc_stage.load(std::memory_order_acquire);
        _snprintf_s(out, cap, _TRUNCATE,
            "render_frame=%llu render_tick=%llu render_phase=%s render_section=%s render_tid=%lu "
            "peek_qs=0x%08lX peek_gle=%lu peek_flags=0x%08X peek_filter=0x%llX peek_calls=%llu peek_returns=%llu send_only_defers=%llu send_only_flushes=%llu "
            "dispatch_stage=%s dispatch_msg=%s(0x%04X) dispatch_hwnd=0x%llX dispatch_wp=0x%llX dispatch_lp=0x%llX dispatch_enter=%llu dispatch_exit=%llu "
            "wndproc_stage=%s wndproc_msg=%s(0x%04X) wndproc_hwnd=0x%llX wndproc_wp=0x%llX wndproc_lp=0x%llX wnd_enter=%llu wnd_exit=%llu "
            "cursor=%ld,%ld buttons=0x%04X fg=0x%llX active=0x%llX focus=0x%llX capture=0x%llX",
            static_cast<unsigned long long>(g_render_frame.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_render_last_tick_ms.load(std::memory_order_acquire)),
            render_phase ? render_phase : "<null>",
            render_section ? render_section : "<null>",
            g_render_thread_id.load(std::memory_order_acquire),
            static_cast<unsigned long>(g_peek_queue_status.load(std::memory_order_acquire)),
            static_cast<unsigned long>(g_peek_last_error.load(std::memory_order_acquire)),
            g_peek_remove_flags.load(std::memory_order_acquire),
            static_cast<unsigned long long>(g_peek_filter_hwnd.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_peek_call_count.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_peek_return_count.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_peek_send_only_defers.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_peek_send_only_flushes.load(std::memory_order_acquire)),
            dispatch_stage ? dispatch_stage : "<null>",
            message_name(g_dispatch_msg.load(std::memory_order_acquire)),
            g_dispatch_msg.load(std::memory_order_acquire),
            static_cast<unsigned long long>(g_dispatch_hwnd.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_dispatch_wparam.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_dispatch_lparam.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_dispatch_enter_count.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_dispatch_exit_count.load(std::memory_order_acquire)),
            wndproc_stage ? wndproc_stage : "<null>",
            message_name(g_wndproc_msg.load(std::memory_order_acquire)),
            g_wndproc_msg.load(std::memory_order_acquire),
            static_cast<unsigned long long>(g_wndproc_hwnd.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_wndproc_wparam.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_wndproc_lparam.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_wndproc_enter_count.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(g_wndproc_exit_count.load(std::memory_order_acquire)),
            cursor.x,
            cursor.y,
            static_cast<unsigned>((GetAsyncKeyState(VK_LBUTTON) & 0x8000 ? 1u : 0u) |
                (GetAsyncKeyState(VK_RBUTTON) & 0x8000 ? 2u : 0u) |
                (GetAsyncKeyState(VK_MBUTTON) & 0x8000 ? 4u : 0u) |
                (GetAsyncKeyState(VK_XBUTTON1) & 0x8000 ? 8u : 0u) |
                (GetAsyncKeyState(VK_XBUTTON2) & 0x8000 ? 16u : 0u)),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(GetForegroundWindow())),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(GetActiveWindow())),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(GetFocus())),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(GetCapture())));
    }
}

namespace aida_focus_monitor {
    inline std::atomic<bool> g_focused{true};
    inline std::atomic<bool> g_stop{false};

    inline bool foreground_belongs_to_process(HWND hwnd) {
        HWND fg = ::GetForegroundWindow();
        if (!fg) return false;
        if (fg == hwnd) return true;
        DWORD pid = 0;
        ::GetWindowThreadProcessId(fg, &pid);
        return pid == ::GetCurrentProcessId();
    }

    inline void start(HWND hwnd) {
        const uint64_t start_tick = static_cast<uint64_t>(GetTickCount64());
        startup_log_critical_fmt("focus_monitor_start_pre hwnd=0x%llX pid=%lu tid=%lu tick=%llu",
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(start_tick));
        g_stop.store(false, std::memory_order_release);
        g_focused.store(foreground_belongs_to_process(hwnd), std::memory_order_release);
        const auto submit_result = submit_main_executor_task(
            "ui",
            "focus_monitor",
            aida::infra::executor::domain_t::service,
            "long_lived_service",
            [hwnd]() {
            startup_log_critical_fmt("focus_monitor_worker_enter hwnd=0x%llX pid=%lu tid=%lu tick=%llu",
                static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(GetTickCount64()));
            while (!g_stop.load(std::memory_order_acquire)) {
                g_focused.store(foreground_belongs_to_process(hwnd), std::memory_order_release);
                ::Sleep(200);
            }
            startup_log_critical_fmt("focus_monitor_worker_exit hwnd=0x%llX pid=%lu tid=%lu tick=%llu",
                static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(GetTickCount64()));
        });
        bool posted = submit_result.submitted;
        startup_log_critical_fmt("focus_monitor_start_post posted=%d focused=%d elapsed_ms=%llu hwnd=0x%llX",
            posted ? 1 : 0,
            g_focused.load(std::memory_order_acquire) ? 1 : 0,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - start_tick),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)));
    }

    inline void stop() {
        g_stop.store(true, std::memory_order_release);
    }

    inline bool focused() {
        return g_focused.load(std::memory_order_acquire);
    }
}

namespace aida_hotkey_monitor {
    inline std::atomic<bool> g_started{ false };
    inline std::atomic<bool> g_stop{ false };
    inline std::atomic<bool> g_registered{ false };
    inline std::atomic<DWORD> g_thread_id{ 0 };
    inline std::atomic<std::uint64_t> g_last_trigger_ms{ 0 };

    inline bool trigger(HWND hwnd, const char* source, WORD mods, WORD vk, DWORD queue_status) {
        const std::uint64_t now_ms = static_cast<std::uint64_t>(GetTickCount64());
        const std::uint64_t last_ms = g_last_trigger_ms.load(std::memory_order_acquire);
        if (last_ms != 0 && now_ms >= last_ms && now_ms - last_ms < 750ULL)
            return false;
        const bool foreground = aida_focus_monitor::foreground_belongs_to_process(hwnd);
        diag::log_tagged_critical_fmt("ui",
            "test_all_start hotkey=%s id=0x%X mods=0x%04X vk=0x%04X foreground=%d hwnd=0x%llX queue=0x%08lX caller_tid=%lu registered=%d running=%d",
            source && source[0] ? source : "ctrl_shift_t",
            kAidaFullTestHotkeyId,
            static_cast<unsigned>(mods),
            static_cast<unsigned>(vk),
            foreground ? 1 : 0,
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
            static_cast<unsigned long>(queue_status),
            GetCurrentThreadId(),
            g_registered.load(std::memory_order_acquire) ? 1 : 0,
            test_all_features::is_running() ? 1 : 0);
        if (!foreground)
            return false;
        const bool posted = test_all_features::post_hotkey_trigger(source && source[0] ? source : "ctrl_shift_t");
        if (posted)
            g_last_trigger_ms.store(now_ms, std::memory_order_release);
        return posted;
    }

    inline void run(HWND hwnd) {
            const DWORD tid = GetCurrentThreadId();
        g_thread_id.store(tid, std::memory_order_release);
        startup_log_critical_fmt("hotkey_monitor_worker_enter hwnd=0x%llX pid=%lu tid=%lu tick=%llu",
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
            GetCurrentProcessId(),
            tid,
            static_cast<unsigned long long>(GetTickCount64()));
        MSG init_msg{};
        (void)::PeekMessageW(&init_msg, nullptr, WM_USER, WM_USER, PM_NOREMOVE);
        ::SetLastError(0);
        const BOOL registered = ::RegisterHotKey(nullptr,
            kAidaFullTestHotkeyId,
            MOD_CONTROL | MOD_SHIFT | MOD_NOREPEAT,
            'T');
        const DWORD register_gle = ::GetLastError();
        g_registered.store(registered != FALSE, std::memory_order_release);
        startup_log_critical_fmt("hotkey_register ctrl_shift_t worker ok=%d id=0x%X tid=%lu gle=%lu hwnd=0x%llX",
            registered ? 1 : 0,
            kAidaFullTestHotkeyId,
            tid,
            static_cast<unsigned long>(register_gle),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)));
        bool chord_latched = false;
        while (!g_stop.load(std::memory_order_acquire)) {
            const DWORD wait_result = ::MsgWaitForMultipleObjectsEx(0, nullptr, 25, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
            if (wait_result == WAIT_OBJECT_0) {
                for (unsigned drained = 0; drained < 32; ++drained) {
                    MSG msg{};
                    ::SetLastError(0);
                    if (!::PeekMessageW(&msg, nullptr, 0U, 0U, PM_REMOVE))
                        break;
                    if (msg.message == WM_QUIT) {
                        g_stop.store(true, std::memory_order_release);
                        break;
                    }
                    if (msg.message == WM_HOTKEY && static_cast<int>(msg.wParam) == kAidaFullTestHotkeyId) {
                        const WORD mods = LOWORD(msg.lParam);
                        const WORD vk = HIWORD(msg.lParam);
                        (void)trigger(hwnd, "worker_wm_hotkey_ctrl_shift_t", mods, vk, kAidaQueueStatusUnavailable);
                        continue;
                    }
                    if (msg.hwnd) {
                        ::TranslateMessage(&msg);
                        ::DispatchMessageW(&msg);
                    }
                }
            }
            const bool chord_down = aida_ctrl_shift_t_chord_down();
            if (chord_down && !chord_latched)
                (void)trigger(hwnd, "worker_async_ctrl_shift_t", static_cast<WORD>(MOD_CONTROL | MOD_SHIFT), 'T', kAidaQueueStatusUnavailable);
            chord_latched = chord_down;
        }
        if (g_registered.exchange(false, std::memory_order_acq_rel)) {
            ::SetLastError(0);
            const BOOL unregistered = ::UnregisterHotKey(nullptr, kAidaFullTestHotkeyId);
            startup_log_critical_fmt("hotkey_unregister ctrl_shift_t worker ok=%d id=0x%X tid=%lu gle=%lu",
                unregistered ? 1 : 0,
                kAidaFullTestHotkeyId,
                tid,
                static_cast<unsigned long>(GetLastError()));
        }
        g_thread_id.store(0, std::memory_order_release);
        g_started.store(false, std::memory_order_release);
        startup_log_critical_fmt("hotkey_monitor_worker_exit hwnd=0x%llX pid=%lu tid=%lu tick=%llu",
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
            GetCurrentProcessId(),
            tid,
            static_cast<unsigned long long>(GetTickCount64()));
    }

    inline void start(HWND hwnd) {
        const uint64_t start_tick = static_cast<uint64_t>(GetTickCount64());
        startup_log_critical_fmt("hotkey_monitor_start_pre hwnd=0x%llX pid=%lu tid=%lu tick=%llu",
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(start_tick));
        bool expected = false;
        if (!g_started.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
            startup_log_critical_fmt("hotkey_monitor_start_already_active hwnd=0x%llX worker_tid=%lu",
                static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
                g_thread_id.load(std::memory_order_acquire));
            return;
        }
        g_stop.store(false, std::memory_order_release);
        const auto submit_result = submit_main_executor_task(
            "ui",
            "hotkey_monitor",
            aida::infra::executor::domain_t::service,
            "long_lived_service",
            [hwnd]() {
            run(hwnd);
        });
        bool posted = submit_result.submitted;
        if (!posted) {
            g_started.store(false, std::memory_order_release);
            g_stop.store(true, std::memory_order_release);
        }
        startup_log_critical_fmt("hotkey_monitor_start_post posted=%d elapsed_ms=%llu hwnd=0x%llX worker_tid=%lu",
            posted ? 1 : 0,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - start_tick),
            static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
            g_thread_id.load(std::memory_order_acquire));
    }

    inline void stop() {
        g_stop.store(true, std::memory_order_release);
        const DWORD tid = g_thread_id.load(std::memory_order_acquire);
        BOOL posted = FALSE;
        DWORD gle = 0;
        if (tid != 0) {
            ::SetLastError(0);
            posted = ::PostThreadMessageW(tid, WM_QUIT, 0, 0);
            gle = ::GetLastError();
        }
        startup_log_critical_fmt("hotkey_monitor_stop tid=%lu posted=%d gle=%lu registered=%d",
            tid,
            posted ? 1 : 0,
            static_cast<unsigned long>(gle),
            g_registered.load(std::memory_order_acquire) ? 1 : 0);
    }
}

namespace aida_shutdown_diag {
    inline std::atomic<const char*> g_phase{"running"};
    inline std::atomic<uint64_t> g_phase_tick_ms{0};

    void mark(const char* phase)
    {
        const char* value = phase ? phase : "<null>";
        g_phase.store(value, std::memory_order_release);
        g_phase_tick_ms.store(static_cast<uint64_t>(GetTickCount64()), std::memory_order_release);
        diag::log_tagged_critical_fmt("shutdown",
            "phase=%s pid=%lu tid=%lu tick=%llu",
            value,
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(GetTickCount64()));
    }

    uint64_t phase_age_ms()
    {
        const uint64_t tick = g_phase_tick_ms.load(std::memory_order_acquire);
        const uint64_t now = static_cast<uint64_t>(GetTickCount64());
        return tick != 0 && now >= tick ? now - tick : 0;
    }

    const char* phase_name()
    {
        return g_phase.load(std::memory_order_acquire);
    }
}

static DWORD count_current_process_threads(DWORD* err_out)
{
    if (err_out)
        *err_out = 0;
    const DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        if (err_out)
            *err_out = GetLastError();
        return 0;
    }
    THREADENTRY32 te = {};
    te.dwSize = sizeof(te);
    DWORD count = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid)
                ++count;
            te.dwSize = sizeof(te);
        } while (Thread32Next(snap, &te));
    } else if (err_out) {
        *err_out = GetLastError();
    }
    CloseHandle(snap);
    return count;
}

static void format_message_pump_stall_context(char* out, size_t cap)
{
    if (!out || cap == 0)
        return;
    out[0] = 0;
    char full_snapshot[1700] = {};
    char ui_phase[900] = {};
    char ui_dispatch[900] = {};
    char queue_snapshot[2600] = {};
    test_all_features::format_debug_snapshot(full_snapshot, sizeof(full_snapshot));
    test_all_features::format_ui_phase_snapshot(ui_phase, sizeof(ui_phase));
    aida::ui_thread::format_snapshot(ui_dispatch, sizeof(ui_dispatch));
    aida::qt::crash_integration::format_taskflow_runtime_crash_snapshot(queue_snapshot, sizeof(queue_snapshot));
    DWORD thread_err = 0;
    const DWORD threads = count_current_process_threads(&thread_err);
    DWORD handles = 0;
    const BOOL handle_ok = GetProcessHandleCount(GetCurrentProcess(), &handles);
    const DWORD handle_err = handle_ok ? 0UL : GetLastError();
    const char* render_phase = aida_tracer::crash_render_phase_name();
    const char* render_section = g_render_section.c_str();
    const char* dispatch_stage = aida_tracer::crash_dispatch_stage();
    const char* wndproc_stage = aida_tracer::crash_wndproc_stage();
    _snprintf_s(out, cap, _TRUNCATE,
        "pid=%lu tid=%lu threads=%lu thread_err=%lu handles=%lu handle_ok=%d handle_err=%lu "
        "render_phase=%s render_section=%s dispatch_stage=%s dispatch_msg=%s(0x%04X) wndproc_stage=%s wndproc_msg=%s(0x%04X) "
        "full_test_running=%d ui={%.760s} ui_dispatch={%.760s} full={%.1200s} queues={%.1800s}",
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        static_cast<unsigned long>(threads),
        static_cast<unsigned long>(thread_err),
        static_cast<unsigned long>(handles),
        handle_ok ? 1 : 0,
        static_cast<unsigned long>(handle_err),
        render_phase ? render_phase : "<null>",
        render_section ? render_section : "<null>",
        dispatch_stage ? dispatch_stage : "<null>",
        aida_tracer::message_name(aida_tracer::crash_dispatch_msg()),
        aida_tracer::crash_dispatch_msg(),
        wndproc_stage ? wndproc_stage : "<null>",
        aida_tracer::message_name(aida_tracer::crash_wndproc_msg()),
        aida_tracer::crash_wndproc_msg(),
        test_all_features::is_running() ? 1 : 0,
        ui_phase[0] ? ui_phase : "<empty>",
        ui_dispatch[0] ? ui_dispatch : "<empty>",
        full_snapshot[0] ? full_snapshot : "<empty>",
        queue_snapshot[0] ? queue_snapshot : "<empty>");
}

static void emit_window_hung_snapshot(
    uint64_t stall_streak,
    uint64_t frame,
    uint64_t age_ms,
    uint64_t phase_id,
    const char* phase_name,
    const char* render_section,
    DWORD render_tid,
    DWORD peek_status,
    DWORD peek_error,
    const char* dispatch_stage,
    UINT dispatch_msg,
    UINT_PTR dispatch_hwnd,
    const char* wndproc_stage,
    UINT wndproc_msg,
    UINT_PTR wndproc_hwnd)
{
    constexpr UINT kSendTimeoutFlags = SMTO_ABORTIFHUNG | SMTO_ERRORONEXIT;
    constexpr UINT kSendTimeoutMs = 50U;
    char mcp_snapshot[1400] = {};
    char queue_snapshot[3000] = {};
    char ui_dispatch_snapshot[1400] = {};
    mcp_standalone::format_runtime_diagnostic_snapshot(mcp_snapshot, sizeof(mcp_snapshot));
    aida::qt::crash_integration::format_taskflow_runtime_hung_snapshot(queue_snapshot, sizeof(queue_snapshot));
    aida::ui_thread::format_snapshot(ui_dispatch_snapshot, sizeof(ui_dispatch_snapshot));

    HWND hwnd = aida::qt::main_window_handle();
    const BOOL hwnd_valid = hwnd ? ::IsWindow(hwnd) : FALSE;
    DWORD hwnd_pid = 0;
    DWORD ui_owner_tid = hwnd_valid ? ::GetWindowThreadProcessId(hwnd, &hwnd_pid) : 0;
    BOOL is_hung = FALSE;
    DWORD_PTR send_lresult = 0;
    BOOL send_ok = FALSE;
    DWORD send_gle = ERROR_INVALID_WINDOW_HANDLE;
    if (hwnd_valid) {
        is_hung = ::IsHungAppWindow(hwnd);
        ::SetLastError(0);
        send_ok = static_cast<BOOL>(::SendMessageTimeoutW(hwnd, WM_NULL, 0, 0, kSendTimeoutFlags, kSendTimeoutMs, &send_lresult) != 0);
        send_gle = send_ok ? 0UL : ::GetLastError();
    }

    const uint64_t now_ms = static_cast<uint64_t>(::GetTickCount64());
    const uint64_t last_render_tick = aida_tracer::g_render_last_tick_ms.load(std::memory_order_acquire);
    const DWORD current_queue_status = kAidaQueueStatusUnavailable;

    char testlab_step_buf[260] = {};
    uint64_t testlab_step_start = 0;
    test_all_features::current_phase_and_step(nullptr, 0, testlab_step_buf, sizeof(testlab_step_buf), &testlab_step_start);
    const uint64_t testlab_step_elapsed = (testlab_step_start != 0 && now_ms >= testlab_step_start)
        ? (now_ms - testlab_step_start) : 0;
    const uint64_t input_event_age = (g_last_input_event_tick_ms != 0 && now_ms >= g_last_input_event_tick_ms)
        ? (now_ms - g_last_input_event_tick_ms) : 0;

    mcp_standalone::bounded_diag_snapshot_t bdiag = mcp_standalone::bounded_diagnostic_snapshot();
    std::string top_labels = aida::ui_thread::top_queued_labels(8);

    aida::diagnostics::window_hung::hung_context_t hctx;
    hctx.hwnd = hwnd;
    hctx.ui_owner_tid = ui_owner_tid;
    hctx.current_tid = ::GetCurrentThreadId();
    hctx.is_hung = is_hung;
    hctx.send_wm_null_ok = send_ok;
    hctx.send_wm_null_gle = send_gle;
    hctx.send_wm_null_lresult = static_cast<DWORD_PTR>(send_lresult);
    hctx.send_timeout_ms = kSendTimeoutMs;
    hctx.send_flags = kSendTimeoutFlags;
    hctx.peek_queue_status = peek_status;
    hctx.current_queue_status = current_queue_status;
    hctx.peek_gle = peek_error;
    hctx.peek_remove_flags = aida_tracer::g_peek_remove_flags.load(std::memory_order_acquire);
    hctx.peek_filter_hwnd = static_cast<std::uint64_t>(aida_tracer::g_peek_filter_hwnd.load(std::memory_order_acquire));
    hctx.peek_call_count = aida_tracer::g_peek_call_count.load(std::memory_order_acquire);
    hctx.peek_return_count = aida_tracer::g_peek_return_count.load(std::memory_order_acquire);
    hctx.send_only_defers = aida_tracer::g_peek_send_only_defers.load(std::memory_order_acquire);
    hctx.send_only_flushes = aida_tracer::g_peek_send_only_flushes.load(std::memory_order_acquire);
    hctx.stall_streak = stall_streak;
    hctx.frame = frame;
    hctx.heartbeat_tick_ms = last_render_tick;
    hctx.heartbeat_age_ms = age_ms;
    hctx.phase_name = phase_name;
    hctx.render_section = render_section;
    hctx.phase_id = phase_id;
    hctx.dispatch_stage = dispatch_stage;
    hctx.dispatch_msg = dispatch_msg;
    hctx.dispatch_hwnd = static_cast<UINT_PTR>(dispatch_hwnd);
    hctx.wndproc_stage = wndproc_stage;
    hctx.wndproc_msg = wndproc_msg;
    hctx.wndproc_hwnd = static_cast<UINT_PTR>(wndproc_hwnd);
    hctx.render_tid = render_tid;
    hctx.last_input_event_ms = input_event_age;
    hctx.last_successful_pump_return_ms = 0;
    hctx.ui_dispatcher_queue_depth = aida::ui_thread::pending_count();
    hctx.ui_dispatcher_oldest_queued_age_ms = aida::ui_thread::oldest_queued_age_ms();
    hctx.ui_dispatcher_wake_pending = aida::ui_thread::wake_pending();
    hctx.ui_dispatcher_rejected_count = aida::ui_thread::rejected_count();
    hctx.ui_dispatcher_drained_count = aida::ui_thread::drained_count();
    hctx.ui_dispatcher_budget_hit_count = aida::ui_thread::budget_hit_count();
    hctx.ui_dispatcher_time_budget_hit_count = aida::ui_thread::time_budget_hit_count();
    hctx.ui_dispatcher_affinity_violations = aida::ui_thread::affinity_violation_count();
    hctx.ui_dispatcher_top_labels = top_labels.c_str();
    hctx.mcp_active_requests = bdiag.active_requests;
    hctx.mcp_active_leases = bdiag.active_leases;
    hctx.mcp_oldest_owner = bdiag.oldest_owner;
    hctx.mcp_pending_cancellation_count = bdiag.pending_cancellations;
    hctx.capacity_pressure = bdiag.capacity_snapshot;
    hctx.downstream_pressure = bdiag.downstream_snapshot;
    hctx.testlab_step = testlab_step_buf;
    hctx.testlab_step_elapsed_ms = testlab_step_elapsed;
    hctx.driver_watchdog_ms = driver_bridge::driver_watchdog_age_ms();
    hctx.mcp_snapshot = mcp_snapshot;
    hctx.queue_snapshot = queue_snapshot;
    hctx.ui_dispatch_snapshot = ui_dispatch_snapshot;
    aida::diagnostics::window_hung::log_window_hung_snapshot(hctx);
    aida::diagnostics::window_hung::emit_hung_breadcrumb(hwnd, age_ms, phase_name);
}

int main(int argc, char** argv)
{
    aida_early_startup::install();
    aida_early_startup::mark("main_enter");
    aida_early_startup::mark("diagnostic_exception_scope_initialize_pre");
    bool diagnostic_scope_ready = aida::diagnostic_exception_scope::initialize();
    aida_early_startup::mark(diagnostic_scope_ready ? "diagnostic_exception_scope_initialized" : "diagnostic_exception_scope_failed");
    aida_early_startup::mark("diagnostic_veh_install_pre");
    PVOID diagnostic_veh = aida::qt::crash_integration::install_diagnostic_veh();
    aida_early_startup::mark(diagnostic_veh ? "diagnostic_veh_installed" : "diagnostic_veh_install_failed");
    aida_early_startup::mark("normal_diag_log_pre");
    diag::log_tagged_critical("main", "diagnostic_veh_installed");
    aida::ui_thread::capture_owner_tid(::GetCurrentThreadId(), "main", "startup", "main_enter");
    command_sessions::set_ui_thread_id(::GetCurrentThreadId());
    aida::infra::executor::set_ui_owner_tid(::GetCurrentThreadId());
    aida::infra::taskflow_eval::log_evaluation();
    diag::log_tagged_critical_fmt("startup",
        "startup_begin pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    aida_early_startup::mark_normal_diagnostics_reached();
    aida_early_startup::mark("disk_backed_startup_state_pre");
    log_disk_backed_startup_state("post_veh");
    aida_early_startup::mark("normal_startup_state_logged");
    aida_early_startup::mark("single_instance_gate_pre");
    const aida::qt::AidaSingleInstance::AcquireResult gate_result = aida::qt::AidaSingleInstance::acquire_process_gate();
    if (gate_result != aida::qt::AidaSingleInstance::AcquireResult::primary) {
        diag::log_tagged_critical("main", "single_instance_gate_refused");
        aida_early_startup::mark("single_instance_gate_refused");
        return 0;
    }
    aida_early_startup::mark("single_instance_gate_acquired");
    aida_early_startup::mark("post_gate_main_enter_pre");
    startup_log_critical_fmt("main_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    crash_log_write("main_enter");
    aida_early_startup::mark("post_gate_main_enter_done");

    aida_early_startup::mark("post_gate_taskflow_pool_query_pre");
    const int taskflow_general_pool_size = aida::infra::taskflow_runtime::general_pool_size();
    const int taskflow_service_pool_size = aida::infra::taskflow_runtime::service_pool_size();
    const int taskflow_critical_pool_size = aida::infra::taskflow_runtime::domain_pool(
        aida::infra::taskflow_runtime::executor_domain_t::critical).configured_pool_size;
    aida_early_startup::mark("post_gate_taskflow_pool_query_done");
    startup_log_critical_fmt("taskflow_runtime_initialize_pre pid=%lu tid=%lu tick=%llu general_pool_size=%d service_pool_size=%d critical_pool_size=%d",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()),
        taskflow_general_pool_size,
        taskflow_service_pool_size,
        taskflow_critical_pool_size);
    aida_early_startup::mark("post_gate_taskflow_initialize_pre");
    aida::infra::taskflow_runtime::initialize();
    aida_early_startup::mark("post_gate_taskflow_initialize_done");
    const auto taskflow_init_snapshot = aida::infra::taskflow_runtime::active_snapshot();
    startup_log_critical_fmt("taskflow_runtime_initialize_post pid=%lu tid=%lu tick=%llu accepting=%d shutdown=%d total_active=%u work_pending=%llu service_pending=%llu critical_pending=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()),
        taskflow_init_snapshot.accepting ? 1 : 0,
        taskflow_init_snapshot.shutting_down ? 1 : 0,
        static_cast<unsigned>(taskflow_init_snapshot.total_active),
        static_cast<unsigned long long>(taskflow_init_snapshot.work_queue_pending),
        static_cast<unsigned long long>(taskflow_init_snapshot.service_queue_pending),
        static_cast<unsigned long long>(taskflow_init_snapshot.critical_queue_pending));
    crash_log_write("taskflow_runtime_init_ok");
    aida_early_startup::mark("post_gate_taskflow_runtime_init_ok");
    phase0_post_wer_configuration_logging("post_taskflow_runtime_init");
    aida::diagnostics::metadata_ring::emit_breadcrumb(
        aida::diagnostics::metadata_ring::breadcrumb_category_t::startup_shutdown,
        "standalone_startup_begin", "phase0_complete", true);
    aida::diagnostics::wer::log_wer_correlation("startup");

    aida_early_startup::mark("post_gate_tracer_start_pre");
    startup_log_critical_fmt("tracer_start_pre pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    aida_tracer::start();
    aida_early_startup::mark("post_gate_tracer_start_done");
    startup_log_critical_fmt("tracer_start_post pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));

    aida_early_startup::mark("post_gate_unhandled_exception_filter_set_pre");
    aida::qt::crash_integration::install_unhandled_exception_filter();
    crash_log_write("exception_filter_set");
    aida_early_startup::mark("post_gate_exception_filter_set");

    std::set_terminate([]() noexcept {
        const std::exception_ptr eptr = std::current_exception();
        if (eptr) {
            try {
                std::rethrow_exception(eptr);
            } catch (const std::exception& ex) {
                startup_log_critical_fmt("terminate_cpp_exception type=%s what=%s tid=%lu",
                    typeid(ex).name(), ex.what(),
                    static_cast<unsigned long>(::GetCurrentThreadId()));
            } catch (...) {
                crash_log_write("terminate_cpp_exception_nonstd");
            }
        } else {
            crash_log_write("terminate_no_active_exception");
        }
        std::abort();
    });
    crash_log_write("terminate_handler_set");

    {
        aida_early_startup::mark("post_gate_settings_load_pre");
        const uint64_t settings_tick = static_cast<uint64_t>(GetTickCount64());
        startup_log_critical_fmt("settings_load_pre pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(settings_tick));
        bool settings_loaded = g_sa_settings.load();
        aida_early_startup::mark("post_gate_settings_load_done");
        g_sa_settings.editor_line_numbers   = true;
        g_sa_settings.editor_word_wrap      = true;
        g_sa_settings.editor_minimap        = true;
        g_sa_settings.editor_bracket_match  = true;
        g_sa_settings.editor_highlight_line = true;
        g_sa_settings.editor_auto_complete  = true;
        g_sa_settings.ghost_text_enabled    = true;
        g_sa_settings.auto_save_enabled     = true;
        crash_log_fmt("startup_settings_loaded=%d", settings_loaded ? 1 : 0);
        startup_log_critical_fmt("settings_load_post loaded=%d elapsed_ms=%llu",
            settings_loaded ? 1 : 0,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - settings_tick));
    }

    aida_early_startup::mark("post_gate_appusermodelid_pre");
    HRESULT aumid_hr = ::SetCurrentProcessExplicitAppUserModelID(L"AiDA.Standalone.IDE");
    startup_log_critical_fmt("appusermodelid hr=0x%08lX",
        static_cast<unsigned long>(aumid_hr));

    aida_early_startup::mark("post_gate_appusermodelid_done");

    aida_early_startup::mark("post_gate_dpi_awareness_pre");
    startup_log_critical_fmt("dpi_awareness_pre pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    startup_log_critical_fmt("dpi_awareness_post last_err=%lu",
        static_cast<unsigned long>(GetLastError()));
    crash_log_write("dpi_awareness_set");
    aida_early_startup::mark("post_gate_dpi_awareness_done");

    QGuiApplication::setHighDpiScaleFactorRoundingPolicy(
        Qt::HighDpiScaleFactorRoundingPolicy::RoundPreferFloor);
    crash_log_write("hidpi_rounding_policy=RoundPreferFloor");

    QCoreApplication::setApplicationName("AiDAStandalone");
    QCoreApplication::setOrganizationName("AiDA");
    aida::qt::AidaApplication app(argc, argv);
    Q_INIT_RESOURCE(aida);
    aida::qt::install_qt_message_handler();
    if (QScreen* primary_screen = QGuiApplication::primaryScreen()) {
        const QSizeF physical_mm = primary_screen->physicalSize();
        crash_log_fmt("qt_screen primary name=%s logical=%dx%d physical_mm=%.0fx%.0f dpr=%.3f logical_dpi=%.1f physical_dpi=%.1f screens=%d",
            primary_screen->name().toUtf8().constData(),
            primary_screen->size().width(),
            primary_screen->size().height(),
            static_cast<double>(physical_mm.width()),
            static_cast<double>(physical_mm.height()),
            static_cast<double>(primary_screen->devicePixelRatio()),
            static_cast<double>(primary_screen->logicalDotsPerInch()),
            static_cast<double>(primary_screen->physicalDotsPerInch()),
            static_cast<int>(QGuiApplication::screens().size()));
    }
    app.setQuitOnLastWindowClosed(false);
    const bool theme_installed = aida::qt::theme::AidaThemeController::instance().installIntoApplication(app);
    diag::log_tagged_fmt("qt_shell", "theme_installed ok=%d", theme_installed ? 1 : 0);

    const ads::CDockManager::ConfigFlags qads_config_flags =
        ads::CDockManager::FocusHighlighting
        | ads::CDockManager::OpaqueSplitterResize
        | ads::CDockManager::DragPreviewShowsContentPixmap
        | ads::CDockManager::DragPreviewHasWindowFrame
        | ads::CDockManager::DragPreviewIsDynamic
        | ads::CDockManager::ActiveTabHasCloseButton
        | ads::CDockManager::AllTabsHaveCloseButton
        | ads::CDockManager::RetainTabSizeWhenCloseButtonHidden
        | ads::CDockManager::DockAreaHasCloseButton
        | ads::CDockManager::DockAreaCloseButtonClosesTab
        | ads::CDockManager::DockAreaHasUndockButton
        | ads::CDockManager::DockAreaHasTabsMenuButton
        | ads::CDockManager::DockAreaDynamicTabsMenuButtonVisibility
        | ads::CDockManager::FloatingContainerHasWidgetTitle
        | ads::CDockManager::FloatingContainerHasWidgetIcon;
    ads::CDockManager::setConfigFlags(qads_config_flags);
    diag::log_tagged_critical_fmt("qt_shell",
        "qads_config_flags_set mask=0x%08X tid=%lu",
        static_cast<unsigned>(qads_config_flags.toInt()),
        static_cast<unsigned long>(::GetCurrentThreadId()));

    aida::qt::UiDispatcher* ui_dispatcher = aida::qt::create_ui_dispatcher(&app);
    (void)ui_dispatcher;
    aida::qt::set_gui_post([](std::function<void()> fn) {
        QMetaObject::invokeMethod(aida::qt::ui_dispatcher_instance(), std::move(fn),
            Qt::QueuedConnection);
    });
    diag::log_tagged("qt_shell", "gui_post_installed");

    const int screen_w = GetSystemMetrics(SM_CXSCREEN);
    const int screen_h = GetSystemMetrics(SM_CYSCREEN);
    crash_log_fmt("screen=%dx%d", screen_w, screen_h);

    aida::qt::AidaMainWindow window;
    window.setWindowTitle(QStringLiteral("AiDA"));
    window.setWindowIcon(QIcon(":/img/aidalogo.png"));
    const HWND aida_hwnd = reinterpret_cast<HWND>(window.winId());
    window.applyDwmBackdrop();
    crash_log_fmt("hwnd=%p", aida_hwnd);

    QSettings settings(QSettings::IniFormat, QSettings::UserScope, "AiDA", "AiDAStandalone");
    const QByteArray saved_geometry = settings.value(QStringLiteral("geometry")).toByteArray();
    bool geometry_restored = false;
    if (!saved_geometry.isEmpty()) {
        geometry_restored = window.restoreGeometry(saved_geometry);
        diag::log_tagged_fmt("qt_shell",
            "window_geometry_restore ok=%d bytes=%lld",
            geometry_restored ? 1 : 0,
            static_cast<long long>(saved_geometry.size()));
    }
    if (!geometry_restored) {
        if (QScreen* screen = window.screen()) {
            const QRect area = screen->availableGeometry();
            qreal normal_w = area.width() * 0.75;
            qreal normal_h = area.height() * 0.75;
            if (normal_w < 1000.0 && area.width() >= 1000)
                normal_w = qMin<qreal>(static_cast<qreal>(area.width()), 1000.0);
            if (normal_h < 600.0 && area.height() >= 600)
                normal_h = qMin<qreal>(static_cast<qreal>(area.height()), 600.0);
            window.setGeometry(
                area.left() + static_cast<int>((area.width() - normal_w) * 0.5),
                area.top() + static_cast<int>((area.height() - normal_h) * 0.5),
                static_cast<int>(normal_w), static_cast<int>(normal_h));
        }
    }
    window.setFileOpenHandler([](const std::string& path) {
        aida::qt::explorer::open_path(path);
    });

    aida::qt::chrome::bind_legacy_chrome_hooks();
    auto* chrome = aida::qt::chrome::composeChrome(&window);

    aida::qt::AidaEventLoopMonitor eventloop_monitor;
    aida::qt::AidaEventLoopMonitor::tracer_hooks_t tracer_hooks;
    tracer_hooks.render_pulse = [](std::uint64_t frame) { aida_tracer::render_pulse(frame); };
    tracer_hooks.mark_render_phase = [](const char* name) { aida_tracer::mark_render_phase(name); };
    eventloop_monitor.setTracerHooks(tracer_hooks);
    eventloop_monitor.start();
    eventloop_monitor.setObservedWindow(aida_hwnd);

    if (geometry_restored)
        window.show();
    else
        window.showMaximized();
    crash_log_write("window_shown");
    aida_hotkey_monitor::start(aida_hwnd);
    aida::ui_thread::mark_ready("main", "ui_dispatcher", "post_init");

    aida::qt::AidaSessionBridge session_bridge;
    session_bridge.install();
    session_bridge.setExitReviewGateHook([] {
        auto* composer = aida::qt::chrome::chromeComposer();
        return composer && composer->exitReview() ? composer->exitReview()->gateHook() : true;
    });
    session_bridge.setSessionAbortHook([] {
        auto* composer = aida::qt::chrome::chromeComposer();
        if (composer && composer->exitReview())
            composer->exitReview()->onSessionAbort();
    });

    aida::qt::AidaSingleInstance single_instance;
    if (!single_instance.startServer(&window)) {
        diag::log_tagged_critical("qt_shell", "single_instance_server_start_failed");
    }

    aida::qt::AidaStartupOrchestrator orchestrator;
    chrome->bindOrchestrator(&orchestrator);
    orchestrator.kickoffBackgroundInit();

    const bool layout_restored = window.dockHost()->restoreOrBuildDefault();
    diag::log_tagged_critical_fmt("qt_shell",
        "dock_host_restore_or_build_default ok=%d tid=%lu",
        layout_restored ? 1 : 0,
        static_cast<unsigned long>(::GetCurrentThreadId()));

    crash_log_write("entering_render_loop");
    startup_log_critical_fmt("focus_monitor_main_start_pre hwnd=0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(aida_hwnd)));
    aida_focus_monitor::start(aida_hwnd);
    const int ui_prior_priority = GetThreadPriority(GetCurrentThread());
    const BOOL ui_priority_set = SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
    startup_log_critical_fmt("render_loop_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    diag::log_tagged_critical_fmt("render",
        "ui_thread_priority prior=%d set=%d current=%d gle=%lu",
        ui_prior_priority,
        ui_priority_set ? 1 : 0,
        GetThreadPriority(GetCurrentThread()),
        ui_priority_set ? 0UL : GetLastError());

    QObject::connect(&app, &QCoreApplication::aboutToQuit, &app, [&window, &eventloop_monitor]() {
        aida_shutdown_diag::mark("shutdown_sequence_begin");
        aida::diagnostics::metadata_ring::emit_breadcrumb(
            aida::diagnostics::metadata_ring::breadcrumb_category_t::startup_shutdown,
            "standalone_shutdown_begin", "cleanup_starting", true);
        aida::diagnostics::metadata_ring::request_shutdown();
        aida::diagnostics::observer::stop();
        eventloop_monitor.stop();
        diag::log_tagged_critical_fmt("main",
            "shutdown_sequence_begin hwnd=0x%llX tid=%lu",
            (unsigned long long)reinterpret_cast<UINT_PTR>(aida::qt::main_window_handle()),
            GetCurrentThreadId());
        aida_tracer::mark_render_phase("shutdown_sequence_begin");
        aida::ui_thread::mark_window_destroying("main", "about_to_quit", "defensive");
        aida::ui_thread::shutdown();
        {
            char queue_snapshot[2400] = {};
            aida::qt::crash_integration::format_taskflow_runtime_crash_snapshot(queue_snapshot, sizeof(queue_snapshot));
            diag::log_tagged_critical_fmt("main", "shutdown_queue_snapshot_pre %s", queue_snapshot);
        }
        aida_shutdown_diag::mark("shutdown_testlab_cancel");
        test_all_features::cancel_tests();
        diag::log_tagged_critical("main", "shutdown_testlab_cancel_done");
        aida_shutdown_diag::mark("shutdown_camoufox_force_cleanup");
        try {
            aida::burp::camoufox::force_cleanup("main.shutdown_sequence");
            diag::log_tagged_critical("main", "shutdown_camoufox_force_cleanup_done");
        } catch (...) {
            aida::diagnostics::crash::emit_crash_breadcrumb(0xE06D7363u, nullptr, "shutdown_camoufox_force_cleanup");
            diag::log_tagged_critical("main", "shutdown_camoufox_force_cleanup_exception");
        }
        aida_shutdown_diag::mark("shutdown_hotkey_monitor");
        aida_hotkey_monitor::stop();
        diag::log_tagged_critical("main", "shutdown_hotkey_monitor_done");
        aida_shutdown_diag::mark("shutdown_focus_monitor");
        aida_focus_monitor::stop();
        diag::log_tagged_critical("main", "shutdown_focus_monitor_done");
        aida_shutdown_diag::mark("shutdown_prelude_begin");
        diag::log_tagged_critical("main", "shutdown_prelude_begin");
        aida_shutdown_diag::mark("shutdown_driver_bridge_deferred");
        diag::log_tagged_critical("main", "shutdown_driver_bridge_deferred reason=queue_drain_required");
        aida_shutdown_diag::mark("shutdown_prelude_done");
        diag::log_tagged_critical("main", "shutdown_prelude_done");
        aida_shutdown_diag::mark("shutdown_terminal");
        aida::qt::programming::host::shutdown_terminal();
        diag::log_tagged_critical("main", "shutdown_terminal_done");
        aida_shutdown_diag::mark("shutdown_network");
        aida::qt::net::shutdown_network_domain();
        diag::log_tagged_critical("main", "shutdown_network_done");
        aida_shutdown_diag::mark("shutdown_script_engine");
        script_engine::shutdown();
        diag::log_tagged_critical("main", "shutdown_script_engine_done");
        aida_shutdown_diag::mark("shutdown_workflow_tools");
        workflow_tools::shutdown_services();
        diag::log_tagged_critical("main", "shutdown_workflow_tools_done");
        aida_shutdown_diag::mark("shutdown_chat");
        ::shutdown_standalone_chat();
        diag::log_tagged_critical("main", "shutdown_chat_done");
        aida_shutdown_diag::mark("shutdown_auth_http");
        aida::auth::http::cleanup();
        diag::log_tagged_critical("main", "shutdown_auth_http_done");
        aida_shutdown_diag::mark("shutdown_ide_shell");
        {
            QSettings layout_settings(QSettings::IniFormat, QSettings::UserScope, "AiDA", "AiDAStandalone");
            layout_settings.setValue(QStringLiteral("geometry"), window.saveGeometry());
        }
        diag::log_tagged_critical("main", "shutdown_geometry_saved");
        aida_shutdown_diag::mark("shutdown_executor");
        aida::infra::executor::shutdown();
        diag::log_tagged_critical("main", "shutdown_executor_done");
        aida_shutdown_diag::mark("shutdown_event_bus");
        aida::events::shutdown();
        diag::log_tagged_critical("main", "shutdown_event_bus_done");
        aida_shutdown_diag::mark("shutdown_exit_process");
        diag::log_tagged_critical("main", "shutdown_exit_process_pre");
    }, Qt::DirectConnection);

    aida_early_startup::mark("qt_exec_enter");
    app.exec();
    aida_early_startup::mark("qt_exec_exit");

    aida::qt::AidaSingleInstance::release_process_gate();
    aida_early_startup::mark("main_exit");
    diag::flush_async_logs(5000);
    return 0;
}
