#include "qt/qt_startup_orchestrator.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <QMetaObject>

#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <string>

#include "helpers/diag_log.hpp"
#include "core/ai/standalone_chat.hpp"
#include "core/diagnostics/crash_snapshot.hpp"
#include "core/infra/executor.hpp"
#include "core/runtime/standalone_driver.hpp"
#include "core/scanner/memory_scanner.hpp"
#include "core/network/mitm_proxy.hpp"
#include "core/tools/script_engine.hpp"
#include "core/network/burp/camoufox_bridge.hpp"

namespace aida::qt {

namespace {

static std::atomic<int> g_bg_init_step{0};
static std::atomic<int> g_bg_init_total{0};
static std::atomic<bool> g_bg_init_done{false};
static std::atomic<AidaStartupOrchestrator*> g_orchestrator_instance{nullptr};
static std::atomic<bool> g_authorized_features_initialized{false};
static std::atomic<bool> g_authorized_features_posted{false};
static std::atomic<bool> g_camoufox_prewarm_posted{false};
static std::atomic<bool> g_script_engine_startup_init_posted{false};

void startup_log_critical(const char* detail)
{
    diag::log_tagged_critical("startup", detail ? detail : "<null>");
}

void startup_log_critical_fmt(const char* fmt, ...)
{
    char buf[2048] = {};
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    startup_log_critical(buf);
}

const char* startup_bg_phase_label(int step)
{
    switch (step)
    {
    case 0: return "Bootstrapping";
    case 1: return "Initializing AiDA runtime core";
    case 2: return "Probing network surface";
    case 3: return "Arming memory scanner";
    case 4: return "Spinning up MITM proxy";
    case 5: return "Loading script engine";
    case 6: return "Ready";
    default: return "<out_of_range>";
    }
}

void log_deferred_init(const char* step_name, const char* owning_wave)
{
    diag::log_tagged_fmt("bg_init",
        "deferred_init step=%s reason=imgui_coupled_tu wave=%s",
        step_name ? step_name : "<unknown>",
        owning_wave ? owning_wave : "<unknown>");
    startup_log_critical_fmt("deferred_init step=%s reason=imgui_coupled_tu wave=%s pid=%lu tid=%lu tick=%llu",
        step_name ? step_name : "<unknown>",
        owning_wave ? owning_wave : "<unknown>",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
}

aida::infra::executor::submit_result_t submit_main_executor_task(
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

__declspec(noinline) DWORD seh_memory_scanner_initialize()
{
    const uint64_t started = static_cast<uint64_t>(GetTickCount64());
    startup_log_critical_fmt("seh_memory_scanner_initialize_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(started));
    __try {
        memory_scanner::initialize();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        aida::diagnostics::crash::emit_crash_breadcrumb(GetExceptionCode(), nullptr, "seh_memory_scanner_initialize");
        startup_log_critical_fmt("seh_memory_scanner_initialize_exception code=0x%08X elapsed_ms=%llu last_err=%lu",
            GetExceptionCode(),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
            static_cast<unsigned long>(GetLastError()));
        return GetExceptionCode();
    }
    startup_log_critical_fmt("seh_memory_scanner_initialize_exit elapsed_ms=%llu last_err=%lu",
        static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
        static_cast<unsigned long>(GetLastError()));
    return 0;
}

__declspec(noinline) DWORD seh_mitm_proxy_pre_initialize()
{
    const uint64_t started = static_cast<uint64_t>(GetTickCount64());
    startup_log_critical_fmt("seh_mitm_proxy_pre_initialize_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(started));
    __try {
        mitm_proxy::pre_initialize();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        aida::diagnostics::crash::emit_crash_breadcrumb(GetExceptionCode(), nullptr, "seh_mitm_proxy_pre_initialize");
        startup_log_critical_fmt("seh_mitm_proxy_pre_initialize_exception code=0x%08X elapsed_ms=%llu last_err=%lu",
            GetExceptionCode(),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
            static_cast<unsigned long>(GetLastError()));
        return GetExceptionCode();
    }
    startup_log_critical_fmt("seh_mitm_proxy_pre_initialize_exit elapsed_ms=%llu last_err=%lu",
        static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
        static_cast<unsigned long>(GetLastError()));
    return 0;
}

__declspec(noinline) DWORD seh_init_standalone_chat()
{
    const uint64_t started = static_cast<uint64_t>(GetTickCount64());
    startup_log_critical_fmt("seh_init_standalone_chat_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(started));
    __try {
        ::init_standalone_chat();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        aida::diagnostics::crash::emit_crash_breadcrumb(GetExceptionCode(), nullptr, "seh_init_standalone_chat");
        startup_log_critical_fmt("seh_init_standalone_chat_exception code=0x%08X elapsed_ms=%llu last_err=%lu",
            GetExceptionCode(),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
            static_cast<unsigned long>(GetLastError()));
        return GetExceptionCode();
    }
    startup_log_critical_fmt("seh_init_standalone_chat_exit elapsed_ms=%llu last_err=%lu",
        static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
        static_cast<unsigned long>(GetLastError()));
    return 0;
}

__declspec(noinline) DWORD seh_script_engine_initialize()
{
    const uint64_t started = static_cast<uint64_t>(GetTickCount64());
    startup_log_critical_fmt("seh_script_engine_initialize_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(started));
    bool ok = false;
    __try {
        ok = script_engine::initialize();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        aida::diagnostics::crash::emit_crash_breadcrumb(GetExceptionCode(), nullptr, "seh_script_engine_initialize");
        startup_log_critical_fmt("seh_script_engine_initialize_exception code=0x%08X elapsed_ms=%llu last_err=%lu",
            GetExceptionCode(),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
            static_cast<unsigned long>(GetLastError()));
        return GetExceptionCode();
    }
    startup_log_critical_fmt("seh_script_engine_initialize_exit ok=%d initialized=%d elapsed_ms=%llu last_err=%lu",
        ok ? 1 : 0,
        script_engine::is_initialized() ? 1 : 0,
        static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
        static_cast<unsigned long>(GetLastError()));
    return ok ? 0 : ERROR_NOT_READY;
}

void log_driver_bridge_initialize_call_post(bool ok, uint64_t started)
{
    std::string status = driver_bridge::status();
    startup_log_critical_fmt("seh_driver_bridge_initialize_call_post ok=%d loaded=%d kernel=%d status=%.160s elapsed_ms=%llu last_err=%lu",
        ok ? 1 : 0,
        driver_bridge::is_loaded() ? 1 : 0,
        driver_bridge::using_kernel_driver() ? 1 : 0,
        status.c_str(),
        static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
        static_cast<unsigned long>(GetLastError()));
}

__declspec(noinline) DWORD seh_driver_bridge_initialize_raw(bool* out_ok)
{
    __try {
        if (out_ok)
            *out_ok = driver_bridge::initialize();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        aida::diagnostics::crash::emit_crash_breadcrumb(GetExceptionCode(), nullptr, "seh_driver_bridge_initialize_raw");
        return GetExceptionCode();
    }
    return 0;
}

__declspec(noinline) DWORD seh_driver_bridge_initialize()
{
    const uint64_t started = static_cast<uint64_t>(GetTickCount64());
    bool ok = false;
    startup_log_critical_fmt("seh_driver_bridge_initialize_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(started));
    DWORD seh = seh_driver_bridge_initialize_raw(&ok);
    if (seh != 0) {
        startup_log_critical_fmt("seh_driver_bridge_initialize_exception code=0x%08X elapsed_ms=%llu last_err=%lu",
            seh,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
            static_cast<unsigned long>(GetLastError()));
        return seh;
    }
    log_driver_bridge_initialize_call_post(ok, started);
    startup_log_critical_fmt("seh_driver_bridge_initialize_exit elapsed_ms=%llu last_err=%lu",
        static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
        static_cast<unsigned long>(GetLastError()));
    return 0;
}

void post_script_engine_startup_initialize()
{
    if (script_engine::is_initialized()) {
        startup_log_critical_fmt("script_engine_startup_async_skip already_initialized=1 pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(GetTickCount64()));
        return;
    }

    bool expected = false;
    if (!g_script_engine_startup_init_posted.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        startup_log_critical_fmt("script_engine_startup_async_skip already_posted=1 initialized=%d pid=%lu tid=%lu tick=%llu",
            script_engine::is_initialized() ? 1 : 0,
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(GetTickCount64()));
        return;
    }

    const uint64_t queued_at = static_cast<uint64_t>(GetTickCount64());
    startup_log_critical_fmt("script_engine_startup_async_posting pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(queued_at));
    std::function<void()> init_task = [queued_at]() {
        const uint64_t started = static_cast<uint64_t>(GetTickCount64());
        startup_log_critical_fmt("script_engine_startup_async_enter pid=%lu tid=%lu queued_ms=%llu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(started - queued_at),
            static_cast<unsigned long long>(started));
        DWORD seh = seh_script_engine_initialize();
        startup_log_critical_fmt("script_engine_startup_async_exit seh=0x%08X initialized=%d elapsed_ms=%llu last_err=%lu",
            seh,
            script_engine::is_initialized() ? 1 : 0,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
            static_cast<unsigned long>(GetLastError()));
        if (seh != 0 && !script_engine::is_initialized())
            g_script_engine_startup_init_posted.store(false, std::memory_order_release);
    };

    bool posted_executor = false;
    std::string reject_reason = "<none>";
    try {
        const auto submit_result = submit_main_executor_task(
            "startup",
            "script_engine_startup_init",
            aida::infra::executor::domain_t::long_running,
            "startup_init",
            std::move(init_task));
        posted_executor = submit_result.submitted;
        if (!submit_result.reject_reason.empty())
            reject_reason = submit_result.reject_reason;
        startup_log_critical_fmt("script_engine_startup_async_posted pid=%lu tid=%lu service=%d work=%d executor=%d domain=long_running reject_reason=%.160s elapsed_ms=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            0,
            0,
            posted_executor ? 1 : 0,
            reject_reason.c_str(),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - queued_at));
    } catch (const std::exception& e) {
        g_script_engine_startup_init_posted.store(false, std::memory_order_release);
        startup_log_critical_fmt("script_engine_startup_async_post_exception elapsed_ms=%llu what=%.160s",
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - queued_at),
            e.what());
    } catch (...) {
        aida::diagnostics::crash::emit_crash_breadcrumb(0xE06D7363u, nullptr, "script_engine_startup_async_post");
        g_script_engine_startup_init_posted.store(false, std::memory_order_release);
        startup_log_critical_fmt("script_engine_startup_async_post_exception elapsed_ms=%llu what=<unknown>",
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - queued_at));
    }

    if (!posted_executor && !script_engine::is_initialized()) {
        g_script_engine_startup_init_posted.store(false, std::memory_order_release);
        startup_log_critical_fmt("script_engine_startup_async_post_failed pid=%lu tid=%lu queued_ms=%llu reason=%.160s initialized=%d",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - queued_at),
            reject_reason.c_str(),
            script_engine::is_initialized() ? 1 : 0);
    }
}

void run_authorized_feature_initializers(const char* source)
{
    auto run = [source](const char* phase, DWORD(*fn)()) {
        DWORD seh = 0;
        const uint64_t started = static_cast<uint64_t>(GetTickCount64());
        startup_log_critical_fmt("authorized_feature_phase_pre source=%s phase=%s pid=%lu tid=%lu tick=%llu",
            source ? source : "unknown",
            phase ? phase : "unknown",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(started));
        diag::log_tagged_fmt("bg_init", "%s_start source=%s", phase, source ? source : "unknown");
        try {
            seh = fn();
        } catch (const std::exception& e) {
            startup_log_critical_fmt("authorized_feature_phase_cpp_exception source=%s phase=%s elapsed_ms=%llu what=%.160s",
                source ? source : "unknown",
                phase ? phase : "unknown",
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
                e.what());
            diag::log_tagged_fmt("bg_init", "%s_cpp_exception source=%s what=%s",
                phase, source ? source : "unknown", e.what());
            return false;
        } catch (...) {
            aida::diagnostics::crash::emit_crash_breadcrumb(0xE06D7363u, nullptr, "authorized_feature_phase");
            startup_log_critical_fmt("authorized_feature_phase_cpp_exception source=%s phase=%s elapsed_ms=%llu what=<unknown>",
                source ? source : "unknown",
                phase ? phase : "unknown",
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            diag::log_tagged_fmt("bg_init", "%s_cpp_exception source=%s what=<unknown>",
                phase, source ? source : "unknown");
            return false;
        }
        if (seh != 0) {
            startup_log_critical_fmt("authorized_feature_phase_seh source=%s phase=%s code=0x%08X last_err=%lu elapsed_ms=%llu",
                source ? source : "unknown",
                phase ? phase : "unknown",
                seh,
                static_cast<unsigned long>(GetLastError()),
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
            diag::log_tagged_fmt("bg_init", "%s_seh source=%s code=0x%08X last_err=%lu",
                phase, source ? source : "unknown", seh, GetLastError());
            return false;
        }
        startup_log_critical_fmt("authorized_feature_phase_post source=%s phase=%s seh=0x%08X elapsed_ms=%llu last_err=%lu",
            source ? source : "unknown",
            phase ? phase : "unknown",
            seh,
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
            static_cast<unsigned long>(GetLastError()));
        diag::log_tagged_fmt("bg_init", "%s_ok source=%s", phase, source ? source : "unknown");
        return true;
    };

    bool ok = true;
    diag::log_tagged_fmt("bg_init", "%s_start source=%s", "network_view_init", source ? source : "unknown");
    log_deferred_init("network_view_init", "10_network_a.md");
    startup_log_critical_fmt("authorized_feature_phase_post source=%s phase=%s seh=0x%08X elapsed_ms=%llu last_err=%lu",
        source ? source : "unknown",
        "network_view_init",
        0UL,
        0ULL,
        static_cast<unsigned long>(GetLastError()));
    ok = run("memory_scanner_init", seh_memory_scanner_initialize) && ok;
    ok = run("mitm_proxy_pre_init", seh_mitm_proxy_pre_initialize) && ok;
    startup_log_critical_fmt("authorized_feature_phase_async_post source=%s phase=script_engine_init pid=%lu tid=%lu tick=%llu",
        source ? source : "unknown",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    diag::log_tagged_fmt("bg_init", "script_engine_init_async_start source=%s", source ? source : "unknown");
    post_script_engine_startup_initialize();
    g_authorized_features_initialized.store(ok, std::memory_order_release);
    if (!ok)
        g_authorized_features_posted.store(false, std::memory_order_release);
    startup_log_critical_fmt("authorized_feature_initializers_done source=%s ok=%d pid=%lu tid=%lu tick=%llu",
        source ? source : "unknown",
        ok ? 1 : 0,
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    diag::log_tagged_fmt("bg_init", "authorized_feature_initializers_done source=%s ok=%d",
        source ? source : "unknown", ok ? 1 : 0);
}

}

AidaStartupOrchestrator::AidaStartupOrchestrator(QObject* parent)
    : QObject(parent)
{
    g_orchestrator_instance.store(this, std::memory_order_release);
    connect(this, &QObject::destroyed, [](QObject* obj) {
        AidaStartupOrchestrator* expected = static_cast<AidaStartupOrchestrator*>(obj);
        g_orchestrator_instance.compare_exchange_strong(expected, nullptr, std::memory_order_acq_rel);
    });
}

AidaStartupOrchestrator::~AidaStartupOrchestrator()
{
    AidaStartupOrchestrator* expected = this;
    g_orchestrator_instance.compare_exchange_strong(expected, nullptr, std::memory_order_acq_rel);
}

int AidaStartupOrchestrator::bgInitStep() const
{
    return g_bg_init_step.load(std::memory_order_acquire);
}

int AidaStartupOrchestrator::bgInitTotal() const
{
    return g_bg_init_total.load(std::memory_order_acquire);
}

bool AidaStartupOrchestrator::bgInitDone() const
{
    return g_bg_init_done.load(std::memory_order_acquire);
}

void AidaStartupOrchestrator::kickoffBackgroundInit()
{
    if (kickoff_posted_.exchange(true, std::memory_order_acq_rel)) {
        diag::log_tagged_critical("bg_init", "bg_init_kickoff_skipped already_posted=1");
        return;
    }

    g_bg_init_step.store(0, std::memory_order_release);
    g_bg_init_done.store(false, std::memory_order_release);
    g_bg_init_total.store(6, std::memory_order_release);
    startup_log_critical_fmt("bg_init_config total=%d initial_step=%d label=%s pid=%lu tid=%lu tick=%llu",
        g_bg_init_total.load(std::memory_order_acquire),
        g_bg_init_step.load(std::memory_order_acquire),
        startup_bg_phase_label(g_bg_init_step.load(std::memory_order_acquire)),
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    startup_log_critical_fmt("bg_init_critical_post_pre pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));

    const uint64_t thread_tick_seed = static_cast<uint64_t>(GetTickCount64());
    const auto bg_submit_result = submit_main_executor_task(
        "startup",
        "startup.bg_init",
        aida::infra::executor::domain_t::security_liveness,
        "security_liveness",
        [thread_tick_seed]() {
        const uint64_t thread_tick = thread_tick_seed;
        startup_log_critical_fmt("bg_init_thread_entry pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(thread_tick));
        diag::log_tagged("bg_init", "thread_entry");

        auto store_bg_step = [](int step, const char* source, const char* phase) {
            int before = g_bg_init_step.load(std::memory_order_acquire);
            g_bg_init_step.store(step, std::memory_order_release);
            startup_log_critical_fmt(
                "bg_init_step_transition source=%s phase=%s before=%d after=%d label=%s pid=%lu tid=%lu tick=%llu",
                source ? source : "unknown",
                phase ? phase : "unknown",
                before,
                step,
                startup_bg_phase_label(step),
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(GetTickCount64()));
        };

        auto run_step = [&store_bg_step](const char* start_log, const char* phase, const char* ok_log, int step, auto&& fn) {
            bool cpp_ok = true;
            DWORD seh_code = 0;
            const uint64_t started = static_cast<uint64_t>(GetTickCount64());
            startup_log_critical_fmt("bg_init_run_step_pre phase=%s start_log=%s target_step=%d target_label=%s pid=%lu tid=%lu tick=%llu",
                phase ? phase : "unknown",
                start_log ? start_log : "unknown",
                step,
                startup_bg_phase_label(step),
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(started));
            store_bg_step(step, "bg_init_worker_enter", phase);
            diag::log_tagged("bg_init", start_log);
            try {
                seh_code = fn();
            } catch (const std::exception& e) {
                cpp_ok = false;
                startup_log_critical_fmt("bg_init_run_step_cpp_exception phase=%s elapsed_ms=%llu what=%.160s",
                    phase ? phase : "unknown",
                    static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
                    e.what());
                diag::log_tagged_fmt("bg_init", "%s_cpp_exception what=%s", phase, e.what());
            } catch (...) {
                aida::diagnostics::crash::emit_crash_breadcrumb(0xE06D7363u, nullptr, "bg_init_run_step");
                cpp_ok = false;
                startup_log_critical_fmt("bg_init_run_step_cpp_exception phase=%s elapsed_ms=%llu what=<unknown>",
                    phase ? phase : "unknown",
                    static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
                diag::log_tagged_fmt("bg_init", "%s_cpp_exception what=<unknown>", phase);
            }
            if (seh_code != 0) {
                startup_log_critical_fmt("bg_init_run_step_seh phase=%s code=0x%08X last_err=%lu elapsed_ms=%llu",
                    phase ? phase : "unknown",
                    seh_code,
                    static_cast<unsigned long>(GetLastError()),
                    static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started));
                diag::log_tagged_fmt("bg_init", "%s_seh code=0x%08X last_err=%lu", phase, seh_code, GetLastError());
            }
            if (cpp_ok && seh_code == 0)
                diag::log_tagged("bg_init", ok_log);
            else
                diag::log_tagged_fmt("bg_init", "%s_failed cpp=%d seh=0x%08X", phase, cpp_ok ? 1 : 0, seh_code);
            startup_log_critical_fmt("bg_init_run_step_post phase=%s cpp=%d seh=0x%08X elapsed_ms=%llu last_err=%lu",
                phase ? phase : "unknown",
                cpp_ok ? 1 : 0,
                seh_code,
                static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - started),
                static_cast<unsigned long>(GetLastError()));
            store_bg_step(step, "bg_init_worker", phase);
        };

        run_step("init_standalone_chat_start", "init_standalone_chat", "init_standalone_chat_ok", 1,
            []() { return seh_init_standalone_chat(); });
        log_deferred_init("init_standalone_chat", "13_ai_settings.md");

        store_bg_step(2, "bg_init_worker_enter", "network_view_init");
        diag::log_tagged("bg_init", "network_view_init_start");
        log_deferred_init("network_view_init", "10_network_a.md");
        store_bg_step(2, "bg_init_worker", "network_view_init");

        run_step("memory_scanner_init_start", "memory_scanner_init", "memory_scanner_init_ok", 3,
            []() { return seh_memory_scanner_initialize(); });

        run_step("mitm_proxy_pre_init_start", "mitm_proxy_pre_init", "mitm_proxy_pre_init_ok", 4,
            []() { return seh_mitm_proxy_pre_initialize(); });

        startup_log_critical_fmt("bg_init_script_engine_async_pre phase=script_engine_init target_step=5 target_label=%s pid=%lu tid=%lu tick=%llu",
            startup_bg_phase_label(5),
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(GetTickCount64()));
        diag::log_tagged("bg_init", "script_engine_init_async_start");
        post_script_engine_startup_initialize();
        store_bg_step(5, "bg_init_worker", "script_engine_init_async_posted");
        diag::log_tagged("bg_init", "script_engine_init_async_posted");
        g_authorized_features_initialized.store(true, std::memory_order_release);
        g_authorized_features_posted.store(true, std::memory_order_release);

        store_bg_step(6, "bg_init_worker", "bg_init_all_steps_done");

        g_bg_init_done.store(true, std::memory_order_release);
        startup_log_critical_fmt("bg_init_thread_exit elapsed_ms=%llu final_step=%d pid=%lu tid=%lu tick=%llu",
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - thread_tick),
            g_bg_init_step.load(std::memory_order_acquire),
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(GetTickCount64()));
        diag::log_tagged("bg_init", "thread_exit");
        AidaStartupOrchestrator* self = g_orchestrator_instance.load(std::memory_order_acquire);
        if (self) {
            QMetaObject::invokeMethod(self, [self]() {
                self->queueDeferredServicesTrigger("bg_init_done");
                Q_EMIT self->backgroundInitFinished();
            }, Qt::QueuedConnection);
        }
    });
    bool bg_posted = bg_submit_result.submitted;
    startup_log_critical_fmt("bg_init_critical_post_post posted=%d pid=%lu tid=%lu tick=%llu",
        bg_posted ? 1 : 0,
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));

    driver_bridge::set_log_callback([](const std::string& msg) {
        diag::log_tagged("main", msg.c_str());
    });
    startup_log_critical_fmt("driver_bridge_log_callback_set pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));

    startup_log_critical_fmt("driver_bridge_init_critical_post_pre pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    startup_log_critical_fmt("driver_bridge_launch_context before_post loaded=%d kernel=%d",
        driver_bridge::is_loaded() ? 1 : 0,
        driver_bridge::using_kernel_driver() ? 1 : 0);
    const auto driver_submit_result = submit_main_executor_task(
        "startup",
        "startup.driver_bridge_init",
        aida::infra::executor::domain_t::security_liveness,
        "driver",
        [] {
        const uint64_t driver_tick = static_cast<uint64_t>(GetTickCount64());
        startup_log_critical_fmt("driver_bridge_init_thread_entry pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(driver_tick));
        diag::log_tagged("drv_init", "thread_entry");
        DWORD seh_dbi = seh_driver_bridge_initialize();
        if (seh_dbi != 0)
            diag::log_tagged_fmt("drv_init", "driver_bridge_initialize_seh code=0x%08X last_err=%lu", seh_dbi, GetLastError());
        startup_log_critical_fmt("driver_bridge_launch_context after_initialize seh=0x%08X loaded=%d kernel=%d",
            seh_dbi,
            driver_bridge::is_loaded() ? 1 : 0,
            driver_bridge::using_kernel_driver() ? 1 : 0);
        startup_log_critical_fmt("driver_bridge_init_thread_exit seh=0x%08X loaded=%d kernel=%d status=%.160s elapsed_ms=%llu last_err=%lu",
            seh_dbi,
            driver_bridge::is_loaded() ? 1 : 0,
            driver_bridge::using_kernel_driver() ? 1 : 0,
            driver_bridge::status().c_str(),
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - driver_tick),
            static_cast<unsigned long>(GetLastError()));
        diag::log_tagged("drv_init", "thread_exit");
    });
    bool driver_posted = driver_submit_result.submitted;
    startup_log_critical_fmt("driver_bridge_init_critical_post_post posted=%d pid=%lu tid=%lu tick=%llu",
        driver_posted ? 1 : 0,
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(GetTickCount64()));
    diag::log_tagged("main", "driver_bridge_thread_launched");
}

void AidaStartupOrchestrator::onViewsReady()
{
    views_ready_.store(true, std::memory_order_release);
    diag::log_tagged_critical_fmt("bg_init",
        "views_ready_marked bg_init_done=%d tid=%lu",
        g_bg_init_done.load(std::memory_order_acquire) ? 1 : 0,
        static_cast<unsigned long>(::GetCurrentThreadId()));
    queueDeferredServicesTrigger("views_ready");
}

void AidaStartupOrchestrator::onBootFinished()
{
    diag::log_tagged_critical_fmt("bg_init",
        "boot_finished_received bg_init_done=%d tid=%lu",
        g_bg_init_done.load(std::memory_order_acquire) ? 1 : 0,
        static_cast<unsigned long>(::GetCurrentThreadId()));
    onViewsReady();
}

void AidaStartupOrchestrator::queueDeferredServicesTrigger(const char* source)
{
    const std::string source_copy = source ? source : "unknown";
    QMetaObject::invokeMethod(this, [this, source_copy]() {
        runDeferredServicesTrigger(source_copy.c_str());
    }, Qt::QueuedConnection);
}

void AidaStartupOrchestrator::runDeferredServicesTrigger(const char* source)
{
    if (!g_bg_init_done.load(std::memory_order_acquire) ||
        !views_ready_.load(std::memory_order_acquire))
        return;
    if (deferred_triggered_.exchange(true, std::memory_order_acq_rel))
        return;

    if (!g_authorized_features_initialized.load(std::memory_order_acquire) &&
        !g_authorized_features_posted.exchange(true, std::memory_order_acq_rel))
    {
        startup_log_critical_fmt("render_authorized_feature_critical_post_pre source=%s pid=%lu tid=%lu tick=%llu",
            source ? source : "unknown",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(GetTickCount64()));
        const auto submit_result = submit_main_executor_task(
            "startup",
            "render.authorized_feature_init",
            aida::infra::executor::domain_t::long_running,
            "startup_init",
            [] {
            startup_log_critical_fmt("render_authorized_feature_worker_enter pid=%lu tid=%lu tick=%llu",
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(GetTickCount64()));
            run_authorized_feature_initializers("render_authorized");
            startup_log_critical_fmt("render_authorized_feature_worker_exit pid=%lu tid=%lu tick=%llu",
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(GetTickCount64()));
        });
        bool posted = submit_result.submitted;
        startup_log_critical_fmt("render_authorized_feature_critical_post_post posted=%d source=%s",
            posted ? 1 : 0,
            source ? source : "unknown");
        if (!posted)
        {
            g_authorized_features_posted.store(false, std::memory_order_release);
            diag::log_tagged("bg_init", "authorized_feature_initializers_critical_post_failed");
        }
    }
    log_deferred_init("mark_ide_ready_for_mcp_services", "13_ai_settings.md");
    log_deferred_init("start_authorized_mcp_services", "13_ai_settings.md");
    ::mark_ide_ready_for_mcp_services();
    ::start_authorized_mcp_services();
    if (!g_camoufox_prewarm_posted.exchange(true, std::memory_order_acq_rel))
    {
        bool prewarm_posted = aida::burp::camoufox::prewarm_default_async("render_authorized");
        startup_log_critical_fmt("camoufox_prewarm_request posted=%d source=%s pid=%lu tid=%lu tick=%llu",
            prewarm_posted ? 1 : 0,
            source ? source : "unknown",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(GetTickCount64()));
        if (!prewarm_posted)
            g_camoufox_prewarm_posted.store(false, std::memory_order_release);
    }
    Q_EMIT deferredServicesTriggered();
}

}
