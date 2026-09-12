#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>

#include <nlohmann/json.hpp>

namespace sandbox
{
    struct config
    {
        std::wstring exe_path;
        std::wstring arguments;
        std::wstring working_dir;
        uint32_t     timeout_ms = 30000;
        uint64_t     max_memory = 512ULL * 1024 * 1024;
        uint32_t     max_memory_mb = 512;
        bool         capture_stdout = true;
        bool         capture_stderr = true;
        bool         use_appcontainer = true;
        bool         allow_network = false;
        bool         allow_clipboard = false;
        bool         allow_gpu = false;
        bool         cleanup_session = true;
        std::atomic<bool>* cancel_token = nullptr;
    };

    struct result
    {
        bool        success = false;
        uint32_t    exit_code = 0;
        uint32_t    pid = 0;
        std::string stdout_data;
        std::string stderr_data;
        std::string error;
        bool        timed_out = false;
        bool        killed = false;
        bool        cancelled = false;
        uint64_t    peak_memory_bytes = 0;
        uint32_t    elapsed_ms = 0;
        std::string session_dir;
        std::string wsb_path;
    };

    namespace detail
    {
        inline std::wstring windows_sandbox_exe()
        {
            wchar_t system_root[MAX_PATH] = {};
            GetEnvironmentVariableW(L"SystemRoot", system_root, MAX_PATH);
            if (system_root[0] == 0)
                return {};
            std::filesystem::path path = std::filesystem::path(system_root) / L"System32" / L"WindowsSandbox.exe";
            if (!std::filesystem::exists(path))
                return {};
            return path.wstring();
        }

        inline std::wstring ps_quote(const std::wstring& text)
        {
            std::wstring result = L"'";
            for (wchar_t ch : text) {
                if (ch == L'\'')
                    result += L"''";
                else
                    result.push_back(ch);
            }
            result += L"'";
            return result;
        }

        inline std::string narrow(const std::wstring& text)
        {
            if (text.empty())
                return {};
            int needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.c_str(), -1,
                                             nullptr, 0, nullptr, nullptr);
            if (needed <= 1)
                return {};
            std::string out(static_cast<size_t>(needed), '\0');
            if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.c_str(), -1, out.data(),
                                    needed, nullptr, nullptr) != needed)
                return {};
            out.resize(static_cast<size_t>(needed - 1));
            return out;
        }

        inline std::wstring xml_escape(const std::wstring& text)
        {
            std::wstring out;
            out.reserve(text.size() + 16);
            for (wchar_t ch : text) {
                switch (ch) {
                    case L'&':  out += L"&amp;";  break;
                    case L'<':  out += L"&lt;";   break;
                    case L'>':  out += L"&gt;";   break;
                    case L'"':  out += L"&quot;"; break;
                    case L'\'': out += L"&apos;"; break;
                    default:    out.push_back(ch); break;
                }
            }
            return out;
        }

        inline std::string read_utf8_file(const std::filesystem::path& path)
        {
            std::ifstream ifs(path, std::ios::binary);
            if (!ifs.is_open())
                return {};
            return std::string((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
        }

        inline bool read_json_file(const std::filesystem::path& path, nlohmann::json& out)
        {
            const std::string raw = read_utf8_file(path);
            if (raw.empty())
                return false;
            auto parsed = nlohmann::json::parse(raw, nullptr, false);
            if (parsed.is_discarded() || !parsed.is_object())
                return false;
            out = std::move(parsed);
            return true;
        }

        inline bool json_bool_field(const nlohmann::json& value, const char* key, bool fallback)
        {
            if (!value.is_object() || !value.contains(key))
                return fallback;
            const auto& field = value[key];
            if (field.is_boolean())
                return field.get<bool>();
            if (field.is_number_integer())
                return field.get<int64_t>() != 0;
            if (field.is_number_unsigned())
                return field.get<uint64_t>() != 0;
            if (field.is_string()) {
                std::string text = field.get<std::string>();
                std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
                    return static_cast<char>(std::tolower(c));
                });
                if (text == "true" || text == "1" || text == "yes")
                    return true;
                if (text == "false" || text == "0" || text == "no")
                    return false;
            }
            return fallback;
        }

        inline uint32_t json_u32_field(const nlohmann::json& value, const char* key, uint32_t fallback)
        {
            if (!value.is_object() || !value.contains(key))
                return fallback;
            const auto& field = value[key];
            if (field.is_number_unsigned()) {
                uint64_t raw = field.get<uint64_t>();
                return raw > 0xFFFFFFFFull ? 0xFFFFFFFFu : static_cast<uint32_t>(raw);
            }
            if (field.is_number_integer()) {
                int64_t raw = field.get<int64_t>();
                if (raw < 0)
                    return fallback;
                return raw > 0xFFFFFFFFll ? 0xFFFFFFFFu : static_cast<uint32_t>(raw);
            }
            if (field.is_string()) {
                try {
                    std::string text = field.get<std::string>();
                    size_t idx = 0;
                    unsigned long long raw = std::stoull(text, &idx, 0);
                    if (idx == text.size())
                        return raw > 0xFFFFFFFFull ? 0xFFFFFFFFu : static_cast<uint32_t>(raw);
                } catch (...) {
                }
            }
            return fallback;
        }

        struct close_window_ctx
        {
            DWORD pid = 0;
            bool posted = false;
        };

        inline BOOL CALLBACK close_window_enum_proc(HWND hwnd, LPARAM param)
        {
            auto* ctx = reinterpret_cast<close_window_ctx*>(param);
            DWORD pid = 0;
            GetWindowThreadProcessId(hwnd, &pid);
            if (ctx && pid == ctx->pid && IsWindowVisible(hwnd)) {
                PostMessageW(hwnd, WM_CLOSE, 0, 0);
                ctx->posted = true;
            }
            return TRUE;
        }

        inline bool request_process_window_close(DWORD pid)
        {
            if (pid == 0)
                return false;
            close_window_ctx ctx;
            ctx.pid = pid;
            EnumWindows(close_window_enum_proc, reinterpret_cast<LPARAM>(&ctx));
            return ctx.posted;
        }

        inline void close_or_terminate_process(HANDLE process, DWORD pid, DWORD close_wait_ms)
        {
            if (!process || process == INVALID_HANDLE_VALUE)
                return;
            if (WaitForSingleObject(process, 0) == WAIT_OBJECT_0)
                return;
            if (request_process_window_close(pid)) {
                if (WaitForSingleObject(process, close_wait_ms) == WAIT_OBJECT_0)
                    return;
            }
            TerminateProcess(process, 0);
        }

        inline void copy_workspace(const std::filesystem::path& source_dir,
                                   const std::filesystem::path& target_dir)
        {
            std::error_code ec;
            std::filesystem::create_directories(target_dir, ec);
            if (!std::filesystem::exists(source_dir))
                return;

            for (const auto& entry : std::filesystem::recursive_directory_iterator(source_dir, ec)) {
                if (ec)
                    break;
                const auto relative = std::filesystem::relative(entry.path(), source_dir, ec);
                if (ec)
                    continue;
                const auto destination = target_dir / relative;
                if (entry.is_directory(ec)) {
                    std::filesystem::create_directories(destination, ec);
                    continue;
                }
                if (!entry.is_regular_file(ec))
                    continue;
                std::filesystem::create_directories(destination.parent_path(), ec);
                std::filesystem::copy_file(entry.path(), destination,
                                           std::filesystem::copy_options::overwrite_existing, ec);
            }
        }

        inline std::filesystem::path create_session_dir()
        {
            wchar_t temp_path[MAX_PATH] = {};
            GetTempPathW(MAX_PATH, temp_path);
            const auto tick = std::chrono::steady_clock::now().time_since_epoch().count();
            std::filesystem::path dir = std::filesystem::path(temp_path) / L"AiDAStandalone" / L"Sandbox"
                                      / std::to_wstring(GetCurrentProcessId())
                                      / std::to_wstring(static_cast<unsigned long long>(tick));
            std::filesystem::create_directories(dir);
            return dir;
        }

        inline void write_runner_script(const std::filesystem::path& script_path,
                                        const std::wstring& guest_root,
                                        const std::wstring& guest_exe,
                                        const std::wstring& guest_arguments,
                                        uint32_t timeout_ms,
                                        bool capture_stdout,
                                        bool capture_stderr)
        {
            std::wofstream ofs(script_path, std::ios::trunc);
            ofs << L"$ErrorActionPreference = 'Stop'\n";
            ofs << L"$guestRoot = " << ps_quote(guest_root) << L"\n";
            ofs << L"$exePath = " << ps_quote(guest_exe) << L"\n";
            ofs << L"$argLine = " << ps_quote(guest_arguments) << L"\n";
            ofs << L"$stdoutFile = Join-Path $guestRoot 'stdout.txt'\n";
            ofs << L"$stderrFile = Join-Path $guestRoot 'stderr.txt'\n";
            ofs << L"$metaFile = Join-Path $guestRoot 'metadata.json'\n";
            ofs << L"$tmpMetaFile = Join-Path $guestRoot ('metadata.' + [guid]::NewGuid().ToString('N') + '.tmp')\n";
            ofs << L"$workDir = Split-Path -Path $exePath -Parent\n";
            ofs << L"$sw = [System.Diagnostics.Stopwatch]::StartNew()\n";
            ofs << L"$timedOut = $false\n";
            ofs << L"$killed = $false\n";
            ofs << L"$exitCode = 0\n";
            ofs << L"$pidValue = 0\n";
            ofs << L"if (" << (capture_stdout ? L"$true" : L"$false") << L") { if (Test-Path $stdoutFile) { Remove-Item $stdoutFile -Force } }\n";
            ofs << L"if (" << (capture_stderr ? L"$true" : L"$false") << L") { if (Test-Path $stderrFile) { Remove-Item $stderrFile -Force } }\n";
            ofs << L"if (Test-Path $metaFile) { Remove-Item $metaFile -Force }\n";
            ofs << L"if (Test-Path $tmpMetaFile) { Remove-Item $tmpMetaFile -Force }\n";
            ofs << L"$proc = Start-Process -FilePath $exePath -ArgumentList $argLine -WorkingDirectory $workDir "
                   L"-PassThru -WindowStyle Hidden"
                << (capture_stdout ? L" -RedirectStandardOutput $stdoutFile" : L"")
                << (capture_stderr ? L" -RedirectStandardError $stderrFile" : L"")
                << L"\n";
            ofs << L"$pidValue = $proc.Id\n";
            ofs << L"if (-not $proc.WaitForExit(" << timeout_ms << L")) {\n";
            ofs << L"  $timedOut = $true\n";
            ofs << L"  try { taskkill /T /F /PID $proc.Id | Out-Null } catch {}\n";
            ofs << L"  try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch {}\n";
            ofs << L"  $killed = $true\n";
            ofs << L"  $proc.WaitForExit(5000) | Out-Null\n";
            ofs << L"}\n";
            ofs << L"$sw.Stop()\n";
            ofs << L"if ($proc.HasExited -and $null -ne $proc.ExitCode) { $exitCode = [int]$proc.ExitCode }\n";
            ofs << L"if ($null -eq $exitCode) { $exitCode = 0 }\n";
            ofs << L"$meta = [ordered]@{\n";
            ofs << L"  success = $true\n";
            ofs << L"  exit_code = $exitCode\n";
            ofs << L"  pid = $pidValue\n";
            ofs << L"  timed_out = $timedOut\n";
            ofs << L"  killed = $killed\n";
            ofs << L"  elapsed_ms = [int]$sw.ElapsedMilliseconds\n";
            ofs << L"}\n";
            ofs << L"$json = $meta | ConvertTo-Json -Depth 4\n";
            ofs << L"$utf8NoBom = New-Object System.Text.UTF8Encoding($false)\n";
            ofs << L"[System.IO.File]::WriteAllText($tmpMetaFile, $json, $utf8NoBom)\n";
            ofs << L"Move-Item -LiteralPath $tmpMetaFile -Destination $metaFile -Force\n";
        }

        inline void write_wsb(const std::filesystem::path& wsb_path,
                              const std::filesystem::path& session_dir,
                              const config& cfg)
        {
            std::wofstream ofs(wsb_path, std::ios::trunc);
            const std::wstring host = xml_escape(session_dir.wstring());
            const std::wstring host_input = xml_escape((session_dir / L"input").wstring());
            const std::wstring guest_root = L"C:\\Users\\WDAGUtilityAccount\\Desktop\\AiDAWorkspace";
            const std::wstring guest_input = guest_root + L"\\input";
            ofs << L"<Configuration>\n";
            ofs << L"  <Networking>" << (cfg.allow_network ? L"Default" : L"Disable") << L"</Networking>\n";
            ofs << L"  <ClipboardRedirection>" << (cfg.allow_clipboard ? L"Default" : L"Disable") << L"</ClipboardRedirection>\n";
            ofs << L"  <PrinterRedirection>Disable</PrinterRedirection>\n";
            ofs << L"  <AudioInput>Disable</AudioInput>\n";
            ofs << L"  <VideoInput>Disable</VideoInput>\n";
            ofs << L"  <vGPU>" << (cfg.allow_gpu ? L"Default" : L"Disable") << L"</vGPU>\n";

            if (cfg.max_memory_mb > 0)
                ofs << L"  <MemoryInMB>" << cfg.max_memory_mb << L"</MemoryInMB>\n";

            ofs << L"  <MappedFolders>\n";

            ofs << L"    <MappedFolder>\n";
            ofs << L"      <HostFolder>" << host_input << L"</HostFolder>\n";
            ofs << L"      <SandboxFolder>" << xml_escape(guest_input) << L"</SandboxFolder>\n";
            ofs << L"      <ReadOnly>true</ReadOnly>\n";
            ofs << L"    </MappedFolder>\n";

            ofs << L"    <MappedFolder>\n";
            ofs << L"      <HostFolder>" << host << L"</HostFolder>\n";
            ofs << L"      <SandboxFolder>" << xml_escape(guest_root) << L"</SandboxFolder>\n";
            ofs << L"      <ReadOnly>false</ReadOnly>\n";
            ofs << L"    </MappedFolder>\n";

            ofs << L"  </MappedFolders>\n";
            ofs << L"  <LogonCommand>\n";
            ofs << L"    <Command>powershell.exe -ExecutionPolicy Bypass -File "
                << xml_escape(guest_root) << L"\\run.ps1</Command>\n";
            ofs << L"  </LogonCommand>\n";
            ofs << L"</Configuration>\n";
        }
    }

    inline result execute(const config& cfg)
    {
        result res;
        const auto sandbox_exe = detail::windows_sandbox_exe();
        if (sandbox_exe.empty()) {
            res.error = "Windows Sandbox is unavailable. Enable the Windows Sandbox feature first.";
            return res;
        }

        if (cfg.exe_path.empty()) {
            res.error = "No executable path specified.";
            return res;
        }


        if (cfg.exe_path.find(L'\0') != std::wstring::npos ||
            cfg.exe_path.find(L'`')  != std::wstring::npos ||
            cfg.exe_path.find(L'$')  != std::wstring::npos ||
            cfg.exe_path.find(L';')  != std::wstring::npos ||
            cfg.exe_path.find(L'|')  != std::wstring::npos ||
            cfg.exe_path.find(L'&')  != std::wstring::npos) {
            res.error = "Executable path contains forbidden characters.";
            return res;
        }

        const std::filesystem::path exe_path(cfg.exe_path);
        if (!std::filesystem::exists(exe_path)) {
            res.error = "Target executable does not exist.";
            return res;
        }

        const auto session_dir = detail::create_session_dir();
        const auto host_input_dir = session_dir / L"input";
        const auto host_wsb = session_dir / L"session.wsb";
        const auto host_script = session_dir / L"run.ps1";
        const auto host_meta = session_dir / L"metadata.json";
        const auto host_stdout = session_dir / L"stdout.txt";
        const auto host_stderr = session_dir / L"stderr.txt";

        const std::filesystem::path source_dir =
            (!cfg.working_dir.empty() && std::filesystem::exists(cfg.working_dir))
            ? std::filesystem::path(cfg.working_dir)
            : exe_path.parent_path();

        detail::copy_workspace(source_dir, host_input_dir);
        if (!std::filesystem::exists(host_input_dir / exe_path.filename())) {
            std::error_code ec;
            std::filesystem::copy_file(exe_path, host_input_dir / exe_path.filename(),
                                       std::filesystem::copy_options::overwrite_existing, ec);
        }

        const std::wstring guest_root = L"C:\\Users\\WDAGUtilityAccount\\Desktop\\AiDAWorkspace";
        const std::wstring guest_exe = guest_root + L"\\input\\" + exe_path.filename().wstring();
        detail::write_runner_script(host_script, guest_root, guest_exe, cfg.arguments,
                                    cfg.timeout_ms, cfg.capture_stdout, cfg.capture_stderr);
        detail::write_wsb(host_wsb, session_dir, cfg);

        STARTUPINFOW si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        std::wstring cmd = L"\"" + sandbox_exe + L"\" \"" + host_wsb.wstring() + L"\"";
        const auto start_tick = GetTickCount();

        if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                            nullptr, session_dir.c_str(), &si, &pi)) {
            res.error = "Failed to launch Windows Sandbox.";
            return res;
        }

        CloseHandle(pi.hThread);
        res.pid = pi.dwProcessId;

        const uint32_t host_timeout = (std::max)(cfg.timeout_ms + 120000u, 180000u);
        bool sandbox_alive = true;
        bool cancelled = false;
        bool process_exited = false;
        DWORD exit_tick = 0;
        bool metadata_ready = false;
        nlohmann::json meta;
        while ((GetTickCount() - start_tick) < host_timeout) {
            if (cfg.cancel_token && cfg.cancel_token->load(std::memory_order_acquire)) {
                cancelled = true;
                break;
            }
            if (detail::read_json_file(host_meta, meta)) {
                metadata_ready = true;
                break;
            }
            DWORD wait_state = WaitForSingleObject(pi.hProcess, 500);
            if (wait_state == WAIT_OBJECT_0) {
                sandbox_alive = false;
                if (!process_exited) {
                    process_exited = true;
                    exit_tick = GetTickCount();
                }
                if ((GetTickCount() - exit_tick) > 5000)
                    break;
            }
        }

        if (cancelled) {
            res.cancelled = true;
            res.killed = sandbox_alive;
            if (sandbox_alive)
                TerminateProcess(pi.hProcess, 0xDEAD);
            CloseHandle(pi.hProcess);
            res.error = "Sandbox execution cancelled by client request.";
            res.elapsed_ms = static_cast<uint32_t>(GetTickCount() - start_tick);
            res.session_dir = detail::narrow(session_dir.wstring());
            res.wsb_path = detail::narrow(host_wsb.wstring());
            if (cfg.cleanup_session) {
                std::error_code ec;
                std::filesystem::remove_all(session_dir, ec);
            }
            return res;
        }

        if (!metadata_ready) {
            res.timed_out = !sandbox_alive ? false : true;
            res.killed = sandbox_alive;
            if (sandbox_alive)
                TerminateProcess(pi.hProcess, 0xDEAD);
            CloseHandle(pi.hProcess);
            res.error = sandbox_alive
                ? "Timed out waiting for Windows Sandbox to return execution metadata."
                : "Windows Sandbox terminated before producing execution metadata.";
            res.session_dir = detail::narrow(session_dir.wstring());
            res.wsb_path = detail::narrow(host_wsb.wstring());
            return res;
        }

        detail::close_or_terminate_process(pi.hProcess, pi.dwProcessId, 8000);
        CloseHandle(pi.hProcess);

        res.success = detail::json_bool_field(meta, "success", false);
        res.exit_code = detail::json_u32_field(meta, "exit_code", 0u);
        res.timed_out = detail::json_bool_field(meta, "timed_out", false);
        res.killed = detail::json_bool_field(meta, "killed", false);
        res.elapsed_ms = detail::json_u32_field(meta, "elapsed_ms", static_cast<uint32_t>(GetTickCount() - start_tick));
        res.stdout_data = cfg.capture_stdout ? detail::read_utf8_file(host_stdout) : std::string();
        res.stderr_data = cfg.capture_stderr ? detail::read_utf8_file(host_stderr) : std::string();
        res.session_dir = detail::narrow(session_dir.wstring());
        res.wsb_path = detail::narrow(host_wsb.wstring());


        if (cfg.cleanup_session) {
            std::error_code ec;
            std::filesystem::remove_all(session_dir, ec);
        }

        return res;
    }
}
