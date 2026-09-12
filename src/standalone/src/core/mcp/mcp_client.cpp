

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <windows.h>
#include <winsock2.h>
#include <bcrypt.h>

#include "mcp_client.hpp"
#include "auth_store.hpp"
#include "event_bus.hpp"
#include "../infra/executor.hpp"
#include "../network/burp/camoufox_bridge.hpp"
#include "../../helpers/diag_log.hpp"

#include <httplib.h>
#include <openssl/evp.h>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <memory>
#include <thread>
#include <functional>
#include <utility>
#include <unordered_map>
#include <array>
#include <condition_variable>
#include <deque>
#include <limits>
#include <new>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Ws2_32.lib")

extern mcp_client::manager_t s_mcp_client_mgr;

namespace file_browser { extern std::string current_dir; }

namespace mcp_client
{

static constexpr size_t kMaximumMcpServerNameBytes = 508;

#if defined(AIDA_C03_MCP_OAUTH_FIXTURE)
struct oauth_fixture_task_t
{
    std::uint64_t id = 0;
    std::uint64_t deadline_ms = 0;
    std::function<void()> cancel;
    std::function<void()> body;
    bool cancelled = false;
};

struct oauth_fixture_runtime_t
{
    std::mutex mutex;
    int64_t now_unix = 1700000000;
    std::uint64_t now_ms = 1000;
    std::uint64_t next_task_id = 1;
    bool browser_result = true;
    std::unordered_map<std::string, server_config_t> configs;
    std::unordered_map<std::string, aida::auth::auth_info_t> credentials;
    std::deque<c03_oauth_fixture::http_reply_t> http_replies;
    std::vector<c03_oauth_fixture::http_request_t> http_requests;
    std::deque<oauth_fixture_task_t> tasks;
    std::vector<c03_oauth_fixture::event_t> events;
    std::array<bool, 5> faults{};
};

static oauth_fixture_runtime_t& oauth_fixture_runtime()
{
    static oauth_fixture_runtime_t runtime;
    return runtime;
}

static bool consume_oauth_fixture_fault(c03_oauth_fixture::fault_point_t point)
{
    const size_t index = static_cast<size_t>(point);
    auto& runtime = oauth_fixture_runtime();
    std::lock_guard<std::mutex> lock(runtime.mutex);
    if (index >= runtime.faults.size() || !runtime.faults[index])
        return false;
    runtime.faults[index] = false;
    return true;
}
#endif

static bool valid_mcp_server_name(const std::string& server_name) noexcept
{
    if (server_name.empty() || server_name.size() > kMaximumMcpServerNameBytes
        || server_name.back() == '/')
        return false;
    for (unsigned char ch : server_name) {
        if (ch < 0x21 || ch == 0x7F || ch == '\\')
            return false;
    }
    return true;
}

static bool submit_mcp_client_task(const char* label,
                                   aida::infra::executor::domain_t domain,
                                   const char* thread_class,
                                   int priority,
                                   std::function<void()> body)
{
    aida::infra::executor::submission_t sub;
    sub.owner_subsystem = "mcp_client";
    sub.label = label;
    sub.thread_class = thread_class;
    sub.domain = domain;
    sub.priority = priority;
    sub.body = std::move(body);
    return aida::infra::executor::submit(std::move(sub)).submitted;
}

static std::uint64_t mcp_oauth_now_ms()
{
#if defined(AIDA_C03_MCP_OAUTH_FIXTURE)
    std::lock_guard<std::mutex> lock(oauth_fixture_runtime().mutex);
    return oauth_fixture_runtime().now_ms;
#else
    return aida::infra::executor::now_ms();
#endif
}

static bool mcp_oauth_deadline_ms_after(std::uint64_t delta,
                                        std::uint64_t& deadline)
{
    const std::uint64_t now = mcp_oauth_now_ms();
    if (delta == 0 || now > (std::numeric_limits<std::uint64_t>::max)() - delta)
        return false;
    deadline = now + delta;
    return true;
}

static aida::infra::executor::submit_result_t submit_mcp_oauth_task(
    const char* label,
    aida::infra::executor::domain_t domain,
    const char* thread_class,
    int priority,
    std::uint64_t deadline_ms,
    std::uint64_t generation,
    std::function<void()> cancel_hook,
    std::function<void()> body)
{
#if defined(AIDA_C03_MCP_OAUTH_FIXTURE)
    static_cast<void>(label);
    static_cast<void>(domain);
    static_cast<void>(thread_class);
    static_cast<void>(priority);
    static_cast<void>(generation);
    aida::infra::executor::submit_result_t result;
    auto& runtime = oauth_fixture_runtime();
    std::lock_guard<std::mutex> lock(runtime.mutex);
    if (runtime.tasks.size() >= 128u
        || runtime.next_task_id == (std::numeric_limits<std::uint64_t>::max)()) {
        result.reject_reason = "fixture_task_capacity_or_generation_exhausted";
        return result;
    }
    oauth_fixture_task_t task;
    task.id = runtime.next_task_id++;
    task.deadline_ms = deadline_ms;
    task.cancel = std::move(cancel_hook);
    task.body = std::move(body);
    result.submitted = true;
    result.task_id = task.id;
    runtime.tasks.push_back(std::move(task));
    return result;
#else
    aida::infra::executor::submission_t sub;
    sub.owner_subsystem = "mcp_oauth";
    sub.label = label;
    sub.thread_class = thread_class;
    sub.domain = domain;
    sub.priority = priority;
    sub.cancel_hook = std::move(cancel_hook);
    sub.deadline_ms = deadline_ms;
    sub.generation = generation;
    sub.failure_policy = "terminal_failure";
    sub.shutdown_policy = "cancel_pending";
    sub.body = std::move(body);
    return aida::infra::executor::submit(std::move(sub));
#endif
}

static bool cancel_mcp_oauth_task(std::uint64_t task_id)
{
    if (task_id == 0)
        return false;
#if defined(AIDA_C03_MCP_OAUTH_FIXTURE)
    std::function<void()> cancel;
    {
        auto& runtime = oauth_fixture_runtime();
        std::lock_guard<std::mutex> lock(runtime.mutex);
        for (auto& task : runtime.tasks) {
            if (task.id == task_id && !task.cancelled) {
                task.cancelled = true;
                cancel = task.cancel;
                break;
            }
        }
    }
    if (cancel) {
        cancel();
        return true;
    }
    return false;
#else
    return aida::infra::executor::cancel(task_id);
#endif
}

static void secure_clear_string(std::string& value) noexcept
{
    if (!value.empty())
        SecureZeroMemory(value.data(), value.size());
    std::string empty;
    value.swap(empty);
}

static std::string& global_last_error_ref()
{
    static thread_local std::string s;
    return s;
}

static void set_global_last_error(const std::string& text)
{
    secure_clear_string(global_last_error_ref());
    global_last_error_ref() = text;
#if !defined(AIDA_C03_MCP_OAUTH_FIXTURE)
    if (!text.empty()) {
        const std::string line = std::string("[mcp.oauth] ") + text;
        diag::log_tagged("mcp.oauth", line.c_str());
    }
#endif
}

static std::uint64_t mcp_log_hash(const std::string& text)
{
    std::uint64_t h = 14695981039346656037ULL;
    for (unsigned char c : text) {
        h ^= static_cast<std::uint64_t>(c);
        h *= 1099511628211ULL;
    }
    return h;
}

static std::wstring utf8_to_wide_string(const std::string& text)
{
    if (text.empty())
        return {};
    const int wlen = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
    if (wlen <= 0)
        return {};
    std::wstring out(static_cast<size_t>(wlen), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), out.data(), wlen);
    return out;
}

static bool directory_exists_w(const std::wstring& path)
{
    if (path.empty())
        return false;
    DWORD attr = GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

std::string last_error()
{
    return global_last_error_ref();
}

static std::string global_last_error_copy()
{
    return global_last_error_ref();
}


static std::string sanitize_utf8(const std::string& input)
{
    std::string result;
    result.reserve(input.size());
    for (size_t i = 0; i < input.size();) {
        unsigned char c = static_cast<unsigned char>(input[i]);
        if (c < 0x80) {
            result += static_cast<char>(c);
            ++i;
        } else if ((c & 0xE0) == 0xC0 && i + 1 < input.size()) {
            result += input[i]; result += input[i + 1]; i += 2;
        } else if ((c & 0xF0) == 0xE0 && i + 2 < input.size()) {
            result += input[i]; result += input[i + 1]; result += input[i + 2]; i += 3;
        } else if ((c & 0xF8) == 0xF0 && i + 3 < input.size()) {
            result += input[i]; result += input[i + 1]; result += input[i + 2]; result += input[i + 3]; i += 4;
        } else {
            result += "\xEF\xBF\xBD";
            ++i;
        }
    }
    return result;
}

static std::string json_dump_safe(const json& j, int indent = -1)
{
    try { return j.dump(indent); }
    catch (...) { return "{}"; }
}

static std::string lower_ascii_copy(std::string text)
{
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return text;
}

static std::string redact_labeled_log_text(std::string text)
{
    static const char* labels[] = {
        "token", "access_token", "refresh_token", "password", "passwd", "pass",
        "secret", "client_secret", "api_key", "apikey", "authorization",
        "cookie", "set-cookie", "license", "session"
    };
    for (const char* label : labels) {
        std::string lowered = lower_ascii_copy(text);
        std::size_t pos = 0;
        const std::string needle(label);
        while ((pos = lowered.find(needle, pos)) != std::string::npos) {
            std::size_t value_start = pos + needle.size();
            while (value_start < text.size() && (text[value_start] == ' ' || text[value_start] == '\t' ||
                   text[value_start] == ':' || text[value_start] == '=' || text[value_start] == '"' ||
                   text[value_start] == '\'')) {
                ++value_start;
            }
            if (value_start >= text.size()) {
                pos += needle.size();
                continue;
            }
            std::size_t value_end = value_start;
            while (value_end < text.size()) {
                const char c = text[value_end];
                if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '"' ||
                    c == '\'' || c == ',' || c == ';' || c == '&' || c == '}')
                    break;
                ++value_end;
            }
            if (value_end > value_start) {
                text.replace(value_start, value_end - value_start, "<redacted>");
                lowered = lower_ascii_copy(text);
                pos = value_start + 10;
            } else {
                pos += needle.size();
            }
        }
    }
    return text;
}

static std::string compact_log_text(std::string text, size_t cap)
{
    text = sanitize_utf8(text);
    text = redact_labeled_log_text(std::move(text));
    for (char& c : text) {
        if (c == '\n' || c == '\r' || c == '\t')
            c = ' ';
    }
    if (text.size() > cap)
        text = text.substr(0, cap) + "...(truncated)";
    return text;
}

static unsigned first_byte_or_zero(const std::string& text)
{
    if (text.empty())
        return 0;
    return static_cast<unsigned>(static_cast<unsigned char>(text.front()));
}

static std::string rpc_error_summary_for_log(const json& err)
{
    if (!err.is_object())
        return "type=" + std::string(err.type_name());
    std::string message;
    if (err.contains("message") && err["message"].is_string())
        message = compact_log_text(err["message"].get<std::string>(), 500);
    std::string data_type = "missing";
    std::size_t data_size = 0;
    if (err.contains("data")) {
        data_type = err["data"].type_name();
        if (err["data"].is_array() || err["data"].is_object())
            data_size = err["data"].size();
    }
    long long code = 0;
    bool has_code = false;
    if (err.contains("code") && err["code"].is_number_integer()) {
        code = err["code"].get<long long>();
        has_code = true;
    }
    std::ostringstream oss;
    oss << "code=" << (has_code ? std::to_string(code) : "missing")
        << " message='" << message << "'"
        << " data_type=" << data_type
        << " data_size=" << data_size;
    return oss.str();
}

static std::string request_method_for_log(const json& request)
{
    if (request.is_object() && request.contains("method") && request["method"].is_string())
        return request["method"].get<std::string>();
    return {};
}

static json initialize_params(bool include_interactive_capabilities)
{
    json capabilities = json::object();
    if (include_interactive_capabilities) {
        capabilities["roots"] = {{"listChanged", true}};
        capabilities["sampling"] = json::object();
    }

    json client_info = json::object();
    client_info["name"] = "AiDA Standalone";
    client_info["version"] = "1.0.0";

    json params = json::object();
    params["protocolVersion"] = "2024-11-05";
    params["capabilities"] = std::move(capabilities);
    params["clientInfo"] = std::move(client_info);
    return params;
}

static std::string sanitize_identifier(const std::string& input)
{
    std::string out;
    out.reserve(input.size());
    for (char c : input) {
        const unsigned char uc = static_cast<unsigned char>(c);
        const bool keep = (uc >= '0' && uc <= '9')
                       || (uc >= 'A' && uc <= 'Z')
                       || (uc >= 'a' && uc <= 'z')
                       || uc == '_'
                       || uc == '-';
        out.push_back(keep ? static_cast<char>(uc) : '_');
    }
    return out;
}

static std::string make_qualified_tool_name(const std::string& server, const std::string& tool)
{
    return sanitize_identifier(server) + "_" + sanitize_identifier(tool);
}


struct parsed_url_t
{
    std::string scheme;
    std::string host_with_port;
    std::string host;
    int         port = 0;
    bool        is_https = true;
    bool        explicit_scheme = false;
    std::string path;
    std::string origin;
};

static bool parse_url_full(const std::string& url, parsed_url_t& out)
{
    if (url.empty() || url.size() > 32768u || url.find('#') != std::string::npos)
        return false;
    for (unsigned char ch : url) {
        if (ch <= 0x20 || ch == 0x7f || ch == '\\')
            return false;
    }
    std::string work = url;
    out = parsed_url_t{};

    if (work.rfind("https://", 0) == 0) {
        out.explicit_scheme = true;
        out.scheme = "https";
        out.is_https = true;
        out.port = 443;
        work = work.substr(8);
    } else if (work.rfind("http://", 0) == 0) {
        out.explicit_scheme = true;
        out.scheme = "http";
        out.is_https = false;
        out.port = 80;
        work = work.substr(7);
    } else {
        out.scheme = "https";
        out.is_https = true;
        out.port = 443;
    }

    auto slash = work.find_first_of("/?");
    std::string authority;
    if (slash == std::string::npos) {
        authority = work;
        out.path = "/";
    } else {
        authority = work.substr(0, slash);
        out.path = work[slash] == '?' ? "/" + work.substr(slash) : work.substr(slash);
        if (out.path.empty()) out.path = "/";
    }

    if (authority.empty() || authority.find('@') != std::string::npos)
        return false;

    std::string port_text;
    if (authority.front() == '[') {
        const size_t close = authority.find(']');
        if (close == std::string::npos || close == 1)
            return false;
        out.host = authority.substr(1, close - 1);
        if (close + 1 < authority.size()) {
            if (authority[close + 1] != ':')
                return false;
            port_text = authority.substr(close + 2);
        }
    } else {
        const size_t colon = authority.rfind(':');
        if (colon != std::string::npos) {
            if (authority.find(':') != colon)
                return false;
            out.host = authority.substr(0, colon);
            port_text = authority.substr(colon + 1);
        } else {
            out.host = authority;
        }
    }
    if (out.host.empty())
        return false;
    if (!port_text.empty()) {
        unsigned long port = 0;
        for (unsigned char ch : port_text) {
            if (ch < '0' || ch > '9')
                return false;
            port = port * 10ul + static_cast<unsigned long>(ch - '0');
            if (port > 65535ul)
                return false;
        }
        if (port == 0)
            return false;
        out.port = static_cast<int>(port);
    } else if (authority.back() == ':') {
        return false;
    }

    out.host_with_port = authority;
    out.origin = out.scheme + "://" + authority;
    return !out.host.empty();
}

static bool valid_oauth_network_endpoint(const parsed_url_t& endpoint)
{
    std::string host = endpoint.host;
    std::transform(host.begin(), host.end(), host.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    const bool loopback = host == "localhost" || host == "127.0.0.1" || host == "::1";
    return endpoint.explicit_scheme && !endpoint.origin.empty()
        && endpoint.host_with_port.find('@') == std::string::npos
        && (endpoint.is_https || (endpoint.scheme == "http" && loopback));
}

static int64_t now_unix_seconds()
{
#if defined(AIDA_C03_MCP_OAUTH_FIXTURE)
    std::lock_guard<std::mutex> lock(oauth_fixture_runtime().mutex);
    return oauth_fixture_runtime().now_unix;
#else
    return static_cast<int64_t>(std::time(nullptr));
#endif
}

static bool mcp_oauth_deadline_unix_after(int64_t delta, int64_t& deadline)
{
    const int64_t now = now_unix_seconds();
    if (delta <= 0 || now > (std::numeric_limits<int64_t>::max)() - delta)
        return false;
    deadline = now + delta;
    return true;
}


static bool secure_random_bytes(unsigned char* out, size_t length)
{
    NTSTATUS rc = BCryptGenRandom(nullptr, out, static_cast<ULONG>(length),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return rc == 0;
}

static std::string base64url_encode(const unsigned char* data, size_t length)
{
    static const char kCharset[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((length + 2) / 3) * 4);
    size_t i = 0;
    while (i + 3 <= length) {
        const unsigned int v = (static_cast<unsigned int>(data[i]) << 16)
            | (static_cast<unsigned int>(data[i + 1]) << 8)
            | static_cast<unsigned int>(data[i + 2]);
        out.push_back(kCharset[(v >> 18) & 0x3F]);
        out.push_back(kCharset[(v >> 12) & 0x3F]);
        out.push_back(kCharset[(v >> 6) & 0x3F]);
        out.push_back(kCharset[v & 0x3F]);
        i += 3;
    }
    if (i < length) {
        const size_t left = length - i;
        unsigned int v = static_cast<unsigned int>(data[i]) << 16;
        if (left == 2)
            v |= static_cast<unsigned int>(data[i + 1]) << 8;
        out.push_back(kCharset[(v >> 18) & 0x3F]);
        out.push_back(kCharset[(v >> 12) & 0x3F]);
        if (left == 2)
            out.push_back(kCharset[(v >> 6) & 0x3F]);
    }
    std::replace(out.begin(), out.end(), '+', '-');
    std::replace(out.begin(), out.end(), '/', '_');
    return out;
}

static std::string generate_pkce_verifier()
{
    static const char kVerifierCharset[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    constexpr size_t kLen = 43;
    unsigned char rnd[kLen] = {};
    if (!secure_random_bytes(rnd, kLen)) {
        SecureZeroMemory(rnd, sizeof(rnd));
        return {};
    }
    const size_t charset_len = std::strlen(kVerifierCharset);
    std::string out;
    out.reserve(kLen);
    for (size_t i = 0; i < kLen; ++i)
        out.push_back(kVerifierCharset[rnd[i] % charset_len]);
    SecureZeroMemory(rnd, sizeof(rnd));
    return out;
}

static std::string sha256_base64url(const std::string& input)
{
    unsigned char digest[32] = {};
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
        return {};
    std::string out;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1
        && EVP_DigestUpdate(ctx, input.data(), input.size()) == 1) {
        unsigned int dl = 0;
        if (EVP_DigestFinal_ex(ctx, digest, &dl) == 1)
            out = base64url_encode(digest, dl);
    }
    EVP_MD_CTX_free(ctx);
    SecureZeroMemory(digest, sizeof(digest));
    return out;
}

static std::string generate_state_token()
{
    unsigned char rnd[32] = {};
    if (!secure_random_bytes(rnd, sizeof(rnd))) {
        SecureZeroMemory(rnd, sizeof(rnd));
        return {};
    }
    std::string token = base64url_encode(rnd, sizeof(rnd));
    SecureZeroMemory(rnd, sizeof(rnd));
    return token;
}

static std::string url_encode(const std::string& s)
{
    std::string out;
    out.reserve(s.size() * 3);
    for (unsigned char c : s) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
            || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            char buf[4];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%%%02X", c);
            out.append(buf);
        }
    }
    return out;
}


static bool ensure_winsock()
{
    static std::once_flag once;
    static int rc = 0;
    std::call_once(once, []() {
        WSADATA wsa{};
        rc = WSAStartup(MAKEWORD(2, 2), &wsa);
    });
    return rc == 0;
}

static bool open_browser(const std::string& url)
{
    if (url.empty())
        return false;
#if defined(AIDA_C03_MCP_OAUTH_FIXTURE)
    if (consume_oauth_fixture_fault(c03_oauth_fixture::fault_point_t::browser))
        throw std::bad_alloc();
    std::lock_guard<std::mutex> lock(oauth_fixture_runtime().mutex);
    return oauth_fixture_runtime().browser_result;
#else
    if (!aida::burp::camoufox::ensure_ready()) {
        diag::log_tagged("mcp.oauth",
            "[mcp.oauth] Camoufox ensure_ready failed; refusing default-browser fallback");
        return false;
    }
    const bool opened = aida::burp::camoufox::navigate(url, "domcontentloaded", 45000);
    diag::log_tagged("mcp.oauth",
        opened
            ? "[mcp.oauth] authorization_url opened in Camoufox"
            : "[mcp.oauth] Camoufox navigate failed; refusing default-browser fallback");
    return opened;
#endif
}

struct oauth_request_control_t
{
    std::mutex mutex;
    std::atomic<bool> cancelled{false};
    httplib::Client* active_client = nullptr;

    bool bind(httplib::Client& client) noexcept
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (cancelled.load(std::memory_order_acquire))
            return false;
        active_client = &client;
        return true;
    }

    void unbind(httplib::Client& client) noexcept
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (active_client == &client)
            active_client = nullptr;
    }

    void cancel() noexcept
    {
        cancelled.store(true, std::memory_order_release);
        std::lock_guard<std::mutex> lock(mutex);
        if (active_client) {
            try {
                active_client->stop();
            } catch (...) {
            }
        }
    }
};


struct callback_listener_t
{
    std::atomic<SOCKET> sock{INVALID_SOCKET};
    std::atomic<SOCKET> accepted_sock{INVALID_SOCKET};
    std::atomic<bool> stop{false};
    std::uint64_t      generation = 0;
    std::shared_ptr<struct oauth_transient_flow_t> flow;
};

enum class oauth_flow_phase_t
{
    initializing,
    active,
    exchanging,
    committed,
    terminal
};

struct oauth_transient_flow_t
{
    std::mutex mutex;
    std::mutex commit_mutex;
    std::condition_variable terminal_cv;
    std::uint64_t generation = 0;
    std::array<unsigned char, 16> incarnation{};
    std::uint64_t config_generation = 0;
    std::array<unsigned char, 16> config_incarnation{};
    std::uint64_t persistence_epoch = 0;
    oauth_flow_phase_t phase = oauth_flow_phase_t::initializing;
    bool cancelled = false;
    bool callback_done = false;
    bool event_published = false;
    bool terminal_ready = false;
    bool terminal_success = false;
    bool dynamic_client = false;
    std::string server_name;
    std::string mcp_endpoint;
    std::string config_fingerprint;
    std::string state_token;
    std::string code_verifier;
    std::string client_id;
    std::string client_secret;
    std::string redirect_uri;
    std::string token_endpoint;
    std::string scope;
    std::string received_code;
    std::string terminal_code_digest;
    std::string error;
    int64_t deadline_unix = 0;
    std::uint64_t listener_task_id = 0;
    std::uint64_t poll_task_id = 0;
    std::uint64_t initialization_task_id = 0;
    std::shared_ptr<oauth_request_control_t> request_control;
    std::weak_ptr<callback_listener_t> listener;

    ~oauth_transient_flow_t();
};

struct oauth_state_binding_t
{
    std::shared_ptr<oauth_transient_flow_t> flow;
    std::uint64_t generation = 0;
    std::array<unsigned char, 16> incarnation{};
};

struct secure_string_scope_t
{
    std::string& value;
    ~secure_string_scope_t()
    {
        secure_clear_string(value);
    }
};

struct scope_exit_t
{
    std::function<void()> body;
    ~scope_exit_t()
    {
        if (body)
            body();
    }
};

static void secure_clear_json_strings(json& value) noexcept
{
    try {
        if (value.is_string()) {
            auto& text = value.get_ref<std::string&>();
            secure_clear_string(text);
        } else if (value.is_object()) {
            for (auto it = value.begin(); it != value.end(); ++it)
                secure_clear_json_strings(it.value());
        } else if (value.is_array()) {
            for (auto& child : value)
                secure_clear_json_strings(child);
        }
        value = json::object();
    } catch (...) {
        value = json::object();
    }
}

static void secure_clear_auth_info(aida::auth::auth_info_t& info) noexcept
{
    secure_clear_string(info.refresh);
    secure_clear_string(info.access);
    secure_clear_string(info.account_id);
    secure_clear_string(info.enterprise_url);
    secure_clear_string(info.email);
    secure_clear_string(info.api_key);
    secure_clear_string(info.wellknown_key);
    secure_clear_string(info.wellknown_token);
    secure_clear_json_strings(info.metadata);
    secure_clear_string(info.custom_client_id);
    secure_clear_string(info.custom_redirect_uri);
    for (auto& scope : info.custom_scopes)
        secure_clear_string(scope);
    info.custom_scopes.clear();
    info.expires_unix = 0;
    info.kind = aida::auth::auth_kind_t::none;
}

struct secure_auth_info_scope_t
{
    aida::auth::auth_info_t& info;
    ~secure_auth_info_scope_t()
    {
        secure_clear_auth_info(info);
    }
};

static void secure_clear_server_config(server_config_t& config) noexcept
{
    secure_clear_string(config.name);
    secure_clear_string(config.url);
    secure_clear_string(config.command);
    for (auto& argument : config.args)
        secure_clear_string(argument);
    config.args.clear();
    while (!config.env.empty()) {
        auto node = config.env.extract(config.env.begin());
        secure_clear_string(node.key());
        secure_clear_string(node.mapped());
    }
    secure_clear_string(config.api_key);
    secure_clear_string(config.oauth_client_id);
    secure_clear_string(config.oauth_client_secret);
    secure_clear_string(config.oauth_scope);
    secure_clear_string(config.oauth_redirect_uri);
    config.enabled = false;
    config.auto_connect = false;
    config.oauth_enabled = false;
}

struct secure_server_config_scope_t
{
    server_config_t& config;
    ~secure_server_config_scope_t()
    {
        secure_clear_server_config(config);
    }
};

static void append_fingerprint_field(std::string& canonical, const std::string& value)
{
    canonical += std::to_string(value.size());
    canonical.push_back(':');
    canonical.append(value);
    canonical.push_back(';');
}

static std::string server_config_fingerprint(const server_config_t& config)
{
    std::string canonical;
    secure_string_scope_t canonical_guard{canonical};
    canonical.reserve(512u + config.url.size() + config.command.size()
        + config.api_key.size() + config.oauth_client_secret.size());
    append_fingerprint_field(canonical, config.name);
    append_fingerprint_field(canonical, std::to_string(static_cast<int>(config.transport)));
    append_fingerprint_field(canonical, config.url);
    append_fingerprint_field(canonical, config.command);
    append_fingerprint_field(canonical, std::to_string(config.args.size()));
    for (const auto& argument : config.args)
        append_fingerprint_field(canonical, argument);
    append_fingerprint_field(canonical, std::to_string(config.env.size()));
    for (const auto& entry : config.env) {
        append_fingerprint_field(canonical, entry.first);
        append_fingerprint_field(canonical, entry.second);
    }
    append_fingerprint_field(canonical, config.api_key);
    append_fingerprint_field(canonical, config.enabled ? "1" : "0");
    append_fingerprint_field(canonical, config.auto_connect ? "1" : "0");
    append_fingerprint_field(canonical, config.oauth_enabled ? "1" : "0");
    append_fingerprint_field(canonical, config.oauth_client_id);
    append_fingerprint_field(canonical, config.oauth_client_secret);
    append_fingerprint_field(canonical, config.oauth_scope);
    append_fingerprint_field(canonical, config.oauth_redirect_uri);
    return sha256_base64url(canonical);
}

struct secure_json_scope_t
{
    json& value;
    ~secure_json_scope_t()
    {
        secure_clear_json_strings(value);
    }
};

struct secure_http_headers_scope_t
{
    httplib::Headers& headers;
    ~secure_http_headers_scope_t()
    {
        for (auto& header : headers)
            secure_clear_string(header.second);
        headers.clear();
    }
};

static void secure_clear_http_response(httplib::Response& response) noexcept
{
    secure_clear_string(response.body);
    for (auto& header : response.headers)
        secure_clear_string(header.second);
    response.headers.clear();
}

struct secure_http_response_scope_t
{
    httplib::Response& response;
    ~secure_http_response_scope_t()
    {
        secure_clear_http_response(response);
    }
};

struct oauth_exchange_material_t
{
    std::string server_name;
    std::string mcp_endpoint;
    std::string token_endpoint;
    std::string client_id;
    std::string client_secret;
    std::string redirect_uri;
    std::string code_verifier;
    std::string authorization_code;
    std::string scope;
    std::string config_fingerprint;
    std::uint64_t config_generation = 0;
    std::array<unsigned char, 16> config_incarnation{};
    std::uint64_t persistence_epoch = 0;
    int64_t deadline_unix = 0;
    bool dynamic_client = false;
    std::shared_ptr<oauth_request_control_t> request_control;

    ~oauth_exchange_material_t()
    {
        secure_clear_string(server_name);
        secure_clear_string(mcp_endpoint);
        secure_clear_string(token_endpoint);
        secure_clear_string(client_id);
        secure_clear_string(client_secret);
        secure_clear_string(redirect_uri);
        secure_clear_string(code_verifier);
        secure_clear_string(authorization_code);
        secure_clear_string(scope);
        secure_clear_string(config_fingerprint);
        SecureZeroMemory(config_incarnation.data(), config_incarnation.size());
        if (request_control)
            request_control->cancel();
        request_control.reset();
    }
};

static void clear_oauth_flow_locked(oauth_transient_flow_t& flow) noexcept
{
    secure_clear_string(flow.server_name);
    secure_clear_string(flow.mcp_endpoint);
    secure_clear_string(flow.config_fingerprint);
    secure_clear_string(flow.state_token);
    secure_clear_string(flow.code_verifier);
    secure_clear_string(flow.client_id);
    secure_clear_string(flow.client_secret);
    secure_clear_string(flow.redirect_uri);
    secure_clear_string(flow.token_endpoint);
    secure_clear_string(flow.scope);
    secure_clear_string(flow.received_code);
    secure_clear_string(flow.terminal_code_digest);
    secure_clear_string(flow.error);
    if (flow.request_control)
        flow.request_control->cancel();
    flow.request_control.reset();
    flow.listener.reset();
    SecureZeroMemory(flow.incarnation.data(), flow.incarnation.size());
    SecureZeroMemory(flow.config_incarnation.data(), flow.config_incarnation.size());
    flow.generation = 0;
    flow.config_generation = 0;
    flow.persistence_epoch = 0;
    flow.deadline_unix = 0;
    flow.listener_task_id = 0;
    flow.poll_task_id = 0;
    flow.initialization_task_id = 0;
    flow.cancelled = true;
    flow.callback_done = true;
    flow.event_published = true;
    flow.terminal_ready = true;
    flow.terminal_success = false;
    flow.dynamic_client = false;
    flow.phase = oauth_flow_phase_t::terminal;
}

oauth_transient_flow_t::~oauth_transient_flow_t()
{
    clear_oauth_flow_locked(*this);
}

static oauth_state_binding_t* oauth_state_binding(oauth_state_t& state) noexcept
{
    return static_cast<oauth_state_binding_t*>(state.flow_binding);
}

static void release_oauth_state_binding(oauth_state_t& state) noexcept
{
    auto* binding = oauth_state_binding(state);
    state.flow_binding = nullptr;
    delete binding;
}

static bool bind_oauth_state(oauth_state_t& state,
                             const std::shared_ptr<oauth_transient_flow_t>& flow) noexcept
{
    release_oauth_state_binding(state);
    auto* binding = new (std::nothrow) oauth_state_binding_t();
    if (!binding)
        return false;
    binding->flow = flow;
    binding->generation = flow->generation;
    binding->incarnation = flow->incarnation;
    state.flow_binding = binding;
    return true;
}

static void scrub_oauth_state_transients(oauth_state_t& state) noexcept
{
    secure_clear_string(state.server_name);
    secure_clear_string(state.authorization_url);
    secure_clear_string(state.state_token);
    secure_clear_string(state.code_verifier);
    secure_clear_string(state.code_challenge);
    secure_clear_string(state.client_id);
    secure_clear_string(state.client_secret);
    secure_clear_string(state.redirect_uri);
    secure_clear_string(state.token_endpoint);
    secure_clear_string(state.authorization_endpoint);
    secure_clear_string(state.registration_endpoint);
    secure_clear_string(state.scope);
    release_oauth_state_binding(state);
    state.callback_port = 0;
    state.deadline_unix = 0;
}

struct oauth_terminal_receipt_t
{
    std::string server_name;
    std::string code_digest;
    std::string error;
    int64_t expires_unix = 0;
    bool success = false;

    ~oauth_terminal_receipt_t()
    {
        secure_clear_string(server_name);
        secure_clear_string(code_digest);
        secure_clear_string(error);
    }

    oauth_terminal_receipt_t() = default;
    oauth_terminal_receipt_t(const oauth_terminal_receipt_t&) = delete;
    oauth_terminal_receipt_t& operator=(const oauth_terminal_receipt_t&) = delete;
    oauth_terminal_receipt_t(oauth_terminal_receipt_t&&) noexcept = default;
    oauth_terminal_receipt_t& operator=(oauth_terminal_receipt_t&&) noexcept = default;
};

static std::mutex& oauth_terminal_receipt_mutex()
{
    static std::mutex mutex;
    return mutex;
}

static std::vector<oauth_terminal_receipt_t>& oauth_terminal_receipts()
{
    static std::vector<oauth_terminal_receipt_t> receipts;
    return receipts;
}

static void record_oauth_terminal_receipt(const std::string& server_name,
                                          const std::string& code_digest,
                                          const std::string& error,
                                          bool success)
{
    constexpr size_t kMaximumReceipts = 128;
    constexpr int64_t kReceiptLifetimeSeconds = 300;
    const int64_t now = now_unix_seconds();
    std::lock_guard<std::mutex> lock(oauth_terminal_receipt_mutex());
    auto& receipts = oauth_terminal_receipts();
    receipts.erase(std::remove_if(receipts.begin(), receipts.end(),
        [now](const oauth_terminal_receipt_t& receipt) {
            return receipt.expires_unix <= now;
        }), receipts.end());
    for (auto& receipt : receipts) {
        if (receipt.server_name == server_name && receipt.code_digest == code_digest) {
            secure_clear_string(receipt.error);
            receipt.error = error;
            receipt.success = success;
            receipt.expires_unix = now + kReceiptLifetimeSeconds;
            return;
        }
    }
    if (receipts.size() >= kMaximumReceipts)
        receipts.erase(receipts.begin());
    oauth_terminal_receipt_t receipt;
    receipt.server_name = server_name;
    receipt.code_digest = code_digest;
    receipt.error = error;
    receipt.success = success;
    receipt.expires_unix = now + kReceiptLifetimeSeconds;
    receipts.push_back(std::move(receipt));
}

static bool find_oauth_terminal_receipt(const std::string& server_name,
                                        const std::string& code_digest,
                                        bool& success,
                                        std::string& error)
{
    const int64_t now = now_unix_seconds();
    std::lock_guard<std::mutex> lock(oauth_terminal_receipt_mutex());
    auto& receipts = oauth_terminal_receipts();
    receipts.erase(std::remove_if(receipts.begin(), receipts.end(),
        [now](const oauth_terminal_receipt_t& receipt) {
            return receipt.expires_unix <= now;
        }), receipts.end());
    for (const auto& receipt : receipts) {
        if (receipt.server_name == server_name && receipt.code_digest == code_digest) {
            success = receipt.success;
            error = receipt.error;
            return true;
        }
    }
    return false;
}

struct oauth_trigger_request_t
{
    std::atomic<bool> cancelled{false};
    std::atomic<bool> completed{false};
    std::atomic<bool> callback_done{false};
    std::atomic<bool> event_done{false};
    std::uint64_t generation = 0;
    std::atomic<std::uint64_t> task_id{0};
    std::shared_ptr<oauth_state_t> state;
    auth_completion_callback_t callback;
    std::string server_name;

    ~oauth_trigger_request_t()
    {
        secure_clear_string(server_name);
    }
};

static std::mutex& oauth_trigger_registry_mutex()
{
    static std::mutex mutex;
    return mutex;
}

static std::unordered_map<std::string, std::shared_ptr<oauth_trigger_request_t>>& oauth_trigger_registry()
{
    static std::unordered_map<std::string, std::shared_ptr<oauth_trigger_request_t>> requests;
    return requests;
}

static std::uint64_t& oauth_trigger_generation()
{
    static std::uint64_t generation = 0;
    return generation;
}

static std::mutex& oauth_flow_registry_mutex()
{
    static std::mutex mutex;
    return mutex;
}

static std::unordered_map<std::string, std::shared_ptr<oauth_transient_flow_t>>& oauth_flow_registry()
{
    static std::unordered_map<std::string, std::shared_ptr<oauth_transient_flow_t>> flows;
    return flows;
}

static std::uint64_t& oauth_flow_generation()
{
    static std::uint64_t generation = 0;
    return generation;
}

static std::mutex& mcp_auth_epoch_mutex()
{
    static std::mutex mutex;
    return mutex;
}

static std::unordered_map<std::string, std::uint64_t>& mcp_auth_epochs()
{
    static std::unordered_map<std::string, std::uint64_t> epochs;
    return epochs;
}

static bool read_mcp_auth_epoch(const std::string& server_name, std::uint64_t& epoch)
{
    constexpr size_t kMaximumEpochs = 128;
    std::lock_guard<std::mutex> lock(mcp_auth_epoch_mutex());
    auto& epochs = mcp_auth_epochs();
    const auto existing = epochs.find(server_name);
    if (existing != epochs.end()) {
        epoch = existing->second;
        return true;
    }
    if (epochs.size() >= kMaximumEpochs)
        return false;
    epoch = 1;
    epochs.emplace(server_name, epoch);
    return true;
}

static bool claim_mcp_auth_epoch(const std::string& server_name, std::uint64_t expected)
{
    std::lock_guard<std::mutex> lock(mcp_auth_epoch_mutex());
    const auto it = mcp_auth_epochs().find(server_name);
    if (it == mcp_auth_epochs().end() || it->second != expected
        || it->second == (std::numeric_limits<std::uint64_t>::max)())
        return false;
    ++it->second;
    return true;
}

static bool mcp_auth_epoch_matches(const std::string& server_name, std::uint64_t expected)
{
    std::lock_guard<std::mutex> lock(mcp_auth_epoch_mutex());
    const auto it = mcp_auth_epochs().find(server_name);
    return it != mcp_auth_epochs().end() && it->second == expected;
}

static std::uint64_t next_mcp_auth_epoch(std::uint64_t epoch) noexcept
{
    if (epoch == (std::numeric_limits<std::uint64_t>::max)())
        return 0;
    ++epoch;
    return epoch;
}

static void invalidate_mcp_auth_epoch(const std::string& server_name)
{
    std::uint64_t epoch = 0;
    if (!read_mcp_auth_epoch(server_name, epoch))
        return;
    std::lock_guard<std::mutex> lock(mcp_auth_epoch_mutex());
    const auto it = mcp_auth_epochs().find(server_name);
    if (it == mcp_auth_epochs().end()
        || it->second == (std::numeric_limits<std::uint64_t>::max)())
        return;
    ++it->second;
}

struct mcp_config_incarnation_t
{
    std::uint64_t generation = 0;
    std::array<unsigned char, 16> incarnation{};
    std::string fingerprint;
};

static std::mutex& mcp_config_incarnation_mutex()
{
    static std::mutex mutex;
    return mutex;
}

static std::unordered_map<std::string, mcp_config_incarnation_t>& mcp_config_incarnations()
{
    static std::unordered_map<std::string, mcp_config_incarnation_t> incarnations;
    return incarnations;
}

static bool advance_mcp_config_incarnation(const std::string& server_name,
                                           const std::string& fingerprint,
                                           mcp_config_incarnation_t* snapshot = nullptr,
                                           bool* changed = nullptr)
{
    constexpr size_t kMaximumConfigIncarnations = 128;
    std::lock_guard<std::mutex> lock(mcp_config_incarnation_mutex());
    auto& incarnations = mcp_config_incarnations();
    auto it = incarnations.find(server_name);
    bool did_change = false;
    if (it == incarnations.end()) {
        if (incarnations.size() >= kMaximumConfigIncarnations)
            return false;
        mcp_config_incarnation_t created;
        created.generation = 1;
        created.fingerprint = fingerprint;
        if (!secure_random_bytes(created.incarnation.data(), created.incarnation.size()))
            return false;
        it = incarnations.emplace(server_name, std::move(created)).first;
        did_change = true;
    } else if (it->second.fingerprint != fingerprint) {
        if (it->second.generation == (std::numeric_limits<std::uint64_t>::max)())
            return false;
        std::array<unsigned char, 16> next_incarnation{};
        if (!secure_random_bytes(next_incarnation.data(), next_incarnation.size()))
            return false;
        ++it->second.generation;
        it->second.incarnation = next_incarnation;
        it->second.fingerprint = fingerprint;
        did_change = true;
    }
    if (snapshot)
        *snapshot = it->second;
    if (changed)
        *changed = did_change;
    return true;
}

static bool invalidate_mcp_config_incarnation(const std::string& server_name)
{
    std::lock_guard<std::mutex> lock(mcp_config_incarnation_mutex());
    const auto it = mcp_config_incarnations().find(server_name);
    if (it == mcp_config_incarnations().end()
        || it->second.generation == (std::numeric_limits<std::uint64_t>::max)())
        return false;
    std::array<unsigned char, 16> next_incarnation{};
    if (!secure_random_bytes(next_incarnation.data(), next_incarnation.size()))
        return false;
    ++it->second.generation;
    it->second.incarnation = next_incarnation;
    secure_clear_string(it->second.fingerprint);
    return true;
}

static bool mcp_config_incarnation_matches(const std::string& server_name,
                                           const std::string& fingerprint,
                                           std::uint64_t generation,
                                           const std::array<unsigned char, 16>& incarnation)
{
    std::lock_guard<std::mutex> lock(mcp_config_incarnation_mutex());
    const auto it = mcp_config_incarnations().find(server_name);
    return it != mcp_config_incarnations().end()
        && it->second.generation == generation
        && it->second.incarnation == incarnation
        && it->second.fingerprint == fingerprint;
}

static void ensure_oauth_reaper_task();
static void finalize_stale_oauth_flow(
    const std::shared_ptr<oauth_transient_flow_t>& flow);

static bool register_oauth_flow(const std::shared_ptr<oauth_transient_flow_t>& flow,
                                std::string& error)
{
    constexpr size_t kMaximumFlows = 128;
    std::vector<std::shared_ptr<oauth_transient_flow_t>> stale;
    {
        std::lock_guard<std::mutex> registry_lock(oauth_flow_registry_mutex());
        auto& registry = oauth_flow_registry();
        const int64_t now = now_unix_seconds();
        for (auto it = registry.begin(); it != registry.end();) {
            bool remove = false;
            {
                std::lock_guard<std::mutex> flow_lock(it->second->mutex);
                remove = it->second->cancelled
                    || it->second->phase == oauth_flow_phase_t::terminal
                    || (it->second->deadline_unix != 0 && now > it->second->deadline_unix);
                if (remove && !it->second->terminal_ready)
                    it->second->cancelled = true;
            }
            if (remove) {
                bool terminal = false;
                {
                    std::lock_guard<std::mutex> flow_lock(it->second->mutex);
                    terminal = it->second->terminal_ready;
                }
                if (terminal) {
                    ++it;
                } else {
                    stale.push_back(it->second);
                    ++it;
                }
            } else {
                ++it;
            }
        }
    }
    for (const auto& expired : stale)
        finalize_stale_oauth_flow(expired);

    bool accepted = false;
    {
        std::lock_guard<std::mutex> registry_lock(oauth_flow_registry_mutex());
        auto& registry = oauth_flow_registry();
        if (registry.find(flow->server_name) != registry.end()) {
            error = "an OAuth flow is already active for this MCP server";
        } else if (registry.size() >= kMaximumFlows) {
            error = "the bounded MCP OAuth flow registry is full";
        } else {
            std::uint64_t& generation = oauth_flow_generation();
            if (generation == (std::numeric_limits<std::uint64_t>::max)()) {
                error = "the MCP OAuth flow generation space is exhausted; restart is required";
            } else if (!secure_random_bytes(flow->incarnation.data(), flow->incarnation.size())) {
                error = "the MCP OAuth flow incarnation could not be generated";
            } else {
                ++generation;
                flow->generation = generation;
                registry.emplace(flow->server_name, flow);
                accepted = true;
            }
        }
    }
    if (accepted)
        ensure_oauth_reaper_task();
    return accepted;
}

static std::shared_ptr<oauth_transient_flow_t> find_oauth_flow(
    const std::string& server_name,
    const std::string* expected_state_token)
{
    std::lock_guard<std::mutex> registry_lock(oauth_flow_registry_mutex());
    const auto it = oauth_flow_registry().find(server_name);
    if (it == oauth_flow_registry().end())
        return {};
    const auto flow = it->second;
    std::lock_guard<std::mutex> flow_lock(flow->mutex);
    if (expected_state_token && flow->state_token != *expected_state_token)
        return {};
    return flow;
}

struct oauth_callback_params_t
{
    std::string code;
    std::string state;
    bool has_code = false;
    bool has_state = false;
    bool has_error = false;
    bool valid = true;

    oauth_callback_params_t() = default;
    oauth_callback_params_t(const oauth_callback_params_t&) = delete;
    oauth_callback_params_t& operator=(const oauth_callback_params_t&) = delete;
    oauth_callback_params_t(oauth_callback_params_t&& other) noexcept
        : code(std::move(other.code)),
          state(std::move(other.state)),
          has_code(other.has_code),
          has_state(other.has_state),
          has_error(other.has_error),
          valid(other.valid)
    {
        other.has_code = false;
        other.has_state = false;
        other.has_error = false;
        other.valid = false;
    }

    ~oauth_callback_params_t()
    {
        secure_clear_string(code);
        secure_clear_string(state);
    }
};

static bool decode_query_component(const std::string& encoded,
                                   size_t maximum,
                                   std::string& decoded)
{
    decoded.clear();
    if (encoded.size() > maximum * 3u)
        return false;
    decoded.reserve((std::min)(encoded.size(), maximum));
    auto hex_value = [](unsigned char ch) -> int {
        if (ch >= '0' && ch <= '9') return static_cast<int>(ch - '0');
        if (ch >= 'A' && ch <= 'F') return static_cast<int>(ch - 'A' + 10);
        if (ch >= 'a' && ch <= 'f') return static_cast<int>(ch - 'a' + 10);
        return -1;
    };
    for (size_t i = 0; i < encoded.size(); ++i) {
        unsigned char value = static_cast<unsigned char>(encoded[i]);
        if (value == '+') {
            value = ' ';
        } else if (value == '%') {
            if (i + 2 >= encoded.size())
                return false;
            const int high = hex_value(static_cast<unsigned char>(encoded[i + 1]));
            const int low = hex_value(static_cast<unsigned char>(encoded[i + 2]));
            if (high < 0 || low < 0)
                return false;
            value = static_cast<unsigned char>((high << 4) | low);
            i += 2;
        }
        if (value == 0 || value == '\r' || value == '\n' || decoded.size() >= maximum)
            return false;
        decoded.push_back(static_cast<char>(value));
    }
    return true;
}

static oauth_callback_params_t parse_query_string(const std::string& query)
{
    oauth_callback_params_t out;
    if (query.size() > 16384u) {
        out.valid = false;
        return out;
    }
    size_t pos = 0;
    size_t fields = 0;
    while (pos < query.size()) {
        if (++fields > 16u) {
            out.valid = false;
            return out;
        }
        size_t amp = query.find('&', pos);
        if (amp == std::string::npos) amp = query.size();
        std::string pair = query.substr(pos, amp - pos);
        secure_string_scope_t pair_guard{pair};
        const size_t eq = pair.find('=');
        std::string encoded_key = (eq == std::string::npos) ? pair : pair.substr(0, eq);
        std::string encoded_value = (eq == std::string::npos) ? std::string{} : pair.substr(eq + 1);
        secure_string_scope_t encoded_key_guard{encoded_key};
        secure_string_scope_t encoded_value_guard{encoded_value};
        std::string key;
        std::string val;
        secure_string_scope_t key_guard{key};
        secure_string_scope_t value_guard{val};
        if (!decode_query_component(encoded_key, 64u, key)
            || !decode_query_component(encoded_value, 4096u, val)) {
            out.valid = false;
            return out;
        }
        if (key == "code") {
            if (out.has_code) out.valid = false;
            out.has_code = true;
            out.code = val;
        } else if (key == "state") {
            if (out.has_state) out.valid = false;
            out.has_state = true;
            out.state = val;
        } else if (key == "error") {
            if (out.has_error) out.valid = false;
            out.has_error = true;
        }
        if (!out.valid)
            return out;
        pos = amp + 1;
    }
    return out;
}

static std::string build_callback_response_html_success()
{
    return std::string(
        "<!doctype html><html><head><title>AiDA MCP Authorization Successful</title>"
        "<style>body{font-family:system-ui,-apple-system,sans-serif;display:flex;"
        "justify-content:center;align-items:center;height:100vh;margin:0;"
        "background:#131010;color:#f1ecec}.container{text-align:center;padding:2rem}"
        "h1{color:#4ade80;margin-bottom:1rem}p{color:#b7b1b1}</style></head><body>"
        "<div class=\"container\"><h1>Authorization Successful</h1>"
        "<p>You can close this window and return to AiDA.</p></div>"
        "<script>setTimeout(function(){window.close();},2000);</script></body></html>");
}

static std::string build_callback_response_html_failure(const std::string& reason)
{
    std::string esc;
    esc.reserve(reason.size() + 16);
    for (char c : reason) {
        switch (c) {
            case '<': esc += "&lt;"; break;
            case '>': esc += "&gt;"; break;
            case '&': esc += "&amp;"; break;
            case '"': esc += "&quot;"; break;
            default: esc.push_back(c); break;
        }
    }
    return std::string(
        "<!doctype html><html><head><title>AiDA MCP Authorization Failed</title>"
        "<style>body{font-family:system-ui,-apple-system,sans-serif;display:flex;"
        "justify-content:center;align-items:center;height:100vh;margin:0;"
        "background:#131010;color:#f1ecec}.container{text-align:center;padding:2rem}"
        "h1{color:#fc533a;margin-bottom:1rem}p{color:#b7b1b1}.error{color:#ff917b;"
        "font-family:monospace;margin-top:1rem;padding:1rem;background:#3c140d;"
        "border-radius:0.5rem}</style></head><body><div class=\"container\">"
        "<h1>Authorization Failed</h1><p>An error occurred during authorization.</p>"
        "<div class=\"error\">") + esc
        + "</div></div></body></html>";
}

static void send_listener_response(SOCKET client, int status, const std::string& body)
{
    std::string status_text;
    switch (status) {
        case 200: status_text = "OK"; break;
        case 400: status_text = "Bad Request"; break;
        case 404: status_text = "Not Found"; break;
        default: status_text = "OK"; break;
    }
    std::string resp = "HTTP/1.1 " + std::to_string(status) + " " + status_text + "\r\n";
    resp += "Content-Type: text/html; charset=utf-8\r\n";
    resp += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    resp += "Connection: close\r\n";
    resp += "Server: AiDA/1.0\r\n";
    resp += "\r\n";
    resp += body;
    ::send(client, resp.data(), static_cast<int>(resp.size()), 0);
}

static void complete_oauth_callback(const std::shared_ptr<oauth_transient_flow_t>& flow,
                                    std::uint64_t generation,
                                    std::string code,
                                    std::string error)
{
    std::lock_guard<std::mutex> lock(flow->mutex);
    if (flow->generation != generation || flow->phase != oauth_flow_phase_t::active
        || flow->cancelled || flow->callback_done) {
        secure_clear_string(code);
        secure_clear_string(error);
        return;
    }
    if (flow->deadline_unix != 0 && now_unix_seconds() > flow->deadline_unix) {
        secure_clear_string(code);
        secure_clear_string(error);
        flow->error = "OAuth flow timed out";
    } else {
        flow->received_code = std::move(code);
        flow->error = std::move(error);
    }
    flow->callback_done = true;
}

static bool oauth_flow_cancelled_or_expired(const std::shared_ptr<oauth_transient_flow_t>& flow,
                                            std::uint64_t generation)
{
    std::lock_guard<std::mutex> lock(flow->mutex);
    return flow->generation != generation || flow->cancelled
        || flow->phase == oauth_flow_phase_t::terminal
        || (flow->deadline_unix != 0 && now_unix_seconds() > flow->deadline_unix);
}

static void close_oauth_accepted_socket(const std::shared_ptr<callback_listener_t>& ctx) noexcept
{
    const SOCKET client = ctx->accepted_sock.exchange(INVALID_SOCKET, std::memory_order_acq_rel);
    if (client != INVALID_SOCKET) {
        shutdown(client, SD_BOTH);
        closesocket(client);
    }
}

static void finalize_expired_oauth_listener_flow(
    const std::shared_ptr<oauth_transient_flow_t>& flow);

static void oauth_listener_thread(std::shared_ptr<callback_listener_t> ctx)
{
    const auto flow = ctx->flow;
    while (!ctx->stop.load(std::memory_order_acquire)
        && !oauth_flow_cancelled_or_expired(flow, ctx->generation)) {
        WSAPOLLFD pfd{};
        pfd.fd = ctx->sock.load(std::memory_order_acquire);
        if (pfd.fd == INVALID_SOCKET)
            return;
        pfd.events = POLLIN;
        int rc = WSAPoll(&pfd, 1, 250);
        if (rc <= 0)
            continue;

        sockaddr_storage cli{};
        int cli_len = sizeof(cli);
        const SOCKET listener = ctx->sock.load(std::memory_order_acquire);
        if (listener == INVALID_SOCKET)
            return;
        SOCKET client = accept(listener, reinterpret_cast<sockaddr*>(&cli), &cli_len);
        if (client == INVALID_SOCKET)
            continue;
        ctx->accepted_sock.store(client, std::memory_order_release);
        if (ctx->stop.load(std::memory_order_acquire)
            || oauth_flow_cancelled_or_expired(flow, ctx->generation)) {
            close_oauth_accepted_socket(ctx);
            return;
        }

        DWORD tv = 5000;
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO,
            reinterpret_cast<const char*>(&tv), sizeof(tv));
        setsockopt(client, SOL_SOCKET, SO_SNDTIMEO,
            reinterpret_cast<const char*>(&tv), sizeof(tv));

        std::string raw;
        secure_string_scope_t raw_guard{raw};
        raw.reserve(2048);
        char buf[1024];
        for (int i = 0; i < 32; ++i) {
            int n = recv(client, buf, sizeof(buf), 0);
            if (n <= 0)
                break;
            raw.append(buf, n);
            if (raw.find("\r\n\r\n") != std::string::npos)
                break;
            if (raw.size() > 16384)
                break;
        }
        SecureZeroMemory(buf, sizeof(buf));

        const size_t first_space = raw.find(' ');
        const size_t second_space = (first_space == std::string::npos)
            ? std::string::npos
            : raw.find(' ', first_space + 1);
        if (first_space == std::string::npos || second_space == std::string::npos) {
            send_listener_response(client, 400,
                build_callback_response_html_failure("malformed request"));
            close_oauth_accepted_socket(ctx);
            continue;
        }

        std::string target = raw.substr(first_space + 1, second_space - first_space - 1);
        secure_string_scope_t target_guard{target};
        const size_t qpos = target.find('?');
        const std::string path_part = (qpos == std::string::npos) ? target : target.substr(0, qpos);
        std::string query_str = (qpos == std::string::npos) ? std::string{} : target.substr(qpos + 1);
        secure_string_scope_t query_guard{query_str};

        if (path_part != "/mcp/oauth/callback" && path_part != "/auth/callback") {
            send_listener_response(client, 404,
                build_callback_response_html_failure("not found"));
            close_oauth_accepted_socket(ctx);
            continue;
        }

        auto params = parse_query_string(query_str);
        if (!params.valid) {
            send_listener_response(client, 400,
                build_callback_response_html_failure("invalid callback query"));
            close_oauth_accepted_socket(ctx);
            complete_oauth_callback(flow, ctx->generation, {}, "invalid callback query");
            return;
        }

        if (params.has_error) {
            std::string detail = "OAuth authorization server rejected the request";
            send_listener_response(client, 200,
                build_callback_response_html_failure(detail));
            close_oauth_accepted_socket(ctx);
            complete_oauth_callback(flow, ctx->generation, {}, std::move(detail));
            return;
        }

        if (!params.has_code || !params.has_state) {
            send_listener_response(client, 400,
                build_callback_response_html_failure("missing code or state"));
            close_oauth_accepted_socket(ctx);
            complete_oauth_callback(flow, ctx->generation, {}, "missing code or state");
            return;
        }

        std::string expected_state;
        {
            std::lock_guard<std::mutex> lock(flow->mutex);
            expected_state = flow->state_token;
        }
        if (params.state != expected_state) {
            send_listener_response(client, 400,
                build_callback_response_html_failure("state mismatch"));
            close_oauth_accepted_socket(ctx);
            complete_oauth_callback(flow, ctx->generation, {}, "state mismatch (csrf)");
            secure_clear_string(expected_state);
            return;
        }
        secure_clear_string(expected_state);

        if (params.code.empty() || params.code.size() > 4096) {
            send_listener_response(client, 400,
                build_callback_response_html_failure("invalid authorization code"));
            close_oauth_accepted_socket(ctx);
            complete_oauth_callback(flow, ctx->generation, {}, "invalid authorization code");
            return;
        }

        send_listener_response(client, 200,
            build_callback_response_html_success());
        close_oauth_accepted_socket(ctx);
        complete_oauth_callback(flow, ctx->generation, std::move(params.code), {});
        return;
    }
    finalize_expired_oauth_listener_flow(flow);
}

static bool start_oauth_listener(oauth_state_t& state,
                                 const std::shared_ptr<oauth_transient_flow_t>& flow)
{
#if defined(AIDA_C03_MCP_OAUTH_FIXTURE)
    state.callback_port = 49152 + static_cast<int>(flow->generation % 10000u);
    if (!bind_oauth_state(state, flow)) {
        state.error = "OAuth state ownership allocation failed";
        return false;
    }
    return true;
#else
    if (!ensure_winsock()) {
        state.error = "winsock init failed";
        return false;
    }

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        state.error = "socket() failed wsa=" + std::to_string(WSAGetLastError());
        return false;
    }

    BOOL yes = TRUE;
    setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
        reinterpret_cast<const char*>(&yes), sizeof(yes));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(0);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        const int wsa = WSAGetLastError();
        closesocket(s);
        state.error = "bind 127.0.0.1:0 failed wsa=" + std::to_string(wsa);
        return false;
    }

    sockaddr_in bound_addr{};
    int bound_len = sizeof(bound_addr);
    if (getsockname(s, reinterpret_cast<sockaddr*>(&bound_addr), &bound_len) == SOCKET_ERROR) {
        const int wsa = WSAGetLastError();
        closesocket(s);
        state.error = "getsockname failed wsa=" + std::to_string(wsa);
        return false;
    }
    state.callback_port = ntohs(bound_addr.sin_port);

    if (listen(s, 4) == SOCKET_ERROR) {
        const int wsa = WSAGetLastError();
        closesocket(s);
        state.error = "listen failed wsa=" + std::to_string(wsa);
        return false;
    }

    auto ctx = std::make_shared<callback_listener_t>();
    ctx->sock.store(s, std::memory_order_release);
    ctx->flow = flow;
    {
        std::lock_guard<std::mutex> lock(flow->mutex);
        ctx->generation = flow->generation;
        flow->listener = ctx;
    }
    if (!bind_oauth_state(state, flow)) {
        const SOCKET listener = ctx->sock.exchange(INVALID_SOCKET, std::memory_order_acq_rel);
        if (listener != INVALID_SOCKET)
            closesocket(listener);
        state.error = "OAuth state ownership allocation failed";
        return false;
    }
    const int64_t remaining_seconds = (std::max)(static_cast<int64_t>(1),
        state.deadline_unix - now_unix_seconds());
    std::uint64_t task_deadline_ms = 0;
    if (remaining_seconds > static_cast<int64_t>(
            (std::numeric_limits<std::uint64_t>::max)() / 1000ULL)
        || !mcp_oauth_deadline_ms_after(
            static_cast<std::uint64_t>(remaining_seconds) * 1000ULL,
            task_deadline_ms)) {
        const SOCKET listener = ctx->sock.exchange(INVALID_SOCKET, std::memory_order_acq_rel);
        if (listener != INVALID_SOCKET)
            closesocket(listener);
        release_oauth_state_binding(state);
        state.error = "OAuth callback listener deadline is not representable";
        return false;
    }
    auto submitted = submit_mcp_oauth_task(
            "mcp_client.oauth_listener",
            aida::infra::executor::domain_t::service,
            "service_loop",
            4,
            task_deadline_ms,
            ctx->generation,
            [ctx]() {
                ctx->stop.store(true, std::memory_order_release);
                close_oauth_accepted_socket(ctx);
                const SOCKET listener = ctx->sock.exchange(INVALID_SOCKET, std::memory_order_acq_rel);
                if (listener != INVALID_SOCKET) {
                    shutdown(listener, SD_BOTH);
                    closesocket(listener);
                }
            },
            [ctx]() {
            oauth_listener_thread(ctx);
            close_oauth_accepted_socket(ctx);
            const SOCKET listener = ctx->sock.exchange(INVALID_SOCKET, std::memory_order_acq_rel);
            if (listener != INVALID_SOCKET)
                closesocket(listener);
        });
    if (!submitted.submitted) {
        const SOCKET listener = ctx->sock.exchange(INVALID_SOCKET, std::memory_order_acq_rel);
        if (listener != INVALID_SOCKET)
            closesocket(listener);
        release_oauth_state_binding(state);
        state.error = submitted.reject_reason.empty()
            ? "OAuth callback listener submission was rejected"
            : "OAuth callback listener submission was rejected: " + submitted.reject_reason;
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(flow->mutex);
        flow->listener_task_id = submitted.task_id;
    }
    return true;
#endif
}

static httplib::Result do_https_post(const std::string& origin, const std::string& path,
                                     const httplib::Headers& hdrs,
                                     const std::string& body, const std::string& content_type,
                                     int read_timeout_sec = 30)
{
#if defined(AIDA_C03_MCP_OAUTH_FIXTURE)
    static_cast<void>(origin);
    static_cast<void>(path);
    static_cast<void>(hdrs);
    static_cast<void>(body);
    static_cast<void>(content_type);
    static_cast<void>(read_timeout_sec);
    c03_oauth_fixture::http_reply_t reply;
    {
        auto& runtime = oauth_fixture_runtime();
        std::lock_guard<std::mutex> lock(runtime.mutex);
        if (runtime.http_replies.empty())
            return {};
        c03_oauth_fixture::http_request_t request;
        request.method = "POST";
        request.url = origin + path;
        request.body = body;
        for (const auto& header : hdrs)
            request.headers[header.first] = header.second;
        runtime.http_requests.push_back(std::move(request));
        reply = std::move(runtime.http_replies.front());
        runtime.http_replies.pop_front();
    }
    secure_string_scope_t body_guard{reply.body};
    secure_string_scope_t error_guard{reply.error};
    scope_exit_t headers_guard{[&reply]() {
        for (auto& header : reply.headers)
            secure_clear_string(header.second);
        reply.headers.clear();
    }};
    if (!reply.transport_ok)
        return {};
    auto response = std::make_unique<httplib::Response>();
    response->status = reply.status;
    response->body = reply.body;
    for (const auto& header : reply.headers)
        response->headers.emplace(header.first, header.second);
    return httplib::Result(std::move(response), httplib::Error::Success);
#else
    httplib::Client cli(origin);
    cli.set_connection_timeout(15);
    if (read_timeout_sec < 30) read_timeout_sec = 30;
    if (read_timeout_sec > 180) read_timeout_sec = 180;
    cli.set_read_timeout(read_timeout_sec);
    cli.set_write_timeout(15);
    const bool is_https_origin = origin.rfind("https://", 0) == 0;
    cli.enable_server_certificate_verification(is_https_origin);
    cli.set_follow_location(false);
    return cli.Post(path.c_str(), hdrs, body, content_type.c_str());
#endif
}

static constexpr size_t kOauthMetadataResponseLimit = 256u * 1024u;
static constexpr size_t kOauthRegistrationResponseLimit = 256u * 1024u;
static constexpr size_t kOauthTokenResponseLimit = 1024u * 1024u;

static bool parse_bounded_content_length(const std::string& text,
                                         size_t maximum,
                                         size_t& value) noexcept
{
    if (text.empty()) {
        value = 0;
        return true;
    }
    size_t parsed = 0;
    for (unsigned char ch : text) {
        if (ch < '0' || ch > '9')
            return false;
        const size_t digit = static_cast<size_t>(ch - '0');
        if (parsed > (maximum - (std::min)(maximum, digit)) / 10u)
            return false;
        parsed = parsed * 10u + digit;
        if (parsed > maximum)
            return false;
    }
    value = parsed;
    return true;
}

static httplib::Result do_oauth_request(
    const char* method,
    const parsed_url_t& url,
    const httplib::Headers& headers,
    const std::string& body,
    const char* content_type,
    size_t response_limit,
    const std::shared_ptr<oauth_request_control_t>& request_control,
    int64_t deadline_unix,
    std::string& transport_error)
{
    transport_error.clear();
    if (!method || !valid_oauth_network_endpoint(url)
        || response_limit == 0 || deadline_unix <= now_unix_seconds()) {
        transport_error = "OAuth request metadata or deadline is invalid";
        return {};
    }

    auto control = request_control ? request_control : std::make_shared<oauth_request_control_t>();
    if (control->cancelled.load(std::memory_order_acquire)) {
        transport_error = "OAuth request was cancelled";
        return {};
    }

#if defined(AIDA_C03_MCP_OAUTH_FIXTURE)
    static_cast<void>(method);
    static_cast<void>(headers);
    static_cast<void>(body);
    static_cast<void>(content_type);
    if (consume_oauth_fixture_fault(c03_oauth_fixture::fault_point_t::http_request))
        throw std::bad_alloc();
    c03_oauth_fixture::http_reply_t reply;
    {
        auto& runtime = oauth_fixture_runtime();
        std::lock_guard<std::mutex> lock(runtime.mutex);
        if (runtime.http_replies.empty()) {
            transport_error = "fixture HTTP reply queue is empty";
            return {};
        }
        c03_oauth_fixture::http_request_t request;
        request.oauth_request = true;
        request.method = method;
        request.url = url.origin + url.path;
        request.body = body;
        for (const auto& header : headers)
            request.headers[header.first] = header.second;
        runtime.http_requests.push_back(std::move(request));
        reply = std::move(runtime.http_replies.front());
        runtime.http_replies.pop_front();
    }
    secure_string_scope_t reply_body_guard{reply.body};
    secure_string_scope_t reply_error_guard{reply.error};
    scope_exit_t reply_headers_guard{[&reply]() {
        for (auto& header : reply.headers)
            secure_clear_string(header.second);
        reply.headers.clear();
    }};
    if (!reply.transport_ok) {
        transport_error = reply.error.empty() ? "fixture transport failure" : reply.error;
        return {};
    }
    if (reply.body.size() > response_limit) {
        transport_error = "OAuth response body exceeds its bounded limit";
        return {};
    }
    const auto content_length = reply.headers.find("Content-Length");
    if (content_length != reply.headers.end()) {
        size_t parsed_length = 0;
        if (!parse_bounded_content_length(content_length->second,
                response_limit, parsed_length)) {
            transport_error = "OAuth response Content-Length is invalid or exceeds its bounded limit";
            return {};
        }
    }
    auto response = std::make_unique<httplib::Response>();
    response->status = reply.status;
    response->body = reply.body;
    for (const auto& header : reply.headers)
        response->headers.emplace(header.first, header.second);
    return httplib::Result(std::move(response), httplib::Error::Success);
#else
    try {
        httplib::Client client(url.origin);
        const int64_t remaining_seconds = (std::max)(static_cast<int64_t>(1),
            deadline_unix - now_unix_seconds());
        const int timeout_seconds = static_cast<int>((std::min)(remaining_seconds,
            static_cast<int64_t>(30)));
        client.set_connection_timeout((std::min)(timeout_seconds, 15));
        client.set_read_timeout(timeout_seconds);
        client.set_write_timeout((std::min)(timeout_seconds, 15));
        client.set_max_timeout(static_cast<time_t>(remaining_seconds * 1000));
        client.enable_server_certificate_verification(url.is_https);
        client.set_follow_location(false);

        std::string response_body;
        secure_string_scope_t response_body_guard{response_body};
        response_body.reserve((std::min)(response_limit, static_cast<size_t>(16384)));
        bool response_too_large = false;
        bool invalid_content_length = false;

        httplib::Request request;
        scope_exit_t request_guard{[&request]() {
            secure_clear_string(request.body);
            for (auto& header : request.headers)
                secure_clear_string(header.second);
            request.headers.clear();
        }};
        request.method = method;
        request.path = url.path;
        request.headers = headers;
        request.body = body;
        if (content_type && *content_type)
            request.set_header("Content-Type", content_type);
        request.response_handler = [&](const httplib::Response& response) {
            if (control->cancelled.load(std::memory_order_acquire)
                || now_unix_seconds() > deadline_unix)
                return false;
            if (response.has_header("Content-Length")) {
                size_t content_length = 0;
                if (!parse_bounded_content_length(response.get_header_value("Content-Length"),
                        response_limit, content_length)) {
                    invalid_content_length = true;
                    return false;
                }
            }
            return true;
        };
        request.content_receiver = [&](const char* data, size_t size,
                                        std::uint64_t, std::uint64_t) {
            if (control->cancelled.load(std::memory_order_acquire)
                || now_unix_seconds() > deadline_unix)
                return false;
            if (size > response_limit - response_body.size()) {
                response_too_large = true;
                return false;
            }
            response_body.append(data, size);
            return true;
        };

        if (!control->bind(client)) {
            transport_error = "OAuth request was cancelled";
            return {};
        }
        struct binding_scope_t {
            std::shared_ptr<oauth_request_control_t> control;
            httplib::Client& client;
            ~binding_scope_t() { control->unbind(client); }
        } binding_scope{control, client};

        auto result = client.send(request);
        if (response_too_large) {
            transport_error = "OAuth response body exceeds its bounded limit";
            return {};
        }
        if (invalid_content_length) {
            transport_error = "OAuth response Content-Length is invalid or exceeds its bounded limit";
            return {};
        }
        if (control->cancelled.load(std::memory_order_acquire)) {
            transport_error = "OAuth request was cancelled";
            return {};
        }
        if (now_unix_seconds() > deadline_unix) {
            transport_error = "OAuth request deadline expired";
            return {};
        }
        if (result)
            result->body.swap(response_body);
        return result;
    } catch (const std::bad_alloc&) {
        transport_error = "OAuth request allocation failed";
        return {};
    } catch (...) {
        transport_error = "OAuth request failed with an unexpected transport exception";
        return {};
    }
#endif
}

static httplib::Result do_oauth_get(
    const parsed_url_t& url,
    const httplib::Headers& headers,
    size_t response_limit,
    const std::shared_ptr<oauth_request_control_t>& request_control,
    int64_t deadline_unix,
    std::string& transport_error)
{
    static const std::string empty_body;
    return do_oauth_request("GET", url, headers, empty_body, nullptr,
        response_limit, request_control, deadline_unix, transport_error);
}

static httplib::Result do_oauth_post(
    const parsed_url_t& url,
    const httplib::Headers& headers,
    const std::string& body,
    const char* content_type,
    size_t response_limit,
    const std::shared_ptr<oauth_request_control_t>& request_control,
    int64_t deadline_unix,
    std::string& transport_error)
{
    return do_oauth_request("POST", url, headers, body, content_type,
        response_limit, request_control, deadline_unix, transport_error);
}


static bool fetch_oauth_metadata(const parsed_url_t& server_url,
                                 std::string& token_endpoint,
                                 std::string& authorization_endpoint,
                                 std::string& registration_endpoint,
                                 const std::shared_ptr<oauth_request_control_t>& request_control,
                                 int64_t deadline_unix,
                                 std::string& error_out)
{
    error_out.clear();
    if (!valid_oauth_network_endpoint(server_url)) {
        error_out = "OAuth metadata endpoint is invalid";
        return false;
    }
    const std::string well_known_path = "/.well-known/oauth-authorization-server";
    parsed_url_t metadata_url = server_url;
    metadata_url.path = well_known_path;

    httplib::Headers headers = {
        { "Accept", "application/json" },
        { "User-Agent", "AiDA-MCP/1.0" }
    };
    std::string transport_error;
    secure_string_scope_t transport_error_guard{transport_error};
    auto res = do_oauth_get(metadata_url, headers, kOauthMetadataResponseLimit,
        request_control, deadline_unix, transport_error);
    if (!res || res->status < 200 || res->status >= 300) {
        error_out = !transport_error.empty()
            ? transport_error
            : !res
                ? "OAuth metadata endpoint is unreachable"
                : "OAuth metadata endpoint status=" + std::to_string(res->status);
        return false;
    }
    secure_http_response_scope_t response_guard{*res};

    json doc = json::parse(res->body, nullptr, false);
    secure_json_scope_t metadata_guard{doc};
    if (doc.is_discarded() || !doc.is_object()) {
        error_out = "OAuth metadata response is not a JSON object";
        return false;
    }

    if (doc.contains("token_endpoint") && doc["token_endpoint"].is_string())
        token_endpoint = doc["token_endpoint"].get<std::string>();
    if (doc.contains("authorization_endpoint") && doc["authorization_endpoint"].is_string())
        authorization_endpoint = doc["authorization_endpoint"].get<std::string>();
    if (doc.contains("registration_endpoint") && doc["registration_endpoint"].is_string())
        registration_endpoint = doc["registration_endpoint"].get<std::string>();

    parsed_url_t token_url;
    parsed_url_t authorization_url;
    if (!parse_url_full(token_endpoint, token_url)
        || !parse_url_full(authorization_endpoint, authorization_url)
        || !valid_oauth_network_endpoint(token_url)
        || !valid_oauth_network_endpoint(authorization_url)) {
        error_out = "OAuth metadata contains an invalid authorization or token endpoint";
        return false;
    }
    if (!registration_endpoint.empty()) {
        parsed_url_t registration_url;
        if (!parse_url_full(registration_endpoint, registration_url)
            || !valid_oauth_network_endpoint(registration_url)) {
            error_out = "OAuth metadata contains an invalid registration endpoint";
            return false;
        }
    }
    return true;
}

static bool register_dynamic_client(const std::string& registration_endpoint,
                                    const std::string& redirect_uri,
                                    std::string& client_id_out,
                                    std::string& client_secret_out,
                                    std::string& error_out,
                                    const std::shared_ptr<oauth_request_control_t>& request_control,
                                    int64_t deadline_unix)
{
    parsed_url_t reg;
    if (!parse_url_full(registration_endpoint, reg) || !valid_oauth_network_endpoint(reg)) {
        error_out = "invalid registration_endpoint url";
        return false;
    }

    json req = {
        { "redirect_uris", json::array({ redirect_uri }) },
        { "client_name", "AiDA Standalone" },
        { "client_uri", "https://aidapro.net" },
        { "grant_types", json::array({ "authorization_code", "refresh_token" }) },
        { "response_types", json::array({ "code" }) },
        { "token_endpoint_auth_method", "none" }
    };
    secure_json_scope_t request_guard{req};

    httplib::Headers headers = {
        { "Accept", "application/json" },
        { "User-Agent", "AiDA-MCP/1.0" }
    };

    std::string request_body = req.dump();
    secure_string_scope_t request_body_guard{request_body};
    std::string transport_error;
    secure_string_scope_t transport_error_guard{transport_error};
    auto res = do_oauth_post(reg, headers, request_body, "application/json",
        kOauthRegistrationResponseLimit, request_control, deadline_unix, transport_error);
    if (!res) {
        error_out = transport_error.empty()
            ? "registration unreachable: " + httplib::to_string(res.error())
            : transport_error;
        return false;
    }
    secure_http_response_scope_t response_guard{*res};
    if (res->status < 200 || res->status >= 300) {
        error_out = "registration status=" + std::to_string(res->status);
        return false;
    }

    json doc = json::parse(res->body, nullptr, false);
    secure_json_scope_t registration_guard{doc};
    if (doc.is_discarded() || !doc.is_object()) {
        error_out = "registration response not json";
        return false;
    }

    if (!doc.contains("client_id") || !doc["client_id"].is_string()) {
        error_out = "registration response missing client_id";
        return false;
    }
    client_id_out = doc["client_id"].get<std::string>();
    if (doc.contains("client_secret")) {
        if (!doc["client_secret"].is_string()) {
            error_out = "registration response client_secret has the wrong type";
            return false;
        }
        client_secret_out = doc["client_secret"].get<std::string>();
    }
    if (client_id_out.empty() || client_id_out.size() > 2048
        || client_secret_out.size() > 8192) {
        error_out = "registration response client identity exceeds bounded limits";
        return false;
    }
    return true;
}

static std::string build_authorize_url(const std::string& authorize_endpoint,
                                       const std::string& client_id,
                                       const std::string& redirect_uri,
                                       const std::string& scope,
                                       const std::string& code_challenge,
                                       const std::string& state_token)
{
    std::string encoded_client_id = url_encode(client_id);
    std::string encoded_redirect_uri = url_encode(redirect_uri);
    std::string encoded_scope = url_encode(scope);
    std::string encoded_challenge = url_encode(code_challenge);
    std::string encoded_state = url_encode(state_token);
    secure_string_scope_t client_id_guard{encoded_client_id};
    secure_string_scope_t redirect_guard{encoded_redirect_uri};
    secure_string_scope_t scope_guard{encoded_scope};
    secure_string_scope_t challenge_guard{encoded_challenge};
    secure_string_scope_t state_guard{encoded_state};
    std::string url = authorize_endpoint;
    url += (authorize_endpoint.find('?') == std::string::npos) ? "?" : "&";
    url += "response_type=code";
    url += "&client_id=";
    url += encoded_client_id;
    url += "&redirect_uri=";
    url += encoded_redirect_uri;
    if (!scope.empty()) {
        url += "&scope=";
        url += encoded_scope;
    }
    url += "&code_challenge=";
    url += encoded_challenge;
    url += "&code_challenge_method=S256";
    url += "&state=";
    url += encoded_state;
    return url;
}

static bool exchange_authorization_code(const std::string& token_endpoint,
                                        const std::string& client_id,
                                        const std::string& client_secret,
                                        const std::string& redirect_uri,
                                        const std::string& code,
                                        const std::string& code_verifier,
                                        std::string& access_out,
                                        std::string& refresh_out,
                                        int64_t& expires_in_out,
                                        std::string& scope_out,
                                        std::string& error_out,
                                        const std::shared_ptr<oauth_request_control_t>& request_control,
                                        int64_t deadline_unix)
{
    parsed_url_t te;
    if (!parse_url_full(token_endpoint, te) || !valid_oauth_network_endpoint(te)) {
        error_out = "invalid token_endpoint url";
        return false;
    }

    std::string encoded_code = url_encode(code);
    std::string encoded_redirect_uri = url_encode(redirect_uri);
    std::string encoded_client_id = url_encode(client_id);
    std::string encoded_verifier = url_encode(code_verifier);
    std::string encoded_client_secret = url_encode(client_secret);
    secure_string_scope_t code_guard{encoded_code};
    secure_string_scope_t redirect_guard{encoded_redirect_uri};
    secure_string_scope_t client_id_guard{encoded_client_id};
    secure_string_scope_t verifier_guard{encoded_verifier};
    secure_string_scope_t client_secret_guard{encoded_client_secret};
    std::string body = "grant_type=authorization_code";
    secure_string_scope_t body_guard{body};
    body += "&code=";
    body += encoded_code;
    body += "&redirect_uri=";
    body += encoded_redirect_uri;
    body += "&client_id=";
    body += encoded_client_id;
    body += "&code_verifier=";
    body += encoded_verifier;
    if (!client_secret.empty()) {
        body += "&client_secret=";
        body += encoded_client_secret;
    }

    httplib::Headers headers = {
        { "Accept", "application/json" },
        { "User-Agent", "AiDA-MCP/1.0" }
    };

    std::string transport_error;
    secure_string_scope_t transport_error_guard{transport_error};
    auto res = do_oauth_post(te, headers, body,
        "application/x-www-form-urlencoded", kOauthTokenResponseLimit,
        request_control, deadline_unix, transport_error);
    if (!res) {
        error_out = transport_error.empty()
            ? "token endpoint unreachable: " + httplib::to_string(res.error())
            : transport_error;
        return false;
    }
    secure_http_response_scope_t response_guard{*res};
    if (res->status < 200 || res->status >= 300) {
        error_out = "token endpoint status=" + std::to_string(res->status);
        return false;
    }
    json doc = json::parse(res->body, nullptr, false);
    secure_json_scope_t token_guard{doc};
    if (doc.is_discarded() || !doc.is_object()) {
        error_out = "token response not json";
        return false;
    }

    if (!doc.contains("access_token") || !doc["access_token"].is_string()) {
        error_out = "token response access_token is missing or has the wrong type";
        return false;
    }
    if (doc.contains("refresh_token") && !doc["refresh_token"].is_string()) {
        error_out = "token response refresh_token has the wrong type";
        return false;
    }
    if (doc.contains("scope") && !doc["scope"].is_string()) {
        error_out = "token response scope has the wrong type";
        return false;
    }
    if (doc.contains("expires_in") && !doc["expires_in"].is_number_integer()) {
        error_out = "token response expires_in has the wrong type";
        return false;
    }
    access_out = doc["access_token"].get<std::string>();
    refresh_out = doc.contains("refresh_token")
        ? doc["refresh_token"].get<std::string>() : std::string{};
    expires_in_out = doc.contains("expires_in")
        ? doc["expires_in"].get<int64_t>() : static_cast<int64_t>(3600);
    scope_out = doc.contains("scope")
        ? doc["scope"].get<std::string>() : std::string{};
    if (access_out.empty()) {
        error_out = "token response missing access_token";
        return false;
    }
    if (access_out.size() > 1024u * 1024u || refresh_out.size() > 1024u * 1024u
        || scope_out.size() > 4096u) {
        error_out = "token response fields exceed bounded limits";
        return false;
    }
    return true;
}

static bool refresh_authorization_token(const std::string& token_endpoint,
                                        const std::string& client_id,
                                        const std::string& client_secret,
                                        const std::string& refresh_token,
                                        std::string& access_out,
                                        std::string& refresh_out,
                                        int64_t& expires_in_out,
                                        std::string& scope_out,
                                        std::string& error_out,
                                        const std::shared_ptr<oauth_request_control_t>& request_control,
                                        int64_t deadline_unix)
{
    parsed_url_t te;
    if (!parse_url_full(token_endpoint, te) || !valid_oauth_network_endpoint(te)) {
        error_out = "invalid token_endpoint url";
        return false;
    }

    std::string encoded_refresh_token = url_encode(refresh_token);
    std::string encoded_client_id = url_encode(client_id);
    std::string encoded_client_secret = url_encode(client_secret);
    secure_string_scope_t refresh_token_guard{encoded_refresh_token};
    secure_string_scope_t client_id_guard{encoded_client_id};
    secure_string_scope_t client_secret_guard{encoded_client_secret};
    std::string body = "grant_type=refresh_token";
    secure_string_scope_t body_guard{body};
    body += "&refresh_token=";
    body += encoded_refresh_token;
    body += "&client_id=";
    body += encoded_client_id;
    if (!client_secret.empty()) {
        body += "&client_secret=";
        body += encoded_client_secret;
    }

    httplib::Headers headers = {
        { "Accept", "application/json" },
        { "User-Agent", "AiDA-MCP/1.0" }
    };

    std::string transport_error;
    secure_string_scope_t transport_error_guard{transport_error};
    auto res = do_oauth_post(te, headers, body,
        "application/x-www-form-urlencoded", kOauthTokenResponseLimit,
        request_control, deadline_unix, transport_error);
    if (!res) {
        error_out = transport_error.empty()
            ? "refresh endpoint unreachable: " + httplib::to_string(res.error())
            : transport_error;
        return false;
    }
    secure_http_response_scope_t response_guard{*res};
    if (res->status < 200 || res->status >= 300) {
        error_out = "refresh endpoint status=" + std::to_string(res->status);
        return false;
    }
    json doc = json::parse(res->body, nullptr, false);
    secure_json_scope_t refresh_guard{doc};
    if (doc.is_discarded() || !doc.is_object()) {
        error_out = "refresh response not json";
        return false;
    }
    if (!doc.contains("access_token") || !doc["access_token"].is_string()) {
        error_out = "refresh response access_token is missing or has the wrong type";
        return false;
    }
    if (doc.contains("refresh_token") && !doc["refresh_token"].is_string()) {
        error_out = "refresh response refresh_token has the wrong type";
        return false;
    }
    if (doc.contains("scope") && !doc["scope"].is_string()) {
        error_out = "refresh response scope has the wrong type";
        return false;
    }
    if (doc.contains("expires_in") && !doc["expires_in"].is_number_integer()) {
        error_out = "refresh response expires_in has the wrong type";
        return false;
    }
    access_out = doc["access_token"].get<std::string>();
    refresh_out = doc.contains("refresh_token")
        ? doc["refresh_token"].get<std::string>() : refresh_token;
    expires_in_out = doc.contains("expires_in")
        ? doc["expires_in"].get<int64_t>() : static_cast<int64_t>(3600);
    scope_out = doc.contains("scope")
        ? doc["scope"].get<std::string>() : std::string{};
    if (access_out.empty()) {
        error_out = "refresh response missing access_token";
        return false;
    }
    if (access_out.size() > 1024u * 1024u || refresh_out.size() > 1024u * 1024u
        || scope_out.size() > 4096u) {
        error_out = "refresh response fields exceed bounded limits";
        return false;
    }
    return true;
}


static std::string mcp_auth_key(const std::string& server_name)
{
    return std::string("mcp:") + server_name;
}

static bool load_mcp_auth(const std::string& server_name, aida::auth::auth_info_t& out)
{
#if defined(AIDA_C03_MCP_OAUTH_FIXTURE)
    std::lock_guard<std::mutex> lock(oauth_fixture_runtime().mutex);
    const auto it = oauth_fixture_runtime().credentials.find(server_name);
    if (it == oauth_fixture_runtime().credentials.end())
        return false;
    out = it->second;
    return true;
#else
    return aida::auth::store::get(mcp_auth_key(server_name), out);
#endif
}

static bool save_mcp_auth_if(const std::string& server_name,
                             const aida::auth::auth_info_t& info,
                             const std::function<bool()>& commit_guard)
{
#if defined(AIDA_C03_MCP_OAUTH_FIXTURE)
    if (consume_oauth_fixture_fault(c03_oauth_fixture::fault_point_t::credential_store))
        throw std::bad_alloc();
    std::lock_guard<std::mutex> lock(oauth_fixture_runtime().mutex);
    if (commit_guard && !commit_guard())
        return false;
    auto& credentials = oauth_fixture_runtime().credentials;
    const auto existing = credentials.find(server_name);
    if (existing != credentials.end())
        secure_clear_auth_info(existing->second);
    credentials[server_name] = info;
    return true;
#else
    return aida::auth::store::set_if(mcp_auth_key(server_name), info, commit_guard);
#endif
}

static bool delete_mcp_auth(const std::string& server_name)
{
#if defined(AIDA_C03_MCP_OAUTH_FIXTURE)
    std::lock_guard<std::mutex> lock(oauth_fixture_runtime().mutex);
    auto& credentials = oauth_fixture_runtime().credentials;
    const auto existing = credentials.find(server_name);
    if (existing != credentials.end()) {
        secure_clear_auth_info(existing->second);
        credentials.erase(existing);
    }
    return true;
#else
    return aida::auth::store::remove(mcp_auth_key(server_name));
#endif
}


client_t::client_t() = default;

client_t::~client_t()
{
    disconnect();
    std::lock_guard<std::mutex> lock(_mtx);
    scrub_sensitive_state_locked();
}

void client_t::scrub_sensitive_state_locked() noexcept
{
    secure_clear_server_config(_cfg);
    secure_clear_string(_server_name_str);
    secure_clear_string(_server_version);
    secure_clear_string(_last_error);
    secure_clear_string(_sse_session_id);
    secure_clear_string(_sse_post_path);
    secure_clear_string(_streamable_session_id);
    secure_clear_string(_oauth_token_endpoint);
    _cached_tools.clear();
}

client_t::client_t(client_t&& o) noexcept
{
    std::scoped_lock lock(o._mtx, o._oauth_request_mutex);
    _cfg              = std::move(o._cfg);
    _state            = o._state;
    _server_name_str  = std::move(o._server_name_str);
    _server_version   = std::move(o._server_version);
    _last_error       = std::move(o._last_error);
    _cached_tools     = std::move(o._cached_tools);
    _next_id          = o._next_id;
    _transport_mode   = o._transport_mode;
    _sse_session_id   = std::move(o._sse_session_id);
    _sse_post_path    = std::move(o._sse_post_path);
    _streamable_session_id = std::move(o._streamable_session_id);
    _oauth_status     = o._oauth_status;
    _oauth_token_endpoint = std::move(o._oauth_token_endpoint);
    _oauth_request_control = std::move(o._oauth_request_control);
    _child_process    = o._child_process;
    _child_stdin_w    = o._child_stdin_w;
    _child_stdout_r   = o._child_stdout_r;
    _child_process_id = o._child_process_id;
    o._child_process  = nullptr;
    o._child_stdin_w  = nullptr;
    o._child_stdout_r = nullptr;
    o._child_process_id = 0;
    o._state          = connection_state_t::disconnected;
    o._oauth_status   = oauth_status_t::not_required;
    o._transport_mode = transport_mode_t::auto_detect;
    o.scrub_sensitive_state_locked();
}

client_t& client_t::operator=(client_t&& o) noexcept
{
    if (this != &o) {
        disconnect();
        std::scoped_lock lock(o._mtx, _mtx,
            o._oauth_request_mutex, _oauth_request_mutex);
        scrub_sensitive_state_locked();
        _cfg              = std::move(o._cfg);
        _state            = o._state;
        _server_name_str  = std::move(o._server_name_str);
        _server_version   = std::move(o._server_version);
        _last_error       = std::move(o._last_error);
        _cached_tools     = std::move(o._cached_tools);
        _next_id          = o._next_id;
        _transport_mode   = o._transport_mode;
        _sse_session_id   = std::move(o._sse_session_id);
        _sse_post_path    = std::move(o._sse_post_path);
        _streamable_session_id = std::move(o._streamable_session_id);
        _oauth_status     = o._oauth_status;
        _oauth_token_endpoint = std::move(o._oauth_token_endpoint);
        _oauth_request_control = std::move(o._oauth_request_control);
        _child_process    = o._child_process;
        _child_stdin_w    = o._child_stdin_w;
        _child_stdout_r   = o._child_stdout_r;
        _child_process_id = o._child_process_id;
        o._child_process  = nullptr;
        o._child_stdin_w  = nullptr;
        o._child_stdout_r = nullptr;
        o._child_process_id = 0;
        o._state          = connection_state_t::disconnected;
        o._oauth_status   = oauth_status_t::not_required;
        o._transport_mode = transport_mode_t::auto_detect;
        o.scrub_sensitive_state_locked();
    }
    return *this;
}

bool client_t::connect(const server_config_t& cfg)
{
    bool need_disconnect = false;
    {
        std::lock_guard<std::mutex> peek(_mtx);
        need_disconnect = (_state == connection_state_t::connected);
    }
    if (need_disconnect) disconnect();
    std::lock_guard<std::mutex> lk(_mtx);
    scrub_sensitive_state_locked();
    _cfg   = cfg;
    _state = connection_state_t::connecting;
    _transport_mode = transport_mode_t::auto_detect;
    _oauth_status = oauth_status_t::not_required;


    if (_cfg.transport == transport_type_t::stdio) {
        if (!launch_stdio_process()) {
            _state = connection_state_t::error;
            return false;
        }
        _transport_mode = transport_mode_t::stdio_local;
        return perform_initialize_locked();
    }

    return perform_remote_handshake();
}

bool client_t::perform_remote_handshake()
{
    parsed_url_t purl;
    if (!parse_url_full(_cfg.url, purl)) {
        _last_error = "Invalid MCP server URL: " + _cfg.url;
        _state = connection_state_t::error;
        return false;
    }

    if (!ensure_access_token_fresh_locked()) {
        if (_last_error.empty())
            _last_error = "MCP OAuth credential is expired and could not be refreshed";
        _oauth_status = oauth_status_t::needs_auth;
        _state = connection_state_t::error;
        return false;
    }

    httplib::Headers probe_headers = {
        { "Content-Type", "application/json" },
        { "Accept", "text/event-stream, application/json" },
        { "User-Agent", "AiDA-MCP/1.0" }
    };
    secure_http_headers_scope_t probe_headers_guard{probe_headers};
    if (!_cfg.api_key.empty())
        probe_headers.emplace("Authorization", "Bearer " + _cfg.api_key);
    aida::auth::auth_info_t stored;
    secure_auth_info_scope_t stored_guard{stored};
    if (load_mcp_auth(_cfg.name, stored) && !stored.access.empty()) {
        if (!_cfg.api_key.empty()) {
            for (auto it = probe_headers.begin(); it != probe_headers.end();) {
                if (it->first == "Authorization") it = probe_headers.erase(it);
                else ++it;
            }
        }
        probe_headers.emplace("Authorization", "Bearer " + stored.access);
    }

    json init_req = rpc_request("initialize", initialize_params(true));
    std::string init_body = json_dump_safe(init_req);
    secure_string_scope_t init_body_guard{init_body};

    auto streamable_res = do_https_post(purl.origin, purl.path, probe_headers,
        init_body, "application/json");

    if (streamable_res) {
        secure_http_response_scope_t response_guard{*streamable_res};
        const int sc = streamable_res->status;
        const std::string& sb = streamable_res->body;
        if (sc == 401 || sc == 403) {
            detect_oauth_metadata();
            _oauth_status = oauth_status_t::needs_auth;
            _last_error = "MCP server requires OAuth authentication";
            _state = connection_state_t::error;
            return false;
        }
        if (sc >= 200 && sc < 300) {
            json response = json::parse(sb, nullptr, false);
            secure_json_scope_t response_json_guard{response};
            if (!response.is_discarded() && response.is_object()) {
                _transport_mode = transport_mode_t::streamable_http;
                for (const auto& h : streamable_res->headers) {
                    if (_stricmp(h.first.c_str(), "Mcp-Session-Id") == 0) {
                        _streamable_session_id = h.second;
                        break;
                    }
                }
                if (response.contains("error")) {
                    _last_error = response["error"].value("message", "Initialize error");
                    _state = connection_state_t::error;
                    return false;
                }
                if (response.contains("result")) {
                    const auto& result = response["result"];
                    if (result.contains("serverInfo")) {
                        _server_name_str = result["serverInfo"].value("name", _cfg.name);
                        _server_version  = result["serverInfo"].value("version", "");
                    }
                }
                if (_server_name_str.empty()) _server_name_str = _cfg.name;
                json notif;
                notif["jsonrpc"] = "2.0";
                notif["method"]  = "notifications/initialized";
                json notif_resp;
                send_rpc(notif_resp, notif);
                _state = connection_state_t::connected;
                _oauth_status = stored.access.empty() ? oauth_status_t::not_required : oauth_status_t::authenticated;
                return true;
            }
        }
        if (sc != 405 && sc != 406 && sc != 404) {
            secure_clear_string(_last_error);
            _last_error = "StreamableHTTP HTTP " + std::to_string(sc);
        }
    } else {
        secure_clear_string(_last_error);
        _last_error = "StreamableHTTP request failed: " + httplib::to_string(streamable_res.error());
    }

    _transport_mode = transport_mode_t::sse_legacy;
    _sse_post_path = purl.path;
    if (_sse_post_path.empty() || _sse_post_path == "/") _sse_post_path = "/message";

    return perform_initialize_locked();
}

bool client_t::detect_oauth_metadata()
{
    parsed_url_t server_url;
    if (!parse_url_full(_cfg.url, server_url)) return false;

    std::string te, ae, re;
    std::string discovery_error;
    secure_string_scope_t token_endpoint_guard{te};
    secure_string_scope_t authorization_endpoint_guard{ae};
    secure_string_scope_t registration_endpoint_guard{re};
    secure_string_scope_t discovery_error_guard{discovery_error};
    std::shared_ptr<oauth_request_control_t> request_control;
    try {
        std::lock_guard<std::mutex> request_lock(_oauth_request_mutex);
        if (!_oauth_request_control)
            _oauth_request_control = std::make_shared<oauth_request_control_t>();
        request_control = _oauth_request_control;
    } catch (...) {
        _last_error = "OAuth metadata request allocation failed";
        return false;
    }
    scope_exit_t request_scope{[this, request_control]() {
        std::lock_guard<std::mutex> request_lock(_oauth_request_mutex);
        if (_oauth_request_control == request_control)
            _oauth_request_control.reset();
    }};
    int64_t metadata_deadline = 0;
    if (!mcp_oauth_deadline_unix_after(30, metadata_deadline)) {
        _last_error = "OAuth metadata deadline is not representable";
        return false;
    }
    if (fetch_oauth_metadata(server_url, te, ae, re,
            request_control, metadata_deadline, discovery_error)) {
        secure_clear_string(_oauth_token_endpoint);
        _oauth_token_endpoint = te;
        return true;
    }
    if (!discovery_error.empty())
        _last_error = discovery_error;
    return false;
}

bool client_t::perform_initialize_locked()
{
    json init_req = rpc_request("initialize", initialize_params(false));

    json response;
    if (!send_rpc(response, init_req)) {
        const std::string inner = _last_error;
        _last_error = "Initialize failed: " + inner;
        _state = connection_state_t::error;
        kill_stdio_process();
        return false;
    }

    if (response.contains("error")) {
        _last_error = response["error"].value("message", "Unknown initialization error");
        _state = connection_state_t::error;
        kill_stdio_process();
        return false;
    }


    if (response.contains("result")) {
        const auto& result = response["result"];
        if (result.contains("serverInfo")) {
            _server_name_str = result["serverInfo"].value("name", _cfg.name);
            _server_version  = result["serverInfo"].value("version", "");
        }
    }

    if (_server_name_str.empty())
        _server_name_str = _cfg.name;


    json notif;
    notif["jsonrpc"] = "2.0";
    notif["method"]  = "notifications/initialized";
    json notif_resp;
    send_rpc(notif_resp, notif);

    _state = connection_state_t::connected;
    return true;
}

void client_t::disconnect()
{
    std::shared_ptr<oauth_request_control_t> request_control;
    {
        std::lock_guard<std::mutex> request_lock(_oauth_request_mutex);
        request_control.swap(_oauth_request_control);
    }
    if (request_control)
        request_control->cancel();

    std::lock_guard<std::mutex> lk(_mtx);

    if (_state == connection_state_t::disconnected)
        return;

    kill_stdio_process();
    _state = connection_state_t::disconnected;
    _cached_tools.clear();
    secure_clear_string(_streamable_session_id);
    secure_clear_string(_sse_session_id);
    secure_clear_string(_sse_post_path);
}

bool client_t::reconnect()
{
    server_config_t cfg;
    secure_server_config_scope_t config_guard{cfg};
    {
        std::lock_guard<std::mutex> lk(_mtx);
        cfg = _cfg;
    }
    disconnect();
    return connect(cfg);
}

std::vector<remote_tool_t> client_t::list_tools()
{
    std::lock_guard<std::mutex> lk(_mtx);

    if (_state != connection_state_t::connected) {
        _last_error = "Not connected";
        return {};
    }

    json req = rpc_request("tools/list");
    json response;
    if (!send_rpc(response, req)) {
        const std::string inner = _last_error;
        _last_error = "tools/list failed: " + inner;
        return _cached_tools;
    }

    if (response.contains("error")) {
        _last_error = response["error"].value("message", "tools/list error");
        return _cached_tools;
    }

    std::vector<remote_tool_t> next_tools;
    if (response.contains("result") && response["result"].contains("tools")) {
        const std::string server_label = _server_name_str.empty() ? _cfg.name : _server_name_str;
        for (const auto& t : response["result"]["tools"]) {
            remote_tool_t tool;
            tool.server_name   = server_label;
            tool.original_name = t.value("name", "");
            if (tool.original_name.empty()) continue;
            tool.name         = make_qualified_tool_name(server_label, tool.original_name);
            tool.description  = t.value("description", "");
            if (t.contains("inputSchema"))
                tool.input_schema = t["inputSchema"];
            if (t.contains("annotations"))
                tool.annotations = t["annotations"];
            next_tools.push_back(std::move(tool));
        }
    }

    _cached_tools = std::move(next_tools);
    return _cached_tools;
}

namespace {

int tool_call_read_timeout_sec(const json& arguments)
{
    int timeout_ms = 0;
    if (arguments.is_object())
    {
        for (const char* key : {"call_timeout_ms", "timeout_ms", "evaluate_timeout_ms", "timeout"})
        {
            auto it = arguments.find(key);
            if (it == arguments.end())
                continue;
            try
            {
                if (it->is_number_integer())
                    timeout_ms = (std::max)(timeout_ms, it->get<int>());
                else if (it->is_number())
                    timeout_ms = (std::max)(timeout_ms, static_cast<int>(it->get<double>()));
            }
            catch (...) {}
        }
    }
    if (timeout_ms <= 0)
        return 30;
    int seconds = (timeout_ms + 999) / 1000 + 10;
    if (seconds < 30) seconds = 30;
    if (seconds > 180) seconds = 180;
    return seconds;
}

}

call_result_t client_t::call_tool(const std::string& tool_name, const json& arguments)
{
    diag::log_tagged_fmt("mcp", "call_tool enter server='%s' tool='%s'",
        _cfg.name.c_str(), tool_name.c_str());
    std::lock_guard<std::mutex> lk(_mtx);

    if (_state != connection_state_t::connected) {
        diag::log_tagged_fmt("mcp", "call_tool FAILED not_connected server='%s'", _cfg.name.c_str());
        return call_result_t::error("Not connected to " + _cfg.name);
    }

    json req = rpc_request("tools/call", {
        {"name", tool_name},
        {"arguments", arguments}
    });

    json response;
    const int http_read_timeout_sec = tool_call_read_timeout_sec(arguments);
    if (!send_rpc(response, req, http_read_timeout_sec)) {
        diag::log_tagged_fmt("mcp", "call_tool RPC_FAILED server='%s' tool='%s' error='%s'",
            _cfg.name.c_str(), tool_name.c_str(), _last_error.c_str());
        return call_result_t::error("tools/call failed: " + _last_error);
    }

    if (response.contains("error")) {
        std::string err_msg = response["error"].value("message", "Tool execution error");
        diag::log_tagged_fmt("mcp", "call_tool ERROR server='%s' tool='%s' msg='%s'",
            _cfg.name.c_str(), tool_name.c_str(), err_msg.c_str());
        return call_result_t::error(err_msg);
    }

    if (!response.contains("result")) {
        diag::log_tagged_fmt("mcp", "call_tool EMPTY_RESULT server='%s' tool='%s'",
            _cfg.name.c_str(), tool_name.c_str());
        return call_result_t::error("Empty result from server");
    }

    const auto& result = response["result"];


    std::string text;
    json data;
    if (result.contains("content") && result["content"].is_array()) {
        for (const auto& block : result["content"]) {
            if (block.value("type", "") == "text") {
                if (!text.empty()) text += "\n";
                text += block.value("text", "");
            } else {

                if (data.is_null()) data = json::array();
                data.push_back(block);
            }
        }
    }

    bool is_error = result.value("isError", false);
    if (is_error) {
        diag::log_tagged_fmt("mcp", "call_tool TOOL_ERROR server='%s' tool='%s' text_len=%zu",
            _cfg.name.c_str(), tool_name.c_str(), text.size());
        return call_result_t::error(text.empty() ? "Tool returned error" : text);
    }

    diag::log_tagged_fmt("mcp", "call_tool SUCCESS server='%s' tool='%s' text_len=%zu",
        _cfg.name.c_str(), tool_name.c_str(), text.size());
    return call_result_t::ok(sanitize_utf8(text), data);
}

std::vector<remote_resource_t> client_t::list_resources()
{
    std::lock_guard<std::mutex> lk(_mtx);

    if (_state != connection_state_t::connected)
        return {};

    json req = rpc_request("resources/list");
    json response;
    if (!send_rpc(response, req)) {
        const std::string inner = _last_error;
        _last_error = "resources/list failed: " + inner;
        return {};
    }

    std::vector<remote_resource_t> resources;
    if (response.contains("result") && response["result"].contains("resources")) {
        for (const auto& r : response["result"]["resources"]) {
            remote_resource_t res;
            res.server_name = _server_name_str;
            res.uri         = r.value("uri", "");
            res.name        = r.value("name", "");
            res.description = r.value("description", "");
            res.mime_type   = r.value("mimeType", "");
            if (!res.uri.empty())
                resources.push_back(std::move(res));
        }
    }

    return resources;
}

std::string client_t::read_resource(const std::string& uri)
{
    std::lock_guard<std::mutex> lk(_mtx);

    if (_state != connection_state_t::connected)
        return {};

    json req = rpc_request("resources/read", {{"uri", uri}});
    json response;
    if (!send_rpc(response, req)) {
        const std::string inner = _last_error;
        _last_error = "resources/read failed: " + inner;
        return {};
    }

    if (response.contains("result") && response["result"].contains("contents")) {
        const auto& contents = response["result"]["contents"];
        if (contents.is_array() && !contents.empty()) {
            return contents[0].value("text", json_dump_safe(contents[0]));
        }
    }

    return {};
}

std::vector<remote_prompt_t> client_t::list_prompts()
{
    std::lock_guard<std::mutex> lk(_mtx);

    if (_state != connection_state_t::connected) {
        _last_error = "Not connected";
        return {};
    }

    json req = rpc_request("prompts/list");
    json response;
    if (!send_rpc(response, req)) {
        const std::string inner = _last_error;
        _last_error = "prompts/list failed: " + inner;
        return {};
    }

    if (response.contains("error")) {
        _last_error = response["error"].value("message", "prompts/list error");
        return {};
    }

    std::vector<remote_prompt_t> prompts;
    if (response.contains("result") && response["result"].contains("prompts")) {
        for (const auto& p : response["result"]["prompts"]) {
            remote_prompt_t pr;
            pr.server_name = _server_name_str;
            pr.name        = p.value("name", "");
            pr.description = p.value("description", "");
            if (p.contains("arguments") && p["arguments"].is_array()) {
                for (const auto& a : p["arguments"]) {
                    prompt_argument_t arg;
                    arg.name        = a.value("name", "");
                    arg.description = a.value("description", "");
                    arg.required    = a.value("required", false);
                    if (!arg.name.empty())
                        pr.arguments.push_back(std::move(arg));
                }
            }
            if (!pr.name.empty())
                prompts.push_back(std::move(pr));
        }
    }

    return prompts;
}

std::string client_t::get_prompt(const std::string& prompt_name,
                                 const std::map<std::string, std::string>& arguments)
{
    std::lock_guard<std::mutex> lk(_mtx);

    if (_state != connection_state_t::connected) {
        _last_error = "Not connected";
        return {};
    }

    json args_obj = json::object();
    for (const auto& kv : arguments)
        args_obj[kv.first] = kv.second;

    json params = json::object();
    params["name"] = prompt_name;
    if (!arguments.empty())
        params["arguments"] = args_obj;

    json req = rpc_request("prompts/get", params);
    json response;
    if (!send_rpc(response, req)) {
        const std::string inner = _last_error;
        _last_error = "prompts/get failed: " + inner;
        return {};
    }

    if (response.contains("error")) {
        _last_error = response["error"].value("message", "prompts/get error");
        return {};
    }

    if (!response.contains("result"))
        return {};

    const auto& result = response["result"];
    std::string accumulated;
    if (result.contains("messages") && result["messages"].is_array()) {
        for (const auto& msg : result["messages"]) {
            if (!msg.contains("content")) continue;
            const auto& content = msg["content"];
            if (content.is_object()) {
                if (content.value("type", "") == "text") {
                    if (!accumulated.empty()) accumulated += "\n";
                    accumulated += content.value("text", "");
                }
            } else if (content.is_array()) {
                for (const auto& block : content) {
                    if (block.value("type", "") == "text") {
                        if (!accumulated.empty()) accumulated += "\n";
                        accumulated += block.value("text", "");
                    }
                }
            }
        }
    }

    return accumulated;
}

bool client_t::is_connected() const
{
    std::lock_guard<std::mutex> lk(_mtx);
    return _state == connection_state_t::connected;
}

connection_state_t client_t::state() const
{
    std::lock_guard<std::mutex> lk(_mtx);
    return _state;
}

const std::string& client_t::server_name() const
{
    std::lock_guard<std::mutex> lk(_mtx);
    return _server_name_str;
}

std::string client_t::last_error() const
{
    std::lock_guard<std::mutex> lk(_mtx);
    return _last_error;
}

const server_config_t& client_t::config() const
{
    std::lock_guard<std::mutex> lk(_mtx);
    return _cfg;
}

std::uint32_t client_t::child_process_id() const
{
    std::lock_guard<std::mutex> lk(_mtx);
    return _child_process_id;
}

const std::vector<remote_tool_t>& client_t::cached_tools() const
{
    std::lock_guard<std::mutex> lk(_mtx);
    return _cached_tools;
}

oauth_status_t client_t::oauth_status() const
{
    std::lock_guard<std::mutex> lk(_mtx);
    return _oauth_status;
}

transport_mode_t client_t::active_transport_mode() const
{
    std::lock_guard<std::mutex> lk(_mtx);
    return _transport_mode;
}


json client_t::rpc_request(const std::string& method, const json& params)
{

    json req;
    req["jsonrpc"] = "2.0";
    req["method"]  = method;


    if (method.find("notifications/") == std::string::npos)
        req["id"] = _next_id++;

    if (!params.is_null() && !params.empty())
        req["params"] = params;

    return req;
}

bool client_t::send_rpc(json& out, const json& request, int http_read_timeout_sec)
{
    switch (_cfg.transport) {
    case transport_type_t::http_sse:
        return send_http(out, request, http_read_timeout_sec);
    case transport_type_t::stdio:
        return send_stdio(out, request, http_read_timeout_sec);
    default:
        _last_error = "Unsupported transport type";
        return false;
    }
}

bool client_t::ensure_access_token_fresh_locked()
{
    if (_cfg.transport == transport_type_t::stdio) return true;

    aida::auth::auth_info_t info;
    secure_auth_info_scope_t info_guard{info};
    if (!load_mcp_auth(_cfg.name, info)) return true;
    if (info.kind != aida::auth::auth_kind_t::oauth) return true;
    if (info.access.empty()) return true;
    if (info.expires_unix == 0) return true;

    const int64_t now = now_unix_seconds();
    if (now < info.expires_unix - 30) return true;

    return refresh_access_token_locked();
}

bool client_t::refresh_access_token_locked()
{
    try {
        aida::auth::auth_info_t info;
        secure_auth_info_scope_t info_guard{info};
        if (!load_mcp_auth(_cfg.name, info) || info.kind != aida::auth::auth_kind_t::oauth) {
            _last_error = "OAuth refresh credential is unavailable";
            _oauth_status = oauth_status_t::needs_auth;
            return false;
        }

        std::uint64_t persistence_epoch = 0;
        if (!read_mcp_auth_epoch(_cfg.name, persistence_epoch)) {
            _last_error = "The bounded MCP OAuth persistence registry is full";
            _oauth_status = oauth_status_t::needs_auth;
            return false;
        }
        if (persistence_epoch == (std::numeric_limits<std::uint64_t>::max)()) {
            _last_error = "The MCP OAuth persistence generation space is exhausted; restart is required";
            _oauth_status = oauth_status_t::needs_auth;
            return false;
        }
        if (info.refresh.empty()) {
            _last_error = "OAuth refresh credential is unavailable";
            _oauth_status = oauth_status_t::needs_auth;
            return false;
        }

        oauth_exchange_material_t material;
        material.server_name = _cfg.name;
        material.mcp_endpoint = _cfg.url;
        material.token_endpoint = _oauth_token_endpoint;
        material.client_id = _cfg.oauth_client_id.empty()
            ? info.custom_client_id : _cfg.oauth_client_id;
        material.client_secret = _cfg.oauth_client_secret;

        auto read_metadata_string = [&](const char* key, std::string& destination,
                                        size_t maximum) -> bool {
            if (!info.metadata.is_object() || !info.metadata.contains(key))
                return true;
            const auto& value = info.metadata[key];
            if (!value.is_string()) {
                _last_error = std::string("OAuth stored metadata has the wrong type for ") + key;
                return false;
            }
            destination = value.get<std::string>();
            if (destination.size() > maximum) {
                _last_error = std::string("OAuth stored metadata exceeds the bounded limit for ") + key;
                return false;
            }
            return true;
        };

        if (material.token_endpoint.empty()
            && !read_metadata_string("mcp_token_endpoint", material.token_endpoint, 8192u)) {
            _oauth_status = oauth_status_t::needs_auth;
            return false;
        }
        if (material.client_secret.empty()
            && !read_metadata_string("mcp_client_secret", material.client_secret, 8192u)) {
            _oauth_status = oauth_status_t::needs_auth;
            return false;
        }

        auto request_control = std::make_shared<oauth_request_control_t>();
        {
            std::lock_guard<std::mutex> request_lock(_oauth_request_mutex);
            if (_oauth_request_control)
                _oauth_request_control->cancel();
            _oauth_request_control = request_control;
        }
        scope_exit_t request_scope{[this, request_control]() {
            std::lock_guard<std::mutex> request_lock(_oauth_request_mutex);
            if (_oauth_request_control == request_control)
                _oauth_request_control.reset();
        }};
        int64_t request_deadline = 0;
        if (!mcp_oauth_deadline_unix_after(45, request_deadline)) {
            _last_error = "OAuth refresh deadline is not representable";
            _oauth_status = oauth_status_t::needs_auth;
            return false;
        }

        if (material.token_endpoint.empty()) {
            parsed_url_t server_url;
            std::string authorization_endpoint;
            std::string registration_endpoint;
            std::string discovery_error;
            secure_string_scope_t authorization_endpoint_guard{authorization_endpoint};
            secure_string_scope_t registration_endpoint_guard{registration_endpoint};
            secure_string_scope_t discovery_error_guard{discovery_error};
            if (!parse_url_full(_cfg.url, server_url)
                || !fetch_oauth_metadata(server_url, material.token_endpoint,
                    authorization_endpoint, registration_endpoint,
                    request_control, request_deadline, discovery_error)) {
                _last_error = discovery_error.empty()
                    ? "OAuth refresh metadata discovery failed" : discovery_error;
                _oauth_status = oauth_status_t::needs_auth;
                return false;
            }
            secure_clear_string(_oauth_token_endpoint);
            _oauth_token_endpoint = material.token_endpoint;
        }

        if (material.client_id.empty()) {
            _last_error = "OAuth refresh requires a configured or persisted client identity";
            _oauth_status = oauth_status_t::needs_auth;
            return false;
        }
        if (material.token_endpoint.size() > 8192 || material.client_id.size() > 2048
            || material.client_secret.size() > 8192) {
            _last_error = "OAuth refresh metadata exceeds bounded transient-flow limits";
            _oauth_status = oauth_status_t::needs_auth;
            return false;
        }

        std::string new_access, new_refresh, new_scope, err;
        secure_string_scope_t new_access_guard{new_access};
        secure_string_scope_t new_refresh_guard{new_refresh};
        secure_string_scope_t new_scope_guard{new_scope};
        secure_string_scope_t error_guard{err};
        int64_t expires_in = 3600;

        if (!refresh_authorization_token(material.token_endpoint, material.client_id,
                material.client_secret, info.refresh, new_access, new_refresh,
                expires_in, new_scope, err, request_control, request_deadline)) {
            _last_error = err.empty() ? "OAuth refresh failed" : err;
            _oauth_status = oauth_status_t::needs_auth;
            return false;
        }

        constexpr int64_t kMaximumTokenLifetimeSeconds = 31536000;
        if (new_access.empty() || expires_in <= 0 || expires_in > kMaximumTokenLifetimeSeconds) {
            _last_error = "OAuth refresh returned invalid token metadata";
            _oauth_status = oauth_status_t::needs_auth;
            return false;
        }
        int64_t refreshed_expires_unix = 0;
        if (!mcp_oauth_deadline_unix_after(expires_in, refreshed_expires_unix)) {
            _last_error = "OAuth refresh expiry is not representable";
            _oauth_status = oauth_status_t::needs_auth;
            return false;
        }

        aida::auth::auth_info_t updated;
        secure_auth_info_scope_t updated_guard{updated};
        updated.kind = aida::auth::auth_kind_t::oauth;
        updated.access = new_access;
        updated.refresh = new_refresh;
        updated.expires_unix = refreshed_expires_unix;
        updated.metadata = info.metadata;
        updated.custom_client_id = info.custom_client_id;
        updated.custom_redirect_uri = info.custom_redirect_uri;
        updated.custom_scopes = info.custom_scopes;
        if (!save_mcp_auth_if(_cfg.name, updated,
                [this, persistence_epoch]() {
                    return claim_mcp_auth_epoch(_cfg.name, persistence_epoch);
                })) {
            _last_error = "OAuth credential persistence failed: " + aida::auth::store::last_error();
            _oauth_status = oauth_status_t::needs_auth;
            return false;
        }
        const std::uint64_t committed_epoch = next_mcp_auth_epoch(persistence_epoch);
        if (committed_epoch == 0
            || !mcp_auth_epoch_matches(_cfg.name, committed_epoch)) {
            _last_error = "OAuth credential was removed during refresh commit";
            _oauth_status = oauth_status_t::needs_auth;
            return false;
        }
        _oauth_status = oauth_status_t::authenticated;
        secure_clear_string(_last_error);
        return true;
    } catch (const std::bad_alloc&) {
        _last_error = "OAuth refresh allocation failed";
    } catch (...) {
        _last_error = "OAuth refresh failed with an unexpected exception";
    }
    _oauth_status = oauth_status_t::needs_auth;
    return false;
}


bool client_t::send_http(json& out, const json& request, int read_timeout_sec)
{
    if (!ensure_access_token_fresh_locked())
        return false;

    parsed_url_t purl;
    if (!parse_url_full(_cfg.url, purl)) {
        _last_error = "Invalid MCP server URL: " + _cfg.url;
        return false;
    }

    std::string body = json_dump_safe(request);
    secure_string_scope_t body_guard{body};
    std::string post_path = purl.path;
    if (_transport_mode == transport_mode_t::sse_legacy && !_sse_post_path.empty())
        post_path = _sse_post_path;

    auto build_headers = [this]() {
        httplib::Headers headers = {
            {"Content-Type", "application/json"}
        };
        if (_transport_mode == transport_mode_t::streamable_http)
            headers.emplace("Accept", "text/event-stream, application/json");
        else
            headers.emplace("Accept", "application/json");
        headers.emplace("User-Agent", "AiDA-MCP/1.0");

        aida::auth::auth_info_t stored;
        secure_auth_info_scope_t stored_guard{stored};
        if (load_mcp_auth(_cfg.name, stored) && !stored.access.empty()) {
            headers.emplace("Authorization", "Bearer " + stored.access);
        } else if (!_cfg.api_key.empty()) {
            headers.emplace("Authorization", "Bearer " + _cfg.api_key);
        }
        if (!_streamable_session_id.empty())
            headers.emplace("Mcp-Session-Id", _streamable_session_id);
        return headers;
    };

    auto request_headers = build_headers();
    secure_http_headers_scope_t request_headers_guard{request_headers};
    auto res = do_https_post(purl.origin, post_path, request_headers,
        body, "application/json", read_timeout_sec);

    if (res && (res->status == 401 || res->status == 403)) {
        bool refreshed = false;
        {
            aida::auth::auth_info_t info;
            secure_auth_info_scope_t info_guard{info};
            if (load_mcp_auth(_cfg.name, info)
                && info.kind == aida::auth::auth_kind_t::oauth
                && !info.refresh.empty()) {
                refreshed = refresh_access_token_locked();
            }
        }
        if (refreshed) {
            secure_clear_http_response(*res);
            auto retry_headers = build_headers();
            secure_http_headers_scope_t retry_headers_guard{retry_headers};
            res = do_https_post(purl.origin, post_path, retry_headers,
                body, "application/json", read_timeout_sec);
        }
    }

    if (!res) {
        secure_clear_string(_last_error);
        _last_error = "HTTP request failed: " + httplib::to_string(res.error());
        return false;
    }
    secure_http_response_scope_t response_guard{*res};

    if (res->status == 401 || res->status == 403) {
        detect_oauth_metadata();
        _oauth_status = oauth_status_t::needs_auth;
        _last_error = "HTTP " + std::to_string(res->status)
            + ": MCP server requires OAuth authentication";
        return false;
    }

    if (res->status < 200 || res->status >= 300) {
        secure_clear_string(_last_error);
        _last_error = "HTTP " + std::to_string(res->status);
        return false;
    }


    json response = json::parse(res->body, nullptr, false);
    secure_json_scope_t response_json_guard{response};
    if (response.is_discarded()) {
        const std::string& body_text = res->body;
        size_t pos = 0;
        while (pos < body_text.size()) {
            size_t nl = body_text.find('\n', pos);
            if (nl == std::string::npos) nl = body_text.size();
            std::string line = body_text.substr(pos, nl - pos);
            secure_string_scope_t line_guard{line};
            pos = nl + 1;
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) continue;
            if (!line.empty() && line.front() == ':') continue;
            const size_t colon = line.find(':');
            if (colon == std::string::npos) continue;
            const std::string field = line.substr(0, colon);
            if (field != "data") continue;
            size_t val_start = colon + 1;
            if (val_start < line.size() && line[val_start] == ' ') ++val_start;
            std::string data_part = line.substr(val_start);
            secure_string_scope_t data_part_guard{data_part};
            if (data_part == "[DONE]") continue;
            json maybe = json::parse(data_part, nullptr, false);
            secure_json_scope_t maybe_guard{maybe};
            if (!maybe.is_discarded() && maybe.is_object()) {
                if (maybe.contains("method") && !maybe.contains("id")) {
                    process_notification(maybe);
                    continue;
                }
                if (maybe.contains("method") && maybe.contains("id")) {
                    json inbound_response;
                    if (dispatch_inbound_request(maybe, inbound_response))
                        send_inbound_response(inbound_response);
                    continue;
                }
                out = std::move(maybe);
                return true;
            }
        }
        _last_error = "Invalid JSON response from MCP server";
        return false;
    }

    if (response.is_object() && response.contains("method") && !response.contains("id")) {
        process_notification(response);
        out = json::object();
        return true;
    }

    if (response.is_object() && response.contains("method") && response.contains("id")) {
        json inbound_response;
        if (dispatch_inbound_request(response, inbound_response))
            send_inbound_response(inbound_response);
        out = json::object();
        return true;
    }

    out = std::move(response);
    return true;
}

static std::string encode_file_uri_path(const std::string& abs_path)
{
    std::string normalized;
    normalized.reserve(abs_path.size());
    for (char c : abs_path) {
        if (c == '\\') normalized.push_back('/');
        else           normalized.push_back(c);
    }

    std::string out;
    out.reserve(normalized.size() * 3);
    for (unsigned char c : normalized) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
            || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.'
            || c == '~' || c == '/' || c == ':') {
            out.push_back(static_cast<char>(c));
        } else {
            char buf[4];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%%%02X", c);
            out.append(buf);
        }
    }
    return out;
}

json client_t::build_roots_list_result() const
{
    std::string workspace_path = file_browser::current_dir;
    if (workspace_path.empty()) {
        char buf[MAX_PATH] = {};
        if (GetCurrentDirectoryA(MAX_PATH, buf) > 0)
            workspace_path = buf;
    }

    json roots = json::array();
    if (!workspace_path.empty()) {
        const std::string encoded = encode_file_uri_path(workspace_path);
        std::string uri;
        uri.reserve(encoded.size() + 8);
        uri += "file:///";
        if (!encoded.empty() && encoded.front() == '/')
            uri += encoded.substr(1);
        else
            uri += encoded;

        json entry;
        entry["uri"]  = uri;
        entry["name"] = "AiDA workspace";
        roots.push_back(std::move(entry));
    }

    json result;
    result["roots"] = std::move(roots);
    return result;
}

bool client_t::dispatch_inbound_request(const json& request, json& response_out)
{
    if (!request.is_object() || !request.contains("method") || !request.contains("id"))
        return false;

    const std::string method = request.value("method", std::string{});
    const json& id_val = request["id"];

    json response;
    response["jsonrpc"] = "2.0";
    response["id"]      = id_val;

    if (method == "roots/list") {
        response["result"] = build_roots_list_result();
    } else if (method == "ping") {
        response["result"] = json::object();
    } else {
        json err;
        err["code"]    = -32601;
        err["message"] = std::string("Method not found: ") + method;
        response["error"] = std::move(err);
    }

    response_out = std::move(response);
    return true;
}

bool client_t::post_outbound_http_message(const json& message)
{
    parsed_url_t purl;
    if (!parse_url_full(_cfg.url, purl))
        return false;

    std::string post_path = purl.path;
    if (_transport_mode == transport_mode_t::sse_legacy && !_sse_post_path.empty())
        post_path = _sse_post_path;

    httplib::Headers headers = {
        {"Content-Type", "application/json"}
    };
    secure_http_headers_scope_t headers_guard{headers};
    if (_transport_mode == transport_mode_t::streamable_http)
        headers.emplace("Accept", "text/event-stream, application/json");
    else
        headers.emplace("Accept", "application/json");
    headers.emplace("User-Agent", "AiDA-MCP/1.0");

    aida::auth::auth_info_t stored;
    secure_auth_info_scope_t stored_guard{stored};
    if (load_mcp_auth(_cfg.name, stored) && !stored.access.empty()) {
        headers.emplace("Authorization", "Bearer " + stored.access);
    } else if (!_cfg.api_key.empty()) {
        headers.emplace("Authorization", "Bearer " + _cfg.api_key);
    }
    if (!_streamable_session_id.empty())
        headers.emplace("Mcp-Session-Id", _streamable_session_id);

    std::string body = json_dump_safe(message);
    secure_string_scope_t body_guard{body};
    auto res = do_https_post(purl.origin, post_path, headers, body, "application/json");
    if (!res)
        return false;
    secure_http_response_scope_t response_guard{*res};
    return res->status >= 200 && res->status < 300;
}

void client_t::send_inbound_response(const json& response)
{
    if (_cfg.transport == transport_type_t::stdio) {
        std::string body = json_dump_safe(response);
        secure_string_scope_t body_guard{body};
        write_to_stdin(body);
        return;
    }
    if (_cfg.transport == transport_type_t::http_sse) {
        post_outbound_http_message(response);
    }
}

void client_t::process_notification(const json& notif)
{
    if (!notif.is_object() || !notif.contains("method")) return;
    const std::string method = notif.value("method", std::string{});

    if (method == "notifications/tools/list_changed"
        || method == "notifications/resources/list_changed"
        || method == "notifications/prompts/list_changed") {
        if (method == "notifications/tools/list_changed") {
            json req = rpc_request("tools/list");
            json response;
            if (!send_rpc(response, req)) {
                const std::string inner = _last_error;
                _last_error = "tools/list refresh failed: " + inner;
                return;
            }
            if (response.contains("result") && response["result"].contains("tools")) {
                std::vector<remote_tool_t> next_tools;
                const std::string server_label = _server_name_str.empty() ? _cfg.name : _server_name_str;
                for (const auto& t : response["result"]["tools"]) {
                    remote_tool_t tool;
                    tool.server_name   = server_label;
                    tool.original_name = t.value("name", "");
                    if (tool.original_name.empty()) continue;
                    tool.name          = make_qualified_tool_name(server_label, tool.original_name);
                    tool.description   = t.value("description", "");
                    if (t.contains("inputSchema")) tool.input_schema = t["inputSchema"];
                    if (t.contains("annotations")) tool.annotations = t["annotations"];
                    next_tools.push_back(std::move(tool));
                }
                _cached_tools = std::move(next_tools);
            }
        }

        aida::events::mcp_tools_changed_t payload;
        payload.server_name = _server_name_str.empty() ? _cfg.name : _server_name_str;
        payload.tool_count = static_cast<int>(_cached_tools.size());
        aida::events::publish(aida::events::event_mcp_tools_changed, payload);
    }
}

bool client_t::poll_notifications()
{
    std::lock_guard<std::mutex> lk(_mtx);
    if (_state != connection_state_t::connected) return false;
    if (_cfg.transport != transport_type_t::stdio) return false;
    if (!_child_stdout_r) return false;

    DWORD bytes_avail = 0;
    if (!PeekNamedPipe(static_cast<HANDLE>(_child_stdout_r), nullptr, 0, nullptr, &bytes_avail, nullptr))
        return false;
    if (bytes_avail == 0) return false;

    std::string line;
    if (!read_line_from_stdout(line, 1000))
        return false;
    if (line.empty()) return false;
    json maybe = json::parse(line, nullptr, false);
    if (maybe.is_discarded() || !maybe.is_object()) return false;
    if (maybe.contains("method") && !maybe.contains("id")) {
        process_notification(maybe);
        return true;
    }
    if (maybe.contains("method") && maybe.contains("id")) {
        json inbound_response;
        if (dispatch_inbound_request(maybe, inbound_response))
            send_inbound_response(inbound_response);
        return true;
    }
    return false;
}


bool client_t::launch_stdio_process()
{


    if (_cfg.command.empty()) {
        _last_error = "No command specified for stdio transport";
        return false;
    }


    std::string cmdline = _cfg.command;
    for (const auto& arg : _cfg.args)
        cmdline += " " + arg;

    std::wstring current_directory;
    auto cwd_it = _cfg.env.find("AIDA_CAMOUFOX_WORKING_DIR");
    if (cwd_it != _cfg.env.end() && !cwd_it->second.empty()) {
        current_directory = utf8_to_wide_string(cwd_it->second);
        if (!directory_exists_w(current_directory)) {
            _last_error = "Invalid MCP stdio working directory";
            diag::log_tagged_fmt("mcp_stdio",
                "launch_invalid_working_dir server_hash=0x%016llX name_len=%zu cwd_hash=0x%016llX cwd_len=%zu",
                static_cast<unsigned long long>(mcp_log_hash(_cfg.name)),
                _cfg.name.size(),
                static_cast<unsigned long long>(mcp_log_hash(cwd_it->second)),
                cwd_it->second.size());
            return false;
        }
    }

    std::vector<wchar_t> env_block;
    if (!_cfg.env.empty()) {

        wchar_t* current_env = GetEnvironmentStringsW();
        if (current_env) {

            const wchar_t* p = current_env;
            while (*p) {
                size_t len = wcslen(p) + 1;
                env_block.insert(env_block.end(), p, p + len);
                p += len;
            }
            FreeEnvironmentStringsW(current_env);
        }

        for (const auto& [key, val] : _cfg.env) {
            std::wstring entry;
            entry.reserve(key.size() + val.size() + 2);
            for (char c : key)   entry += static_cast<wchar_t>(c);
            entry += L'=';
            for (char c : val)   entry += static_cast<wchar_t>(c);
            entry += L'\0';
            env_block.insert(env_block.end(), entry.begin(), entry.end());
        }
        env_block.push_back(L'\0');
    }


    SECURITY_ATTRIBUTES sa{};
    sa.nLength              = sizeof(sa);
    sa.bInheritHandle       = TRUE;
    sa.lpSecurityDescriptor = nullptr;

    HANDLE stdin_read  = nullptr, stdin_write  = nullptr;
    HANDLE stdout_read = nullptr, stdout_write = nullptr;
    struct pipe_guard_t {
        HANDLE& a; HANDLE& b; HANDLE& c; HANDLE& d;
        bool dismissed = false;
        ~pipe_guard_t() noexcept {
            if (dismissed) return;
            if (a) ::CloseHandle(a);
            if (b) ::CloseHandle(b);
            if (c) ::CloseHandle(c);
            if (d) ::CloseHandle(d);
        }
        void dismiss_kept() noexcept { dismissed = true; }
        void dismiss_all() noexcept { a = b = c = d = nullptr; dismissed = true; }
    } pipe_guard{stdin_read, stdin_write, stdout_read, stdout_write};

    if (!CreatePipe(&stdin_read, &stdin_write, &sa, 0) ||
        !CreatePipe(&stdout_read, &stdout_write, &sa, 0))
    {
        _last_error = "Failed to create pipes for stdio transport";
        return false;
    }


    SetHandleInformation(stdin_write, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdInput   = stdin_read;
    si.hStdOutput  = stdout_write;
    si.hStdError   = GetStdHandle(STD_ERROR_HANDLE);
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi{};


    std::wstring wcmdline;
    if (!cmdline.empty()) {
        const int wlen = MultiByteToWideChar(CP_UTF8, 0, cmdline.c_str(),
            static_cast<int>(cmdline.size()), nullptr, 0);
        if (wlen <= 0) {
            _last_error = "Failed to convert command line to UTF-16: " + cmdline;
            return false;
        }
        wcmdline.resize(static_cast<size_t>(wlen));
        MultiByteToWideChar(CP_UTF8, 0, cmdline.c_str(), static_cast<int>(cmdline.size()),
            wcmdline.data(), wlen);
    }

    BOOL created = CreateProcessW(
        nullptr,
        wcmdline.data(),
        nullptr, nullptr,
        TRUE,
        CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
        env_block.empty() ? nullptr : env_block.data(),
        current_directory.empty() ? nullptr : current_directory.c_str(),
        &si, &pi
    );


    ::CloseHandle(stdin_read); stdin_read = nullptr;
    ::CloseHandle(stdout_write); stdout_write = nullptr;

    if (!created) {
        _last_error = "Failed to launch MCP server process: " + cmdline;
        return false;
    }

    ::CloseHandle(pi.hThread);
    _child_process  = pi.hProcess;
    _child_process_id = pi.dwProcessId;
    _child_stdin_w  = stdin_write; stdin_write = nullptr;
    _child_stdout_r = stdout_read; stdout_read = nullptr;


    Sleep(200);


    DWORD exit_code = 0;
    if (GetExitCodeProcess(static_cast<HANDLE>(_child_process), &exit_code) &&
        exit_code != STILL_ACTIVE)
    {
        _last_error = "MCP server process exited immediately (code " + std::to_string(exit_code) + ")";
        kill_stdio_process();
        return false;
    }

    return true;
}

void client_t::kill_stdio_process()
{


    if (_child_stdin_w) {
        CloseHandle(static_cast<HANDLE>(_child_stdin_w));
        _child_stdin_w = nullptr;
    }
    if (_child_stdout_r) {
        CloseHandle(static_cast<HANDLE>(_child_stdout_r));
        _child_stdout_r = nullptr;
    }
    if (_child_process) {
        TerminateProcess(static_cast<HANDLE>(_child_process), 0);
        WaitForSingleObject(static_cast<HANDLE>(_child_process), 3000);
        CloseHandle(static_cast<HANDLE>(_child_process));
        _child_process = nullptr;
        _child_process_id = 0;
    }
}

bool client_t::read_line_from_stdout(std::string& out, std::uint32_t timeout_ms)
{
    out.clear();

    if (!_child_stdout_r) {
        _last_error = "stdio: no stdout handle";
        return false;
    }

    const uint64_t start_ms = GetTickCount64();
    const uint64_t limit_ms = timeout_ms == 0 ? 1ULL : static_cast<uint64_t>(timeout_ms);

    while (true) {
        DWORD available = 0;
        if (!PeekNamedPipe(static_cast<HANDLE>(_child_stdout_r), nullptr, 0, nullptr, &available, nullptr)) {
            if (out.empty()) {
                _last_error = "stdio: failed to inspect child stdout";
                return false;
            }
            break;
        }
        if (available == 0) {
            DWORD exit_code = STILL_ACTIVE;
            if (_child_process &&
                GetExitCodeProcess(static_cast<HANDLE>(_child_process), &exit_code) &&
                exit_code != STILL_ACTIVE) {
                _last_error = "stdio: child process exited while waiting for stdout code=" + std::to_string(exit_code);
                return false;
            }
            const uint64_t elapsed = GetTickCount64() - start_ms;
            if (elapsed >= limit_ms) {
                _last_error = "stdio: timed out waiting for child stdout after " + std::to_string(elapsed) + "ms";
                return false;
            }
            Sleep(10);
            continue;
        }
        char ch = 0;
        DWORD read_bytes = 0;
        BOOL ok = ReadFile(static_cast<HANDLE>(_child_stdout_r), &ch, 1, &read_bytes, nullptr);
        if (!ok || read_bytes == 0) {
            if (out.empty()) {
                _last_error = "stdio: child process closed stdout";
                return false;
            }
            break;
        }
        if (ch == '\n')
            break;
        if (ch != '\r')
            out += ch;
    }

    return true;
}

bool client_t::write_to_stdin(const std::string& data)
{
    if (!_child_stdin_w) {
        _last_error = "stdio: no stdin handle";
        return false;
    }

    std::string msg = data + "\n";
    DWORD written;
    BOOL ok = WriteFile(
        static_cast<HANDLE>(_child_stdin_w),
        msg.c_str(),
        static_cast<DWORD>(msg.size()),
        &written, nullptr
    );
    if (!ok) {
        _last_error = "stdio: failed to write to child stdin";
        return false;
    }
    return true;
}

bool client_t::send_stdio(json& out, const json& request, int read_timeout_sec)
{
    const std::string body = json_dump_safe(request);
    const std::string method = request_method_for_log(request);
    if (read_timeout_sec < 1)
        read_timeout_sec = 1;
    if (read_timeout_sec > 300)
        read_timeout_sec = 300;
    const std::uint32_t read_timeout_ms = static_cast<std::uint32_t>(read_timeout_sec) * 1000u;
    diag::log_tagged_fmt("mcp_stdio", "send request server='%s' method='%s' has_id=%d body_bytes=%zu",
        _cfg.name.c_str(), method.c_str(), request.contains("id") ? 1 : 0, body.size());
    if (!write_to_stdin(body)) {
        diag::log_tagged_fmt("mcp_stdio", "send write_failed server='%s' method='%s' err='%s'",
            _cfg.name.c_str(), method.c_str(), compact_log_text(_last_error, 500).c_str());
        return false;
    }

    if (!request.contains("id")) {
        out = json::object();
        return true;
    }

    while (true) {
        std::string response_str;
        if (!read_line_from_stdout(response_str, read_timeout_ms)) {
            diag::log_tagged_fmt("mcp_stdio", "recv failed server='%s' method='%s' err='%s'",
                _cfg.name.c_str(), method.c_str(), compact_log_text(_last_error, 500).c_str());
            return false;
        }
        diag::log_tagged_fmt("mcp_stdio", "recv line server='%s' method='%s' bytes=%zu",
            _cfg.name.c_str(), method.c_str(), response_str.size());

        json response = json::parse(response_str, nullptr, false);
        if (response.is_discarded()) {
            _last_error = "stdio: invalid JSON response";
            diag::log_tagged_fmt("mcp_stdio", "recv invalid_json server='%s' method='%s' bytes=%zu first_byte=0x%02X",
                _cfg.name.c_str(), method.c_str(), response_str.size(),
                first_byte_or_zero(response_str));
            return false;
        }

        if (response.is_object() && response.contains("method") && !response.contains("id")) {
            diag::log_tagged_fmt("mcp_stdio", "recv notification server='%s' method='%s' notif='%s'",
                _cfg.name.c_str(), method.c_str(), response.value("method", std::string()).c_str());
            process_notification(response);
            continue;
        }
        if (response.is_object() && response.contains("method") && response.contains("id")) {
            diag::log_tagged_fmt("mcp_stdio", "recv inbound_request server='%s' method='%s' inbound='%s'",
                _cfg.name.c_str(), method.c_str(), response.value("method", std::string()).c_str());
            json inbound_response;
            if (dispatch_inbound_request(response, inbound_response))
                send_inbound_response(inbound_response);
            continue;
        }
        if (response.is_object() && response.contains("error")) {
            const auto& err = response["error"];
            diag::log_tagged_fmt("mcp_stdio", "recv rpc_error server='%s' method='%s' error='%s'",
                _cfg.name.c_str(), method.c_str(), rpc_error_summary_for_log(err).c_str());
        } else {
            diag::log_tagged_fmt("mcp_stdio", "recv response server='%s' method='%s' has_result=%d",
                _cfg.name.c_str(), method.c_str(),
                response.is_object() && response.contains("result") ? 1 : 0);
        }
        out = std::move(response);
        return true;
    }
}


manager_t::manager_t()  = default;
manager_t::~manager_t() { disconnect_all(); }

manager_t::entry_t::~entry_t()
{
    secure_clear_server_config(cfg);
}

void manager_t::add_server(const server_config_t& cfg)
{
    std::string config_fingerprint;
    secure_string_scope_t config_fingerprint_guard{config_fingerprint};
    try {
        config_fingerprint = server_config_fingerprint(cfg);
    } catch (...) {
        diag::log_tagged("mcp", "add_server rejected because the configuration fingerprint could not be created");
        return;
    }
    if (config_fingerprint.empty()) {
        diag::log_tagged("mcp", "add_server rejected because the configuration fingerprint is empty");
        return;
    }
    bool config_changed = false;
    if (!advance_mcp_config_incarnation(cfg.name, config_fingerprint, nullptr, &config_changed)) {
        diag::log_tagged("mcp", "add_server rejected because the bounded configuration incarnation could not advance");
        return;
    }

    diag::log_tagged_fmt("mcp", "add_server name_hash=0x%016llX name_len=%zu url_hash=0x%016llX enabled=%d auto_connect=%d",
        static_cast<unsigned long long>(mcp_log_hash(cfg.name)),
        cfg.name.size(),
        static_cast<unsigned long long>(mcp_log_hash(cfg.url)),
        static_cast<int>(cfg.enabled),
        static_cast<int>(cfg.auto_connect));
    bool updated_existing = false;
    {
        std::lock_guard<std::mutex> lk(_mtx);
        for (auto& ep : _entries) {
            if (ep->cfg.name == cfg.name) {
                secure_clear_server_config(ep->cfg);
                ep->cfg = cfg;
                updated_existing = true;
                break;
            }
        }

        if (!updated_existing) {
            auto ep = std::make_shared<entry_t>();
            ep->cfg = cfg;
            _entries.push_back(std::move(ep));
            diag::log_tagged_fmt("mcp", "add_server added_new name_hash=0x%016llX name_len=%zu total_servers=%zu",
                static_cast<unsigned long long>(mcp_log_hash(cfg.name)),
                cfg.name.size(),
                _entries.size());
        }
    }
    if (updated_existing) {
        diag::log_tagged_fmt("mcp", "add_server updated_existing name_hash=0x%016llX name_len=%zu",
            static_cast<unsigned long long>(mcp_log_hash(cfg.name)),
            cfg.name.size());
        if (config_changed)
            (void)cancel_auth(cfg.name);
    }
}

void manager_t::remove_server(const std::string& name)
{
    diag::log_tagged_fmt("mcp", "remove_server name='%s'", name.c_str());
    std::shared_ptr<entry_t> target;
    {
        std::lock_guard<std::mutex> lk(_mtx);

        auto it = std::find_if(_entries.begin(), _entries.end(),
            [&](const std::shared_ptr<entry_t>& ep) { return ep && ep->cfg.name == name; });

        if (it == _entries.end()) {
            diag::log_tagged_fmt("mcp", "remove_server NOT_FOUND name='%s'", name.c_str());
            return;
        }
        target = *it;
        _entries.erase(it);
    }

    (void)invalidate_mcp_config_incarnation(name);
    (void)cancel_auth(name);
    if (target) {
        target->client.disconnect();
        diag::log_tagged_fmt("mcp", "remove_server disconnected name='%s'", name.c_str());
    }
}

void manager_t::connect_all()
{
    diag::log_tagged("mcp", "connect_all enter");
    std::vector<std::string> to_connect;
    {
        std::lock_guard<std::mutex> lk(_mtx);
        to_connect.reserve(_entries.size());
        for (auto& ep : _entries) {
            auto& e = *ep;
            if (e.cfg.enabled && e.cfg.auto_connect &&
                e.client.state() != connection_state_t::connected)
            {
                bool already = false;
                for (const auto& n : _in_flight_connects) {
                    if (n == e.cfg.name) { already = true; break; }
                }
                if (already) continue;
                to_connect.push_back(e.cfg.name);
                _in_flight_connects.push_back(e.cfg.name);
            }
        }
    }

    for (const auto& name : to_connect) {
        server_config_t cfg;
        secure_server_config_scope_t config_guard{cfg};
        bool found = false;
        {
            std::lock_guard<std::mutex> lk(_mtx);
            for (auto& ep : _entries) {
                if (ep->cfg.name == name) {
                    cfg = ep->cfg;
                    found = true;
                    break;
                }
            }
        }
        if (!found) {
            std::lock_guard<std::mutex> lk(_mtx);
            _in_flight_connects.erase(
                std::remove(_in_flight_connects.begin(), _in_flight_connects.end(), name),
                _in_flight_connects.end());
            continue;
        }

        client_t tmp_client;
        bool ok = tmp_client.connect(cfg);
        if (ok) {
            tmp_client.list_tools();
            ok = tmp_client.state() == connection_state_t::connected;
        }

        std::lock_guard<std::mutex> lk(_mtx);
        _in_flight_connects.erase(
            std::remove(_in_flight_connects.begin(), _in_flight_connects.end(), name),
            _in_flight_connects.end());
        for (auto& ep : _entries) {
            if (ep->cfg.name == name) {
                ep->client = std::move(tmp_client);
                break;
            }
        }
    }
}

void manager_t::disconnect_all()
{
    diag::log_tagged("mcp", "disconnect_all enter");
    std::vector<std::shared_ptr<entry_t>> snapshot;
    {
        std::lock_guard<std::mutex> lk(_mtx);
        snapshot = _entries;
    }
    for (auto& ep : snapshot) {
        (void)cancel_auth(ep->cfg.name);
        ep->client.disconnect();
    }
    diag::log_tagged_fmt("mcp", "disconnect_all done disconnected=%zu", snapshot.size());
}

bool manager_t::connect_server(const std::string& name)
{
    server_config_t cfg;
    secure_server_config_scope_t config_guard{cfg};
    bool found = false;
    {
        std::lock_guard<std::mutex> lk(_mtx);
        for (auto& ep : _entries) {
            if (ep->cfg.name == name) {
                cfg = ep->cfg;
                found = true;
                break;
            }
        }
        if (!found) return false;
        if (!cfg.enabled) {
            diag::log_tagged_fmt("mcp",
                "connect_server_blocked_disabled name_hash=0x%016llX name_len=%zu auto_connect=%d transport=%d",
                static_cast<unsigned long long>(mcp_log_hash(cfg.name)),
                cfg.name.size(),
                static_cast<int>(cfg.auto_connect),
                static_cast<int>(cfg.transport));
            return false;
        }
        for (const auto& n : _in_flight_connects) {
            if (n == name) return true;
        }
        _in_flight_connects.push_back(name);
    }

    client_t tmp_client;
    bool ok = tmp_client.connect(cfg);
    if (ok) {
        tmp_client.list_tools();
        ok = tmp_client.state() == connection_state_t::connected;
    }

    std::lock_guard<std::mutex> lk(_mtx);
    _in_flight_connects.erase(
        std::remove(_in_flight_connects.begin(), _in_flight_connects.end(), name),
        _in_flight_connects.end());
    for (auto& ep : _entries) {
        if (ep->cfg.name == name) {
            ep->client = std::move(tmp_client);
            return ok;
        }
    }
    return false;
}

void manager_t::disconnect_server(const std::string& name)
{
    std::shared_ptr<entry_t> target;
    {
        std::lock_guard<std::mutex> lk(_mtx);
        for (auto& ep : _entries) {
            if (ep->cfg.name == name) {
                target = ep;
                break;
            }
        }
    }
    if (target) target->client.disconnect();
}

std::vector<remote_tool_t> manager_t::get_all_tools()
{
    std::vector<std::shared_ptr<entry_t>> snapshot;
    {
        std::lock_guard<std::mutex> lk(_mtx);
        snapshot = _entries;
    }

    std::vector<remote_tool_t> all;
    for (auto& ep : snapshot) {
        auto& e = *ep;
        if (e.client.is_connected()) {
            const auto& tools = e.client.cached_tools();
            all.insert(all.end(), tools.begin(), tools.end());
        }
    }
    return all;
}

call_result_t manager_t::call_tool(const std::string& qualified_name, const json& arguments)
{
    std::vector<std::shared_ptr<entry_t>> snapshot;
    {
        std::lock_guard<std::mutex> lk(_mtx);
        snapshot = _entries;
    }

    size_t legacy_sep = qualified_name.find("::");
    if (legacy_sep != std::string::npos) {
        std::string server = qualified_name.substr(0, legacy_sep);
        std::string tool   = qualified_name.substr(legacy_sep + 2);

        std::shared_ptr<entry_t> target;
        for (auto& ep : snapshot) {
            if (ep->cfg.name == server && ep->client.is_connected()) {
                target = ep;
                break;
            }
        }
        if (target) return target->client.call_tool(tool, arguments);
        return call_result_t::error("MCP server '" + server + "' not found or not connected");
    }

    std::shared_ptr<entry_t> target;
    std::string resolved_tool;
    for (auto& ep : snapshot) {
        if (!ep->client.is_connected()) continue;
        for (const auto& t : ep->client.cached_tools()) {
            if (t.name == qualified_name) {
                target = ep;
                resolved_tool = t.original_name.empty() ? t.name : t.original_name;
                break;
            }
        }
        if (target) break;
    }
    if (target) return target->client.call_tool(resolved_tool, arguments);

    for (auto& ep : snapshot) {
        if (!ep->client.is_connected()) continue;
        for (const auto& t : ep->client.cached_tools()) {
            if (t.original_name == qualified_name) {
                target = ep;
                resolved_tool = t.original_name;
                break;
            }
        }
        if (target) break;
    }
    if (target) return target->client.call_tool(resolved_tool, arguments);

    return call_result_t::error("MCP tool '" + qualified_name + "' not found on any connected server");
}

size_t manager_t::tool_count() const
{
    std::vector<std::shared_ptr<entry_t>> snapshot;
    {
        std::lock_guard<std::mutex> lk(_mtx);
        snapshot = _entries;
    }

    size_t count = 0;
    for (const auto& ep : snapshot) {
        const auto& e = *ep;
        if (e.client.is_connected())
            count += e.client.cached_tools().size();
    }
    return count;
}

std::vector<remote_resource_t> manager_t::get_all_resources()
{
    std::vector<std::shared_ptr<entry_t>> snapshot;
    {
        std::lock_guard<std::mutex> lk(_mtx);
        snapshot = _entries;
    }

    std::vector<remote_resource_t> all;
    for (auto& ep : snapshot) {
        auto& e = *ep;
        if (e.client.is_connected()) {
            auto res = e.client.list_resources();
            all.insert(all.end(), res.begin(), res.end());
        }
    }
    return all;
}

std::string manager_t::read_resource(const std::string& server_name, const std::string& uri)
{
    std::shared_ptr<entry_t> target;
    {
        std::lock_guard<std::mutex> lk(_mtx);
        for (auto& ep : _entries) {
            if (ep->cfg.name == server_name && ep->client.is_connected()) {
                target = ep;
                break;
            }
        }
    }
    if (target) return target->client.read_resource(uri);
    return {};
}

std::vector<remote_prompt_t> manager_t::get_all_prompts()
{
    std::vector<std::shared_ptr<entry_t>> snapshot;
    {
        std::lock_guard<std::mutex> lk(_mtx);
        snapshot = _entries;
    }

    std::vector<remote_prompt_t> all;
    for (auto& ep : snapshot) {
        auto& e = *ep;
        if (e.client.is_connected()) {
            auto pr = e.client.list_prompts();
            all.insert(all.end(), pr.begin(), pr.end());
        }
    }
    return all;
}

std::string manager_t::get_prompt(const std::string& server_name,
                                  const std::string& prompt_name,
                                  const std::map<std::string, std::string>& arguments)
{
    std::shared_ptr<entry_t> target;
    {
        std::lock_guard<std::mutex> lk(_mtx);
        for (auto& ep : _entries) {
            if (ep->cfg.name == server_name && ep->client.is_connected()) {
                target = ep;
                break;
            }
        }
    }
    if (target) return target->client.get_prompt(prompt_name, arguments);
    return {};
}

std::vector<manager_t::server_status_t> manager_t::get_status() const
{
    std::vector<std::shared_ptr<entry_t>> snapshot;
    {
        std::lock_guard<std::mutex> lk(_mtx);
        snapshot = _entries;
    }

    std::vector<server_status_t> result;
    result.reserve(snapshot.size());

    for (const auto& ep : snapshot) {
        const auto& e = *ep;
        result.push_back({
            e.cfg.name,
            e.client.state(),
            e.client.last_error(),
            e.client.cached_tools().size(),
            e.client.oauth_status()
        });
    }

    return result;
}

void manager_t::poll()
{
    std::vector<std::shared_ptr<entry_t>> snapshot;
    std::vector<std::string> in_flight_snapshot;
    {
        std::lock_guard<std::mutex> lk(_mtx);
        snapshot = _entries;
        in_flight_snapshot = _in_flight_connects;
    }

    std::vector<std::string> needs_reconnect;
    for (auto& ep : snapshot) {
        auto& e = *ep;
        if (!e.cfg.enabled || !e.cfg.auto_connect)
            continue;
        auto st = e.client.state();
        if (st == connection_state_t::error || st == connection_state_t::disconnected) {
            if (e.client.oauth_status() == oauth_status_t::needs_auth
                || e.client.oauth_status() == oauth_status_t::needs_client_registration)
                continue;
            bool already = false;
            for (const auto& n : in_flight_snapshot) {
                if (n == e.cfg.name) { already = true; break; }
            }
            if (already) continue;
            needs_reconnect.push_back(e.cfg.name);
            continue;
        }
        if (e.client.is_connected())
            e.client.poll_notifications();
    }

    for (const auto& name : needs_reconnect) {
        (void)submit_mcp_client_task(
            "mcp_client.reconnect",
            aida::infra::executor::domain_t::external_tool,
            "bounded_task",
            3,
            [this, name]() { this->connect_server(name); });
    }
}

bool manager_t::refresh_tools(const std::string& name)
{
    std::shared_ptr<entry_t> target;
    {
        std::lock_guard<std::mutex> lk(_mtx);
        for (auto& ep : _entries) {
            if (ep->cfg.name == name) {
                target = ep;
                break;
            }
        }
    }
    if (!target) return false;
    if (!target->client.is_connected()) return false;
    auto tools = target->client.list_tools();
    if (!target->client.is_connected()) return false;
    aida::events::mcp_tools_changed_t payload;
    payload.server_name = name;
    payload.tool_count = static_cast<int>(tools.size());
    aida::events::publish(aida::events::event_mcp_tools_changed, payload);
    return true;
}

bool manager_t::find_config(const std::string& name, server_config_t& out) const
{
    std::lock_guard<std::mutex> lk(_mtx);
    for (const auto& ep : _entries) {
        if (ep->cfg.name == name) {
            out = ep->cfg;
            return true;
        }
    }
    return false;
}

json manager_t::mcp_tool_list_json()
{
    std::vector<std::shared_ptr<entry_t>> snapshot;
    {
        std::lock_guard<std::mutex> lk(_mtx);
        snapshot = _entries;
    }

    json arr = json::array();
    for (auto& ep : snapshot) {
        auto& e = *ep;
        if (!e.client.is_connected()) continue;
        for (const auto& t : e.client.cached_tools()) {
            json entry;
            entry["name"]        = t.name;
            entry["description"] = t.description;
            if (!t.input_schema.is_null() && !t.input_schema.empty())
                entry["input_schema"] = t.input_schema;
            else
                entry["input_schema"] = json{{"type", "object"}, {"properties", json::object()}};
            entry["server_name"]   = t.server_name;
            entry["original_name"] = t.original_name;
            arr.push_back(std::move(entry));
        }
    }
    return arr;
}


struct oauth_terminal_snapshot_t
{
    bool ready = false;
    bool success = false;
    std::string error;

    ~oauth_terminal_snapshot_t()
    {
        secure_clear_string(error);
    }
};

static std::shared_ptr<oauth_transient_flow_t> oauth_flow_from_state(oauth_state_t& state)
{
    const auto* binding = oauth_state_binding(state);
    if (!binding || !binding->flow)
        return {};
    const auto flow = binding->flow;
    std::lock_guard<std::mutex> lock(flow->mutex);
    if (flow->generation != binding->generation
        || flow->incarnation != binding->incarnation)
        return {};
    return flow;
}

static void remove_oauth_flow_registry_reference(
    const std::shared_ptr<oauth_transient_flow_t>& flow)
{
    if (!flow)
        return;
    std::lock_guard<std::mutex> registry_lock(oauth_flow_registry_mutex());
    auto& registry = oauth_flow_registry();
    for (auto it = registry.begin(); it != registry.end(); ++it) {
        if (it->second == flow) {
            registry.erase(it);
            return;
        }
    }
}

static void stop_oauth_flow_io(const std::shared_ptr<oauth_transient_flow_t>& flow,
                               bool cancel_owned_tasks)
{
    if (!flow)
        return;
    std::shared_ptr<callback_listener_t> listener;
    std::shared_ptr<oauth_request_control_t> request_control;
    std::array<std::uint64_t, 3> task_ids{};
    {
        std::lock_guard<std::mutex> lock(flow->mutex);
        listener = flow->listener.lock();
        request_control = flow->request_control;
        task_ids = {flow->listener_task_id, flow->poll_task_id,
            flow->initialization_task_id};
    }
    if (listener) {
        listener->stop.store(true, std::memory_order_release);
        close_oauth_accepted_socket(listener);
        const SOCKET socket = listener->sock.exchange(INVALID_SOCKET, std::memory_order_acq_rel);
        if (socket != INVALID_SOCKET) {
            shutdown(socket, SD_BOTH);
            closesocket(socket);
        }
    }
    if (request_control)
        request_control->cancel();
    if (cancel_owned_tasks) {
        for (const std::uint64_t task_id : task_ids) {
            if (task_id != 0)
                (void)cancel_mcp_oauth_task(task_id);
        }
    }
}

static bool reserve_oauth_terminal_event(
    const std::shared_ptr<oauth_transient_flow_t>& flow,
    std::string& server_name,
    std::string& error,
    bool& success,
    std::uint64_t& generation)
{
    std::lock_guard<std::mutex> registry_lock(oauth_flow_registry_mutex());
    bool current = false;
    for (const auto& entry : oauth_flow_registry()) {
        if (entry.second == flow) {
            current = true;
            break;
        }
    }
    if (!current)
        return false;
    std::lock_guard<std::mutex> lock(flow->mutex);
    if (!flow->terminal_ready || flow->event_published)
        return false;
    flow->event_published = true;
    server_name = flow->server_name;
    error = flow->error;
    success = flow->terminal_success;
    generation = flow->generation;
    return true;
}

static void publish_oauth_terminal_event(
    const std::shared_ptr<oauth_transient_flow_t>& flow,
    bool retry_fixture_fault = true)
{
    std::string server_name;
    std::string error;
    secure_string_scope_t server_name_guard{server_name};
    secure_string_scope_t error_guard{error};
    bool success = false;
    std::uint64_t generation = 0;
    if (!reserve_oauth_terminal_event(flow, server_name, error, success, generation))
        return;
    try {
#if defined(AIDA_C03_MCP_OAUTH_FIXTURE)
        if (consume_oauth_fixture_fault(c03_oauth_fixture::fault_point_t::event_publish))
            throw std::bad_alloc();
        c03_oauth_fixture::event_t event;
        event.server_name = server_name;
        event.status = success ? oauth_status_t::authenticated : oauth_status_t::failed;
        event.error = error;
        event.generation = generation;
        std::lock_guard<std::mutex> fixture_lock(oauth_fixture_runtime().mutex);
        oauth_fixture_runtime().events.push_back(std::move(event));
#else
        if (success) {
            aida::events::oauth_completed_t completed;
            completed.provider_id = mcp_auth_key(server_name);
            aida::events::publish(aida::events::event_oauth_completed, completed);
        } else {
            aida::events::oauth_failed_t failed;
            failed.provider_id = mcp_auth_key(server_name);
            failed.error = error;
            aida::events::publish(aida::events::event_oauth_failed, failed);
        }
#endif
    } catch (...) {
#if defined(AIDA_C03_MCP_OAUTH_FIXTURE)
        if (retry_fixture_fault) {
            {
                std::lock_guard<std::mutex> lock(flow->mutex);
                if (flow->terminal_ready)
                    flow->event_published = false;
            }
            publish_oauth_terminal_event(flow, false);
        }
#else
        static_cast<void>(retry_fixture_fault);
#endif
    }
}

static oauth_terminal_snapshot_t finalize_oauth_flow(
    const std::shared_ptr<oauth_transient_flow_t>& flow,
    bool success,
    std::string error,
    std::string code_digest,
    bool cancel_owned_tasks,
    bool commit_lock_held = false)
{
    secure_string_scope_t input_error_guard{error};
    secure_string_scope_t input_digest_guard{code_digest};
    oauth_terminal_snapshot_t snapshot;
    if (!flow) {
        snapshot.ready = true;
        snapshot.success = success;
        snapshot.error = error;
        return snapshot;
    }
    std::unique_lock<std::mutex> commit_lock(flow->commit_mutex, std::defer_lock);
    if (!commit_lock_held)
        commit_lock.lock();

    std::string server_name;
    std::string receipt_digest;
    std::string receipt_error;
    secure_string_scope_t server_name_guard{server_name};
    secure_string_scope_t receipt_digest_guard{receipt_digest};
    secure_string_scope_t receipt_error_guard{receipt_error};
    bool became_terminal = false;
    {
        std::lock_guard<std::mutex> lock(flow->mutex);
        if (!flow->terminal_ready) {
            flow->terminal_ready = true;
            flow->terminal_success = success;
            flow->phase = oauth_flow_phase_t::terminal;
            flow->cancelled = !success;
            secure_clear_string(flow->error);
            flow->error = error;
            secure_clear_string(flow->terminal_code_digest);
            flow->terminal_code_digest = code_digest;
            secure_clear_string(flow->mcp_endpoint);
            secure_clear_string(flow->config_fingerprint);
            secure_clear_string(flow->state_token);
            secure_clear_string(flow->code_verifier);
            secure_clear_string(flow->client_id);
            secure_clear_string(flow->client_secret);
            secure_clear_string(flow->redirect_uri);
            secure_clear_string(flow->token_endpoint);
            secure_clear_string(flow->scope);
            secure_clear_string(flow->received_code);
            SecureZeroMemory(flow->config_incarnation.data(), flow->config_incarnation.size());
            flow->config_generation = 0;
            flow->callback_done = true;
            server_name = flow->server_name;
            receipt_digest = flow->terminal_code_digest;
            receipt_error = flow->error;
            became_terminal = true;
        }
        snapshot.ready = flow->terminal_ready;
        snapshot.success = flow->terminal_success;
        snapshot.error = flow->error;
    }
    flow->terminal_cv.notify_all();
    if (became_terminal) {
        stop_oauth_flow_io(flow, cancel_owned_tasks);
        if (!receipt_digest.empty())
            record_oauth_terminal_receipt(server_name, receipt_digest, receipt_error, success);
        publish_oauth_terminal_event(flow);
        remove_oauth_flow_registry_reference(flow);
        std::lock_guard<std::mutex> lock(flow->mutex);
        flow->request_control.reset();
        flow->listener.reset();
        flow->listener_task_id = 0;
        flow->poll_task_id = 0;
        flow->initialization_task_id = 0;
    }
    return snapshot;
}

static void finalize_stale_oauth_flow(
    const std::shared_ptr<oauth_transient_flow_t>& flow)
{
    static_cast<void>(finalize_oauth_flow(flow, false,
        "OAuth flow expired or was abandoned before completion", {}, true));
}

static oauth_status_t complete_oauth_state(oauth_state_t& state,
                                           const oauth_terminal_snapshot_t& terminal,
                                           bool cancelled)
{
    if (state.done.load(std::memory_order_acquire))
        return state.terminal_status.load(std::memory_order_acquire);
    bool expected = false;
    if (!state.terminalizing.compare_exchange_strong(expected, true,
            std::memory_order_acq_rel)) {
        return state.done.load(std::memory_order_acquire)
            ? state.terminal_status.load(std::memory_order_acquire)
            : oauth_status_t::authenticating;
    }
    secure_clear_string(state.error);
    state.error = terminal.error;
    const oauth_status_t status = terminal.success
        ? oauth_status_t::authenticated : oauth_status_t::failed;
    state.cancelled.store(cancelled, std::memory_order_release);
    state.terminal_status.store(status, std::memory_order_release);
    scrub_oauth_state_transients(state);
    state.done.store(true, std::memory_order_release);
    return status;
}

static oauth_terminal_snapshot_t cancel_oauth_flow(
    const std::shared_ptr<oauth_transient_flow_t>& flow,
    const std::string& error,
    bool cancel_owned_tasks = true)
{
    if (!flow) {
        oauth_terminal_snapshot_t terminal;
        terminal.ready = true;
        terminal.error = error;
        return terminal;
    }
    {
        std::lock_guard<std::mutex> lock(flow->mutex);
        if (!flow->terminal_ready)
            flow->cancelled = true;
    }
    return finalize_oauth_flow(flow, false, error, {}, cancel_owned_tasks);
}

static void finalize_expired_oauth_listener_flow(
    const std::shared_ptr<oauth_transient_flow_t>& flow)
{
    bool expired = false;
    {
        std::lock_guard<std::mutex> lock(flow->mutex);
        expired = !flow->terminal_ready && flow->deadline_unix != 0
            && now_unix_seconds() > flow->deadline_unix;
    }
    if (expired)
        (void)finalize_oauth_flow(flow, false, "OAuth flow timed out", {}, false);
}

static std::atomic<bool>& oauth_reaper_running()
{
    static std::atomic<bool> running{false};
    return running;
}

static void ensure_oauth_reaper_task()
{
#if defined(AIDA_C03_MCP_OAUTH_FIXTURE)
    oauth_reaper_running().store(false, std::memory_order_release);
    return;
#else
    bool expected = false;
    if (!oauth_reaper_running().compare_exchange_strong(expected, true,
            std::memory_order_acq_rel))
        return;
    std::shared_ptr<std::atomic<bool>> stop;
    try {
        stop = std::make_shared<std::atomic<bool>>(false);
    } catch (...) {
        oauth_reaper_running().store(false, std::memory_order_release);
        throw;
    }
    const std::uint64_t start_ms = mcp_oauth_now_ms();
    std::uint64_t task_deadline_ms = 0;
    if (!mcp_oauth_deadline_ms_after(310000ULL, task_deadline_ms)) {
        oauth_reaper_running().store(false, std::memory_order_release);
        return;
    }
    auto submitted = submit_mcp_oauth_task(
        "mcp_client.oauth_reaper",
        aida::infra::executor::domain_t::service,
        "service_loop",
        2,
        task_deadline_ms,
        0,
        [stop]() {
            stop->store(true, std::memory_order_release);
            oauth_reaper_running().store(false, std::memory_order_release);
        },
        [start_ms, stop]() {
            while (!stop->load(std::memory_order_acquire)) {
                std::vector<std::shared_ptr<oauth_transient_flow_t>> snapshot;
                {
                    std::lock_guard<std::mutex> registry_lock(oauth_flow_registry_mutex());
                    snapshot.reserve(oauth_flow_registry().size());
                    for (const auto& entry : oauth_flow_registry())
                        snapshot.push_back(entry.second);
                }
                const int64_t now = now_unix_seconds();
                for (const auto& flow : snapshot) {
                    bool expired = false;
                    {
                        std::lock_guard<std::mutex> lock(flow->mutex);
                        expired = !flow->terminal_ready && flow->deadline_unix != 0
                            && now > flow->deadline_unix;
                    }
                    if (expired)
                        (void)finalize_oauth_flow(flow, false,
                            "OAuth flow timed out", {}, true);
                }
                bool empty = false;
                {
                    std::lock_guard<std::mutex> registry_lock(oauth_flow_registry_mutex());
                    empty = oauth_flow_registry().empty();
                }
                if (empty || stop->load(std::memory_order_acquire)
                    || mcp_oauth_now_ms() - start_ms >= 300000ULL)
                    break;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            oauth_reaper_running().store(false, std::memory_order_release);
            bool needs_restart = false;
            {
                std::lock_guard<std::mutex> registry_lock(oauth_flow_registry_mutex());
                needs_restart = !oauth_flow_registry().empty();
            }
            if (!stop->load(std::memory_order_acquire) && needs_restart)
                ensure_oauth_reaper_task();
        });
    if (!submitted.submitted)
        oauth_reaper_running().store(false, std::memory_order_release);
#endif
}

oauth_state_t::~oauth_state_t()
{
    const auto flow = oauth_flow_from_state(*this);
    if (flow)
        (void)cancel_oauth_flow(flow, "OAuth flow owner was abandoned");
    scrub_oauth_state_transients(*this);
    secure_clear_string(error);
    done.store(true, std::memory_order_release);
    cancelled.store(true, std::memory_order_release);
    terminalizing.store(true, std::memory_order_release);
    terminal_status.store(oauth_status_t::failed, std::memory_order_release);
}

static std::shared_ptr<oauth_trigger_request_t> find_oauth_trigger_request(
    const std::string& server_name)
{
    std::lock_guard<std::mutex> lock(oauth_trigger_registry_mutex());
    const auto it = oauth_trigger_registry().find(server_name);
    return it == oauth_trigger_registry().end() ? nullptr : it->second;
}

static bool register_oauth_trigger_request(
    const std::shared_ptr<oauth_trigger_request_t>& request,
    std::string& error)
{
    constexpr size_t kMaximumRequests = 128;
    std::lock_guard<std::mutex> lock(oauth_trigger_registry_mutex());
    auto& registry = oauth_trigger_registry();
    for (auto it = registry.begin(); it != registry.end();) {
        if (!it->second || it->second->completed.load(std::memory_order_acquire))
            it = registry.erase(it);
        else
            ++it;
    }
    if (registry.find(request->server_name) != registry.end()) {
        error = "an OAuth trigger request is already active for this MCP server";
        return false;
    }
    if (registry.size() >= kMaximumRequests) {
        error = "the bounded MCP OAuth trigger registry is full";
        return false;
    }
    std::uint64_t& generation = oauth_trigger_generation();
    if (generation == (std::numeric_limits<std::uint64_t>::max)()) {
        error = "the MCP OAuth trigger generation space is exhausted; restart is required";
        return false;
    }
    request->generation = ++generation;
    registry.emplace(request->server_name, request);
    return true;
}

static void erase_oauth_trigger_request(
    const std::shared_ptr<oauth_trigger_request_t>& request)
{
    if (!request)
        return;
    std::lock_guard<std::mutex> lock(oauth_trigger_registry_mutex());
    auto& registry = oauth_trigger_registry();
    const auto it = registry.find(request->server_name);
    if (it != registry.end() && it->second == request)
        registry.erase(it);
}

static void invoke_oauth_trigger_callback(
    const std::shared_ptr<oauth_trigger_request_t>& request,
    oauth_status_t status,
    std::string error)
{
    secure_string_scope_t error_guard{error};
    if (!request || request->callback_done.exchange(true, std::memory_order_acq_rel))
        return;
    try {
        if (request->callback)
            request->callback(request->server_name, status, error);
    } catch (...) {
    }
}

static void publish_oauth_trigger_failure(
    const std::shared_ptr<oauth_trigger_request_t>& request,
    const std::string& error,
    bool retry_fixture_fault = true)
{
    if (!request || request->event_done.exchange(true, std::memory_order_acq_rel))
        return;
    bool current = false;
    {
        std::lock_guard<std::mutex> lock(oauth_trigger_registry_mutex());
        const auto it = oauth_trigger_registry().find(request->server_name);
        current = it != oauth_trigger_registry().end() && it->second == request;
    }
    if (!current)
        return;
    try {
#if defined(AIDA_C03_MCP_OAUTH_FIXTURE)
        if (consume_oauth_fixture_fault(c03_oauth_fixture::fault_point_t::event_publish))
            throw std::bad_alloc();
        c03_oauth_fixture::event_t event;
        event.server_name = request->server_name;
        event.status = oauth_status_t::failed;
        event.error = error;
        event.generation = request->generation;
        std::lock_guard<std::mutex> fixture_lock(oauth_fixture_runtime().mutex);
        oauth_fixture_runtime().events.push_back(std::move(event));
#else
        aida::events::oauth_failed_t failed;
        failed.provider_id = mcp_auth_key(request->server_name);
        failed.error = error;
        aida::events::publish(aida::events::event_oauth_failed, failed);
#endif
    } catch (...) {
#if defined(AIDA_C03_MCP_OAUTH_FIXTURE)
        if (retry_fixture_fault) {
            request->event_done.store(false, std::memory_order_release);
            publish_oauth_trigger_failure(request, error, false);
        }
#else
        static_cast<void>(retry_fixture_fault);
#endif
    }
}

static bool find_oauth_server_config(const std::string& server_name,
                                     server_config_t& config)
{
#if defined(AIDA_C03_MCP_OAUTH_FIXTURE)
    if (consume_oauth_fixture_fault(c03_oauth_fixture::fault_point_t::config_lookup))
        throw std::bad_alloc();
    std::lock_guard<std::mutex> lock(oauth_fixture_runtime().mutex);
    const auto it = oauth_fixture_runtime().configs.find(server_name);
    if (it == oauth_fixture_runtime().configs.end())
        return false;
    config = it->second;
    return true;
#else
    return ::s_mcp_client_mgr.find_config(server_name, config);
#endif
}

bool supports_oauth(const std::string& server_name)
{
    server_config_t cfg;
    if (!find_oauth_server_config(server_name, cfg)) return false;
    secure_server_config_scope_t config_guard{cfg};
    if (cfg.transport != transport_type_t::http_sse) return false;
    return cfg.oauth_enabled;
}

bool has_stored_tokens(const std::string& server_name)
{
    aida::auth::auth_info_t info;
    secure_auth_info_scope_t info_guard{info};
    if (!load_mcp_auth(server_name, info)) return false;
    return !info.access.empty();
}

oauth_status_t auth_status(const std::string& server_name)
{
    const auto trigger = find_oauth_trigger_request(server_name);
    if (trigger && !trigger->completed.load(std::memory_order_acquire))
        return oauth_status_t::authenticating;
    const auto flow = find_oauth_flow(server_name, nullptr);
    if (flow) {
        std::lock_guard<std::mutex> lock(flow->mutex);
        if (!flow->terminal_ready)
            return oauth_status_t::authenticating;
        return flow->terminal_success
            ? oauth_status_t::authenticated : oauth_status_t::failed;
    }
    aida::auth::auth_info_t info;
    secure_auth_info_scope_t info_guard{info};
    if (!load_mcp_auth(server_name, info) || info.access.empty())
        return oauth_status_t::needs_auth;
    if (info.expires_unix == 0) return oauth_status_t::authenticated;
    const int64_t now = now_unix_seconds();
    if (now >= info.expires_unix) return oauth_status_t::needs_auth;
    return oauth_status_t::authenticated;
}

static bool oauth_state_is_bounded(const oauth_state_t& state)
{
    return valid_mcp_server_name(state.server_name)
        && !state.state_token.empty() && state.state_token.size() <= 256
        && !state.code_verifier.empty() && state.code_verifier.size() <= 256
        && !state.code_challenge.empty() && state.code_challenge.size() <= 256
        && !state.client_id.empty() && state.client_id.size() <= 2048
        && state.client_secret.size() <= 8192
        && !state.redirect_uri.empty() && state.redirect_uri.size() <= 8192
        && !state.token_endpoint.empty() && state.token_endpoint.size() <= 8192
        && !state.authorization_endpoint.empty() && state.authorization_endpoint.size() <= 8192
        && state.registration_endpoint.size() <= 8192
        && state.scope.size() <= 4096
        && !state.authorization_url.empty() && state.authorization_url.size() <= 32768
        && state.deadline_unix > now_unix_seconds();
}

static bool fail_oauth_start(oauth_state_t& state,
                             const std::shared_ptr<oauth_transient_flow_t>& flow,
                             std::string error)
{
    secure_string_scope_t error_guard{error};
    oauth_terminal_snapshot_t terminal;
    if (flow)
        terminal = finalize_oauth_flow(flow, false, error, {}, true);
    else {
        terminal.ready = true;
        terminal.success = false;
        terminal.error = error;
    }
    set_global_last_error(terminal.error);
    (void)complete_oauth_state(state, terminal,
        state.cancelled.load(std::memory_order_acquire));
    return false;
}

static bool activate_oauth_flow(const std::shared_ptr<oauth_transient_flow_t>& flow,
                                const oauth_state_t& state,
                                const std::string& mcp_endpoint)
{
    std::string fingerprint;
    std::uint64_t config_generation = 0;
    std::array<unsigned char, 16> config_incarnation{};
    {
        std::lock_guard<std::mutex> lock(flow->mutex);
        fingerprint = flow->config_fingerprint;
        config_generation = flow->config_generation;
        config_incarnation = flow->config_incarnation;
    }
    secure_string_scope_t fingerprint_guard{fingerprint};
    if (!mcp_config_incarnation_matches(flow->server_name, fingerprint,
            config_generation, config_incarnation)) {
        SecureZeroMemory(config_incarnation.data(), config_incarnation.size());
        return false;
    }
    SecureZeroMemory(config_incarnation.data(), config_incarnation.size());
    std::lock_guard<std::mutex> lock(flow->mutex);
    if (flow->phase != oauth_flow_phase_t::initializing || flow->cancelled
        || (flow->deadline_unix != 0 && now_unix_seconds() > flow->deadline_unix))
        return false;
    flow->mcp_endpoint = mcp_endpoint;
    flow->code_verifier = state.code_verifier;
    flow->client_id = state.client_id;
    flow->client_secret = state.client_secret;
    flow->redirect_uri = state.redirect_uri;
    flow->token_endpoint = state.token_endpoint;
    flow->scope = state.scope;
    flow->phase = oauth_flow_phase_t::active;
    return true;
}


bool start_auth(const std::string& server_name, oauth_state_t& out_state)
{
    const auto previous = oauth_flow_from_state(out_state);
    if (previous)
        (void)cancel_oauth_flow(previous, "OAuth flow was replaced by a new start request");
    scrub_oauth_state_transients(out_state);
    secure_clear_string(out_state.error);
    out_state.server_name = server_name;
    out_state.done.store(false);
    out_state.cancelled.store(false);
    out_state.terminalizing.store(false);
    out_state.terminal_status.store(oauth_status_t::authenticating);
    out_state.error.clear();
    if (!mcp_oauth_deadline_unix_after(300, out_state.deadline_unix))
        return fail_oauth_start(out_state, {}, "MCP OAuth deadline is not representable");

    if (!valid_mcp_server_name(server_name))
        return fail_oauth_start(out_state, {}, "MCP OAuth server identity is invalid or too large");
    std::shared_ptr<oauth_transient_flow_t> flow;
    try {
        server_config_t cfg;
        if (!find_oauth_server_config(server_name, cfg))
            return fail_oauth_start(out_state, {}, "MCP server is not registered");
        secure_server_config_scope_t config_guard{cfg};
        if (cfg.transport != transport_type_t::http_sse || !cfg.oauth_enabled)
            return fail_oauth_start(out_state, {},
                "MCP server does not support enabled remote OAuth");

        parsed_url_t purl;
        if (!parse_url_full(cfg.url, purl) || !valid_oauth_network_endpoint(purl))
            return fail_oauth_start(out_state, {}, "Invalid MCP OAuth server URL");

        std::string config_fingerprint = server_config_fingerprint(cfg);
        secure_string_scope_t config_fingerprint_guard{config_fingerprint};
        if (config_fingerprint.empty())
            return fail_oauth_start(out_state, {}, "MCP OAuth configuration fingerprint failed");
        mcp_config_incarnation_t config_incarnation;
        if (!advance_mcp_config_incarnation(server_name, config_fingerprint,
                &config_incarnation, nullptr)) {
            return fail_oauth_start(out_state, {},
                "MCP OAuth configuration incarnation is unavailable or exhausted");
        }

        out_state.code_verifier = generate_pkce_verifier();
        if (out_state.code_verifier.empty())
            return fail_oauth_start(out_state, {}, "PKCE verifier generation failed");
        out_state.code_challenge = sha256_base64url(out_state.code_verifier);
        if (out_state.code_challenge.empty())
            return fail_oauth_start(out_state, {}, "PKCE challenge derivation failed");
        out_state.state_token = generate_state_token();
        if (out_state.state_token.empty())
            return fail_oauth_start(out_state, {}, "state token generation failed");

        flow = std::make_shared<oauth_transient_flow_t>();
        flow->server_name = server_name;
        flow->state_token = out_state.state_token;
        flow->deadline_unix = out_state.deadline_unix;
        flow->request_control = std::make_shared<oauth_request_control_t>();
        flow->config_fingerprint = config_fingerprint;
        flow->config_generation = config_incarnation.generation;
        flow->config_incarnation = config_incarnation.incarnation;
        if (!read_mcp_auth_epoch(server_name, flow->persistence_epoch))
            return fail_oauth_start(out_state, flow,
                "The bounded MCP OAuth persistence registry is full");
        if (flow->persistence_epoch == (std::numeric_limits<std::uint64_t>::max)())
            return fail_oauth_start(out_state, flow,
                "The MCP OAuth persistence generation space is exhausted; restart is required");
        std::string registry_error;
        secure_string_scope_t registry_error_guard{registry_error};
        if (!register_oauth_flow(flow, registry_error))
            return fail_oauth_start(out_state, flow, registry_error);

        if (!start_oauth_listener(out_state, flow)) {
            return fail_oauth_start(out_state, flow,
                out_state.error.empty() ? "OAuth callback listener submission failed" : out_state.error);
        }

        const std::string bound_redirect = "http://127.0.0.1:"
            + std::to_string(out_state.callback_port) + "/mcp/oauth/callback";
        if (!cfg.oauth_redirect_uri.empty() && cfg.oauth_redirect_uri != bound_redirect) {
            return fail_oauth_start(out_state, flow,
                "Configured OAuth redirect URI does not exactly match the bound random loopback listener");
        }
        out_state.redirect_uri = bound_redirect;

        std::string te;
        std::string ae;
        std::string re;
        std::string discovery_error;
        secure_string_scope_t token_endpoint_guard{te};
        secure_string_scope_t authorization_endpoint_guard{ae};
        secure_string_scope_t registration_endpoint_guard{re};
        secure_string_scope_t discovery_error_guard{discovery_error};
        if (!fetch_oauth_metadata(purl, te, ae, re, flow->request_control,
                out_state.deadline_unix, discovery_error)) {
            return fail_oauth_start(out_state, flow,
                discovery_error.empty()
                    ? "OAuth metadata discovery failed for the MCP server"
                    : discovery_error);
        }
        if (oauth_flow_cancelled_or_expired(flow, flow->generation))
            return fail_oauth_start(out_state, flow, "OAuth flow was cancelled or expired during discovery");

        out_state.token_endpoint = te;
        out_state.authorization_endpoint = ae;
        out_state.registration_endpoint = re;
        out_state.scope = cfg.oauth_scope;
        out_state.client_id = cfg.oauth_client_id;
        out_state.client_secret = cfg.oauth_client_secret;

        if (out_state.client_id.empty()) {
            if (re.empty()) {
                return fail_oauth_start(out_state, flow,
                    "Server does not support dynamic client registration and no OAuth client ID is configured");
            }
            std::string registration_error;
            std::string new_client_id;
            std::string new_client_secret;
            secure_string_scope_t registration_error_guard{registration_error};
            secure_string_scope_t client_id_guard{new_client_id};
            secure_string_scope_t client_secret_guard{new_client_secret};
            if (!register_dynamic_client(re, out_state.redirect_uri,
                    new_client_id, new_client_secret, registration_error,
                    flow->request_control, out_state.deadline_unix)) {
                return fail_oauth_start(out_state, flow,
                    "dynamic client registration failed: " + registration_error);
            }
            out_state.client_id = new_client_id;
            out_state.client_secret = new_client_secret;
            bool dynamic_client_recorded = false;
            {
                std::lock_guard<std::mutex> flow_lock(flow->mutex);
                if (flow->phase == oauth_flow_phase_t::initializing
                    && !flow->cancelled) {
                    flow->dynamic_client = true;
                    dynamic_client_recorded = true;
                }
            }
            if (!dynamic_client_recorded) {
                return fail_oauth_start(out_state, flow,
                    "OAuth flow was cancelled during dynamic client registration");
            }
        }

        out_state.authorization_url = build_authorize_url(
            out_state.authorization_endpoint, out_state.client_id,
            out_state.redirect_uri, out_state.scope,
            out_state.code_challenge, out_state.state_token);
        if (!oauth_state_is_bounded(out_state))
            return fail_oauth_start(out_state, flow,
                "OAuth metadata exceeds bounded transient-flow limits");
        if (!activate_oauth_flow(flow, out_state, cfg.url))
            return fail_oauth_start(out_state, flow,
                "OAuth flow activation lost its configuration generation or was cancelled");
        if (!open_browser(out_state.authorization_url)) {
#if !defined(AIDA_C03_MCP_OAUTH_FIXTURE)
            diag::log_tagged("mcp.oauth",
                "[mcp.oauth] Camoufox open failed; non-Camoufox browser fallback is disabled");
#endif
            return fail_oauth_start(out_state, flow,
                "Camoufox failed to open the OAuth authorization URL");
        }
        if (oauth_flow_cancelled_or_expired(flow, flow->generation))
            return fail_oauth_start(out_state, flow,
                "OAuth flow was cancelled or expired while opening Camoufox");
        set_global_last_error({});
        return true;
    } catch (const std::bad_alloc&) {
        return fail_oauth_start(out_state, flow, "OAuth initialization allocation failed");
    } catch (...) {
        return fail_oauth_start(out_state, flow,
            "OAuth initialization failed with an unexpected exception");
    }
}

static oauth_terminal_snapshot_t finish_oauth_flow_exact(
    const std::shared_ptr<oauth_transient_flow_t>& flow,
    const std::string& authorization_code);

oauth_status_t poll_auth(oauth_state_t& state)
{
    if (state.done.load(std::memory_order_acquire))
        return state.terminal_status.load(std::memory_order_acquire);

    const auto flow = oauth_flow_from_state(state);
    if (!flow) {
        oauth_terminal_snapshot_t terminal;
        terminal.ready = true;
        terminal.error = "OAuth flow ownership is unavailable or its incarnation does not match";
        set_global_last_error(terminal.error);
        return complete_oauth_state(state, terminal, true);
    }

    if (state.cancelled.load(std::memory_order_acquire)) {
        auto terminal = cancel_oauth_flow(flow, "OAuth flow was cancelled");
        set_global_last_error(terminal.error);
        return complete_oauth_state(state, terminal, true);
    }

    std::string callback_error;
    std::string authorization_code;
    bool callback_done = false;
    bool expired = false;
    oauth_terminal_snapshot_t existing_terminal;
    {
        std::lock_guard<std::mutex> lock(flow->mutex);
        expired = flow->deadline_unix != 0 && now_unix_seconds() > flow->deadline_unix;
        existing_terminal.ready = flow->terminal_ready;
        existing_terminal.success = flow->terminal_success;
        existing_terminal.error = flow->error;
        callback_done = flow->callback_done;
        if (callback_done && !flow->terminal_ready) {
            callback_error = flow->error;
            authorization_code = flow->received_code;
        }
    }
    secure_string_scope_t callback_error_guard{callback_error};
    secure_string_scope_t authorization_code_guard{authorization_code};

    if (existing_terminal.ready) {
        set_global_last_error(existing_terminal.success ? std::string{} : existing_terminal.error);
        return complete_oauth_state(state, existing_terminal,
            !existing_terminal.success && state.cancelled.load(std::memory_order_acquire));
    }
    if (expired) {
        auto terminal = cancel_oauth_flow(flow, "OAuth flow timed out");
        set_global_last_error(terminal.error);
        return complete_oauth_state(state, terminal, true);
    }
    if (!callback_done)
        return oauth_status_t::authenticating;

    oauth_terminal_snapshot_t terminal;
    if (!callback_error.empty()) {
        terminal = finalize_oauth_flow(flow, false, callback_error, {}, false);
    } else if (authorization_code.empty()) {
        terminal = finalize_oauth_flow(flow, false,
            "OAuth callback completed without an authorization code", {}, false);
    } else {
        terminal = finish_oauth_flow_exact(flow, authorization_code);
    }
    set_global_last_error(terminal.success ? std::string{} : terminal.error);
    return complete_oauth_state(state, terminal, false);
}

static oauth_terminal_snapshot_t finish_oauth_flow_exact(
    const std::shared_ptr<oauth_transient_flow_t>& flow,
    const std::string& authorization_code)
{
    oauth_terminal_snapshot_t terminal;
    if (!flow) {
        terminal.error = "finish_auth requires an exact active OAuth flow";
        return terminal;
    }
    std::string code_digest;
    secure_string_scope_t code_digest_guard{code_digest};
    try {
        code_digest = sha256_base64url(authorization_code);
        if (code_digest.empty()) {
            terminal.error = "finish_auth could not derive the authorization-code receipt identity";
            return terminal;
        }

        oauth_exchange_material_t material;
        std::unique_lock<std::mutex> lock(flow->mutex);
        if (flow->terminal_ready) {
            terminal.ready = true;
            terminal.success = flow->terminal_success;
            terminal.error = flow->error;
            return terminal;
        }
        if (flow->phase == oauth_flow_phase_t::exchanging) {
            const int64_t deadline = flow->deadline_unix;
            const auto wait_deadline = std::chrono::system_clock::from_time_t(
                static_cast<std::time_t>((std::min)(deadline,
                    now_unix_seconds() + 45)));
            flow->terminal_cv.wait_until(lock, wait_deadline, [&flow]() {
                return flow->terminal_ready || flow->cancelled
                    || flow->phase != oauth_flow_phase_t::exchanging;
            });
            if (flow->terminal_ready) {
                terminal.ready = true;
                terminal.success = flow->terminal_success;
                terminal.error = flow->error;
                return terminal;
            }
            lock.unlock();
            return finalize_oauth_flow(flow, false,
                "OAuth authorization-code exchange exceeded its bounded deadline",
                code_digest, true);
        }
        if (flow->cancelled || (flow->deadline_unix != 0
                && now_unix_seconds() > flow->deadline_unix)) {
            lock.unlock();
            return finalize_oauth_flow(flow, false,
                "finish_auth rejected a cancelled or expired OAuth flow",
                code_digest, true);
        }
        if (flow->phase != oauth_flow_phase_t::active) {
            terminal.error = "finish_auth rejected an OAuth flow that is not callback-ready";
            return terminal;
        }
        if (!flow->callback_done) {
            terminal.error = "finish_auth requires a validated loopback callback before accepting a code";
            return terminal;
        }
        if (!flow->error.empty()) {
            std::string callback_error = flow->error;
            lock.unlock();
            secure_string_scope_t callback_error_guard{callback_error};
            return finalize_oauth_flow(flow, false, callback_error,
                code_digest, false);
        }
        if (flow->received_code.empty() || flow->received_code != authorization_code) {
            terminal.error = "finish_auth authorization code does not match the validated callback";
            return terminal;
        }

        flow->phase = oauth_flow_phase_t::exchanging;
        material.server_name = flow->server_name;
        material.mcp_endpoint = flow->mcp_endpoint;
        material.token_endpoint = flow->token_endpoint;
        material.client_id = flow->client_id;
        material.client_secret = flow->client_secret;
        material.redirect_uri = flow->redirect_uri;
        material.code_verifier = flow->code_verifier;
        material.authorization_code = authorization_code;
        material.scope = flow->scope;
        material.config_fingerprint = flow->config_fingerprint;
        material.config_generation = flow->config_generation;
        material.config_incarnation = flow->config_incarnation;
        material.persistence_epoch = flow->persistence_epoch;
        material.deadline_unix = flow->deadline_unix;
        material.dynamic_client = flow->dynamic_client;
        material.request_control = flow->request_control;
        lock.unlock();

        server_config_t cfg;
        if (!find_oauth_server_config(material.server_name, cfg)) {
            return finalize_oauth_flow(flow, false,
                "finish_auth rejected a removed MCP server configuration",
                code_digest, false);
        }
        secure_server_config_scope_t config_guard{cfg};
        std::string current_fingerprint = server_config_fingerprint(cfg);
        secure_string_scope_t current_fingerprint_guard{current_fingerprint};
        if (current_fingerprint != material.config_fingerprint
            || !mcp_config_incarnation_matches(material.server_name,
                material.config_fingerprint, material.config_generation,
                material.config_incarnation)) {
            return finalize_oauth_flow(flow, false,
                "finish_auth rejected a changed MCP server configuration generation",
                code_digest, false);
        }
        if (material.token_endpoint.empty() || material.client_id.empty()
            || material.redirect_uri.empty() || material.code_verifier.empty()
            || material.request_control == nullptr) {
            return finalize_oauth_flow(flow, false,
                "finish_auth active OAuth metadata is incomplete",
                code_digest, false);
        }

        std::string access;
        std::string refresh;
        std::string returned_scope;
        std::string exchange_error;
        secure_string_scope_t access_guard{access};
        secure_string_scope_t refresh_guard{refresh};
        secure_string_scope_t returned_scope_guard{returned_scope};
        secure_string_scope_t exchange_error_guard{exchange_error};
        int64_t expires_in = 3600;
        if (!exchange_authorization_code(material.token_endpoint, material.client_id,
                material.client_secret, material.redirect_uri,
                material.authorization_code, material.code_verifier,
                access, refresh, expires_in, returned_scope, exchange_error,
                material.request_control, material.deadline_unix)) {
            return finalize_oauth_flow(flow, false,
                exchange_error.empty()
                    ? "OAuth authorization-code exchange failed" : exchange_error,
                code_digest, false);
        }

        constexpr int64_t kMaximumTokenLifetimeSeconds = 31536000;
        if (access.empty() || expires_in <= 0 || expires_in > kMaximumTokenLifetimeSeconds) {
            return finalize_oauth_flow(flow, false,
                "OAuth token endpoint returned invalid bounded token metadata",
                code_digest, false);
        }
        int64_t token_expires_unix = 0;
        if (!mcp_oauth_deadline_unix_after(expires_in, token_expires_unix)) {
            return finalize_oauth_flow(flow, false,
                "OAuth token expiry is not representable", code_digest, false);
        }

        aida::auth::auth_info_t info;
        secure_auth_info_scope_t info_guard{info};
        info.kind = aida::auth::auth_kind_t::oauth;
        info.access = access;
        info.refresh = refresh;
        info.expires_unix = token_expires_unix;
        info.custom_client_id = material.client_id;
        info.custom_redirect_uri = material.redirect_uri;
        const std::string& effective_scope = returned_scope.empty()
            ? material.scope : returned_scope;
        size_t scope_begin = 0;
        while (scope_begin < effective_scope.size()) {
            while (scope_begin < effective_scope.size()
                && std::isspace(static_cast<unsigned char>(effective_scope[scope_begin])))
                ++scope_begin;
            if (scope_begin >= effective_scope.size())
                break;
            size_t scope_end = scope_begin;
            while (scope_end < effective_scope.size()
                && !std::isspace(static_cast<unsigned char>(effective_scope[scope_end])))
                ++scope_end;
            if (info.custom_scopes.size() >= 128u
                || scope_end - scope_begin > 4096u) {
                return finalize_oauth_flow(flow, false,
                    "OAuth scope metadata exceeds bounded persistence limits",
                    code_digest, false);
            }
            info.custom_scopes.emplace_back(effective_scope.substr(
                scope_begin, scope_end - scope_begin));
            scope_begin = scope_end;
        }
        info.metadata = json::object({
            {"mcp_token_endpoint", material.token_endpoint},
            {"mcp_config_fingerprint", material.config_fingerprint},
            {"mcp_dynamic_client", material.dynamic_client}
        });
        if (material.dynamic_client && !material.client_secret.empty())
            info.metadata["mcp_client_secret"] = material.client_secret;

        std::unique_lock<std::mutex> commit_lock(flow->commit_mutex);
        bool eligible = false;
        {
            std::lock_guard<std::mutex> flow_lock(flow->mutex);
            eligible = !flow->terminal_ready && !flow->cancelled
                && flow->phase == oauth_flow_phase_t::exchanging
                && (flow->deadline_unix == 0
                    || now_unix_seconds() <= flow->deadline_unix);
        }
        eligible = eligible && mcp_config_incarnation_matches(material.server_name,
            material.config_fingerprint, material.config_generation,
            material.config_incarnation);
        if (!eligible) {
            return finalize_oauth_flow(flow, false,
                "OAuth flow became stale before credential commit",
                code_digest, false, true);
        }
        const bool saved = save_mcp_auth_if(material.server_name, info,
            [&flow, &material]() {
                std::lock_guard<std::mutex> flow_lock(flow->mutex);
                if (flow->terminal_ready || flow->cancelled
                    || flow->phase != oauth_flow_phase_t::exchanging
                    || (flow->deadline_unix != 0
                        && now_unix_seconds() > flow->deadline_unix)
                    || !mcp_config_incarnation_matches(material.server_name,
                        material.config_fingerprint, material.config_generation,
                        material.config_incarnation)
                    || !claim_mcp_auth_epoch(material.server_name,
                        material.persistence_epoch)) {
                    return false;
                }
                flow->phase = oauth_flow_phase_t::committed;
                return true;
            });
        if (!saved) {
            const std::string persistence_error = "OAuth credential persistence failed: "
                + aida::auth::store::last_error();
            return finalize_oauth_flow(flow, false, persistence_error,
                code_digest, false, true);
        }
        const std::uint64_t committed_epoch = next_mcp_auth_epoch(material.persistence_epoch);
        bool committed = committed_epoch != 0
            && mcp_auth_epoch_matches(material.server_name, committed_epoch)
            && mcp_config_incarnation_matches(material.server_name,
                material.config_fingerprint, material.config_generation,
                material.config_incarnation);
        {
            std::lock_guard<std::mutex> flow_lock(flow->mutex);
            committed = committed && flow->phase == oauth_flow_phase_t::committed
                && !flow->terminal_ready;
        }
        if (!committed) {
            return finalize_oauth_flow(flow, false,
                "OAuth credential was removed or its configuration changed during commit",
                code_digest, false, true);
        }
        return finalize_oauth_flow(flow, true, {}, code_digest, false, true);
    } catch (const std::bad_alloc&) {
        return finalize_oauth_flow(flow, false,
            "OAuth completion allocation failed", code_digest, true);
    } catch (...) {
        return finalize_oauth_flow(flow, false,
            "OAuth completion failed with an unexpected exception", code_digest, true);
    }
}

bool finish_auth(const std::string& server_name, const std::string& authorization_code)
{
    if (!valid_mcp_server_name(server_name)
        || authorization_code.empty() || authorization_code.size() > 4096) {
        set_global_last_error("finish_auth received invalid bounded flow identity or authorization code");
        return false;
    }
    std::string code_digest;
    secure_string_scope_t code_digest_guard{code_digest};
    try {
        code_digest = sha256_base64url(authorization_code);
    } catch (...) {
        set_global_last_error("finish_auth authorization-code receipt allocation failed");
        return false;
    }
    const auto flow = find_oauth_flow(server_name, nullptr);
    if (flow) {
        auto terminal = finish_oauth_flow_exact(flow, authorization_code);
        set_global_last_error(terminal.success ? std::string{} : terminal.error);
        return terminal.ready && terminal.success;
    }
    bool receipt_success = false;
    std::string receipt_error;
    secure_string_scope_t receipt_error_guard{receipt_error};
    if (!code_digest.empty()
        && find_oauth_terminal_receipt(server_name, code_digest,
            receipt_success, receipt_error)) {
        set_global_last_error(receipt_success ? std::string{} : receipt_error);
        return receipt_success;
    }
    set_global_last_error("finish_auth requires one exact active transient OAuth flow");
    return false;
}

bool remove_auth(const std::string& server_name)
{
    if (!valid_mcp_server_name(server_name)) {
        set_global_last_error("remove_auth received an invalid MCP server identity");
        return false;
    }
    invalidate_mcp_auth_epoch(server_name);
    (void)cancel_auth(server_name);
    if (!delete_mcp_auth(server_name)) {
        set_global_last_error("auth_store::remove failed: " + aida::auth::store::last_error());
        return false;
    }
    set_global_last_error({});
    return true;
}

bool cancel_auth(oauth_state_t& state)
{
    if (state.done.load(std::memory_order_acquire)) {
        const bool already_cancelled = state.cancelled.load(std::memory_order_acquire);
        set_global_last_error(already_cancelled
            ? "OAuth flow was already cancelled" : "OAuth flow already completed");
        return already_cancelled;
    }
    const auto flow = oauth_flow_from_state(state);
    if (!flow) {
        oauth_terminal_snapshot_t terminal;
        terminal.ready = true;
        terminal.error = "OAuth flow is not active or its incarnation does not match";
        state.cancelled.store(true, std::memory_order_release);
        (void)complete_oauth_state(state, terminal, true);
        set_global_last_error(terminal.error);
        return false;
    }
    auto terminal = cancel_oauth_flow(flow, "OAuth flow was cancelled");
    (void)complete_oauth_state(state, terminal, !terminal.success);
    if (terminal.success) {
        set_global_last_error("OAuth flow already completed successfully");
        return false;
    }
    set_global_last_error(terminal.error);
    return true;
}

bool cancel_auth(const std::string& server_name)
{
    if (!valid_mcp_server_name(server_name)) {
        set_global_last_error("cancel_auth received an invalid MCP server identity");
        return false;
    }
    bool found = false;
    const auto request = find_oauth_trigger_request(server_name);
    if (request) {
        found = true;
        request->cancelled.store(true, std::memory_order_release);
        oauth_status_t callback_status = oauth_status_t::failed;
        std::string callback_error = "OAuth flow was cancelled";
        secure_string_scope_t callback_error_guard{callback_error};
        if (request->state) {
            request->state->cancelled.store(true, std::memory_order_release);
            const auto flow = oauth_flow_from_state(*request->state);
            if (flow) {
                auto terminal = cancel_oauth_flow(flow, "OAuth flow was cancelled", false);
                (void)complete_oauth_state(*request->state, terminal, !terminal.success);
                if (terminal.success) {
                    callback_status = oauth_status_t::authenticated;
                    secure_clear_string(callback_error);
                } else if (!terminal.error.empty()) {
                    callback_error = terminal.error;
                }
            } else if (!request->state->done.load(std::memory_order_acquire)) {
                oauth_terminal_snapshot_t terminal;
                terminal.ready = true;
                terminal.error = "OAuth flow was cancelled before initialization completed";
                (void)complete_oauth_state(*request->state, terminal, true);
                publish_oauth_trigger_failure(request, terminal.error);
                callback_error = terminal.error;
            } else {
                callback_status = request->state->terminal_status.load(std::memory_order_acquire);
                if (callback_status == oauth_status_t::authenticated)
                    secure_clear_string(callback_error);
                else
                    callback_error = request->state->error;
            }
        }
        invoke_oauth_trigger_callback(request, callback_status, callback_error);
        request->completed.store(true, std::memory_order_release);
        const std::uint64_t task_id = request->task_id.exchange(0, std::memory_order_acq_rel);
        erase_oauth_trigger_request(request);
        if (task_id != 0)
            (void)cancel_mcp_oauth_task(task_id);
    }
    const auto flow = find_oauth_flow(server_name, nullptr);
    if (flow) {
        found = true;
        (void)cancel_oauth_flow(flow, "OAuth flow was cancelled");
    }
    set_global_last_error(found ? "OAuth flow was cancelled"
                                : "No active OAuth flow exists for this MCP server");
    return found;
}


bool trigger_auth_flow(const std::string& server_name, auth_completion_callback_t on_complete)
{
    if (!valid_mcp_server_name(server_name)) {
        set_global_last_error("trigger_auth_flow received an invalid MCP server identity");
        return false;
    }
    std::shared_ptr<oauth_trigger_request_t> request;
    try {
        request = std::make_shared<oauth_trigger_request_t>();
        request->server_name = server_name;
        request->state = std::make_shared<oauth_state_t>();
        request->state->server_name = server_name;
        request->callback = std::move(on_complete);
    } catch (...) {
        set_global_last_error("trigger_auth_flow allocation failed");
        return false;
    }

    std::string registration_error;
    secure_string_scope_t registration_error_guard{registration_error};
    if (!register_oauth_trigger_request(request, registration_error)) {
        set_global_last_error(registration_error);
        return false;
    }

    std::uint64_t task_deadline_ms = 0;
    if (!mcp_oauth_deadline_ms_after(300000ULL, task_deadline_ms)) {
        const std::string error = "OAuth trigger deadline is not representable";
        publish_oauth_trigger_failure(request, error);
        invoke_oauth_trigger_callback(request, oauth_status_t::failed, error);
        request->completed.store(true, std::memory_order_release);
        erase_oauth_trigger_request(request);
        set_global_last_error(error);
        return false;
    }

    auto submitted = submit_mcp_oauth_task(
        "mcp_client.oauth_initialize_and_poll",
        aida::infra::executor::domain_t::external_tool,
        "bounded_task",
        3,
        task_deadline_ms,
        request->generation,
        [request]() {
            request->cancelled.store(true, std::memory_order_release);
            request->task_id.store(0, std::memory_order_release);
            try {
                if (request->state) {
                    const auto flow = oauth_flow_from_state(*request->state);
                    oauth_terminal_snapshot_t terminal;
                    if (flow) {
                        std::lock_guard<std::mutex> lock(flow->mutex);
                        terminal.ready = flow->terminal_ready;
                        terminal.success = flow->terminal_success;
                        terminal.error = flow->error;
                    }
                    if (terminal.ready) {
                        (void)complete_oauth_state(*request->state, terminal,
                            !terminal.success);
                        invoke_oauth_trigger_callback(request,
                            terminal.success ? oauth_status_t::authenticated
                                             : oauth_status_t::failed,
                            terminal.success ? std::string{} : terminal.error);
                        request->completed.store(true, std::memory_order_release);
                        erase_oauth_trigger_request(request);
                        return;
                    }
                }
                (void)cancel_auth(request->server_name);
            } catch (...) {
                request->completed.store(true, std::memory_order_release);
                erase_oauth_trigger_request(request);
            }
        },
        [request]() {
            if (request->cancelled.load(std::memory_order_acquire)) {
                invoke_oauth_trigger_callback(request, oauth_status_t::failed,
                    "OAuth flow was cancelled before initialization");
                request->completed.store(true, std::memory_order_release);
                erase_oauth_trigger_request(request);
                return;
            }
            if (!start_auth(request->server_name, *request->state)) {
                std::string error = request->state->error.empty()
                    ? global_last_error_copy() : request->state->error;
                secure_string_scope_t error_guard{error};
                invoke_oauth_trigger_callback(request, oauth_status_t::failed, error);
                request->completed.store(true, std::memory_order_release);
                erase_oauth_trigger_request(request);
                return;
            }
            const auto flow = oauth_flow_from_state(*request->state);
            if (flow) {
                std::lock_guard<std::mutex> lock(flow->mutex);
                const std::uint64_t task_id = request->task_id.load(std::memory_order_acquire);
                flow->initialization_task_id = task_id;
                flow->poll_task_id = task_id;
            }
            for (;;) {
                if (request->cancelled.load(std::memory_order_acquire))
                    request->state->cancelled.store(true, std::memory_order_release);
                const oauth_status_t status = poll_auth(*request->state);
                if (status == oauth_status_t::authenticating) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    continue;
                }
                std::string error;
                if (status != oauth_status_t::authenticated)
                    error = request->state->error.empty()
                        ? global_last_error_copy() : request->state->error;
                secure_string_scope_t error_guard{error};
                invoke_oauth_trigger_callback(request, status, error);
                request->completed.store(true, std::memory_order_release);
                erase_oauth_trigger_request(request);
                return;
            }
        });
    if (!submitted.submitted) {
        const std::string error = submitted.reject_reason.empty()
            ? "failed to schedule OAuth initialization"
            : "failed to schedule OAuth initialization: " + submitted.reject_reason;
        publish_oauth_trigger_failure(request, error);
        invoke_oauth_trigger_callback(request, oauth_status_t::failed, error);
        request->completed.store(true, std::memory_order_release);
        erase_oauth_trigger_request(request);
        set_global_last_error(error);
        return false;
    }
    request->task_id.store(submitted.task_id, std::memory_order_release);
    set_global_last_error({});
    return true;
}

#if defined(AIDA_C03_MCP_OAUTH_FIXTURE)
namespace c03_oauth_fixture
{

static void reap_expired_fixture_flows()
{
    std::vector<std::shared_ptr<oauth_transient_flow_t>> snapshot;
    {
        std::lock_guard<std::mutex> registry_lock(oauth_flow_registry_mutex());
        for (const auto& entry : oauth_flow_registry())
            snapshot.push_back(entry.second);
    }
    const int64_t now = now_unix_seconds();
    for (const auto& flow : snapshot) {
        bool expired = false;
        {
            std::lock_guard<std::mutex> lock(flow->mutex);
            expired = !flow->terminal_ready && flow->deadline_unix != 0
                && now > flow->deadline_unix;
        }
        if (expired)
            (void)finalize_oauth_flow(flow, false, "OAuth flow timed out", {}, true);
    }
}

void reset()
{
    std::vector<std::string> servers;
    {
        std::lock_guard<std::mutex> lock(oauth_trigger_registry_mutex());
        for (const auto& entry : oauth_trigger_registry())
            servers.push_back(entry.first);
    }
    {
        std::lock_guard<std::mutex> lock(oauth_flow_registry_mutex());
        for (const auto& entry : oauth_flow_registry())
            servers.push_back(entry.first);
    }
    std::sort(servers.begin(), servers.end());
    servers.erase(std::unique(servers.begin(), servers.end()), servers.end());
    for (const auto& server : servers)
        (void)cancel_auth(server);

    std::deque<oauth_fixture_task_t> tasks;
    {
        auto& runtime = oauth_fixture_runtime();
        std::lock_guard<std::mutex> lock(runtime.mutex);
        tasks.swap(runtime.tasks);
    }
    for (auto& task : tasks) {
        if (task.cancel)
            task.cancel();
    }
    tasks.clear();

    {
        std::lock_guard<std::mutex> lock(oauth_flow_registry_mutex());
        oauth_flow_registry().clear();
        oauth_flow_generation() = 0;
    }
    {
        std::lock_guard<std::mutex> lock(oauth_trigger_registry_mutex());
        oauth_trigger_registry().clear();
        oauth_trigger_generation() = 0;
    }
    {
        std::lock_guard<std::mutex> lock(oauth_terminal_receipt_mutex());
        oauth_terminal_receipts().clear();
    }
    {
        std::lock_guard<std::mutex> lock(mcp_auth_epoch_mutex());
        mcp_auth_epochs().clear();
    }
    {
        std::lock_guard<std::mutex> lock(mcp_config_incarnation_mutex());
        for (auto& entry : mcp_config_incarnations())
            secure_clear_string(entry.second.fingerprint);
        mcp_config_incarnations().clear();
    }
    {
        auto& runtime = oauth_fixture_runtime();
        std::lock_guard<std::mutex> lock(runtime.mutex);
        for (auto& entry : runtime.configs)
            secure_clear_server_config(entry.second);
        runtime.configs.clear();
        for (auto& entry : runtime.credentials)
            secure_clear_auth_info(entry.second);
        runtime.credentials.clear();
        for (auto& reply : runtime.http_replies) {
            secure_clear_string(reply.body);
            secure_clear_string(reply.error);
            for (auto& header : reply.headers)
                secure_clear_string(header.second);
        }
        runtime.http_replies.clear();
        for (auto& request : runtime.http_requests) {
            secure_clear_string(request.method);
            secure_clear_string(request.url);
            secure_clear_string(request.body);
            for (auto& header : request.headers)
                secure_clear_string(header.second);
            request.headers.clear();
        }
        runtime.http_requests.clear();
        for (auto& event : runtime.events) {
            secure_clear_string(event.server_name);
            secure_clear_string(event.error);
        }
        runtime.events.clear();
        runtime.now_unix = 1700000000;
        runtime.now_ms = 1000;
        runtime.next_task_id = 1;
        runtime.browser_result = true;
        runtime.faults.fill(false);
    }
    oauth_reaper_running().store(false, std::memory_order_release);
    set_global_last_error({});
}

void set_time(int64_t unix_seconds)
{
    {
        auto& runtime = oauth_fixture_runtime();
        std::lock_guard<std::mutex> lock(runtime.mutex);
        runtime.now_unix = unix_seconds;
    }
    reap_expired_fixture_flows();
}

void advance_time(int64_t seconds)
{
    {
        auto& runtime = oauth_fixture_runtime();
        std::lock_guard<std::mutex> lock(runtime.mutex);
        if (seconds > 0) {
            runtime.now_unix = runtime.now_unix <= (std::numeric_limits<int64_t>::max)() - seconds
                ? runtime.now_unix + seconds
                : (std::numeric_limits<int64_t>::max)();
        }
        if (seconds > 0) {
            const std::uint64_t seconds_unsigned = static_cast<std::uint64_t>(seconds);
            if (seconds_unsigned > (std::numeric_limits<std::uint64_t>::max)() / 1000ULL) {
                runtime.now_ms = (std::numeric_limits<std::uint64_t>::max)();
            } else {
                const std::uint64_t delta = seconds_unsigned * 1000ULL;
                runtime.now_ms = runtime.now_ms <= (std::numeric_limits<std::uint64_t>::max)() - delta
                    ? runtime.now_ms + delta
                    : (std::numeric_limits<std::uint64_t>::max)();
            }
        }
    }
    reap_expired_fixture_flows();
}

bool add_server(const server_config_t& config)
{
    if (!valid_mcp_server_name(config.name))
        return false;
    std::string fingerprint;
    secure_string_scope_t fingerprint_guard{fingerprint};
    try {
        fingerprint = server_config_fingerprint(config);
    } catch (...) {
        return false;
    }
    bool changed = false;
    if (fingerprint.empty()
        || !advance_mcp_config_incarnation(config.name, fingerprint, nullptr, &changed))
        return false;
    bool existing_config = false;
    {
        auto& runtime = oauth_fixture_runtime();
        std::lock_guard<std::mutex> lock(runtime.mutex);
        auto it = runtime.configs.find(config.name);
        existing_config = it != runtime.configs.end();
        if (existing_config)
            secure_clear_server_config(it->second);
        runtime.configs[config.name] = config;
    }
    if (changed && existing_config)
        (void)cancel_auth(config.name);
    return true;
}

void set_browser_result(bool result)
{
    std::lock_guard<std::mutex> lock(oauth_fixture_runtime().mutex);
    oauth_fixture_runtime().browser_result = result;
}

void fail_next(fault_point_t point)
{
    const size_t index = static_cast<size_t>(point);
    auto& runtime = oauth_fixture_runtime();
    std::lock_guard<std::mutex> lock(runtime.mutex);
    if (index < runtime.faults.size())
        runtime.faults[index] = true;
}

void queue_http_reply(http_reply_t reply)
{
    std::lock_guard<std::mutex> lock(oauth_fixture_runtime().mutex);
    oauth_fixture_runtime().http_replies.push_back(std::move(reply));
}

std::vector<http_request_t> take_http_requests()
{
    std::vector<http_request_t> requests;
    std::lock_guard<std::mutex> lock(oauth_fixture_runtime().mutex);
    requests.swap(oauth_fixture_runtime().http_requests);
    return requests;
}

size_t run_ready_tasks(size_t maximum)
{
    size_t executed = 0;
    while (executed < maximum) {
        oauth_fixture_task_t task;
        {
            auto& runtime = oauth_fixture_runtime();
            std::lock_guard<std::mutex> lock(runtime.mutex);
            if (runtime.tasks.empty())
                break;
            task = std::move(runtime.tasks.front());
            runtime.tasks.pop_front();
            if (task.deadline_ms != 0 && runtime.now_ms > task.deadline_ms)
                task.cancelled = true;
        }
        if (task.cancelled) {
            if (task.cancel)
                task.cancel();
        } else if (task.body) {
            try {
                task.body();
            } catch (...) {
                if (task.cancel)
                    task.cancel();
            }
        }
        ++executed;
    }
    return executed;
}

size_t pending_task_count()
{
    std::lock_guard<std::mutex> lock(oauth_fixture_runtime().mutex);
    return oauth_fixture_runtime().tasks.size();
}

size_t pending_http_reply_count()
{
    std::lock_guard<std::mutex> lock(oauth_fixture_runtime().mutex);
    return oauth_fixture_runtime().http_replies.size();
}

size_t active_flow_count()
{
    std::lock_guard<std::mutex> lock(oauth_flow_registry_mutex());
    return oauth_flow_registry().size();
}

size_t active_trigger_count()
{
    std::lock_guard<std::mutex> lock(oauth_trigger_registry_mutex());
    return oauth_trigger_registry().size();
}

size_t active_flow_secret_bytes()
{
    size_t bytes = 0;
    std::lock_guard<std::mutex> registry_lock(oauth_flow_registry_mutex());
    for (const auto& entry : oauth_flow_registry()) {
        std::lock_guard<std::mutex> flow_lock(entry.second->mutex);
        bytes += entry.second->state_token.size();
        bytes += entry.second->code_verifier.size();
        bytes += entry.second->client_id.size();
        bytes += entry.second->client_secret.size();
        bytes += entry.second->received_code.size();
        bytes += entry.second->terminal_code_digest.size();
    }
    return bytes;
}

bool get_active_state_token(const std::string& server_name, std::string& state_token)
{
    const auto flow = find_oauth_flow(server_name, nullptr);
    if (!flow)
        return false;
    std::lock_guard<std::mutex> lock(flow->mutex);
    if (flow->phase != oauth_flow_phase_t::active
        || flow->terminal_ready || flow->cancelled || flow->state_token.empty())
        return false;
    state_token = flow->state_token;
    return true;
}

bool deliver_callback(const std::string& server_name,
                      const std::string& state_token,
                      const std::string& code,
                      const std::string& error)
{
    const auto flow = find_oauth_flow(server_name, &state_token);
    if (!flow)
        return false;
    std::uint64_t generation = 0;
    {
        std::lock_guard<std::mutex> lock(flow->mutex);
        generation = flow->generation;
    }
    complete_oauth_callback(flow, generation, code, error);
    std::lock_guard<std::mutex> lock(flow->mutex);
    return flow->callback_done;
}

bool get_credential(const std::string& server_name, credential_t& credential)
{
    aida::auth::auth_info_t info;
    secure_auth_info_scope_t info_guard{info};
    if (!load_mcp_auth(server_name, info))
        return false;
    credential.access = info.access;
    credential.refresh = info.refresh;
    credential.expires_unix = info.expires_unix;
    credential.metadata = info.metadata;
    credential.client_id = info.custom_client_id;
    credential.redirect_uri = info.custom_redirect_uri;
    credential.scopes = info.custom_scopes;
    return true;
}

std::vector<event_t> take_events()
{
    std::vector<event_t> events;
    std::lock_guard<std::mutex> lock(oauth_fixture_runtime().mutex);
    events.swap(oauth_fixture_runtime().events);
    return events;
}

void set_flow_generation(std::uint64_t generation)
{
    std::lock_guard<std::mutex> lock(oauth_flow_registry_mutex());
    oauth_flow_generation() = generation;
}

void set_trigger_generation(std::uint64_t generation)
{
    std::lock_guard<std::mutex> lock(oauth_trigger_registry_mutex());
    oauth_trigger_generation() = generation;
}

void set_auth_epoch(const std::string& server_name, std::uint64_t epoch)
{
    std::lock_guard<std::mutex> lock(mcp_auth_epoch_mutex());
    mcp_auth_epochs()[server_name] = epoch;
}

void set_config_generation(const std::string& server_name, std::uint64_t generation)
{
    std::lock_guard<std::mutex> lock(mcp_config_incarnation_mutex());
    auto it = mcp_config_incarnations().find(server_name);
    if (it != mcp_config_incarnations().end())
        it->second.generation = generation;
}

}
#endif

}
