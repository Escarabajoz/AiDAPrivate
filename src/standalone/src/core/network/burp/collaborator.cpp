#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>

#include "collaborator.hpp"
#include "../executor_status.hpp"
#include "../../infra/executor.hpp"
#include "../../mcp/downstream_producer_governor.hpp"
#include "helpers/diag_log.hpp"

#include "httplib.h"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <nlohmann/json.hpp>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <utility>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")

namespace aida {
namespace burp {
namespace collaborator {

namespace {

struct wsa_guard_t
{
    WSADATA data{};
    bool    ok = false;
    wsa_guard_t() { ok = (WSAStartup(MAKEWORD(2, 2), &data) == 0); }
    ~wsa_guard_t() { if (ok) WSACleanup(); }
};

static wsa_guard_t s_wsa_guard;

struct poll_cursor_state_t
{
    std::string token;
    uint64_t    since_ms = 0;
    uint64_t    after_id = 0;
    uint64_t    updated_ms = 0;
};

struct state_t
{
    std::mutex                                              mtx;
    std::atomic<bool>                                       running{false};
    std::atomic<bool>                                       http_alive{false};
    std::atomic<bool>                                       dns_alive{false};
    std::atomic<bool>                                       smtp_alive{false};
    std::atomic<bool>                                       stop_request{false};

    collaborator_config_t                                   config;
    uint64_t                                                started_ms = 0;

    std::deque<interaction_t>                               interactions;
    std::atomic<uint64_t>                                   next_id{1};

    std::unordered_map<std::string, token_info_t>           tokens;
    std::unordered_map<std::string, poll_cursor_state_t>     poll_cursors;
    std::atomic<bool>                                       durable_loaded{false};
    std::atomic<bool>                                       loading_durable{false};

    std::shared_ptr<httplib::Server>                        http_server;
    SOCKET                                                  http_socket = INVALID_SOCKET;
    std::atomic<bool>                                       http_thread_alive{false};
    std::atomic<DWORD>                                      http_worker_tid{0};
    std::atomic<uint32_t>                                   http_start_state{0};
    std::atomic<uint32_t>                                   http_sessions_active{0};
    std::atomic<uint64_t>                                   worker_generation{0};

    SOCKET                                                  dns_socket = INVALID_SOCKET;
    std::atomic<bool>                                       dns_thread_alive{false};
    std::atomic<DWORD>                                      dns_worker_tid{0};

    SOCKET                                                  smtp_socket = INVALID_SOCKET;
    std::atomic<bool>                                       smtp_thread_alive{false};
    std::atomic<DWORD>                                      smtp_worker_tid{0};
    std::atomic<uint32_t>                                   smtp_sessions_active{0};

    std::mutex                                              worker_mtx;
    std::condition_variable                                 worker_cv;

    std::mutex                                              err_mtx;
    std::string                                             last_err;
};

static state_t g_state;

struct http_session_worker_group_t
{
    std::unique_ptr<mcp_standalone::downstream::feature_worker_group_t> group;
    std::once_flag init_flag;

    void ensure()
    {
        std::call_once(init_flag, [this]() {
            mcp_standalone::downstream::feature_worker_group_config_t cfg;
            cfg.owner_subsystem = "collaborator.http_session";
            cfg.kind = mcp_standalone::downstream::producer_kind_t::burp_network;
            cfg.worker_count = mcp_standalone::downstream::default_quotas().burp_network_worker_group_size;
            cfg.queue_depth = mcp_standalone::downstream::default_quotas().burp_network_queue_depth;
            cfg.label_prefix = "collab.http_session";
            cfg.default_timeout_ms = 30000;
            group = std::make_unique<mcp_standalone::downstream::feature_worker_group_t>(cfg);
        });
    }

    void shutdown()
    {
        if (group) {
            group->shutdown();
            group.reset();
        }
    }
};

static http_session_worker_group_t s_http_session_wg;

static uint64_t now_ms();

static void mark_worker_started(std::atomic<bool>& alive, std::atomic<DWORD>& tid)
{
    {
        std::lock_guard<std::mutex> lk(g_state.worker_mtx);
        tid.store(GetCurrentThreadId(), std::memory_order_release);
        alive.store(true, std::memory_order_release);
    }
    g_state.worker_cv.notify_all();
}

static void mark_worker_stopped(std::atomic<bool>& alive, std::atomic<DWORD>& tid)
{
    {
        std::lock_guard<std::mutex> lk(g_state.worker_mtx);
        alive.store(false, std::memory_order_release);
        tid.store(0, std::memory_order_release);
    }
    g_state.worker_cv.notify_all();
}

struct worker_lifetime_t
{
    std::atomic<bool>&  alive;
    std::atomic<DWORD>& tid;

    worker_lifetime_t(std::atomic<bool>& alive_ref, std::atomic<DWORD>& tid_ref)
        : alive(alive_ref), tid(tid_ref)
    {
        mark_worker_started(alive, tid);
    }

    ~worker_lifetime_t()
    {
        mark_worker_stopped(alive, tid);
    }
};

struct active_session_t
{
    std::atomic<uint32_t>& counter;
    const char*            tag;
    std::string            client;
    uint16_t               port;
    uint64_t               started;

    active_session_t(std::atomic<uint32_t>& counter_ref, const char* tag_ref, std::string client_ref, uint16_t port_ref)
        : counter(counter_ref), tag(tag_ref), client(std::move(client_ref)), port(port_ref), started(0)
    {
        started = now_ms();
        uint32_t active = counter.fetch_add(1, std::memory_order_acq_rel) + 1;
        ::diag::log_tagged_fmt("collaborator", "%s_enter client=%s:%u active=%u pid=%lu tid=%lu",
            tag,
            client.c_str(),
            static_cast<unsigned>(port),
            active,
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()));
    }

    ~active_session_t()
    {
        uint32_t active = counter.fetch_sub(1, std::memory_order_acq_rel) - 1;
        ::diag::log_tagged_fmt("collaborator", "%s_exit client=%s:%u active=%u elapsed_ms=%llu",
            tag,
            client.c_str(),
            static_cast<unsigned>(port),
            active,
            static_cast<unsigned long long>(now_ms() - started));
        g_state.worker_cv.notify_all();
    }
};

static void set_last_error(const std::string& msg)
{
    std::lock_guard<std::mutex> lk(g_state.err_mtx);
    g_state.last_err = msg;
}

static uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

using json = nlohmann::json;

static std::string wide_to_utf8(const std::wstring& text)
{
    if (text.empty()) return {};
    int needed = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string out(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), out.data(), needed, nullptr, nullptr);
    return out;
}

static std::filesystem::path default_state_path_fs()
{
    wchar_t buf[32768] = {};
    const DWORD buf_count = static_cast<DWORD>(sizeof(buf) / sizeof(buf[0]));
    DWORD len = GetEnvironmentVariableW(L"APPDATA", buf, buf_count);
    std::filesystem::path base;
    if (len > 0 && len < buf_count) {
        base = std::filesystem::path(std::wstring(buf, buf + len));
    } else {
        base = std::filesystem::current_path();
    }
    return base / L"AiDA" / L"Standalone" / L"burp" / L"collaborator_state.json";
}

static std::string path_to_utf8(const std::filesystem::path& path)
{
    return wide_to_utf8(path.wstring());
}

static std::string lower_ascii(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (char c : s) out.push_back(static_cast<char>(::tolower(static_cast<unsigned char>(c))));
    return out;
}

static std::string trim_ascii(const std::string& s)
{
    size_t a = 0;
    while (a < s.size() && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) ++a;
    size_t b = s.size();
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) --b;
    return s.substr(a, b - a);
}

static std::string hex_encode(const uint8_t* data, size_t len)
{
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out[i * 2] = kHex[(data[i] >> 4) & 0x0f];
        out[i * 2 + 1] = kHex[data[i] & 0x0f];
    }
    return out;
}

static bool hmac_sha256_hex(const std::string& secret, const std::string& body, std::string& out)
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD object_len = 0;
    DWORD hash_len = 0;
    DWORD got = 0;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) < 0)
        return false;
    bool ok = false;
    do {
        if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_len), sizeof(object_len), &got, 0) < 0) break;
        if (BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_len), sizeof(hash_len), &got, 0) < 0) break;
        std::vector<uint8_t> object(object_len);
        std::vector<uint8_t> digest(hash_len);
        if (secret.size() > static_cast<size_t>(ULONG_MAX) || body.size() > static_cast<size_t>(ULONG_MAX)) break;
        if (BCryptCreateHash(alg, &hash, object.data(), object_len,
                             reinterpret_cast<PUCHAR>(const_cast<char*>(secret.data())),
                             static_cast<ULONG>(secret.size()), 0) < 0) break;
        if (BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<char*>(body.data())),
                           static_cast<ULONG>(body.size()), 0) < 0) break;
        if (BCryptFinishHash(hash, digest.data(), hash_len, 0) < 0) break;
        out = hex_encode(digest.data(), digest.size());
        ok = true;
    } while (false);
    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

struct parsed_webhook_url_t
{
    std::string scheme;
    std::string host;
    std::string origin;
    std::string path;
    uint16_t    port = 0;
};

static bool parse_webhook_url(const std::string& url, parsed_webhook_url_t& out)
{
    const std::string u = trim_ascii(url);
    const size_t scheme_pos = u.find("://");
    if (scheme_pos == std::string::npos)
        return false;
    parsed_webhook_url_t parsed;
    parsed.scheme = lower_ascii(u.substr(0, scheme_pos));
    if (parsed.scheme != "http" && parsed.scheme != "https")
        return false;
    const size_t authority_start = scheme_pos + 3;
    const size_t path_start = u.find_first_of("/?#", authority_start);
    const std::string authority = u.substr(authority_start, path_start == std::string::npos ? std::string::npos : path_start - authority_start);
    if (authority.empty() || authority.find('@') != std::string::npos)
        return false;
    const bool https = parsed.scheme == "https";
    if (authority.size() > 2 && authority.front() == '[') {
        const size_t close = authority.find(']');
        if (close == std::string::npos)
            return false;
        parsed.host = authority.substr(1, close - 1);
        parsed.port = https ? 443 : 80;
        if (close + 1 < authority.size()) {
            if (authority[close + 1] != ':')
                return false;
            const std::string ps = authority.substr(close + 2);
            if (ps.empty()) return false;
            int v = 0;
            for (char c : ps) {
                if (c < '0' || c > '9') return false;
                v = v * 10 + (c - '0');
                if (v > 65535) return false;
            }
            if (v <= 0) return false;
            parsed.port = static_cast<uint16_t>(v);
        }
        parsed.origin = parsed.scheme + "://[" + parsed.host + "]";
    } else {
        const size_t colon = authority.rfind(':');
        parsed.host = colon == std::string::npos ? authority : authority.substr(0, colon);
        if (parsed.host.empty())
            return false;
        parsed.port = https ? 443 : 80;
        if (colon != std::string::npos) {
            const std::string ps = authority.substr(colon + 1);
            if (ps.empty()) return false;
            int v = 0;
            for (char c : ps) {
                if (c < '0' || c > '9') return false;
                v = v * 10 + (c - '0');
                if (v > 65535) return false;
            }
            if (v <= 0) return false;
            parsed.port = static_cast<uint16_t>(v);
        }
        parsed.origin = parsed.scheme + "://" + parsed.host;
    }
    if ((https && parsed.port != 443) || (!https && parsed.port != 80))
        parsed.origin += ":" + std::to_string(parsed.port);
    if (path_start == std::string::npos) {
        parsed.path = "/";
    } else if (u[path_start] == '/') {
        parsed.path = u.substr(path_start);
    } else if (u[path_start] == '?') {
        parsed.path = "/" + u.substr(path_start);
    } else {
        parsed.path = "/";
    }
    const size_t fragment = parsed.path.find('#');
    if (fragment != std::string::npos)
        parsed.path.erase(fragment);
    if (parsed.path.empty())
        parsed.path = "/";
    out = std::move(parsed);
    return true;
}

static json config_to_json(const collaborator_config_t& cfg)
{
    return json{
        {"bind_ip", cfg.bind_ip},
        {"http_port", cfg.http_port},
        {"dns_port", cfg.dns_port},
        {"smtp_port", cfg.smtp_port},
        {"smtps_port", cfg.smtps_port},
        {"ldap_port", cfg.ldap_port},
        {"enable_http", cfg.enable_http},
        {"enable_dns", cfg.enable_dns},
        {"enable_smtp", cfg.enable_smtp},
        {"public_host", cfg.public_host},
        {"public_ip", cfg.public_ip},
        {"canned_body", cfg.canned_body},
        {"canned_content_type", cfg.canned_content_type},
        {"max_interactions", cfg.max_interactions},
        {"smtp_max_message", cfg.smtp_max_message}
    };
}

static bool config_from_json(const json& j, collaborator_config_t& cfg)
{
    if (!j.is_object()) return false;
    if (j.contains("bind_ip") && j["bind_ip"].is_string()) cfg.bind_ip = j["bind_ip"].get<std::string>();
    if (j.contains("http_port") && j["http_port"].is_number_unsigned()) cfg.http_port = static_cast<uint16_t>((std::min)(j["http_port"].get<unsigned>(), 65535u));
    if (j.contains("dns_port") && j["dns_port"].is_number_unsigned()) cfg.dns_port = static_cast<uint16_t>((std::min)(j["dns_port"].get<unsigned>(), 65535u));
    if (j.contains("smtp_port") && j["smtp_port"].is_number_unsigned()) cfg.smtp_port = static_cast<uint16_t>((std::min)(j["smtp_port"].get<unsigned>(), 65535u));
    if (j.contains("smtps_port") && j["smtps_port"].is_number_unsigned()) cfg.smtps_port = static_cast<uint16_t>((std::min)(j["smtps_port"].get<unsigned>(), 65535u));
    if (j.contains("ldap_port") && j["ldap_port"].is_number_unsigned()) cfg.ldap_port = static_cast<uint16_t>((std::min)(j["ldap_port"].get<unsigned>(), 65535u));
    if (j.contains("enable_http") && j["enable_http"].is_boolean()) cfg.enable_http = j["enable_http"].get<bool>();
    if (j.contains("enable_dns") && j["enable_dns"].is_boolean()) cfg.enable_dns = j["enable_dns"].get<bool>();
    if (j.contains("enable_smtp") && j["enable_smtp"].is_boolean()) cfg.enable_smtp = j["enable_smtp"].get<bool>();
    if (j.contains("public_host") && j["public_host"].is_string()) cfg.public_host = j["public_host"].get<std::string>();
    if (j.contains("public_ip") && j["public_ip"].is_string()) cfg.public_ip = j["public_ip"].get<std::string>();
    if (j.contains("canned_body") && j["canned_body"].is_string()) cfg.canned_body = j["canned_body"].get<std::string>();
    if (j.contains("canned_content_type") && j["canned_content_type"].is_string()) cfg.canned_content_type = j["canned_content_type"].get<std::string>();
    if (j.contains("max_interactions") && j["max_interactions"].is_number_unsigned()) cfg.max_interactions = (std::min)(j["max_interactions"].get<size_t>(), static_cast<size_t>(1048576));
    if (j.contains("smtp_max_message") && j["smtp_max_message"].is_number_integer()) cfg.smtp_max_message = (std::max)(1, j["smtp_max_message"].get<int>());
    return true;
}

static json interaction_to_json_locked(const interaction_t& it)
{
    json details = json::object();
    for (const auto& kv : it.details) details[kv.first] = kv.second;
    return json{
        {"id", it.id},
        {"timestamp_ms", it.timestamp_ms},
        {"kind", it.kind},
        {"client_ip", it.client_ip},
        {"client_port", it.client_port},
        {"subdomain", it.subdomain},
        {"raw", it.raw},
        {"details", std::move(details)},
        {"payload_token", it.payload_token}
    };
}

static bool interaction_from_json(const json& j, interaction_t& it)
{
    if (!j.is_object()) return false;
    interaction_t parsed;
    parsed.id = j.value("id", static_cast<uint64_t>(0));
    parsed.timestamp_ms = j.value("timestamp_ms", static_cast<uint64_t>(0));
    parsed.kind = j.value("kind", std::string());
    parsed.client_ip = j.value("client_ip", std::string());
    parsed.client_port = static_cast<uint16_t>((std::min)(j.value("client_port", 0), 65535));
    parsed.subdomain = j.value("subdomain", std::string());
    parsed.raw = j.value("raw", std::string());
    parsed.payload_token = lower_ascii(j.value("payload_token", std::string()));
    const json details = j.value("details", json::object());
    if (details.is_object()) {
        for (auto iter = details.begin(); iter != details.end(); ++iter) {
            if (iter.value().is_string()) parsed.details[iter.key()] = iter.value().get<std::string>();
            else parsed.details[iter.key()] = iter.value().dump();
        }
    }
    if (parsed.id == 0 || parsed.kind.empty()) return false;
    it = std::move(parsed);
    return true;
}

static json token_to_json(const token_info_t& t)
{
    return json{
        {"token", t.token},
        {"full_domain", t.full_domain},
        {"issued_ms", t.issued_ms},
        {"last_seen_ms", t.last_seen_ms},
        {"interaction_count", t.interaction_count}
    };
}

static bool token_from_json(const json& j, token_info_t& t)
{
    if (!j.is_object()) return false;
    token_info_t parsed;
    parsed.token = lower_ascii(j.value("token", std::string()));
    parsed.full_domain = j.value("full_domain", std::string());
    parsed.issued_ms = j.value("issued_ms", static_cast<uint64_t>(0));
    parsed.last_seen_ms = j.value("last_seen_ms", static_cast<uint64_t>(0));
    parsed.interaction_count = j.value("interaction_count", static_cast<size_t>(0));
    if (parsed.token.empty()) return false;
    t = std::move(parsed);
    return true;
}

static json cursor_to_json(const std::string& id, const poll_cursor_state_t& c)
{
    return json{
        {"cursor", id},
        {"token", c.token},
        {"since_ms", c.since_ms},
        {"after_id", c.after_id},
        {"updated_ms", c.updated_ms}
    };
}

static bool cursor_from_json(const json& j, std::string& id, poll_cursor_state_t& c)
{
    if (!j.is_object()) return false;
    id = j.value("cursor", std::string());
    if (id.size() < 8 || id.size() > 96) return false;
    c.token = lower_ascii(j.value("token", std::string()));
    c.since_ms = j.value("since_ms", static_cast<uint64_t>(0));
    c.after_id = j.value("after_id", static_cast<uint64_t>(0));
    c.updated_ms = j.value("updated_ms", static_cast<uint64_t>(0));
    return true;
}

static json capabilities_json()
{
    return json{
        {"supported_transports", json::array({"http", "dns", "smtp"})},
        {"unsupported_transports", json::array({"smtps", "ldap"})},
        {"smtps_supported", false},
        {"ldap_supported", false},
        {"webhook_delivery_supported", true},
        {"webhook_signing_supported", true},
        {"file_export_supported", true},
        {"async_polling_supported", true},
        {"durable_state_supported", true}
    };
}

static json snapshot_json_locked()
{
    json root;
    root["version"] = 2;
    root["saved_ms"] = now_ms();
    root["config"] = config_to_json(g_state.config);
    root["started_ms"] = g_state.started_ms;
    root["next_id"] = g_state.next_id.load(std::memory_order_acquire);
    root["capabilities"] = capabilities_json();
    root["tokens"] = json::array();
    for (const auto& kv : g_state.tokens) root["tokens"].push_back(token_to_json(kv.second));
    root["interactions"] = json::array();
    for (const auto& it : g_state.interactions) root["interactions"].push_back(interaction_to_json_locked(it));
    root["poll_cursors"] = json::array();
    for (const auto& kv : g_state.poll_cursors) root["poll_cursors"].push_back(cursor_to_json(kv.first, kv.second));
    return root;
}

static void recompute_token_counts_locked()
{
    for (auto& kv : g_state.tokens) {
        kv.second.interaction_count = 0;
        kv.second.last_seen_ms = 0;
    }
    for (const auto& it : g_state.interactions) {
        if (it.payload_token.empty()) continue;
        auto found = g_state.tokens.find(it.payload_token);
        if (found == g_state.tokens.end()) continue;
        found->second.interaction_count++;
        found->second.last_seen_ms = (std::max)(found->second.last_seen_ms, it.timestamp_ms);
    }
}

static bool import_json_locked(const json& doc, bool replace_existing)
{
    if (!doc.is_object() || doc.value("version", 0) < 1) {
        set_last_error("collaborator.import: invalid schema");
        return false;
    }
    if (replace_existing) {
        g_state.interactions.clear();
        g_state.tokens.clear();
        g_state.poll_cursors.clear();
        g_state.next_id.store(1, std::memory_order_release);
    }
    const bool running = g_state.running.load(std::memory_order_acquire);
    if (!running && doc.contains("config")) {
        collaborator_config_t cfg = g_state.config;
        if (config_from_json(doc["config"], cfg))
            g_state.config = cfg;
    }
    uint64_t max_id = 0;
    if (doc.contains("tokens") && doc["tokens"].is_array()) {
        for (const auto& jt : doc["tokens"]) {
            token_info_t token;
            if (token_from_json(jt, token))
                g_state.tokens[token.token] = std::move(token);
        }
    }
    if (doc.contains("interactions") && doc["interactions"].is_array()) {
        for (const auto& ji : doc["interactions"]) {
            interaction_t it;
            if (!interaction_from_json(ji, it)) continue;
            max_id = (std::max)(max_id, it.id);
            auto existing = std::find_if(g_state.interactions.begin(), g_state.interactions.end(), [&](const interaction_t& cur) {
                return cur.id == it.id;
            });
            if (existing == g_state.interactions.end())
                g_state.interactions.push_back(std::move(it));
            else
                *existing = std::move(it);
        }
        std::sort(g_state.interactions.begin(), g_state.interactions.end(), [](const interaction_t& a, const interaction_t& b) {
            return a.id < b.id;
        });
        while (g_state.interactions.size() > g_state.config.max_interactions)
            g_state.interactions.pop_front();
    }
    if (doc.contains("poll_cursors") && doc["poll_cursors"].is_array()) {
        for (const auto& jc : doc["poll_cursors"]) {
            std::string id;
            poll_cursor_state_t c;
            if (cursor_from_json(jc, id, c))
                g_state.poll_cursors[id] = std::move(c);
        }
    }
    const uint64_t stored_next = doc.value("next_id", static_cast<uint64_t>(0));
    g_state.next_id.store((std::max)(stored_next, max_id + 1), std::memory_order_release);
    recompute_token_counts_locked();
    set_last_error("");
    return true;
}

static bool write_json_atomic(const std::filesystem::path& path, const json& doc)
{
    std::error_code ec;
    if (!path.parent_path().empty())
        std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) {
        set_last_error("collaborator.save: create parent failed: " + ec.message());
        return false;
    }
    const std::filesystem::path tmp(path.wstring() + L".tmp");
    const std::string dump = doc.dump(2);
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            set_last_error("collaborator.save: open failed");
            return false;
        }
        out.write(dump.data(), static_cast<std::streamsize>(dump.size()));
        if (!out) {
            set_last_error("collaborator.save: write failed");
            return false;
        }
    }
    std::filesystem::rename(tmp, path, ec);
    if (ec) {
        std::filesystem::remove(path, ec);
        ec.clear();
        std::filesystem::rename(tmp, path, ec);
    }
    if (ec) {
        set_last_error("collaborator.save: replace failed: " + ec.message());
        return false;
    }
    return true;
}

static bool read_json_file(const std::filesystem::path& path, json& out)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        set_last_error("collaborator.load: open failed");
        return false;
    }
    std::stringstream ss;
    ss << in.rdbuf();
    out = json::parse(ss.str(), nullptr, false);
    if (out.is_discarded()) {
        set_last_error("collaborator.load: parse failed");
        return false;
    }
    return true;
}

static bool save_default_state_unlocked()
{
    if (g_state.loading_durable.load(std::memory_order_acquire)) return true;
    json snap;
    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        snap = snapshot_json_locked();
    }
    return write_json_atomic(default_state_path_fs(), snap);
}

static void ensure_loaded()
{
    bool should_load = false;
    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        should_load = !g_state.durable_loaded.load(std::memory_order_acquire);
        if (should_load) {
            g_state.durable_loaded.store(true, std::memory_order_release);
            g_state.loading_durable.store(true, std::memory_order_release);
        }
    }
    if (!should_load) return;
    const auto path = default_state_path_fs();
    std::error_code ec;
    if (std::filesystem::exists(path, ec)) {
        json doc;
        if (read_json_file(path, doc)) {
            std::lock_guard<std::mutex> lk(g_state.mtx);
            import_json_locked(doc, false);
        }
    }
    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        g_state.loading_durable.store(false, std::memory_order_release);
    }
}

static bool is_lower_alpha(char c) { return c >= 'a' && c <= 'z'; }

static std::string strip_port_from_host(const std::string& host)
{
    if (host.empty()) return host;
    if (host[0] == '[') {
        size_t end = host.find(']');
        if (end != std::string::npos) return host.substr(1, end - 1);
        return host;
    }
    size_t colon = host.find(':');
    if (colon == std::string::npos) return host;
    return host.substr(0, colon);
}

static std::string extract_token_from_label(const std::string& label)
{
    std::string lower = lower_ascii(label);
    if (lower.size() < 8 || lower.size() > 64) return {};
    for (char c : lower) {
        if (!is_lower_alpha(c)) return {};
    }
    return lower;
}

static std::string extract_token_from_host(const std::string& host, const std::string& public_host)
{
    std::string h = lower_ascii(strip_port_from_host(host));
    std::string p = lower_ascii(public_host);
    if (!p.empty()) {
        if (h.size() > p.size() + 1) {
            size_t pos = h.size() - p.size();
            if (h.compare(pos, p.size(), p) == 0 && h[pos - 1] == '.') {
                std::string sub = h.substr(0, pos - 1);
                size_t dot = sub.rfind('.');
                std::string leaf = (dot == std::string::npos) ? sub : sub.substr(dot + 1);
                return extract_token_from_label(leaf);
            }
        }
    }
    size_t first_dot = h.find('.');
    std::string leaf = (first_dot == std::string::npos) ? h : h.substr(0, first_dot);
    return extract_token_from_label(leaf);
}

static std::string extract_token_from_qname(const std::string& qname, const std::string& public_host)
{
    return extract_token_from_host(qname, public_host);
}

static std::string extract_token_from_path(const std::string& path)
{
    size_t start = 0;
    if (!path.empty() && path[0] == '/') start = 1;
    size_t end = path.find('/', start);
    if (end == std::string::npos) end = path.find('?', start);
    if (end == std::string::npos) end = path.size();
    if (end <= start) return {};
    std::string seg = path.substr(start, end - start);
    return extract_token_from_label(seg);
}

static void append_interaction(interaction_t&& it)
{
    ensure_loaded();
    bool persist = true;
    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        persist = !g_state.loading_durable.load(std::memory_order_acquire);
        if (it.id == 0) it.id = g_state.next_id.fetch_add(1);
        if (it.timestamp_ms == 0) it.timestamp_ms = now_ms();

        if (!it.payload_token.empty()) {
            auto found = g_state.tokens.find(it.payload_token);
            if (found != g_state.tokens.end()) {
                found->second.interaction_count++;
                found->second.last_seen_ms = it.timestamp_ms;
            }
        }

        g_state.interactions.push_back(std::move(it));
        while (g_state.interactions.size() > g_state.config.max_interactions) {
            g_state.interactions.pop_front();
        }
    }
    g_state.worker_cv.notify_all();
    if (persist)
        save_default_state_unlocked();
}

static std::string client_ip_to_string(uint32_t ip_be)
{
    char buf[INET_ADDRSTRLEN] = {};
    in_addr a{};
    a.s_addr = ip_be;
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return std::string(buf);
}

static std::string make_raw_http(const httplib::Request& req)
{
    std::string raw;
    raw.reserve(512 + req.body.size());
    raw += req.method;
    raw += ' ';
    raw += req.path;
    if (!req.params.empty()) {
        raw += '?';
        bool first = true;
        for (const auto& kv : req.params) {
            if (!first) raw += '&';
            raw += kv.first;
            raw += '=';
            raw += kv.second;
            first = false;
        }
    }
    raw += ' ';
    raw += "HTTP/1.1\r\n";
    for (const auto& kv : req.headers) {
        raw += kv.first;
        raw += ": ";
        raw += kv.second;
        raw += "\r\n";
    }
    raw += "\r\n";
    raw += req.body;
    return raw;
}

static void on_http_request(const httplib::Request& req, httplib::Response& res)
{
    collaborator_config_t cfg_snapshot;
    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        cfg_snapshot = g_state.config;
    }

    interaction_t it;
    it.kind = "http";
    it.client_ip = req.remote_addr;
    it.client_port = (req.remote_port < 0 || req.remote_port > 65535) ? 0 : static_cast<uint16_t>(req.remote_port);
    it.timestamp_ms = now_ms();

    std::string host_hdr;
    auto host_it = req.headers.find("Host");
    if (host_it != req.headers.end()) host_hdr = host_it->second;
    it.subdomain = strip_port_from_host(host_hdr);

    std::string token = extract_token_from_host(host_hdr, cfg_snapshot.public_host);
    if (token.empty()) token = extract_token_from_path(req.path);
    it.payload_token = token;

    it.raw = make_raw_http(req);

    it.details["method"]   = req.method;
    it.details["path"]     = req.path;
    it.details["body"]     = req.body;
    it.details["host"]     = host_hdr;
    if (!req.params.empty()) {
        std::string q;
        bool first = true;
        for (const auto& kv : req.params) {
            if (!first) q += '&';
            q += kv.first; q += '='; q += kv.second;
            first = false;
        }
        it.details["query"] = q;
    }
    auto ua_it = req.headers.find("User-Agent");
    if (ua_it != req.headers.end()) it.details["user_agent"] = ua_it->second;
    auto ref_it = req.headers.find("Referer");
    if (ref_it != req.headers.end()) it.details["referer"] = ref_it->second;
    auto auth_it = req.headers.find("Authorization");
    if (auth_it != req.headers.end()) it.details["authorization"] = auth_it->second;

    ::diag::log_tagged_fmt("collaborator",
        "http_interaction client=%s:%u host='%s' method='%s' path='%s' token='%s' body_size=%zu",
        it.client_ip.c_str(), it.client_port,
        host_hdr.c_str(), req.method.c_str(), req.path.c_str(),
        it.payload_token.c_str(), req.body.size());

    append_interaction(std::move(it));

    if (!cfg_snapshot.canned_body.empty()) {
        res.set_content(cfg_snapshot.canned_body, cfg_snapshot.canned_content_type);
    } else {
        res.status = 200;
        res.set_content("", "text/plain");
    }
    res.set_header("Server", "AiDA-Collaborator/1.0");
}

static bool parse_http_content_length(const std::string& headers, size_t& content_length)
{
    content_length = 0;
    size_t pos = 0;
    while (pos < headers.size()) {
        size_t eol = headers.find("\r\n", pos);
        if (eol == std::string::npos)
            eol = headers.size();
        std::string line = headers.substr(pos, eol - pos);
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = lower_ascii(trim_ascii(line.substr(0, colon)));
            if (key == "content-length") {
                std::string val = trim_ascii(line.substr(colon + 1));
                char* end = nullptr;
                unsigned long long parsed = std::strtoull(val.c_str(), &end, 10);
                if (end && *end == '\0') {
                    content_length = static_cast<size_t>(parsed);
                    return true;
                }
            }
        }
        if (eol == headers.size())
            break;
        pos = eol + 2;
    }
    return false;
}

static void send_http_response(SOCKET s, const std::string& body, const std::string& content_type)
{
    std::string response;
    response.reserve(body.size() + 256);
    response += "HTTP/1.1 200 OK\r\n";
    response += "Server: AiDA-Collaborator/1.0\r\n";
    response += "Content-Type: ";
    response += content_type.empty() ? "text/plain" : content_type;
    response += "\r\nContent-Length: ";
    response += std::to_string(body.size());
    response += "\r\nConnection: close\r\n\r\n";
    response += body;
    const char* data = response.data();
    size_t left = response.size();
    while (left != 0) {
        int n = send(s, data, static_cast<int>(std::min<size_t>(left, 16384)), 0);
        if (n <= 0)
            break;
        data += n;
        left -= static_cast<size_t>(n);
    }
}

static void on_raw_http_request(const std::string& raw, const std::string& client_ip, uint16_t client_port, SOCKET client_sock)
{
    collaborator_config_t cfg_snapshot;
    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        cfg_snapshot = g_state.config;
    }

    const size_t header_end = raw.find("\r\n\r\n");
    const std::string header_block = header_end == std::string::npos ? raw : raw.substr(0, header_end);
    const std::string body = header_end == std::string::npos ? std::string() : raw.substr(header_end + 4);

    std::istringstream stream(header_block);
    std::string request_line;
    std::getline(stream, request_line);
    if (!request_line.empty() && request_line.back() == '\r')
        request_line.pop_back();

    std::istringstream request_line_stream(request_line);
    std::string method;
    std::string target;
    std::string version;
    request_line_stream >> method >> target >> version;

    std::unordered_map<std::string, std::string> headers;
    std::string line;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty())
            break;
        size_t colon = line.find(':');
        if (colon == std::string::npos)
            continue;
        headers[lower_ascii(trim_ascii(line.substr(0, colon)))] = trim_ascii(line.substr(colon + 1));
    }

    std::string path = target.empty() ? "/" : target;
    std::string query;
    size_t qpos = path.find('?');
    if (qpos != std::string::npos) {
        query = path.substr(qpos + 1);
        path = path.substr(0, qpos);
    }

    std::string host_hdr;
    auto host_it = headers.find("host");
    if (host_it != headers.end())
        host_hdr = host_it->second;

    interaction_t it;
    it.kind = "http";
    it.client_ip = client_ip;
    it.client_port = client_port;
    it.timestamp_ms = now_ms();
    it.subdomain = strip_port_from_host(host_hdr);
    std::string token = extract_token_from_host(host_hdr, cfg_snapshot.public_host);
    if (token.empty())
        token = extract_token_from_path(path);
    it.payload_token = token;
    it.raw = raw;
    it.details["method"] = method;
    it.details["path"] = path;
    it.details["body"] = body;
    it.details["host"] = host_hdr;
    if (!query.empty())
        it.details["query"] = query;
    auto ua_it = headers.find("user-agent");
    if (ua_it != headers.end())
        it.details["user_agent"] = ua_it->second;
    auto ref_it = headers.find("referer");
    if (ref_it != headers.end())
        it.details["referer"] = ref_it->second;
    auto auth_it = headers.find("authorization");
    if (auth_it != headers.end())
        it.details["authorization"] = auth_it->second;

    ::diag::log_tagged_fmt("collaborator",
        "raw_http_interaction client=%s:%u host='%s' method='%s' path='%s' token='%s' body_size=%zu",
        it.client_ip.c_str(), it.client_port, host_hdr.c_str(), method.c_str(), path.c_str(),
        it.payload_token.c_str(), body.size());

    append_interaction(std::move(it));

    send_http_response(client_sock, cfg_snapshot.canned_body, cfg_snapshot.canned_content_type);
}

static void raw_http_session(SOCKET client_sock, std::string client_ip, uint16_t client_port)
{
    DWORD timeout = 1500;
    setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));

    std::string request;
    request.reserve(4096);
    size_t content_length = 0;
    bool have_content_length = false;
    constexpr size_t max_request_bytes = 64u * 1024u * 1024u;
    char buf[4096];
    while (request.size() < max_request_bytes) {
        int n = recv(client_sock, buf, sizeof(buf), 0);
        if (n <= 0)
            break;
        request.append(buf, buf + n);
        size_t header_end = request.find("\r\n\r\n");
        if (header_end != std::string::npos) {
            if (!have_content_length) {
                have_content_length = parse_http_content_length(request.substr(0, header_end), content_length);
            }
            const size_t body_have = request.size() - (header_end + 4);
            if (!have_content_length || body_have >= content_length)
                break;
        }
    }
    if (!request.empty()) {
        on_raw_http_request(request, client_ip, client_port, client_sock);
    }
    closesocket(client_sock);
}

static SOCKET open_http_listener(const std::string& bind_ip, uint16_t port, uint64_t start_ms)
{
    ::diag::log_tagged_fmt("collaborator", "http_listener_open_entry bind=%s:%u pid=%lu tid=%lu",
        bind_ip.c_str(),
        static_cast<unsigned>(port),
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()));

    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) {
        ::diag::log_tagged_fmt("collaborator", "http_socket_create_failed err=%d", WSAGetLastError());
        return INVALID_SOCKET;
    }

    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, bind_ip.c_str(), &bind_addr.sin_addr) != 1)
        bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    bool bound = bind(listen_sock, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) != SOCKET_ERROR;
    const int bind_err = bound ? 0 : WSAGetLastError();
    if (!bound) {
        ::diag::log_tagged_fmt("collaborator", "http_bind_failed bind=%s:%u err=%d elapsed_ms=%llu",
            bind_ip.c_str(), static_cast<unsigned>(port), bind_err,
            static_cast<unsigned long long>(now_ms() - start_ms));
        closesocket(listen_sock);
        return INVALID_SOCKET;
    }

    bool listen_ok = listen(listen_sock, 32) != SOCKET_ERROR;
    const int listen_err = listen_ok ? 0 : WSAGetLastError();
    if (!listen_ok) {
        ::diag::log_tagged_fmt("collaborator", "http_listen_failed bind=%s:%u err=%d elapsed_ms=%llu",
            bind_ip.c_str(), static_cast<unsigned>(port), listen_err,
            static_cast<unsigned long long>(now_ms() - start_ms));
        closesocket(listen_sock);
        return INVALID_SOCKET;
    }

    ::diag::log_tagged_fmt("collaborator", "http_listener_ready bind=%s:%u elapsed_ms=%llu",
        bind_ip.c_str(), static_cast<unsigned>(port),
        static_cast<unsigned long long>(now_ms() - start_ms));
    return listen_sock;
}

static void http_thread_main(std::string bind_ip, uint16_t port, uint64_t generation, uint64_t post_ms)
{
    const uint64_t start_ms = now_ms();
    worker_lifetime_t worker(g_state.http_thread_alive, g_state.http_worker_tid);
    ::diag::log_tagged_fmt("collaborator", "http_thread_accept_entry mode=queue bind=%s:%u generation=%llu queued_ms=%llu pid=%lu tid=%lu",
        bind_ip.c_str(),
        static_cast<unsigned>(port),
        static_cast<unsigned long long>(generation),
        static_cast<unsigned long long>(start_ms >= post_ms ? start_ms - post_ms : 0),
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()));

    bool current_generation = generation == g_state.worker_generation.load(std::memory_order_acquire);
    if (!current_generation || g_state.stop_request.load(std::memory_order_acquire)) {
        g_state.http_alive.store(false);
        if (current_generation) {
            g_state.http_start_state.store(3u, std::memory_order_release);
            g_state.worker_cv.notify_all();
        }
        ::diag::log_tagged_fmt("collaborator", "http_thread_exit_before_open bind=%s:%u generation=%llu current_generation=%llu elapsed_ms=%llu stop_request=%d",
            bind_ip.c_str(),
            static_cast<unsigned>(port),
            static_cast<unsigned long long>(generation),
            static_cast<unsigned long long>(g_state.worker_generation.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(now_ms() - start_ms),
            g_state.stop_request.load(std::memory_order_acquire) ? 1 : 0);
        return;
    }

    g_state.http_start_state.store(1u, std::memory_order_release);
    g_state.worker_cv.notify_all();

    const uint64_t listener_start_ms = now_ms();
    SOCKET listen_sock = open_http_listener(bind_ip, port, listener_start_ms);
    const uint64_t listener_ready_ms = now_ms() - listener_start_ms;
    if (listen_sock == INVALID_SOCKET) {
        g_state.http_alive.store(false);
        current_generation = generation == g_state.worker_generation.load(std::memory_order_acquire);
        if (current_generation) {
            g_state.http_start_state.store(3u, std::memory_order_release);
            g_state.worker_cv.notify_all();
        }
        if (current_generation)
            set_last_error("http_listener_open_failed");
        ::diag::log_tagged_fmt("collaborator", "http_thread_listener_failed bind=%s:%u generation=%llu elapsed_ms=%llu",
            bind_ip.c_str(),
            static_cast<unsigned>(port),
            static_cast<unsigned long long>(generation),
            static_cast<unsigned long long>(now_ms() - start_ms));
        return;
    }
    current_generation = generation == g_state.worker_generation.load(std::memory_order_acquire);
    if (!current_generation || g_state.stop_request.load(std::memory_order_acquire)) {
        closesocket(listen_sock);
        g_state.http_alive.store(false);
        if (current_generation) {
            g_state.http_start_state.store(3u, std::memory_order_release);
            g_state.worker_cv.notify_all();
        }
        ::diag::log_tagged_fmt("collaborator", "http_thread_exit_after_open bind=%s:%u generation=%llu current_generation=%llu socket=0x%llX elapsed_ms=%llu stop_request=%d",
            bind_ip.c_str(),
            static_cast<unsigned>(port),
            static_cast<unsigned long long>(generation),
            static_cast<unsigned long long>(g_state.worker_generation.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(listen_sock),
            static_cast<unsigned long long>(now_ms() - start_ms),
            g_state.stop_request.load(std::memory_order_acquire) ? 1 : 0);
        return;
    }

    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        g_state.http_socket = listen_sock;
    }
    g_state.http_alive.store(true);
    g_state.http_start_state.store(2u, std::memory_order_release);
    g_state.worker_cv.notify_all();
    ::diag::log_tagged_fmt("collaborator", "http_thread_listener_ready bind=%s:%u generation=%llu socket=0x%llX listener_ready_ms=%llu total_ready_ms=%llu",
        bind_ip.c_str(),
        static_cast<unsigned>(port),
        static_cast<unsigned long long>(generation),
        static_cast<unsigned long long>(listen_sock),
        static_cast<unsigned long long>(listener_ready_ms),
        static_cast<unsigned long long>(now_ms() - start_ms));

    while (!g_state.stop_request.load(std::memory_order_acquire)) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(listen_sock, &fds);
        timeval tv{};
        tv.tv_sec = 0;
        tv.tv_usec = 500000;
        int sel = select(0, &fds, nullptr, nullptr, &tv);
        if (sel <= 0)
            continue;

        sockaddr_in client_addr{};
        int addr_len = sizeof(client_addr);
        SOCKET client_sock = accept(listen_sock, reinterpret_cast<sockaddr*>(&client_addr), &addr_len);
        if (client_sock == INVALID_SOCKET)
            continue;

        std::string client_ip = client_ip_to_string(client_addr.sin_addr.s_addr);
        uint16_t client_port = ntohs(client_addr.sin_port);
        auto task = [client_sock, client_ip, client_port]() {
            active_session_t active(g_state.http_sessions_active, "http_session", client_ip, client_port);
            raw_http_session(client_sock, client_ip, client_port);
        };
        ::diag::log_tagged_fmt("collaborator", "http_session_dispatch_begin client=%s:%u active=%u pid=%lu tid=%lu",
            client_ip.c_str(),
            static_cast<unsigned>(client_port),
            g_state.http_sessions_active.load(std::memory_order_acquire),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()));
        bool spawned = false;
        mcp_standalone::downstream::producer_identity_t sess_id;
        sess_id.kind = mcp_standalone::downstream::producer_kind_t::burp_network;
        sess_id.tool_name = "collaborator.http_session";
        sess_id.domain = client_ip;
        auto sess_admission = mcp_standalone::downstream::scoped_admission_t::acquire(sess_id);
        if (!sess_admission.active()) {
            ::diag::log_tagged_fmt("collaborator", "BURP-NETWORK-WORKER-REJECT client=%s:%u reason=%s quota=%s observed=%zu limit=%zu",
                client_ip.c_str(),
                static_cast<unsigned>(client_port),
                sess_admission.result().reason.c_str(),
                sess_admission.result().quota_name.c_str(),
                sess_admission.result().observed, sess_admission.result().limit);
        } else {
            const uint64_t sess_token = sess_admission.token();
            ::diag::log_tagged_fmt("collaborator", "BURP-NETWORK-WORKER-ADMIT client=%s:%u token=%llu",
                client_ip.c_str(),
                static_cast<unsigned>(client_port),
                static_cast<unsigned long long>(sess_token));
            s_http_session_wg.ensure();
            if (s_http_session_wg.group) {
                auto sess_admission_ptr = std::make_shared<mcp_standalone::downstream::scoped_admission_t>(std::move(sess_admission));
                auto posted = s_http_session_wg.group->post([task, sess_admission_ptr, sess_token, client_sock, client_ip, client_port]() {
                    task();
                    ::diag::log_tagged_fmt("collaborator", "BURP-NETWORK-WORKER-RELEASE client=%s:%u token=%llu reason=completed",
                        client_ip.c_str(),
                        static_cast<unsigned>(client_port),
                        static_cast<unsigned long long>(sess_token));
                    sess_admission_ptr->release("completed");
                });
                if (posted) {
                    spawned = true;
                } else {
                    ::diag::log_tagged_fmt("collaborator", "BURP-NETWORK-WORKER-RELEASE client=%s:%u token=%llu reason=worker_group_full",
                        client_ip.c_str(),
                        static_cast<unsigned>(client_port),
                        static_cast<unsigned long long>(sess_token));
                }
            }
        }
        if (!spawned) {
            ::diag::log_tagged_fmt("collaborator", "http_session_dispatch_fallback_inline client=%s:%u active=%u",
                client_ip.c_str(),
                static_cast<unsigned>(client_port),
                g_state.http_sessions_active.load(std::memory_order_acquire));
            task();
        } else {
            ::diag::log_tagged_fmt("collaborator", "http_session_thread_started client=%s:%u active=%u",
                client_ip.c_str(),
                static_cast<unsigned>(client_port),
                g_state.http_sessions_active.load(std::memory_order_acquire));
        }
    }

    bool close_listen_sock = true;
    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        if (g_state.http_socket == listen_sock) {
            g_state.http_socket = INVALID_SOCKET;
        } else {
            close_listen_sock = false;
        }
    }
    if (close_listen_sock)
        closesocket(listen_sock);
    g_state.http_alive.store(false);
    g_state.worker_cv.notify_all();
    ::diag::log_tagged_fmt("collaborator",
        "http_thread_exit bind=%s:%u listen_ok=1 elapsed_ms=%llu stop_request=%d",
        bind_ip.c_str(),
        static_cast<unsigned>(port),
        static_cast<unsigned long long>(now_ms() - start_ms),
        g_state.stop_request.load() ? 1 : 0);
}

struct dns_parse_result_t
{
    bool        valid = false;
    uint16_t    transaction_id = 0;
    uint16_t    flags = 0;
    uint16_t    qd_count = 0;
    std::string qname;
    uint16_t    qtype = 0;
    uint16_t    qclass = 0;
    size_t      header_end = 12;
    size_t      question_end = 0;
};

static dns_parse_result_t parse_dns_question(const uint8_t* buf, size_t len)
{
    dns_parse_result_t r;
    if (len < 12) return r;
    r.transaction_id = static_cast<uint16_t>((buf[0] << 8) | buf[1]);
    r.flags          = static_cast<uint16_t>((buf[2] << 8) | buf[3]);
    r.qd_count       = static_cast<uint16_t>((buf[4] << 8) | buf[5]);
    if (r.qd_count == 0) return r;

    size_t pos = 12;
    std::string name;
    int label_loops = 0;
    while (pos < len) {
        if (label_loops++ > 64) return r;
        uint8_t lab_len = buf[pos];
        if (lab_len == 0) {
            pos += 1;
            break;
        }
        if ((lab_len & 0xC0) != 0) {
            return r;
        }
        if (pos + 1 + lab_len > len) return r;
        if (!name.empty()) name.push_back('.');
        for (size_t i = 0; i < lab_len; ++i) {
            uint8_t c = buf[pos + 1 + i];
            name.push_back(static_cast<char>(c));
        }
        pos += 1 + lab_len;
        if (name.size() > 255) return r;
    }
    if (pos + 4 > len) return r;
    r.qname  = name;
    r.qtype  = static_cast<uint16_t>((buf[pos] << 8) | buf[pos + 1]);
    r.qclass = static_cast<uint16_t>((buf[pos + 2] << 8) | buf[pos + 3]);
    r.question_end = pos + 4;
    r.valid = true;
    return r;
}

static const char* dns_qtype_name(uint16_t qt)
{
    switch (qt) {
        case 1:  return "A";
        case 2:  return "NS";
        case 5:  return "CNAME";
        case 6:  return "SOA";
        case 12: return "PTR";
        case 15: return "MX";
        case 16: return "TXT";
        case 28: return "AAAA";
        case 33: return "SRV";
        case 35: return "NAPTR";
        case 41: return "OPT";
        case 257: return "CAA";
        default:  return "OTHER";
    }
}

static std::vector<uint8_t> build_dns_answer(const dns_parse_result_t& q, const std::vector<uint8_t>& query_raw, uint32_t answer_ip_be)
{
    std::vector<uint8_t> out;
    out.reserve(query_raw.size() + 32);
    out.assign(query_raw.begin(), query_raw.begin() + static_cast<ptrdiff_t>(std::min(query_raw.size(), q.question_end)));
    out[2] = 0x84;
    out[3] = 0x00;
    out[4] = 0x00; out[5] = 0x01;
    out[6] = 0x00; out[7] = (q.qtype == 1) ? 0x01 : 0x00;
    out[8] = 0x00; out[9] = 0x00;
    out[10] = 0x00; out[11] = 0x00;

    if (q.qtype != 1) {
        return out;
    }

    out.push_back(0xC0);
    out.push_back(0x0C);
    out.push_back(0x00); out.push_back(0x01);
    out.push_back(0x00); out.push_back(0x01);
    out.push_back(0x00); out.push_back(0x00); out.push_back(0x00); out.push_back(0x3C);
    out.push_back(0x00); out.push_back(0x04);
    out.push_back(static_cast<uint8_t>(answer_ip_be & 0xFF));
    out.push_back(static_cast<uint8_t>((answer_ip_be >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((answer_ip_be >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((answer_ip_be >> 24) & 0xFF));
    return out;
}

static void dns_thread_main(std::string bind_ip, uint16_t port, std::string public_host, std::string public_ip, uint64_t generation, uint64_t post_ms)
{
    const uint64_t start_ms = now_ms();
    worker_lifetime_t worker(g_state.dns_thread_alive, g_state.dns_worker_tid);
    ::diag::log_tagged_fmt("collaborator", "dns_thread_enter mode=queue bind=%s:%u host=%s ip=%s generation=%llu queued_ms=%llu pid=%lu tid=%lu",
        bind_ip.c_str(),
        static_cast<unsigned>(port),
        public_host.c_str(),
        public_ip.c_str(),
        static_cast<unsigned long long>(generation),
        static_cast<unsigned long long>(start_ms >= post_ms ? start_ms - post_ms : 0),
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()));
    if (generation != g_state.worker_generation.load(std::memory_order_acquire) ||
        g_state.stop_request.load(std::memory_order_acquire)) {
        ::diag::log_tagged_fmt("collaborator", "dns_thread_exit_before_open bind=%s:%u generation=%llu current_generation=%llu elapsed_ms=%llu stop_request=%d",
            bind_ip.c_str(),
            static_cast<unsigned>(port),
            static_cast<unsigned long long>(generation),
            static_cast<unsigned long long>(g_state.worker_generation.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(now_ms() - start_ms),
            g_state.stop_request.load(std::memory_order_acquire) ? 1 : 0);
        return;
    }

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        ::diag::log_tagged_fmt("collaborator", "dns_socket_create_failed err=%d", WSAGetLastError());
        return;
    }

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, bind_ip.c_str(), &bind_addr.sin_addr) != 1) {
        bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }

    if (bind(sock, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) == SOCKET_ERROR) {
        int err = WSAGetLastError();
        ::diag::log_tagged_fmt("collaborator", "dns_bind_failed addr=%s:%u err=%d", bind_ip.c_str(), port, err);
        closesocket(sock);
        return;
    }

    DWORD recv_timeout = 500;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&recv_timeout), sizeof(recv_timeout));

    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        g_state.dns_socket = sock;
    }
    g_state.dns_alive.store(true);

    uint32_t answer_ip_be = 0;
    in_addr aip{};
    if (inet_pton(AF_INET, public_ip.c_str(), &aip) == 1) {
        answer_ip_be = aip.s_addr;
    } else {
        answer_ip_be = htonl(INADDR_LOOPBACK);
    }

    ::diag::log_tagged_fmt("collaborator", "dns_listener_ready bind=%s:%u public_host='%s' public_ip='%s'",
        bind_ip.c_str(), port, public_host.c_str(), public_ip.c_str());

    while (!g_state.stop_request.load(std::memory_order_acquire)) {
        uint8_t buf[1500];
        sockaddr_in from{};
        int from_len = sizeof(from);
        int n = recvfrom(sock, reinterpret_cast<char*>(buf), sizeof(buf), 0,
                         reinterpret_cast<sockaddr*>(&from), &from_len);
        if (n <= 0) {
            int err = WSAGetLastError();
            if (err == WSAETIMEDOUT || err == WSAEWOULDBLOCK) continue;
            if (g_state.stop_request.load(std::memory_order_acquire)) break;
            continue;
        }
        if (n < 12) continue;

        std::vector<uint8_t> raw_q(buf, buf + n);
        dns_parse_result_t parsed = parse_dns_question(buf, static_cast<size_t>(n));
        if (!parsed.valid) continue;

        std::string client = client_ip_to_string(from.sin_addr.s_addr);
        uint16_t client_port = ntohs(from.sin_port);
        std::string token = extract_token_from_qname(parsed.qname, public_host);

        std::string raw_dump;
        raw_dump.reserve(static_cast<size_t>(n) * 3);
        for (int i = 0; i < n; ++i) {
            char hex[4];
            snprintf(hex, sizeof(hex), "%02x ", buf[i]);
            raw_dump += hex;
        }

        interaction_t it;
        it.kind = "dns";
        it.client_ip = client;
        it.client_port = client_port;
        it.subdomain = parsed.qname;
        it.payload_token = token;
        it.raw = raw_dump;
        it.details["qname"]  = parsed.qname;
        it.details["qtype"]  = dns_qtype_name(parsed.qtype);
        char tid[16];
        snprintf(tid, sizeof(tid), "0x%04x", parsed.transaction_id);
        it.details["txn_id"] = tid;

        ::diag::log_tagged_fmt("collaborator",
            "dns_interaction client=%s:%u qname='%s' qtype=%s token='%s'",
            client.c_str(), client_port, parsed.qname.c_str(),
            dns_qtype_name(parsed.qtype), token.c_str());

        append_interaction(std::move(it));

        std::vector<uint8_t> answer = build_dns_answer(parsed, raw_q, answer_ip_be);
        if (!answer.empty()) {
            sendto(sock, reinterpret_cast<const char*>(answer.data()),
                   static_cast<int>(answer.size()), 0,
                   reinterpret_cast<sockaddr*>(&from), from_len);
        }
    }

    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        g_state.dns_socket = INVALID_SOCKET;
    }
    closesocket(sock);
    g_state.dns_alive.store(false);
    ::diag::log_tagged_fmt("collaborator", "dns_thread_exit elapsed_ms=%llu stop_request=%d",
        static_cast<unsigned long long>(now_ms() - start_ms),
        g_state.stop_request.load(std::memory_order_acquire) ? 1 : 0);
}

static bool smtp_send_line(SOCKET s, const char* text)
{
    size_t len = std::strlen(text);
    size_t sent = 0;
    while (sent < len) {
        int n = send(s, text + sent, static_cast<int>(len - sent), 0);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

static int smtp_recv_line(SOCKET s, std::string& out_line, int timeout_ms, size_t max_len = 4096)
{
    DWORD t = static_cast<DWORD>(timeout_ms);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&t), sizeof(t));
    out_line.clear();
    while (out_line.size() < max_len) {
        char c = 0;
        int n = recv(s, &c, 1, 0);
        if (n <= 0) return -1;
        out_line.push_back(c);
        if (out_line.size() >= 2 &&
            out_line[out_line.size() - 2] == '\r' &&
            out_line[out_line.size() - 1] == '\n') {
            out_line.resize(out_line.size() - 2);
            return static_cast<int>(out_line.size());
        }
    }
    return static_cast<int>(out_line.size());
}

static void smtp_session(SOCKET client_sock, std::string client_ip, uint16_t client_port,
                          std::string public_host, int max_message)
{
    smtp_send_line(client_sock, "220 collaborator.aida ESMTP\r\n");

    std::string mail_from;
    std::vector<std::string> rcpts;
    std::string envelope_log;
    bool quit = false;

    while (!quit && !g_state.stop_request.load(std::memory_order_acquire)) {
        std::string line;
        int rcv = smtp_recv_line(client_sock, line, 30000);
        if (rcv < 0) break;
        envelope_log += line;
        envelope_log += "\r\n";

        std::string upper = lower_ascii(line);
        if (upper.rfind("ehlo ", 0) == 0 || upper.rfind("ehlo\t", 0) == 0 || upper == "ehlo") {
            std::string banner = "250-collaborator.aida\r\n250 SIZE " + std::to_string(max_message) + "\r\n";
            if (!smtp_send_line(client_sock, banner.c_str())) break;
        } else if (upper.rfind("helo", 0) == 0) {
            if (!smtp_send_line(client_sock, "250 collaborator.aida\r\n")) break;
        } else if (upper.rfind("mail from:", 0) == 0) {
            mail_from = trim_ascii(line.substr(10));
            if (!smtp_send_line(client_sock, "250 OK\r\n")) break;
        } else if (upper.rfind("rcpt to:", 0) == 0) {
            rcpts.push_back(trim_ascii(line.substr(8)));
            if (!smtp_send_line(client_sock, "250 OK\r\n")) break;
        } else if (upper == "data") {
            if (!smtp_send_line(client_sock, "354 End data with <CR><LF>.<CR><LF>\r\n")) break;
            std::string body;
            body.reserve(2048);
            while (!g_state.stop_request.load(std::memory_order_acquire)) {
                std::string dline;
                int dr = smtp_recv_line(client_sock, dline, 60000,
                                        static_cast<size_t>(max_message) > 0 ? static_cast<size_t>(max_message) : 65536);
                if (dr < 0) { quit = true; break; }
                if (dline == ".") break;
                if (!dline.empty() && dline[0] == '.') body += dline.substr(1);
                else body += dline;
                body += "\r\n";
                if (static_cast<int>(body.size()) > max_message) break;
            }
            envelope_log += body;
            if (quit) break;

            std::string token;
            for (const auto& r : rcpts) {
                std::string lower_r = lower_ascii(r);
                size_t at = lower_r.find('@');
                if (at == std::string::npos) continue;
                std::string domain = lower_r.substr(at + 1);
                if (!domain.empty() && domain.back() == '>') domain.pop_back();
                token = extract_token_from_host(domain, public_host);
                if (!token.empty()) break;
            }
            if (token.empty()) {
                std::string lower_mf = lower_ascii(mail_from);
                size_t at = lower_mf.find('@');
                if (at != std::string::npos) {
                    std::string domain = lower_mf.substr(at + 1);
                    if (!domain.empty() && domain.back() == '>') domain.pop_back();
                    token = extract_token_from_host(domain, public_host);
                }
            }

            interaction_t it;
            it.kind = "smtp";
            it.client_ip = client_ip;
            it.client_port = client_port;
            it.subdomain = mail_from;
            it.payload_token = token;
            it.raw = envelope_log;
            it.details["mail_from"] = mail_from;
            std::string rcpt_joined;
            for (size_t i = 0; i < rcpts.size(); ++i) {
                if (i) rcpt_joined += ", ";
                rcpt_joined += rcpts[i];
            }
            it.details["rcpt_to"] = rcpt_joined;
            it.details["body"] = body;

            ::diag::log_tagged_fmt("collaborator",
                "smtp_interaction client=%s:%u mail_from='%s' rcpt_count=%zu token='%s' body_size=%zu",
                client_ip.c_str(), client_port,
                mail_from.c_str(), rcpts.size(), token.c_str(), body.size());

            append_interaction(std::move(it));
            mail_from.clear();
            rcpts.clear();
            envelope_log.clear();

            if (!smtp_send_line(client_sock, "250 2.0.0 Ok: queued\r\n")) break;
        } else if (upper == "rset") {
            mail_from.clear();
            rcpts.clear();
            if (!smtp_send_line(client_sock, "250 OK\r\n")) break;
        } else if (upper == "noop") {
            if (!smtp_send_line(client_sock, "250 OK\r\n")) break;
        } else if (upper == "quit") {
            smtp_send_line(client_sock, "221 Bye\r\n");
            quit = true;
        } else if (upper.empty()) {
            continue;
        } else {
            if (!smtp_send_line(client_sock, "502 Command not implemented\r\n")) break;
        }
    }

    shutdown(client_sock, SD_BOTH);
    closesocket(client_sock);
}

static void smtp_thread_main(std::string bind_ip, uint16_t port, std::string public_host, int max_message, uint64_t generation, uint64_t post_ms)
{
    const uint64_t start_ms = now_ms();
    worker_lifetime_t worker(g_state.smtp_thread_alive, g_state.smtp_worker_tid);
    ::diag::log_tagged_fmt("collaborator", "smtp_thread_enter mode=queue bind=%s:%u host=%s max_message=%d generation=%llu queued_ms=%llu pid=%lu tid=%lu",
        bind_ip.c_str(),
        static_cast<unsigned>(port),
        public_host.c_str(),
        max_message,
        static_cast<unsigned long long>(generation),
        static_cast<unsigned long long>(start_ms >= post_ms ? start_ms - post_ms : 0),
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()));
    if (generation != g_state.worker_generation.load(std::memory_order_acquire) ||
        g_state.stop_request.load(std::memory_order_acquire)) {
        ::diag::log_tagged_fmt("collaborator", "smtp_thread_exit_before_open bind=%s:%u generation=%llu current_generation=%llu elapsed_ms=%llu stop_request=%d",
            bind_ip.c_str(),
            static_cast<unsigned>(port),
            static_cast<unsigned long long>(generation),
            static_cast<unsigned long long>(g_state.worker_generation.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(now_ms() - start_ms),
            g_state.stop_request.load(std::memory_order_acquire) ? 1 : 0);
        return;
    }

    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) {
        ::diag::log_tagged_fmt("collaborator", "smtp_socket_create_failed err=%d", WSAGetLastError());
        return;
    }

    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, bind_ip.c_str(), &bind_addr.sin_addr) != 1) {
        bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }

    if (bind(listen_sock, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) == SOCKET_ERROR) {
        int err = WSAGetLastError();
        ::diag::log_tagged_fmt("collaborator", "smtp_bind_failed addr=%s:%u err=%d", bind_ip.c_str(), port, err);
        closesocket(listen_sock);
        return;
    }

    if (listen(listen_sock, 16) == SOCKET_ERROR) {
        int err = WSAGetLastError();
        ::diag::log_tagged_fmt("collaborator", "smtp_listen_failed err=%d", err);
        closesocket(listen_sock);
        return;
    }

    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        g_state.smtp_socket = listen_sock;
    }
    g_state.smtp_alive.store(true);

    ::diag::log_tagged_fmt("collaborator", "smtp_listener_ready bind=%s:%u", bind_ip.c_str(), port);

    while (!g_state.stop_request.load(std::memory_order_acquire)) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(listen_sock, &fds);
        timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 500000;
        int sel = select(0, &fds, nullptr, nullptr, &tv);
        if (sel <= 0) continue;

        sockaddr_in client_addr{};
        int addr_len = sizeof(client_addr);
        SOCKET client_sock = accept(listen_sock, reinterpret_cast<sockaddr*>(&client_addr), &addr_len);
        if (client_sock == INVALID_SOCKET) continue;

        std::string client_ip = client_ip_to_string(client_addr.sin_addr.s_addr);
        uint16_t client_port = ntohs(client_addr.sin_port);

        std::string pub_host_copy = public_host;
        int max_msg = max_message;
        auto task = [client_sock, client_ip, client_port, pub_host_copy, max_msg]() {
            active_session_t active(g_state.smtp_sessions_active, "smtp_session", client_ip, client_port);
            smtp_session(client_sock, client_ip, client_port, pub_host_copy, max_msg);
        };
        ::diag::log_tagged_fmt("collaborator", "smtp_session_post_begin client=%s:%u active=%u pid=%lu tid=%lu",
            client_ip.c_str(),
            static_cast<unsigned>(client_port),
            g_state.smtp_sessions_active.load(std::memory_order_acquire),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()));
        const bool posted = [&]() {
            ::aida::infra::executor::submission_t sub;
            sub.owner_subsystem = "burp.collaborator";
            sub.label = "collaborator.smtp_session";
            sub.thread_class = "service_loop";
            sub.domain = aida::infra::executor::domain_t::security_liveness;
            sub.priority = 4;
            sub.body = task;
            return ::aida::infra::executor::submit(std::move(sub)).submitted;
        }();
        if (!posted) {
            closesocket(client_sock);
            ::diag::log_tagged_fmt("collaborator", "smtp_session_post_failed client=%s:%u active=%u",
                client_ip.c_str(),
                static_cast<unsigned>(client_port),
                g_state.smtp_sessions_active.load(std::memory_order_acquire));
        } else {
            ::diag::log_tagged_fmt("collaborator", "smtp_session_posted client=%s:%u active=%u",
                client_ip.c_str(),
                static_cast<unsigned>(client_port),
                g_state.smtp_sessions_active.load(std::memory_order_acquire));
        }
    }

    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        g_state.smtp_socket = INVALID_SOCKET;
    }
    closesocket(listen_sock);
    g_state.smtp_alive.store(false);
    ::diag::log_tagged_fmt("collaborator", "smtp_thread_exit elapsed_ms=%llu stop_request=%d",
        static_cast<unsigned long long>(now_ms() - start_ms),
        g_state.stop_request.load(std::memory_order_acquire) ? 1 : 0);
}

static std::string generate_token_internal()
{
    uint8_t raw[12];
    NTSTATUS s = BCryptGenRandom(nullptr, raw, sizeof(raw), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (s != 0) {
        for (size_t i = 0; i < sizeof(raw); ++i) {
            raw[i] = static_cast<uint8_t>((now_ms() >> (i % 8)) ^ (i * 37));
        }
    }
    std::string out;
    out.resize(16);
    for (size_t i = 0; i < 16; ++i) {
        uint8_t b = raw[i % sizeof(raw)] ^ static_cast<uint8_t>((i * 11) & 0xFF);
        out[i] = static_cast<char>('a' + (b % 26));
    }
    return out;
}

}

bool start(const collaborator_config_t& cfg)
{
    ensure_loaded();
    diag::log_tagged_fmt("collaborator", "start entry http=%d dns=%d smtp=%d bind=%s http_port=%u dns_port=%u smtp_port=%u",
        static_cast<int>(cfg.enable_http), static_cast<int>(cfg.enable_dns), static_cast<int>(cfg.enable_smtp),
        cfg.bind_ip.c_str(), static_cast<unsigned>(cfg.http_port),
        static_cast<unsigned>(cfg.dns_port), static_cast<unsigned>(cfg.smtp_port));
    if (!s_wsa_guard.ok) {
        diag::log_tagged_fmt("collaborator", "start winsock_not_initialized");
        set_last_error("winsock_init_failed");
        return false;
    }

    if (g_state.running.exchange(true)) {
        diag::log_tagged_fmt("collaborator", "start already_running");
        set_last_error("already_running");
        return false;
    }

    g_state.stop_request.store(false);
    const uint64_t generation = g_state.worker_generation.fetch_add(1u, std::memory_order_acq_rel) + 1u;
    diag::log_tagged_fmt("collaborator", "start generation=%llu",
        static_cast<unsigned long long>(generation));

    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        g_state.config = cfg;
        if (g_state.config.max_interactions == 0) g_state.config.max_interactions = 4096;
        if (g_state.config.smtp_max_message <= 0) g_state.config.smtp_max_message = 1024 * 1024;
        g_state.started_ms = now_ms();
    }

    if (cfg.enable_http) {
        g_state.http_server = std::make_shared<httplib::Server>();
        auto handler = [](const httplib::Request& req, httplib::Response& res) {
            on_http_request(req, res);
        };
        g_state.http_server->Get(".*", handler);
        g_state.http_server->Post(".*", handler);
        g_state.http_server->Put(".*", handler);
        g_state.http_server->Patch(".*", handler);
        g_state.http_server->Delete(".*", handler);
        g_state.http_server->Options(".*", handler);
        g_state.http_server->set_payload_max_length(64 * 1024 * 1024);

        std::string bind_ip = cfg.bind_ip;
        uint16_t port = cfg.http_port;
        g_state.http_thread_alive.store(false);
        g_state.http_worker_tid.store(0);
        g_state.http_start_state.store(0u, std::memory_order_release);
        g_state.http_sessions_active.store(0);
        g_state.http_alive.store(false);
        DWORD thread_start_tick = GetTickCount();
        const uint64_t post_ms = now_ms();
        const auto cq_before = aida::network::executor_status::critical_stats();
        const auto wq_before = aida::network::executor_status::work_stats();
        diag::log_tagged_fmt("collaborator",
            "http_thread_post requested bind=%s:%u generation=%llu host_pid=%lu host_tid=%lu cq_alive=%d cq_shutdown=%d cq_pending=%llu cq_active=%u cq_started=%llu cq_finished=%llu wq_alive=%d wq_shutdown=%d wq_pending=%llu wq_active=%u wq_started=%llu wq_finished=%llu",
            bind_ip.c_str(),
            port,
            static_cast<unsigned long long>(generation),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()),
            cq_before.alive ? 1 : 0,
            cq_before.shutting_down ? 1 : 0,
            static_cast<unsigned long long>(cq_before.pending),
            cq_before.active,
            static_cast<unsigned long long>(cq_before.started),
            static_cast<unsigned long long>(cq_before.finished),
            wq_before.alive ? 1 : 0,
            wq_before.shutting_down ? 1 : 0,
            static_cast<unsigned long long>(wq_before.pending),
            wq_before.active,
            static_cast<unsigned long long>(wq_before.started),
            static_cast<unsigned long long>(wq_before.finished));
        bool posted = false;
        try {
            std::function<void()> task = [bind_ip, port, generation, post_ms]() {
                http_thread_main(bind_ip, port, generation, post_ms);
            };
            posted = [&]() {
                ::aida::infra::executor::submission_t sub;
                sub.owner_subsystem = "burp.collaborator";
                sub.label = "collaborator.http_thread";
                sub.thread_class = "service_loop";
                sub.domain = aida::infra::executor::domain_t::security_liveness;
                sub.priority = 4;
                sub.body = std::move(task);
                return ::aida::infra::executor::submit(std::move(sub)).submitted;
            }();
        } catch (...) {
            posted = false;
        }
        if (!posted) {
            g_state.http_thread_alive.store(false);
            g_state.http_alive.store(false);
            const auto cq_after = aida::network::executor_status::critical_stats();
            const auto wq_after = aida::network::executor_status::work_stats();
            diag::log_tagged_fmt("collaborator",
                "http_thread_post_failed elapsed_ms=%lu bind=%s:%u generation=%llu cq_alive=%d cq_shutdown=%d cq_pending=%llu cq_active=%u cq_rejected=%llu wq_alive=%d wq_shutdown=%d wq_pending=%llu wq_active=%u wq_rejected=%llu",
                static_cast<unsigned long>(GetTickCount() - thread_start_tick),
                bind_ip.c_str(),
                port,
                static_cast<unsigned long long>(generation),
                cq_after.alive ? 1 : 0,
                cq_after.shutting_down ? 1 : 0,
                static_cast<unsigned long long>(cq_after.pending),
                cq_after.active,
                static_cast<unsigned long long>(cq_after.rejected),
                wq_after.alive ? 1 : 0,
                wq_after.shutting_down ? 1 : 0,
                static_cast<unsigned long long>(wq_after.pending),
                wq_after.active,
                static_cast<unsigned long long>(wq_after.rejected));
            set_last_error("http_thread_post_failed");
            stop();
            return false;
        }
        diag::log_tagged_fmt("collaborator",
            "http_thread_posted queue=%s bind=%s:%u generation=%llu elapsed_ms=%lu",
            "security_liveness",
            bind_ip.c_str(),
            port,
            static_cast<unsigned long long>(generation),
            static_cast<unsigned long>(GetTickCount() - thread_start_tick));
        {
            std::unique_lock<std::mutex> lk(g_state.worker_mtx);
            const bool ready = g_state.worker_cv.wait_for(
                lk,
                std::chrono::milliseconds(3000),
                []() {
                    return g_state.http_start_state.load(std::memory_order_acquire) >= 2u;
                });
            const uint32_t start_state = g_state.http_start_state.load(std::memory_order_acquire);
            if (!ready || start_state != 2u || !g_state.http_alive.load(std::memory_order_acquire)) {
                const auto cq_after = aida::network::executor_status::critical_stats();
                const auto wq_after = aida::network::executor_status::work_stats();
                diag::log_tagged_fmt("collaborator",
                    "http_thread_ready_wait_failed ready=%d state=%u alive=%d thread_alive=%d tid=%lu elapsed_ms=%lu bind=%s:%u generation=%llu queue=%s cq_pending=%llu cq_active=%u cq_started=%llu cq_finished=%llu wq_pending=%llu wq_active=%u wq_started=%llu wq_finished=%llu",
                    ready ? 1 : 0,
                    start_state,
                    g_state.http_alive.load(std::memory_order_acquire) ? 1 : 0,
                    g_state.http_thread_alive.load(std::memory_order_acquire) ? 1 : 0,
                    static_cast<unsigned long>(g_state.http_worker_tid.load(std::memory_order_acquire)),
                    static_cast<unsigned long>(GetTickCount() - thread_start_tick),
                    bind_ip.c_str(),
                    port,
                    static_cast<unsigned long long>(generation),
                    "security_liveness",
                    static_cast<unsigned long long>(cq_after.pending),
                    cq_after.active,
                    static_cast<unsigned long long>(cq_after.started),
                    static_cast<unsigned long long>(cq_after.finished),
                    static_cast<unsigned long long>(wq_after.pending),
                    wq_after.active,
                    static_cast<unsigned long long>(wq_after.started),
                    static_cast<unsigned long long>(wq_after.finished));
                lk.unlock();
                set_last_error(start_state == 3u ? "http_listener_open_failed" : "http_thread_enter_wait_failed");
                stop();
                return false;
            }
        }
        ::diag::log_tagged_fmt("collaborator", "http_started mode=queue bind=%s:%u ready=1 alive=%d thread_alive=%d generation=%llu",
            bind_ip.c_str(), port,
            g_state.http_alive.load() ? 1 : 0,
            g_state.http_thread_alive.load() ? 1 : 0,
            static_cast<unsigned long long>(generation));
    }

    if (cfg.enable_dns) {
        std::string bind_ip = cfg.bind_ip;
        uint16_t port = cfg.dns_port;
        std::string public_host = cfg.public_host;
        std::string public_ip = cfg.public_ip;
        g_state.dns_thread_alive.store(false);
        g_state.dns_worker_tid.store(0);
        DWORD thread_start_tick = GetTickCount();
        const uint64_t post_ms = now_ms();
        const auto cq_before = aida::network::executor_status::critical_stats();
        const auto wq_before = aida::network::executor_status::work_stats();
        diag::log_tagged_fmt("collaborator",
            "dns_thread_post requested bind=%s:%u host=%s ip=%s generation=%llu host_pid=%lu host_tid=%lu cq_pending=%llu cq_active=%u wq_pending=%llu wq_active=%u",
            bind_ip.c_str(),
            port,
            public_host.c_str(),
            public_ip.c_str(),
            static_cast<unsigned long long>(generation),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()),
            static_cast<unsigned long long>(cq_before.pending),
            cq_before.active,
            static_cast<unsigned long long>(wq_before.pending),
            wq_before.active);
        bool posted = false;
        try {
            std::function<void()> task = [bind_ip, port, public_host, public_ip, generation, post_ms]() {
                dns_thread_main(bind_ip, port, public_host, public_ip, generation, post_ms);
            };
            posted = [&]() {
                ::aida::infra::executor::submission_t sub;
                sub.owner_subsystem = "burp.collaborator";
                sub.label = "collaborator.dns_thread";
                sub.thread_class = "service_loop";
                sub.domain = aida::infra::executor::domain_t::security_liveness;
                sub.priority = 4;
                sub.body = std::move(task);
                return ::aida::infra::executor::submit(std::move(sub)).submitted;
            }();
        } catch (...) {
            posted = false;
        }
        if (!posted) {
            const auto cq_after = aida::network::executor_status::critical_stats();
            const auto wq_after = aida::network::executor_status::work_stats();
            diag::log_tagged_fmt("collaborator",
                "dns_thread_post_failed elapsed_ms=%lu bind=%s:%u generation=%llu cq_pending=%llu cq_active=%u cq_rejected=%llu wq_pending=%llu wq_active=%u wq_rejected=%llu",
                static_cast<unsigned long>(GetTickCount() - thread_start_tick),
                bind_ip.c_str(),
                port,
                static_cast<unsigned long long>(generation),
                static_cast<unsigned long long>(cq_after.pending),
                cq_after.active,
                static_cast<unsigned long long>(cq_after.rejected),
                static_cast<unsigned long long>(wq_after.pending),
                wq_after.active,
                static_cast<unsigned long long>(wq_after.rejected));
            set_last_error("dns_thread_post_failed");
            stop();
            return false;
        }
        diag::log_tagged_fmt("collaborator",
            "dns_thread_posted queue=%s bind=%s:%u generation=%llu elapsed_ms=%lu",
            "security_liveness",
            bind_ip.c_str(),
            port,
            static_cast<unsigned long long>(generation),
            static_cast<unsigned long>(GetTickCount() - thread_start_tick));
        DWORD wait_iter = 0;
        while (!g_state.dns_alive.load() && wait_iter < 60) {
            Sleep(50);
            ++wait_iter;
        }
        ::diag::log_tagged_fmt("collaborator", "dns_started bind=%s:%u alive=%d generation=%llu",
            bind_ip.c_str(), port, g_state.dns_alive.load() ? 1 : 0,
            static_cast<unsigned long long>(generation));
        if (!g_state.dns_alive.load()) {
            set_last_error("dns_thread_not_ready");
            stop();
            return false;
        }
    }

    if (cfg.enable_smtp) {
        std::string bind_ip = cfg.bind_ip;
        uint16_t port = cfg.smtp_port;
        std::string public_host = cfg.public_host;
        int max_msg = cfg.smtp_max_message;
        g_state.smtp_thread_alive.store(false);
        g_state.smtp_worker_tid.store(0);
        g_state.smtp_sessions_active.store(0);
        DWORD thread_start_tick = GetTickCount();
        const uint64_t post_ms = now_ms();
        const auto cq_before = aida::network::executor_status::critical_stats();
        const auto wq_before = aida::network::executor_status::work_stats();
        diag::log_tagged_fmt("collaborator",
            "smtp_thread_post requested bind=%s:%u host=%s max_msg=%d generation=%llu host_pid=%lu host_tid=%lu cq_pending=%llu cq_active=%u wq_pending=%llu wq_active=%u",
            bind_ip.c_str(),
            port,
            public_host.c_str(),
            max_msg,
            static_cast<unsigned long long>(generation),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()),
            static_cast<unsigned long long>(cq_before.pending),
            cq_before.active,
            static_cast<unsigned long long>(wq_before.pending),
            wq_before.active);
        bool posted = false;
        try {
            std::function<void()> task = [bind_ip, port, public_host, max_msg, generation, post_ms]() {
                smtp_thread_main(bind_ip, port, public_host, max_msg, generation, post_ms);
            };
            posted = [&]() {
                ::aida::infra::executor::submission_t sub;
                sub.owner_subsystem = "burp.collaborator";
                sub.label = "collaborator.smtp_thread";
                sub.thread_class = "service_loop";
                sub.domain = aida::infra::executor::domain_t::security_liveness;
                sub.priority = 4;
                sub.body = std::move(task);
                return ::aida::infra::executor::submit(std::move(sub)).submitted;
            }();
        } catch (...) {
            posted = false;
        }
        if (!posted) {
            const auto cq_after = aida::network::executor_status::critical_stats();
            const auto wq_after = aida::network::executor_status::work_stats();
            diag::log_tagged_fmt("collaborator",
                "smtp_thread_post_failed elapsed_ms=%lu bind=%s:%u generation=%llu cq_pending=%llu cq_active=%u cq_rejected=%llu wq_pending=%llu wq_active=%u wq_rejected=%llu",
                static_cast<unsigned long>(GetTickCount() - thread_start_tick),
                bind_ip.c_str(),
                port,
                static_cast<unsigned long long>(generation),
                static_cast<unsigned long long>(cq_after.pending),
                cq_after.active,
                static_cast<unsigned long long>(cq_after.rejected),
                static_cast<unsigned long long>(wq_after.pending),
                wq_after.active,
                static_cast<unsigned long long>(wq_after.rejected));
            set_last_error("smtp_thread_post_failed");
            stop();
            return false;
        }
        diag::log_tagged_fmt("collaborator",
            "smtp_thread_posted queue=%s bind=%s:%u generation=%llu elapsed_ms=%lu",
            "security_liveness",
            bind_ip.c_str(),
            port,
            static_cast<unsigned long long>(generation),
            static_cast<unsigned long>(GetTickCount() - thread_start_tick));
        DWORD wait_iter = 0;
        while (!g_state.smtp_alive.load() && wait_iter < 60) {
            Sleep(50);
            ++wait_iter;
        }
        ::diag::log_tagged_fmt("collaborator", "smtp_started bind=%s:%u alive=%d generation=%llu",
            bind_ip.c_str(), port, g_state.smtp_alive.load() ? 1 : 0,
            static_cast<unsigned long long>(generation));
        if (!g_state.smtp_alive.load()) {
            set_last_error("smtp_thread_not_ready");
            stop();
            return false;
        }
    }

    set_last_error("");
    diag::log_tagged_fmt("collaborator", "start done http_alive=%d dns_alive=%d smtp_alive=%d",
        g_state.http_alive.load() ? 1 : 0,
        g_state.dns_alive.load() ? 1 : 0,
        g_state.smtp_alive.load() ? 1 : 0);
    save_default_state_unlocked();
    return true;
}

void stop()
{
    const uint64_t t0 = now_ms();
    diag::log_tagged_fmt("collaborator", "stop entry");
    if (!g_state.running.exchange(false)) {
        diag::log_tagged_fmt("collaborator", "stop not_running");
        return;
    }

    g_state.stop_request.store(true);
    const uint64_t stop_generation = g_state.worker_generation.fetch_add(1u, std::memory_order_acq_rel) + 1u;
    diag::log_tagged_fmt("collaborator", "stop generation=%llu",
        static_cast<unsigned long long>(stop_generation));

    const bool http_thread_alive = g_state.http_thread_alive.load();
    const bool dns_thread_alive = g_state.dns_thread_alive.load();
    const bool smtp_thread_alive = g_state.smtp_thread_alive.load();
    diag::log_tagged_fmt("collaborator",
        "stop state http_alive=%d http_thread_alive=%d dns_alive=%d dns_thread_alive=%d smtp_alive=%d smtp_thread_alive=%d",
        g_state.http_alive.load() ? 1 : 0,
        http_thread_alive ? 1 : 0,
        g_state.dns_alive.load() ? 1 : 0,
        dns_thread_alive ? 1 : 0,
        g_state.smtp_alive.load() ? 1 : 0,
        smtp_thread_alive ? 1 : 0);

    std::shared_ptr<httplib::Server> http_server = g_state.http_server;
    if (http_server && (http_thread_alive || http_server->is_running())) {
        diag::log_tagged_fmt("collaborator", "stop http_server_stop begin running=%d thread_alive=%d",
            http_server->is_running() ? 1 : 0,
            http_thread_alive ? 1 : 0);
        http_server->stop();
        diag::log_tagged_fmt("collaborator", "stop http_server_stop end running=%d",
            http_server->is_running() ? 1 : 0);
    } else if (http_server) {
        diag::log_tagged_fmt("collaborator", "stop http_server_stop skipped running=0 thread_alive=0");
    }

    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        if (g_state.http_socket != INVALID_SOCKET) {
            closesocket(g_state.http_socket);
            g_state.http_socket = INVALID_SOCKET;
        }
        if (g_state.dns_socket != INVALID_SOCKET) {
            closesocket(g_state.dns_socket);
            g_state.dns_socket = INVALID_SOCKET;
        }
        if (g_state.smtp_socket != INVALID_SOCKET) {
            closesocket(g_state.smtp_socket);
            g_state.smtp_socket = INVALID_SOCKET;
        }
    }

    auto wait_worker = [](const char* name, std::atomic<bool>& alive, std::atomic<DWORD>& tid, DWORD timeout_ms) {
        const DWORD tid_snapshot = tid.load(std::memory_order_acquire);
        diag::log_tagged_fmt("collaborator", "stop %s_wait begin tid=%lu timeout_ms=%lu alive=%d",
            name,
            static_cast<unsigned long>(tid_snapshot),
            static_cast<unsigned long>(timeout_ms),
            alive.load(std::memory_order_acquire) ? 1 : 0);
        std::unique_lock<std::mutex> lk(g_state.worker_mtx);
        const bool stopped = g_state.worker_cv.wait_for(
            lk,
            std::chrono::milliseconds(timeout_ms),
            [&alive]() { return !alive.load(std::memory_order_acquire); });
        diag::log_tagged_fmt("collaborator", "stop %s_wait end stopped=%d alive=%d tid=%lu",
            name,
            stopped ? 1 : 0,
            alive.load(std::memory_order_acquire) ? 1 : 0,
            static_cast<unsigned long>(tid.load(std::memory_order_acquire)));
        return stopped;
    };

    auto wait_sessions = [](const char* name, std::atomic<uint32_t>& active, DWORD timeout_ms) {
        const uint32_t initial = active.load(std::memory_order_acquire);
        diag::log_tagged_fmt("collaborator", "stop %s_wait begin active=%u timeout_ms=%lu",
            name,
            initial,
            static_cast<unsigned long>(timeout_ms));
        std::unique_lock<std::mutex> lk(g_state.worker_mtx);
        const bool drained = g_state.worker_cv.wait_for(
            lk,
            std::chrono::milliseconds(timeout_ms),
            [&active]() { return active.load(std::memory_order_acquire) == 0; });
        diag::log_tagged_fmt("collaborator", "stop %s_wait end drained=%d active=%u",
            name,
            drained ? 1 : 0,
            active.load(std::memory_order_acquire));
        return drained;
    };

    if (http_thread_alive)
        wait_worker("http_worker", g_state.http_thread_alive, g_state.http_worker_tid, 1500);
    if (dns_thread_alive)
        wait_worker("dns_worker", g_state.dns_thread_alive, g_state.dns_worker_tid, 1500);
    if (smtp_thread_alive)
        wait_worker("smtp_worker", g_state.smtp_thread_alive, g_state.smtp_worker_tid, 1500);
    if (g_state.http_sessions_active.load(std::memory_order_acquire) != 0)
        wait_sessions("http_sessions", g_state.http_sessions_active, 1500);
    if (g_state.smtp_sessions_active.load(std::memory_order_acquire) != 0)
        wait_sessions("smtp_sessions", g_state.smtp_sessions_active, 1500);

    g_state.http_server.reset();

    g_state.http_alive.store(false);
    g_state.dns_alive.store(false);
    g_state.smtp_alive.store(false);

    s_http_session_wg.shutdown();

    ::diag::log_tagged_fmt("collaborator", "stopped elapsed_ms=%llu",
        static_cast<unsigned long long>(now_ms() - t0));
    save_default_state_unlocked();
}

bool is_running()
{
    ensure_loaded();
    bool r = g_state.running.load();
    ::diag::log_tagged_fmt("collaborator", "is_running result=%d", static_cast<int>(r));
    return r;
}

status_t status()
{
    ensure_loaded();
    status_t s;
    std::lock_guard<std::mutex> lk(g_state.mtx);
    s.running = g_state.running.load();
    s.http_alive = g_state.http_alive.load();
    s.dns_alive  = g_state.dns_alive.load();
    s.smtp_alive = g_state.smtp_alive.load();
    s.smtps_supported = false;
    s.ldap_supported = false;
    s.bind_ip   = g_state.config.bind_ip;
    s.http_port = g_state.config.http_port;
    s.dns_port  = g_state.config.dns_port;
    s.smtp_port = g_state.config.smtp_port;
    s.smtps_port = g_state.config.smtps_port;
    s.ldap_port = g_state.config.ldap_port;
    s.public_host = g_state.config.public_host;
    s.public_ip   = g_state.config.public_ip;
    s.interaction_count = g_state.interactions.size();
    s.token_count = g_state.tokens.size();
    s.poll_cursor_count = g_state.poll_cursors.size();
    s.started_ms = g_state.started_ms;
    s.durable_state_path = path_to_utf8(default_state_path_fs());
    ::diag::log_tagged_fmt("collaborator", "status running=%d http=%d dns=%d smtp=%d interactions=%zu tokens=%zu",
        static_cast<int>(s.running), static_cast<int>(s.http_alive),
        static_cast<int>(s.dns_alive), static_cast<int>(s.smtp_alive),
        s.interaction_count, s.token_count);
    return s;
}

collaborator_config_t current_config()
{
    ensure_loaded();
    ::diag::log_tagged_fmt("collaborator", "current_config entry");
    std::lock_guard<std::mutex> lk(g_state.mtx);
    return g_state.config;
}

std::string generate_token()
{
    ensure_loaded();
    std::string tok;
    std::string full;
    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        int attempts = 0;
        do {
            tok = generate_token_internal();
            ++attempts;
        } while (g_state.tokens.find(tok) != g_state.tokens.end() && attempts < 16);

        token_info_t info;
        info.token = tok;
        info.full_domain = tok + "." + g_state.config.public_host;
        info.issued_ms = now_ms();
        full = info.full_domain;
        g_state.tokens[tok] = info;
    }
    ::diag::log_tagged_fmt("collaborator", "token_generated token='%s' full='%s'",
        tok.c_str(), full.c_str());
    save_default_state_unlocked();
    return tok;
}

std::vector<token_info_t> list_tokens()
{
    ensure_loaded();
    ::diag::log_tagged_fmt("collaborator", "list_tokens entry");
    std::vector<token_info_t> out;
    std::lock_guard<std::mutex> lk(g_state.mtx);
    out.reserve(g_state.tokens.size());
    for (const auto& kv : g_state.tokens) out.push_back(kv.second);
    ::diag::log_tagged_fmt("collaborator", "list_tokens result=%zu", out.size());
    return out;
}

bool forget_token(const std::string& token)
{
    ensure_loaded();
    ::diag::log_tagged_fmt("collaborator", "forget_token entry token=%s", token.c_str());
    std::string norm = lower_ascii(token);
    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        auto it = g_state.tokens.find(norm);
        if (it == g_state.tokens.end()) {
            ::diag::log_tagged_fmt("collaborator", "forget_token not_found token=%s", token.c_str());
            return false;
        }
        g_state.tokens.erase(it);
        for (auto cur = g_state.poll_cursors.begin(); cur != g_state.poll_cursors.end(); ) {
            if (cur->second.token == norm) cur = g_state.poll_cursors.erase(cur);
            else ++cur;
        }
    }
    ::diag::log_tagged_fmt("collaborator", "forget_token ok token=%s", token.c_str());
    save_default_state_unlocked();
    return true;
}

std::vector<interaction_t> poll_since(uint64_t timestamp_ms_inclusive)
{
    ensure_loaded();
    ::diag::log_tagged_fmt("collaborator", "poll_since entry ts=%llu", static_cast<unsigned long long>(timestamp_ms_inclusive));
    std::vector<interaction_t> out;
    std::lock_guard<std::mutex> lk(g_state.mtx);
    out.reserve(g_state.interactions.size());
    for (const auto& it : g_state.interactions) {
        if (it.timestamp_ms >= timestamp_ms_inclusive) out.push_back(it);
    }
    ::diag::log_tagged_fmt("collaborator", "poll_since result=%zu", out.size());
    return out;
}

std::vector<interaction_t> poll_by_token(const std::string& token)
{
    ensure_loaded();
    ::diag::log_tagged_fmt("collaborator", "poll_by_token entry token=%s", token.c_str());
    std::string norm = lower_ascii(token);
    std::vector<interaction_t> out;
    std::lock_guard<std::mutex> lk(g_state.mtx);
    for (const auto& it : g_state.interactions) {
        if (it.payload_token == norm) out.push_back(it);
    }
    ::diag::log_tagged_fmt("collaborator", "poll_by_token result=%zu token=%s", out.size(), token.c_str());
    return out;
}

std::vector<interaction_t> snapshot_all(size_t max_entries)
{
    ensure_loaded();
    ::diag::log_tagged_fmt("collaborator", "snapshot_all entry max=%zu", max_entries);
    std::vector<interaction_t> out;
    std::lock_guard<std::mutex> lk(g_state.mtx);
    size_t total = g_state.interactions.size();
    size_t skip = (max_entries == 0 || max_entries >= total) ? 0 : (total - max_entries);
    size_t i = 0;
    for (const auto& it : g_state.interactions) {
        if (i++ < skip) continue;
        out.push_back(it);
    }
    ::diag::log_tagged_fmt("collaborator", "snapshot_all result=%zu total=%zu", out.size(), total);
    return out;
}

bool get_interaction(uint64_t id, interaction_t& out)
{
    ensure_loaded();
    ::diag::log_tagged_fmt("collaborator", "get_interaction entry id=%llu", static_cast<unsigned long long>(id));
    std::lock_guard<std::mutex> lk(g_state.mtx);
    for (const auto& it : g_state.interactions) {
        if (it.id == id) {
            ::diag::log_tagged_fmt("collaborator", "get_interaction found id=%llu kind=%s", static_cast<unsigned long long>(id), it.kind.c_str());
            out = it;
            return true;
        }
    }
    ::diag::log_tagged_fmt("collaborator", "get_interaction not_found id=%llu", static_cast<unsigned long long>(id));
    return false;
}

void clear()
{
    ensure_loaded();
    ::diag::log_tagged_fmt("collaborator", "clear entry");
    size_t n = 0;
    size_t token_count = 0;
    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        n = g_state.interactions.size();
        g_state.interactions.clear();
        g_state.poll_cursors.clear();
        for (auto& kv : g_state.tokens) {
            kv.second.interaction_count = 0;
            kv.second.last_seen_ms = 0;
        }
        token_count = g_state.tokens.size();
        g_state.next_id.store(1);
    }
    ::diag::log_tagged_fmt("collaborator", "clear done cleared_interactions=%zu tokens_reset=%zu", n, token_count);
    save_default_state_unlocked();
}

nlohmann::json export_json()
{
    ensure_loaded();
    std::lock_guard<std::mutex> lk(g_state.mtx);
    return snapshot_json_locked();
}

bool import_json(const nlohmann::json& doc, bool replace_existing)
{
    ensure_loaded();
    bool ok = false;
    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        ok = import_json_locked(doc, replace_existing);
    }
    if (ok) {
        g_state.worker_cv.notify_all();
        save_default_state_unlocked();
    }
    return ok;
}

static poll_result_t collect_poll_locked(const poll_request_t& request, const std::string& cursor_id)
{
    poll_result_t result;
    result.cursor = cursor_id;
    const std::string token = lower_ascii(request.token);
    uint64_t after_id = request.after_id;
    uint64_t since_ms = request.since_ms;
    auto cursor_it = cursor_id.empty() ? g_state.poll_cursors.end() : g_state.poll_cursors.find(cursor_id);
    if (cursor_it != g_state.poll_cursors.end()) {
        if (token.empty() || token == cursor_it->second.token) {
            after_id = (std::max)(after_id, cursor_it->second.after_id);
            since_ms = (std::max)(since_ms, cursor_it->second.since_ms);
        }
    }
    const size_t max_entries = (std::min)(request.max_entries == 0 ? static_cast<size_t>(256) : request.max_entries, static_cast<size_t>(4096));
    for (const auto& it : g_state.interactions) {
        if (!token.empty() && it.payload_token != token) continue;
        if (after_id != 0 && it.id <= after_id) continue;
        if (since_ms != 0 && it.timestamp_ms < since_ms) continue;
        result.interactions.push_back(it);
        result.next_after_id = (std::max)(result.next_after_id, it.id);
        result.next_since_ms = (std::max)(result.next_since_ms, it.timestamp_ms + 1);
        if (result.interactions.size() >= max_entries) break;
    }
    if (result.next_after_id == 0) result.next_after_id = after_id;
    if (result.next_since_ms == 0) result.next_since_ms = since_ms;
    if (!cursor_id.empty()) {
        auto& c = g_state.poll_cursors[cursor_id];
        c.token = token;
        c.after_id = result.next_after_id;
        c.since_ms = result.next_since_ms;
        c.updated_ms = now_ms();
    }
    return result;
}

poll_result_t poll_async(const poll_request_t& request)
{
    ensure_loaded();
    std::string cursor = request.cursor;
    if (cursor.empty()) {
        cursor = generate_token_internal();
    }
    const uint32_t wait_ms = (std::min)(request.wait_ms, static_cast<uint32_t>(30000));
    const uint64_t deadline = now_ms() + wait_ms;
    for (;;) {
        poll_result_t ready;
        bool has_ready = false;
        bool persist_ready = false;
        {
            std::lock_guard<std::mutex> lk(g_state.mtx);
            ready = collect_poll_locked(request, cursor);
            if (!ready.interactions.empty() || wait_ms == 0) {
                ready.timed_out = ready.interactions.empty() && wait_ms != 0;
                persist_ready = !g_state.loading_durable.load(std::memory_order_acquire);
                has_ready = true;
            }
        }
        if (has_ready) {
            if (persist_ready) save_default_state_unlocked();
            return ready;
        }
        const uint64_t now = now_ms();
        if (now >= deadline) {
            poll_result_t result;
            bool persist_timeout = false;
            {
                std::lock_guard<std::mutex> lk(g_state.mtx);
                result = collect_poll_locked(request, cursor);
                result.timed_out = result.interactions.empty();
                persist_timeout = !g_state.loading_durable.load(std::memory_order_acquire);
            }
            if (persist_timeout) save_default_state_unlocked();
            return result;
        }
        std::unique_lock<std::mutex> lk(g_state.worker_mtx);
        const uint64_t remaining = deadline > now ? deadline - now : 0;
        g_state.worker_cv.wait_for(lk, std::chrono::milliseconds((std::min<uint64_t>)(remaining, 250)));
    }
}

bool save_state_to_file(const std::string& path)
{
    ensure_loaded();
    if (path.empty()) {
        set_last_error("collaborator.save: empty path");
        return false;
    }
    json snap;
    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        snap = snapshot_json_locked();
    }
    const bool ok = write_json_atomic(std::filesystem::path(path), snap);
    diag::log_tagged_fmt("collaborator", "save_state path=%s ok=%d", path.c_str(), ok ? 1 : 0);
    return ok;
}

bool load_state_from_file(const std::string& path, bool replace_existing)
{
    ensure_loaded();
    if (path.empty()) {
        set_last_error("collaborator.load: empty path");
        return false;
    }
    json doc;
    if (!read_json_file(std::filesystem::path(path), doc))
        return false;
    const bool ok = import_json(doc, replace_existing);
    diag::log_tagged_fmt("collaborator", "load_state path=%s ok=%d replace=%d", path.c_str(), ok ? 1 : 0, replace_existing ? 1 : 0);
    return ok;
}

bool save_default_state()
{
    ensure_loaded();
    const bool ok = save_default_state_unlocked();
    diag::log_tagged_fmt("collaborator", "save_default_state path=%s ok=%d", path_to_utf8(default_state_path_fs()).c_str(), ok ? 1 : 0);
    return ok;
}

bool load_default_state(bool replace_existing)
{
    const auto path = default_state_path_fs();
    json doc;
    if (!read_json_file(path, doc))
        return false;
    bool ok = false;
    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        g_state.durable_loaded.store(true, std::memory_order_release);
        g_state.loading_durable.store(true, std::memory_order_release);
        ok = import_json_locked(doc, replace_existing);
        g_state.loading_durable.store(false, std::memory_order_release);
    }
    if (ok) save_default_state_unlocked();
    diag::log_tagged_fmt("collaborator", "load_default_state path=%s ok=%d replace=%d", path_to_utf8(path).c_str(), ok ? 1 : 0, replace_existing ? 1 : 0);
    return ok;
}

std::string default_state_path()
{
    return path_to_utf8(default_state_path_fs());
}

bool export_interactions_to_file(const std::string& path,
                                 const std::string& token,
                                 uint64_t since_ms,
                                 uint64_t after_id,
                                 size_t max_entries)
{
    ensure_loaded();
    if (path.empty()) {
        set_last_error("collaborator.export: empty path");
        return false;
    }
    const std::string norm = lower_ascii(token);
    const size_t cap = (std::min)(max_entries == 0 ? static_cast<size_t>(65536) : max_entries, static_cast<size_t>(1048576));
    json out;
    out["version"] = 1;
    out["exported_ms"] = now_ms();
    out["token"] = norm;
    out["since_ms"] = since_ms;
    out["after_id"] = after_id;
    out["interactions"] = json::array();
    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        for (const auto& it : g_state.interactions) {
            if (!norm.empty() && it.payload_token != norm) continue;
            if (after_id != 0 && it.id <= after_id) continue;
            if (since_ms != 0 && it.timestamp_ms < since_ms) continue;
            out["interactions"].push_back(interaction_to_json_locked(it));
            if (out["interactions"].size() >= cap) break;
        }
    }
    const bool ok = write_json_atomic(std::filesystem::path(path), out);
    diag::log_tagged_fmt("collaborator", "export_interactions path=%s count=%llu ok=%d",
        path.c_str(),
        static_cast<unsigned long long>(out["interactions"].size()),
        ok ? 1 : 0);
    return ok;
}

bool post_interactions_webhook(const std::string& url,
                               const std::string& token,
                               uint64_t since_ms,
                               uint64_t after_id,
                               size_t max_entries,
                               const std::string& signing_secret,
                               uint32_t timeout_ms,
                               webhook_delivery_result_t& result)
{
    ensure_loaded();
    result = webhook_delivery_result_t{};
    parsed_webhook_url_t endpoint;
    if (!parse_webhook_url(url, endpoint)) {
        result.error = "collaborator.webhook: invalid http or https URL";
        set_last_error(result.error);
        return false;
    }
    const std::string norm = lower_ascii(token);
    const size_t cap = (std::min)(max_entries == 0 ? static_cast<size_t>(4096) : max_entries, static_cast<size_t>(65536));
    json payload;
    payload["version"] = 1;
    payload["exported_ms"] = now_ms();
    payload["delivery"] = "webhook";
    payload["token"] = norm;
    payload["since_ms"] = since_ms;
    payload["after_id"] = after_id;
    payload["interactions"] = json::array();
    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        for (const auto& it : g_state.interactions) {
            if (!norm.empty() && it.payload_token != norm) continue;
            if (after_id != 0 && it.id <= after_id) continue;
            if (since_ms != 0 && it.timestamp_ms < since_ms) continue;
            payload["interactions"].push_back(interaction_to_json_locked(it));
            if (payload["interactions"].size() >= cap) break;
        }
    }
    const std::string body = payload.dump();
    const std::string timestamp = std::to_string(now_ms());

    httplib::Headers headers = {
        {"Accept", "application/json"},
        {"User-Agent", "AiDA-Collaborator/1.0"},
        {"X-AiDA-Collaborator-Timestamp", timestamp}
    };
    if (!signing_secret.empty()) {
        std::string sig;
        if (!hmac_sha256_hex(signing_secret, timestamp + "." + body, sig)) {
            result.error = "collaborator.webhook: signature generation failed";
            set_last_error(result.error);
            return false;
        }
        headers.emplace("X-AiDA-Collaborator-Signature", "sha256=" + sig);
    }

    const uint32_t bounded_timeout = (std::min)(timeout_ms == 0 ? 10000u : timeout_ms, 60000u);
    httplib::Client cli(endpoint.origin);
    cli.set_connection_timeout(std::chrono::milliseconds(bounded_timeout));
    cli.set_read_timeout(std::chrono::milliseconds(bounded_timeout));
    cli.set_write_timeout(std::chrono::milliseconds(bounded_timeout));
    cli.enable_server_certificate_verification(true);
    cli.set_follow_location(false);

    auto res = cli.Post(endpoint.path.c_str(), headers, body, "application/json");
    result.origin = endpoint.origin;
    result.path = endpoint.path;
    result.interaction_count = payload["interactions"].size();
    if (!res) {
        result.error = "collaborator.webhook: transport failed: " + httplib::to_string(res.error());
        set_last_error(result.error);
        diag::log_tagged_fmt("collaborator", "webhook_export transport_failed origin=%s path_len=%zu count=%zu err=%s",
            endpoint.origin.c_str(), endpoint.path.size(), result.interaction_count, result.error.c_str());
        return false;
    }
    result.status_code = res->status;
    result.delivered = res->status >= 200 && res->status < 300;
    if (!result.delivered) {
        result.error = "collaborator.webhook: HTTP " + std::to_string(res->status);
        set_last_error(result.error);
    } else {
        set_last_error("");
    }
    diag::log_tagged_fmt("collaborator", "webhook_export origin=%s path_len=%zu status=%d delivered=%d count=%zu",
        endpoint.origin.c_str(), endpoint.path.size(), result.status_code, result.delivered ? 1 : 0, result.interaction_count);
    return result.delivered;
}

std::string last_error()
{
    std::lock_guard<std::mutex> lk(g_state.err_mtx);
    std::string e = g_state.last_err;
    ::diag::log_tagged_fmt("collaborator", "last_error queried val=%s", e.c_str());
    return e;
}

}
}
}
