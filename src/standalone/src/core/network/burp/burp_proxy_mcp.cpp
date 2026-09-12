#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef small
#undef small
#endif

#include "burp_proxy_mcp.hpp"
#include "../mitm_proxy.hpp"
#include "../../settings/standalone_compat.hpp"
#include "helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace proxy_mcp {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

namespace {

tool_result_t error_with_data(const std::string& text, const json& data)
{
    return tool_result_t{false, text, data};
}

std::vector<uint8_t> base64_decode(const std::string& s)
{
    static const int8_t tbl[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    };
    std::vector<uint8_t> out;
    out.reserve(s.size() * 3 / 4);
    uint32_t buf = 0; int bits = 0;
    for (unsigned char c : s) {
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        int v = tbl[c];
        if (v == -1) return std::vector<uint8_t>();
        if (v == -2) break;
        buf = (buf << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buf >> bits) & 0xFF));
        }
    }
    return out;
}

std::string base64_encode_bytes(const uint8_t* data, size_t len)
{
    static const char* alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t a = data[i];
        uint32_t b = (i + 1 < len) ? data[i + 1] : 0;
        uint32_t c = (i + 2 < len) ? data[i + 2] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;
        out.push_back(alpha[(triple >> 18) & 0x3F]);
        out.push_back(alpha[(triple >> 12) & 0x3F]);
        out.push_back((i + 1 < len) ? alpha[(triple >> 6) & 0x3F] : '=');
        out.push_back((i + 2 < len) ? alpha[triple & 0x3F]        : '=');
    }
    return out;
}

const char* exchange_state_str(mitm_proxy::http_exchange::state_t s)
{
    switch (s) {
    case mitm_proxy::http_exchange::state_t::pending:    return "pending";
    case mitm_proxy::http_exchange::state_t::forwarding: return "forwarding";
    case mitm_proxy::http_exchange::state_t::complete:   return "complete";
    case mitm_proxy::http_exchange::state_t::dropped:    return "dropped";
    case mitm_proxy::http_exchange::state_t::error:      return "error";
    }
    return "unknown";
}

json exchange_to_json(const mitm_proxy::http_exchange& ex)
{
    json out;
    out["id"]              = static_cast<uint64_t>(ex.id);
    out["timestamp"]       = static_cast<uint64_t>(ex.timestamp);
    out["client_addr"]     = ex.client_addr;
    out["client_port"]     = static_cast<uint32_t>(ex.client_port);
    out["target_host"]     = ex.target_host;
    out["target_port"]     = static_cast<uint32_t>(ex.target_port);
    out["is_tls"]          = ex.is_tls;
    out["is_websocket"]    = ex.is_websocket;
    out["is_h2"]           = ex.is_h2;
    out["state"]           = exchange_state_str(ex.state);
    out["latency_ms"]      = static_cast<uint64_t>(ex.latency_ms);
    out["request_size"]    = static_cast<uint64_t>(ex.request_size);
    out["response_size"]   = static_cast<uint64_t>(ex.response_size);
    out["request_method"]  = ex.request.method;
    out["request_path"]    = ex.request.uri;
    out["response_status"] = ex.response.status_code;

    constexpr size_t max_body_b64 = 4096;
    if (!ex.raw_request.empty()) {
        size_t cap = ex.raw_request.size();
        if (cap > max_body_b64) cap = max_body_b64;
        out["request_body_b64"] = base64_encode_bytes(ex.raw_request.data(), cap);
        out["request_body_truncated"] = (ex.raw_request.size() > max_body_b64);
    } else {
        out["request_body_b64"] = "";
        out["request_body_truncated"] = false;
    }
    if (!ex.raw_response.empty()) {
        size_t cap = ex.raw_response.size();
        if (cap > max_body_b64) cap = max_body_b64;
        out["response_body_b64"] = base64_encode_bytes(ex.raw_response.data(), cap);
        out["response_body_truncated"] = (ex.raw_response.size() > max_body_b64);
    } else {
        out["response_body_b64"] = "";
        out["response_body_truncated"] = false;
    }
    return out;
}

json stats_to_json(const mitm_proxy::proxy_stats& st)
{
    json out;
    out["running"]            = st.running;
    out["total_requests"]     = static_cast<uint64_t>(st.total_requests);
    out["total_bytes_in"]     = static_cast<uint64_t>(st.total_bytes_in);
    out["total_bytes_out"]    = static_cast<uint64_t>(st.total_bytes_out);
    out["active_connections"] = static_cast<uint32_t>(st.active_connections);
    out["history_size"]       = static_cast<uint64_t>(st.history_size);
    out["held_count"]         = static_cast<uint64_t>(st.held_count);
    return out;
}

json tls_obs_to_json(const mitm_proxy::tls_observation_t& obs)
{
    json out;
    out["timestamp"]   = static_cast<uint64_t>(obs.timestamp);
    out["kind"]        = mitm_proxy::to_string(obs.kind);
    out["client_addr"] = obs.client_addr;
    out["client_port"] = static_cast<uint32_t>(obs.client_port);
    out["target_host"] = obs.target_host;
    out["target_port"] = static_cast<uint32_t>(obs.target_port);
    out["sni"]         = obs.sni;
    out["alpn"]        = obs.alpn;
    out["detail"]      = obs.detail;
    return out;
}

tool_result_t handle_start(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "proxy_start entry");
    mitm_proxy::proxy_config cfg;
    if (p.contains("bind_addr") && p["bind_addr"].is_string()) cfg.bind_addr = p["bind_addr"].get<std::string>();
    if (p.contains("bind_port")) {
        if (!p["bind_port"].is_number_integer()) return tool_result_t::error("bind_port must be an integer in 1..65535");
        long long v = p["bind_port"].get<long long>();
        if (v < 1 || v > 65535) return tool_result_t::error("bind_port must be in 1..65535");
        cfg.bind_port = static_cast<uint16_t>(v);
    }
    if (p.contains("decode_tls") && p["decode_tls"].is_boolean()) cfg.decode_tls = p["decode_tls"].get<bool>();
    if (p.contains("enable_h2") && p["enable_h2"].is_boolean()) cfg.enable_h2 = p["enable_h2"].get<bool>();
    if (p.contains("enable_websocket") && p["enable_websocket"].is_boolean()) cfg.enable_websocket = p["enable_websocket"].get<bool>();
    diag::log_tagged_fmt("mcp_burp", "proxy_start bind=%s:%u decode_tls=%d h2=%d ws=%d",
        cfg.bind_addr.c_str(), static_cast<unsigned>(cfg.bind_port), (int)cfg.decode_tls, (int)cfg.enable_h2, (int)cfg.enable_websocket);

    bool ok = mitm_proxy::start(cfg);
    if (!ok)
    {
        diag::log_tagged_fmt("mcp_burp", "proxy_start failed");
        json data = stats_to_json(mitm_proxy::get_stats());
        data["error"] = "start_failed";
        data["requested_bind_addr"] = cfg.bind_addr;
        data["requested_bind_port"] = static_cast<uint32_t>(cfg.bind_port);
        data["requested_decode_tls"] = cfg.decode_tls;
        data["requested_enable_h2"] = cfg.enable_h2;
        data["requested_enable_websocket"] = cfg.enable_websocket;
        return error_with_data("proxy start failed", data);
    }
    diag::log_tagged_fmt("mcp_burp", "proxy_start ok bind=%s:%u", cfg.bind_addr.c_str(), static_cast<unsigned>(cfg.bind_port));
    auto st = mitm_proxy::get_stats();
    return tool_result_t::ok("proxy started bind=" + cfg.bind_addr + ":" + std::to_string(cfg.bind_port), stats_to_json(st));
}

tool_result_t handle_stop(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "proxy_stop entry");
    mitm_proxy::stop();
    diag::log_tagged_fmt("mcp_burp", "proxy_stop ok");
    auto st = mitm_proxy::get_stats();
    return tool_result_t::ok("proxy stopped running=" + std::to_string(st.running ? 1 : 0), stats_to_json(st));
}

tool_result_t handle_status(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "proxy_status entry");
    bool running = mitm_proxy::is_running();
    auto st = mitm_proxy::get_stats();
    diag::log_tagged_fmt("mcp_burp", "proxy_status ok running=%d requests=%llu", (int)running, static_cast<unsigned long long>(st.total_requests));
    json data = stats_to_json(st);
    data["running"] = running;
    return tool_result_t::ok("proxy status running=" + std::to_string(running ? 1 : 0) + " requests=" + std::to_string(st.total_requests), data);
}

tool_result_t handle_intercept_on(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "proxy_intercept_on entry");
    mitm_proxy::set_intercept_enabled(true);
    diag::log_tagged_fmt("mcp_burp", "proxy_intercept_on ok");
    auto st = mitm_proxy::get_stats();
    json data = stats_to_json(st);
    data["intercept_enabled"] = true;
    return tool_result_t::ok("intercept enabled", data);
}

tool_result_t handle_intercept_off(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "proxy_intercept_off entry");
    mitm_proxy::set_intercept_enabled(false);
    diag::log_tagged_fmt("mcp_burp", "proxy_intercept_off ok");
    auto st = mitm_proxy::get_stats();
    json data = stats_to_json(st);
    data["intercept_enabled"] = false;
    return tool_result_t::ok("intercept disabled", data);
}

tool_result_t handle_history(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "proxy_history entry");
    size_t limit = 0;
    if (p.contains("limit")) {
        if (!p["limit"].is_number_integer()) return tool_result_t::error("limit must be a non-negative integer");
        long long v = p["limit"].get<long long>();
        if (v < 0 || v > 100000) return tool_result_t::error("limit must be in 0..100000");
        limit = static_cast<size_t>(v);
    }
    std::string filter_host;
    if (p.contains("filter_host") && p["filter_host"].is_string()) filter_host = p["filter_host"].get<std::string>();
    diag::log_tagged_fmt("mcp_burp", "proxy_history limit=%zu filter_host=%s", limit, filter_host.c_str());

    auto hist = mitm_proxy::get_history(limit);
    json arr = json::array();
    size_t count = 0;
    for (const auto& ex : hist) {
        if (!filter_host.empty() && ex.target_host != filter_host) continue;
        arr.push_back(exchange_to_json(ex));
        ++count;
    }
    diag::log_tagged_fmt("mcp_burp", "proxy_history ok count=%zu", count);
    json result;
    result["exchanges"] = std::move(arr);
    result["count"] = static_cast<uint64_t>(count);
    return tool_result_t::ok("history count=" + std::to_string(count), result);
}

tool_result_t handle_held(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "proxy_held entry");
    auto held = mitm_proxy::get_held_exchanges();
    json arr = json::array();
    for (const auto& ex : held) arr.push_back(exchange_to_json(ex));
    diag::log_tagged_fmt("mcp_burp", "proxy_held ok count=%zu", held.size());
    json result;
    result["held"] = std::move(arr);
    result["count"] = static_cast<uint64_t>(held.size());
    return tool_result_t::ok("held count=" + std::to_string(held.size()), result);
}

tool_result_t handle_forward(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "proxy_forward entry");
    if (!p.contains("exchange_id") || !p["exchange_id"].is_number())
    {
        diag::log_tagged_fmt("mcp_burp", "proxy_forward missing_exchange_id");
        return tool_result_t::error("exchange_id parameter required");
    }
    uint64_t id = p["exchange_id"].get<uint64_t>();
    diag::log_tagged_fmt("mcp_burp", "proxy_forward id=%llu", static_cast<unsigned long long>(id));
    mitm_proxy::forward_exchange(id);
    diag::log_tagged_fmt("mcp_burp", "proxy_forward ok id=%llu", static_cast<unsigned long long>(id));
    json result;
    result["forwarded_id"] = static_cast<uint64_t>(id);
    auto st = mitm_proxy::get_stats();
    result["held_count"] = static_cast<uint64_t>(st.held_count);
    return tool_result_t::ok("forwarded exchange id=" + std::to_string(id), result);
}

tool_result_t handle_forward_all(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "proxy_forward_all entry");
    auto before = mitm_proxy::get_stats();
    mitm_proxy::forward_all();
    auto after = mitm_proxy::get_stats();
    diag::log_tagged_fmt("mcp_burp", "proxy_forward_all ok before_held=%zu after_held=%zu", before.held_count, after.held_count);
    json result = stats_to_json(after);
    result["before_held_count"] = static_cast<uint64_t>(before.held_count);
    result["after_held_count"] = static_cast<uint64_t>(after.held_count);
    return tool_result_t::ok("forwarded all held=" + std::to_string(before.held_count), result);
}

tool_result_t handle_drop(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "proxy_drop entry");
    if (!p.contains("exchange_id") || !p["exchange_id"].is_number())
    {
        diag::log_tagged_fmt("mcp_burp", "proxy_drop missing_exchange_id");
        return tool_result_t::error("exchange_id parameter required");
    }
    uint64_t id = p["exchange_id"].get<uint64_t>();
    diag::log_tagged_fmt("mcp_burp", "proxy_drop id=%llu", static_cast<unsigned long long>(id));
    mitm_proxy::drop_exchange(id);
    diag::log_tagged_fmt("mcp_burp", "proxy_drop ok id=%llu", static_cast<unsigned long long>(id));
    json result;
    result["dropped_id"] = static_cast<uint64_t>(id);
    auto st = mitm_proxy::get_stats();
    result["held_count"] = static_cast<uint64_t>(st.held_count);
    return tool_result_t::ok("dropped exchange id=" + std::to_string(id), result);
}

tool_result_t handle_drop_all(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "proxy_drop_all entry");
    auto before = mitm_proxy::get_stats();
    mitm_proxy::drop_all();
    auto after = mitm_proxy::get_stats();
    diag::log_tagged_fmt("mcp_burp", "proxy_drop_all ok before_held=%zu after_held=%zu", before.held_count, after.held_count);
    json result = stats_to_json(after);
    result["before_held_count"] = static_cast<uint64_t>(before.held_count);
    result["after_held_count"] = static_cast<uint64_t>(after.held_count);
    return tool_result_t::ok("dropped all held=" + std::to_string(before.held_count), result);
}

tool_result_t handle_stats(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "proxy_stats entry");
    auto st = mitm_proxy::get_stats();
    diag::log_tagged_fmt("mcp_burp", "proxy_stats ok running=%d requests=%llu history=%zu held=%zu",
        (int)st.running, static_cast<unsigned long long>(st.total_requests), st.history_size, st.held_count);
    return tool_result_t::ok("stats running=" + std::to_string(st.running ? 1 : 0) + " requests=" + std::to_string(st.total_requests), stats_to_json(st));
}

tool_result_t handle_modify_and_forward(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "proxy_modify_and_forward entry");
    if (!p.contains("exchange_id") || !p["exchange_id"].is_number())
    {
        diag::log_tagged_fmt("mcp_burp", "proxy_modify_and_forward missing_exchange_id");
        return tool_result_t::error("exchange_id parameter required");
    }
    if (!p.contains("modified_request_b64") || !p["modified_request_b64"].is_string())
    {
        diag::log_tagged_fmt("mcp_burp", "proxy_modify_and_forward missing_modified_request_b64");
        return tool_result_t::error("modified_request_b64 parameter required");
    }
    uint64_t id = p["exchange_id"].get<uint64_t>();
    std::string b64 = p["modified_request_b64"].get<std::string>();
    diag::log_tagged_fmt("mcp_burp", "proxy_modify_and_forward id=%llu b64_len=%zu", static_cast<unsigned long long>(id), b64.size());

    auto decoded = base64_decode(b64);
    if (decoded.empty() && !b64.empty())
    {
        diag::log_tagged_fmt("mcp_burp", "proxy_modify_and_forward invalid_base64");
        return tool_result_t::error("modified_request_b64 invalid base64");
    }
    diag::log_tagged_fmt("mcp_burp", "proxy_modify_and_forward decoded_len=%zu", decoded.size());
    mitm_proxy::forward_modified(id, decoded);
    diag::log_tagged_fmt("mcp_burp", "proxy_modify_and_forward ok id=%llu", static_cast<unsigned long long>(id));
    json result;
    result["modified_id"] = static_cast<uint64_t>(id);
    result["modified_request_size"] = static_cast<uint64_t>(decoded.size());
    auto st = mitm_proxy::get_stats();
    result["held_count"] = static_cast<uint64_t>(st.held_count);
    return tool_result_t::ok("modified and forwarded exchange id=" + std::to_string(id) + " bytes=" + std::to_string(decoded.size()), result);
}

tool_result_t handle_tls_observations(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "proxy_tls_observations entry");
    size_t limit = 0;
    if (p.contains("limit")) {
        if (!p["limit"].is_number_integer()) return tool_result_t::error("limit must be a non-negative integer");
        const auto value = p["limit"].get<long long>();
        if (value < 0 || value > 100000) return tool_result_t::error("limit must be in 0..100000");
        limit = static_cast<size_t>(value);
    }
    diag::log_tagged_fmt("mcp_burp", "proxy_tls_observations limit=%zu", limit);
    auto obs = mitm_proxy::get_tls_observations(limit);
    json arr = json::array();
    for (const auto& o : obs) arr.push_back(tls_obs_to_json(o));
    diag::log_tagged_fmt("mcp_burp", "proxy_tls_observations ok count=%zu", obs.size());
    json result;
    result["observations"] = std::move(arr);
    result["count"] = static_cast<uint64_t>(obs.size());
    return tool_result_t::ok("tls observations count=" + std::to_string(obs.size()), result);
}

tool_result_t handle_clear_history(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "proxy_clear_history entry");
    auto before = mitm_proxy::get_stats();
    mitm_proxy::clear_history();
    auto after = mitm_proxy::get_stats();
    diag::log_tagged_fmt("mcp_burp", "proxy_clear_history ok before_history=%zu after_history=%zu", before.history_size, after.history_size);
    json result = stats_to_json(after);
    result["before_history_size"] = static_cast<uint64_t>(before.history_size);
    result["after_history_size"] = static_cast<uint64_t>(after.history_size);
    return tool_result_t::ok("cleared history before=" + std::to_string(before.history_size) + " after=" + std::to_string(after.history_size), result);
}

tool_result_t handle_clear_tls_observations(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "proxy_clear_tls_observations entry");
    mitm_proxy::clear_tls_observations();
    diag::log_tagged_fmt("mcp_burp", "proxy_clear_tls_observations ok");
    auto st = mitm_proxy::get_stats();
    return tool_result_t::ok("cleared tls observations", stats_to_json(st));
}

}

void register_proxy_tools(mcp_standalone::server_t& srv)
{
    register_compat(srv, {
        "burp_proxy_manage", "burp",
        "Manage the Burp-style MITM proxy. Actions: start, stop, status, intercept_on, intercept_off, history, held, forward, forward_all, drop, drop_all, stats, modify_and_forward, tls_observations, clear_history, clear_tls_observations.",
        {{"action", "string", "start|stop|status|intercept_on|intercept_off|history|held|forward|forward_all|drop|drop_all|stats|modify_and_forward|tls_observations|clear_history|clear_tls_observations", true},
         {"bind_addr", "string", "Bind address for start (default 127.0.0.1)", false},
         {"bind_port", "number", "Bind port for start (default 8443)", false},
         {"decode_tls", "boolean", "Decode TLS for start (default true)", false},
         {"enable_h2", "boolean", "Enable HTTP/2 for start (default true)", false},
         {"enable_websocket", "boolean", "Enable WebSocket for start (default true)", false},
         {"exchange_id", "number", "Exchange ID for forward/drop/modify_and_forward", false},
         {"modified_request_b64", "string", "Base64-encoded modified request for modify_and_forward", false},
         {"limit", "number", "Max results for history/tls_observations (0 = all)", false},
         {"filter_host", "string", "Filter history by target host", false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "start") return handle_start(p);
            if (action == "stop") return handle_stop(p);
            if (action == "status") return handle_status(p);
            if (action == "intercept_on") return handle_intercept_on(p);
            if (action == "intercept_off") return handle_intercept_off(p);
            if (action == "history") return handle_history(p);
            if (action == "held") return handle_held(p);
            if (action == "forward") return handle_forward(p);
            if (action == "forward_all") return handle_forward_all(p);
            if (action == "drop") return handle_drop(p);
            if (action == "drop_all") return handle_drop_all(p);
            if (action == "stats") return handle_stats(p);
            if (action == "modify_and_forward") return handle_modify_and_forward(p);
            if (action == "tls_observations") return handle_tls_observations(p);
            if (action == "clear_history") return handle_clear_history(p);
            if (action == "clear_tls_observations") return handle_clear_tls_observations(p);
            return compat_unknown_action("burp_proxy_manage", action);
        },
        false
    });
}

}
}
}
