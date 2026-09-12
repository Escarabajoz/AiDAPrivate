#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef small
#undef small
#endif

#include "burp_repeater_mcp.hpp"
#include "repeater.hpp"
#include "../mitm_proxy.hpp"
#include "../../settings/standalone_compat.hpp"
#include "helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace repeater_mcp {

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

std::string upper_ascii(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return s;
}

bool header_name_equals(const std::string& name, const std::string& expected)
{
    return upper_ascii(name) == upper_ascii(expected);
}

struct parsed_request_t {
    std::string method;
    std::string target;
    std::string version;
    std::vector<std::pair<std::string, std::string>> headers;
    std::vector<uint8_t> body;
};

bool parse_raw_request(const std::vector<uint8_t>& raw, parsed_request_t& out)
{
    if (raw.empty()) return false;
    const uint8_t* data = raw.data();
    size_t len = raw.size();

    const uint8_t* sep = nullptr;
    for (size_t i = 0; i + 3 < len; ++i) {
        if (data[i] == '\r' && data[i+1] == '\n' && data[i+2] == '\r' && data[i+3] == '\n') {
            sep = data + i;
            break;
        }
    }
    if (!sep) return false;

    size_t header_block_len = static_cast<size_t>(sep - data);
    std::string header_block(reinterpret_cast<const char*>(data), header_block_len);
    out.body.assign(sep + 4, data + len);

    size_t first_eol = header_block.find("\r\n");
    if (first_eol == std::string::npos) return false;
    std::string request_line = header_block.substr(0, first_eol);

    size_t sp1 = request_line.find(' ');
    if (sp1 == std::string::npos) return false;
    size_t sp2 = request_line.find(' ', sp1 + 1);
    if (sp2 == std::string::npos) return false;

    out.method  = request_line.substr(0, sp1);
    out.target  = request_line.substr(sp1 + 1, sp2 - sp1 - 1);
    out.version = request_line.substr(sp2 + 1);

    size_t pos = first_eol + 2;
    while (pos < header_block.size()) {
        size_t eol = header_block.find("\r\n", pos);
        if (eol == std::string::npos) eol = header_block.size();
        std::string line = header_block.substr(pos, eol - pos);
        pos = eol + 2;
        if (line.empty()) continue;
        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string name = line.substr(0, colon);
        std::string val  = line.substr(colon + 1);
        while (!val.empty() && (val.front() == ' ' || val.front() == '\t'))
            val.erase(val.begin());
        out.headers.emplace_back(std::move(name), std::move(val));
    }
    return true;
}

std::vector<uint8_t> rebuild_raw_request(const parsed_request_t& req)
{
    std::string out;
    out.reserve(256 + req.headers.size() * 64 + req.body.size());
    out += req.method;
    out += " ";
    out += req.target;
    out += " ";
    out += req.version.empty() ? std::string("HTTP/1.1") : req.version;
    out += "\r\n";
    for (const auto& h : req.headers) {
        out += h.first;
        out += ": ";
        out += h.second;
        out += "\r\n";
    }
    out += "\r\n";
    out.append(reinterpret_cast<const char*>(req.body.data()), req.body.size());
    return std::vector<uint8_t>(out.begin(), out.end());
}

void apply_header_modifications(parsed_request_t& req, const json& mods)
{
    if (!mods.is_object()) return;
    for (auto it = mods.begin(); it != mods.end(); ++it) {
        const std::string& name = it.key();
        std::string val;
        if (it.value().is_string())
            val = it.value().get<std::string>();
        else if (it.value().is_number())
            val = std::to_string(it.value().get<int64_t>());
        else if (it.value().is_boolean())
            val = it.value().get<bool>() ? "true" : "false";
        else
            val = it.value().dump();

        bool replaced = false;
        for (auto& h : req.headers) {
            if (header_name_equals(h.first, name)) {
                h.second = val;
                replaced = true;
                break;
            }
        }
        if (!replaced)
            req.headers.emplace_back(name, val);
    }
}

void apply_body_modification(parsed_request_t& req, const std::string& body_str)
{
    req.body.assign(body_str.begin(), body_str.end());
    bool found_cl = false;
    for (auto& h : req.headers) {
        if (header_name_equals(h.first, "Content-Length")) {
            h.second = std::to_string(req.body.size());
            found_cl = true;
            break;
        }
    }
    if (!found_cl && !req.body.empty())
        req.headers.emplace_back("Content-Length", std::to_string(req.body.size()));
}

void apply_method_modification(parsed_request_t& req, const std::string& method)
{
    req.method = upper_ascii(method);
}

bool apply_modifications(std::vector<uint8_t>& raw_request, const json& params)
{
    if (!params.contains("modify_headers") && !params.contains("modify_body") && !params.contains("modify_method"))
        return true;

    parsed_request_t parsed;
    if (!parse_raw_request(raw_request, parsed))
        return false;

    if (params.contains("modify_method") && params["modify_method"].is_string())
        apply_method_modification(parsed, params["modify_method"].get<std::string>());

    if (params.contains("modify_headers") && params["modify_headers"].is_object())
        apply_header_modifications(parsed, params["modify_headers"]);

    if (params.contains("modify_body") && params["modify_body"].is_string())
        apply_body_modification(parsed, params["modify_body"].get<std::string>());

    raw_request = rebuild_raw_request(parsed);
    return true;
}

json send_result_to_json(const repeater::send_result_t& r, uint64_t tab_id, const std::vector<uint8_t>& request_sent)
{
    json out;
    out["tab_id"] = static_cast<uint64_t>(tab_id);
    out["success"] = r.success;
    out["status_code"] = r.status_code;
    json headers = json::array();
    for (const auto& h : r.response_headers)
        headers.push_back({h.first, h.second});
    out["response_headers"] = std::move(headers);
    out["response_body_b64"] = base64_encode_bytes(r.raw_response.data(), r.raw_response.size());
    size_t preview_len = std::min<size_t>(r.raw_response.size(), 2000);
    std::string preview(reinterpret_cast<const char*>(r.raw_response.data()), preview_len);
    out["response_body_preview"] = preview;
    out["latency_ms"] = static_cast<uint64_t>(r.latency_ms);
    std::string req_text(request_sent.begin(), request_sent.end());
    out["request_sent"] = req_text;
    out["error"] = r.error;
    return out;
}

json tab_to_json(const repeater::repeater_tab_t& t)
{
    json out;
    out["id"] = static_cast<uint64_t>(t.id);
    out["name"] = t.name;
    out["host"] = t.host;
    out["port"] = static_cast<uint16_t>(t.port);
    out["use_tls"] = t.use_tls;
    out["status_code"] = t.status_code;
    out["latency_ms"] = static_cast<uint64_t>(t.latency_ms);
    out["error"] = t.error;
    out["created_ms"] = static_cast<uint64_t>(t.created_ms);
    out["last_sent_ms"] = static_cast<uint64_t>(t.last_sent_ms);
    out["has_response"] = t.has_response;
    std::string req_text(t.raw_request.begin(), t.raw_request.end());
    out["request_text"] = req_text;
    out["request_b64"] = base64_encode_bytes(t.raw_request.data(), t.raw_request.size());
    if (!t.raw_response.empty())
    {
        std::string resp_text(t.raw_response.begin(), t.raw_response.end());
        out["response_text"] = resp_text;
        out["response_b64"] = base64_encode_bytes(t.raw_response.data(), t.raw_response.size());
        size_t preview_len = std::min<size_t>(t.raw_response.size(), 2000);
        out["response_preview"] = std::string(reinterpret_cast<const char*>(t.raw_response.data()), preview_len);
    }
    return out;
}

tool_result_t handle_send(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "repeater_send entry");
    if (!p.contains("host") || !p["host"].is_string() || p["host"].get<std::string>().empty())
    {
        diag::log_tagged_fmt("mcp_burp", "repeater_send missing_host");
        return tool_result_t::error("host parameter required");
    }
    const std::string host = p["host"].get<std::string>();
    uint16_t port = 443;
    if (p.contains("port")) {
        if (!p["port"].is_number_integer()) return tool_result_t::error("port must be an integer in 1..65535");
        long long v = p["port"].get<long long>();
        if (v < 1 || v > 65535) return tool_result_t::error("port must be in 1..65535");
        port = static_cast<uint16_t>(v);
    }
    bool use_tls = true;
    if (p.contains("use_tls") && p["use_tls"].is_boolean()) use_tls = p["use_tls"].get<bool>();
    std::string name;
    if (p.contains("name") && p["name"].is_string()) name = p["name"].get<std::string>();

    std::vector<uint8_t> raw_request;
    if (p.contains("raw_request") && p["raw_request"].is_string())
    {
        const std::string& s = p["raw_request"].get<std::string>();
        raw_request.assign(s.begin(), s.end());
    }
    else if (p.contains("raw_request_b64") && p["raw_request_b64"].is_string())
    {
        raw_request = base64_decode(p["raw_request_b64"].get<std::string>());
        if (raw_request.empty())
        {
            diag::log_tagged_fmt("mcp_burp", "repeater_send invalid_base64");
            return tool_result_t::error("raw_request_b64 invalid base64");
        }
    }
    else
    {
        diag::log_tagged_fmt("mcp_burp", "repeater_send missing_request");
        return tool_result_t::error("raw_request or raw_request_b64 parameter required");
    }

    if (!apply_modifications(raw_request, p))
    {
        diag::log_tagged_fmt("mcp_burp", "repeater_send modification_failed");
        return tool_result_t::error("failed to apply modifications to raw request");
    }

    uint64_t tab_id = repeater::create_tab(host, port, use_tls, raw_request, name);
    diag::log_tagged_fmt("mcp_burp", "repeater_send created_tab id=%llu host=%s", static_cast<unsigned long long>(tab_id), host.c_str());

    repeater::send_result_t result = repeater::send(tab_id);
    json data = send_result_to_json(result, tab_id, raw_request);
    if (result.success)
    {
        diag::log_tagged_fmt("mcp_burp", "repeater_send ok tab_id=%llu status=%d", static_cast<unsigned long long>(tab_id), result.status_code);
        return tool_result_t::ok("repeater send status=" + std::to_string(result.status_code) + " tab_id=" + std::to_string(tab_id), data);
    }
    diag::log_tagged_fmt("mcp_burp", "repeater_send failed tab_id=%llu err=%s", static_cast<unsigned long long>(tab_id), result.error.c_str());
    return error_with_data("repeater send failed: " + result.error, data);
}

tool_result_t handle_send_raw(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "repeater_send_raw entry");
    if (!p.contains("host") || !p["host"].is_string() || p["host"].get<std::string>().empty())
    {
        diag::log_tagged_fmt("mcp_burp", "repeater_send_raw missing_host");
        return tool_result_t::error("host parameter required");
    }
    const std::string host = p["host"].get<std::string>();
    uint16_t port = 443;
    if (p.contains("port")) {
        if (!p["port"].is_number_integer()) return tool_result_t::error("port must be an integer in 1..65535");
        long long v = p["port"].get<long long>();
        if (v < 1 || v > 65535) return tool_result_t::error("port must be in 1..65535");
        port = static_cast<uint16_t>(v);
    }
    bool use_tls = true;
    if (p.contains("use_tls") && p["use_tls"].is_boolean()) use_tls = p["use_tls"].get<bool>();
    int timeout_ms = 15000;
    if (p.contains("timeout_ms")) {
        if (!p["timeout_ms"].is_number_integer()) return tool_result_t::error("timeout_ms must be an integer");
        long long tv = p["timeout_ms"].get<long long>();
        if (tv < 1 || tv > 300000) return tool_result_t::error("timeout_ms must be in 1..300000");
        timeout_ms = static_cast<int>(tv);
    }
    bool follow_redirects = false;
    if (p.contains("follow_redirects") && p["follow_redirects"].is_boolean()) follow_redirects = p["follow_redirects"].get<bool>();

    std::vector<uint8_t> raw_request;
    if (p.contains("raw_request_b64") && p["raw_request_b64"].is_string())
    {
        raw_request = base64_decode(p["raw_request_b64"].get<std::string>());
        if (raw_request.empty())
        {
            diag::log_tagged_fmt("mcp_burp", "repeater_send_raw invalid_base64");
            return tool_result_t::error("raw_request_b64 invalid base64");
        }
    }
    else if (p.contains("raw_request") && p["raw_request"].is_string())
    {
        const std::string& s = p["raw_request"].get<std::string>();
        raw_request.assign(s.begin(), s.end());
    }
    else
    {
        diag::log_tagged_fmt("mcp_burp", "repeater_send_raw missing_request");
        return tool_result_t::error("raw_request_b64 or raw_request parameter required");
    }

    if (!apply_modifications(raw_request, p))
    {
        diag::log_tagged_fmt("mcp_burp", "repeater_send_raw modification_failed");
        return tool_result_t::error("failed to apply modifications to raw request");
    }

    repeater::send_result_t result = repeater::send_raw(host, port, use_tls, raw_request, timeout_ms, follow_redirects);
    json data = send_result_to_json(result, 0, raw_request);
    if (result.success)
    {
        diag::log_tagged_fmt("mcp_burp", "repeater_send_raw ok host=%s status=%d", host.c_str(), result.status_code);
        return tool_result_t::ok("repeater send_raw status=" + std::to_string(result.status_code), data);
    }
    diag::log_tagged_fmt("mcp_burp", "repeater_send_raw failed host=%s err=%s", host.c_str(), result.error.c_str());
    return error_with_data("repeater send_raw failed: " + result.error, data);
}

tool_result_t handle_send_from_exchange(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "repeater_send_from_exchange entry");
    if (!p.contains("exchange_id") || !p["exchange_id"].is_number_unsigned())
    {
        diag::log_tagged_fmt("mcp_burp", "repeater_send_from_exchange missing_exchange_id");
        return tool_result_t::error("exchange_id parameter (unsigned number) required");
    }
    const uint64_t exchange_id = p["exchange_id"].get<uint64_t>();
    diag::log_tagged_fmt("mcp_burp", "repeater_send_from_exchange id=%llu", static_cast<unsigned long long>(exchange_id));

    const auto exchanges = mitm_proxy::get_history_by_ids({exchange_id});
    if (exchanges.empty())
    {
        diag::log_tagged_fmt("mcp_burp", "repeater_send_from_exchange not_found id=%llu", static_cast<unsigned long long>(exchange_id));
        return tool_result_t::error("exchange not found");
    }

    const auto& ex = exchanges.front();
    if (ex.raw_request.empty())
    {
        diag::log_tagged_fmt("mcp_burp", "repeater_send_from_exchange empty_request id=%llu", static_cast<unsigned long long>(exchange_id));
        return tool_result_t::error("exchange has no raw request data");
    }

    std::vector<uint8_t> raw_request = ex.raw_request;
    std::string host = ex.target_host;
    uint16_t port = ex.target_port;
    bool use_tls = ex.is_tls;

    if (host.empty())
    {
        diag::log_tagged_fmt("mcp_burp", "repeater_send_from_exchange empty_host id=%llu", static_cast<unsigned long long>(exchange_id));
        return tool_result_t::error("exchange has no target host");
    }

    if (!apply_modifications(raw_request, p))
    {
        diag::log_tagged_fmt("mcp_burp", "repeater_send_from_exchange modification_failed id=%llu", static_cast<unsigned long long>(exchange_id));
        return tool_result_t::error("failed to apply modifications to raw request");
    }

    int timeout_ms = 15000;
    if (p.contains("timeout_ms")) {
        if (!p["timeout_ms"].is_number_integer()) return tool_result_t::error("timeout_ms must be an integer");
        const auto value = p["timeout_ms"].get<long long>();
        if (value < 1 || value > 300000) return tool_result_t::error("timeout_ms must be in 1..300000");
        timeout_ms = static_cast<int>(value);
    }
    bool follow_redirects = false;
    if (p.contains("follow_redirects") && p["follow_redirects"].is_boolean()) follow_redirects = p["follow_redirects"].get<bool>();

    repeater::send_result_t result = repeater::send_raw(host, port, use_tls, raw_request, timeout_ms, follow_redirects);
    json data = send_result_to_json(result, 0, raw_request);
    data["exchange_id"] = static_cast<uint64_t>(exchange_id);
    if (result.success)
    {
        diag::log_tagged_fmt("mcp_burp", "repeater_send_from_exchange ok id=%llu status=%d", static_cast<unsigned long long>(exchange_id), result.status_code);
        return tool_result_t::ok("repeater send_from_exchange status=" + std::to_string(result.status_code), data);
    }
    diag::log_tagged_fmt("mcp_burp", "repeater_send_from_exchange failed id=%llu err=%s", static_cast<unsigned long long>(exchange_id), result.error.c_str());
    return error_with_data("repeater send_from_exchange failed: " + result.error, data);
}

tool_result_t handle_list_tabs(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "repeater_list_tabs entry");
    auto tabs = repeater::list_tabs();
    json arr = json::array();
    for (const auto& t : tabs)
        arr.push_back(tab_to_json(t));
    diag::log_tagged_fmt("mcp_burp", "repeater_list_tabs ok count=%zu", tabs.size());
    json r;
    r["tabs"] = std::move(arr);
    r["count"] = static_cast<uint64_t>(tabs.size());
    return tool_result_t::ok("tabs count=" + std::to_string(tabs.size()), r);
}

tool_result_t handle_get_tab(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "repeater_get_tab entry");
    if (!p.contains("tab_id") || !p["tab_id"].is_number_unsigned())
    {
        diag::log_tagged_fmt("mcp_burp", "repeater_get_tab missing_tab_id");
        return tool_result_t::error("tab_id parameter (unsigned number) required");
    }
    const uint64_t tab_id = p["tab_id"].get<uint64_t>();
    repeater::repeater_tab_t tab;
    if (!repeater::get_tab(tab_id, tab))
    {
        diag::log_tagged_fmt("mcp_burp", "repeater_get_tab not_found id=%llu", static_cast<unsigned long long>(tab_id));
        return tool_result_t::error("tab not found");
    }
    diag::log_tagged_fmt("mcp_burp", "repeater_get_tab ok id=%llu", static_cast<unsigned long long>(tab_id));
    return tool_result_t::ok("tab " + std::to_string(tab_id), tab_to_json(tab));
}

tool_result_t handle_close_tab(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "repeater_close_tab entry");
    if (!p.contains("tab_id") || !p["tab_id"].is_number_unsigned())
    {
        diag::log_tagged_fmt("mcp_burp", "repeater_close_tab missing_tab_id");
        return tool_result_t::error("tab_id parameter (unsigned number) required");
    }
    const uint64_t tab_id = p["tab_id"].get<uint64_t>();
    if (!repeater::close_tab(tab_id))
    {
        diag::log_tagged_fmt("mcp_burp", "repeater_close_tab not_found id=%llu", static_cast<unsigned long long>(tab_id));
        return tool_result_t::error("tab not found");
    }
    diag::log_tagged_fmt("mcp_burp", "repeater_close_tab ok id=%llu", static_cast<unsigned long long>(tab_id));
    json r;
    r["tab_id"] = static_cast<uint64_t>(tab_id);
    r["closed"] = true;
    return tool_result_t::ok("tab " + std::to_string(tab_id) + " closed", r);
}

tool_result_t handle_update_request(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "repeater_update_request entry");
    if (!p.contains("tab_id") || !p["tab_id"].is_number_unsigned())
    {
        diag::log_tagged_fmt("mcp_burp", "repeater_update_request missing_tab_id");
        return tool_result_t::error("tab_id parameter (unsigned number) required");
    }
    const uint64_t tab_id = p["tab_id"].get<uint64_t>();

    std::vector<uint8_t> raw_request;
    if (p.contains("raw_request") && p["raw_request"].is_string())
    {
        const std::string& s = p["raw_request"].get<std::string>();
        raw_request.assign(s.begin(), s.end());
    }
    else if (p.contains("raw_request_b64") && p["raw_request_b64"].is_string())
    {
        raw_request = base64_decode(p["raw_request_b64"].get<std::string>());
        if (raw_request.empty())
        {
            diag::log_tagged_fmt("mcp_burp", "repeater_update_request invalid_base64");
            return tool_result_t::error("raw_request_b64 invalid base64");
        }
    }
    else
    {
        diag::log_tagged_fmt("mcp_burp", "repeater_update_request missing_request");
        return tool_result_t::error("raw_request or raw_request_b64 parameter required");
    }

    if (!repeater::update_tab_request(tab_id, raw_request))
    {
        diag::log_tagged_fmt("mcp_burp", "repeater_update_request not_found id=%llu", static_cast<unsigned long long>(tab_id));
        return tool_result_t::error("tab not found");
    }
    diag::log_tagged_fmt("mcp_burp", "repeater_update_request ok id=%llu req_len=%zu", static_cast<unsigned long long>(tab_id), raw_request.size());
    json r;
    r["tab_id"] = static_cast<uint64_t>(tab_id);
    r["updated"] = true;
    r["request_length"] = static_cast<uint64_t>(raw_request.size());
    return tool_result_t::ok("tab request updated", r);
}

tool_result_t handle_update_target(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "repeater_update_target entry");
    if (!p.contains("tab_id") || !p["tab_id"].is_number_unsigned())
    {
        diag::log_tagged_fmt("mcp_burp", "repeater_update_target missing_tab_id");
        return tool_result_t::error("tab_id parameter (unsigned number) required");
    }
    const uint64_t tab_id = p["tab_id"].get<uint64_t>();
    if (!p.contains("host") || !p["host"].is_string() || p["host"].get<std::string>().empty())
    {
        diag::log_tagged_fmt("mcp_burp", "repeater_update_target missing_host");
        return tool_result_t::error("host parameter required");
    }
    const std::string host = p["host"].get<std::string>();
    uint16_t port = 443;
    if (p.contains("port") && p["port"].is_number()) port = static_cast<uint16_t>(p["port"].get<int>());
    bool use_tls = true;
    if (p.contains("use_tls") && p["use_tls"].is_boolean()) use_tls = p["use_tls"].get<bool>();

    if (!repeater::update_tab_target(tab_id, host, port, use_tls))
    {
        diag::log_tagged_fmt("mcp_burp", "repeater_update_target not_found id=%llu", static_cast<unsigned long long>(tab_id));
        return tool_result_t::error("tab not found");
    }
    diag::log_tagged_fmt("mcp_burp", "repeater_update_target ok id=%llu host=%s port=%u tls=%d",
        static_cast<unsigned long long>(tab_id), host.c_str(), static_cast<unsigned>(port), static_cast<int>(use_tls));
    json r;
    r["tab_id"] = static_cast<uint64_t>(tab_id);
    r["updated"] = true;
    r["host"] = host;
    r["port"] = static_cast<uint16_t>(port);
    r["use_tls"] = use_tls;
    return tool_result_t::ok("tab target updated", r);
}

}

void register_repeater_tools(mcp_standalone::server_t& srv)
{
    register_compat(srv, {
        "burp_repeater_manage", "burp",
        "Manage the Burp-style Repeater: resend HTTP requests with modifications. Actions: send, send_raw, list_tabs, get_tab, close_tab, send_from_exchange, update_request, update_target.",
        {{"action", "string", "send|send_raw|list_tabs|get_tab|close_tab|send_from_exchange|update_request|update_target", true},
         {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "send") return handle_send(p);
            if (action == "send_raw") return handle_send_raw(p);
            if (action == "list_tabs") return handle_list_tabs(p);
            if (action == "get_tab") return handle_get_tab(p);
            if (action == "close_tab") return handle_close_tab(p);
            if (action == "send_from_exchange") return handle_send_from_exchange(p);
            if (action == "update_request") return handle_update_request(p);
            if (action == "update_target") return handle_update_target(p);
            return compat_unknown_action("burp_repeater_manage", action);
        },
        false
    });
}

}
}
}
