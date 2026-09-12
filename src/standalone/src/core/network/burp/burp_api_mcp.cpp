#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "burp_api_mcp.hpp"
#include "api_definition.hpp"
#include "audit_http.hpp"
#include "graphql.hpp"
#include "ws_editor.hpp"
#include "burp_logger.hpp"
#include "report_generator.hpp"
#include "issue.hpp"

#include "../../settings/standalone_compat.hpp"
#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace api_mcp {

namespace {

using tool_result_t = mcp_standalone::tool_result_t;
using json = nlohmann::json;

tool_result_t error_with_data(const std::string& text, json data)
{
    return tool_result_t{false, text, std::move(data)};
}

struct url_log_t
{
    std::string host;
    std::string path;
    bool has_query = false;
    size_t length = 0;
};

url_log_t summarize_url_for_log(const std::string& url)
{
    url_log_t out;
    out.length = url.size();
    std::string scheme, host, path;
    uint16_t port = 0;
    if (audit_http::parse_url(url, scheme, host, port, path))
    {
        out.host = host;
        size_t q = path.find('?');
        size_t f = path.find('#');
        out.has_query = q != std::string::npos;
        size_t path_end = path.size();
        if (q != std::string::npos) path_end = q;
        if (f != std::string::npos && f < path_end) path_end = f;
        out.path = path.substr(0, path_end);
    }
    else
    {
        size_t cursor = 0;
        size_t scheme_pos = url.find("://");
        if (scheme_pos != std::string::npos) cursor = scheme_pos + 3;
        size_t host_end = url.find_first_of("/?#", cursor);
        if (host_end == std::string::npos) host_end = url.size();
        if (host_end > cursor) out.host = url.substr(cursor, host_end - cursor);
        size_t path_start = url.find('/', cursor);
        size_t q = url.find('?', cursor);
        size_t f = url.find('#', cursor);
        out.has_query = q != std::string::npos;
        size_t path_end = url.size();
        if (q != std::string::npos) path_end = q;
        if (f != std::string::npos && f < path_end) path_end = f;
        if (path_start != std::string::npos && path_start < path_end) out.path = url.substr(path_start, path_end - path_start);
    }
    if (out.host.empty()) out.host = "<missing>";
    if (out.path.empty()) out.path = "/";
    if (out.path.size() > 240)
    {
        out.path.resize(240);
        out.path += "...";
    }
    return out;
}

std::string lower_ascii_copy(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool url_has_explicit_port(const std::string& url)
{
    const size_t scheme = url.find("://");
    const size_t host_start = scheme == std::string::npos ? 0 : scheme + 3;
    if (host_start >= url.size())
        return false;
    const size_t host_end = url.find_first_of("/?#", host_start);
    const size_t end = host_end == std::string::npos ? url.size() : host_end;
    if (url[host_start] == '[')
    {
        const size_t close = url.find(']', host_start + 1);
        return close != std::string::npos && close + 1 < end && url[close + 1] == ':';
    }
    return url.find(':', host_start) != std::string::npos && url.find(':', host_start) < end;
}

bool parse_port_u16(const std::string& text, uint16_t& port)
{
    try
    {
        size_t parsed_len = 0;
        const unsigned long parsed = std::stoul(text, &parsed_len);
        if (parsed_len != text.size() || parsed == 0 || parsed > 65535)
            return false;
        port = static_cast<uint16_t>(parsed);
        return true;
    }
    catch (...) { return false; }
}

bool json_port_u16(const json& value, uint16_t& port)
{
    if (value.is_number_unsigned())
    {
        const unsigned long long parsed = value.get<unsigned long long>();
        if (parsed == 0 || parsed > 65535)
            return false;
        port = static_cast<uint16_t>(parsed);
        return true;
    }
    if (value.is_number_integer())
    {
        const long long parsed = value.get<long long>();
        if (parsed <= 0 || parsed > 65535)
            return false;
        port = static_cast<uint16_t>(parsed);
        return true;
    }
    if (value.is_string())
        return parse_port_u16(value.get<std::string>(), port);
    return false;
}

bool apply_ws_url(ws_editor::ws_connection_config_t& cfg, const std::string& url, std::string& error)
{
    const size_t scheme_sep = url.find("://");
    if (scheme_sep == std::string::npos)
    {
        error = "WebSocket URL requires ws:// or wss:// scheme";
        return false;
    }
    std::string scheme = url.substr(0, scheme_sep);
    scheme = lower_ascii_copy(scheme);
    if (scheme != "ws" && scheme != "wss")
    {
        error = "WebSocket URL scheme must be ws or wss";
        return false;
    }
    const size_t authority_start = scheme_sep + 3;
    const size_t authority_end = url.find_first_of("/?#", authority_start);
    const std::string authority = authority_end == std::string::npos
        ? url.substr(authority_start)
        : url.substr(authority_start, authority_end - authority_start);
    if (authority.empty())
    {
        error = "WebSocket URL host is empty";
        return false;
    }
    std::string host;
    uint16_t port = scheme == "wss" ? 443 : 80;
    if (authority.front() == '[')
    {
        const size_t close = authority.find(']');
        if (close == std::string::npos || close == 1)
        {
            error = "invalid bracketed WebSocket host";
            return false;
        }
        host = authority.substr(1, close - 1);
        if (close + 1 < authority.size())
        {
            if (authority[close + 1] != ':')
            {
                error = "invalid WebSocket authority";
                return false;
            }
            if (!parse_port_u16(authority.substr(close + 2), port))
            {
                error = "invalid WebSocket URL port";
                return false;
            }
        }
    }
    else
    {
        const size_t colon = authority.rfind(':');
        if (colon != std::string::npos && authority.find(':') == colon)
        {
            host = authority.substr(0, colon);
            if (!parse_port_u16(authority.substr(colon + 1), port))
            {
                error = "invalid WebSocket URL port";
                return false;
            }
        }
        else
        {
            host = authority;
        }
    }
    if (host.empty() || port == 0)
    {
        error = "WebSocket URL host or port is empty";
        return false;
    }
    const bool explicit_port = url_has_explicit_port(url);
    if (!explicit_port)
        port = scheme == "wss" ? 443 : 80;
    std::string path = authority_end == std::string::npos ? std::string("/") : url.substr(authority_end);
    if (path.empty())
        path = "/";
    else if (path[0] != '/')
        path.insert(path.begin(), '/');
    cfg.scheme = scheme;
    cfg.host = host;
    cfg.port = port;
    cfg.path = path.empty() ? std::string("/") : path;
    return true;
}

std::map<std::string, std::string> json_obj_to_map(const json& j)
{
    std::map<std::string, std::string> out;
    if (!j.is_object()) return out;
    for (auto it = j.begin(); it != j.end(); ++it) {
        if (it.value().is_string()) out[it.key()] = it.value().get<std::string>();
        else                          out[it.key()] = it.value().dump();
    }
    return out;
}

std::vector<uint8_t> base64_decode(const std::string& s)
{
    static const int8_t table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };
    std::vector<uint8_t> out;
    out.reserve((s.size() / 4) * 3);
    uint32_t val = 0;
    int bits = 0;
    for (unsigned char c : s) {
        if (c == '=') break;
        int8_t v = table[c];
        if (v < 0) continue;
        val = (val << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((val >> bits) & 0xFF));
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

json api_collection_ids_json(const std::vector<api_definition::api_collection_t>& cols)
{
    json arr = json::array();
    for (const auto& c : cols) arr.push_back(c.id);
    return arr;
}

json ws_status_to_json(const ws_editor::ws_status_t& s)
{
    json j;
    j["id"] = s.id;
    j["conn_id"] = s.id;
    j["url"] = s.url;
    j["connected"] = s.connected;
    j["frames_sent"] = static_cast<uint64_t>(s.frames_sent);
    j["frames_received"] = static_cast<uint64_t>(s.frames_received);
    j["opened_ms"] = s.opened_ms;
    j["last_error"] = s.last_error;
    return j;
}

json count_or_null(bool available, size_t value)
{
    return available ? json(static_cast<uint64_t>(value)) : json(nullptr);
}

json bool_or_null(bool available, bool value)
{
    return available ? json(value) : json(nullptr);
}

bool json_u64_value(const json& value, uint64_t& out)
{
    if (value.is_number_unsigned()) {
        out = value.get<uint64_t>();
        return true;
    }
    if (value.is_number_integer()) {
        const int64_t v = value.get<int64_t>();
        if (v >= 0) {
            out = static_cast<uint64_t>(v);
            return true;
        }
    }
    if (value.is_string()) {
        try {
            const std::string text = value.get<std::string>();
            size_t used = 0;
            out = std::stoull(text, &used);
            return used == text.size();
        } catch (...) {
        }
    }
    return false;
}

json ws_status_or_null(bool available, const ws_editor::ws_status_t& s)
{
    return available ? ws_status_to_json(s) : json(nullptr);
}

json ws_send_result_to_json(uint64_t id,
                            const std::string& type,
                            int opcode,
                            size_t byte_count,
                            bool before_available,
                            const ws_editor::ws_status_t& before,
                            size_t before_recorded_count,
                            bool after_available,
                            const ws_editor::ws_status_t& after,
                            size_t after_recorded_count)
{
    json out;
    out["conn_id"] = id;
    out["connection_id"] = id;
    out["sent"] = true;
    out["type"] = type;
    out["opcode"] = opcode;
    out["byte_count"] = static_cast<uint64_t>(byte_count);
    out["connected_before"] = bool_or_null(before_available, before.connected);
    out["connected_after"] = bool_or_null(after_available, after.connected);
    out["frame_count_before"] = count_or_null(before_available, before.frames_sent);
    out["frame_count_after"] = count_or_null(after_available, after.frames_sent);
    out["frames_sent_before"] = count_or_null(before_available, before.frames_sent);
    out["frames_sent_after"] = count_or_null(after_available, after.frames_sent);
    out["frames_received_before"] = count_or_null(before_available, before.frames_received);
    out["frames_received_after"] = count_or_null(after_available, after.frames_received);
    out["recorded_frame_count_before"] = count_or_null(before_available, before_recorded_count);
    out["recorded_frame_count_after"] = count_or_null(after_available, after_recorded_count);
    if (before_available && after_available)
    {
        out["frame_count_delta"] = static_cast<int64_t>(after.frames_sent) - static_cast<int64_t>(before.frames_sent);
        out["recorded_frame_count_delta"] = static_cast<int64_t>(after_recorded_count) - static_cast<int64_t>(before_recorded_count);
    }
    else
    {
        out["frame_count_delta"] = nullptr;
        out["recorded_frame_count_delta"] = nullptr;
    }
    out["before"] = ws_status_or_null(before_available, before);
    out["after"] = ws_status_or_null(after_available, after);
    return out;
}

tool_result_t tool_api_import(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "api_import format=%s source_len=%zu", params.value("format", std::string("auto")).c_str(), params.value("source", std::string()).size());
    if (!params.is_object())
    {
        diag::log_tagged_fmt("mcp_burp", "api_import invalid_params");
        return tool_result_t::error("invalid params");
    }
    std::string format = params.value("format", std::string("auto"));
    std::string source = params.value("source", std::string());
    if (source.empty())
    {
        diag::log_tagged_fmt("mcp_burp", "api_import missing_source");
        return tool_result_t::error("source is required");
    }
    api_definition::api_format_t fmt = api_definition::api_format_t::auto_detect;
    api_definition::parse_format(format, fmt);

    uint64_t id = 0;
    if (source.rfind("text:", 0) == 0) {
        diag::log_tagged_fmt("mcp_burp", "api_import from_text format=%s", format.c_str());
        id = api_definition::import_from_text(source.substr(5), fmt);
    } else if (source.rfind("url:", 0) == 0) {
        diag::log_tagged_fmt("mcp_burp", "api_import from_url url=%s", source.substr(4).c_str());
        id = api_definition::import_from_url(source.substr(4));
    } else if (source.rfind("http://", 0) == 0 || source.rfind("https://", 0) == 0) {
        diag::log_tagged_fmt("mcp_burp", "api_import from_url url=%s", source.c_str());
        id = api_definition::import_from_url(source);
    } else {
        diag::log_tagged_fmt("mcp_burp", "api_import from_file path=%s", source.c_str());
        id = api_definition::import_from_file(source, fmt);
    }
    if (id == 0)
    {
        diag::log_tagged_fmt("mcp_burp", "api_import failed err=%s", api_definition::last_error().c_str());
        return tool_result_t::error(api_definition::last_error());
    }

    diag::log_tagged_fmt("mcp_burp", "api_import ok collection_id=%llu", static_cast<unsigned long long>(id));
    json out;
    api_definition::api_collection_t col;
    if (api_definition::get_collection(id, col)) out = api_definition::collection_to_json(col);
    else                                          out["collection_id"] = id;
    return tool_result_t::ok(out.dump(2), out);
}

tool_result_t tool_api_list(const json& params)
{
    (void)params;
    diag::log_tagged_fmt("mcp_burp", "api_list entry");
    auto cols = api_definition::list_collections();
    json arr = json::array();
    for (const auto& c : cols) arr.push_back(api_definition::collection_to_json(c));
    diag::log_tagged_fmt("mcp_burp", "api_list ok count=%zu", cols.size());
    json out;
    out["count"]       = arr.size();
    out["collections"] = std::move(arr);
    return tool_result_t::ok(out.dump(2), out);
}

tool_result_t tool_api_get(const json& params)
{
    uint64_t id = params.value("collection_id", 0ull);
    diag::log_tagged_fmt("mcp_burp", "api_get collection_id=%llu", static_cast<unsigned long long>(id));
    api_definition::api_collection_t col;
    if (!api_definition::get_collection(id, col))
    {
        diag::log_tagged_fmt("mcp_burp", "api_get not_found id=%llu", static_cast<unsigned long long>(id));
        return tool_result_t::error("collection not found");
    }
    diag::log_tagged_fmt("mcp_burp", "api_get ok id=%llu", static_cast<unsigned long long>(id));
    json j = api_definition::collection_to_json(col);
    return tool_result_t::ok(j.dump(2), j);
}

tool_result_t tool_api_remove(const json& params)
{
    uint64_t id = params.value("collection_id", 0ull);
    diag::log_tagged_fmt("mcp_burp", "api_remove collection_id=%llu", static_cast<unsigned long long>(id));
    auto before = api_definition::list_collections();
    api_definition::api_collection_t removed_collection;
    bool had_collection = api_definition::get_collection(id, removed_collection);
    bool ok = api_definition::remove_collection(id);
    if (!ok)
    {
        diag::log_tagged_fmt("mcp_burp", "api_remove not_found id=%llu", static_cast<unsigned long long>(id));
        return tool_result_t::error("collection not found");
    }
    auto after = api_definition::list_collections();
    json out;
    out["action"] = "remove_collection";
    out["collection_id"] = id;
    out["id"] = id;
    out["collection_name"] = had_collection ? removed_collection.name : std::string();
    out["removed"] = true;
    out["before_count"] = static_cast<uint64_t>(before.size());
    out["after_count"] = static_cast<uint64_t>(after.size());
    out["remaining_count"] = static_cast<uint64_t>(after.size());
    out["remaining_ids"] = api_collection_ids_json(after);
    if (had_collection) out["collection"] = api_definition::collection_to_json(removed_collection);
    diag::log_tagged_fmt("mcp_burp", "api_remove ok id=%llu", static_cast<unsigned long long>(id));
    return tool_result_t::ok(out.dump(2), out);
}

tool_result_t tool_api_send(const json& params)
{
    uint64_t cid = params.value("collection_id", 0ull);
    std::string rid = params.value("request_id", std::string());
    diag::log_tagged_fmt("mcp_burp", "api_send collection_id=%llu request_id=%s", static_cast<unsigned long long>(cid), rid.c_str());
    api_definition::api_collection_t col;
    if (!api_definition::get_collection(cid, col))
    {
        diag::log_tagged_fmt("mcp_burp", "api_send collection_not_found id=%llu", static_cast<unsigned long long>(cid));
        return tool_result_t::error("collection not found");
    }
    const api_definition::api_request_template_t* tpl = nullptr;
    for (const auto& r : col.requests) if (r.id == rid) { tpl = &r; break; }
    if (!tpl)
    {
        diag::log_tagged_fmt("mcp_burp", "api_send request_not_found rid=%s", rid.c_str());
        return tool_result_t::error("request not found");
    }

    auto pv = json_obj_to_map(params.value("path_values", json::object()));
    auto qv = json_obj_to_map(params.value("query_values", json::object()));
    auto hv = json_obj_to_map(params.value("header_values", json::object()));
    std::string body = params.value("body_override", std::string());

    auto raw = api_definition::render_to_raw_request(*tpl, pv, qv, hv, body);

    std::string scheme, host, path; uint16_t port = 0;
    if (!audit_http::parse_url(tpl->base_url, scheme, host, port, path))
    {
        diag::log_tagged_fmt("mcp_burp", "api_send url_parse_failed url=%s", tpl->base_url.c_str());
        json err;
        err["error"] = "base_url parse failed";
        err["collection_id"] = cid;
        err["request_id"] = rid;
        err["base_url"] = tpl->base_url;
        return error_with_data("base_url parse failed", err);
    }
    bool tls = (scheme == "https");
    diag::log_tagged_fmt("mcp_burp", "api_send sending host=%s port=%d tls=%d", host.c_str(), (int)port, (int)tls);

    audit_http::send_options_t opts;
    opts.timeout_ms = 20000;
    opts.enforce_scope = params.value("enforce_scope", false);
    auto ex = audit_http::send(raw, host, port, tls, opts);
    if (!ex.has_value())
    {
        std::string err = audit_http::last_error();
        diag::log_tagged_fmt("mcp_burp", "api_send send_failed err=%s", err.c_str());
        json data;
        data["error"] = err;
        data["collection_id"] = cid;
        data["request_id"] = rid;
        data["scheme"] = scheme;
        data["host"] = host;
        data["port"] = port;
        data["path"] = path;
        data["tls"] = tls;
        data["base_url"] = tpl->base_url;
        data["status"] = "transport_failed";
        return error_with_data(err, data);
    }

    burp::logger::record(burp::logger::source_t::api, *ex);
    diag::log_tagged_fmt("mcp_burp", "api_send ok status=%d latency_ms=%lld host=%s", ex->status_code, static_cast<long long>(ex->latency_ms), host.c_str());

    json out;
    out["id"]          = ex->id;
    out["status"]      = ex->status_code;
    out["latency_ms"]  = ex->latency_ms;
    out["host"]        = ex->host;
    out["path"]        = ex->path;
    out["response_bytes"] = ex->resp_body.size();
    json hdrs = json::array();
    for (const auto& h : ex->resp_headers) hdrs.push_back(json{{"name", h.first}, {"value", h.second}});
    out["response_headers"] = std::move(hdrs);
    out["response_body_preview"] = std::string(
        reinterpret_cast<const char*>(ex->resp_body.data()),
        std::min<size_t>(ex->resp_body.size(), 8192));
    return tool_result_t::ok(out.dump(2), out);
}

tool_result_t tool_api_audit(const json& params)
{
    uint64_t cid = params.value("collection_id", 0ull);
    diag::log_tagged_fmt("mcp_burp", "api_audit collection_id=%llu", static_cast<unsigned long long>(cid));
    auto auth = json_obj_to_map(params.value("auth_values", json::object()));
    api_definition::audit_result_t res;
    bool ok = api_definition::audit_entire_collection(cid, auth, res);
    if (!ok)
    {
        diag::log_tagged_fmt("mcp_burp", "api_audit failed err=%s", api_definition::last_error().c_str());
        return tool_result_t::error(api_definition::last_error());
    }
    diag::log_tagged_fmt("mcp_burp", "api_audit ok audit_id=%llu requests_sent=%zu issues=%zu", static_cast<unsigned long long>(res.audit_id), res.requests_sent, res.issues_raised);
    json out;
    out["audit_id"]        = res.audit_id;
    out["requests_sent"]   = res.requests_sent;
    out["requests_failed"] = res.requests_failed;
    out["issues_raised"]   = res.issues_raised;
    out["status"]          = res.status;
    if (res.requests_sent == 0)
    {
        out["ok"] = false;
        out["error"] = "api_audit_sent_no_requests";
        diag::log_tagged_fmt("mcp_burp", "api_audit no_requests_sent audit_id=%llu requests_failed=%zu status=%s",
            static_cast<unsigned long long>(res.audit_id), res.requests_failed, res.status.c_str());
        return error_with_data("api audit sent no requests", out);
    }
    return tool_result_t::ok(out.dump(2), out);
}

tool_result_t tool_gql_introspect(const json& params)
{
    std::string ep = params.value("endpoint", std::string());
    const url_log_t endpoint_log = summarize_url_for_log(ep);
    diag::log_tagged_fmt("mcp_burp", "gql_introspect host=%s path=%s query=%d endpoint_len=%zu params_keys=%zu",
        endpoint_log.host.c_str(), endpoint_log.path.c_str(), (int)endpoint_log.has_query, endpoint_log.length,
        params.is_object() ? params.size() : 0);
    if (ep.empty())
    {
        diag::log_tagged_fmt("mcp_burp", "gql_introspect missing_endpoint");
        return tool_result_t::error("endpoint required");
    }
    auto hdrs = json_obj_to_map(params.value("headers", json::object()));
    graphql::gql_schema_t sch;
    std::string raw;
    if (!graphql::introspect(ep, hdrs, sch, raw))
    {
        std::string err = graphql::last_error();
        diag::log_tagged_fmt("mcp_burp", "gql_introspect failed err=%s", err.c_str());
        json data;
        data["error"] = err;
        data["endpoint"] = ep;
        data["host"] = endpoint_log.host;
        data["path"] = endpoint_log.path;
        data["status"] = "transport_or_parse_failed";
        return error_with_data(err, data);
    }
    diag::log_tagged_fmt("mcp_burp", "gql_introspect ok host=%s path=%s raw_len=%zu types=%zu",
        endpoint_log.host.c_str(), endpoint_log.path.c_str(), raw.size(), sch.types.size());
    json j = graphql::schema_to_json(sch);
    return tool_result_t::ok(j.dump(2), j);
}

tool_result_t tool_gql_example(const json& params)
{
    std::string ep    = params.value("endpoint", std::string());
    std::string field = params.value("field_name", std::string());
    int depth         = params.value("depth", 2);
    const url_log_t endpoint_log = summarize_url_for_log(ep);
    diag::log_tagged_fmt("mcp_burp", "gql_example host=%s path=%s query=%d endpoint_len=%zu field=%s depth=%d",
        endpoint_log.host.c_str(), endpoint_log.path.c_str(), (int)endpoint_log.has_query, endpoint_log.length,
        field.c_str(), depth);
    if (field.empty())
    {
        diag::log_tagged_fmt("mcp_burp", "gql_example missing_field_name");
        return tool_result_t::error("field_name required");
    }
    graphql::gql_schema_t sch;
    if (!graphql::get_cached_schema(ep, sch)) {
        diag::log_tagged_fmt("mcp_burp", "gql_example no_cached_schema introspecting host=%s path=%s",
            endpoint_log.host.c_str(), endpoint_log.path.c_str());
        std::string raw;
        if (!graphql::introspect(ep, {}, sch, raw))
        {
            std::string err = graphql::last_error();
            diag::log_tagged_fmt("mcp_burp", "gql_example introspect_failed err=%s", err.c_str());
            json data;
            data["error"] = err;
            data["endpoint"] = ep;
            data["host"] = endpoint_log.host;
            data["path"] = endpoint_log.path;
            data["field_name"] = field;
            data["status"] = "introspection_failed";
            return error_with_data(err, data);
        }
    }
    std::string q = graphql::build_example_query(sch, field, depth);
    diag::log_tagged_fmt("mcp_burp", "gql_example ok field=%s query_len=%zu", field.c_str(), q.size());
    json out;
    out["query"] = q;
    return tool_result_t::ok(q, out);
}

tool_result_t tool_gql_send(const json& params)
{
    std::string ep = params.value("endpoint", std::string());
    const url_log_t endpoint_log = summarize_url_for_log(ep);
    diag::log_tagged_fmt("mcp_burp", "gql_send host=%s path=%s query=%d endpoint_len=%zu params_keys=%zu",
        endpoint_log.host.c_str(), endpoint_log.path.c_str(), (int)endpoint_log.has_query, endpoint_log.length,
        params.is_object() ? params.size() : 0);
    if (ep.empty())
    {
        diag::log_tagged_fmt("mcp_burp", "gql_send missing_endpoint");
        return tool_result_t::error("endpoint required");
    }
    auto hdrs = json_obj_to_map(params.value("headers", json::object()));
    std::string q = params.value("query", std::string());
    if (q.empty())
    {
        diag::log_tagged_fmt("mcp_burp", "gql_send missing_query");
        return tool_result_t::error("query required");
    }
    json variables = params.value("variables", json::object());

    nlohmann::json resp;
    std::string raw;
    if (!graphql::send_query(ep, hdrs, q, variables, resp, raw))
    {
        std::string err = graphql::last_error();
        diag::log_tagged_fmt("mcp_burp", "gql_send failed err=%s", err.c_str());
        json data;
        data["error"] = err;
        data["endpoint"] = ep;
        data["host"] = endpoint_log.host;
        data["path"] = endpoint_log.path;
        data["query_length"] = q.size();
        data["status"] = "send_failed";
        return error_with_data(err, data);
    }
    diag::log_tagged_fmt("mcp_burp", "gql_send ok host=%s path=%s raw_len=%zu response_type=%s",
        endpoint_log.host.c_str(), endpoint_log.path.c_str(), raw.size(), resp.type_name());
    return tool_result_t::ok(resp.dump(2), resp);
}

tool_result_t tool_ws_connect(const json& params)
{
    ws_editor::ws_connection_config_t cfg;
    cfg.scheme = "wss";
    cfg.port = 443;
    cfg.path = "/";
    const std::string url = params.value("url", std::string());
    bool parsed_url = false;
    if (!url.empty())
    {
        std::string parse_error;
        parsed_url = apply_ws_url(cfg, url, parse_error);
        if (!parsed_url)
        {
            diag::log_tagged_fmt("mcp_burp", "ws_connect url_parse_failed url_len=%zu err=%s", url.size(), parse_error.c_str());
            json data;
            data["error"] = parse_error;
            data["url_length"] = url.size();
            data["status"] = "url_parse_failed";
            return error_with_data(parse_error, data);
        }
    }
    cfg.scheme = params.value("scheme", cfg.scheme);
    cfg.scheme = lower_ascii_copy(cfg.scheme);
    cfg.host   = params.value("host", cfg.host);
    if (cfg.scheme != "ws" && cfg.scheme != "wss")
    {
        json data;
        data["error"] = "WebSocket scheme must be ws or wss";
        data["scheme"] = cfg.scheme;
        data["status"] = "invalid_scheme";
        return error_with_data("WebSocket scheme must be ws or wss", data);
    }
    if (params.contains("port"))
    {
        uint16_t explicit_port = 0;
        if (!json_port_u16(params["port"], explicit_port))
        {
            json data;
            data["error"] = "WebSocket port must be in range 1..65535";
            data["status"] = "invalid_port";
            return error_with_data("WebSocket port must be in range 1..65535", data);
        }
        cfg.port = explicit_port;
    }
    cfg.path   = params.value("path", cfg.path.empty() ? std::string("/") : cfg.path);
    if (cfg.path.empty())
        cfg.path = "/";
    else if (cfg.path[0] != '/')
        cfg.path.insert(cfg.path.begin(), '/');
    cfg.origin = params.value("origin", std::string());
    cfg.subprotocol = params.value("subprotocol", std::string());
    if (params.contains("verify_tls") && !params["verify_tls"].is_boolean())
        return tool_result_t::error("verify_tls must be a boolean");
    cfg.verify_tls = params.value("verify_tls", true);
    if (params.contains("connect_timeout_ms")) {
        if (!params["connect_timeout_ms"].is_number_integer()) return tool_result_t::error("connect_timeout_ms must be an integer");
        const auto value = params["connect_timeout_ms"].get<long long>();
        if (value < 1 || value > 120000) return tool_result_t::error("connect_timeout_ms must be in 1..120000");
        cfg.connect_timeout_ms = static_cast<int>(value);
    }
    if (params.contains("read_timeout_ms")) {
        if (!params["read_timeout_ms"].is_number_integer()) return tool_result_t::error("read_timeout_ms must be an integer");
        const auto value = params["read_timeout_ms"].get<long long>();
        if (value < 1 || value > 300000) return tool_result_t::error("read_timeout_ms must be in 1..300000");
        cfg.read_timeout_ms = static_cast<int>(value);
    }
    if (params.contains("headers") && !params["headers"].is_object())
        return tool_result_t::error("headers must be an object");
    diag::log_tagged_fmt("mcp_burp", "ws_connect scheme=%s host=%s port=%d path=%s parsed_url=%d timeout_ms=%d",
        cfg.scheme.c_str(), cfg.host.c_str(), (int)cfg.port, cfg.path.c_str(), parsed_url ? 1 : 0, cfg.connect_timeout_ms);
    if (params.contains("headers") && params["headers"].is_object()) {
        for (auto it = params["headers"].begin(); it != params["headers"].end(); ++it) {
            cfg.headers.emplace_back(it.key(),
                it.value().is_string() ? it.value().get<std::string>() : it.value().dump());
        }
    }
    uint64_t id = ws_editor::connect(cfg);
    if (id == 0)
    {
        std::string err = ws_editor::last_error();
        diag::log_tagged_fmt("mcp_burp", "ws_connect failed err=%s", err.c_str());
        json data;
        data["error"] = err;
        data["scheme"] = cfg.scheme;
        data["host"] = cfg.host;
        data["port"] = cfg.port;
        data["path"] = cfg.path;
        data["parsed_url"] = parsed_url;
        data["connect_timeout_ms"] = cfg.connect_timeout_ms;
        data["status"] = "connect_failed";
        return error_with_data(err, data);
    }
    diag::log_tagged_fmt("mcp_burp", "ws_connect ok conn_id=%llu", static_cast<unsigned long long>(id));
    json out;
    out["conn_id"] = id;
    return tool_result_t::ok(out.dump(2), out);
}

tool_result_t tool_ws_disconnect(const json& params)
{
    uint64_t id = params.value("conn_id", 0ull);
    diag::log_tagged_fmt("mcp_burp", "ws_disconnect conn_id=%llu", static_cast<unsigned long long>(id));
    ws_editor::ws_status_t before;
    bool before_available = ws_editor::get_status(id, before);
    size_t before_recorded_count = before_available ? ws_editor::frame_count(id) : 0;
    if (!ws_editor::disconnect(id))
    {
        std::string err = ws_editor::last_error();
        diag::log_tagged_fmt("mcp_burp", "ws_disconnect failed err=%s", err.c_str());
        return tool_result_t::error(err);
    }
    ws_editor::ws_status_t after;
    bool after_available = ws_editor::get_status(id, after);
    size_t after_recorded_count = after_available ? ws_editor::frame_count(id) : 0;
    json out;
    out["conn_id"] = id;
    out["connection_id"] = id;
    out["disconnected"] = true;
    out["connected_before"] = bool_or_null(before_available, before.connected);
    out["connected_after"] = after_available ? json(after.connected) : json(false);
    out["record_available_before"] = before_available;
    out["record_available_after"] = after_available;
    out["frame_count_before"] = count_or_null(before_available, before.frames_sent);
    out["frame_count_after"] = count_or_null(after_available, after.frames_sent);
    out["frames_sent_before"] = count_or_null(before_available, before.frames_sent);
    out["frames_sent_after"] = count_or_null(after_available, after.frames_sent);
    out["frames_received_before"] = count_or_null(before_available, before.frames_received);
    out["frames_received_after"] = count_or_null(after_available, after.frames_received);
    out["recorded_frame_count_before"] = count_or_null(before_available, before_recorded_count);
    out["recorded_frame_count_after"] = count_or_null(after_available, after_recorded_count);
    out["before"] = ws_status_or_null(before_available, before);
    out["after"] = ws_status_or_null(after_available, after);
    diag::log_tagged_fmt("mcp_burp", "ws_disconnect ok conn_id=%llu", static_cast<unsigned long long>(id));
    return tool_result_t::ok("disconnected", out);
}

tool_result_t tool_ws_send_text(const json& params)
{
    uint64_t id = params.value("conn_id", 0ull);
    std::string msg = params.value("msg", std::string());
    diag::log_tagged_fmt("mcp_burp", "ws_send_text conn_id=%llu msg_len=%zu", static_cast<unsigned long long>(id), msg.size());
    ws_editor::ws_status_t before;
    bool before_available = ws_editor::get_status(id, before);
    size_t before_recorded_count = before_available ? ws_editor::frame_count(id) : 0;
    if (!ws_editor::send_text(id, msg))
    {
        std::string err = ws_editor::last_error();
        diag::log_tagged_fmt("mcp_burp", "ws_send_text failed err=%s", err.c_str());
        return tool_result_t::error(err);
    }
    ws_editor::ws_status_t after;
    bool after_available = ws_editor::get_status(id, after);
    size_t after_recorded_count = after_available ? ws_editor::frame_count(id) : 0;
    json out = ws_send_result_to_json(id, "text", 1, msg.size(), before_available, before, before_recorded_count, after_available, after, after_recorded_count);
    diag::log_tagged_fmt("mcp_burp", "ws_send_text ok conn_id=%llu", static_cast<unsigned long long>(id));
    return tool_result_t::ok(
        "sent text frame conn_id=" + std::to_string(id) +
        " msg_len=" + std::to_string(msg.size()) +
        " frames_before=" + std::to_string(before_recorded_count) +
        " frames_after=" + std::to_string(after_recorded_count),
        out);
}

tool_result_t tool_ws_send_binary(const json& params)
{
    uint64_t id = params.value("conn_id", 0ull);
    if (!params.contains("data_b64") || !params["data_b64"].is_string())
        return tool_result_t::error("data_b64 is required and must be a string");
    std::string b64 = params.value("data_b64", std::string());
    if (b64.empty())
        return tool_result_t::error("data_b64 is required");
    diag::log_tagged_fmt("mcp_burp", "ws_send_binary conn_id=%llu b64_len=%zu", static_cast<unsigned long long>(id), b64.size());
    auto bin = base64_decode(b64);
    if (bin.empty())
        return tool_result_t::error("data_b64 is invalid base64");
    ws_editor::ws_status_t before;
    bool before_available = ws_editor::get_status(id, before);
    size_t before_recorded_count = before_available ? ws_editor::frame_count(id) : 0;
    if (!ws_editor::send_binary(id, bin))
    {
        std::string err = ws_editor::last_error();
        diag::log_tagged_fmt("mcp_burp", "ws_send_binary failed err=%s", err.c_str());
        return tool_result_t::error(err);
    }
    ws_editor::ws_status_t after;
    bool after_available = ws_editor::get_status(id, after);
    size_t after_recorded_count = after_available ? ws_editor::frame_count(id) : 0;
    json out = ws_send_result_to_json(id, "binary", 2, bin.size(), before_available, before, before_recorded_count, after_available, after, after_recorded_count);
    diag::log_tagged_fmt("mcp_burp", "ws_send_binary ok conn_id=%llu bytes=%zu", static_cast<unsigned long long>(id), bin.size());
    return tool_result_t::ok(
        "sent binary frame conn_id=" + std::to_string(id) +
        " data_len=" + std::to_string(bin.size()) +
        " frames_before=" + std::to_string(before_recorded_count) +
        " frames_after=" + std::to_string(after_recorded_count),
        out);
}

tool_result_t tool_ws_send_raw(const json& params)
{
    uint64_t id = params.value("conn_id", 0ull);
    if (params.contains("payload_b64") && !params["payload_b64"].is_string())
        return tool_result_t::error("payload_b64 must be a string");
    if (params.contains("opcode") && !params["opcode"].is_number_integer())
        return tool_result_t::error("opcode must be an integer");
    if (params.contains("fin") && !params["fin"].is_boolean())
        return tool_result_t::error("fin must be a boolean");
    if (params.contains("masked") && !params["masked"].is_boolean())
        return tool_result_t::error("masked must be a boolean");
    int opcode = params.value("opcode", 1);
    bool fin = params.value("fin", true);
    bool masked = params.value("masked", true);
    std::string b64 = params.value("payload_b64", std::string());
    if (opcode < 0 || opcode > 15)
        return tool_result_t::error("opcode must be in 0..15");
    diag::log_tagged_fmt("mcp_burp", "ws_send_raw conn_id=%llu opcode=%d fin=%d masked=%d", static_cast<unsigned long long>(id), opcode, (int)fin, (int)masked);
    auto bin = base64_decode(b64);
    if (bin.empty() && !b64.empty())
        return tool_result_t::error("payload_b64 is invalid base64");
    ws_editor::ws_status_t before;
    bool before_available = ws_editor::get_status(id, before);
    size_t before_recorded_count = before_available ? ws_editor::frame_count(id) : 0;
    if (!ws_editor::send_raw_frame(id, static_cast<uint8_t>(opcode), fin, masked, bin))
    {
        std::string err = ws_editor::last_error();
        diag::log_tagged_fmt("mcp_burp", "ws_send_raw failed err=%s", err.c_str());
        return tool_result_t::error(err);
    }
    ws_editor::ws_status_t after;
    bool after_available = ws_editor::get_status(id, after);
    size_t after_recorded_count = after_available ? ws_editor::frame_count(id) : 0;
    json out = ws_send_result_to_json(id, "raw", opcode, bin.size(), before_available, before, before_recorded_count, after_available, after, after_recorded_count);
    out["fin"] = fin;
    out["masked"] = masked;
    diag::log_tagged_fmt("mcp_burp", "ws_send_raw ok conn_id=%llu bytes=%zu", static_cast<unsigned long long>(id), bin.size());
    return tool_result_t::ok(
        "sent raw frame conn_id=" + std::to_string(id) +
        " data_len=" + std::to_string(bin.size()) +
        " frames_before=" + std::to_string(before_recorded_count) +
        " frames_after=" + std::to_string(after_recorded_count),
        out);
}

tool_result_t tool_ws_list(const json& params)
{
    (void)params;
    diag::log_tagged_fmt("mcp_burp", "ws_list entry");
    auto items = ws_editor::list_connections();
    json arr = json::array();
    for (const auto& s : items) {
        json j;
        j["id"]              = s.id;
        j["url"]             = s.url;
        j["connected"]       = s.connected;
        j["frames_sent"]     = s.frames_sent;
        j["frames_received"] = s.frames_received;
        j["opened_ms"]       = s.opened_ms;
        j["last_error"]      = s.last_error;
        arr.push_back(std::move(j));
    }
    diag::log_tagged_fmt("mcp_burp", "ws_list ok count=%zu", items.size());
    json out;
    out["count"] = arr.size();
    out["connections"] = std::move(arr);
    return tool_result_t::ok(out.dump(2), out);
}

tool_result_t tool_ws_frames(const json& params)
{
    uint64_t id = params.value("conn_id", 0ull);
    size_t start = 0;
    size_t maxv = 256;
    if (params.contains("start")) {
        if (!params["start"].is_number_integer()) return tool_result_t::error("start must be an integer");
        const auto value = params["start"].get<long long>();
        if (value < 0 || value > 10000000) return tool_result_t::error("start must be in 0..10000000");
        start = static_cast<size_t>(value);
    }
    if (params.contains("max")) {
        if (!params["max"].is_number_integer()) return tool_result_t::error("max must be an integer");
        const auto value = params["max"].get<long long>();
        if (value < 1 || value > 10000) return tool_result_t::error("max must be in 1..10000");
        maxv = static_cast<size_t>(value);
    }
    diag::log_tagged_fmt("mcp_burp", "ws_frames conn_id=%llu start=%zu max=%zu", static_cast<unsigned long long>(id), start, maxv);
    ws_editor::ws_status_t st;
    if (!ws_editor::get_status(id, st))
    {
        std::string err = "ws_editor.frames: not found";
        diag::log_tagged_fmt("mcp_burp", "ws_frames failed conn_id=%llu err=%s", static_cast<unsigned long long>(id), err.c_str());
        return tool_result_t::error(err);
    }
    auto rows = ws_editor::frames(id, start, maxv);
    json arr = json::array();
    for (const auto& f : rows) {
        json j;
        j["ts_ms"]   = f.ts_ms;
        j["outbound"] = f.outbound;
        j["opcode"]  = f.opcode;
        j["preview"] = f.preview;
        j["payload_b64"] = base64_encode_bytes(f.payload.data(), f.payload.size());
        arr.push_back(std::move(j));
    }
    diag::log_tagged_fmt("mcp_burp", "ws_frames ok conn_id=%llu frames=%zu", static_cast<unsigned long long>(id), rows.size());
    json out;
    out["count"]  = arr.size();
    out["frames"] = std::move(arr);
    return tool_result_t::ok(out.dump(2), out);
}

tool_result_t tool_ws_clear(const json& params)
{
    uint64_t id = params.value("conn_id", 0ull);
    diag::log_tagged_fmt("mcp_burp", "ws_clear conn_id=%llu", static_cast<unsigned long long>(id));
    ws_editor::ws_status_t st;
    if (!ws_editor::get_status(id, st))
    {
        std::string err = "ws_editor.clear_frames: not found";
        diag::log_tagged_fmt("mcp_burp", "ws_clear failed conn_id=%llu err=%s", static_cast<unsigned long long>(id), err.c_str());
        return tool_result_t::error(err);
    }
    const size_t before_frames = ws_editor::frame_count(id);
    ws_editor::clear_frames(id);
    const size_t after_frames = ws_editor::frame_count(id);
    json out;
    out["conn_id"] = id;
    out["connection_id"] = id;
    out["frames_before"] = static_cast<uint64_t>(before_frames);
    out["frames_after"] = static_cast<uint64_t>(after_frames);
    out["cleared_count"] = static_cast<uint64_t>(before_frames >= after_frames ? before_frames - after_frames : 0);
    diag::log_tagged_fmt("mcp_burp", "ws_clear ok conn_id=%llu", static_cast<unsigned long long>(id));
    return tool_result_t::ok("cleared", out);
}

tool_result_t tool_report_generate(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "report_generate format=%s output=%s", params.value("format", std::string("html")).c_str(), params.value("output_path", std::string()).c_str());
    report::report_config_t cfg;
    cfg.title         = params.value("title", std::string());
    cfg.client        = params.value("client", std::string());
    cfg.scope_summary = params.value("scope_summary", std::string());
    cfg.output_path   = params.value("output_path", std::string());
    cfg.include_evidence    = params.value("include_evidence", true);
    cfg.include_remediation = params.value("include_remediation", true);
    cfg.session_id = params.value("session_id", std::string());
    cfg.include_session_context = params.value("include_session_context", true);
    cfg.include_audit_trail = params.value("include_audit_trail", false);
    if (params.contains("audit_trail_limit")) {
        if (!params["audit_trail_limit"].is_number_integer()) return tool_result_t::error("audit_trail_limit must be an integer");
        long long v = params["audit_trail_limit"].get<long long>();
        if (v < 0 || v > 10000) return tool_result_t::error("audit_trail_limit must be in 0..10000");
        cfg.audit_trail_limit = static_cast<size_t>(v);
    } else {
        cfg.audit_trail_limit = 128;
    }
    cfg.target_domain = params.value("target_domain", params.value("host", std::string()));
    cfg.include_recon = params.value("include_recon", true);
    cfg.include_suppressed = params.value("include_suppressed", false);
    std::string fmt_s = params.value("format", std::string("html"));
    report::parse_format(fmt_s, cfg.format);
    if (params.contains("include_issue_ids") && params["include_issue_ids"].is_array()) {
        for (const auto& v : params["include_issue_ids"]) {
            uint64_t id = 0;
            if (json_u64_value(v, id)) cfg.include_issue_ids.push_back(id);
        }
    }
    if (params.contains("audit_id")) {
        uint64_t audit_id = 0;
        if (!json_u64_value(params["audit_id"], audit_id))
            return tool_result_t::error("invalid audit_id");
        cfg.has_audit_id = true;
        cfg.audit_id = audit_id;
    }
    if (params.contains("severity_min") && params["severity_min"].is_string()) {
        severity_t sev = severity_t::info;
        if (!parse_severity(params["severity_min"].get<std::string>(), sev))
            return tool_result_t::error("invalid severity_min");
        cfg.has_severity_min = true;
        cfg.severity_min = sev;
    }
    if (params.contains("include_offensive_run_ids") && params["include_offensive_run_ids"].is_array()) {
        for (const auto& v : params["include_offensive_run_ids"])
            if (v.is_string()) cfg.include_offensive_run_ids.push_back(v.get<std::string>());
    }
    std::string out;
    if (!report::generate(cfg, out))
    {
        diag::log_tagged_fmt("mcp_burp", "report_generate failed err=%s", out.c_str());
        return tool_result_t::error(out);
    }
    diag::log_tagged_fmt("mcp_burp", "report_generate ok output_len=%zu format=%s inline=%d", out.size(), fmt_s.c_str(), cfg.output_path.empty() ? 1 : 0);
    json j;
    j["output_path"] = cfg.output_path.empty() ? std::string() : out;
    j["inline"] = cfg.output_path.empty();
    if (cfg.output_path.empty())
        j["content"] = out;
    j["format"]      = report::format_label(cfg.format);
    return tool_result_t::ok(cfg.output_path.empty() ? std::string("report generated inline") : out, j);
}

}

void register_api_tools(mcp_standalone::server_t& srv)
{
    using p = mcp_standalone::tool_param_t;

    srv.register_tool({
        "burp_api_manage",
        "Manage imported API collections and requests. Actions: import, list_collections, get_collection, remove_collection, send_request, audit_collection.",
        {{"action", "string", "import|list_collections|get_collection|remove_collection|send_request|audit_collection", true},
         {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false}},
        false,
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "import") return tool_api_import(p);
            if (action == "list_collections") return tool_api_list(p);
            if (action == "get_collection") return tool_api_get(p);
            if (action == "remove_collection") return tool_api_remove(p);
            if (action == "send_request") return tool_api_send(p);
            if (action == "audit_collection") return tool_api_audit(p);
            return compat_unknown_action("burp_api_manage", action);
        },
        mcp_standalone::tool_visibility_t::external_visible
    });

    srv.register_tool({
        "burp_graphql_manage",
        "Manage GraphQL introspection, examples, and requests. Actions: introspect, example, send.",
        {{"action", "string", "introspect|example|send", true},
         {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false}},
        false,
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "introspect") return tool_gql_introspect(p);
            if (action == "example") return tool_gql_example(p);
            if (action == "send") return tool_gql_send(p);
            return compat_unknown_action("burp_graphql_manage", action);
        }
    });

    srv.register_tool({
        "burp_ws_manage",
        "Manage WebSocket connections and frames. Actions: connect, disconnect, send_text, send_binary, send_raw, list_connections, frames, clear_frames.",
        {{"action", "string", "connect|disconnect|send_text|send_binary|send_raw|list_connections|frames|clear_frames", true},
         {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false}},
        false,
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "connect") return tool_ws_connect(p);
            if (action == "disconnect") return tool_ws_disconnect(p);
            if (action == "send_text") return tool_ws_send_text(p);
            if (action == "send_binary") return tool_ws_send_binary(p);
            if (action == "send_raw") return tool_ws_send_raw(p);
            if (action == "list_connections") return tool_ws_list(p);
            if (action == "frames") return tool_ws_frames(p);
            if (action == "clear_frames") return tool_ws_clear(p);
            return compat_unknown_action("burp_ws_manage", action);
        }
    });

    srv.register_tool({
        "burp_report_generate",
        "Generate a vulnerability report from issue_store. format = html|markdown|json|sarif_2_1_0|csv.",
        {
            {"title",                "string",  "Report title.", false},
            {"client",               "string",  "Client name.", false},
            {"scope_summary",        "string",  "Scope summary text.", false},
            {"include_issue_ids",    "array",   "Optional list of issue ids; empty = all issues.", false},
            {"format",               "string",  "Output format.", true},
            {"output_path",          "string",  "Destination file path; omit for inline output.", false},
            {"include_evidence",     "boolean", "Embed request/response evidence (default true).", false},
            {"include_remediation",  "boolean", "Embed remediation text (default true).", false},
            {"session_id",           "string",  "Audit session id filter.", false},
            {"include_session_context","boolean","Include audit session context.", false},
            {"include_audit_trail",   "boolean", "Include redacted audit trail context.", false},
            {"audit_trail_limit",     "number",  "Maximum audit trail entries.", false},
            {"severity_min",          "string",  "Minimum severity.", false},
            {"target_domain",         "string",  "Target domain filter.", false},
            {"audit_id",              "number",  "Scanner audit id filter.", false},
            {"include_recon",         "boolean", "Include recon/offensive context.", false},
            {"include_offensive_run_ids","array","Offensive run ids to include when present in redacted context.", false},
        },
        false, tool_report_generate
    });

    diag::log_tagged("burp.api_mcp", "registered Burp API/GraphQL/WS/Logger/Reports tools");
}

}
}
}
