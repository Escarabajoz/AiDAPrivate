#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "burp_scanner_mcp.hpp"

#include "active_scanner.hpp"
#include "audit_http.hpp"
#include "burp_logger.hpp"
#include "issue.hpp"
#include "passive_scanner.hpp"
#include "scanner_module.hpp"
#include "site_map.hpp"

#include "../../settings/standalone_compat.hpp"
#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace burp {

namespace {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

tool_result_t scanner_param_error(const std::string& message, const std::string& parameter, const std::string& code = "invalid_param")
{
    json d;
    d["success"] = false;
    d["parameter"] = parameter;
    d["code"] = code;
    return tool_result_t::error(message, code, d);
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

std::string upper_ascii(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return s;
}

std::string header_safe(std::string s)
{
    for (char& c : s) {
        unsigned char uc = static_cast<unsigned char>(c);
        if (uc < 0x20 || uc == 0x7F)
            c = '_';
    }
    return s;
}

std::string safe_session_id(std::string s)
{
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())))
        s.erase(s.begin());
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())))
        s.pop_back();
    if (s.size() > 128)
        s.resize(128);
    for (char& c : s) {
        const unsigned char uc = static_cast<unsigned char>(c);
        if (uc < 0x20 || uc == 0x7F)
            c = '_';
    }
    return s;
}

bool header_name_equals(const std::string& name, const char* expected)
{
    std::string lhs = upper_ascii(name);
    std::string rhs = upper_ascii(expected ? std::string(expected) : std::string());
    return lhs == rhs;
}

bool has_header(const std::vector<std::pair<std::string, std::string>>& headers, const char* name)
{
    for (const auto& h : headers) {
        if (header_name_equals(h.first, name))
            return true;
    }
    return false;
}

bool valid_method_token(const std::string& method)
{
    if (method.empty() || method.size() > 32)
        return false;
    for (unsigned char c : method) {
        if (std::isalnum(c))
            continue;
        switch (c) {
            case '!':
            case '#':
            case '$':
            case '%':
            case '&':
            case '\'':
            case '*':
            case '+':
            case '-':
            case '.':
            case '^':
            case '_':
            case '`':
            case '|':
            case '~':
                continue;
            default:
                return false;
        }
    }
    return true;
}

bool has_crlf_header_terminator(const std::vector<uint8_t>& raw)
{
    if (raw.size() < 4)
        return false;
    for (size_t i = 0; i + 3 < raw.size(); ++i) {
        if (raw[i] == '\r' && raw[i + 1] == '\n' && raw[i + 2] == '\r' && raw[i + 3] == '\n')
            return true;
    }
    return false;
}

bool parse_headers_param(const json& params, std::vector<std::pair<std::string, std::string>>& out, std::string& err)
{
    if (!params.contains("headers"))
        return true;
    const json* value = &params["headers"];
    json parsed;
    if (value->is_string()) {
        const std::string text = value->get<std::string>();
        try {
            parsed = json::parse(text);
            value = &parsed;
        } catch (...) {
            err = "headers string must contain a JSON object or array";
            return false;
        }
    }
    if (value->is_object()) {
        for (auto it = value->begin(); it != value->end(); ++it) {
            if (!it.value().is_string()) {
                err = "headers object values must be strings";
                return false;
            }
            out.emplace_back(it.key(), it.value().get<std::string>());
        }
        return true;
    }
    if (value->is_array()) {
        for (size_t i = 0; i < value->size(); ++i) {
            const json& entry = (*value)[i];
            if (entry.is_object()) {
                if (!entry.contains("name") || !entry["name"].is_string() ||
                    !entry.contains("value") || !entry["value"].is_string()) {
                    err = "headers array objects require string name and value";
                    return false;
                }
                out.emplace_back(entry["name"].get<std::string>(), entry["value"].get<std::string>());
            } else if (entry.is_array() && entry.size() == 2 && entry[0].is_string() && entry[1].is_string()) {
                out.emplace_back(entry[0].get<std::string>(), entry[1].get<std::string>());
            } else {
                err = "headers array entries must be [name,value] or {name,value}";
                return false;
            }
        }
        return true;
    }
    err = "headers must be an object, array, or JSON string";
    return false;
}

bool request_body_from_params(const json& params, std::string& body, std::string& err)
{
    if (params.contains("body_b64") && params["body_b64"].is_string()) {
        const std::string encoded = params["body_b64"].get<std::string>();
        auto decoded = base64_decode(encoded);
        if (decoded.empty() && !encoded.empty()) {
            err = "body_b64 invalid base64";
            return false;
        }
        body.clear();
        if (!decoded.empty())
            body.assign(reinterpret_cast<const char*>(decoded.data()), decoded.size());
        return true;
    }
    if (params.contains("body") && params["body"].is_string()) {
        body = params["body"].get<std::string>();
        return true;
    }
    return true;
}

bool body_is_json_document(const std::string& body)
{
    if (body.empty())
        return false;
    try {
        (void)json::parse(body);
        return true;
    } catch (...) {
        return false;
    }
}

bool build_request_from_url(const json& params, std::vector<uint8_t>& out_raw, std::string& err)
{
    const std::string url = params["url"].get<std::string>();
    std::string scheme;
    std::string host;
    std::string path;
    uint16_t port = 0;
    if (!audit_http::parse_url(url, scheme, host, port, path)) {
        err = "invalid url";
        return false;
    }
    if (path.empty())
        path = "/";
    std::string body;
    if (!request_body_from_params(params, body, err))
        return false;
    std::string method = params.contains("method") && params["method"].is_string()
        ? upper_ascii(params["method"].get<std::string>())
        : (body.empty() ? std::string("GET") : std::string("POST"));
    if (method.empty())
        method = "GET";
    if (!valid_method_token(method)) {
        err = "invalid method";
        return false;
    }
    std::string host_header = host;
    if ((scheme == "https" && port != 443) || (scheme != "https" && port != 80)) {
        host_header += ":";
        host_header += std::to_string(port);
    }
    std::vector<std::pair<std::string, std::string>> headers;
    if (!parse_headers_param(params, headers, err))
        return false;
    if (params.contains("content_type") && params["content_type"].is_string() && !has_header(headers, "Content-Type"))
        headers.emplace_back("Content-Type", params["content_type"].get<std::string>());
    if (!body.empty() && !has_header(headers, "Content-Type"))
        headers.emplace_back("Content-Type", body_is_json_document(body) ? "application/json" : "application/x-www-form-urlencoded");

    std::string req;
    req.reserve(method.size() + path.size() + host_header.size() + body.size() + 256);
    req += method;
    req += " ";
    req += path;
    req += " HTTP/1.1\r\nHost: ";
    req += header_safe(host_header);
    req += "\r\nUser-Agent: AiDA-MCP-Scanner/1.0\r\nAccept: */*\r\nAccept-Encoding: identity\r\n";
    for (const auto& h : headers) {
        if (h.first.empty() || header_name_equals(h.first, "Host") || header_name_equals(h.first, "Content-Length"))
            continue;
        req += header_safe(h.first);
        req += ": ";
        req += header_safe(h.second);
        req += "\r\n";
    }
    if (!body.empty() || method == "POST" || method == "PUT" || method == "PATCH") {
        req += "Content-Length: ";
        req += std::to_string(body.size());
        req += "\r\n";
    }
    req += "Connection: close\r\n\r\n";
    req += body;
    out_raw.assign(req.begin(), req.end());
    std::string content_type;
    bool has_cookie = false;
    bool has_auth = false;
    for (const auto& h : headers) {
        if (header_name_equals(h.first, "Content-Type")) content_type = h.second;
        if (header_name_equals(h.first, "Cookie")) has_cookie = true;
        if (header_name_equals(h.first, "Authorization")) has_auth = true;
    }
    diag::log_tagged_fmt("mcp_burp", "tool_start_audit synthesized_request method=%s url=%s host=%s port=%u path=%s headers=%zu body_len=%zu req_len=%zu content_type=%s has_cookie=%d has_authorization=%d",
        method.c_str(), url.c_str(), host.c_str(), static_cast<unsigned>(port), path.c_str(), headers.size(), body.size(), out_raw.size(),
        content_type.c_str(), has_cookie ? 1 : 0, has_auth ? 1 : 0);
    return true;
}

std::string exchange_request_target(const exchange_observed_t& ex)
{
    std::string target = ex.path.empty() ? std::string("/") : ex.path;
    if (!target.empty() && target.front() != '/')
        target.insert(target.begin(), '/');
    if (!ex.query.empty()) {
        target += "?";
        target += ex.query;
    }
    return target;
}

std::string exchange_url(const exchange_observed_t& ex)
{
    const std::string scheme = ex.scheme.empty() ? (ex.port == 443 ? std::string("https") : std::string("http")) : ex.scheme;
    std::string url = scheme + "://" + ex.host;
    const bool default_port = (scheme == "https" && ex.port == 443) || (scheme == "http" && ex.port == 80) || ex.port == 0;
    if (!default_port) {
        url += ":";
        url += std::to_string(ex.port);
    }
    url += exchange_request_target(ex);
    return url;
}

std::string host_header_for_exchange(const exchange_observed_t& ex)
{
    const std::string scheme = ex.scheme.empty() ? (ex.port == 443 ? std::string("https") : std::string("http")) : ex.scheme;
    std::string host = ex.host;
    const bool default_port = (scheme == "https" && ex.port == 443) || (scheme == "http" && ex.port == 80) || ex.port == 0;
    if (!default_port) {
        host += ":";
        host += std::to_string(ex.port);
    }
    return host;
}

bool build_request_from_exchange(const exchange_observed_t& ex, std::vector<uint8_t>& out_raw, std::string& out_url, std::string& err)
{
    if (ex.host.empty()) {
        err = "exchange has no host";
        return false;
    }
    std::string method = ex.method.empty() ? std::string("GET") : upper_ascii(ex.method);
    if (!valid_method_token(method)) {
        err = "exchange has invalid method";
        return false;
    }
    out_url = exchange_url(ex);
    const std::string target = exchange_request_target(ex);
    std::string req;
    req.reserve(method.size() + target.size() + ex.host.size() + ex.req_body.size() + 512);
    req += method;
    req += " ";
    req += target;
    req += " HTTP/1.1\r\nHost: ";
    req += header_safe(host_header_for_exchange(ex));
    req += "\r\n";
    bool has_user_agent = false;
    bool has_accept = false;
    bool has_cookie = false;
    bool has_auth = false;
    for (const auto& h : ex.req_headers) {
        if (h.first.empty())
            continue;
        if (header_name_equals(h.first, "Host") ||
            header_name_equals(h.first, "Content-Length") ||
            header_name_equals(h.first, "Connection"))
            continue;
        if (header_name_equals(h.first, "User-Agent"))
            has_user_agent = true;
        if (header_name_equals(h.first, "Accept"))
            has_accept = true;
        if (header_name_equals(h.first, "Cookie"))
            has_cookie = true;
        if (header_name_equals(h.first, "Authorization"))
            has_auth = true;
        req += header_safe(h.first);
        req += ": ";
        req += header_safe(h.second);
        req += "\r\n";
    }
    if (!has_user_agent)
        req += "User-Agent: AiDA-MCP-Scanner/1.0\r\n";
    if (!has_accept)
        req += "Accept: */*\r\n";
    if (!ex.req_body.empty() || method == "POST" || method == "PUT" || method == "PATCH") {
        req += "Content-Length: ";
        req += std::to_string(ex.req_body.size());
        req += "\r\n";
    }
    req += "Connection: close\r\n\r\n";
    if (!ex.req_body.empty())
        req.append(reinterpret_cast<const char*>(ex.req_body.data()), ex.req_body.size());
    out_raw.assign(req.begin(), req.end());
    diag::log_tagged_fmt("mcp_burp", "tool_start_audit exchange_request exchange_id=%llu method=%s url=%s headers=%zu body_len=%zu req_len=%zu preserved_cookie=%d preserved_authorization=%d",
        static_cast<unsigned long long>(ex.id), method.c_str(), out_url.c_str(), ex.req_headers.size(), ex.req_body.size(), out_raw.size(),
        has_cookie ? 1 : 0, has_auth ? 1 : 0);
    return true;
}

bool extract_request_payload(const json& params, std::vector<uint8_t>& out_raw, std::string& err)
{
    if (params.contains("raw_request_b64") && params["raw_request_b64"].is_string()) {
        auto dec = base64_decode(params["raw_request_b64"].get<std::string>());
        if (dec.empty()) { err = "raw_request_b64 invalid base64"; return false; }
        out_raw = std::move(dec);
        return true;
    }
    if (params.contains("raw_request") && params["raw_request"].is_string()) {
        const std::string& s = params["raw_request"].get_ref<const std::string&>();
        out_raw.assign(s.begin(), s.end());
        return true;
    }
    if (params.contains("url") && params["url"].is_string())
        return build_request_from_url(params, out_raw, err);
    err = "missing raw_request or raw_request_b64";
    return false;
}

size_t issue_count_for_audit(uint64_t audit_id)
{
    issue_store::initialize();
    issue_filter_t filter;
    filter.has_audit_id = true;
    filter.audit_id = audit_id;
    return issue_store::list(filter).size();
}

uint64_t unix_ms_now()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

uint64_t audit_runtime_elapsed_ms(const active_scanner::audit_status_t& st)
{
    if (st.started_ms == 0) return 0;
    const uint64_t end = st.ended_ms != 0 ? st.ended_ms : unix_ms_now();
    return end > st.started_ms ? end - st.started_ms : 0;
}

json load_snapshot_json(const active_scanner::scanner_load_t& load)
{
    return json{
        {"active_audits", load.active_audits},
        {"running_audits", load.running_audits},
        {"active_workers", load.active_workers},
        {"queue_depth", load.queue_depth},
        {"in_flight_requests", load.in_flight_requests},
        {"max_active_audits", load.max_active_audits},
        {"shutting_down", load.shutting_down}
    };
}

std::string probe_evidence_state(const active_scanner::audit_status_t& st, size_t reported_issues)
{
    if (reported_issues > 0)
        return "issue_evidence_observed";
    if (st.responses_received > 0)
        return "response_evidence_observed";
    if (st.transport_failures > 0)
        return "transport_failures_present";
    if (st.completed_probes > 0)
        return "probes_completed_no_response";
    if (st.running || st.cancel_requested)
        return "pending";
    return "not_started_or_drained";
}

void attach_scanner_evidence_fields(json& data,
                                    const active_scanner::audit_status_t& st,
                                    size_t stored_issues,
                                    size_t reported_issues,
                                    const active_scanner::scanner_load_t& load)
{
    const bool functional_probe_evidence = reported_issues > 0 || st.responses_received > 0;
    const bool worker_activity = st.active_workers > 0 || st.queued_workers > 0 ||
        st.in_flight_requests > 0 || load.active_workers > 0 ||
        load.queue_depth > 0 || load.in_flight_requests > 0;
    const bool completed_all_known = st.total_probes > 0 && st.completed_probes >= st.total_probes;
    const bool terminal_state = !st.running && !st.cancel_requested &&
        (st.ended_ms != 0 || st.drained || completed_all_known ||
         st.transport_circuit_breaker_open || st.transport_failures > 0 || st.no_response_count > 0);
    const bool terminal_without_probe_evidence = terminal_state && !functional_probe_evidence;
    data["status_source"] = "active_scanner::get_status";
    data["stored_issue_count"] = stored_issues;
    data["runtime_issue_count"] = st.issues_found;
    data["reported_issue_count"] = reported_issues;
    data["functional_probe_evidence"] = functional_probe_evidence;
    data["proof_ready"] = functional_probe_evidence;
    data["proof_pending"] = !functional_probe_evidence && !terminal_without_probe_evidence &&
        (st.running || worker_activity || (st.total_probes > 0 && st.completed_probes < st.total_probes));
    data["accepted_pending"] = data["proof_pending"];
    data["terminal_transport_failure"] = terminal_without_probe_evidence &&
        (st.transport_failures > 0 || st.no_response_count > 0 ||
         st.transport_circuit_breaker_open || !st.last_transport_error.empty());
    data["terminal_no_probe_evidence"] = terminal_without_probe_evidence;
    data["terminal_without_functional_proof"] = terminal_without_probe_evidence;
    data["worker_active"] = worker_activity;
    data["load_active_workers"] = load.active_workers;
    data["load_queue_depth"] = load.queue_depth;
    data["load_in_flight_requests"] = load.in_flight_requests;
    data["probe_evidence_state"] = probe_evidence_state(st, reported_issues);
    data["load_snapshot"] = load_snapshot_json(load);
}

tool_result_t tool_start_audit(const json& p)
{
    const uint64_t started = GetTickCount64();
    const DWORD tid = GetCurrentThreadId();
    diag::log_tagged_fmt("mcp_burp", "tool_start_audit url=%s exchange_id=%llu tid=%lu",
        p.contains("url") && p["url"].is_string() ? p["url"].get<std::string>().c_str() : "<missing>",
        p.contains("exchange_id") && p["exchange_id"].is_number_unsigned() ? static_cast<unsigned long long>(p["exchange_id"].get<uint64_t>()) : 0ULL,
        static_cast<unsigned long>(tid));
    std::vector<uint8_t> raw;
    std::string err;
    std::string url = p.contains("url") && p["url"].is_string() ? p["url"].get<std::string>() : std::string();
    if (p.contains("exchange_id")) {
        if (!p["exchange_id"].is_number_unsigned())
            return scanner_param_error("exchange_id must be an unsigned integer", "exchange_id");
        const uint64_t exchange_id = p["exchange_id"].get<uint64_t>();
        exchange_observed_t ex;
        if (!sitemap::find_exchange(exchange_id, ex)) {
            diag::log_tagged_fmt("mcp_burp", "tool_start_audit exchange_not_found id=%llu tid=%lu elapsed_ms=%llu",
                static_cast<unsigned long long>(exchange_id), static_cast<unsigned long>(tid), static_cast<unsigned long long>(GetTickCount64() - started));
            return scanner_param_error("exchange not found", "exchange_id", "exchange_not_found");
        }
        if (!build_request_from_exchange(ex, raw, url, err)) {
            diag::log_tagged_fmt("mcp_burp", "tool_start_audit exchange_payload_error id=%llu err=%s tid=%lu elapsed_ms=%llu",
                static_cast<unsigned long long>(exchange_id), err.c_str(), static_cast<unsigned long>(tid), static_cast<unsigned long long>(GetTickCount64() - started));
            return scanner_param_error(err, "exchange_id");
        }
    } else if (!p.contains("url") || !p["url"].is_string()) {
        return scanner_param_error("missing 'url'", "url", "missing_required");
    }
    if (raw.empty() && !extract_request_payload(p, raw, err)) {
        diag::log_tagged_fmt("mcp_burp", "tool_start_audit payload_error=%s tid=%lu elapsed_ms=%llu", err.c_str(), static_cast<unsigned long>(tid), static_cast<unsigned long long>(GetTickCount64() - started));
        const std::string param = err == "invalid url" ? "url" :
            (err.find("method") != std::string::npos ? "method" :
            (err.find("headers") != std::string::npos ? "headers" :
            (err.find("body_b64") != std::string::npos ? "body_b64" :
            (err.find("raw_request_b64") != std::string::npos ? "raw_request_b64" : "raw_request"))));
        return scanner_param_error(err, param);
    }
    if (raw.empty()) {
        diag::log_tagged_fmt("mcp_burp", "tool_start_audit payload_error=empty_raw_request tid=%lu elapsed_ms=%llu",
            static_cast<unsigned long>(tid), static_cast<unsigned long long>(GetTickCount64() - started));
        return scanner_param_error("empty raw request", "raw_request");
    }
    if (!has_crlf_header_terminator(raw)) {
        const bool ends_crlf = raw.size() >= 2 && raw[raw.size() - 2] == '\r' && raw[raw.size() - 1] == '\n';
        if (!ends_crlf) {
            raw.push_back('\r'); raw.push_back('\n');
        }
        raw.push_back('\r'); raw.push_back('\n');
        diag::log_tagged_fmt("mcp_burp", "tool_start_audit appended_missing_header_terminator req_len=%zu tid=%lu",
            raw.size(), static_cast<unsigned long>(tid));
    }
    active_scanner::audit_config_t cfg;
    if (p.contains("modules") && p["modules"].is_array()) {
        for (const auto& m : p["modules"]) if (m.is_string()) cfg.enabled_modules.push_back(m.get<std::string>());
    }
    if (p.contains("scope_only") && p["scope_only"].is_boolean()) cfg.scope_only = p["scope_only"].get<bool>();
    if (p.contains("follow_redirects") && p["follow_redirects"].is_boolean()) cfg.follow_redirects = p["follow_redirects"].get<bool>();
    if (p.contains("timeout_ms")) {
        if (!p["timeout_ms"].is_number_integer()) return scanner_param_error("timeout_ms must be an integer", "timeout_ms");
        const auto value = p["timeout_ms"].get<long long>();
        if (value < 1 || value > 120000) return scanner_param_error("timeout_ms must be in 1..120000", "timeout_ms");
        cfg.timeout_ms = static_cast<int>(value);
    }
    if (p.contains("max_concurrent")) {
        if (!p["max_concurrent"].is_number_integer()) return scanner_param_error("max_concurrent must be an integer", "max_concurrent");
        const auto value = p["max_concurrent"].get<long long>();
        if (value < 1 || value > 64) return scanner_param_error("max_concurrent must be in 1..64", "max_concurrent");
        cfg.max_concurrent_requests = static_cast<size_t>(value);
        cfg.max_concurrent_explicit = true;
    }
    if (p.contains("throttle_ms")) {
        if (!p["throttle_ms"].is_number_integer()) return scanner_param_error("throttle_ms must be an integer", "throttle_ms");
        const auto value = p["throttle_ms"].get<long long>();
        if (value < 0 || value > 60000) return scanner_param_error("throttle_ms must be in 0..60000", "throttle_ms");
        cfg.request_throttle_ms = static_cast<size_t>(value);
        cfg.request_throttle_explicit = true;
    }
    if (p.contains("per_module_cap")) {
        if (!p["per_module_cap"].is_number_integer()) return scanner_param_error("per_module_cap must be an integer", "per_module_cap");
        const auto value = p["per_module_cap"].get<long long>();
        if (value < 1 || value > 100000) return scanner_param_error("per_module_cap must be in 1..100000", "per_module_cap");
        cfg.per_module_request_cap = static_cast<size_t>(value);
    }
    if (p.contains("session_id")) {
        if (!p["session_id"].is_string())
            return scanner_param_error("session_id must be a string", "session_id");
        cfg.session_id = safe_session_id(p["session_id"].get<std::string>());
    }
    if (p.contains("scan_id")) {
        if (!p["scan_id"].is_number_unsigned())
            return scanner_param_error("scan_id must be an unsigned integer", "scan_id");
        cfg.scan_id = p["scan_id"].get<uint64_t>();
    }

    const auto before = active_scanner::load_snapshot();
    diag::log_tagged_fmt("mcp_burp", "tool_start_audit enqueue_begin url=%s req_len=%zu active_audits=%zu running_audits=%zu queue_depth=%zu in_flight=%zu max_active=%zu tid=%lu",
        url.c_str(),
        raw.size(),
        before.active_audits,
        before.running_audits,
        before.queue_depth,
        before.in_flight_requests,
        before.max_active_audits,
        static_cast<unsigned long>(tid));
    auto id = active_scanner::enqueue_target(raw, url, cfg);
    if (id == 0) {
        const auto after = active_scanner::load_snapshot();
        const std::string last = active_scanner::last_error();
        const std::string last_code = active_scanner::last_error_code();
        const std::string code = last_code.empty() ? "scanner_enqueue_failed" : last_code;
        json data;
        data["success"] = false;
        data["code"] = code;
        data["error"] = last;
        data["url"] = url;
        if (!cfg.session_id.empty())
            data["session_id"] = cfg.session_id;
        data["scan_id"] = cfg.scan_id;
        data["request_length"] = raw.size();
        data["active_audits"] = after.active_audits;
        data["running_audits"] = after.running_audits;
        data["queue_depth"] = after.queue_depth;
        data["in_flight_requests"] = after.in_flight_requests;
        data["max_active_audits"] = after.max_active_audits;
        data["elapsed_ms"] = static_cast<unsigned long long>(GetTickCount64() - started);
        data["thread_id"] = static_cast<unsigned long>(tid);
        data["status_source"] = "active_scanner::enqueue_target";
        data["engine_acceptance"] = "enqueue_rejected";
        data["proof_pending"] = false;
        data["proof_ready"] = false;
        data["accepted_pending"] = false;
        data["functional_probe_evidence"] = false;
        data["terminal_transport_failure"] = false;
        data["terminal_no_probe_evidence"] = true;
        data["terminal_without_functional_proof"] = true;
        data["load_snapshot_before"] = load_snapshot_json(before);
        data["load_snapshot_after"] = load_snapshot_json(after);
        diag::log_tagged_fmt("mcp_burp", "tool_start_audit enqueue_failed err=%s code=%s req_len=%zu active_audits=%zu running_audits=%zu queue_depth=%zu in_flight=%zu elapsed_ms=%llu tid=%lu",
            last.c_str(), code.c_str(), raw.size(), after.active_audits, after.running_audits, after.queue_depth, after.in_flight_requests,
            static_cast<unsigned long long>(GetTickCount64() - started), static_cast<unsigned long>(tid));
        return tool_result_t::error(last.empty() ? "Scanner enqueue failed" : last, code, data);
    }
    const auto after = active_scanner::load_snapshot();
    diag::log_tagged_fmt("mcp_burp", "tool_start_audit ok audit_id=%llu req_len=%zu active_audits=%zu running_audits=%zu queue_depth=%zu in_flight=%zu elapsed_ms=%llu tid=%lu",
        static_cast<unsigned long long>(id), raw.size(), after.active_audits, after.running_audits, after.queue_depth, after.in_flight_requests,
        static_cast<unsigned long long>(GetTickCount64() - started), static_cast<unsigned long>(tid));
    json data;
    data["audit_id"] = id;
    if (!cfg.session_id.empty())
        data["session_id"] = cfg.session_id;
    data["scan_id"] = cfg.scan_id != 0 ? cfg.scan_id : id;
    data["url"] = url;
    if (p.contains("exchange_id") && p["exchange_id"].is_number_unsigned())
        data["exchange_id"] = p["exchange_id"].get<uint64_t>();
    data["request_length"] = raw.size();
    data["active_audits"] = after.active_audits;
    data["running_audits"] = after.running_audits;
    data["queue_depth"] = after.queue_depth;
    data["in_flight_requests"] = after.in_flight_requests;
    data["status_source"] = "active_scanner::enqueue_target";
    data["engine_acceptance"] = "audit_id_allocated";
    data["accepted_pending"] = true;
    data["proof_pending"] = true;
    data["proof_ready"] = false;
    data["functional_probe_evidence"] = false;
    data["terminal_transport_failure"] = false;
    data["terminal_no_probe_evidence"] = false;
    data["terminal_without_functional_proof"] = false;
    data["completed_probes"] = 0;
    data["total_probes"] = 0;
    data["responses_received"] = 0;
    data["issues_found"] = 0;
    data["active_workers"] = after.active_workers;
    data["queued_workers"] = after.queue_depth;
    data["load_active_workers"] = after.active_workers;
    data["load_queue_depth"] = after.queue_depth;
    data["load_in_flight_requests"] = after.in_flight_requests;
    data["probe_evidence_state"] = "pending";
    data["load_snapshot_before"] = load_snapshot_json(before);
    data["load_snapshot_after"] = load_snapshot_json(after);
    return tool_result_t::ok(std::string("Audit started: ") + std::to_string(id), data);
}

tool_result_t tool_audit_status(const json& p)
{
    const uint64_t started = GetTickCount64();
    const DWORD tid = GetCurrentThreadId();
    diag::log_tagged_fmt("mcp_burp", "tool_audit_status audit_id=%llu tid=%lu", p.contains("audit_id") && p["audit_id"].is_number_unsigned() ? static_cast<unsigned long long>(p["audit_id"].get<uint64_t>()) : 0ULL, static_cast<unsigned long>(tid));
    if (!p.contains("audit_id") || !p["audit_id"].is_number_unsigned())
        return scanner_param_error("missing 'audit_id'", "audit_id", "missing_required");
    uint64_t id = p["audit_id"].get<uint64_t>();
    active_scanner::audit_status_t st;
    if (!active_scanner::get_status(id, st)) {
        const auto load = active_scanner::load_snapshot();
        json data;
        data["success"] = false;
        data["audit_id"] = id;
        data["active_audits"] = load.active_audits;
        data["running_audits"] = load.running_audits;
        data["queue_depth"] = load.queue_depth;
        data["in_flight_requests"] = load.in_flight_requests;
        data["elapsed_ms"] = static_cast<unsigned long long>(GetTickCount64() - started);
        data["handler_elapsed_ms"] = data["elapsed_ms"];
        data["thread_id"] = static_cast<unsigned long>(tid);
        diag::log_tagged_fmt("mcp_burp", "tool_audit_status not_found id=%llu active_audits=%zu running_audits=%zu queue_depth=%zu in_flight=%zu elapsed_ms=%llu tid=%lu",
            static_cast<unsigned long long>(id), load.active_audits, load.running_audits, load.queue_depth, load.in_flight_requests,
            static_cast<unsigned long long>(GetTickCount64() - started), static_cast<unsigned long>(tid));
        return tool_result_t::error("audit not found", "audit_not_found", data);
    }
    const size_t stored_issues = issue_count_for_audit(id);
    const size_t issues_found = std::max(st.issues_found, stored_issues);
    const auto load = active_scanner::load_snapshot();
    const uint64_t handler_elapsed_ms = GetTickCount64() - started;
    const uint64_t audit_elapsed_ms = audit_runtime_elapsed_ms(st);
    json data;
    data["id"] = st.id;
    if (!st.session_id.empty())
        data["session_id"] = st.session_id;
    data["scan_id"] = st.scan_id;
    data["url"] = st.url;
    data["host"] = st.host;
    data["port"] = st.port;
    data["tls"] = st.tls;
    data["total_points"] = st.total_points;
    data["total_probes"] = st.total_probes;
    data["completed_probes"] = st.completed_probes;
    data["issues_found"] = issues_found;
    data["responses_received"] = st.responses_received;
    data["no_response_count"] = st.no_response_count;
    data["transport_failures"] = st.transport_failures;
    data["last_transport_error"] = st.last_transport_error;
    data["transport_error_code"] = st.transport_error_code;
    data["transport_error_class"] = st.transport_error_class;
    data["transport_circuit_breaker_open"] = st.transport_circuit_breaker_open;
    data["transport_circuit_breaker_hits"] = st.transport_circuit_breaker_hits;
    data["transport_circuit_breaker_threshold"] = st.transport_circuit_breaker_threshold;
    data["effective_max_concurrent"] = st.effective_max_concurrent;
    data["effective_throttle_ms"] = st.effective_throttle_ms;
    data["transport_backoff_ms"] = st.transport_backoff_ms;
    data["transport_degraded"] = st.transport_failures > 0 || (st.completed_probes > 0 && st.responses_received == 0);
    data["scan_interpretation"] = (st.completed_probes > 0 && st.responses_received == 0 && st.transport_failures > 0)
        ? "transport_failed_no_responses"
        : (st.transport_failures > 0 ? "transport_degraded" : (issues_found == 0 ? "no_issues_observed" : "issues_observed"));
    data["running"] = st.running;
    data["cancelled"] = st.cancelled;
    data["cancel_requested"] = st.cancel_requested;
    data["drained"] = st.drained;
    data["started_ms"] = st.started_ms;
    data["ended_ms"] = st.ended_ms;
    data["audit_elapsed_ms"] = audit_elapsed_ms;
    data["handler_elapsed_ms"] = handler_elapsed_ms;
    data["request_length"] = st.request_length;
    data["queue_depth"] = load.queue_depth;
    data["active_audits"] = load.active_audits;
    data["running_audits"] = load.running_audits;
    data["active_workers"] = st.active_workers;
    data["queued_workers"] = st.queued_workers;
    data["in_flight_requests"] = load.in_flight_requests;
    data["audit_in_flight_requests"] = st.in_flight_requests;
    data["elapsed_ms"] = audit_elapsed_ms;
    data["thread_id"] = static_cast<unsigned long>(tid);
    attach_scanner_evidence_fields(data, st, stored_issues, issues_found, load);
    diag::log_tagged_fmt("mcp_burp", "tool_audit_status ok id=%llu running=%d cancelled=%d cancel_requested=%d drained=%d runtime_issues=%zu stored_issues=%zu reported_issues=%zu responses=%zu no_response=%zu transport_failures=%zu transport_error_code=%u transport_error_class=%s circuit_open=%d circuit_hits=%zu circuit_threshold=%zu last_transport_error=%s req_len=%zu active_audits=%zu running_audits=%zu queue_depth=%zu in_flight=%zu effective_concurrency=%zu effective_throttle_ms=%zu audit_elapsed_ms=%llu handler_elapsed_ms=%llu tid=%lu",
        static_cast<unsigned long long>(id),
        (int)st.running,
        st.cancelled ? 1 : 0,
        st.cancel_requested ? 1 : 0,
        st.drained ? 1 : 0,
        st.issues_found,
        stored_issues,
        issues_found,
        st.responses_received,
        st.no_response_count,
        st.transport_failures,
        st.transport_error_code,
        st.transport_error_class.c_str(),
        st.transport_circuit_breaker_open ? 1 : 0,
        st.transport_circuit_breaker_hits,
        st.transport_circuit_breaker_threshold,
        st.last_transport_error.c_str(),
        st.request_length,
        load.active_audits,
        load.running_audits,
        load.queue_depth,
        load.in_flight_requests,
        st.effective_max_concurrent,
        st.effective_throttle_ms,
        static_cast<unsigned long long>(audit_elapsed_ms),
        static_cast<unsigned long long>(handler_elapsed_ms),
        static_cast<unsigned long>(tid));
    return tool_result_t::ok(data);
}

tool_result_t tool_list_audits(const json&)
{
    const uint64_t started = GetTickCount64();
    const DWORD tid = GetCurrentThreadId();
    diag::log_tagged_fmt("mcp_burp", "tool_list_audits entry tid=%lu", static_cast<unsigned long>(tid));
    auto v = active_scanner::list_audits();
    const auto load = active_scanner::load_snapshot();
    json arr = json::array();
    for (const auto& st : v) {
        const size_t stored_issues = issue_count_for_audit(st.id);
        const size_t issues_found = std::max(st.issues_found, stored_issues);
        json e;
        e["id"] = st.id;
        if (!st.session_id.empty())
            e["session_id"] = st.session_id;
        e["scan_id"] = st.scan_id;
        e["url"] = st.url;
        e["host"] = st.host;
        e["port"] = st.port;
        e["tls"] = st.tls;
        e["total_probes"] = st.total_probes;
        e["completed_probes"] = st.completed_probes;
        e["issues_found"] = issues_found;
        e["responses_received"] = st.responses_received;
        e["no_response_count"] = st.no_response_count;
        e["transport_failures"] = st.transport_failures;
        e["last_transport_error"] = st.last_transport_error;
        e["transport_error_code"] = st.transport_error_code;
        e["transport_error_class"] = st.transport_error_class;
        e["transport_circuit_breaker_open"] = st.transport_circuit_breaker_open;
        e["transport_circuit_breaker_hits"] = st.transport_circuit_breaker_hits;
        e["transport_circuit_breaker_threshold"] = st.transport_circuit_breaker_threshold;
        e["effective_max_concurrent"] = st.effective_max_concurrent;
        e["effective_throttle_ms"] = st.effective_throttle_ms;
        e["transport_backoff_ms"] = st.transport_backoff_ms;
        e["transport_degraded"] = st.transport_failures > 0 || (st.completed_probes > 0 && st.responses_received == 0);
        e["scan_interpretation"] = (st.completed_probes > 0 && st.responses_received == 0 && st.transport_failures > 0)
            ? "transport_failed_no_responses"
            : (st.transport_failures > 0 ? "transport_degraded" : (issues_found == 0 ? "no_issues_observed" : "issues_observed"));
        e["running"] = st.running;
        e["cancelled"] = st.cancelled;
        e["cancel_requested"] = st.cancel_requested;
        e["drained"] = st.drained;
        e["started_ms"] = st.started_ms;
        e["ended_ms"] = st.ended_ms;
        e["elapsed_ms"] = audit_runtime_elapsed_ms(st);
        e["audit_elapsed_ms"] = e["elapsed_ms"];
        e["request_length"] = st.request_length;
        e["active_workers"] = st.active_workers;
        e["queued_workers"] = st.queued_workers;
        e["audit_in_flight_requests"] = st.in_flight_requests;
        attach_scanner_evidence_fields(e, st, stored_issues, issues_found, load);
        arr.push_back(std::move(e));
    }
    json data;
    data["count"] = arr.size();
    data["audits"] = std::move(arr);
    data["active_audits"] = load.active_audits;
    data["running_audits"] = load.running_audits;
    data["queue_depth"] = load.queue_depth;
    data["in_flight_requests"] = load.in_flight_requests;
    data["max_active_audits"] = load.max_active_audits;
    data["load_snapshot"] = load_snapshot_json(load);
    data["status_source"] = "active_scanner::list_audits";
    data["elapsed_ms"] = static_cast<unsigned long long>(GetTickCount64() - started);
    data["thread_id"] = static_cast<unsigned long>(tid);
    diag::log_tagged_fmt("mcp_burp", "tool_list_audits ok count=%zu active_audits=%zu running_audits=%zu queue_depth=%zu in_flight=%zu elapsed_ms=%llu tid=%lu",
        v.size(), load.active_audits, load.running_audits, load.queue_depth, load.in_flight_requests,
        static_cast<unsigned long long>(GetTickCount64() - started), static_cast<unsigned long>(tid));
    return tool_result_t::ok(data);
}

tool_result_t tool_cancel(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "tool_cancel audit_id=%llu", p.contains("audit_id") && p["audit_id"].is_number_unsigned() ? static_cast<unsigned long long>(p["audit_id"].get<uint64_t>()) : 0ULL);
    if (!p.contains("audit_id") || !p["audit_id"].is_number_unsigned())
        return tool_result_t::error("missing 'audit_id'");
    uint64_t id = p["audit_id"].get<uint64_t>();
    if (!active_scanner::cancel_audit(id)) { diag::log_tagged_fmt("mcp_burp", "tool_cancel not_found id=%llu", static_cast<unsigned long long>(id)); return tool_result_t::error("audit not found"); }
    const bool drained = active_scanner::wait_for_audit_idle(id, 20000);
    diag::log_tagged_fmt("mcp_burp", "tool_cancel ok id=%llu drained=%d", static_cast<unsigned long long>(id), drained ? 1 : 0);
    json data; data["audit_id"] = id; data["cancelled"] = true; data["cancel_requested"] = true; data["drained"] = drained;
    if (!drained)
        return tool_result_t::error("audit cancellation timed out before drain", "audit_cancel_timeout", data);
    return tool_result_t::ok(std::string("Cancelled audit ") + std::to_string(id), data);
}

tool_result_t tool_list_issues(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "tool_list_issues entry");
    issue_filter_t f;
    if (p.contains("severity_min") && p["severity_min"].is_string()) {
        severity_t sv; if (parse_severity(p["severity_min"].get<std::string>(), sv)) {
            f.has_severity_min = true; f.severity_min = sv;
        }
    }
    if (p.contains("confidence_min") && p["confidence_min"].is_string()) {
        confidence_t cf; if (parse_confidence(p["confidence_min"].get<std::string>(), cf)) {
            f.has_confidence_min = true; f.confidence_min = cf;
        }
    }
    if (p.contains("host") && p["host"].is_string()) f.host_substring = p["host"].get<std::string>();
    if (p.contains("type") && p["type"].is_string()) f.type_key_substring = p["type"].get<std::string>();
    if (p.contains("audit_id") && p["audit_id"].is_number_unsigned()) {
        f.has_audit_id = true; f.audit_id = p["audit_id"].get<uint64_t>();
    }
    if (p.contains("limit")) {
        if (!p["limit"].is_number_integer()) return scanner_param_error("limit must be an integer", "limit");
        const auto value = p["limit"].get<long long>();
        if (value < 0 || value > 10000) return scanner_param_error("limit must be in 0..10000", "limit");
        f.limit = static_cast<size_t>(value);
    }
    json data = issue_store::export_json(f);
    diag::log_tagged_fmt("mcp_burp", "tool_list_issues ok");
    return tool_result_t::ok(data);
}

tool_result_t tool_get_issue(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "tool_get_issue issue_id=%llu", p.contains("issue_id") && p["issue_id"].is_number_unsigned() ? static_cast<unsigned long long>(p["issue_id"].get<uint64_t>()) : 0ULL);
    if (!p.contains("issue_id") || !p["issue_id"].is_number_unsigned())
        return tool_result_t::error("missing 'issue_id'");
    uint64_t id = p["issue_id"].get<uint64_t>();
    issue_t it;
    if (!issue_store::get(id, it)) { diag::log_tagged_fmt("mcp_burp", "tool_get_issue not_found id=%llu", static_cast<unsigned long long>(id)); return tool_result_t::error("issue not found"); }
    diag::log_tagged_fmt("mcp_burp", "tool_get_issue ok id=%llu", static_cast<unsigned long long>(id));
    return tool_result_t::ok(issue_store::issue_to_json(it));
}

tool_result_t tool_passive_status(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "tool_passive_status entry");
    auto st = passive_scanner::get_stats();
    json data;
    data["enabled"] = passive_scanner::is_enabled();
    data["exchanges_scanned"] = st.exchanges_scanned;
    data["issues_found"] = st.issues_found;
    data["last_scan_ms"] = st.last_scan_ms;
    diag::log_tagged_fmt("mcp_burp", "tool_passive_status ok enabled=%d scanned=%zu issues=%zu", (int)passive_scanner::is_enabled(), st.exchanges_scanned, st.issues_found);
    return tool_result_t::ok(data);
}

tool_result_t tool_list_modules(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "tool_list_modules entry");
    auto v = scanner::all_modules();
    json arr = json::array();
    for (const auto& m : v) {
        json e;
        e["id"] = m.id;
        e["name"] = m.name;
        e["category"] = m.category;
        e["max_probes_per_point"] = m.max_probes_per_point;
        arr.push_back(std::move(e));
    }
    json data;
    data["count"] = arr.size();
    data["modules"] = std::move(arr);
    diag::log_tagged_fmt("mcp_burp", "tool_list_modules ok count=%zu", v.size());
    return tool_result_t::ok(data);
}

tool_result_t tool_clear_issues(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "tool_clear_issues entry");
    size_t n = issue_store::count();
    issue_store::clear();
    diag::log_tagged_fmt("mcp_burp", "tool_clear_issues ok cleared=%zu", n);
    json data; data["cleared"] = n;
    return tool_result_t::ok(std::string("Cleared ") + std::to_string(n) + std::string(" issues"), data);
}

tool_result_t tool_passive_enable(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "tool_passive_enable enabled=%d", p.contains("enabled") && p["enabled"].is_boolean() ? (int)p["enabled"].get<bool>() : -1);
    const bool enabled = p.contains("enabled") && p["enabled"].is_boolean() ? p["enabled"].get<bool>() : true;
    passive_scanner::set_enabled(enabled);
    json data; data["enabled"] = passive_scanner::is_enabled();
    diag::log_tagged_fmt("mcp_burp", "tool_passive_enable ok enabled=%d", (int)passive_scanner::is_enabled());
    return tool_result_t::ok(data);
}

}

void register_scanner_tools(mcp_standalone::server_t& srv)
{
    active_scanner::initialize();
    sitemap::initialize();
    logger::initialize();
    passive_scanner::initialize();
    issue_store::initialize();

    register_compat(srv, {
        "burp_scanner_manage", "scanner",
        "Manage Burp-style active/passive scanning and issue storage. Actions: start_audit, audit_status, list_audits, cancel, list_issues, get_issue, clear_issues, passive_status, list_modules, passive_enable.",
        {{"action", "string", "start_audit|audit_status|list_audits|cancel|list_issues|get_issue|clear_issues|passive_status|list_modules|passive_enable", true},
         {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false},
         {"url", "string", "Target URL for start_audit; if no raw_request/raw_request_b64 is supplied a raw HTTP request is synthesized from url/method/body/headers.", false},
         {"method", "string", "HTTP method for synthesized start_audit requests; defaults to GET, or POST when body/body_b64 is supplied.", false},
         {"headers", "object|array|string", "Headers for synthesized start_audit requests as object, array of {name,value}, array pairs, or JSON string.", false},
         {"body", "string", "Text body for synthesized start_audit requests.", false},
         {"body_b64", "string", "Base64 body for synthesized start_audit requests.", false},
         {"content_type", "string", "Content-Type for synthesized start_audit request bodies.", false},
         {"raw_request", "string", "Raw HTTP request for start_audit", false},
         {"raw_request_b64", "string", "Base64 raw HTTP request for start_audit", false},
         {"exchange_id", "number", "Sitemap/logger exchange id to replay as the start_audit request.", false},
         {"audit_id", "number", "Audit id for audit_status or cancel", false},
         {"session_id", "string", "Optional audit session id for start_audit context binding.", false},
         {"scan_id", "number", "Optional scan id for start_audit context binding.", false},
         {"scope_only", "boolean", "Keep active audit requests constrained to Burp scope", false},
         {"enabled", "boolean", "passive_enable toggle; defaults to true when omitted.", false},
         {"max_concurrent", "number", "Per-audit request concurrency cap", false},
         {"throttle_ms", "number", "Per-request throttle in milliseconds; explicit values override external-host defaults.", false},
         {"timeout_ms", "number", "Per-request transport timeout in milliseconds.", false},
         {"follow_redirects", "boolean", "Follow redirects in audit transport; defaults false so first-hop redirect deltas remain visible.", false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "start_audit") return tool_start_audit(p);
            if (action == "audit_status") return tool_audit_status(p);
            if (action == "list_audits") return tool_list_audits(p);
            if (action == "cancel") return tool_cancel(p);
            if (action == "list_issues") return tool_list_issues(p);
            if (action == "get_issue") return tool_get_issue(p);
            if (action == "clear_issues") return tool_clear_issues(p);
            if (action == "passive_status") return tool_passive_status(p);
            if (action == "list_modules") return tool_list_modules(p);
            if (action == "passive_enable") return tool_passive_enable(p);
            return compat_unknown_action("burp_scanner_manage", action);
        },
        false
    });

    diag::log_tagged_fmt("burp", "burp_scanner_mcp registered %zu tools (modules=%zu)",
        static_cast<size_t>(1), scanner::count());
}

}
}
