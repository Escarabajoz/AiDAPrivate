#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "api_enum_tools_standalone.hpp"
#include "js_analysis_tools_standalone.hpp"

#include "burp/api_definition.hpp"
#include "burp/audit_http.hpp"
#include "burp/camoufox_bridge.hpp"
#include "burp/jwt_lab.hpp"
#include "burp/site_map.hpp"
#include "../../helpers/diag_log.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace network {
namespace api_enum_tools {

namespace {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

struct fetch_result_t
{
    bool        ok = false;
    std::string body;
    int         status = 0;
    std::string content_type;
    std::string error;
    bool        truncated = false;
};

struct endpoint_sink_t
{
    json endpoints = json::array();
    std::set<std::string> seen;
};

std::string lower_copy(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string upper_copy(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return s;
}

bool starts_with_ci(const std::string& s, const std::string& prefix)
{
    if (s.size() < prefix.size()) return false;
    for (std::size_t i = 0; i < prefix.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(s[i])) != std::tolower(static_cast<unsigned char>(prefix[i])))
            return false;
    }
    return true;
}

bool method_is_http(const std::string& method)
{
    const std::string m = upper_copy(method);
    return m == "GET" || m == "POST" || m == "PUT" || m == "PATCH" || m == "DELETE" || m == "HEAD" || m == "OPTIONS" || m == "TRACE";
}

std::string normalize_method(const std::string& method)
{
    std::string out = upper_copy(method);
    if (out.empty()) return "UNKNOWN";
    return method_is_http(out) ? out : "UNKNOWN";
}

std::vector<std::pair<std::string, std::string>> headers_from_json(const json& j)
{
    std::vector<std::pair<std::string, std::string>> out;
    if (!j.is_object()) return out;
    for (auto it = j.begin(); it != j.end(); ++it) {
        if (!it.value().is_string()) continue;
        const std::string name = it.key();
        const std::string value = it.value().get<std::string>();
        if (name.find('\r') != std::string::npos || name.find('\n') != std::string::npos) continue;
        if (value.find('\r') != std::string::npos || value.find('\n') != std::string::npos) continue;
        const std::string lname = lower_copy(name);
        if (lname == "host" || lname == "connection" || lname == "content-length") continue;
        out.emplace_back(name, value);
    }
    return out;
}

std::string host_header_value(const std::string& host, std::uint16_t port, bool tls)
{
    if ((tls && port == 443) || (!tls && port == 80)) return host;
    return host + ":" + std::to_string(static_cast<unsigned>(port));
}

bool call_expired()
{
    if (mcp_standalone::current_call_cancelled())
        return true;
    const std::uint64_t deadline = mcp_standalone::current_call_deadline_ms();
    return deadline != 0 && static_cast<std::uint64_t>(GetTickCount64()) >= deadline;
}

int bounded_timeout_ms(int requested, int fallback, int min_ms, int max_ms)
{
    int value = requested <= 0 ? fallback : requested;
    value = std::max(min_ms, std::min(value, max_ms));
    const std::uint64_t deadline = mcp_standalone::current_call_deadline_ms();
    if (deadline != 0) {
        const std::uint64_t now = static_cast<std::uint64_t>(GetTickCount64());
        if (deadline <= now)
            return 1;
        value = static_cast<int>(std::min<std::uint64_t>(static_cast<std::uint64_t>(value), deadline - now));
    }
    return std::max(1, value);
}

fetch_result_t fetch_text_url(const std::string& url,
                              const json& headers,
                              int timeout_ms,
                              bool enforce_scope,
                              std::size_t max_bytes,
                              const char* source_label)
{
    fetch_result_t out;
    if (call_expired()) {
        out.error = "cancelled";
        return out;
    }
    std::string scheme;
    std::string host;
    std::string path;
    std::uint16_t port = 0;
    if (!burp::audit_http::parse_url(url, scheme, host, port, path)) {
        out.error = "url parse failed";
        return out;
    }
    const bool tls = scheme == "https";
    std::ostringstream req;
    req << "GET " << (path.empty() ? "/" : path) << " HTTP/1.1\r\n";
    req << "Host: " << host_header_value(host, port, tls) << "\r\n";
    req << "User-Agent: AiDA-API-Discovery/1.0\r\n";
    req << "Accept: application/json, application/yaml, text/yaml, text/plain, */*\r\n";
    for (const auto& h : headers_from_json(headers))
        req << h.first << ": " << h.second << "\r\n";
    req << "Connection: close\r\n\r\n";
    const std::string raw = req.str();
    std::vector<std::uint8_t> bytes(raw.begin(), raw.end());
    burp::audit_http::send_options_t opts;
    opts.timeout_ms = bounded_timeout_ms(timeout_ms, 15000, 250, 45000);
    opts.follow_redirects = true;
    opts.max_redirects = 4;
    opts.enforce_scope = enforce_scope;
    opts.exchange_source = source_label ? source_label : "api_enum";
    auto ex = burp::audit_http::send(bytes, host, port, tls, opts);
    if (!ex.has_value()) {
        out.error = burp::audit_http::last_error();
        return out;
    }
    out.status = ex->status_code;
    for (const auto& h : ex->resp_headers) {
        if (lower_copy(h.first) == "content-type") {
            out.content_type = h.second;
            break;
        }
    }
    if (ex->status_code < 200 || ex->status_code >= 300) {
        out.error = "HTTP " + std::to_string(ex->status_code);
        return out;
    }
    const std::size_t n = max_bytes == 0 ? ex->resp_body.size() : std::min(max_bytes, ex->resp_body.size());
    out.body.assign(reinterpret_cast<const char*>(ex->resp_body.data()), n);
    out.truncated = n < ex->resp_body.size();
    out.ok = true;
    return out;
}

std::string origin_from_url(const std::string& url)
{
    std::string scheme, host, path;
    std::uint16_t port = 0;
    if (!burp::audit_http::parse_url(url, scheme, host, port, path)) return {};
    std::string origin = scheme + "://" + host;
    if ((scheme == "https" && port != 443) || (scheme == "http" && port != 80))
        origin += ":" + std::to_string(static_cast<unsigned>(port));
    return origin;
}

bool url_looks_like_spec(const std::string& url)
{
    const std::string u = lower_copy(url);
    return u.find("openapi") != std::string::npos || u.find("swagger") != std::string::npos ||
        u.find("api-docs") != std::string::npos || u.find(".yaml") != std::string::npos ||
        u.find(".yml") != std::string::npos || u.find(".json") != std::string::npos;
}

std::vector<std::string> openapi_candidate_urls(const std::string& url)
{
    std::vector<std::string> out;
    const std::string origin = origin_from_url(url);
    if (url_looks_like_spec(url)) out.push_back(url);
    if (origin.empty()) return out;
    static const char* paths[] = {
        "/openapi.json",
        "/openapi.yaml",
        "/swagger.json",
        "/swagger.yaml",
        "/api-docs",
        "/v3/api-docs",
        "/v3/api-docs/swagger-config",
        "/api/openapi.json",
        "/api/swagger.json",
        "/docs/openapi.json",
        "/docs/swagger.json",
        "/swagger/v1/swagger.json",
        "/swagger-ui/swagger.json"
    };
    std::set<std::string> seen(out.begin(), out.end());
    for (const char* p : paths) {
        std::string candidate = origin + p;
        if (seen.insert(candidate).second) out.push_back(std::move(candidate));
    }
    return out;
}

bool import_spec_text(const std::string& text,
                      const std::string& source,
                      const std::string& format_hint,
                      std::uint64_t& id,
                      json& collection_json,
                      std::string& error)
{
    burp::api_definition::api_format_t fmt = burp::api_definition::api_format_t::auto_detect;
    if (!format_hint.empty())
        burp::api_definition::parse_format(format_hint, fmt);
    id = burp::api_definition::import_from_text(text, fmt);
    if (id == 0) {
        error = burp::api_definition::last_error();
        return false;
    }
    burp::api_definition::api_collection_t col;
    if (!burp::api_definition::get_collection(id, col)) {
        error = "imported collection not found";
        return false;
    }
    collection_json = burp::api_definition::collection_to_json(col);
    collection_json["source"] = js_analysis_tools::redact_url_for_output(source);
    return true;
}

void push_endpoint(endpoint_sink_t& sink,
                   const std::string& method,
                   const std::string& path,
                   const std::string& source,
                   double confidence,
                   const json& extra = json::object())
{
    if (path.empty()) return;
    const std::string m = normalize_method(method);
    const std::string p = js_analysis_tools::redact_url_for_output(path);
    const std::string key = m + "\n" + p + "\n" + source;
    if (!sink.seen.insert(key).second) return;
    json item = extra.is_object() ? extra : json::object();
    item["method"] = m;
    item["path"] = p;
    item["source"] = source;
    item["confidence"] = confidence;
    sink.endpoints.push_back(std::move(item));
}

void append_collection_endpoints(endpoint_sink_t& sink,
                                 const burp::api_definition::api_collection_t& col,
                                 const std::string& source,
                                 double confidence)
{
    for (const auto& req : col.requests) {
        json extra;
        extra["collection_id"] = col.id;
        extra["request_id"] = req.id;
        extra["base_url"] = js_analysis_tools::redact_url_for_output(req.base_url.empty() ? col.base_url : req.base_url);
        if (!req.summary.empty()) extra["summary"] = req.summary;
        push_endpoint(sink, req.method, req.path, source, confidence, extra);
    }
}

bool collection_from_id(std::uint64_t id, burp::api_definition::api_collection_t& col, std::string& error)
{
    if (!burp::api_definition::get_collection(id, col)) {
        error = "collection not found";
        return false;
    }
    return true;
}

void append_js_endpoints(endpoint_sink_t& sink,
                         const std::string& source,
                         const std::string& label,
                         bool include_relative,
                         std::size_t max_results,
                         const std::string& source_kind,
                         double confidence_scale)
{
    json eps = js_analysis_tools::extract_endpoints_from_source(source, label, include_relative, max_results);
    for (const auto& ep : eps) {
        json extra = ep;
        const std::string method = ep.value("method", std::string("UNKNOWN"));
        const std::string path = ep.value("path", std::string());
        const double base_conf = ep.value("confidence", 0.60);
        extra.erase("method");
        extra.erase("path");
        extra.erase("source");
        extra["js_source"] = ep.value("source", std::string());
        push_endpoint(sink, method, path, source_kind, std::min(0.99, base_conf * confidence_scale), extra);
    }
}

void append_sitemap_endpoints(endpoint_sink_t& sink, const std::string& host, std::uint16_t port)
{
    if (host.empty() || port == 0) return;
    const auto paths = burp::sitemap::list_paths(host, port);
    for (const std::string& path : paths) {
        if (call_expired()) return;
        const auto exchanges = burp::sitemap::list_exchanges_for(host, port, path);
        if (exchanges.empty()) {
            json extra;
            extra["host"] = host;
            extra["port"] = port;
            push_endpoint(sink, "UNKNOWN", path, "sitemap", 0.62, extra);
        } else {
            for (const auto& ex : exchanges) {
                json extra;
                extra["host"] = ex.host;
                extra["port"] = ex.port;
                extra["status"] = ex.status_code;
                extra["exchange_id"] = ex.id;
                push_endpoint(sink, ex.method, ex.path.empty() ? path : ex.path, "sitemap", 0.72, extra);
            }
        }
    }
}

std::string body_to_string(const std::vector<std::uint8_t>& body)
{
    if (body.empty()) return {};
    return std::string(reinterpret_cast<const char*>(body.data()), body.size());
}

std::set<std::string> json_top_keys(const std::string& text)
{
    std::set<std::string> keys;
    json parsed = json::parse(text, nullptr, false);
    if (!parsed.is_object()) return keys;
    for (auto it = parsed.begin(); it != parsed.end(); ++it)
        keys.insert(it.key());
    return keys;
}

json set_difference_json(const std::set<std::string>& a, const std::set<std::string>& b)
{
    json out = json::array();
    for (const auto& v : a) {
        if (b.find(v) == b.end()) out.push_back(v);
    }
    return out;
}

std::string value_type_label(const json& value)
{
    if (value.is_null()) return "null";
    if (value.is_boolean()) return "boolean";
    if (value.is_number_integer()) return "integer";
    if (value.is_number_unsigned()) return "unsigned";
    if (value.is_number_float()) return "float";
    if (value.is_string()) return "string";
    if (value.is_array()) return "array";
    if (value.is_object()) return "object";
    return "unknown";
}

json default_mass_assignment_fields()
{
    json fields = json::object();
    fields["isAdmin"] = true;
    fields["admin"] = true;
    fields["role"] = "admin";
    fields["roles"] = json::array({"admin"});
    fields["permissions"] = json::array({"*"});
    fields["plan"] = "enterprise";
    fields["subscription"] = "premium";
    fields["verified"] = true;
    fields["email_verified"] = true;
    fields["owner"] = true;
    fields["price"] = 0;
    fields["credit"] = 999999;
    return fields;
}

json candidate_fields_from_params(const json& params)
{
    json fields = default_mass_assignment_fields();
    if (params.contains("fields") && params["fields"].is_object()) {
        for (auto it = params["fields"].begin(); it != params["fields"].end(); ++it)
            fields[it.key()] = it.value();
    }
    if (params.contains("candidate_fields") && params["candidate_fields"].is_array()) {
        json custom = json::object();
        for (const auto& v : params["candidate_fields"]) {
            if (v.is_string()) {
                const std::string name = v.get<std::string>();
                if (!name.empty()) {
                    if (fields.contains(name))
                        custom[name] = fields[name];
                    else
                        custom[name] = true;
                }
            } else if (v.is_object() && v.contains("name") && v["name"].is_string()) {
                const std::string name = v["name"].get<std::string>();
                if (!name.empty()) {
                    if (v.contains("value"))
                        custom[name] = v["value"];
                    else
                        custom[name] = true;
                }
            }
        }
        if (!custom.empty()) fields = std::move(custom);
    }
    return fields;
}

std::vector<std::uint8_t> build_json_request(const std::string& method,
                                             const std::string& host,
                                             std::uint16_t port,
                                             bool tls,
                                             const std::string& path,
                                             const json& body,
                                             const json& headers)
{
    const std::string body_text = body.dump();
    std::ostringstream req;
    req << upper_copy(method) << " " << (path.empty() ? "/" : path) << " HTTP/1.1\r\n";
    req << "Host: " << host_header_value(host, port, tls) << "\r\n";
    bool has_content_type = false;
    for (const auto& h : headers_from_json(headers)) {
        if (lower_copy(h.first) == "content-type") has_content_type = true;
        req << h.first << ": " << h.second << "\r\n";
    }
    if (!has_content_type) req << "Content-Type: application/json\r\n";
    req << "Accept: application/json, text/plain, */*\r\n";
    req << "User-Agent: AiDA-API-MassAssignment/1.0\r\n";
    req << "Content-Length: " << body_text.size() << "\r\n";
    req << "Connection: close\r\n\r\n";
    req << body_text;
    const std::string raw = req.str();
    return std::vector<std::uint8_t>(raw.begin(), raw.end());
}

json exchange_summary(const burp::exchange_observed_t& ex)
{
    const std::string body = body_to_string(ex.resp_body);
    json out;
    out["status"] = ex.status_code;
    out["latency_ms"] = ex.latency_ms;
    out["body_length"] = static_cast<std::uint64_t>(ex.resp_body.size());
    out["body_sha256"] = js_analysis_tools::sha256_hex(body);
    out["json_top_keys"] = json::array();
    for (const auto& key : json_top_keys(body)) out["json_top_keys"].push_back(key);
    return out;
}

std::optional<burp::exchange_observed_t> send_json_variant(const std::string& method,
                                                           const std::string& url,
                                                           const json& body,
                                                           const json& headers,
                                                           int timeout_ms,
                                                           bool enforce_scope,
                                                           std::string& error)
{
    std::string scheme, host, path;
    std::uint16_t port = 0;
    if (!burp::audit_http::parse_url(url, scheme, host, port, path)) {
        error = "url parse failed";
        return std::nullopt;
    }
    const bool tls = scheme == "https";
    std::vector<std::uint8_t> raw = build_json_request(method, host, port, tls, path, body, headers);
    burp::audit_http::send_options_t opts;
    opts.timeout_ms = bounded_timeout_ms(timeout_ms, 15000, 250, 45000);
    opts.follow_redirects = false;
    opts.max_redirects = 0;
    opts.enforce_scope = enforce_scope;
    opts.exchange_source = "api_mass_assignment";
    auto ex = burp::audit_http::send(raw, host, port, tls, opts);
    if (!ex.has_value()) {
        error = burp::audit_http::last_error();
        return std::nullopt;
    }
    return ex;
}

tool_result_t tool_discover_openapi(const json& params)
{
    diag::log_tagged_fmt("api_enum", "discover_openapi entry has_url=%d has_source=%d", params.contains("url") ? 1 : 0, params.contains("source") ? 1 : 0);
    json out;
    out["found"] = false;
    out["probes"] = json::array();
    const std::string format = params.value("format", std::string("auto"));
    if (params.contains("source") && params["source"].is_string()) {
        const std::string source = params["source"].get<std::string>();
        std::uint64_t id = 0;
        json collection;
        std::string error;
        if (import_spec_text(source, "inline_source", format, id, collection, error)) {
            out["found"] = true;
            out["source"] = "inline_source";
            out["collection_id"] = id;
            out["collection"] = std::move(collection);
            out["spec_sha256"] = js_analysis_tools::sha256_hex(source);
            return tool_result_t::ok(out.dump(2), out);
        }
        out["error"] = error;
        return tool_result_t::error("OpenAPI source parse failed", out);
    }
    if (!params.contains("url") || !params["url"].is_string())
        return tool_result_t::error("url or source is required");

    const std::string url = params["url"].get<std::string>();
    const int timeout_ms = params.value("timeout_ms", 12000);
    const bool enforce_scope = params.value("enforce_scope", false);
    const int max_probes = std::max(1, std::min(params.value("max_probes", 12), 32));
    const std::size_t max_bytes = static_cast<std::size_t>(std::max(65536, std::min(params.value("max_source_bytes", 8388608), 33554432)));
    std::vector<std::string> candidates = openapi_candidate_urls(url);
    if (candidates.empty()) candidates.push_back(url);
    if (static_cast<int>(candidates.size()) > max_probes) candidates.resize(static_cast<std::size_t>(max_probes));

    for (const std::string& candidate : candidates) {
        if (call_expired())
            return tool_result_t::error("cancelled", out);
        json probe;
        probe["url"] = js_analysis_tools::redact_url_for_output(candidate);
        fetch_result_t fetched = fetch_text_url(candidate, params.value("headers", json::object()), timeout_ms, enforce_scope, max_bytes, "api_openapi_discovery");
        probe["status"] = fetched.status;
        probe["content_type"] = fetched.content_type;
        probe["bytes"] = static_cast<std::uint64_t>(fetched.body.size());
        probe["truncated"] = fetched.truncated;
        if (!fetched.ok) {
            probe["ok"] = false;
            probe["error"] = fetched.error;
            out["probes"].push_back(std::move(probe));
            continue;
        }
        std::uint64_t id = 0;
        json collection;
        std::string error;
        if (import_spec_text(fetched.body, candidate, format, id, collection, error)) {
            probe["ok"] = true;
            probe["collection_id"] = id;
            out["probes"].push_back(std::move(probe));
            out["found"] = true;
            out["source"] = js_analysis_tools::redact_url_for_output(candidate);
            out["collection_id"] = id;
            out["collection"] = std::move(collection);
            out["spec_sha256"] = js_analysis_tools::sha256_hex(fetched.body);
            diag::log_tagged_fmt("api_enum", "discover_openapi found url=%s collection_id=%llu", js_analysis_tools::redact_url_for_output(candidate).c_str(), static_cast<unsigned long long>(id));
            return tool_result_t::ok(out.dump(2), out);
        }
        probe["ok"] = false;
        probe["parse_error"] = error;
        out["probes"].push_back(std::move(probe));
    }
    return tool_result_t::ok(out.dump(2), out);
}

tool_result_t tool_enumerate_endpoints(const json& params)
{
    diag::log_tagged_fmt("api_enum", "enumerate_endpoints entry has_url=%d has_source=%d", params.contains("url") ? 1 : 0, params.contains("source") ? 1 : 0);
    endpoint_sink_t sink;
    json sources = json::array();
    const bool include_relative = params.value("include_relative", true);
    const std::size_t max_results = static_cast<std::size_t>(std::max(1, std::min(params.value("max_results", 1024), 8192)));

    if (params.contains("collection_id") && params["collection_id"].is_number()) {
        burp::api_definition::api_collection_t col;
        std::string error;
        const std::uint64_t id = params["collection_id"].get<std::uint64_t>();
        if (collection_from_id(id, col, error)) {
            append_collection_endpoints(sink, col, "openapi_collection", 0.98);
            sources.push_back(json{{"type", "collection"}, {"collection_id", id}, {"requests", static_cast<std::uint64_t>(col.requests.size())}});
        }
    }

    if (params.contains("source") && params["source"].is_string() && sink.endpoints.size() < max_results) {
        const std::string source = params["source"].get<std::string>();
        const std::string label = params.value("source_name", std::string("inline_source"));
        std::uint64_t id = 0;
        json collection;
        std::string error;
        if (import_spec_text(source, label, params.value("format", std::string("auto")), id, collection, error)) {
            burp::api_definition::api_collection_t col;
            if (burp::api_definition::get_collection(id, col))
                append_collection_endpoints(sink, col, "openapi_source", 0.96);
            sources.push_back(json{{"type", "openapi_source"}, {"collection_id", id}, {"sha256", js_analysis_tools::sha256_hex(source)}});
        } else {
            append_js_endpoints(sink, source, label, include_relative, max_results - sink.endpoints.size(), "static_js_source", 1.0);
            sources.push_back(json{{"type", "static_js_source"}, {"parse_error", error}, {"sha256", js_analysis_tools::sha256_hex(source)}});
        }
    }

    if (params.contains("url") && params["url"].is_string() && sink.endpoints.size() < max_results) {
        const std::string url = params["url"].get<std::string>();
        const int timeout_ms = params.value("timeout_ms", 12000);
        const bool enforce_scope = params.value("enforce_scope", false);
        const std::size_t max_bytes = static_cast<std::size_t>(std::max(65536, std::min(params.value("max_source_bytes", 8388608), 33554432)));
        std::vector<std::string> candidates = url_looks_like_spec(url) ? std::vector<std::string>{url} : openapi_candidate_urls(url);
        const int max_probes = std::max(1, std::min(params.value("max_probes", 8), 24));
        if (static_cast<int>(candidates.size()) > max_probes) candidates.resize(static_cast<std::size_t>(max_probes));
        bool parsed_spec = false;
        for (const std::string& candidate : candidates) {
            if (call_expired())
                return tool_result_t::error("cancelled");
            fetch_result_t fetched = fetch_text_url(candidate, params.value("headers", json::object()), timeout_ms, enforce_scope, max_bytes, "api_endpoint_enum");
            json src;
            src["type"] = "url_probe";
            src["url"] = js_analysis_tools::redact_url_for_output(candidate);
            src["status"] = fetched.status;
            src["bytes"] = static_cast<std::uint64_t>(fetched.body.size());
            if (!fetched.ok) {
                src["error"] = fetched.error;
                sources.push_back(std::move(src));
                continue;
            }
            std::uint64_t id = 0;
            json collection;
            std::string error;
            if (import_spec_text(fetched.body, candidate, params.value("format", std::string("auto")), id, collection, error)) {
                burp::api_definition::api_collection_t col;
                if (burp::api_definition::get_collection(id, col))
                    append_collection_endpoints(sink, col, "openapi_url", 0.96);
                src["type"] = "openapi_url";
                src["collection_id"] = id;
                parsed_spec = true;
                sources.push_back(std::move(src));
                break;
            }
            if (candidate == url) {
                append_js_endpoints(sink, fetched.body, candidate, include_relative, max_results - sink.endpoints.size(), "static_js_url", 1.0);
                src["type"] = "static_js_url";
                src["parse_error"] = error;
            } else {
                src["parse_error"] = error;
            }
            sources.push_back(std::move(src));
        }
        if (!parsed_spec && !url_looks_like_spec(url) && sink.endpoints.size() < max_results) {
            fetch_result_t fetched = fetch_text_url(url, params.value("headers", json::object()), timeout_ms, enforce_scope, max_bytes, "api_endpoint_enum_js");
            if (fetched.ok) {
                append_js_endpoints(sink, fetched.body, url, include_relative, max_results - sink.endpoints.size(), "static_js_url", 1.0);
                sources.push_back(json{{"type", "static_js_url"}, {"url", js_analysis_tools::redact_url_for_output(url)}, {"bytes", static_cast<std::uint64_t>(fetched.body.size())}});
            }
        }
    }

    if (params.value("include_sitemap", true) && sink.endpoints.size() < max_results) {
        std::string host = params.value("host", std::string());
        std::uint16_t port = 0;
        if (params.contains("port")) {
            const auto& value = params["port"];
            std::uint64_t parsed = 0;
            if (value.is_number_unsigned())
                parsed = value.get<std::uint64_t>();
            else if (value.is_number_integer()) {
                const auto signed_value = value.get<std::int64_t>();
                if (signed_value < 0)
                    return tool_result_t::error("port must be an integer from 0 to 65535");
                parsed = static_cast<std::uint64_t>(signed_value);
            } else {
                return tool_result_t::error("port must be an integer from 0 to 65535");
            }
            if (parsed > 65535)
                return tool_result_t::error("port must be an integer from 0 to 65535");
            port = static_cast<std::uint16_t>(parsed);
        }
        if (host.empty() && params.contains("url") && params["url"].is_string()) {
            std::string scheme, path;
            burp::audit_http::parse_url(params["url"].get<std::string>(), scheme, host, port, path);
        }
        const std::size_t before = sink.endpoints.size();
        append_sitemap_endpoints(sink, host, port);
        if (sink.endpoints.size() != before)
            sources.push_back(json{{"type", "sitemap"}, {"host", host}, {"port", port}, {"count", static_cast<std::uint64_t>(sink.endpoints.size() - before)}});
    }

    if (params.value("include_browser_scripts", false) && sink.endpoints.size() < max_results) {
        json args;
        args["action"] = "list";
        args["page_id"] = params.value("page_id", std::string());
        args["session_id"] = params.value("session_id", std::string());
        auto list = burp::camoufox::call_tool("scripts", args, bounded_timeout_ms(params.value("browser_timeout_ms", 15000), 15000, 250, 45000));
        json browser_source;
        browser_source["type"] = "browser_scripts";
        browser_source["ok"] = list.ok;
        if (list.ok && list.data.is_object() && list.data.contains("scripts") && list.data["scripts"].is_array()) {
            std::size_t scripts_seen = 0;
            for (const auto& item : list.data["scripts"]) {
                if (sink.endpoints.size() >= max_results || scripts_seen >= 32 || call_expired()) break;
                if (!item.is_object()) continue;
                const std::string script_url = item.value("url", std::string());
                if (script_url.empty()) continue;
                json get_args;
                get_args["action"] = "get";
                get_args["url"] = script_url;
                get_args["page_id"] = args["page_id"];
                get_args["session_id"] = args["session_id"];
                auto got = burp::camoufox::call_tool("scripts", get_args, bounded_timeout_ms(params.value("browser_timeout_ms", 15000), 15000, 250, 45000));
                if (got.ok && got.data.is_object() && got.data.contains("source") && got.data["source"].is_string()) {
                    append_js_endpoints(sink, got.data["source"].get<std::string>(), script_url, include_relative, max_results - sink.endpoints.size(), "browser_script", 1.0);
                    ++scripts_seen;
                }
            }
            browser_source["scripts_examined"] = static_cast<std::uint64_t>(scripts_seen);
        } else {
            browser_source["error"] = list.error.empty() ? list.text : list.error;
        }
        sources.push_back(std::move(browser_source));
    }

    if (sink.endpoints.size() > max_results) {
        json trimmed = json::array();
        for (std::size_t i = 0; i < max_results; ++i)
            trimmed.push_back(sink.endpoints[i]);
        sink.endpoints = std::move(trimmed);
    }
    json out;
    out["count"] = sink.endpoints.size();
    out["sources"] = std::move(sources);
    out["endpoints"] = std::move(sink.endpoints);
    diag::log_tagged_fmt("api_enum", "enumerate_endpoints done count=%zu", out["count"].get<std::size_t>());
    return tool_result_t::ok(out.dump(2), out);
}

tool_result_t tool_test_mass_assignment(const json& params)
{
    diag::log_tagged_fmt("api_enum", "test_mass_assignment entry has_url=%d", params.contains("url") ? 1 : 0);
    if (!params.contains("url") || !params["url"].is_string())
        return tool_result_t::error("url is required");
    if (!params.contains("body") || !params["body"].is_object())
        return tool_result_t::error("body object is required");
    const std::string url = params["url"].get<std::string>();
    const std::string method = normalize_method(params.value("method", std::string("POST")));
    if (method == "UNKNOWN" || method == "GET" || method == "HEAD")
        return tool_result_t::error("method must be POST, PUT, PATCH, DELETE, or OPTIONS for JSON body variants");
    const int timeout_ms = params.value("timeout_ms", 15000);
    const bool enforce_scope = params.value("enforce_scope", false);
    const int max_variants = std::max(1, std::min(params.value("max_variants", 8), 20));
    const json headers = params.value("headers", json::object());
    const json baseline_body = params["body"];
    std::string error;
    auto baseline = send_json_variant(method, url, baseline_body, headers, timeout_ms, enforce_scope, error);
    if (!baseline.has_value()) {
        json err;
        err["error"] = error;
        err["url"] = js_analysis_tools::redact_url_for_output(url);
        return tool_result_t::error("baseline request failed", err);
    }
    const json baseline_summary = exchange_summary(*baseline);
    const std::string baseline_resp = body_to_string(baseline->resp_body);
    const std::set<std::string> baseline_keys = json_top_keys(baseline_resp);
    json fields = candidate_fields_from_params(params);
    json evidence = json::array();
    int sent = 0;
    for (auto it = fields.begin(); it != fields.end() && sent < max_variants; ++it) {
        if (call_expired())
            return tool_result_t::error("cancelled");
        const std::string field = it.key();
        if (field.empty() || baseline_body.contains(field)) continue;
        json variant_body = baseline_body;
        variant_body[field] = it.value();
        std::string send_error;
        auto variant = send_json_variant(method, url, variant_body, headers, timeout_ms, enforce_scope, send_error);
        ++sent;
        if (!variant.has_value()) {
            json row;
            row["field"] = field;
            row["value_type"] = value_type_label(it.value());
            row["transport_error"] = send_error;
            evidence.push_back(std::move(row));
            continue;
        }
        const std::string variant_resp = body_to_string(variant->resp_body);
        const std::set<std::string> variant_keys = json_top_keys(variant_resp);
        const bool status_changed = variant->status_code != baseline->status_code;
        const long long length_delta = static_cast<long long>(variant->resp_body.size()) - static_cast<long long>(baseline->resp_body.size());
        const long long abs_length_delta = length_delta < 0 ? -length_delta : length_delta;
        const bool hash_changed = js_analysis_tools::sha256_hex(variant_resp) != js_analysis_tools::sha256_hex(baseline_resp);
        const bool reflected_field = baseline_resp.find(field) == std::string::npos && variant_resp.find(field) != std::string::npos;
        const json added_keys = set_difference_json(variant_keys, baseline_keys);
        const json removed_keys = set_difference_json(baseline_keys, variant_keys);
        const bool key_delta = !added_keys.empty() || !removed_keys.empty();
        if (status_changed || abs_length_delta > 16 || reflected_field || key_delta) {
            json row;
            row["field"] = field;
            row["value_type"] = value_type_label(it.value());
            row["baseline_status"] = baseline->status_code;
            row["variant_status"] = variant->status_code;
            row["status_changed"] = status_changed;
            row["length_delta"] = length_delta;
            row["baseline_body_length"] = static_cast<std::uint64_t>(baseline->resp_body.size());
            row["variant_body_length"] = static_cast<std::uint64_t>(variant->resp_body.size());
            row["variant_body_sha256"] = js_analysis_tools::sha256_hex(variant_resp);
            row["body_hash_changed"] = hash_changed;
            row["reflected_field_name"] = reflected_field;
            row["json_keys_added"] = added_keys;
            row["json_keys_removed"] = removed_keys;
            row["confidence"] = status_changed || key_delta ? 0.78 : (reflected_field ? 0.70 : 0.55);
            evidence.push_back(std::move(row));
        }
    }
    json out;
    out["url"] = js_analysis_tools::redact_url_for_output(url);
    out["method"] = method;
    out["baseline"] = baseline_summary;
    out["variants_sent"] = sent;
    out["evidence_count"] = evidence.size();
    out["differential_evidence"] = std::move(evidence);
    out["no_differential_evidence"] = out["evidence_count"].get<std::size_t>() == 0;
    diag::log_tagged_fmt("api_enum", "test_mass_assignment done variants=%d evidence=%zu", sent, out["evidence_count"].get<std::size_t>());
    return tool_result_t::ok(out.dump(2), out);
}

tool_result_t tool_jwt_test_confusion(const json& params)
{
    diag::log_tagged_fmt("api_enum", "jwt_test_confusion entry token_present=%d pem_present=%d", params.contains("token") ? 1 : 0, params.contains("rsa_public_pem") ? 1 : 0);
    if (!params.contains("token") || !params["token"].is_string())
        return tool_result_t::error("token is required");
    if (!params.contains("rsa_public_pem") || !params["rsa_public_pem"].is_string())
        return tool_result_t::error("rsa_public_pem is required");
    const std::string token = params["token"].get<std::string>();
    const std::string pem = params["rsa_public_pem"].get<std::string>();
    burp::jwt_lab::jwt_parsed_t parsed = burp::jwt_lab::decode(token);
    if (!parsed.valid_structure) {
        json err;
        err["token_sha256"] = js_analysis_tools::sha256_hex(token);
        err["token_length"] = static_cast<std::uint64_t>(token.size());
        err["error"] = burp::jwt_lab::last_error();
        return tool_result_t::error("invalid JWT structure", err);
    }
    std::vector<std::string> candidates = burp::jwt_lab::attack_alg_confusion(token, pem);
    json rows = json::array();
    for (const auto& c : candidates) {
        burp::jwt_lab::jwt_parsed_t cp = burp::jwt_lab::decode(c);
        json row;
        row["candidate_sha256"] = js_analysis_tools::sha256_hex(c);
        row["candidate_length"] = static_cast<std::uint64_t>(c.size());
        row["alg"] = cp.alg;
        row["valid_structure"] = cp.valid_structure;
        rows.push_back(std::move(row));
    }
    json out;
    out["original_alg"] = parsed.alg;
    out["token_sha256"] = js_analysis_tools::sha256_hex(token);
    out["token_length"] = static_cast<std::uint64_t>(token.size());
    out["rsa_public_pem_sha256"] = js_analysis_tools::sha256_hex(pem);
    out["rsa_public_pem_length"] = static_cast<std::uint64_t>(pem.size());
    out["candidate_count"] = rows.size();
    out["candidates"] = std::move(rows);
    out["raw_tokens_returned"] = false;
    return tool_result_t::ok(out.dump(2), out);
}

std::string kid_payload_kind(const std::string& kid)
{
    const std::string k = lower_copy(kid);
    if (k.find("union") != std::string::npos || k.find("select") != std::string::npos)
        return "sql_meta_character_probe";
    if (k.find("file:") != std::string::npos)
        return "file_url_probe";
    if (k.find("\\") != std::string::npos || k.find("nul") != std::string::npos)
        return "windows_path_probe";
    if (k.find("../") != std::string::npos || k.find("..%2f") != std::string::npos || k.find("/dev/") != std::string::npos || k.find("/etc/") != std::string::npos || k.find("/proc/") != std::string::npos)
        return "posix_path_traversal_probe";
    return "header_key_id_probe";
}

tool_result_t tool_jwt_test_kid_injection(const json& params)
{
    diag::log_tagged_fmt("api_enum", "jwt_test_kid_injection entry token_present=%d payloads_present=%d", params.contains("token") ? 1 : 0, params.contains("kid_payloads") ? 1 : 0);
    if (!params.contains("token") || !params["token"].is_string())
        return tool_result_t::error("token is required");
    const std::string token = params["token"].get<std::string>();
    burp::jwt_lab::jwt_parsed_t parsed = burp::jwt_lab::decode(token);
    if (!parsed.valid_structure) {
        json err;
        err["token_sha256"] = js_analysis_tools::sha256_hex(token);
        err["token_length"] = static_cast<std::uint64_t>(token.size());
        err["error"] = burp::jwt_lab::last_error();
        return tool_result_t::error("invalid JWT structure", err);
    }
    std::set<std::string> requested_kid_hashes;
    json requested = json::array();
    if (params.contains("kid_payloads") && params["kid_payloads"].is_array()) {
        for (const auto& item : params["kid_payloads"]) {
            if (!item.is_string())
                continue;
            const std::string kid = item.get<std::string>();
            if (kid.empty() || kid.size() > 1024)
                continue;
            const std::string hash = js_analysis_tools::sha256_hex(kid);
            requested_kid_hashes.insert(hash);
            requested.push_back(json{{"kid_sha256", hash}, {"kid_length", static_cast<std::uint64_t>(kid.size())}, {"kind", kid_payload_kind(kid)}});
        }
    }
    const std::size_t max_candidates = static_cast<std::size_t>(std::max(1, std::min(params.value("max_candidates", 32), 128)));
    std::vector<std::string> candidates = burp::jwt_lab::attack_kid_traversal(token);
    json rows = json::array();
    for (const auto& c : candidates) {
        if (rows.size() >= max_candidates || call_expired())
            break;
        burp::jwt_lab::jwt_parsed_t cp = burp::jwt_lab::decode(c);
        const std::string kid_hash = js_analysis_tools::sha256_hex(cp.kid);
        if (!requested_kid_hashes.empty() && requested_kid_hashes.find(kid_hash) == requested_kid_hashes.end())
            continue;
        json row;
        row["candidate_sha256"] = js_analysis_tools::sha256_hex(c);
        row["candidate_length"] = static_cast<std::uint64_t>(c.size());
        row["valid_structure"] = cp.valid_structure;
        row["alg"] = cp.alg;
        row["kid_sha256"] = kid_hash;
        row["kid_length"] = static_cast<std::uint64_t>(cp.kid.size());
        row["kid_kind"] = kid_payload_kind(cp.kid);
        rows.push_back(std::move(row));
    }
    json out;
    out["original_alg"] = parsed.alg;
    out["original_kid_present"] = !parsed.kid.empty();
    if (!parsed.kid.empty()) {
        out["original_kid_sha256"] = js_analysis_tools::sha256_hex(parsed.kid);
        out["original_kid_length"] = static_cast<std::uint64_t>(parsed.kid.size());
    }
    out["token_sha256"] = js_analysis_tools::sha256_hex(token);
    out["token_length"] = static_cast<std::uint64_t>(token.size());
    out["requested_payloads"] = std::move(requested);
    out["candidate_count"] = rows.size();
    out["candidates"] = std::move(rows);
    out["raw_tokens_returned"] = false;
    out["kid_payload_filter_applied"] = !requested_kid_hashes.empty();
    return tool_result_t::ok(out.dump(2), out);
}

}

void register_api_enum_tools(mcp_standalone::server_t& srv)
{
    using p = mcp_standalone::tool_param_t;
    srv.register_tool({
        "aida.api.discover_openapi",
        "Discover OpenAPI or Swagger definitions from a supplied source or common well-known paths.",
        {p{"url", "string", "Base URL or direct OpenAPI/Swagger URL to probe.", false},
         p{"source", "string", "Inline OpenAPI/Swagger JSON or YAML source.", false},
         p{"format", "string", "auto|openapi_json|openapi_yaml|swagger_v2.", false},
         p{"headers", "object", "Optional request headers for probes.", false},
         p{"max_probes", "number", "Maximum common paths to probe.", false},
         p{"max_source_bytes", "number", "Maximum fetched spec bytes.", false},
         p{"timeout_ms", "number", "Per-probe timeout.", false},
         p{"enforce_scope", "boolean", "Require Burp scope for outbound probes.", false}},
        false,
        tool_discover_openapi
    });

    srv.register_tool({
        "aida.api.enumerate_endpoints",
        "Enumerate API endpoints from OpenAPI collections/specs, sitemap entries, browser scripts, and static JavaScript.",
        {p{"url", "string", "Base URL, direct spec URL, or JavaScript URL.", false},
         p{"source", "string", "Inline OpenAPI/Swagger or JavaScript source.", false},
         p{"source_name", "string", "Label for inline source.", false},
         p{"format", "string", "auto|openapi_json|openapi_yaml|swagger_v2.", false},
         p{"collection_id", "number", "Existing API collection ID from burp_api_manage/import.", false},
         p{"headers", "object", "Optional request headers for URL probes.", false},
         p{"include_relative", "boolean", "Include relative JS API paths.", false},
         p{"include_sitemap", "boolean", "Include Burp sitemap paths for host/port.", false},
         p{"include_browser_scripts", "boolean", "Query loaded Camoufox browser scripts.", false},
         p{"host", "string", "Sitemap host override.", false},
         p{"port", "number", "Sitemap port override.", false},
         p{"max_results", "number", "Maximum endpoints to return.", false},
         p{"max_probes", "number", "Maximum OpenAPI probes.", false},
         p{"max_source_bytes", "number", "Maximum fetched source bytes.", false},
         p{"timeout_ms", "number", "Per-fetch timeout.", false},
         p{"page_id", "string", "Optional Camoufox page id for browser script enumeration.", false},
         p{"session_id", "string", "Optional Camoufox session id for browser script enumeration.", false},
         p{"browser_timeout_ms", "number", "Bounded Camoufox script query timeout.", false},
         p{"enforce_scope", "boolean", "Require Burp scope for outbound probes.", false}},
        false,
        tool_enumerate_endpoints
    });

    srv.register_tool({
        "aida.api.test_mass_assignment",
        "Send bounded JSON field-injection variants and report status, length, hash, and JSON-shape differential evidence only.",
        {p{"url", "string", "Target endpoint URL.", true},
         p{"method", "string", "POST|PUT|PATCH|DELETE|OPTIONS.", false},
         p{"headers", "object", "Optional request headers.", false},
         p{"body", "object", "Baseline JSON object body.", true},
         p{"fields", "object", "Candidate field values keyed by field name.", false},
         p{"candidate_fields", "array", "Candidate field names or objects with name/value.", false},
         p{"max_variants", "number", "Maximum variants to send.", false},
         p{"timeout_ms", "number", "Per-request timeout.", false},
         p{"enforce_scope", "boolean", "Require Burp scope for outbound requests.", false}},
        false,
        tool_test_mass_assignment
    });

    srv.register_tool({
        "aida.jwt.test_confusion",
        "Generate JWT algorithm-confusion candidates using the existing JWT lab and return redacted hashes and metadata only.",
        {p{"token", "string", "JWT to test; raw token is never returned.", true},
         p{"rsa_public_pem", "string", "RSA public key PEM used as HMAC material; raw key is never returned.", true}},
        true,
        tool_jwt_test_confusion
    });

    srv.register_tool({
        "aida.jwt.test_kid_injection",
        "Generate JWT kid traversal/injection candidates through the existing JWT lab and return redacted hashes and metadata only.",
        {p{"token", "string", "JWT to test; raw token is never returned.", true},
         p{"kid_payloads", "array", "Optional kid payload allow-list; values are hashed and matched against generated probes.", false},
         p{"max_candidates", "number", "Maximum candidate metadata rows to return.", false}},
        true,
        tool_jwt_test_kid_injection
    });
}

}
}
}
