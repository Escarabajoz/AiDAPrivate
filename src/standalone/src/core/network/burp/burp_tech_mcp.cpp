#include "burp_tech_mcp.hpp"
#include "tech_fingerprint.hpp"
#include "audit_http.hpp"
#include "burp_events.hpp"
#include "../../infra/event_bus.hpp"

#include "../../../helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace tech {

namespace {

using mcp_standalone::tool_def_t;
using mcp_standalone::tool_result_t;
using nlohmann::json;

tool_result_t error_with_data(const std::string& text, const json& data)
{
    return tool_result_t{false, text, data};
}

std::vector<uint8_t> build_get_request(const std::string& host, const std::string& path)
{
    std::string s;
    s += "GET "; s += path.empty() ? std::string("/") : path; s += " HTTP/1.1\r\n";
    s += "Host: "; s += host; s += "\r\n";
    s += "User-Agent: AiDA-Burp/1.0\r\n";
    s += "Accept: */*\r\n";
    s += "Connection: close\r\n\r\n";
    return std::vector<uint8_t>(s.begin(), s.end());
}

json tech_to_json(const tech_t& t)
{
    json j;
    j["name"]             = t.name;
    j["category"]         = t.category;
    j["version"]          = t.version;
    j["confidence_label"] = t.confidence_label;
    return j;
}

tool_result_t tool_fingerprint(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "tech_fingerprint entry");
    if (!params.is_object() || !params.contains("url") || !params["url"].is_string())
    {
        diag::log_tagged_fmt("mcp_burp", "tech_fingerprint missing_url");
        return tool_result_t::error("missing_url");
    }
    std::string url = params["url"].get<std::string>();
    diag::log_tagged_fmt("mcp_burp", "tech_fingerprint url=%s", url.c_str());
    initialize();
    std::string scheme, host, path;
    uint16_t port = 0;
    if (!audit_http::parse_url(url, scheme, host, port, path))
    {
        diag::log_tagged_fmt("mcp_burp", "tech_fingerprint invalid_url url=%s", url.c_str());
        json data;
        data["error"] = "invalid_url";
        data["url"] = url;
        data["status"] = "parse_failed";
        return error_with_data("invalid_url", data);
    }
    bool tls = (scheme == "https");
    audit_http::send_options_t opt;
    opt.timeout_ms = 15000;
    opt.follow_redirects = true;
    opt.return_first_redirect = false;
    opt.enforce_scope = false;
    opt.publish_exchange = true;
    opt.exchange_source = "tech_fingerprint";
    std::string host_header = host;
    if ((tls && port != 443) || (!tls && port != 80)) {
        host_header += ":";
        host_header += std::to_string(port);
    }
    diag::log_tagged_fmt("mcp_burp", "tech_fingerprint send_options timeout_ms=%d follow_redirects=%d return_first_redirect=%d publish_exchange=%d",
        opt.timeout_ms, opt.follow_redirects ? 1 : 0, opt.return_first_redirect ? 1 : 0, opt.publish_exchange ? 1 : 0);
    auto req = build_get_request(host_header, path);
    auto resp = audit_http::send(req, host, port, tls, opt);
    if (!resp.has_value())
    {
        std::string err = audit_http::last_error();
        diag::log_tagged_fmt("mcp_burp", "tech_fingerprint send_failed err=%s", err.c_str());
        json data;
        data["error"] = err;
        data["url"] = url;
        data["scheme"] = scheme;
        data["host"] = host;
        data["port"] = port;
        data["path"] = path;
        data["tls"] = tls;
        data["status"] = "send_failed";
        return error_with_data(std::string("send_failed: ") + err, data);
    }
    auto items = fingerprint(resp->resp_headers, resp->resp_body, url);
    diag::log_tagged_fmt("mcp_burp", "tech_fingerprint ok url=%s status=%d techs=%zu latency_ms=%llu tls_version=%s alpn=%s exchange_id=%llu",
        url.c_str(), resp->status_code, items.size(), static_cast<unsigned long long>(resp->latency_ms),
        resp->tls_version.c_str(), resp->alpn.c_str(), static_cast<unsigned long long>(resp->id));
    json arr = json::array();
    for (const auto& t : items) arr.push_back(tech_to_json(t));
    json out;
    out["url"]          = url;
    out["status_code"]  = resp->status_code;
    out["exchange_id"]  = resp->id;
    out["latency_ms"]   = resp->latency_ms;
    out["tls_version"]  = resp->tls_version;
    out["alpn"]         = resp->alpn;
    out["follow_redirects"] = opt.follow_redirects;
    out["technologies"] = arr;
    return tool_result_t::ok(out);
}

tool_result_t tool_inventory(const json& params)
{
    (void)params;
    diag::log_tagged_fmt("mcp_burp", "tech_inventory entry");
    auto items = inventory();
    json arr = json::array();
    for (const auto& h : items) {
        json techs = json::array();
        for (const auto& t : h.technologies) techs.push_back(tech_to_json(t));
        json h_obj;
        h_obj["host"]         = h.host;
        h_obj["technologies"] = techs;
        arr.push_back(h_obj);
    }
    diag::log_tagged_fmt("mcp_burp", "tech_inventory ok hosts=%zu", items.size());
    json out;
    out["host_count"] = arr.size();
    out["hosts"]      = arr;
    if (items.empty()) {
        out["status"] = "empty";
        out["error"] = "no_technology_fingerprints_recorded";
    }
    return tool_result_t::ok(out);
}

tool_result_t tool_clear(const json& params)
{
    (void)params;
    diag::log_tagged_fmt("mcp_burp", "tech_clear entry");
    clear_inventory();
    diag::log_tagged_fmt("mcp_burp", "tech_clear ok");
    json j;
    j["ok"] = true;
    return tool_result_t::ok(j);
}

}

void register_tech_tools(mcp_standalone::server_t& srv)
{
    {
        tool_def_t t;
        t.name = "burp_tech_fingerprint";
        t.description = "Fetch a URL and identify the underlying technology stack (web server, framework, CMS, "
                        "front-end library, CDN, analytics, auth) using header + body regex rules.";
        t.params = { {"url", "string", "Full URL", true} };
        t.read_only = false;
        t.handler = tool_fingerprint;
        srv.register_tool(std::move(t));
    }
    {
        tool_def_t t;
        t.name = "burp_tech_inventory";
        t.description = "Return the deduped inventory of technologies detected across every host observed during this session.";
        t.params = {};
        t.read_only = true;
        t.handler = tool_inventory;
        srv.register_tool(std::move(t));
    }
    {
        tool_def_t t;
        t.name = "burp_tech_clear";
        t.description = "Clear the tech-fingerprint inventory.";
        t.params = {};
        t.read_only = false;
        t.handler = tool_clear;
        srv.register_tool(std::move(t));
    }
}

}
}
}
