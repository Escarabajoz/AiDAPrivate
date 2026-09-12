#include "burp_csp_mcp.hpp"
#include "csp_analyzer.hpp"
#include "audit_http.hpp"

#include "../../../helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace csp {

namespace {

using mcp_standalone::tool_def_t;
using mcp_standalone::tool_result_t;
using nlohmann::json;

tool_result_t error_with_data(const std::string& text, const json& data)
{
    return tool_result_t{false, text, data};
}

nlohmann::json result_to_json(const csp_result_t& r)
{
    json j;
    j["score"] = r.score;
    j["has_csp"] = r.has_csp;
    j["is_report_only"] = r.is_report_only;
    json dirs = json::array();
    for (const auto& d : r.directives) {
        json o;
        o["name"] = d.name;
        o["values"] = d.values;
        dirs.push_back(o);
    }
    j["directives"] = dirs;
    json fs = json::array();
    for (const auto& f : r.findings) {
        json o;
        o["id"] = f.id;
        o["title"] = f.title;
        o["severity"] = f.severity;
        o["description"] = f.description;
        o["evidence"] = f.evidence;
        fs.push_back(o);
    }
    j["findings"] = fs;
    return j;
}

tool_result_t tool_analyze(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "csp_analyze entry");
    if (!params.is_object() || !params.contains("csp_header_value") || !params["csp_header_value"].is_string())
    {
        diag::log_tagged_fmt("mcp_burp", "csp_analyze missing_csp_header_value");
        return tool_result_t::error("missing_csp_header_value");
    }
    if (params["csp_header_value"].get_ref<const std::string&>().size() > 65536)
        return tool_result_t::error("csp_header_value exceeds 65536 bytes");
    bool report_only = false;
    if (params.contains("is_report_only") && params["is_report_only"].is_boolean())
        report_only = params["is_report_only"].get<bool>();
    diag::log_tagged_fmt("mcp_burp", "csp_analyze report_only=%d", (int)report_only);
    auto res = analyze(params["csp_header_value"].get<std::string>(), report_only);
    diag::log_tagged_fmt("mcp_burp", "csp_analyze ok score=%d findings=%zu", res.score, res.findings.size());
    return tool_result_t::ok(result_to_json(res));
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

tool_result_t tool_analyze_url(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "csp_analyze_url entry");
    if (!params.is_object() || !params.contains("url") || !params["url"].is_string())
    {
        diag::log_tagged_fmt("mcp_burp", "csp_analyze_url missing_url");
        return tool_result_t::error("missing_url");
    }
    const std::string url = params["url"].get<std::string>();
    diag::log_tagged_fmt("mcp_burp", "csp_analyze_url url=%s", url.c_str());
    std::string scheme, host, path;
    uint16_t port = 0;
    if (!audit_http::parse_url(url, scheme, host, port, path))
    {
        diag::log_tagged_fmt("mcp_burp", "csp_analyze_url invalid_url url=%s", url.c_str());
        json data;
        data["error"] = "invalid_url";
        data["url"] = url;
        data["status"] = "parse_failed";
        return error_with_data("invalid_url", data);
    }
    bool tls = (scheme == "https");
    diag::log_tagged_fmt("mcp_burp", "csp_analyze_url sending host=%s port=%d tls=%d", host.c_str(), (int)port, (int)tls);

    audit_http::send_options_t opt;
    opt.timeout_ms = 15000;
    opt.follow_redirects = true;
    opt.enforce_scope = false;

    auto req = build_get_request(host, path);
    auto resp = audit_http::send(req, host, port, tls, opt);
    if (!resp.has_value())
    {
        std::string err = audit_http::last_error();
        diag::log_tagged_fmt("mcp_burp", "csp_analyze_url send_failed err=%s", err.c_str());
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
    auto res = analyze_for_response(resp->resp_headers);
    diag::log_tagged_fmt("mcp_burp", "csp_analyze_url ok status=%d score=%d findings=%zu", resp->status_code, res.score, res.findings.size());
    json j = result_to_json(res);
    j["url"] = url;
    j["status_code"] = resp->status_code;
    return tool_result_t::ok(j);
}

}

void register_csp_tools(mcp_standalone::server_t& srv)
{
    {
        tool_def_t t;
        t.name = "burp_csp_analyze";
        t.description = "Analyze a Content-Security-Policy header value. Returns the parsed directives, "
                        "a list of findings (each with id/title/severity/description/evidence), and a 0-100 score.";
        t.params = {
            {"csp_header_value", "string", "Raw CSP header value", true},
            {"is_report_only",   "boolean", "Was this delivered via Content-Security-Policy-Report-Only?", false},
        };
        t.read_only = true;
        t.handler = tool_analyze;
        srv.register_tool(std::move(t));
    }
    {
        tool_def_t t;
        t.name = "burp_csp_analyze_url";
        t.description = "Fetch a URL via the AiDA audit HTTP client and analyze the CSP header on the response.";
        t.params = {
            {"url", "string", "Full URL including scheme (http/https)", true},
        };
        t.read_only = false;
        t.handler = tool_analyze_url;
        srv.register_tool(std::move(t));
    }
}

}
}
}
