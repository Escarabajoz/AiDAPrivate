#include "burp_bambda_mcp.hpp"
#include "bambda.hpp"

#include "../../../helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <optional>
#include <string>

namespace aida {
namespace burp {
namespace bambda {

namespace {

using mcp_standalone::tool_def_t;
using mcp_standalone::tool_result_t;
using nlohmann::json;

row_view_t make_provider_for_json_object(const json& obj)
{
    row_view_t v;
    json snapshot = obj;
    v.get_string = [snapshot](const std::string& path) -> std::optional<std::string> {
        const json* cur = &snapshot;
        size_t pos = 0;
        while (pos < path.size()) {
            size_t dot = path.find('.', pos);
            std::string key = (dot == std::string::npos) ? path.substr(pos) : path.substr(pos, dot - pos);
            pos = (dot == std::string::npos) ? path.size() : dot + 1;
            if (!cur->is_object()) return std::nullopt;
            auto it = cur->find(key);
            if (it == cur->end()) return std::nullopt;
            cur = &(*it);
        }
        if (cur->is_string()) return cur->get<std::string>();
        if (cur->is_number()) return cur->dump();
        if (cur->is_boolean()) return std::string(cur->get<bool>() ? "true" : "false");
        if (cur->is_null()) return std::nullopt;
        return cur->dump();
    };
    v.get_number = [snapshot](const std::string& path) -> std::optional<int64_t> {
        const json* cur = &snapshot;
        size_t pos = 0;
        while (pos < path.size()) {
            size_t dot = path.find('.', pos);
            std::string key = (dot == std::string::npos) ? path.substr(pos) : path.substr(pos, dot - pos);
            pos = (dot == std::string::npos) ? path.size() : dot + 1;
            if (!cur->is_object()) return std::nullopt;
            auto it = cur->find(key);
            if (it == cur->end()) return std::nullopt;
            cur = &(*it);
        }
        if (cur->is_number_integer()) return cur->get<int64_t>();
        if (cur->is_number_unsigned()) return static_cast<int64_t>(cur->get<uint64_t>());
        if (cur->is_number_float()) return static_cast<int64_t>(cur->get<double>());
        if (cur->is_boolean()) return cur->get<bool>() ? 1 : 0;
        if (cur->is_string()) {
            try { return static_cast<int64_t>(std::stoll(cur->get<std::string>())); } catch (...) { return std::nullopt; }
        }
        return std::nullopt;
    };
    return v;
}

tool_result_t tool_compile(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "bambda_compile entry");
    if (!params.is_object() || !params.contains("source") || !params["source"].is_string())
    {
        diag::log_tagged_fmt("mcp_burp", "bambda_compile missing_source");
        return tool_result_t::error("missing_source");
    }
    if (params["source"].get_ref<const std::string&>().size() > 65536)
        return tool_result_t::error("source exceeds 65536 bytes");
    auto p = compile(params["source"].get<std::string>());
    diag::log_tagged_fmt("mcp_burp", "bambda_compile ok valid=%d err=%s", (int)p.valid, p.error.c_str());
    json j;
    j["valid"] = p.valid;
    j["error"] = p.error;
    j["source"] = p.source;
    return p.valid ? tool_result_t::ok(j) : tool_result_t::error("bambda compile failed", j);
}

tool_result_t tool_test(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "bambda_test entry");
    if (!params.is_object() || !params.contains("source") || !params["source"].is_string())
    {
        diag::log_tagged_fmt("mcp_burp", "bambda_test missing_source");
        return tool_result_t::error("missing_source");
    }
    if (!params.contains("row") || !params["row"].is_object())
    {
        diag::log_tagged_fmt("mcp_burp", "bambda_test missing_row");
        return tool_result_t::error("missing_row");
    }
    if (params["source"].get_ref<const std::string&>().size() > 65536)
        return tool_result_t::error("source exceeds 65536 bytes");
    if (params["row"].dump().size() > 1048576)
        return tool_result_t::error("row exceeds 1048576 serialized bytes");
    auto p = compile(params["source"].get<std::string>());
    if (!p.valid)
    {
        diag::log_tagged_fmt("mcp_burp", "bambda_test compile_failed err=%s", p.error.c_str());
        json j;
        j["valid"] = false;
        j["error"] = p.error;
        return tool_result_t::error("bambda compile failed", j);
    }
    auto provider = make_provider_for_json_object(params["row"]);
    bool match = evaluate(p, provider);
    diag::log_tagged_fmt("mcp_burp", "bambda_test ok match=%d", (int)match);
    json j;
    j["valid"] = true;
    j["match"] = match;
    return tool_result_t::ok(j);
}

tool_result_t tool_help(const json& params)
{
    (void)params;
    diag::log_tagged_fmt("mcp_burp", "bambda_help entry");
    json j;
    j["help"] = bambda_help_text();
    diag::log_tagged_fmt("mcp_burp", "bambda_help ok");
    return tool_result_t::ok(j);
}

}

void register_bambda_tools(mcp_standalone::server_t& srv)
{
    {
        tool_def_t t;
        t.name = "burp_bambda_compile";
        t.description = "Compile a Bambda filter DSL expression. Returns valid/error and echoes the source. "
                        "Bambda is a tiny safe expression DSL used by the logger/proxy/sitemap views to filter rows.";
        t.params = {
            {"source", "string", "Filter source code", true},
        };
        t.read_only = true;
        t.handler = tool_compile;
        srv.register_tool(std::move(t));
    }
    {
        tool_def_t t;
        t.name = "burp_bambda_test";
        t.description = "Compile a Bambda expression and evaluate it against a row object (JSON). "
                        "Use dotted paths like 'request.host' and 'response.status' to match fields.";
        t.params = {
            {"source", "string", "Filter source code", true},
            {"row",    "object", "Row JSON to test against",  true},
        };
        t.read_only = true;
        t.handler = tool_test;
        srv.register_tool(std::move(t));
    }
    {
        tool_def_t t;
        t.name = "burp_bambda_help";
        t.description = "Get the human-readable help text for Bambda (operators, fields, examples).";
        t.params = {};
        t.read_only = true;
        t.handler = tool_help;
        srv.register_tool(std::move(t));
    }
}

}
}
}
