#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef small
#undef small
#endif

#include "burp_report_mcp.hpp"
#include "report_generator.hpp"
#include "issue.hpp"
#include "evidence_store.hpp"
#include "../../settings/standalone_compat.hpp"
#include "helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace report_mcp {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

namespace {

tool_result_t error_with_data(const std::string& text, const json& data)
{
    return tool_result_t{false, text, data};
}

std::string safe_text(const std::string& value, size_t limit = 256)
{
    return evidence_store::redact_sensitive_text(value, limit);
}

json report_to_json(const report::generated_report_t& r)
{
    json out;
    out["id"] = static_cast<uint64_t>(r.id);
    out["ts_ms"] = static_cast<uint64_t>(r.ts_ms);
    out["title"] = r.title;
    out["output_path"] = r.output_path;
    out["inline"] = r.inline_output;
    out["format"] = report::format_label(r.format);
    out["issue_count"] = static_cast<uint64_t>(r.issue_count);
    return out;
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

tool_result_t handle_generate(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "report_generate entry");
    if (!p.contains("title") || !p["title"].is_string() || p["title"].get<std::string>().empty())
    {
        diag::log_tagged_fmt("mcp_burp", "report_generate missing_title");
        return tool_result_t::error("title parameter required for generate action");
    }
    if (!p.contains("format") || !p["format"].is_string())
    {
        diag::log_tagged_fmt("mcp_burp", "report_generate missing_format");
        return tool_result_t::error("format parameter required for generate action");
    }
    std::string format_str = p["format"].get<std::string>();
    report::report_format_t fmt;
    if (!report::parse_format(format_str, fmt))
    {
        diag::log_tagged_fmt("mcp_burp", "report_generate invalid_format=%s", format_str.c_str());
        return tool_result_t::error("invalid format: " + format_str + " (expected html, markdown, json, sarif_2_1, or csv)");
    }

    report::report_config_t cfg;
    cfg.title = p["title"].get<std::string>();
    cfg.format = fmt;
    if (p.contains("client") && p["client"].is_string()) cfg.client = p["client"].get<std::string>();
    if (p.contains("scope_summary") && p["scope_summary"].is_string()) cfg.scope_summary = p["scope_summary"].get<std::string>();
    if (p.contains("include_evidence") && p["include_evidence"].is_boolean()) cfg.include_evidence = p["include_evidence"].get<bool>();
    if (p.contains("include_remediation") && p["include_remediation"].is_boolean()) cfg.include_remediation = p["include_remediation"].get<bool>();
    if (p.contains("output_path") && p["output_path"].is_string()) cfg.output_path = p["output_path"].get<std::string>();
    if (p.contains("session_id") && p["session_id"].is_string()) cfg.session_id = p["session_id"].get<std::string>();
    if (p.contains("include_session_context") && p["include_session_context"].is_boolean()) cfg.include_session_context = p["include_session_context"].get<bool>();
    if (p.contains("include_audit_trail") && p["include_audit_trail"].is_boolean()) cfg.include_audit_trail = p["include_audit_trail"].get<bool>();
    if (p.contains("audit_trail_limit")) {
        if (!p["audit_trail_limit"].is_number_integer()) return tool_result_t::error("audit_trail_limit must be an integer");
        const auto value = p["audit_trail_limit"].get<long long>();
        if (value < 0 || value > 10000) return tool_result_t::error("audit_trail_limit must be in 0..10000");
        cfg.audit_trail_limit = static_cast<size_t>(value);
    }
    if (p.contains("target_domain") && p["target_domain"].is_string()) cfg.target_domain = p["target_domain"].get<std::string>();
    else if (p.contains("host") && p["host"].is_string()) cfg.target_domain = p["host"].get<std::string>();
    if (p.contains("include_recon") && p["include_recon"].is_boolean()) cfg.include_recon = p["include_recon"].get<bool>();
    if (p.contains("include_suppressed") && p["include_suppressed"].is_boolean()) cfg.include_suppressed = p["include_suppressed"].get<bool>();

    if (p.contains("include_issue_ids") && p["include_issue_ids"].is_array())
    {
        for (const auto& v : p["include_issue_ids"])
        {
            uint64_t id = 0;
            if (json_u64_value(v, id)) cfg.include_issue_ids.push_back(id);
        }
    }

    if (p.contains("severity_min") && p["severity_min"].is_string())
    {
        std::string sev_str = p["severity_min"].get<std::string>();
        severity_t sev;
        if (parse_severity(sev_str, sev))
        {
            cfg.has_severity_min = true;
            cfg.severity_min = sev;
        }
        else
        {
            diag::log_tagged_fmt("mcp_burp", "report_generate invalid_severity_min=%s", sev_str.c_str());
            return tool_result_t::error("invalid severity_min: " + sev_str + " (expected info, low, medium, high, or critical)");
        }
    }
    if (p.contains("audit_id")) {
        uint64_t audit_id = 0;
        if (!json_u64_value(p["audit_id"], audit_id))
            return tool_result_t::error("invalid audit_id");
        cfg.has_audit_id = true;
        cfg.audit_id = audit_id;
    }
    if (p.contains("include_offensive_run_ids") && p["include_offensive_run_ids"].is_array()) {
        for (const auto& v : p["include_offensive_run_ids"])
            if (v.is_string()) cfg.include_offensive_run_ids.push_back(v.get<std::string>());
    }

    const std::string safe_title = safe_text(cfg.title);
    diag::log_tagged_fmt("mcp_burp", "report_generate title=%s format=%s issue_ids=%zu evidence=%d remediation=%d",
        safe_title.c_str(), format_str.c_str(), cfg.include_issue_ids.size(), (int)cfg.include_evidence, (int)cfg.include_remediation);

    std::string out_path_or_error;
    bool ok = report::generate(cfg, out_path_or_error);
    if (!ok)
    {
        diag::log_tagged_fmt("mcp_burp", "report_generate failed err=%s", out_path_or_error.c_str());
        json data;
        data["error"] = out_path_or_error;
        data["status"] = "generate_failed";
        data["title"] = safe_title;
        data["format"] = format_str;
        return error_with_data("report generation failed: " + out_path_or_error, data);
    }

    diag::log_tagged_fmt("mcp_burp", "report_generate ok output_len=%zu inline=%d", out_path_or_error.size(), cfg.output_path.empty() ? 1 : 0);
    json result;
    result["status"] = "generated";
    result["output_path"] = cfg.output_path.empty() ? std::string() : out_path_or_error;
    result["inline"] = cfg.output_path.empty();
    if (cfg.output_path.empty())
        result["content"] = out_path_or_error;
    result["title"] = safe_title;
    result["format"] = format_str;
    size_t issue_count = 0;
    uint64_t newest_ts = 0;
    for (const auto& r : report::list_reports()) {
        if (((cfg.output_path.empty() && r.inline_output) || (!cfg.output_path.empty() && r.output_path == cfg.output_path)) && r.ts_ms >= newest_ts) {
            issue_count = r.issue_count;
            newest_ts = r.ts_ms;
        }
    }
    result["issue_count"] = static_cast<uint64_t>(issue_count);
    return tool_result_t::ok(cfg.output_path.empty() ? std::string("report generated inline") : std::string("report generated: " + out_path_or_error), result);
}

tool_result_t handle_list(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "report_list entry");
    auto reports = report::list_reports();
    json arr = json::array();
    for (const auto& r : reports) arr.push_back(report_to_json(r));
    diag::log_tagged_fmt("mcp_burp", "report_list ok count=%zu", reports.size());
    json result;
    result["reports"] = std::move(arr);
    result["count"] = static_cast<uint64_t>(reports.size());
    return tool_result_t::ok("reports count=" + std::to_string(reports.size()), result);
}

tool_result_t handle_count(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "report_count entry");
    size_t n = report::reports_count();
    diag::log_tagged_fmt("mcp_burp", "report_count ok count=%zu", n);
    json result;
    result["count"] = static_cast<uint64_t>(n);
    return tool_result_t::ok("reports count=" + std::to_string(n), result);
}

tool_result_t handle_clear_history(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "report_clear_history entry");
    size_t before = report::reports_count();
    report::clear_history();
    size_t after = report::reports_count();
    diag::log_tagged_fmt("mcp_burp", "report_clear_history ok before=%zu after=%zu", before, after);
    json result;
    result["before_count"] = static_cast<uint64_t>(before);
    result["after_count"] = static_cast<uint64_t>(after);
    result["cleared"] = static_cast<uint64_t>(before >= after ? before - after : 0);
    return tool_result_t::ok("report history cleared before=" + std::to_string(before) + " after=" + std::to_string(after), result);
}

}

void register_report_tools(mcp_standalone::server_t& srv)
{
    register_compat(srv, {
        "burp_report_manage", "burp",
        "Manage Burp-style vulnerability reports. Actions: generate, list, count, clear_history.",
        {{"action", "string", "generate|list|count|clear_history", true},
         {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "generate") return handle_generate(p);
            if (action == "list") return handle_list(p);
            if (action == "count") return handle_count(p);
            if (action == "clear_history") return handle_clear_history(p);
            return compat_unknown_action("burp_report_manage", action);
        },
        false
    });
}

}
}
}
