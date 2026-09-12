#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef small
#undef small
#endif

#include "burp_logger_mcp.hpp"
#include "burp_logger.hpp"
#include "../../settings/standalone_compat.hpp"
#include "helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace logger_mcp {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

namespace {

tool_result_t error_with_data(const std::string& text, const json& data)
{
    return tool_result_t{false, text, data};
}

json log_row_to_json(const logger::log_row_t& row)
{
    json out;
    out["id"] = static_cast<uint64_t>(row.id);
    out["ts_ms"] = static_cast<uint64_t>(row.ts_ms);
    out["method"] = row.method;
    out["url"] = row.url;
    out["host"] = row.host;
    out["port"] = static_cast<uint32_t>(row.port);
    out["status"] = row.status;
    out["request_length"] = static_cast<uint64_t>(row.request_length);
    out["response_length"] = static_cast<uint64_t>(row.response_length);
    out["latency_ms"] = static_cast<uint64_t>(row.latency_ms);
    out["mime_type"] = row.mime_type;
    out["source"] = logger::source_label(row.source);
    out["exchange_id"] = static_cast<uint64_t>(row.exchange_id);
    return out;
}

void apply_filter(logger::log_filter_t& f, const json& p)
{
    if (p.contains("method") && p["method"].is_string()) f.method = p["method"].get<std::string>();
    if (p.contains("host_regex") && p["host_regex"].is_string()) f.host_regex = p["host_regex"].get<std::string>();
    if (p.contains("url_regex") && p["url_regex"].is_string()) f.url_regex = p["url_regex"].get<std::string>();
    if (p.contains("status_min") && p["status_min"].is_number()) f.status_min = p["status_min"].get<int>();
    if (p.contains("status_max") && p["status_max"].is_number()) f.status_max = p["status_max"].get<int>();
    if (p.contains("source") && p["source"].is_string()) f.source = p["source"].get<std::string>();
    if (p.contains("time_from_ms") && p["time_from_ms"].is_number()) f.time_from_ms = p["time_from_ms"].get<uint64_t>();
    if (p.contains("time_to_ms") && p["time_to_ms"].is_number()) f.time_to_ms = p["time_to_ms"].get<uint64_t>();
    if (p.contains("mime_type") && p["mime_type"].is_string()) f.mime_type = p["mime_type"].get<std::string>();
}

logger::log_filter_t build_filter(const json& p)
{
    logger::log_filter_t f;
    if (p.contains("filter") && p["filter"].is_object())
        apply_filter(f, p["filter"]);
    apply_filter(f, p);
    return f;
}

tool_result_t handle_query(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "logger_query entry");
    size_t limit = 100;
    auto parse_limit = [](const json& v, size_t& out) -> bool {
        if (!v.is_number_integer()) return false;
        long long vv = v.get<long long>();
        if (vv < 0 || vv > 100000) return false;
        out = static_cast<size_t>(vv);
        return true;
    };
    if (p.contains("limit")) {
        if (!parse_limit(p["limit"], limit)) return tool_result_t::error("limit must be in 0..100000");
    } else if (p.contains("filter") && p["filter"].is_object() && p["filter"].contains("limit")) {
        if (!parse_limit(p["filter"]["limit"], limit)) return tool_result_t::error("limit must be in 0..100000");
    }
    auto f = build_filter(p);
    auto rows = logger::query(f, limit);
    json arr = json::array();
    for (const auto& row : rows) arr.push_back(log_row_to_json(row));
    diag::log_tagged_fmt("mcp_burp", "logger_query ok count=%zu limit=%zu", rows.size(), limit);
    json result;
    result["rows"] = std::move(arr);
    result["count"] = static_cast<uint64_t>(rows.size());
    result["limit"] = static_cast<uint64_t>(limit);
    return tool_result_t::ok("logger query count=" + std::to_string(rows.size()), result);
}

tool_result_t handle_stats(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "logger_stats entry");
    size_t total = logger::total_rows();
    size_t cap = logger::capacity();
    diag::log_tagged_fmt("mcp_burp", "logger_stats ok total=%zu capacity=%zu", total, cap);
    json result;
    result["total_rows"] = static_cast<uint64_t>(total);
    result["capacity"] = static_cast<uint64_t>(cap);
    return tool_result_t::ok("logger stats total=" + std::to_string(total) + " capacity=" + std::to_string(cap), result);
}

tool_result_t handle_clear(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "logger_clear entry");
    size_t before = logger::total_rows();
    logger::clear();
    size_t after = logger::total_rows();
    diag::log_tagged_fmt("mcp_burp", "logger_clear ok before=%zu after=%zu", before, after);
    json result;
    result["before_total"] = static_cast<uint64_t>(before);
    result["after_total"] = static_cast<uint64_t>(after);
    result["cleared"] = static_cast<uint64_t>(before >= after ? before - after : 0);
    return tool_result_t::ok("logger cleared rows=" + std::to_string(before) + " after=" + std::to_string(after), result);
}

tool_result_t handle_export_csv(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "logger_export_csv entry");
    if (!p.contains("file_path") || !p["file_path"].is_string() || p["file_path"].get<std::string>().empty())
    {
        if (!p.contains("path") || !p["path"].is_string() || p["path"].get<std::string>().empty())
        {
            diag::log_tagged_fmt("mcp_burp", "logger_export_csv missing_file_path");
            return tool_result_t::error("file_path parameter required for export_csv action");
        }
    }
    std::string path = p.contains("file_path") && p["file_path"].is_string() && !p["file_path"].get<std::string>().empty()
        ? p["file_path"].get<std::string>()
        : p["path"].get<std::string>();
    auto f = build_filter(p);
    diag::log_tagged_fmt("mcp_burp", "logger_export_csv path=%s", path.c_str());
    bool ok = logger::export_csv(path, f);
    if (!ok)
    {
        std::string err = logger::last_error();
        diag::log_tagged_fmt("mcp_burp", "logger_export_csv failed err=%s", err.c_str());
        json data;
        data["file_path"] = path;
        data["error"] = err;
        data["status"] = "export_failed";
        return error_with_data("logger export_csv failed: " + err, data);
    }
    diag::log_tagged_fmt("mcp_burp", "logger_export_csv ok path=%s", path.c_str());
    json result;
    result["file_path"] = path;
    result["status"] = "exported";
    return tool_result_t::ok("exported CSV to " + path, result);
}

tool_result_t handle_set_capacity(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "logger_set_capacity entry");
    if (!p.contains("capacity") || !p["capacity"].is_number_integer())
    {
        diag::log_tagged_fmt("mcp_burp", "logger_set_capacity missing_capacity");
        return tool_result_t::error("capacity parameter required for set_capacity action");
    }
    long long cv = p["capacity"].get<long long>();
    if (cv < 1 || cv > 1000000) return tool_result_t::error("capacity must be in 1..1000000");
    size_t cap = static_cast<size_t>(cv);
    diag::log_tagged_fmt("mcp_burp", "logger_set_capacity capacity=%zu", cap);
    logger::set_capacity(cap);
    size_t actual = logger::capacity();
    diag::log_tagged_fmt("mcp_burp", "logger_set_capacity ok actual=%zu", actual);
    json result;
    result["requested_capacity"] = static_cast<uint64_t>(cap);
    result["actual_capacity"] = static_cast<uint64_t>(actual);
    return tool_result_t::ok("capacity set to " + std::to_string(actual), result);
}

}

void register_logger_tools(mcp_standalone::server_t& srv)
{
    register_compat(srv, {
        "burp_logger_manage", "burp",
        "Manage the Burp-style HTTP logger. Actions: query, stats, total, clear, export_csv, set_capacity.",
        {{"action", "string", "query|stats|total|clear|export_csv|set_capacity", true},
         {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "query") return handle_query(p);
            if (action == "stats") return handle_stats(p);
            if (action == "total") return handle_stats(p);
            if (action == "clear") return handle_clear(p);
            if (action == "export_csv") return handle_export_csv(p);
            if (action == "set_capacity") return handle_set_capacity(p);
            return compat_unknown_action("burp_logger_manage", action);
        },
        false
    });
}

}
}
}
