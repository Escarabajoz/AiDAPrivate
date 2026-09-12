#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef small
#undef small
#endif

#include "burp_collaborator_mcp.hpp"
#include "collaborator.hpp"
#include "../../settings/standalone_compat.hpp"
#include "helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace collaborator_mcp {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

namespace {

tool_result_t error_with_data(const std::string& text, const json& data)
{
    return tool_result_t{false, text, data};
}

json interaction_to_json(const aida::burp::collaborator::interaction_t& it)
{
    json out;
    out["id"] = static_cast<uint64_t>(it.id);
    out["timestamp_ms"] = static_cast<uint64_t>(it.timestamp_ms);
    out["kind"] = it.kind;
    out["client_ip"] = it.client_ip;
    out["client_port"] = static_cast<uint32_t>(it.client_port);
    out["subdomain"] = it.subdomain;
    out["payload_token"] = it.payload_token;
    out["raw"] = it.raw;
    json details = json::object();
    for (const auto& kv : it.details) details[kv.first] = kv.second;
    out["details"] = std::move(details);
    return out;
}

json status_to_json(const aida::burp::collaborator::status_t& s)
{
    json out;
    out["running"] = s.running;
    out["http_alive"] = s.http_alive;
    out["dns_alive"]  = s.dns_alive;
    out["smtp_alive"] = s.smtp_alive;
    out["smtps_supported"] = s.smtps_supported;
    out["ldap_supported"] = s.ldap_supported;
    out["bind_ip"]    = s.bind_ip;
    out["http_port"]  = static_cast<uint32_t>(s.http_port);
    out["dns_port"]   = static_cast<uint32_t>(s.dns_port);
    out["smtp_port"]  = static_cast<uint32_t>(s.smtp_port);
    out["smtps_port"] = static_cast<uint32_t>(s.smtps_port);
    out["ldap_port"]  = static_cast<uint32_t>(s.ldap_port);
    out["public_host"] = s.public_host;
    out["public_ip"]   = s.public_ip;
    out["interaction_count"] = static_cast<uint64_t>(s.interaction_count);
    out["token_count"] = static_cast<uint64_t>(s.token_count);
    out["poll_cursor_count"] = static_cast<uint64_t>(s.poll_cursor_count);
    out["started_ms"]  = static_cast<uint64_t>(s.started_ms);
    out["durable_state_path"] = s.durable_state_path;
    out["supported_transports"] = json::array({"http", "dns", "smtp"});
    out["unsupported_transports"] = json::array({"smtps", "ldap"});
    out["webhook_delivery_supported"] = true;
    out["webhook_signing_supported"] = true;
    out["file_export_supported"] = true;
    out["async_polling_supported"] = true;
    return out;
}

json token_to_json(const aida::burp::collaborator::token_info_t& t)
{
    json e;
    e["token"] = t.token;
    e["full_domain"] = t.full_domain;
    e["issued_ms"] = static_cast<uint64_t>(t.issued_ms);
    e["last_seen_ms"] = static_cast<uint64_t>(t.last_seen_ms);
    e["interaction_count"] = static_cast<uint64_t>(t.interaction_count);
    return e;
}

json poll_result_to_json(const aida::burp::collaborator::poll_result_t& result)
{
    json out;
    out["cursor"] = result.cursor;
    out["next_since_ms"] = result.next_since_ms;
    out["next_after_id"] = result.next_after_id;
    out["timed_out"] = result.timed_out;
    out["interactions"] = json::array();
    for (const auto& it : result.interactions) out["interactions"].push_back(interaction_to_json(it));
    out["count"] = static_cast<uint64_t>(result.interactions.size());
    return out;
}

tool_result_t handle_status(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "collaborator_status entry");
    auto s = aida::burp::collaborator::status();
    diag::log_tagged_fmt("mcp_burp", "collaborator_status ok running=%d interactions=%llu", (int)s.running, static_cast<unsigned long long>(s.interaction_count));
    return tool_result_t::ok("collaborator status running=" + std::to_string(s.running ? 1 : 0) + " interactions=" + std::to_string(s.interaction_count) + " tokens=" + std::to_string(s.token_count), status_to_json(s));
}

tool_result_t handle_start(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "collaborator_start entry");
    aida::burp::collaborator::collaborator_config_t cfg;
    if (p.contains("bind_ip") && p["bind_ip"].is_string()) cfg.bind_ip = p["bind_ip"].get<std::string>();
    auto parse_port = [&](const char* key, uint16_t& out) -> bool {
        if (!p.contains(key)) return true;
        if (!p[key].is_number_integer()) return false;
        long long v = p[key].get<long long>();
        if (v < 1 || v > 65535) return false;
        out = static_cast<uint16_t>(v);
        return true;
    };
    if (!parse_port("http_port", cfg.http_port) ||
        !parse_port("dns_port", cfg.dns_port) ||
        !parse_port("smtp_port", cfg.smtp_port) ||
        !parse_port("smtps_port", cfg.smtps_port) ||
        !parse_port("ldap_port", cfg.ldap_port)) {
        return tool_result_t::error("port must be an integer in 1..65535");
    }
    if (p.contains("public_host") && p["public_host"].is_string()) cfg.public_host = p["public_host"].get<std::string>();
    if (p.contains("public_ip")   && p["public_ip"].is_string())   cfg.public_ip   = p["public_ip"].get<std::string>();
    if (p.contains("enable_http") && p["enable_http"].is_boolean()) cfg.enable_http = p["enable_http"].get<bool>();
    if (p.contains("enable_dns")  && p["enable_dns"].is_boolean())  cfg.enable_dns  = p["enable_dns"].get<bool>();
    if (p.contains("enable_smtp") && p["enable_smtp"].is_boolean()) cfg.enable_smtp = p["enable_smtp"].get<bool>();
    const bool requested_smtps = p.contains("enable_smtps") && p["enable_smtps"].is_boolean() && p["enable_smtps"].get<bool>();
    const bool requested_ldap = p.contains("enable_ldap") && p["enable_ldap"].is_boolean() && p["enable_ldap"].get<bool>();
    if (requested_smtps || requested_ldap) {
        json data = status_to_json(aida::burp::collaborator::status());
        data["requested_enable_smtps"] = requested_smtps;
        data["requested_enable_ldap"] = requested_ldap;
        data["status"] = "unsupported_transport";
        return error_with_data("collaborator local listener contract supports http, dns, and smtp only; smtps and ldap are intentionally unsupported", data);
    }
    if (p.contains("canned_body") && p["canned_body"].is_string()) cfg.canned_body = p["canned_body"].get<std::string>();
    if (p.contains("canned_content_type") && p["canned_content_type"].is_string()) cfg.canned_content_type = p["canned_content_type"].get<std::string>();
    if (p.contains("max_interactions")) {
        if (!p["max_interactions"].is_number_unsigned()) return tool_result_t::error("max_interactions must be a non-negative integer");
        size_t v = p["max_interactions"].get<size_t>();
        if (v == 0 || v > 1000000) return tool_result_t::error("max_interactions must be in 1..1000000");
        cfg.max_interactions = v;
    }
    if (p.contains("smtp_max_message")) {
        if (!p["smtp_max_message"].is_number_integer()) return tool_result_t::error("smtp_max_message must be an integer");
        long long v = p["smtp_max_message"].get<long long>();
        if (v < 1024 || v > 100 * 1024 * 1024) return tool_result_t::error("smtp_max_message must be in 1024..104857600");
        cfg.smtp_max_message = static_cast<int>(v);
    }
    diag::log_tagged_fmt("mcp_burp", "collaborator_start public_host=%s http=%d dns=%d smtp=%d", cfg.public_host.c_str(), (int)cfg.enable_http, (int)cfg.enable_dns, (int)cfg.enable_smtp);

    bool ok = aida::burp::collaborator::start(cfg);
    if (!ok)
    {
        std::string err = aida::burp::collaborator::last_error();
        diag::log_tagged_fmt("mcp_burp", "collaborator_start failed err=%s", err.c_str());
        json data = status_to_json(aida::burp::collaborator::status());
        data["error"] = err;
        data["requested_enable_http"] = cfg.enable_http;
        data["requested_enable_dns"] = cfg.enable_dns;
        data["requested_enable_smtp"] = cfg.enable_smtp;
        data["requested_http_port"] = cfg.http_port;
        data["requested_dns_port"] = cfg.dns_port;
        data["requested_smtp_port"] = cfg.smtp_port;
        data["requested_smtps_port"] = cfg.smtps_port;
        data["requested_ldap_port"] = cfg.ldap_port;
        data["status"] = "start_failed";
        return error_with_data("collaborator start failed: " + err, data);
    }
    diag::log_tagged_fmt("mcp_burp", "collaborator_start ok");
    auto s = aida::burp::collaborator::status();
    return tool_result_t::ok("collaborator started http_port=" + std::to_string(s.http_port), status_to_json(s));
}

tool_result_t handle_stop(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "collaborator_stop entry");
    aida::burp::collaborator::stop();
    diag::log_tagged_fmt("mcp_burp", "collaborator_stop ok");
    auto s = aida::burp::collaborator::status();
    return tool_result_t::ok("collaborator stopped running=" + std::to_string(s.running ? 1 : 0), status_to_json(s));
}

tool_result_t handle_generate_token(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "collaborator_generate_token entry");
    if (!aida::burp::collaborator::is_running())
    {
        diag::log_tagged_fmt("mcp_burp", "collaborator_generate_token not_running");
        return tool_result_t::error("collaborator not running");
    }
    auto cfg = aida::burp::collaborator::current_config();
    std::string tok = aida::burp::collaborator::generate_token();
    diag::log_tagged_fmt("mcp_burp", "collaborator_generate_token ok token=%s host=%s", tok.c_str(), cfg.public_host.c_str());
    json out;
    out["token"] = tok;
    out["full_domain"] = tok + "." + cfg.public_host;
    out["public_host"] = cfg.public_host;
    return tool_result_t::ok("token generated len=" + std::to_string(tok.size()), out);
}

tool_result_t handle_poll(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "collaborator_poll entry");
    json out = json::array();
    size_t count = 0;
    if (p.contains("token") && p["token"].is_string() && !p["token"].get<std::string>().empty()) {
        const std::string tok = p["token"].get<std::string>();
        diag::log_tagged_fmt("mcp_burp", "collaborator_poll by_token token=%s", tok.c_str());
        auto list = aida::burp::collaborator::poll_by_token(tok);
        for (const auto& it : list) out.push_back(interaction_to_json(it));
        count = list.size();
    } else {
        uint64_t since = 0;
        if (p.contains("since_ms") && p["since_ms"].is_number_unsigned()) since = p["since_ms"].get<uint64_t>();
        diag::log_tagged_fmt("mcp_burp", "collaborator_poll since_ms=%llu", static_cast<unsigned long long>(since));
        auto list = aida::burp::collaborator::poll_since(since);
        for (const auto& it : list) out.push_back(interaction_to_json(it));
        count = list.size();
    }
    diag::log_tagged_fmt("mcp_burp", "collaborator_poll ok count=%zu", count);
    json result;
    result["interactions"] = std::move(out);
    return tool_result_t::ok("collaborator interactions count=" + std::to_string(count), result);
}

tool_result_t handle_get_interaction(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "collaborator_get_interaction entry");
    if (!p.contains("id") || !p["id"].is_number())
    {
        diag::log_tagged_fmt("mcp_burp", "collaborator_get_interaction missing_id");
        return tool_result_t::error("id parameter required");
    }
    uint64_t id = p["id"].get<uint64_t>();
    diag::log_tagged_fmt("mcp_burp", "collaborator_get_interaction id=%llu", static_cast<unsigned long long>(id));
    aida::burp::collaborator::interaction_t it;
    if (!aida::burp::collaborator::get_interaction(id, it))
    {
        diag::log_tagged_fmt("mcp_burp", "collaborator_get_interaction not_found id=%llu", static_cast<unsigned long long>(id));
        return tool_result_t::error("interaction not found");
    }
    diag::log_tagged_fmt("mcp_burp", "collaborator_get_interaction ok id=%llu kind=%s", static_cast<unsigned long long>(id), it.kind.c_str());
    return tool_result_t::ok("interaction", interaction_to_json(it));
}

tool_result_t handle_clear(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "collaborator_clear entry");
    auto before = aida::burp::collaborator::status();
    aida::burp::collaborator::clear();
    auto after = aida::burp::collaborator::status();
    diag::log_tagged_fmt("mcp_burp", "collaborator_clear ok before_interactions=%zu after_interactions=%zu tokens_before=%zu tokens_after=%zu",
        before.interaction_count, after.interaction_count, before.token_count, after.token_count);
    json result = status_to_json(after);
    result["before_interaction_count"] = static_cast<uint64_t>(before.interaction_count);
    result["after_interaction_count"] = static_cast<uint64_t>(after.interaction_count);
    result["before_token_count"] = static_cast<uint64_t>(before.token_count);
    result["after_token_count"] = static_cast<uint64_t>(after.token_count);
    result["cleared_interactions"] = static_cast<uint64_t>(before.interaction_count >= after.interaction_count ? before.interaction_count - after.interaction_count : 0);
    return tool_result_t::ok("cleared interactions=" + std::to_string(before.interaction_count) + " after=" + std::to_string(after.interaction_count), result);
}

tool_result_t handle_list_tokens(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "collaborator_list_tokens entry");
    auto toks = aida::burp::collaborator::list_tokens();
    json arr = json::array();
    for (const auto& t : toks) {
        arr.push_back(token_to_json(t));
    }
    diag::log_tagged_fmt("mcp_burp", "collaborator_list_tokens ok count=%zu", toks.size());
    json r;
    r["tokens"] = std::move(arr);
    return tool_result_t::ok("tokens count=" + std::to_string(toks.size()), r);
}

tool_result_t handle_forget_token(const json& p)
{
    if (!p.contains("token") || !p["token"].is_string() || p["token"].get<std::string>().empty())
        return tool_result_t::error("token parameter required");
    const std::string token = p["token"].get<std::string>();
    const bool ok = aida::burp::collaborator::forget_token(token);
    if (!ok)
        return tool_result_t::error("token not found");
    json out = status_to_json(aida::burp::collaborator::status());
    out["deleted_token"] = token;
    return tool_result_t::ok("token deleted", out);
}

tool_result_t handle_poll_async(const json& p)
{
    aida::burp::collaborator::poll_request_t req;
    if (p.contains("token") && p["token"].is_string()) req.token = p["token"].get<std::string>();
    if (p.contains("cursor") && p["cursor"].is_string()) req.cursor = p["cursor"].get<std::string>();
    if (p.contains("since_ms") && p["since_ms"].is_number_unsigned()) req.since_ms = p["since_ms"].get<uint64_t>();
    if (p.contains("after_id") && p["after_id"].is_number_unsigned()) req.after_id = p["after_id"].get<uint64_t>();
    if (p.contains("max_entries") && p["max_entries"].is_number_unsigned()) req.max_entries = p["max_entries"].get<size_t>();
    if (p.contains("wait_ms") && p["wait_ms"].is_number_unsigned()) req.wait_ms = p["wait_ms"].get<uint32_t>();
    auto result = aida::burp::collaborator::poll_async(req);
    return tool_result_t::ok("async poll interactions=" + std::to_string(result.interactions.size()), poll_result_to_json(result));
}

tool_result_t handle_export_state(const json& p)
{
    if (p.contains("path") && p["path"].is_string() && !p["path"].get<std::string>().empty()) {
        const std::string path = p["path"].get<std::string>();
        if (!aida::burp::collaborator::save_state_to_file(path))
            return tool_result_t::error(aida::burp::collaborator::last_error());
        json out;
        out["path"] = path;
        out["status"] = status_to_json(aida::burp::collaborator::status());
        return tool_result_t::ok("collaborator state exported", out);
    }
    return tool_result_t::ok(aida::burp::collaborator::export_json());
}

tool_result_t handle_import_state(const json& p)
{
    const bool replace_existing = p.value("replace_existing", true);
    bool ok = false;
    if (p.contains("path") && p["path"].is_string() && !p["path"].get<std::string>().empty()) {
        ok = aida::burp::collaborator::load_state_from_file(p["path"].get<std::string>(), replace_existing);
    } else if (p.contains("state") && p["state"].is_object()) {
        ok = aida::burp::collaborator::import_json(p["state"], replace_existing);
    } else {
        return tool_result_t::error("path or state object required");
    }
    if (!ok)
        return tool_result_t::error(aida::burp::collaborator::last_error());
    return tool_result_t::ok("collaborator state imported", status_to_json(aida::burp::collaborator::status()));
}

tool_result_t handle_save_state(const json&)
{
    if (!aida::burp::collaborator::save_default_state())
        return tool_result_t::error(aida::burp::collaborator::last_error());
    json out = status_to_json(aida::burp::collaborator::status());
    out["path"] = aida::burp::collaborator::default_state_path();
    return tool_result_t::ok("collaborator state saved", out);
}

tool_result_t handle_load_state(const json& p)
{
    const bool replace_existing = p.value("replace_existing", true);
    if (!aida::burp::collaborator::load_default_state(replace_existing))
        return tool_result_t::error(aida::burp::collaborator::last_error());
    json out = status_to_json(aida::burp::collaborator::status());
    out["path"] = aida::burp::collaborator::default_state_path();
    return tool_result_t::ok("collaborator state loaded", out);
}

tool_result_t handle_export_interactions(const json& p)
{
    if (!p.contains("path") || !p["path"].is_string() || p["path"].get<std::string>().empty())
        return tool_result_t::error("path parameter required");
    const std::string path = p["path"].get<std::string>();
    const std::string token = p.value("token", std::string());
    uint64_t since_ms = 0;
    uint64_t after_id = 0;
    size_t max_entries = 0;
    if (p.contains("since_ms") && p["since_ms"].is_number_unsigned()) since_ms = p["since_ms"].get<uint64_t>();
    if (p.contains("after_id") && p["after_id"].is_number_unsigned()) after_id = p["after_id"].get<uint64_t>();
    if (p.contains("max_entries") && p["max_entries"].is_number_unsigned()) max_entries = p["max_entries"].get<size_t>();
    if (!aida::burp::collaborator::export_interactions_to_file(path, token, since_ms, after_id, max_entries))
        return tool_result_t::error(aida::burp::collaborator::last_error());
    json out;
    out["path"] = path;
    out["token"] = token;
    out["since_ms"] = since_ms;
    out["after_id"] = after_id;
    return tool_result_t::ok("collaborator interactions exported", out);
}

tool_result_t handle_webhook_export(const json& p)
{
    if (!p.contains("url") || !p["url"].is_string() || p["url"].get<std::string>().empty())
        return tool_result_t::error("url parameter required");
    const std::string url = p["url"].get<std::string>();
    const std::string token = p.value("token", std::string());
    const std::string signing_secret = p.value("signing_secret", std::string());
    uint64_t since_ms = 0;
    uint64_t after_id = 0;
    size_t max_entries = 0;
    uint32_t timeout_ms = 10000;
    if (p.contains("since_ms") && p["since_ms"].is_number_unsigned()) since_ms = p["since_ms"].get<uint64_t>();
    if (p.contains("after_id") && p["after_id"].is_number_unsigned()) after_id = p["after_id"].get<uint64_t>();
    if (p.contains("max_entries")) {
        if (!p["max_entries"].is_number_integer()) return tool_result_t::error("max_entries must be an integer");
        const auto value = p["max_entries"].get<long long>();
        if (value < 0 || value > 100000) return tool_result_t::error("max_entries must be in 0..100000");
        max_entries = static_cast<size_t>(value);
    }
    if (p.contains("timeout_ms")) {
        if (!p["timeout_ms"].is_number_integer()) return tool_result_t::error("timeout_ms must be an integer");
        const auto value = p["timeout_ms"].get<long long>();
        if (value < 1 || value > 120000) return tool_result_t::error("timeout_ms must be in 1..120000");
        timeout_ms = static_cast<uint32_t>(value);
    }
    aida::burp::collaborator::webhook_delivery_result_t result;
    const bool delivered = aida::burp::collaborator::post_interactions_webhook(
        url, token, since_ms, after_id, max_entries, signing_secret, timeout_ms, result);
    json out;
    out["delivered"] = result.delivered;
    out["status_code"] = result.status_code;
    out["interaction_count"] = static_cast<uint64_t>(result.interaction_count);
    out["origin"] = result.origin;
    out["path"] = result.path;
    out["token"] = token;
    out["since_ms"] = since_ms;
    out["after_id"] = after_id;
    out["signed"] = !signing_secret.empty();
    if (!result.error.empty()) out["error"] = result.error;
    if (!delivered)
        return error_with_data(result.error.empty() ? "collaborator webhook export failed" : result.error, out);
    return tool_result_t::ok("collaborator webhook delivered", out);
}

}

void register_collaborator_tools(mcp_standalone::server_t& srv)
{
    register_compat(srv, {
        "burp_collaborator_manage", "burp",
        "Manage the Burp-style out-of-band Collaborator server. Actions: status, start, stop, generate_token, poll, poll_async, get_interaction, clear, list_tokens, forget_token, export_state, import_state, save_state, load_state, export_interactions, webhook_export.",
        {{"action", "string", "status|start|stop|generate_token|poll|poll_async|get_interaction|clear|list_tokens|forget_token|export_state|import_state|save_state|load_state|export_interactions|webhook_export", true},
         {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "status") return handle_status(p);
            if (action == "start") return handle_start(p);
            if (action == "stop") return handle_stop(p);
            if (action == "generate_token") return handle_generate_token(p);
            if (action == "poll") return handle_poll(p);
            if (action == "poll_async") return handle_poll_async(p);
            if (action == "get_interaction") return handle_get_interaction(p);
            if (action == "clear") return handle_clear(p);
            if (action == "list_tokens") return handle_list_tokens(p);
            if (action == "forget_token") return handle_forget_token(p);
            if (action == "export_state") return handle_export_state(p);
            if (action == "import_state") return handle_import_state(p);
            if (action == "save_state") return handle_save_state(p);
            if (action == "load_state") return handle_load_state(p);
            if (action == "export_interactions") return handle_export_interactions(p);
            if (action == "webhook_export") return handle_webhook_export(p);
            return compat_unknown_action("burp_collaborator_manage", action);
        },
        false
    });
}

}
}
}
