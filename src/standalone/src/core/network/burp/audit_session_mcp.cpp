#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "audit_session_mcp.hpp"

#include "audit_http.hpp"
#include "audit_session.hpp"
#include "audit_trail.hpp"
#include "evidence_store.hpp"
#include "findings_db.hpp"
#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <functional>
#include <mutex>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace audit_session_mcp_store {

namespace {

using json = nlohmann::json;

std::mutex& error_mutex()
{
    static std::mutex m;
    return m;
}

std::string& error_slot()
{
    static std::string e;
    return e;
}

uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

void set_error(const std::string& value)
{
    std::lock_guard<std::mutex> lk(error_mutex());
    error_slot() = value;
}

std::string lower_copy(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

bool valid_public_status(const std::string& status)
{
    const std::string s = lower_copy(status);
    return s == "open" || s == "active" || s == "paused" || s == "closed";
}

std::string truncate_text(const std::string& value, size_t max_len)
{
    if (value.size() <= max_len)
        return value;
    return value.substr(0, max_len) + "...[truncated]";
}

std::string sqlite_status_from_public(const std::string& status)
{
    const std::string s = lower_copy(status);
    if (s == "open")
        return "active";
    if (s == "paused")
        return "paused";
    if (s == "closed")
        return "closed";
    if (s == "active")
        return "active";
    return status;
}

std::string public_status_from_sqlite(const std::string& status)
{
    const std::string s = lower_copy(status);
    if (s == "active")
        return "open";
    if (s == "closed" || s == "paused")
        return s;
    return status.empty() ? std::string("open") : status;
}

json metadata_with_fields(json metadata, const std::string& client, const std::string& scope_summary, const std::string& owner)
{
    if (!metadata.is_object())
        metadata = json::object();
    if (!client.empty())
        metadata["client"] = client;
    if (!scope_summary.empty())
        metadata["scope_summary"] = scope_summary;
    if (!owner.empty())
        metadata["owner"] = owner;
    return evidence_store::redact_sensitive_json(metadata);
}

std::string metadata_string(const json& metadata, const char* key)
{
    if (metadata.is_object() && metadata.contains(key) && metadata[key].is_string())
        return metadata[key].get<std::string>();
    return {};
}

target_t target_from_sqlite(const audit_session::audit_target_t& in)
{
    target_t out;
    out.id = std::to_string(in.id);
    out.url = in.url;
    out.scheme = in.scheme;
    out.host = in.host;
    out.port = in.port;
    out.path = "/";
    std::string scheme;
    std::string host;
    std::string path;
    uint16_t port = 0;
    if (audit_http::parse_url(in.url, scheme, host, port, path)) {
        out.scheme = scheme;
        out.host = host;
        out.port = port;
        out.path = path.empty() ? std::string("/") : path;
    }
    out.label = in.host;
    out.added_ms = in.added_ms;
    out.active = true;
    return out;
}

session_t session_from_sqlite(const audit_session::session_t& in, bool include_targets)
{
    session_t out;
    out.id = in.session_id;
    out.title = in.title;
    out.client = metadata_string(in.metadata_json, "client");
    out.scope_summary = metadata_string(in.metadata_json, "scope_summary");
    if (out.scope_summary.empty())
        out.scope_summary = in.description;
    out.status = public_status_from_sqlite(in.status);
    out.owner = metadata_string(in.metadata_json, "owner");
    if (in.notes_json.is_string())
        out.notes = in.notes_json.get<std::string>();
    else if (!in.notes_json.empty() && !in.notes_json.is_null())
        out.notes = in.notes_json.dump();
    out.created_ms = in.created_ms;
    out.updated_ms = in.closed_ms != 0 ? in.closed_ms : in.created_ms;
    out.closed_ms = in.closed_ms;
    out.metadata = evidence_store::redact_sensitive_json(in.metadata_json);
    if (include_targets) {
        for (const auto& t : audit_session::list_targets(in.session_id))
            out.targets.push_back(target_from_sqlite(t));
    }
    return out;
}

audit_session::list_filter_t sqlite_filter_from_public(const session_filter_t& filter)
{
    audit_session::list_filter_t out;
    out.include_closed = filter.include_closed;
    out.status = filter.status.empty() ? std::string() : sqlite_status_from_public(filter.status);
    out.limit = filter.limit;
    return out;
}

evidence_record_t evidence_from_sqlite(const evidence_store::evidence_record_t& in)
{
    evidence_record_t out;
    out.id = in.id;
    out.session_id = in.session_id;
    out.issue_id = in.finding_id;
    out.exchange_id = in.exchange_id;
    out.source = in.metadata_json.value("source", std::string("sqlite"));
    out.category = evidence_store::kind_to_string(in.kind);
    out.label = in.description;
    out.captured_ms = in.captured_ms;
    out.request_length = in.request_raw.size();
    out.response_length = in.response_raw.size();
    out.request_sha256 = evidence_store::sha256_hex(in.request_raw);
    out.response_sha256 = evidence_store::sha256_hex(in.response_raw);
    out.request_preview = truncate_text(evidence_store::redact_sensitive_text(in.request_raw), 4096);
    out.response_preview = truncate_text(evidence_store::redact_sensitive_text(in.response_raw), 4096);
    out.marker_length = in.marker.size();
    out.marker_sha256 = in.marker.empty() ? std::string() : evidence_store::sha256_hex(in.marker);
    out.marker_preview = truncate_text(evidence_store::redact_sensitive_text(in.marker), 512);
    out.extra = evidence_store::redact_sensitive_json(in.metadata_json);
    out.extra["kind"] = evidence_store::kind_to_string(in.kind);
    out.extra["content_sha256"] = in.content_sha256;
    if (!in.screenshot_path.empty())
        out.extra["screenshot_path"] = in.screenshot_path;
    if (!in.file_path.empty())
        out.extra["file_path"] = in.file_path;
    if (!in.timing_json.empty())
        out.extra["timing"] = evidence_store::redact_sensitive_json(in.timing_json);
    return out;
}

suppression_t suppression_from_issue(const issue_t& issue, const std::string& session_id)
{
    suppression_t out;
    out.id = issue.id;
    out.session_id = session_id.empty() ? issue.session_id : session_id;
    out.issue_id = issue.id;
    out.scope = "finding";
    out.reason = issue.suppress_reason;
    out.actor = issue.suppressed_by;
    out.issue_type = issue.type_key;
    out.host = issue.host;
    out.path = issue.path;
    out.created_ms = issue.suppressed_ms;
    out.active = issue.suppressed;
    return out;
}

audit_entry_t audit_from_sqlite(const audit_trail::record_t& in)
{
    audit_entry_t out;
    out.id = in.id;
    out.session_id = in.session_id;
    out.ts_ms = in.timestamp_ms;
    out.actor = in.caller;
    out.tool = in.tool_name;
    out.action = in.tool_name;
    out.read_only = true;
    out.ok = in.success;
    out.elapsed_ms = in.duration_ms;
    out.summary = in.success ? std::string("ok") : in.error_message;
    out.params_summary = in.parameters_preview_json;
    out.result_summary = in.result_summary_json;
    return out;
}

uint64_t parse_target_id(const std::string& id)
{
    try {
        size_t used = 0;
        uint64_t parsed = std::stoull(id, &used);
        if (used == id.size())
            return parsed;
    } catch (...) {
    }
    return 0;
}

}

bool initialize()
{
    if (!findings_db::initialize()) {
        set_error(findings_db::last_error());
        return false;
    }
    if (!audit_session::initialize()) {
        set_error(audit_session::last_error());
        return false;
    }
    if (!evidence_store::initialize()) {
        set_error(evidence_store::last_error());
        return false;
    }
    if (!audit_trail::initialize()) {
        set_error(audit_trail::last_error());
        return false;
    }
    return true;
}

void shutdown()
{
    audit_trail::shutdown();
    evidence_store::shutdown();
    audit_session::shutdown();
}

bool save_to_disk()
{
    return initialize();
}

bool load_from_disk()
{
    return initialize();
}

std::string storage_path()
{
    return findings_db::storage_path();
}

std::string last_error()
{
    std::lock_guard<std::mutex> lk(error_mutex());
    return error_slot();
}

std::string create_session(const std::string& title,
                           const std::string& client,
                           const std::string& scope_summary,
                           const std::string& owner,
                           const nlohmann::json& metadata)
{
    audit_session::create_request_t req;
    req.title = title.empty() ? std::string("Web Audit Session") : title;
    req.description = scope_summary;
    req.metadata_json = metadata_with_fields(metadata, client, scope_summary, owner);
    audit_session::session_t out;
    if (!audit_session::create(req, out)) {
        set_error(audit_session::last_error());
        return {};
    }
    return out.session_id;
}

bool get_session(const std::string& id, session_t& out)
{
    audit_session::session_t session;
    if (!audit_session::get(id, session)) {
        set_error(audit_session::last_error());
        return false;
    }
    out = session_from_sqlite(session, true);
    return true;
}

std::vector<session_t> list_sessions(const session_filter_t& filter)
{
    std::vector<session_t> out;
    if (!filter.status.empty() && !valid_public_status(filter.status)) {
        set_error("invalid_status");
        return out;
    }
    for (const auto& session : audit_session::list(sqlite_filter_from_public(filter)))
        out.push_back(session_from_sqlite(session, false));
    return out;
}

bool update_session(const std::string& id, const session_update_t& update, session_t& out)
{
    audit_session::session_t current;
    if (!audit_session::get(id, current)) {
        set_error(audit_session::last_error());
        return false;
    }
    json metadata = current.metadata_json.is_object() ? current.metadata_json : json::object();
    audit_session::update_request_t req;
    req.session_id = id;
    if (update.has_title) {
        req.has_title = true;
        req.title = update.title;
    }
    if (update.has_scope_summary) {
        req.has_description = true;
        req.description = update.scope_summary;
        metadata["scope_summary"] = update.scope_summary;
    }
    if (update.has_status) {
        if (!valid_public_status(update.status)) {
            set_error("invalid_status");
            return false;
        }
        req.has_status = true;
        req.status = sqlite_status_from_public(update.status);
    }
    if (update.has_client)
        metadata["client"] = update.client;
    if (update.has_owner)
        metadata["owner"] = update.owner;
    if (update.has_metadata) {
        for (auto it = update.metadata.begin(); it != update.metadata.end(); ++it)
            metadata[it.key()] = it.value();
    }
    if (update.has_notes) {
        req.has_notes = true;
        req.notes_json = json::array({update.notes});
    }
    req.has_metadata = update.has_client || update.has_owner || update.has_scope_summary || update.has_metadata;
    if (req.has_metadata)
        req.metadata_json = evidence_store::redact_sensitive_json(metadata);
    audit_session::session_t changed;
    if (!audit_session::update(req, changed)) {
        set_error(audit_session::last_error());
        return false;
    }
    out = session_from_sqlite(changed, true);
    return true;
}

bool close_session(const std::string& id, const std::string& reason, session_t& out)
{
    if (!reason.empty()) {
        session_update_t update;
        update.has_notes = true;
        update.notes = reason;
        session_t ignored;
        if (!update_session(id, update, ignored))
            return false;
    }
    audit_session::session_t closed;
    if (!audit_session::close(id, closed)) {
        set_error(audit_session::last_error());
        return false;
    }
    out = session_from_sqlite(closed, true);
    return true;
}

bool delete_session(const std::string& id)
{
    if (!audit_session::remove(id)) {
        set_error(audit_session::last_error());
        return false;
    }
    return true;
}

bool add_target(const std::string& session_id, target_t target, target_t& out)
{
    std::string url = target.url;
    if (url.empty() && !target.host.empty()) {
        const std::string scheme = target.scheme.empty() ? std::string("https") : target.scheme;
        url = scheme + "://" + target.host;
        if (target.port != 0 && !((scheme == "https" && target.port == 443) || (scheme == "http" && target.port == 80)))
            url += ":" + std::to_string(target.port);
        url += target.path.empty() ? std::string("/") : target.path;
    }
    const bool is_primary = audit_session::list_targets(session_id).empty();
    audit_session::audit_target_t stored;
    if (!audit_session::add_target(session_id, url, is_primary, stored)) {
        set_error(audit_session::last_error());
        return false;
    }
    out = target_from_sqlite(stored);
    if (!target.label.empty())
        out.label = evidence_store::redact_sensitive_text(target.label, 256);
    return true;
}

std::vector<target_t> list_targets(const std::string& session_id)
{
    std::vector<target_t> out;
    for (const auto& target : audit_session::list_targets(session_id))
        out.push_back(target_from_sqlite(target));
    return out;
}

bool remove_target(const std::string& session_id, const std::string& target_id)
{
    uint64_t id = parse_target_id(target_id);
    if (id == 0) {
        for (const auto& target : audit_session::list_targets(session_id)) {
            if (target.url == target_id || target.host == target_id) {
                id = target.id;
                break;
            }
        }
    }
    if (id == 0) {
        set_error("target_not_found");
        return false;
    }
    if (!audit_session::remove_target(session_id, id)) {
        set_error(audit_session::last_error());
        return false;
    }
    return true;
}

uint64_t store_evidence(evidence_record_t record)
{
    evidence_store::evidence_capture_t capture;
    capture.finding_id = record.issue_id;
    capture.session_id = record.session_id;
    capture.exchange_id = record.exchange_id;
    capture.kind = evidence_store::evidence_kind_t::request_response;
    capture.request_raw = record.request_preview;
    capture.response_raw = record.response_preview;
    capture.marker = record.marker_preview;
    capture.description = record.label.empty() ? record.category : record.label;
    capture.metadata_json = record.extra.is_object() ? record.extra : json::object();
    capture.metadata_json["source"] = record.source.empty() ? "audit_session_mcp_store" : record.source;
    evidence_store::evidence_record_t stored;
    if (!evidence_store::capture(capture, stored)) {
        set_error(evidence_store::last_error());
        return 0;
    }
    return stored.id;
}

std::vector<evidence_record_t> list_evidence(const evidence_query_t& query)
{
    evidence_store::evidence_filter_t filter;
    filter.session_id = query.session_id;
    filter.finding_id = query.issue_id;
    filter.exchange_id = query.exchange_id;
    filter.limit = query.limit;
    std::vector<evidence_record_t> out;
    for (const auto& record : evidence_store::list(filter))
        out.push_back(evidence_from_sqlite(record));
    return out;
}

size_t evidence_count_for_issue(const std::string& session_id, uint64_t issue_id)
{
    evidence_query_t query;
    query.session_id = session_id;
    query.issue_id = issue_id;
    query.limit = 0;
    return list_evidence(query).size();
}

uint64_t suppress_finding(suppression_t suppression)
{
    findings_db::suppression_t req;
    req.finding_id = suppression.issue_id;
    req.reason = suppression.reason;
    req.suppressed_by = suppression.actor.empty() ? std::string("mcp") : suppression.actor;
    req.scope = suppression.scope.empty() ? std::string("finding") : suppression.scope;
    req.create_rule = true;
    if (!findings_db::suppress(req)) {
        set_error(findings_db::last_error());
        return 0;
    }
    return suppression.issue_id;
}

bool is_suppressed(uint64_t issue_id, const std::string& session_id)
{
    issue_t issue;
    if (!findings_db::get(issue_id, issue))
        return false;
    if (!session_id.empty() && !issue.session_id.empty() && issue.session_id != session_id)
        return false;
    return issue.suppressed;
}

std::vector<suppression_t> list_suppressions(const std::string& session_id, bool active_only)
{
    findings_db::finding_filter_t filter;
    filter.session_id = session_id;
    filter.include_suppressed = true;
    filter.limit = 0;
    std::vector<suppression_t> out;
    for (const auto& issue : findings_db::list(filter)) {
        if (!issue.suppressed)
            continue;
        suppression_t s = suppression_from_issue(issue, session_id);
        if (active_only && !s.active)
            continue;
        out.push_back(std::move(s));
    }
    std::sort(out.begin(), out.end(), [](const suppression_t& a, const suppression_t& b) { return a.created_ms > b.created_ms; });
    return out;
}

uint64_t append_audit(audit_entry_t entry)
{
    audit_trail::event_t event;
    event.session_id = entry.session_id;
    event.timestamp_ms = entry.ts_ms == 0 ? now_ms() : entry.ts_ms;
    event.tool_name = entry.tool;
    event.parameters_json = entry.params_summary.is_object() ? entry.params_summary : json::object();
    event.result_json = entry.result_summary.is_object() ? entry.result_summary : json{{"summary", entry.summary}};
    event.duration_ms = entry.elapsed_ms;
    event.caller = entry.actor.empty() ? std::string("mcp") : entry.actor;
    event.success = entry.ok;
    event.error_message = entry.ok ? std::string() : entry.summary;
    uint64_t id = 0;
    if (!audit_trail::record(event, &id)) {
        set_error(audit_trail::last_error());
        return 0;
    }
    return id;
}

std::vector<audit_entry_t> list_audit(const audit_query_t& query)
{
    audit_trail::query_filter_t filter;
    filter.session_id = query.session_id;
    filter.tool_name_substring = query.tool;
    filter.since_ms = query.since_ms;
    filter.until_ms = query.until_ms;
    filter.limit = query.limit == 0 ? 128 : query.limit;
    std::vector<audit_entry_t> out;
    for (const auto& record : audit_trail::query(filter))
        out.push_back(audit_from_sqlite(record));
    return out;
}

nlohmann::json target_to_json(const target_t& target)
{
    json j;
    j["id"] = target.id;
    j["label"] = redact_for_output(target.label);
    j["url"] = redact_url_for_output(target.url);
    j["scheme"] = target.scheme;
    j["host"] = target.host;
    j["port"] = target.port;
    j["path"] = redact_url_for_output(target.path);
    j["added_ms"] = target.added_ms;
    j["active"] = target.active;
    return j;
}

nlohmann::json session_to_json(const session_t& session, bool include_targets)
{
    json j;
    j["id"] = session.id;
    j["session_id"] = session.id;
    j["title"] = redact_for_output(session.title);
    j["client"] = redact_for_output(session.client);
    j["scope_summary"] = redact_for_output(session.scope_summary);
    j["status"] = session.status;
    j["owner"] = redact_for_output(session.owner);
    j["notes"] = redact_for_output(session.notes);
    j["created_ms"] = session.created_ms;
    j["updated_ms"] = session.updated_ms;
    j["closed_ms"] = session.closed_ms;
    j["target_count"] = session.targets.size();
    j["metadata"] = redact_json_for_output(session.metadata);
    if (include_targets) {
        j["targets"] = json::array();
        for (const auto& target : session.targets)
            j["targets"].push_back(target_to_json(target));
    }
    return j;
}

nlohmann::json evidence_to_json(const evidence_record_t& record)
{
    json j;
    j["id"] = record.id;
    j["session_id"] = record.session_id;
    j["issue_id"] = record.issue_id;
    j["finding_id"] = record.issue_id;
    j["exchange_id"] = record.exchange_id;
    j["source"] = redact_for_output(record.source);
    j["category"] = redact_for_output(record.category);
    j["label"] = redact_for_output(record.label);
    j["captured_ms"] = record.captured_ms;
    j["method"] = record.method;
    j["url"] = redact_url_for_output(record.url);
    j["host"] = record.host;
    j["port"] = record.port;
    j["path"] = redact_url_for_output(record.path);
    j["status_code"] = record.status_code;
    j["request"] = json{{"length", record.request_length}, {"sha256", record.request_sha256}, {"preview", truncate_text(redact_for_output(record.request_preview), 2048)}, {"redacted", true}};
    j["response"] = json{{"length", record.response_length}, {"sha256", record.response_sha256}, {"preview", truncate_text(redact_for_output(record.response_preview), 2048)}, {"redacted", true}};
    if (record.marker_length != 0 || !record.marker_sha256.empty() || !record.marker_preview.empty())
        j["marker"] = json{{"length", record.marker_length}, {"sha256", record.marker_sha256}, {"preview", truncate_text(redact_for_output(record.marker_preview), 256)}, {"redacted", true}};
    j["extra"] = redact_json_for_output(record.extra);
    return j;
}

nlohmann::json suppression_to_json(const suppression_t& suppression)
{
    json j;
    j["id"] = suppression.id;
    j["session_id"] = suppression.session_id;
    j["issue_id"] = suppression.issue_id;
    j["scope"] = suppression.scope;
    j["reason"] = redact_for_output(suppression.reason);
    j["actor"] = redact_for_output(suppression.actor);
    j["issue_type"] = redact_for_output(suppression.issue_type);
    j["host"] = suppression.host;
    j["path"] = redact_url_for_output(suppression.path);
    j["created_ms"] = suppression.created_ms;
    j["expires_ms"] = suppression.expires_ms;
    j["active"] = suppression.active;
    return j;
}

nlohmann::json audit_entry_to_json(const audit_entry_t& entry)
{
    json j;
    j["id"] = entry.id;
    j["session_id"] = entry.session_id;
    j["ts_ms"] = entry.ts_ms;
    j["actor"] = redact_for_output(entry.actor);
    j["tool"] = redact_for_output(entry.tool);
    j["action"] = redact_for_output(entry.action);
    j["read_only"] = entry.read_only;
    j["ok"] = entry.ok;
    j["elapsed_ms"] = entry.elapsed_ms;
    j["target"] = redact_url_for_output(entry.target);
    j["summary"] = truncate_text(redact_for_output(entry.summary), 1024);
    j["params_summary"] = redact_json_for_output(entry.params_summary);
    j["result_summary"] = redact_json_for_output(entry.result_summary);
    return j;
}

nlohmann::json report_context_json(const std::string& session_id, bool include_audit_trail, size_t audit_limit)
{
    if (session_id.empty())
        return json::object();
    session_t session;
    if (!get_session(session_id, session))
        return json::object();
    json out;
    out["session"] = session_to_json(session, true);
    evidence_query_t eq;
    eq.session_id = session_id;
    eq.limit = 256;
    const auto evidence = list_evidence(eq);
    out["evidence_count"] = evidence.size();
    out["evidence"] = json::array();
    for (const auto& record : evidence)
        out["evidence"].push_back(evidence_to_json(record));
    const auto suppressions = list_suppressions(session_id, true);
    out["suppression_count"] = suppressions.size();
    out["suppressions"] = json::array();
    for (const auto& suppression : suppressions)
        out["suppressions"].push_back(suppression_to_json(suppression));
    if (include_audit_trail) {
        audit_query_t aq;
        aq.session_id = session_id;
        aq.limit = audit_limit == 0 ? 128 : audit_limit;
        const auto audit = list_audit(aq);
        out["audit_trail_count"] = audit.size();
        out["audit_trail"] = json::array();
        for (const auto& entry : audit)
            out["audit_trail"].push_back(audit_entry_to_json(entry));
    }
    return out;
}

nlohmann::json redact_json_for_output(const nlohmann::json& value)
{
    return evidence_store::redact_sensitive_json(value, 1024);
}

std::string redact_for_output(const std::string& value)
{
    return evidence_store::redact_sensitive_text(value, 2048);
}

std::string redact_url_for_output(const std::string& value)
{
    return evidence_store::redact_sensitive_text(value, 2048);
}

std::string hash_for_output(const std::string& value)
{
    return evidence_store::sha256_hex(value);
}

}

namespace {

using json = nlohmann::json;
using namespace audit_session_mcp_store;

std::string session_id_from_params(const json& params)
{
    if (params.contains("session_id") && params["session_id"].is_string())
        return params["session_id"].get<std::string>();
    if (params.contains("id") && params["id"].is_string())
        return params["id"].get<std::string>();
    return {};
}

uint16_t port_from_params(const json& params, uint16_t fallback)
{
    if (!params.contains("port"))
        return fallback;
    const auto& value = params["port"];
    uint64_t parsed = 0;
    if (value.is_number_unsigned()) {
        parsed = value.get<uint64_t>();
    } else if (value.is_number_integer()) {
        const int64_t signed_value = value.get<int64_t>();
        if (signed_value <= 0)
            return fallback;
        parsed = static_cast<uint64_t>(signed_value);
    } else if (value.is_string()) {
        try {
            const std::string text = value.get<std::string>();
            size_t used = 0;
            parsed = std::stoull(text, &used);
            if (used != text.size())
                return fallback;
        } catch (...) {
            return fallback;
        }
    } else {
        return fallback;
    }
    if (parsed == 0 || parsed > 65535)
        return fallback;
    return static_cast<uint16_t>(parsed);
}

target_t target_from_params(const json& params)
{
    target_t target;
    target.label = params.value("label", std::string());
    target.url = params.value("target_url", params.value("url", std::string()));
    target.scheme = params.value("scheme", std::string("https"));
    target.host = params.value("host", std::string());
    target.port = port_from_params(params, static_cast<uint16_t>(target.scheme == "http" ? 80 : 443));
    target.path = params.value("path", std::string("/"));
    target.active = true;
    if (!target.url.empty()) {
        std::string parsed_scheme;
        std::string parsed_host;
        std::string parsed_path;
        uint16_t parsed_port = 0;
        if (audit_http::parse_url(target.url, parsed_scheme, parsed_host, parsed_port, parsed_path)) {
            target.scheme = parsed_scheme;
            target.host = parsed_host;
            target.port = parsed_port;
            target.path = parsed_path.empty() ? std::string("/") : parsed_path;
        }
    } else if (!target.host.empty()) {
        target.url = target.scheme + "://" + target.host;
        if ((target.scheme == "https" && target.port != 443) || (target.scheme == "http" && target.port != 80))
            target.url += ":" + std::to_string(target.port);
        target.url += target.path.empty() ? std::string("/") : target.path;
    }
    return target;
}

void register_one(mcp_standalone::server_t& srv,
                  const std::string& name,
                  const std::string& description,
                  std::vector<mcp_standalone::tool_param_t> params,
                  bool read_only,
                  std::function<mcp_standalone::tool_result_t(const json&)> handler)
{
    mcp_standalone::tool_def_t t;
    t.name = name;
    t.description = description;
    t.params = std::move(params);
    t.read_only = read_only;
    t.handler = std::move(handler);
    srv.register_tool(std::move(t));
}

mcp_standalone::tool_result_t tool_create(const json& params)
{
    if (!params.is_object())
        return mcp_standalone::tool_result_t::error("parameters must be an object");
    if (params.contains("metadata") && !params["metadata"].is_object())
        return mcp_standalone::tool_result_t::error("metadata must be an object");
    if (params.contains("targets") && !params["targets"].is_array())
        return mcp_standalone::tool_result_t::error("targets must be an array");
    const std::string id = create_session(
        params.value("title", params.value("name", std::string("Web Audit Session"))),
        params.value("client", std::string()),
        params.value("scope_summary", std::string()),
        params.value("owner", std::string("mcp")),
        params.contains("metadata") ? params["metadata"] : json::object());
    if (id.empty())
        return mcp_standalone::tool_result_t::error(last_error().empty() ? "session create failed" : last_error());
    if (params.contains("targets") && params["targets"].is_array()) {
        for (const auto& jt : params["targets"]) {
            if (!jt.is_object())
            {
                delete_session(id);
                return mcp_standalone::tool_result_t::error("each target must be an object");
            }
            target_t target = target_from_params(jt);
            if (target.host.empty())
            {
                delete_session(id);
                return mcp_standalone::tool_result_t::error("each target requires host or target_url");
            }
            target_t stored;
            if (!add_target(id, target, stored)) {
                const std::string error = last_error().empty() ? "target add failed" : last_error();
                delete_session(id);
                return mcp_standalone::tool_result_t::error(error);
            }
        }
    }
    session_t session;
    if (!get_session(id, session)) {
        const std::string error = last_error().empty() ? "created session could not be loaded" : last_error();
        delete_session(id);
        return mcp_standalone::tool_result_t::error(error);
    }
    json out;
    out["session"] = session_to_json(session, true);
    out["session_id"] = id;
    return mcp_standalone::tool_result_t::ok(out);
}

mcp_standalone::tool_result_t tool_get(const json& params)
{
    session_t session;
    const std::string id = session_id_from_params(params);
    if (id.empty() || !get_session(id, session))
        return mcp_standalone::tool_result_t::error("session not found");
    json out;
    out["session"] = session_to_json(session, params.value("include_targets", true));
    return mcp_standalone::tool_result_t::ok(out);
}

mcp_standalone::tool_result_t tool_list(const json& params)
{
    session_filter_t filter;
    filter.status = params.value("status", std::string());
    if (!filter.status.empty() && !valid_public_status(filter.status))
        return mcp_standalone::tool_result_t::error("invalid status: expected open, active, paused, or closed");
    filter.include_closed = params.value("include_closed", true);
    {
        if (params.contains("limit")) {
            if (!params["limit"].is_number_integer()) return mcp_standalone::tool_result_t::error("limit must be an integer");
            long long v = params["limit"].get<long long>();
            if (v < 0 || v > 10000) return mcp_standalone::tool_result_t::error("limit must be in 0..10000");
            filter.limit = static_cast<size_t>(v);
        } else {
            filter.limit = 128;
        }
    }
    const auto sessions = list_sessions(filter);
    json out;
    out["count"] = sessions.size();
    out["sessions"] = json::array();
    for (const auto& session : sessions)
        out["sessions"].push_back(session_to_json(session, params.value("include_targets", false)));
    return mcp_standalone::tool_result_t::ok(out);
}

mcp_standalone::tool_result_t tool_update(const json& params)
{
    const std::string id = session_id_from_params(params);
    if (id.empty())
        return mcp_standalone::tool_result_t::error("session_id is required");
    session_update_t update;
    if (params.contains("title") && params["title"].is_string()) {
        update.has_title = true;
        update.title = params["title"].get<std::string>();
    }
    if (params.contains("name") && params["name"].is_string()) {
        update.has_title = true;
        update.title = params["name"].get<std::string>();
    }
    if (params.contains("client") && params["client"].is_string()) {
        update.has_client = true;
        update.client = params["client"].get<std::string>();
    }
    if (params.contains("scope_summary") && params["scope_summary"].is_string()) {
        update.has_scope_summary = true;
        update.scope_summary = params["scope_summary"].get<std::string>();
    }
    if (params.contains("status") && params["status"].is_string()) {
        update.has_status = true;
        update.status = params["status"].get<std::string>();
    }
    if (params.contains("owner") && params["owner"].is_string()) {
        update.has_owner = true;
        update.owner = params["owner"].get<std::string>();
    }
    if (params.contains("notes") && params["notes"].is_string()) {
        update.has_notes = true;
        update.notes = params["notes"].get<std::string>();
    }
    if (params.contains("metadata") && params["metadata"].is_object()) {
        update.has_metadata = true;
        update.metadata = params["metadata"];
    }
    session_t session;
    if (!update_session(id, update, session))
        return mcp_standalone::tool_result_t::error(last_error().empty() ? "session update failed" : last_error());
    json out;
    out["session"] = session_to_json(session, true);
    return mcp_standalone::tool_result_t::ok(out);
}

mcp_standalone::tool_result_t tool_close(const json& params)
{
    const std::string id = session_id_from_params(params);
    if (id.empty())
        return mcp_standalone::tool_result_t::error("session_id is required");
    session_t session;
    if (!close_session(id, params.value("reason", std::string()), session))
        return mcp_standalone::tool_result_t::error(last_error().empty() ? "session close failed" : last_error());
    json out;
    out["closed"] = true;
    out["session"] = session_to_json(session, true);
    return mcp_standalone::tool_result_t::ok(out);
}

mcp_standalone::tool_result_t tool_delete(const json& params)
{
    const std::string id = session_id_from_params(params);
    if (id.empty())
        return mcp_standalone::tool_result_t::error("session_id is required");
    const bool removed = delete_session(id);
    json out;
    out["deleted"] = removed;
    out["session_id"] = id;
    if (!removed)
        return mcp_standalone::tool_result_t::error("session not found", out);
    return mcp_standalone::tool_result_t::ok(out);
}

mcp_standalone::tool_result_t tool_target_add(const json& params)
{
    const std::string id = session_id_from_params(params);
    if (id.empty())
        return mcp_standalone::tool_result_t::error("session_id is required");
    target_t target = target_from_params(params);
    if (target.host.empty())
        return mcp_standalone::tool_result_t::error("target host or target_url is required");
    target_t stored;
    if (!add_target(id, target, stored))
        return mcp_standalone::tool_result_t::error(last_error().empty() ? "session not found" : last_error());
    json out;
    out["target"] = target_to_json(stored);
    out["session_id"] = id;
    return mcp_standalone::tool_result_t::ok(out);
}

mcp_standalone::tool_result_t tool_target_list(const json& params)
{
    const std::string id = session_id_from_params(params);
    if (id.empty())
        return mcp_standalone::tool_result_t::error("session_id is required");
    session_t session;
    if (!get_session(id, session))
        return mcp_standalone::tool_result_t::error(last_error().empty() ? "session not found" : last_error());
    const auto& targets = session.targets;
    json out;
    out["session_id"] = id;
    out["count"] = targets.size();
    out["targets"] = json::array();
    for (const auto& target : targets)
        out["targets"].push_back(target_to_json(target));
    return mcp_standalone::tool_result_t::ok(out);
}

mcp_standalone::tool_result_t tool_target_remove(const json& params)
{
    const std::string id = session_id_from_params(params);
    const std::string target_id = params.value("target_id", params.value("url", params.value("host", std::string())));
    if (id.empty() || target_id.empty())
        return mcp_standalone::tool_result_t::error("session_id and target_id are required");
    const bool removed = remove_target(id, target_id);
    json out;
    out["session_id"] = id;
    out["target_id"] = target_id;
    out["removed"] = removed;
    if (!removed)
        return mcp_standalone::tool_result_t::error("target not found", out);
    return mcp_standalone::tool_result_t::ok(out);
}

}

namespace audit_session_mcp {

void register_audit_session_tools(mcp_standalone::server_t& srv)
{
    using p = mcp_standalone::tool_param_t;
    register_one(srv, "aida.web.session.create", "Create a web audit session with optional targets and metadata.", {
        p{"title", "string", "Session title.", false},
        p{"name", "string", "Session title alias.", false},
        p{"client", "string", "Client name.", false},
        p{"scope_summary", "string", "Scope summary.", false},
        p{"owner", "string", "Operator label.", false},
        p{"metadata", "object", "Additional redacted metadata.", false},
        p{"targets", "array", "Optional targets to add.", false}
    }, false, tool_create);
    register_one(srv, "aida.web.session.get", "Get a web audit session.", {
        p{"session_id", "string", "Session id.", true},
        p{"include_targets", "boolean", "Include targets.", false}
    }, true, tool_get);
    register_one(srv, "aida.web.session.list", "List web audit sessions.", {
        p{"status", "string", "Optional status filter: open|paused|closed.", false},
        p{"include_closed", "boolean", "Include closed sessions.", false},
        p{"include_targets", "boolean", "Include target arrays.", false},
        p{"limit", "number", "Maximum sessions.", false}
    }, true, tool_list);
    register_one(srv, "aida.web.session.update", "Update web audit session metadata.", {
        p{"session_id", "string", "Session id.", true},
        p{"title", "string", "New title.", false},
        p{"client", "string", "New client.", false},
        p{"scope_summary", "string", "New scope summary.", false},
        p{"status", "string", "open|paused|closed.", false},
        p{"owner", "string", "Owner label.", false},
        p{"notes", "string", "Redacted notes.", false},
        p{"metadata", "object", "Replacement metadata.", false}
    }, false, tool_update);
    register_one(srv, "aida.web.session.close", "Close a web audit session.", {
        p{"session_id", "string", "Session id.", true},
        p{"reason", "string", "Closure reason.", false}
    }, false, tool_close);
    register_one(srv, "aida.web.session.delete", "Delete a web audit session and its SQLite-backed targets.", {
        p{"session_id", "string", "Session id.", true}
    }, false, tool_delete);
    register_one(srv, "aida.web.session.target.add", "Add a target to a web audit session.", {
        p{"session_id", "string", "Session id.", true},
        p{"target_url", "string", "Target URL.", false},
        p{"url", "string", "Target URL alias.", false},
        p{"scheme", "string", "http|https.", false},
        p{"host", "string", "Target host.", false},
        p{"port", "number", "Target port.", false},
        p{"path", "string", "Target path.", false},
        p{"label", "string", "Target label.", false}
    }, false, tool_target_add);
    register_one(srv, "aida.web.session.target.list", "List targets for a web audit session.", {
        p{"session_id", "string", "Session id.", true}
    }, true, tool_target_list);
    register_one(srv, "aida.web.session.target.remove", "Remove a target from a web audit session.", {
        p{"session_id", "string", "Session id.", true},
        p{"target_id", "string", "Target id, URL, or host.", true}
    }, false, tool_target_remove);
    diag::log_tagged("audit_session_mcp", "registered web audit session tools");
}

}
}
}
