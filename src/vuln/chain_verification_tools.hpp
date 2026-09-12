#pragma once

#include "../aida_pro.hpp"
#include "../agent_tools.hpp"
#include "../multibinary_index.hpp"
#include "../multibinary_project.hpp"
#include "chain_extraction.hpp"
#include "chain_path_trace.hpp"
#include "chain_report.hpp"
#include "chain_schema.hpp"
#include "chain_store.hpp"
#include "chain_verifier.hpp"
#include "chain_verification_engine.hpp"
#include "ida_gateway.hpp"
#include "verification_engine.hpp"

#include <auto.hpp>
#include <bytes.hpp>
#include <dbg.hpp>
#include <entry.hpp>
#include <funcs.hpp>
#include <ida.hpp>
#include <idd.hpp>
#include <kernwin.hpp>
#include <lines.hpp>
#include <nalt.hpp>
#include <name.hpp>
#include <prodir.h>
#include <segment.hpp>
#include <xref.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <functional>
#include <iomanip>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace aida
{
namespace vuln
{
namespace chain_mcp
{
namespace
{

using json = nlohmann::json;

constexpr const char* kRequestSchema = "aida.ida.mcp.manage.v1";
constexpr const char* kResponseSchema = "aida.ida.mcp.response.v1";
constexpr const char* kChainSchema = "aida_chain_document_v2";
constexpr const char* kReportSchema = "chain_verification_report_v2";

struct field_rule_t
{
    std::string name;
    std::string type;
    bool required = false;
    std::vector<std::string> enum_values;
};

struct operation_meta_t
{
    std::string name;
    std::string description;
    bool read_only = true;
    bool destructive = false;
    bool deterministic = true;
    bool job_mode = false;
    std::string cache_policy;
    int default_timeout_ms = 1000;
    int hard_timeout_ms = 30000;
    std::vector<std::string> required_indices;
    std::vector<field_rule_t> fields;
    bool allow_extra = false;
};

struct request_ctx_t
{
    std::string tool;
    std::string operation;
    std::string request_id;
    std::string job_id;
    std::string job_mode;
    std::string idempotency_key;
    std::string cursor;
    int limit = 100;
    json budget = json::object();
    json payload = json::object();
};

struct job_record_t
{
    std::string job_id;
    std::string project_id;
    std::string tool;
    std::string operation;
    std::string state;
    std::string report_id;
    std::string error_code;
    std::string error_message;
    std::string idempotency_key;
    std::string idempotency_scope;
    std::string generation;
    std::string runtime_epoch;
    uint64_t created_at_ms = 0;
    uint64_t updated_at_ms = 0;
    double progress = 0.0;
    bool cancel_requested = false;
    json request;
    json result;
    json events = json::array();
    json resources = json::array();
};

struct report_record_t
{
    std::string report_id;
    std::string project_id;
    std::string job_id;
    std::string chain_id;
    uint64_t created_at_ms = 0;
    std::string content_hash;
    json report;
};

struct index_record_t
{
    std::string index_id;
    std::string status;
    std::string generation;
    uint64_t built_at_ms = 0;
    json coverage = json::object();
};

struct state_t
{
    std::mutex mutex;
    std::unordered_map<std::string, job_record_t> jobs;
    std::unordered_map<std::string, report_record_t> reports;
    std::unordered_map<std::string, index_record_t> indices;
    std::unordered_map<std::string, std::string> idempotency_jobs;
    std::unordered_map<std::string, aida::vuln::chain::cancellation_token_t> cancellation_tokens;
    std::unordered_map<std::string, std::shared_ptr<std::atomic_bool>> gateway_cancel_flags;
    std::unordered_set<std::string> hydrated_job_projects;
    std::unordered_set<std::string> hydrated_report_projects;
    json corpus_manifest = json::object();
    std::atomic<uint64_t> next_job{1};
    std::atomic<uint64_t> next_report{1};
};

state_t& state()
{
    static state_t s;
    return s;
}

uint64_t now_ms()
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

std::string runtime_epoch_id()
{
    static const std::string epoch = []() {
        std::ostringstream ss;
        ss << "mcp-runtime-" << std::hex << now_ms() << "-"
           << std::chrono::steady_clock::now().time_since_epoch().count();
        return ss.str();
    }();
    return epoch;
}

std::string hex_lower(const uint8_t* data, size_t n)
{
    static const char* h = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i)
    {
        out.push_back(h[(data[i] >> 4) & 0xf]);
        out.push_back(h[data[i] & 0xf]);
    }
    return out;
}

uint64_t fnv1a64(const std::string& text)
{
    uint64_t h = 1469598103934665603ull;
    for (unsigned char c : text)
    {
        h ^= static_cast<uint64_t>(c);
        h *= 1099511628211ull;
    }
    return h;
}

std::string hash_text(const std::string& text)
{
    std::ostringstream ss;
    ss << "fnv1a64:" << std::hex << std::setw(16) << std::setfill('0') << fnv1a64(text);
    return ss.str();
}

std::string scalar_to_string(const json& v)
{
    if (v.is_string())
        return v.get<std::string>();
    if (v.is_number_unsigned())
    {
        std::ostringstream ss;
        ss << "0x" << std::hex << v.get<uint64_t>();
        return ss.str();
    }
    if (v.is_number_integer())
    {
        int64_t n = v.get<int64_t>();
        std::ostringstream ss;
        if (n < 0)
            ss << n;
        else
            ss << "0x" << std::hex << static_cast<uint64_t>(n);
        return ss.str();
    }
    if (v.is_number_float())
        return std::to_string(v.get<double>());
    return std::string();
}

std::string basename_of(const std::string& path)
{
    const size_t p = path.find_last_of("/\\");
    return p == std::string::npos ? path : path.substr(p + 1);
}

std::string lowercase_ascii(std::string value)
{
    for (char& c : value)
    {
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c + ('a' - 'A'));
    }
    return value;
}

std::string input_path()
{
    char path[4096] = {};
    get_input_file_path(path, sizeof(path));
    return std::string(path[0] ? path : "");
}

std::string idb_path()
{
    const char* p = get_path(PATH_TYPE_IDB);
    return std::string(p ? p : "");
}

std::string input_md5()
{
    uchar md5[16] = {};
    if (!retrieve_input_file_md5(md5))
        return std::string();
    return hex_lower(md5, sizeof(md5));
}

std::string input_sha256()
{
    uchar sha[32] = {};
    if (!retrieve_input_file_sha256(sha))
        return std::string();
    return hex_lower(sha, sizeof(sha));
}

std::string processor_name()
{
    char proc[IDAINFO_PROCNAME_SIZE] = {};
    if (inf_get_procname(proc, sizeof(proc)))
        return proc;
    return std::string();
}

int bitness()
{
    if (inf_is_64bit())
        return 64;
    if (inf_is_32bit_exactly())
        return 32;
    return 16;
}

std::string fmt_ea(ea_t ea)
{
    return agent_tools::helpers::format_address(ea);
}

std::string generation_id()
{
    json g;
    g["input_sha256"] = input_sha256();
    g["imagebase"] = fmt_ea(static_cast<ea_t>(get_imagebase()));
    g["min_ea"] = fmt_ea(inf_get_min_ea());
    g["max_ea"] = fmt_ea(inf_get_max_ea());
    g["functions"] = static_cast<uint64_t>(get_func_qty());
    g["segments"] = get_segm_qty();
    g["auto_ok"] = auto_is_ok();
    return hash_text(g.dump());
}

json module_identity()
{
    aida::vuln::chain::corpus_record_t corpus = aida::vuln::chain::snapshot_current_idb_corpus();
    json m;
    m["module_id"] = corpus.identity.corpus_id;
    m["corpus_id"] = corpus.identity.corpus_id;
    m["canonical_name"] = corpus.identity.canonical_name;
    m["input_file"] = corpus.identity.input_path;
    m["input_path"] = corpus.identity.input_path;
    m["input_basename"] = basename_of(corpus.identity.input_path);
    m["idb_path"] = corpus.identity.idb_path;
    m["input_md5"] = corpus.identity.hashes.md5;
    m["input_sha256"] = corpus.identity.hashes.sha256;
    m["imagebase"] = fmt_ea(static_cast<ea_t>(corpus.identity.image_base));
    m["image_base"] = fmt_ea(static_cast<ea_t>(corpus.identity.image_base));
    m["min_ea"] = fmt_ea(static_cast<ea_t>(corpus.identity.min_ea));
    m["max_ea"] = fmt_ea(static_cast<ea_t>(corpus.identity.max_ea));
    m["processor"] = corpus.identity.processor;
    m["bitness"] = corpus.identity.bitness;
    m["address_model"] = "module_id+rva";
    m["generation"] = generation_id();
    return m;
}

json instance_identity()
{
    json i;
    i["instance_id"] = nullptr;
#ifdef _WIN32
    i["pid"] = static_cast<uint64_t>(GetCurrentProcessId());
#else
    i["pid"] = 0;
#endif
    i["idb_path"] = idb_path();
    i["input_file"] = input_path();
    i["input_basename"] = basename_of(input_path());
    i["input_md5"] = input_md5();
    i["input_sha256"] = input_sha256();
    i["processor"] = processor_name();
    i["bitness"] = bitness();
    i["database_generation"] = generation_id();
    i["auto_analysis_ok"] = auto_is_ok();
    return i;
}

bool is_common_key(const std::string& key)
{
    static const std::set<std::string> keys = {
        "operation", "action", "schema_version", "instance_id", "pid", "request_id",
        "idempotency_key", "job_mode", "cursor", "limit", "budget", "payload"
    };
    return keys.find(key) != keys.end();
}

int clamp_int(int value, int lo, int hi)
{
    return std::max(lo, std::min(hi, value));
}

int int_param(const json& j, const char* key, int def, int lo, int hi)
{
    int value = def;
    if (j.contains(key))
    {
        const json& v = j.at(key);
        if (v.is_number_integer())
            value = v.get<int>();
        else if (v.is_number_unsigned())
            value = static_cast<int>(std::min<uint64_t>(static_cast<uint64_t>(hi), v.get<uint64_t>()));
        else if (v.is_number_float())
            value = static_cast<int>(v.get<double>());
        else if (v.is_string())
        {
            char* endp = nullptr;
            long parsed = std::strtol(v.get_ref<const std::string&>().c_str(), &endp, 0);
            if (endp != v.get_ref<const std::string&>().c_str())
                value = static_cast<int>(parsed);
        }
    }
    return clamp_int(value, lo, hi);
}

json field_schema(const field_rule_t& f)
{
    json s;
    if (f.type == "location")
    {
        s["oneOf"] = json::array({
            json::object({{"type", "string"}}),
            json::object({{"type", "number"}}),
            json::object({{"type", "object"}, {"properties", json::object({
                {"ea", json::object({{"type", "string"}})},
                {"address", json::object({{"type", "string"}})},
                {"rva", json::object({{"type", "string"}})},
                {"module_id", json::object({{"type", "string"}})}
            })}})
        });
        return s;
    }
    s["type"] = f.type;
    if (!f.enum_values.empty())
        s["enum"] = f.enum_values;
    if (f.type == "array")
        s["items"] = json::object({{"type", "object"}});
    return s;
}

json payload_schema(const operation_meta_t& meta)
{
    json props = json::object();
    json req = json::array();
    for (const auto& f : meta.fields)
    {
        props[f.name] = field_schema(f);
        if (f.required)
            req.push_back(f.name);
    }
    json s;
    s["type"] = "object";
    s["properties"] = props;
    s["additionalProperties"] = meta.allow_extra;
    if (!req.empty())
        s["required"] = req;
    return s;
}

json meta_to_json(const operation_meta_t& meta)
{
    json j;
    j["operation"] = meta.name;
    j["description"] = meta.description;
    j["read_only"] = meta.read_only;
    j["destructive"] = meta.destructive;
    j["deterministic"] = meta.deterministic;
    j["job_mode"] = meta.job_mode;
    j["cache_policy"] = meta.cache_policy;
    j["default_timeout_ms"] = meta.default_timeout_ms;
    j["hard_timeout_ms"] = meta.hard_timeout_ms;
    j["required_indices"] = meta.required_indices;
    j["payload_schema"] = payload_schema(meta);
    return j;
}

const operation_meta_t* find_meta(const std::vector<operation_meta_t>& metas, const std::string& op)
{
    for (const auto& m : metas)
    {
        if (m.name == op)
            return &m;
    }
    return nullptr;
}

json operations_json(const std::vector<operation_meta_t>& metas)
{
    json arr = json::array();
    for (const auto& m : metas)
        arr.push_back(meta_to_json(m));
    return arr;
}

std::vector<std::string> operation_names(const std::vector<operation_meta_t>& metas)
{
    std::vector<std::string> names;
    names.reserve(metas.size());
    for (const auto& m : metas)
        names.push_back(m.name);
    return names;
}

std::vector<agent_tools::tool_param_t> common_params(const std::vector<operation_meta_t>& metas)
{
    return {
        {std::string("operation"), std::string("string"), std::string("Manage operation name."), true, operation_names(metas), json()},
        {std::string("schema_version"), std::string("string"), std::string("Request schema version; use aida.ida.mcp.manage.v1."), false},
        {std::string("action"), std::string("string"), std::string("Migration alias for operation."), false, operation_names(metas), json()},
        {std::string("request_id"), std::string("string"), std::string("Optional caller correlation id."), false},
        {std::string("idempotency_key"), std::string("string"), std::string("Optional retry-safe job key."), false},
        {std::string("job_mode"), std::string("string"), std::string("inline, job, or auto."), false, {"inline", "job", "auto"}, json()},
        {std::string("cursor"), std::string("string"), std::string("Opaque pagination cursor returned by a prior page."), false},
        {std::string("limit"), std::string("number"), std::string("Page size limit."), false},
        {std::string("budget"), std::string("object"), std::string("Timeout, byte, item, depth, solver, and partial-result budget."), false},
        {std::string("payload"), std::string("object"), std::string("Operation-specific request payload."), false}
    };
}

bool type_matches(const json& value, const std::string& type)
{
    if (type == "location")
        return value.is_string() || value.is_number() || value.is_object();
    if (type == "string")
        return value.is_string() || value.is_number();
    if (type == "number" || type == "integer")
        return value.is_number() || value.is_string();
    if (type == "boolean")
        return value.is_boolean();
    if (type == "object")
        return value.is_object();
    if (type == "array")
        return value.is_array();
    return true;
}

std::optional<ea_t> parse_location(const json& v)
{
    if (v.is_string() || v.is_number())
        return agent_tools::helpers::parse_address(scalar_to_string(v));
    if (!v.is_object())
        return std::nullopt;
    for (const char* k : {"ea", "address", "addr"})
    {
        if (v.contains(k))
            return agent_tools::helpers::parse_address(scalar_to_string(v.at(k)));
    }
    if (v.contains("rva"))
    {
        auto rva = agent_tools::helpers::parse_address(scalar_to_string(v.at("rva")));
        if (rva)
            return static_cast<ea_t>(get_imagebase()) + *rva;
    }
    return std::nullopt;
}

std::optional<ea_t> payload_location(const json& payload, const char* key)
{
    if (!payload.contains(key))
        return std::nullopt;
    return parse_location(payload.at(key));
}

std::string cursor_for(const std::string& op, const std::string& generation, size_t offset)
{
    std::ostringstream ss;
    ss << "ac1." << op << "." << generation << "." << offset;
    return ss.str();
}

bool parse_cursor(const std::string& cursor, const std::string& op, const std::string& generation, size_t& offset)
{
    offset = 0;
    if (cursor.empty())
        return true;
    const std::string prefix = "ac1." + op + "." + generation + ".";
    if (cursor.rfind(prefix, 0) != 0)
        return false;
    std::string n = cursor.substr(prefix.size());
    if (n.empty())
        return false;
    char* endp = nullptr;
    unsigned long long parsed = _strtoui64(n.c_str(), &endp, 10);
    if (endp == n.c_str() || *endp != '\0')
        return false;
    offset = static_cast<size_t>(parsed);
    return true;
}

json page_json(const std::string& cursor, const std::string& next_cursor, int limit, size_t returned, bool truncated)
{
    json p;
    p["cursor"] = cursor.empty() ? json(nullptr) : json(cursor);
    p["next_cursor"] = next_cursor.empty() ? json(nullptr) : json(next_cursor);
    p["limit"] = limit;
    p["returned"] = returned;
    p["truncated"] = truncated;
    return p;
}

agent_tools::tool_result_t result_from_envelope(const json& envelope, const std::string& message, bool success, const std::string& error_code = std::string())
{
    if (success)
        return agent_tools::tool_result_t::ok(message, envelope);
    agent_tools::tool_result_t r;
    r.success = false;
    r.output = message;
    r.data = envelope;
    r.error_code = error_code;
    return r;
}

json base_envelope(const request_ctx_t& ctx, bool ok)
{
    json e;
    e["ok"] = ok;
    e["schema"] = kResponseSchema;
    e["tool"] = ctx.tool;
    e["operation"] = ctx.operation;
    e["request_id"] = ctx.request_id;
    e["instance"] = instance_identity();
    e["module"] = module_identity();
    e["job"] = nullptr;
    e["page"] = nullptr;
    e["data"] = nullptr;
    e["warnings"] = json::array();
    e["resources"] = json::array();
    e["error"] = nullptr;
    return e;
}

agent_tools::tool_result_t ok_envelope(const request_ctx_t& ctx,
                                       const json& data,
                                       const json& job = json(),
                                       const json& page = json(),
                                       const json& warnings = json::array(),
                                       const json& resources = json::array())
{
    json e = base_envelope(ctx, true);
    e["data"] = data;
    if (!job.is_null() && !job.empty())
        e["job"] = job;
    if (!page.is_null() && !page.empty())
        e["page"] = page;
    e["warnings"] = warnings;
    e["resources"] = resources;
    std::string msg = ctx.tool + "." + ctx.operation + " ok";
    return result_from_envelope(e, msg, true);
}

agent_tools::tool_result_t error_envelope(const request_ctx_t& ctx,
                                          const std::string& code,
                                          const std::string& message,
                                          const json& details = json::object(),
                                          bool retryable = false)
{
    json e = base_envelope(ctx, false);
    e["data"] = nullptr;
    e["error"] = {
        {"code", code},
        {"message", message},
        {"retryable", retryable},
        {"details", details}
    };
    return result_from_envelope(e, ctx.tool + "." + ctx.operation + " " + code + ": " + message, false, code);
}

std::string new_request_id()
{
    static std::atomic<uint64_t> seq{1};
    std::ostringstream ss;
    ss << "req-" << now_ms() << "-" << seq.fetch_add(1);
    return ss.str();
}

request_ctx_t parse_request(const std::string& tool,
                            const json& params,
                            const std::vector<operation_meta_t>& metas,
                            agent_tools::tool_result_t& failure)
{
    request_ctx_t ctx;
    ctx.tool = tool;
    ctx.operation = params.value("operation", params.value("action", std::string()));
    ctx.request_id = params.value("request_id", new_request_id());
    ctx.job_mode = params.value("job_mode", std::string("auto"));
    ctx.idempotency_key = params.value("idempotency_key", std::string());
    ctx.cursor = params.value("cursor", std::string());
    ctx.limit = int_param(params, "limit", 100, 1, 1000);
    ctx.budget = params.contains("budget") && params["budget"].is_object() ? params["budget"] : json::object();
    ctx.payload = params.contains("payload") && params["payload"].is_object() ? params["payload"] : json::object();

    if (ctx.operation.empty())
    {
        ctx.operation = "unknown";
        failure = error_envelope(ctx, "bad_param", "operation is required", {{"field", "operation"}});
        return ctx;
    }

    if (params.contains("schema_version") && params["schema_version"].is_string()
        && params["schema_version"].get<std::string>() != kRequestSchema)
    {
        failure = error_envelope(ctx, "schema_version_unsupported", "schema_version must be aida.ida.mcp.manage.v1",
                                 {{"field", "schema_version"}, {"actual", params["schema_version"]}});
        return ctx;
    }

    const operation_meta_t* meta = find_meta(metas, ctx.operation);
    if (!meta)
    {
        failure = error_envelope(ctx, "unknown_operation", "unsupported operation for " + tool,
                                 {{"operation", ctx.operation}, {"allowed", operation_names(metas)}});
        return ctx;
    }

    if (params.is_object())
    {
        for (auto it = params.begin(); it != params.end(); ++it)
        {
            if (!is_common_key(it.key()) && !ctx.payload.contains(it.key()))
                ctx.payload[it.key()] = it.value();
        }
    }

    std::set<std::string> allowed;
    for (const auto& f : meta->fields)
        allowed.insert(f.name);
    if (!meta->allow_extra)
    {
        for (auto it = ctx.payload.begin(); it != ctx.payload.end(); ++it)
        {
            if (allowed.find(it.key()) == allowed.end())
            {
                failure = error_envelope(ctx, "bad_param", "unexpected payload field",
                                         {{"field", "payload." + it.key()}, {"operation", ctx.operation}});
                return ctx;
            }
        }
    }

    for (const auto& f : meta->fields)
    {
        if (f.required && !ctx.payload.contains(f.name))
        {
            failure = error_envelope(ctx, "bad_param", "required payload field is missing",
                                     {{"field", "payload." + f.name}, {"operation", ctx.operation}});
            return ctx;
        }
        if (ctx.payload.contains(f.name))
        {
            const json& v = ctx.payload.at(f.name);
            if (!type_matches(v, f.type))
            {
                failure = error_envelope(ctx, "bad_param", "payload field has the wrong type",
                                         {{"field", "payload." + f.name}, {"expected", f.type}});
                return ctx;
            }
            if (!f.enum_values.empty() && v.is_string())
            {
                const std::string actual = v.get<std::string>();
                if (std::find(f.enum_values.begin(), f.enum_values.end(), actual) == f.enum_values.end())
                {
                    failure = error_envelope(ctx, "bad_param", "payload field is outside the allowed enum",
                                             {{"field", "payload." + f.name}, {"allowed", f.enum_values}});
                    return ctx;
                }
            }
        }
    }

    failure = agent_tools::tool_result_t{};
    return ctx;
}

json job_to_json(const job_record_t& j)
{
    json out;
    out["job_id"] = j.job_id;
    out["project_id"] = j.project_id.empty() ? json(nullptr) : json(j.project_id);
    out["tool"] = j.tool;
    out["operation"] = j.operation;
    out["state"] = j.state;
    out["report_id"] = j.report_id.empty() ? json(nullptr) : json(j.report_id);
    out["created_at_ms"] = j.created_at_ms;
    out["updated_at_ms"] = j.updated_at_ms;
    out["progress"] = j.progress;
    out["idempotency_key"] = j.idempotency_key.empty() ? json(nullptr) : json(j.idempotency_key);
    out["idempotency_scope"] = j.idempotency_scope.empty() ? json(nullptr) : json(j.idempotency_scope);
    out["generation"] = j.generation;
    out["runtime_epoch"] = j.runtime_epoch.empty() ? json(nullptr) : json(j.runtime_epoch);
    out["stale_generation"] = !j.generation.empty() && j.generation != generation_id();
    out["cancel_requested"] = j.cancel_requested;
    out["error_code"] = j.error_code.empty() ? json(nullptr) : json(j.error_code);
    out["error_message"] = j.error_message.empty() ? json(nullptr) : json(j.error_message);
    out["events"] = j.events;
    out["resources"] = j.resources;
    return out;
}

struct job_create_result_t
{
    std::string job_id;
    bool reused = false;
    job_record_t snapshot;
};

std::string idempotency_scope(const request_ctx_t& ctx, const std::string& generation)
{
    if (ctx.idempotency_key.empty())
        return std::string();
    return generation + "|" + ctx.tool + "|" + ctx.operation + "|" + ctx.idempotency_key;
}

json job_resource_manifest(const std::string& job_id)
{
    return json::array({
        {{"uri", "ida://jobs/" + job_id + "/result"}, {"kind", "job_result"}, {"job_id", job_id}},
        {{"uri", "ida://jobs/" + job_id + "/events"}, {"kind", "job_events"}, {"job_id", job_id}}
    });
}

bool active_job_state(const std::string& state_name)
{
    return state_name == "queued" || state_name == "running" || state_name == "cancelling";
}

std::string project_id_from_ctx(const request_ctx_t& ctx)
{
    const std::string captured_project = ctx.payload.value("_aida_project_id", std::string());
    if (!captured_project.empty())
        return aida::vuln::chain::sanitize_store_component(captured_project);
    const std::string explicit_project = ctx.payload.value("project_id", std::string());
    if (!explicit_project.empty())
        return aida::vuln::chain::sanitize_store_component(explicit_project);
    return aida::vuln::chain::sanitize_store_component(aida::multibinary::default_project_id_for_current_idb());
}

json job_store_json(const job_record_t& j)
{
    return {
        {"schema", "aida_mcp_job_record_v1"},
        {"job_id", j.job_id},
        {"project_id", j.project_id},
        {"tool", j.tool},
        {"operation", j.operation},
        {"state", j.state},
        {"report_id", j.report_id},
        {"created_at_ms", j.created_at_ms},
        {"updated_at_ms", j.updated_at_ms},
        {"progress", j.progress},
        {"idempotency_key", j.idempotency_key},
        {"idempotency_scope", j.idempotency_scope},
        {"generation", j.generation},
        {"runtime_epoch", j.runtime_epoch},
        {"cancel_requested", j.cancel_requested},
        {"error_code", j.error_code},
        {"error_message", j.error_message},
        {"events", j.events},
        {"resources", j.resources},
        {"request", j.request},
        {"result", j.result}
    };
}

std::string json_string_field(const json& v, const char* key, const std::string& fallback = std::string())
{
    if (!v.contains(key) || !v.at(key).is_string())
        return fallback;
    return v.at(key).get<std::string>();
}

uint64_t json_u64_field(const json& v, const char* key, uint64_t fallback = 0)
{
    if (!v.contains(key))
        return fallback;
    const json& item = v.at(key);
    if (item.is_number_unsigned())
        return item.get<uint64_t>();
    if (item.is_number_integer())
    {
        const int64_t signed_value = item.get<int64_t>();
        return signed_value < 0 ? fallback : static_cast<uint64_t>(signed_value);
    }
    return fallback;
}

double json_double_field(const json& v, const char* key, double fallback = 0.0)
{
    if (!v.contains(key) || !v.at(key).is_number())
        return fallback;
    return v.at(key).get<double>();
}

std::optional<job_record_t> job_from_store_json(const json& v)
{
    if (!v.is_object())
        return std::nullopt;
    job_record_t j;
    j.job_id = json_string_field(v, "job_id");
    if (j.job_id.empty())
        return std::nullopt;
    j.project_id = json_string_field(v, "project_id");
    j.tool = json_string_field(v, "tool");
    j.operation = json_string_field(v, "operation");
    j.state = json_string_field(v, "state", "failed");
    j.report_id = json_string_field(v, "report_id");
    j.error_code = json_string_field(v, "error_code");
    j.error_message = json_string_field(v, "error_message");
    j.idempotency_key = json_string_field(v, "idempotency_key");
    j.idempotency_scope = json_string_field(v, "idempotency_scope");
    j.generation = json_string_field(v, "generation");
    j.runtime_epoch = json_string_field(v, "runtime_epoch");
    j.created_at_ms = json_u64_field(v, "created_at_ms");
    j.updated_at_ms = json_u64_field(v, "updated_at_ms", j.created_at_ms);
    j.progress = json_double_field(v, "progress", active_job_state(j.state) ? 0.01 : 1.0);
    j.cancel_requested = v.value("cancel_requested", false);
    j.request = v.value("request", json::object());
    j.result = v.value("result", json::object());
    j.events = v.value("events", json::array());
    j.resources = v.value("resources", json::array());
    if (j.project_id.empty() && j.request.is_object())
        j.project_id = j.request.value("project_id", std::string());
    if (j.project_id.empty())
        j.project_id = "default";
    if (j.runtime_epoch != runtime_epoch_id() && active_job_state(j.state))
    {
        const uint64_t ts = now_ms();
        j.state = "failed";
        j.error_code = "runtime_interrupted";
        j.error_message = "job was interrupted before this plugin runtime started";
        j.updated_at_ms = ts;
        j.progress = 1.0;
        j.events.push_back({{"ts_ms", ts}, {"state", "failed"}, {"event", "runtime_interrupted"}, {"previous_runtime_epoch", j.runtime_epoch}});
    }
    return j;
}

json report_store_json(const report_record_t& r)
{
    return {
        {"schema", "aida_mcp_report_record_v1"},
        {"report_id", r.report_id},
        {"project_id", r.project_id},
        {"job_id", r.job_id},
        {"chain_id", r.chain_id},
        {"created_at_ms", r.created_at_ms},
        {"content_hash", r.content_hash},
        {"report", r.report}
    };
}

std::optional<report_record_t> report_from_store_json(const json& v)
{
    if (!v.is_object())
        return std::nullopt;
    report_record_t r;
    r.report_id = json_string_field(v, "report_id");
    if (r.report_id.empty())
        return std::nullopt;
    r.project_id = json_string_field(v, "project_id", "default");
    r.job_id = json_string_field(v, "job_id");
    r.chain_id = json_string_field(v, "chain_id");
    r.created_at_ms = json_u64_field(v, "created_at_ms");
    r.content_hash = json_string_field(v, "content_hash");
    r.report = v.value("report", json::object());
    if (r.content_hash.empty())
        r.content_hash = hash_text(r.report.dump());
    return r;
}

void cache_job_record_locked(state_t& s, const job_record_t& j)
{
    s.jobs[j.job_id] = j;
    if (!j.idempotency_scope.empty())
        s.idempotency_jobs[j.idempotency_scope] = j.job_id;
    auto tok = s.cancellation_tokens.find(j.job_id);
    if (tok == s.cancellation_tokens.end())
        tok = s.cancellation_tokens.emplace(j.job_id, aida::vuln::chain::cancellation_token_t()).first;
    auto flag = s.gateway_cancel_flags.find(j.job_id);
    if (flag == s.gateway_cancel_flags.end())
        flag = s.gateway_cancel_flags.emplace(j.job_id, std::make_shared<std::atomic_bool>(false)).first;
    if (j.cancel_requested)
    {
        tok->second.cancel();
        flag->second->store(true, std::memory_order_release);
    }
}

void persist_job_record(const job_record_t& j)
{
    if (j.project_id.empty() || j.job_id.empty())
        return;
    aida::vuln::chain::save_chain_job_record(j.project_id, j.job_id, job_store_json(j));
}

void persist_report_record(const report_record_t& r)
{
    if (r.project_id.empty() || r.report_id.empty())
        return;
    aida::vuln::chain::save_chain_report_record(r.project_id, r.report_id, report_store_json(r));
}

void hydrate_jobs_for_project(const std::string& project_id)
{
    if (project_id.empty())
        return;
    auto& s = state();
    {
        std::lock_guard<std::mutex> lock(s.mutex);
        if (s.hydrated_job_projects.find(project_id) != s.hydrated_job_projects.end())
            return;
        s.hydrated_job_projects.insert(project_id);
    }
    auto loaded = aida::vuln::chain::list_chain_job_records(project_id);
    std::vector<job_record_t> changed;
    {
        std::lock_guard<std::mutex> lock(s.mutex);
        for (const auto& record : loaded.records)
        {
            auto parsed = job_from_store_json(record);
            if (!parsed)
                continue;
            cache_job_record_locked(s, *parsed);
            if (parsed->error_code == "runtime_interrupted")
                changed.push_back(*parsed);
        }
    }
    for (const auto& j : changed)
        persist_job_record(j);
}

void hydrate_reports_for_project(const std::string& project_id)
{
    if (project_id.empty())
        return;
    auto& s = state();
    {
        std::lock_guard<std::mutex> lock(s.mutex);
        if (s.hydrated_report_projects.find(project_id) != s.hydrated_report_projects.end())
            return;
        s.hydrated_report_projects.insert(project_id);
    }
    auto loaded = aida::vuln::chain::list_chain_report_records(project_id);
    std::lock_guard<std::mutex> lock(s.mutex);
    for (const auto& record : loaded.records)
    {
        auto parsed = report_from_store_json(record);
        if (!parsed)
            continue;
        s.reports[parsed->report_id] = *parsed;
    }
}

std::optional<job_record_t> load_job_record_from_store(const std::string& project_id, const std::string& job_id)
{
    if (project_id.empty() || job_id.empty())
        return std::nullopt;
    auto loaded = aida::vuln::chain::load_chain_job_record(project_id, job_id);
    if (!loaded.ok)
        return std::nullopt;
    auto parsed = job_from_store_json(loaded.record);
    if (!parsed)
        return std::nullopt;
    auto& s = state();
    {
        std::lock_guard<std::mutex> lock(s.mutex);
        cache_job_record_locked(s, *parsed);
    }
    if (parsed->error_code == "runtime_interrupted")
        persist_job_record(*parsed);
    return parsed;
}

std::optional<report_record_t> load_report_record_from_store(const std::string& project_id, const std::string& report_id)
{
    if (project_id.empty() || report_id.empty())
        return std::nullopt;
    auto loaded = aida::vuln::chain::load_chain_report_record(project_id, report_id);
    if (!loaded.ok)
        return std::nullopt;
    auto parsed = report_from_store_json(loaded.record);
    if (!parsed)
        return std::nullopt;
    auto& s = state();
    std::lock_guard<std::mutex> lock(s.mutex);
    s.reports[parsed->report_id] = *parsed;
    return parsed;
}

job_create_result_t create_job(const request_ctx_t& ctx)
{
    auto& s = state();
    const std::string project_id = project_id_from_ctx(ctx);
    hydrate_jobs_for_project(project_id);
    const std::string gen = ctx.payload.value("_aida_generation", std::string()).empty() ? generation_id() : ctx.payload.value("_aida_generation", std::string());
    const std::string idem = idempotency_scope(ctx, gen);
    std::lock_guard<std::mutex> lock(s.mutex);
    if (!idem.empty())
    {
        auto found = s.idempotency_jobs.find(idem);
        if (found != s.idempotency_jobs.end())
        {
            auto jit = s.jobs.find(found->second);
            if (jit != s.jobs.end())
                return {jit->second.job_id, true, jit->second};
        }
    }
    const uint64_t id = s.next_job.fetch_add(1);
    std::ostringstream ss;
    ss << "ida-job-" << std::hex << fnv1a64(gen + runtime_epoch_id()) << "-" << now_ms() << "-" << id;
    job_record_t j;
    j.job_id = ss.str();
    j.project_id = project_id;
    j.tool = ctx.tool;
    j.operation = ctx.operation;
    j.state = "queued";
    j.idempotency_key = ctx.idempotency_key;
    j.idempotency_scope = idem;
    j.generation = gen;
    j.runtime_epoch = runtime_epoch_id();
    j.created_at_ms = now_ms();
    j.updated_at_ms = j.created_at_ms;
    j.progress = 0.0;
    j.resources = job_resource_manifest(j.job_id);
    j.request = {
        {"tool", ctx.tool},
        {"operation", ctx.operation},
        {"request_id", ctx.request_id},
        {"project_id", project_id},
        {"payload", ctx.payload},
        {"budget", ctx.budget},
        {"job_mode", ctx.job_mode},
        {"idempotency_key", ctx.idempotency_key},
        {"idempotency_scope", idem},
        {"runtime_epoch", j.runtime_epoch},
        {"generation", gen}
    };
    j.events.push_back({{"ts_ms", j.created_at_ms}, {"state", "queued"}, {"event", "job_queued"}, {"generation", gen}});
    const std::string job_id = j.job_id;
    job_record_t snapshot = j;
    s.jobs.emplace(job_id, std::move(j));
    s.cancellation_tokens[job_id] = aida::vuln::chain::cancellation_token_t();
    s.gateway_cancel_flags[job_id] = std::make_shared<std::atomic_bool>(false);
    if (!idem.empty())
        s.idempotency_jobs[idem] = job_id;
    persist_job_record(snapshot);
    return {job_id, false, snapshot};
}

void append_job_event(const std::string& job_id, const std::string& event, const json& details = json::object())
{
    auto& s = state();
    std::optional<job_record_t> changed;
    std::lock_guard<std::mutex> lock(s.mutex);
    auto it = s.jobs.find(job_id);
    if (it == s.jobs.end())
        return;
    json e;
    e["ts_ms"] = now_ms();
    e["event"] = event;
    if (!details.is_null() && !details.empty())
        e["details"] = details;
    it->second.events.push_back(std::move(e));
    while (it->second.events.size() > 256)
        it->second.events.erase(it->second.events.begin());
    it->second.updated_at_ms = now_ms();
    changed = it->second;
    if (changed)
        persist_job_record(*changed);
}

bool mark_job_running(const std::string& job_id)
{
    auto& s = state();
    std::lock_guard<std::mutex> lock(s.mutex);
    auto it = s.jobs.find(job_id);
    if (it == s.jobs.end())
        return false;
    if (it->second.cancel_requested)
        return false;
    it->second.state = "running";
    it->second.updated_at_ms = now_ms();
    it->second.progress = std::max(it->second.progress, 0.01);
    it->second.events.push_back({{"ts_ms", it->second.updated_at_ms}, {"state", "running"}, {"event", "job_running"}});
    persist_job_record(it->second);
    return true;
}

void finish_job(const std::string& job_id,
                const std::string& state_name,
                const json& result,
                const std::string& report_id = std::string(),
                const std::string& err_code = std::string(),
                const std::string& err_msg = std::string(),
                const json& resources = json::array())
{
    auto& s = state();
    std::lock_guard<std::mutex> lock(s.mutex);
    auto it = s.jobs.find(job_id);
    if (it == s.jobs.end())
        return;
    std::string final_state = state_name;
    std::string final_error_code = err_code;
    std::string final_error_message = err_msg;
    if (it->second.cancel_requested && state_name == "completed")
    {
        final_state = "cancelled";
        final_error_code = "cancelled";
        final_error_message = "job was cancelled before completion was published";
    }
    it->second.state = final_state;
    it->second.updated_at_ms = now_ms();
    it->second.progress = final_state == "completed" || final_state == "failed" || final_state == "cancelled" ? 1.0 : it->second.progress;
    it->second.result = result;
    it->second.report_id = report_id;
    it->second.error_code = final_error_code;
    it->second.error_message = final_error_message;
    if (!resources.is_null() && !resources.empty())
        it->second.resources = resources;
    it->second.events.push_back({{"ts_ms", it->second.updated_at_ms}, {"state", final_state}, {"event", "job_" + final_state}});
    persist_job_record(it->second);
}

std::optional<job_record_t> get_job(const std::string& job_id, const std::string& project_id = std::string())
{
    auto& s = state();
    {
        std::lock_guard<std::mutex> lock(s.mutex);
        auto it = s.jobs.find(job_id);
        if (it != s.jobs.end())
            return it->second;
    }
    if (!project_id.empty())
        return load_job_record_from_store(project_id, job_id);
    return std::nullopt;
}

bool job_cancel_requested(const std::string& job_id)
{
    auto& s = state();
    std::lock_guard<std::mutex> lock(s.mutex);
    auto it = s.jobs.find(job_id);
    return it != s.jobs.end() && it->second.cancel_requested;
}

aida::vuln::chain::cancellation_token_t cancellation_token_for_job(const std::string& job_id)
{
    auto& s = state();
    std::lock_guard<std::mutex> lock(s.mutex);
    return s.cancellation_tokens[job_id];
}

std::shared_ptr<std::atomic_bool> gateway_cancel_flag_for_job(const std::string& job_id)
{
    auto& s = state();
    std::lock_guard<std::mutex> lock(s.mutex);
    auto it = s.gateway_cancel_flags.find(job_id);
    if (it != s.gateway_cancel_flags.end())
        return it->second;
    auto flag = std::make_shared<std::atomic_bool>(false);
    s.gateway_cancel_flags[job_id] = flag;
    return flag;
}

bool cancel_job_record(const std::string& job_id)
{
    auto& s = state();
    std::lock_guard<std::mutex> lock(s.mutex);
    auto it = s.jobs.find(job_id);
    if (it == s.jobs.end())
        return false;
    it->second.cancel_requested = true;
    const bool was_active = it->second.state == "running" || it->second.state == "cancelling";
    it->second.state = was_active ? "cancelling" : "cancelled";
    it->second.updated_at_ms = now_ms();
    if (!was_active)
        it->second.progress = 1.0;
    it->second.events.push_back({{"ts_ms", it->second.updated_at_ms}, {"state", it->second.state}, {"event", was_active ? "job_cancelling" : "job_cancelled"}});
    auto tok = s.cancellation_tokens.find(job_id);
    if (tok != s.cancellation_tokens.end())
        tok->second.cancel();
    auto flag = s.gateway_cancel_flags.find(job_id);
    if (flag != s.gateway_cancel_flags.end() && flag->second)
        flag->second->store(true, std::memory_order_release);
    persist_job_record(it->second);
    return true;
}

json cancel_all_job_records()
{
    auto& s = state();
    std::lock_guard<std::mutex> lock(s.mutex);
    json ids = json::array();
    const uint64_t ts = now_ms();
    for (auto& kv : s.jobs)
    {
        job_record_t& j = kv.second;
        if (j.state == "completed" || j.state == "failed" || j.state == "cancelled")
            continue;
        j.cancel_requested = true;
        const bool was_active = j.state == "running" || j.state == "cancelling";
        j.state = was_active ? "cancelling" : "cancelled";
        j.updated_at_ms = ts;
        if (!was_active)
            j.progress = 1.0;
        j.events.push_back({{"ts_ms", ts}, {"state", j.state}, {"event", was_active ? "job_cancelling" : "job_cancelled"}});
        ids.push_back(j.job_id);
        auto tok = s.cancellation_tokens.find(j.job_id);
        if (tok != s.cancellation_tokens.end())
            tok->second.cancel();
        auto flag = s.gateway_cancel_flags.find(j.job_id);
        if (flag != s.gateway_cancel_flags.end() && flag->second)
            flag->second->store(true, std::memory_order_release);
        persist_job_record(j);
    }
    return {{"cancelled", !ids.empty()}, {"cancelled_count", ids.size()}, {"job_ids", ids}};
}

std::string store_report(const std::string& project_id, const std::string& job_id, const std::string& chain_id, const json& report)
{
    auto& s = state();
    const uint64_t id = s.next_report.fetch_add(1);
    std::ostringstream ss;
    ss << "ida-report-" << std::hex << fnv1a64(job_id + report.dump()) << "-" << id;
    report_record_t r;
    r.report_id = ss.str();
    r.project_id = project_id.empty() ? std::string("default") : project_id;
    r.job_id = job_id;
    r.chain_id = chain_id;
    r.created_at_ms = now_ms();
    r.report = report;
    r.report["report_id"] = r.report_id;
    r.content_hash = hash_text(r.report.dump());
    std::lock_guard<std::mutex> lock(s.mutex);
    s.reports.emplace(r.report_id, std::move(r));
    auto it = s.reports.find(ss.str());
    if (it != s.reports.end())
        persist_report_record(it->second);
    return ss.str();
}

std::optional<report_record_t> get_report_record(const std::string& report_id, const std::string& project_id = std::string())
{
    auto& s = state();
    {
        std::lock_guard<std::mutex> lock(s.mutex);
        auto it = s.reports.find(report_id);
        if (it != s.reports.end())
            return it->second;
    }
    if (!project_id.empty())
        return load_report_record_from_store(project_id, report_id);
    return std::nullopt;
}

struct queued_job_result_t
{
    bool ok = false;
    json data = json::object();
    std::string report_id;
    std::string error_code;
    std::string error_message;
    json resources = json::array();
};

json chain_document_from_ctx(const request_ctx_t& ctx, const json& module_override);
queued_job_result_t execute_queued_mcp_job(const request_ctx_t& ctx, const job_record_t& job);

struct async_context_capture_t
{
    bool ok = false;
    std::string error_code;
    std::string error_message;
    json data = json::object();
};

class mcp_job_runtime_t
{
public:
    mcp_job_runtime_t()
    {
        gateway.start();
        worker = std::thread([this]() { worker_loop(); });
    }

    ~mcp_job_runtime_t()
    {
        shutdown();
    }

    mcp_job_runtime_t(const mcp_job_runtime_t&) = delete;
    mcp_job_runtime_t& operator=(const mcp_job_runtime_t&) = delete;

    async_context_capture_t capture_context(const request_ctx_t& ctx)
    {
        gateway.start();
        ida_gateway_request_t request;
        request.domain = ida_gateway_domain_t::mixed;
        request.phase = "mcp_job";
        request.operation = "capture_context";
        request.mff_flags = MFF_READ;
        request.deadline_ms = 10000;
        ida_gateway_result_t result = gateway.execute(request, [ctx](const ida_gateway_context_t&) {
            const std::string explicit_project = ctx.payload.value("project_id", std::string());
            const std::string project_id = explicit_project.empty()
                ? aida::multibinary::default_project_id_for_current_idb()
                : explicit_project;
            return json{
                {"generation", generation_id()},
                {"project_id", aida::vuln::chain::sanitize_store_component(project_id)},
                {"module", module_identity()}
            };
        });
        async_context_capture_t capture;
        capture.ok = result.ok;
        capture.data = result.data;
        if (!result.ok)
        {
            capture.error_code = result.stale_generation ? "stale_generation" : (result.timed_out ? "timeout" : (result.cancelled ? "cancelled" : "idb_unavailable"));
            capture.error_message = result.error.empty() ? "failed to capture async job context through IDA gateway" : result.error;
        }
        return capture;
    }

    bool enqueue(const request_ctx_t& ctx, const std::string& job_id, std::string& error)
    {
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (stopping.load(std::memory_order_acquire))
            {
                error = "runtime_stopping";
                return false;
            }
            if (queue.size() >= k_max_queue_depth)
            {
                error = "queue_full";
                return false;
            }
            queue.push_back({ctx, job_id});
        }
        cv.notify_one();
        return true;
    }

    json diagnostics()
    {
        std::lock_guard<std::mutex> lock(mutex);
        return {
            {"runtime_epoch", runtime_epoch_id()},
            {"stopping", stopping.load(std::memory_order_acquire)},
            {"queue_depth", queue.size()},
            {"active_job_id", active_job_id.empty() ? json(nullptr) : json(active_job_id)},
            {"max_queue_depth", k_max_queue_depth},
            {"gateway", gateway.metrics_json()}
        };
    }

    ida_gateway_result_t execute_ida_job(const request_ctx_t& ctx,
                                         const std::string& job_id,
                                         int mff_flags,
                                         uint32_t deadline_ms,
                                         const std::function<json()>& body)
    {
        ida_gateway_request_t request;
        request.domain = ida_gateway_domain_t::mixed;
        request.phase = "mcp_job";
        request.operation = ctx.operation;
        request.mff_flags = mff_flags;
        request.deadline_ms = deadline_ms;
        request.modal_policy = ida_gateway_modal_policy_t::defer_if_modal;
        request.cancellation = gateway_cancel_flag_for_job(job_id);
        return gateway.execute(request, [body](const ida_gateway_context_t&) {
            return body();
        });
    }

    void shutdown()
    {
        const bool already = stopping.exchange(true, std::memory_order_acq_rel);
        if (!already)
        {
            cancel_all_job_records();
            gateway.cancel_all();
        }
        cv.notify_all();
        if (worker.joinable())
            worker.join();
        gateway.stop();
    }

private:
    struct queued_job_t
    {
        request_ctx_t ctx;
        std::string job_id;
    };

    static constexpr std::size_t k_max_queue_depth = 8;

    std::mutex mutex;
    std::condition_variable cv;
    std::deque<queued_job_t> queue;
    std::thread worker;
    ida_gateway_t gateway;
    std::atomic_bool stopping{false};
    std::string active_job_id;

    async_context_capture_t current_generation()
    {
        ida_gateway_request_t request;
        request.domain = ida_gateway_domain_t::mixed;
        request.phase = "mcp_job";
        request.operation = "generation_check";
        request.mff_flags = MFF_READ;
        request.deadline_ms = 10000;
        ida_gateway_result_t result = gateway.execute(request, [](const ida_gateway_context_t&) {
            return json{{"generation", generation_id()}};
        });
        async_context_capture_t capture;
        capture.ok = result.ok;
        capture.data = result.data;
        if (!result.ok)
        {
            capture.error_code = result.stale_generation ? "stale_generation" : (result.timed_out ? "timeout" : (result.cancelled ? "cancelled" : "idb_unavailable"));
            capture.error_message = result.error.empty() ? "failed to check generation through IDA gateway" : result.error;
        }
        return capture;
    }

    bool generation_matches(const job_record_t& job, queued_job_result_t& failure)
    {
        async_context_capture_t current = current_generation();
        if (!current.ok)
        {
            failure.ok = false;
            failure.error_code = current.error_code;
            failure.error_message = current.error_message;
            failure.data = current.data;
            return false;
        }
        const std::string now_generation = current.data.value("generation", std::string());
        if (!job.generation.empty() && now_generation != job.generation)
        {
            failure.ok = false;
            failure.error_code = "stale_generation";
            failure.error_message = "IDB generation changed while the job was queued or running";
            failure.data = {{"submitted_generation", job.generation}, {"current_generation", now_generation}};
            return false;
        }
        return true;
    }

    void worker_loop()
    {
        while (true)
        {
            queued_job_t item;
            {
                std::unique_lock<std::mutex> lock(mutex);
                cv.wait(lock, [this]() { return stopping.load(std::memory_order_acquire) || !queue.empty(); });
                if (stopping.load(std::memory_order_acquire) && queue.empty())
                    break;
                item = queue.front();
                queue.pop_front();
                active_job_id = item.job_id;
            }

            auto job = get_job(item.job_id, project_id_from_ctx(item.ctx));
            if (!job)
            {
                std::lock_guard<std::mutex> lock(mutex);
                active_job_id.clear();
                continue;
            }
            if (!mark_job_running(item.job_id))
            {
                finish_job(item.job_id, "cancelled", {{"cancelled", true}}, std::string(), "cancelled", "job was cancelled before execution");
                std::lock_guard<std::mutex> lock(mutex);
                active_job_id.clear();
                continue;
            }
            queued_job_result_t stale_failure;
            if (!generation_matches(*job, stale_failure))
            {
                finish_job(item.job_id, "failed", stale_failure.data, std::string(), stale_failure.error_code, stale_failure.error_message);
                std::lock_guard<std::mutex> lock(mutex);
                active_job_id.clear();
                continue;
            }

            queued_job_result_t result;
            try
            {
                result = execute_queued_mcp_job(item.ctx, *job);
            }
            catch (const std::exception& ex)
            {
                result.ok = false;
                result.error_code = "internal_error";
                result.error_message = ex.what();
            }
            catch (...)
            {
                result.ok = false;
                result.error_code = "internal_error";
                result.error_message = "unknown async job exception";
            }

            auto after = get_job(item.job_id, project_id_from_ctx(item.ctx));
            if (after && after->cancel_requested)
            {
                finish_job(item.job_id, "cancelled", result.data, result.report_id, "cancelled", "job cancellation was requested", result.resources);
            }
            else
            {
                queued_job_result_t publish_failure;
                if (after && !generation_matches(*after, publish_failure))
                    finish_job(item.job_id, "failed", result.data.empty() ? publish_failure.data : result.data, result.report_id, publish_failure.error_code, publish_failure.error_message, result.resources);
                else
                    finish_job(item.job_id, result.ok ? "completed" : "failed", result.data, result.report_id, result.error_code, result.error_message, result.resources);
            }

            {
                std::lock_guard<std::mutex> lock(mutex);
                active_job_id.clear();
            }
        }
    }
};

mcp_job_runtime_t& job_runtime()
{
    (void)state();
    static mcp_job_runtime_t runtime;
    return runtime;
}

json resource_for_report(const report_record_t& r, const std::string& format)
{
    json res;
    res["uri"] = "ida://chain/reports/" + r.report_id + "?format=" + format;
    res["kind"] = "report";
    res["report_id"] = r.report_id;
    res["format"] = format;
    res["content_hash"] = r.content_hash;
    res["available_via"] = "ida_report_manage.export_report";
    return res;
}

json make_capabilities(const std::string& tool, const std::vector<operation_meta_t>& metas)
{
    json d;
    d["schema_version"] = kRequestSchema;
    d["response_schema"] = kResponseSchema;
    d["tool"] = tool;
    d["operations"] = operations_json(metas);
    d["operation_field"] = "operation";
    d["action_alias_accepted"] = true;
    d["routing"] = {
        {"instance_id", "Handled by the existing MCP proxy before this tool executes."},
        {"pid", "Handled by the existing MCP proxy before this tool executes."}
    };
    d["common_error_codes"] = {
        "bad_param", "unsupported_operation", "unknown_operation", "schema_version_unsupported",
        "peer_unavailable", "peer_timeout", "wrong_instance", "idb_unavailable",
        "analysis_not_settled", "hexrays_unavailable", "index_required", "budget_exhausted",
        "result_too_large", "cursor_expired", "job_not_found", "job_conflict", "cancelled",
        "timeout", "stale_generation", "destructive_denied", "license_required", "rate_limited",
        "internal_error"
    };
    d["examples"] = json::array({
        {{"operation", "capabilities"}, {"payload", json::object()}},
        {{"operation", "status"}, {"payload", json::object()}},
        {{"operation", "functions"}, {"limit", 100}, {"payload", {{"filter", ""}}}}
    });
    return d;
}

json segment_json(const segment_t* seg)
{
    json s;
    if (!seg)
        return s;
    qstring name;
    qstring cls;
    get_segm_name(&name, seg);
    get_segm_class(&cls, seg);
    s["name"] = name.c_str();
    s["class"] = cls.c_str();
    s["start_ea"] = fmt_ea(seg->start_ea);
    s["end_ea"] = fmt_ea(seg->end_ea);
    s["size"] = static_cast<uint64_t>(seg->end_ea - seg->start_ea);
    s["type"] = static_cast<int>(segtype(seg->start_ea));
    s["perm"] = seg->perm;
    s["read"] = (seg->perm & SEGPERM_READ) != 0;
    s["write"] = (seg->perm & SEGPERM_WRITE) != 0;
    s["execute"] = (seg->perm & SEGPERM_EXEC) != 0;
    return s;
}

json function_json(func_t* fn, bool include_segment)
{
    json f;
    if (!fn)
        return f;
    qstring name;
    get_func_name(&name, fn->start_ea);
    f["address"] = fmt_ea(fn->start_ea);
    f["rva"] = fmt_ea(fn->start_ea - static_cast<ea_t>(get_imagebase()));
    f["end_address"] = fmt_ea(fn->end_ea);
    f["size"] = static_cast<uint64_t>(fn->end_ea - fn->start_ea);
    f["name"] = name.c_str();
    f["flags"] = fn->flags;
    if (include_segment)
        f["segment"] = segment_json(getseg(fn->start_ea));
    return f;
}

json import_rows(int max_rows)
{
    struct import_state_t
    {
        json rows = json::array();
        int max_rows = 0;
        std::string module;
    } st;
    st.max_rows = max_rows;
    const uint qty = get_import_module_qty();
    for (uint i = 0; i < qty && static_cast<int>(st.rows.size()) < max_rows; ++i)
    {
        qstring mod;
        get_import_module_name(&mod, static_cast<int>(i));
        st.module = mod.c_str();
        enum_import_names(static_cast<int>(i), [](ea_t ea, const char* name, uval_t ordinal, void* ud) -> int {
            auto* s = static_cast<import_state_t*>(ud);
            if (static_cast<int>(s->rows.size()) >= s->max_rows)
                return 0;
            json r;
            r["module"] = s->module;
            r["name"] = name ? name : "";
            r["ea"] = ea == BADADDR ? json(nullptr) : json(fmt_ea(ea));
            r["ordinal"] = static_cast<uint64_t>(ordinal);
            s->rows.push_back(r);
            return 1;
        }, &st);
    }
    return st.rows;
}

json entry_rows(int max_rows)
{
    json rows = json::array();
    const size_t qty = get_entry_qty();
    for (size_t i = 0; i < qty && static_cast<int>(rows.size()) < max_rows; ++i)
    {
        const uval_t ord = get_entry_ordinal(i);
        const ea_t ea = get_entry(ord);
        qstring name;
        qstring fwd;
        get_entry_name(&name, ord);
        get_entry_forwarder(&fwd, ord);
        rows.push_back({
            {"ordinal", static_cast<uint64_t>(ord)},
            {"ea", ea == BADADDR ? json(nullptr) : json(fmt_ea(ea))},
            {"name", name.c_str()},
            {"forwarder", fwd.c_str()}
        });
    }
    return rows;
}

json segment_rows()
{
    json rows = json::array();
    const int qty = get_segm_qty();
    for (int i = 0; i < qty; ++i)
        rows.push_back(segment_json(getnseg(i)));
    return rows;
}

bool ea_range_valid(ea_t start, ea_t end)
{
    return start != BADADDR && end != BADADDR && end > start;
}

bool ea_ranges_overlap(ea_t a_start, ea_t a_end, ea_t b_start, ea_t b_end)
{
    return ea_range_valid(a_start, a_end) && ea_range_valid(b_start, b_end)
        && a_start < b_end && b_start < a_end;
}

uint64_t ea_range_size(ea_t start, ea_t end)
{
    if (!ea_range_valid(start, end))
        return 0;
    return static_cast<uint64_t>(end - start);
}

json segment_rows_for_range(ea_t start, ea_t end, ea_t image_base, int max_rows)
{
    json rows = json::array();
    const int qty = get_segm_qty();
    for (int i = 0; i < qty && static_cast<int>(rows.size()) < max_rows; ++i)
    {
        segment_t* seg = getnseg(i);
        if (!seg || !ea_ranges_overlap(start, end, seg->start_ea, seg->end_ea))
            continue;
        json s = segment_json(seg);
        if (image_base != BADADDR && seg->start_ea >= image_base)
            s["rva_start"] = fmt_ea(seg->start_ea - image_base);
        if (image_base != BADADDR && seg->end_ea >= image_base)
            s["rva_end"] = fmt_ea(seg->end_ea - image_base);
        rows.push_back(std::move(s));
    }
    return rows;
}

std::optional<ea_t> json_location_field(const json& object, const char* key)
{
    if (!object.is_object() || !object.contains(key))
        return std::nullopt;
    return parse_location(object.at(key));
}

bool module_range_from_json(const json& module, ea_t& start, ea_t& end)
{
    start = BADADDR;
    end = BADADDR;
    for (const char* key : {"mapped_start", "min_ea", "base", "image_base"})
    {
        auto value = json_location_field(module, key);
        if (value)
        {
            start = *value;
            break;
        }
    }
    for (const char* key : {"mapped_end", "max_ea", "end"})
    {
        auto value = json_location_field(module, key);
        if (value)
        {
            end = *value;
            break;
        }
    }
    return ea_range_valid(start, end);
}

std::string module_search_text(const json& module)
{
    std::string text;
    for (const char* key : {"source", "module_id", "corpus_id", "name", "path", "canonical_name", "input_file", "input_path", "input_basename"})
    {
        if (module.contains(key) && module.at(key).is_string())
        {
            if (!text.empty())
                text.push_back('\n');
            text += module.at(key).get<std::string>();
        }
    }
    return lowercase_ascii(text);
}

void collect_selector_strings_from_object(const json& object, std::vector<std::string>& out)
{
    if (!object.is_object())
        return;
    for (const char* key : {"module", "module_id", "name", "path"})
    {
        if (object.contains(key))
        {
            std::string value = scalar_to_string(object.at(key));
            if (!value.empty())
                out.push_back(value);
        }
    }
}

std::vector<std::string> selector_strings(const json& payload)
{
    std::vector<std::string> values;
    collect_selector_strings_from_object(payload, values);
    if (payload.contains("selector"))
    {
        if (payload["selector"].is_object())
            collect_selector_strings_from_object(payload["selector"], values);
        else
        {
            std::string value = scalar_to_string(payload["selector"]);
            if (!value.empty())
                values.push_back(value);
        }
    }
    return values;
}

std::optional<ea_t> selector_location(const json& payload, const char* key)
{
    auto direct = payload_location(payload, key);
    if (direct)
        return direct;
    if (payload.contains("selector") && payload["selector"].is_object())
        return json_location_field(payload["selector"], key);
    return std::nullopt;
}

bool module_selector_present(const json& payload)
{
    return payload.contains("module") || payload.contains("module_id") || payload.contains("name")
        || payload.contains("path") || payload.contains("address") || payload.contains("base")
        || payload.contains("selector");
}

bool module_matches_selector(const json& module, const json& payload)
{
    if (!module_selector_present(payload))
        return false;

    ea_t start = BADADDR;
    ea_t end = BADADDR;
    const bool has_range = module_range_from_json(module, start, end);
    auto requested_base = selector_location(payload, "base");
    if (requested_base && has_range && *requested_base == start)
        return true;
    auto requested_address = selector_location(payload, "address");
    if (requested_address && has_range && *requested_address >= start && *requested_address < end)
        return true;

    const std::string searchable = module_search_text(module);
    for (std::string selector : selector_strings(payload))
    {
        selector = lowercase_ascii(selector);
        if (!selector.empty() && searchable.find(selector) != std::string::npos)
            return true;
    }
    return false;
}

json function_coverage_for_range(ea_t start, ea_t end, bool include_functions, int max_functions)
{
    json out;
    out["range_valid"] = ea_range_valid(start, end);
    out["mapped_bytes"] = ea_range_size(start, end);
    out["function_count"] = 0;
    out["function_bytes"] = 0;
    out["executable_segment_bytes"] = 0;
    out["functions_truncated"] = false;
    out["functions"] = json::array();
    if (!ea_range_valid(start, end))
        return out;

    const int seg_qty = get_segm_qty();
    for (int i = 0; i < seg_qty; ++i)
    {
        segment_t* seg = getnseg(i);
        if (!seg || (seg->perm & SEGPERM_EXEC) == 0 || !ea_ranges_overlap(start, end, seg->start_ea, seg->end_ea))
            continue;
        const ea_t overlap_start = std::max(start, seg->start_ea);
        const ea_t overlap_end = std::min(end, seg->end_ea);
        out["executable_segment_bytes"] = out["executable_segment_bytes"].get<uint64_t>() + ea_range_size(overlap_start, overlap_end);
    }

    std::map<std::string, json> by_segment;
    const size_t qty = get_func_qty();
    for (size_t i = 0; i < qty; ++i)
    {
        func_t* fn = getn_func(i);
        if (!fn || !ea_ranges_overlap(start, end, fn->start_ea, fn->end_ea))
            continue;
        out["function_count"] = out["function_count"].get<uint64_t>() + 1;
        const ea_t overlap_start = std::max(start, fn->start_ea);
        const ea_t overlap_end = std::min(end, fn->end_ea);
        const uint64_t bytes = ea_range_size(overlap_start, overlap_end);
        out["function_bytes"] = out["function_bytes"].get<uint64_t>() + bytes;

        std::string seg_name = "unsegmented";
        if (segment_t* seg = getseg(fn->start_ea))
        {
            qstring qname;
            get_segm_name(&qname, seg);
            seg_name = qname.empty() ? "unnamed" : std::string(qname.c_str());
        }
        json& bucket = by_segment[seg_name];
        if (bucket.is_null())
        {
            bucket = json::object();
            bucket["segment"] = seg_name;
            bucket["function_count"] = 0;
            bucket["function_bytes"] = 0;
        }
        bucket["function_count"] = bucket["function_count"].get<uint64_t>() + 1;
        bucket["function_bytes"] = bucket["function_bytes"].get<uint64_t>() + bytes;

        if (include_functions)
        {
            if (static_cast<int>(out["functions"].size()) < max_functions)
                out["functions"].push_back(function_json(fn, true));
            else
                out["functions_truncated"] = true;
        }
    }

    json segs = json::array();
    for (auto& kv : by_segment)
        segs.push_back(std::move(kv.second));
    out["by_segment"] = std::move(segs);

    const double mapped = static_cast<double>(out["mapped_bytes"].get<uint64_t>());
    const double exec = static_cast<double>(out["executable_segment_bytes"].get<uint64_t>());
    const double func_bytes = static_cast<double>(out["function_bytes"].get<uint64_t>());
    out["coverage_ratio_mapped"] = mapped > 0.0 ? func_bytes / mapped : 0.0;
    out["coverage_ratio_executable"] = exec > 0.0 ? func_bytes / exec : 0.0;
    return out;
}

json static_module_json(const json& payload, bool detail)
{
    const int max_rows = int_param(payload, "max_rows", 256, 1, 100000);
    const int max_segments = int_param(payload, "max_segments", max_rows, 1, 10000);
    const int max_imports = int_param(payload, "max_imports", max_rows, 1, 100000);
    const int max_exports = int_param(payload, "max_exports", max_rows, 1, 100000);
    const int max_functions = int_param(payload, "max_functions", max_rows, 1, 100000);
    const bool include_segments = payload.value("include_segments", true);
    const bool include_imports = payload.value("include_imports", true);
    const bool include_exports = payload.value("include_exports", true);
    const bool include_functions = payload.value("include_functions", false);

    const ea_t image_base = static_cast<ea_t>(get_imagebase());
    const ea_t min_ea = inf_get_min_ea();
    const ea_t max_ea = inf_get_max_ea();
    const ea_t entry = inf_get_start_ea();
    json m = module_identity();
    m["schema"] = "aida.ida.module.static.v1";
    m["source"] = "idb_static";
    m["mode"] = "static";
    m["name"] = m.value("input_basename", std::string());
    m["path"] = m.value("input_path", std::string());
    m["base"] = fmt_ea(image_base);
    m["end"] = fmt_ea(max_ea);
    m["mapped_start"] = fmt_ea(min_ea);
    m["mapped_end"] = fmt_ea(max_ea);
    m["size"] = ea_range_size(min_ea, max_ea);
    m["entry_point"] = entry == BADADDR ? json(nullptr) : json(fmt_ea(entry));
    m["architecture"] = {{"processor", processor_name()}, {"bitness", bitness()}, {"big_endian", inf_is_be()}};
    m["pe_metadata"] = {
        {"file_type", static_cast<int>(inf_get_filetype())},
        {"is_dll", inf_is_dll()},
        {"is_kernel", inf_is_kernel_mode()},
        {"image_base", fmt_ea(image_base)},
        {"entry_point", entry == BADADDR ? json(nullptr) : json(fmt_ea(entry))},
        {"entry_count", static_cast<uint64_t>(get_entry_qty())},
        {"segment_count", get_segm_qty()},
        {"import_module_count", get_import_module_qty()},
        {"function_count", static_cast<uint64_t>(get_func_qty())},
        {"input_md5", input_md5()},
        {"input_sha256", input_sha256()}
    };
    m["function_coverage"] = function_coverage_for_range(min_ea, max_ea, include_functions, max_functions);
    if (include_segments || detail)
    {
        json segs = segment_rows_for_range(min_ea, max_ea, image_base, max_segments);
        m["segments"] = segs;
        m["sections"] = std::move(segs);
    }
    if (include_imports || detail)
        m["imports"] = import_rows(max_imports);
    if (include_exports || detail)
        m["exports"] = entry_rows(max_exports);
    return m;
}

json dynamic_idb_correlation(ea_t start, ea_t end, const json& payload, bool detail)
{
    json c;
    c["range_valid"] = ea_range_valid(start, end);
    c["overlaps_current_idb"] = ea_ranges_overlap(start, end, inf_get_min_ea(), inf_get_max_ea());
    c["segments"] = json::array();
    c["function_coverage"] = json::object();
    c["imports_exports_available"] = false;
    if (!ea_range_valid(start, end))
        return c;
    const int max_segments = int_param(payload, "max_segments", 256, 1, 10000);
    const int max_functions = int_param(payload, "max_functions", 256, 1, 100000);
    const bool include_functions = payload.value("include_functions", false);
    c["segments"] = segment_rows_for_range(start, end, start, max_segments);
    c["function_coverage"] = function_coverage_for_range(start, end, include_functions && detail, max_functions);
    if (c.value("overlaps_current_idb", false))
    {
        c["static_module"] = module_identity();
        c["imports_exports_available"] = true;
    }
    return c;
}

json dynamic_module_json(const modinfo_t& info, const json& payload, bool detail)
{
    const std::string path = std::string(info.name.c_str());
    json m;
    m["schema"] = "aida.ida.module.dynamic.v1";
    m["source"] = "ida_debugger";
    m["mode"] = "dynamic";
    m["name"] = basename_of(path);
    m["path"] = path;
    m["base"] = info.base == BADADDR ? json(nullptr) : json(fmt_ea(info.base));
    m["size"] = static_cast<uint64_t>(info.size);
    m["end"] = json(nullptr);
    if (info.base != BADADDR && info.size != 0)
        m["end"] = fmt_ea(info.base + static_cast<ea_t>(info.size));
    m["rebase_to"] = info.rebase_to == BADADDR ? json(nullptr) : json(fmt_ea(info.rebase_to));
    m["image_base"] = m["base"];
    m["architecture"] = {{"processor", processor_name()}, {"bitness", bitness()}, {"source", "current_ida_debugger"}};
    m["pe_metadata"] = {{"available", false}, {"reason", "ida_debugger_module_list_does_not_expose_pe_headers"}};
    m["imports_available"] = false;
    m["exports_available"] = false;
    if (detail && info.base != BADADDR && info.size != 0)
        m["idb_correlation"] = dynamic_idb_correlation(info.base, info.base + static_cast<ea_t>(info.size), payload, detail);
    return m;
}

json dynamic_modules_json(const json& payload, bool detail, json& warnings)
{
    json out;
    const int max_modules = int_param(payload, "max_modules", 1024, 1, 100000);
    const int state = get_process_state();
    out["debugger_state"] = state;
    out["debugger_attached"] = state != DSTATE_NOTASK;
    out["enumerator"] = "get_first_module/get_next_module";
    out["modules"] = json::array();
    out["total_returned"] = 0;
    out["truncated"] = false;
    if (state == DSTATE_NOTASK)
    {
        warnings.push_back({{"code", "debugger_not_active"}, {"message", "IDA debugger state has no active task; dynamic module list is unavailable"}});
        return out;
    }

    modinfo_t info;
    for (bool ok = get_first_module(&info); ok; ok = get_next_module(&info))
    {
        if (static_cast<int>(out["modules"].size()) >= max_modules)
        {
            out["truncated"] = true;
            break;
        }
        out["modules"].push_back(dynamic_module_json(info, payload, detail));
    }
    out["total_returned"] = out["modules"].size();
    if (out["modules"].empty())
        warnings.push_back({{"code", "dynamic_modules_empty"}, {"message", "IDA debugger is active but exposed no process modules through get_first_module/get_next_module"}});
    return out;
}

json selected_module_analysis(const json& module, const json& payload)
{
    json out;
    out["schema"] = "aida.ida.module.analysis.v1";
    out["module"] = module;
    out["source"] = module.value("source", std::string());
    out["static_idb_backing"] = module.value("source", std::string()) == "idb_static";
    out["dynamic_debugger_backing"] = module.value("source", std::string()) == "ida_debugger";
    ea_t start = BADADDR;
    ea_t end = BADADDR;
    if (module_range_from_json(module, start, end))
    {
        out["range"] = {{"start", fmt_ea(start)}, {"end", fmt_ea(end)}, {"size", ea_range_size(start, end)}};
        out["idb_function_coverage"] = function_coverage_for_range(start, end, payload.value("include_functions", false), int_param(payload, "max_functions", 256, 1, 100000));
        out["idb_segments"] = segment_rows_for_range(start, end, start, int_param(payload, "max_segments", 256, 1, 10000));
    }
    out["has_imports"] = module.contains("imports") && module["imports"].is_array() && !module["imports"].empty();
    out["has_exports"] = module.contains("exports") && module["exports"].is_array() && !module["exports"].empty();
    out["has_segments"] = module.contains("segments") && module["segments"].is_array() && !module["segments"].empty();
    out["coverage"] = module.value("function_coverage", json::object());
    if (module.contains("idb_correlation"))
        out["idb_correlation"] = module["idb_correlation"];
    return out;
}

json module_re_data(const request_ctx_t& ctx, json& warnings)
{
    const json& payload = ctx.payload;
    std::string mode = lowercase_ascii(scalar_to_string(payload.value("mode", json("both"))));
    std::string analysis = lowercase_ascii(scalar_to_string(payload.value("analysis", json("list"))));
    if (mode.empty())
        mode = "both";
    if (analysis.empty())
        analysis = "list";
    const bool want_static = mode == "static" || mode == "both";
    const bool want_dynamic = mode == "dynamic" || mode == "both";
    const bool selector_present = module_selector_present(payload);
    const bool detail = payload.value("detail", false) || analysis == "details" || analysis == "analyze" || selector_present;

    json data;
    data["schema"] = "aida.ida.module_re.v1";
    data["mode"] = mode;
    data["analysis"] = analysis;
    data["instance"] = instance_identity();
    data["static"] = {{"modules", json::array()}, {"total_returned", 0}};
    data["dynamic"] = {{"modules", json::array()}, {"total_returned", 0}, {"debugger_attached", false}};

    if (want_static)
    {
        data["static"]["modules"].push_back(static_module_json(payload, detail));
        data["static"]["total_returned"] = data["static"]["modules"].size();
    }
    if (want_dynamic)
        data["dynamic"] = dynamic_modules_json(payload, detail, warnings);

    json selected = json::array();
    if (selector_present)
    {
        for (const json& module : data["static"]["modules"])
        {
            if (module_matches_selector(module, payload))
                selected.push_back(module);
        }
        for (const json& module : data["dynamic"]["modules"])
        {
            if (module_matches_selector(module, payload))
                selected.push_back(module);
        }
        if (selected.empty())
            warnings.push_back({{"code", "module_selector_no_match"}, {"message", "No static or dynamic module matched the supplied selector"}});
    }
    else if (analysis == "analyze")
    {
        if (!data["static"]["modules"].empty())
            selected.push_back(data["static"]["modules"].front());
        else if (!data["dynamic"]["modules"].empty())
            selected.push_back(data["dynamic"]["modules"].front());
    }

    data["selected_modules"] = selected;
    data["selected_count"] = selected.size();
    if (!selected.empty() && (analysis == "details" || analysis == "analyze" || selector_present))
    {
        data["selected_analysis"] = json::array();
        for (const json& module : selected)
            data["selected_analysis"].push_back(selected_module_analysis(module, payload));
    }
    data["summary"] = {
        {"static_modules", data["static"]["total_returned"]},
        {"dynamic_modules", data["dynamic"].value("total_returned", 0)},
        {"selected_modules", selected.size()}
    };
    return data;
}

json inventory_json(const json& payload)
{
    const int max_rows = int_param(payload, "max_rows", 256, 1, 5000);
    const bool include_segments = payload.value("include_segments", true);
    const bool include_imports = payload.value("include_imports", true);
    const bool include_entries = payload.value("include_entries", true);
    json inv;
    inv["schema"] = "aida.ida.project.inventory.v1";
    inv["module"] = module_identity();
    inv["instance"] = instance_identity();
    inv["auto_analysis_ok"] = auto_is_ok();
    inv["function_count"] = static_cast<uint64_t>(get_func_qty());
    inv["segment_count"] = get_segm_qty();
    inv["import_module_count"] = get_import_module_qty();
    inv["entry_count"] = static_cast<uint64_t>(get_entry_qty());
    if (include_segments)
        inv["segments"] = segment_rows();
    if (include_imports)
        inv["imports_preview"] = import_rows(max_rows);
    if (include_entries)
        inv["entry_points"] = entry_rows(max_rows);
    return inv;
}

json page_vector(const request_ctx_t& ctx, const std::string& op, const json& full, json& page)
{
    const std::string gen = generation_id();
    size_t offset = 0;
    if (!parse_cursor(ctx.cursor, op, gen, offset))
    {
        page = json::object({{"error", "cursor_expired"}});
        return json::array();
    }
    json out = json::array();
    const size_t total = full.is_array() ? full.size() : 0;
    const size_t end = std::min(total, offset + static_cast<size_t>(ctx.limit));
    for (size_t i = offset; i < end; ++i)
        out.push_back(full.at(i));
    const bool truncated = end < total;
    const std::string next = truncated ? cursor_for(op, gen, end) : std::string();
    page = page_json(ctx.cursor, next, ctx.limit, out.size(), truncated);
    page["total_known"] = total;
    return out;
}

std::string pointer_escape(const std::string& key)
{
    std::string out;
    out.reserve(key.size());
    for (char c : key)
    {
        if (c == '~')
            out += "~0";
        else if (c == '/')
            out += "~1";
        else
            out.push_back(c);
    }
    return out;
}

std::string hex_encode_text(const std::string& text)
{
    static const char* h = "0123456789abcdef";
    std::string out;
    out.reserve(text.size() * 2);
    for (unsigned char c : text)
    {
        out.push_back(h[(c >> 4) & 0x0f]);
        out.push_back(h[c & 0x0f]);
    }
    return out;
}

bool hex_decode_text(const std::string& hex, std::string& out)
{
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    };
    if ((hex.size() & 1u) != 0)
        return false;
    out.clear();
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2)
    {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0)
            return false;
        out.push_back(static_cast<char>((hi << 4) | lo));
    }
    return true;
}

std::string nested_cursor_for(const std::string& op, const std::string& generation, const std::string& path, size_t offset)
{
    return "ac2." + op + "." + generation + "." + std::to_string(offset) + "." + hex_encode_text(path);
}

bool parse_nested_cursor(const std::string& cursor, const std::string& op, const std::string& generation, std::string& path, size_t& offset)
{
    offset = 0;
    path.clear();
    const std::string prefix = "ac2." + op + "." + generation + ".";
    if (cursor.rfind(prefix, 0) != 0)
        return false;
    const std::string rest = cursor.substr(prefix.size());
    const std::size_t dot = rest.find('.');
    if (dot == std::string::npos)
        return false;
    const std::string n = rest.substr(0, dot);
    const std::string encoded = rest.substr(dot + 1);
    char* endp = nullptr;
    unsigned long long parsed = _strtoui64(n.c_str(), &endp, 10);
    if (endp == n.c_str() || *endp != '\0')
        return false;
    offset = static_cast<size_t>(parsed);
    return hex_decode_text(encoded, path);
}

json* json_at_pointer(json& root, const std::string& path)
{
    if (path.empty())
        return nullptr;
    try
    {
        return &root.at(json::json_pointer(path));
    }
    catch (...)
    {
        return nullptr;
    }
}

json page_array_slice(const json& full, size_t offset, size_t limit)
{
    json out = json::array();
    if (!full.is_array())
        return out;
    const size_t total = full.size();
    const size_t end = std::min(total, offset + limit);
    for (size_t i = offset; i < end; ++i)
        out.push_back(full.at(i));
    return out;
}

void cap_nested_arrays(json& node,
                       const std::string& path,
                       size_t limit,
                       const std::string& op,
                       const std::string& generation,
                       json& nested,
                       size_t& capped_count)
{
    if (node.is_array())
    {
        const size_t total = node.size();
        if (total > limit)
        {
            node = page_array_slice(node, 0, limit);
            nested.push_back({{"path", path},
                              {"cursor", nullptr},
                              {"next_cursor", nested_cursor_for(op, generation, path, limit)},
                              {"limit", limit},
                              {"returned", node.size()},
                              {"total_known", total},
                              {"truncated", true}});
            ++capped_count;
        }
        for (size_t i = 0; i < node.size(); ++i)
            cap_nested_arrays(node[i], path + "/" + std::to_string(i), limit, op, generation, nested, capped_count);
        return;
    }
    if (!node.is_object())
        return;
    for (auto it = node.begin(); it != node.end(); ++it)
        cap_nested_arrays(it.value(), path + "/" + pointer_escape(it.key()), limit, op, generation, nested, capped_count);
}

bool apply_nested_pagination(const request_ctx_t& ctx,
                             const std::string& op,
                             json& data,
                             const std::string& default_path,
                             json& page)
{
    const std::string gen = generation_id();
    std::string path = ctx.payload.value("page_path", std::string());
    size_t offset = 0;
    if (!ctx.cursor.empty())
    {
        if (ctx.cursor.rfind("ac2.", 0) == 0)
        {
            if (!parse_nested_cursor(ctx.cursor, op, gen, path, offset))
            {
                page = json::object({{"error", "cursor_expired"}});
                return false;
            }
        }
        else if (!path.empty())
        {
            if (!parse_cursor(ctx.cursor, op, gen, offset))
            {
                page = json::object({{"error", "cursor_expired"}});
                return false;
            }
        }
    }
    if (path.empty())
        path = default_path;
    if (!path.empty())
    {
        json* target = json_at_pointer(data, path);
        if (target == nullptr || !target->is_array())
        {
            page = json::object({{"error", "bad_page_path"}, {"path", path}});
            return false;
        }
        const size_t total = target->size();
        const size_t limit = static_cast<size_t>(ctx.limit);
        *target = page_array_slice(*target, offset, limit);
        const bool truncated = offset + target->size() < total;
        page = page_json(ctx.cursor, truncated ? nested_cursor_for(op, gen, path, offset + target->size()) : std::string(), ctx.limit, target->size(), truncated);
        page["path"] = path;
        page["total_known"] = total;
        return true;
    }
    json nested = json::array();
    size_t capped_count = 0;
    cap_nested_arrays(data, std::string(), static_cast<size_t>(ctx.limit), op, gen, nested, capped_count);
    page = json::object({{"cursor", ctx.cursor.empty() ? json(nullptr) : json(ctx.cursor)},
                         {"next_cursor", nullptr},
                         {"limit", ctx.limit},
                         {"returned", nullptr},
                         {"truncated", !nested.empty()},
                         {"nested", std::move(nested)}});
    return true;
}

agent_tools::tool_result_t invoke_registered(const std::string& tool_name, const json& params)
{
    return agent_tools::ToolRegistry::instance().execute_tool(tool_name, params);
}

json wrapped_tool_result(const std::string& tool_name, const agent_tools::tool_result_t& r)
{
    json d;
    d["legacy_tool"] = tool_name;
    d["success"] = r.success;
    d["message"] = r.output;
    d["error_code"] = r.error_code.empty() ? json(nullptr) : json(r.error_code);
    d["data"] = r.data.is_null() ? json::object() : r.data;
    return d;
}

json chain_document_from_ctx(const request_ctx_t& ctx);
aida::vuln::chain::budget_limits_t budget_limits_from_ctx(const request_ctx_t& ctx);

json boundary_match_data(const json& payload)
{
    json out;
    out["schema"] = "aida.ida.chain.boundary_match.v1";
    out["verdict"] = "inconclusive";
    out["matches"] = json::array();
    out["mismatches"] = json::array();
    out["counterevidence"] = json::array();
    out["unproven"] = json::array();

    const json producer = payload.value("producer", json::object());
    const json consumer = payload.value("consumer", json::object());
    if (producer.is_object() && consumer.is_object())
    {
        if (producer.contains("postconditions") && consumer.contains("preconditions"))
        {
            const std::string pp = producer["postconditions"].dump();
            const std::string cp = consumer["preconditions"].dump();
            if (pp == cp)
                out["matches"].push_back({{"kind", "postcondition_precondition"}, {"hash", hash_text(pp)}});
            else
                out["mismatches"].push_back({{"kind", "postcondition_precondition"}, {"producer_hash", hash_text(pp)}, {"consumer_hash", hash_text(cp)}});
        }
        if (producer.contains("output") && consumer.contains("input"))
        {
            if (producer["output"] == consumer["input"])
                out["matches"].push_back({{"kind", "output_input"}, {"value", producer["output"]}});
            else
                out["mismatches"].push_back({{"kind", "output_input"}, {"producer", producer["output"]}, {"consumer", consumer["input"]}});
        }
    }

    auto source = payload_location(payload, "source");
    auto sink = payload_location(payload, "sink");
    if (sink)
    {
        json p;
        if (source)
            p["source"] = fmt_ea(*source);
        p["sink"] = fmt_ea(*sink);
        p["max_branches"] = int_param(payload, "max_branches", 64, 1, 1024);
        auto r = invoke_registered("extract_wire_path_constraints", p);
        out["wire_constraints"] = wrapped_tool_result("extract_wire_path_constraints", r);
    }

    if (!out["mismatches"].empty())
    {
        out["verdict"] = "refuted";
        out["counterevidence"] = out["mismatches"];
    }
    else if (!out["matches"].empty())
        out["verdict"] = "confirmed";
    else
        out["unproven"].push_back({{"reason", "no comparable producer/consumer facts were supplied"}});
    return out;
}

json call_edges_from_function(func_t* fn, int max_edges)
{
    json edges = json::array();
    if (!fn)
        return edges;
    func_item_iterator_t fii(fn);
    for (bool ok = fii.first(); ok && static_cast<int>(edges.size()) < max_edges; ok = fii.next_head())
    {
        ea_t item = fii.current();
        xrefblk_t xb;
        for (bool xok = xb.first_from(item, XREF_FAR); xok && static_cast<int>(edges.size()) < max_edges; xok = xb.next_from())
        {
            func_t* callee = get_func(xb.to);
            if (!callee)
                continue;
            json e;
            e["call_ea"] = fmt_ea(item);
            e["callee"] = function_json(callee, false);
            e["xref_type"] = xb.type;
            edges.push_back(e);
        }
    }
    return edges;
}

json trigger_confirm_data(const json& payload)
{
    json out;
    out["schema"] = "aida.ida.chain.trigger_confirm.v1";
    out["verdict"] = "inconclusive";
    out["path"] = json::array();
    out["frontier_exhausted"] = false;
    out["unresolved_edges"] = json::array();
    auto entry = payload_location(payload, "entry");
    if (!entry)
        entry = payload_location(payload, "trigger");
    auto target = payload_location(payload, "target");
    if (!target)
        target = payload_location(payload, "sink");
    if (!target)
    {
        out["failure"] = "target or sink is required";
        return out;
    }
    const int max_depth = int_param(payload, "max_depth", 5, 1, 32);
    const int max_functions = int_param(payload, "max_functions", 512, 1, 20000);
    func_t* target_fn = get_func(*target);
    if (!target_fn)
    {
        out["failure"] = "target is not inside a known function";
        out["target"] = fmt_ea(*target);
        return out;
    }
    if (!entry)
    {
        xrefblk_t xb;
        json callers = json::array();
        for (bool ok = xb.first_to(target_fn->start_ea, XREF_FAR); ok && callers.size() < static_cast<size_t>(max_functions); ok = xb.next_to())
        {
            func_t* caller = get_func(xb.from);
            if (caller)
                callers.push_back({{"call_ea", fmt_ea(xb.from)}, {"caller", function_json(caller, false)}});
        }
        out["candidate_callers"] = callers;
        out["verdict"] = callers.empty() ? "inconclusive" : "confirmed";
        out["rationale"] = callers.empty() ? "no static callers found inside the current IDB budget" : "static caller evidence found";
        return out;
    }
    func_t* entry_fn = get_func(*entry);
    if (!entry_fn)
    {
        out["failure"] = "entry is not inside a known function";
        out["entry"] = fmt_ea(*entry);
        return out;
    }
    struct node_t { ea_t fn; std::vector<ea_t> path; int depth; };
    std::vector<node_t> queue;
    std::set<ea_t> seen;
    queue.push_back({entry_fn->start_ea, {entry_fn->start_ea}, 0});
    seen.insert(entry_fn->start_ea);
    size_t head = 0;
    while (head < queue.size() && seen.size() <= static_cast<size_t>(max_functions))
    {
        node_t cur = queue[head++];
        if (cur.fn == target_fn->start_ea)
        {
            out["verdict"] = "confirmed";
            for (ea_t ea : cur.path)
                out["path"].push_back(fmt_ea(ea));
            return out;
        }
        if (cur.depth >= max_depth)
            continue;
        func_t* fn = get_func(cur.fn);
        json edges = call_edges_from_function(fn, max_functions);
        for (const auto& e : edges)
        {
            auto callee_ea = parse_location(e["callee"]["address"]);
            if (!callee_ea || seen.find(*callee_ea) != seen.end())
                continue;
            std::vector<ea_t> np = cur.path;
            np.push_back(*callee_ea);
            queue.push_back({*callee_ea, std::move(np), cur.depth + 1});
            seen.insert(*callee_ea);
        }
    }
    out["frontier_exhausted"] = head >= queue.size();
    out["visited_functions"] = seen.size();
    out["verdict"] = "inconclusive";
    out["rationale"] = "no static call path reached the target inside the supplied budget";
    return out;
}

json validation_errors_to_json(const std::vector<aida::vuln::chain::failure_code_t>& failures)
{
    json arr = json::array();
    for (auto f : failures)
        arr.push_back(aida::vuln::chain::failure_code_str(f));
    return arr;
}

aida::vuln::chain::budget_limits_t budget_limits_from_ctx(const request_ctx_t& ctx)
{
    aida::vuln::chain::budget_limits_t limits;
    json b = ctx.budget.is_object() ? ctx.budget : json::object();
    limits.total_timeout_ms = static_cast<uint32_t>(int_param(b, "total_timeout_ms", int_param(ctx.payload, "timeout_ms", static_cast<int>(limits.total_timeout_ms), 100, 600000), 100, 600000));
    limits.solver_timeout_ms = static_cast<uint32_t>(int_param(b, "solver_timeout_ms", static_cast<int>(limits.solver_timeout_ms), 100, 120000));
    limits.max_functions = static_cast<size_t>(int_param(b, "max_functions", static_cast<int>(limits.max_functions), 1, 1000000));
    limits.max_links = static_cast<size_t>(int_param(b, "max_links", static_cast<int>(limits.max_links), 1, 100000));
    limits.max_paths_per_link = static_cast<size_t>(int_param(b, "max_paths_per_link", static_cast<int>(limits.max_paths_per_link), 1, 100000));
    limits.max_branch_obligations = static_cast<size_t>(int_param(b, "max_branch_obligations", static_cast<int>(limits.max_branch_obligations), 1, 100000));
    limits.max_call_obligations = static_cast<size_t>(int_param(b, "max_call_obligations", static_cast<int>(limits.max_call_obligations), 1, 100000));
    limits.max_solver_queries = static_cast<size_t>(int_param(b, "max_solver_queries", static_cast<int>(limits.max_solver_queries), 1, 1000000));
    limits.max_facts = static_cast<size_t>(int_param(b, "max_facts", static_cast<int>(limits.max_facts), 1, 1000000));
    limits.max_report_events = static_cast<size_t>(int_param(b, "max_report_events", static_cast<int>(limits.max_report_events), 1, 1000000));
    return limits;
}

json current_corpus_for_engine(const json& m)
{
    return {
        {"corpus_id", m.value("corpus_id", std::string("current"))},
        {"kind", "binary"},
        {"availability", "loaded"},
        {"trust", "ida_extracted"},
        {"chain_critical", true},
        {"identity", m}
    };
}

json current_corpus_for_engine()
{
    return current_corpus_for_engine(module_identity());
}

json chain_document_from_ctx(const request_ctx_t& ctx, const json& module_override)
{
    if (ctx.payload.contains("chain") && ctx.payload["chain"].is_object())
        return ctx.payload["chain"];
    json doc;
    doc["schema"] = kChainSchema;
    doc["chain_id"] = ctx.payload.value("chain_id", std::string("chain:" + ctx.request_id));
    doc["title"] = "AiDA MCP shorthand chain request";
    doc["corpus"] = json::array({current_corpus_for_engine(module_override.is_object() ? module_override : module_identity())});
    json link;
    link["link_id"] = ctx.payload.value("link_id", std::string("link:0"));
    link["role"] = "transition";
    if (ctx.payload.contains("source"))
        link["source"] = ctx.payload["source"];
    if (ctx.payload.contains("sink"))
        link["sink"] = ctx.payload["sink"];
    link["metadata"] = {{"mcp_shorthand", true}};
    doc["links"] = json::array({link});
    json objective;
    objective["contract_id"] = "objective:source_to_sink";
    objective["dimension"] = "final_objective";
    objective["subject"] = "chain";
    objective["predicate"] = "source_reaches_sink";
    objective["required"] = {{"source", ctx.payload.value("source", json(nullptr))}, {"sink", ctx.payload.value("sink", json(nullptr))}, {"achieved", true}};
    objective["proof_state"] = "unknown";
    objective["criticality"] = "objective_critical";
    doc["objectives"] = json::array({objective});
    return doc;
}

json chain_document_from_ctx(const request_ctx_t& ctx)
{
    return chain_document_from_ctx(ctx, module_identity());
}

json strict_chain_validation_data(const json& chain)
{
    json out;
    out["schema"] = "aida.ida.chain.validation.v2";
    out["valid"] = false;
    out["errors"] = json::array();
    out["warnings"] = json::array();
    out["normalized"] = json::object();
    out["engine_normalized"] = json::object();

    aida::vuln::chain::parse_chain_document_result_t parsed = aida::vuln::chain::parse_chain_document(chain);
    out["valid"] = parsed.ok;
    out["migrated"] = parsed.migrated;
    out["schema_validation"] = aida::vuln::chain::to_json(parsed.validation);
    out["normalized"] = parsed.normalized;
    if (!parsed.validation.errors.empty())
    {
        for (const auto& e : parsed.validation.errors)
            out["errors"].push_back(aida::vuln::chain::to_json(e));
    }

    aida::vuln::chain::verification_document_t normalized;
    std::vector<aida::vuln::chain::failure_code_t> failures;
    std::string error;
    bool engine_ok = aida::vuln::chain::engine().normalize_document(chain, normalized, failures, error);
    out["engine_valid"] = engine_ok;
    out["engine_failures"] = validation_errors_to_json(failures);
    out["engine_error"] = error.empty() ? json(nullptr) : json(error);
    if (engine_ok)
        out["engine_normalized"] = aida::vuln::chain::to_json(normalized);
    if (!engine_ok && out["errors"].empty())
        out["errors"].push_back({{"code", "engine_normalization_failed"}, {"message", error}, {"failures", validation_errors_to_json(failures)}, {"acceptance_blocker", true}});
    out["valid"] = parsed.ok && engine_ok;
    return out;
}

json chain_validation_data(const json& chain)
{
    return strict_chain_validation_data(chain);
}

json build_chain_report(const request_ctx_t& ctx,
                        const std::string& job_id,
                        const json& module_override = json(),
                        const std::string& generation_override = std::string())
{
    json chain = chain_document_from_ctx(ctx, module_override);
    json validation = strict_chain_validation_data(chain);
    aida::vuln::chain::verification_request_t request;
    request.document = chain;
    request.limits = budget_limits_from_ctx(ctx);
    request.capture_idb_snapshot = module_override.is_null() || module_override.empty();
    request.cancellation = cancellation_token_for_job(job_id);
    append_job_event(job_id, "chain_verify_start", {{"chain_id", chain.value("chain_id", std::string())}, {"validation", validation.value("valid", false)}});
    aida::vuln::chain::verification_report_t engine_report = aida::vuln::chain::engine().verify(request);
    json report = aida::vuln::chain::to_json(engine_report);
    report["schema"] = kReportSchema;
    report["version"] = 2;
    report["job_id"] = job_id;
    report["engine"] = "ChainVerificationEngine";
    report["validation"] = validation;
    report["acceptance"] = report.value("verdict", std::string()) == "confirmed" ? "accepted" : (report.value("verdict", std::string()) == "refuted" ? "rejected" : "not_accepted");
    report["confidence"] = report.value("verdict", std::string()) == "confirmed" ? "proven" : "strict_unaccepted";
    report["summary"] = report.value("verdict", std::string()) == "confirmed"
        ? "Chain confirmed by the universal verifier."
        : "Chain was not accepted by the universal verifier.";
    report["phase_status"] = json::array({{{"phase", "validate_spec"}, {"ok", validation.value("valid", false)}, {"details", validation}}});
    report["unproven_critical_facts"] = json::array();
    if (report.contains("failures") && report["failures"].is_array())
    {
        for (const auto& f : report["failures"])
            report["unproven_critical_facts"].push_back({{"failure", f}, {"acceptance_blocker", true}});
    }
    report["first_failure"] = report["unproven_critical_facts"].empty() ? json(nullptr) : report["unproven_critical_facts"].front();
    report["corpus"] = json::array({module_override.is_object() && !module_override.empty() ? module_override : module_identity()});
    report["resource_manifest"] = json::array();
    report["generation_manifest"] = json::array({generation_override.empty() ? generation_id() : generation_override});
    report["budget_manifest"] = aida::vuln::chain::to_json(request.limits);
    if (!report.contains("diagnostics") || !report["diagnostics"].is_object())
        report["diagnostics"] = json::object();
    report["diagnostics"]["legacy_local_report_removed"] = true;
    report["diagnostics"]["verify_engine"] = verify::engine().verdict_summary();
    append_job_event(job_id, "chain_verify_end", {{"verdict", report.value("verdict", std::string())}, {"acceptance", report["acceptance"]}});
    return report;
}

std::string markdown_report(const report_record_t& r)
{
    std::ostringstream ss;
    ss << "# AiDA Chain Verification Report\n\n";
    ss << "- Report: `" << r.report_id << "`\n";
    ss << "- Job: `" << r.job_id << "`\n";
    ss << "- Chain: `" << r.chain_id << "`\n";
    ss << "- Verdict: `" << r.report.value("verdict", std::string("inconclusive")) << "`\n";
    ss << "- Acceptance: `" << r.report.value("acceptance", std::string("not_accepted")) << "`\n\n";
    ss << "## Links\n\n";
    if (r.report.contains("links") && r.report["links"].is_array())
    {
        for (const auto& l : r.report["links"])
        {
            ss << "- `" << l.value("link_id", std::string()) << "` verdict `"
               << l.value("verdict", std::string("inconclusive")) << "`\n";
        }
    }
    return ss.str();
}

json sarif_report(const report_record_t& r)
{
    json sarif;
    sarif["version"] = "2.1.0";
    sarif["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json";
    json run;
    run["tool"]["driver"]["name"] = "AiDA IDA Chain Verifier";
    run["tool"]["driver"]["informationUri"] = "ida://aida-chain";
    run["results"] = json::array();
    if (r.report.contains("links") && r.report["links"].is_array())
    {
        for (const auto& l : r.report["links"])
        {
            if (l.value("verdict", std::string()) == "confirmed")
                continue;
            json res;
            res["ruleId"] = "AIDA_CHAIN_" + l.value("verdict", std::string("INCONCLUSIVE"));
            res["level"] = l.value("verdict", std::string()) == "refuted" ? "error" : "warning";
            res["message"]["text"] = "Chain link " + l.value("link_id", std::string()) + " verdict: " + l.value("verdict", std::string("inconclusive"));
            run["results"].push_back(res);
        }
    }
    sarif["runs"] = json::array({run});
    return sarif;
}

json export_report_data(const report_record_t& r, const std::string& format)
{
    json d;
    d["report_id"] = r.report_id;
    d["format"] = format;
    d["content_hash"] = r.content_hash;
    d["resource"] = resource_for_report(r, format);
    if (format == "json")
        d["content"] = r.report;
    else if (format == "markdown")
        d["content"] = markdown_report(r);
    else if (format == "sarif")
        d["content"] = sarif_report(r);
    return d;
}

bool prepare_async_job_context(request_ctx_t& ctx, agent_tools::tool_result_t& failure)
{
    async_context_capture_t capture = job_runtime().capture_context(ctx);
    if (!capture.ok)
    {
        failure = error_envelope(ctx,
                                 capture.error_code.empty() ? std::string("idb_unavailable") : capture.error_code,
                                 capture.error_message.empty() ? std::string("failed to capture async job context") : capture.error_message,
                                 capture.data);
        return false;
    }
    ctx.payload["_aida_generation"] = capture.data.value("generation", std::string());
    ctx.payload["_aida_project_id"] = capture.data.value("project_id", std::string("default"));
    ctx.payload["_aida_module_identity"] = capture.data.value("module", json::object());
    if (ctx.tool == "ida_chain_manage"
        && (ctx.operation == "submit" || ctx.operation == "start" || ctx.operation == "verify_link")
        && (!ctx.payload.contains("chain") || !ctx.payload["chain"].is_object()))
    {
        ctx.payload["chain"] = chain_document_from_ctx(ctx, ctx.payload["_aida_module_identity"]);
    }
    failure = agent_tools::tool_result_t{};
    return true;
}

agent_tools::tool_result_t enqueue_async_job(request_ctx_t& ctx)
{
    agent_tools::tool_result_t failure;
    if (!prepare_async_job_context(ctx, failure))
        return failure;
    job_create_result_t created = create_job(ctx);
    request_ctx_t job_ctx = ctx;
    job_ctx.job_id = created.job_id;
    if (created.reused)
    {
        return ok_envelope(job_ctx,
                           {{"job", job_to_json(created.snapshot)}, {"reused", true}, {"result", created.snapshot.result}},
                           job_to_json(created.snapshot),
                           json(),
                           json::array(),
                           created.snapshot.resources);
    }
    std::string enqueue_error;
    if (!job_runtime().enqueue(job_ctx, created.job_id, enqueue_error))
    {
        finish_job(created.job_id, "failed", {{"enqueue_error", enqueue_error}}, std::string(), "queue_full", enqueue_error.empty() ? "job queue is full" : enqueue_error);
        auto failed = get_job(created.job_id, project_id_from_ctx(job_ctx));
        return error_envelope(job_ctx,
                              enqueue_error == "runtime_stopping" ? "cancelled" : "rate_limited",
                              enqueue_error.empty() ? "job queue is full" : enqueue_error,
                              {{"job", failed ? job_to_json(*failed) : job_to_json(created.snapshot)}});
    }
    auto queued = get_job(created.job_id, project_id_from_ctx(job_ctx));
    const json job_json = queued ? job_to_json(*queued) : job_to_json(created.snapshot);
    return ok_envelope(job_ctx,
                       {{"queued", true}, {"job_id", created.job_id}, {"job", job_json}},
                       job_json,
                       json(),
                       json::array(),
                       queued ? queued->resources : created.snapshot.resources);
}

bool json_contains_evidence(const json& node, const std::string& evidence_id, const std::string& address, json& out)
{
    if (node.is_object())
    {
        bool match = false;
        if (!evidence_id.empty())
        {
            for (const char* key : {"evidence_id", "fact_id", "link_id", "report_id", "job_id"})
            {
                if (node.contains(key) && node[key].is_string() && node[key].get<std::string>() == evidence_id)
                    match = true;
            }
        }
        if (!address.empty())
        {
            for (const char* key : {"ea", "address", "source", "sink", "comparison_ea"})
            {
                if (node.contains(key) && node[key].is_string() && node[key].get<std::string>() == address)
                    match = true;
            }
            if (node.contains("cited_eas") && node["cited_eas"].is_array())
            {
                for (const auto& ea : node["cited_eas"])
                {
                    if (ea.is_string() && ea.get<std::string>() == address)
                        match = true;
                }
            }
        }
        if (match)
        {
            out = node;
            return true;
        }
        for (auto it = node.begin(); it != node.end(); ++it)
        {
            if (json_contains_evidence(it.value(), evidence_id, address, out))
                return true;
        }
    }
    else if (node.is_array())
    {
        for (const auto& item : node)
        {
            if (json_contains_evidence(item, evidence_id, address, out))
                return true;
        }
    }
    return false;
}

const std::vector<operation_meta_t>& chain_ops()
{
    static const std::vector<operation_meta_t> ops = {
        {"capabilities", "Return chain verifier operations, payload schemas, examples, metadata, and error codes.", true, false, true, false, "schema", 500, 2000, {}, {}, false},
        {"validate_spec", "Validate and normalize an aida_chain_document_v2 chain specification.", true, false, true, false, "none", 1000, 5000, {}, {{"chain", "object", true, {}}}, false},
        {"submit", "Validate, verify, ledger, and report a chain verification request.", false, false, false, true, "ledger", 120000, 600000, {"taint_engine", "symbolic_engine", "smt_solver"}, {{"chain", "object", false, {}}, {"chain_id", "string", false, {}}, {"source", "location", false, {}}, {"sink", "location", false, {}}, {"timeout_ms", "number", false, {}}}, true},
        {"start", "Alias for submit with job semantics.", false, false, false, true, "ledger", 120000, 600000, {"taint_engine", "symbolic_engine", "smt_solver"}, {{"chain", "object", false, {}}, {"chain_id", "string", false, {}}, {"source", "location", false, {}}, {"sink", "location", false, {}}, {"timeout_ms", "number", false, {}}}, true},
        {"status", "Return verifier engine status or one chain job status.", true, false, false, false, "none", 500, 2000, {}, {{"job_id", "string", false, {}}}, false},
        {"cancel", "Cancel one chain job when job_id is supplied, otherwise cancel plugin-owned chain jobs through their job tokens.", false, false, false, false, "job_state", 500, 2000, {}, {{"job_id", "string", false, {}}}, false},
        {"resume", "Resume a cancelled or failed chain job from its saved request payload.", false, false, false, true, "ledger", 120000, 600000, {"taint_engine", "symbolic_engine", "smt_solver"}, {{"job_id", "string", true, {}}}, false},
        {"export", "Export a chain report by report_id or job_id in json, markdown, or sarif format.", true, false, true, false, "report", 1000, 10000, {}, {{"report_id", "string", false, {}}, {"job_id", "string", false, {}}, {"format", "string", false, {"json", "markdown", "sarif"}}}, false},
        {"verify_link", "Verify a source-to-sink link through the strict chain verifier without modal UI.", false, false, false, true, "verdict_cache", 5000, 60000, {"chain_verification_engine"}, {{"source", "location", true, {}}, {"sink", "location", true, {}}, {"timeout_ms", "number", false, {}}, {"link_id", "string", false, {}}}, false},
        {"boundary_match", "Compare producer and consumer facts and extract wire constraints where source/sink are supplied.", true, false, true, false, "none", 1000, 30000, {"symbolic_engine"}, {{"producer", "object", false, {}}, {"consumer", "object", false, {}}, {"source", "location", false, {}}, {"sink", "location", false, {}}, {"max_branches", "number", false, {}}}, false},
        {"trigger_confirm", "Confirm or refute a bounded static trigger path from entry/trigger to target/sink.", true, false, true, false, "none", 2000, 30000, {"cfg_engine"}, {{"entry", "location", false, {}}, {"trigger", "location", false, {}}, {"target", "location", false, {}}, {"sink", "location", false, {}}, {"max_depth", "number", false, {}}, {"max_functions", "number", false, {}}}, false},
        {"get_report", "Fetch a stored chain verification report.", true, false, true, false, "report", 1000, 10000, {}, {{"report_id", "string", false, {}}, {"job_id", "string", false, {}}}, false},
        {"list", "List stored chain reports and verification jobs.", true, false, false, false, "report", 1000, 10000, {}, {{"verdict", "string", false, {"confirmed", "refuted", "timeout", "inconclusive", "unsupported"}}, {"include_jobs", "boolean", false, {}}}, false},
        {"evidence_fetch", "Fetch cited evidence from a stored report by evidence_id, link_id, fact_id, job_id, report_id, or address.", true, false, true, false, "report", 1000, 10000, {}, {{"report_id", "string", false, {}}, {"job_id", "string", false, {}}, {"evidence_id", "string", false, {}}, {"address", "location", false, {}}}, false},
        {"explain_failure", "Return the first failure, unproven critical facts, refutations, and counterevidence for a report.", true, false, true, false, "report", 1000, 10000, {}, {{"report_id", "string", false, {}}, {"job_id", "string", false, {}}}, false},
        {"diagnostics", "Return chain verifier engine, ledger, job, index, and modal-safety diagnostics.", true, false, false, false, "none", 1000, 10000, {}, {}, false}
    };
    return ops;
}

const std::vector<operation_meta_t>& project_ops()
{
    static const std::vector<operation_meta_t> ops = {
        {"capabilities", "Return project, corpus, and index operation schemas.", true, false, true, false, "schema", 500, 2000, {}, {}, false},
        {"inventory_current", "Return deterministic current-IDB inventory with module identity, hashes, segments, imports, entries, and counts.", true, false, true, false, "none", 500, 5000, {}, {{"include_segments", "boolean", false, {}}, {"include_imports", "boolean", false, {}}, {"include_entries", "boolean", false, {}}, {"max_rows", "number", false, {}}}, false},
        {"inventory_all", "Return local inventory merged with MCP-router fanout results when called over MCP, or with supplied inventory documents for direct in-process callers.", true, false, false, false, "none", 1000, 30000, {}, {{"include_segments", "boolean", false, {}}, {"include_imports", "boolean", false, {}}, {"include_entries", "boolean", false, {}}, {"max_rows", "number", false, {}}, {"fanout_result", "object", false, {}}, {"inventories", "array", false, {}}}, true},
        {"list", "List durable multibinary projects under the IDA user directory.", true, false, true, false, "project", 500, 5000, {}, {}, false},
        {"load", "Load one durable project manifest and module records.", true, false, true, false, "project", 500, 10000, {}, {{"project_id", "string", true, {}}}, false},
        {"save", "Create or update a durable project from supplied module records or inventory/fanout data.", false, false, false, true, "project", 1000, 60000, {}, {{"project_id", "string", false, {}}, {"modules", "array", false, {}}, {"fanout_result", "object", false, {}}, {"inventories", "array", false, {}}, {"force_lock", "boolean", false, {}}}, true},
        {"delete", "Delete one durable project after explicit confirmation.", false, true, false, false, "project", 1000, 30000, {}, {{"project_id", "string", true, {}}, {"confirm_destructive", "boolean", true, {}}, {"reason", "string", true, {}}}, false},
        {"status", "Return durable project manifest, cache, generation, stale-state, and cross-edge readiness.", true, false, false, false, "project", 500, 10000, {}, {{"project_id", "string", false, {}}}, false},
        {"corpus_snapshot", "Return a durable project manifest when project_id is supplied, otherwise the current module corpus record.", true, false, true, false, "corpus", 500, 5000, {}, {{"project_id", "string", false, {}}}, false},
        {"corpus_bind", "Bind supplied modules, inventories, fanout responses, and the current module into a durable multibinary project.", false, false, false, false, "corpus", 1000, 60000, {}, {{"modules", "array", false, {}}, {"project_id", "string", false, {}}, {"corpus_id", "string", false, {}}, {"role", "string", false, {}}, {"fanout_result", "object", false, {}}, {"inventories", "array", false, {}}, {"force_lock", "boolean", false, {}}}, true},
        {"corpus_export", "Export a durable project manifest or the current in-memory compatibility corpus manifest.", true, false, true, false, "corpus", 500, 5000, {}, {{"format", "string", false, {"json"}}, {"project_id", "string", false, {}}}, false},
        {"index_build", "Build durable module identity, import/export, function, local-edge, netnode, and cross-edge indexes for the current IDB.", false, false, false, true, "index", 30000, 600000, {}, {{"project_id", "string", false, {}}, {"indices", "array", false, {}}, {"force", "boolean", false, {}}, {"max_functions", "number", false, {}}, {"max_edges", "number", false, {}}, {"max_imports", "number", false, {}}, {"max_exports", "number", false, {}}}, false},
        {"index_status", "Return durable index readiness, generation, stale-state, and cross-edge diagnostics.", true, false, false, false, "index", 500, 5000, {}, {{"project_id", "string", false, {}}, {"indices", "array", false, {}}}, false},
        {"index_page_status", "Return durable page manifests for function, xref, signature, dispatch, callback, global, import/export, summary, and cross-edge indexes.", true, false, false, false, "index", 500, 10000, {}, {{"project_id", "string", false, {}}, {"module_id", "string", false, {}}}, false},
        {"index_page", "Load one durable index page by family/module/page_index or by returned cursor.", true, false, true, false, "index", 500, 30000, {}, {{"project_id", "string", false, {}}, {"module_id", "string", false, {}}, {"family", "string", false, {}}, {"cursor", "string", false, {}}, {"page_index", "number", false, {}}}, false},
        {"resolve_cross_edges", "Resolve and persist the project cross-module import/export/forwarder graph.", false, false, false, true, "index", 1000, 120000, {}, {{"project_id", "string", false, {}}}, false},
        {"resolve_reference", "Resolve one module/name, module/ordinal, import, or module_id+rva reference through the durable project graph.", true, false, true, false, "index", 1000, 30000, {}, {{"project_id", "string", false, {}}, {"reference", "object", true, {}}}, false},
        {"verify_chain", "Verify a chain against durable project modules, normalized addresses, cross edges, and link boundary facts with fail-closed confirmation rules.", false, false, false, true, "project_verifier", 5000, 600000, {}, {{"project_id", "string", false, {}}, {"chain", "object", true, {}}, {"options", "object", false, {}}}, true},
        {"case_study_regressions", "Run source-backed NTFS/AFD/pvScan0 project semantics over supplied chain/source evidence without synthetic passes.", false, false, false, true, "project_verifier", 5000, 600000, {}, {{"project_id", "string", false, {}}, {"chain", "object", false, {}}, {"source_checks", "array", false, {}}, {"options", "object", false, {}}}, true}
    };
    return ops;
}

const std::vector<operation_meta_t>& extract_ops()
{
    static const std::vector<operation_meta_t> ops = {
        {"capabilities", "Return extraction and evidence operation schemas.", true, false, true, false, "schema", 500, 2000, {}, {}, false},
        {"functions", "List functions with cursor pagination.", true, false, true, false, "none", 1000, 5000, {}, {{"filter", "string", false, {}}, {"include_segments", "boolean", false, {}}}, false},
        {"function", "Fetch normalized function metadata by address.", true, false, true, false, "none", 1000, 5000, {}, {{"address", "location", true, {}}, {"include_xrefs", "boolean", false, {}}}, false},
        {"instructions", "Fetch paginated disassembly rows for a function.", true, false, true, false, "none", 1000, 10000, {}, {{"address", "location", true, {}}}, false},
        {"xrefs", "Fetch code/data xrefs to or from an address.", true, false, true, false, "none", 1000, 10000, {}, {{"address", "location", true, {}}, {"direction", "string", false, {"to", "from", "both"}}, {"kind", "string", false, {"code", "data", "all"}}}, false},
        {"bytes", "Read bytes from the database with max-byte budget.", true, false, true, false, "none", 500, 5000, {}, {{"address", "location", true, {}}, {"size", "number", true, {}}}, false},
        {"decompile", "Return Hex-Rays pseudocode through the existing non-wait decompiler helper.", true, false, false, false, "none", 1000, 30000, {}, {{"address", "location", true, {}}}, false},
        {"imports", "List imports with pagination.", true, false, true, false, "none", 1000, 10000, {}, {}, false},
        {"exports", "List entry/export records with pagination.", true, false, true, false, "none", 1000, 10000, {}, {}, false},
        {"segments", "List IDA segments and permissions.", true, false, true, false, "none", 500, 5000, {}, {}, false},
        {"corpus_snapshot", "Return module and corpus identity adjacent to extraction results.", true, false, true, false, "none", 500, 5000, {}, {}, false},
        {"extract_module_facts", "Return normalized module, segment, entry, import, function index, full mapped-item xref index, resolver index, and cache facts.", true, false, true, false, "extraction_cache", 1000, 30000, {}, {{"layers", "array", false, {}}, {"maturities", "array", false, {}}, {"force_refresh", "boolean", false, {}}, {"max_functions", "number", false, {}}, {"max_module_items", "number", false, {}}, {"max_xrefs_per_address", "number", false, {}}, {"page_path", "string", false, {}}}, true},
        {"extract_function_facts", "Return normalized raw, CFG, xref, type, ctree, microcode, side-effect, and cache facts for one function.", true, false, true, false, "extraction_cache", 2000, 60000, {}, {{"address", "location", true, {}}, {"layers", "array", false, {}}, {"maturities", "array", false, {}}, {"force_refresh", "boolean", false, {}}, {"max_instructions", "number", false, {}}, {"max_basic_blocks", "number", false, {}}, {"max_ctree_nodes", "number", false, {}}, {"max_microcode_instructions", "number", false, {}}, {"page_path", "string", false, {}}}, true},
        {"extract_function_batch", "Return a cancellable bounded batch of normalized function facts.", true, false, true, false, "extraction_cache", 5000, 120000, {}, {{"functions", "array", false, {}}, {"layers", "array", false, {}}, {"maturities", "array", false, {}}, {"force_refresh", "boolean", false, {}}, {"max_functions", "number", false, {}}, {"timeout_ms", "number", false, {}}, {"page_path", "string", false, {}}}, true},
        {"extract_xref_graph", "Return normalized xref indexes and cross-function/module reachability evidence around a function or address.", true, false, true, false, "extraction_cache", 2000, 60000, {}, {{"address", "location", true, {}}, {"target", "location", false, {}}, {"layers", "array", false, {}}, {"direction", "string", false, {"to", "from", "both"}}, {"max_depth", "number", false, {}}, {"max_functions", "number", false, {}}, {"modules", "array", false, {}}, {"page_path", "string", false, {}}}, true},
        {"extract_path_window", "Return a normalized path corridor between entry and target inside one function.", true, false, true, false, "extraction_cache", 2000, 60000, {}, {{"entry", "location", true, {}}, {"target", "location", true, {}}, {"layers", "array", false, {}}, {"max_blocks", "number", false, {}}, {"max_steps", "number", false, {}}, {"page_path", "string", false, {}}}, true},
        {"extract_type_facts", "Return normalized function type, stack, local, argument, UDT, enum, and dependency facts.", true, false, true, false, "extraction_cache", 1000, 30000, {}, {{"address", "location", true, {}}, {"force_refresh", "boolean", false, {}}, {"page_path", "string", false, {}}}, true},
        {"resolve_cross_binary", "Resolve a module/RVA, import/export, public symbol, thunk, or controlled target against supplied module fact stores.", true, false, true, false, "extraction_cache", 1000, 30000, {}, {{"reference", "object", true, {}}, {"modules", "array", false, {}}, {"include_current_module", "boolean", false, {}}, {"max_module_items", "number", false, {}}, {"page_path", "string", false, {}}}, true},
        {"case_study_self_check", "Run source-backed extraction self-checks for NTFS/ETW zero-vs-copy, ETW trigger negative evidence, AFD LIST_ENTRY guard, or pvScan0 self-reference classes.", true, false, true, false, "extraction_cache", 2000, 60000, {}, {{"case_id", "string", false, {"all", "ntfs_etw_zero_vs_copy", "etw_trigger_negative", "afd_list_entry_guard", "pvscan0_self_reference"}}, {"address", "location", false, {}}, {"entry", "location", false, {}}, {"target", "location", false, {}}, {"modules", "array", false, {}}, {"max_depth", "number", false, {}}, {"max_functions", "number", false, {}}, {"page_path", "string", false, {}}}, true},
        {"extraction_cache_status", "Return extraction cache counters and storage status.", true, false, true, false, "extraction_cache", 500, 5000, {}, {}, false},
        {"invalidate_extraction_cache", "Clear plugin-owned extraction cache storage.", false, true, true, false, "none", 500, 10000, {}, {{"confirm_destructive", "boolean", true, {}}, {"reason", "string", true, {}}}, false},
        {"evidence_fetch", "Fetch evidence from reports or address-local function/xref context.", true, false, true, false, "report", 1000, 10000, {}, {{"report_id", "string", false, {}}, {"job_id", "string", false, {}}, {"evidence_id", "string", false, {}}, {"address", "location", false, {}}}, false}
    };
    return ops;
}

const std::vector<operation_meta_t>& report_ops()
{
    static const std::vector<operation_meta_t> ops = {
        {"capabilities", "Return report and ledger operation schemas.", true, false, true, false, "schema", 500, 2000, {}, {}, false},
        {"list_reports", "List stored chain verification reports.", true, false, false, false, "report", 1000, 10000, {}, {{"verdict", "string", false, {"confirmed", "refuted", "timeout", "inconclusive", "unsupported"}}}, false},
        {"get_report", "Get a stored report by report_id or job_id.", true, false, true, false, "report", 1000, 10000, {}, {{"report_id", "string", false, {}}, {"job_id", "string", false, {}}}, false},
        {"export_report", "Export a stored report in json, markdown, or sarif.", true, false, true, false, "report", 1000, 10000, {}, {{"report_id", "string", false, {}}, {"job_id", "string", false, {}}, {"format", "string", false, {"json", "markdown", "sarif"}}}, false},
        {"evidence_fetch", "Fetch report evidence by evidence_id or address.", true, false, true, false, "report", 1000, 10000, {}, {{"report_id", "string", false, {}}, {"job_id", "string", false, {}}, {"evidence_id", "string", false, {}}, {"address", "location", false, {}}}, false},
        {"ledger_status", "Return verifier ledger summary.", true, false, false, false, "ledger", 500, 5000, {}, {}, false},
        {"ledger_save", "Persist verifier ledger through the existing netnode-backed engine path.", false, false, false, false, "ledger", 1000, 10000, {}, {}, false},
        {"ledger_load", "Load verifier ledger through the existing netnode-backed engine path.", false, false, false, false, "ledger", 1000, 10000, {}, {}, false},
        {"ledger_clear", "Clear verifier ledger through the existing engine path.", false, true, false, false, "ledger", 1000, 10000, {}, {{"confirm_destructive", "boolean", true, {}}, {"reason", "string", true, {}}}, false}
    };
    return ops;
}

const std::vector<operation_meta_t>& job_ops()
{
    static const std::vector<operation_meta_t> ops = {
        {"capabilities", "Return job and diagnostics operation schemas.", true, false, true, false, "schema", 500, 2000, {}, {}, false},
        {"list", "List plugin-owned jobs.", true, false, false, false, "job_state", 1000, 10000, {}, {{"state", "string", false, {"queued", "running", "cancelling", "completed", "cancelled", "failed"}}}, false},
        {"status", "Return one job status.", true, false, false, false, "job_state", 500, 5000, {}, {{"job_id", "string", true, {}}}, false},
        {"result", "Return one job result with report resources.", true, false, true, false, "job_state", 1000, 10000, {}, {{"job_id", "string", true, {}}, {"page_path", "string", false, {}}}, true},
        {"events", "Return one job event ring.", true, false, true, false, "job_state", 1000, 10000, {}, {{"job_id", "string", true, {}}}, false},
        {"cancel", "Cancel one plugin-owned job through its job runtime token.", false, false, false, false, "job_state", 500, 5000, {}, {{"job_id", "string", true, {}}}, false},
        {"resume", "Resume a chain job from stored request data.", false, false, false, true, "job_state", 1000, 600000, {}, {{"job_id", "string", true, {}}}, false},
        {"diagnostics", "Return job counts, report counts, engine status, index state, and modal-safety evidence.", true, false, false, false, "diagnostics", 1000, 10000, {}, {}, false},
        {"prune", "Prune inactive jobs older than a supplied age.", false, true, false, false, "job_state", 1000, 10000, {}, {{"older_than_ms", "number", false, {}}, {"state", "string", false, {"completed", "cancelled", "failed", "all"}}}, false}
    };
    return ops;
}

const std::vector<operation_meta_t>& discover_ops()
{
    static const std::vector<operation_meta_t> ops = {
        {"capabilities", "Return discovery operation schemas.", true, false, true, false, "schema", 500, 2000, {}, {}, false},
        {"catalog", "Return the compact public MCP catalog with legacy compatibility counts.", true, false, false, false, "registry", 500, 5000, {}, {}, false},
        {"resources", "List MCP resources and templates emitted by the plugin.", true, false, false, false, "resources", 500, 5000, {}, {}, false},
        {"instances", "Return live IDA instance routing inventory.", true, false, false, false, "instances", 1000, 10000, {}, {}, false},
        {"module", "Return current module identity and binary metadata.", true, false, false, false, "module", 500, 5000, {}, {}, false},
        {"modules", "List and analyze static IDB modules plus dynamic debugger-exposed process modules.", true, false, false, false, "module_re", 1000, 30000, {}, {{"mode", "string", false, {"static", "dynamic", "both"}}, {"analysis", "string", false, {"list", "details", "analyze"}}, {"module", "string", false, {}}, {"module_id", "string", false, {}}, {"name", "string", false, {}}, {"path", "string", false, {}}, {"selector", "object", false, {}}, {"address", "location", false, {}}, {"base", "location", false, {}}, {"detail", "boolean", false, {}}, {"include_segments", "boolean", false, {}}, {"include_imports", "boolean", false, {}}, {"include_exports", "boolean", false, {}}, {"include_functions", "boolean", false, {}}, {"max_rows", "number", false, {}}, {"max_modules", "number", false, {}}, {"max_segments", "number", false, {}}, {"max_imports", "number", false, {}}, {"max_exports", "number", false, {}}, {"max_functions", "number", false, {}}}, false},
        {"functions", "List functions with cursor pagination.", true, false, true, false, "idb_snapshot", 1000, 30000, {}, {{"filter", "string", false, {}}, {"include_segments", "boolean", false, {}}}, false},
        {"function", "Resolve one function by address.", true, false, true, false, "idb_snapshot", 1000, 10000, {}, {{"address", "location", true, {}}, {"include_xrefs", "boolean", false, {}}}, false},
        {"address", "Resolve one address.", true, false, true, false, "idb_snapshot", 1000, 10000, {}, {{"address", "location", true, {}}}, false},
        {"imports", "List imports with cursor pagination.", true, false, true, false, "idb_snapshot", 1000, 30000, {}, {{"filter", "string", false, {}}}, false},
        {"exports", "List exports with cursor pagination.", true, false, true, false, "idb_snapshot", 1000, 30000, {}, {{"filter", "string", false, {}}}, false},
        {"segments", "List current IDB segments.", true, false, true, false, "idb_snapshot", 1000, 10000, {}, {}, false}
    };
    return ops;
}

const std::vector<operation_meta_t>& analysis_ops()
{
    static const std::vector<operation_meta_t> ops = {
        {"capabilities", "Return analysis operation schemas.", true, false, true, false, "schema", 500, 2000, {}, {}, false},
        {"status", "Return analysis engine readiness and cache state.", true, false, false, false, "diagnostics", 500, 5000, {}, {}, false},
        {"build_index", "Warm one or more analysis indices through the existing index builder.", false, false, false, true, "index", 10000, 600000, {}, {{"indices", "array", false, {}}, {"max_seconds", "number", false, {}}}, true},
        {"function", "Return composite function analysis.", true, false, true, false, "analysis", 2000, 60000, {}, {{"address", "location", true, {}}, {"limit", "number", false, {}}}, false},
        {"batch", "Analyze multiple functions.", true, false, true, false, "analysis", 5000, 120000, {}, {{"functions", "array", false, {}}, {"addrs", "array", false, {}}}, true},
        {"component", "Analyze a component represented by functions.", true, false, true, false, "analysis", 5000, 120000, {}, {{"functions", "array", true, {}}}, true},
        {"control_flow", "Return control-flow analysis for one function.", true, false, true, false, "analysis", 2000, 60000, {"cfg_engine"}, {{"address", "location", true, {}}}, false},
        {"data_flow", "Return local data-flow analysis around one address.", true, false, true, false, "analysis", 2000, 60000, {"taint_engine"}, {{"address", "location", true, {}}, {"max_depth", "number", false, {}}}, false},
        {"callgraph", "Build a bounded call graph.", true, false, true, false, "analysis", 2000, 60000, {"cfg_engine"}, {{"address", "location", true, {}}, {"depth", "number", false, {}}}, false},
        {"taint", "Run taint path analysis.", true, false, false, true, "analysis", 5000, 120000, {"taint_engine"}, {{"max_paths", "number", false, {}}}, true},
        {"vulnerability", "Run a named vulnerability analysis tool through the consolidated analysis surface.", true, false, false, true, "analysis", 5000, 120000, {"taint_engine", "microcode_engine", "cfg_engine"}, {{"tool", "string", true, {}}, {"arguments", "object", false, {}}}, true}
    };
    return ops;
}

const std::vector<operation_meta_t>& cache_ops()
{
    static const std::vector<operation_meta_t> ops = {
        {"capabilities", "Return cache operation schemas.", true, false, true, false, "schema", 500, 2000, {}, {}, false},
        {"status", "Return extraction, index, output, and job cache status.", true, false, false, false, "cache", 500, 10000, {}, {}, false},
        {"build", "Build project/index cache pages.", false, false, false, true, "index", 10000, 600000, {}, {{"project_id", "string", false, {}}, {"indices", "array", false, {}}, {"force", "boolean", false, {}}}, true},
        {"index_status", "Return project index status.", true, false, false, false, "index", 500, 10000, {}, {{"project_id", "string", false, {}}}, false},
        {"index_page", "Load one persisted project index page.", true, false, true, false, "index", 1000, 30000, {}, {{"project_id", "string", false, {}}, {"module_id", "string", false, {}}, {"family", "string", false, {}}, {"cursor", "string", false, {}}, {"page_index", "number", false, {}}}, false},
        {"extraction_status", "Return extraction cache counters.", true, false, true, false, "extraction_cache", 500, 5000, {}, {}, false},
        {"invalidate_extraction", "Clear extraction cache.", false, true, true, false, "extraction_cache", 500, 10000, {}, {{"confirm_destructive", "boolean", true, {}}, {"reason", "string", true, {}}}, false},
        {"output_cache", "List, inspect, or evict MCP output cache entries.", false, false, false, false, "output_cache", 500, 10000, {}, {{"op", "string", false, {"list", "stats", "evict"}}, {"output_id", "string", false, {}}, {"all", "boolean", false, {}}}, false},
        {"prune_jobs", "Prune completed job records.", false, true, false, false, "job_state", 500, 10000, {}, {{"older_than_ms", "number", false, {}}, {"state", "string", false, {"completed", "cancelled", "failed", "all"}}}, false}
    };
    return ops;
}

const std::vector<operation_meta_t>& mutation_ops()
{
    static const std::vector<operation_meta_t> ops = {
        {"capabilities", "Return mutation operation schemas.", true, false, true, false, "schema", 500, 2000, {}, {}, false},
        {"preview", "Preview one mutation and return a receipt without modifying the IDB.", true, false, false, false, "idb_snapshot", 1000, 10000, {}, {{"mutation", "object", true, {}}}, true},
        {"batch_preview", "Preview multiple mutations and return receipts without modifying the IDB.", true, false, false, false, "idb_snapshot", 2000, 30000, {}, {{"items", "array", true, {}}}, true},
        {"batch_apply", "Apply multiple confirmed mutations with receipts.", false, true, false, false, "idb_write", 5000, 120000, {}, {{"items", "array", true, {}}, {"confirm_destructive", "boolean", true, {}}, {"reason", "string", true, {}}}, true},
        {"rename_function", "Rename one function with expected-old-name stale checking.", false, true, false, false, "idb_write", 1000, 10000, {}, {{"address", "location", true, {}}, {"new_name", "string", true, {}}, {"expected_old_name", "string", false, {}}, {"confirm_destructive", "boolean", true, {}}, {"reason", "string", true, {}}}, false},
        {"set_function_signature", "Apply one function signature.", false, true, false, false, "idb_write", 1000, 10000, {}, {{"address", "location", true, {}}, {"signature", "string", true, {}}, {"confirm_destructive", "boolean", true, {}}, {"reason", "string", true, {}}}, false},
        {"apply_type", "Apply one type declaration to an address.", false, true, false, false, "idb_write", 1000, 10000, {}, {{"address", "location", true, {}}, {"type", "string", true, {}}, {"confirm_destructive", "boolean", true, {}}, {"reason", "string", true, {}}}, false},
        {"declare_type", "Declare one or more C types in the local type library.", false, true, false, false, "idb_write", 1000, 10000, {}, {{"declaration", "string", true, {}}, {"confirm_destructive", "boolean", true, {}}, {"reason", "string", true, {}}}, false},
        {"set_comment", "Set one address comment with expected-old-comment stale checking.", false, true, false, false, "idb_write", 1000, 10000, {}, {{"address", "location", true, {}}, {"comment", "string", true, {}}, {"repeatable", "boolean", false, {}}, {"expected_old_comment", "string", false, {}}, {"confirm_destructive", "boolean", true, {}}, {"reason", "string", true, {}}}, false},
        {"patch_bytes", "Patch bytes with mandatory expected-old-bytes stale checking.", false, true, false, false, "idb_write", 1000, 10000, {}, {{"address", "location", true, {}}, {"bytes", "string", true, {}}, {"expected_old_bytes", "string", true, {}}, {"confirm_destructive", "boolean", true, {}}, {"reason", "string", true, {}}}, false},
        {"delete_function", "Delete one function with expected-old-name stale checking.", false, true, false, false, "idb_write", 1000, 10000, {}, {{"address", "location", true, {}}, {"expected_old_name", "string", false, {}}, {"confirm_destructive", "boolean", true, {}}, {"reason", "string", true, {}}}, false},
        {"idb_save", "Save the IDB with a destructive receipt.", false, true, false, false, "idb_write", 1000, 60000, {}, {{"path", "string", false, {}}, {"backup", "boolean", false, {}}, {"compact", "boolean", false, {}}, {"confirm_destructive", "boolean", true, {}}, {"reason", "string", true, {}}}, false}
    };
    return ops;
}

const std::vector<operation_meta_t>& diagnostics_ops()
{
    static const std::vector<operation_meta_t> ops = {
        {"capabilities", "Return diagnostics operation schemas.", true, false, true, false, "schema", 500, 2000, {}, {}, false},
        {"health", "Return server and plugin health.", true, false, false, false, "diagnostics", 500, 5000, {}, {}, false},
        {"tool_registry", "Return registry counts, public manage surface, hidden legacy tools, and operation metadata.", true, false, false, false, "registry", 500, 5000, {}, {}, false},
        {"index_status", "Return analysis index readiness.", true, false, false, false, "diagnostics", 500, 5000, {}, {}, false},
        {"jobs", "Return job runtime diagnostics.", true, false, false, false, "diagnostics", 500, 10000, {}, {}, false},
        {"chain", "Return chain verifier diagnostics.", true, false, false, false, "diagnostics", 500, 10000, {}, {}, false},
        {"resources", "Return resource catalog diagnostics.", true, false, false, false, "resources", 500, 5000, {}, {}, false},
        {"self_check", "Return source-owned self-checks for chain schema, report, store, and runtime invariants.", true, false, false, false, "diagnostics", 1000, 10000, {}, {}, false}
    };
    return ops;
}

agent_tools::tool_result_t handle_report_fetch_like(const request_ctx_t& ctx, bool explain_only, bool export_only = false)
{
    std::string report_id = ctx.payload.value("report_id", std::string());
    const std::string job_id = ctx.payload.value("job_id", std::string());
    if (report_id.empty() && !job_id.empty())
    {
        auto job = get_job(job_id, project_id_from_ctx(ctx));
        if (!job)
            return error_envelope(ctx, "job_not_found", "job_id was not found", {{"job_id", job_id}});
        report_id = job->report_id;
    }
    if (report_id.empty())
        return error_envelope(ctx, "bad_param", "report_id or job_id is required", {{"required", json::array({"report_id", "job_id"})}});
    auto rec = get_report_record(report_id, project_id_from_ctx(ctx));
    if (!rec)
        return error_envelope(ctx, "job_not_found", "report_id was not found", {{"report_id", report_id}});
    json resources = json::array({resource_for_report(*rec, "json"), resource_for_report(*rec, "markdown"), resource_for_report(*rec, "sarif")});
    if (export_only)
    {
        std::string fmt = ctx.payload.value("format", std::string("json"));
        return ok_envelope(ctx, export_report_data(*rec, fmt), json(), json(), json::array(), json::array({resource_for_report(*rec, fmt)}));
    }
    if (explain_only)
    {
        json d;
        d["report_id"] = rec->report_id;
        d["verdict"] = rec->report.value("verdict", std::string("inconclusive"));
        d["acceptance"] = rec->report.value("acceptance", std::string("not_accepted"));
        d["first_failure"] = rec->report.value("first_failure", json(nullptr));
        d["unproven_critical_facts"] = rec->report.value("unproven_critical_facts", json::array());
        d["boundaries"] = rec->report.value("boundaries", json::array());
        d["links"] = rec->report.value("links", json::array());
        return ok_envelope(ctx, d, json(), json(), json::array(), resources);
    }
    json d;
    d["report"] = rec->report;
    d["content_hash"] = rec->content_hash;
    return ok_envelope(ctx, d, json(), json(), json::array(), resources);
}

agent_tools::tool_result_t handle_evidence_fetch(const request_ctx_t& ctx)
{
    std::string report_id = ctx.payload.value("report_id", std::string());
    const std::string job_id = ctx.payload.value("job_id", std::string());
    if (report_id.empty() && !job_id.empty())
    {
        auto job = get_job(job_id, project_id_from_ctx(ctx));
        if (!job)
            return error_envelope(ctx, "job_not_found", "job_id was not found", {{"job_id", job_id}});
        report_id = job->report_id;
    }
    const std::string evidence_id = ctx.payload.value("evidence_id", std::string());
    std::string address;
    if (ctx.payload.contains("address"))
    {
        auto ea = payload_location(ctx.payload, "address");
        if (ea)
            address = fmt_ea(*ea);
        else if (ctx.payload["address"].is_string())
            address = ctx.payload["address"].get<std::string>();
    }
    if (!report_id.empty())
    {
        auto rec = get_report_record(report_id, project_id_from_ctx(ctx));
        if (!rec)
            return error_envelope(ctx, "job_not_found", "report_id was not found", {{"report_id", report_id}});
        json found;
        if (!json_contains_evidence(rec->report, evidence_id, address, found))
            return error_envelope(ctx, "bad_param", "evidence was not found in report", {{"report_id", report_id}, {"evidence_id", evidence_id}, {"address", address}});
        return ok_envelope(ctx, {{"evidence", found}, {"report_id", report_id}});
    }
    if (!address.empty())
    {
        json d;
        auto ea = agent_tools::helpers::parse_address(address);
        if (!ea)
            return error_envelope(ctx, "bad_param", "address is invalid", {{"address", address}});
        d["address"] = fmt_ea(*ea);
        func_t* fn = get_func(*ea);
        d["function"] = fn ? function_json(fn, true) : json(nullptr);
        json xp = {{"address", fmt_ea(*ea)}, {"direction", "both"}, {"kind", "all"}};
        request_ctx_t nested = ctx;
        nested.operation = "xrefs";
        nested.payload = xp;
        d["xrefs"] = json::object();
        xrefblk_t xb;
        json to = json::array();
        for (bool ok = xb.first_to(*ea, XREF_ALL); ok; ok = xb.next_to())
            to.push_back({{"from", fmt_ea(xb.from)}, {"to", fmt_ea(xb.to)}, {"type", xb.type}, {"iscode", xb.iscode != 0}});
        json from = json::array();
        for (bool ok = xb.first_from(*ea, XREF_ALL); ok; ok = xb.next_from())
            from.push_back({{"from", fmt_ea(xb.from)}, {"to", fmt_ea(xb.to)}, {"type", xb.type}, {"iscode", xb.iscode != 0}});
        d["xrefs"]["to"] = to;
        d["xrefs"]["from"] = from;
        return ok_envelope(ctx, d);
    }
    return error_envelope(ctx, "bad_param", "report_id/job_id plus evidence_id, or address, is required");
}

agent_tools::tool_result_t handle_chain_manage(const json& params)
{
    agent_tools::tool_result_t failure;
    request_ctx_t ctx = parse_request("ida_chain_manage", params, chain_ops(), failure);
    if (!failure.output.empty() || !failure.data.is_null())
        return failure;
    if (ctx.operation == "capabilities")
        return ok_envelope(ctx, make_capabilities(ctx.tool, chain_ops()));
    if (ctx.operation == "validate_spec")
        return ok_envelope(ctx, chain_validation_data(ctx.payload["chain"]));
    if (ctx.operation == "status")
    {
        const std::string job_id = ctx.payload.value("job_id", std::string());
        if (!job_id.empty())
        {
            auto job = get_job(job_id, project_id_from_ctx(ctx));
            if (!job)
                return error_envelope(ctx, "job_not_found", "job_id was not found", {{"job_id", job_id}});
            return ok_envelope(ctx, {{"job", job_to_json(*job)}, {"result_available", !job->result.is_null() && !job->result.empty()}}, job_to_json(*job));
        }
        return ok_envelope(ctx, {{"engine", verify::engine().verdict_summary()}});
    }
    if (ctx.operation == "cancel")
    {
        const std::string job_id = ctx.payload.value("job_id", std::string());
        if (!job_id.empty())
        {
            if (!get_job(job_id, project_id_from_ctx(ctx)))
                return error_envelope(ctx, "job_not_found", "job_id was not found", {{"job_id", job_id}});
            if (!cancel_job_record(job_id))
                return error_envelope(ctx, "job_not_found", "job_id was not found", {{"job_id", job_id}});
            auto job = get_job(job_id, project_id_from_ctx(ctx));
            return ok_envelope(ctx, {{"cancelled", true}, {"job", job ? job_to_json(*job) : json::object()}}, job ? job_to_json(*job) : json());
        }
        return ok_envelope(ctx, cancel_all_job_records());
    }
    if (ctx.operation == "verify_link")
        return enqueue_async_job(ctx);
    if (ctx.operation == "boundary_match")
        return ok_envelope(ctx, boundary_match_data(ctx.payload));
    if (ctx.operation == "trigger_confirm")
        return ok_envelope(ctx, trigger_confirm_data(ctx.payload));
    if (ctx.operation == "submit" || ctx.operation == "start")
        return enqueue_async_job(ctx);
    if (ctx.operation == "resume")
    {
        const std::string job_id = ctx.payload.value("job_id", std::string());
        auto job = get_job(job_id, project_id_from_ctx(ctx));
        if (!job)
            return error_envelope(ctx, "job_not_found", "job_id was not found", {{"job_id", job_id}});
        if (!job->request.contains("payload"))
            return error_envelope(ctx, "job_conflict", "job has no resumable payload", {{"job_id", job_id}});
        json p;
        p["operation"] = "submit";
        p["request_id"] = ctx.request_id;
        p["payload"] = job->request["payload"];
        p["budget"] = job->request.value("budget", json::object());
        return handle_chain_manage(p);
    }
    if (ctx.operation == "export")
        return handle_report_fetch_like(ctx, false, true);
    if (ctx.operation == "get_report")
        return handle_report_fetch_like(ctx, false);
    if (ctx.operation == "evidence_fetch")
        return handle_evidence_fetch(ctx);
    if (ctx.operation == "explain_failure")
        return handle_report_fetch_like(ctx, true);
    if (ctx.operation == "list")
    {
        json arr = json::array();
        const std::string verdict = ctx.payload.value("verdict", std::string());
        hydrate_reports_for_project(project_id_from_ctx(ctx));
        if (ctx.payload.value("include_jobs", false))
            hydrate_jobs_for_project(project_id_from_ctx(ctx));
        {
            auto& s = state();
            std::lock_guard<std::mutex> lock(s.mutex);
            for (const auto& kv : s.reports)
            {
                const auto& r = kv.second;
                const std::string rv = r.report.value("verdict", std::string("inconclusive"));
                if (!verdict.empty() && rv != verdict)
                    continue;
                arr.push_back({{"report_id", r.report_id}, {"job_id", r.job_id}, {"chain_id", r.chain_id}, {"created_at_ms", r.created_at_ms}, {"verdict", rv}, {"content_hash", r.content_hash}});
            }
        }
        json page;
        json rows = page_vector(ctx, "list", arr, page);
        if (page.contains("error"))
            return error_envelope(ctx, "cursor_expired", "cursor does not match this operation or database generation");
        json data;
        data["reports"] = rows;
        if (ctx.payload.value("include_jobs", false))
        {
            data["jobs"] = json::array();
            auto& s = state();
            std::lock_guard<std::mutex> lock(s.mutex);
            for (const auto& kv : s.jobs)
                data["jobs"].push_back(job_to_json(kv.second));
        }
        return ok_envelope(ctx, data, json(), page);
    }
    if (ctx.operation == "diagnostics")
    {
        json d;
        d["engine"] = verify::engine().verdict_summary();
        d["in_flight_count"] = verify::engine().in_flight_count();
        d["auto_analysis_ok"] = auto_is_ok();
        d["modal_safety"] = {{"manage_waitbox_free", true}, {"manage_ui_cancel_free", true}, {"interactive_cancel_requires_explicit_option", true}};
        d["job_runtime"] = job_runtime().diagnostics();
        hydrate_jobs_for_project(project_id_from_ctx(ctx));
        hydrate_reports_for_project(project_id_from_ctx(ctx));
        {
            auto& s = state();
            std::lock_guard<std::mutex> lock(s.mutex);
            d["job_count"] = s.jobs.size();
            d["report_count"] = s.reports.size();
            d["index_count"] = s.indices.size();
        }
        return ok_envelope(ctx, d);
    }
    return error_envelope(ctx, "unknown_operation", "unhandled operation", {{"operation", ctx.operation}});
}

agent_tools::tool_result_t handle_project_manage(const json& params)
{
    agent_tools::tool_result_t failure;
    request_ctx_t ctx = parse_request("ida_project_manage", params, project_ops(), failure);
    if (!failure.output.empty() || !failure.data.is_null())
        return failure;
    auto project_result = [&](const aida::multibinary::project_io_result_t& r) -> agent_tools::tool_result_t {
        if (r.ok)
            return ok_envelope(ctx, r.data);
        return error_envelope(ctx, r.error_code.empty() ? "project_error" : r.error_code,
                              r.error_message.empty() ? "project operation failed" : r.error_message,
                              r.data);
    };
    if (ctx.operation == "capabilities")
        return ok_envelope(ctx, make_capabilities(ctx.tool, project_ops()));
    if (ctx.operation == "save" || ctx.operation == "index_build" || ctx.operation == "resolve_cross_edges" || ctx.operation == "verify_chain" || ctx.operation == "case_study_regressions")
        return enqueue_async_job(ctx);
    if (ctx.operation == "inventory_current")
    {
        const int max_rows = int_param(ctx.payload, "max_rows", 256, 1, 100000);
        json inv = aida::multibinary::current_idb_inventory(ctx.payload.value("include_segments", true),
                                                            ctx.payload.value("include_imports", true),
                                                            ctx.payload.value("include_entries", true),
                                                            static_cast<std::size_t>(max_rows));
        return ok_envelope(ctx, inv);
    }
    if (ctx.operation == "inventory_all")
    {
        const int max_rows = int_param(ctx.payload, "max_rows", 256, 1, 100000);
        json local = aida::multibinary::current_idb_inventory(ctx.payload.value("include_segments", true),
                                                             ctx.payload.value("include_imports", true),
                                                             ctx.payload.value("include_entries", true),
                                                             static_cast<std::size_t>(max_rows));
        const bool has_supplied_fanout = ctx.payload.contains("fanout_result") || ctx.payload.contains("inventories");
        json supplied = json::object();
        if (ctx.payload.contains("fanout_result"))
            supplied["fanout_result"] = ctx.payload["fanout_result"];
        if (ctx.payload.contains("inventories"))
            supplied["inventories"] = ctx.payload["inventories"];
        json d;
        d["local"] = local;
        d["merged"] = aida::multibinary::merge_inventory_documents(local, supplied);
        std::set<std::string> supplied_instances;
        std::function<void(const json&)> collect_instance_ids = [&](const json& node) {
            if (node.is_object())
            {
                if (node.contains("instance") && node["instance"].is_object())
                {
                    const std::string id = node["instance"].contains("instance_id") && node["instance"]["instance_id"].is_string()
                        ? node["instance"]["instance_id"].get<std::string>()
                        : std::string();
                    if (!id.empty())
                        supplied_instances.insert(id);
                }
                const std::string direct = node.contains("instance_id") && node["instance_id"].is_string()
                    ? node["instance_id"].get<std::string>()
                    : std::string();
                if (!direct.empty())
                    supplied_instances.insert(direct);
                for (auto it = node.begin(); it != node.end(); ++it)
                    collect_instance_ids(it.value());
            }
            else if (node.is_array())
            {
                for (const json& item : node)
                    collect_instance_ids(item);
            }
        };
        collect_instance_ids(local);
        collect_instance_ids(supplied);
        d["peer_data_gaps"] = json::array();
        agent_tools::tool_result_t live_instances = invoke_registered("list_ida_instances", json::object());
        if (live_instances.success && live_instances.data.contains("instances") && live_instances.data["instances"].is_array())
        {
            for (const json& inst : live_instances.data["instances"])
            {
                const std::string id = inst.value("instance_id", std::string());
                if (id.empty() || supplied_instances.find(id) != supplied_instances.end())
                    continue;
                d["peer_data_gaps"].push_back({{"kind", "peer_data_missing"}, {"instance", inst}, {"reason", "query_all_instances inventory result was not supplied to ida_project_manage"}});
            }
        }
        else if (!live_instances.success)
        {
            d["peer_data_gaps"].push_back({{"kind", "peer_registry_unavailable"}, {"error_code", live_instances.error_code}, {"message", live_instances.output}});
        }
        d["fanout"] = has_supplied_fanout
            ? json({{"executed", true}, {"executed_by_router", ctx.payload.value("fanout_executed_by_router", false)}, {"tool", "query_all_instances"}})
            : json({{"executed", false},
                    {"tool", "query_all_instances"},
                    {"arguments", {{"tool", "ida_project_manage"}, {"arguments", {{"operation", "inventory_current"}, {"payload", ctx.payload}}}}},
                    {"reason", "direct fanout is only safe from the MCP routing layer; direct in-process callers must supply payload.fanout_result"}});
        d["instances_routing_compatible"] = true;
        return ok_envelope(ctx, d);
    }
    if (ctx.operation == "list")
        return project_result(aida::multibinary::list_projects());
    if (ctx.operation == "load")
        return project_result(aida::multibinary::load_project_modules(ctx.payload.value("project_id", std::string())));
    if (ctx.operation == "delete")
    {
        if (!ctx.payload.value("confirm_destructive", false) || ctx.payload.value("reason", std::string()).empty())
            return error_envelope(ctx, "destructive_denied", "delete requires confirm_destructive=true and a non-empty reason");
        return project_result(aida::multibinary::delete_project(ctx.payload.value("project_id", std::string())));
    }
    if (ctx.operation == "status")
    {
        const std::string project_id = ctx.payload.value("project_id", aida::multibinary::default_project_id_for_current_idb());
        return project_result(aida::multibinary::index_status(project_id));
    }
    if (ctx.operation == "corpus_snapshot")
    {
        const std::string project_id = ctx.payload.value("project_id", std::string());
        if (!project_id.empty())
            return project_result(aida::multibinary::load_project_manifest(project_id));
        auto& s = state();
        std::lock_guard<std::mutex> lock(s.mutex);
        json d = s.corpus_manifest.empty() ? json::object({{"corpus_id", "current"}, {"modules", json::array({module_identity()})}, {"generation", generation_id()}}) : s.corpus_manifest;
        return ok_envelope(ctx, d);
    }
    if (ctx.operation == "corpus_bind")
    {
        const int max_rows = int_param(ctx.payload, "max_rows", 100000, 1, 1000000);
        aida::multibinary::project_io_result_t saved = ctx.payload.contains("modules") && ctx.payload["modules"].is_array()
            ? aida::multibinary::save_or_update_project(ctx.payload.value("project_id", ctx.payload.value("corpus_id", std::string())),
                                                        ctx.payload["modules"],
                                                        ctx.payload)
            : aida::multibinary::bind_current_inventory_to_project(ctx.payload.value("project_id", ctx.payload.value("corpus_id", std::string())),
                                                                   aida::multibinary::current_idb_inventory(true, true, true, static_cast<std::size_t>(max_rows)),
                                                                   ctx.payload,
                                                                   ctx.payload);
        if (!saved.ok)
            return project_result(saved);
        auto loaded = aida::multibinary::load_project_manifest(saved.data.value("project_id", ctx.payload.value("project_id", std::string())));
        auto& s = state();
        {
            std::lock_guard<std::mutex> lock(s.mutex);
            s.corpus_manifest = loaded.ok ? loaded.data["manifest"] : saved.data;
        }
        return ok_envelope(ctx, saved.data);
    }
    if (ctx.operation == "corpus_export")
    {
        const std::string project_id = ctx.payload.value("project_id", std::string());
        if (!project_id.empty())
        {
            auto loaded = aida::multibinary::load_project_manifest(project_id);
            if (!loaded.ok)
                return project_result(loaded);
            return ok_envelope(ctx, {{"format", "json"}, {"manifest", loaded.data["manifest"]}, {"content_hash", aida::multibinary::content_hash_summary(loaded.data["manifest"])}});
        }
        auto& s = state();
        std::lock_guard<std::mutex> lock(s.mutex);
        json manifest = s.corpus_manifest.empty() ? json::object({{"corpus_id", "current"}, {"modules", json::array({module_identity()})}, {"generation", generation_id()}}) : s.corpus_manifest;
        return ok_envelope(ctx, {{"format", "json"}, {"manifest", manifest}, {"content_hash", hash_text(manifest.dump())}});
    }
    if (ctx.operation == "index_status")
    {
        const std::string project_id = ctx.payload.value("project_id", aida::multibinary::default_project_id_for_current_idb());
        return project_result(aida::multibinary::index_status(project_id));
    }
    if (ctx.operation == "index_page_status")
    {
        const std::string project_id = ctx.payload.value("project_id", aida::multibinary::default_project_id_for_current_idb());
        return project_result(aida::multibinary::index_page_status(project_id, ctx.payload.value("module_id", std::string())));
    }
    if (ctx.operation == "index_page")
    {
        const std::string project_id = ctx.payload.value("project_id", aida::multibinary::default_project_id_for_current_idb());
        const std::size_t page_index = static_cast<std::size_t>(int_param(ctx.payload, "page_index", 0, 0, 1000000000));
        return project_result(aida::multibinary::load_index_page(project_id,
                                                                 ctx.payload.value("module_id", std::string()),
                                                                 ctx.payload.value("family", std::string()),
                                                                 ctx.payload.value("cursor", std::string()),
                                                                 page_index));
    }
    if (ctx.operation == "resolve_reference")
    {
        const std::string project_id = ctx.payload.value("project_id", aida::multibinary::default_project_id_for_current_idb());
        return project_result(aida::multibinary::resolve_project_reference(project_id, ctx.payload.value("reference", json::object())));
    }
    return error_envelope(ctx, "unknown_operation", "unhandled operation", {{"operation", ctx.operation}});
}

json project_io_result_json(const aida::multibinary::project_io_result_t& r)
{
    return {
        {"ok", r.ok},
        {"data", r.data},
        {"error_code", r.error_code},
        {"error_message", r.error_message}
    };
}

queued_job_result_t queued_chain_report_job(const request_ctx_t& ctx, const job_record_t& job)
{
    queued_job_result_t out;
    const json module = ctx.payload.value("_aida_module_identity", json::object());
    const std::string generation = ctx.payload.value("_aida_generation", job.generation);
    json report = build_chain_report(ctx, job.job_id, module, generation);
    const std::string chain_id = report.value("chain_id", std::string("chain:" + ctx.request_id));
    const std::string report_id = store_report(job.project_id, job.job_id, chain_id, report);
    auto rec = get_report_record(report_id, job.project_id);
    json resources = rec ? json::array({resource_for_report(*rec, "json"), resource_for_report(*rec, "markdown"), resource_for_report(*rec, "sarif")}) : json::array();
    for (const auto& item : job_resource_manifest(job.job_id))
        resources.push_back(item);
    out.ok = true;
    out.report_id = report_id;
    out.resources = resources;
    json stored_report = rec ? rec->report : report;
    if (ctx.operation == "verify_link")
    {
        out.data = {
            {"schema", kReportSchema},
            {"engine", "ChainVerificationEngine"},
            {"legacy_tool", nullptr},
            {"report_id", report_id},
            {"data", stored_report},
            {"verdict", stored_report.value("verdict", std::string("inconclusive"))},
            {"acceptance", stored_report.value("verdict", std::string()) == "confirmed" ? "accepted" : (stored_report.value("verdict", std::string()) == "refuted" ? "rejected" : "not_accepted")},
            {"link_report", stored_report.contains("links") && stored_report["links"].is_array() && !stored_report["links"].empty() ? stored_report["links"].front() : json::object()},
            {"link_id", ctx.payload.value("link_id", std::string("link:0"))}
        };
    }
    else
    {
        out.data = {{"report_id", report_id}, {"report", stored_report}};
    }
    return out;
}

queued_job_result_t queued_project_job(const request_ctx_t& ctx, const job_record_t& job)
{
    const int flags = (ctx.operation == "save" || ctx.operation == "index_build" || ctx.operation == "resolve_cross_edges") ? MFF_WRITE : MFF_READ;
    ida_gateway_result_t gateway_result = job_runtime().execute_ida_job(ctx, job.job_id, flags, 600000, [ctx]() {
        if (ctx.operation == "save")
        {
            if (ctx.payload.contains("modules") && ctx.payload["modules"].is_array())
                return project_io_result_json(aida::multibinary::save_or_update_project(ctx.payload.value("project_id", std::string()),
                                                                                       ctx.payload["modules"],
                                                                                       ctx.payload));
            const int max_rows = int_param(ctx.payload, "max_rows", 100000, 1, 1000000);
            json local = aida::multibinary::current_idb_inventory(true, true, true, static_cast<std::size_t>(max_rows));
            return project_io_result_json(aida::multibinary::bind_current_inventory_to_project(ctx.payload.value("project_id", std::string()),
                                                                                              local,
                                                                                              ctx.payload,
                                                                                              ctx.payload));
        }
        if (ctx.operation == "index_build")
        {
            json indices = ctx.payload.contains("indices") && ctx.payload["indices"].is_array() ? ctx.payload["indices"] : json::array({"functions", "segments", "imports", "entries", "verifier"});
            aida::multibinary::index_build_options_t options = aida::multibinary::index_options_from_json(ctx.payload);
            options.force = ctx.payload.value("force", options.force);
            return project_io_result_json(aida::multibinary::build_current_module_index(ctx.payload.value("project_id", std::string()), indices, options));
        }
        if (ctx.operation == "resolve_cross_edges")
        {
            const std::string project_id = ctx.payload.value("project_id", aida::multibinary::default_project_id_for_current_idb());
            return project_io_result_json(aida::multibinary::resolve_project_cross_edges(project_id));
        }
        if (ctx.operation == "verify_chain")
        {
            const std::string project_id = ctx.payload.value("project_id", std::string());
            return project_io_result_json(aida::vuln::chain_verifier::verify_project_chain(project_id,
                                                                                          ctx.payload.value("chain", json::object()),
                                                                                          ctx.payload.value("options", json::object())));
        }
        if (ctx.operation == "case_study_regressions")
        {
            const std::string project_id = ctx.payload.value("project_id", std::string());
            return project_io_result_json(aida::vuln::chain_verifier::run_case_study_regressions(project_id, ctx.payload));
        }
        return json{{"ok", false}, {"data", json::object()}, {"error_code", "unknown_operation"}, {"error_message", "unsupported queued project operation"}};
    });

    queued_job_result_t out;
    if (!gateway_result.ok)
    {
        out.ok = false;
        out.error_code = gateway_result.stale_generation ? "stale_generation" : (gateway_result.timed_out ? "timeout" : (gateway_result.cancelled ? "cancelled" : "idb_unavailable"));
        out.error_message = gateway_result.error.empty() ? "project job gateway execution failed" : gateway_result.error;
        out.data = gateway_result.data;
        return out;
    }
    out.ok = gateway_result.data.value("ok", false);
    out.data = gateway_result.data.value("data", json::object());
    out.error_code = gateway_result.data.value("error_code", std::string());
    out.error_message = gateway_result.data.value("error_message", std::string());
    out.resources = job_resource_manifest(job.job_id);
    const std::string project_id = ctx.payload.value("project_id", job.project_id);
    if (!project_id.empty())
    {
        out.resources.push_back({{"uri", "ida://projects/" + project_id + "/index/status"}, {"kind", "index_status"}, {"project_id", project_id}});
        out.resources.push_back({{"uri", "ida://projects/" + project_id + "/index/pages"}, {"kind", "index_pages"}, {"project_id", project_id}});
    }
    return out;
}

queued_job_result_t execute_queued_mcp_job(const request_ctx_t& ctx, const job_record_t& job)
{
    if (ctx.tool == "ida_chain_manage" && (ctx.operation == "submit" || ctx.operation == "start" || ctx.operation == "verify_link"))
        return queued_chain_report_job(ctx, job);
    if (ctx.tool == "ida_project_manage" && (ctx.operation == "save" || ctx.operation == "index_build" || ctx.operation == "resolve_cross_edges" || ctx.operation == "verify_chain" || ctx.operation == "case_study_regressions"))
        return queued_project_job(ctx, job);
    queued_job_result_t out;
    out.ok = false;
    out.error_code = "unknown_operation";
    out.error_message = "queued job operation is not supported";
    return out;
}

std::vector<std::string> strings_from_array_field(const json& payload, const char* key)
{
    std::vector<std::string> out;
    if (!payload.contains(key) || !payload[key].is_array())
        return out;
    for (const auto& item : payload[key])
    {
        if (item.is_string())
            out.push_back(item.get<std::string>());
    }
    return out;
}

bool contains_string(const std::vector<std::string>& values, const std::string& value)
{
    return std::find(values.begin(), values.end(), value) != values.end();
}

aida::vuln::chain::extraction_options_t extraction_options_from_ctx(const request_ctx_t& ctx)
{
    aida::vuln::chain::extraction_options_t options;
    const std::vector<std::string> layers = strings_from_array_field(ctx.payload, "layers");
    if (!layers.empty())
    {
        options.include_bytes = contains_string(layers, "raw") || contains_string(layers, "bytes") || contains_string(layers, "instructions") || contains_string(layers, "assembly");
        options.include_xrefs = contains_string(layers, "raw") || contains_string(layers, "xrefs") || contains_string(layers, "xref_graph");
        options.include_xref_indexes = contains_string(layers, "xrefs") || contains_string(layers, "xref_graph");
        options.include_types = contains_string(layers, "types") || contains_string(layers, "type");
        options.include_ctree = contains_string(layers, "ctree") || contains_string(layers, "decompiler") || contains_string(layers, "hexrays");
        options.include_microcode = contains_string(layers, "microcode");
        options.include_effects = contains_string(layers, "effects") || contains_string(layers, "side_effects");
    }
    options.force_refresh = ctx.payload.value("force_refresh", false);
    options.max_instructions = static_cast<std::size_t>(int_param(ctx.payload, "max_instructions", static_cast<int>(options.max_instructions), 1, 200000));
    options.max_basic_blocks = static_cast<std::size_t>(int_param(ctx.payload, "max_basic_blocks", static_cast<int>(options.max_basic_blocks), 1, 50000));
    options.max_xrefs_per_address = static_cast<std::size_t>(int_param(ctx.payload, "max_xrefs_per_address", static_cast<int>(options.max_xrefs_per_address), 1, 10000));
    options.max_ctree_nodes = static_cast<std::size_t>(int_param(ctx.payload, "max_ctree_nodes", static_cast<int>(options.max_ctree_nodes), 1, 200000));
    options.max_microcode_instructions = static_cast<std::size_t>(int_param(ctx.payload, "max_microcode_instructions", static_cast<int>(options.max_microcode_instructions), 1, 200000));
    options.max_pseudocode_lines = static_cast<std::size_t>(int_param(ctx.payload, "max_pseudocode_lines", static_cast<int>(options.max_pseudocode_lines), 1, 50000));
    options.max_batch_functions = static_cast<std::size_t>(int_param(ctx.payload, "max_functions", static_cast<int>(options.max_batch_functions), 1, 20000));
    options.max_module_items = static_cast<std::size_t>(int_param(ctx.payload, "max_module_items", static_cast<int>(options.max_module_items), 1, 1000000));
    if (ctx.payload.contains("timeout_ms") || ctx.budget.contains("timeout_ms"))
        options.timeout_ms = static_cast<std::uint64_t>(int_param(ctx.payload.contains("timeout_ms") ? ctx.payload : ctx.budget, "timeout_ms", 0, 0, 600000));
    if (!ctx.job_id.empty())
    {
        const std::string job_id = ctx.job_id;
        options.cancellation_requested = [job_id]() {
            return job_cancel_requested(job_id);
        };
    }
    std::vector<std::string> maturities = strings_from_array_field(ctx.payload, "maturities");
    if (!maturities.empty())
        options.microcode_maturities = maturities;
    return options;
}

std::vector<ea_t> function_locations_from_payload(const json& payload)
{
    std::vector<ea_t> out;
    if (!payload.contains("functions") || !payload["functions"].is_array())
        return out;
    for (const auto& item : payload["functions"])
    {
        std::optional<ea_t> ea;
        if (item.is_object() && item.contains("address"))
            ea = parse_location(item["address"]);
        else
            ea = parse_location(item);
        if (ea)
            out.push_back(*ea);
    }
    return out;
}

struct function_start_page_t
{
    std::vector<ea_t> starts;
    json page = json::object();
    bool cursor_ok = true;
};

function_start_page_t function_start_page(const request_ctx_t& ctx, std::size_t max_functions)
{
    struct request_t : public exec_request_t
    {
        request_ctx_t ctx;
        std::size_t max_functions = 0;
        function_start_page_t result;
        request_t(const request_ctx_t& c, std::size_t m) : ctx(c), max_functions(m) {}
        ssize_t idaapi execute() override
        {
            size_t offset = 0;
            if (!parse_cursor(ctx.cursor, "extract_function_batch", generation_id(), offset))
            {
                result.cursor_ok = false;
                return 1;
            }
            const std::size_t qty = get_func_qty();
            const std::size_t limit = std::min<std::size_t>(static_cast<std::size_t>(ctx.limit), max_functions);
            const std::size_t end = std::min(qty, offset + limit);
            for (std::size_t i = offset; i < end; ++i)
            {
                func_t* fn = getn_func(i);
                if (fn != nullptr)
                    result.starts.push_back(fn->start_ea);
            }
            const bool truncated = end < qty;
            const std::string next = truncated ? cursor_for("extract_function_batch", generation_id(), end) : std::string();
            result.page = page_json(ctx.cursor, next, static_cast<int>(limit), result.starts.size(), truncated);
            return 1;
        }
    };
    request_t req(ctx, max_functions);
    if (execute_sync(req, MFF_READ) <= 0)
    {
        req.result.cursor_ok = false;
        return req.result;
    }
    return req.result;
}

aida::vuln::chain::path_trace_options_t path_options_from_ctx(const request_ctx_t& ctx)
{
    aida::vuln::chain::path_trace_options_t options;
    options.max_blocks = static_cast<std::size_t>(int_param(ctx.payload, "max_blocks", static_cast<int>(options.max_blocks), 1, 50000));
    options.max_steps = static_cast<std::size_t>(int_param(ctx.payload, "max_steps", static_cast<int>(options.max_steps), 1, 200000));
    options.max_unresolved_edges = static_cast<std::size_t>(int_param(ctx.payload, "max_unresolved_edges", static_cast<int>(options.max_unresolved_edges), 1, 50000));
    return options;
}

json resolver_modules_from_ctx(const request_ctx_t& ctx, const json& current_module = json())
{
    json modules = json::array();
    std::unordered_set<std::string> seen;
    auto module_id_of = [](const json& module) {
        if (module.contains("identity") && module["identity"].is_object())
            return module["identity"].value("module_id", module["identity"].value("corpus_id", std::string()));
        if (module.contains("module") && module["module"].is_object())
            return module["module"].value("module_id", module["module"].value("corpus_id", std::string()));
        return module.value("module_id", module.value("corpus_id", std::string()));
    };
    auto append = [&](const json& module) {
        if (!module.is_object())
            return;
        const std::string id = module_id_of(module);
        const std::string key = id.empty() ? hash_text(module.dump()) : id;
        if (!seen.insert(key).second)
            return;
        modules.push_back(module);
    };
    if (!current_module.is_null() && !current_module.empty())
        append(current_module);
    if (ctx.payload.contains("modules") && ctx.payload["modules"].is_array())
    {
        for (const json& module : ctx.payload["modules"])
            append(module);
    }
    if (modules.empty() || ctx.payload.value("include_current_module", true))
    {
        aida::vuln::chain::extraction_options_t options = extraction_options_from_ctx(ctx);
        options.include_bytes = false;
        options.include_types = false;
        options.include_ctree = false;
        options.include_microcode = false;
        options.include_effects = false;
        options.include_xrefs = true;
        options.include_xref_indexes = true;
        append(aida::vuln::chain::to_json(aida::vuln::chain::extract_module_snapshot(options)));
    }
    return modules;
}

bool target_reference_matches(const json& target_ref, const json& resolved)
{
    if (!target_ref.is_object() || !resolved.is_object() || !resolved.value("resolved", false))
        return false;
    const json target = resolved.value("target", json::object());
    std::string wanted_module = target_ref.value("module_id", target_ref.value("corpus_id", std::string()));
    if (wanted_module.empty() && target_ref.contains("module") && target_ref["module"].is_object())
        wanted_module = target_ref["module"].value("module_id", target_ref["module"].value("corpus_id", std::string()));
    std::string got_module = target.value("module_id", target.value("corpus_id", std::string()));
    if (got_module.empty() && target.contains("module") && target["module"].is_object())
        got_module = target["module"].value("module_id", target["module"].value("corpus_id", std::string()));
    const bool wanted_has_rva = target_ref.contains("rva") && !target_ref["rva"].is_null()
        && (!target_ref["rva"].is_string() || !target_ref["rva"].get<std::string>().empty());
    const bool got_has_rva = target.contains("rva") && !target["rva"].is_null()
        && (!target["rva"].is_string() || !target["rva"].get<std::string>().empty());
    if (!wanted_module.empty() && !got_module.empty() && wanted_module != got_module)
        return false;
    if (wanted_has_rva && got_has_rva)
    {
        auto wanted_rva = agent_tools::helpers::parse_address(scalar_to_string(target_ref["rva"]));
        auto got_rva = agent_tools::helpers::parse_address(scalar_to_string(target["rva"]));
        if (wanted_rva && got_rva && *wanted_rva != *got_rva)
            return false;
    }
    std::string wanted_symbol = target_ref.value("symbol", target_ref.value("name", std::string()));
    std::string got_symbol = target.value("symbol", target.value("name", std::string()));
    if (!wanted_symbol.empty() && !got_symbol.empty() && lowercase_ascii(wanted_symbol) != lowercase_ascii(got_symbol))
        return false;
    return !wanted_module.empty() || wanted_has_rva || !wanted_symbol.empty();
}

json cross_reachability_data(const request_ctx_t& ctx,
                             ea_t entry_ea,
                             const std::optional<ea_t>& local_target,
                             const json& target_ref,
                             const json& resolver_modules)
{
    json out;
    out["schema"] = "aida_chain_cross_reachability_v1";
    out["entry"] = fmt_ea(entry_ea);
    out["target"] = target_ref.is_null() ? json(nullptr) : target_ref;
    out["verdict"] = "incomplete";
    out["reached"] = false;
    out["negative_evidence_complete"] = false;
    out["visited_functions"] = json::array();
    out["visited_modules"] = json::array();
    out["traversed_edges"] = json::array();
    out["unresolved_edges"] = json::array();
    out["cross_binary_resolutions"] = json::array();
    out["cutoff_reason"] = nullptr;
    func_t* entry_fn = get_func(entry_ea);
    if (entry_fn == nullptr)
    {
        out["cutoff_reason"] = "entry_not_in_function";
        return out;
    }
    ea_t target_fn_ea = BADADDR;
    if (local_target)
    {
        func_t* tf = get_func(*local_target);
        target_fn_ea = tf != nullptr ? tf->start_ea : *local_target;
    }
    const std::uint64_t start = now_ms();
    const int max_depth = int_param(ctx.payload, "max_depth", 8, 1, 128);
    const int max_functions = int_param(ctx.payload, "max_functions", 1024, 1, 100000);
    struct node_t
    {
        ea_t fn = BADADDR;
        int depth = 0;
        std::vector<ea_t> path;
    };
    std::deque<node_t> queue;
    std::set<ea_t> seen;
    queue.push_back({entry_fn->start_ea, 0, {entry_fn->start_ea}});
    seen.insert(entry_fn->start_ea);
    bool unresolved = false;
    bool cutoff = false;
    while (!queue.empty())
    {
        if (seen.size() > static_cast<size_t>(max_functions))
        {
            cutoff = true;
            out["cutoff_reason"] = "function_budget_exhausted";
            break;
        }
        if (ctx.budget.contains("timeout_ms") && now_ms() - start >= static_cast<std::uint64_t>(int_param(ctx.budget, "timeout_ms", 0, 0, 600000)))
        {
            cutoff = true;
            out["cutoff_reason"] = "timeout";
            break;
        }
        if (!ctx.job_id.empty() && job_cancel_requested(ctx.job_id))
        {
            cutoff = true;
            out["cutoff_reason"] = "cancelled";
            break;
        }
        node_t cur = queue.front();
        queue.pop_front();
        out["visited_functions"].push_back(fmt_ea(cur.fn));
        if (cur.fn == target_fn_ea)
        {
            out["verdict"] = "confirmed";
            out["reached"] = true;
            out["path"] = json::array();
            for (ea_t step : cur.path)
                out["path"].push_back(fmt_ea(step));
            return out;
        }
        if (cur.depth >= max_depth)
        {
            cutoff = true;
            out["cutoff_reason"] = "depth_budget_exhausted";
            continue;
        }
        aida::vuln::chain::extraction_options_t options = extraction_options_from_ctx(ctx);
        options.include_bytes = false;
        options.include_types = false;
        options.include_ctree = false;
        options.include_microcode = false;
        options.include_effects = false;
        options.include_xrefs = true;
        options.include_xref_indexes = true;
        aida::vuln::chain::function_snapshot_t snapshot = aida::vuln::chain::extract_function_snapshot(cur.fn, options);
        const std::string module_id = snapshot.identity.start.module.module_id;
        if (!module_id.empty())
            out["visited_modules"].push_back(module_id);
        for (const auto& call : snapshot.calls)
        {
            json edge;
            edge["from_function"] = fmt_ea(cur.fn);
            edge["callsite"] = aida::vuln::chain::to_json(call.callsite);
            edge["kind"] = call.kind;
            edge["callee_name"] = call.callee_name;
            edge["resolution_quality"] = call.resolution_quality;
            if (!call.resolved || call.kind == "indirect")
            {
                unresolved = true;
                out["unresolved_edges"].push_back(edge);
                continue;
            }
            edge["target"] = aida::vuln::chain::to_json(call.target);
            out["traversed_edges"].push_back(edge);
            if (local_target && call.target.ea == static_cast<std::uint64_t>(*local_target))
            {
                out["verdict"] = "confirmed";
                out["reached"] = true;
                out["path"] = json::array();
                for (ea_t step : cur.path)
                    out["path"].push_back(fmt_ea(step));
                out["path"].push_back(fmt_ea(static_cast<ea_t>(call.target.ea)));
                return out;
            }
            json ref;
            ref["address"] = aida::vuln::chain::to_json(call.target);
            ref["symbol"] = call.callee_name;
            json resolved = aida::vuln::chain::resolve_cross_binary_reference(resolver_modules, ref);
            out["cross_binary_resolutions"].push_back(resolved);
            if (target_reference_matches(target_ref, resolved))
            {
                out["verdict"] = "confirmed";
                out["reached"] = true;
                out["path"] = json::array();
                for (ea_t step : cur.path)
                    out["path"].push_back(fmt_ea(step));
                out["path"].push_back(resolved["target"]);
                return out;
            }
            func_t* callee = get_func(static_cast<ea_t>(call.target.ea));
            if (callee == nullptr)
                continue;
            if (!seen.insert(callee->start_ea).second)
                continue;
            std::vector<ea_t> next_path = cur.path;
            next_path.push_back(callee->start_ea);
            queue.push_back({callee->start_ea, cur.depth + 1, std::move(next_path)});
        }
    }
    if (!cutoff && !unresolved)
    {
        out["verdict"] = "refuted";
        out["negative_evidence_complete"] = true;
        out["cutoff_reason"] = nullptr;
    }
    else
    {
        out["verdict"] = "incomplete";
        if (out["cutoff_reason"].is_null())
            out["cutoff_reason"] = unresolved ? "unresolved_indirect_or_external_edges" : "frontier_incomplete";
    }
    out["visited_function_count"] = seen.size();
    return out;
}

json xref_graph_data(const request_ctx_t& ctx, const aida::vuln::chain::function_snapshot_t& snapshot, std::optional<ea_t> target)
{
    json data;
    data["function"] = aida::vuln::chain::to_json(snapshot.identity);
    data["xref_from_index"] = snapshot.xref_from_index;
    data["xref_to_index"] = snapshot.xref_to_index;
    data["calls"] = json::array();
    for (const auto& call : snapshot.calls)
        data["calls"].push_back(aida::vuln::chain::to_json(call));
    data["branches"] = json::array();
    for (const auto& branch : snapshot.branches)
        data["branches"].push_back(aida::vuln::chain::to_json(branch));
    data["reachable_evidence"] = json::object();
    if (target)
    {
        aida::vuln::chain::path_trace_t trace = aida::vuln::chain::trace_path_corridor(snapshot, snapshot.identity.start.ea, static_cast<std::uint64_t>(*target), path_options_from_ctx(ctx));
        data["reachable_evidence"] = aida::vuln::chain::to_json(trace);
        data["reachable_evidence"]["negative_evidence_complete"] = !trace.reached && trace.complete;
    }
    json modules = resolver_modules_from_ctx(ctx);
    data["corpus_reachability"] = cross_reachability_data(ctx,
                                                         static_cast<ea_t>(snapshot.identity.start.ea),
                                                         target,
                                                         ctx.payload.value("target", json(nullptr)),
                                                         modules);
    data["resolver_index"] = aida::vuln::chain::build_cross_binary_resolver_index(modules);
    return data;
}

bool json_text_contains(const json& value, const std::vector<std::string>& needles)
{
    const std::string text = lowercase_ascii(value.dump());
    for (const std::string& needle : needles)
    {
        if (text.find(lowercase_ascii(needle)) != std::string::npos)
            return true;
    }
    return false;
}

json zero_vs_copy_check(const aida::vuln::chain::function_snapshot_t& snapshot)
{
    json out;
    out["case_id"] = "ntfs_etw_zero_vs_copy";
    out["status"] = "unproven";
    out["evidence"] = json::array();
    bool zero_write = false;
    bool copied_write = false;
    for (const auto& effect : snapshot.effects)
    {
        const std::string kind = effect.value("kind", std::string());
        const json source = effect.value("source", json::object());
        const std::string origin = source.value("value_origin", std::string());
        if ((kind == "memory_set" || kind == "write") && origin == "constant_zero")
        {
            zero_write = true;
            out["evidence"].push_back(effect);
        }
        if ((kind == "memory_copy" || kind == "write") && (origin == "copied_from_memory" || origin == "copied_from_input"))
        {
            copied_write = true;
            out["evidence"].push_back(effect);
        }
    }
    out["zero_write_present"] = zero_write;
    out["copied_write_present"] = copied_write;
    if (zero_write && copied_write)
        out["status"] = "passed";
    else
        out["reason"] = "function_facts_do_not_contain_both_constant_zero_and_copied_write_sources";
    return out;
}

json afd_list_entry_guard_check(const aida::vuln::chain::function_snapshot_t& snapshot)
{
    json out;
    out["case_id"] = "afd_list_entry_guard";
    out["status"] = "unproven";
    out["evidence"] = json::array();
    bool has_48 = false;
    bool has_50 = false;
    bool has_branch = false;
    bool has_later_indirect_call = false;
    std::uint64_t first_branch = 0;
    for (const auto& branch : snapshot.branches)
    {
        const json bj = aida::vuln::chain::to_json(branch);
        if (json_text_contains(bj, {"0x48", "+48", " 48h", "list_entry", "flink", "blink"}))
            has_48 = true;
        if (json_text_contains(bj, {"0x50", "+50", " 50h", "list_entry", "flink", "blink"}))
            has_50 = true;
        if (json_text_contains(bj, {"0x48", "+48", "0x50", "+50", "list_entry", "flink", "blink"}))
        {
            has_branch = true;
            if (first_branch == 0)
                first_branch = branch.branch.ea;
            out["evidence"].push_back(bj);
        }
    }
    for (const auto& ins : snapshot.instructions)
    {
        if (!ins.is_indirect || !ins.is_call)
            continue;
        if (first_branch == 0 || ins.location.ea > first_branch)
        {
            has_later_indirect_call = true;
            out["evidence"].push_back(aida::vuln::chain::to_json(ins));
            break;
        }
    }
    if (json_text_contains(snapshot.ctree.memory_facts, {"0x48", "+48", " 48h"}))
        has_48 = true;
    if (json_text_contains(snapshot.ctree.memory_facts, {"0x50", "+50", " 50h"}))
        has_50 = true;
    out["offset_0x48_present"] = has_48;
    out["offset_0x50_present"] = has_50;
    out["branch_before_indirect_call_present"] = has_branch && has_later_indirect_call;
    if (has_48 && has_50 && has_branch && has_later_indirect_call)
        out["status"] = "passed";
    else
        out["reason"] = "source_facts_do_not_prove_list_entry_offsets_and_guard_before_indirect_call";
    return out;
}

json pvscan0_self_reference_check(const aida::vuln::chain::function_snapshot_t& snapshot)
{
    json out;
    out["case_id"] = "pvscan0_self_reference";
    out["status"] = "unproven";
    out["evidence"] = json::array();
    bool found = false;
    bool preserves_destination_and_source = false;
    for (const auto& effect : snapshot.effects)
    {
        const std::string kind = effect.value("kind", std::string());
        const std::string operation = lowercase_ascii(effect.value("operation", std::string()));
        if (operation.find("setbitmapbits") == std::string::npos && !json_text_contains(effect.value("tags", json::array()), {"pvscan0"}))
            continue;
        found = true;
        const json destination = effect.value("destination", json::object());
        const json source = effect.value("source", json::object());
        if (!destination.value("text", std::string()).empty() && (!source.value("text", std::string()).empty() || source.value("controlled_by_input", false)))
            preserves_destination_and_source = true;
        if (kind == "memory_set" || kind == "memory_copy" || kind == "write")
            out["evidence"].push_back(effect);
    }
    out["setbitmapbits_effect_present"] = found;
    out["destination_and_source_preserved"] = preserves_destination_and_source;
    if (found && preserves_destination_and_source)
        out["status"] = "passed";
    else
        out["reason"] = "source_facts_do_not_preserve_setbitmapbits_destination_and_source_expressions";
    return out;
}

json etw_trigger_negative_check(const request_ctx_t& ctx, const json& resolver_modules)
{
    json out;
    out["case_id"] = "etw_trigger_negative";
    out["status"] = "unproven";
    auto entry = payload_location(ctx.payload, "entry");
    std::optional<ea_t> target = payload_location(ctx.payload, "target");
    if (!entry || (!target && !ctx.payload.contains("target")))
    {
        out["reason"] = "entry_and_target_are_required_for_trigger_negative_evidence";
        return out;
    }
    json reach = cross_reachability_data(ctx, *entry, target, ctx.payload.value("target", json(nullptr)), resolver_modules);
    out["evidence"] = reach;
    if (reach.value("negative_evidence_complete", false))
        out["status"] = "passed";
    else
        out["reason"] = reach.value("cutoff_reason", std::string("target_reached_or_evidence_incomplete"));
    return out;
}

json case_study_self_check_data(const request_ctx_t& ctx)
{
    json out;
    out["schema"] = "aida_chain_case_study_self_check_v1";
    out["overall"] = "unproven";
    out["checks"] = json::array();
    const std::string case_id = ctx.payload.value("case_id", std::string("all"));
    aida::vuln::chain::extraction_options_t options = extraction_options_from_ctx(ctx);
    options.include_bytes = true;
    options.include_xrefs = true;
    options.include_xref_indexes = true;
    options.include_types = true;
    options.include_ctree = true;
    options.include_microcode = false;
    options.include_effects = true;
    std::optional<ea_t> address = payload_location(ctx.payload, "address");
    aida::vuln::chain::function_snapshot_t snapshot;
    bool has_snapshot = false;
    if (address)
    {
        snapshot = aida::vuln::chain::extract_function_snapshot(*address, options);
        has_snapshot = snapshot.identity.start.ea != 0;
        out["function"] = aida::vuln::chain::to_json(snapshot.identity);
    }
    if ((case_id == "all" || case_id == "ntfs_etw_zero_vs_copy") && has_snapshot)
        out["checks"].push_back(zero_vs_copy_check(snapshot));
    else if (case_id == "all" || case_id == "ntfs_etw_zero_vs_copy")
        out["checks"].push_back({{"case_id", "ntfs_etw_zero_vs_copy"}, {"status", "unproven"}, {"reason", "address_is_required"}});
    if (case_id == "all" || case_id == "etw_trigger_negative")
        out["checks"].push_back(etw_trigger_negative_check(ctx, resolver_modules_from_ctx(ctx)));
    if ((case_id == "all" || case_id == "afd_list_entry_guard") && has_snapshot)
        out["checks"].push_back(afd_list_entry_guard_check(snapshot));
    else if (case_id == "all" || case_id == "afd_list_entry_guard")
        out["checks"].push_back({{"case_id", "afd_list_entry_guard"}, {"status", "unproven"}, {"reason", "address_is_required"}});
    if ((case_id == "all" || case_id == "pvscan0_self_reference") && has_snapshot)
        out["checks"].push_back(pvscan0_self_reference_check(snapshot));
    else if (case_id == "all" || case_id == "pvscan0_self_reference")
        out["checks"].push_back({{"case_id", "pvscan0_self_reference"}, {"status", "unproven"}, {"reason", "address_is_required"}});
    bool any = false;
    bool all_passed = true;
    for (const auto& check : out["checks"])
    {
        any = true;
        if (check.value("status", std::string()) != "passed")
            all_passed = false;
    }
    if (any && all_passed)
        out["overall"] = "passed";
    return out;
}

agent_tools::tool_result_t handle_extract_manage(const json& params)
{
    agent_tools::tool_result_t failure;
    request_ctx_t ctx = parse_request("ida_extract_manage", params, extract_ops(), failure);
    if (!failure.output.empty() || !failure.data.is_null())
        return failure;
    if (ctx.operation == "capabilities")
        return ok_envelope(ctx, make_capabilities(ctx.tool, extract_ops()));
    if (ctx.operation == "extract_module_facts")
    {
        aida::vuln::chain::extraction_options_t options = extraction_options_from_ctx(ctx);
        aida::vuln::chain::module_snapshot_t snapshot = aida::vuln::chain::extract_module_snapshot(options);
        json data = {{"module_facts", aida::vuln::chain::to_json(snapshot)}};
        json nested_page;
        if (!apply_nested_pagination(ctx, "extract_module_facts", data, std::string(), nested_page))
            return error_envelope(ctx, nested_page.value("error", std::string("bad_page_path")), "nested page path is invalid", nested_page);
        return ok_envelope(ctx, data, json(), nested_page);
    }
    if (ctx.operation == "extract_function_facts")
    {
        auto ea = payload_location(ctx.payload, "address");
        if (!ea)
            return error_envelope(ctx, "bad_param", "address is invalid", {{"field", "payload.address"}});
        aida::vuln::chain::extraction_options_t options = extraction_options_from_ctx(ctx);
        aida::vuln::chain::function_snapshot_t snapshot = aida::vuln::chain::extract_function_snapshot(*ea, options);
        json data = {{"function_facts", aida::vuln::chain::to_json(snapshot)}};
        json nested_page;
        if (!apply_nested_pagination(ctx, "extract_function_facts", data, std::string(), nested_page))
            return error_envelope(ctx, nested_page.value("error", std::string("bad_page_path")), "nested page path is invalid", nested_page);
        return ok_envelope(ctx, data, json(), nested_page);
    }
    if (ctx.operation == "extract_function_batch")
    {
        aida::vuln::chain::extraction_options_t options = extraction_options_from_ctx(ctx);
        std::vector<ea_t> functions = function_locations_from_payload(ctx.payload);
        json page;
        if (functions.empty())
        {
            function_start_page_t starts = function_start_page(ctx, options.max_batch_functions);
            if (!starts.cursor_ok)
                return error_envelope(ctx, "cursor_expired", "cursor does not match this operation or database generation");
            functions = std::move(starts.starts);
            page = starts.page;
        }
        if (functions.empty())
        {
            json empty_batch;
            empty_batch["schema"] = aida::vuln::chain::k_chain_extraction_schema;
            empty_batch["module"] = module_identity();
            empty_batch["functions"] = json::array();
            empty_batch["statuses"] = json::array();
            empty_batch["complete"] = true;
            empty_batch["cancelled"] = false;
            empty_batch["timeout"] = false;
            empty_batch["reason"] = "empty_page";
            return ok_envelope(ctx, {{"batch", empty_batch}}, json(), page);
        }
        options.max_batch_functions = std::min(options.max_batch_functions, functions.size());
        aida::vuln::chain::function_batch_result_t batch = aida::vuln::chain::extract_function_batch(functions, options);
        json data = {{"batch", aida::vuln::chain::to_json(batch)}};
        json nested_page;
        if (!apply_nested_pagination(ctx, "extract_function_batch", data, std::string(), nested_page))
            return error_envelope(ctx, nested_page.value("error", std::string("bad_page_path")), "nested page path is invalid", nested_page);
        if (!page.empty())
            nested_page["function_page"] = page;
        return ok_envelope(ctx, data, json(), nested_page);
    }
    if (ctx.operation == "extract_xref_graph")
    {
        auto ea = payload_location(ctx.payload, "address");
        if (!ea)
            return error_envelope(ctx, "bad_param", "address is invalid", {{"field", "payload.address"}});
        aida::vuln::chain::extraction_options_t options = extraction_options_from_ctx(ctx);
        if (!ctx.payload.contains("layers"))
        {
            options.include_bytes = false;
            options.include_types = false;
            options.include_ctree = false;
            options.include_microcode = false;
            options.include_effects = false;
            options.include_xrefs = true;
            options.include_xref_indexes = true;
        }
        std::optional<ea_t> target = payload_location(ctx.payload, "target");
        aida::vuln::chain::function_snapshot_t snapshot = aida::vuln::chain::extract_function_snapshot(*ea, options);
        json data = {{"xref_graph", xref_graph_data(ctx, snapshot, target)}};
        json nested_page;
        if (!apply_nested_pagination(ctx, "extract_xref_graph", data, std::string(), nested_page))
            return error_envelope(ctx, nested_page.value("error", std::string("bad_page_path")), "nested page path is invalid", nested_page);
        return ok_envelope(ctx, data, json(), nested_page);
    }
    if (ctx.operation == "extract_path_window")
    {
        auto entry = payload_location(ctx.payload, "entry");
        auto target = payload_location(ctx.payload, "target");
        if (!entry || !target)
            return error_envelope(ctx, "bad_param", "entry and target are required", {{"required", json::array({"payload.entry", "payload.target"})}});
        aida::vuln::chain::extraction_options_t options = extraction_options_from_ctx(ctx);
        if (!ctx.payload.contains("layers"))
        {
            options.include_bytes = false;
            options.include_types = false;
            options.include_ctree = false;
            options.include_microcode = false;
            options.include_effects = true;
            options.include_xrefs = true;
            options.include_xref_indexes = true;
        }
        aida::vuln::chain::function_snapshot_t snapshot = aida::vuln::chain::extract_function_snapshot(*entry, options);
        aida::vuln::chain::path_trace_t trace = aida::vuln::chain::trace_path_corridor(snapshot, static_cast<std::uint64_t>(*entry), static_cast<std::uint64_t>(*target), path_options_from_ctx(ctx));
        json data = {{"function", aida::vuln::chain::to_json(snapshot.identity)}, {"path", aida::vuln::chain::to_json(trace)}, {"cache", aida::vuln::chain::to_json(snapshot.cache)}};
        json nested_page;
        if (!apply_nested_pagination(ctx, "extract_path_window", data, std::string(), nested_page))
            return error_envelope(ctx, nested_page.value("error", std::string("bad_page_path")), "nested page path is invalid", nested_page);
        return ok_envelope(ctx, data, json(), nested_page);
    }
    if (ctx.operation == "extract_type_facts")
    {
        auto ea = payload_location(ctx.payload, "address");
        if (!ea)
            return error_envelope(ctx, "bad_param", "address is invalid", {{"field", "payload.address"}});
        aida::vuln::chain::extraction_options_t options;
        options.include_bytes = false;
        options.include_xrefs = false;
        options.include_xref_indexes = false;
        options.include_ctree = false;
        options.include_microcode = false;
        options.include_effects = false;
        options.include_types = true;
        options.force_refresh = ctx.payload.value("force_refresh", false);
        aida::vuln::chain::function_snapshot_t snapshot = aida::vuln::chain::extract_function_snapshot(*ea, options);
        json statuses = json::array();
        for (const auto& status : snapshot.statuses)
            statuses.push_back(aida::vuln::chain::to_json(status));
        json data = {{"function", aida::vuln::chain::to_json(snapshot.identity)}, {"type", aida::vuln::chain::to_json(snapshot.type)}, {"statuses", statuses}, {"cache", aida::vuln::chain::to_json(snapshot.cache)}};
        json nested_page;
        if (!apply_nested_pagination(ctx, "extract_type_facts", data, std::string(), nested_page))
            return error_envelope(ctx, nested_page.value("error", std::string("bad_page_path")), "nested page path is invalid", nested_page);
        return ok_envelope(ctx, data, json(), nested_page);
    }
    if (ctx.operation == "resolve_cross_binary")
    {
        json modules = resolver_modules_from_ctx(ctx);
        json reference = ctx.payload.value("reference", json::object());
        json data = {{"resolver_index", aida::vuln::chain::build_cross_binary_resolver_index(modules)},
                     {"resolution", aida::vuln::chain::resolve_cross_binary_reference(modules, reference)}};
        json nested_page;
        if (!apply_nested_pagination(ctx, "resolve_cross_binary", data, std::string(), nested_page))
            return error_envelope(ctx, nested_page.value("error", std::string("bad_page_path")), "nested page path is invalid", nested_page);
        return ok_envelope(ctx, data, json(), nested_page);
    }
    if (ctx.operation == "case_study_self_check")
    {
        json data = {{"self_check", case_study_self_check_data(ctx)}};
        json nested_page;
        if (!apply_nested_pagination(ctx, "case_study_self_check", data, std::string(), nested_page))
            return error_envelope(ctx, nested_page.value("error", std::string("bad_page_path")), "nested page path is invalid", nested_page);
        return ok_envelope(ctx, data, json(), nested_page);
    }
    if (ctx.operation == "extraction_cache_status")
        return ok_envelope(ctx, {{"cache", aida::vuln::chain::extraction_cache_status()}});
    if (ctx.operation == "invalidate_extraction_cache")
    {
        if (!ctx.payload.value("confirm_destructive", false) || ctx.payload.value("reason", std::string()).empty())
            return error_envelope(ctx, "destructive_denied", "invalidate_extraction_cache requires confirm_destructive=true and a non-empty reason");
        aida::vuln::chain::clear_extraction_cache();
        return ok_envelope(ctx, {{"cleared", true}, {"cache", aida::vuln::chain::extraction_cache_status()}});
    }
    if (ctx.operation == "functions")
    {
        json all = json::array();
        const std::string filter = ctx.payload.value("filter", std::string());
        const bool include_segments = ctx.payload.value("include_segments", false);
        const size_t qty = get_func_qty();
        for (size_t i = 0; i < qty; ++i)
        {
            func_t* fn = getn_func(i);
            if (!fn)
                continue;
            json f = function_json(fn, include_segments);
            if (!filter.empty() && f.value("name", std::string()).find(filter) == std::string::npos)
                continue;
            all.push_back(f);
        }
        json page;
        json rows = page_vector(ctx, "functions", all, page);
        if (page.contains("error"))
            return error_envelope(ctx, "cursor_expired", "cursor does not match this operation or database generation");
        return ok_envelope(ctx, {{"functions", rows}, {"total_known", all.size()}}, json(), page);
    }
    if (ctx.operation == "function")
    {
        auto ea = payload_location(ctx.payload, "address");
        if (!ea)
            return error_envelope(ctx, "bad_param", "address is invalid", {{"field", "payload.address"}});
        func_t* fn = get_func(*ea);
        if (!fn)
            return error_envelope(ctx, "bad_param", "no function contains address", {{"address", fmt_ea(*ea)}});
        json d = function_json(fn, true);
        if (ctx.payload.value("include_xrefs", false))
        {
            json xrefs = json::array();
            xrefblk_t xb;
            for (bool ok = xb.first_to(fn->start_ea, XREF_ALL); ok; ok = xb.next_to())
                xrefs.push_back({{"from", fmt_ea(xb.from)}, {"to", fmt_ea(xb.to)}, {"type", xb.type}, {"iscode", xb.iscode != 0}});
            d["xrefs_to_start"] = xrefs;
        }
        return ok_envelope(ctx, d);
    }
    if (ctx.operation == "instructions")
    {
        auto ea = payload_location(ctx.payload, "address");
        if (!ea)
            return error_envelope(ctx, "bad_param", "address is invalid", {{"field", "payload.address"}});
        func_t* fn = get_func(*ea);
        if (!fn)
            return error_envelope(ctx, "bad_param", "no function contains address", {{"address", fmt_ea(*ea)}});
        json all = json::array();
        func_item_iterator_t fii(fn);
        for (bool ok = fii.first(); ok; ok = fii.next_head())
        {
            ea_t item = fii.current();
            qstring dis;
            generate_disasm_line(&dis, item, GENDSM_FORCE_CODE);
            tag_remove(&dis);
            all.push_back({{"ea", fmt_ea(item)}, {"rva", fmt_ea(item - static_cast<ea_t>(get_imagebase()))}, {"text", dis.c_str()}});
        }
        json page;
        json rows = page_vector(ctx, "instructions", all, page);
        if (page.contains("error"))
            return error_envelope(ctx, "cursor_expired", "cursor does not match this operation or database generation");
        return ok_envelope(ctx, {{"function", function_json(fn, false)}, {"instructions", rows}}, json(), page);
    }
    if (ctx.operation == "xrefs")
    {
        auto ea = payload_location(ctx.payload, "address");
        if (!ea)
            return error_envelope(ctx, "bad_param", "address is invalid", {{"field", "payload.address"}});
        const std::string direction = ctx.payload.value("direction", std::string("both"));
        const std::string kind = ctx.payload.value("kind", std::string("all"));
        const int flags = kind == "code" ? XREF_FAR : (kind == "data" ? XREF_DATA : XREF_ALL);
        json all = json::array();
        xrefblk_t xb;
        if (direction == "to" || direction == "both")
        {
            for (bool ok = xb.first_to(*ea, flags); ok; ok = xb.next_to())
                all.push_back({{"direction", "to"}, {"from", fmt_ea(xb.from)}, {"to", fmt_ea(xb.to)}, {"type", xb.type}, {"iscode", xb.iscode != 0}});
        }
        if (direction == "from" || direction == "both")
        {
            for (bool ok = xb.first_from(*ea, flags); ok; ok = xb.next_from())
                all.push_back({{"direction", "from"}, {"from", fmt_ea(xb.from)}, {"to", fmt_ea(xb.to)}, {"type", xb.type}, {"iscode", xb.iscode != 0}});
        }
        json page;
        json rows = page_vector(ctx, "xrefs", all, page);
        if (page.contains("error"))
            return error_envelope(ctx, "cursor_expired", "cursor does not match this operation or database generation");
        return ok_envelope(ctx, {{"address", fmt_ea(*ea)}, {"xrefs", rows}}, json(), page);
    }
    if (ctx.operation == "bytes")
    {
        auto ea = payload_location(ctx.payload, "address");
        if (!ea)
            return error_envelope(ctx, "bad_param", "address is invalid", {{"field", "payload.address"}});
        int size = int_param(ctx.payload, "size", 16, 1, 1048576);
        int max_bytes = int_param(ctx.budget, "max_bytes", 1048576, 1, 1048576);
        if (size > max_bytes)
            return error_envelope(ctx, "budget_exhausted", "requested size exceeds max_bytes budget", {{"size", size}, {"max_bytes", max_bytes}});
        std::vector<uint8_t> buf(static_cast<size_t>(size));
        ssize_t got = get_bytes(buf.data(), buf.size(), *ea);
        if (got < 0)
            return error_envelope(ctx, "bad_param", "failed to read bytes", {{"address", fmt_ea(*ea)}});
        json bytes = json::array();
        std::ostringstream hex;
        for (ssize_t i = 0; i < got; ++i)
        {
            bytes.push_back(buf[static_cast<size_t>(i)]);
            if (i)
                hex << ' ';
            hex << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buf[static_cast<size_t>(i)]);
        }
        return ok_envelope(ctx, {{"address", fmt_ea(*ea)}, {"size", got}, {"bytes", bytes}, {"hex", hex.str()}, {"complete", got == size}});
    }
    if (ctx.operation == "decompile")
    {
        auto ea = payload_location(ctx.payload, "address");
        if (!ea)
            return error_envelope(ctx, "bad_param", "address is invalid", {{"field", "payload.address"}});
        func_t* fn = get_func(*ea);
        if (!fn)
            return error_envelope(ctx, "bad_param", "no function contains address", {{"address", fmt_ea(*ea)}});
        json d;
        d["function"] = function_json(fn, true);
        d["pseudocode"] = agent_tools::helpers::get_pseudocode(fn->start_ea);
        d["hexrays_no_wait"] = true;
        d["preview_only"] = false;
        return ok_envelope(ctx, d);
    }
    if (ctx.operation == "imports")
    {
        json all = import_rows(1000000);
        json page;
        json rows = page_vector(ctx, "imports", all, page);
        if (page.contains("error"))
            return error_envelope(ctx, "cursor_expired", "cursor does not match this operation or database generation");
        return ok_envelope(ctx, {{"imports", rows}, {"total_known", all.size()}}, json(), page);
    }
    if (ctx.operation == "exports")
    {
        json all = entry_rows(1000000);
        json page;
        json rows = page_vector(ctx, "exports", all, page);
        if (page.contains("error"))
            return error_envelope(ctx, "cursor_expired", "cursor does not match this operation or database generation");
        return ok_envelope(ctx, {{"exports", rows}, {"total_known", all.size()}}, json(), page);
    }
    if (ctx.operation == "segments")
        return ok_envelope(ctx, {{"segments", segment_rows()}});
    if (ctx.operation == "corpus_snapshot")
        return ok_envelope(ctx, {{"module", module_identity()}, {"instance", instance_identity()}});
    if (ctx.operation == "evidence_fetch")
        return handle_evidence_fetch(ctx);
    return error_envelope(ctx, "unknown_operation", "unhandled operation", {{"operation", ctx.operation}});
}

agent_tools::tool_result_t handle_report_manage(const json& params)
{
    agent_tools::tool_result_t failure;
    request_ctx_t ctx = parse_request("ida_report_manage", params, report_ops(), failure);
    if (!failure.output.empty() || !failure.data.is_null())
        return failure;
    if (ctx.operation == "capabilities")
        return ok_envelope(ctx, make_capabilities(ctx.tool, report_ops()));
    if (ctx.operation == "get_report")
        return handle_report_fetch_like(ctx, false);
    if (ctx.operation == "export_report")
        return handle_report_fetch_like(ctx, false, true);
    if (ctx.operation == "evidence_fetch")
        return handle_evidence_fetch(ctx);
    if (ctx.operation == "list_reports")
    {
        json arr = json::array();
        const std::string verdict = ctx.payload.value("verdict", std::string());
        hydrate_reports_for_project(project_id_from_ctx(ctx));
        {
            auto& s = state();
            std::lock_guard<std::mutex> lock(s.mutex);
            for (const auto& kv : s.reports)
            {
                const auto& r = kv.second;
                const std::string rv = r.report.value("verdict", std::string("inconclusive"));
                if (!verdict.empty() && rv != verdict)
                    continue;
                arr.push_back({{"report_id", r.report_id}, {"job_id", r.job_id}, {"chain_id", r.chain_id}, {"created_at_ms", r.created_at_ms}, {"verdict", rv}, {"acceptance", r.report.value("acceptance", std::string("not_accepted"))}, {"content_hash", r.content_hash}});
            }
        }
        json page;
        json rows = page_vector(ctx, "list_reports", arr, page);
        if (page.contains("error"))
            return error_envelope(ctx, "cursor_expired", "cursor does not match this operation or database generation");
        return ok_envelope(ctx, {{"reports", rows}}, json(), page);
    }
    if (ctx.operation == "ledger_status")
        return ok_envelope(ctx, verify::engine().verdict_summary());
    if (ctx.operation == "ledger_save" || ctx.operation == "ledger_load")
    {
        const std::string action = ctx.operation == "ledger_save" ? "save" : "load";
        return ok_envelope(ctx, verify::engine().persist_ledger(action));
    }
    if (ctx.operation == "ledger_clear")
    {
        if (!ctx.payload.value("confirm_destructive", false) || ctx.payload.value("reason", std::string()).empty())
            return error_envelope(ctx, "destructive_denied", "ledger_clear requires confirm_destructive=true and a non-empty reason");
        return ok_envelope(ctx, verify::engine().persist_ledger("clear"));
    }
    return error_envelope(ctx, "unknown_operation", "unhandled operation", {{"operation", ctx.operation}});
}

agent_tools::tool_result_t handle_job_manage(const json& params)
{
    agent_tools::tool_result_t failure;
    request_ctx_t ctx = parse_request("ida_job_manage", params, job_ops(), failure);
    if (!failure.output.empty() || !failure.data.is_null())
        return failure;
    if (ctx.operation == "capabilities")
        return ok_envelope(ctx, make_capabilities(ctx.tool, job_ops()));
    if (ctx.operation == "status")
    {
        const std::string job_id = ctx.payload.value("job_id", std::string());
        auto job = get_job(job_id, project_id_from_ctx(ctx));
        if (!job)
            return error_envelope(ctx, "job_not_found", "job_id was not found", {{"job_id", job_id}});
        return ok_envelope(ctx, {{"job", job_to_json(*job)}}, job_to_json(*job));
    }
    if (ctx.operation == "result")
    {
        const std::string job_id = ctx.payload.value("job_id", std::string());
        auto job = get_job(job_id, project_id_from_ctx(ctx));
        if (!job)
            return error_envelope(ctx, "job_not_found", "job_id was not found", {{"job_id", job_id}});
        json resources = json::array();
        if (!job->report_id.empty())
        {
            auto rec = get_report_record(job->report_id, job->project_id);
            if (rec)
                resources = json::array({resource_for_report(*rec, "json"), resource_for_report(*rec, "markdown"), resource_for_report(*rec, "sarif")});
        }
        for (const auto& r : job->resources)
            resources.push_back(r);
        json data = {{"job", job_to_json(*job)}, {"result", job->result}};
        json page;
        if (!apply_nested_pagination(ctx, "job_result", data, "/result", page))
            return error_envelope(ctx, page.value("error", std::string("bad_page_path")), "nested page path is invalid", page);
        return ok_envelope(ctx, data, job_to_json(*job), page, json::array(), resources);
    }
    if (ctx.operation == "events")
    {
        const std::string job_id = ctx.payload.value("job_id", std::string());
        auto job = get_job(job_id, project_id_from_ctx(ctx));
        if (!job)
            return error_envelope(ctx, "job_not_found", "job_id was not found", {{"job_id", job_id}});
        return ok_envelope(ctx, {{"job_id", job_id}, {"events", job->events}, {"stale_generation", !job->generation.empty() && job->generation != generation_id()}}, job_to_json(*job));
    }
    if (ctx.operation == "list")
    {
        json all = json::array();
        const std::string state_filter = ctx.payload.value("state", std::string());
        hydrate_jobs_for_project(project_id_from_ctx(ctx));
        {
            auto& s = state();
            std::lock_guard<std::mutex> lock(s.mutex);
            for (const auto& kv : s.jobs)
            {
                if (!state_filter.empty() && kv.second.state != state_filter)
                    continue;
                all.push_back(job_to_json(kv.second));
            }
        }
        json page;
        json rows = page_vector(ctx, "jobs", all, page);
        if (page.contains("error"))
            return error_envelope(ctx, "cursor_expired", "cursor does not match this operation or database generation");
        return ok_envelope(ctx, {{"jobs", rows}}, json(), page);
    }
    if (ctx.operation == "cancel")
    {
        const std::string job_id = ctx.payload.value("job_id", std::string());
        if (!get_job(job_id, project_id_from_ctx(ctx)))
            return error_envelope(ctx, "job_not_found", "job_id was not found", {{"job_id", job_id}});
        if (!cancel_job_record(job_id))
            return error_envelope(ctx, "job_not_found", "job_id was not found", {{"job_id", job_id}});
        auto job = get_job(job_id, project_id_from_ctx(ctx));
        return ok_envelope(ctx, {{"cancelled", true}, {"job", job ? job_to_json(*job) : json::object()}}, job ? job_to_json(*job) : json());
    }
    if (ctx.operation == "resume")
    {
        const std::string job_id = ctx.payload.value("job_id", std::string());
        auto job = get_job(job_id, project_id_from_ctx(ctx));
        if (!job)
            return error_envelope(ctx, "job_not_found", "job_id was not found", {{"job_id", job_id}});
        if (job->tool != "ida_chain_manage" || !job->request.contains("payload"))
            return error_envelope(ctx, "job_conflict", "only ida_chain_manage jobs with saved payloads can be resumed", {{"job_id", job_id}, {"tool", job->tool}});
        json p;
        p["operation"] = "submit";
        p["request_id"] = ctx.request_id;
        p["payload"] = job->request["payload"];
        p["budget"] = job->request.value("budget", json::object());
        return handle_chain_manage(p);
    }
    if (ctx.operation == "diagnostics")
    {
        json d;
        d["engine"] = verify::engine().verdict_summary();
        d["in_flight_count"] = verify::engine().in_flight_count();
        d["auto_analysis_ok"] = auto_is_ok();
        d["modal_safety"] = {{"manage_waitbox_free", true}, {"manage_ui_cancel_free", true}, {"interactive_cancel_requires_explicit_option", true}};
        d["job_runtime"] = job_runtime().diagnostics();
        json states = json::object();
        hydrate_jobs_for_project(project_id_from_ctx(ctx));
        hydrate_reports_for_project(project_id_from_ctx(ctx));
        {
            auto& s = state();
            std::lock_guard<std::mutex> lock(s.mutex);
            for (const auto& kv : s.jobs)
                states[kv.second.state] = states.value(kv.second.state, 0) + 1;
            d["job_count"] = s.jobs.size();
            d["report_count"] = s.reports.size();
            d["index_count"] = s.indices.size();
            d["job_states"] = states;
        }
        return ok_envelope(ctx, d);
    }
    if (ctx.operation == "prune")
    {
        const uint64_t age = static_cast<uint64_t>(int_param(ctx.payload, "older_than_ms", 3600000, 0, 2147483647));
        const std::string sf = ctx.payload.value("state", std::string("all"));
        const uint64_t cutoff = now_ms() > age ? now_ms() - age : 0;
        size_t removed = 0;
        json removed_ids = json::array();
        hydrate_jobs_for_project(project_id_from_ctx(ctx));
        auto& s = state();
        std::lock_guard<std::mutex> lock(s.mutex);
        for (auto it = s.jobs.begin(); it != s.jobs.end(); )
        {
            const bool state_ok = sf == "all" || it->second.state == sf;
            if (state_ok && it->second.updated_at_ms < cutoff && !active_job_state(it->second.state))
            {
                const std::string project_id = it->second.project_id;
                const std::string job_id = it->second.job_id;
                if (!it->second.idempotency_scope.empty())
                    s.idempotency_jobs.erase(it->second.idempotency_scope);
                s.cancellation_tokens.erase(it->second.job_id);
                s.gateway_cancel_flags.erase(it->second.job_id);
                it = s.jobs.erase(it);
                aida::vuln::chain::delete_chain_job_record(project_id, job_id);
                removed_ids.push_back(job_id);
                ++removed;
            }
            else
                ++it;
        }
        return ok_envelope(ctx, {{"removed", removed}, {"job_ids", removed_ids}});
    }
    return error_envelope(ctx, "unknown_operation", "unhandled operation", {{"operation", ctx.operation}});
}

json forward_params(const request_ctx_t& ctx, const std::string& operation, const json& payload)
{
    json p;
    p["operation"] = operation;
    p["request_id"] = ctx.request_id;
    p["job_mode"] = ctx.job_mode;
    p["idempotency_key"] = ctx.idempotency_key;
    p["cursor"] = ctx.cursor;
    p["limit"] = ctx.limit;
    p["budget"] = ctx.budget;
    p["payload"] = payload;
    return p;
}

agent_tools::tool_result_t adopt_manage_result(const request_ctx_t& ctx, const agent_tools::tool_result_t& nested)
{
    if (nested.data.is_object() && nested.data.contains("ok"))
    {
        if (nested.success)
            return ok_envelope(ctx,
                               nested.data.value("data", json(nullptr)),
                               nested.data.value("job", json()),
                               nested.data.value("page", json()),
                               nested.data.value("warnings", json::array()),
                               nested.data.value("resources", json::array()));
        json err = nested.data.value("error", json::object());
        return error_envelope(ctx,
                              err.value("code", nested.error_code.empty() ? std::string("nested_error") : nested.error_code),
                              err.value("message", nested.output),
                              err.value("details", nested.data),
                              err.value("retryable", false));
    }
    if (nested.success)
        return ok_envelope(ctx, wrapped_tool_result(ctx.operation, nested));
    return error_envelope(ctx, nested.error_code.empty() ? "nested_error" : nested.error_code, nested.output, nested.data);
}

json registry_catalog_data()
{
    json data;
    data["schema"] = "aida.ida.mcp.registry.v1";
    data["public_tools"] = json::array();
    data["legacy_tools"] = json::array();
    data["internal_tools"] = json::array();
    data["counts"] = json::object({{"public", 0}, {"legacy", 0}, {"internal", 0}});
    for (const auto* tool : agent_tools::ToolRegistry::instance().get_all_tools())
    {
        if (!tool)
            continue;
        json entry;
        entry["name"] = tool->name;
        entry["category"] = tool->category;
        entry["read_only"] = tool->read_only;
        entry["destructive"] = tool->destructive;
        entry["deterministic"] = tool->deterministic;
        entry["visibility"] = tool->visibility;
        entry["required_indices"] = tool->required_indices;
        if (!tool->deprecated_by_tool.empty())
            entry["deprecated_by"] = {{"tool", tool->deprecated_by_tool}, {"operation", tool->deprecated_by_operation}};
        if (!tool->operations.empty())
        {
            entry["operations"] = json::array();
            for (const auto& op : tool->operations)
            {
                json oj;
                oj["operation"] = op.name;
                oj["description"] = op.description;
                oj["read_only"] = op.read_only;
                oj["destructive"] = op.destructive;
                oj["deterministic"] = op.deterministic;
                oj["job_mode"] = op.job_mode;
                oj["cache_policy"] = op.cache_policy;
                oj["default_timeout_ms"] = op.default_timeout_ms;
                oj["hard_timeout_ms"] = op.hard_timeout_ms;
                oj["required_indices"] = op.required_indices;
                oj["input_schema"] = op.input_schema;
                oj["output_schema"] = op.output_schema;
                entry["operations"].push_back(oj);
            }
        }
        if (tool->visibility == "public")
        {
            data["public_tools"].push_back(entry);
            data["counts"]["public"] = data["counts"].value("public", 0) + 1;
        }
        else if (tool->visibility == "internal")
        {
            data["internal_tools"].push_back(entry);
            data["counts"]["internal"] = data["counts"].value("internal", 0) + 1;
        }
        else
        {
            data["legacy_tools"].push_back(entry);
            data["counts"]["legacy"] = data["counts"].value("legacy", 0) + 1;
        }
    }
    return data;
}

json resource_catalog_data()
{
    json data;
    data["resources"] = json::array({
        {{"uri", "ida://binary-info"}, {"kind", "static"}},
        {{"uri", "ida://database-info"}, {"kind", "static"}},
        {{"uri", "ida://modules/static"}, {"kind", "module_re_static"}},
        {{"uri", "ida://modules/dynamic"}, {"kind", "module_re_dynamic"}},
        {{"uri", "ida://segments"}, {"kind", "static"}},
        {{"uri", "ida://imports"}, {"kind", "static"}},
        {{"uri", "ida://exports"}, {"kind", "static"}},
        {{"uri", "ida://corpus/current/manifest"}, {"kind", "corpus_manifest"}},
        {{"uri", "ida://cache/status"}, {"kind", "cache_status"}},
        {{"uri", "ida://jobs"}, {"kind", "job_list"}},
        {{"uri", "ida://chain/reports"}, {"kind", "report_list"}}
    });
    data["templates"] = json::array({
        "ida://function/{address}",
        "ida://address/{address}",
        "ida://module/{selector}",
        "ida://modules/{mode}",
        "ida://struct/{name}",
        "ida://import/{name}",
        "ida://export/{name}",
        "ida://xrefs/from/{addr}",
        "ida://chain/reports/{report_id}?format={format}",
        "ida://reports/exports/{report_id}.{format}",
        "ida://jobs/{job_id}/result",
        "ida://jobs/{job_id}/events",
        "ida://corpus/{project_id}/manifest",
        "ida://cache/{area}/status",
        "ida://evidence/{report_id}/{evidence_id}"
    });
    return data;
}

agent_tools::tool_result_t handle_discover_manage(const json& params)
{
    agent_tools::tool_result_t failure;
    request_ctx_t ctx = parse_request("ida_discover_manage", params, discover_ops(), failure);
    if (!failure.output.empty() || !failure.data.is_null())
        return failure;
    if (ctx.operation == "capabilities")
        return ok_envelope(ctx, make_capabilities(ctx.tool, discover_ops()));
    if (ctx.operation == "catalog")
        return ok_envelope(ctx, registry_catalog_data());
    if (ctx.operation == "resources")
        return ok_envelope(ctx, resource_catalog_data());
    if (ctx.operation == "instances")
        return ok_envelope(ctx, wrapped_tool_result("list_ida_instances", invoke_registered("list_ida_instances", json::object())));
    if (ctx.operation == "module")
    {
        json d;
        d["module"] = module_identity();
        d["binary_info"] = wrapped_tool_result("get_binary_info", invoke_registered("get_binary_info", json::object()));
        return ok_envelope(ctx, d, json(), json(), json::array(), json::array({{{"uri", "ida://corpus/current/manifest"}, {"kind", "corpus_manifest"}}}));
    }
    if (ctx.operation == "modules")
    {
        std::string mode = lowercase_ascii(scalar_to_string(ctx.payload.value("mode", json("both"))));
        std::string analysis = lowercase_ascii(scalar_to_string(ctx.payload.value("analysis", json("list"))));
        if (mode.empty())
            mode = "both";
        if (analysis.empty())
            analysis = "list";
        if (mode != "static" && mode != "dynamic" && mode != "both")
            return error_envelope(ctx, "bad_param", "mode must be static, dynamic, or both", {{"field", "payload.mode"}, {"actual", mode}});
        if (analysis != "list" && analysis != "details" && analysis != "analyze")
            return error_envelope(ctx, "bad_param", "analysis must be list, details, or analyze", {{"field", "payload.analysis"}, {"actual", analysis}});
        json warnings = json::array();
        const json d = module_re_data(ctx, warnings);
        return ok_envelope(ctx, d, json(), json(), warnings, json::array({{{"uri", "ida://modules/static"}, {"kind", "module_re_static"}}, {{"uri", "ida://modules/dynamic"}, {"kind", "module_re_dynamic"}}}));
    }
    if (ctx.operation == "functions")
        return adopt_manage_result(ctx, handle_extract_manage(forward_params(ctx, "functions", ctx.payload)));
    if (ctx.operation == "function")
        return adopt_manage_result(ctx, handle_extract_manage(forward_params(ctx, "function", ctx.payload)));
    if (ctx.operation == "imports")
        return adopt_manage_result(ctx, handle_extract_manage(forward_params(ctx, "imports", ctx.payload)));
    if (ctx.operation == "exports")
        return adopt_manage_result(ctx, handle_extract_manage(forward_params(ctx, "exports", ctx.payload)));
    if (ctx.operation == "segments")
        return adopt_manage_result(ctx, handle_extract_manage(forward_params(ctx, "segments", ctx.payload)));
    if (ctx.operation == "address")
    {
        auto ea = payload_location(ctx.payload, "address");
        if (!ea)
            return error_envelope(ctx, "bad_param", "address is invalid", {{"field", "payload.address"}});
        return ok_envelope(ctx, wrapped_tool_result("get_address_info", invoke_registered("get_address_info", {{"address", fmt_ea(*ea)}})));
    }
    return error_envelope(ctx, "unknown_operation", "unhandled operation", {{"operation", ctx.operation}});
}

agent_tools::tool_result_t handle_analysis_manage(const json& params)
{
    agent_tools::tool_result_t failure;
    request_ctx_t ctx = parse_request("ida_analysis_manage", params, analysis_ops(), failure);
    if (!failure.output.empty() || !failure.data.is_null())
        return failure;
    if (ctx.operation == "capabilities")
        return ok_envelope(ctx, make_capabilities(ctx.tool, analysis_ops()));
    if (ctx.operation == "status")
        return ok_envelope(ctx, {{"index_status", wrapped_tool_result("index_status", invoke_registered("index_status", json::object()))}, {"chain", verify::engine().verdict_summary()}});
    if (ctx.operation == "build_index")
    {
        json p;
        if (ctx.payload.contains("indices"))
            p["indices"] = ctx.payload["indices"];
        if (ctx.payload.contains("max_seconds"))
            p["max_seconds"] = ctx.payload["max_seconds"];
        return ok_envelope(ctx, wrapped_tool_result("build_index", invoke_registered("build_index", p)));
    }
    if (ctx.operation == "function")
    {
        auto ea = payload_location(ctx.payload, "address");
        if (!ea)
            return error_envelope(ctx, "bad_param", "address is invalid", {{"field", "payload.address"}});
        return ok_envelope(ctx, wrapped_tool_result("analyze_function", invoke_registered("analyze_function", {{"addr", fmt_ea(*ea)}, {"limit", ctx.payload.value("limit", 100)}})));
    }
    if (ctx.operation == "batch" || ctx.operation == "component")
        return ok_envelope(ctx, wrapped_tool_result(ctx.operation == "component" ? "analyze_component" : "analyze_batch", invoke_registered(ctx.operation == "component" ? "analyze_component" : "analyze_batch", ctx.payload)));
    if (ctx.operation == "control_flow" || ctx.operation == "data_flow" || ctx.operation == "callgraph")
    {
        auto ea = payload_location(ctx.payload, "address");
        if (!ea)
            return error_envelope(ctx, "bad_param", "address is invalid", {{"field", "payload.address"}});
        std::string tool = ctx.operation == "control_flow" ? "analyze_control_flow" : (ctx.operation == "data_flow" ? "analyze_data_flow" : "build_call_graph");
        json p = ctx.payload;
        p["address"] = fmt_ea(*ea);
        return ok_envelope(ctx, wrapped_tool_result(tool, invoke_registered(tool, p)));
    }
    if (ctx.operation == "taint")
        return ok_envelope(ctx, wrapped_tool_result("run_taint_analysis", invoke_registered("run_taint_analysis", ctx.payload)));
    if (ctx.operation == "vulnerability")
    {
        const std::string tool = ctx.payload.value("tool", std::string());
        json arguments = ctx.payload.value("arguments", json::object());
        if (tool.empty())
            return error_envelope(ctx, "bad_param", "payload.tool is required");
        const auto* def = agent_tools::ToolRegistry::instance().get_tool(tool);
        if (!def || def->destructive)
            return error_envelope(ctx, "bad_param", "payload.tool must name a registered read-only analysis tool", {{"tool", tool}});
        return ok_envelope(ctx, wrapped_tool_result(tool, invoke_registered(tool, arguments)));
    }
    return error_envelope(ctx, "unknown_operation", "unhandled operation", {{"operation", ctx.operation}});
}

agent_tools::tool_result_t handle_cache_manage(const json& params)
{
    agent_tools::tool_result_t failure;
    request_ctx_t ctx = parse_request("ida_cache_manage", params, cache_ops(), failure);
    if (!failure.output.empty() || !failure.data.is_null())
        return failure;
    if (ctx.operation == "capabilities")
        return ok_envelope(ctx, make_capabilities(ctx.tool, cache_ops()));
    if (ctx.operation == "status")
    {
        json d;
        d["extraction"] = aida::vuln::chain::extraction_cache_status();
        d["output_cache"] = wrapped_tool_result("list_outputs", invoke_registered("list_outputs", {{"op", "stats"}}));
        d["index"] = handle_project_manage(forward_params(ctx, "index_status", ctx.payload)).data;
        d["jobs"] = handle_job_manage(forward_params(ctx, "diagnostics", json::object())).data;
        return ok_envelope(ctx, d, json(), json(), json::array(), json::array({{{"uri", "ida://cache/status"}, {"kind", "cache_status"}}}));
    }
    if (ctx.operation == "build")
        return adopt_manage_result(ctx, handle_project_manage(forward_params(ctx, "index_build", ctx.payload)));
    if (ctx.operation == "index_status")
        return adopt_manage_result(ctx, handle_project_manage(forward_params(ctx, "index_status", ctx.payload)));
    if (ctx.operation == "index_page")
        return adopt_manage_result(ctx, handle_project_manage(forward_params(ctx, "index_page", ctx.payload)));
    if (ctx.operation == "extraction_status")
        return adopt_manage_result(ctx, handle_extract_manage(forward_params(ctx, "extraction_cache_status", ctx.payload)));
    if (ctx.operation == "invalidate_extraction")
        return adopt_manage_result(ctx, handle_extract_manage(forward_params(ctx, "invalidate_extraction_cache", ctx.payload)));
    if (ctx.operation == "output_cache")
        return ok_envelope(ctx, wrapped_tool_result("list_outputs", invoke_registered("list_outputs", ctx.payload)));
    if (ctx.operation == "prune_jobs")
        return adopt_manage_result(ctx, handle_job_manage(forward_params(ctx, "prune", ctx.payload)));
    return error_envelope(ctx, "unknown_operation", "unhandled operation", {{"operation", ctx.operation}});
}

std::string compact_hex(std::string text)
{
    std::string out;
    out.reserve(text.size());
    for (char c : text)
    {
        if (std::isxdigit(static_cast<unsigned char>(c)))
            out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return out;
}

std::string read_bytes_compact_hex(ea_t ea, size_t count)
{
    std::vector<uint8_t> bytes(count);
    ssize_t got = get_bytes(bytes.data(), bytes.size(), ea);
    if (got <= 0)
        return std::string();
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (ssize_t i = 0; i < got; ++i)
        ss << std::setw(2) << static_cast<unsigned>(bytes[static_cast<size_t>(i)]);
    return ss.str();
}

bool destructive_confirmed(const request_ctx_t& ctx, const json& payload)
{
    return (payload.value("confirm_destructive", false) || ctx.payload.value("confirm_destructive", false))
        && !payload.value("reason", ctx.payload.value("reason", std::string())).empty();
}

json mutation_receipt(const std::string& action, const json& payload, const json& before, bool applied)
{
    json r;
    r["receipt_id"] = hash_text(action + "|" + payload.dump() + "|" + before.dump() + "|" + generation_id());
    r["action"] = action;
    r["payload"] = payload;
    r["before"] = before;
    r["applied"] = applied;
    r["generation"] = generation_id();
    return r;
}

agent_tools::tool_result_t apply_or_preview_mutation(const request_ctx_t& ctx, const json& payload, bool apply)
{
    const std::string action = payload.value("operation", payload.value("action", std::string()));
    if (action.empty())
        return error_envelope(ctx, "bad_param", "mutation action is required");
    if (apply && !destructive_confirmed(ctx, payload))
        return error_envelope(ctx, "destructive_denied", "mutation requires confirm_destructive=true and a non-empty reason");

    json before = json::object();
    json direct_params = json::object();
    std::string direct_tool;
    if (action == "rename_function")
    {
        auto ea = payload_location(payload, "address");
        if (!ea)
            return error_envelope(ctx, "bad_param", "address is invalid", {{"field", "address"}});
        func_t* fn = get_func(*ea);
        if (!fn)
            return error_envelope(ctx, "bad_param", "no function contains address", {{"address", fmt_ea(*ea)}});
        qstring old_name;
        get_func_name(&old_name, fn->start_ea);
        before["address"] = fmt_ea(fn->start_ea);
        before["name"] = old_name.c_str();
        if (payload.contains("expected_old_name") && payload["expected_old_name"].is_string() && payload["expected_old_name"].get<std::string>() != before.value("name", std::string()))
            return error_envelope(ctx, "stale_generation", "expected_old_name does not match current function name", {{"expected", payload["expected_old_name"]}, {"actual", before["name"]}});
        direct_tool = "rename_function";
        direct_params = {{"address", fmt_ea(fn->start_ea)}, {"new_name", payload.value("new_name", std::string())}};
    }
    else if (action == "set_function_signature")
    {
        auto ea = payload_location(payload, "address");
        if (!ea)
            return error_envelope(ctx, "bad_param", "address is invalid", {{"field", "address"}});
        before["address"] = fmt_ea(*ea);
        direct_tool = "set_function_signature";
        direct_params = {{"address", fmt_ea(*ea)}, {"signature", payload.value("signature", std::string())}};
    }
    else if (action == "apply_type")
    {
        auto ea = payload_location(payload, "address");
        if (!ea)
            return error_envelope(ctx, "bad_param", "address is invalid", {{"field", "address"}});
        before["address"] = fmt_ea(*ea);
        direct_tool = "apply_type";
        direct_params = {{"address", fmt_ea(*ea)}, {"type", payload.value("type", std::string())}};
    }
    else if (action == "declare_type")
    {
        before["type_library"] = "local";
        direct_tool = "declare_type";
        direct_params = {{"declaration", payload.value("declaration", std::string())}};
    }
    else if (action == "set_comment")
    {
        auto ea = payload_location(payload, "address");
        if (!ea)
            return error_envelope(ctx, "bad_param", "address is invalid", {{"field", "address"}});
        const bool repeatable = payload.value("repeatable", false);
        qstring old_comment;
        get_cmt(&old_comment, *ea, repeatable);
        before["address"] = fmt_ea(*ea);
        before["comment"] = old_comment.c_str();
        before["repeatable"] = repeatable;
        if (payload.contains("expected_old_comment") && payload["expected_old_comment"].is_string() && payload["expected_old_comment"].get<std::string>() != before.value("comment", std::string()))
            return error_envelope(ctx, "stale_generation", "expected_old_comment does not match current comment", {{"expected", payload["expected_old_comment"]}, {"actual", before["comment"]}});
        direct_tool = repeatable ? "set_repeatable_comment" : "set_comment";
        direct_params = {{"address", fmt_ea(*ea)}, {"comment", payload.value("comment", std::string())}};
    }
    else if (action == "patch_bytes")
    {
        auto ea = payload_location(payload, "address");
        if (!ea)
            return error_envelope(ctx, "bad_param", "address is invalid", {{"field", "address"}});
        const std::string new_bytes = compact_hex(payload.value("bytes", std::string()));
        const std::string expected = compact_hex(payload.value("expected_old_bytes", std::string()));
        if ((new_bytes.size() & 1u) != 0 || new_bytes.empty())
            return error_envelope(ctx, "bad_param", "bytes must be a non-empty even-length hex string");
        if (apply && expected.empty())
            return error_envelope(ctx, "bad_param", "patch_bytes requires expected_old_bytes");
        const std::string current = read_bytes_compact_hex(*ea, expected.empty() ? new_bytes.size() / 2 : expected.size() / 2);
        before["address"] = fmt_ea(*ea);
        before["bytes"] = current;
        if (!expected.empty() && current != expected)
            return error_envelope(ctx, "stale_generation", "expected_old_bytes does not match current bytes", {{"expected", expected}, {"actual", current}});
        direct_tool = "patch_bytes";
        direct_params = {{"address", fmt_ea(*ea)}, {"bytes", new_bytes}};
    }
    else if (action == "delete_function")
    {
        auto ea = payload_location(payload, "address");
        if (!ea)
            return error_envelope(ctx, "bad_param", "address is invalid", {{"field", "address"}});
        func_t* fn = get_func(*ea);
        if (!fn)
            return error_envelope(ctx, "bad_param", "no function contains address", {{"address", fmt_ea(*ea)}});
        qstring old_name;
        get_func_name(&old_name, fn->start_ea);
        before["address"] = fmt_ea(fn->start_ea);
        before["name"] = old_name.c_str();
        if (payload.contains("expected_old_name") && payload["expected_old_name"].is_string() && payload["expected_old_name"].get<std::string>() != before.value("name", std::string()))
            return error_envelope(ctx, "stale_generation", "expected_old_name does not match current function name", {{"expected", payload["expected_old_name"]}, {"actual", before["name"]}});
        direct_tool = "delete_function";
        direct_params = {{"address", fmt_ea(fn->start_ea)}};
    }
    else if (action == "idb_save")
    {
        before["idb_path"] = idb_path();
        direct_tool = "idb_save";
        direct_params = payload;
    }
    else
    {
        return error_envelope(ctx, "unknown_operation", "unsupported mutation action", {{"action", action}});
    }

    json receipt = mutation_receipt(action, payload, before, apply);
    if (!apply)
        return ok_envelope(ctx, {{"receipt", receipt}});
    agent_tools::tool_result_t applied = invoke_registered(direct_tool, direct_params);
    json data;
    data["receipt"] = receipt;
    data["result"] = wrapped_tool_result(direct_tool, applied);
    if (!applied.success)
        return error_envelope(ctx, applied.error_code.empty() ? "mutation_failed" : applied.error_code, applied.output, data);
    return ok_envelope(ctx, data);
}

agent_tools::tool_result_t handle_mutation_manage(const json& params)
{
    agent_tools::tool_result_t failure;
    request_ctx_t ctx = parse_request("ida_mutation_manage", params, mutation_ops(), failure);
    if (!failure.output.empty() || !failure.data.is_null())
        return failure;
    if (ctx.operation == "capabilities")
        return ok_envelope(ctx, make_capabilities(ctx.tool, mutation_ops()));
    if (ctx.operation == "preview")
        return apply_or_preview_mutation(ctx, ctx.payload.value("mutation", json::object()), false);
    if (ctx.operation == "batch_preview" || ctx.operation == "batch_apply")
    {
        const bool apply = ctx.operation == "batch_apply";
        if (apply && !destructive_confirmed(ctx, ctx.payload))
            return error_envelope(ctx, "destructive_denied", "batch_apply requires confirm_destructive=true and a non-empty reason");
        json results = json::array();
        for (const auto& item : ctx.payload.value("items", json::array()))
        {
            json p = item;
            if (apply)
            {
                p["confirm_destructive"] = true;
                p["reason"] = ctx.payload.value("reason", std::string());
            }
            request_ctx_t item_ctx = ctx;
            item_ctx.payload = p;
            agent_tools::tool_result_t r = apply_or_preview_mutation(item_ctx, p, apply);
            results.push_back({{"ok", r.success}, {"data", r.data}, {"message", r.output}, {"error_code", r.error_code.empty() ? json(nullptr) : json(r.error_code)}});
            if (!r.success && apply)
                return error_envelope(ctx, r.error_code.empty() ? "mutation_failed" : r.error_code, "batch_apply stopped at first failed mutation", {{"results", results}});
        }
        return ok_envelope(ctx, {{"results", results}, {"applied", apply}});
    }
    return apply_or_preview_mutation(ctx, ctx.payload, true);
}

agent_tools::tool_result_t handle_diagnostics_manage(const json& params)
{
    agent_tools::tool_result_t failure;
    request_ctx_t ctx = parse_request("ida_diagnostics_manage", params, diagnostics_ops(), failure);
    if (!failure.output.empty() || !failure.data.is_null())
        return failure;
    if (ctx.operation == "capabilities")
        return ok_envelope(ctx, make_capabilities(ctx.tool, diagnostics_ops()));
    if (ctx.operation == "health")
        return ok_envelope(ctx, wrapped_tool_result("server_health", invoke_registered("server_health", json::object())));
    if (ctx.operation == "tool_registry")
        return ok_envelope(ctx, registry_catalog_data());
    if (ctx.operation == "index_status")
        return ok_envelope(ctx, wrapped_tool_result("index_status", invoke_registered("index_status", json::object())));
    if (ctx.operation == "jobs")
        return adopt_manage_result(ctx, handle_job_manage(forward_params(ctx, "diagnostics", json::object())));
    if (ctx.operation == "chain")
        return adopt_manage_result(ctx, handle_chain_manage(forward_params(ctx, "diagnostics", json::object())));
    if (ctx.operation == "resources")
        return ok_envelope(ctx, resource_catalog_data());
    if (ctx.operation == "self_check")
    {
        json d;
        d["chain_schema"] = aida::vuln::chain::to_json(aida::vuln::chain::chain_schema_self_check());
        d["chain_report"] = aida::vuln::chain::to_json(aida::vuln::chain::chain_report_self_check());
        d["chain_store"] = aida::vuln::chain::to_json(aida::vuln::chain::chain_store_self_check());
        json registry = registry_catalog_data();
        d["registry"] = registry["counts"];
        return ok_envelope(ctx, d);
    }
    return error_envelope(ctx, "unknown_operation", "unhandled operation", {{"operation", ctx.operation}});
}

json common_output_schema()
{
    return json::object({
        {"type", "object"},
        {"properties", {
            {"ok", {{"type", "boolean"}}},
            {"schema", {{"type", "string"}}},
            {"tool", {{"type", "string"}}},
            {"operation", {{"type", "string"}}},
            {"request_id", {{"type", "string"}}},
            {"instance", {{"type", "object"}}},
            {"module", {{"type", "object"}}},
            {"job", {{"type", json::array({"object", "null"})}}},
            {"page", {{"type", json::array({"object", "null"})}}},
            {"data", json::object()},
            {"warnings", {{"type", "array"}}},
            {"resources", {{"type", "array"}}},
            {"error", {{"type", json::array({"object", "null"})}}}
        }},
        {"required", json::array({"ok", "schema", "tool", "operation", "request_id", "instance", "module", "data", "warnings", "resources", "error"})},
        {"additionalProperties", true}
    });
}

void register_one(const std::string& name,
                  const std::string& category,
                  const std::string& description,
                  const std::vector<operation_meta_t>& metas,
                  std::function<agent_tools::tool_result_t(const json&)> handler,
                  bool read_only,
                  bool deterministic)
{
    agent_tools::tool_definition_t def;
    def.name = name;
    def.category = category;
    def.description = description;
    def.parameters = common_params(metas);
    def.handler = std::move(handler);
    def.read_only = read_only;
    def.destructive = false;
    def.deterministic = deterministic;
    def.output_schema = common_output_schema();
    def.required_indices = {};
    def.visibility = "public";
    for (const auto& meta : metas)
    {
        if (!meta.read_only)
            def.read_only = false;
        if (meta.destructive)
            def.destructive = true;
        if (!meta.deterministic)
            def.deterministic = false;
        agent_tools::tool_operation_t op;
        op.name = meta.name;
        op.description = meta.description;
        op.read_only = meta.read_only;
        op.destructive = meta.destructive;
        op.deterministic = meta.deterministic;
        op.job_mode = meta.job_mode;
        op.cache_policy = meta.cache_policy;
        op.default_timeout_ms = meta.default_timeout_ms;
        op.hard_timeout_ms = meta.hard_timeout_ms;
        op.required_indices = meta.required_indices;
        op.input_schema = payload_schema(meta);
        op.output_schema = common_output_schema();
        def.operations.push_back(std::move(op));
    }
    agent_tools::ToolRegistry::instance().register_tool(def);
}

}

inline void register_manage_tools()
{
    register_one(std::string("ida_chain_manage"),
                 std::string("ida_mcp_manage"),
                 std::string("Consolidated chain-verification MCP surface: validate, submit, start, status, cancel, resume, export, verify links, match boundaries, confirm triggers, list reports, fetch evidence, and diagnose verifier state."),
                 chain_ops(),
                 handle_chain_manage,
                 false,
                 false);
    register_one(std::string("ida_project_manage"),
                 std::string("ida_mcp_manage"),
                 std::string("Consolidated project, corpus, and index MCP surface for module inventory, corpus snapshots, corpus binding, index build/status, and export."),
                 project_ops(),
                 handle_project_manage,
                 false,
                 false);
    register_one(std::string("ida_extract_manage"),
                 std::string("ida_mcp_manage"),
                 std::string("Consolidated extraction and evidence MCP surface for functions, instructions, xrefs, bytes, decompilation, imports, exports, segments, corpus identity, and evidence fetch."),
                 extract_ops(),
                 handle_extract_manage,
                 false,
                 false);
    register_one(std::string("ida_discover_manage"),
                 std::string("ida_mcp_manage"),
                 std::string("Consolidated discovery MCP surface for public catalog, resources, live instances, static/dynamic module reverse engineering, functions, imports, exports, segments, and address lookup."),
                 discover_ops(),
                 handle_discover_manage,
                 true,
                 false);
    register_one(std::string("ida_analysis_manage"),
                 std::string("ida_mcp_manage"),
                 std::string("Consolidated analysis MCP surface for index status/build, function analysis, control/data flow, call graphs, taint analysis, and read-only vulnerability analysis routing."),
                 analysis_ops(),
                 handle_analysis_manage,
                 false,
                 false);
    register_one(std::string("ida_cache_manage"),
                 std::string("ida_mcp_manage"),
                 std::string("Consolidated cache MCP surface for extraction cache, project index pages, output cache, and job pruning."),
                 cache_ops(),
                 handle_cache_manage,
                 false,
                 false);
    register_one(std::string("ida_mutation_manage"),
                 std::string("ida_mcp_manage"),
                 std::string("Consolidated destructive IDB mutation MCP surface with previews, receipts, stale expected-old-value checks, confirmation, and reason capture."),
                 mutation_ops(),
                 handle_mutation_manage,
                 false,
                 false);
    register_one(std::string("ida_diagnostics_manage"),
                 std::string("ida_mcp_manage"),
                 std::string("Consolidated diagnostics MCP surface for health, registry visibility, resources, chain verifier state, index status, jobs, and self-checks."),
                 diagnostics_ops(),
                 handle_diagnostics_manage,
                 true,
                 false);
    register_one(std::string("ida_report_manage"),
                 std::string("ida_mcp_manage"),
                 std::string("Consolidated report and ledger MCP surface for report listing, retrieval, export, evidence lookup, and verifier ledger operations."),
                 report_ops(),
                 handle_report_manage,
                 false,
                 false);
    register_one(std::string("ida_job_manage"),
                 std::string("ida_mcp_manage"),
                 std::string("Consolidated diagnostics and job MCP surface for status, result retrieval, cancellation, resume, pruning, and runtime diagnostics."),
                 job_ops(),
                 handle_job_manage,
                 false,
                 false);
}

}
}
}
