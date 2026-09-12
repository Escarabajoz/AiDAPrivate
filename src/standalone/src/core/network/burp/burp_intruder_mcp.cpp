#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "burp_intruder_mcp.hpp"

#include "intruder_engine.hpp"
#include "param_miner.hpp"
#include "h2_editor.hpp"

#include "../../settings/standalone_compat.hpp"
#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace burp {

namespace {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

std::vector<uint8_t> b64_decode(const std::string& s);

const char* json_type_name(const json& j)
{
    if (j.is_object()) return "object";
    if (j.is_array()) return "array";
    if (j.is_string()) return "string";
    if (j.is_boolean()) return "boolean";
    if (j.is_number()) return "number";
    if (j.is_null()) return "null";
    return "other";
}

std::string json_shape(const json& j, size_t max_keys = 12)
{
    std::ostringstream oss;
    oss << json_type_name(j);
    if (j.is_object())
    {
        oss << "{";
        size_t n = 0;
        for (auto it = j.begin(); it != j.end() && n < max_keys; ++it, ++n)
        {
            if (n) oss << ",";
            oss << it.key() << ":" << json_type_name(it.value());
        }
        if (j.size() > max_keys) oss << ",...";
        oss << "}";
    }
    else if (j.is_array())
    {
        oss << "[" << j.size() << "]";
    }
    return oss.str();
}

const char* json_observed_type(const json& j)
{
    if (j.is_object()) return "object";
    if (j.is_array()) return "array";
    if (j.is_string()) return "string";
    if (j.is_boolean()) return "boolean";
    if (j.is_number_unsigned()) return "number_unsigned";
    if (j.is_number_integer()) return "number_integer";
    if (j.is_number_float()) return "number_float";
    if (j.is_null()) return "null";
    return "other";
}

const json* json_member(const json& obj, const char* key)
{
    if (!obj.is_object()) return nullptr;
    auto it = obj.find(key);
    if (it == obj.end()) return nullptr;
    return &(*it);
}

std::string range_text(uint64_t min_value, uint64_t max_value)
{
    return std::to_string(min_value) + ".." + std::to_string(max_value);
}

tool_result_t h2_field_error(const std::string& field, const json* value, const std::string& expected, const std::string& reason)
{
    const char* observed = value ? json_observed_type(*value) : "missing";
    json data;
    data["code"] = "invalid_field";
    data["field"] = field;
    data["expected"] = expected;
    data["observed_type"] = observed;
    data["reason"] = reason;
    diag::log_tagged_fmt("mcp_burp", "h2_send parse_error field=%s observed=%s expected=%s reason=%s",
        field.c_str(), observed, expected.c_str(), reason.c_str());
    return tool_result_t::error("invalid field '" + field + "': " + reason, data);
}

bool h2_parse_required_string(const json& params, const char* field, std::string& out, tool_result_t& err)
{
    const json* value = json_member(params, field);
    if (!value) {
        err = h2_field_error(field, nullptr, "string", "required string field is missing");
        return false;
    }
    if (!value->is_string()) {
        err = h2_field_error(field, value, "string", "must be a string");
        return false;
    }
    const auto* text = value->get_ptr<const json::string_t*>();
    if (!text) {
        err = h2_field_error(field, value, "string", "string storage is unavailable");
        return false;
    }
    out = *text;
    diag::log_tagged_fmt("mcp_burp", "h2_send parse_field field=%s outcome=ok type=%s len=%zu",
        field, json_observed_type(*value), out.size());
    return true;
}

bool h2_parse_optional_bool(const json& params, const char* field, bool default_value, bool& out, tool_result_t& err)
{
    const json* value = json_member(params, field);
    if (!value) {
        out = default_value;
        diag::log_tagged_fmt("mcp_burp", "h2_send parse_field field=%s outcome=default value=%d",
            field, static_cast<int>(out));
        return true;
    }
    if (!value->is_boolean()) {
        err = h2_field_error(field, value, "boolean", "must be a boolean");
        return false;
    }
    const auto* parsed = value->get_ptr<const json::boolean_t*>();
    if (!parsed) {
        err = h2_field_error(field, value, "boolean", "boolean storage is unavailable");
        return false;
    }
    out = *parsed;
    diag::log_tagged_fmt("mcp_burp", "h2_send parse_field field=%s outcome=ok type=%s value=%d",
        field, json_observed_type(*value), static_cast<int>(out));
    return true;
}

bool h2_json_to_u64(const json& value, uint64_t& out, std::string& reason)
{
    if (value.is_number_unsigned()) {
        const auto* parsed = value.get_ptr<const json::number_unsigned_t*>();
        if (!parsed) {
            reason = "unsigned integer storage is unavailable";
            return false;
        }
        out = static_cast<uint64_t>(*parsed);
        return true;
    }
    if (value.is_number_integer()) {
        const auto* parsed = value.get_ptr<const json::number_integer_t*>();
        if (!parsed) {
            reason = "integer storage is unavailable";
            return false;
        }
        if (*parsed < 0) {
            reason = "must not be negative";
            return false;
        }
        out = static_cast<uint64_t>(*parsed);
        return true;
    }
    if (value.is_number_float()) {
        reason = "must be an integer, not a floating-point number";
        return false;
    }
    reason = "must be an integer";
    return false;
}

bool h2_parse_bounded_u64(const json& params, const char* field, uint64_t default_value, uint64_t min_value, uint64_t max_value, uint64_t& out, tool_result_t& err)
{
    const json* value = json_member(params, field);
    const std::string expected = "integer " + range_text(min_value, max_value);
    if (!value) {
        out = default_value;
        diag::log_tagged_fmt("mcp_burp", "h2_send parse_field field=%s outcome=default value=%llu bounds=%s",
            field, static_cast<unsigned long long>(out), range_text(min_value, max_value).c_str());
        return true;
    }
    uint64_t parsed = 0;
    std::string reason;
    if (!h2_json_to_u64(*value, parsed, reason)) {
        err = h2_field_error(field, value, expected, reason);
        return false;
    }
    if (parsed < min_value || parsed > max_value) {
        err = h2_field_error(field, value, expected, "must be between " + range_text(min_value, max_value));
        return false;
    }
    out = parsed;
    diag::log_tagged_fmt("mcp_burp", "h2_send parse_field field=%s outcome=ok type=%s value=%llu bounds=%s",
        field, json_observed_type(*value), static_cast<unsigned long long>(out), range_text(min_value, max_value).c_str());
    return true;
}

bool h2_is_base64_text(const std::string& text)
{
    size_t symbols = 0;
    size_t padding = 0;
    bool seen_padding = false;
    for (unsigned char c : text) {
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        ++symbols;
        if (c == '=') {
            seen_padding = true;
            ++padding;
            if (padding > 2) return false;
            continue;
        }
        if (seen_padding) return false;
        if (c >= 'A' && c <= 'Z') continue;
        if (c >= 'a' && c <= 'z') continue;
        if (c >= '0' && c <= '9') continue;
        if (c == '+' || c == '/') continue;
        return false;
    }
    if (symbols == 0) return true;
    if (padding > 0 && (symbols % 4) != 0) return false;
    if ((symbols % 4) == 1) return false;
    return true;
}

bool h2_parse_pseudo_headers(const json& params, h2_editor::pseudo_headers_t& out, tool_result_t& err)
{
    const json* value = json_member(params, "pseudo_headers");
    if (!value) {
        diag::log_tagged_fmt("mcp_burp", "h2_send pseudo_headers_parse outcome=default method=%s path_len=%zu scheme=%s authority_len=%zu",
            out.method.c_str(), out.path.size(), out.scheme.c_str(), out.authority.size());
        return true;
    }
    if (!value->is_object()) {
        err = h2_field_error("pseudo_headers", value, "object", "must be an object");
        return false;
    }
    const char* keys[] = { "method", "path", "scheme", "authority" };
    std::string* targets[] = { &out.method, &out.path, &out.scheme, &out.authority };
    for (size_t i = 0; i < 4; ++i) {
        const json* member = json_member(*value, keys[i]);
        if (!member) {
            diag::log_tagged_fmt("mcp_burp", "h2_send pseudo_headers_field field=pseudo_headers.%s outcome=default len=%zu",
                keys[i], targets[i]->size());
            continue;
        }
        if (!member->is_string()) {
            err = h2_field_error(std::string("pseudo_headers.") + keys[i], member, "string", "pseudo-header value must be a string");
            return false;
        }
        const auto* text = member->get_ptr<const json::string_t*>();
        if (!text) {
            err = h2_field_error(std::string("pseudo_headers.") + keys[i], member, "string", "string storage is unavailable");
            return false;
        }
        *targets[i] = *text;
        diag::log_tagged_fmt("mcp_burp", "h2_send pseudo_headers_field field=pseudo_headers.%s outcome=ok len=%zu",
            keys[i], targets[i]->size());
    }
    diag::log_tagged_fmt("mcp_burp", "h2_send pseudo_headers_parse outcome=ok method=%s path_len=%zu scheme=%s authority_len=%zu",
        out.method.c_str(), out.path.size(), out.scheme.c_str(), out.authority.size());
    return true;
}

bool h2_parse_headers(const json& params, std::vector<std::pair<std::string, std::string>>& out, tool_result_t& err)
{
    const json* value = json_member(params, "headers");
    if (!value) {
        diag::log_tagged_fmt("mcp_burp", "h2_send headers_parse outcome=default count=0");
        return true;
    }
    json parsed;
    if (value->is_string()) {
        const auto* text = value->get_ptr<const json::string_t*>();
        if (!text) {
            err = h2_field_error("headers", value, "array or object", "headers string storage is unavailable");
            return false;
        }
        try {
            parsed = json::parse(*text);
            value = &parsed;
            diag::log_tagged_fmt("mcp_burp", "h2_send headers_parse string_json decoded_shape=%s", json_shape(parsed).c_str());
        } catch (...) {
            err = h2_field_error("headers", value, "array or object", "headers string must contain a JSON array or object");
            return false;
        }
    }
    if (value->is_object()) {
        size_t index = 0;
        for (auto it = value->begin(); it != value->end(); ++it) {
            const std::string field = "headers." + it.key();
            if (!it.value().is_string()) {
                err = h2_field_error(field, &it.value(), "string", "object-style header values must be strings");
                return false;
            }
            const auto* value_text = it.value().get_ptr<const json::string_t*>();
            if (!value_text) {
                err = h2_field_error(field, &it.value(), "string", "header value storage is unavailable");
                return false;
            }
            out.push_back({ it.key(), *value_text });
            diag::log_tagged_fmt("mcp_burp", "h2_send header_parse index=%zu shape=object-map outcome=ok name_len=%zu value_len=%zu",
                index, it.key().size(), value_text->size());
            ++index;
        }
        diag::log_tagged_fmt("mcp_burp", "h2_send headers_parse outcome=ok shape=object count=%zu", out.size());
        return true;
    }
    if (!value->is_array()) {
        err = h2_field_error("headers", value, "array or object", "must be an object map, an array of [name,value] arrays, or an array of {name,value} objects");
        return false;
    }
    size_t index = 0;
    for (const auto& entry : *value) {
        const std::string base = "headers[" + std::to_string(index) + "]";
        std::string name;
        std::string header_value;
        if (entry.is_array()) {
            if (entry.size() != 2) {
                err = h2_field_error(base, &entry, "array[2]", "header array entry must contain exactly two elements");
                return false;
            }
            if (!entry[0].is_string()) {
                err = h2_field_error(base + "[0]", &entry[0], "string", "header name must be a string");
                return false;
            }
            if (!entry[1].is_string()) {
                err = h2_field_error(base + "[1]", &entry[1], "string", "header value must be a string");
                return false;
            }
            const auto* name_text = entry[0].get_ptr<const json::string_t*>();
            const auto* value_text = entry[1].get_ptr<const json::string_t*>();
            if (!name_text || !value_text) {
                err = h2_field_error(base, &entry, "array[2]", "header string storage is unavailable");
                return false;
            }
            name = *name_text;
            header_value = *value_text;
            diag::log_tagged_fmt("mcp_burp", "h2_send header_parse index=%zu shape=array outcome=ok name_len=%zu value_len=%zu",
                index, name.size(), header_value.size());
        } else if (entry.is_object()) {
            const json* name_member = json_member(entry, "name");
            const json* value_member = json_member(entry, "value");
            if (!name_member) {
                err = h2_field_error(base + ".name", nullptr, "string", "header name field is missing");
                return false;
            }
            if (!value_member) {
                err = h2_field_error(base + ".value", nullptr, "string", "header value field is missing");
                return false;
            }
            if (!name_member->is_string()) {
                err = h2_field_error(base + ".name", name_member, "string", "header name must be a string");
                return false;
            }
            if (!value_member->is_string()) {
                err = h2_field_error(base + ".value", value_member, "string", "header value must be a string");
                return false;
            }
            const auto* name_text = name_member->get_ptr<const json::string_t*>();
            const auto* value_text = value_member->get_ptr<const json::string_t*>();
            if (!name_text || !value_text) {
                err = h2_field_error(base, &entry, "object", "header string storage is unavailable");
                return false;
            }
            name = *name_text;
            header_value = *value_text;
            diag::log_tagged_fmt("mcp_burp", "h2_send header_parse index=%zu shape=object outcome=ok name_len=%zu value_len=%zu",
                index, name.size(), header_value.size());
        } else {
            err = h2_field_error(base, &entry, "array pair or object pair", "header entry must be [name,value] or {name,value}");
            return false;
        }
        out.push_back({ std::move(name), std::move(header_value) });
        ++index;
    }
    diag::log_tagged_fmt("mcp_burp", "h2_send headers_parse outcome=ok count=%zu", out.size());
    return true;
}

bool h2_parse_body(const json& params, std::vector<uint8_t>& out, tool_result_t& err)
{
    const json* body_b64 = json_member(params, "body_b64");
    if (body_b64) {
        if (!body_b64->is_string()) {
            err = h2_field_error("body_b64", body_b64, "string", "body_b64 must be a string");
            return false;
        }
        const auto* text = body_b64->get_ptr<const json::string_t*>();
        if (!text) {
            err = h2_field_error("body_b64", body_b64, "string", "string storage is unavailable");
            return false;
        }
        if (!h2_is_base64_text(*text)) {
            err = h2_field_error("body_b64", body_b64, "base64 string", "must contain only base64 alphabet, padding, or whitespace");
            return false;
        }
        out = b64_decode(*text);
        diag::log_tagged_fmt("mcp_burp", "h2_send parse_field field=body_b64 outcome=ok type=%s b64_len=%zu body_len=%zu",
            json_observed_type(*body_b64), text->size(), out.size());
        return true;
    }
    const json* body = json_member(params, "body");
    if (body) {
        if (!body->is_string()) {
            err = h2_field_error("body", body, "string", "body must be a string");
            return false;
        }
        const auto* text = body->get_ptr<const json::string_t*>();
        if (!text) {
            err = h2_field_error("body", body, "string", "string storage is unavailable");
            return false;
        }
        out.assign(text->begin(), text->end());
        diag::log_tagged_fmt("mcp_burp", "h2_send parse_field field=body outcome=ok type=%s body_len=%zu",
            json_observed_type(*body), out.size());
        return true;
    }
    diag::log_tagged_fmt("mcp_burp", "h2_send parse_field field=body outcome=default body_len=0");
    return true;
}

bool h2_parse_raw_frames(const json& params, h2_editor::request_t& req, bool& raw_requested, tool_result_t& err)
{
    const json* raw = json_member(params, "raw_frames_b64");
    if (!raw) {
        raw_requested = false;
        diag::log_tagged_fmt("mcp_burp", "h2_send parse_field field=raw_frames_b64 outcome=default present=0");
        return true;
    }
    if (!raw->is_string()) {
        err = h2_field_error("raw_frames_b64", raw, "string", "raw_frames_b64 must be a string");
        return false;
    }
    const auto* text = raw->get_ptr<const json::string_t*>();
    if (!text) {
        err = h2_field_error("raw_frames_b64", raw, "string", "string storage is unavailable");
        return false;
    }
    if (!h2_is_base64_text(*text)) {
        err = h2_field_error("raw_frames_b64", raw, "base64 string", "must contain only base64 alphabet, padding, or whitespace");
        return false;
    }
    auto bytes = b64_decode(*text);
    std::vector<h2_editor::frame_t> frames;
    if (!h2_editor::decode_frames(bytes, frames)) {
        diag::log_tagged_fmt("mcp_burp", "h2_send raw_frames_decode_failed b64_len=%zu bytes=%zu",
            text->size(), bytes.size());
        err = h2_field_error("raw_frames_b64", raw, "base64-encoded HTTP/2 frames", "decoded bytes are not complete HTTP/2 frames");
        return false;
    }
    size_t decoded_wire_len = 0;
    for (const auto& frame : frames) {
        decoded_wire_len += 9 + frame.payload.size();
    }
    if (decoded_wire_len != bytes.size()) {
        diag::log_tagged_fmt("mcp_burp", "h2_send raw_frames_trailing_bytes b64_len=%zu bytes=%zu decoded_wire_len=%zu frames=%zu",
            text->size(), bytes.size(), decoded_wire_len, frames.size());
        err = h2_field_error("raw_frames_b64", raw, "base64-encoded HTTP/2 frames", "decoded bytes contain trailing partial frame data");
        return false;
    }
    req.use_raw_frames = true;
    req.raw_frames = std::move(frames);
    raw_requested = true;
    diag::log_tagged_fmt("mcp_burp", "h2_send parse_field field=raw_frames_b64 outcome=ok type=%s b64_len=%zu bytes=%zu frames=%zu",
        json_observed_type(*raw), text->size(), bytes.size(), req.raw_frames.size());
    return true;
}

uint64_t unix_ms_now()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

uint64_t intruder_elapsed_ms(const intruder::status_t& s)
{
    if (s.started_unix_ms == 0)
        return 0;
    const uint64_t end = s.finished_unix_ms != 0 ? s.finished_unix_ms : unix_ms_now();
    return end > s.started_unix_ms ? end - s.started_unix_ms : 0;
}

std::string intruder_completion_state(const intruder::status_t& s, size_t results)
{
    if (s.job_id == 0)
        return "not_found";
    if (s.running)
        return "running";
    if (s.total > 0 && s.sent >= s.total)
        return s.errors > 0 && results == 0 ? "completed_errors_only" : "completed";
    if (s.sent > 0 || results > 0)
        return "stopped_partial";
    return "created_no_requests";
}

size_t result_count(uint64_t job_id);

json status_to_json(const intruder::status_t& s)
{
    const size_t results = s.job_id == 0 ? 0 : result_count(s.job_id);
    const bool request_proof_ready = s.sent > 0 || results > 0;
    const bool terminal = s.job_id != 0 && !s.running;
    json r;
    r["job_id"] = s.job_id;
    r["total"] = s.total;
    r["sent"] = s.sent;
    r["errors"] = s.errors;
    r["requests_sent"] = s.sent;
    r["request_errors"] = s.errors;
    r["running"] = s.running;
    r["current_rps"] = s.current_rps;
    r["started_unix_ms"] = s.started_unix_ms;
    r["finished_unix_ms"] = s.finished_unix_ms;
    r["elapsed_ms"] = intruder_elapsed_ms(s);
    r["result_count"] = static_cast<uint64_t>(results);
    r["completion_state"] = intruder_completion_state(s, results);
    r["progress_fraction"] = s.total == 0 ? 0.0 : static_cast<double>(s.sent) / static_cast<double>(s.total);
    r["request_proof_ready"] = request_proof_ready;
    r["result_proof_ready"] = results > 0;
    r["functional_proof"] = request_proof_ready;
    r["proof_ready"] = request_proof_ready;
    r["proof_pending"] = s.job_id != 0 && !request_proof_ready && s.running;
    r["accepted_pending"] = s.job_id != 0 && !request_proof_ready && s.running;
    r["worker_terminal"] = terminal;
    r["terminal_no_request_evidence"] = terminal && !request_proof_ready;
    r["terminal_without_functional_proof"] = terminal && !request_proof_ready;
    r["proof_requirement"] = "request_sent_or_result_row";
    r["status_source"] = "intruder::status";
    return r;
}

size_t result_count(uint64_t job_id)
{
    return intruder::results(job_id, 0, 0).size();
}

std::vector<uint8_t> b64_decode(const std::string& s)
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

std::string b64_encode(const std::vector<uint8_t>& v)
{
    static const char* alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((v.size() + 2) / 3) * 4);
    size_t i = 0;
    while (i + 3 <= v.size()) {
        uint32_t n = (static_cast<uint32_t>(v[i]) << 16) | (static_cast<uint32_t>(v[i + 1]) << 8) | v[i + 2];
        out.push_back(alpha[(n >> 18) & 0x3F]);
        out.push_back(alpha[(n >> 12) & 0x3F]);
        out.push_back(alpha[(n >> 6) & 0x3F]);
        out.push_back(alpha[n & 0x3F]);
        i += 3;
    }
    if (i < v.size()) {
        uint32_t n = static_cast<uint32_t>(v[i]) << 16;
        if (i + 1 < v.size()) n |= static_cast<uint32_t>(v[i + 1]) << 8;
        out.push_back(alpha[(n >> 18) & 0x3F]);
        out.push_back(alpha[(n >> 12) & 0x3F]);
        if (i + 1 < v.size()) out.push_back(alpha[(n >> 6) & 0x3F]);
        else                  out.push_back('=');
        out.push_back('=');
    }
    return out;
}

static tool_result_t burp_intruder_start(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "intruder_start host=%s mode=%s",
        params.contains("host") && params["host"].is_string() ? params["host"].get<std::string>().c_str() : "<missing>",
        params.value("attack_mode", std::string("sniper")).c_str());
    intruder::config_t cfg;
    if (!params.contains("host") || !params["host"].is_string()) {
        return tool_result_t::error("host required");
    }
    cfg.host = params["host"].get<std::string>();
    if (params.contains("port")) {
        if (!params["port"].is_number_integer()) return tool_result_t::error("port must be an integer in 1..65535");
        long long v = params["port"].get<long long>();
        if (v < 1 || v > 65535) return tool_result_t::error("port must be in 1..65535");
        cfg.port = static_cast<uint16_t>(v);
    } else {
        cfg.port = 443;
    }
    if (params.contains("scheme") && params["scheme"].is_string()) cfg.scheme = params["scheme"].get<std::string>();

    if (params.contains("base_request_b64") && params["base_request_b64"].is_string()) {
        auto dec = b64_decode(params["base_request_b64"].get<std::string>());
        if (dec.empty()) return tool_result_t::error("base_request_b64 invalid");
        cfg.base_request = std::move(dec);
    } else if (params.contains("base_request") && params["base_request"].is_string()) {
        const std::string& s = params["base_request"].get_ref<const std::string&>();
        cfg.base_request.assign(s.begin(), s.end());
    } else {
        return tool_result_t::error("base_request or base_request_b64 required");
    }

    std::string am = params.value("attack_mode", std::string("sniper"));
    if (!intruder::parse_attack_mode(am, cfg.attack_mode)) return tool_result_t::error("invalid attack_mode");
    std::string em = params.value("engine_mode", std::string("http1_pooled"));
    if (!intruder::parse_engine_mode(em, cfg.engine_mode)) return tool_result_t::error("invalid engine_mode");

    if (params.contains("positions") && params["positions"].is_array()) {
        for (auto& it : params["positions"]) {
            if (!it.is_array() || it.size() < 2) continue;
            if (!it[0].is_number_unsigned() || !it[1].is_number_unsigned()) continue;
            size_t off = it[0].get<size_t>();
            size_t len = it[1].get<size_t>();
            if (len == 0 || len > 8192) continue;
            if (off > 10000000) continue;
            cfg.positions.push_back({ off, len });
        }
    }
    if (params.contains("payload_sets") && params["payload_sets"].is_array()) {
        for (auto& s : params["payload_sets"]) {
            std::vector<std::string> ps;
            if (s.is_array()) {
                for (auto& p : s) if (p.is_string()) ps.push_back(p.get<std::string>());
            }
            cfg.payload_sets.push_back(std::move(ps));
        }
    }

    cfg.concurrency = params.value("concurrency", static_cast<size_t>(32));
    cfg.requests_per_second_cap = params.value("rps_cap", static_cast<size_t>(0));
    cfg.total_requests_cap = params.value("total_cap", static_cast<size_t>(0));
    cfg.timeout_ms = params.value("timeout_ms", 15000);
    cfg.follow_redirects = params.value("follow_redirects", 0);
    cfg.race_gate_size = params.value("race_gate_size", static_cast<size_t>(30));
    cfg.race_warmup_count = params.value("race_warmup", 0);
    cfg.max_response_body_bytes = params.value("max_body_bytes", static_cast<size_t>(65536));

    uint64_t id = intruder::start(std::move(cfg));
    if (id == 0) {
        diag::log_tagged_fmt("mcp_burp", "intruder_start failed err=%s", intruder::last_error().c_str());
        return tool_result_t::error(std::string("intruder::start failed: ") + intruder::last_error());
    }
    diag::log_tagged_fmt("mcp_burp", "intruder_start ok job_id=%llu", static_cast<unsigned long long>(id));
    const intruder::status_t start_status = intruder::status(id);
    const json start_status_json = status_to_json(start_status);
    const bool request_proof_ready = start_status_json.value("request_proof_ready", false);
    json r;
    r["job_id"] = id;
    r["status"] = start_status_json;
    r["result_count"] = static_cast<uint64_t>(result_count(id));
    r["requests_sent"] = static_cast<uint64_t>(start_status.sent);
    r["request_errors"] = static_cast<uint64_t>(start_status.errors);
    r["engine_acceptance"] = "job_id_allocated";
    r["accepted_pending"] = !request_proof_ready && start_status.running;
    r["proof_pending"] = !request_proof_ready && start_status.running;
    r["proof_ready"] = request_proof_ready;
    r["request_proof_ready"] = request_proof_ready;
    r["result_proof_ready"] = r["result_count"].get<uint64_t>() > 0;
    r["functional_proof"] = request_proof_ready;
    r["worker_terminal"] = start_status.job_id != 0 && !start_status.running;
    r["terminal_no_request_evidence"] = start_status.job_id != 0 && !start_status.running && !request_proof_ready;
    r["terminal_without_functional_proof"] = start_status.job_id != 0 && !start_status.running && !request_proof_ready;
    r["proof_requirement"] = "request_sent_or_result_row";
    r["proof_kind"] = request_proof_ready ? "request_or_result" :
        (start_status.running ? "accepted_pending" : "terminal_no_request_evidence");
    const std::string message = request_proof_ready ? "intruder job started with request proof" :
        (start_status.running ? "intruder job accepted; request proof pending" : "intruder job accepted but worker is terminal without request proof");
    return tool_result_t::ok(message, r);
}

static tool_result_t burp_intruder_status(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "intruder_status job_id=%llu", params.contains("job_id") ? static_cast<unsigned long long>(params["job_id"].get<uint64_t>()) : 0ULL);
    if (!params.contains("job_id")) return tool_result_t::error("job_id required");
    uint64_t id = params["job_id"].get<uint64_t>();
    intruder::status_t s = intruder::status(id);
    if (s.job_id == 0) { diag::log_tagged_fmt("mcp_burp", "intruder_status not_found id=%llu", static_cast<unsigned long long>(id)); return tool_result_t::error("job not found"); }
    json r = status_to_json(s);
    diag::log_tagged_fmt("mcp_burp", "intruder_status ok id=%llu sent=%zu running=%d", static_cast<unsigned long long>(id), s.sent, (int)s.running);
    return tool_result_t::ok(r);
}

static tool_result_t burp_intruder_results(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "intruder_results job_id=%llu", params.contains("job_id") ? static_cast<unsigned long long>(params["job_id"].get<uint64_t>()) : 0ULL);
    if (!params.contains("job_id")) return tool_result_t::error("job_id required");
    uint64_t id = params["job_id"].get<uint64_t>();
    size_t start_idx = params.value("start", static_cast<size_t>(0));
    size_t max_count = params.value("max", static_cast<size_t>(100));
    auto rows = intruder::results(id, start_idx, max_count);
    const intruder::status_t status = intruder::status(id);
    const bool request_proof_ready = status.sent > 0 || !rows.empty();
    json arr = json::array();
    size_t error_count = 0;
    size_t successful_count = 0;
    for (auto& r : rows) {
        json e;
        e["index"] = r.index;
        e["payloads"] = r.payloads;
        e["status_code"] = r.status_code;
        e["response_size"] = r.response_size;
        e["latency_ms"] = r.latency_ms;
        e["error"] = r.error;
        e["error_msg"] = r.error_msg;
        e["preview"] = r.response_preview.substr(0, 1024);
        e["raw_b64"] = b64_encode(r.response_raw);
        if (r.error)
            ++error_count;
        else
            ++successful_count;
        arr.push_back(e);
    }
    json out;
    out["job_id"] = id;
    out["count"] = rows.size();
    out["error_count"] = static_cast<uint64_t>(error_count);
    out["successful_count"] = static_cast<uint64_t>(successful_count);
    out["window_start"] = static_cast<uint64_t>(start_idx);
    out["window_max"] = static_cast<uint64_t>(max_count);
    out["result_count"] = static_cast<uint64_t>(result_count(id));
    out["requests_sent"] = static_cast<uint64_t>(status.sent);
    out["request_errors"] = static_cast<uint64_t>(status.errors);
    out["request_proof_ready"] = request_proof_ready;
    out["result_proof_ready"] = !rows.empty();
    out["functional_proof"] = request_proof_ready;
    out["proof_ready"] = request_proof_ready;
    out["proof_pending"] = status.running && !request_proof_ready;
    out["accepted_pending"] = status.running && !request_proof_ready;
    out["terminal_no_request_evidence"] = status.job_id != 0 && !status.running && !request_proof_ready;
    out["proof_requirement"] = "request_sent_or_result_row";
    out["status"] = status_to_json(status);
    if (!rows.empty())
    {
        const auto& first = rows.front();
        out["first_result_index"] = static_cast<uint64_t>(first.index);
        out["first_result_status_code"] = first.status_code;
        out["first_result_error"] = first.error;
        out["first_result_latency_ms"] = first.latency_ms;
        out["first_result_response_size"] = static_cast<uint64_t>(first.response_size);
    }
    out["results"] = std::move(arr);
    diag::log_tagged_fmt("mcp_burp", "intruder_results ok id=%llu count=%zu errors=%zu successful=%zu",
        static_cast<unsigned long long>(id), rows.size(), error_count, successful_count);
    return tool_result_t::ok(out);
}

static tool_result_t burp_intruder_stop(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "intruder_stop job_id=%llu", params.contains("job_id") ? static_cast<unsigned long long>(params["job_id"].get<uint64_t>()) : 0ULL);
    if (!params.contains("job_id")) return tool_result_t::error("job_id required");
    uint64_t id = params["job_id"].get<uint64_t>();
    const intruder::status_t before = intruder::status(id);
    if (before.job_id == 0) { diag::log_tagged_fmt("mcp_burp", "intruder_stop not_found id=%llu", static_cast<unsigned long long>(id)); return tool_result_t::error("job not found"); }
    const size_t results_before = result_count(id);
    if (!intruder::stop(id)) { diag::log_tagged_fmt("mcp_burp", "intruder_stop not_found id=%llu", static_cast<unsigned long long>(id)); return tool_result_t::error("job not found"); }
    const intruder::status_t after = intruder::status(id);
    const size_t results_after = result_count(id);
    json out;
    out["job_id"] = id;
    out["stopped"] = true;
    out["status_before"] = status_to_json(before);
    out["status_after"] = status_to_json(after);
    out["results_before"] = static_cast<uint64_t>(results_before);
    out["results_after"] = static_cast<uint64_t>(results_after);
    diag::log_tagged_fmt("mcp_burp", "intruder_stop ok id=%llu", static_cast<unsigned long long>(id));
    return tool_result_t::ok("intruder job stopped", out);
}

static tool_result_t burp_intruder_list_jobs(const json& params)
{
    (void)params;
    diag::log_tagged_fmt("mcp_burp", "intruder_list_jobs entry");
    auto jobs = intruder::list_jobs();
    json arr = json::array();
    for (auto& s : jobs) {
        json e = status_to_json(s);
        arr.push_back(e);
    }
    json out;
    out["count"] = jobs.size();
    out["jobs"] = std::move(arr);
    diag::log_tagged_fmt("mcp_burp", "intruder_list_jobs ok count=%zu", jobs.size());
    return tool_result_t::ok(out);
}

static tool_result_t burp_intruder_clear(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "intruder_clear job_id=%llu", params.contains("job_id") ? static_cast<unsigned long long>(params["job_id"].get<uint64_t>()) : 0ULL);
    if (!params.contains("job_id")) return tool_result_t::error("job_id required");
    uint64_t id = params["job_id"].get<uint64_t>();
    const auto before_jobs = intruder::list_jobs();
    const intruder::status_t before = intruder::status(id);
    if (before.job_id == 0) { diag::log_tagged_fmt("mcp_burp", "intruder_clear not_found id=%llu", static_cast<unsigned long long>(id)); return tool_result_t::error("job not found"); }
    const size_t results_before = result_count(id);
    if (!intruder::clear(id)) { diag::log_tagged_fmt("mcp_burp", "intruder_clear not_found id=%llu", static_cast<unsigned long long>(id)); return tool_result_t::error("job not found"); }
    const auto after_jobs = intruder::list_jobs();
    json out;
    out["job_id"] = id;
    out["cleared"] = true;
    out["cleared_count"] = static_cast<uint64_t>(before_jobs.size() >= after_jobs.size() ? before_jobs.size() - after_jobs.size() : 0);
    out["before_count"] = static_cast<uint64_t>(before_jobs.size());
    out["after_count"] = static_cast<uint64_t>(after_jobs.size());
    out["results_before"] = static_cast<uint64_t>(results_before);
    out["results_after"] = 0;
    out["removed_job"] = status_to_json(before);
    diag::log_tagged_fmt("mcp_burp", "intruder_clear ok id=%llu", static_cast<unsigned long long>(id));
    return tool_result_t::ok("intruder job cleared", out);
}

static tool_result_t burp_param_miner_start(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "param_miner_start target=%s loc=%s",
        params.contains("target_url") && params["target_url"].is_string() ? params["target_url"].get<std::string>().c_str() : "<missing>",
        params.value("location", std::string("query")).c_str());
    if (!params.contains("target_url") || !params["target_url"].is_string()) {
        return tool_result_t::error("target_url required");
    }
    aida::burp::param_miner::config_t cfg;
    cfg.target_url = params["target_url"].get<std::string>();
    std::string loc_s = params.value("location", std::string("query"));
    if (!aida::burp::param_miner::parse_location(loc_s, cfg.location)) {
        return tool_result_t::error("invalid location");
    }
    if (params.contains("wordlist_id") && params["wordlist_id"].is_string()) {
        cfg.wordlist_id = params["wordlist_id"].get<std::string>();
    }
    if (params.contains("custom_words") && params["custom_words"].is_array()) {
        for (auto& w : params["custom_words"]) if (w.is_string()) cfg.custom_words.push_back(w.get<std::string>());
    }
    cfg.concurrency = params.value("concurrency", static_cast<size_t>(8));
    cfg.throttle_ms = params.value("throttle_ms", 0);
    cfg.timeout_ms = params.value("timeout_ms", 12000);
    cfg.baseline_count = params.value("baseline_count", static_cast<size_t>(5));
    cfg.diff_sigma_threshold = params.value("diff_sigma_threshold", 3.0);
    cfg.report_as_issues = params.value("report_as_issues", true);

    uint64_t id = aida::burp::param_miner::start(std::move(cfg));
    if (id == 0) { diag::log_tagged_fmt("mcp_burp", "param_miner_start failed err=%s", aida::burp::param_miner::last_error().c_str()); return tool_result_t::error(std::string("param_miner::start failed: ") + aida::burp::param_miner::last_error()); }
    diag::log_tagged_fmt("mcp_burp", "param_miner_start ok job_id=%llu", static_cast<unsigned long long>(id));
    json out;
    out["job_id"] = id;
    return tool_result_t::ok("param miner started", out);
}

static tool_result_t burp_param_miner_status(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "param_miner_status id=%llu", params.contains("id") ? static_cast<unsigned long long>(params["id"].get<uint64_t>()) : 0ULL);
    if (!params.contains("id")) return tool_result_t::error("id required");
    uint64_t id = params["id"].get<uint64_t>();
    auto s = aida::burp::param_miner::status(id);
    if (s.job_id == 0) { diag::log_tagged_fmt("mcp_burp", "param_miner_status not_found id=%llu", static_cast<unsigned long long>(id)); return tool_result_t::error("job not found"); }
    json out;
    out["job_id"] = s.job_id;
    out["total"] = s.total;
    out["tried"] = s.tried;
    out["hits"] = s.hits;
    out["running"] = s.running;
    diag::log_tagged_fmt("mcp_burp", "param_miner_status ok id=%llu tried=%zu hits=%zu running=%d", static_cast<unsigned long long>(id), s.tried, s.hits, (int)s.running);
    return tool_result_t::ok(out);
}

static tool_result_t burp_param_miner_results(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "param_miner_results id=%llu", params.contains("id") ? static_cast<unsigned long long>(params["id"].get<uint64_t>()) : 0ULL);
    if (!params.contains("id")) return tool_result_t::error("id required");
    uint64_t id = params["id"].get<uint64_t>();
    auto hits = aida::burp::param_miner::results(id);
    json arr = json::array();
    for (auto& h : hits) {
        json e;
        e["param"] = h.param_name;
        e["location"] = h.location_label;
        e["status"] = h.status_code;
        e["size"] = h.response_size;
        e["sigma"] = h.size_diff_sigma;
        e["cache_diff"] = h.cache_diff;
        e["echoed"] = h.echoed;
        e["header_echoed"] = h.header_echoed;
        e["evidence"] = h.evidence;
        arr.push_back(e);
    }
    json out;
    out["count"] = hits.size();
    out["hits"] = std::move(arr);
    diag::log_tagged_fmt("mcp_burp", "param_miner_results ok id=%llu count=%zu", static_cast<unsigned long long>(id), hits.size());
    return tool_result_t::ok(out);
}

static tool_result_t burp_param_miner_stop(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "param_miner_stop id=%llu", params.contains("id") ? static_cast<unsigned long long>(params["id"].get<uint64_t>()) : 0ULL);
    if (!params.contains("id")) return tool_result_t::error("id required");
    uint64_t id = params["id"].get<uint64_t>();
    const auto before = aida::burp::param_miner::status(id);
    if (before.job_id == 0) { diag::log_tagged_fmt("mcp_burp", "param_miner_stop not_found id=%llu", static_cast<unsigned long long>(id)); return tool_result_t::error("job not found"); }
    const auto hits_before = aida::burp::param_miner::results(id);
    if (!aida::burp::param_miner::stop(id)) { diag::log_tagged_fmt("mcp_burp", "param_miner_stop failed id=%llu", static_cast<unsigned long long>(id)); return tool_result_t::error("job not found"); }
    const auto after = aida::burp::param_miner::status(id);
    const auto hits_after = aida::burp::param_miner::results(id);
    json out;
    out["job_id"] = id;
    out["cleanup"] = {
        {"stop_requested", true},
        {"stop_succeeded", true},
        {"job_existed_before", before.job_id != 0},
        {"job_exists_after", after.job_id != 0},
        {"running_before", before.running},
        {"running_after", after.running},
        {"total_before", static_cast<uint64_t>(before.total)},
        {"tried_before", static_cast<uint64_t>(before.tried)},
        {"tried_after", static_cast<uint64_t>(after.tried)},
        {"hits_before", static_cast<uint64_t>(hits_before.size())},
        {"hits_after", static_cast<uint64_t>(hits_after.size())}
    };
    diag::log_tagged_fmt("mcp_burp", "param_miner_stop ok id=%llu running_before=%d running_after=%d tried_before=%zu tried_after=%zu hits_before=%zu hits_after=%zu",
        static_cast<unsigned long long>(id), before.running ? 1 : 0, after.running ? 1 : 0,
        before.tried, after.tried, hits_before.size(), hits_after.size());
    return tool_result_t::ok("param miner stopped", out);
}

static tool_result_t burp_h2_send(const json& params)
{
    const json* host_for_shape = json_member(params, "host");
    diag::log_tagged_fmt("mcp_burp", "h2_send entry params_shape=%s host_type=%s",
        json_shape(params).c_str(),
        host_for_shape ? json_observed_type(*host_for_shape) : "missing");
    if (!params.is_object()) {
        return h2_field_error("$", &params, "object", "params must be an object");
    }

    constexpr uint64_t kDefaultPort = 443;
    constexpr uint64_t kDefaultTimeoutMs = 15000;
    constexpr uint64_t kMaxTimeoutMs = 120000;
    constexpr uint64_t kMaxFlags = static_cast<uint64_t>(std::numeric_limits<uint32_t>::max());

    h2_editor::request_t req;
    tool_result_t parse_err;

    if (!h2_parse_required_string(params, "host", req.host, parse_err)) return parse_err;

    uint64_t parsed_port = 0;
    if (!h2_parse_bounded_u64(params, "port", kDefaultPort, 1, 65535, parsed_port, parse_err)) return parse_err;
    req.port = static_cast<uint16_t>(parsed_port);

    uint64_t parsed_timeout = 0;
    if (!h2_parse_bounded_u64(params, "timeout_ms", kDefaultTimeoutMs, 1, kMaxTimeoutMs, parsed_timeout, parse_err)) return parse_err;
    req.timeout_ms = static_cast<int>(parsed_timeout);

    bool offline_validate = false;
    if (!h2_parse_optional_bool(params, "offline_validate", false, offline_validate, parse_err)) return parse_err;

    diag::log_tagged_fmt("mcp_burp", "h2_send core_params_ok host_len=%zu port=%u timeout_ms=%d offline_validate=%d",
        req.host.size(), static_cast<unsigned>(req.port), req.timeout_ms, static_cast<int>(offline_validate));

    if (offline_validate) {
        diag::log_tagged_fmt("mcp_burp", "h2_send offline_validate host=%s port=%u timeout_ms=%d",
            req.host.c_str(), static_cast<unsigned>(req.port), req.timeout_ms);
        h2_editor::frame_t settings;
        settings.type = 4;
        settings.flags = 0;
        settings.stream_id = 0;
        std::vector<uint8_t> wire = h2_editor::encode_frame(settings);
        std::vector<h2_editor::frame_t> frames;
        bool decoded = h2_editor::decode_frames(wire, frames);
        const bool offline_ok = decoded && frames.size() == 1 && frames[0].type == 4 && frames[0].stream_id == 0;
        json out;
        out["ok"] = offline_ok;
        out["offline_validate"] = true;
        out["frames"] = frames.size();
        out["raw_wire_out_b64"] = b64_encode(wire);
        out["body_size"] = 0;
        out["latency_ms"] = 0;
        diag::log_tagged_fmt("mcp_burp", "h2_send offline_validate result ok=%d frames=%zu wire_len=%zu",
            static_cast<int>(offline_ok), frames.size(), wire.size());
        return tool_result_t::ok(out);
    }

    bool raw_requested = false;
    if (!h2_parse_raw_frames(params, req, raw_requested, parse_err)) return parse_err;
    if (raw_requested) {
        diag::log_tagged_fmt("mcp_burp", "h2_send raw_frames mode frames=%zu", req.raw_frames.size());
    } else {
        if (!h2_parse_pseudo_headers(params, req.pseudo, parse_err)) return parse_err;
        if (!h2_parse_headers(params, req.headers, parse_err)) return parse_err;
        if (!h2_parse_body(params, req.body, parse_err)) return parse_err;

        uint64_t parsed_flags = 0;
        if (!h2_parse_bounded_u64(params, "flags", static_cast<uint64_t>(req.flags), 0, kMaxFlags, parsed_flags, parse_err)) return parse_err;
        req.flags = static_cast<uint32_t>(parsed_flags);
    }
    diag::log_tagged_fmt("mcp_burp", "h2_send dispatch host=%s port=%u method=%s path_len=%zu has_query=%d headers=%zu body_len=%zu use_raw=%d raw_frames=%zu timeout_ms=%d",
        req.host.c_str(), static_cast<unsigned>(req.port), req.pseudo.method.c_str(),
        req.pseudo.path.size(), (int)(req.pseudo.path.find('?') != std::string::npos),
        req.headers.size(), req.body.size(), (int)req.use_raw_frames, req.raw_frames.size(), req.timeout_ms);

    h2_editor::response_t r = h2_editor::send(req);
    json out;
    out["ok"] = r.ok;
    out["status_code"] = r.status_code;
    out["latency_ms"] = r.latency_ms;
    out["error_msg"] = r.error_msg;
    json hdrs = json::array();
    for (auto& h : r.headers) {
        json e = json::array();
        e.push_back(h.first);
        e.push_back(h.second);
        hdrs.push_back(e);
    }
    out["headers"] = std::move(hdrs);
    out["body_b64"] = b64_encode(r.body);
    out["body_size"] = r.body.size();
    out["raw_wire_in_b64"]  = b64_encode(r.raw_wire_in);
    out["raw_wire_out_b64"] = b64_encode(r.raw_wire_out);
    diag::log_tagged_fmt("mcp_burp", "h2_send result ok=%d status=%d latency=%llums err_len=%zu headers=%zu body_len=%zu wire_in=%zu wire_out=%zu",
        (int)r.ok, r.status_code, static_cast<unsigned long long>(r.latency_ms), r.error_msg.size(),
        r.headers.size(), r.body.size(), r.raw_wire_in.size(), r.raw_wire_out.size());
    if (!r.ok) {
        return tool_result_t::error(r.error_msg.empty() ? std::string("h2_send_failed") : r.error_msg);
    }
    return tool_result_t::ok(out);
}

}

void register_intruder_tools(mcp_standalone::server_t& srv)
{
    register_compat(srv, {
        "burp_intruder_manage", "burp_intruder",
        "Manage Intruder/Turbo attack jobs. Actions: start, status, results, stop, list_jobs, clear.",
        {{"action", "string", "start|status|results|stop|list_jobs|clear", true},
         {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "start") return burp_intruder_start(p);
            if (action == "status") return burp_intruder_status(p);
            if (action == "results") return burp_intruder_results(p);
            if (action == "stop") return burp_intruder_stop(p);
            if (action == "list_jobs") return burp_intruder_list_jobs(p);
            if (action == "clear") return burp_intruder_clear(p);
            return compat_unknown_action("burp_intruder_manage", action);
        },
        false });

    register_compat(srv, {
        "burp_param_miner_manage", "burp_param_miner",
        "Manage hidden parameter discovery jobs. Actions: start, status, results, stop.",
        {{"action", "string", "start|status|results|stop", true},
         {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "start") return burp_param_miner_start(p);
            if (action == "status") return burp_param_miner_status(p);
            if (action == "results") return burp_param_miner_results(p);
            if (action == "stop") return burp_param_miner_stop(p);
            return compat_unknown_action("burp_param_miner_manage", action);
        },
        false });

    register_compat(srv, {
        "burp_h2_send", "burp_h2",
        "Send a single, fully user-controlled HTTP/2 request. Supports pseudo-header overrides, "
        "explicit stream flags, and a raw frame bytes mode for spec violations.",
        {
            { "host", "string", "Target host", true },
            { "port", "number", "Target port 1..65535 (default 443)", false },
            { "timeout_ms", "number", "Timeout in ms 1..120000 (default 15000)", false },
            { "pseudo_headers", "object", "Object {method, path, scheme, authority}", false },
            { "headers", "array|object|string", "Headers as object map, JSON string, array of [name, value], or array of {name, value} string pairs", false },
            { "body", "string", "Body text", false },
            { "body_b64", "string", "Body, base64 encoded (preferred for binary)", false },
            { "flags", "number", "uint32 bitfield: 1=END_STREAM 2=END_HEADERS 4=PADDED 8=PRIORITY", false },
            { "raw_frames_b64", "string", "Pre-encoded HTTP/2 frames as base64 (raw mode bypasses HEADERS/DATA construction)", false },
            { "offline_validate", "boolean", "Validate HTTP/2 frame encode/decode without opening a socket", false }
        },
        burp_h2_send, false });

    diag::log_tagged("burp", "intruder_mcp_registered");
}

}
}
