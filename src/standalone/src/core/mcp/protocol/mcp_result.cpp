#include "mcp_result.hpp"

#include <utility>

namespace aida::standalone::mcp::protocol {

namespace {

bool is_metadata_object(const json& value) {
    return value.is_object();
}

std::string normalized_text(std::string value, const char* fallback) {
    if (value.empty()) {
        return fallback;
    }
    return value;
}

json merge_metadata(const json& current, const json& trusted) {
    json merged = current;
    for (auto it = trusted.begin(); it != trusted.end(); ++it) {
        merged[it.key()] = it.value();
    }
    return merged;
}

mcp_result_t metadata_failure(const char* field) {
    return mcp_result_t::failure(
        result_error_code_t::internal_error,
        "MCP result metadata is invalid.",
        json{{"field", field}});
}

}

std::string_view canonical_error_code(result_error_code_t code) noexcept {
    switch (code) {
    case result_error_code_t::cancelled:
        return "MCP_TOOL_CANCELLED";
    case result_error_code_t::invalid_input:
        return "MCP_TOOL_INPUT_INVALID";
    case result_error_code_t::invalid_output:
        return "MCP_TOOL_OUTPUT_INVALID";
    case result_error_code_t::target_policy_rejected:
        return "MCP_TOOL_TARGET_POLICY_REJECTED";
    case result_error_code_t::effect_policy_rejected:
        return "MCP_TOOL_EFFECT_POLICY_REJECTED";
    case result_error_code_t::invalid_contract:
        return "MCP_TOOL_CONTRACT_INVALID";
    case result_error_code_t::handler_failed:
        return "MCP_TOOL_HANDLER_FAILED";
    case result_error_code_t::internal_error:
        return "MCP_TOOL_INTERNAL_ERROR";
    }
    return "MCP_TOOL_INTERNAL_ERROR";
}

mcp_result_t mcp_result_t::success(
    std::string text,
    const json& structured_content,
    const json& aida_metadata) {
    if (!structured_content.is_object()) {
        return failure(
            result_error_code_t::invalid_output,
            "Tool structured content must be a JSON object.",
            json{{"field", "structuredContent"}});
    }
    if (!is_metadata_object(aida_metadata)) {
        return metadata_failure("aida_metadata");
    }

    mcp_result_t result;
    result.text_ = normalized_text(std::move(text), "Tool completed.");
    result.structured_content_ = structured_content;
    result.aida_metadata_ = aida_metadata;
    return result;
}

mcp_result_t mcp_result_t::failure(
    result_error_code_t code,
    std::string text,
    const json& details,
    const json& aida_metadata) {
    json normalized_details = details;
    if (!normalized_details.is_object()) {
        if (code == result_error_code_t::internal_error) {
            normalized_details = json{{"field", "details"}};
        } else {
            return failure(
                result_error_code_t::internal_error,
                "MCP result error details are invalid.",
                json{{"field", "details"}},
                aida_metadata.is_object() ? aida_metadata : json::object());
        }
    }
    if (!is_metadata_object(aida_metadata)) {
        if (code == result_error_code_t::internal_error) {
            return failure(
                result_error_code_t::internal_error,
                "MCP result metadata is invalid.",
                json{{"field", "aida_metadata"}});
        }
        return metadata_failure("aida_metadata");
    }

    const std::string_view canonical = canonical_error_code(code);
    const std::string canonical_string(canonical);
    mcp_result_t result;
    result.is_error_ = true;
    result.text_ = normalized_text(std::move(text), "Tool execution failed.");
    result.structured_content_ = json{
        {"error", json{
            {"code", canonical_string},
            {"message", result.text_},
            {"details", normalized_details},
        }},
    };
    result.aida_metadata_ = aida_metadata;
    result.aida_metadata_["error_code"] = canonical_string;
    result.error_code_.assign(canonical.data(), canonical.size());
    return result;
}

bool mcp_result_t::is_error() const noexcept {
    return is_error_;
}

std::string_view mcp_result_t::text() const noexcept {
    return text_;
}

const json& mcp_result_t::structured_content() const noexcept {
    return structured_content_;
}

const json& mcp_result_t::aida_metadata() const noexcept {
    return aida_metadata_;
}

std::string_view mcp_result_t::error_code() const noexcept {
    return error_code_;
}

json mcp_result_t::envelope() const {
    return json{
        {"content", json::array({json{{"type", "text"}, {"text", text_}}})},
        {"structuredContent", structured_content_},
        {"isError", is_error_},
        {"_meta", json{{"aida", aida_metadata_}}},
    };
}

mcp_result_t mcp_result_t::with_aida_metadata(const json& trusted_metadata) const {
    if (!is_metadata_object(trusted_metadata)) {
        return metadata_failure("trusted_metadata");
    }

    mcp_result_t result = *this;
    result.aida_metadata_ = merge_metadata(aida_metadata_, trusted_metadata);
    if (result.is_error_)
        result.aida_metadata_["error_code"] = result.error_code_;
    return result;
}

}
