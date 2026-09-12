#include "protocol_core_harness.hpp"
#include "../c03/assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/mcp/protocol/mcp_tool_contract.hpp"

#include <string_view>
#include <utility>

namespace aida::standalone::tests::mcp_compat {

namespace {

using aida::standalone::mcp::protocol::cancellation_token_t;
using aida::standalone::mcp::protocol::effect_lock_t;
using aida::standalone::mcp::protocol::mcp_result_t;
using aida::standalone::mcp::protocol::schema_runtime_t;
using aida::standalone::mcp::protocol::target_requirement_t;
using aida::standalone::mcp::protocol::tool_contract_t;
using aida::standalone::mcp::protocol::tool_effect_t;
using aida::standalone::mcp::protocol::invoke_tool_contract;
using json = aida::standalone::mcp::protocol::json;

tool_contract_t make_contract() {
    tool_contract_t contract;
    contract.name = "protocol_core_probe";
    contract.description = "Protocol core compatibility probe.";
    contract.input_schema = json{
        {"type", "object"},
        {"additionalProperties", false},
        {"properties", json{
            {"value", json{{"type", "integer"}}},
            {"pid", json{{"type", "integer"}}},
            {"bin_name", json{{"type", "string"}}},
        }},
        {"required", json::array({"value"})},
    };
    contract.output_schema = json{
        {"type", "object"},
        {"additionalProperties", false},
        {"properties", json{{"value", json{{"type", "integer"}}}}},
        {"required", json::array({"value"})},
    };
    contract.annotations = json{
        {"title", "Protocol Core Probe"},
        {"readOnlyHint", true},
        {"destructiveHint", false},
    };
    contract.target_policy.requirement = target_requirement_t::optional;
    contract.target_policy.accepts_pid = true;
    contract.target_policy.accepts_bin_name = true;
    contract.effect_policy.effect = tool_effect_t::workspace_read;
    contract.effect_policy.lock = effect_lock_t::workspace_shared;
    contract.effect_policy.read_only = true;
    return contract;
}

bool has_error_code(const mcp_result_t& result, std::string_view code) {
    const bool accepted = result.is_error() && result.error_code() == code &&
           result.envelope()["structuredContent"]["error"]["code"] == std::string(code);
	aida::analysis::c03_test::assertion_telemetry::record_assertion(
		accepted, code, __FILE__, __LINE__);
	return accepted;
}

}

bool run_protocol_core_harness(std::string& failure) {
    const auto reject = [&failure](std::string_view message) {
		aida::analysis::c03_test::assertion_telemetry::record_assertion(false, message, __FILE__, __LINE__);
        failure.assign(message.data(), message.size());
        return false;
    };

    schema_runtime_t cache_runtime(4);
    const json local_reference_schema = {
        {"$defs", json{{"positive", json{{"type", "integer"}, {"minimum", 1}}}}},
        {"type", "object"},
        {"additionalProperties", false},
        {"properties", json{{"value", json{{"$ref", "#/$defs/positive"}}}}},
        {"required", json::array({"value"})},
    };
    if (!cache_runtime.validate(local_reference_schema, json{{"value", 7}}).valid ||
        !cache_runtime.validate(local_reference_schema, json{{"value", 8}}).valid) {
        return reject("local schema references must compile and validate");
    }
    const auto cache_stats = cache_runtime.cache_stats();
    if (cache_stats.entries != 1 || cache_stats.misses != 1 || cache_stats.hits == 0) {
        return reject("schema runtime did not reuse its compiled validator");
    }
    if (cache_runtime.compile(json{{"$ref", "https://invalid.example/schema.json"}}).valid ||
        cache_runtime.compile(json{{"$id", "https://invalid.example/schema.json"}, {"type", "object"}}).valid) {
        return reject("schema runtime accepted a remote schema reference or identifier");
    }
    schema_runtime_t moved_runtime(2);
    schema_runtime_t moved_from_runtime(std::move(moved_runtime));
    if (moved_runtime.validate(json{{"type", "object"}}, json::object()).valid ||
        moved_runtime.cache_stats().entries != 0) {
        return reject("moved-from schema runtime was not safely inert");
    }

    json upstream_payload = {{"value", 7}};
    const json upstream_before = upstream_payload;
    const auto upstream_result = mcp_result_t::success(
        "Probe completed.",
        upstream_payload,
        json{{"adapter", "compat"}});
    const auto enriched_result = upstream_result.with_aida_metadata(json{{"contract", "protocol_core_probe"}});
    const json envelope = enriched_result.envelope();
    if (upstream_payload != upstream_before || envelope["structuredContent"] != upstream_before ||
        envelope["structuredContent"].contains("_meta") || envelope["content"].size() != 1 ||
        envelope["content"][0]["type"] != "text" || envelope["content"][0]["text"] != "Probe completed." ||
        envelope["isError"] || envelope["_meta"]["aida"]["adapter"] != "compat" ||
        envelope["_meta"]["aida"]["contract"] != "protocol_core_probe") {
        return reject("result envelope mutated structured content or omitted canonical metadata");
    }

    schema_runtime_t runtime(16);
    const tool_contract_t contract = make_contract();
    const auto definition = aida::standalone::mcp::protocol::validate_tool_contract(contract, runtime);
    if (!definition.valid) {
        return reject("valid protocol contract was rejected");
    }
    const json listed = contract.tool_list_entry();
    if (listed["inputSchema"] != contract.input_schema || listed["outputSchema"] != contract.output_schema ||
        listed["annotations"] != contract.annotations) {
        return reject("tool list entry does not preserve explicit schemas and annotations");
    }

    tool_contract_t invalid_effect = contract;
    invalid_effect.effect_policy.lock = effect_lock_t::debugger_lane;
    if (aida::standalone::mcp::protocol::validate_tool_contract(invalid_effect, runtime).valid) {
        return reject("inconsistent effect and lock policy was accepted");
    }

    const auto success_handler = [](const json& arguments, const cancellation_token_t&) {
        return mcp_result_t::success("Tool completed.", json{{"value", arguments["value"]}});
    };
    const auto effect_rejected = invoke_tool_contract(
        invalid_effect,
        json{{"value", 10}},
        success_handler,
        runtime);
    if (!has_error_code(effect_rejected, "MCP_TOOL_EFFECT_POLICY_REJECTED")) {
        return reject("effect policy violation did not produce the canonical effect error");
    }
    const auto valid_result = invoke_tool_contract(
        contract,
        json{{"value", 11}},
        success_handler,
        runtime,
        json{{"request", "compat"}});
    if (valid_result.is_error() || valid_result.envelope()["_meta"]["aida"]["tool"] != contract.name ||
        valid_result.envelope()["_meta"]["aida"]["effect"] != "workspace_read" ||
        valid_result.envelope()["structuredContent"]["value"] != 11) {
        return reject("valid invocation omitted contract provenance or structured output");
    }

    const auto invalid_input = invoke_tool_contract(
        contract,
        json{{"value", "not-an-integer"}},
        success_handler,
        runtime);
    if (!has_error_code(invalid_input, "MCP_TOOL_INPUT_INVALID")) {
        return reject("invalid input did not produce the canonical input error");
    }

    const auto invalid_output = invoke_tool_contract(
        contract,
        json{{"value", 13}},
        [](const json&, const cancellation_token_t&) {
            return mcp_result_t::success("Tool completed.", json{{"value", "not-an-integer"}});
        },
        runtime);
    if (!has_error_code(invalid_output, "MCP_TOOL_OUTPUT_INVALID")) {
        return reject("invalid output did not produce the canonical output error");
    }

    tool_contract_t target_required = contract;
    target_required.target_policy.requirement = target_requirement_t::required;
    const auto missing_target = invoke_tool_contract(
        target_required,
        json{{"value", 17}},
        success_handler,
        runtime);
    if (!has_error_code(missing_target, "MCP_TOOL_TARGET_POLICY_REJECTED")) {
        return reject("required target policy did not reject a selector-free invocation");
    }

    tool_contract_t target_independent = contract;
    target_independent.target_policy.requirement = target_requirement_t::independent;
    target_independent.target_policy.accepts_pid = false;
    target_independent.target_policy.accepts_bin_name = false;
    target_independent.input_schema["properties"].erase("pid");
    target_independent.input_schema["properties"].erase("bin_name");
    const auto unexpected_target = invoke_tool_contract(
        target_independent,
        json{{"value", 19}, {"pid", 101}},
        success_handler,
        runtime);
    if (!has_error_code(unexpected_target, "MCP_TOOL_TARGET_POLICY_REJECTED")) {
        return reject("target-independent tool accepted a target selector");
    }

    bool cancelled_handler_called = false;
    const auto cancelled = invoke_tool_contract(
        contract,
        json{{"value", 23}},
        [&cancelled_handler_called](const json&, const cancellation_token_t&) {
            cancelled_handler_called = true;
            return mcp_result_t::success("Tool completed.", json{{"value", 23}});
        },
        runtime,
        cancellation_token_t::create(true));
    if (cancelled_handler_called || !has_error_code(cancelled, "MCP_TOOL_CANCELLED")) {
        return reject("cancelled invocation reached the handler or lost its canonical error");
    }

    failure.clear();
	aida::analysis::c03_test::assertion_telemetry::record_assertion(
		true, "MCP protocol core contract satisfied", __FILE__, __LINE__);
    return true;
}

}
