#include "mcp_production_core_harness.hpp"

#include "../../../src/core/analysis/workspace/overlay_journal.hpp"
#include "../../../src/core/mcp/compat/c03_compatibility_registration.hpp"
#include "../../../src/core/mcp/compat/ida_contracts_generated.hpp"
#include "../../../src/core/mcp/registry/tool_registry.hpp"
#include "../../analysis_workspace/workspace_fixture_builder.hpp"
#include "../assertion_telemetry/assertion_telemetry.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <exception>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace aida::analysis::c03_test::mcp_production_core {
namespace {

using json = nlohmann::json;
using test_fixture::analysis_contract_pe64;
using test_fixture::analyze_workspace;
using test_fixture::close_workspace;
using test_fixture::fixture_error_t;
using test_fixture::fixture_root_t;
using test_fixture::install_services;
using test_fixture::open_workspace;
using test_fixture::write_bytes_fixture;

void require(bool condition, const std::string& message)
{
    assertion_telemetry::record_assertion(
        condition, message, __FILE__, __LINE__);
    if (!condition)
        throw fixture_error_t(message);
}

mcp_standalone::tool_def_t independent_tool(
    std::string name,
    std::function<mcp_standalone::tool_result_t(const json&)> handler)
{
    mcp_standalone::tool_def_t tool;
    tool.name = std::move(name);
    tool.description = "bounded production registry harness tool";
    tool.target_independent = true;
    tool.input_schema = json{
        {"type", "object"},
        {"additionalProperties", false},
        {"properties", json{{"value", json{{"type", "integer"}}}}},
        {"required", json::array()}};
    tool.output_schema = json{
        {"type", "object"},
        {"additionalProperties", false},
        {"properties", json{{"ok", json{{"type", "boolean"}}}}},
        {"required", json::array({"ok"})}};
    tool.annotations = json::object();
    tool.handler = std::move(handler);
    return tool;
}

void verify_inventory(mcp_standalone::tool_registry_t& registry)
{
    const auto tools = registry.snapshot_tools();
    std::set<std::string> actual;
    for (const auto& tool : tools) {
        require(actual.insert(tool.name).second,
            "production registry contains a duplicate tool name");
        require(tool.visibility ==
                    mcp_standalone::tool_visibility_t::external_visible &&
                    tool.production_registry_dispatch &&
                    tool.input_schema.is_object() &&
                    tool.output_schema.is_object() &&
                    tool.annotations.is_object() &&
                    static_cast<bool>(tool.handler || tool.workspace_handler),
            "registered compatibility tool lacks its production contract or handler");
    }

    std::set<std::string> expected;
    const auto* contracts =
        aida::standalone::mcp::compat::contracts();
    for (std::size_t index = 0;
         index < aida::standalone::mcp::compat::contract_count(); ++index)
        expected.emplace(contracts[index].name);
    for (const auto name :
         aida::standalone::mcp::compat::k_aida_extension_names)
        expected.emplace(name);
    require(actual == expected &&
                actual.size() ==
                    aida::standalone::mcp::compat::k_union_tool_count &&
                actual.find("py_eval") == actual.end() &&
                actual.find("list_instances") != actual.end(),
            "production registry inventory differs from the exact 92-name union");
}

void verify_targetless_dispatch(mcp_standalone::tool_registry_t& registry)
{
    const auto converted = registry.call_registered_tool(
        "int_convert", json{{"inputs", json{{"text", "42"}}}});
    require(converted.success && converted.data.is_object() &&
                converted.data.contains("result") &&
                converted.data["result"].is_array() &&
                converted.data["result"].size() == 1 &&
                converted.meta.contains("aida") &&
                converted.meta["aida"].value(
                    "contract_name", std::string()) == "int_convert",
            "target-independent generated handler did not use production dispatch");

    const auto malformed = registry.call_registered_tool(
        "int_convert", json{{"inputs", 42}});
    require(!malformed.success &&
                malformed.error_code == "MCP_TOOL_INPUT_SCHEMA_INVALID",
            "production registry accepted malformed generated input");

    const auto instances = registry.call_registered_tool(
        "list_instances", json::object());
    require(instances.success && instances.data.is_object() &&
                instances.data.contains("instances") &&
                instances.data["instances"].is_array(),
            "proxy-local list_instances did not use production registry state");
}

void verify_registry_guards()
{
    mcp_standalone::tool_registry_t registry;
    require(registry.register_tool(independent_tool(
                "bounded", [](const json&) {
                    return mcp_standalone::tool_result_t::ok(
                        json{{"ok", true}});
                })),
            "bounded registry tool did not register");
    require(!registry.register_tool(independent_tool(
                 "bounded", [](const json&) {
                     return mcp_standalone::tool_result_t::ok(
                         json{{"ok", true}});
                 })),
             "production registry accepted a duplicate tool");
    require(registry.register_tool(independent_tool(
                 "decompile_function", [](const json&) {
                     return mcp_standalone::tool_result_t::ok(
                         json{{"ok", true}});
                 })),
             "decompile duplicate fixture did not register");
    require(!registry.register_tool(independent_tool(
                 "decompile_function", [](const json&) {
                     return mcp_standalone::tool_result_t::ok(
                         json{{"ok", true}});
                 })),
             "production registry replaced a duplicate decompile tool");

    auto malformed_output = independent_tool(
        "malformed_output", [](const json&) {
            return mcp_standalone::tool_result_t::ok(
                json{{"ok", "not_boolean"}});
        });
    require(registry.register_tool(std::move(malformed_output)),
            "malformed-output fixture did not register");
    const auto output = registry.call_registered_tool(
        "malformed_output", json::object());
    require(!output.success &&
                output.error_code == "MCP_TOOL_OUTPUT_SCHEMA_INVALID",
            "production registry delivered schema-invalid output");

    auto throwing = independent_tool(
        "throwing", [](const json&) -> mcp_standalone::tool_result_t {
            throw std::runtime_error("bounded handler exception");
        });
    require(registry.register_tool(std::move(throwing)),
            "throwing fixture did not register");
    const auto exception = registry.call_registered_tool(
        "throwing", json::object());
    require(!exception.success &&
                exception.error_code == "MCP_TOOL_HANDLER_EXCEPTION",
            "production registry leaked a handler exception");

    const auto cancelled_token =
        mcp_standalone::make_call_cancel_token(true);
    mcp_standalone::direct_dispatch_options_t cancelled_options;
    cancelled_options.cancellation = cancelled_token;
    const auto cancelled = registry.call_registered_tool(
        "bounded", json::object(), std::move(cancelled_options));
    require(!cancelled.success &&
                cancelled.error_code == "MCP_TOOL_CANCELLED",
            "production registry started a pre-cancelled invocation");

    mcp_standalone::direct_dispatch_options_t deadline_options;
    deadline_options.deadline_ms = 1;
    const auto expired = registry.call_registered_tool(
        "bounded", json::object(), std::move(deadline_options));
    require(!expired.success &&
                expired.error_code == "MCP_TOOL_DEADLINE_EXPIRED",
            "production registry started an expired invocation");

    require(registry.set_dispatch_capacity(1),
            "production registry rejected a valid bounded capacity");
    std::mutex mutex;
    std::condition_variable condition;
    bool entered = false;
    bool released = false;
    auto blocking = independent_tool(
        "blocking", [&](const json&) {
            std::unique_lock<std::mutex> lock(mutex);
            entered = true;
            condition.notify_all();
            condition.wait(lock, [&released] { return released; });
            return mcp_standalone::tool_result_t::ok(json{{"ok", true}});
        });
    require(registry.register_tool(std::move(blocking)),
            "blocking fixture did not register");
    mcp_standalone::tool_result_t first;
    std::thread worker([&] {
        first = registry.call_registered_tool("blocking", json::object());
    });
    bool observed_entry = false;
    {
        std::unique_lock<std::mutex> lock(mutex);
        observed_entry = condition.wait_for(
            lock, std::chrono::seconds(5), [&entered] { return entered; });
    }
    mcp_standalone::tool_result_t rejected;
    if (observed_entry)
        rejected = registry.call_registered_tool("bounded", json::object());
    {
        std::lock_guard<std::mutex> lock(mutex);
        released = true;
    }
    condition.notify_all();
    worker.join();
    require(observed_entry && first.success && !rejected.success &&
                rejected.error_code == "MCP_TOOL_CAPACITY_REJECT" &&
                registry.active_dispatches() == 0,
            "production registry capacity accounting did not fail closed");
}

void verify_workspace_dispatch(mcp_standalone::tool_registry_t& registry)
{
    fixture_root_t root("mcp_production_core");
    const auto first_path = write_bytes_fixture(
        root.path() / "first" / "mcp-first.exe",
        analysis_contract_pe64(0x81));
    const auto second_path = write_bytes_fixture(
        root.path() / "second" / "mcp-second.exe",
        analysis_contract_pe64(0x82));
    std::shared_ptr<analysis_workspace_t> first;
    std::shared_ptr<analysis_workspace_t> second;
    try {
        first = open_workspace(first_path, "mcp-first.exe");
        second = open_workspace(second_path, "mcp-second.exe");
        install_services(first);
        install_services(second);
        analyze_workspace(first, 1);
        analyze_workspace(second, 1);

        const auto ambiguous = registry.call_registered_tool(
            "list_funcs", json{{"queries", json::object()}});
        require(!ambiguous.success &&
                    (ambiguous.error_code == "TARGET_REQUIRED" ||
                     ambiguous.error_code == "TARGET_AMBIGUOUS"),
                "multiple workspaces did not require an explicit selector");

        const auto conflict = registry.call_registered_tool(
            "list_funcs", json{{"bin_name", "mcp-first.exe"},
                {"pid", 7}, {"queries", json::object()}});
        require(!conflict.success &&
                    conflict.error_code == "TARGET_CONFLICT",
                "production routing accepted conflicting selectors");

        const auto listed = registry.call_registered_tool(
            "list_funcs", json{{"bin_name", "mcp-first.exe"},
                {"queries", json{{"offset", 0}, {"count", 64}}}});
        require(listed.success && listed.data.is_object() &&
                    listed.data.contains("result") &&
                    listed.data["result"].is_array() &&
                    listed.data["result"].size() == 1 &&
                    listed.data["result"][0].contains("data") &&
                    listed.data["result"][0]["data"].is_array() &&
                    !listed.data["result"][0]["data"].empty(),
                "production workspace handler did not return exact generated output");

        const auto overlay_before = first->overlay_revision();
        mcp_standalone::tool_def_t stale_tool;
        stale_tool.name = "stale_read_fixture";
        stale_tool.description = "generation fence fixture";
        stale_tool.read_only = true;
        stale_tool.input_schema = json{{"type", "object"},
            {"additionalProperties", false},
            {"properties", json{{"bin_name", json{{"type", "string"}}}}},
            {"required", json::array({"bin_name"})}};
        stale_tool.output_schema = json{{"type", "object"},
            {"additionalProperties", false},
            {"properties", json{{"ok", json{{"type", "boolean"}}}}},
            {"required", json::array({"ok"})}};
        stale_tool.annotations = json::object();
        require(registry.register_tool(std::move(stale_tool),
            [](const json&,
               const mcp_standalone::workspace_request_context_t& context) {
                const auto image = context.workspace->normalized_image();
                if (!image || image->address_mappings.empty())
                    return mcp_standalone::tool_result_t::error(
                        "mapped image unavailable", "NO_IMAGE", json::object());
                const auto mapping = std::find_if(
                    image->address_mappings.begin(),
                    image->address_mappings.end(), [](const auto& item) {
                        return item.size != 0 &&
                            (item.target_space ==
                                 address_space_id_t::relative_virtual ||
                             item.target_space ==
                                 address_space_id_t::virtual_address);
                    });
                if (mapping == image->address_mappings.end())
                    return mcp_standalone::tool_result_t::error(
                        "mapped address unavailable", "NO_ADDRESS", json::object());
                overlay_transaction_request_t transaction;
                transaction.expected_revision =
                    context.workspace->overlay_revision();
                overlay_operation_t operation;
                operation.kind = overlay_operation_kind_t::comment;
                operation.address.space = mapping->target_space;
                operation.address.value = mapping->target_start;
                operation.address.architecture = image->architecture;
                operation.address.mode = image->architecture_mode;
                operation.text = "read fence transition";
                transaction.operations.push_back(std::move(operation));
                const auto committed =
                    context.workspace->overlay()->transact(transaction);
                if (!committed)
                    return mcp_standalone::tool_result_t::error(
                        committed.error().message,
                        committed.error().stable_code());
                return mcp_standalone::tool_result_t::ok(
                    json{{"ok", true}});
            }), "stale read fixture did not register");
        const auto stale = registry.call_registered_tool(
            "stale_read_fixture", json{{"bin_name", "mcp-first.exe"}});
        require(!stale.success && stale.error_code == "TARGET_STALE" &&
                    first->overlay_revision() > overlay_before,
                "read-only result was not fenced after workspace revision change");

        const auto unsafe_revision = first->overlay_revision();
        const auto debugger = registry.call_registered_tool(
            "dbg_status", json{{"bin_name", "mcp-first.exe"}});
        require(!debugger.success &&
                    first->overlay_revision() == unsafe_revision,
                "strict-unavailable safe debugger capability did not fail closed");

        close_workspace(second, true);
        second.reset();
        const auto unique = registry.call_registered_tool(
            "list_funcs", json{{"queries", json::object()}});
        require(unique.success,
                "single open workspace did not permit selector omission");
        close_workspace(first, true);
        first.reset();
        const auto closed = registry.call_registered_tool(
            "list_funcs", json{{"bin_name", "mcp-first.exe"},
                {"queries", json::object()}});
        require(!closed.success &&
                    (closed.error_code == "TARGET_NOT_FOUND" ||
                     closed.error_code == "TARGET_CLOSED"),
                "closed workspace generation remained routable");
    } catch (...) {
        if (first)
            close_workspace(first, true);
        if (second)
            close_workspace(second, true);
        throw;
    }
}

}

int run()
{
    try {
        verify_registry_guards();
        mcp_standalone::tool_registry_t registry;
        mcp_standalone::register_c03_compatibility_tools(registry);
        verify_inventory(registry);
        verify_targetless_dispatch(registry);
        verify_workspace_dispatch(registry);
        std::cout << "mcp production registry core harness passed\n";
        return 0;
    } catch (const std::exception& error) {
        assertion_telemetry::record_exception(error.what());
        std::cerr << "mcp production registry core harness failed: "
                  << error.what() << '\n';
        return 1;
    }
}

}
