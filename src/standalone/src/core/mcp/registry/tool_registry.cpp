#include "tool_registry.hpp"

#include "../protocol/schema_runtime.hpp"
#include "../../analysis/workspace/analysis_workspace.hpp"
#include "../../analysis/workspace/workspace_registry.hpp"

#include <algorithm>
#include <exception>
#include <limits>
#include <memory>
#include <utility>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace mcp_standalone {
namespace {

thread_local std::string current_diagnostic_id;
thread_local std::string current_request_id;
thread_local std::string current_tool_name;
thread_local std::uint64_t current_deadline_ms = 0;
thread_local std::atomic<bool>* current_cancellation = nullptr;

std::uint64_t monotonic_ms() noexcept {
    return static_cast<std::uint64_t>(GetTickCount64());
}

bool externally_visible(const tool_def_t& tool) noexcept {
    return tool.visibility == tool_visibility_t::external_visible;
}

tool_result_t dispatch_error(std::string text, std::string code,
                             json details = json::object()) {
    details["disposition"] = "not_started";
    return tool_result_t::error(text, code, details);
}

std::optional<std::uint32_t> parse_pid(const json& value) {
    std::uint64_t parsed = 0;
    if (value.is_number_unsigned()) {
        parsed = value.get<std::uint64_t>();
    } else if (value.is_number_integer()) {
        const auto signed_value = value.get<std::int64_t>();
        if (signed_value <= 0)
            return std::nullopt;
        parsed = static_cast<std::uint64_t>(signed_value);
    } else {
        return std::nullopt;
    }
    if (parsed == 0 || parsed >
            static_cast<std::uint64_t>((std::numeric_limits<std::uint32_t>::max)()))
        return std::nullopt;
    return static_cast<std::uint32_t>(parsed);
}

workspace_request_context_t make_workspace_context(
    const tool_def_t& tool, const json& arguments,
    const direct_dispatch_options_t& options,
    tool_result_t& failure) {
    workspace_request_context_t context;
    if (!arguments.is_object()) {
        failure = dispatch_error("Tool arguments must be an object.",
            "MCP_TOOL_INPUT_SCHEMA_INVALID",
            json{{"stable_code", "arguments_not_object"}});
        return context;
    }

    const bool has_binary = arguments.contains("binary_id") &&
        !arguments.at("binary_id").is_null();
    const bool has_name = arguments.contains("bin_name") &&
        !arguments.at("bin_name").is_null();
    const bool has_pid = arguments.contains("pid") &&
        !arguments.at("pid").is_null();
    const std::size_t selector_count = static_cast<std::size_t>(has_binary) +
        static_cast<std::size_t>(has_name) + static_cast<std::size_t>(has_pid);
    if (selector_count > 1) {
        failure = dispatch_error("Only one workspace selector may be supplied.",
            "TARGET_CONFLICT",
            json{{"binary_id", has_binary}, {"bin_name", has_name},
                 {"pid", has_pid}, {"ui_selection_changed", false}});
        return context;
    }

    aida::analysis::target_selector_t selector;
    if (has_binary) {
        if (!arguments.at("binary_id").is_string()) {
            failure = dispatch_error("binary_id must be a hexadecimal string.",
                "INVALID_ARGUMENT", json{{"selector", "binary_id"}});
            return context;
        }
        const auto parsed = aida::analysis::binary_id_t::from_hex(
            arguments.at("binary_id").get<std::string>());
        if (!parsed) {
            failure = dispatch_error("binary_id is invalid.", "INVALID_ARGUMENT",
                json{{"selector", "binary_id"}});
            return context;
        }
        selector.binary_id = *parsed;
    } else if (has_name) {
        if (!arguments.at("bin_name").is_string()) {
            failure = dispatch_error("bin_name must be a string.",
                "INVALID_ARGUMENT", json{{"selector", "bin_name"}});
            return context;
        }
        selector.bin_name = arguments.at("bin_name").get<std::string>();
    } else if (has_pid) {
        const auto parsed = parse_pid(arguments.at("pid"));
        if (!parsed) {
            failure = dispatch_error("pid must be a positive 32-bit integer.",
                "INVALID_ARGUMENT", json{{"selector", "pid"}});
            return context;
        }
        selector.pid = *parsed;
    }

    aida::analysis::target_resolution_options_t resolution_options;
    resolution_options.allow_unique_substring = has_name;
    resolution_options.require_selector_when_multiple = true;
    auto resolved = aida::analysis::workspace_registry().resolve(
        selector, resolution_options);
    if (!resolved) {
        const auto& error = resolved.error();
        json details{{"phase", error.phase},
                     {"stable_code", error.stable_code()},
                     {"ui_selection_changed", false}};
        for (const auto& detail : error.details)
            details[detail.first] = detail.second;
        failure = dispatch_error(error.message, error.stable_code(),
            std::move(details));
        return context;
    }

    context.workspace = resolved.take_value();
    if (!context.workspace || context.workspace->closing() ||
        context.workspace->closed() || context.workspace->generation() == 0) {
        context.workspace.reset();
        failure = dispatch_error("Resolved workspace generation is closed.",
            "TARGET_CLOSED", json{{"ui_selection_changed", false}});
        return context;
    }
    context.kind = context.workspace->identity().target_kind();
    context.binary_id = context.workspace->identity().binary_id();
    if (context.workspace->identity().process())
        context.pid = context.workspace->identity().process()->pid;
    context.analysis_revision = context.workspace->analysis_revision();
    context.overlay_revision = context.workspace->overlay_revision();
    context.cancellation = options.cancellation
        ? options.cancellation.get() : current_cancel_token();
    context.deadline_ms = options.deadline_ms != 0
        ? options.deadline_ms : current_call_deadline_ms();
    context.diagnostic_id = options.diagnostic_id;
    context.request_id = options.request_id;
    context.tool_name = tool.name;
    return context;
}

tool_result_t validate_schema(
    const json& schema, const json& value, const char* code,
    const char* message) {
    if (schema.is_null() || schema.empty())
        return tool_result_t::ok("");
    if (!schema.is_object())
        return dispatch_error("Tool schema is not an object.",
            "MCP_TOOL_CONTRACT_INVALID");
    aida::standalone::mcp::protocol::schema_runtime_t runtime(32);
    const auto result = runtime.validate(schema, value);
    if (result.valid)
        return tool_result_t::ok("");
    return dispatch_error(message, code,
        json{{"schema", result.diagnostics()}});
}

}

cancel_token_ptr_t make_call_cancel_token(bool cancelled) {
    return std::make_shared<std::atomic<bool>>(cancelled);
}

void signal_call_cancel_token(const cancel_token_ptr_t& token) noexcept {
    if (token)
        token->store(true, std::memory_order_release);
}

std::atomic<bool>* current_cancel_token() noexcept {
    return current_cancellation;
}

bool current_call_cancelled() noexcept {
    return current_cancellation &&
        current_cancellation->load(std::memory_order_acquire);
}

const char* current_call_diag_id() noexcept {
    return current_diagnostic_id.c_str();
}

const char* current_call_request_id() noexcept {
    return current_request_id.c_str();
}

const char* current_call_tool_name() noexcept {
    return current_tool_name.c_str();
}

std::uint64_t current_call_deadline_ms() noexcept {
    return current_deadline_ms;
}

scoped_call_metadata_t::scoped_call_metadata_t(
    const std::string& diagnostic_id, const std::string& tool_name,
    std::uint64_t deadline_ms)
    : scoped_call_metadata_t(
          diagnostic_id, std::string(), tool_name, deadline_ms) {}

scoped_call_metadata_t::scoped_call_metadata_t(
    const std::string& diagnostic_id, const std::string& request_id,
    const std::string& tool_name, std::uint64_t deadline_ms)
    : previous_diagnostic_id_(current_diagnostic_id),
      previous_request_id_(current_request_id),
      previous_tool_name_(current_tool_name),
      previous_deadline_ms_(current_deadline_ms), active_(true) {
    current_diagnostic_id = diagnostic_id;
    current_request_id = request_id.empty() ? diagnostic_id : request_id;
    current_tool_name = tool_name;
    current_deadline_ms = deadline_ms;
}

scoped_call_metadata_t::~scoped_call_metadata_t() {
    if (!active_)
        return;
    current_diagnostic_id = std::move(previous_diagnostic_id_);
    current_request_id = std::move(previous_request_id_);
    current_tool_name = std::move(previous_tool_name_);
    current_deadline_ms = previous_deadline_ms_;
    active_ = false;
}

scoped_call_cancel_t::scoped_call_cancel_t(cancel_token_ptr_t token)
    : token_(std::move(token)) {
    if (token_) {
        previous_ = current_cancellation;
        current_cancellation = token_.get();
        active_ = true;
    }
}

scoped_call_cancel_t::~scoped_call_cancel_t() {
    release();
}

scoped_call_cancel_t::scoped_call_cancel_t(scoped_call_cancel_t&& other) noexcept
    : token_(std::move(other.token_)), previous_(other.previous_),
      active_(other.active_) {
    other.previous_ = nullptr;
    other.active_ = false;
}

scoped_call_cancel_t& scoped_call_cancel_t::operator=(
    scoped_call_cancel_t&& other) noexcept {
    if (this != &other) {
        release();
        token_ = std::move(other.token_);
        previous_ = other.previous_;
        active_ = other.active_;
        other.previous_ = nullptr;
        other.active_ = false;
    }
    return *this;
}

void scoped_call_cancel_t::cancel() noexcept {
    signal_call_cancel_token(token_);
}

void scoped_call_cancel_t::release() noexcept {
    if (!active_)
        return;
    current_cancellation = previous_;
    previous_ = nullptr;
    active_ = false;
}

bool tool_registry_t::register_tool(tool_def_t tool) {
    if (tool.name.empty() ||
        (!tool.handler && !tool.workspace_handler) ||
        (!tool.input_schema.is_null() && !tool.input_schema.is_object()) ||
        (!tool.output_schema.is_null() && !tool.output_schema.is_object()) ||
        (!tool.annotations.is_null() && !tool.annotations.is_object()))
        return false;
    std::lock_guard<std::mutex> lock(tools_mutex_);
    const auto duplicate = std::find_if(
        tools_.begin(), tools_.end(), [&tool](const tool_def_t& existing) {
            return existing.name == tool.name;
    });
    if (duplicate != tools_.end())
        return false;
    tools_.push_back(std::move(tool));
    return true;
}

bool tool_registry_t::replace_tool(tool_def_t tool) {
    if (tool.name.empty() ||
        (!tool.handler && !tool.workspace_handler) ||
        (!tool.input_schema.is_null() && !tool.input_schema.is_object()) ||
        (!tool.output_schema.is_null() && !tool.output_schema.is_object()) ||
        (!tool.annotations.is_null() && !tool.annotations.is_object()))
        return false;
    std::lock_guard<std::mutex> lock(tools_mutex_);
    const auto existing = std::find_if(
        tools_.begin(), tools_.end(), [&tool](const tool_def_t& candidate) {
            return candidate.name == tool.name;
        });
    if (existing == tools_.end())
        return false;
    *existing = std::move(tool);
    return true;
}

bool tool_registry_t::register_tool(
    tool_def_t tool,
    std::function<tool_result_t(
        const json&,
        const std::shared_ptr<aida::analysis::analysis_workspace_t>&)> handler) {
    if (!handler)
        return false;
    tool.workspace_handler = [handler = std::move(handler)](
        const json& arguments, const workspace_request_context_t& context) {
        return handler(arguments, context.workspace);
    };
    tool.handler = {};
    return register_tool(std::move(tool));
}

bool tool_registry_t::register_tool(
    tool_def_t tool,
    std::function<tool_result_t(
        const json&,
        const workspace_request_context_t&)> handler) {
    if (!handler)
        return false;
    tool.workspace_handler = std::move(handler);
    tool.handler = {};
    return register_tool(std::move(tool));
}

void tool_registry_t::set_validation_hook(tool_validation_hook_t hook) {
    std::lock_guard<std::mutex> lock(validation_mutex_);
    validation_hook_ = std::move(hook);
}

bool tool_registry_t::set_dispatch_capacity(std::size_t capacity) noexcept {
    if (capacity == 0 || capacity > 4096)
        return false;
    dispatch_capacity_.store(capacity, std::memory_order_release);
    return true;
}

std::size_t tool_registry_t::dispatch_capacity() const noexcept {
    return dispatch_capacity_.load(std::memory_order_acquire);
}

std::size_t tool_registry_t::active_dispatches() const noexcept {
    return active_dispatches_.load(std::memory_order_acquire);
}

std::vector<tool_def_t> tool_registry_t::snapshot_tools() const {
    std::lock_guard<std::mutex> lock(tools_mutex_);
    return tools_;
}

const std::vector<tool_def_t>& tool_registry_t::tools_view() const noexcept {
    return tools_;
}

std::optional<tool_def_t> tool_registry_t::find_tool(
    const std::string& name, bool external_visible_only) const {
    std::lock_guard<std::mutex> lock(tools_mutex_);
    const auto found = std::find_if(
        tools_.begin(), tools_.end(), [&name](const tool_def_t& tool) {
            return tool.name == name;
        });
    if (found == tools_.end() ||
        (external_visible_only && !externally_visible(*found)))
        return std::nullopt;
    return *found;
}

tool_result_t tool_registry_t::call_registered_tool(
    const std::string& name, const json& arguments,
    direct_dispatch_options_t options) {
    if (name.empty())
        return dispatch_error("Missing tool name.", "MCP_TOOL_NAME_MISSING");
    const auto tool = find_tool(name, options.external_visible_only);
    if (!tool)
        return dispatch_error("Unknown tool: " + name, "MCP_TOOL_NOT_FOUND",
            json{{"tool", name},
                 {"external_visible_only", options.external_visible_only}});

    std::size_t observed = active_dispatches_.load(std::memory_order_acquire);
    for (;;) {
        const auto capacity = dispatch_capacity_.load(std::memory_order_acquire);
        if (observed >= capacity)
            return dispatch_error("MCP registry dispatch capacity is exhausted.",
                "MCP_TOOL_CAPACITY_REJECT",
                json{{"active", observed}, {"capacity", capacity}});
        if (active_dispatches_.compare_exchange_weak(
                observed, observed + 1, std::memory_order_acq_rel,
                std::memory_order_acquire))
            break;
    }
    struct release_t final {
        std::atomic<std::size_t>& active;
        ~release_t() { active.fetch_sub(1, std::memory_order_acq_rel); }
    } release{active_dispatches_};

    const auto sequence = request_sequence_.fetch_add(
        1, std::memory_order_acq_rel) + 1;
    if (options.request_id.empty())
        options.request_id = "registry-" + std::to_string(sequence);
    if (options.diagnostic_id.empty())
        options.diagnostic_id = options.request_id;
    if (!options.cancellation)
        options.cancellation = make_call_cancel_token(false);
    tool_validation_hook_t hook;
    {
        std::lock_guard<std::mutex> lock(validation_mutex_);
        hook = validation_hook_;
    }
    return invoke_registered_tool_definition(*tool, arguments, options, hook);
}

tool_result_t invoke_registered_tool_definition(
    const tool_def_t& tool, const json& arguments,
    const direct_dispatch_options_t& supplied_options,
    const tool_validation_hook_t& validation_hook) {
    direct_dispatch_options_t options = supplied_options;
    if (!options.cancellation) {
        if (auto* current = current_cancel_token()) {
            options.cancellation = cancel_token_ptr_t(
                current, [](std::atomic<bool>*) {});
        } else {
            options.cancellation = make_call_cancel_token(false);
        }
    }
    if (options.deadline_ms == 0)
        options.deadline_ms = current_call_deadline_ms();
    if (options.request_id.empty())
        options.request_id = "registry-direct";
    if (options.diagnostic_id.empty())
        options.diagnostic_id = options.request_id;
    scoped_call_cancel_t cancellation_scope(options.cancellation);
    scoped_call_metadata_t metadata_scope(options.diagnostic_id,
        options.request_id, tool.name, options.deadline_ms);

    const auto stopped = [&options]() {
        return options.cancellation &&
            options.cancellation->load(std::memory_order_acquire);
    };
    const auto expired = [&options]() {
        return options.deadline_ms != 0 && monotonic_ms() >= options.deadline_ms;
    };
    if (stopped())
        return dispatch_error("Tool invocation was cancelled before validation.",
            "MCP_TOOL_CANCELLED", json{{"phase", "pre_validation"}});
    if (expired())
        return dispatch_error("Tool invocation deadline expired before validation.",
            "MCP_TOOL_DEADLINE_EXPIRED", json{{"phase", "pre_validation"}});

    const auto schema_input = validate_schema(tool.input_schema, arguments,
        "MCP_TOOL_INPUT_SCHEMA_INVALID",
        "Tool arguments do not satisfy the registered input schema.");
    if (!schema_input.success)
        return schema_input;
    if (validation_hook) {
        const auto validation = validation_hook(tool, arguments);
        if (!validation.success)
            return validation;
    }

    tool_result_t result;
    std::shared_ptr<aida::analysis::analysis_workspace_t> workspace;
    std::uint64_t generation_before = 0;
    std::uint64_t analysis_revision_before = 0;
    std::uint64_t overlay_revision_before = 0;
    try {
        if (tool.workspace_handler) {
            tool_result_t resolution_failure;
            auto context = make_workspace_context(
                tool, arguments, options, resolution_failure);
            if (!context.workspace)
                return resolution_failure;
            workspace = context.workspace;
            generation_before = workspace->generation();
            analysis_revision_before = context.analysis_revision;
            overlay_revision_before = context.overlay_revision;
            if (stopped())
                return dispatch_error(
                    "Tool invocation was cancelled before target dispatch.",
                    "MCP_TOOL_CANCELLED", json{{"phase", "pre_dispatch"}});
            if (expired())
                return dispatch_error(
                    "Tool invocation deadline expired before target dispatch.",
                    "MCP_TOOL_DEADLINE_EXPIRED",
                    json{{"phase", "pre_dispatch"}});
            result = tool.workspace_handler(arguments, context);
        } else if (tool.handler) {
            result = tool.handler(arguments);
        } else {
            return dispatch_error("Registered tool has no handler.",
                "MCP_TOOL_HANDLER_MISSING", json{{"tool", tool.name}});
        }
    } catch (const std::exception&) {
        return tool_result_t::error("Tool handler raised an exception.",
            "MCP_TOOL_HANDLER_EXCEPTION",
            json{{"tool", tool.name}, {"disposition", "failed"}});
    } catch (...) {
        return tool_result_t::error("Tool handler raised an unknown exception.",
            "MCP_TOOL_HANDLER_EXCEPTION",
            json{{"tool", tool.name}, {"disposition", "failed"}});
    }

    if (stopped())
        return tool_result_t::error(
            "Tool invocation was cancelled before result delivery.",
            "MCP_TOOL_CANCELLED",
            json{{"phase", "post_dispatch"}, {"disposition", "discarded"}});
    if (expired())
        return tool_result_t::error(
            "Tool invocation deadline expired before result delivery.",
            "MCP_TOOL_DEADLINE_EXPIRED",
            json{{"phase", "post_dispatch"}, {"disposition", "discarded"}});
    if (workspace && tool.read_only &&
        (workspace->closing() || workspace->closed() ||
         workspace->generation() != generation_before ||
         workspace->analysis_revision() != analysis_revision_before ||
         workspace->overlay_revision() != overlay_revision_before)) {
        return tool_result_t::error(
            "Workspace generation changed during a read-only tool invocation.",
            "TARGET_STALE",
            json{{"generation_before", generation_before},
                 {"generation_after", workspace->generation()},
                 {"analysis_revision_before", analysis_revision_before},
                 {"analysis_revision_after", workspace->analysis_revision()},
                 {"overlay_revision_before", overlay_revision_before},
                 {"overlay_revision_after", workspace->overlay_revision()},
                 {"disposition", "discarded"}});
    }
    if (!result.success)
        return result;
    const auto schema_output = validate_schema(tool.output_schema, result.data,
        "MCP_TOOL_OUTPUT_SCHEMA_INVALID",
        "Tool result does not satisfy the registered output schema.");
    if (!schema_output.success)
        return schema_output;
    return result;
}

}
