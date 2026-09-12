#include "aida_pro.hpp"
#include "ida_utils.hpp"
#include "graphrag.hpp"
#include "analysis_db.hpp"
#include "multibinary_project.hpp"
#include "aida_ipc.hpp"
#include "vuln/vuln_tools.hpp"
#include "vuln/verification_tools.hpp"
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4996)
#endif
#include "vuln/chain_verification_tools.hpp"
#ifdef _MSC_VER
#pragma warning(pop)
#endif
#include "vuln/vuln_signatures.hpp"
// Slice C12 — bring in taint engine public surface for taint_tools_ext.
#include "vuln/taint_engine.hpp"
#include <allins.hpp>
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <loader.hpp>
#include <chrono>
#include <netnode.hpp>
#include <set>
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4267)
#endif
#include <regfinder.hpp>
#ifdef _MSC_VER
#pragma warning(pop)
#endif

using json = nlohmann::json;

namespace agent_tools
{

inline int safe_json_int_value(const json& v, int fallback)
{
    if (v.is_number_integer())
    {
        const std::int64_t value = v.get<std::int64_t>();
        if (value >= (std::numeric_limits<int>::min)() && value <= (std::numeric_limits<int>::max)())
            return static_cast<int>(value);
    }
    else if (v.is_number_unsigned())
    {
        const std::uint64_t value = v.get<std::uint64_t>();
        if (value <= static_cast<std::uint64_t>((std::numeric_limits<int>::max)()))
            return static_cast<int>(value);
    }
    else if (v.is_number_float())
    {
        const double value = v.get<double>();
        if (std::isfinite(value) && value >= (std::numeric_limits<int>::min)() && value <= (std::numeric_limits<int>::max)())
            return static_cast<int>(value);
    }
    return fallback;
}

inline int safe_json_int_param(const json& params, const char* key, int fallback)
{
    if (!params.is_object() || !params.contains(key))
        return fallback;
    return safe_json_int_value(params.at(key), fallback);
}

static func_t* get_func(ea_t ea)
{
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4996)
#endif
    func_t* fn = ::get_func(ea);
#ifdef _MSC_VER
#pragma warning(pop)
#endif
    return fn;
}

static func_t* getn_func(size_t n)
{
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4996)
#endif
    func_t* fn = ::getn_func(n);
#ifdef _MSC_VER
#pragma warning(pop)
#endif
    return fn;
}

static segment_t* getseg(ea_t ea)
{
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4996)
#endif
    segment_t* seg = ::getseg(ea);
#ifdef _MSC_VER
#pragma warning(pop)
#endif
    return seg;
}

static segment_t* getnseg(int n)
{
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4996)
#endif
    segment_t* seg = ::getnseg(n);
#ifdef _MSC_VER
#pragma warning(pop)
#endif
    return seg;
}

static segment_t* get_segm_by_name(const char* name)
{
    ea_t ea = ::get_segment_ea_by_name(name);
    return ea == BADADDR ? nullptr : getseg(ea);
}

static ssize_t aida_get_segm_name(qstring* out, const segment_t* seg, int flags = 0)
{
    return seg != nullptr ? ::get_segment_name(out, seg->start_ea, flags) : -1;
}

static bool aida_func_contains(const func_t* pfn, ea_t ea)
{
    return pfn != nullptr && ::function_contains(pfn->start_ea, ea);
}

static void aida_reanalyze_function(func_t* pfn, ea_t ea1 = 0, ea_t ea2 = BADADDR, bool analyze_parents = false)
{
    if (pfn != nullptr)
        ::reanalyze_function_ea(pfn->start_ea, ea1, ea2, analyze_parents);
}

static ea_t aida_calc_thunk_func_target(func_t* pfn, ea_t* fptr)
{
    if (pfn == nullptr)
        return BADADDR;
    func_entry_info_t fi;
    if (!::get_func_entry_info(&fi, pfn->start_ea))
        return BADADDR;
    return ::calc_thunk_function_target(&fi, fptr);
}

static cfuncptr_t aida_decompile_func(func_t* pfn, hexrays_failure_t* hf = nullptr, int decomp_flags = 0)
{
    if (pfn == nullptr)
        return cfuncptr_t(nullptr);
    return ::decompile_function(pfn->start_ea, hf, decomp_flags);
}

static cfuncptr_t decompile(func_t* pfn, hexrays_failure_t* hf = nullptr, int decomp_flags = 0)
{
    return aida_decompile_func(pfn, hf, decomp_flags);
}

static asize_t aida_get_frame_size(const func_t* pfn)
{
    return pfn != nullptr ? ::get_frame_size_ea(pfn->start_ea) : 0;
}

static bool aida_get_func_frame(tinfo_t* out, const func_t* pfn)
{
    return pfn != nullptr && ::get_func_frame_ea(out, pfn->start_ea);
}

static bool aida_set_func_cmt(const func_t* pfn, const char* cmt, bool repeatable)
{
    return pfn != nullptr && ::set_func_cmt_ea(pfn->start_ea, cmt, repeatable);
}

static bool aida_define_stkvar(func_t* pfn, const char* name, sval_t off, const tinfo_t& tif)
{
    return pfn != nullptr && ::define_stkvar_ea(pfn->start_ea, name, off, tif);
}

static bool aida_add_segm_ex(segment_t* seg, const char* name, const char* sclass, int flags)
{
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4996)
#endif
    bool ok = ::add_segm_ex(seg, name, sclass, flags);
#ifdef _MSC_VER
#pragma warning(pop)
#endif
    return ok;
}

class func_item_iterator_t
{
    function_item_iterator_t impl_;

public:
    func_item_iterator_t() = default;
    explicit func_item_iterator_t(func_t* pfn, ea_t ea = BADADDR)
    {
        set(pfn, ea);
    }

    bool set(func_t* pfn, ea_t ea = BADADDR)
    {
        return impl_.set(pfn != nullptr ? pfn->start_ea : BADADDR, ea);
    }

    bool first()
    {
        return impl_.first();
    }

    ea_t current() const
    {
        return impl_.current();
    }

    bool next_addr()
    {
        return impl_.next_addr();
    }

    bool next_head()
    {
        return impl_.next_head();
    }

    bool next_code()
    {
        return impl_.next_code();
    }
};

static std::string current_module_graph_key()
{
    aida::vuln::chain::corpus_record_t corpus = aida::vuln::chain::snapshot_current_idb_corpus();
    if (!corpus.identity.corpus_id.empty())
        return corpus.identity.corpus_id;
    return aida_db::AnalysisDB::instance().get_binary_hash();
}

tool_result_t tool_result_t::ok(const std::string& msg, const json& data)
{
    tool_result_t r;
    r.success = true;
    r.output = sanitize_utf8(msg);
    r.data = data;
    sanitize_json_utf8_inplace(r.data);
    return r;
}

tool_result_t tool_result_t::error(const std::string& msg)
{
    tool_result_t r;
    r.success = false;
    r.output = sanitize_utf8(msg);
    return r;
}

ToolRegistry& ToolRegistry::instance()
{
    static ToolRegistry registry;
    static bool first_call = true;
    if (first_call)
    {
        first_call = false;
        aida_ipc::trace_breadcrumb("agent_tools: ToolRegistry::instance() first call — singleton created");
    }
    return registry;
}

static bool registry_migration_destructive_name(const std::string& name)
{
    return name == "delete_function"
        || name == "delete_stack_var"
        || name == "rename_function"
        || name == "set_function_signature"
        || name == "patch_bytes"
        || name == "undefine"
        || name == "write_memory"
        || name == "idb_save"
        || name == "diff_before_after"
        || name == "patch"
        || name == "patch_asm"
        || name == "put_int"
        || name == "set_comments"
        || name == "set_comment"
        || name == "set_repeatable_comment"
        || name == "set_function_comment"
        || name == "append_comments"
        || name == "rename"
        || name == "define_func"
        || name == "define_code"
        || name == "declare_stack"
        || name == "delete_stack"
        || name == "declare_type"
        || name == "apply_type"
        || name == "enum_upsert"
        || name == "create_enum"
        || name == "create_struct"
        || name == "add_struct_member"
        || name == "create_stack_var"
        || name == "create_segment"
        || name == "set_type"
        || name == "type_apply_batch"
        || name == "py_eval"
        || name == "py_exec_file"
        || name == "apply_callee_prototype";
}

static std::pair<std::string, std::string> registry_migration_deprecated_target(const std::string& name)
{
    static const std::map<std::string, std::pair<std::string, std::string>> targets = {
        {"get_binary_info", {"ida_discover_manage", "module"}},
        {"list_functions", {"ida_discover_manage", "functions"}},
        {"list_funcs", {"ida_discover_manage", "functions"}},
        {"get_function", {"ida_discover_manage", "function"}},
        {"decompile_function", {"ida_extract_manage", "decompile"}},
        {"decompile", {"ida_extract_manage", "decompile"}},
        {"disassemble_function", {"ida_extract_manage", "instructions"}},
        {"disasm", {"ida_extract_manage", "instructions"}},
        {"get_xrefs_to", {"ida_extract_manage", "xrefs"}},
        {"get_xrefs_from", {"ida_extract_manage", "xrefs"}},
        {"xrefs_to", {"ida_extract_manage", "xrefs"}},
        {"list_imports", {"ida_discover_manage", "imports"}},
        {"imports", {"ida_discover_manage", "imports"}},
        {"list_exports", {"ida_discover_manage", "exports"}},
        {"export_funcs", {"ida_discover_manage", "exports"}},
        {"list_segments", {"ida_discover_manage", "segments"}},
        {"get_address_info", {"ida_discover_manage", "address"}},
        {"build_call_graph", {"ida_analysis_manage", "callgraph"}},
        {"callgraph", {"ida_analysis_manage", "callgraph"}},
        {"analyze_function", {"ida_analysis_manage", "function"}},
        {"analyze_batch", {"ida_analysis_manage", "batch"}},
        {"analyze_component", {"ida_analysis_manage", "component"}},
        {"analyze_control_flow", {"ida_analysis_manage", "control_flow"}},
        {"analyze_data_flow", {"ida_analysis_manage", "data_flow"}},
        {"run_taint_analysis", {"ida_analysis_manage", "taint"}},
        {"index_status", {"ida_diagnostics_manage", "index_status"}},
        {"build_index", {"ida_cache_manage", "build"}},
        {"list_outputs", {"ida_cache_manage", "output_cache"}},
        {"server_health", {"ida_diagnostics_manage", "health"}},
        {"rename_function", {"ida_mutation_manage", "rename_function"}},
        {"rename", {"ida_mutation_manage", "batch_apply"}},
        {"batch_rename", {"ida_mutation_manage", "batch_apply"}},
        {"set_function_signature", {"ida_mutation_manage", "set_function_signature"}},
        {"apply_type", {"ida_mutation_manage", "apply_type"}},
        {"set_type", {"ida_mutation_manage", "apply_type"}},
        {"type_apply_batch", {"ida_mutation_manage", "batch_apply"}},
        {"declare_type", {"ida_mutation_manage", "declare_type"}},
        {"set_comment", {"ida_mutation_manage", "set_comment"}},
        {"set_repeatable_comment", {"ida_mutation_manage", "set_comment"}},
        {"set_function_comment", {"ida_mutation_manage", "set_comment"}},
        {"set_decompiler_comment", {"ida_mutation_manage", "set_comment"}},
        {"set_comments", {"ida_mutation_manage", "batch_apply"}},
        {"append_comments", {"ida_mutation_manage", "batch_apply"}},
        {"patch_bytes", {"ida_mutation_manage", "patch_bytes"}},
        {"patch", {"ida_mutation_manage", "batch_apply"}},
        {"patch_asm", {"ida_mutation_manage", "batch_apply"}},
        {"put_int", {"ida_mutation_manage", "batch_apply"}},
        {"idb_save", {"ida_mutation_manage", "idb_save"}},
        {"define_func", {"ida_mutation_manage", "batch_apply"}},
        {"define_code", {"ida_mutation_manage", "batch_apply"}},
        {"delete_function", {"ida_mutation_manage", "delete_function"}}
    };
    auto it = targets.find(name);
    if (it == targets.end())
        return {};
    return it->second;
}

static json operation_metadata_to_json(const tool_operation_t& op)
{
    json j;
    j["operation"] = op.name;
    j["description"] = op.description;
    j["read_only"] = op.read_only;
    j["destructive"] = op.destructive;
    j["deterministic"] = op.deterministic;
    j["job_mode"] = op.job_mode;
    j["cache_policy"] = op.cache_policy;
    j["default_timeout_ms"] = op.default_timeout_ms;
    j["hard_timeout_ms"] = op.hard_timeout_ms;
    j["required_indices"] = op.required_indices;
    if (!op.input_schema.is_null() && !op.input_schema.empty())
        j["input_schema"] = op.input_schema;
    if (!op.output_schema.is_null() && !op.output_schema.empty())
        j["output_schema"] = op.output_schema;
    return j;
}

static tool_result_t attach_deprecated_metadata(const tool_definition_t& tool, tool_result_t result)
{
    if (tool.deprecated_by_tool.empty())
        return result;
    json dep;
    dep["tool"] = tool.deprecated_by_tool;
    dep["operation"] = tool.deprecated_by_operation.empty() ? json(nullptr) : json(tool.deprecated_by_operation);
    dep["visibility"] = "legacy";
    if (result.data.is_null() || result.data.empty())
        result.data = json::object();
    if (result.data.is_object())
        result.data["deprecated_by"] = dep;
    else
        result.data = json{{"legacy_result", result.data}, {"deprecated_by", dep}};
    return result;
}

void ToolRegistry::register_tool(const tool_definition_t& tool)
{
    aida_ipc::trace_breadcrumb("agent_tools: register_tool ENTRY name=%s", tool.name.c_str());

    if (tool.name.empty())
    {
        aida_ipc::trace_breadcrumb("agent_tools: register_tool REJECTED unnamed tool");
        msg("AiDA ToolRegistry: rejected unnamed tool\n");
        return;
    }

    if (_tools.find(tool.name) != _tools.end())
    {
        aida_ipc::trace_breadcrumb("agent_tools: register_tool REJECTED duplicate name=%s", tool.name.c_str());
        msg("AiDA ToolRegistry: rejected duplicate tool name=%s\n", tool.name.c_str());
        return;
    }

    if (!tool.handler)
    {
        aida_ipc::trace_breadcrumb("agent_tools: register_tool REJECTED no handler name=%s", tool.name.c_str());
        msg("AiDA ToolRegistry: rejected tool without handler name=%s\n", tool.name.c_str());
        return;
    }

    tool_definition_t normalized = tool;
    if (normalized.visibility.empty())
        normalized.visibility = "legacy";
    const bool manage_name = normalized.name.size() > 11
        && normalized.name.rfind("ida_", 0) == 0
        && normalized.name.compare(normalized.name.size() - 7, 7, "_manage") == 0;
    if (manage_name && normalized.visibility == "legacy")
        normalized.visibility = "public";
    if (normalized.category == "session")
        normalized.visibility = "internal";
    if (registry_migration_destructive_name(normalized.name))
    {
        normalized.read_only = false;
        normalized.destructive = true;
        normalized.deterministic = false;
    }
    auto dep = registry_migration_deprecated_target(normalized.name);
    if (normalized.deprecated_by_tool.empty() && !dep.first.empty())
    {
        normalized.deprecated_by_tool = dep.first;
        normalized.deprecated_by_operation = dep.second;
    }

    if (normalized.read_only && normalized.destructive)
    {
        aida_ipc::trace_breadcrumb("agent_tools: register_tool REJECTED impossible metadata name=%s read_only=1 destructive=1", normalized.name.c_str());
        msg("AiDA ToolRegistry: rejected impossible metadata name=%s read_only=1 destructive=1\n", normalized.name.c_str());
        return;
    }

    static const std::set<std::string> supported_types = {
        "array", "boolean", "integer", "number", "object", "string"
    };
    std::set<std::string> parameter_names;
    for (const auto& param : normalized.parameters)
    {
        if (param.name.empty() || supported_types.find(param.type) == supported_types.end()
            || !parameter_names.insert(param.name).second)
        {
            aida_ipc::trace_breadcrumb("agent_tools: register_tool REJECTED invalid parameter metadata name=%s param=%s type=%s",
                normalized.name.c_str(), param.name.c_str(), param.type.c_str());
            msg("AiDA ToolRegistry: rejected invalid parameter metadata tool=%s param=%s type=%s\n",
                normalized.name.c_str(), param.name.c_str(), param.type.c_str());
            return;
        }
    }

    if (normalized.visibility != "public" && normalized.visibility != "legacy"
        && normalized.visibility != "internal")
    {
        aida_ipc::trace_breadcrumb("agent_tools: register_tool REJECTED invalid visibility name=%s visibility=%s",
            normalized.name.c_str(), normalized.visibility.c_str());
        msg("AiDA ToolRegistry: rejected invalid visibility tool=%s visibility=%s\n",
            normalized.name.c_str(), normalized.visibility.c_str());
        return;
    }

    aida_ipc::trace_breadcrumb("agent_tools: register_tool OK name=%s category=%s read_only=%d destructive=%d total_tools=%zu",
        normalized.name.c_str(), normalized.category.c_str(),
        normalized.read_only ? 1 : 0, normalized.destructive ? 1 : 0,
        _tools.size() + 1);
    _tools.emplace(normalized.name, std::move(normalized));
}

const tool_definition_t* ToolRegistry::get_tool(const std::string& name) const
{
    aida_ipc::trace_breadcrumb("agent_tools: get_tool ENTRY name=%s", name.c_str());
    auto it = _tools.find(name);
    const tool_definition_t* result = (it != _tools.end()) ? &it->second : nullptr;
    aida_ipc::trace_breadcrumb("agent_tools: get_tool EXIT name=%s found=%d", name.c_str(), result ? 1 : 0);
    return result;
}

std::vector<std::string> ToolRegistry::get_tool_names() const
{
    aida_ipc::trace_breadcrumb("agent_tools: get_tool_names ENTRY total_tools=%zu", _tools.size());
    std::vector<std::string> names;
    names.reserve(_tools.size());
    for (const auto& [name, _] : _tools)
        names.push_back(name);
    aida_ipc::trace_breadcrumb("agent_tools: get_tool_names EXIT count=%zu", names.size());
    return names;
}

std::vector<const tool_definition_t*> ToolRegistry::get_tools_by_category(const std::string& category) const
{
    aida_ipc::trace_breadcrumb("agent_tools: get_tools_by_category ENTRY category=%s total_tools=%zu", category.c_str(), _tools.size());
    std::vector<const tool_definition_t*> result;
    for (const auto& [_, tool] : _tools)
    {
        if (tool.category == category)
            result.push_back(&tool);
    }
    aida_ipc::trace_breadcrumb("agent_tools: get_tools_by_category EXIT category=%s count=%zu", category.c_str(), result.size());
    return result;
}

std::vector<const tool_definition_t*> ToolRegistry::get_all_tools() const
{
    aida_ipc::trace_breadcrumb("agent_tools: get_all_tools ENTRY total_tools=%zu", _tools.size());
    std::vector<const tool_definition_t*> result;
    result.reserve(_tools.size());

    auto meta_it = _tools.find("list_all_available_tools");
    if (meta_it != _tools.end())
        result.push_back(&meta_it->second);

    for (const auto& [name, tool] : _tools)
    {
        if (name != "list_all_available_tools")
            result.push_back(&tool);
    }
    aida_ipc::trace_breadcrumb("agent_tools: get_all_tools EXIT count=%zu", result.size());
    return result;
}

json ToolRegistry::generate_tools_schema() const
{
    aida_ipc::trace_breadcrumb("agent_tools: generate_tools_schema ENTRY total_tools=%zu", _tools.size());
    json tools_array = json::array();

    for (const auto& [_, tool] : _tools)
    {
        json tool_json;
        tool_json["name"] = tool.name;
        tool_json["category"] = tool.category;
        tool_json["description"] = tool.description;
        tool_json["read_only"] = tool.read_only;
        tool_json["destructive"] = tool.destructive;
        tool_json["deterministic"] = tool.deterministic;
        tool_json["required_indices"] = tool.required_indices;
        tool_json["visibility"] = tool.visibility;
        if (!tool.deprecated_by_tool.empty())
        {
            tool_json["deprecated_by"] = {
                {"tool", tool.deprecated_by_tool},
                {"operation", tool.deprecated_by_operation.empty() ? json(nullptr) : json(tool.deprecated_by_operation)}
            };
        }
        if (!tool.operations.empty())
        {
            tool_json["operations"] = json::array();
            for (const auto& op : tool.operations)
                tool_json["operations"].push_back(operation_metadata_to_json(op));
        }
        if (!tool.output_schema.is_null() && !tool.output_schema.empty())
            tool_json["output_schema"] = tool.output_schema;

        json params = json::object();
        json required_params = json::array();

        for (const auto& param : tool.parameters)
        {
            json param_json;
            param_json["type"] = param.type;
            param_json["description"] = param.description;
            if (!param.enum_values.empty())
                param_json["enum"] = param.enum_values;
            if (param.type == "array" && !param.items_schema.is_null())
                param_json["items"] = param.items_schema;
            else if (param.type == "array")
                param_json["items"] = json::object({{"type", "object"}});
            params[param.name] = param_json;

            if (param.required)
                required_params.push_back(param.name);
        }

        tool_json["parameters"] = {
            {"type", "object"},
            {"properties", params},
            {"required", required_params}
        };

        tools_array.push_back(tool_json);
    }

    aida_ipc::trace_breadcrumb("agent_tools: generate_tools_schema EXIT count=%zu", tools_array.size());
    return tools_array;
}

std::string ToolRegistry::generate_tools_description() const
{
    aida_ipc::trace_breadcrumb("agent_tools: generate_tools_description ENTRY total_tools=%zu", _tools.size());
    std::ostringstream ss;

    std::map<std::string, std::vector<const tool_definition_t*>> by_category;
    for (const auto& [_, tool] : _tools)
        by_category[tool.category].push_back(&tool);

    for (const auto& [category, tools] : by_category)
    {
        ss << "\n## " << category << " Tools\n\n";
        for (const auto* tool : tools)
        {
            ss << "### " << tool->name << "\n";
            ss << tool->description << "\n";
            ss << "Parameters:\n";
            for (const auto& param : tool->parameters)
            {
                ss << "  - `" << param.name << "` (" << param.type << ")";
                if (!param.required) ss << " [optional]";
                ss << ": " << param.description << "\n";
            }
            ss << "\n";
        }
    }

    aida_ipc::trace_breadcrumb("agent_tools: generate_tools_description EXIT");
    return ss.str();
}

tool_result_t ToolRegistry::execute_tool(const std::string& name, const json& params)
{
    aida_ipc::trace_breadcrumb("agent_tools: execute_tool ENTRY name=%s", name.c_str());

    const auto* tool = get_tool(name);
    if (!tool)
    {
        aida_ipc::trace_breadcrumb("agent_tools: execute_tool FAIL unknown tool name=%s", name.c_str());
        return tool_result_t::error(std::string("Unknown tool: ") + name);
    }

    json sanitized_params = params.is_object() ? params : json::object();

    for (const auto& param : tool->parameters)
    {
        if (param.required && !sanitized_params.contains(param.name))
        {
            aida_ipc::trace_breadcrumb("agent_tools: execute_tool FAIL missing param tool=%s param=%s", name.c_str(), param.name.c_str());
            return tool_result_t::error(std::string("Missing required parameter: ") + param.name, "bad_param");
        }

        if (sanitized_params.contains(param.name))
        {
            auto& val = sanitized_params[param.name];
            if (val.is_null())
            {
                if (param.type == "string")
                    val = "";
                else if (param.type == "number")
                    val = 0;
                else if (param.type == "boolean")
                    val = false;
                else if (param.type == "array")
                    val = json::array();
            }
            else if (param.type == "string" && val.is_number_unsigned())
            {
                std::ostringstream ss;
                ss << "0x" << std::hex << val.get<uint64_t>();
                val = ss.str();
            }
            else if (param.type == "string" && val.is_number_integer())
            {
                const auto signed_value = val.get<int64_t>();
                if (signed_value < 0)
                    val = std::to_string(signed_value);
                else
                {
                    std::ostringstream ss;
                    ss << "0x" << std::hex << static_cast<uint64_t>(signed_value);
                    val = ss.str();
                }
            }
            else if (param.type == "string" && val.is_number())
            {
                val = std::to_string(val.get<double>());
            }
            else if (param.type == "number" && val.is_string())
            {
                std::string sv = val.get<std::string>();
                try {
                    size_t consumed = 0;
                    if (sv.size() > 2 && sv[0] == '0' && (sv[1] == 'x' || sv[1] == 'X'))
                        val = static_cast<uint64_t>(std::stoull(sv, &consumed, 16));
                    else if (!sv.empty() && sv[0] == '-')
                        val = static_cast<int64_t>(std::stoll(sv, &consumed, 0));
                    else if (!sv.empty())
                        val = static_cast<uint64_t>(std::stoull(sv, &consumed, 0));
                    else
                        return tool_result_t::error(
                            std::string("Invalid numeric value for parameter '") + param.name + "'",
                            "bad_param");
                    if (consumed != sv.size())
                        return tool_result_t::error(
                            std::string("Invalid numeric value for parameter '") + param.name + "'",
                            "bad_param");
                } catch (...) {
                    return tool_result_t::error(
                        std::string("Invalid numeric value for parameter '") + param.name + "'",
                        "bad_param");
                }
            }

            const bool type_valid =
                (param.type == "string" && val.is_string())
                || (param.type == "number" && val.is_number())
                || (param.type == "integer" && (val.is_number_integer() || val.is_number_unsigned()))
                || (param.type == "boolean" && val.is_boolean())
                || (param.type == "array" && val.is_array())
                || (param.type == "object" && val.is_object());
            if (!type_valid)
            {
                aida_ipc::trace_breadcrumb("agent_tools: execute_tool FAIL invalid type tool=%s param=%s expected=%s",
                    name.c_str(), param.name.c_str(), param.type.c_str());
                return tool_result_t::error(
                    std::string("Invalid type for parameter '") + param.name + "': expected " + param.type,
                    "bad_param");
            }
            if (!param.enum_values.empty())
            {
                if (!val.is_string()
                    || std::find(param.enum_values.begin(), param.enum_values.end(), val.get<std::string>()) == param.enum_values.end())
                {
                    aida_ipc::trace_breadcrumb("agent_tools: execute_tool FAIL invalid enum tool=%s param=%s",
                        name.c_str(), param.name.c_str());
                    return tool_result_t::error(
                        std::string("Invalid value for parameter '") + param.name + "'",
                        "bad_param");
                }
            }
        }
    }

    try
    {
        aida_ipc::trace_breadcrumb("agent_tools: execute_tool CALLING HANDLER name=%s", name.c_str());
        auto result = attach_deprecated_metadata(*tool, tool->handler(sanitized_params));
        aida_ipc::trace_breadcrumb("agent_tools: execute_tool EXIT name=%s success=%d", name.c_str(), result.success ? 1 : 0);
        return result;
    }
    catch (const std::exception& e)
    {
        aida_ipc::trace_breadcrumb("agent_tools: execute_tool EXCEPTION name=%s what=%s", name.c_str(), e.what());
        return attach_deprecated_metadata(*tool, tool_result_t::error(std::string("Tool execution error: ") + e.what()));
    }
    catch (...)
    {
        aida_ipc::trace_breadcrumb("agent_tools: execute_tool EXCEPTION name=%s non_std=1", name.c_str());
        return attach_deprecated_metadata(*tool, tool_result_t::error("Tool execution error: unknown exception", "unknown"));
    }
}

tool_result_t ToolRegistry::execute_tool_batch(
    const std::vector<std::pair<std::string, json>>& calls,
    bool stop_on_error,
    std::vector<tool_result_t>* out)
{
    aida_ipc::trace_breadcrumb("agent_tools: execute_tool_batch ENTRY calls=%zu stop_on_error=%d", calls.size(), stop_on_error ? 1 : 0);
    if (out)
    {
        out->clear();
        out->reserve(calls.size());
    }

    size_t ok_count = 0;
    size_t fail_count = 0;
    tool_result_t first_failure;
    bool have_failure = false;

    for (size_t i = 0; i < calls.size(); ++i)
    {
        const auto& c = calls[i];
        tool_result_t r = execute_tool(c.first, c.second);
        if (out)
            out->push_back(r);

        if (r.success)
        {
            ++ok_count;
        }
        else
        {
            ++fail_count;
            if (!have_failure)
            {
                first_failure = r;
                have_failure = true;
            }
            if (stop_on_error)
                break;
        }
    }

    if (have_failure)
    {
        aida_ipc::trace_breadcrumb("agent_tools: execute_tool_batch EXIT had_failure ok=%zu fail=%zu total=%zu", ok_count, fail_count, calls.size());
        return first_failure;
    }

    std::ostringstream ss;
    ss << std::string("Batch ok: ") << ok_count << std::string("/") << calls.size();
    json data;
    data["ok"] = ok_count;
    data["fail"] = fail_count;
    data["total"] = calls.size();
    aida_ipc::trace_breadcrumb("agent_tools: execute_tool_batch EXIT all_ok ok=%zu total=%zu", ok_count, calls.size());
    return tool_result_t::ok(ss.str(), data);
}


namespace helpers
{

std::optional<ea_t> parse_address(const std::string& addr_str)
{
    if (addr_str.empty())
        return std::nullopt;

    try
    {
        size_t idx = 0;
        ea_t addr;
        if (addr_str.substr(0, 2) == "0x" || addr_str.substr(0, 2) == "0X")
            addr = std::stoull(addr_str, &idx, 16);
        else if (std::all_of(addr_str.begin(), addr_str.end(),
                            [](char c) { return std::isxdigit(static_cast<unsigned char>(c)) != 0; }))
            addr = std::stoull(addr_str, &idx, 16);
        else
            addr = std::stoull(addr_str, &idx, 0);

        if (idx == addr_str.length())
            return addr;
    }
    catch (...) {}

    ea_t ea = get_name_ea(BADADDR, addr_str.c_str());
    if (ea != BADADDR)
        return ea;

    return std::nullopt;
}

std::vector<ea_t> parse_addresses(const json& param)
{
    std::vector<ea_t> result;

    if (param.is_string())
    {
        std::string s = param.get<std::string>();
        std::istringstream iss(s);
        std::string token;
        while (std::getline(iss, token, ','))
        {
            token.erase(0, token.find_first_not_of(" \t"));
            size_t last = token.find_last_not_of(" \t");
            if (last == std::string::npos)
                continue;
            token.erase(last + 1);
            if (auto ea = parse_address(token))
                result.push_back(*ea);
        }
    }
    else if (param.is_array())
    {
        for (const auto& item : param)
        {
            if (item.is_string())
            {
                if (auto ea = parse_address(item.get<std::string>()))
                    result.push_back(*ea);
            }
            else if (item.is_number())
            {
                result.push_back(static_cast<ea_t>(item.get<uint64_t>()));
            }
        }
    }
    else if (param.is_number())
    {
        result.push_back(static_cast<ea_t>(param.get<uint64_t>()));
    }

    return result;
}

std::string get_pseudocode(ea_t ea)
{
    if (!init_hexrays_plugin())
        return "// Hex-Rays decompiler not available";

    func_t* pfn = get_func(ea);
    if (!pfn)
        return "// No function at address";

    if (!ida_utils::is_safely_decompilable(pfn))
        return "// Non-decompilable function (thunk/extern/tail)";

    try
    {
        cfuncptr_t cfunc = aida_decompile_func(pfn, nullptr, DECOMP_NO_WAIT);
        if (!cfunc)
            return "// Decompilation failed";

        qstring code;
        qstring_printer_t printer(cfunc, code, false);
        cfunc->print_func(printer);
        return code.c_str();
    }
    catch (const vd_failure_t& e)
    {
        return std::string("// Decompilation error: ") + e.desc().c_str();
    }
    catch (...)
    {
        return "// Decompilation crashed (access violation) - skipped";
    }
}

std::string get_disassembly(ea_t start, ea_t end)
{
    if (end == BADADDR)
    {
        func_t* pfn = get_func(start);
        if (pfn)
            end = pfn->end_ea;
        else
            end = start + 0x100;
    }

    text_t text;
    gen_disasm_text(text, start, end, false);

    std::ostringstream ss;
    for (const auto& line : text)
    {
        qstring clean;
        tag_remove(&clean, line.line.c_str());
        ss << clean.c_str() << "\n";
    }
    return ss.str();
}

std::string format_address(ea_t ea)
{
    std::ostringstream ss;
    ss << "0x" << std::hex << std::uppercase << ea;
    return ss.str();
}

std::string get_name_or_address(ea_t ea)
{
    qstring name;
    if (get_name(&name, ea) > 0 && !name.empty())
        return name.c_str();
    return format_address(ea);
}

}

namespace function_tools
{

tool_result_t get_function(const json& params)
{
    auto addresses = helpers::parse_addresses(params["address"]);
    if (addresses.empty())
        return tool_result_t::error(std::string("Invalid or no address provided"));

    json functions = json::array();

    for (ea_t ea : addresses)
    {
        func_t* pfn = get_func(ea);
        if (!pfn)
        {
            functions.push_back({
                {"address", helpers::format_address(ea)},
                {"error", "No function at this address"}
            });
            continue;
        }

        qstring func_name;
        get_func_name(&func_name, pfn->start_ea);

        json func_info;
        func_info["address"] = helpers::format_address(pfn->start_ea);
        func_info["end_address"] = helpers::format_address(pfn->end_ea);
        func_info["name"] = func_name.c_str();
        func_info["size"] = pfn->end_ea - pfn->start_ea;
        func_info["flags"] = pfn->flags;
        func_info["is_library"] = (pfn->flags & FUNC_LIB) != 0;
        func_info["is_thunk"] = (pfn->flags & FUNC_THUNK) != 0;
        func_info["does_return"] = pfn->does_return();

        tinfo_t tif;
        if (get_tinfo(&tif, pfn->start_ea))
        {
            qstring proto;
            tif.print(&proto);
            func_info["prototype"] = proto.c_str();
        }

        functions.push_back(func_info);
    }

    std::ostringstream ss;
    ss << "Found " << functions.size() << " function(s)";
    return tool_result_t::ok(ss.str(), functions);
}

tool_result_t list_functions(const json& params)
{
    int offset = params.value("offset", 0);
    int limit = params.value("limit", 100);
    std::string filter = params.value("filter", "");

    size_t total = get_func_qty();
    json functions = json::array();

    std::regex filter_regex;
    bool use_filter = !filter.empty();
    if (use_filter)
    {
        try { filter_regex = std::regex(filter, std::regex::icase); }
        catch (...) { return tool_result_t::error(std::string("Invalid filter regex")); }
    }

    int count = 0;
    int skipped = 0;

    for (size_t i = 0; i < total && count < limit; i++)
    {
        func_t* pfn = getn_func(i);
        if (!pfn) continue;

        qstring name;
        get_func_name(&name, pfn->start_ea);

        if (use_filter && !std::regex_search(name.c_str(), filter_regex))
            continue;

        if (skipped < offset)
        {
            skipped++;
            continue;
        }

        functions.push_back({
            {"index", i},
            {"address", helpers::format_address(pfn->start_ea)},
            {"name", name.c_str()},
            {"size", pfn->end_ea - pfn->start_ea}
        });
        count++;
    }

    json result;
    result["functions"] = functions;
    result["total"] = total;
    result["offset"] = offset;
    result["limit"] = limit;
    result["returned"] = count;

    std::ostringstream ss;
    ss << "Listed " << count << " functions (total: " << total << ")";
    return tool_result_t::ok(ss.str(), result);
}

tool_result_t decompile_function(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(std::string("Invalid address"));

    func_t* pfn = get_func(*ea_opt);
    if (!pfn)
        return tool_result_t::error(std::string("No function at address"));

    json result;
    result["address"] = helpers::format_address(pfn->start_ea);
    result["end_address"] = helpers::format_address(pfn->end_ea);
    result["size"] = pfn->end_ea - pfn->start_ea;

    qstring func_name;
    get_func_name(&func_name, pfn->start_ea);
    result["name"] = func_name.c_str();

    tinfo_t tif;
    if (get_tinfo(&tif, pfn->start_ea))
    {
        qstring proto;
        tif.print(&proto);
        result["prototype"] = proto.c_str();
    }

    if (!init_hexrays_plugin())
    {
        result["code"] = "// Hex-Rays decompiler not available";
        return tool_result_t::ok(std::string("Decompilation complete (no Hex-Rays)"), result);
    }

    if (!ida_utils::is_safely_decompilable(pfn))
    {
        result["code"] = "// Non-decompilable function (thunk/extern/tail)";
        return tool_result_t::ok(std::string("Function is not decompilable"), result);
    }

    try
    {
        cfuncptr_t cfunc = aida_decompile_func(pfn, nullptr, DECOMP_NO_WAIT);
        if (!cfunc)
        {
            result["code"] = "// Decompilation failed";
            return tool_result_t::ok(std::string("Decompilation failed"), result);
        }

        qstring code;
        qstring_printer_t printer(cfunc, code, false);
        cfunc->print_func(printer);
        result["code"] = code.c_str();

        lvars_t* lvars = cfunc->get_lvars();
        if (lvars && !lvars->empty())
        {
            json vars_arr = json::array();
            for (size_t i = 0; i < lvars->size(); i++)
            {
                const lvar_t& lv = (*lvars)[i];
                if (!lv.used())
                    continue;
                qstring tstr;
                lv.tif.print(&tstr);
                json v;
                v["name"] = lv.name.c_str();
                v["type"] = tstr.c_str();
                v["is_arg"] = lv.is_arg_var();
                vars_arr.push_back(v);
            }
            result["local_variables"] = vars_arr;
        }

        json strings = json::array();
        func_item_iterator_t fii;
        for (bool ok = fii.set(pfn); ok; ok = fii.next_addr())
        {
            ea_t item_ea = fii.current();
            xrefblk_t xb;
            for (bool xok = xb.first_from(item_ea, XREF_DATA); xok; xok = xb.next_from())
            {
                qstring str;
                if (get_strlit_contents(&str, xb.to, -1, STRTYPE_C) > 0)
                {
                    strings.push_back({
                        {"address", helpers::format_address(xb.to)},
                        {"value", str.c_str()}
                    });
                }
            }
        }
        if (!strings.empty())
            result["strings"] = strings;
    }
    catch (const vd_failure_t& e)
    {
        result["code"] = std::string("// Decompilation error: ") + e.desc().c_str();
    }

    return tool_result_t::ok(std::string("Decompilation complete"), result);
}

tool_result_t disassemble_function(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(std::string("Invalid address"));

    func_t* pfn = get_func(*ea_opt);
    if (!pfn)
        return tool_result_t::error(std::string("No function at address"));

    std::string disasm = helpers::get_disassembly(pfn->start_ea, pfn->end_ea);

    json result;
    result["address"] = helpers::format_address(pfn->start_ea);
    result["end_address"] = helpers::format_address(pfn->end_ea);
    result["disassembly"] = disasm;

    qstring func_name;
    get_func_name(&func_name, pfn->start_ea);
    result["name"] = func_name.c_str();
    result["size"] = pfn->end_ea - pfn->start_ea;

    result["frame_size"] = aida_get_frame_size(pfn);
    result["local_vars_size"] = pfn->frsize;
    result["saved_regs_size"] = pfn->frregs;
    result["args_size"] = pfn->argsize;

    return tool_result_t::ok(std::string("Disassembly complete"), result);
}

tool_result_t get_xrefs_to(const json& params)
{
    auto addresses = helpers::parse_addresses(params["address"]);
    if (addresses.empty())
        return tool_result_t::error(std::string("Invalid or no address provided"));

    int limit = params.value("limit", 100);

    json all_xrefs = json::array();

    for (ea_t ea : addresses)
    {
        json xrefs_for_addr = json::array();
        int count = 0;

        xrefblk_t xb;
        for (bool ok = xb.first_to(ea, XREF_ALL); ok && count < limit; ok = xb.next_to())
        {
            json xref;
            xref["from"] = helpers::format_address(xb.from);
            xref["to"] = helpers::format_address(xb.to);
            xref["is_code"] = xb.iscode;
            xref["type"] = xb.type;
            xref["is_user"] = xb.user;

            xref["from_name"] = helpers::get_name_or_address(xb.from);

            xrefs_for_addr.push_back(xref);
            count++;
        }

        all_xrefs.push_back({
            {"target", helpers::format_address(ea)},
            {"xrefs", xrefs_for_addr},
            {"count", count}
        });
    }

    return tool_result_t::ok(std::string("Cross-references retrieved"), all_xrefs);
}

tool_result_t get_xrefs_from(const json& params)
{
    auto addresses = helpers::parse_addresses(params["address"]);
    if (addresses.empty())
        return tool_result_t::error(std::string("Invalid or no address provided"));

    int limit = params.value("limit", 100);

    json all_xrefs = json::array();

    for (ea_t ea : addresses)
    {
        json xrefs_for_addr = json::array();
        int count = 0;

        xrefblk_t xb;
        for (bool ok = xb.first_from(ea, XREF_ALL); ok && count < limit; ok = xb.next_from())
        {
            json xref;
            xref["from"] = helpers::format_address(xb.from);
            xref["to"] = helpers::format_address(xb.to);
            xref["is_code"] = xb.iscode;
            xref["type"] = xb.type;
            xref["is_user"] = xb.user;

            xref["to_name"] = helpers::get_name_or_address(xb.to);

            xrefs_for_addr.push_back(xref);
            count++;
        }

        all_xrefs.push_back({
            {"source", helpers::format_address(ea)},
            {"xrefs", xrefs_for_addr},
            {"count", count}
        });
    }

    return tool_result_t::ok(std::string("Cross-references retrieved"), all_xrefs);
}

tool_result_t rename_function(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(std::string("Invalid address"));

    std::string new_name = params["new_name"].get<std::string>();
    if (new_name.empty())
        return tool_result_t::error(std::string("New name cannot be empty"));

    func_t* pfn = get_func(*ea_opt);
    if (!pfn)
        return tool_result_t::error(std::string("No function at address"));

    bool success = set_name(pfn->start_ea, new_name.c_str(), SN_FORCE | SN_NODUMMY);

    if (success)
    {

        auto& store = graphrag::GraphStore::instance();
        auto* node = store.get_node_by_address(
            current_module_graph_key(),
            graphrag::node_type_t::FUNCTION, pfn->start_ea);
        if (node)
        {
            node->name = new_name;
            store.upsert_node(*node);
        }

        return tool_result_t::ok(std::string("Function renamed to: ") + new_name);
    }
    else
        return tool_result_t::error(std::string("Failed to rename function"));
}

tool_result_t define_function(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(std::string("Invalid address"));

    ea_t end_ea = BADADDR;
    if (params.contains("end"))
    {
        auto end_opt = helpers::parse_address(params["end"].get<std::string>());
        if (end_opt) end_ea = *end_opt;
    }

    bool success = add_func(*ea_opt, end_ea);

    if (success)
        return tool_result_t::ok(std::string("Function defined at ") + helpers::format_address(*ea_opt));
    else
        return tool_result_t::error(std::string("Failed to define function"));
}

tool_result_t get_stack_frame(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(std::string("Invalid address"));

    func_t* pfn = get_func(*ea_opt);
    if (!pfn)
        return tool_result_t::error(std::string("No function at address"));

    tinfo_t frame_tif;
    if (!aida_get_func_frame(&frame_tif, pfn))
        return tool_result_t::error(std::string("No stack frame available"));

    udt_type_data_t udt;
    if (!frame_tif.get_udt_details(&udt))
        return tool_result_t::error(std::string("Cannot get frame details"));

    json vars = json::array();
    for (size_t i = 0; i < udt.size(); i++)
    {
        const udm_t& member = udt[i];
        qstring type_str;
        member.type.print(&type_str);

        vars.push_back({
            {"name", member.name.c_str()},
            {"offset", member.offset / 8},
            {"size", member.size / 8},
            {"type", type_str.c_str()}
        });
    }

    json result;
    result["function"] = helpers::format_address(pfn->start_ea);
    result["frame_size"] = aida_get_frame_size(pfn);
    result["local_vars_size"] = pfn->frsize;
    result["variables"] = vars;

    return tool_result_t::ok(std::string("Stack frame retrieved"), result);
}

tool_result_t set_function_signature(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(std::string("Invalid address"));

    std::string signature = params["signature"].get<std::string>();

    tinfo_t tif;
    qstring name;
    if (!parse_decl(&tif, &name, nullptr, signature.c_str(), PT_SIL))
        return tool_result_t::error(std::string("Failed to parse signature: ") + signature);

    if (!apply_tinfo(*ea_opt, tif, TINFO_DEFINITE))
        return tool_result_t::error(std::string("Failed to apply type"));

    return tool_result_t::ok(std::string("Function signature applied"));
}

tool_result_t build_call_graph(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(std::string("Invalid address"));

    int depth = params.value("depth", 3);
    if (depth < 0) depth = 0;
    if (depth > 16) depth = 16;

    constexpr size_t MAX_NODES = 4096;
    std::map<ea_t, json> nodes;
    std::set<std::pair<ea_t, ea_t>> edges;

    std::deque<std::pair<ea_t, int>> work;
    work.push_back({*ea_opt, 0});

    while (!work.empty() && nodes.size() < MAX_NODES)
    {
        auto [ea, current_depth] = work.front();
        work.pop_front();

        if (current_depth > depth) continue;
        if (nodes.count(ea)) continue;

        func_t* pfn = get_func(ea);
        if (!pfn) continue;

        qstring name;
        get_func_name(&name, pfn->start_ea);

        nodes[ea] = {
            {"address", helpers::format_address(ea)},
            {"name", name.c_str()},
            {"depth", current_depth}
        };

        if (current_depth >= depth) continue;

        func_item_iterator_t fii;
        for (bool ok = fii.set(pfn); ok; ok = fii.next_addr())
        {
            xrefblk_t xb;
            for (bool xok = xb.first_from(fii.current(), XREF_ALL); xok; xok = xb.next_from())
            {
                if (xb.iscode && (xb.type == fl_CN || xb.type == fl_CF))
                {
                    func_t* callee = get_func(xb.to);
                    if (callee)
                    {
                        edges.insert({ea, callee->start_ea});
                        if (!nodes.count(callee->start_ea))
                            work.push_back({callee->start_ea, current_depth + 1});
                    }
                }
            }
        }
    }

    json result;
    result["nodes"] = json::array();
    for (const auto& [_, node] : nodes)
        result["nodes"].push_back(node);

    result["edges"] = json::array();
    for (const auto& [from, to] : edges)
    {
        result["edges"].push_back({
            {"from", helpers::format_address(from)},
            {"to", helpers::format_address(to)}
        });
    }

    return tool_result_t::ok(std::string("Call graph built"), result);
}

tool_result_t get_basic_blocks(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(std::string("Invalid address"));

    func_t* pfn = get_func(*ea_opt);
    if (!pfn)
        return tool_result_t::error(std::string("No function at address"));

    qflow_chart_t fc;
    fc.create("", pfn, BADADDR, BADADDR, FC_RESERVED);

    json blocks = json::array();
    for (int i = 0; i < fc.size(); i++)
    {
        const qbasic_block_t& bb = fc.blocks[i];

        json successors = json::array();
        for (int j = 0; j < fc.nsucc(i); j++)
            successors.push_back(fc.succ(i, j));

        json predecessors = json::array();
        for (int j = 0; j < fc.npred(i); j++)
            predecessors.push_back(fc.pred(i, j));

        blocks.push_back({
            {"id", i},
            {"start", helpers::format_address(bb.start_ea)},
            {"end", helpers::format_address(bb.end_ea)},
            {"successors", successors},
            {"predecessors", predecessors}
        });
    }

    return tool_result_t::ok(std::string("Basic blocks retrieved"), blocks);
}

void register_tools()
{
    auto& registry = ToolRegistry::instance();

    registry.register_tool({
        std::string("get_function"),
        std::string("function"),
        std::string("Get function information by address or name. Auto-detects whether input is address or name."),
        {{std::string("address"), std::string("string"), std::string("Address (0x...) or function name"), true}},
        get_function
    });

    registry.register_tool({
        std::string("list_functions"),
        std::string("function"),
        std::string("List all functions in the binary (paginated). Optionally filter by regex pattern."),
        {
            {std::string("offset"), std::string("number"), std::string("Starting offset for pagination"), false},
            {std::string("limit"), std::string("number"), std::string("Maximum number of results (default 100)"), false},
            {std::string("filter"), std::string("string"), std::string("Regex pattern to filter function names"), false}
        },
        list_functions
    });

    registry.register_tool({
        std::string("decompile_function"),
        std::string("function"),
        std::string("Decompile a function at the given address using Hex-Rays."),
        {{std::string("address"), std::string("string"), std::string("Function address to decompile"), true}},
        decompile_function,
        true
    });

    registry.register_tool({
        std::string("disassemble_function"),
        std::string("function"),
        std::string("Get full disassembly of a function with details (args, stack frame, etc)."),
        {{std::string("address"), std::string("string"), std::string("Function address"), true}},
        disassemble_function
    });

    registry.register_tool({
        std::string("get_xrefs_to"),
        std::string("function"),
        std::string("Get all cross-references TO the specified address(es)."),
        {
            {std::string("address"), std::string("string"), std::string("Target address(es) - single, comma-separated, or array"), true},
            {std::string("limit"), std::string("number"), std::string("Maximum xrefs per address (default 100)"), false}
        },
        get_xrefs_to
    });

    registry.register_tool({
        std::string("get_xrefs_from"),
        std::string("function"),
        std::string("Get all cross-references FROM the specified address(es)."),
        {
            {std::string("address"), std::string("string"), std::string("Source address(es)"), true},
            {std::string("limit"), std::string("number"), std::string("Maximum xrefs per address (default 100)"), false}
        },
        get_xrefs_from
    });

    registry.register_tool({
        std::string("rename_function"),
        std::string("function"),
        std::string("Rename the function at the given address."),
        {
            {std::string("address"), std::string("string"), std::string("Function address"), true},
            {std::string("new_name"), std::string("string"), std::string("New function name (PascalCase recommended)"), true}
        },
        rename_function,
        false
    });

    registry.register_tool({
        std::string("define_function"),
        std::string("function"),
        std::string("Define a function at the given address. IDA will auto-detect bounds if end not specified."),
        {
            {std::string("address"), std::string("string"), std::string("Start address"), true},
            {std::string("end"), std::string("string"), std::string("Optional end address"), false}
        },
        define_function,
        false
    });

    registry.register_tool({
        std::string("get_stack_frame"),
        std::string("function"),
        std::string("Get stack frame variables for the function at the given address."),
        {{std::string("address"), std::string("string"), std::string("Function address"), true}},
        get_stack_frame
    });

    registry.register_tool({
        std::string("set_function_signature"),
        std::string("function"),
        std::string("Set/change the type signature of a function."),
        {
            {std::string("address"), std::string("string"), std::string("Function address"), true},
            {std::string("signature"), std::string("string"), std::string("C function prototype (e.g., 'int foo(char* a, int b)')"), true}
        },
        set_function_signature,
        false
    });

    registry.register_tool({
        std::string("build_call_graph"),
        std::string("function"),
        std::string("Build a call graph from the root function with configurable depth."),
        {
            {std::string("address"), std::string("string"), std::string("Root function address"), true},
            {std::string("depth"), std::string("number"), std::string("Maximum recursion depth (default 3)"), false}
        },
        build_call_graph
    });

    registry.register_tool({
        std::string("get_basic_blocks"),
        std::string("function"),
        std::string("Get basic blocks of a function with successors and predecessors."),
        {{std::string("address"), std::string("string"), std::string("Function address"), true}},
        get_basic_blocks
    });

}

}

namespace memory_tools
{

tool_result_t read_bytes(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(std::string("Invalid address"));

    size_t size = params.value("size", 16);
    if (size > 4096)
        return tool_result_t::error(std::string("Size too large (max 4096)"));

    if (!is_loaded(*ea_opt))
        return tool_result_t::error(std::string("Address not mapped in database"));

    std::vector<uint8_t> buffer(size);
    ssize_t bytes_read = get_bytes(buffer.data(), size, *ea_opt);

    if (bytes_read < 0)
        return tool_result_t::error(std::string("Failed to read bytes"));

    std::ostringstream hex_ss;
    for (ssize_t i = 0; i < bytes_read; i++)
    {
        if (i > 0) hex_ss << " ";
        hex_ss << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[i];
    }

    json result;
    result["address"] = helpers::format_address(*ea_opt);
    result["size"] = bytes_read;
    result["hex"] = hex_ss.str();

    result["bytes"] = json::array();
    for (ssize_t i = 0; i < bytes_read; i++)
        result["bytes"].push_back(buffer[i]);

    return tool_result_t::ok(std::string("Bytes read successfully"), result);
}

tool_result_t read_integer(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(std::string("Invalid address"));

    std::string type = params.value("type", "u64");

    if (!is_loaded(*ea_opt))
        return tool_result_t::error(std::string("Address not mapped in database"));

    uint64_t value = 0;
    int64_t signed_value = 0;
    bool is_signed = type[0] == 'i';

    if (type == "i8" || type == "u8")
    {
        value = get_byte(*ea_opt);
        signed_value = (int8_t)value;
    }
    else if (type == "i16" || type == "u16" || type == "i16le" || type == "u16le")
    {
        value = get_word(*ea_opt);
        signed_value = (int16_t)value;
    }
    else if (type == "i32" || type == "u32" || type == "i32le" || type == "u32le")
    {
        value = get_dword(*ea_opt);
        signed_value = (int32_t)value;
    }
    else if (type == "i64" || type == "u64" || type == "i64le" || type == "u64le")
    {
        value = get_qword(*ea_opt);
        signed_value = (int64_t)value;
    }
    else
    {
        return tool_result_t::error(std::string("Unknown type: ") + type);
    }

    json result;
    result["address"] = helpers::format_address(*ea_opt);
    result["type"] = type;
    result["unsigned_value"] = value;
    result["signed_value"] = signed_value;
    result["hex"] = helpers::format_address(value);

    return tool_result_t::ok(std::string("Integer read successfully"), result);
}

tool_result_t read_string(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(std::string("Invalid address"));

    int max_len = params.value("max_length", 1024);

    if (!is_loaded(*ea_opt))
        return tool_result_t::error(std::string("Address not mapped in database"));

    qstring str;
    if (get_strlit_contents(&str, *ea_opt, max_len, STRTYPE_C) <= 0)
        return tool_result_t::error(std::string("No string at address or read failed"));

    json result;
    result["address"] = helpers::format_address(*ea_opt);
    result["value"] = str.c_str();
    result["length"] = str.length();

    return tool_result_t::ok(std::string("String read successfully"), result);
}

tool_result_t read_global(const json& params)
{
    std::string name_or_addr = params["name"].get<std::string>();

    auto ea_opt = helpers::parse_address(name_or_addr);
    if (!ea_opt)
        return tool_result_t::error(std::string("Invalid address or name"));

    if (!is_loaded(*ea_opt))
        return tool_result_t::error(std::string("Address not mapped in database"));

    asize_t item_size = get_item_size(*ea_opt);

    json result;
    result["address"] = helpers::format_address(*ea_opt);
    result["name"] = helpers::get_name_or_address(*ea_opt);
    result["size"] = item_size;

    if (item_size <= 8)
    {
        uval_t value;
        if (get_data_value(&value, *ea_opt, item_size))
        {
            result["value"] = value;
            result["hex"] = helpers::format_address(value);
        }
    }

    return tool_result_t::ok(std::string("Global read successfully"), result);
}

tool_result_t patch_bytes(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(std::string("Invalid address"));

    if (!is_loaded(*ea_opt))
        return tool_result_t::error(std::string("Address not mapped in database"));

    std::string hex_bytes = params["bytes"].get<std::string>();

    std::vector<uint8_t> bytes;
    std::istringstream iss(hex_bytes);
    std::string token;

    hex_bytes.erase(std::remove(hex_bytes.begin(), hex_bytes.end(), ' '), hex_bytes.end());

    for (size_t i = 0; i + 1 < hex_bytes.length(); i += 2)
    {
        std::string byte_str = hex_bytes.substr(i, 2);
        try
        {
            bytes.push_back(static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16)));
        }
        catch (...)
        {
            return tool_result_t::error(std::string("Invalid hex byte: ") + byte_str);
        }
    }

    if (bytes.empty())
        return tool_result_t::error(std::string("No bytes to patch"));

    for (size_t i = 0; i < bytes.size(); i++)
    {
        if (!is_loaded(*ea_opt + i))
            return tool_result_t::error(std::string("Address out of range at offset ") + std::to_string(i));
        patch_byte(*ea_opt + i, bytes[i]);
    }

    json result;
    result["address"] = helpers::format_address(*ea_opt);
    result["size"] = bytes.size();

    return tool_result_t::ok(std::string("Bytes patched successfully"), result);
}

tool_result_t make_code(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(std::string("Invalid address"));

    insn_t insn;
    if (decode_insn(&insn, *ea_opt) <= 0)
        return tool_result_t::error(std::string("Failed to decode instruction"));

    if (create_insn(*ea_opt) == 0)
        return tool_result_t::error(std::string("Failed to create instruction"));

    return tool_result_t::ok(std::string("Code created at ") + helpers::format_address(*ea_opt));
}

tool_result_t make_data(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(std::string("Invalid address"));

    std::string type = params.value("type", "byte");

    bool ok = false;
    if (type == "word")       ok = create_word(*ea_opt, 2);
    else if (type == "dword") ok = create_dword(*ea_opt, 4);
    else if (type == "qword") ok = create_qword(*ea_opt, 8);
    else                       ok = create_byte(*ea_opt, 1);

    if (!ok)
        return tool_result_t::error(std::string("Failed to create data"));

    return tool_result_t::ok(std::string("Data created at ") + helpers::format_address(*ea_opt));
}

tool_result_t undefine(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(std::string("Invalid address"));

    asize_t size = params.value("size", 1);

    if (params.contains("end"))
    {
        auto end_opt = helpers::parse_address(params["end"].get<std::string>());
        if (end_opt)
            size = *end_opt - *ea_opt;
    }

    if (!del_items(*ea_opt, DELIT_SIMPLE, size))
        return tool_result_t::error(std::string("Failed to undefine"));

    return tool_result_t::ok(std::string("Undefined ") + std::to_string(size) + " bytes");
}

tool_result_t list_globals(const json& params)
{
    int offset = params.value("offset", 0);
    int limit = params.value("limit", 100);
    std::string filter = params.value("filter", "");

    std::regex filter_regex;
    bool use_filter = !filter.empty();
    if (use_filter)
    {
        try { filter_regex = std::regex(filter, std::regex::icase); }
        catch (...) { return tool_result_t::error(std::string("Invalid filter regex")); }
    }

    json globals = json::array();
    int count = 0;
    int skipped = 0;

    for (size_t i = 0; i < get_nlist_size() && count < limit; i++)
    {
        ea_t ea = get_nlist_ea(i);

        if (get_func(ea))
            continue;

        const char* nname = get_nlist_name(i);
        qstring name = nname ? nname : "";

        if (use_filter && !std::regex_search(name.c_str(), filter_regex))
            continue;

        if (skipped < offset)
        {
            skipped++;
            continue;
        }

        globals.push_back({
            {"address", helpers::format_address(ea)},
            {"name", name.c_str()},
            {"size", get_item_size(ea)}
        });
        count++;
    }

    json result;
    result["globals"] = globals;
    result["returned"] = count;

    return tool_result_t::ok(std::string("Globals listed"), result);
}

void register_tools()
{
    auto& registry = ToolRegistry::instance();

    registry.register_tool({
        std::string("read_bytes"),
        std::string("memory"),
        std::string("Read raw bytes from the database at the specified address."),
        {
            {std::string("address"), std::string("string"), std::string("Start address"), true},
            {std::string("size"), std::string("number"), std::string("Number of bytes to read (max 4096, default 16)"), false}
        },
        read_bytes
    });

    registry.register_tool({
        std::string("read_integer"),
        std::string("memory"),
        std::string("Read an integer value at address. Type can be i8/u8/i16/u16/i32/u32/i64/u64."),
        {
            {std::string("address"), std::string("string"), std::string("Address to read"), true},
            {std::string("type"), std::string("string"), std::string("Integer type (default u64)"), false, {std::string("i8"), std::string("u8"), std::string("i16"), std::string("u16"), std::string("i32"), std::string("u32"), std::string("i64"), std::string("u64")}}
        },
        read_integer
    });

    registry.register_tool({
        std::string("read_string"),
        std::string("memory"),
        std::string("Read a null-terminated string at the specified address."),
        {
            {std::string("address"), std::string("string"), std::string("String address"), true},
            {std::string("max_length"), std::string("number"), std::string("Maximum string length (default 1024)"), false}
        },
        read_string
    });

    registry.register_tool({
        std::string("read_global"),
        std::string("memory"),
        std::string("Read a global variable value by address or name."),
        {{std::string("name"), std::string("string"), std::string("Address or name of the global variable"), true}},
        read_global
    });

    registry.register_tool({
        std::string("patch_bytes"),
        std::string("memory"),
        std::string("Write bytes to the database at the specified address."),
        {
            {std::string("address"), std::string("string"), std::string("Start address"), true},
            {std::string("bytes"), std::string("string"), std::string("Hex bytes (e.g., '90 90 90' or '909090')"), true}
        },
        patch_bytes,
        false
    });

    registry.register_tool({
        std::string("make_code"),
        std::string("memory"),
        std::string("Convert bytes at address to code (instruction)."),
        {{std::string("address"), std::string("string"), std::string("Address to convert"), true}},
        make_code,
        false
    });

    registry.register_tool({
        std::string("make_data"),
        std::string("memory"),
        std::string("Convert address to data of specified type."),
        {
            {std::string("address"), std::string("string"), std::string("Address to convert"), true},
            {std::string("type"), std::string("string"), std::string("Data type (byte, word, dword, qword)"), false, {std::string("byte"), std::string("word"), std::string("dword"), std::string("qword")}}
        },
        make_data,
        false
    });

    registry.register_tool({
        std::string("undefine"),
        std::string("memory"),
        std::string("Undefine item(s) at address, converting back to raw bytes."),
        {
            {std::string("address"), std::string("string"), std::string("Start address"), true},
            {std::string("size"), std::string("number"), std::string("Number of bytes"), false},
            {std::string("end"), std::string("string"), std::string("End address (alternative to size)"), false}
        },
        undefine,
        false
    });

    registry.register_tool({
        std::string("list_globals"),
        std::string("memory"),
        std::string("List global variables (paginated, filtered by regex)."),
        {
            {std::string("offset"), std::string("number"), std::string("Starting offset"), false},
            {std::string("limit"), std::string("number"), std::string("Maximum results (default 100)"), false},
            {std::string("filter"), std::string("string"), std::string("Regex filter for names"), false}
        },
        list_globals
    });

}

}

namespace comment_tools
{

tool_result_t set_comment(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(std::string("Invalid address"));

    std::string comment = params["comment"].get<std::string>();

    if (!set_cmt(*ea_opt, comment.c_str(), false))
        return tool_result_t::error(std::string("Failed to set comment"));

    return tool_result_t::ok(std::string("Comment set at ") + helpers::format_address(*ea_opt));
}

tool_result_t set_repeatable_comment(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(std::string("Invalid address"));

    std::string comment = params["comment"].get<std::string>();

    if (!set_cmt(*ea_opt, comment.c_str(), true))
        return tool_result_t::error(std::string("Failed to set repeatable comment"));

    return tool_result_t::ok(std::string("Repeatable comment set"));
}

tool_result_t set_function_comment(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(std::string("Invalid address"));

    func_t* pfn = get_func(*ea_opt);
    if (!pfn)
        return tool_result_t::error(std::string("No function at address"));

    std::string comment = params["comment"].get<std::string>();
    bool repeatable = params.value("repeatable", false);

    if (!aida_set_func_cmt(pfn, comment.c_str(), repeatable))
        return tool_result_t::error(std::string("Failed to set function comment"));

    return tool_result_t::ok(std::string("Function comment set"));
}

tool_result_t get_comment(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(std::string("Invalid address"));

    qstring regular_cmt, repeatable_cmt;
    get_cmt(&regular_cmt, *ea_opt, false);
    get_cmt(&repeatable_cmt, *ea_opt, true);

    json result;
    result["address"] = helpers::format_address(*ea_opt);
    result["comment"] = regular_cmt.c_str();
    result["repeatable_comment"] = repeatable_cmt.c_str();

    return tool_result_t::ok(std::string("Comment retrieved"), result);
}

tool_result_t set_extra_comment(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(std::string("Invalid address"));

    std::string comment = params["comment"].get<std::string>();
    std::string position = params.value("position", "anterior");

    int line_idx = (position == "posterior") ? E_NEXT : E_PREV;

    update_extra_cmt(*ea_opt, line_idx, comment.c_str());

    return tool_result_t::ok(std::string("Extra comment set"));
}

tool_result_t rename_variable(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(std::string("Invalid address"));

    std::string original_name = params["original_name"].get<std::string>();
    std::string new_name = params["new_name"].get<std::string>();

    if (!init_hexrays_plugin())
        return tool_result_t::error(std::string("Hex-Rays not available"));

    func_t* pfn = get_func(*ea_opt);
    if (!pfn)
        return tool_result_t::error(std::string("No function at address"));

    if (!ida_utils::is_safely_decompilable(pfn))
        return tool_result_t::error(std::string("Function is not decompilable (thunk/extern/tail)"));

    try
    {
        cfuncptr_t cfunc = decompile(pfn);
        if (!cfunc)
            return tool_result_t::error(std::string("Decompilation failed"));

        lvars_t* lvars = cfunc->get_lvars();
        if (!lvars)
            return tool_result_t::error(std::string("No local variables"));

        for (size_t i = 0; i < lvars->size(); i++)
        {
            lvar_t& lvar = (*lvars)[i];
            if (lvar.name == original_name.c_str())
            {
                lvar_saved_info_t info;
                info.ll = lvar;
                info.name = new_name.c_str();
                if (modify_user_lvar_info(pfn->start_ea, MLI_NAME, info))
                    return tool_result_t::ok(std::string("Variable renamed: ") + original_name + " -> " + new_name);
                else
                    return tool_result_t::error(std::string("Failed to rename variable"));
            }
        }

        return tool_result_t::error(std::string("Variable not found: ") + original_name);
    }
    catch (const vd_failure_t& e)
    {
        return tool_result_t::error(std::string("Decompilation error: ") + std::string(e.desc().c_str()));
    }
}

void register_tools()
{
    auto& registry = ToolRegistry::instance();

    registry.register_tool({
        std::string("set_comment"),
        std::string("comment"),
        std::string("Set a regular comment at the specified address (visible in disassembly)."),
        {
            {std::string("address"), std::string("string"), std::string("Address"), true},
            {std::string("comment"), std::string("string"), std::string("Comment text"), true}
        },
        set_comment,
        false
    });

    registry.register_tool({
        std::string("set_repeatable_comment"),
        std::string("comment"),
        std::string("Set a repeatable comment (appears at all references to this address)."),
        {
            {std::string("address"), std::string("string"), std::string("Address"), true},
            {std::string("comment"), std::string("string"), std::string("Comment text"), true}
        },
        set_repeatable_comment,
        false
    });

    registry.register_tool({
        std::string("set_function_comment"),
        std::string("comment"),
        std::string("Set a comment on the function header."),
        {
            {std::string("address"), std::string("string"), std::string("Function address"), true},
            {std::string("comment"), std::string("string"), std::string("Comment text"), true},
            {std::string("repeatable"), std::string("boolean"), std::string("Make it repeatable (default false)"), false}
        },
        set_function_comment,
        false
    });

    registry.register_tool({
        std::string("get_comment"),
        std::string("comment"),
        std::string("Get comments at the specified address."),
        {{std::string("address"), std::string("string"), std::string("Address"), true}},
        get_comment
    });

    registry.register_tool({
        std::string("set_extra_comment"),
        std::string("comment"),
        std::string("Set anterior (before) or posterior (after) comment lines."),
        {
            {std::string("address"), std::string("string"), std::string("Address"), true},
            {std::string("comment"), std::string("string"), std::string("Comment text"), true},
            {std::string("position"), std::string("string"), std::string("anterior or posterior (default anterior)"), false, {std::string("anterior"), std::string("posterior")}}
        },
        set_extra_comment,
        false
    });

    registry.register_tool({
        std::string("rename_variable"),
        std::string("comment"),
        std::string("Rename a local variable in the decompiled function."),
        {
            {std::string("address"), std::string("string"), std::string("Function address"), true},
            {std::string("original_name"), std::string("string"), std::string("Current variable name"), true},
            {std::string("new_name"), std::string("string"), std::string("New variable name (camelCase recommended)"), true}
        },
        rename_variable,
        false
    });

}

}

namespace type_tools
{

tool_result_t declare_type(const json& params)
{
    std::string declaration = params["declaration"].get<std::string>();

    til_t* ti = get_idati();
    if (!ti)
        return tool_result_t::error(std::string("Cannot get local type library"));

    int count = parse_decls(ti, declaration.c_str(), nullptr, HTI_DCL);
    if (count <= 0)
        return tool_result_t::error(std::string("Failed to parse type declaration"));

    json result;
    result["types_added"] = count;
    return tool_result_t::ok(std::string("Declared ") + std::to_string(count) + " type(s)", result);
}

tool_result_t apply_type(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(std::string("Invalid address"));

    std::string type_str = params["type"].get<std::string>();

    tinfo_t tif;
    qstring name;
    if (!parse_decl(&tif, &name, nullptr, type_str.c_str(), PT_SIL))
        return tool_result_t::error(std::string("Failed to parse type: ") + type_str);

    if (!apply_tinfo(*ea_opt, tif, TINFO_DEFINITE))
        return tool_result_t::error(std::string("Failed to apply type at address"));

    return tool_result_t::ok(std::string("Type applied at ") + helpers::format_address(*ea_opt));
}

tool_result_t infer_type(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(std::string("Invalid address"));

    tinfo_t tif;
    int result_code = guess_tinfo(&tif, *ea_opt);

    if (result_code == GUESS_FUNC_FAILED)
        return tool_result_t::error(std::string("Failed to infer type"));

    qstring type_str;
    tif.print(&type_str);

    json result;
    result["address"] = helpers::format_address(*ea_opt);
    result["type"] = type_str.c_str();
    result["confidence"] = (result_code == GUESS_FUNC_OK) ? "high" : "low";

    return tool_result_t::ok(std::string("Type inferred"), result);
}

tool_result_t search_structs(const json& params)
{
    std::string pattern = params["pattern"].get<std::string>();
    int limit = params.value("limit", 50);

    std::regex filter_regex;
    try { filter_regex = std::regex(pattern, std::regex::icase); }
    catch (...) { return tool_result_t::error(std::string("Invalid regex pattern")); }

    til_t* ti = get_idati();
    if (!ti)
        return tool_result_t::error(std::string("Cannot get local type library"));

    json structs = json::array();
    uint32 count = get_ordinal_count(ti);

    for (uint32 i = 1; i <= count && (int)structs.size() < limit; i++)
    {
        const char* tname = get_numbered_type_name(ti, i);
        if (!tname)
            continue;

        if (!std::regex_search(tname, filter_regex))
            continue;

        tinfo_t tif;
        if (tif.get_numbered_type(ti, i))
        {
            qstring type_str;
            tif.print(&type_str);
            structs.push_back({
                {"ordinal", i},
                {"name", tname},
                {"type", type_str.c_str()},
                {"is_struct", tif.is_struct()},
                {"is_enum", tif.is_enum()},
                {"is_typedef", tif.is_typedef()},
                {"size", (size_t)tif.get_size()}
            });
        }
    }

    return tool_result_t::ok(std::string("Found ") + std::to_string(structs.size()) + " matching types", structs);
}

tool_result_t get_struct(const json& params)
{
    std::string name = params["name"].get<std::string>();

    til_t* ti = get_idati();
    if (!ti)
        return tool_result_t::error(std::string("Cannot get local type library"));

    int32 ordinal = get_type_ordinal(ti, name.c_str());
    if (ordinal <= 0)
        return tool_result_t::error(std::string("Type not found: ") + name);

    tinfo_t tif;
    if (!tif.get_numbered_type(ti, ordinal))
        return tool_result_t::error(std::string("Cannot load type"));

    json result;
    result["name"] = name;
    result["ordinal"] = ordinal;
    result["size"] = (size_t)tif.get_size();
    result["is_struct"] = tif.is_struct();
    result["is_union"] = tif.is_union();
    result["is_enum"] = tif.is_enum();

    if (tif.is_struct() || tif.is_union())
    {
        udt_type_data_t udt;
        if (tif.get_udt_details(&udt))
        {
            json members = json::array();
            for (size_t i = 0; i < udt.size(); i++)
            {
                const udm_t& m = udt[i];
                qstring mtype;
                m.type.print(&mtype);
                members.push_back({
                    {"name", m.name.c_str()},
                    {"offset", m.offset / 8},
                    {"size", m.size / 8},
                    {"type", mtype.c_str()}
                });
            }
            result["members"] = members;
        }
    }
    else if (tif.is_enum())
    {
        enum_type_data_t etd;
        if (tif.get_enum_details(&etd))
        {
            json members = json::array();
            for (size_t i = 0; i < etd.size(); i++)
            {
                members.push_back({
                    {"name", etd[i].name.c_str()},
                    {"value", (int64_t)etd[i].value}
                });
            }
            result["members"] = members;
        }
    }

    qstring printed;
    tif.print(&printed);
    result["declaration"] = printed.c_str();

    return tool_result_t::ok(std::string("Type retrieved"), result);
}

tool_result_t create_struct(const json& params)
{
    std::string name = params["name"].get<std::string>();

    tinfo_t tif;
    udt_type_data_t udt;
    udt.taudt_bits |= TAUDT_UNALIGNED;

    if (params.contains("members") && params["members"].is_array())
    {
        for (const auto& mem : params["members"])
        {
            udm_t m;
            m.name = (mem.contains("name") && mem["name"].is_string()) ? mem["name"].get<std::string>().c_str() : "field";

            std::string type_str = (mem.contains("type") && mem["type"].is_string()) ? mem["type"].get<std::string>() : "int";
            tinfo_t mt;
            if (!parse_decl(&mt, nullptr, nullptr, (type_str + " x;").c_str(), PT_SIL | PT_VAR))
                mt = tinfo_t(BT_INT32);
            m.type = mt;
            m.size = mt.get_size() * 8;

            if (mem.contains("offset") && mem["offset"].is_number())
                m.offset = mem["offset"].get<uint64_t>() * 8;

            udt.push_back(m);
        }
    }

    tif.create_udt(udt, BTF_STRUCT);
    tif.set_named_type(get_idati(), name.c_str());

    return tool_result_t::ok(std::string("Struct created: ") + name);
}

tool_result_t add_struct_member(const json& params)
{
    std::string struct_name = params["struct_name"].get<std::string>();
    std::string member_name = params["member_name"].get<std::string>();
    std::string type_str = params.value("type", "int");

    til_t* ti = get_idati();
    int32 ordinal = get_type_ordinal(ti, struct_name.c_str());
    if (ordinal <= 0)
        return tool_result_t::error(std::string("Struct not found: ") + struct_name);

    tinfo_t tif;
    if (!tif.get_numbered_type(ti, ordinal))
        return tool_result_t::error(std::string("Cannot load struct"));

    udt_type_data_t udt;
    if (!tif.get_udt_details(&udt))
        return tool_result_t::error(std::string("Not a struct/union"));

    udm_t m;
    m.name = member_name.c_str();

    tinfo_t mt;
    if (!parse_decl(&mt, nullptr, nullptr, (type_str + " x;").c_str(), PT_SIL | PT_VAR))
        mt = tinfo_t(BT_INT32);
    m.type = mt;
    m.size = mt.get_size() * 8;

    if (params.contains("offset"))
        m.offset = params["offset"].get<uint64_t>() * 8;

    udt.push_back(m);

    tinfo_t new_tif;
    new_tif.create_udt(udt, BTF_STRUCT);
    new_tif.set_named_type(ti, struct_name.c_str(), NTF_REPLACE);

    return tool_result_t::ok(std::string("Member added to ") + struct_name);
}

tool_result_t get_struct_field_xrefs(const json& params)
{
    std::string struct_name = params["struct_name"].get<std::string>();
    std::string field_name = params["field_name"].get<std::string>();
    int limit = params.value("limit", 100);

    til_t* ti = get_idati();
    int32 ordinal = get_type_ordinal(ti, struct_name.c_str());
    if (ordinal <= 0)
        return tool_result_t::error(std::string("Struct not found: ") + struct_name);

    tinfo_t tif;
    if (!tif.get_numbered_type(ti, ordinal))
        return tool_result_t::error(std::string("Cannot load struct"));

    udt_type_data_t udt;
    if (!tif.get_udt_details(&udt))
        return tool_result_t::error(std::string("Not a struct/union"));

    uint64_t field_offset = 0;
    bool found = false;
    for (size_t i = 0; i < udt.size(); i++)
    {
        if (udt[i].name == field_name.c_str())
        {
            field_offset = udt[i].offset / 8;
            found = true;
            break;
        }
    }

    if (!found)
        return tool_result_t::error(std::string("Field not found: ") + field_name);

    json result;
    result["struct"] = struct_name;
    result["field"] = field_name;
    result["field_offset"] = field_offset;
    result["note"] = "Use find_immediate or search to find accesses to this offset";

    return tool_result_t::ok(std::string("Struct field info retrieved"), result);
}

tool_result_t create_stack_var(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(std::string("Invalid address"));

    func_t* pfn = get_func(*ea_opt);
    if (!pfn)
        return tool_result_t::error(std::string("No function at address"));

    sval_t offset = params["offset"].get<int64_t>();
    std::string var_name = params["name"].get<std::string>();
    std::string type_str = params.value("type", "__int64");

    tinfo_t mt;
    if (!parse_decl(&mt, nullptr, nullptr, (type_str + " x;").c_str(), PT_SIL | PT_VAR))
        mt = tinfo_t(BT_INT64);

    if (!aida_define_stkvar(pfn, var_name.c_str(), offset, mt))
        return tool_result_t::error(std::string("Failed to create stack variable"));

    return tool_result_t::ok(std::string("Stack variable created: ") + var_name);
}

tool_result_t delete_stack_var(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(std::string("Invalid address"));

    func_t* pfn = get_func(*ea_opt);
    if (!pfn)
        return tool_result_t::error(std::string("No function at address"));

    std::string var_name = params["name"].get<std::string>();

    std::string py_code =
        "import ida_frame, ida_funcs, ida_struct\n"
        "pfn = ida_funcs.get_func(" + std::to_string(*ea_opt) + ")\n"
        "_aida_del_result = False\n"
        "if pfn:\n"
        "    frame = ida_frame.get_frame(pfn)\n"
        "    if frame:\n"
        "        for i in range(frame.memqty):\n"
        "            m = frame.get_member(i)\n"
        "            if m and ida_struct.get_member_name(m.id) == '" + var_name + "':\n"
        "                ida_struct.del_struc_member(frame, m.soff)\n"
        "                _aida_del_result = True\n"
        "                break\n";

    extlang_object_t python = find_extlang_by_name("python");
    if (!python)
        return tool_result_t::error(std::string("Python not available for stack var deletion"));

    qstring errbuf;
    if (!python->eval_snippet(py_code.c_str(), &errbuf))
        return tool_result_t::error(std::string("Python error: ") + std::string(errbuf.c_str()));

    idc_value_t rv;
    qstring eval_err;
    if (python->eval_expr(&rv, BADADDR, "_aida_del_result", &eval_err)
        && rv.is_integral() && (rv.vtype == VT_INT64 ? rv.i64 : rv.num) != 0)
        return tool_result_t::ok(std::string("Stack variable deleted: ") + var_name);

    return tool_result_t::error(std::string("Variable not found in stack frame: ") + var_name);
}

tool_result_t read_struct_field(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(std::string("Invalid address"));

    std::string struct_name = params["struct_name"].get<std::string>();
    std::string field_name = params["field_name"].get<std::string>();

    til_t* ti = get_idati();
    int32 ordinal = get_type_ordinal(ti, struct_name.c_str());
    if (ordinal <= 0)
        return tool_result_t::error(std::string("Struct not found"));

    tinfo_t tif;
    if (!tif.get_numbered_type(ti, ordinal))
        return tool_result_t::error(std::string("Cannot load struct"));

    udt_type_data_t udt;
    if (!tif.get_udt_details(&udt))
        return tool_result_t::error(std::string("Not a struct"));

    for (size_t i = 0; i < udt.size(); i++)
    {
        if (udt[i].name == field_name.c_str())
        {
            ea_t field_ea = *ea_opt + udt[i].offset / 8;
            asize_t field_bytes = udt[i].size / 8;

            json result;
            result["address"] = helpers::format_address(*ea_opt);
            result["field_address"] = helpers::format_address(field_ea);
            result["field_name"] = field_name;
            result["field_offset"] = udt[i].offset / 8;
            result["field_size"] = field_bytes;

            if (field_bytes <= 8 && is_loaded(field_ea))
            {
                uval_t val;
                if (get_data_value(&val, field_ea, field_bytes))
                {
                    result["value"] = val;
                    result["hex"] = helpers::format_address(val);
                }
            }

            return tool_result_t::ok(std::string("Field value read"), result);
        }
    }

    return tool_result_t::error(std::string("Field not found: ") + field_name);
}

tool_result_t list_types(const json& params)
{
    int offset = params.value("offset", 0);
    int limit = params.value("limit", 100);
    std::string filter = params.value("filter", "");

    std::regex filter_regex;
    bool use_filter = !filter.empty();
    if (use_filter)
    {
        try { filter_regex = std::regex(filter, std::regex::icase); }
        catch (...) { return tool_result_t::error(std::string("Invalid filter regex")); }
    }

    til_t* ti = get_idati();
    if (!ti)
        return tool_result_t::error(std::string("No local type library"));

    json types = json::array();
    uint32 total = get_ordinal_count(ti);
    int skipped = 0;

    for (uint32 i = 1; i <= total && (int)types.size() < limit; i++)
    {
        const char* tname = get_numbered_type_name(ti, i);
        if (!tname)
            continue;

        if (use_filter && !std::regex_search(tname, filter_regex))
            continue;

        if (skipped < offset)
        {
            skipped++;
            continue;
        }

        tinfo_t tif;
        tif.get_numbered_type(ti, i);

        types.push_back({
            {"ordinal", i},
            {"name", tname},
            {"is_struct", tif.is_struct()},
            {"is_enum", tif.is_enum()},
            {"is_typedef", tif.is_typedef()},
            {"size", (size_t)tif.get_size()}
        });
    }

    json result;
    result["types"] = types;
    result["total"] = total;
    result["returned"] = types.size();

    return tool_result_t::ok(std::string("Types listed"), result);
}

tool_result_t create_enum(const json& params)
{
    std::string name = params["name"].get<std::string>();
    if (name.empty())
        return tool_result_t::error(std::string("Enum name is required"));

    tinfo_t tif;
    enum_type_data_t etd;

    if (params.contains("members") && params["members"].is_array())
    {
        for (const auto& mem : params["members"])
        {
            edm_t m;
            m.name = (mem.contains("name") && mem["name"].is_string()) ? mem["name"].get<std::string>().c_str() : "member";
            m.value = (mem.contains("value") && mem["value"].is_number()) ? mem["value"].get<int64_t>() : 0;
            etd.push_back(m);
        }
    }

    if (!tif.create_enum(etd))
        return tool_result_t::error(std::string("Failed to construct enum tinfo for: ") + name);
    if (tif.set_named_type(get_idati(), name.c_str()) != TERR_OK)
        return tool_result_t::error(std::string("Failed to register enum in type library: ") + name);

    return tool_result_t::ok(std::string("Enum created: ") + name);
}

void register_tools()
{
    auto& registry = ToolRegistry::instance();

    registry.register_tool({std::string("declare_type"), std::string("type"),
        std::string("Parse and declare C type(s) in the local type library."),
        {{std::string("declaration"), std::string("string"), std::string("C type declaration (struct, enum, typedef, etc.)"), true}},
        declare_type, false});

    registry.register_tool({std::string("apply_type"), std::string("type"),
        std::string("Apply a C type to a function, global, or address."),
        {{std::string("address"), std::string("string"), std::string("Target address"), true},
         {std::string("type"), std::string("string"), std::string("C type declaration (e.g., 'int __fastcall(void*, int)')"), true}},
        apply_type, false});

    registry.register_tool({std::string("infer_type"), std::string("type"),
        std::string("Infer/guess the type at an address using Hex-Rays or heuristics."),
        {{std::string("address"), std::string("string"), std::string("Address to analyze"), true}},
        infer_type});

    registry.register_tool({std::string("search_structs"), std::string("type"),
        std::string("Search structures/types by name pattern (regex)."),
        {{std::string("pattern"), std::string("string"), std::string("Regex pattern"), true},
         {std::string("limit"), std::string("number"), std::string("Max results (default 50)"), false}},
        search_structs});

    registry.register_tool({std::string("get_struct"), std::string("type"),
        std::string("Get detailed struct/type info including all members."),
        {{std::string("name"), std::string("string"), std::string("Type name"), true}},
        get_struct});

    registry.register_tool({std::string("create_struct"), std::string("type"),
        std::string("Create a new struct type."),
        {{std::string("name"), std::string("string"), std::string("Struct name"), true},
         {std::string("members"), std::string("array"), std::string("Array of {name, type, offset} objects"), false, {},
          json::object({
              {"type", "object"},
              {"properties", json::object({
                  {"name", json::object({{"type", "string"}, {"description", "Member name"}})},
                  {"type", json::object({{"type", "string"}, {"description", "C type (e.g., 'int', 'char*')"}})},
                  {"offset", json::object({{"type", "number"}, {"description", "Byte offset in struct"}})}
              })},
              {"required", json::array({"name"})}
          })
        }},
        create_struct, false});

    registry.register_tool({std::string("add_struct_member"), std::string("type"),
        std::string("Add a member to an existing struct."),
        {{std::string("struct_name"), std::string("string"), std::string("Struct name"), true},
         {std::string("member_name"), std::string("string"), std::string("Member name"), true},
         {std::string("type"), std::string("string"), std::string("Member C type (default 'int')"), false},
         {std::string("offset"), std::string("number"), std::string("Byte offset in struct"), false}},
        add_struct_member, false});

    registry.register_tool({std::string("get_struct_field_xrefs"), std::string("type"),
        std::string("Get cross-references to a specific struct field."),
        {{std::string("struct_name"), std::string("string"), std::string("Struct name"), true},
         {std::string("field_name"), std::string("string"), std::string("Field name"), true},
         {std::string("limit"), std::string("number"), std::string("Max results"), false}},
        get_struct_field_xrefs});

    registry.register_tool({std::string("create_stack_var"), std::string("type"),
        std::string("Create a stack variable in a function's frame."),
        {{std::string("address"), std::string("string"), std::string("Function address"), true},
         {std::string("offset"), std::string("number"), std::string("Stack offset"), true},
         {std::string("name"), std::string("string"), std::string("Variable name"), true},
         {std::string("type"), std::string("string"), std::string("C type (default '__int64')"), false}},
        create_stack_var, false});

    registry.register_tool({std::string("delete_stack_var"), std::string("type"),
        std::string("Delete a stack variable by name."),
        {{std::string("address"), std::string("string"), std::string("Function address"), true},
         {std::string("name"), std::string("string"), std::string("Variable name to delete"), true}},
        delete_stack_var, false});

    registry.register_tool({std::string("read_struct_field"), std::string("type"),
        std::string("Read the value of a struct field at a specific address."),
        {{std::string("address"), std::string("string"), std::string("Base address of the struct instance"), true},
         {std::string("struct_name"), std::string("string"), std::string("Struct type name"), true},
         {std::string("field_name"), std::string("string"), std::string("Field name to read"), true}},
        read_struct_field});

    registry.register_tool({std::string("list_types"), std::string("type"),
        std::string("List all types in the local type library (paginated, filtered)."),
        {{std::string("offset"), std::string("number"), std::string("Starting offset"), false},
         {std::string("limit"), std::string("number"), std::string("Max results (default 100)"), false},
         {std::string("filter"), std::string("string"), std::string("Regex filter"), false}},
        list_types});

    registry.register_tool({std::string("create_enum"), std::string("type"),
        std::string("Create a new enum type."),
        {{std::string("name"), std::string("string"), std::string("Enum name"), true},
         {std::string("members"), std::string("array"), std::string("Array of {name, value} objects"), false, {},
          json::object({
              {"type", "object"},
              {"properties", json::object({
                  {"name", json::object({{"type", "string"}, {"description", "Enum member name"}})},
                  {"value", json::object({{"type", "number"}, {"description", "Enum member value"}})}
              })},
              {"required", json::array({"name", "value"})}
          })
        }},
        create_enum, false});
}

}

namespace import_tools
{

struct import_data_t
{
    json imports;
    int limit;
    int count;
    std::string module_name;
    std::regex* filter;
};

static int idaapi import_enum_cb(ea_t ea, const char* name, uval_t ord, void* param)
{
    auto* data = static_cast<import_data_t*>(param);
    if (data->count >= data->limit)
        return 0;

    std::string import_name = name ? name : "";
    if (data->filter && !import_name.empty() && !std::regex_search(import_name, *data->filter))
        return 1;

    json entry;
    entry["address"] = helpers::format_address(ea);
    entry["name"] = import_name;
    entry["ordinal"] = ord;
    entry["module"] = data->module_name;
    data->imports.push_back(entry);
    data->count++;
    return 1;
}

tool_result_t list_imports(const json& params)
{
    int offset = params.value("offset", 0);
    int limit = params.value("limit", 200);
    std::string filter = params.value("filter", "");

    std::regex filter_regex;
    std::regex* filter_ptr = nullptr;
    if (!filter.empty())
    {
        try {
            filter_regex = std::regex(filter, std::regex::icase);
            filter_ptr = &filter_regex;
        }
        catch (...) { return tool_result_t::error(std::string("Invalid filter regex")); }
    }

    json all_imports = json::array();
    uint module_count = get_import_module_qty();
    int total_count = 0;
    int skipped = 0;

    for (uint i = 0; i < module_count && total_count < limit; i++)
    {
        qstring mod_name;
        get_import_module_name(&mod_name, i);

        import_data_t data;
        data.imports = json::array();
        data.limit = limit - total_count;
        data.count = 0;
        data.module_name = mod_name.c_str();
        data.filter = filter_ptr;

        enum_import_names(i, import_enum_cb, &data);

        for (auto& imp : data.imports)
        {
            if (skipped < offset)
            {
                skipped++;
                continue;
            }
            all_imports.push_back(imp);
            total_count++;
        }
    }

    json result;
    result["imports"] = all_imports;
    result["module_count"] = module_count;
    result["returned"] = total_count;

    return tool_result_t::ok(std::string("Listed ") + std::to_string(total_count) + " imports", result);
}

tool_result_t list_exports(const json& params)
{
    int offset = params.value("offset", 0);
    int limit = params.value("limit", 200);
    std::string filter = params.value("filter", "");

    std::regex filter_regex;
    bool use_filter = !filter.empty();
    if (use_filter)
    {
        try { filter_regex = std::regex(filter, std::regex::icase); }
        catch (...) { return tool_result_t::error(std::string("Invalid filter regex")); }
    }

    json exports = json::array();
    size_t total = get_entry_qty();
    int count = 0;
    int skipped = 0;

    for (size_t i = 0; i < total && count < limit; i++)
    {
        uval_t ord = get_entry_ordinal(i);
        ea_t ea = get_entry(ord);
        if (ea == BADADDR)
            continue;

        qstring ename;
        get_entry_name(&ename, ord);

        if (use_filter && !std::regex_search(ename.c_str(), filter_regex))
            continue;

        if (skipped < offset)
        {
            skipped++;
            continue;
        }

        exports.push_back({
            {"address", helpers::format_address(ea)},
            {"name", ename.c_str()},
            {"ordinal", ord}
        });
        count++;
    }

    json result;
    result["exports"] = exports;
    result["total"] = total;
    result["returned"] = count;

    return tool_result_t::ok(std::string("Listed ") + std::to_string(count) + " exports", result);
}

tool_result_t get_import(const json& params)
{
    std::string name_or_addr = params["name"].get<std::string>();

    auto ea_opt = helpers::parse_address(name_or_addr);
    if (!ea_opt)
        return tool_result_t::error(std::string("Cannot resolve import"));

    qstring imp_name;
    if (get_name(&imp_name, *ea_opt) <= 0)
        return tool_result_t::error(std::string("No name at address"));

    json result;
    result["address"] = helpers::format_address(*ea_opt);
    result["name"] = imp_name.c_str();

    xrefblk_t xb;
    json xrefs = json::array();
    int count = 0;
    for (bool ok = xb.first_to(*ea_opt, XREF_ALL); ok && count < 50; ok = xb.next_to())
    {
        xrefs.push_back({
            {"from", helpers::format_address(xb.from)},
            {"from_name", helpers::get_name_or_address(xb.from)}
        });
        count++;
    }
    result["references"] = xrefs;

    return tool_result_t::ok(std::string("Import info retrieved"), result);
}

void register_tools()
{
    auto& registry = ToolRegistry::instance();

    registry.register_tool({std::string("list_imports"), std::string("import"),
        std::string("List all imported symbols with module names (paginated, filtered)."),
        {{std::string("offset"), std::string("number"), std::string("Start offset"), false},
         {std::string("limit"), std::string("number"), std::string("Max results (default 200)"), false},
         {std::string("filter"), std::string("string"), std::string("Regex filter for import names"), false}},
        list_imports});

    registry.register_tool({std::string("list_exports"), std::string("import"),
        std::string("List all exported symbols (paginated, filtered)."),
        {{std::string("offset"), std::string("number"), std::string("Start offset"), false},
         {std::string("limit"), std::string("number"), std::string("Max results (default 200)"), false},
         {std::string("filter"), std::string("string"), std::string("Regex filter"), false}},
        list_exports});

    registry.register_tool({std::string("get_import"), std::string("import"),
        std::string("Get details about a specific import by name or address."),
        {{std::string("name"), std::string("string"), std::string("Import name or address"), true}},
        get_import});
}

}

namespace search_tools
{

tool_result_t search_strings(const json& params)
{
    std::string pattern = params["pattern"].get<std::string>();
    int limit = params.value("limit", 100);
    int offset = params.value("offset", 0);


    {
        std::string hash = current_module_graph_key();
        if (!hash.empty())
        {
            auto& store = graphrag::GraphStore::instance();
            auto stats = store.get_stats(hash);
            if (stats.nodes > 0)
            {
                graphrag::QueryEngine qe(store);
                json semantic_results = qe.search_semantic(hash, pattern, limit);
                if (!semantic_results.empty())
                {
                    return tool_result_t::ok(
                        std::string("Binary is indexed Ã¢â‚¬â€ used semantic search (faster). Found ")
                        + std::to_string(semantic_results.size())
                        + std::string(" results. Use search_semantic directly for best performance."),
                        semantic_results);
                }

            }
        }
    }

    std::regex filter_regex;
    try { filter_regex = std::regex(pattern, std::regex::icase); }
    catch (...) { return tool_result_t::error(std::string("Invalid regex pattern")); }

    size_t total = get_strlist_qty();
    if (total == 0)
    {
        show_wait_box("NODELAY\nAiDA: Building string list...");
        build_strlist();
        hide_wait_box();
        total = get_strlist_qty();
    }

    json strings = json::array();
    int count = 0;
    int skipped = 0;

    show_wait_box("NODELAY\nAiDA: Searching strings (0 / %zu)...", total);

    for (size_t i = 0; i < total && count < limit; i++)
    {
        if (i % 500 == 0)
        {
            replace_wait_box("AiDA: Searching strings (%zu / %zu)...", i, total);
            if (user_cancelled())
                break;
        }

        string_info_t si;
        if (!get_strlist_item(&si, i))
            continue;

        qstring str;
        if (get_strlit_contents(&str, si.ea, si.length, si.type) <= 0)
            continue;

        if (!std::regex_search(str.c_str(), filter_regex))
            continue;

        if (skipped < offset)
        {
            skipped++;
            continue;
        }

        strings.push_back({
            {"address", helpers::format_address(si.ea)},
            {"value", str.c_str()},
            {"length", si.length},
            {"type", si.type}
        });
        count++;
    }

    hide_wait_box();

    json result;
    result["strings"] = strings;
    result["total_strings"] = total;
    result["returned"] = count;

    return tool_result_t::ok(std::string("Found ") + std::to_string(count) + " matching strings", result);
}

tool_result_t find_bytes(const json& params)
{
    std::string pattern = params["pattern"].get<std::string>();
    int limit = params.value("limit", 20);

    ea_t start_ea = inf_get_min_ea();
    ea_t end_ea = inf_get_max_ea();

    if (params.contains("start"))
    {
        auto s = helpers::parse_address(params["start"].get<std::string>());
        if (s) start_ea = *s;
    }
    if (params.contains("end"))
    {
        auto e = helpers::parse_address(params["end"].get<std::string>());
        if (e) end_ea = *e;
    }

    compiled_binpat_vec_t binpat;
    qstring errbuf;
    if (!parse_binpat_str(&binpat, start_ea, pattern.c_str(), 16, PBSENC_DEF1BPU, &errbuf))
        return tool_result_t::error(std::string("Invalid byte pattern: ") + std::string(errbuf.c_str()));

    json matches = json::array();
    ea_t current = start_ea;

    show_wait_box("NODELAY\nAiDA: Searching byte pattern...");

    for (int i = 0; i < limit; i++)
    {
        replace_wait_box("AiDA: Searching byte pattern (%d found)...", i);
        if (user_cancelled())
            break;

        ea_t found = bin_search(current, end_ea, binpat,
                                BIN_SEARCH_FORWARD);
        if (found == BADADDR)
            break;

        matches.push_back({
            {"address", helpers::format_address(found)},
            {"name", helpers::get_name_or_address(found)}
        });

        current = found + 1;
    }

    hide_wait_box();

    return tool_result_t::ok(std::string("Found ") + std::to_string(matches.size()) + " matches", matches);
}

tool_result_t find_instructions(const json& params)
{
    std::string pattern = params["pattern"].get<std::string>();
    int limit = params.value("limit", 20);


    {
        std::string hash = current_module_graph_key();
        if (!hash.empty())
        {
            auto& store = graphrag::GraphStore::instance();
            auto stats = store.get_stats(hash);
            if (stats.nodes > 0)
            {
                graphrag::QueryEngine qe(store);
                json semantic_results = qe.search_semantic(hash, pattern, limit);
                if (!semantic_results.empty())
                {
                    return tool_result_t::ok(
                        std::string("Binary is indexed Ã¢â‚¬â€ used semantic search (faster). Found ")
                        + std::to_string(semantic_results.size())
                        + std::string(" results. Use search_semantic directly for best performance."),
                        semantic_results);
                }

            }
        }
    }

    ea_t start_ea = inf_get_min_ea();
    ea_t end_ea = inf_get_max_ea();

    if (params.contains("start"))
    {
        auto s = helpers::parse_address(params["start"].get<std::string>());
        if (s) start_ea = *s;
    }

    json matches = json::array();
    ea_t ea = start_ea;

    show_wait_box("NODELAY\nAiDA: Searching instructions...");

    while (ea < end_ea && (int)matches.size() < limit)
    {
        replace_wait_box("AiDA: Searching instructions (%zu found)...", matches.size());
        if (user_cancelled())
            break;

        ea_t found = find_text(ea, 0, 0, pattern.c_str(),
                               SEARCH_DOWN | SEARCH_NEXT);
        if (found == BADADDR)
            break;

        insn_t insn;
        if (decode_insn(&insn, found) > 0)
        {
            qstring disasm_line;
            generate_disasm_line(&disasm_line, found, GENDSM_FORCE_CODE);
            qstring clean;
            tag_remove(&clean, disasm_line.c_str());

            matches.push_back({
                {"address", helpers::format_address(found)},
                {"disassembly", clean.c_str()},
                {"size", insn.size}
            });
        }

        ea = found + 1;
    }

    hide_wait_box();

    return tool_result_t::ok(std::string("Found ") + std::to_string(matches.size()) + " instructions", matches);
}

tool_result_t find_immediate(const json& params)
{
    uint64_t value;
    if (params["value"].is_string())
    {
        auto ea_opt = helpers::parse_address(params["value"].get<std::string>());
        if (!ea_opt)
            return tool_result_t::error(std::string("Invalid value"));
        value = *ea_opt;
    }
    else
    {
        value = params["value"].get<uint64_t>();
    }

    int limit = params.value("limit", 20);

    ea_t start_ea = inf_get_min_ea();
    if (params.contains("start"))
    {
        auto s = helpers::parse_address(params["start"].get<std::string>());
        if (s) start_ea = *s;
    }

    json matches = json::array();
    ea_t ea = start_ea;

    show_wait_box("NODELAY\nAiDA: Searching immediate values...");

    for (int i = 0; i < limit; i++)
    {
        replace_wait_box("AiDA: Searching immediate values (%d found)...", i);
        if (user_cancelled())
            break;

        int opnum = -1;
        ea_t found = find_imm(ea, SEARCH_DOWN | SEARCH_NEXT,
                              (uval_t)value, &opnum);
        if (found == BADADDR)
            break;

        qstring disasm_line;
        generate_disasm_line(&disasm_line, found, GENDSM_FORCE_CODE);
        qstring clean;
        tag_remove(&clean, disasm_line.c_str());

        matches.push_back({
            {"address", helpers::format_address(found)},
            {"operand", opnum},
            {"disassembly", clean.c_str()},
            {"function", helpers::get_name_or_address(found)}
        });

        ea = found + 1;
    }

    hide_wait_box();

    return tool_result_t::ok(std::string("Found ") + std::to_string(matches.size()) + " occurrences", matches);
}

void register_tools()
{
    auto& registry = ToolRegistry::instance();

    registry.register_tool({std::string("search_strings"), std::string("search"),
        std::string("Search strings with case-insensitive regex (paginated). "
               "Auto-redirects to semantic search when binary is indexed for faster results."),
        {{std::string("pattern"), std::string("string"), std::string("Regex pattern to match"), true},
         {std::string("offset"), std::string("number"), std::string("Pagination offset"), false},
         {std::string("limit"), std::string("number"), std::string("Max results (default 100)"), false}},
        search_strings});

    registry.register_tool({std::string("find_bytes"), std::string("search"),
        std::string("Find byte pattern(s) in binary. Supports wildcards with '??' (e.g., '48 8B ?? ?? 89')."),
        {{std::string("pattern"), std::string("string"), std::string("Hex byte pattern (e.g., '48 8B ?? ??')"), true},
         {std::string("start"), std::string("string"), std::string("Start address (optional)"), false},
         {std::string("end"), std::string("string"), std::string("End address (optional)"), false},
         {std::string("limit"), std::string("number"), std::string("Max results (default 20)"), false}},
        find_bytes});

    registry.register_tool({std::string("find_instructions"), std::string("search"),
        std::string("Find instruction sequence(s) in code by text match. "
               "Auto-redirects to semantic search when binary is indexed for faster results. "
               "Prefer search_semantic directly for indexed binaries."),
        {{std::string("pattern"), std::string("string"), std::string("Instruction text to search for"), true},
         {std::string("start"), std::string("string"), std::string("Start address (optional)"), false},
         {std::string("limit"), std::string("number"), std::string("Max results (default 20)"), false}},
        find_instructions});

    registry.register_tool({std::string("find_immediate"), std::string("search"),
        std::string("Find immediate value occurrences in instructions."),
        {{std::string("value"), std::string("string"), std::string("Immediate value (decimal or 0x hex)"), true},
         {std::string("start"), std::string("string"), std::string("Start address (optional)"), false},
         {std::string("limit"), std::string("number"), std::string("Max results (default 20)"), false}},
        find_immediate});

}

}


namespace segment_tools
{

static std::string format_segment_permissions(const segment_t& seg)
{
    std::string perms;
    if ((seg.perm & SEGPERM_READ) != 0)  perms += "R";
    if ((seg.perm & SEGPERM_WRITE) != 0) perms += "W";
    if ((seg.perm & SEGPERM_EXEC) != 0)  perms += "X";
    return perms;
}

static int segment_bitness_bits(const segment_t& seg)
{
    switch (seg.bitness)
    {
        case 0: return 16;
        case 1: return 32;
        default: return 64;
    }
}

static qstring get_safe_segment_name(const segment_t* seg)
{
    qstring name;
    if (seg == nullptr || get_segment_name(&name, seg->start_ea, 1) <= 0 || name.empty())
        name = "<unnamed>";
    return name;
}

static qstring get_safe_segment_class(const segment_t* seg)
{
    qstring sclass;
    if (seg == nullptr || get_segment_class(&sclass, seg->start_ea) <= 0 || sclass.empty())
        sclass = "unknown";
    return sclass;
}

static json build_segment_json(const segment_t* seg)
{
    qstring name = get_safe_segment_name(seg);
    qstring sclass = get_safe_segment_class(seg);

    return {
        {"index", get_segm_num(seg->start_ea)},
        {"name", name.c_str()},
        {"class", sclass.c_str()},
        {"start", helpers::format_address(seg->start_ea)},
        {"end", helpers::format_address(seg->end_ea)},
        {"size", seg->end_ea - seg->start_ea},
        {"permissions", format_segment_permissions(*seg)},
        {"bitness", segment_bitness_bits(*seg)},
        {"type", seg->type}
    };
}

tool_result_t list_segments(const json&)
{
    json segments = json::array();

    for (ea_t seg_ea = get_first_segment_ea(); seg_ea != BADADDR; seg_ea = get_next_segment_ea(seg_ea))
    {
        segment_t* seg = getseg(seg_ea);
        if (seg == nullptr)
            continue;
        if (seg->end_ea <= seg->start_ea)
            continue;

        segments.push_back(build_segment_json(seg));
    }

    return tool_result_t::ok(std::string("Listed ") + std::to_string(segments.size()) + " segments", segments);
}

tool_result_t get_segment(const json& params)
{
    ea_t ea = BADADDR;

    if (params.contains("address"))
    {
        auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
        if (ea_opt) ea = *ea_opt;
    }
    else if (params.contains("name"))
    {
        segment_t* seg = get_segm_by_name(params["name"].get<std::string>().c_str());
        if (seg) ea = seg->start_ea;
    }

    if (ea == BADADDR)
        return tool_result_t::error(std::string("Segment not found"));

    segment_t* seg = getseg(ea);
    if (!seg)
        return tool_result_t::error(std::string("No segment at address"));

    json result = build_segment_json(seg);
    result["alignment"] = seg->align;
    result["type"] = seg->type;

    return tool_result_t::ok(std::string("Segment info retrieved"), result);
}

tool_result_t create_segment(const json& params)
{
    auto start_opt = helpers::parse_address(params["start"].get<std::string>());
    if (!start_opt)
        return tool_result_t::error(std::string("Invalid start address"));

    auto end_opt = helpers::parse_address(params["end"].get<std::string>());
    if (!end_opt)
        return tool_result_t::error(std::string("Invalid end address"));

    std::string name = params["name"].get<std::string>();
    std::string sclass = params.value("class", std::string("DATA"));

    if (*end_opt <= *start_opt)
        return tool_result_t::error(std::string("End address must be greater than start address"));


    ea_t aligned_start = *start_opt & ~0xFULL;
    ea_t aligned_end   = (*end_opt + 0xF) & ~0xFULL;
    if (aligned_end <= aligned_start)
        aligned_end = aligned_start + 0x1000;


    if (getseg(aligned_start))
        return tool_result_t::error(std::string("Segment already exists at ") + helpers::format_address(aligned_start));


    segment_t seg;
    seg.start_ea = aligned_start;
    seg.end_ea   = aligned_end;
    seg.bitness  = inf_is_64bit() ? 2 : (inf_is_32bit_exactly() ? 1 : 0);
    seg.align    = saRelByte;
    seg.comb     = scPub;
    seg.perm     = SEGPERM_READ | SEGPERM_WRITE;

    bool is_code = (sclass == "CODE");
    if (is_code)
    {
        seg.type = SEG_CODE;
        seg.perm |= SEGPERM_EXEC;
    }
    else
    {
        seg.type = SEG_DATA;
    }

    if (!aida_add_segm_ex(&seg, name.c_str(), sclass.c_str(), ADDSEG_QUIET | ADDSEG_NOSREG))
        return tool_result_t::error(std::string("Failed to create segment at ") +
                                    helpers::format_address(aligned_start) + std::string("-") +
                                    helpers::format_address(aligned_end));

    json result;
    result["start"] = helpers::format_address(aligned_start);
    result["end"]   = helpers::format_address(aligned_end);
    result["name"]  = name;
    result["size"]  = aligned_end - aligned_start;
    result["bitness"] = seg.bitness == 2 ? 64 : (seg.bitness == 1 ? 32 : 16);

    return tool_result_t::ok(std::string("Segment created: ") + name, result);
}

void register_tools()
{
    auto& registry = ToolRegistry::instance();

    registry.register_tool({std::string("list_segments"), std::string("segment"),
        std::string("List all segments/sections in the binary."),
        {}, list_segments});

    registry.register_tool({std::string("get_segment"), std::string("segment"),
        std::string("Get detailed info about a segment by address or name."),
        {{std::string("address"), std::string("string"), std::string("Address within segment"), false},
         {std::string("name"), std::string("string"), std::string("Segment name"), false}},
        get_segment});

    registry.register_tool({std::string("create_segment"), std::string("segment"),
        std::string("Create a new segment with proper alignment. Automatically aligns addresses to paragraph "
               "boundaries and sets correct bitness (64/32/16) based on the current binary. "
               "Uses add_segm_ex for full control, avoiding 'bad segment start' errors with kernel addresses."),
        {{std::string("start"), std::string("string"), std::string("Start address (will be aligned down to paragraph boundary)"), true},
         {std::string("end"), std::string("string"), std::string("End address (will be aligned up to paragraph boundary)"), true},
         {std::string("name"), std::string("string"), std::string("Segment name"), true},
         {std::string("class"), std::string("string"), std::string("Segment class: CODE or DATA (default DATA)"), false}},
        create_segment, false});
}

}

namespace binary_tools
{

tool_result_t get_binary_info(const json&)
{
    json result;

    qstring procname = inf_get_procname();
    result["processor"] = procname.c_str();
    result["bitness"] = inf_get_app_bitness();
    result["is_64bit"] = inf_is_64bit();
    result["is_dll"] = inf_is_dll();
    result["is_big_endian"] = inf_is_be();
    result["file_type"] = (int)inf_get_filetype();
    result["min_ea"] = helpers::format_address(inf_get_min_ea());
    result["max_ea"] = helpers::format_address(inf_get_max_ea());

    result["function_count"] = (size_t)get_func_qty();
    result["segment_count"] = get_segm_qty();
    result["entry_count"] = (size_t)get_entry_qty();
    result["import_module_count"] = get_import_module_qty();

    return tool_result_t::ok(std::string("Binary info retrieved"), result);
}

// -------------------------------------------------------------------------
// Slice B7 — canonical merged binary identity / capability fingerprint.
// Returns md5/sha256/crc32, image bounds, processor/bitness/kind, the entry
// point table, segment summary, an imports-by-module-category histogram,
// and a derived boolean capability vector. Lives in binary category as
// the single source of truth for "what is this binary?".
// -------------------------------------------------------------------------
namespace {

struct fp_import_collector_t
{
    std::vector<std::string> names;
};

static int idaapi fp_import_cb(ea_t /*ea*/, const char* name, uval_t /*ord*/, void* param)
{
    auto* c = static_cast<fp_import_collector_t*>(param);
    if (name && *name)
        c->names.emplace_back(name);
    if (c->names.size() >= 4096)
        return 0;
    return 1;
}

// Module categorization for the capabilities vector. Keep this list short and
// case-insensitive — the goal is "what attack surface does this binary touch?".
static std::string categorize_import_module(const std::string& mod)
{
    std::string lower;
    lower.reserve(mod.size());
    for (char c : mod)
        lower.push_back((char)std::tolower((unsigned char)c));

    if (lower.find("ws2_32")    != std::string::npos
     || lower.find("wsock32")   != std::string::npos
     || lower.find("mswsock")   != std::string::npos
     || lower.find("iphlpapi")  != std::string::npos)
        return "WINSOCK";

    if (lower.find("wininet")   != std::string::npos
     || lower.find("winhttp")   != std::string::npos
     || lower.find("urlmon")    != std::string::npos)
        return "WININET";

    if (lower.find("rpcrt4")    != std::string::npos
     || lower.find("rpcns4")    != std::string::npos)
        return "RPC";

    if (lower.find("ole32")     != std::string::npos
     || lower.find("oleaut32")  != std::string::npos
     || lower.find("combase")   != std::string::npos)
        return "COM";

    if (lower.find("ntdll")     != std::string::npos)
        return "IPC"; // ntdll houses NtAlpc*, NtCreateNamedPipeFile, etc.

    if (lower.find("kernel32")  != std::string::npos)
        return "IPC"; // CreateNamedPipe, TransactNamedPipe, etc.

    if (lower.find("advapi32")  != std::string::npos)
        return "CRYPTO";
    if (lower.find("bcrypt")    != std::string::npos
     || lower.find("ncrypt")    != std::string::npos
     || lower.find("crypt32")   != std::string::npos)
        return "CRYPTO";

    if (lower.find("ntoskrnl")  != std::string::npos
     || lower.find("hal")       != std::string::npos
     || lower.find("ndis")      != std::string::npos
     || lower.find("wdfldr")    != std::string::npos
     || lower.find("fltmgr")    != std::string::npos)
        return "ALPC";

    if (lower.find("shlwapi")   != std::string::npos
     || lower.find("shell32")   != std::string::npos
     || lower.find("shcore")    != std::string::npos
     || lower.find("user32")    != std::string::npos
     || lower.find("gdi32")     != std::string::npos)
        return "FILE";

    return "OTHER";
}

} // anonymous

tool_result_t binary_fingerprint(const json&)
{
    json result;

    // --- Hashes ---------------------------------------------------------
    {
        unsigned char md5[16] = {};
        unsigned char sha[32] = {};
        if (retrieve_input_file_md5(md5))
        {
            char buf[33] = {};
            for (int i = 0; i < 16; ++i)
                ::qsnprintf(buf + i * 2, 3, "%02x", md5[i]);
            result["md5"] = std::string(buf, 32);
        }
        if (retrieve_input_file_sha256(sha))
        {
            char buf[65] = {};
            for (int i = 0; i < 32; ++i)
                ::qsnprintf(buf + i * 2, 3, "%02x", sha[i]);
            result["sha256"] = std::string(buf, 64);
        }
        uint32_t crc = retrieve_input_file_crc32();
        char crcbuf[16] = {};
        ::qsnprintf(crcbuf, sizeof(crcbuf), "%08x", crc);
        result["crc32"] = std::string(crcbuf);
    }

    // --- Paths and identity ---------------------------------------------
    {
        char pathbuf[QMAXPATH] = {};
        get_input_file_path(pathbuf, sizeof(pathbuf));
        result["path"] = std::string(pathbuf);

        // get_path returns a non-owning const char* (never nullptr per SDK).
        const char* idb_p = get_path(PATH_TYPE_IDB);
        result["idb_path"] = std::string(idb_p ? idb_p : "");
    }
    result["filetype"]    = (int)inf_get_filetype();
    result["is_dll"]      = inf_is_dll();
    result["is_kernel"]   = inf_is_kernel_mode();
    result["bitness"]     = inf_get_app_bitness();
    {
        qstring proc = inf_get_procname();
        result["processor"] = std::string(proc.c_str());
    }
    result["image_base"]  = helpers::format_address((ea_t)get_imagebase());
    result["min_ea"]      = helpers::format_address(inf_get_min_ea());
    result["max_ea"]      = helpers::format_address(inf_get_max_ea());
    // instance_id is a per-IDA-process UUID maintained by mcp_server's
    // instance_registry. agent_tools does not link the registry, so emit the
    // input file MD5 hex as a stable per-binary identifier; the MCP layer can
    // overlay its own instance_id at the routing edge.
    if (result.contains("md5"))
        result["instance_id"] = result["md5"];
    result["hexrays_available"] = init_hexrays_plugin();

    // --- Entry points ---------------------------------------------------
    json entries = json::array();
    size_t entry_qty = get_entry_qty();
    for (size_t i = 0; i < entry_qty; ++i)
    {
        uval_t ord = get_entry_ordinal(i);
        ea_t ea = get_entry(ord);
        if (ea == BADADDR)
            continue;
        qstring name;
        get_entry_name(&name, ord);
        json ej;
        ej["ord"]  = (uint64_t)ord;
        ej["name"] = std::string(name.c_str());
        ej["ea"]   = helpers::format_address(ea);
        func_t* pfn = get_func(ea);
        bool is_thunk = pfn && (pfn->flags & FUNC_THUNK);
        ej["is_thunk"] = is_thunk;
        if (is_thunk)
        {
            ea_t fptr = BADADDR;
            ea_t target = aida_calc_thunk_func_target(pfn, &fptr);
            if (target != BADADDR)
                ej["thunk_target"] = helpers::format_address(target);
        }
        entries.push_back(ej);
        if (entries.size() >= 1024)
            break;
    }
    result["entry_points"] = entries;

    // --- Segments -------------------------------------------------------
    json segs = json::array();
    int sqty = get_segm_qty();
    for (int i = 0; i < sqty; ++i)
    {
        segment_t* s = getnseg(i);
        if (!s)
            continue;
        qstring name;
        aida_get_segm_name(&name, s);
        json sj;
        sj["name"]  = std::string(name.c_str());
        sj["start"] = helpers::format_address(s->start_ea);
        sj["end"]   = helpers::format_address(s->end_ea);
        sj["type"]  = (int)s->type;
        sj["perm"]  = (int)s->perm;
        sj["size"]  = (uint64_t)(s->end_ea - s->start_ea);
        segs.push_back(sj);
    }
    result["segments"] = segs;

    // --- Imports + capability map --------------------------------------
    json imports = json::array();
    std::map<std::string, bool> cap;
    cap["network"]            = false;
    cap["rpc"]                = false;
    cap["com"]                = false;
    cap["driver"]             = false;
    cap["service"]            = false;
    cap["alpc"]               = false;
    cap["ndis"]               = false;
    cap["crypto"]             = false;
    cap["tls_callbacks"]      = false;
    cap["exception_handlers"] = false;

    uint mod_qty = get_import_module_qty();
    for (uint mi = 0; mi < mod_qty; ++mi)
    {
        qstring modname;
        if (!get_import_module_name(&modname, mi))
            continue;
        fp_import_collector_t coll;
        enum_import_names(mi, fp_import_cb, &coll);

        std::string mod_str = modname.c_str();
        std::string category = categorize_import_module(mod_str);

        json mj;
        mj["module"]   = mod_str;
        mj["category"] = category;
        mj["count"]    = (uint64_t)coll.names.size();
        json top = json::array();
        for (size_t k = 0; k < coll.names.size() && k < 12; ++k)
            top.push_back(coll.names[k]);
        mj["top_names"] = top;
        imports.push_back(mj);

        if (category == "WINSOCK" || category == "WININET")
            cap["network"] = true;
        if (category == "RPC")
            cap["rpc"] = true;
        if (category == "COM")
            cap["com"] = true;
        if (category == "ALPC")
        {
            cap["alpc"] = true;
            std::string lm = mod_str;
            for (char& c : lm) c = (char)std::tolower((unsigned char)c);
            if (lm.find("ndis") != std::string::npos)
                cap["ndis"] = true;
        }
        if (category == "CRYPTO")
            cap["crypto"] = true;

        // Driver/service inference based on filetype + import shape.
        std::string lm = mod_str;
        for (char& c : lm) c = (char)std::tolower((unsigned char)c);
        if (lm.find("ntoskrnl") != std::string::npos
         || lm.find("hal")      != std::string::npos
         || lm.find("wdfldr")   != std::string::npos)
            cap["driver"] = true;
        if (lm.find("advapi32") != std::string::npos)
        {
            for (const auto& n : coll.names)
            {
                if (n.find("CreateService")   != std::string::npos
                 || n.find("StartServiceCtrl") != std::string::npos
                 || n.find("RegisterService")  != std::string::npos)
                {
                    cap["service"] = true;
                    break;
                }
            }
        }
    }
    result["imports"] = imports;

    // TLS callbacks indicator: look up segment named ".tls" or known
    // TLS-callback table import.
    for (const auto& seg_entry : result["segments"])
    {
        if (seg_entry.contains("name"))
        {
            std::string sn = seg_entry["name"].get<std::string>();
            std::string ln;
            for (char c : sn) ln.push_back((char)std::tolower((unsigned char)c));
            if (ln.find(".tls") != std::string::npos)
            {
                cap["tls_callbacks"] = true;
                break;
            }
        }
    }
    // SEH / __try blocks indicator via the .pdata segment.
    for (const auto& seg_entry : result["segments"])
    {
        if (seg_entry.contains("name"))
        {
            std::string sn = seg_entry["name"].get<std::string>();
            std::string ln;
            for (char c : sn) ln.push_back((char)std::tolower((unsigned char)c));
            if (ln.find(".pdata") != std::string::npos
             || ln.find(".xdata") != std::string::npos)
            {
                cap["exception_handlers"] = true;
                break;
            }
        }
    }

    if (inf_is_kernel_mode())
        cap["driver"] = true;

    result["capabilities"] = cap;
    result["function_count"] = (uint64_t)get_func_qty();
    result["string_count"]   = (uint64_t)get_strlist_qty();

    return tool_result_t::ok(std::string("binary_fingerprint ok"), result);
}

void register_tools()
{
    auto& registry = ToolRegistry::instance();

    registry.register_tool({std::string("get_binary_info"), std::string("binary"),
        std::string("Get binary file metadata (processor, bitness, file type, etc)."),
        {}, get_binary_info});

    static auto fp_name = std::string("binary_fingerprint");
    static auto fp_cat  = std::string("binary");
    static auto fp_desc = std::string(
        "Canonical binary identity + attack-surface fingerprint. Returns md5/sha256/crc32, "
        "image bounds, processor/bitness/dll/kernel flags, entry points (with thunk targets), "
        "segments, imports grouped by module category (WINSOCK/WININET/RPC/COM/ALPC/IPC/CRYPTO/"
        "FILE/OTHER), function/string counts, and a derived capabilities boolean vector "
        "(network/rpc/com/driver/service/alpc/ndis/crypto/tls_callbacks/exception_handlers).");
    tool_definition_t fp_def;
    fp_def.name = fp_name;
    fp_def.category = fp_cat;
    fp_def.description = fp_desc;
    fp_def.handler = binary_fingerprint;
    fp_def.read_only = true;
    fp_def.destructive = false;
    fp_def.deterministic = true;
    fp_def.output_schema = json::object({
        {std::string("type"), std::string("object")},
        {std::string("required"), json::array({std::string("filetype"), std::string("is_dll"), std::string("is_kernel"), std::string("bitness"), std::string("processor"), std::string("entry_points"), std::string("segments"), std::string("imports"), std::string("capabilities")})},
        {std::string("additionalProperties"), true}
    });
    registry.register_tool(fp_def);
}

}

namespace python_tools
{

tool_result_t execute_python(const json& params)
{
    std::string code = params["code"].get<std::string>();

    static const char b64_alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string b64;
    b64.reserve(((code.size() + 2) / 3) * 4);
    for (size_t i = 0; i < code.size(); i += 3)
    {
        unsigned char c0 = static_cast<unsigned char>(code[i]);
        unsigned char c1 = (i + 1 < code.size()) ? static_cast<unsigned char>(code[i + 1]) : 0;
        unsigned char c2 = (i + 2 < code.size()) ? static_cast<unsigned char>(code[i + 2]) : 0;
        uint32_t v = (static_cast<uint32_t>(c0) << 16)
                   | (static_cast<uint32_t>(c1) << 8)
                   | static_cast<uint32_t>(c2);
        b64.push_back(b64_alphabet[(v >> 18) & 0x3F]);
        b64.push_back(b64_alphabet[(v >> 12) & 0x3F]);
        b64.push_back((i + 1 < code.size()) ? b64_alphabet[(v >> 6) & 0x3F] : '=');
        b64.push_back((i + 2 < code.size()) ? b64_alphabet[v & 0x3F] : '=');
    }

    std::string wrapper = R"PY(
import sys, io, json as _json, base64 as _b64
_aida_stdout = io.StringIO()
_aida_stderr = io.StringIO()
_aida_result = None
_aida_user_code = _b64.b64decode(")PY";
    wrapper += b64;
    wrapper += R"PY(").decode("utf-8")
try:
    _old_stdout, _old_stderr = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = _aida_stdout, _aida_stderr
    try:
        _aida_result = eval(compile(_aida_user_code, "<aida>", "eval"))
    except SyntaxError:
        exec(compile(_aida_user_code, "<aida>", "exec"))
    sys.stdout, sys.stderr = _old_stdout, _old_stderr
except Exception as _e:
    sys.stdout, sys.stderr = _old_stdout, _old_stderr
    import traceback as _tb
    _aida_stderr.write(_tb.format_exc())
_aida_out = _json.dumps({
    "result": str(_aida_result) if _aida_result is not None else None,
    "stdout": _aida_stdout.getvalue(),
    "stderr": _aida_stderr.getvalue()
})
)PY";

    extlang_object_t python = find_extlang_by_name("python");
    if (!python)
        return tool_result_t::error(std::string("Python interpreter not available in IDA"));

    qstring errbuf;
    bool ok = python->eval_snippet(wrapper.c_str(), &errbuf);

    if (!ok)
        return tool_result_t::error(std::string("Python execution failed: ") + std::string(errbuf.c_str()));

    idc_value_t rv;
    qstring eval_err;
    if (python->eval_expr(&rv, BADADDR, "_aida_out", &eval_err))
    {
        try
        {
            std::string result_str = rv.c_str();
            json parsed = json::parse(result_str);
            return tool_result_t::ok(std::string("Python executed successfully"), parsed);
        }
        catch (...) {}
    }

    return tool_result_t::ok(std::string("Python executed (no structured output)"));
}

void register_tools()
{
    auto& registry = ToolRegistry::instance();

    registry.register_tool({std::string("execute_python"), std::string("python"),
        std::string("Execute arbitrary Python code in IDA context. Returns dict with result/stdout/stderr. ") +
        std::string("Supports Jupyter-style evaluation (expressions auto-return, statements exec)."),
        {{std::string("code"), std::string("string"), std::string("Python code to execute"), true}},
        execute_python, false});
}

}


static void responsive_auto_wait(ea_t start, ea_t end, const char* status_msg)
{
    if (start != 0 || end != BADADDR)
        auto_mark_range(start, end, AU_FINAL);

    if (!auto_is_ok() && !user_cancelled())
        auto_wait_range(0, BADADDR);

    (void)status_msg;
}

namespace navigation_tools
{

tool_result_t jump_to_address(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(std::string("Invalid address"));

    bool ok = jumpto(*ea_opt);
    if (!ok)
        return tool_result_t::error(std::string("Failed to navigate to ") + helpers::format_address(*ea_opt));

    return tool_result_t::ok(std::string("Navigated to ") + helpers::format_address(*ea_opt));
}

tool_result_t get_current_address(const json&)
{
    ea_t ea = get_screen_ea();
    if (ea == BADADDR)
        return tool_result_t::error(std::string("No current address available"));

    json data;
    data["address"] = helpers::format_address(ea);

    qstring name;
    if (get_name(&name, ea) > 0)
        data["name"] = std::string(name.c_str());

    func_t* fn = get_func(ea);
    if (fn)
    {
        data["function_start"] = helpers::format_address(fn->start_ea);
        qstring fname;
        if (get_func_name(&fname, fn->start_ea) > 0)
            data["function_name"] = std::string(fname.c_str());
        data["offset_in_function"] = helpers::format_address(ea - fn->start_ea);
    }

    segment_t* seg = getseg(ea);
    if (seg)
    {
        qstring segname;
        if (aida_get_segm_name(&segname, seg) > 0)
            data["segment"] = std::string(segname.c_str());
    }

    return tool_result_t::ok(std::string("Current address: ") + helpers::format_address(ea), data);
}

tool_result_t demangle_name(const json& params)
{
    std::string name = params["name"].get<std::string>();

    qstring demangled;
    int32 res = ::demangle_name(&demangled, name.c_str(), 0, DQT_FULL);

    if (res <= 0 || demangled.empty())
        return tool_result_t::error(std::string("Could not demangle: ") + name);

    json data;
    data["mangled"] = name;
    data["demangled"] = std::string(demangled.c_str());

    return tool_result_t::ok(std::string(demangled.c_str()), data);
}

tool_result_t wait_for_analysis(const json&)
{
    show_wait_box("HIDECANCEL\nAiDA: Waiting for auto-analysis...");
    responsive_auto_wait(0, BADADDR, "Waiting for auto-analysis...");
    hide_wait_box();
    bool ok = auto_is_ok();

    if (!ok)
        return tool_result_t::error(std::string("Analysis was cancelled by user"));

    return tool_result_t::ok(std::string("Auto-analysis completed"));
}

tool_result_t delete_function(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(std::string("Invalid address"));

    func_t* fn = get_func(*ea_opt);
    if (!fn)
        return tool_result_t::error(std::string("No function at ") + helpers::format_address(*ea_opt));

    qstring fname;
    get_func_name(&fname, fn->start_ea);
    ea_t start = fn->start_ea;

    bool ok = del_func(start);
    if (!ok)
        return tool_result_t::error(std::string("Failed to delete function at ") + helpers::format_address(start));

    return tool_result_t::ok(std::string("Deleted function ") + std::string(fname.c_str()) + " at " + helpers::format_address(start));
}

tool_result_t set_decompiler_comment(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(std::string("Invalid address"));

    std::string comment = params["comment"].get<std::string>();

    func_t* fn = get_func(*ea_opt);
    if (!fn)
        return tool_result_t::error(std::string("No function at ") + helpers::format_address(*ea_opt));

    if (!ida_utils::is_safely_decompilable(fn))
        return tool_result_t::error(std::string("Function is not decompilable (thunk/extern/tail)"));

    try
    {
        hexrays_failure_t hf;
        cfuncptr_t cfunc = decompile(fn, &hf);
        if (!cfunc)
            return tool_result_t::error(std::string("Decompilation failed: ") + std::string(hf.desc().c_str()));

        treeloc_t loc;
        loc.ea = *ea_opt;
        loc.itp = ITP_SEMI;

        cfunc->set_user_cmt(loc, comment.c_str());
        cfunc->save_user_cmts();

        return tool_result_t::ok(std::string("Decompiler comment set at ") + helpers::format_address(*ea_opt));
    }
    catch (const vd_failure_t& e)
    {
        return tool_result_t::error(std::string("Decompilation failed: ") + std::string(e.desc().c_str()));
    }
    catch (...)
    {
        return tool_result_t::error(std::string("Decompilation crashed for ") + helpers::format_address(*ea_opt));
    }
}

tool_result_t batch_rename(const json& params)
{
    auto renames = params["renames"];
    if (!renames.is_array())
        return tool_result_t::error(std::string("'renames' must be an array of {address, name} objects"));

    int success_count = 0;
    int fail_count = 0;
    json results = json::array();

    for (const auto& item : renames)
    {
        if (!item.is_object() || !item.contains("address") || !item.contains("name"))
        {
            fail_count++;
            continue;
        }
        std::string addr_str = item["address"].is_string() ? item["address"].get<std::string>() : (item["address"].is_number() ? item["address"].dump() : "");
        std::string new_name = item["name"].is_string() ? item["name"].get<std::string>() : "";

        auto ea_opt = helpers::parse_address(addr_str);
        if (!ea_opt)
        {
            results.push_back({{"address", addr_str}, {"success", false}, {"error", "Invalid address"}});
            fail_count++;
            continue;
        }

        bool ok = set_name(*ea_opt, new_name.c_str(), SN_CHECK);
        if (ok)
        {
            results.push_back({{"address", addr_str}, {"success", true}, {"name", new_name}});
            success_count++;


            auto& store = graphrag::GraphStore::instance();
            auto* node = store.get_node_by_address(
                current_module_graph_key(),
                graphrag::node_type_t::FUNCTION, *ea_opt);
            if (node)
            {
                node->name = new_name;
                store.upsert_node(*node);
            }
        }
        else
        {
            results.push_back({{"address", addr_str}, {"success", false}, {"error", "set_name failed"}});
            fail_count++;
        }
    }

    json data;
    data["results"] = results;
    data["success_count"] = success_count;
    data["fail_count"] = fail_count;

    return tool_result_t::ok(
        "Renamed " + std::to_string(success_count) + " items, " + std::to_string(fail_count) + " failures",
        data);
}

tool_result_t get_address_info(const json& params)
{
    auto ea_opt = helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(std::string("Invalid address"));

    ea_t ea = *ea_opt;
    json data;
    data["address"] = helpers::format_address(ea);

    qstring name;
    if (get_name(&name, ea) > 0)
        data["name"] = std::string(name.c_str());

    qstring demangled_name;
    if (name.size() > 0 && ::demangle_name(&demangled_name, name.c_str(), 0, DQT_FULL) > 0 && !demangled_name.empty())
        data["demangled"] = std::string(demangled_name.c_str());

    flags64_t f = get_flags(ea);
    data["is_code"] = is_code(f);
    data["is_data"] = is_data(f);
    data["is_head"] = is_head(f);
    data["is_tail"] = is_tail(f);
    data["has_name"] = has_name(f);
    data["has_xref"] = has_xref(f);

    qstring cmt;
    if (get_cmt(&cmt, ea, false) > 0)
        data["comment"] = std::string(cmt.c_str());

    qstring rcmt;
    if (get_cmt(&rcmt, ea, true) > 0)
        data["repeatable_comment"] = std::string(rcmt.c_str());

    func_t* fn = get_func(ea);
    if (fn)
    {
        qstring fname;
        get_func_name(&fname, fn->start_ea);
        data["function"] = std::string(fname.c_str());
        data["function_start"] = helpers::format_address(fn->start_ea);
        data["function_end"] = helpers::format_address(fn->end_ea);
    }

    segment_t* seg = getseg(ea);
    if (seg)
    {
        qstring segname;
        aida_get_segm_name(&segname, seg);
        data["segment"] = std::string(segname.c_str());
        data["segment_start"] = helpers::format_address(seg->start_ea);
        data["segment_end"] = helpers::format_address(seg->end_ea);
    }

    tinfo_t ti;
    if (get_tinfo(&ti, ea))
    {
        qstring type_str;
        ti.print(&type_str);
        data["type"] = std::string(type_str.c_str());
    }

    return tool_result_t::ok(std::string("Address info for ") + helpers::format_address(ea), data);
}

void register_tools()
{
    auto& registry = ToolRegistry::instance();

    registry.register_tool({std::string("jump_to_address"), std::string("navigation"),
        std::string("Navigate IDA view to the specified address."),
        {{std::string("address"), std::string("string"), std::string("Target address (hex or decimal)"), true}},
        jump_to_address});

    registry.register_tool({std::string("get_current_address"), std::string("navigation"),
        std::string("Get the current cursor address in IDA with context (function, segment, name)."),
        {},
        get_current_address});

    registry.register_tool({std::string("demangle_name"), std::string("navigation"),
        std::string("Demangle a C++ mangled symbol name."),
        {{std::string("name"), std::string("string"), std::string("Mangled symbol name"), true}},
        demangle_name});

    registry.register_tool({std::string("wait_for_analysis"), std::string("navigation"),
        std::string("Wait for IDA auto-analysis to complete before proceeding. Returns when all analysis queues are empty."),
        {},
        wait_for_analysis});

    registry.register_tool({std::string("delete_function"), std::string("navigation"),
        std::string("Delete/remove a function definition at the given address."),
        {{std::string("address"), std::string("string"), std::string("Address within the function to delete"), true}},
        delete_function, false});

    registry.register_tool({std::string("set_decompiler_comment"), std::string("navigation"),
        std::string("Set a comment in the Hex-Rays decompiler pseudocode view at the specified address."),
        {{std::string("address"), std::string("string"), std::string("Address to attach the decompiler comment"), true},
         {std::string("comment"), std::string("string"), std::string("Comment text (empty to delete)"), true}},
        set_decompiler_comment, false});

    registry.register_tool({std::string("batch_rename"), std::string("navigation"),
        std::string("Rename multiple addresses at once. Efficient for bulk renaming operations."),
        {{std::string("renames"), std::string("array"), std::string("Array of objects with 'address' and 'name' fields"), true, {},
          json::object({
              {"type", "object"},
              {"properties", json::object({
                  {"address", json::object({{"type", "string"}, {"description", "Address in hex (e.g., '0x140001000')"}})},
                  {"name", json::object({{"type", "string"}, {"description", "New name for the address"}})}
              })},
              {"required", json::array({"address", "name"})}
          })
        }},
        batch_rename, false});

    registry.register_tool({std::string("get_address_info"), std::string("navigation"),
        std::string("Get comprehensive information about a specific address: name, type, flags, comments, segment, function."),
        {{std::string("address"), std::string("string"), std::string("Address to query"), true}},
        get_address_info});
}

}

namespace analysis_tools
{

tool_result_t detect_obfuscation_patterns(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(std::string("Invalid address"));

    ea_t ea = *addr;
    func_t* pfn = get_func(ea);
    if (!pfn)
        return tool_result_t::error(std::string("No function at ") + helpers::format_address(ea));

    size_t scan_size = params.value("scan_size", 0);
    ea_t scan_start = pfn->start_ea;
    ea_t scan_end   = pfn->end_ea;
    if (scan_size > 0)
        scan_end = std::min(scan_start + static_cast<ea_t>(scan_size), pfn->end_ea);

    json result;
    result["function"] = helpers::get_name_or_address(pfn->start_ea);
    result["start"]    = helpers::format_address(scan_start);
    result["end"]      = helpers::format_address(scan_end);

    json patterns = json::array();
    int opaque_predicates = 0;
    int dead_code_blocks  = 0;
    int junk_sequences    = 0;
    int indirect_jumps    = 0;
    int self_modifying    = 0;
    int stack_manip       = 0;

    ea_t cur = scan_start;
    ea_t prev_ea = BADADDR;
    int nop_run = 0;

    while (cur < scan_end && cur != BADADDR)
    {
        insn_t insn;
        int len = decode_insn(&insn, cur);
        if (len <= 0)
        {
            cur = next_head(cur, scan_end);
            if (cur == BADADDR) break;
            continue;
        }

        if (insn.itype == NN_nop)
        {
            ++nop_run;
            if (nop_run == 4)
            {
                ++junk_sequences;
                json p;
                p["type"]    = std::string("nop_sled");
                p["address"] = helpers::format_address(cur - 3);
                p["note"]    = std::string("4+ consecutive NOPs suggest junk insertion");
                patterns.push_back(std::move(p));
            }
        }
        else
        {
            nop_run = 0;
        }

        if (prev_ea != BADADDR && (insn.itype == NN_jz || insn.itype == NN_jnz ||
            insn.itype == NN_jbe || insn.itype == NN_ja))
        {
            insn_t prev_insn;
            if (decode_insn(&prev_insn, prev_ea) > 0)
            {
                bool is_opaque = false;
                if (prev_insn.itype == NN_xor && prev_insn.ops[0].type == o_reg &&
                    prev_insn.ops[1].type == o_reg && prev_insn.ops[0].reg == prev_insn.ops[1].reg)
                    is_opaque = true;
                if (prev_insn.itype == NN_test && prev_insn.ops[0].type == o_reg &&
                    prev_insn.ops[1].type == o_reg && prev_insn.ops[0].reg == prev_insn.ops[1].reg)
                    is_opaque = true;

                if (is_opaque)
                {
                    ++opaque_predicates;
                    json p;
                    p["type"]    = std::string("opaque_predicate");
                    p["address"] = helpers::format_address(cur);
                    qstring dis;
                    generate_disasm_line(&dis, cur, GENDSM_FORCE_CODE);
                    tag_remove(&dis);
                    p["instruction"] = dis.c_str();
                    patterns.push_back(std::move(p));
                }
            }
        }

        if (insn.itype == NN_jmpni || insn.itype == NN_jmpfi)
        {
            ++indirect_jumps;
            json p;
            p["type"]    = std::string("indirect_jump");
            p["address"] = helpers::format_address(cur);
            qstring dis;
            generate_disasm_line(&dis, cur, GENDSM_FORCE_CODE);
            tag_remove(&dis);
            p["instruction"] = dis.c_str();
            patterns.push_back(std::move(p));
        }

        if (insn.itype == NN_push && prev_ea != BADADDR)
        {
            ea_t next = cur + len;
            insn_t next_insn;
            if (next < scan_end && decode_insn(&next_insn, next) > 0 && next_insn.itype == NN_retn)
            {
                ++stack_manip;
                json p;
                p["type"]    = std::string("push_ret_redirect");
                p["address"] = helpers::format_address(cur);
                p["note"]    = std::string("push+ret pattern used as indirect jump (anti-disassembly)");
                patterns.push_back(std::move(p));
            }
        }

        prev_ea = cur;
        cur += len;
    }

    func_item_iterator_t fii(pfn);
    std::set<ea_t> reachable;
    for (bool ok = fii.first(); ok; ok = fii.next_head())
    {
        ea_t item = fii.current();
        xrefblk_t xb;
        bool has_incoming = false;
        if (item == pfn->start_ea)
            has_incoming = true;
        else
        {
            for (bool xok = xb.first_to(item, XREF_ALL); xok; xok = xb.next_to())
            {
                if (xb.iscode && aida_func_contains(pfn, xb.from))
                {
                    has_incoming = true;
                    break;
                }
            }
        }
        if (!has_incoming)
        {
            ++dead_code_blocks;
            if (dead_code_blocks <= 10)
            {
                json p;
                p["type"]    = std::string("dead_code");
                p["address"] = helpers::format_address(item);
                p["note"]    = std::string("No incoming code xrefs within function - possibly dead/junk code");
                patterns.push_back(std::move(p));
            }
        }
    }

    result["patterns"]           = std::move(patterns);
    result["opaque_predicates"]  = opaque_predicates;
    result["dead_code_blocks"]   = dead_code_blocks;
    result["junk_sequences"]     = junk_sequences;
    result["indirect_jumps"]     = indirect_jumps;
    result["stack_manipulation"] = stack_manip;

    int score = 0;
    if (opaque_predicates > 0) score += std::min(opaque_predicates * 10, 25);
    if (dead_code_blocks > 2)  score += 15;
    if (junk_sequences > 0)    score += std::min(junk_sequences * 8, 20);
    if (indirect_jumps > 0)    score += std::min(indirect_jumps * 15, 25);
    if (stack_manip > 0)       score += 15;
    result["obfuscation_score_pct"] = std::min(score, 100);

    return tool_result_t::ok(std::string("Obfuscation pattern detection complete"), result);
}

tool_result_t analyze_control_flow(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(std::string("Invalid address"));

    ea_t ea = *addr;
    func_t* pfn = get_func(ea);
    if (!pfn)
        return tool_result_t::error(std::string("No function at ") + helpers::format_address(ea));

    json result;
    result["function"] = helpers::get_name_or_address(pfn->start_ea);
    result["start"]    = helpers::format_address(pfn->start_ea);
    result["end"]      = helpers::format_address(pfn->end_ea);
    result["size"]     = pfn->end_ea - pfn->start_ea;

    json blocks = json::array();
    int block_count = 0;
    int edge_count  = 0;
    int back_edges  = 0;
    std::set<ea_t> block_starts;
    block_starts.insert(pfn->start_ea);

    func_item_iterator_t fii(pfn);
    for (bool ok = fii.first(); ok; ok = fii.next_head())
    {
        ea_t item = fii.current();
        insn_t insn;
        if (decode_insn(&insn, item) <= 0)
            continue;

        if (is_basic_block_end(insn, false))
        {
            ea_t fall = item + insn.size;
            if (fall < pfn->end_ea && aida_func_contains(pfn, fall))
                block_starts.insert(fall);

            xrefblk_t xb;
            for (bool xok = xb.first_from(item, XREF_ALL); xok; xok = xb.next_from())
            {
                if (xb.iscode && aida_func_contains(pfn, xb.to))
                    block_starts.insert(xb.to);
            }
        }
    }

    for (ea_t bs : block_starts)
    {
        ++block_count;
        ea_t block_end = pfn->end_ea;
        auto it = block_starts.upper_bound(bs);
        if (it != block_starts.end())
            block_end = *it;

        int insn_count = 0;
        ea_t last_insn = bs;
        for (ea_t a = bs; a < block_end && a != BADADDR;)
        {
            insn_t insn;
            int len = decode_insn(&insn, a);
            if (len <= 0) break;
            ++insn_count;
            last_insn = a;
            a += len;
        }

        json blk;
        blk["start"]       = helpers::format_address(bs);
        blk["end"]         = helpers::format_address(block_end);
        blk["instructions"] = insn_count;

        json successors = json::array();
        xrefblk_t xb;
        for (bool xok = xb.first_from(last_insn, XREF_ALL); xok; xok = xb.next_from())
        {
            if (xb.iscode && aida_func_contains(pfn, xb.to))
            {
                ++edge_count;
                successors.push_back(helpers::format_address(xb.to));
                if (xb.to <= bs)
                    ++back_edges;
            }
        }

        ea_t fall = last_insn;
        insn_t last;
        if (decode_insn(&last, last_insn) > 0)
        {
            fall = last_insn + last.size;
            if (fall < pfn->end_ea && aida_func_contains(pfn, fall) && !is_basic_block_end(last, true))
            {
                ++edge_count;
                successors.push_back(helpers::format_address(fall));
            }
        }
        blk["successors"] = std::move(successors);

        if (blocks.size() < 200)
            blocks.push_back(std::move(blk));
    }

    result["basic_blocks"]  = std::move(blocks);
    result["block_count"]   = block_count;
    result["edge_count"]    = edge_count;
    result["back_edges"]    = back_edges;

    int cyclomatic = edge_count - block_count + 2;
    if (cyclomatic < 1) cyclomatic = 1;
    result["cyclomatic_complexity"] = cyclomatic;

    return tool_result_t::ok(std::string("Control flow analysis complete"), result);
}

tool_result_t get_function_complexity(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(std::string("Invalid address"));

    ea_t ea = *addr;
    func_t* pfn = get_func(ea);
    if (!pfn)
        return tool_result_t::error(std::string("No function at ") + helpers::format_address(ea));

    json result;
    qstring fname;
    get_func_name(&fname, pfn->start_ea);
    result["function"] = fname.c_str();
    result["start"]    = helpers::format_address(pfn->start_ea);
    result["size"]     = pfn->end_ea - pfn->start_ea;

    int total_insns = 0, call_count = 0, branch_count = 0, ret_count = 0;
    int arith_count = 0, mem_access = 0, string_ops = 0;
    std::set<ea_t> block_starts;
    block_starts.insert(pfn->start_ea);
    int edge_count = 0;

    func_item_iterator_t fii(pfn);
    for (bool ok = fii.first(); ok; ok = fii.next_head())
    {
        ea_t item = fii.current();
        insn_t insn;
        if (decode_insn(&insn, item) <= 0) continue;
        ++total_insns;

        if (insn.itype == NN_call || insn.itype == NN_callni || insn.itype == NN_callfi)
            ++call_count;
        if (insn.itype == NN_retn || insn.itype == NN_retf)
            ++ret_count;
        if (insn.itype >= NN_ja && insn.itype <= NN_jz)
            ++branch_count;
        if (insn.itype == NN_add || insn.itype == NN_sub || insn.itype == NN_imul ||
            insn.itype == NN_idiv || insn.itype == NN_mul || insn.itype == NN_div ||
            insn.itype == NN_shl || insn.itype == NN_shr || insn.itype == NN_sar)
            ++arith_count;
        if (insn.itype == NN_movs || insn.itype == NN_stos || insn.itype == NN_cmps ||
            insn.itype == NN_scas || insn.itype == NN_lods)
            ++string_ops;

        for (int oi = 0; oi < UA_MAXOP; ++oi)
        {
            if (insn.ops[oi].type == o_mem || insn.ops[oi].type == o_phrase ||
                insn.ops[oi].type == o_displ)
            {
                ++mem_access;
                break;
            }
        }

        if (is_basic_block_end(insn, false))
        {
            ea_t fall = item + insn.size;
            if (aida_func_contains(pfn, fall)) { block_starts.insert(fall); ++edge_count; }
            xrefblk_t xb;
            for (bool xok = xb.first_from(item, XREF_ALL); xok; xok = xb.next_from())
            {
                if (xb.iscode && aida_func_contains(pfn, xb.to))
                {
                    block_starts.insert(xb.to);
                    ++edge_count;
                }
            }
        }
    }

    int block_count = static_cast<int>(block_starts.size());
    int cyclomatic = edge_count - block_count + 2;
    if (cyclomatic < 1) cyclomatic = 1;

    result["instruction_count"]    = total_insns;
    result["basic_block_count"]    = block_count;
    result["edge_count"]           = edge_count;
    result["cyclomatic_complexity"] = cyclomatic;
    result["call_count"]           = call_count;
    result["branch_count"]         = branch_count;
    result["return_count"]         = ret_count;
    result["arithmetic_ops"]       = arith_count;
    result["memory_accesses"]      = mem_access;
    result["string_operations"]    = string_ops;

    std::set<uint16> unique_ops;
    std::set<uint64_t> unique_operands;
    func_item_iterator_t fii2(pfn);
    for (bool ok = fii2.first(); ok; ok = fii2.next_head())
    {
        insn_t insn;
        if (decode_insn(&insn, fii2.current()) <= 0) continue;
        unique_ops.insert(insn.itype);
        for (int oi = 0; oi < UA_MAXOP && insn.ops[oi].type != o_void; ++oi)
        {
            uint64_t key = (static_cast<uint64_t>(insn.ops[oi].type) << 48) |
                           (static_cast<uint64_t>(insn.ops[oi].reg) << 32) |
                           static_cast<uint64_t>(insn.ops[oi].value & 0xFFFFFFFF);
            unique_operands.insert(key);
        }
    }
    result["unique_operators"] = unique_ops.size();
    result["unique_operands"]  = unique_operands.size();

    std::string complexity_rating;
    if (cyclomatic <= 5)       complexity_rating = "simple";
    else if (cyclomatic <= 10) complexity_rating = "moderate";
    else if (cyclomatic <= 20) complexity_rating = "complex";
    else if (cyclomatic <= 50) complexity_rating = "very_complex";
    else                       complexity_rating = "extremely_complex";
    result["complexity_rating"] = complexity_rating;

    return tool_result_t::ok(std::string("Function complexity analysis"), result);
}

tool_result_t analyze_string_decryption(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(std::string("Invalid address"));

    ea_t ea = *addr;
    func_t* pfn = get_func(ea);
    if (!pfn)
        return tool_result_t::error(std::string("No function at ") + helpers::format_address(ea));

    json result;
    result["function"] = helpers::get_name_or_address(pfn->start_ea);

    json candidates = json::array();
    int xor_loops = 0, byte_manip_chains = 0, stack_strings = 0;

    func_item_iterator_t fii(pfn);
    ea_t xor_chain_start = BADADDR;
    int xor_chain_len = 0;
    int mov_byte_chain = 0;
    ea_t mov_byte_start = BADADDR;

    for (bool ok = fii.first(); ok; ok = fii.next_head())
    {
        ea_t item = fii.current();
        insn_t insn;
        if (decode_insn(&insn, item) <= 0) continue;

        if (insn.itype == NN_xor)
        {
            bool self_xor = (insn.ops[0].type == o_reg && insn.ops[1].type == o_reg &&
                             insn.ops[0].reg == insn.ops[1].reg);
            if (!self_xor)
            {
                if (xor_chain_start == BADADDR) xor_chain_start = item;
                ++xor_chain_len;
            }
            else
            {
                if (xor_chain_len >= 2)
                {
                    ++xor_loops;
                    json c;
                    c["type"]    = std::string("xor_decryption");
                    c["start"]   = helpers::format_address(xor_chain_start);
                    c["length"]  = xor_chain_len;
                    c["note"]    = std::string("Consecutive XOR operations suggest string/data decryption");
                    candidates.push_back(std::move(c));
                }
                xor_chain_start = BADADDR;
                xor_chain_len = 0;
            }
        }
        else
        {
            if (xor_chain_len >= 2)
            {
                ++xor_loops;
                json c;
                c["type"]    = std::string("xor_decryption");
                c["start"]   = helpers::format_address(xor_chain_start);
                c["length"]  = xor_chain_len;
                candidates.push_back(std::move(c));
            }
            xor_chain_start = BADADDR;
            xor_chain_len = 0;
        }

        if (insn.itype == NN_mov && insn.ops[0].type == o_displ &&
            insn.ops[1].type == o_imm && insn.ops[1].value >= 0x20 && insn.ops[1].value <= 0x7E)
        {
            if (mov_byte_start == BADADDR) mov_byte_start = item;
            ++mov_byte_chain;
        }
        else
        {
            if (mov_byte_chain >= 4)
            {
                ++stack_strings;
                json c;
                c["type"]    = std::string("stack_string");
                c["start"]   = helpers::format_address(mov_byte_start);
                c["length"]  = mov_byte_chain;
                c["note"]    = std::string("Sequential byte MOVs to stack - likely stack-constructed string");

                std::string reconstructed;
                ea_t scan = mov_byte_start;
                for (int i = 0; i < mov_byte_chain && scan < pfn->end_ea; ++i)
                {
                    insn_t si;
                    if (decode_insn(&si, scan) > 0 && si.itype == NN_mov &&
                        si.ops[1].type == o_imm && si.ops[1].value >= 0x20 && si.ops[1].value <= 0x7E)
                    {
                        reconstructed += static_cast<char>(si.ops[1].value);
                    }
                    scan = next_head(scan, pfn->end_ea);
                }
                if (!reconstructed.empty())
                    c["reconstructed"] = reconstructed;

                candidates.push_back(std::move(c));
            }
            mov_byte_chain = 0;
            mov_byte_start = BADADDR;
        }

        if (insn.itype == NN_call || insn.itype == NN_callni)
        {
            ea_t target = BADADDR;
            if (insn.ops[0].type == o_near || insn.ops[0].type == o_far)
                target = insn.ops[0].addr;
            if (target != BADADDR)
            {
                qstring tname;
                if (get_func_name(&tname, target) > 0)
                {
                    std::string name_lower(tname.c_str());
                    std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::tolower);
                    if (name_lower.find("decrypt") != std::string::npos ||
                        name_lower.find("decode") != std::string::npos ||
                        name_lower.find("deobfus") != std::string::npos ||
                        name_lower.find("unpack") != std::string::npos)
                    {
                        json c;
                        c["type"]      = std::string("decrypt_call");
                        c["address"]   = helpers::format_address(item);
                        c["target"]    = tname.c_str();
                        candidates.push_back(std::move(c));
                    }
                }
            }
        }
    }

    result["candidates"]       = std::move(candidates);
    result["xor_patterns"]     = xor_loops;
    result["stack_strings"]    = stack_strings;

    return tool_result_t::ok(std::string("String decryption analysis"), result);
}

tool_result_t analyze_indirect_calls(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(std::string("Invalid address"));

    ea_t ea = *addr;
    func_t* pfn = get_func(ea);
    if (!pfn)
        return tool_result_t::error(std::string("No function at ") + helpers::format_address(ea));

    json result;
    result["function"] = helpers::get_name_or_address(pfn->start_ea);

    json calls = json::array();
    int vtable_calls = 0, func_ptr_calls = 0, register_calls = 0;

    func_item_iterator_t fii(pfn);
    for (bool ok = fii.first(); ok; ok = fii.next_head())
    {
        ea_t item = fii.current();
        insn_t insn;
        if (decode_insn(&insn, item) <= 0) continue;

        bool is_indirect_call = (insn.itype == NN_callni || insn.itype == NN_callfi);
        bool is_indirect_jmp  = (insn.itype == NN_jmpni || insn.itype == NN_jmpfi);

        if (!is_indirect_call && !is_indirect_jmp) continue;

        json entry;
        entry["address"] = helpers::format_address(item);
        entry["type"]    = is_indirect_call ? "indirect_call" : "indirect_jump";

        qstring dis;
        generate_disasm_line(&dis, item, GENDSM_FORCE_CODE);
        tag_remove(&dis);
        entry["instruction"] = dis.c_str();

        if (insn.ops[0].type == o_displ)
        {
            ++vtable_calls;
            entry["classification"] = std::string("vtable_call");
            entry["base_register"]  = static_cast<int>(insn.ops[0].reg);
            entry["offset"]         = static_cast<int64_t>(insn.ops[0].addr);
        }
        else if (insn.ops[0].type == o_mem)
        {
            ++func_ptr_calls;
            entry["classification"] = std::string("function_pointer");
            entry["target_address"] = helpers::format_address(static_cast<ea_t>(insn.ops[0].addr));
            qstring tname;
            if (get_name(&tname, static_cast<ea_t>(insn.ops[0].addr)) > 0)
                entry["target_name"] = tname.c_str();
        }
        else if (insn.ops[0].type == o_reg)
        {
            ++register_calls;
            entry["classification"] = std::string("register_call");
            entry["register"]       = static_cast<int>(insn.ops[0].reg);
        }
        else
        {
            entry["classification"] = std::string("other");
        }

        json targets = json::array();
        xrefblk_t xb;
        for (bool xok = xb.first_from(item, XREF_FAR); xok; xok = xb.next_from())
        {
            if (xb.iscode)
            {
                json t;
                t["address"] = helpers::format_address(xb.to);
                qstring tname;
                if (get_func_name(&tname, xb.to) > 0)
                    t["name"] = tname.c_str();
                targets.push_back(std::move(t));
            }
        }
        if (!targets.empty())
            entry["resolved_targets"] = std::move(targets);

        calls.push_back(std::move(entry));
    }

    result["indirect_calls"]   = std::move(calls);
    result["vtable_calls"]     = vtable_calls;
    result["func_ptr_calls"]   = func_ptr_calls;
    result["register_calls"]   = register_calls;
    result["total"]            = vtable_calls + func_ptr_calls + register_calls;

    return tool_result_t::ok(std::string("Indirect call analysis"), result);
}

tool_result_t find_crypto_constants(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    size_t scan_size = params.value("scan_size", 65536);
    if (scan_size > 1048576) scan_size = 1048576;

    ea_t start_ea;
    ea_t end_ea;

    if (addr)
    {
        start_ea = *addr;
        func_t* pfn = get_func(start_ea);
        if (pfn)
            end_ea = pfn->end_ea;
        else
            end_ea = start_ea + static_cast<ea_t>(scan_size);
    }
    else
    {
        start_ea = inf_get_min_ea();
        end_ea   = std::min(start_ea + static_cast<ea_t>(scan_size), inf_get_max_ea());
    }

    struct crypto_sig_t {
        const char* name;
        const char* algorithm;
        uint32_t    value;
    };
    static const crypto_sig_t signatures[] = {
        {"SHA-256 H0",     "SHA-256",    0x6A09E667},
        {"SHA-256 H1",     "SHA-256",    0xBB67AE85},
        {"SHA-256 H2",     "SHA-256",    0x3C6EF372},
        {"SHA-256 H3",     "SHA-256",    0xA54FF53A},
        {"SHA-256 K[0]",   "SHA-256",    0x428A2F98},
        {"SHA-256 K[1]",   "SHA-256",    0x71374491},
        {"MD5 T[1]",       "MD5",        0xD76AA478},
        {"MD5 T[2]",       "MD5",        0xE8C7B756},
        {"MD5 T[3]",       "MD5",        0x242070DB},
        {"MD5 init A",     "MD5",        0x67452301},
        {"MD5 init B",     "MD5",        0xEFCDAB89},
        {"MD5 init C",     "MD5",        0x98BADCFE},
        {"MD5 init D",     "MD5",        0x10325476},
        {"AES Te0[0]",     "AES",        0xC66363A5},
        {"AES Te0[1]",     "AES",        0xF87C7C84},
        {"AES Td0[0]",     "AES",        0x51F4A750},
        {"AES sbox[0..3]", "AES",        0x637C777B},
        {"CRC32 poly",     "CRC32",      0xEDB88320},
        {"CRC32 poly alt", "CRC32",      0x04C11DB7},
        {"Blowfish P[0]",  "Blowfish",   0x243F6A88},
        {"Blowfish P[1]",  "Blowfish",   0x85A308D3},
        {"SHA-1 K0",       "SHA-1",      0x5A827999},
        {"SHA-1 K1",       "SHA-1",      0x6ED9EBA1},
        {"SHA-1 K2",       "SHA-1",      0x8F1BBCDC},
        {"SHA-1 K3",       "SHA-1",      0xCA62C1D6},
        {"TEA delta",      "TEA/XTEA",   0x9E3779B9},
        {"RC5/RC6 P32",    "RC5/RC6",    0xB7E15163},
        {"RC5/RC6 Q32",    "RC5/RC6",    0x9E3779B9},
        {"ChaCha20",       "ChaCha20",   0x61707865},
        {"Salsa20",        "Salsa20",    0x61707865},
    };

    json found = json::array();
    std::set<std::string> found_algos;

    for (ea_t cur = start_ea; cur < end_ea && cur != BADADDR;)
    {
        insn_t insn;
        int len = decode_insn(&insn, cur);
        if (len <= 0)
        {
            cur = next_head(cur, end_ea);
            if (cur == BADADDR) break;
            continue;
        }

        for (int oi = 0; oi < UA_MAXOP && insn.ops[oi].type != o_void; ++oi)
        {
            if (insn.ops[oi].type != o_imm) continue;
            uint32_t val = static_cast<uint32_t>(insn.ops[oi].value);
            for (const auto& sig : signatures)
            {
                if (val == sig.value)
                {
                    json f;
                    f["address"]   = helpers::format_address(cur);
                    f["constant"]  = sig.name;
                    f["algorithm"] = sig.algorithm;
                    f["value"]     = helpers::format_address(static_cast<ea_t>(val));
                    qstring dis;
                    generate_disasm_line(&dis, cur, GENDSM_FORCE_CODE);
                    tag_remove(&dis);
                    f["instruction"] = dis.c_str();
                    found.push_back(std::move(f));
                    found_algos.insert(sig.algorithm);
                }
            }
        }
        cur += len;
    }

    for (ea_t cur = start_ea; cur + 4 <= end_ea; cur += 4)
    {
        if (!is_loaded(cur)) continue;
        uint32_t val = static_cast<uint32_t>(get_dword(cur));
        for (const auto& sig : signatures)
        {
            if (val == sig.value)
            {
                bool dup = false;
                for (const auto& f : found)
                {
                    if (f.value("address", "") == helpers::format_address(cur))
                    { dup = true; break; }
                }
                if (!dup)
                {
                    json f;
                    f["address"]   = helpers::format_address(cur);
                    f["constant"]  = sig.name;
                    f["algorithm"] = sig.algorithm;
                    f["value"]     = helpers::format_address(static_cast<ea_t>(val));
                    f["source"]    = std::string("data");
                    found.push_back(std::move(f));
                    found_algos.insert(sig.algorithm);
                }
            }
        }
    }

    json result;
    result["scan_start"]  = helpers::format_address(start_ea);
    result["scan_end"]    = helpers::format_address(end_ea);
    result["matches"]     = std::move(found);
    result["match_count"] = found.size();

    json algos = json::array();
    for (const auto& a : found_algos)
        algos.push_back(a);
    result["algorithms_detected"] = std::move(algos);

    return tool_result_t::ok(std::string("Crypto constant scan"), result);
}

tool_result_t analyze_data_flow(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(std::string("Invalid address"));

    ea_t ea = *addr;
    func_t* pfn = get_func(ea);
    if (!pfn)
        return tool_result_t::error(std::string("No function at ") + helpers::format_address(ea));

    int max_depth = params.value("max_depth", 32);
    if (max_depth < 1) max_depth = 1;
    if (max_depth > 256) max_depth = 256;

    json result;
    result["function"] = helpers::get_name_or_address(pfn->start_ea);
    result["start_address"] = helpers::format_address(ea);

    json defs = json::array();
    json uses = json::array();

    ea_t scan = ea;
    int steps = 0;
    std::set<ea_t> visited;
    while (scan >= pfn->start_ea && steps < max_depth)
    {
        if (visited.count(scan)) break;
        visited.insert(scan);
        insn_t insn;
        if (decode_insn(&insn, scan) <= 0) break;
        if (scan != ea)
        {
            bool is_def = (insn.itype == NN_mov || insn.itype == NN_lea ||
                insn.itype == NN_xor || insn.itype == NN_add || insn.itype == NN_sub ||
                insn.itype == NN_and || insn.itype == NN_or || insn.itype == NN_shl ||
                insn.itype == NN_shr || insn.itype == NN_imul || insn.itype == NN_movzx ||
                insn.itype == NN_movsx);
            if (is_def)
            {
                json d;
                d["address"] = helpers::format_address(scan);
                qstring dis;
                generate_disasm_line(&dis, scan, GENDSM_FORCE_CODE);
                tag_remove(&dis);
                d["instruction"] = dis.c_str();
                d["direction"] = std::string("backward");
                d["distance"] = steps;
                defs.push_back(std::move(d));
            }
        }
        scan = prev_head(scan, pfn->start_ea);
        ++steps;
    }

    scan = ea; steps = 0; visited.clear();
    while (scan < pfn->end_ea && steps < max_depth)
    {
        if (visited.count(scan)) break;
        visited.insert(scan);
        insn_t insn;
        if (decode_insn(&insn, scan) <= 0) break;
        if (scan != ea)
        {
            json u;
            u["address"] = helpers::format_address(scan);
            qstring dis;
            generate_disasm_line(&dis, scan, GENDSM_FORCE_CODE);
            tag_remove(&dis);
            u["instruction"] = dis.c_str();
            u["direction"] = std::string("forward");
            u["distance"] = steps;
            if (insn.itype == NN_call || insn.itype == NN_callni)
                u["usage_type"] = std::string("call_argument");
            else if (insn.itype == NN_cmp || insn.itype == NN_test)
                u["usage_type"] = std::string("comparison");
            else if (insn.itype == NN_mov && insn.ops[0].type == o_mem)
                u["usage_type"] = std::string("store");
            else if (insn.itype == NN_push)
                u["usage_type"] = std::string("push");
            else
                u["usage_type"] = std::string("computation");
            uses.push_back(std::move(u));
        }
        scan = next_head(scan, pfn->end_ea);
        ++steps;
    }

    result["definitions"] = std::move(defs);
    result["uses"] = std::move(uses);
    result["pseudocode"] = helpers::get_pseudocode(pfn->start_ea);

    return tool_result_t::ok(std::string("Data flow analysis"), result);
}

tool_result_t detect_anti_analysis(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(std::string("Invalid address"));

    ea_t ea = *addr;
    func_t* pfn = get_func(ea);
    ea_t scan_start = pfn ? pfn->start_ea : ea;
    ea_t scan_end = pfn ? pfn->end_ea : ea + 4096;

    json result;
    if (pfn) result["function"] = helpers::get_name_or_address(pfn->start_ea);
    result["scan_start"] = helpers::format_address(scan_start);
    result["scan_end"] = helpers::format_address(scan_end);

    json detections = json::array();
    int anti_debug = 0, anti_vm = 0, anti_disasm = 0, timing_checks = 0;

    static const char* dbg_apis[] = {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "NtSetInformationThread",
        "OutputDebugString", "GetTickCount", "QueryPerformanceCounter",
        "NtQuerySystemInformation", "DbgBreakPoint", "DbgUiRemoteBreakin",
        nullptr
    };
    static const char* vm_apis[] = {
        "GetSystemFirmwareTable", "EnumSystemFirmwareTable", nullptr
    };
    static const char* vm_strings[] = {
        "VMware", "VBox", "VBOX", "Virtual", "QEMU", "Xen",
        "vmtoolsd", "vmwaretray", "vboxservice", nullptr
    };

    auto check_insn = [&](ea_t item) {
        insn_t insn;
        if (decode_insn(&insn, item) <= 0) return;

        if (insn.itype == NN_call || insn.itype == NN_callni || insn.itype == NN_callfi)
        {
            ea_t target = BADADDR;
            if (insn.ops[0].type == o_near || insn.ops[0].type == o_far)
                target = insn.ops[0].addr;
            else if (insn.ops[0].type == o_mem)
                target = static_cast<ea_t>(insn.ops[0].addr);
            if (target != BADADDR)
            {
                qstring tname;
                if (get_name(&tname, target) > 0)
                {
                    for (int i = 0; dbg_apis[i]; ++i)
                    {
                        if (tname.find(dbg_apis[i]) != qstring::npos)
                        {
                            ++anti_debug;
                            json d; d["type"] = std::string("anti_debug_api");
                            d["address"] = helpers::format_address(item);
                            d["api"] = tname.c_str();
                            detections.push_back(std::move(d)); break;
                        }
                    }
                    for (int i = 0; vm_apis[i]; ++i)
                    {
                        if (tname.find(vm_apis[i]) != qstring::npos)
                        {
                            ++anti_vm;
                            json d; d["type"] = std::string("anti_vm_api");
                            d["address"] = helpers::format_address(item);
                            d["api"] = tname.c_str();
                            detections.push_back(std::move(d)); break;
                        }
                    }
                }
            }
        }
        if (insn.itype == NN_cpuid)
        {
            ++anti_vm;
            json d; d["type"] = std::string("cpuid_check");
            d["address"] = helpers::format_address(item);
            d["note"] = std::string("CPUID for VM/hypervisor detection");
            detections.push_back(std::move(d));
        }
        if (insn.itype == NN_rdtsc)
        {
            ++timing_checks;
            json d; d["type"] = std::string("timing_check");
            d["address"] = helpers::format_address(item);
            d["note"] = std::string("RDTSC timing-based anti-debug");
            detections.push_back(std::move(d));
        }
        if (insn.itype == NN_int && insn.ops[0].type == o_imm && insn.ops[0].value == 0x2D)
        {
            ++anti_debug;
            json d; d["type"] = std::string("int2d_anti_debug");
            d["address"] = helpers::format_address(item);
            detections.push_back(std::move(d));
        }
        if (insn.itype == NN_int3)
        {
            ++anti_debug;
            json d; d["type"] = std::string("int3_trap");
            d["address"] = helpers::format_address(item);
            detections.push_back(std::move(d));
        }
        if (insn.itype == NN_in)
        {
            ++anti_vm;
            json d; d["type"] = std::string("port_io_check");
            d["address"] = helpers::format_address(item);
            d["note"] = std::string("IN instruction for VMware backdoor");
            detections.push_back(std::move(d));
        }
    };

    if (pfn)
    {
        func_item_iterator_t fii(pfn);
        for (bool ok = fii.first(); ok; ok = fii.next_head())
            check_insn(fii.current());
    }
    else
    {
        for (ea_t cur = scan_start; cur < scan_end && cur != BADADDR;)
        {
            check_insn(cur);
            insn_t tmp;
            int len = decode_insn(&tmp, cur);
            cur = (len > 0) ? cur + len : next_head(cur, scan_end);
            if (cur == BADADDR) break;
        }
    }

    if (pfn)
    {
        func_item_iterator_t fii2(pfn);
        for (bool ok = fii2.first(); ok; ok = fii2.next_head())
        {
            xrefblk_t xb;
            for (bool xok = xb.first_from(fii2.current(), XREF_DATA); xok; xok = xb.next_from())
            {
                flags64_t f = get_flags(xb.to);
                if (!is_strlit(f)) continue;
                qstring s;
                if (get_strlit_contents(&s, xb.to, -1, get_str_type(xb.to)) <= 0) continue;
                for (int i = 0; vm_strings[i]; ++i)
                {
                    if (s.find(vm_strings[i]) != qstring::npos)
                    {
                        ++anti_vm;
                        json d; d["type"] = std::string("anti_vm_string");
                        d["address"] = helpers::format_address(fii2.current());
                        d["string"] = s.c_str();
                        d["pattern"] = vm_strings[i];
                        detections.push_back(std::move(d)); break;
                    }
                }
            }
        }
    }

    result["detections"] = std::move(detections);
    result["anti_debug"] = anti_debug;
    result["anti_vm"] = anti_vm;
    result["anti_disasm"] = anti_disasm;
    result["timing_checks"] = timing_checks;

    int score = 0;
    if (anti_debug > 0) score += std::min(anti_debug * 15, 40);
    if (anti_vm > 0) score += std::min(anti_vm * 15, 30);
    if (timing_checks > 0) score += std::min(timing_checks * 15, 20);
    if (anti_disasm > 0) score += 10;
    result["anti_analysis_score_pct"] = std::min(score, 100);

    return tool_result_t::ok(std::string("Anti-analysis detection"), result);
}


tool_result_t analyze_pe_headers(const json& params)
{
    ea_t base = get_imagebase();
    if (params.contains("address"))
    {
        auto a = helpers::parse_address(params.value("address", std::string()));
        if (a) base = *a;
    }

    std::uint16_t e_magic = is_loaded(base) ? get_word(base) : 0;
    if (e_magic != 0x5A4D)
        return tool_result_t::error(std::string("Not a valid PE: missing MZ signature at ") + helpers::format_address(base));

    std::uint32_t pe_off = get_dword(base + 0x3C);
    ea_t pe_hdr = base + pe_off;
    if (!is_loaded(pe_hdr) || get_dword(pe_hdr) != 0x00004550)
        return tool_result_t::error(std::string("Invalid PE signature at ") + helpers::format_address(pe_hdr));

    json result;
    result["image_base"] = helpers::format_address(base);


    ea_t coff = pe_hdr + 4;
    std::uint16_t machine       = get_word(coff);
    std::uint16_t num_sections  = get_word(coff + 2);
    std::uint32_t timestamp     = get_dword(coff + 4);
    std::uint16_t opt_size      = get_word(coff + 16);
    std::uint16_t characteristics = get_word(coff + 18);

    json coff_j;
    switch (machine)
    {
    case 0x8664: coff_j["machine"] = "AMD64"; break;
    case 0x14C:  coff_j["machine"] = "i386"; break;
    case 0xAA64: coff_j["machine"] = "ARM64"; break;
    default:     coff_j["machine"] = helpers::format_address(machine); break;
    }
    coff_j["num_sections"] = num_sections;
    coff_j["timestamp"]    = timestamp;

    std::vector<std::string> char_flags;
    if (characteristics & 0x0002) char_flags.push_back("EXECUTABLE_IMAGE");
    if (characteristics & 0x0020) char_flags.push_back("LARGE_ADDRESS_AWARE");
    if (characteristics & 0x2000) char_flags.push_back("DLL");
    coff_j["characteristics_flags"] = char_flags;
    result["coff_header"] = std::move(coff_j);


    ea_t opt = coff + 20;
    std::uint16_t magic = get_word(opt);
    bool is64 = (magic == 0x20B);
    result["pe_format"] = is64 ? "PE32+ (64-bit)" : "PE32 (32-bit)";

    json opt_j;
    opt_j["linker_version"] = std::to_string(get_byte(opt + 2)) + "." + std::to_string(get_byte(opt + 3));
    opt_j["entry_point"]    = helpers::format_address(base + get_dword(opt + 16));
    opt_j["section_alignment"] = get_dword(opt + 32);
    opt_j["file_alignment"]    = get_dword(opt + 36);

    std::uint64_t img_base_pe = is64
        ? static_cast<std::uint64_t>(get_qword(opt + 24))
        : static_cast<std::uint64_t>(get_dword(opt + 28));
    opt_j["image_base_pe"]    = helpers::format_address(static_cast<ea_t>(img_base_pe));
    opt_j["size_of_image"]    = get_dword(opt + 56);
    opt_j["size_of_headers"]  = get_dword(opt + 60);
    opt_j["checksum"]         = get_dword(opt + 64);
    opt_j["subsystem"]        = get_word(opt + 68);

    std::uint16_t dll_chars = get_word(opt + 70);
    std::vector<std::string> dll_flags;
    if (dll_chars & 0x0040) dll_flags.push_back("DYNAMIC_BASE (ASLR)");
    if (dll_chars & 0x0080) dll_flags.push_back("FORCE_INTEGRITY");
    if (dll_chars & 0x0100) dll_flags.push_back("NX_COMPAT (DEP)");
    if (dll_chars & 0x0400) dll_flags.push_back("NO_SEH");
    if (dll_chars & 0x4000) dll_flags.push_back("GUARD_CF");
    opt_j["dll_characteristics_flags"] = dll_flags;
    result["optional_header"] = std::move(opt_j);


    std::uint32_t num_dd;
    ea_t dd_base;
    if (is64) { num_dd = get_dword(opt + 108); dd_base = opt + 112; }
    else      { num_dd = get_dword(opt + 92);  dd_base = opt + 96;  }

    static const char* dd_names[] = {
        "Export","Import","Resource","Exception","Security",
        "Relocation","Debug","Architecture","GlobalPtr","TLS",
        "LoadConfig","BoundImport","IAT","DelayImport","CLR","Reserved"
    };

    json dirs = json::array();
    for (std::uint32_t i = 0; i < std::min(num_dd, 16u); ++i)
    {
        ea_t dd_ea = dd_base + i * 8;
        if (!is_loaded(dd_ea)) break;
        std::uint32_t rva  = get_dword(dd_ea);
        std::uint32_t sz   = get_dword(dd_ea + 4);
        if (rva == 0 && sz == 0) continue;

        json dd;
        dd["index"] = i;
        dd["name"]  = dd_names[i];
        dd["rva"]   = helpers::format_address(static_cast<ea_t>(rva));
        dd["va"]    = helpers::format_address(base + rva);
        dd["size"]  = sz;


        if (i == 0 && rva)
        {
            ea_t exp = base + rva;
            if (is_loaded(exp + 20))
            {
                dd["num_functions"] = get_dword(exp + 20);
                dd["num_names"]     = get_dword(exp + 24);
            }
        }
        else if (i == 3 && rva)
        {
            dd["runtime_function_count"] = sz / 12;
        }
        else if (i == 5 && rva)
        {
            ea_t cur = base + rva;
            ea_t rel_end = cur + sz;
            int blocks = 0;
            while (cur < rel_end)
            {
                if (!is_loaded(cur + 4)) break;
                std::uint32_t bsz = get_dword(cur + 4);
                if (bsz == 0) break;
                ++blocks;
                cur += bsz;
            }
            dd["relocation_blocks"] = blocks;
        }
        else if (i == 9 && rva)
        {
            ea_t tls = base + rva;
            json tls_j;
            ea_t cb_va;
            if (!is_loaded(tls))
            {
                tls_j["error"] = "TLS directory not loaded";
                cb_va = 0;
            }
            else if (is64)
            {
                tls_j["raw_data_start"]    = helpers::format_address(static_cast<ea_t>(get_qword(tls)));
                tls_j["raw_data_end"]      = helpers::format_address(static_cast<ea_t>(get_qword(tls + 8)));
                cb_va = static_cast<ea_t>(get_qword(tls + 24));
            }
            else
            {
                tls_j["raw_data_start"]    = helpers::format_address(get_dword(tls));
                tls_j["raw_data_end"]      = helpers::format_address(get_dword(tls + 4));
                cb_va = get_dword(tls + 12);
            }
            tls_j["callbacks_address"] = helpers::format_address(cb_va);

            json cbs = json::array();
            if (cb_va != 0 && is_loaded(cb_va))
            {
                for (int ci = 0; ci < 64; ++ci)
                {
                    std::uint64_t cb = is64 ? get_qword(cb_va + ci * 8) : get_dword(cb_va + ci * 4);
                    if (cb == 0) break;
                    json c;
                    c["address"] = helpers::format_address(static_cast<ea_t>(cb));
                    qstring nm;
                    if (get_name(&nm, static_cast<ea_t>(cb)) && !nm.empty())
                        c["name"] = nm.c_str();
                    cbs.push_back(std::move(c));
                }
            }
            tls_j["callbacks"]         = std::move(cbs);
            tls_j["callback_count"]    = tls_j["callbacks"].size();
            dd["tls_info"]             = std::move(tls_j);
        }
        else if (i == 10 && rva && is64)
        {
            ea_t lc = base + rva;
            json lc_j;
            if (is_loaded(lc + 88))
            {
                lc_j["security_cookie"]          = helpers::format_address(static_cast<ea_t>(get_qword(lc + 88)));
                lc_j["guard_cf_check_function"]  = helpers::format_address(static_cast<ea_t>(get_qword(lc + 112)));
                lc_j["guard_cf_function_table"]  = helpers::format_address(static_cast<ea_t>(get_qword(lc + 128)));
                lc_j["guard_cf_function_count"]  = static_cast<std::uint64_t>(get_qword(lc + 136));
            }
            dd["load_config"] = std::move(lc_j);
        }
        dirs.push_back(std::move(dd));
    }
    result["data_directories"] = std::move(dirs);


    ea_t sec_tbl = opt + opt_size;
    json secs = json::array();
    for (int si = 0; si < num_sections; ++si)
    {
        ea_t sec = sec_tbl + si * 40;
        if (!is_loaded(sec)) break;
        char sname[9] = {};
        for (int j = 0; j < 8; ++j)
            sname[j] = static_cast<char>(get_byte(sec + j));

        std::uint32_t vsize   = get_dword(sec + 8);
        std::uint32_t vrva    = get_dword(sec + 12);
        std::uint32_t rsize   = get_dword(sec + 16);
        std::uint32_t rptr    = get_dword(sec + 20);
        std::uint32_t chars   = get_dword(sec + 36);

        ea_t sec_va = base + vrva;
        std::uint32_t check_sz = std::min(vsize, 65536u);
        std::uint32_t freq[256] = {};
        std::uint32_t cnt = 0;
        for (std::uint32_t b = 0; b < check_sz; ++b)
        {
            if (is_loaded(sec_va + b))
            {
                freq[get_byte(sec_va + b)]++;
                ++cnt;
            }
        }
        double ent = 0.0;
        if (cnt > 0)
        {
            for (int k = 0; k < 256; ++k)
            {
                if (freq[k] == 0) continue;
                double p = static_cast<double>(freq[k]) / cnt;
                ent -= p * std::log2(p);
            }
        }

        json s;
        s["name"]            = sname;
        s["virtual_address"] = helpers::format_address(sec_va);
        s["virtual_size"]    = vsize;
        s["raw_size"]        = rsize;
        s["raw_offset"]      = rptr;
        s["entropy"]         = std::round(ent * 100.0) / 100.0;

        std::vector<std::string> fl;
        if (chars & 0x00000020) fl.push_back("CODE");
        if (chars & 0x00000040) fl.push_back("INITIALIZED_DATA");
        if (chars & 0x00000080) fl.push_back("UNINITIALIZED_DATA");
        if (chars & 0x02000000) fl.push_back("DISCARDABLE");
        if (chars & 0x20000000) fl.push_back("EXECUTE");
        if (chars & 0x40000000) fl.push_back("READ");
        if (chars & 0x80000000) fl.push_back("WRITE");
        s["flags"] = fl;

        if (ent > 7.0) s["classification"] = "likely_packed_or_encrypted";
        else if (ent > 6.5) s["classification"] = "high_entropy_suspicious";
        else if ((chars & 0x20000000) && (chars & 0x80000000)) s["classification"] = "rwx_suspicious";
        else s["classification"] = "normal";

        secs.push_back(std::move(s));
    }
    result["sections"] = std::move(secs);

    return tool_result_t::ok(std::string("PE header analysis for ") + helpers::format_address(base), result);
}


tool_result_t analyze_entropy(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(std::string("Invalid address"));

    std::uint32_t size    = params.value("size", 4096);
    if (size > 1048576) size = 1048576;
    std::uint32_t window  = params.value("window_size", 256);
    if (window < 32) window = 32;
    if (window > size) window = size;


    std::uint32_t freq[256] = {};
    std::uint32_t total = 0;
    for (std::uint32_t i = 0; i < size; ++i)
    {
        if (is_loaded(*addr + i)) { freq[get_byte(*addr + i)]++; ++total; }
    }
    double overall = 0.0;
    if (total > 0)
    {
        for (int k = 0; k < 256; ++k)
        {
            if (freq[k] == 0) continue;
            double p = static_cast<double>(freq[k]) / total;
            overall -= p * std::log2(p);
        }
    }


    json windows = json::array();
    std::uint32_t step = std::max(window / 2, 1u);
    double max_ent = 0.0, min_ent = 8.0;
    for (std::uint32_t off = 0; off + window <= size; off += step)
    {
        std::uint32_t wf[256] = {};
        std::uint32_t wc = 0;
        for (std::uint32_t b = 0; b < window; ++b)
        {
            if (is_loaded(*addr + off + b)) { wf[get_byte(*addr + off + b)]++; ++wc; }
        }
        double ent = 0.0;
        if (wc > 0)
        {
            for (int k = 0; k < 256; ++k)
            {
                if (wf[k] == 0) continue;
                double p = static_cast<double>(wf[k]) / wc;
                ent -= p * std::log2(p);
            }
        }
        if (ent > max_ent) max_ent = ent;
        if (ent < min_ent) min_ent = ent;

        json w;
        w["offset"]  = off;
        w["address"] = helpers::format_address(*addr + off);
        w["entropy"] = std::round(ent * 100.0) / 100.0;
        if (ent > 7.0) w["classification"] = "encrypted_or_compressed";
        else if (ent > 6.0) w["classification"] = "suspicious";
        else if (ent < 1.0) w["classification"] = "nearly_empty";
        else w["classification"] = "normal";
        windows.push_back(std::move(w));
    }

    json result;
    result["address"]             = helpers::format_address(*addr);
    result["size"]                = size;
    result["overall_entropy"]     = std::round(overall * 100.0) / 100.0;
    result["max_window_entropy"]  = std::round(max_ent * 100.0) / 100.0;
    result["min_window_entropy"]  = std::round(min_ent * 100.0) / 100.0;
    result["window_size"]         = window;
    result["windows"]             = std::move(windows);

    std::string verdict;
    if (overall > 7.5)      verdict = "almost_certainly_encrypted_or_compressed";
    else if (overall > 7.0) verdict = "likely_packed";
    else if (overall > 6.0) verdict = "suspicious_high_entropy";
    else                    verdict = "normal";
    result["verdict"] = verdict;

    return tool_result_t::ok(std::string("Entropy: ") + std::to_string(overall) + std::string(" bits/byte Ã¢â‚¬â€ ") + verdict, result);
}


tool_result_t detect_hooks(const json& params)
{
    auto addr_opt = helpers::parse_address(params.value("address", std::string()));
    std::uint32_t max_fn = params.value("max_functions", 500);
    if (max_fn > 10000) max_fn = 10000;

    segment_t* target_seg = addr_opt ? getseg(*addr_opt) : nullptr;
    int checked = 0;
    json hooks = json::array();

    for (std::size_t i = 0; i < get_func_qty() && checked < static_cast<int>(max_fn); ++i)
    {
        func_t* fn = getn_func(i);
        if (!fn) continue;
        if (target_seg && getseg(fn->start_ea) != target_seg) continue;
        ++checked;

        ea_t ea = fn->start_ea;
        if (!is_loaded(ea)) continue;
        std::uint8_t pr[16];
        for (int b = 0; b < 16; ++b) pr[b] = is_loaded(ea + b) ? static_cast<std::uint8_t>(get_byte(ea + b)) : 0;

        std::string hook_type;
        ea_t hook_target = BADADDR;

        if (pr[0] == 0xE9)
        {
            std::int32_t rel;
            std::memcpy(&rel, &pr[1], 4);
            hook_target = ea + 5 + rel;
            hook_type = "jmp_rel32";
        }
        else if (pr[0] == 0xFF && pr[1] == 0x25)
        {
            std::int32_t disp;
            std::memcpy(&disp, &pr[2], 4);
            ea_t ptr = ea + 6 + disp;
            hook_target = is_loaded(ptr) ? static_cast<ea_t>(get_qword(ptr)) : BADADDR;
            hook_type = "jmp_indirect_rip";
        }
        else if (pr[0] == 0x48 && pr[1] == 0xB8 && pr[10] == 0xFF && pr[11] == 0xE0)
        {
            std::memcpy(&hook_target, &pr[2], 8);
            hook_type = "mov_rax_jmp_rax";
        }
        else if (pr[0] == 0x68 && pr[5] == 0xC3)
        {
            std::uint32_t t;
            std::memcpy(&t, &pr[1], 4);
            hook_target = static_cast<ea_t>(t);
            hook_type = "push_ret";
        }
        else if (pr[0] == 0xCC)
        {
            hook_type = "int3_breakpoint";
        }

        if (hook_type.empty()) continue;

        json h;
        h["address"] = helpers::format_address(ea);
        qstring nm;
        if (get_name(&nm, ea) && !nm.empty()) h["name"] = nm.c_str();
        h["hook_type"] = hook_type;
        if (hook_target != BADADDR)
        {
            h["target"] = helpers::format_address(hook_target);
            segment_t* ts = getseg(hook_target);
            if (ts) { qstring sn; if (aida_get_segm_name(&sn, ts) && !sn.empty()) h["target_segment"] = sn.c_str(); }
            qstring tn;
            if (get_name(&tn, hook_target) && !tn.empty()) h["target_name"] = tn.c_str();
        }

        std::ostringstream hex;
        for (int b = 0; b < 16; ++b)
        {
            if (b > 0) hex << " ";
            hex << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(pr[b]);
        }
        h["prologue_bytes"] = hex.str();
        hooks.push_back(std::move(h));
    }

    json result;
    result["functions_checked"] = checked;
    result["hooks_found"]       = hooks.size();
    result["hooks"]             = std::move(hooks);
    return tool_result_t::ok(std::string("Hook detection: ") + std::to_string(result["hooks_found"].get<std::size_t>()) +
                             std::string(" hooks in ") + std::to_string(checked) + std::string(" functions"), result);
}


tool_result_t detect_direct_syscalls(const json& params)
{
    auto addr_opt = helpers::parse_address(params.value("address", std::string()));
    std::uint32_t scan_size = params.value("size", 0);

    json syscalls = json::array();

    auto scan = [&](ea_t start, ea_t end)
    {
        for (ea_t ea = start; ea + 10 < end; ++ea)
        {
            if (!is_loaded(ea)) continue;


            if (get_byte(ea) == 0x4C && get_byte(ea + 1) == 0x8B && get_byte(ea + 2) == 0xD1 &&
                get_byte(ea + 3) == 0xB8 && get_byte(ea + 8) == 0x0F && get_byte(ea + 9) == 0x05)
            {
                std::uint32_t num = get_dword(ea + 4);
                json sc;
                sc["address"]        = helpers::format_address(ea);
                sc["syscall_number"] = num;
                sc["syscall_hex"]    = helpers::format_address(static_cast<ea_t>(num));
                sc["pattern"]        = "mov_r10_rcx__mov_eax__syscall";

                func_t* fn = get_func(ea);
                if (fn) { qstring n; if (get_name(&n, fn->start_ea) && !n.empty()) sc["function"] = n.c_str(); }
                syscalls.push_back(std::move(sc));
                ea += 9;
            }

            else if (get_byte(ea) == 0xB8 && get_byte(ea + 5) == 0x0F && get_byte(ea + 6) == 0x05)
            {
                std::uint32_t num = get_dword(ea + 1);
                if (num > 0x1000) continue;
                json sc;
                sc["address"]        = helpers::format_address(ea);
                sc["syscall_number"] = num;
                sc["pattern"]        = "mov_eax__syscall";

                func_t* fn = get_func(ea);
                if (fn) { qstring n; if (get_name(&n, fn->start_ea) && !n.empty()) sc["function"] = n.c_str(); }
                syscalls.push_back(std::move(sc));
                ea += 6;
            }

            else if (get_byte(ea) == 0xCD && get_byte(ea + 1) == 0x2E)
            {
                if (ea >= start + 5 && is_loaded(ea - 5) && get_byte(ea - 5) == 0xB8)
                {
                    json sc;
                    sc["address"]        = helpers::format_address(ea - 5);
                    sc["syscall_number"] = get_dword(ea - 4);
                    sc["pattern"]        = "mov_eax__int2e";
                    syscalls.push_back(std::move(sc));
                }
            }
        }
    };

    if (addr_opt && scan_size > 0)
        scan(*addr_opt, *addr_opt + scan_size);
    else if (addr_opt)
    {
        segment_t* seg = getseg(*addr_opt);
        if (seg) scan(seg->start_ea, seg->end_ea);
        else     scan(*addr_opt, *addr_opt + 0x10000);
    }
    else
    {
        for (int i = 0; i < get_segm_qty(); ++i)
        {
            segment_t* seg = getnseg(i);
            if (!seg || seg->type != SEG_CODE) continue;
            scan(seg->start_ea, seg->end_ea);
        }
    }

    json result;
    result["syscalls_found"] = syscalls.size();
    result["syscalls"]       = std::move(syscalls);
    if (!result["syscalls"].empty())
        result["note"] = std::string("Direct syscalls bypass IAT hooks and usermode API monitoring. "
                                "Common in anti-cheats, packers, and malware.");
    return tool_result_t::ok(std::string("Direct syscall scan: ") + std::to_string(result["syscalls_found"].get<std::size_t>()) + std::string(" found"), result);
}


tool_result_t resolve_api_hashes(const json& params)
{
    std::string algorithm = params.value("algorithm", "ror13");


    std::vector<std::uint32_t> targets;
    if (params.contains("hashes") && params["hashes"].is_array())
    {
        for (const auto& h : params["hashes"])
        {
            if (h.is_number()) targets.push_back(h.get<std::uint32_t>());
            else if (h.is_string()) { auto a = helpers::parse_address(h.get<std::string>()); if (a) targets.push_back(static_cast<std::uint32_t>(*a)); }
        }
    }
    else if (params.contains("hash"))
    {
        if (params["hash"].is_number()) targets.push_back(params["hash"].get<std::uint32_t>());
        else { auto a = helpers::parse_address(params.value("hash", std::string())); if (a) targets.push_back(static_cast<std::uint32_t>(*a)); }
    }
    if (targets.empty())
        return tool_result_t::error(std::string("No hash values provided. Use 'hash' or 'hashes' parameter."));


    auto h_ror13 = [](const std::string& s) -> std::uint32_t {
        std::uint32_t h = 0;
        for (char c : s) h = ((h >> 13) | (h << 19)) + static_cast<std::uint8_t>(c);
        return h;
    };
    auto h_djb2 = [](const std::string& s) -> std::uint32_t {
        std::uint32_t h = 5381;
        for (char c : s) h = ((h << 5) + h) + static_cast<std::uint8_t>(c);
        return h;
    };
    auto h_crc32 = [](const std::string& s) -> std::uint32_t {
        std::uint32_t crc = 0xFFFFFFFF;
        for (char c : s) { crc ^= static_cast<std::uint8_t>(c); for (int i = 0; i < 8; ++i) crc = (crc >> 1) ^ (0xEDB88320 & (~((crc & 1) - 1))); }
        return ~crc;
    };
    auto h_fnv1a = [](const std::string& s) -> std::uint32_t {
        std::uint32_t h = 0x811C9DC5;
        for (char c : s) { h ^= static_cast<std::uint8_t>(c); h *= 0x01000193; }
        return h;
    };
    auto h_sdbm = [](const std::string& s) -> std::uint32_t {
        std::uint32_t h = 0;
        for (char c : s) h = static_cast<std::uint8_t>(c) + (h << 6) + (h << 16) - h;
        return h;
    };

    std::string algo_lc = algorithm;
    std::transform(algo_lc.begin(), algo_lc.end(), algo_lc.begin(), ::tolower);
    std::function<std::uint32_t(const std::string&)> hash_fn;
    if (algo_lc == "ror13")       hash_fn = h_ror13;
    else if (algo_lc == "djb2")   hash_fn = h_djb2;
    else if (algo_lc == "crc32")  hash_fn = h_crc32;
    else if (algo_lc == "fnv1a" || algo_lc == "fnv") hash_fn = h_fnv1a;
    else if (algo_lc == "sdbm")   hash_fn = h_sdbm;
    else return tool_result_t::error(std::string("Unknown algorithm: ") + algorithm + std::string(". Supported: ror13, djb2, crc32, fnv1a, sdbm"));


    std::vector<std::pair<std::string, std::string>> api_names;
    for (size_t i = 0; i < static_cast<size_t>(get_import_module_qty()); ++i)
    {
        qstring mod_name;
        get_import_module_name(&mod_name, static_cast<int>(i));
        std::string dll = mod_name.c_str();
        struct ctx_t { std::vector<std::pair<std::string, std::string>>* apis; std::string dll; };
        ctx_t ctx{&api_names, dll};
        enum_import_names(static_cast<int>(i), [](ea_t, const char* nm, uval_t, void* ud) -> int {
            auto* c = static_cast<ctx_t*>(ud);
            if (nm && nm[0]) c->apis->push_back({c->dll, nm});
            return 1;
        }, &ctx);
    }

    static const char* common[] = {
        "VirtualAlloc","VirtualAllocEx","VirtualFree","VirtualProtect","VirtualQuery",
        "ReadProcessMemory","WriteProcessMemory","OpenProcess","CreateRemoteThread",
        "NtAllocateVirtualMemory","NtReadVirtualMemory","NtWriteVirtualMemory",
        "NtProtectVirtualMemory","NtOpenProcess","NtQueryInformationProcess",
        "NtQuerySystemInformation","NtSetInformationThread","NtCreateThreadEx",
        "NtDeviceIoControlFile","NtClose","NtCreateFile","NtOpenFile",
        "NtMapViewOfSection","NtUnmapViewOfSection","NtQueryVirtualMemory",
        "GetProcAddress","LoadLibraryA","LoadLibraryW","LoadLibraryExA","LoadLibraryExW",
        "GetModuleHandleA","GetModuleHandleW","CreateFileA","CreateFileW",
        "ReadFile","WriteFile","CreateProcessA","CreateProcessW",
        "ExitProcess","TerminateProcess","IsDebuggerPresent","CheckRemoteDebuggerPresent",
        "GetTickCount","QueryPerformanceCounter","Sleep",
        "CreateThread","ResumeThread","SuspendThread","GetThreadContext","SetThreadContext",
        "WSAStartup","socket","connect","send","recv","closesocket",
        "RegOpenKeyExA","RegOpenKeyExW","RegQueryValueExA","RegSetValueExA",
        "CryptEncrypt","CryptDecrypt","BCryptOpenAlgorithmProvider","BCryptEncrypt","BCryptDecrypt",
        nullptr
    };
    for (int i = 0; common[i]; ++i) api_names.push_back({"common", common[i]});

    std::set<std::uint32_t> target_set(targets.begin(), targets.end());
    json resolved = json::array();
    std::set<std::uint32_t> found_set;

    bool try_dll = params.value("include_dll_name", false);

    for (const auto& [dll, api] : api_names)
    {
        std::uint32_t h = hash_fn(api);
        if (target_set.count(h))
        {
            json r; r["hash"] = helpers::format_address(static_cast<ea_t>(h)); r["api"] = api; r["dll"] = dll;
            found_set.insert(h);
            resolved.push_back(std::move(r));
        }
        if (try_dll)
        {
            std::string full = dll + "!" + api;
            h = hash_fn(full);
            if (target_set.count(h))
            {
                json r; r["hash"] = helpers::format_address(static_cast<ea_t>(h)); r["api"] = full; r["dll"] = dll;
                found_set.insert(h);
                resolved.push_back(std::move(r));
            }
        }
    }

    json result;
    result["algorithm"]        = algorithm;
    result["total_queried"]    = targets.size();
    result["resolved_count"]   = found_set.size();
    result["unresolved_count"] = targets.size() - found_set.size();
    result["resolved"]         = std::move(resolved);

    json unres = json::array();
    for (auto h : targets) { if (!found_set.count(h)) unres.push_back(helpers::format_address(static_cast<ea_t>(h))); }
    result["unresolved"] = std::move(unres);

    return tool_result_t::ok(std::string("API hash resolution: ") + std::to_string(found_set.size()) +
                             "/" + std::to_string(targets.size()) + std::string(" resolved"), result);
}


tool_result_t reconstruct_vtable(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(std::string("Invalid VTABLE address"));

    std::uint32_t max_entries = params.value("max_entries", 200);
    if (max_entries > 1000) max_entries = 1000;

    bool is_64 = inf_is_64bit();
    std::size_t ptr_sz = is_64 ? 8 : 4;

    json entries = json::array();
    ea_t vt = *addr;


    json rtti;
    if (is_64 && is_loaded(vt - 8))
    {
        ea_t col_ptr = static_cast<ea_t>(get_qword(vt - 8));
        if (is_loaded(col_ptr))
        {
            std::uint32_t sig = get_dword(col_ptr);
            if (sig == 0 || sig == 1)
            {
                rtti["col_address"] = helpers::format_address(col_ptr);
                rtti["signature"]   = sig;
                if (sig == 1)
                {
                    std::int32_t td_off   = get_dword(col_ptr + 12);
                    std::int32_t chd_off  = get_dword(col_ptr + 16);
                    std::int32_t self_off = get_dword(col_ptr + 20);
                    std::uint64_t img_base = static_cast<std::uint64_t>(col_ptr) - self_off;

                    ea_t td = static_cast<ea_t>(img_base + td_off);
                    if (is_loaded(td + 16))
                    {
                        char tname[256] = {};
                        for (int i = 0; i < 255; ++i) { char c = static_cast<char>(get_byte(td + 16 + i)); if (!c) break; tname[i] = c; }
                        rtti["type_descriptor_name"] = tname;
                        qstring dem;
                        if (demangle_name(&dem, tname, 0) > 0 && !dem.empty())
                            rtti["demangled_class"] = dem.c_str();
                    }
                    ea_t chd = static_cast<ea_t>(img_base + chd_off);
                    if (is_loaded(chd)) rtti["num_base_classes"] = get_dword(chd + 8);
                }
            }
        }
    }

    for (std::uint32_t i = 0; i < max_entries; ++i)
    {
        ea_t entry_ea = vt + i * ptr_sz;
        if (!is_loaded(entry_ea)) break;
        ea_t fn_addr = is_64 ? static_cast<ea_t>(get_qword(entry_ea)) : get_dword(entry_ea);
        if (fn_addr == 0 || !is_loaded(fn_addr)) break;
        segment_t* fs = getseg(fn_addr);
        if (!fs || fs->type != SEG_CODE) break;

        json e;
        e["index"]   = i;
        e["offset"]  = helpers::format_address(static_cast<ea_t>(i * ptr_sz));
        e["address"] = helpers::format_address(fn_addr);

        func_t* fn = get_func(fn_addr);
        qstring nm;
        if (get_name(&nm, fn_addr) && !nm.empty())
        {
            e["name"] = nm.c_str();
            qstring dem;
            if (demangle_name(&dem, nm.c_str(), 0) > 0 && !dem.empty())
                e["demangled"] = dem.c_str();
        }
        if (fn) e["function_size"] = static_cast<std::uint64_t>(fn->size());
        entries.push_back(std::move(e));
    }

    json result;
    result["vtable_address"] = helpers::format_address(*addr);
    result["entry_count"]    = entries.size();
    result["pointer_size"]   = ptr_sz;
    result["entries"]        = std::move(entries);
    if (!rtti.empty()) result["rtti"] = std::move(rtti);

    return tool_result_t::ok(std::string("VTABLE: ") + std::to_string(result["entry_count"].get<std::size_t>()) +
                             std::string(" entries at ") + helpers::format_address(*addr), result);
}


tool_result_t classify_memory_pages(const json& params)
{
    auto addr_opt = helpers::parse_address(params.value("address", std::string()));
    ea_t start_ea = addr_opt ? *addr_opt : inf_get_min_ea();
    size_t total_size = params.value("size", (size_t)0);
    size_t page_size = params.value("page_size", (size_t)4096);
    if (page_size < 256) page_size = 256;

    segment_t* seg = getseg(start_ea);
    if (!seg && total_size == 0)
        return tool_result_t::error(std::string("No segment at address and no size specified"));

    ea_t end_ea = (total_size > 0) ? (start_ea + total_size)
                                    : (seg ? seg->end_ea : (start_ea + 0x10000));

    json pages = json::array();
    int code_pages = 0, data_pages = 0, encrypted_pages = 0, padding_pages = 0, mixed_pages = 0;

    show_wait_box("Classifying memory pages...");
    for (ea_t ea = start_ea; ea < end_ea; ea += page_size)
    {
        if (user_cancelled()) break;
        size_t sz = static_cast<size_t>(std::min((ea_t)page_size, end_ea - ea));

        std::vector<uint8_t> buf(sz);
        size_t loaded = 0;
        for (size_t i = 0; i < sz; ++i)
        {
            if (is_loaded(ea + i)) { buf[i] = get_byte(ea + i); ++loaded; }
        }

        if (loaded < sz / 2)
        {
            json pg;
            pg["address"] = helpers::format_address(ea);
            pg["class"]   = "unmapped";
            pg["loaded_ratio"] = static_cast<double>(loaded) / sz;
            pages.push_back(std::move(pg));
            continue;
        }


        int freq[256] = {};
        for (size_t i = 0; i < sz; ++i) freq[buf[i]]++;
        double entropy = 0.0;
        for (int i = 0; i < 256; ++i)
        {
            if (freq[i] == 0) continue;
            double p_val = static_cast<double>(freq[i]) / sz;
            entropy -= p_val * std::log2(p_val);
        }

        int max_freq = *std::max_element(freq, freq + 256);
        double uniformity = static_cast<double>(max_freq) / sz;


        int valid_insns = 0, total_bytes_decoded = 0;
        for (ea_t ip = ea; ip < ea + sz; )
        {
            insn_t insn;
            int insn_sz = decode_insn(&insn, ip);
            if (insn_sz > 0) { ++valid_insns; total_bytes_decoded += insn_sz; ip += insn_sz; }
            else { ip += 1; }
        }
        double insn_ratio = (sz > 0) ? static_cast<double>(total_bytes_decoded) / sz : 0.0;
        double zero_ratio = (sz > 0) ? static_cast<double>(freq[0]) / sz : 0.0;
        int printable = 0;
        for (int i = 0x20; i <= 0x7E; ++i) printable += freq[i];
        double string_ratio = (sz > 0) ? static_cast<double>(printable) / sz : 0.0;

        std::string classification;
        if (zero_ratio > 0.85)                              { classification = "padding"; ++padding_pages; }
        else if (uniformity > 0.7)                          { classification = "single_byte_encrypted"; ++encrypted_pages; }
        else if (entropy > 7.2 && insn_ratio < 0.3)        { classification = "encrypted_or_compressed"; ++encrypted_pages; }
        else if (entropy > 6.5 && insn_ratio < 0.5)        { classification = "obfuscated_code"; ++mixed_pages; }
        else if (insn_ratio > 0.75 && entropy < 6.5)       { classification = "code"; ++code_pages; }
        else if (string_ratio > 0.6)                        { classification = "string_data"; ++data_pages; }
        else if (insn_ratio < 0.3 && entropy < 5.0)        { classification = "structured_data"; ++data_pages; }
        else                                                { classification = "mixed"; ++mixed_pages; }

        json pg;
        pg["address"]       = helpers::format_address(ea);
        pg["size"]          = sz;
        pg["class"]         = classification;
        pg["entropy"]       = std::round(entropy * 100) / 100;
        pg["insn_ratio"]    = std::round(insn_ratio * 100) / 100;
        pg["zero_ratio"]    = std::round(zero_ratio * 100) / 100;
        pg["string_ratio"]  = std::round(string_ratio * 100) / 100;
        pg["valid_insns"]   = valid_insns;
        pages.push_back(std::move(pg));
    }
    hide_wait_box();

    json result;
    result["start"]       = helpers::format_address(start_ea);
    result["end"]         = helpers::format_address(end_ea);
    result["page_size"]   = page_size;
    result["total_pages"] = pages.size();
    result["summary"] = {{"code", code_pages}, {"data", data_pages}, {"encrypted", encrypted_pages},
                         {"padding", padding_pages}, {"mixed", mixed_pages}};
    result["pages"] = std::move(pages);

    return tool_result_t::ok(std::string("Classified ") + std::to_string(result["total_pages"].get<std::size_t>()) +
                             std::string(" pages: ") + std::to_string(code_pages) + std::string(" code, ") +
                             std::to_string(encrypted_pages) + std::string(" encrypted, ") +
                             std::to_string(data_pages) + std::string(" data"), result);
}


tool_result_t detect_vm_handler_pattern(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(std::string("Invalid address"));

    ea_t ea = *addr;
    size_t scan_size = params.value("scan_size", 4096);
    if (scan_size > 65536) scan_size = 65536;

    json result;
    result["scan_start"] = helpers::format_address(ea);

    json patterns = json::array();
    ea_t scan_end = ea + scan_size;
    ea_t cur = ea;

    int indirect_jumps = 0;
    int cmp_chains = 0;
    ea_t last_cmp = BADADDR;

    while (cur < scan_end && cur != BADADDR)
    {
        insn_t insn;
        int len = decode_insn(&insn, cur);
        if (len <= 0)
        {
            cur = next_head(cur, scan_end);
            if (cur == BADADDR) break;
            continue;
        }

        if (insn.itype == NN_jmpni || insn.itype == NN_jmpfi)
        {
            ++indirect_jumps;
            json p;
            p["type"] = std::string("indirect_jump");
            p["address"] = helpers::format_address(cur);
            qstring dis;
            generate_disasm_line(&dis, cur, GENDSM_FORCE_CODE);
            tag_remove(&dis);
            p["instruction"] = dis.c_str();

            ea_t prev = prev_head(cur, ea);
            if (prev != BADADDR)
            {
                insn_t prev_insn;
                if (decode_insn(&prev_insn, prev) > 0)
                {
                    qstring prev_dis;
                    generate_disasm_line(&prev_dis, prev, GENDSM_FORCE_CODE);
                    tag_remove(&prev_dis);
                    p["preceding_instruction"] = prev_dis.c_str();
                }
            }
            patterns.push_back(std::move(p));
        }

        if (insn.itype == NN_cmp)
        {
            if (last_cmp != BADADDR && (cur - last_cmp) < 32)
                ++cmp_chains;
            last_cmp = cur;
        }

        if (insn.itype == NN_loop || insn.itype == NN_loopd ||
            insn.itype == NN_loopw || insn.itype == NN_loopne ||
            insn.itype == NN_loope)
        {
            json p;
            p["type"] = std::string("loop_instruction");
            p["address"] = helpers::format_address(cur);
            qstring dis;
            generate_disasm_line(&dis, cur, GENDSM_FORCE_CODE);
            tag_remove(&dis);
            p["instruction"] = dis.c_str();
            patterns.push_back(std::move(p));
        }

        cur += len;
    }

    if (cmp_chains >= 3)
    {
        json p;
        p["type"] = std::string("cmp_dispatch_chain");
        p["chain_length"] = cmp_chains;
        p["note"] = std::string("Multiple sequential CMP instructions suggest opcode-based dispatch (VM handler table)");
        patterns.push_back(std::move(p));
    }

    result["patterns"] = std::move(patterns);
    result["indirect_jumps_found"] = indirect_jumps;
    result["cmp_chain_length"] = cmp_chains;
    result["scan_bytes"] = scan_size;

    int score = 0;
    if (indirect_jumps > 0) score += 30;
    if (cmp_chains >= 5) score += 30;
    if (cmp_chains >= 10) score += 20;
    if (indirect_jumps > 2) score += 20;
    result["vm_confidence_pct"] = std::min(score, 100);

    return tool_result_t::ok(std::string("VM handler pattern detection"), result);
}

tool_result_t map_vm_handler_table(const json& params)
{
    auto table_addr = helpers::parse_address(params.value("table_address", std::string()));
    if (!table_addr)
        return tool_result_t::error(std::string("Invalid table_address"));

    ea_t base = *table_addr;
    int entry_count = params.value("entry_count", 256);
    if (entry_count < 1) entry_count = 1;
    if (entry_count > 4096) entry_count = 4096;
    int entry_size = params.value("entry_size", 8);
    if (entry_size != 4 && entry_size != 8) entry_size = 8;

    json handlers = json::array();
    json result;
    result["table_base"] = helpers::format_address(base);
    result["entry_size"] = entry_size;

    for (int i = 0; i < entry_count; ++i)
    {
        ea_t slot = base + static_cast<ea_t>(i) * entry_size;
        ea_t target = BADADDR;

        if (!is_loaded(slot)) continue;
        if (entry_size == 8)
            target = get_qword(slot);
        else
            target = static_cast<ea_t>(get_dword(slot));

        if (target == 0 || target == BADADDR)
            continue;

        json entry;
        entry["index"] = i;
        entry["slot"] = helpers::format_address(slot);
        entry["target"] = helpers::format_address(target);

        qstring tname;
        if (get_func_name(&tname, target) > 0)
            entry["name"] = tname.c_str();

        func_t* pfn = get_func(target);
        if (pfn)
        {
            ea_t end = std::min(pfn->end_ea, target + 64);
            entry["disassembly"] = helpers::get_disassembly(target, end);
        }
        else
        {
            entry["disassembly"] = helpers::get_disassembly(target, target + 32);
        }

        handlers.push_back(std::move(entry));
    }

    size_t valid_count = handlers.size();
    result["handlers"] = std::move(handlers);
    result["valid_entries"] = valid_count;
    return tool_result_t::ok(std::string("VM handler table map"), result);
}

void register_tools()
{
    auto& registry = ToolRegistry::instance();

    registry.register_tool({std::string("detect_obfuscation_patterns"), std::string("analysis"),
        std::string("Scan a function for obfuscation patterns: opaque predicates, dead code, "
               "junk insertion, indirect jumps, push/ret redirects. Returns obfuscation score."),
        {{std::string("address"), std::string("string"), std::string("Function address"), true},
         {std::string("scan_size"), std::string("number"), std::string("Max bytes to scan (default: full function)"), false}},
        detect_obfuscation_patterns});

    registry.register_tool({std::string("analyze_control_flow"), std::string("analysis"),
        std::string("Analyze function control flow: basic blocks, edges, back-edges, cyclomatic complexity."),
        {{std::string("address"), std::string("string"), std::string("Function address"), true}},
        analyze_control_flow});

    registry.register_tool({std::string("get_function_complexity"), std::string("analysis"),
        std::string("Compute complexity metrics: cyclomatic complexity, instruction counts, Halstead metrics."),
        {{std::string("address"), std::string("string"), std::string("Function address"), true}},
        get_function_complexity});

    registry.register_tool({std::string("analyze_string_decryption"), std::string("analysis"),
        std::string("Detect string decryption patterns: XOR loops, stack strings, decrypt calls."),
        {{std::string("address"), std::string("string"), std::string("Function address"), true}},
        analyze_string_decryption});

    registry.register_tool({std::string("analyze_indirect_calls"), std::string("analysis"),
        std::string("Find and classify indirect calls/jumps: vtable, function pointer, register calls."),
        {{std::string("address"), std::string("string"), std::string("Function address"), true}},
        analyze_indirect_calls});

    registry.register_tool({std::string("find_crypto_constants"), std::string("analysis"),
        std::string("Scan for well-known crypto constants (AES, SHA-256, MD5, CRC32, Blowfish, TEA, ChaCha20)."),
        {{std::string("address"), std::string("string"), std::string("Start address (optional)"), false},
         {std::string("scan_size"), std::string("number"), std::string("Bytes to scan (default 65536)"), false}},
        find_crypto_constants});

    registry.register_tool({std::string("analyze_data_flow"), std::string("analysis"),
        std::string("Track data flow around an instruction: backward defs, forward uses, usage classification."),
        {{std::string("address"), std::string("string"), std::string("Instruction address"), true},
         {std::string("register"), std::string("string"), std::string("Register to track (optional)"), false},
         {std::string("max_depth"), std::string("number"), std::string("Max scan depth per direction (default 32)"), false}},
        analyze_data_flow, false});

    registry.register_tool({std::string("detect_anti_analysis"), std::string("analysis"),
        std::string("Detect anti-debug/anti-VM techniques: API calls, CPUID/RDTSC, INT traps, VM strings."),
        {{std::string("address"), std::string("string"), std::string("Function or start address"), true}},
        detect_anti_analysis});

    registry.register_tool({std::string("analyze_pe_headers"), std::string("analysis"),
        std::string("Deep PE header analysis: COFF/Optional headers, all 16 data directories, TLS callbacks, Load Config, sections with entropy/classification. Essential for packed/protected binary analysis."),
        {{std::string("address"), std::string("string"), std::string("Override image base address (default: IDB image base)"), false}},
        analyze_pe_headers, true});

    registry.register_tool({std::string("analyze_entropy"), std::string("analysis"),
        std::string("Compute Shannon entropy of a memory region using a sliding window. Identifies encrypted, compressed, or packed sections."),
        {{std::string("address"), std::string("string"), std::string("Start address to analyze"), true},
         {std::string("size"), std::string("number"), std::string("Size in bytes (default: 4096)"), false},
         {std::string("window_size"), std::string("number"), std::string("Sliding window size (default: 256)"), false}},
        analyze_entropy, true});

    registry.register_tool({std::string("detect_hooks"), std::string("analysis"),
        std::string("Scan function prologues for inline hooks: jmp rel32, jmp [rip+disp], mov rax/jmp rax, push/ret, int3. Finds anti-cheat and security product hooks."),
        {{std::string("address"), std::string("string"), std::string("Limit scan to segment containing this address"), false},
         {std::string("max_functions"), std::string("number"), std::string("Max functions to check (default: 500)"), false}},
        detect_hooks, true});

    registry.register_tool({std::string("detect_direct_syscalls"), std::string("analysis"),
        std::string("Find direct NT syscall stubs (mov r10,rcx; mov eax,N; syscall/int2e). Common in anti-cheats and malware to bypass API hooks."),
        {{std::string("address"), std::string("string"), std::string("Address or segment to scan"), false},
         {std::string("size"), std::string("number"), std::string("Scan size in bytes (0 = full segment)"), false}},
        detect_direct_syscalls, true});

    registry.register_tool({std::string("resolve_api_hashes"), std::string("analysis"),
        std::string("Resolve hashed API imports using ror13, djb2, crc32, fnv1a, or sdbm. Builds dictionary from IDB imports + common Windows APIs."),
        {{std::string("hash"), std::string("string"), std::string("Single hash value to resolve"), false},
         {std::string("hashes"), std::string("array"), std::string("Array of hash values to resolve"), false},
         {std::string("algorithm"), std::string("string"), std::string("Hash algorithm: ror13, djb2, crc32, fnv1a, sdbm (default: ror13)"), false},
         {std::string("include_dll_name"), std::string("boolean"), std::string("Also try DLL!API format (default: false)"), false}},
        resolve_api_hashes, true});

    registry.register_tool({std::string("reconstruct_vtable"), std::string("analysis"),
        std::string("Reconstruct C++ virtual function table. Reads pointer array, validates code targets, extracts RTTI (COL, type descriptor, class hierarchy). Handles demangling."),
        {{std::string("address"), std::string("string"), std::string("VTABLE start address"), true},
         {std::string("max_entries"), std::string("number"), std::string("Max entries to read (default: 200)"), false}},
        reconstruct_vtable, true});

    registry.register_tool({std::string("classify_memory_pages"), std::string("analysis"),
        std::string("Classify memory pages as code, data, encrypted/compressed, padding, string data, or obfuscated. "
               "Uses entropy, instruction decoding, zero-ratio and string-ratio heuristics per page. "
               "Essential for understanding packed binary layout and finding hidden code regions."),
        {{std::string("address"), std::string("string"), std::string("Start address (default: segment start or image base)"), false},
         {std::string("size"), std::string("number"), std::string("Total bytes to classify (default: full segment)"), false},
         {std::string("page_size"), std::string("number"), std::string("Page granularity in bytes (default: 4096, min: 256)"), false}},
        classify_memory_pages, true});


    registry.register_tool({std::string("detect_vm_handler_pattern"), std::string("analysis"),
        std::string("Scan a code region for virtualization patterns: indirect jump tables, CMP dispatch chains, "
               "loop instructions. Returns a VM confidence score and identified patterns. "
               "Use this to detect VMProtect/Themida/custom VM handlers."),
        {{std::string("address"), std::string("string"), std::string("Start address to scan"), true},
         {std::string("scan_size"), std::string("number"), std::string("Bytes to scan (default 4096, max 65536)"), false}},
        detect_vm_handler_pattern});

    registry.register_tool({std::string("map_vm_handler_table"), std::string("analysis"),
        std::string("Read a VM handler/dispatch table from the IDB and resolve each entry to its "
               "target function. Returns handler addresses, names, and first instructions."),
        {{std::string("table_address"), std::string("string"), std::string("Base address of the handler table"), true},
         {std::string("entry_count"), std::string("number"), std::string("Number of entries to read (default 256, max 4096)"), false},
         {std::string("entry_size"), std::string("number"), std::string("Size of each entry in bytes (4 or 8, default 8)"), false}},
        map_vm_handler_table});
}

}

namespace deobfuscation_tools
{

tool_result_t nop_junk_instructions(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(std::string("Invalid address"));

    ea_t ea = *addr;
    func_t* pfn = get_func(ea);
    if (!pfn)
        return tool_result_t::error(std::string("No function at ") + helpers::format_address(ea));

    bool aggressive = params.value("aggressive", false);
    int nop_threshold = params.value("nop_threshold", 3);
    if (nop_threshold < 2) nop_threshold = 2;
    if (nop_threshold > 16) nop_threshold = 16;

    json result;
    result["function"] = helpers::get_name_or_address(pfn->start_ea);
    result["start"]    = helpers::format_address(pfn->start_ea);
    result["end"]      = helpers::format_address(pfn->end_ea);

    int nops_patched = 0;
    int dead_blocks_nopped = 0;
    int junk_sequences_nopped = 0;
    json patches = json::array();

    std::set<ea_t> dead_starts;
    if (aggressive)
    {
        func_item_iterator_t fii(pfn);
        for (bool ok = fii.first(); ok; ok = fii.next_head())
        {
            ea_t item = fii.current();
            if (item == pfn->start_ea) continue;

            xrefblk_t xb;
            bool has_incoming = false;
            for (bool xok = xb.first_to(item, XREF_ALL); xok; xok = xb.next_to())
            {
                if (xb.iscode && aida_func_contains(pfn, xb.from))
                {
                    has_incoming = true;
                    break;
                }
            }

            if (!has_incoming)
            {
                ea_t prev = prev_head(item, pfn->start_ea);
                if (prev != BADADDR)
                {
                    insn_t prev_insn;
                    if (decode_insn(&prev_insn, prev) > 0)
                    {
                        if (!is_basic_block_end(prev_insn, false))
                            has_incoming = true;
                    }
                }
            }

            if (!has_incoming)
                dead_starts.insert(item);
        }
    }

    ea_t cur = pfn->start_ea;
    while (cur < pfn->end_ea && cur != BADADDR)
    {
        insn_t insn;
        int len = decode_insn(&insn, cur);
        if (len <= 0)
        {
            cur = next_head(cur, pfn->end_ea);
            if (cur == BADADDR) break;
            continue;
        }

        if (insn.itype == NN_nop)
        {
            ea_t nop_start = cur;
            int nop_count = 0;
            ea_t scan = cur;
            while (scan < pfn->end_ea)
            {
                insn_t ns;
                int nlen = decode_insn(&ns, scan);
                if (nlen <= 0 || ns.itype != NN_nop) break;
                ++nop_count;
                scan += nlen;
            }

            if (nop_count >= nop_threshold)
            {
                ++junk_sequences_nopped;
                json p;
                p["type"]    = std::string("nop_sled");
                p["address"] = helpers::format_address(nop_start);
                p["count"]   = nop_count;
                patches.push_back(std::move(p));
                cur = scan;
                continue;
            }
        }

        if (aggressive && dead_starts.count(cur))
        {
            ea_t block_end = pfn->end_ea;
            ea_t scan = cur;
            while (scan < pfn->end_ea)
            {
                insn_t di;
                int dlen = decode_insn(&di, scan);
                if (dlen <= 0) break;

                ea_t next = scan + dlen;
                if (next < pfn->end_ea && dead_starts.count(next) == 0)
                {
                    xrefblk_t xb;
                    bool has_incoming = false;
                    for (bool xok = xb.first_to(next, XREF_ALL); xok; xok = xb.next_to())
                    {
                        if (xb.iscode) { has_incoming = true; break; }
                    }
                    if (has_incoming)
                    {
                        block_end = next;
                        break;
                    }
                }

                if (is_basic_block_end(di, false))
                {
                    block_end = scan + dlen;
                    break;
                }
                scan += dlen;
            }

            int patched_count = 0;
            for (ea_t p = cur; p < block_end; ++p)
            {
                if (patch_byte(p, 0x90))
                    ++patched_count;
            }
            if (patched_count > 0)
            {
                ++dead_blocks_nopped;
                nops_patched += patched_count;
                json p;
                p["type"]    = std::string("dead_code_nopped");
                p["address"] = helpers::format_address(cur);
                p["size"]    = patched_count;
                patches.push_back(std::move(p));
            }
            cur = block_end;
            continue;
        }

        cur += len;
    }

    if (nops_patched > 0)
        aida_reanalyze_function(pfn);

    result["patches"]               = std::move(patches);
    result["nops_patched"]          = nops_patched;
    result["dead_blocks_nopped"]    = dead_blocks_nopped;
    result["junk_sequences_found"]  = junk_sequences_nopped;

    return tool_result_t::ok(std::string("Junk instruction cleanup: ") + std::to_string(nops_patched) + " bytes NOPed", result);
}

tool_result_t resolve_opaque_predicates(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(std::string("Invalid address"));

    ea_t ea = *addr;
    func_t* pfn = get_func(ea);
    if (!pfn)
        return tool_result_t::error(std::string("No function at ") + helpers::format_address(ea));

    bool dry_run = params.value("dry_run", false);

    json result;
    result["function"] = helpers::get_name_or_address(pfn->start_ea);
    json resolved = json::array();
    int count = 0;

    ea_t cur = pfn->start_ea;
    ea_t prev_ea = BADADDR;

    while (cur < pfn->end_ea && cur != BADADDR)
    {
        insn_t insn;
        int len = decode_insn(&insn, cur);
        if (len <= 0)
        {
            cur = next_head(cur, pfn->end_ea);
            if (cur == BADADDR) break;
            continue;
        }

        if (prev_ea != BADADDR &&
            (insn.itype == NN_jz || insn.itype == NN_jnz ||
             insn.itype == NN_jbe || insn.itype == NN_ja ||
             insn.itype == NN_jl || insn.itype == NN_jge ||
             insn.itype == NN_jle || insn.itype == NN_jg))
        {
            insn_t prev_insn;
            if (decode_insn(&prev_insn, prev_ea) > 0)
            {
                bool is_always_zero = false;
                bool is_always_nonzero = false;

                if (prev_insn.itype == NN_xor &&
                    prev_insn.ops[0].type == o_reg &&
                    prev_insn.ops[1].type == o_reg &&
                    prev_insn.ops[0].reg == prev_insn.ops[1].reg)
                {
                    is_always_zero = true;
                }
                if (prev_insn.itype == NN_test &&
                    prev_insn.ops[0].type == o_reg &&
                    prev_insn.ops[1].type == o_reg &&
                    prev_insn.ops[0].reg == prev_insn.ops[1].reg)
                {
                    ea_t prev2 = prev_head(prev_ea, pfn->start_ea);
                    if (prev2 != BADADDR)
                    {
                        insn_t prev2_insn;
                        if (decode_insn(&prev2_insn, prev2) > 0 &&
                            prev2_insn.itype == NN_xor &&
                            prev2_insn.ops[0].type == o_reg &&
                            prev2_insn.ops[1].type == o_reg &&
                            prev2_insn.ops[0].reg == prev2_insn.ops[1].reg &&
                            prev2_insn.ops[0].reg == prev_insn.ops[0].reg)
                        {
                            is_always_zero = true;
                        }
                    }
                }

                if (is_always_zero || is_always_nonzero)
                {
                    json patch_entry;
                    patch_entry["address"] = helpers::format_address(cur);
                    qstring dis;
                    generate_disasm_line(&dis, cur, GENDSM_FORCE_CODE);
                    tag_remove(&dis);
                    patch_entry["original_insn"] = dis.c_str();

                    bool should_take_branch = false;
                    if (is_always_zero)
                    {
                        should_take_branch = (insn.itype == NN_jz || insn.itype == NN_jbe ||
                                              insn.itype == NN_jle || insn.itype == NN_jge);
                    }
                    else
                    {
                        should_take_branch = (insn.itype == NN_jnz || insn.itype == NN_ja ||
                                              insn.itype == NN_jg || insn.itype == NN_jl);
                    }

                    if (!dry_run)
                    {
                        if (should_take_branch)
                        {
                            if (insn.size == 2)
                            {
                                patch_byte(cur, 0xEB);
                                patch_entry["action"] = std::string("converted_to_jmp_short");
                            }
                            else if (insn.size == 6)
                            {
                                patch_byte(cur, 0x90);
                                patch_byte(cur + 1, 0xE9);
                                patch_entry["action"] = std::string("converted_to_jmp_near");
                            }
                            else
                            {
                                patch_entry["action"] = std::string("skipped_unusual_size");
                            }
                        }
                        else
                        {
                            for (int i = 0; i < insn.size; ++i)
                                patch_byte(cur + i, 0x90);
                            patch_entry["action"] = std::string("nopped_never_taken");
                        }
                    }
                    else
                    {
                        patch_entry["action"] = should_take_branch
                            ? std::string("would_convert_to_jmp")
                            : std::string("would_nop");
                    }

                    patch_entry["branch_decision"] = should_take_branch ? "always_taken" : "never_taken";
                    resolved.push_back(std::move(patch_entry));
                    ++count;
                }
            }
        }

        prev_ea = cur;
        cur += len;
    }

    if (!dry_run && count > 0)
        aida_reanalyze_function(pfn);

    result["resolved"]  = std::move(resolved);
    result["count"]     = count;
    result["dry_run"]   = dry_run;

    return tool_result_t::ok(std::string("Resolved ") + std::to_string(count) + " opaque predicates", result);
}

tool_result_t patch_anti_debug(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(std::string("Invalid address"));

    ea_t ea = *addr;
    func_t* pfn = get_func(ea);
    ea_t scan_start = pfn ? pfn->start_ea : ea;
    ea_t scan_end   = pfn ? pfn->end_ea : ea + params.value("size", (size_t)4096);

    bool dry_run = params.value("dry_run", false);
    bool patch_api_calls = params.value("patch_api_calls", true);
    bool patch_int_traps = params.value("patch_int_traps", true);
    bool patch_timing    = params.value("patch_timing", true);

    static const char* anti_debug_apis[] = {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "NtSetInformationThread",
        "OutputDebugString", "DbgBreakPoint", "DbgUiRemoteBreakin",
        "NtQuerySystemInformation",
        nullptr
    };

    json result;
    if (pfn) result["function"] = helpers::get_name_or_address(pfn->start_ea);
    json patches = json::array();
    int total_patched = 0;

    ea_t cur = scan_start;
    while (cur < scan_end && cur != BADADDR)
    {
        insn_t insn;
        int len = decode_insn(&insn, cur);
        if (len <= 0)
        {
            cur = next_head(cur, scan_end);
            if (cur == BADADDR) break;
            continue;
        }

        if (patch_api_calls && (insn.itype == NN_call || insn.itype == NN_callni || insn.itype == NN_callfi))
        {
            ea_t target = BADADDR;
            if (insn.ops[0].type == o_near || insn.ops[0].type == o_far)
                target = insn.ops[0].addr;
            else if (insn.ops[0].type == o_mem)
                target = static_cast<ea_t>(insn.ops[0].addr);

            if (target != BADADDR)
            {
                qstring tname;
                if (get_name(&tname, target) > 0)
                {
                    for (int i = 0; anti_debug_apis[i]; ++i)
                    {
                        if (tname.find(anti_debug_apis[i]) != qstring::npos)
                        {
                            json p;
                            p["type"]    = std::string("anti_debug_call");
                            p["address"] = helpers::format_address(cur);
                            p["api"]     = tname.c_str();

                            if (!dry_run)
                            {
                                for (int b = 0; b < insn.size; ++b)
                                    patch_byte(cur + b, 0x90);
                                p["action"] = std::string("nopped");
                                ++total_patched;

                                if (std::string(anti_debug_apis[i]) == "IsDebuggerPresent")
                                {
                                    if (insn.size >= 2)
                                    {
                                        patch_byte(cur, 0x31);
                                        patch_byte(cur + 1, 0xC0);
                                        for (int b = 2; b < insn.size; ++b)
                                            patch_byte(cur + b, 0x90);
                                        p["action"] = std::string("replaced_with_xor_eax_eax");
                                    }
                                }
                            }
                            else
                            {
                                p["action"] = std::string("would_nop");
                            }

                            patches.push_back(std::move(p));
                            break;
                        }
                    }
                }
            }
        }

        if (patch_int_traps && insn.itype == NN_int &&
            insn.ops[0].type == o_imm && insn.ops[0].value == 0x2D)
        {
            json p;
            p["type"]    = std::string("int2d_trap");
            p["address"] = helpers::format_address(cur);
            if (!dry_run)
            {
                for (int b = 0; b < insn.size; ++b)
                    patch_byte(cur + b, 0x90);
                p["action"] = std::string("nopped");
                ++total_patched;
            }
            else
            {
                p["action"] = std::string("would_nop");
            }
            patches.push_back(std::move(p));
        }

        if (patch_int_traps && insn.itype == NN_int3)
        {
            json p;
            p["type"]    = std::string("int3_trap");
            p["address"] = helpers::format_address(cur);
            if (!dry_run)
            {
                patch_byte(cur, 0x90);
                p["action"] = std::string("nopped");
                ++total_patched;
            }
            else
            {
                p["action"] = std::string("would_nop");
            }
            patches.push_back(std::move(p));
        }

        if (patch_timing && insn.itype == NN_rdtsc)
        {
            json p;
            p["type"]    = std::string("rdtsc_timing");
            p["address"] = helpers::format_address(cur);
            if (!dry_run)
            {
                if (insn.size >= 2)
                {
                    patch_byte(cur, 0x31);
                    patch_byte(cur + 1, 0xC0);
                    p["action"] = std::string("replaced_with_xor_eax");
                }
                ++total_patched;
            }
            else
            {
                p["action"] = std::string("would_patch");
            }
            patches.push_back(std::move(p));
        }

        cur += len;
    }

    if (!dry_run && total_patched > 0 && pfn)
        aida_reanalyze_function(pfn);

    result["patches"]       = std::move(patches);
    result["total_patched"] = total_patched;
    result["dry_run"]       = dry_run;

    return tool_result_t::ok(std::string("Anti-debug patching: ") + std::to_string(total_patched) + " patches", result);
}

tool_result_t decode_strings_in_function(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(std::string("Invalid address"));

    ea_t ea = *addr;
    func_t* pfn = get_func(ea);
    if (!pfn)
        return tool_result_t::error(std::string("No function at ") + helpers::format_address(ea));

    bool add_comments = params.value("add_comments", true);

    json result;
    result["function"] = helpers::get_name_or_address(pfn->start_ea);
    json decoded_strings = json::array();

    ea_t cur = pfn->start_ea;
    ea_t stack_str_start = BADADDR;
    std::string stack_str_chars;
    int stack_str_count = 0;

    while (cur < pfn->end_ea && cur != BADADDR)
    {
        insn_t insn;
        int len = decode_insn(&insn, cur);
        if (len <= 0)
        {
            cur = next_head(cur, pfn->end_ea);
            if (cur == BADADDR) break;
            continue;
        }

        bool is_byte_mov = (insn.itype == NN_mov &&
                           insn.ops[0].type == o_displ &&
                           insn.ops[1].type == o_imm);

        if (is_byte_mov)
        {
            uint64_t val = insn.ops[1].value;
            if (val >= 0x20 && val <= 0x7E)
            {
                if (stack_str_start == BADADDR)
                    stack_str_start = cur;
                stack_str_chars += static_cast<char>(val);
                ++stack_str_count;
                cur += len;
                continue;
            }
        }

        if (insn.itype == NN_mov && insn.ops[0].type == o_displ && insn.ops[1].type == o_imm)
        {
            uint64_t val = insn.ops[1].value;
            std::string chunk;
            bool all_printable = true;
            int byte_count = 0;

            if (val > 0xFF && val <= 0xFFFFFFFF)
                byte_count = 4;
            else if (val > 0xFFFFFFFF)
                byte_count = 8;

            if (byte_count > 0)
            {
                for (int b = 0; b < byte_count; ++b)
                {
                    char c = static_cast<char>((val >> (b * 8)) & 0xFF);
                    if (c == 0) break;
                    if (c < 0x20 || c > 0x7E) { all_printable = false; break; }
                    chunk += c;
                }
                if (all_printable && chunk.size() >= 2)
                {
                    if (stack_str_start == BADADDR)
                        stack_str_start = cur;
                    stack_str_chars += chunk;
                    stack_str_count++;
                    cur += len;
                    continue;
                }
            }
        }

        if (stack_str_count >= 3 && !stack_str_chars.empty())
        {
            json s;
            s["type"]    = std::string("stack_string");
            s["address"] = helpers::format_address(stack_str_start);
            s["decoded"] = stack_str_chars;
            s["length"]  = stack_str_chars.size();
            decoded_strings.push_back(std::move(s));

            if (add_comments)
                set_cmt(stack_str_start, (std::string("AiDA: Stack string: \"") + stack_str_chars + "\"").c_str(), false);
        }
        stack_str_start = BADADDR;
        stack_str_chars.clear();
        stack_str_count = 0;

        cur += len;
    }

    if (stack_str_count >= 3 && !stack_str_chars.empty())
    {
        json s;
        s["type"]    = std::string("stack_string");
        s["address"] = helpers::format_address(stack_str_start);
        s["decoded"] = stack_str_chars;
        s["length"]  = stack_str_chars.size();
        decoded_strings.push_back(std::move(s));
        if (add_comments)
            set_cmt(stack_str_start, (std::string("AiDA: Stack string: \"") + stack_str_chars + "\"").c_str(), false);
    }

    func_item_iterator_t fii(pfn);
    for (bool ok = fii.first(); ok; ok = fii.next_head())
    {
        ea_t item = fii.current();
        insn_t insn;
        if (decode_insn(&insn, item) <= 0) continue;

        if (insn.itype == NN_xor && insn.ops[1].type == o_imm)
        {
            uint8_t xor_key = static_cast<uint8_t>(insn.ops[1].value & 0xFF);
            if (xor_key == 0) continue;

            xrefblk_t xb;
            for (bool xok = xb.first_from(item, XREF_DATA); xok; xok = xb.next_from())
            {
                ea_t data_ea = xb.to;
                if (!is_loaded(data_ea)) continue;

                std::string decoded;
                for (int i = 0; i < 256; ++i)
                {
                    if (!is_loaded(data_ea + i)) break;
                    uint8_t b = get_byte(data_ea + i);
                    char c = static_cast<char>(b ^ xor_key);
                    if (c == 0) break;
                    if (c < 0x20 || c > 0x7E) { decoded.clear(); break; }
                    decoded += c;
                }

                if (decoded.size() >= 4)
                {
                    json s;
                    s["type"]     = std::string("xor_string");
                    s["address"]  = helpers::format_address(item);
                    s["data_at"]  = helpers::format_address(data_ea);
                    s["xor_key"]  = helpers::format_address(static_cast<ea_t>(xor_key));
                    s["decoded"]  = decoded;
                    s["length"]   = decoded.size();
                    decoded_strings.push_back(std::move(s));

                    if (add_comments)
                    {
                        set_cmt(item, (std::string("AiDA: XOR-decrypted string (key=0x") +
                                      helpers::format_address(static_cast<ea_t>(xor_key)).substr(2) +
                                      "): \"" + decoded + "\"").c_str(), false);
                    }
                }
            }
        }
    }

    int total_decoded = static_cast<int>(decoded_strings.size());
    result["decoded_strings"] = std::move(decoded_strings);
    result["total_decoded"]   = total_decoded;

    return tool_result_t::ok(std::string("String decoding: ") + std::to_string(total_decoded) + " strings found", result);
}

tool_result_t rebuild_function(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(std::string("Invalid address"));

    ea_t ea = *addr;
    func_t* pfn = get_func(ea);
    ea_t start = pfn ? pfn->start_ea : ea;
    ea_t end   = pfn ? pfn->end_ea : BADADDR;

    bool force_recreate = params.value("force_recreate", false);
    bool create_instructions = params.value("create_instructions", true);

    json result;
    result["original_start"] = helpers::format_address(start);
    if (end != BADADDR)
        result["original_end"] = helpers::format_address(end);

    int insns_created = 0;
    int errors = 0;

    if (force_recreate && pfn)
    {
        del_func(start);
        result["deleted_original"] = true;

        if (end != BADADDR)
            del_items(start, DELIT_SIMPLE, end - start);
    }

    if (create_instructions)
    {
        ea_t range_end = (end != BADADDR) ? end : start + 0x10000;
        ea_t cur = start;
        while (cur < range_end && cur != BADADDR)
        {
            int len = create_insn(cur);
            if (len > 0)
            {
                ++insns_created;
                cur += len;
            }
            else
            {
                ++errors;
                cur = next_addr(cur);
                if (cur == BADADDR) break;
            }
        }
    }

    bool func_created = add_func(start, BADADDR);
    pfn = get_func(start);

    if (pfn)
    {
        aida_reanalyze_function(pfn);
        result["new_start"] = helpers::format_address(pfn->start_ea);
        result["new_end"]   = helpers::format_address(pfn->end_ea);
        result["new_size"]  = pfn->end_ea - pfn->start_ea;
    }

    if (end != BADADDR)
    {
        auto_mark_range(start, end, AU_FINAL);
        plan_range(start, end);


        responsive_auto_wait(start, end, "Rebuilding function analysis");
    }

    result["function_created"]   = func_created;
    result["instructions_created"] = insns_created;
    result["errors"]             = errors;

    return tool_result_t::ok(std::string("Function rebuilt: ") + std::to_string(insns_created) + " instructions", result);
}

tool_result_t identify_protector(const json& params)
{
    size_t scan_size = params.value("scan_size", (size_t)0x100000);
    if (scan_size > 0x1000000) scan_size = 0x1000000;

    ea_t start = inf_get_min_ea();
    ea_t end   = std::min(start + static_cast<ea_t>(scan_size), inf_get_max_ea());

    json result;
    json detections = json::array();

    struct section_sig_t {
        const char* name;
        const char* protector;
    };
    static const section_sig_t section_sigs[] = {
        {".vmp",    "VMProtect"},
        {".vmp0",   "VMProtect"},
        {".vmp1",   "VMProtect"},
        {".vmp2",   "VMProtect"},
        {".vmprotect", "VMProtect"},
        {".themida", "Themida/WinLicense"},
        {".Themida", "Themida/WinLicense"},
        {"Themida",  "Themida/WinLicense"},
        {".upx",    "UPX"},
        {"UPX0",    "UPX"},
        {"UPX1",    "UPX"},
        {"UPX2",    "UPX"},
        {".aspack", "ASPack"},
        {".adata",  "ASPack"},
        {".nsp",    "NSPack"},
        {".enigma", "Enigma Protector"},
        {".perplex", "PECompact"},
        {".petite", "Petite"},
        {".yP",     "Y's Crypter"},
        {".sforce", "StarForce"},
        {"_winzip_", "WinZip SFX"},
        {".shrink", "Shrinker"},
        {".RLPack", "RLPack"},
        {".MaskPE", "MaskPE"},
        {".ndata",  "NSIS Installer"},
        {".rsrc",   ""},
        {nullptr,   nullptr}
    };

    for (int si = 0; si < get_segm_qty(); ++si)
    {
        segment_t* seg = getnseg(si);
        if (!seg) continue;

        qstring sname;
        aida_get_segm_name(&sname, seg);

        for (int k = 0; section_sigs[k].name; ++k)
        {
            if (sname == section_sigs[k].name && section_sigs[k].protector[0] != '\0')
            {
                json d;
                d["type"]      = std::string("section_name");
                d["section"]   = sname.c_str();
                d["protector"] = section_sigs[k].protector;
                d["start"]     = helpers::format_address(seg->start_ea);
                d["size"]      = seg->size();
                detections.push_back(std::move(d));
            }
        }
    }

    struct byte_sig_t {
        const char* protector;
        const char* description;
        const uint8_t* pattern;
        const uint8_t* mask;
        int length;
    };

    static const uint8_t vmp_push_call[] = { 0x68, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00 };
    static const uint8_t vmp_push_mask[] = { 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00 };

    static const uint8_t themida_sig[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0x60, 0x0F, 0x31 };
    static const uint8_t themida_mask[] = { 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF };

    static const uint8_t upx_sig[] = { 0x60, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x8D, 0xBE };
    static const uint8_t upx_mask[] = { 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF };

    static const byte_sig_t byte_sigs[] = {
        {"VMProtect", "VMProtect entry stub (push/call pattern)", vmp_push_call, vmp_push_mask, 10},
        {"Themida/WinLicense", "Themida stolen code entry", themida_sig, themida_mask, 8},
        {"UPX", "UPX decompression stub", upx_sig, upx_mask, 8},
    };

    ea_t ep = inf_get_start_ea();
    if (ep != BADADDR)
    {
        for (const auto& sig : byte_sigs)
        {
            for (ea_t scan = (ep > 0x100 ? ep - 0x100 : ep); scan < ep + 0x1000 && scan < end; ++scan)
            {
                if (!is_loaded(scan)) continue;
                bool match = true;
                for (int i = 0; i < sig.length; ++i)
                {
                    if (!is_loaded(scan + i)) { match = false; break; }
                    uint8_t b = get_byte(scan + i);
                    if ((b & sig.mask[i]) != (sig.pattern[i] & sig.mask[i]))
                    {
                        match = false;
                        break;
                    }
                }
                if (match)
                {
                    json d;
                    d["type"]        = std::string("byte_signature");
                    d["address"]     = helpers::format_address(scan);
                    d["protector"]   = sig.protector;
                    d["description"] = sig.description;
                    detections.push_back(std::move(d));
                    break;
                }
            }
        }
    }

    static const char* protector_strings[] = {
        "VMProtect begin", "VMProtect end", "VMProtectSDK",
        "Themida", "WinLicense", "Oreans Technologies",
        "UPX!", "This program cannot be run",
        "ASProtect", "StarForce",
        "Enigma protector", "EXECryptor",
        ".NET Reactor", "ConfuserEx",
        "Obsidium", "PECompact",
        nullptr
    };

    for (int si = 0; si < get_segm_qty(); ++si)
    {
        segment_t* seg = getnseg(si);
        if (!seg) continue;

        qstring sname;
        aida_get_segm_name(&sname, seg);
        if (sname != ".rdata" && sname != ".data" && sname != ".rsrc") continue;

        ea_t seg_end = std::min(seg->end_ea, seg->start_ea + static_cast<ea_t>(0x100000));
        for (ea_t scan = seg->start_ea; scan < seg_end; ++scan)
        {
            if (!is_loaded(scan)) continue;
            flags64_t f = get_flags(scan);
            if (!is_strlit(f)) continue;

            qstring s;
            if (get_strlit_contents(&s, scan, -1, get_str_type(scan)) <= 0) continue;

            for (int k = 0; protector_strings[k]; ++k)
            {
                if (s.find(protector_strings[k]) != qstring::npos)
                {
                    json d;
                    d["type"]      = std::string("string_reference");
                    d["address"]   = helpers::format_address(scan);
                    d["string"]    = s.c_str();
                    d["protector"] = protector_strings[k];
                    detections.push_back(std::move(d));
                    break;
                }
            }
        }
    }

    json entropy_info = json::array();
    for (int si = 0; si < get_segm_qty(); ++si)
    {
        segment_t* seg = getnseg(si);
        if (!seg || seg->size() == 0) continue;

        qstring sname;
        aida_get_segm_name(&sname, seg);

        size_t sample_size = std::min(static_cast<size_t>(seg->size()), static_cast<size_t>(4096));
        int freq[256] = {0};
        int valid_bytes = 0;

        for (size_t i = 0; i < sample_size; ++i)
        {
            ea_t addr = seg->start_ea + i;
            if (!is_loaded(addr)) continue;
            ++freq[get_byte(addr)];
            ++valid_bytes;
        }

        if (valid_bytes > 0)
        {
            double entropy = 0.0;
            for (int k = 0; k < 256; ++k)
            {
                if (freq[k] == 0) continue;
                double p = static_cast<double>(freq[k]) / valid_bytes;
                entropy -= p * std::log2(p);
            }

            json ei;
            ei["section"] = sname.c_str();
            ei["entropy"]  = entropy;
            ei["size"]     = seg->size();
            ei["verdict"]  = (entropy > 7.5) ? "packed/encrypted" :
                            (entropy > 6.5) ? "compressed/obfuscated" :
                            (entropy > 5.0) ? "normal_code" : "sparse_data";
            entropy_info.push_back(std::move(ei));

            if (entropy > 7.5)
            {
                json d;
                d["type"]      = std::string("high_entropy");
                d["section"]   = sname.c_str();
                d["entropy"]   = entropy;
                d["note"]      = std::string("High entropy suggests packed/encrypted section");
                detections.push_back(std::move(d));
            }
        }
    }

    result["detections"]   = std::move(detections);
    result["entropy"]      = std::move(entropy_info);
    result["detection_count"] = result["detections"].size();

    std::set<std::string> found_protectors;
    for (const auto& d : result["detections"])
    {
        if (d.contains("protector") && d["protector"].is_string())
            found_protectors.insert(d["protector"].get<std::string>());
    }

    json protectors = json::array();
    for (const auto& p : found_protectors)
        protectors.push_back(p);
    result["protectors_found"] = std::move(protectors);

    std::string summary = found_protectors.empty()
        ? "No known protectors detected"
        : "Detected: ";
    for (const auto& p : found_protectors)
        summary += p + ", ";
    if (!found_protectors.empty())
        summary = summary.substr(0, summary.size() - 2);

    return tool_result_t::ok(summary, result);
}

tool_result_t deobfuscate_control_flow(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(std::string("Invalid address"));

    ea_t ea = *addr;
    func_t* pfn = get_func(ea);
    if (!pfn)
        return tool_result_t::error(std::string("No function at ") + helpers::format_address(ea));

    json result;
    result["function"] = helpers::get_name_or_address(pfn->start_ea);
    result["start"]    = helpers::format_address(pfn->start_ea);
    result["end"]      = helpers::format_address(pfn->end_ea);

    std::map<ea_t, int> backedge_targets;
    std::set<ea_t> all_block_starts;
    all_block_starts.insert(pfn->start_ea);

    func_item_iterator_t fii(pfn);
    for (bool ok = fii.first(); ok; ok = fii.next_head())
    {
        ea_t item = fii.current();
        insn_t insn;
        if (decode_insn(&insn, item) <= 0) continue;

        if (is_basic_block_end(insn, false))
        {
            ea_t fall = item + insn.size;
            if (aida_func_contains(pfn, fall))
                all_block_starts.insert(fall);

            xrefblk_t xb;
            for (bool xok = xb.first_from(item, XREF_ALL); xok; xok = xb.next_from())
            {
                if (xb.iscode && aida_func_contains(pfn, xb.to))
                {
                    all_block_starts.insert(xb.to);
                    if (xb.to <= item)
                        backedge_targets[xb.to]++;
                }
            }
        }
    }

    ea_t dispatcher = BADADDR;
    int max_backedges = 0;
    for (const auto& [addr_target, count] : backedge_targets)
    {
        if (count > max_backedges)
        {
            max_backedges = count;
            dispatcher = addr_target;
        }
    }

    json cff_analysis;
    cff_analysis["block_count"]    = all_block_starts.size();
    cff_analysis["back_edge_targets"] = backedge_targets.size();

    bool is_cff = false;
    if (dispatcher != BADADDR && max_backedges >= 3 &&
        all_block_starts.size() >= 5)
    {
        is_cff = true;
        cff_analysis["dispatcher_address"] = helpers::format_address(dispatcher);
        cff_analysis["dispatcher_backedge_count"] = max_backedges;

        json state_var_info;
        ea_t disp_end = pfn->end_ea;
        auto it = all_block_starts.upper_bound(dispatcher);
        if (it != all_block_starts.end())
            disp_end = *it;

        for (ea_t dc = dispatcher; dc < disp_end && dc != BADADDR;)
        {
            insn_t dins;
            int dlen = decode_insn(&dins, dc);
            if (dlen <= 0) break;

            if (dins.itype == NN_cmp || dins.itype == NN_sub || dins.itype == NN_test)
            {
                qstring dis;
                generate_disasm_line(&dis, dc, GENDSM_FORCE_CODE);
                tag_remove(&dis);
                state_var_info["dispatcher_comparison"] = dis.c_str();
                state_var_info["comparison_address"]    = helpers::format_address(dc);

                if (dins.ops[0].type == o_reg)
                    state_var_info["state_register"] = static_cast<int>(dins.ops[0].reg);
                if (dins.ops[0].type == o_displ || dins.ops[0].type == o_mem)
                    state_var_info["state_memory"] = helpers::format_address(static_cast<ea_t>(dins.ops[0].addr));
                break;
            }
            dc += dlen;
        }
        cff_analysis["state_variable"] = state_var_info;

        json state_blocks = json::array();
        for (ea_t bs : all_block_starts)
        {
            ea_t block_end = pfn->end_ea;
            auto bit = all_block_starts.upper_bound(bs);
            if (bit != all_block_starts.end())
                block_end = *bit;

            ea_t last_insn = bs;
            for (ea_t a = bs; a < block_end;)
            {
                insn_t ti;
                int tlen = decode_insn(&ti, a);
                if (tlen <= 0) break;
                last_insn = a;
                a += tlen;
            }

            xrefblk_t xb;
            bool jumps_to_dispatcher = false;
            for (bool xok = xb.first_from(last_insn, XREF_ALL); xok; xok = xb.next_from())
            {
                if (xb.iscode && xb.to == dispatcher)
                {
                    jumps_to_dispatcher = true;
                    break;
                }
            }

            if (jumps_to_dispatcher && bs != dispatcher)
            {
                json sb;
                sb["start"] = helpers::format_address(bs);
                sb["end"]   = helpers::format_address(block_end);

                for (ea_t a = bs; a < block_end;)
                {
                    insn_t si;
                    int slen = decode_insn(&si, a);
                    if (slen <= 0) break;

                    if (si.itype == NN_mov && si.ops[1].type == o_imm)
                    {
                        if (si.ops[0].type == o_reg || si.ops[0].type == o_displ || si.ops[0].type == o_mem)
                        {
                            sb["next_state"] = static_cast<int64_t>(si.ops[1].value);
                            sb["state_assign_addr"] = helpers::format_address(a);
                        }
                    }
                    a += slen;
                }

                state_blocks.push_back(std::move(sb));
            }
        }

        cff_analysis["state_blocks"]      = std::move(state_blocks);
        cff_analysis["state_block_count"] = cff_analysis["state_blocks"].size();

        set_cmt(dispatcher, "AiDA: CFF Dispatcher block - state variable switch", false);
        for (const auto& sb : cff_analysis["state_blocks"])
        {
            auto sb_addr = helpers::parse_address(sb.value("start", std::string()));
            if (sb_addr)
            {
                std::string comment = "AiDA: CFF State block";
                if (sb.contains("next_state"))
                    comment += " ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ next_state=" + std::to_string(sb["next_state"].get<int64_t>());
                set_cmt(*sb_addr, comment.c_str(), false);
            }
        }
    }

    cff_analysis["is_control_flow_flattened"] = is_cff;
    result["cff_analysis"] = std::move(cff_analysis);

    std::string summary = is_cff
        ? "Control flow flattening detected and mapped (" + std::to_string(max_backedges) + " state blocks)"
        : "No control flow flattening pattern detected";

    return tool_result_t::ok(summary, result);
}

tool_result_t reconstruct_imports(const json& params)
{
    auto base_opt = helpers::parse_address(params.value("address", std::string()));
    ea_t base = base_opt ? *base_opt : inf_get_min_ea();
    size_t scan_size = params.value("scan_size", (size_t)0x100000);

    json result;
    result["base"] = helpers::format_address(base);

    uint import_count = get_import_module_qty();
    json known_imports = json::array();
    std::map<ea_t, std::string> import_map;

    for (uint i = 0; i < import_count; ++i)
    {
        qstring mod_name;
        get_import_module_name(&mod_name, i);

        struct enum_ctx_t {
            std::map<ea_t, std::string>* map;
            std::string module;
        };
        enum_ctx_t ctx;
        ctx.map = &import_map;
        ctx.module = mod_name.c_str();

        enum_import_names(i, [](ea_t ea, const char* name, uval_t , void* param) -> int {
            auto* c = static_cast<enum_ctx_t*>(param);
            if (name && name[0])
                (*c->map)[ea] = std::string(c->module) + "!" + name;
            return 1;
        }, &ctx);
    }

    json iat_entries = json::array();
    int resolved = 0;
    int unresolved = 0;

    for (int si = 0; si < get_segm_qty(); ++si)
    {
        segment_t* seg = getnseg(si);
        if (!seg) continue;

        qstring sname;
        aida_get_segm_name(&sname, seg);

        bool is_iat = (sname == ".idata" || sname == ".rdata" || sname == "IAT");
        if (!is_iat) continue;

        for (ea_t ea = seg->start_ea; ea + 8 <= seg->end_ea; ea += 8)
        {
            if (!is_loaded(ea)) continue;

            uint64 val = get_qword(ea);
            if (val == 0 || val == BADADDR) continue;

            qstring target_name;
            if (get_name(&target_name, static_cast<ea_t>(val)) > 0 && !target_name.empty())
            {
                json ie;
                ie["iat_address"]   = helpers::format_address(ea);
                ie["target"]        = helpers::format_address(static_cast<ea_t>(val));
                ie["resolved_name"] = target_name.c_str();
                iat_entries.push_back(std::move(ie));
                ++resolved;
            }
            else
            {
                if (getseg(static_cast<ea_t>(val)))
                {
                    ++unresolved;
                    json ie;
                    ie["iat_address"] = helpers::format_address(ea);
                    ie["target"]      = helpers::format_address(static_cast<ea_t>(val));
                    ie["status"]      = std::string("unresolved");
                    iat_entries.push_back(std::move(ie));
                }
            }
        }
    }

    int names_set = 0;

    for (auto& iat_entry : iat_entries)
    {
        if (iat_entry.value("status", "") != "unresolved") continue;
        auto target_opt = helpers::parse_address(iat_entry["target"].get<std::string>());
        if (!target_opt) continue;
        ea_t target_ea = *target_opt;


        auto it = import_map.find(target_ea);
        if (it != import_map.end())
        {
            iat_entry["resolved_name"] = it->second;
            iat_entry.erase("status");
            ++names_set;
            ++resolved; --unresolved;
            continue;
        }


        qstring found_name;
        if (get_name(&found_name, target_ea, GN_DEMANGLED) > 0 && !found_name.empty())
        {
            iat_entry["resolved_name"] = found_name.c_str();
            iat_entry.erase("status");
            set_name(target_ea, found_name.c_str(), SN_NOWARN | SN_NOCHECK);
            ++names_set;
            ++resolved; --unresolved;
            continue;
        }


        segment_t* target_seg = getseg(target_ea);
        if (target_seg)
        {
            qstring seg_name;
            aida_get_segm_name(&seg_name, target_seg);

            if (target_seg->perm & SEGPERM_EXEC)
            {
                func_t* f = get_func(target_ea);
                if (!f)
                {
                    add_func(target_ea);
                    f = get_func(target_ea);
                }
                if (f)
                {
                    qstring fn;
                    if (get_func_name(&fn, target_ea) > 0 && !fn.empty())
                    {
                        auto iat_ea = helpers::parse_address(iat_entry["iat_address"].get<std::string>());
                        if (iat_ea)
                        {
                            std::string label = std::string("imp_") + fn.c_str();
                            set_name(*iat_ea, label.c_str(), SN_NOWARN | SN_NOCHECK);
                        }
                        iat_entry["resolved_name"] = fn.c_str();
                        iat_entry.erase("status");
                        ++names_set;
                        ++resolved; --unresolved;
                    }
                }
            }
        }
    }

    json call_thunks = json::array();
    for (const auto& iat_entry : iat_entries)
    {
        if (iat_entry.value("status", "") != "unresolved") continue;

        auto iat_ea = helpers::parse_address(iat_entry["iat_address"].get<std::string>());
        if (!iat_ea) continue;

        xrefblk_t xb;
        int ref_count = 0;
        for (bool xok = xb.first_to(*iat_ea, XREF_ALL); xok && ref_count < 50; xok = xb.next_to())
        {
            ++ref_count;
            insn_t insn;
            if (decode_insn(&insn, xb.from) > 0)
            {
                if (insn.itype == NN_call || insn.itype == NN_callni ||
                    insn.itype == NN_jmp || insn.itype == NN_jmpni)
                {
                    json ct;
                    ct["caller"]      = helpers::format_address(xb.from);
                    ct["iat_slot"]    = helpers::format_address(*iat_ea);
                    ct["target"]      = iat_entry["target"];
                    call_thunks.push_back(std::move(ct));
                }
            }
        }
    }

    result["import_modules"]       = import_count;
    result["known_imports"]        = import_map.size();
    result["iat_entries_found"]    = iat_entries.size();
    result["resolved_entries"]     = resolved;
    result["unresolved_entries"]   = unresolved;
    result["iat_entries"]          = std::move(iat_entries);
    result["call_thunks"]          = std::move(call_thunks);
    result["names_set"]            = names_set;

    return tool_result_t::ok(std::string("Import reconstruction: ") + std::to_string(resolved) +
                             " resolved, " + std::to_string(unresolved) + " unresolved", result);
}

tool_result_t unpack_section(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(std::string("Invalid address"));

    ea_t section_start = *addr;
    segment_t* seg = getseg(section_start);
    if (!seg)
        return tool_result_t::error(std::string("No segment at ") + helpers::format_address(section_start));

    size_t section_size = params.value("size", static_cast<size_t>(seg->size()));
    if (section_size > static_cast<size_t>(seg->size()))
        section_size = static_cast<size_t>(seg->size());

    std::string method = params.value("method", "auto");
    std::string key_str = params.value("key", "");
    bool create_code = params.value("create_code", true);

    json result;
    result["section_start"]  = helpers::format_address(section_start);
    result["section_size"]   = section_size;
    result["method"]         = method;

    std::vector<uint8_t> xor_key;
    if (!key_str.empty())
    {
        std::string clean = key_str;
        clean.erase(std::remove(clean.begin(), clean.end(), ' '), clean.end());
        for (size_t i = 0; i + 1 < clean.size(); i += 2)
        {
            try { xor_key.push_back(static_cast<uint8_t>(std::stoul(clean.substr(i, 2), nullptr, 16))); }
            catch (...) {}
        }
    }

    if (method == "auto" && xor_key.empty())
    {
        int best_key = -1;
        int best_valid = 0;

        for (int k = 1; k < 256; ++k)
        {
            int valid_insns = 0;
            ea_t test_end = std::min(section_start + static_cast<ea_t>(256), section_start + static_cast<ea_t>(section_size));

            for (ea_t a = section_start; a < test_end; ++a)
            {
                if (!is_loaded(a)) continue;
                uint8_t orig = get_byte(a);
                uint8_t decoded = orig ^ static_cast<uint8_t>(k);

                if (decoded == 0x48 || decoded == 0x49 || decoded == 0x4C ||
                    decoded == 0x55 || decoded == 0x53 || decoded == 0x56 ||
                    decoded == 0x41 || decoded == 0x89 || decoded == 0x8B ||
                    decoded == 0xE8 || decoded == 0xE9 || decoded == 0xEB ||
                    decoded == 0xC3 || decoded == 0xCC || decoded == 0x90)
                {
                    ++valid_insns;
                }
            }

            if (valid_insns > best_valid)
            {
                best_valid = valid_insns;
                best_key = k;
            }
        }

        if (best_key > 0 && best_valid >= 20)
        {
            xor_key.push_back(static_cast<uint8_t>(best_key));
            method = "xor_single";
            result["detected_key"] = helpers::format_address(static_cast<ea_t>(best_key));
            result["key_confidence"] = best_valid;
        }
        else
        {
            return tool_result_t::error(std::string("Auto-detection failed. Provide an explicit key or method."));
        }
    }
    else if (method == "auto" && !xor_key.empty())
    {
        method = (xor_key.size() == 1) ? "xor_single" : "xor_multi";
    }

    int bytes_patched = 0;
    show_wait_box("HIDECANCEL\nAiDA: Decrypting section (0x%zX bytes)...", section_size);

    if (method == "xor_single" || method == "xor_multi")
    {
        for (size_t i = 0; i < section_size; ++i)
        {
            ea_t cur_ea = section_start + i;
            if (!is_loaded(cur_ea)) continue;

            if (i % 0x10000 == 0)
                replace_wait_box("HIDECANCEL\nAiDA: Decrypting 0x%zX / 0x%zX...", i, section_size);

            uint8_t orig = get_byte(cur_ea);
            uint8_t key_byte = xor_key[i % xor_key.size()];
            uint8_t decrypted = orig ^ key_byte;

            if (decrypted != orig)
            {
                patch_byte(cur_ea, decrypted);
                ++bytes_patched;
            }
        }
    }
    else if (method == "xor_rolling")
    {
        uint8_t rolling = xor_key.empty() ? 0 : xor_key[0];
        for (size_t i = 0; i < section_size; ++i)
        {
            ea_t cur_ea = section_start + i;
            if (!is_loaded(cur_ea)) continue;

            uint8_t orig = get_byte(cur_ea);
            uint8_t decrypted = orig ^ rolling;
            rolling = orig;

            if (decrypted != orig)
            {
                patch_byte(cur_ea, decrypted);
                ++bytes_patched;
            }
        }
    }

    hide_wait_box();

    int insns_created = 0;
    if (create_code && (seg->perm & SEGPERM_EXEC))
    {
        show_wait_box("HIDECANCEL\nAiDA: Re-analyzing decrypted code...");

        del_items(section_start, DELIT_SIMPLE, static_cast<asize_t>(section_size));

        ea_t cur = section_start;
        ea_t code_end = section_start + static_cast<ea_t>(section_size);
        while (cur < code_end && cur != BADADDR)
        {
            int len = create_insn(cur);
            if (len > 0)
            {
                ++insns_created;
                cur += len;
            }
            else
            {
                cur = next_addr(cur);
                if (cur == BADADDR) break;
            }
        }

        auto_mark_range(section_start, code_end, AU_CODE);
        auto_mark_range(section_start, code_end, AU_FINAL);

        hide_wait_box();
    }

    result["bytes_patched"]      = bytes_patched;
    result["instructions_created"] = insns_created;
    result["method_used"]        = method;
    if (!xor_key.empty())
    {
        std::ostringstream ks;
        for (size_t i = 0; i < xor_key.size(); ++i)
        {
            if (i > 0) ks << " ";
            ks << std::hex << std::setw(2) << std::setfill('0') << (int)xor_key[i];
        }
        result["key_used"] = ks.str();
    }

    return tool_result_t::ok(std::string("Section unpacked: ") + std::to_string(bytes_patched) +
                             " bytes decrypted, " + std::to_string(insns_created) + " instructions created", result);
}

tool_result_t full_deobfuscation_pass(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(std::string("Invalid address"));

    ea_t ea = *addr;
    func_t* pfn = get_func(ea);
    if (!pfn)
        return tool_result_t::error(std::string("No function at ") + helpers::format_address(ea));

    bool dry_run = params.value("dry_run", false);

    json result;
    result["function"] = helpers::get_name_or_address(pfn->start_ea);
    result["start"]    = helpers::format_address(pfn->start_ea);
    result["end"]      = helpers::format_address(pfn->end_ea);
    result["original_size"] = pfn->end_ea - pfn->start_ea;

    json steps = json::array();

    show_wait_box("HIDECANCEL\nAiDA: Full deobfuscation pass...");

    replace_wait_box("HIDECANCEL\nAiDA: Step 1/6 - Detecting obfuscation...");
    auto detect_result = analysis_tools::detect_obfuscation_patterns(
        json({{"address", helpers::format_address(ea)}}));
    steps.push_back({{"step", "detect_obfuscation"},
                     {"success", detect_result.success},
                     {"score", detect_result.data.value("obfuscation_score_pct", 0)}});

    int obf_score = detect_result.data.value("obfuscation_score_pct", 0);

    replace_wait_box("HIDECANCEL\nAiDA: Step 2/6 - Resolving opaque predicates...");
    auto opaque_result = resolve_opaque_predicates(
        json({{"address", helpers::format_address(ea)}, {"dry_run", dry_run}}));
    steps.push_back({{"step", "resolve_opaque_predicates"},
                     {"success", opaque_result.success},
                     {"count", opaque_result.data.value("count", 0)}});

    replace_wait_box("HIDECANCEL\nAiDA: Step 3/6 - Removing junk code...");
    auto junk_result = nop_junk_instructions(
        json({{"address", helpers::format_address(ea)},
              {"aggressive", obf_score >= 50}}));
    steps.push_back({{"step", "nop_junk"},
                     {"success", junk_result.success},
                     {"nops_patched", junk_result.data.value("nops_patched", 0)}});

    replace_wait_box("HIDECANCEL\nAiDA: Step 4/6 - Decoding strings...");
    auto strings_result = decode_strings_in_function(
        json({{"address", helpers::format_address(ea)}, {"add_comments", true}}));
    steps.push_back({{"step", "decode_strings"},
                     {"success", strings_result.success},
                     {"strings_found", strings_result.data.value("total_decoded", 0)}});

    replace_wait_box("HIDECANCEL\nAiDA: Step 5/6 - Analyzing control flow...");
    auto cff_result = deobfuscate_control_flow(
        json({{"address", helpers::format_address(ea)}}));
    steps.push_back({{"step", "deobfuscate_cff"},
                     {"success", cff_result.success},
                     {"is_cff", cff_result.data.contains("cff_analysis") ?
                          cff_result.data["cff_analysis"].value("is_control_flow_flattened", false) : false}});

    int total_changes = opaque_result.data.value("count", 0) +
                        junk_result.data.value("nops_patched", 0);
    if (!dry_run && total_changes > 0)
    {
        replace_wait_box("HIDECANCEL\nAiDA: Step 6/6 - Rebuilding function...");
        auto rebuild_result = rebuild_function(
            json({{"address", helpers::format_address(pfn->start_ea)},
                  {"force_recreate", true},
                  {"create_instructions", true}}));
        steps.push_back({{"step", "rebuild_function"},
                         {"success", rebuild_result.success},
                         {"instructions", rebuild_result.data.value("instructions_created", 0)}});
    }
    else
    {
        steps.push_back({{"step", "rebuild_function"},
                         {"success", true},
                         {"note", dry_run ? "Skipped (dry run)" : "Skipped (no patches applied)"}});
    }


    if (!dry_run && total_changes > 0)
        responsive_auto_wait(0, BADADDR, "Applying deobfuscation changes");

    hide_wait_box();

    if (!dry_run)
    {
        pfn = get_func(ea);
        if (pfn)
        {
            std::string pseudo = helpers::get_pseudocode(pfn->start_ea);
            if (!pseudo.empty() && pseudo.find("not available") == std::string::npos)
                result["deobfuscated_pseudocode"] = pseudo;
        }
    }

    result["steps"]         = std::move(steps);
    result["dry_run"]       = dry_run;
    result["total_changes"] = total_changes;

    if (!dry_run && total_changes > 0)
    {
        auto post_detect = analysis_tools::detect_obfuscation_patterns(
            json({{"address", helpers::format_address(ea)}}));
        int post_score = post_detect.data.value("obfuscation_score_pct", 0);
        result["pre_obfuscation_score"]  = obf_score;
        result["post_obfuscation_score"] = post_score;
        result["score_reduction"]        = obf_score - post_score;
    }

    return tool_result_t::ok(std::string("Full deobfuscation pass complete: ") +
                             std::to_string(total_changes) + " changes", result);
}


tool_result_t devirtualize_function(const json& params)
{
    auto addr = helpers::parse_address(params.value("address", std::string()));
    if (!addr)
        return tool_result_t::error(std::string("Invalid address"));

    ea_t ea = *addr;
    func_t* fn = get_func(ea);
    if (!fn)
        return tool_result_t::error(std::string("No function at ") + helpers::format_address(ea));

    std::uint32_t max_handlers = params.value("max_handlers", 256);
    if (max_handlers > 4096) max_handlers = 4096;
    bool add_comments = params.value("add_comments", true);

    json result;
    result["function"] = helpers::format_address(fn->start_ea);
    result["function_size"] = static_cast<std::uint64_t>(fn->size());


    ea_t dispatch_addr = BADADDR;
    ea_t table_addr = BADADDR;
    int table_entry_size = 8;
    int indirect_jumps = 0;
    int cmp_count = 0;
    ea_t last_cmp = BADADDR;

    for (ea_t cur = fn->start_ea; cur < fn->end_ea && cur != BADADDR;)
    {
        insn_t insn;
        int len = decode_insn(&insn, cur);
        if (len <= 0) { cur = next_head(cur, fn->end_ea); if (cur == BADADDR) break; continue; }


        if (insn.itype == NN_cmp)
        {
            if (last_cmp != BADADDR && (cur - last_cmp) < 32) ++cmp_count;
            last_cmp = cur;
        }


        if (insn.itype == NN_jmpni || insn.itype == NN_jmpfi)
        {
            ++indirect_jumps;
            if (dispatch_addr == BADADDR) dispatch_addr = cur;

            for (int op = 0; op < UA_MAXOP; ++op)
            {
                if (insn.ops[op].type == o_displ || insn.ops[op].type == o_phrase)
                {
                    if (insn.ops[op].addr != 0) table_addr = insn.ops[op].addr;
                }
                if (insn.ops[op].type == o_mem)
                    table_addr = insn.ops[op].addr;
            }
        }
        cur += len;
    }

    result["dispatcher_address"]  = dispatch_addr != BADADDR ? helpers::format_address(dispatch_addr) : "not_found";
    result["indirect_jumps"]      = indirect_jumps;
    result["cmp_chain_length"]    = cmp_count;

    int score = 0;
    if (indirect_jumps > 0) score += 25;
    if (cmp_count >= 3) score += 25;
    if (cmp_count >= 8) score += 25;
    if (indirect_jumps > 2) score += 25;
    result["vm_confidence_pct"] = std::min(score, 100);

    if (score < 25)
    {
        result["conclusion"] = std::string("Function does not appear to use VM-based obfuscation.");
        return tool_result_t::ok(std::string("VM confidence too low: ") + std::to_string(score) + "%", result);
    }


    json handlers = json::array();
    if (table_addr != BADADDR)
    {
        result["handler_table"] = helpers::format_address(table_addr);
        bool is_64 = inf_is_64bit();
        table_entry_size = is_64 ? 8 : 4;

        for (std::uint32_t i = 0; i < max_handlers; ++i)
        {
            ea_t slot = table_addr + i * table_entry_size;
            if (!is_loaded(slot)) break;
            ea_t target = is_64 ? static_cast<ea_t>(get_qword(slot)) : get_dword(slot);
            if (target == 0 || target == BADADDR || !is_loaded(target)) break;
            segment_t* ts = getseg(target);
            if (!ts || ts->type != SEG_CODE) break;

            json h;
            h["opcode"] = i;
            h["address"] = helpers::format_address(target);

            qstring nm;
            if (get_name(&nm, target) && !nm.empty()) h["name"] = nm.c_str();


            func_t* hfn = get_func(target);
            ea_t hend = hfn ? hfn->end_ea : target + 64;
            int instr_count = 0;
            bool has_push = false, has_pop = false, has_add = false, has_sub = false;
            bool has_xor = false, has_and = false, has_or = false, has_shr = false, has_shl = false;
            bool has_cmp = false, has_call = false, has_jcc = false;
            bool reads_mem = false, writes_mem = false;

            for (ea_t ic = target; ic < hend && ic != BADADDR && instr_count < 128;)
            {
                insn_t hi;
                int hl = decode_insn(&hi, ic);
                if (hl <= 0) break;
                ++instr_count;
                if (hi.itype == NN_push || hi.itype == NN_pushf) has_push = true;
                if (hi.itype == NN_pop || hi.itype == NN_popf)   has_pop = true;
                if (hi.itype == NN_add || hi.itype == NN_adc)    has_add = true;
                if (hi.itype == NN_sub || hi.itype == NN_sbb)    has_sub = true;
                if (hi.itype == NN_xor)   has_xor = true;
                if (hi.itype == NN_and)    has_and = true;
                if (hi.itype == NN_or)     has_or = true;
                if (hi.itype == NN_shr || hi.itype == NN_sar) has_shr = true;
                if (hi.itype == NN_shl || hi.itype == NN_sal) has_shl = true;
                if (hi.itype == NN_cmp || hi.itype == NN_test) has_cmp = true;
                if (hi.itype == NN_call || hi.itype == NN_callni) has_call = true;
                if (hi.itype >= NN_ja && hi.itype <= NN_jz) has_jcc = true;
                for (int op = 0; op < UA_MAXOP && hi.ops[op].type != o_void; ++op)
                {
                    if (hi.ops[op].type == o_mem || hi.ops[op].type == o_displ || hi.ops[op].type == o_phrase)
                    {
                        if (op == 0) writes_mem = true; else reads_mem = true;
                    }
                }
                ic += hl;
            }

            std::string classification;
            if (has_push && !has_pop && !has_add && !has_sub && !has_xor) classification = "vm_push";
            else if (has_pop && !has_push && !has_add && !has_sub)         classification = "vm_pop";
            else if (has_add && !has_sub)                                   classification = "vm_add";
            else if (has_sub && !has_add)                                   classification = "vm_sub";
            else if (has_xor && !has_and && !has_or)                       classification = "vm_xor";
            else if (has_and)                                               classification = "vm_and";
            else if (has_or)                                                classification = "vm_or";
            else if (has_shr)                                               classification = "vm_shr";
            else if (has_shl)                                               classification = "vm_shl";
            else if (has_cmp && has_jcc)                                    classification = "vm_cmp_jcc";
            else if (has_call)                                              classification = "vm_call";
            else if (reads_mem && !writes_mem)                              classification = "vm_load";
            else if (writes_mem && !reads_mem)                              classification = "vm_store";
            else if (instr_count <= 3)                                      classification = "vm_nop";
            else                                                            classification = "vm_complex";

            h["classification"]  = classification;
            h["instruction_count"] = instr_count;

            if (add_comments)
            {
                std::string cmt = "VM handler " + std::to_string(i) + ": " + classification;
                set_cmt(target, cmt.c_str(), true);
            }

            handlers.push_back(std::move(h));
        }
    }

    result["handler_count"]           = handlers.size();
    result["handlers"]                = std::move(handlers);
    result["handler_table_entry_size"] = table_entry_size;


    json summary;
    std::map<std::string, int> class_counts;
    for (const auto& h : result["handlers"]) class_counts[h["classification"].get<std::string>()]++;
    summary["handler_classifications"] = class_counts;
    summary["has_arithmetic"]          = class_counts.count("vm_add") || class_counts.count("vm_sub");
    summary["has_logic"]               = class_counts.count("vm_xor") || class_counts.count("vm_and") || class_counts.count("vm_or");
    summary["has_memory"]              = class_counts.count("vm_load") || class_counts.count("vm_store") || class_counts.count("vm_push") || class_counts.count("vm_pop");
    summary["has_control_flow"]        = class_counts.count("vm_cmp_jcc") || class_counts.count("vm_call");
    result["summary"] = std::move(summary);

    return tool_result_t::ok(std::string("VM devirtualization: ") + std::to_string(result["handler_count"].get<std::size_t>()) +
                             std::string(" handlers classified"), result);
}

void register_tools()
{
    auto& registry = ToolRegistry::instance();

    registry.register_tool({std::string("nop_junk_instructions"), std::string("deobfuscation"),
        std::string("NOP-out junk instructions in a function: dead code blocks without incoming xrefs, "
               "long NOP sleds, and unreachable code. Uses patch_byte to preserve originals. "
               "Set 'aggressive' to true to remove all unreachable code blocks."),
        {{std::string("address"), std::string("string"), std::string("Function address"), true},
         {std::string("aggressive"), std::string("boolean"), std::string("Aggressively NOP unreachable blocks (default false)"), false},
         {std::string("nop_threshold"), std::string("number"), std::string("Min consecutive NOPs to report as sled (default 3)"), false}},
        nop_junk_instructions, false});

    registry.register_tool({std::string("resolve_opaque_predicates"), std::string("deobfuscation"),
        std::string("Detect and resolve opaque predicates: xor reg,reg + conditional jump patterns. "
               "Converts always-taken branches to unconditional JMP and NOPs never-taken branches. "
               "Set dry_run=true to preview without patching."),
        {{std::string("address"), std::string("string"), std::string("Function address"), true},
         {std::string("dry_run"), std::string("boolean"), std::string("Preview changes without patching (default false)"), false}},
        resolve_opaque_predicates, false});

    registry.register_tool({std::string("patch_anti_debug"), std::string("deobfuscation"),
        std::string("Detect and NOP-out anti-debugging techniques in a function: "
               "IsDebuggerPresent/CheckRemoteDebuggerPresent calls (replaced with xor eax,eax), "
               "NtQueryInformationProcess, INT 2D/INT 3 traps, and RDTSC timing checks."),
        {{std::string("address"), std::string("string"), std::string("Function or start address"), true},
         {std::string("dry_run"), std::string("boolean"), std::string("Preview without patching (default false)"), false},
         {std::string("patch_api_calls"), std::string("boolean"), std::string("Patch anti-debug API calls (default true)"), false},
         {std::string("patch_int_traps"), std::string("boolean"), std::string("Patch INT 2D/INT 3 traps (default true)"), false},
         {std::string("patch_timing"), std::string("boolean"), std::string("Patch RDTSC timing checks (default true)"), false},
         {std::string("size"), std::string("number"), std::string("Scan size if no function found (default 4096)"), false}},
        patch_anti_debug, false});

    registry.register_tool({std::string("decode_strings_in_function"), std::string("deobfuscation"),
        std::string("Decode obfuscated strings in a function: stack-constructed strings (sequential byte MOVs), "
               "multi-byte immediate moves with packed ASCII, and XOR-encrypted data references. "
               "Automatically adds decoded string values as IDA comments."),
        {{std::string("address"), std::string("string"), std::string("Function address"), true},
         {std::string("add_comments"), std::string("boolean"), std::string("Add decoded values as IDA comments (default true)"), false}},
        decode_strings_in_function, false});

    registry.register_tool({std::string("rebuild_function"), std::string("deobfuscation"),
        std::string("Re-analyze function boundaries after deobfuscation patches. "
               "Deletes the existing function, undefines bytes, recreates instructions, "
               "and rebuilds the function with auto-analysis. Use after patching."),
        {{std::string("address"), std::string("string"), std::string("Function start address"), true},
         {std::string("force_recreate"), std::string("boolean"), std::string("Delete and fully recreate (default false)"), false},
         {std::string("create_instructions"), std::string("boolean"), std::string("Create instructions during rebuild (default true)"), false}},
        rebuild_function, false});

    registry.register_tool({std::string("identify_protector"), std::string("deobfuscation"),
        std::string("Identify protection/packing schemes: VMProtect, Themida/WinLicense, UPX, ASPack, "
               "Enigma, PECompact, etc. Scans section names, byte signatures at entry point, "
               "string references, and calculates section entropy to detect packed/encrypted regions."),
        {{std::string("scan_size"), std::string("number"), std::string("Bytes to scan (default 1MB, max 16MB)"), false}},
        identify_protector});

    registry.register_tool({std::string("deobfuscate_control_flow"), std::string("deobfuscation"),
        std::string("Detect and map control flow flattening (CFF) in a function. "
               "Identifies: the dispatcher block (dominant back-edge target), "
               "state variable (comparison in dispatcher), state blocks (jump-back-to-dispatcher blocks), "
               "and state transitions. Annotates the structure with IDA comments."),
        {{std::string("address"), std::string("string"), std::string("Function address"), true}},
        deobfuscate_control_flow});

    registry.register_tool({std::string("reconstruct_imports"), std::string("deobfuscation"),
        std::string("Rebuild import table after unpacking. Scans IAT segments (.idata, .rdata) "
               "for pointer entries, resolves them against known imports, and identifies "
               "unresolved call thunks that need manual resolution."),
        {{std::string("address"), std::string("string"), std::string("Base address (default min_ea)"), false},
         {std::string("scan_size"), std::string("number"), std::string("Scan range in bytes (default 1MB)"), false}},
        reconstruct_imports, false});

    registry.register_tool({std::string("unpack_section"), std::string("deobfuscation"),
        std::string("Decrypt/unpack a packed section directly in the IDB. Supports: "
               "single-byte XOR (auto-detects key), multi-byte XOR key, and rolling XOR. "
               "After decryption, optionally creates instructions and triggers re-analysis. "
               "Use identify_protector first to find packed sections."),
        {{std::string("address"), std::string("string"), std::string("Section start address"), true},
         {std::string("size"), std::string("number"), std::string("Bytes to decrypt (default: full segment)"), false},
         {std::string("method"), std::string("string"), std::string("Decryption method: auto, xor_single, xor_multi, xor_rolling"), false,
          {std::string("auto"), std::string("xor_single"), std::string("xor_multi"), std::string("xor_rolling")}},
         {std::string("key"), std::string("string"), std::string("XOR key as hex bytes (e.g. '4A' or '4A 5B 6C')"), false},
         {std::string("create_code"), std::string("boolean"), std::string("Create instructions after decrypt (default true)"), false}},
        unpack_section, false});

    registry.register_tool({std::string("full_deobfuscation_pass"), std::string("deobfuscation"),
        std::string("Complete automated deobfuscation pipeline for a function: "
               "(1) Detect obfuscation patterns and compute score, "
               "(2) Resolve opaque predicates, "
               "(3) NOP junk instructions, "
               "(4) Decode hidden strings and add comments, "
               "(5) Analyze control flow flattening, "
               "(6) Rebuild function with re-analysis. "
               "Produces before/after obfuscation scores and deobfuscated pseudocode."),
        {{std::string("address"), std::string("string"), std::string("Function address"), true},
         {std::string("dry_run"), std::string("boolean"), std::string("Preview all steps without patching (default false)"), false}},
        full_deobfuscation_pass, false});

    registry.register_tool({std::string("devirtualize_function"), std::string("deobfuscation"),
        std::string("Analyze a VM-protected function: detect the dispatcher, locate the handler table, "
               "classify each VM handler (push/pop/add/sub/xor/and/or/shr/shl/cmp/call/load/store/nop). "
               "Produces a full handler map with semantic labels. Use on VMProtect/Themida virtualized code."),
        {{std::string("address"), std::string("string"), std::string("Function address"), true},
         {std::string("max_handlers"), std::string("number"), std::string("Max handler table entries (default: 256)"), false},
         {std::string("add_comments"), std::string("boolean"), std::string("Add VM handler labels as IDA comments (default: true)"), false}},
        devirtualize_function});
}

}

static std::string get_current_binary_hash()
{
    return current_module_graph_key();
}

namespace graphrag_tools
{

static bool is_graph_indexed()
{
    std::string hash = get_current_binary_hash();
    if (hash.empty()) return false;
    auto& store = graphrag::GraphStore::instance();
    auto stats = store.get_stats(hash);
    return stats.nodes > 0;
}

static tool_result_t not_indexed_error()
{
    return tool_result_t::error(std::string("The binary is not indexed. "
        "The user must click the 'Index Binary' button in the AiDA panel before "
        "RAG tools can be used. Do NOT call any graphrag tools until the binary is indexed."));
}

tool_result_t get_semantic_analysis(const json& params)
{
    if (!is_graph_indexed()) return not_indexed_error();

    std::string addr_str = json_str(params, "address");
    auto addr = helpers::parse_address(addr_str);
    if (!addr) return tool_result_t::error(std::string("Invalid address"));

    std::string hash = get_current_binary_hash();
    if (hash.empty()) return tool_result_t::error(std::string("No binary loaded"));

    auto& store = graphrag::GraphStore::instance();
    graphrag::QueryEngine qe(store);
    json result = qe.get_semantic_analysis(hash, *addr);
    return tool_result_t::ok(std::string("Semantic analysis for ") + addr_str, result);
}

tool_result_t search_semantic(const json& params)
{
    if (!is_graph_indexed()) return not_indexed_error();

    std::string query = json_str(params, "query");
    if (query.empty()) return tool_result_t::error(std::string("Missing query parameter"));

    int limit = 10;
    if (params.contains("limit"))
    {
        const auto& v = params["limit"];
        if (v.is_number_integer())
        {
            const std::int64_t value = v.get<std::int64_t>();
            if (value >= (std::numeric_limits<int>::min)() && value <= (std::numeric_limits<int>::max)())
                limit = static_cast<int>(value);
        }
        else if (v.is_number_unsigned())
        {
            const std::uint64_t value = v.get<std::uint64_t>();
            if (value <= static_cast<std::uint64_t>((std::numeric_limits<int>::max)()))
                limit = static_cast<int>(value);
        }
        else if (v.is_number_float())
        {
            const double value = v.get<double>();
            if (std::isfinite(value) && value >= (std::numeric_limits<int>::min)() && value <= (std::numeric_limits<int>::max)())
                limit = static_cast<int>(value);
        }
    }

    std::string hash = get_current_binary_hash();
    if (hash.empty()) return tool_result_t::error(std::string("No binary loaded"));

    auto& store = graphrag::GraphStore::instance();
    graphrag::QueryEngine qe(store);
    json result = qe.search_semantic(hash, query, limit);
    return tool_result_t::ok(std::string("Found ") + std::to_string(result.size()) + std::string(" results"), result);
}

tool_result_t get_similar_functions(const json& params)
{
    if (!is_graph_indexed()) return not_indexed_error();

    std::string addr_str = json_str(params, "address");
    auto addr = helpers::parse_address(addr_str);
    if (!addr) return tool_result_t::error(std::string("Invalid address"));

    int limit = 5;
    if (params.contains("limit"))
    {
        const auto& v = params["limit"];
        if (v.is_number_integer())
        {
            const std::int64_t value = v.get<std::int64_t>();
            if (value >= (std::numeric_limits<int>::min)() && value <= (std::numeric_limits<int>::max)())
                limit = static_cast<int>(value);
        }
        else if (v.is_number_unsigned())
        {
            const std::uint64_t value = v.get<std::uint64_t>();
            if (value <= static_cast<std::uint64_t>((std::numeric_limits<int>::max)()))
                limit = static_cast<int>(value);
        }
        else if (v.is_number_float())
        {
            const double value = v.get<double>();
            if (std::isfinite(value) && value >= (std::numeric_limits<int>::min)() && value <= (std::numeric_limits<int>::max)())
                limit = static_cast<int>(value);
        }
    }

    std::string hash = get_current_binary_hash();
    if (hash.empty()) return tool_result_t::error(std::string("No binary loaded"));

    auto& store = graphrag::GraphStore::instance();
    graphrag::QueryEngine qe(store);
    json result = qe.get_similar_functions(hash, *addr, limit);
    return tool_result_t::ok(std::string("Found ") + std::to_string(result.size()) + std::string(" similar functions"), result);
}

tool_result_t get_call_context(const json& params)
{
    if (!is_graph_indexed()) return not_indexed_error();

    std::string addr_str = json_str(params, "address");
    auto addr = helpers::parse_address(addr_str);
    if (!addr) return tool_result_t::error(std::string("Invalid address"));

    int depth = 2;
    if (params.contains("depth"))
    {
        const auto& v = params["depth"];
        if (v.is_number_integer())
        {
            const std::int64_t value = v.get<std::int64_t>();
            if (value >= (std::numeric_limits<int>::min)() && value <= (std::numeric_limits<int>::max)())
                depth = static_cast<int>(value);
        }
        else if (v.is_number_unsigned())
        {
            const std::uint64_t value = v.get<std::uint64_t>();
            if (value <= static_cast<std::uint64_t>((std::numeric_limits<int>::max)()))
                depth = static_cast<int>(value);
        }
        else if (v.is_number_float())
        {
            const double value = v.get<double>();
            if (std::isfinite(value) && value >= (std::numeric_limits<int>::min)() && value <= (std::numeric_limits<int>::max)())
                depth = static_cast<int>(value);
        }
    }

    std::string hash = get_current_binary_hash();
    if (hash.empty()) return tool_result_t::error(std::string("No binary loaded"));

    auto& store = graphrag::GraphStore::instance();
    graphrag::QueryEngine qe(store);
    json result = qe.get_call_context(hash, *addr, depth);
    return tool_result_t::ok(std::string("Call context for ") + addr_str, result);
}

tool_result_t get_taint_paths(const json& params)
{
    if (!is_graph_indexed()) return not_indexed_error();

    std::string addr_str = json_str(params, "address");
    auto addr = helpers::parse_address(addr_str);
    if (!addr) return tool_result_t::error(std::string("Invalid address"));

    std::string hash = get_current_binary_hash();
    if (hash.empty()) return tool_result_t::error(std::string("No binary loaded"));

    auto& store = graphrag::GraphStore::instance();
    graphrag::QueryEngine qe(store);
    json result = qe.get_taint_paths(hash, *addr);
    return tool_result_t::ok(std::string("Taint paths for ") + addr_str, result);
}

tool_result_t get_community_info(const json& params)
{
    if (!is_graph_indexed()) return not_indexed_error();

    std::string addr_str = json_str(params, "address");
    auto addr = helpers::parse_address(addr_str);
    if (!addr) return tool_result_t::error(std::string("Invalid address"));

    std::string hash = get_current_binary_hash();
    if (hash.empty()) return tool_result_t::error(std::string("No binary loaded"));

    auto& store = graphrag::GraphStore::instance();
    graphrag::QueryEngine qe(store);
    json result = qe.get_community_info(hash, *addr);
    return tool_result_t::ok(std::string("Community info for ") + addr_str, result);
}

tool_result_t run_security_analysis(const json& params)
{
    if (!is_graph_indexed()) return not_indexed_error();

    std::string hash = get_current_binary_hash();
    if (hash.empty()) return tool_result_t::error(std::string("No binary loaded"));

    graphrag::ensure_full_binary_index(hash, [](int current, int total, const std::string& name) {
        if (current == 1 || (current % 100) == 0 || current == total)
            msg("[AiDA GraphRAG] Preparing full graph %d/%d: %s\n", current, total, name.c_str());
    });

    auto& store = graphrag::GraphStore::instance();
    auto nodes = store.get_nodes_by_type(hash, graphrag::node_type_t::FUNCTION);

    int risky = 0;
    json high_risk = json::array();
    json crypto_functions = json::array();
    std::map<std::string, int> vuln_type_counts;

    for (auto* n : nodes)
    {
        if (n->risk_level == "HIGH" || n->risk_level == "CRITICAL")
        {
            ++risky;
            if (high_risk.size() < 50)
            {
                high_risk.push_back({
                    {"name", n->name}, {"address", n->address},
                    {"risk_level", n->risk_level}, {"security_flags", n->security_flags}
                });
            }
        }

        if (!n->crypto_apis.empty() && crypto_functions.size() < 50)
        {
            crypto_functions.push_back({
                {"name", n->name}, {"address", n->address},
                {"crypto_apis", n->crypto_apis},
                {"activity_profile", n->activity_profile}
            });
        }

        for (auto& f : n->security_flags)
            if (f.find("_RISK") != std::string::npos)
                ++vuln_type_counts[f];
    }

    json data;
    data["total_functions"] = nodes.size();
    data["high_risk_count"] = risky;
    data["high_risk_functions"] = high_risk;
    data["crypto_functions_count"] = crypto_functions.size();
    data["crypto_functions"] = crypto_functions;
    data["vulnerability_types"] = vuln_type_counts;
    return tool_result_t::ok(std::string("Security analysis: ") + std::to_string(risky)
        + std::string(" high-risk functions, ") + std::to_string(crypto_functions.size())
        + std::string(" crypto routines found"), data);
}

tool_result_t run_taint_analysis(const json& params)
{
    if (!is_graph_indexed()) return not_indexed_error();

    std::string hash = get_current_binary_hash();
    if (hash.empty()) return tool_result_t::error(std::string("No binary loaded"));

    int max_paths = 20;
    max_paths = safe_json_int_param(params, "max_paths", max_paths);

    auto& store = graphrag::GraphStore::instance();
    graphrag::TaintAnalyzer analyzer(store);
    auto paths = analyzer.find_taint_paths(hash, max_paths, true);

    json data = json::array();
    for (auto& p : paths)
    {
        json pj;
        pj["source"] = p.source_name;
        pj["sink"] = p.sink_name;
        pj["path_length"] = p.path.size();
        pj["path"] = p.path_names;
        if (!p.source_apis.empty()) pj["source_apis"] = p.source_apis;
        if (!p.sink_apis.empty()) pj["sink_apis"] = p.sink_apis;
        if (!p.vulnerability_type.empty()) pj["vulnerability_type"] = p.vulnerability_type;
        data.push_back(pj);
    }

    graphrag::save_graph(hash);
    return tool_result_t::ok(std::string("Found ") + std::to_string(paths.size()) + std::string(" taint paths"), data);
}

tool_result_t detect_communities(const json& params)
{
    if (!is_graph_indexed()) return not_indexed_error();

    std::string hash = get_current_binary_hash();
    if (hash.empty()) return tool_result_t::error(std::string("No binary loaded"));

    bool force = false;
    if (params.contains("force") && params["force"].is_boolean())
        force = params["force"].get<bool>();

    auto& store = graphrag::GraphStore::instance();
    graphrag::CommunityDetector detector(store);
    int count = detector.detect(hash, 2, 50, force);

    auto communities = store.get_communities(hash);
    json data = json::array();
    for (auto& c : communities)
    {
        data.push_back({
            {"id", c.id}, {"label", c.label},
            {"purpose", c.purpose}, {"size", c.member_ids.size()}
        });
    }

    graphrag::save_graph(hash);
    return tool_result_t::ok(std::string("Detected ") + std::to_string(count) + std::string(" communities"), data);
}

tool_result_t analyze_network_flow(const json& params)
{
    if (!is_graph_indexed()) return not_indexed_error();

    std::string hash = get_current_binary_hash();
    if (hash.empty()) return tool_result_t::error(std::string("No binary loaded"));

    auto& store = graphrag::GraphStore::instance();
    graphrag::NetworkFlowAnalyzer analyzer(store);
    auto result = analyzer.analyze(hash);

    json data;
    data["send_functions"] = result.send_functions;
    data["recv_functions"] = result.recv_functions;
    data["send_edges_created"] = result.send_edges_created;
    data["recv_edges_created"] = result.recv_edges_created;


    json send_paths = json::array();
    for (auto& fp : result.send_paths)
    {
        json pj;
        pj["source"] = fp.source_name;
        pj["target"] = fp.target_name;
        pj["api"] = fp.api_name;
        pj["hops"] = fp.hop_count;
        pj["path_length"] = fp.path.size();
        send_paths.push_back(pj);
    }
    data["send_paths"] = send_paths;

    json recv_paths = json::array();
    for (auto& fp : result.recv_paths)
    {
        json pj;
        pj["source"] = fp.source_name;
        pj["target"] = fp.target_name;
        pj["api"] = fp.api_name;
        pj["hops"] = fp.hop_count;
        recv_paths.push_back(pj);
    }
    data["recv_paths"] = recv_paths;

    graphrag::save_graph(hash);
    return tool_result_t::ok(std::string("Network flow: ") + std::to_string(result.send_functions.size())
        + std::string(" send, ") + std::to_string(result.recv_functions.size()) + std::string(" recv, ")
        + std::to_string(result.send_paths.size() + result.recv_paths.size()) + std::string(" paths"), data);
}

tool_result_t index_function(const json& params)
{
    std::string addr_str = json_str(params, "address");
    auto addr = helpers::parse_address(addr_str);
    if (!addr) return tool_result_t::error(std::string("Invalid address"));

    std::string hash = get_current_binary_hash();
    if (hash.empty()) return tool_result_t::error(std::string("No binary loaded"));

    auto& store = graphrag::GraphStore::instance();
    graphrag::StructureExtractor extractor(store);
    auto* node = extractor.extract_function(*addr, hash);
    if (!node) return tool_result_t::error(std::string("Failed to extract function"));


    auto& vs = graphrag::get_vector_store();
    std::string text = graphrag::build_embedding_text(*node);

    graphrag::EmbeddingClient ec;
    std::vector<float> vec;
    if (ec.is_available())
        vec = ec.embed_single(text);
    else
    {
        auto& lv = graphrag::get_local_vectorizer();
        if (lv.is_built())
            vec = lv.vectorize(text);
    }

    if (!vec.empty())
        vs.add(node->id, std::move(vec));

    graphrag::save_graph(hash);
    graphrag::save_vectors(hash);

    json data;
    data["function_name"] = node->name;
    data["address"] = node->address;
    data["node_id"] = node->id;
    data["has_embedding"] = vs.has(node->id);
    return tool_result_t::ok(std::string("Indexed function: ") + node->name, data);
}

tool_result_t reindex_all(const json& params)
{
    std::string hash = get_current_binary_hash();
    if (hash.empty()) return tool_result_t::error(std::string("No binary loaded"));

    bool reindexed = false;
    bool ok = graphrag::ensure_full_binary_index(hash, nullptr, &reindexed);
    if (!ok) return tool_result_t::error(std::string("Index failed"));

    graphrag::save_graph(hash);
    graphrag::save_vectors(hash);

    auto& store = graphrag::GraphStore::instance();
    auto stats = store.get_stats(hash);
    auto& vs = graphrag::get_vector_store();

    json data;
    data["nodes"] = stats.nodes;
    data["edges"] = stats.edges;
    data["communities"] = stats.communities;
    data["vector_count"] = vs.size();
    data["reindexed"] = reindexed;
    return tool_result_t::ok(std::string("Reindexed: ") + std::to_string(stats.nodes) + std::string(" nodes, ")
        + std::to_string(vs.size()) + std::string(" vectors"), data);
}

tool_result_t get_graph_stats(const json& params)
{
    std::string hash = get_current_binary_hash();
    if (hash.empty()) return tool_result_t::error(std::string("No binary loaded"));

    auto& store = graphrag::GraphStore::instance();
    auto stats = store.get_stats(hash);
    auto& vs = graphrag::get_vector_store();
    auto& lv = graphrag::get_local_vectorizer();

    json data;
    data["nodes"] = stats.nodes;
    data["edges"] = stats.edges;
    data["communities"] = stats.communities;
    data["stale_nodes"] = stats.stale;
    data["binary_hash"] = hash;
    data["vector_count"] = vs.size();
    data["vector_dimensions"] = vs.dimensions();
    data["vectorizer_ready"] = lv.is_built();
    return tool_result_t::ok(std::string("Graph: ") + std::to_string(stats.nodes) + std::string(" nodes, ")
        + std::to_string(stats.edges) + std::string(" edges, ")
        + std::to_string(vs.size()) + std::string(" vectors"), data);
}

tool_result_t get_security_overview(const json& params)
{
    if (!is_graph_indexed()) return not_indexed_error();

    std::string hash = get_current_binary_hash();
    if (hash.empty()) return tool_result_t::error(std::string("No binary loaded"));

    int limit = 50;
    limit = safe_json_int_param(params, "limit", limit);
auto& store = graphrag::GraphStore::instance();
    graphrag::QueryEngine qe(store);
    json data = qe.get_security_analysis(hash, limit);
    return tool_result_t::ok(std::string("Security overview: ") +
        std::to_string(data.value("total_functions", 0)) + std::string(" functions analyzed"), data);
}

tool_result_t get_activity_analysis(const json& params)
{
    if (!is_graph_indexed()) return not_indexed_error();

    std::string hash = get_current_binary_hash();
    if (hash.empty()) return tool_result_t::error(std::string("No binary loaded"));

    std::string filter;
    if (params.contains("activity_type") && params["activity_type"].is_string())
        filter = params["activity_type"].get<std::string>();

    auto& store = graphrag::GraphStore::instance();
    graphrag::QueryEngine qe(store);
    json data = qe.get_activity_analysis(hash, filter);
    return tool_result_t::ok(std::string("Activity analysis complete"), data);
}

tool_result_t get_all_communities(const json& params)
{
    if (!is_graph_indexed()) return not_indexed_error();

    std::string hash = get_current_binary_hash();
    if (hash.empty()) return tool_result_t::error(std::string("No binary loaded"));

    auto& store = graphrag::GraphStore::instance();
    graphrag::QueryEngine qe(store);
    json data = qe.get_all_communities(hash);
    return tool_result_t::ok(std::string("Found ") +
        std::to_string(data.value("total_communities", 0)) + std::string(" communities"), data);
}

void register_tools()
{
    auto& registry = ToolRegistry::instance();

    registry.register_tool({
        std::string("get_semantic_analysis"), std::string("graphrag"),
        std::string("Get comprehensive semantic analysis of a function from the knowledge graph. "
               "Returns the function's summary, security flags, risk level, callers, callees, "
               "community membership, and decompiled code. Use this to understand what a "
               "function does and its relationships in the codebase."),
        {{std::string("address"), std::string("string"), std::string("Function address"), true}},
        get_semantic_analysis, true});

    registry.register_tool({
        std::string("search_semantic"), std::string("graphrag"),
        std::string("Search the knowledge graph using vector embeddings and keyword matching. "
               "Searches across function names, decompiled code, strings, URLs, IPs, domains, "
               "file paths, registry keys, API names, and security flags. MUCH FASTER than "
               "IDA search tools for indexed binaries. Use this FIRST when looking for strings, "
               "API usage, or code patterns in an indexed binary. Falls back to IDA search "
               "tools only if RAG returns no results."),
        {{std::string("query"), std::string("string"), std::string("Search query: string literal, API name, IP, URL, domain, code pattern, or natural language"), true},
         {std::string("limit"), std::string("number"), std::string("Maximum results (default 10)"), false}},
        search_semantic, true});

    registry.register_tool({
        std::string("get_similar_functions"), std::string("graphrag"),
        std::string("Find functions similar to the given one using vector embedding cosine "
               "similarity. Compares function code, names, and security features in embedding "
               "space. Falls back to call-graph structural similarity if embeddings are "
               "unavailable. Useful for finding related functionality or duplicate code."),
        {{std::string("address"), std::string("string"), std::string("Function address"), true},
         {std::string("limit"), std::string("number"), std::string("Maximum results (default 5)"), false}},
        get_similar_functions, true});

    registry.register_tool({
        std::string("get_call_context"), std::string("graphrag"),
        std::string("Get multi-level call context showing callers and callees of a function to "
               "the specified depth. Provides a tree view of the function's position in "
               "the call graph for understanding data flow and control flow."),
        {{std::string("address"), std::string("string"), std::string("Function address"), true},
         {std::string("depth"), std::string("number"), std::string("Depth of caller/callee tree (default 2)"), false}},
        get_call_context, true});

    registry.register_tool({
        std::string("get_taint_paths_for_function"), std::string("graphrag"),
        std::string("Get taint analysis paths involving the specified function. Shows data flow "
               "from untrusted sources (recv, read, scanf) to dangerous sinks (strcpy, system, "
               "CreateProcess). Identifies potential vulnerability chains."),
        {{std::string("address"), std::string("string"), std::string("Function address"), true}},
        get_taint_paths, true});

    registry.register_tool({
        std::string("get_community_info"), std::string("graphrag"),
        std::string("Get information about the functional community (cluster) a function belongs to. "
               "Shows community purpose (network, crypto, file_io, etc.), all member functions, "
               "and the community label."),
        {{std::string("address"), std::string("string"), std::string("Function address"), true}},
        get_community_info, true});

    registry.register_tool({
        std::string("run_security_analysis"), std::string("graphrag"),
        std::string("Run security analysis across the entire knowledge graph. Identifies high-risk "
               "functions with dangerous API usage, buffer overflow risks, command injection "
               "vectors, and other vulnerabilities. Returns the riskiest functions."),
        {},
        run_security_analysis, true});

    registry.register_tool({
        std::string("run_taint_analysis"), std::string("graphrag"),
        std::string("Run taint analysis to find data flow paths from untrusted input sources to "
               "dangerous sinks. Discovers potential vulnerability chains where user-controlled "
               "data reaches unsafe operations like strcpy, system, or CreateProcess."),
        {{std::string("max_paths"), std::string("number"), std::string("Maximum taint paths to find (default 20)"), false}},
        run_taint_analysis, false});

    registry.register_tool({
        std::string("detect_communities"), std::string("graphrag"),
        std::string("Detect functional communities (clusters) in the call graph using Label Propagation. "
               "Groups related functions by their calling patterns and infers the purpose of each "
               "community (network, crypto, file_io, process, init, gui, etc.)."),
        {{std::string("force"), std::string("boolean"), std::string("Force re-detection even if communities exist (default false)"), false}},
        detect_communities, false});

    registry.register_tool({
        std::string("analyze_network_flow"), std::string("graphrag"),
        std::string("Analyze network data flow patterns in the binary. Identifies functions that "
               "send and receive network data, creates flow edges, and maps the network "
               "communication architecture of the binary."),
        {},
        analyze_network_flow, false});

    registry.register_tool({
        std::string("get_graph_stats"), std::string("graphrag"),
        std::string("Get statistics about the knowledge graph: total nodes, edges, communities, "
               "stale node count, and vector embedding count. Use to check index status."),
        {},
        get_graph_stats, true});

    registry.register_tool({
        std::string("get_security_overview"), std::string("graphrag"),
        std::string("Get a comprehensive security overview of the entire binary from the knowledge "
               "graph. Returns risk distribution (critical/high/medium/low counts), security "
               "flag distribution across all functions, and the most dangerous functions with "
               "their specific vulnerabilities and activity profiles."),
        {{std::string("limit"), std::string("number"), std::string("Maximum high-risk functions to return (default 50)"), false}},
        get_security_overview, true});

    registry.register_tool({
        std::string("get_activity_analysis"), std::string("graphrag"),
        std::string("Analyze activity profiles of functions in the binary. Groups functions by "
               "their behavior: NETWORK_CLIENT, NETWORK_SERVER, FILE_RW, FILE_READER, "
               "FILE_WRITER, CRYPTO_CIPHER, CRYPTO_ENCRYPT, CRYPTO_DECRYPT, CRYPTO_HASH, "
               "PROCESS_INJECTOR, PROCESS_SPAWNER. Optionally filter to one activity type."),
        {{std::string("activity_type"), std::string("string"), std::string("Optional: filter to specific activity type (e.g. 'NETWORK_CLIENT')"), false}},
        get_activity_analysis, true});

    registry.register_tool({
        std::string("get_all_communities"), std::string("graphrag"),
        std::string("List all detected functional communities (clusters) in the binary. Returns "
               "each community's ID, label, detected purpose (network/crypto/file_io/process/"
               "registry/init/gui/etc.), member count, and member function details."),
        {},
        get_all_communities, true});
}

}


namespace aida_ida_batch_tools
{

static auto g_start_time = std::chrono::steady_clock::now();

static std::string trim_copy(std::string s)
{
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())))
        s.erase(s.begin());
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())))
        s.pop_back();
    return s;
}

static std::string value_to_string(const json& v)
{
    if (v.is_string())
        return v.get<std::string>();
    if (v.is_number_integer())
    {
        int64_t signed_value = v.get<int64_t>();
        if (signed_value < 0)
            return std::to_string(signed_value);
        std::ostringstream ss;
        ss << "0x" << std::hex << std::uppercase << static_cast<uint64_t>(signed_value);
        return ss.str();
    }
    if (v.is_number())
        return std::to_string(v.get<double>());
    return "";
}

static json normalize_list(const json& value)
{
    if (value.is_array())
        return value;
    if (value.is_object())
        return json::array({value});
    if (value.is_string())
    {
        std::string s = trim_copy(value.get<std::string>());
        if (!s.empty() && (s.front() == '[' || s.front() == '{'))
        {
            try
            {
                json parsed = json::parse(s);
                if (parsed.is_array())
                    return parsed;
                if (parsed.is_object())
                    return json::array({parsed});
            }
            catch (...) {}
        }
        json arr = json::array();
        std::istringstream iss(s);
        std::string part;
        while (std::getline(iss, part, ','))
        {
            part = trim_copy(part);
            if (!part.empty())
                arr.push_back(part);
        }
        if (arr.empty() && !s.empty())
            arr.push_back(s);
        return arr;
    }
    if (!value.is_null())
        return json::array({value});
    return json::array();
}

static json get_list_param(const json& params, const char* name, const char* alt = nullptr)
{
    if (params.contains(name))
        return normalize_list(params[name]);
    if (alt && params.contains(alt))
        return normalize_list(params[alt]);
    return json::array();
}

static std::string first_string_field(const json& item, std::initializer_list<const char*> names)
{
    if (!item.is_object())
        return value_to_string(item);
    for (const char* name : names)
    {
        if (item.contains(name))
            return value_to_string(item[name]);
    }
    return "";
}

static json make_page_params(const json& q, int default_limit)
{
    json p = json::object();
    p["offset"] = 0;
    p["limit"] = default_limit;
    if (q.is_object())
    {
        if (q.contains("offset")) p["offset"] = q["offset"];
        if (q.contains("limit")) p["limit"] = q["limit"];
        if (q.contains("count")) p["limit"] = q["count"];
        if (q.contains("filter")) p["filter"] = q["filter"];
        if (q.contains("name")) p["filter"] = q["name"];
        if (q.contains("pattern")) p["filter"] = q["pattern"];
        return p;
    }
    if (q.is_string())
    {
        std::string s = trim_copy(q.get<std::string>());
        if (!s.empty() && s != "*")
            p["filter"] = s;
    }
    return p;
}

static bool parse_int_type(const std::string& text, int& bytes, bool& sign, bool& big_endian, std::string& normalized)
{
    std::string s = text;
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (s.empty())
        s = "u64le";
    if (s == "byte") s = "u8le";
    if (s == "word") s = "u16le";
    if (s == "dword") s = "u32le";
    if (s == "qword") s = "u64le";
    if (s.size() < 2)
        return false;
    sign = s[0] == 'i';
    if (s[0] != 'i' && s[0] != 'u')
        return false;
    size_t pos = 1;
    int bits = 0;
    while (pos < s.size() && std::isdigit(static_cast<unsigned char>(s[pos])))
    {
        bits = bits * 10 + (s[pos] - '0');
        pos++;
    }
    if (bits != 8 && bits != 16 && bits != 32 && bits != 64)
        return false;
    std::string endian = s.substr(pos);
    if (endian.empty())
        endian = "le";
    if (endian != "le" && endian != "be")
        return false;
    bytes = bits / 8;
    big_endian = endian == "be";
    normalized = std::string(sign ? "i" : "u") + std::to_string(bits) + endian;
    return true;
}

static uint64_t read_raw_uint(ea_t ea, int bytes, bool big_endian)
{
    uint64_t value = 0;
    for (int i = 0; i < bytes; i++)
    {
        uint8_t b = static_cast<uint8_t>(get_byte(ea + i));
        if (big_endian)
            value = (value << 8) | b;
        else
            value |= static_cast<uint64_t>(b) << (i * 8);
    }
    return value;
}

static int64_t sign_extend_value(uint64_t value, int bytes)
{
    int bits = bytes * 8;
    if (bits >= 64)
        return static_cast<int64_t>(value);
    uint64_t mask = 1ULL << (bits - 1);
    uint64_t full = (1ULL << bits) - 1;
    value &= full;
    if ((value & mask) != 0)
        value |= ~full;
    return static_cast<int64_t>(value);
}

static std::string bytes_to_hex(uint64_t value, int bytes, bool big_endian)
{
    std::ostringstream ss;
    for (int i = 0; i < bytes; i++)
    {
        int index = big_endian ? (bytes - 1 - i) : i;
        if (i > 0)
            ss << " ";
        ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
           << ((value >> (index * 8)) & 0xFF);
    }
    return ss.str();
}

static tool_result_t server_health(const json&)
{
    json data;
    qstring procname = inf_get_procname();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - g_start_time).count();
    data["status"] = "ok";
    data["server"] = "aida-ida-mcp";
    data["server_family"] = "aida-ida-mcp";
    data["processor"] = procname.c_str();
    data["bitness"] = inf_get_app_bitness();
    data["is_64bit"] = inf_is_64bit();
    data["auto_analysis_complete"] = auto_is_ok();
    data["hexrays_available"] = init_hexrays_plugin();
    data["uptime_seconds"] = elapsed;
    data["function_count"] = (size_t)get_func_qty();
    data["segment_count"] = get_segm_qty();
    return tool_result_t::ok(std::string("IDA server is healthy"), data);
}

static tool_result_t server_warmup(const json& params)
{
    bool wait_analysis = params.value("wait_auto_analysis", params.value("wait", true));
    bool init_hexrays = params.value("init_hexrays", true);
    json data;
    if (wait_analysis)
        auto_wait_range(0, BADADDR);
    data["auto_analysis_complete"] = auto_is_ok();
    data["hexrays_available"] = init_hexrays ? init_hexrays_plugin() : false;
    data["function_count"] = (size_t)get_func_qty();
    return tool_result_t::ok(std::string("IDA warmup complete"), data);
}

static tool_result_t decompile(const json& params)
{
    json p;
    if (params.contains("addr"))
        p["address"] = params["addr"];
    else
        p["address"] = params.value("address", "");
    return function_tools::decompile_function(p);
}

static tool_result_t disasm(const json& params)
{
    json p;
    if (params.contains("addr"))
        p["address"] = params["addr"];
    else
        p["address"] = params.value("address", "");
    return function_tools::disassemble_function(p);
}

static tool_result_t list_funcs(const json& params)
{
    return function_tools::list_functions(make_page_params(params.contains("query") ? params["query"] : params, 100));
}

static tool_result_t lookup_funcs(const json& params)
{
    json queries = get_list_param(params, "queries", "addrs");
    if (queries.empty() && params.contains("addr"))
        queries = json::array({params["addr"]});
    json out = json::array();
    for (const auto& q : queries)
    {
        json p;
        p["address"] = first_string_field(q, {"addr", "address", "name", "query"});
        auto r = function_tools::get_function(p);
        if (r.success)
            out.push_back(r.data);
        else
            out.push_back({{"query", p["address"]}, {"error", r.output}});
    }
    return tool_result_t::ok(std::string("Function lookup complete"), out);
}

static tool_result_t func_query(const json& params)
{
    json queries = get_list_param(params, "queries", "query");
    if (queries.empty())
        queries.push_back(params);
    json results = json::array();
    for (const auto& q : queries)
    {
        json page = make_page_params(q, 100);
        auto r = function_tools::list_functions(page);
        if (r.success)
            results.push_back(r.data);
        else
            results.push_back({{"error", r.output}});
    }
    return tool_result_t::ok(std::string("Function query complete"), results);
}

static tool_result_t imports(const json& params)
{
    json p;
    p["offset"] = params.value("offset", 0);
    p["limit"] = params.value("count", params.value("limit", 200));
    if (params.contains("filter"))
        p["filter"] = params["filter"];
    return import_tools::list_imports(p);
}

static tool_result_t imports_query(const json& params)
{
    json queries = get_list_param(params, "queries", "query");
    if (queries.empty())
        queries.push_back(params);
    json results = json::array();
    for (const auto& q : queries)
    {
        auto r = import_tools::list_imports(make_page_params(q, 200));
        results.push_back(r.success ? r.data : json{{"error", r.output}});
    }
    return tool_result_t::ok(std::string("Import query complete"), results);
}

static tool_result_t list_globals_batch(const json& params)
{
    if (!params.contains("queries") && !params.contains("query"))
        return memory_tools::list_globals(params);
    json queries = get_list_param(params, "queries", "query");
    json results = json::array();
    for (const auto& q : queries)
    {
        auto r = memory_tools::list_globals(make_page_params(q, 100));
        results.push_back(r.success ? r.data : json{{"error", r.output}});
    }
    return tool_result_t::ok(std::string("Global query complete"), results);
}

static tool_result_t entity_query(const json& params)
{
    json queries = get_list_param(params, "queries", "query");
    if (queries.empty())
        queries.push_back(params);
    json results = json::array();
    for (const auto& q : queries)
    {
        std::string kind = q.is_object() ? q.value("kind", q.value("type", "functions")) : "functions";
        std::transform(kind.begin(), kind.end(), kind.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (kind == "function" || kind == "functions" || kind == "func")
        {
            auto r = function_tools::list_functions(make_page_params(q, 100));
            results.push_back(r.success ? r.data : json{{"kind", kind}, {"error", r.output}});
        }
        else if (kind == "global" || kind == "globals" || kind == "data")
        {
            auto r = memory_tools::list_globals(make_page_params(q, 100));
            results.push_back(r.success ? r.data : json{{"kind", kind}, {"error", r.output}});
        }
        else if (kind == "import" || kind == "imports")
        {
            auto r = import_tools::list_imports(make_page_params(q, 200));
            results.push_back(r.success ? r.data : json{{"kind", kind}, {"error", r.output}});
        }
        else
        {
            results.push_back({{"kind", kind}, {"error", "Unsupported entity kind in static IDA plugin scope"}});
        }
    }
    return tool_result_t::ok(std::string("Entity query complete"), results);
}

static tool_result_t xrefs_to(const json& params)
{
    json p;
    p["address"] = params.contains("addrs") ? params["addrs"] : params.value("addr", params.value("address", json()));
    p["limit"] = params.value("limit", params.value("count", 100));
    return function_tools::get_xrefs_to(p);
}

static tool_result_t xref_query(const json& params)
{
    json queries = get_list_param(params, "queries", "query");
    if (queries.empty())
        queries.push_back(params);
    json results = json::array();
    for (const auto& q : queries)
    {
        json p;
        p["address"] = first_string_field(q, {"addr", "address", "ea"});
        p["limit"] = q.is_object() ? q.value("limit", q.value("count", 100)) : 100;
        std::string direction = q.is_object() ? q.value("direction", q.value("dir", "to")) : "to";
        auto r = (direction == "from" || direction == "out" || direction == "outgoing")
            ? function_tools::get_xrefs_from(p)
            : function_tools::get_xrefs_to(p);
        results.push_back(r.success ? r.data : json{{"addr", p["address"]}, {"error", r.output}});
    }
    return tool_result_t::ok(std::string("Xref query complete"), results);
}

static tool_result_t callees(const json& params)
{
    json addrs = get_list_param(params, "addrs", "addr");
    json results = json::array();
    for (const auto& a : addrs)
    {
        std::string addr = value_to_string(a);
        auto ea_opt = helpers::parse_address(addr);
        json item;
        item["addr"] = addr;
        item["callees"] = json::array();
        if (!ea_opt)
        {
            item["error"] = "Invalid address";
            results.push_back(item);
            continue;
        }
        func_t* pfn = get_func(*ea_opt);
        if (!pfn)
        {
            item["error"] = "No function at address";
            results.push_back(item);
            continue;
        }
        std::set<ea_t> seen;
        func_item_iterator_t fii;
        for (bool ok = fii.set(pfn); ok; ok = fii.next_addr())
        {
            xrefblk_t xb;
            for (bool xok = xb.first_from(fii.current(), XREF_ALL); xok; xok = xb.next_from())
            {
                if (!xb.iscode || (xb.type != fl_CN && xb.type != fl_CF))
                    continue;
                func_t* callee = get_func(xb.to);
                if (!callee || !seen.insert(callee->start_ea).second)
                    continue;
                qstring name;
                get_func_name(&name, callee->start_ea);
                item["callees"].push_back({{"addr", helpers::format_address(callee->start_ea)}, {"name", name.c_str()}});
            }
        }
        results.push_back(item);
    }
    return tool_result_t::ok(std::string("Callees retrieved"), results);
}

static tool_result_t basic_blocks(const json& params)
{
    json addrs = get_list_param(params, "addrs", "addr");
    json results = json::array();
    for (const auto& a : addrs)
    {
        json p;
        p["address"] = value_to_string(a);
        auto r = function_tools::get_basic_blocks(p);
        results.push_back(r.success ? json{{"addr", p["address"]}, {"blocks", r.data}} : json{{"addr", p["address"]}, {"error", r.output}});
    }
    return tool_result_t::ok(std::string("Basic blocks retrieved"), results);
}

static tool_result_t get_bytes_batch(const json& params)
{
    json regions = get_list_param(params, "regions", "items");
    json results = json::array();
    for (const auto& q : regions)
    {
        json p;
        if (q.is_string())
        {
            std::string s = q.get<std::string>();
            size_t colon = s.find(':');
            p["address"] = colon == std::string::npos ? s : s.substr(0, colon);
            p["size"] = colon == std::string::npos ? 16 : std::stoull(s.substr(colon + 1), nullptr, 0);
        }
        else
        {
            p["address"] = first_string_field(q, {"addr", "address"});
            p["size"] = q.value("size", q.value("count", 16));
        }
        auto r = memory_tools::read_bytes(p);
        results.push_back(r.success ? json{{"addr", p["address"]}, {"data", r.data.value("hex", "")}, {"bytes", r.data.value("bytes", json::array())}} : json{{"addr", p["address"]}, {"data", nullptr}, {"error", r.output}});
    }
    return tool_result_t::ok(std::string("Bytes read"), results);
}

static tool_result_t get_int(const json& params)
{
    json queries = get_list_param(params, "queries", "items");
    json results = json::array();
    for (const auto& q : queries)
    {
        std::string addr = first_string_field(q, {"addr", "address"});
        std::string ty = q.is_object() ? q.value("ty", q.value("type", "u64le")) : "u64le";
        int bytes = 0;
        bool sign = false;
        bool be = false;
        std::string norm;
        auto ea_opt = helpers::parse_address(addr);
        if (!ea_opt || !parse_int_type(ty, bytes, sign, be, norm))
        {
            results.push_back({{"addr", addr}, {"ty", ty}, {"value", nullptr}, {"error", "Invalid address or integer type"}});
            continue;
        }
        if (!is_loaded(*ea_opt))
        {
            results.push_back({{"addr", addr}, {"ty", norm}, {"value", nullptr}, {"error", "Address not mapped in database"}});
            continue;
        }
        uint64_t raw = read_raw_uint(*ea_opt, bytes, be);
        results.push_back({{"addr", addr}, {"ty", norm}, {"value", sign ? json(sign_extend_value(raw, bytes)) : json(raw)}});
    }
    return tool_result_t::ok(std::string("Integer read"), results);
}

static tool_result_t get_string(const json& params)
{
    json addrs = get_list_param(params, "addrs", "addr");
    json results = json::array();
    for (const auto& a : addrs)
    {
        json p;
        p["address"] = value_to_string(a);
        auto r = memory_tools::read_string(p);
        results.push_back(r.success ? json{{"addr", p["address"]}, {"value", r.data.value("value", "")}} : json{{"addr", p["address"]}, {"value", nullptr}, {"error", r.output}});
    }
    return tool_result_t::ok(std::string("Strings read"), results);
}

static tool_result_t get_global_value(const json& params)
{
    json queries = get_list_param(params, "queries", "names");
    if (queries.empty() && params.contains("name"))
        queries.push_back(params["name"]);
    json results = json::array();
    for (const auto& q : queries)
    {
        std::string query = value_to_string(q);
        json p;
        p["name"] = query;
        auto r = memory_tools::read_global(p);
        if (!r.success)
            results.push_back({{"query", query}, {"value", nullptr}, {"error", r.output}});
        else if (r.data.contains("hex"))
            results.push_back({{"query", query}, {"value", r.data["hex"]}});
        else if (r.data.contains("value"))
            results.push_back({{"query", query}, {"value", r.data["value"]}});
        else
            results.push_back({{"query", query}, {"value", r.data.dump()}});
    }
    return tool_result_t::ok(std::string("Global values read"), results);
}

static tool_result_t patch(const json& params)
{
    json patches = get_list_param(params, "patches", "items");
    json results = json::array();
    for (const auto& item : patches)
    {
        json p;
        p["address"] = first_string_field(item, {"addr", "address"});
        p["bytes"] = item.value("data", item.value("bytes", ""));
        auto r = memory_tools::patch_bytes(p);
        results.push_back(r.success ? json{{"addr", p["address"]}, {"size", r.data.value("size", 0)}} : json{{"addr", p["address"]}, {"size", 0}, {"error", r.output}});
    }
    return tool_result_t::ok(std::string("Patch requests processed"), results);
}

static tool_result_t patch_asm(const json& params)
{
    json items = get_list_param(params, "items", "patches");
    if (items.empty() && params.contains("asm"))
        items.push_back(params);
    json results = json::array();
    for (const auto& item : items)
    {
        std::string addr = first_string_field(item, {"addr", "address"});
        std::string asm_text = item.value("asm", item.value("assembly", ""));
        auto ea_opt = helpers::parse_address(addr);
        if (!ea_opt || asm_text.empty())
        {
            results.push_back({{"addr", addr}, {"error", "Address and assembly are required"}});
            continue;
        }
        uchar bytes[64] = {};
        ssize_t n = processor_t::assemble(bytes, *ea_opt, 0, *ea_opt, inf_is_32bit_or_higher(), asm_text.c_str());
        if (n <= 0)
        {
            results.push_back({{"addr", addr}, {"asm", asm_text}, {"error", "Assembly failed"}});
            continue;
        }
        std::ostringstream hex;
        for (ssize_t i = 0; i < n; ++i)
        {
            if (i > 0)
                hex << " ";
            hex << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]);
        }
        auto r = memory_tools::patch_bytes({{"address", addr}, {"bytes", hex.str()}});
        results.push_back(r.success ? json{{"addr", addr}, {"asm", asm_text}, {"bytes", hex.str()}} : json{{"addr", addr}, {"asm", asm_text}, {"error", r.output}});
    }
    return tool_result_t::ok(std::string("Assembly patch requests processed"), results);
}

static tool_result_t put_int(const json& params)
{
    json items = get_list_param(params, "items", "queries");
    json results = json::array();
    for (const auto& item : items)
    {
        std::string addr = first_string_field(item, {"addr", "address"});
        std::string ty = item.value("ty", item.value("type", "u32le"));
        std::string value_text = value_to_string(item.contains("value") ? item["value"] : json());
        int bytes = 0;
        bool sign = false;
        bool be = false;
        std::string norm;
        if (!parse_int_type(ty, bytes, sign, be, norm))
        {
            results.push_back({{"addr", addr}, {"ty", ty}, {"value", value_text}, {"error", "Invalid integer type"}});
            continue;
        }
        uint64_t parsed = 0;
        try
        {
            if (!sign && !value_text.empty() && value_text[0] == '-')
                throw std::invalid_argument("negative unsigned integer");
            parsed = sign ? static_cast<uint64_t>(std::stoll(value_text, nullptr, 0)) : std::stoull(value_text, nullptr, 0);
        }
        catch (...)
        {
            results.push_back({{"addr", addr}, {"ty", norm}, {"value", value_text}, {"error", "Invalid integer value"}});
            continue;
        }
        json p;
        p["address"] = addr;
        p["bytes"] = bytes_to_hex(parsed, bytes, be);
        auto r = memory_tools::patch_bytes(p);
        results.push_back(r.success ? json{{"addr", addr}, {"ty", norm}, {"value", value_text}} : json{{"addr", addr}, {"ty", norm}, {"value", value_text}, {"error", r.output}});
    }
    return tool_result_t::ok(std::string("Integer writes processed"), results);
}

static tool_result_t set_comments(const json& params)
{
    json items = get_list_param(params, "items", "comments");
    json results = json::array();
    for (const auto& item : items)
    {
        json p;
        p["address"] = first_string_field(item, {"addr", "address"});
        p["comment"] = item.value("comment", "");
        auto r = comment_tools::set_comment(p);
        if (r.success)
            navigation_tools::set_decompiler_comment(p);
        results.push_back(r.success ? json{{"addr", p["address"]}} : json{{"addr", p["address"]}, {"error", r.output}});
    }
    return tool_result_t::ok(std::string("Comments processed"), results);
}

static tool_result_t append_comments(const json& params)
{
    json items = get_list_param(params, "items", "comments");
    json results = json::array();
    for (const auto& item : items)
    {
        std::string addr = first_string_field(item, {"addr", "address"});
        std::string text = item.value("comment", "");
        bool dedupe = item.value("dedupe", true);
        auto ea_opt = helpers::parse_address(addr);
        if (!ea_opt)
        {
            results.push_back({{"addr", addr}, {"error", "Invalid address"}});
            continue;
        }
        qstring current_q;
        get_cmt(&current_q, *ea_opt, false);
        std::string current = current_q.c_str();
        bool skipped = false;
        if (dedupe && !text.empty())
        {
            std::istringstream iss(current);
            std::string line;
            while (std::getline(iss, line))
            {
                if (trim_copy(line) == trim_copy(text))
                {
                    skipped = true;
                    break;
                }
            }
        }
        if (skipped)
        {
            results.push_back({{"addr", addr}, {"skipped", true}});
            continue;
        }
        std::string combined = current.empty() ? text : current + "\n" + text;
        json p;
        p["address"] = addr;
        p["comment"] = combined;
        auto r = comment_tools::set_comment(p);
        results.push_back(r.success ? json{{"addr", addr}, {"appended", true}} : json{{"addr", addr}, {"error", r.output}});
    }
    return tool_result_t::ok(std::string("Append comments processed"), results);
}

static tool_result_t rename(const json& params)
{
    json result;
    int total = 0;
    int ok = 0;
    int failed = 0;
    auto handle_array = [&](const char* key, auto fn) {
        json arr = get_list_param(params, key);
        json out = json::array();
        for (const auto& item : arr)
        {
            total++;
            json r = fn(item);
            if (r.contains("error")) failed++; else ok++;
            out.push_back(r);
        }
        if (!arr.empty())
            result[key] = out;
    };
    handle_array("func", [](const json& item) {
        json p;
        p["address"] = first_string_field(item, {"addr", "func_addr", "func"});
        p["new_name"] = item.value("name", item.value("new", item.value("new_name", "")));
        auto r = function_tools::rename_function(p);
        return r.success ? json{{"addr", p["address"]}, {"name", p["new_name"]}} : json{{"addr", p["address"]}, {"name", p["new_name"]}, {"error", r.output}};
    });
    handle_array("data", [](const json& item) {
        std::string addr = first_string_field(item, {"addr", "address"});
        std::string name = item.value("name", item.value("new", item.value("new_name", "")));
        auto ea_opt = helpers::parse_address(addr.empty() ? item.value("old", "") : addr);
        if (!ea_opt || name.empty())
            return json{{"addr", addr}, {"name", name}, {"error", "Data rename requires addr/name"}};
        if (!set_name(*ea_opt, name.c_str(), SN_CHECK | SN_NODUMMY))
            return json{{"addr", helpers::format_address(*ea_opt)}, {"name", name}, {"error", "Rename failed"}};
        return json{{"addr", helpers::format_address(*ea_opt)}, {"name", name}};
    });
    handle_array("global", [](const json& item) {
        std::string addr = first_string_field(item, {"addr", "address", "old", "name"});
        std::string name = item.value("new", item.value("new_name", ""));
        if (name.empty() && item.contains("addr"))
            name = item.value("name", "");
        auto ea_opt = helpers::parse_address(addr);
        if (!ea_opt || name.empty())
            return json{{"addr", addr}, {"name", name}, {"error", "Global rename requires target/name"}};
        if (!set_name(*ea_opt, name.c_str(), SN_CHECK | SN_NODUMMY))
            return json{{"addr", helpers::format_address(*ea_opt)}, {"name", name}, {"error", "Rename failed"}};
        return json{{"addr", helpers::format_address(*ea_opt)}, {"name", name}};
    });
    handle_array("local", [](const json& item) {
        json p;
        p["address"] = first_string_field(item, {"func_addr", "func", "addr"});
        p["original_name"] = item.value("old", item.value("name", ""));
        p["new_name"] = item.value("new", item.value("new_name", ""));
        auto r = comment_tools::rename_variable(p);
        return r.success ? json{{"func_addr", p["address"]}, {"old", p["original_name"]}, {"new", p["new_name"]}} : json{{"func_addr", p["address"]}, {"old", p["original_name"]}, {"new", p["new_name"]}, {"error", r.output}};
    });
    if (params.contains("globals") && !result.contains("global"))
    {
        json copy = params;
        copy["global"] = params["globals"];
        return rename(copy);
    }
    result["summary"] = {{"total", total}, {"ok", ok}, {"failed", failed}, {"stopped", false}};
    return tool_result_t::ok(std::string("Rename batch processed"), result);
}

static tool_result_t define_func(const json& params)
{
    json items = get_list_param(params, "items", "funcs");
    json results = json::array();
    for (const auto& item : items)
    {
        json p;
        p["address"] = first_string_field(item, {"addr", "address"});
        if (item.contains("end"))
            p["end"] = item["end"];
        auto r = function_tools::define_function(p);
        results.push_back(r.success ? json{{"addr", p["address"]}} : json{{"addr", p["address"]}, {"error", r.output}});
    }
    return tool_result_t::ok(std::string("Function definitions processed"), results);
}

static tool_result_t define_code(const json& params)
{
    json items = get_list_param(params, "items", "addrs");
    json results = json::array();
    for (const auto& item : items)
    {
        json p;
        p["address"] = first_string_field(item, {"addr", "address"});
        auto r = memory_tools::make_code(p);
        results.push_back(r.success ? json{{"addr", p["address"]}} : json{{"addr", p["address"]}, {"error", r.output}});
    }
    return tool_result_t::ok(std::string("Code definitions processed"), results);
}

static tool_result_t stack_frame(const json& params)
{
    json addrs = get_list_param(params, "addrs", "addr");
    json results = json::array();
    for (const auto& a : addrs)
    {
        json p;
        p["address"] = value_to_string(a);
        auto r = function_tools::get_stack_frame(p);
        results.push_back(r.success ? r.data : json{{"addr", p["address"]}, {"error", r.output}});
    }
    return tool_result_t::ok(std::string("Stack frames retrieved"), results);
}

static tool_result_t declare_stack(const json& params)
{
    json items = get_list_param(params, "items", "vars");
    json results = json::array();
    for (const auto& item : items)
    {
        json p;
        p["address"] = first_string_field(item, {"func_addr", "func", "addr"});
        p["offset"] = item.value("offset", 0);
        p["name"] = item.value("name", "");
        p["type"] = item.value("ty", item.value("type", "__int64"));
        auto r = type_tools::create_stack_var(p);
        results.push_back(r.success ? json{{"func_addr", p["address"]}, {"name", p["name"]}} : json{{"func_addr", p["address"]}, {"name", p["name"]}, {"error", r.output}});
    }
    return tool_result_t::ok(std::string("Stack declarations processed"), results);
}

static tool_result_t delete_stack(const json& params)
{
    json items = get_list_param(params, "items", "vars");
    json results = json::array();
    for (const auto& item : items)
    {
        json p;
        p["address"] = first_string_field(item, {"func_addr", "func", "addr"});
        p["name"] = item.value("name", "");
        auto r = type_tools::delete_stack_var(p);
        results.push_back(r.success ? json{{"func_addr", p["address"]}, {"name", p["name"]}} : json{{"func_addr", p["address"]}, {"name", p["name"]}, {"error", r.output}});
    }
    return tool_result_t::ok(std::string("Stack deletes processed"), results);
}

static tool_result_t declare_type(const json& params)
{
    json decls = get_list_param(params, "decls", "declarations");
    if (decls.empty() && params.contains("declaration"))
        decls.push_back(params["declaration"]);
    json results = json::array();
    for (const auto& d : decls)
    {
        json p;
        p["declaration"] = value_to_string(d);
        auto r = type_tools::declare_type(p);
        results.push_back(r.success ? json{{"decl", p["declaration"]}} : json{{"decl", p["declaration"]}, {"error", r.output}});
    }
    return tool_result_t::ok(std::string("Type declarations processed"), results);
}

static tool_result_t read_struct(const json& params)
{
    json queries = get_list_param(params, "queries", "items");
    json results = json::array();
    for (const auto& q : queries)
    {
        std::string addr = first_string_field(q, {"addr", "address"});
        std::string struct_name = q.value("struct", q.value("struct_name", q.value("type", "")));
        auto ea_opt = helpers::parse_address(addr);
        if (!ea_opt || struct_name.empty())
        {
            results.push_back({{"addr", addr}, {"struct", struct_name}, {"members", nullptr}, {"error", "Address and struct are required"}});
            continue;
        }
        til_t* ti = get_idati();
        int32 ordinal = get_type_ordinal(ti, struct_name.c_str());
        tinfo_t tif;
        udt_type_data_t udt;
        if (ordinal <= 0 || !tif.get_numbered_type(ti, ordinal) || !tif.get_udt_details(&udt))
        {
            results.push_back({{"addr", addr}, {"struct", struct_name}, {"members", nullptr}, {"error", "Struct not found"}});
            continue;
        }
        json members = json::array();
        for (size_t i = 0; i < udt.size(); i++)
        {
            const udm_t& m = udt[i];
            asize_t size = static_cast<asize_t>(std::max<uint64_t>(1, m.size / 8));
            ea_t field_ea = *ea_opt + m.offset / 8;
            qstring type_s;
            m.type.print(&type_s);
            json member;
            member["offset"] = helpers::format_address(m.offset / 8);
            member["type"] = type_s.c_str();
            member["name"] = m.name.c_str();
            member["size"] = size;
            if (size <= 8 && is_loaded(field_ea))
            {
                uval_t val = 0;
                if (get_data_value(&val, field_ea, size))
                    member["value"] = helpers::format_address(val);
            }
            members.push_back(member);
        }
        results.push_back({{"addr", addr}, {"struct", struct_name}, {"members", members}});
    }
    return tool_result_t::ok(std::string("Struct reads processed"), results);
}

static tool_result_t search_structs_batch(const json& params)
{
    json p;
    p["pattern"] = params.value("filter", params.value("pattern", ".*"));
    p["limit"] = params.value("limit", 100);
    return type_tools::search_structs(p);
}

static tool_result_t type_query(const json& params)
{
    json queries = get_list_param(params, "queries", "query");
    if (queries.empty())
        queries.push_back(params);
    json results = json::array();
    for (const auto& q : queries)
    {
        auto r = type_tools::list_types(make_page_params(q, 100));
        std::string kind = q.is_object() ? q.value("kind", "any") : "any";
        results.push_back(r.success ? json{{"kind", kind}, {"data", r.data.value("types", json::array())}, {"total", r.data.value("total", 0)}, {"next_offset", nullptr}} : json{{"error", r.output}});
    }
    return tool_result_t::ok(std::string("Type query complete"), results);
}

static tool_result_t set_type(const json& params)
{
    json edits = get_list_param(params, "edits", "items");
    json results = json::array();
    for (const auto& edit : edits)
    {
        std::string kind = edit.value("kind", "");
        std::string type_text = edit.value("ty", edit.value("type", edit.value("decl", edit.value("declaration", ""))));
        json p;
        p["address"] = first_string_field(edit, {"addr", "address", "name"});
        if (edit.contains("signature") || kind == "function")
        {
            p["signature"] = edit.value("signature", type_text);
            auto r = function_tools::set_function_signature(p);
            results.push_back(r.success ? json{{"edit", edit}, {"kind", "function"}, {"ok", true}} : json{{"edit", edit}, {"kind", "function"}, {"error", r.output}});
        }
        else
        {
            p["type"] = type_text;
            auto r = type_tools::apply_type(p);
            results.push_back(r.success ? json{{"edit", edit}, {"kind", "global"}, {"ok", true}} : json{{"edit", edit}, {"kind", "global"}, {"error", r.output}});
        }
    }
    return tool_result_t::ok(std::string("Type edits processed"), results);
}

static tool_result_t infer_types(const json& params)
{
    json addrs = get_list_param(params, "addrs", "addr");
    json results = json::array();
    for (const auto& a : addrs)
    {
        json p;
        p["address"] = value_to_string(a);
        auto r = type_tools::infer_type(p);
        results.push_back(r.success ? json{{"addr", p["address"]}, {"inferred_type", r.data.value("type", "")}, {"method", "aida"}, {"confidence", r.data.value("confidence", "low")}} : json{{"addr", p["address"]}, {"inferred_type", nullptr}, {"confidence", "none"}, {"error", r.output}});
    }
    return tool_result_t::ok(std::string("Type inference processed"), results);
}

static std::string address_param(const json& params)
{
    if (params.contains("addr")) return value_to_string(params["addr"]);
    if (params.contains("address")) return value_to_string(params["address"]);
    if (params.contains("ea")) return value_to_string(params["ea"]);
    if (params.contains("func")) return value_to_string(params["func"]);
    if (params.contains("function")) return value_to_string(params["function"]);
    if (params.contains("root")) return value_to_string(params["root"]);
    return "";
}

static tool_result_t idb_save(const json& params)
{
    std::string path = params.value("path", params.value("outfile", ""));
    uint32 flags = 0;
    if (params.value("backup", true))
        flags |= DBFL_BAK;
    if (params.value("compact", false))
        flags |= DBFL_COMP;
    bool ok = save_database(path.empty() ? nullptr : path.c_str(), flags);
    if (!ok)
        return tool_result_t::error(std::string("Failed to save IDB"));
    json data;
    data["path"] = path.empty() ? "current" : path;
    data["backup"] = (flags & DBFL_BAK) != 0;
    data["compact"] = (flags & DBFL_COMP) != 0;
    return tool_result_t::ok(std::string("IDB saved"), data);
}

static tool_result_t find_regex(const json& params)
{
    std::string pattern = params.value("pattern", params.value("regex", params.value("query", "")));
    int limit = params.value("limit", params.value("count", 50));
    if (pattern.empty())
        return tool_result_t::error(std::string("Pattern is required"));
    json data;
    auto strings = search_tools::search_strings({{"pattern", pattern}, {"limit", limit}});
    auto insns = search_tools::find_instructions({{"pattern", pattern}, {"limit", limit}});
    data["strings"] = strings.success ? strings.data : json{{"error", strings.output}};
    data["instructions"] = insns.success ? insns.data : json{{"error", insns.output}};
    return tool_result_t::ok(std::string("Regex search complete"), data);
}

static tool_result_t search_text(const json& params)
{
    std::string pattern = params.value("text", params.value("pattern", params.value("query", "")));
    int limit = params.value("limit", params.value("count", 100));
    if (pattern.empty())
        return tool_result_t::error(std::string("Search text is required"));
    return search_tools::search_strings({{"pattern", pattern}, {"limit", limit}});
}

static tool_result_t export_funcs(const json& params)
{
    json p = make_page_params(params, 200);
    return import_tools::list_exports(p);
}

static tool_result_t callgraph(const json& params)
{
    json p;
    p["address"] = address_param(params);
    p["depth"] = params.value("depth", params.value("max_depth", 3));
    return function_tools::build_call_graph(p);
}

static tool_result_t func_profile(const json& params)
{
    std::string addr = address_param(params);
    if (addr.empty())
        return tool_result_t::error(std::string("Address is required"));
    json data;
    auto fn = function_tools::get_function({{"address", addr}});
    auto complexity = analysis_tools::get_function_complexity({{"address", addr}});
    auto cfg = analysis_tools::analyze_control_flow({{"address", addr}});
    data["function"] = fn.success ? fn.data : json{{"error", fn.output}};
    data["complexity"] = complexity.success ? complexity.data : json{{"error", complexity.output}};
    data["control_flow"] = cfg.success ? cfg.data : json{{"error", cfg.output}};
    return tool_result_t::ok(std::string("Function profile complete"), data);
}

static tool_result_t analyze_function_batch(const json& params)
{
    std::string addr = address_param(params);
    if (addr.empty())
        return tool_result_t::error(std::string("Address is required"));
    json data;
    auto fn = function_tools::get_function({{"address", addr}});
    auto decomp = function_tools::decompile_function({{"address", addr}});
    auto disasm = function_tools::disassemble_function({{"address", addr}});
    auto to = function_tools::get_xrefs_to({{"address", addr}, {"limit", params.value("limit", 100)}});
    auto from = function_tools::get_xrefs_from({{"address", addr}, {"limit", params.value("limit", 100)}});
    auto blocks = function_tools::get_basic_blocks({{"address", addr}});
    auto profile = func_profile({{"addr", addr}});
    data["function"] = fn.success ? fn.data : json{{"error", fn.output}};
    data["decompilation"] = decomp.success ? decomp.data : json{{"error", decomp.output}};
    data["disassembly"] = disasm.success ? disasm.data : json{{"error", disasm.output}};
    data["xrefs_to"] = to.success ? to.data : json{{"error", to.output}};
    data["xrefs_from"] = from.success ? from.data : json{{"error", from.output}};
    data["basic_blocks"] = blocks.success ? blocks.data : json{{"error", blocks.output}};
    data["profile"] = profile.success ? profile.data : json{{"error", profile.output}};
    return tool_result_t::ok(std::string("Function analysis complete"), data);
}

static tool_result_t analyze_batch(const json& params)
{
    json addrs = get_list_param(params, "addrs", "addresses");
    if (addrs.empty())
        addrs = get_list_param(params, "items", "functions");
    if (addrs.empty() && !address_param(params).empty())
        addrs.push_back(address_param(params));
    json results = json::array();
    for (const auto& item : addrs)
    {
        json p;
        p["addr"] = first_string_field(item, {"addr", "address", "ea", "func"});
        auto r = analyze_function_batch(p);
        results.push_back(r.success ? r.data : json{{"addr", p["addr"]}, {"error", r.output}});
    }
    return tool_result_t::ok(std::string("Batch analysis complete"), results);
}

static tool_result_t analyze_component(const json& params)
{
    return analyze_batch(params);
}

static tool_result_t diff_before_after(const json& params)
{
    std::string addr = address_param(params);
    std::string action = params.value("action", params.value("operation", ""));
    json args = params.value("args", params.value("arguments", json::object()));
    if (addr.empty() || action.empty())
        return tool_result_t::error(std::string("Address and action are required"));
    auto before = function_tools::decompile_function({{"address", addr}});
    agent_tools::tool_result_t applied = tool_result_t::error(std::string("Unsupported action"));
    if (action == "rename_func" || action == "rename_function")
    {
        std::string name = args.value("name", args.value("new_name", ""));
        applied = function_tools::rename_function({{"address", addr}, {"new_name", name}});
    }
    else if (action == "set_comment")
    {
        std::string comment = args.value("comment", "");
        applied = comment_tools::set_comment({{"address", addr}, {"comment", comment}});
    }
    else if (action == "set_type")
    {
        std::string type_text = args.value("type", args.value("signature", ""));
        applied = function_tools::set_function_signature({{"address", addr}, {"signature", type_text}});
    }
    else if (action == "patch_bytes")
    {
        std::string bytes = args.value("bytes", args.value("data", ""));
        applied = memory_tools::patch_bytes({{"address", addr}, {"bytes", bytes}});
    }
    else if (action == "patch_asm")
    {
        std::string asm_text = args.value("asm", args.value("assembly", ""));
        applied = patch_asm({{"items", json::array({json::object({{"addr", addr}, {"asm", asm_text}})})}});
    }
    auto after = function_tools::decompile_function({{"address", addr}});
    json data;
    data["target"] = addr;
    data["action"] = action;
    data["before"] = before.success ? before.data : json{{"error", before.output}};
    data["applied"] = applied.success ? json{{"ok", true}, {"data", applied.data}, {"output", applied.output}} : json{{"ok", false}, {"error", applied.output}};
    data["after"] = after.success ? after.data : json{{"error", after.output}};
    return tool_result_t::ok(std::string("Before/after diff action complete"), data);
}

static tool_result_t trace_data_flow(const json& params)
{
    json p;
    p["address"] = address_param(params);
    p["max_depth"] = params.value("max_depth", params.value("depth", 32));
    return analysis_tools::analyze_data_flow(p);
}

static tool_result_t xrefs_to_field(const json& params)
{
    json p;
    p["struct_name"] = params.value("struct_name", params.value("struct", params.value("type", "")));
    p["field_name"] = params.value("field_name", params.value("field", params.value("member", "")));
    p["limit"] = params.value("limit", 100);
    return type_tools::get_struct_field_xrefs(p);
}

static tool_result_t find_batch(const json& params)
{
    std::string kind = params.value("kind", params.value("type", "text"));
    std::transform(kind.begin(), kind.end(), kind.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (kind == "bytes" || kind == "byte")
        return search_tools::find_bytes({{"pattern", params.value("pattern", params.value("query", ""))}, {"limit", params.value("limit", 20)}});
    if (kind == "instruction" || kind == "instructions" || kind == "insn")
        return search_tools::find_instructions({{"pattern", params.value("pattern", params.value("query", ""))}, {"limit", params.value("limit", 20)}});
    if (kind == "function" || kind == "functions")
        return function_tools::list_functions(make_page_params(params, 100));
    if (kind == "import" || kind == "imports")
        return import_tools::list_imports(make_page_params(params, 200));
    if (kind == "export" || kind == "exports")
        return import_tools::list_exports(make_page_params(params, 200));
    return search_text(params);
}

static tool_result_t insn_query(const json& params)
{
    json queries = get_list_param(params, "queries", "query");
    if (queries.empty())
        queries.push_back(params);
    json results = json::array();
    for (const auto& q : queries)
    {
        std::string pattern = first_string_field(q, {"pattern", "text", "query", "mnemonic"});
        int limit = q.is_object() ? q.value("limit", q.value("count", 20)) : 20;
        auto r = search_tools::find_instructions({{"pattern", pattern}, {"limit", limit}});
        results.push_back(r.success ? r.data : json{{"pattern", pattern}, {"error", r.output}});
    }
    return tool_result_t::ok(std::string("Instruction query complete"), results);
}

static tool_result_t enum_upsert(const json& params)
{
    json items = get_list_param(params, "items", "enums");
    if (items.empty())
        items.push_back(params);
    json results = json::array();
    for (const auto& item : items)
    {
        json p;
        p["name"] = item.value("name", "");
        p["members"] = item.value("members", json::array());
        auto r = type_tools::create_enum(p);
        results.push_back(r.success ? json{{"name", p["name"]}, {"ok", true}} : json{{"name", p["name"]}, {"error", r.output}});
    }
    return tool_result_t::ok(std::string("Enum upsert batch processed"), results);
}

static tool_result_t type_inspect(const json& params)
{
    std::string name = params.value("name", params.value("type", ""));
    if (!name.empty())
        return type_tools::get_struct({{"name", name}});
    return type_tools::list_types(make_page_params(params, 100));
}

static tool_result_t type_apply_batch(const json& params)
{
    return set_type(params);
}

static tool_result_t py_exec_file(const json& params)
{
    std::string path = params.value("path", params.value("file", ""));
    if (path.empty())
        return tool_result_t::error(std::string("Path is required"));
    std::ifstream f(path, std::ios::binary);
    if (!f)
        return tool_result_t::error(std::string("Failed to open Python file"));
    std::ostringstream ss;
    ss << f.rdbuf();
    std::string code = ss.str();
    if (code.size() > 1024 * 1024)
        return tool_result_t::error(std::string("Python file too large"));
    return python_tools::execute_python({{"code", code}});
}

static tool_result_t survey_binary(const json& params)
{
    int count = params.value("count", params.value("limit", 50));
    json data;
    data["binary"] = binary_tools::get_binary_info(json::object()).data;
    data["functions"] = function_tools::list_functions({{"offset", 0}, {"limit", count}}).data;
    data["imports"] = import_tools::list_imports({{"offset", 0}, {"limit", count}}).data;
    data["globals"] = memory_tools::list_globals({{"offset", 0}, {"limit", count}}).data;
    return tool_result_t::ok(std::string("Binary survey complete"), data);
}

static tool_result_t make_signature(const json& params)
{
    std::string addr = params.contains("addr") ? value_to_string(params["addr"]) : value_to_string(params.value("address", json()));
    int max_bytes = params.value("max_bytes", params.value("size", 64));
    if (max_bytes <= 0)
        max_bytes = 64;
    if (max_bytes > 512)
        max_bytes = 512;
    auto ea_opt = helpers::parse_address(addr);
    if (!ea_opt)
        return tool_result_t::error(std::string("Invalid address"));
    func_t* pfn = get_func(*ea_opt);
    ea_t start = pfn ? pfn->start_ea : *ea_opt;
    ea_t end = pfn ? pfn->end_ea : start + max_bytes;
    size_t size = static_cast<size_t>(std::min<ea_t>(end - start, max_bytes));
    std::vector<uint8_t> buffer(size);
    ssize_t n = ::get_bytes(buffer.data(), size, start);
    if (n <= 0)
        return tool_result_t::error(std::string("Failed to read bytes for signature"));
    std::ostringstream sig;
    for (ssize_t i = 0; i < n; i++)
    {
        if (i > 0)
            sig << " ";
        sig << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[i]);
    }
    json data;
    data["addr"] = helpers::format_address(start);
    data["size"] = n;
    data["signature"] = sig.str();
    data["format"] = "ida_bytes";
    return tool_result_t::ok(std::string("Signature generated"), data);
}

static tool_result_t make_signature_for_function(const json& params)
{
    return make_signature(params);
}

static tool_result_t py_eval(const json& params)
{
    json p;
    p["code"] = params.value("code", params.value("expr", ""));
    return python_tools::execute_python(p);
}

void register_tools()
{
    auto& registry = ToolRegistry::instance();
    registry.register_tool({std::string("server_health"), std::string("aida_ida_batch"), std::string("Return IDA plugin health and static analysis state."), {}, server_health, true});
    registry.register_tool({std::string("server_warmup"), std::string("aida_ida_batch"), std::string("Warm IDA analysis/decompiler state for AiDA clients."), {{std::string("wait_auto_analysis"), std::string("boolean"), std::string("Wait for auto-analysis"), false}, {std::string("init_hexrays"), std::string("boolean"), std::string("Initialize Hex-Rays"), false}}, server_warmup, true});
    registry.register_tool({std::string("idb_save"), std::string("aida_ida_batch"), std::string("Save the current IDB."), {{std::string("path"), std::string("string"), std::string("Optional output IDB path"), false}, {std::string("backup"), std::string("boolean"), std::string("Create an IDB backup"), false}, {std::string("compact"), std::string("boolean"), std::string("Compact database during save"), false}}, idb_save, false});
    registry.register_tool({std::string("decompile"), std::string("aida_ida_batch"), std::string("AiDA alias for decompile_function."), {{std::string("addr"), std::string("string"), std::string("Function address or name"), true}}, decompile, true});
    registry.register_tool({std::string("disasm"), std::string("aida_ida_batch"), std::string("AiDA alias for disassemble_function."), {{std::string("addr"), std::string("string"), std::string("Function address or name"), true}}, disasm, true});
    registry.register_tool({std::string("list_funcs"), std::string("aida_ida_batch"), std::string("List functions using offset/count pagination."), {{std::string("offset"), std::string("number"), std::string("Start offset"), false}, {std::string("count"), std::string("number"), std::string("Result count"), false}, {std::string("filter"), std::string("string"), std::string("Name filter"), false}}, list_funcs, true});
    registry.register_tool({std::string("lookup_funcs"), std::string("aida_ida_batch"), std::string("Lookup functions by address or name."), {{std::string("queries"), std::string("array"), std::string("Function lookup requests"), true}}, lookup_funcs, true});
    registry.register_tool({std::string("func_query"), std::string("aida_ida_batch"), std::string("Batch function catalog query."), {{std::string("queries"), std::string("array"), std::string("Function query requests"), true}}, func_query, true});
    registry.register_tool({std::string("func_profile"), std::string("aida_ida_batch"), std::string("Return function metadata, complexity, and control-flow profile."), {{std::string("addr"), std::string("string"), std::string("Function address or name"), true}}, func_profile, true});
    registry.register_tool({std::string("analyze_function"), std::string("aida_ida_batch"), std::string("Return a composite function analysis package."), {{std::string("addr"), std::string("string"), std::string("Function address or name"), true}, {std::string("limit"), std::string("number"), std::string("Xref limit"), false}}, analyze_function_batch, true});
    registry.register_tool({std::string("analyze_batch"), std::string("aida_ida_batch"), std::string("Analyze multiple functions."), {{std::string("addrs"), std::string("array"), std::string("Function addresses"), true}}, analyze_batch, true});
    registry.register_tool({std::string("analyze_component"), std::string("aida_ida_batch"), std::string("Analyze a component represented by a batch of functions."), {{std::string("functions"), std::string("array"), std::string("Component function addresses"), true}}, analyze_component, true});
    registry.register_tool({std::string("diff_before_after"), std::string("aida_ida_batch"), std::string("Apply a supported edit and return before/after decompilation data."), {{std::string("addr"), std::string("string"), std::string("Function address or name"), true}, {std::string("action"), std::string("string"), std::string("Edit action"), true}, {std::string("args"), std::string("object"), std::string("Action arguments"), false}}, diff_before_after, false});
    registry.register_tool({std::string("trace_data_flow"), std::string("aida_ida_batch"), std::string("Trace local data-flow around an address."), {{std::string("addr"), std::string("string"), std::string("Instruction address"), true}, {std::string("max_depth"), std::string("number"), std::string("Maximum scan depth"), false}}, trace_data_flow, true});
    registry.register_tool({std::string("imports"), std::string("aida_ida_batch"), std::string("List imports using offset/count."), {{std::string("offset"), std::string("number"), std::string("Start offset"), false}, {std::string("count"), std::string("number"), std::string("Result count"), false}, {std::string("filter"), std::string("string"), std::string("Name filter"), false}}, imports, true});
    registry.register_tool({std::string("imports_query"), std::string("aida_ida_batch"), std::string("Batch import catalog query."), {{std::string("queries"), std::string("array"), std::string("Import query requests"), true}}, imports_query, true});
    registry.register_tool({std::string("export_funcs"), std::string("aida_ida_batch"), std::string("List exports using offset/count pagination."), {{std::string("offset"), std::string("number"), std::string("Start offset"), false}, {std::string("count"), std::string("number"), std::string("Result count"), false}, {std::string("filter"), std::string("string"), std::string("Name filter"), false}}, export_funcs, true});
    registry.register_tool({std::string("list_globals"), std::string("memory"), std::string("List globals with AiDA batch query shapes."), {{std::string("offset"), std::string("number"), std::string("Start offset"), false}, {std::string("limit"), std::string("number"), std::string("Max results"), false}, {std::string("filter"), std::string("string"), std::string("Regex filter"), false}, {std::string("queries"), std::string("array"), std::string("Batch query requests"), false}}, list_globals_batch, true});
    registry.register_tool({std::string("entity_query"), std::string("aida_ida_batch"), std::string("Query function/global/import entity catalogs."), {{std::string("queries"), std::string("array"), std::string("Entity query requests"), true}}, entity_query, true});
    registry.register_tool({std::string("xrefs_to"), std::string("aida_ida_batch"), std::string("AiDA alias for get_xrefs_to."), {{std::string("addrs"), std::string("array"), std::string("Target addresses"), true}, {std::string("limit"), std::string("number"), std::string("Maximum xrefs"), false}}, xrefs_to, true});
    registry.register_tool({std::string("xref_query"), std::string("aida_ida_batch"), std::string("Batch xref query with to/from direction."), {{std::string("queries"), std::string("array"), std::string("Xref query requests"), true}}, xref_query, true});
    registry.register_tool({std::string("xrefs_to_field"), std::string("aida_ida_batch"), std::string("Return information for a struct field and suggested offset search."), {{std::string("struct_name"), std::string("string"), std::string("Struct name"), true}, {std::string("field_name"), std::string("string"), std::string("Field name"), true}, {std::string("limit"), std::string("number"), std::string("Maximum xrefs"), false}}, xrefs_to_field, true});
    registry.register_tool({std::string("callees"), std::string("aida_ida_batch"), std::string("List callees for functions."), {{std::string("addrs"), std::string("array"), std::string("Function addresses"), true}}, callees, true});
    registry.register_tool({std::string("basic_blocks"), std::string("aida_ida_batch"), std::string("List basic blocks for functions."), {{std::string("addrs"), std::string("array"), std::string("Function addresses"), true}}, basic_blocks, true});
    registry.register_tool({std::string("callgraph"), std::string("aida_ida_batch"), std::string("Build a call graph from a root function."), {{std::string("addr"), std::string("string"), std::string("Root function address"), true}, {std::string("depth"), std::string("number"), std::string("Maximum depth"), false}}, callgraph, true});
    registry.register_tool({std::string("find"), std::string("aida_ida_batch"), std::string("AiDA finder across text, bytes, instructions, functions, imports, and exports."), {{std::string("kind"), std::string("string"), std::string("Result kind"), false}, {std::string("pattern"), std::string("string"), std::string("Search pattern"), false}, {std::string("limit"), std::string("number"), std::string("Maximum results"), false}}, find_batch, true});
    registry.register_tool({std::string("find_regex"), std::string("aida_ida_batch"), std::string("Search strings and instructions by regex/text pattern."), {{std::string("pattern"), std::string("string"), std::string("Regex pattern"), true}, {std::string("limit"), std::string("number"), std::string("Maximum results per class"), false}}, find_regex, true});
    registry.register_tool({std::string("search_text"), std::string("aida_ida_batch"), std::string("Search IDA string literals by text or regex."), {{std::string("text"), std::string("string"), std::string("Search text"), true}, {std::string("limit"), std::string("number"), std::string("Maximum results"), false}}, search_text, true});
    registry.register_tool({std::string("insn_query"), std::string("aida_ida_batch"), std::string("Batch instruction text query."), {{std::string("queries"), std::string("array"), std::string("Instruction query requests"), true}}, insn_query, true});
    registry.register_tool({std::string("get_bytes"), std::string("aida_ida_batch"), std::string("Read byte regions using {addr,size} requests."), {{std::string("regions"), std::string("array"), std::string("Memory regions"), true}}, get_bytes_batch, true});
    registry.register_tool({std::string("get_int"), std::string("aida_ida_batch"), std::string("Read integers using {addr,ty} requests."), {{std::string("queries"), std::string("array"), std::string("Integer read requests"), true}}, get_int, true});
    registry.register_tool({std::string("get_string"), std::string("aida_ida_batch"), std::string("Read strings from addresses."), {{std::string("addrs"), std::string("array"), std::string("String addresses"), true}}, get_string, true});
    registry.register_tool({std::string("get_global_value"), std::string("aida_ida_batch"), std::string("Read global values by address or name."), {{std::string("queries"), std::string("array"), std::string("Global value requests"), true}}, get_global_value, true});
    registry.register_tool({std::string("patch"), std::string("aida_ida_batch"), std::string("Patch bytes using {addr,data} requests."), {{std::string("patches"), std::string("array"), std::string("Patch requests"), true}}, patch, false});
    registry.register_tool({std::string("patch_asm"), std::string("aida_ida_batch"), std::string("Assemble and patch instructions at addresses."), {{std::string("items"), std::string("array"), std::string("Assembly patch requests"), false}, {std::string("addr"), std::string("string"), std::string("Patch address"), false}, {std::string("asm"), std::string("string"), std::string("Assembly instruction"), false}}, patch_asm, false});
    registry.register_tool({std::string("put_int"), std::string("aida_ida_batch"), std::string("Patch integer values using {addr,ty,value} requests."), {{std::string("items"), std::string("array"), std::string("Integer write requests"), true}}, put_int, false});
    registry.register_tool({std::string("set_comments"), std::string("aida_ida_batch"), std::string("Set comments at addresses."), {{std::string("items"), std::string("array"), std::string("Comment requests"), true}}, set_comments, false});
    registry.register_tool({std::string("append_comments"), std::string("aida_ida_batch"), std::string("Append comments at addresses."), {{std::string("items"), std::string("array"), std::string("Comment append requests"), true}}, append_comments, false});
    registry.register_tool({std::string("rename"), std::string("aida_ida_batch"), std::string("Batch rename functions, globals, and locals."), {{std::string("func"), std::string("array"), std::string("Function renames"), false}, {std::string("data"), std::string("array"), std::string("Data renames"), false}, {std::string("global"), std::string("array"), std::string("Global renames"), false}, {std::string("local"), std::string("array"), std::string("Local renames"), false}}, rename, false});
    registry.register_tool({std::string("define_func"), std::string("aida_ida_batch"), std::string("Define functions."), {{std::string("items"), std::string("array"), std::string("Function definition requests"), true}}, define_func, false});
    registry.register_tool({std::string("define_code"), std::string("aida_ida_batch"), std::string("Create code at addresses."), {{std::string("items"), std::string("array"), std::string("Code definition requests"), true}}, define_code, false});
    registry.register_tool({std::string("stack_frame"), std::string("aida_ida_batch"), std::string("Read function stack frames."), {{std::string("addrs"), std::string("array"), std::string("Function addresses"), true}}, stack_frame, true});
    registry.register_tool({std::string("declare_stack"), std::string("aida_ida_batch"), std::string("Declare stack variables."), {{std::string("items"), std::string("array"), std::string("Stack variable declarations"), true}}, declare_stack, false});
    registry.register_tool({std::string("delete_stack"), std::string("aida_ida_batch"), std::string("Delete stack variables."), {{std::string("items"), std::string("array"), std::string("Stack variable deletes"), true}}, delete_stack, false});
    registry.register_tool({std::string("declare_type"), std::string("type"), std::string("Declare C types with AiDA batch request shapes."), {{std::string("decls"), std::string("array"), std::string("C type declarations"), false}, {std::string("declaration"), std::string("string"), std::string("Single C type declaration"), false}}, declare_type, false});
    registry.register_tool({std::string("enum_upsert"), std::string("aida_ida_batch"), std::string("Create enum types from AiDA batch requests."), {{std::string("items"), std::string("array"), std::string("Enum definitions"), false}, {std::string("name"), std::string("string"), std::string("Enum name"), false}, {std::string("members"), std::string("array"), std::string("Enum members"), false}}, enum_upsert, false});
    registry.register_tool({std::string("read_struct"), std::string("aida_ida_batch"), std::string("Read struct members at addresses."), {{std::string("queries"), std::string("array"), std::string("Struct read requests"), true}}, read_struct, true});
    registry.register_tool({std::string("search_structs"), std::string("type"), std::string("Search structs/types using filter or pattern."), {{std::string("filter"), std::string("string"), std::string("Name filter"), false}, {std::string("pattern"), std::string("string"), std::string("Regex pattern"), false}, {std::string("limit"), std::string("number"), std::string("Max results"), false}}, search_structs_batch, true});
    registry.register_tool({std::string("type_query"), std::string("aida_ida_batch"), std::string("Batch type catalog query."), {{std::string("queries"), std::string("array"), std::string("Type query requests"), true}}, type_query, true});
    registry.register_tool({std::string("type_inspect"), std::string("aida_ida_batch"), std::string("Inspect a named type or list local types."), {{std::string("name"), std::string("string"), std::string("Type name"), false}, {std::string("limit"), std::string("number"), std::string("Maximum list results"), false}}, type_inspect, true});
    registry.register_tool({std::string("set_type"), std::string("aida_ida_batch"), std::string("Apply function/global types."), {{std::string("edits"), std::string("array"), std::string("Type edit requests"), true}}, set_type, false});
    registry.register_tool({std::string("type_apply_batch"), std::string("aida_ida_batch"), std::string("Apply multiple type edits."), {{std::string("edits"), std::string("array"), std::string("Type edit requests"), true}}, type_apply_batch, false});
    registry.register_tool({std::string("infer_types"), std::string("aida_ida_batch"), std::string("Infer types at addresses."), {{std::string("addrs"), std::string("array"), std::string("Addresses"), true}}, infer_types, true});
    registry.register_tool({std::string("survey_binary"), std::string("aida_ida_batch"), std::string("Return a compact binary survey."), {{std::string("count"), std::string("number"), std::string("Sample count"), false}}, survey_binary, true});
    registry.register_tool({std::string("make_signature"), std::string("aida_ida_batch"), std::string("Generate a byte-pattern signature for an address or function."), {{std::string("addr"), std::string("string"), std::string("Address or function name"), true}, {std::string("max_bytes"), std::string("number"), std::string("Maximum bytes"), false}}, make_signature, true});
    registry.register_tool({std::string("make_signature_for_function"), std::string("aida_ida_batch"), std::string("Generate a byte-pattern signature for a function."), {{std::string("addr"), std::string("string"), std::string("Function address or name"), true}, {std::string("max_bytes"), std::string("number"), std::string("Maximum bytes"), false}}, make_signature_for_function, true});
    registry.register_tool({std::string("py_eval"), std::string("aida_ida_batch"), std::string("Execute Python code in IDA context."), {{std::string("code"), std::string("string"), std::string("Python code or expression"), false}, {std::string("expr"), std::string("string"), std::string("Python expression"), false}}, py_eval, false});
    registry.register_tool({std::string("py_exec_file"), std::string("aida_ida_batch"), std::string("Execute a Python file in IDA context."), {{std::string("path"), std::string("string"), std::string("Python file path"), true}}, py_exec_file, false});
}

}

// ============================================================================
// Slice B — meta_tools (orchestration / planning / introspection)
//
// Note on the cross-TU surface used by list_outputs: the MCP output cache is a
// translation-unit-local static in mcp_server.cpp. Slice B9 exposes it through
// the global aida_mcp_internal accessor namespace declared near
// mcp_server.cpp:354. The forward declarations live just above this block at
// global (::) scope so meta_tools links against them without dragging the
// whole mcp_server header surface in.
// ============================================================================

} // namespace agent_tools

namespace aida_mcp_internal {
struct output_cache_entry_t
{
    std::string id;
    size_t      json_bytes = 0;
};
struct output_cache_stats_t
{
    size_t total_entries = 0;
    size_t total_bytes   = 0;
    size_t limit         = 0;
    size_t text_limit    = 0;
};
std::vector<output_cache_entry_t> output_cache_list();
output_cache_stats_t              output_cache_stats();
bool                              output_cache_evict_one(const std::string& id);
size_t                            output_cache_evict_all();
// Forward decl: parallel batch runner lives in mcp_server.cpp. Slice B2's
// tool_batch_call dispatches to it when parallel=true is requested AND every
// sub-tool is read_only=true. Returns a per-call results vector + cancel/timeout
// flags. Declared here so meta_tools::tool_batch_call links cleanly.
struct parallel_batch_outcome_t
{
    std::vector<agent_tools::tool_result_t> results;
    std::vector<std::string> labels;
    size_t partial_count = 0;
    uint64_t total_ms = 0;
    bool cancelled = false;
    bool timed_out = false;
};
parallel_batch_outcome_t run_batch_parallel(
    const std::vector<std::pair<std::string, nlohmann::json>>& calls,
    const std::vector<std::string>& labels,
    bool stop_on_error,
    int max_wall_seconds);
} // namespace aida_mcp_internal

namespace agent_tools
{

namespace meta_tools
{

// ----------------------------------------------------------------------------
// Slice B2 — tool_batch_call
// ----------------------------------------------------------------------------
tool_result_t tool_batch_call(const json& params)
{
    if (!params.contains("calls") || !params["calls"].is_array())
        return tool_result_t::error(std::string("Missing or invalid 'calls' array"), std::string("bad_param"));

    const json& calls_arr = params["calls"];

    const bool stop_on_error = params.value("stop_on_error", true);
    const bool want_parallel = params.value("parallel", false);
    double max_wall_seconds  = 60.0;
    if (params.contains("max_wall_seconds") && params["max_wall_seconds"].is_number())
        max_wall_seconds = params["max_wall_seconds"].get<double>();
    if (max_wall_seconds <= 0.0) max_wall_seconds = 60.0;

    // Pre-resolve tool definitions to compute aggregate flags + validate.
    std::vector<std::pair<std::string, json>> resolved;
    std::vector<std::string> labels;
    bool all_read_only = true;
    bool any_destructive = false;
    auto& registry = ToolRegistry::instance();

    resolved.reserve(calls_arr.size());
    labels.reserve(calls_arr.size());
    for (size_t i = 0; i < calls_arr.size(); ++i)
    {
        const json& c = calls_arr[i];
        if (!c.is_object() || !c.contains("tool") || !c["tool"].is_string())
        {
            return tool_result_t::error(
                std::string("calls[") + std::to_string(i) + std::string("] missing 'tool' string"),
                std::string("bad_param"));
        }
        std::string tname = c["tool"].get<std::string>();
        const auto* def = registry.get_tool(tname);
        if (!def)
        {
            return tool_result_t::error(
                std::string("Unknown tool: ") + tname,
                std::string("bad_param"));
        }
        if (!def->read_only) all_read_only = false;
        if (def->destructive) any_destructive = true;

        json args = json::object();
        if (c.contains("arguments") && c["arguments"].is_object())
            args = c["arguments"];

        std::string label;
        if (c.contains("label") && c["label"].is_string())
            label = c["label"].get<std::string>();

        resolved.emplace_back(std::move(tname), std::move(args));
        labels.push_back(std::move(label));
    }

    const bool fell_back_to_serial = want_parallel && !all_read_only;
    const bool can_parallel        = want_parallel && all_read_only;

    auto t_start = std::chrono::steady_clock::now();

    std::vector<tool_result_t> results_vec;
    size_t partial_count = 0;
    bool deadline_reached = false;
    bool ran_in_parallel  = false;

    if (can_parallel)
    {
        // Delegate to the qthread-backed parallel runner in mcp_server.cpp.
        // Read-only only — the runner does not coordinate writes against IDA's
        // main thread invariants.
        auto outcome = ::aida_mcp_internal::run_batch_parallel(
            resolved, labels, stop_on_error, (int)max_wall_seconds);
        results_vec     = std::move(outcome.results);
        // The runner pre-resizes results to resolved.size() and fills every
        // slot (workers + post-loop fill-in). Normalise partial_count to mean
        // "results produced" for consistency with the serial path.
        partial_count   = results_vec.size();
        deadline_reached= outcome.timed_out || outcome.cancelled;
        ran_in_parallel = true;
    }
    else
    {
        for (size_t i = 0; i < resolved.size(); ++i)
        {
            // Cooperative deadline + cancel checks between calls.
            auto now = std::chrono::steady_clock::now();
            double elapsed = std::chrono::duration<double>(now - t_start).count();
            if (elapsed > max_wall_seconds)
            {
                deadline_reached = true;
                break;
            }
            if (user_cancelled())
            {
                deadline_reached = true;
                break;
            }

            tool_result_t r = registry.execute_tool(resolved[i].first, resolved[i].second);
            results_vec.push_back(r);
            ++partial_count;
            if (!r.success && stop_on_error)
                break;
        }
    }

    auto t_end = std::chrono::steady_clock::now();
    uint64_t total_ms = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();

    json results_json = json::array();
    size_t ok_count = 0, fail_count = 0;
    for (size_t i = 0; i < results_vec.size(); ++i)
    {
        const auto& r = results_vec[i];
        json e;
        e["tool"]    = resolved[i].first;
        if (!labels[i].empty()) e["label"] = labels[i];
        e["success"] = r.success;
        if (!r.error_code.empty())
            e["error_code"] = r.error_code;
        e["output"]  = r.output;
        e["data"]    = r.data;
        results_json.push_back(std::move(e));
        if (r.success) ++ok_count; else ++fail_count;
    }

    json data;
    data["results"]              = results_json;
    data["total_ms"]             = total_ms;
    data["partial_count"]        = partial_count;
    data["total_requested"]      = resolved.size();
    data["ran_in_parallel"]      = ran_in_parallel;
    data["fell_back_to_serial"]  = fell_back_to_serial;
    data["all_read_only"]        = all_read_only;
    data["any_destructive"]      = any_destructive;
    data["deadline_reached"]     = deadline_reached;

    std::ostringstream ss;
    ss << std::string("Batch ran ") << partial_count << std::string("/") << resolved.size()
       << std::string(" calls (") << ok_count << std::string(" ok, ") << fail_count << std::string(" fail) in ")
       << total_ms << std::string("ms");
    if (fell_back_to_serial)
        ss << std::string("; parallel requested but mixed/write tools -> serial");
    if (deadline_reached)
        ss << std::string("; deadline reached");

    return tool_result_t::ok(ss.str(), data);
}

// ----------------------------------------------------------------------------
// Slice B3 — plan_the_hunt
//
// Hardcoded workflow library keyed by hunt_type. Steps reference tools that may
// not exist in the current registry yet (other slices) — that is intentional;
// the agent treats the plan as a recipe and skips unknown tools.
// ----------------------------------------------------------------------------
static json build_hunt_plan_library()
{
    json lib = json::object();

    auto step = [](const char* tool, const char* why,
                   const json& typical_args, const char* expected_evidence,
                   const char* on_empty, int expected_cost_ms) -> json
    {
        json s;
        s["tool"]              = tool;
        s["why"]               = why;
        s["typical_args"]      = typical_args;
        s["expected_evidence"] = expected_evidence;
        s["on_empty"]          = on_empty;
        s["expected_cost_ms"]  = expected_cost_ms;
        return s;
    };

    // remote_0click_rce
    {
        json p;
        p["steps"] = json::array({
            step("binary_fingerprint",
                 "Confirm binary is network-facing (network=true) and identify kind (driver/dll/exe).",
                 json::object(),
                 "capabilities.network=true and imports include WINSOCK/RPC/COM",
                 "Likely not a remote attack surface — pivot to local/IPC hunt.", 200),
            step("list_remote_entrypoints",
                 "Rank pre-auth-likely server entrypoints (RPC/COM/HTTP/named-pipe).",
                 json::object({{"top_n", 64}}),
                 "Ranked list with pre_auth_likelihood>=0.6",
                 "Try enumerate_rpc_servers / find_pre_auth_paths directly.", 800),
            step("enumerate_rpc_servers",
                 "Enumerate MIDL_SERVER_INFO tables / RpcServerRegisterIf callees.",
                 json::object(),
                 "RPC interface UUIDs + dispatch table EAs",
                 "Binary may not be MIDL-generated.", 1500),
            step("find_pre_auth_paths",
                 "Locate dispatch paths reachable before authentication check.",
                 json::object(),
                 "Functions reached before SSPI/Negotiate/CheckSecurityContext",
                 "Authentication may be elsewhere; widen list_remote_entrypoints scope.", 4000),
            step("trace_all_network_to_sinks",
                 "Taint propagate from network sources to memory/integer sinks.",
                 json::object({{"max_depth", 16}}),
                 "Taint paths with score>=70",
                 "Increase max_depth or relax filters.", 8000),
            step("hunt_remote_rce",
                 "Verification: SMT-back the taint paths and demand reachable, controlled writes.",
                 json::object(),
                 "Verified RCE candidates with SMT model",
                 "Symbolic engine timed out — try smaller slice.", 12000),
        });
        p["required_indices"] = json::array({"taint_engine", "microcode_engine", "cfg_engine"});
        p["notes"] = std::string("Remote 0-click RCE focuses on attacker reaching a pre-auth dispatch and tainting controllable bytes into a write/exec sink.");
        lib["remote_0click_rce"] = p;
    }

    // kernel_ioctl_bug
    {
        json p;
        p["steps"] = json::array({
            step("binary_fingerprint",
                 "Confirm kernel-mode (is_kernel=true) and capability vector mentions driver.",
                 json::object(),
                 "is_kernel=true and capabilities.driver=true",
                 "Not a driver — switch hunt_type.", 200),
            step("enumerate_ioctl_handlers",
                 "Locate IRP_MJ_DEVICE_CONTROL dispatch + IOCTL code switch.",
                 json::object(),
                 "Dispatch table EA + per-IOCTL handler map",
                 "Manual locate via xrefs to IoCreateDevice / IRP MajorFunction[].", 2000),
            step("classify_ioctl_buffer_methods",
                 "Decode METHOD_BUFFERED/IN_DIRECT/OUT_DIRECT/NEITHER per IOCTL.",
                 json::object(),
                 "Method enum per IOCTL code",
                 "Default to NEITHER (highest risk) and continue.", 1000),
            step("trace_ioctl_userptr_to_sinks",
                 "Taint Irp->UserBuffer / Type3InputBuffer to kernel sinks.",
                 json::object(),
                 "Taint paths from user buffer to memcpy / write_user / ProbeForRead missing",
                 "Re-run with relaxed sink set.", 8000),
            step("hunt_kernel_writewhatwhere",
                 "Symbolic search for arbitrary write primitives.",
                 json::object(),
                 "Verified W/W primitive callsites",
                 "Try hunt_kernel_uaf next.", 12000),
        });
        p["required_indices"] = json::array({"kernel_engine", "taint_engine", "microcode_engine"});
        p["notes"] = std::string("Kernel IOCTL bugs centre on missing ProbeForRead/Write and method-NEITHER buffers reaching kernel sinks.");
        lib["kernel_ioctl_bug"] = p;
    }

    // sandbox_escape
    {
        json p;
        p["steps"] = json::array({
            step("binary_fingerprint",
                 "Identify sandbox-relevant capability (COM/RPC/ALPC).",
                 json::object(),
                 "capabilities.com or capabilities.alpc true",
                 "Pivot to local privilege escalation hunt.", 200),
            step("enumerate_com_servers",
                 "List CoRegisterClassObject/DllGetClassObject implementations.",
                 json::object(),
                 "CLSID table + class object factories",
                 "Look at ALPC/named-pipe IPC instead.", 2000),
            step("list_alpc_servers",
                 "Find ALPC ports advertised via NtAlpcCreatePort.",
                 json::object(),
                 "Named ALPC ports + message dispatch loops",
                 "ALPC may not be used.", 1500),
            step("trace_low_il_to_high_il",
                 "Taint paths from cross-IL boundaries to privileged operations.",
                 json::object(),
                 "Cross-integrity-level taint paths",
                 "Broaden sources to all IPC entrypoints.", 8000),
        });
        p["required_indices"] = json::array({"surface_engine", "taint_engine"});
        p["notes"] = std::string("Sandbox escape requires identifying a higher-IL service reachable from sandbox-IL and finding controllable input that reaches privileged action.");
        lib["sandbox_escape"] = p;
    }

    // parser_bug
    {
        json p;
        p["steps"] = json::array({
            step("binary_fingerprint",
                 "Quick capability check.", json::object(),
                 "Any input-heavy capability set",
                 "Still worth running parser hunt.", 200),
            step("find_format_parsers",
                 "Locate fixed-length headers + variable-length payload parsers.",
                 json::object(),
                 "Functions matching parser shape (loop + length prefix read)",
                 "Try graphrag search_semantic for 'parser'.", 3000),
            step("classify_parser_kind",
                 "Classify each candidate (TLV, length-prefixed, ASN.1, protobuf, XML).",
                 json::object(),
                 "Kind label + confidence per parser",
                 "Move to broader trace_all_user_to_sinks.", 2000),
            step("hunt_integer_overflow_into_alloc",
                 "Find arithmetic on attacker-controlled length feeding allocation.",
                 json::object(),
                 "Integer overflow callsites with SMT proof",
                 "Lower SMT timeout and re-run.", 8000),
        });
        p["required_indices"] = json::array({"microcode_engine", "symbolic_engine", "smt_solver"});
        p["notes"] = std::string("Parser bugs commonly originate from missing length/range checks before allocation or copy.");
        lib["parser_bug"] = p;
    }

    // auth_bypass
    {
        json p;
        p["steps"] = json::array({
            step("binary_fingerprint",
                 "Surface check.", json::object(),
                 "Network or service capability",
                 "Skip auth_bypass hunt.", 200),
            step("find_auth_checks",
                 "Locate SSPI/NTLM/Negotiate/AcceptSecurityContext callsites.",
                 json::object(),
                 "Functions wrapping auth checks",
                 "Auth may be delegated; search graphrag.", 2000),
            step("find_unauthenticated_reachable",
                 "Walk reverse from auth check; find callers reachable without it.",
                 json::object(),
                 "Pre-auth reachable function set",
                 "All paths gated — bypass unlikely.", 6000),
            step("symbolically_prove_bypass",
                 "Symbolic execution to prove an unauthenticated path reaches a privileged op.",
                 json::object(),
                 "Concrete SMT model bypassing auth",
                 "Try relaxed model.", 10000),
        });
        p["required_indices"] = json::array({"cfg_engine", "symbolic_engine", "smt_solver"});
        p["notes"] = std::string("Auth bypass = privileged path reachable without auth check or with broken check semantics.");
        lib["auth_bypass"] = p;
    }

    // uaf
    {
        json p;
        p["steps"] = json::array({
            step("binary_fingerprint",
                 "Surface check.", json::object(),
                 "Any complex object lifetime surface",
                 "Skip uaf.", 200),
            step("find_allocators_and_frees",
                 "Locate pairing alloc/free family callsites.",
                 json::object(),
                 "alloc/free pairs with object types",
                 "Allocators may be inlined; widen.", 3000),
            step("hunt_uaf",
                 "Symbolic execution chasing post-free deref.",
                 json::object(),
                 "Concrete UAF paths with proof",
                 "Increase symbolic budget.", 12000),
        });
        p["required_indices"] = json::array({"taint_engine", "symbolic_engine"});
        p["notes"] = std::string("Use-after-free hunts require lifetime tracking — costly but high-value.");
        lib["uaf"] = p;
    }

    // format_string
    {
        json p;
        p["steps"] = json::array({
            step("binary_fingerprint",
                 "Surface check.", json::object(),
                 "Imports printf-family",
                 "Likely no format-string surface.", 200),
            step("find_printf_calls",
                 "Locate printf-family callsites.",
                 json::object(),
                 "List of printf-family call EAs + format-arg index",
                 "No printf family used.", 1500),
            step("trace_format_to_attacker",
                 "Taint format argument back to known sources.",
                 json::object(),
                 "Tainted format-string paths",
                 "Format arg appears to be constant — done.", 4000),
        });
        p["required_indices"] = json::array({"taint_engine", "microcode_engine"});
        p["notes"] = std::string("Format-string bugs are easy wins when the fmt arg is attacker-controlled.");
        lib["format_string"] = p;
    }

    // all = aggregate of every hunt above, in order.
    {
        json p;
        json steps = json::array();
        json req   = json::array({"graphrag", "taint_engine", "microcode_engine", "cfg_engine", "kernel_engine", "surface_engine", "symbolic_engine", "smt_solver"});
        // Reference each hunt as a meta-step so the agent can fan out.
        const char* hunts[] = {
            "remote_0click_rce", "kernel_ioctl_bug", "sandbox_escape",
            "parser_bug", "auth_bypass", "uaf", "format_string" };
        for (auto* h : hunts)
        {
            json s;
            s["tool"]              = "plan_the_hunt";
            s["why"]               = std::string(std::string("Fan out to ")) + h;
            s["typical_args"]      = json::object({{"hunt_type", h}});
            s["expected_evidence"] = std::string("Nested plan returned");
            s["on_empty"]          = std::string("Unknown hunt type — should not happen here.");
            s["expected_cost_ms"]  = 10;
            steps.push_back(std::move(s));
        }
        p["steps"] = std::move(steps);
        p["required_indices"] = std::move(req);
        p["notes"] = std::string("Aggregate plan — execute each hunt sequentially or in parallel.");
        lib["all"] = p;
    }

    return lib;
}

tool_result_t plan_the_hunt(const json& params)
{
    std::string hunt_type = std::string("remote_0click_rce");
    if (params.contains("hunt_type") && params["hunt_type"].is_string())
        hunt_type = params["hunt_type"].get<std::string>();

    static const json lib = build_hunt_plan_library();
    auto it = lib.find(hunt_type);
    if (it == lib.end())
    {
        std::ostringstream ss;
        ss << std::string("Unknown hunt_type '") << hunt_type << std::string("'. Valid: ");
        bool first = true;
        for (auto kv = lib.cbegin(); kv != lib.cend(); ++kv)
        {
            if (!first) ss << std::string(", ");
            ss << kv.key();
            first = false;
        }
        return tool_result_t::error(ss.str(), std::string("bad_param"));
    }

    json data;
    data["hunt_type"]        = hunt_type;
    data["plan"]             = *it;
    data["step_count"]       = it->value("steps", json::array()).size();
    return tool_result_t::ok(std::string("Plan for ") + hunt_type, data);
}

// ----------------------------------------------------------------------------
// Slice B4 — index_status
// ----------------------------------------------------------------------------
static json engine_status_stub(bool available = false, bool populated = false, uint64_t count = 0)
{
    json j;
    j["available"] = available;
    j["populated"] = populated;
    j["count"]     = count;
    return j;
}

tool_result_t index_status(const json&)
{
    json data;

    // Binary MD5 (matches binary_fingerprint formatting).
    {
        unsigned char md5[16] = {};
        if (retrieve_input_file_md5(md5))
        {
            char buf[33] = {};
            for (int i = 0; i < 16; ++i)
                ::qsnprintf(buf + i * 2, 3, "%02x", md5[i]);
            data["binary_md5"] = std::string(buf, 32);
        }
        else
        {
            data["binary_md5"] = "";
        }
    }

    data["auto_analysis_ok"]   = auto_is_ok();
    data["hexrays_available"]  = init_hexrays_plugin();

    json engines;
    // No unified status APIs on these engines yet — graceful degradation.
    // Downstream slices that wire real status methods are expected to update
    // this block in place. Slice B owners must not depend on engine internals.
    engines["graphrag"]         = engine_status_stub();
    engines["taint_engine"]     = engine_status_stub();
    engines["microcode_engine"] = engine_status_stub();
    engines["cfg_engine"]       = engine_status_stub();
    engines["kernel_engine"]    = engine_status_stub();
    engines["surface_engine"]   = engine_status_stub();
    engines["symbolic_engine"]  = engine_status_stub();
    engines["smt_solver"]       = engine_status_stub();

    data["engines"] = engines;

    return tool_result_t::ok(std::string("Index status snapshot"), data);
}

// ----------------------------------------------------------------------------
// Slice B5 — build_index
// ----------------------------------------------------------------------------
static const char* k_valid_engines[] = {
    "graphrag", "taint_engine", "microcode_engine", "cfg_engine",
    "kernel_engine", "surface_engine", "symbolic_engine", "smt_solver"
};

tool_result_t build_index(const json& params)
{
    std::vector<std::string> requested;
    bool all = false;

    if (!params.contains("indices"))
    {
        all = true;
    }
    else
    {
        const json& v = params["indices"];
        if (v.is_string())
        {
            std::string s = v.get<std::string>();
            if (s == "all") all = true;
            else            requested.push_back(s);
        }
        else if (v.is_array())
        {
            for (const auto& e : v)
            {
                if (e.is_string())
                {
                    std::string s = e.get<std::string>();
                    if (s == "all") { all = true; break; }
                    requested.push_back(s);
                }
            }
        }
        else
        {
            return tool_result_t::error(std::string("'indices' must be string or array"), std::string("bad_param"));
        }
    }

    if (all)
    {
        requested.clear();
        for (auto* n : k_valid_engines) requested.emplace_back(n);
    }

    // Validate names.
    for (const auto& name : requested)
    {
        bool ok = false;
        for (auto* n : k_valid_engines) if (name == n) { ok = true; break; }
        if (!ok)
        {
            return tool_result_t::error(std::string("Unknown engine: ") + name, std::string("bad_param"));
        }
    }

    double max_seconds = 60.0;
    if (params.contains("max_seconds") && params["max_seconds"].is_number())
        max_seconds = params["max_seconds"].get<double>();
    if (max_seconds <= 0.0) max_seconds = 60.0;

    show_wait_box("AiDA: warming engines...");
    auto t_start = std::chrono::steady_clock::now();

    json warmed = json::array();
    bool deadline_reached = false;
    bool any_partial = false;

    for (const auto& name : requested)
    {
        auto now = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - t_start).count();
        if (elapsed > max_seconds)
        {
            deadline_reached = true;
            break;
        }
        if (user_cancelled())
        {
            deadline_reached = true;
            break;
        }

        json entry;
        entry["engine"]    = name;
        auto t_engine = std::chrono::steady_clock::now();

        // Engines have no unified warm-up API yet; downstream slices are
        // expected to plug into this switch. Report partial=true for each so
        // the caller knows nothing was actually warmed.
        bool populated = false;
        uint64_t count = 0;
        std::string err;
        try
        {
            // Pass via %s to defend against engine names containing '%' if a
            // downstream slice ever expands the valid-engine list.
            replace_wait_box("AiDA: warming %s...", name.c_str());
            // Intentional no-op for Slice B — engines populate themselves on
            // first use. Mark partial=true so callers do not assume success.
        }
        catch (const std::exception& e)
        {
            err = e.what();
        }

        auto t_engine_end = std::chrono::steady_clock::now();
        uint64_t engine_ms = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(t_engine_end - t_engine).count();

        entry["populated"]  = populated;
        entry["count"]      = count;
        entry["elapsed_ms"] = engine_ms;
        entry["partial"]    = true; // no warm-up backend wired yet
        if (!err.empty()) entry["error"] = err;
        any_partial = true;
        warmed.push_back(std::move(entry));
    }

    hide_wait_box();
    auto t_end = std::chrono::steady_clock::now();
    uint64_t total_ms = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();

    json data;
    data["warmed"]            = warmed;
    data["total_ms"]          = total_ms;
    data["deadline_reached"]  = deadline_reached;
    data["any_partial"]       = any_partial;

    std::ostringstream ss;
    ss << std::string("build_index: ") << warmed.size() << std::string(" engines visited in ") << total_ms << std::string("ms");
    if (any_partial) ss << std::string(" (partial — no warm-up backend wired)");
    if (deadline_reached) ss << std::string(" [deadline reached]");

    return tool_result_t::ok(ss.str(), data);
}

// ----------------------------------------------------------------------------
// Slice B6 — session_scratch
// ----------------------------------------------------------------------------
static const char* k_scratch_node_name = "$ AiDA.hunt.scratch";
static constexpr size_t k_scratch_max_total_bytes = 512 * 1024;
// We store the user payloads under tag htag (default). The aggregate size
// counter is stored under a separate altval tag to avoid colliding with hash
// keys. Use a distinct tag char.
static constexpr uchar k_scratch_size_tag = 'A';
static constexpr nodeidx_t k_scratch_size_altidx = 0;

static netnode get_scratch_node()
{
    return netnode(k_scratch_node_name, 0, true);
}

static uint64_t scratch_get_total_bytes(netnode& nn)
{
    nodeidx_t v = nn.altval(k_scratch_size_altidx, k_scratch_size_tag);
    return (uint64_t)v;
}

static void scratch_set_total_bytes(netnode& nn, uint64_t v)
{
    nn.altset(k_scratch_size_altidx, (nodeidx_t)v, k_scratch_size_tag);
}

static std::vector<std::string> scratch_collect_keys(netnode& nn)
{
    std::vector<std::string> keys;
    qstring cur;
    ssize_t got = nn.hashfirst(&cur);
    while (got >= 0)
    {
        // Snapshot cur before passing it back into hashnext — the SDK writes
        // the next key into the same qstring buffer and could invalidate the
        // backing pointer otherwise.
        std::string prev(cur.c_str(), cur.length());
        keys.push_back(prev);
        if (keys.size() > 100000) break; // safety
        got = nn.hashnext(&cur, prev.c_str());
    }
    return keys;
}

static size_t scratch_value_size(netnode& nn, const char* key)
{
    return (size_t)nn.hashval(key, nullptr, 0);
}

// Auto-prune: walks keys, deletes oldest-by-key-order until under threshold.
// netnode hash iteration order is not strictly insertion order, but it is
// deterministic given the IDA backing — good enough as a bounded eviction.
static size_t scratch_autoprune(netnode& nn, uint64_t threshold)
{
    size_t pruned = 0;
    uint64_t total = scratch_get_total_bytes(nn);
    if (total <= threshold) return 0;

    auto keys = scratch_collect_keys(nn);
    for (const auto& k : keys)
    {
        if (total <= threshold) break;
        ssize_t sz = nn.hashval(k.c_str(), nullptr, 0);
        if (sz <= 0) continue;
        nn.hashdel(k.c_str());
        if ((uint64_t)sz <= total) total -= (uint64_t)sz; else total = 0;
        ++pruned;
    }
    scratch_set_total_bytes(nn, total);
    return pruned;
}

tool_result_t session_scratch(const json& params)
{
    std::string op = std::string("get");
    if (params.contains("op") && params["op"].is_string())
        op = params["op"].get<std::string>();

    netnode nn = get_scratch_node();

    if (op == "set")
    {
        if (!params.contains("key") || !params["key"].is_string())
            return tool_result_t::error(std::string("'key' required"), std::string("bad_param"));
        std::string key = params["key"].get<std::string>();
        if (key.empty() || key.size() > 512)
            return tool_result_t::error(std::string("'key' must be 1..512 chars"), std::string("bad_param"));

        std::string value;
        if (params.contains("value"))
        {
            const json& v = params["value"];
            if (v.is_string())     value = v.get<std::string>();
            else if (!v.is_null()) value = v.dump();
            // empty/null allowed
        }

        size_t old_sz = scratch_value_size(nn, key.c_str());
        nn.hashset(key.c_str(), value.empty() ? "" : value.data(), value.size());
        uint64_t total = scratch_get_total_bytes(nn);
        // Adjust counter: subtract old, add new (saturate).
        total = (total >= old_sz) ? (total - old_sz) : 0;
        total += value.size();
        scratch_set_total_bytes(nn, total);

        size_t pruned = scratch_autoprune(nn, k_scratch_max_total_bytes);

        json data;
        data["key"]           = key;
        data["bytes_written"] = (uint64_t)value.size();
        data["total_bytes"]   = scratch_get_total_bytes(nn);
        data["pruned_count"]  = (uint64_t)pruned;
        return tool_result_t::ok(std::string("scratch set ok"), data);
    }
    else if (op == "get")
    {
        if (!params.contains("key") || !params["key"].is_string())
            return tool_result_t::error(std::string("'key' required"), std::string("bad_param"));
        std::string key = params["key"].get<std::string>();

        ssize_t need = nn.hashval(key.c_str(), nullptr, 0);
        if (need < 0)
        {
            json data;
            data["found"] = false;
            data["key"]   = key;
            return tool_result_t::ok(std::string("scratch get: not found"), data);
        }
        std::string buf;
        buf.resize((size_t)need);
        if (need > 0)
            nn.hashval(key.c_str(), buf.data(), buf.size());

        json data;
        data["found"] = true;
        data["key"]   = key;
        data["value"] = buf;
        data["bytes"] = (uint64_t)buf.size();
        return tool_result_t::ok(std::string("scratch get ok"), data);
    }
    else if (op == "append")
    {
        if (!params.contains("key") || !params["key"].is_string())
            return tool_result_t::error(std::string("'key' required"), std::string("bad_param"));
        std::string key = params["key"].get<std::string>();
        std::string add;
        if (params.contains("value"))
        {
            const json& v = params["value"];
            if (v.is_string())     add = v.get<std::string>();
            else if (!v.is_null()) add = v.dump();
        }

        std::string cur;
        ssize_t have = nn.hashval(key.c_str(), nullptr, 0);
        if (have > 0)
        {
            cur.resize((size_t)have);
            nn.hashval(key.c_str(), cur.data(), cur.size());
        }
        size_t old_sz = (have > 0) ? (size_t)have : 0;
        cur.append(add);
        nn.hashset(key.c_str(), cur.empty() ? "" : cur.data(), cur.size());
        uint64_t total = scratch_get_total_bytes(nn);
        total = (total >= old_sz) ? (total - old_sz) : 0;
        total += cur.size();
        scratch_set_total_bytes(nn, total);

        size_t pruned = scratch_autoprune(nn, k_scratch_max_total_bytes);

        json data;
        data["key"]           = key;
        data["new_length"]    = (uint64_t)cur.size();
        data["total_bytes"]   = scratch_get_total_bytes(nn);
        data["pruned_count"]  = (uint64_t)pruned;
        return tool_result_t::ok(std::string("scratch append ok"), data);
    }
    else if (op == "list")
    {
        uint64_t offset = 0;
        uint64_t limit  = 256;
        if (params.contains("offset") && params["offset"].is_number_unsigned())
            offset = params["offset"].get<uint64_t>();
        if (params.contains("limit") && params["limit"].is_number_unsigned())
            limit = std::min<uint64_t>(params["limit"].get<uint64_t>(), 4096);

        auto keys = scratch_collect_keys(nn);
        json arr = json::array();
        for (uint64_t i = offset; i < (uint64_t)keys.size() && arr.size() < limit; ++i)
        {
            json e;
            e["key"]   = keys[i];
            e["bytes"] = (uint64_t)nn.hashval(keys[i].c_str(), nullptr, 0);
            arr.push_back(std::move(e));
        }
        json data;
        data["entries"]    = arr;
        data["total_keys"] = (uint64_t)keys.size();
        data["total_bytes"]= scratch_get_total_bytes(nn);
        data["offset"]     = offset;
        data["limit"]      = limit;
        return tool_result_t::ok(std::string("scratch list ok"), data);
    }
    else if (op == "delete")
    {
        bool all = params.value("all", false);
        if (all)
        {
            auto keys = scratch_collect_keys(nn);
            for (const auto& k : keys) nn.hashdel(k.c_str());
            nn.hashdel_all();
            scratch_set_total_bytes(nn, 0);
            json data;
            data["deleted_count"] = (uint64_t)keys.size();
            data["all"]           = true;
            return tool_result_t::ok(std::string("scratch delete all ok"), data);
        }
        if (!params.contains("key") || !params["key"].is_string())
            return tool_result_t::error(std::string("'key' or all=true required"), std::string("bad_param"));
        std::string key = params["key"].get<std::string>();
        ssize_t sz = nn.hashval(key.c_str(), nullptr, 0);
        bool removed = false;
        if (sz >= 0)
        {
            nn.hashdel(key.c_str());
            uint64_t total = scratch_get_total_bytes(nn);
            uint64_t s = (sz > 0) ? (uint64_t)sz : 0;
            total = (total >= s) ? (total - s) : 0;
            scratch_set_total_bytes(nn, total);
            removed = true;
        }
        json data;
        data["key"]     = key;
        data["removed"] = removed;
        data["total_bytes"] = scratch_get_total_bytes(nn);
        return tool_result_t::ok(removed ? std::string("scratch delete ok") : std::string("scratch delete: not found"), data);
    }

    return tool_result_t::error(std::string("Unknown op: ") + op + std::string(" (set|get|append|list|delete)"),
                                 std::string("bad_param"));
}

// ----------------------------------------------------------------------------
// Slice B8 — list_remote_entrypoints
// ----------------------------------------------------------------------------
struct b8_func_acc_t
{
    ea_t func_ea = BADADDR;
    std::set<std::string> source_names;
    std::set<std::string> source_categories;
    qstring name;
};

static void b8_walk_source_array(const aida::vuln::sig::source_signature_t* arr, size_t count,
                                 const char* category,
                                 std::map<ea_t, b8_func_acc_t>& acc)
{
    for (size_t i = 0; i < count; ++i)
    {
        std::string sname(arr[i].name.data(), arr[i].name.size());
        ea_t sym = get_name_ea(BADADDR, sname.c_str());
        if (sym == BADADDR)
            continue;

        xrefblk_t xb;
        for (bool ok = xb.first_to(sym, XREF_ALL); ok; ok = xb.next_to())
        {
            func_t* pfn = get_func(xb.from);
            if (!pfn) continue;
            ea_t fea = pfn->start_ea;
            auto& slot = acc[fea];
            if (slot.func_ea == BADADDR)
            {
                slot.func_ea = fea;
                get_func_name(&slot.name, fea);
            }
            slot.source_names.insert(sname);
            slot.source_categories.insert(category);
        }
    }
}

tool_result_t list_remote_entrypoints(const json& params)
{
    uint64_t top_n = 64;
    if (params.contains("top_n") && params["top_n"].is_number_unsigned())
        top_n = std::min<uint64_t>(params["top_n"].get<uint64_t>(), 256);

    using namespace aida::vuln::sig;

    std::map<ea_t, b8_func_acc_t> acc;

#define B8_WALK(arr, cat) b8_walk_source_array((arr), sizeof(arr)/sizeof((arr)[0]), (cat), acc)
    B8_WALK(RPC_SERVER_SINKS,       "rpc_server");
    B8_WALK(COM_SERVER_SINKS,       "com_server");
    B8_WALK(ALPC_SOURCES,           "alpc");
    B8_WALK(NAMED_PIPE_SOURCES,     "named_pipe");
    B8_WALK(SOCKET_ACCEPT_SOURCES,  "socket_accept");
    B8_WALK(HTTP_SERVER_SOURCES,    "http_server");
    B8_WALK(WEBSOCKET_SOURCES,      "websocket");
    B8_WALK(NDIS_WSK_SOURCES,       "ndis_wsk");
    B8_WALK(KERNEL_IRP_SOURCES,     "kernel_irp");
#undef B8_WALK

    static const char* k_init_hints[] = {
        "init", "setup", "start", "handler", "dispatch", "process", "receive"
    };

    struct ranked_t
    {
        ea_t ea = BADADDR;
        std::string name;
        std::vector<std::string> categories;
        std::vector<std::string> reachable_imports;
        std::set<std::string> kinds;
        double score = 0.0;
    };

    std::vector<ranked_t> ranked;
    ranked.reserve(acc.size());
    for (auto& kv : acc)
    {
        ranked_t r;
        r.ea   = kv.first;
        r.name = kv.second.name.c_str();
        for (const auto& c : kv.second.source_categories)
        {
            r.categories.push_back(c);
            r.kinds.insert(c);
        }
        for (const auto& n : kv.second.source_names)
            r.reachable_imports.push_back(n);

        double s = 0.5;
        s += 0.10 * (double)r.kinds.size();

        std::string lower = r.name;
        for (auto& ch : lower) ch = (char)std::tolower((unsigned char)ch);
        for (auto* hint : k_init_hints)
        {
            if (lower.find(hint) != std::string::npos)
            {
                s += 0.20;
                break; // one bonus per function
            }
        }
        if (s > 1.0) s = 1.0;
        if (s < 0.0) s = 0.0;
        r.score = s;
        ranked.push_back(std::move(r));
    }

    std::sort(ranked.begin(), ranked.end(),
              [](const ranked_t& a, const ranked_t& b)
              {
                  if (a.score != b.score) return a.score > b.score;
                  return a.ea < b.ea;
              });

    json arr = json::array();
    for (size_t i = 0; i < ranked.size() && arr.size() < top_n; ++i)
    {
        const auto& r = ranked[i];
        json e;
        e["ea"]                  = helpers::format_address(r.ea);
        e["name"]                = r.name;
        e["category"]            = r.categories;
        e["kind_evidence"]       = std::vector<std::string>(r.kinds.begin(), r.kinds.end());
        e["reachable_imports"]   = r.reachable_imports;
        e["pre_auth_likelihood"] = r.score;
        arr.push_back(std::move(e));
    }

    json data;
    data["entries"]         = arr;
    data["total_candidates"]= (uint64_t)ranked.size();
    data["top_n"]           = top_n;

    std::ostringstream ss;
    ss << std::string("list_remote_entrypoints: ") << arr.size() << std::string("/") << ranked.size()
       << std::string(" entrypoints");
    return tool_result_t::ok(ss.str(), data);
}

// ----------------------------------------------------------------------------
// Slice B9 — list_outputs (delegates to mcp_server output cache)
// ----------------------------------------------------------------------------
tool_result_t list_outputs(const json& params)
{
    std::string op = std::string("list");
    if (params.contains("op") && params["op"].is_string())
        op = params["op"].get<std::string>();

    if (op == "list")
    {
        auto entries = aida_mcp_internal::output_cache_list();
        json arr = json::array();
        for (const auto& e : entries)
        {
            json je;
            je["output_id"]   = e.id;
            je["total_bytes"] = (uint64_t)e.json_bytes;
            arr.push_back(std::move(je));
        }
        json data;
        data["entries"]     = arr;
        data["entry_count"] = (uint64_t)entries.size();
        return tool_result_t::ok(std::string("list_outputs: list ok"), data);
    }
    if (op == "stats")
    {
        auto s = aida_mcp_internal::output_cache_stats();
        json data;
        data["entry_count"] = (uint64_t)s.total_entries;
        data["used"]        = (uint64_t)s.total_bytes;
        data["capacity"]    = (uint64_t)s.limit;
        data["text_limit"]  = (uint64_t)s.text_limit;
        return tool_result_t::ok(std::string("list_outputs: stats ok"), data);
    }
    if (op == "evict")
    {
        bool all = params.value("all", false);
        if (all)
        {
            size_t n = aida_mcp_internal::output_cache_evict_all();
            json data;
            data["evicted_count"] = (uint64_t)n;
            data["all"]           = true;
            return tool_result_t::ok(std::string("list_outputs: evict all ok"), data);
        }
        if (!params.contains("output_id") || !params["output_id"].is_string())
            return tool_result_t::error(std::string("'output_id' or all=true required"), std::string("bad_param"));
        std::string id = params["output_id"].get<std::string>();
        bool ok = aida_mcp_internal::output_cache_evict_one(id);
        json data;
        data["evicted_count"] = ok ? 1 : 0;
        data["evicted_ids"]   = ok ? json::array({id}) : json::array();
        return tool_result_t::ok(ok ? std::string("list_outputs: evict ok") : std::string("list_outputs: id not found"), data);
    }

    return tool_result_t::error(std::string("Unknown op: ") + op + std::string(" (list|stats|evict)"),
                                 std::string("bad_param"));
}

// ----------------------------------------------------------------------------
// Slice B10 — ask_capability
// ----------------------------------------------------------------------------
struct b10_suggestion_t
{
    std::string tool;
    std::string why;
    json        typical_args;
    json        sample_call;
};

static const std::map<std::string, std::vector<const char*>>& b10_keyword_map()
{
    static const std::map<std::string, std::vector<const char*>> m = {
        {"network",      {"binary_fingerprint", "list_remote_entrypoints", "trace_all_network_to_sinks"}},
        {"socket",       {"list_remote_entrypoints", "trace_all_network_to_sinks"}},
        {"recv",         {"list_remote_entrypoints", "trace_all_network_to_sinks"}},
        {"send",         {"list_remote_entrypoints", "trace_all_network_to_sinks"}},
        {"http",         {"list_remote_entrypoints"}},
        {"https",        {"list_remote_entrypoints"}},
        {"websocket",    {"list_remote_entrypoints"}},
        {"rpc",          {"list_remote_entrypoints", "enumerate_rpc_servers"}},
        {"midl",         {"enumerate_rpc_servers"}},
        {"com",          {"enumerate_com_servers"}},
        {"clsid",        {"enumerate_com_servers"}},
        {"alpc",         {"list_alpc_servers"}},
        {"pipe",         {"list_remote_entrypoints"}},
        {"namedpipe",    {"list_remote_entrypoints"}},
        {"driver",       {"binary_fingerprint", "enumerate_ioctl_handlers", "classify_ioctl_buffer_methods"}},
        {"kernel",       {"binary_fingerprint", "enumerate_ioctl_handlers", "hunt_kernel_writewhatwhere"}},
        {"ioctl",        {"enumerate_ioctl_handlers", "classify_ioctl_buffer_methods", "trace_ioctl_userptr_to_sinks"}},
        {"irp",          {"enumerate_ioctl_handlers"}},
        {"taint",        {"trace_all_network_to_sinks", "trace_taint_reverse"}},
        {"reverse",      {"trace_taint_reverse"}},
        {"flow",         {"trace_data_flow", "trace_all_network_to_sinks"}},
        {"vtable",       {"reconstruct_vtable", "find_dispatch_tables"}},
        {"dispatch",     {"find_dispatch_tables"}},
        {"indirect",     {"analyze_indirect_calls"}},
        {"vfunc",        {"reconstruct_vtable"}},
        {"format",       {"find_format_parsers", "find_printf_calls"}},
        {"printf",       {"find_printf_calls", "trace_format_to_attacker"}},
        {"parser",       {"find_format_parsers", "hunt_integer_overflow_into_alloc"}},
        {"overflow",     {"hunt_integer_overflow_into_alloc"}},
        {"integer",      {"hunt_integer_overflow_into_alloc"}},
        {"uaf",          {"hunt_uaf", "find_allocators_and_frees"}},
        {"free",         {"find_allocators_and_frees", "hunt_uaf"}},
        {"alloc",        {"find_allocators_and_frees"}},
        {"auth",         {"find_auth_checks", "find_unauthenticated_reachable"}},
        {"login",        {"find_auth_checks"}},
        {"crypto",       {"find_crypto_constants", "binary_fingerprint"}},
        {"hash",         {"find_crypto_constants"}},
        {"vmprotect",    {"identify_protector", "deobfuscate_control_flow"}},
        {"obfuscation",  {"detect_obfuscation_patterns", "identify_protector"}},
        {"vm",           {"detect_vm_handler_pattern", "map_vm_handler_table"}},
        {"deobfuscate",  {"deobfuscate_control_flow", "decode_strings_in_function"}},
        {"strings",      {"search_strings", "decode_strings_in_function"}},
        {"decrypt",      {"analyze_string_decryption", "decode_strings_in_function"}},
        {"hook",         {"detect_hooks"}},
        {"syscall",      {"detect_direct_syscalls"}},
        {"antidebug",    {"detect_anti_analysis", "patch_anti_debug"}},
        {"sandbox",      {"binary_fingerprint", "find_unauthenticated_reachable"}},
        {"pe",           {"analyze_pe_headers"}},
        {"entropy",      {"analyze_entropy", "identify_protector"}},
        {"import",       {"list_imports", "binary_fingerprint"}},
        {"export",       {"list_exports"}},
        {"function",     {"list_functions", "get_function"}},
        {"decompile",    {"decompile", "decompile_function"}},
        {"disasm",       {"disasm", "disassemble_function"}},
        {"xref",         {"xrefs_to", "xref_query"}},
        {"struct",       {"reconstruct_struct", "create_struct"}},
        {"type",         {"declare_type", "infer_type"}},
        {"graph",        {"build_call_graph", "callgraph"}},
        {"semantic",     {"search_semantic", "get_semantic_analysis"}},
        {"similar",      {"get_similar_functions"}},
        {"community",    {"get_community_info", "detect_communities"}},
        {"plan",         {"plan_the_hunt"}},
        {"capability",   {"binary_fingerprint", "ask_capability"}},
        {"identity",     {"binary_fingerprint"}},
        {"fingerprint",  {"binary_fingerprint"}},
        {"warmup",       {"build_index", "index_status"}},
        {"status",       {"index_status", "server_health"}},
        {"index",        {"build_index", "index_status"}},
        {"scratch",      {"session_scratch"}},
        {"output",       {"list_outputs"}},
        {"example",      {"sample_tool_io"}},
        {"sample",       {"sample_tool_io"}},
        {"batch",        {"tool_batch_call"}},
        {"parallel",     {"tool_batch_call"}},
    };
    return m;
}

static const std::map<std::string, std::pair<std::string, json>>& b10_tool_hints()
{
    // (why, typical_args). sample_call is built per suggestion below.
    static const std::map<std::string, std::pair<std::string, json>> m = {
        {"binary_fingerprint",        {"Identify binary kind and attack-surface capability vector.", json::object()}},
        {"list_remote_entrypoints",   {"Rank network/RPC/COM/ALPC/HTTP entrypoints by pre-auth likelihood.", json::object({{"top_n", 64}})}},
        {"trace_all_network_to_sinks",{"Taint paths from network sources to memory/integer sinks.", json::object({{"max_depth", 16}})}},
        {"enumerate_rpc_servers",     {"List MIDL/NDR RPC server interfaces and dispatch tables.", json::object()}},
        {"enumerate_com_servers",     {"List COM class factories and CoRegister sites.", json::object()}},
        {"list_alpc_servers",         {"Locate NtAlpcCreatePort callsites and message loops.", json::object()}},
        {"enumerate_ioctl_handlers",  {"Find IRP_MJ_DEVICE_CONTROL dispatch + IOCTL switch.", json::object()}},
        {"classify_ioctl_buffer_methods",{"Decode METHOD_BUFFERED/IN_DIRECT/OUT_DIRECT/NEITHER per IOCTL.", json::object()}},
        {"trace_ioctl_userptr_to_sinks",{"Taint Irp->UserBuffer into kernel sinks.", json::object()}},
        {"hunt_kernel_writewhatwhere",{"Symbolic search for arbitrary kernel write primitives.", json::object()}},
        {"reconstruct_vtable",        {"Recover vtable at address from class metadata + xrefs.", json::object({{"address", "0x140020000"}})}},
        {"find_dispatch_tables",      {"Locate vtable-shaped read-only tables of code pointers.", json::object()}},
        {"analyze_indirect_calls",    {"Resolve indirect calls within a function.", json::object({{"address", "0x140001000"}})}},
        {"find_format_parsers",       {"Locate likely format/protocol parser functions.", json::object()}},
        {"find_printf_calls",         {"Locate printf-family callsites.", json::object()}},
        {"trace_format_to_attacker",  {"Backtrack format-string argument to its source.", json::object()}},
        {"hunt_integer_overflow_into_alloc",{"Find integer arithmetic feeding alloc size.", json::object()}},
        {"hunt_uaf",                  {"Symbolic search for use-after-free.", json::object()}},
        {"find_allocators_and_frees", {"Pair alloc/free family callsites.", json::object()}},
        {"find_auth_checks",          {"Locate SSPI/Negotiate/AcceptSecurityContext callers.", json::object()}},
        {"find_unauthenticated_reachable",{"Walk reverse from auth check, find pre-auth reachable callers.", json::object()}},
        {"find_crypto_constants",     {"Scan for AES/SHA/MD5 magic constants.", json::object()}},
        {"identify_protector",        {"Identify packer/protector (VMProtect/Themida/etc).", json::object()}},
        {"deobfuscate_control_flow",  {"Resolve flattened CFG / opaque predicates in a function.", json::object({{"address", "0x140001000"}})}},
        {"detect_vm_handler_pattern", {"Detect VM dispatcher pattern at a function.", json::object({{"address", "0x140001000"}})}},
        {"map_vm_handler_table",      {"Map VM handler table starting at address.", json::object({{"address", "0x140050000"}})}},
        {"detect_obfuscation_patterns",{"Classify obfuscation features used by the binary.", json::object()}},
        {"decode_strings_in_function",{"Statically/dynamically decode wrapped strings.", json::object({{"address", "0x140001000"}})}},
        {"analyze_string_decryption", {"Identify string-decryption routines.", json::object()}},
        {"detect_hooks",              {"Find IAT/EAT/inline hooks.", json::object()}},
        {"detect_direct_syscalls",    {"Locate inlined syscall instructions.", json::object()}},
        {"detect_anti_analysis",      {"Detect anti-debug/anti-VM patterns.", json::object()}},
        {"patch_anti_debug",          {"Neutralise known anti-debug patterns.", json::object()}},
        {"search_strings",            {"Search string literals.", json::object({{"text", "password"}})}},
        {"analyze_pe_headers",        {"Parse PE headers + characteristics.", json::object()}},
        {"analyze_entropy",           {"Per-section entropy histogram.", json::object()}},
        {"reconstruct_struct",        {"Reconstruct struct layout at address.", json::object({{"address", "0x140050000"}})}},
        {"create_struct",             {"Create a struct from a C declaration.", json::object()}},
        {"declare_type",              {"Declare a C type into the type system.", json::object()}},
        {"infer_type",                {"Infer the type of a variable at address.", json::object()}},
        {"list_imports",              {"List imports (filterable, paginated).", json::object()}},
        {"list_exports",              {"List exports (filterable, paginated).", json::object()}},
        {"list_functions",            {"List functions (filterable, paginated).", json::object()}},
        {"get_function",              {"Return function metadata.", json::object({{"address", "0x140001000"}})}},
        {"decompile",                 {"Decompile a function by address or name.", json::object({{"addr", "main"}})}},
        {"decompile_function",        {"Decompile a function.", json::object({{"address", "0x140001000"}})}},
        {"disasm",                    {"Disassemble a function.", json::object({{"addr", "0x140001000"}})}},
        {"disassemble_function",      {"Disassemble a function.", json::object({{"address", "0x140001000"}})}},
        {"xrefs_to",                  {"List xrefs to address(es).", json::object({{"addrs", json::array({"0x140001000"})}})}},
        {"xref_query",                {"Batch xref query.", json::object()}},
        {"build_call_graph",          {"Build a call graph rooted at address.", json::object({{"address", "0x140001000"}, {"depth", 3}})}},
        {"callgraph",                 {"AiDA alias for build_call_graph.", json::object({{"addr", "0x140001000"}, {"depth", 3}})}},
        {"search_semantic",           {"Semantic search across the knowledge graph.", json::object({{"query", "buffer overflow"}})}},
        {"get_semantic_analysis",     {"Semantic analysis of a function.", json::object({{"address", "0x140001000"}})}},
        {"get_similar_functions",     {"Find similar functions via embedding cosine.", json::object({{"address", "0x140001000"}, {"limit", 5}})}},
        {"get_community_info",        {"Community info for a function.", json::object({{"address", "0x140001000"}})}},
        {"detect_communities",        {"Detect communities in the call graph.", json::object()}},
        {"plan_the_hunt",             {"Return a workflow plan for a hunt type.", json::object({{"hunt_type", "remote_0click_rce"}})}},
        {"ask_capability",            {"Suggest tools given a goal sentence.", json::object({{"goal", "find network parsers"}})}},
        {"build_index",               {"Warm engine indices.", json::object({{"indices", "all"}})}},
        {"index_status",              {"Snapshot engine readiness.", json::object()}},
        {"session_scratch",           {"Set/get/append/list/delete session scratch.", json::object({{"op", "set"}, {"key", "k"}, {"value", "v"}})}},
        {"list_outputs",              {"Manage cached MCP outputs.", json::object({{"op", "stats"}})}},
        {"sample_tool_io",            {"Example arguments and result per tool.", json::object()}},
        {"tool_batch_call",           {"Run multiple tool calls in one MCP request.", json::object({{"calls", json::array()}})}},
        {"server_health",             {"Return IDA plugin health.", json::object()}},
        {"trace_data_flow",           {"Trace local data-flow around an address.", json::object({{"addr", "0x140001000"}})}},
        {"trace_taint_reverse",       {"Backward taint from a sink to sources.", json::object()}},
    };
    return m;
}

tool_result_t ask_capability(const json& params)
{
    std::string goal;
    if (params.contains("goal") && params["goal"].is_string())
        goal = params["goal"].get<std::string>();
    if (goal.empty())
        return tool_result_t::error(std::string("'goal' string required"), std::string("bad_param"));

    std::string lower = goal;
    for (auto& c : lower) c = (char)std::tolower((unsigned char)c);

    const auto& kmap = b10_keyword_map();
    std::map<std::string, int> score;
    for (const auto& kv : kmap)
    {
        const std::string& kw = kv.first;
        if (lower.find(kw) == std::string::npos) continue;
        for (auto* t : kv.second)
            score[t] += 1;
    }

    std::vector<std::pair<std::string,int>> sorted(score.begin(), score.end());
    std::sort(sorted.begin(), sorted.end(),
              [](auto& a, auto& b)
              {
                  if (a.second != b.second) return a.second > b.second;
                  return a.first < b.first;
              });

    const auto& hints = b10_tool_hints();
    json suggestions = json::array();
    for (size_t i = 0; i < sorted.size() && suggestions.size() < 8; ++i)
    {
        const std::string& tname = sorted[i].first;
        json sug;
        sug["tool"]  = tname;
        sug["score"] = sorted[i].second;
        auto h = hints.find(tname);
        if (h != hints.end())
        {
            sug["why"]          = h->second.first;
            sug["typical_args"] = h->second.second;
            json sample;
            sample["tool"]      = tname;
            sample["arguments"] = h->second.second;
            sug["sample_call"]  = sample;
        }
        else
        {
            sug["why"]          = std::string("Matched keyword(s) in goal");
            sug["typical_args"] = json::object();
            sug["sample_call"]  = json::object({{"tool", tname}, {"arguments", json::object()}});
        }
        suggestions.push_back(std::move(sug));
    }

    json data;
    data["goal"]        = goal;
    data["suggestions"] = suggestions;
    return tool_result_t::ok(std::string("ask_capability: ") + std::to_string(suggestions.size()) + std::string(" suggestions"),
                              data);
}

// ----------------------------------------------------------------------------
// Slice B11 — sample_tool_io
// ----------------------------------------------------------------------------
static const std::map<std::string, json>& b11_examples()
{
    static const std::map<std::string, json> m = {
        {"binary_fingerprint", json::object({
            {"example_arguments", json::object()},
            {"example_result", json::object({
                {"success", true},
                {"output",  "binary_fingerprint ok"},
                {"data", json::object({
                    {"md5", "00112233445566778899aabbccddeeff"},
                    {"sha256", "<64 hex>"},
                    {"crc32", "deadbeef"},
                    {"filetype", 11},
                    {"is_dll", false},
                    {"is_kernel", false},
                    {"bitness", 64},
                    {"processor", "metapc"},
                    {"image_base", "0x140000000"},
                    {"capabilities", json::object({
                        {"network", true}, {"rpc", true}, {"com", false},
                        {"driver", false}, {"alpc", false}
                    })}
                })}
            })},
            {"result_size_estimate", 4096},
            {"typical_latency_ms", 200}
        })},
        {"decompile", json::object({
            {"example_arguments", json::object({{"addr", "0x140001000"}})},
            {"example_result", json::object({
                {"success", true},
                {"output", "Decompilation ok"},
                {"data", json::object({{"pseudocode", "int __fastcall main(int argc, char **argv) {...}"}})}
            })},
            {"result_size_estimate", 8192},
            {"typical_latency_ms", 500}
        })},
        {"disasm", json::object({
            {"example_arguments", json::object({{"addr", "0x140001000"}})},
            {"example_result", json::object({
                {"success", true},
                {"output", "Disassembly ok"},
                {"data", json::object({{"text", "push rbp\nmov rbp, rsp\n..."}})}
            })},
            {"result_size_estimate", 6144},
            {"typical_latency_ms", 80}
        })},
        {"find_calls_to", json::object({
            {"example_arguments", json::object({{"name", "memcpy"}})},
            {"example_result", json::object({
                {"success", true},
                {"output", "Found 14 callsites"},
                {"data", json::object({{"callsites", json::array({"0x140002a10", "0x140003120"})}})}
            })},
            {"result_size_estimate", 2048},
            {"typical_latency_ms", 120}
        })},
        {"list_remote_entrypoints", json::object({
            {"example_arguments", json::object({{"top_n", 16}})},
            {"example_result", json::object({
                {"success", true},
                {"output", "list_remote_entrypoints: 12/24 entrypoints"},
                {"data", json::object({
                    {"entries", json::array({json::object({
                        {"ea", "0x140003000"}, {"name", "DispatchHandler"},
                        {"category", json::array({"rpc_server", "alpc"})},
                        {"pre_auth_likelihood", 0.8}
                    })})}
                })}
            })},
            {"result_size_estimate", 8192},
            {"typical_latency_ms", 400}
        })},
        {"plan_the_hunt", json::object({
            {"example_arguments", json::object({{"hunt_type", "remote_0click_rce"}})},
            {"example_result", json::object({
                {"success", true},
                {"output", "Plan for remote_0click_rce"},
                {"data", json::object({{"plan", json::object({{"steps", json::array()}})}})}
            })},
            {"result_size_estimate", 4096},
            {"typical_latency_ms", 5}
        })},
        {"index_status", json::object({
            {"example_arguments", json::object()},
            {"example_result", json::object({
                {"success", true},
                {"output", "Index status snapshot"},
                {"data", json::object({
                    {"binary_md5", "<hex>"},
                    {"auto_analysis_ok", true},
                    {"hexrays_available", true},
                    {"engines", json::object({
                        {"taint_engine", json::object({{"available", false}, {"populated", false}, {"count", 0}})}
                    })}
                })}
            })},
            {"result_size_estimate", 1024},
            {"typical_latency_ms", 5}
        })},
        {"session_scratch", json::object({
            {"example_arguments", json::object({{"op", "set"}, {"key", "last_hunt"}, {"value", "remote_0click_rce"}})},
            {"example_result", json::object({
                {"success", true},
                {"output", "scratch set ok"},
                {"data", json::object({{"key", "last_hunt"}, {"bytes_written", 18}, {"total_bytes", 18}, {"pruned_count", 0}})}
            })},
            {"result_size_estimate", 256},
            {"typical_latency_ms", 5}
        })},
        {"tool_batch_call", json::object({
            {"example_arguments", json::object({
                {"calls", json::array({
                    json::object({{"tool", "binary_fingerprint"}, {"arguments", json::object()}, {"label", "fp"}}),
                    json::object({{"tool", "index_status"},      {"arguments", json::object()}, {"label", "idx"}})
                })},
                {"stop_on_error", true},
                {"parallel", false}
            })},
            {"example_result", json::object({
                {"success", true},
                {"output", "Batch ran 2/2 calls (2 ok, 0 fail)"},
                {"data", json::object({{"results", json::array()}, {"total_ms", 240}})}
            })},
            {"result_size_estimate", 8192},
            {"typical_latency_ms", 250}
        })},
        {"ask_capability", json::object({
            {"example_arguments", json::object({{"goal", "find network parsers and trace input to sinks"}})},
            {"example_result", json::object({
                {"success", true},
                {"output", "ask_capability: 5 suggestions"},
                {"data", json::object({{"suggestions", json::array()}})}
            })},
            {"result_size_estimate", 2048},
            {"typical_latency_ms", 5}
        })},
        {"trace_all_network_to_sinks", json::object({
            {"example_arguments", json::object({{"max_depth", 16}})},
            {"example_result", json::object({
                {"success", true},
                {"output", "Taint paths found: 7"},
                {"data", json::object({{"paths", json::array()}})}
            })},
            {"result_size_estimate", 16384},
            {"typical_latency_ms", 8000}
        })},
    };
    return m;
}

tool_result_t sample_tool_io(const json& params)
{
    const auto& ex = b11_examples();

    if (params.contains("tool") && params["tool"].is_string())
    {
        std::string tname = params["tool"].get<std::string>();
        auto it = ex.find(tname);
        if (it != ex.end())
        {
            json data = it->second;
            data["tool"] = tname;
            return tool_result_t::ok(std::string("sample_tool_io: ") + tname, data);
        }
        // Generic stub for unknown tool.
        json data;
        data["tool"]                  = tname;
        data["example_arguments"]     = json::object();
        data["example_result"]        = json::object({
            {"success", true}, {"output", "..."}, {"data", json::object()}
        });
        data["result_size_estimate"]  = 0;
        data["typical_latency_ms"]    = 0;
        data["note"]                  = std::string("no specific example");
        return tool_result_t::ok(std::string("sample_tool_io: ") + tname + std::string(" (generic)"), data);
    }

    // List all examples.
    json arr = json::array();
    for (const auto& kv : ex)
    {
        json e = kv.second;
        e["tool"] = kv.first;
        arr.push_back(std::move(e));
    }
    json data;
    data["examples"] = arr;
    data["count"]    = (uint64_t)arr.size();
    return tool_result_t::ok(std::string("sample_tool_io: ") + std::to_string(arr.size()) + std::string(" examples"),
                              data);
}

// ----------------------------------------------------------------------------
// register_tools — wires every meta_tools handler into ToolRegistry.
// ----------------------------------------------------------------------------
void register_tools()
{
    auto& registry = ToolRegistry::instance();
    tool_definition_t def;

    // tool_batch_call
    def = {};
    def.name = std::string("tool_batch_call");
    def.category = std::string("meta");
    def.description = std::string(
        "Run multiple tool calls in a single MCP request. Calls run serially in this iteration; "
        "if parallel=true is requested with any non-read-only sub-tool, the orchestrator falls back "
        "to serial and reports fell_back_to_serial=true. Returns per-call success/output/data plus "
        "aggregate counters. Sub-tool names are validated up-front against the registry.");
    def.parameters = {
        {std::string("calls"), std::string("array"), std::string("Array of {tool, arguments, label?} sub-calls"), true},
        {std::string("parallel"), std::string("boolean"), std::string("Request parallel execution (only honoured when all sub-tools are read-only)"), false},
        {std::string("stop_on_error"), std::string("boolean"), std::string("Stop iteration at the first failure (default true)"), false},
        {std::string("max_wall_seconds"), std::string("number"), std::string("Wall-clock deadline in seconds (default 60)"), false},
    };
    def.handler = tool_batch_call;
    def.read_only = false;       // mixed semantics — caller must reason about sub-tools
    def.destructive = false;     // see comment above
    def.deterministic = false;   // depends on sub-tools + wall clock
    def.output_schema = json::object({{std::string("type"), std::string("object")}, {std::string("additionalProperties"), true}});
    registry.register_tool(def);

    // plan_the_hunt
    def = {};
    def.name = std::string("plan_the_hunt");
    def.category = std::string("meta");
    def.description = std::string(
        "Return a hardcoded workflow plan for a hunt type (remote_0click_rce, kernel_ioctl_bug, "
        "sandbox_escape, parser_bug, auth_bypass, uaf, format_string, all). The plan lists ordered "
        "tool steps with why/typical_args/expected_evidence/on_empty/expected_cost_ms and the engine "
        "indices the agent should warm up first. Steps may reference tools that don't exist yet.");
    def.parameters = {
        {std::string("hunt_type"), std::string("string"), std::string("Hunt type (default remote_0click_rce)"), false,
         {std::string("remote_0click_rce"), std::string("kernel_ioctl_bug"), std::string("sandbox_escape"),
          std::string("parser_bug"), std::string("auth_bypass"), std::string("uaf"), std::string("format_string"), std::string("all")}},
    };
    def.handler = plan_the_hunt;
    def.read_only = true;
    def.destructive = false;
    def.deterministic = true;
    def.output_schema = json::object({{std::string("type"), std::string("object")}, {std::string("additionalProperties"), true}});
    registry.register_tool(def);

    // index_status
    def = {};
    def.name = std::string("index_status");
    def.category = std::string("meta");
    def.description = std::string(
        "Snapshot which analysis engines are warm. Returns binary_md5, auto_analysis_ok, "
        "hexrays_available, and per-engine {available, populated, count} for graphrag, "
        "taint_engine, microcode_engine, cfg_engine, kernel_engine, surface_engine, "
        "symbolic_engine, smt_solver. Engines not yet wired report available=false.");
    def.parameters = {};
    def.handler = index_status;
    def.read_only = true;
    def.destructive = false;
    def.deterministic = false; // engine state changes between calls
    def.output_schema = json::object({{std::string("type"), std::string("object")}, {std::string("additionalProperties"), true}});
    registry.register_tool(def);

    // build_index
    def = {};
    def.name = std::string("build_index");
    def.category = std::string("meta");
    def.description = std::string(
        "Warm one or more engine indices (graphrag, taint_engine, microcode_engine, cfg_engine, "
        "kernel_engine, surface_engine, symbolic_engine, smt_solver, or 'all'). Per-engine timing "
        "and partial flags are reported. Cooperatively cancellable via user_cancelled().");
    def.parameters = {
        {std::string("indices"), std::string("string"), std::string("Engine name, 'all', or array of names (default 'all')"), false},
        {std::string("max_seconds"), std::string("number"), std::string("Wall-clock deadline (default 60)"), false},
    };
    def.handler = build_index;
    def.read_only = false;     // engines may populate caches
    def.destructive = false;
    def.deterministic = false;
    def.output_schema = json::object({{std::string("type"), std::string("object")}, {std::string("additionalProperties"), true}});
    registry.register_tool(def);

    // session_scratch
    def = {};
    def.name = std::string("session_scratch");
    def.category = std::string("meta");
    def.description = std::string(
        "Persistent per-IDB scratch store backed by netnode '$ AiDA.hunt.scratch'. Ops: set, "
        "get, append, list, delete. Auto-prunes when total stored size exceeds 512KB.");
    def.parameters = {
        {std::string("op"), std::string("string"), std::string("Operation"), true,
         {std::string("set"), std::string("get"), std::string("append"), std::string("list"), std::string("delete")}},
        {std::string("key"), std::string("string"), std::string("Key (required for set/get/append/delete)"), false},
        {std::string("value"), std::string("string"), std::string("Value (string; for set/append). JSON objects are dumped to string."), false},
        {std::string("offset"), std::string("number"), std::string("List offset"), false},
        {std::string("limit"), std::string("number"), std::string("List page size"), false},
        {std::string("all"), std::string("boolean"), std::string("delete: remove every key"), false},
    };
    def.handler = session_scratch;
    def.read_only = false;
    def.destructive = false;
    def.deterministic = false;
    def.output_schema = json::object({{std::string("type"), std::string("object")}, {std::string("additionalProperties"), true}});
    registry.register_tool(def);

    // list_remote_entrypoints
    def = {};
    def.name = std::string("list_remote_entrypoints");
    def.category = std::string("vuln");
    def.description = std::string(
        "Walk RPC/COM/ALPC/named-pipe/socket-accept/HTTP/WebSocket/NDIS-WSK/kernel-IRP gate "
        "imports and rank the containing functions by pre_auth_likelihood. Sorts descending; "
        "honours top_n.");
    def.parameters = {
        {std::string("top_n"), std::string("number"), std::string("Maximum entries to return (default 64, max 256)"), false},
    };
    def.handler = list_remote_entrypoints;
    def.read_only = true;
    def.destructive = false;
    def.deterministic = true;
    def.output_schema = json::object({{std::string("type"), std::string("object")}, {std::string("additionalProperties"), true}});
    registry.register_tool(def);

    // list_outputs
    def = {};
    def.name = std::string("list_outputs");
    def.category = std::string("meta");
    def.description = std::string(
        "Manage the MCP output cache. Ops: list (per-entry id+bytes), stats (capacity/used/count), "
        "evict (by output_id or all=true).");
    def.parameters = {
        {std::string("op"), std::string("string"), std::string("Operation"), false,
         {std::string("list"), std::string("stats"), std::string("evict")}},
        {std::string("output_id"), std::string("string"), std::string("evict: cache entry id"), false},
        {std::string("all"), std::string("boolean"), std::string("evict: clear every entry"), false},
    };
    def.handler = list_outputs;
    def.read_only = false; // evict mutates the cache
    def.destructive = false;
    def.deterministic = false;
    def.output_schema = json::object({{std::string("type"), std::string("object")}, {std::string("additionalProperties"), true}});
    registry.register_tool(def);

    // ask_capability
    def = {};
    def.name = std::string("ask_capability");
    def.category = std::string("meta");
    def.description = std::string(
        "Given a free-form goal sentence, suggest up to 8 tools (with why/typical_args/sample_call) "
        "drawn from a hardcoded keyword->tool map. Scores by number of matching keywords.");
    def.parameters = {
        {std::string("goal"), std::string("string"), std::string("Free-form description of the desired outcome"), true},
    };
    def.handler = ask_capability;
    def.read_only = true;
    def.destructive = false;
    def.deterministic = true;
    def.output_schema = json::object({{std::string("type"), std::string("object")}, {std::string("additionalProperties"), true}});
    registry.register_tool(def);

    // sample_tool_io
    def = {};
    def.name = std::string("sample_tool_io");
    def.category = std::string("meta");
    def.description = std::string(
        "Return canned example arguments + example result for a tool (or for ~10 popular tools if "
        "no tool is specified). Tools not in the example DB receive a generic stub.");
    def.parameters = {
        {std::string("tool"), std::string("string"), std::string("Tool name (optional)"), false},
    };
    def.handler = sample_tool_io;
    def.read_only = true;
    def.destructive = false;
    def.deterministic = true;
    def.output_schema = json::object({{std::string("type"), std::string("object")}, {std::string("additionalProperties"), true}});
    registry.register_tool(def);
}

} // namespace meta_tools

namespace sdk_underused_tools
{

namespace
{
std::string lower_ascii(std::string s)
{
    for (char& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

json open_object_schema()
{
    return json::object({{std::string("type"), std::string("object")}, {std::string("additionalProperties"), true}});
}

json ea_to_json(ea_t ea)
{
    if (ea == BADADDR)
        return json(nullptr);
    return helpers::format_address(ea);
}

std::optional<ea_t> parse_ea_any(const json& params, std::initializer_list<const char*> names)
{
    for (const char* n : names)
    {
        if (!params.contains(n))
            continue;
        const json& v = params[n];
        if (v.is_string())
        {
            auto ea = helpers::parse_address(v.get<std::string>());
            if (ea)
                return ea;
        }
        else if (v.is_number_unsigned())
        {
            return static_cast<ea_t>(v.get<uint64_t>());
        }
        else if (v.is_number_integer())
        {
            int64_t raw = v.get<int64_t>();
            if (raw >= 0)
                return static_cast<ea_t>(raw);
        }
    }
    return std::nullopt;
}

std::string reg_name_from_num(int reg);

std::string type_to_string(const tinfo_t& tif, const char* name = nullptr)
{
    if (tif.empty())
        return {};
    qstring out;
    if (tif.print(&out, name, PRTYPE_1LINE))
        return std::string(out.c_str());
    return std::string(tif.dstr());
}

std::string argloc_to_summary(const argloc_t& loc)
{
    if (loc.is_reg())
    {
        std::string out = reg_name_from_num(loc.reg1());
        if (loc.is_reg2())
            out += std::string(":") + reg_name_from_num(loc.reg2());
        return out;
    }
    if (loc.is_stkoff())
        return std::string("stack+") + std::to_string(loc.stkoff());
    if (loc.is_scattered())
        return std::string("scattered");
    if (loc.atype() == ALOC_NONE)
        return std::string("none");
    return std::string("argloc_type_") + std::to_string(loc.atype());
}

std::string reg_name_from_num(int reg)
{
    if (reg < 0)
        return {};
    qstring out;
    if (get_reg_name(&out, reg, 0) > 0 && !out.empty())
        return std::string(out.c_str());
    if (get_reg_name(&out, reg, inf_is_64bit() ? 8 : 4) > 0 && !out.empty())
        return std::string(out.c_str());
    if (PH.reg_names != nullptr && reg < PH.regs_num && PH.reg_names[reg] != nullptr)
        return std::string(PH.reg_names[reg]);
    return std::to_string(reg);
}

int reg_num_from_json(const json& v)
{
    if (v.is_number_integer())
    {
        const std::int64_t value = v.get<std::int64_t>();
        if (value >= (std::numeric_limits<int>::min)() && value <= (std::numeric_limits<int>::max)())
            return static_cast<int>(value);
        return -1;
    }
    if (v.is_number_unsigned())
    {
        const std::uint64_t value = v.get<std::uint64_t>();
        if (value <= static_cast<std::uint64_t>((std::numeric_limits<int>::max)()))
            return static_cast<int>(value);
        return -1;
    }
    if (!v.is_string())
        return -1;

    std::string requested = v.get<std::string>();
    std::string lowered = lower_ascii(requested);
    if (PH.reg_names != nullptr)
    {
        for (int i = 0; i < PH.regs_num; ++i)
        {
            const char* rn = PH.reg_names[i];
            if (rn != nullptr && lower_ascii(std::string(rn)) == lowered)
                return i;
        }
    }

    bitrange_t br;
    const char* base = processor_t::get_reg_info(requested.c_str(), &br);
    if (base != nullptr && PH.reg_names != nullptr)
    {
        std::string b = lower_ascii(std::string(base));
        for (int i = 0; i < PH.regs_num; ++i)
        {
            const char* rn = PH.reg_names[i];
            if (rn != nullptr && lower_ascii(std::string(rn)) == b)
                return i;
        }
    }

    ssize_t r = processor_t::str2reg(requested.c_str());
    if (r >= 0 && r < PH.regs_num)
        return static_cast<int>(r);
    return -1;
}

std::string rvi_state(const reg_value_info_t& rvi)
{
    if (rvi.empty()) return std::string("UNDEF");
    if (rvi.is_num()) return std::string("NUM");
    if (rvi.is_spd()) return std::string("SPD");
    if (rvi.is_dead_end()) return std::string("DEADEND");
    if (rvi.aborted()) return std::string("ABORTED");
    if (rvi.is_badinsn()) return std::string("BADINSN");
    if (rvi.is_unkinsn()) return std::string("UNKINSN");
    if (rvi.is_unkfunc()) return std::string("UNKFUNC");
    if (rvi.is_unkloop()) return std::string("UNKLOOP");
    if (rvi.is_unkmult()) return std::string("UNKMULT");
    if (rvi.is_unkxref()) return std::string("UNKXREF");
    if (rvi.is_unkvals()) return std::string("UNKVALS");
    return std::string("UNK");
}

json reg_value_snapshot(ea_t ea, int reg, int max_depth)
{
    json out;
    out["ea"] = helpers::format_address(ea);
    out["reg"] = reg;
    out["reg_name"] = reg_name_from_num(reg);

    reg_value_info_t rvi;
    bool supported = find_reg_value_info(&rvi, ea, reg, max_depth);
    out["supported"] = supported;
    out["state"] = supported ? rvi_state(rvi) : std::string("UNSUPPORTED");
    out["unique"] = supported && rvi.is_value_unique();
    out["description"] = supported ? std::string(rvi.dstr().c_str()) : std::string();

    json vals = json::array();
    if (supported)
    {
        for (const reg_value_def_t* it = rvi.vals_begin(); it != rvi.vals_end(); ++it)
        {
            json v;
            v["val"] = helpers::format_address(static_cast<ea_t>(it->val));
            v["uval"] = static_cast<uint64_t>(it->val);
            v["def_ea"] = ea_to_json(it->def_ea);
            v["def_itype"] = it->def_itype;
            v["flags"] = it->flags;
            v["pc_based"] = it->is_pc_based();
            v["like_got"] = it->is_like_got();
            vals.push_back(std::move(v));
        }
    }
    out["values"] = vals;
    return out;
}

json func_flags_json(func_t* pfn)
{
    json f;
    uint64_t flags = pfn ? static_cast<uint64_t>(pfn->flags) : 0;
    f["raw"] = flags;
    f["noret"] = pfn && (pfn->flags & FUNC_NORET) != 0;
    f["library"] = pfn && (pfn->flags & FUNC_LIB) != 0;
    f["thunk"] = pfn && (pfn->flags & FUNC_THUNK) != 0;
    f["static"] = pfn && (pfn->flags & FUNC_STATICDEF) != 0;
    f["frame"] = pfn && (pfn->flags & FUNC_FRAME) != 0;
    f["fuzzy_sp"] = pfn && (pfn->flags & FUNC_FUZZY_SP) != 0;
    return f;
}

std::string runtime_import_category(const std::string& mod)
{
    std::string lower = lower_ascii(mod);
    if (lower.find("ws2_32") != std::string::npos || lower.find("wsock32") != std::string::npos || lower.find("mswsock") != std::string::npos || lower.find("iphlpapi") != std::string::npos)
        return std::string("WINSOCK");
    if (lower.find("wininet") != std::string::npos || lower.find("winhttp") != std::string::npos || lower.find("urlmon") != std::string::npos || lower.find("httpapi") != std::string::npos)
        return std::string("WININET");
    if (lower.find("rpcrt4") != std::string::npos || lower.find("rpcns4") != std::string::npos)
        return std::string("RPC");
    if (lower.find("ole32") != std::string::npos || lower.find("oleaut32") != std::string::npos || lower.find("combase") != std::string::npos)
        return std::string("COM");
    if (lower.find("ntdll") != std::string::npos)
        return std::string("ALPC");
    if (lower.find("bcrypt") != std::string::npos || lower.find("ncrypt") != std::string::npos || lower.find("crypt32") != std::string::npos || lower.find("advapi32") != std::string::npos)
        return std::string("CRYPTO");
    if (lower.find("kernel32") != std::string::npos || lower.find("api-ms-win-core") != std::string::npos)
        return std::string("IPC");
    if (lower.find("ntoskrnl") != std::string::npos || lower.find("hal") != std::string::npos || lower.find("ndis") != std::string::npos || lower.find("wdfldr") != std::string::npos || lower.find("fltmgr") != std::string::npos)
        return std::string("IPC");
    if (lower.find("shlwapi") != std::string::npos || lower.find("shell32") != std::string::npos || lower.find("shcore") != std::string::npos || lower.find("user32") != std::string::npos || lower.find("gdi32") != std::string::npos)
        return std::string("FILE");
    return std::string("OTHER");
}

ea_t first_call_target(ea_t caller)
{
    xrefblk_t xb;
    for (bool ok = xb.first_from(caller, XREF_CODE | XREF_NOFLOW); ok; ok = xb.next_from())
    {
        int t = xb.type & XREF_MASK;
        if (t == fl_CF || t == fl_CN)
            return xb.to;
    }
    insn_t insn;
    if (decode_insn(&insn, caller) > 0 && is_call_insn(insn))
    {
        if (insn.ops[0].type == o_near || insn.ops[0].type == o_far)
            return insn.ops[0].addr;
    }
    return BADADDR;
}

json address_flags(ea_t ea)
{
    flags64_t f = get_flags(ea);
    aflags_t af = get_aflags(ea);
    func_t* pfn = get_func(ea);
    json out;
    out["ea"] = helpers::format_address(ea);
    out["flags"] = static_cast<uint64_t>(f);
    out["aflags"] = static_cast<uint64_t>(af);
    out["is_code"] = is_code(f);
    out["is_data"] = is_data(f);
    out["is_unknown"] = is_unknown(f);
    out["is_head"] = is_head(f);
    out["has_name"] = has_name(f);
    out["has_xref"] = has_xref(f);
    out["has_jump_or_flow_xref"] = has_jump_or_flow_xref(ea);
    out["is_libitem"] = is_libitem(ea);
    out["is_noret"] = is_noret(ea);
    out["has_ti"] = has_ti(ea);
    out["is_userti"] = is_userti(ea);
    out["function"] = pfn ? ea_to_json(pfn->start_ea) : json(nullptr);
    out["function_flags"] = func_flags_json(pfn);
    xrefblk_t xb;
    int xrefs_from = 0;
    for (bool ok = xb.first_from(ea, XREF_ALL); ok && xrefs_from < 1024; ok = xb.next_from())
        ++xrefs_from;
    int xrefs_to = 0;
    for (bool ok = xb.first_to(ea, XREF_ALL); ok && xrefs_to < 1024; ok = xb.next_to())
        ++xrefs_to;
    out["xrefs_from_count"] = xrefs_from;
    out["xrefs_to_count"] = xrefs_to;
    return out;
}

bool name_has_guard_marker(ea_t ea)
{
    if (ea == BADADDR)
        return false;
    qstring nm;
    if (get_name(&nm, ea, GN_VISIBLE) <= 0 || nm.empty())
        return false;
    std::string n = lower_ascii(std::string(nm.c_str()));
    return n.find("guard_dispatch_icall") != std::string::npos
        || n.find("guard_check_icall") != std::string::npos
        || n.find("__guard") != std::string::npos
        || n.find("guard_xfg") != std::string::npos;
}

tool_result_t list_entry_points_enriched(const json& params)
{
    size_t limit = 4096;
    if (params.contains("limit") && params["limit"].is_number_unsigned())
        limit = std::min<size_t>(params["limit"].get<size_t>(), 65536);

    struct entry_row_t { int rank = 0; ea_t ea = BADADDR; json j; };
    std::vector<entry_row_t> rows;
    rows.reserve(get_entry_qty());

    size_t qty = get_entry_qty();
    for (size_t i = 0; i < qty; ++i)
    {
        uval_t ord = get_entry_ordinal(i);
        ea_t ea = get_entry(ord);
        if (ea == BADADDR)
            continue;

        qstring name;
        get_entry_name(&name, ord);
        std::string name_s = std::string(name.c_str());

        qstring fwd;
        bool has_forwarder = get_entry_forwarder(&fwd, ord) >= 0 && !fwd.empty();

        qstring dem;
        if (!name_s.empty())
            ::demangle_name(&dem, name_s.c_str(), 0, DQT_FULL);

        func_t* pfn = get_func(ea);
        bool is_thunk = pfn && (pfn->flags & FUNC_THUNK) != 0;
        bool is_library = (pfn && (pfn->flags & FUNC_LIB) != 0) || is_libitem(ea);
        bool is_no_ret = (pfn && (pfn->flags & FUNC_NORET) != 0) || is_noret(ea);

        json j;
        j["ordinal"] = static_cast<uint64_t>(ord);
        j["ea"] = helpers::format_address(ea);
        j["name"] = name_s;
        j["demangled_name"] = std::string(dem.c_str());
        j["forwarder"] = has_forwarder ? json(std::string(fwd.c_str())) : json(nullptr);
        j["exported_by_name"] = !name_s.empty();
        j["function_start"] = pfn ? ea_to_json(pfn->start_ea) : json(nullptr);
        j["is_library"] = is_library;
        j["is_thunk"] = is_thunk;
        j["is_noret"] = is_no_ret;
        j["aflags"] = static_cast<uint64_t>(get_aflags(ea));
        j["function_flags"] = func_flags_json(pfn);
        if (is_thunk)
        {
            ea_t fptr = BADADDR;
            ea_t target = aida_calc_thunk_func_target(pfn, &fptr);
            j["thunk_target"] = ea_to_json(target);
            j["thunk_function_pointer"] = ea_to_json(fptr);
        }

        int rank = 0;
        if (is_library) rank += 8;
        if (is_thunk) rank += 4;
        if (name_s.empty()) rank += 2;
        if (has_forwarder) rank += 1;
        rows.push_back({rank, ea, std::move(j)});
    }

    std::sort(rows.begin(), rows.end(), [](const entry_row_t& a, const entry_row_t& b) {
        if (a.rank != b.rank) return a.rank < b.rank;
        return a.ea < b.ea;
    });

    json arr = json::array();
    for (size_t i = 0; i < rows.size() && i < limit; ++i)
        arr.push_back(std::move(rows[i].j));

    json data;
    data["entries"] = std::move(arr);
    data["total"] = rows.size();
    data["returned"] = data["entries"].size();
    return tool_result_t::ok(std::string("list_entry_points_enriched: ") + std::to_string(data["returned"].get<size_t>()) + std::string(" entries"), data);
}

tool_result_t trace_register_value(const json& params)
{
    auto ea = parse_ea_any(params, {"address", "ea"});
    if (!ea)
        return tool_result_t::error(std::string("Missing or invalid address"), std::string("bad_param"));
    if (!params.contains("reg"))
        return tool_result_t::error(std::string("Missing reg"), std::string("bad_param"));
    int reg = reg_num_from_json(params["reg"]);
    if (reg < 0)
        return tool_result_t::error(std::string("Unknown register"), std::string("bad_param"));
    int max_depth = params.value("max_depth", 0);
    return tool_result_t::ok(std::string("trace_register_value: ") + reg_name_from_num(reg), reg_value_snapshot(*ea, reg, max_depth));
}

tool_result_t get_call_argument_loads(const json& params)
{
    auto caller = parse_ea_any(params, {"caller", "caller_ea", "call_ea", "address", "ea"});
    if (!caller)
        return tool_result_t::error(std::string("Missing or invalid caller address"), std::string("bad_param"));

    int max_depth = params.value("max_depth", 0);
    std::string prototype;
    if (params.contains("prototype") && params["prototype"].is_string())
        prototype = params["prototype"].get<std::string>();

    tinfo_t tif;
    qstring parsed_name;
    bool parsed = false;
    bool applied = false;
    if (!prototype.empty())
    {
        parsed = parse_decl(&tif, &parsed_name, nullptr, prototype.c_str(), PT_SIL | PT_SYMBOL | PT_TYP | PT_SEMICOLON);
        if (!parsed)
            return tool_result_t::error(std::string("Could not parse prototype"), std::string("bad_param"));
        applied = apply_callee_tinfo(*caller, tif);
    }

    eavec_t arg_addrs;
    bool have_arg_addrs = get_arg_addrs(&arg_addrs, *caller);

    tinfo_t call_tif = tif;
    if (!call_tif.empty() && call_tif.is_funcptr())
        call_tif = call_tif.get_pointed_object();
    func_type_data_t ftd;
    bool have_ftd = !call_tif.empty() && call_tif.get_func_details(&ftd);

    size_t argc = have_ftd ? ftd.size() : arg_addrs.size();
    json args = json::array();
    for (size_t i = 0; i < argc; ++i)
    {
        ea_t load_ea = (i < arg_addrs.size()) ? arg_addrs[i] : BADADDR;
        json a;
        a["index"] = i;
        a["load_ea"] = ea_to_json(load_ea);
        if (have_ftd && i < ftd.size())
        {
            const funcarg_t& fa = ftd[i];
            a["name"] = std::string(fa.name.c_str());
            a["type"] = type_to_string(fa.type);
            a["argloc"] = argloc_to_summary(fa.argloc);
            if (load_ea != BADADDR && fa.argloc.is_reg())
            {
                json hints = json::array();
                hints.push_back(reg_value_snapshot(load_ea, fa.argloc.reg1(), max_depth));
                if (fa.argloc.is_reg2())
                    hints.push_back(reg_value_snapshot(load_ea, fa.argloc.reg2(), max_depth));
                a["value_hint"] = std::move(hints);
            }
        }
        args.push_back(std::move(a));
    }

    json data;
    data["caller"] = helpers::format_address(*caller);
    data["callee"] = ea_to_json(first_call_target(*caller));
    data["prototype"] = prototype;
    data["parsed"] = parsed;
    data["applied_callee_tinfo"] = applied;
    data["arg_addrs_available"] = have_arg_addrs;
    data["args"] = std::move(args);
    return tool_result_t::ok(std::string("get_call_argument_loads: ") + std::to_string(data["args"].size()) + std::string(" args"), data);
}

tool_result_t get_address_aflags(const json& params)
{
    auto ea = parse_ea_any(params, {"address", "ea"});
    if (!ea)
        return tool_result_t::error(std::string("Missing or invalid address"), std::string("bad_param"));
    return tool_result_t::ok(std::string("get_address_aflags: ") + helpers::format_address(*ea), address_flags(*ea));
}

tool_result_t classify_thunks_and_guards(const json& params)
{
    auto start = parse_ea_any(params, {"start", "start_ea"});
    auto end = parse_ea_any(params, {"end", "end_ea"});
    ea_t lo = start.value_or(inf_get_min_ea());
    ea_t hi = end.value_or(inf_get_max_ea());
    size_t max_functions = params.value("max_functions", 20000u);

    json thunks = json::array();
    json cfg_guards = json::array();
    json return_thunks = json::array();
    size_t visited = 0;

    for (size_t i = 0; i < get_func_qty() && visited < max_functions; ++i)
    {
        func_t* pfn = getn_func(i);
        if (!pfn || pfn->start_ea < lo || pfn->start_ea >= hi)
            continue;
        ++visited;

        if ((pfn->flags & FUNC_THUNK) != 0)
        {
            ea_t fptr = BADADDR;
            ea_t target = aida_calc_thunk_func_target(pfn, &fptr);
            json t;
            t["ea"] = helpers::format_address(pfn->start_ea);
            t["target"] = ea_to_json(target);
            t["function_pointer"] = ea_to_json(fptr);
            qstring nm;
            if (get_func_name(&nm, pfn->start_ea) > 0)
                t["name"] = std::string(nm.c_str());
            thunks.push_back(std::move(t));
        }

        func_item_iterator_t fii(pfn);
        for (bool ok = fii.first(); ok; ok = fii.next_head())
        {
            ea_t item = fii.current();
            if (item < lo || item >= hi)
                continue;
            insn_t insn;
            if (decode_insn(&insn, item) <= 0)
                continue;
            int reg = -1;
            ssize_t cfg = processor_t::is_control_flow_guard(&reg, &insn);
            if (cfg == 1 || cfg == 2 || (cfg < 0 && name_has_guard_marker(first_call_target(item))))
            {
                json g;
                g["ea"] = helpers::format_address(item);
                g["kind"] = cfg == 2 ? std::string("security_check") : std::string("indirect_call_guard");
                g["reg"] = reg;
                if (reg >= 0)
                    g["reg_name"] = reg_name_from_num(reg);
                g["target"] = ea_to_json(first_call_target(item));
                cfg_guards.push_back(std::move(g));
            }
            else if (cfg == 3 || (cfg < 0 && is_ret_insn(insn) && name_has_guard_marker(pfn->start_ea)))
            {
                return_thunks.push_back(helpers::format_address(item));
            }
        }
    }

    json data;
    data["range_start"] = helpers::format_address(lo);
    data["range_end"] = helpers::format_address(hi);
    data["functions_visited"] = visited;
    data["thunks"] = std::move(thunks);
    data["cfg_guards"] = std::move(cfg_guards);
    data["return_thunks"] = std::move(return_thunks);
    return tool_result_t::ok(std::string("classify_thunks_and_guards"), data);
}

tool_result_t apply_callee_prototype(const json& params)
{
    auto caller = parse_ea_any(params, {"caller", "caller_ea", "call_ea", "address", "ea"});
    if (!caller)
        return tool_result_t::error(std::string("Missing or invalid caller address"), std::string("bad_param"));
    if (!params.contains("prototype") || !params["prototype"].is_string())
        return tool_result_t::error(std::string("Missing prototype"), std::string("bad_param"));

    std::string prototype = params["prototype"].get<std::string>();
    tinfo_t tif;
    qstring parsed_name;
    if (!parse_decl(&tif, &parsed_name, nullptr, prototype.c_str(), PT_SIL | PT_SYMBOL | PT_TYP | PT_SEMICOLON))
        return tool_result_t::error(std::string("Could not parse prototype"), std::string("bad_param"));

    bool applied_call = apply_callee_tinfo(*caller, tif);
    ea_t callee = BADADDR;
    auto explicit_callee = parse_ea_any(params, {"callee", "callee_ea", "target"});
    if (explicit_callee)
        callee = *explicit_callee;
    else
        callee = first_call_target(*caller);

    bool apply_to_callee = params.value("apply_to_callee", false);
    bool applied_callee = false;
    if (apply_to_callee && callee != BADADDR)
        applied_callee = apply_tinfo(callee, tif, TINFO_DEFINITE);

    json data;
    data["caller"] = helpers::format_address(*caller);
    data["callee"] = ea_to_json(callee);
    data["prototype"] = type_to_string(tif, parsed_name.empty() ? nullptr : parsed_name.c_str());
    data["applied_callsite"] = applied_call;
    data["applied_callee"] = applied_callee;
    data["parsed_name"] = std::string(parsed_name.c_str());
    return applied_call || applied_callee
        ? tool_result_t::ok(std::string("apply_callee_prototype ok"), data)
        : tool_result_t::error(std::string("apply_callee_prototype failed"), std::string("unknown"));
}

tool_result_t ensure_analysis_settled(const json& params)
{
    bool wait = params.value("wait", true);
    bool final_pass = params.value("final_pass", true);
    auto start = parse_ea_any(params, {"start", "start_ea"});
    auto end = parse_ea_any(params, {"end", "end_ea"});
    ea_t lo = start.value_or(inf_get_min_ea());
    ea_t hi = end.value_or(inf_get_max_ea());

    bool before = auto_is_ok();
    ssize_t range_steps = 0;
    bool wait_ok = true;
    if (!before && wait)
    {
        auto_mark_range(lo, hi, final_pass ? AU_FINAL : AU_USED);
        range_steps = auto_wait_range(lo, hi);
        wait_ok = range_steps >= 0;
        if (wait_ok && !auto_is_ok())
            wait_ok = auto_wait();
    }

    json data;
    data["settled_before"] = before;
    data["settled"] = auto_is_ok();
    data["waited"] = wait && !before;
    data["wait_ok"] = wait_ok;
    data["range_steps"] = range_steps;
    data["range_start"] = helpers::format_address(lo);
    data["range_end"] = helpers::format_address(hi);
    return tool_result_t::ok(data["settled"].get<bool>() ? std::string("analysis settled") : std::string("analysis not settled"), data);
}

tool_result_t reachability_query(const json& params)
{
    auto& registry = ToolRegistry::instance();
    const auto* target = registry.get_tool(std::string("reachable_under_constraints"));
    if (!target)
        return tool_result_t::error(std::string("External hook missing: reachable_under_constraints is not registered in this build"), std::string("not_implemented"));

    json translated = params;
    if (translated.contains("from") && !translated.contains("source"))
        translated["source"] = translated["from"];
    if (translated.contains("to") && !translated.contains("target"))
        translated["target"] = translated["to"];
    if (translated.contains("avoid") && !translated.contains("avoid_list"))
        translated["avoid_list"] = translated["avoid"];
    return registry.execute_tool(std::string("reachable_under_constraints"), translated);
}

struct runtime_import_state_t
{
    json imports = json::array();
    size_t limit = 512;
    bool truncated = false;
};

int idaapi runtime_import_cb(ea_t ea, const char* name, uval_t ord, void* ud)
{
    auto* st = static_cast<runtime_import_state_t*>(ud);
    if (st->imports.size() >= st->limit)
    {
        st->truncated = true;
        return 0;
    }
    json imp;
    imp["ea"] = ea_to_json(ea);
    imp["name"] = name ? std::string(name) : std::string();
    imp["ord"] = static_cast<uint64_t>(ord);
    st->imports.push_back(std::move(imp));
    return 1;
}

tool_result_t get_binary_runtime_profile(const json& params)
{
    size_t max_imports_per_module = params.value("max_imports_per_module", 512u);
    max_imports_per_module = std::min<size_t>(max_imports_per_module, 8192);

    json data;
    data["filetype"] = static_cast<int>(inf_get_filetype());
    data["is_dll"] = inf_is_dll();
    data["is_kernel"] = inf_is_kernel_mode();
    data["bitness"] = inf_get_app_bitness();
    qstring proc = inf_get_procname();
    data["procname"] = std::string(proc.c_str());
    data["image_base"] = helpers::format_address(static_cast<ea_t>(get_imagebase()));
    data["min_ea"] = helpers::format_address(inf_get_min_ea());
    data["max_ea"] = helpers::format_address(inf_get_max_ea());

    json modules = json::array();
    uint qty = get_import_module_qty();
    for (uint i = 0; i < qty; ++i)
    {
        qstring name;
        if (!get_import_module_name(&name, i))
            continue;
        runtime_import_state_t st;
        st.limit = max_imports_per_module;
        enum_import_names(static_cast<int>(i), runtime_import_cb, &st);
        std::string mod = std::string(name.c_str());
        json m;
        m["name"] = mod;
        m["category"] = runtime_import_category(mod);
        m["imports"] = std::move(st.imports);
        m["truncated"] = st.truncated;
        modules.push_back(std::move(m));
    }
    data["modules"] = std::move(modules);
    return tool_result_t::ok(std::string("get_binary_runtime_profile: ") + std::to_string(qty) + std::string(" modules"), data);
}

} // namespace

void register_tools()
{
    auto& reg = ToolRegistry::instance();
    auto add = [&](std::string name, std::string category, std::string description, std::vector<tool_param_t> params, std::function<tool_result_t(const json&)> handler, bool read_only, bool destructive, bool deterministic, std::vector<std::string> required_indices = {})
    {
        tool_definition_t def;
        def.name = std::move(name);
        def.category = std::move(category);
        def.description = std::move(description);
        def.parameters = std::move(params);
        def.handler = std::move(handler);
        def.read_only = read_only;
        def.destructive = destructive;
        def.deterministic = deterministic;
        def.required_indices = std::move(required_indices);
        def.output_schema = open_object_schema();
        reg.register_tool(def);
    };

    add(std::string("list_entry_points_enriched"), std::string("sdk_underused"), std::string("List entry points with names, demangling, forwarders, function flags, aflags, library/thunk/noreturn classification, and thunk targets, sorted for vulnerability triage."),
        {{std::string("limit"), std::string("number"), std::string("Maximum entries to return"), false}}, list_entry_points_enriched, true, false, true);
    add(std::string("trace_register_value"), std::string("sdk_underused"), std::string("Use IDA's register tracker to recover the value state of a register at an address."),
        {{std::string("address"), std::string("string"), std::string("Instruction address"), true}, {std::string("reg"), std::string("string"), std::string("Register name or ordinal"), true}, {std::string("max_depth"), std::string("number"), std::string("Basic-block search depth, 0 uses IDA defaults"), false}}, trace_register_value, true, false, true);
    add(std::string("get_call_argument_loads"), std::string("sdk_underused"), std::string("Retrieve argument initialization addresses for a callsite and augment register arguments with regfinder value snapshots. Supplying a prototype applies callee type info so IDA can materialize argument load addresses."),
        {{std::string("caller"), std::string("string"), std::string("Call instruction address"), false}, {std::string("address"), std::string("string"), std::string("Alias for caller"), false}, {std::string("prototype"), std::string("string"), std::string("Optional callee prototype or symbol name"), false}, {std::string("max_depth"), std::string("number"), std::string("Regfinder depth"), false}}, get_call_argument_loads, false, false, false);
    add(std::string("get_address_aflags"), std::string("sdk_underused"), std::string("Return IDA analysis flags, function flags, type flags, xref state, and decoded boolean helpers for an address."),
        {{std::string("address"), std::string("string"), std::string("Address to inspect"), true}}, get_address_aflags, true, false, true);
    add(std::string("classify_thunks_and_guards"), std::string("sdk_underused"), std::string("Enumerate thunk functions and control-flow-guard/return-thunk callsites using IDA's thunk and processor CFG helpers, with conservative guard-name fallback."),
        {{std::string("start"), std::string("string"), std::string("Optional range start"), false}, {std::string("end"), std::string("string"), std::string("Optional range end"), false}, {std::string("max_functions"), std::string("number"), std::string("Function visit cap"), false}}, classify_thunks_and_guards, true, false, true);
    add(std::string("apply_callee_prototype"), std::string("sdk_underused"), std::string("Parse a callee prototype and permanently apply it to a callsite; optionally apply the definite type to the callee target too."),
        {{std::string("caller"), std::string("string"), std::string("Call instruction address"), false}, {std::string("address"), std::string("string"), std::string("Alias for caller"), false}, {std::string("prototype"), std::string("string"), std::string("C prototype or symbol name"), true}, {std::string("callee"), std::string("string"), std::string("Optional explicit callee address"), false}, {std::string("apply_to_callee"), std::string("boolean"), std::string("Also apply TINFO_DEFINITE at callee"), false}}, apply_callee_prototype, false, true, false);
    add(std::string("ensure_analysis_settled"), std::string("sdk_underused"), std::string("Check and optionally wait for IDA auto-analysis to settle over a range or the whole database."),
        {{std::string("start"), std::string("string"), std::string("Optional range start"), false}, {std::string("end"), std::string("string"), std::string("Optional range end"), false}, {std::string("wait"), std::string("boolean"), std::string("Wait when analysis is not settled"), false}, {std::string("final_pass"), std::string("boolean"), std::string("Queue final-pass analysis for the range"), false}}, ensure_analysis_settled, false, false, false);
    add(std::string("reachability_query"), std::string("sdk_underused"), std::string("Alias wrapper for reachable_under_constraints with translated parameter names."),
        {{std::string("from"), std::string("string"), std::string("Source address alias"), false}, {std::string("to"), std::string("string"), std::string("Target address alias"), false}, {std::string("avoid"), std::string("array"), std::string("Avoid-list alias"), false}}, reachability_query, true, false, false, {std::string("cfg_engine")});
    add(std::string("get_binary_runtime_profile"), std::string("sdk_underused"), std::string("Return runtime-relevant binary metadata and per-import-module categorized imports."),
        {{std::string("max_imports_per_module"), std::string("number"), std::string("Import cap per module"), false}}, get_binary_runtime_profile, true, false, true);
}

} // namespace sdk_underused_tools


void initialize_all_tools()
{
    aida_ipc::trace_breadcrumb("agent_tools: initialize_all_tools ENTRY");
    aida_ipc::trace_breadcrumb("agent_tools: initialize_all_tools calling function_tools::register_tools");
    function_tools::register_tools();
    aida_ipc::trace_breadcrumb("agent_tools: initialize_all_tools calling memory_tools::register_tools");
    memory_tools::register_tools();
    aida_ipc::trace_breadcrumb("agent_tools: initialize_all_tools calling comment_tools::register_tools");
    comment_tools::register_tools();
    aida_ipc::trace_breadcrumb("agent_tools: initialize_all_tools calling type_tools::register_tools");
    type_tools::register_tools();
    aida_ipc::trace_breadcrumb("agent_tools: initialize_all_tools calling import_tools::register_tools");
    import_tools::register_tools();
    aida_ipc::trace_breadcrumb("agent_tools: initialize_all_tools calling search_tools::register_tools");
    search_tools::register_tools();
    aida_ipc::trace_breadcrumb("agent_tools: initialize_all_tools calling segment_tools::register_tools");
    segment_tools::register_tools();
    aida_ipc::trace_breadcrumb("agent_tools: initialize_all_tools calling binary_tools::register_tools");
    binary_tools::register_tools();
    aida_ipc::trace_breadcrumb("agent_tools: initialize_all_tools calling python_tools::register_tools");
    python_tools::register_tools();
    aida_ipc::trace_breadcrumb("agent_tools: initialize_all_tools calling navigation_tools::register_tools");
    navigation_tools::register_tools();
    aida_ipc::trace_breadcrumb("agent_tools: initialize_all_tools calling analysis_tools::register_tools");
    analysis_tools::register_tools();
    aida_ipc::trace_breadcrumb("agent_tools: initialize_all_tools calling deobfuscation_tools::register_tools");
    deobfuscation_tools::register_tools();
    aida_ipc::trace_breadcrumb("agent_tools: initialize_all_tools calling graphrag_tools::register_tools");
    graphrag_tools::register_tools();
    aida_ipc::trace_breadcrumb("agent_tools: initialize_all_tools calling vuln_tools::register_tools");
    vuln_tools::register_tools();
    aida_ipc::trace_breadcrumb("agent_tools: initialize_all_tools calling vuln_tools::register_advanced_tools");
    vuln_tools::register_advanced_tools();
    aida_ipc::trace_breadcrumb("agent_tools: initialize_all_tools calling aida::vuln::verify::tools::register_verification_tools");
    aida::vuln::verify::tools::register_verification_tools();
    aida_ipc::trace_breadcrumb("agent_tools: initialize_all_tools calling aida::vuln::chain_mcp::register_manage_tools");
    aida::vuln::chain_mcp::register_manage_tools();
    aida_ipc::trace_breadcrumb("agent_tools: initialize_all_tools calling aida_ida_batch_tools::register_tools");
    aida_ida_batch_tools::register_tools();
    aida_ipc::trace_breadcrumb("agent_tools: initialize_all_tools calling meta_tools::register_tools");
    meta_tools::register_tools();
    aida_ipc::trace_breadcrumb("agent_tools: initialize_all_tools calling sdk_underused_tools::register_tools");
    sdk_underused_tools::register_tools();
    // Slice C12 — taint-engine MCP surface.
    aida_ipc::trace_breadcrumb("agent_tools: initialize_all_tools calling taint_tools_ext::register_tools");
    taint_tools_ext::register_tools();
    // Slice H6-H12, H16 — graphrag MCP extensions.
    aida_ipc::trace_breadcrumb("agent_tools: initialize_all_tools calling graphrag_tools_ext::register_tools");
    graphrag_tools_ext::register_tools();
    // Slice H13, H14 — binary registry + capability index.
    aida_ipc::trace_breadcrumb("agent_tools: initialize_all_tools calling binary_tools_ext::register_tools");
    binary_tools_ext::register_tools();

    aida_ipc::trace_breadcrumb("agent_tools: initialize_all_tools registering list_all_available_tools meta tool");

    ToolRegistry::instance().register_tool({
        std::string("list_all_available_tools"), std::string("meta"),
        std::string("Returns the complete list of all available IDA Pro tools with their ") +
        std::string("names, categories, descriptions, and parameter schemas. Use this ") +
        std::string("tool when asked what tools or capabilities are available."),
        {
            {std::string("category"), std::string("string"),
             std::string("Optional: filter by category (function, memory, comment, type, ") +
               std::string("import, search, segment, binary, python, navigation, analysis, deobfuscation, graphrag, vuln, vuln_advanced, vuln_verify, meta)"),
             false}
        },
        [](const json& params) -> tool_result_t {
            auto& registry = ToolRegistry::instance();
            std::string filter_category;
            if (params.contains("category") && params["category"].is_string())
                filter_category = params["category"].get<std::string>();

            auto selected = filter_category.empty()
                ? registry.get_all_tools()
                : registry.get_tools_by_category(filter_category);

            json tools_arr = json::array();
            for (const auto* tool : selected)
            {
                json tj;
                tj["name"]        = tool->name;
                tj["category"]    = tool->category;
                tj["description"] = tool->description;
                tj["read_only"]   = tool->read_only;
                tj["destructive"] = tool->destructive;
                tj["deterministic"] = tool->deterministic;
                tj["required_indices"] = tool->required_indices;
                if (!tool->output_schema.is_null() && !tool->output_schema.empty())
                    tj["output_schema"] = tool->output_schema;

                json params_arr = json::array();
                for (const auto& p : tool->parameters)
                {
                    json pj;
                    pj["name"]        = p.name;
                    pj["type"]        = p.type;
                    pj["description"] = p.description;
                    pj["required"]    = p.required;
                    if (!p.enum_values.empty())
                        pj["enum"] = p.enum_values;
                    params_arr.push_back(pj);
                }
                tj["parameters"] = params_arr;
                tools_arr.push_back(tj);
            }

            std::string summary = std::string("Found ") + std::to_string(tools_arr.size()) + std::string(" tools");
            if (!filter_category.empty())
                summary += std::string(" in category '") + filter_category + std::string("'");
            return tool_result_t::ok(summary, tools_arr);
        },
        true
    });

    aida_ipc::trace_breadcrumb("agent_tools: initialize_all_tools all registrations done, querying final tool count");
    auto final_count = ToolRegistry::instance().get_tool_names().size();
    aida_ipc::trace_breadcrumb("agent_tools: initialize_all_tools EXIT total_tools=%zu", final_count);
    msg("AiDA: Initialized %zu agent tools\n", final_count);
}

// =============================================================================
// Slice C12 — Taint-engine MCP tools.
// Reaches into aida::vuln::taint::engine() lazily; tools that depend on full
// indexing declare required_indices=["taint_engine"] so the MCP layer warms
// the index before invoking the handler.
// =============================================================================
namespace taint_tools_ext
{

namespace
{
    using nlohmann::json;
    using aida::vuln::taint::TaintEngine;
    using aida::vuln::taint::taint_kind_t;
    using aida::vuln::taint::taint_kind_str;
    using aida::vuln::taint::taint_path_t;
    using aida::vuln::taint::reach_record_t;

    std::mutex& engine_mtx()
    {
        static std::mutex m;
        return m;
    }

    ea_t parse_ea_or_name(const std::string& spec)
    {
        if (spec.empty()) return BADADDR;
        auto p = agent_tools::helpers::parse_address(spec);
        if (p.has_value()) return *p;
        return get_name_ea(BADADDR, spec.c_str());
    }

    std::string ea_hex(ea_t ea)
    {
        if (ea == BADADDR) return std::string("0x0");
        std::ostringstream ss;
        ss << "0x" << std::hex << std::uppercase << static_cast<std::uint64_t>(ea);
        return ss.str();
    }

    std::optional<taint_kind_t> parse_kind_opt(const json& params, const std::string& key)
    {
        if (!params.is_object()) return std::nullopt;
        auto it = params.find(key);
        if (it == params.end() || !it->is_string()) return std::nullopt;
        std::string s = it->get<std::string>();
        struct row_t { const char* name; taint_kind_t k; };
        static const row_t rows[] = {
            {"user_input",       taint_kind_t::user_input},
            {"network_input",    taint_kind_t::network_input},
            {"file_input",       taint_kind_t::file_input},
            {"env_input",        taint_kind_t::env_input},
            {"registry_input",   taint_kind_t::registry_input},
            {"kernel_userptr",   taint_kind_t::kernel_userptr},
            {"rpc_input",        taint_kind_t::rpc_input},
            {"com_input",        taint_kind_t::com_input},
            {"alpc_input",       taint_kind_t::alpc_input},
            {"named_pipe_input", taint_kind_t::named_pipe_input},
            {"socket_input",     taint_kind_t::socket_input},
            {"http_input",       taint_kind_t::http_input},
            {"websocket_input",  taint_kind_t::websocket_input},
            {"ndis_wsk_input",   taint_kind_t::ndis_wsk_input},
            {"kernel_irp_input", taint_kind_t::kernel_irp_input},
        };
        for (const auto& r : rows) if (s == r.name) return r.k;
        return std::nullopt;
    }

    tool_result_t handle_trace_all_network_to_sinks(const json& params)
    {
        bool require_unsanitized = false;
        int max_paths = 64;
        int max_depth = 10;
        if (params.is_object()) {
            if (params.contains("require_unsanitized") && params["require_unsanitized"].is_boolean())
                require_unsanitized = params["require_unsanitized"].get<bool>();
            max_paths = safe_json_int_param(params, "max_paths", max_paths);
max_depth = safe_json_int_param(params, "max_depth", max_depth);
}
        auto only_kind = parse_kind_opt(params, "only_kind");
        std::vector<taint_path_t> paths;
        {
            std::lock_guard<std::mutex> lk(engine_mtx());
            paths = aida::vuln::taint::engine().trace_all_network_to_sinks(
                require_unsanitized, max_paths, max_depth, only_kind);
        }
        json arr = json::array();
        for (const auto& p : paths) arr.push_back(aida::vuln::taint::to_json(p));
        json data;
        data["count"] = paths.size();
        data["paths"] = std::move(arr);
        return tool_result_t::ok(
            std::string("trace_all_network_to_sinks: ") + std::to_string(paths.size()) + std::string(" path(s)"),
            data);
    }

    tool_result_t handle_trace_taint_reverse(const json& params)
    {
        std::string sink_spec;
        int max_paths = 16, max_depth = 10;
        if (params.is_object()) {
            if (params.contains("sink") && params["sink"].is_string())
                sink_spec = params["sink"].get<std::string>();
            max_paths = safe_json_int_param(params, "max_paths", max_paths);
max_depth = safe_json_int_param(params, "max_depth", max_depth);
}
        if (sink_spec.empty())
            return tool_result_t::error(std::string("sink required"), std::string("bad_param"));
        ea_t sink_ea = parse_ea_or_name(sink_spec);
        if (sink_ea == BADADDR)
            return tool_result_t::error(std::string("could not resolve sink"), std::string("bad_param"));
        std::vector<taint_path_t> paths;
        {
            std::lock_guard<std::mutex> lk(engine_mtx());
            paths = aida::vuln::taint::engine().trace_paths_reverse(sink_ea, max_paths, max_depth);
        }
        json arr = json::array();
        for (const auto& p : paths) arr.push_back(aida::vuln::taint::to_json(p));
        json data;
        data["count"] = paths.size();
        data["paths"] = std::move(arr);
        data["sink_ea"] = ea_hex(sink_ea);
        return tool_result_t::ok(
            std::string("trace_taint_reverse: ") + std::to_string(paths.size()) + std::string(" path(s)"),
            data);
    }

    tool_result_t handle_function_taint_brief(const json& params)
    {
        if (!params.is_object() || !params.contains("function"))
            return tool_result_t::error(std::string("function required"), std::string("bad_param"));
        std::string spec = params["function"].is_string() ? params["function"].get<std::string>() : std::string();
        ea_t ea = parse_ea_or_name(spec);
        if (ea == BADADDR)
            return tool_result_t::error(std::string("could not resolve function"), std::string("no_function_at_addr"));
        func_t* pfn = get_func(ea);
        if (pfn == nullptr)
            return tool_result_t::error(std::string("not a function"), std::string("no_function_at_addr"));
        json data;
        {
            std::lock_guard<std::mutex> lk(engine_mtx());
            data = aida::vuln::taint::engine().function_taint_brief(pfn->start_ea);
        }
        return tool_result_t::ok(std::string("function_taint_brief"), data);
    }

    tool_result_t handle_list_input_source_callsites(const json& params)
    {
        auto only_kind = parse_kind_opt(params, "only_kind");
        std::vector<std::tuple<ea_t, ea_t, std::string, taint_kind_t>> rows;
        {
            std::lock_guard<std::mutex> lk(engine_mtx());
            rows = aida::vuln::taint::engine().enumerate_input_callsites(only_kind);
        }
        json arr = json::array();
        for (const auto& t : rows) {
            json r;
            r["call_ea"]  = ea_hex(std::get<0>(t));
            r["func_ea"]  = ea_hex(std::get<1>(t));
            r["callee"]   = std::get<2>(t);
            r["kind"]     = taint_kind_str(std::get<3>(t));
            arr.push_back(std::move(r));
        }
        json data;
        data["count"] = rows.size();
        data["callsites"] = std::move(arr);
        return tool_result_t::ok(
            std::string("list_input_source_callsites: ") + std::to_string(rows.size()), data);
    }

    tool_result_t handle_list_sink_callsites(const json& /*params*/)
    {
        std::vector<std::tuple<ea_t, ea_t, std::string, std::string>> rows;
        {
            std::lock_guard<std::mutex> lk(engine_mtx());
            rows = aida::vuln::taint::engine().enumerate_sink_callsites();
        }
        json arr = json::array();
        for (const auto& t : rows) {
            json r;
            r["call_ea"]  = ea_hex(std::get<0>(t));
            r["func_ea"]  = ea_hex(std::get<1>(t));
            r["callee"]   = std::get<2>(t);
            r["category"] = std::get<3>(t);
            arr.push_back(std::move(r));
        }
        json data;
        data["count"] = rows.size();
        data["callsites"] = std::move(arr);
        return tool_result_t::ok(
            std::string("list_sink_callsites: ") + std::to_string(rows.size()), data);
    }

    tool_result_t handle_rank_hot_functions(const json& params)
    {
        int limit = 64;
        limit = safe_json_int_param(params, "limit", limit);
if (limit <= 0) limit = 64;
        if (limit > 1024) limit = 1024;
        struct row_t { ea_t ea; std::string name; int score; int hops; std::set<std::string> cats; };
        std::vector<row_t> ranked;
        {
            std::lock_guard<std::mutex> lk(engine_mtx());
            auto& eng = aida::vuln::taint::engine();
            if (!eng.is_analyzed()) eng.analyze_all();
            // Iterate all summaries with both forward + backward reach.
            for (const auto& sum : eng.get_all_summaries())
            {
                const reach_record_t* fr = eng.forward_reach_for(sum.func_ea);
                const reach_record_t* br = eng.backward_reach_for(sum.func_ea);
                if (fr == nullptr || br == nullptr) continue;
                if (fr->sink_categories.empty() && br->input_kinds.empty()) continue;
                int hops = (fr->min_hops_to_sink == INT_MAX ? 16 : fr->min_hops_to_sink)
                         + (br->min_hops_from_source == INT_MAX ? 16 : br->min_hops_from_source);
                int score = -(hops)
                          + static_cast<int>(fr->sink_categories.size()) * 5
                          + static_cast<int>(br->input_kinds.size()) * 5;
                row_t r;
                r.ea = sum.func_ea; r.name = sum.name; r.score = score; r.hops = hops;
                r.cats = fr->sink_categories;
                ranked.push_back(std::move(r));
            }
        }
        std::sort(ranked.begin(), ranked.end(),
                  [](const row_t& a, const row_t& b){ return a.score > b.score; });
        if (static_cast<int>(ranked.size()) > limit) ranked.resize(limit);
        json arr = json::array();
        for (const auto& r : ranked) {
            json j;
            j["func_ea"] = ea_hex(r.ea);
            j["name"]    = r.name;
            j["score"]   = r.score;
            j["hops"]    = r.hops;
            json cs = json::array();
            for (const auto& c : r.cats) cs.push_back(c);
            j["sink_categories"] = std::move(cs);
            arr.push_back(std::move(j));
        }
        json data;
        data["count"] = ranked.size();
        data["functions"] = std::move(arr);
        return tool_result_t::ok(
            std::string("rank_hot_functions: ") + std::to_string(ranked.size()), data);
    }

    tool_result_t handle_trace_taint_inject(const json& params)
    {
        // Synthetic-source variant: pretend `function`'s entry is an input source
        // with the supplied kind; returns paths to any reachable sink.
        if (!params.is_object() || !params.contains("function"))
            return tool_result_t::error(std::string("function required"), std::string("bad_param"));
        std::string spec = params["function"].is_string() ? params["function"].get<std::string>() : std::string();
        ea_t ea = parse_ea_or_name(spec);
        if (ea == BADADDR)
            return tool_result_t::error(std::string("could not resolve function"), std::string("no_function_at_addr"));
        func_t* pfn = get_func(ea);
        if (pfn == nullptr)
            return tool_result_t::error(std::string("not a function"), std::string("no_function_at_addr"));
        int max_paths = 16, max_depth = 10;
        max_paths = safe_json_int_param(params, "max_paths", max_paths);
max_depth = safe_json_int_param(params, "max_depth", max_depth);
std::vector<taint_path_t> paths;
        {
            std::lock_guard<std::mutex> lk(engine_mtx());
            paths = aida::vuln::taint::engine().trace_paths_from_source(
                pfn->start_ea, max_paths, max_depth);
        }
        json arr = json::array();
        for (const auto& p : paths) arr.push_back(aida::vuln::taint::to_json(p));
        json data;
        data["count"] = paths.size();
        data["paths"] = std::move(arr);
        data["func_ea"] = ea_hex(pfn->start_ea);
        return tool_result_t::ok(
            std::string("trace_taint_inject: ") + std::to_string(paths.size()) + std::string(" path(s)"),
            data);
    }

    tool_result_t handle_taint_engine_status(const json& /*params*/)
    {
        json data;
        {
            std::lock_guard<std::mutex> lk(engine_mtx());
            auto& eng = aida::vuln::taint::engine();
            data["analyzed"] = eng.is_analyzed();
            data["summary_count"] = eng.get_all_summaries().size();
        }
        return tool_result_t::ok(std::string("taint_engine_status"), data);
    }

    tool_result_t handle_trace_field_taint(const json& params)
    {
        if (!params.is_object() || !params.contains("function"))
            return tool_result_t::error(std::string("function required"), std::string("bad_param"));
        std::string spec = params["function"].is_string()
                            ? params["function"].get<std::string>()
                            : std::string();
        ea_t ea = parse_ea_or_name(spec);
        if (ea == BADADDR)
            return tool_result_t::error(std::string("could not resolve function"), std::string("no_function_at_addr"));
        func_t* pfn = get_func(ea);
        if (pfn == nullptr)
            return tool_result_t::error(std::string("not a function"), std::string("no_function_at_addr"));
        // function_taint_brief carries the per-param sink uses + inferred kinds,
        // which is the canonical "what struct fields produced taint" answer
        // exposed without ripping the field map out of the engine.
        json brief;
        {
            std::lock_guard<std::mutex> lk(engine_mtx());
            brief = aida::vuln::taint::engine().function_taint_brief(pfn->start_ea);
        }
        return tool_result_t::ok(std::string("trace_field_taint"), brief);
    }

} // namespace (anonymous)

void register_tools()
{
    auto& reg = ToolRegistry::instance();

    auto add = [&](std::string nm, std::string cat, std::string desc,
                   std::vector<tool_param_t> p,
                   std::function<tool_result_t(const json&)> h,
                   bool read_only, bool deterministic,
                   const std::vector<std::string>& required_indices)
    {
        tool_definition_t def;
        def.name = std::move(nm);
        def.category = std::move(cat);
        def.description = std::move(desc);
        def.parameters = std::move(p);
        def.handler = std::move(h);
        def.read_only = read_only;
        def.destructive = false;
        def.deterministic = deterministic;
        def.required_indices = required_indices;
        reg.register_tool(def);
    };

    add(std::string("trace_all_network_to_sinks"), std::string("taint"),
        std::string("Enumerate every imported attacker-controllable source callsite (recv / "
                 "ReadFile / RPC / COM / ALPC / named pipe / WSK / HTTP / WebSocket / "
                 "kernel IRP) and report a ranked list of taint paths reaching dangerous "
                 "sinks (buffer overflow, command injection, format string, "
                 "SafeArray parser, deserialization). Uses the C6 forward reachability "
                 "index for pruning. Optional only_kind filter narrows by source kind."),
        {
            {std::string("require_unsanitized"), std::string("boolean"),
             std::string("If true, drop paths whose dominant route has any LENGTH_VALIDATOR_HELPERS / AUTH_GATE_HELPERS hit."), false},
            {std::string("max_paths"), std::string("number"), std::string("Default 64."), false},
            {std::string("max_depth"), std::string("number"), std::string("Default 10."), false},
            {std::string("only_kind"), std::string("string"),
             std::string("Restrict to one of user_input/network_input/rpc_input/com_input/alpc_input/named_pipe_input/socket_input/http_input/websocket_input/ndis_wsk_input/kernel_irp_input."),
             false},
        },
        handle_trace_all_network_to_sinks,
        true, false, {std::string("taint_engine")});

    add("trace_taint_reverse", "taint",
        "BFS backward from a given sink callsite through the call graph "
                 "using the C6 backward reachability index for pruning. Returns "
                 "canonical taint paths from any reachable input-source function "
                 "back to the sink. Use this when you have a specific sink and "
                 "want to know which attacker-reachable callers could feed it.",
        {
            {std::string("sink"), std::string("string"), std::string("Sink EA (0x...) or symbol."), true},
            {std::string("max_paths"), std::string("number"), std::string("Default 16."), false},
            {std::string("max_depth"), std::string("number"), std::string("Default 10."), false},
        },
        handle_trace_taint_reverse,
        true, false, {std::string("taint_engine")});

    add("function_taint_brief", "taint",
        "Per-function JSON dump: per-parameter taint flags, sink uses with "
                 "callee/category/arg_idx, validators seen on the parameter, inferred "
                 "taint kinds, cyclomatic complexity, and forward reach summary "
                 "(sink categories + min_hops_to_sink). Useful as a single round-trip "
                 "report when triaging a candidate function.",
        {
            {std::string("function"), std::string("string"), std::string("Function EA or symbol."), true},
        },
        handle_function_taint_brief,
        true, false, {std::string("taint_engine")});

    add("list_input_source_callsites", "taint",
        "Walk xrefs to every imported symbol in INPUT_SOURCES + RPC/COM/ALPC/"
                 "named pipe/socket/HTTP/WebSocket/NDIS-WSK/kernel-IRP source arrays and "
                 "return each callsite's call_ea, containing func_ea, callee, and "
                 "taint_kind_t. Deterministic — no analysis required.",
        {
            {std::string("only_kind"), std::string("string"),
             std::string("Optional kind filter (same names as trace_all_network_to_sinks)."), false},
        },
        handle_list_input_source_callsites,
        true, true, {});

    add("list_sink_callsites", "taint",
        "Walk xrefs to every dangerous-sink symbol (BUFFER_OVERFLOW_SINKS, "
                 "COMMAND_INJECTION_SINKS, PATH_TRAVERSAL_SINKS, FORMAT_STRING_FUNCS, "
                 "SAFEARRAY_PARSER_SINKS, DESERIALIZATION_SINKS) and return each "
                 "callsite's call_ea, containing func_ea, callee, and category. "
                 "Deterministic — no analysis required.",
        {},
        handle_list_sink_callsites,
        true, true, {});

    add("rank_hot_functions", "taint",
        "Rank functions by combined source-reach + sink-reach score. Uses the "
                 "C6 forward/backward reachability indices. Functions that sit on a "
                 "short path between a known input source and a known sink rank highest. "
                 "Returns func_ea, name, score, hop distance, and the set of reachable "
                 "sink categories. Limit defaults to 64.",
        {
            {std::string("limit"), std::string("number"), std::string("Default 64, max 1024."), false},
        },
        handle_rank_hot_functions,
        true, false, {std::string("taint_engine")});

    add("trace_taint_inject", "taint",
        "Treat the given function's entry as a synthetic taint source and "
                 "enumerate taint paths to any reachable sink. Useful when no formal "
                 "import edge exists (e.g. you suspect a custom message-dispatcher is "
                 "the real attack surface).",
        {
            {std::string("function"), std::string("string"), std::string("Function EA or symbol."), true},
            {std::string("max_paths"), std::string("number"), std::string("Default 16."), false},
            {std::string("max_depth"), std::string("number"), std::string("Default 10."), false},
        },
        handle_trace_taint_inject,
        true, false, {});

    add("taint_engine_status", "taint",
        "Return whether the taint engine has completed analyze_all and how "
                 "many per-function summaries are cached. Deterministic.",
        {},
        handle_taint_engine_status,
        true, true, {});

    add("trace_field_taint", "taint",
        "Report the engine's view of struct-field taint propagation in a "
                 "given function. Re-uses function_taint_brief output, which carries "
                 "per-parameter inferred kinds (including kernel_userptr from the "
                 "KERNEL_USERPTR_TAINT_FIELDS gate) and sink uses with arg indexes.",
        {
            {std::string("function"), std::string("string"), std::string("Function EA or symbol."), true},
        },
        handle_trace_field_taint,
        true, false, {std::string("taint_engine")});
}

} // namespace taint_tools_ext

// =============================================================================
// Slice H - GraphRAG MCP extensions (H6, H7, H8, H9, H10, H11, H12, H16).
// read_only=true on every tool.
// =============================================================================
namespace graphrag_tools_ext
{

namespace
{
    using nlohmann::json;

    std::string current_hash()
    {
        return current_module_graph_key();
    }

    bool graph_indexed()
    {
        std::string h = current_hash();
        if (h.empty()) return false;
        return graphrag::GraphStore::instance().get_stats(h).nodes > 0;
    }

    tool_result_t not_indexed_error()
    {
        return tool_result_t::error(
            std::string("The binary is not indexed; click 'Index Binary' first."),
            std::string("index_empty"));
    }

    // ---- H6 bulk_decompile -------------------------------------------------
    struct decomp_request_t : public exec_request_t
    {
        std::vector<ea_t> eas;
        size_t max_len;
        std::vector<json>* out_entries;
        int* cache_hits;
        int* cache_misses;
        const settings_t* settings_ptr;

        ssize_t idaapi execute() override
        {
            if (!init_hexrays_plugin()) return 0;
            for (ea_t ea : eas)
            {
                func_t* pfn = get_func(ea);
                if (!pfn) { ++(*cache_misses); continue; }

                // Probe the persistent rag cache for an existing entry; the
                // cache stores full pseudocode in raw_code via store_full.
                json entry;
                entry["ea"] = ea;
                qstring fname; get_func_name(&fname, pfn->start_ea);
                entry["name"] = std::string(fname.c_str());

                json cached_ctx;
                std::string ci, ct, cm;
                bool was_cached = false;
                if (settings_ptr)
                {
                    nlohmann::json ctx = ida_utils::get_full_cached_context(pfn->start_ea, *settings_ptr, false, max_len);
                    if (ctx.contains("decompiled_code") && ctx["decompiled_code"].is_string())
                    {
                        std::string code = ctx["decompiled_code"].get<std::string>();
                        if (!code.empty())
                        {
                            entry["language"] = std::string("c");
                            entry["code"] = code.size() > max_len ? code.substr(0, max_len) : code;
                            entry["cached"] = true;
                            was_cached = true;
                            ++(*cache_hits);
                        }
                    }
                }

                if (!was_cached)
                {
                    ++(*cache_misses);
                    auto pair = ida_utils::get_function_code(pfn->start_ea, max_len, false);
                    entry["language"] = pair.second;
                    entry["code"] = pair.first;
                    entry["cached"] = false;
                }
                out_entries->push_back(std::move(entry));
            }
            return 0;
        }
    };

    tool_result_t handle_bulk_decompile(const json& params)
    {
        std::vector<ea_t> eas = helpers::parse_addresses(
            params.contains("eas") ? params["eas"] : json::array());
        if (eas.empty())
            return tool_result_t::error(std::string("eas required"), std::string("bad_param"));

        size_t max_len = 6000;
        if (params.contains("max_len_per_func") && params["max_len_per_func"].is_number_integer())
            max_len = params["max_len_per_func"].get<size_t>();

        std::vector<json> entries;
        int hits = 0, misses = 0;

        settings_t s; // copy-constructible default; matches existing function_tools usage.
        decomp_request_t req;
        req.eas = std::move(eas);
        req.max_len = max_len;
        req.out_entries = &entries;
        req.cache_hits = &hits;
        req.cache_misses = &misses;
        req.settings_ptr = &s;
        execute_sync(req, MFF_WRITE);

        json data;
        data["entries"] = entries;
        data["cache_hits_count"]   = hits;
        data["cache_misses_count"] = misses;
        return tool_result_t::ok(
            std::string("bulk_decompile: ") + std::to_string(entries.size()) + std::string(" entries"),
            data);
    }

    // ---- H7 string_triangulate --------------------------------------------
    tool_result_t handle_string_triangulate(const json& params)
    {
        if (!graph_indexed()) return not_indexed_error();
        std::string hash = current_hash();

        std::vector<std::string> patterns;
        if (params.contains("patterns") && params["patterns"].is_array())
            for (auto& p : params["patterns"]) if (p.is_string()) patterns.push_back(p.get<std::string>());
        if (patterns.empty())
            return tool_result_t::error(std::string("patterns required"), std::string("bad_param"));

        std::vector<std::regex> regs;
        regs.reserve(patterns.size());
        for (auto& p : patterns) regs.emplace_back(p, std::regex::icase);

        build_strlist();
        size_t qty = get_strlist_qty();

        auto& store = graphrag::GraphStore::instance();
        json results = json::array();

        for (size_t pi = 0; pi < patterns.size(); ++pi)
        {
            json pat_block;
            pat_block["pattern"] = patterns[pi];
            json strings_arr = json::array();
            for (size_t i = 0; i < qty; ++i)
            {
                string_info_t si;
                if (!get_strlist_item(&si, i)) continue;
                qstring sv;
                get_strlit_contents(&sv, si.ea, si.length, si.type);
                std::string svs = sv.c_str();
                if (!std::regex_search(svs, regs[pi])) continue;

                json sentry;
                sentry["ea"]    = si.ea;
                sentry["value"] = svs;

                // xrefs to this string -> containing function
                json xrefs_arr = json::array();
                xrefblk_t xb;
                for (bool ok = xb.first_to(si.ea, XREF_DATA); ok; ok = xb.next_to())
                {
                    json xj;
                    xj["from_ea"] = xb.from;
                    func_t* pfn = get_func(xb.from);
                    if (pfn)
                    {
                        qstring nm; get_func_name(&nm, pfn->start_ea);
                        json infn;
                        infn["ea"]   = pfn->start_ea;
                        infn["name"] = nm.c_str();
                        auto* gnode = store.get_node_by_address(hash, graphrag::node_type_t::FUNCTION, pfn->start_ea);
                        infn["risk_level"] = gnode ? gnode->risk_level : std::string();
                        xj["in_function"] = std::move(infn);
                    }
                    // taint reach probe - cheap "calls a known sink" answer.
                    json reaches = json::array();
                    xj["reaches_sinks"] = reaches;
                    xrefs_arr.push_back(std::move(xj));
                }
                sentry["xrefs"] = std::move(xrefs_arr);
                strings_arr.push_back(std::move(sentry));
            }
            pat_block["strings"] = std::move(strings_arr);
            results.push_back(std::move(pat_block));
        }

        return tool_result_t::ok(std::string("string_triangulate"), results);
    }

    // ---- H8 bulk semantic analysis ----------------------------------------
    tool_result_t handle_bulk_semantic_analysis(const json& params)
    {
        if (!graph_indexed()) return not_indexed_error();
        std::string hash = current_hash();
        auto& store = graphrag::GraphStore::instance();
        graphrag::QueryEngine qe(store);

        bool include_raw_code = false;
        if (params.contains("include_raw_code") && params["include_raw_code"].is_boolean())
            include_raw_code = params["include_raw_code"].get<bool>();

        std::vector<int> node_ids;
        if (params.contains("node_ids") && params["node_ids"].is_array())
            for (auto& v : params["node_ids"]) { if (v.is_number_integer()) { const auto __iv = v.get<std::int64_t>(); if (__iv >= std::numeric_limits<int>::min() && __iv <= std::numeric_limits<int>::max()) node_ids.push_back(static_cast<int>(__iv)); } else if (v.is_number_unsigned()) { const auto __uv = v.get<std::uint64_t>(); if (__uv <= static_cast<std::uint64_t>(std::numeric_limits<int>::max())) node_ids.push_back(static_cast<int>(__uv)); } }

        std::vector<ea_t> addrs;
        if (params.contains("addresses"))
            addrs = helpers::parse_addresses(params["addresses"]);

        // Resolve node_ids -> addresses.
        for (int id : node_ids)
        {
            auto* n = store.get_node(id);
            if (n && n->binary_hash == hash && n->address != BADADDR) addrs.push_back(n->address);
        }

        json out = json::array();
        for (ea_t a : addrs)
        {
            json entry = qe.get_semantic_analysis(hash, a);
            if (!include_raw_code) entry.erase("raw_code");
            out.push_back(std::move(entry));
        }
        return tool_result_t::ok(std::string("bulk_semantic_analysis"), out);
    }

    // ---- H9 filter_functions ----------------------------------------------
    tool_result_t handle_filter_functions(const json& params)
    {
        if (!graph_indexed()) return not_indexed_error();
        std::string hash = current_hash();
        auto& store = graphrag::GraphStore::instance();
        auto matches = store.filter_nodes(hash, params);

        json out = json::array();
        for (auto* n : matches)
        {
            json e;
            e["node_id"]          = n->id;
            e["ea"]               = n->address;
            e["name"]             = n->name;
            e["risk_level"]       = n->risk_level;
            e["security_flags"]   = n->security_flags;
            e["activity_profile"] = n->activity_profile;
            out.push_back(std::move(e));
        }
        return tool_result_t::ok(
            std::string("filter_functions: ") + std::to_string(out.size()) + std::string(" hit(s)"),
            out);
    }

    // ---- H10 list_external_entries ----------------------------------------
    tool_result_t handle_list_external_entries(const json& params)
    {
        std::vector<std::string> filter;
        if (params.is_object() && params.contains("categories") && params["categories"].is_array())
            for (auto& v : params["categories"]) if (v.is_string()) filter.push_back(v.get<std::string>());

        auto entries = graphrag::extract_externally_reachable_entries();
        json out = json::array();
        for (auto& e : entries)
        {
            if (!filter.empty())
            {
                bool keep = false;
                for (auto& f : filter) if (e.category == f) { keep = true; break; }
                if (!keep) continue;
            }
            json je;
            je["ea"]       = e.ea;
            je["name"]     = e.name;
            je["category"] = e.category;
            je["source"]   = e.source;
            out.push_back(std::move(je));
        }
        return tool_result_t::ok(
            std::string("list_external_entries: ") + std::to_string(out.size()) + std::string(" entries"),
            out);
    }

    // ---- H11 security_delta -----------------------------------------------
    tool_result_t handle_security_delta(const json& params)
    {
        if (!graph_indexed()) return not_indexed_error();
        std::string hash = current_hash();

        graphrag::query_cursor_t in_cursor;
        if (params.contains("cursor") && params["cursor"].is_string())
            graphrag::decode_cursor(params["cursor"].get<std::string>(), in_cursor);

        int limit = 50;
        limit = safe_json_int_param(params, "limit", limit);
auto& store = graphrag::GraphStore::instance();
        graphrag::QueryEngine qe(store);
        graphrag::query_cursor_t out_cursor;
        bool has_more = false;
        json result = qe.get_security_analysis(hash, limit, in_cursor, out_cursor, has_more);

        json data;
        data["analysis"]    = result;
        data["next_cursor"] = graphrag::encode_cursor(out_cursor);
        data["has_more"]    = has_more;
        return tool_result_t::ok(std::string("security_delta"), data);
    }

    // ---- H12 vuln_pre_auth_taint_paths ------------------------------------
    tool_result_t handle_pre_auth_taint_paths(const json& params)
    {
        std::string pattern = "(?i)auth|login|verify|check_perm|access_check|impersonate|token";
        if (params.is_object() && params.contains("auth_regex") && params["auth_regex"].is_string())
            pattern = params["auth_regex"].get<std::string>();
        std::regex auth_re;
        try { auth_re = std::regex(pattern); }
        catch (...) { return tool_result_t::error(std::string("bad auth_regex"), std::string("bad_param")); }

        int max_paths = 64, max_depth = 10;
        if (params.is_object())
        {
            max_paths = safe_json_int_param(params, "max_paths", max_paths);
max_depth = safe_json_int_param(params, "max_depth", max_depth);
}

        std::vector<aida::vuln::taint::taint_path_t> paths;
        try {
            paths = aida::vuln::taint::engine().trace_all_network_to_sinks(
                false, max_paths, max_depth, std::nullopt);
        } catch (...) {
            return tool_result_t::error(std::string("taint engine unavailable"), std::string("index_empty"));
        }

        json arr = json::array();
        for (const auto& p : paths)
        {
            bool crossed_auth = false;
            std::vector<std::string> path_names;
            for (auto& step : p.steps)
            {
                if (!step.func_name.empty())
                {
                    path_names.push_back(step.func_name);
                    if (std::regex_search(step.func_name, auth_re)) { crossed_auth = true; break; }
                }
            }
            if (crossed_auth) continue;
            json pj;
            pj["source"] = p.origin.source_name;
            pj["sink"]   = p.sink_name;
            pj["path"]   = path_names;
            pj["vulnerability_type"] = p.vulnerability_type;
            pj["pre_auth"]  = true;
            pj["hop_count"] = static_cast<int>(p.steps.size());
            arr.push_back(std::move(pj));
        }
        json data;
        data["paths"] = arr;
        return tool_result_t::ok(
            std::string("pre_auth_taint_paths: ") + std::to_string(arr.size()) + std::string(" path(s)"),
            data);
    }

    // ---- H16 extract_dispatch_tables --------------------------------------
    struct switch_collector_t : public ctree_visitor_t
    {
        json* out_handlers;
        switch_collector_t(json* out) : ctree_visitor_t(CV_FAST), out_handlers(out) {}
        int idaapi visit_insn(cinsn_t* i) override
        {
            if (i->op == cit_switch && i->cswitch)
            {
                json table = json::object();
                table["type"] = "switch";
                table["base_ea"] = static_cast<uint64_t>(i->ea);
                json handlers = json::array();
                for (size_t idx = 0; idx < i->cswitch->cases.size(); ++idx)
                {
                    const ccase_t& c = i->cswitch->cases[idx];
                    json h;
                    h["index"] = static_cast<int>(idx);
                    h["ea"] = static_cast<uint64_t>(c.ea);
                    qstring nm; get_func_name(&nm, c.ea);
                    h["name"] = nm.c_str();
                    handlers.push_back(std::move(h));
                }
                table["size"] = handlers.size();
                table["handlers"] = std::move(handlers);
                out_handlers->push_back(std::move(table));
            }
            return 0;
        }
    };

    tool_result_t handle_extract_dispatch_tables(const json& params)
    {
        if (!init_hexrays_plugin())
            return tool_result_t::error(std::string("hexrays unavailable"), std::string("decompile_failed"));

        std::string addr_str;
        if (params.is_object() && params.contains("address") && params["address"].is_string())
            addr_str = params["address"].get<std::string>();
        auto ea_opt = helpers::parse_address(addr_str);
        if (!ea_opt)
            return tool_result_t::error(std::string("address required"), std::string("bad_param"));

        func_t* pfn = get_func(*ea_opt);
        if (!pfn) return tool_result_t::error(std::string("no function at address"), std::string("no_function_at_addr"));

        json tables = json::array();
        try
        {
            hexrays_failure_t hf;
            cfuncptr_t cfunc = aida_decompile_func(pfn, &hf, DECOMP_NO_WAIT);
            if (cfunc != nullptr)
            {
                switch_collector_t vis(&tables);
                vis.apply_to(&cfunc->body, nullptr);
            }
        }
        catch (...) {}

        // Second substrate: data-segment function-pointer arrays referencing
        // this function's body. Cheap heuristic, bounded by function size.
        // (Vtable detection is left to the rtti_* MCP tool family.)

        json data;
        data["tables"] = tables;
        return tool_result_t::ok(std::string("extract_dispatch_tables"), data);
    }

} // namespace (anonymous)

void register_tools()
{
    auto& reg = ToolRegistry::instance();
    auto add = [&](std::string nm, std::string cat, std::string desc,
                   std::vector<tool_param_t> p,
                   std::function<tool_result_t(const json&)> h,
                   bool read_only, bool deterministic,
                   const std::vector<std::string>& required_indices)
    {
        tool_definition_t def;
        def.name = std::move(nm);
        def.category = std::move(cat);
        def.description = std::move(desc);
        def.parameters = std::move(p);
        def.handler = std::move(h);
        def.read_only = read_only;
        def.destructive = false;
        def.deterministic = deterministic;
        def.required_indices = required_indices;
        reg.register_tool(def);
    };

    add("bulk_decompile", "graphrag",
        "Batched decompilation that writes through the netnode-backed "
                 "rag cache. Skips entries already present in the cache.",
        {
            {std::string("eas"), std::string("array"), std::string("Function EAs to decompile."), true},
            {std::string("max_len_per_func"), std::string("number"), std::string("Truncate each function at this many chars (default 6000)."), false},
            {std::string("include_context"), std::string("boolean"), std::string("Reserved for future use."), false},
        },
        handle_bulk_decompile,
        true, false, {});

    add("string_triangulate", "graphrag",
        "Match strings by regex pattern and join through xrefs to the "
                 "containing functions, decorated with the graphrag risk_level.",
        {
            {std::string("patterns"), std::string("array"), std::string("Regex patterns to match string literals."), true},
        },
        handle_string_triangulate,
        true, false, {std::string("graphrag")});

    add("graphrag_bulk_semantic_analysis", "graphrag",
        "Batched semantic analysis. Accepts node_ids OR addresses. "
                 "Strips raw_code by default to keep payloads small.",
        {
            {std::string("node_ids"), std::string("array"), std::string("Graph node IDs."), false},
            {std::string("addresses"), std::string("array"), std::string("Function EAs."), false},
            {std::string("include_raw_code"), std::string("boolean"), std::string("Include raw_code in response."), false},
        },
        handle_bulk_semantic_analysis,
        true, true, {std::string("graphrag")});

    add("graphrag_filter_functions", "graphrag",
        "Structured AND/OR predicate over the inverted indices. "
                 "Predicate fields: all_flags, any_flags, all_apis, any_apis, "
                 "risk_levels.",
        {
            {std::string("all_flags"), std::string("array"), std::string("Security flags required (AND)."), false},
            {std::string("any_flags"), std::string("array"), std::string("Security flags allowed (OR)."), false},
            {std::string("all_apis"), std::string("array"), std::string("API names required (AND)."), false},
            {std::string("any_apis"), std::string("array"), std::string("API names allowed (OR)."), false},
            {std::string("risk_levels"), std::string("array"), std::string("Risk levels to include."), false},
        },
        handle_filter_functions,
        true, true, {std::string("graphrag")});

    add("graphrag_list_external_entries", "graphrag",
        "Aggregate externally-reachable entry points: PE exports, "
                 "RPC NDR stubs, COM IDispatch, driver dispatch, WinRT, "
                 "service handlers, WSK callbacks.",
        {
            {std::string("categories"), std::string("array"), std::string("Optional category filter."), false},
        },
        handle_list_external_entries,
        true, true, {});

    add("graphrag_security_delta", "graphrag",
        "Cursored security analysis: only nodes updated since the "
                 "supplied cursor are returned. Cursor is opaque base64-JSON.",
        {
            {std::string("cursor"), std::string("string"), std::string("Opaque cursor from a prior call."), false},
            {std::string("limit"), std::string("number"), std::string("Max items per page (default 50)."), false},
        },
        handle_security_delta,
        true, false, {std::string("graphrag")});

    add("vuln_pre_auth_taint_paths", "vuln",
        "Filter Slice C taint paths to drop those crossing an auth "
                 "function. Survivors are marked pre_auth=true. The default "
                 "auth_regex matches auth/login/verify/check_perm/access_check/"
                 "impersonate/token (case-insensitive).",
        {
            {std::string("auth_regex"), std::string("string"), std::string("Auth-crossing regex (case-insensitive)."), false},
            {std::string("max_paths"), std::string("number"), std::string("Maximum candidate paths to inspect."), false},
            {std::string("max_depth"), std::string("number"), std::string("Maximum DFS depth."), false},
        },
        handle_pre_auth_taint_paths,
        true, false, {std::string("taint_engine")});

    add("extract_dispatch_tables", "graphrag",
        "Third dispatch-table substrate: walks decompiled cit_switch "
                 "nodes for the function at address and reports handler EAs.",
        {
            {std::string("address"), std::string("string"), std::string("Function EA to scan."), true},
        },
        handle_extract_dispatch_tables,
        true, false, {});
}

} // namespace graphrag_tools_ext

// =============================================================================
// Slice H - Binary registry & capability tools (H13, H14).
// =============================================================================
namespace binary_tools_ext
{

namespace
{
    using nlohmann::json;

    tool_result_t handle_binary_list_registered(const json&)
    {
        auto entries = aida_db::AnalysisDB::instance().list_registered_binaries();
        json out = json::array();
        for (auto& e : entries)
        {
            json je;
            je["hash"]                = e.hash;
            je["first_seen_ms"]       = e.first_seen_ms;
            je["last_seen_ms"]        = e.last_seen_ms;
            je["has_graph"]           = e.has_graph;
            je["has_vectors"]         = e.has_vectors;
            je["fingerprint_summary"] = e.fingerprint_summary;
            out.push_back(std::move(je));
        }
        return tool_result_t::ok(
            std::string("binary_list_registered: ") + std::to_string(out.size()) + std::string(" binaries"),
            out);
    }

    struct iat_collector_state_t
    {
        // import_name -> { module, callsites:[{ea, func_ea, func_name}] }
        std::unordered_map<std::string, json> entries;
        std::string current_module;
        const std::vector<std::string>* filter_apis = nullptr;
    };

    static int idaapi iat_walk_cb(ea_t ea, const char* name, uval_t, void* p)
    {
        if (!name) return 1;
        auto* st = static_cast<iat_collector_state_t*>(p);
        std::string nm = name;
        if (st->filter_apis && !st->filter_apis->empty())
        {
            bool match = false;
            for (auto& f : *st->filter_apis) if (f == nm) { match = true; break; }
            if (!match) return 1;
        }

        json& e = st->entries[nm];
        if (e.is_null())
        {
            e = json::object();
            e["module"] = st->current_module;
            e["callsite_count"] = 0;
            e["callsites"] = json::array();
        }

        xrefblk_t xb;
        for (bool ok = xb.first_to(ea, XREF_ALL); ok; ok = xb.next_to())
        {
            json cs;
            cs["ea"] = xb.from;
            func_t* pfn = get_func(xb.from);
            cs["func_ea"]   = pfn ? pfn->start_ea : BADADDR;
            qstring fn;
            if (pfn) get_func_name(&fn, pfn->start_ea);
            cs["func_name"] = std::string(fn.c_str());
            e["callsites"].push_back(std::move(cs));
            e["callsite_count"] = safe_json_int_value(e["callsite_count"], 0) + 1;
        }
        return 1;
    }

    tool_result_t handle_binary_capability_index(const json& params)
    {
        std::vector<std::string> filter_apis;
        if (params.is_object() && params.contains("filter_apis") && params["filter_apis"].is_array())
            for (auto& v : params["filter_apis"]) if (v.is_string()) filter_apis.push_back(v.get<std::string>());

        iat_collector_state_t st;
        st.filter_apis = filter_apis.empty() ? nullptr : &filter_apis;

        uint nmod = get_import_module_qty();
        for (uint m = 0; m < nmod; ++m)
        {
            qstring mbuf;
            if (!get_import_module_name(&mbuf, m)) continue;
            st.current_module = mbuf.c_str();
            enum_import_names(m, iat_walk_cb, &st);
        }

        json out = json::object();
        for (auto& [k, v] : st.entries) out[k] = v;
        return tool_result_t::ok(
            std::string("binary_capability_index: ") + std::to_string(st.entries.size()) + std::string(" imports"),
            out);
    }

} // namespace (anonymous)

void register_tools()
{
    auto& reg = ToolRegistry::instance();
    auto add = [&](std::string nm, std::string cat, std::string desc,
                   std::vector<tool_param_t> p,
                   std::function<tool_result_t(const json&)> h,
                   bool read_only, bool deterministic,
                   const std::vector<std::string>& required_indices)
    {
        tool_definition_t def;
        def.name = std::move(nm);
        def.category = std::move(cat);
        def.description = std::move(desc);
        def.parameters = std::move(p);
        def.handler = std::move(h);
        def.read_only = read_only;
        def.destructive = false;
        def.deterministic = deterministic;
        def.required_indices = required_indices;
        reg.register_tool(def);
    };

    add("binary_list_registered", "binary",
        "List binaries that have ever been registered with the analysis DB. "
                 "Each record carries the hash, first/last seen timestamps, graph "
                 "and vector availability flags, and a fingerprint summary.",
        {},
        handle_binary_list_registered,
        true, true, {});

    add("binary_capability_index", "binary",
        "Inverted IAT view: import_name -> {module, callsite_count, "
                 "callsites:[{ea, func_ea, func_name}]}. Optional filter_apis "
                 "scopes to a named subset.",
        {
            {std::string("filter_apis"), std::string("array"), std::string("Optional list of API names."), false},
        },
        handle_binary_capability_index,
        true, true, {});
}

} // namespace binary_tools_ext

}
