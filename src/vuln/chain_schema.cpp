#include "chain_schema.hpp"

#include <limits>
#include <unordered_set>
#include <utility>

namespace aida
{
namespace vuln
{
namespace chain
{

namespace
{

bool require_object(const nlohmann::json& value, validation_result_t& errors, const std::string& path)
{
    if (value.is_object())
        return true;
    errors.add("invalid_chain_schema", path, "chain document must be a JSON object");
    return false;
}

bool read_string_field(const nlohmann::json& value,
                       const char* key,
                       std::string& out,
                       validation_result_t& errors,
                       const std::string& path,
                       bool required)
{
    auto it = value.find(key);
    if (it == value.end())
    {
        if (required)
            errors.add("missing_required_field", path + "/" + key, "field is required");
        return !required;
    }
    if (!it->is_string())
    {
        errors.add("invalid_type", path + "/" + key, "expected string");
        return false;
    }
    out = it->get<std::string>();
    if (required && out.empty())
    {
        errors.add("invalid_id", path + "/" + key, "string must not be empty");
        return false;
    }
    return true;
}

bool read_int_field(const nlohmann::json& value,
                    const char* key,
                    int& out,
                    validation_result_t& errors,
                    const std::string& path)
{
    auto it = value.find(key);
    if (it == value.end())
        return true;
    if (!it->is_number_integer())
    {
        errors.add("invalid_type", path + "/" + key, "expected integer");
        return false;
    }
    const auto integer = it->get<nlohmann::json::number_integer_t>();
    if (integer < (std::numeric_limits<int>::min)() || integer > (std::numeric_limits<int>::max)())
    {
        errors.add("invalid_range", path + "/" + key, "integer is outside the supported range");
        return false;
    }
    out = static_cast<int>(integer);
    return true;
}

bool no_unknown_fields(const nlohmann::json& value,
                       const std::unordered_set<std::string>& allowed,
                       validation_result_t& errors,
                       const std::string& path)
{
    bool ok = true;
    for (auto it = value.begin(); it != value.end(); ++it)
    {
        if (allowed.find(it.key()) == allowed.end())
        {
            errors.add("unknown_field", path + "/" + it.key(), "unknown field");
            ok = false;
        }
    }
    return ok;
}

template <typename T>
bool read_array(const nlohmann::json& value,
                const char* key,
                std::vector<T>& out,
                bool (*reader)(const nlohmann::json&, T&, validation_result_t&, const std::string&),
                validation_result_t& errors,
                const std::string& path,
                bool required)
{
    auto it = value.find(key);
    if (it == value.end())
    {
        if (required)
            errors.add("missing_required_field", path + "/" + key, "field is required");
        return !required;
    }
    if (!it->is_array())
    {
        errors.add("invalid_type", path + "/" + key, "expected array");
        return false;
    }
    bool ok = true;
    out.clear();
    out.reserve(it->size());
    for (std::size_t i = 0; i < it->size(); ++i)
    {
        T item;
        if (!reader((*it)[i], item, errors, path + "/" + key + "/" + std::to_string(i)))
            ok = false;
        out.push_back(std::move(item));
    }
    return ok;
}

bool read_corpus_item(const nlohmann::json& value, corpus_record_t& out, validation_result_t& errors, const std::string& path)
{
    return from_json(value, out, errors, path);
}

bool read_fact_item(const nlohmann::json& value, fact_t& out, validation_result_t& errors, const std::string& path)
{
    return from_json(value, out, errors, path);
}

bool read_assumption_item(const nlohmann::json& value, assumption_t& out, validation_result_t& errors, const std::string& path)
{
    return from_json(value, out, errors, path);
}

bool read_link_item(const nlohmann::json& value, link_spec_t& out, validation_result_t& errors, const std::string& path)
{
    return from_json(value, out, errors, path);
}

bool read_objective_item(const nlohmann::json& value, objective_spec_t& out, validation_result_t& errors, const std::string& path)
{
    return from_json(value, out, errors, path);
}

nlohmann::json corpus_from_v1_module(const nlohmann::json& module)
{
    nlohmann::json identity = nlohmann::json::object();
    const std::string id = module.value("id", module.value("module_id", std::string()));
    identity["corpus_id"] = id;
    identity["canonical_name"] = module.value("name", id);
    identity["input_path"] = module.value("path", std::string());
    identity["image_base"] = module.value("image_base", std::string("0x0"));
    identity["bitness"] = module.value("bitness", 0);
    identity["hashes"] = nlohmann::json::object();
    if (module.contains("sha256"))
        identity["hashes"]["sha256"] = module["sha256"];
    if (module.contains("md5"))
        identity["hashes"]["md5"] = module["md5"];
    nlohmann::json out;
    out["kind"] = "binary";
    out["availability"] = module.contains("instance_id") ? "peer_loaded" : "missing";
    out["trust"] = module.contains("instance_id") ? "ida_extracted" : "user_declared";
    out["identity"] = std::move(identity);
    out["segments"] = nlohmann::json::array();
    out["live_instances"] = nlohmann::json::array();
    if (module.contains("instance_id"))
    {
        nlohmann::json inst;
        inst["instance_id"] = module["instance_id"];
        out["live_instances"].push_back(std::move(inst));
    }
    out["loader_model"] = nlohmann::json::object();
    return out;
}

fact_t make_blocking_fact(const std::string& id,
                          fact_kind_t kind,
                          const std::string& predicate,
                          const nlohmann::json& subject,
                          proof_state_t state)
{
    fact_t fact;
    fact.fact_id = id;
    fact.kind = kind;
    fact.subject = subject;
    fact.predicate = predicate;
    fact.value.kind = value_kind_t::unknown;
    fact.proof_state = state;
    fact.criticality = fact_criticality_t::chain_critical;
    assign_fact_id_if_missing(fact);
    return fact;
}

void collect_required_fact_ids(const std::vector<fact_t>& facts, std::unordered_set<std::string>& ids)
{
    for (const auto& f : facts)
    {
        if (!f.fact_id.empty())
            ids.insert(f.fact_id);
    }
}

}

nlohmann::json to_json(const chain_document_t& value)
{
    nlohmann::json j;
    j["schema"] = value.schema;
    j["version"] = value.version;
    j["chain_id"] = value.chain_id;
    j["title"] = value.title;
    j["target"] = to_json(value.target);
    j["corpus"] = nlohmann::json::array();
    for (const auto& c : value.corpus)
        j["corpus"].push_back(to_json(c));
    j["entry"] = value.entry;
    j["objects"] = value.objects;
    j["inputs"] = value.inputs;
    j["events"] = value.events;
    j["facts"] = nlohmann::json::array();
    for (const auto& f : value.facts)
        j["facts"].push_back(to_json(f));
    j["assumptions"] = nlohmann::json::array();
    for (const auto& a : value.assumptions)
        j["assumptions"].push_back(to_json(a));
    j["links"] = nlohmann::json::array();
    for (const auto& l : value.links)
        j["links"].push_back(to_json(l));
    j["objectives"] = nlohmann::json::array();
    for (const auto& o : value.objectives)
        j["objectives"].push_back(to_json(o));
    j["policies"] = to_json(value.policies);
    j["initial_state"] = to_json(value.initial_state);
    j["metadata"] = value.metadata;
    return j;
}

bool from_json(const nlohmann::json& value, chain_document_t& out, validation_result_t& errors, const std::string& path)
{
    if (!require_object(value, errors, path))
        return false;
    no_unknown_fields(value, {"schema", "version", "chain_id", "title", "target", "corpus", "entry", "objects", "inputs", "events", "facts", "assumptions", "links", "objectives", "policies", "policy", "initial_state", "metadata"}, errors, path);
    bool ok = true;
    ok = read_string_field(value, "schema", out.schema, errors, path, true) && ok;
    ok = read_int_field(value, "version", out.version, errors, path) && ok;
    ok = read_string_field(value, "chain_id", out.chain_id, errors, path, true) && ok;
    ok = read_string_field(value, "title", out.title, errors, path, false) && ok;
    if (out.schema != k_chain_document_schema)
    {
        errors.add("unsupported_version", path + "/schema", "expected aida_chain_document_v2");
        ok = false;
    }
    if (out.version != k_chain_document_version)
    {
        errors.add("unsupported_version", path + "/version", "expected version 2");
        ok = false;
    }
    auto target = value.find("target");
    if (target == value.end())
    {
        errors.add("missing_required_field", path + "/target", "field is required");
        ok = false;
    }
    else
    {
        ok = from_json(*target, out.target, errors, path + "/target") && ok;
    }
    ok = read_array(value, "corpus", out.corpus, read_corpus_item, errors, path, true) && ok;
    auto entry = value.find("entry");
    if (entry != value.end())
    {
        if (!entry->is_object())
        {
            errors.add("invalid_type", path + "/entry", "expected object");
            ok = false;
        }
        else
        {
            out.entry = *entry;
        }
    }
    auto objects = value.find("objects");
    if (objects != value.end())
    {
        if (!objects->is_array())
        {
            errors.add("invalid_type", path + "/objects", "expected array");
            ok = false;
        }
        else
        {
            out.objects = *objects;
        }
    }
    auto inputs = value.find("inputs");
    if (inputs != value.end())
    {
        if (!inputs->is_array())
        {
            errors.add("invalid_type", path + "/inputs", "expected array");
            ok = false;
        }
        else
        {
            out.inputs = *inputs;
        }
    }
    auto events = value.find("events");
    if (events != value.end())
    {
        if (!events->is_array())
        {
            errors.add("invalid_type", path + "/events", "expected array");
            ok = false;
        }
        else
        {
            out.events = *events;
        }
    }
    ok = read_array(value, "facts", out.facts, read_fact_item, errors, path, false) && ok;
    ok = read_array(value, "assumptions", out.assumptions, read_assumption_item, errors, path, false) && ok;
    ok = read_array(value, "links", out.links, read_link_item, errors, path, true) && ok;
    ok = read_array(value, "objectives", out.objectives, read_objective_item, errors, path, true) && ok;
    auto policies = value.find("policies");
    if (policies == value.end())
        policies = value.find("policy");
    if (policies != value.end())
    {
        ok = from_json(*policies, out.policies, errors, path + "/policies") && ok;
    }
    auto state = value.find("initial_state");
    if (state != value.end())
        ok = from_json(*state, out.initial_state, errors, path + "/initial_state") && ok;
    auto meta = value.find("metadata");
    if (meta != value.end())
    {
        if (!meta->is_object())
        {
            errors.add("invalid_type", path + "/metadata", "expected object");
            ok = false;
        }
        else
        {
            out.metadata = *meta;
        }
    }
    validation_result_t semantic = validate_chain_document(out);
    errors.errors.insert(errors.errors.end(), semantic.errors.begin(), semantic.errors.end());
    return ok && semantic.ok();
}

parse_chain_document_result_t parse_chain_document(const nlohmann::json& value)
{
    parse_chain_document_result_t result;
    validation_result_t migration_errors;
    nlohmann::json normalized = migrate_chain_document_json(value, migration_errors);
    result.migrated = normalized != value;
    result.validation.errors.insert(result.validation.errors.end(), migration_errors.errors.begin(), migration_errors.errors.end());
    if (!migration_errors.ok())
    {
        result.ok = false;
        result.normalized = normalized;
        return result;
    }
    result.normalized = normalized;
    bool parsed = from_json(normalized, result.document, result.validation, "");
    result.ok = parsed && result.validation.ok();
    if (result.ok)
        result.normalized = to_json(result.document);
    return result;
}

validation_result_t validate_chain_document(const chain_document_t& value)
{
    validation_result_t result;
    if (value.schema != k_chain_document_schema)
        result.add("unsupported_version", "/schema", "schema must be aida_chain_document_v2");
    if (value.chain_id.empty())
        result.add("missing_required_field", "/chain_id", "chain id is required");
    if (value.corpus.empty())
        result.add("missing_corpus", "/corpus", "at least one corpus entry is required");
    if (value.links.empty())
        result.add("invalid_chain_schema", "/links", "at least one link is required");
    if (value.objectives.empty())
        result.add("missing_objective", "/objectives", "at least one proof objective is required");
    validation_result_t corpus_errors = validate_corpus_records(value.corpus);
    result.errors.insert(result.errors.end(), corpus_errors.errors.begin(), corpus_errors.errors.end());
    std::unordered_set<std::string> corpus_ids;
    for (const auto& c : value.corpus)
    {
        if (!c.identity.corpus_id.empty())
            corpus_ids.insert(c.identity.corpus_id);
    }
    std::unordered_set<std::string> link_ids;
    std::unordered_set<std::string> fact_ids;
    collect_required_fact_ids(value.facts, fact_ids);
    for (std::size_t i = 0; i < value.links.size(); ++i)
    {
        const auto& link = value.links[i];
        const std::string path = "/links/" + std::to_string(i);
        if (link.link_id.empty())
            result.add("missing_required_field", path + "/link_id", "link id is required");
        else if (!link_ids.insert(link.link_id).second)
            result.add("duplicate_id", path + "/link_id", "duplicate link id");
        if (!link.corpus_id.empty() && corpus_ids.find(link.corpus_id) == corpus_ids.end())
            result.add("missing_corpus", path + "/corpus_id", "link references an unknown corpus");
        collect_required_fact_ids(link.preconditions, fact_ids);
        collect_required_fact_ids(link.postconditions, fact_ids);
        collect_required_fact_ids(link.facts, fact_ids);
        for (std::size_t f = 0; f < link.preconditions.size(); ++f)
        {
            if (critical_fact_blocks_confirmation(link.preconditions[f]))
                result.add("critical_fact_unproven", path + "/preconditions/" + std::to_string(f) + "/proof_state", "critical precondition is not proven");
        }
        for (std::size_t f = 0; f < link.postconditions.size(); ++f)
        {
            if (critical_fact_blocks_confirmation(link.postconditions[f]))
                result.add("critical_fact_unproven", path + "/postconditions/" + std::to_string(f) + "/proof_state", "critical postcondition is not proven");
        }
        for (std::size_t a = 0; a < link.assumptions.size(); ++a)
        {
            if (assumption_blocks_confirmation(link.assumptions[a]))
                result.add("critical_assumption_unproven", path + "/assumptions/" + std::to_string(a) + "/proof_state", "critical assumption is not proven");
        }
    }
    std::unordered_set<std::string> objective_ids;
    for (std::size_t i = 0; i < value.objectives.size(); ++i)
    {
        const auto& objective = value.objectives[i];
        const std::string path = "/objectives/" + std::to_string(i);
        if (objective.objective_id.empty())
            result.add("missing_required_field", path + "/objective_id", "objective id is required");
        else if (!objective_ids.insert(objective.objective_id).second)
            result.add("duplicate_id", path + "/objective_id", "duplicate objective id");
        for (const auto& required_id : objective.required_fact_ids)
        {
            if (fact_ids.find(required_id) == fact_ids.end())
                result.add("objective_not_achieved", path + "/required_fact_ids", "objective requires unknown fact id " + required_id);
        }
        for (std::size_t f = 0; f < objective.required_facts.size(); ++f)
        {
            if (critical_fact_blocks_confirmation(objective.required_facts[f]))
                result.add("critical_fact_unproven", path + "/required_facts/" + std::to_string(f) + "/proof_state", "objective-critical fact is not proven");
        }
    }
    validation_result_t state_errors = validate_trace_state(value.initial_state);
    result.errors.insert(result.errors.end(), state_errors.errors.begin(), state_errors.errors.end());
    return result;
}

nlohmann::json migrate_chain_document_json(const nlohmann::json& value, validation_result_t& errors)
{
    if (!value.is_object())
    {
        errors.add("invalid_chain_schema", "", "chain document must be an object");
        return value;
    }
    const std::string schema = value.value("schema", std::string());
    if (schema == k_chain_document_schema)
        return value;
    if (schema != "aida.chain_document.v1" && schema != "chain_document_v1")
    {
        errors.add("unsupported_version", "/schema", "unsupported chain document schema");
        return value;
    }
    nlohmann::json out;
    out["schema"] = k_chain_document_schema;
    out["version"] = k_chain_document_version;
    out["chain_id"] = value.value("chain_id", stable_id("chain", value));
    out["title"] = value.value("description", value.value("title", std::string()));
    out["target"] = nlohmann::json{
        {"architecture", value.value("architecture", std::string("unknown"))},
        {"platform", value.value("target_platform", std::string("unknown"))},
        {"endianness", value.value("endianness", std::string("unknown"))},
        {"pointer_width_bits", value.value("pointer_width_bits", 0)},
        {"environment", value.value("environment", nlohmann::json::object())},
    };
    out["corpus"] = nlohmann::json::array();
    if (value.contains("modules") && value["modules"].is_array())
    {
        for (const auto& module : value["modules"])
            out["corpus"].push_back(corpus_from_v1_module(module));
    }
    out["entry"] = value.value("entry_state", nlohmann::json::object());
    out["objects"] = value.value("state_declarations", nlohmann::json::array());
    out["inputs"] = value.value("inputs", nlohmann::json::array());
    out["events"] = value.value("events", nlohmann::json::array());
    out["facts"] = nlohmann::json::array();
    out["assumptions"] = nlohmann::json::array();
    out["links"] = value.value("links", nlohmann::json::array());
    out["objectives"] = value.value("objectives", nlohmann::json::array());
    if (out["objectives"].empty() && value.contains("final_objective"))
        out["objectives"].push_back(value["final_objective"]);
    out["policies"] = value.value("proof_policy", nlohmann::json::object());
    out["initial_state"] = nlohmann::json::object();
    out["metadata"] = nlohmann::json{{"migrated_from_schema", schema}};
    errors.add("schema_migrated", "/schema", "legacy chain document migrated to aida_chain_document_v2", validation_severity_t::warning, false);
    if (out["corpus"].empty())
        errors.add("missing_corpus", "/modules", "legacy document has no modules to migrate");
    return out;
}

nlohmann::json chain_document_json_schema()
{
    return nlohmann::json{
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"$id", "aida://schemas/aida_chain_document_v2"},
        {"type", "object"},
        {"additionalProperties", false},
        {"required", nlohmann::json::array({"schema", "chain_id", "target", "corpus", "links", "objectives"})},
        {"properties", nlohmann::json{
            {"schema", nlohmann::json{{"const", k_chain_document_schema}}},
            {"version", nlohmann::json{{"const", k_chain_document_version}}},
            {"chain_id", nlohmann::json{{"type", "string"}, {"minLength", 1}}},
            {"title", nlohmann::json{{"type", "string"}}},
            {"target", nlohmann::json{{"type", "object"}}},
            {"corpus", nlohmann::json{{"type", "array"}, {"minItems", 1}}},
            {"entry", nlohmann::json{{"type", "object"}}},
            {"objects", nlohmann::json{{"type", "array"}}},
            {"inputs", nlohmann::json{{"type", "array"}}},
            {"events", nlohmann::json{{"type", "array"}}},
            {"facts", nlohmann::json{{"type", "array"}}},
            {"assumptions", nlohmann::json{{"type", "array"}}},
            {"links", nlohmann::json{{"type", "array"}, {"minItems", 1}}},
            {"objectives", nlohmann::json{{"type", "array"}, {"minItems", 1}}},
            {"policies", nlohmann::json{{"type", "object"}}},
            {"initial_state", nlohmann::json{{"type", "object"}}},
            {"metadata", nlohmann::json{{"type", "object"}}},
        }},
        {"failure_codes", nlohmann::json::array({"invalid_chain_schema", "ambiguous_corpus_binding", "missing_corpus", "unknown_field", "critical_fact_unproven", "critical_assumption_unproven", "missing_objective", "objective_not_achieved"})},
        {"confirmation_rule", "confirmed requires every chain-critical and objective-critical fact, assumption, boundary, corpus, and final goal to be proven"},
    };
}

validation_result_t chain_schema_self_check()
{
    nlohmann::json doc;
    doc["schema"] = k_chain_document_schema;
    doc["version"] = k_chain_document_version;
    doc["chain_id"] = "self_check";
    doc["target"] = nlohmann::json{{"architecture", "unknown"}, {"platform", "unknown"}, {"endianness", "unknown"}, {"pointer_width_bits", 64}, {"environment", nlohmann::json::object()}};
    corpus_record_t corpus = make_missing_corpus("mod_missing", "missing.bin", "self check");
    corpus.availability = corpus_availability_t::recorded_only;
    doc["corpus"] = nlohmann::json::array({to_json(corpus)});
    fact_t fact = make_blocking_fact("self_fact", fact_kind_t::content_fact, "controlled", nlohmann::json{{"input", "x"}}, proof_state_t::proven);
    doc["links"] = nlohmann::json::array({nlohmann::json{{"link_id", "link0"}, {"corpus_id", "mod_missing"}, {"preconditions", nlohmann::json::array({to_json(fact)})}}});
    objective_spec_t objective;
    objective.objective_id = "objective0";
    objective.kind = objective_kind_t::memory_write;
    objective.required_fact_ids.push_back(fact.fact_id);
    doc["objectives"] = nlohmann::json::array({to_json(objective)});
    parse_chain_document_result_t parsed = parse_chain_document(doc);
    validation_result_t result = parsed.validation;
    if (!parsed.ok)
        result.add("self_check_failed", "/", "valid minimal v2 chain did not parse");
    doc["links"][0]["preconditions"][0]["proof_state"] = "unknown";
    parse_chain_document_result_t blocked = parse_chain_document(doc);
    if (blocked.validation.ok())
        result.add("self_check_failed", "/links/0/preconditions/0/proof_state", "unknown critical fact did not block validation");
    return result;
}

}
}
}
