#include "chain_binary_corpus.hpp"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <limits>
#include <sstream>
#include <unordered_set>
#include <utility>

#include <auto.hpp>
#include <diskio.hpp>
#include <ida.hpp>
#include <loader.hpp>
#include <nalt.hpp>
#include <segment.hpp>

namespace aida
{
namespace vuln
{
namespace chain
{

namespace
{

template <typename EnumT>
struct enum_name_t
{
    EnumT value;
    const char* name;
};

constexpr enum_name_t<corpus_kind_t> k_corpus_kind_names[] = {
    {corpus_kind_t::binary, "binary"},
    {corpus_kind_t::firmware_region, "firmware_region"},
    {corpus_kind_t::protocol_spec, "protocol_spec"},
    {corpus_kind_t::memory_snapshot, "memory_snapshot"},
    {corpus_kind_t::external_contract, "external_contract"},
    {corpus_kind_t::recorded_trace, "recorded_trace"},
};

constexpr enum_name_t<corpus_availability_t> k_corpus_availability_names[] = {
    {corpus_availability_t::loaded, "loaded"},
    {corpus_availability_t::peer_loaded, "peer_loaded"},
    {corpus_availability_t::missing, "missing"},
    {corpus_availability_t::partial, "partial"},
    {corpus_availability_t::recorded_only, "recorded_only"},
};

constexpr enum_name_t<corpus_trust_t> k_corpus_trust_names[] = {
    {corpus_trust_t::ida_extracted, "ida_extracted"},
    {corpus_trust_t::recorded_dynamic, "recorded_dynamic"},
    {corpus_trust_t::user_declared, "user_declared"},
    {corpus_trust_t::imported_contract, "imported_contract"},
};

constexpr enum_name_t<address_kind_t> k_address_kind_names[] = {
    {address_kind_t::image_rva, "image_rva"},
    {address_kind_t::segment_offset, "segment_offset"},
    {address_kind_t::import_slot, "import_slot"},
    {address_kind_t::export_forwarder, "export_forwarder"},
    {address_kind_t::synthetic, "synthetic"},
    {address_kind_t::unknown, "unknown"},
};

constexpr enum_name_t<location_layer_t> k_location_layer_names[] = {
    {location_layer_t::raw, "raw"},
    {location_layer_t::ctree, "ctree"},
    {location_layer_t::microcode, "microcode"},
    {location_layer_t::type, "type"},
    {location_layer_t::xref, "xref"},
    {location_layer_t::dynamic, "dynamic"},
    {location_layer_t::declared, "declared"},
};

constexpr enum_name_t<location_confidence_t> k_location_confidence_names[] = {
    {location_confidence_t::exact, "exact"},
    {location_confidence_t::symbolic_exact, "symbolic_exact"},
    {location_confidence_t::weak_name, "weak_name"},
    {location_confidence_t::ambiguous, "ambiguous"},
    {location_confidence_t::unresolved, "unresolved"},
};

template <typename EnumT, std::size_t N>
const char* enum_to_string(EnumT value, const enum_name_t<EnumT> (&items)[N], const char* fallback)
{
    for (const auto& item : items)
    {
        if (item.value == value)
            return item.name;
    }
    return fallback;
}

template <typename EnumT, std::size_t N>
std::optional<EnumT> enum_from_string(const std::string& value, const enum_name_t<EnumT> (&items)[N])
{
    for (const auto& item : items)
    {
        if (value == item.name)
            return item.value;
    }
    return std::nullopt;
}

bool require_object(const nlohmann::json& value, validation_result_t& errors, const std::string& path)
{
    if (value.is_object())
        return true;
    errors.add("invalid_type", path, "expected object");
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

bool read_bool_field(const nlohmann::json& value,
                     const char* key,
                     bool& out,
                     validation_result_t& errors,
                     const std::string& path)
{
    auto it = value.find(key);
    if (it == value.end())
        return true;
    if (!it->is_boolean())
    {
        errors.add("invalid_type", path + "/" + key, "expected boolean");
        return false;
    }
    out = it->get<bool>();
    return true;
}

bool read_u64_field(const nlohmann::json& value,
                    const char* key,
                    std::uint64_t& out,
                    validation_result_t& errors,
                    const std::string& path)
{
    auto it = value.find(key);
    if (it == value.end())
        return true;
    if (!parse_u64_json(*it, out))
    {
        errors.add("invalid_integer", path + "/" + key, "expected unsigned integer or hex string");
        return false;
    }
    return true;
}

bool read_i32_field(const nlohmann::json& value,
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
        errors.add("invalid_integer", path + "/" + key, "expected integer");
        return false;
    }
    const auto integer = it->get<nlohmann::json::number_integer_t>();
    if (integer < (std::numeric_limits<int>::min)() || integer > (std::numeric_limits<int>::max)())
    {
        errors.add("integer_out_of_range", path + "/" + key, "value exceeds int32");
        return false;
    }
    out = static_cast<int>(integer);
    return true;
}

bool read_u32_field(const nlohmann::json& value,
                    const char* key,
                    std::uint32_t& out,
                    validation_result_t& errors,
                    const std::string& path)
{
    std::uint64_t tmp = out;
    if (!read_u64_field(value, key, tmp, errors, path))
        return false;
    if (tmp > 0xFFFFFFFFULL)
    {
        errors.add("integer_out_of_range", path + "/" + key, "value exceeds uint32");
        return false;
    }
    out = static_cast<std::uint32_t>(tmp);
    return true;
}

template <typename T>
bool read_enum_field(const nlohmann::json& value,
                     const char* key,
                     T& out,
                     std::optional<T> (*from_string_fn)(const std::string&),
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
        errors.add("invalid_type", path + "/" + key, "expected string enum");
        return false;
    }
    const std::string text = it->get<std::string>();
    auto parsed = from_string_fn(text);
    if (!parsed)
    {
        errors.add("invalid_enum", path + "/" + key, "invalid enum value '" + text + "'");
        return false;
    }
    out = *parsed;
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
                const std::string& path)
{
    auto it = value.find(key);
    if (it == value.end())
        return true;
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

bool read_segment_array_item(const nlohmann::json& value, segment_record_t& out, validation_result_t& errors, const std::string& path)
{
    return from_json(value, out, errors, path);
}

bool read_instance_array_item(const nlohmann::json& value, live_instance_metadata_t& out, validation_result_t& errors, const std::string& path)
{
    return from_json(value, out, errors, path);
}

std::string hex_lower_bytes(const unsigned char* bytes, std::size_t size)
{
    static const char k_hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(size * 2);
    for (std::size_t i = 0; i < size; ++i)
    {
        out.push_back(k_hex[bytes[i] >> 4]);
        out.push_back(k_hex[bytes[i] & 0x0F]);
    }
    return out;
}

std::string crc32_hex(std::uint32_t value)
{
    std::ostringstream ss;
    ss << std::hex << std::nouppercase << std::setfill('0') << std::setw(8) << value;
    return ss.str();
}

std::string path_basename(const std::string& path)
{
    const std::size_t pos = path.find_last_of("/\\");
    if (pos == std::string::npos)
        return path;
    return path.substr(pos + 1);
}

std::string lowercase_ascii(std::string value)
{
    for (char& c : value)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return value;
}

std::string segment_digest_for(const std::vector<segment_record_t>& segments)
{
    nlohmann::json j = nlohmann::json::array();
    for (const auto& s : segments)
    {
        j.push_back(nlohmann::json{
            {"name", s.name},
            {"class", s.segment_class},
            {"start_rva", s.start_rva},
            {"size", s.size},
            {"r", s.read},
            {"w", s.write},
            {"x", s.execute},
            {"type", s.type},
        });
    }
    return stable_id("segdigest", j);
}

normalize_address_result_t normalize_failure(const std::string& code, const std::string& path, const std::string& message)
{
    normalize_address_result_t out;
    out.ok = false;
    out.error.code = code;
    out.error.path = path;
    out.error.message = message;
    out.error.severity = validation_severity_t::error;
    out.error.acceptance_blocker = true;
    return out;
}

std::optional<segment_record_t> segment_for_ea(const corpus_record_t& corpus, std::uint64_t ea)
{
    for (const auto& s : corpus.segments)
    {
        if (ea >= s.start_ea && ea < s.end_ea)
            return s;
    }
    return std::nullopt;
}

}

const char* to_string(corpus_kind_t value)
{
    return enum_to_string(value, k_corpus_kind_names, "binary");
}

const char* to_string(corpus_availability_t value)
{
    return enum_to_string(value, k_corpus_availability_names, "missing");
}

const char* to_string(corpus_trust_t value)
{
    return enum_to_string(value, k_corpus_trust_names, "user_declared");
}

const char* to_string(address_kind_t value)
{
    return enum_to_string(value, k_address_kind_names, "unknown");
}

const char* to_string(location_layer_t value)
{
    return enum_to_string(value, k_location_layer_names, "raw");
}

const char* to_string(location_confidence_t value)
{
    return enum_to_string(value, k_location_confidence_names, "unresolved");
}

std::optional<corpus_kind_t> corpus_kind_from_string(const std::string& value)
{
    return enum_from_string(value, k_corpus_kind_names);
}

std::optional<corpus_availability_t> corpus_availability_from_string(const std::string& value)
{
    return enum_from_string(value, k_corpus_availability_names);
}

std::optional<corpus_trust_t> corpus_trust_from_string(const std::string& value)
{
    return enum_from_string(value, k_corpus_trust_names);
}

std::optional<address_kind_t> address_kind_from_string(const std::string& value)
{
    return enum_from_string(value, k_address_kind_names);
}

std::optional<location_layer_t> location_layer_from_string(const std::string& value)
{
    return enum_from_string(value, k_location_layer_names);
}

std::optional<location_confidence_t> location_confidence_from_string(const std::string& value)
{
    return enum_from_string(value, k_location_confidence_names);
}

nlohmann::json to_json(const hash_identity_t& value)
{
    return nlohmann::json{
        {"md5", value.md5},
        {"sha256", value.sha256},
        {"crc32", value.crc32},
        {"input_size", value.input_size},
    };
}

nlohmann::json to_json(const live_instance_metadata_t& value)
{
    return nlohmann::json{
        {"instance_id", value.instance_id},
        {"pid", value.pid},
        {"port", value.port},
        {"base_url", value.base_url},
        {"mcp_url", value.mcp_url},
        {"heartbeat_ms", value.heartbeat_ms},
        {"index_generation", value.index_generation},
        {"metadata", value.metadata},
    };
}

nlohmann::json to_json(const segment_record_t& value)
{
    return nlohmann::json{
        {"name", value.name},
        {"class", value.segment_class},
        {"start_ea", hex_u64(value.start_ea)},
        {"end_ea", hex_u64(value.end_ea)},
        {"start_rva", hex_u64(value.start_rva)},
        {"size", value.size},
        {"read", value.read},
        {"write", value.write},
        {"execute", value.execute},
        {"type", value.type},
    };
}

nlohmann::json to_json(const corpus_identity_t& value)
{
    return nlohmann::json{
        {"corpus_id", value.corpus_id},
        {"canonical_name", value.canonical_name},
        {"input_path", value.input_path},
        {"idb_path", value.idb_path},
        {"hashes", to_json(value.hashes)},
        {"image_base", hex_u64(value.image_base)},
        {"min_ea", hex_u64(value.min_ea)},
        {"max_ea", hex_u64(value.max_ea)},
        {"processor", value.processor},
        {"bitness", value.bitness},
        {"file_type", value.file_type},
        {"is_dll", value.is_dll},
        {"is_kernel", value.is_kernel},
        {"is_big_endian", value.is_big_endian},
        {"pdb_guid_age", value.pdb_guid_age},
        {"pdb_path", value.pdb_path},
        {"segment_digest", value.segment_digest},
        {"exportset_digest", value.exportset_digest},
        {"symbol_set_digest", value.symbol_set_digest},
    };
}

nlohmann::json to_json(const corpus_record_t& value)
{
    nlohmann::json j;
    j["kind"] = to_string(value.kind);
    j["availability"] = to_string(value.availability);
    j["trust"] = to_string(value.trust);
    j["identity"] = to_json(value.identity);
    j["segments"] = nlohmann::json::array();
    for (const auto& s : value.segments)
        j["segments"].push_back(to_json(s));
    j["live_instances"] = nlohmann::json::array();
    for (const auto& inst : value.live_instances)
        j["live_instances"].push_back(to_json(inst));
    j["loader_model"] = value.loader_model;
    j["metadata"] = value.metadata;
    return j;
}

nlohmann::json to_json(const canonical_address_t& value)
{
    return nlohmann::json{
        {"corpus_id", value.corpus_id},
        {"ea", hex_u64(value.ea)},
        {"rva", hex_u64(value.rva)},
        {"segment", value.segment},
        {"segment_start_rva", hex_u64(value.segment_start_rva)},
        {"segment_offset", hex_u64(value.segment_offset)},
        {"function_id", value.function_id},
        {"instruction_id", value.instruction_id},
        {"kind", to_string(value.kind)},
        {"layer", to_string(value.layer)},
        {"confidence", to_string(value.confidence)},
    };
}

nlohmann::json to_json(const normalize_address_result_t& value)
{
    return nlohmann::json{
        {"ok", value.ok},
        {"address", to_json(value.address)},
        {"error", to_json(value.error)},
    };
}

bool from_json(const nlohmann::json& value, hash_identity_t& out, validation_result_t& errors, const std::string& path)
{
    if (!require_object(value, errors, path))
        return false;
    no_unknown_fields(value, {"md5", "sha256", "crc32", "input_size"}, errors, path);
    bool ok = true;
    ok = read_string_field(value, "md5", out.md5, errors, path, false) && ok;
    ok = read_string_field(value, "sha256", out.sha256, errors, path, false) && ok;
    ok = read_string_field(value, "crc32", out.crc32, errors, path, false) && ok;
    ok = read_u64_field(value, "input_size", out.input_size, errors, path) && ok;
    return ok;
}

bool from_json(const nlohmann::json& value, live_instance_metadata_t& out, validation_result_t& errors, const std::string& path)
{
    if (!require_object(value, errors, path))
        return false;
    no_unknown_fields(value, {"instance_id", "pid", "port", "base_url", "mcp_url", "heartbeat_ms", "index_generation", "metadata"}, errors, path);
    bool ok = true;
    ok = read_string_field(value, "instance_id", out.instance_id, errors, path, false) && ok;
    ok = read_u64_field(value, "pid", out.pid, errors, path) && ok;
    ok = read_i32_field(value, "port", out.port, errors, path) && ok;
    ok = read_string_field(value, "base_url", out.base_url, errors, path, false) && ok;
    ok = read_string_field(value, "mcp_url", out.mcp_url, errors, path, false) && ok;
    ok = read_u64_field(value, "heartbeat_ms", out.heartbeat_ms, errors, path) && ok;
    ok = read_u64_field(value, "index_generation", out.index_generation, errors, path) && ok;
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
    return ok;
}

bool from_json(const nlohmann::json& value, segment_record_t& out, validation_result_t& errors, const std::string& path)
{
    if (!require_object(value, errors, path))
        return false;
    no_unknown_fields(value, {"name", "class", "start_ea", "end_ea", "start_rva", "size", "read", "write", "execute", "type"}, errors, path);
    bool ok = true;
    ok = read_string_field(value, "name", out.name, errors, path, false) && ok;
    ok = read_string_field(value, "class", out.segment_class, errors, path, false) && ok;
    ok = read_u64_field(value, "start_ea", out.start_ea, errors, path) && ok;
    ok = read_u64_field(value, "end_ea", out.end_ea, errors, path) && ok;
    ok = read_u64_field(value, "start_rva", out.start_rva, errors, path) && ok;
    ok = read_u64_field(value, "size", out.size, errors, path) && ok;
    ok = read_bool_field(value, "read", out.read, errors, path) && ok;
    ok = read_bool_field(value, "write", out.write, errors, path) && ok;
    ok = read_bool_field(value, "execute", out.execute, errors, path) && ok;
    ok = read_i32_field(value, "type", out.type, errors, path) && ok;
    if (out.end_ea < out.start_ea)
    {
        errors.add("invalid_address_range", path + "/end_ea", "segment end precedes start");
        ok = false;
    }
    if (out.size == 0 && out.end_ea >= out.start_ea)
        out.size = out.end_ea - out.start_ea;
    return ok;
}

bool from_json(const nlohmann::json& value, corpus_identity_t& out, validation_result_t& errors, const std::string& path)
{
    if (!require_object(value, errors, path))
        return false;
    no_unknown_fields(value, {"corpus_id", "canonical_name", "input_path", "idb_path", "hashes", "image_base", "min_ea", "max_ea", "processor", "bitness", "file_type", "is_dll", "is_kernel", "is_big_endian", "pdb_guid_age", "pdb_path", "segment_digest", "exportset_digest", "symbol_set_digest"}, errors, path);
    bool ok = true;
    ok = read_string_field(value, "corpus_id", out.corpus_id, errors, path, true) && ok;
    ok = read_string_field(value, "canonical_name", out.canonical_name, errors, path, false) && ok;
    ok = read_string_field(value, "input_path", out.input_path, errors, path, false) && ok;
    ok = read_string_field(value, "idb_path", out.idb_path, errors, path, false) && ok;
    auto hashes = value.find("hashes");
    if (hashes != value.end())
        ok = from_json(*hashes, out.hashes, errors, path + "/hashes") && ok;
    ok = read_u64_field(value, "image_base", out.image_base, errors, path) && ok;
    ok = read_u64_field(value, "min_ea", out.min_ea, errors, path) && ok;
    ok = read_u64_field(value, "max_ea", out.max_ea, errors, path) && ok;
    ok = read_string_field(value, "processor", out.processor, errors, path, false) && ok;
    ok = read_u32_field(value, "bitness", out.bitness, errors, path) && ok;
    ok = read_i32_field(value, "file_type", out.file_type, errors, path) && ok;
    ok = read_bool_field(value, "is_dll", out.is_dll, errors, path) && ok;
    ok = read_bool_field(value, "is_kernel", out.is_kernel, errors, path) && ok;
    ok = read_bool_field(value, "is_big_endian", out.is_big_endian, errors, path) && ok;
    ok = read_string_field(value, "pdb_guid_age", out.pdb_guid_age, errors, path, false) && ok;
    ok = read_string_field(value, "pdb_path", out.pdb_path, errors, path, false) && ok;
    ok = read_string_field(value, "segment_digest", out.segment_digest, errors, path, false) && ok;
    ok = read_string_field(value, "exportset_digest", out.exportset_digest, errors, path, false) && ok;
    ok = read_string_field(value, "symbol_set_digest", out.symbol_set_digest, errors, path, false) && ok;
    if (out.canonical_name.empty())
        out.canonical_name = canonical_name_from_path(out.input_path);
    if (out.corpus_id.empty())
        out.corpus_id = derive_module_id(out);
    return ok;
}

bool from_json(const nlohmann::json& value, corpus_record_t& out, validation_result_t& errors, const std::string& path)
{
    if (!require_object(value, errors, path))
        return false;
    no_unknown_fields(value, {"kind", "availability", "trust", "identity", "segments", "live_instances", "loader_model", "metadata"}, errors, path);
    bool ok = true;
    ok = read_enum_field(value, "kind", out.kind, corpus_kind_from_string, errors, path, false) && ok;
    ok = read_enum_field(value, "availability", out.availability, corpus_availability_from_string, errors, path, false) && ok;
    ok = read_enum_field(value, "trust", out.trust, corpus_trust_from_string, errors, path, false) && ok;
    auto identity = value.find("identity");
    if (identity == value.end())
    {
        errors.add("missing_required_field", path + "/identity", "field is required");
        ok = false;
    }
    else
    {
        ok = from_json(*identity, out.identity, errors, path + "/identity") && ok;
    }
    ok = read_array(value, "segments", out.segments, read_segment_array_item, errors, path) && ok;
    ok = read_array(value, "live_instances", out.live_instances, read_instance_array_item, errors, path) && ok;
    auto loader = value.find("loader_model");
    if (loader != value.end())
    {
        if (!loader->is_object())
        {
            errors.add("invalid_type", path + "/loader_model", "expected object");
            ok = false;
        }
        else
        {
            out.loader_model = *loader;
        }
    }
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
    if (out.identity.segment_digest.empty() && !out.segments.empty())
        out.identity.segment_digest = segment_digest_for(out.segments);
    if (out.identity.corpus_id.empty())
        out.identity.corpus_id = derive_module_id(out.identity);
    return ok;
}

bool from_json(const nlohmann::json& value, canonical_address_t& out, validation_result_t& errors, const std::string& path)
{
    if (!require_object(value, errors, path))
        return false;
    no_unknown_fields(value, {"corpus_id", "ea", "rva", "segment", "segment_start_rva", "segment_offset", "function_id", "instruction_id", "kind", "layer", "confidence"}, errors, path);
    bool ok = true;
    ok = read_string_field(value, "corpus_id", out.corpus_id, errors, path, true) && ok;
    ok = read_u64_field(value, "ea", out.ea, errors, path) && ok;
    ok = read_u64_field(value, "rva", out.rva, errors, path) && ok;
    ok = read_string_field(value, "segment", out.segment, errors, path, false) && ok;
    ok = read_u64_field(value, "segment_start_rva", out.segment_start_rva, errors, path) && ok;
    ok = read_u64_field(value, "segment_offset", out.segment_offset, errors, path) && ok;
    ok = read_string_field(value, "function_id", out.function_id, errors, path, false) && ok;
    ok = read_string_field(value, "instruction_id", out.instruction_id, errors, path, false) && ok;
    ok = read_enum_field(value, "kind", out.kind, address_kind_from_string, errors, path, false) && ok;
    ok = read_enum_field(value, "layer", out.layer, location_layer_from_string, errors, path, false) && ok;
    ok = read_enum_field(value, "confidence", out.confidence, location_confidence_from_string, errors, path, false) && ok;
    return ok;
}

corpus_record_t make_missing_corpus(const std::string& corpus_id,
                                    const std::string& canonical_name,
                                    const std::string& reason)
{
    corpus_record_t out;
    out.kind = corpus_kind_t::binary;
    out.availability = corpus_availability_t::missing;
    out.trust = corpus_trust_t::user_declared;
    out.identity.corpus_id = corpus_id.empty() ? normalize_id_component(canonical_name) : corpus_id;
    out.identity.canonical_name = canonical_name;
    out.metadata["missing_reason"] = reason;
    return out;
}

corpus_record_t snapshot_current_idb_corpus(const std::string& corpus_id_override)
{
    corpus_record_t out;
    out.kind = corpus_kind_t::binary;
    out.availability = corpus_availability_t::loaded;
    out.trust = corpus_trust_t::ida_extracted;
    char path_buf[QMAXPATH] = {};
    get_input_file_path(path_buf, sizeof(path_buf));
    out.identity.input_path = path_buf[0] ? std::string(path_buf) : std::string();
    const char* idb_path = get_path(PATH_TYPE_IDB);
    out.identity.idb_path = idb_path ? std::string(idb_path) : std::string();
    out.identity.canonical_name = canonical_name_from_path(out.identity.input_path);
    unsigned char md5[16] = {};
    if (retrieve_input_file_md5(md5))
        out.identity.hashes.md5 = hex_lower_bytes(md5, sizeof(md5));
    unsigned char sha[32] = {};
    if (retrieve_input_file_sha256(sha))
        out.identity.hashes.sha256 = hex_lower_bytes(sha, sizeof(sha));
    out.identity.hashes.crc32 = crc32_hex(retrieve_input_file_crc32());
    out.identity.image_base = static_cast<std::uint64_t>(get_imagebase());
    out.identity.min_ea = static_cast<std::uint64_t>(inf_get_min_ea());
    out.identity.max_ea = static_cast<std::uint64_t>(inf_get_max_ea());
    qstring proc = inf_get_procname();
    out.identity.processor = proc.c_str();
    out.identity.bitness = static_cast<std::uint32_t>(inf_get_app_bitness());
    out.identity.file_type = static_cast<int>(inf_get_filetype());
    out.identity.is_dll = inf_is_dll();
    out.identity.is_kernel = inf_is_kernel_mode();
    out.identity.is_big_endian = inf_is_be();
    for (int i = 0; i < get_segm_qty(); ++i)
    {
        segment_t* seg = getnseg(i);
        if (seg == nullptr || seg->end_ea <= seg->start_ea)
            continue;
        segment_record_t sr;
        qstring name;
        if (get_segm_name(&name, seg) > 0)
            sr.name = name.c_str();
        qstring cls;
        if (get_segm_class(&cls, seg) > 0)
            sr.segment_class = cls.c_str();
        sr.start_ea = static_cast<std::uint64_t>(seg->start_ea);
        sr.end_ea = static_cast<std::uint64_t>(seg->end_ea);
        sr.start_rva = sr.start_ea >= out.identity.image_base ? sr.start_ea - out.identity.image_base : 0;
        sr.size = sr.end_ea - sr.start_ea;
        sr.read = (seg->perm & SEGPERM_READ) != 0;
        sr.write = (seg->perm & SEGPERM_WRITE) != 0;
        sr.execute = (seg->perm & SEGPERM_EXEC) != 0;
        sr.type = segtype(seg->start_ea);
        out.segments.push_back(std::move(sr));
    }
    out.identity.segment_digest = segment_digest_for(out.segments);
    out.identity.corpus_id = corpus_id_override.empty() ? derive_module_id(out.identity) : corpus_id_override;
    out.loader_model["auto_analysis_ok"] = auto_is_ok();
    out.loader_model["segment_count"] = out.segments.size();
    out.loader_model["image_base"] = hex_u64(out.identity.image_base);
    return out;
}

std::string derive_module_id(const corpus_identity_t& identity)
{
    if (!identity.hashes.sha256.empty())
        return "sha256_" + normalize_id_component(identity.hashes.sha256);
    if (!identity.hashes.md5.empty())
        return "md5_" + normalize_id_component(identity.hashes.md5);
    nlohmann::json fallback;
    fallback["canonical_name"] = identity.canonical_name;
    fallback["crc32"] = identity.hashes.crc32;
    fallback["input_size"] = identity.hashes.input_size;
    fallback["image_base"] = identity.image_base;
    fallback["processor"] = identity.processor;
    fallback["bitness"] = identity.bitness;
    fallback["segment_digest"] = identity.segment_digest;
    return stable_id("module", fallback);
}

std::string canonical_name_from_path(const std::string& path)
{
    return lowercase_ascii(path_basename(path));
}

std::optional<const corpus_record_t*> find_corpus(const std::vector<corpus_record_t>& corpus, const std::string& corpus_id)
{
    for (const auto& c : corpus)
    {
        if (c.identity.corpus_id == corpus_id)
            return &c;
    }
    return std::nullopt;
}

std::optional<corpus_record_t*> find_corpus(std::vector<corpus_record_t>& corpus, const std::string& corpus_id)
{
    for (auto& c : corpus)
    {
        if (c.identity.corpus_id == corpus_id)
            return &c;
    }
    return std::nullopt;
}

normalize_address_result_t normalize_ea(const corpus_record_t& corpus,
                                        std::uint64_t ea,
                                        location_layer_t layer)
{
    if (corpus.identity.corpus_id.empty())
        return normalize_failure("invalid_corpus_identity", "/corpus/identity/corpus_id", "corpus id is empty");
    if (corpus.availability == corpus_availability_t::missing)
        return normalize_failure("missing_corpus", "/corpus/" + corpus.identity.corpus_id, "corpus is missing");
    if (ea < corpus.identity.min_ea || ea >= corpus.identity.max_ea)
        return normalize_failure("address_out_of_corpus", "/location/ea", "EA is outside corpus bounds");
    auto seg = segment_for_ea(corpus, ea);
    if (!seg)
        return normalize_failure("address_unmapped", "/location/ea", "EA is not covered by a corpus segment");
    normalize_address_result_t out;
    out.ok = true;
    out.address.corpus_id = corpus.identity.corpus_id;
    out.address.ea = ea;
    out.address.rva = ea >= corpus.identity.image_base ? ea - corpus.identity.image_base : seg->start_rva + (ea - seg->start_ea);
    out.address.segment = seg->name;
    out.address.segment_start_rva = seg->start_rva;
    out.address.segment_offset = ea - seg->start_ea;
    out.address.kind = ea >= corpus.identity.image_base ? address_kind_t::image_rva : address_kind_t::segment_offset;
    out.address.layer = layer;
    out.address.confidence = location_confidence_t::exact;
    out.address.instruction_id = corpus.identity.corpus_id + ":" + hex_u64(out.address.rva);
    return out;
}

normalize_address_result_t normalize_rva(const corpus_record_t& corpus,
                                         std::uint64_t rva,
                                         location_layer_t layer)
{
    if (corpus.identity.image_base == 0)
        return normalize_failure("invalid_image_base", "/corpus/identity/image_base", "image base is unavailable");
    return normalize_ea(corpus, corpus.identity.image_base + rva, layer);
}

bool corpus_blocks_confirmation(const corpus_record_t& corpus)
{
    return corpus.availability != corpus_availability_t::loaded
        && corpus.availability != corpus_availability_t::peer_loaded
        && corpus.availability != corpus_availability_t::recorded_only;
}

validation_result_t validate_corpus_records(const std::vector<corpus_record_t>& corpus)
{
    validation_result_t result;
    std::unordered_set<std::string> ids;
    std::unordered_set<std::string> binding_keys;
    for (std::size_t i = 0; i < corpus.size(); ++i)
    {
        const auto& c = corpus[i];
        const std::string base_path = "/corpus/" + std::to_string(i);
        if (c.identity.corpus_id.empty())
            result.add("missing_required_field", base_path + "/identity/corpus_id", "corpus id is required");
        else if (!ids.insert(c.identity.corpus_id).second)
            result.add("duplicate_id", base_path + "/identity/corpus_id", "duplicate corpus id");
        if (c.identity.canonical_name.empty() && c.identity.input_path.empty() && c.identity.hashes.sha256.empty() && c.identity.hashes.md5.empty())
            result.add("ambiguous_corpus_binding", base_path + "/identity", "corpus requires a name, path, or hash");
        const std::string bind_key = c.identity.canonical_name + "|" + c.identity.hashes.sha256 + "|" + c.identity.hashes.md5 + "|" + c.identity.segment_digest;
        if (!bind_key.empty() && !binding_keys.insert(bind_key).second)
            result.add("ambiguous_corpus_binding", base_path + "/identity", "duplicate corpus binding");
        if (c.availability == corpus_availability_t::loaded && c.segments.empty() && c.kind == corpus_kind_t::binary)
            result.add("partial_corpus", base_path + "/segments", "loaded binary corpus has no segment map");
        if (c.availability == corpus_availability_t::missing)
            result.add("missing_corpus", base_path + "/availability", "missing corpus blocks confirmation");
    }
    return result;
}

}
}
}
