#include "chain_store.hpp"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <utility>

#include <diskio.hpp>
#include <netnode.hpp>
#include <pro.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace aida
{
namespace vuln
{
namespace chain
{

namespace
{

constexpr const char* k_chain_ledger_node = "$ AiDA.chain.ledger.v2";
constexpr nodeidx_t k_chain_ledger_blob_start = 1;
constexpr uchar k_chain_ledger_blob_tag = 'C';
constexpr std::size_t k_chain_ledger_page_size = 512 * 1024;
constexpr nodeidx_t k_chain_ledger_max_pages = 256;
constexpr std::uint64_t k_chain_store_max_json_bytes = 64ULL * 1024ULL * 1024ULL;

std::string join_path(const std::string& a, const std::string& b)
{
    if (a.empty())
        return b;
    if (a.back() == '/' || a.back() == '\\')
        return a + b;
    return a + "/" + b;
}

bool ensure_dir_recursive(const std::string& path)
{
    if (path.empty())
        return false;
    if (qisdir(path.c_str()))
        return true;
    const std::size_t sep = path.find_last_of("/\\");
    if (sep != std::string::npos && sep > 0)
    {
        const std::string parent = path.substr(0, sep);
        if (!ensure_dir_recursive(parent))
            return false;
    }
    const int rc = qmkdir(path.c_str(), 0755);
    return rc == 0 || qisdir(path.c_str());
}

bool write_text_atomic(const std::string& path, const std::string& text)
{
    const std::size_t sep = path.find_last_of("/\\");
    if (sep != std::string::npos && sep > 0)
    {
        if (!ensure_dir_recursive(path.substr(0, sep)))
            return false;
    }
    const std::string tmp = path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out.is_open())
            return false;
        out.write(text.data(), static_cast<std::streamsize>(text.size()));
        if (!out.good())
            return false;
    }
#ifdef _WIN32
    if (MoveFileExA(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0)
        return true;
    DeleteFileA(tmp.c_str());
    return false;
#else
    if (std::rename(tmp.c_str(), path.c_str()) == 0)
        return true;
    std::remove(tmp.c_str());
    return false;
#endif
}

bool read_text_limited(const std::string& path, std::string& out, validation_result_t& validation)
{
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in.is_open())
    {
        validation.add("store_not_found", "/path", "file not found: " + path);
        return false;
    }
    const std::streamoff size = in.tellg();
    if (size < 0 || static_cast<std::uint64_t>(size) > k_chain_store_max_json_bytes)
    {
        validation.add("resource_exhausted", "/path", "file exceeds chain store size limit: " + path);
        return false;
    }
    in.seekg(0, std::ios::beg);
    out.assign(static_cast<std::size_t>(size), '\0');
    if (!out.empty())
        in.read(&out[0], static_cast<std::streamsize>(out.size()));
    if (!in.good() && !in.eof())
    {
        validation.add("store_read_failed", "/path", "failed to read file: " + path);
        return false;
    }
    return true;
}

std::string chain_document_path(const std::string& project_id, const std::string& chain_id)
{
    return join_path(join_path(chain_project_root(project_id), "chains"), sanitize_store_component(chain_id) + ".json");
}

std::string chain_report_path(const std::string& project_id, const std::string& report_id)
{
    return join_path(join_path(chain_project_root(project_id), "reports"), sanitize_store_component(report_id) + ".json");
}

std::string chain_job_record_root(const std::string& project_id)
{
    const std::string root = join_path(chain_project_root(project_id), "jobs");
    ensure_dir_recursive(root);
    return root;
}

std::string chain_report_record_root(const std::string& project_id)
{
    const std::string root = join_path(chain_project_root(project_id), "report_records");
    ensure_dir_recursive(root);
    return root;
}

std::string chain_job_record_path(const std::string& project_id, const std::string& job_id)
{
    return join_path(chain_job_record_root(project_id), sanitize_store_component(job_id) + ".json");
}

std::string chain_report_record_path(const std::string& project_id, const std::string& report_id)
{
    return join_path(chain_report_record_root(project_id), sanitize_store_component(report_id) + ".json");
}

chain_store_status_t save_json_record(const std::string& action, const std::string& path, const nlohmann::json& record)
{
    chain_store_status_t status;
    status.action = action;
    status.path = path;
    if (!record.is_object())
    {
        status.validation.add("invalid_type", "/record", "record must be an object");
        return status;
    }
    const std::string text = record.dump(2) + "\n";
    status.bytes = text.size();
    status.ok = write_text_atomic(status.path, text);
    if (!status.ok)
        status.validation.add("store_write_failed", "/path", "failed to write json record");
    return status;
}

chain_json_record_load_result_t load_json_record(const std::string& action, const std::string& path)
{
    chain_json_record_load_result_t result;
    result.action = action;
    result.path = path;
    std::string text;
    if (!read_text_limited(result.path, text, result.validation))
        return result;
    try
    {
        result.record = nlohmann::json::parse(text);
    }
    catch (const std::exception& e)
    {
        result.validation.add("corrupt_store", "/json", e.what());
        return result;
    }
    if (!result.record.is_object())
        result.validation.add("invalid_type", "/record", "record must be an object");
    result.ok = result.validation.ok();
    return result;
}

chain_json_record_list_result_t list_json_records(const std::string& action, const std::string& root)
{
    chain_json_record_list_result_t result;
    result.action = action;
    result.path = root;
    ensure_dir_recursive(root);
    std::error_code ec;
    std::vector<std::filesystem::path> files;
    for (const auto& entry : std::filesystem::directory_iterator(std::filesystem::path(root), ec))
    {
        if (ec)
            break;
        if (entry.is_regular_file(ec) && entry.path().extension() == ".json")
            files.push_back(entry.path());
    }
    if (ec)
    {
        result.validation.add("store_list_failed", "/path", ec.message());
        return result;
    }
    std::sort(files.begin(), files.end());
    for (const auto& file : files)
    {
        chain_json_record_load_result_t loaded = load_json_record(action + "_load_item", file.string());
        if (!loaded.ok)
        {
            result.validation.errors.insert(result.validation.errors.end(), loaded.validation.errors.begin(), loaded.validation.errors.end());
            continue;
        }
        result.bytes += static_cast<std::uint64_t>(loaded.record.dump().size());
        result.records.push_back(std::move(loaded.record));
    }
    result.ok = result.validation.ok();
    return result;
}

chain_store_status_t delete_json_record(const std::string& action, const std::string& path)
{
    chain_store_status_t status;
    status.action = action;
    status.path = path;
    std::error_code ec;
    if (!std::filesystem::exists(std::filesystem::path(path), ec))
    {
        status.ok = !ec;
        if (ec)
            status.validation.add("store_delete_failed", "/path", ec.message());
        return status;
    }
    status.ok = std::filesystem::remove(std::filesystem::path(path), ec);
    if (!status.ok)
        status.validation.add("store_delete_failed", "/path", ec ? ec.message() : std::string("failed to remove record"));
    return status;
}

chain_report_t parse_report_shallow(const nlohmann::json& raw, validation_result_t& validation)
{
    chain_report_t report;
    if (!raw.is_object())
    {
        validation.add("invalid_report_schema", "", "report must be an object");
        return report;
    }
    const std::string schema = raw.value("schema", std::string());
    if (schema != k_chain_report_schema)
        validation.add("invalid_report_schema", "/schema", "report schema mismatch");
    report.schema = schema;
    report.version = raw.value("version", k_chain_report_version);
    report.report_id = raw.value("report_id", std::string());
    report.chain_id = raw.value("chain_id", std::string());
    report.job_id = raw.value("job_id", std::string());
    if (auto v = chain_verdict_from_string(raw.value("verdict", std::string("inconclusive"))))
        report.verdict = *v;
    else
        validation.add("invalid_enum", "/verdict", "invalid report verdict");
    if (auto a = report_acceptance_from_string(raw.value("acceptance", std::string("blocked"))))
        report.acceptance = *a;
    else
        validation.add("invalid_enum", "/acceptance", "invalid report acceptance");
    if (auto c = confidence_policy_from_string(raw.value("confidence", std::string("strict_proof_only"))))
        report.confidence = *c;
    else
        validation.add("invalid_enum", "/confidence", "invalid confidence policy");
    if (auto p = proof_level_from_string(raw.value("proof_level_reached", std::string("p0_schema"))))
        report.proof_level_reached = *p;
    else
        validation.add("invalid_enum", "/proof_level_reached", "invalid proof level");
    report.summary = raw.value("summary", std::string());
    report.trace_manifest = raw.value("trace_manifest", nlohmann::json::object());
    report.fact_manifest = raw.value("fact_manifest", nlohmann::json::object());
    report.solver_manifest = raw.value("solver_manifest", nlohmann::json::object());
    report.resource_manifest = raw.value("resource_manifest", nlohmann::json::object());
    report.generation_manifest = raw.value("generation_manifest", nlohmann::json::object());
    report.budget_manifest = raw.value("budget_manifest", nlohmann::json::object());
    report.diagnostics = raw.value("diagnostics", nlohmann::json::object());
    validation_result_t acceptance_validation = validate_chain_report(report);
    validation.errors.insert(validation.errors.end(), acceptance_validation.errors.begin(), acceptance_validation.errors.end());
    return report;
}

std::vector<std::uint8_t> load_ledger_blob(validation_result_t& validation)
{
    std::vector<std::uint8_t> packed;
    netnode nn(k_chain_ledger_node, 0, false);
    if (nn == BADNODE)
        return packed;
    for (nodeidx_t page = 0; page < k_chain_ledger_max_pages; ++page)
    {
        size_t size = nn.blobsize(k_chain_ledger_blob_start + page, k_chain_ledger_blob_tag);
        if (size == 0)
            break;
        void* blob = nn.getblob(nullptr, &size, k_chain_ledger_blob_start + page, k_chain_ledger_blob_tag);
        if (blob == nullptr)
        {
            validation.add("store_read_failed", "/ledger", "failed to read ledger page");
            break;
        }
        const std::unique_ptr<void, decltype(&qfree)> blob_guard(blob, &qfree);
        const auto* bytes = static_cast<const std::uint8_t*>(blob_guard.get());
        packed.insert(packed.end(), bytes, bytes + size);
    }
    return packed;
}

bool write_ledger_blob(const std::vector<std::uint8_t>& packed, chain_ledger_result_t& result)
{
    netnode nn(k_chain_ledger_node, 0, true);
    if (nn == BADNODE)
    {
        result.validation.add("store_write_failed", "/ledger", "failed to open ledger netnode");
        return false;
    }
    for (nodeidx_t page = 0; page < k_chain_ledger_max_pages; ++page)
        nn.delblob(k_chain_ledger_blob_start + page, k_chain_ledger_blob_tag);
    std::size_t offset = 0;
    nodeidx_t page = 0;
    while (offset < packed.size())
    {
        if (page >= k_chain_ledger_max_pages)
        {
            result.validation.add("resource_exhausted", "/ledger", "ledger exceeds page limit");
            return false;
        }
        const std::size_t chunk = (std::min)(k_chain_ledger_page_size, packed.size() - offset);
        if (!nn.setblob(packed.data() + offset, chunk, k_chain_ledger_blob_start + page, k_chain_ledger_blob_tag))
        {
            result.validation.add("store_write_failed", "/ledger", "failed to write ledger page");
            return false;
        }
        offset += chunk;
        ++page;
    }
    result.pages = page;
    result.bytes = packed.size();
    return true;
}

}

nlohmann::json to_json(const chain_store_status_t& value)
{
    return nlohmann::json{
        {"ok", value.ok},
        {"action", value.action},
        {"path", value.path},
        {"bytes", value.bytes},
        {"migrated", value.migrated},
        {"validation", to_json(value.validation)},
    };
}

nlohmann::json to_json(const chain_document_load_result_t& value)
{
    return nlohmann::json{
        {"ok", value.ok},
        {"migrated", value.migrated},
        {"path", value.path},
        {"document", value.ok ? to_json(value.document) : nlohmann::json::object()},
        {"validation", to_json(value.validation)},
    };
}

nlohmann::json to_json(const chain_report_load_result_t& value)
{
    return nlohmann::json{
        {"ok", value.ok},
        {"path", value.path},
        {"report", value.ok ? to_json(value.report) : nlohmann::json::object()},
        {"validation", to_json(value.validation)},
    };
}

nlohmann::json to_json(const chain_ledger_record_t& value)
{
    return nlohmann::json{
        {"record_id", value.record_id},
        {"chain_id", value.chain_id},
        {"report_id", value.report_id},
        {"document_id", value.document_id},
        {"verdict", to_string(value.verdict)},
        {"acceptance", to_string(value.acceptance)},
        {"updated_at_ms", value.updated_at_ms},
        {"summary", value.summary},
    };
}

nlohmann::json to_json(const chain_ledger_result_t& value)
{
    nlohmann::json records = nlohmann::json::array();
    for (const auto& record : value.records)
        records.push_back(to_json(record));
    return nlohmann::json{
        {"ok", value.ok},
        {"action", value.action},
        {"bytes", value.bytes},
        {"pages", value.pages},
        {"records", std::move(records)},
        {"validation", to_json(value.validation)},
    };
}

nlohmann::json to_json(const chain_json_record_load_result_t& value)
{
    return nlohmann::json{
        {"ok", value.ok},
        {"action", value.action},
        {"path", value.path},
        {"record", value.ok ? value.record : nlohmann::json::object()},
        {"validation", to_json(value.validation)},
    };
}

nlohmann::json to_json(const chain_json_record_list_result_t& value)
{
    nlohmann::json records = nlohmann::json::array();
    for (const auto& record : value.records)
        records.push_back(record);
    return nlohmann::json{
        {"ok", value.ok},
        {"action", value.action},
        {"path", value.path},
        {"bytes", value.bytes},
        {"records", std::move(records)},
        {"validation", to_json(value.validation)},
    };
}

bool from_json(const nlohmann::json& value, chain_ledger_record_t& out, validation_result_t& errors, const std::string& path)
{
    if (!value.is_object())
    {
        errors.add("invalid_type", path, "expected object");
        return false;
    }
    out.record_id = value.value("record_id", std::string());
    out.chain_id = value.value("chain_id", std::string());
    out.report_id = value.value("report_id", std::string());
    out.document_id = value.value("document_id", std::string());
    if (auto v = chain_verdict_from_string(value.value("verdict", std::string("inconclusive"))))
        out.verdict = *v;
    else
        errors.add("invalid_enum", path + "/verdict", "invalid verdict");
    if (auto a = report_acceptance_from_string(value.value("acceptance", std::string("blocked"))))
        out.acceptance = *a;
    else
        errors.add("invalid_enum", path + "/acceptance", "invalid acceptance");
    if (value.contains("updated_at_ms") && !parse_u64_json(value["updated_at_ms"], out.updated_at_ms))
        errors.add("invalid_integer", path + "/updated_at_ms", "invalid timestamp");
    out.summary = value.value("summary", nlohmann::json::object());
    if (out.record_id.empty())
        out.record_id = stable_id("ledger", value);
    return errors.ok();
}

std::string chain_store_root()
{
    const char* user_dir = get_user_idadir();
    std::string root = user_dir ? std::string(user_dir) : std::string(".");
    root = join_path(root, "aida_projects");
    ensure_dir_recursive(root);
    return root;
}

std::string chain_project_root(const std::string& project_id)
{
    const std::string safe_project = sanitize_store_component(project_id.empty() ? "default" : project_id);
    const std::string root = join_path(chain_store_root(), safe_project);
    ensure_dir_recursive(root);
    ensure_dir_recursive(join_path(root, "chains"));
    ensure_dir_recursive(join_path(root, "reports"));
    ensure_dir_recursive(join_path(root, "traces"));
    ensure_dir_recursive(join_path(root, "resources"));
    ensure_dir_recursive(join_path(root, "jobs"));
    ensure_dir_recursive(join_path(root, "report_records"));
    return root;
}

std::string sanitize_store_component(const std::string& value)
{
    std::string out = normalize_id_component(value);
    if (out.size() > 96)
        out.resize(96);
    return out.empty() ? std::string("default") : out;
}

chain_store_status_t save_chain_document(const std::string& project_id, const chain_document_t& document)
{
    chain_store_status_t status;
    status.action = "save_chain_document";
    status.path = chain_document_path(project_id, document.chain_id);
    status.validation = validate_chain_document(document);
    if (!status.validation.ok())
        return status;
    const std::string text = to_json(document).dump(2) + "\n";
    status.bytes = text.size();
    status.ok = write_text_atomic(status.path, text);
    if (!status.ok)
        status.validation.add("store_write_failed", "/path", "failed to write chain document");
    return status;
}

chain_document_load_result_t load_chain_document(const std::string& project_id, const std::string& chain_id)
{
    chain_document_load_result_t result;
    result.path = chain_document_path(project_id, chain_id);
    std::string text;
    if (!read_text_limited(result.path, text, result.validation))
        return result;
    try
    {
        result.raw = nlohmann::json::parse(text);
    }
    catch (const std::exception& e)
    {
        result.validation.add("corrupt_store", "/json", e.what());
        return result;
    }
    parse_chain_document_result_t parsed = parse_chain_document(result.raw);
    result.validation.errors.insert(result.validation.errors.end(), parsed.validation.errors.begin(), parsed.validation.errors.end());
    result.ok = parsed.ok;
    result.migrated = parsed.migrated;
    result.document = std::move(parsed.document);
    return result;
}

chain_store_status_t save_chain_report(const std::string& project_id, const chain_report_t& report)
{
    chain_store_status_t status;
    status.action = "save_chain_report";
    status.path = chain_report_path(project_id, report.report_id);
    status.validation = validate_chain_report(report);
    if (!status.validation.ok())
        return status;
    const std::string text = report_machine_export(report).dump(2) + "\n";
    status.bytes = text.size();
    status.ok = write_text_atomic(status.path, text);
    if (!status.ok)
        status.validation.add("store_write_failed", "/path", "failed to write chain report");
    return status;
}

chain_report_load_result_t load_chain_report(const std::string& project_id, const std::string& report_id)
{
    chain_report_load_result_t result;
    result.path = chain_report_path(project_id, report_id);
    std::string text;
    if (!read_text_limited(result.path, text, result.validation))
        return result;
    try
    {
        result.raw = nlohmann::json::parse(text);
    }
    catch (const std::exception& e)
    {
        result.validation.add("corrupt_store", "/json", e.what());
        return result;
    }
    result.report = parse_report_shallow(result.raw, result.validation);
    result.ok = result.validation.ok();
    return result;
}

chain_store_status_t save_chain_job_record(const std::string& project_id, const std::string& job_id, const nlohmann::json& record)
{
    return save_json_record("save_chain_job_record", chain_job_record_path(project_id, job_id), record);
}

chain_json_record_load_result_t load_chain_job_record(const std::string& project_id, const std::string& job_id)
{
    return load_json_record("load_chain_job_record", chain_job_record_path(project_id, job_id));
}

chain_json_record_list_result_t list_chain_job_records(const std::string& project_id)
{
    return list_json_records("list_chain_job_records", chain_job_record_root(project_id));
}

chain_store_status_t delete_chain_job_record(const std::string& project_id, const std::string& job_id)
{
    return delete_json_record("delete_chain_job_record", chain_job_record_path(project_id, job_id));
}

chain_store_status_t save_chain_report_record(const std::string& project_id, const std::string& report_id, const nlohmann::json& record)
{
    return save_json_record("save_chain_report_record", chain_report_record_path(project_id, report_id), record);
}

chain_json_record_load_result_t load_chain_report_record(const std::string& project_id, const std::string& report_id)
{
    return load_json_record("load_chain_report_record", chain_report_record_path(project_id, report_id));
}

chain_json_record_list_result_t list_chain_report_records(const std::string& project_id)
{
    return list_json_records("list_chain_report_records", chain_report_record_root(project_id));
}

chain_store_status_t delete_chain_report_record(const std::string& project_id, const std::string& report_id)
{
    return delete_json_record("delete_chain_report_record", chain_report_record_path(project_id, report_id));
}

chain_ledger_record_t ledger_record_from_report(const chain_report_t& report)
{
    chain_ledger_record_t record;
    record.chain_id = report.chain_id;
    record.report_id = report.report_id;
    record.document_id = report.generation_manifest.value("document_id", std::string());
    record.verdict = report.verdict;
    record.acceptance = report.acceptance;
    record.updated_at_ms = now_ms();
    record.summary = nlohmann::json{
        {"summary", report.summary},
        {"proof_level_reached", to_string(report.proof_level_reached)},
        {"first_failure", to_json(report.first_failure)},
    };
    record.record_id = stable_id("ledger", nlohmann::json{{"chain_id", record.chain_id}, {"report_id", record.report_id}});
    return record;
}

chain_ledger_result_t chain_ledger_save(const chain_ledger_record_t& record)
{
    chain_ledger_result_t result = chain_ledger_load();
    result.action = "save";
    if (!result.validation.ok())
        return result;
    bool replaced = false;
    for (auto& existing : result.records)
    {
        if (existing.record_id == record.record_id)
        {
            existing = record;
            replaced = true;
            break;
        }
    }
    if (!replaced)
        result.records.push_back(record);
    nlohmann::json root;
    root["schema"] = "aida_chain_ledger_v2";
    root["version"] = 2;
    root["updated_at_ms"] = now_ms();
    root["records"] = nlohmann::json::array();
    for (const auto& item : result.records)
        root["records"].push_back(to_json(item));
    std::vector<std::uint8_t> packed = nlohmann::json::to_msgpack(root);
    result.ok = write_ledger_blob(packed, result);
    return result;
}

chain_ledger_result_t chain_ledger_load()
{
    chain_ledger_result_t result;
    result.action = "load";
    std::vector<std::uint8_t> packed = load_ledger_blob(result.validation);
    result.bytes = packed.size();
    if (!result.validation.ok())
        return result;
    if (packed.empty())
    {
        result.ok = true;
        return result;
    }
    nlohmann::json root = nlohmann::json::from_msgpack(packed, true, false);
    if (root.is_discarded() || !root.is_object())
    {
        result.validation.add("corrupt_store", "/ledger", "ledger msgpack is corrupt");
        return result;
    }
    if (root.value("schema", std::string()) != "aida_chain_ledger_v2")
    {
        result.validation.add("unsupported_version", "/ledger/schema", "unsupported ledger schema");
        return result;
    }
    if (!root.contains("records") || !root["records"].is_array())
    {
        result.validation.add("corrupt_store", "/ledger/records", "ledger records array missing");
        return result;
    }
    for (std::size_t i = 0; i < root["records"].size(); ++i)
    {
        chain_ledger_record_t record;
        from_json(root["records"][i], record, result.validation, "/ledger/records/" + std::to_string(i));
        if (result.validation.ok())
            result.records.push_back(std::move(record));
    }
    result.ok = result.validation.ok();
    return result;
}

chain_ledger_result_t chain_ledger_clear()
{
    chain_ledger_result_t result;
    result.action = "clear";
    netnode nn(k_chain_ledger_node, 0, false);
    if (nn != BADNODE)
        nn.kill();
    result.ok = true;
    return result;
}

validation_result_t chain_store_self_check()
{
    validation_result_t result;
    chain_report_t report;
    report.chain_id = "store_self_check";
    report.report_id = "store_report_self_check";
    report.verdict = chain_verdict_t::confirmed;
    report.acceptance = report_acceptance_t::accepted;
    chain_ledger_record_t record = ledger_record_from_report(report);
    if (record.record_id.empty() || record.chain_id != report.chain_id)
        result.add("self_check_failed", "/ledger_record", "ledger record generation failed");
    const std::string component = sanitize_store_component("A:B/../C");
    if (component.find('/') != std::string::npos || component.find('\\') != std::string::npos || component.find(':') != std::string::npos)
        result.add("self_check_failed", "/path", "store path component was not sanitized");
    return result;
}

}
}
}
