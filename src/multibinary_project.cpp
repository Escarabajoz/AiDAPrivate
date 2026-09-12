#include "multibinary_project.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

#include <auto.hpp>
#include <diskio.hpp>
#include <entry.hpp>
#include <funcs.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <nalt.hpp>
#include <prodir.h>
#include <segment.hpp>

#ifdef _WIN32
#include <windows.h>
#else
#include <signal.h>
#include <unistd.h>
#endif

namespace aida
{
namespace multibinary
{
namespace
{

using json = nlohmann::json;

std::string path_join(const std::string& left, const std::string& right)
{
    if (left.empty())
        return right;
    if (right.empty())
        return left;
    const char last = left.back();
    if (last == '/' || last == '\\')
        return left + right;
#ifdef _WIN32
    return left + "\\" + right;
#else
    return left + "/" + right;
#endif
}

std::string dirname_of(const std::string& path)
{
    const size_t pos = path.find_last_of("/\\");
    if (pos == std::string::npos)
        return std::string();
    return path.substr(0, pos);
}

bool ensure_dir_recursive_local(const std::string& dir)
{
    if (dir.empty())
        return false;
    if (qisdir(dir.c_str()))
        return true;
    const std::string parent = dirname_of(dir);
    if (!parent.empty() && parent != dir && !qisdir(parent.c_str()))
    {
        if (!ensure_dir_recursive_local(parent))
            return false;
    }
    return qmkdir(dir.c_str(), 0755) == 0 || qisdir(dir.c_str());
}

bool read_json_file(const std::string& path, json& out, std::string* error)
{
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open())
    {
        if (error != nullptr)
            *error = "open_failed";
        return false;
    }
    try
    {
        in >> out;
        return true;
    }
    catch (const std::exception& ex)
    {
        if (error != nullptr)
            *error = ex.what();
        return false;
    }
}

bool write_json_file(const std::string& path, const json& value, std::string* error)
{
    const std::string dir = dirname_of(path);
    if (!dir.empty() && !ensure_dir_recursive_local(dir))
    {
        if (error != nullptr)
            *error = "mkdir_failed";
        return false;
    }
    const std::string tmp = path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out.is_open())
        {
            if (error != nullptr)
                *error = "open_tmp_failed";
            return false;
        }
        out << value.dump(2);
        out << '\n';
        if (!out.good())
        {
            if (error != nullptr)
                *error = "write_failed";
            return false;
        }
    }
    std::error_code ec;
    std::filesystem::rename(tmp, path, ec);
    if (ec)
    {
        std::filesystem::remove(path, ec);
        ec.clear();
        std::filesystem::rename(tmp, path, ec);
    }
    if (ec)
    {
        if (error != nullptr)
            *error = ec.message();
        std::filesystem::remove(tmp, ec);
        return false;
    }
    return true;
}

std::uint64_t current_pid()
{
#ifdef _WIN32
    return static_cast<std::uint64_t>(GetCurrentProcessId());
#else
    return static_cast<std::uint64_t>(getpid());
#endif
}

bool pid_alive(std::uint64_t pid)
{
    if (pid == 0)
        return false;
    if (pid == current_pid())
        return true;
#ifdef _WIN32
    if (pid > static_cast<std::uint64_t>((std::numeric_limits<DWORD>::max)()))
        return false;
    HANDLE h = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (h == nullptr)
        return false;
    DWORD rc = WaitForSingleObject(h, 0);
    CloseHandle(h);
    return rc == WAIT_TIMEOUT;
#else
    if (pid > static_cast<std::uint64_t>((std::numeric_limits<pid_t>::max)()))
        return false;
    return kill(static_cast<pid_t>(pid), 0) == 0;
#endif
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

std::string basename_of(const std::string& path)
{
    const size_t pos = path.find_last_of("/\\");
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

std::uint64_t parse_u64_loose(const json& value)
{
    if (value.is_number_unsigned())
        return value.get<std::uint64_t>();
    if (value.is_number_integer())
        return static_cast<std::uint64_t>(value.get<std::int64_t>());
    if (!value.is_string())
        return 0;
    const std::string s = value.get<std::string>();
    char* endp = nullptr;
#ifdef _WIN32
    unsigned long long parsed = _strtoui64(s.c_str(), &endp, 0);
#else
    unsigned long long parsed = std::strtoull(s.c_str(), &endp, 0);
#endif
    if (endp == s.c_str())
        return 0;
    return static_cast<std::uint64_t>(parsed);
}

std::string hex_u64(std::uint64_t value)
{
    std::ostringstream ss;
    ss << "0x" << std::hex << std::nouppercase << value;
    return ss.str();
}

std::string module_name_from_json(const json& module)
{
    if (module.contains("identity") && module["identity"].is_object())
    {
        const json& id = module["identity"];
        std::string name = id.value("canonical_name", std::string());
        if (!name.empty())
            return lowercase_ascii(name);
        name = id.value("input_path", std::string());
        if (!name.empty())
            return lowercase_ascii(basename_of(name));
    }
    std::string name = module.value("canonical_name", module.value("input_basename", module.value("module_name", std::string())));
    if (name.empty())
        name = basename_of(module.value("input_file", module.value("input_path", std::string())));
    return lowercase_ascii(name);
}

json module_identity_object(const json& module)
{
    if (module.contains("identity") && module["identity"].is_object())
        return module["identity"];
    if (module.contains("module") && module["module"].is_object())
        return module["module"];
    return module;
}

json current_instance_json()
{
    json i;
    i["instance_id"] = nullptr;
    i["pid"] = current_pid();
    const char* idb = get_path(PATH_TYPE_IDB);
    i["idb_path"] = idb != nullptr ? std::string(idb) : std::string();
    char path[QMAXPATH] = {};
    get_input_file_path(path, sizeof(path));
    i["input_file"] = path[0] ? std::string(path) : std::string();
    i["input_basename"] = basename_of(i.value("input_file", std::string()));
    uchar md5[16] = {};
    if (retrieve_input_file_md5(md5))
    {
        static const char h[] = "0123456789abcdef";
        std::string s;
        s.reserve(32);
        for (uchar b : md5)
        {
            s.push_back(h[b >> 4]);
            s.push_back(h[b & 0xf]);
        }
        i["file_md5"] = s;
    }
    uchar sha[32] = {};
    if (retrieve_input_file_sha256(sha))
    {
        static const char h[] = "0123456789abcdef";
        std::string s;
        s.reserve(64);
        for (uchar b : sha)
        {
            s.push_back(h[b >> 4]);
            s.push_back(h[b & 0xf]);
        }
        i["file_sha256"] = s;
    }
    qstring proc = inf_get_procname();
    i["processor"] = proc.c_str();
    i["bitness"] = static_cast<std::uint32_t>(inf_get_app_bitness());
    i["image_base"] = hex_u64(static_cast<std::uint64_t>(get_imagebase()));
    i["min_ea"] = hex_u64(static_cast<std::uint64_t>(inf_get_min_ea()));
    i["max_ea"] = hex_u64(static_cast<std::uint64_t>(inf_get_max_ea()));
    i["index_generation"] = 0;
    i["heartbeat_ms"] = now_ms();
    return i;
}

json import_rows(std::size_t max_rows)
{
    struct import_state_t
    {
        json rows = json::array();
        std::size_t max_rows = 0;
        std::string module_name;
    } st;
    st.max_rows = max_rows;
    const uint qty = get_import_module_qty();
    for (uint i = 0; i < qty && st.rows.size() < max_rows; ++i)
    {
        qstring mod;
        get_import_module_name(&mod, static_cast<int>(i));
        st.module_name = mod.c_str();
        enum_import_names(static_cast<int>(i), [](ea_t ea, const char* name, uval_t ordinal, void* ud) -> int {
            auto* s = static_cast<import_state_t*>(ud);
            if (s->rows.size() >= s->max_rows)
                return 0;
            json row;
            row["module"] = s->module_name;
            row["name"] = name != nullptr ? std::string(name) : std::string();
            row["ordinal"] = static_cast<std::uint64_t>(ordinal);
            row["ea"] = ea == BADADDR ? json(nullptr) : json(hex_u64(static_cast<std::uint64_t>(ea)));
            s->rows.push_back(std::move(row));
            return 1;
        }, &st);
    }
    return st.rows;
}

json entry_rows(std::size_t max_rows)
{
    json rows = json::array();
    const size_t qty = get_entry_qty();
    for (size_t i = 0; i < qty && rows.size() < max_rows; ++i)
    {
        const uval_t ord = get_entry_ordinal(i);
        const ea_t ea = get_entry(ord);
        qstring name;
        qstring fwd;
        get_entry_name(&name, ord);
        get_entry_forwarder(&fwd, ord);
        json row;
        row["ordinal"] = static_cast<std::uint64_t>(ord);
        row["name"] = name.c_str();
        row["forwarder"] = fwd.c_str();
        row["ea"] = ea == BADADDR ? json(nullptr) : json(hex_u64(static_cast<std::uint64_t>(ea)));
        rows.push_back(std::move(row));
    }
    return rows;
}

json normalize_imports(const json& module)
{
    if (module.contains("imports") && module["imports"].is_array())
        return module["imports"];
    if (module.contains("imports_preview") && module["imports_preview"].is_array())
        return module["imports_preview"];
    return json::array();
}

json normalize_exports(const json& module)
{
    if (module.contains("exports") && module["exports"].is_array())
        return module["exports"];
    if (module.contains("entry_points") && module["entry_points"].is_array())
        return module["entry_points"];
    if (module.contains("entries") && module["entries"].is_array())
        return module["entries"];
    return json::array();
}

void collect_inventory_objects(const json& node, std::vector<json>& out)
{
    if (node.is_object())
    {
        const std::string schema = node.value("schema", std::string());
        if (schema == "aida.ida.project.inventory.v1")
            out.push_back(node);
        if (node.contains("content") && node["content"].is_array())
        {
            for (const json& item : node["content"])
            {
                if (!item.is_object() || !item.contains("text") || !item["text"].is_string())
                    continue;
                try
                {
                    json parsed = json::parse(item["text"].get<std::string>());
                    collect_inventory_objects(parsed, out);
                }
                catch (...)
                {
                }
            }
        }
        for (auto it = node.begin(); it != node.end(); ++it)
            collect_inventory_objects(it.value(), out);
    }
    else if (node.is_array())
    {
        for (const json& item : node)
            collect_inventory_objects(item, out);
    }
}

json module_from_inventory(const json& inventory)
{
    json raw = inventory.value("module", json::object());
    json module = normalize_module_record(raw);
    if (!module.is_object() || module.empty())
        module = json::object();
    module["schema"] = k_module_schema;
    module["version"] = k_project_schema_version;
    module["availability"] = "loaded";
    module["trust"] = "ida_extracted";
    module["updated_at_ms"] = now_ms();
    if (!module.contains("live_instances") || !module["live_instances"].is_array())
        module["live_instances"] = json::array();
    if (inventory.contains("instance") && inventory["instance"].is_object())
        module["live_instances"].push_back(inventory["instance"]);
    if (inventory.contains("segments") && inventory["segments"].is_array())
        module["segments"] = inventory["segments"];
    if (inventory.contains("imports_preview") && inventory["imports_preview"].is_array())
        module["imports"] = inventory["imports_preview"];
    if (inventory.contains("entry_points") && inventory["entry_points"].is_array())
        module["exports"] = inventory["entry_points"];
    module["function_count"] = inventory.value("function_count", module.value("function_count", static_cast<std::uint64_t>(0)));
    module["segment_count"] = inventory.value("segment_count", module.value("segment_count", static_cast<int>(0)));
    module["import_module_count"] = inventory.value("import_module_count", module.value("import_module_count", static_cast<int>(0)));
    module["entry_count"] = inventory.value("entry_count", module.value("entry_count", static_cast<std::uint64_t>(0)));
    module["auto_analysis_ok"] = inventory.value("auto_analysis_ok", false);
    module["index_generation"] = inventory.value("generation", module.value("index_generation", std::string()));
    return normalize_module_record(module);
}

json make_manifest(const std::string& project_id, const json& modules, const json& previous, const json& options)
{
    json manifest = previous.is_object() ? previous : json::object();
    const std::uint64_t ts = now_ms();
    manifest["schema"] = k_project_schema;
    manifest["version"] = k_project_schema_version;
    manifest["project_id"] = project_id;
    manifest["created_at_ms"] = manifest.value("created_at_ms", ts);
    manifest["updated_at_ms"] = ts;
    manifest["producer"] = "AiDA IDA plugin";
    manifest["sdk_context"] = json::object({
        {"processor", modules.empty() ? std::string() : module_identity_object(modules.front()).value("processor", std::string())},
        {"bitness", modules.empty() ? 0 : module_identity_object(modules.front()).value("bitness", 0)}
    });
    manifest["signature_db_rev"] = options.value("signature_db_rev", manifest.value("signature_db_rev", std::string("builtin")));
    manifest["module_index_generation"] = manifest.value("module_index_generation", static_cast<std::uint64_t>(0)) + 1;
    manifest["modules"] = modules;
    manifest["module_count"] = modules.size();
    manifest["content_hash"] = stable_hash_hex(modules.dump());
    return manifest;
}

project_io_result_t make_error(const std::string& code, const std::string& message, const json& data = json::object())
{
    project_io_result_t r;
    r.ok = false;
    r.error_code = code;
    r.error_message = message;
    r.data = data;
    return r;
}

project_io_result_t make_ok(const json& data)
{
    project_io_result_t r;
    r.ok = true;
    r.data = data;
    return r;
}

}

std::uint64_t now_ms()
{
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

std::string stable_hash_hex(const std::string& text)
{
    std::uint64_t h = 1469598103934665603ull;
    for (unsigned char c : text)
    {
        h ^= static_cast<std::uint64_t>(c);
        h *= 1099511628211ull;
    }
    std::ostringstream ss;
    ss << std::hex << std::setw(16) << std::setfill('0') << h;
    return ss.str();
}

std::string sanitize_id_component(const std::string& text)
{
    std::string out;
    out.reserve(text.size());
    for (unsigned char c : text)
    {
        if (c >= 'A' && c <= 'Z')
            out.push_back(static_cast<char>(c - 'A' + 'a'));
        else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-')
            out.push_back(static_cast<char>(c));
        else if (c == '.' || c == ':' || c == '/' || c == '\\' || c == ' ')
            out.push_back('_');
    }
    while (!out.empty() && out.front() == '_')
        out.erase(out.begin());
    while (!out.empty() && out.back() == '_')
        out.pop_back();
    if (out.empty())
        out = "unnamed";
    return out;
}

std::string canonical_module_id_from_hashes(const std::string& sha256,
                                             const std::string& md5,
                                             const std::string& canonical_name,
                                             const std::string& input_path)
{
    if (!sha256.empty())
        return "sha256_" + sanitize_id_component(sha256);
    if (!md5.empty())
        return "md5_" + sanitize_id_component(md5);
    json fallback;
    fallback["canonical_name"] = lowercase_ascii(canonical_name);
    fallback["input_path"] = lowercase_ascii(input_path);
    return "module_" + stable_hash_hex(fallback.dump());
}

std::string canonical_module_id_from_json(const json& module)
{
    json identity = module_identity_object(module);
    std::string id = identity.value("module_id", identity.value("corpus_id", std::string()));
    if (!id.empty() && id.find(':') == std::string::npos)
        return sanitize_id_component(id);
    const std::string sha = identity.value("input_sha256", identity.value("file_sha256", std::string()));
    const std::string md5 = identity.value("input_md5", identity.value("file_md5", std::string()));
    const std::string name = identity.value("canonical_name", identity.value("input_basename", identity.value("module_name", std::string())));
    const std::string path = identity.value("input_path", identity.value("input_file", std::string()));
    return canonical_module_id_from_hashes(sha, md5, name.empty() ? basename_of(path) : name, path);
}

std::string projects_root()
{
    const char* base = get_user_idadir();
    return path_join(base != nullptr ? std::string(base) : std::string("."), "aida_projects");
}

std::string project_root(const std::string& project_id)
{
    return path_join(projects_root(), sanitize_id_component(project_id));
}

std::string default_project_id_for_current_idb()
{
    vuln::chain::corpus_record_t corpus = vuln::chain::snapshot_current_idb_corpus();
    const std::string id = corpus.identity.corpus_id.empty()
        ? canonical_module_id_from_hashes(corpus.identity.hashes.sha256, corpus.identity.hashes.md5, corpus.identity.canonical_name, corpus.identity.input_path)
        : corpus.identity.corpus_id;
    return "project_" + sanitize_id_component(id);
}

bool ensure_project_dirs(const std::string& project_id, std::string* error)
{
    const std::string root = project_root(project_id);
    const std::vector<std::string> dirs = {
        root,
        path_join(root, "modules"),
        path_join(root, "functions"),
        path_join(path_join(root, "functions"), "pages"),
        path_join(root, "edges"),
        path_join(path_join(root, "edges"), "pages"),
        path_join(root, "xrefs"),
        path_join(root, "signatures"),
        path_join(root, "dispatch_tables"),
        path_join(root, "callbacks"),
        path_join(root, "globals"),
        path_join(root, "imports"),
        path_join(root, "exports"),
        path_join(root, "summaries"),
        path_join(root, "chains"),
        path_join(root, "traces"),
        path_join(root, "reports"),
        path_join(root, "resources"),
        path_join(root, "locks")
    };
    for (const std::string& dir : dirs)
    {
        if (!ensure_dir_recursive_local(dir))
        {
            if (error != nullptr)
                *error = dir;
            return false;
        }
    }
    return true;
}

project_lock_t::project_lock_t(std::string id) : project_id(std::move(id))
{
    lock_path = path_join(path_join(project_root(project_id), "locks"), "project.lock");
}

project_lock_t::project_lock_t(project_lock_t&& other) noexcept
{
    *this = std::move(other);
}

project_lock_t& project_lock_t::operator=(project_lock_t&& other) noexcept
{
    if (this != &other)
    {
        release();
        project_id = std::move(other.project_id);
        lock_path = std::move(other.lock_path);
        acquired = other.acquired;
        stale_recovered = other.stale_recovered;
        error_code = std::move(other.error_code);
        error_message = std::move(other.error_message);
        other.acquired = false;
    }
    return *this;
}

project_lock_t::~project_lock_t()
{
    release();
}

bool project_lock_t::acquire(bool force)
{
    std::string dir_error;
    if (!ensure_project_dirs(project_id, &dir_error))
    {
        error_code = "project_dir_error";
        error_message = dir_error;
        return false;
    }
    json existing;
    std::string read_error;
    if (read_json_file(lock_path, existing, &read_error))
    {
        const std::uint64_t pid = existing.value("pid", static_cast<std::uint64_t>(0));
        const std::uint64_t ts = existing.value("created_at_ms", static_cast<std::uint64_t>(0));
        const bool alive = pid_alive(pid);
        const bool fresh = now_ms() >= ts && now_ms() - ts < 10ull * 60ull * 1000ull;
        if (!force && alive && fresh && pid != current_pid())
        {
            error_code = "project_lock_held";
            error_message = "project lock is held by a live process";
            return false;
        }
        stale_recovered = !alive || !fresh || force;
    }
    json lock;
    lock["schema"] = "aida.multibinary.project.lock";
    lock["project_id"] = project_id;
    lock["pid"] = current_pid();
    lock["created_at_ms"] = now_ms();
    std::string write_error;
    if (!write_json_file(lock_path, lock, &write_error))
    {
        error_code = "project_lock_write_failed";
        error_message = write_error;
        return false;
    }
    acquired = true;
    return true;
}

void project_lock_t::release()
{
    if (!acquired)
        return;
    json existing;
    std::string read_error;
    if (read_json_file(lock_path, existing, &read_error)
        && existing.value("pid", static_cast<std::uint64_t>(0)) == current_pid())
    {
        std::remove(lock_path.c_str());
    }
    acquired = false;
}

project_io_result_t load_project_manifest(const std::string& project_id)
{
    const std::string path = path_join(project_root(project_id), "project.json");
    json manifest;
    std::string error;
    if (!read_json_file(path, manifest, &error))
        return make_error("project_not_found", "project manifest could not be read", {{"project_id", project_id}, {"path", path}, {"error", error}});
    if (!manifest.is_object() || manifest.value("schema", std::string()) != k_project_schema)
        return make_error("project_schema_invalid", "project manifest schema is invalid", {{"project_id", project_id}, {"path", path}});
    return make_ok({{"project_id", project_id}, {"root", project_root(project_id)}, {"manifest", manifest}});
}

project_io_result_t save_project_manifest(const std::string& project_id, const json& manifest)
{
    std::string dir_error;
    if (!ensure_project_dirs(project_id, &dir_error))
        return make_error("project_dir_error", "project directories could not be created", {{"path", dir_error}});
    const std::string path = path_join(project_root(project_id), "project.json");
    std::string error;
    if (!write_json_file(path, manifest, &error))
        return make_error("project_write_failed", "project manifest could not be written", {{"path", path}, {"error", error}});
    return make_ok({{"project_id", project_id}, {"path", path}, {"manifest", manifest}});
}

project_io_result_t delete_project(const std::string& project_id)
{
    const std::string root = project_root(project_id);
    std::error_code ec;
    const auto removed = std::filesystem::remove_all(root, ec);
    if (ec)
        return make_error("project_delete_failed", "project directory could not be deleted", {{"project_id", project_id}, {"path", root}, {"error", ec.message()}});
    return make_ok({{"project_id", project_id}, {"path", root}, {"removed_entries", static_cast<std::uint64_t>(removed)}});
}

project_io_result_t list_projects()
{
    ensure_dir_recursive_local(projects_root());
    json rows = json::array();
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(projects_root(), ec))
    {
        if (ec)
            break;
        if (!entry.is_directory())
            continue;
        const std::string id = entry.path().filename().string();
        json manifest;
        std::string error;
        const std::string path = path_join(entry.path().string(), "project.json");
        if (read_json_file(path, manifest, &error) && manifest.is_object())
        {
            rows.push_back({
                {"project_id", manifest.value("project_id", id)},
                {"path", entry.path().string()},
                {"schema", manifest.value("schema", std::string())},
                {"version", manifest.value("version", 0)},
                {"module_count", manifest.value("module_count", static_cast<std::size_t>(0))},
                {"updated_at_ms", manifest.value("updated_at_ms", static_cast<std::uint64_t>(0))},
                {"content_hash", manifest.value("content_hash", std::string())}
            });
        }
    }
    if (ec)
        return make_error("project_list_failed", "project directory could not be listed", {{"root", projects_root()}, {"error", ec.message()}});
    std::sort(rows.begin(), rows.end(), [](const json& a, const json& b) {
        return a.value("updated_at_ms", static_cast<std::uint64_t>(0)) > b.value("updated_at_ms", static_cast<std::uint64_t>(0));
    });
    return make_ok({{"root", projects_root()}, {"projects", rows}});
}

project_io_result_t project_status(const std::string& project_id)
{
    project_io_result_t loaded = load_project_manifest(project_id);
    if (!loaded.ok)
        return loaded;
    json manifest = loaded.data["manifest"];
    json status;
    status["project_id"] = project_id;
    status["root"] = project_root(project_id);
    status["schema"] = manifest.value("schema", std::string());
    status["version"] = manifest.value("version", 0);
    status["module_count"] = manifest.value("module_count", static_cast<std::size_t>(0));
    status["module_index_generation"] = manifest.value("module_index_generation", static_cast<std::uint64_t>(0));
    status["updated_at_ms"] = manifest.value("updated_at_ms", static_cast<std::uint64_t>(0));
    status["content_hash"] = manifest.value("content_hash", std::string());
    status["modules"] = json::array();
    for (const json& module : manifest.value("modules", json::array()))
    {
        const std::string id = canonical_module_id_from_json(module);
        const std::string module_path = path_join(path_join(project_root(project_id), "modules"), sanitize_id_component(id) + ".json");
        const std::string function_path = path_join(path_join(project_root(project_id), "functions"), sanitize_id_component(id) + ".msgpack");
        json row;
        row["module_id"] = id;
        row["canonical_name"] = module_name_from_json(module);
        row["availability"] = module.value("availability", std::string("missing"));
        row["module_record_present"] = std::filesystem::exists(module_path);
        row["function_cache_present"] = std::filesystem::exists(function_path);
        row["index_generation"] = module.value("index_generation", json(nullptr));
        row["stale"] = module.value("stale", false);
        status["modules"].push_back(std::move(row));
    }
    const std::string cross_path = path_join(path_join(project_root(project_id), "edges"), "cross_edges.msgpack");
    status["cross_edges_present"] = std::filesystem::exists(cross_path);
    return make_ok(status);
}

json canonical_address_json(const std::string& module_id,
                            std::uint64_t rva,
                            std::uint64_t ea_hint,
                            const std::string& segment,
                            std::uint64_t segment_start_rva,
                            std::uint64_t segment_offset,
                            const std::string& confidence)
{
    json out;
    out["module_id"] = module_id;
    out["corpus_id"] = module_id;
    out["rva"] = hex_u64(rva);
    out["ea_hint"] = ea_hint == 0 ? json(nullptr) : json(hex_u64(ea_hint));
    out["segment"] = segment;
    out["segment_start_rva"] = hex_u64(segment_start_rva);
    out["segment_offset"] = hex_u64(segment_offset);
    out["address_key"] = module_id + "+" + hex_u64(rva);
    out["confidence"] = confidence;
    return out;
}

json canonical_address_from_chain(const vuln::chain::canonical_address_t& address)
{
    return canonical_address_json(address.corpus_id,
                                  address.rva,
                                  address.ea,
                                  address.segment,
                                  address.segment_start_rva,
                                  address.segment_offset,
                                  vuln::chain::to_string(address.confidence));
}

json canonical_module_record_from_corpus(const vuln::chain::corpus_record_t& corpus,
                                         const json& instance,
                                         const json& extra)
{
    json module;
    module["schema"] = k_module_schema;
    module["version"] = k_project_schema_version;
    module["availability"] = vuln::chain::to_string(corpus.availability);
    module["trust"] = vuln::chain::to_string(corpus.trust);
    module["identity"] = vuln::chain::to_json(corpus.identity);
    module["identity"]["module_id"] = corpus.identity.corpus_id;
    module["segments"] = vuln::chain::to_json(corpus)["segments"];
    module["loader_model"] = corpus.loader_model;
    module["metadata"] = corpus.metadata;
    module["imports"] = json::array();
    module["exports"] = json::array();
    module["functions"] = json::array();
    module["cross_edges"] = json::array();
    module["live_instances"] = json::array();
    if (instance.is_object() && !instance.empty())
        module["live_instances"].push_back(instance);
    module["created_at_ms"] = now_ms();
    module["updated_at_ms"] = module["created_at_ms"];
    module["index_generation"] = 0;
    if (extra.is_object())
    {
        for (auto it = extra.begin(); it != extra.end(); ++it)
            module[it.key()] = it.value();
    }
    return normalize_module_record(module);
}

json current_idb_inventory(bool include_segments,
                           bool include_imports,
                           bool include_entries,
                           std::size_t max_rows)
{
    struct request_t : public exec_request_t
    {
        bool include_segments = true;
        bool include_imports = true;
        bool include_entries = true;
        std::size_t max_rows = 0;
        json result = json::object();

        ssize_t idaapi execute() override
        {
            vuln::chain::corpus_record_t corpus = vuln::chain::snapshot_current_idb_corpus();
            json module = canonical_module_record_from_corpus(corpus, current_instance_json());
            module["function_count"] = static_cast<std::uint64_t>(get_func_qty());
            module["segment_count"] = get_segm_qty();
            module["import_module_count"] = get_import_module_qty();
            module["entry_count"] = static_cast<std::uint64_t>(get_entry_qty());
            if (include_imports)
                module["imports"] = import_rows(max_rows);
            if (include_entries)
                module["exports"] = entry_rows(max_rows);
            result["schema"] = "aida.ida.project.inventory.v1";
            result["module"] = module;
            result["instance"] = current_instance_json();
            result["auto_analysis_ok"] = auto_is_ok();
            result["function_count"] = module["function_count"];
            result["segment_count"] = module["segment_count"];
            result["import_module_count"] = module["import_module_count"];
            result["entry_count"] = module["entry_count"];
            if (include_segments)
                result["segments"] = module["segments"];
            if (include_imports)
                result["imports_preview"] = module["imports"];
            if (include_entries)
                result["entry_points"] = module["exports"];
            result["generation"] = stable_hash_hex(module.dump());
            return 1;
        }
    } req;
    req.include_segments = include_segments;
    req.include_imports = include_imports;
    req.include_entries = include_entries;
    req.max_rows = max_rows;
    if (execute_sync(req, MFF_READ) <= 0)
        return json::object({{"schema", "aida.ida.project.inventory.v1"}, {"error", "execute_sync_failed"}});
    return req.result;
}

json merge_inventory_documents(const json& local_inventory, const json& supplied)
{
    std::vector<json> inventories;
    if (local_inventory.is_object() && local_inventory.value("schema", std::string()) == "aida.ida.project.inventory.v1")
        inventories.push_back(local_inventory);
    collect_inventory_objects(supplied, inventories);
    json modules = json::array();
    for (const json& inv : inventories)
        modules.push_back(module_from_inventory(inv));
    modules = merge_modules(json::array(), modules);
    json out;
    out["schema"] = "aida.multibinary.inventory.merge";
    out["inventory_count"] = inventories.size();
    out["modules"] = modules;
    out["missing_modules"] = missing_modules_from_imports(modules);
    return out;
}

json normalize_module_record(const json& module)
{
    if (!module.is_object())
        return json::object();
    json out = module;
    json identity = module_identity_object(out);
    const std::string module_id = canonical_module_id_from_json(out);
    const std::string canonical_name = module_name_from_json(out);
    if (!out.contains("identity") || !out["identity"].is_object())
        out["identity"] = json::object();
    out["identity"]["corpus_id"] = module_id;
    out["identity"]["module_id"] = module_id;
    if (out["identity"].value("canonical_name", std::string()).empty())
        out["identity"]["canonical_name"] = canonical_name;
    for (const char* key : {"input_path", "input_file", "idb_path", "processor", "input_md5", "input_sha256", "file_md5", "file_sha256"})
    {
        if (!identity.value(key, std::string()).empty() && !out["identity"].contains(key))
            out["identity"][key] = identity[key];
    }
    if (identity.contains("imagebase") && !out["identity"].contains("image_base"))
        out["identity"]["image_base"] = parse_u64_loose(identity["imagebase"]);
    if (identity.contains("image_base") && !out["identity"].contains("image_base"))
        out["identity"]["image_base"] = parse_u64_loose(identity["image_base"]);
    if (identity.contains("min_ea") && !out["identity"].contains("min_ea"))
        out["identity"]["min_ea"] = parse_u64_loose(identity["min_ea"]);
    if (identity.contains("max_ea") && !out["identity"].contains("max_ea"))
        out["identity"]["max_ea"] = parse_u64_loose(identity["max_ea"]);
    if (identity.contains("bitness") && !out["identity"].contains("bitness"))
        out["identity"]["bitness"] = identity["bitness"];
    out["module_id"] = module_id;
    out["corpus_id"] = module_id;
    out["canonical_name"] = canonical_name;
    out["address_model"] = "module_id+rva";
    out["schema"] = out.value("schema", std::string(k_module_schema));
    out["version"] = out.value("version", k_project_schema_version);
    out["availability"] = out.value("availability", std::string("loaded"));
    out["trust"] = out.value("trust", std::string("ida_extracted"));
    if (!out.contains("segments") || !out["segments"].is_array())
        out["segments"] = json::array();
    if (!out.contains("imports") || !out["imports"].is_array())
        out["imports"] = normalize_imports(out);
    if (!out.contains("exports") || !out["exports"].is_array())
        out["exports"] = normalize_exports(out);
    if (!out.contains("live_instances") || !out["live_instances"].is_array())
        out["live_instances"] = json::array();
    out["updated_at_ms"] = out.value("updated_at_ms", now_ms());
    return out;
}

json merge_modules(const json& existing_modules, const json& incoming_modules)
{
    std::unordered_map<std::string, json> by_id;
    auto append_one = [&](const json& raw) {
        json module = normalize_module_record(raw);
        if (!module.is_object() || module.empty())
            return;
        const std::string id = canonical_module_id_from_json(module);
        if (id.empty())
            return;
        auto it = by_id.find(id);
        if (it == by_id.end())
        {
            by_id.emplace(id, module);
            return;
        }
        json& dst = it->second;
        if (dst.value("availability", std::string("missing")) == "missing" && module.value("availability", std::string("missing")) != "missing")
            dst = module;
        else
        {
            for (const char* key : {"segments", "imports", "exports", "functions", "cross_edges"})
            {
                if (module.contains(key) && module[key].is_array() && (!dst.contains(key) || dst[key].empty()))
                    dst[key] = module[key];
            }
            dst["updated_at_ms"] = std::max(dst.value("updated_at_ms", static_cast<std::uint64_t>(0)), module.value("updated_at_ms", static_cast<std::uint64_t>(0)));
        }
        if (!dst.contains("live_instances") || !dst["live_instances"].is_array())
            dst["live_instances"] = json::array();
        std::unordered_set<std::string> seen;
        for (const json& inst : dst["live_instances"])
            seen.insert(inst.dump());
        if (module.contains("live_instances") && module["live_instances"].is_array())
        {
            for (const json& inst : module["live_instances"])
            {
                const std::string key = inst.dump();
                if (seen.insert(key).second)
                    dst["live_instances"].push_back(inst);
            }
        }
    };
    if (existing_modules.is_array())
    {
        for (const json& item : existing_modules)
            append_one(item);
    }
    if (incoming_modules.is_array())
    {
        for (const json& item : incoming_modules)
            append_one(item);
    }
    json out = json::array();
    std::vector<std::string> ids;
    ids.reserve(by_id.size());
    for (const auto& kv : by_id)
        ids.push_back(kv.first);
    std::sort(ids.begin(), ids.end());
    for (const std::string& id : ids)
        out.push_back(by_id[id]);
    return out;
}

json missing_modules_from_imports(const json& modules)
{
    std::unordered_map<std::string, std::vector<std::string>> loaded_names;
    if (modules.is_array())
    {
        for (const json& module : modules)
        {
            const std::string availability = module.value("availability", std::string("missing"));
            if (availability == "missing")
                continue;
            const std::string name = module_name_from_json(module);
            if (!name.empty())
                loaded_names[name].push_back(canonical_module_id_from_json(module));
        }
    }
    std::unordered_map<std::string, json> missing;
    if (modules.is_array())
    {
        for (const json& module : modules)
        {
            const std::string importer_id = canonical_module_id_from_json(module);
            for (const json& imp : normalize_imports(module))
            {
                if (!imp.is_object())
                    continue;
                std::string name = lowercase_ascii(imp.value("module", imp.value("module_name", std::string())));
                if (name.empty())
                    continue;
                if (loaded_names.find(name) != loaded_names.end())
                    continue;
                const std::string id = "missing_" + sanitize_id_component(name);
                json& rec = missing[id];
                if (rec.empty())
                {
                    rec["schema"] = k_module_schema;
                    rec["version"] = k_project_schema_version;
                    rec["module_id"] = id;
                    rec["corpus_id"] = id;
                    rec["canonical_name"] = name;
                    rec["availability"] = "missing";
                    rec["trust"] = "user_declared";
                    rec["identity"] = json::object({{"corpus_id", id}, {"module_id", id}, {"canonical_name", name}});
                    rec["imports"] = json::array();
                    rec["exports"] = json::array();
                    rec["segments"] = json::array();
                    rec["live_instances"] = json::array();
                    rec["missing_reason"] = "referenced_by_imports";
                    rec["referenced_by"] = json::array();
                }
                rec["referenced_by"].push_back({{"module_id", importer_id}, {"import", imp}});
            }
        }
    }
    json out = json::array();
    std::vector<std::string> ids;
    ids.reserve(missing.size());
    for (const auto& kv : missing)
        ids.push_back(kv.first);
    std::sort(ids.begin(), ids.end());
    for (const std::string& id : ids)
        out.push_back(missing[id]);
    return out;
}

project_io_result_t save_or_update_project(const std::string& requested_project_id,
                                           const json& modules,
                                           const json& options)
{
    std::string project_id = requested_project_id.empty() ? default_project_id_for_current_idb() : sanitize_id_component(requested_project_id);
    project_lock_t lock(project_id);
    if (!lock.acquire(options.value("force_lock", false)))
        return make_error(lock.error_code, lock.error_message, {{"project_id", project_id}, {"lock_path", lock.lock_path}});
    project_io_result_t previous = load_project_manifest(project_id);
    json previous_manifest = previous.ok ? previous.data["manifest"] : json::object();
    json merged = merge_modules(previous_manifest.value("modules", json::array()), modules);
    merged = merge_modules(merged, missing_modules_from_imports(merged));
    json manifest = make_manifest(project_id, merged, previous_manifest, options);
    project_io_result_t saved = save_project_manifest(project_id, manifest);
    if (!saved.ok)
        return saved;
    for (const json& module : merged)
    {
        project_io_result_t wrote = write_module_record(project_id, module);
        if (!wrote.ok)
            return wrote;
    }
    json data = saved.data;
    data["lock_recovered"] = lock.stale_recovered;
    return make_ok(data);
}

project_io_result_t bind_current_inventory_to_project(const std::string& requested_project_id,
                                                      const json& local_inventory,
                                                      const json& supplied_inventory,
                                                      const json& options)
{
    json merged_inventory = merge_inventory_documents(local_inventory, supplied_inventory);
    json modules = merge_modules(merged_inventory.value("modules", json::array()), merged_inventory.value("missing_modules", json::array()));
    project_io_result_t saved = save_or_update_project(requested_project_id, modules, options);
    if (!saved.ok)
        return saved;
    saved.data["inventory"] = merged_inventory;
    return saved;
}

project_io_result_t load_project_modules(const std::string& project_id)
{
    project_io_result_t manifest_result = load_project_manifest(project_id);
    if (!manifest_result.ok)
        return manifest_result;
    json modules = json::array();
    for (const json& summary : manifest_result.data["manifest"].value("modules", json::array()))
    {
        const std::string id = canonical_module_id_from_json(summary);
        const std::string path = path_join(path_join(project_root(project_id), "modules"), sanitize_id_component(id) + ".json");
        json module;
        std::string error;
        if (read_json_file(path, module, &error))
            modules.push_back(normalize_module_record(module));
        else
            modules.push_back(normalize_module_record(summary));
    }
    return make_ok({{"project_id", project_id}, {"modules", modules}, {"manifest", manifest_result.data["manifest"]}});
}

project_io_result_t write_module_record(const std::string& project_id, const json& module)
{
    json normalized = normalize_module_record(module);
    const std::string id = canonical_module_id_from_json(normalized);
    if (id.empty())
        return make_error("module_identity_missing", "module record has no canonical module id", {{"module", module}});
    const std::string path = path_join(path_join(project_root(project_id), "modules"), sanitize_id_component(id) + ".json");
    std::string error;
    if (!write_json_file(path, normalized, &error))
        return make_error("module_write_failed", "module record could not be written", {{"module_id", id}, {"path", path}, {"error", error}});
    return make_ok({{"project_id", project_id}, {"module_id", id}, {"path", path}, {"module", normalized}});
}

json content_hash_summary(const json& value)
{
    const std::string dump = value.dump();
    return json::object({{"algorithm", "fnv1a64"}, {"hash", stable_hash_hex(dump)}, {"bytes", dump.size()}});
}

}
}
