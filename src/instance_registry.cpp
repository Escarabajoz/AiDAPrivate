#include "aida_pro.hpp"
#include "instance_registry.hpp"
#include "ida_utils.hpp"
#include "multibinary_project.hpp"

#include <netnode.hpp>
#include <prodir.h>
#include <bcrypt.h>
#include <limits>
#pragma comment(lib, "bcrypt.lib")

#ifdef _WIN32
#include <windows.h>
#endif

using json = nlohmann::json;

namespace {

constexpr int kHeartbeatPeriodMs = 5000;
constexpr int kStaleThresholdMs  = 30000;

std::string generate_instance_id_local()
{
    unsigned char rnd[16] = {};
    NTSTATUS st = BCryptGenRandom(nullptr, rnd, sizeof(rnd),
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (st != 0)
    {
        auto t = std::chrono::steady_clock::now().time_since_epoch().count();
        for (size_t i = 0; i < sizeof(rnd); ++i)
            rnd[i] = static_cast<unsigned char>((t >> (i * 8)) ^ i);
    }
    static const char hex[] = "0123456789abcdef";
    std::string id;
    id.reserve(32);
    for (size_t i = 0; i < sizeof(rnd); ++i)
    {
        id.push_back(hex[rnd[i] >> 4]);
        id.push_back(hex[rnd[i] & 0x0f]);
    }
    return id;
}

std::string sanitize_basename_for_entry(const std::string& input)
{
    std::string out;
    out.reserve(input.size());
    for (unsigned char c : input)
    {
        if (c >= 'A' && c <= 'Z')
            out.push_back(static_cast<char>(c - 'A' + 'a'));
        else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_')
            out.push_back(static_cast<char>(c));
        else if (c == '.' || c == ' ')
            out.push_back('-');
    }
    while (!out.empty() && (out.front() == '-' || out.front() == '_'))
        out.erase(out.begin());
    while (!out.empty() && (out.back() == '-' || out.back() == '_'))
        out.pop_back();
    if (out.empty())
        out = "instance";
    if (out.size() > 40)
        out.resize(40);
    return out;
}

std::string get_input_basename_local()
{
    char path[QMAXPATH] = {};
    get_input_file_path(path, sizeof(path));
    if (path[0] == '\0')
        return std::string();
    std::string s(path);
    size_t sep = s.find_last_of("/\\");
    std::string base = (sep == std::string::npos) ? s : s.substr(sep + 1);
    return base;
}

std::string get_input_path_local()
{
    char path[QMAXPATH] = {};
    get_input_file_path(path, sizeof(path));
    return std::string(path[0] ? path : "");
}

std::string get_idb_path_local()
{
    const char* p = get_path(PATH_TYPE_IDB);
    return std::string(p ? p : "");
}

std::string hex_u64_local(uint64_t value)
{
    char buf[32] = {};
    qsnprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(value));
    return std::string(buf);
}

std::string hex_lower_bytes(const uint8_t* data, size_t n)
{
    static const char hex[] = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i)
    {
        s.push_back(hex[data[i] >> 4]);
        s.push_back(hex[data[i] & 0x0f]);
    }
    return s;
}

std::string json_scalar_string(const json& value)
{
    if (value.is_string())
        return value.get<std::string>();
    if (value.is_number_unsigned())
        return hex_u64_local(value.get<uint64_t>());
    if (value.is_number_integer())
        return hex_u64_local(static_cast<uint64_t>(value.get<int64_t>()));
    return std::string();
}

void refresh_multibinary_metadata_local(ida_instance_record_t& rec)
{
    rec.image_base = hex_u64_local(static_cast<uint64_t>(get_imagebase()));
    rec.image_min_ea = hex_u64_local(static_cast<uint64_t>(inf_get_min_ea()));
    rec.image_max_ea = hex_u64_local(static_cast<uint64_t>(inf_get_max_ea()));
    rec.module_id = aida::multibinary::canonical_module_id_from_hashes(rec.file_sha256, rec.file_md5, rec.input_basename, rec.input_file);
    if (rec.index_generation.empty())
        rec.index_generation = "unindexed:" + rec.module_id;
    try
    {
        netnode nn("$ AiDA.multibinary.module");
        if (nn == BADNODE)
            return;
        qvector<uchar> blob;
        if (nn.getblob(&blob, 0, 'M') <= 0)
            return;
        std::vector<uint8_t> data(blob.begin(), blob.end());
        json module = json::from_msgpack(data);
        const std::string module_id = aida::multibinary::canonical_module_id_from_json(module);
        if (!module_id.empty() && module_id != rec.module_id)
            return;
        if (module.contains("index_generation"))
            rec.index_generation = json_scalar_string(module["index_generation"]);
        if (module.contains("identity") && module["identity"].is_object())
        {
            const json& identity = module["identity"];
            if (identity.contains("image_base"))
                rec.image_base = json_scalar_string(identity["image_base"]);
            if (identity.contains("min_ea"))
                rec.image_min_ea = json_scalar_string(identity["min_ea"]);
            if (identity.contains("max_ea"))
                rec.image_max_ea = json_scalar_string(identity["max_ea"]);
        }
    }
    catch (...)
    {
    }
}

std::string get_hostname_local()
{
#ifdef _WIN32
    wchar_t buf[256] = {};
    DWORD sz = 256;
    if (GetComputerNameW(buf, &sz) && sz > 0)
    {
        char out[256] = {};
        int r = WideCharToMultiByte(CP_UTF8, 0, buf, -1, out, sizeof(out), nullptr, nullptr);
        if (r > 0)
            return std::string(out);
    }
    return std::string("unknown-host");
#else
    char buf[256] = {};
    if (gethostname(buf, sizeof(buf) - 1) == 0)
        return std::string(buf);
    return std::string("unknown-host");
#endif
}

bool ensure_dir_recursive(const std::string& dir_path)
{
    if (dir_path.empty())
        return false;
    if (qisdir(dir_path.c_str()))
        return true;
    size_t sep = dir_path.find_last_of("/\\");
    if (sep != std::string::npos && sep > 0)
    {
        std::string parent = dir_path.substr(0, sep);
        if (!ensure_dir_recursive(parent))
            return false;
    }
    int rc = qmkdir(dir_path.c_str(), 0755);
    return rc == 0 || qisdir(dir_path.c_str());
}

}

json ida_instance_record_t::to_json() const
{
    json j;
    j["instance_id"]       = instance_id;
    j["pid"]               = pid;
    j["port"]              = port;
    j["base_url"]          = base_url;
    j["mcp_url"]           = mcp_url;
    j["sse_url"]           = sse_url;
    j["idb_path"]          = idb_path;
    j["input_file"]        = input_file;
    j["input_basename"]    = input_basename;
    j["display_name"]      = display_name;
    j["config_entry_name"] = config_entry_name;
    j["file_md5"]          = file_md5;
    j["file_sha256"]       = file_sha256;
    j["module_id"]         = module_id;
    j["index_generation"]  = index_generation;
    j["image_base"]        = image_base;
    j["image_min_ea"]      = image_min_ea;
    j["image_max_ea"]      = image_max_ea;
    j["processor"]         = processor;
    j["bitness"]           = bitness;
    j["hostname"]          = hostname;
    j["ida_version"]       = ida_version;
    j["started_at_ms"]     = started_at_ms;
    j["last_heartbeat_ms"] = last_heartbeat_ms;
    return j;
}

ida_instance_record_t ida_instance_record_t::from_json(const json& j)
{
    ida_instance_record_t r;
    r.instance_id       = j.value("instance_id", "");
    r.pid               = j.value("pid", static_cast<uint64_t>(0));
    r.port              = j.value("port", 0);
    r.base_url          = j.value("base_url", "");
    r.mcp_url           = j.value("mcp_url", "");
    r.sse_url           = j.value("sse_url", "");
    r.idb_path          = j.value("idb_path", "");
    r.input_file        = j.value("input_file", "");
    r.input_basename    = j.value("input_basename", "");
    r.display_name      = j.value("display_name", "");
    r.config_entry_name = j.value("config_entry_name", "");
    r.file_md5          = j.value("file_md5", "");
    r.file_sha256       = j.value("file_sha256", "");
    r.module_id         = j.value("module_id", "");
    r.index_generation  = j.value("index_generation", "");
    r.image_base        = j.value("image_base", "");
    r.image_min_ea      = j.value("image_min_ea", "");
    r.image_max_ea      = j.value("image_max_ea", "");
    r.processor         = j.value("processor", "");
    r.bitness           = j.value("bitness", 0);
    r.hostname          = j.value("hostname", "");
    r.ida_version       = j.value("ida_version", "");
    r.started_at_ms     = j.value("started_at_ms", static_cast<uint64_t>(0));
    r.last_heartbeat_ms = j.value("last_heartbeat_ms", static_cast<uint64_t>(0));
    return r;
}

instance_registry_t::instance_registry_t() = default;

instance_registry_t::~instance_registry_t()
{
    stop();
}

uint64_t instance_registry_t::now_ms()
{
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

std::string instance_registry_t::registry_dir()
{
#ifdef _WIN32
    qstring buf;
    if (qgetenv("APPDATA", &buf) && !buf.empty())
    {
        std::string p(buf.c_str());
        p += "\\AiDA\\ida_instances";
        return p;
    }
    qstring drive, hpath;
    if (qgetenv("HOMEDRIVE", &drive) && qgetenv("HOMEPATH", &hpath))
    {
        std::string p = std::string(drive.c_str()) + std::string(hpath.c_str());
        p += "\\AiDA\\ida_instances";
        return p;
    }
    return std::string("C:\\AiDA\\ida_instances");
#else
    qstring buf;
    if (qgetenv("HOME", &buf) && !buf.empty())
    {
        std::string p(buf.c_str());
        p += "/.config/aida/ida_instances";
        return p;
    }
    return std::string("/tmp/aida/ida_instances");
#endif
}

std::string instance_registry_t::self_file_path() const
{
    std::string dir = registry_dir();
    std::string sep =
#ifdef _WIN32
        "\\";
#else
        "/";
#endif
    return dir + sep + _self.instance_id + ".json";
}

uint64_t instance_registry_t::hash_string(const std::string& s) const
{
    uint64_t h = 1469598103934665603ULL;
    for (unsigned char c : s)
    {
        h ^= static_cast<uint64_t>(c);
        h *= 1099511628211ULL;
    }
    return h;
}

void instance_registry_t::compute_self_identity(int port, const std::string& base_url,
                                                const std::string& mcp_url, const std::string& sse_url)
{
    _self.instance_id = generate_instance_id_local();
#ifdef _WIN32
    _self.pid = static_cast<uint64_t>(GetCurrentProcessId());
#else
    _self.pid = static_cast<uint64_t>(getpid());
#endif
    _self.port     = port;
    _self.base_url = base_url;
    _self.mcp_url  = mcp_url;
    _self.sse_url  = sse_url;

    _self.input_file     = get_input_path_local();
    _self.input_basename = get_input_basename_local();
    _self.idb_path       = get_idb_path_local();

    qstring procname = inf_get_procname();
    _self.processor  = procname.c_str();
    _self.bitness    = inf_is_64bit() ? 64 : (inf_is_32bit_exactly() ? 32 : 16);
    _self.hostname   = get_hostname_local();
    _self.ida_version = AIDA_VERSION;
    _self.started_at_ms = now_ms();
    _self.last_heartbeat_ms = _self.started_at_ms;
    _self.is_self = true;

    if (!_self.input_basename.empty())
        _self.display_name = _self.input_basename + " (pid " + std::to_string(_self.pid) + ")";
    else if (!_self.idb_path.empty())
    {
        std::string idb = _self.idb_path;
        size_t sep = idb.find_last_of("/\\");
        std::string base = (sep == std::string::npos) ? idb : idb.substr(sep + 1);
        _self.display_name = base + " (pid " + std::to_string(_self.pid) + ")";
    }
    else
    {
        _self.display_name = "IDA pid " + std::to_string(_self.pid);
    }

    std::string base_for_entry = !_self.input_basename.empty()
        ? _self.input_basename
        : (!_self.idb_path.empty() ? _self.idb_path : "instance");
    _self.config_entry_name = compute_config_entry_name(base_for_entry);

    uchar md5[16] = {};
    if (retrieve_input_file_md5(md5))
        _self.file_md5 = hex_lower_bytes(md5, 16);
    uchar sha[32] = {};
    if (retrieve_input_file_sha256(sha))
        _self.file_sha256 = hex_lower_bytes(sha, 32);
    refresh_multibinary_metadata_local(_self);
}

std::string instance_registry_t::compute_config_entry_name(const std::string& base)
{
    std::string sanitized = sanitize_basename_for_entry(base);
    std::string entry = "AiDA-IDA-MCP-" + sanitized;
    uint64_t h = hash_string(_self.instance_id);
    char suffix[16] = {};
    qsnprintf(suffix, sizeof(suffix), "-%04x", static_cast<unsigned>(h & 0xffff));
    entry += suffix;
    return entry;
}

bool instance_registry_t::start(int port, const std::string& base_url,
                                const std::string& mcp_url, const std::string& sse_url)
{
    if (_running.load())
        return true;

    {
        std::lock_guard<std::mutex> lk(_mtx);
        compute_self_identity(port, base_url, mcp_url, sse_url);
    }

    if (!ensure_dir_recursive(registry_dir()))
    {
        msg("AiDA MCP: Could not create registry dir %s\n", registry_dir().c_str());
        return false;
    }

    {
        std::lock_guard<std::mutex> lk(_mtx);
        prune_stale_locked();
        write_self_file();
        auto live = scan_locked();
        _last_known_peer_ids.clear();
        _last_known_peer_ids.reserve(live.size());
        for (const auto& r : live)
            _last_known_peer_ids.push_back(r.instance_id);
    }

    _stop_requested = false;
    _running = true;

    try
    {
        _heartbeat_thread = std::thread([this]() { heartbeat_thread_func(); });
    }
    catch (const std::exception&)
    {
        _running = false;
        return false;
    }

    return true;
}

void instance_registry_t::stop()
{
    if (!_running.load() && !_heartbeat_thread.joinable())
        return;

    _stop_requested = true;
    _running = false;

    if (_heartbeat_thread.joinable())
        _heartbeat_thread.join();

    {
        std::lock_guard<std::mutex> lk(_mtx);
        delete_self_file();
    }
}

void instance_registry_t::heartbeat_thread_func()
{
    while (!_stop_requested.load(std::memory_order_acquire))
    {
        for (int i = 0; i < kHeartbeatPeriodMs / 100; ++i)
        {
            if (_stop_requested.load(std::memory_order_acquire))
                return;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (_stop_requested.load(std::memory_order_acquire))
            return;

        bool peers_changed = false;
        std::function<void()> cb_snapshot;
        {
            std::lock_guard<std::mutex> lk(_mtx);
            _self.last_heartbeat_ms = now_ms();
            refresh_multibinary_metadata_local(_self);
            write_self_file();
            prune_stale_locked();

            auto live = scan_locked();
            std::vector<std::string> ids;
            ids.reserve(live.size());
            for (const auto& r : live)
                ids.push_back(r.instance_id);
            std::sort(ids.begin(), ids.end());
            std::vector<std::string> last_sorted = _last_known_peer_ids;
            std::sort(last_sorted.begin(), last_sorted.end());
            if (ids != last_sorted)
            {
                _last_known_peer_ids = ids;
                peers_changed = true;
            }
            if (peers_changed)
                cb_snapshot = _peer_change_cb;
        }

        if (peers_changed && cb_snapshot)
            cb_snapshot();
    }
}

void instance_registry_t::on_peer_set_changed(std::function<void()> cb)
{
    std::lock_guard<std::mutex> lk(_mtx);
    _peer_change_cb = std::move(cb);
}

bool instance_registry_t::is_pid_alive(uint64_t pid) const
{
    if (pid == 0)
        return false;
#ifdef _WIN32
    if (pid > static_cast<uint64_t>((std::numeric_limits<DWORD>::max)()))
        return false;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (h == nullptr)
    {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED)
            return true;
        return false;
    }
    DWORD exit_code = 0;
    BOOL ok = GetExitCodeProcess(h, &exit_code);
    CloseHandle(h);
    if (!ok)
        return false;
    return exit_code == STILL_ACTIVE;
#else
    if (pid > static_cast<uint64_t>((std::numeric_limits<pid_t>::max)()))
        return false;
    return ::kill(static_cast<pid_t>(pid), 0) == 0 || errno == EPERM;
#endif
}

bool instance_registry_t::load_record(const std::string& path, ida_instance_record_t& out) const
{
    FILE* fp = qfopen(path.c_str(), "rb");
    if (!fp)
        return false;
    file_janitor_t fj(fp);
    uint64 size = qfsize(fp);
    if (size == 0 || size > 256 * 1024)
        return false;
    std::string raw;
    raw.resize(static_cast<size_t>(size));
    if (qfread(fp, &raw[0], raw.size()) != static_cast<ssize_t>(raw.size()))
        return false;
    try
    {
        json j = json::parse(raw);
        out = ida_instance_record_t::from_json(j);
        return !out.instance_id.empty();
    }
    catch (...)
    {
        return false;
    }
}

std::vector<ida_instance_record_t> instance_registry_t::scan_locked() const
{
    std::vector<ida_instance_record_t> out;
    std::string dir = registry_dir();
    qstring pattern = dir.c_str();
#ifdef _WIN32
    pattern.append("\\*.json");
#else
    pattern.append("/*.json");
#endif
    qffblk64_t blk;
    int rc = qfindfirst(pattern.c_str(), &blk, 0);
    while (rc == 0)
    {
        std::string fname = blk.ff_name;
        if (fname != "." && fname != "..")
        {
            std::string fp = dir;
#ifdef _WIN32
            fp += "\\";
#else
            fp += "/";
#endif
            fp += fname;
            ida_instance_record_t rec;
            if (load_record(fp, rec))
            {
                rec.is_self = (rec.instance_id == _self.instance_id);
                out.push_back(rec);
            }
        }
        rc = qfindnext(&blk);
    }
    return out;
}

void instance_registry_t::prune_stale_locked() const
{
    std::string dir = registry_dir();
    std::vector<std::pair<std::string, ida_instance_record_t>> entries;

    {
        qstring pattern = dir.c_str();
#ifdef _WIN32
        pattern.append("\\*.json");
#else
        pattern.append("/*.json");
#endif
        qffblk64_t blk;
        int rc = qfindfirst(pattern.c_str(), &blk, 0);
        while (rc == 0)
        {
            std::string fname = blk.ff_name;
            if (fname != "." && fname != "..")
            {
                std::string fp = dir;
#ifdef _WIN32
                fp += "\\";
#else
                fp += "/";
#endif
                fp += fname;
                ida_instance_record_t rec;
                bool ok = load_record(fp, rec);
                entries.emplace_back(fp, ok ? rec : ida_instance_record_t{});
                if (!ok)
                    entries.back().second.instance_id.clear();
            }
            rc = qfindnext(&blk);
        }
    }

    uint64_t now = now_ms();
    for (auto& kv : entries)
    {
        const std::string& fp = kv.first;
        const ida_instance_record_t& rec = kv.second;

        bool drop = false;
        if (rec.instance_id.empty())
        {
            drop = true;
        }
        else if (rec.instance_id == _self.instance_id)
        {
            continue;
        }
        else
        {
            bool stale_hb = (rec.last_heartbeat_ms == 0)
                || (now > rec.last_heartbeat_ms
                    && (now - rec.last_heartbeat_ms) > static_cast<uint64_t>(kStaleThresholdMs));
            bool dead_pid = !is_pid_alive(rec.pid);
            if (stale_hb || dead_pid)
                drop = true;
        }
        if (drop)
            qunlink(fp.c_str());
    }
}

void instance_registry_t::write_self_file()
{
    std::string path = self_file_path();
    std::string tmp = path + ".tmp";
    json j = _self.to_json();
    std::string content = json_dump_safe(j, 2);
    content += "\n";
    FILE* fp = qfopen(tmp.c_str(), "wb");
    if (!fp)
        return;
    {
        file_janitor_t fj(fp);
        qfwrite(fp, content.c_str(), content.size());
    }
#ifdef _WIN32
    MoveFileExA(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING);
#else
    ::rename(tmp.c_str(), path.c_str());
#endif
}

void instance_registry_t::delete_self_file()
{
    std::string path = self_file_path();
    qunlink(path.c_str());
}

ida_instance_record_t instance_registry_t::self_record() const
{
    std::lock_guard<std::mutex> lk(_mtx);
    return _self;
}

std::vector<ida_instance_record_t> instance_registry_t::live_peers() const
{
    std::lock_guard<std::mutex> lk(_mtx);
    auto all = scan_locked();
    std::vector<ida_instance_record_t> out;
    out.reserve(all.size());
    for (auto& r : all)
    {
        if (r.instance_id != _self.instance_id)
            out.push_back(std::move(r));
    }
    return out;
}

std::vector<ida_instance_record_t> instance_registry_t::all_live_instances() const
{
    std::lock_guard<std::mutex> lk(_mtx);
    auto all = scan_locked();
    bool found_self = false;
    for (auto& r : all)
    {
        if (r.instance_id == _self.instance_id)
        {
            r = _self;
            r.is_self = true;
            found_self = true;
        }
    }
    if (!found_self)
    {
        ida_instance_record_t self_copy = _self;
        self_copy.is_self = true;
        all.push_back(self_copy);
    }
    return all;
}

bool instance_registry_t::find_instance(const std::string& instance_id, ida_instance_record_t& out) const
{
    if (instance_id.empty())
        return false;
    std::lock_guard<std::mutex> lk(_mtx);
    if (instance_id == _self.instance_id)
    {
        out = _self;
        out.is_self = true;
        return true;
    }
    auto all = scan_locked();
    for (auto& r : all)
    {
        if (r.instance_id == instance_id)
        {
            out = r;
            out.is_self = (r.instance_id == _self.instance_id);
            return true;
        }
    }
    return false;
}

bool instance_registry_t::find_instance_by_pid(uint64_t pid, ida_instance_record_t& out) const
{
    if (pid == 0)
        return false;
    std::lock_guard<std::mutex> lk(_mtx);
    if (pid == _self.pid)
    {
        out = _self;
        out.is_self = true;
        return true;
    }
    auto all = scan_locked();
    for (auto& r : all)
    {
        if (r.pid == pid)
        {
            out = r;
            out.is_self = (r.instance_id == _self.instance_id);
            return true;
        }
    }
    return false;
}
