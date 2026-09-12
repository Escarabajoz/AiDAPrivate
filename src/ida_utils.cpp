#include "aida_pro.hpp"
#include <set>
#include <list>
#include <unordered_map>
#include <netnode.hpp>
#include "analysis_db.hpp"

namespace {

struct rag_full_cache_entry_t {
    nlohmann::json full_context;
    std::string    imports_context;
    std::string    type_context;
    std::string    binary_metadata;
    std::chrono::steady_clock::time_point timestamp;
    uint32_t       access_count;
};

class rag_cache_impl_t {
    static constexpr size_t  MAX_ENTRIES       = 1024;
    static constexpr int64_t BASE_TTL_SECONDS  = 300;
    static constexpr int64_t BOOST_PER_ACCESS  = 60;
    static constexpr int64_t MAX_TTL_SECONDS   = 900;
    static constexpr size_t  MAX_PERSISTENT_ENTRIES = 512;
    static constexpr size_t  MAX_PERSISTENT_BYTES   = 4 * 1024 * 1024;
    static constexpr size_t  MAX_PERSISTENT_RECORD_BYTES = 512 * 1024;
    static constexpr uchar   RAG_ENTRY_TAG = 'R';
    static constexpr uchar   RAG_INDEX_TAG = 'I';

    using lru_list_t = std::list<ea_t>;

    struct cache_slot_t {
        rag_full_cache_entry_t entry;
        lru_list_t::iterator   lru_it;
    };

    struct persistent_index_entry_t {
        ea_t      ea = BADADDR;
        nodeidx_t slot = BADNODE;
        uint64_t last_access_ms = 0;
        size_t   bytes = 0;
    };

    std::unordered_map<ea_t, cache_slot_t> _map;
    lru_list_t _lru;
    std::mutex _mtx;
    std::string _last_binary_hash;

    int64_t effective_ttl(uint32_t ac) const
    {
        int64_t ttl = BASE_TTL_SECONDS + static_cast<int64_t>(ac) * BOOST_PER_ACCESS;
        return (ttl < MAX_TTL_SECONDS) ? ttl : MAX_TTL_SECONDS;
    }

    void evict_oldest_locked()
    {
        if (_lru.empty()) return;
        ea_t victim = _lru.back();
        _lru.pop_back();
        _map.erase(victim);
    }

    void touch_locked(typename std::unordered_map<ea_t, cache_slot_t>::iterator it)
    {
        _lru.erase(it->second.lru_it);
        _lru.push_front(it->first);
        it->second.lru_it = _lru.begin();
        it->second.entry.access_count++;
    }

    bool is_expired_locked(const rag_full_cache_entry_t& e) const
    {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - e.timestamp).count();
        return elapsed > effective_ttl(e.access_count);
    }

    // ---- Slice H1: netnode persistence helpers ------------------------------
    static std::string current_binary_hash()
    {
        try { return aida_db::AnalysisDB::instance().get_binary_hash(); }
        catch (...) { return {}; }
    }

    static netnode persistent_netnode(bool create_if_missing)
    {
        return netnode("$ AiDA.rag.cache", 0, create_if_missing);
    }

    static uint64_t hash64(const std::string& s)
    {
        uint64_t h = 1469598103934665603ull;
        for (unsigned char c : s)
        {
            h ^= c;
            h *= 1099511628211ull;
        }
        return h;
    }

    static nodeidx_t slot_for(const std::string& s)
    {
        uint64_t h = hash64(s);
        if (sizeof(nodeidx_t) < sizeof(uint64_t))
            h = (h ^ (h >> 32)) & 0x7fffffffull;
        else
            h &= 0x7fffffffffffffffull;
        nodeidx_t slot = static_cast<nodeidx_t>(h);
        if (slot == BADNODE || slot == 0)
            slot = static_cast<nodeidx_t>(1);
        return slot;
    }

    static nodeidx_t entry_slot(const std::string& hash, ea_t ea)
    {
        return slot_for(std::string("entry:") + hash + ":" + std::to_string(static_cast<uint64_t>(ea)));
    }

    static nodeidx_t index_slot(const std::string& hash)
    {
        return slot_for(std::string("index:") + hash);
    }

    static uint64_t epoch_ms()
    {
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
    }

    // The on-disk record format. Tag MSGPACK + timestamp is in seconds since
    // epoch (steady_clock cannot be persisted), access_count is preserved.
    static std::vector<uint8_t> serialize_entry(const std::string& hash, ea_t ea,
                                                const rag_full_cache_entry_t& e)
    {
        nlohmann::json j;
        j["v"] = 1;
        j["binary_hash"] = hash;
        j["ea"] = static_cast<uint64_t>(ea);
        j["ts_epoch_ms"] = epoch_ms();
        j["ac"] = e.access_count;
        j["full_context"] = e.full_context;
        j["imports_context"] = e.imports_context;
        j["type_context"] = e.type_context;
        j["binary_metadata"] = e.binary_metadata;
        return nlohmann::json::to_msgpack(j);
    }

    static bool deserialize_entry(const std::vector<uint8_t>& blob,
                                  const std::string& expected_hash,
                                  ea_t expected_ea,
                                  rag_full_cache_entry_t& out_entry,
                                  uint64_t& out_ts_epoch_ms)
    {
        try
        {
            auto j = nlohmann::json::from_msgpack(blob);
            if (!j.contains("v")) return false;
            if (j.value("binary_hash", std::string()) != expected_hash)
                return false;
            if (static_cast<ea_t>(j.value("ea", uint64_t(BADADDR))) != expected_ea)
                return false;
            out_ts_epoch_ms = j.value("ts_epoch_ms", uint64_t(0));
            out_entry.access_count = j.value("ac", uint32_t(0));
            out_entry.full_context = j.value("full_context", nlohmann::json());
            out_entry.imports_context = j.value("imports_context", std::string());
            out_entry.type_context = j.value("type_context", std::string());
            out_entry.binary_metadata = j.value("binary_metadata", std::string());
            // Re-anchor steady_clock timestamp so TTL still functions in-session.
            // We treat any stored entry as "fresh enough" on load — TTL is
            // session-scoped expiry, not a wall-clock invariant.
            out_entry.timestamp = std::chrono::steady_clock::now();
            return true;
        }
        catch (...) { return false; }
    }

    static std::vector<persistent_index_entry_t> load_index(const std::string& hash)
    {
        std::vector<persistent_index_entry_t> out;
        if (hash.empty()) return out;
        netnode nn = persistent_netnode(false);
        if (nn == BADNODE) return out;
        qvector<uchar> blob;
        if (nn.getblob(&blob, index_slot(hash), RAG_INDEX_TAG) <= 0)
            return out;
        try
        {
            std::vector<uint8_t> data(blob.begin(), blob.end());
            auto j = nlohmann::json::from_msgpack(data);
            if (j.value("binary_hash", std::string()) != hash)
                return out;
            if (!j.contains("entries") || !j["entries"].is_array())
                return out;
            for (const auto& item : j["entries"])
            {
                persistent_index_entry_t e;
                e.ea = static_cast<ea_t>(item.value("ea", uint64_t(BADADDR)));
                e.slot = static_cast<nodeidx_t>(item.value("slot", uint64_t(BADNODE)));
                e.last_access_ms = item.value("last_access_ms", uint64_t(0));
                e.bytes = item.value("bytes", size_t(0));
                if (e.ea != BADADDR && e.slot != BADNODE)
                    out.push_back(e);
            }
        }
        catch (...) { out.clear(); }
        return out;
    }

    static void save_index(const std::string& hash,
                           const std::vector<persistent_index_entry_t>& entries)
    {
        if (hash.empty()) return;
        netnode nn = persistent_netnode(true);
        if (nn == BADNODE) return;
        nlohmann::json j;
        j["v"] = 1;
        j["binary_hash"] = hash;
        j["entries"] = nlohmann::json::array();
        for (const auto& e : entries)
        {
            j["entries"].push_back({
                {"ea", static_cast<uint64_t>(e.ea)},
                {"slot", static_cast<uint64_t>(e.slot)},
                {"last_access_ms", e.last_access_ms},
                {"bytes", e.bytes}
            });
        }
        auto blob = nlohmann::json::to_msgpack(j);
        if (!blob.empty())
            nn.setblob(blob.data(), blob.size(), index_slot(hash), RAG_INDEX_TAG);
    }

    static void remove_index(const std::string& hash)
    {
        if (hash.empty()) return;
        netnode nn = persistent_netnode(false);
        if (nn == BADNODE) return;
        nn.delblob(index_slot(hash), RAG_INDEX_TAG);
    }

    static void touch_persistent_index(const std::string& hash, ea_t ea,
                                       nodeidx_t slot, size_t bytes)
    {
        if (hash.empty()) return;
        netnode nn = persistent_netnode(true);
        if (nn == BADNODE) return;
        auto entries = load_index(hash);
        bool found = false;
        uint64_t ts = epoch_ms();
        for (auto& e : entries)
        {
            if (e.ea == ea)
            {
                e.slot = slot;
                e.last_access_ms = ts;
                e.bytes = bytes;
                found = true;
                break;
            }
        }
        if (!found)
            entries.push_back({ea, slot, ts, bytes});

        auto total_bytes = [] (const std::vector<persistent_index_entry_t>& vec) {
            size_t total = 0;
            for (const auto& e : vec) total += e.bytes;
            return total;
        };

        while (entries.size() > MAX_PERSISTENT_ENTRIES || total_bytes(entries) > MAX_PERSISTENT_BYTES)
        {
            auto victim = std::min_element(entries.begin(), entries.end(),
                [](const persistent_index_entry_t& a, const persistent_index_entry_t& b) {
                    return a.last_access_ms < b.last_access_ms;
                });
            if (victim == entries.end()) break;
            nn.delblob(victim->slot, RAG_ENTRY_TAG);
            entries.erase(victim);
        }
        save_index(hash, entries);
    }

    static void clear_persistent_hash(const std::string& hash)
    {
        if (hash.empty()) return;
        netnode nn = persistent_netnode(false);
        if (nn == BADNODE) return;
        auto entries = load_index(hash);
        for (const auto& e : entries)
            nn.delblob(e.slot, RAG_ENTRY_TAG);
        remove_index(hash);
    }

    void maybe_invalidate_on_hash_change_locked()
    {
        std::string h = current_binary_hash();
        if (h == _last_binary_hash) return;
        // First-time anchor is not an invalidation.
        if (!_last_binary_hash.empty())
        {
            _map.clear();
            _lru.clear();
        }
        _last_binary_hash = std::move(h);
    }

    bool persist_load_locked(ea_t ea, cache_slot_t& out_slot)
    {
        netnode nn = persistent_netnode(false);
        if (nn == BADNODE || _last_binary_hash.empty()) return false;
        qvector<uchar> qblob;
        nodeidx_t slot = entry_slot(_last_binary_hash, ea);
        ssize_t got = nn.getblob(&qblob, slot, RAG_ENTRY_TAG);
        if (got <= 0) return false;
        std::vector<uint8_t> blob(qblob.begin(), qblob.end());
        rag_full_cache_entry_t entry;
        uint64_t ts_epoch_ms = 0;
        if (!deserialize_entry(blob, _last_binary_hash, ea, entry, ts_epoch_ms)) return false;
        touch_persistent_index(_last_binary_hash, ea, slot, blob.size());
        out_slot.entry = std::move(entry);
        return true;
    }

    void persist_store_locked(ea_t ea, const rag_full_cache_entry_t& e)
    {
        if (_last_binary_hash.empty()) return;
        netnode nn = persistent_netnode(true);
        if (nn == BADNODE) return;
        auto blob = serialize_entry(_last_binary_hash, ea, e);
        if (blob.empty() || blob.size() > MAX_PERSISTENT_RECORD_BYTES) return;
        nodeidx_t slot = entry_slot(_last_binary_hash, ea);
        if (nn.setblob(blob.data(), blob.size(), slot, RAG_ENTRY_TAG))
            touch_persistent_index(_last_binary_hash, ea, slot, blob.size());
    }

    void persist_evict_locked(ea_t ea)
    {
        if (_last_binary_hash.empty()) return;
        netnode nn = persistent_netnode(false);
        if (nn == BADNODE) return;
        nn.delblob(entry_slot(_last_binary_hash, ea), RAG_ENTRY_TAG);
        auto entries = load_index(_last_binary_hash);
        entries.erase(std::remove_if(entries.begin(), entries.end(),
            [ea](const persistent_index_entry_t& e) { return e.ea == ea; }), entries.end());
        if (entries.empty())
            remove_index(_last_binary_hash);
        else
            save_index(_last_binary_hash, entries);
    }

    void persist_clear_locked()
    {
        clear_persistent_hash(_last_binary_hash);
    }

public:
    static rag_cache_impl_t& instance()
    {
        static rag_cache_impl_t inst;
        return inst;
    }

    bool lookup(ea_t ea, std::string& out_imports, std::string& out_types)
    {
        std::lock_guard<std::mutex> lk(_mtx);
        maybe_invalidate_on_hash_change_locked();
        auto it = _map.find(ea);
        if (it == _map.end())
        {
            // LRU miss: try persistent backing.
            cache_slot_t reloaded;
            if (!persist_load_locked(ea, reloaded)) return false;
            // Hydrate LRU.
            while (_map.size() >= MAX_ENTRIES) evict_oldest_locked();
            _lru.push_front(ea);
            reloaded.lru_it = _lru.begin();
            auto [ins_it, _] = _map.emplace(ea, std::move(reloaded));
            out_imports = ins_it->second.entry.imports_context;
            out_types   = ins_it->second.entry.type_context;
            return true;
        }

        if (is_expired_locked(it->second.entry))
        {
            _lru.erase(it->second.lru_it);
            _map.erase(it);
            return false;
        }

        touch_locked(it);
        out_imports = it->second.entry.imports_context;
        out_types   = it->second.entry.type_context;
        return true;
    }

    bool lookup_full(ea_t ea, nlohmann::json& out_context,
                     std::string& out_imports, std::string& out_types,
                     std::string& out_metadata)
    {
        std::lock_guard<std::mutex> lk(_mtx);
        maybe_invalidate_on_hash_change_locked();
        auto it = _map.find(ea);
        if (it == _map.end())
        {
            // Cross-session reload from netnode.
            cache_slot_t reloaded;
            if (!persist_load_locked(ea, reloaded)) return false;
            if (reloaded.entry.full_context.is_null()
                || reloaded.entry.full_context.empty()) return false;
            while (_map.size() >= MAX_ENTRIES) evict_oldest_locked();
            _lru.push_front(ea);
            reloaded.lru_it = _lru.begin();
            auto [ins_it, _] = _map.emplace(ea, std::move(reloaded));
            auto& e = ins_it->second.entry;
            out_context  = e.full_context;
            out_imports  = e.imports_context;
            out_types    = e.type_context;
            out_metadata = e.binary_metadata;
            return true;
        }

        auto& e = it->second.entry;
        if (is_expired_locked(e))
        {
            _lru.erase(it->second.lru_it);
            _map.erase(it);
            return false;
        }

        if (e.full_context.is_null() || e.full_context.empty())
            return false;

        touch_locked(it);
        out_context  = e.full_context;
        out_imports  = e.imports_context;
        out_types    = e.type_context;
        out_metadata = e.binary_metadata;
        return true;
    }

    void store(ea_t ea, const std::string& imports, const std::string& types)
    {
        std::lock_guard<std::mutex> lk(_mtx);
        maybe_invalidate_on_hash_change_locked();
        auto it = _map.find(ea);
        if (it != _map.end())
        {
            it->second.entry.imports_context = imports;
            it->second.entry.type_context    = types;
            it->second.entry.timestamp = std::chrono::steady_clock::now();
            touch_locked(it);
            persist_store_locked(ea, it->second.entry);
            return;
        }

        while (_map.size() >= MAX_ENTRIES)
            evict_oldest_locked();

        _lru.push_front(ea);
        cache_slot_t slot;
        slot.entry.imports_context = imports;
        slot.entry.type_context    = types;
        slot.entry.timestamp       = std::chrono::steady_clock::now();
        slot.entry.access_count    = 0;
        slot.lru_it                = _lru.begin();
        auto [ins_it, _] = _map.emplace(ea, std::move(slot));
        persist_store_locked(ea, ins_it->second.entry);
    }

    void store_full(ea_t ea, const nlohmann::json& context,
                    const std::string& imports, const std::string& types,
                    const std::string& metadata)
    {
        std::lock_guard<std::mutex> lk(_mtx);
        maybe_invalidate_on_hash_change_locked();
        auto it = _map.find(ea);
        if (it != _map.end())
        {
            auto& e          = it->second.entry;
            e.full_context    = context;
            e.imports_context = imports;
            e.type_context    = types;
            e.binary_metadata = metadata;
            e.timestamp       = std::chrono::steady_clock::now();
            touch_locked(it);
            persist_store_locked(ea, e);
            return;
        }

        while (_map.size() >= MAX_ENTRIES)
            evict_oldest_locked();

        _lru.push_front(ea);
        cache_slot_t slot;
        slot.entry.full_context    = context;
        slot.entry.imports_context = imports;
        slot.entry.type_context    = types;
        slot.entry.binary_metadata = metadata;
        slot.entry.timestamp       = std::chrono::steady_clock::now();
        slot.entry.access_count    = 0;
        slot.lru_it                = _lru.begin();
        auto [ins_it, _] = _map.emplace(ea, std::move(slot));
        persist_store_locked(ea, ins_it->second.entry);
    }

    void evict(ea_t ea)
    {
        std::lock_guard<std::mutex> lk(_mtx);
        maybe_invalidate_on_hash_change_locked();
        persist_evict_locked(ea);
        auto it = _map.find(ea);
        if (it != _map.end())
        {
            _lru.erase(it->second.lru_it);
            _map.erase(it);
        }
    }

    void clear()
    {
        std::lock_guard<std::mutex> lk(_mtx);
        maybe_invalidate_on_hash_change_locked();
        persist_clear_locked();
        _map.clear();
        _lru.clear();
    }
};

}

namespace ida_utils
{
    struct decomp_request_t : public exec_request_t
    {
        ea_t ea;
        size_t max_len;
        bool force_assembly;
        get_code_callback_t callback;

        decomp_request_t(ea_t e, size_t ml, bool fa, get_code_callback_t cb)
            : ea(e), max_len(ml), force_assembly(fa), callback(std::move(cb)) {}

        ssize_t idaapi execute() override
        {
            std::pair<std::string, std::string> result;
            try
            {
                result = get_function_code(ea, max_len, force_assembly);
            }
            catch (const std::exception& ex)
            {
                result = { std::string("// Error: ") + ex.what(), "Error" };
            }
            catch (...)
            {
                result = { "// Error: Unknown exception during decompilation.", "Error" };
            }
            if (callback)
                callback(result);
            delete this;
            return 0;
        }
    };

    struct match_info {
        size_t start;
        size_t len;
        qstring replacement;

        bool operator<(const match_info& other) const {
            if (start != other.start)
                return start < other.start;
            return len > other.len;
        }
    };

    static qstring create_markup_replacement(ea_t ea, const std::string& text_to_markup, int color_code)
    {
        qstring replacement;
        tag_addr(&replacement, ea);
        replacement.append(SCOLOR_ON, 1);
        replacement.append(color_code);
        replacement.append(text_to_markup.c_str());
        replacement.append(SCOLOR_OFF, 1);
        replacement.append(color_code);
        tag_addr(&replacement, ea);
        return replacement;
    }

    std::string markup_text_with_addresses(const std::string& text)
    {
        std::vector<match_info> matches;

        static const std::regex pattern(
            "\\b(sub|loc|j_sub|case|def|byte|word|dword|qword|xmmword|ymmword|zmmword|tbyte|asc|str|stru|arr|off|seg|ptr|unk|align)_([0-9A-Fa-f]+)\\b",
            std::regex_constants::icase);

        auto words_begin = std::sregex_iterator(text.begin(), text.end(), pattern);
        auto words_end = std::sregex_iterator();

        for (std::sregex_iterator i = words_begin; i != words_end; ++i)
        {
            std::smatch match = *i;
            std::string full_match_str = match.str(0);
            std::string hex_str = match.str(2);

            ea_t ea = BADADDR;
            try { ea = std::stoull(hex_str, nullptr, 16); }
            catch (...) { continue; }

            if (is_mapped(ea))
            {
                match_info mi;
                mi.start = match.position(0);
                mi.len = match.length(0);
                mi.replacement = create_markup_replacement(ea, full_match_str, COLOR_CNAME);
                matches.push_back(mi);
            }
        }

        const char* special_names[] = { "start", "WinMain", "main" };
        for (const char* name : special_names)
        {
            ea_t ea = get_name_ea(BADADDR, name);
            if (ea != BADADDR)
            {
                std::string s_name(name);
                size_t pos = text.find(s_name, 0);
                while (pos != std::string::npos)
                {
                    bool pre_ok = (pos == 0) || !is_word_char(text[pos - 1]);
                    bool post_ok = (pos + s_name.length() >= text.length()) || !is_word_char(text[pos + s_name.length()]);
                    if (pre_ok && post_ok)
                    {
                        match_info mi;
                        mi.start = pos;
                        mi.len = s_name.length();
                        mi.replacement = create_markup_replacement(ea, s_name, COLOR_CNAME);
                        matches.push_back(mi);
                    }
                    pos = text.find(s_name, pos + 1);
                }
            }
        }

        static const std::regex hex_pattern("\\b(0x[0-9A-Fa-f]{7,16})\\b", std::regex_constants::icase);
        auto hex_begin = std::sregex_iterator(text.begin(), text.end(), hex_pattern);
        auto hex_end = std::sregex_iterator();

        for (std::sregex_iterator i = hex_begin; i != hex_end; ++i)
        {
            std::smatch match = *i;
            std::string hex_str = match.str(1);

            ea_t ea = BADADDR;
            try { ea = std::stoull(hex_str, nullptr, 16); }
            catch (...) { continue; }

            if (is_mapped(ea))
            {
                match_info mi;
                mi.start = match.position(0);
                mi.len = match.length(0);
                mi.replacement = create_markup_replacement(ea, hex_str, COLOR_DREF);
                matches.push_back(mi);
            }
        }

        std::sort(matches.begin(), matches.end());
        std::vector<match_info> final_matches;
        if (!matches.empty())
        {
            final_matches.push_back(matches[0]);
            for (size_t i = 1; i < matches.size(); ++i)
            {
                if (matches[i].start >= (final_matches.back().start + final_matches.back().len))
                {
                    final_matches.push_back(matches[i]);
                }
            }
        }

        qstring result;
        size_t last_pos = 0;
        for (const auto& mi : final_matches)
        {
            result.append(text.c_str() + last_pos, mi.start - last_pos);
            result.append(mi.replacement);
            last_pos = mi.start + mi.len;
        }
        result.append(text.c_str() + last_pos);

        return result.c_str();
    }

    static std::string truncate_string(const std::string& s, size_t max_len)
    {
        if (s.length() > max_len)
        {
            if (max_len <= 3)
                return s.substr(0, max_len);
            return s.substr(0, max_len - 3) + "...";
        }
        return s;
    }

    std::pair<std::string, std::string> get_function_code(ea_t ea, size_t max_len, bool force_assembly)
    {
        if (max_len == 0)
        {
            size_t context_tokens = static_cast<size_t>(g_settings.get_active_context_window());
            max_len = (std::min)(context_tokens * 3, static_cast<size_t>(262144));
        }

        if (!force_assembly && init_hexrays_plugin())
        {
            try
            {
                func_t* pfn_for_decomp = get_func(ea);
                if (pfn_for_decomp != nullptr && is_safely_decompilable(pfn_for_decomp))
                {
                    cfuncptr_t cfunc = decompile_func(pfn_for_decomp, nullptr, DECOMP_NO_WAIT);
                    if (cfunc != nullptr)
                    {
                        qstring code_qstr;
                        qstring_printer_t printer(cfunc, code_qstr, false);
                        cfunc->print_func(printer);
                        return { truncate_string(code_qstr.c_str(), max_len), "C/C++" };
                    }
                }
            }
            catch (const vd_failure_t&)
            {
                msg("AiDA: Decompilation failed at 0x%llx, falling back to assembly.\n", ea);
            }
        }

        func_t* pfn = get_func(ea);
        if (pfn == nullptr)
        {
            qstring err;
            err.sprnt("// Error: Couldn't get function at 0x%llx", ea);
            return { err.c_str(), "Error" };
        }

        text_t disasm_text;
        gen_disasm_text(disasm_text, pfn->start_ea, pfn->end_ea, false);

        std::stringstream ss;
        for (const twinline_t& tw_line : disasm_text)
        {
            qstring clean_line;
            tag_remove(&clean_line, tw_line.line.c_str());
            ss << clean_line.c_str() << '\n';
        }
        return { truncate_string(ss.str(), max_len), "Assembly" };
    }

    void get_function_code(ea_t ea, get_code_callback_t callback, size_t max_len, bool force_assembly)
    {
        auto req = new decomp_request_t(ea, max_len, force_assembly, std::move(callback));
        execute_sync(*req, MFF_WRITE | MFF_NOWAIT);
    }

    static void recursive_get_xrefs_context(
        ea_t target_ea,
        const settings_t& settings,
        bool find_callers,
        int current_depth,
        std::set<ea_t>& visited_funcs,
        qstring& result,
        int& count)
    {
        if (current_depth >= settings.xref_analysis_depth || count >= settings.xref_context_count)
            return;

        if (visited_funcs.count(target_ea))
            return;
        visited_funcs.insert(target_ea);

        if (current_depth > 0)
        {
            qstring name;
            get_func_name(&name, target_ea);
            if (name.empty())
                name.sprnt("sub_%llx", target_ea);

            auto code_pair = get_function_code(target_ea, settings.xref_code_snippet_lines * 80);
            const char* direction = find_callers ? "Called by" : "Calls";

            result.cat_sprnt("// --- %s: %s at 0x%llx (Depth: %d) ---\n",
                direction, name.c_str(), target_ea, current_depth);
            result.cat_sprnt("// Language: %s\n", code_pair.second.c_str());
            result.cat_sprnt("```cpp\n%s\n```\n\n", code_pair.first.c_str());
            count++;
        }

        if (find_callers)
        {
            xrefblk_t xb;
            for (bool ok = xb.first_to(target_ea, XREF_ALL); ok && count < settings.xref_context_count; ok = xb.next_to())
            {
                if (xb.iscode)
                {
                    func_t* pfn = get_func(xb.from);
                    if (pfn)
                        recursive_get_xrefs_context(pfn->start_ea, settings, find_callers, current_depth + 1, visited_funcs, result, count);
                }
            }
        }
        else
        {
            func_t* pfn = get_func(target_ea);
            if (pfn)
            {
                func_item_iterator_t fii(pfn);
                for (bool ok = fii.first(); ok && count < settings.xref_context_count; ok = fii.next_head())
                {
                    xrefblk_t xb;
                    for (bool ok_ref = xb.first_from(fii.current(), XREF_ALL); ok_ref && count < settings.xref_context_count; ok_ref = xb.next_from())
                    {
                        if (xb.iscode && (xb.type == fl_CN || xb.type == fl_CF))
                        {
                            func_t* callee_pfn = get_func(xb.to);
                            if (callee_pfn)
                                recursive_get_xrefs_context(callee_pfn->start_ea, settings, find_callers, current_depth + 1, visited_funcs, result, count);
                        }
                    }
                }
            }
        }
    }

    std::string get_code_xrefs_to(ea_t ea, const settings_t& settings)
    {
        qstring result;
        int count = 0;
        std::set<ea_t> visited_funcs;
        recursive_get_xrefs_context(ea, settings, true, 0, visited_funcs, result, count);
        if (result.empty())
            return "// No code cross-references found.";
        return result.c_str();
    }

    std::string get_code_xrefs_from(ea_t ea, const settings_t& settings)
    {
        qstring result;
        int count = 0;
        std::set<ea_t> visited_funcs;
        recursive_get_xrefs_context(ea, settings, false, 0, visited_funcs, result, count);
        if (result.empty())
            return "// No calls to other functions found.";
        return result.c_str();
    }

    static std::string get_struct_usage_from_cfunc(cfuncptr_t cfunc, ssize_t this_var_idx, const tinfo_t& struct_tif, ea_t ea)
    {
        qstring struct_name;
        struct_tif.get_type_name(&struct_name);
        if (struct_name.empty())
            struct_name.sprnt("struct_at_0x%llx", ea);

        struct member_access_visitor_t : public ctree_visitor_t
        {
            cfunc_t* cfunc;
            ssize_t this_var_idx;
            std::map<uint64, std::set<std::string>> accesses;
            std::map<ea_t, std::string> stringified_insns;

            member_access_visitor_t(cfunc_t* cf, ssize_t idx)
                : ctree_visitor_t(CV_PARENTS), cfunc(cf), this_var_idx(idx) {}

            cinsn_t* get_parent_insn()
            {
                for (ssize_t i = parents.size() - 1; i >= 0; --i)
                {
                    citem_t* p = parents[i];
                    if (!p->is_expr())
                        return (cinsn_t*)p;
                }
                return nullptr;
            }

            int idaapi visit_expr(cexpr_t* expr) override
            {
                if ((expr->op == cot_memptr || expr->op == cot_memref) && expr->x && expr->x->op == cot_var)
                {
                    if (expr->x->v.idx == this_var_idx)
                    {
                        uint64 member_offset = expr->m;
                        cinsn_t* parent_insn = get_parent_insn();
                        if (parent_insn)
                        {
                            ea_t insn_ea = parent_insn->ea;
                            if (stringified_insns.find(insn_ea) == stringified_insns.end())
                            {
                                qstring line;
                                qstring_printer_t pr(cfunc, line, false);
                                parent_insn->print(0, pr);
                                tag_remove(&line);
                                stringified_insns[insn_ea] = line.c_str();
                            }
                            qstring usage_line;
                            usage_line.sprnt("// 0x%llx: %s", expr->ea, stringified_insns[insn_ea].c_str());
                            accesses[member_offset].insert(usage_line.c_str());
                        }
                        else
                        {
                            qstring insn_str;
                            expr->print1(&insn_str, cfunc);
                            tag_remove(&insn_str);
                            qstring usage_line;
                            usage_line.sprnt("// 0x%llx: %s", expr->ea, insn_str.c_str());
                            accesses[member_offset].insert(usage_line.c_str());
                        }
                    }
                }
                return 0;
            }
        };

        member_access_visitor_t visitor(cfunc, this_var_idx);
        visitor.apply_to(&cfunc->body, nullptr);

        if (visitor.accesses.empty())
        {
            qstring result;
            result.sprnt("// No direct member accesses for struct '%s' found in this function.", struct_name.c_str());
            return result.c_str();
        }

        qstring output;
        output.sprnt("// Member accesses for struct '%s' found in this function:\n", struct_name.c_str());
        for (const auto& pair : visitor.accesses)
        {
            udm_t udm;
            if (struct_tif.get_udm_by_offset(&udm, pair.first * 8) >= 0)
            {
                output.cat_sprnt("//   - Member: %s (offset 0x%X)\n", udm.name.c_str(), (uint32)udm.offset / 8);
            }
            else
            {
                output.cat_sprnt("//   - Member at offset 0x%X\n", (uint32)pair.first);
            }
            for (const auto& usage : pair.second)
            {
                output.cat_sprnt("//     usage: %s\n", usage.c_str());
            }
        }
        return output.c_str();
    }

    std::string get_struct_usage_context(ea_t ea)
    {
        func_t* pfn = get_func(ea);
        if (pfn == nullptr)
            return "// Struct usage analysis requires a valid function context.";

        if (!is_safely_decompilable(pfn))
            return "// Struct usage analysis requires a decompilable function.";

        cfuncptr_t cfunc(nullptr);
        try
        {
            mba_ranges_t mbr(pfn);
            cfunc = decompile(mbr, nullptr, DECOMP_NO_WAIT);
        }
        catch (const vd_failure_t&)
        {
            return "// Struct usage analysis requires a decompilable function.";
        }
        catch (...)
        {
            return "// Struct usage analysis requires a decompilable function.";
        }

        if (!cfunc)
            return "// Struct usage analysis requires a decompilable function.";

        lvars_t* lvars = cfunc->get_lvars();
        if (!lvars || lvars->empty())
            return "// No local variables found for struct usage analysis.";

        ssize_t this_var_idx = -1;
        tinfo_t struct_tif;

        for (ssize_t i = 0; i < (ssize_t)lvars->size(); ++i)
        {
            lvar_t& lvar = (*lvars)[i];
            if (lvar.is_thisarg() || (lvar.is_arg_var() && lvar.type().is_ptr() && lvar.type().get_pointed_object().is_udt()))
            {
                this_var_idx = i;
                struct_tif = lvar.type().get_pointed_object();
                break;
            }
        }

        if (this_var_idx == -1 || !struct_tif.is_udt())
            return "// Could not identify a struct pointer argument for usage analysis.";

        return get_struct_usage_from_cfunc(cfunc, this_var_idx, struct_tif, ea);
    }

    std::string get_data_xrefs_for_struct(const tinfo_t& struct_tif, const settings_t& settings)
    {
        if (!struct_tif.is_udt())
            return "// Not a valid UDT (struct/union).";

        qstring struct_name;
        struct_tif.get_type_name(&struct_name);
        if (struct_name.empty())
            struct_name = "anonymous_struct";

        qstring output;
        output.sprnt("// Data cross-references to members of struct '%s':\n", struct_name.c_str());
        bool found_any = false;

        udt_type_data_t udt_data;
        if (!struct_tif.get_udt_details(&udt_data))
            return output.c_str();

        for (size_t i = 0; i < udt_data.size(); ++i)
        {
            const udm_t& udm = udt_data[i];
            tid_t member_tid = struct_tif.get_udm_tid(i);
            if (member_tid == BADADDR)
                continue;

            qstrvec_t member_xrefs;
            xrefblk_t xb;
            for (bool ok = xb.first_to(member_tid, XREF_DATA); ok && member_xrefs.size() < (size_t)settings.xref_context_count; ok = xb.next_to())
            {
                qstring func_name_qstr = "UnknownFunction";
                func_t* pfn = get_func(xb.from);
                if (pfn)
                    get_func_name(&func_name_qstr, pfn->start_ea);
                std::string func_name = func_name_qstr.c_str();

                char xtype_char = xrefchar(xb.type);
                const char* access_type = (xtype_char == 'w') ? "Write" : (xtype_char == 'r') ? "Read" : "Offset";

                qstring disasm_line_qstr;
                generate_disasm_line(&disasm_line_qstr, xb.from, GENDSM_REMOVE_TAGS);
                disasm_line_qstr.trim2();
                std::string disasm_line = disasm_line_qstr.c_str();

                qstring line;
                line.sprnt("//  - %s in %s at 0x%llx: %s", access_type, func_name.c_str(), xb.from, disasm_line.c_str());
                member_xrefs.push_back(line);
            }

            if (!member_xrefs.empty())
            {
                found_any = true;
                output.cat_sprnt("// Member: %s::%s (offset 0x%X)\n", struct_name.c_str(), udm.name.c_str(), (uint32)(udm.offset / 8));
                for (const auto& xref_line : member_xrefs)
                {
                    output.append(xref_line);
                    output.append("\n");
                }
                output.append("\n");
            }
        }

        if (!found_any)
        {
            output.sprnt("// No data cross-references found for members of struct '%s'.", struct_name.c_str());
        }

        return output.c_str();
    }

    nlohmann::json get_context_for_prompt(ea_t ea, bool include_struct_context, size_t max_len)
    {
        func_t* pfn = get_func(ea);
        if (pfn == nullptr)
        {
            qstring err_msg;
            err_msg.sprnt("No function found at address 0x%llx.", ea);
            return { {"ok", false}, {"message", err_msg.c_str()} };
        }

        if (max_len == 0)
        {
            size_t context_tokens = static_cast<size_t>(g_settings.get_active_context_window());
            max_len = (std::min)(context_tokens * 3, static_cast<size_t>(262144));
        }

        qstring ea_hex_str;
        ea_hex_str.sprnt("%llx", ea);

        cfuncptr_t cfunc(nullptr);
        bool decompile_ok = false;
        std::string code_str;
        std::string language;
        lvars_t* lvars = nullptr;

        if (init_hexrays_plugin() && is_safely_decompilable(pfn))
        {
            try
            {
                mba_ranges_t mbr(pfn);
                cfunc = decompile(mbr, nullptr, DECOMP_NO_WAIT);
                if (cfunc)
                {
                    decompile_ok = true;
                    qstring code_qstr;
                    qstring_printer_t printer(cfunc, code_qstr, false);
                    cfunc->print_func(printer);
                    code_str = truncate_string(code_qstr.c_str(), max_len);
                    language = "C/C++";
                    lvars = cfunc->get_lvars();
                }
            }
            catch (const vd_failure_t&)
            {
                decompile_ok = false;
            }
        }

        if (!decompile_ok)
        {
            text_t disasm_text;
            gen_disasm_text(disasm_text, pfn->start_ea, pfn->end_ea, false);
            std::stringstream ss;
            for (const twinline_t& tw_line : disasm_text)
            {
                qstring clean_line;
                tag_remove(&clean_line, tw_line.line.c_str());
                ss << clean_line.c_str() << '\n';
            }
            code_str = truncate_string(ss.str(), max_len);
            language = "Assembly";
        }

        if (code_str.empty())
        {
            qstring err_msg;
            err_msg.sprnt("Could not get code for function at 0x%llx.", ea);
            return { {"ok", false}, {"message", err_msg.c_str()} };
        }

        nlohmann::json context = {
            {"ok", true},
            {"code", code_str},
            {"language", language},
            {"func_ea_hex", ea_hex_str.c_str()},
            {"xrefs_to", get_code_xrefs_to(ea, g_settings)},
            {"xrefs_from", get_code_xrefs_from(ea, g_settings)},
        };

        tinfo_t func_tif;
        if (get_tinfo(&func_tif, ea))
        {
            qstring func_proto;
            func_tif.print(&func_proto, "", 0, 0, PRTYPE_1LINE | PRTYPE_NOARGS);
            context["func_prototype"] = func_proto.c_str();
        }
        else
        {
            context["func_prototype"] = "// Could not retrieve function prototype.";
        }

        context["local_vars"] = "// Decompilation failed or not available.";
        context["decompiler_warnings"] = "// No decompiler warnings.";
        context["type_context"] = "// No custom types referenced by this function.";
        if (include_struct_context)
            context["struct_context"] = "// Decompilation failed or not available.";

        if (decompile_ok)
        {
            if (lvars && !lvars->empty())
            {
                qstring lvars_str;
                for (const auto& lv : *lvars)
                {
                    lvars_str.cat_sprnt("// %s %s; // location: %s, size: %d\n",
                        lv.type().dstr(),
                        lv.name.c_str(),
                        lv.location.dstr(),
                        lv.width);
                }
                context["local_vars"] = lvars_str.c_str();
            }
            else
            {
                context["local_vars"] = "// No local variables found.";
            }

            hexwarns_t& warns = cfunc->get_warnings();
            if (!warns.empty())
            {
                qstring warns_str;
                for (const auto& warn : warns)
                {
                    warns_str.append(warn.text.c_str());
                    warns_str.append("\n");
                }
                context["decompiler_warnings"] = warns_str.c_str();
            }

            if (lvars)
            {
                qstring type_result;
                std::set<qstring> found_types;
                for (const auto& lv : *lvars)
                {
                    tinfo_t tif = lv.type();
                    if (tif.is_ptr())
                        tif = tif.get_pointed_object();

                    if (tif.is_udt() || tif.is_enum())
                    {
                        qstring type_name;
                        tif.get_type_name(&type_name);
                        if (!type_name.empty() && found_types.find(type_name) == found_types.end())
                        {
                            found_types.insert(type_name);
                            qstring type_def;
                            tif.print(&type_def);
                            type_result.cat_sprnt("// Type: %s\n%s\n\n", type_name.c_str(), type_def.c_str());
                        }
                    }
                }
                if (!type_result.empty())
                    context["type_context"] = type_result.c_str();
            }

            if (include_struct_context)
            {
                tinfo_t struct_tif;
                lvar_t* this_lvar = nullptr;
                ssize_t this_var_idx = -1;
                if (lvars)
                {
                    for (ssize_t i = 0; i < (ssize_t)lvars->size(); ++i)
                    {
                        lvar_t& lv = (*lvars)[i];
                        if (lv.is_thisarg())
                        {
                            this_lvar = &lv;
                            this_var_idx = i;
                            break;
                        }
                    }
                    if (this_lvar == nullptr)
                    {
                        for (ssize_t i = 0; i < (ssize_t)lvars->size(); ++i)
                        {
                            lvar_t& lv = (*lvars)[i];
                            if (lv.is_arg_var() && lv.type().is_ptr() && lv.type().get_pointed_object().is_udt())
                            {
                                this_lvar = &lv;
                                this_var_idx = i;
                                break;
                            }
                        }
                    }
                }
                if (this_lvar && this_lvar->type().is_ptr())
                {
                    struct_tif = this_lvar->type().get_pointed_object();
                }

                if (struct_tif.is_udt() && this_var_idx >= 0)
                {
                    std::string usage_context = get_struct_usage_from_cfunc(cfunc, this_var_idx, struct_tif, ea);
                    std::string data_xref_context = get_data_xrefs_for_struct(struct_tif, g_settings);
                    context["struct_context"] = usage_context + "\n\n" + data_xref_context;
                }
                else
                {
                    context["struct_context"] = "// No struct context could be determined for this function.";
                }
            }
        }

        static constexpr size_t MAX_STRING_XREFS = 50;
        qstring string_xrefs_str = "// No string literals referenced.\n";
        std::set<qstring> found_strings;
        func_item_iterator_t fii(pfn);
        for (bool ok = fii.first(); ok && found_strings.size() < MAX_STRING_XREFS; ok = fii.next_head())
        {
            xrefblk_t xb;
            for (bool ok_ref = xb.first_from(fii.current(), XREF_DATA);
                 ok_ref && found_strings.size() < MAX_STRING_XREFS;
                 ok_ref = xb.next_from())
            {
                flags64_t s_flags = get_flags(xb.to);
                if (is_strlit(s_flags))
                {
                    int32 strtype = get_str_type(xb.to);
                    qstring s;
                    if (get_strlit_contents(&s, xb.to, -1, strtype) > 0)
                    {
                        if (found_strings.find(s) == found_strings.end())
                        {
                            if (found_strings.empty()) string_xrefs_str.clear();
                            string_xrefs_str.cat_sprnt("\"%s\"\n", s.c_str());
                            found_strings.insert(s);
                        }
                    }
                }
            }
        }
        if (found_strings.size() >= MAX_STRING_XREFS)
            string_xrefs_str.cat_sprnt("// ... (capped at %zu strings)\n", MAX_STRING_XREFS);
        context["string_xrefs"] = string_xrefs_str.c_str();
        return context;
    }

    std::string format_prompt(const char* prompt_template, const nlohmann::json& context)
    {
        std::string result = prompt_template;
        for (auto const& [key, val] : context.items())
        {
            if (!val.is_string())
                continue;
            std::string placeholder = "{" + key + "}";
            const std::string& replacement = val.get_ref<const std::string&>();
            size_t pos = result.find(placeholder);
            while (pos != std::string::npos)
            {
                result.replace(pos, placeholder.length(), replacement);
                pos = result.find(placeholder, pos + replacement.length());
            }
        }
        return result;
    }

    void apply_struct_from_cpp(const std::string& cpp_code, ea_t ea)
    {
        std::string struct_code;
        std::smatch match_md;
        static const std::regex md_code_re("```(?:cpp)?\\s*([\\s\\S]*?)\\s*```");
        if (std::regex_search(cpp_code, match_md, md_code_re))
        {
            struct_code = match_md[1].str();
        }
        else
        {
            if (cpp_code.find("struct") != std::string::npos)
            {
                struct_code = cpp_code;
            }
            else
            {
                warning("AI response did not contain a C++ struct definition.\n"
                        "Full response:\n%s", cpp_code.c_str());
                return;
            }
        }

        struct_code.erase(0, struct_code.find_first_not_of(" \t\n\r"));
        struct_code.erase(struct_code.find_last_not_of(" \t\n\r") + 1);

        std::smatch match_name;
        static const std::regex struct_name_re("struct\\s+([a-zA-Z_][a-zA-Z0-9_]*)");
        if (!std::regex_search(struct_code, match_name, struct_name_re))
        {
            warning("AiDA: Could not find a valid struct name in the AI-generated code.");
            msg("--- Invalid Code Snippet ---\n%s\n----------------------------\n", struct_code.c_str());
            return;
        }
        std::string original_struct_name = match_name[1].str();
        std::string final_struct_name = original_struct_name;

        til_t* idati = get_idati();
        if (get_type_ordinal(idati, final_struct_name.c_str()) != 0)
        {
            qstring question;
            question.sprnt("A struct named '%s' already exists. What would you like to do?", final_struct_name.c_str());

            int choice = ask_buttons("~O~verwrite", "~R~ename", "~C~ancel", ASKBTN_CANCEL, question.c_str());

            if (choice == ASKBTN_YES)
            {
                msg("AiDA: Struct '%s' already exists, overwriting.\n", final_struct_name.c_str());
                if (!del_named_type(idati, final_struct_name.c_str(), NTF_TYPE))
                {
                    warning("AiDA: Failed to delete existing struct '%s'. Aborting overwrite.", final_struct_name.c_str());
                    return;
                }
            }
            else if (choice == ASKBTN_NO)
            {
                int counter = 1;
                do
                {
                    qstring temp_qstr;
                    temp_qstr.sprnt("%s_%d", original_struct_name.c_str(), counter++);
                    final_struct_name = temp_qstr.c_str();
                } while (get_type_ordinal(idati, final_struct_name.c_str()) != 0);
                msg("AiDA: Renaming to '%s' to avoid conflict.\n", final_struct_name.c_str());
            }
            else
            {
                msg("AiDA: Struct creation cancelled by user.\n");
                return;
            }
        }

        if (final_struct_name != original_struct_name)
        {
            struct_code = std::regex_replace(struct_code, std::regex("struct\\s+" + original_struct_name), "struct " + final_struct_name);
        }

        msg("--- AiDA: Attempting to parse the following C++ struct ---\n%s\n--------------------------------------------------------\n", struct_code.c_str());

        if (parse_decls(idati, struct_code.c_str(), msg, HTI_DCL) != 0)
        {
            warning("AiDA: Failed to parse the C++ struct. See the Output window for details and the code that was attempted.");
            return;
        }

        msg("AiDA: Struct '%s' created/updated successfully.\n", final_struct_name.c_str());

        uint32 ordinal = get_type_ordinal(idati, final_struct_name.c_str());
        if (ordinal != 0)
        {
            open_loctypes_window(ordinal);
        }

        func_t* pfn = get_func(ea);
        if (pfn == nullptr)
        {
            msg("AiDA: No function at 0x%llx to apply type to.\n", ea);
            return;
        }

        if (!init_hexrays_plugin() || !is_safely_decompilable(pfn))
        {
            msg("AiDA: Hex-Rays decompiler not available. Cannot automatically apply type to function arguments.\n");
            return;
        }

        try
        {
            cfuncptr_t cfunc = decompile_func(pfn, nullptr, DECOMP_NO_WAIT);
            if (cfunc == nullptr)
            {
                warning("AiDA: Could not decompile function at 0x%llx to apply type.", ea);
                return;
            }

            lvars_t* lvars = cfunc->get_lvars();
            lvar_t* target_lvar = nullptr;

            if (lvars)
            {
                for (auto& lv : *lvars)
                {
                    if (lv.is_thisarg())
                    {
                        target_lvar = &lv;
                        break;
                    }
                }
                if (target_lvar == nullptr)
                {
                    for (auto& lv : *lvars)
                    {
                        if (lv.is_arg_var() && lv.type().is_ptr())
                        {
                            target_lvar = &lv;
                            break;
                        }
                    }
                }
            }

            if (target_lvar)
            {
                qstring new_type_str;
                new_type_str.sprnt("%s*", final_struct_name.c_str());

                tinfo_t tif;
                if (tif.parse(new_type_str.c_str()))
                {
                    lvar_saved_info_t lsi;
                    lsi.ll = *target_lvar;
                    lsi.type = tif;

                    if (modify_user_lvar_info(pfn->start_ea, MLI_TYPE, lsi))
                    {
                        msg("AiDA: Applied type '%s' to argument '%s'.\n", new_type_str.c_str(), target_lvar->name.c_str());
                        mark_cfunc_dirty(pfn->start_ea, true);
                    }
                    else
                    {
                        warning("AiDA: Failed to apply type '%s' to lvar '%s'.", new_type_str.c_str(), target_lvar->name.c_str());
                    }
                }
            }
            else
            {
                msg("AiDA: Could not find a suitable argument to apply the new struct type to.\n");
            }
        }
        catch (const vd_failure_t&)
        {
            warning("AiDA: Decompilation failed, cannot automatically apply type.");
        }
        catch (const std::exception& e)
        {
            warning("AiDA: An unexpected error occurred during type application: %s", e.what());
        }
    }
    bool is_word_char(char c)
    {
        return qisalnum(c) || c == '_' || c == ':';
    }

    struct func_chooser_t : public chooser_t
    {
        const std::vector<ea_t>& funcs;
        func_chooser_t(const std::vector<ea_t>& f)
           : chooser_t(CH_MODAL, 1, WIDTHS, HEADER, "Select a function that references this item"), funcs(f) {}

        const void* get_obj_id(size_t* len) const override
        {
            *len = sizeof(this);
            return this;
        }

        size_t idaapi get_count() const override { return funcs.size(); }
        void idaapi get_row(
            qstrvec_t* out,
            int* ,
            chooser_item_attrs_t* ,
            size_t n) const override
        {
            qstring func_name;
            get_func_name(&func_name, funcs[n]);
            out->push_back(func_name);
        }

        static const int WIDTHS[];
        static const char* const HEADER[];
    };

    const int func_chooser_t::WIDTHS[] = { 30 };
    const char* const func_chooser_t::HEADER[] = { "Function" };

    func_t* get_function_for_item(ea_t ea)
    {
        func_t* pfn = get_func(ea);
        if (pfn != nullptr)
        {
            return pfn;
        }

        qstring name;
        ea_t item_ea = get_item_head(ea);
        if (!get_name(&name, item_ea))
        {
            warning("AiDA: Please place the cursor inside a function or on a named data item.");
            return nullptr;
        }

        xrefblk_t xb;
        std::set<ea_t> func_eas;
        for (bool ok = xb.first_to(item_ea, XREF_ALL); ok; ok = xb.next_to())
        {
            if (xb.iscode)
            {
                func_t* ref_pfn = get_func(xb.from);
                if (ref_pfn)
                {
                    func_eas.insert(ref_pfn->start_ea);
                }
            }
        }

        if (func_eas.empty())
        {
            warning("AiDA: No code references found to '%s'. Action requires a function context.", name.c_str());
            return nullptr;
        }

        if (func_eas.size() == 1)
        {
            return get_func(*func_eas.begin());
        }

        std::vector<ea_t> func_vec(func_eas.begin(), func_eas.end());
        func_chooser_t chooser(func_vec);
        ssize_t selected_idx = chooser.choose();

        if (selected_idx < 0)
        {
            return nullptr;
        }

        return get_func(func_vec[selected_idx]);
    }

    qstring qstring_tolower(const qstring& s)
    {
        qstring lower_s = s;
        qstrlwr(lower_s.begin());
        return lower_s;
    }

    bool get_address_from_line_pos(ea_t* out_ea, const char* , int )
    {
        TWidget* view = get_current_viewer();
        if (view == nullptr)
            return false;

        listing_location_t lloc;
        if (get_custom_viewer_location(&lloc, view, CVLF_USE_MOUSE))
        {
            if (lloc.loc != nullptr && lloc.loc->place() != nullptr)
            {
                if (const ea_t ea = lloc.loc->place()->toea(); ea != BADADDR)
                {
                    *out_ea = ea;
                    return true;
                }
            }
        }
        return false;
    }

    static qstring escape_for_idc(const std::string& s)
    {
        qstring escaped;
        escaped.reserve(s.length() * 2);
        for (char c : s)
        {
            switch (c)
            {
            case '"':  escaped.append("\\\""); break;
            case '\\': escaped.append("\\\\"); break;
            case '\n': escaped.append("\\n");  break;
            case '\r': escaped.append("\\r");  break;
            case '\t': escaped.append("\\t");  break;
            default:
                if (c < 32 || static_cast<unsigned char>(c) > 126)
                {
                    escaped.cat_sprnt("\\x%02X", static_cast<unsigned char>(c));
                }
                else
                {
                    escaped.append(c);
                }
                break;
            }
        }
        return escaped;
    }

    bool set_clipboard_text(const qstring& text)
    {
#ifdef _WIN32
        if (!OpenClipboard(nullptr))
        {
            warning("AiDA: Could not open clipboard.");
            return false;
        }

        struct clipboard_closer_t
        {
            ~clipboard_closer_t() { CloseClipboard(); }
        } closer;

        if (!EmptyClipboard())
        {
            warning("AiDA: Could not empty clipboard.");
            return false;
        }

        qwstring wtext;
        if (!utf8_utf16(&wtext, text.c_str()))
        {
            warning("AiDA: Failed to convert text to UTF-16 for clipboard.");
            return false;
        }

        size_t wlen = wtext.length();
        HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, (wlen + 1) * sizeof(wchar16_t));
        if (hg == nullptr)
        {
            warning("AiDA: GlobalAlloc failed for clipboard.");
            return false;
        }

        wchar16_t* locked_mem = (wchar16_t*)GlobalLock(hg);
        if (locked_mem == nullptr)
        {
            warning("AiDA: GlobalLock failed for clipboard.");
            GlobalFree(hg);
            return false;
        }

        memcpy(locked_mem, wtext.c_str(), (wlen + 1) * sizeof(wchar16_t));
        GlobalUnlock(hg);

        if (SetClipboardData(CF_UNICODETEXT, hg) == nullptr)
        {
            warning("AiDA: SetClipboardData failed.");
            GlobalFree(hg);
            return false;
        }

        return true;
#elif defined(__LINUX__) || defined(__linux__)
#ifdef fwrite
#undef fwrite
#endif
        const char* commands[] = { "wl-copy", "xclip -selection clipboard" };
        for (const char* cmd : commands) {
            FILE* pipe = popen(cmd, "w");
            if (pipe) {
                fwrite(text.c_str(), 1, text.length(), pipe);
                pclose(pipe);
                return true;
            }
        }
        warning("AiDA: Could not find 'wl-copy' or 'xclip' to set clipboard.");
        return false;
#else
        warning("AiDA: Clipboard copy not implemented for this platform.");
        return false;
#endif
    }

    std::string format_context_for_clipboard(const nlohmann::json& context)
    {
        std::stringstream ss;

        ss << "Function: " << json_str(context, "func_ea_hex", "N/A") << "\n";
        ss << "Prototype: " << json_str(context, "func_prototype", "// N/A") << "\n\n";

        ss << "--- Decompiled " << json_str(context, "language", "Code") << " ---\n";
        ss << json_str(context, "code", "// No code available.") << "\n\n";

        ss << "--- Local Variables ---\n";
        ss << json_str(context, "local_vars", "// No local variables found.") << "\n\n";

        ss << "--- String Literals Referenced ---\n";
        ss << json_str(context, "string_xrefs", "// No string literals referenced.") << "\n\n";

        ss << "--- Callers (Functions that call this one) ---\n";
        ss << json_str(context, "xrefs_to", "// No callers found.") << "\n\n";

        ss << "--- Callees (Functions this one calls) ---\n";
        ss << json_str(context, "xrefs_from", "// No callees found.") << "\n\n";

        if (context.contains("struct_context")) {
            ss << "--- Struct Member Usage & Data Cross-References ---\n";
            ss << json_str(context, "struct_context", "// No struct context available.") << "\n\n";
        }

        ss << "--- Decompiler Warnings ---\n";
        ss << json_str(context, "decompiler_warnings", "// No decompiler warnings.") << "\n";

        return ss.str();
    }

    qstring apply_renames_from_ai(ea_t func_ea, const std::string& cpp_code)
    {
        if (!init_hexrays_plugin())
        {
            warning("AiDA: Renaming requires the Hex-Rays decompiler.");
            return "";
        }

        func_t* pfn = get_func(func_ea);
        if (pfn == nullptr)
        {
            warning("AiDA: Function at 0x%llx not found for renaming.", func_ea);
            return "";
        }

        if (!is_safely_decompilable(pfn))
        {
            warning("AiDA: Function at 0x%llx is not decompilable (thunk/extern/tail).", func_ea);
            return "";
        }

        cfuncptr_t cfunc(nullptr);
        try
        {
            cfunc = decompile_func(pfn, nullptr, DECOMP_NO_WAIT);
        }
        catch (const vd_failure_t&) { cfunc = cfuncptr_t(nullptr); }
        catch (...) { cfunc = cfuncptr_t(nullptr); }
        if (cfunc == nullptr)
        {
            warning("AiDA: Decompilation failed for function at 0x%llx.", func_ea);
            return "";
        }

        std::string rename_block;
        std::smatch match_md;
        static const std::regex md_code_re2("```(?:cpp)?\\s*([\\s\\S]*?)\\s*```");
        if (std::regex_search(cpp_code, match_md, md_code_re2))
        {
            rename_block = match_md[1].str();
        }
        else
        {
            rename_block = cpp_code;
        }

        std::stringstream ss(rename_block);
        std::string line;
        qstring summary;
        int renamed_count = 0;

        while (std::getline(ss, line))
        {
            if (line.rfind("//", 0) != 0)
                continue;

            size_t arrow_pos = line.find("->");
            if (arrow_pos == std::string::npos)
                continue;

            std::string left_part_str = line.substr(2, arrow_pos - 2);
            std::string right_part_str = line.substr(arrow_pos + 2);

            size_t comment_pos = right_part_str.find("//");
            if (comment_pos != std::string::npos)
                right_part_str = right_part_str.substr(0, comment_pos);

            qstring q_left(left_part_str.c_str());
            q_left.trim2();
            if (q_left.ends_with(";"))
                q_left.remove_last();
            q_left.trim2();

            qstring q_right(right_part_str.c_str());
            q_right.trim2();
            if (q_right.ends_with(";"))
                q_right.remove_last();
            q_right.trim2();


            auto sanitize_name = [](qstring& s) {
                ssize_t paren = s.find('(');
                if (paren != -1)
                    s.resize(paren);

                ssize_t bracket = s.find('[');
                if (bracket != -1)
                    s.resize(bracket);

                s.trim2();

                ssize_t pos = s.rfind(' ');
                if (pos == -1)
                    pos = s.rfind('*');

                if (pos != -1)
                    s = s.substr(pos + 1);

                s.trim2();
            };

            qstring original_name = q_left;
            qstring new_name = q_right;
            sanitize_name(original_name);
            sanitize_name(new_name);

            if (original_name.empty() || new_name.empty() || original_name == new_name)
                continue;

            bool renamed = false;
            lvars_t* lvars = cfunc->get_lvars();
            if (lvars)
            {
                for (lvar_t& lv : *lvars)
                {
                    if (lv.name == original_name)
                    {
                        lvar_saved_info_t lsi;
                        lsi.ll = lv;
                        lsi.name = new_name;
                        if (modify_user_lvar_info(func_ea, MLI_NAME, lsi))
                        {
                            summary.cat_sprnt("Local variable: %s -> %s\n", original_name.c_str(), new_name.c_str());
                            renamed = true;
                            renamed_count++;
                        }
                        else
                        {
                            msg("AiDA: Failed to rename local variable '%s' to '%s'.\n", original_name.c_str(), new_name.c_str());
                        }
                        break;
                    }
                }
            }

            if (!renamed)
            {
                ea_t addr = get_name_ea(func_ea, original_name.c_str());
                if (addr != BADADDR)
                {
                    bool is_local_to_func = func_contains(pfn, addr);
                    bool name_is_relevant = is_local_to_func;

                    if (!name_is_relevant)
                    {
                        xrefblk_t xb;
                        for (bool ok = xb.first_to(addr, XREF_ALL); ok; ok = xb.next_to())
                        {
                            if (func_contains(pfn, xb.from))
                            {
                                name_is_relevant = true;
                                break;
                            }
                        }
                    }

                    if (name_is_relevant)
                    {
                        if (set_name(addr, new_name.c_str(), SN_FORCE | SN_NODUMMY))
                        {
                            summary.cat_sprnt("%s: %s -> %s (at 0x%llx)\n",
                                is_local_to_func ? "Local label" : "Global name",
                                original_name.c_str(), new_name.c_str(), addr);
                            renamed = true;
                            renamed_count++;
                        }
                        else
                        {
                            msg("AiDA: Failed to rename '%s' to '%s'.\n", original_name.c_str(), new_name.c_str());
                        }
                    }
                }
            }

            if (!renamed)
            {
                segment_t* seg = get_segm_by_name(original_name.c_str());
                if (seg != nullptr)
                {
                    if (set_segm_name(seg, new_name.c_str()) != 0)
                    {
                        summary.cat_sprnt("Segment: %s -> %s\n", original_name.c_str(), new_name.c_str());
                        renamed = true;
                        renamed_count++;
                        mark_builtin_widgets(IWID_SEGS | IWID_DISASM);
                    }
                    else
                    {
                        msg("AiDA: Failed to rename segment '%s' to '%s'.\n", original_name.c_str(), new_name.c_str());
                    }
                }
            }

            if (!renamed)
            {
                til_t* til = get_idati();
                tinfo_t tif;
                if (tif.get_named_type(til, original_name.c_str()))
                {
                    if (tif.is_udt() || tif.is_enum())
                    {
                        if (tif.rename_type(new_name.c_str()) == TERR_OK)
                        {
                            summary.cat_sprnt("%s: %s -> %s\n",
                                tif.is_udt() ? "Struct/Union" : "Enum",
                                original_name.c_str(), new_name.c_str());
                            renamed = true;
                            renamed_count++;
                            mark_builtin_widgets(IWID_TILS | IWID_TITREE);
                        }
                        else
                        {
                            msg("AiDA: Failed to rename type '%s' to '%s'.\n", original_name.c_str(), new_name.c_str());
                        }
                    }
                }
            }
        }

        if (renamed_count > 0)
        {
            msg("AiDA: Applied %d renames.\n", renamed_count);
            invalidate_rag_cache();
        }

        return summary;
    }

    std::string get_binary_metadata()
    {
        static std::string cached;
        if (!cached.empty())
            return cached;

        qstring result;

        char input_file[QMAXPATH];
        get_input_file_path(input_file, sizeof(input_file));
        result.cat_sprnt("// Binary: %s\n", input_file);

        qstring proc_name = inf_get_procname();
        result.cat_sprnt("// Processor: %s\n", proc_name.c_str());

        int bitness = inf_is_64bit() ? 64 : (inf_is_32bit_exactly() ? 32 : 16);
        result.cat_sprnt("// Bitness: %d-bit\n", bitness);

        filetype_t ft = inf_get_filetype();
        const char* ft_name = "Unknown";
        switch (ft)
        {
        case f_PE:      ft_name = "PE (Windows)"; break;
        case f_ELF:     ft_name = "ELF (Linux/Unix)"; break;
        case f_MACHO:   ft_name = "Mach-O (macOS/iOS)"; break;
        case f_BIN:     ft_name = "Raw Binary"; break;
        case f_COFF:    ft_name = "COFF"; break;
        default:        break;
        }
        result.cat_sprnt("// File type: %s\n", ft_name);

        comp_t cc = inf_get_cc_id();
        const char* cc_name = "Unknown";
        switch (cc)
        {
        case COMP_MS:   cc_name = "Visual C++"; break;
        case COMP_GNU:  cc_name = "GNU GCC"; break;
        case COMP_BC:   cc_name = "Borland C++"; break;
        default:        break;
        }
        result.cat_sprnt("// Compiler: %s\n", cc_name);

        result.cat_sprnt("// Image base: 0x%llx\n", inf_get_min_ea());

        cached = result.c_str();
        return cached;
    }

    std::string get_imports_for_function(ea_t ea)
    {
        func_t* pfn = get_func(ea);
        if (pfn == nullptr)
            return "// No function context for import analysis.";

        qstring result;
        result.reserve(1024);
        std::set<qstring> found_imports;

        func_item_iterator_t fii(pfn);
        for (bool ok = fii.first(); ok; ok = fii.next_head())
        {
            xrefblk_t xb;
            for (bool ok_ref = xb.first_from(fii.current(), XREF_ALL); ok_ref; ok_ref = xb.next_from())
            {
                if (!xb.iscode)
                    continue;

                segment_t* seg = getseg(xb.to);
                if (seg == nullptr)
                    continue;

                qstring seg_name;
                get_segm_name(&seg_name, seg);

                bool is_import = (seg_name == ".idata" || seg_name == ".plt" ||
                                  seg_name == "__stubs" || seg_name == "extern" ||
                                  seg->type == SEG_XTRN);

                if (is_import)
                {
                    qstring import_name;
                    if (get_name(&import_name, xb.to) && !import_name.empty())
                    {
                        if (found_imports.find(import_name) == found_imports.end())
                        {
                            found_imports.insert(import_name);
                            result.cat_sprnt("// Import: %s (at 0x%llx)\n", import_name.c_str(), xb.to);
                        }
                    }
                }
            }
        }

        if (result.empty())
            return "// No imported functions called by this function.";

        return result.c_str();
    }

    std::string get_type_context_for_function(ea_t ea)
    {
        if (!init_hexrays_plugin())
            return "// Decompiler not available for type context analysis.";

        func_t* pfn = get_func(ea);
        if (pfn == nullptr)
            return "// No function context.";

        if (!is_safely_decompilable(pfn))
            return "// Function is not decompilable (thunk/extern/tail).";

        qstring result;
        std::set<qstring> found_types;

        try
        {
            cfuncptr_t cfunc = decompile_func(pfn, nullptr, DECOMP_NO_WAIT);
            if (cfunc == nullptr)
                return "// Decompilation failed.";

            lvars_t* lvars = cfunc->get_lvars();
            if (lvars)
            {
                for (const auto& lv : *lvars)
                {
                    tinfo_t tif = lv.type();
                    if (tif.is_ptr())
                        tif = tif.get_pointed_object();

                    if (tif.is_udt() || tif.is_enum())
                    {
                        qstring type_name;
                        tif.get_type_name(&type_name);
                        if (!type_name.empty() && found_types.find(type_name) == found_types.end())
                        {
                            found_types.insert(type_name);

                            qstring type_def;
                            tif.print(&type_def);
                            result.cat_sprnt("// Type: %s\n%s\n\n", type_name.c_str(), type_def.c_str());
                        }
                    }
                }
            }
        }
        catch (const vd_failure_t&)
        {
            return "// Decompilation failed for type context.";
        }

        if (result.empty())
            return "// No custom types referenced by this function.";

        return result.c_str();
    }

    nlohmann::json get_rag_context(ea_t ea, const settings_t& , const nlohmann::json* cached_context)
    {
        nlohmann::json rag;

        func_t* pfn = get_func(ea);
        ea_t func_start = pfn ? pfn->start_ea : ea;

        std::string metadata = get_binary_metadata();
        if (pfn)
        {
            qstring neighbors;
            neighbors.reserve(512);
            ea_t cursor = pfn->start_ea;
            for (int i = 0; i < 3; ++i)
            {
                func_t* p = get_prev_func(cursor);
                if (!p) break;
                cursor = p->start_ea;
                qstring name;
                get_func_name(&name, cursor);
                if (!name.empty())
                    neighbors.cat_sprnt("// Nearby: %s (0x%llx)\n", name.c_str(), cursor);
            }
            cursor = pfn->start_ea;
            for (int i = 0; i < 3; ++i)
            {
                func_t* n = get_next_func(cursor);
                if (!n) break;
                cursor = n->start_ea;
                qstring name;
                get_func_name(&name, cursor);
                if (!name.empty())
                    neighbors.cat_sprnt("// Nearby: %s (0x%llx)\n", name.c_str(), cursor);
            }
            if (!neighbors.empty())
            {
                metadata += "\n";
                metadata += neighbors.c_str();
            }
        }
        rag["binary_metadata"] = std::move(metadata);

        std::string cached_imports, cached_types;
        if (rag_cache_impl_t::instance().lookup(func_start, cached_imports, cached_types))
        {
            rag["imports_context"] = std::move(cached_imports);
            if (cached_context && cached_context->contains("type_context")
                && (*cached_context)["type_context"].is_string())
            {
                rag["type_context"] = (*cached_context)["type_context"];
            }
            else
            {
                rag["type_context"] = std::move(cached_types);
            }
        }
        else
        {
            std::string imports = get_imports_for_function(ea);
            std::string types;
            if (cached_context && cached_context->contains("type_context")
                && (*cached_context)["type_context"].is_string())
            {
                types = (*cached_context)["type_context"].get<std::string>();
            }
            else
            {
                types = get_type_context_for_function(ea);
            }
            rag["imports_context"] = imports;
            rag["type_context"]    = types;

            rag_cache_impl_t::instance().store(func_start, imports, types);
        }

        return rag;
    }

    void invalidate_rag_cache()
    {
        rag_cache_impl_t::instance().clear();
    }

    void invalidate_rag_cache_for(ea_t ea)
    {
        func_t* pfn = get_func(ea);
        rag_cache_impl_t::instance().evict(pfn ? pfn->start_ea : ea);
    }

    nlohmann::json get_full_cached_context(ea_t ea, const settings_t& settings,
                                           bool include_struct_context, size_t max_len)
    {
        using nlohmann::json;

        func_t* pfn = get_func(ea);
        ea_t func_start = pfn ? pfn->start_ea : ea;

        if (max_len != 0 || !pfn)
        {
            json context = get_context_for_prompt(ea, include_struct_context, max_len);
            if (context.contains("ok") && context["ok"].is_boolean() && context["ok"].get<bool>())
            {
                json rag = get_rag_context(ea, settings, &context);
                context["binary_metadata"] = json_str(rag, "binary_metadata", "// No metadata available.");
                context["imports_context"] = json_str(rag, "imports_context", "// No import context.");
                context["type_context"]    = json_str(rag, "type_context", "// No type context.");
            }
            return context;
        }

        json cached_ctx;
        std::string cached_imports, cached_types, cached_metadata;
        if (rag_cache_impl_t::instance().lookup_full(
                func_start, cached_ctx, cached_imports, cached_types, cached_metadata))
        {
            cached_ctx["binary_metadata"] = !cached_metadata.empty()
                ? cached_metadata : get_binary_metadata();
            cached_ctx["imports_context"] = cached_imports;
            if (!cached_types.empty())
                cached_ctx["type_context"] = cached_types;
            return cached_ctx;
        }

        json context = get_context_for_prompt(ea, true, 0);
        if (!(context.contains("ok") && context["ok"].is_boolean() && context["ok"].get<bool>()))
            return context;

        json rag = get_rag_context(ea, settings, &context);
        std::string metadata = json_str(rag, "binary_metadata", "// No metadata available.");
        std::string imports  = json_str(rag, "imports_context", "// No import context.");
        std::string types    = json_str(context, "type_context", "// No custom types referenced by this function.");

        context["binary_metadata"] = metadata;
        context["imports_context"] = imports;

        rag_cache_impl_t::instance().store_full(func_start, context, imports, types, metadata);

        return context;
    }

    void apply_struct_from_cpp_ex(const std::string& cpp_code, ea_t ea, const std::string& target_param)
    {
        std::string struct_code;
        std::smatch match_md;
        static const std::regex md_code_re3("```(?:cpp)?\\s*([\\s\\S]*?)\\s*```");
        if (std::regex_search(cpp_code, match_md, md_code_re3))
        {
            struct_code = match_md[1].str();
        }
        else if (cpp_code.find("struct") != std::string::npos || cpp_code.find("enum") != std::string::npos)
        {
            struct_code = cpp_code;
        }
        else
        {
            warning("AiDA: AI response did not contain a C++ type definition.\nFull response:\n%s", cpp_code.c_str());
            return;
        }

        struct_code.erase(0, struct_code.find_first_not_of(" \t\n\r"));
        struct_code.erase(struct_code.find_last_not_of(" \t\n\r") + 1);

        std::smatch match_name;
        std::string type_keyword;
        static const std::regex type_name_re("(struct|enum|union)\\s+([a-zA-Z_][a-zA-Z0-9_]*)");
        if (std::regex_search(struct_code, match_name, type_name_re))
        {
            type_keyword = match_name[1].str();
        }
        else
        {
            warning("AiDA: Could not find a valid type name in the AI-generated code.");
            return;
        }
        std::string original_type_name = match_name[2].str();
        std::string final_type_name = original_type_name;

        til_t* idati = get_idati();

        if (get_type_ordinal(idati, final_type_name.c_str()) != 0)
        {
            qstring question;
            question.sprnt("A type named '%s' already exists. What would you like to do?", final_type_name.c_str());

            int choice = ask_buttons("~O~verwrite", "~R~ename", "~C~ancel", ASKBTN_CANCEL, question.c_str());

            if (choice == ASKBTN_YES)
            {
                msg("AiDA: Type '%s' already exists, overwriting.\n", final_type_name.c_str());
                if (!del_named_type(idati, final_type_name.c_str(), NTF_TYPE))
                {
                    warning("AiDA: Failed to delete existing type '%s'. Aborting.", final_type_name.c_str());
                    return;
                }
            }
            else if (choice == ASKBTN_NO)
            {
                int counter = 1;
                do
                {
                    qstring temp_qstr;
                    temp_qstr.sprnt("%s_%d", original_type_name.c_str(), counter++);
                    final_type_name = temp_qstr.c_str();
                } while (get_type_ordinal(idati, final_type_name.c_str()) != 0);
                msg("AiDA: Renaming to '%s' to avoid conflict.\n", final_type_name.c_str());
            }
            else
            {
                msg("AiDA: Type creation cancelled.\n");
                return;
            }
        }

        if (final_type_name != original_type_name)
        {
            struct_code = std::regex_replace(struct_code,
                std::regex("(struct|enum|union)\\s+" + original_type_name),
                type_keyword + " " + final_type_name);
        }

        msg("--- AiDA: Attempting to parse the following type definition ---\n%s\n-----------------------------------------------------------\n",
            struct_code.c_str());

        if (parse_decls(idati, struct_code.c_str(), msg, HTI_DCL) != 0)
        {
            warning("AiDA: Failed to parse the type definition. See Output window.");
            return;
        }

        msg("AiDA: Type '%s' created/updated successfully.\n", final_type_name.c_str());

        invalidate_rag_cache();

        uint32 ordinal = get_type_ordinal(idati, final_type_name.c_str());
        if (ordinal != 0)
        {
            open_loctypes_window(ordinal);
        }

        func_t* pfn = get_func(ea);
        if (pfn == nullptr || !init_hexrays_plugin())
            return;

        try
        {
            cfuncptr_t cfunc = decompile_func(pfn, nullptr, DECOMP_NO_WAIT);
            if (cfunc == nullptr)
                return;

            lvars_t* lvars = cfunc->get_lvars();
            lvar_t* target_lvar = nullptr;

            if (lvars)
            {
                if (!target_param.empty())
                {
                    for (auto& lv : *lvars)
                    {
                        if (lv.name == target_param.c_str())
                        {
                            target_lvar = &lv;
                            break;
                        }
                    }
                }

                if (!target_lvar)
                {
                    for (auto& lv : *lvars)
                    {
                        if (lv.is_thisarg())
                        {
                            target_lvar = &lv;
                            break;
                        }
                    }
                    if (!target_lvar)
                    {
                        for (auto& lv : *lvars)
                        {
                            if (lv.is_arg_var() && lv.type().is_ptr())
                            {
                                target_lvar = &lv;
                                break;
                            }
                        }
                    }
                }
            }

            if (target_lvar)
            {
                qstring new_type_str;
                new_type_str.sprnt("%s*", final_type_name.c_str());

                tinfo_t tif;
                if (tif.parse(new_type_str.c_str()))
                {
                    lvar_saved_info_t lsi;
                    lsi.ll = *target_lvar;
                    lsi.type = tif;

                    if (modify_user_lvar_info(pfn->start_ea, MLI_TYPE, lsi))
                    {
                        msg("AiDA: Applied type '%s' to argument '%s'.\n",
                            new_type_str.c_str(), target_lvar->name.c_str());
                        mark_cfunc_dirty(pfn->start_ea, true);
                    }
                    else
                    {
                        warning("AiDA: Failed to apply type '%s' to lvar '%s'.",
                            new_type_str.c_str(), target_lvar->name.c_str());
                    }
                }
            }
            else
            {
                msg("AiDA: No suitable argument found to apply the new type to.\n");
            }
        }
        catch (const vd_failure_t&)
        {
            warning("AiDA: Decompilation failed, cannot apply type.");
        }
        catch (const std::exception& e)
        {
            warning("AiDA: Error during type application: %s", e.what());
        }
    }

    bool update_existing_struct(const std::string& struct_name, const std::string& new_definition)
    {
        til_t* idati = get_idati();

        if (get_type_ordinal(idati, struct_name.c_str()) != 0)
        {
            if (!del_named_type(idati, struct_name.c_str(), NTF_TYPE))
            {
                msg("AiDA: Failed to delete existing type '%s' for update.\n", struct_name.c_str());
                return false;
            }
        }

        if (parse_decls(idati, new_definition.c_str(), msg, HTI_DCL) != 0)
        {
            msg("AiDA: Failed to parse updated type definition for '%s'.\n", struct_name.c_str());
            return false;
        }

        msg("AiDA: Type '%s' updated successfully.\n", struct_name.c_str());
        invalidate_rag_cache();
        return true;
    }

    bool is_safely_decompilable(func_t* pfn)
    {
        if (pfn == nullptr)
            return false;


        if (pfn->flags & FUNC_TAIL)
            return false;


        if (pfn->flags & FUNC_THUNK)
            return false;


        if (pfn->flags & FUNC_OUTLINE)
            return false;


        if (pfn->size() == 0)
            return false;


        segment_t* seg = getseg(pfn->start_ea);
        if (seg != nullptr && seg->type == SEG_XTRN)
            return false;

        return true;
    }
}
