#pragma once

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>

#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <chrono>
#include <algorithm>
#include <cstdint>
#include <mutex>

#include <nlohmann/json.hpp>


namespace task_persistence {


struct task_metadata_t
{
    std::string id;
    std::string title;
    std::string mode_slug        = "agent";
    std::string provider_kind;
    std::string model_name;
    int64_t     created_at       = 0;
    int64_t     updated_at       = 0;
    int         message_count    = 0;
    int64_t     total_input_tokens  = 0;
    int64_t     total_output_tokens = 0;
    double      total_cost_usd   = 0.0;
    std::string status           = "active";
};


struct chat_message_t
{
    std::string text;
    std::string thinking_text;
    bool        is_user         = false;
    bool        has_thinking    = false;
    bool        streaming       = false;
    int64_t     timestamp       = 0;
    int         input_tokens    = 0;
    int         output_tokens   = 0;
    int         cache_read      = 0;
    int         cache_write     = 0;
    bool        is_summary      = false;
    std::string condense_id;
    std::string condense_parent;
    bool        is_truncation_marker = false;
    std::string truncation_id;
    std::string truncation_parent;
    double      cost            = 0.0;
    std::string tool_name;
    bool        is_tool_result  = false;
    std::string model_id;
};


struct api_message_t
{
    std::string role;
    nlohmann::json content;
    int64_t     timestamp       = 0;
    bool        is_summary      = false;
    std::string condense_id;
    std::string condense_parent;
};


inline std::filesystem::path get_tasks_dir()
{
    wchar_t* appdata = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata))) {
        auto dir = std::filesystem::path(appdata) / L"AiDA" / L"Standalone" / L"tasks";
        CoTaskMemFree(appdata);
        return dir;
    }
    return std::filesystem::current_path() / "aida_tasks";
}


inline std::string generate_task_id()
{
    auto now = std::chrono::system_clock::now().time_since_epoch();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
    char buf[64];
    snprintf(buf, sizeof(buf), "task_%lld_%04x",
             static_cast<long long>(ms),
             static_cast<unsigned>(GetTickCount64() & 0xFFFF));
    return buf;
}


inline int64_t unix_timestamp_ms()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}


inline bool write_json_atomic(const std::filesystem::path& target, const std::string& payload)
{
    auto tmp = target;
    tmp += L".tmp";
    {
        std::ofstream ofs(tmp, std::ios::binary | std::ios::trunc);
        if (!ofs) return false;
        ofs.write(payload.data(), static_cast<std::streamsize>(payload.size()));
        if (!ofs.good()) {
            ofs.close();
            std::error_code rm_ec;
            std::filesystem::remove(tmp, rm_ec);
            return false;
        }
        ofs.flush();
        ofs.close();
    }
    if (!MoveFileExW(tmp.c_str(), target.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        std::error_code rm_ec;
        std::filesystem::remove(tmp, rm_ec);
        return false;
    }
    return true;
}

inline std::mutex& task_io_mutex()
{
    static std::mutex m;
    return m;
}

inline bool save_task(
    const std::string& task_id,
    const task_metadata_t& metadata,
    const std::vector<chat_message_t>& chat_messages,
    const std::vector<api_message_t>& api_messages)
{
    if (task_id.empty()) return false;
    if (task_id.find("..") != std::string::npos) return false;
    if (task_id.find('/')  != std::string::npos) return false;
    if (task_id.find('\\') != std::string::npos) return false;
    if (task_id.find(':')  != std::string::npos) return false;

    std::lock_guard<std::mutex> lock(task_io_mutex());

    auto task_dir = get_tasks_dir() / task_id;
    std::error_code ec;
    std::filesystem::create_directories(task_dir, ec);
    if (ec) return false;

    using json = nlohmann::json;

    std::string meta_payload;
    std::string chat_payload;
    std::string api_payload;

    try {
        json meta;
        meta["schema_version"] = 1;
        meta["id"]             = metadata.id;
        meta["title"]          = metadata.title;
        meta["mode_slug"]      = metadata.mode_slug;
        meta["provider_kind"]  = metadata.provider_kind;
        meta["model_name"]     = metadata.model_name;
        meta["created_at"]     = metadata.created_at;
        meta["updated_at"]     = metadata.updated_at;
        meta["message_count"]  = metadata.message_count;
        meta["total_input_tokens"]  = metadata.total_input_tokens;
        meta["total_output_tokens"] = metadata.total_output_tokens;
        meta["total_cost_usd"] = metadata.total_cost_usd;
        meta["status"]         = metadata.status;
        meta_payload = meta.dump(2);

        json arr = json::array();
        for (auto& m : chat_messages) {
            json msg;
            msg["text"]                 = m.text;
            msg["thinking_text"]        = m.thinking_text;
            msg["is_user"]              = m.is_user;
            msg["has_thinking"]         = m.has_thinking;
            msg["streaming"]            = m.streaming;
            msg["timestamp"]            = m.timestamp;
            msg["input_tokens"]         = m.input_tokens;
            msg["output_tokens"]        = m.output_tokens;
            msg["cache_read"]           = m.cache_read;
            msg["cache_write"]          = m.cache_write;
            msg["is_summary"]           = m.is_summary;
            msg["condense_id"]          = m.condense_id;
            msg["condense_parent"]      = m.condense_parent;
            msg["is_truncation_marker"] = m.is_truncation_marker;
            msg["truncation_id"]        = m.truncation_id;
            msg["truncation_parent"]    = m.truncation_parent;
            msg["cost"]                 = m.cost;
            msg["tool_name"]            = m.tool_name;
            msg["is_tool_result"]       = m.is_tool_result;
            msg["model_id"]             = m.model_id;
            arr.push_back(std::move(msg));
        }
        chat_payload = arr.dump();

        json api_arr = json::array();
        for (auto& m : api_messages) {
            json msg;
            msg["role"]            = m.role;
            msg["content"]         = m.content;
            msg["timestamp"]       = m.timestamp;
            msg["is_summary"]      = m.is_summary;
            msg["condense_id"]     = m.condense_id;
            msg["condense_parent"] = m.condense_parent;
            api_arr.push_back(std::move(msg));
        }
        api_payload = api_arr.dump();
    } catch (...) {
        return false;
    }

    auto meta_tmp = task_dir / "metadata.json.tmp";
    auto chat_tmp = task_dir / "chat_messages.json.tmp";
    auto api_tmp  = task_dir / "api_messages.json.tmp";
    auto meta_dst = task_dir / "metadata.json";
    auto chat_dst = task_dir / "chat_messages.json";
    auto api_dst  = task_dir / "api_messages.json";

    auto write_tmp = [](const std::filesystem::path& tmp, const std::string& payload) -> bool {
        std::ofstream ofs(tmp, std::ios::binary | std::ios::trunc);
        if (!ofs) return false;
        ofs.write(payload.data(), static_cast<std::streamsize>(payload.size()));
        if (!ofs.good()) {
            ofs.close();
            std::error_code rm_ec;
            std::filesystem::remove(tmp, rm_ec);
            return false;
        }
        ofs.flush();
        ofs.close();
        return true;
    };

    auto cleanup_tmps = [&]() {
        std::error_code rm_ec;
        std::filesystem::remove(meta_tmp, rm_ec);
        std::filesystem::remove(chat_tmp, rm_ec);
        std::filesystem::remove(api_tmp, rm_ec);
    };

    if (!write_tmp(meta_tmp, meta_payload) ||
        !write_tmp(chat_tmp, chat_payload) ||
        !write_tmp(api_tmp,  api_payload)) {
        cleanup_tmps();
        return false;
    }

    if (!MoveFileExW(meta_tmp.c_str(), meta_dst.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        cleanup_tmps();
        return false;
    }
    if (!MoveFileExW(chat_tmp.c_str(), chat_dst.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        cleanup_tmps();
        return false;
    }
    if (!MoveFileExW(api_tmp.c_str(), api_dst.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        cleanup_tmps();
        return false;
    }

    return true;
}


inline bool load_task_metadata(const std::string& task_id, task_metadata_t& out)
{
    auto meta_path = get_tasks_dir() / task_id / "metadata.json";
    std::ifstream ifs(meta_path, std::ios::binary);
    if (!ifs) return false;

    try {
        auto j = nlohmann::json::parse(ifs);
        if (!j.is_object()) return false;
        auto js = [&](const char* key, const std::string& fallback) -> std::string {
            if (j.contains(key) && j[key].is_string()) return j[key].get<std::string>();
            return fallback;
        };
        auto ji = [&](const char* key, int fallback) -> int {
            if (j.contains(key) && j[key].is_number_integer()) return j[key].get<int>();
            return fallback;
        };
        auto ji64 = [&](const char* key, int64_t fallback) -> int64_t {
            if (j.contains(key) && j[key].is_number_integer()) return j[key].get<int64_t>();
            return fallback;
        };
        auto jd = [&](const char* key, double fallback) -> double {
            if (j.contains(key) && j[key].is_number()) return j[key].get<double>();
            return fallback;
        };
        out.id             = js("id", task_id);
        out.title          = js("title", "");
        out.mode_slug      = js("mode_slug", "agent");
        out.provider_kind  = js("provider_kind", "");
        out.model_name     = js("model_name", "");
        out.created_at     = ji64("created_at", 0);
        out.updated_at     = ji64("updated_at", 0);
        out.message_count  = ji("message_count", 0);
        out.total_input_tokens  = ji64("total_input_tokens", 0);
        out.total_output_tokens = ji64("total_output_tokens", 0);
        out.total_cost_usd = jd("total_cost_usd", 0.0);
        out.status         = js("status", "active");
        return true;
    } catch (...) {
        return false;
    }
}


inline bool load_chat_messages(const std::string& task_id, std::vector<chat_message_t>& out)
{
    auto path = get_tasks_dir() / task_id / "chat_messages.json";
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return false;

    try {
        auto arr = nlohmann::json::parse(ifs);
        if (!arr.is_array()) return false;
        if (arr.size() > 100000) return false;

        out.clear();
        out.reserve((std::min)(arr.size(), static_cast<size_t>(100000)));
        for (auto& j : arr) {
            if (!j.is_object()) continue;
            chat_message_t m;
            auto js = [&](const char* key, const std::string& fallback) -> std::string {
                if (j.contains(key) && j[key].is_string()) return j[key].get<std::string>();
                return fallback;
            };
            auto ji = [&](const char* key, int fallback) -> int {
                if (j.contains(key) && j[key].is_number_integer()) return j[key].get<int>();
                return fallback;
            };
            auto ji64 = [&](const char* key, int64_t fallback) -> int64_t {
                if (j.contains(key) && j[key].is_number_integer()) return j[key].get<int64_t>();
                return fallback;
            };
            auto jb = [&](const char* key, bool fallback) -> bool {
                if (j.contains(key) && j[key].is_boolean()) return j[key].get<bool>();
                return fallback;
            };
            auto jd = [&](const char* key, double fallback) -> double {
                if (j.contains(key) && j[key].is_number()) return j[key].get<double>();
                return fallback;
            };
            m.text                 = js("text", "");
            m.thinking_text        = js("thinking_text", "");
            m.is_user              = jb("is_user", false);
            m.has_thinking         = jb("has_thinking", false);
            m.streaming            = jb("streaming", false);
            m.timestamp            = ji64("timestamp", 0);
            m.input_tokens         = ji("input_tokens", 0);
            m.output_tokens        = ji("output_tokens", 0);
            m.cache_read           = ji("cache_read", 0);
            m.cache_write          = ji("cache_write", 0);
            m.is_summary           = jb("is_summary", false);
            m.condense_id          = js("condense_id", "");
            m.condense_parent      = js("condense_parent", "");
            m.is_truncation_marker = jb("is_truncation_marker", false);
            m.truncation_id        = js("truncation_id", "");
            m.truncation_parent    = js("truncation_parent", "");
            m.cost                 = jd("cost", 0.0);
            m.tool_name            = js("tool_name", "");
            m.is_tool_result       = jb("is_tool_result", false);
            m.model_id             = js("model_id", "");
            out.push_back(std::move(m));
        }
        return true;
    } catch (...) {
        return false;
    }
}


inline bool load_api_messages(const std::string& task_id, std::vector<api_message_t>& out)
{
    auto path = get_tasks_dir() / task_id / "api_messages.json";
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return false;

    try {
        auto arr = nlohmann::json::parse(ifs);
        if (!arr.is_array()) return false;
        if (arr.size() > 100000) return false;

        out.clear();
        out.reserve((std::min)(arr.size(), static_cast<size_t>(100000)));
        for (auto& j : arr) {
            if (!j.is_object()) continue;
            api_message_t m;
            auto js = [&](const char* key, const std::string& fallback) -> std::string {
                if (j.contains(key) && j[key].is_string()) return j[key].get<std::string>();
                return fallback;
            };
            auto ji64 = [&](const char* key, int64_t fallback) -> int64_t {
                if (j.contains(key) && j[key].is_number_integer()) return j[key].get<int64_t>();
                return fallback;
            };
            auto jb = [&](const char* key, bool fallback) -> bool {
                if (j.contains(key) && j[key].is_boolean()) return j[key].get<bool>();
                return fallback;
            };
            m.role            = js("role", "");
            if (j.contains("content"))
                m.content     = j["content"];
            m.timestamp       = ji64("timestamp", 0);
            m.is_summary      = jb("is_summary", false);
            m.condense_id     = js("condense_id", "");
            m.condense_parent = js("condense_parent", "");
            out.push_back(std::move(m));
        }
        return true;
    } catch (...) {
        return false;
    }
}


inline std::vector<task_metadata_t> list_tasks()
{
    std::vector<task_metadata_t> result;
    auto tasks_dir = get_tasks_dir();

    std::error_code ec;
    if (!std::filesystem::exists(tasks_dir, ec))
        return result;

    for (auto& entry : std::filesystem::directory_iterator(tasks_dir, ec)) {
        if (!entry.is_directory()) continue;
        auto dir_name = entry.path().filename().string();
        task_metadata_t meta;
        if (load_task_metadata(dir_name, meta))
            result.push_back(std::move(meta));
    }

    std::sort(result.begin(), result.end(),
        [](const task_metadata_t& a, const task_metadata_t& b) {
            return a.updated_at > b.updated_at;
        });
    return result;
}


inline bool delete_task(const std::string& task_id)
{
    if (task_id.empty()) return false;
    if (task_id.find("..") != std::string::npos) return false;
    if (task_id.find('/')  != std::string::npos) return false;
    if (task_id.find('\\') != std::string::npos) return false;
    if (task_id.find(':')  != std::string::npos) return false;

    std::lock_guard<std::mutex> lock(task_io_mutex());

    auto task_dir = get_tasks_dir() / task_id;
    std::error_code ec;
    if (!std::filesystem::exists(task_dir, ec))
        return false;

    const auto removed = std::filesystem::remove_all(task_dir, ec);
    if (ec) return false;
    return removed > 0;
}


inline std::string extract_title_from_first_message(const std::string& text, int max_len = 60)
{
    if (text.empty()) return "New Chat";
    if (max_len <= 0) return "New Chat";
    const size_t cap = static_cast<size_t>(max_len);
    std::string title = text.substr(0, cap);

    auto nl = title.find('\n');
    if (nl != std::string::npos) title = title.substr(0, nl);

    while (!title.empty() && (title.back() == ' ' || title.back() == '\n' || title.back() == '\r'))
        title.pop_back();

    if (cap > 3 && title.size() >= cap - 3)
        title += "...";

    return title.empty() ? "New Chat" : title;
}

}
