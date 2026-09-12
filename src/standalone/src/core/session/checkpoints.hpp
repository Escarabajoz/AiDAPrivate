#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <cstdint>
#include <chrono>
#include <sstream>
#include <algorithm>

#include <nlohmann/json.hpp>

#include "session_store.hpp"
#include "event_bus.hpp"


namespace checkpoints {

namespace detail {
inline std::string& last_error_ref()
{
    static std::string s_last_error;
    return s_last_error;
}
inline void set_last_error(const std::string& msg)
{
    last_error_ref() = msg;
}

inline bool safe_path_component(const std::string& value)
{
    return !value.empty() && value != "." && value != ".." &&
           value.find_first_of("/\\:") == std::string::npos;
}

inline bool safe_relative_path(const std::filesystem::path& path)
{
    if (path.empty() || path.is_absolute() || path.has_root_name() || path.has_root_directory())
        return false;
    for (const auto& component : path) {
        if (component.empty() || component == "." || component == ".." ||
            component.native().find(L':') != std::wstring::npos)
            return false;
    }
    return true;
}
}

inline const std::string& last_error()
{
    return detail::last_error_ref();
}


struct file_snapshot_t
{
    std::string relative_path;
    std::string content_hash;
    int64_t     size = 0;
};


struct checkpoint_t
{
    std::string id;
    std::string task_id;
    std::string message;
    int64_t     timestamp = 0;
    int         message_index = -1;
    std::vector<file_snapshot_t> files;
};


inline std::string make_checkpoint_id()
{
    static std::atomic<uint64_t> seq{0};
    const uint64_t n = seq.fetch_add(1, std::memory_order_relaxed) + 1;
    auto now = std::chrono::system_clock::now().time_since_epoch();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
    char buf[48];
    snprintf(buf, sizeof(buf),
             "cp_%lld_%llu",
             static_cast<long long>(ms),
             static_cast<unsigned long long>(n));
    return buf;
}


inline bool write_file_atomic(const std::filesystem::path& dest, const char* data, size_t size)
{
    std::error_code ec;
    std::filesystem::create_directories(dest.parent_path(), ec);
    if (ec) return false;
    auto tmp = dest;
    tmp += ".tmp";
    {
        std::ofstream ofs(tmp, std::ios::binary | std::ios::trunc);
        if (!ofs) return false;
        if (size > 0) ofs.write(data, static_cast<std::streamsize>(size));
        ofs.flush();
        if (!ofs) return false;
    }
    if (!MoveFileExW(tmp.c_str(), dest.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        std::filesystem::remove(tmp, ec);
        return false;
    }
    return true;
}


inline std::string hash_content(const std::string& content)
{
    uint64_t h = 14695981039346656037ULL;
    for (unsigned char c : content) {
        h ^= c;
        h *= 1099511628211ULL;
    }
    char buf[20];
    snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(h));
    return buf;
}


class service_t
{
public:
    explicit service_t(const std::string& workspace_root) : _workspace(workspace_root) {}

    void set_storage_dir(const std::string& dir) { _storage = dir; }

    bool save_checkpoint(
        const std::string& task_id,
        const std::string& message,
        int message_index,
        const std::vector<std::string>& tracked_files)
    {
        std::lock_guard<std::mutex> lk(_mutex);

        if (!detail::safe_path_component(task_id)) return false;

        checkpoint_t cp;
        cp.id = make_checkpoint_id();
        cp.task_id = task_id;
        cp.message = message;
        cp.message_index = message_index;
        cp.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        auto cp_dir = checkpoint_dir(task_id, cp.id);
        std::error_code ec;
        std::filesystem::create_directories(cp_dir, ec);
        if (ec) return false;

        for (const auto& rel_path : tracked_files) {
            const std::filesystem::path relative(rel_path);
            if (!detail::safe_relative_path(relative)) return false;
            auto full_path = std::filesystem::path(_workspace) / relative;
            ec.clear();
            const bool exists = std::filesystem::exists(full_path, ec);
            if (ec) return false;
            if (!exists) continue;

            std::ifstream ifs(full_path, std::ios::binary);
            if (!ifs) return false;

            std::string content((std::istreambuf_iterator<char>(ifs)),
                                 std::istreambuf_iterator<char>());

            file_snapshot_t snap;
            snap.relative_path = rel_path;
            snap.content_hash = hash_content(content);
            snap.size = static_cast<int64_t>(content.size());
            cp.files.push_back(snap);

            auto dest = std::filesystem::path(cp_dir) / relative;
            if (!write_file_atomic(dest, content.data(), content.size())) {
                return false;
            }
        }

        if (!save_manifest_locked(task_id, cp)) return false;

        auto& task_cps = _checkpoints[task_id];
        task_cps.push_back(cp);
        return true;
    }

    bool restore_checkpoint(const std::string& task_id, const std::string& checkpoint_id)
    {
        std::lock_guard<std::mutex> lk(_mutex);

        if (!detail::safe_path_component(task_id) ||
            !detail::safe_path_component(checkpoint_id)) return false;

        auto cp_dir = checkpoint_dir(task_id, checkpoint_id);
        if (!std::filesystem::exists(cp_dir)) return false;

        auto manifest = load_manifest_locked(task_id, checkpoint_id);
        if (manifest.id.empty()) return false;

        for (const auto& snap : manifest.files) {
            const std::filesystem::path relative(snap.relative_path);
            if (!detail::safe_relative_path(relative)) return false;
            auto src = std::filesystem::path(cp_dir) / relative;
            auto dest = std::filesystem::path(_workspace) / relative;

            std::error_code ec;
            const bool exists = std::filesystem::exists(src, ec);
            if (ec || !exists) return false;

            std::ifstream ifs(src, std::ios::binary);
            if (!ifs) return false;

            std::string content((std::istreambuf_iterator<char>(ifs)),
                                 std::istreambuf_iterator<char>());

            if (!write_file_atomic(dest, content.data(), content.size())) {
                return false;
            }
        }

        return true;
    }

    bool rewind_to_checkpoint(
        const std::string& task_id,
        const std::string& session_id,
        const std::string& checkpoint_id)
    {
        if (session_id.empty() || checkpoint_id.empty()) {
            detail::set_last_error("rewind_invalid_args");
            return false;
        }

        if (!restore_checkpoint(task_id, checkpoint_id)) {
            detail::set_last_error("rewind_restore_failed");
            return false;
        }

        int target_index = -1;
        {
            std::lock_guard<std::mutex> lk(_mutex);
            auto manifest = load_manifest_locked(task_id, checkpoint_id);
            if (manifest.id.empty()) {
                detail::set_last_error("rewind_manifest_missing_after_restore");
                return false;
            }
            target_index = manifest.message_index;
        }

        std::vector<aida::session::message_t> messages;
        if (!aida::session::list_messages(session_id, messages, -1)) {
            detail::set_last_error(
                std::string("rewind_list_messages_failed: ") + aida::session::last_error());
            return false;
        }

        for (size_t i = 0; i < messages.size(); ++i) {
            if (static_cast<int>(i) <= target_index) continue;
            if (!aida::session::remove_message(session_id, messages[i].id)) {
                detail::set_last_error(
                    std::string("rewind_remove_message_failed: ") + aida::session::last_error());
                return false;
            }
        }

        {
            aida::events::session_updated_t evt;
            evt.session_id     = session_id;
            evt.fields_changed = "messages,total_cost,checkpoint";
            aida::events::publish(aida::events::event_session_updated, evt);
        }

        return true;
    }

    std::vector<checkpoint_t> list_checkpoints(const std::string& task_id) const
    {
        std::lock_guard<std::mutex> lk(_mutex);

        std::vector<checkpoint_t> result;
        if (!detail::safe_path_component(task_id)) return result;
        auto task_dir = std::filesystem::path(_storage) / task_id;
        if (std::filesystem::exists(task_dir)) {
            for (const auto& entry : std::filesystem::directory_iterator(task_dir)) {
                if (!entry.is_directory()) continue;
                auto cp = load_manifest_locked(task_id, entry.path().filename().string());
                if (!cp.id.empty())
                    result.push_back(cp);
            }
        }

        auto it = _checkpoints.find(task_id);
        if (it != _checkpoints.end()) {
            for (const auto& cached : it->second) {
                bool already = false;
                for (const auto& existing : result) {
                    if (existing.id == cached.id) { already = true; break; }
                }
                if (!already) result.push_back(cached);
            }
        }

        std::sort(result.begin(), result.end(),
                  [](const checkpoint_t& a, const checkpoint_t& b) { return a.timestamp < b.timestamp; });
        return result;
    }

    std::vector<std::pair<std::string, std::string>> get_diff(
        const std::string& task_id,
        const std::string& cp_a,
        const std::string& cp_b) const
    {
        std::lock_guard<std::mutex> lk(_mutex);

        std::vector<std::pair<std::string, std::string>> changes;

        if (!detail::safe_path_component(task_id) ||
            !detail::safe_path_component(cp_a) ||
            !detail::safe_path_component(cp_b)) return changes;

        auto dir_a = checkpoint_dir(task_id, cp_a);
        auto dir_b = checkpoint_dir(task_id, cp_b);

        auto manifest_a = load_manifest_locked(task_id, cp_a);
        auto manifest_b = load_manifest_locked(task_id, cp_b);

        auto load_content = [](const std::filesystem::path& p, std::string& out) -> bool {
            if (!std::filesystem::exists(p)) return false;
            std::ifstream ifs(p, std::ios::binary);
            if (!ifs) return false;
            out.assign((std::istreambuf_iterator<char>(ifs)),
                        std::istreambuf_iterator<char>());
            return true;
        };

        std::vector<std::string> seen_in_b;
        seen_in_b.reserve(manifest_b.files.size());

        for (const auto& snap : manifest_b.files) {
            seen_in_b.push_back(snap.relative_path);
            auto file_a = std::filesystem::path(dir_a) / snap.relative_path;
            auto file_b = std::filesystem::path(dir_b) / snap.relative_path;

            std::string content_a, content_b;
            const bool has_a = load_content(file_a, content_a);
            (void)load_content(file_b, content_b);

            if (!has_a) {
                changes.emplace_back(snap.relative_path, "[new file]");
                continue;
            }
            if (content_a != content_b) {
                changes.emplace_back(snap.relative_path, "[modified]");
            }
        }

        for (const auto& snap : manifest_a.files) {
            bool present_in_b = false;
            for (const auto& path_b : seen_in_b) {
                if (path_b == snap.relative_path) { present_in_b = true; break; }
            }
            if (!present_in_b) {
                changes.emplace_back(snap.relative_path, "[deleted]");
            }
        }

        return changes;
    }

private:
    std::string _workspace;
    std::string _storage;
    std::map<std::string, std::vector<checkpoint_t>> _checkpoints;
    mutable std::mutex _mutex;

    std::string checkpoint_dir(const std::string& task_id, const std::string& cp_id) const
    {
        return (std::filesystem::path(_storage) / task_id / cp_id).string();
    }

    bool save_manifest_locked(const std::string& task_id, const checkpoint_t& cp) const
    {
        nlohmann::json j;
        j["id"] = cp.id;
        j["task_id"] = cp.task_id;
        j["message"] = cp.message;
        j["timestamp"] = cp.timestamp;
        j["message_index"] = cp.message_index;

        auto files = nlohmann::json::array();
        for (const auto& f : cp.files) {
            files.push_back({{"path", f.relative_path}, {"hash", f.content_hash}, {"size", f.size}});
        }
        j["files"] = files;

        auto path = std::filesystem::path(checkpoint_dir(task_id, cp.id)) / "manifest.json";
        const std::string blob = j.dump(2);
        return write_file_atomic(path, blob.data(), blob.size());
    }

    checkpoint_t load_manifest_locked(const std::string& task_id, const std::string& cp_id) const
    {
        checkpoint_t cp;
        auto path = std::filesystem::path(checkpoint_dir(task_id, cp_id)) / "manifest.json";
        if (!std::filesystem::exists(path)) return cp;

        std::ifstream ifs(path);
        if (!ifs) return cp;

        auto j = nlohmann::json::parse(ifs, nullptr, false);
        if (j.is_discarded()) return cp;

        cp.id = j.value("id", "");
        cp.task_id = j.value("task_id", "");
        cp.message = j.value("message", "");
        cp.timestamp = j.value("timestamp", (int64_t)0);
        cp.message_index = j.value("message_index", -1);

        if (j.contains("files") && j["files"].is_array()) {
            for (const auto& f : j["files"]) {
                file_snapshot_t snap;
                snap.relative_path = f.value("path", "");
                snap.content_hash = f.value("hash", "");
                snap.size = f.value("size", (int64_t)0);
                cp.files.push_back(snap);
            }
        }

        return cp;
    }
};


}
