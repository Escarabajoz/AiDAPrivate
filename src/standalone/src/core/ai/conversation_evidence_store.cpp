#include "core/ai/conversation_evidence_store.hpp"

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "preview/shell_preview_platform.hpp"
#include "preview/shell_preview.hpp"
#else
#include "core/infra/executor.hpp"
#include "core/ui/task_center.hpp"
#include "core/ui/ui_thread_dispatcher.hpp"

#define NOMINMAX
#include <windows.h>
#include <shlobj.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <limits>
#include <memory>
#include <mutex>
#include <string_view>
#include <system_error>
#include <utility>

#include <nlohmann/json.hpp>
#endif

namespace aida::conversation_store {

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

request_result_t submit(request_t request) noexcept
{
    const bool reading = request.operation == operation_t::switch_conversation ||
        request.operation == operation_t::refresh_catalog ||
        request.operation == operation_t::load_evidence;
    aida::preview::record(reading ? aida::preview::shell_action_t::open_file :
        aida::preview::shell_action_t::save_file, "conversation_evidence_store");
    return request_result_t::preview_recorded;
}

std::optional<completion_t> take_completion() noexcept { return std::nullopt; }
bool request_retry() noexcept { return false; }
status_t status() noexcept { return {}; }
bool commit_lifecycle(request_t, std::string& error) noexcept
{
    error.clear();
    aida::preview::record(aida::preview::shell_action_t::save_file,
        "conversation_evidence_store.lifecycle");
    return true;
}

#else
namespace {

struct file_handle_guard_t {
    HANDLE value = INVALID_HANDLE_VALUE;
    explicit file_handle_guard_t(HANDLE handle) noexcept : value(handle) {}
    ~file_handle_guard_t() noexcept { close(); }
    void close() noexcept {
        if (value != INVALID_HANDLE_VALUE) {
            ::CloseHandle(value);
            value = INVALID_HANDLE_VALUE;
        }
    }
    file_handle_guard_t(const file_handle_guard_t&) = delete;
    file_handle_guard_t& operator=(const file_handle_guard_t&) = delete;
};

constexpr std::uint64_t kMaximumConversationBytes = 32ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t kMaximumEvidenceBytes = 2ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t kMaximumCatalogAggregateBytes = 256ULL * 1024ULL * 1024ULL;
constexpr std::size_t kMaximumCatalogFiles = 4096;
constexpr std::size_t kMaximumDirectoryEntries = 8192;
constexpr std::size_t kMaximumMessageText = 1024U * 1024U;
constexpr std::size_t kMaximumTitle = 512;
constexpr std::size_t kMaximumIdentity = 128;
constexpr std::size_t kMaximumMetadata = 512;

struct runtime_t {
    std::mutex mutex;
    std::mutex write_mutex;
    std::atomic<std::uint64_t> serial{0};
    std::atomic<std::uint64_t> retry_serial{0};
    bool pending = false;
    status_t ui_status;
    std::shared_ptr<const request_t> active;
    std::shared_ptr<const request_t> failed;
    std::uint64_t failed_serial = 0;
    std::shared_ptr<completion_t> completion;
    std::string active_task_id;
};

runtime_t& runtime() noexcept
{
    static runtime_t value;
    return value;
}

bool valid_id(std::string_view id) noexcept
{
    if (id.empty() || id.size() > kMaximumIdentity)
        return false;
    return std::all_of(id.begin(), id.end(), [](unsigned char value) {
        return std::isalnum(value) != 0 || value == '-' || value == '_';
    });
}

bool bounded(std::string_view value, std::size_t maximum, bool empty = true) noexcept
{
    return value.size() <= maximum && (empty || !value.empty()) &&
        value.find('\0') == std::string_view::npos;
}

std::uint64_t fnv1a(std::string_view value) noexcept
{
    std::uint64_t hash = 14695981039346656037ULL;
    for (const char raw_byte : value) {
        const auto byte = static_cast<unsigned char>(raw_byte);
        hash ^= byte;
        hash *= 1099511628211ULL;
    }
    return hash;
}

bool storage_root(std::filesystem::path& root, std::string& error) noexcept
{
    PWSTR appdata = nullptr;
    if (FAILED(::SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata)) ||
        !appdata) {
        error = "Conversation storage is unavailable.";
        return false;
    }
    try {
        root = std::filesystem::path(appdata) / L"AiDA" / L"Standalone" /
            L"conversations";
    } catch (...) {
        ::CoTaskMemFree(appdata);
        error = "Conversation storage path construction failed.";
        return false;
    }
    ::CoTaskMemFree(appdata);
    std::error_code ec;
    std::filesystem::create_directories(root, ec);
    if (ec) {
        error = "Conversation storage could not be created.";
        return false;
    }
    root = std::filesystem::weakly_canonical(root, ec);
    if (ec || root.empty()) {
        error = "Conversation storage could not be canonicalized.";
        return false;
    }
    return true;
}

std::filesystem::path conversation_path(const std::filesystem::path& root,
    std::string_view id)
{
    return root / (std::string(id) + ".json");
}

std::filesystem::path evidence_path(const std::filesystem::path& root,
    std::string_view id)
{
    return root / ("evidence-" + std::to_string(fnv1a(id)) + ".json");
}

bool exact_child(const std::filesystem::path& root,
    const std::filesystem::path& path) noexcept
{
    try {
        return path.parent_path() == root;
    } catch (...) {
        return false;
    }
}

bool read_exact(const std::filesystem::path& path, std::uint64_t maximum,
    std::string& bytes, std::string& error, bool absent_ok = false) noexcept
{
    file_handle_guard_t file(::CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (file.value == INVALID_HANDLE_VALUE) {
        if (absent_ok && ::GetLastError() == ERROR_FILE_NOT_FOUND) {
            bytes.clear();
            return true;
        }
        error = "A conversation store file could not be opened.";
        return false;
    }
    LARGE_INTEGER size{};
    if (!::GetFileSizeEx(file.value, &size) || size.QuadPart < 0 ||
        static_cast<std::uint64_t>(size.QuadPart) > maximum) {
        error = "A conversation store file exceeds its exact bound.";
        return false;
    }
    try { bytes.resize(static_cast<std::size_t>(size.QuadPart)); }
    catch (...) {
        error = "A bounded conversation store buffer could not be allocated.";
        return false;
    }
    std::size_t offset = 0;
    bool ok = true;
    while (offset < bytes.size()) {
        const DWORD chunk = static_cast<DWORD>((std::min)(bytes.size() - offset,
            static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
        DWORD read = 0;
        if (!::ReadFile(file.value, bytes.data() + offset, chunk, &read, nullptr) || read == 0) {
            ok = false;
            break;
        }
        offset += read;
    }
    if (!ok || offset != bytes.size()) {
        bytes.clear();
        error = "A conversation store file could not be read exactly.";
        return false;
    }
    return true;
}

bool write_atomic(const std::filesystem::path& path, std::string_view bytes,
    std::uint64_t maximum, std::uint64_t serial, std::string& error) noexcept
{
    if (bytes.empty() || bytes.size() > maximum) {
        error = "A conversation store payload exceeds its exact bound.";
        return false;
    }
    std::filesystem::path temporary = path;
    temporary += L".aida-" + std::to_wstring(serial) + L".tmp";
    file_handle_guard_t file(::CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr));
    if (file.value == INVALID_HANDLE_VALUE) {
        error = "A conversation store temporary file could not be created.";
        return false;
    }
    std::size_t offset = 0;
    bool ok = true;
    while (offset < bytes.size()) {
        const DWORD chunk = static_cast<DWORD>((std::min)(bytes.size() - offset,
            static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
        DWORD written = 0;
        if (!::WriteFile(file.value, bytes.data() + offset, chunk, &written, nullptr) ||
            written != chunk) {
            ok = false;
            break;
        }
        offset += written;
    }
    LARGE_INTEGER size{};
    if (ok) ok = ::FlushFileBuffers(file.value) != FALSE;
    if (ok) ok = ::GetFileSizeEx(file.value, &size) != FALSE &&
        size.QuadPart == static_cast<LONGLONG>(bytes.size());
    file.close();
    if (ok) ok = ::MoveFileExW(temporary.c_str(), path.c_str(),
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != FALSE;
    if (!ok) {
        ::DeleteFileW(temporary.c_str());
        error = "A conversation store file could not be replaced atomically.";
        return false;
    }
    return true;
}

bool validate_message(const message_t& message, std::uint64_t& aggregate,
    std::string& error) noexcept
{
    if (!bounded(message.text, kMaximumMessageText) ||
        !bounded(message.thinking_text, kMaximumMessageText) ||
        !bounded(message.model_id, 256)) {
        error = "Conversation message content exceeds its exact bound.";
        return false;
    }
    aggregate += message.text.size() + message.thinking_text.size() +
        message.model_id.size();
    if (aggregate > kMaximumConversationBytes) {
        error = "Conversation message content exceeds the aggregate bound.";
        return false;
    }
    return true;
}

bool validate_evidence(const evidence_t& item, std::string_view session,
    std::uint64_t& aggregate, std::string& error) noexcept
{
    if (item.sensitive) {
        error = "Sensitive evidence is not eligible for metadata persistence.";
        return false;
    }
    if (!bounded(item.id, 256, false) || !bounded(item.project_id, 256) ||
        !bounded(item.workspace_id, 256) || !bounded(item.session_id,
            kMaximumIdentity, false) || !bounded(item.source_view_id, 256, false) ||
        !bounded(item.source_kind, 128, false) ||
        !bounded(item.entity_id, kMaximumMetadata, false) ||
        !bounded(item.display_label, kMaximumMetadata) ||
        !bounded(item.return_target, kMaximumMetadata)) {
        error = "Evidence metadata exceeds its exact field bound.";
        return false;
    }
    aggregate += item.id.size() + item.project_id.size() + item.workspace_id.size() +
        item.session_id.size() + item.source_view_id.size() + item.source_kind.size() +
        item.entity_id.size() + item.display_label.size() + item.return_target.size();
    if (!valid_id(item.session_id) ||
        item.entity_id.empty() || item.content_hash == 0 ||
        item.session_id != session || aggregate > kMaximumEvidenceBytes) {
        error = "Evidence metadata violates the persisted metadata contract.";
        return false;
    }
    return true;
}

nlohmann::json message_json(const message_t& message)
{
    return {{"text", message.text}, {"thinking_text", message.thinking_text},
        {"is_user", message.is_user}, {"has_thinking", message.has_thinking},
        {"timestamp", message.timestamp}, {"input_tokens", message.input_tokens},
        {"output_tokens", message.output_tokens},
        {"cache_read_tokens", message.cache_read_tokens},
        {"cache_write_tokens", message.cache_write_tokens},
        {"model_id", message.model_id}};
}

nlohmann::json evidence_json(const evidence_t& item)
{
    return {{"id", item.id}, {"project_id", item.project_id},
        {"workspace_id", item.workspace_id}, {"session_id", item.session_id},
        {"source_view_id", item.source_view_id}, {"source_kind", item.source_kind},
        {"entity_id", item.entity_id}, {"display_label", item.display_label},
        {"return_target", item.return_target}, {"address", item.address},
        {"revision", item.revision}, {"generation", item.generation},
        {"snapshot_hash", item.snapshot_hash}, {"content_hash", item.content_hash},
        {"created_ms", item.created_ms}, {"truncated", item.truncated},
        {"sensitive", item.sensitive}};
}

bool load_evidence(const std::filesystem::path& root, std::string_view id,
    std::vector<evidence_t>& result, std::string& error);

bool serialize_snapshot(const snapshot_t& snapshot, std::uint64_t serial,
    const std::filesystem::path& root, bool& partial, std::string& error)
{
    if (!valid_id(snapshot.id) || snapshot.messages.size() > maximum_messages ||
        snapshot.evidence.size() > maximum_evidence ||
        !bounded(snapshot.title, kMaximumTitle)) {
        error = "The conversation snapshot violates its exact bounds.";
        return false;
    }
    if (snapshot.require_absent) {
        const DWORD attributes = ::GetFileAttributesW(
            conversation_path(root, snapshot.id).c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES) {
            error = "The new conversation identity already exists.";
            return false;
        }
        const DWORD last_error = ::GetLastError();
        if (last_error != ERROR_FILE_NOT_FOUND && last_error != ERROR_PATH_NOT_FOUND) {
            error = "The new conversation identity could not be reserved safely.";
            return false;
        }
    }
    std::uint64_t aggregate = 0;
    nlohmann::json messages = nlohmann::json::array();
    for (const auto& message : snapshot.messages) {
        if (!validate_message(message, aggregate, error)) return false;
        messages.push_back(message_json(message));
    }
    nlohmann::json conversation{{"schema", "aida.conversation"}, {"version", 2},
        {"id", snapshot.id}, {"revision", snapshot.revision},
        {"title", snapshot.title}, {"created", snapshot.created},
        {"pinned", snapshot.pinned}, {"messages", std::move(messages)}};
    const std::string conversation_payload = conversation.dump(2);
    if (snapshot.evidence_authoritative) {
        std::vector<evidence_t> existing;
        if (!load_evidence(root, snapshot.id, existing, error)) return false;
        nlohmann::json evidence{{"schema", "aida.conversation.evidence-metadata"},
            {"version", 1}, {"conversation_id", snapshot.id},
            {"items", nlohmann::json::array()}};
        aggregate = 0;
        for (const auto& item : snapshot.evidence) {
            if (!validate_evidence(item, snapshot.id, aggregate, error)) return false;
            evidence["items"].push_back(evidence_json(item));
        }
        const std::string evidence_payload = evidence.dump(2);
        if (!write_atomic(evidence_path(root, snapshot.id), evidence_payload,
                kMaximumEvidenceBytes, serial, error))
            return false;
    }
    if (!write_atomic(conversation_path(root, snapshot.id), conversation_payload,
            kMaximumConversationBytes, serial, error)) {
        partial = snapshot.evidence_authoritative;
        error = snapshot.evidence_authoritative
            ? "Conversation commit failed after evidence metadata was committed; retry will reconcile both files."
            : "The conversation snapshot could not be committed atomically.";
        return false;
    }
    return true;
}

nlohmann::json parse_bounded(std::string_view bytes)
{
    return nlohmann::json::parse(bytes.begin(), bytes.end(),
        [](int depth, nlohmann::json::parse_event_t, nlohmann::json&) {
            return depth <= 8;
        }, false);
}

bool checked_string_field(const nlohmann::json& object, const char* key,
    std::size_t maximum, std::string& result, bool required = false)
{
    const auto found = object.find(key);
    if (found == object.end()) {
        result.clear();
        return !required;
    }
    if (!found->is_string()) return false;
    result = found->get<std::string>();
    return bounded(result, maximum, !required);
}

bool checked_u64_field(const nlohmann::json& object, const char* key,
    std::uint64_t& result)
{
    const auto found = object.find(key);
    if (found == object.end()) {
        result = 0;
        return true;
    }
    if (found->is_number_unsigned()) {
        result = found->get<std::uint64_t>();
        return true;
    }
    if (found->is_number_integer()) {
        const auto value = found->get<std::int64_t>();
        if (value < 0) return false;
        result = static_cast<std::uint64_t>(value);
        return true;
    }
    return false;
}

bool checked_i64_field(const nlohmann::json& object, const char* key,
    std::int64_t& result)
{
    const auto found = object.find(key);
    if (found == object.end()) {
        result = 0;
        return true;
    }
    if (found->is_number_integer()) {
        result = found->get<std::int64_t>();
        return true;
    }
    if (found->is_number_unsigned()) {
        const auto value = found->get<std::uint64_t>();
        if (value > static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()))
            return false;
        result = static_cast<std::int64_t>(value);
        return true;
    }
    return false;
}

bool checked_nonnegative_int_field(const nlohmann::json& object, const char* key,
    int& result)
{
    std::uint64_t value = 0;
    if (!checked_u64_field(object, key, value) ||
        value > static_cast<std::uint64_t>((std::numeric_limits<int>::max)()))
        return false;
    result = static_cast<int>(value);
    return true;
}

bool checked_bool_field(const nlohmann::json& object, const char* key, bool& result)
{
    const auto found = object.find(key);
    if (found == object.end()) {
        result = false;
        return true;
    }
    if (!found->is_boolean()) return false;
    result = found->get<bool>();
    return true;
}

bool load_evidence(const std::filesystem::path& root, std::string_view id,
    std::vector<evidence_t>& result, std::string& error)
{
    std::string bytes;
    if (!read_exact(evidence_path(root, id), kMaximumEvidenceBytes, bytes, error, true))
        return false;
    if (bytes.empty()) return true;
    const auto document = parse_bounded(bytes);
    std::string schema;
    std::string conversation_id;
    int version = 0;
    if (!document.is_object() ||
        !checked_string_field(document, "schema", 64, schema, true) ||
        !checked_nonnegative_int_field(document, "version", version) ||
        !checked_string_field(document, "conversation_id", kMaximumIdentity,
            conversation_id, true) ||
        schema != "aida.conversation.evidence-metadata" || version != 1 ||
        conversation_id != id ||
        !document.contains("items") || !document["items"].is_array() ||
        document["items"].size() > maximum_evidence) {
        error = "Evidence metadata is invalid or belongs to another conversation.";
        return false;
    }
    std::uint64_t aggregate = 0;
    for (const auto& object : document["items"]) {
        if (!object.is_object()) {
            error = "Evidence metadata contains an invalid record.";
            return false;
        }
        evidence_t item;
        if (!checked_string_field(object, "id", 256, item.id, true) ||
            !checked_string_field(object, "project_id", 256, item.project_id) ||
            !checked_string_field(object, "workspace_id", 256, item.workspace_id) ||
            !checked_string_field(object, "session_id", kMaximumIdentity,
                item.session_id, true) ||
            !checked_string_field(object, "source_view_id", 256,
                item.source_view_id, true) ||
            !checked_string_field(object, "source_kind", 128,
                item.source_kind, true) ||
            !checked_string_field(object, "entity_id", kMaximumMetadata,
                item.entity_id, true) ||
            !checked_string_field(object, "display_label", kMaximumMetadata,
                item.display_label) ||
            !checked_string_field(object, "return_target", kMaximumMetadata,
                item.return_target)) {
            error = "Evidence metadata contains an invalid bounded string field.";
            return false;
        }
        if (!checked_u64_field(object, "address", item.address) ||
            !checked_u64_field(object, "revision", item.revision) ||
            !checked_u64_field(object, "generation", item.generation) ||
            !checked_u64_field(object, "snapshot_hash", item.snapshot_hash) ||
            !checked_u64_field(object, "content_hash", item.content_hash) ||
            !checked_u64_field(object, "created_ms", item.created_ms) ||
            !checked_bool_field(object, "truncated", item.truncated) ||
            !checked_bool_field(object, "sensitive", item.sensitive)) {
            error = "Evidence metadata contains an invalid typed field.";
            return false;
        }
        if (item.sensitive) continue;
        if (!validate_evidence(item, id, aggregate, error)) return false;
        result.push_back(std::move(item));
    }
    return true;
}

bool load_snapshot(const std::filesystem::path& root, std::string_view id,
    snapshot_t& result, std::string& error, bool include_evidence = true)
{
    if (!valid_id(id)) { error = "The conversation identity is invalid."; return false; }
    std::string bytes;
    if (!read_exact(conversation_path(root, id), kMaximumConversationBytes, bytes, error))
        return false;
    const auto document = parse_bounded(bytes);
    if (!document.is_object() || !document.contains("messages") ||
        !document["messages"].is_array() ||
        document["messages"].size() > maximum_messages) {
        error = "The conversation document is invalid or exceeds its message bound.";
        return false;
    }
    const bool versioned = document.contains("schema") || document.contains("version");
    if (versioned) {
        std::string schema;
        int version = 0;
        if (!checked_string_field(document, "schema", 64, schema, true) ||
            !checked_nonnegative_int_field(document, "version", version) ||
            schema != "aida.conversation" || version != 2) {
            error = "The conversation schema or version is unsupported.";
            return false;
        }
    }
    if (!checked_string_field(document, "id", kMaximumIdentity, result.id)) {
        error = "The conversation identity field is invalid.";
        return false;
    }
    if (result.id.empty()) result.id = std::string(id);
    if (result.id != id) { error = "The conversation document identity does not match its file."; return false; }
    if (!checked_u64_field(document, "revision", result.revision)) {
        error = "The conversation revision is invalid.";
        return false;
    }
    if (!checked_string_field(document, "title", kMaximumTitle, result.title)) {
        error = "The conversation title exceeds its exact bound.";
        return false;
    }
    if (!checked_i64_field(document, "created", result.created) ||
        !checked_bool_field(document, "pinned", result.pinned)) {
        error = "The conversation metadata contains an invalid typed field.";
        return false;
    }
    std::uint64_t aggregate = 0;
    for (const auto& object : document["messages"]) {
        if (!object.is_object()) { error = "The conversation contains an invalid message."; return false; }
        message_t message;
        if (!checked_string_field(object, "text", kMaximumMessageText, message.text) ||
            !checked_string_field(object, "thinking_text", kMaximumMessageText,
                message.thinking_text) ||
            !checked_string_field(object, "model_id", 256, message.model_id)) {
            error = "The conversation contains an invalid bounded message string.";
            return false;
        }
        if (!checked_bool_field(object, "is_user", message.is_user) ||
            !checked_bool_field(object, "has_thinking", message.has_thinking) ||
            !checked_i64_field(object, "timestamp", message.timestamp) ||
            !checked_nonnegative_int_field(object, "input_tokens", message.input_tokens) ||
            !checked_nonnegative_int_field(object, "output_tokens", message.output_tokens) ||
            !checked_nonnegative_int_field(object, "cache_read_tokens", message.cache_read_tokens) ||
            !checked_nonnegative_int_field(object, "cache_write_tokens", message.cache_write_tokens)) {
            error = "The conversation contains an invalid typed message field.";
            return false;
        }
        if (!validate_message(message, aggregate, error)) return false;
        result.messages.push_back(std::move(message));
    }
    if (include_evidence) {
        if (!load_evidence(root, id, result.evidence, error)) return false;
        result.evidence_authoritative = true;
    }
    return true;
}

bool catalog(const std::filesystem::path& root, std::vector<summary_t>& result,
    std::string& error)
{
    std::error_code ec;
    std::filesystem::directory_iterator cursor(root, ec), end;
    std::size_t entries = 0;
    std::size_t files = 0;
    std::uint64_t aggregate_bytes = 0;
    while (!ec && cursor != end) {
        if (++entries > kMaximumDirectoryEntries) {
            error = "The conversation directory exceeds its exact entry bound.";
            return false;
        }
        const auto path = cursor->path();
        const bool regular = cursor->is_regular_file(ec);
        cursor.increment(ec);
        if (ec || !regular || path.extension() != L".json" ||
            path.filename().wstring().rfind(L"evidence-", 0) == 0)
            continue;
        if (++files > kMaximumCatalogFiles) {
            error = "The conversation catalog exceeds its exact file bound.";
            return false;
        }
        const std::string id = path.stem().string();
        if (!valid_id(id) || !exact_child(root, path)) continue;
        WIN32_FILE_ATTRIBUTE_DATA attributes{};
        if (!::GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &attributes))
            continue;
        const std::uint64_t file_bytes =
            (static_cast<std::uint64_t>(attributes.nFileSizeHigh) << 32U) |
            attributes.nFileSizeLow;
        if (file_bytes > kMaximumConversationBytes ||
            aggregate_bytes > kMaximumCatalogAggregateBytes - file_bytes) {
            error = "The conversation catalog exceeds its aggregate byte bound.";
            return false;
        }
        aggregate_bytes += file_bytes;
        snapshot_t loaded;
        std::string item_error;
        if (!load_snapshot(root, id, loaded, item_error, false)) continue;
        result.push_back({loaded.id, loaded.title, loaded.created,
            static_cast<int>(loaded.messages.size()), loaded.pinned, loaded.revision});
    }
    if (ec) { error = "The conversation catalog could not be enumerated exactly."; return false; }
    std::sort(result.begin(), result.end(), [](const summary_t& left, const summary_t& right) {
        if (left.pinned != right.pinned) return left.pinned > right.pinned;
        if (left.created != right.created) return left.created > right.created;
        return left.id < right.id;
    });
    return true;
}

bool delete_transaction(const std::filesystem::path& root, const request_t& request,
    std::uint64_t serial, bool& partial, std::string& error)
{
    snapshot_t existing;
    if (!load_snapshot(root, request.target_id, existing, error)) return false;
    if (existing.revision != request.target_revision) {
        error = "The conversation changed after deletion was reviewed.";
        return false;
    }
    const auto conversation = conversation_path(root, request.target_id);
    const auto evidence = evidence_path(root, request.target_id);
    auto conversation_tombstone = conversation;
    conversation_tombstone += L".delete-" + std::to_wstring(serial);
    auto evidence_tombstone = evidence;
    evidence_tombstone += L".delete-" + std::to_wstring(serial);
    if (!::MoveFileExW(conversation.c_str(), conversation_tombstone.c_str(),
            MOVEFILE_WRITE_THROUGH)) {
        error = "The reviewed conversation could not be staged for deletion.";
        return false;
    }
    const DWORD evidence_attributes = ::GetFileAttributesW(evidence.c_str());
    const bool evidence_exists = evidence_attributes != INVALID_FILE_ATTRIBUTES;
    if (!evidence_exists && ::GetLastError() != ERROR_FILE_NOT_FOUND) {
        const bool rolled_back = ::MoveFileExW(conversation_tombstone.c_str(),
            conversation.c_str(), MOVEFILE_WRITE_THROUGH) != FALSE;
        partial = !rolled_back;
        error = rolled_back
            ? "Evidence deletion preflight failed; the conversation deletion was rolled back."
            : "Evidence deletion preflight failed and conversation rollback is incomplete.";
        return false;
    }
    if (evidence_exists && !::MoveFileExW(evidence.c_str(), evidence_tombstone.c_str(),
            MOVEFILE_WRITE_THROUGH)) {
        const bool rolled_back = ::MoveFileExW(conversation_tombstone.c_str(),
            conversation.c_str(), MOVEFILE_WRITE_THROUGH) != FALSE;
        partial = !rolled_back;
        error = rolled_back
            ? "Evidence deletion staging failed; the conversation deletion was rolled back."
            : "Evidence deletion staging failed and conversation rollback is incomplete.";
        return false;
    }
    const bool conversation_removed = ::DeleteFileW(conversation_tombstone.c_str()) != FALSE;
    const bool evidence_removed = !evidence_exists || ::DeleteFileW(evidence_tombstone.c_str()) != FALSE;
    partial = !conversation_removed || !evidence_removed;
    if (partial)
        error = "The conversation is deleted but tombstone cleanup is incomplete.";
    return true;
}

bool execute(const request_t& request, std::uint64_t serial, completion_t& result)
{
    std::filesystem::path root;
    if (!storage_root(root, result.error)) return false;
    result.source_revision = request.current.revision;
    result.source_catalog_generation = request.catalog_generation;
    result.target_id = request.target_id;
    if ((request.operation == operation_t::save ||
         request.operation == operation_t::switch_conversation ||
         request.operation == operation_t::new_conversation ||
         request.operation == operation_t::fork_conversation ||
         request.operation == operation_t::export_markdown) &&
        !request.current.id.empty()) {
        if (!serialize_snapshot(request.current, serial, root, result.partial, result.error))
            return false;
        result.committed_summary = summary_t{request.current.id, request.current.title,
            request.current.created, static_cast<int>(request.current.messages.size()),
            request.current.pinned, request.current.revision};
    }
    if (request.operation == operation_t::save) {
        if (!catalog(root, result.catalog, result.error)) {
            result.partial = true;
            return true;
        }
        result.catalog_authoritative = true;
    } else if (request.operation == operation_t::switch_conversation) {
        snapshot_t loaded;
        if (!load_snapshot(root, request.target_id, loaded, result.error)) return false;
        if (loaded.revision != request.target_revision) {
            result.error = "The target conversation changed before it could be loaded.";
            return false;
        }
        result.loaded = std::move(loaded);
        if (!catalog(root, result.catalog, result.error)) {
            result.partial = true;
            return true;
        }
        result.catalog_authoritative = true;
    } else if (request.operation == operation_t::new_conversation) {
        result.loaded = snapshot_t{};
        if (!catalog(root, result.catalog, result.error)) {
            result.partial = true;
            return true;
        }
        result.catalog_authoritative = true;
    } else if (request.operation == operation_t::refresh_catalog) {
        if (!catalog(root, result.catalog, result.error)) return false;
        result.catalog_authoritative = true;
    } else if (request.operation == operation_t::delete_conversation) {
        if (!delete_transaction(root, request, serial, result.partial, result.error)) return false;
        if (!catalog(root, result.catalog, result.error)) {
            result.partial = true;
            return true;
        }
        result.catalog_authoritative = true;
    } else if (request.operation == operation_t::set_pinned) {
        snapshot_t loaded;
        if (!load_snapshot(root, request.target_id, loaded, result.error)) return false;
        if (loaded.revision != request.target_revision) {
            result.error = "The conversation changed before the pin update committed.";
            return false;
        }
        loaded.pinned = request.pinned;
        ++loaded.revision;
        if (!serialize_snapshot(loaded, serial, root, result.partial, result.error)) return false;
        result.committed_summary = summary_t{loaded.id, loaded.title, loaded.created,
            static_cast<int>(loaded.messages.size()), loaded.pinned, loaded.revision};
        if (!catalog(root, result.catalog, result.error)) {
            result.partial = true;
            return true;
        }
        result.catalog_authoritative = true;
    } else if (request.operation == operation_t::fork_conversation) {
        snapshot_t loaded;
        if (!load_snapshot(root, request.target_id, loaded, result.error)) return false;
        if (loaded.revision != request.target_revision) {
            result.error = "The conversation changed before the fork committed.";
            return false;
        }
        const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        loaded.id = std::to_string(now) + "-" + std::to_string(::GetCurrentProcessId()) +
            "-" + std::to_string(serial);
        if (::GetFileAttributesW(conversation_path(root, loaded.id).c_str()) != INVALID_FILE_ATTRIBUTES ||
            ::GetFileAttributesW(evidence_path(root, loaded.id).c_str()) != INVALID_FILE_ATTRIBUTES) {
            result.error = "A unique fork identity could not be reserved.";
            return false;
        }
        loaded.title = loaded.title.empty() ? "Forked conversation" : loaded.title + " (fork)";
        loaded.created = now;
        loaded.pinned = false;
        loaded.revision = 1;
        for (auto& item : loaded.evidence) item.session_id = loaded.id;
        if (!serialize_snapshot(loaded, serial, root, result.partial, result.error)) {
            if (result.partial) {
                const bool rolled_back = ::DeleteFileW(evidence_path(root, loaded.id).c_str()) != FALSE ||
                    ::GetLastError() == ERROR_FILE_NOT_FOUND;
                result.partial = !rolled_back;
                result.error = rolled_back
                    ? "The fork transaction failed and its evidence metadata was rolled back."
                    : "The fork transaction failed and evidence rollback is incomplete.";
            }
            return false;
        }
        result.target_id = loaded.id;
        result.loaded = std::move(loaded);
        if (!catalog(root, result.catalog, result.error)) {
            result.partial = true;
            return true;
        }
        result.catalog_authoritative = true;
    } else if (request.operation == operation_t::export_markdown) {
        snapshot_t loaded;
        if (!load_snapshot(root, request.target_id, loaded, result.error)) return false;
        if (loaded.revision != request.target_revision) {
            result.error = "The conversation changed before its export snapshot was read.";
            return false;
        }
        std::string markdown = "# " + (loaded.title.empty() ? std::string("AiDA Conversation") : loaded.title) +
            "\n\nConversation ID: `" + loaded.id + "`\n\n";
        for (const auto& message : loaded.messages) {
            markdown += message.is_user ? "## User\n\n" : "## Assistant\n\n";
            markdown += message.text + "\n\n";
            if (markdown.size() > kMaximumConversationBytes) {
                result.error = "The Markdown export exceeds its exact bound.";
                return false;
            }
        }
        std::filesystem::path output(request.output_path);
        if (!output.is_absolute() || output.filename().empty()) {
            result.error = "The Markdown export destination is invalid.";
            return false;
        }
        if (!write_atomic(output, markdown, kMaximumConversationBytes, serial, result.error)) return false;
        if (!catalog(root, result.catalog, result.error)) {
            result.partial = true;
            return true;
        }
        result.catalog_authoritative = true;
    } else if (request.operation == operation_t::save_evidence) {
        snapshot_t evidence_only = request.current;
        if (!valid_id(evidence_only.id) || evidence_only.evidence.size() > maximum_evidence) {
            result.error = "The evidence persistence snapshot is invalid.";
            return false;
        }
        nlohmann::json document{{"schema", "aida.conversation.evidence-metadata"},
            {"version", 1}, {"conversation_id", evidence_only.id},
            {"items", nlohmann::json::array()}};
        std::uint64_t aggregate = 0;
        for (const auto& item : evidence_only.evidence) {
            if (!validate_evidence(item, evidence_only.id, aggregate, result.error)) return false;
            document["items"].push_back(evidence_json(item));
        }
        std::vector<evidence_t> existing;
        if (!load_evidence(root, evidence_only.id, existing, result.error)) return false;
        if (!write_atomic(evidence_path(root, evidence_only.id), document.dump(2),
                kMaximumEvidenceBytes, serial, result.error)) return false;
    } else if (request.operation == operation_t::load_evidence) {
        snapshot_t loaded;
        loaded.id = request.target_id;
        if (!load_evidence(root, request.target_id, loaded.evidence, result.error)) return false;
        loaded.evidence_authoritative = true;
        result.loaded = std::move(loaded);
    }
    return true;
}

request_result_t submit_native(request_t request, std::uint64_t retry_of = 0)
{
    runtime_t& current = runtime();
    {
        std::lock_guard<std::mutex> lock(current.mutex);
        if (current.pending || current.completion ||
            (current.failed && current.failed_serial != retry_of))
            return request_result_t::busy;
        current.pending = true;
        current.ui_status = {true, false, false, request.operation,
            "Conversation persistence queued", {}};
    }
    const std::uint64_t serial = current.serial.fetch_add(1, std::memory_order_acq_rel) + 1;
    const std::string task_id = "conversation.store." + std::to_string(serial);
    auto immutable = std::make_shared<const request_t>(std::move(request));
    {
        std::lock_guard<std::mutex> lock(current.mutex);
        current.active = immutable;
        current.active_task_id = task_id;
        current.completion.reset();
    }
    aida::ui::task_center::task_registration_t registration;
    registration.id = task_id;
    registration.source = "conversation_evidence_store";
    registration.owner = "AI Conversation";
    registration.owner_view = "view.ai_chat";
    registration.owner_action = "Persist conversation and evidence";
    registration.target = "AiDA conversation store";
    registration.label = "Conversation store transaction";
    registration.stage = "Queued immutable conversation transaction";
    registration.affected_entity = "conversation.store.v2";
    registration.callbacks.retry = [serial] {
        runtime_t& retry_runtime = runtime();
        std::lock_guard<std::mutex> lock(retry_runtime.mutex);
        if (retry_runtime.pending || !retry_runtime.failed ||
            retry_runtime.failed_serial != serial)
            return false;
        retry_runtime.retry_serial.store(serial, std::memory_order_release);
        return true;
    };
    if (!aida::ui::task_center::register_task(std::move(registration))) {
        std::lock_guard<std::mutex> lock(current.mutex);
        current.pending = false;
        current.failed = immutable;
        current.failed_serial = serial;
        current.ui_status = {false, true, true, immutable->operation,
            "Conversation transaction rejected", "Task Center rejected the transaction."};
        return request_result_t::rejected;
    }
    auto result = std::make_shared<completion_t>();
    result->serial = serial;
    result->operation = immutable->operation;
    aida::infra::executor::submission_t submission;
    submission.owner_subsystem = "conversation_evidence_store";
    submission.label = "conversation.store.transaction";
    submission.thread_class = "bounded_file_io";
    submission.domain = aida::infra::executor::domain_t::diagnostics;
    submission.priority = 2;
    submission.generation = serial;
    submission.ui_access_policy = "none";
    submission.failure_policy = "retain_request_for_retry";
    submission.shutdown_policy = "drain";
    submission.body = [immutable, result, task_id] {
        static_cast<void>(aida::ui::task_center::update_task(task_id,
            aida::ui::task_center::task_state_t::running, 0.2f,
            "Executing bounded conversation transaction"));
        try {
            std::lock_guard<std::mutex> write_lock(runtime().write_mutex);
            result->success = execute(*immutable, result->serial, *result);
        }
        catch (...) {
            result->success = false;
            result->error = "The conversation transaction failed safely.";
        }
        runtime_t& completed = runtime();
        {
            std::lock_guard<std::mutex> lock(completed.mutex);
            completed.pending = false;
            completed.completion = result;
            completed.active.reset();
            completed.active_task_id.clear();
            completed.ui_status.pending = false;
            completed.ui_status.failed = !result->success;
            completed.ui_status.retryable = !result->success;
            completed.ui_status.operation = result->operation;
            completed.ui_status.stage = result->success ?
                "Conversation transaction completed" : "Conversation transaction failed";
            completed.ui_status.error = result->error;
            if (result->success) {
                completed.failed.reset();
                completed.failed_serial = 0;
            } else {
                completed.failed = immutable;
                completed.failed_serial = result->serial;
            }
        }
        static_cast<void>(aida::ui::task_center::update_task(task_id,
            result->success ? (result->partial ?
                aida::ui::task_center::task_state_t::partial :
                aida::ui::task_center::task_state_t::completed) :
                aida::ui::task_center::task_state_t::failed,
            1.0f, result->success ? "Conversation transaction committed" :
                "Conversation transaction failed", result->error));
    };
    const auto submitted = aida::infra::executor::submit(std::move(submission));
    if (!submitted.submitted) {
        std::lock_guard<std::mutex> lock(current.mutex);
        current.pending = false;
        current.failed = immutable;
        current.failed_serial = serial;
        current.ui_status = {false, true, true, immutable->operation,
            "Conversation scheduling failed", "The executor rejected the transaction."};
        static_cast<void>(aida::ui::task_center::update_task(task_id,
            aida::ui::task_center::task_state_t::failed, 1.0f,
            "Conversation scheduling failed", submitted.reject_reason));
        return request_result_t::rejected;
    }
    return request_result_t::queued;
}

void process_retry() noexcept
{
    runtime_t& current = runtime();
    const std::uint64_t requested = current.retry_serial.exchange(0,
        std::memory_order_acq_rel);
    if (requested == 0) return;
    std::shared_ptr<const request_t> failed;
    {
        std::lock_guard<std::mutex> lock(current.mutex);
        if (!current.pending && current.failed_serial == requested)
            failed = current.failed;
    }
    if (!failed) return;
    try { static_cast<void>(submit_native(*failed, requested)); }
    catch (...) {
        std::lock_guard<std::mutex> lock(current.mutex);
        current.ui_status = {false, true, true, failed->operation,
            "Conversation retry failed", "The retained transaction could not be queued."};
    }
}

}

request_result_t submit(request_t request) noexcept
{
    if (!aida::ui_thread::is_owner_thread()) return request_result_t::rejected;
    try { return submit_native(std::move(request)); }
    catch (...) { return request_result_t::rejected; }
}

std::optional<completion_t> take_completion() noexcept
{
    runtime_t& current = runtime();
    {
        std::lock_guard<std::mutex> lock(current.mutex);
        if (current.completion) {
            completion_t result = std::move(*current.completion);
            current.completion.reset();
            return result;
        }
    }
    process_retry();
    return std::nullopt;
}

bool request_retry() noexcept
{
    if (!aida::ui_thread::is_owner_thread()) return false;
    runtime_t& current = runtime();
    std::lock_guard<std::mutex> lock(current.mutex);
    if (current.pending || !current.failed) return false;
    current.retry_serial.store(current.failed_serial, std::memory_order_release);
    return true;
}

status_t status() noexcept
{
    runtime_t& current = runtime();
    std::lock_guard<std::mutex> lock(current.mutex);
    status_t result = current.ui_status;
    if (current.completion && current.completion->success) {
        result.pending = true;
        result.stage = "Conversation transaction awaiting UI publication";
    }
    return result;
}

bool commit_lifecycle(request_t request, std::string& error) noexcept
{
    error.clear();
    try {
        if (request.operation != operation_t::save) {
            error = "Only a complete conversation snapshot can be committed during lifecycle shutdown.";
            return false;
        }
        completion_t result;
        result.operation = request.operation;
        result.serial = runtime().serial.fetch_add(1, std::memory_order_acq_rel) + 1;
        std::lock_guard<std::mutex> write_lock(runtime().write_mutex);
        const bool committed = execute(request, result.serial, result);
        error = result.error;
        return committed;
    } catch (...) {
        error = "The final conversation snapshot could not be committed safely.";
        return false;
    }
}

#endif

}
