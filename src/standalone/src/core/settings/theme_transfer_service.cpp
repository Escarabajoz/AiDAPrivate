#include "core/settings/theme_transfer_service.hpp"

#include "core/infra/executor.hpp"
#include "core/ui/task_center.hpp"
#include "core/ui/ui_thread_dispatcher.hpp"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cmath>
#include <filesystem>
#include <limits>
#include <memory>
#include <mutex>
#include <unordered_set>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

namespace aida::theme_transfer {

namespace {

constexpr std::uint64_t kMaximumDocumentBytes = 1024ULL * 1024ULL;
constexpr int kMaximumIconIndex = 4095;

struct request_t {
    std::uint64_t serial = 0;
    operation_t operation = operation_t::import_theme;
    std::string task_id;
    std::filesystem::path path;
    std::string export_payload;
};

struct file_handle_guard_t {
    HANDLE value = INVALID_HANDLE_VALUE;

    explicit file_handle_guard_t(HANDLE handle) noexcept : value(handle) {}
    ~file_handle_guard_t() noexcept { close(); }

    void close() noexcept
    {
        if (value != INVALID_HANDLE_VALUE) {
            ::CloseHandle(value);
            value = INVALID_HANDLE_VALUE;
        }
    }

    file_handle_guard_t(const file_handle_guard_t&) = delete;
    file_handle_guard_t& operator=(const file_handle_guard_t&) = delete;
};

struct runtime_t {
    std::mutex mutex;
    std::atomic<std::uint64_t> serial{0};
    std::atomic<std::uint64_t> retry_requested{0};
    bool pending = false;
    status_t ui_status;
    std::shared_ptr<const request_t> active_request;
    std::shared_ptr<const request_t> failed_request;
    std::shared_ptr<completion_t> completion;
};

runtime_t& runtime() noexcept
{
    static runtime_t value;
    return value;
}

bool bounded_text(const std::string& value, std::size_t maximum, bool allow_empty) noexcept
{
    return value.size() <= maximum && (allow_empty || !value.empty()) &&
        value.find('\0') == std::string::npos;
}

bool validate_theme(const theme_t& theme, std::string& error) noexcept
{
    if (!bounded_text(theme.name, maximum_theme_name_bytes, false)) {
        error = "Theme names must contain between 1 and 96 bytes.";
        return false;
    }
    for (const float channel : theme.accent) {
        if (!std::isfinite(channel) || channel < 0.0f || channel > 1.0f) {
            error = "Theme accent channels must be finite values between 0 and 1.";
            return false;
        }
    }
    if (theme.icon_index < -1 || theme.icon_index > kMaximumIconIndex) {
        error = "The theme icon index is outside the supported range.";
        return false;
    }
    if (!bounded_text(theme.icon_file_path, maximum_icon_path_bytes, true)) {
        error = "The theme icon path exceeds its exact bound or contains an embedded null.";
        return false;
    }
    error.clear();
    return true;
}

nlohmann::json serialize_theme(const theme_t& theme)
{
    return nlohmann::json{
        {"schema_version", 1},
        {"name", theme.name},
        {"accent", {theme.accent[0], theme.accent[1], theme.accent[2]}},
        {"bg_base", theme.bg_base},
        {"panel_bg", theme.panel_bg},
        {"panel_header", theme.panel_header},
        {"title_bar", theme.title_bar},
        {"text_primary", theme.text_primary},
        {"text_secondary", theme.text_secondary},
        {"text_dim", theme.text_dim},
        {"icon_index", theme.icon_index},
        {"icon_file_path", theme.icon_file_path}
    };
}

bool read_u32(const nlohmann::json& root, const char* key,
    std::uint32_t& value, std::string& error)
{
    const auto iterator = root.find(key);
    if (iterator == root.end() ||
        (!iterator->is_number_unsigned() && !iterator->is_number_integer())) {
        error = std::string("The theme field '") + key + "' must be an integer color.";
        return false;
    }
    if (iterator->is_number_integer()) {
        const auto signed_value = iterator->get<std::int64_t>();
        if (signed_value < 0 ||
            static_cast<std::uint64_t>(signed_value) >
                (std::numeric_limits<std::uint32_t>::max)()) {
            error = std::string("The theme field '") + key + "' is outside the color range.";
            return false;
        }
        value = static_cast<std::uint32_t>(signed_value);
        return true;
    }
    const auto unsigned_value = iterator->get<std::uint64_t>();
    if (unsigned_value > (std::numeric_limits<std::uint32_t>::max)()) {
        error = std::string("The theme field '") + key + "' is outside the color range.";
        return false;
    }
    value = static_cast<std::uint32_t>(unsigned_value);
    return true;
}

bool parse_theme(const std::string& payload, theme_t& theme, std::string& error)
{
    const nlohmann::json root = nlohmann::json::parse(payload, nullptr, false);
    if (root.is_discarded() || !root.is_object()) {
        error = "The theme document is not valid JSON object data.";
        return false;
    }
    static const std::unordered_set<std::string> allowed{
        "schema_version", "name", "accent", "bg_base", "panel_bg",
        "panel_header", "title_bar", "text_primary", "text_secondary",
        "text_dim", "icon_index", "icon_file_path"
    };
    for (auto iterator = root.begin(); iterator != root.end(); ++iterator) {
        if (allowed.find(iterator.key()) == allowed.end()) {
            error = "The theme document contains an unsupported field: " + iterator.key();
            return false;
        }
    }
    if (root.contains("schema_version")) {
        if (!root["schema_version"].is_number_integer()) {
            error = "The theme schema version is unsupported.";
            return false;
        }
        const auto version = root["schema_version"].get<std::int64_t>();
        if (version != 1) {
            error = "The theme schema version is unsupported.";
            return false;
        }
    }
    const auto name = root.find("name");
    if (name == root.end() || !name->is_string()) {
        error = "The theme document requires a string name.";
        return false;
    }
    theme.name = name->get<std::string>();
    const auto accent = root.find("accent");
    if (accent == root.end() || !accent->is_array() || accent->size() != 3) {
        error = "The theme document requires exactly three accent channels.";
        return false;
    }
    for (std::size_t index = 0; index < theme.accent.size(); ++index) {
        if (!(*accent)[index].is_number()) {
            error = "Every theme accent channel must be numeric.";
            return false;
        }
        theme.accent[index] = (*accent)[index].get<float>();
    }
    if (!read_u32(root, "bg_base", theme.bg_base, error) ||
        !read_u32(root, "panel_bg", theme.panel_bg, error) ||
        !read_u32(root, "panel_header", theme.panel_header, error) ||
        !read_u32(root, "title_bar", theme.title_bar, error) ||
        !read_u32(root, "text_primary", theme.text_primary, error) ||
        !read_u32(root, "text_secondary", theme.text_secondary, error) ||
        !read_u32(root, "text_dim", theme.text_dim, error))
        return false;
    const auto icon_index = root.find("icon_index");
    if (icon_index == root.end() || !icon_index->is_number_integer()) {
        error = "The theme document requires an integer icon index.";
        return false;
    }
    const auto raw_icon_index = icon_index->get<std::int64_t>();
    if (raw_icon_index < -1 || raw_icon_index > kMaximumIconIndex) {
        error = "The theme icon index is outside the supported range.";
        return false;
    }
    theme.icon_index = static_cast<int>(raw_icon_index);
    const auto icon_path = root.find("icon_file_path");
    if (icon_path != root.end()) {
        if (!icon_path->is_string()) {
            error = "The theme icon path must be a string.";
            return false;
        }
        theme.icon_file_path = icon_path->get<std::string>();
    }
    return validate_theme(theme, error);
}

bool read_file_exact(const std::filesystem::path& path, std::string& payload,
    std::string& error) noexcept
{
    file_handle_guard_t file(::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr));
    if (file.value == INVALID_HANDLE_VALUE) {
        error = "The selected theme file could not be opened.";
        return false;
    }
    LARGE_INTEGER size{};
    if (!::GetFileSizeEx(file.value, &size) || size.QuadPart <= 0 ||
        static_cast<std::uint64_t>(size.QuadPart) > kMaximumDocumentBytes) {
        error = "The selected theme file is empty, unreadable, or exceeds 1 MiB.";
        return false;
    }
    try {
        payload.resize(static_cast<std::size_t>(size.QuadPart));
    } catch (...) {
        error = "Memory for the bounded theme document could not be allocated.";
        return false;
    }
    std::size_t offset = 0;
    bool ok = true;
    while (offset < payload.size()) {
        const DWORD request = static_cast<DWORD>((std::min)(
            payload.size() - offset,
            static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
        DWORD read = 0;
        if (!::ReadFile(file.value, payload.data() + offset, request, &read, nullptr) ||
            read == 0) {
            ok = false;
            break;
        }
        offset += read;
    }
    if (!ok || offset != payload.size()) {
        payload.clear();
        error = "The selected theme file could not be read exactly.";
        return false;
    }
    return true;
}

bool write_file_atomic(const request_t& request, std::string& error) noexcept
{
    const std::filesystem::path parent = request.path.parent_path();
    if (parent.empty()) {
        error = "The theme export destination has no containing directory.";
        return false;
    }
    std::error_code path_error;
    if (!std::filesystem::is_directory(parent, path_error) || path_error) {
        error = "The theme export directory does not exist or is inaccessible.";
        return false;
    }
    std::filesystem::path temporary = request.path;
    temporary += L".aida-theme-" + std::to_wstring(request.serial) + L".tmp";
    file_handle_guard_t file(::CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr));
    if (file.value == INVALID_HANDLE_VALUE) {
        error = "The temporary theme export file could not be created.";
        return false;
    }
    std::size_t offset = 0;
    bool ok = true;
    while (offset < request.export_payload.size()) {
        const DWORD chunk = static_cast<DWORD>((std::min)(
            request.export_payload.size() - offset,
            static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
        DWORD written = 0;
        if (!::WriteFile(file.value, request.export_payload.data() + offset,
                chunk, &written, nullptr) || written == 0) {
            ok = false;
            break;
        }
        offset += written;
    }
    LARGE_INTEGER exact_size{};
    if (ok)
        ok = ::FlushFileBuffers(file.value) != FALSE;
    if (ok)
        ok = ::GetFileSizeEx(file.value, &exact_size) != FALSE &&
            exact_size.QuadPart == static_cast<LONGLONG>(request.export_payload.size());
    file.close();
    if (ok) {
        ok = ::MoveFileExW(temporary.c_str(), request.path.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != FALSE;
    }
    if (!ok) {
        ::DeleteFileW(temporary.c_str());
        error = "The theme export could not be written and replaced atomically.";
        return false;
    }
    return true;
}

request_result_t submit_request(request_t request);

void process_retry() noexcept
{
    runtime_t& current = runtime();
    const std::uint64_t requested = current.retry_requested.exchange(0,
        std::memory_order_acq_rel);
    if (requested == 0)
        return;
    std::shared_ptr<const request_t> failed;
    {
        std::lock_guard<std::mutex> lock(current.mutex);
        if (!current.pending && current.failed_request &&
            current.failed_request->serial == requested)
            failed = current.failed_request;
    }
    if (!failed)
        return;
    request_t retry = *failed;
    retry.serial = 0;
    retry.task_id.clear();
    try {
        static_cast<void>(submit_request(std::move(retry)));
    } catch (...) {
        std::lock_guard<std::mutex> lock(current.mutex);
        current.pending = false;
        current.ui_status = {false, true, true,
            "Theme retry scheduling failed",
            "The retained theme request could not be queued again."};
    }
}

request_result_t submit_request(request_t request)
{
    runtime_t& current = runtime();
    {
        std::lock_guard<std::mutex> lock(current.mutex);
        if (current.pending)
            return request_result_t::busy;
        current.pending = true;
        current.ui_status.pending = true;
        current.ui_status.failed = false;
        current.ui_status.retryable = false;
        current.ui_status.error.clear();
        current.ui_status.stage = request.operation == operation_t::import_theme
            ? "Theme import queued" : "Theme export queued";
    }
    request.serial = current.serial.fetch_add(1, std::memory_order_acq_rel) + 1;
    request.task_id = "theme.transfer." + std::to_string(request.serial);
    auto immutable_request = std::make_shared<const request_t>(std::move(request));
    {
        std::lock_guard<std::mutex> lock(current.mutex);
        current.active_request = immutable_request;
        current.completion.reset();
    }
    aida::ui::task_center::task_registration_t registration;
    registration.id = immutable_request->task_id;
    registration.source = "theme_transfer";
    registration.owner = "Appearance";
    registration.owner_view = "view.settings";
    registration.owner_action = immutable_request->operation == operation_t::import_theme
        ? "Import theme" : "Export theme";
    registration.target = "AiDA custom theme";
    registration.label = registration.owner_action;
    registration.stage = "Queued bounded theme file operation";
    registration.affected_entity = "settings.custom_themes";
    registration.callbacks.retry = [serial = immutable_request->serial] {
        runtime_t& retry_runtime = runtime();
        std::lock_guard<std::mutex> lock(retry_runtime.mutex);
        if (retry_runtime.pending || !retry_runtime.failed_request ||
            retry_runtime.failed_request->serial != serial)
            return false;
        retry_runtime.retry_requested.store(serial, std::memory_order_release);
        return true;
    };
    if (!aida::ui::task_center::register_task(std::move(registration))) {
        std::lock_guard<std::mutex> lock(current.mutex);
        current.pending = false;
        current.failed_request = immutable_request;
        current.active_request.reset();
        current.ui_status = {false, true, true,
            "Theme transfer scheduling failed",
            "Task Center rejected the theme file operation."};
        return request_result_t::rejected;
    }
    auto result = std::make_shared<completion_t>();
    result->serial = immutable_request->serial;
    result->operation = immutable_request->operation;
    aida::infra::executor::submission_t submission;
    submission.owner_subsystem = "theme_transfer";
    submission.label = "theme.transfer.file_io";
    submission.thread_class = "bounded_file_io";
    submission.domain = aida::infra::executor::domain_t::diagnostics;
    submission.priority = 2;
    submission.generation = immutable_request->serial;
    submission.ui_access_policy = "none";
    submission.failure_policy = "retain_request_for_retry";
    submission.shutdown_policy = "drain";
    submission.body = [immutable_request, result] {
        static_cast<void>(aida::ui::task_center::update_task(
            immutable_request->task_id,
            aida::ui::task_center::task_state_t::running, 0.2f,
            immutable_request->operation == operation_t::import_theme
                ? "Reading bounded theme document" : "Writing atomic theme export"));
        std::string error;
        try {
            if (immutable_request->operation == operation_t::import_theme) {
                std::string payload;
                theme_t theme;
                result->success = read_file_exact(immutable_request->path, payload, error) &&
                    parse_theme(payload, theme, error);
                if (result->success)
                    result->imported_theme = std::move(theme);
            } else {
                result->success = write_file_atomic(*immutable_request, error);
            }
        } catch (const std::exception&) {
            result->success = false;
            error = "The theme document could not be processed safely.";
        } catch (...) {
            result->success = false;
            error = "The theme transfer failed with an unknown error.";
        }
        result->error = std::move(error);
        runtime_t& completed_runtime = runtime();
        {
            std::lock_guard<std::mutex> lock(completed_runtime.mutex);
            completed_runtime.completion = result;
            if (result->success && result->operation == operation_t::import_theme) {
                completed_runtime.ui_status.stage = "Theme validated; awaiting UI application";
            } else {
                completed_runtime.pending = false;
                completed_runtime.active_request.reset();
                completed_runtime.ui_status.pending = false;
                completed_runtime.ui_status.failed = !result->success;
                completed_runtime.ui_status.retryable = !result->success;
                completed_runtime.ui_status.stage = result->success
                    ? "Theme export completed" : "Theme transfer failed";
                completed_runtime.ui_status.error = result->error;
                if (result->success)
                    completed_runtime.failed_request.reset();
                else
                    completed_runtime.failed_request = immutable_request;
            }
        }
        if (result->success && result->operation == operation_t::import_theme) {
            static_cast<void>(aida::ui::task_center::update_task(
                immutable_request->task_id,
                aida::ui::task_center::task_state_t::running, 0.9f,
                "Theme validated; awaiting UI application"));
        } else {
            static_cast<void>(aida::ui::task_center::update_task(
                immutable_request->task_id,
                result->success ? aida::ui::task_center::task_state_t::completed :
                    aida::ui::task_center::task_state_t::failed,
                1.0f,
                result->success ? "Theme export replaced atomically" :
                    "Theme transfer failed",
                result->error));
        }
    };
    const auto submitted = aida::infra::executor::submit(std::move(submission));
    if (!submitted.submitted) {
        {
            std::lock_guard<std::mutex> lock(current.mutex);
            current.pending = false;
            current.failed_request = immutable_request;
            current.active_request.reset();
            current.ui_status = {false, true, true,
                "Theme transfer scheduling failed",
                "The bounded theme file worker could not be scheduled."};
        }
        static_cast<void>(aida::ui::task_center::update_task(
            immutable_request->task_id,
            aida::ui::task_center::task_state_t::failed, 1.0f,
            "Theme transfer scheduling failed", submitted.reject_reason));
        return request_result_t::rejected;
    }
    return request_result_t::queued;
}

bool valid_request_path(const std::string& path) noexcept
{
    return bounded_text(path, maximum_icon_path_bytes, false);
}

}

request_result_t request_import(std::string path) noexcept
{
    if (!aida::ui_thread::is_owner_thread() || !valid_request_path(path))
        return request_result_t::rejected;
    try {
        request_t request;
        request.operation = operation_t::import_theme;
        request.path = std::filesystem::path(std::move(path));
        return submit_request(std::move(request));
    } catch (...) {
        return request_result_t::rejected;
    }
}

request_result_t request_export(std::string path, const theme_t& theme) noexcept
{
    if (!aida::ui_thread::is_owner_thread() || !valid_request_path(path))
        return request_result_t::rejected;
    try {
        std::string error;
        if (!validate_theme(theme, error)) {
            runtime_t& current = runtime();
            std::lock_guard<std::mutex> lock(current.mutex);
            current.ui_status = {false, true, false,
                "Theme export validation failed", std::move(error)};
            return request_result_t::rejected;
        }
        request_t request;
        request.operation = operation_t::export_theme;
        request.path = std::filesystem::path(std::move(path));
        request.export_payload = serialize_theme(theme).dump(2);
        if (request.export_payload.empty() ||
            request.export_payload.size() > kMaximumDocumentBytes)
            return request_result_t::rejected;
        return submit_request(std::move(request));
    } catch (...) {
        return request_result_t::rejected;
    }
}

std::optional<completion_t> take_completion() noexcept
{
    process_retry();
    runtime_t& current = runtime();
    std::lock_guard<std::mutex> lock(current.mutex);
    if (!current.completion)
        return std::nullopt;
    completion_t result = std::move(*current.completion);
    current.completion.reset();
    return result;
}

void acknowledge_import(std::uint64_t serial, bool applied, std::string error) noexcept
{
    if (!aida::ui_thread::is_owner_thread())
        return;
    runtime_t& current = runtime();
    std::string task_id;
    std::string result_error;
    {
        std::lock_guard<std::mutex> lock(current.mutex);
        if (!current.active_request || current.active_request->serial != serial ||
            current.active_request->operation != operation_t::import_theme)
            return;
        task_id = current.active_request->task_id;
        current.pending = false;
        current.ui_status.pending = false;
        current.ui_status.failed = !applied;
        current.ui_status.retryable = !applied;
        current.ui_status.stage = applied ? "Theme import completed" :
            "Theme import application failed";
        current.ui_status.error = std::move(error);
        result_error = current.ui_status.error;
        if (applied)
            current.failed_request.reset();
        else
            current.failed_request = current.active_request;
        current.active_request.reset();
    }
    static_cast<void>(aida::ui::task_center::update_task(task_id,
        applied ? aida::ui::task_center::task_state_t::completed :
            aida::ui::task_center::task_state_t::failed,
        1.0f,
        applied ? "Theme imported; settings persistence queued" :
            "Theme import could not be applied",
        std::move(result_error)));
}

bool request_retry() noexcept
{
    if (!aida::ui_thread::is_owner_thread())
        return false;
    runtime_t& current = runtime();
    std::lock_guard<std::mutex> lock(current.mutex);
    if (current.pending || !current.failed_request)
        return false;
    current.retry_requested.store(current.failed_request->serial,
        std::memory_order_release);
    return true;
}

status_t status() noexcept
{
    runtime_t& current = runtime();
    std::lock_guard<std::mutex> lock(current.mutex);
    return current.ui_status;
}


}
