#include "schema_runtime.hpp"

#include <nlohmann/json-schema.hpp>

#include <algorithm>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

namespace aida::standalone::mcp::protocol {

namespace {

constexpr std::size_t k_max_schema_bytes = 2u * 1024u * 1024u;
constexpr std::size_t k_max_schema_nodes = 65536u;
constexpr std::size_t k_max_schema_depth = 128u;
constexpr std::size_t k_max_errors = 64u;
constexpr std::size_t k_max_fragment_bytes = 256u;
constexpr std::size_t k_max_message_bytes = 512u;

std::string bounded_string(const std::string& value, std::size_t maximum) {
    if (value.size() <= maximum) {
        return value;
    }
    if (maximum <= 3) {
        return value.substr(0, maximum);
    }
    return value.substr(0, maximum - 3) + "...";
}

std::string escape_json_pointer_token(const std::string& token) {
    std::string escaped;
    escaped.reserve(token.size());
    for (const char character : token) {
        if (character == '~') {
            escaped += "~0";
        } else if (character == '/') {
            escaped += "~1";
        } else {
            escaped += character;
        }
    }
    return escaped;
}

std::string bounded_fragment(const json& value) {
    if (value.is_object()) {
        return "object(size=" + std::to_string(value.size()) + ")";
    }
    if (value.is_array()) {
        return "array(size=" + std::to_string(value.size()) + ")";
    }
    try {
        return bounded_string(value.dump(), k_max_fragment_bytes);
    } catch (...) {
        return "unavailable";
    }
}

void add_error(
    schema_validation_t& result,
    std::string path,
    std::string keyword,
    std::string message,
    std::string instance_fragment = {}) {
    result.valid = false;
    if (result.errors.size() == k_max_errors) {
        result.truncated = true;
        return;
    }
    result.errors.push_back({
        std::move(path),
        std::move(keyword),
        bounded_string(message, k_max_message_bytes),
        bounded_string(instance_fragment, k_max_fragment_bytes),
    });
}

void normalize_errors(schema_validation_t& result) {
    std::sort(result.errors.begin(), result.errors.end(), [](const schema_error_t& left, const schema_error_t& right) {
        if (left.path != right.path) {
            return left.path < right.path;
        }
        if (left.keyword != right.keyword) {
            return left.keyword < right.keyword;
        }
        if (left.message != right.message) {
            return left.message < right.message;
        }
        return left.instance_fragment < right.instance_fragment;
    });
    result.errors.erase(
        std::unique(result.errors.begin(), result.errors.end(), [](const schema_error_t& left, const schema_error_t& right) {
            return left.path == right.path &&
                   left.keyword == right.keyword &&
                   left.message == right.message &&
                   left.instance_fragment == right.instance_fragment;
        }),
        result.errors.end());
}

bool is_local_reference(const json& value) {
    if (!value.is_string()) {
        return false;
    }
    const std::string& reference = value.get_ref<const std::string&>();
    return !reference.empty() && reference.front() == '#';
}

void inspect_schema_node(
    const json& value,
    const std::string& path,
    std::size_t depth,
    std::size_t& visited,
    schema_validation_t& result) {
    if (depth > k_max_schema_depth) {
        add_error(result, path, "depth", "schema exceeds the maximum nesting depth");
        return;
    }
    if (++visited > k_max_schema_nodes) {
        add_error(result, path, "size", "schema exceeds the maximum node count");
        return;
    }
    if (value.is_object()) {
        for (auto it = value.begin(); it != value.end(); ++it) {
            const std::string child_path = path + "/" + escape_json_pointer_token(it.key());
            if (it.key() == "$ref" || it.key() == "$dynamicRef" || it.key() == "$recursiveRef") {
                if (!is_local_reference(it.value())) {
                    add_error(
                        result,
                        child_path,
                        "reference",
                        "remote schema references are disabled",
                        bounded_fragment(it.value()));
                }
            } else if (it.key() == "$id") {
                if (!it.value().is_string() || (!it.value().get_ref<const std::string&>().empty() &&
                                               it.value().get_ref<const std::string&>().front() != '#')) {
                    add_error(
                        result,
                        child_path,
                        "identifier",
                        "external schema identifiers are disabled",
                        bounded_fragment(it.value()));
                }
            }
            inspect_schema_node(it.value(), child_path, depth + 1, visited, result);
        }
        return;
    }
    if (value.is_array()) {
        for (std::size_t index = 0; index < value.size(); ++index) {
            inspect_schema_node(value[index], path + "/" + std::to_string(index), depth + 1, visited, result);
        }
    }
}

schema_validation_t inspect_schema(const json& schema) {
    schema_validation_t result;
    if (!schema.is_object()) {
        add_error(result, "(schema)", "type", "schema must be a JSON object", bounded_fragment(schema));
        return result;
    }

    std::string serialized;
    try {
        serialized = schema.dump();
    } catch (...) {
        add_error(result, "(schema)", "serialization", "schema serialization failed");
        return result;
    }
    if (serialized.size() > k_max_schema_bytes) {
        add_error(result, "(schema)", "size", "schema exceeds the maximum serialized size");
        return result;
    }

    std::size_t visited = 0;
    inspect_schema_node(schema, "#", 0, visited, result);
    normalize_errors(result);
    return result;
}

nlohmann::json_schema::schema_loader rejecting_schema_loader() {
    return [](const nlohmann::json_uri&, json&) {
        throw std::runtime_error("remote schema retrieval is disabled");
    };
}

class collecting_error_handler_t final : public nlohmann::json_schema::basic_error_handler {
public:
    explicit collecting_error_handler_t(schema_validation_t& result)
        : result_(result) {
    }

    void error(
        const json::json_pointer& pointer,
        const json& instance,
        const std::string& message) override {
        std::string path = pointer.to_string();
        if (path.empty()) {
            path = "(root)";
        }
        add_error(result_, std::move(path), "validation", message, bounded_fragment(instance));
    }

    void reset() override {
        basic_error_handler::reset();
    }

private:
    schema_validation_t& result_;
};

}

struct schema_runtime_t::impl_t {
    struct compiled_schema_t {
        schema_validation_t setup;
        std::unique_ptr<nlohmann::json_schema::json_validator> validator;
        std::mutex validation_mutex;
    };

    struct cache_entry_t {
        std::shared_ptr<compiled_schema_t> compiled;
        std::uint64_t last_used = 0;
    };

    explicit impl_t(std::size_t requested_capacity)
        : capacity(requested_capacity == 0 ? 1 : requested_capacity) {
    }

    std::shared_ptr<compiled_schema_t> acquire(const json& schema) {
        std::string key;
        try {
            key = schema.dump();
        } catch (...) {
            auto failed = std::make_shared<compiled_schema_t>();
            add_error(failed->setup, "(schema)", "serialization", "schema serialization failed");
            return failed;
        }

        {
            std::lock_guard<std::mutex> lock(cache_mutex);
            const auto existing = cache.find(key);
            if (existing != cache.end()) {
                ++statistics.hits;
                existing->second.last_used = ++clock;
                return existing->second.compiled;
            }
            ++statistics.misses;
        }

        auto compiled = std::make_shared<compiled_schema_t>();
        compiled->setup = inspect_schema(schema);
        if (compiled->setup.valid) {
            try {
                compiled->validator = std::make_unique<nlohmann::json_schema::json_validator>(
                    rejecting_schema_loader(), nullptr, nullptr);
                compiled->validator->set_root_schema(schema);
            } catch (...) {
                add_error(
                    compiled->setup,
                    "(schema)",
                    "compilation",
                    "schema validator initialization failed");
            }
        }
        normalize_errors(compiled->setup);

        std::lock_guard<std::mutex> lock(cache_mutex);
        const auto existing = cache.find(key);
        if (existing != cache.end()) {
            ++statistics.hits;
            existing->second.last_used = ++clock;
            return existing->second.compiled;
        }

        while (cache.size() >= capacity) {
            const auto victim = std::min_element(cache.begin(), cache.end(), [](const auto& left, const auto& right) {
                return left.second.last_used < right.second.last_used;
            });
            if (victim == cache.end()) {
                break;
            }
            cache.erase(victim);
            ++statistics.evictions;
        }
        cache.emplace(key, cache_entry_t{compiled, ++clock});
        return compiled;
    }

    std::size_t capacity;
    mutable std::mutex cache_mutex;
    std::map<std::string, cache_entry_t> cache;
    schema_cache_stats_t statistics;
    std::uint64_t clock = 0;
};

json schema_validation_t::diagnostics() const {
    json serialized_errors = json::array();
    for (const auto& error : errors) {
        serialized_errors.push_back(json{
            {"path", error.path},
            {"keyword", error.keyword},
            {"message", error.message},
            {"instance", error.instance_fragment},
        });
    }
    return json{
        {"valid", valid},
        {"truncated", truncated},
        {"errors", std::move(serialized_errors)},
    };
}

std::string schema_validation_t::summary() const {
    if (valid) {
        return "valid";
    }
    std::ostringstream stream;
    stream << "schema validation failed with " << errors.size() << " error(s)";
    if (truncated) {
        stream << "; additional errors were truncated";
    }
    for (const auto& error : errors) {
        stream << "; at " << error.path << ": " << error.message;
    }
    return stream.str();
}

schema_runtime_t::schema_runtime_t(std::size_t cache_capacity)
    : impl_(std::make_unique<impl_t>(cache_capacity)) {
}

schema_runtime_t::~schema_runtime_t() = default;

schema_runtime_t::schema_runtime_t(schema_runtime_t&&) noexcept = default;

schema_runtime_t& schema_runtime_t::operator=(schema_runtime_t&&) noexcept = default;

schema_validation_t schema_runtime_t::compile(const json& schema) {
    if (!impl_) {
        schema_validation_t result;
        add_error(result, "(runtime)", "state", "schema runtime is moved-from");
        return result;
    }
    return impl_->acquire(schema)->setup;
}

schema_validation_t schema_runtime_t::validate(const json& schema, const json& instance) {
    if (!impl_) {
        schema_validation_t result;
        add_error(result, "(runtime)", "state", "schema runtime is moved-from");
        return result;
    }
    const auto compiled = impl_->acquire(schema);
    if (!compiled->setup.valid || !compiled->validator) {
        return compiled->setup;
    }

    schema_validation_t result;
    collecting_error_handler_t error_handler(result);
    try {
        std::lock_guard<std::mutex> lock(compiled->validation_mutex);
        compiled->validator->validate(instance, error_handler, nlohmann::json_uri("#"));
    } catch (...) {
        add_error(result, "(root)", "execution", "schema validation execution failed");
    }
    normalize_errors(result);
    return result;
}

schema_cache_stats_t schema_runtime_t::cache_stats() const {
    if (!impl_)
        return {};
    std::lock_guard<std::mutex> lock(impl_->cache_mutex);
    schema_cache_stats_t result = impl_->statistics;
    result.entries = impl_->cache.size();
    return result;
}

void schema_runtime_t::clear() {
    if (!impl_)
        return;
    std::lock_guard<std::mutex> lock(impl_->cache_mutex);
    impl_->cache.clear();
    impl_->statistics.entries = 0;
}

}
