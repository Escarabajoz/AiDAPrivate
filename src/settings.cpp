#include "aida_pro.hpp"

#include <cmath>
#include <limits>

#ifdef __NT__
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "Crypt32.lib")
#include "aida_ipc.hpp"
#endif

static constexpr uint8_t CFG_OBF_KEY[] = {
    0xA3, 0x7B, 0x1E, 0xD4, 0x5F, 0x92, 0xC8, 0x06,
    0xE1, 0x3A, 0x8D, 0x47, 0xB0, 0x6C, 0xF5, 0x29
};
static constexpr const char CFG_OBF_PREFIX[] = "enc1:";
static constexpr const char CFG_DPAPI_PREFIX[] = "dpapi1:";

static std::string hex_encode_bytes(const unsigned char* data, size_t size)
{
    std::string out;
    out.reserve(size * 2);
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < size; ++i)
    {
        const unsigned char b = data[i];
        out.push_back(digits[(b >> 4) & 0x0F]);
        out.push_back(digits[b & 0x0F]);
    }
    return out;
}

static bool hex_decode_bytes(const std::string& text, std::vector<unsigned char>& out)
{
    if ((text.size() % 2) != 0)
        return false;

    out.clear();
    out.reserve(text.size() / 2);
    for (size_t i = 0; i < text.size(); i += 2)
    {
        unsigned int byte_value = 0;
        std::istringstream iss(text.substr(i, 2));
        iss >> std::hex >> byte_value;
        if (iss.fail())
            return false;
        out.push_back(static_cast<unsigned char>(byte_value));
    }
    return true;
}

#ifdef __NT__
static std::string protect_with_dpapi(const std::string& plaintext, const char* scope)
{
    if (plaintext.empty())
        return plaintext;

    DATA_BLOB input_blob{};
    input_blob.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(plaintext.data()));
    input_blob.cbData = static_cast<DWORD>(plaintext.size());

    DATA_BLOB entropy_blob{};
    entropy_blob.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(scope));
    entropy_blob.cbData = static_cast<DWORD>(std::strlen(scope));

    DATA_BLOB output_blob{};
    if (!CryptProtectData(&input_blob,
                          L"AiDA Secret",
                          &entropy_blob,
                          nullptr,
                          nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN,
                          &output_blob))
    {
        return "";
    }

    std::string protected_hex = hex_encode_bytes(output_blob.pbData, output_blob.cbData);
    LocalFree(output_blob.pbData);
    return std::string(CFG_DPAPI_PREFIX) + protected_hex;
}

static std::string unprotect_with_dpapi(const std::string& encoded, const char* scope)
{
    if (encoded.compare(0, sizeof(CFG_DPAPI_PREFIX) - 1, CFG_DPAPI_PREFIX) != 0)
        return "";

    std::vector<unsigned char> protected_bytes;
    if (!hex_decode_bytes(encoded.substr(sizeof(CFG_DPAPI_PREFIX) - 1), protected_bytes))
        return "";

    DATA_BLOB input_blob{};
    input_blob.pbData = protected_bytes.data();
    input_blob.cbData = static_cast<DWORD>(protected_bytes.size());

    DATA_BLOB entropy_blob{};
    entropy_blob.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(scope));
    entropy_blob.cbData = static_cast<DWORD>(std::strlen(scope));

    DATA_BLOB output_blob{};
    if (!CryptUnprotectData(&input_blob,
                            nullptr,
                            &entropy_blob,
                            nullptr,
                            nullptr,
                            CRYPTPROTECT_UI_FORBIDDEN,
                            &output_blob))
    {
        return "";
    }

    std::string plaintext(reinterpret_cast<const char*>(output_blob.pbData), output_blob.cbData);
    SecureZeroMemory(output_blob.pbData, output_blob.cbData);
    LocalFree(output_blob.pbData);
    return plaintext;
}
#endif

static std::string obfuscate_key(const std::string& plain)
{
    if (plain.empty())
        return plain;


#ifdef __NT__
    if (std::string protected_value = protect_with_dpapi(plain, "AiDA:settings:v1");
        !protected_value.empty())
    {
        return protected_value;
    }
#endif

    std::string out;
    out.reserve(plain.size() * 2 + sizeof(CFG_OBF_PREFIX));
    out = CFG_OBF_PREFIX;

    for (size_t i = 0; i < plain.size(); ++i)
    {
        uint8_t b = static_cast<uint8_t>(plain[i]) ^ CFG_OBF_KEY[i % sizeof(CFG_OBF_KEY)];
        char hex[3];
        qsnprintf(hex, sizeof(hex), "%02x", b);
        out += hex;
    }
    return out;
}

static std::string deobfuscate_key(const std::string& encoded)
{
    if (encoded.empty())
        return encoded;


#ifdef __NT__
    if (encoded.compare(0, sizeof(CFG_DPAPI_PREFIX) - 1, CFG_DPAPI_PREFIX) == 0)
    {
        std::string plaintext = unprotect_with_dpapi(encoded, "AiDA:settings:v1");
        return plaintext;
    }
#endif

    if (encoded.compare(0, sizeof(CFG_OBF_PREFIX) - 1, CFG_OBF_PREFIX) != 0)
        return encoded;


    std::string hex_part = encoded.substr(sizeof(CFG_OBF_PREFIX) - 1);
    std::string out;
    out.reserve(hex_part.size() / 2);

    for (size_t i = 0; i + 1 < hex_part.size(); i += 2)
    {
        uint8_t b = static_cast<uint8_t>(std::stoi(hex_part.substr(i, 2), nullptr, 16));
        b ^= CFG_OBF_KEY[(i / 2) % sizeof(CFG_OBF_KEY)];
        out.push_back(static_cast<char>(b));
    }
    return out;
}

static std::string get_trimmed_json_string(const nlohmann::json& j, const char* key, const std::string& default_val)
{
    std::string val = j.value(key, default_val);
    qstring q_val = val.c_str();
    q_val.trim2();
    return q_val.c_str();
}

static std::string get_trimmed_key_string(const nlohmann::json& j, const char* key, const std::string& default_val)
{
    std::string raw = get_trimmed_json_string(j, key, default_val);
    return deobfuscate_key(raw);
}

settings_t g_settings;

const std::vector<std::string> settings_t::gemini_models = {
    std::string("gemini-3-pro-preview"),
    std::string("gemini-2.5-pro"),
    std::string("gemini-2.5-flash"),
    std::string("gemini-2.5-flash-lite"),
    std::string("gemini-2.0-flash"),
    std::string("gemini-2.0-flash-lite"),
    std::string("gemini-1.5-pro-latest"),
    std::string("gemini-1.5-pro"),
    std::string("gemini-1.5-pro-002"),
    std::string("gemini-1.5-flash-latest"),
    std::string("gemini-1.5-flash"),
    std::string("gemini-1.5-flash-8b"),
    std::string("gemini-1.5-flash-8b-latest"),
    std::string("gemini-2.0-flash-exp"),
    std::string("gemini-2.0-flash-lite-preview"),
    std::string("gemini-2.0-pro-exp"),
    std::string("gemini-2.0-flash-thinking-exp"),
    std::string("gemma-3-1b-it"),
    std::string("gemma-3-4b-it"),
    std::string("gemma-3-12b-it"),
    std::string("gemma-3-27b-it"),
    std::string("gemma-3n-e4b-it"),
    std::string("gemma-3n-e2b-it")
};

const std::vector<std::string> settings_t::openai_models = {
  std::string("gpt-5.1 Instant"),
  std::string("gpt-5.1 Thinking"),
  std::string("gpt-5"),
  std::string("gpt-5-mini"),
  std::string("gpt-5-nano"),
  std::string("o3-pro"),
  std::string("o3"),
  std::string("o3-mini"),
  std::string("o1-pro"),
  std::string("o1"),
  std::string("o4-mini"),
  std::string("gpt-4.5-preview"),
  std::string("gpt-4.1"),
  std::string("gpt-4.1-mini"),
  std::string("gpt-4.1-nano"),
  std::string("gpt-4o"),
  std::string("gpt-4-turbo"),
  std::string("gpt-4"),
  std::string("gpt-4o-mini"),
  std::string("gpt-3.5-turbo"),
  std::string("gpt-3.5-turbo-16k"),
};

const std::vector<std::string> settings_t::openrouter_models = {
  std::string("moonshotai/kimi-k2:free"),
  std::string("openai/gpt-oss-20b:free"),
  std::string("z-ai/glm-4.5-air:free"),
  std::string("tngtech/deepseek-r1t2-chimera:free"),

};

const std::vector<std::string> settings_t::anthropic_models = {
  std::string("claude-opus-4-6"),
  std::string("claude-opus-4-6 (Max Effort)"),
  std::string("claude-opus-4-6 (Standard)"),
  std::string("claude-sonnet-4-6"),
  std::string("claude-opus-4-5 (High Effort)"),
  std::string("claude-opus-4-5 (Medium Effort)"),
  std::string("claude-opus-4-5 (Low Effort)"),
  std::string("claude-sonnet-4-5"),
  std::string("claude-haiku-4-5"),
  std::string("claude-opus-4-1"),
  std::string("claude-opus-4"),
  std::string("claude-sonnet-4"),
  std::string("claude-3-7-sonnet-thought"),
  std::string("claude-3-7-sonnet"),
  std::string("claude-3.5-sonnet-latest"),
  std::string("claude-3.5-haiku-latest"),
  std::string("claude-3-opus-latest"),
  std::string("claude-3-sonnet-latest"),
  std::string("claude-3-haiku-latest"),
  std::string("claude-2.1"),
  std::string("claude-2"),
  std::string("claude-instant-v1.2"),
};

const std::vector<std::string> settings_t::copilot_models = {
    std::string("gpt-5.3-codex"),
    std::string("claude-sonnet-4"),
    std::string("claude-3.7-sonnet-thought"),
    std::string("gemini-2.5-pro"),
    std::string("claude-3.7-sonnet"),
    std::string("gpt-4.1-2025-04-14"),
    std::string("gpt-4.1"),
    std::string("o4-mini-2025-04-16"),
    std::string("o4-mini"),
    std::string("o3-mini-2025-01-31"),
    std::string("o3-mini"),
    std::string("o3-mini-paygo"),
    std::string("claude-3.5-sonnet"),
    std::string("gemini-2.0-flash-001"),
    std::string("gpt-4o-2024-11-20"),
    std::string("gpt-4o-2024-08-06"),
    std::string("gpt-4o-2024-05-13"),
    std::string("gpt-4o"),
    std::string("gpt-4o-copilot"),
    std::string("gpt-4-o-preview"),
    std::string("gpt-4-0125-preview"),
    std::string("gpt-4"),
    std::string("gpt-4-0613"),
    std::string("gpt-4o-mini-2024-07-18"),
    std::string("gpt-4o-mini"),
    std::string("gpt-3.5-turbo"),
    std::string("gpt-3.5-turbo-0613"),
};

const std::vector<std::string> settings_t::local_llm_models = {
    std::string("llama3.3:latest"),
    std::string("llama3.1:latest"),
    std::string("llama3:latest"),
    std::string("qwen3:latest"),
    std::string("qwen2.5-coder:latest"),
    std::string("deepseek-r1:latest"),
    std::string("deepseek-coder-v2:latest"),
    std::string("codellama:latest"),
    std::string("mistral:latest"),
    std::string("mixtral:latest"),
    std::string("phi4:latest"),
    std::string("gemma3:latest"),
    std::string("command-r:latest"),
};

static void to_json(nlohmann::json& j, const settings_t& s)
{
    j = nlohmann::json{
        {"api_provider", s.api_provider},
        {"gemini_api_key", obfuscate_key(s.gemini_api_key)},
        {"gemini_model_name", s.gemini_model_name},
        {"gemini_base_url", s.gemini_base_url},
        {"openai_api_key", obfuscate_key(s.openai_api_key)},
        {"openai_model_name", s.openai_model_name},
        {"openai_base_url", s.openai_base_url},
        {"openrouter_api_key", obfuscate_key(s.openrouter_api_key)},
        {"openrouter_model_name", s.openrouter_model_name},
        {"anthropic_api_key", obfuscate_key(s.anthropic_api_key)},
        {"anthropic_model_name", s.anthropic_model_name},
        {"anthropic_base_url", s.anthropic_base_url},
        {"copilot_proxy_address", s.copilot_proxy_address},
        {"copilot_model_name", s.copilot_model_name},
        {"local_llm_base_url", s.local_llm_base_url},
        {"local_llm_model_name", s.local_llm_model_name},
        {"local_llm_api_key", obfuscate_key(s.local_llm_api_key)},
        {"local_llm_context_window", s.local_llm_context_window},
        {"xref_context_count", s.xref_context_count},
        {"xref_analysis_depth", s.xref_analysis_depth},
        {"xref_code_snippet_lines", s.xref_code_snippet_lines},
        {"bulk_processing_delay", s.bulk_processing_delay},
        {"max_root_func_scan_count", s.max_root_func_scan_count},
        {"max_root_func_candidates", s.max_root_func_candidates},
        {"custom_prompts", s.custom_prompts},
        {"active_prompt_name", s.active_prompt_name},
        {"temperature", s.temperature},
        {"check_for_updates", s.check_for_updates},
        {"mcp_enabled", s.mcp_enabled},
        {"mcp_port", s.mcp_port},
        {"embedding_enabled", s.embedding_enabled},
        {"embedding_api_url", s.embedding_api_url},
        {"embedding_api_key", obfuscate_key(s.embedding_api_key)},
        {"embedding_model_name", s.embedding_model_name},
        {"embedding_dimensions", s.embedding_dimensions},
        {"embedding_batch_size", s.embedding_batch_size}
    };
}

static int safe_json_int(const nlohmann::json& j, const char* key, int fallback)
{
    auto it = j.find(key);
    if (it == j.end() || it->is_null())
        return fallback;
    if (it->is_number_integer())
    {
        const std::int64_t v = it->get<std::int64_t>();
        if (v >= (std::numeric_limits<int>::min)() && v <= (std::numeric_limits<int>::max)())
            return static_cast<int>(v);
        return fallback;
    }
    if (it->is_number_unsigned())
    {
        const std::uint64_t v = it->get<std::uint64_t>();
        if (v <= static_cast<std::uint64_t>((std::numeric_limits<int>::max)()))
            return static_cast<int>(v);
        return fallback;
    }
    if (it->is_number_float())
    {
        const double v = it->get<double>();
        if (std::isfinite(v) && v >= (std::numeric_limits<int>::min)() && v <= (std::numeric_limits<int>::max)())
            return static_cast<int>(v);
        return fallback;
    }
    return fallback;
}

static double safe_json_double(const nlohmann::json& j, const char* key, double fallback)
{
    auto it = j.find(key);
    if (it == j.end() || it->is_null())
        return fallback;
    if (it->is_number_float() || it->is_number_integer() || it->is_number_unsigned())
    {
        const double v = it->get<double>();
        if (std::isfinite(v))
            return v;
        return fallback;
    }
    return fallback;
}

static void from_json(const nlohmann::json& j, settings_t& s)
{
    settings_t d;
    s.api_provider = j.value("api_provider", d.api_provider);

    s.gemini_api_key = get_trimmed_key_string(j, "gemini_api_key", d.gemini_api_key);
    s.gemini_model_name = j.value("gemini_model_name", d.gemini_model_name);
    s.gemini_base_url = get_trimmed_json_string(j, "gemini_base_url", d.gemini_base_url);

    s.openai_api_key = get_trimmed_key_string(j, "openai_api_key", d.openai_api_key);
    s.openai_model_name = j.value("openai_model_name", d.openai_model_name);
    s.openai_base_url = get_trimmed_json_string(j, "openai_base_url", d.openai_base_url);

    s.openrouter_api_key = get_trimmed_key_string(j, "openrouter_api_key", d.openrouter_api_key);
    s.openrouter_model_name = j.value("openrouter_model_name", d.openrouter_model_name);

    s.anthropic_api_key = get_trimmed_key_string(j, "anthropic_api_key", d.anthropic_api_key);
    s.anthropic_model_name = j.value("anthropic_model_name", d.anthropic_model_name);
    s.anthropic_base_url = get_trimmed_json_string(j, "anthropic_base_url", d.anthropic_base_url);

    s.copilot_proxy_address = j.value("copilot_proxy_address", d.copilot_proxy_address);
    s.copilot_model_name = j.value("copilot_model_name", d.copilot_model_name);

    s.local_llm_base_url = get_trimmed_json_string(j, "local_llm_base_url", d.local_llm_base_url);
    s.local_llm_model_name = j.value("local_llm_model_name", d.local_llm_model_name);
    s.local_llm_api_key = get_trimmed_key_string(j, "local_llm_api_key", d.local_llm_api_key);
    s.local_llm_context_window = safe_json_int(j, "local_llm_context_window", d.local_llm_context_window);

    s.xref_context_count = safe_json_int(j, "xref_context_count", d.xref_context_count);
    s.xref_analysis_depth = safe_json_int(j, "xref_analysis_depth", d.xref_analysis_depth);
    s.xref_code_snippet_lines = safe_json_int(j, "xref_code_snippet_lines", d.xref_code_snippet_lines);

    s.bulk_processing_delay = safe_json_double(j, "bulk_processing_delay", d.bulk_processing_delay);

    s.max_root_func_scan_count = safe_json_int(j, "max_root_func_scan_count", d.max_root_func_scan_count);
    s.max_root_func_candidates = safe_json_int(j, "max_root_func_candidates", d.max_root_func_candidates);

    s.temperature = safe_json_double(j, "temperature", d.temperature);
    s.check_for_updates = j.value("check_for_updates", d.check_for_updates);

    s.mcp_enabled = j.value("mcp_enabled", d.mcp_enabled);
    s.mcp_port = safe_json_int(j, "mcp_port", d.mcp_port);

    s.embedding_enabled = j.value("embedding_enabled", d.embedding_enabled);
    s.embedding_api_url = get_trimmed_json_string(j, "embedding_api_url", d.embedding_api_url);
    s.embedding_api_key = get_trimmed_key_string(j, "embedding_api_key", d.embedding_api_key);
    s.embedding_model_name = j.value("embedding_model_name", d.embedding_model_name);
    s.embedding_dimensions = safe_json_int(j, "embedding_dimensions", d.embedding_dimensions);
    s.embedding_batch_size = safe_json_int(j, "embedding_batch_size", d.embedding_batch_size);

    if (j.contains("custom_prompts"))
        j.at("custom_prompts").get_to(s.custom_prompts);
    s.active_prompt_name = j.value("active_prompt_name", d.active_prompt_name);
}

static qstring get_config_file()
{
    qstring path = get_user_idadir();
    path.append("/ai_assistant.cfg");
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_settings_get_config_file path=%s", path.c_str());
#endif
    return path;
}

static bool save_settings_to_file(const settings_t& settings, const qstring& path)
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_settings_save_enter path=%s exists=%d",
                               path.c_str(), qfileexist(path.c_str()) ? 1 : 0);
#endif
    try
    {
        nlohmann::json merged = nlohmann::json::object();
        if (qfileexist(path.c_str()))
        {
            FILE* existing = qfopen(path.c_str(), "rb");
            if (existing != nullptr)
            {
                file_janitor_t existing_fj(existing);
                const uint64 existing_size = qfsize(existing);
                if (existing_size > 0)
                {
                    qstring existing_json;
                    existing_json.resize(existing_size);
                    if (qfread(existing, existing_json.begin(), existing_size) == existing_size)
                    {
                        try
                        {
                            merged = nlohmann::json::parse(existing_json.c_str());
                            if (!merged.is_object())
                                merged = nlohmann::json::object();
                        }
                        catch (...)
                        {
                            merged = nlohmann::json::object();
                        }
                    }
                }
            }
        }

        nlohmann::json settings_json = settings;
        for (auto it = settings_json.begin(); it != settings_json.end(); ++it)
            merged[it.key()] = it.value();

        std::string json_str = merged.dump(4);

        FILE* fp = qfopen(path.c_str(), "wb");
        if (fp == nullptr)
        {
            warning("Failed to open settings file for writing: %s", path.c_str());
            return false;
        }

        file_janitor_t fj(fp);

        size_t written = qfwrite(fp, json_str.c_str(), json_str.length());
        if (written != json_str.length())
        {
            warning("Failed to write all settings to %s", path.c_str());
            return false;
        }

        msg("Settings saved to %s\n", path.c_str());
#ifdef __NT__
        aida_ipc::trace_breadcrumb("ida_settings_save_ok path=%s", path.c_str());
#endif
        return true;
    }
    catch (const std::exception& e)
    {
        warning("Failed to serialize settings: %s", e.what());
#ifdef __NT__
        aida_ipc::trace_breadcrumb("ida_settings_save_exception path=%s what=%s", path.c_str(), e.what());
#endif
        return false;
    }
}

static bool load_settings_from_file(settings_t& settings, const qstring& path)
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_settings_load_file_enter path=%s", path.c_str());
#endif
    if (!qfileexist(path.c_str()))
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("ida_settings_load_file_not_found path=%s", path.c_str());
#endif
        return false;
    }

    FILE* fp = qfopen(path.c_str(), "rb");
    if (fp == nullptr)
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("ida_settings_load_file_open_failed path=%s", path.c_str());
#endif
        return false;
    }

    file_janitor_t fj(fp);

    uint64 file_size = qfsize(fp);
    if (file_size == 0)
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("ida_settings_load_file_empty path=%s", path.c_str());
#endif
        return false;
    }

    qstring json_data;
    json_data.resize(file_size);
    if (qfread(fp, json_data.begin(), file_size) != file_size)
    {
        warning("Failed to read settings file: %s", path.c_str());
#ifdef __NT__
        aida_ipc::trace_breadcrumb("ida_settings_load_file_read_failed path=%s", path.c_str());
#endif
        return false;
    }

    try
    {
#ifdef __NT__
        aida_ipc::trace_breadcrumb("ida_settings_load_file_parse_enter path=%s size=%llu", path.c_str(), static_cast<unsigned long long>(file_size));
#endif
        nlohmann::json j = nlohmann::json::parse(json_data.c_str());

        bool missing = false;
        auto req = [&](const char* key){ if (!j.contains(key)) missing = true; };
        req("api_provider");
        req("gemini_api_key"); req("gemini_model_name"); req("gemini_base_url");
        req("openai_api_key"); req("openai_model_name"); req("openai_base_url");
        req("openrouter_api_key"); req("openrouter_model_name");
        req("anthropic_api_key"); req("anthropic_model_name"); req("anthropic_base_url");
        req("copilot_proxy_address"); req("copilot_model_name");
        req("local_llm_base_url"); req("local_llm_model_name"); req("local_llm_api_key");
        req("local_llm_context_window");
        req("xref_context_count"); req("xref_analysis_depth"); req("xref_code_snippet_lines");
        req("bulk_processing_delay");
        req("max_root_func_scan_count"); req("max_root_func_candidates");
        req("custom_prompts"); req("active_prompt_name");
        req("temperature");
        req("check_for_updates");
        req("mcp_enabled");
        req("mcp_port");

        settings = j.get<settings_t>();

        if (missing)
        {
#ifdef __NT__
            aida_ipc::trace_breadcrumb("ida_settings_load_file_missing_keys path=%s saving", path.c_str());
#endif
            save_settings_to_file(settings, path);
        }
#ifdef __NT__
        aida_ipc::trace_breadcrumb("ida_settings_load_file_ok path=%s provider=%s", path.c_str(), settings.api_provider.c_str());
#endif
        return true;
    }
    catch (const std::exception& e)
    {
        warning("Could not parse config file %s: %s", path.c_str(), e.what());
#ifdef __NT__
        aida_ipc::trace_breadcrumb("ida_settings_load_file_parse_error path=%s what=%s", path.c_str(), e.what());
#endif
        return false;
    }
}


settings_t::settings_t() :
    api_provider(""),
    gemini_api_key(""),
    gemini_model_name(std::string("gemini-2.5-flash")),
    gemini_base_url(""),
    openai_api_key(""),
    openai_model_name(std::string("gpt-5")),
    openai_base_url(""),
    openrouter_api_key(""),
    openrouter_model_name(std::string("moonshotai/kimi-k2:free")),
    anthropic_api_key(""),
    anthropic_model_name(std::string("claude-sonnet-4-5")),
    anthropic_base_url(""),
    copilot_proxy_address(std::string("http://127.0.0.1:4141")),
    copilot_model_name(std::string("gpt-5.3-codex")),
    local_llm_base_url(std::string("http://localhost:1234")),
    local_llm_model_name(""),
    local_llm_api_key(""),
    local_llm_context_window(8192),
    xref_context_count(5),
    xref_analysis_depth(3),
    xref_code_snippet_lines(30),
    bulk_processing_delay(1.5),
    max_root_func_scan_count(40),
    max_root_func_candidates(40),
    temperature(0.1),
    check_for_updates(true),
    mcp_enabled(true),
    mcp_port(13120),
    embedding_enabled(true),
    embedding_api_url(""),
    embedding_api_key(""),
    embedding_model_name(std::string("text-embedding-3-small")),
    embedding_dimensions(1536),
    embedding_batch_size(32)
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_settings_ctor_enter mcp_enabled=%d mcp_port=%d",
                               mcp_enabled ? 1 : 0, mcp_port);
#endif
}

void settings_t::save()
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_settings_save_call");
#endif
    save_settings_to_file(*this, get_config_file());
}

void settings_t::load(aida_plugin_t* plugin_instance)
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_settings_load_enter plugin=%p", static_cast<void*>(plugin_instance));
#endif
    bool has_env_keys = false;
    qstring val;

    if (gemini_api_key.empty() && qgetenv("GEMINI_API_KEY", &val))
    {
        val.trim2();
        gemini_api_key = val.c_str();
        has_env_keys = true;
    }
    if (openai_api_key.empty() && qgetenv("OPENAI_API_KEY", &val))
    {
        val.trim2();
        openai_api_key = val.c_str();
        has_env_keys = true;
    }
    if (openrouter_api_key.empty() && qgetenv("OPENROUTER_API_KEY", &val))
    {
        val.trim2();
        openrouter_api_key = val.c_str();
        has_env_keys = true;
    }
    if (anthropic_api_key.empty() && qgetenv("ANTHROPIC_API_KEY", &val))
    {
        val.trim2();
        anthropic_api_key = val.c_str();
        has_env_keys = true;
    }

    if (has_env_keys)
    {
        msg("Loaded one or more API keys from environment variables.\n");
#ifdef __NT__
        aida_ipc::trace_breadcrumb("ida_settings_load_env_keys_loaded");
#endif
    }

    bool config_exists_and_valid = load_from_file();
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_settings_load_after_load_from_file config_valid=%d provider_empty=%d",
                               config_exists_and_valid ? 1 : 0, api_provider.empty() ? 1 : 0);
#endif

    if (!config_exists_and_valid || api_provider.empty())
    {
        msg("AiDA: No configuration found. MCP server will start with defaults.\n");
#ifdef __NT__
        aida_ipc::trace_breadcrumb("ida_settings_load_no_config_using_defaults");
#endif
        return;
    }

    if (config_exists_and_valid)
    {
        msg("Loaded settings from %s\n", get_config_file().c_str());
#ifdef __NT__
        aida_ipc::trace_breadcrumb("ida_settings_load_ok path=%s provider=%s",
                                   get_config_file().c_str(), api_provider.c_str());
#endif
    }
}

bool settings_t::load_from_file()
{
#ifdef __NT__
    aida_ipc::trace_breadcrumb("ida_settings_load_from_file_call");
#endif
    return load_settings_from_file(*this, get_config_file());
}

std::string settings_t::get_active_api_key() const
{
    std::string result;
    qstring provider = ida_utils::qstring_tolower(api_provider.c_str());
    if (provider == "gemini")
        result = gemini_api_key.empty() ? gemini_base_url : gemini_api_key;
    else if (provider == "openai")
        result = openai_api_key.empty() ? openai_base_url : openai_api_key;
    else if (provider == "openrouter")
        result = openrouter_api_key;
    else if (provider == "anthropic")
        result = anthropic_api_key.empty() ? anthropic_base_url : anthropic_api_key;
    else if (provider == "copilot")
        result = copilot_proxy_address;
    else if (provider == "local llm")
        result = local_llm_base_url;
    return result;
}

int settings_t::get_model_context_window(const std::string& model_name)
{
    static const std::unordered_map<std::string, int> context_windows = {
        {std::string("gemini-3-pro-preview"),             1000000},
        {std::string("gemini-2.5-pro"),                   1048576},
        {std::string("gemini-2.5-flash"),                 1048576},
        {std::string("gemini-2.5-flash-lite"),            1048576},
        {std::string("gemini-2.0-flash"),                 1048576},
        {std::string("gemini-2.0-flash-lite"),            1048576},
        {std::string("gemini-1.5-pro-latest"),            2097152},
        {std::string("gemini-1.5-pro"),                   2097152},
        {std::string("gemini-1.5-pro-002"),               2097152},
        {std::string("gemini-1.5-flash-latest"),          1048576},
        {std::string("gemini-1.5-flash"),                 1048576},
        {std::string("gemini-1.5-flash-8b"),              1048576},
        {std::string("gemini-1.5-flash-8b-latest"),       1048576},
        {std::string("gemini-2.0-flash-exp"),             1048576},
        {std::string("gemini-2.0-flash-lite-preview"),    1048576},
        {std::string("gemini-2.0-pro-exp"),               1048576},
        {std::string("gemini-2.0-flash-thinking-exp"),    1048576},
        {std::string("gemma-3-1b-it"),                      32768},
        {std::string("gemma-3-4b-it"),                      32768},
        {std::string("gemma-3-12b-it"),                     32768},
        {std::string("gemma-3-27b-it"),                     32768},
        {std::string("gemma-3n-e4b-it"),                    32768},
        {std::string("gemma-3n-e2b-it"),                    32768},

        {std::string("gpt-5.1 Instant"),                  1047576},
        {std::string("gpt-5.1 Thinking"),                 1047576},
        {std::string("gpt-5"),                             1047576},
        {std::string("gpt-5-mini"),                        1047576},
        {std::string("gpt-5-nano"),                         524288},
        {std::string("o3-pro"),                             200000},
        {std::string("o3"),                                 200000},
        {std::string("o3-mini"),                            200000},
        {std::string("o1-pro"),                             200000},
        {std::string("o1"),                                 200000},
        {std::string("o4-mini"),                            200000},
        {std::string("gpt-4.5-preview"),                   128000},
        {std::string("gpt-4.1"),                           1047576},
        {std::string("gpt-4.1-mini"),                      1047576},
        {std::string("gpt-4.1-nano"),                      1047576},
        {std::string("gpt-4o"),                             128000},
        {std::string("gpt-4-turbo"),                        128000},
        {std::string("gpt-4"),                                8192},
        {std::string("gpt-4o-mini"),                        128000},
        {std::string("gpt-3.5-turbo"),                      16385},
        {std::string("gpt-3.5-turbo-16k"),                  16385},

        {std::string("moonshotai/kimi-k2:free"),            131072},
        {std::string("openai/gpt-oss-20b:free"),            128000},
        {std::string("z-ai/glm-4.5-air:free"),             128000},
        {std::string("tngtech/deepseek-r1t2-chimera:free"), 164000},

        {std::string("claude-opus-4-5 (High Effort)"),      200000},
        {std::string("claude-opus-4-5 (Medium Effort)"),    200000},
        {std::string("claude-opus-4-5 (Low Effort)"),       200000},
        {std::string("claude-sonnet-4-5"),                  200000},
        {std::string("claude-haiku-4-5"),                   200000},
        {std::string("claude-opus-4-1"),                    200000},
        {std::string("claude-opus-4"),                      200000},
        {std::string("claude-sonnet-4"),                    200000},
        {std::string("claude-3-7-sonnet-thought"),          200000},
        {std::string("claude-3-7-sonnet"),                  200000},
        {std::string("claude-3.7-sonnet-thought"),          200000},
        {std::string("claude-3.7-sonnet"),                  200000},
        {std::string("claude-3.5-sonnet-latest"),           200000},
        {std::string("claude-3.5-haiku-latest"),            200000},
        {std::string("claude-3.5-sonnet"),                  200000},
        {std::string("claude-3-opus-latest"),               200000},
        {std::string("claude-3-sonnet-latest"),             200000},
        {std::string("claude-3-haiku-latest"),              200000},
        {std::string("claude-2.1"),                         200000},
        {std::string("claude-2"),                           100000},
        {std::string("claude-instant-v1.2"),                100000},

        {std::string("gpt-4.1-2025-04-14"),               1047576},
        {std::string("o4-mini-2025-04-16"),                 200000},
        {std::string("o3-mini-2025-01-31"),                 200000},
        {std::string("o3-mini-paygo"),                      200000},
        {std::string("gemini-2.0-flash-001"),              1048576},
        {std::string("gpt-4o-2024-11-20"),                  128000},
        {std::string("gpt-4o-2024-08-06"),                  128000},
        {std::string("gpt-4o-2024-05-13"),                  128000},
        {std::string("gpt-4o-copilot"),                     128000},
        {std::string("gpt-4-o-preview"),                    128000},
        {std::string("gpt-4-0125-preview"),                 128000},
        {std::string("gpt-4-0613"),                           8192},
        {std::string("gpt-4o-mini-2024-07-18"),             128000},
        {std::string("gpt-3.5-turbo-0613"),                  16385},
    };

    auto it = context_windows.find(model_name);
    if (it != context_windows.end())
        return it->second;

    return 128000;
}

int settings_t::get_active_context_window() const
{
    qstring provider = ida_utils::qstring_tolower(api_provider.c_str());
    std::string model;
    if (provider == "gemini")          model = gemini_model_name;
    else if (provider == "openai")     model = openai_model_name;
    else if (provider == "openrouter") model = openrouter_model_name;
    else if (provider == "anthropic")  model = anthropic_model_name;
    else if (provider == "copilot")    model = copilot_model_name;
    else if (provider == "local llm") return local_llm_context_window > 0 ? local_llm_context_window : 8192;
    else                               return 128000;
    return get_model_context_window(model);
}

bool settings_t::has_custom_base_url() const
{
    qstring provider = ida_utils::qstring_tolower(api_provider.c_str());
    if (provider == "gemini") return !gemini_base_url.empty();
    if (provider == "openai") return !openai_base_url.empty();
    if (provider == "anthropic") return !anthropic_base_url.empty();
    if (provider == "copilot") return !copilot_proxy_address.empty();
    if (provider == "local llm") return !local_llm_base_url.empty();
    return false;
}

void settings_t::prompt_for_api_key()
{
    qstring provider = ida_utils::qstring_tolower(api_provider.c_str());

    if (has_custom_base_url())
        return;

    if (provider == "copilot")
    {
        warning("Copilot provider is selected, but the proxy address is not configured. Please set it in the settings dialog.");
        return;
    }

    if (provider == "local llm")
    {
        warning("Local LLM provider is selected, but the server URL is not configured. Please set it in the settings dialog.");
        return;
    }

    qstring provider_name = api_provider.c_str();
    if (!provider_name.empty())
        provider_name[0] = qtoupper(provider_name[0]);

    warning("%s API key not found.", provider_name.c_str());

    qstring key;
    qstring question;
    question.sprnt("Please enter your %s API key to continue:", provider_name.c_str());
    if (ask_str(&key, HIST_SRCH, question.c_str()))
    {
        if (provider == "gemini") gemini_api_key = key.c_str();
        else if (provider == "openai") openai_api_key = key.c_str();
        else if (provider == "openrouter") openrouter_api_key = key.c_str();
        else if (provider == "anthropic") anthropic_api_key = key.c_str();
        save();
    }
    else
    {
        warning("Plugin will be disabled until an API key is provided for %s.", provider_name.c_str());
    }
}
