#pragma once

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shlobj.h>
#include <wincrypt.h>
#endif

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <map>
#include <limits>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../auth/auth_store.hpp"

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Shell32.lib")
#endif

namespace sa_settings_detail
{
    static constexpr uint8_t CFG_OBF_KEY[] = {
        0xA3, 0x7B, 0x1E, 0xD4, 0x5F, 0x92, 0xC8, 0x06,
        0xE1, 0x3A, 0x8D, 0x47, 0xB0, 0x6C, 0xF5, 0x29
    };
    static constexpr const char CFG_OBF_PREFIX[]   = "enc1:";
    static constexpr const char CFG_DPAPI_PREFIX[] = "dpapi1:";

    inline std::string trim(const std::string& s)
    {
        const auto start = s.find_first_not_of(" \t\r\n");
        if (start == std::string::npos)
            return {};
        return s.substr(start, s.find_last_not_of(" \t\r\n") - start + 1);
    }

    inline std::string hex_encode(const unsigned char* data, size_t size)
    {
        std::string out;
        out.reserve(size * 2);
        static const char digits[] = "0123456789abcdef";
        for (size_t i = 0; i < size; ++i) {
            out.push_back(digits[(data[i] >> 4) & 0x0F]);
            out.push_back(digits[data[i] & 0x0F]);
        }
        return out;
    }

    inline bool hex_decode(const std::string& text, std::vector<unsigned char>& out)
    {
        if ((text.size() % 2) != 0)
            return false;

        auto nibble = [](char c, unsigned& v) -> bool {
            if (c >= '0' && c <= '9') { v = static_cast<unsigned>(c - '0'); return true; }
            if (c >= 'a' && c <= 'f') { v = static_cast<unsigned>(c - 'a' + 10); return true; }
            if (c >= 'A' && c <= 'F') { v = static_cast<unsigned>(c - 'A' + 10); return true; }
            return false;
        };

        out.clear();
        out.reserve(text.size() / 2);
        for (size_t i = 0; i < text.size(); i += 2) {
            unsigned hi = 0, lo = 0;
            if (!nibble(text[i], hi) || !nibble(text[i + 1], lo))
                return false;
            out.push_back(static_cast<unsigned char>((hi << 4) | lo));
        }
        return true;
    }

    inline std::recursive_mutex& io_mutex()
    {
        static std::recursive_mutex m;
        return m;
    }

    inline std::string& last_error_ref()
    {
        static std::string s;
        return s;
    }

    inline std::string protect_dpapi(const std::string& plaintext, const char* scope)
    {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        (void)scope;
        return plaintext;
#else
        if (plaintext.empty())
            return plaintext;

        if (plaintext.size() > static_cast<size_t>(MAXDWORD)) return {};
        if (std::strlen(scope) > static_cast<size_t>(MAXDWORD)) return {};
        DATA_BLOB input_blob{
            static_cast<DWORD>(plaintext.size()),
            reinterpret_cast<BYTE*>(const_cast<char*>(plaintext.data()))
        };
        DATA_BLOB entropy_blob{
            static_cast<DWORD>(std::strlen(scope)),
            reinterpret_cast<BYTE*>(const_cast<char*>(scope))
        };
        DATA_BLOB output_blob{};

        if (!CryptProtectData(&input_blob, L"AiDA Standalone Secret", &entropy_blob,
                              nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output_blob))
            return {};

        const std::string encoded = hex_encode(output_blob.pbData, output_blob.cbData);
        LocalFree(output_blob.pbData);
        return std::string(CFG_DPAPI_PREFIX) + encoded;
#endif
    }

    inline std::string unprotect_dpapi(const std::string& encoded, const char* scope)
    {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        (void)scope;
        return encoded;
#else
        if (encoded.compare(0, std::strlen(CFG_DPAPI_PREFIX), CFG_DPAPI_PREFIX) != 0)
            return {};

        std::vector<unsigned char> bytes;
        if (!hex_decode(encoded.substr(std::strlen(CFG_DPAPI_PREFIX)), bytes))
            return {};
        if (bytes.size() > static_cast<size_t>(MAXDWORD)) return {};

        DATA_BLOB input_blob{static_cast<DWORD>(bytes.size()), bytes.data()};
        DATA_BLOB entropy_blob{
            static_cast<DWORD>(std::strlen(scope)),
            reinterpret_cast<BYTE*>(const_cast<char*>(scope))
        };
        DATA_BLOB output_blob{};

        if (!CryptUnprotectData(&input_blob, nullptr, &entropy_blob, nullptr, nullptr,
                                CRYPTPROTECT_UI_FORBIDDEN, &output_blob))
            return {};

        std::string result(reinterpret_cast<const char*>(output_blob.pbData), output_blob.cbData);
        SecureZeroMemory(output_blob.pbData, output_blob.cbData);
        LocalFree(output_blob.pbData);
        return result;
#endif
    }

    inline std::string xor_obfuscate(const std::string& plain)
    {
        std::string out(CFG_OBF_PREFIX);
        out.reserve(out.size() + plain.size() * 2);
        static const char digits[] = "0123456789abcdef";
        for (size_t i = 0; i < plain.size(); ++i) {
            const uint8_t b = static_cast<uint8_t>(plain[i]) ^ CFG_OBF_KEY[i % sizeof(CFG_OBF_KEY)];
            out.push_back(digits[(b >> 4) & 0x0F]);
            out.push_back(digits[b & 0x0F]);
        }
        return out;
    }

    inline std::string obfuscate_key(const std::string& plain)
    {
        if (plain.empty())
            return plain;

        const auto dpapi = protect_dpapi(plain, "AiDA:standalone:settings:v2");
        if (!dpapi.empty())
            return dpapi;

        return xor_obfuscate(plain);
    }

    inline std::string deobfuscate_key(const std::string& encoded)
    {
        if (encoded.empty())
            return encoded;
        if (encoded.compare(0, std::strlen(CFG_DPAPI_PREFIX), CFG_DPAPI_PREFIX) == 0)
            return unprotect_dpapi(encoded, "AiDA:standalone:settings:v2");
        if (encoded.compare(0, std::strlen(CFG_OBF_PREFIX), CFG_OBF_PREFIX) != 0)
            return encoded;

        const std::string hex_part = encoded.substr(std::strlen(CFG_OBF_PREFIX));
        std::vector<unsigned char> bytes;
        if (!hex_decode(hex_part, bytes))
            return std::string();
        std::string out;
        out.reserve(bytes.size());
        for (size_t i = 0; i < bytes.size(); ++i)
            out.push_back(static_cast<char>(bytes[i] ^ CFG_OBF_KEY[i % sizeof(CFG_OBF_KEY)]));
        return out;
    }

    inline std::string make_profile_id(const std::string& display_name, size_t index)
    {
        std::string id;
        id.reserve(display_name.size() + 8);
        for (char value : display_name) {
            const unsigned char c = static_cast<unsigned char>(value);
            if (std::isalnum(c))
                id.push_back(static_cast<char>(std::tolower(c)));
            else if (c == ' ' || c == '-' || c == '_')
                id.push_back('-');
        }
        if (id.empty())
            id = "profile";
        id += "-" + std::to_string(index);
        return id;
    }

    inline std::string normalize_provider_kind(std::string kind)
    {
        kind = trim(kind);
        if (kind == "openai")
            return "openai_compatible";
        if (kind == "local_llm")
            return "local";
        if (kind.empty())
            return "openai_compatible";
        return kind;
    }

    inline std::string canonicalize_internal_kind(std::string id)
    {
        id = trim(id);
        if (id.empty())
            return "openai_compatible";
        if (id == "google" || id == "google-ai" || id == "google-generative-ai" || id == "google-genai")
            return "gemini";
        if (id == "google-vertex" || id == "vertex" || id == "vertex-anthropic")
            return "vertex";
        if (id == "anthropic" || id == "claude")
            return "anthropic";
        if (id == "openai")
            return "openai_native";
        if (id == "openai-codex" || id == "openai_codex")
            return "openai_codex";
        if (id == "github-copilot" || id == "copilot")
            return "github-copilot";
        if (id == "openrouter")
            return "openrouter";
        if (id == "amazon-bedrock" || id == "bedrock")
            return "bedrock";
        if (id == "deepseek")
            return "deepseek";
        if (id == "mistral" || id == "codestral")
            return "mistral";
        if (id == "xai" || id == "grok")
            return "xai";
        if (id == "sambanova")
            return "sambanova";
        if (id == "fireworks" || id == "fireworks-ai")
            return "fireworks";
        if (id == "moonshot" || id == "moonshot-ai")
            return "moonshot";
        if (id == "minimax")
            return "minimax";
        if (id == "qwen" || id == "qwen-code" || id == "qwen_code")
            return "qwen_code";
        if (id == "baseten")
            return "baseten";
        if (id == "zai" || id == "z-ai" || id == "bigmodel")
            return "zai";
        if (id == "ollama")
            return "ollama";
        if (id == "lmstudio" || id == "lm-studio")
            return "lmstudio";
        if (id == "azure" || id == "azure-openai")
            return "azure";
        if (id == "requesty")
            return "requesty";
        if (id == "unbound")
            return "unbound";
        if (id == "vercel-ai" || id == "vercel_ai")
            return "vercel_ai";
        if (id == "litellm")
            return "litellm";
        if (id == "local" || id == "local_llm")
            return "local";
        if (id == "openai_native" || id == "openai_compatible" || id == "gemini")
            return id;
        return id;
    }

    inline bool read_json_file(const std::filesystem::path& path, nlohmann::json& out)
    {
        std::error_code ec;
        auto sz = std::filesystem::file_size(path, ec);
        if (!ec && sz > 16 * 1024 * 1024) return false;
        std::ifstream ifs(path);
        if (!ifs.is_open())
            return false;
        try {
            ifs >> out;
            return out.is_object();
        } catch (...) {
            out = nlohmann::json::object();
            return false;
        }
    }
}

struct provider_profile_t
{
    std::string id;
    std::string display_name;
    std::string kind = "openai_compatible";
    std::string base_url;
    std::string api_key;
    std::string model;
    std::string headers_json;
    bool        enabled = true;


    std::string aws_access_key;
    std::string aws_secret_key;
    std::string aws_session_token;
    std::string aws_region = "us-east-1";
    bool        aws_use_cross_region = false;


    std::string vertex_project_id;
    std::string vertex_region = "us-east5";
    std::string vertex_key_file;


    int         ollama_num_ctx = 0;


    std::string reasoning_effort;


    bool        lmstudio_speculative_decoding = false;
    std::string lmstudio_draft_model;


    std::string mistral_codestral_url;


    std::string azure_deployment;
    std::string azure_api_version = "2024-10-21";
};

struct theme_pack_t
{
    int         version = 1;
    std::string name;
    std::string palette_json;
    std::string icon_mode = "builtin";
    int         builtin_icon = 3;
    std::string custom_icon_path;
};

struct workspace_state_t
{
    std::string root_path;
    std::string open_tabs_json;
    std::string view_visibility_json = "{}";
    std::string quick_open_mru_json = "{}";
    std::string graph_state_json = "{}";
    int         active_tab = -1;
    std::string last_active_path;
    std::string active_view = "editor";
    float       right_width = 350.0f;
    bool        right_visible = true;
    bool        legacy_bottom_visible = false;
};

struct sandbox_settings_t
{
    bool        enabled = true;
    int         timeout_ms = 30000;
    int         memory_limit_mb = 256;
    std::string network_mode = "off";
    std::string shared_folder_root;
};


struct mcp_client_server_t
{
    std::string name;
    std::string url;
    std::string transport = "http_sse";
    std::string command;
    std::string args;
    std::string api_key;
    bool        enabled = true;
    bool        auto_connect = true;
};

struct settings_sa_t
{
    std::vector<provider_profile_t> provider_profiles;
    std::string active_provider_profile_id;

    double      temperature = 0.7;
    int         mcp_port = 29117;
    bool        mcp_enabled = true;

    int         active_theme_idx = 0;
    int         active_custom_theme_idx = -1;
    int         editor_tab_size = 4;
    float       editor_font_size = 14.0f;
    bool        editor_auto_complete = true;
    bool        editor_line_numbers = true;
    bool        editor_highlight_line = true;
    int         theme_icon_index = 3;
    std::string custom_icon_path;
    std::string custom_themes_json;
    int         ui_density = 0;
    bool        ui_reduced_motion = false;
    bool        ui_diagnostics_mode = false;
    std::string ui_table_preferences_json;
    std::string ui_filter_preferences_json;
    std::string debugger_definitions_json;
	std::string memory_scanner_state_json;


    bool        enable_reasoning    = false;
    int         reasoning_budget    = 10000;
    std::string reasoning_effort    = "medium";
    bool        prompt_caching      = true;
    int         max_agentic_rounds  = 15;
    bool        first_run_completed = false;


    bool        editor_word_wrap    = false;
    bool        editor_minimap      = false;
    bool        editor_bracket_match = true;
    float       chat_font_size      = 13.0f;
    int         chat_density        = 1;
    bool        chat_show_timestamps = true;
    bool        chat_show_tokens     = true;
    bool        ghost_text_enabled   = false;
    std::string ghost_text_model;
    std::string ghost_text_provider_id;
    int         ghost_text_debounce_ms = 500;


    bool        auto_save_enabled  = false;
    int         auto_save_interval_s = 30;


    std::string terminal_shell = "powershell.exe";
    int         terminal_scrollback = 10000;
    std::string terminal_profile_id = "configured";
    std::string terminal_default_cwd;
    bool        terminal_restore_sessions = true;
    std::string terminal_sessions_json;
    std::string programming_tasks_json;
    std::string programming_selected_task_id;
    std::string keybinding_overrides_json = "{}";


    bool        tool_auto_approve    = false;
    std::string tool_always_allow;
    std::string tool_always_deny;
    bool        force_xml_tools      = false;


    bool        auto_approve_read       = false;
    bool        auto_approve_write      = false;
    bool        auto_approve_execute    = false;
    bool        auto_approve_mcp        = false;
    bool        auto_approve_mode_switch = false;
    bool        auto_approve_subtask    = false;
    int         auto_approve_max_requests = 0;
    double      auto_approve_max_cost    = 0.0;
    std::string auto_approve_allowed_commands;
    std::string aidaignore_path;


    double      condense_threshold       = 0.80;
    double      condense_buffer          = 0.10;


    std::string recent_workspaces_json;


    bool        activity_bar_visible = true;


    int         window_x = -1;
    int         window_y = -1;
    int         window_w = 1400;
    int         window_h = 850;
    bool        window_maximized = false;

    workspace_state_t workspace;
    sandbox_settings_t sandbox;
    std::vector<mcp_client_server_t> mcp_client_servers;

    std::string marketplace_installed_json;


    std::string default_provider_id;
    std::string default_model_id;
    std::string small_model_provider_id;
    std::string small_model_id;
    std::string default_agent_name = "build";

    std::map<std::string, std::string> preferred_model_per_provider;
    std::map<std::string, std::string> provider_base_url_overrides;
    std::map<std::string, std::string> provider_headers_overrides;

    std::string api_provider = "openai_compatible";
    std::string gemini_api_key;
    std::string gemini_model_name = "gemini-2.5-flash";
    std::string gemini_base_url;
    std::string openai_api_key;
    std::string openai_model_name = "gpt-4.1-mini";
    std::string openai_base_url;
    std::string openrouter_api_key;
    std::string openrouter_model_name = "openai/gpt-oss-20b:free";
    std::string anthropic_api_key;
    std::string anthropic_model_name = "claude-sonnet-4";
    std::string anthropic_base_url;
    std::string local_llm_base_url = "http://127.0.0.1:11434";
    std::string local_llm_model_name = "llama3.3:latest";
    std::string local_llm_api_key;

    std::string pdb_search_paths;
    std::string symbol_cache_dir;
    bool        symbol_auto_download = false;
    std::string symbol_server_url = "https://msdl.microsoft.com/download/symbols";

    static std::filesystem::path config_path()
    {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        return {};
#else
        wchar_t* appdata = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata))) {
            auto path = std::filesystem::path(appdata) / L"AiDA" / L"Standalone" / L"settings.json";
            CoTaskMemFree(appdata);
            return path;
        }
        return std::filesystem::current_path() / "aida_standalone_settings.json";
#endif
    }

    static const std::vector<std::string>& provider_kinds()
    {
        static const std::vector<std::string> v = {
            "anthropic", "openai_compatible", "openai_native", "openai_codex",
            "gemini", "openrouter", "deepseek", "mistral", "xai",
            "sambanova", "fireworks", "moonshot", "minimax", "qwen_code",
            "baseten", "zai", "ollama", "lmstudio", "bedrock", "vertex",
            "requesty", "unbound", "vercel_ai", "litellm", "local"
        };
        return v;
    }

    static const std::string& provider_display_name(const std::string& kind)
    {
        static const std::map<std::string, std::string> names = {
            {"anthropic",        "Anthropic"},
            {"openai_compatible","OpenAI Compatible"},
            {"openai_native",    "OpenAI"},
            {"openai_codex",     "OpenAI Codex"},
            {"gemini",           "Google Gemini"},
            {"openrouter",       "OpenRouter"},
            {"deepseek",         "DeepSeek"},
            {"mistral",          "Mistral AI"},
            {"xai",              "xAI (Grok)"},
            {"sambanova",        "SambaNova"},
            {"fireworks",        "Fireworks AI"},
            {"moonshot",         "Moonshot (Kimi)"},
            {"minimax",          "MiniMax"},
            {"qwen_code",        "Qwen Code"},
            {"baseten",          "Baseten"},
            {"zai",              "ZAI (GLM)"},
            {"ollama",           "Ollama"},
            {"lmstudio",         "LM Studio"},
            {"bedrock",          "AWS Bedrock"},
            {"vertex",           "GCP Vertex AI"},
            {"requesty",         "Requesty"},
            {"unbound",          "Unbound"},
            {"vercel_ai",        "Vercel AI Gateway"},
            {"litellm",          "LiteLLM"},
            {"local",            "Local (Custom)"},
        };
        static const std::string fallback = "Unknown";
        auto it = names.find(kind);
        return it != names.end() ? it->second : fallback;
    }


    static const std::vector<std::string>& gemini_models()
    {
        static const std::vector<std::string> v = {
            "gemini-3.1-pro-preview", "gemini-3.1-pro-preview-customtools",
            "gemini-3-pro-preview", "gemini-3-flash-preview",
            "gemini-2.5-pro", "gemini-2.5-pro-preview-06-05",
            "gemini-2.5-pro-preview-05-06", "gemini-2.5-pro-preview-03-25",
            "gemini-flash-latest", "gemini-2.5-flash-preview-09-2025",
            "gemini-2.5-flash", "gemini-flash-lite-latest",
            "gemini-2.5-flash-lite-preview-09-2025"
        };
        return v;
    }

    static const std::vector<std::string>& openai_models()
    {
        static const std::vector<std::string> v = {
            "gpt-5.1-codex-max",
            "gpt-5.4", "gpt-5.4-mini", "gpt-5.4-nano",
            "gpt-5.2", "gpt-5.2-codex", "gpt-5.3-codex",
            "gpt-5.2-chat-latest", "gpt-5.3-chat-latest",
            "gpt-5.1", "gpt-5.1-codex", "gpt-5.1-codex-mini",
            "gpt-5", "gpt-5-mini", "gpt-5-codex", "gpt-5-nano", "gpt-5-chat-latest",
            "gpt-4.1", "gpt-4.1-mini", "gpt-4.1-nano",
            "o3", "o3-high", "o3-low",
            "o4-mini", "o4-mini-high", "o4-mini-low",
            "o3-mini", "o3-mini-high", "o3-mini-low",
            "o1", "o1-preview", "o1-mini",
            "gpt-4o", "gpt-4o-mini",
            "codex-mini-latest",
            "gpt-5-2025-08-07", "gpt-5-mini-2025-08-07", "gpt-5-nano-2025-08-07"
        };
        return v;
    }

    static const std::vector<std::string>& openai_codex_models()
    {
        static const std::vector<std::string> v = {
            "gpt-5.1-codex-max", "gpt-5.1-codex", "gpt-5.3-codex",
            "gpt-5.3-codex-spark", "gpt-5.2-codex",
            "gpt-5.1", "gpt-5", "gpt-5-codex", "gpt-5-codex-mini",
            "gpt-5.1-codex-mini", "gpt-5.4", "gpt-5.4-mini", "gpt-5.2"
        };
        return v;
    }

    static const std::vector<std::string>& anthropic_models()
    {
        static const std::vector<std::string> v = {
            "claude-sonnet-4-6", "claude-sonnet-4-5", "claude-sonnet-4-20250514",
            "claude-opus-4-6", "claude-opus-4-5-20251101",
            "claude-opus-4-1-20250805", "claude-opus-4-20250514",
            "claude-3-7-sonnet-20250219:thinking", "claude-3-7-sonnet-20250219",
            "claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022",
            "claude-3-opus-20240229", "claude-3-haiku-20240307",
            "claude-haiku-4-5-20251001"
        };
        return v;
    }

    static const std::vector<std::string>& openrouter_models()
    {
        static const std::vector<std::string> v = {
            "anthropic/claude-sonnet-4.5", "anthropic/claude-sonnet-4",
            "anthropic/claude-opus-4-1", "anthropic/claude-opus-4",
            "openai/gpt-5.1-codex-max", "openai/gpt-5.4", "openai/gpt-4.1",
            "openai/o3", "openai/o4-mini",
            "google/gemini-2.5-pro", "google/gemini-2.5-flash",
            "deepseek/deepseek-chat-v3-0324", "deepseek/deepseek-r1",
            "x-ai/grok-4.20-beta-0309-reasoning",
            "meta-llama/llama-3.3-70b-instruct",
            "mistralai/mistral-large-latest",
            "openai/gpt-oss-20b:free", "moonshotai/kimi-k2:free"
        };
        return v;
    }

    static const std::vector<std::string>& deepseek_models()
    {
        static const std::vector<std::string> v = {
            "deepseek-chat", "deepseek-reasoner"
        };
        return v;
    }

    static const std::vector<std::string>& mistral_models()
    {
        static const std::vector<std::string> v = {
            "magistral-medium-latest", "devstral-medium-latest",
            "mistral-medium-latest", "codestral-latest",
            "mistral-large-latest", "ministral-8b-latest",
            "ministral-3b-latest", "mistral-small-latest",
            "pixtral-large-latest"
        };
        return v;
    }

    static const std::vector<std::string>& xai_models()
    {
        static const std::vector<std::string> v = {
            "grok-4.20-beta-0309-reasoning", "grok-4.20-beta-0309-non-reasoning",
            "grok-code-fast-1",
            "grok-4-1-fast-reasoning", "grok-4-1-fast-non-reasoning",
            "grok-4-fast-reasoning", "grok-4-fast-non-reasoning",
            "grok-4-0709", "grok-3-mini", "grok-3"
        };
        return v;
    }

    static const std::vector<std::string>& sambanova_models()
    {
        static const std::vector<std::string> v = {
            "Meta-Llama-3.1-8B-Instruct", "Meta-Llama-3.3-70B-Instruct",
            "DeepSeek-R1", "DeepSeek-V3-0324", "DeepSeek-V3.1",
            "Llama-4-Maverick-17B-128E-Instruct", "Qwen3-32B",
            "gpt-oss-120b"
        };
        return v;
    }

    static const std::vector<std::string>& fireworks_models()
    {
        static const std::vector<std::string> v = {
            "accounts/fireworks/models/kimi-k2-instruct",
            "accounts/fireworks/models/kimi-k2-instruct-0905",
            "accounts/fireworks/models/kimi-k2-thinking",
            "accounts/fireworks/models/kimi-k2p5",
            "accounts/fireworks/models/minimax-m2",
            "accounts/fireworks/models/minimax-m2p1",
            "accounts/fireworks/models/qwen3-235b-a22b-instruct-2507",
            "accounts/fireworks/models/qwen3-coder-480b-a35b-instruct",
            "accounts/fireworks/models/deepseek-r1-0528",
            "accounts/fireworks/models/deepseek-v3",
            "accounts/fireworks/models/deepseek-v3p1",
            "accounts/fireworks/models/deepseek-v3p2",
            "accounts/fireworks/models/glm-4p5",
            "accounts/fireworks/models/glm-4p5-air",
            "accounts/fireworks/models/glm-4p6",
            "accounts/fireworks/models/glm-4p7",
            "accounts/fireworks/models/gpt-oss-20b",
            "accounts/fireworks/models/gpt-oss-120b",
            "accounts/fireworks/models/llama-v3p3-70b-instruct",
            "accounts/fireworks/models/llama4-maverick-instruct-basic",
            "accounts/fireworks/models/llama4-scout-instruct-basic"
        };
        return v;
    }

    static const std::vector<std::string>& moonshot_models()
    {
        static const std::vector<std::string> v = {
            "kimi-k2-0711-preview", "kimi-k2-0905-preview",
            "kimi-k2-turbo-preview", "kimi-k2-thinking", "kimi-k2.5"
        };
        return v;
    }

    static const std::vector<std::string>& minimax_models()
    {
        static const std::vector<std::string> v = {
            "MiniMax-M2.5", "MiniMax-M2", "MiniMax-M2-Stable", "MiniMax-M2.1"
        };
        return v;
    }

    static const std::vector<std::string>& qwen_code_models()
    {
        static const std::vector<std::string> v = {
            "qwen3-coder-plus", "qwen3-coder-flash"
        };
        return v;
    }

    static const std::vector<std::string>& baseten_models()
    {
        static const std::vector<std::string> v = {
            "moonshotai/Kimi-K2-Thinking", "zai-org/GLM-4.6",
            "deepseek-ai/DeepSeek-R1", "deepseek-ai/DeepSeek-R1-0528",
            "deepseek-ai/DeepSeek-V3-0324", "deepseek-ai/DeepSeek-V3.1",
            "deepseek-ai/DeepSeek-V3.2", "openai/gpt-oss-120b",
            "Qwen/Qwen3-235B-A22B-Instruct-2507",
            "Qwen/Qwen3-Coder-480B-A35B-Instruct",
            "moonshotai/Kimi-K2-Instruct-0905"
        };
        return v;
    }

    static const std::vector<std::string>& zai_models()
    {
        static const std::vector<std::string> v = {
            "glm-4.5", "glm-4.5-air", "glm-4.5-x", "glm-4.5-airx", "glm-4.5-flash",
            "glm-4.5v", "glm-4.6v", "glm-4.6",
            "glm-4.7", "glm-5",
            "glm-4.7-flash", "glm-4.7-flashx",
            "glm-4.6v-flash", "glm-4.6v-flashx",
            "glm-4-32b-0414-128k"
        };
        return v;
    }

    static const std::vector<std::string>& bedrock_models()
    {
        static const std::vector<std::string> v = {
            "anthropic.claude-sonnet-4-5-20250929-v1:0", "anthropic.claude-sonnet-4-6",
            "amazon.nova-pro-v1:0", "amazon.nova-pro-latency-optimized-v1:0",
            "amazon.nova-lite-v1:0", "amazon.nova-2-lite-v1:0", "amazon.nova-micro-v1:0",
            "anthropic.claude-sonnet-4-20250514-v1:0",
            "anthropic.claude-opus-4-1-20250805-v1:0",
            "anthropic.claude-opus-4-6-v1",
            "anthropic.claude-opus-4-5-20251101-v1:0",
            "anthropic.claude-opus-4-20250514-v1:0",
            "anthropic.claude-3-7-sonnet-20250219-v1:0",
            "anthropic.claude-3-5-sonnet-20241022-v2:0",
            "anthropic.claude-3-5-haiku-20241022-v1:0",
            "anthropic.claude-haiku-4-5-20251001-v1:0",
            "anthropic.claude-3-5-sonnet-20240620-v1:0",
            "anthropic.claude-3-opus-20240229-v1:0",
            "anthropic.claude-3-sonnet-20240229-v1:0",
            "anthropic.claude-3-haiku-20240307-v1:0",
            "deepseek.r1-v1:0",
            "openai.gpt-oss-20b-1:0", "openai.gpt-oss-120b-1:0",
            "meta.llama3-3-70b-instruct-v1:0",
            "meta.llama3-2-90b-instruct-v1:0", "meta.llama3-2-11b-instruct-v1:0",
            "meta.llama3-2-3b-instruct-v1:0", "meta.llama3-2-1b-instruct-v1:0",
            "meta.llama3-1-405b-instruct-v1:0",
            "meta.llama3-1-70b-instruct-v1:0",
            "meta.llama3-1-70b-instruct-latency-optimized-v1:0",
            "meta.llama3-1-8b-instruct-v1:0",
            "meta.llama3-70b-instruct-v1:0", "meta.llama3-8b-instruct-v1:0",
            "amazon.titan-text-lite-v1:0", "amazon.titan-text-express-v1:0",
            "moonshot.kimi-k2-thinking", "minimax.minimax-m2",
            "qwen.qwen3-next-80b-a3b", "qwen.qwen3-coder-480b-a35b-v1:0"
        };
        return v;
    }

    static const std::vector<std::string>& vertex_models()
    {
        static const std::vector<std::string> v = {
            "gemini-3.1-pro-preview", "gemini-3.1-pro-preview-customtools",
            "gemini-3-pro-preview", "gemini-3-flash-preview",
            "gemini-2.5-flash-preview-05-20:thinking", "gemini-2.5-flash-preview-05-20",
            "gemini-2.5-flash", "gemini-2.5-flash-preview-04-17:thinking",
            "gemini-2.5-flash-preview-04-17",
            "gemini-2.5-pro-preview-03-25", "gemini-2.5-pro-preview-05-06",
            "gemini-2.5-pro-preview-06-05", "gemini-2.5-pro",
            "gemini-2.5-pro-exp-03-25",
            "gemini-2.0-pro-exp-02-05", "gemini-2.0-flash-001",
            "gemini-2.0-flash-lite-001", "gemini-2.0-flash-thinking-exp-01-21",
            "gemini-1.5-flash-002", "gemini-1.5-pro-002",
            "claude-sonnet-4@20250514", "claude-sonnet-4-5@20250929",
            "claude-sonnet-4-6", "claude-haiku-4-5@20251001",
            "claude-opus-4-6", "claude-opus-4-5@20251101",
            "claude-opus-4-1@20250805", "claude-opus-4@20250514",
            "claude-3-7-sonnet@20250219:thinking", "claude-3-7-sonnet@20250219",
            "claude-3-5-sonnet-v2@20241022", "claude-3-5-sonnet@20240620",
            "claude-3-5-haiku@20241022",
            "claude-3-opus@20240229", "claude-3-haiku@20240307",
            "gemini-2.5-flash-lite-preview-06-17",
            "llama-4-maverick-17b-128e-instruct-maas",
            "deepseek-r1-0528-maas", "deepseek-v3.1-maas",
            "gpt-oss-120b-maas", "gpt-oss-20b-maas",
            "qwen3-coder-480b-a35b-instruct-maas",
            "qwen3-235b-a22b-instruct-2507-maas",
            "moonshotai/kimi-k2-thinking-maas"
        };
        return v;
    }

    static const std::vector<std::string>& ollama_models()
    {

        static const std::vector<std::string> v = {
            "devstral:24b", "llama3.3:latest", "llama3.1:latest",
            "qwen2.5-coder:latest", "qwen2.5:latest",
            "deepseek-r1:latest", "deepseek-v3:latest",
            "mistral:latest", "mixtral:latest",
            "gemma2:latest", "phi3:latest",
            "codellama:latest", "starcoder2:latest"
        };
        return v;
    }

    static const std::vector<std::string>& lmstudio_models()
    {

        static const std::vector<std::string> v = {
            "mistralai/devstral-small-2505",
            "lmstudio-community/Meta-Llama-3.1-8B-Instruct-GGUF",
            "TheBloke/Mistral-7B-Instruct-v0.2-GGUF",
            "TheBloke/CodeLlama-13B-Instruct-GGUF"
        };
        return v;
    }

    static const std::vector<std::string>& local_llm_models()
    {
        static const std::vector<std::string> v = {
            "llama3.3:latest", "qwen2.5-coder:latest",
            "deepseek-r1:latest", "mistral:latest"
        };
        return v;
    }

    static const std::vector<std::string>& models_for_kind(const std::string& kind)
    {
        const std::string normalized = sa_settings_detail::normalize_provider_kind(kind);
        if (normalized == "gemini")           return gemini_models();
        if (normalized == "anthropic")        return anthropic_models();
        if (normalized == "openrouter")       return openrouter_models();
        if (normalized == "deepseek")         return deepseek_models();
        if (normalized == "mistral")          return mistral_models();
        if (normalized == "xai")              return xai_models();
        if (normalized == "sambanova")        return sambanova_models();
        if (normalized == "fireworks")        return fireworks_models();
        if (normalized == "moonshot")         return moonshot_models();
        if (normalized == "minimax")          return minimax_models();
        if (normalized == "qwen_code")        return qwen_code_models();
        if (normalized == "baseten")          return baseten_models();
        if (normalized == "zai")              return zai_models();
        if (normalized == "openai_codex")     return openai_codex_models();
        if (normalized == "bedrock")          return bedrock_models();
        if (normalized == "vertex")           return vertex_models();
        if (normalized == "ollama")           return ollama_models();
        if (normalized == "lmstudio")         return lmstudio_models();
        if (normalized == "local")            return local_llm_models();
        if (normalized == "openai_native")    return openai_models();
        return openai_models();
    }

    settings_sa_t ai_runtime_snapshot() const
    {
        std::lock_guard<std::recursive_mutex> lock(sa_settings_detail::io_mutex());
        return *this;
    }

    provider_profile_t* get_active_profile()
    {
        ensure_default_profiles();
        auto it = std::find_if(provider_profiles.begin(), provider_profiles.end(),
            [&](const provider_profile_t& profile) {
                return profile.id == active_provider_profile_id;
            });
        if (it != provider_profiles.end())
            return &(*it);

        active_provider_profile_id = provider_profiles.front().id;
        return &provider_profiles.front();
    }

    const provider_profile_t* get_active_profile() const
    {
        return const_cast<settings_sa_t*>(this)->get_active_profile();
    }

    std::string get_active_profile_kind() const
    {
        if (!default_provider_id.empty())
            return sa_settings_detail::canonicalize_internal_kind(default_provider_id);
        const auto* profile = get_active_profile();
        return profile ? sa_settings_detail::canonicalize_internal_kind(sa_settings_detail::normalize_provider_kind(profile->kind)) : std::string("openai_compatible");
    }

    std::string selected_provider_id() const
    {
        if (!default_provider_id.empty())
            return default_provider_id;
        const auto* profile = get_active_profile();
        if (profile)
            return sa_settings_detail::normalize_provider_kind(profile->kind);
        return std::string("openai_compatible");
    }

    std::string selected_model_id() const
    {
        if (!default_model_id.empty())
            return default_model_id;
        const auto* profile = get_active_profile();
        return profile ? profile->model : std::string();
    }

    void set_selection(const std::string& provider_id, const std::string& model_id)
    {
        default_provider_id = provider_id;
        default_model_id = model_id;
    }

    void set_small_model_selection(const std::string& provider_id, const std::string& model_id)
    {
        small_model_provider_id = provider_id;
        small_model_id = model_id;
    }

    std::string get_active_profile_name() const
    {
        const auto* profile = get_active_profile();
        return profile ? profile->display_name : std::string("Default");
    }

    std::string get_active_api_key() const
    {
        const auto* profile = get_active_profile();
        return profile ? profile->api_key : std::string();
    }

    std::string resolve_active_api_key() const
    {
        bool from_store = false;
        return resolve_active_api_key(from_store);
    }

    std::string resolve_active_api_key(bool& out_from_store) const
    {
        out_from_store = false;

        if (default_provider_id.empty()) {
            const auto* profile = get_active_profile();
            if (profile && !profile->api_key.empty())
                return profile->api_key;
        }

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
        {
            const std::string pid = selected_provider_id();
            if (!pid.empty()) {
                aida::auth::auth_info_t info;
                if (aida::auth::store::get(pid, info) && !info.api_key.empty()) {
                    out_from_store = true;
                    return info.api_key;
                }
            }
        }
#endif

        const auto* profile = get_active_profile();
        if (profile && !profile->api_key.empty())
            return profile->api_key;

        return std::string();
    }

    std::string get_active_model() const
    {
        if (!default_model_id.empty())
            return default_model_id;
        const auto* profile = get_active_profile();
        return profile ? profile->model : std::string();
    }

    static std::string default_base_url_for_kind(const std::string& kind)
    {
        if (kind == "gemini")           return "https://generativelanguage.googleapis.com";
        if (kind == "anthropic")        return "https://api.anthropic.com";
        if (kind == "openrouter")       return "https://openrouter.ai";
        if (kind == "deepseek")         return "https://api.deepseek.com";
        if (kind == "mistral")          return "https://api.mistral.ai";
        if (kind == "xai")              return "https://api.x.ai";
        if (kind == "sambanova")        return "https://api.sambanova.ai";
        if (kind == "fireworks")        return "https://api.fireworks.ai";
        if (kind == "moonshot")         return "https://api.moonshot.cn";
        if (kind == "minimax")          return "https://api.minimaxi.chat";
        if (kind == "qwen_code")        return "https://chat.qwen.ai";
        if (kind == "baseten")          return "https://bridge.baseten.co";
        if (kind == "zai")              return "https://open.bigmodel.cn";
        if (kind == "openai_codex")     return "https://api.openai.com";
        if (kind == "github-copilot")   return "https://api.githubcopilot.com";
        if (kind == "ollama")           return "http://127.0.0.1:11434";
        if (kind == "lmstudio")         return "http://127.0.0.1:1234";
        if (kind == "requesty")         return "https://router.requesty.ai";
        if (kind == "unbound")          return "https://api.getunbound.ai";
        if (kind == "vercel_ai")        return "https://sdk.vercel.ai";
        if (kind == "litellm")          return "http://127.0.0.1:4000";
        if (kind == "local")            return "http://127.0.0.1:11434";
        if (kind == "openai_native")    return "https://api.openai.com";
        return "https://api.openai.com";
    }

    std::string get_active_base_url() const
    {
        const auto* profile = get_active_profile();
        if (!profile)
            return {};
        if (!profile->base_url.empty())
            return profile->base_url;

        const std::string kind = sa_settings_detail::canonicalize_internal_kind(sa_settings_detail::normalize_provider_kind(profile->kind));
        return default_base_url_for_kind(kind);
    }

    std::string resolve_active_base_url() const
    {
        if (default_provider_id.empty()) {
            const auto* profile = get_active_profile();
            if (profile && !profile->base_url.empty())
                return profile->base_url;
        }
        return default_base_url_for_kind(get_active_profile_kind());
    }

    std::map<std::string, std::string> get_active_headers() const
    {
        std::map<std::string, std::string> headers;
        const auto* profile = get_active_profile();
        if (!profile || profile->headers_json.empty())
            return headers;

        try {
            const auto parsed = nlohmann::json::parse(profile->headers_json);
            if (!parsed.is_object())
                return headers;
            for (auto it = parsed.begin(); it != parsed.end(); ++it) {
                if (it.value().is_string())
                    headers[it.key()] = it.value().get<std::string>();
            }
        } catch (...) {
        }
        return headers;
    }

    void ensure_default_profiles()
    {
        if (!provider_profiles.empty()) {
            if (active_provider_profile_id.empty())
                active_provider_profile_id = provider_profiles.front().id;
            return;
        }

        auto make_profile = [](const char* pid, const char* name, const char* pkind,
                               const char* url, const char* mdl) -> provider_profile_t {
            provider_profile_t p;
            p.id = pid; p.display_name = name; p.kind = pkind;
            p.base_url = url; p.model = mdl; p.headers_json = "{}";
            return p;
        };
        provider_profiles = {
            make_profile("anthropic-default",  "Anthropic",           "anthropic",        "https://api.anthropic.com",                   "claude-sonnet-4-5"),
            make_profile("openai-default",     "OpenAI",              "openai_native",     "https://api.openai.com",                      "gpt-5.1-codex-max"),
            make_profile("openai-codex-def",   "OpenAI Codex",        "openai_codex",      "https://api.openai.com",                      "gpt-5.3-codex"),
            make_profile("gemini-default",     "Gemini",              "gemini",            "https://generativelanguage.googleapis.com",    "gemini-3.1-pro-preview"),
            make_profile("openrouter-default", "OpenRouter",          "openrouter",        "https://openrouter.ai",                       "anthropic/claude-sonnet-4.5"),
            make_profile("deepseek-default",   "DeepSeek",            "deepseek",          "https://api.deepseek.com",                    "deepseek-chat"),
            make_profile("mistral-default",    "Mistral",             "mistral",           "https://api.mistral.ai",                      "codestral-latest"),
            make_profile("xai-default",        "xAI (Grok)",          "xai",               "https://api.x.ai",                            "grok-4.20-beta-0309-reasoning"),
            make_profile("sambanova-default",  "SambaNova",           "sambanova",         "https://api.sambanova.ai",                    "Meta-Llama-3.3-70B-Instruct"),
            make_profile("fireworks-default",  "Fireworks AI",        "fireworks",         "https://api.fireworks.ai",                    "accounts/fireworks/models/kimi-k2-instruct-0905"),
            make_profile("moonshot-default",   "Moonshot (Kimi)",     "moonshot",          "https://api.moonshot.cn",                     "kimi-k2-0905-preview"),
            make_profile("minimax-default",    "MiniMax",             "minimax",           "https://api.minimaxi.chat",                   "MiniMax-M2.5"),
            make_profile("qwen-code-default",  "Qwen Code",           "qwen_code",         "https://chat.qwen.ai",                        "qwen3-coder-plus"),
            make_profile("baseten-default",    "Baseten",             "baseten",           "https://bridge.baseten.co",                   "zai-org/GLM-4.6"),
            make_profile("zai-default",        "ZAI (GLM)",           "zai",               "https://open.bigmodel.cn",                    "glm-4.6"),
            make_profile("ollama-default",     "Ollama",              "ollama",            "http://127.0.0.1:11434",                      "devstral:24b"),
            make_profile("lmstudio-default",   "LM Studio",           "lmstudio",          "http://127.0.0.1:1234",                       "mistralai/devstral-small-2505"),
            make_profile("bedrock-default",    "AWS Bedrock",         "bedrock",           "",                                            "anthropic.claude-sonnet-4-5-20250929-v1:0"),
            make_profile("vertex-default",     "GCP Vertex AI",       "vertex",            "",                                            "claude-sonnet-4-5@20250929"),
            make_profile("requesty-default",   "Requesty",            "requesty",          "https://router.requesty.ai",                  "coding/claude-4-sonnet"),
            make_profile("unbound-default",    "Unbound",             "unbound",           "https://api.getunbound.ai",                   "anthropic/claude-sonnet-4-5"),
            make_profile("vercel-ai-default",  "Vercel AI Gateway",   "vercel_ai",         "https://sdk.vercel.ai",                       "anthropic/claude-sonnet-4"),
            make_profile("litellm-default",    "LiteLLM",             "litellm",           "http://127.0.0.1:4000",                       "claude-3-7-sonnet-20250219"),
            make_profile("local-default",      "Local (Custom)",      "local",             "http://127.0.0.1:11434",                      "llama3.3:latest"),
        };
        active_provider_profile_id = provider_profiles.front().id;
        sync_legacy_fields_from_active_profile();
    }

    void sync_legacy_fields_from_active_profile()
    {
        const auto* profile = get_active_profile();
        if (!profile)
            return;

        api_provider = sa_settings_detail::normalize_provider_kind(profile->kind);
        theme_icon_index = std::clamp(theme_icon_index, 0, 3);

        if (api_provider == "gemini") {
            gemini_api_key = profile->api_key;
            gemini_model_name = profile->model;
            gemini_base_url = profile->base_url;
        } else if (api_provider == "anthropic") {
            anthropic_api_key = profile->api_key;
            anthropic_model_name = profile->model;
            anthropic_base_url = profile->base_url;
        } else if (api_provider == "openrouter") {
            openrouter_api_key = profile->api_key;
            openrouter_model_name = profile->model;
        } else if (api_provider == "local") {
            local_llm_api_key = profile->api_key;
            local_llm_model_name = profile->model;
            local_llm_base_url = profile->base_url;
        } else {
            openai_api_key = profile->api_key;
            openai_model_name = profile->model;
            openai_base_url = profile->base_url;
            api_provider = "openai_compatible";
        }
    }

    void apply_legacy_fields_to_active_profile()
    {
        auto* profile = get_active_profile();
        if (!profile)
            return;

        const std::string kind = sa_settings_detail::normalize_provider_kind(api_provider);
        const std::string profile_kind = sa_settings_detail::normalize_provider_kind(profile->kind);

        if (kind != profile_kind)
            return;

        if (kind == "gemini") {
            profile->base_url = gemini_base_url;
            profile->api_key = gemini_api_key;
            profile->model = gemini_model_name;
        } else if (kind == "anthropic") {
            profile->base_url = anthropic_base_url;
            profile->api_key = anthropic_api_key;
            profile->model = anthropic_model_name;
        } else if (kind == "openrouter") {
            profile->base_url = "https://openrouter.ai";
            profile->api_key = openrouter_api_key;
            profile->model = openrouter_model_name;
        } else if (kind == "local") {
            profile->base_url = local_llm_base_url;
            profile->api_key = local_llm_api_key;
            profile->model = local_llm_model_name;
        } else if (kind == "openai_compatible") {
            profile->base_url = openai_base_url;
            profile->api_key = openai_api_key;
            profile->model = openai_model_name;
        }
    }

    void migrate_legacy_fields_into_profiles()
    {
        if (!provider_profiles.empty())
            return;

        auto push = [&](const char* pid, const char* name, const char* pkind,
                        const std::string& url, const std::string& key, const std::string& mdl) {
            provider_profile_t p;
            p.id = pid; p.display_name = name; p.kind = pkind;
            p.base_url = url; p.api_key = key; p.model = mdl; p.headers_json = "{}";
            provider_profiles.push_back(std::move(p));
        };

        if (!openai_model_name.empty() || !openai_api_key.empty() || !openai_base_url.empty()) {
            push("openai-default", "OpenAI Compatible", "openai_compatible",
                openai_base_url.empty() ? "https://api.openai.com" : openai_base_url,
                openai_api_key, openai_model_name.empty() ? "gpt-4.1-mini" : openai_model_name);
        }
        if (!gemini_model_name.empty() || !gemini_api_key.empty()) {
            push("gemini-default", "Gemini", "gemini",
                gemini_base_url.empty() ? "https://generativelanguage.googleapis.com" : gemini_base_url,
                gemini_api_key, gemini_model_name.empty() ? "gemini-2.5-flash" : gemini_model_name);
        }
        if (!anthropic_model_name.empty() || !anthropic_api_key.empty()) {
            push("anthropic-default", "Anthropic", "anthropic",
                anthropic_base_url.empty() ? "https://api.anthropic.com" : anthropic_base_url,
                anthropic_api_key, anthropic_model_name.empty() ? "claude-sonnet-4" : anthropic_model_name);
        }
        if (!openrouter_model_name.empty() || !openrouter_api_key.empty()) {
            push("openrouter-default", "OpenRouter", "openrouter",
                "https://openrouter.ai", openrouter_api_key,
                openrouter_model_name.empty() ? "openai/gpt-oss-20b:free" : openrouter_model_name);
        }
        if (!local_llm_model_name.empty() || !local_llm_base_url.empty()) {
            push("local-default", "Local LLM", "local",
                local_llm_base_url.empty() ? "http://127.0.0.1:11434" : local_llm_base_url,
                local_llm_api_key,
                local_llm_model_name.empty() ? "llama3.3:latest" : local_llm_model_name);
        }

        ensure_default_profiles();
        if (active_provider_profile_id.empty()) {
            const std::string desired = sa_settings_detail::normalize_provider_kind(api_provider);
            auto it = std::find_if(provider_profiles.begin(), provider_profiles.end(),
                [&](const provider_profile_t& profile) {
                    return sa_settings_detail::normalize_provider_kind(profile.kind) == desired;
                });
            active_provider_profile_id = (it != provider_profiles.end()) ? it->id : provider_profiles.front().id;
        }
    }

    bool load()
    {
        std::lock_guard<std::recursive_mutex> lock(sa_settings_detail::io_mutex());
        sa_settings_detail::last_error_ref().clear();

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        ensure_default_profiles();
        if (active_provider_profile_id.empty() && !provider_profiles.empty())
            active_provider_profile_id = provider_profiles.front().id;
        if (default_provider_id.empty())
            default_provider_id = "openai_native";
        if (default_model_id.empty())
            default_model_id = "gpt-5.4";
        if (small_model_provider_id.empty())
            small_model_provider_id = "openai_native";
        if (small_model_id.empty())
            small_model_id = "gpt-5.4-mini";
        if (mcp_client_servers.empty()) {
            mcp_client_server_t local;
            local.name = "AiDA Local Tools";
            local.url = "http://127.0.0.1:29117/mcp";
            local.transport = "http_sse";
            local.enabled = true;
            local.auto_connect = true;
            mcp_client_servers.push_back(std::move(local));

            mcp_client_server_t docs;
            docs.name = "Reverse Engineering Docs";
            docs.url = "http://127.0.0.1:29118/mcp";
            docs.transport = "http_sse";
            docs.enabled = true;
            docs.auto_connect = false;
            mcp_client_servers.push_back(std::move(docs));
        }
        workspace.root_path = "C:\\analysis\\nightfall";
        workspace.last_active_path = "C:\\analysis\\nightfall\\nightfall.exe";
        workspace.active_view = "disassembly";
        first_run_completed = true;
        sync_legacy_fields_from_active_profile();
        return true;
#else

        nlohmann::json root;
        auto source = config_path();

        if (!sa_settings_detail::read_json_file(source, root)) {
            ensure_default_profiles();
            sa_settings_detail::last_error_ref() = "no settings file present; using defaults";
            return false;
        }

        auto str = [&](const char* key, std::string& dst) {
            if (root.contains(key) && root[key].is_string())
                dst = root[key].get<std::string>();
        };
        auto secret = [&](const char* key, std::string& dst) {
            if (root.contains(key) && root[key].is_string())
                dst = sa_settings_detail::deobfuscate_key(sa_settings_detail::trim(root[key].get<std::string>()));
        };
        auto integer = [&](const char* key, int& dst) {
            if (!root.contains(key)) return;
            const auto& v = root[key];
            if (!v.is_number_integer() && !v.is_number_unsigned()) return;
            try {
                long long vv = v.get<long long>();
                if (vv < INT_MIN || vv > INT_MAX) return;
                dst = static_cast<int>(vv);
            } catch (...) {}
        };
        auto i64 = [&](const char* key, int64_t& dst) {
            if (!root.contains(key)) return;
            const auto& v = root[key];
            if (!v.is_number_integer() && !v.is_number_unsigned()) return;
            try {
                if (v.is_number_unsigned()) {
                    unsigned long long uv = v.get<unsigned long long>();
                    if (uv > static_cast<unsigned long long>(LLONG_MAX)) return;
                    dst = static_cast<int64_t>(uv);
                } else {
                    dst = v.get<int64_t>();
                }
            } catch (...) {}
        };
        auto boolean = [&](const char* key, bool& dst) {
            if (root.contains(key) && root[key].is_boolean())
                dst = root[key].get<bool>();
        };

        str("default_provider_id", default_provider_id);
        str("default_model_id", default_model_id);
        str("small_model_provider_id", small_model_provider_id);
        str("small_model_id", small_model_id);
        str("default_agent_name", default_agent_name);

        str("api_provider", api_provider);
        secret("gemini_api_key", gemini_api_key);
        str("gemini_model_name", gemini_model_name);
        str("gemini_base_url", gemini_base_url);
        secret("openai_api_key", openai_api_key);
        str("openai_model_name", openai_model_name);
        str("openai_base_url", openai_base_url);
        secret("openrouter_api_key", openrouter_api_key);
        str("openrouter_model_name", openrouter_model_name);
        secret("anthropic_api_key", anthropic_api_key);
        str("anthropic_model_name", anthropic_model_name);
        str("anthropic_base_url", anthropic_base_url);
        secret("local_llm_api_key", local_llm_api_key);
        str("local_llm_model_name", local_llm_model_name);
        str("local_llm_base_url", local_llm_base_url);

        str("pdb_search_paths", pdb_search_paths);
        str("symbol_cache_dir", symbol_cache_dir);
        boolean("symbol_auto_download", symbol_auto_download);
        str("symbol_server_url", symbol_server_url);
        if (root.contains("temperature") && root["temperature"].is_number()) {
            try {
                double vv = root["temperature"].get<double>();
                if (std::isfinite(vv)) temperature = vv;
            } catch (...) {}
        }
        integer("mcp_port", mcp_port);
        boolean("mcp_enabled", mcp_enabled);

        integer("active_theme_idx", active_theme_idx);
        integer("active_custom_theme_idx", active_custom_theme_idx);
        integer("editor_tab_size", editor_tab_size);
        boolean("editor_auto_complete", editor_auto_complete);
        boolean("editor_line_numbers", editor_line_numbers);
        boolean("editor_highlight_line", editor_highlight_line);
        integer("theme_icon_index", theme_icon_index);
        str("custom_icon_path", custom_icon_path);
        str("custom_themes_json", custom_themes_json);
        integer("ui_density", ui_density);
        boolean("ui_reduced_motion", ui_reduced_motion);
        boolean("ui_diagnostics_mode", ui_diagnostics_mode);
        str("ui_table_preferences_json", ui_table_preferences_json);
        str("ui_filter_preferences_json", ui_filter_preferences_json);
        str("debugger_definitions_json", debugger_definitions_json);
		str("memory_scanner_state_json", memory_scanner_state_json);
        ui_density = ui_density == 1 ? 1 : 0;
        if (root.contains("editor_font_size") && root["editor_font_size"].is_number()) {
            try {
                double vv = root["editor_font_size"].get<double>();
                if (std::isfinite(vv) && vv >= -1e6 && vv <= 1e6) editor_font_size = static_cast<float>(vv);
            } catch (...) {}
        }
        if (root.contains("chat_font_size") && root["chat_font_size"].is_number()) {
            try {
                double vv = root["chat_font_size"].get<double>();
                if (std::isfinite(vv) && vv >= -1e6 && vv <= 1e6) chat_font_size = static_cast<float>(vv);
            } catch (...) {}
        }

        boolean("enable_reasoning", enable_reasoning);
        integer("reasoning_budget", reasoning_budget);
        str("reasoning_effort", reasoning_effort);
        boolean("prompt_caching", prompt_caching);
        integer("max_agentic_rounds", max_agentic_rounds);
        boolean("first_run_completed", first_run_completed);

        boolean("editor_word_wrap", editor_word_wrap);
        boolean("editor_minimap", editor_minimap);
        boolean("editor_bracket_match", editor_bracket_match);
        integer("chat_density", chat_density);
        boolean("chat_show_timestamps", chat_show_timestamps);
        boolean("chat_show_tokens", chat_show_tokens);
        boolean("ghost_text_enabled", ghost_text_enabled);
        str("ghost_text_model", ghost_text_model);
        str("ghost_text_provider_id", ghost_text_provider_id);
        integer("ghost_text_debounce_ms", ghost_text_debounce_ms);

        boolean("auto_save_enabled", auto_save_enabled);
        integer("auto_save_interval_s", auto_save_interval_s);
        str("terminal_shell", terminal_shell);
        integer("terminal_scrollback", terminal_scrollback);
        str("terminal_profile_id", terminal_profile_id);
        str("terminal_default_cwd", terminal_default_cwd);
        boolean("terminal_restore_sessions", terminal_restore_sessions);
        str("terminal_sessions_json", terminal_sessions_json);
        str("programming_tasks_json", programming_tasks_json);
        str("programming_selected_task_id", programming_selected_task_id);
        str("keybinding_overrides_json", keybinding_overrides_json);
        boolean("tool_auto_approve", tool_auto_approve);
        str("tool_always_allow", tool_always_allow);
        str("tool_always_deny", tool_always_deny);
        boolean("force_xml_tools", force_xml_tools);

        boolean("auto_approve_read", auto_approve_read);
        boolean("auto_approve_write", auto_approve_write);
        boolean("auto_approve_execute", auto_approve_execute);
        boolean("auto_approve_mcp", auto_approve_mcp);
        boolean("auto_approve_mode_switch", auto_approve_mode_switch);
        boolean("auto_approve_subtask", auto_approve_subtask);
        integer("auto_approve_max_requests", auto_approve_max_requests);
        if (root.contains("auto_approve_max_cost") && root["auto_approve_max_cost"].is_number()) {
            try {
                double vv = root["auto_approve_max_cost"].get<double>();
                if (std::isfinite(vv)) auto_approve_max_cost = vv;
            } catch (...) {}
        }
        str("auto_approve_allowed_commands", auto_approve_allowed_commands);
        str("aidaignore_path", aidaignore_path);
        if (root.contains("condense_threshold") && root["condense_threshold"].is_number()) {
            try {
                double vv = root["condense_threshold"].get<double>();
                if (std::isfinite(vv)) condense_threshold = vv;
            } catch (...) {}
        }
        if (root.contains("condense_buffer") && root["condense_buffer"].is_number()) {
            try {
                double vv = root["condense_buffer"].get<double>();
                if (std::isfinite(vv)) condense_buffer = vv;
            } catch (...) {}
        }
        str("recent_workspaces_json", recent_workspaces_json);
        boolean("activity_bar_visible", activity_bar_visible);

        integer("window_x", window_x);
        integer("window_y", window_y);
        integer("window_w", window_w);
        integer("window_h", window_h);
        boolean("window_maximized", window_maximized);

        auto json_get_string = [](const nlohmann::json& obj, const char* key, const std::string& fallback) -> std::string {
            if (obj.contains(key) && obj[key].is_string())
                return obj[key].get<std::string>();
            return fallback;
        };
        auto json_get_int = [](const nlohmann::json& obj, const char* key, int fallback) -> int {
            if (!obj.contains(key)) return fallback;
            const auto& v = obj[key];
            if (!v.is_number_integer() && !v.is_number_unsigned()) return fallback;
            try {
                long long vv = v.get<long long>();
                if (vv < INT_MIN || vv > INT_MAX) return fallback;
                return static_cast<int>(vv);
            } catch (...) { return fallback; }
        };
        auto json_get_bool = [](const nlohmann::json& obj, const char* key, bool fallback) -> bool {
            if (obj.contains(key) && obj[key].is_boolean())
                return obj[key].get<bool>();
            return fallback;
        };

        if (root.contains("provider_profiles") && root["provider_profiles"].is_array()) {
            if (root["provider_profiles"].size() > 1024) return true;
            provider_profiles.clear();
            size_t index = 0;
            for (const auto& item : root["provider_profiles"]) {
                if (!item.is_object())
                    continue;
                provider_profile_t profile;
                profile.display_name = json_get_string(item, "display_name", json_get_string(item, "name", "Profile"));
                profile.id = json_get_string(item, "id", sa_settings_detail::make_profile_id(profile.display_name, index++));
                profile.kind = sa_settings_detail::normalize_provider_kind(json_get_string(item, "kind", "openai_compatible"));
                profile.base_url = json_get_string(item, "base_url", "");
                if (item.contains("api_key") && item["api_key"].is_string())
                    profile.api_key = sa_settings_detail::deobfuscate_key(sa_settings_detail::trim(item["api_key"].get<std::string>()));
                profile.model = json_get_string(item, "model", "");
                profile.headers_json = json_get_string(item, "headers_json", "{}");
                profile.enabled = json_get_bool(item, "enabled", true);


                if (item.contains("aws_access_key") && item["aws_access_key"].is_string())
                    profile.aws_access_key = sa_settings_detail::deobfuscate_key(sa_settings_detail::trim(item["aws_access_key"].get<std::string>()));
                if (item.contains("aws_secret_key") && item["aws_secret_key"].is_string())
                    profile.aws_secret_key = sa_settings_detail::deobfuscate_key(sa_settings_detail::trim(item["aws_secret_key"].get<std::string>()));
                if (item.contains("aws_session_token") && item["aws_session_token"].is_string())
                    profile.aws_session_token = sa_settings_detail::deobfuscate_key(sa_settings_detail::trim(item["aws_session_token"].get<std::string>()));
                profile.aws_region = json_get_string(item, "aws_region", "us-east-1");
                profile.aws_use_cross_region = json_get_bool(item, "aws_use_cross_region", false);


                profile.vertex_project_id = json_get_string(item, "vertex_project_id", "");
                profile.vertex_region = json_get_string(item, "vertex_region", "us-east5");
                profile.vertex_key_file = json_get_string(item, "vertex_key_file", "");


                profile.ollama_num_ctx = json_get_int(item, "ollama_num_ctx", 0);


                profile.reasoning_effort = json_get_string(item, "reasoning_effort", "");


                profile.lmstudio_speculative_decoding = json_get_bool(item, "lmstudio_speculative_decoding", false);
                profile.lmstudio_draft_model = json_get_string(item, "lmstudio_draft_model", "");


                profile.mistral_codestral_url = json_get_string(item, "mistral_codestral_url", "");


                profile.azure_deployment = json_get_string(item, "azure_deployment", "");
                profile.azure_api_version = json_get_string(item, "azure_api_version", "2024-10-21");

                provider_profiles.push_back(std::move(profile));
            }
        }
        str("active_provider_profile_id", active_provider_profile_id);

        if (root.contains("workspace") && root["workspace"].is_object()) {
            const auto& ws = root["workspace"];
            workspace.root_path = json_get_string(ws, "root_path", "");
            workspace.open_tabs_json = json_get_string(ws, "open_tabs_json", "[]");
            workspace.view_visibility_json = json_get_string(ws, "view_visibility_json", "{}");
            workspace.quick_open_mru_json = json_get_string(ws, "quick_open_mru_json", "{}");
            workspace.graph_state_json = json_get_string(ws, "graph_state_json", "{}");
            if (workspace.quick_open_mru_json.size() > 256U * 1024U)
                workspace.quick_open_mru_json = "{}";
            if (workspace.graph_state_json.size() > 256U * 1024U)
                workspace.graph_state_json = "{}";
            workspace.active_tab = json_get_int(ws, "active_tab", -1);
            workspace.last_active_path = json_get_string(ws, "last_active_path", "");
            workspace.active_view = json_get_string(ws, "active_view", "editor");
            if (ws.contains("right_width") && ws["right_width"].is_number())
                workspace.right_width = ws["right_width"].get<float>();
            workspace.right_visible  = json_get_bool(ws, "right_visible", true);
            workspace.legacy_bottom_visible = json_get_bool(ws, "bottom_visible", false);
        }

        if (root.contains("sandbox") && root["sandbox"].is_object()) {
            const auto& sb = root["sandbox"];
            sandbox.enabled = json_get_bool(sb, "enabled", true);
            sandbox.timeout_ms = json_get_int(sb, "timeout_ms", 30000);
            sandbox.memory_limit_mb = json_get_int(sb, "memory_limit_mb", 256);
            sandbox.network_mode = json_get_string(sb, "network_mode", "off");
            sandbox.shared_folder_root = json_get_string(sb, "shared_folder_root", "");
        }


        if (root.contains("mcp_client_servers") && root["mcp_client_servers"].is_array()) {
            mcp_client_servers.clear();
            for (const auto& item : root["mcp_client_servers"]) {
                if (!item.is_object()) continue;
                mcp_client_server_t srv;
                srv.name         = json_get_string(item, "name", "");
                srv.url          = json_get_string(item, "url", "");
                srv.transport    = json_get_string(item, "transport", "http_sse");
                srv.command      = json_get_string(item, "command", "");
                srv.args         = json_get_string(item, "args", "");
                if (item.contains("api_key") && item["api_key"].is_string())
                    srv.api_key = sa_settings_detail::deobfuscate_key(
                        sa_settings_detail::trim(item["api_key"].get<std::string>()));
                srv.enabled      = json_get_bool(item, "enabled", true);
                srv.auto_connect = json_get_bool(item, "auto_connect", true);
                if (!srv.name.empty())
                    mcp_client_servers.push_back(std::move(srv));
            }
        }

        marketplace_installed_json = json_get_string(root, "marketplace_installed_json", "");

        if (root.contains("preferred_model_per_provider") && root["preferred_model_per_provider"].is_object()) {
            preferred_model_per_provider.clear();
            for (auto it = root["preferred_model_per_provider"].begin(); it != root["preferred_model_per_provider"].end(); ++it) {
                if (it.value().is_string())
                    preferred_model_per_provider[it.key()] = it.value().get<std::string>();
            }
        }
        if (root.contains("provider_base_url_overrides") && root["provider_base_url_overrides"].is_object()) {
            provider_base_url_overrides.clear();
            for (auto it = root["provider_base_url_overrides"].begin(); it != root["provider_base_url_overrides"].end(); ++it) {
                if (it.value().is_string())
                    provider_base_url_overrides[it.key()] = it.value().get<std::string>();
            }
        }
        if (root.contains("provider_headers_overrides") && root["provider_headers_overrides"].is_object()) {
            provider_headers_overrides.clear();
            for (auto it = root["provider_headers_overrides"].begin(); it != root["provider_headers_overrides"].end(); ++it) {
                if (it.value().is_string())
                    provider_headers_overrides[it.key()] = it.value().get<std::string>();
            }
        }

        migrate_legacy_fields_into_profiles();
        sync_legacy_fields_from_active_profile();

        return true;
#endif
    }

    static const std::string& last_error()
    {
        return sa_settings_detail::last_error_ref();
    }

    bool save()
    {
        std::lock_guard<std::recursive_mutex> lock(sa_settings_detail::io_mutex());
        sa_settings_detail::last_error_ref().clear();

        ensure_default_profiles();
        apply_legacy_fields_to_active_profile();
        sync_legacy_fields_from_active_profile();

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        return true;
#else

        auto path = config_path();
        std::error_code dir_ec;
        std::filesystem::create_directories(path.parent_path(), dir_ec);
        if (dir_ec) {
            sa_settings_detail::last_error_ref() = "create_directories failed: " + dir_ec.message();
            return false;
        }

        nlohmann::json root = nlohmann::json::object();
        root["schema_version"] = 1;
        root["default_provider_id"] = default_provider_id;
        root["default_model_id"] = default_model_id;
        root["small_model_provider_id"] = small_model_provider_id;
        root["small_model_id"] = small_model_id;
        root["default_agent_name"] = default_agent_name;
        root["api_provider"] = api_provider;
        root["gemini_api_key"] = sa_settings_detail::obfuscate_key(gemini_api_key);
        root["gemini_model_name"] = gemini_model_name;
        root["gemini_base_url"] = gemini_base_url;
        root["openai_api_key"] = sa_settings_detail::obfuscate_key(openai_api_key);
        root["openai_model_name"] = openai_model_name;
        root["openai_base_url"] = openai_base_url;
        root["openrouter_api_key"] = sa_settings_detail::obfuscate_key(openrouter_api_key);
        root["openrouter_model_name"] = openrouter_model_name;
        root["anthropic_api_key"] = sa_settings_detail::obfuscate_key(anthropic_api_key);
        root["anthropic_model_name"] = anthropic_model_name;
        root["anthropic_base_url"] = anthropic_base_url;
        root["local_llm_api_key"] = sa_settings_detail::obfuscate_key(local_llm_api_key);
        root["local_llm_model_name"] = local_llm_model_name;
        root["local_llm_base_url"] = local_llm_base_url;

        root["pdb_search_paths"] = pdb_search_paths;
        root["symbol_cache_dir"] = symbol_cache_dir;
        root["symbol_auto_download"] = symbol_auto_download;
        root["symbol_server_url"] = symbol_server_url;
        root["temperature"] = temperature;
        root["mcp_port"] = mcp_port;
        root["mcp_enabled"] = mcp_enabled;

        root["active_theme_idx"] = active_theme_idx;
        root["active_custom_theme_idx"] = active_custom_theme_idx;
        root["editor_tab_size"] = editor_tab_size;
        root["editor_font_size"] = editor_font_size;
        root["editor_auto_complete"] = editor_auto_complete;
        root["editor_line_numbers"] = editor_line_numbers;
        root["editor_highlight_line"] = editor_highlight_line;
        root["theme_icon_index"] = theme_icon_index;
        root["custom_icon_path"] = custom_icon_path;
        root["custom_themes_json"] = custom_themes_json;
        root["ui_density"] = ui_density == 1 ? 1 : 0;
        root["ui_reduced_motion"] = ui_reduced_motion;
        root["ui_diagnostics_mode"] = ui_diagnostics_mode;
        root["ui_table_preferences_json"] = ui_table_preferences_json;
        root["ui_filter_preferences_json"] = ui_filter_preferences_json;
        root["debugger_definitions_json"] = debugger_definitions_json;
		root["memory_scanner_state_json"] = memory_scanner_state_json;

        root["enable_reasoning"] = enable_reasoning;
        root["reasoning_budget"] = reasoning_budget;
        root["reasoning_effort"] = reasoning_effort;
        root["prompt_caching"] = prompt_caching;
        root["max_agentic_rounds"] = max_agentic_rounds;
        root["first_run_completed"] = first_run_completed;
        root["chat_font_size"] = chat_font_size;
        root["editor_word_wrap"] = editor_word_wrap;
        root["editor_minimap"] = editor_minimap;
        root["editor_bracket_match"] = editor_bracket_match;
        root["chat_density"] = chat_density;
        root["chat_show_timestamps"] = chat_show_timestamps;
        root["chat_show_tokens"] = chat_show_tokens;
        root["ghost_text_enabled"] = ghost_text_enabled;
        root["ghost_text_model"] = ghost_text_model;
        root["ghost_text_provider_id"] = ghost_text_provider_id;
        root["ghost_text_debounce_ms"] = ghost_text_debounce_ms;

        root["auto_save_enabled"] = auto_save_enabled;
        root["auto_save_interval_s"] = auto_save_interval_s;
        root["terminal_shell"] = terminal_shell;
        root["terminal_scrollback"] = terminal_scrollback;
        root["terminal_profile_id"] = terminal_profile_id;
        root["terminal_default_cwd"] = terminal_default_cwd;
        root["terminal_restore_sessions"] = terminal_restore_sessions;
        root["terminal_sessions_json"] = terminal_sessions_json;
        root["programming_tasks_json"] = programming_tasks_json;
        root["programming_selected_task_id"] = programming_selected_task_id;
        root["keybinding_overrides_json"] = keybinding_overrides_json;
        root["tool_auto_approve"] = tool_auto_approve;
        root["tool_always_allow"] = tool_always_allow;
        root["tool_always_deny"] = tool_always_deny;
        root["force_xml_tools"] = force_xml_tools;

        root["auto_approve_read"] = auto_approve_read;
        root["auto_approve_write"] = auto_approve_write;
        root["auto_approve_execute"] = auto_approve_execute;
        root["auto_approve_mcp"] = auto_approve_mcp;
        root["auto_approve_mode_switch"] = auto_approve_mode_switch;
        root["auto_approve_subtask"] = auto_approve_subtask;
        root["auto_approve_max_requests"] = auto_approve_max_requests;
        root["auto_approve_max_cost"] = auto_approve_max_cost;
        root["auto_approve_allowed_commands"] = auto_approve_allowed_commands;
        root["aidaignore_path"] = aidaignore_path;
        root["condense_threshold"] = condense_threshold;
        root["condense_buffer"] = condense_buffer;
        root["recent_workspaces_json"] = recent_workspaces_json;
        root["activity_bar_visible"] = activity_bar_visible;

        root["window_x"] = window_x;
        root["window_y"] = window_y;
        root["window_w"] = window_w;
        root["window_h"] = window_h;
        root["window_maximized"] = window_maximized;

        nlohmann::json profiles = nlohmann::json::array();
        for (const auto& profile : provider_profiles) {
            nlohmann::json pj = {
                {"id", profile.id},
                {"display_name", profile.display_name},
                {"kind", sa_settings_detail::normalize_provider_kind(profile.kind)},
                {"base_url", profile.base_url},
                {"api_key", sa_settings_detail::obfuscate_key(profile.api_key)},
                {"model", profile.model},
                {"headers_json", profile.headers_json.empty() ? std::string("{}") : profile.headers_json},
                {"enabled", profile.enabled}
            };


            if (!profile.aws_access_key.empty())
                pj["aws_access_key"] = sa_settings_detail::obfuscate_key(profile.aws_access_key);
            if (!profile.aws_secret_key.empty())
                pj["aws_secret_key"] = sa_settings_detail::obfuscate_key(profile.aws_secret_key);
            if (!profile.aws_session_token.empty())
                pj["aws_session_token"] = sa_settings_detail::obfuscate_key(profile.aws_session_token);
            if (profile.aws_region != "us-east-1")
                pj["aws_region"] = profile.aws_region;
            if (profile.aws_use_cross_region)
                pj["aws_use_cross_region"] = true;


            if (!profile.vertex_project_id.empty())
                pj["vertex_project_id"] = profile.vertex_project_id;
            if (profile.vertex_region != "us-east5")
                pj["vertex_region"] = profile.vertex_region;
            if (!profile.vertex_key_file.empty())
                pj["vertex_key_file"] = profile.vertex_key_file;


            if (profile.ollama_num_ctx > 0)
                pj["ollama_num_ctx"] = profile.ollama_num_ctx;


            if (!profile.reasoning_effort.empty())
                pj["reasoning_effort"] = profile.reasoning_effort;


            if (profile.lmstudio_speculative_decoding)
                pj["lmstudio_speculative_decoding"] = true;
            if (!profile.lmstudio_draft_model.empty())
                pj["lmstudio_draft_model"] = profile.lmstudio_draft_model;


            if (!profile.mistral_codestral_url.empty())
                pj["mistral_codestral_url"] = profile.mistral_codestral_url;


            if (!profile.azure_deployment.empty())
                pj["azure_deployment"] = profile.azure_deployment;
            if (profile.azure_api_version != "2024-10-21")
                pj["azure_api_version"] = profile.azure_api_version;

            profiles.push_back(std::move(pj));
        }
        root["provider_profiles"] = profiles;
        root["active_provider_profile_id"] = active_provider_profile_id;

        root["workspace"] = {
            {"root_path", workspace.root_path},
            {"open_tabs_json", workspace.open_tabs_json},
            {"view_visibility_json", workspace.view_visibility_json},
            {"quick_open_mru_json", workspace.quick_open_mru_json},
            {"graph_state_json", workspace.graph_state_json},
            {"active_tab", workspace.active_tab},
            {"last_active_path", workspace.last_active_path},
            {"active_view", workspace.active_view}
        };

        root["sandbox"] = {
            {"enabled", sandbox.enabled},
            {"timeout_ms", sandbox.timeout_ms},
            {"memory_limit_mb", sandbox.memory_limit_mb},
            {"network_mode", sandbox.network_mode},
            {"shared_folder_root", sandbox.shared_folder_root}
        };


        nlohmann::json mcp_clients = nlohmann::json::array();
        for (const auto& srv : mcp_client_servers) {
            mcp_clients.push_back({
                {"name",         srv.name},
                {"url",          srv.url},
                {"transport",    srv.transport},
                {"command",      srv.command},
                {"args",         srv.args},
                {"api_key",      sa_settings_detail::obfuscate_key(srv.api_key)},
                {"enabled",      srv.enabled},
                {"auto_connect", srv.auto_connect}
            });
        }
        root["mcp_client_servers"] = mcp_clients;
        root["marketplace_installed_json"] = marketplace_installed_json;

        nlohmann::json prefs = nlohmann::json::object();
        for (const auto& kv : preferred_model_per_provider)
            prefs[kv.first] = kv.second;
        root["preferred_model_per_provider"] = prefs;

        nlohmann::json base_overrides = nlohmann::json::object();
        for (const auto& kv : provider_base_url_overrides)
            base_overrides[kv.first] = kv.second;
        root["provider_base_url_overrides"] = base_overrides;

        nlohmann::json header_overrides = nlohmann::json::object();
        for (const auto& kv : provider_headers_overrides)
            header_overrides[kv.first] = kv.second;
        root["provider_headers_overrides"] = header_overrides;

        const std::string payload = root.dump(4);
        constexpr std::size_t maximum_payload_bytes = 16U * 1024U * 1024U;
        if (payload.empty() || payload.size() > maximum_payload_bytes) {
            sa_settings_detail::last_error_ref() = "serialized settings payload exceeds the exact bound";
            return false;
        }

        nlohmann::json verify_parse;
        try {
            verify_parse = nlohmann::json::parse(payload);
        } catch (...) {
            sa_settings_detail::last_error_ref() = "serialized payload failed re-parse";
            return false;
        }
        if (!verify_parse.is_object()) {
            sa_settings_detail::last_error_ref() = "serialized payload is not an object";
            return false;
        }

        auto tmp_path = path;
        tmp_path += L".tmp";
        HANDLE file = CreateFileW(tmp_path.c_str(), GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
        if (file == INVALID_HANDLE_VALUE) {
            sa_settings_detail::last_error_ref() = "failed to open temp settings file for write: " +
                std::to_string(GetLastError());
            return false;
        }
        std::size_t offset = 0;
        bool wrote = true;
        while (offset < payload.size()) {
            const DWORD requested = static_cast<DWORD>((std::min)(payload.size() - offset,
                static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
            DWORD completed = 0;
            if (!WriteFile(file, payload.data() + offset, requested, &completed, nullptr) ||
                completed == 0) {
                wrote = false;
                break;
            }
            offset += completed;
        }
        LARGE_INTEGER written_size{};
        const bool exact_size = wrote && FlushFileBuffers(file) != FALSE &&
            GetFileSizeEx(file, &written_size) != FALSE && written_size.QuadPart >= 0 &&
            static_cast<std::uint64_t>(written_size.QuadPart) == payload.size();
        const DWORD write_error = exact_size ? ERROR_SUCCESS : GetLastError();
        CloseHandle(file);
        if (!exact_size) {
            sa_settings_detail::last_error_ref() = "failed exact settings temp write: " +
                std::to_string(write_error);
            DeleteFileW(tmp_path.c_str());
            return false;
        }

        if (!MoveFileExW(tmp_path.c_str(), path.c_str(),
                         MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            sa_settings_detail::last_error_ref() = "MoveFileExW failed: " + std::to_string(GetLastError());
            DeleteFileW(tmp_path.c_str());
            return false;
        }
        return true;
#endif
    }
};

inline settings_sa_t g_sa_settings;
