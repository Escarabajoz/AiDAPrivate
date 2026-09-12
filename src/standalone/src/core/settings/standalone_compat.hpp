

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shlobj.h>

#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")

#include "mcp_standalone.hpp"

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>


using uchar = unsigned char;


inline void show_wait_box(const char*, ...) {}
inline void hide_wait_box() {}
inline void replace_wait_box(const char*, ...) {}


#ifndef SEGPERM_READ
#define SEGPERM_READ   1
#define SEGPERM_WRITE  2
#define SEGPERM_EXEC   4
#endif
#ifndef ADDSEG_QUIET
#define ADDSEG_QUIET   1
#define ADDSEG_NOSREG  2
#endif
#ifndef SEG_CODE
#define SEG_CODE 2
#define SEG_DATA 3
#define SEG_NORM 7
#endif
#ifndef saRelByte
#define saRelByte 1
#define scPub     2
#endif
struct segment_t {
    uint64_t start_ea = 0;
    uint64_t end_ea   = 0;
    uint64_t size     = 0;
    unsigned char perm = 0;
    int type           = 0;
    int bitness        = 0;
    int align          = 0;
    int comb           = 0;

    uint64_t& startEA = start_ea;
    void update() {}
};
inline segment_t* getseg(uint64_t) { return nullptr; }
inline bool add_segm_ex(segment_t*, const char*, const char*, int) { return false; }
inline void put_byte(uint64_t, unsigned char) {}
inline void put_bytes(uint64_t, const void*, size_t) {}
inline void patch_byte(uint64_t, unsigned char) {}
inline bool is_mapped(uint64_t) { return false; }


#ifndef qsnprintf_defined
#define qsnprintf_defined
inline int qsnprintf(char* buf, size_t n, const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int r = vsnprintf_s(buf, n, _TRUNCATE, fmt, ap);
    va_end(ap);
    return r;
}
#endif


inline bool sa_parse_address(const std::string& text, uint64_t& out)
{
    if (text.empty()) return false;
    try {
        size_t idx = 0;
        out = std::stoull(text, &idx, 0);
        return idx == text.size();
    } catch (...) {
        return false;
    }
}


inline std::optional<uint64_t> sa_parse_address(const std::string& text)
{
    uint64_t val = 0;
    if (sa_parse_address(text, val))
        return val;
    return std::nullopt;
}

inline std::string sa_format_address(uint64_t addr)
{
    std::ostringstream os;
    os << "0x" << std::uppercase << std::hex << addr;
    return os.str();
}


struct compat_param_t
{
    std::string name;
    std::string type;
    std::string description;
    bool        required = false;

    std::vector<std::string>  enum_values   = {};
    nlohmann::json            items_schema  = {};


    operator mcp_standalone::tool_param_t() const
    {
        return {name, type, description, required};
    }
};


struct compat_tool_def_t
{
    std::string name;
    std::string category;
    std::string description;
    std::vector<compat_param_t> params;
    std::function<mcp_standalone::tool_result_t(const nlohmann::json&)> handler;
    bool read_only = true;
};


inline void register_compat(mcp_standalone::server_t& srv,
                            compat_tool_def_t          def)
{
    std::vector<mcp_standalone::tool_param_t> converted_params;
    converted_params.reserve(def.params.size());
    for (auto& p : def.params)
        converted_params.push_back(static_cast<mcp_standalone::tool_param_t>(p));

    srv.register_tool({
        std::move(def.name),
        std::move(def.description),
        std::move(converted_params),
        def.read_only,
        std::move(def.handler)
    });
}

inline std::string compat_action_name(const nlohmann::json& params)
{
    if (params.contains("action") && params["action"].is_string())
        return params["action"].get<std::string>();
    if (params.contains("operation") && params["operation"].is_string())
        return params["operation"].get<std::string>();
    return {};
}

inline nlohmann::json compat_action_payload(const nlohmann::json& params)
{
    nlohmann::json out = params.is_object() ? params : nlohmann::json::object();
    if (params.contains("payload") && params["payload"].is_object()) {
        for (auto it = params["payload"].begin(); it != params["payload"].end(); ++it)
            out[it.key()] = it.value();
    }
    out.erase("action");
    out.erase("operation");
    out.erase("payload");
    return out;
}

inline mcp_standalone::tool_result_t compat_unknown_action(const char* tool_name,
                                                           const std::string& action)
{
    return mcp_standalone::tool_result_t::error(
        std::string(tool_name) + " unknown action: " + action);
}


inline std::string get_downloads_folder()
{
    PWSTR known_path = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Downloads, 0, nullptr, &known_path)) && known_path) {
        const int needed = WideCharToMultiByte(CP_UTF8, 0, known_path, -1, nullptr, 0, nullptr, nullptr);
        if (needed > 1) {
            std::string out(static_cast<size_t>(needed), '\0');
            int written = WideCharToMultiByte(CP_UTF8, 0, known_path, -1, out.data(), needed, nullptr, nullptr);
            if (written <= 0) {
                CoTaskMemFree(known_path);
                return std::string();
            }
            out.resize(static_cast<size_t>(written - 1));
            CoTaskMemFree(known_path);
            out.push_back('\\');
            return out;
        }
        CoTaskMemFree(known_path);
    }
    char buf[MAX_PATH] = {};
    DWORD len = GetEnvironmentVariableA("USERPROFILE", buf, MAX_PATH);
    if (len > 0 && len < MAX_PATH)
        return std::string(buf, len) + "\\Downloads\\";
    return "C:\\Users\\Public\\Downloads\\";
}

inline void ensure_parent_dir_exists(const std::string& file_path)
{
    if (file_path.empty()) return;
    std::filesystem::path p(file_path);
    auto parent = p.parent_path();
    if (parent.empty()) return;
    std::error_code ec;
    std::filesystem::create_directories(parent, ec);
}
