

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "mcp_standalone.hpp"
#include "../../helpers/diag_log.hpp"
#include "standalone_tools_fwd.hpp"
#include "standalone_settings.hpp"
#include "auto_approval.hpp"
#include "event_bus.hpp"
#include "standalone_chat.hpp"
#include "command_sessions.hpp"
#include "../mcp/downstream_producer_governor.hpp"
#include "../helpers/globals.h"
#include "../infra/executor.hpp"
#include "../infra/taskflow_runtime.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <regex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;


namespace coding_tools
{


static bool is_text_extension(const std::string& ext)
{
    static const char* text_exts[] = {
        ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx",
        ".py", ".pyw", ".pyi", ".rb", ".rs", ".go", ".java", ".kt",
        ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
        ".cs", ".fs", ".vb", ".swift", ".m", ".mm",
        ".lua", ".pl", ".pm", ".tcl", ".sh", ".bash", ".zsh", ".fish",
        ".bat", ".cmd", ".ps1", ".psm1",
        ".asm", ".s", ".inc", ".nasm",
        ".json", ".jsonc", ".json5",
        ".xml", ".html", ".htm", ".xhtml", ".svg",
        ".css", ".scss", ".sass", ".less",
        ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
        ".md", ".markdown", ".rst", ".txt", ".log",
        ".cmake", ".make", ".makefile", ".mk",
        ".dockerfile", ".gitignore", ".editorconfig",
        ".sql", ".graphql", ".proto", ".thrift",
        ".r", ".R", ".jl", ".m", ".nb",
        ".vue", ".svelte", ".astro",
        ".tf", ".hcl", ".nix", ".dhall",
        ".def", ".map", ".ld", ".lds",
    };
    std::string lower_ext = ext;
    std::transform(lower_ext.begin(), lower_ext.end(), lower_ext.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    for (const char* e : text_exts)
        if (lower_ext == e) return true;
    return false;
}


static std::string sanitize_path(const std::string& raw)
{

    std::string p = raw;

    for (char& c : p) { if (c == '/') c = '\\'; }


    if (!file_browser::current_dir.empty() && !p.empty() && p[0] != '\\' &&
        (p.size() < 2 || p[1] != ':'))
    {
        p = file_browser::current_dir + "\\" + p;
    }


    std::error_code ec;
    auto canonical = fs::weakly_canonical(fs::path(p), ec);
    if (ec) return raw;
    return canonical.string();
}


static bool path_within_workspace(const std::string& canonical_path)
{
    if (file_browser::current_dir.empty())
        return true;

    std::error_code ec;
    auto ws = fs::weakly_canonical(fs::path(file_browser::current_dir), ec);
    if (ec) return false;

    auto ws_str = ws.string();
    auto p_str  = canonical_path;

    std::transform(ws_str.begin(), ws_str.end(), ws_str.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    std::transform(p_str.begin(), p_str.end(), p_str.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    return p_str.find(ws_str) == 0;
}

static tool_result_t tool_read_file(const json& params)
{
    diag::log_tagged_fmt("coding", "read_file entry path='%.120s'",
        params.contains("path") && params["path"].is_string()
            ? params["path"].get<std::string>().c_str() : "");
    if (!params.contains("path") || !params["path"].is_string())
    {
        diag::log_tagged_fmt("coding", "read_file missing path");
        return tool_result_t::error("Missing required parameter: path");
    }

    std::string path = sanitize_path(params["path"].get<std::string>());
    diag::log_tagged_fmt("coding", "read_file resolved='%.120s'", path.c_str());
    if (!path_within_workspace(path))
    {
        diag::log_tagged_fmt("coding", "read_file outside workspace path='%.120s'", path.c_str());
        return tool_result_t::error("Path is outside the workspace.");
    }

    std::error_code ec;
    if (!fs::exists(path, ec))
    {
        diag::log_tagged_fmt("coding", "read_file not found path='%.120s'", path.c_str());
        return tool_result_t::error("File not found: " + path);
    }

    if (fs::is_directory(path, ec))
    {
        diag::log_tagged_fmt("coding", "read_file is directory path='%.120s'", path.c_str());
        return tool_result_t::error("Path is a directory, not a file. Use list_directory instead.");
    }

    auto file_size = fs::file_size(path, ec);
    if (ec || file_size > 2 * 1024 * 1024)
    {
        diag::log_tagged_fmt("coding", "read_file too large size=%llu path='%.120s'",
            (unsigned long long)file_size, path.c_str());
        return tool_result_t::error("File too large (>2MB). Use read_file with line range instead.");
    }

    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open())
    {
        diag::log_tagged_fmt("coding", "read_file open fail path='%.120s'", path.c_str());
        return tool_result_t::error("Cannot open file: " + path);
    }

    std::string content((std::istreambuf_iterator<char>(ifs)),
                         std::istreambuf_iterator<char>());
    ifs.close();

    diag::log_tagged_fmt("coding", "read_file loaded bytes=%zu path='%.120s'",
        content.size(), path.c_str());
    int start_line = 1;
    int end_line   = 0;

    if (params.contains("start_line") && params["start_line"].is_number_integer())
        start_line = (std::max)(1, params["start_line"].get<int>());
    if (params.contains("end_line") && params["end_line"].is_number_integer())
        end_line = params["end_line"].get<int>();


    if (start_line > 1 || end_line > 0) {
        std::istringstream ss(content);
        std::string line;
        std::string result;
        int line_num = 0;
        while (std::getline(ss, line)) {
            ++line_num;
            if (line_num < start_line) continue;
            if (end_line > 0 && line_num > end_line) break;
            result += std::to_string(line_num) + " | " + line + "\n";
        }
        if (result.empty())
            return tool_result_t::error("Line range out of bounds (file has " +
                                        std::to_string(line_num) + " lines).");
        return tool_result_t::ok(result);
    }


    if (content.size() < 200000) {
        std::istringstream ss(content);
        std::string line;
        std::string numbered;
        int line_num = 0;
        while (std::getline(ss, line)) {
            ++line_num;
            numbered += std::to_string(line_num) + " | " + line + "\n";
        }
        return tool_result_t::ok(numbered);
    }

    return tool_result_t::ok(content);
}


static tool_result_t tool_write_file(const json& params)
{
    diag::log_tagged_fmt("coding", "write_file entry path='%.120s'",
        params.contains("path") && params["path"].is_string()
            ? params["path"].get<std::string>().c_str() : "");
    if (!params.contains("path") || !params["path"].is_string())
    {
        diag::log_tagged_fmt("coding", "write_file missing path");
        return tool_result_t::error("Missing required parameter: path");
    }
    if (!params.contains("content") || !params["content"].is_string())
    {
        diag::log_tagged_fmt("coding", "write_file missing content");
        return tool_result_t::error("Missing required parameter: content");
    }

    std::string path = sanitize_path(params["path"].get<std::string>());
    if (!path_within_workspace(path))
    {
        diag::log_tagged_fmt("coding", "write_file outside workspace path='%.120s'", path.c_str());
        return tool_result_t::error("Path is outside the workspace.");
    }

    const std::string& content = params["content"].get_ref<const std::string&>();


    std::error_code ec;
    auto parent = fs::path(path).parent_path();
    if (!parent.empty())
        fs::create_directories(parent, ec);

    std::string review_detail;
    if (file_tabs::stage_external_proposal(path, content, "MCP write_file", review_detail)) {
        diag::log_tagged_fmt("coding", "write_file review_required path='%.120s'", path.c_str());
        return tool_result_t::ok(review_detail);
    }
    const auto written = file_tabs::atomic_write_file(path, content);
    if (!written.succeeded) {
        diag::log_tagged_fmt("coding", "write_file atomic fail path='%.120s'", path.c_str());
        return tool_result_t::error(written.detail);
    }
    diag::log_tagged_fmt("coding", "write_file ok bytes=%zu path='%.120s'",
        content.size(), path.c_str());

    file_tabs::accept_external_write(path, content);


    file_browser::needs_refresh = true;

    {
        aida::events::file_edited_t evt;
        evt.path       = path;
        evt.kind       = "write";
        evt.session_id = chat_active_session();
        aida::events::publish(aida::events::event_file_edited, evt);
    }

    return tool_result_t::ok("File written: " + path + " (" +
                             std::to_string(content.size()) + " bytes)");
}


static tool_result_t tool_edit_file(const json& params)
{
    diag::log_tagged_fmt("coding", "edit_file entry path='%.120s'",
        params.contains("path") && params["path"].is_string()
            ? params["path"].get<std::string>().c_str() : "");
    if (!params.contains("path") || !params["path"].is_string())
    {
        diag::log_tagged_fmt("coding", "edit_file missing path");
        return tool_result_t::error("Missing required parameter: path");
    }
    if (!params.contains("old_text") || !params["old_text"].is_string())
    {
        diag::log_tagged_fmt("coding", "edit_file missing old_text");
        return tool_result_t::error("Missing required parameter: old_text");
    }
    if (!params.contains("new_text") || !params["new_text"].is_string())
    {
        diag::log_tagged_fmt("coding", "edit_file missing new_text");
        return tool_result_t::error("Missing required parameter: new_text");
    }

    std::string path = sanitize_path(params["path"].get<std::string>());
    if (!path_within_workspace(path))
    {
        diag::log_tagged_fmt("coding", "edit_file outside workspace path='%.120s'", path.c_str());
        return tool_result_t::error("Path is outside the workspace.");
    }

    std::error_code ec;
    if (!fs::exists(path, ec))
    {
        diag::log_tagged_fmt("coding", "edit_file not found path='%.120s'", path.c_str());
        return tool_result_t::error("File not found: " + path);
    }


    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open())
        return tool_result_t::error("Cannot open file: " + path);
    std::string content((std::istreambuf_iterator<char>(ifs)),
                         std::istreambuf_iterator<char>());
    ifs.close();

    const std::string& old_text = params["old_text"].get_ref<const std::string&>();
    const std::string& new_text = params["new_text"].get_ref<const std::string&>();


    size_t pos = content.find(old_text);
    if (pos == std::string::npos)
    {
        diag::log_tagged_fmt("coding", "edit_file old_text not found path='%.120s'", path.c_str());
        return tool_result_t::error("old_text not found in file. Ensure it matches exactly "
                                    "(including whitespace and indentation).");
    }

    size_t second = content.find(old_text, pos + old_text.size());
    if (second != std::string::npos)
    {
        diag::log_tagged_fmt("coding", "edit_file old_text ambiguous path='%.120s'", path.c_str());
        return tool_result_t::error("old_text matches multiple locations (" +
            std::to_string(2) + "+). Include more surrounding context to match uniquely.");
    }


    content.replace(pos, old_text.size(), new_text);


    std::string review_detail;
    if (file_tabs::stage_external_proposal(path, content, "MCP edit_file", review_detail)) {
        diag::log_tagged_fmt("coding", "edit_file review_required path='%.120s'", path.c_str());
        return tool_result_t::ok(review_detail);
    }
    const auto written = file_tabs::atomic_write_file(path, content);
    if (!written.succeeded) {
        diag::log_tagged_fmt("coding", "edit_file atomic fail path='%.120s'", path.c_str());
        return tool_result_t::error(written.detail);
    }
    diag::log_tagged_fmt("coding", "edit_file ok path='%.120s'", path.c_str());

    file_tabs::accept_external_write(path, content);


    int line_num = 1;
    for (size_t i = 0; i < pos && i < content.size(); ++i)
        if (content[i] == '\n') ++line_num;

    {
        aida::events::file_edited_t evt;
        evt.path       = path;
        evt.kind       = "edit";
        evt.session_id = chat_active_session();
        aida::events::publish(aida::events::event_file_edited, evt);
    }

    return tool_result_t::ok("Edit applied at line " + std::to_string(line_num) +
                             " in " + path);
}


static tool_result_t tool_list_directory(const json& params)
{
    diag::log_tagged_fmt("coding", "list_directory entry path='%.120s'",
        params.contains("path") && params["path"].is_string()
            ? params["path"].get<std::string>().c_str() : "");
    std::string path;
    if (params.contains("path") && params["path"].is_string())
        path = sanitize_path(params["path"].get<std::string>());
    else if (!file_browser::current_dir.empty())
        path = file_browser::current_dir;
    else
    {
        diag::log_tagged_fmt("coding", "list_directory no path no workspace");
        return tool_result_t::error("No path specified and no workspace directory set.");
    }

    diag::log_tagged_fmt("coding", "list_directory resolved='%.120s'", path.c_str());
    std::error_code ec;
    if (!fs::is_directory(path, ec))
    {
        diag::log_tagged_fmt("coding", "list_directory not a dir path='%.120s'", path.c_str());
        return tool_result_t::error("Not a directory: " + path);
    }

    std::string output;
    int count = 0;
    constexpr int MAX_ENTRIES = 500;

    for (auto& entry : fs::directory_iterator(path, ec)) {
        if (++count > MAX_ENTRIES) {
            output += "... (truncated at " + std::to_string(MAX_ENTRIES) + " entries)\n";
            break;
        }
        auto name = entry.path().filename().string();
        if (entry.is_directory(ec))
            output += name + "/\n";
        else {
            auto sz = entry.file_size(ec);
            output += name;
            if (!ec && sz > 0) {
                if (sz >= 1048576)
                    output += "  (" + std::to_string(sz / 1048576) + " MB)";
                else if (sz >= 1024)
                    output += "  (" + std::to_string(sz / 1024) + " KB)";
                else
                    output += "  (" + std::to_string(sz) + " B)";
            }
            output += "\n";
        }
    }

    if (output.empty())
    {
        diag::log_tagged_fmt("coding", "list_directory empty path='%.120s'", path.c_str());
        return tool_result_t::ok("Directory is empty: " + path);
    }

    diag::log_tagged_fmt("coding", "list_directory ok count=%d path='%.120s'", count, path.c_str());
    return tool_result_t::ok("Contents of " + path + ":\n" + output);
}


static tool_result_t tool_search_workspace(const json& params)
{
    diag::log_tagged_fmt("coding", "search_workspace entry query='%.80s'",
        params.contains("query") && params["query"].is_string()
            ? params["query"].get<std::string>().c_str() : "");
    if (!params.contains("query") || !params["query"].is_string())
    {
        diag::log_tagged_fmt("coding", "search_workspace missing query");
        return tool_result_t::error("Missing required parameter: query");
    }

    std::string query = params["query"].get<std::string>();
    if (query.empty())
    {
        diag::log_tagged_fmt("coding", "search_workspace empty query");
        return tool_result_t::error("Query cannot be empty.");
    }

    std::string root = file_browser::current_dir;
    if (params.contains("path") && params["path"].is_string()) {
        std::string custom = sanitize_path(params["path"].get<std::string>());
        if (!path_within_workspace(custom))
            return tool_result_t::error("Path is outside the workspace.");
        std::error_code ec;
        if (fs::is_directory(custom, ec))
            root = custom;
    }
    if (root.empty())
        return tool_result_t::error("No workspace directory set.");

    std::string include_pattern;
    std::string exclude_pattern;
    bool use_regex = false;

    if (params.contains("include") && params["include"].is_string())
        include_pattern = params["include"].get<std::string>();
    if (params.contains("exclude") && params["exclude"].is_string())
        exclude_pattern = params["exclude"].get<std::string>();
    if (params.contains("regex") && params["regex"].is_boolean())
        use_regex = params["regex"].get<bool>();


    struct match_t {
        std::string filepath;
        int         line_number;
        std::string line_text;
    };
    std::vector<match_t> matches;
    constexpr int MAX_MATCHES = 100;
    constexpr int MAX_FILES = 5000;
    int files_scanned = 0;

    std::regex re;
    bool regex_valid = false;
    if (use_regex) {
        try {
            re = std::regex(query, std::regex::ECMAScript | std::regex::optimize);
            regex_valid = true;
        } catch (...) {
            return tool_result_t::error("Invalid regex pattern: " + query);
        }
    }


    std::string lower_query = query;
    if (!use_regex)
        std::transform(lower_query.begin(), lower_query.end(), lower_query.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });


    std::vector<std::string> excluded_dirs;
    if (!exclude_pattern.empty()) {
        std::istringstream ess(exclude_pattern);
        std::string tok;
        while (std::getline(ess, tok, ',')) {
            while (!tok.empty() && tok.front() == ' ') tok.erase(tok.begin());
            while (!tok.empty() && tok.back() == ' ') tok.pop_back();
            if (!tok.empty()) excluded_dirs.push_back(tok);
        }
    }

    excluded_dirs.push_back("node_modules");
    excluded_dirs.push_back(".git");
    excluded_dirs.push_back("__pycache__");
    excluded_dirs.push_back(".vs");

    std::error_code ec;
    for (auto it = fs::recursive_directory_iterator(root,
            fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator(); ++it)
    {
        if (static_cast<int>(matches.size()) >= MAX_MATCHES) break;
        if (files_scanned >= MAX_FILES) break;

        if (it->is_directory(ec)) {
            auto dirname = it->path().filename().string();
            bool skip = false;
            for (auto& ex : excluded_dirs) {
                if (dirname == ex) { skip = true; break; }
            }
            if (skip) { it.disable_recursion_pending(); continue; }
            continue;
        }

        if (!it->is_regular_file(ec)) continue;

        auto ext = it->path().extension().string();
        if (!is_text_extension(ext) && ext != "") continue;


        if (!include_pattern.empty()) {
            auto fname = it->path().filename().string();
            std::string lower_fname = fname;
            std::transform(lower_fname.begin(), lower_fname.end(), lower_fname.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            std::string lower_inc = include_pattern;
            std::transform(lower_inc.begin(), lower_inc.end(), lower_inc.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            std::string lower_ext = ext;
            std::transform(lower_ext.begin(), lower_ext.end(), lower_ext.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            bool include_match = lower_fname.find(lower_inc) != std::string::npos ||
                                 lower_ext.find(lower_inc) != std::string::npos;
            if (!include_match && lower_inc.size() > 1 && lower_inc[0] == '*') {
                std::string suffix = lower_inc.substr(1);
                include_match = lower_fname.size() >= suffix.size() &&
                    lower_fname.compare(lower_fname.size() - suffix.size(), suffix.size(), suffix) == 0;
            }
            if (!include_match)
                continue;
        }

        ++files_scanned;


        auto fsz = it->file_size(ec);
        if (ec || fsz > 2 * 1024 * 1024) continue;

        std::ifstream ifs(it->path(), std::ios::binary);
        if (!ifs.is_open()) continue;

        std::string line;
        int line_num = 0;
        while (std::getline(ifs, line)) {
            ++line_num;
            if (static_cast<int>(matches.size()) >= MAX_MATCHES) break;

            bool found = false;
            if (use_regex && regex_valid) {
                found = std::regex_search(line, re);
            } else {
                std::string lower_line = line;
                std::transform(lower_line.begin(), lower_line.end(), lower_line.begin(),
                    [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                found = (lower_line.find(lower_query) != std::string::npos);
            }

            if (found) {

                std::string display_line = line;
                if (display_line.size() > 200)
                    display_line = display_line.substr(0, 200) + "...";

                auto first = display_line.find_first_not_of(" \t");
                if (first != std::string::npos && first > 0)
                    display_line = display_line.substr(first);

                matches.push_back({
                    it->path().string(),
                    line_num,
                    display_line
                });
            }
        }
    }

    diag::log_tagged_fmt("coding", "search_workspace scanned=%d matches=%zu query='%.80s'",
        files_scanned, matches.size(), query.c_str());
    if (matches.empty())
        return tool_result_t::ok("No matches found for \"" + query + "\" in " +
                                 std::to_string(files_scanned) + " files.");

    std::string result = "Found " + std::to_string(matches.size()) + " match(es) in " +
                         std::to_string(files_scanned) + " files:\n\n";
    for (auto& m : matches) {

        std::string display_path = m.filepath;
        if (!root.empty() && display_path.find(root) == 0)
            display_path = display_path.substr(root.size() + 1);
        result += display_path + ":" + std::to_string(m.line_number) + ": " +
                  m.line_text + "\n";
    }

    return tool_result_t::ok(result);
}


static tool_result_t tool_run_command(const json& params)
{
    diag::log_tagged_fmt("coding", "run_command entry cmd='%.120s'",
        params.contains("command") && params["command"].is_string()
            ? params["command"].get<std::string>().c_str() : "");
    if (!params.contains("command") || !params["command"].is_string())
    {
        diag::log_tagged_fmt("coding", "run_command missing command");
        return tool_result_t::error("Missing required parameter: command");
    }

    std::string command = params["command"].get<std::string>();
    if (command.empty())
    {
        diag::log_tagged_fmt("coding", "run_command empty command");
        return tool_result_t::error("Command cannot be empty.");
    }


    if (auto_approval::is_dangerous_command(command)) {
        diag::log_tagged_fmt("coding", "run_command dangerous cmd='%.120s'", command.c_str());
        output_log::push(bottom_tab_t::sandbox_log,
            "[run_command] WARNING: Potentially dangerous command detected: " + command);
    }

    int timeout_ms = 30000;
    if (params.contains("timeout_ms") && params["timeout_ms"].is_number_integer())
        timeout_ms = (std::clamp)(params["timeout_ms"].get<int>(), 1000, 600000);

    bool wait = true;
    if (params.contains("wait") && params["wait"].is_boolean())
        wait = params["wait"].get<bool>();

    bool want_session = false;
    std::string explicit_session_id;
    if (params.contains("session_id") && params["session_id"].is_string()) {
        explicit_session_id = params["session_id"].get<std::string>();
        want_session = true;
    }
    if (!wait) want_session = true;

    std::string cwd = file_browser::current_dir;
    bool cwd_from_params = false;
    if (params.contains("cwd") && params["cwd"].is_string()) {
        std::string custom = sanitize_path(params["cwd"].get<std::string>());
        if (!path_within_workspace(custom))
            return tool_result_t::error("cwd is outside the workspace.");
        std::error_code ec;
        if (fs::is_directory(custom, ec)) {
            cwd = custom;
            cwd_from_params = true;
        }
    }

    if (!cwd.empty()) {
        std::error_code cwd_ec;
        if (!fs::is_directory(cwd, cwd_ec)) {
            const std::string prior = cwd;
            diag::log_tagged_fmt("coding",
                "run_command cwd_invalid cwd='%.260s' err=%d msg='%.160s' cmd='%.120s' from_params=%d",
                prior.c_str(),
                cwd_ec.value(),
                cwd_ec.message().c_str(),
                command.c_str(),
                cwd_from_params ? 1 : 0);
            std::error_code temp_ec;
            std::string fallback = fs::temp_directory_path(temp_ec).string();
            if (temp_ec || fallback.empty() || !fs::is_directory(fallback, temp_ec)) {
                diag::log_tagged_fmt("coding",
                    "run_command cwd_fallback_failed prior='%.260s' temp_err=%d temp_msg='%.160s'",
                    prior.c_str(),
                    temp_ec.value(),
                    temp_ec.message().c_str());
                return tool_result_t::error(
                    "Working directory is invalid and no fallback is available (prior=" + prior +
                    ", err=" + std::to_string(cwd_ec.value()) + ").");
            }
            diag::log_tagged_fmt("coding",
                "run_command cwd_fallback prior='%.260s' fallback='%.260s'",
                prior.c_str(),
                fallback.c_str());
            cwd = std::move(fallback);
        }
    }

    output_log::push(bottom_tab_t::sandbox_log,
        "[run_command] $ " + command);


    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = nullptr;

    HANDLE h_stdout_rd = nullptr, h_stdout_wr = nullptr;
    if (!CreatePipe(&h_stdout_rd, &h_stdout_wr, &sa, 0))
        return tool_result_t::error("Failed to create pipe for stdout.");
    SetHandleInformation(h_stdout_rd, HANDLE_FLAG_INHERIT, 0);

    HANDLE h_stderr_rd = nullptr, h_stderr_wr = nullptr;
    if (!CreatePipe(&h_stderr_rd, &h_stderr_wr, &sa, 0)) {
        CloseHandle(h_stdout_rd);
        CloseHandle(h_stdout_wr);
        return tool_result_t::error("Failed to create pipe for stderr.");
    }
    SetHandleInformation(h_stderr_rd, HANDLE_FLAG_INHERIT, 0);


    std::string cmdline = "cmd.exe /s /c \"" + command + "\"";

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = h_stdout_wr;
    si.hStdError = h_stderr_wr;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi{};

    auto bg_admission = command_sessions::acquire_background_command_admission(
        "standalone", "session_unknown", command);
    if (!bg_admission.admitted) {
        diag::log_tagged_fmt("coding",
            "run_command downstream_rejected reason=%s quota=%s observed=%zu limit=%zu cmd='%.120s'",
            bg_admission.reason.c_str(),
            bg_admission.quota_name.c_str(),
            bg_admission.observed,
            bg_admission.limit,
            command.c_str());
        CloseHandle(h_stdout_rd);
        CloseHandle(h_stdout_wr);
        CloseHandle(h_stderr_rd);
        CloseHandle(h_stderr_wr);
        json rej = command_sessions::background_command_rejection_json(bg_admission, "standalone", "session_unknown", command);
        return tool_result_t::error("Downstream capacity exhausted; command was not started.",
            "MCP_DOWNSTREAM_CAPACITY_REJECT", rej);
    }
    const std::uint64_t bg_downstream_token = bg_admission.admission_token;

    SetLastError(ERROR_SUCCESS);
    BOOL created = CreateProcessA(
        nullptr,
        &cmdline[0],
        nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW,
        nullptr,
        cwd.empty() ? nullptr : cwd.c_str(),
        &si, &pi);
    const DWORD create_gle = created ? ERROR_SUCCESS : GetLastError();

    CloseHandle(h_stdout_wr);
    CloseHandle(h_stderr_wr);

    if (!created) {
        diag::log_tagged_fmt("coding",
            "run_command create process fail err=%lu cwd='%.260s' cmd='%.120s'",
            create_gle,
            cwd.c_str(),
            command.c_str());
        mcp_standalone::downstream::governor_t::instance().release(bg_downstream_token, "create_process_failed");
        CloseHandle(h_stdout_rd);
        CloseHandle(h_stderr_rd);
        return tool_result_t::error("Failed to launch command: " + command +
                                    " (cwd=" + (cwd.empty() ? std::string("<none>") : cwd) +
                                    ", error " + std::to_string(create_gle) + ")");
    }

    diag::log_tagged_fmt("coding", "run_command process started pid=%lu wait=%d cmd='%.120s'",
        pi.dwProcessId, (int)wait, command.c_str());
    constexpr size_t MAX_OUTPUT = 1048576;

    if (want_session) {
        command_sessions::prune_finished(64);
        auto sess = std::make_unique<command_sessions::command_session_t>();
        sess->id = explicit_session_id.empty()
            ? command_sessions::generate_session_id()
            : explicit_session_id;
        sess->command = command;
        sess->started_at = std::chrono::steady_clock::now();
        sess->process_info = pi;
        sess->stdout_read = h_stdout_rd;
        sess->stderr_read = h_stderr_rd;
        sess->timeout_ms = timeout_ms;
        sess->alive.store(true);
        sess->downstream_token = bg_downstream_token;
        sess->principal_id = "standalone";

        std::string session_id_copy = sess->id;
        command_sessions::command_session_t* raw = command_sessions::register_session(std::move(sess));

        raw->reader_done.store(false, std::memory_order_release);
        bool reader_posted = false;
        try {
            aida::infra::executor::submission_t sub;
            sub.owner_subsystem = "coding_tools";
            sub.label = "coding_tools.run_command.reader";
            sub.thread_class = "blocking_command_reader";
            sub.domain = aida::infra::executor::domain_t::long_running;
            sub.priority = 3;
            sub.body = [raw, timeout_ms]() {
                const DWORD tid = GetCurrentThreadId();
                const ULONGLONG start_tick = GetTickCount64();
                diag::log_tagged_fmt("coding",
                    "run_command reader_enter session_id='%s' pid=%lu tid=%lu timeout_ms=%d",
                    raw->id.c_str(),
                    static_cast<unsigned long>(raw->process_info.dwProcessId),
                    static_cast<unsigned long>(tid),
                    timeout_ms);
                try {
                    auto start = std::chrono::steady_clock::now();
                    auto drain_pipe = [&](HANDLE h, std::string& dest) -> bool {
                        DWORD avail = 0;
                        if (!PeekNamedPipe(h, nullptr, 0, nullptr, &avail, nullptr)) return false;
                        if (avail == 0) return true;
                        while (avail > 0) {
                            char buf[8192];
                            DWORD read_bytes = 0;
                            DWORD to_read = (std::min)(static_cast<DWORD>(sizeof(buf)), avail);
                            if (!ReadFile(h, buf, to_read, &read_bytes, nullptr) || read_bytes == 0)
                                return false;
                            {
                                std::lock_guard<std::mutex> lk(raw->output_mutex);
                                if (dest.size() < MAX_OUTPUT) {
                                    size_t room = MAX_OUTPUT - dest.size();
                                    size_t take = (read_bytes < room) ? read_bytes : room;
                                    dest.append(buf, take);
                                }
                            }
                            avail = 0;
                            if (!PeekNamedPipe(h, nullptr, 0, nullptr, &avail, nullptr)) return false;
                        }
                        return true;
                    };

                    while (raw->alive.load()) {
                        if (timeout_ms > 0) {
                            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::steady_clock::now() - start).count();
                            if (elapsed >= timeout_ms) {
                                raw->timed_out.store(true);
                                TerminateProcess(raw->process_info.hProcess, 1);
                                break;
                            }
                        }

                        bool out_ok = drain_pipe(raw->stdout_read, raw->stdout_buf);
                        bool err_ok = drain_pipe(raw->stderr_read, raw->stderr_buf);
                        if (!out_ok && !err_ok) break;

                        DWORD wait_res = WaitForSingleObject(raw->process_info.hProcess, 50);
                        if (wait_res == WAIT_OBJECT_0) {
                            drain_pipe(raw->stdout_read, raw->stdout_buf);
                            drain_pipe(raw->stderr_read, raw->stderr_buf);
                            break;
                        }
                    }

                    DWORD exit_code = 0;
                    GetExitCodeProcess(raw->process_info.hProcess, &exit_code);
                    raw->exit_code.store(static_cast<int64_t>(exit_code));
                    raw->finished_at = std::chrono::steady_clock::now();
                    raw->alive.store(false);

                    output_log::push(bottom_tab_t::sandbox_log,
                        "[run_command:" + raw->id + "] exit=" + std::to_string(exit_code) +
                        (raw->timed_out.load() ? " (TIMED OUT)" : ""));
                }
                catch (const std::exception& ex) {
                    raw->alive.store(false);
                    diag::log_tagged_fmt("coding",
                        "run_command reader_exception session_id='%s' tid=%lu error=%s",
                        raw->id.c_str(),
                        static_cast<unsigned long>(tid),
                        ex.what());
                }
                catch (...) {
                    raw->alive.store(false);
                    diag::log_tagged_fmt("coding",
                        "run_command reader_exception_unknown session_id='%s' tid=%lu",
                        raw->id.c_str(),
                        static_cast<unsigned long>(tid));
                }
                diag::log_tagged_fmt("coding",
                    "run_command reader_exit session_id='%s' tid=%lu elapsed_ms=%llu alive=%d timed_out=%d exit=%lld",
                    raw->id.c_str(),
                    static_cast<unsigned long>(tid),
                    static_cast<unsigned long long>(GetTickCount64() - start_tick),
                    raw->alive.load() ? 1 : 0,
                    raw->timed_out.load() ? 1 : 0,
                    static_cast<long long>(raw->exit_code.load()));
                raw->reader_done.store(true, std::memory_order_release);
            };
            reader_posted = aida::infra::executor::submit(std::move(sub)).submitted;
        } catch (...) {
            reader_posted = false;
        }
        if (!reader_posted) {
            const auto qs = aida::infra::taskflow_runtime::active_snapshot();
            diag::log_tagged_fmt("coding",
                "run_command reader_post_failed session_id='%s' pid=%lu runtime_accepting=%d runtime_shutdown=%d service_pending=%llu service_active=%u total_submitted=%llu total_rejected=%llu",
                session_id_copy.c_str(),
                static_cast<unsigned long>(pi.dwProcessId),
                qs.accepting ? 1 : 0,
                qs.shutting_down ? 1 : 0,
                static_cast<unsigned long long>(qs.service_queue_pending),
                static_cast<unsigned>(qs.service_queue_active),
                static_cast<unsigned long long>(qs.total_submitted),
                static_cast<unsigned long long>(qs.total_rejected));
            raw->alive.store(false, std::memory_order_release);
            if (raw->process_info.hProcess) {
                DWORD code = 0;
                if (GetExitCodeProcess(raw->process_info.hProcess, &code) && code == STILL_ACTIVE)
                    TerminateProcess(raw->process_info.hProcess, 1);
            }
            raw->reader_done.store(true, std::memory_order_release);
            command_sessions::remove_session(session_id_copy);
            return tool_result_t::error("Failed to schedule command reader on executor.");
        }

        if (wait) {
            while (!raw->reader_done.load(std::memory_order_acquire))
                std::this_thread::sleep_for(std::chrono::milliseconds(1));

            std::string out_copy, err_copy;
            int64_t exit_code = 0;
            bool was_timeout = false;
            {
                std::lock_guard<std::mutex> lk(raw->output_mutex);
                out_copy = raw->stdout_buf;
                err_copy = raw->stderr_buf;
                exit_code = raw->exit_code.load();
                was_timeout = raw->timed_out.load();
            }

            std::string result;
            result += "Session ID: " + session_id_copy + "\n";
            result += "Exit code: " + std::to_string(exit_code);
            if (was_timeout)
                result += " (timed out after " + std::to_string(timeout_ms) + "ms)";
            result += "\n";
            if (!out_copy.empty()) {
                result += "--- stdout ---\n";
                if (out_copy.size() >= MAX_OUTPUT)
                    result += "(stdout truncated to " + std::to_string(MAX_OUTPUT) + " bytes)\n";
                result += out_copy;
                if (!out_copy.empty() && out_copy.back() != '\n') result += "\n";
            }
            if (!err_copy.empty()) {
                result += "--- stderr ---\n";
                if (err_copy.size() >= MAX_OUTPUT)
                    result += "(stderr truncated to " + std::to_string(MAX_OUTPUT) + " bytes)\n";
                result += err_copy;
            }
            if (out_copy.empty() && err_copy.empty())
                result += "(no output)";
            return tool_result_t::ok(result);
        }

        diag::log_tagged_fmt("coding", "run_command bg session_id='%s' cmd='%.120s'",
            session_id_copy.c_str(), command.c_str());
        return tool_result_t::ok(
            "Started background command (session " + session_id_copy + "). "
            "Use read_command_output with this id to retrieve output.",
            json{{"session_id", session_id_copy}, {"command", command}});
    }


    std::string output;
    auto start = std::chrono::steady_clock::now();
    bool timed_out = false;

    auto drain = [&](HANDLE h) {
        DWORD avail = 0;
        if (!PeekNamedPipe(h, nullptr, 0, nullptr, &avail, nullptr)) return false;
        if (avail == 0) return true;
        char buf[4096];
        DWORD to_read = (std::min)(static_cast<DWORD>(sizeof(buf)), avail);
        if (output.size() >= MAX_OUTPUT) return true;
        size_t room = MAX_OUTPUT - output.size();
        if (static_cast<size_t>(to_read) > room) to_read = static_cast<DWORD>(room);
        DWORD read_bytes = 0;
        if (ReadFile(h, buf, to_read, &read_bytes, nullptr) && read_bytes > 0)
            output.append(buf, read_bytes);
        return true;
    };

    bool cancelled = false;
    while (true) {
        if (mcp_standalone::current_call_cancelled()) {
            cancelled = true;
            TerminateProcess(pi.hProcess, 1);
            break;
        }
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed >= timeout_ms) {
            timed_out = true;
            TerminateProcess(pi.hProcess, 1);
            break;
        }

        bool any_data = false;
        DWORD avail_out = 0, avail_err = 0;
        PeekNamedPipe(h_stdout_rd, nullptr, 0, nullptr, &avail_out, nullptr);
        PeekNamedPipe(h_stderr_rd, nullptr, 0, nullptr, &avail_err, nullptr);

        if (avail_out > 0) { drain(h_stdout_rd); any_data = true; }
        if (avail_err > 0) { drain(h_stderr_rd); any_data = true; }
        if (output.size() >= MAX_OUTPUT) break;

        if (!any_data) {
            if (WaitForSingleObject(pi.hProcess, 50) == WAIT_OBJECT_0) {
                while (true) {
                    DWORD a_out = 0, a_err = 0;
                    PeekNamedPipe(h_stdout_rd, nullptr, 0, nullptr, &a_out, nullptr);
                    PeekNamedPipe(h_stderr_rd, nullptr, 0, nullptr, &a_err, nullptr);
                    if (a_out == 0 && a_err == 0) break;
                    if (a_out > 0) drain(h_stdout_rd);
                    if (a_err > 0) drain(h_stderr_rd);
                    if (output.size() >= MAX_OUTPUT) break;
                }
                break;
            }
        }
    }

    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);

    CloseHandle(h_stdout_rd);
    CloseHandle(h_stderr_rd);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    mcp_standalone::downstream::governor_t::instance().release(bg_downstream_token, "sync_complete");


    output_log::push(bottom_tab_t::sandbox_log,
        "[run_command] exit=" + std::to_string(exit_code) +
        (cancelled ? " (CANCELLED)" : (timed_out ? " (TIMED OUT)" : "")));

    if (cancelled)
    {
        diag::log_tagged_fmt("coding", "run_command cancelled cmd='%.120s'", command.c_str());
        return tool_result_t::error("Command cancelled by client request.");
    }

    diag::log_tagged_fmt("coding", "run_command finished exit=%lu timed_out=%d cmd='%.120s'",
        exit_code, (int)timed_out, command.c_str());
    std::string result;
    result += "Exit code: " + std::to_string(exit_code);
    if (timed_out)
        result += " (timed out after " + std::to_string(timeout_ms) + "ms)";
    result += "\n";
    if (!output.empty()) {
        if (output.size() >= MAX_OUTPUT)
            result += "(output truncated to " + std::to_string(MAX_OUTPUT) + " bytes)\n";
        result += output;
    } else {
        result += "(no output)";
    }

    return tool_result_t::ok(result);
}


static tool_result_t tool_cancel_command(const json& params)
{
    diag::log_tagged_fmt("coding", "cancel_command entry session_id='%s'",
        params.contains("session_id") && params["session_id"].is_string()
            ? params["session_id"].get<std::string>().c_str() : "");
    if (!params.contains("session_id") || !params["session_id"].is_string())
    {
        diag::log_tagged_fmt("coding", "cancel_command missing session_id");
        return tool_result_t::error("Missing required parameter: session_id");
    }

    std::string session_id = params["session_id"].get<std::string>();
    if (session_id.empty())
    {
        diag::log_tagged_fmt("coding", "cancel_command empty session_id");
        return tool_result_t::error("session_id cannot be empty.");
    }

    bool was_running = false;
    bool reader_done = false;
    bool terminate_attempted = false;
    bool terminate_ok = false;
    DWORD terminate_error = 0;
    bool found = command_sessions::with_session(session_id,
        [&](command_sessions::command_session_t& sess) {
            was_running = sess.alive.load();
            reader_done = sess.reader_done.load(std::memory_order_acquire);
            sess.alive.store(false, std::memory_order_release);
            if (was_running) {
                sess.finished_at = std::chrono::steady_clock::now();
                int64_t prior_exit = sess.exit_code.load(std::memory_order_acquire);
                if (prior_exit < 0)
                    sess.exit_code.store(1, std::memory_order_release);
            }
            if (sess.process_info.hProcess) {
                DWORD code = 0;
                if (GetExitCodeProcess(sess.process_info.hProcess, &code)) {
                    if (code == STILL_ACTIVE) {
                        terminate_attempted = true;
                        if (TerminateProcess(sess.process_info.hProcess, 1)) {
                            terminate_ok = true;
                        } else {
                            terminate_error = GetLastError();
                        }
                    } else if (sess.exit_code.load(std::memory_order_acquire) < 0) {
                        sess.exit_code.store(static_cast<int64_t>(code), std::memory_order_release);
                    }
                } else {
                    terminate_error = GetLastError();
                }
            }
        });

    if (!found)
    {
        diag::log_tagged_fmt("coding", "cancel_command not found session_id='%s'", session_id.c_str());
        return tool_result_t::error("Session not found: " + session_id);
    }

    const ULONGLONG cleanup_start = GetTickCount64();
    uint32_t cleanup_polls = 0;
    while (!reader_done && GetTickCount64() - cleanup_start < 1500) {
        Sleep(10);
        ++cleanup_polls;
        command_sessions::with_session(session_id,
            [&](command_sessions::command_session_t& sess) {
                reader_done = sess.reader_done.load(std::memory_order_acquire);
            });
    }

    bool removed = false;
    if (reader_done)
        removed = command_sessions::remove_session(session_id);

    diag::log_tagged_fmt("coding",
        "cancel_command ok session_id='%s' was_running=%d reader_done=%d removed=%d terminate_attempted=%d terminate_ok=%d terminate_error=%lu cleanup_wait_ms=%llu cleanup_polls=%u",
        session_id.c_str(),
        (int)was_running,
        reader_done ? 1 : 0,
        removed ? 1 : 0,
        terminate_attempted ? 1 : 0,
        terminate_ok ? 1 : 0,
        static_cast<unsigned long>(terminate_error),
        static_cast<unsigned long long>(GetTickCount64() - cleanup_start),
        cleanup_polls);
    output_log::push(bottom_tab_t::sandbox_log,
        "[cancel_command] session=" + session_id +
        (was_running ? " (terminated)" : " (already finished)") +
        (removed ? "" : " (cleanup pending)"));

    json data;
    data["cancelled"] = true;
    data["session_id"] = session_id;
    data["was_running"] = was_running;
    data["reader_done"] = reader_done;
    data["removed"] = removed;
    data["terminate_attempted"] = terminate_attempted;
    data["terminate_error"] = terminate_error;
    return tool_result_t::ok("Cancelled session " + session_id, data);
}


static tool_result_t tool_list_commands(const json& /*params*/)
{
    diag::log_tagged_fmt("coding", "list_commands entry");
    auto ids = command_sessions::list_sessions();
    diag::log_tagged_fmt("coding", "list_commands session_count=%zu", ids.size());

    json sessions = json::array();
    std::string text;
    text += "Sessions: " + std::to_string(ids.size()) + "\n";

    for (const auto& id : ids) {
        json entry;
        std::string sess_id;
        std::string sess_cmd;
        bool running = false;
        int64_t exit_code = 0;
        bool timed_out = false;
        int64_t duration_ms = 0;
        size_t stdout_bytes = 0;
        size_t stderr_bytes = 0;

        bool found = command_sessions::with_session(id,
            [&](command_sessions::command_session_t& sess) {
                sess_id = sess.id;
                sess_cmd = sess.command;
                running = sess.alive.load();
                exit_code = sess.exit_code.load();
                timed_out = sess.timed_out.load();
                auto end = running ? std::chrono::steady_clock::now() : sess.finished_at;
                duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    end - sess.started_at).count();
                std::lock_guard<std::mutex> lk(sess.output_mutex);
                stdout_bytes = sess.stdout_buf.size();
                stderr_bytes = sess.stderr_buf.size();
            });

        if (!found) continue;

        entry["id"] = sess_id;
        entry["command"] = sess_cmd;
        entry["running"] = running;
        entry["exit_code"] = running ? json(nullptr) : json(exit_code);
        entry["timed_out"] = timed_out;
        entry["duration_ms"] = duration_ms;
        entry["lines_buffered"] = static_cast<int64_t>(stdout_bytes + stderr_bytes);
        entry["stdout_bytes"] = static_cast<int64_t>(stdout_bytes);
        entry["stderr_bytes"] = static_cast<int64_t>(stderr_bytes);
        sessions.push_back(entry);

        text += "  " + sess_id + " | " +
            (running ? "running" : ("exit=" + std::to_string(exit_code))) +
            " | " + std::to_string(duration_ms) + "ms" +
            " | " + sess_cmd + "\n";
    }

    if (ids.empty())
        text += "(no active sessions)";

    json data;
    data["sessions"] = sessions;
    return tool_result_t::ok(text, data);
}


void register_coding_tools(mcp_standalone::server_t& srv)
{
    diag::log_tagged_fmt("coding", "register_coding_tools entry");
    using p = mcp_standalone::tool_param_t;

    srv.register_tool({
        "read_file",
        "Read the contents of a file. Returns contents with line numbers. "
        "Supports optional line range (start_line / end_line, 1-indexed). "
        "Maximum file size: 2MB.",
        {
            {"path",       "string", "Absolute or workspace-relative path to the file.", true},
            {"start_line", "integer", "Starting line number (1-indexed, inclusive). Optional.", false},
            {"end_line",   "integer", "Ending line number (1-indexed, inclusive). Optional.", false},
        },
        true,
        tool_read_file,
        mcp_standalone::tool_visibility_t::internal_only
    });

    srv.register_tool({
        "write_file",
        "Create or overwrite a file with the given content. "
        "Parent directories will be created automatically. "
        "If the file is open in the editor, it will be synced.",
        {
            {"path",    "string", "Absolute or workspace-relative path.", true},
            {"content", "string", "Complete file content to write.", true},
        },
        false,
        tool_write_file,
        mcp_standalone::tool_visibility_t::internal_only
    });

    srv.register_tool({
        "edit_file",
        "Edit a file by replacing an exact text occurrence (str_replace pattern). "
        "old_text must match exactly one location in the file. Include enough context "
        "(3-5 surrounding lines) to ensure uniqueness.",
        {
            {"path",     "string", "Absolute or workspace-relative path.", true},
            {"old_text", "string", "Exact text to find and replace. Must match exactly once.", true},
            {"new_text", "string", "Replacement text.", true},
        },
        false,
        tool_edit_file,
        mcp_standalone::tool_visibility_t::internal_only
    });

    srv.register_tool({
        "list_directory",
        "List files and subdirectories in a directory. Shows names with sizes. "
        "Directories have trailing '/'. If path is omitted, lists the workspace root.",
        {
            {"path", "string", "Directory path. Defaults to workspace root if omitted.", false},
        },
        true,
        tool_list_directory,
        mcp_standalone::tool_visibility_t::internal_only
    });

    srv.register_tool({
        "search_workspace",
        "Search for text in files across the workspace. Returns matching lines with "
        "file paths and line numbers. Supports regex. Case-insensitive by default.",
        {
            {"query",   "string",  "Text or regex pattern to search for.", true},
            {"path",    "string",  "Restrict search to this subdirectory. Optional.", false},
            {"include", "string",  "Only search files matching this name/extension pattern.", false},
            {"exclude", "string",  "Comma-separated directory names to exclude.", false},
            {"regex",   "boolean", "Treat query as ECMAScript regex. Default: false.", false},
        },
        true,
        tool_search_workspace,
        mcp_standalone::tool_visibility_t::internal_only
    });

    srv.register_tool({
        "run_command",
        "Execute a shell command and return its output. Runs via cmd.exe. "
        "Default timeout: 30 seconds. Maximum timeout: 600 seconds. "
        "Stdout and stderr are captured separately, each truncated at 1MB. "
        "Pass wait=false (or supply session_id) to run in the background and "
        "retrieve output later via read_command_output.",
        {
            {"command",    "string",  "Shell command to execute.", true},
            {"timeout_ms", "integer", "Timeout in milliseconds (1000-600000). Default: 30000.", false},
            {"cwd",        "string",  "Working directory. Defaults to workspace root.", false},
            {"wait",       "boolean", "If false, run in the background and return a session id immediately. Default: true.", false},
            {"session_id", "string",  "Optional explicit session id. If omitted while wait=false, one is generated.", false},
        },
        false,
        tool_run_command,
        mcp_standalone::tool_visibility_t::internal_only
    });

    srv.register_tool({
        "cancel_command",
        "Cancel a background command session previously started with run_command (wait=false). "
        "If the child process is still running, it is terminated. The session is then removed "
        "from the registry. Use list_commands to discover active session ids.",
        {
            {"session_id", "string", "The terminal session id returned by run_command.", true},
        },
        false,
        tool_cancel_command,
        mcp_standalone::tool_visibility_t::internal_only
    });

    srv.register_tool({
        "list_commands",
        "List all currently registered background command sessions (running and finished, "
        "until pruned). Returns one entry per session with id, command, running state, "
        "exit code, duration, and buffered output sizes.",
        {},
        true,
        tool_list_commands,
        mcp_standalone::tool_visibility_t::internal_only
    });
    diag::log_tagged_fmt("coding", "register_coding_tools done");
}

}
