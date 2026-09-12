#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef CPPHTTPLIB_OPENSSL_SUPPORT
#define CPPHTTPLIB_OPENSSL_SUPPORT
#endif
#include <windows.h>
#include <shlobj.h>

#include "mcp_marketplace.hpp"
#include "../infra/executor.hpp"
#include "mcp_client.hpp"
#include "standalone_settings.hpp"
#include "../settings/settings_persistence_service.hpp"
#include "../helpers/globals.h"
#include "../../helpers/diag_log.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <QElapsedTimer>
#include <QFileInfo>
#include <QProcess>
#include <QStandardPaths>
#include <QString>
#include <QStringList>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <functional>
#include <utility>

extern mcp_client::manager_t s_mcp_client_mgr;

namespace mcp_marketplace
{

using json = nlohmann::json;


static std::mutex               s_mtx;
static std::vector<package_info_t>  s_results;
static search_state_t           s_search_state = search_state_t::idle;
static std::string              s_search_error;

static install_state_t          s_install_state = install_state_t::idle;
static std::string              s_install_error;

static bool submit_marketplace_task(const char* label, std::function<void()> body)
{
    aida::infra::executor::submission_t sub;
    sub.owner_subsystem = "mcp_marketplace";
    sub.label = label;
    sub.thread_class = "bounded_task";
    sub.domain = aida::infra::executor::domain_t::external_tool;
    sub.priority = 3;
    sub.body = std::move(body);
    return aida::infra::executor::submit(std::move(sub)).submitted;
}

static std::mutex               s_installed_mtx;
static std::vector<installed_server_t> s_installed;

static std::atomic<bool>        s_shutdown{false};

struct deferred_log_entry_t
{
    bottom_tab_t tab;
    std::string  line;
};

static std::mutex                          s_deferred_mtx;
static std::vector<deferred_log_entry_t>   s_deferred_logs;
static std::atomic<bool>                   s_persisted_load_initialized{false};
static install_state_t                     s_last_observed_install_state = install_state_t::idle;
static std::atomic<bool>                   s_install_persist_pending{false};

static void enqueue_deferred_log(bottom_tab_t tab, std::string line)
{
    std::lock_guard<std::mutex> lk(s_deferred_mtx);
    if (s_deferred_logs.size() >= 1024)
        s_deferred_logs.erase(s_deferred_logs.begin());
    s_deferred_logs.push_back({tab, std::move(line)});
}


static std::filesystem::path marketplace_dir()
{
    wchar_t* appdata = nullptr;
    std::filesystem::path base;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata))) {
        base = std::filesystem::path(appdata) / L"AiDA" / L"Standalone" / L"marketplace";
        CoTaskMemFree(appdata);
    } else {
        base = std::filesystem::current_path() / "aida_marketplace";
    }
    std::error_code ec;
    std::filesystem::create_directories(base, ec);
    return base;
}


std::string registry_label(registry_t reg)
{
    return reg == registry_t::pypi ? "PyPI" : "npm";
}


std::string install_root()
{
    return marketplace_dir().string();
}


static bool safe_for_shell_identifier(const std::string& s)
{
    for (unsigned char c : s) {
        const bool ok = (c >= '0' && c <= '9')
                     || (c >= 'A' && c <= 'Z')
                     || (c >= 'a' && c <= 'z')
                     || c == '-' || c == '_' || c == '.'
                     || c == '/' || c == '@';
        if (!ok) return false;
    }
    return !s.empty();
}


static std::string make_safe_package_dir_name(const std::string& name)
{
    std::string safe_name;
    safe_name.reserve(name.size());
    for (char c : name) {
        const unsigned char uc = static_cast<unsigned char>(c);
        const bool keep = (uc >= '0' && uc <= '9')
                       || (uc >= 'A' && uc <= 'Z')
                       || (uc >= 'a' && uc <= 'z')
                       || uc == '-'
                       || uc == '_'
                       || uc == '.';
        safe_name.push_back(keep ? static_cast<char>(uc) : '_');
    }
    while (!safe_name.empty() && safe_name.front() == '.') safe_name.erase(safe_name.begin());
    return safe_name;
}


static bool is_child_path(const std::filesystem::path& root, const std::filesystem::path& child)
{
    const std::string root_str = root.lexically_normal().string();
    const std::string child_str = child.lexically_normal().string();
    if (root_str.empty() || child_str.size() < root_str.size())
        return false;
    if (child_str.compare(0, root_str.size(), root_str) != 0)
        return false;
    if (child_str.size() == root_str.size())
        return true;
    const char sep = child_str[root_str.size()];
    return sep == '\\' || sep == '/';
}


static bool resolve_install_path(const std::string& name, std::filesystem::path& out, std::string& error)
{
    std::string safe_name = make_safe_package_dir_name(name);
    if (safe_name.empty() || safe_name == "." || safe_name == "..") {
        error = "Refusing to install package with unsafe name: " + name;
        return false;
    }

    auto dir = marketplace_dir();
    std::error_code can_ec;
    auto root = std::filesystem::weakly_canonical(dir, can_ec);
    if (can_ec) root = dir;
    auto pkg_path = std::filesystem::weakly_canonical(dir / safe_name, can_ec);
    if (can_ec) pkg_path = dir / safe_name;

    if (!is_child_path(root, pkg_path)) {
        error = "Refusing to install outside marketplace directory: " + name;
        return false;
    }

    out = std::move(pkg_path);
    return true;
}


static installed_server_t make_install_preview(const package_info_t& p, const std::string& pkg_dir)
{
    installed_server_t srv;
    srv.package_name = p.name;
    srv.version = p.version;
    srv.registry = p.registry;
    srv.install_path = pkg_dir;
    srv.transport = "stdio";
    srv.enabled = false;
    srv.auto_connect = false;
    if (p.registry == registry_t::npm) {
        srv.command = "cmd.exe";
        srv.args = {"/c", "npx", "-y", p.name};
    } else {
        std::string venv_dir = pkg_dir + "\\venv";
        srv.command = venv_dir + "\\Scripts\\python.exe";
        srv.args = {"-m", p.name};
    }
    return srv;
}


installed_server_t preview_install(const package_info_t& pkg)
{
    std::filesystem::path path;
    std::string error;
    if (!resolve_install_path(pkg.name, path, error)) {
        installed_server_t srv;
        srv.package_name = pkg.name;
        srv.version = pkg.version;
        srv.registry = pkg.registry;
        srv.install_path = marketplace_dir().string();
        return srv;
    }
    return make_install_preview(pkg, path.string());
}


static std::string quote_display_arg(const std::string& arg)
{
    if (arg.empty())
        return "\"\"";
    bool needs_quote = false;
    for (char c : arg) {
        if (c == ' ' || c == '\t' || c == '"' || c == '\'') {
            needs_quote = true;
            break;
        }
    }
    if (!needs_quote)
        return arg;
    std::string out = "\"";
    for (char c : arg) {
        if (c == '"')
            out += "\\\"";
        else
            out.push_back(c);
    }
    out.push_back('"');
    return out;
}


std::string launch_command_preview(const installed_server_t& srv)
{
    std::string out = quote_display_arg(srv.command);
    for (const auto& arg : srv.args) {
        out.push_back(' ');
        out += quote_display_arg(arg);
    }
    return out;
}


static install_output_hook_t s_install_output_hook;
static std::mutex              s_install_output_mtx;

void set_install_output_hook(install_output_hook_t hook)
{
    std::lock_guard<std::mutex> lk(s_install_output_mtx);
    s_install_output_hook = std::move(hook);
}

static void emit_install_output(const std::string& line)
{
    install_output_hook_t hook;
    {
        std::lock_guard<std::mutex> lk(s_install_output_mtx);
        hook = s_install_output_hook;
    }
    if (hook)
        hook(line);
}

static void feed_install_output_line(std::string& pending, const char* data, qsizetype size)
{
    for (qsizetype i = 0; i < size; ++i) {
        const char c = data[i];
        if (c == '\n') {
            while (!pending.empty() && pending.back() == '\r')
                pending.pop_back();
            emit_install_output(pending);
            pending.clear();
        } else {
            pending.push_back(c);
        }
    }
}

static std::string run_process_capture(const QString& program,
                                       const QStringList& args,
                                       const std::string& working_dir,
                                       int timeout_ms = 60000,
                                       int* out_exit_code = nullptr)
{
    std::string output;
    std::string pending_line;
    QProcess process;
    if (!working_dir.empty())
        process.setWorkingDirectory(QString::fromStdString(working_dir));
    process.setProcessChannelMode(QProcess::SeparateChannels);
    diag::log_tagged_fmt("mcp_market", "install_spawn program='%s' argc=%d",
        program.toStdString().c_str(), static_cast<int>(args.size()));
    process.start(program, args);
    if (!process.waitForStarted(10000)) {
        const std::string err = "Failed to start " + program.toStdString() + ": "
            + process.errorString().toStdString();
        emit_install_output(err);
        return err;
    }
    QElapsedTimer timer;
    timer.start();
    bool terminated = false;
    while (true) {
        if (timer.elapsed() > timeout_ms) {
            process.terminate();
            if (!process.waitForFinished(3000)) {
                process.kill();
                process.waitForFinished(1000);
            }
            terminated = true;
        }
        bool progressed = false;
        if (process.waitForReadyRead(50)) {
            const QByteArray out = process.readAllStandardOutput();
            const QByteArray err = process.readAllStandardError();
            if (!out.isEmpty()) {
                output.append(out.constData(), static_cast<size_t>(out.size()));
                feed_install_output_line(pending_line, out.constData(), out.size());
                progressed = true;
            }
            if (!err.isEmpty()) {
                output.append(err.constData(), static_cast<size_t>(err.size()));
                feed_install_output_line(pending_line, err.constData(), err.size());
                progressed = true;
            }
        }
        if (process.state() == QProcess::NotRunning && !progressed)
            break;
        if (process.state() == QProcess::NotRunning) {
            const QByteArray out = process.readAllStandardOutput();
            const QByteArray err = process.readAllStandardError();
            if (!out.isEmpty()) {
                output.append(out.constData(), static_cast<size_t>(out.size()));
                feed_install_output_line(pending_line, out.constData(), out.size());
            }
            if (!err.isEmpty()) {
                output.append(err.constData(), static_cast<size_t>(err.size()));
                feed_install_output_line(pending_line, err.constData(), err.size());
            }
            break;
        }
    }
    if (!pending_line.empty()) {
        emit_install_output(pending_line);
        pending_line.clear();
    }
    if (terminated)
        emit_install_output("Process timed out and was terminated");
    int exit_code = terminated ? -1 : process.exitCode();
    if (out_exit_code) *out_exit_code = exit_code;
    diag::log_tagged_fmt("mcp_market", "install_spawn_exit program='%s' code=%d timeout=%d",
        program.toStdString().c_str(), exit_code, terminated ? 1 : 0);
    return output;
}


static std::vector<package_info_t> search_npm(const std::string& query, std::string& err_out)
{
    std::vector<package_info_t> results;
    err_out.clear();

    httplib::Client cli("https://registry.npmjs.org");
    cli.set_connection_timeout(10);
    cli.set_read_timeout(15);


    std::string search_term = query;
    if (search_term.find("mcp") == std::string::npos)
        search_term = "mcp " + search_term;

    std::string path = "/-/v1/search?text=" + httplib::detail::encode_url(search_term)
                     + "+keywords:mcp&size=30";

    auto res = cli.Get(path);
    if (!res) {
        err_out = "registry.npmjs.org unreachable: " + httplib::to_string(res.error());
        return results;
    }
    if (res->status != 200) {
        err_out = "registry.npmjs.org returned HTTP " + std::to_string(res->status);
        return results;
    }

    auto j = json::parse(res->body, nullptr, false);
    if (j.is_discarded() || !j.contains("objects")) {
        err_out = "registry.npmjs.org returned malformed JSON";
        return results;
    }

    for (auto& obj : j["objects"]) {
        if (!obj.contains("package")) continue;
        auto& pkg = obj["package"];

        package_info_t info;
        info.name = pkg.value("name", "");
        info.description = pkg.value("description", "");
        info.version = pkg.value("version", "");
        info.registry = registry_t::npm;

        if (pkg.contains("author") && pkg["author"].is_object())
            info.author = pkg["author"].value("name", "");

        if (pkg.contains("links")) {
            info.homepage = pkg["links"].value("homepage", "");
            info.repository = pkg["links"].value("repository", "");
        }


        if (obj.contains("score") && obj["score"].contains("detail")) {
            auto pop = obj["score"]["detail"].value("popularity", 0.0);
            info.weekly_downloads = static_cast<int64_t>(pop * 100000);
        }

        if (pkg.contains("keywords") && pkg["keywords"].is_array()) {
            std::string kw;
            for (auto& k : pkg["keywords"]) {
                if (!k.is_string()) continue;
                if (!kw.empty()) kw += ", ";
                kw += k.get<std::string>();
            }
            info.keywords_str = kw;
        }


        info.display_name = info.name;
        auto slash = info.display_name.rfind('/');
        if (slash != std::string::npos)
            info.display_name = info.display_name.substr(slash + 1);

        for (const char* prefix : {"server-", "mcp-server-", "mcp-"}) {
            if (info.display_name.find(prefix) == 0) {
                info.display_name = info.display_name.substr(strlen(prefix));
                break;
            }
        }

        if (!info.display_name.empty())
            info.display_name[0] = static_cast<char>(
                std::toupper(static_cast<unsigned char>(info.display_name[0])));

        if (!info.name.empty())
            results.push_back(std::move(info));
    }

    return results;
}


static std::vector<package_info_t> search_pypi(const std::string& query, std::string& err_out)
{
    std::vector<package_info_t> results;
    err_out.clear();
    bool any_transport_ok = false;

    httplib::Client cli("https://pypi.org");
    cli.set_connection_timeout(10);
    cli.set_read_timeout(15);


    std::string search_term = query;
    if (search_term.find("mcp") == std::string::npos)
        search_term = "mcp " + search_term;

    std::string path = "/pypi/" + httplib::detail::encode_url(search_term) + "/json";


    auto res = cli.Get(path);
    if (res) any_transport_ok = true;
    if (res && res->status == 200) {
        auto j = json::parse(res->body, nullptr, false);
        if (!j.is_discarded() && j.contains("info")) {
            auto& info_obj = j["info"];
            package_info_t info;
            info.name = info_obj.value("name", "");
            info.description = info_obj.value("summary", "");
            info.version = info_obj.value("version", "");
            info.author = info_obj.value("author", "");
            info.license = info_obj.value("license", "");
            info.homepage = info_obj.value("home_page", "");
            info.registry = registry_t::pypi;
            info.display_name = info.name;
            if (!info.name.empty())
                results.push_back(std::move(info));
        }
    }


    static const char* mcp_pypi_prefixes[] = {
        "mcp-server-", "mcp-", "modelcontextprotocol-"
    };

    for (const char* prefix : mcp_pypi_prefixes) {
        std::string pkg_name = std::string(prefix) + query;
        std::string pkg_path = "/pypi/" + httplib::detail::encode_url(pkg_name) + "/json";
        auto pkg_res = cli.Get(pkg_path);
        if (pkg_res) any_transport_ok = true;
        if (!pkg_res || pkg_res->status != 200) continue;

        auto j = json::parse(pkg_res->body, nullptr, false);
        if (j.is_discarded() || !j.contains("info")) continue;

        auto& info_obj = j["info"];
        package_info_t info;
        info.name = info_obj.value("name", "");
        info.description = info_obj.value("summary", "");
        info.version = info_obj.value("version", "");
        info.author = info_obj.value("author", "");
        info.license = info_obj.value("license", "");
        info.homepage = info_obj.value("home_page", "");
        info.registry = registry_t::pypi;
        info.display_name = info.name;


        bool dup = false;
        for (auto& r : results)
            if (r.name == info.name) { dup = true; break; }
        if (!dup && !info.name.empty())
            results.push_back(std::move(info));
    }

    if (!any_transport_ok)
        err_out = "pypi.org unreachable";
    return results;
}


void search_async(const std::string& query, registry_t reg)
{
    diag::log_tagged_fmt("mcp_market", "search_async query='%.80s' reg=%d",
        query.c_str(), (int)reg);

    {
        std::lock_guard<std::mutex> lk(s_mtx);
        s_search_state = search_state_t::searching;
        s_search_error.clear();
        s_results.clear();
    }

    std::string q = query;
    const bool posted = submit_marketplace_task("mcp_marketplace.search", [q, reg]() {
        std::vector<package_info_t> results;
        std::string err;
        try {
            if (reg == registry_t::npm)
                results = search_npm(q, err);
            else
                results = search_pypi(q, err);
        } catch (...) {
            std::lock_guard<std::mutex> lk(s_mtx);
            s_search_state = search_state_t::error_state;
            s_search_error = "Search failed with an exception.";
            return;
        }


        {
            std::lock_guard<std::mutex> lk2(s_installed_mtx);
            for (auto& r : results) {
                for (auto& inst : s_installed) {
                    if (inst.package_name == r.name) {
                        r.is_installed = true;
                        break;
                    }
                }
            }
        }

        std::lock_guard<std::mutex> lk(s_mtx);
        s_results = std::move(results);
        if (s_results.empty() && !err.empty()) {
            diag::log_tagged_fmt("mcp_market", "search_async error err='%s'", err.c_str());
            s_search_state = search_state_t::error_state;
            s_search_error = err;
        } else {
            diag::log_tagged_fmt("mcp_market", "search_async done results=%zu", s_results.size());
            s_search_state = search_state_t::done;
            s_search_error.clear();
        }
    });
    if (!posted) {
        std::lock_guard<std::mutex> lk(s_mtx);
        s_search_state = search_state_t::error_state;
        s_search_error = "Failed to schedule marketplace search.";
    }
}


search_state_t get_search_state()
{
    std::lock_guard<std::mutex> lk(s_mtx);
    return s_search_state;
}

std::string get_search_error()
{
    std::lock_guard<std::mutex> lk(s_mtx);
    return s_search_error;
}

std::vector<package_info_t> get_search_results()
{
    std::lock_guard<std::mutex> lk(s_mtx);
    return s_results;
}


void install_async(const package_info_t& pkg)
{
    diag::log_tagged_fmt("mcp_market", "install_async pkg='%s' version='%s'",
        pkg.name.c_str(), pkg.version.c_str());

    {
        std::lock_guard<std::mutex> lk(s_mtx);
        s_install_state = install_state_t::installing;
        s_install_error.clear();
    }

    package_info_t p = pkg;
    const bool posted = submit_marketplace_task("mcp_marketplace.install", [p]() {
        std::filesystem::path pkg_path;
        std::string path_error;
        if (!resolve_install_path(p.name, pkg_path, path_error)) {
            std::lock_guard<std::mutex> lk(s_mtx);
            s_install_state = install_state_t::error_state;
            s_install_error = path_error;
            return;
        }
        std::string pkg_dir = pkg_path.string();

        std::error_code ec;
        std::filesystem::create_directories(pkg_dir, ec);

        std::string output;
        installed_server_t srv = make_install_preview(p, pkg_dir);

        if (!safe_for_shell_identifier(p.name) ||
            (!p.version.empty() && !safe_for_shell_identifier(p.version))) {
            std::lock_guard<std::mutex> lk(s_mtx);
            s_install_state = install_state_t::error_state;
            s_install_error = "Refusing to install package with shell-unsafe identifier: " + p.name;
            return;
        }

        if (p.registry == registry_t::npm) {
            diag::log_tagged_fmt("mcp_market", "install_async npm pkg='%s' dir='%.120s'",
                p.name.c_str(), pkg_dir.c_str());
            std::string spec = p.name + (p.version.empty() ? std::string{} : "@" + p.version);
            const QString node = QStandardPaths::findExecutable(QStringLiteral("node"));
            QString npm_cli;
            if (!node.isEmpty()) {
                const QString node_dir = QFileInfo(node).absolutePath();
                const QString candidate = node_dir
                    + QStringLiteral("/node_modules/npm/bin/npm-cli.js");
                if (QFileInfo::exists(candidate))
                    npm_cli = candidate;
            }
            int npm_exit = -1;
            if (!node.isEmpty() && !npm_cli.isEmpty()) {
                emit_install_output("npm install (node) " + spec);
                output = run_process_capture(node,
                    { npm_cli, QStringLiteral("install"),
                      QStringLiteral("--prefix"), QString::fromStdString(pkg_dir),
                      QString::fromStdString(spec) },
                    pkg_dir, 120000, &npm_exit);
                if (npm_exit != 0) {
                    diag::log_tagged_fmt("mcp_market", "install_async npm_failed pkg='%s' exit=%d", p.name.c_str(), npm_exit);
                    std::lock_guard<std::mutex> lk(s_mtx);
                    s_install_state = install_state_t::error_state;
                    s_install_error = "npm install failed (exit " + std::to_string(npm_exit) + "). Output:\n" + output.substr(0, 500);
                    return;
                }
            } else {
                diag::log_tagged("mcp_market",
                    "install_async npm node/npm-cli resolution failed; using cmd.exe fallback");
                emit_install_output("npm install (cmd.exe) " + spec);
                QProcess process;
                process.setWorkingDirectory(QString::fromStdString(pkg_dir));
                process.setProcessChannelMode(QProcess::SeparateChannels);
                const QString native = QStringLiteral("/c npm install --prefix \"%1\" \"%2\"")
                    .arg(QString::fromStdString(pkg_dir), QString::fromStdString(spec));
                process.setNativeArguments(native);
                process.start(QStringLiteral("cmd.exe"), {});
                if (!process.waitForStarted(10000)) {
                    output = "Failed to start cmd.exe: "
                        + process.errorString().toStdString();
                    emit_install_output(output);
                    npm_exit = -1;
                    diag::log_tagged_fmt("mcp_market", "install_async npm_cmd_start_failed pkg='%s'", p.name.c_str());
                    {
                        std::lock_guard<std::mutex> lk(s_mtx);
                        s_install_state = install_state_t::error_state;
                        s_install_error = output;
                    }
                    return;
                } else {
                    QElapsedTimer timer;
                    timer.start();
                    std::string pending_line;
                    while (true) {
                        if (timer.elapsed() > 120000) {
                            process.terminate();
                            if (!process.waitForFinished(3000)) {
                                process.kill();
                                process.waitForFinished(1000);
                            }
                            break;
                        }
                        bool progressed = false;
                        if (process.waitForReadyRead(50)) {
                            const QByteArray out = process.readAllStandardOutput();
                            const QByteArray err = process.readAllStandardError();
                            if (!out.isEmpty()) {
                                output.append(out.constData(),
                                    static_cast<size_t>(out.size()));
                                feed_install_output_line(pending_line, out.constData(),
                                    out.size());
                                progressed = true;
                            }
                            if (!err.isEmpty()) {
                                output.append(err.constData(),
                                    static_cast<size_t>(err.size()));
                                feed_install_output_line(pending_line, err.constData(),
                                    err.size());
                                progressed = true;
                            }
                        }
                        if (process.state() == QProcess::NotRunning && !progressed)
                            break;
                        if (process.state() == QProcess::NotRunning) {
                            const QByteArray out = process.readAllStandardOutput();
                            const QByteArray err = process.readAllStandardError();
                            if (!out.isEmpty()) {
                                output.append(out.constData(),
                                    static_cast<size_t>(out.size()));
                                feed_install_output_line(pending_line, out.constData(),
                                    out.size());
                            }
                            if (!err.isEmpty()) {
                                output.append(err.constData(),
                                    static_cast<size_t>(err.size()));
                                feed_install_output_line(pending_line, err.constData(),
                                    err.size());
                            }
                            break;
                        }
                    }
                    if (!pending_line.empty())
                        emit_install_output(pending_line);
                    npm_exit = process.exitCode();
                    if (npm_exit != 0) {
                        diag::log_tagged_fmt("mcp_market", "install_async npm_cmd_failed pkg='%s' exit=%d", p.name.c_str(), npm_exit);
                        std::lock_guard<std::mutex> lk(s_mtx);
                        s_install_state = install_state_t::error_state;
                        s_install_error = "npm install failed (exit " + std::to_string(npm_exit) + "). Output:\n" + output.substr(0, 500);
                        return;
                    }
                }
            }
        } else {
            diag::log_tagged_fmt("mcp_market", "install_async pypi pkg='%s' dir='%.120s'",
                p.name.c_str(), pkg_dir.c_str());
            std::string venv_dir = pkg_dir + "\\venv";
            const QString python =
                QStandardPaths::findExecutable(QStringLiteral("python"));
            if (python.isEmpty()) {
                std::lock_guard<std::mutex> lk(s_mtx);
                s_install_state = install_state_t::error_state;
                s_install_error = "python.exe not found on PATH";
                emit_install_output(s_install_error);
                return;
            }
            emit_install_output("python -m venv " + venv_dir);
            int venv_exit = -1;
            run_process_capture(python,
                { QStringLiteral("-m"), QStringLiteral("venv"),
                  QString::fromStdString(venv_dir) },
                pkg_dir, 60000, &venv_exit);
            if (venv_exit != 0) {
                diag::log_tagged_fmt("mcp_market", "install_async venv_failed pkg='%s' exit=%d", p.name.c_str(), venv_exit);
                std::lock_guard<std::mutex> lk(s_mtx);
                s_install_state = install_state_t::error_state;
                s_install_error = "python -m venv failed (exit " + std::to_string(venv_exit) + ")";
                return;
            }

            const QString pip = QString::fromStdString(venv_dir + "\\Scripts\\pip.exe");
            std::string spec = p.version.empty() ? p.name : (p.name + "==" + p.version);
            emit_install_output("pip install " + spec);
            int pip_exit = -1;
            output = run_process_capture(pip,
                { QStringLiteral("install"), QString::fromStdString(spec) },
                pkg_dir, 120000, &pip_exit);
            if (pip_exit != 0) {
                diag::log_tagged_fmt("mcp_market", "install_async pip_failed pkg='%s' exit=%d", p.name.c_str(), pip_exit);
                std::lock_guard<std::mutex> lk(s_mtx);
                s_install_state = install_state_t::error_state;
                s_install_error = "pip install failed (exit " + std::to_string(pip_exit) + "). Output:\n" + output.substr(0, 500);
                return;
            }
        }


        bool success = false;
        if (p.registry == registry_t::npm) {
            std::filesystem::path pkg_node = std::filesystem::path(pkg_dir) / "node_modules" / p.name;
            success = std::filesystem::exists(pkg_node, ec);
            if (!success || ec) {
                ec.clear();
                success = std::filesystem::exists(std::filesystem::path(pkg_dir) / "node_modules", ec);
            }
            if (success && ec) success = false;
        } else {
            success = std::filesystem::exists(pkg_dir + "\\venv\\Scripts\\pip.exe", ec);
            if (success && ec) success = false;
            if (success) {
                bool py_exists = std::filesystem::exists(pkg_dir + "\\venv\\Scripts\\python.exe", ec);
                if (!py_exists || ec) success = false;
            }
        }

        if (!success) {
            diag::log_tagged_fmt("mcp_market", "install_async fail pkg='%s'", p.name.c_str());
            std::lock_guard<std::mutex> lk(s_mtx);
            s_install_state = install_state_t::error_state;
            s_install_error = "Install failed. Output:\n" + output.substr(0, 500);
            return;
        }
        diag::log_tagged_fmt("mcp_market", "install_async ok pkg='%s'", p.name.c_str());


        {
            std::lock_guard<std::mutex> lk(s_installed_mtx);

            s_installed.erase(
                std::remove_if(s_installed.begin(), s_installed.end(),
                    [&](const installed_server_t& s) { return s.package_name == p.name; }),
                s_installed.end());
            s_installed.push_back(srv);
        }

        {
            std::lock_guard<std::mutex> lk(s_mtx);
            s_install_state = install_state_t::done;
        }

        s_install_persist_pending.store(true, std::memory_order_release);

        enqueue_deferred_log(bottom_tab_t::output,
            "[marketplace] Installed disabled server " + p.name + "@" + p.version);
    });
    if (!posted) {
        std::lock_guard<std::mutex> lk(s_mtx);
        s_install_state = install_state_t::error_state;
        s_install_error = "Failed to schedule marketplace install.";
    }
}


install_state_t get_install_state()
{
    std::lock_guard<std::mutex> lk(s_mtx);
    return s_install_state;
}

std::string get_install_error()
{
    std::lock_guard<std::mutex> lk(s_mtx);
    return s_install_error;
}

std::vector<installed_server_t> get_installed()
{
    std::lock_guard<std::mutex> lk(s_installed_mtx);
    return s_installed;
}


void activate_server(const installed_server_t& srv)
{
    diag::log_tagged_fmt("mcp_market", "activate_server pkg='%s'", srv.package_name.c_str());
    if (!srv.enabled) {
        diag::log_tagged_fmt("mcp_market", "activate_server blocked_disabled pkg='%s'",
            srv.package_name.c_str());
        enqueue_deferred_log(bottom_tab_t::mcp_log,
            "[marketplace] Enable before connecting: " + srv.package_name);
        return;
    }
    mcp_client::server_config_t cfg;
    cfg.name = srv.package_name;
    cfg.transport = (srv.transport == "stdio")
        ? mcp_client::transport_type_t::stdio
        : mcp_client::transport_type_t::http_sse;
    cfg.command = srv.command;
    cfg.args = srv.args;
    cfg.env = srv.env;
    cfg.enabled = srv.enabled;
    cfg.auto_connect = srv.auto_connect;

    ::s_mcp_client_mgr.add_server(cfg);
    ::s_mcp_client_mgr.connect_server(cfg.name);

    diag::log_tagged_fmt("mcp_market", "activate_server ok pkg='%s'", srv.package_name.c_str());
    enqueue_deferred_log(bottom_tab_t::mcp_log,
        "[marketplace] Activated server: " + srv.package_name);
}

void deactivate_server(const std::string& package_name)
{
    diag::log_tagged_fmt("mcp_market", "deactivate_server pkg='%s'", package_name.c_str());
    ::s_mcp_client_mgr.disconnect_server(package_name);
    ::s_mcp_client_mgr.remove_server(package_name);

    diag::log_tagged_fmt("mcp_market", "deactivate_server ok pkg='%s'", package_name.c_str());
    enqueue_deferred_log(bottom_tab_t::mcp_log,
        "[marketplace] Deactivated server: " + package_name);
}


bool set_server_policy(const std::string& package_name, bool enabled, bool auto_connect)
{
    bool changed = false;
    {
        std::lock_guard<std::mutex> lk(s_installed_mtx);
        for (auto& srv : s_installed) {
            if (srv.package_name != package_name)
                continue;
            srv.enabled = enabled;
            srv.auto_connect = enabled && auto_connect;
            changed = true;
            break;
        }
    }

    if (!changed)
        return false;

    if (!enabled) {
        ::s_mcp_client_mgr.disconnect_server(package_name);
        ::s_mcp_client_mgr.remove_server(package_name);
    }

    s_install_persist_pending.store(true, std::memory_order_release);
    diag::log_tagged_fmt("mcp_market", "set_server_policy pkg='%s' enabled=%d auto_connect=%d",
        package_name.c_str(), enabled ? 1 : 0, (enabled && auto_connect) ? 1 : 0);
    enqueue_deferred_log(bottom_tab_t::mcp_log,
        std::string("[marketplace] Policy updated: ") + package_name);
    return true;
}


void load_installed(const std::string& json_str)
{
    if (json_str.empty()) return;
    auto j = json::parse(json_str, nullptr, false);
    if (j.is_discarded() || !j.is_array()) return;

    std::lock_guard<std::mutex> lk(s_installed_mtx);
    s_installed.clear();
    for (auto& item : j) {
        installed_server_t srv;
        srv.package_name = item.value("package_name", "");
        srv.version      = item.value("version", "");
        srv.registry     = item.value("registry", "npm") == "pypi" ? registry_t::pypi : registry_t::npm;
        srv.install_path = item.value("install_path", "");
        srv.transport    = item.value("transport", "stdio");
        srv.command      = item.value("command", "");
        if (item.contains("args") && item["args"].is_array()) {
            for (auto& a : item["args"]) {
                if (a.is_string())
                    srv.args.push_back(a.get<std::string>());
            }
        }
        if (item.contains("env") && item["env"].is_object()) {
            for (auto it2 = item["env"].begin(); it2 != item["env"].end(); ++it2) {
                if (it2.value().is_string())
                    srv.env[it2.key()] = it2.value().get<std::string>();
            }
        }
        srv.enabled      = item.value("enabled", false);
        srv.auto_connect  = srv.enabled && item.value("auto_connect", false);

        if (!srv.package_name.empty())
            s_installed.push_back(std::move(srv));
    }
}


std::string save_installed()
{
    std::lock_guard<std::mutex> lk(s_installed_mtx);
    json arr = json::array();
    for (auto& srv : s_installed) {
        json item = {
            {"package_name", srv.package_name},
            {"version",      srv.version},
            {"registry",     srv.registry == registry_t::pypi ? "pypi" : "npm"},
            {"install_path", srv.install_path},
            {"transport",    srv.transport},
            {"command",      srv.command},
            {"enabled",      srv.enabled},
            {"auto_connect", srv.auto_connect}
        };
        json args_arr = json::array();
        for (auto& a : srv.args) args_arr.push_back(a);
        item["args"] = args_arr;

        json env_obj = json::object();
        for (auto& [k, v] : srv.env) env_obj[k] = v;
        item["env"] = env_obj;

        arr.push_back(std::move(item));
    }
    return arr.dump();
}


void tick()
{
    if (s_shutdown.load(std::memory_order_acquire))
        return;

    bool expected_uninit = false;
    if (s_persisted_load_initialized.compare_exchange_strong(
            expected_uninit, true,
            std::memory_order_acq_rel, std::memory_order_acquire))
    {
        bool need_load = false;
        {
            std::lock_guard<std::mutex> lk(s_installed_mtx);
            need_load = s_installed.empty();
        }
        if (need_load)
        {
            const std::string& cached = g_sa_settings.marketplace_installed_json;
            if (!cached.empty())
                load_installed(cached);
        }
    }

    std::vector<deferred_log_entry_t> drained;
    {
        std::lock_guard<std::mutex> lk(s_deferred_mtx);
        if (!s_deferred_logs.empty())
            drained.swap(s_deferred_logs);
    }
    for (auto& entry : drained)
        output_log::push(entry.tab, entry.line);

    install_state_t cur_install;
    {
        std::lock_guard<std::mutex> lk(s_mtx);
        cur_install = s_install_state;
    }

    bool install_just_finished =
        (s_last_observed_install_state == install_state_t::installing) &&
        (cur_install == install_state_t::done || cur_install == install_state_t::error_state);

    s_last_observed_install_state = cur_install;

    bool persist_now = s_install_persist_pending.exchange(false, std::memory_order_acq_rel);
    if (persist_now || install_just_finished)
    {
        std::string serialized = save_installed();
        if (g_sa_settings.marketplace_installed_json != serialized)
        {
            g_sa_settings.marketplace_installed_json = std::move(serialized);
            static_cast<void>(aida::settings_persistence::request_save(g_sa_settings));
        }
    }
}


void shutdown()
{
    s_shutdown.store(true);
}

}
