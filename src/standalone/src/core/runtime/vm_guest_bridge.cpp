#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "vm_guest_bridge.hpp"
#include "../../helpers/diag_log.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <fstream>
#include <limits>
#include <mutex>
#include <string>
#include <thread>
#include <utility>

namespace fs = std::filesystem;

namespace vm_guest_bridge {
namespace {

std::mutex g_mtx;
active_session_t g_session;
std::atomic<uint64_t> g_request_seq{1};

std::string narrow_utf8(const std::wstring& text) {
	if (text.empty()) return {};
	if (text.size() > static_cast<size_t>((std::numeric_limits<int>::max)())) return {};
	const int length = static_cast<int>(text.size());
	int needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), length, nullptr, 0, nullptr, nullptr);
	if (needed <= 0) return {};
	std::string out(static_cast<size_t>(needed), '\0');
	if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), length, out.data(), needed, nullptr, nullptr) != needed)
		return {};
	return out;
}

std::wstring widen_utf8(const std::string& text) {
	if (text.empty()) return {};
	if (text.size() > static_cast<size_t>((std::numeric_limits<int>::max)())) return {};
	const int length = static_cast<int>(text.size());
	int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), length, nullptr, 0);
	if (needed <= 0) return {};
	std::wstring out(static_cast<size_t>(needed), L'\0');
	if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), length, out.data(), needed) != needed)
		return {};
	return out;
}

uint64_t now_ms() {
	return static_cast<uint64_t>(GetTickCount64());
}

std::string path_utf8(const fs::path& path) {
	return narrow_utf8(path.wstring());
}

bool exists_clean(const fs::path& path, std::string* error_out = nullptr) {
	std::error_code ec;
	const bool exists = fs::exists(path, ec);
	if (error_out) *error_out = ec ? ec.message() : std::string();
	return !ec && exists;
}

uint32_t count_json_files(const fs::path& dir, std::string* error_out = nullptr) {
	std::error_code ec;
	if (!fs::exists(dir, ec)) {
		if (error_out) *error_out = ec ? ec.message() : "missing";
		return 0;
	}
	uint32_t count = 0;
	for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) {
		std::error_code type_ec;
		if (it->is_regular_file(type_ec) && it->path().extension() == L".json")
			++count;
	}
	if (error_out) *error_out = ec ? ec.message() : std::string();
	return count;
}

bool json_bool_field(const nlohmann::json& value, const char* key, bool fallback) {
	if (!value.is_object())
		return fallback;
	auto it = value.find(key);
	if (it == value.end())
		return fallback;
	if (it->is_boolean())
		return it->get<bool>();
	if (it->is_number_unsigned())
		return it->get<uint64_t>() != 0;
	if (it->is_number_integer())
		return it->get<int64_t>() != 0;
	return fallback;
}

std::string json_string_field(const nlohmann::json& value, const char* key, const std::string& fallback) {
	if (!value.is_object())
		return fallback;
	auto it = value.find(key);
	if (it == value.end() || !it->is_string())
		return fallback;
	return it->get<std::string>();
}

void log_request_state(const char* phase,
                       const active_session_t& session,
                       const std::string& command,
                       const std::string& id,
                       const fs::path& request_path,
                       const fs::path& response_path,
                       uint32_t timeout_ms,
                       uint64_t elapsed_ms,
                       const std::string& detail) {
	const fs::path bridge = session.bridge_dir;
	const fs::path requests = bridge / L"requests";
	const fs::path responses = bridge / L"responses";
	std::string bridge_error;
	std::string requests_error;
	std::string responses_error;
	std::string request_file_error;
	std::string response_file_error;
	const bool bridge_exists = exists_clean(bridge, &bridge_error);
	const bool requests_exists = exists_clean(requests, &requests_error);
	const bool responses_exists = exists_clean(responses, &responses_error);
	const bool request_file_exists = exists_clean(request_path, &request_file_error);
	const bool response_file_exists = exists_clean(response_path, &response_file_error);
	std::string pending_requests_error;
	std::string pending_responses_error;
	const uint32_t pending_requests = count_json_files(requests, &pending_requests_error);
	const uint32_t pending_responses = count_json_files(responses, &pending_responses_error);
	const uint64_t age_ms = session.started_ms != 0 && now_ms() >= session.started_ms ? now_ms() - session.started_ms : 0;
	diag::log_tagged_fmt("vm_guest_bridge",
		"%s id='%s' command='%s' timeout_ms=%u elapsed_ms=%llu session_age_ms=%llu bridge='%s' requests='%s' responses='%s' request_path='%s' response_path='%s' bridge_exists=%d requests_exists=%d responses_exists=%d request_file_exists=%d response_file_exists=%d pending_requests=%u pending_responses=%u bridge_error='%s' requests_error='%s' responses_error='%s' request_file_error='%s' response_file_error='%s' pending_requests_error='%s' pending_responses_error='%s' detail='%s'",
		phase ? phase : "request_state",
		id.c_str(),
		command.c_str(),
		static_cast<unsigned>(timeout_ms),
		static_cast<unsigned long long>(elapsed_ms),
		static_cast<unsigned long long>(age_ms),
		path_utf8(bridge).c_str(),
		path_utf8(requests).c_str(),
		path_utf8(responses).c_str(),
		path_utf8(request_path).c_str(),
		path_utf8(response_path).c_str(),
		bridge_exists ? 1 : 0,
		requests_exists ? 1 : 0,
		responses_exists ? 1 : 0,
		request_file_exists ? 1 : 0,
		response_file_exists ? 1 : 0,
		static_cast<unsigned>(pending_requests),
		static_cast<unsigned>(pending_responses),
		bridge_error.c_str(),
		requests_error.c_str(),
		responses_error.c_str(),
		request_file_error.c_str(),
		response_file_error.c_str(),
		pending_requests_error.c_str(),
		pending_responses_error.c_str(),
		detail.c_str());
}

bool write_text_file(const fs::path& path, const std::string& text) {
	std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
	if (!ofs.is_open()) return false;
	ofs.write(text.data(), static_cast<std::streamsize>(text.size()));
	return ofs.good();
}

bool write_json_atomic(const fs::path& path, const nlohmann::json& value) {
	std::error_code ec;
	fs::create_directories(path.parent_path(), ec);
	const fs::path tmp = path.wstring() + L".tmp";
	if (!write_text_file(tmp, value.dump(2))) return false;
	fs::rename(tmp, path, ec);
	if (!ec) return true;
	ec.clear();
	fs::remove(path, ec);
	ec.clear();
	fs::rename(tmp, path, ec);
	return !ec;
}

bool ensure_bridge_layout(const fs::path& bridge, std::string* error_out) {
	if (bridge.empty()) {
		if (error_out) *error_out = "bridge directory is empty";
		return false;
	}
	std::error_code ec;
	fs::create_directories(bridge, ec);
	if (ec) {
		if (error_out) *error_out = "failed to create bridge directory: " + ec.message();
		return false;
	}
	ec.clear();
	fs::create_directories(bridge / L"requests", ec);
	if (ec) {
		if (error_out) *error_out = "failed to create bridge requests directory: " + ec.message();
		return false;
	}
	ec.clear();
	fs::create_directories(bridge / L"responses", ec);
	if (ec) {
		if (error_out) *error_out = "failed to create bridge responses directory: " + ec.message();
		return false;
	}
	ec.clear();
	fs::create_directories(bridge / L"artifacts", ec);
	if (ec) {
		if (error_out) *error_out = "failed to create bridge artifacts directory: " + ec.message();
		return false;
	}
	return true;
}

bool read_json_limited(const fs::path& path, nlohmann::json& out, std::string* error_out) {
	std::error_code ec;
	uintmax_t size = fs::file_size(path, ec);
	if (ec) {
		if (error_out) *error_out = "response file is unavailable: " + ec.message();
		return false;
	}
	if (size > 10u * 1024u * 1024u) {
		if (error_out) *error_out = "guest response exceeded 10 MiB";
		return false;
	}
	std::ifstream ifs(path, std::ios::binary);
	if (!ifs.is_open()) {
		if (error_out) *error_out = "failed to open guest response";
		return false;
	}
	std::string text(static_cast<size_t>(size), '\0');
	if (size > 0) ifs.read(text.data(), static_cast<std::streamsize>(text.size()));
	try {
		out = nlohmann::json::parse(text);
		return true;
	} catch (const std::exception& e) {
		if (error_out) *error_out = std::string("failed to parse guest response: ") + e.what();
		return false;
	}
}

std::string make_request_id() {
	uint64_t seq = g_request_seq.fetch_add(1, std::memory_order_acq_rel);
	char buf[96];
	std::snprintf(buf, sizeof(buf), "%lu_%llu_%llu",
		static_cast<unsigned long>(GetCurrentProcessId()),
		static_cast<unsigned long long>(GetTickCount64()),
		static_cast<unsigned long long>(seq));
	return std::string(buf);
}

}

void activate(const std::wstring& session_dir, const std::wstring& sample_path) {
	std::string error;
	(void)activate_bridge(session_dir, (fs::path(session_dir) / L"output").wstring(), sample_path, "windows_sandbox", &error);
}

bool activate_bridge(const std::wstring& session_dir,
                     const std::wstring& bridge_dir,
                     const std::wstring& sample_path,
                     const std::string& bridge_kind,
                     std::string* error_out) {
	fs::path bridge(bridge_dir);
	std::string error;
	if (!ensure_bridge_layout(bridge, &error)) {
		if (error_out) *error_out = error;
		diag::log_tagged_fmt("vm_guest_bridge",
			"activate_failed session_dir='%s' bridge_dir='%s' kind='%s' error='%s'",
			narrow_utf8(session_dir).c_str(),
			narrow_utf8(bridge_dir).c_str(),
			bridge_kind.c_str(),
			error.c_str());
		return false;
	}
	std::lock_guard<std::mutex> lk(g_mtx);
	active_session_t next;
	next.active = true;
	next.session_dir = session_dir;
	next.bridge_dir = bridge.wstring();
	next.sample_path = sample_path;
	next.bridge_kind = bridge_kind.empty() ? "custom" : bridge_kind;
	next.started_ms = now_ms();
	g_session = std::move(next);
	diag::log_tagged_fmt("vm_guest_bridge",
		"activated session_dir='%s' bridge_dir='%s' sample='%s' kind='%s'",
		narrow_utf8(g_session.session_dir).c_str(),
		narrow_utf8(g_session.bridge_dir).c_str(),
		narrow_utf8(g_session.sample_path).c_str(),
		g_session.bridge_kind.c_str());
	if (error_out) error_out->clear();
	return true;
}

void deactivate() {
	std::lock_guard<std::mutex> lk(g_mtx);
	if (g_session.active) {
		diag::log_tagged_fmt("vm_guest_bridge",
			"deactivated session_dir='%s'",
			narrow_utf8(g_session.session_dir).c_str());
	}
	g_session = active_session_t{};
}

bool is_active() {
	std::lock_guard<std::mutex> lk(g_mtx);
	return g_session.active;
}

active_session_t current() {
	std::lock_guard<std::mutex> lk(g_mtx);
	return g_session;
}

bool prepare_bridge_directory(const std::wstring& bridge_dir,
                              const std::wstring& guest_sample_path,
                              const std::wstring& guest_args,
                              std::string* error_out) {
	fs::path bridge(bridge_dir);
	std::string error;
	if (!ensure_bridge_layout(bridge, &error)) {
		if (error_out) *error_out = error;
		return false;
	}
	nlohmann::json cfg;
	cfg["sample"] = narrow_utf8(guest_sample_path);
	cfg["args"] = narrow_utf8(guest_args);
	cfg["created_host_ms"] = now_ms();
	cfg["bridge_format"] = 1;
	cfg["agent"] = "AiDAGuestAgent";
	if (!write_json_atomic(bridge / L"launch_config.json", cfg)) {
		if (error_out) *error_out = "failed to write launch_config.json";
		return false;
	}
	if (error_out) error_out->clear();
	return true;
}

nlohmann::json status_snapshot() {
	active_session_t session = current();
	nlohmann::json out;
	out["active"] = session.active;
	out["session_dir"] = narrow_utf8(session.session_dir);
	out["bridge_dir"] = narrow_utf8(session.bridge_dir);
	out["sample_path"] = narrow_utf8(session.sample_path);
	out["bridge_kind"] = session.bridge_kind;
	out["started_ms"] = session.started_ms;
	if (!session.active)
		return out;
	fs::path bridge(session.bridge_dir);
	fs::path requests = bridge / L"requests";
	fs::path responses = bridge / L"responses";
	fs::path artifacts = bridge / L"artifacts";
	std::string bridge_error;
	std::string requests_error;
	std::string responses_error;
	std::string artifacts_error;
	out["bridge_exists"] = exists_clean(bridge, &bridge_error);
	out["requests_exists"] = exists_clean(requests, &requests_error);
	out["responses_exists"] = exists_clean(responses, &responses_error);
	out["artifacts_exists"] = exists_clean(artifacts, &artifacts_error);
	out["pending_requests"] = count_json_files(requests);
	out["pending_responses"] = count_json_files(responses);
	out["bridge_error"] = bridge_error;
	out["requests_error"] = requests_error;
	out["responses_error"] = responses_error;
	out["artifacts_error"] = artifacts_error;
	nlohmann::json guest_status;
	std::string status_error;
	if (read_json_limited(bridge / L"status.json", guest_status, &status_error)) {
		out["guest_status"] = guest_status;
		out["guest_status_available"] = true;
	} else {
		out["guest_status_available"] = false;
		out["guest_status_error"] = status_error;
	}
	return out;
}

nlohmann::json request(const std::string& command,
                       const nlohmann::json& params,
                       uint32_t timeout_ms,
                       std::string* error_out) {
	active_session_t session;
	{
		std::lock_guard<std::mutex> lk(g_mtx);
		session = g_session;
	}
	if (!session.active) {
		if (error_out) *error_out = "no active VM bridge";
		return {};
	}
	if (timeout_ms == 0) timeout_ms = 5000;
	if (timeout_ms > 300000) timeout_ms = 300000;
	fs::path bridge = session.bridge_dir;
	fs::path requests = bridge / L"requests";
	fs::path responses = bridge / L"responses";
	std::error_code requests_ec;
	fs::create_directories(requests, requests_ec);
	std::error_code responses_ec;
	fs::create_directories(responses, responses_ec);
	std::string id = make_request_id();
	nlohmann::json req;
	req["id"] = id;
	req["command"] = command;
	req["params"] = params.is_null() ? nlohmann::json::object() : params;
	req["created_host_ms"] = now_ms();
	fs::path request_path = requests / (widen_utf8(id) + L".json");
	fs::path response_path = responses / (widen_utf8(id) + L".json");
	const uint64_t request_started_ms = now_ms();
	if (requests_ec || responses_ec) {
		std::string detail = "create_directories requests_error='" + requests_ec.message() +
			"' responses_error='" + responses_ec.message() + "'";
		log_request_state("request_dir_create_error", session, command, id, request_path,
			response_path, timeout_ms, 0, detail);
	}
	if (!write_json_atomic(request_path, req)) {
		log_request_state("request_write_failed", session, command, id, request_path,
			response_path, timeout_ms, now_ms() - request_started_ms, "write_json_atomic_failed");
		if (error_out) *error_out = "failed to write guest request id=" + id +
			" path=" + path_utf8(request_path);
		return {};
	}
	diag::log_tagged_fmt("vm_guest_bridge",
		"request_written id='%s' command='%s' timeout_ms=%u request_path='%s' response_path='%s'",
		id.c_str(), command.c_str(), static_cast<unsigned>(timeout_ms),
		path_utf8(request_path).c_str(), path_utf8(response_path).c_str());
	auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
	std::string last_exists_error;
	bool logged_exists_error = false;
	while (std::chrono::steady_clock::now() < deadline) {
		std::error_code exists_ec;
		if (fs::exists(response_path, exists_ec)) {
			nlohmann::json response;
			if (!read_json_limited(response_path, response, error_out)) {
				const std::string detail = error_out ? *error_out : "read_json_limited_failed";
				log_request_state("response_read_failed", session, command, id, request_path,
					response_path, timeout_ms, now_ms() - request_started_ms, detail);
				return {};
			}
			std::error_code remove_ec;
			fs::remove(response_path, remove_ec);
			if (!response.is_object()) {
				const std::string type_name = response.type_name();
				const std::string detail = "response_type=" + type_name;
				log_request_state("response_invalid_type", session, command, id, request_path,
					response_path, timeout_ms, now_ms() - request_started_ms, detail);
				if (error_out) *error_out = "guest response was not a JSON object: " + type_name;
				return {};
			}
			bool ok = json_bool_field(response, "ok", false);
			if (!ok) {
				const std::string guest_error = json_string_field(response, "error", "guest command failed");
				const std::string detail = "guest_error='" + guest_error + "' remove_error='" + remove_ec.message() + "'";
				log_request_state("response_guest_failed", session, command, id, request_path,
					response_path, timeout_ms, now_ms() - request_started_ms, detail);
				if (error_out) *error_out = guest_error;
				return response;
			}
			const std::string detail = "remove_error='" + remove_ec.message() +
				"' data_type='" + (response.contains("data") ? response["data"].type_name() : "missing") + "'";
			log_request_state("response_ok", session, command, id, request_path,
				response_path, timeout_ms, now_ms() - request_started_ms, detail);
			return response;
		}
		if (exists_ec && !logged_exists_error) {
			last_exists_error = exists_ec.message();
			log_request_state("response_exists_error", session, command, id, request_path,
				response_path, timeout_ms, now_ms() - request_started_ms, last_exists_error);
			logged_exists_error = true;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
	}
	const uint64_t elapsed_ms = now_ms() - request_started_ms;
	const std::string detail = last_exists_error.empty()
		? "deadline_expired"
		: "deadline_expired last_exists_error='" + last_exists_error + "'";
	log_request_state("request_timeout", session, command, id, request_path,
		response_path, timeout_ms, elapsed_ms, detail);
	if (error_out) *error_out = "guest agent timed out waiting for command: " + command +
		" id=" + id +
		" elapsed_ms=" + std::to_string(elapsed_ms) +
		" timeout_ms=" + std::to_string(timeout_ms) +
		" bridge_dir=" + path_utf8(bridge) +
		" request_path=" + path_utf8(request_path) +
		" response_path=" + path_utf8(response_path);
	return {};
}

std::string artifact_host_path(const std::string& artifact_name) {
	if (artifact_name.empty()) return {};
	active_session_t session = current();
	if (!session.active) return {};
	fs::path artifact = fs::path(session.bridge_dir) / L"artifacts" / widen_utf8(artifact_name);
	return narrow_utf8(artifact.wstring());
}

}
