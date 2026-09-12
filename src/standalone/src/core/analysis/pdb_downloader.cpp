#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "pdb_downloader.hpp"
#include "../../helpers/diag_log.hpp"
#include "../mcp/downstream_producer_governor.hpp"

#include <windows.h>
#include <winhttp.h>
#include <fcntl.h>
#include <fdi.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <memory>
#include <string>
#include <system_error>
#include <vector>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "cabinet.lib")

namespace pdb_downloader {

namespace {

struct parsed_url_t {
	bool        https = false;
	std::wstring host;
	std::wstring path;
	int         port = 80;
};

bool parse_url(const std::string& url, parsed_url_t& out)
{
	std::string u = url;
	bool https = false;
	if (u.rfind("https://", 0) == 0) {
		https = true;
		u.erase(0, 8);
	} else if (u.rfind("http://", 0) == 0) {
		u.erase(0, 7);
	} else {
		return false;
	}
	int port = https ? 443 : 80;
	auto slash = u.find('/');
	std::string host_part = (slash == std::string::npos) ? u : u.substr(0, slash);
	std::string path_part = (slash == std::string::npos) ? std::string("/") : u.substr(slash);
	auto colon = host_part.find(':');
	if (colon != std::string::npos) {
		std::string port_str = host_part.substr(colon + 1);
		host_part = host_part.substr(0, colon);
		char* end = nullptr;
		long p = std::strtol(port_str.c_str(), &end, 10);
		if (end && *end == '\0' && p > 0 && p < 65536) port = static_cast<int>(p);
	}
	if (path_part.empty()) path_part = "/";

	int hlen = MultiByteToWideChar(CP_UTF8, 0, host_part.c_str(), -1, nullptr, 0);
	int plen = MultiByteToWideChar(CP_UTF8, 0, path_part.c_str(), -1, nullptr, 0);
	if (hlen <= 0 || plen <= 0) return false;
	out.host.assign(hlen - 1, L'\0');
	out.path.assign(plen - 1, L'\0');
	MultiByteToWideChar(CP_UTF8, 0, host_part.c_str(), -1, out.host.data(), hlen);
	MultiByteToWideChar(CP_UTF8, 0, path_part.c_str(), -1, out.path.data(), plen);
	out.https = https;
	out.port = port;
	return true;
}

struct winhttp_handle_t {
	HINTERNET h = nullptr;
	winhttp_handle_t() = default;
	explicit winhttp_handle_t(HINTERNET v) : h(v) {}
	~winhttp_handle_t() { if (h) WinHttpCloseHandle(h); }
	winhttp_handle_t(const winhttp_handle_t&) = delete;
	winhttp_handle_t& operator=(const winhttp_handle_t&) = delete;
	winhttp_handle_t(winhttp_handle_t&& o) noexcept : h(o.h) { o.h = nullptr; }
	winhttp_handle_t& operator=(winhttp_handle_t&& o) noexcept {
		if (this != &o) {
			if (h) WinHttpCloseHandle(h);
			h = o.h;
			o.h = nullptr;
		}
		return *this;
	}
	explicit operator bool() const { return h != nullptr; }
};

struct file_handle_closer_t {
    void operator()(void* value) const noexcept
    {
        if (value && value != INVALID_HANDLE_VALUE)
            CloseHandle(static_cast<HANDLE>(value));
    }
};

using file_handle_t = std::unique_ptr<void, file_handle_closer_t>;

bool http_get_to_file(const std::string& url,
                      const std::filesystem::path& destination,
                      const progress_callback_t& on_progress,
                      const std::atomic<bool>* cancel,
                      std::string& error,
                      uint64_t& out_bytes,
                      int& out_status)
{
	out_bytes = 0;
	out_status = 0;
	diag::log_tagged_fmt("pdb_dl", "http_get_to_file url=%s", url.c_str());

	parsed_url_t pu;
	if (!parse_url(url, pu)) {
		error = "invalid url";
		diag::log_tagged_fmt("pdb_dl", "http_get_to_file failed invalid_url url=%s", url.c_str());
		return false;
	}

	HINTERNET raw_session = WinHttpOpen(L"AiDA/1.0",
		WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);
	if (!raw_session) {
		raw_session = WinHttpOpen(L"AiDA/1.0",
			WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
			WINHTTP_NO_PROXY_BYPASS, 0);
	}
	winhttp_handle_t session(raw_session);
	if (!session) {
		error = "WinHttpOpen err=" + std::to_string(GetLastError());
		return false;
	}

	WinHttpSetTimeouts(session.h, 30000, 30000, 30000, 120000);

	DWORD secure_protocols =
		WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 |
		WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
	WinHttpSetOption(session.h, WINHTTP_OPTION_SECURE_PROTOCOLS,
		&secure_protocols, sizeof(secure_protocols));

	winhttp_handle_t connection(WinHttpConnect(session.h, pu.host.c_str(),
		static_cast<INTERNET_PORT>(pu.port), 0));
	if (!connection) {
		error = "WinHttpConnect err=" + std::to_string(GetLastError());
		return false;
	}

	const DWORD req_flags = pu.https ? WINHTTP_FLAG_SECURE : 0u;
	winhttp_handle_t request_handle(WinHttpOpenRequest(connection.h,
		L"GET", pu.path.c_str(), nullptr, WINHTTP_NO_REFERER,
		WINHTTP_DEFAULT_ACCEPT_TYPES, req_flags));
	if (!request_handle) {
		error = "WinHttpOpenRequest err=" + std::to_string(GetLastError());
		return false;
	}

	const wchar_t* extra_headers = L"User-Agent: Microsoft-Symbol-Server/10.0.0.0\r\n";
	if (!WinHttpSendRequest(request_handle.h, extra_headers,
		static_cast<DWORD>(-1), nullptr, 0, 0, 0)) {
		error = "WinHttpSendRequest err=" + std::to_string(GetLastError());
		return false;
	}

	if (!WinHttpReceiveResponse(request_handle.h, nullptr)) {
		error = "WinHttpReceiveResponse err=" + std::to_string(GetLastError());
		return false;
	}

	DWORD status_code = 0;
	DWORD status_size = sizeof(status_code);
	if (!WinHttpQueryHeaders(request_handle.h,
		WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
		WINHTTP_HEADER_NAME_BY_INDEX, &status_code, &status_size,
		WINHTTP_NO_HEADER_INDEX)) {
		error = "WinHttpQueryHeaders err=" + std::to_string(GetLastError());
		return false;
	}
	out_status = static_cast<int>(status_code);
	diag::log_tagged_fmt("pdb_dl", "http_get_to_file status=%d url=%s", static_cast<int>(status_code), url.c_str());

	if (status_code < 200 || status_code >= 300) {
		error = "http status=" + std::to_string(status_code);
		diag::log_tagged_fmt("pdb_dl", "http_get_to_file failed http_error status=%d url=%s",
			static_cast<int>(status_code), url.c_str());
		return false;
	}

	uint64_t content_length = 0;
	{
		wchar_t cl_buf[64] = {};
		DWORD cl_size = sizeof(cl_buf);
		if (WinHttpQueryHeaders(request_handle.h,
			WINHTTP_QUERY_CONTENT_LENGTH,
			WINHTTP_HEADER_NAME_BY_INDEX, cl_buf, &cl_size,
			WINHTTP_NO_HEADER_INDEX)) {
			wchar_t* end = nullptr;
			unsigned long long v = _wcstoui64(cl_buf, &end, 10);
			if (end && *end == L'\0') content_length = static_cast<uint64_t>(v);
		}
	}

	auto emit_progress = [&](uint64_t recv) {
		if (!on_progress) return;
		progress_t p;
		p.bytes_received = recv;
		p.bytes_total = content_length;
		if (content_length > 0) {
			uint64_t pct = (recv * 100ULL) / content_length;
			p.percent = pct > 100 ? 100 : static_cast<int>(pct);
		}
		on_progress(p);
	};

	emit_progress(0);

	std::error_code ec;
	std::filesystem::create_directories(destination.parent_path(), ec);

    file_handle_t hf(reinterpret_cast<void*>(CreateFileW(destination.c_str(), GENERIC_WRITE, 0, nullptr,
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr)));
    if (!hf) {
        error = "CreateFileW err=" + std::to_string(GetLastError());
        return false;
	}

	bool ok = true;
	uint64_t total = 0;
	uint64_t last_emit = 0;
	std::vector<char> chunk;
	chunk.reserve(64 * 1024);

	for (;;) {
		if (cancel && cancel->load(std::memory_order_acquire)) {
			error = "cancelled";
			ok = false;
			break;
		}
		DWORD available = 0;
		if (!WinHttpQueryDataAvailable(request_handle.h, &available)) {
			error = "WinHttpQueryDataAvailable err=" + std::to_string(GetLastError());
			ok = false;
			break;
		}
		if (available == 0) break;
		if (available > chunk.capacity()) chunk.reserve(available);
		chunk.resize(available);
		DWORD read = 0;
		if (!WinHttpReadData(request_handle.h, chunk.data(), available, &read)) {
			error = "WinHttpReadData err=" + std::to_string(GetLastError());
			ok = false;
			break;
		}
		if (read == 0) break;
		DWORD written = 0;
        if (!WriteFile(static_cast<HANDLE>(hf.get()), chunk.data(), read, &written, nullptr) || written != read) {
			error = "WriteFile err=" + std::to_string(GetLastError());
			ok = false;
			break;
		}
		total += read;
		if (total - last_emit >= 64 * 1024 || (content_length > 0 && total == content_length)) {
			emit_progress(total);
			last_emit = total;
		}
		if (total > 512ULL * 1024ULL * 1024ULL) {
			error = "response too large";
			ok = false;
			break;
		}
	}

    out_bytes = total;
	if (ok) emit_progress(total);
	if (!ok) {
		std::filesystem::remove(destination, ec);
		diag::log_tagged_fmt("pdb_dl", "http_get_to_file failed bytes=%llu err=%s url=%s",
			static_cast<unsigned long long>(total), error.c_str(), url.c_str());
	} else {
		diag::log_tagged_fmt("pdb_dl", "http_get_to_file complete bytes=%llu url=%s",
			static_cast<unsigned long long>(total), url.c_str());
	}
	return ok;
}

INT_PTR DIAMONDAPI fdi_open(LPSTR file, int oflag, int pmode)
{
	(void)pmode;
	DWORD access = (oflag & _O_WRONLY) ? GENERIC_WRITE :
		((oflag & _O_RDWR) ? (GENERIC_READ | GENERIC_WRITE) : GENERIC_READ);
	DWORD share = FILE_SHARE_READ;
	DWORD disp = (oflag & _O_CREAT) ? CREATE_ALWAYS : OPEN_EXISTING;
	HANDLE h = CreateFileA(file, access, share, nullptr, disp, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (h == INVALID_HANDLE_VALUE) return -1;
	return reinterpret_cast<INT_PTR>(h);
}

UINT DIAMONDAPI fdi_read(INT_PTR hf, void* memory, UINT cb)
{
	DWORD read = 0;
	if (!ReadFile(reinterpret_cast<HANDLE>(hf), memory, cb, &read, nullptr))
		return static_cast<UINT>(-1);
	return read;
}

UINT DIAMONDAPI fdi_write(INT_PTR hf, void* memory, UINT cb)
{
	DWORD written = 0;
	if (!WriteFile(reinterpret_cast<HANDLE>(hf), memory, cb, &written, nullptr))
		return static_cast<UINT>(-1);
	return written;
}

int DIAMONDAPI fdi_close(INT_PTR hf)
{
	return CloseHandle(reinterpret_cast<HANDLE>(hf)) ? 0 : -1;
}

long DIAMONDAPI fdi_seek(INT_PTR hf, long dist, int seektype)
{
	DWORD method = FILE_BEGIN;
	if (seektype == SEEK_CUR) method = FILE_CURRENT;
	else if (seektype == SEEK_END) method = FILE_END;
	LONG hi = 0;
	DWORD r = SetFilePointer(reinterpret_cast<HANDLE>(hf), dist, &hi, method);
	if (r == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR) return -1;
	return static_cast<long>(r);
}

FNALLOC(fdi_alloc)
{
	return HeapAlloc(GetProcessHeap(), 0, cb);
}

FNFREE(fdi_free)
{
	HeapFree(GetProcessHeap(), 0, pv);
}

struct fdi_ctx_t {
	std::string target_dir;
	std::string final_path;
	bool        wrote_any = false;
};

INT_PTR DIAMONDAPI fdi_notify(FDINOTIFICATIONTYPE fdint, PFDINOTIFICATION pfdin)
{
	if (fdint == fdintCOPY_FILE) {
		auto* ctx = static_cast<fdi_ctx_t*>(pfdin->pv);
		const std::filesystem::path member_path(pfdin->psz1);
		if (member_path.is_absolute() || member_path.has_root_name())
			return -1;
		for (const auto& component : member_path) {
			if (component == L"..")
				return -1;
		}
		std::filesystem::path target = std::filesystem::path(ctx->target_dir) / member_path;
		std::error_code ec;
		std::filesystem::create_directories(target.parent_path(), ec);
		if (ec)
			return -1;
		HANDLE h = CreateFileA(target.string().c_str(), GENERIC_WRITE, 0, nullptr,
			CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (h == INVALID_HANDLE_VALUE) return -1;
		ctx->final_path = target.string();
		ctx->wrote_any = true;
		return reinterpret_cast<INT_PTR>(h);
	}
	if (fdint == fdintCLOSE_FILE_INFO) {
		CloseHandle(reinterpret_cast<HANDLE>(pfdin->hf));
		return TRUE;
	}
	if (fdint == fdintNEXT_CABINET || fdint == fdintCABINET_INFO ||
	    fdint == fdintENUMERATE || fdint == fdintPARTIAL_FILE) {
		return 0;
	}
	return 0;
}

bool fdi_decompress(const std::filesystem::path& cab_path,
                    const std::filesystem::path& target_dir,
                    std::string& out_extracted_path,
                    std::string& error)
{
	diag::log_tagged_fmt("pdb_dl", "fdi_decompress cab=%s target_dir=%s",
		cab_path.string().c_str(), target_dir.string().c_str());
	ERF erf = {};
	HFDI hfdi = FDICreate(fdi_alloc, fdi_free, fdi_open, fdi_read,
		fdi_write, fdi_close, fdi_seek, cpuUNKNOWN, &erf);
	if (!hfdi) {
		error = "FDICreate failed err=" + std::to_string(erf.erfOper);
		diag::log_tagged_fmt("pdb_dl", "fdi_decompress failed FDICreate err=%d", erf.erfOper);
		return false;
	}

	std::string cab_str = cab_path.string();
	auto sep = cab_str.find_last_of("/\\");
	std::string dir_part = (sep == std::string::npos) ? std::string("") : cab_str.substr(0, sep + 1);
	std::string file_part = (sep == std::string::npos) ? cab_str : cab_str.substr(sep + 1);

	std::vector<char> dir_buf(dir_part.begin(), dir_part.end());
	dir_buf.push_back('\0');
	std::vector<char> file_buf(file_part.begin(), file_part.end());
	file_buf.push_back('\0');

	fdi_ctx_t ctx;
	ctx.target_dir = target_dir.string();

	BOOL ok = FDICopy(hfdi, file_buf.data(), dir_buf.data(), 0, fdi_notify, nullptr, &ctx);
	FDIDestroy(hfdi);

	if (!ok || !ctx.wrote_any) {
		error = "FDICopy failed err=" + std::to_string(erf.erfOper);
		diag::log_tagged_fmt("pdb_dl", "fdi_decompress failed FDICopy err=%d cab=%s",
			erf.erfOper, cab_path.string().c_str());
		return false;
	}
	out_extracted_path = ctx.final_path;
	diag::log_tagged_fmt("pdb_dl", "fdi_decompress complete extracted=%s", ctx.final_path.c_str());
	return true;
}

std::filesystem::path build_local_target(const download_request_t& req)
{
	std::string folder = req.pdb_guid;
	char age_buf[16];
	std::snprintf(age_buf, sizeof(age_buf), "%X", static_cast<unsigned>(req.pdb_age));
	folder += age_buf;
	return std::filesystem::path(req.cache_root) / req.pdb_name / folder / req.pdb_name;
}

std::string build_server_url(const std::string& server_base,
                             const std::string& pdb_name,
                             const std::string& pdb_guid,
                             uint32_t pdb_age,
                             bool compressed)
{
	std::string out = server_base;
	if (!out.empty() && out.back() == '/') out.pop_back();
	out += "/";
	out += pdb_name;
	out += "/";
	out += pdb_guid;
	char age_buf[16];
	std::snprintf(age_buf, sizeof(age_buf), "%X", static_cast<unsigned>(pdb_age));
	out += age_buf;
	out += "/";
	if (compressed) {
		std::string compressed_name = pdb_name;
		if (compressed_name.size() >= 4 &&
		    (compressed_name[compressed_name.size() - 1] == 'b' ||
		     compressed_name[compressed_name.size() - 1] == 'B')) {
			compressed_name[compressed_name.size() - 1] = '_';
		}
		out += compressed_name;
	} else {
		out += pdb_name;
	}
	return out;
}

}

bool resolve_cache_path(const download_request_t& req, std::string& out_path)
{
	out_path.clear();
	diag::log_tagged_fmt("pdb_dl", "resolve_cache_path pdb=%s guid=%s age=%u",
		req.pdb_name.c_str(), req.pdb_guid.c_str(), req.pdb_age);
	if (req.pdb_name.empty() || req.pdb_guid.empty() || req.cache_root.empty()) {
		diag::log_tagged("pdb_dl", "resolve_cache_path failed invalid_request");
		return false;
	}
	auto target = build_local_target(req);
	std::error_code ec;
	if (std::filesystem::exists(target, ec) && std::filesystem::is_regular_file(target, ec)) {
		auto sz = std::filesystem::file_size(target, ec);
		if (!ec && sz > 0) {
			out_path = target.string();
			diag::log_tagged_fmt("pdb_dl", "resolve_cache_path cache_hit path=%s bytes=%llu",
				out_path.c_str(), static_cast<unsigned long long>(sz));
			return true;
		}
	}
	diag::log_tagged_fmt("pdb_dl", "resolve_cache_path cache_miss pdb=%s", req.pdb_name.c_str());
	return false;
}

bool download_pdb_sync(const download_request_t& req,
                       const progress_callback_t& on_progress,
                       const std::atomic<bool>* cancel,
                       download_result_t& out)
{
	out = {};
	diag::log_tagged_fmt("pdb_dl", "download_pdb_sync entry pdb=%s guid=%s age=%u server=%s",
		req.pdb_name.c_str(), req.pdb_guid.c_str(), req.pdb_age, req.server_base.c_str());

	if (req.pdb_name.empty() || req.pdb_guid.empty() || req.server_base.empty() ||
	    req.cache_root.empty()) {
		out.error = "invalid request";
		diag::log_tagged("pdb_dl", "download_pdb_sync failed invalid_request");
		return false;
	}

	std::string cached;
	if (resolve_cache_path(req, cached)) {
		out.ok = true;
		out.local_path = cached;
		out.from_cache = true;
		std::error_code ec;
		auto sz = std::filesystem::file_size(cached, ec);
		out.bytes_downloaded = ec ? 0 : sz;
		diag::log_tagged_fmt("pdb_dl", "download_pdb_sync from_cache pdb=%s path=%s bytes=%llu",
			req.pdb_name.c_str(), cached.c_str(),
			static_cast<unsigned long long>(out.bytes_downloaded));
		if (on_progress) {
			progress_t p;
			p.bytes_received = out.bytes_downloaded;
			p.bytes_total = out.bytes_downloaded;
			p.percent = 100;
			on_progress(p);
		}
		return true;
	}

	mcp_standalone::downstream::producer_identity_t pdb_dl_id;
	pdb_dl_id.kind = mcp_standalone::downstream::producer_kind_t::pdb_parser;
	pdb_dl_id.tool_name = "download_pdb_sync";
	mcp_standalone::downstream::scoped_admission_t pdb_dl_admission =
		mcp_standalone::downstream::scoped_admission_t::acquire(pdb_dl_id);
	if (!pdb_dl_admission.active()) {
		auto rej = mcp_standalone::downstream::governor_t::instance().try_admit(pdb_dl_id);
		diag::log_tagged_fmt("pdb_dl",
			"FEATURE-WORKER-GROUP-REJECT download_pdb_sync pdb=%s reason=%s quota=%s observed=%zu limit=%zu",
			req.pdb_name.c_str(),
			rej.reason.c_str(), rej.quota_name.c_str(), rej.observed, rej.limit);
		out.error = "PDB parser capacity exhausted; download was not started.";
		return false;
	}
	diag::log_tagged_fmt("pdb_dl",
		"FEATURE-WORKER-GROUP-ADMIT download_pdb_sync pdb=%s token=%llu",
		req.pdb_name.c_str(),
		static_cast<unsigned long long>(pdb_dl_admission.token()));

	auto target = build_local_target(req);
	std::error_code ec;
	std::filesystem::create_directories(target.parent_path(), ec);
	if (ec) {
		out.error = "cache directory creation failed: " + ec.message();
		return false;
	}

	std::string url = build_server_url(req.server_base, req.pdb_name,
		req.pdb_guid, req.pdb_age, false);
	diag::log_tagged_fmt("pdb_dl", "download_pdb_sync http_request url=%s", url.c_str());

	std::string error;
	uint64_t bytes = 0;
	int status = 0;
	bool ok = http_get_to_file(url, target, on_progress, cancel, error, bytes, status);

	if (!ok && status == 404) {
		diag::log_tagged_fmt("pdb_dl", "download_pdb_sync 404_fallback_to_cab pdb=%s", req.pdb_name.c_str());
		std::string cab_url = build_server_url(req.server_base, req.pdb_name,
			req.pdb_guid, req.pdb_age, true);
		diag::log_tagged_fmt("pdb_dl", "download_pdb_sync cab_url=%s", cab_url.c_str());
		auto cab_target = target;
		std::string cab_name = req.pdb_name;
		if (!cab_name.empty() && (cab_name.back() == 'b' || cab_name.back() == 'B'))
			cab_name.back() = '_';
		cab_target.replace_filename(cab_name);
		uint64_t cab_bytes = 0;
		int cab_status = 0;
		std::string cab_error;
		bool cab_ok = http_get_to_file(cab_url, cab_target, on_progress, cancel,
			cab_error, cab_bytes, cab_status);
		if (!cab_ok) {
			out.error = "primary http " + error + "; compressed " + cab_error;
		diag::log_tagged_fmt("pdb_dl", "download_pdb_sync cab_download_failed pdb=%s err=%s",
			req.pdb_name.c_str(), out.error.c_str());
		if (pdb_dl_admission.active()) {
			diag::log_tagged_fmt("pdb_dl",
				"FEATURE-WORKER-GROUP-RELEASE download_pdb_sync pdb=%s token=%llu reason=completed",
				req.pdb_name.c_str(),
				static_cast<unsigned long long>(pdb_dl_admission.token()));
			pdb_dl_admission.release("completed");
		}
		return false;
		}
		diag::log_tagged_fmt("pdb_dl", "download_pdb_sync cab_downloaded bytes=%llu decompressing",
			static_cast<unsigned long long>(cab_bytes));

		std::string extracted;
		std::string fdi_err;
		if (!fdi_decompress(cab_target, cab_target.parent_path(), extracted, fdi_err)) {
			std::filesystem::remove(cab_target, ec);
			out.error = "cab decompress failed: " + fdi_err;
		diag::log_tagged_fmt("pdb_dl", "download_pdb_sync cab_decompress_failed err=%s", fdi_err.c_str());
		if (pdb_dl_admission.active()) {
			diag::log_tagged_fmt("pdb_dl",
				"FEATURE-WORKER-GROUP-RELEASE download_pdb_sync pdb=%s token=%llu reason=completed",
				req.pdb_name.c_str(),
				static_cast<unsigned long long>(pdb_dl_admission.token()));
			pdb_dl_admission.release("completed");
		}
		return false;
		}
		std::filesystem::remove(cab_target, ec);
		diag::log_tagged_fmt("pdb_dl", "download_pdb_sync cab_decompressed extracted=%s", extracted.c_str());

		if (std::filesystem::path(extracted) != target) {
			std::filesystem::rename(extracted, target, ec);
			if (ec) {
				std::filesystem::copy_file(extracted, target,
					std::filesystem::copy_options::overwrite_existing, ec);
				std::filesystem::remove(extracted, ec);
			}
		}
		out.ok = true;
		out.local_path = target.string();
		out.bytes_downloaded = cab_bytes;
		out.from_cache = false;
		diag::log_tagged_fmt("pdb_dl", "download_pdb_sync complete via_cab pdb=%s path=%s bytes=%llu",
			req.pdb_name.c_str(), out.local_path.c_str(),
			static_cast<unsigned long long>(out.bytes_downloaded));
		if (pdb_dl_admission.active()) {
			diag::log_tagged_fmt("pdb_dl",
				"FEATURE-WORKER-GROUP-RELEASE download_pdb_sync pdb=%s token=%llu reason=completed",
				req.pdb_name.c_str(),
				static_cast<unsigned long long>(pdb_dl_admission.token()));
			pdb_dl_admission.release("completed");
		}
		return true;
	}

	if (!ok) {
		out.error = error;
		diag::log_tagged_fmt("pdb_dl", "download_pdb_sync failed pdb=%s err=%s",
			req.pdb_name.c_str(), error.c_str());
		if (pdb_dl_admission.active()) {
			diag::log_tagged_fmt("pdb_dl",
				"FEATURE-WORKER-GROUP-RELEASE download_pdb_sync pdb=%s token=%llu reason=completed",
				req.pdb_name.c_str(),
				static_cast<unsigned long long>(pdb_dl_admission.token()));
			pdb_dl_admission.release("completed");
		}
		return false;
	}

	out.ok = true;
	out.local_path = target.string();
	out.bytes_downloaded = bytes;
	out.from_cache = false;
	diag::log_tagged_fmt("pdb_dl", "download_pdb_sync complete direct pdb=%s path=%s bytes=%llu",
		req.pdb_name.c_str(), out.local_path.c_str(),
		static_cast<unsigned long long>(out.bytes_downloaded));
	if (pdb_dl_admission.active()) {
		diag::log_tagged_fmt("pdb_dl",
			"FEATURE-WORKER-GROUP-RELEASE download_pdb_sync pdb=%s token=%llu reason=completed",
			req.pdb_name.c_str(),
			static_cast<unsigned long long>(pdb_dl_admission.token()));
		pdb_dl_admission.release("completed");
	}
	return true;
}

}
