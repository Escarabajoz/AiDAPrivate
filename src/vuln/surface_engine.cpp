#include "../aida_pro.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <bytes.hpp>
#include <entry.hpp>
#include <frame.hpp>
#include <funcs.hpp>
#include <gdl.hpp>
#include <hexrays.hpp>
#include <ida.hpp>
#include <name.hpp>
#include <nalt.hpp>
#include <netnode.hpp>
#include <segment.hpp>
#include <strlist.hpp>
#include <typeinf.hpp>
#include <xref.hpp>

#include "../agent_tools.hpp"
#include "../ida_utils.hpp"
#include "microcode_engine.hpp"
#include "taint_engine.hpp"
#include "vuln_common.hpp"
#include "vuln_signatures.hpp"
#include "vuln_tools.hpp"

namespace aida
{
namespace vuln
{
namespace surface_engine
{

namespace
{

using json = nlohmann::json;

constexpr int kMaxBfsDepth        = 4;
constexpr int kMaxQueueElements   = 4096;
constexpr int kMaxCallersPerFunc  = 256;
constexpr int kMaxScannableFuncs  = 8192;

std::string ea_to_hex(ea_t ea)
{
    if (ea == BADADDR)
        return std::string(std::string("0x0"));
    std::ostringstream ss;
    ss << "0x" << std::hex << std::uppercase << static_cast<std::uint64_t>(ea);
    return ss.str();
}

std::string ascii_lower(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (char c : s)
    {
        unsigned char uc = static_cast<unsigned char>(c);
        out.push_back(static_cast<char>(uc >= 'A' && uc <= 'Z' ? uc + ('a' - 'A') : uc));
    }
    return out;
}

std::string strip_known_prefixes(const std::string& raw)
{
    static const char* const prefixes[] = {
        "__imp_", "__imp__", "_imp_", "_imp__", "imp_",
        "j_", "j_imp_", "thunk_", "_thunk_",
    };
    std::string out = raw;
    bool changed = true;
    while (changed)
    {
        changed = false;
        for (const char* p : prefixes)
        {
            const std::size_t plen = std::strlen(p);
            if (out.size() > plen && out.compare(0, plen, p) == 0)
            {
                out.erase(0, plen);
                changed = true;
                break;
            }
        }
    }
    if (out.size() > 1 && out.front() == '_')
    {
        bool only_alnum = true;
        for (char c : out)
        {
            if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '$' || c == '@' || c == '?'))
            {
                only_alnum = false;
                break;
            }
        }
        if (only_alnum)
            out.erase(0, 1);
    }
    auto at_pos = out.find('@');
    if (at_pos != std::string::npos)
        out.erase(at_pos);
    return out;
}

bool name_matches_signature(const std::string& callee, std::string_view sig)
{
    if (callee.empty() || sig.empty())
        return false;
    const std::string sig_l = ascii_lower(std::string(sig));
    const std::string call_l = ascii_lower(callee);
    if (call_l == sig_l)
        return true;
    const std::string stripped = ascii_lower(strip_known_prefixes(callee));
    if (stripped == sig_l)
        return true;
    if (call_l.size() > sig_l.size() &&
        call_l.compare(call_l.size() - sig_l.size(), sig_l.size(), sig_l) == 0)
        return true;
    if (stripped.size() > sig_l.size() &&
        stripped.compare(stripped.size() - sig_l.size(), sig_l.size(), sig_l) == 0)
        return true;
    return false;
}

std::string func_name_for(ea_t func_ea)
{
    if (func_ea == BADADDR)
        return std::string();
    qstring nm;
    if (get_func_name(&nm, func_ea) > 0 && !nm.empty())
        return std::string(nm.c_str());
    qstring vn;
    if (get_name(&vn, func_ea) > 0 && !vn.empty())
        return std::string(vn.c_str());
    std::ostringstream ss;
    ss << "sub_" << std::hex << std::uppercase << static_cast<std::uint64_t>(func_ea);
    return ss.str();
}

std::string raw_name_for(ea_t ea)
{
    if (ea == BADADDR)
        return std::string();
    qstring nm;
    if (get_name(&nm, ea) > 0 && !nm.empty())
        return std::string(nm.c_str());
    qstring fnm;
    if (get_func_name(&fnm, ea) > 0 && !fnm.empty())
        return std::string(fnm.c_str());
    return std::string();
}

std::mutex& engine_mutex()
{
    static std::mutex m;
    return m;
}

ea_t containing_func_ea(ea_t ea)
{
    if (ea == BADADDR)
        return BADADDR;
    func_t* pfn = get_func(ea);
    if (pfn == nullptr)
        return BADADDR;
    return pfn->start_ea;
}

cfuncptr_t decompile_safe(ea_t func_ea)
{
    if (func_ea == BADADDR)
        return cfuncptr_t(nullptr);
    if (!init_hexrays_plugin())
        return cfuncptr_t(nullptr);
    func_t* pfn = get_func(func_ea);
    if (pfn == nullptr || !ida_utils::is_safely_decompilable(pfn))
        return cfuncptr_t(nullptr);
    try
    {
        return decompile_func(pfn, nullptr, DECOMP_NO_WAIT);
    }
    catch (const vd_failure_t&)
    {
        return cfuncptr_t(nullptr);
    }
    catch (...)
    {
        return cfuncptr_t(nullptr);
    }
}

struct call_graph_t
{
    std::unordered_map<ea_t, std::vector<ea_t>> callees;
    std::unordered_map<ea_t, std::vector<ea_t>> callers;
};

call_graph_t build_call_graph()
{
    call_graph_t g;
    const std::size_t fq = get_func_qty();
    g.callees.reserve(fq);
    g.callers.reserve(fq);

    for (std::size_t i = 0; i < fq; ++i)
    {
        func_t* pfn = getn_func(i);
        if (pfn == nullptr)
            continue;
        ea_t fea = pfn->start_ea;
        std::unordered_set<ea_t> outset;
        func_item_iterator_t fii(pfn);
        for (bool ok = fii.first(); ok; ok = fii.next_head())
        {
            ea_t cur = fii.current();
            xrefblk_t xb;
            for (bool ix = xb.first_from(cur, XREF_ALL); ix; ix = xb.next_from())
            {
                if (!xb.iscode)
                    continue;
                if (xb.type != fl_CN && xb.type != fl_CF)
                    continue;
                func_t* tgt = get_func(xb.to);
                ea_t tea = tgt != nullptr ? tgt->start_ea : xb.to;
                if (tea == BADADDR || tea == fea)
                    continue;
                if (outset.insert(tea).second)
                    g.callees[fea].push_back(tea);
            }
        }
    }

    for (const auto& kv : g.callees)
    {
        ea_t caller = kv.first;
        for (ea_t callee : kv.second)
            g.callers[callee].push_back(caller);
    }

    for (auto& kv : g.callees)
    {
        std::sort(kv.second.begin(), kv.second.end());
        kv.second.erase(std::unique(kv.second.begin(), kv.second.end()), kv.second.end());
    }
    for (auto& kv : g.callers)
    {
        std::sort(kv.second.begin(), kv.second.end());
        kv.second.erase(std::unique(kv.second.begin(), kv.second.end()), kv.second.end());
    }

    return g;
}

const call_graph_t& cached_call_graph()
{
    static std::mutex mtx;
    static std::optional<call_graph_t> cache;
    std::lock_guard<std::mutex> lk(mtx);
    if (!cache.has_value())
        cache = build_call_graph();
    return *cache;
}

struct dynamic_source_t
{
    ea_t        source_ea = BADADDR;
    ea_t        func_ea = BADADDR;
    std::string kind;
    std::string name;
};

std::string current_md5_token()
{
    uchar md5[16] = {};
    if (!retrieve_input_file_md5(md5))
        return std::string();
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(32);
    for (uchar b : md5)
    {
        out.push_back(hex[(b >> 4) & 0xF]);
        out.push_back(hex[b & 0xF]);
    }
    return out;
}

std::vector<dynamic_source_t>& dynamic_sources()
{
    static std::vector<dynamic_source_t> sources;
    return sources;
}

std::string& dynamic_sources_md5()
{
    static std::string md5;
    return md5;
}

void reset_dynamic_sources_if_idb_changed()
{
    const std::string cur = current_md5_token();
    std::string& stored = dynamic_sources_md5();
    if (stored != cur)
    {
        stored = cur;
        dynamic_sources().clear();
    }
}

std::vector<callsite_t> input_source_callsites_safe()
{
    return aida::vuln::callsites::input_source_callsites();
}

std::vector<callsite_t> sink_callsites_safe()
{
    std::vector<std::string> names;
    names.reserve(64);
    for (const auto& s : sig::BUFFER_OVERFLOW_SINKS)
        names.emplace_back(s.name);
    for (const auto& s : sig::COMMAND_INJECTION_SINKS)
        names.emplace_back(s.name);
    for (const auto& s : sig::PATH_TRAVERSAL_SINKS)
        names.emplace_back(s.name);
    for (const auto& s : sig::FORMAT_STRING_FUNCS)
        names.emplace_back(s.name);
    for (const auto& s : sig::SAFEARRAY_PARSER_SINKS)
        names.emplace_back(s.name);
    for (const auto& s : sig::DESERIALIZATION_SINKS)
        names.emplace_back(s.name);
    std::sort(names.begin(), names.end());
    names.erase(std::unique(names.begin(), names.end()), names.end());
    return aida::vuln::callsites::all_calls_to(names);
}

int caller_distance_to(const call_graph_t& g, ea_t from, ea_t to, int max_depth)
{
    if (from == BADADDR || to == BADADDR)
        return -1;
    if (from == to)
        return 0;
    std::deque<std::pair<ea_t, int>> q;
    std::unordered_set<ea_t> visited;
    q.emplace_back(from, 0);
    visited.insert(from);
    while (!q.empty())
    {
        auto [cur, d] = q.front();
        q.pop_front();
        if (d >= max_depth)
            continue;
        auto it = g.callers.find(cur);
        if (it == g.callers.end())
            continue;
        for (ea_t prev : it->second)
        {
            if (!visited.insert(prev).second)
                continue;
            if (prev == to)
                return d + 1;
            q.emplace_back(prev, d + 1);
            if (q.size() > static_cast<std::size_t>(kMaxQueueElements))
                return -1;
        }
    }
    return -1;
}

int callee_distance_to(const call_graph_t& g, ea_t from, ea_t to, int max_depth)
{
    if (from == BADADDR || to == BADADDR)
        return -1;
    if (from == to)
        return 0;
    std::deque<std::pair<ea_t, int>> q;
    std::unordered_set<ea_t> visited;
    q.emplace_back(from, 0);
    visited.insert(from);
    while (!q.empty())
    {
        auto [cur, d] = q.front();
        q.pop_front();
        if (d >= max_depth)
            continue;
        auto it = g.callees.find(cur);
        if (it == g.callees.end())
            continue;
        for (ea_t nxt : it->second)
        {
            if (!visited.insert(nxt).second)
                continue;
            if (nxt == to)
                return d + 1;
            q.emplace_back(nxt, d + 1);
            if (q.size() > static_cast<std::size_t>(kMaxQueueElements))
                return -1;
        }
    }
    return -1;
}

std::optional<ea_t> parse_addr_param(const json& params, const std::string& key)
{
    if (!params.is_object())
        return std::nullopt;
    auto it = params.find(key);
    if (it == params.end() || it->is_null())
        return std::nullopt;
    if (it->is_string())
    {
        const std::string s = it->get<std::string>();
        if (s.empty())
            return std::nullopt;
        return agent_tools::helpers::parse_address(s);
    }
    if (it->is_number_unsigned())
        return static_cast<ea_t>(it->get<std::uint64_t>());
    if (it->is_number_integer())
        return static_cast<ea_t>(it->get<std::int64_t>());
    return std::nullopt;
}

int extract_int_param(const json& params, const std::string& key, int default_value)
{
    if (!params.is_object())
        return default_value;
    auto it = params.find(key);
    if (it == params.end() || it->is_null())
        return default_value;
    try
    {
        if (it->is_number_integer())
        {
            const std::int64_t value = it->get<std::int64_t>();
            if (value < (std::numeric_limits<int>::min)() || value > (std::numeric_limits<int>::max)())
                return default_value;
            return static_cast<int>(value);
        }
        if (it->is_number_unsigned())
        {
            const std::uint64_t value = it->get<std::uint64_t>();
            if (value > static_cast<std::uint64_t>((std::numeric_limits<int>::max)()))
                return default_value;
            return static_cast<int>(value);
        }
        if (it->is_number())
        {
            const double value = it->get<double>();
            if (!std::isfinite(value) || value < (std::numeric_limits<int>::min)() || value > (std::numeric_limits<int>::max)())
                return default_value;
            return static_cast<int>(value);
        }
        if (it->is_string())
        {
            const std::string s = it->get<std::string>();
            if (s.empty())
                return default_value;
            return std::stoi(s);
        }
    }
    catch (...)
    {
        return default_value;
    }
    return default_value;
}

ea_t resolve_address_or_name(const std::string& spec)
{
    if (spec.empty())
        return BADADDR;
    auto parsed = agent_tools::helpers::parse_address(spec);
    if (parsed.has_value())
        return *parsed;
    ea_t ea = get_name_ea(BADADDR, spec.c_str());
    return ea;
}

cwe_t make_cwe(int id, const char* nm)
{
    cwe_t c;
    c.id = id;
    c.name = nm;
    return c;
}

const char* cwe_name_for(int id)
{
    switch (id)
    {
    case 22:   return "Path Traversal";
    case 78:   return "OS Command Injection";
    case 120:  return "Buffer Copy without Checking Size of Input";
    case 125:  return "Out-of-bounds Read";
    case 129:  return "Improper Validation of Array Index";
    case 130:  return "Improper Handling of Length Parameter Inconsistency";
    case 134:  return "Use of Externally-Controlled Format String";
    case 190:  return "Integer Overflow or Wraparound";
    case 193:  return "Off-by-one Error";
    case 194:  return "Unexpected Sign Extension";
    case 195:  return "Signed to Unsigned Conversion Error";
    case 242:  return "Use of Inherently Dangerous Function";
    case 358:  return "Improperly Implemented Security Check for Standard";
    case 367:  return "Time-of-check Time-of-use (TOCTOU) Race Condition";
    case 415:  return "Double Free";
    case 416:  return "Use After Free";
    case 476:  return "NULL Pointer Dereference";
    case 502:  return "Deserialization of Untrusted Data";
    case 770:  return "Allocation of Resources Without Limits or Throttling";
    case 787:  return "Out-of-bounds Write";
    case 798:  return "Use of Hard-coded Credentials";
    case 822:  return "Untrusted Pointer Dereference";
    case 839:  return "Numeric Range Comparison Without Minimum Check";
    case 1188: return "Insecure Default Initialization of Resource";
    default:   return "Unknown CWE";
    }
}

json findings_to_json_array(const std::vector<vuln_finding_t>& findings)
{
    json arr = json::array();
    for (const auto& f : findings)
        arr.push_back(to_json(f));
    return arr;
}

bool is_alloc_like(const std::string& nm)
{
    for (const auto& a : sig::ALLOC_FUNCS)
    {
        if (name_matches_signature(nm, a))
            return true;
    }
    return false;
}

bool is_free_like(const std::string& nm)
{
    for (const auto& f : sig::FREE_FUNCS)
    {
        if (name_matches_signature(nm, f))
            return true;
    }
    return false;
}

bool is_validator_like(const std::string& nm)
{
    for (const auto& v : sig::KERNEL_VALIDATORS)
    {
        if (name_matches_signature(nm, v))
            return true;
    }
    return false;
}

bool is_input_source_like(const std::string& nm)
{
    for (const auto& s : sig::INPUT_SOURCES)
    {
        if (name_matches_signature(nm, s.name))
            return true;
    }
    return false;
}

bool is_dangerous_sink(const std::string& nm)
{
    for (const auto& s : sig::BUFFER_OVERFLOW_SINKS)
    {
        if (name_matches_signature(nm, s.name))
            return true;
    }
    for (const auto& s : sig::COMMAND_INJECTION_SINKS)
    {
        if (name_matches_signature(nm, s.name))
            return true;
    }
    for (const auto& s : sig::FORMAT_STRING_FUNCS)
    {
        if (name_matches_signature(nm, s.name))
            return true;
    }
    return false;
}

bool is_crypto_function(const std::string& nm)
{
    for (const auto& s : sig::WEAK_HASH_FUNCS)
    {
        if (name_matches_signature(nm, s.name))
            return true;
    }
    for (const auto& s : sig::WEAK_CIPHER_FUNCS)
    {
        if (name_matches_signature(nm, s.name))
            return true;
    }
    const std::string l = ascii_lower(nm);
    if (l.find("aes_") != std::string::npos)
        return true;
    if (l.find("sha256") != std::string::npos || l.find("sha512") != std::string::npos)
        return true;
    if (l.find("hmac") != std::string::npos)
        return true;
    if (l.find("evp_") != std::string::npos)
        return true;
    if (l.find("crypt") != std::string::npos)
        return true;
    return false;
}

std::vector<std::string> known_callback_apis()
{
    return {
        "SetWindowsHookExA", "SetWindowsHookExW", "SetWindowsHookEx", "SetWindowsHookExEx",
        "CreateRemoteThread", "CreateRemoteThreadEx", "CreateThread", "RtlCreateUserThread",
        "IoRegisterDeviceInterface", "KeInitializeDpc", "KeInitializeTimer",
        "KeInitializeTimerEx", "IoSetCompletionRoutine", "IoSetCompletionRoutineEx",
        "IoRegisterPlugPlayNotification", "IoRegisterShutdownNotification",
        "IoRegisterFsRegistrationChange", "ExRegisterCallback",
        "RegisterServiceCtrlHandlerA", "RegisterServiceCtrlHandlerW",
        "RegisterServiceCtrlHandlerExA", "RegisterServiceCtrlHandlerExW",
        "SetUnhandledExceptionFilter", "AddVectoredExceptionHandler",
        "AddVectoredContinueHandler", "_set_se_translator", "signal",
        "atexit", "_onexit", "_beginthread", "_beginthreadex",
        "RegisterWaitForSingleObject", "RegisterWaitForSingleObjectEx",
        "CreateTimerQueueTimer", "QueueUserAPC", "QueueUserWorkItem",
        "PsSetCreateProcessNotifyRoutine", "PsSetCreateProcessNotifyRoutineEx",
        "PsSetCreateProcessNotifyRoutineEx2", "PsSetCreateThreadNotifyRoutine",
        "PsSetCreateThreadNotifyRoutineEx", "PsSetLoadImageNotifyRoutine",
        "CmRegisterCallback", "CmRegisterCallbackEx", "ObRegisterCallbacks",
        "KeRegisterBugCheckCallback", "KeRegisterBugCheckReasonCallback",
        "EtwRegister", "IoWMIRegistrationControl", "WskRegister",
        "WskCaptureProviderNPI", "FltRegisterFilter",
    };
}

int callback_arg_index(const std::string& api)
{
    const std::string l = ascii_lower(api);
    if (l.find("setwindowshook") != std::string::npos)
        return 1;
    if (l == "createremotethread" || l == "createremotethreadex" ||
        l == "createthread" || l == "rtlcreateuserthread")
        return 2;
    if (l == "ioregisterdeviceinterface")
        return 1;
    if (l.find("keinitializedpc") != std::string::npos ||
        l.find("keinitializetimer") != std::string::npos)
        return 1;
    if (l.find("iosetcompletionroutine") != std::string::npos)
        return 1;
    if (l.find("ioregisterplugplay") != std::string::npos)
        return 1;
    if (l.find("ioregistershutdown") != std::string::npos)
        return 0;
    if (l.find("ioregisterfsregistration") != std::string::npos)
        return 0;
    if (l.find("exregistercallback") != std::string::npos)
        return 1;
    if (l.find("registerservicectrlhandler") != std::string::npos)
        return 1;
    if (l == "setunhandledexceptionfilter" ||
        l == "addvectoredexceptionhandler" ||
        l == "addvectoredcontinuehandler")
        return 0;
    if (l == "_set_se_translator")
        return 0;
    if (l == "signal")
        return 1;
    if (l == "atexit" || l == "_onexit")
        return 0;
    if (l == "_beginthread" || l == "_beginthreadex")
        return 0;
    if (l.find("registerwaitforsingleobject") != std::string::npos)
        return 1;
    if (l.find("createtimerqueuetimer") != std::string::npos)
        return 1;
    if (l.find("queueuserapc") != std::string::npos)
        return 0;
    if (l.find("queueuserworkitem") != std::string::npos)
        return 0;
    if (l.find("pssetcreateprocessnotify") != std::string::npos)
        return 0;
    if (l.find("pssetcreatethreadnotify") != std::string::npos)
        return 0;
    if (l.find("pssetloadimagenotify") != std::string::npos)
        return 0;
    if (l.find("cmregistercallback") != std::string::npos)
        return 0;
    if (l.find("obregistercallbacks") != std::string::npos)
        return 1;
    if (l.find("keregisterbugcheck") != std::string::npos)
        return 0;
    if (l.find("etwregister") != std::string::npos)
        return 3;
    if (l.find("iowmiregistrationcontrol") != std::string::npos)
        return 0;
    if (l.find("wskregister") != std::string::npos)
        return 1;
    if (l.find("wskcaptureprovidernpi") != std::string::npos)
        return 2;
    if (l.find("fltregisterfilter") != std::string::npos)
        return 1;
    return 0;
}

bool security_sensitive_callback_api(const std::string& api)
{
    const std::string l = ascii_lower(api);
    if (l.find("setwindowshook") != std::string::npos)
        return true;
    if (l == "setunhandledexceptionfilter")
        return true;
    if (l.find("addvectored") != std::string::npos)
        return true;
    if (l.find("ioregister") != std::string::npos)
        return true;
    if (l.find("exregistercallback") != std::string::npos)
        return true;
    if (l.find("psset") != std::string::npos || l.find("cmregister") != std::string::npos ||
        l.find("obregister") != std::string::npos || l.find("keregisterbugcheck") != std::string::npos ||
        l.find("etwregister") != std::string::npos || l.find("wsk") != std::string::npos ||
        l.find("fltregisterfilter") != std::string::npos)
        return true;
    return false;
}

cwe_t cwe_for_callback(const std::string& api)
{
    if (security_sensitive_callback_api(api))
        return make_cwe(358, cwe_name_for(358));
    return make_cwe(0, "Informational");
}

struct call_visitor_t : public ctree_visitor_t
{
    cfunc_t*                          cfunc = nullptr;
    std::function<int(cexpr_t*)>      on_call;
    int                               last_result = 0;

    call_visitor_t(cfunc_t* cf, std::function<int(cexpr_t*)> cb)
        : ctree_visitor_t(CV_FAST), cfunc(cf), on_call(std::move(cb)) {}

    int idaapi visit_expr(cexpr_t* expr) override
    {
        if (expr != nullptr && expr->op == cot_call && on_call)
        {
            last_result = on_call(expr);
            return last_result;
        }
        return 0;
    }
};

ea_t resolve_call_target_ea(const cexpr_t* call_expr)
{
    if (call_expr == nullptr || call_expr->op != cot_call || call_expr->x == nullptr)
        return BADADDR;
    const cexpr_t* x = call_expr->x;
    while (x != nullptr && (x->op == cot_cast || x->op == cot_ref) && x->x != nullptr)
        x = x->x;
    if (x == nullptr)
        return BADADDR;
    if (x->op == cot_obj)
        return x->obj_ea;
    return BADADDR;
}

std::string resolve_call_target_name(const cexpr_t* call_expr)
{
    if (call_expr == nullptr || call_expr->op != cot_call || call_expr->x == nullptr)
        return std::string();
    const cexpr_t* x = call_expr->x;
    while (x != nullptr && (x->op == cot_cast || x->op == cot_ref) && x->x != nullptr)
        x = x->x;
    if (x == nullptr)
        return std::string();
    if (x->op == cot_obj)
    {
        ea_t ea = x->obj_ea;
        if (ea == BADADDR)
            return std::string();
        std::string raw = raw_name_for(ea);
        if (!raw.empty())
            return raw;
        std::string fname = func_name_for(ea);
        return fname;
    }
    if (x->op == cot_helper && x->helper != nullptr)
        return std::string(x->helper);
    return std::string();
}

const cexpr_t* unwrap_cast_ref(const cexpr_t* e)
{
    while (e != nullptr && (e->op == cot_cast || e->op == cot_ref) && e->x != nullptr)
        e = e->x;
    return e;
}

ea_t literal_callback_arg(const cexpr_t* call_expr, int arg_idx)
{
    if (call_expr == nullptr || call_expr->op != cot_call || call_expr->a == nullptr)
        return BADADDR;
    if (arg_idx < 0 || static_cast<std::size_t>(arg_idx) >= call_expr->a->size())
        return BADADDR;
    const cexpr_t* arg = static_cast<const cexpr_t*>(&(*call_expr->a)[arg_idx]);
    arg = unwrap_cast_ref(arg);
    if (arg == nullptr)
        return BADADDR;
    if (arg->op == cot_obj)
        return arg->obj_ea;
    return BADADDR;
}

bool ea_is_function(ea_t ea)
{
    if (ea == BADADDR)
        return false;
    func_t* pfn = get_func(ea);
    if (pfn == nullptr)
        return false;
    return pfn->start_ea == ea;
}

}

attack_surface_score_t score_function(ea_t func_ea)
{
    attack_surface_score_t out;
    out.func_ea = func_ea;
    if (func_ea == BADADDR)
        return out;

    func_t* pfn = get_func(func_ea);
    if (pfn == nullptr)
        return out;

    const call_graph_t& g = cached_call_graph();

    auto& te = aida::vuln::taint::engine();
    if (!te.is_analyzed())
        te.analyze_all();
    const auto* sum = te.get_summary(func_ea);

    int input_proximity = 0;
    {
        std::vector<callsite_t> sources = input_source_callsites_safe();
        std::unordered_set<ea_t> seen_src_funcs;
        for (const auto& cs : sources)
        {
            if (cs.func_ea == BADADDR)
                continue;
            if (!seen_src_funcs.insert(cs.func_ea).second)
                continue;
            int d = caller_distance_to(g, func_ea, cs.func_ea, kMaxBfsDepth);
            if (d < 0)
                continue;
            int contrib = 5 - d;
            if (contrib < 1)
                contrib = 1;
            input_proximity += contrib;
            if (input_proximity >= 25)
            {
                input_proximity = 25;
                break;
            }
        }
    }

    int sink_count = 0;
    {
        std::vector<callsite_t> sinks = sink_callsites_safe();
        std::unordered_set<ea_t> seen_sink_funcs;
        for (const auto& cs : sinks)
        {
            if (cs.func_ea == BADADDR)
                continue;
            if (!seen_sink_funcs.insert(cs.func_ea).second)
                continue;
            int d = callee_distance_to(g, func_ea, cs.func_ea, kMaxBfsDepth);
            if (d < 0)
                continue;
            int contrib = 5 - d;
            if (contrib < 1)
                contrib = 1;
            sink_count += contrib;
            if (sink_count >= 25)
            {
                sink_count = 25;
                break;
            }
        }
    }

    int missing_validators = 0;
    if (sum != nullptr)
    {
        std::set<int> diff;
        for (int idx : sum->params_passed_to_sinks)
        {
            if (sum->params_validated.count(idx) == 0)
                diff.insert(idx);
        }
        missing_validators = static_cast<int>(diff.size()) * 4;
        if (missing_validators > 20)
            missing_validators = 20;
    }

    int complexity = 0;
    if (sum != nullptr)
    {
        double v = std::log2(static_cast<double>(sum->cyclomatic + 1)) * 3.0;
        if (v < 0.0) v = 0.0;
        if (v > 15.0) v = 15.0;
        complexity = static_cast<int>(v);
    }

    int taint_paths = 0;
    if (sum != nullptr)
    {
        if (!sum->input_sources_called.empty() && !sum->sinks_reached.empty())
        {
            taint_paths = static_cast<int>(sum->input_sources_called.size() * sum->sinks_reached.size());
        }
        else if (sum->returns_tainted && !sum->sinks_reached.empty())
        {
            taint_paths = static_cast<int>(sum->sinks_reached.size());
        }
        if (taint_paths > 15)
            taint_paths = 15;
    }

    out.input_proximity    = input_proximity;
    out.sink_count         = sink_count;
    out.missing_validators = missing_validators;
    out.complexity         = complexity;
    out.taint_paths        = taint_paths;
    out.classification     = classify_function_role(func_ea);
    out.total_score = input_proximity + sink_count + missing_validators + complexity + taint_paths;
    if (out.total_score > 100)
        out.total_score = 100;
    return out;
}

std::vector<ea_t> attacker_reachable_functions()
{
    reset_dynamic_sources_if_idb_changed();
    std::vector<ea_t> out;
    const call_graph_t& g = cached_call_graph();
    std::vector<callsite_t> sources = input_source_callsites_safe();

    std::unordered_set<ea_t> seen;
    std::deque<ea_t> q;
    for (const auto& cs : sources)
    {
        if (cs.func_ea == BADADDR)
            continue;
        if (seen.insert(cs.func_ea).second)
            q.push_back(cs.func_ea);
    }
    for (const auto& ds : dynamic_sources())
    {
        if (ds.func_ea == BADADDR)
            continue;
        if (seen.insert(ds.func_ea).second)
            q.push_back(ds.func_ea);
    }

    while (!q.empty())
    {
        ea_t cur = q.front();
        q.pop_front();
        out.push_back(cur);
        auto it = g.callers.find(cur);
        if (it == g.callers.end())
            continue;
        for (ea_t prev : it->second)
        {
            if (!seen.insert(prev).second)
                continue;
            q.push_back(prev);
            if (q.size() > static_cast<std::size_t>(kMaxQueueElements))
                break;
        }
    }

    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

namespace
{

bool function_calls_count(const taint::func_summary_t* sum, bool (*pred)(const std::string&))
{
    if (sum == nullptr)
        return false;
    for (const auto& nm : sum->allocs_called)
        if (pred(nm))
            return true;
    for (const auto& nm : sum->frees_called)
        if (pred(nm))
            return true;
    for (const auto& nm : sum->validators_called)
        if (pred(nm))
            return true;
    for (const auto& nm : sum->input_sources_called)
        if (pred(nm))
            return true;
    for (const auto& nm : sum->sinks_reached)
        if (pred(nm))
            return true;
    return false;
}

struct callee_counts_t
{
    int allocs = 0;
    int frees = 0;
    int validators = 0;
    int input_sources = 0;
    int sinks = 0;
    int crypto = 0;
    int total_calls = 0;
};

callee_counts_t collect_callee_counts(ea_t func_ea)
{
    callee_counts_t cc;
    if (func_ea == BADADDR)
        return cc;
    const call_graph_t& g = cached_call_graph();
    auto it = g.callees.find(func_ea);
    if (it == g.callees.end())
        return cc;
    for (ea_t cee : it->second)
    {
        std::string nm = func_name_for(cee);
        if (nm.empty())
            continue;
        cc.total_calls++;
        if (is_alloc_like(nm)) cc.allocs++;
        if (is_free_like(nm)) cc.frees++;
        if (is_validator_like(nm)) cc.validators++;
        if (is_input_source_like(nm)) cc.input_sources++;
        if (is_dangerous_sink(nm)) cc.sinks++;
        if (is_crypto_function(nm)) cc.crypto++;
    }
    return cc;
}

bool function_has_irp_pattern(ea_t func_ea)
{
    if (func_ea == BADADDR)
        return false;
    const call_graph_t& g = cached_call_graph();
    auto it = g.callees.find(func_ea);
    if (it == g.callees.end())
        return false;
    static const std::vector<std::string> irp_apis = {
        "IoCallDriver", "IoCompleteRequest", "IofCompleteRequest",
        "IoBuildSynchronousFsdRequest", "IoAllocateIrp",
        "IoCreateDevice", "IoCreateSymbolicLink",
    };
    for (ea_t cee : it->second)
    {
        std::string nm = func_name_for(cee);
        for (const auto& a : irp_apis)
        {
            if (name_matches_signature(nm, a))
                return true;
        }
    }
    return false;
}

bool function_has_ipc_pattern(ea_t func_ea, int& count)
{
    count = 0;
    if (func_ea == BADADDR)
        return false;
    const call_graph_t& g = cached_call_graph();
    auto it = g.callees.find(func_ea);
    if (it == g.callees.end())
        return false;
    static const std::vector<std::string> ipc_apis = {
        "recv", "recvfrom", "send", "sendto", "WSARecv", "WSASend",
        "WSARecvFrom", "WSASendTo", "WriteFile", "ReadFile",
        "TransmitFile", "TransmitPackets",
    };
    for (ea_t cee : it->second)
    {
        std::string nm = func_name_for(cee);
        for (const auto& a : ipc_apis)
        {
            if (name_matches_signature(nm, a))
            {
                count++;
                break;
            }
        }
    }
    return count >= 2;
}

bool function_has_validator_pattern(ea_t func_ea)
{
    if (func_ea == BADADDR)
        return false;
    const call_graph_t& g = cached_call_graph();
    auto it = g.callees.find(func_ea);
    if (it == g.callees.end())
        return false;
    for (ea_t cee : it->second)
    {
        std::string nm = func_name_for(cee);
        if (is_validator_like(nm))
            return true;
    }
    return false;
}

bool function_registers_callbacks(ea_t func_ea)
{
    if (func_ea == BADADDR)
        return false;
    const call_graph_t& g = cached_call_graph();
    auto it = g.callees.find(func_ea);
    if (it == g.callees.end())
        return false;
    auto cbs = known_callback_apis();
    for (ea_t cee : it->second)
    {
        std::string nm = func_name_for(cee);
        for (const auto& a : cbs)
        {
            if (name_matches_signature(nm, a))
                return true;
        }
    }
    return false;
}

struct switch_visitor_t : public ctree_visitor_t
{
    int  switch_count = 0;
    int  default_count = 0;
    int  total_cases = 0;
    bool subject_is_field = false;
    bool subject_is_var = false;

    switch_visitor_t() : ctree_visitor_t(CV_FAST) {}

    int idaapi visit_insn(cinsn_t* ins) override
    {
        if (ins == nullptr)
            return 0;
        if (ins->op == cit_switch && ins->cswitch != nullptr)
        {
            switch_count++;
            const cexpr_t& subj = ins->cswitch->expr;
            const cexpr_t* x = unwrap_cast_ref(&subj);
            if (x != nullptr)
            {
                if (x->op == cot_memptr || x->op == cot_memref)
                    subject_is_field = true;
                else if (x->op == cot_var)
                    subject_is_var = true;
            }
            for (std::size_t i = 0; i < ins->cswitch->cases.size(); ++i)
            {
                const ccase_t& cc = ins->cswitch->cases[i];
                total_cases += static_cast<int>(cc.values.size());
                if (cc.values.empty())
                    default_count++;
            }
        }
        return 0;
    }
};

bool function_has_dispatcher_shape(ea_t func_ea, int& num_cases, bool& has_default)
{
    num_cases = 0;
    has_default = false;
    cfuncptr_t cf = decompile_safe(func_ea);
    if (!cf)
        return false;
    switch_visitor_t v;
    v.apply_to(&cf->body, nullptr);
    num_cases = v.total_cases;
    has_default = v.default_count > 0;
    return v.switch_count > 0 && v.total_cases > 5 && has_default;
}

bool function_has_parser_shape(ea_t func_ea)
{
    cfuncptr_t cf = decompile_safe(func_ea);
    if (!cf)
        return false;
    switch_visitor_t v;
    v.apply_to(&cf->body, nullptr);
    if (v.switch_count == 0)
        return false;
    return v.subject_is_field;
}

}

std::string classify_function_role(ea_t func_ea)
{
    if (func_ea == BADADDR)
        return std::string("unknown");
    auto& te = aida::vuln::taint::engine();
    if (!te.is_analyzed())
        te.analyze_all();
    const auto* sum = te.get_summary(func_ea);

    std::string nm = func_name_for(func_ea);
    for (const auto& a : sig::ALLOC_FUNCS)
    {
        if (name_matches_signature(nm, a))
            return std::string("allocator");
    }
    for (const auto& f : sig::FREE_FUNCS)
    {
        if (name_matches_signature(nm, f))
            return std::string("deallocator");
    }
    for (const auto& v : sig::KERNEL_VALIDATORS)
    {
        if (name_matches_signature(nm, v))
            return std::string("validator");
    }

    callee_counts_t cc = collect_callee_counts(func_ea);

    if (cc.allocs > 2 && cc.allocs > (cc.total_calls / 2))
        return std::string("allocator");
    if (cc.frees > 2 && cc.frees > (cc.total_calls / 2))
        return std::string("deallocator");

    if (function_has_irp_pattern(func_ea))
        return std::string("ioctl_handler");

    int ipc_calls = 0;
    if (function_has_ipc_pattern(func_ea, ipc_calls))
        return std::string("ipc_endpoint");

    int num_cases = 0;
    bool has_default = false;
    if (function_has_dispatcher_shape(func_ea, num_cases, has_default))
        return std::string("dispatcher");

    if (function_has_parser_shape(func_ea))
        return std::string("parser");

    if (function_has_validator_pattern(func_ea) || (sum != nullptr && !sum->validators_called.empty()))
        return std::string("validator");

    if (function_registers_callbacks(func_ea))
        return std::string("callback");

    if (cc.crypto > 0 || (sum != nullptr && function_calls_count(sum, +[](const std::string& n) { return is_crypto_function(n); })))
        return std::string("crypto");

    return std::string("utility");
}

namespace
{

struct callback_visitor_t : public ctree_visitor_t
{
    cfunc_t* cfunc = nullptr;
    std::vector<vuln_finding_t>* findings = nullptr;
    std::unordered_set<std::string>* api_index = nullptr;
    std::size_t limit = 0;

    callback_visitor_t(cfunc_t* cf, std::vector<vuln_finding_t>* out,
                       std::unordered_set<std::string>* idx, std::size_t lim)
        : ctree_visitor_t(CV_FAST), cfunc(cf), findings(out), api_index(idx), limit(lim) {}

    int idaapi visit_expr(cexpr_t* expr) override
    {
        if (findings == nullptr || api_index == nullptr || cfunc == nullptr)
            return 0;
        if (findings->size() >= limit)
            return 1;
        if (expr == nullptr)
            return 0;

        if (expr->op == cot_call)
        {
            std::string nm = resolve_call_target_name(expr);
            if (nm.empty())
                return 0;
            std::string canonical;
            for (const auto& a : *api_index)
            {
                if (name_matches_signature(nm, a))
                {
                    canonical = a;
                    break;
                }
            }
            if (canonical.empty())
                return 0;
            int idx = callback_arg_index(canonical);
            ea_t cb_ea = literal_callback_arg(expr, idx);
            if (cb_ea == BADADDR)
                return 0;
            if (!ea_is_function(cb_ea))
                return 0;

            vuln_finding_t f;
            std::ostringstream id;
            id << "vuln/callback_register/" << std::hex << std::uppercase
               << static_cast<std::uint64_t>(expr->ea);
            f.id = id.str();
            f.primary_ea = expr->ea;
            f.related_eas.push_back(cb_ea);
            cwe_t cwe = cwe_for_callback(canonical);
            if (cwe.id != 0)
                f.cwes.push_back(cwe);
            f.severity   = security_sensitive_callback_api(canonical) ? severity_t::low : severity_t::info;
            f.confidence = confidence_t::likely;
            std::ostringstream tt;
            tt << "Function-pointer registration: " << canonical << "(... &"
               << func_name_for(cb_ea) << ")";
            f.title = tt.str();
            std::ostringstream rat;
            rat << "Call to " << canonical << " at " << ea_to_hex(expr->ea)
                << " registers literal callback " << ea_to_hex(cb_ea)
                << " (" << func_name_for(cb_ea) << ")";
            f.rationale = rat.str();
            json ev;
            ev["api"]              = canonical;
            ev["call_ea"]          = ea_to_hex(expr->ea);
            ev["callback_ea"]      = ea_to_hex(cb_ea);
            ev["callback_name"]    = func_name_for(cb_ea);
            ev["callback_arg_idx"] = idx;
            f.evidence = std::move(ev);
            findings->push_back(std::move(f));
        }
        else if (expr->op == cot_asg && expr->x != nullptr && expr->y != nullptr)
        {
            const cexpr_t* lhs = unwrap_cast_ref(expr->x);
            if (lhs != nullptr && (lhs->op == cot_idx || lhs->op == cot_memptr || lhs->op == cot_memref))
            {
                qstring lhs_text;
                expr->x->print1(&lhs_text, cfunc);
                tag_remove(&lhs_text);
                std::string ls(lhs_text.c_str());
                std::string lower_ls = ascii_lower(ls);
                if (lower_ls.find("majorfunction") != std::string::npos)
                {
                    const cexpr_t* rhs = unwrap_cast_ref(expr->y);
                    ea_t cb_ea = BADADDR;
                    if (rhs != nullptr)
                    {
                        if (rhs->op == cot_obj)
                            cb_ea = rhs->obj_ea;
                    }
                    if (cb_ea != BADADDR && ea_is_function(cb_ea))
                    {
                        vuln_finding_t f;
                        std::ostringstream id;
                        id << "vuln/callback_register/major_function/" << std::hex << std::uppercase
                           << static_cast<std::uint64_t>(expr->ea);
                        f.id = id.str();
                        f.primary_ea = expr->ea;
                        f.related_eas.push_back(cb_ea);
                        f.cwes.push_back(make_cwe(358, cwe_name_for(358)));
                        f.severity   = severity_t::low;
                        f.confidence = confidence_t::likely;
                        std::ostringstream tt;
                        tt << "Function-pointer registration: DriverObject->MajorFunction[*] = &"
                           << func_name_for(cb_ea);
                        f.title = tt.str();
                        std::ostringstream rat;
                        rat << "Assignment at " << ea_to_hex(expr->ea)
                            << " stores literal callback " << ea_to_hex(cb_ea)
                            << " (" << func_name_for(cb_ea) << ") into a DriverObject MajorFunction slot";
                        f.rationale = rat.str();
                        json ev;
                        ev["assignment_ea"] = ea_to_hex(expr->ea);
                        ev["callback_ea"]   = ea_to_hex(cb_ea);
                        ev["callback_name"] = func_name_for(cb_ea);
                        ev["lhs"]           = ls;
                        f.evidence = std::move(ev);
                        findings->push_back(std::move(f));
                    }
                }
            }
        }

        if (findings->size() >= limit)
            return 1;
        return 0;
    }
};

}

std::vector<vuln_finding_t> enumerate_callbacks()
{
    std::vector<vuln_finding_t> out;
    if (!init_hexrays_plugin())
        return out;

    auto apis = known_callback_apis();
    std::unordered_set<std::string> api_index;
    for (auto& a : apis)
        api_index.insert(a);

    std::vector<callsite_t> calls = aida::vuln::callsites::all_calls_to(apis);
    std::unordered_set<ea_t> caller_funcs;
    for (const auto& cs : calls)
    {
        if (cs.func_ea != BADADDR)
            caller_funcs.insert(cs.func_ea);
    }

    const std::size_t limit = 1024;

    if (aida::vuln::kernel_engine::is_kernel_driver())
    {
        const std::size_t fq = get_func_qty();
        for (std::size_t i = 0; i < fq && caller_funcs.size() < static_cast<std::size_t>(kMaxScannableFuncs); ++i)
        {
            func_t* pfn = getn_func(i);
            if (pfn == nullptr)
                continue;
            caller_funcs.insert(pfn->start_ea);
        }
    }

    for (ea_t fea : caller_funcs)
    {
        if (out.size() >= limit)
            break;
        cfuncptr_t cf = decompile_safe(fea);
        if (!cf)
            continue;
        callback_visitor_t v(cf.operator->(), &out, &api_index, limit);
        v.apply_to(&cf->body, nullptr);
    }

    return out;
}

namespace
{

vuln_finding_t make_wxe_segment_finding(const segment_t& s, const std::string& name)
{
    vuln_finding_t f;
    std::ostringstream id;
    id << "vuln/wx_segment/" << std::hex << std::uppercase
       << static_cast<std::uint64_t>(s.start_ea);
    f.id = id.str();
    f.primary_ea = s.start_ea;
    f.related_eas.push_back(s.end_ea);
    f.cwes.push_back(make_cwe(1188, cwe_name_for(1188)));
    f.severity   = severity_t::critical;
    f.confidence = confidence_t::confirmed;
    std::ostringstream tt;
    tt << "Writable+executable segment: " << (name.empty() ? std::string("<unnamed>") : name);
    f.title = tt.str();
    std::ostringstream rat;
    rat << "Segment '" << name << "' [" << ea_to_hex(s.start_ea) << ", "
        << ea_to_hex(s.end_ea) << ") has both SEGPERM_EXEC and SEGPERM_WRITE set, "
        << "violating W^X policy and providing a primitive for code injection or self-modification.";
    f.rationale = rat.str();
    json ev;
    ev["segment_name"]   = name;
    ev["start_ea"]       = ea_to_hex(s.start_ea);
    ev["end_ea"]         = ea_to_hex(s.end_ea);
    ev["perm"]           = static_cast<int>(s.perm);
    ev["perm_exec"]      = (s.perm & SEGPERM_EXEC)  != 0;
    ev["perm_write"]     = (s.perm & SEGPERM_WRITE) != 0;
    ev["perm_read"]      = (s.perm & SEGPERM_READ)  != 0;
    ev["source"]         = "segment";
    f.evidence = std::move(ev);
    return f;
}

vuln_finding_t make_wxe_pe_section_finding(ea_t base, ea_t va, ea_t end_va,
                                           const std::string& name, std::uint32_t chars)
{
    vuln_finding_t f;
    std::ostringstream id;
    id << "vuln/wx_pe_section/" << std::hex << std::uppercase
       << static_cast<std::uint64_t>(va);
    f.id = id.str();
    f.primary_ea = va;
    f.related_eas.push_back(base);
    f.related_eas.push_back(end_va);
    f.cwes.push_back(make_cwe(1188, cwe_name_for(1188)));
    f.severity   = severity_t::critical;
    f.confidence = confidence_t::confirmed;
    std::ostringstream tt;
    tt << "Writable+executable PE section: " << (name.empty() ? std::string("<unnamed>") : name);
    f.title = tt.str();
    std::ostringstream rat;
    rat << "PE section '" << name << "' has both IMAGE_SCN_MEM_EXECUTE (0x20000000) and "
        << "IMAGE_SCN_MEM_WRITE (0x80000000) set in characteristics (0x"
        << std::hex << std::uppercase << chars << ").";
    f.rationale = rat.str();
    json ev;
    ev["section_name"]    = name;
    ev["va"]              = ea_to_hex(va);
    ev["end_va"]          = ea_to_hex(end_va);
    ev["characteristics"] = chars;
    ev["execute_bit"]     = true;
    ev["write_bit"]       = true;
    ev["source"]          = "pe_header";
    f.evidence = std::move(ev);
    return f;
}

}

std::vector<vuln_finding_t> find_writable_executable_pages()
{
    std::vector<vuln_finding_t> out;

    const int qty = get_segm_qty();
    for (int i = 0; i < qty; ++i)
    {
        segment_t* s = getnseg(i);
        if (s == nullptr)
            continue;
        if (s->perm == 0)
            continue;
        if ((s->perm & SEGPERM_EXEC) == 0 || (s->perm & SEGPERM_WRITE) == 0)
            continue;
        qstring nm;
        std::string name;
        if (get_segm_name(&nm, s, 0) > 0 && !nm.empty())
            name = nm.c_str();
        out.push_back(make_wxe_segment_finding(*s, name));
    }

    ea_t base = get_imagebase();
    if (is_loaded(base) && get_word(base) == 0x5A4D)
    {
        std::uint32_t pe_off = get_dword(base + 0x3C);
        ea_t pe_hdr = base + pe_off;
        if (is_loaded(pe_hdr) && get_dword(pe_hdr) == 0x00004550)
        {
            ea_t coff = pe_hdr + 4;
            std::uint16_t num_sections = get_word(coff + 2);
            std::uint16_t opt_size     = get_word(coff + 16);
            ea_t opt = coff + 20;
            ea_t sec_tbl = opt + opt_size;
            for (int si = 0; si < static_cast<int>(num_sections); ++si)
            {
                ea_t sec = sec_tbl + si * 40;
                if (!is_loaded(sec))
                    break;
                char sname[9] = {};
                for (int jj = 0; jj < 8; ++jj)
                    sname[jj] = static_cast<char>(get_byte(sec + jj));
                std::uint32_t vsize = get_dword(sec + 8);
                std::uint32_t vrva  = get_dword(sec + 12);
                std::uint32_t chars = get_dword(sec + 36);
                if (((chars & 0x20000000u) != 0) && ((chars & 0x80000000u) != 0))
                {
                    ea_t va     = base + vrva;
                    ea_t end_va = va + vsize;
                    out.push_back(make_wxe_pe_section_finding(base, va, end_va,
                                                              std::string(sname), chars));
                }
            }
        }
    }

    return out;
}

namespace
{

template <typename ArrayT>
void append_source_names_surface(std::vector<std::string>& out, const ArrayT& arr)
{
    for (const auto& s : arr)
        out.emplace_back(s.name);
}

template <typename ArrayT>
void append_sink_names_surface(std::vector<std::string>& out, const ArrayT& arr)
{
    for (const auto& s : arr)
        out.emplace_back(s.name);
}

std::vector<std::string> all_endpoint_names_for_kind(const std::string& kind)
{
    std::vector<std::string> names;
    const std::string k = ascii_lower(kind);
    if (k.empty() || k == "all" || k == "rpc")
        append_source_names_surface(names, sig::RPC_SERVER_SINKS);
    if (k.empty() || k == "all" || k == "com")
        append_source_names_surface(names, sig::COM_SERVER_SINKS);
    if (k.empty() || k == "all" || k == "alpc")
        append_source_names_surface(names, sig::ALPC_SOURCES);
    if (k.empty() || k == "all" || k == "pipe")
        append_source_names_surface(names, sig::NAMED_PIPE_SOURCES);
    if (k.empty() || k == "all" || k == "socket")
        append_source_names_surface(names, sig::SOCKET_ACCEPT_SOURCES);
    if (k.empty() || k == "all" || k == "http")
        append_source_names_surface(names, sig::HTTP_SERVER_SOURCES);
    if (k.empty() || k == "all" || k == "websocket")
        append_source_names_surface(names, sig::WEBSOCKET_SOURCES);
    if (k.empty() || k == "all" || k == "wsk" || k == "ndis")
        append_source_names_surface(names, sig::NDIS_WSK_SOURCES);
    std::sort(names.begin(), names.end());
    names.erase(std::unique(names.begin(), names.end()), names.end());
    return names;
}

std::vector<std::string> all_sink_names_surface()
{
    std::vector<std::string> names;
    append_sink_names_surface(names, sig::BUFFER_OVERFLOW_SINKS);
    append_sink_names_surface(names, sig::COMMAND_INJECTION_SINKS);
    append_sink_names_surface(names, sig::PATH_TRAVERSAL_SINKS);
    append_sink_names_surface(names, sig::FORMAT_STRING_FUNCS);
    append_sink_names_surface(names, sig::SAFEARRAY_PARSER_SINKS);
    append_sink_names_surface(names, sig::DESERIALIZATION_SINKS);
    std::sort(names.begin(), names.end());
    names.erase(std::unique(names.begin(), names.end()), names.end());
    return names;
}

bool kind_allowed(const std::vector<std::string>& kinds, const std::string& kind)
{
    if (kinds.empty())
        return true;
    for (const auto& k : kinds)
    {
        const std::string lk = ascii_lower(k);
        if (lk == "all" || lk == ascii_lower(kind))
            return true;
    }
    return false;
}

ea_t read_ptr_surface(ea_t ea)
{
    if (ea == BADADDR || !is_loaded(ea))
        return BADADDR;
    return inf_is_64bit() ? static_cast<ea_t>(get_qword(ea)) : static_cast<ea_t>(get_dword(ea));
}

bool valid_func_start_surface(ea_t ea)
{
    if (ea == BADADDR || !is_loaded(ea))
        return false;
    func_t* pfn = get_func(ea);
    return pfn != nullptr && pfn->start_ea == ea;
}

ea_t object_arg_at_call(ea_t func_ea, ea_t call_ea, int arg_idx)
{
    cfuncptr_t cf = decompile_safe(func_ea);
    if (!cf)
        return BADADDR;
    ea_t out = BADADDR;
    call_visitor_t v(cf.operator->(), [&](cexpr_t* e) -> int {
        if (e == nullptr || e->ea != call_ea || e->a == nullptr || arg_idx < 0 ||
            static_cast<std::size_t>(arg_idx) >= e->a->size())
        {
            return 0;
        }
        const cexpr_t* arg = static_cast<const cexpr_t*>(&(*e->a)[arg_idx]);
        arg = unwrap_cast_ref(arg);
        if (arg != nullptr && arg->op == cot_obj)
        {
            out = arg->obj_ea;
            return 1;
        }
        return 0;
    });
    v.apply_to(&cf->body, nullptr);
    return out;
}

std::vector<ea_t> decode_rpc_handler_table(ea_t table_ea, bool& partial, json& evidence)
{
    std::vector<ea_t> handlers;
    if (table_ea == BADADDR || !is_loaded(table_ea))
        return handlers;
    const ea_t ptrsz = inf_is_64bit() ? 8 : 4;
    uint32_t count = get_dword(table_ea);
    ea_t ptr_array = read_ptr_surface(table_ea + ptrsz);
    if (count > 0 && count <= 256 && ptr_array != BADADDR && is_loaded(ptr_array))
    {
        for (uint32_t i = 0; i < count; ++i)
        {
            ea_t h = read_ptr_surface(ptr_array + static_cast<ea_t>(i) * ptrsz);
            if (!valid_func_start_surface(h))
            {
                partial = true;
                continue;
            }
            handlers.push_back(h);
        }
        if (!handlers.empty())
        {
            evidence["rpc_dispatch_table_ea"] = ea_to_hex(table_ea);
            evidence["rpc_dispatch_count"] = count;
            evidence["rpc_dispatch_array_ea"] = ea_to_hex(ptr_array);
            return handlers;
        }
    }
    for (int i = 0; i < 64 && static_cast<int>(handlers.size()) < 256; ++i)
    {
        ea_t h = read_ptr_surface(table_ea + static_cast<ea_t>(i) * ptrsz);
        if (!valid_func_start_surface(h))
        {
            if (!handlers.empty())
                break;
            continue;
        }
        handlers.push_back(h);
    }
    if (!handlers.empty())
    {
        evidence["rpc_dispatch_table_ea"] = ea_to_hex(table_ea);
        evidence["rpc_layout"] = "direct_function_pointer_array";
    }
    return handlers;
}

std::vector<ea_t> decode_rpc_handlers_from_interface(ea_t interface_ea, bool& partial, json& evidence)
{
    std::vector<ea_t> handlers;
    if (interface_ea == BADADDR || !is_loaded(interface_ea))
        return handlers;
    evidence["rpc_interface_ea"] = ea_to_hex(interface_ea);
    const ea_t ptrsz = inf_is_64bit() ? 8 : 4;
    const std::vector<ea_t> offsets = {
        ptrsz * 4, ptrsz * 5, ptrsz * 6, ptrsz * 7,
        0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60,
    };
    std::set<ea_t> seen;
    for (ea_t off : offsets)
    {
        ea_t candidate = read_ptr_surface(interface_ea + off);
        if (candidate == BADADDR || !seen.insert(candidate).second)
            continue;
        bool local_partial = false;
        json local_ev = evidence;
        std::vector<ea_t> h = decode_rpc_handler_table(candidate, local_partial, local_ev);
        if (!h.empty())
        {
            partial = partial || local_partial;
            evidence = std::move(local_ev);
            handlers.insert(handlers.end(), h.begin(), h.end());
        }
    }
    std::sort(handlers.begin(), handlers.end());
    handlers.erase(std::unique(handlers.begin(), handlers.end()), handlers.end());
    return handlers;
}

json endpoint_record(const std::string& kind,
                     const std::string& name,
                     ea_t register_ea,
                     ea_t handler_ea,
                     const json& evidence)
{
    json e;
    e["kind"] = kind;
    e["name"] = name;
    e["register_ea"] = ea_to_hex(register_ea);
    e["handler_ea"] = ea_to_hex(handler_ea);
    e["handler_name"] = func_name_for(handler_ea);
    e["evidence"] = evidence;
    return e;
}

std::string surface_cache_key(const std::string& suffix)
{
    return current_md5_token() + "|sig=" + std::to_string(sig::SIGNATURE_DATABASE_REVISION) +
           "|chg=" + std::to_string(inf_get_database_change_count()) + "|" + suffix;
}

std::optional<json> surface_cache_get(const std::string& key)
{
    netnode n("$ AiDA.dispatch.cache", 0, true);
    if (n == BADNODE)
        return std::nullopt;
    qstring out;
    if (n.hashstr(&out, key.c_str(), 'S') <= 0)
        return std::nullopt;
    try
    {
        return json::parse(out.c_str());
    }
    catch (...)
    {
        return std::nullopt;
    }
}

void surface_cache_put(const std::string& key, const json& data)
{
    netnode n("$ AiDA.dispatch.cache", 0, true);
    if (n == BADNODE)
        return;
    const std::string dump = data.dump();
    n.hashset(key.c_str(), dump.c_str(), dump.size() + 1, 'S');
}

json endpoint_calls_for_kind(const std::string& kind)
{
    json arr = json::array();
    std::vector<std::string> names = all_endpoint_names_for_kind(kind);
    std::vector<callsite_t> calls = aida::vuln::callsites::all_calls_to(names);
    for (const auto& cs : calls)
    {
        if (cs.func_ea == BADADDR)
            continue;
        json ev;
        ev["source"] = "callsite";
        ev["callee"] = cs.callee_name;
        ev["callsite"] = to_json(cs);
        arr.push_back(endpoint_record(kind, cs.callee_name, cs.call_ea, cs.func_ea, ev));
    }
    return arr;
}

json enumerate_rpc_servers_impl()
{
    json arr = json::array();
    std::vector<std::string> names = all_endpoint_names_for_kind("rpc");
    std::vector<callsite_t> calls = aida::vuln::callsites::all_calls_to(names);
    for (const auto& cs : calls)
    {
        if (cs.func_ea == BADADDR)
            continue;
        bool partial = false;
        json ev;
        ev["source"] = "rpc_register_callsite";
        ev["callee"] = cs.callee_name;
        ea_t iface = object_arg_at_call(cs.func_ea, cs.call_ea, 0);
        std::vector<ea_t> handlers = decode_rpc_handlers_from_interface(iface, partial, ev);
        ev["partial"] = partial || handlers.empty();
        if (handlers.empty())
        {
            ev["fallback"] = "dispatch_table_not_resolved_valid_func_t";
            arr.push_back(endpoint_record("rpc", cs.callee_name, cs.call_ea, cs.func_ea, ev));
            continue;
        }
        for (ea_t h : handlers)
            arr.push_back(endpoint_record("rpc", cs.callee_name, cs.call_ea, h, ev));
    }
    return arr;
}

json enumerate_com_servers_impl()
{
    json arr = endpoint_calls_for_kind("com");
    for (size_t i = 0; i < get_entry_qty(); ++i)
    {
        uval_t ord = get_entry_ordinal(i);
        ea_t ea = get_entry(ord);
        if (ea == BADADDR)
            continue;
        qstring nm;
        if (get_entry_name(&nm, ord) <= 0 || nm.empty())
            continue;
        std::string n = nm.c_str();
        if (!name_matches_signature(n, "DllGetClassObject") && !name_matches_signature(n, "DllRegisterServer"))
            continue;
        json ev;
        ev["source"] = "export";
        ev["export_name"] = n;
        arr.push_back(endpoint_record("com", n, ea, ea, ev));
    }
    return arr;
}

json enumerate_network_listeners_impl()
{
    json arr = json::array();
    for (const char* kind : {"socket", "http", "pipe", "websocket", "wsk"})
    {
        json part = endpoint_calls_for_kind(kind);
        for (auto& e : part)
            arr.push_back(std::move(e));
    }
    return arr;
}

json enumerate_alpc_servers_impl()
{
    return endpoint_calls_for_kind("alpc");
}

json all_ipc_endpoints_uncached(const std::vector<std::string>& kinds)
{
    json arr = json::array();
    if (kind_allowed(kinds, "rpc"))
    {
        json p = enumerate_rpc_servers_impl();
        for (auto& e : p) arr.push_back(std::move(e));
    }
    if (kind_allowed(kinds, "com"))
    {
        json p = enumerate_com_servers_impl();
        for (auto& e : p) arr.push_back(std::move(e));
    }
    if (kind_allowed(kinds, "alpc"))
    {
        json p = enumerate_alpc_servers_impl();
        for (auto& e : p) arr.push_back(std::move(e));
    }
    if (kind_allowed(kinds, "socket") || kind_allowed(kinds, "http") || kind_allowed(kinds, "pipe") ||
        kind_allowed(kinds, "websocket") || kind_allowed(kinds, "wsk"))
    {
        json p = enumerate_network_listeners_impl();
        for (auto& e : p)
        {
            std::string k = e.value("kind", std::string());
            if (kind_allowed(kinds, k))
                arr.push_back(std::move(e));
        }
    }
    if (kind_allowed(kinds, "kernel") || kind_allowed(kinds, "kernel_irp") || kind_allowed(kinds, "ioctl"))
    {
        for (const auto& h : aida::vuln::kernel_engine::find_ioctl_handlers())
        {
            json ev;
            ev["source"] = h.source_model.empty() ? "kernel_ioctl" : h.source_model;
            ev["handler_source_evidence"] = h.evidence;
            ev["fallback_metadata"] = h.fallback_metadata;
            arr.push_back(endpoint_record("kernel_irp", "IRP_MJ_DEVICE_CONTROL", h.handler_ea, h.handler_ea, ev));
        }
    }
    return arr;
}

std::vector<std::string> json_string_array_param(const json& params, const char* key)
{
    std::vector<std::string> out;
    if (!params.is_object())
        return out;
    auto it = params.find(key);
    if (it == params.end() || it->is_null())
        return out;
    if (it->is_string())
    {
        out.push_back(it->get<std::string>());
        return out;
    }
    if (it->is_array())
    {
        for (const auto& v : *it)
        {
            if (v.is_string())
                out.push_back(v.get<std::string>());
        }
    }
    return out;
}

bool json_bool_param_surface(const json& params, const char* key, bool fallback)
{
    if (!params.is_object())
        return fallback;
    auto it = params.find(key);
    if (it == params.end() || it->is_null())
        return fallback;
    if (it->is_boolean())
        return it->get<bool>();
    if (it->is_number_integer())
        return it->get<std::int64_t>() != 0;
    if (it->is_number_unsigned())
        return it->get<std::uint64_t>() != 0;
    return fallback;
}

int json_int_param_surface(const json& params, const char* key, int fallback)
{
    if (!params.is_object())
        return fallback;
    auto it = params.find(key);
    if (it == params.end() || it->is_null())
        return fallback;
    try
    {
        if (it->is_number_integer())
        {
            const std::int64_t value = it->get<std::int64_t>();
            if (value < (std::numeric_limits<int>::min)() || value > (std::numeric_limits<int>::max)())
                return fallback;
            return static_cast<int>(value);
        }
        if (it->is_number_unsigned())
        {
            const std::uint64_t value = it->get<std::uint64_t>();
            if (value > static_cast<std::uint64_t>((std::numeric_limits<int>::max)()))
                return fallback;
            return static_cast<int>(value);
        }
        if (it->is_number())
        {
            const double value = it->get<double>();
            if (!std::isfinite(value) || value < (std::numeric_limits<int>::min)() || value > (std::numeric_limits<int>::max)())
                return fallback;
            return static_cast<int>(value);
        }
        if (it->is_string())
            return std::stoi(it->get<std::string>());
    }
    catch (...)
    {
        return fallback;
    }
    return fallback;
}

std::string extract_snippet_at(cfunc_t* cf, ea_t ea)
{
    if (cf == nullptr || ea == BADADDR)
        return std::string();
    citem_t* it = cf->body.find_closest_addr(ea);
    if (it == nullptr)
        return std::string();
    qstring out;
    if (it->is_expr())
        static_cast<cexpr_t*>(it)->print1(&out, cf);
    else
        static_cast<cinsn_t*>(it)->print1(&out, cf);
    tag_remove(&out);
    std::string s(out.c_str());
    if (s.size() > 200)
    {
        s.resize(197);
        s.append("...");
    }
    return s;
}

int block_containing_ea_surface(const qflow_chart_t& fc, ea_t ea)
{
    int qty = fc.size();
    for (int i = 0; i < qty; ++i)
    {
        const qbasic_block_t& bb = fc.blocks[i];
        if (ea >= bb.start_ea && ea < bb.end_ea)
            return i;
    }
    return -1;
}

bool auth_free_path_exists(func_t* pfn, const std::vector<ea_t>& auth_call_eas)
{
    if (pfn == nullptr)
        return true;
    if (auth_call_eas.empty())
        return true;
    qflow_chart_t fc;
    fc.create("", pfn, BADADDR, BADADDR, FC_RESERVED);
    int qty = fc.size();
    if (qty <= 0)
        return true;
    std::unordered_set<int> auth_blocks;
    for (ea_t ea : auth_call_eas)
    {
        int b = block_containing_ea_surface(fc, ea);
        if (b >= 0)
            auth_blocks.insert(b);
    }
    if (auth_blocks.empty())
        return true;
    if (auth_blocks.count(0) != 0)
        return false;
    std::deque<int> q;
    std::unordered_set<int> seen;
    q.push_back(0);
    seen.insert(0);
    while (!q.empty())
    {
        int cur = q.front();
        q.pop_front();
        int succ_n = fc.nsucc(cur);
        if (succ_n == 0)
            return true;
        for (int i = 0; i < succ_n; ++i)
        {
            int next = fc.succ(cur, i);
            if (next < 0 || next >= qty)
                continue;
            if (auth_blocks.count(next) != 0)
                continue;
            if (!seen.insert(next).second)
                continue;
            q.push_back(next);
        }
    }
    return false;
}

}

json fingerprint_binary_attack_profile()
{
    json data;
    data["filetype"] = static_cast<int>(inf_get_filetype());
    data["is_dll"] = inf_is_dll();
    data["is_kernel"] = aida::vuln::kernel_engine::is_kernel_driver() || inf_is_kernel_mode();
    data["bitness"] = inf_get_app_bitness();
    data["min_ea"] = ea_to_hex(inf_get_min_ea());
    data["max_ea"] = ea_to_hex(inf_get_max_ea());
    data["processor"] = std::string(inf_get_procname().c_str());
    json evidence = json::array();
    for (const char* kind : {"rpc", "com", "alpc", "socket", "http", "pipe", "websocket", "wsk"})
    {
        std::vector<std::string> names = all_endpoint_names_for_kind(kind);
        std::vector<callsite_t> calls = aida::vuln::callsites::all_calls_to(names);
        if (!calls.empty())
        {
            json e;
            e["kind"] = kind;
            e["callsite_count"] = calls.size();
            evidence.push_back(std::move(e));
        }
    }
    data["evidence"] = evidence;
    data["suspected_endpoints"] = enumerate_ipc_endpoints({"all"})["endpoints"];
    data["has_auth_layer"] = !aida::vuln::callsites::all_calls_to(std::vector<std::string>{
        "AccessCheck", "SeAccessCheck", "RpcImpersonateClient", "CoImpersonateClient",
        "AcceptSecurityContext", "PrivilegeCheck"}).empty();
    std::string kind = "library_or_local_tool";
    if (data["is_kernel"].get<bool>())
        kind = "kernel_driver";
    else if (!data["suspected_endpoints"].empty())
        kind = "server_or_ipc_component";
    data["kind"] = kind;
    return data;
}

json enumerate_ipc_endpoints(const std::vector<std::string>& kinds)
{
    const std::string key = surface_cache_key("ipc_endpoints|" + json(kinds).dump());
    if (auto cached = surface_cache_get(key); cached.has_value())
    {
        (*cached)["cached"] = true;
        return *cached;
    }
    json endpoints = all_ipc_endpoints_uncached(kinds);
    json data;
    data["endpoints"] = std::move(endpoints);
    data["count"] = data["endpoints"].size();
    data["cached"] = false;
    surface_cache_put(key, data);
    return data;
}

json compute_pre_auth_handler_set()
{
    json endpoints = enumerate_ipc_endpoints({"all"})["endpoints"];
    json arr = json::array();
    for (const auto& ep : endpoints)
    {
        std::string hs = ep.value("handler_ea", std::string());
        ea_t h = resolve_address_or_name(hs);
        if (h == BADADDR)
            continue;
        func_t* pfn = get_func(h);
        if (pfn == nullptr)
            continue;
        h = pfn->start_ea;
        aida::vuln::callsites::validator_summary_t sum = aida::vuln::callsites::summarize_validators_in_function(h);
        bool has_auth = !sum.auth_gates_seen.empty();
        bool auth_free = auth_free_path_exists(pfn, sum.auth_gate_call_eas);
        json r;
        r["handler_ea"] = ea_to_hex(h);
        r["handler_name"] = func_name_for(h);
        r["source_endpoint"] = ep;
        r["dominates_no_auth_check"] = auth_free;
        r["auth_free_path_exists"] = auth_free;
        r["auth_call_eas"] = json::array();
        for (ea_t e : sum.auth_gate_call_eas)
            r["auth_call_eas"].push_back(ea_to_hex(e));
        r["rationale"] = has_auth
            ? (auth_free ? "qflow_path_avoids_auth_gate_block" : "auth_gate_block_intercepts_all_qflow_paths")
            : "no_auth_gate_helper_seen_in_handler";
        arr.push_back(std::move(r));
    }
    json data;
    data["handlers"] = std::move(arr);
    data["count"] = data["handlers"].size();
    return data;
}

json enumerate_handler_reachable_sinks(ea_t handler_ea, int max_depth, int max_hits)
{
    if (max_depth <= 0)
        max_depth = 6;
    if (max_depth > 16)
        max_depth = 16;
    if (max_hits <= 0)
        max_hits = 64;
    if (max_hits > 512)
        max_hits = 512;
    func_t* pfn = get_func(handler_ea);
    json data;
    data["handler_ea"] = ea_to_hex(handler_ea);
    data["sinks"] = json::array();
    if (pfn == nullptr)
        return data;
    handler_ea = pfn->start_ea;
    std::vector<callsite_t> sinks = aida::vuln::callsites::all_calls_to(all_sink_names_surface());
    std::unordered_map<ea_t, std::vector<callsite_t>> by_func;
    for (const auto& cs : sinks)
        by_func[cs.func_ea].push_back(cs);
    const call_graph_t& g = cached_call_graph();
    std::deque<std::pair<ea_t, int>> q;
    std::unordered_set<ea_t> seen;
    q.push_back({handler_ea, 0});
    seen.insert(handler_ea);
    while (!q.empty())
    {
        auto [cur, depth] = q.front();
        q.pop_front();
        auto hit = by_func.find(cur);
        if (hit != by_func.end())
        {
            aida::vuln::callsites::validator_summary_t sum = aida::vuln::callsites::summarize_validators_in_function(cur);
            for (const auto& cs : hit->second)
            {
                json s = to_json(cs);
                s["caller_name"] = func_name_for(cur);
                s["depth"] = depth;
                s["validators_seen"] = sum.validators_seen;
                s["auth_gates_seen"] = sum.auth_gates_seen;
                data["sinks"].push_back(std::move(s));
                if (static_cast<int>(data["sinks"].size()) >= max_hits)
                {
                    data["truncated"] = true;
                    data["count"] = data["sinks"].size();
                    return data;
                }
            }
        }
        if (depth >= max_depth)
            continue;
        auto it = g.callees.find(cur);
        if (it == g.callees.end())
            continue;
        for (ea_t next : it->second)
        {
            if (!seen.insert(next).second)
                continue;
            q.push_back({next, depth + 1});
        }
    }
    data["truncated"] = false;
    data["count"] = data["sinks"].size();
    return data;
}

json classify_exploit_primitive(ea_t sink_ea)
{
    json data;
    data["sink_ea"] = ea_to_hex(sink_ea);
    data["primitive"] = "unknown";
    func_t* pfn = get_func(sink_ea);
    if (pfn == nullptr)
        return data;
    data["sink_func_ea"] = ea_to_hex(pfn->start_ea);
    data["sink_func_name"] = func_name_for(pfn->start_ea);
    std::string callee;
    for (const auto& ci : aida::vuln::callsites::per_function_call_index(pfn->start_ea))
    {
        if (ci.call_ea == sink_ea)
        {
            callee = ci.callee_name;
            break;
        }
    }
    data["callee"] = callee;
    std::string primitive = "unknown";
    for (const auto& s : sig::COMMAND_INJECTION_SINKS)
        if (name_matches_signature(callee, s.name)) primitive = "command_injection";
    for (const auto& s : sig::PATH_TRAVERSAL_SINKS)
        if (name_matches_signature(callee, s.name)) primitive = "path_traversal";
    for (const auto& s : sig::FORMAT_STRING_FUNCS)
        if (name_matches_signature(callee, s.name)) primitive = "format_string_write";
    for (const auto& s : sig::DESERIALIZATION_SINKS)
        if (name_matches_signature(callee, s.name)) primitive = "type_confusion";
    for (const auto& s : sig::BUFFER_OVERFLOW_SINKS)
    {
        if (name_matches_signature(callee, s.name))
        {
            asize_t frame_size = get_frame_size(pfn);
            primitive = frame_size > 0 ? "stack_overflow" : "heap_overflow";
        }
    }
    data["primitive"] = primitive;
    data["frame_size"] = static_cast<std::uint64_t>(get_frame_size(pfn));
    data["rationale"] = "classified_from_sink_signature_and_function_frame_metadata";
    return data;
}

json find_protocol_routers(int min_cases, int max_results)
{
    if (min_cases <= 0)
        min_cases = 4;
    if (max_results <= 0)
        max_results = 64;
    if (max_results > 512)
        max_results = 512;
    std::vector<aida::vuln::cfg_engine::switch_dispatch_t> switches = aida::vuln::cfg_engine::enumerate_switch_dispatch(BADADDR);
    json arr = json::array();
    for (const auto& sw : switches)
    {
        if (sw.ncases < min_cases)
            continue;
        json r;
        r["router_ea"] = ea_to_hex(sw.jmp_ea);
        r["tag_offset"] = -1;
        r["case_count"] = sw.ncases;
        r["handlers"] = json::array();
        std::set<ea_t> handlers;
        for (const auto& c : sw.cases)
            if (c.handler_func_ea != BADADDR)
                handlers.insert(c.handler_func_ea);
        int max_sinks = 0;
        for (ea_t h : handlers)
        {
            r["handlers"].push_back(ea_to_hex(h));
            json sinks = enumerate_handler_reachable_sinks(h, 4, 64);
            max_sinks = std::max(max_sinks, static_cast<int>(sinks.value("count", static_cast<std::size_t>(0))));
        }
        r["max_reachable_sinks"] = max_sinks;
        arr.push_back(std::move(r));
        if (static_cast<int>(arr.size()) >= max_results)
            break;
    }
    json data;
    data["routers"] = std::move(arr);
    data["count"] = data["routers"].size();
    return data;
}

json resolve_indirect_call_targets(ea_t call_ea)
{
    json arr = json::array();
    func_t* pfn = get_func(call_ea);
    if (pfn != nullptr)
    {
        for (const auto& ic : aida::vuln::cfg_engine::find_indirect_calls(pfn->start_ea))
        {
            if (ic.call_ea != call_ea)
                continue;
            for (const auto& t : ic.targets)
            {
                json e;
                e["target_ea"] = ea_to_hex(t.target_ea);
                e["name"] = t.name;
                e["source"] = t.source;
                e["rationale"] = t.rationale;
                e["confidence"] = t.target_ea == BADADDR ? "plausible" : "likely";
                arr.push_back(std::move(e));
            }
        }
    }
    json data;
    data["call_ea"] = ea_to_hex(call_ea);
    data["targets"] = std::move(arr);
    data["count"] = data["targets"].size();
    return data;
}

json explain_vulnerability_chain_v2(ea_t source_ea, ea_t sink_ea, bool require_pre_auth)
{
    json data;
    data["source_address"] = ea_to_hex(source_ea);
    data["sink_address"] = ea_to_hex(sink_ea);
    data["paths"] = json::array();
    std::vector<aida::vuln::taint::taint_path_t> paths = aida::vuln::taint::engine().trace_paths(source_ea, sink_ea, 8, 8);
    json preauth = compute_pre_auth_handler_set();
    bool pre_auth_clean = true;
    for (const auto& h : preauth["handlers"])
    {
        if (!h.value("dominates_no_auth_check", true))
            pre_auth_clean = false;
    }
    if (require_pre_auth && !pre_auth_clean)
    {
        data["pre_auth_clean"] = false;
        data["filtered"] = true;
        return data;
    }
    for (const auto& p : paths)
    {
        json pj = aida::vuln::taint::to_json(p);
        for (auto& step : pj["steps"])
            step["wire_field_offset"] = nullptr;
        data["paths"].push_back(std::move(pj));
    }
    data["pre_auth_clean"] = pre_auth_clean;
    data["total_paths"] = data["paths"].size();
    return data;
}

json hunt_remote_rce(int top_k, bool extract_constraints)
{
    if (top_k <= 0)
        top_k = 10;
    if (top_k > 50)
        top_k = 50;
    std::vector<json> candidates;
    json profile = fingerprint_binary_attack_profile();
    json preauth = compute_pre_auth_handler_set();
    for (const auto& h : preauth["handlers"])
    {
        if (!h.value("dominates_no_auth_check", false))
            continue;
        std::string handler_s = h.value("handler_ea", std::string());
        ea_t handler = resolve_address_or_name(handler_s);
        if (handler == BADADDR)
            continue;
        json sinks = enumerate_handler_reachable_sinks(handler, 6, 64);
        for (const auto& s : sinks["sinks"])
        {
            std::string sink_s = s.value("call_ea", std::string());
            ea_t sink = resolve_address_or_name(sink_s);
            json prim = classify_exploit_primitive(sink);
            std::string primitive = prim.value("primitive", std::string("unknown"));
            int score = 10;
            if (primitive == "command_injection") score += 90;
            else if (primitive == "stack_overflow" || primitive == "heap_overflow") score += 70;
            else if (primitive == "format_string_write") score += 65;
            else if (primitive == "type_confusion") score += 60;
            else if (primitive == "path_traversal") score += 25;
            json c;
            c["score"] = score;
            c["handler"] = h;
            c["sink"] = s;
            c["primitive"] = prim;
            c["rationale"] = "pre_auth_endpoint_reaches_dangerous_sink";
            if (extract_constraints)
                c["constraints"] = "external_hook_required: extract_wire_path_constraints";
            candidates.push_back(std::move(c));
        }
    }
    std::sort(candidates.begin(), candidates.end(), [](const json& a, const json& b) {
        return a.value("score", 0) > b.value("score", 0);
    });
    while (static_cast<int>(candidates.size()) > top_k)
        candidates.pop_back();
    json candidate_array = json::array();
    for (auto& c : candidates)
        candidate_array.push_back(std::move(c));
    json data;
    data["profile"] = profile;
    data["candidates"] = std::move(candidate_array);
    data["count"] = data["candidates"].size();
    return data;
}

json rank_attack_surface(int limit, const std::string& role_filter)
{
    if (limit <= 0)
        limit = 50;
    if (limit > 512)
        limit = 512;
    std::vector<attack_surface_score_t> scores;
    for (ea_t fea : attacker_reachable_functions())
    {
        attack_surface_score_t s = score_function(fea);
        if (!role_filter.empty() && role_filter != "all" && s.classification != role_filter)
            continue;
        scores.push_back(s);
    }
    std::sort(scores.begin(), scores.end(), [](const attack_surface_score_t& a, const attack_surface_score_t& b) {
        return a.total_score > b.total_score;
    });
    json arr = json::array();
    for (size_t i = 0; i < scores.size() && static_cast<int>(i) < limit; ++i)
    {
        const auto& s = scores[i];
        json r;
        r["func_ea"] = ea_to_hex(s.func_ea);
        r["func_name"] = func_name_for(s.func_ea);
        r["total_score"] = s.total_score;
        r["classification"] = s.classification;
        r["input_proximity"] = s.input_proximity;
        r["sink_count"] = s.sink_count;
        r["missing_validators"] = s.missing_validators;
        r["complexity"] = s.complexity;
        r["taint_paths"] = s.taint_paths;
        arr.push_back(std::move(r));
    }
    json data;
    data["functions"] = std::move(arr);
    data["count"] = data["functions"].size();
    return data;
}

json add_dynamic_taint_source(ea_t source_ea, const std::string& kind, const std::string& name)
{
    reset_dynamic_sources_if_idb_changed();
    func_t* pfn = get_func(source_ea);
    json data;
    data["added"] = false;
    if (pfn == nullptr)
    {
        data["reason"] = "no_function_at_addr";
        return data;
    }
    dynamic_source_t ds;
    ds.source_ea = source_ea;
    ds.func_ea = pfn->start_ea;
    ds.kind = kind.empty() ? "dynamic" : kind;
    ds.name = name.empty() ? func_name_for(pfn->start_ea) : name;
    dynamic_sources().push_back(ds);
    data["added"] = true;
    data["source_ea"] = ea_to_hex(ds.source_ea);
    data["func_ea"] = ea_to_hex(ds.func_ea);
    data["kind"] = ds.kind;
    data["name"] = ds.name;
    data["session_source_count"] = dynamic_sources().size();
    return data;
}

json enumerate_callbacks_extended()
{
    std::vector<vuln_finding_t> findings = enumerate_callbacks();
    json data;
    data["count"] = findings.size();
    data["findings"] = findings_to_json_array(findings);
    data["coverage"] = json::array({
        "WSK_PROVIDER_DISPATCH", "PsSetCreateProcessNotifyRoutine", "PsSetCreateThreadNotifyRoutine",
        "PsSetLoadImageNotifyRoutine", "CmRegisterCallback", "ObRegisterCallbacks",
        "PRINTPROVIDOR", "KeRegisterBugCheckCallback", "EtwRegister", "IoWMIRegistrationControl",
        "FltRegisterFilter"
    });
    return data;
}

namespace tools
{

namespace
{

agent_tools::tool_result_t handle_analyze_function_attack_surface(const json& params)
{
    auto addr = parse_addr_param(params, "address");
    if (!addr.has_value())
        return agent_tools::tool_result_t::error(std::string("address parameter is required"));
    ea_t fea = *addr;
    func_t* pfn = get_func(fea);
    if (pfn == nullptr)
        return agent_tools::tool_result_t::error(std::string("address does not lie inside a function"));
    fea = pfn->start_ea;

    attack_surface_score_t score;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        score = score_function(fea);
    }

    json data;
    data["func_ea"]            = ea_to_hex(score.func_ea);
    data["func_name"]          = func_name_for(score.func_ea);
    data["total_score"]        = score.total_score;
    data["input_proximity"]    = score.input_proximity;
    data["sink_count"]         = score.sink_count;
    data["missing_validators"] = score.missing_validators;
    data["complexity"]         = score.complexity;
    data["taint_paths"]        = score.taint_paths;
    data["classification"]     = score.classification;

    json breakdown = json::object();
    {
        json b = json::object();
        b["score"] = score.input_proximity;
        b["max"]   = 25;
        b["description"] = "Reachability from input sources via reverse call graph (depth <= 4)";
        breakdown["input_proximity"] = std::move(b);
    }
    {
        json b = json::object();
        b["score"] = score.sink_count;
        b["max"]   = 25;
        b["description"] = "Forward reachability to dangerous sinks via call graph (depth <= 4)";
        breakdown["sink_count"] = std::move(b);
    }
    {
        json b = json::object();
        b["score"] = score.missing_validators;
        b["max"]   = 20;
        b["description"] = "Tainted parameters that flow to sinks without validation";
        breakdown["missing_validators"] = std::move(b);
    }
    {
        json b = json::object();
        b["score"] = score.complexity;
        b["max"]   = 15;
        b["description"] = "log2(cyclomatic + 1) * 3, capped at 15";
        breakdown["complexity"] = std::move(b);
    }
    {
        json b = json::object();
        b["score"] = score.taint_paths;
        b["max"]   = 15;
        b["description"] = "Number of input-source x sink combinations on this function";
        breakdown["taint_paths"] = std::move(b);
    }
    data["breakdown"] = std::move(breakdown);

    std::ostringstream msg;
    msg << std::string("Attack-surface score: ") << score.total_score << std::string("/100 (")
        << score.classification << std::string(")");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

agent_tools::tool_result_t handle_list_attacker_reachable_functions(const json& params)
{
    int limit = extract_int_param(params, "limit", 200);
    if (limit <= 0) limit = 200;
    if (limit > 4096) limit = 4096;

    std::vector<ea_t> funcs;
    std::size_t total_sources = 0;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        funcs = attacker_reachable_functions();
        total_sources = input_source_callsites_safe().size();
    }

    json arr = json::array();
    int emitted = 0;
    for (ea_t fea : funcs)
    {
        if (emitted >= limit)
            break;
        json e;
        e["ea"]   = ea_to_hex(fea);
        e["name"] = func_name_for(fea);
        arr.push_back(std::move(e));
        emitted++;
    }

    json data;
    data["count"]               = static_cast<int>(funcs.size());
    data["limit"]               = limit;
    data["functions"]           = std::move(arr);
    data["total_input_sources"] = total_sources;

    std::ostringstream msg;
    msg << std::string("Attacker-reachable functions: ") << funcs.size();
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

agent_tools::tool_result_t handle_classify_function_role(const json& params)
{
    auto addr = parse_addr_param(params, "address");
    if (!addr.has_value())
        return agent_tools::tool_result_t::error(std::string("address parameter is required"));
    func_t* pfn = get_func(*addr);
    if (pfn == nullptr)
        return agent_tools::tool_result_t::error(std::string("address does not lie inside a function"));
    ea_t fea = pfn->start_ea;

    std::string role;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        role = classify_function_role(fea);
    }

    json data;
    data["func_ea"]   = ea_to_hex(fea);
    data["func_name"] = func_name_for(fea);
    data["role"]      = role;

    std::ostringstream msg;
    msg << std::string("Function role: ") << role;
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

agent_tools::tool_result_t handle_enumerate_callbacks(const json&)
{
    std::vector<vuln_finding_t> findings;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        findings = enumerate_callbacks();
    }
    json data;
    data["count"]    = findings.size();
    data["findings"] = findings_to_json_array(findings);
    std::ostringstream msg;
    msg << std::string("Callback registration scan: ") << findings.size() << std::string(" finding(s)");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

agent_tools::tool_result_t handle_find_writable_executable_pages(const json&)
{
    std::vector<vuln_finding_t> findings;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        findings = find_writable_executable_pages();
    }
    json data;
    data["count"]       = findings.size();
    data["findings"]    = findings_to_json_array(findings);
    data["primary_cwe"] = 1188;
    std::ostringstream msg;
    msg << std::string("W^X violation scan: ") << findings.size() << std::string(" finding(s)");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

agent_tools::tool_result_t handle_explain_vulnerability_chain(const json& params)
{
    const std::string source_spec = params.is_object() && params.contains("source_address") &&
                                    params["source_address"].is_string()
        ? params["source_address"].get<std::string>() : std::string();
    const std::string sink_spec = params.is_object() && params.contains("sink_address") &&
                                  params["sink_address"].is_string()
        ? params["sink_address"].get<std::string>() : std::string();
    if (source_spec.empty() || sink_spec.empty())
        return agent_tools::tool_result_t::error(std::string("source_address and sink_address required"));

    ea_t source_ea = resolve_address_or_name(source_spec);
    ea_t sink_ea   = resolve_address_or_name(sink_spec);
    if (source_ea == BADADDR)
        return agent_tools::tool_result_t::error(std::string("Could not resolve source address: ") + source_spec);
    if (sink_ea == BADADDR)
        return agent_tools::tool_result_t::error(std::string("Could not resolve sink address: ") + sink_spec);

    std::vector<aida::vuln::taint::taint_path_t> paths;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        paths = aida::vuln::taint::engine().trace_paths(source_ea, sink_ea, 8, 8);
    }

    json paths_arr = json::array();
    for (const auto& p : paths)
    {
        json pj;
        std::ostringstream md;
        md << "## Taint path from " << p.origin.source_name << " ("
           << ea_to_hex(p.origin.source_ea) << ") to "
           << p.sink_name << " (" << ea_to_hex(p.sink_ea) << ")\n\n";
        md << "Vulnerability type: **" << p.vulnerability_type << "**  \n";
        md << "Severity: **" << severity_str(p.severity) << "**  \n";
        md << "Confidence: **" << confidence_str(p.confidence) << "**\n\n";

        json steps_arr = json::array();
        int step_idx = 1;
        for (const auto& st : p.steps)
        {
            md << "### Step " << step_idx << ": " << st.func_name << " (" << ea_to_hex(st.func_ea) << ")\n";
            md << "- EA: " << ea_to_hex(st.ea) << "\n";
            if (!st.description.empty())
                md << "- Action: " << st.description << "\n";
            std::string snippet;
            cfuncptr_t cf = decompile_safe(st.func_ea);
            if (cf)
                snippet = extract_snippet_at(cf.operator->(), st.ea);
            if (!snippet.empty())
                md << "```c\n" << snippet << "\n```\n";
            if (!st.condition.empty())
                md << "- Condition: `" << st.condition << "`\n";
            md << "\n";

            json sj;
            sj["ea"]          = ea_to_hex(st.ea);
            sj["func_ea"]     = ea_to_hex(st.func_ea);
            sj["func_name"]   = st.func_name;
            sj["snippet"]     = snippet;
            sj["condition"]   = st.condition;
            sj["summary"]     = st.description;
            steps_arr.push_back(std::move(sj));
            step_idx++;
        }

        if (!p.conditions.empty())
        {
            md << "### Accumulated path conditions\n";
            for (const auto& c : p.conditions)
                md << "- `" << c << "`\n";
            md << "\n";
        }

        pj["narrative_md"] = md.str();
        pj["steps"]        = std::move(steps_arr);
        json conds = json::array();
        for (const auto& c : p.conditions)
            conds.push_back(c);
        pj["conditions"] = std::move(conds);
        json origin_j = json::object();
        origin_j["source_ea"]      = ea_to_hex(p.origin.source_ea);
        origin_j["source_func_ea"] = ea_to_hex(p.origin.source_func_ea);
        origin_j["source_name"]    = p.origin.source_name;
        origin_j["kind"]           = aida::vuln::taint::taint_kind_str(p.origin.kind);
        pj["origin"] = std::move(origin_j);

        json sink_j = json::object();
        sink_j["sink_ea"]        = ea_to_hex(p.sink_ea);
        sink_j["sink_func_ea"]   = ea_to_hex(p.sink_func_ea);
        sink_j["sink_name"]      = p.sink_name;
        sink_j["sink_arg_index"] = p.sink_arg_index;
        pj["sink"] = std::move(sink_j);
        pj["vulnerability_type"] = p.vulnerability_type;
        pj["severity"]           = severity_str(p.severity);
        pj["confidence"]         = confidence_str(p.confidence);
        paths_arr.push_back(std::move(pj));
    }

    json data;
    data["paths"]       = std::move(paths_arr);
    data["total_paths"] = paths.size();
    data["source_ea"]   = ea_to_hex(source_ea);
    data["sink_ea"]     = ea_to_hex(sink_ea);
    data["source_func"] = func_name_for(containing_func_ea(source_ea));
    data["sink_func"]   = func_name_for(containing_func_ea(sink_ea));

    std::ostringstream msg;
    msg << std::string("Vulnerability chain explanation: ") << paths.size() << std::string(" path(s)");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

namespace
{

struct state_machine_visitor_t : public ctree_visitor_t
{
    cfunc_t* cfunc = nullptr;
    bool subject_is_state = false;
    int  total_cases = 0;
    int  num_states = 0;
    bool unguarded = false;
    std::vector<json> transitions;
    std::vector<json> raw_subjects;

    state_machine_visitor_t(cfunc_t* cf) : ctree_visitor_t(CV_FAST), cfunc(cf) {}

    static bool is_state_like_name(const std::string& s)
    {
        std::string l = ascii_lower(s);
        return l.find("state") != std::string::npos ||
               l.find("status") != std::string::npos ||
               l.find("phase") != std::string::npos ||
               l.find("mode") != std::string::npos ||
               l.find("step") != std::string::npos ||
               l.find("stage") != std::string::npos ||
               l.find("fsm") != std::string::npos;
    }

    int idaapi visit_insn(cinsn_t* ins) override
    {
        if (cfunc == nullptr || ins == nullptr)
            return 0;
        if (ins->op != cit_switch || ins->cswitch == nullptr)
            return 0;

        const cexpr_t& subj = ins->cswitch->expr;
        const cexpr_t* x = unwrap_cast_ref(&subj);
        std::string subj_text;
        {
            qstring qs;
            subj.print1(&qs, cfunc);
            tag_remove(&qs);
            subj_text = qs.c_str();
        }
        bool is_state = false;
        if (x != nullptr)
        {
            if (x->op == cot_memptr || x->op == cot_memref || x->op == cot_obj || x->op == cot_var)
            {
                if (is_state_like_name(subj_text))
                    is_state = true;
            }
        }

        for (std::size_t i = 0; i < ins->cswitch->cases.size(); ++i)
        {
            const ccase_t& cc = ins->cswitch->cases[i];
            total_cases += static_cast<int>(cc.values.size());
        }
        if (!is_state)
            return 0;

        subject_is_state = true;
        num_states += static_cast<int>(ins->cswitch->cases.size());

        for (std::size_t i = 0; i < ins->cswitch->cases.size(); ++i)
        {
            const ccase_t& cc = ins->cswitch->cases[i];
            std::uint64_t case_value = cc.values.empty() ? 0ull : cc.values.front();
            std::int64_t to_value = -1;
            ea_t code_ea = cc.ea;
            bool guarded = false;
            const cinsn_t& body = static_cast<const cinsn_t&>(cc);
            if (body.op == cit_block && body.cblock != nullptr)
            {
                for (const cinsn_t& stmt : *body.cblock)
                {
                    if (stmt.op == cit_if && stmt.cif != nullptr)
                        guarded = true;
                    if (stmt.op == cit_expr && stmt.cexpr != nullptr &&
                        stmt.cexpr->op == cot_asg)
                    {
                        const cexpr_t* lhs = unwrap_cast_ref(stmt.cexpr->x);
                        const cexpr_t* rhs = unwrap_cast_ref(stmt.cexpr->y);
                        if (lhs != nullptr && rhs != nullptr && rhs->op == cot_num && rhs->n != nullptr)
                        {
                            qstring lhs_q;
                            stmt.cexpr->x->print1(&lhs_q, cfunc);
                            tag_remove(&lhs_q);
                            std::string lhs_text(lhs_q.c_str());
                            if (lhs_text == subj_text)
                            {
                                to_value = static_cast<std::int64_t>(rhs->n->_value);
                                code_ea  = stmt.ea;
                                break;
                            }
                        }
                    }
                }
            }
            if (!guarded && to_value >= 0)
                unguarded = true;
            json tr;
            tr["case_value"] = case_value;
            tr["from"]       = case_value;
            tr["to"]         = to_value;
            tr["code_ea"]    = ea_to_hex(code_ea);
            tr["guarded"]    = guarded;
            transitions.push_back(std::move(tr));
        }

        return 0;
    }
};

}

agent_tools::tool_result_t handle_map_state_machine(const json& params)
{
    auto addr = parse_addr_param(params, "address");
    if (!addr.has_value())
        return agent_tools::tool_result_t::error(std::string("address parameter is required"));
    func_t* pfn = get_func(*addr);
    if (pfn == nullptr)
        return agent_tools::tool_result_t::error(std::string("address does not lie inside a function"));
    ea_t fea = pfn->start_ea;

    cfuncptr_t cf(nullptr);
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        cf = decompile_safe(fea);
    }
    if (!cf)
        return agent_tools::tool_result_t::error(std::string("Could not decompile function"));

    state_machine_visitor_t v(cf.operator->());
    v.apply_to(&cf->body, nullptr);

    json data;
    data["func_ea"]          = ea_to_hex(fea);
    data["func_name"]        = func_name_for(fea);
    data["is_state_machine"] = v.subject_is_state;
    data["num_states"]       = v.num_states;
    json transitions_j = json::array();
    for (const auto& tr : v.transitions)
        transitions_j.push_back(tr);
    data["transitions"] = std::move(transitions_j);

    std::vector<vuln_finding_t> findings;
    if (v.subject_is_state && v.unguarded)
    {
        vuln_finding_t f;
        std::ostringstream id;
        id << "vuln/state_machine_illegal/" << std::hex << std::uppercase
           << static_cast<std::uint64_t>(fea);
        f.id = id.str();
        f.primary_ea = fea;
        f.cwes.push_back(make_cwe(0, "Illegal state transition"));
        f.severity   = severity_t::info;
        f.confidence = confidence_t::plausible;
        std::ostringstream tt;
        tt << "Possible illegal state transitions in " << func_name_for(fea);
        f.title = tt.str();
        std::ostringstream rat;
        rat << "Function " << func_name_for(fea) << " contains a state-machine switch with at least "
            << "one case that updates the state field without an explicit guard. Reaching an unexpected "
            << "state from an attacker-influenced input may bypass intended sequencing.";
        f.rationale = rat.str();
        json ev;
        ev["transitions"] = data["transitions"];
        f.evidence = std::move(ev);
        findings.push_back(std::move(f));
    }
    data["findings"] = findings_to_json_array(findings);

    std::ostringstream msg;
    msg << (v.subject_is_state ? std::string("State machine detected: ")
                                : std::string("No state machine: "))
        << func_name_for(fea);
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

namespace
{

struct length_arith_visitor_t : public ctree_visitor_t
{
    cfunc_t* cfunc = nullptr;
    std::vector<vuln_finding_t>* findings = nullptr;
    ea_t func_ea = BADADDR;
    int budget = 0;

    length_arith_visitor_t(cfunc_t* cf, std::vector<vuln_finding_t>* out, ea_t fea, int b)
        : ctree_visitor_t(CV_FAST), cfunc(cf), findings(out), func_ea(fea), budget(b) {}

    int idaapi visit_expr(cexpr_t* expr) override
    {
        if (cfunc == nullptr || findings == nullptr || expr == nullptr)
            return 0;
        if (static_cast<int>(findings->size()) >= budget)
            return 1;
        if (expr->op != cot_call)
            return 0;
        std::string nm = resolve_call_target_name(expr);
        if (nm.empty())
            return 0;

        bool is_memcpy_like = name_matches_signature(nm, "memcpy") ||
                              name_matches_signature(nm, "memmove") ||
                              name_matches_signature(nm, "RtlCopyMemory") ||
                              name_matches_signature(nm, "RtlMoveMemory");
        if (!is_memcpy_like)
            return 0;
        if (expr->a == nullptr || expr->a->size() < 3)
            return 0;

        const cexpr_t* sz = unwrap_cast_ref(static_cast<const cexpr_t*>(&(*expr->a)[2]));
        if (sz == nullptr)
            return 0;

        bool size_is_arith = (sz->op == cot_add || sz->op == cot_sub || sz->op == cot_mul ||
                              sz->op == cot_shl);
        bool size_is_var   = (sz->op == cot_var);

        if (!size_is_arith && !size_is_var)
            return 0;

        bool found_off_by_one = false;
        if (sz->op == cot_sub && sz->y != nullptr)
        {
            const cexpr_t* rhs = unwrap_cast_ref(sz->y);
            if (rhs != nullptr && rhs->op == cot_num && rhs->n != nullptr && rhs->n->_value == 1)
                found_off_by_one = true;
        }

        vuln_finding_t f;
        std::ostringstream id;
        id << "vuln/proto_parser/" << std::hex << std::uppercase
           << static_cast<std::uint64_t>(expr->ea);
        f.id = id.str();
        f.primary_ea = expr->ea;
        f.related_eas.push_back(func_ea);

        int cwe_id = found_off_by_one ? 193 : 130;
        f.cwes.push_back(make_cwe(cwe_id, cwe_name_for(cwe_id)));
        f.severity   = found_off_by_one ? severity_t::medium : severity_t::high;
        f.confidence = confidence_t::plausible;

        std::ostringstream tt;
        tt << (found_off_by_one ? "Possible off-by-one in " : "Length-not-checked in ")
           << nm << "(...) call within " << func_name_for(func_ea);
        f.title = tt.str();
        std::ostringstream rat;
        rat << "Call to " << nm << " at " << ea_to_hex(expr->ea)
            << " uses a non-literal size expression that may not be bounds-checked against "
            << "the destination size. ";
        if (found_off_by_one)
            rat << "Detected pattern length=n-1 used in " << nm << "(dst, src, n).";
        f.rationale = rat.str();
        json ev;
        ev["call_ea"]   = ea_to_hex(expr->ea);
        ev["callee"]    = nm;
        ev["func_ea"]   = ea_to_hex(func_ea);
        ev["off_by_one"] = found_off_by_one;
        f.evidence = std::move(ev);
        findings->push_back(std::move(f));

        return 0;
    }
};

}

agent_tools::tool_result_t handle_find_protocol_parser_bugs(const json& params)
{
    auto addr = parse_addr_param(params, "address");
    int limit = extract_int_param(params, "limit", 64);
    if (limit <= 0) limit = 64;
    if (limit > 1024) limit = 1024;

    std::vector<vuln_finding_t> findings;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        std::vector<ea_t> targets;
        if (addr.has_value())
        {
            func_t* pfn = get_func(*addr);
            if (pfn != nullptr)
                targets.push_back(pfn->start_ea);
        }
        else
        {
            const std::size_t fq = get_func_qty();
            for (std::size_t i = 0; i < fq && targets.size() < static_cast<std::size_t>(kMaxScannableFuncs); ++i)
            {
                func_t* pfn = getn_func(i);
                if (pfn == nullptr)
                    continue;
                targets.push_back(pfn->start_ea);
            }
        }

        auto& te = aida::vuln::taint::engine();
        if (!te.is_analyzed())
            te.analyze_all();

        for (ea_t fea : targets)
        {
            if (static_cast<int>(findings.size()) >= limit)
                break;
            const auto* sum = te.get_summary(fea);
            bool relevant = sum != nullptr && (!sum->input_sources_called.empty() ||
                                                !sum->params_passed_to_sinks.empty());
            if (!relevant && !addr.has_value())
                continue;
            cfuncptr_t cf = decompile_safe(fea);
            if (!cf)
                continue;
            length_arith_visitor_t v(cf.operator->(), &findings, fea, limit);
            v.apply_to(&cf->body, nullptr);
        }
    }

    json data;
    data["count"]    = findings.size();
    data["findings"] = findings_to_json_array(findings);
    std::ostringstream msg;
    msg << std::string("Protocol-parser bug scan: ") << findings.size() << std::string(" finding(s)");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

namespace
{

bool tinfo_is_unsigned_integer(const tinfo_t& t)
{
    if (t.empty())
        return false;
    if (!t.is_integral())
        return false;
    return t.is_unsigned();
}

bool tinfo_is_signed_integer(const tinfo_t& t)
{
    if (t.empty())
        return false;
    if (!t.is_integral())
        return false;
    return t.is_signed();
}

const lvar_t* lvar_at(cfunc_t* cf, const cexpr_t* e)
{
    if (cf == nullptr || e == nullptr)
        return nullptr;
    const cexpr_t* x = unwrap_cast_ref(e);
    if (x == nullptr || x->op != cot_var)
        return nullptr;
    lvars_t* lv = cf->get_lvars();
    if (lv == nullptr)
        return nullptr;
    if (x->v.idx < 0 || static_cast<std::size_t>(x->v.idx) >= lv->size())
        return nullptr;
    return &(*lv)[x->v.idx];
}

bool is_signed_compare(ctype_t op)
{
    return op == cot_sgt || op == cot_sge || op == cot_slt || op == cot_sle;
}

bool is_compare(ctype_t op)
{
    return is_signed_compare(op) || op == cot_ugt || op == cot_uge ||
           op == cot_ult || op == cot_ule || op == cot_eq || op == cot_ne;
}

struct loose_bounds_visitor_t : public ctree_visitor_t
{
    cfunc_t* cfunc = nullptr;
    std::vector<vuln_finding_t>* findings = nullptr;
    ea_t func_ea = BADADDR;
    int budget = 0;

    loose_bounds_visitor_t(cfunc_t* cf, std::vector<vuln_finding_t>* out, ea_t fea, int b)
        : ctree_visitor_t(CV_FAST), cfunc(cf), findings(out), func_ea(fea), budget(b) {}

    int idaapi visit_insn(cinsn_t* ins) override
    {
        if (cfunc == nullptr || findings == nullptr || ins == nullptr)
            return 0;
        if (static_cast<int>(findings->size()) >= budget)
            return 1;
        if (ins->op != cit_if || ins->cif == nullptr)
            return 0;
        const cexpr_t& cond = ins->cif->expr;
        if (!is_signed_compare(cond.op))
            return 0;
        const cexpr_t* lhs = unwrap_cast_ref(cond.x);
        const cexpr_t* rhs = unwrap_cast_ref(cond.y);
        if (lhs == nullptr || rhs == nullptr)
            return 0;

        bool rhs_const = (rhs->op == cot_num);
        if (!rhs_const)
            return 0;

        const lvar_t* lv = lvar_at(cfunc, lhs);
        if (lv == nullptr)
            return 0;
        if (!tinfo_is_unsigned_integer(lv->tif))
            return 0;

        vuln_finding_t f;
        std::ostringstream id;
        id << "vuln/loose_bounds/" << std::hex << std::uppercase
           << static_cast<std::uint64_t>(ins->ea);
        f.id = id.str();
        f.primary_ea = ins->ea;
        f.related_eas.push_back(func_ea);
        f.cwes.push_back(make_cwe(839, cwe_name_for(839)));
        f.severity   = severity_t::medium;
        f.confidence = confidence_t::plausible;
        std::ostringstream tt;
        tt << "Signed comparison of unsigned value in " << func_name_for(func_ea);
        f.title = tt.str();
        std::ostringstream rat;
        rat << "if-condition at " << ea_to_hex(ins->ea)
            << " uses signed comparison operator on lvar '" << lv->name.c_str()
            << "' whose declared type is unsigned. A negative-valued attacker input may bypass the bound.";
        f.rationale = rat.str();
        json ev;
        ev["if_ea"]    = ea_to_hex(ins->ea);
        ev["lvar"]     = lv->name.c_str();
        ev["compare"]  = static_cast<int>(cond.op);
        f.evidence = std::move(ev);
        findings->push_back(std::move(f));
        return 0;
    }
};

}

agent_tools::tool_result_t handle_find_loose_bounds_checks(const json& params)
{
    auto addr = parse_addr_param(params, "address");
    int limit = extract_int_param(params, "limit", 64);
    if (limit <= 0) limit = 64;
    if (limit > 1024) limit = 1024;

    std::vector<vuln_finding_t> findings;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        std::vector<ea_t> targets;
        if (addr.has_value())
        {
            func_t* pfn = get_func(*addr);
            if (pfn != nullptr)
                targets.push_back(pfn->start_ea);
        }
        else
        {
            const std::size_t fq = get_func_qty();
            for (std::size_t i = 0; i < fq && targets.size() < static_cast<std::size_t>(kMaxScannableFuncs); ++i)
            {
                func_t* pfn = getn_func(i);
                if (pfn == nullptr)
                    continue;
                targets.push_back(pfn->start_ea);
            }
        }

        for (ea_t fea : targets)
        {
            if (static_cast<int>(findings.size()) >= limit)
                break;
            cfuncptr_t cf = decompile_safe(fea);
            if (!cf)
                continue;
            loose_bounds_visitor_t v(cf.operator->(), &findings, fea, limit);
            v.apply_to(&cf->body, nullptr);
        }
    }

    json data;
    data["count"]       = findings.size();
    data["findings"]    = findings_to_json_array(findings);
    data["primary_cwe"] = 839;
    std::ostringstream msg;
    msg << std::string("Loose bounds-check scan: ") << findings.size() << std::string(" finding(s)");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

namespace
{

struct sign_confusion_visitor_t : public ctree_visitor_t
{
    cfunc_t* cfunc = nullptr;
    std::vector<vuln_finding_t>* findings = nullptr;
    ea_t func_ea = BADADDR;
    int budget = 0;

    sign_confusion_visitor_t(cfunc_t* cf, std::vector<vuln_finding_t>* out, ea_t fea, int b)
        : ctree_visitor_t(CV_FAST), cfunc(cf), findings(out), func_ea(fea), budget(b) {}

    static bool side_is_signed_or_unsigned(cfunc_t* cf, const cexpr_t* e, bool& is_signed, bool& is_unsigned)
    {
        is_signed   = false;
        is_unsigned = false;
        if (cf == nullptr || e == nullptr)
            return false;
        const cexpr_t* x = unwrap_cast_ref(e);
        if (x == nullptr)
            return false;
        if (x->op == cot_var)
        {
            const lvar_t* lv = lvar_at(cf, x);
            if (lv == nullptr)
                return false;
            is_signed   = tinfo_is_signed_integer(lv->tif);
            is_unsigned = tinfo_is_unsigned_integer(lv->tif);
            return is_signed || is_unsigned;
        }
        if (x->op == cot_num && x->n != nullptr)
        {
            is_signed   = static_cast<std::int64_t>(x->n->_value) < 0;
            is_unsigned = !is_signed;
            return true;
        }
        if (!x->type.empty())
        {
            is_signed   = x->type.is_signed();
            is_unsigned = x->type.is_unsigned();
            return is_signed || is_unsigned;
        }
        return false;
    }

    int idaapi visit_expr(cexpr_t* expr) override
    {
        if (cfunc == nullptr || findings == nullptr || expr == nullptr)
            return 0;
        if (static_cast<int>(findings->size()) >= budget)
            return 1;
        if (!is_compare(expr->op))
            return 0;

        bool ls = false, lu = false, rs = false, ru = false;
        if (!side_is_signed_or_unsigned(cfunc, expr->x, ls, lu))
            return 0;
        if (!side_is_signed_or_unsigned(cfunc, expr->y, rs, ru))
            return 0;
        if ((ls && ru) || (lu && rs))
        {
            vuln_finding_t f;
            std::ostringstream id;
            id << "vuln/sign_confusion/" << std::hex << std::uppercase
               << static_cast<std::uint64_t>(expr->ea);
            f.id = id.str();
            f.primary_ea = expr->ea;
            f.related_eas.push_back(func_ea);
            f.cwes.push_back(make_cwe(195, cwe_name_for(195)));
            f.severity   = severity_t::medium;
            f.confidence = confidence_t::plausible;
            std::ostringstream tt;
            tt << "Signed/unsigned comparison in " << func_name_for(func_ea);
            f.title = tt.str();
            std::ostringstream rat;
            rat << "Comparison at " << ea_to_hex(expr->ea)
                << " mixes signed and unsigned operands. Implicit promotion to unsigned can "
                << "skip negative-value paths and bypass length checks.";
            f.rationale = rat.str();
            json ev;
            ev["expr_ea"]    = ea_to_hex(expr->ea);
            ev["lhs_signed"] = ls;
            ev["lhs_unsigned"] = lu;
            ev["rhs_signed"] = rs;
            ev["rhs_unsigned"] = ru;
            f.evidence = std::move(ev);
            findings->push_back(std::move(f));
        }
        return 0;
    }
};

}

agent_tools::tool_result_t handle_find_signed_unsigned_confusion(const json& params)
{
    auto addr = parse_addr_param(params, "address");
    int limit = extract_int_param(params, "limit", 64);
    if (limit <= 0) limit = 64;
    if (limit > 1024) limit = 1024;

    std::vector<vuln_finding_t> findings;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        std::vector<ea_t> targets;
        if (addr.has_value())
        {
            func_t* pfn = get_func(*addr);
            if (pfn != nullptr)
                targets.push_back(pfn->start_ea);
        }
        else
        {
            const std::size_t fq = get_func_qty();
            for (std::size_t i = 0; i < fq && targets.size() < static_cast<std::size_t>(kMaxScannableFuncs); ++i)
            {
                func_t* pfn = getn_func(i);
                if (pfn == nullptr)
                    continue;
                targets.push_back(pfn->start_ea);
            }
        }
        for (ea_t fea : targets)
        {
            if (static_cast<int>(findings.size()) >= limit)
                break;
            cfuncptr_t cf = decompile_safe(fea);
            if (!cf)
                continue;
            sign_confusion_visitor_t v(cf.operator->(), &findings, fea, limit);
            v.apply_to(&cf->body, nullptr);
        }
    }

    json data;
    data["count"]       = findings.size();
    data["findings"]    = findings_to_json_array(findings);
    data["primary_cwe"] = 195;
    std::ostringstream msg;
    msg << std::string("Signed/unsigned-confusion scan: ") << findings.size() << std::string(" finding(s)");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

namespace
{

struct null_check_collector_t : public ctree_visitor_t
{
    cfunc_t* cfunc = nullptr;
    std::unordered_set<int> checked_lvars;
    std::unordered_set<int> alloc_assigned_lvars;
    std::vector<vuln_finding_t>* findings = nullptr;
    ea_t func_ea = BADADDR;
    int budget = 0;

    null_check_collector_t(cfunc_t* cf, std::vector<vuln_finding_t>* out, ea_t fea, int b)
        : ctree_visitor_t(CV_FAST), cfunc(cf), findings(out), func_ea(fea), budget(b) {}

    static int extract_lvar_idx(const cexpr_t* e)
    {
        if (e == nullptr)
            return -1;
        const cexpr_t* x = unwrap_cast_ref(e);
        if (x == nullptr)
            return -1;
        if (x->op == cot_var)
            return x->v.idx;
        return -1;
    }

    int idaapi visit_insn(cinsn_t* ins) override
    {
        if (cfunc == nullptr || ins == nullptr)
            return 0;
        if (ins->op == cit_if && ins->cif != nullptr)
        {
            const cexpr_t& cond = ins->cif->expr;
            if (cond.op == cot_eq || cond.op == cot_ne)
            {
                const cexpr_t* x = unwrap_cast_ref(cond.x);
                const cexpr_t* y = unwrap_cast_ref(cond.y);
                bool x_zero = (x != nullptr && x->op == cot_num && x->n != nullptr && x->n->_value == 0);
                bool y_zero = (y != nullptr && y->op == cot_num && y->n != nullptr && y->n->_value == 0);
                if (y_zero)
                {
                    int idx = extract_lvar_idx(cond.x);
                    if (idx >= 0)
                        checked_lvars.insert(idx);
                }
                else if (x_zero)
                {
                    int idx = extract_lvar_idx(cond.y);
                    if (idx >= 0)
                        checked_lvars.insert(idx);
                }
            }
            else
            {
                int idx = extract_lvar_idx(&cond);
                if (idx >= 0)
                    checked_lvars.insert(idx);
            }
        }
        return 0;
    }

    int idaapi visit_expr(cexpr_t* expr) override
    {
        if (cfunc == nullptr || findings == nullptr || expr == nullptr)
            return 0;
        if (static_cast<int>(findings->size()) >= budget)
            return 1;

        if (expr->op == cot_asg && expr->x != nullptr && expr->y != nullptr)
        {
            const cexpr_t* lhs = unwrap_cast_ref(expr->x);
            const cexpr_t* rhs = unwrap_cast_ref(expr->y);
            if (lhs != nullptr && rhs != nullptr && lhs->op == cot_var && rhs->op == cot_call)
            {
                std::string nm = resolve_call_target_name(rhs);
                if (!nm.empty() && is_alloc_like(nm))
                    alloc_assigned_lvars.insert(lhs->v.idx);
            }
        }

        if (expr->op == cot_ptr || expr->op == cot_memptr || expr->op == cot_idx)
        {
            const cexpr_t* base = expr->op == cot_idx ? expr->x : expr->x;
            int idx = extract_lvar_idx(base);
            if (idx >= 0 && alloc_assigned_lvars.count(idx) && checked_lvars.count(idx) == 0)
            {
                vuln_finding_t f;
                std::ostringstream id;
                id << "vuln/missing_null_check/" << std::hex << std::uppercase
                   << static_cast<std::uint64_t>(expr->ea);
                f.id = id.str();
                f.primary_ea = expr->ea;
                f.related_eas.push_back(func_ea);
                f.cwes.push_back(make_cwe(476, cwe_name_for(476)));
                f.severity   = severity_t::medium;
                f.confidence = confidence_t::plausible;
                std::ostringstream tt;
                tt << "Missing NULL check in " << func_name_for(func_ea);
                f.title = tt.str();
                std::ostringstream rat;
                rat << "Pointer lvar v" << idx << " was assigned from a possibly-NULL allocator and "
                    << "is dereferenced at " << ea_to_hex(expr->ea)
                    << " without an intervening explicit zero-check.";
                f.rationale = rat.str();
                json ev;
                ev["deref_ea"] = ea_to_hex(expr->ea);
                ev["lvar_idx"] = idx;
                f.evidence = std::move(ev);
                findings->push_back(std::move(f));
            }
        }
        return 0;
    }
};

}

agent_tools::tool_result_t handle_find_missing_null_check(const json& params)
{
    auto addr = parse_addr_param(params, "address");
    int limit = extract_int_param(params, "limit", 64);
    if (limit <= 0) limit = 64;
    if (limit > 1024) limit = 1024;

    std::vector<vuln_finding_t> findings;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        std::vector<ea_t> targets;
        if (addr.has_value())
        {
            func_t* pfn = get_func(*addr);
            if (pfn != nullptr)
                targets.push_back(pfn->start_ea);
        }
        else
        {
            const std::size_t fq = get_func_qty();
            for (std::size_t i = 0; i < fq && targets.size() < static_cast<std::size_t>(kMaxScannableFuncs); ++i)
            {
                func_t* pfn = getn_func(i);
                if (pfn == nullptr)
                    continue;
                targets.push_back(pfn->start_ea);
            }
        }
        for (ea_t fea : targets)
        {
            if (static_cast<int>(findings.size()) >= limit)
                break;
            cfuncptr_t cf = decompile_safe(fea);
            if (!cf)
                continue;
            null_check_collector_t v(cf.operator->(), &findings, fea, limit);
            v.apply_to(&cf->body, nullptr);
        }
    }

    json data;
    data["count"]       = findings.size();
    data["findings"]    = findings_to_json_array(findings);
    data["primary_cwe"] = 476;
    std::ostringstream msg;
    msg << std::string("Missing-NULL-check scan: ") << findings.size() << std::string(" finding(s)");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

namespace
{

bool is_toctou_check_api(const std::string& nm)
{
    static const std::vector<std::string> apis = {
        "GetFileAttributesA", "GetFileAttributesW", "GetFileAttributesExA",
        "GetFileAttributesExW", "PathFileExistsA", "PathFileExistsW",
        "_access", "_waccess", "stat", "_stat", "_wstat", "_stat64", "_wstat64",
        "OpenFile", "RegOpenKeyA", "RegOpenKeyW", "RegOpenKeyExA", "RegOpenKeyExW",
    };
    for (const auto& a : apis)
    {
        if (name_matches_signature(nm, a))
            return true;
    }
    return false;
}

bool is_toctou_use_api(const std::string& nm)
{
    static const std::vector<std::string> apis = {
        "CreateFileA", "CreateFileW", "CreateFile2", "fopen", "_wfopen",
        "_open", "_wopen", "open",
        "DeleteFileA", "DeleteFileW", "MoveFileA", "MoveFileW",
        "MoveFileExA", "MoveFileExW", "CopyFileA", "CopyFileW",
        "CopyFileExA", "CopyFileExW",
    };
    for (const auto& a : apis)
    {
        if (name_matches_signature(nm, a))
            return true;
    }
    return false;
}

struct toctou_visitor_t : public ctree_visitor_t
{
    cfunc_t* cfunc = nullptr;
    std::vector<vuln_finding_t>* findings = nullptr;
    ea_t func_ea = BADADDR;
    int budget = 0;
    std::vector<std::pair<ea_t, std::string>> checks;

    toctou_visitor_t(cfunc_t* cf, std::vector<vuln_finding_t>* out, ea_t fea, int b)
        : ctree_visitor_t(CV_FAST), cfunc(cf), findings(out), func_ea(fea), budget(b) {}

    static std::string identify_arg(cfunc_t* cf, const cexpr_t* e)
    {
        if (cf == nullptr || e == nullptr)
            return std::string();
        const cexpr_t* x = unwrap_cast_ref(e);
        if (x == nullptr)
            return std::string();
        if (x->op == cot_var)
        {
            std::ostringstream ss;
            ss << "v" << x->v.idx;
            return ss.str();
        }
        if (x->op == cot_obj)
        {
            std::ostringstream ss;
            ss << "obj@" << std::hex << std::uppercase << static_cast<std::uint64_t>(x->obj_ea);
            return ss.str();
        }
        if (x->op == cot_str && x->string != nullptr)
            return std::string("str:") + x->string;
        return std::string();
    }

    int idaapi visit_expr(cexpr_t* expr) override
    {
        if (cfunc == nullptr || findings == nullptr || expr == nullptr)
            return 0;
        if (static_cast<int>(findings->size()) >= budget)
            return 1;
        if (expr->op != cot_call)
            return 0;
        std::string nm = resolve_call_target_name(expr);
        if (nm.empty())
            return 0;

        if (is_toctou_check_api(nm))
        {
            if (expr->a != nullptr && !expr->a->empty())
            {
                std::string argk = identify_arg(cfunc, static_cast<const cexpr_t*>(&(*expr->a)[0]));
                if (!argk.empty())
                    checks.emplace_back(expr->ea, argk);
            }
            return 0;
        }

        if (is_toctou_use_api(nm))
        {
            if (expr->a == nullptr || expr->a->empty())
                return 0;
            std::string argk = identify_arg(cfunc, static_cast<const cexpr_t*>(&(*expr->a)[0]));
            if (argk.empty())
                return 0;
            for (const auto& c : checks)
            {
                if (c.second != argk)
                    continue;
                vuln_finding_t f;
                std::ostringstream id;
                id << "vuln/toctou/" << std::hex << std::uppercase
                   << static_cast<std::uint64_t>(expr->ea);
                f.id = id.str();
                f.primary_ea = expr->ea;
                f.related_eas.push_back(c.first);
                f.related_eas.push_back(func_ea);
                f.cwes.push_back(make_cwe(367, cwe_name_for(367)));
                f.severity   = severity_t::high;
                f.confidence = confidence_t::plausible;
                std::ostringstream tt;
                tt << "TOCTOU: check at " << ea_to_hex(c.first)
                   << " precedes use of same identifier at " << ea_to_hex(expr->ea);
                f.title = tt.str();
                std::ostringstream rat;
                rat << "Function " << func_name_for(func_ea) << " checks file/identifier '" << argk
                    << "' at " << ea_to_hex(c.first) << " then uses it at "
                    << ea_to_hex(expr->ea) << ". The window between check and use can be exploited "
                    << "by an attacker with write access to the path namespace (CWE-367).";
                f.rationale = rat.str();
                json ev;
                ev["check_ea"] = ea_to_hex(c.first);
                ev["use_ea"]   = ea_to_hex(expr->ea);
                ev["arg_key"]  = argk;
                ev["check_call"] = "<see related_eas[0]>";
                ev["use_call"]   = nm;
                f.evidence = std::move(ev);
                findings->push_back(std::move(f));
                if (static_cast<int>(findings->size()) >= budget)
                    return 1;
                break;
            }
        }
        return 0;
    }
};

}

agent_tools::tool_result_t handle_find_toctou_patterns(const json& params)
{
    auto addr = parse_addr_param(params, "address");
    int limit = extract_int_param(params, "limit", 64);
    if (limit <= 0) limit = 64;
    if (limit > 1024) limit = 1024;

    std::vector<vuln_finding_t> findings;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        std::vector<ea_t> targets;
        if (addr.has_value())
        {
            func_t* pfn = get_func(*addr);
            if (pfn != nullptr)
                targets.push_back(pfn->start_ea);
        }
        else
        {
            const std::size_t fq = get_func_qty();
            for (std::size_t i = 0; i < fq && targets.size() < static_cast<std::size_t>(kMaxScannableFuncs); ++i)
            {
                func_t* pfn = getn_func(i);
                if (pfn == nullptr)
                    continue;
                targets.push_back(pfn->start_ea);
            }
        }
        for (ea_t fea : targets)
        {
            if (static_cast<int>(findings.size()) >= limit)
                break;
            cfuncptr_t cf = decompile_safe(fea);
            if (!cf)
                continue;
            toctou_visitor_t v(cf.operator->(), &findings, fea, limit);
            v.apply_to(&cf->body, nullptr);
        }
    }

    json data;
    data["count"]       = findings.size();
    data["findings"]    = findings_to_json_array(findings);
    data["primary_cwe"] = 367;
    std::ostringstream msg;
    msg << std::string("TOCTOU pattern scan: ") << findings.size() << std::string(" finding(s)");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

namespace
{

bool mop_traces_to_param(const mop_t& op, const std::unordered_set<int>& tainted_lvars)
{
    switch (op.t)
    {
    case mop_l:
        if (op.l != nullptr && tainted_lvars.count(op.l->idx))
            return true;
        return false;
    case mop_d:
        if (op.d != nullptr)
        {
            if (mop_traces_to_param(op.d->l, tainted_lvars))
                return true;
            if (mop_traces_to_param(op.d->r, tainted_lvars))
                return true;
        }
        return false;
    case mop_a:
        if (op.a != nullptr)
            return mop_traces_to_param(static_cast<const mop_t&>(*op.a), tainted_lvars);
        return false;
    default:
        return false;
    }
}

void seed_argument_taint(const mba_t& mba, std::unordered_set<int>& tainted_lvars)
{
    for (size_t i = 0; i < mba.argidx.size(); ++i)
    {
        if (mba.argidx[i] >= 0)
            tainted_lvars.insert(mba.argidx[i]);
    }
}

}

agent_tools::tool_result_t handle_find_arbitrary_rw_primitives(const json& params)
{
    auto addr = parse_addr_param(params, "address");
    int limit = extract_int_param(params, "limit", 64);
    if (limit <= 0) limit = 64;
    if (limit > 1024) limit = 1024;

    std::vector<vuln_finding_t> findings;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());

        std::vector<ea_t> targets;
        if (addr.has_value())
        {
            func_t* pfn = get_func(*addr);
            if (pfn != nullptr)
                targets.push_back(pfn->start_ea);
        }
        else
        {
            const std::size_t fq = get_func_qty();
            for (std::size_t i = 0; i < fq && targets.size() < static_cast<std::size_t>(kMaxScannableFuncs); ++i)
            {
                func_t* pfn = getn_func(i);
                if (pfn == nullptr)
                    continue;
                targets.push_back(pfn->start_ea);
            }
        }

        const bool kernel = aida::vuln::kernel_engine::is_kernel_driver();

        for (ea_t fea : targets)
        {
            if (static_cast<int>(findings.size()) >= limit)
                break;
            auto handle = aida::vuln::microcode::generate(fea, MMAT_LVARS);
            if (!handle.has_value() || !handle->mba)
                continue;
            mba_t& mba = *handle->mba;

            std::unordered_set<int> tainted_lvars;
            seed_argument_taint(mba, tainted_lvars);

            for (int b = 0; b < mba.qty; ++b)
            {
                if (static_cast<int>(findings.size()) >= limit)
                    break;
                mblock_t* blk = mba.get_mblock(static_cast<uint>(b));
                if (blk == nullptr)
                    continue;
                for (minsn_t* m = blk->head; m != nullptr; m = m->next)
                {
                    if (static_cast<int>(findings.size()) >= limit)
                        break;
                    if (m->opcode != m_ldx && m->opcode != m_stx)
                        continue;

                    bool addr_tainted = false;
                    bool val_tainted  = false;
                    if (m->opcode == m_ldx)
                    {
                        addr_tainted = mop_traces_to_param(m->r, tainted_lvars);
                    }
                    else
                    {
                        addr_tainted = mop_traces_to_param(m->d, tainted_lvars);
                        val_tainted  = mop_traces_to_param(m->l, tainted_lvars);
                    }

                    if (!addr_tainted && !val_tainted)
                        continue;

                    int cwe_id = m->opcode == m_stx ? 787 : 125;
                    bool is_write = m->opcode == m_stx;

                    vuln_finding_t f;
                    std::ostringstream id;
                    id << "vuln/arbitrary_" << (is_write ? "w" : "r") << "/"
                       << std::hex << std::uppercase << static_cast<std::uint64_t>(m->ea);
                    f.id = id.str();
                    f.primary_ea = m->ea;
                    f.related_eas.push_back(fea);
                    f.cwes.push_back(make_cwe(cwe_id, cwe_name_for(cwe_id)));
                    f.severity   = severity_t::critical;
                    f.confidence = (kernel && is_write && addr_tainted && val_tainted)
                                       ? confidence_t::likely : confidence_t::plausible;
                    std::ostringstream tt;
                    tt << (is_write ? "Arbitrary-write primitive in " : "Arbitrary-read primitive in ")
                       << func_name_for(fea);
                    f.title = tt.str();
                    std::ostringstream rat;
                    rat << "Microcode " << (is_write ? "m_stx" : "m_ldx") << " at "
                        << ea_to_hex(m->ea)
                        << " uses an attacker-influenced address operand"
                        << (is_write && val_tainted ? " AND attacker-controlled value" : "")
                        << ". In a kernel context this is a strong arbitrary-write candidate.";
                    f.rationale = rat.str();
                    json ev;
                    ev["op_ea"]        = ea_to_hex(m->ea);
                    ev["op_kind"]      = is_write ? "m_stx" : "m_ldx";
                    ev["addr_tainted"] = addr_tainted;
                    ev["val_tainted"]  = val_tainted;
                    ev["kernel"]       = kernel;
                    f.evidence = std::move(ev);
                    findings.push_back(std::move(f));
                }
            }
        }
    }

    json data;
    data["count"]    = findings.size();
    data["findings"] = findings_to_json_array(findings);
    data["primary_cwe_write"] = 787;
    data["primary_cwe_read"]  = 125;
    std::ostringstream msg;
    msg << std::string("Arbitrary R/W primitive scan: ") << findings.size() << std::string(" finding(s)");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

namespace
{

const std::vector<std::string>& deserializer_names()
{
    static const std::vector<std::string> names = {
        "BinaryFormatter::Deserialize", "BinaryFormatter_Deserialize",
        "marshal::loads", "marshal_loads",
        "pickle::loads", "pickle_loads",
        "unserialize",
        "ObjectInputStream::readObject", "ObjectInputStream_readObject",
        "readObject",
        "deserialize", "Deserialize", "DeSerialize",
        "unmarshal", "Unmarshal",
        "read_blob", "ReadBlob",
        "from_bytes", "FromBytes",
        "load_from_string", "loads",
        "fastbinaryDecode",
        "yaml_load", "yaml_load_unsafe",
        "_unpickle",
        "phpunserialize",
    };
    return names;
}

bool is_deserializer_callee(const std::string& nm)
{
    for (const auto& d : deserializer_names())
    {
        if (name_matches_signature(nm, d))
            return true;
    }
    const std::string l = ascii_lower(nm);
    if (l.find("deserialize") != std::string::npos)
        return true;
    if (l.find("unmarshal") != std::string::npos)
        return true;
    if (l.find("from_bytes") != std::string::npos)
        return true;
    if (l.find("read_blob") != std::string::npos)
        return true;
    return false;
}

bool is_byte_dispatch_helper(const std::string& nm)
{
    return name_matches_signature(nm, "wcsstr") ||
           name_matches_signature(nm, "strstr") ||
           name_matches_signature(nm, "memchr") ||
           name_matches_signature(nm, "wmemchr");
}

struct deserialize_visitor_t : public ctree_visitor_t
{
    cfunc_t* cfunc = nullptr;
    std::vector<vuln_finding_t>* findings = nullptr;
    const aida::vuln::taint::func_summary_t* summary = nullptr;
    ea_t func_ea = BADADDR;
    int budget = 0;

    deserialize_visitor_t(cfunc_t* cf, std::vector<vuln_finding_t>* out,
                          const aida::vuln::taint::func_summary_t* sum, ea_t fea, int b)
        : ctree_visitor_t(CV_FAST), cfunc(cf), findings(out), summary(sum), func_ea(fea), budget(b) {}

    int idaapi visit_expr(cexpr_t* expr) override
    {
        if (cfunc == nullptr || findings == nullptr || expr == nullptr)
            return 0;
        if (static_cast<int>(findings->size()) >= budget)
            return 1;
        if (expr->op != cot_call)
            return 0;
        std::string nm = resolve_call_target_name(expr);
        if (nm.empty())
            return 0;

        bool is_des = is_deserializer_callee(nm);
        bool is_dispatch = is_byte_dispatch_helper(nm);
        if (!is_des && !is_dispatch)
            return 0;

        bool first_arg_tainted = false;
        if (expr->a != nullptr && !expr->a->empty() && summary != nullptr)
        {
            const cexpr_t* arg0 = unwrap_cast_ref(static_cast<const cexpr_t*>(&(*expr->a)[0]));
            if (arg0 != nullptr && arg0->op == cot_var)
            {
                int li = arg0->v.idx;
                lvars_t* lv = cfunc->get_lvars();
                if (lv != nullptr && li >= 0 && static_cast<std::size_t>(li) < lv->size())
                {
                    const lvar_t& l = (*lv)[li];
                    if (l.is_arg_var() && summary->tainted_param_indices.count(li))
                        first_arg_tainted = true;
                }
            }
        }
        if (is_des && summary != nullptr && (!summary->input_sources_called.empty() ||
                                              !summary->tainted_param_indices.empty()))
            first_arg_tainted = true;

        if (!is_des && !first_arg_tainted)
            return 0;

        vuln_finding_t f;
        std::ostringstream id;
        id << "vuln/deserialize/" << std::hex << std::uppercase
           << static_cast<std::uint64_t>(expr->ea);
        f.id = id.str();
        f.primary_ea = expr->ea;
        f.related_eas.push_back(func_ea);
        f.cwes.push_back(make_cwe(502, cwe_name_for(502)));
        f.severity   = severity_t::high;
        f.confidence = confidence_t::plausible;
        std::ostringstream tt;
        if (is_des)
            tt << "Unsafe deserialization candidate in " << func_name_for(func_ea) << ": " << nm;
        else
            tt << "Byte-dispatch over attacker buffer in " << func_name_for(func_ea) << ": " << nm;
        f.title = tt.str();
        std::ostringstream rat;
        rat << "Call to " << nm << " at " << ea_to_hex(expr->ea)
            << " consumes a buffer that traces back to attacker-controlled input. ";
        if (is_des)
            rat << "Deserialization frameworks routinely yield arbitrary code execution when invoked on untrusted bytes.";
        else
            rat << "Walking attacker-controlled bytes and dispatching on a tag byte is a classic decoder pattern.";
        f.rationale = rat.str();
        json ev;
        ev["call_ea"] = ea_to_hex(expr->ea);
        ev["callee"]  = nm;
        ev["func_ea"] = ea_to_hex(func_ea);
        ev["mode"]    = is_des ? "deserializer" : "byte_dispatch";
        f.evidence = std::move(ev);
        findings->push_back(std::move(f));
        return 0;
    }
};

}

agent_tools::tool_result_t handle_find_unsafe_deserializers(const json& params)
{
    auto addr = parse_addr_param(params, "address");
    int limit = extract_int_param(params, "limit", 64);
    if (limit <= 0) limit = 64;
    if (limit > 1024) limit = 1024;

    std::vector<vuln_finding_t> findings;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        std::vector<ea_t> targets;
        if (addr.has_value())
        {
            func_t* pfn = get_func(*addr);
            if (pfn != nullptr)
                targets.push_back(pfn->start_ea);
        }
        else
        {
            const std::size_t fq = get_func_qty();
            for (std::size_t i = 0; i < fq && targets.size() < static_cast<std::size_t>(kMaxScannableFuncs); ++i)
            {
                func_t* pfn = getn_func(i);
                if (pfn == nullptr)
                    continue;
                targets.push_back(pfn->start_ea);
            }
        }

        auto& te = aida::vuln::taint::engine();
        if (!te.is_analyzed())
            te.analyze_all();

        for (ea_t fea : targets)
        {
            if (static_cast<int>(findings.size()) >= limit)
                break;
            cfuncptr_t cf = decompile_safe(fea);
            if (!cf)
                continue;
            const auto* sum = te.get_summary(fea);
            deserialize_visitor_t v(cf.operator->(), &findings, sum, fea, limit);
            v.apply_to(&cf->body, nullptr);
        }
    }

    json data;
    data["count"]       = findings.size();
    data["findings"]    = findings_to_json_array(findings);
    data["primary_cwe"] = 502;
    std::ostringstream msg;
    msg << std::string("Unsafe-deserializer scan: ") << findings.size() << std::string(" finding(s)");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

namespace
{

struct off_by_one_visitor_t : public ctree_visitor_t
{
    cfunc_t* cfunc = nullptr;
    std::vector<vuln_finding_t>* findings = nullptr;
    ea_t func_ea = BADADDR;
    int budget = 0;

    off_by_one_visitor_t(cfunc_t* cf, std::vector<vuln_finding_t>* out, ea_t fea, int b)
        : ctree_visitor_t(CV_FAST), cfunc(cf), findings(out), func_ea(fea), budget(b) {}

    static bool cond_is_le_or_ule(const cexpr_t& cond)
    {
        return cond.op == cot_sle || cond.op == cot_ule;
    }

    static int extract_lvar_idx(const cexpr_t* e)
    {
        if (e == nullptr)
            return -1;
        const cexpr_t* x = unwrap_cast_ref(e);
        if (x == nullptr || x->op != cot_var)
            return -1;
        return x->v.idx;
    }

    void emit_off_by_one(ea_t loop_ea, int loop_var_idx)
    {
        vuln_finding_t f;
        std::ostringstream id;
        id << "vuln/off_by_one_loop/" << std::hex << std::uppercase
           << static_cast<std::uint64_t>(loop_ea);
        f.id = id.str();
        f.primary_ea = loop_ea;
        f.related_eas.push_back(func_ea);
        f.cwes.push_back(make_cwe(193, cwe_name_for(193)));
        f.severity   = severity_t::medium;
        f.confidence = confidence_t::plausible;
        std::ostringstream tt;
        tt << "Possible off-by-one loop bound in " << func_name_for(func_ea);
        f.title = tt.str();
        std::ostringstream rat;
        rat << "Loop at " << ea_to_hex(loop_ea)
            << " uses '<= bound' instead of '< bound'. If the body indexes into a fixed-size buffer "
            << "with bound = sizeof(buffer), the final iteration writes one past the end.";
        f.rationale = rat.str();
        json ev;
        ev["loop_ea"] = ea_to_hex(loop_ea);
        ev["loop_var_idx"] = loop_var_idx;
        f.evidence = std::move(ev);
        findings->push_back(std::move(f));
    }

    int idaapi visit_insn(cinsn_t* ins) override
    {
        if (cfunc == nullptr || findings == nullptr || ins == nullptr)
            return 0;
        if (static_cast<int>(findings->size()) >= budget)
            return 1;
        if (ins->op == cit_for && ins->cfor != nullptr)
        {
            const cexpr_t& cond = ins->cfor->expr;
            if (cond_is_le_or_ule(cond))
            {
                int idx = extract_lvar_idx(cond.x);
                emit_off_by_one(ins->ea, idx);
            }
        }
        else if (ins->op == cit_while && ins->cwhile != nullptr)
        {
            const cexpr_t& cond = ins->cwhile->expr;
            if (cond_is_le_or_ule(cond))
            {
                int idx = extract_lvar_idx(cond.x);
                emit_off_by_one(ins->ea, idx);
            }
        }
        else if (ins->op == cit_do && ins->cdo != nullptr)
        {
            const cexpr_t& cond = ins->cdo->expr;
            if (cond_is_le_or_ule(cond))
            {
                int idx = extract_lvar_idx(cond.x);
                emit_off_by_one(ins->ea, idx);
            }
        }
        return 0;
    }

    int idaapi visit_expr(cexpr_t* expr) override
    {
        if (cfunc == nullptr || findings == nullptr || expr == nullptr)
            return 0;
        if (static_cast<int>(findings->size()) >= budget)
            return 1;
        if (expr->op != cot_call)
            return 0;
        std::string nm = resolve_call_target_name(expr);
        if (nm.empty())
            return 0;
        bool is_strncpy_like = name_matches_signature(nm, "strncpy") ||
                               name_matches_signature(nm, "wcsncpy") ||
                               name_matches_signature(nm, "_strncpy") ||
                               name_matches_signature(nm, "strncat") ||
                               name_matches_signature(nm, "wcsncat");
        if (!is_strncpy_like)
            return 0;
        if (expr->a == nullptr || expr->a->size() < 3)
            return 0;
        const cexpr_t* sz = unwrap_cast_ref(static_cast<const cexpr_t*>(&(*expr->a)[2]));
        if (sz == nullptr)
            return 0;

        bool size_is_sizeof_dst = false;
        const cexpr_t* dst = unwrap_cast_ref(static_cast<const cexpr_t*>(&(*expr->a)[0]));
        if (sz->op == cot_sizeof && sz->x != nullptr)
        {
            const cexpr_t* sof = unwrap_cast_ref(sz->x);
            if (dst != nullptr && sof != nullptr && dst->op == sof->op)
            {
                if (dst->op == cot_var && dst->v.idx == sof->v.idx)
                    size_is_sizeof_dst = true;
                else if (dst->op == cot_obj && dst->obj_ea == sof->obj_ea)
                    size_is_sizeof_dst = true;
            }
        }
        if (!size_is_sizeof_dst)
            return 0;

        vuln_finding_t f;
        std::ostringstream id;
        id << "vuln/strncpy_no_terminator/" << std::hex << std::uppercase
           << static_cast<std::uint64_t>(expr->ea);
        f.id = id.str();
        f.primary_ea = expr->ea;
        f.related_eas.push_back(func_ea);
        f.cwes.push_back(make_cwe(193, cwe_name_for(193)));
        f.severity   = severity_t::medium;
        f.confidence = confidence_t::plausible;
        std::ostringstream tt;
        tt << "strncpy(dst, src, sizeof(dst)) without explicit NUL terminator in " << func_name_for(func_ea);
        f.title = tt.str();
        std::ostringstream rat;
        rat << "Call to " << nm << " at " << ea_to_hex(expr->ea)
            << " uses sizeof(dst) for the length argument. strncpy does NOT guarantee a trailing "
            << "NUL when the source is at least as long as the buffer; downstream consumers may "
            << "read past the end. Add 'dst[sizeof(dst) - 1] = 0;' immediately after the call.";
        f.rationale = rat.str();
        json ev;
        ev["call_ea"] = ea_to_hex(expr->ea);
        ev["callee"]  = nm;
        ev["func_ea"] = ea_to_hex(func_ea);
        f.evidence = std::move(ev);
        findings->push_back(std::move(f));
        return 0;
    }
};

}

agent_tools::tool_result_t handle_find_off_by_one_patterns(const json& params)
{
    auto addr = parse_addr_param(params, "address");
    int limit = extract_int_param(params, "limit", 64);
    if (limit <= 0) limit = 64;
    if (limit > 1024) limit = 1024;

    std::vector<vuln_finding_t> findings;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        std::vector<ea_t> targets;
        if (addr.has_value())
        {
            func_t* pfn = get_func(*addr);
            if (pfn != nullptr)
                targets.push_back(pfn->start_ea);
        }
        else
        {
            const std::size_t fq = get_func_qty();
            for (std::size_t i = 0; i < fq && targets.size() < static_cast<std::size_t>(kMaxScannableFuncs); ++i)
            {
                func_t* pfn = getn_func(i);
                if (pfn == nullptr)
                    continue;
                targets.push_back(pfn->start_ea);
            }
        }
        for (ea_t fea : targets)
        {
            if (static_cast<int>(findings.size()) >= limit)
                break;
            cfuncptr_t cf = decompile_safe(fea);
            if (!cf)
                continue;
            off_by_one_visitor_t v(cf.operator->(), &findings, fea, limit);
            v.apply_to(&cf->body, nullptr);
        }
    }

    json data;
    data["count"]       = findings.size();
    data["findings"]    = findings_to_json_array(findings);
    data["primary_cwe"] = 193;
    std::ostringstream msg;
    msg << std::string("Off-by-one pattern scan: ") << findings.size() << std::string(" finding(s)");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

agent_tools::tool_result_t handle_fingerprint_binary_attack_profile(const json&)
{
    json data = fingerprint_binary_attack_profile();
    sanitize_json_utf8_inplace(data);
    return agent_tools::tool_result_t::ok(std::string("Binary attack profile"), data);
}

agent_tools::tool_result_t handle_enumerate_ipc_endpoints(const json& params)
{
    json data = enumerate_ipc_endpoints(json_string_array_param(params, "kinds"));
    sanitize_json_utf8_inplace(data);
    return agent_tools::tool_result_t::ok(std::string("IPC endpoints: ") +
                                          std::to_string(data.value("count", static_cast<std::size_t>(0))), data);
}

agent_tools::tool_result_t handle_compute_pre_auth_handler_set(const json&)
{
    json data = compute_pre_auth_handler_set();
    sanitize_json_utf8_inplace(data);
    return agent_tools::tool_result_t::ok(std::string("Pre-auth handlers: ") +
                                          std::to_string(data.value("count", static_cast<std::size_t>(0))), data);
}

agent_tools::tool_result_t handle_enumerate_handler_reachable_sinks(const json& params)
{
    auto addr = parse_addr_param(params, "handler_ea");
    if (!addr.has_value())
        addr = parse_addr_param(params, "address");
    if (!addr.has_value())
        return agent_tools::tool_result_t::error(std::string("handler_ea is required"), "bad_param");
    json data = enumerate_handler_reachable_sinks(*addr,
        json_int_param_surface(params, "max_depth", 6),
        json_int_param_surface(params, "max_hits", 64));
    sanitize_json_utf8_inplace(data);
    return agent_tools::tool_result_t::ok(std::string("Reachable sinks: ") +
                                          std::to_string(data.value("count", static_cast<std::size_t>(0))), data);
}

agent_tools::tool_result_t handle_classify_exploit_primitive(const json& params)
{
    auto addr = parse_addr_param(params, "sink_ea");
    if (!addr.has_value())
        addr = parse_addr_param(params, "address");
    if (!addr.has_value())
        return agent_tools::tool_result_t::error(std::string("sink_ea is required"), "bad_param");
    json data = classify_exploit_primitive(*addr);
    sanitize_json_utf8_inplace(data);
    return agent_tools::tool_result_t::ok(std::string("Exploit primitive: ") + data.value("primitive", std::string("unknown")), data);
}

agent_tools::tool_result_t handle_find_protocol_routers(const json& params)
{
    json data = find_protocol_routers(json_int_param_surface(params, "min_cases", 4),
                                      json_int_param_surface(params, "max_results", 64));
    sanitize_json_utf8_inplace(data);
    return agent_tools::tool_result_t::ok(std::string("Protocol routers: ") +
                                          std::to_string(data.value("count", static_cast<std::size_t>(0))), data);
}

agent_tools::tool_result_t handle_resolve_indirect_call_targets_workflow(const json& params)
{
    auto addr = parse_addr_param(params, "call_ea");
    if (!addr.has_value())
        addr = parse_addr_param(params, "address");
    if (!addr.has_value())
        return agent_tools::tool_result_t::error(std::string("call_ea is required"), "bad_param");
    json data = resolve_indirect_call_targets(*addr);
    sanitize_json_utf8_inplace(data);
    return agent_tools::tool_result_t::ok(std::string("Indirect call targets: ") +
                                          std::to_string(data.value("count", static_cast<std::size_t>(0))), data);
}

agent_tools::tool_result_t handle_explain_vulnerability_chain_v2(const json& params)
{
    auto src = parse_addr_param(params, "source_address");
    auto sink = parse_addr_param(params, "sink_address");
    if (!src.has_value() || !sink.has_value())
        return agent_tools::tool_result_t::error(std::string("source_address and sink_address are required"), "bad_param");
    json data = explain_vulnerability_chain_v2(*src, *sink,
        json_bool_param_surface(params, "require_pre_auth", false));
    sanitize_json_utf8_inplace(data);
    return agent_tools::tool_result_t::ok(std::string("Vulnerability chain v2"), data);
}

agent_tools::tool_result_t handle_hunt_remote_rce(const json& params)
{
    json data = hunt_remote_rce(json_int_param_surface(params, "top_k", 10),
                                json_bool_param_surface(params, "extract_constraints", false));
    sanitize_json_utf8_inplace(data);
    return agent_tools::tool_result_t::ok(std::string("Remote RCE hunt candidates: ") +
                                          std::to_string(data.value("count", static_cast<std::size_t>(0))), data);
}

agent_tools::tool_result_t handle_rank_attack_surface(const json& params)
{
    std::string role = params.is_object() && params.contains("role_filter") && params["role_filter"].is_string()
        ? params["role_filter"].get<std::string>() : std::string("all");
    json data = rank_attack_surface(json_int_param_surface(params, "limit", 50), role);
    sanitize_json_utf8_inplace(data);
    return agent_tools::tool_result_t::ok(std::string("Attack surface ranking: ") +
                                          std::to_string(data.value("count", static_cast<std::size_t>(0))), data);
}

agent_tools::tool_result_t handle_add_dynamic_taint_source(const json& params)
{
    auto addr = parse_addr_param(params, "source_ea");
    if (!addr.has_value())
        addr = parse_addr_param(params, "address");
    if (!addr.has_value())
        return agent_tools::tool_result_t::error(std::string("source_ea is required"), "bad_param");
    std::string kind = params.is_object() && params.contains("kind") && params["kind"].is_string()
        ? params["kind"].get<std::string>() : std::string("dynamic");
    std::string name = params.is_object() && params.contains("name") && params["name"].is_string()
        ? params["name"].get<std::string>() : std::string();
    json data = add_dynamic_taint_source(*addr, kind, name);
    sanitize_json_utf8_inplace(data);
    if (!data.value("added", false))
        return agent_tools::tool_result_t::error(std::string("source_ea does not lie inside a function"), "no_function_at_addr");
    return agent_tools::tool_result_t::ok(std::string("Dynamic taint source added"), data);
}

agent_tools::tool_result_t handle_enumerate_callbacks_extended(const json&)
{
    json data = enumerate_callbacks_extended();
    sanitize_json_utf8_inplace(data);
    return agent_tools::tool_result_t::ok(std::string("Extended callback scan: ") +
                                          std::to_string(data.value("count", static_cast<std::size_t>(0))), data);
}

}

void register_tier2_surface_tools()
{
    auto& registry = agent_tools::ToolRegistry::instance();
    auto register_taint_required = [&](agent_tools::tool_definition_t def) {
        def.required_indices = {std::string("taint_engine")};
        registry.register_tool(def);
    };

    registry.register_tool({
        std::string("analyze_function_attack_surface"),
        std::string("vuln_advanced"),
        std::string("Compute a 0-100 attack-surface score for the given function. Decomposes the score "
               "into input_proximity (reverse-graph distance to input sources, max 25), sink_count "
               "(forward distance to dangerous sinks, max 25), missing_validators (parameters that "
               "flow to sinks without validation, max 20), complexity (log2 of cyclomatic, max 15), "
               "and taint_paths (input x sink combinations on this function, max 15). Also returns "
               "the function's classified role (allocator/deallocator/validator/parser/dispatcher/"
               "ioctl_handler/ipc_endpoint/callback/crypto/utility)."),
        {
            {std::string("address"), std::string("string"),
             std::string("Address (0x...) of the function to score."), true},
        },
        handle_analyze_function_attack_surface,
        true,
    });

    registry.register_tool({
        std::string("list_attacker_reachable_functions"),
        std::string("vuln_advanced"),
        std::string("Enumerate every function reachable (via reverse call-graph BFS) from any known "
               "input-source callsite. These are the functions that can directly or transitively "
               "process attacker-controlled bytes and therefore form the binary's primary attack "
               "surface."),
        {
            {std::string("limit"), std::string("number"),
             std::string("Maximum number of functions to return (default 200, max 4096)."), false},
        },
        handle_list_attacker_reachable_functions,
        true,
    });

    registry.register_tool({
        std::string("classify_function_role"),
        std::string("vuln_advanced"),
        std::string("Heuristically label a function with a single role: allocator, deallocator, "
               "validator, parser, dispatcher, ioctl_handler, ipc_endpoint, callback, crypto, or "
               "utility. Combines name signatures, callee-set heuristics, switch-shape analysis, "
               "and taint summaries."),
        {
            {std::string("address"), std::string("string"),
             std::string("Address (0x...) of the function to classify."), true},
        },
        handle_classify_function_role,
        true,
    });

    registry.register_tool({
        std::string("enumerate_callbacks"),
        std::string("vuln_advanced"),
        std::string("Find places where the binary registers a function pointer with the operating system "
               "or another component. Covers SetWindowsHookEx*, CreateRemoteThread*, CreateThread, "
               "RtlCreateUserThread, IoRegisterDeviceInterface, KeInitializeDpc, KeInitializeTimer*, "
               "IoSetCompletionRoutine*, IoRegister*Notification, ExRegisterCallback, "
               "RegisterServiceCtrlHandler*, SetUnhandledExceptionFilter, AddVectored*Handler, "
               "_set_se_translator, signal, atexit, _onexit, _beginthread*, and "
               "DriverObject->MajorFunction[*] assignments in kernel drivers. Each finding records "
               "the registered callback's EA and the registration call EA. Security-sensitive "
               "registrations are flagged with CWE-358."),
        {},
        handle_enumerate_callbacks,
        true,
    });

    registry.register_tool({
        std::string("find_writable_executable_pages"),
        std::string("vuln_advanced"),
        std::string("Identify segments and PE sections that are simultaneously writable and executable "
               "(W^X violation, CWE-1188). Scans IDA segments via SEGPERM_EXEC|SEGPERM_WRITE and "
               "additionally walks the PE section table for IMAGE_SCN_MEM_EXECUTE | "
               "IMAGE_SCN_MEM_WRITE. Each match is emitted as a critical, confirmed finding."),
        {},
        handle_find_writable_executable_pages,
        true,
    });

    registry.register_tool({
        std::string("explain_vulnerability_chain"),
        std::string("vuln_advanced"),
        std::string("Generate a markdown narrative plus structured JSON for taint paths from a source "
               "callsite to a sink callsite. Each step in each path is annotated with the "
               "decompiled snippet at the step EA, accumulated path conditions, and the engine's "
               "summary text."),
        {
            {std::string("source_address"), std::string("string"),
             std::string("Address (0x...) or symbol name of the input-source callsite."), true},
            {std::string("sink_address"),   std::string("string"),
             std::string("Address (0x...) or symbol name of the dangerous-sink callsite."), true},
        },
        handle_explain_vulnerability_chain,
        true,
    });

    registry.register_tool({
        std::string("map_state_machine"),
        std::string("vuln_advanced"),
        std::string("Detect state-machine-like dispatch in the given function. A state machine is a "
               "switch on a global / member field whose name resembles state/status/phase/mode/"
               "step/stage/fsm, with cases that update the same field. Returns the detected "
               "transitions and emits an info-level finding when at least one transition lacks an "
               "explicit guard, indicating possible illegal-state attacks."),
        {
            {std::string("address"), std::string("string"),
             std::string("Address (0x...) of the function to analyze."), true},
        },
        handle_map_state_machine,
        true,
    });

    registry.register_tool({
        std::string("find_protocol_parser_bugs"),
        std::string("vuln_advanced"),
        std::string("Detect bugs in protocol parsers that consume externally-controlled input and "
               "dispatch on length/type/cmd fields. Flags memcpy/memmove/RtlCopyMemory/RtlMoveMemory "
               "calls whose size argument is non-literal arithmetic on attacker-influenced data "
               "(CWE-130 length-not-checked) and detects size = n - 1 patterns flowing into a copy "
               "of n bytes (CWE-193 off-by-one)."),
        {
            {std::string("address"), std::string("string"),
             std::string("Optional address (0x...) of a single function to scan; default scans every function."),
             false},
            {std::string("limit"), std::string("number"),
             std::string("Maximum number of findings to return (default 64, max 1024)."), false},
        },
        handle_find_protocol_parser_bugs,
        true,
    });

    registry.register_tool({
        std::string("find_loose_bounds_checks"),
        std::string("vuln_advanced"),
        std::string("Detect if-conditions that compare an attacker-influenced value against a constant "
               "bound but use the wrong relational operator. Specifically flags signed comparisons "
               "(cot_sgt/sge/slt/sle) against an unsigned-typed lvar where a negative attacker "
               "value would slip through. CWE-839."),
        {
            {std::string("address"), std::string("string"),
             std::string("Optional address (0x...) of a single function to scan; default scans every function."),
             false},
            {std::string("limit"), std::string("number"),
             std::string("Maximum number of findings to return (default 64, max 1024)."), false},
        },
        handle_find_loose_bounds_checks,
        true,
    });

    registry.register_tool({
        std::string("find_signed_unsigned_confusion"),
        std::string("vuln_advanced"),
        std::string("Detect signed/unsigned comparisons whose operands have differing signedness "
               "(signed lvar vs unsigned lvar/literal, or vice versa). Implicit promotion to "
               "unsigned can suppress negative-value paths and bypass length checks. CWE-194/195."),
        {
            {std::string("address"), std::string("string"),
             std::string("Optional address (0x...) of a single function to scan; default scans every function."),
             false},
            {std::string("limit"), std::string("number"),
             std::string("Maximum number of findings to return (default 64, max 1024)."), false},
        },
        handle_find_signed_unsigned_confusion,
        true,
    });

    registry.register_tool({
        std::string("find_missing_null_check"),
        std::string("vuln_advanced"),
        std::string("Detect pointer dereferences that follow an allocator (malloc/calloc/realloc/"
               "HeapAlloc/RtlAllocateHeap/LocalAlloc/GlobalAlloc/VirtualAlloc/ExAllocatePool*/operator new) "
               "without an intervening explicit null-check on the same pointer. CWE-476."),
        {
            {std::string("address"), std::string("string"),
             std::string("Optional address (0x...) of a single function to scan; default scans every function."),
             false},
            {std::string("limit"), std::string("number"),
             std::string("Maximum number of findings to return (default 64, max 1024)."), false},
        },
        handle_find_missing_null_check,
        true,
    });

    registry.register_tool({
        std::string("find_toctou_patterns"),
        std::string("vuln_advanced"),
        std::string("Detect Time-of-Check-to-Time-of-Use races in the same function: a check call "
               "(GetFileAttributes*/PathFileExists*/_access/stat*/OpenFile/RegOpenKey*) followed by "
               "a use call (CreateFile*/fopen/_open/DeleteFile*/MoveFile*/CopyFile*) on the same "
               "identifier. CWE-367."),
        {
            {std::string("address"), std::string("string"),
             std::string("Optional address (0x...) of a single function to scan; default scans every function."),
             false},
            {std::string("limit"), std::string("number"),
             std::string("Maximum number of findings to return (default 64, max 1024)."), false},
        },
        handle_find_toctou_patterns,
        true,
    });

    registry.register_tool({
        std::string("find_arbitrary_rw_primitives"),
        std::string("vuln_advanced"),
        std::string("Detect microcode m_ldx/m_stx instructions whose effective address (and, for stores, "
               "value) traces back via def-use to a function parameter or input source. In a kernel "
               "context this yields high-confidence arbitrary-write/arbitrary-read primitives "
               "(CWE-787 / CWE-125)."),
        {
            {std::string("address"), std::string("string"),
             std::string("Optional address (0x...) of a single function to scan; default scans every function."),
             false},
            {std::string("limit"), std::string("number"),
             std::string("Maximum number of findings to return (default 64, max 1024)."), false},
        },
        handle_find_arbitrary_rw_primitives,
        true,
    });

    registry.register_tool({
        std::string("find_unsafe_deserializers"),
        std::string("vuln_advanced"),
        std::string("Detect calls to deserialization frameworks (BinaryFormatter::Deserialize, "
               "marshal::loads, pickle::loads, unserialize, ObjectInputStream::readObject, generic "
               "*deserialize*/*unmarshal*/*read_blob*/*from_bytes* helpers) whose first argument "
               "traces back to attacker-controlled bytes. Also flags wcsstr/strstr/memchr "
               "byte-dispatch loops over attacker buffers. CWE-502."),
        {
            {std::string("address"), std::string("string"),
             std::string("Optional address (0x...) of a single function to scan; default scans every function."),
             false},
            {std::string("limit"), std::string("number"),
             std::string("Maximum number of findings to return (default 64, max 1024)."), false},
        },
        handle_find_unsafe_deserializers,
        true,
    });

    registry.register_tool({
        std::string("find_off_by_one_patterns"),
        std::string("vuln_advanced"),
        std::string("Detect off-by-one buffer-access patterns: for/while/do loops whose condition uses "
               "'<= bound' (cot_sle / cot_ule) instead of '< bound', and strncpy/wcsncpy/strncat/"
               "wcsncat calls of the form strncpy(dst, src, sizeof(dst)) which do not guarantee "
               "a trailing NUL terminator. CWE-193."),
        {
            {std::string("address"), std::string("string"),
             std::string("Optional address (0x...) of a single function to scan; default scans every function."),
             false},
            {std::string("limit"), std::string("number"),
             std::string("Maximum number of findings to return (default 64, max 1024)."), false},
        },
        handle_find_off_by_one_patterns,
        true,
    });

    registry.register_tool({
        std::string("fingerprint_binary_attack_profile"),
        std::string("vuln_workflow"),
        std::string("One-call binary attack-surface classifier using IDA file metadata, imports, endpoint callsites, and auth-gate evidence."),
        {},
        handle_fingerprint_binary_attack_profile,
        true,
    });

    registry.register_tool({
        std::string("enumerate_ipc_endpoints"),
        std::string("vuln_workflow"),
        std::string("Enumerate RPC, COM, ALPC, network, named-pipe, WSK/NDIS, and kernel IOCTL endpoints with handler EAs and recovery evidence."),
        {
            {std::string("kinds"), std::string("array"), std::string("Optional endpoint kinds: rpc, com, alpc, socket, http, pipe, websocket, wsk, kernel_irp, all."), false},
        },
        handle_enumerate_ipc_endpoints,
        true,
    });

    register_taint_required({
        std::string("compute_pre_auth_handler_set"),
        std::string("vuln_workflow"),
        std::string("Classify endpoint handlers as pre-auth when no recognized auth-gate helper is observed in the handler body."),
        {},
        handle_compute_pre_auth_handler_set,
        true,
    });

    register_taint_required({
        std::string("enumerate_handler_reachable_sinks"),
        std::string("vuln_workflow"),
        std::string("Walk the callgraph forward from an endpoint handler and collect reachable dangerous sink callsites with validator/auth annotations."),
        {
            {std::string("handler_ea"), std::string("string"), std::string("Endpoint handler address."), true},
            {std::string("max_depth"), std::string("number"), std::string("Maximum call depth (default 6)."), false},
            {std::string("max_hits"), std::string("number"), std::string("Maximum sink hits (default 64)."), false},
        },
        handle_enumerate_handler_reachable_sinks,
        true,
    });

    registry.register_tool({
        std::string("classify_exploit_primitive"),
        std::string("vuln_workflow"),
        std::string("Classify a sink callsite as stack/heap overflow, command injection, format string, type confusion, path traversal, or unknown."),
        {
            {std::string("sink_ea"), std::string("string"), std::string("Sink callsite address."), true},
        },
        handle_classify_exploit_primitive,
        true,
    });

    registry.register_tool({
        std::string("find_protocol_routers"),
        std::string("vuln_workflow"),
        std::string("Find switch-on-opcode protocol routers via CFG switch dispatch enumeration and summarize handler reachability to sinks."),
        {
            {std::string("min_cases"), std::string("number"), std::string("Minimum switch cases (default 4)."), false},
            {std::string("max_results"), std::string("number"), std::string("Maximum routers (default 64)."), false},
        },
        handle_find_protocol_routers,
        true,
    });

    registry.register_tool({
        std::string("resolve_indirect_call_targets"),
        std::string("vuln_workflow"),
        std::string("Resolve one indirect call through existing typeinfo, vtable, RTTI, constant-pool, xref, and microcode SSA resolvers."),
        {
            {std::string("call_ea"), std::string("string"), std::string("Indirect call address."), true},
        },
        handle_resolve_indirect_call_targets_workflow,
        true,
    });

    register_taint_required({
        std::string("explain_vulnerability_chain_v2"),
        std::string("vuln_workflow"),
        std::string("Explain a taint chain with pre-auth classification and per-step wire-field offset annotations when recovered."),
        {
            {std::string("source_address"), std::string("string"), std::string("Source callsite address."), true},
            {std::string("sink_address"), std::string("string"), std::string("Sink callsite address."), true},
            {std::string("require_pre_auth"), std::string("boolean"), std::string("Filter out chains that are not pre-auth clean."), false},
        },
        handle_explain_vulnerability_chain_v2,
        true,
    });

    register_taint_required({
        std::string("hunt_remote_rce"),
        std::string("vuln_workflow"),
        std::string("End-to-end remote RCE hunt orchestrator: profile binary, enumerate endpoints, filter pre-auth handlers, collect reachable sinks, classify primitives, and rank candidates."),
        {
            {std::string("top_k"), std::string("number"), std::string("Maximum candidates (default 10)."), false},
            {std::string("extract_constraints"), std::string("boolean"), std::string("Request constraint extraction marker for the top candidates."), false},
        },
        handle_hunt_remote_rce,
        true,
    });

    register_taint_required({
        std::string("rank_attack_surface"),
        std::string("vuln_workflow"),
        std::string("Batch-score attacker-reachable functions and return the top ranked functions, optionally filtered by classified role."),
        {
            {std::string("limit"), std::string("number"), std::string("Maximum functions (default 50)."), false},
            {std::string("role_filter"), std::string("string"), std::string("Optional role filter or all."), false},
        },
        handle_rank_attack_surface,
        true,
    });

    {
        agent_tools::tool_definition_t def;
        def.name = std::string("add_dynamic_taint_source");
        def.category = std::string("vuln_workflow");
        def.description = std::string("Add a runtime session taint source for surface ranking and attacker reachability. Resets automatically when the input MD5 changes.");
        def.parameters = {
            {std::string("source_ea"), std::string("string"), std::string("Address inside the source function."), true},
            {std::string("kind"), std::string("string"), std::string("Source kind label."), false},
            {std::string("name"), std::string("string"), std::string("Optional display name."), false},
        };
        def.handler = handle_add_dynamic_taint_source;
        def.read_only = false;
        def.destructive = false;
        def.deterministic = false;
        registry.register_tool(def);
    }

    registry.register_tool({
        std::string("enumerate_callbacks_extended"),
        std::string("vuln_workflow"),
        std::string("Extended callback registration scan covering user-mode callbacks plus WSK, process/thread/image, registry, object, bugcheck, ETW, WMI, and minifilter callback registrations."),
        {},
        handle_enumerate_callbacks_extended,
        true,
    });
}

}

}
}
}
