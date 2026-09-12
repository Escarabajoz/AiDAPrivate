#include "../aida_pro.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <bytes.hpp>
#include <entry.hpp>
#include <funcs.hpp>
#include <hexrays.hpp>
#include <ida.hpp>
#include <loader.hpp>
#include <nalt.hpp>
#include <name.hpp>
#include <typeinf.hpp>
#include <ua.hpp>
#include <allins.hpp>

#include "../agent_tools.hpp"
#include "../ida_utils.hpp"
#include "microcode_engine.hpp"
#include "vuln_common.hpp"
#include "vuln_signatures.hpp"
#include "vuln_tools.hpp"

namespace aida
{
namespace vuln
{
namespace kernel_engine
{

namespace
{

constexpr uint32_t IRP_MJ_DEVICE_CONTROL_INDEX = 14;

inline std::string format_address_string(ea_t ea)
{
    if (ea == BADADDR)
        return "0x0";
    std::ostringstream ss;
    ss << "0x" << std::hex << std::uppercase << static_cast<std::uint64_t>(ea);
    return ss.str();
}

inline cwe_t make_cwe(int id, const char* name)
{
    cwe_t c;
    c.id = id;
    c.name = name;
    return c;
}

inline std::string make_finding_id(const char* prefix, ea_t ea, uint32_t code)
{
    std::ostringstream ss;
    ss << prefix << std::hex << std::uppercase << static_cast<std::uint64_t>(ea)
       << "_" << static_cast<std::uint32_t>(code);
    return ss.str();
}

inline bool name_matches_driver_entry(const std::string& nm)
{
    if (nm.empty())
        return false;
    std::string lower;
    lower.reserve(nm.size());
    for (char c : nm)
        lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    return lower == "driverentry"
        || lower == "_driverentry"
        || lower == "fxdriverentry"
        || lower == "gsdriverentry";
}

inline bool name_is_kernel_module(const char* mod)
{
    if (!mod || !*mod)
        return false;
    std::string s = mod;
    for (auto& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s == "ntoskrnl.exe"
        || s == "ntkrnlmp.exe"
        || s == "ntkrnlpa.exe"
        || s == "ntkrpamp.exe"
        || s == "hal.dll"
        || s == "ndis.sys"
        || s == "fltmgr.sys"
        || s == "wdf01000.sys"
        || s == "wdfldr.sys"
        || s == "ksecdd.sys"
        || s == "tcpip.sys"
        || s == "netio.sys"
        || s == "msrpc.sys";
}

inline ea_t pe_optional_header_base(ea_t image_base)
{
    if (!is_loaded(image_base))
        return BADADDR;
    if (get_word(image_base) != 0x5A4D)
        return BADADDR;
    std::uint32_t pe_off = get_dword(image_base + 0x3C);
    ea_t pe_hdr = image_base + pe_off;
    if (!is_loaded(pe_hdr) || get_dword(pe_hdr) != 0x00004550)
        return BADADDR;
    return pe_hdr + 4 + 20;
}

inline std::uint16_t pe_subsystem(ea_t image_base)
{
    ea_t opt = pe_optional_header_base(image_base);
    if (opt == BADADDR)
        return 0;
    return get_word(opt + 68);
}

inline bool pe_is_native_subsystem()
{
    ea_t base = get_imagebase();
    if (base == BADADDR || !is_loaded(base))
        return false;
    std::uint16_t sub = pe_subsystem(base);
    return sub == 1;
}

inline bool imports_kernel_module()
{
    uint qty = get_import_module_qty();
    for (uint i = 0; i < qty; ++i)
    {
        qstring mod_name;
        if (!get_import_module_name(&mod_name, static_cast<int>(i)))
            continue;
        if (name_is_kernel_module(mod_name.c_str()))
            return true;
    }
    return false;
}

inline ea_t exported_driver_entry_ea()
{
    size_t total = get_entry_qty();
    for (size_t i = 0; i < total; ++i)
    {
        uval_t ord = get_entry_ordinal(i);
        ea_t ea = get_entry(ord);
        if (ea == BADADDR)
            continue;
        qstring ename;
        if (get_entry_name(&ename, ord) <= 0)
            continue;
        if (name_matches_driver_entry(ename.c_str()))
            return ea;
    }
    return BADADDR;
}

inline ea_t named_function_driver_entry_ea()
{
    ea_t ea = get_name_ea(BADADDR, "DriverEntry");
    if (ea != BADADDR)
        return ea;
    ea = get_name_ea(BADADDR, "GsDriverEntry");
    if (ea != BADADDR)
        return ea;
    ea = get_name_ea(BADADDR, "FxDriverEntry");
    if (ea != BADADDR)
        return ea;
    return BADADDR;
}

inline ea_t locate_driver_entry()
{
    ea_t ea = exported_driver_entry_ea();
    if (ea != BADADDR)
        return ea;
    ea = named_function_driver_entry_ea();
    if (ea != BADADDR)
        return ea;
    size_t total = get_func_qty();
    for (size_t i = 0; i < total; ++i)
    {
        func_t* pfn = getn_func(i);
        if (!pfn)
            continue;
        qstring nm;
        if (get_func_name(&nm, pfn->start_ea) <= 0)
            continue;
        if (name_matches_driver_entry(nm.c_str()))
            return pfn->start_ea;
    }
    return BADADDR;
}

inline bool is_likely_ioctl_immediate(uint64_t v)
{
    if (v == 0)
        return false;
    if (v >> 32)
        return false;
    uint32_t code = static_cast<uint32_t>(v & 0xFFFFFFFFu);
    if (code < 0x10000u)
        return false;
    uint32_t device_type = (code >> 16) & 0xFFFFu;
    if (device_type == 0)
        return false;
    return true;
}

inline cexpr_t* skip_expr_casts(cexpr_t* e)
{
    while (e != nullptr && (e->op == cot_cast || e->op == cot_ref))
        e = e->x;
    return e;
}

inline bool extract_handler_target(cexpr_t* rhs, ea_t& out_ea, std::string& out_name)
{
    cexpr_t* e = skip_expr_casts(rhs);
    if (e == nullptr)
        return false;
    if (e->op == cot_obj)
    {
        ea_t target = e->obj_ea;
        if (target == BADADDR)
            return false;
        func_t* pfn = get_func(target);
        if (pfn != nullptr)
            out_ea = pfn->start_ea;
        else
            out_ea = target;
        qstring nm;
        if (out_ea != BADADDR && get_func_name(&nm, out_ea) > 0)
            out_name = nm.c_str();
        else if (out_ea != BADADDR && get_name(&nm, out_ea) > 0)
            out_name = nm.c_str();
        else
            out_name = format_address_string(out_ea);
        return out_ea != BADADDR;
    }
    return false;
}

inline bool match_major_function_lhs(cexpr_t* lhs, uint32_t* index_out)
{
    if (lhs == nullptr)
        return false;
    cexpr_t* idx_expr = lhs;
    cexpr_t* idx_value = nullptr;
    if (idx_expr->op == cot_idx)
    {
        idx_value = idx_expr->y;
        idx_expr = idx_expr->x;
    }
    cexpr_t* mem = skip_expr_casts(idx_expr);
    if (mem == nullptr)
        return false;
    if (mem->op != cot_memptr && mem->op != cot_memref)
        return false;
    qstring member_name;
    bool member_named = false;
    if (mem->x != nullptr)
    {
        tinfo_t parent_type = mem->x->type;
        if (mem->op == cot_memptr)
            parent_type.remove_ptr_or_array();
        udt_type_data_t udt;
        if (parent_type.get_udt_details(&udt))
        {
            for (size_t i = 0; i < udt.size(); ++i)
            {
                const udm_t& u = udt[i];
                uint64 bit_off = static_cast<uint64>(u.offset);
                uint64 byte_off = bit_off / 8u;
                if (byte_off == static_cast<uint64>(mem->m))
                {
                    member_name = u.name;
                    member_named = true;
                    break;
                }
            }
        }
    }
    if (!member_named)
        return false;
    if (std::strcmp(member_name.c_str(), "MajorFunction") != 0)
        return false;
    if (index_out != nullptr)
    {
        if (idx_value != nullptr && idx_value->op == cot_num && idx_value->n != nullptr)
            *index_out = static_cast<uint32_t>(idx_value->n->_value);
        else
            *index_out = 0xFFFFFFFFu;
    }
    return true;
}

struct dispatch_collector_t : public ctree_visitor_t
{
    std::unordered_map<ea_t, ioctl_handler_t> handlers;

    dispatch_collector_t() : ctree_visitor_t(CV_PARENTS) {}

    int idaapi visit_expr(cexpr_t* expr) override
    {
        if (!expr)
            return 0;
        if (expr->op != cot_asg)
            return 0;
        if (expr->x == nullptr || expr->y == nullptr)
            return 0;
        uint32_t major_index = 0xFFFFFFFFu;
        if (!match_major_function_lhs(expr->x, &major_index))
            return 0;
        ea_t handler_ea = BADADDR;
        std::string handler_name;
        if (!extract_handler_target(expr->y, handler_ea, handler_name))
            return 0;
        if (handler_ea == BADADDR)
            return 0;
        bool covers_device_control = false;
        if (major_index == 0xFFFFFFFFu)
            covers_device_control = true;
        else if (major_index == IRP_MJ_DEVICE_CONTROL_INDEX)
            covers_device_control = true;
        if (!covers_device_control)
            return 0;
        auto it = handlers.find(handler_ea);
        if (it == handlers.end())
        {
            ioctl_handler_t h;
            h.handler_ea = handler_ea;
            h.handler_name = handler_name;
            handlers.emplace(handler_ea, std::move(h));
        }
        return 0;
    }
};

inline std::vector<uint32_t> scan_ioctl_codes_microcode(ea_t handler_ea)
{
    std::vector<uint32_t> codes;
    if (handler_ea == BADADDR)
        return codes;
    auto handle_opt = aida::vuln::microcode::generate(handler_ea, MMAT_LVARS);
    if (!handle_opt.has_value())
        return codes;
    mba_t* mba = handle_opt->mba.get();
    if (mba == nullptr)
        return codes;
    struct ioctl_visitor_t : public minsn_visitor_t
    {
        std::unordered_set<uint64_t> seen;
        std::vector<uint32_t>* out;
        explicit ioctl_visitor_t(std::vector<uint32_t>* o) : out(o) {}
        int idaapi visit_minsn() override
        {
            if (curins == nullptr)
                return 0;
            mcode_t op = curins->opcode;
            if (op != m_setz && op != m_setnz
                && op != m_jz && op != m_jnz
                && op != m_seta && op != m_setae
                && op != m_setb && op != m_setbe
                && op != m_ja && op != m_jae
                && op != m_jb && op != m_jbe
                && op != m_setg && op != m_setge
                && op != m_setl && op != m_setle
                && op != m_jg && op != m_jge
                && op != m_jl && op != m_jle
                && op != m_sub)
                return 0;
            const mop_t* candidate = nullptr;
            if (curins->r.t == mop_n)
                candidate = &curins->r;
            else if (curins->l.t == mop_n)
                candidate = &curins->l;
            if (candidate == nullptr || candidate->nnn == nullptr)
                return 0;
            uint64_t v = candidate->nnn->value;
            if (!is_likely_ioctl_immediate(v))
                return 0;
            uint32_t code = static_cast<uint32_t>(v & 0xFFFFFFFFu);
            if (seen.insert(code).second)
                out->push_back(code);
            return 0;
        }
    };
    ioctl_visitor_t visitor(&codes);
    mba->for_all_insns(visitor);
    return codes;
}

inline std::vector<uint32_t> scan_ioctl_codes_disasm(ea_t handler_ea)
{
    std::vector<uint32_t> codes;
    if (handler_ea == BADADDR)
        return codes;
    func_t* pfn = get_func(handler_ea);
    if (pfn == nullptr)
        return codes;
    std::unordered_set<uint32_t> seen;
    ea_t cur = pfn->start_ea;
    while (cur < pfn->end_ea && cur != BADADDR)
    {
        insn_t insn;
        int len = decode_insn(&insn, cur);
        if (len <= 0)
        {
            cur = next_head(cur, pfn->end_ea);
            if (cur == BADADDR)
                break;
            continue;
        }
        if (insn.itype == NN_cmp || insn.itype == NN_sub)
        {
            const op_t* imm_op = nullptr;
            const op_t* reg_op = nullptr;
            if (insn.ops[1].type == o_imm && (insn.ops[0].type == o_reg || insn.ops[0].type == o_displ || insn.ops[0].type == o_phrase))
            {
                imm_op = &insn.ops[1];
                reg_op = &insn.ops[0];
            }
            else if (insn.ops[0].type == o_imm && (insn.ops[1].type == o_reg || insn.ops[1].type == o_displ || insn.ops[1].type == o_phrase))
            {
                imm_op = &insn.ops[0];
                reg_op = &insn.ops[1];
            }
            if (imm_op != nullptr && reg_op != nullptr)
            {
                uint64_t v = static_cast<uint64_t>(imm_op->value);
                if (is_likely_ioctl_immediate(v))
                {
                    uint32_t code = static_cast<uint32_t>(v & 0xFFFFFFFFu);
                    if (seen.insert(code).second)
                        codes.push_back(code);
                }
            }
        }
        cur += len;
    }
    return codes;
}

inline std::vector<uint32_t> collect_ioctl_codes(ea_t handler_ea)
{
    std::vector<uint32_t> codes = scan_ioctl_codes_microcode(handler_ea);
    if (!codes.empty())
        return codes;
    return scan_ioctl_codes_disasm(handler_ea);
}

inline ea_t read_ptr_kernel(ea_t ea)
{
    if (ea == BADADDR || !is_loaded(ea))
        return BADADDR;
    return inf_is_64bit() ? static_cast<ea_t>(get_qword(ea)) : static_cast<ea_t>(get_dword(ea));
}

inline bool valid_func_start_kernel(ea_t ea)
{
    if (ea == BADADDR || !is_loaded(ea))
        return false;
    func_t* pfn = get_func(ea);
    return pfn != nullptr && pfn->start_ea == ea;
}

inline void add_handler_record(std::vector<ioctl_handler_t>& result,
                               std::unordered_set<ea_t>& seen,
                               ea_t handler_ea,
                               const std::string& source,
                               const std::string& evidence,
                               uint32_t major,
                               const std::vector<std::string>& metadata)
{
    if (!valid_func_start_kernel(handler_ea))
        return;
    if (!seen.insert(handler_ea).second)
        return;
    ioctl_handler_t h;
    h.handler_ea = handler_ea;
    h.handler_name = format_address_string(handler_ea);
    qstring nm;
    if (get_func_name(&nm, handler_ea) > 0 && !nm.empty())
        h.handler_name = nm.c_str();
    h.ioctl_codes = collect_ioctl_codes(handler_ea);
    h.source_model = source;
    h.evidence = evidence;
    h.major_function = major;
    h.fallback_metadata = metadata;
    result.push_back(std::move(h));
}

inline ea_t object_arg_from_call(ea_t func_ea, ea_t call_ea, int arg_idx)
{
    if (!init_hexrays_plugin())
        return BADADDR;
    func_t* pfn = get_func(func_ea);
    if (pfn == nullptr || !ida_utils::is_safely_decompilable(pfn))
        return BADADDR;
    cfuncptr_t cf(nullptr);
    try
    {
        cf = decompile_func(pfn, nullptr, DECOMP_NO_WAIT);
    }
    catch (...)
    {
        cf.reset();
    }
    if (!cf)
        return BADADDR;
    ea_t out = BADADDR;
    struct object_arg_visitor_t : public ctree_visitor_t
    {
        ea_t call_ea = BADADDR;
        int arg_idx = -1;
        ea_t out = BADADDR;
        object_arg_visitor_t(ea_t c, int a) : ctree_visitor_t(CV_FAST), call_ea(c), arg_idx(a) {}
        int idaapi visit_expr(cexpr_t* e) override
        {
            if (e == nullptr || e->op != cot_call || e->ea != call_ea || e->a == nullptr)
                return 0;
            if (arg_idx < 0 || static_cast<std::size_t>(arg_idx) >= e->a->size())
                return 0;
            cexpr_t* arg = static_cast<cexpr_t*>(&(*e->a)[arg_idx]);
            arg = skip_expr_casts(arg);
            if (arg != nullptr && arg->op == cot_obj)
            {
                out = arg->obj_ea;
                return 1;
            }
            return 0;
        }
    };
    object_arg_visitor_t v(call_ea, arg_idx);
    v.apply_to(&cf->body, nullptr);
    out = v.out;
    return out;
}

void collect_wdf_queue_handlers(std::vector<ioctl_handler_t>& result, std::unordered_set<ea_t>& seen)
{
    std::vector<std::string> names = {"WdfIoQueueCreate"};
    std::vector<callsite_t> calls = aida::vuln::callsites::all_calls_to(names);
    std::vector<std::string> metadata;
    tid_t tid = get_named_type_tid("_WDF_IO_QUEUE_CONFIG");
    if (tid == BADADDR || tid == 0)
        metadata.push_back("wdf_named_type_missing_fallback_offsets");
    else
        metadata.push_back("wdf_named_type_present_offsets_still_cross_checked");
    const ea_t ptrsz = inf_is_64bit() ? 8 : 4;
    const std::vector<ea_t> offsets = {0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78};
    for (const auto& cs : calls)
    {
        ea_t cfg = object_arg_from_call(cs.func_ea, cs.call_ea, 1);
        if (cfg == BADADDR)
        {
            std::vector<std::string> md = metadata;
            md.push_back("wdf_config_arg_not_static_object");
            add_handler_record(result, seen, cs.func_ea, "wdf_queue_create_fallback_caller",
                               "WdfIoQueueCreate caller used as fallback handler", 0xFFFFFFFFu, md);
            continue;
        }
        for (ea_t off : offsets)
        {
            ea_t h = read_ptr_kernel(cfg + off);
            if (!valid_func_start_kernel(h))
                continue;
            std::vector<std::string> md = metadata;
            std::ostringstream ev;
            ev << "WDF_IO_QUEUE_CONFIG candidate at " << format_address_string(cfg)
               << " offset 0x" << std::hex << std::uppercase << static_cast<std::uint64_t>(off);
            add_handler_record(result, seen, h, "wdf_queue_config", ev.str(), 0xFFFFFFFFu, md);
        }
    }
}

struct fastio_assignment_visitor_t : public ctree_visitor_t
{
    std::vector<ea_t> handlers;
    cfunc_t* cfunc = nullptr;
    fastio_assignment_visitor_t(cfunc_t* cf) : ctree_visitor_t(CV_FAST), cfunc(cf) {}
    int idaapi visit_expr(cexpr_t* e) override
    {
        if (e == nullptr || e->op != cot_asg || e->x == nullptr || e->y == nullptr)
            return 0;
        qstring lhs;
        e->x->print1(&lhs, cfunc);
        tag_remove(&lhs);
        std::string s = lhs.c_str();
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (s.find("fastio") == std::string::npos)
            return 0;
        cexpr_t* rhs = skip_expr_casts(e->y);
        if (rhs != nullptr && rhs->op == cot_obj && valid_func_start_kernel(rhs->obj_ea))
            handlers.push_back(rhs->obj_ea);
        return 0;
    }
};

void collect_fastio_handlers(std::vector<ioctl_handler_t>& result, std::unordered_set<ea_t>& seen)
{
    if (!init_hexrays_plugin())
        return;
    const size_t fq = get_func_qty();
    for (size_t i = 0; i < fq; ++i)
    {
        func_t* pfn = getn_func(i);
        if (pfn == nullptr || !ida_utils::is_safely_decompilable(pfn))
            continue;
        cfuncptr_t cf(nullptr);
        try
        {
            cf = decompile_func(pfn, nullptr, DECOMP_NO_WAIT);
        }
        catch (...)
        {
            cf.reset();
        }
        if (!cf)
            continue;
        fastio_assignment_visitor_t v(cf.operator->());
        v.apply_to(&cf->body, nullptr);
        for (ea_t h : v.handlers)
            add_handler_record(result, seen, h, "fastio_dispatch", "FastIoDispatch assignment", 0xFFFFFFFFu, {});
    }
}

void collect_minifilter_handlers(std::vector<ioctl_handler_t>& result, std::unordered_set<ea_t>& seen)
{
    std::vector<callsite_t> calls = aida::vuln::callsites::all_calls_to({"FltRegisterFilter"});
    const ea_t ptrsz = inf_is_64bit() ? 8 : 4;
    const std::vector<ea_t> reg_offsets = {0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50};
    for (const auto& cs : calls)
    {
        ea_t reg = object_arg_from_call(cs.func_ea, cs.call_ea, 1);
        if (reg == BADADDR)
        {
            add_handler_record(result, seen, cs.func_ea, "minifilter_fallback_caller",
                               "FltRegisterFilter registration object not statically resolved", 0xFFFFFFFFu,
                               {"flt_registration_arg_not_static_object"});
            continue;
        }
        for (ea_t off : reg_offsets)
        {
            ea_t ops = read_ptr_kernel(reg + off);
            if (ops == BADADDR || !is_loaded(ops))
                continue;
            for (int i = 0; i < 128; ++i)
            {
                ea_t entry = ops + static_cast<ea_t>(i) * (ptrsz * 4);
                if (!is_loaded(entry))
                    break;
                uint32_t major = get_dword(entry);
                if (major == 0xFFFFFFFFu)
                    break;
                if (major > 0x1Bu)
                    continue;
                ea_t pre = read_ptr_kernel(entry + ptrsz);
                ea_t post = read_ptr_kernel(entry + ptrsz * 2);
                std::ostringstream ev;
                ev << "FLT_OPERATION_REGISTRATION candidate at " << format_address_string(entry)
                   << " major " << major;
                add_handler_record(result, seen, pre, "minifilter_preop", ev.str(), major, {});
                add_handler_record(result, seen, post, "minifilter_postop", ev.str(), major, {});
            }
        }
    }
}

struct user_pointer_use_t
{
    ea_t        deref_ea = BADADDR;
    std::string field;
    bool        is_store = false;
};

struct user_ptr_visitor_t : public ctree_visitor_t
{
    std::vector<user_pointer_use_t> uses;
    std::set<ea_t> probe_for_read_calls;
    std::set<ea_t> probe_for_write_calls;
    std::set<ea_t> any_validator_calls;

    user_ptr_visitor_t() : ctree_visitor_t(CV_PARENTS) {}

    static bool is_validator_name(const std::string& nm)
    {
        for (auto v : aida::vuln::sig::KERNEL_VALIDATORS)
        {
            if (nm.find(std::string(v)) != std::string::npos)
                return true;
        }
        return false;
    }

    static bool member_matches_taint_field(const std::string& member_name)
    {
        if (member_name.empty())
            return false;
        if (member_name == "UserBuffer")
            return true;
        if (member_name == "Type3InputBuffer")
            return true;
        if (member_name == "SystemBuffer")
            return true;
        if (member_name == "MdlAddress")
            return true;
        return false;
    }

    static std::string member_name_for(cexpr_t* mem)
    {
        if (mem == nullptr || mem->x == nullptr)
            return std::string();
        if (mem->op != cot_memptr && mem->op != cot_memref)
            return std::string();
        tinfo_t parent_type = mem->x->type;
        if (mem->op == cot_memptr)
            parent_type.remove_ptr_or_array();
        udt_type_data_t udt;
        if (!parent_type.get_udt_details(&udt))
            return std::string();
        for (size_t i = 0; i < udt.size(); ++i)
        {
            const udm_t& u = udt[i];
            uint64 byte_off = static_cast<uint64>(u.offset) / 8u;
            if (byte_off == static_cast<uint64>(mem->m))
                return u.name.c_str();
        }
        return std::string();
    }

    int idaapi visit_expr(cexpr_t* expr) override
    {
        if (!expr)
            return 0;
        if (expr->op == cot_call && expr->x != nullptr)
        {
            cexpr_t* callee = skip_expr_casts(expr->x);
            std::string nm;
            if (callee != nullptr && callee->op == cot_obj && callee->obj_ea != BADADDR)
            {
                qstring qn;
                if (get_func_name(&qn, callee->obj_ea) > 0)
                    nm = qn.c_str();
                else if (get_name(&qn, callee->obj_ea) > 0)
                    nm = qn.c_str();
            }
            else if (callee != nullptr && callee->op == cot_helper && callee->helper != nullptr)
            {
                nm = callee->helper;
            }
            if (!nm.empty())
            {
                if (nm.find("ProbeForRead") != std::string::npos)
                    probe_for_read_calls.insert(expr->ea);
                if (nm.find("ProbeForWrite") != std::string::npos)
                    probe_for_write_calls.insert(expr->ea);
                if (is_validator_name(nm))
                    any_validator_calls.insert(expr->ea);
            }
            return 0;
        }
        if (expr->op != cot_memptr && expr->op != cot_memref)
            return 0;
        std::string member = member_name_for(expr);
        if (!member_matches_taint_field(member))
            return 0;
        bool found_use = false;
        bool is_store = false;
        ea_t use_ea = expr->ea;
        for (ssize_t i = static_cast<ssize_t>(parents.size()) - 1; i >= 0; --i)
        {
            citem_t* p = parents[i];
            if (p == nullptr)
                continue;
            if (!p->is_expr())
            {
                if (!found_use)
                {
                    found_use = true;
                    use_ea = p->ea;
                }
                break;
            }
            cexpr_t* pe = static_cast<cexpr_t*>(p);
            if (pe->op == cot_ptr || pe->op == cot_idx)
            {
                found_use = true;
                use_ea = pe->ea;
                if (i > 0)
                {
                    citem_t* gp = parents[i - 1];
                    if (gp != nullptr && gp->is_expr())
                    {
                        cexpr_t* gpe = static_cast<cexpr_t*>(gp);
                        if (gpe->op >= cot_asg && gpe->op <= cot_asgumod && gpe->x == pe)
                            is_store = true;
                    }
                }
                break;
            }
            if (pe->op >= cot_asg && pe->op <= cot_asgumod)
            {
                if (pe->x != nullptr && pe->x == expr)
                {
                    found_use = true;
                    use_ea = pe->ea;
                    is_store = true;
                }
                break;
            }
            if (pe->op == cot_call && pe->x != expr)
            {
                found_use = true;
                use_ea = pe->ea;
                break;
            }
        }
        if (!found_use)
            return 0;
        user_pointer_use_t u;
        u.deref_ea = use_ea;
        u.field = member;
        u.is_store = is_store;
        uses.push_back(std::move(u));
        return 0;
    }
};

inline ea_t earliest_validator_for(const user_ptr_visitor_t& v, mba_t* mba, ea_t deref_ea, bool require_write_probe, std::string& which_probe)
{
    if (mba == nullptr)
        return BADADDR;
    auto try_set = [&](const std::set<ea_t>& s, const char* label) -> ea_t {
        for (ea_t pe : s)
        {
            if (pe == BADADDR)
                continue;
            if (aida::vuln::microcode::insn_predates(*mba, pe, deref_ea))
            {
                which_probe = label;
                return pe;
            }
        }
        return BADADDR;
    };
    ea_t found = BADADDR;
    if (require_write_probe)
    {
        found = try_set(v.probe_for_write_calls, "ProbeForWrite");
        if (found != BADADDR)
            return found;
    }
    found = try_set(v.probe_for_read_calls, "ProbeForRead");
    if (found != BADADDR)
        return found;
    found = try_set(v.probe_for_write_calls, "ProbeForWrite");
    if (found != BADADDR)
        return found;
    found = try_set(v.any_validator_calls, "kernel_validator");
    if (found != BADADDR)
        return found;
    return BADADDR;
}

}

bool is_kernel_driver()
{
    if (pe_is_native_subsystem())
        return true;
    if (imports_kernel_module())
        return true;
    if (exported_driver_entry_ea() != BADADDR)
        return true;
    if (named_function_driver_entry_ea() != BADADDR)
        return true;
    return false;
}

ioctl_decoded_t decode_ioctl(uint32_t code)
{
    ioctl_decoded_t d;
    d.code = code;
    d.device_type = static_cast<uint16_t>((code >> 16) & 0xFFFFu);
    d.function_code = static_cast<uint16_t>((code >> 2) & 0xFFFu);
    d.method = static_cast<uint8_t>(code & 0x3u);
    d.access = static_cast<uint8_t>((code >> 14) & 0x3u);
    switch (d.method)
    {
    case 0: d.method_name = "BUFFERED";   break;
    case 1: d.method_name = "IN_DIRECT";  break;
    case 2: d.method_name = "OUT_DIRECT"; break;
    case 3: d.method_name = "NEITHER";    break;
    default: d.method_name = "UNKNOWN";   break;
    }
    switch (d.access)
    {
    case 0: d.access_name = "ANY";        break;
    case 1: d.access_name = "READ";       break;
    case 2: d.access_name = "WRITE";      break;
    case 3: d.access_name = "READ_WRITE"; break;
    default: d.access_name = "UNKNOWN";   break;
    }
    return d;
}

std::vector<ioctl_handler_t> find_ioctl_handlers()
{
    std::vector<ioctl_handler_t> result;
    if (!is_kernel_driver())
        return result;
    std::unordered_set<ea_t> seen_handlers;
    if (!init_hexrays_plugin())
        return result;
    ea_t entry_ea = locate_driver_entry();
    if (entry_ea == BADADDR)
    {
        collect_wdf_queue_handlers(result, seen_handlers);
        collect_fastio_handlers(result, seen_handlers);
        collect_minifilter_handlers(result, seen_handlers);
        return result;
    }
    func_t* pfn = get_func(entry_ea);
    if (pfn != nullptr && ida_utils::is_safely_decompilable(pfn))
    {
        cfuncptr_t cfunc(nullptr);
        try
        {
            cfunc = decompile_func(pfn, nullptr, DECOMP_NO_WAIT);
        }
        catch (const vd_failure_t&)
        {
            cfunc.reset();
        }
        catch (...)
        {
            cfunc.reset();
        }
        if (cfunc != nullptr)
        {
            dispatch_collector_t collector;
            collector.apply_to(&cfunc->body, nullptr);
            result.reserve(collector.handlers.size());
            for (auto& kv : collector.handlers)
            {
                ioctl_handler_t h = std::move(kv.second);
                if (!seen_handlers.insert(h.handler_ea).second)
                    continue;
                h.ioctl_codes = collect_ioctl_codes(h.handler_ea);
                h.source_model = "driver_object_major_function";
                h.evidence = "DriverObject->MajorFunction assignment";
                if (h.major_function == 0xFFFFFFFFu)
                    h.major_function = IRP_MJ_DEVICE_CONTROL_INDEX;
                result.push_back(std::move(h));
            }
        }
    }
    collect_wdf_queue_handlers(result, seen_handlers);
    collect_fastio_handlers(result, seen_handlers);
    collect_minifilter_handlers(result, seen_handlers);
    std::sort(result.begin(), result.end(), [](const ioctl_handler_t& a, const ioctl_handler_t& b) {
        return a.handler_ea < b.handler_ea;
    });
    return result;
}

std::vector<vuln_finding_t> find_user_pointer_derefs(int max_findings)
{
    std::vector<vuln_finding_t> findings;
    if (max_findings <= 0)
        return findings;
    if (!is_kernel_driver())
        return findings;
    if (!init_hexrays_plugin())
        return findings;
    std::vector<ioctl_handler_t> handlers = find_ioctl_handlers();
    if (handlers.empty())
        return findings;
    std::unordered_set<uint64_t> emitted;
    for (const auto& h : handlers)
    {
        if (static_cast<int>(findings.size()) >= max_findings)
            break;
        if (h.handler_ea == BADADDR)
            continue;
        bool has_neither = false;
        std::vector<uint32_t> neither_codes;
        for (uint32_t code : h.ioctl_codes)
        {
            if ((code & 0x3u) == 3u)
            {
                has_neither = true;
                neither_codes.push_back(code);
            }
        }
        if (!has_neither && !h.ioctl_codes.empty())
            continue;
        func_t* pfn = get_func(h.handler_ea);
        if (pfn == nullptr)
            continue;
        if (!ida_utils::is_safely_decompilable(pfn))
            continue;
        cfuncptr_t cfunc(nullptr);
        try
        {
            cfunc = decompile_func(pfn, nullptr, DECOMP_NO_WAIT);
        }
        catch (const vd_failure_t&)
        {
            cfunc.reset();
        }
        catch (...)
        {
            cfunc.reset();
        }
        if (cfunc == nullptr)
            continue;
        user_ptr_visitor_t visitor;
        visitor.apply_to(&cfunc->body, nullptr);
        if (visitor.uses.empty())
            continue;
        auto handle_opt = aida::vuln::microcode::generate(h.handler_ea, MMAT_LVARS);
        mba_t* mba = handle_opt.has_value() ? handle_opt->mba.get() : nullptr;
        uint32_t reporting_code = 0;
        const char* reporting_method = "NEITHER";
        if (!neither_codes.empty())
            reporting_code = neither_codes.front();
        else if (!h.ioctl_codes.empty())
        {
            reporting_code = h.ioctl_codes.front();
            switch (reporting_code & 0x3u)
            {
            case 0: reporting_method = "BUFFERED"; break;
            case 1: reporting_method = "IN_DIRECT"; break;
            case 2: reporting_method = "OUT_DIRECT"; break;
            case 3: reporting_method = "NEITHER"; break;
            }
        }
        for (const auto& u : visitor.uses)
        {
            if (static_cast<int>(findings.size()) >= max_findings)
                break;
            if (u.deref_ea == BADADDR)
                continue;
            uint64_t key = (static_cast<uint64_t>(h.handler_ea) << 1) ^ static_cast<uint64_t>(u.deref_ea);
            if (!emitted.insert(key).second)
                continue;
            std::string which_probe;
            ea_t probe_ea = mba != nullptr
                ? earliest_validator_for(visitor, mba, u.deref_ea, u.is_store, which_probe)
                : BADADDR;
            vuln_finding_t f;
            f.related_eas.push_back(h.handler_ea);
            if (probe_ea == BADADDR)
            {
                f.id = make_finding_id("KERNEL_UNVALIDATED_USERPTR_", u.deref_ea, reporting_code);
                f.severity = severity_t::critical;
                f.confidence = confidence_t::likely;
                f.cwes.push_back(make_cwe(822, "Untrusted Pointer Dereference"));
                f.primary_ea = u.deref_ea;
                f.title = "User-mode pointer dereferenced without ProbeForRead/Write";
                std::ostringstream rss;
                rss << "Handler at " << format_address_string(h.handler_ea)
                    << " (" << h.handler_name << ") dereferences user-controlled field '"
                    << u.field << "' at " << format_address_string(u.deref_ea)
                    << (u.is_store ? " (store)" : " (load)")
                    << " with no preceding ProbeForRead/Write call. Method "
                    << reporting_method << " requires manual validation of the user pointer; "
                    << "absence of ProbeForRead/Write enables arbitrary kernel read/write via "
                    << "an attacker-supplied pointer (CWE-822).";
                f.rationale = rss.str();
                nlohmann::json ev;
                ev["handler_ea"] = format_address_string(h.handler_ea);
                ev["handler_name"] = h.handler_name;
                ev["deref_ea"] = format_address_string(u.deref_ea);
                ev["field"] = u.field;
                ev["method"] = reporting_method;
                ev["ioctl_code"] = static_cast<std::uint64_t>(reporting_code);
                ev["is_store"] = u.is_store;
                ev["no_probe"] = true;
                if (!neither_codes.empty())
                {
                    nlohmann::json codes_arr = nlohmann::json::array();
                    for (uint32_t c : neither_codes)
                        codes_arr.push_back(static_cast<std::uint64_t>(c));
                    ev["neither_ioctl_codes"] = std::move(codes_arr);
                }
                f.evidence = std::move(ev);
            }
            else
            {
                f.id = make_finding_id("KERNEL_PROBE_PRESENT_BUT_WEAK_", u.deref_ea, reporting_code);
                f.severity = severity_t::high;
                f.confidence = confidence_t::plausible;
                f.cwes.push_back(make_cwe(129, "Improper Validation of Array Index"));
                f.primary_ea = u.deref_ea;
                f.title = "Probe present but coverage may not match deref size";
                std::ostringstream rss;
                rss << "Handler at " << format_address_string(h.handler_ea)
                    << " (" << h.handler_name << ") calls " << which_probe << " at "
                    << format_address_string(probe_ea) << " before dereferencing user-controlled "
                    << "field '" << u.field << "' at " << format_address_string(u.deref_ea)
                    << (u.is_store ? " (store)" : " (load)") << ". The probe size cannot be "
                    << "statically tied to the dereferenced size at this maturity level; if the "
                    << "probe length is attacker-controlled or smaller than the access width, the "
                    << "validation is bypassable (CWE-129).";
                f.rationale = rss.str();
                nlohmann::json ev;
                ev["handler_ea"] = format_address_string(h.handler_ea);
                ev["handler_name"] = h.handler_name;
                ev["deref_ea"] = format_address_string(u.deref_ea);
                ev["field"] = u.field;
                ev["method"] = reporting_method;
                ev["ioctl_code"] = static_cast<std::uint64_t>(reporting_code);
                ev["is_store"] = u.is_store;
                ev["probe_ea"] = format_address_string(probe_ea);
                ev["probe_kind"] = which_probe;
                ev["mismatch_reason"] = "probe_size_not_proven_to_cover_deref_width";
                f.evidence = std::move(ev);
            }
            findings.push_back(std::move(f));
        }
    }
    return findings;
}

namespace tools
{

namespace
{

inline int extract_int_param(const nlohmann::json& params, const char* key, int default_value)
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

inline nlohmann::json findings_to_json(const std::vector<vuln_finding_t>& findings)
{
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& f : findings)
        arr.push_back(to_json(f));
    return arr;
}

inline nlohmann::json decoded_to_json(const ioctl_decoded_t& d)
{
    nlohmann::json j;
    j["code"] = static_cast<std::uint64_t>(d.code);
    j["code_hex"] = format_address_string(static_cast<ea_t>(d.code));
    j["device_type"] = static_cast<std::uint32_t>(d.device_type);
    j["function_code"] = static_cast<std::uint32_t>(d.function_code);
    j["method"] = static_cast<std::uint32_t>(d.method);
    j["method_name"] = d.method_name != nullptr ? d.method_name : "";
    j["access"] = static_cast<std::uint32_t>(d.access);
    j["access_name"] = d.access_name != nullptr ? d.access_name : "";
    return j;
}

}

agent_tools::tool_result_t handle_find_kernel_ioctl_handlers(const nlohmann::json&)
{
    if (!is_kernel_driver())
    {
        return agent_tools::tool_result_t::error(
            std::string("Not a kernel driver - analyze_pe_headers + DriverEntry check failed"));
    }
    ea_t entry_ea = locate_driver_entry();
    std::vector<ioctl_handler_t> handlers = find_ioctl_handlers();
    nlohmann::json data;
    data["is_driver"] = true;
    data["driver_entry_ea"] = format_address_string(entry_ea);
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& h : handlers)
    {
        nlohmann::json hj;
        hj["handler_ea"] = format_address_string(h.handler_ea);
        hj["name"] = h.handler_name;
        hj["source_model"] = h.source_model;
        hj["evidence"] = h.evidence;
        hj["major_function"] = h.major_function;
        hj["fallback_metadata"] = h.fallback_metadata;
        nlohmann::json codes = nlohmann::json::array();
        for (uint32_t c : h.ioctl_codes)
            codes.push_back(decoded_to_json(decode_ioctl(c)));
        hj["ioctl_codes"] = std::move(codes);
        arr.push_back(std::move(hj));
    }
    data["dispatcher_handlers"] = std::move(arr);
    data["total_handlers"] = handlers.size();
    std::string msg = std::string("Kernel IOCTL dispatcher scan: ") +
                      std::to_string(handlers.size()) +
                      std::string(" handler(s)");
    return agent_tools::tool_result_t::ok(msg, data);
}

agent_tools::tool_result_t handle_find_user_pointer_deref(const nlohmann::json& params)
{
    if (!is_kernel_driver())
        return agent_tools::tool_result_t::error(std::string("Not a kernel driver"));
    int limit = extract_int_param(params, "limit", 64);
    if (limit <= 0)
        return agent_tools::tool_result_t::error(std::string("limit must be a positive integer"));
    if (limit > 4096)
        limit = 4096;
    std::vector<vuln_finding_t> findings = find_user_pointer_derefs(limit);
    nlohmann::json data;
    data["count"] = findings.size();
    data["findings"] = findings_to_json(findings);
    data["limit"] = limit;
    data["primary_cwe"] = 822;
    std::string msg = std::string("User-pointer dereference scan: ") +
                      std::to_string(findings.size()) +
                      std::string(" finding(s)");
    return agent_tools::tool_result_t::ok(msg, data);
}

void register_tier1_kernel_tools()
{
    auto& registry = agent_tools::ToolRegistry::instance();

    registry.register_tool({
        std::string("find_kernel_ioctl_handlers"),
        std::string("vuln"),
        std::string("Detect a Windows kernel driver and enumerate its IRP_MJ_DEVICE_CONTROL "
               "dispatcher(s). Locates DriverEntry (export, named symbol, or shape match), "
               "decompiles it, and walks the C-tree for assignments to "
               "DriverObject->MajorFunction[14] (IRP_MJ_DEVICE_CONTROL). Loop-init and "
               "sequential-write idioms are both recognised. For each dispatcher, the "
               "function's microcode is then scanned for compares against the "
               "Irp->IoStackLocation->IoControlCode field; the captured immediates are "
               "reported with CTL_CODE-decomposed device_type/function_code/method/access. "
               "If microcode IOCTL probes return nothing the engine falls back to a "
               "disassembly cmp/sub immediate scan with an IOCTL-shape heuristic."),
        {},
        handle_find_kernel_ioctl_handlers,
        true,
    });

    registry.register_tool({
        std::string("find_user_pointer_deref"),
        std::string("vuln"),
        std::string("Find user-mode pointer dereferences in a Windows kernel driver's IOCTL "
               "dispatchers that occur without a preceding ProbeForRead/Write call. "
               "For every dispatcher the engine decompiles the handler, walks the C-tree "
               "for memptr accesses to known user-pointer fields (UserBuffer, "
               "Type3InputBuffer, AssociatedIrp.SystemBuffer, MdlAddress) and uses "
               "microcode insn-precedes ordering to determine whether ProbeForRead/Write "
               "(or another kernel validator from KERNEL_VALIDATORS) executes earlier on "
               "every path. Method-NEITHER IOCTLs are prioritised because manual probing "
               "is mandatory there. Emits CWE-822 (Untrusted Pointer Dereference) when no "
               "probe is present and CWE-129 (Improper Validation of Array Index) when a "
               "probe exists but its size cannot be statically proven to cover the "
               "dereferenced width."),
        {
            {std::string("limit"), std::string("number"),
             std::string("Maximum number of findings to return (default 64, max 4096)"), false},
        },
        handle_find_user_pointer_deref,
        true,
    });
}

}

}
}
}
