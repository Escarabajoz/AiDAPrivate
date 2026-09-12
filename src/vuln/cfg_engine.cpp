#include "../aida_pro.hpp"

#include "vuln_tools.hpp"
#include "microcode_engine.hpp"
#include "vuln_signatures.hpp"

#include <nlohmann/json.hpp>
#include <ida.hpp>
#include <funcs.hpp>
#include <bytes.hpp>
#include <name.hpp>
#include <nalt.hpp>
#include <xref.hpp>
#include <segment.hpp>
#include <typeinf.hpp>
#include <gdl.hpp>
#include <netnode.hpp>
#include <ua.hpp>
#include <allins.hpp>
#include <hexrays.hpp>
#include <demangle.hpp>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <limits>
#include <mutex>
#include <optional>
#include <queue>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace aida
{
namespace vuln
{
namespace cfg_engine
{

namespace
{

using nlohmann::json;
using agent_tools::tool_result_t;

constexpr size_t kMaxIndirectCallsPerFunc = 32u;
constexpr size_t kMaxTargetsPerCall = 16u;
constexpr size_t kMaxAllFuncsScan = 4096u;
constexpr size_t kMaxBypassPathDepth = 16u;
constexpr size_t kMaxBypassPathsCap = 64u;
constexpr int    kMaxConstScanBackBytes = 96;

std::string fmt_addr(ea_t ea)
{
    if (ea == BADADDR)
        return std::string(std::string("0x0"));
    return agent_tools::helpers::format_address(ea);
}

std::string name_of(ea_t ea)
{
    if (ea == BADADDR)
        return std::string();
    qstring nm;
    if (get_name(&nm, ea) > 0 && !nm.empty())
        return std::string(nm.c_str());
    return std::string();
}

std::string demangle_or_name(ea_t ea)
{
    qstring nm;
    if (get_name(&nm, ea) <= 0 || nm.empty())
        return std::string();
    qstring dem;
    if (demangle_name(&dem, nm.c_str(), 0) > 0 && !dem.empty())
        return std::string(dem.c_str());
    return std::string(nm.c_str());
}

bool ea_in_code_segment(ea_t ea)
{
    if (ea == BADADDR || !is_loaded(ea))
        return false;
    segment_t* s = getseg(ea);
    if (!s)
        return false;
    return s->type == SEG_CODE;
}

bool is_indirect_call_insn(const insn_t& ins)
{
    return ins.itype == NN_callni || ins.itype == NN_callfi;
}

bool is_unconditional_jmp(const insn_t& ins)
{
    return ins.itype == NN_jmp;
}

bool is_conditional_jmp(const insn_t& ins)
{
    switch (ins.itype)
    {
    case NN_ja:    case NN_jae:   case NN_jb:    case NN_jbe:
    case NN_jc:    case NN_jcxz:  case NN_jecxz: case NN_jrcxz:
    case NN_je:    case NN_jg:    case NN_jge:   case NN_jl:
    case NN_jle:   case NN_jna:   case NN_jnae:  case NN_jnb:
    case NN_jnbe:  case NN_jnc:   case NN_jne:   case NN_jng:
    case NN_jnge:  case NN_jnl:   case NN_jnle:  case NN_jno:
    case NN_jnp:   case NN_jns:   case NN_jnz:   case NN_jo:
    case NN_jp:    case NN_jpe:   case NN_jpo:   case NN_js:
    case NN_jz:
        return true;
    default:
        return false;
    }
}

void merge_targets(std::vector<indirect_target_t>& dst, indirect_target_t add)
{
    if (add.target_ea == BADADDR && add.name.empty())
        return;
    for (auto& t : dst)
    {
        if (t.target_ea == add.target_ea && t.source == add.source && t.name == add.name)
            return;
    }
    if (dst.size() >= kMaxTargetsPerCall)
        return;
    dst.push_back(std::move(add));
}

void append_reason(std::string& reason, const std::string& tag)
{
    if (reason.empty())
    {
        reason = tag;
        return;
    }
    if (reason.find(tag) != std::string::npos)
        return;
    reason += ',';
    reason += tag;
}

bool resolve_typeinfo(ea_t call_ea, indirect_target_t& out_t)
{
    tinfo_t tif;
    if (!get_tinfo(&tif, call_ea))
        return false;

    tinfo_t pointed = tif;
    if (pointed.is_ptr())
        pointed.remove_ptr_or_array();

    if (!pointed.is_func() && !tif.is_funcptr())
        return false;

    qstring tstr;
    if (pointed.print(&tstr))
    {
        out_t.name = tstr.c_str();
    }
    out_t.source = std::string("typeinfo");
    out_t.rationale = std::string("Operand has function-pointer type info attached");
    out_t.target_ea = BADADDR;
    return true;
}

bool resolve_direct_mem_operand(const insn_t& ins, indirect_target_t& out_t)
{
    const op_t& op = ins.ops[0];
    if (op.type != o_mem)
        return false;
    ea_t slot = static_cast<ea_t>(op.addr);
    if (!is_loaded(slot))
        return false;
    bool is_64 = inf_is_64bit();
    ea_t target = is_64 ? static_cast<ea_t>(get_qword(slot))
                        : static_cast<ea_t>(get_dword(slot));
    if (target == 0 || !is_loaded(target))
        return false;
    if (!ea_in_code_segment(target))
        return false;

    out_t.target_ea = target;
    out_t.name = demangle_or_name(target);
    if (out_t.name.empty())
        out_t.name = name_of(slot);
    out_t.source = std::string("global_fptr");
    out_t.rationale = std::string("Indirect call reads function pointer from a global slot pointing into a code segment");
    return true;
}

void resolve_xrefs(ea_t call_ea, std::vector<indirect_target_t>& out, std::string& reason)
{
    xrefblk_t xb;
    int count = 0;
    for (bool ok = xb.first_from(call_ea, XREF_ALL); ok && count < 64; ok = xb.next_from(), ++count)
    {
        if (!xb.iscode)
            continue;
        if (xb.type != fl_CN && xb.type != fl_CF && xb.type != fl_JN && xb.type != fl_JF)
            continue;
        if (!ea_in_code_segment(xb.to))
            continue;
        func_t* tf = get_func(xb.to);
        if (!tf || tf->start_ea != xb.to)
            continue;
        indirect_target_t t;
        t.target_ea = xb.to;
        t.name = demangle_or_name(xb.to);
        t.source = std::string("xref_switch");
        t.rationale = std::string("IDA cross-reference resolved this indirect target (switch table or analyzer trace)");
        size_t before = out.size();
        merge_targets(out, std::move(t));
        if (out.size() != before)
            append_reason(reason, std::string("xref_switch"));
    }
}

bool init_hexrays_safely()
{
    static bool checked = false;
    static bool ok = false;
    if (!checked)
    {
        try
        {
            ok = init_hexrays_plugin();
        }
        catch (...)
        {
            ok = false;
        }
        checked = true;
    }
    return ok;
}

struct vtable_visitor_t : public ctree_visitor_t
{
    ea_t                     target_call_ea = BADADDR;
    bool                     hit_vtable = false;
    bool                     hit_obj_call = false;
    ea_t                     resolved_obj_ea = BADADDR;
    uint32_t                 member_offset = 0;
    int                      ptr_size = 0;

    vtable_visitor_t() : ctree_visitor_t(CV_PARENTS) {}

    int idaapi visit_expr(cexpr_t* e) override
    {
        if (!e || e->op != cot_call || e->ea != target_call_ea)
            return 0;
        cexpr_t* callee = e->x;
        if (!callee)
            return 0;

        cexpr_t* probe = callee;
        while (probe && (probe->op == cot_cast || probe->op == cot_ref))
            probe = probe->x;
        if (!probe)
            return 0;

        if (probe->op == cot_memptr || probe->op == cot_memref)
        {
            hit_vtable = true;
            member_offset = probe->m;
            ptr_size = probe->ptrsize;
            cexpr_t* base = probe->x;
            while (base && (base->op == cot_cast || base->op == cot_ref))
                base = base->x;
            if (base && base->op == cot_obj)
                resolved_obj_ea = base->obj_ea;
            return 1;
        }

        if (probe->op == cot_obj)
        {
            hit_obj_call = true;
            resolved_obj_ea = probe->obj_ea;
            return 1;
        }

        if (probe->op == cot_idx)
        {
            hit_vtable = true;
            cexpr_t* base = probe->x;
            while (base && (base->op == cot_cast || base->op == cot_ref))
                base = base->x;
            if (base && base->op == cot_obj)
                resolved_obj_ea = base->obj_ea;
            return 1;
        }
        return 0;
    }
};

void resolve_via_vtable(ea_t call_ea, ea_t func_ea, std::vector<indirect_target_t>& out, std::string& reason)
{
    if (!init_hexrays_safely())
        return;
    func_t* pfn = get_func(func_ea);
    if (!pfn)
        return;

    cfuncptr_t cfunc(nullptr);
    try
    {
        cfunc = decompile_func(pfn, nullptr, DECOMP_NO_WAIT);
    }
    catch (const vd_failure_t&)
    {
        return;
    }
    catch (...)
    {
        return;
    }
    if (!cfunc)
        return;

    vtable_visitor_t vv;
    vv.target_call_ea = call_ea;
    try
    {
        vv.apply_to(&cfunc->body, nullptr);
    }
    catch (...)
    {
        return;
    }

    if (vv.hit_obj_call && vv.resolved_obj_ea != BADADDR)
    {
        if (ea_in_code_segment(vv.resolved_obj_ea))
        {
            indirect_target_t t;
            t.target_ea = vv.resolved_obj_ea;
            t.name = demangle_or_name(vv.resolved_obj_ea);
            t.source = std::string("hexrays_obj");
            t.rationale = std::string("Hex-Rays resolved indirect call to an object whose ea is a code-segment entry");
            size_t before = out.size();
            merge_targets(out, std::move(t));
            if (out.size() != before)
                append_reason(reason, std::string("hexrays_obj"));
            return;
        }
    }

    if (!vv.hit_vtable || vv.resolved_obj_ea == BADADDR)
        return;
    if (!is_loaded(vv.resolved_obj_ea))
        return;

    bool is_64 = inf_is_64bit();
    size_t ptr_sz = is_64 ? 8u : 4u;
    ea_t vtable_base = vv.resolved_obj_ea;

    if (is_64 && is_loaded(vtable_base) && getseg(vtable_base) && getseg(vtable_base)->type != SEG_CODE)
    {
        ea_t maybe = static_cast<ea_t>(get_qword(vtable_base));
        if (is_loaded(maybe) && getseg(maybe) && getseg(maybe)->type != SEG_CODE)
            vtable_base = maybe;
    }

    ea_t entry_ea = vtable_base + static_cast<ea_t>(vv.member_offset);
    if (!is_loaded(entry_ea))
        return;

    ea_t fn_addr = is_64 ? static_cast<ea_t>(get_qword(entry_ea))
                         : static_cast<ea_t>(get_dword(entry_ea));
    if (fn_addr == 0 || !ea_in_code_segment(fn_addr))
    {
        ea_t scan = vtable_base;
        for (size_t i = 0; i < 8 && is_loaded(scan); ++i)
        {
            ea_t v = is_64 ? static_cast<ea_t>(get_qword(scan))
                           : static_cast<ea_t>(get_dword(scan));
            if (v && ea_in_code_segment(v))
            {
                indirect_target_t t;
                t.target_ea = v;
                t.name = demangle_or_name(v);
                t.source = std::string("vtable");
                t.rationale = std::string("Hex-Rays vtable trace: candidate slot ") + fmt_addr(scan);
                size_t before = out.size();
                merge_targets(out, std::move(t));
                if (out.size() != before)
                    append_reason(reason, std::string("vtable"));
            }
            scan += static_cast<ea_t>(ptr_sz);
        }
        return;
    }

    indirect_target_t t;
    t.target_ea = fn_addr;
    t.name = demangle_or_name(fn_addr);
    t.source = std::string("vtable");
    t.rationale = std::string("Hex-Rays resolved vtable slot at ") + fmt_addr(entry_ea);
    size_t before = out.size();
    merge_targets(out, std::move(t));
    if (out.size() != before)
        append_reason(reason, std::string("vtable"));

    ea_t col_ea = is_64 ? (vtable_base >= 8 ? vtable_base - 8 : BADADDR)
                        : (vtable_base >= 4 ? vtable_base - 4 : BADADDR);
    if (col_ea != BADADDR && is_loaded(col_ea))
    {
        ea_t col_ptr = is_64 ? static_cast<ea_t>(get_qword(col_ea))
                             : static_cast<ea_t>(get_dword(col_ea));
        if (is_loaded(col_ptr))
        {
            uint32_t sig = get_dword(col_ptr);
            if (sig == 0u || sig == 1u)
            {
                int32_t td_off = static_cast<int32_t>(get_dword(col_ptr + 12));
                int32_t self_off = static_cast<int32_t>(get_dword(col_ptr + 20));
                uint64_t img_base = static_cast<uint64_t>(col_ptr) - static_cast<uint64_t>(static_cast<int64_t>(self_off));
                ea_t td = static_cast<ea_t>(img_base + static_cast<uint64_t>(static_cast<int64_t>(td_off)));
                if (is_loaded(td + 16))
                {
                    char tname[256] = {};
                    for (int i = 0; i < 255; ++i)
                    {
                        char ch = static_cast<char>(get_byte(td + 16 + static_cast<ea_t>(i)));
                        if (!ch)
                            break;
                        tname[i] = ch;
                    }
                    if (tname[0] != 0)
                    {
                        indirect_target_t r;
                        r.target_ea = BADADDR;
                        r.name = tname;
                        qstring dem;
                        if (demangle_name(&dem, tname, 0) > 0 && !dem.empty())
                            r.name = dem.c_str();
                        r.source = std::string("rtti");
                        r.rationale = std::string("MSVC RTTI class hierarchy descriptor at ") + fmt_addr(col_ptr);
                        size_t before2 = out.size();
                        merge_targets(out, std::move(r));
                        if (out.size() != before2)
                            append_reason(reason, std::string("rtti"));
                    }
                }
            }
        }
    }
}

void resolve_via_microcode(ea_t call_ea, ea_t func_ea, std::vector<indirect_target_t>& out, std::string& reason)
{
    auto handle = aida::vuln::microcode::generate(func_ea, MMAT_LVARS);
    if (!handle.has_value() || !handle->mba)
        return;
    mba_t* mba = handle->mba.get();
    int qty = mba->qty;
    for (int b = 0; b < qty; ++b)
    {
        mblock_t* blk = mba->get_mblock(static_cast<uint>(b));
        if (!blk)
            continue;
        for (minsn_t* m = blk->head; m != nullptr; m = m->next)
        {
            if (m->ea != call_ea)
                continue;
            if (m->opcode != m_icall && m->opcode != m_call)
                continue;
            if (m->opcode == m_call)
                continue;

            if (m->l.t == mop_v && ea_in_code_segment(m->l.g))
            {
                indirect_target_t t;
                t.target_ea = m->l.g;
                t.name = demangle_or_name(m->l.g);
                t.source = std::string("microcode");
                t.rationale = std::string("Microcode call target is a global value (mop_v) in a code segment");
                size_t before = out.size();
                merge_targets(out, std::move(t));
                if (out.size() != before)
                    append_reason(reason, std::string("microcode"));
                continue;
            }

            auto chain = aida::vuln::microcode::def_use_chain(*mba, m->l);
            if (chain.defs.empty())
                continue;

            bool is_64 = inf_is_64bit();

            int probed = 0;
            for (ea_t def_ea : chain.defs)
            {
                if (++probed > 8)
                    break;
                insn_t di;
                if (decode_insn(&di, def_ea) <= 0)
                    continue;
                for (int oi = 0; oi < UA_MAXOP; ++oi)
                {
                    const op_t& op = di.ops[oi];
                    if (op.type == o_void)
                        break;
                    ea_t cand = BADADDR;
                    if (op.type == o_imm)
                        cand = static_cast<ea_t>(op.value);
                    else if (op.type == o_mem)
                    {
                        ea_t slot = static_cast<ea_t>(op.addr);
                        if (is_loaded(slot))
                        {
                            cand = is_64 ? static_cast<ea_t>(get_qword(slot))
                                         : static_cast<ea_t>(get_dword(slot));
                        }
                    }
                    if (cand == BADADDR || cand == 0)
                        continue;
                    if (!ea_in_code_segment(cand))
                        continue;
                    func_t* tf = get_func(cand);
                    if (!tf || tf->start_ea != cand)
                        continue;
                    indirect_target_t t;
                    t.target_ea = cand;
                    t.name = demangle_or_name(cand);
                    t.source = std::string("microcode_ssa");
                    t.rationale = std::string("Microcode SSA def-use trace from call operand to constant function pointer at ") + fmt_addr(def_ea);
                    size_t before = out.size();
                    merge_targets(out, std::move(t));
                    if (out.size() != before)
                        append_reason(reason, std::string("microcode_ssa"));
                }
                if (out.size() >= kMaxTargetsPerCall)
                    break;
            }
        }
    }
}

void resolve_via_constant_pool(ea_t call_ea, ea_t func_ea, std::vector<indirect_target_t>& out, std::string& reason)
{
    func_t* pfn = get_func(func_ea);
    if (!pfn)
        return;
    ea_t lo = pfn->start_ea;
    ea_t scan = call_ea;
    int budget = kMaxConstScanBackBytes;
    int hits = 0;
    while (scan > lo && budget > 0 && hits < 8)
    {
        ea_t prev = prev_head(scan, lo);
        if (prev == BADADDR || prev < lo)
            break;
        budget -= static_cast<int>(scan - prev);
        scan = prev;
        insn_t di;
        if (decode_insn(&di, prev) <= 0)
            continue;
        if (di.itype != NN_lea && di.itype != NN_mov)
            continue;
        for (int oi = 0; oi < UA_MAXOP; ++oi)
        {
            const op_t& op = di.ops[oi];
            if (op.type == o_void)
                break;
            ea_t cand = BADADDR;
            if (op.type == o_mem || op.type == o_far || op.type == o_near)
                cand = static_cast<ea_t>(op.addr);
            else if (op.type == o_imm)
                cand = static_cast<ea_t>(op.value);
            if (cand == BADADDR || cand == 0)
                continue;
            if (!ea_in_code_segment(cand))
                continue;
            func_t* tf = get_func(cand);
            if (!tf || tf->start_ea != cand)
                continue;
            indirect_target_t t;
            t.target_ea = cand;
            t.name = demangle_or_name(cand);
            t.source = std::string("const_lea");
            t.rationale = std::string("Backwards scan found lea/mov of code address ") + fmt_addr(cand) + std::string(" at ") + fmt_addr(prev);
            size_t before = out.size();
            merge_targets(out, std::move(t));
            if (out.size() != before)
            {
                append_reason(reason, std::string("const_lea"));
                ++hits;
            }
        }
    }
}

indirect_call_t analyze_indirect_call(ea_t call_ea, ea_t func_ea, const insn_t& ins)
{
    indirect_call_t ic;
    ic.call_ea = call_ea;
    ic.func_ea = func_ea;

    if (ins.ops[0].type == o_mem)
    {
        indirect_target_t direct;
        if (resolve_direct_mem_operand(ins, direct))
        {
            merge_targets(ic.targets, std::move(direct));
            append_reason(ic.reason, std::string("global_fptr"));
        }
    }

    indirect_target_t ti;
    if (resolve_typeinfo(call_ea, ti))
    {
        merge_targets(ic.targets, std::move(ti));
        append_reason(ic.reason, std::string("typeinfo"));
    }

    resolve_xrefs(call_ea, ic.targets, ic.reason);
    resolve_via_vtable(call_ea, func_ea, ic.targets, ic.reason);
    resolve_via_constant_pool(call_ea, func_ea, ic.targets, ic.reason);
    resolve_via_microcode(call_ea, func_ea, ic.targets, ic.reason);

    if (ic.reason.empty())
        ic.reason = std::string("unresolved");

    return ic;
}

std::vector<indirect_call_t> scan_function(ea_t func_ea)
{
    std::vector<indirect_call_t> out;
    func_t* pfn = get_func(func_ea);
    if (!pfn)
        return out;

    func_item_iterator_t fii(pfn);
    size_t found = 0;
    for (bool ok = fii.first(); ok && found < kMaxIndirectCallsPerFunc; ok = fii.next_head())
    {
        ea_t cur = fii.current();
        insn_t ins;
        if (decode_insn(&ins, cur) <= 0)
            continue;
        if (!is_indirect_call_insn(ins))
            continue;
        indirect_call_t ic = analyze_indirect_call(cur, pfn->start_ea, ins);
        out.push_back(std::move(ic));
        ++found;
    }
    return out;
}

json target_to_json(const indirect_target_t& t)
{
    json j;
    j["target_ea"] = fmt_addr(t.target_ea);
    j["name"]      = t.name;
    j["source"]    = t.source;
    j["rationale"] = t.rationale;
    return j;
}

json call_to_json(const indirect_call_t& ic)
{
    json j;
    j["call_ea"]   = fmt_addr(ic.call_ea);
    j["func_ea"]   = fmt_addr(ic.func_ea);
    qstring fnm;
    if (get_func_name(&fnm, ic.func_ea) > 0 && !fnm.empty())
        j["func_name"] = fnm.c_str();
    else
        j["func_name"] = name_of(ic.func_ea);
    json arr = json::array();
    for (const auto& t : ic.targets)
        arr.push_back(target_to_json(t));
    j["targets"] = std::move(arr);
    j["reason"]  = ic.reason;
    return j;
}

int find_block_containing(const qflow_chart_t& fc, ea_t ea)
{
    int n = fc.size();
    for (int i = 0; i < n; ++i)
    {
        const qbasic_block_t& bb = fc.blocks[i];
        if (ea >= bb.start_ea && ea < bb.end_ea)
            return i;
    }
    return -1;
}

ea_t block_terminator_ea(const qflow_chart_t& fc, int idx)
{
    if (idx < 0 || idx >= fc.size())
        return BADADDR;
    const qbasic_block_t& bb = fc.blocks[idx];
    if (bb.start_ea >= bb.end_ea)
        return BADADDR;
    ea_t scan = bb.end_ea;
    func_t* pfn = fc.pfn;
    ea_t lo = pfn ? pfn->start_ea : bb.start_ea;
    ea_t prev = prev_head(scan, lo);
    if (prev == BADADDR || prev < bb.start_ea)
        return BADADDR;
    return prev;
}

std::string describe_branch_kind(const qflow_chart_t& fc, int from_idx, int to_idx, int avoid_idx)
{
    ea_t term_ea = block_terminator_ea(fc, from_idx);
    if (term_ea == BADADDR)
        return std::string(std::string("fallthrough"));
    insn_t ins;
    if (decode_insn(&ins, term_ea) <= 0)
        return std::string(std::string("fallthrough"));
    if (is_unconditional_jmp(ins))
        return std::string("unconditional_jmp@") + fmt_addr(term_ea);
    if (is_conditional_jmp(ins))
    {
        ea_t taken = static_cast<ea_t>(ins.ops[0].addr);
        const qbasic_block_t& tgt = fc.blocks[to_idx];
        const qbasic_block_t& bypassed = fc.blocks[avoid_idx];
        bool taken_to_tgt = (taken >= tgt.start_ea && taken < tgt.end_ea);
        bool taken_to_avoid = (taken >= bypassed.start_ea && taken < bypassed.end_ea);
        if (taken_to_tgt)
            return std::string("true_branch_at_") + fmt_addr(term_ea);
        if (taken_to_avoid)
            return std::string("false_branch_at_") + fmt_addr(term_ea);
        return std::string("conditional_at_") + fmt_addr(term_ea);
    }
    if (ins.itype == NN_call || ins.itype == NN_callni || ins.itype == NN_callfi)
        return std::string("post_call_at_") + fmt_addr(term_ea);
    return std::string("flow_at_") + fmt_addr(term_ea);
}

std::vector<ea_t> collect_block_eas(const qflow_chart_t& fc, int idx)
{
    std::vector<ea_t> out;
    if (idx < 0 || idx >= fc.size())
        return out;
    const qbasic_block_t& bb = fc.blocks[idx];
    if (bb.start_ea >= bb.end_ea)
        return out;
    func_t* pfn = fc.pfn;
    func_item_iterator_t fii;
    if (pfn)
        fii.set(pfn, bb.start_ea);
    else
        fii.set_range(bb.start_ea, bb.end_ea);
    if (fii.current() < bb.start_ea)
        fii.set_ea(bb.start_ea);
    out.push_back(bb.start_ea);
    while (fii.next_head())
    {
        ea_t cur = fii.current();
        if (cur >= bb.end_ea)
            break;
        out.push_back(cur);
        if (out.size() > 256)
            break;
    }
    return out;
}

void enumerate_paths(const qflow_chart_t& fc,
                     int entry,
                     int sink,
                     int avoid,
                     size_t max_paths,
                     std::vector<std::vector<int>>& paths)
{
    if (entry == avoid)
        return;
    int qty = fc.size();
    if (qty <= 0)
        return;

    std::vector<int> path;
    std::vector<bool> on_path(static_cast<size_t>(qty), false);

    std::function<void(int)> dfs = [&](int node)
    {
        if (paths.size() >= max_paths)
            return;
        if (node == avoid)
            return;
        if (path.size() > kMaxBypassPathDepth)
            return;
        if (on_path[static_cast<size_t>(node)])
            return;
        path.push_back(node);
        on_path[static_cast<size_t>(node)] = true;

        if (node == sink)
        {
            paths.push_back(path);
        }
        else
        {
            int succ_n = fc.nsucc(node);
            for (int s = 0; s < succ_n && paths.size() < max_paths; ++s)
            {
                int next = fc.succ(node, s);
                if (next < 0 || next >= qty)
                    continue;
                if (next == avoid)
                    continue;
                if (on_path[static_cast<size_t>(next)])
                    continue;
                dfs(next);
            }
        }

        on_path[static_cast<size_t>(node)] = false;
        path.pop_back();
    };

    dfs(entry);
}

int dom_intersect(const std::vector<int>& postdom,
                  const std::vector<int>& postorder_index,
                  int b1, int b2)
{
    int finger1 = b1;
    int finger2 = b2;
    while (finger1 != finger2)
    {
        if (finger1 < 0 || finger2 < 0)
            return -1;
        while (finger1 != finger2 && postorder_index[static_cast<size_t>(finger1)] < postorder_index[static_cast<size_t>(finger2)])
        {
            int next = postdom[static_cast<size_t>(finger1)];
            if (next == finger1 || next < 0)
                return -1;
            finger1 = next;
        }
        while (finger1 != finger2 && postorder_index[static_cast<size_t>(finger2)] < postorder_index[static_cast<size_t>(finger1)])
        {
            int next = postdom[static_cast<size_t>(finger2)];
            if (next == finger2 || next < 0)
                return -1;
            finger2 = next;
        }
    }
    return finger1;
}

void compute_postorder_reverse(int virtual_exit_id, int total,
                               const std::vector<std::vector<int>>& reverse_succ,
                               std::vector<int>& reverse_postorder)
{
    std::vector<bool> visited(static_cast<size_t>(total), false);
    std::vector<int> stack;
    std::vector<int> idx_stack;
    stack.push_back(virtual_exit_id);
    idx_stack.push_back(0);
    visited[static_cast<size_t>(virtual_exit_id)] = true;
    while (!stack.empty())
    {
        int u = stack.back();
        int& it = idx_stack.back();
        const auto& succs = reverse_succ[static_cast<size_t>(u)];
        if (it < static_cast<int>(succs.size()))
        {
            int v = succs[static_cast<size_t>(it++)];
            if (!visited[static_cast<size_t>(v)])
            {
                visited[static_cast<size_t>(v)] = true;
                stack.push_back(v);
                idx_stack.push_back(0);
            }
        }
        else
        {
            reverse_postorder.push_back(u);
            stack.pop_back();
            idx_stack.pop_back();
        }
    }
    std::reverse(reverse_postorder.begin(), reverse_postorder.end());
}

std::vector<int> compute_post_dominators(const qflow_chart_t& fc)
{
    int qty = fc.size();
    int virtual_exit_id = qty;
    int total = qty + 1;

    std::vector<std::vector<int>> reverse_succ(static_cast<size_t>(total));
    for (int i = 0; i < qty; ++i)
    {
        int sn = fc.nsucc(i);
        if (sn == 0)
        {
            reverse_succ[static_cast<size_t>(virtual_exit_id)].push_back(i);
        }
        else
        {
            for (int s = 0; s < sn; ++s)
            {
                int next = fc.succ(i, s);
                if (next < 0 || next >= qty)
                    continue;
                reverse_succ[static_cast<size_t>(next)].push_back(i);
            }
        }
    }

    std::vector<int> rpo;
    rpo.reserve(static_cast<size_t>(total));
    compute_postorder_reverse(virtual_exit_id, total, reverse_succ, rpo);

    std::vector<int> postorder_index(static_cast<size_t>(total), -1);
    for (int i = static_cast<int>(rpo.size()) - 1; i >= 0; --i)
    {
        int node = rpo[static_cast<size_t>(i)];
        postorder_index[static_cast<size_t>(node)] = static_cast<int>(rpo.size()) - 1 - i;
    }

    std::vector<int> postdom(static_cast<size_t>(total), -1);
    postdom[static_cast<size_t>(virtual_exit_id)] = virtual_exit_id;

    bool changed = true;
    int safety = 0;
    while (changed && safety < 4096)
    {
        changed = false;
        ++safety;
        for (int node : rpo)
        {
            if (node == virtual_exit_id)
                continue;
            int new_idom = -1;
            int sn = (node < qty) ? fc.nsucc(node) : 0;
            std::vector<int> succs;
            if (node < qty)
            {
                if (sn == 0)
                {
                    succs.push_back(virtual_exit_id);
                }
                else
                {
                    for (int s = 0; s < sn; ++s)
                    {
                        int next = fc.succ(node, s);
                        if (next < 0 || next >= qty)
                            continue;
                        succs.push_back(next);
                    }
                }
            }
            for (int succ : succs)
            {
                if (postdom[static_cast<size_t>(succ)] == -1)
                    continue;
                if (new_idom == -1)
                    new_idom = succ;
                else
                    new_idom = dom_intersect(postdom, postorder_index, succ, new_idom);
                if (new_idom == -1)
                    break;
            }
            if (new_idom != -1 && postdom[static_cast<size_t>(node)] != new_idom)
            {
                postdom[static_cast<size_t>(node)] = new_idom;
                changed = true;
            }
        }
    }
    return postdom;
}

bool postdom_dominates(const std::vector<int>& postdom, int from, int to)
{
    if (from < 0 || to < 0)
        return false;
    int virt = static_cast<int>(postdom.size()) - 1;
    int cur = from;
    int safety = 0;
    while (cur != -1 && cur != virt && safety < 4096)
    {
        if (cur == to)
            return true;
        int next = postdom[static_cast<size_t>(cur)];
        if (next == cur)
            break;
        cur = next;
        ++safety;
    }
    return false;
}

std::string build_path_rationale(const qflow_chart_t& fc,
                                 const std::vector<int>& path_blocks,
                                 int check_block,
                                 ea_t check_ea,
                                 ea_t sink_ea)
{
    std::string r;
    r += std::string("Path enters function at block 0 and reaches sink ");
    r += fmt_addr(sink_ea);
    r += std::string(" without traversing block ");
    r += std::to_string(check_block);
    r += std::string(" (which contains the check at ");
    r += fmt_addr(check_ea);
    r += std::string("). ");

    for (size_t i = 0; i + 1 < path_blocks.size(); ++i)
    {
        int from_b = path_blocks[i];
        int to_b   = path_blocks[i + 1];
        bool from_branches_to_check = false;
        int sn = fc.nsucc(from_b);
        for (int s = 0; s < sn; ++s)
        {
            if (fc.succ(from_b, s) == check_block)
            {
                from_branches_to_check = true;
                break;
            }
        }
        if (!from_branches_to_check)
            continue;
        std::string kind = describe_branch_kind(fc, from_b, to_b, check_block);
        r += std::string("Block ");
        r += std::to_string(from_b);
        r += std::string(" routes to block ");
        r += std::to_string(to_b);
        r += std::string(" via ");
        r += kind;
        r += std::string(" instead of the check block. ");
    }

    if (!path_blocks.empty())
    {
        int last_b = path_blocks.back();
        if (fc.is_ret_block(static_cast<size_t>(last_b)))
            r += std::string("Path terminates in a return block. ");
        else if (fc.is_noret_block(static_cast<size_t>(last_b)))
            r += std::string("Path terminates in a noret block (early-return bypass). ");
    }

    return r;
}

std::string md5_token()
{
    uchar md5[16] = {};
    if (!retrieve_input_file_md5(md5))
        return std::string("no_md5");
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

std::string dispatch_cache_key(const std::string& suffix)
{
    return md5_token() + "|sig=" + std::to_string(aida::vuln::sig::SIGNATURE_DATABASE_REVISION) +
           "|chg=" + std::to_string(inf_get_database_change_count()) + "|" + suffix;
}

std::optional<json> dispatch_cache_get(const std::string& key)
{
    netnode n("$ AiDA.dispatch.cache", 0, true);
    if (n == BADNODE)
        return std::nullopt;
    qstring out;
    if (n.hashstr(&out, key.c_str(), 'D') <= 0)
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

void dispatch_cache_put(const std::string& key, const json& data)
{
    netnode n("$ AiDA.dispatch.cache", 0, true);
    if (n == BADNODE)
        return;
    const std::string dump = data.dump();
    n.hashset(key.c_str(), dump.c_str(), dump.size() + 1, 'D');
}

bool function_has_call_near(ea_t target)
{
    func_t* pfn = get_func(target);
    if (pfn == nullptr)
        return false;
    ea_t cur = target;
    int seen = 0;
    while (cur != BADADDR && cur < pfn->end_ea && seen < 48)
    {
        insn_t ins;
        if (decode_insn(&ins, cur) <= 0)
        {
            cur = next_head(cur, pfn->end_ea);
            ++seen;
            continue;
        }
        if (ins.itype == NN_call || ins.itype == NN_callfi || ins.itype == NN_callni)
            return true;
        cur = next_head(cur, pfn->end_ea);
        ++seen;
    }
    return false;
}

json switch_case_to_json(const switch_case_t& c)
{
    json j;
    j["value"] = c.value;
    j["jump_target_ea"] = fmt_addr(c.jump_target_ea);
    j["handler_func_ea"] = fmt_addr(c.handler_func_ea);
    j["handler_name"] = c.handler_name;
    j["has_call"] = c.has_call;
    return j;
}

json switch_dispatch_to_json(const switch_dispatch_t& d)
{
    json j;
    j["jmp_ea"] = fmt_addr(d.jmp_ea);
    j["switch_kind"] = d.switch_kind;
    j["ncases"] = d.ncases;
    j["default_target"] = fmt_addr(d.default_target);
    j["cases"] = json::array();
    for (const auto& c : d.cases)
        j["cases"].push_back(switch_case_to_json(c));
    return j;
}

switch_case_t make_switch_case(std::uint64_t value, ea_t target)
{
    switch_case_t c;
    c.value = value;
    c.jump_target_ea = target;
    func_t* tf = get_func(target);
    if (tf != nullptr)
    {
        c.handler_func_ea = tf->start_ea;
        c.handler_name = demangle_or_name(tf->start_ea);
        c.has_call = function_has_call_near(target);
    }
    return c;
}

void collect_asm_switches_in_func(func_t* pfn, std::vector<switch_dispatch_t>& out)
{
    if (pfn == nullptr)
        return;
    func_item_iterator_t fii(pfn);
    for (bool ok = fii.first(); ok; ok = fii.next_head())
    {
        ea_t ea = fii.current();
        insn_t ins;
        if (decode_insn(&ins, ea) <= 0)
            continue;
        if (ins.itype != NN_jmpni && ins.itype != NN_jmpfi)
            continue;
        switch_info_t si;
        if (get_switch_info(&si, ea) <= 0)
            continue;
        casevec_t cases;
        eavec_t targets;
        if (!calc_switch_cases(&cases, &targets, ea, si))
            continue;
        switch_dispatch_t d;
        d.jmp_ea = ea;
        d.switch_kind = "asm";
        d.ncases = static_cast<int>(si.ncases);
        d.default_target = si.defjump;
        for (size_t i = 0; i < targets.size(); ++i)
        {
            if (i < cases.size())
            {
                const svalvec_t& vals = cases[i];
                if (vals.empty())
                {
                    d.cases.push_back(make_switch_case(0, targets[i]));
                }
                else
                {
                    for (sval_t v : vals)
                        d.cases.push_back(make_switch_case(static_cast<std::uint64_t>(v), targets[i]));
                }
            }
            else
            {
                d.cases.push_back(make_switch_case(static_cast<std::uint64_t>(i), targets[i]));
            }
        }
        if (d.ncases <= 0)
            d.ncases = static_cast<int>(d.cases.size());
        out.push_back(std::move(d));
    }
}

struct hex_switch_visitor_t : public ctree_visitor_t
{
    std::vector<switch_dispatch_t>* out = nullptr;
    explicit hex_switch_visitor_t(std::vector<switch_dispatch_t>* o) : ctree_visitor_t(CV_FAST), out(o) {}
    int idaapi visit_insn(cinsn_t* ins) override
    {
        if (out == nullptr || ins == nullptr || ins->op != cit_switch || ins->cswitch == nullptr)
            return 0;
        switch_dispatch_t d;
        d.jmp_ea = ins->ea;
        d.switch_kind = "hexrays";
        d.default_target = BADADDR;
        for (size_t i = 0; i < ins->cswitch->cases.size(); ++i)
        {
            const ccase_t& cc = ins->cswitch->cases[i];
            ea_t target = cc.ea;
            if (cc.values.empty())
            {
                d.cases.push_back(make_switch_case(0, target));
            }
            else
            {
                for (sval_t v : cc.values)
                    d.cases.push_back(make_switch_case(static_cast<std::uint64_t>(v), target));
            }
        }
        d.ncases = static_cast<int>(d.cases.size());
        out->push_back(std::move(d));
        return 0;
    }
};

void collect_hex_switches_in_func(func_t* pfn, std::vector<switch_dispatch_t>& out)
{
    if (pfn == nullptr || !init_hexrays_plugin() || !ida_utils::is_safely_decompilable(pfn))
        return;
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
        return;
    hex_switch_visitor_t v(&out);
    v.apply_to(&cf->body, nullptr);
}

std::string lower_string_cfg(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (char c : s)
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    return out;
}

bool target_filter_matches(const indirect_call_t& ic, const std::string& filter)
{
    if (filter.empty())
        return true;
    const std::string f = lower_string_cfg(filter);
    for (const auto& t : ic.targets)
    {
        if (lower_string_cfg(t.name).find(f) != std::string::npos)
            return true;
    }
    return false;
}

bool indirect_call_is_vtable(const indirect_call_t& ic)
{
    if (lower_string_cfg(ic.reason).find("vtable") != std::string::npos)
        return true;
    for (const auto& t : ic.targets)
    {
        if (lower_string_cfg(t.source).find("vtable") != std::string::npos)
            return true;
    }
    return false;
}

json vtable_entry_json(ea_t ea)
{
    json e;
    e["ea"] = fmt_addr(ea);
    e["name"] = demangle_or_name(ea);
    return e;
}

void scan_rdata_vtables(int min_entries, int max_entries, json& arr)
{
    const bool is64 = inf_is_64bit();
    const ea_t step = is64 ? 8 : 4;
    for (int i = 0; i < get_segm_qty(); ++i)
    {
        segment_t* seg = getnseg(i);
        if (seg == nullptr || seg->type == SEG_CODE)
            continue;
        if (seg->perm != 0 && (seg->perm & SEGPERM_WRITE) != 0)
            continue;
        for (ea_t ea = seg->start_ea; ea + step <= seg->end_ea;)
        {
            std::vector<ea_t> entries;
            ea_t cur = ea;
            while (cur + step <= seg->end_ea && static_cast<int>(entries.size()) < max_entries)
            {
                ea_t target = is64 ? static_cast<ea_t>(get_qword(cur))
                                   : static_cast<ea_t>(get_dword(cur));
                if (!ea_in_code_segment(target))
                    break;
                func_t* pfn = get_func(target);
                if (pfn == nullptr || pfn->start_ea != target)
                    break;
                entries.push_back(target);
                cur += step;
            }
            if (static_cast<int>(entries.size()) >= min_entries)
            {
                qstring nm;
                std::string name;
                if (get_name(&nm, ea) > 0 && !nm.empty())
                    name = nm.c_str();
                json v;
                v["vtable_ea"] = fmt_addr(ea);
                v["name"] = name;
                v["entry_count"] = entries.size();
                v["confidence"] = name.find("vft") != std::string::npos || name.find("vtable") != std::string::npos ? "likely" : "plausible";
                v["source"] = "rdata_pointer_array";
                v["entries"] = json::array();
                for (ea_t e : entries)
                    v["entries"].push_back(vtable_entry_json(e));
                arr.push_back(std::move(v));
                ea = cur;
            }
            else
            {
                ea += step;
            }
        }
    }
}

struct func_graph_t
{
    std::unordered_map<ea_t, std::vector<ea_t>> callees;
};

func_graph_t build_func_graph()
{
    func_graph_t g;
    const size_t fq = get_func_qty();
    for (size_t i = 0; i < fq; ++i)
    {
        func_t* pfn = getn_func(i);
        if (pfn == nullptr)
            continue;
        std::unordered_set<ea_t> seen;
        func_item_iterator_t fii(pfn);
        for (bool ok = fii.first(); ok; ok = fii.next_head())
        {
            ea_t item = fii.current();
            for (ea_t to = get_first_fcref_from(item); to != BADADDR; to = get_next_fcref_from(item, to))
            {
                func_t* tf = get_func(to);
                if (tf == nullptr || tf->start_ea == pfn->start_ea)
                    continue;
                if (seen.insert(tf->start_ea).second)
                    g.callees[pfn->start_ea].push_back(tf->start_ea);
            }
        }
    }
    return g;
}

const func_graph_t& cached_cfg_call_graph()
{
    static std::mutex mtx;
    static std::optional<func_graph_t> cache;
    static uint32 change_count = 0;
    std::lock_guard<std::mutex> lk(mtx);
    uint32 cur = inf_get_database_change_count();
    if (!cache.has_value() || cur != change_count)
    {
        cache = build_func_graph();
        change_count = cur;
    }
    return *cache;
}

bool cfg_bool_param(const json& params, const char* key, bool fallback)
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

int cfg_int_param(const json& params, const char* key, int fallback)
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
            return value >= (std::numeric_limits<int>::min)() && value <= (std::numeric_limits<int>::max)()
                ? static_cast<int>(value) : fallback;
        }
        if (it->is_number_unsigned())
        {
            const std::uint64_t value = it->get<std::uint64_t>();
            return value <= static_cast<std::uint64_t>((std::numeric_limits<int>::max)())
                ? static_cast<int>(value) : fallback;
        }
        if (it->is_number())
        {
            const double value = it->get<double>();
            return std::isfinite(value) && value >= (std::numeric_limits<int>::min)()
                    && value <= (std::numeric_limits<int>::max)()
                ? static_cast<int>(value) : fallback;
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

std::vector<ea_t> cfg_addr_array_param(const json& params, const char* key)
{
    std::vector<ea_t> out;
    if (!params.is_object())
        return out;
    auto it = params.find(key);
    if (it == params.end() || it->is_null())
        return out;
    auto add_one = [&](const json& v) {
        if (v.is_string())
        {
            auto p = agent_tools::helpers::parse_address(v.get<std::string>());
            if (p.has_value())
                out.push_back(*p);
        }
        else if (v.is_number_unsigned())
        {
            out.push_back(static_cast<ea_t>(v.get<std::uint64_t>()));
        }
        else if (v.is_number_integer())
        {
            out.push_back(static_cast<ea_t>(v.get<std::int64_t>()));
        }
    };
    if (it->is_array())
    {
        for (const auto& v : *it)
            add_one(v);
    }
    else
    {
        add_one(*it);
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

tool_result_t handler_enumerate_switch_dispatch(const json& params)
{
    ea_t fea = BADADDR;
    if (params.is_object() && params.contains("address") && !params["address"].is_null())
    {
        if (params["address"].is_string())
        {
            const std::string s = params["address"].get<std::string>();
            if (!s.empty() && s != "all" && s != "ALL")
            {
                auto p = agent_tools::helpers::parse_address(s);
                if (!p.has_value())
                    return tool_result_t::error(std::string("Invalid address"), "bad_param");
                fea = *p;
            }
        }
    }
    std::vector<switch_dispatch_t> v = enumerate_switch_dispatch(fea);
    json arr = json::array();
    for (const auto& d : v)
        arr.push_back(switch_dispatch_to_json(d));
    json data;
    data["count"] = arr.size();
    data["dispatches"] = std::move(arr);
    sanitize_json_utf8_inplace(data);
    return tool_result_t::ok(std::string("Switch dispatchers: ") + std::to_string(data["count"].get<size_t>()), data);
}

tool_result_t handler_list_dispatchers(const json& params)
{
    json data = list_dispatchers(cfg_int_param(params, "top_n", 25));
    sanitize_json_utf8_inplace(data);
    return tool_result_t::ok(std::string("Dispatchers: ") + std::to_string(data.value("count", static_cast<std::size_t>(0))), data);
}

tool_result_t handler_resolve_indirect_calls_batched(const json& params)
{
    std::vector<ea_t> funcs = cfg_addr_array_param(params, "functions");
    std::string target_filter;
    if (params.is_object())
    {
        auto it = params.find("target_name_filter");
        if (it != params.end() && it->is_string())
            target_filter = it->get<std::string>();
    }
    json data = resolve_indirect_calls_batched(funcs,
        cfg_bool_param(params, "only_unresolved", false),
        cfg_bool_param(params, "only_vtable", false),
        target_filter);
    sanitize_json_utf8_inplace(data);
    return tool_result_t::ok(std::string("Batched indirect calls: ") + std::to_string(data.value("count", static_cast<std::size_t>(0))), data);
}

tool_result_t handler_enumerate_vtables(const json& params)
{
    json data = enumerate_vtables(cfg_int_param(params, "min_entries", 3),
                                  cfg_int_param(params, "max_entries", 256));
    sanitize_json_utf8_inplace(data);
    return tool_result_t::ok(std::string("Vtables: ") + std::to_string(data.value("count", static_cast<std::size_t>(0))), data);
}

tool_result_t handler_reachable_under_constraints(const json& params)
{
    std::vector<ea_t> sources = cfg_addr_array_param(params, "sources");
    std::vector<ea_t> sinks = cfg_addr_array_param(params, "sinks");
    std::vector<ea_t> blocked = cfg_addr_array_param(params, "must_not_cross_funcs");
    if (sources.empty() || sinks.empty())
        return tool_result_t::error(std::string("sources and sinks must be non-empty arrays"), "bad_param");
    for (ea_t& s : sources)
    {
        func_t* pfn = get_func(s);
        if (pfn != nullptr)
            s = pfn->start_ea;
    }
    for (ea_t& s : sinks)
    {
        func_t* pfn = get_func(s);
        if (pfn != nullptr)
            s = pfn->start_ea;
    }
    for (ea_t& s : blocked)
    {
        func_t* pfn = get_func(s);
        if (pfn != nullptr)
            s = pfn->start_ea;
    }
    json data = reachable_under_constraints(sources, sinks, blocked,
                                            cfg_int_param(params, "max_depth", 6));
    sanitize_json_utf8_inplace(data);
    return tool_result_t::ok(std::string("Reachability pairs: ") +
                             std::to_string(data["pairs_reachable"].size()), data);
}

tool_result_t handler_postdominates(const json& params)
{
    std::vector<ea_t> funcs = cfg_addr_array_param(params, "func_ea");
    if (funcs.empty())
        funcs = cfg_addr_array_param(params, "address");
    if (funcs.empty())
        return tool_result_t::error(std::string("func_ea is required"), "bad_param");
    func_t* pfn = get_func(funcs.front());
    if (pfn == nullptr)
        return tool_result_t::error(std::string("func_ea does not lie inside a function"), "no_function_at_addr");
    int from_block = cfg_int_param(params, "from_block", -1);
    int to_block = cfg_int_param(params, "to_block", -1);
    if (from_block < 0 || to_block < 0)
        return tool_result_t::error(std::string("from_block and to_block are required"), "bad_param");
    bool result = block_post_dominates(pfn->start_ea, from_block, to_block);
    json data;
    data["func_ea"] = fmt_addr(pfn->start_ea);
    data["from_block"] = from_block;
    data["to_block"] = to_block;
    data["postdominates"] = result;
    return tool_result_t::ok(result ? std::string("Postdominates") : std::string("Does not postdominate"), data);
}

tool_result_t handler_find_indirect_call_targets(const json& params)
{
    std::string addr_param = params.value("address", std::string());
    bool scan_all = false;
    ea_t target_func_ea = BADADDR;
    if (addr_param.empty() || addr_param == std::string("all") || addr_param == std::string("ALL"))
    {
        scan_all = true;
    }
    else
    {
        auto parsed = agent_tools::helpers::parse_address(addr_param);
        if (!parsed)
            return tool_result_t::error(std::string("Invalid address"));
        target_func_ea = *parsed;
    }

    json calls = json::array();
    size_t total_calls = 0;

    if (scan_all)
    {
        size_t fq = get_func_qty();
        size_t scanned = 0;
        for (size_t i = 0; i < fq && scanned < kMaxAllFuncsScan; ++i)
        {
            func_t* pfn = getn_func(i);
            if (!pfn)
                continue;
            ++scanned;
            auto v = scan_function(pfn->start_ea);
            for (auto& ic : v)
            {
                calls.push_back(call_to_json(ic));
                ++total_calls;
            }
        }
    }
    else
    {
        func_t* pfn = get_func(target_func_ea);
        if (!pfn)
            return tool_result_t::error(std::string("No function at ") + agent_tools::helpers::format_address(target_func_ea));
        auto v = scan_function(pfn->start_ea);
        for (auto& ic : v)
        {
            calls.push_back(call_to_json(ic));
            ++total_calls;
        }
    }

    json result;
    result["count"] = total_calls;
    result["calls"] = std::move(calls);
    sanitize_json_utf8_inplace(result);
    return tool_result_t::ok(std::string("Indirect call targets: ") + std::to_string(total_calls), result);
}

tool_result_t handler_find_check_bypass_paths(const json& params)
{
    std::string ca = params.value("check_address", std::string());
    std::string sa = params.value("sink_address", std::string());
    int max_paths = params.value("max_paths", 8);
    if (max_paths <= 0)
        max_paths = 8;
    if (static_cast<size_t>(max_paths) > kMaxBypassPathsCap)
        max_paths = static_cast<int>(kMaxBypassPathsCap);

    auto pca = agent_tools::helpers::parse_address(ca);
    auto psa = agent_tools::helpers::parse_address(sa);
    if (!pca || !psa)
        return tool_result_t::error(std::string("Invalid check_address or sink_address"));

    ea_t check_ea = *pca;
    ea_t sink_ea  = *psa;

    auto paths = aida::vuln::cfg_engine::find_bypass_paths(check_ea, sink_ea);
    if (static_cast<int>(paths.size()) > max_paths)
        paths.resize(static_cast<size_t>(max_paths));

    json arr = json::array();
    for (const auto& p : paths)
    {
        json pj;
        pj["func_ea"]  = fmt_addr(p.func_ea);
        pj["check_ea"] = fmt_addr(p.check_ea);
        pj["sink_ea"]  = fmt_addr(p.sink_ea);
        json bp = json::array();
        for (ea_t e : p.block_path)
            bp.push_back(fmt_addr(e));
        json eat = json::array();
        for (ea_t e : p.ea_trace)
            eat.push_back(fmt_addr(e));
        pj["block_path"] = std::move(bp);
        pj["ea_trace"]   = std::move(eat);
        pj["rationale"]  = p.rationale;
        arr.push_back(std::move(pj));
    }

    json result;
    result["count"] = arr.size();
    result["paths"] = std::move(arr);
    sanitize_json_utf8_inplace(result);
    return tool_result_t::ok(std::string("Bypass paths: ") + std::to_string(result["count"].get<size_t>()), result);
}

}

std::vector<switch_dispatch_t> enumerate_switch_dispatch(ea_t func_ea)
{
    std::vector<switch_dispatch_t> out;
    if (func_ea == BADADDR)
    {
        const size_t fq = get_func_qty();
        for (size_t i = 0; i < fq && i < kMaxAllFuncsScan; ++i)
        {
            func_t* pfn = getn_func(i);
            if (pfn == nullptr)
                continue;
            collect_asm_switches_in_func(pfn, out);
            collect_hex_switches_in_func(pfn, out);
        }
        return out;
    }
    func_t* pfn = get_func(func_ea);
    if (pfn == nullptr)
        return out;
    collect_asm_switches_in_func(pfn, out);
    collect_hex_switches_in_func(pfn, out);
    return out;
}

nlohmann::json list_dispatchers(int top_n)
{
    if (top_n <= 0)
        top_n = 25;
    if (top_n > 256)
        top_n = 256;
    const std::string key = dispatch_cache_key("list_dispatchers|" + std::to_string(top_n));
    if (auto cached = dispatch_cache_get(key); cached.has_value())
    {
        (*cached)["cached"] = true;
        return *cached;
    }
    std::vector<switch_dispatch_t> all = enumerate_switch_dispatch(BADADDR);
    std::sort(all.begin(), all.end(), [](const switch_dispatch_t& a, const switch_dispatch_t& b) {
        return a.ncases > b.ncases;
    });
    json arr = json::array();
    for (size_t i = 0; i < all.size() && static_cast<int>(i) < top_n; ++i)
    {
        json d = switch_dispatch_to_json(all[i]);
        if (d["cases"].is_array() && d["cases"].size() > 16)
        {
            json sample = json::array();
            for (size_t j = 0; j < 16 && j < d["cases"].size(); ++j)
                sample.push_back(d["cases"][j]);
            d["sample_cases"] = std::move(sample);
            d.erase("cases");
        }
        arr.push_back(std::move(d));
    }
    json data;
    data["dispatchers"] = std::move(arr);
    data["count"] = data["dispatchers"].size();
    data["total_seen"] = all.size();
    data["cache_key"] = key;
    data["cached"] = false;
    dispatch_cache_put(key, data);
    return data;
}

nlohmann::json resolve_indirect_calls_batched(const std::vector<ea_t>& func_eas,
                                              bool only_unresolved,
                                              bool only_vtable,
                                              const std::string& target_name_filter)
{
    std::vector<indirect_call_t> calls;
    if (func_eas.empty())
    {
        calls = find_indirect_calls(BADADDR);
    }
    else
    {
        for (ea_t fea : func_eas)
        {
            std::vector<indirect_call_t> v = find_indirect_calls(fea);
            calls.insert(calls.end(), v.begin(), v.end());
        }
    }
    std::sort(calls.begin(), calls.end(), [](const indirect_call_t& a, const indirect_call_t& b) {
        if (a.call_ea != b.call_ea)
            return a.call_ea < b.call_ea;
        return a.func_ea < b.func_ea;
    });
    calls.erase(std::unique(calls.begin(), calls.end(), [](const indirect_call_t& a, const indirect_call_t& b) {
        return a.call_ea == b.call_ea && a.func_ea == b.func_ea;
    }), calls.end());
    json arr = json::array();
    for (const auto& ic : calls)
    {
        if (only_unresolved && !ic.targets.empty())
            continue;
        if (only_vtable && !indirect_call_is_vtable(ic))
            continue;
        if (!target_filter_matches(ic, target_name_filter))
            continue;
        arr.push_back(call_to_json(ic));
    }
    json data;
    data["count"] = arr.size();
    data["calls"] = std::move(arr);
    return data;
}

nlohmann::json enumerate_vtables(int min_entries, int max_entries)
{
    if (min_entries <= 0)
        min_entries = 3;
    if (max_entries <= 0)
        max_entries = 256;
    if (max_entries > 4096)
        max_entries = 4096;
    json arr = json::array();
    const til_t* ti = get_idati();
    for (const char* name = first_named_type(ti, NTF_TYPE); name != nullptr; name = next_named_type(ti, name, NTF_TYPE))
    {
        tinfo_t tif;
        if (!tif.get_named_type(ti, name))
            continue;
        udt_type_data_t udt;
        if (!tif.get_udt_details(&udt))
            continue;
        if (!udt.is_vftable())
            continue;
        json v;
        v["name"] = name;
        v["vtable_ea"] = fmt_addr(BADADDR);
        v["entry_count"] = udt.size();
        v["confidence"] = "likely";
        v["source"] = "named_type_vftable";
        v["entries"] = json::array();
        arr.push_back(std::move(v));
    }
    scan_rdata_vtables(min_entries, max_entries, arr);
    json data;
    data["count"] = arr.size();
    data["vtables"] = std::move(arr);
    return data;
}

nlohmann::json reachable_under_constraints(const std::vector<ea_t>& sources,
                                           const std::vector<ea_t>& sinks,
                                           const std::vector<ea_t>& must_not_cross_funcs,
                                           int max_depth)
{
    if (max_depth <= 0)
        max_depth = 6;
    if (max_depth > 32)
        max_depth = 32;
    const func_graph_t& g = cached_cfg_call_graph();
    std::unordered_set<ea_t> sink_set(sinks.begin(), sinks.end());
    std::unordered_set<ea_t> block_set(must_not_cross_funcs.begin(), must_not_cross_funcs.end());
    json reachable = json::array();
    json blocked = json::array();
    const int expansion_cap = std::max(16, max_depth * 16);
    struct node_t { ea_t ea; int depth; std::vector<ea_t> path; };
    for (ea_t src : sources)
    {
        func_t* sf = get_func(src);
        if (sf == nullptr)
            continue;
        src = sf->start_ea;
        std::queue<node_t> q;
        std::unordered_set<ea_t> visited;
        q.push({src, 0, {src}});
        visited.insert(src);
        int expansions = 0;
        while (!q.empty() && expansions < expansion_cap)
        {
            node_t cur = std::move(q.front());
            q.pop();
            ++expansions;
            if (sink_set.count(cur.ea) != 0)
            {
                json r;
                r["source_ea"] = fmt_addr(src);
                r["sink_ea"] = fmt_addr(cur.ea);
                r["length"] = cur.path.size();
                r["path"] = json::array();
                for (ea_t p : cur.path)
                    r["path"].push_back(fmt_addr(p));
                reachable.push_back(std::move(r));
                continue;
            }
            if (cur.depth >= max_depth)
                continue;
            auto it = g.callees.find(cur.ea);
            if (it == g.callees.end())
                continue;
            for (ea_t next : it->second)
            {
                if (block_set.count(next) != 0)
                {
                    json b;
                    b["source_ea"] = fmt_addr(src);
                    b["sink_ea"] = fmt_addr(BADADDR);
                    b["blocking_func_ea"] = fmt_addr(next);
                    blocked.push_back(std::move(b));
                    continue;
                }
                if (!visited.insert(next).second)
                    continue;
                std::vector<ea_t> np = cur.path;
                np.push_back(next);
                q.push({next, cur.depth + 1, std::move(np)});
            }
        }
    }
    json data;
    data["pairs_reachable"] = std::move(reachable);
    data["pairs_blocked_by"] = std::move(blocked);
    data["max_depth"] = max_depth;
    data["expansion_cap"] = expansion_cap;
    return data;
}

std::vector<indirect_call_t> find_indirect_calls(ea_t func_ea)
{
    std::vector<indirect_call_t> out;
    if (func_ea == BADADDR)
    {
        size_t fq = get_func_qty();
        size_t scanned = 0;
        for (size_t i = 0; i < fq && scanned < kMaxAllFuncsScan; ++i)
        {
            func_t* pfn = getn_func(i);
            if (!pfn)
                continue;
            ++scanned;
            auto v = scan_function(pfn->start_ea);
            for (auto& ic : v)
                out.push_back(std::move(ic));
        }
        return out;
    }
    func_t* pfn = get_func(func_ea);
    if (!pfn)
        return out;
    return scan_function(pfn->start_ea);
}

std::vector<bypass_path_t> find_bypass_paths(ea_t check_ea, ea_t sink_ea)
{
    std::vector<bypass_path_t> out;
    func_t* pcheck = get_func(check_ea);
    func_t* psink  = get_func(sink_ea);
    if (!pcheck || !psink)
        return out;
    if (pcheck->start_ea != psink->start_ea)
        return out;

    qflow_chart_t fc;
    fc.create("", pcheck, BADADDR, BADADDR, FC_RESERVED);
    if (fc.size() <= 0)
        return out;

    int check_block = find_block_containing(fc, check_ea);
    int sink_block  = find_block_containing(fc, sink_ea);
    int entry_block = 0;
    if (check_block < 0 || sink_block < 0)
        return out;
    if (check_block == sink_block)
        return out;
    if (entry_block == check_block)
        return out;

    std::vector<std::vector<int>> paths;
    enumerate_paths(fc, entry_block, sink_block, check_block, kMaxBypassPathsCap, paths);

    for (const auto& bp : paths)
    {
        bypass_path_t bpp;
        bpp.func_ea  = pcheck->start_ea;
        bpp.check_ea = check_ea;
        bpp.sink_ea  = sink_ea;
        bpp.block_path.reserve(bp.size());
        bpp.ea_trace.reserve(bp.size() * 8);
        for (int b : bp)
        {
            if (b < 0 || b >= fc.size())
                continue;
            bpp.block_path.push_back(fc.blocks[b].start_ea);
            auto eas = collect_block_eas(fc, b);
            for (ea_t e : eas)
            {
                if (bpp.ea_trace.size() >= 4096u)
                    break;
                bpp.ea_trace.push_back(e);
            }
        }
        bpp.rationale = build_path_rationale(fc, bp, check_block, check_ea, sink_ea);
        out.push_back(std::move(bpp));
    }

    return out;
}

bool block_post_dominates(ea_t func_ea, int from_block, int to_block)
{
    func_t* pfn = get_func(func_ea);
    if (!pfn)
        return false;
    qflow_chart_t fc;
    fc.create("", pfn, BADADDR, BADADDR, FC_RESERVED);
    int qty = fc.size();
    if (qty <= 0)
        return false;
    if (from_block < 0 || from_block >= qty)
        return false;
    if (to_block < 0 || to_block >= qty)
        return false;
    if (from_block == to_block)
        return true;

    std::vector<int> postdom = compute_post_dominators(fc);
    if (postdom.size() != static_cast<size_t>(qty + 1))
        return false;
    return postdom_dominates(postdom, from_block, to_block);
}

void register_tier1_cfg_tools()
{
    auto& registry = agent_tools::ToolRegistry::instance();

    registry.register_tool({
        std::string("find_indirect_call_targets"),
        std::string("vuln"),
        std::string("Enumerate every indirect call (callni/callfi/register/memory) in the given function (or 'all' to scan every function) and resolve targets via type-info, IDA xrefs, vtables (Hex-Rays), constant pool scans, microcode SSA def-use, and MSVC RTTI. Returns per-call resolved-target arrays plus the resolution method that succeeded."),
        {
            { std::string("address"), std::string("string"), std::string("Function ea (0x...) or 'all' to scan every function"), true }
        },
        handler_find_indirect_call_targets,
        true
    });

    registry.register_tool({
        std::string("find_check_bypass_paths"),
        std::string("vuln"),
        std::string("Enumerate paths through the function CFG that route AROUND a specific check (its block excluded from BFS/DFS) and still reach a sink. Both check_address and sink_address must be inside the same function. Returns block paths, ea traces, and a rationale describing how each path bypasses the check (true/false branch of a conditional, unconditional jmp, post-call edge, early-return)."),
        {
            { std::string("check_address"), std::string("string"), std::string("Address of the check / validator instruction"), true },
            { std::string("sink_address"),  std::string("string"), std::string("Address of the sink the attacker wants to reach"), true },
            { std::string("max_paths"),     std::string("number"), std::string("Max paths to return (default 8, max 64)"),         false }
        },
        handler_find_check_bypass_paths,
        true
    });

    registry.register_tool({
        std::string("enumerate_switch_dispatch"),
        std::string("vuln"),
        std::string("Enumerate switch dispatchers using disassembly switch_info_t/calc_switch_cases and Hex-Rays cit_switch cases. Address may be a function address or 'all'."),
        {
            { std::string("address"), std::string("string"), std::string("Function address or 'all' (default all)."), false },
        },
        handler_enumerate_switch_dispatch,
        true
    });

    registry.register_tool({
        std::string("list_dispatchers"),
        std::string("vuln"),
        std::string("Return the top switch dispatchers by case count from the dispatch cache, rebuilding it from switch_info_t and Hex-Rays switch data when stale."),
        {
            { std::string("top_n"), std::string("number"), std::string("Maximum dispatchers to return (default 25, max 256)."), false },
        },
        handler_list_dispatchers,
        true
    });

    registry.register_tool({
        std::string("resolve_indirect_calls_batched"),
        std::string("vuln"),
        std::string("Batch version of indirect-call target resolution over multiple functions with server-side unresolved, vtable, and target-name filters."),
        {
            { std::string("functions"), std::string("array"), std::string("Function addresses. Empty scans every function up to the configured cap."), false },
            { std::string("only_unresolved"), std::string("boolean"), std::string("Only return indirect calls with no resolved targets."), false },
            { std::string("only_vtable"), std::string("boolean"), std::string("Only return vtable-derived indirect calls."), false },
            { std::string("target_name_filter"), std::string("string"), std::string("Case-insensitive substring filter over resolved target names."), false },
        },
        handler_resolve_indirect_calls_batched,
        true
    });

    registry.register_tool({
        std::string("enumerate_vtables"),
        std::string("vuln"),
        std::string("Enumerate vtables from named vftable types and read-only pointer arrays that resolve to function starts, returning confidence per table."),
        {
            { std::string("min_entries"), std::string("number"), std::string("Minimum pointer-array entries (default 3)."), false },
            { std::string("max_entries"), std::string("number"), std::string("Maximum entries per table (default 256)."), false },
        },
        handler_enumerate_vtables,
        true
    });

    registry.register_tool({
        std::string("reachable_under_constraints"),
        std::string("vuln"),
        std::string("Inter-procedural callgraph BFS from source functions to sink functions while pruning must_not_cross_funcs, capped at max_depth * 16 expansions per source."),
        {
            { std::string("sources"), std::string("array"), std::string("Source function addresses."), true },
            { std::string("sinks"), std::string("array"), std::string("Sink function addresses."), true },
            { std::string("must_not_cross_funcs"), std::string("array"), std::string("Functions that block reachability."), false },
            { std::string("max_depth"), std::string("number"), std::string("Maximum call depth (default 6, max 32)."), false },
        },
        handler_reachable_under_constraints,
        true
    });

    registry.register_tool({
        std::string("postdominates"),
        std::string("vuln"),
        std::string("Return whether one qflow_chart_t basic block postdominates another in a function."),
        {
            { std::string("func_ea"), std::string("string"), std::string("Function address."), true },
            { std::string("from_block"), std::string("number"), std::string("Block being tested."), true },
            { std::string("to_block"), std::string("number"), std::string("Candidate postdominator block."), true },
        },
        handler_postdominates,
        true
    });
}

}
}
}
