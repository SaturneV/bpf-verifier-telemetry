/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM bpf_verifier

#if !defined(_TRACE_BPF_VERIFIER_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_BPF_VERIFIER_H

#include <linux/tracepoint.h>

/*
 * Tracepoint for BPF verifier aggregated per-program statistics.
 * Emitted once per program at the end of verification.
 *
 * State-level mismatch categories are packed two-per-u64 (high/low 32 bits):
 *   mismatch_pair1: cbdepth(low32)   | curframe(high32)
 *   mismatch_pair2: spec(low32)      | sleepable(high32)
 *   mismatch_pair3: refsafe(low32)   | callsite(high32)
 *   mismatch_pair4: registers(low32) | stack(high32)
 *
 * Register-field mismatch sub-categories (all 8) packed two-per-u64:
 *   reg_field_pair1: type(low32)      | range(high32)
 *   reg_field_pair2: var_off(low32)   | id(high32)
 *   reg_field_pair3: ref_obj_id(low32)| offset(high32)
 *   reg_field_pair4: frameno(low32)   | other(high32)
 */
TRACE_EVENT(bpf_verifier_prog_stats,

	TP_PROTO(const char *prog_name, u32 prog_len,
		 u32 total_states_compared, u32 total_states_matched, u32 total_states_mismatched,
		 u64 mismatch_pair1, u64 mismatch_pair2, u64 mismatch_pair3, u64 mismatch_pair4,
		 u64 reg_field_pair1, u64 reg_field_pair2,
		 u64 reg_field_pair3, u64 reg_field_pair4),

	TP_ARGS(prog_name, prog_len,
		total_states_compared, total_states_matched, total_states_mismatched,
		mismatch_pair1, mismatch_pair2, mismatch_pair3, mismatch_pair4,
		reg_field_pair1, reg_field_pair2,
		reg_field_pair3, reg_field_pair4),

	TP_STRUCT__entry(
		__string(prog_name, prog_name)
		__field(u32, prog_len)
		__field(u32, total_states_compared)
		__field(u32, total_states_matched)
		__field(u32, total_states_mismatched)
		__field(u32, mismatch_callback_depth)
		__field(u32, mismatch_curframe)
		__field(u32, mismatch_speculative)
		__field(u32, mismatch_sleepable)
		__field(u32, mismatch_refsafe)
		__field(u32, mismatch_callsite)
		__field(u32, mismatch_registers)
		__field(u32, mismatch_stack)
		__field(u32, reg_mismatch_type)
		__field(u32, reg_mismatch_range)
		__field(u32, reg_mismatch_var_off)
		__field(u32, reg_mismatch_id)
		__field(u32, reg_mismatch_ref_obj_id)
		__field(u32, reg_mismatch_offset)
		__field(u32, reg_mismatch_frameno)
		__field(u32, reg_mismatch_other)
	),

	TP_fast_assign(
		__assign_str(prog_name);
		__entry->prog_len                = prog_len;
		__entry->total_states_compared   = total_states_compared;
		__entry->total_states_matched    = total_states_matched;
		__entry->total_states_mismatched = total_states_mismatched;
		/* Unpack state-level mismatch pairs */
		__entry->mismatch_callback_depth = (u32)(mismatch_pair1 & 0xFFFFFFFFU);
		__entry->mismatch_curframe       = (u32)(mismatch_pair1 >> 32);
		__entry->mismatch_speculative    = (u32)(mismatch_pair2 & 0xFFFFFFFFU);
		__entry->mismatch_sleepable      = (u32)(mismatch_pair2 >> 32);
		__entry->mismatch_refsafe        = (u32)(mismatch_pair3 & 0xFFFFFFFFU);
		__entry->mismatch_callsite       = (u32)(mismatch_pair3 >> 32);
		__entry->mismatch_registers      = (u32)(mismatch_pair4 & 0xFFFFFFFFU);
		__entry->mismatch_stack          = (u32)(mismatch_pair4 >> 32);
		/* Unpack all 8 register-field mismatch sub-categories */
		__entry->reg_mismatch_type       = (u32)(reg_field_pair1 & 0xFFFFFFFFU);
		__entry->reg_mismatch_range      = (u32)(reg_field_pair1 >> 32);
		__entry->reg_mismatch_var_off    = (u32)(reg_field_pair2 & 0xFFFFFFFFU);
		__entry->reg_mismatch_id         = (u32)(reg_field_pair2 >> 32);
		__entry->reg_mismatch_ref_obj_id = (u32)(reg_field_pair3 & 0xFFFFFFFFU);
		__entry->reg_mismatch_offset     = (u32)(reg_field_pair3 >> 32);
		__entry->reg_mismatch_frameno    = (u32)(reg_field_pair4 & 0xFFFFFFFFU);
		__entry->reg_mismatch_other      = (u32)(reg_field_pair4 >> 32);
	),

	TP_printk("prog_name=%s prog_len=%u total_compared=%u matched=%u mismatched=%u "
		  "mismatch_breakdown(cbdepth=%u curframe=%u spec=%u sleepable=%u refsafe=%u callsite=%u regs=%u stack=%u) "
		  "reg_field_mismatch(type=%u range=%u var_off=%u id=%u ref_obj_id=%u offset=%u frameno=%u other=%u)",
		  __get_str(prog_name), __entry->prog_len,
		  __entry->total_states_compared, __entry->total_states_matched,
		  __entry->total_states_mismatched,
		  __entry->mismatch_callback_depth, __entry->mismatch_curframe,
		  __entry->mismatch_speculative, __entry->mismatch_sleepable,
		  __entry->mismatch_refsafe, __entry->mismatch_callsite,
		  __entry->mismatch_registers, __entry->mismatch_stack,
		  __entry->reg_mismatch_type, __entry->reg_mismatch_range,
		  __entry->reg_mismatch_var_off, __entry->reg_mismatch_id,
		  __entry->reg_mismatch_ref_obj_id, __entry->reg_mismatch_offset,
		  __entry->reg_mismatch_frameno, __entry->reg_mismatch_other)
);

/*
 * Tracepoint for BPF verifier aggregated per-instruction statistics.
 * Emitted for each instruction that has at least one state comparison.
 *
 * Same packing scheme as bpf_verifier_prog_stats (see above).
 */
TRACE_EVENT(bpf_verifier_insn_stats,

	TP_PROTO(const char *prog_name, u32 insn_idx,
		 u32 states_compared, u32 states_matched, u32 states_mismatched,
		 u64 mismatch_pair1, u64 mismatch_pair2, u64 mismatch_pair3, u64 mismatch_pair4,
		 u64 reg_field_pair1, u64 reg_field_pair2,
		 u64 reg_field_pair3, u64 reg_field_pair4),

	TP_ARGS(prog_name, insn_idx,
		states_compared, states_matched, states_mismatched,
		mismatch_pair1, mismatch_pair2, mismatch_pair3, mismatch_pair4,
		reg_field_pair1, reg_field_pair2,
		reg_field_pair3, reg_field_pair4),

	TP_STRUCT__entry(
		__string(prog_name, prog_name)
		__field(u32, insn_idx)
		__field(u32, states_compared)
		__field(u32, states_matched)
		__field(u32, states_mismatched)
		__field(u32, mismatch_callback_depth)
		__field(u32, mismatch_curframe)
		__field(u32, mismatch_speculative)
		__field(u32, mismatch_sleepable)
		__field(u32, mismatch_refsafe)
		__field(u32, mismatch_callsite)
		__field(u32, mismatch_registers)
		__field(u32, mismatch_stack)
		__field(u32, reg_mismatch_type)
		__field(u32, reg_mismatch_range)
		__field(u32, reg_mismatch_var_off)
		__field(u32, reg_mismatch_id)
		__field(u32, reg_mismatch_ref_obj_id)
		__field(u32, reg_mismatch_offset)
		__field(u32, reg_mismatch_frameno)
		__field(u32, reg_mismatch_other)
	),

	TP_fast_assign(
		__assign_str(prog_name);
		__entry->insn_idx           = insn_idx;
		__entry->states_compared    = states_compared;
		__entry->states_matched     = states_matched;
		__entry->states_mismatched  = states_mismatched;
		/* Unpack state-level mismatch pairs */
		__entry->mismatch_callback_depth = (u32)(mismatch_pair1 & 0xFFFFFFFFU);
		__entry->mismatch_curframe       = (u32)(mismatch_pair1 >> 32);
		__entry->mismatch_speculative    = (u32)(mismatch_pair2 & 0xFFFFFFFFU);
		__entry->mismatch_sleepable      = (u32)(mismatch_pair2 >> 32);
		__entry->mismatch_refsafe        = (u32)(mismatch_pair3 & 0xFFFFFFFFU);
		__entry->mismatch_callsite       = (u32)(mismatch_pair3 >> 32);
		__entry->mismatch_registers      = (u32)(mismatch_pair4 & 0xFFFFFFFFU);
		__entry->mismatch_stack          = (u32)(mismatch_pair4 >> 32);
		/* Unpack all 8 register-field mismatch sub-categories */
		__entry->reg_mismatch_type       = (u32)(reg_field_pair1 & 0xFFFFFFFFU);
		__entry->reg_mismatch_range      = (u32)(reg_field_pair1 >> 32);
		__entry->reg_mismatch_var_off    = (u32)(reg_field_pair2 & 0xFFFFFFFFU);
		__entry->reg_mismatch_id         = (u32)(reg_field_pair2 >> 32);
		__entry->reg_mismatch_ref_obj_id = (u32)(reg_field_pair3 & 0xFFFFFFFFU);
		__entry->reg_mismatch_offset     = (u32)(reg_field_pair3 >> 32);
		__entry->reg_mismatch_frameno    = (u32)(reg_field_pair4 & 0xFFFFFFFFU);
		__entry->reg_mismatch_other      = (u32)(reg_field_pair4 >> 32);
	),

	TP_printk("prog_name=%s insn_idx=%u compared=%u matched=%u mismatched=%u "
		  "mismatch_breakdown(cbdepth=%u curframe=%u spec=%u sleepable=%u refsafe=%u callsite=%u regs=%u stack=%u) "
		  "reg_field_mismatch(type=%u range=%u var_off=%u id=%u ref_obj_id=%u offset=%u frameno=%u other=%u)",
		  __get_str(prog_name), __entry->insn_idx,
		  __entry->states_compared, __entry->states_matched, __entry->states_mismatched,
		  __entry->mismatch_callback_depth, __entry->mismatch_curframe,
		  __entry->mismatch_speculative, __entry->mismatch_sleepable,
		  __entry->mismatch_refsafe, __entry->mismatch_callsite,
		  __entry->mismatch_registers, __entry->mismatch_stack,
		  __entry->reg_mismatch_type, __entry->reg_mismatch_range,
		  __entry->reg_mismatch_var_off, __entry->reg_mismatch_id,
		  __entry->reg_mismatch_ref_obj_id, __entry->reg_mismatch_offset,
		  __entry->reg_mismatch_frameno, __entry->reg_mismatch_other)
);

#endif

/* This part must be outside protection */
#include <trace/define_trace.h>
