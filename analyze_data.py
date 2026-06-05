#!/usr/bin/env python3
"""
analyze_data.py — BPF Verifier Mismatch Analysis
====================================================
1.  Verifier State Mismatch Categories Distribution
2a. Register Field Properties (Aggregate)
2b. Register Field Properties (Per-program breakdown)
3.  Bottleneck Concentration within Programs
4a. Mismatch count distribution by class
4b. Mismatch category share per class

Usage:
    python3 analyze_data.py [--results DIR] [--out DIR] [--fmt png|pdf|svg]

Requirements:
    pip install pandas matplotlib seaborn numpy scipy
"""

import argparse
import json
import sys
from pathlib import Path
from collections import defaultdict

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

# ─── Field definitions ────────────────────────────────────────────────────────

STATE_CATS = ["registers","stack","callsite","refsafe",
              "curframe","cbdepth","speculative","sleepable"]
REG_CATS   = ["range","type","var_off","id",
              "ref_obj_id","offset","frameno","other"]

STATE_LABELS = {
    "registers":"Register state","stack":"Stack state",
    "callsite":"Call site","refsafe":"Ref safety",
    "curframe":"Current frame","cbdepth":"Call depth",
    "speculative":"Speculative","sleepable":"Sleepable",
}
REG_LABELS = {
    "range":"Value range","type":"Type mismatch",
    "var_off":"Var offset","id":"Register ID",
    "ref_obj_id":"Ref obj ID","offset":"Ptr offset",
    "frameno":"Frame number","other":"Other",
}
GROUP_LABELS = {
    "loop":"Loop-heavy","subprog":"Subprog-heavy",
    "map":"Map/Ref-heavy","network":"Networking",
    "tracing":"Tracing","other":"Other",
}

# ─── Data loading ─────────────────────────────────────────────────────────────

def load_json_files(results_dir):
    records = []
    for group_dir in sorted(results_dir.iterdir()):
        if not group_dir.is_dir():
            continue
        group = group_dir.name
        for jf in sorted(group_dir.glob("*.json")):
            try:
                data = json.loads(jf.read_text())
                data["group"] = group
                records.append(data)
            except Exception:
                continue
    return records

def build_dataframes(records):
    prog_rows, insn_rows = [], []
    for r in records:
        total = r.get("total_mismatches_displayed", 0)
        if total == 0:
            continue
        prog_name = r.get("prog_name", "unknown")
        group     = r.get("group", "other")
        agg = defaultdict(int)
        for insn in r.get("instructions", []):
            bd = insn.get("mismatch_breakdown", {})
            rf = insn.get("reg_field_mismatch", {})
            for c in STATE_CATS:
                agg[c] += bd.get(c, 0)
            for c in REG_CATS:
                agg[f"reg_{c}"] += rf.get(c, 0)
            agg["total_compared"] += insn.get("states_compared", 0)
            m = insn.get("states_mismatched", 0)
            if m > 0:
                insn_rows.append({
                    "prog_name": prog_name, "group": group,
                    "insn_idx": insn.get("insn_idx", 0),
                    "states_mismatched": m,
                    "states_compared":   insn.get("states_compared", 0),
                    **{c: bd.get(c, 0) for c in STATE_CATS},
                })
        prog_rows.append({
            "prog_name": prog_name, "group": group,
            "total_mismatches": total,
            **{c: agg[c] for c in STATE_CATS},
            **{f"reg_{c}": agg[f"reg_{c}"] for c in REG_CATS},
            "total_compared": agg["total_compared"],
        })
    prog_df = pd.DataFrame(prog_rows)
    insn_df = pd.DataFrame(insn_rows) if insn_rows else pd.DataFrame()
    return prog_df, insn_df

def savefig(fig, out_dir, name, fmt):
    path = out_dir / f"{name}.{fmt}"
    fig.savefig(path, bbox_inches="tight", dpi=180)
    print(f"  Saved → {path}")
    plt.close(fig)

# ─────────────────────────────────────────────────────────────────────────────
# Fig 1 — Verifier State Mismatch Categories Distribution
# ─────────────────────────────────────────────────────────────────────────────

def fig1(prog_df, out_dir, fmt):
    print("  Fig1: Verifier State Mismatch Category Distribution...")
    cats   = [c for c in STATE_CATS]
    labels = [STATE_LABELS[c] for c in cats]
    totals = [int(prog_df[c].sum()) for c in cats]
    grand  = sum(totals)

    dom_counts = defaultdict(int)
    for _, row in prog_df.iterrows():
        dom = max(cats, key=lambda c: row[c])
        if row[dom] > 0:
            dom_counts[dom] += 1
    dom_pcts = [dom_counts[c] / len(prog_df) * 100 for c in cats]

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(8, 10))
    #fig.suptitle("Verifier State Mismatch Category Distribution",
    #             fontsize=13, fontweight="bold")

    bars1 = ax1.bar(labels, totals)
    for bar, t in zip(bars1, totals):
        pct = t / grand * 100
        ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height()/2,
                 f"{pct:.1f}%", ha="center", va="center",
                 fontsize=8, fontweight="bold", color="white")
        ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height()*1.01,
                 f"{t:,}", ha="center", va="bottom", fontsize=8)
    ax1.set_title("Total mismatch count per category")
    ax1.set_ylabel("Total mismatches")
    ax1.set_xticklabels(labels, rotation=30, ha="right")
    ax1.yaxis.grid(True, alpha=0.3)
    ax1.set_axisbelow(True)

    bars2 = ax2.bar(labels, dom_pcts)
    for bar, p in zip(bars2, dom_pcts):
        if p > 0:
            ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                     f"{p:.1f}%", ha="center", va="bottom", fontsize=8)
    ax2.set_title("% of programs where category is dominant")
    ax2.set_ylabel("% of programs")
    ax2.set_ylim(0, 105)
    ax2.set_xticklabels(labels, rotation=30, ha="right")
    ax2.yaxis.grid(True, alpha=0.3)
    ax2.set_axisbelow(True)

    fig.tight_layout()
    savefig(fig, out_dir, "fig1_category_distribution", fmt)

    dom_cat  = cats[totals.index(max(totals))]
    dom_prog = max(cats, key=lambda c: dom_counts[c])
    print(f"    → Dominant by volume  : {STATE_LABELS[dom_cat]} ({max(totals)/grand*100:.1f}%)")
    print(f"    → Dominant by programs: {STATE_LABELS[dom_prog]} ({dom_counts[dom_prog]}/{len(prog_df)} progs)")

# ─────────────────────────────────────────────────────────────────────────────
# Fig 2a — Register Field Aggregate Counts
# ─────────────────────────────────────────────────────────────────────────────

def fig2a(prog_df, out_dir, fmt):
    print("  Fig2a: Register Field Aggregate Counts...")
    reg_df = prog_df[prog_df["registers"] > 0].copy()
    if reg_df.empty:
        print("    [SKIP] no programs with register mismatches")
        return

    reg_cols  = [f"reg_{c}" for c in REG_CATS]
    present   = [c for c in reg_cols if reg_df[c].sum() > 0]
    ptotals   = [int(reg_df[c].sum()) for c in present]
    grand     = sum(ptotals)
    order     = sorted(range(len(present)), key=lambda i: ptotals[i], reverse=True)
    present_s = [present[i] for i in order]
    plabels_s = [REG_LABELS[present_s[i][4:]] for i in range(len(present_s))]
    ptotals_s = [ptotals[i] for i in order]

    fig, ax = plt.subplots(figsize=(8, 5))
    #fig.suptitle("Register Field Properties Causing Mismatches",
    #             fontsize=13, fontweight="bold")

    bars = ax.bar(plabels_s, ptotals_s)
    for bar, t in zip(bars, ptotals_s):
        pct = t / grand * 100 if grand > 0 else 0
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height()/2,
                f"{pct:.1f}%", ha="center", va="center",
                fontsize=8, fontweight="bold", color="white")
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height()*1.01,
                f"{t:,}", ha="center", va="bottom", fontsize=8)
    ax.set_title("Aggregate register field mismatch counts")
    ax.set_ylabel("Mismatch count")
    ax.set_xticklabels(plabels_s, rotation=30, ha="right")
    ax.yaxis.grid(True, alpha=0.3)
    ax.set_axisbelow(True)

    fig.tight_layout()
    savefig(fig, out_dir, "fig2a_register_fields_aggregate", fmt)
    print(f"    → Dominant: {REG_LABELS[present_s[0][4:]]} ({ptotals_s[0]/grand*100:.1f}%)")

# ─────────────────────────────────────────────────────────────────────────────
# Fig 2b — Register Field Breakdown per Program (Top 20)
# ─────────────────────────────────────────────────────────────────────────────

def fig2b(prog_df, out_dir, fmt):
    print("  Fig2b: Register Field Breakdown — Top 20 Programs...")
    reg_df = prog_df[prog_df["registers"] > 0].copy()
    if reg_df.empty:
        print("    [SKIP] no programs with register mismatches")
        return

    reg_cols  = [f"reg_{c}" for c in REG_CATS]
    present   = [c for c in reg_cols if reg_df[c].sum() > 0]
    ptotals   = [int(reg_df[c].sum()) for c in present]
    order     = sorted(range(len(present)), key=lambda i: ptotals[i], reverse=True)
    present_s = [present[i] for i in order]

    top20  = reg_df.nlargest(20, "registers")
    x      = np.arange(len(top20))
    bottom = np.zeros(len(top20))

    fig, ax = plt.subplots(figsize=(8, 5))
    #fig.suptitle("Register Field Properties Causing Mismatches",
    #             fontsize=13, fontweight="bold")

    for col in present_s:
        vals = top20[col].values
        ax.bar(x, vals, bottom=bottom, label=REG_LABELS[col[4:]], width=0.7)
        bottom += vals
    ax.set_xticks(x)
    ax.set_xticklabels([p[:12] for p in top20["prog_name"].values],
                        rotation=40, ha="right", fontsize=7)
    ax.set_title("Register field breakdown — top 20 programs by register mismatches")
    ax.set_ylabel("Register field mismatch count")
    ax.legend(fontsize=7, loc="upper right")
    ax.yaxis.grid(True, alpha=0.3)
    ax.set_axisbelow(True)

    fig.tight_layout()
    savefig(fig, out_dir, "fig2b_register_fields_per_program", fmt)

# ─────────────────────────────────────────────────────────────────────────────
# Fig 3 — Bottleneck Concentration within Programs
# ─────────────────────────────────────────────────────────────────────────────

def fig3(records, out_dir, fmt):
    print("  Fig3: Bottleneck Concentration within Programs...")

    prog_insn = {}
    for r in records:
        if r.get("total_mismatches_displayed", 0) == 0:
            continue
        key  = (r.get("prog_name", "?"), r.get("group", "other"))
        vals = [i["states_mismatched"]
                for i in r.get("instructions", [])
                if i.get("states_mismatched", 0) > 0]
        if len(vals) >= 2:
            prog_insn[key] = vals

    if not prog_insn:
        print("    [SKIP] not enough per-instruction data")
        return

    X_GRID     = np.linspace(0, 100, 200)
    cdf_matrix = []

    for vals in prog_insn.values():
        arr   = np.sort(vals)[::-1]
        total = arr.sum()
        cum   = np.cumsum(arr) / total * 100
        x     = np.arange(1, len(cum)+1) / len(cum) * 100
        cdf_matrix.append(np.interp(X_GRID, x, cum))

    cdf_matrix = np.array(cdf_matrix)
    med_cdf    = np.median(cdf_matrix, axis=0)
    p10_cdf    = np.percentile(cdf_matrix, 10, axis=0)
    p90_cdf    = np.percentile(cdf_matrix, 90, axis=0)

    fig, ax = plt.subplots(figsize=(8, 6))
    #fig.suptitle("Bottleneck Concentration within Programs",
    #             fontsize=13, fontweight="bold")

    ax.fill_between(X_GRID, p10_cdf, p90_cdf, alpha=0.25, label="P10–P90 band")
    ax.plot(X_GRID, med_cdf, linewidth=2, label="Median across programs")
    ax.set_xlabel("Cumulative % of instructions (sorted by mismatch count DESC)")
    ax.set_ylabel("Cumulative % of program's total mismatches")
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.legend(fontsize=9)
    ax.set_title("CDF of mismatch concentration (per-program, aggregated)")
    ax.yaxis.grid(True, alpha=0.3)
    ax.set_axisbelow(True)

    fig.tight_layout()
    savefig(fig, out_dir, "fig3_concentration", fmt)
    print(f"    → n = {len(cdf_matrix)} programs")

# ─────────────────────────────────────────────────────────────────────────────
# Fig 4a — Mismatch Count Distribution by Program Class
# ─────────────────────────────────────────────────────────────────────────────

def fig4a(prog_df, out_dir, fmt):
    print("  Fig4a: Mismatch Count Distribution by Program Class...")
    if prog_df.empty:
        print("    [SKIP]")
        return

    groups     = [g for g in ["loop","map","network","other"]
                  if g in prog_df["group"].values] # subprog/tracing categories excluded (not statistically representative)
    group_data = [prog_df[prog_df["group"]==g]["total_mismatches"].values
                  for g in groups]

    fig, ax = plt.subplots(figsize=(8, 5))
    #fig.suptitle("Verifier Bottleneck Characteristics by Program Class",
    #             fontsize=13, fontweight="bold")

    ax.boxplot(group_data, patch_artist=True)
    ax.set_xticks(range(1, len(groups)+1))
    ax.set_xticklabels([GROUP_LABELS.get(g,g) for g in groups],
                        rotation=20, ha="right", fontsize=9)
    ax.set_ylabel("Total mismatches per program")
    ax.set_title("Mismatch count distribution by class")
    ax.set_yscale("log")
    ax.yaxis.grid(True, alpha=0.3)
    ax.set_axisbelow(True)
    for i, (g, gd) in enumerate(zip(groups, group_data)):
        if len(gd) > 0:
            ax.text(i+1, np.median(gd)*1.15, f"n={len(gd)}",
                    ha="center", va="bottom", fontsize=7)

    fig.tight_layout()
    savefig(fig, out_dir, "fig4a_by_class_boxplot", fmt)

# ─────────────────────────────────────────────────────────────────────────────
# Fig 4b — Mismatch Category Share per Program Class
# ─────────────────────────────────────────────────────────────────────────────

def fig4b(prog_df, out_dir, fmt):
    print("  Fig4b: Mismatch Category Share per Program Class...")
    if prog_df.empty:
        print("    [SKIP]")
        return

    cats = STATE_CATS
    groups = [g for g in ["loop", "map", "network", "other"]
              if g in prog_df["group"].values] # subprog/tracing categories excluded (not statistically representative)

    matrix, row_labels = [], []
    for g in groups:
        gdf     = prog_df[prog_df["group"]==g]
        total_g = gdf["total_mismatches"].sum()
        row_labels.append(GROUP_LABELS.get(g, g))
        matrix.append([gdf[c].sum()/total_g*100 if total_g > 0 else 0
                        for c in cats])
    matrix_df = pd.DataFrame(matrix, index=row_labels,
                              columns=[STATE_LABELS[c] for c in cats])

    # Wider figure to accommodate all 8 columns
    fig, ax = plt.subplots(figsize=(8, 4))

    sns.heatmap(matrix_df, ax=ax, cmap="YlOrRd",
                annot=True, fmt=".0f", annot_kws={"size": 8},
                linewidths=0.4,
                cbar_kws={"label": "% of group's mismatches", "shrink": 0.8})
    ax.set_title("Mismatch category share per class (%)")
    ax.tick_params(axis="x", rotation=30, labelsize=8)
    ax.tick_params(axis="y", rotation=0,  labelsize=9)

    fig.tight_layout()
    savefig(fig, out_dir, "fig4b_by_class_heatmap", fmt)

    for g in groups:
        gdf = prog_df[prog_df["group"]==g]
        if gdf.empty:
            continue
        total_g = gdf["total_mismatches"].sum()
        dom_c   = max(cats, key=lambda c: gdf[c].sum())
        print(f"    → {GROUP_LABELS.get(g,g):<18} dominant: "
              f"{STATE_LABELS[dom_c]} ({gdf[dom_c].sum()/total_g*100:.1f}%),"
              f"  n={len(gdf)}")

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", default="./results/data")
    parser.add_argument("--out",     default="./results/figures")
    parser.add_argument("--fmt",     default="png", choices=["png","pdf","svg"])
    args = parser.parse_args()

    results_dir = Path(args.results)
    out_dir     = Path(args.out)
    if not results_dir.exists():
        print(f"ERROR: {results_dir} not found", file=sys.stderr)
        sys.exit(1)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Loading results from {results_dir} …")
    records = load_json_files(results_dir)
    print(f"  {len(records)} JSON files loaded.")

    prog_df, insn_df = build_dataframes(records)
    print(f"  Programs with mismatches    : {len(prog_df)}")
    print(f"  Instructions with mismatches: {len(insn_df)}")
    print(f"  Total mismatches            : {prog_df['total_mismatches'].sum():,}")
    print(f"  Groups                      : {sorted(prog_df['group'].unique())}\n")

    print("Generating figures…")
    fig1(prog_df, out_dir, args.fmt)
    fig2a(prog_df, out_dir, args.fmt)
    fig2b(prog_df, out_dir, args.fmt)
    fig3(records, out_dir, args.fmt)
    fig4a(prog_df, out_dir, args.fmt)
    fig4b(prog_df, out_dir, args.fmt)

    print(f"\nDone. Figures in {out_dir}/")

if __name__ == "__main__":
    main()