#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# bpf_batch_analyzer.sh — Load BPF .bpf.o files, collect verifier mismatch data
#
# Usage:
#   sudo ./bpf_batch_analyzer.sh [--objs DIR] [--reporter PATH] [--out DIR]
#
# Options:
#   --objs     DIR    Directory containing .bpf.o files (default: ./bpf_objs)
#   --reporter PATH   Path to bpf_verifier_source_report (default: ./bpf-mismatch-report)
#   --out      DIR    Output root directory (default: ./bpf_analyser_out)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

OBJS_DIR="./bpf_objs"
REPORTER="./bpf-mismatch-report"
OUT_DIR="./bpf_analyser_out"

TRACE_FILE="/sys/kernel/tracing/trace"
TRACE_ON="/sys/kernel/tracing/tracing_on"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --objs)     OBJS_DIR="$2";   shift 2 ;;
        --reporter) REPORTER="$2";   shift 2 ;;
        --out)      OUT_DIR="$2";    shift 2 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

RESULTS_DIR="${OUT_DIR}/results"

# ── Sanity checks ─────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Must run as root (sudo)." >&2; exit 1
fi
if [[ ! -d "$OBJS_DIR" ]]; then
    echo "ERROR: Objects directory not found: $OBJS_DIR" >&2; exit 1
fi
if [[ ! -x "$REPORTER" ]]; then
    echo "ERROR: Reporter binary not found: $REPORTER" >&2
    echo "       Compile with: gcc -O2 -o bpf_verifier_source_report bpf_verifier_source_report.c -ldw -lelf" >&2
    exit 1
fi

mkdir -p "$OUT_DIR" "$RESULTS_DIR"

echo "════════════════════════════════════════════════════════════════"
echo "  BPF Verifier Profiling Pipeline"
echo "  Objects dir : $OBJS_DIR"
echo "  Reporter    : $REPORTER"
echo "  Output      : $OUT_DIR"
echo "════════════════════════════════════════════════════════════════"

# ── Collect and filter .bpf.o files ──────────────────────────────────────────
mapfile -t ALL_OBJS < <(find "$OBJS_DIR" -maxdepth 2 -name "*.bpf.o" | sort)

# We want to skip objects that are known to be failing the verifier
FILTERED_OBJS=()
SKIP_PATTERNS='core_reloc|_fail\.|_err\.|_bad\.|_wrong\.|_missing\.|runner\.|loader\.'
for obj in "${ALL_OBJS[@]}"; do
    basename=$(basename "$obj")
    echo "$basename" | grep -qE "$SKIP_PATTERNS" && continue
    FILTERED_OBJS+=("$obj")
done

echo ""
echo "  Total .bpf.o found : ${#ALL_OBJS[@]}"
echo "  After filtering    : ${#FILTERED_OBJS[@]}"

# ── Enable tracing ────────────────────────────────────────────────────────────
echo ""
echo "━━━ Enabling BPF verifier tracepoints ━━━"
echo 1 > "$TRACE_ON"
TP_ENABLED=0
for tp in /sys/kernel/tracing/events/bpf_verifier/*/enable; do
    if [[ -f "$tp" ]]; then
        echo 1 > "$tp"
        ((TP_ENABLED++)) || true
    fi
done
if [[ $TP_ENABLED -eq 0 ]]; then
    echo "ERROR: No bpf_verifier tracepoints found. Check your kernel build." >&2
    exit 1
fi
echo "  Enabled $TP_ENABLED tracepoint(s)"

# ── Helper: extract real BPF function names from ELF ─────────────────────────
get_prog_names() {
    local obj="$1"
    local tool=""

    if command -v llvm-readelf &>/dev/null; then
        tool="llvm-readelf"
    elif command -v readelf &>/dev/null; then
        tool="readelf"
    else
        echo "$(basename "$obj" .bpf.o | cut -c1-15)"
        return
    fi

    # Extract FUNC symbols, strip section prefixes like "fentry/" "xdp/"
    # then sanitise: keep only alphanumeric + underscore, truncate to 15 chars
    "$tool" --symbols "$obj" 2>/dev/null \
        | awk '/FUNC/ {print $NF}' \
        | grep -v '^$' \
        | sed 's|.*/||'         \
        | tr -cd 'a-zA-Z0-9_\n' \
        | awk 'length>0'        \
        | cut -c1-15            \
        | sort -u               \
        || echo "$(basename "$obj" .bpf.o | cut -c1-15)"
}

# ── Main loop ─────────────────────────────────────────────────────────────────
echo ""
echo "━━━ Loading programs and collecting data ━━━"

total=0; with_data=0; no_data=0; load_fail=0

for obj_path in "${FILTERED_OBJS[@]}"; do
    [[ -f "$obj_path" ]] || continue

    basename=$(basename "$obj_path" .bpf.o)

    # Group by filename heuristic (not perfect but helps organise results by category)
    group="other"
    case "$basename" in
        *loop*|*iter_*)                            group="loop"    ;;
        *subprog*|*tailcall*|*freplace*)           group="subprog" ;;
        *map*|*btf*|*bloom*|*ringbuf*)             group="map"     ;;
        *xdp*|*tc_*|*sk_*|*socket*)               group="network" ;;
        *kprobe*|*tracepoint*|*fentry*|*fexit*|*lsm*) group="tracing" ;;
    esac

    group_dir="${RESULTS_DIR}/${group}"
    mkdir -p "$group_dir"

    # Clear trace buffer to isolate this object's verification data
    echo > "$TRACE_FILE"

    # Load — triggers verification for all progs inside the object
    pin_path="/sys/fs/bpf/_pipeline_$$"
    if bpftool prog load "$obj_path" "$pin_path" 2>/dev/null; then
        rm -f "$pin_path"
    else
        ((load_fail++)) || true
    fi

    # Get real function names from ELF
    mapfile -t PROG_NAMES < <(get_prog_names "$obj_path")
    if [[ ${#PROG_NAMES[@]} -eq 0 ]]; then
        PROG_NAMES=("${basename:0:15}")
    fi

    echo ""
    printf "  [%-8s] %s  (%d prog(s))\n" "$group" "$basename" "${#PROG_NAMES[@]}"

    for prog_name in "${PROG_NAMES[@]}"; do
        [[ -z "$prog_name" ]] && continue

        printf "    %-20s → " "$prog_name"

        # Sanitise prog_name for use as a filename (already done above but be safe)
        safe_name=$(echo "$prog_name" | tr -cd 'a-zA-Z0-9_-')
        [[ -z "$safe_name" ]] && { echo "skip (empty name after sanitise)"; continue; }

        json_out="${group_dir}/${basename}__${safe_name}.json"

        mismatch_count=0
        if "$REPORTER" --json "$json_out" "$prog_name" "$obj_path" 2>/dev/null; then
            mismatch_count=$(python3 -c \
                "import json; d=json.load(open('$json_out')); print(d.get('total_mismatches_displayed',0))" \
                2>/dev/null || echo 0)
        fi

        if [[ "$mismatch_count" -gt 0 ]]; then
            printf "%6d mismatches\n" "$mismatch_count"
            ((with_data++)) || true
        else
            printf "no data\n"
            cat > "$json_out" <<EOF
{
  "prog_name": "$prog_name",
  "group": "$group",
  "elf_obj": "$obj_path",
  "total_instructions_with_mismatches": 0,
  "displayed": 0,
  "total_mismatches_displayed": 0,
  "instructions": []
}
EOF
            ((no_data++)) || true
        fi

        ((total++)) || true
    done
done

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  Pipeline complete"
echo "  Total prog names processed : $total"
echo "  With mismatch data         : $with_data"
echo "  No data / trivial          : $no_data"
echo "  Object load failures       : $load_fail"
echo ""
echo "  JSON results : $RESULTS_DIR"
echo "════════════════════════════════════════════════════════════════"
