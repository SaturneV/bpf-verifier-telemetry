/*
 * BPF Verifier Mismatches to Source Code Report
 *
 * Reads bpf_verifier_insn_stats tracepoints, aggregates state mismatches
 * per instruction, then maps each instruction back to its C source line
 * using DWARF debug info embedded in the compiled BPF .o file.
 *
 * State-level mismatch categories tracked:
 *   cbdepth, curframe, spec, sleepable, refsafe, callsite, registers, stack
 *
 * Register-field mismatch sub-categories tracked (all 8):
 *   type, range, var_off, id, ref_obj_id, offset, frameno, other
 *   (requires kernel patch + bpf_verifier.h with reg_field_pair3/pair4 args)
 *
 * Requirements:
 *   - BPF program compiled with: clang -g -O2 -target bpf -c prog.bpf.c -o prog.bpf.o
 *   - elfutils development libraries: apt install libdw-dev / dnf install elfutils-devel
 *   - Kernel built with verifier.patch and trace/events/bpf_verifier.h applied
 *
 * Compile:
 *   gcc -O2 -o bpf_verifier_source_report bpf_verifier_source_report.c -ldw -lelf
 *
 * Usage:
 *   sudo ./bpf_verifier_source_report [--top N] [--html out.html] [--json out.json] <prog_name> <prog.bpf.o>
 *
 * Examples:
 *   sudo ./bpf_verifier_source_report test_comp ./test_comp.bpf.o
 *   sudo ./bpf_verifier_source_report --top 5 test_comp ./test_comp.bpf.o
 *   sudo ./bpf_verifier_source_report --html report.html test_comp ./test_comp.bpf.o
 *   sudo ./bpf_verifier_source_report --json report.json test_comp ./test_comp.bpf.o
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <fcntl.h>
#include <stdbool.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <dwarf.h>

#define TRACE_FILE       "/sys/kernel/tracing/trace"
#define MAX_LINE         1024
#define MAX_SOURCE_LINE  512
#define MAX_INSTRUCTIONS 10000
#define MAX_SOURCE_LINES 50000

#define BPF_INSN_SIZE 8

/* ──────────────────────────────────────────────
 * Data structures
 * ────────────────────────────────────────────── */

typedef struct {
    unsigned int  insn_idx;
    unsigned long states_mismatched;

    /* mismatch_breakdown fields */
    unsigned int  mismatch_cbdepth;
    unsigned int  mismatch_curframe;
    unsigned int  mismatch_spec;
    unsigned int  mismatch_sleepable;
    unsigned int  mismatch_refsafe;
    unsigned int  mismatch_callsite;
    unsigned int  mismatch_registers;
    unsigned int  mismatch_stack;

    /* reg_field_mismatch fields (only meaningful when mismatch_registers > 0) */
    unsigned int  reg_type;
    unsigned int  reg_range;
    unsigned int  reg_var_off;
    unsigned int  reg_id;
    unsigned int  reg_ref_obj_id;
    unsigned int  reg_offset;
    unsigned int  reg_frameno;
    unsigned int  reg_other;

    /* DWARF source location */
    char          src_file[MAX_SOURCE_LINE];
    int           src_line;
    char          src_text[MAX_SOURCE_LINE];
} insn_stat_t;

/* Per-source-line aggregated mismatch data */
typedef struct {
    unsigned long total;
    unsigned int  registers;
    unsigned int  stack;
    unsigned int  cbdepth;
    unsigned int  curframe;
    unsigned int  spec;
    unsigned int  sleepable;
    unsigned int  refsafe;
    unsigned int  callsite;
    /* reg field sub-breakdown */
    unsigned int  reg_type;
    unsigned int  reg_range;
    unsigned int  reg_var_off;
    unsigned int  reg_id;
    unsigned int  reg_ref_obj_id;
    unsigned int  reg_offset;
    unsigned int  reg_frameno;
    unsigned int  reg_other;
} line_stat_t;

/* ──────────────────────────────────────────────
 * Tracepoint parser
 * ────────────────────────────────────────────── */

int parse_tracepoint(const char *prog_name, insn_stat_t *stats, int *count)
{
    FILE *fp;
    char  line[MAX_LINE];
    int   found_count = 0;

    fp = fopen(TRACE_FILE, "r");
    if (!fp) {
        perror("Error opening trace file");
        fprintf(stderr, "Make sure you have permissions (use sudo)\n");
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, "bpf_verifier_insn_stats") || !strstr(line, prog_name))
            continue;

        unsigned int  insn_idx          = 0;
        unsigned long states_mismatched = 0;
        unsigned int  cbdepth = 0, curframe = 0, spec = 0, sleepable = 0;
        unsigned int  refsafe = 0, callsite = 0, regs = 0, stack = 0;
        unsigned int  rtype = 0, rrange = 0, rvar_off = 0, rid = 0;
        unsigned int  rref_obj_id = 0, roffset = 0, rframeno = 0, rother = 0;

        char *ptr = strstr(line, "insn_idx=");
        if (ptr) sscanf(ptr, "insn_idx=%u", &insn_idx);

        ptr = strstr(line, "mismatched=");
        if (ptr) sscanf(ptr, "mismatched=%lu", &states_mismatched);

        if (states_mismatched == 0) continue;

        ptr = strstr(line, "mismatch_breakdown(");
        if (ptr) {
            sscanf(ptr,
                "mismatch_breakdown(cbdepth=%u curframe=%u spec=%u "
                "sleepable=%u refsafe=%u callsite=%u regs=%u stack=%u)",
                &cbdepth, &curframe, &spec, &sleepable,
                &refsafe, &callsite, &regs, &stack);
        }

        ptr = strstr(line, "reg_field_mismatch(");
        if (ptr) {
            sscanf(ptr,
                "reg_field_mismatch(type=%u range=%u var_off=%u id=%u "
                "ref_obj_id=%u offset=%u frameno=%u other=%u)",
                &rtype, &rrange, &rvar_off, &rid,
                &rref_obj_id, &roffset, &rframeno, &rother);
        }

        /* Aggregate if instruction already seen */
        int found = 0;
        for (int i = 0; i < found_count; i++) {
            if (stats[i].insn_idx == insn_idx) {
                stats[i].states_mismatched   += states_mismatched;
                stats[i].mismatch_cbdepth    += cbdepth;
                stats[i].mismatch_curframe   += curframe;
                stats[i].mismatch_spec       += spec;
                stats[i].mismatch_sleepable  += sleepable;
                stats[i].mismatch_refsafe    += refsafe;
                stats[i].mismatch_callsite   += callsite;
                stats[i].mismatch_registers  += regs;
                stats[i].mismatch_stack      += stack;
                stats[i].reg_type            += rtype;
                stats[i].reg_range           += rrange;
                stats[i].reg_var_off         += rvar_off;
                stats[i].reg_id              += rid;
                stats[i].reg_ref_obj_id      += rref_obj_id;
                stats[i].reg_offset          += roffset;
                stats[i].reg_frameno         += rframeno;
                stats[i].reg_other           += rother;
                found = 1;
                break;
            }
        }

        if (!found && found_count < MAX_INSTRUCTIONS) {
            insn_stat_t *s        = &stats[found_count];
            s->insn_idx           = insn_idx;
            s->states_mismatched  = states_mismatched;
            s->mismatch_cbdepth   = cbdepth;
            s->mismatch_curframe  = curframe;
            s->mismatch_spec      = spec;
            s->mismatch_sleepable = sleepable;
            s->mismatch_refsafe   = refsafe;
            s->mismatch_callsite  = callsite;
            s->mismatch_registers = regs;
            s->mismatch_stack     = stack;
            s->reg_type           = rtype;
            s->reg_range          = rrange;
            s->reg_var_off        = rvar_off;
            s->reg_id             = rid;
            s->reg_ref_obj_id     = rref_obj_id;
            s->reg_offset         = roffset;
            s->reg_frameno        = rframeno;
            s->reg_other          = rother;
            s->src_line           = 0;
            s->src_file[0]        = '\0';
            s->src_text[0]        = '\0';
            found_count++;
        }
    }

    fclose(fp);
    *count = found_count;
    return found_count > 0 ? 0 : -1;
}

/* ──────────────────────────────────────────────
 * Source-line reader
 * ────────────────────────────────────────────── */

static void read_source_line(const char *filepath, int lineno, char *buf, size_t bufsz)
{
    buf[0] = '\0';
    if (lineno <= 0 || !filepath || filepath[0] == '\0') return;

    FILE *fp = fopen(filepath, "r");
    if (!fp) return;

    char tmp[MAX_SOURCE_LINE];
    int  cur = 0;
    while (fgets(tmp, sizeof(tmp), fp)) {
        cur++;
        if (cur == lineno) {
            char *p = tmp;
            while (*p == ' ' || *p == '\t') p++;
            size_t len = strlen(p);
            while (len > 0 && (p[len-1] == '\n' || p[len-1] == '\r'))
                p[--len] = '\0';
            snprintf(buf, bufsz, "%s", p);
            break;
        }
    }
    fclose(fp);
}

/* ──────────────────────────────────────────────
 * DWARF lookup
 * ────────────────────────────────────────────── */

int dwarf_lookup(const char *obj_path, insn_stat_t *stats, int count)
{
    int fd = open(obj_path, O_RDONLY);
    if (fd < 0) {
        perror("open ELF object");
        return -1;
    }

    Dwarf *dbg = dwarf_begin(fd, DWARF_C_READ);
    if (!dbg) {
        fprintf(stderr, "dwarf_begin failed: %s\n", dwarf_errmsg(-1));
        close(fd);
        return -1;
    }

    Dwarf_Off cu_off  = 0;
    Dwarf_Off next_cu = 0;
    size_t    hdr_sz;

    while (dwarf_nextcu(dbg, cu_off, &next_cu, &hdr_sz, NULL, NULL, NULL) == 0) {
        Dwarf_Die cu_die;
        if (!dwarf_offdie(dbg, cu_off + hdr_sz, &cu_die)) {
            cu_off = next_cu;
            continue;
        }

        Dwarf_Lines *lines;
        size_t       nlines;
        if (dwarf_getsrclines(&cu_die, &lines, &nlines) != 0) {
            cu_off = next_cu;
            continue;
        }

        for (int si = 0; si < count; si++) {
            if (stats[si].src_line != 0) continue;

            Dwarf_Addr  target    = (Dwarf_Addr)stats[si].insn_idx * BPF_INSN_SIZE;
            Dwarf_Addr  best_addr = 0;
            const char *best_file = NULL;
            int         best_line = 0;
            int         found     = 0;

            for (size_t li = 0; li < nlines; li++) {
                Dwarf_Line *dl = dwarf_onesrcline(lines, li);
                if (!dl) continue;

                Dwarf_Addr addr;
                if (dwarf_lineaddr(dl, &addr) != 0) continue;

                bool end_seq = false;
                dwarf_lineendsequence(dl, &end_seq);
                if (end_seq) continue;

                if (addr <= target && addr >= best_addr) {
                    int ln = 0;
                    dwarf_lineno(dl, &ln);
                    if (ln == 0) continue;

                    best_addr = addr;
                    best_line = ln;
                    best_file = dwarf_linesrc(dl, NULL, NULL);
                    found     = 1;
                }
            }

            if (found && best_file) {
                snprintf(stats[si].src_file, sizeof(stats[si].src_file),
                         "%s", best_file);
                stats[si].src_line = best_line;
                read_source_line(best_file, best_line,
                                 stats[si].src_text, sizeof(stats[si].src_text));
            }
        }

        cu_off = next_cu;
    }

    dwarf_end(dbg);
    close(fd);
    return 0;
}

/* ──────────────────────────────────────────────
 * Terminal report printer
 * ────────────────────────────────────────────── */

/* Print a single non-zero u32 field with a label, indented */
#define PRINT_NZ(label, val) \
    do { if ((val) > 0) printf("      %-28s %u\n", (label), (val)); } while(0)

void print_report(insn_stat_t *stats, int count, int top)
{
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║              BPF Verifier Source Code Mismatch Report              ║\n");
    printf("╚════════════════════════════════════════════════════════════════════╝\n");
    printf("\n");

    if (count == 0) {
        printf("No mismatches found.\n");
        return;
    }

    /* Sort by states_mismatched descending */
    for (int i = 0; i < count - 1; i++) {
        for (int j = 0; j < count - i - 1; j++) {
            if (stats[j].states_mismatched < stats[j+1].states_mismatched) {
                insn_stat_t tmp = stats[j];
                stats[j]        = stats[j+1];
                stats[j+1]      = tmp;
            }
        }
    }

    int display = (top > 0 && top < count) ? top : count;

    if (top > 0)
        printf("Showing top %d of %d instructions with mismatches.\n\n", display, count);
    else
        printf("Showing all %d instructions with mismatches.\n\n", count);

    for (int i = 0; i < display; i++) {
        insn_stat_t *s = &stats[i];

        printf("[%d/%d] Instruction: 0x%x  (byte offset 0x%x)\n",
               i + 1, display, s->insn_idx, s->insn_idx * BPF_INSN_SIZE);
        printf("Total Mismatches: %lu\n", s->states_mismatched);

        if (s->src_line > 0) {
            printf("Source: %s:%d\n", s->src_file, s->src_line);
            if (s->src_text[0] != '\0')
                printf("  ->  %s\n", s->src_text);
        } else {
            printf("Source: (no DWARF mapping found)\n");
        }

        /* ── State mismatch breakdown ── */
        bool has_breakdown = s->mismatch_registers || s->mismatch_stack ||
                             s->mismatch_cbdepth   || s->mismatch_curframe ||
                             s->mismatch_spec       || s->mismatch_sleepable ||
                             s->mismatch_refsafe    || s->mismatch_callsite;
        if (has_breakdown) {
            printf("  Mismatch breakdown:\n");
            PRINT_NZ("Register state:",    s->mismatch_registers);
            PRINT_NZ("Stack state:",       s->mismatch_stack);
            PRINT_NZ("Call stack depth:",  s->mismatch_cbdepth);
            PRINT_NZ("Current frame:",     s->mismatch_curframe);
            PRINT_NZ("Speculative state:", s->mismatch_spec);
            PRINT_NZ("Sleepable flag:",    s->mismatch_sleepable);
            PRINT_NZ("Reference safety:",  s->mismatch_refsafe);
            PRINT_NZ("Call site context:", s->mismatch_callsite);
        }

        /* ── Register field sub-breakdown (only when register mismatches exist) ── */
        bool has_reg_fields = s->mismatch_registers > 0 &&
                              (s->reg_type || s->reg_range  || s->reg_var_off ||
                               s->reg_id   || s->reg_ref_obj_id || s->reg_offset ||
                               s->reg_frameno || s->reg_other);
        if (has_reg_fields) {
            printf("  Register field causing mismatch:\n");
            PRINT_NZ("Type mismatch:",        s->reg_type);
            PRINT_NZ("Value range:",          s->reg_range);
            PRINT_NZ("Variable offset:",      s->reg_var_off);
            PRINT_NZ("Register ID:",          s->reg_id);
            PRINT_NZ("Ref object ID:",        s->reg_ref_obj_id);
            PRINT_NZ("Pointer offset:",       s->reg_offset);
            PRINT_NZ("Frame number:",         s->reg_frameno);
            PRINT_NZ("Other:",                s->reg_other);
        }

        printf("──────────────────────────────────────────────────────────────────────────────────────\n");
    }
    printf("\n");
}

/* ──────────────────────────────────────────────
 * HTML helpers
 * ────────────────────────────────────────────── */

static void html_escape(FILE *fp, const char *s)
{
    for (; *s; s++) {
        switch (*s) {
            case '&':  fputs("&amp;",  fp); break;
            case '<':  fputs("&lt;",   fp); break;
            case '>':  fputs("&gt;",   fp); break;
            case '"':  fputs("&quot;", fp); break;
            case '\'': fputs("&#39;",  fp); break;
            default:   fputc(*s, fp);       break;
        }
    }
}

/* Emit a tooltip row only if value > 0 */
static void tip_row(FILE *fp, const char *label, unsigned int val)
{
    if (val > 0)
        fprintf(fp, "%s: %u<br>", label, val);
}

/* ──────────────────────────────────────────────
 * HTML heatmap writer
 * ────────────────────────────────────────────── */

int write_html_report(const char     *html_path,
                      const char     *prog_name,
                      insn_stat_t    *stats,
                      int             stat_count)
{
    /* Find source file from DWARF data */
    const char *src_path = NULL;
    for (int i = 0; i < stat_count; i++) {
        if (stats[i].src_line > 0 && stats[i].src_file[0] != '\0') {
            src_path = stats[i].src_file;
            break;
        }
    }
    if (!src_path) {
        fprintf(stderr, "HTML: no source file path found in DWARF data\n");
        return -1;
    }

    /* Read source file */
    FILE *src_fp = fopen(src_path, "r");
    if (!src_fp) {
        fprintf(stderr, "HTML: cannot open source file '%s'\n", src_path);
        return -1;
    }
    char  **src_lines  = calloc(MAX_SOURCE_LINES, sizeof(char *));
    int     src_nlines = 0;
    char    tmp[MAX_SOURCE_LINE];
    while (fgets(tmp, sizeof(tmp), src_fp) && src_nlines < MAX_SOURCE_LINES) {
        size_t len = strlen(tmp);
        while (len > 0 && (tmp[len-1] == '\n' || tmp[len-1] == '\r'))
            tmp[--len] = '\0';
        src_lines[src_nlines++] = strdup(tmp);
    }
    fclose(src_fp);

    /* Build per-line aggregates */
    line_stat_t *ls = calloc(src_nlines + 1, sizeof(line_stat_t));
    if (!ls) { fprintf(stderr, "HTML: out of memory\n"); return -1; }

    for (int i = 0; i < stat_count; i++) {
        int ln = stats[i].src_line;
        if (ln <= 0 || ln > src_nlines) continue;
        ls[ln].total       += stats[i].states_mismatched;
        ls[ln].registers   += stats[i].mismatch_registers;
        ls[ln].stack       += stats[i].mismatch_stack;
        ls[ln].cbdepth     += stats[i].mismatch_cbdepth;
        ls[ln].curframe    += stats[i].mismatch_curframe;
        ls[ln].spec        += stats[i].mismatch_spec;
        ls[ln].sleepable   += stats[i].mismatch_sleepable;
        ls[ln].refsafe     += stats[i].mismatch_refsafe;
        ls[ln].callsite    += stats[i].mismatch_callsite;
        ls[ln].reg_type        += stats[i].reg_type;
        ls[ln].reg_range       += stats[i].reg_range;
        ls[ln].reg_var_off     += stats[i].reg_var_off;
        ls[ln].reg_id          += stats[i].reg_id;
        ls[ln].reg_ref_obj_id  += stats[i].reg_ref_obj_id;
        ls[ln].reg_offset      += stats[i].reg_offset;
        ls[ln].reg_frameno     += stats[i].reg_frameno;
        ls[ln].reg_other       += stats[i].reg_other;
    }

    unsigned long max_val = 1;
    unsigned long total_mismatches = 0;
    int hot_lines = 0, hot_line_no = 0;
    unsigned long hot_line_val = 0;
    for (int ln = 1; ln <= src_nlines; ln++) {
        total_mismatches += ls[ln].total;
        if (ls[ln].total > 0) hot_lines++;
        if (ls[ln].total > max_val) max_val = ls[ln].total;
        if (ls[ln].total > hot_line_val) { hot_line_val = ls[ln].total; hot_line_no = ln; }
    }

    FILE *out = fopen(html_path, "w");
    if (!out) { perror("HTML: cannot open output file"); free(ls); return -1; }

    /* ── HEAD + CSS ── */
    fprintf(out,
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
        "<meta charset=\"UTF-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
        "<title>BPF Verifier Heatmap — %s</title>\n"
        "<style>\n"
        "* { box-sizing: border-box; margin: 0; padding: 0; }\n"
        "body { background:#1e1e2e; color:#cdd6f4; font-family:'Segoe UI',system-ui,sans-serif; padding:2rem; }\n"
        "h1 { font-size:1.4rem; margin-bottom:0.3rem; color:#cba6f7; }\n"
        ".meta { font-size:0.85rem; color:#6c7086; margin-bottom:1.5rem; }\n"
        ".cards { display:flex; flex-wrap:wrap; gap:1rem; margin-bottom:1.5rem; }\n"
        ".card { background:#313244; border-radius:8px; padding:0.7rem 1.2rem; min-width:160px; }\n"
        ".card .lbl { font-size:0.75rem; color:#6c7086; }\n"
        ".card .val { font-size:1.3rem; font-weight:600; color:#cba6f7; }\n"
        ".legend { display:flex; align-items:center; gap:0.8rem; margin-bottom:1.2rem; font-size:0.82rem; color:#a6adc8; }\n"
        ".legend-bar { width:160px; height:14px; border-radius:3px; background:linear-gradient(to right,#1e1e2e,#ff3232); border:1px solid #45475a; }\n"
        ".code-wrap { background:#181825; border:1px solid #313244; border-radius:8px; overflow:auto; font-family:'JetBrains Mono','Fira Code',monospace; font-size:0.82rem; line-height:1.55; }\n"
        "table.code { width:100%%; border-collapse:collapse; }\n"
        "table.code tr:hover { filter:brightness(1.25); cursor:default; }\n"
        "td.ln { user-select:none; text-align:right; padding:1px 10px 1px 14px; color:#45475a; min-width:3.5em; border-right:1px solid #313244; vertical-align:top; }\n"
        "td.heat { width:6px; min-width:6px; padding:0; vertical-align:top; }\n"
        "td.cnt { text-align:right; padding:1px 8px; min-width:5em; font-size:0.78rem; color:#f38ba8; vertical-align:top; }\n"
        "td.cnt.z { color:transparent; }\n"
        "td.src { padding:1px 14px 1px 10px; white-space:pre; vertical-align:top; }\n"
        /* tooltip */
        ".tt { position:relative; }\n"
        ".tip { visibility:hidden; opacity:0; background:#313244; color:#cdd6f4; border:1px solid #585b70;\n"
        "       border-radius:6px; padding:0.5rem 0.8rem; position:absolute; left:0; top:100%%; z-index:10;\n"
        "       white-space:nowrap; font-size:0.78rem; line-height:1.8; box-shadow:0 4px 16px rgba(0,0,0,.5);\n"
        "       pointer-events:none; transition:opacity .15s; margin-top:2px; }\n"
        ".tt:hover .tip { visibility:visible; opacity:1; }\n"
        /* reg field sub-section inside tooltip */
        ".tip .reg-hdr { color:#cba6f7; font-weight:600; margin-top:0.35rem; display:block; }\n"
        ".tip .reg-fields { color:#a6e3a1; }\n"
        "</style>\n</head>\n<body>\n",
        prog_name);

    /* ── Header + summary cards ── */
    fprintf(out,
        "<h1>BPF Verifier Heatmap</h1>\n"
        "<div class=\"meta\">Program: <strong>%s</strong> &nbsp;|&nbsp; Source: <strong>%s</strong></div>\n"
        "<div class=\"cards\">\n"
        "  <div class=\"card\"><div class=\"lbl\">Total mismatches</div><div class=\"val\">%lu</div></div>\n"
        "  <div class=\"card\"><div class=\"lbl\">Hot lines</div><div class=\"val\">%d</div></div>\n"
        "  <div class=\"card\"><div class=\"lbl\">Hottest line</div><div class=\"val\">:%d</div></div>\n"
        "  <div class=\"card\"><div class=\"lbl\">Source lines</div><div class=\"val\">%d</div></div>\n"
        "</div>\n"
        "<div class=\"legend\"><span>Low</span><div class=\"legend-bar\"></div><span>High</span>"
        "<span style=\"margin-left:1rem;color:#45475a\">Hover a highlighted line for full breakdown</span></div>\n",
        prog_name, src_path,
        total_mismatches, hot_lines, hot_line_no, src_nlines);

    /* ── Code table ── */
    fprintf(out, "<div class=\"code-wrap\"><table class=\"code\">\n");

    for (int ln = 1; ln <= src_nlines; ln++) {
        unsigned long lv = ls[ln].total;
        double rel    = (double)lv / (double)max_val;
        double bg_alpha  = lv > 0 ? 0.08 + 0.82 * rel : 0.0;
        double bar_alpha = lv > 0 ? 0.15 + 0.85 * rel : 0.0;

        if (lv > 0)
            fprintf(out, "<tr style=\"background:rgba(255,50,50,%.3f)\" class=\"tt\">", bg_alpha);
        else
            fprintf(out, "<tr>");

        /* Line number */
        fprintf(out, "<td class=\"ln\">%d</td>", ln);

        /* Heat bar */
        if (lv > 0)
            fprintf(out, "<td class=\"heat\" style=\"background:rgba(255,50,50,%.3f)\"></td>", bar_alpha);
        else
            fprintf(out, "<td class=\"heat\"></td>");

        /* Mismatch count */
        if (lv > 0)
            fprintf(out, "<td class=\"cnt\">%lu</td>", lv);
        else
            fprintf(out, "<td class=\"cnt z\">0</td>");

        /* Source code */
        fprintf(out, "<td class=\"src\">");
        if (src_lines[ln-1]) html_escape(out, src_lines[ln-1]);
        fprintf(out, "</td>");

        /* Tooltip */
        if (lv > 0) {
            fprintf(out, "<td style=\"position:relative;padding:0\"><div class=\"tip\">");
            fprintf(out, "<strong>Line %d &mdash; %lu mismatches</strong><br>", ln, lv);

            /* State breakdown */
            tip_row(out, "Register state",    ls[ln].registers);
            tip_row(out, "Stack state",       ls[ln].stack);
            tip_row(out, "Call depth",        ls[ln].cbdepth);
            tip_row(out, "Current frame",     ls[ln].curframe);
            tip_row(out, "Speculative",       ls[ln].spec);
            tip_row(out, "Sleepable",         ls[ln].sleepable);
            tip_row(out, "Ref safety",        ls[ln].refsafe);
            tip_row(out, "Call site",         ls[ln].callsite);

            /* Register field sub-breakdown — only shown when there are reg mismatches */
            bool any_reg_field = ls[ln].reg_type || ls[ln].reg_range  || ls[ln].reg_var_off ||
                                 ls[ln].reg_id   || ls[ln].reg_ref_obj_id || ls[ln].reg_offset ||
                                 ls[ln].reg_frameno || ls[ln].reg_other;
            if (ls[ln].registers > 0 && any_reg_field) {
                fprintf(out, "<span class=\"reg-hdr\">Register field causing mismatch:</span>");
                fprintf(out, "<span class=\"reg-fields\">");
                tip_row(out, "&nbsp; Type mismatch",   ls[ln].reg_type);
                tip_row(out, "&nbsp; Value range",     ls[ln].reg_range);
                tip_row(out, "&nbsp; Variable offset", ls[ln].reg_var_off);
                tip_row(out, "&nbsp; Register ID",     ls[ln].reg_id);
                tip_row(out, "&nbsp; Ref object ID",   ls[ln].reg_ref_obj_id);
                tip_row(out, "&nbsp; Pointer offset",  ls[ln].reg_offset);
                tip_row(out, "&nbsp; Frame number",    ls[ln].reg_frameno);
                tip_row(out, "&nbsp; Other",           ls[ln].reg_other);
                fprintf(out, "</span>");
            }

            fprintf(out, "</div></td>");
        }

        fprintf(out, "</tr>\n");
    }

    fprintf(out, "</table></div>\n</body>\n</html>\n");
    fclose(out);

    for (int i = 0; i < src_nlines; i++) free(src_lines[i]);
    free(src_lines);
    free(ls);
    return 0;
}

/* ──────────────────────────────────────────────
 * JSON helpers
 * ────────────────────────────────────────────── */

/* Escape a string for JSON: backslash, double-quote, and control chars */
static void json_escape(FILE *fp, const char *s)
{
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if      (c == '"')  fputs("\\\"", fp);
        else if (c == '\\') fputs("\\\\", fp);
        else if (c == '\n') fputs("\\n",  fp);
        else if (c == '\r') fputs("\\r",  fp);
        else if (c == '\t') fputs("\\t",  fp);
        else if (c < 0x20)  fprintf(fp, "\\u%04x", c);
        else                fputc(c, fp);
    }
}

/* ──────────────────────────────────────────────
 * JSON report writer
 * ────────────────────────────────────────────── */

/*
 * Emits one JSON object per instruction, sorted by states_mismatched
 * descending (same order as the terminal report).  The array is wrapped
 * in a top-level object that also carries program-level metadata so the
 * file is self-contained.
 *
 * Schema (abbreviated):
 * {
 *   "prog_name": "foo",
 *   "elf_obj":   "foo.bpf.o",
 *   "total_instructions_with_mismatches": N,
 *   "instructions": [
 *     {
 *       "insn_idx":         42,
 *       "byte_offset":      336,
 *       "states_mismatched": 6,
 *       "source": {                        // omitted when no DWARF mapping
 *         "file": "/path/to/prog.bpf.c",
 *         "line": 87,
 *         "text": "if (ctx->data_end > ...)"
 *       },
 *       "mismatch_breakdown": {
 *         "registers":  5,
 *         "stack":      1,
 *         "cbdepth":    0,
 *         "curframe":   0,
 *         "speculative":0,
 *         "sleepable":  0,
 *         "refsafe":    0,
 *         "callsite":   0
 *       },
 *       "reg_field_mismatch": {            // omitted when registers == 0
 *         "type":       0,
 *         "range":      3,
 *         "var_off":    0,
 *         "id":         2,
 *         "ref_obj_id": 0,
 *         "offset":     0,
 *         "frameno":    0,
 *         "other":      0
 *       }
 *     },
 *     ...
 *   ]
 * }
 */
int write_json_report(const char  *json_path,
                      const char  *prog_name,
                      const char  *obj_path,
                      insn_stat_t *stats,
                      int          count,
                      int          top)
{
    FILE *fp = fopen(json_path, "w");
    if (!fp) {
        perror("JSON: cannot open output file");
        return -1;
    }

    /* stats[] is already sorted by print_report(); respect --top */
    int display = (top > 0 && top < count) ? top : count;

    /* Compute total mismatches across displayed instructions */
    unsigned long total_mismatches = 0;
    for (int i = 0; i < display; i++)
        total_mismatches += stats[i].states_mismatched;

    /* ── Top-level object ── */
    fprintf(fp, "{\n");
    fprintf(fp, "  \"prog_name\": \""); json_escape(fp, prog_name); fprintf(fp, "\",\n");
    fprintf(fp, "  \"elf_obj\": \"");   json_escape(fp, obj_path);  fprintf(fp, "\",\n");
    fprintf(fp, "  \"total_instructions_with_mismatches\": %d,\n", count);
    fprintf(fp, "  \"displayed\": %d,\n", display);
    fprintf(fp, "  \"total_mismatches_displayed\": %lu,\n", total_mismatches);
    fprintf(fp, "  \"instructions\": [\n");

    for (int i = 0; i < display; i++) {
        insn_stat_t *s = &stats[i];
        bool last = (i == display - 1);

        fprintf(fp, "    {\n");
        fprintf(fp, "      \"insn_idx\": %u,\n",          s->insn_idx);
        fprintf(fp, "      \"byte_offset\": %u,\n",       s->insn_idx * BPF_INSN_SIZE);
        fprintf(fp, "      \"states_mismatched\": %lu",   s->states_mismatched);

        /* ── Source location (optional) ── */
        if (s->src_line > 0) {
            fprintf(fp, ",\n      \"source\": {\n");
            fprintf(fp, "        \"file\": \""); json_escape(fp, s->src_file); fprintf(fp, "\",\n");
            fprintf(fp, "        \"line\": %d,\n", s->src_line);
            fprintf(fp, "        \"text\": \""); json_escape(fp, s->src_text); fprintf(fp, "\"\n");
            fprintf(fp, "      }");
        }

        /* ── State-level mismatch breakdown (always present) ── */
        fprintf(fp, ",\n      \"mismatch_breakdown\": {\n");
        fprintf(fp, "        \"registers\":   %u,\n", s->mismatch_registers);
        fprintf(fp, "        \"stack\":        %u,\n", s->mismatch_stack);
        fprintf(fp, "        \"cbdepth\":      %u,\n", s->mismatch_cbdepth);
        fprintf(fp, "        \"curframe\":     %u,\n", s->mismatch_curframe);
        fprintf(fp, "        \"speculative\":  %u,\n", s->mismatch_spec);
        fprintf(fp, "        \"sleepable\":    %u,\n", s->mismatch_sleepable);
        fprintf(fp, "        \"refsafe\":      %u,\n", s->mismatch_refsafe);
        fprintf(fp, "        \"callsite\":     %u\n",  s->mismatch_callsite);
        fprintf(fp, "      }");

        /* ── Register field sub-breakdown (only when registers > 0) ── */
        if (s->mismatch_registers > 0) {
            fprintf(fp, ",\n      \"reg_field_mismatch\": {\n");
            fprintf(fp, "        \"type\":       %u,\n", s->reg_type);
            fprintf(fp, "        \"range\":      %u,\n", s->reg_range);
            fprintf(fp, "        \"var_off\":    %u,\n", s->reg_var_off);
            fprintf(fp, "        \"id\":         %u,\n", s->reg_id);
            fprintf(fp, "        \"ref_obj_id\": %u,\n", s->reg_ref_obj_id);
            fprintf(fp, "        \"offset\":     %u,\n", s->reg_offset);
            fprintf(fp, "        \"frameno\":    %u,\n", s->reg_frameno);
            fprintf(fp, "        \"other\":      %u\n",  s->reg_other);
            fprintf(fp, "      }");
        }

        fprintf(fp, "\n    }%s\n", last ? "" : ",");
    }

    fprintf(fp, "  ]\n}\n");
    fclose(fp);
    return 0;
}

/* ──────────────────────────────────────────────
 * main
 * ────────────────────────────────────────────── */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [--top N] [--html out.html] [--json out.json] <program_name> <path/to/prog.bpf.o>\n"
        "Examples:\n"
        "  %s complex_verifie ./complex_mismatches.o\n"
        "  %s --top 5 complex_verifie ./complex_mismatches.o\n"
        "  %s --html report.html complex_verifie ./complex_mismatches.o\n"
        "  %s --json report.json complex_verifie ./complex_mismatches.o\n\n"
        "Options:\n"
        "  --top N          Show only the N instructions with the most mismatches\n"
        "  --html <file>    Write an HTML heatmap of the source file to <file>\n"
        "  --json <file>    Write a JSON report (per-instruction, with source info) to <file>\n",
        prog, prog, prog, prog, prog);
}

int main(int argc, char *argv[])
{
    int         top       = 0;
    const char *html_path = NULL;
    const char *json_path = NULL;
    const char *prog_name = NULL;
    const char *obj_path  = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--top") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --top requires a numeric argument\n");
                usage(argv[0]); return 1;
            }
            char *end;
            top = (int)strtol(argv[++i], &end, 10);
            if (*end != '\0' || top <= 0) {
                fprintf(stderr, "Error: --top value must be a positive integer\n");
                usage(argv[0]); return 1;
            }
        } else if (strcmp(argv[i], "--html") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --html requires a filename argument\n");
                usage(argv[0]); return 1;
            }
            html_path = argv[++i];
        } else if (strcmp(argv[i], "--json") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --json requires a filename argument\n");
                usage(argv[0]); return 1;
            }
            json_path = argv[++i];
        } else if (!prog_name) {
            prog_name = argv[i];
        } else if (!obj_path) {
            obj_path = argv[i];
        } else {
            fprintf(stderr, "Error: unexpected argument '%s'\n", argv[i]);
            usage(argv[0]); return 1;
        }
    }

    if (!prog_name || !obj_path) {
        usage(argv[0]); return 1;
    }

    printf("=== BPF Verifier Instruction Mismatch Report ===\n");
    printf("Program : %s\n", prog_name);
    printf("ELF obj : %s\n", obj_path);
    if (top > 0)       printf("Mode    : top %d\n", top);
    if (html_path)     printf("HTML    : %s\n", html_path);
    if (json_path)     printf("JSON    : %s\n", json_path);
    printf("\n");

    insn_stat_t *stats = calloc(MAX_INSTRUCTIONS, sizeof(insn_stat_t));
    if (!stats) {
        fprintf(stderr, "Failed to allocate stats array\n");
        return 1;
    }
    int stat_count = 0;

    printf("Reading tracepoint data from %s ...\n", TRACE_FILE);
    if (parse_tracepoint(prog_name, stats, &stat_count) != 0) {
        fprintf(stderr, "No tracepoint data found for program '%s'.\n", prog_name);
        fprintf(stderr, "Make sure:\n"
                        "  1. Tracepoints are enabled\n"
                        "  2. The BPF program has been loaded\n"
                        "  3. You are running as root (sudo)\n");
        free(stats); return 1;
    }
    printf("Found %d instructions with mismatches.\n", stat_count);

    printf("Looking up DWARF debug info in %s ...\n", obj_path);
    if (dwarf_lookup(obj_path, stats, stat_count) != 0) {
        fprintf(stderr, "Warning: DWARF lookup failed — source lines will not be shown.\n"
                        "Make sure the .o was compiled with -g.\n");
    }

    print_report(stats, stat_count, top);

    if (html_path) {
        printf("Writing HTML heatmap to %s ...\n", html_path);
        if (write_html_report(html_path, prog_name, stats, stat_count) == 0)
            printf("Done. Open %s in a browser.\n", html_path);
        else
            fprintf(stderr, "Warning: HTML report generation failed.\n");
    }

    if (json_path) {
        printf("Writing JSON report to %s ...\n", json_path);
        if (write_json_report(json_path, prog_name, obj_path, stats, stat_count, top) == 0)
            printf("Done. %s written.\n", json_path);
        else
            fprintf(stderr, "Warning: JSON report generation failed.\n");
    }

    free(stats);
    return 0;
}