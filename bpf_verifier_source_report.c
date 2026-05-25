/*
 * BPF Verifier Mismatches to Source Code Report
 *
 * Reads bpf_verifier_insn_stats tracepoints, aggregates state mismatches
 * per instruction, then maps each instruction back to its C source line
 * using DWARF debug info embedded in the compiled BPF .o file.
 *
 * Requirements:
 *   - BPF program compiled with: clang -g -O2 -target bpf -c prog.bpf.c -o prog.bpf.o
 *   - elfutils development libraries: apt install libdw-dev / dnf install elfutils-devel
 *
 * Compile:
 *   gcc -O2 -o bpf_verifier_source_report bpf_verifier_source_report.c -ldw -lelf
 *
 * Usage:
 *   sudo ./bpf_verifier_source_report [--top N] [--html out.html] <prog_name> <prog.bpf.o>
 *
 * Examples:
 *   sudo ./bpf_verifier_source_report test_comp ./test_comp.bpf.o
 *   sudo ./bpf_verifier_source_report --top 5 test_comp ./test_comp.bpf.o
 *   sudo ./bpf_verifier_source_report --html report.html test_comp ./test_comp.bpf.o
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
#define MAX_LINE         512
#define MAX_SOURCE_LINE  512
#define MAX_INSTRUCTIONS 10000
#define MAX_SOURCE_LINES 50000  /* max lines we'll read from the .c file */

/* Each BPF instruction is exactly 8 bytes (struct bpf_insn) */
#define BPF_INSN_SIZE 8

/* ──────────────────────────────────────────────
 * Data structures
 * ────────────────────────────────────────────── */

typedef struct {
    unsigned int  insn_idx;
    unsigned long states_mismatched;
    unsigned int  mismatch_cbdepth;
    unsigned int  mismatch_curframe;
    unsigned int  mismatch_spec;
    unsigned int  mismatch_sleepable;
    unsigned int  mismatch_refsafe;
    unsigned int  mismatch_callsite;
    unsigned int  mismatch_registers;
    unsigned int  mismatch_stack;

    /* Filled in by dwarf_lookup() */
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
 * Source-line reader (single line, for terminal)
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

        printf("Mismatch Breakdown:\n");
        if (s->mismatch_registers > 0)
            printf("  - Register state:    %u\n", s->mismatch_registers);
        if (s->mismatch_stack > 0)
            printf("  - Stack state:       %u\n", s->mismatch_stack);
        if (s->mismatch_cbdepth > 0)
            printf("  - Call stack depth:  %u\n", s->mismatch_cbdepth);
        if (s->mismatch_curframe > 0)
            printf("  - Current frame:     %u\n", s->mismatch_curframe);
        if (s->mismatch_spec > 0)
            printf("  - Speculative state: %u\n", s->mismatch_spec);
        if (s->mismatch_sleepable > 0)
            printf("  - Sleepable flag:    %u\n", s->mismatch_sleepable);
        if (s->mismatch_refsafe > 0)
            printf("  - Reference safety:  %u\n", s->mismatch_refsafe);
        if (s->mismatch_callsite > 0)
            printf("  - Call site context: %u\n", s->mismatch_callsite);

        printf("──────────────────────────────────────────────────────────────────────────────────────\n");
    }
    printf("\n");
}

/* ──────────────────────────────────────────────
 * HTML escape helper
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

/* ──────────────────────────────────────────────
 * HTML heatmap report writer
 *
 * Reads the source file, builds a per-line
 * mismatch table (summing all instructions that
 * map to each line), then emits a self-contained
 * HTML file with inline CSS/JS.
 * ────────────────────────────────────────────── */

int write_html_report(const char     *html_path,
                      const char     *prog_name,
                      insn_stat_t    *stats,
                      int             stat_count)
{
    /* ── 1. Determine source file path from the first resolved stat ── */
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

    /* ── 2. Read the entire source file into a line array ── */
    FILE *src_fp = fopen(src_path, "r");
    if (!src_fp) {
        fprintf(stderr, "HTML: cannot open source file '%s'\n", src_path);
        return -1;
    }

    /* We'll store each source line as a malloc'd string */
    char  **src_lines  = calloc(MAX_SOURCE_LINES, sizeof(char *));
    int     src_nlines = 0;
    char    tmp[MAX_SOURCE_LINE];

    while (fgets(tmp, sizeof(tmp), src_fp) && src_nlines < MAX_SOURCE_LINES) {
        /* Strip trailing newline */
        size_t len = strlen(tmp);
        while (len > 0 && (tmp[len-1] == '\n' || tmp[len-1] == '\r'))
            tmp[--len] = '\0';
        src_lines[src_nlines++] = strdup(tmp);
    }
    fclose(src_fp);

    /* ── 3. Build per-line mismatch aggregates ── */
    line_stat_t *line_stats = calloc(src_nlines + 1, sizeof(line_stat_t));
    if (!line_stats) {
        fprintf(stderr, "HTML: out of memory\n");
        return -1;
    }

    for (int i = 0; i < stat_count; i++) {
        int ln = stats[i].src_line;
        if (ln <= 0 || ln > src_nlines) continue;
        line_stats[ln].total     += stats[i].states_mismatched;
        line_stats[ln].registers += stats[i].mismatch_registers;
        line_stats[ln].stack     += stats[i].mismatch_stack;
        line_stats[ln].cbdepth   += stats[i].mismatch_cbdepth;
        line_stats[ln].curframe  += stats[i].mismatch_curframe;
        line_stats[ln].spec      += stats[i].mismatch_spec;
        line_stats[ln].sleepable += stats[i].mismatch_sleepable;
        line_stats[ln].refsafe   += stats[i].mismatch_refsafe;
        line_stats[ln].callsite  += stats[i].mismatch_callsite;
    }

    /* Find maximum for relative scaling */
    unsigned long max_mismatches = 1; /* avoid div-by-zero */
    for (int ln = 1; ln <= src_nlines; ln++) {
        if (line_stats[ln].total > max_mismatches)
            max_mismatches = line_stats[ln].total;
    }

    /* ── 4. Open HTML output ── */
    FILE *out = fopen(html_path, "w");
    if (!out) {
        perror("HTML: cannot open output file");
        free(line_stats);
        return -1;
    }

    /* ── 5. Emit HTML head + CSS ── */
    fprintf(out,
        "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "<meta charset=\"UTF-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
        "<title>BPF Verifier Heatmap — %s</title>\n"
        "<style>\n"
        "  * { box-sizing: border-box; margin: 0; padding: 0; }\n"
        "  body {\n"
        "    background: #1e1e2e;\n"
        "    color: #cdd6f4;\n"
        "    font-family: 'Segoe UI', system-ui, sans-serif;\n"
        "    padding: 2rem;\n"
        "  }\n"
        "  h1 { font-size: 1.4rem; margin-bottom: 0.3rem; color: #cba6f7; }\n"
        "  .meta { font-size: 0.85rem; color: #6c7086; margin-bottom: 1.5rem; }\n"
        "  .legend {\n"
        "    display: flex; align-items: center; gap: 0.8rem;\n"
        "    margin-bottom: 1.2rem; font-size: 0.82rem; color: #a6adc8;\n"
        "  }\n"
        "  .legend-bar {\n"
        "    width: 160px; height: 14px; border-radius: 3px;\n"
        "    background: linear-gradient(to right, #1e1e2e, #ff0000);\n"
        "    border: 1px solid #45475a;\n"
        "  }\n"
        "  /* stats summary table */\n"
        "  .summary {\n"
        "    display: flex; flex-wrap: wrap; gap: 1rem;\n"
        "    margin-bottom: 1.8rem;\n"
        "  }\n"
        "  .stat-card {\n"
        "    background: #313244; border-radius: 8px;\n"
        "    padding: 0.7rem 1.2rem; min-width: 160px;\n"
        "  }\n"
        "  .stat-card .label { font-size: 0.75rem; color: #6c7086; }\n"
        "  .stat-card .value { font-size: 1.3rem; font-weight: 600; color: #cba6f7; }\n"
        "  /* code block */\n"
        "  .code-wrap {\n"
        "    background: #181825;\n"
        "    border: 1px solid #313244;\n"
        "    border-radius: 8px;\n"
        "    overflow: auto;\n"
        "    font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;\n"
        "    font-size: 0.82rem;\n"
        "    line-height: 1.55;\n"
        "  }\n"
        "  table.code { width: 100%%; border-collapse: collapse; }\n"
        "  table.code tr { transition: filter 0.1s; }\n"
        "  table.code tr:hover { filter: brightness(1.25); cursor: default; }\n"
        "  td.ln {\n"
        "    user-select: none; text-align: right;\n"
        "    padding: 1px 10px 1px 14px;\n"
        "    color: #45475a; min-width: 3.5em;\n"
        "    border-right: 1px solid #313244;\n"
        "    vertical-align: top;\n"
        "  }\n"
        "  td.heat {\n"
        "    width: 6px; min-width: 6px; padding: 0;\n"
        "    vertical-align: top;\n"
        "  }\n"
        "  td.count {\n"
        "    text-align: right; padding: 1px 8px;\n"
        "    min-width: 5em; font-size: 0.78rem;\n"
        "    color: #f38ba8; vertical-align: top;\n"
        "  }\n"
        "  td.count.zero { color: transparent; }\n"
        "  td.src {\n"
        "    padding: 1px 14px 1px 10px;\n"
        "    white-space: pre; vertical-align: top;\n"
        "  }\n"
        "  /* tooltip */\n"
        "  .tt {\n"
        "    position: relative;\n"
        "  }\n"
        "  .tt .tip {\n"
        "    visibility: hidden; opacity: 0;\n"
        "    background: #313244; color: #cdd6f4;\n"
        "    border: 1px solid #585b70;\n"
        "    border-radius: 6px; padding: 0.5rem 0.8rem;\n"
        "    position: absolute; left: 0; top: 100%%;\n"
        "    z-index: 10; white-space: nowrap;\n"
        "    font-size: 0.78rem; line-height: 1.6;\n"
        "    box-shadow: 0 4px 16px rgba(0,0,0,0.5);\n"
        "    pointer-events: none;\n"
        "    transition: opacity 0.15s;\n"
        "    margin-top: 2px;\n"
        "  }\n"
        "  .tt:hover .tip { visibility: visible; opacity: 1; }\n"
        "</style>\n"
        "</head>\n"
        "<body>\n",
        prog_name);

    /* ── 6. Header + summary cards ── */
    unsigned long total_mismatches = 0;
    int           hot_lines        = 0;
    int           hot_line_no      = 0;
    unsigned long hot_line_val     = 0;
    for (int ln = 1; ln <= src_nlines; ln++) {
        total_mismatches += line_stats[ln].total;
        if (line_stats[ln].total > 0) hot_lines++;
        if (line_stats[ln].total > hot_line_val) {
            hot_line_val = line_stats[ln].total;
            hot_line_no  = ln;
        }
    }

    fprintf(out,
        "<h1>BPF Verifier Heatmap</h1>\n"
        "<div class=\"meta\">Program: <strong>%s</strong> &nbsp;|&nbsp; Source: <strong>%s</strong></div>\n"
        "<div class=\"summary\">\n"
        "  <div class=\"stat-card\"><div class=\"label\">Total mismatches</div>"
        "<div class=\"value\">%lu</div></div>\n"
        "  <div class=\"stat-card\"><div class=\"label\">Hot lines</div>"
        "<div class=\"value\">%d</div></div>\n"
        "  <div class=\"stat-card\"><div class=\"label\">Hottest line</div>"
        "<div class=\"value\">:%d</div></div>\n"
        "  <div class=\"stat-card\"><div class=\"label\">Source lines</div>"
        "<div class=\"value\">%d</div></div>\n"
        "</div>\n"
        "<div class=\"legend\">"
        "<span>Low</span><div class=\"legend-bar\"></div><span>High</span>"
        "<span style=\"margin-left:1rem;color:#45475a\">Hover a highlighted line for breakdown</span>"
        "</div>\n",
        prog_name, src_path,
        total_mismatches, hot_lines, hot_line_no, src_nlines);

    /* ── 7. Code table ── */
    fprintf(out, "<div class=\"code-wrap\"><table class=\"code\">\n");

    for (int ln = 1; ln <= src_nlines; ln++) {
        unsigned long lv = line_stats[ln].total;

        /* Background color: rgba(255,0,0, intensity) relative to max */
        double intensity = (double)lv / (double)max_mismatches;
        /* Use a sqrt scale so low-count lines are still visible */
        double alpha = 0.0;
        if (lv > 0) {
            alpha = 0.08 + 0.72 * (intensity > 1.0 ? 1.0 : intensity);
            /* sqrt scaling for better contrast at the low end */
            double rel = (double)lv / (double)max_mismatches;
            double sq  = rel < 1.0 ? rel * rel * rel : 1.0; /* cubic for subtlety */
            (void)sq; /* we keep linear but clamp min alpha for visibility */
        }

        char bg_style[64] = "";
        if (lv > 0) {
            /* Recalculate with sqrt for better visual spread */
            double rel = (double)lv / (double)max_mismatches;
            double scaled = rel > 0 ? 0.08 + 0.82 * rel : 0.0;
            if (scaled > 1.0) scaled = 1.0;
            snprintf(bg_style, sizeof(bg_style),
                     " style=\"background:rgba(255,50,50,%.3f)\"", scaled);
            (void)alpha;
        }

        /* Row open — add tt class only if hot */
        if (lv > 0)
            fprintf(out, "<tr%s class=\"tt\">", bg_style);
        else
            fprintf(out, "<tr>");

        /* Line number */
        fprintf(out, "<td class=\"ln\">%d</td>", ln);

        /* Heat bar cell */
        if (lv > 0) {
            double rel    = (double)lv / (double)max_mismatches;
            double scaled = 0.15 + 0.85 * rel;
            fprintf(out, "<td class=\"heat\" style=\"background:rgba(255,50,50,%.3f)\"></td>", scaled);
        } else {
            fprintf(out, "<td class=\"heat\"></td>");
        }

        /* Mismatch count */
        if (lv > 0)
            fprintf(out, "<td class=\"count\">%lu</td>", lv);
        else
            fprintf(out, "<td class=\"count zero\">0</td>");

        /* Source code */
        fprintf(out, "<td class=\"src\">");
        if (src_lines[ln-1])
            html_escape(out, src_lines[ln-1]);
        fprintf(out, "</td>");

        /* Tooltip (only for hot lines) */
        if (lv > 0) {
            fprintf(out, "<td style=\"position:relative;padding:0\"><div class=\"tip\">");
            fprintf(out, "<strong>Line %d — %lu mismatches</strong><br>", ln, lv);
            if (line_stats[ln].registers)
                fprintf(out, "Register state: %u<br>",  line_stats[ln].registers);
            if (line_stats[ln].stack)
                fprintf(out, "Stack state: %u<br>",     line_stats[ln].stack);
            if (line_stats[ln].cbdepth)
                fprintf(out, "Call depth: %u<br>",      line_stats[ln].cbdepth);
            if (line_stats[ln].curframe)
                fprintf(out, "Current frame: %u<br>",   line_stats[ln].curframe);
            if (line_stats[ln].spec)
                fprintf(out, "Speculative: %u<br>",     line_stats[ln].spec);
            if (line_stats[ln].sleepable)
                fprintf(out, "Sleepable: %u<br>",       line_stats[ln].sleepable);
            if (line_stats[ln].refsafe)
                fprintf(out, "Ref safety: %u<br>",      line_stats[ln].refsafe);
            if (line_stats[ln].callsite)
                fprintf(out, "Call site: %u<br>",       line_stats[ln].callsite);
            fprintf(out, "</div></td>");
        }

        fprintf(out, "</tr>\n");
    }

    fprintf(out, "</table></div>\n</body>\n</html>\n");
    fclose(out);

    /* ── 8. Free source lines ── */
    for (int i = 0; i < src_nlines; i++)
        free(src_lines[i]);
    free(src_lines);
    free(line_stats);

    return 0;
}

/* ──────────────────────────────────────────────
 * main
 * ────────────────────────────────────────────── */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [--top N] [--html out.html] <program_name> <path/to/prog.bpf.o>\n"
        "Examples:\n"
        "  %s complex_verifie ./complex_mismatches.o\n"
        "  %s --top 5 complex_verifie ./complex_mismatches.o\n"
        "  %s --html report.html complex_verifie ./complex_mismatches.o\n"
        "  %s --top 10 --html report.html complex_verifie ./complex_mismatches.o\n\n"
        "Options:\n"
        "  --top N          Show only the N instructions with the most mismatches\n"
        "  --html <file>    Write an HTML heatmap of the source file to <file>\n",
        prog, prog, prog, prog, prog);
}

int main(int argc, char *argv[])
{
    int         top       = 0;
    const char *html_path = NULL;
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

    free(stats);
    return 0;
}