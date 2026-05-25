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
 *   gcc -O2 -o bpf_telemetry_reader bpf_telemetry_reader.c -ldw -lelf
 *
 * Usage:
 *   sudo ./bpf_telemetry_reader <prog_name> <path/to/prog.bpf.o>
 *
 * Example:
 *   sudo ./bpf_telemetry_reader test_comp ./test_comp.bpf.o
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

#define TRACE_FILE      "/sys/kernel/tracing/trace"
#define MAX_LINE        512
#define MAX_SOURCE_LINE 512
#define MAX_INSTRUCTIONS 10000

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
    char          src_file[MAX_SOURCE_LINE]; /* absolute or relative path  */
    int           src_line;                  /* 1-based line number, 0 = unknown */
    char          src_text[MAX_SOURCE_LINE]; /* actual source line content  */
} insn_stat_t;

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
                found = 1;
                break;
            }
        }

        if (!found && found_count < MAX_INSTRUCTIONS) {
            insn_stat_t *s       = &stats[found_count];
            s->insn_idx          = insn_idx;
            s->states_mismatched = states_mismatched;
            s->mismatch_cbdepth  = cbdepth;
            s->mismatch_curframe = curframe;
            s->mismatch_spec     = spec;
            s->mismatch_sleepable= sleepable;
            s->mismatch_refsafe  = refsafe;
            s->mismatch_callsite = callsite;
            s->mismatch_registers= regs;
            s->mismatch_stack    = stack;
            s->src_line          = 0;
            s->src_file[0]       = '\0';
            s->src_text[0]       = '\0';
            found_count++;
        }
    }

    fclose(fp);
    *count = found_count;
    return found_count > 0 ? 0 : -1;
}

/* ──────────────────────────────────────────────
 * Source-line reader
 *
 * Given a file path and a 1-based line number,
 * fill 'buf' with the trimmed source text.
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
            /* Trim leading whitespace */
            char *p = tmp;
            while (*p == ' ' || *p == '\t') p++;
            /* Trim trailing newline */
            size_t len = strlen(p);
            while (len > 0 && (p[len-1] == '\n' || p[len-1] == '\r')) {
                p[--len] = '\0';
            }
            snprintf(buf, bufsz, "%s", p);
            break;
        }
    }
    fclose(fp);
}

/* ──────────────────────────────────────────────
 * DWARF lookup
 *
 * Opens the BPF .o ELF file, iterates the DWARF
 * line-number program, and for each instruction
 * converts insn_idx → byte_offset → (file, line).
 *
 * Returns 0 on success, -1 on failure.
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

    /*
     * Walk every DWARF compilation unit (CU).
     * For a single-file BPF program there is usually just one CU,
     * but we handle multiple to be safe.
     */
    Dwarf_Off cu_off  = 0;
    Dwarf_Off next_cu = 0;
    size_t    hdr_sz;

    while (dwarf_nextcu(dbg, cu_off, &next_cu, &hdr_sz, NULL, NULL, NULL) == 0) {
        Dwarf_Die cu_die;
        if (!dwarf_offdie(dbg, cu_off + hdr_sz, &cu_die)) {
            cu_off = next_cu;
            continue;
        }

        /* Get the line-number table for this CU */
        Dwarf_Lines *lines;
        size_t       nlines;
        if (dwarf_getsrclines(&cu_die, &lines, &nlines) != 0) {
            cu_off = next_cu;
            continue;
        }

        /*
         * Each entry in the line table maps a byte address (= byte offset
         * within the section for relocatable .o files) to a source location.
         *
         * For each instruction we want to map:
         *   byte_offset = insn_idx * BPF_INSN_SIZE
         *
         * Strategy: find the line-table entry whose address is the largest
         * value <= byte_offset (lower-bound search).  This is the standard
         * way to map a PC to a source line.
         */
        for (int si = 0; si < count; si++) {
            if (stats[si].src_line != 0) continue; /* already resolved */

            Dwarf_Addr target = (Dwarf_Addr)stats[si].insn_idx * BPF_INSN_SIZE;

            /* Linear scan — line tables are small for BPF programs */
            Dwarf_Addr  best_addr = 0;
            const char *best_file = NULL;
            int         best_line = 0;
            int         found     = 0;

            for (size_t li = 0; li < nlines; li++) {
                Dwarf_Line *dl = dwarf_onesrcline(lines, li);
                if (!dl) continue;

                Dwarf_Addr addr;
                if (dwarf_lineaddr(dl, &addr) != 0) continue;

                /* End-of-sequence markers have addr but no real code */
                bool end_seq = false;
                dwarf_lineendsequence(dl, &end_seq);
                if (end_seq) continue;

                if (addr <= target && addr >= best_addr) {
                    int ln = 0;
                    dwarf_lineno(dl, &ln);
                    if (ln == 0) continue; /* compiler-generated, skip */

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
                                 stats[si].src_text,
                                 sizeof(stats[si].src_text));
            }
        }

        cu_off = next_cu;
    }

    dwarf_end(dbg);
    close(fd);
    return 0;
}

/* ──────────────────────────────────────────────
 * Report printer
 * ────────────────────────────────────────────── */

void print_report(insn_stat_t *stats, int count)
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

    /* Sort by states_mismatched descending (bubble sort — N is small) */
    for (int i = 0; i < count - 1; i++) {
        for (int j = 0; j < count - i - 1; j++) {
            if (stats[j].states_mismatched < stats[j+1].states_mismatched) {
                insn_stat_t tmp = stats[j];
                stats[j]       = stats[j+1];
                stats[j+1]     = tmp;
            }
        }
    }

    for (int i = 0; i < count; i++) {
        insn_stat_t *s = &stats[i];

        printf("Instruction: 0x%x  (byte offset 0x%x)\n",
               s->insn_idx, s->insn_idx * BPF_INSN_SIZE);
        printf("Total Mismatches: %lu\n", s->states_mismatched);

        /* ── Source location ── */
        if (s->src_line > 0) {
            printf("Source: %s:%d\n", s->src_file, s->src_line);
            if (s->src_text[0] != '\0') {
                printf("  ->  %s\n", s->src_text);
            }
        } else {
            printf("Source: (no DWARF mapping found)\n");
        }

        /* ── Mismatch breakdown ── */
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
 * main
 * ────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <program_name> <path/to/prog.bpf.o>\n", argv[0]);
        fprintf(stderr, "Example: %s test_comp ./test_comp.bpf.o\n\n", argv[0]);
        fprintf(stderr, "This tool:\n");
        fprintf(stderr, "  1. Reads bpf_verifier_insn_stats tracepoints filtered by program name\n");
        fprintf(stderr, "  2. Skips instructions with zero mismatches\n");
        fprintf(stderr, "  3. Maps each instruction to its C source line via DWARF debug info\n");
        fprintf(stderr, "  4. Displays a ranked report with source context\n");
        return 1;
    }

    const char *prog_name = argv[1];
    const char *obj_path  = argv[2];

    printf("=== BPF Verifier Instruction Mismatch Report ===\n");
    printf("Program : %s\n", prog_name);
    printf("ELF obj : %s\n\n", obj_path);

    /* Allocate on heap — ~1.28 MB is too large for the stack */
    insn_stat_t *stats = calloc(MAX_INSTRUCTIONS, sizeof(insn_stat_t));
    if (!stats) {
        fprintf(stderr, "Failed to allocate stats array\n");
        return 1;
    }
    int stat_count = 0;

    /* 1. Parse tracepoints */
    printf("Reading tracepoint data from %s ...\n", TRACE_FILE);
    if (parse_tracepoint(prog_name, stats, &stat_count) != 0) {
        fprintf(stderr, "No tracepoint data found for program '%s'.\n", prog_name);
        fprintf(stderr, "Make sure:\n");
        fprintf(stderr, "  1. Tracepoints are enabled\n");
        fprintf(stderr, "  2. The BPF program has been loaded\n");
        fprintf(stderr, "  3. You are running as root (sudo)\n");
        free(stats);
        return 1;
    }
    printf("Found %d instructions with mismatches.\n", stat_count);

    /* 2. Enrich with DWARF source locations */
    printf("Looking up DWARF debug info in %s ...\n", obj_path);
    if (dwarf_lookup(obj_path, stats, stat_count) != 0) {
        fprintf(stderr, "Warning: DWARF lookup failed — source lines will not be shown.\n");
        fprintf(stderr, "Make sure the .o was compiled with -g.\n");
        /* Non-fatal: we still print the numeric report below */
    }

    /* 3. Print report */
    print_report(stats, stat_count);

    free(stats);
    return 0;
}