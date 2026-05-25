/*
 * BPF Verifier Mismatches to Instruction Report
 *
 * Reads bpf_verifier_insn_stats tracepoints and aggregates state mismatches
 * per instruction, then displays a report.
 *
 * Usage: sudo ./bpf_verifier_source_report <program_name>
 * Example: sudo ./bpf_verifier_source_report test_comp
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <inttypes.h>

#define TRACE_FILE "/sys/kernel/tracing/trace"
#define MAX_LINE 512
#define MAX_FILENAME 256
#define MAX_SOURCE_LINE 256
#define MAX_INSTRUCTIONS 10000

/* Structure to hold instruction stats */
typedef struct {
    unsigned int insn_idx;
    unsigned long states_mismatched;
    unsigned int mismatch_cbdepth;
    unsigned int mismatch_curframe;
    unsigned int mismatch_spec;
    unsigned int mismatch_sleepable;
    unsigned int mismatch_refsafe;
    unsigned int mismatch_callsite;
    unsigned int mismatch_registers;
    unsigned int mismatch_stack;
} insn_stat_t;

/* Parse tracepoint output and extract instruction stats */
int parse_tracepoint(const char *prog_name, insn_stat_t *stats, int *count)
{
    FILE *fp;
    char line[MAX_LINE];
    int found_count = 0;

    fp = fopen(TRACE_FILE, "r");
    if (!fp) {
        perror("Error opening trace file");
        fprintf(stderr, "Make sure you have permissions (use sudo)\n");
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        /* Look for bpf_verifier_insn_stats events matching our program */
        if (strstr(line, "bpf_verifier_insn_stats") && strstr(line, prog_name)) {
            unsigned int insn_idx = 0;
            unsigned long states_mismatched = 0;
            unsigned int cbdepth = 0, curframe = 0, spec = 0, sleepable = 0;
            unsigned int refsafe = 0, callsite = 0, regs = 0, stack = 0;

            /* Parse instruction index: insn_idx=<number> */
            char *ptr = strstr(line, "insn_idx=");
            if (ptr) {
                sscanf(ptr, "insn_idx=%u", &insn_idx);
            }

            /* Parse states_mismatched: mismatched=<number> */
            ptr = strstr(line, "mismatched=");
            if (ptr) {
                sscanf(ptr, "mismatched=%lu", &states_mismatched);
            }

            /* Skip entries with zero mismatches */
            if (states_mismatched == 0) {
                continue;
            }

            /* Parse mismatch breakdown: mismatch_breakdown(cbdepth=X curframe=Y ...) */
            ptr = strstr(line, "mismatch_breakdown(");
            if (ptr) {
                sscanf(ptr, "mismatch_breakdown(cbdepth=%u curframe=%u spec=%u sleepable=%u refsafe=%u callsite=%u regs=%u stack=%u)",
                       &cbdepth, &curframe, &spec, &sleepable, &refsafe, &callsite, &regs, &stack);
            }

            /* Aggregate: if this instruction already exists, add to it */
            int found = 0;
            for (int i = 0; i < found_count; i++) {
                if (stats[i].insn_idx == insn_idx) {
                    stats[i].states_mismatched += states_mismatched;
                    stats[i].mismatch_cbdepth += cbdepth;
                    stats[i].mismatch_curframe += curframe;
                    stats[i].mismatch_spec += spec;
                    stats[i].mismatch_sleepable += sleepable;
                    stats[i].mismatch_refsafe += refsafe;
                    stats[i].mismatch_callsite += callsite;
                    stats[i].mismatch_registers += regs;
                    stats[i].mismatch_stack += stack;
                    found = 1;
                    break;
                }
            }

            if (!found && found_count < MAX_INSTRUCTIONS) {
                stats[found_count].insn_idx = insn_idx;
                stats[found_count].states_mismatched = states_mismatched;
                stats[found_count].mismatch_cbdepth = cbdepth;
                stats[found_count].mismatch_curframe = curframe;
                stats[found_count].mismatch_spec = spec;
                stats[found_count].mismatch_sleepable = sleepable;
                stats[found_count].mismatch_refsafe = refsafe;
                stats[found_count].mismatch_callsite = callsite;
                stats[found_count].mismatch_registers = regs;
                stats[found_count].mismatch_stack = stack;
                found_count++;
            }
        }
    }

    fclose(fp);
    *count = found_count;
    return found_count > 0 ? 0 : -1;
}

/* Print results showing instructions with mismatches */
void print_report(insn_stat_t *stats, int count)
{
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                 BPF Verifier Instruction Mismatch Report                           ║\n");
    printf("╚════════════════════════════════════════════════════════════════════════════════════╝\n");
    printf("\n");

    if (count == 0) {
        printf("No mismatches found.\n");
        return;
    }

    /* Sort by states_mismatched descending */
    for (int i = 0; i < count - 1; i++) {
        for (int j = 0; j < count - i - 1; j++) {
            if (stats[j].states_mismatched < stats[j + 1].states_mismatched) {
                insn_stat_t tmp = stats[j];
                stats[j] = stats[j + 1];
                stats[j + 1] = tmp;
            }
        }
    }

    /* Print each instruction with mismatches */
    for (int i = 0; i < count; i++) {
        printf("Instruction: 0x%x\n", stats[i].insn_idx);
        printf("Total Mismatches: %lu\n", stats[i].states_mismatched);
        printf("\nMismatch Reasons Breakdown:\n");

        /* Only show non-zero breakdown categories */
        if (stats[i].mismatch_registers > 0) {
            printf("  - Register state mismatches: %u\n", stats[i].mismatch_registers);
        }
        if (stats[i].mismatch_stack > 0) {
            printf("  - Stack state mismatches: %u\n", stats[i].mismatch_stack);
        }
        if (stats[i].mismatch_cbdepth > 0) {
            printf("  - Call stack depth mismatches: %u\n", stats[i].mismatch_cbdepth);
        }
        if (stats[i].mismatch_curframe > 0) {
            printf("  - Current frame mismatches: %u\n", stats[i].mismatch_curframe);
        }
        if (stats[i].mismatch_spec > 0) {
            printf("  - Speculative state mismatches: %u\n", stats[i].mismatch_spec);
        }
        if (stats[i].mismatch_sleepable > 0) {
            printf("  - Sleepable flag mismatches: %u\n", stats[i].mismatch_sleepable);
        }
        if (stats[i].mismatch_refsafe > 0) {
            printf("  - Reference safety mismatches: %u\n", stats[i].mismatch_refsafe);
        }
        if (stats[i].mismatch_callsite > 0) {
            printf("  - Call site context mismatches: %u\n", stats[i].mismatch_callsite);
        }

        printf("────────────────────────────────────────────────────────────────────────────────────\n");
    }

    printf("\n");
}

int main(int argc, char *argv[])
{
    char *prog_name;
    insn_stat_t stats[MAX_INSTRUCTIONS];
    int stat_count = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <program_name>\n", argv[0]);
        fprintf(stderr, "Example: %s complex_verifie\n", argv[0]);
        fprintf(stderr, "\nThis tool:\n");
        fprintf(stderr, "  1. Reads bpf_verifier_insn_stats tracepoints\n");
        fprintf(stderr, "  2. Filters instructions with mismatches (skips zero mismatches)\n");
        fprintf(stderr, "  3. Displays mismatch breakdown by category\n");
        return 1;
    }

    prog_name = argv[1];

    printf("=== BPF Verifier Instruction Mismatch Report ===\n");
    printf("Program: %s\n\n", prog_name);

    /* Parse tracepoint data */
    printf("Reading tracepoint data...\n");
    if (parse_tracepoint(prog_name, stats, &stat_count) != 0) {
        fprintf(stderr, "No tracepoint data found for program '%s'\n", prog_name);
        fprintf(stderr, "Make sure:\n");
        fprintf(stderr, "  1. Tracepoints are enabled\n");
        fprintf(stderr, "  2. Program has been loaded\n");
        fprintf(stderr, "  3. You're running with sudo\n");
        return 1;
    }
    printf("Found %d instructions with mismatches\n", stat_count);

    /* Print report */
    print_report(stats, stat_count);

    return 0;
}
