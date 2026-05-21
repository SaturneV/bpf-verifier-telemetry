/*
 * Simple BPF Verifier Telemetry Reader
 *
 * Usage: sudo ./bpf_telemetry_reader <program_name>
 * Example: sudo ./bpf_telemetry_reader test_comp
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TRACE_FILE "/sys/kernel/tracing/trace"
#define MAX_LINE 512

int main(int argc, char *argv[])
{
    FILE *fp;
    char line[MAX_LINE];
    char *prog_name;
    int found = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <program_name>\n", argv[0]);
        fprintf(stderr, "Example: %s test_comp\n", argv[0]);
        return 1;
    }

    prog_name = argv[1];

    /* Open trace file */
    fp = fopen(TRACE_FILE, "r");
    if (!fp) {
        perror("Error opening trace file");
        fprintf(stderr, "Make sure you have permissions (use sudo)\n");
        return 1;
    }

    printf("=== BPF Verifier Telemetry for: %s ===\n\n", prog_name);

    /* Read and filter trace lines */
    while (fgets(line, sizeof(line), fp)) {
        /* Look for bpf_verifier_prog_stats events */
        if (strstr(line, "bpf_verifier_prog_stats") && strstr(line, prog_name)) {
            printf("Program Statistics:\n");
            printf("%s\n", line);
            found = 1;
        }
        /* Look for bpf_verifier_insn_stats events for this program */
        else if (strstr(line, "bpf_verifier_insn_stats") && strstr(line, prog_name)) {
            printf("Instruction Statistics:\n");
            printf("%s\n", line);
            found = 1;
        }
    }

    fclose(fp);

    if (!found) {
        printf("No telemetry found for program: %s\n", prog_name);
        printf("\nTip: Enable tracepoints first with:\n");
        printf("  echo 1 > /sys/kernel/tracing/events/bpf_verifier/bpf_verifier_prog_stats/enable\n");
        printf("  echo 1 > /sys/kernel/tracing/events/bpf_verifier/bpf_verifier_insn_stats/enable\n");
        printf("\nThen load a BPF program:\n");
        printf("  bpftool prog load <prog.o> /sys/fs/bpf/<name> type tracepoint autoattach\n");
        return 1;
    }

    return 0;
}