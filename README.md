# bpf-verifier-telemetry

Structured telemetry for the Linux BPF verifier's state-comparison engine. The patch instruments
`verifier.c` to count states comparison, match, and mismatch, categorised by the field that caused the rejection.
Results are emitted via kernel tracepoints and can be mapped back to C source lines using DWARF debug info.

## Components

| File                    | Purpose                                                                                      |
|-------------------------|----------------------------------------------------------------------------------------------|
| `kernel/verifier.patch` | Kernel path for source tree `kernel/bpf/verifier.c                                          |
| `kernel/bpf_verifier.h` | Tracepoint definitions (`bpf_verifier_prog_stats`, `bpf_verifier_insn_stats`)                |
| `bpf-mismatch-report.c` | Userspace tool: reads tracepoints, resolves source lines, outputs terminal/HTML/JSON reports |
| `bpf_batch_analyzer.sh` | Batch pipeline: loads a directory of `.bpf.o` files and runs the reporter over each          |
| `analyze_data.py`       | Python script to aggregate and visualize results from multiple runs                          |
| `example/`              | Example BPF program with debug info and output for testing and demonstration                 |
| `results/`              | Data and figures generated using the BPF selftesting suite and batch analyzer pipeline       |

## What gets tracked

**State-level mismatch categories** (8 total): `callback_depth`, `curframe`, `speculative`, `sleepable`, `refsafe`, `callsite`, `registers`, `stack`.

**Register field sub-categories** (8 total): `type`, `range`, `var_off`, `id`, `ref_obj_id`, `offset`, `frameno`, `other`.

Both per-program totals and per-instruction breakdowns are emitted.

## Quick start

### 1. Get the instrumented kernel

**Option A — clone the pre-instrumented fork:**

```sh
git clone https://github.com/SaturneV/linux-ebpf-verifier-profiling
cd linux-ebpf-verifier-profiling
make -j$(nproc)
```

**Option B — apply the patch to an existing tree:**

```sh
cd linux/
git apply /path/to/verifier.patch
cp /path/to/bpf_verifier.h include/trace/events/
make -j$(nproc)
```

### 2. Build the report tool

```sh
# Requires elfutils dev headers
# apt install libdw-dev   /   dnf install elfutils-devel
gcc -O2 -o bpf-mismatch-report bpf-mismatch-report.c -ldw -lelf
```

### 3. Enable tracepoints

```sh
echo 1 > /sys/kernel/tracing/tracing_on
echo 1 > /sys/kernel/tracing/events/bpf_verifier/enable
```

### 4. Load a BPF program and inspect the results

```sh
bpftool prog load ./my_prog.bpf.o /sys/fs/bpf/my_prog

# Terminal report (top 10 instructions by mismatch count)
sudo ./bpf-mismatch-report --top 10 my_func ./my_prog.bpf.o

# HTML heatmap overlaid on source
sudo ./bpf-mismatch-report --html report.html my_func ./my_prog.bpf.o

# JSON for further processing
sudo ./bpf-mismatch-report --json report.json my_func ./my_prog.bpf.o
```

### 5. Batch analysis

```sh
# Place .bpf.o files under ./bpf_objs/, then:
sudo ./bpf_batch_analyzer.sh --objs ./bpf_objs --reporter ./bpf-mismatch-report --out ./out
# JSON results land in ./out/results/, grouped by program type
```

> **Note:** BPF objects must be compiled with `-g` for source mapping to work.

## Requirements

- Linux kernel with `verifier.patch` and `bpf_verifier.h` applied
- Clang/LLVM for compiling BPF programs with DWARF (`-g -O2 -target bpf`)
- `libdw` / `libelf` (elfutils) for the report tool
- `bpftool` for loading programs
- Root access for tracepoint reads

## Use of AI Tools
During the development of this research project, we used ChatGPT (OpenAI, GPT-5.5) and Claude Sonnet 4.6
for language correction, text refinement, code completion, and code generation assistance. All AI-generated
suggestions, text, and code were reviewed, validated, and, where necessary, modified before inclusion in the final work.
