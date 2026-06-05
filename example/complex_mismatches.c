/*
 * Complex BPF Program - Designed to Trigger Verifier State Mismatches
 * 
 * This program has:
 * - Multiple nested branches and conditions
 * - Complex loops with unpredictable bounds
 * - State divergence points
 * - Random number generation (unpredictable)
 * - Helper function calls with conditional arguments
 * - Bitwise operations and arithmetic
 * - Multiple execution paths that converge
 * 
 * This is guaranteed to trigger many state comparisons and mismatches
 * because the verifier must track all possible paths through the branches.
 * 
 * Compile with: clang -g -O2 -target bpf -I. -c complex_mismatches.c -o complex_mismatches.o
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

/* BPF map for statistics */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_write")
int complex_verifier_challenge(void *ctx)
{
    /* Get random values - unpredictable to verifier */
    __u32 x = bpf_get_prandom_u32();
    __u32 y = bpf_get_prandom_u32();
    __u32 z = bpf_get_prandom_u32();
    __u64 result = 0;
    
    /* Branch 1: First major divergence */
    if (x > 1000) {
        /* Branch 1A */
        if (y > 500) {
            /* Branch 1A1: Nested deep */
            if (z > 200) {
                result = x + y + z;
            } else if (z > 100) {
                result = x + y - z;
            } else {
                result = x + y;
            }
        } else if (y > 250) {
            /* Branch 1A2 */
            result = x - y + z;
        } else {
            /* Branch 1A3 */
            result = (x * y) / (z + 1);
        }
    } else if (x > 500) {
        /* Branch 1B: Multiple conditions */
        if (y > 750) {
            result = (y * z) / (x + 1);
        } else if (y > 250) {
            result = x + (y / (z + 1));
        } else {
            result = z + (x / (y + 1));
        }
    } else {
        /* Branch 1C: Another path */
        if (z > 3000) {
            result = z * x;
        } else if (z > 1000) {
            result = z + x;
        } else {
            result = x - z;
        }
    }
    
    /* Loop with unpredictable iterations - causes state explosion */
    #pragma unroll(0)
    for (__u32 i = 0; i < 15; i++) {
        /* Condition in loop - multiple paths */
        if (i % 3 == 0) {
            result += x;
        } else if (i % 3 == 1) {
            result -= y;
        } else {
            result += z;
        }
        
        /* Nested condition in loop */
        if (i > 5) {
            if (result > 1000000) {
                result = result >> 4;
            }
        }
    }
    
    /* Branch 2: Convergence point with different states */
    if (result > 500000) {
        /* Path A: High result */
        result = result / 100;
        
        if (result > 5000) {
            result = result - 1000;
        } else {
            result = result + 500;
        }
    } else if (result > 100000) {
        /* Path B: Medium result */
        result = result / 10;
        
        if (result > 2000) {
            result = result * 2;
        } else {
            result = result / 2;
        }
    } else {
        /* Path C: Low result */
        result = result * 10;
        
        if (result < 1000) {
            result = result + 5000;
        } else {
            result = result - 1000;
        }
    }
    
    /* Another loop with different loop variable interactions */
    #pragma unroll(0)
    for (__u32 j = 0; j < 20; j++) {
        /* Multiple conditions create more divergence */
        if (j < 5) {
            result += j;
        } else if (j < 10) {
            result -= j;
        } else if (j < 15) {
            result *= j;
        } else {
            result /= (j + 1);
        }
        
        /* Bitwise operations */
        if (j & 1) {
            result ^= j;
        } else {
            result &= (result | j);
        }
    }
    
    /* Branch 3: Complex nested conditions */
    if (x & 0xFF) {
        if (y & 0xFF00) {
            if (z & 0xFF0000) {
                result += (x & y & z);
            } else {
                result += (x | y | z);
            }
        } else {
            if (z ^ x) {
                result -= (x ^ y);
            } else {
                result += (x ^ z);
            }
        }
    } else {
        if ((y + z) > (x + 100)) {
            if (result & 0x1) {
                result += 1;
            } else {
                result -= 1;
            }
        } else {
            result += 2;
        }
    }
    
    /* Another convergence point with state tracking */
    __u32 modifier = 0;
    if (result > 0) {
        if (result > 1000) {
            if (result > 10000) {
                modifier = 10;
            } else {
                modifier = 5;
            }
        } else {
            modifier = 1;
        }
    } else {
        modifier = 0;
    }
    
    result *= modifier;
    
    /* Final loop with result-dependent behavior */
    #pragma unroll(0)
    for (__u32 k = 0; k < 10; k++) {
        if (result > k * 1000) {
            result -= k;
        } else {
            result += k;
        }
        
        /* State tracking within loop */
        if (k > 3) {
            if (result & 0x1) {
                result = result >> 1;
            } else {
                result = result << 1;
            }
        }
    }
    
    /* Update map with result - different branches lead here */
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&stats_map, &key);
    if (val) {
        __sync_fetch_and_add(val, result);
    }
    
    /* Final conditional return */
    if (result & 1) {
        return result & 0xFF;
    } else {
        return (result >> 8) & 0xFF;
    }
}
