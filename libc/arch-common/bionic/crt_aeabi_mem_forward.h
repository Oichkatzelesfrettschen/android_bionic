/* SPDX-License-Identifier: BSD-2-Clause */

#pragma once

#if defined(__arm__)
/*
 * On arm32 the compiler lowers memcpy, memmove and memset to the RTABI
 * __aeabi_mem* helpers. A module that links Rust code also links the Rust
 * compiler_builtins versions of those helpers as weak hidden definitions, and
 * a hidden definition binds every call in the module to it ahead of libc's
 * exported, NEON-optimized memcpy, memmove and memset. These forwarders are
 * weak and hidden too and sit in the crtbegin object at the head of every
 * link; lld keeps the first of two weak definitions, so the module's helpers
 * branch to libc. __aeabi_memset takes (dest, n, c) and __aeabi_memclr takes
 * (dest, n), while memset takes (dest, c, n).
 */
__asm__(
    "  .pushsection .text.__aeabi_mem_libc_forward, \"ax\", %progbits\n"
    "  .syntax unified\n"
    "  .arm\n"
    "  .p2align 2\n"
    "  .weak __aeabi_memcpy8\n  .hidden __aeabi_memcpy8\n  .type __aeabi_memcpy8, %function\n"
    "  .weak __aeabi_memcpy4\n  .hidden __aeabi_memcpy4\n  .type __aeabi_memcpy4, %function\n"
    "  .weak __aeabi_memcpy\n  .hidden __aeabi_memcpy\n  .type __aeabi_memcpy, %function\n"
    "__aeabi_memcpy8:\n"
    "__aeabi_memcpy4:\n"
    "__aeabi_memcpy:\n"
    "  b memcpy\n"
    "  .weak __aeabi_memmove8\n  .hidden __aeabi_memmove8\n  .type __aeabi_memmove8, %function\n"
    "  .weak __aeabi_memmove4\n  .hidden __aeabi_memmove4\n  .type __aeabi_memmove4, %function\n"
    "  .weak __aeabi_memmove\n  .hidden __aeabi_memmove\n  .type __aeabi_memmove, %function\n"
    "__aeabi_memmove8:\n"
    "__aeabi_memmove4:\n"
    "__aeabi_memmove:\n"
    "  b memmove\n"
    "  .weak __aeabi_memset8\n  .hidden __aeabi_memset8\n  .type __aeabi_memset8, %function\n"
    "  .weak __aeabi_memset4\n  .hidden __aeabi_memset4\n  .type __aeabi_memset4, %function\n"
    "  .weak __aeabi_memset\n  .hidden __aeabi_memset\n  .type __aeabi_memset, %function\n"
    "__aeabi_memset8:\n"
    "__aeabi_memset4:\n"
    "__aeabi_memset:\n"
    "  mov r3, r1\n"
    "  mov r1, r2\n"
    "  mov r2, r3\n"
    "  b memset\n"
    "  .weak __aeabi_memclr8\n  .hidden __aeabi_memclr8\n  .type __aeabi_memclr8, %function\n"
    "  .weak __aeabi_memclr4\n  .hidden __aeabi_memclr4\n  .type __aeabi_memclr4, %function\n"
    "  .weak __aeabi_memclr\n  .hidden __aeabi_memclr\n  .type __aeabi_memclr, %function\n"
    "__aeabi_memclr8:\n"
    "__aeabi_memclr4:\n"
    "__aeabi_memclr:\n"
    "  mov r2, r1\n"
    "  mov r1, #0\n"
    "  b memset\n"
    "  .popsection\n");
#endif
