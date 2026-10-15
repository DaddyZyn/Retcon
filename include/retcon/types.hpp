#pragma once

#include <cstdint>
#include <cstddef>
#include <windows.h>

namespace retcon {

#pragma pack(push, 16)
// context block passed to RetconDispatch
// rbx anchors this whole struct during target execution.
// target ret -> gadget jmp qword ptr [rbx] -> derefs cleanup_handler at offset 0
struct alignas(16) context {
    uint64_t cleanup_handler;    // 0x00: target of jmp qword ptr [rbx]
    uint64_t original_rsp;       // 0x08: caller rsp to restore
    uint64_t target_fn;          // 0x10: function we're calling
    uint64_t gadget_addr;        // 0x18: return address placed at [rsp]
    uint64_t synthetic_stack;    // 0x20: synthetic stack buffer
    uint32_t synthetic_size;     // 0x28: byte size of fabricated stack
    uint32_t stack_args_size;    // 0x2C: byte size of stack args (5+)
    uint64_t stack_args_ptr;     // 0x30: packed stack args
    uint64_t arg_rcx;            // 0x38: reg arg 1
    uint64_t arg_rdx;            // 0x40: reg arg 2
    uint64_t arg_r8;             // 0x48: reg arg 3
    uint64_t arg_r9;             // 0x50: reg arg 4
    uint64_t arg_xmm0;           // 0x58: sse arg 1
    uint64_t arg_xmm1;           // 0x60: sse arg 2
    uint64_t arg_xmm2;           // 0x68: sse arg 3
    uint64_t arg_xmm3;           // 0x70: sse arg 4
    
    // non-volatiles restored in cleanup stub
    uint64_t saved_rbx;          // 0x78
    uint64_t saved_rbp;          // 0x80
    uint64_t saved_rdi;          // 0x88
    uint64_t saved_rsi;          // 0x90
    uint64_t saved_r12;          // 0x98
    uint64_t saved_r13;          // 0xA0
    uint64_t saved_r14;          // 0xA8
    uint64_t saved_r15;          // 0xB0
    uint64_t reserved_pad;       // 0xB8: pad to 16-byte align saved_xmm

    // ms x64 abi: xmm6-xmm15 are non-volatile
    alignas(16) uint8_t saved_xmm[10][16]; // 0xC0 .. 0x15F
};
#pragma pack(pop)

// offsets hardcoded in retcon_asm.asm - verify on compile
static_assert(offsetof(context, cleanup_handler) == 0x00, "bad cleanup_handler offset");
static_assert(offsetof(context, original_rsp)    == 0x08, "bad original_rsp offset");
static_assert(offsetof(context, target_fn)       == 0x10, "bad target_fn offset");
static_assert(offsetof(context, gadget_addr)     == 0x18, "bad gadget_addr offset");
static_assert(offsetof(context, synthetic_stack) == 0x20, "bad synthetic_stack offset");
static_assert(offsetof(context, synthetic_size)  == 0x28, "bad synthetic_size offset");
static_assert(offsetof(context, stack_args_size) == 0x2C, "bad stack_args_size offset");
static_assert(offsetof(context, stack_args_ptr)  == 0x30, "bad stack_args_ptr offset");
static_assert(offsetof(context, arg_rcx)         == 0x38, "bad arg_rcx offset");
static_assert(offsetof(context, arg_rdx)         == 0x40, "bad arg_rdx offset");
static_assert(offsetof(context, arg_r8)          == 0x48, "bad arg_r8 offset");
static_assert(offsetof(context, arg_r9)          == 0x50, "bad arg_r9 offset");
static_assert(offsetof(context, arg_xmm0)        == 0x58, "bad arg_xmm0 offset");
static_assert(offsetof(context, saved_rbx)       == 0x78, "bad saved_rbx offset");
static_assert(offsetof(context, saved_xmm)       == 0xC0, "bad saved_xmm offset");

// decoded frame info from .pdata
struct frame_info {
    uint64_t function_start;
    uint64_t return_address;
    uint32_t total_stack_size;
    uint32_t rbx_stack_offset;   // 0 if rbx wasn't saved in this frame
    bool     saves_rbx;
};

// verified signed gadget
struct gadget_info {
    uint64_t address;            // address of the FF 23 instruction
    HMODULE  module_handle;
    frame_info frame;
};

} // namespace retcon
