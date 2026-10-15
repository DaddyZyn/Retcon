#pragma once

#include <cstdint>
#include <array>
#include <vector>
#include <cstring>
#include <intrin.h>
#include <windows.h>
#include <retcon/types.hpp>
#include <retcon/unwind.hpp>
#include <retcon/gadget.hpp>

namespace retcon {

class stack_synthesizer {
public:
    struct synthetic_layout {
        alignas(16) std::array<uint8_t, 1024> buffer{};
        uint32_t total_size = 0;
        uint32_t gadget_frame_offset = 0;
        uint32_t worker_frame_offset = 0;
        uint32_t btit_frame_offset = 0;
        uint32_t ruts_frame_offset = 0;
    };

    // builds synthetic frame chain matching x64 seh specs:
    // [0x00] target ret -> gadget (jmp qword ptr [rbx])
    // Frame 3: gadget frame
    // Frame 2: worker frame (WaitForSingleObjectEx)
    // Frame 1: BaseThreadInitThunk + 0x14
    // Frame 0: RtlUserThreadStart + 0x21
    // Terminator: 0x0
    static bool synthesize(
        const gadget_info& gadget,
        uint64_t context_ptr,
        const uint8_t* stack_args,
        uint32_t stack_args_size,
        synthetic_layout& out_layout
    ) {
        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!k32 || !ntdll) return false;

        uint64_t btit_fn = reinterpret_cast<uint64_t>(GetProcAddress(k32, "BaseThreadInitThunk"));
        uint64_t ruts_fn = reinterpret_cast<uint64_t>(GetProcAddress(ntdll, "RtlUserThreadStart"));
        if (!btit_fn || !ruts_fn) return false;

        frame_info btit_frame{};
        frame_info ruts_frame{};
        if (!unwind_parser::decode_frame(btit_fn + 0x14, btit_frame)) return false;
        if (!unwind_parser::decode_frame(ruts_fn + 0x21, ruts_frame)) return false;

        // resolve a benign system worker frame (e.g. WaitForSingleObjectEx)
        HMODULE kbase = GetModuleHandleW(L"kernelbase.dll");
        uint64_t worker_fn = reinterpret_cast<uint64_t>(GetProcAddress(kbase ? kbase : k32, "WaitForSingleObjectEx"));
        frame_info worker_frame{};
        if (!worker_fn || !unwind_parser::decode_frame(worker_fn + 0x18, worker_frame)) {
            worker_frame.return_address = btit_fn + 0x14;
            worker_frame.total_stack_size = 0x28;
            worker_frame.saves_rbx = false;
        }

        // exact frame sizes from unwind_info - never round these, RtlVirtualUnwind doesn't
        uint32_t gadget_size = gadget.frame.total_stack_size;
        uint32_t worker_size = worker_frame.total_stack_size;
        uint32_t btit_size   = btit_frame.total_stack_size;
        uint32_t ruts_size   = ruts_frame.total_stack_size;

        // make sure stack args don't stomp saved rbx slot
        uint32_t max_arg_space = (gadget.frame.saves_rbx && gadget.frame.rbx_stack_offset > 0x20)
            ? (gadget.frame.rbx_stack_offset - 0x20)
            : (gadget_size - 0x20);
        if (stack_args_size > max_arg_space) return false;

        uint32_t total = 8 + gadget_size + 8 + worker_size + 8 + btit_size + 8 + ruts_size + 8;
        // align total to 16 so (original_rsp [16k+8] - total) % 16 == 8 at target entry
        total = (total + 15) & ~15;

        if (total > out_layout.buffer.size()) return false;

        // zero using rep stosb to avoid touching xmm registers
        __stosb(out_layout.buffer.data(), 0, total);
        uint8_t* p = out_layout.buffer.data();

        // 1. target ret -> gadget
        *reinterpret_cast<uint64_t*>(p) = gadget.address;

        // 2. stack args for target (offset 0x28 = after 32-byte shadow space)
        if (stack_args && stack_args_size > 0) {
            std::memcpy(p + 8 + 0x20, stack_args, stack_args_size);
        }

        // if gadget frame saves rbx, put context pointer in that slot so unwinding doesn't stomp it
        if (gadget.frame.saves_rbx && gadget.frame.rbx_stack_offset > 0) {
            uint32_t rbx_slot = 8 + gadget.frame.rbx_stack_offset;
            if (rbx_slot + 8 <= total) {
                *reinterpret_cast<uint64_t*>(p + rbx_slot) = context_ptr;
            }
        }

        // 3. worker frame ret
        uint32_t worker_ret_offset = 8 + gadget_size;
        *reinterpret_cast<uint64_t*>(p + worker_ret_offset) = worker_frame.return_address;

        if (worker_frame.saves_rbx && worker_frame.rbx_stack_offset > 0) {
            uint32_t rbx_slot = worker_ret_offset + 8 + worker_frame.rbx_stack_offset;
            if (rbx_slot + 8 <= total) {
                *reinterpret_cast<uint64_t*>(p + rbx_slot) = context_ptr;
            }
        }

        // 4. BaseThreadInitThunk ret
        uint32_t btit_ret_offset = worker_ret_offset + 8 + worker_size;
        *reinterpret_cast<uint64_t*>(p + btit_ret_offset) = btit_fn + 0x14;

        if (btit_frame.saves_rbx && btit_frame.rbx_stack_offset > 0) {
            uint32_t btit_rbx_slot = btit_ret_offset + 8 + btit_frame.rbx_stack_offset;
            if (btit_rbx_slot + 8 <= total) {
                *reinterpret_cast<uint64_t*>(p + btit_rbx_slot) = context_ptr;
            }
        }

        // 5. RtlUserThreadStart ret
        uint32_t ruts_ret_offset = btit_ret_offset + 8 + btit_size;
        *reinterpret_cast<uint64_t*>(p + ruts_ret_offset) = ruts_fn + 0x21;

        // 6. null terminator so RtlVirtualUnwind stops cleanly
        uint32_t null_term_offset = ruts_ret_offset + 8 + ruts_size;
        if (null_term_offset + 8 <= total) {
            *reinterpret_cast<uint64_t*>(p + null_term_offset) = 0ULL;
        }

        out_layout.total_size = total;
        return true;
    }
};

} // namespace retcon
