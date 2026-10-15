#pragma once

#include <cstdint>
#include <windows.h>
#include <retcon/types.hpp>

namespace retcon {

enum unwind_op_codes : uint8_t {
    uwop_push_nonvol     = 0,
    uwop_alloc_large     = 1,
    uwop_alloc_small     = 2,
    uwop_set_fpreg       = 3,
    uwop_save_nonvol     = 4,
    uwop_save_nonvol_far = 5,
    uwop_epilog          = 6,
    uwop_spare_code      = 7,
    uwop_save_xmm128     = 8,
    uwop_save_xmm128_far = 9,
    uwop_push_machframe  = 10
};

enum unwind_reg_codes : uint8_t {
    reg_rax = 0,
    reg_rcx = 1,
    reg_rdx = 2,
    reg_rbx = 3,
    reg_rsp = 4,
    reg_rbp = 5,
    reg_rsi = 6,
    reg_rdi = 7,
    reg_r8  = 8,
    reg_r9  = 9,
    reg_r10 = 10,
    reg_r11 = 11,
    reg_r12 = 12,
    reg_r13 = 13,
    reg_r14 = 14,
    reg_r15 = 15
};

#pragma pack(push, 1)
union unwind_code {
    struct {
        uint8_t code_offset;
        uint8_t unwind_op : 4;
        uint8_t op_info   : 4;
    };
    uint16_t frame_offset;
};

struct unwind_info {
    uint8_t version : 3;
    uint8_t flags   : 5;
    uint8_t size_of_prolog;
    uint8_t count_of_codes;
    uint8_t frame_register : 4;
    uint8_t frame_offset   : 4;
    unwind_code codes[1];
};
#pragma pack(pop)

class unwind_parser {
public:
    static bool decode_frame(uint64_t rip, frame_info& out_info) {
        DWORD64 image_base = 0;
        PRUNTIME_FUNCTION rf = RtlLookupFunctionEntry(rip, &image_base, nullptr);
        if (!rf) {
            // leaf function - unwinder will just pop return address
            out_info.function_start = rip;
            out_info.return_address = rip;
            out_info.total_stack_size = 0;
            out_info.saves_rbx = false;
            out_info.rbx_stack_offset = 0;
            return false;
        }

        out_info.function_start = image_base + rf->BeginAddress;
        out_info.return_address = rip;
        out_info.total_stack_size = 0;
        out_info.saves_rbx = false;
        out_info.rbx_stack_offset = 0;

        uint64_t unwind_addr = image_base + rf->UnwindData;
        const auto* ui = reinterpret_cast<const unwind_info*>(unwind_addr);
        if (!ui) return false;

        // rip inside prolog: unwind codes aren't valid yet
        if ((rip - out_info.function_start) < ui->size_of_prolog) {
            return false;
        }

        return parse_unwind_info(unwind_addr, image_base, out_info);
    }

private:
    static bool parse_unwind_info(uint64_t unwind_addr, DWORD64 image_base, frame_info& out_info) {
        const auto* ui = reinterpret_cast<const unwind_info*>(unwind_addr);
        if (!ui) return false;

        // frame pointer (rbp) - rsp resets dynamically, skips linear math. reject.
        if (ui->frame_register != 0) {
            return false;
        }

        uint32_t stack_alloc = 0;
        uint32_t push_bytes = 0;
        bool found_rbx = false;
        uint32_t rbx_offset = 0;

        uint32_t i = 0;
        while (i < ui->count_of_codes) {
            const auto& code = ui->codes[i];
            uint8_t op = code.unwind_op;
            uint8_t info = code.op_info;

            switch (op) {
                case uwop_push_nonvol: {
                    push_bytes += 8;
                    if (info == reg_rbx) {
                        found_rbx = true;
                        // pushes happen before sub rsp in prolog
                        // when unwinding, RtlVirtualUnwind adds stack_alloc then pops
                        rbx_offset = push_bytes - 8;
                    }
                    i += 1;
                    break;
                }
                case uwop_alloc_large: {
                    if (info == 0) {
                        stack_alloc += ui->codes[i + 1].frame_offset * 8;
                        i += 2;
                    } else {
                        uint32_t sz = *reinterpret_cast<const uint32_t*>(&ui->codes[i + 1]);
                        stack_alloc += sz;
                        i += 3;
                    }
                    break;
                }
                case uwop_alloc_small: {
                    stack_alloc += (info * 8) + 8;
                    i += 1;
                    break;
                }
                case uwop_set_fpreg: {
                    // dynamic rsp, bail
                    return false;
                }
                case uwop_epilog: {
                    // v2 epilog indicator eats 2 slots
                    i += 2;
                    break;
                }
                case uwop_spare_code: {
                    // v2 spare code eats 3 slots
                    i += 3;
                    break;
                }
                case uwop_save_nonvol: {
                    uint32_t off = ui->codes[i + 1].frame_offset * 8;
                    if (info == reg_rbx) {
                        found_rbx = true;
                        rbx_offset = off;
                    }
                    i += 2;
                    break;
                }
                case uwop_save_nonvol_far: {
                    uint32_t off = *reinterpret_cast<const uint32_t*>(&ui->codes[i + 1]);
                    if (info == reg_rbx) {
                        found_rbx = true;
                        rbx_offset = off;
                    }
                    i += 3;
                    break;
                }
                case uwop_save_xmm128: {
                    i += 2;
                    break;
                }
                case uwop_save_xmm128_far: {
                    i += 3;
                    break;
                }
                case uwop_push_machframe: {
                    stack_alloc += (info == 0) ? 40 : 48;
                    i += 1;
                    break;
                }
                default: {
                    i += 1;
                    break;
                }
            }
        }

        out_info.total_stack_size = stack_alloc + push_bytes;
        out_info.saves_rbx = found_rbx;
        if (found_rbx) {
            out_info.rbx_stack_offset = stack_alloc + rbx_offset;
        }

        // chained unwind info
        if ((ui->flags & 0x4) /* UNW_FLAG_CHAININFO */) {
            uint32_t chained_index = (ui->count_of_codes + 1) & ~1;
            const auto* chained_rf = reinterpret_cast<const RUNTIME_FUNCTION*>(&ui->codes[chained_index]);
            if (chained_rf) {
                frame_info chained_info{};
                if (parse_unwind_info(image_base + chained_rf->UnwindData, image_base, chained_info)) {
                    out_info.total_stack_size += chained_info.total_stack_size;
                    if (!out_info.saves_rbx && chained_info.saves_rbx) {
                        out_info.saves_rbx = true;
                        out_info.rbx_stack_offset = chained_info.rbx_stack_offset;
                    }
                }
            }
        }

        return true;
    }
};

} // namespace retcon
