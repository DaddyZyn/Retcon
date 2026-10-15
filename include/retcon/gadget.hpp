#pragma once

#include <cstdint>
#include <vector>
#include <algorithm>
#include <windows.h>
#include <retcon/types.hpp>
#include <retcon/unwind.hpp>

namespace retcon {

class gadget_locator {
public:
    static void scan_module_gadgets(const wchar_t* module_name, std::vector<gadget_info>& out_pool) {
        HMODULE mod = GetModuleHandleW(module_name);
        if (!mod) {
            mod = LoadLibraryW(module_name);
            if (!mod) return;
        }

        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(mod);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
            reinterpret_cast<const uint8_t*>(mod) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return;

        const auto* sec = IMAGE_FIRST_SECTION(nt);
        const uint8_t* text_base = nullptr;
        uint32_t text_size = 0;

        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            if (memcmp(sec[i].Name, ".text", 5) == 0) {
                text_base = reinterpret_cast<const uint8_t*>(mod) + sec[i].VirtualAddress;
                text_size = sec[i].Misc.VirtualSize;
                break;
            }
        }

        if (!text_base || text_size < 2) return;

        // scan for FF 23 (jmp qword ptr [rbx])
        for (uint32_t i = 0; i < text_size - 1; ++i) {
            if (text_base[i] == 0xFF && text_base[i + 1] == 0x23) {
                uint64_t cand_addr = reinterpret_cast<uint64_t>(text_base + i);
                
                frame_info fi{};
                if (unwind_parser::decode_frame(cand_addr, fi)) {
                    // need at least 72 bytes to fit shadow space + 5 stack args
                    if (fi.total_stack_size >= 0x48) {
                        gadget_info gi{};
                        gi.address = cand_addr;
                        gi.module_handle = mod;
                        gi.frame = fi;
                        out_pool.push_back(gi);
                    }
                }
            }
        }
    }

    static const std::vector<gadget_info>& get_gadget_pool() {
        static std::vector<gadget_info> cached_pool;
        static bool initialized = false;

        if (!initialized) {
            scan_module_gadgets(L"kernelbase.dll", cached_pool);
            scan_module_gadgets(L"kernel32.dll", cached_pool);
            scan_module_gadgets(L"ntdll.dll", cached_pool);

            // prefer frames that don't save rbx first, then prefer frames <= 512 bytes
            // so they comfortably fit inside the 1024-byte synthetic layout
            std::stable_sort(cached_pool.begin(), cached_pool.end(), [](const gadget_info& a, const gadget_info& b) {
                if (a.frame.saves_rbx != b.frame.saves_rbx) {
                    return !a.frame.saves_rbx && b.frame.saves_rbx;
                }
                bool a_fits = (a.frame.total_stack_size <= 512);
                bool b_fits = (b.frame.total_stack_size <= 512);
                if (a_fits != b_fits) {
                    return a_fits;
                }
                return a.frame.total_stack_size > b.frame.total_stack_size;
            });

            initialized = true;
        }

        return cached_pool;
    }

    static const gadget_info& get_default_gadget() {
        static const gadget_info empty_gadget{};
        const auto& pool = get_gadget_pool();
        if (!pool.empty()) {
            return pool.front();
        }
        return empty_gadget;
    }
};

} // namespace retcon
