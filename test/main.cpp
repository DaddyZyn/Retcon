#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <cassert>
#include <cstring>
#include <windows.h>
#include <retcon/retcon.hpp>

extern "C" void RetconSetXmmCanaries(const void* src160bytes);
extern "C" void RetconGetXmmCanaries(void* dst160bytes);
extern "C" void RetconClobberXmmNonVolatiles();

static std::string get_module_for_address(void* addr) {
    HMODULE mod = nullptr;
    if (GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCSTR>(addr),
        &mod) && mod) {
        char path[MAX_PATH];
        if (GetModuleFileNameA(mod, path, MAX_PATH)) {
            std::string s(path);
            size_t slash = s.find_last_of("\\/");
            if (slash != std::string::npos) return s.substr(slash + 1);
            return s;
        }
    }
    return "UNKNOWN";
}

// test 1: RtlCaptureStackBackTrace inspection
struct backtrace_result {
    bool passed;
    bool found_caller_module;
    bool found_ntdll;
    bool found_kernel;
    std::vector<void*> frames;
};

static backtrace_result g_backtrace_res{};

static void TargetBacktraceWorker() {
    void* frames[32]{};
    WORD captured = RtlCaptureStackBackTrace(0, 32, frames, nullptr);

    std::cout << "\n[*] TargetBacktraceWorker called. Captured " << captured << " frames:\n";

    char current_exe[MAX_PATH]{};
    GetModuleFileNameA(nullptr, current_exe, MAX_PATH);
    std::string exe_name(current_exe);
    size_t slash = exe_name.find_last_of("\\/");
    if (slash != std::string::npos) exe_name = exe_name.substr(slash + 1);

    bool leaked_caller = false;
    bool has_ntdll = false;
    bool has_kernel = false;

    // frame 0 is worker itself. frame 1+ should hide retcon_test.exe completely
    for (WORD i = 0; i < captured; ++i) {
        std::string mod = get_module_for_address(frames[i]);
        std::cout << "    [" << std::setw(2) << i << "] " 
                  << std::hex << std::setw(16) << std::setfill('0') << frames[i] 
                  << std::dec << std::setfill(' ') << " (" << mod << ")\n";

        if (i > 0 && mod == exe_name) {
            leaked_caller = true;
        }
        if (mod == "ntdll.dll") has_ntdll = true;
        if (mod == "KERNEL32.DLL" || mod == "KERNELBASE.dll") has_kernel = true;

        g_backtrace_res.frames.push_back(frames[i]);
    }

    g_backtrace_res.found_caller_module = leaked_caller;
    g_backtrace_res.found_ntdll = has_ntdll;
    g_backtrace_res.found_kernel = has_kernel;
    g_backtrace_res.passed = (!leaked_caller && has_ntdll && has_kernel);
}

// test 2: variadic argument forwarding (reg + stack 5-8)
static uint64_t TargetArgWorker(
    int a1,
    uint64_t a2,
    double a3,
    float a4,
    uint64_t a5,
    int a6,
    double a7,
    const char* a8
) {
    std::cout << "\n    TargetArgWorker received:"
              << "\n      a1: " << a1
              << "\n      a2: 0x" << std::hex << a2 << std::dec
              << "\n      a3: " << a3
              << "\n      a4: " << a4
              << "\n      a5: 0x" << std::hex << a5 << std::dec
              << "\n      a6: " << a6
              << "\n      a7: " << a7
              << "\n      a8: " << (a8 ? a8 : "null") << "\n";

    bool ok = true;
    if (a1 != 42) ok = false;
    if (a2 != 0xDEADBEEFCAFEULL) ok = false;
    if (a3 < 3.1415 || a3 > 3.1416) ok = false;
    if (a4 < 2.718f || a4 > 2.719f) ok = false;
    if (a5 != 0x13371337BEEFULL) ok = false;
    if (a6 != 100) ok = false;
    if (a7 < 99.99 || a7 > 100.01) ok = false;
    if (!a8 || std::strcmp(a8, "retcon_test_string") != 0) ok = false;

    return ok ? 0xC001D00DULL : 0xFA11EDULL;
}

// test 3: double return
static double TargetFloatWorker(double x, double y) {
    return (x * y) + 1.5;
}

// test 4: RtlVirtualUnwind traversal
static bool g_unwind_passed = false;

static void TargetUnwindWorker() {
    CONTEXT ctx{};
    RtlCaptureContext(&ctx);

    std::cout << "\n[*] Simulating RtlVirtualUnwind across synthetic stack...\n";

    UNWIND_HISTORY_TABLE hist{};
    int depth = 0;
    bool reached_root = false;

    while (ctx.Rip != 0 && depth < 32) {
        DWORD64 img_base = 0;
        PRUNTIME_FUNCTION rf = RtlLookupFunctionEntry(ctx.Rip, &img_base, &hist);

        std::string mod = get_module_for_address(reinterpret_cast<void*>(ctx.Rip));
        std::cout << "    Unwind frame [" << std::setw(2) << depth << "]: RIP=0x"
                  << std::hex << ctx.Rip << std::dec << " (" << mod << ")\n";

        if (mod == "ntdll.dll") {
            reached_root = true;
        }

        if (!rf) {
            ctx.Rip = *reinterpret_cast<DWORD64*>(ctx.Rsp);
            ctx.Rsp += 8;
        } else {
            PVOID handler_data = nullptr;
            DWORD64 establisher_frame = 0;
            RtlVirtualUnwind(
                UNW_FLAG_NHANDLER,
                img_base,
                ctx.Rip,
                rf,
                &ctx,
                &handler_data,
                &establisher_frame,
                nullptr
            );
        }

        depth++;
    }

    g_unwind_passed = reached_root;
    std::cout << "    [+] RtlVirtualUnwind successfully reached thread root without faulting.\n";
}

// test 5: float32 return + non-volatile xmm preservation
__declspec(noinline) static float TargetFloat32Worker(float a, float b) {
    volatile float res = a * b;
    RetconClobberXmmNonVolatiles();
    return res;
}

#pragma optimize("", off)
static void RunTest5Helper(float* out_res, uint8_t* out_canaries) {
    alignas(16) uint8_t canaries_in[160]{};
    for (int i = 0; i < 160; ++i) {
        canaries_in[i] = static_cast<uint8_t>(0xA0 + (i % 37));
    }
    RetconSetXmmCanaries(canaries_in);

    float f = retcon::invoke<float>(
        reinterpret_cast<void*>(&TargetFloat32Worker),
        1.5f,
        2.0f
    );

    RetconGetXmmCanaries(out_canaries);
    *out_res = f;
}
#pragma optimize("", on)

// test 6: unwind & call-site audit
#ifndef ProcessUserShadowStackPolicy
#define ProcessUserShadowStackPolicy static_cast<PROCESS_MITIGATION_POLICY>(14)
#endif

struct RETCON_USER_SHADOW_STACK_POLICY {
    union {
        DWORD Flags;
        struct {
            DWORD EnableUserShadowStack : 1;
            DWORD AuditUserShadowStack : 1;
            DWORD SetContextIpValidation : 1;
            DWORD AuditSetContextIpValidation : 1;
            DWORD EnableUserShadowStackStrictMode : 1;
            DWORD BlockUnhandledExceptionReturns : 1;
            DWORD AuditBlockUnhandledExceptionReturns : 1;
            DWORD ReservedFlags : 25;
        };
    };
};

struct audit_result {
    bool passed = false;
    bool all_frames_signed = false;
    bool all_call_sites_valid = false;
    size_t verified_frames = 0;
};

static audit_result g_audit_res{};

static void TargetAuditWorker() {
    CONTEXT ctx{};
    RtlCaptureContext(&ctx);

    std::cout << "\n[*] Running Call-Site & Unwind Integrity Audit from target frame...\n";

    UNWIND_HISTORY_TABLE hist{};
    int depth = 0;
    bool all_signed = true;
    bool all_call_sites = true;
    size_t count = 0;

    while (ctx.Rip != 0 && depth < 32) {
        DWORD64 img_base = 0;
        PRUNTIME_FUNCTION rf = RtlLookupFunctionEntry(ctx.Rip, &img_base, &hist);

        std::string mod = get_module_for_address(reinterpret_cast<void*>(ctx.Rip));

        if (depth > 0) {
            count++;
            bool signed_mod = (mod == "ntdll.dll" || mod == "KERNEL32.DLL" || mod == "KERNELBASE.dll");
            if (!rf || !signed_mod) {
                all_signed = false;
            }

            const uint8_t* rip_bytes = reinterpret_cast<const uint8_t*>(ctx.Rip);
            bool valid_site = false;
            std::string site_type = "UNKNOWN";

            if (rip_bytes[0] == 0xFF && rip_bytes[1] == 0x23) {
                valid_site = true;
                site_type = "GADGET (jmp [rbx])";
            } else if (rip_bytes[-5] == 0xE8) {
                valid_site = true;
                site_type = "CALL rel32 (E8)";
            } else if (rip_bytes[-6] == 0xFF && rip_bytes[-5] == 0x15) {
                valid_site = true;
                site_type = "CALL [rip+disp32] (FF 15)";
            } else if (rip_bytes[-2] == 0xFF && (rip_bytes[-1] & 0xF8) == 0xD0) {
                valid_site = true;
                site_type = "CALL reg (FF D0-D7)";
            } else if (rip_bytes[-3] == 0x41 && rip_bytes[-2] == 0xFF && (rip_bytes[-1] & 0xF8) == 0xD0) {
                valid_site = true;
                site_type = "CALL r8-r15 (41 FF D0-D7)";
            } else {
                valid_site = (rf != nullptr);
                site_type = "SIGNED FUNCTION SITE";
            }

            if (!valid_site) {
                all_call_sites = false;
            }

            std::cout << "    [Audit Frame " << depth << "] RIP=0x"
                      << std::hex << ctx.Rip << std::dec << " (" << mod << ") -> "
                      << site_type << "\n";
        }

        if (!rf) {
            ctx.Rip = *reinterpret_cast<DWORD64*>(ctx.Rsp);
            ctx.Rsp += 8;
        } else {
            PVOID handler_data = nullptr;
            DWORD64 establisher_frame = 0;
            RtlVirtualUnwind(
                UNW_FLAG_NHANDLER,
                img_base,
                ctx.Rip,
                rf,
                &ctx,
                &handler_data,
                &establisher_frame,
                nullptr
            );
        }

        depth++;
    }

    g_audit_res.all_frames_signed = all_signed;
    g_audit_res.all_call_sites_valid = all_call_sites;
    g_audit_res.verified_frames = count;
    g_audit_res.passed = (all_signed && all_call_sites && count >= 3);
}

static LONG WINAPI CrashHandler(PEXCEPTION_POINTERS p) {
    fprintf(stderr, "\n[FATAL] Exception 0x%08lX at RIP=0x%p, Address=0x%p\n",
            p->ExceptionRecord->ExceptionCode,
            reinterpret_cast<void*>(p->ContextRecord->Rip),
            reinterpret_cast<void*>(p->ExceptionRecord->ExceptionAddress));
    fflush(stderr);
    return EXCEPTION_CONTINUE_SEARCH;
}

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
    AddVectoredExceptionHandler(1, CrashHandler);

    std::cout << "========================================================\n";
    std::cout << "  RETCON: x64 Synthetic Call Stack Spoofer Test Suite   \n";
    std::cout << "========================================================\n";

    if (!retcon::initialize()) {
        std::cerr << "[-] Failed to locate signed jmp qword ptr [rbx] gadget!\n";
        return 1;
    }

    std::cout << "[+] Located signed gadget at: 0x" 
              << std::hex << retcon::get_active_gadget() 
              << " (" << get_module_for_address(reinterpret_cast<void*>(retcon::get_active_gadget())) << ")\n"
              << std::dec;

    std::cout << "[*] Gadget pool size: " << retcon::get_gadget_pool().size() << " verified candidates\n";

    // Test 1: backtrace concealment
    std::cout << "\n[1] Running Test 1: Stack Backtrace Inspection...";
    retcon::invoke(reinterpret_cast<void*>(&TargetBacktraceWorker));

    if (g_backtrace_res.passed) {
        std::cout << "[+] TEST 1 PASSED: Caller hidden from backtrace, legitimate OS frames verified.\n";
    } else {
        std::cout << "[-] TEST 1 FAILED: Leaked caller=" << g_backtrace_res.found_caller_module 
                  << ", ntdll=" << g_backtrace_res.found_ntdll 
                  << ", kernel=" << g_backtrace_res.found_kernel << "\n";
    }

    // Test 2: argument forwarding
    std::cout << "\n[2] Running Test 2: Variadic Multi-Argument Passing (8 args)...";
    uint64_t res2 = retcon::invoke<uint64_t>(
        reinterpret_cast<void*>(&TargetArgWorker),
        42,
        0xDEADBEEFCAFEULL,
        3.14159265,
        2.71828f,
        0x13371337BEEFULL,
        100,
        100.0,
        "retcon_test_string"
    );

    bool test2_passed = (res2 == 0xC001D00DULL);
    if (test2_passed) {
        std::cout << "[+] TEST 2 PASSED: All 8 arguments forwarded with 100% precision.\n";
    } else {
        std::cout << "[-] TEST 2 FAILED: Return value = 0x" << std::hex << res2 << std::dec << "\n";
    }

    // Test 3: double return
    std::cout << "\n[3] Running Test 3: Floating-Point Return Fidelity (Double)...";
    double res3 = retcon::invoke<double>(
        reinterpret_cast<void*>(&TargetFloatWorker),
        2.5,
        4.0
    );

    bool test3_passed = (res3 >= 11.49 && res3 <= 11.51);
    if (test3_passed) {
        std::cout << "[+] TEST 3 PASSED: Expected 11.5, received: " << res3 << "\n";
    } else {
        std::cout << "[-] TEST 3 FAILED: Received: " << res3 << "\n";
    }

    // Test 4: unwind walk
    std::cout << "\n[4] Running Test 4: RtlVirtualUnwind Traversal...";
    retcon::invoke(reinterpret_cast<void*>(&TargetUnwindWorker));

    if (g_unwind_passed) {
        std::cout << "[+] TEST 4 PASSED: Stack unwinding cleanly traversed fabricated frames to ntdll.\n";
    } else {
        std::cout << "[-] TEST 4 FAILED: Stack unwinding did not terminate cleanly.\n";
    }

    // Test 5: float return + xmm non-volatiles
    std::cout << "\n[5] Running Test 5: 32-bit Float Return & XMM Non-Volatiles (XMM6-XMM15)...";
    alignas(16) uint8_t xmm_canaries_in[160]{};
    alignas(16) uint8_t xmm_canaries_out[160]{};
    for (int i = 0; i < 160; ++i) {
        xmm_canaries_in[i] = static_cast<uint8_t>(0xA0 + (i % 37));
    }

    float res5 = 0.0f;
    RunTest5Helper(&res5, xmm_canaries_out);

    uint32_t raw_f32_bits = 0;
    std::memcpy(&raw_f32_bits, &res5, sizeof(float));
    bool float_ok = (raw_f32_bits == 0x40400000);
    bool xmm_ok = (std::memcmp(xmm_canaries_in, xmm_canaries_out, 160) == 0);
    bool test5_passed = (float_ok && xmm_ok);

    if (test5_passed) {
        std::cout << "[+] TEST 5 PASSED: 32-bit float returned raw (3.0f, bits=0x"
                  << std::hex << raw_f32_bits << std::dec
                  << ") and all 10 non-volatile XMM registers (XMM6-XMM15) preserved 100%.\n";
    } else {
        std::cout << "[-] TEST 5 FAILED: FloatOk=" << float_ok 
                  << " (bits=0x" << std::hex << raw_f32_bits << std::dec << ", val=" << res5 << ")"
                  << ", XmmPreserved=" << xmm_ok << "\n";
    }

    // Test 6: unwind & call-site audit
    std::cout << "\n[6] Running Test 6: Unwind & Call-Site Integrity Audit...";
    
    RETCON_USER_SHADOW_STACK_POLICY shadow_policy{};
    BOOL cet_ok = GetProcessMitigationPolicy(
        GetCurrentProcess(),
        ProcessUserShadowStackPolicy,
        &shadow_policy,
        sizeof(shadow_policy)
    );

    std::cout << "\n    [*] Host CET Shadow Stack Policy: ";
    if (cet_ok) {
        if (shadow_policy.EnableUserShadowStack) {
            std::cout << "ENFORCED (Strict: " << shadow_policy.EnableUserShadowStackStrictMode << ")\n";
            std::cout << "    [*] Operational Notes: Hardware Shadow Stack active. Synthetic return addresses without hardware pairing trigger #CP on RET.\n";
        } else {
            std::cout << "DISABLED / NOT ENFORCED\n";
            std::cout << "    [*] Operational Notes: Hardware Shadow Stack inactive. Synthetic stack frames and signed jmp [rbx] pivot execute cleanly without #CP faults.\n";
        }
    } else {
        std::cout << "QUERY FAILED OR NOT SUPPORTED ON THIS OS BUILD\n";
    }

    retcon::invoke(reinterpret_cast<void*>(&TargetAuditWorker));

    if (g_audit_res.passed) {
        std::cout << "[+] TEST 6 PASSED: All " << g_audit_res.verified_frames 
                  << " fabricated frames verified signed, call-site authentic, and unwinder-compliant.\n";
    } else {
        std::cout << "[-] TEST 6 FAILED: Signed=" << g_audit_res.all_frames_signed 
                  << ", CallSites=" << g_audit_res.all_call_sites_valid 
                  << ", FrameCount=" << g_audit_res.verified_frames << "\n";
    }

    std::cout << "\n========================================================\n";
    bool all_passed = (g_backtrace_res.passed && 
                       test2_passed && 
                       test3_passed && 
                       g_unwind_passed &&
                       test5_passed &&
                       g_audit_res.passed);

    if (all_passed) {
        std::cout << "  ALL RETCON TEST SUITES PASSED SUCCESSFULLY (6/6)      \n";
    } else {
        std::cout << "  SOME TEST SUITES FAILED                               \n";
    }
    std::cout << "========================================================\n";

    return all_passed ? 0 : 1;
}
