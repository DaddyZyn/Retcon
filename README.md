# retcon

Freestanding x64 synthetic call stack fabricator and return address spoofer for Windows.  
Carves legitimate non-leaf stack frames in signed system modules conforming to `.pdata` / `UNWIND_INFO` specs before executing target functions.

When hooking or detouring internal game / system functions, naive return address spoofers get cooked by kernel stack backtrace collectors (`RtlCaptureStackBackTrace`, ETW-TI, and `RtlVirtualUnwind` walkers) because the synthetic return address isn't backed by valid `.pdata` unwinding codes.

`retcon` synthesizes an authentic thread call chain through signed modules (`ntdll.dll`, `kernel32.dll`, `kernelbase.dll`) that cleanly unwinds down to `ntdll!RtlUserThreadStart` with zero dynamic allocations on the invoke path.

## features

- re-entrant `FF 23` (`jmp qword ptr [rbx]`) gadget routing with zero global state
- exact `.pdata` / `UNWIND_INFO` frame metric sizing (reconstructs saved `RBX` stack offsets)
- zero per-call heap allocations (stack-allocated synthetic frame layout)
- full x64 ABI non-volatile preservation (`RBX`, `RBP`, `RDI`, `RSI`, `R12`-`R15`, and `XMM6`-`XMM15`)
- bit-exact 32-bit `float` and 64-bit `double` raw return value capture
- variadic argument forwarding (GPRs, SSE floats, and stack arguments 5+)
- dynamic stack alignment maintaining `(RSP % 16) == 8` at target entry
- automated 6-part test harness with unwinder and CET Shadow Stack audit

## build

Requires MSVC 2022 (x64) and CMake 3.20+:

```cmd
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
.\build\Release\retcon_test.exe
```

## usage

### basic call

```cpp
#include <retcon/retcon.hpp>

// optional: pre-warm gadget pool (auto-initializes on first call if omitted)
retcon::initialize();

// spoof return address and synthetic call stack
auto result = retcon::invoke<int>((void*)&SomeEngineFunction, 100, 200);
```

### variadic args (registers + stack args 5+)

```cpp
// forwards first 4 args in RCX/RDX/R8/R9 (or XMM0-XMM3), args 5+ placed on synthetic stack
uint64_t res = retcon::invoke<uint64_t>(
    (void*)&TargetFunction,
    42,                             // arg 1: RCX
    (void*)0xDEADBEEFCAFE,          // arg 2: RDX
    3.14159,                        // arg 3: XMM2 (double)
    2.71828f,                       // arg 4: XMM3 (float)
    0x13371337BEEFULL,              // arg 5: [RSP + 0x28]
    100,                            // arg 6: [RSP + 0x30]
    99.99,                          // arg 7: [RSP + 0x38]
    "retcon_payload"                // arg 8: [RSP + 0x40]
);
```

## stack frame topology

Memory layout from lowest memory (`RSP` at target entry) to highest:

```text
[ Low Memory / Current RSP ]
  ├── Target Function Entry Return Address (points into Gadget)
  ├── Frame 3: Gadget Frame (matching gadget's UNWIND_INFO)
  ├── Frame 2: System Worker Frame (WaitForSingleObjectEx in kernelbase.dll)
  ├── Frame 1: kernel32!BaseThreadInitThunk + 0x14 Frame
  ├── Frame 0: ntdll!RtlUserThreadStart + 0x21 Frame (Thread Root)
  └── 0x0000000000000000 (Null return address terminator so RtlVirtualUnwind stops cleanly)
[ High Memory / Saved Context & Caller Stack ]
```

## gadget mechanics (FF 23 vs FF E3)

Public stack spoofers often use `jmp rbx` (`FF E3`), setting `RBX` to their cleanup stub. When the target executes `ret`, `RBX` is holding the instruction pointer, so the stub can't locate the saved context or original `RSP` without thread-unsafe globals.

`retcon` scans for `jmp qword ptr [rbx]` (`FF 23`) in signed modules:
1. `RBX` points to the `retcon::context` struct throughout execution.
2. `[rbx + 0x00]` holds the cleanup stub address (`RetconCleanup`).
3. `[rbx + 0x08]` holds `original_rsp`.
4. Target returns via `ret` -> enters gadget -> executes `jmp qword ptr [rbx]`.
5. Lands in `RetconCleanup` with `RBX` still pointing directly to `context`.
6. `RetconCleanup` restores `RSP = [rbx + 0x08]`, pops non-volatiles, and returns cleanly.

## verification

Output from `retcon_test.exe`:

```text
========================================================
  RETCON: x64 Synthetic Call Stack Spoofer Test Suite   
========================================================
[+] Located signed gadget at: 0x7ffbf273ba3a (KERNELBASE.dll)
[*] Gadget pool size: 25 verified candidates

[1] Running Test 1: Stack Backtrace Inspection...
[*] TargetBacktraceWorker called. Captured 5 frames:
    [ 0] 00007FF6EAD33AD5 (retcon_test.exe)
    [ 1] 00007FFBF273BA3A (KERNELBASE.dll)
    [ 2] 00007FFBF25FC088 (KERNELBASE.dll)
    [ 3] 00007FFBF33DCCB4 (KERNEL32.DLL)
    [ 4] 00007FFBF4D6AD61 (ntdll.dll)
[+] TEST 1 PASSED: Caller hidden from backtrace, legitimate OS frames verified.

[2] Running Test 2: Variadic Multi-Argument Passing (8 args)...
    TargetArgWorker received:
      a1: 42
      a2: 0xdeadbeefcafe
      a3: 3.14159
      a4: 2.71828
      a5: 0x13371337beef
      a6: 100
      a7: 100
      a8: retcon_test_string
[+] TEST 2 PASSED: All 8 arguments forwarded with 100% precision.

[3] Running Test 3: Floating-Point Return Fidelity (Double)...[+] TEST 3 PASSED: Expected 11.5, received: 11.5

[4] Running Test 4: RtlVirtualUnwind Traversal...
[*] Simulating RtlVirtualUnwind across synthetic stack...
    Unwind frame [ 0]: RIP=0x7ff6ead34255 (retcon_test.exe)
    Unwind frame [ 1]: RIP=0x7ffbf273ba3a (KERNELBASE.dll)
    Unwind frame [ 2]: RIP=0x7ffbf25fc088 (KERNELBASE.dll)
    Unwind frame [ 3]: RIP=0x7ffbf33dccb4 (KERNEL32.DLL)
    Unwind frame [ 4]: RIP=0x7ffbf4d6ad61 (ntdll.dll)
    [+] RtlVirtualUnwind successfully reached thread root without faulting.
[+] TEST 4 PASSED: Stack unwinding cleanly traversed fabricated frames to ntdll.

[5] Running Test 5: 32-bit Float Return & XMM Non-Volatiles (XMM6-XMM15)...[+] TEST 5 PASSED: 32-bit float returned raw (3.0f, bits=0x40400000) and all 10 non-volatile XMM registers (XMM6-XMM15) preserved 100%.

[6] Running Test 6: Unwind & Call-Site Integrity Audit...
    [*] Host CET Shadow Stack Policy: DISABLED / NOT ENFORCED
    [*] Operational Notes: Hardware Shadow Stack inactive. Synthetic stack frames and signed jmp [rbx] pivot execute cleanly without #CP faults.

[*] Running Call-Site & Unwind Integrity Audit from target frame...
    [Audit Frame 1] RIP=0x7ffbf273ba3a (KERNELBASE.dll) -> GADGET (jmp [rbx])
    [Audit Frame 2] RIP=0x7ffbf25fc088 (KERNELBASE.dll) -> SIGNED FUNCTION SITE
    [Audit Frame 3] RIP=0x7ffbf33dccb4 (KERNEL32.DLL) -> SIGNED FUNCTION SITE
    [Audit Frame 4] RIP=0x7ffbf4d6ad61 (ntdll.dll) -> SIGNED FUNCTION SITE
[+] TEST 6 PASSED: All 4 fabricated frames verified signed, call-site authentic, and unwinder-compliant.

========================================================
  ALL RETCON TEST SUITES PASSED SUCCESSFULLY (6/6)      
========================================================
```

## license

MIT
