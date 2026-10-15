; retcon low-level x64 bridge
; rbx anchors context across the entire call cycle
.code

; uint64_t RetconDispatch(context* ctx)
; rcx = context pointer
RetconDispatch proc
    ; save caller non-volatiles into context
    mov [rcx + 78h], rbx
    mov [rcx + 80h], rbp
    mov [rcx + 88h], rdi
    mov [rcx + 90h], rsi
    mov [rcx + 98h], r12
    mov [rcx + 0A0h], r13
    mov [rcx + 0A8h], r14
    mov [rcx + 0B0h], r15

    ; ms x64 abi mandates xmm6-xmm15 are non-volatile
    movups xmmword ptr [rcx + 0C0h], xmm6
    movups xmmword ptr [rcx + 0D0h], xmm7
    movups xmmword ptr [rcx + 0E0h], xmm8
    movups xmmword ptr [rcx + 0F0h], xmm9
    movups xmmword ptr [rcx + 100h], xmm10
    movups xmmword ptr [rcx + 110h], xmm11
    movups xmmword ptr [rcx + 120h], xmm12
    movups xmmword ptr [rcx + 130h], xmm13
    movups xmmword ptr [rcx + 140h], xmm14
    movups xmmword ptr [rcx + 150h], xmm15

    ; [rcx] = cleanup stub address for gadget deref
    lea rax, [RetconCleanup]
    mov [rcx + 00h], rax

    ; save original rsp so cleanup can bounce back
    mov [rcx + 08h], rsp

    ; rbx holds context for the duration
    mov rbx, rcx

    ; carve synthetic stack frames on active thread stack
    mov eax, [rbx + 28h]       ; synthetic_size
    sub rsp, rax

    ; copy fabricated frames down to current rsp
    mov rsi, [rbx + 20h]       ; source
    mov rdi, rsp               ; dest
    mov ecx, eax               ; len
    cld
    rep movsb

    ; set up target register args
    mov rcx, [rbx + 38h]
    mov rdx, [rbx + 40h]
    mov r8,  [rbx + 48h]
    mov r9,  [rbx + 50h]

    movq xmm0, qword ptr [rbx + 58h]
    movq xmm1, qword ptr [rbx + 60h]
    movq xmm2, qword ptr [rbx + 68h]
    movq xmm3, qword ptr [rbx + 70h]

    ; [rsp] currently holds gadget address (written by stack synth)
    ; jump into target function
    mov rax, [rbx + 10h]
    jmp rax
RetconDispatch endp

; lands here after target executes ret -> enters gadget -> jmp qword ptr [rbx]
RetconCleanup proc
    ; preserve return values before touching anything
    mov [rbx + 10h], rax
    movq qword ptr [rbx + 18h], xmm0   ; raw 64-bit xmm0

    ; restore original thread rsp
    mov rsp, [rbx + 08h]

    ; restore xmm non-volatiles
    movups xmm6,  xmmword ptr [rbx + 0C0h]
    movups xmm7,  xmmword ptr [rbx + 0D0h]
    movups xmm8,  xmmword ptr [rbx + 0E0h]
    movups xmm9,  xmmword ptr [rbx + 0F0h]
    movups xmm10, xmmword ptr [rbx + 100h]
    movups xmm11, xmmword ptr [rbx + 110h]
    movups xmm12, xmmword ptr [rbx + 120h]
    movups xmm13, xmmword ptr [rbx + 130h]
    movups xmm14, xmmword ptr [rbx + 140h]
    movups xmm15, xmmword ptr [rbx + 150h]

    ; restore gpr non-volatiles
    mov r15, [rbx + 0B0h]
    mov r14, [rbx + 0A8h]
    mov r13, [rbx + 0A0h]
    mov r12, [rbx + 98h]
    mov rsi, [rbx + 90h]
    mov rdi, [rbx + 88h]
    mov rbp, [rbx + 80h]
    mov rbx, [rbx + 78h]       ; rbx restored last

    ; return to caller
    ret
RetconCleanup endp

; test helpers: set/get canaries in xmm6-xmm15
RetconSetXmmCanaries proc
    movups xmm6,  xmmword ptr [rcx + 00h]
    movups xmm7,  xmmword ptr [rcx + 10h]
    movups xmm8,  xmmword ptr [rcx + 20h]
    movups xmm9,  xmmword ptr [rcx + 30h]
    movups xmm10, xmmword ptr [rcx + 40h]
    movups xmm11, xmmword ptr [rcx + 50h]
    movups xmm12, xmmword ptr [rcx + 60h]
    movups xmm13, xmmword ptr [rcx + 70h]
    movups xmm14, xmmword ptr [rcx + 80h]
    movups xmm15, xmmword ptr [rcx + 90h]
    ret
RetconSetXmmCanaries endp

RetconGetXmmCanaries proc
    movups xmmword ptr [rcx + 00h], xmm6
    movups xmmword ptr [rcx + 10h], xmm7
    movups xmmword ptr [rcx + 20h], xmm8
    movups xmmword ptr [rcx + 30h], xmm9
    movups xmmword ptr [rcx + 40h], xmm10
    movups xmmword ptr [rcx + 50h], xmm11
    movups xmmword ptr [rcx + 60h], xmm12
    movups xmmword ptr [rcx + 70h], xmm13
    movups xmmword ptr [rcx + 80h], xmm14
    movups xmmword ptr [rcx + 90h], xmm15
    ret
RetconGetXmmCanaries endp

; clobber non-volatiles inside target to verify restoration
RetconClobberXmmNonVolatiles proc
    xorps xmm6, xmm6
    xorps xmm7, xmm7
    xorps xmm8, xmm8
    xorps xmm9, xmm9
    ret
RetconClobberXmmNonVolatiles endp

end
