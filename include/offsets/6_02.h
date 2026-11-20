#ifndef OFFSETS_6_02_H
#define OFFSETS_6_02_H

// PS5 Firmware 6.02 kernel offsets for Byepervisor-Awake
// KERNEL_ADDRESS_TEXT_BASE = 0xFFFFFFFF80210000
//
// Status:
//   [CONFIRMED]  = verified from ps5-linux-loader off_0602 (exact match)
//   [VERIFIED]   = confirmed correct from decrypted ktext_602.bin dump
//   [FOUND]      = found by scanning ktext dump (unverified)
//   [POP_RBP]    = gadget has extra pop rbp before ret; chain builder adds dummy value
//
// [CONFIRMED] offsets from ps5-linux-loader off_0602
// [VERIFIED] offsets confirmed from ktext_redump4 (kernel base PA 0xCBD0000, Nov 2026)

uint64_t g_sym_map_0602[] = {
  0x3F445F4,  // KERNEL_SYM_DMPML4I                  [CONFIRMED]
  0x3F445F8,  // KERNEL_SYM_DMPDPI                   [CONFIRMED]
  0x3F443D0,  // KERNEL_SYM_PML4PML4I                [CONFIRMED]
  0x2AA9A8,   // KERNEL_SYM_SYS_GETUID               [CONFIRMED]
  0x2A0C38,   // KERNEL_SYM_PRINTF                   [CONFIRMED]
  0x4D72C0,   // KERNEL_SYM_ACPI_SLEEP_MACHDEP_HOOK  [CONFIRMED] unused by exploit
  0x852B02,   // KERNEL_SYM_HV_MP_STARTUP_CALL       [FOUND] call startup_mp in S3 resume path
  0x2A6160,   // KERNEL_SYM_MP_STARTUP_INIT_VECTOR    [FOUND] lea rsi,[rip+...] → this addr
  0x3F44358,  // KERNEL_SYM_PMAP_STORE               [CONFIRMED]
  0x47B0000,  // KERNEL_SYM_DATA_CAVE                [CONFIRMED]
  0x71BDDE0,  // KERNEL_SYM_IDT_ARRAY                [CONFIRMED]
  0x71C0A00,  // KERNEL_SYM_COMMON_TSS               [CONFIRMED]
  0x83028,    // HV_SYM_HEAP_BASE                     [UNUSED] break_hv uses direct VMCB addrs
  0x82A60,    // HV_SYM_PCPUS                         [UNUSED] break_hv uses direct VMCB addrs
};

uint64_t g_gadget_map_0602[] = {
  0x9A6AB4,   // KERNEL_GADGET_PIVOT_ADD_RSP28_RET    [CONFIRMED] add rsp,0x28; pop rbp; ret
  0x2447ED,   // KERNEL_GADGET_IRETQ                  [CONFIRMED] runtime-proven Phase 0
  0x1FEB50,   // KERNEL_GADGET_POP_RAX                [VERIFIED] pop rax; ret — ktext_redump4 (base 0xCBD0000)
  0x2D167C,   // KERNEL_GADGET_POP_RCX                [VERIFIED] pop rcx; ret — ktext_redump4
  0x1E1EF8,   // KERNEL_GADGET_POP_RDI                [CONFIRMED]
  0x1A2A30,   // KERNEL_GADGET_POP_RSI                [CONFIRMED]
  0x2B48DA,   // KERNEL_GADGET_POP_RDX                [CONFIRMED]
  0xADD14C,   // KERNEL_GADGET_POP_R8                 [VERIFIED] pop r8; pop rbp; ret     [POP_RBP]
  0x24A830,   // KERNEL_GADGET_POP_RSP                [CONFIRMED]
  0x283E31,   // KERNEL_GADGET_STORE_RCX_R8           [VERIFIED] mov [rcx],r8; pop rbp; ret  [POP_RBP]
  0x4289CA,   // KERNEL_GADGET_STORE_RDI8_RCX         [VERIFIED] mov [rdi+8],rcx; pop rbp; ret [POP_RBP]
  0x0,        // KERNEL_GADGET_OR_RCX_EAX             NOT FOUND - unused (oneshot=1 always)
  0x9C9546,   // KERNEL_GADGET_SET_DR7                [VERIFIED] mov dr7,rax; mov eax,r8d; pop rbp; ret [POP_RBP]
  0x3F3488,   // KERNEL_GADGET_ST_RCX_RDX             [VERIFIED] mov [rcx],rdx; pop rbp; ret [POP_RBP]
  0x35B4A4,   // KERNEL_GADGET_ST_RCX_RAX             [VERIFIED] mov [rcx],rax; xor eax,eax; pop rbp; ret [POP_RBP]
  0x46F7AE,   // KERNEL_GADGET_MOV_RAX_RSI            [VERIFIED] mov rax,rsi; pop rbp; ret [POP_RBP]
  0x24E2B1,   // KERNEL_GADGET_MOV_RAX_RDI            [VERIFIED] mov rax,rdi; ret (clean)
  0x2835EB,   // KERNEL_GADGET_REP_MOVSB              [VERIFIED] rep movsb; pop rbp; ret [POP_RBP] — ktext_redump4
  0x42B9B5,   // KERNEL_GADGET_CLD                    [VERIFIED] cld; ret (clean)
  0x92,       // KERNEL_GADGET_RET_TRAMP              [VERIFIED] ret — from decrypted ktext dump
  0x23DEF4,   // KERNEL_GADGET_DBREG_RESUME           [FOUND] resumectx tail: loads DR0-7 from [RDI+0x78..0xA0], GPRs from [RDI+0..0x38], ret
  0x4041FA,   // KERNEL_GADGET_MOV_RDI_RSI            [CONFIRMED] mov [rdi],rsi; pop rbp; ret [POP_RBP]
  0x1A6C10,   // KERNEL_GADGET_MOV_RAX_MEM_RAX       [FOUND] mov rax,[rax]; ret (clean)
  0x23D619,   // KERNEL_GADGET_ADD_RAX_RDX            [FOUND] add rax,rdx; ret (clean)
  0x91,       // KERNEL_GADGET_POP_RBP                [VERIFIED] pop rbp; ret — ktext_redump4
};

// === Additional confirmed offsets from ps5-linux-loader off_0602 ===
// These are NOT in the gadget/sym arrays above; use ktext(OFF) directly.
#define OFF_602_FUN_MEMCPY            0x2835B0   // [CONFIRMED]
#define OFF_602_FUN_STOP_CPUS         0xAC1390   // [CONFIRMED]
#define OFF_602_FUN_AS_LAPIC_EOI      0x241E60   // [CONFIRMED]
#define OFF_602_FUN_HV_UNMAP_PT_TMR   0xBC3690   // [CONFIRMED]
#define OFF_602_FUN_SMP_RENDEZVOUS    0xAC1970   // [CONFIRMED]
#define OFF_602_STOPPED_CPUS          0x7310DE0  // [CONFIRMED] data symbol
#define OFF_602_KERNEL_CFI_CHECK      0x4799B0   // [CONFIRMED]
#define OFF_602_HV_CODE_CAVE_PA       0x62806F00 // [CONFIRMED] physical address
#define OFF_602_HV_HANDLE_VMEXIT_PA   0x62841CE0 // [CONFIRMED] physical address

// === WRMSR gadget — found via GMET-off physical memory scan from Linux ===
// Kernel base PA = 0x1D7D0000, all 9 runtime-proven gadgets verified at this base.
#define OFF_602_GAD_WRMSR_RET         0x138C     // [VERIFIED] wrmsr; ret (clean) — ktext_redump4
#define OFF_602_GAD_WRMSR_POP_RBP     0x5829DC   // [VERIFIED-REAL] wrmsr; pop rbp; ret (backup)

// === POP-chain gadgets (PIVOT alternatives) from decrypted ktext_602.bin ===
// POP5: pops 5 regs (0x28 bytes) then ret — matches #UD frame (no error code)
// POP6: pops 6 regs (0x30 bytes) then ret — matches #GP frame (has error code)
// Key advantage over PIVOT: all pops read from CPU-pushed exception frame
// (guaranteed valid), not from pre-written data cave. Only ret reads chain data.
#define OFF_602_POP5_RBX_R15      0xD94     // [VERIFIED] pop rbx;pop r12;pop r13;pop r14;pop r15;ret
#define OFF_602_POP5_ALT          0x265B5A  // [VERIFIED] same bytes at alternate location
#define OFF_602_POP6_RBX_RBP      0x1A2CFC  // [VERIFIED] pop rbx;r12;r13;r14;r15;pop rbp;ret
#define OFF_602_GP_PIVOT          0x328CA9  // [VERIFIED] add rsp,0x30; pop rbp; ret (for #GP)

// === S3 resume DR0 support ===
#define OFF_602_SUSPPCBS_PTR      0x3A8F900  // [FOUND] kernel global: struct pcb **susppcbs
#define OFF_602_SAVECTX           0x23DCF0   // [FOUND] savectx function (saves regs to PCB)
#define OFF_602_SAVECTX_DR0_OFF   0x3F       // offset in savectx: mov rax,dr0; mov [rdi+0x78],rax (7 bytes)
#define OFF_602_SAVECTX_DR7_OFF   0x6E       // offset in savectx: mov rax,dr7; mov [rdi+0xa0],rax (10 bytes)

#endif // OFFSETS_6_02_H
