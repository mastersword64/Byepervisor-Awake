#ifndef OFFSETS_5_02_H
#define OFFSETS_5_02_H

// PS5 Firmware 5.02 kernel offsets for Byepervisor Awake
// KERNEL_ADDRESS_TEXT_BASE = 0xFFFFFFFF80210000
//
// Gadgets/IDT/TSS/HC13 from ps5-linux-loader off_0502
// TODO offsets need ktext dump to find

uint64_t g_sym_map_0502[] = {
  0x0,        // KERNEL_SYM_DMPML4I                  TODO
  0x0,        // KERNEL_SYM_DMPDPI                   TODO
  0x0,        // KERNEL_SYM_PML4PML4I                TODO
  0x0,        // KERNEL_SYM_SYS_GETUID               TODO
  0x2AA140,   // KERNEL_SYM_PRINTF                   [ps5-linux-loader]
  0x0,        // KERNEL_SYM_ACPI_SLEEP_MACHDEP_HOOK  unused
  0x0,        // KERNEL_SYM_HV_MP_STARTUP_CALL       TODO
  0x0,        // KERNEL_SYM_MP_STARTUP_INIT_VECTOR   TODO
  0x0,        // KERNEL_SYM_PMAP_STORE               TODO
  0x0,        // KERNEL_SYM_DATA_CAVE                TODO
  0x724DCA0,  // KERNEL_SYM_IDT_ARRAY                [ps5-linux-loader]
  0x7250850,  // KERNEL_SYM_COMMON_TSS               [ps5-linux-loader]
  0x0,        // HV_SYM_HEAP_BASE                     unused
  0x0,        // HV_SYM_PCPUS                         unused
};

uint64_t g_gadget_map_0502[] = {
  0x983D94,   // KERNEL_GADGET_PIVOT_ADD_RSP28_RET    [ps5-linux-loader]
  0x24B06D,   // KERNEL_GADGET_IRETQ                  [ps5-linux-loader]
  0x0,        // KERNEL_GADGET_POP_RAX                TODO
  0x0,        // KERNEL_GADGET_POP_RCX                TODO
  0x1E8778,   // KERNEL_GADGET_POP_RDI                [ps5-linux-loader]
  0x1A92B0,   // KERNEL_GADGET_POP_RSI                [ps5-linux-loader]
  0x34D532,   // KERNEL_GADGET_POP_RDX                [ps5-linux-loader]
  0x0,        // KERNEL_GADGET_POP_R8                 TODO
  0x2510B0,   // KERNEL_GADGET_POP_RSP                [ps5-linux-loader]
  0x0,        // KERNEL_GADGET_STORE_RCX_R8           TODO
  0x0,        // KERNEL_GADGET_STORE_RDI8_RCX         TODO
  0x0,        // KERNEL_GADGET_OR_RCX_EAX             unused
  0x0,        // KERNEL_GADGET_SET_DR7                TODO
  0x0,        // KERNEL_GADGET_ST_RCX_RDX             TODO
  0x0,        // KERNEL_GADGET_ST_RCX_RAX             TODO
  0x0,        // KERNEL_GADGET_MOV_RAX_RSI            TODO
  0x0,        // KERNEL_GADGET_MOV_RAX_RDI            TODO
  0x0,        // KERNEL_GADGET_REP_MOVSB              TODO
  0x0,        // KERNEL_GADGET_CLD                    TODO
  0x0,        // KERNEL_GADGET_RET_TRAMP              TODO
  0x0,        // KERNEL_GADGET_DBREG_RESUME           TODO
  0x3F3C0A,   // KERNEL_GADGET_MOV_RDI_RSI            [ps5-linux-loader]
  0x0,        // KERNEL_GADGET_MOV_RAX_MEM_RAX        TODO
  0x0,        // KERNEL_GADGET_ADD_RAX_RDX             TODO
  0x0,        // KERNEL_GADGET_POP_RBP                 TODO
};

#define OFF_502_FUN_HV_UNMAP_PT_TMR   0xB99060   // [ps5-linux-loader]

#endif // OFFSETS_5_02_H
