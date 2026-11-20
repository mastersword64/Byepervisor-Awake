#include <sys/types.h>
#include <ps5/kernel.h>

#include "util.h"
#include "kdlsym.h"

#include "offsets/6_02.h"

uint64_t g_fw_version;
uint64_t g_kernel_base = 0;

uint64_t ktext(uint64_t offset)
{
  return KERNEL_ADDRESS_TEXT_BASE + offset;
}

uint64_t kgadget(kgadget_t gadget)
{
  if (gadget >= KERNEL_GADGET_MAX)
    return 0;

  switch(kernel_get_fw_version() & 0xffff0000) {
  case 0x06020000:
    return ktext(g_gadget_map_0602[gadget]);
  default:
    return 0;
  }
}

uint64_t kdlsym(ksym_t sym)
{
  if (sym >= KERNEL_SYM_MAX)
    return 0;

  switch(kernel_get_fw_version() & 0xffff0000) {
  case 0x06020000:
    return ktext(g_sym_map_0602[sym]);
  default:
    return 0;
  }
}

uint64_t rawoff(ksym_t sym)
{
  if (sym >= KERNEL_SYM_MAX)
    return 0;

  switch(kernel_get_fw_version() & 0xffff0000) {
  case 0x06020000:
    return g_sym_map_0602[sym];
  default:
    return 0;
  }
}

uint64_t kdldmap(uint64_t pa)
{
  uint64_t dmpml4i = (uint64_t) kread32(kdlsym(KERNEL_SYM_DMPML4I));
  uint64_t dmpdpi  = (uint64_t) kread32(kdlsym(KERNEL_SYM_DMPDPI));

  return (0xFFFF800000000000 | (dmpml4i << 39) | (dmpdpi << 30)) + pa;
}
