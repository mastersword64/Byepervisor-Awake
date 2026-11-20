# Byepervisor Awake

PS5 Hypervisor defeat payload for firmware 5.00–6.02.

Currently, only supports 6.02

First HV defeat from FreeBSD **without S3 sleep/resume**. Uses Trap Flag single-step to bypass DR0 intercepts, then hypercall 0x13 (`hv_unmap_pt_tmr`) to remove the Trusted Memory Region and DMAP VMCB writes to disable Nested Page Tables on all 16 cores.

Executes in under 2 seconds with no user interaction needed.

Based on [Byepervisor Reborn](https://github.com/EchoStretch/Byepervisor-Reborn) by EchoStretch/PS5Dev (FW 7.61+).  
HV defeat technique from [ps5-linux-loader](https://github.com/ps5-linux/ps5-linux-loader) by TheFlow/flow0 (FW 5.00-6.02).

## Status

| Firmware | Status | Notes |
|----------|--------|-------|
| **6.02** | **Confirmed working** | All offsets verified, tested on console |
| 6.00 | Needs offsets | Gadgets/IDT/TSS/HC13 ready, missing DATA_CAVE/PMAP_STORE/DMPML4I/DMPDPI/HV_MP_STARTUP_CALL |
| 5.50 | Needs offsets | Same as above |
| 5.10 | Needs offsets | Same as above |
| 5.02 | Needs offsets | Same as above |
| 5.00 | Needs offsets | Same as above |

### Why other firmwares should work

All firmwares from 5.00 to 6.02 have `hv_unmap_pt_tmr` (HC 0x13) confirmed in [ps5-linux-loader](https://github.com/ps5-linux/ps5-linux-loader) offset tables. The HV dispatch table structure and VMCB layout are the same across this range. The core exploit method (TF trigger → ROP → HC 0x13 → VMCB write) does not depend on firmware-specific behavior — only the kernel offsets change.

That said, **this has only been tested on 6.02**. Other firmwares may have differences we haven't encountered yet. The offset files are structured and ready — they just need the missing values filled in from a ktext dump of each firmware.

### 6.50 and above

HC 0x13 is not present in ps5-linux-loader for FW 6.50+. Sony likely changed or removed `hv_unmap_pt_tmr` starting from 6.50. Those firmwares use a different HV defeat method (break_hv via S3 resume) and are not supported by this exploit.

## What it does

After the hypervisor is defeated:

- **Kernel .text R/W** — read and modify any kernel code (normally execute-only, enforced by HV)
- **VMCB access** — read/write all 16 VM control blocks via DMAP
- **HV memory R/W** — full hypervisor region accessible

## How it works

1. Pin to CPU1
2. Disable xotext on kernel .text
3. Hook #DB exception via IDT
4. Set Trap Flag → triggers #DB in kernel mode
5. #DB pivots to ROP chain
6. ROP calls HC 0x13 → removes TMR
7. Write to all 16 VMCBs via DMAP → disables NPT
8. Second HC 0x13 → HV reloads VMCBs
9. HV defeated

## Building

Requires [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk).

```bash
PS5_PAYLOAD_SDK=~/ps5-payload-sdk/host make clean all
```

## Usage

Run after kernel exploit:

```bash
nc -q0 <PS5_IP> 9021 < byepervisor_awake.elf
```

## Adding support for other firmwares

The offset files for 5.00–6.00 (`include/offsets/`) have TODO entries (set to 0) for offsets that require a kernel text dump to find. 

PRs with verified offsets are welcome.

## Credits

- **EchoStretch** — Original [Byepervisor Reborn](https://github.com/EchoStretch/Byepervisor-Reborn) exploit (khook framework, chain builder)
- **TheOfficialFloW** — [ps5-linux-loader](https://github.com/ps5-payload-dev/ps5-linux-loader) (kernel offsets, HC 0x13 approach)
- **ps5-payload-dev** — [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk)
- **Devs related to these projects**
- **Claude (Anthropic)** — AI assistance with exploit design, offset scanning, and code
