# Byepervisor Awake

PS5 Hypervisor defeat payload for firmware 5.00–6.02.

First HV defeat from FreeBSD **without S3 sleep/resume**. Uses Trap Flag single-step to bypass DR0 intercepts, then hypercall 0x13 (`hv_unmap_pt_tmr`) to remove the Trusted Memory Region and DMAP VMCB writes to disable Nested Page Tables on all 16 cores.

Executes in under 2 seconds with no user interaction needed.

Based on [Byepervisor Reborn](https://github.com/EchoStretch/Byepervisor-Reborn) by EchoStretch/PS5Dev (FW 7.61+).  
Ported to FW 6.02 by mastersword64 with AI assistance (Claude).

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

All firmwares from 5.00 to 6.02 have `hv_unmap_pt_tmr` (HC 0x13) confirmed in [ps5-linux-loader](https://github.com/ps5-payload-dev/ps5-linux-loader) offset tables. The HV dispatch table structure and VMCB layout are the same across this range. The core exploit method (TF trigger → ROP → HC 0x13 → VMCB write) does not depend on firmware-specific behavior — only the kernel offsets change.

That said, **this has only been tested on 6.02**. Other firmwares may have differences we haven't encountered yet. The offset files are structured and ready — they just need the missing values filled in from a ktext dump of each firmware.

### 6.50 and above

HC 0x13 is not present in ps5-linux-loader for FW 6.50+. Sony likely changed or removed `hv_unmap_pt_tmr` starting from 6.50. Those firmwares use a different HV defeat method (break_hv via S3 resume) and are not supported by this exploit.

## What it does

After the hypervisor is defeated:

- **Kernel .text R/W** — read and modify any kernel code (normally execute-only, enforced by HV)
- **VMCB access** — read/write all 16 VM control blocks via DMAP
- **HV memory R/W** — full hypervisor region accessible

## How it works

1. **TF single-step** — Sets the Trap Flag in RFLAGS via IRETQ. Immediate `#DB` fires in kernel context (CPL=0). The HV blocks `mov dr0` but does not intercept TF.

2. **ROP chain** — The `#DB` handler pivots to a ROP chain stored in a kernel data cave.

3. **HC 0x13** (`hv_unmap_pt_tmr`) — Hypercall that zeros `VMCB[current_vCPU]+0x5F8`, removing TMR protection for the calling vCPU. The HV handler is 20 bytes of code that ignores all guest arguments.

4. **DMAP VMCB writes** — With TMR removed, writes `GMET_ENABLE` (0x8) to the NPT control field of all 16 VMCBs via Direct Memory Access Path.

5. **vmmcall reload** — A second HC 0x13 call forces the HV to re-read the modified VMCBs.

Must run on **CPU1** because HC 0x13 operates on the calling vCPU's VMCB only.

### Comparison

| | Byepervisor Reborn | ps5-linux-loader | **Byepervisor Awake** |
|---|---|---|---|
| FW range | 7.61–13.60 | 5.00–6.50 | 5.00–6.02 |
| Needs S3 sleep | Yes | Yes | **No** |
| Returns to FreeBSD | Yes | No (boots Linux) | **Yes** |
| Trigger | DR0 breakpoint | FACS #GP on resume | **TF single-step** |
| Time | ~30s | ~30s | **< 2s** |

## Building

Requires [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk).

```bash
PS5_PAYLOAD_SDK=~/ps5-payload-sdk/host make clean all
```

## Usage

Run after kernel exploit + kstuff (via elfldr):

```bash
nc -q0 <PS5_IP> 9021 < byepervisor_awake.elf
```

## Output

```
[+] Byepervisor Awake
[+] FW: 6.02
[+] xotext disabled
[+] Building chain
[+] Firing on CPU1
[+] diag=0xcafedead00001337
[+] *** HV DEFEATED! ***
E8 FB 3F 50 00 00 00 00  00 00 00 00 00 00 00 00  |  ..?P............
55 48 89 E5 53 48 83 EC  18 48 8D 1D B0 82 96 03  |  UH..SH...H......
```

PS5 notification:
```
Byepervisor Awake
[HV DEFEATED] FW 6.02
Cookie: 0xcafedead00001337
```

## Adding support for other firmwares

The offset files for 5.00–6.00 (`include/offsets/`) have TODO entries (set to 0) for offsets that require a kernel text dump to find. The exploit exits safely with a PS5 notification on those firmwares until the offsets are filled in.

To find the missing offsets for a firmware:
1. Boot Linux on the target firmware using ps5-linux-loader
2. Dump ktext using physdump
3. Scan the dump for the required symbols (same patterns used for 6.02)
4. Fill in the zeros in the corresponding offset header file

PRs with verified offsets are welcome.

## Credits

- **EchoStretch / PS5Dev** — Original [Byepervisor Reborn](https://github.com/EchoStretch/Byepervisor-Reborn) exploit (khook framework, chain builder)
- **TheOfficialFloW** — [ps5-linux-loader](https://github.com/ps5-payload-dev/ps5-linux-loader) (kernel offsets, HC 0x13 approach)
- **ps5-payload-dev** — [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk)
- **mastersword64** — Port to FW 6.02, TF-based trigger, multi-firmware structure
- **Claude (Anthropic)** — AI assistance with exploit design, offset scanning, and code
