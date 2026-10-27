# Libratone Zipp / Zipp Mini Firmware (FFAA) Unpacker & Repacker

**English** | [简体中文](README.md)

Scripts for unpacking the official OTA firmware packages of Libratone Zipp / Zipp Mini speakers (the `FFAA` container), **drag-and-drop ready on Windows**, and for packing an extracted folder back into a package the device accepts.

Nothing to install. The `.bat` files carry the whole script inside themselves and only rely on the PowerShell and .NET 4.5+ that ship with Windows.

```
FFAA-Unpack.bat   <- drop a firmware zip on it, a folder of the same name appears next to it
FFAA-Pack.bat     <- drop the folder on it, produces <foldername>_repack.zip
```

---

## Contents

- [What it does](#what-it-does)
- [Container format](#container-format)
- [How I cracked it](#how-i-cracked-it)
- [Why this is not a version whitelist](#why-this-is-not-a-version-whitelist)
- [Unpacking](#unpacking)
- [Repacking](#repacking)
- [Verification log](#verification-log)
- [Limitations](#limitations)
- [Files](#files)
- [FAQ](#faq)
- [Disclaimer](#disclaimer)

---

## What it does

| Capability | Detail |
| --- | --- |
| Container detection | Tells an `FFAA` container from a plain ZIP; both are handled |
| Header stripping | Locates the end of the header at runtime, no hard-coded offsets |
| De-obfuscation | Restores a standard ZIP byte by byte; 26 MB in ~2-3 seconds |
| Integrity checks | Confirms the restored payload starts with `PK\x03\x04`, then validates the CRC of every entry |
| Repacking | Reuses the original compressed streams and ZIP metadata; unchanged input reproduces the original package byte for byte |
| Cross-platform decode | `tools/ffaa_decode.py` works on macOS / Linux / any machine with Python 3 |

Tested against packages `287` (an early partial-update package), `621` and `879` (Zipp Mini / Zipp). All three share the same structure; only the header length differs.

---

## Container format

The file is literally **a plain-text header followed by an offset-obfuscated ZIP**:

```
"FFAA\n"
<BT version>   "\n"
<DSP version>  "\n"
<MCU version>  "\n"
<WiFi version> "\n"
<OTA version>  "\n"
"FFAA\n"
<payload>                     <- obfuscated ZIP
```

Schematic only (the actual field values differ per package; this just shows the shape):

```
FFAA
BT_x.y.z
DSP_x.y.z
MCU_x.y.z
WIFI_x.y.z
879
FFAA
\x50\x4b\x03\x04 ...          <- a normal zip once the obfuscation is removed
```

**The header length is not a constant.** It depends on how many characters the five version fields take: package `287` measures 42 bytes, `621` and `879` measure 44. So the code must never hard-code an offset; it searches for the second `FFAA\n` instead (the search is capped at 4096 bytes and stops at the first hit).

### The obfuscation

Applied to the payload only (the header is excluded), with `i` starting at 0 on the first payload byte:

```
obfuscate:   c[i] = (p[i] - (i & 15)) & 0xFF
restore:     p[i] = (c[i] + (i & 15)) & 0xFF
```

That is the entire algorithm. No key, no rounds, no S-boxes. Think of it as a rolling staircase that steps down by one every 16 bytes.

### The ZIP underneath

What comes out is a **standard Info-ZIP style archive** with well-preserved metadata, which is exactly what makes byte-identical repacking possible:

- extra fields `0x5455` (UTC timestamp) and `0x7875` (Unix UID/GID)
- central directory `version made by = 0x031e` (Unix, PKZIP 3.0)
- external attributes: regular file `0x81a40000`, directory `0x41fd0010`
- entries are mostly `deflate`, a few are `store`

### The device side

On the device, `system/bin/otahandler` parses the package (that is the vendor's own unpacker) and `system/bin/verdetect` validates the version to prevent downgrades. The hardware is an Atmel SAMA5D3 (Cortex-A5) running Linux 3.10.0, with an Android4SAM 4.4.2 userland (bionic, no Dalvik, no APK). Knowing this confirms the format is nothing more than "text header + linear offset" and involves no hardware-bound cryptography.

---

## How I cracked it

Writing this down because the same approach works on other firmware that merely *looks* encrypted.

**1. Look at the head.** The file starts with plain-text `FFAA`, five human-readable version strings, then `FFAA` again. The vendor did not even bother to hide the header, which suggests the payload transform is **lightweight and reversible** rather than real encryption.

**2. Rule out known containers.** No `PK\x05\x06` (EOCD) at the end, so not a normal ZIP. No `hsqs`, so not squashfs. No `UBI#`, so not UBI. Entropy close to 8 bits/byte, so not plaintext.

**3. Take differences to find a fingerprint.** This was the breakthrough. Compute byte differences of `c[i]` at various lags and look at the mode:

```
lag = 1  ->  mode -1
lag = 2  ->  mode -2
lag = 4  ->  mode -4
```

The mode equals `-lag` exactly, which is the signature of a **linear decreasing term**: `p[i] - p[i-k]` should center on 0, but everything is shifted by `-k`. So `c[i] = p[i] - f(i)` with `f(i+k) - f(i) = k`.

**4. Find the period.** Align to 16-byte boundaries: at a fixed phase within the block, the same 16-byte block appeared 180 times with this modal sequence:

```
00 ff fe fd fc fb fa f9 f8 f7 f6 f5 f4 f3 f2 f1
```

That is precisely `-(i & 15) & 0xFF`. Large runs of all-zero plaintext are common inside ZIPs (uncompressed padding, alignment), which is why the statistics worked. Period = 16, mask = `i & 15`.

**5. Test the hypothesis.** Recompute with `p[i] = (c[i] + (i & 15)) & 0xFF` and the first bytes immediately become `0x50 0x4B 0x03 0x04`. Python's `zipfile` then validated every entry's CRC.

**6. Cross-check the phase origin.** Run the same formula on an older package whose header is 42 bytes instead of 44, and it works **with no shift correction**. So the phase starts at the first payload byte and is independent of header length. That also proves it is not an offset over the whole file, and it is the reason the tool generalises to every package.

---

## Why this is not a version whitelist

I audited every place in the code that could hide a version assumption. Only two numbers exist:

- `4096` - an upper bound when searching for the header terminator, purely defensive
- `15` - the mask

**There is no version table, no model table, no hash allowlist, no branching on firmware revision.** To prove it, I built four headers that do not exist in the wild (7, 54, 37 and 39 bytes, with different digit counts in the version fields), wrapped the same payload in each, and all four were identified and restored byte for byte.

So: **this is generic format code.** Any package matching "`FFAA\n` ... `FFAA\n` + linearly offset payload" will decode, including unreleased builds. Only 287 / 621 / 879 were tested because those are the only packages available here, not because the code is restricted to them.

---

## Unpacking

### Option 1: drag and drop (recommended)

1. Drag the firmware package (e.g. `xxx_879.zip`) onto `FFAA-Unpack.bat`
2. A folder `xxx_879\` appears next to it with the extracted contents
3. You can also double-click the `.bat` and paste a path; several paths at once are supported

### Option 2: command line

```bat
FFAA-Unpack.bat "D:\fw\zipp_879.zip"

REM or call the PowerShell core directly, same arguments
powershell -NoProfile -ExecutionPolicy Bypass -File ffaa_unpack.ps1 "D:\fw\zipp_879.zip"
```

### Output layout

```
D:\fw\
|-- zipp_879.zip              <- original package, left untouched
`-- zipp_879\                 <- created
   |-- ffaa_header.txt        <- important: the original container header
   |-- mcu_app.bin
   |-- dsp_app.bin
   |-- system_ubifs
   `-- ...
```

- If the target folder already exists the tool appends `_1`, `_2`, ... It **never overwrites**
- Plain ZIPs (no FFAA header) can be dropped in too; the stripping step is skipped
- `ffaa_header.txt` holds the original 42/44-byte header exactly, newlines and all. Keep it: without it, repacking can only guess the version fields

### Cross-platform decode

```bash
python3 tools/ffaa_decode.py firmware.zip            # decode and extract
python3 tools/ffaa_decode.py firmware.zip --info     # print header fields only
python3 tools/ffaa_decode.py firmware.zip -o out.zip # decode without extracting
```

---

## Repacking

### Option 1: drag and drop

1. Make sure **the original zip still sits next to the extracted folder** (the only reliable source of the real header)
2. Edit, add or delete files freely
3. Drag the folder onto `FFAA-Pack.bat`
4. It writes `zipp_879_repack.zip` (suffixed `_1` if that name exists; never overwrites the original)

### Option 2: command line

```bat
ffaa_pack.ps1 <folder> [<folder> ...] [-Template <zip>] [-Version <num>] [-Out <path>] [-Plain] [-NoVerify]
```

| Parameter | Effect |
| --- | --- |
| `folder` | Directory to pack; several are processed in sequence |
| `-Template <zip>` | Explicit template package; otherwise the sibling `<foldername>.zip` is used |
| `-Version <num>` | Overrides the OTA version field (for experiments or rollback tests) |
| `-Out <path>` | Output file or directory; defaults to `<folder>_repack.zip` |
| `-Plain` | Skip the FFAA header and emit a **plain ZIP** (handy for comparison) |
| `-NoVerify` | Skip the post-build decode check (not recommended) |

### What repacking actually does

This is the part that is easy to get wrong. **A generic zip library cannot reproduce the original bytes**, because Info-ZIP's deflate and zlib's default output differ (I tried levels 0-9 plus every memLevel and strategy; none reproduced the vendor streams). So the tool uses a **template-reuse** strategy:

1. **Find the template** - priority: `-Template` argument, then the sibling `<foldername>.zip`, then `ffaa_header.txt` inside the folder, then guess (see Limitations)
2. **Compare entries** - CRC and size for each entry are matched against the template's central directory, sorting them into unchanged / changed / added / removed
3. **Unchanged entries** - copy the **original local header, extra fields (`0x5455` / `0x7875`) and compressed stream verbatim**, recomputing only the offset `lho` inside the new blob
4. **Changed entries** - recompress with deflate, recompute the CRC, and mirror the original extra-field style
5. **New entries** - built to Info-ZIP rules: extra = `0x5455` (mtime) + `0x7875` (uid/gid), `vma` by type (file `0x81a40000`, directory `0x41fd0010`)
6. **Lay out** - write local headers and data first, then the central directory and EOCD, recording each entry's new offset
7. **Re-attach the header** - put `ffaa_header.txt` back verbatim, then apply the **inverse obfuscation** (`- (i & 15)`) over the whole payload
8. **Verify in reverse** - decode the result again, check the entry count, inflate each entry and compare CRCs; any mismatch aborts before anything is written

Because step 3 copies verbatim, **a package repacked with no changes is MD5-identical to the original**. That is also the best way to check whether your edit broke the format: do an unmodified round-trip first, compare the hashes, and only then start changing contents.

### Sample output

```
  [*] zipp_879
       template  : zipp_879.zip
       header    : 1.2.3 | 4.5.6 | 0.9.8 | 1.0.1 | 879
       entries   : 8   same 7, changed 1, added 0, removed 0
       verify    : OK  (decoded again, all CRCs match)
  [OK] zipp_879_repack.zip   26,462,146 bytes
```

`same` were copied verbatim, `changed` were recompressed, `added` / `removed` are self-explanatory. If `same` matches what you expect, the template matched correctly.

---

## Verification log

| Scenario | Result |
| --- | --- |
| Packages 287 / 621 / 879, unmodified | Output is **MD5-identical** to the original (hash prefixes `57cbd7aa` / `6f30bb35` / `0a1b8051`) |
| One file modified | Decoded content correct, all CRCs pass, every other entry byte-identical |
| Entries added / removed | Decoded entry count and contents as expected |
| Four synthetic headers (7 / 54 / 37 / 39 bytes) | Restored byte for byte, proving no version dependency |
| 42-byte header (287) vs 44-byte header (621/879) | Same formula, no phase correction needed |
| `-Plain` output | Opens normally in standard archive tools |

For context on what comes out: package `879` holds 8 files / ~34.8 MB uncompressed, mostly an 18 MB `system_ubifs`. `dsp_app.bin` and the dtb are unchanged between `621` and `879` (eight years apart), and `usbupgrade` and `verdetect` are MD5-identical - the most direct evidence that the container format has not changed in all that time.

---

## Limitations

- **ZIP payloads only.** If a variant turns up whose payload is not `PK\x03\x04`, the tool says "unknown container variant" instead of emitting garbage.
- **Recompressed entries do not match the vendor's bytes.** Content, CRC and sizes are correct, but the deflate bitstream cannot be reproduced. If the device ever validated a whole-package signature this would matter; so far only `verdetect` checks the version field.
- **Missing template produces a warning.** Only the MCU version can be recovered then; BT/DSP/WiFi are filled with `0.0.0` and the header length changes accordingly. Such a package will **very likely be rejected by the device** - useful for format research only.
- **`verdetect` blocks downgrades.** Setting a lower `-Version` will presumably be refused. **I have not flashed any custom package onto real hardware.** Round-tripping official packages is safe; flashing is at your own risk.
- **Requires .NET Framework 4.5+** (bundled with Windows 8 / Server 2012 and later).
- **The `.bat` files rely on `certutil.exe`** to release the embedded PowerShell script into `%TEMP%`. If `certutil` is locked down by policy, run the matching `.ps1` directly.
- Unpacking a 26 MB package takes ~2-3 seconds, mostly CRC validation.

---

## Files

| File | Purpose |
| --- | --- |
| `FFAA-Unpack.bat` | Unpack entry point, drag and drop, fully self-contained (pure ASCII, no BOM) |
| `FFAA-Pack.bat` | Repack entry point, drag and drop, also self-contained |
| `ffaa_unpack.ps1` | Unpack core, usable on its own |
| `ffaa_pack.ps1` | Repack core (PowerShell + inline C#), usable on its own |
| `tools/ffaa_decode.py` | Cross-platform decoder, Python 3 standard library only |
| `LICENSE` | MIT |

The `.bat` and `.ps1` files are two carriers of the same logic: the `.bat` embeds its `.ps1` as base64 at the end of the file, decrypts it to `%TEMP%` with `certutil -decode` at runtime and deletes it afterwards. That keeps distribution to a single file, at the cost of keeping both copies in sync when changing logic.

---

## FAQ

**Why does the output look like a pile of binaries?**
The main payload is `system_ubifs`, a UBIFS image, not a tar. Use `ubireader_extract_files` (`pip install ubi_reader`) to mount the full filesystem. `mcu_app.bin` / `dsp_app.bin` are bare firmware for the respective MCU / DSP.

**Can I flash it?**
No idea, I have not tried. Beyond the container format the device runs `verdetect` on the version, and a bad flash needs a recovery mode to undo. This is a research and analysis tool, not a flashing tool.

**Why not just rewrite the archive with Python's `zipfile`?**
Because the result would not be byte-identical (different deflate output, different extra fields), so the MD5 round-trip check that proves "nothing except my edit changed" would be impossible. Template reuse gives you that guarantee.

**I deleted `ffaa_header.txt`, now what?**
Put the original zip back next to the folder and the script re-reads the header from it. If both are gone it can only guess, and it warns you.

**Can intermediate builds (554 / 588 / 665 / ...) be unpacked?**
Structurally yes (see "Why this is not a version whitelist"), but those packages are not available here. Their URLs exist only in the vendor's cloud database; the CDN no longer mirrors them.

---

## Disclaimer

This project is for **interoperability and security research**: understanding the firmware layout of hardware you own, inspecting update contents, and archiving formats.

- It contains no vendor keys, certificates or copyrighted firmware images
- It provides no firmware download links
- Flashing unofficial firmware can brick a device and void its warranty; you accept that risk
- Follow the laws of your jurisdiction and the vendor's licence terms

If your goal is simply to update your own device, use the vendor's official channel.

## License

[MIT](LICENSE)
