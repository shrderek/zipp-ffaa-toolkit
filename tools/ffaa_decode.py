#!/usr/bin/env python3
"""
FFAA firmware decoder (cross-platform, no dependencies).

Strips the FFAA container from a Libratone OTA package and extracts the
inner ZIP archive.

    python3 ffaa_decode.py package.zip              # decode + extract
    python3 ffaa_decode.py package.zip -o out.zip   # decode only
    python3 ffaa_decode.py package.zip --info       # show header only

Container layout (see README for details):

    "FFAA\\n" <BT> "\\n" <DSP> "\\n" <MCU> "\\n" <WiFi> "\\n" <ver> "\\n" "FFAA\\n"
    payload[i] = (payload[i] + (i & 15)) & 0xFF
"""

import argparse
import os
import sys
import zipfile

MAGIC = b"FFAA\n"
HEADER_SEARCH_LIMIT = 4096


def find_header(data):
    """Return (header_end_offset, header_lines) or (None, None).

    The header always starts with "FFAA\\n" and ends with a second "FFAA\\n".
    Its length depends on the number of digits in the version fields, so the
    end offset must be searched, never hard-coded.
    """
    if not data.startswith(MAGIC):
        return None, None

    limit = min(len(data) - len(MAGIC), HEADER_SEARCH_LIMIT)
    for i in range(len(MAGIC), limit):
        if data[i:i + 5] == MAGIC:
            lines = data[:i].decode("latin-1").strip().split("\n")
            return i + 5, lines

    return None, None


def deobfuscate(payload):
    """p[i] = (c[i] + (i & 15)) & 0xFF  -- offset comes from the payload start."""
    return bytes((b + (i & 15)) & 0xFF for i, b in enumerate(payload))


def main():
    ap = argparse.ArgumentParser(description="Decode a Libratone FFAA OTA package")
    ap.add_argument("package", help="path to the vendor firmware package")
    ap.add_argument("-o", "--out", help="write the decoded ZIP here (default: <name>_dec.zip)")
    ap.add_argument("--info", action="store_true", help="print the header and stop")
    args = ap.parse_args()

    with open(args.package, "rb") as fh:
        data = fh.read()

    header_end, lines = find_header(data)

    if header_end is None:
        # Not an FFAA container. It may already be a bare ZIP.
        print("  [!] no FFAA header found, treating the file as a plain ZIP")
        if not data.startswith(b"PK\x03\x04"):
            print("  [X] this is neither an FFAA container nor a ZIP archive")
            return 1
        zip_bytes = data
    else:
        fields = [l for l in lines if l and l != "FFAA"]
        print("  container : FFAA")
        print("  header    : %d bytes" % header_end)
        if len(fields) >= 5:
            for name, value in zip(("bootloader", "dsp", "mcu", "wifi", "version"), fields):
                print("    %-10s: %s" % (name, value))
        else:
            print("    raw       : %s" % " | ".join(fields))

        if args.info:
            return 0

        zip_bytes = deobfuscate(data[header_end:])
        print("  payload   : %d bytes" % len(zip_bytes))

    if not zip_bytes.startswith(b"PK\x03\x04"):
        print("  [X] restored payload does not start with PK\\x03\\x04")
        print("      the package uses an unknown container variant")
        return 1

    stem = os.path.splitext(os.path.basename(args.package))[0]
    out_zip = args.out or os.path.join(os.path.dirname(os.path.abspath(args.package)), stem + "_dec.zip")

    with open(out_zip, "wb") as fh:
        fh.write(zip_bytes)
    print("  zip       : %s" % out_zip)

    if args.info:
        return 0

    target = out_zip[:-4] if out_zip.lower().endswith(".zip") else out_zip + "_files"
    if os.path.exists(target):
        n = 1
        while os.path.exists("%s_%d" % (target, n)):
            n += 1
        target = "%s_%d" % (target, n)

    with zipfile.ZipFile(out_zip) as zf:
        bad = zf.testzip()
        zf.extractall(target)
        print("  entries   : %d" % len(zf.infolist()))
        print("  crc check : %s" % ("FAILED on " + bad if bad else "all entries OK"))

    print("  output    : %s" % target)
    return 0


if __name__ == "__main__":
    sys.exit(main())
