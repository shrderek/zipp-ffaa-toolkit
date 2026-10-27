<#
  FFAA Firmware Unpacker - PowerShell core

  Container format:
      Plain-text header : "FFAA\n<BT>\n<DSP>\n<MCU>\n<WiFi>\n<OTA version>\nFFAA\n"
                          (length varies with field digits: 42 or 44 bytes)
      Payload           : every byte minus its own offset (mod 16)
                          obfuscation: c[i] = (p[i] - (i & 15)) & 0xFF
                          restore    : p[i] = (c[i] + (i & 15)) & 0xFF
      Restored payload  : standard ZIP archive (PK\x03\x04)

  Plain ZIP archives are also accepted and simply extracted.
  Output goes to a sibling folder named after the archive.

  Usage: powershell -File ffaa_unpack.ps1 "C:\path\to\firmware.zip"
#>
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Paths
)

$ErrorActionPreference = 'Stop'
try { $Host.UI.RawUI.WindowTitle = 'FFAA Firmware Unpacker' } catch { }

function W([string]$text, [string]$color) {
    if ($color) { Write-Host $text -ForegroundColor $color } else { Write-Host $text }
}

if (-not $Paths -or $Paths.Count -eq 0) {
    W ''
    W '  Usage: drag the firmware zip onto FFAA-Unpack.bat,' DarkGray
    W '         or drop it into this window and press Enter.' DarkGray
    W ''
    $ans = Read-Host '  File path'
    if ([string]::IsNullOrWhiteSpace($ans)) { exit }
    $Paths = @($ans.Trim().Trim('"'))
}

# ---- Byte-level restore in C#: ~26 MB takes tens of milliseconds ----
$cs = @'
public class FfaaObf {
    public static byte[] Deobfuscate(byte[] src, int offset) {
        int n = src.Length - offset;
        byte[] dst = new byte[n];
        for (int i = 0; i < n; i++) {
            dst[i] = (byte)(src[offset + i] + (i & 15));
        }
        return dst;
    }
}
'@
$fast = $false
try { Add-Type -TypeDefinition $cs -ErrorAction Stop; $fast = $true } catch { }

try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop } catch { }

$hit = 0; $miss = 0

foreach ($raw in $Paths) {
    $p = $raw.Trim().Trim('"')
    if ([string]::IsNullOrWhiteSpace($p)) { continue }
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {
        W "  [X] File not found: $p" Red; $miss++; continue
    }

    $target = $null
    try {
        $full = (Resolve-Path -LiteralPath $p).ProviderPath
        $data = [System.IO.File]::ReadAllBytes($full)
        if ($data.Length -lt 32) { W "  [X] File too small: $p" Red; $miss++; continue }

        # ---- Detect FFAA container and locate the end of its header ----
        $isFfaa = ($data[0] -eq 70 -and $data[1] -eq 70 -and $data[2] -eq 65 -and $data[3] -eq 65 -and $data[4] -eq 10)
        $hdr = 0
        if ($isFfaa) {
            $limit = [Math]::Min($data.Length - 5, 4096)
            for ($i = 5; $i -lt $limit; $i++) {
                if ($data[$i] -eq 70 -and $data[$i + 1] -eq 70 -and $data[$i + 2] -eq 65 -and $data[$i + 3] -eq 65 -and $data[$i + 4] -eq 10) {
                    $hdr = $i + 5
                    break
                }
            }
            if ($hdr -eq 0) { $isFfaa = $false }
        }

        $parent = [System.IO.Path]::GetDirectoryName($full)
        $stem = [System.IO.Path]::GetFileNameWithoutExtension($full)
        $target = Join-Path $parent $stem
        $k = 1
        while (Test-Path -LiteralPath $target) { $target = Join-Path $parent ($stem + '_' + $k); $k++ }

        $tmp = Join-Path $parent ('~ffaa_' + [Guid]::NewGuid().ToString('N') + '.zip')
        if ($isFfaa) {
            if ($fast) {
                $zipBytes = [FfaaObf]::Deobfuscate($data, $hdr)
            } else {
                $n = $data.Length - $hdr
                $zipBytes = New-Object byte[] $n
                for ($i = 0; $i -lt $n; $i++) {
                    $zipBytes[$i] = [byte](($data[$hdr + $i] + ($i -band 15)) -band 255)
                }
            }
            [System.IO.File]::WriteAllBytes($tmp, $zipBytes)
            $zipPath = $tmp
        } else {
            $zipPath = $full
        }

        # ---- Verify the ZIP signature ----
        $fs = [System.IO.File]::OpenRead($zipPath)
        $sig = New-Object byte[] 4
        $null = $fs.Read($sig, 0, 4)
        $fs.Close()
        if (-not ($sig[0] -eq 0x50 -and $sig[1] -eq 0x4B)) {
            if ($isFfaa) { W "  [X] Restored payload is not a ZIP (unknown container variant): $stem" Red }
            else { W "  [X] Neither an FFAA container nor a ZIP archive: $stem" Red }
            if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }
            $miss++; continue
        }

        $zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
        $count = $zip.Entries.Count
        $rawSize = 0
        foreach ($e in $zip.Entries) { $rawSize += $e.Length }
        $zip.Dispose()

        New-Item -ItemType Directory -Path $target -Force | Out-Null
        [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $target)

        # ---- Keep the container header so FFAA-Pack.bat can rebuild it later ----
        if ($isFfaa) {
            try {
                $hdrRaw = [System.Text.Encoding]::ASCII.GetString($data, 0, $hdr)
                $hdrFile = Join-Path $target 'ffaa_header.txt'
                [System.IO.File]::WriteAllText($hdrFile, $hdrRaw, (New-Object System.Text.UTF8Encoding $false))
            } catch { }
        }

        if ($isFfaa) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }

        # ---- Summary ----
        $hdrText = ''
        if ($isFfaa) {
            $lines = ([System.Text.Encoding]::ASCII.GetString($data, 0, $hdr)).Trim() -split "`r?`n"
            $hdrText = ($lines | Where-Object { $_ -ne 'FFAA' -and $_ -ne '' }) -join ' | '
        }

        W ''
        W "  [OK] $([System.IO.Path]::GetFileName($full))" Green
        if ($isFfaa) {
            W "       container : FFAA, header $hdr bytes" DarkGray
            W "       modules   : $hdrText" DarkGray
        } else {
            W "       container : plain ZIP (no FFAA header)" DarkGray
        }
        W ("       entries   : {0} file(s), {1:N2} MB uncompressed" -f $count, ($rawSize / 1MB)) DarkGray
        W "       output    : $target" Cyan
        $hit++
    }
    catch {
        W "  [X] Failed to process: $raw" Red
        W "      $($_.Exception.Message)" DarkRed
        if ($target -and (Test-Path -LiteralPath $target)) {
            $left = @(Get-ChildItem -LiteralPath $target -Force -ErrorAction SilentlyContinue)
            if ($left.Count -eq 0) { Remove-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue }
        }
        $miss++
    }
}

W ''
if ($Paths.Count -gt 1) {
    W ("  Done: {0} succeeded, {1} failed" -f $hit, $miss) Gray
}
