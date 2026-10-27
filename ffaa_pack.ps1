<#
  FFAA firmware repacker - core engine (PowerShell + inline C#)

  Container layout produced by the vendor:
      "FFAA\n" + <BT> + "\n" + <DSP> + "\n" + <MCU> + "\n" + <WiFi> + "\n" + <ver> + "\n" + "FFAA\n"
      then payload where  c[i] = (p[i] - (i & 15)) & 0xFF

  This tool reverses the exact same step:
      p[i] = (c[i] + (i & 15)) & 0xFF   -> standard ZIP

  Rebuild strategy:
    * if the original archive sits next to the folder, it is used as a template.
      Entries whose content is unchanged keep their ORIGINAL compressed stream,
      local header, extra fields and central record -> the result is byte-identical
      to the original package.
    * changed / new entries are re-compressed and re-checksummed.
    * every produced file is verified by decoding it again (inflate + CRC check).

  Usage:
      powershell -ExecutionPolicy Bypass -File ffaa_pack.ps1 <folder> [<folder> ...]
      optional: -Template <zip>  -Version <num>  -Plain  -NoVerify  -Out <file>
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
    [string[]] $Targets,

    [string] $Template = "",
    [string] $Version = "",
    [string] $Out = "",
    [switch] $Plain,
    [switch] $NoVerify,
    [switch] $Quiet
)

$ErrorActionPreference = "Stop"

$cs = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;

public class FfaaEntry
{
    public string Name;
    public byte[] NameBytes;
    public int Method;
    public int Vne;
    public uint Crc;
    public long CSize;
    public long USize;
    public long Lho;
    public byte[] Lh;
    public byte[] LName;
    public byte[] LExtra;
    public byte[] CData;
    public byte[] Cd;
    public bool IsDir;
}

public class FfaaResult
{
    public byte[] Data;
    public string Header = "";
    public int Same;
    public int Changed;
    public int Added;
    public int Removed;
    public int Entries;
    public string Warning = "";
    public string Error = "";
    public bool Ok;
    public bool IsFfaa;
}

public static class FfaaPack
{
    static readonly uint[] Tbl = MakeTable();

    static uint[] MakeTable()
    {
        uint[] t = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint c = i;
            for (int k = 0; k < 8; k++)
                c = ((c & 1) != 0) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            t[i] = c;
        }
        return t;
    }

    public static uint Crc32(byte[] b)
    {
        uint c = 0xFFFFFFFFu;
        for (int i = 0; i < b.Length; i++)
            c = Tbl[(c ^ b[i]) & 0xFF] ^ (c >> 8);
        return c ^ 0xFFFFFFFFu;
    }

    static byte[] Sub(byte[] d, int off, int len)
    {
        if (off < 0 || len < 0 || off + len > d.Length) throw new Exception("offset out of range");
        byte[] r = new byte[len];
        Buffer.BlockCopy(d, off, r, 0, len);
        return r;
    }

    static ushort R16(byte[] d, int o) { return (ushort)(d[o] | (d[o + 1] << 8)); }
    static uint R32(byte[] d, int o)
    {
        uint v = (uint)(d[o] | (d[o + 1] << 8) | (d[o + 2] << 16));
        v |= ((uint)d[o + 3]) << 24;
        return v;
    }
    static void W16(byte[] d, int o, int v) { d[o] = (byte)(v & 0xFF); d[o + 1] = (byte)((v >> 8) & 0xFF); }
    static void W32(byte[] d, int o, long v) { d[o] = (byte)(v & 0xFF); d[o + 1] = (byte)((v >> 8) & 0xFF); d[o + 2] = (byte)((v >> 16) & 0xFF); d[o + 3] = (byte)((v >> 24) & 0xFF); }

    static string Latin1(byte[] b)
    {
        return Encoding.GetEncoding(28591).GetString(b);
    }

    public static bool LooksFfaa(byte[] d)
    {
        return d.Length > 10 && d[0] == 0x46 && d[1] == 0x46 && d[2] == 0x41 && d[3] == 0x41 && d[4] == 0x0A;
    }

    public static int HeaderEnd(byte[] d)
    {
        if (!LooksFfaa(d)) return -1;
        for (int i = 4; i + 5 <= d.Length; i++)
            if (d[i] == 0x46 && d[i + 1] == 0x46 && d[i + 2] == 0x41 && d[i + 3] == 0x41 && d[i + 4] == 0x0A)
                return i + 5;
        return -1;
    }

    public static byte[] Deobfuscate(byte[] src, int off)
    {
        int n = src.Length - off;
        byte[] dst = new byte[n];
        for (int i = 0; i < n; i++)
            dst[i] = (byte)((src[off + i] + (i & 15)) & 0xFF);
        return dst;
    }

    public static byte[] Obfuscate(byte[] p)
    {
        byte[] dst = new byte[p.Length];
        for (int i = 0; i < p.Length; i++)
            dst[i] = (byte)((p[i] - (i & 15)) & 0xFF);
        return dst;
    }

    static int FindEocd(byte[] d)
    {
        int low = Math.Max(0, d.Length - 22 - 65535);
        for (int i = d.Length - 22; i >= low; i--)
            if (d[i] == 0x50 && d[i + 1] == 0x4B && d[i + 2] == 0x05 && d[i + 3] == 0x06)
                return i;
        return -1;
    }

    public static List<FfaaEntry> ParseZip(byte[] d)
    {
        int eocd = FindEocd(d);
        if (eocd < 0) throw new Exception("EOCD not found - not a ZIP archive");
        int n = R16(d, eocd + 10);
        long cdOff = R32(d, eocd + 16);
        List<FfaaEntry> list = new List<FfaaEntry>();
        int off = (int)cdOff;
        for (int k = 0; k < n; k++)
        {
            if (off + 46 > d.Length || R32(d, off) != 0x02014B50)
                throw new Exception("corrupt central directory at entry " + k);
            FfaaEntry e = new FfaaEntry();
            e.Vne = R16(d, off + 6);
            e.Method = R16(d, off + 10);
            e.Crc = R32(d, off + 16);
            e.CSize = R32(d, off + 20);
            e.USize = R32(d, off + 24);
            int nl = R16(d, off + 28);
            int el = R16(d, off + 30);
            int cl = R16(d, off + 32);
            e.Lho = R32(d, off + 42);
            e.Cd = Sub(d, off, 46 + nl + el + cl);
            e.NameBytes = Sub(d, off + 46, nl);
            e.Name = Latin1(e.NameBytes);
            e.IsDir = e.Name.EndsWith("/");
            int lho = (int)e.Lho;
            if (lho + 30 > d.Length) throw new Exception("bad local header offset for " + e.Name);
            e.Lh = Sub(d, lho, 30);
            int lnl = R16(d, lho + 26);
            int lel = R16(d, lho + 28);
            e.LName = Sub(d, lho + 30, lnl);
            e.LExtra = Sub(d, lho + 30 + lnl, lel);
            int dataOff = lho + 30 + lnl + lel;
            e.CData = Sub(d, dataOff, (int)e.CSize);
            list.Add(e);
            off += 46 + nl + el + cl;
        }
        return list;
    }

    static byte[] PatchCd(byte[] cd, long lho, uint crc, long cs, long us, int meth, int vne)
    {
        byte[] b = (byte[])cd.Clone();
        W16(b, 6, vne);
        W16(b, 10, meth);
        W32(b, 16, crc);
        W32(b, 20, cs);
        W32(b, 24, us);
        W32(b, 42, lho);
        return b;
    }

    static void DosTime(DateTime dt, out int t, out int d)
    {
        if (dt.Year < 1980) dt = new DateTime(1980, 1, 1, 0, 0, 0);
        if (dt.Year > 2107) dt = new DateTime(2107, 12, 31, 23, 59, 58);
        t = (dt.Hour << 11) | (dt.Minute << 5) | (dt.Second / 2);
        d = ((dt.Year - 1980) << 9) | (dt.Month << 5) | dt.Day;
    }

    static byte[] UnixExtra(long unix, uint uid, uint gid, bool central)
    {
        MemoryStream ms = new MemoryStream();
        BinaryWriter w = new BinaryWriter(ms);
        w.Write((ushort)0x5455);
        w.Write((ushort)(central ? 5 : 9));
        w.Write((byte)3);
        w.Write((int)unix);
        if (!central) w.Write((int)unix);
        w.Write((ushort)0x7875);
        w.Write((ushort)11);
        w.Write((byte)1);
        w.Write((byte)4);
        w.Write(uid);
        w.Write((byte)4);
        w.Write(gid);
        w.Flush();
        return ms.ToArray();
    }

    static byte[] Deflate(byte[] src)
    {
        using (MemoryStream ms = new MemoryStream())
        {
            using (DeflateStream ds = new DeflateStream(ms, CompressionLevel.Optimal, true))
                ds.Write(src, 0, src.Length);
            return ms.ToArray();
        }
    }

    static byte[] Inflate(byte[] src, int hint)
    {
        using (MemoryStream ms = new MemoryStream(src))
        using (DeflateStream ds = new DeflateStream(ms, CompressionMode.Decompress))
        using (MemoryStream outp = new MemoryStream(hint > 0 ? hint : 4096))
        {
            byte[] buf = new byte[65536];
            int r;
            while ((r = ds.Read(buf, 0, buf.Length)) > 0)
                outp.Write(buf, 0, r);
            return outp.ToArray();
        }
    }

    public static string GuessVersion(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            byte[] d = File.ReadAllBytes(path);
            string s = Encoding.GetEncoding(28591).GetString(d);
            MatchCollection m = Regex.Matches(s, @"(?<![0-9])[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,3}(?![0-9])");
            if (m.Count == 0) return null;
            Dictionary<string, int> hits = new Dictionary<string, int>();
            foreach (Match x in m)
            {
                if (!hits.ContainsKey(x.Value)) hits[x.Value] = 0;
                hits[x.Value]++;
            }
            string best = null;
            int bestN = -1;
            foreach (KeyValuePair<string, int> kv in hits)
                if (kv.Value > bestN) { bestN = kv.Value; best = kv.Key; }
            return best;
        }
        catch { return null; }
    }

    public static string VersionFromName(string name)
    {
        MatchCollection m = Regex.Matches(name, @"(?<![0-9])([0-9]{3,5})(?![0-9])");
        string best = null;
        foreach (Match x in m)
        {
            string v = x.Groups[1].Value;
            if (v.Length == 8) continue;
            if (v.Length > 5) continue;
            best = v;
        }
        return best;
    }

    static string CleanHeader(string text)
    {
        if (text == null) return null;
        text = text.Replace("\r\n", "\n").Replace("\r", "\n").Trim('\n');
        if (!text.StartsWith("FFAA\n")) return null;
        if (!text.EndsWith("\nFFAA")) return null;
        return text + "\n";
    }

    public static FfaaResult Pack(string folder, string templatePath, string headerText, string versionHint, bool plain, bool verify)
    {
        FfaaResult res = new FfaaResult();
        try
        {
            folder = folder.TrimEnd('\\', '/');
            string folderName = Path.GetFileName(folder);
            if (string.IsNullOrEmpty(folderName)) throw new Exception("cannot determine folder name");

            List<FfaaEntry> tpl = null;
            string header = null;
            bool isFfaa = false;
            bool tplPlain = false;

            if (!string.IsNullOrEmpty(templatePath))
            {
                if (!File.Exists(templatePath)) throw new Exception("template not found: " + templatePath);
                byte[] tb = File.ReadAllBytes(templatePath);
                if (LooksFfaa(tb))
                {
                    int h = HeaderEnd(tb);
                    if (h < 0) throw new Exception("template has a broken FFAA header");
                    header = Encoding.GetEncoding(28591).GetString(tb, 0, h);
                    byte[] inner = Deobfuscate(tb, h);
                    tpl = ParseZip(inner);
                    isFfaa = true;
                }
                else
                {
                    tpl = ParseZip(tb);
                    isFfaa = false;
                    tplPlain = true;
                }
            }

            if (header == null)
            {
                string cleaned = CleanHeader(headerText);
                if (cleaned != null)
                {
                    header = cleaned;
                    isFfaa = true;
                }
            }

            if (header == null && !plain && !tplPlain)
            {
                // Only mcu_app.bin carries a reliable version string; bt/dsp/wifi versions
                // are not present in any payload file, so they cannot be recovered here.
                string mcu = GuessVersion(Path.Combine(folder, "mcu_app.bin"));
                string ver = versionHint;
                if (string.IsNullOrEmpty(ver)) ver = VersionFromName(folderName);
                if (string.IsNullOrEmpty(ver)) ver = "0";
                if (mcu == null) mcu = "0.0.0";
                header = "FFAA\n0.0.0\n0.0.0\n" + mcu + "\n0.0.0\n" + ver + "\nFFAA\n";
                res.Warning = "no template found: only the MCU version could be read from mcu_app.bin;"
                            + " BT/DSP/WiFi are filled with 0.0.0. Put the original .zip next to the folder,"
                            + " or create ffaa_header.txt, to keep the real header.";
                isFfaa = true;
            }

            if (plain) { header = null; isFfaa = false; }

            // ---- collect folder content ----
            Dictionary<string, string> files = new Dictionary<string, string>(StringComparer.Ordinal);
            Dictionary<string, DateTime> mtimes = new Dictionary<string, DateTime>(StringComparer.Ordinal);
            string[] all = Directory.GetFiles(folder, "*", SearchOption.AllDirectories);
            foreach (string p in all)
            {
                string rel = p.Substring(folder.Length).Replace('\\', '/').TrimStart('/');
                string low = rel.ToLowerInvariant();
                if (low == "ffaa_header.txt") continue;
                if (low == "thumbs.db" || low == "desktop.ini" || low == ".ds_store") continue;
                if (low.StartsWith("~ffaa_")) continue;
                files[rel] = p;
                mtimes[rel] = File.GetLastWriteTime(p);
            }

            MemoryStream body = new MemoryStream(1024 * 1024);
            List<byte[]> cds = new List<byte[]>();
            HashSet<string> used = new HashSet<string>(StringComparer.Ordinal);
            uint uid = 1001, gid = 1001;

            if (tpl != null && tpl.Count > 0)
            {
                // inherit uid/gid from the template extra field when possible
                foreach (FfaaEntry e in tpl)
                {
                    if (e.LExtra != null && e.LExtra.Length >= 11)
                    {
                        for (int i = 0; i + 4 <= e.LExtra.Length - 4; i++)
                        {
                            if (e.LExtra[i] == 0x75 && e.LExtra[i + 1] == 0x78 && e.LExtra[i + 2] == 0x0B && e.LExtra[i + 3] == 0x00)
                            {
                                int p2 = i + 4;
                                if (p2 + 11 <= e.LExtra.Length && e.LExtra[p2] == 1 && e.LExtra[p2 + 1] == 4)
                                {
                                    uid = (uint)(e.LExtra[p2 + 2] | (e.LExtra[p2 + 3] << 8) | (e.LExtra[p2 + 4] << 16) | (e.LExtra[p2 + 5] << 24));
                                    if (e.LExtra[p2 + 6] == 4)
                                        gid = (uint)(e.LExtra[p2 + 7] | (e.LExtra[p2 + 8] << 8) | (e.LExtra[p2 + 9] << 16) | (e.LExtra[p2 + 10] << 24));
                                }
                                break;
                            }
                        }
                    }
                }

                foreach (FfaaEntry e in tpl)
                {
                    if (e.IsDir)
                    {
                        long lhoD = body.Length;
                        body.Write(e.Lh, 0, e.Lh.Length);
                        body.Write(e.LName, 0, e.LName.Length);
                        body.Write(e.LExtra, 0, e.LExtra.Length);
                        cds.Add(PatchCd(e.Cd, lhoD, e.Crc, e.CSize, e.USize, e.Method, e.Vne));
                        used.Add(e.Name);
                        res.Same++;
                        continue;
                    }

                    if (!files.ContainsKey(e.Name))
                    {
                        res.Removed++;
                        continue;
                    }

                    string path = files[e.Name];
                    byte[] raw = File.ReadAllBytes(path);

                    if (raw.Length == e.USize && Crc32(raw) == e.Crc)
                    {
                        long lho = body.Length;
                        body.Write(e.Lh, 0, e.Lh.Length);
                        body.Write(e.LName, 0, e.LName.Length);
                        body.Write(e.LExtra, 0, e.LExtra.Length);
                        body.Write(e.CData, 0, e.CData.Length);
                        cds.Add(PatchCd(e.Cd, lho, e.Crc, e.CSize, e.USize, e.Method, e.Vne));
                        used.Add(e.Name);
                        res.Same++;
                    }
                    else
                    {
                        int meth = (e.Method == 0 || e.Method == 8) ? e.Method : 8;
                        byte[] cdata;
                        if (meth == 8)
                        {
                            cdata = Deflate(raw);
                            if (cdata.Length >= raw.Length) { meth = 0; cdata = raw; }
                        }
                        else
                        {
                            cdata = raw;
                            byte[] z = Deflate(raw);
                            if (z.Length < raw.Length) { meth = 8; cdata = z; }
                        }
                        uint crc = Crc32(raw);
                        long lho = body.Length;
                        byte[] lh = (byte[])e.Lh.Clone();
                        W16(lh, 8, meth);
                        W32(lh, 14, crc);
                        W32(lh, 18, cdata.Length);
                        W32(lh, 22, raw.Length);
                        body.Write(lh, 0, lh.Length);
                        body.Write(e.LName, 0, e.LName.Length);
                        body.Write(e.LExtra, 0, e.LExtra.Length);
                        body.Write(cdata, 0, cdata.Length);
                        cds.Add(PatchCd(e.Cd, lho, crc, cdata.Length, raw.Length, meth, meth == 8 ? 20 : 10));
                        used.Add(e.Name);
                        res.Changed++;
                    }
                }
            }

            // ---- append entries that are not in the template ----
            List<string> extra = new List<string>();
            foreach (string k in files.Keys)
                if (!used.Contains(k)) extra.Add(k);
            extra.Sort(StringComparer.Ordinal);

            foreach (string name in extra)
            {
                string path = files[name];
                byte[] raw = File.ReadAllBytes(path);
                byte[] nb = Encoding.GetEncoding(28591).GetBytes(name);
                int tm, dt;
                DosTime(mtimes[name], out tm, out dt);
                long unix = (long)(mtimes[name].ToUniversalTime() - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;

                byte[] cdata = Deflate(raw);
                int meth = 8;
                if (cdata.Length >= raw.Length) { meth = 0; cdata = raw; }
                uint crc = Crc32(raw);
                byte[] lextra = UnixExtra(unix, uid, gid, false);
                byte[] cextra = UnixExtra(unix, uid, gid, true);
                long lho = body.Length;

                byte[] lh = new byte[30];
                W32(lh, 0, 0x04034B50);
                W16(lh, 4, meth == 8 ? 20 : 10);
                W16(lh, 6, 0);
                W16(lh, 8, meth);
                W16(lh, 10, tm);
                W16(lh, 12, dt);
                W32(lh, 14, crc);
                W32(lh, 18, cdata.Length);
                W32(lh, 22, raw.Length);
                W16(lh, 26, nb.Length);
                W16(lh, 28, lextra.Length);
                body.Write(lh, 0, lh.Length);
                body.Write(nb, 0, nb.Length);
                body.Write(lextra, 0, lextra.Length);
                body.Write(cdata, 0, cdata.Length);

                byte[] cd = new byte[46];
                W32(cd, 0, 0x02014B50);
                W16(cd, 4, 0x031E);
                W16(cd, 6, meth == 8 ? 20 : 10);
                W16(cd, 8, 0);
                W16(cd, 10, meth);
                W16(cd, 12, tm);
                W16(cd, 14, dt);
                W32(cd, 16, crc);
                W32(cd, 20, cdata.Length);
                W32(cd, 24, raw.Length);
                W16(cd, 28, nb.Length);
                W16(cd, 30, cextra.Length);
                W16(cd, 32, 0);
                W16(cd, 34, 0);
                W16(cd, 36, 0);
                W32(cd, 38, 0x81A40000);
                W32(cd, 42, lho);
                MemoryStream cdm = new MemoryStream();
                cdm.Write(cd, 0, cd.Length);
                cdm.Write(nb, 0, nb.Length);
                cdm.Write(cextra, 0, cextra.Length);
                cds.Add(cdm.ToArray());
                res.Added++;
            }

            long cdOff = body.Length;
            long cdSize = 0;
            foreach (byte[] c in cds) cdSize += c.Length;
            foreach (byte[] c in cds) body.Write(c, 0, c.Length);

            byte[] eocd = new byte[22];
            W32(eocd, 0, 0x06054B50);
            W16(eocd, 4, 0);
            W16(eocd, 6, 0);
            W16(eocd, 8, cds.Count);
            W16(eocd, 10, cds.Count);
            W32(eocd, 12, cdSize);
            W32(eocd, 16, cdOff);
            W16(eocd, 20, 0);
            body.Write(eocd, 0, eocd.Length);

            byte[] zip = body.ToArray();
            res.Entries = cds.Count;
            res.IsFfaa = isFfaa;

            if (zip.Length < 22 || zip[0] != 0x50 || zip[1] != 0x4B)
                throw new Exception("internal error: produced payload is not a ZIP");

            byte[] blob;
            if (isFfaa)
            {
                byte[] hb = Encoding.GetEncoding(28591).GetBytes(header);
                byte[] ob = Obfuscate(zip);
                blob = new byte[hb.Length + ob.Length];
                Buffer.BlockCopy(hb, 0, blob, 0, hb.Length);
                Buffer.BlockCopy(ob, 0, blob, hb.Length, ob.Length);
                string[] hp = header.TrimEnd('\n').Split('\n');
                if (hp.Length >= 3 && hp[0] == "FFAA" && hp[hp.Length - 1] == "FFAA")
                    res.Header = string.Join(" | ", hp, 1, hp.Length - 2);
                else
                    res.Header = header.Replace("\n", " | ").Trim(' ', '|');
            }
            else
            {
                blob = zip;
            }
            res.Data = blob;

            if (verify && isFfaa)
            {
                int h2 = HeaderEnd(blob);
                if (h2 < 0) throw new Exception("verification failed: header unreadable");
                byte[] back = Deobfuscate(blob, h2);
                List<FfaaEntry> chk = ParseZip(back);
                if (chk.Count != cds.Count)
                    throw new Exception("verification failed: entry count " + chk.Count + " != " + cds.Count);
                foreach (FfaaEntry e in chk)
                {
                    if (e.IsDir || e.Method == 0 && e.CSize == 0) continue;
                    byte[] decoded = e.Method == 8 ? Inflate(e.CData, (int)e.USize) : e.CData;
                    if (decoded.Length != e.USize)
                        throw new Exception("verification failed: size mismatch on " + e.Name);
                    if (Crc32(decoded) != e.Crc)
                        throw new Exception("verification failed: CRC mismatch on " + e.Name);
                }
            }

            res.Ok = true;
            return res;
        }
        catch (Exception ex)
        {
            res.Ok = false;
            res.Error = ex.Message;
            return res;
        }
    }

    public static string Describe(byte[] d)
    {
        if (LooksFfaa(d))
        {
            int h = HeaderEnd(d);
            if (h > 0)
            {
                string t = Encoding.GetEncoding(28591).GetString(d, 0, h);
                return "FFAA, header " + h + " bytes";
            }
        }
        return "plain ZIP";
    }
}
'@

try {
    Add-Type -TypeDefinition $cs -ReferencedAssemblies "System.IO.Compression" -ErrorAction Stop
}
catch {
    Write-Host "  [X] Failed to compile the packed engine: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "      Requires .NET 4.5 or newer (Windows 8 / Server 2012 and above)."
    exit 1
}

function Write-Line([string]$Text, [string]$Color = "") {
    if ($Quiet) { return }
    if ($Color) { Write-Host $Text -ForegroundColor $Color } else { Write-Host $Text }
}

function Resolve-Template([string]$Folder, [string]$Explicit) {
    if ($Explicit) {
        if (Test-Path -LiteralPath $Explicit) { return (Resolve-Path -LiteralPath $Explicit).Path }
        return $null
    }
    $parent = Split-Path -Parent $Folder
    $leaf = Split-Path -Leaf $Folder
    $cand = Join-Path $parent ($leaf + ".zip")
    if (Test-Path -LiteralPath $cand) { return (Resolve-Path -LiteralPath $cand).Path }
    return $null
}

function Get-FreePath([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $Path }
    $dir = Split-Path -Parent $Path
    $base = [IO.Path]::GetFileNameWithoutExtension($Path)
    $ext = [IO.Path]::GetExtension($Path)
    for ($i = 1; $i -lt 1000; $i++) {
        $p = Join-Path $dir ("{0}_{1}{2}" -f $base, $i, $ext)
        if (-not (Test-Path -LiteralPath $p)) { return $p }
    }
    return $Path
}

function Invoke-Pack([string]$Folder) {
    $Folder = $Folder.TrimEnd('\', '/')
    Write-Line ""
    Write-Line ("  [*] " + (Split-Path -Leaf $Folder)) "Cyan"

    $tplPath = Resolve-Template $Folder $Template
    $headerFile = Join-Path $Folder "ffaa_header.txt"
    $headerText = $null
    if (Test-Path -LiteralPath $headerFile) {
        $headerText = [IO.File]::ReadAllText($headerFile)
    }

    $r = [FfaaPack]::Pack($Folder, $tplPath, $headerText, $Version, $Plain.IsPresent, (-not $NoVerify.IsPresent))

    if (-not $r.Ok) {
        Write-Line ("  [X] " + $r.Error) "Red"
        return $false
    }

    if ($Out) {
        $outPath = $Out
        if ((Test-Path -LiteralPath $Folder -PathType Container) -and (Test-Path -LiteralPath $Out -PathType Container)) {
            $outPath = Join-Path $Out ((Split-Path -Leaf $Folder) + "_repack.zip")
        }
    }
    else {
        $parent = Split-Path -Parent $Folder
        $leaf = Split-Path -Leaf $Folder
        $outPath = Get-FreePath (Join-Path $parent ($leaf + "_repack.zip"))
    }

    [IO.File]::WriteAllBytes($outPath, $r.Data)

    if ($tplPath) {
        $tplDesc = [FfaaPack]::Describe([IO.File]::ReadAllBytes($tplPath))
        Write-Line ("       template  : " + (Split-Path -Leaf $tplPath) + "  (" + $tplDesc + ")")
    }
    else {
        Write-Line "       template  : none (built from scratch)"
    }
    if ($r.IsFfaa) {
        Write-Line ("       header    : " + $r.Header)
    }
    Write-Line ("       entries   : " + $r.Entries + "   same " + $r.Same + ", changed " + $r.Changed + ", added " + $r.Added + ", removed " + $r.Removed)
    if (-not $NoVerify) {
        if ($r.IsFfaa) {
            Write-Line "       verify    : OK  (decoded again, all CRCs match)" "Green"
        }
        else {
            Write-Line "       verify    : skipped (plain ZIP output)"
        }
    }
    if ($r.Warning) {
        Write-Line ("       warning   : " + $r.Warning) "Yellow"
    }
    $sizeText = "{0:N0}" -f $r.Data.Length
    Write-Line ("  [OK] " + (Split-Path -Leaf $outPath) + "   " + $sizeText + " bytes") "Green"
    Write-Line ("       output    : " + $outPath)
    return $true
}

Write-Line ""
Write-Line "  ============================================================"
Write-Line "     FFAA firmware repacker   v1.0"
Write-Line "     folder  ->  FFAA container  (byte-identical when unchanged)"
Write-Line "  ============================================================"

if (-not $Targets -or $Targets.Count -eq 0) {
    Write-Line ""
    Write-Line "  Usage:"
    Write-Line "     drag one or more folders onto FFAA-Pack.bat"
    Write-Line "     or: powershell -ExecutionPolicy Bypass -File ffaa_pack.ps1 <folder>"
    Write-Line ""
    Write-Line "  A folder next to its original archive is repacked byte-identically."
    Write-Line "  Output name: <folder>_repack.zip (never overwrites the original)."
    exit 2
}

$okCount = 0
$failCount = 0
foreach ($t in $Targets) {
    if (-not (Test-Path -LiteralPath $t)) {
        Write-Line ("  [X] not found: " + $t) "Red"
        $failCount++
        continue
    }
    $item = Get-Item -LiteralPath $t
    if ($item.PSIsContainer) {
        if (Invoke-Pack $item.FullName) { $okCount++ } else { $failCount++ }
    }
    else {
        Write-Line ("  [X] not a folder: " + $item.Name + "  (extract it first)") "Red"
        $failCount++
    }
}

Write-Line ""
if ($okCount + $failCount -gt 1) {
    Write-Line ("  done: " + $okCount + " ok, " + $failCount + " failed")
}
if ($failCount -gt 0) { exit 1 }
exit 0
