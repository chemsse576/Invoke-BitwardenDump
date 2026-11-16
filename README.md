# Invoke-BitwardenDump

Post-exploitation tool for extracting Bitwarden desktop vault credentials on Windows. Pure PowerShell + .NET P/Invoke — zero external dependencies, single file.

## Disclaimer

> **This tool is intended for authorized penetration testing and security research only.**
>
> You must have explicit written authorization before using this tool against any system you do not own. Unauthorized access to computer systems is illegal under the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, and equivalent laws worldwide.
>
> The authors assume no liability for misuse. **Use responsibly and legally.**

## Attack Surface

Bitwarden Desktop (Electron) with auto-unlock enabled stores the **UserKey** (64 bytes: AES-256 EncKey + HMAC-SHA256 MacKey) in the Windows Credential Manager via its Rust napi module. The key is protected by DPAPI — any process running as the target user can read it. Combined with the encrypted vault cached in `data.json`, this enables full offline decryption without the master password.

**Decryption chain:**
```
Credential Manager (DPAPI) → UserKey (64B)
    → AES-256-CBC + HMAC-SHA256 → RSA Private Key (PKCS8)
    → RSA-OAEP-SHA1 → Organization Keys (if any)
    → AES-256-CBC + HMAC-SHA256 → Vault Entries (name, URL, username, password)
```

## Features

| Mode | Description |
|------|-------------|
| `-Recon` | Enumerate Bitwarden processes, desktop app version, `data.json` analysis, browser extensions (Chrome/Brave/Edge/Firefox), Credential Manager entries, LevelDB key scan, attack path recommendations |
| `-Dump` | Live memory dump of the Bitwarden renderer process — extracts plaintext credentials via regex pattern matching (URL/username/password proximity, JSON structures) |
| `-Offline` | **Primary attack** — Extracts UserKey from Credential Manager, decrypts RSA private key, then decrypts all cached vault ciphers from `data.json`. Works when auto-unlock is enabled (vault timeout = "never") |
| `-ParseDump` | Parse a previously saved memory dump file for credentials |
| `-All` | Full chain: Recon → auto-select best attack (Offline if auto-unlock key found, Dump otherwise) |

## Usage

```powershell
# Reconnaissance — enumerate attack surface
.\Invoke-BitwardenDump.ps1 -Recon

# Offline vault decryption (requires auto-unlock enabled)
.\Invoke-BitwardenDump.ps1 -Offline

# Offline with JSON export
.\Invoke-BitwardenDump.ps1 -Offline -OutputFile vault.json

# Memory dump (auto-detect largest Bitwarden process)
.\Invoke-BitwardenDump.ps1 -Dump

# Memory dump targeting specific PID
.\Invoke-BitwardenDump.ps1 -Dump -TargetPid 12345

# Memory dump + save raw dump to disk
.\Invoke-BitwardenDump.ps1 -Dump -SaveDump

# Parse a saved dump file
.\Invoke-BitwardenDump.ps1 -ParseDump C:\path\to\dump.bin

# Full auto chain (Recon + best attack)
.\Invoke-BitwardenDump.ps1 -All

# Self-hosted Bitwarden instance
.\Invoke-BitwardenDump.ps1 -Offline -ApiUrl https://bitwarden.corp.local
```

## Requirements

- Windows 10/11
- PowerShell 5.1+ (built-in)
- Same user context as the Bitwarden desktop app (no admin required)
- Bitwarden Desktop with auto-unlock enabled (for `-Offline` mode)

## Output

Console output shows decrypted entries with name, URL, username, and password. The `-OutputFile` flag exports results as JSON:

```json
[
  {
    "Name": "example.com",
    "Type": 1,
    "URL": "https://example.com/login",
    "Username": "user@example.com",
    "Password": "s3cret!",
    "OrgId": null
  }
]
```

## Technical Details

### Credential Manager Storage

Bitwarden stores the auto-unlock key as:
- **Target**: `Bitwarden_auto/{userId}_user_auto`
- **Blob**: UTF-16LE encoded JSON string containing base64-encoded UserKey (with surrounding quotes)
- **Protection**: Windows DPAPI (transparent to any process running as the same user)

### EncString Format

Bitwarden uses typed encrypted strings:
- **Type 2**: `2.{IV_b64}|{CT_b64}|{MAC_b64}` — AES-256-CBC + HMAC-SHA256 (symmetric)
- **Type 4**: `4.{CT_b64}` — RSA-2048-OAEP-SHA1 (asymmetric, used for org keys)

### data.json Modern Format

Recent versions use flat keys:
```
global_account_activeAccountId → user ID
user_{uid}_crypto_accountCryptographicState → V1.private_key (EncString)
user_{uid}_ciphers_ciphers → encrypted vault entries
user_{uid}_crypto_organizationKeys → org-specific encryption keys
user_{uid}_kdfConfig_kdfConfig → KDF parameters
```

## Detection

For blue teams — indicators of this technique:
- Process accessing `Bitwarden_auto/*` credential entries via `CredRead`/`CredEnumerate`
- Non-Bitwarden process reading `%APPDATA%\Bitwarden\data.json`
- `ReadProcessMemory` calls targeting Bitwarden.exe from an external process
- PowerShell loading `Add-Type` with `System.Runtime.InteropServices` for credential/memory APIs

## Mitigations

- Disable auto-unlock (set vault timeout to lock on idle/sleep)
- Use biometric unlock instead of auto-unlock where possible
- Monitor Credential Manager access for anomalous readers
- Application whitelisting / PPL on Bitwarden process
- Credential Guard to protect DPAPI keys

## License

MIT — see [LICENSE](LICENSE).
