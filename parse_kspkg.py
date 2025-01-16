import io
import time
import enum
import struct
import pathlib
import argparse

#            twitter.com/@ntpopgetdope     
#        github.com//ntpopgetdope/ace-kspkg 
# ------------------------------------------------
# All reverse engineering peformed on the 16/01/25
# against following version of AssettoCorsaEVO.exe
# ------------------------------------------------
# Build release 0x312e30, version 250116_022721, 
# revision 9468f152c075f15ff3c58a38bc724f8e4e6546a4, 
# steam appid 3058630, built on Jan 16 2025, 02:28:31


class FnvHash:
    FNV_64_PRIME = 0x100000001B3
    FNV1_64A_OFF = 0xCBF29CE484222325
    # http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-1a

    @staticmethod
    def fnv1a_64(data):
        assert isinstance(data, bytes)
        h = FnvHash.FNV1_64A_OFF
        for b in data:
            h = ((h ^ b) * FnvHash.FNV_64_PRIME) % (2 ** 64)
        return h

# ------------------------------------------------------------------------------------------

class KsPckFile:
    FILE_PATH_SZ = 0xE0

    class FileFlags(enum.IntFlag):
        Directory = (1 << 0),
        XorCipher = (1 << 8),

    def __init__(self, raw: bytes):
        self.raw = io.BytesIO(raw)
        max_path = self.FILE_PATH_SZ

        # Unpacking of these happens @ 0x14140f50b within the main parse loop.
        self.file_path = struct.unpack(f"<{max_path}s",  self.raw.read(max_path))[0] # +0x00
        self.align_0E0 = struct.unpack("<i", self.raw.read(struct.calcsize("i")))[0] # +0xE0
        self.inf_flags = struct.unpack("<h", self.raw.read(struct.calcsize("h")))[0] # +0xE4
        self.path_leng = struct.unpack("<h", self.raw.read(struct.calcsize("h")))[0] # +0xE6
        # FNV1A-64 hash of the file path used to order file table entries 
        self.path_fnv1 = struct.unpack("<Q", self.raw.read(struct.calcsize("Q")))[0] # +0xE8
        self.file_size = struct.unpack("<q", self.raw.read(struct.calcsize("q")))[0] # +0xF0
        self.file_offs = struct.unpack("<q", self.raw.read(struct.calcsize("q")))[0] # +0xF8
                                                                                     # +0x100
        # Cleanup path removing trailing nulls & map bitflags to IntFlag.
        self.file_path = str(self.file_path[:self.path_leng].decode())
        self.inf_flags = KsPckFile.FileFlags(self.inf_flags)
        return

class KsPck:
    FILE_TBL_SZ = (2 << 24)
    FILE_ITM_SZ = (1 << 8)

    def __init__(self, kspck_path: str):
        print(f"Parsing input KsPkg file: '{kspck_path}'")
        self.files: dict[int, KsPckFile] = {}
        self.kspck = open(kspck_path, "rb")
        self.xork = None
        self.ftbl = None
        return
    
    def __exit__(self):
        self.kspck.close()
        return
    
    @staticmethod
    def xor_8b_cipher(buffer: bytes|bytearray, xork: bytes) -> bytearray:
        # Need a mutable view of buffer.
        if isinstance(buffer, bytes): 
            buffer = bytearray(buffer)
    
        for i, b in enumerate(buffer):
            buffer[i] ^= xork[i % 8]

        # Return ciphertext.
        return buffer

    def parse_file_tbl(self, save_ftbl: bool=False) -> None:
        # 0x14140f2ce "ResourceManager::ParseKsPkgPackedContent"
        # 0x14140f2ce -> std::basic_istream<char,struct std::char_traits<char> >::seekg(&ios, -0x2000000, SEEK_END);
        # 0x14140f2e2 -> std::basic_istream<char,struct std::char_traits<char> >::read(&ios, pkg_file_tbl, 0x2000000);
        self.kspck.seek(-self.FILE_TBL_SZ, 2)
        self.ftbl = self.kspck.read(self.FILE_TBL_SZ)

        # [NOTE] KsPkg file tables are obfuscated with stupid SIMD optimised XOR cipher (sub_14140b650)
        # obvious due to repeated 0 pad patterns :@ end of region, we can get the XOR key for free...
        # j_ResourceManager::XorBufferSimd(rsrc_mgr, pck_file_tbl, tbl_size_bytes: 0x2000000)
        # rcx: pkg_file_tbl, rdx: 0x2000000, r8: 0x9F9721A97D1135C1 (key; swap endianness)

        # XOR key usually obtained via *(rsrc_mgr + 0x758)
        self.xork = self.ftbl[-8:] # Valid if nulls...
        ascii = ''.join(f"{b:02X}" for b in self.xork)
        print(f"File Table XOR Key: {ascii}")
        print(f"Unciphering KsPkg file table...\n")

        # Obtain plaintext file table.
        self.ftbl = bytearray(self.ftbl)
        self.ftbl = self.xor_8b_cipher(self.ftbl, self.xork)
        
        if save_ftbl: # Optionally save plaintext to disk.
            with open(f"{self.kspck.name}.unxor_file_table.bin", "wb") as f:
                # Good SHA-1: f55c845e896366014e614267ec0936ff8f237c9e
                f.write(self.ftbl)

        # Enumerate all file table entries in the KsPkg (sized @ 256 bytes each)
        for i in range(0, int(self.FILE_TBL_SZ / self.FILE_ITM_SZ)):
            # Unpack file entry struct to pythonic class wrapper.
            idx = i * self.FILE_ITM_SZ # Index in 0x100 bounds.
            file_entry = self.ftbl[idx : idx + self.FILE_ITM_SZ]
            file_entry = KsPckFile(file_entry)

            # Logic @ 0x14140f338 which breaks
            # parse loop upon NULL FNV1-A hash:
            if file_entry.path_fnv1 == 0:
                break
            
            # Store by hash for later operations/lookup.
            self.files[file_entry.path_fnv1] = file_entry
        # Done.
        return 

    def extract_internal(self, file: KsPckFile, out_path: str):
        path = pathlib.Path(file.file_path)
        # Handle non-default extraction path.
        if out_path.casefold() != "content":
            path = pathlib.Path(out_path) / path
        
        # If file entry is a directory, create path & exit.
        if KsPckFile.FileFlags.Directory in file.inf_flags:
            path.mkdir(parents=True, exist_ok=True)
            return

        # Otherwise continue processing as a file.
        path.parent.mkdir(parents=True, exist_ok=True)

        # Read packed from relative to offset.
        self.kspck.seek(file.file_offs, 0)
        data = self.kspck.read(file.file_size)

        # Handle files which use the static XOR ciphering.
        if KsPckFile.FileFlags.XorCipher in file.inf_flags:
            data = self.xor_8b_cipher(data, self.xork)

        # Write processed data to unpacked file dir.
        with open(path, "wb") as f:
            f.write(data)

    def extract_file(self, file_path: str, out_path: str) -> None:
        lookup = file_path.casefold().replace('/', '\\')
        print(f"Extracting single KsPkg file '{lookup}'...")
        
        fnv1a = FnvHash.fnv1a_64(lookup.encode())
        file  = self.files.get(fnv1a) 

        if not file:
            print(f"File lookup by FNV1A-64 0x{fnv1a:04x} failed")
            return
        
        # Otherwise, extract located single file.
        self.extract_internal(file, out_path)
    
    def extract_all(self, out_path: str) -> None:
        print(f"Extracting {len(self.files)} total KsPkg files...")
        start_time = time.perf_counter()

        # Extract all KsPkg file entries to disk...
        # Good SHA-1: 26c9b2a3517c1a1bc2da9e149499c60f34148ad1-00005ACC
        #             737b6571b6420d6a3530a5912033c109f52d94aa-0000751E
        for i, f in enumerate(self.files.values()):
            print(
                f"  [{i+1:03d}/{len(self.files):03d}] " \
                f"0x{f.file_size:08X} bytes: {f.file_path}"
            )
            # Very slow... could do with multithreading and
            # handling of sync issues around file seek etc.
            # [TODO] GoLang port of this entire script lol
            self.extract_internal(f, out_path)
        
        # Finished extraction.
        print(
            f"Extracted {len(self.files)} files in "   \
            f"{time.perf_counter() - start_time:.3f} " \
            f"seconds."
        )

    def list_all(self):
        for i, f in enumerate(self.files.values()):
            print(
                f"KsPkg File #{i}\n"                  \
                f"  -> Path:   {f.file_path}\n"       \
                f"  -> Flags:  {f.inf_flags.name}\n"  \
                f"  -> FNV1A:  0x{f.path_fnv1:08X}\n" \
                f"  -> Size:   0x{f.file_size:08x}\n" \
                f"  -> Offset: 0x{f.file_offs:08x}\n"
            )

    def run_unpacked(self):
        try:
            # N.B. must close internal file
            # handle before renaming it....
            if self.kspck: self.kspck.close()

            print(f"Forcing AC:Evo to use unpacked content...")
            # AC:Evo will run from unpacked resources if the 
            # content.kspkg file cannot be resolved in curdir.
            ace_kspkg = pathlib.Path(self.kspck.name).resolve()
            if ace_kspkg.exists() and ace_kspkg.is_file():
                ace_kspkg.rename(f"{ace_kspkg}.bkup")

        except PermissionError as e:
            print(f"Unable to rename KsPkg, exception: {e}")

# ------------------------------------------------------------------------------------------

def init_argparse() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Assetto Corsa Evo: Kunos Package (kspkg) Extraction Tool",
        epilog="https://github.com/ntpopgetdope/ace-kspkg"
    ); 
    
    parser.add_argument(
        "-l", "--list", action="store_true",
        help="List all files packed within parsed KsPkg"
    )
    parser.add_argument(
        "-i", "--in", type=str, default="content.kspkg", metavar="PATH", 
        help=f"Path to KsPkg file (default: content.kspkg)"
    )

    ex = parser.add_argument_group("extract")
    # Exclusive options for all/single file extraction...
    exopt = ex.add_mutually_exclusive_group()
    exopt.add_argument(
        "-a", "--all", action="store_true",
        help="Extract all files within parsed KsPkg"
    )
    exopt.add_argument(
        "-p", "--path", type=str, metavar="PATH",
        help="Extract a single file by path in KsPkg"
    )

    # Non-exclusive extraction options...
    ex.add_argument(
        "-o", "--out", type=str, default="content", metavar="PATH", 
        help="Path to extract KsPkg to (default: content)"
    )
    ex.add_argument(
        "-r", "--run-unpacked", action="store_true",
        help="Force AC:Evo to run the unpacked content"
    )

    # Return file parser.
    return parser

# ------------------------------------------------------------------------------------------

if __name__ == "__main__":
    print(
        f"Assetto Corsa Evo: Kunos Package (kspkg) Extraction Tool\n"
        f"           github.com//ntpopgetdope/ace-kspkg\n"
        f"               twitter.com/@ntpopgetdope\n"
    )
    parser = init_argparse()
    args = parser.parse_args()
    
    # Require at least one option specified (unpack overrides behaviour)
    if not any([args.list, args.all, args.path, args.run_unpacked]):
        parser.print_help()
        exit(0)

    pck = KsPck("content.kspkg")
    pck.parse_file_tbl()

    if args.list:
        pck.list_all()
    
    if args.all or args.run_unpacked:
        pck.extract_all(args.out)
    elif args.path: # Single file extraction.
        pck.extract_file(args.path, args.out)

    if args.run_unpacked:
        pck.run_unpacked()
