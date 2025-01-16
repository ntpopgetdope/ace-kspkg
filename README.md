# ace-kspkg
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/ntpopgetdope/ace-kspkg/blob/main/README.md) ![Version](https://img.shields.io/badge/version-0.0.1-green) [![Build Target](https://img.shields.io/badge/Assetto%20Corsa%20Evo%20Build-0x312E30-red)](https://steamdb.info/depot/3058631/history/?changeid=M:4846019878964622002) [![Steam](https://img.shields.io/badge/steam-%23000000.svg?&logo=steam&logoColor=white)](https://store.steampowered.com/app/3058630)

**Assetto Corsa Evo: Kunos Package (kspkg) Extraction Tool**
![](https://i.imgur.com/mJTLleu.gif)

All initial reverse engineering was performed on 16/01/25 against following build of AssettoCorsaEVO.exe
> ```
> build release 0x312e30, version 250116_022721, revision 9468f152c075f15ff3c58a38bc724f8e4e6546a4,
> built 16/01/2025 02:28:31, manifest 4846019878964622002, SHA-1 59c3a7a623f7a83bc3bc2c39d11222e5e8dce453
> ```

## Cmdline Usage
```bash
usage: parse_kspkg.py [-h] [-l] [-i PATH] [-a | -p PATH] [-o PATH] [-r]

Assetto Corsa Evo: Kunos Package (kspkg) Extraction Tool

options:
  -h, --help            show this help message and exit
  -l, --list            List all files packed within parsed KsPkg
  -i PATH, --in PATH    Path to KsPkg file (default: content.kspkg)

extract:
  -a, --all             Extract all files within parsed KsPkg
  -p PATH, --path PATH  Extract a single file by path in KsPkg
  -o PATH, --out PATH   Path to extract KsPkg to (default: content)
  -r, --run-unpacked    Force AC:Evo to run the unpacked content
```
**Only list files within the KsPkg file table**<br>
`python parse_kspkg.py --list`

**Extract & force AC:Evo to utilise unpacked files**<br>
`python parse_kspkg.py --all --run-unpacked`

**Extract single file from KsPkg by content path**<br>
`python parse_kspkg.py --path "content\cars\ks_honda_s2000_ap1\data\cardata.car"`

## Format Internals

Kunos Package (KsPkg) files are used to package all AC:Evo game assets into a single "content.kspkg" file. The files consist of linear binary blobs optionally XOR'd with the key `0x9F9721A97D1135C1`, the binary blobs are suffixed by a statically sized `0x2000000` byte (32mb) "File Table" describing the offset, size, extracted path & type of each file via a `0x100` byte structure allowing for a maximum of `0x20000` file entries. Currently the File Table structure is also XOR'd using the same static key as before, more details regarding this process & obtaining the XOR key are outlined below...

### Static XOR Key
Normally, the XOR key used to uncipher KsPkg contents is fetched by the `ResourceManager` class via a `uint64_t` sized field at offset `0x758` and as a result it can be trivially obtained using either of the following two methods:
![](https://i.imgur.com/ilvr2pS.png)
**Dump ResourceManager XOR Key @ Runtime**
> `bp AssettoCorsaEVO+140b65c ".printf /D \"Resource Manager XOR Key %%I64x\", @r8; g"`

**XOR Key via Known-Null Byte Analysis**<br>
> Because Kunos statically sized the File Table to `0x2000000` bytes, we know it must be 0-padded to facilitate future additions etc. Knowing that `KEYMAT ^ 0` == `KEYMAT`, the static 8-byte XOR key becomes an obvious pattern throughout KsPkg file in-place of NULLs... This is used by reimplementation to retrieve key statically.

![](https://i.imgur.com/JUpaQaV.png)

### Root File Table
sizeof(`FileTable`) == `0x2000000`
```c
KsPkgFileTableEntry FileTable[0x20000];
```

### File Table Entry
sizeof(`KsPkgFileTableEntry`) == `0x100`
```c
typedef struct _KsPkgFileTableEntry
{
    char           file_path[0xE0];
    int32_t        aligmt_E0;
    KsPkgFileFlags inf_flags;
    int16_t        path_leng;
    uint64_t       path_fnv1;
    uint64_t       file_size;
    uint64_t       file_offs;
} KsPkgFileTableEntry;
```

### File Info Bitflags
sizeof(`KsPkgFileFlags`) == `0x2`
```c
typedef enum _KsPkgFileFlags : uint16_t
{
    Directory = (1 << 0),
    XorCipher = (1 << 8),
} KsPkgFileFlags;
```

## WinDbg Commands

### ResourceManager::ReadPackedFile (Offset: `0x1413360`)
![](https://i.imgur.com/HIzFjKj.png)

**Log file individual file accesses from KsPkg**
> `bp AssettoCorsaEVO+141371b ".printf /D \"Reading file %ma\", poi(@rax); g"`<br>
> `bp AssettoCorsaEVO+1413728 ".printf /D \" from packedfile %ma\\n\", poi(@rax); g"`

### ResourceManager::ParseKsPkgPackedContent (Offset: `0x140F120`)
![](https://i.imgur.com/d84YEcq.png)

**Dump XOR ciphered file table from KsPkg**
> `bp AssettoCorsaEVO+140f1b1 ".printf /D \"Pkg File Table Buffer %ma\", @rax"`<br>
> `.writemem pkg_file_tbl_xor_ciphertxt.bin @rax L?0x2000000; g`

**Dump unXOR'd plaintext file table from KsPkg**
> `bp AssettoCorsaEVO+140f1b1 ".writemem pkg_file_tbl_xor_plaintxt.bin @rax L?0x2000000; g"`
