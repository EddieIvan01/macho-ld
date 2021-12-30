use libc::{vm_address_t, vm_map_t, vm_prot_t, vm_size_t};
use std::ffi::c_void;

pub const MH_OBJECT: u32 = 1;
pub const MH_EXECUTE: u32 = 2;
pub const MH_FVMLIB: u32 = 3;
pub const MH_CORE: u32 = 4;
pub const MH_PRELOAD: u32 = 5;
pub const MH_DYLIB: u32 = 6;
pub const MH_DYLINKER: u32 = 7;
pub const MH_BUNDLE: u32 = 8;
pub const MH_DYLIB_STUB: u32 = 9;
pub const MH_DSYM: u32 = 10;
pub const MH_KEXT_BUNDLE: u32 = 11;

pub const FAT_MAGIC: u32 = 0xcafebabe;
pub const FAT_CIGAM: u32 = 0xbebafeca; /* NXSwapLong(FAT_MAGIC) */

pub const CPU_TYPE_X86: i32 = 7;
pub const CPU_TYPE_I386: i32 = CPU_TYPE_X86;
pub const CPU_TYPE_X86_64: i32 = (CPU_TYPE_X86 | CPU_ARCH_ABI64);
pub const CPU_TYPE_MC98000: i32 = 10;
pub const CPU_TYPE_HPPA: i32 = 11;
pub const CPU_TYPE_ARM: i32 = 12;
pub const CPU_TYPE_ARM64: i32 = (CPU_TYPE_ARM | CPU_ARCH_ABI64);
pub const CPU_TYPE_MC88000: i32 = 13;
pub const CPU_TYPE_SPARC: i32 = 14;
pub const CPU_TYPE_I860: i32 = 15;
pub const CPU_TYPE_POWERPC: i32 = 18;
pub const CPU_TYPE_POWERPC64: i32 = CPU_TYPE_POWERPC | CPU_ARCH_ABI64;
pub const CPU_ARCH_ABI64: i32 = 0x01000000;

pub const MH_HAS_TLV_DESCRIPTORS: u32 = 0x00800000;
pub const SECTION_TYPE: u32 = 0x000000ff;
pub const S_THREAD_LOCAL_VARIABLES: u32 = 0x13;

pub const LC_REQ_DYLD: u32 = 0x80000000;
/* Constants for the cmd field of all load commands, the type */
pub const LC_SEGMENT: u32 = 0x1; /* segment of this file to be mapped */
pub const LC_SYMTAB: u32 = 0x2; /* link-edit stab symbol table info */
pub const LC_SYMSEG: u32 = 0x3; /* link-edit gdb symbol table info (obsolete) */
pub const LC_THREAD: u32 = 0x4; /* thread */
pub const LC_UNIXTHREAD: u32 = 0x5; /* unix thread (includes a stack) */
pub const LC_LOADFVMLIB: u32 = 0x6; /* load a specified fixed VM shared library */
pub const LC_IDFVMLIB: u32 = 0x7; /* fixed VM shared library identification */
pub const LC_IDENT: u32 = 0x8; /* object identification info (obsolete) */
pub const LC_FVMFILE: u32 = 0x9; /* fixed VM file inclusion (internal use) */
pub const LC_PREPAGE: u32 = 0xa; /* prepage command (internal use) */
pub const LC_DYSYMTAB: u32 = 0xb; /* dynamic link-edit symbol table info */
pub const LC_LOAD_DYLIB: u32 = 0xc; /* load a dynamically linked shared library */
pub const LC_ID_DYLIB: u32 = 0xd; /* dynamically linked shared lib ident */
pub const LC_LOAD_DYLINKER: u32 = 0xe; /* load a dynamic linker */
pub const LC_ID_DYLINKER: u32 = 0xf; /* dynamic linker identification */
pub const LC_PREBOUND_DYLIB: u32 = 0x10; /* modules prebound for a dynamically */
/*  linked shared library */
pub const LC_ROUTINES: u32 = 0x11; /* image routines */
pub const LC_SUB_FRAMEWORK: u32 = 0x12; /* sub framework */
pub const LC_SUB_UMBRELLA: u32 = 0x13; /* sub umbrella */
pub const LC_SUB_CLIENT: u32 = 0x14; /* sub client */
pub const LC_SUB_LIBRARY: u32 = 0x15; /* sub library */
pub const LC_TWOLEVEL_HINTS: u32 = 0x16; /* two-level namespace lookup hints */
pub const LC_PREBIND_CKSUM: u32 = 0x17; /* prebind checksum */

/*
 * load a dynamically linked shared library that is allowed to be missing
 * (all symbols are weak imported).
 */
pub const LC_LOAD_WEAK_DYLIB: u32 = (0x18 | LC_REQ_DYLD);

pub const LC_SEGMENT_64: u32 = 0x19; /* 64-bit segment of this file to be
                                     mapped */
pub const LC_ROUTINES_64: u32 = 0x1a; /* 64-bit image routines */
pub const LC_UUID: u32 = 0x1b; /* the uuid */
pub const LC_RPATH: u32 = (0x1c | LC_REQ_DYLD); /* runpath additions */
pub const LC_CODE_SIGNATURE: u32 = 0x1d; /* local of code signature */
pub const LC_SEGMENT_SPLIT_INFO: u32 = 0x1e; /* local of info to split segments */
pub const LC_REEXPORT_DYLIB: u32 = (0x1f | LC_REQ_DYLD); /* load and re-export dylib */
pub const LC_LAZY_LOAD_DYLIB: u32 = 0x20; /* delay load of dylib until first use */
pub const LC_ENCRYPTION_INFO: u32 = 0x21; /* encrypted segment information */
pub const LC_DYLD_INFO: u32 = 0x22; /* compressed dyld information */
pub const LC_DYLD_INFO_ONLY: u32 = (0x22 | LC_REQ_DYLD); /* compressed dyld information only */
pub const LC_LOAD_UPWARD_DYLIB: u32 = (0x23 | LC_REQ_DYLD); /* load upward dylib */
pub const LC_VERSION_MIN_MACOSX: u32 = 0x24; /* build for MacOSX min OS version */
pub const LC_VERSION_MIN_IPHONEOS: u32 = 0x25; /* build for iPhoneOS min OS version */
pub const LC_FUNCTION_STARTS: u32 = 0x26; /* compressed table of function start addresses */
pub const LC_DYLD_ENVIRONMENT: u32 = 0x27; /* string for dyld to treat
                                           like environment variable */
pub const LC_MAIN: u32 = (0x28 | LC_REQ_DYLD); /* replacement for LC_UNIXTHREAD */
pub const LC_DATA_IN_CODE: u32 = 0x29; /* table of non-instructions in __text */
pub const LC_SOURCE_VERSION: u32 = 0x2A; /* source version used to build binary */
pub const LC_DYLIB_CODE_SIGN_DRS: u32 = 0x2B; /* Code signing DRs copied from linked dylibs */
pub const LC_ENCRYPTION_INFO_64: u32 = 0x2C; /* 64-bit encrypted segment information */
pub const LC_LINKER_OPTION: u32 = 0x2D; /* linker options in MH_OBJECT files */
pub const LC_LINKER_OPTIMIZATION_HINT: u32 = 0x2E; /* optimization hints in MH_OBJECT files */
pub const LC_VERSION_MIN_TVOS: u32 = 0x2F; /* build for AppleTV min OS version */
pub const LC_VERSION_MIN_WATCHOS: u32 = 0x30; /* build for Watch min OS version */
pub const LC_NOTE: u32 = 0x31; /* arbitrary data included within a Mach-O file */
pub const LC_BUILD_VERSION: u32 = 0x32; /* build for platform min OS version */
pub const LC_DYLD_EXPORTS_TRIE: u32 = (0x33 | LC_REQ_DYLD); /* used with linkedit_data_command, payload is trie */
pub const LC_DYLD_CHAINED_FIXUPS: u32 = (0x34 | LC_REQ_DYLD); /* used with linkedit_data_command */
pub const LC_FILESET_ENTRY: u32 = (0x35 | LC_REQ_DYLD); /* used with fileset_entry_command */

#[repr(C)]
pub struct fat_header {
    pub magic: u32,     /* FAT_MAGIC */
    pub nfat_arch: u32, /* number of structs that follow */
}

#[repr(C)]
pub struct fat_arch {
    pub cputype: i32,    /* cpu specifier (int) */
    pub cpusubtype: i32, /* machine specifier (int) */
    pub offset: u32,     /* file offset to this object file */
    pub size: u32,       /* size of this object file */
    pub align: u32,      /* alignment as a power of 2 */
}

#[repr(C)]
pub struct section {
    pub sectname: [u8; 16],
    pub segname: [u8; 16],
    pub addr: u32,
    pub size: u32,
    pub offset: u32,
    pub align: u32,
    pub reloff: u32,
    pub nreloc: u32,
    pub flags: u32,
    pub reserved1: u32,
    pub reserved2: u32,
}

#[repr(C)]

pub struct section_64 {
    pub sectname: [u8; 16],
    pub segname: [u8; 16],
    pub addr: u64,
    pub size: u64,
    pub offset: u32,
    pub align: u32,
    pub reloff: u32,
    pub nreloc: u32,
    pub flags: u32,
    pub reserved1: u32,
    pub reserved2: u32,
    pub reserved3: u32,
}

pub fn format_load_command(num: u32) -> &'static str {
    match num {
        LC_SEGMENT => "LC_SEGMENT",
        LC_SYMTAB => "LC_SYMTAB",
        LC_SYMSEG => "LC_SYMSEG",
        LC_THREAD => "LC_THREAD",
        LC_UNIXTHREAD => "LC_UNIXTHREAD",
        LC_LOADFVMLIB => "LC_LOADFVMLIB",
        LC_IDFVMLIB => "LC_IDFVMLIB",
        LC_IDENT => "LC_IDENT",
        LC_FVMFILE => "LC_FVMFILE",
        LC_PREPAGE => "LC_PREPAGE",
        LC_DYSYMTAB => "LC_DYSYMTAB",
        LC_LOAD_DYLIB => "LC_LOAD_DYLIB",
        LC_ID_DYLIB => "LC_ID_DYLIB",
        LC_LOAD_DYLINKER => "LC_LOAD_DYLINKER",
        LC_ID_DYLINKER => "LC_ID_DYLINKER",
        LC_PREBOUND_DYLIB => "LC_PREBOUND_DYLIB",
        LC_ROUTINES => "LC_ROUTINES",
        LC_SUB_FRAMEWORK => "LC_SUB_FRAMEWORK",
        LC_SUB_UMBRELLA => "LC_SUB_UMBRELLA",
        LC_SUB_CLIENT => "LC_SUB_CLIENT",
        LC_SUB_LIBRARY => "LC_SUB_LIBRARY",
        LC_TWOLEVEL_HINTS => "LC_TWOLEVEL_HINTS",
        LC_PREBIND_CKSUM => "LC_PREBIND_CKSUM",
        LC_LOAD_WEAK_DYLIB => "LC_LOAD_WEAK_DYLIB",
        LC_SEGMENT_64 => "LC_SEGMENT_64",
        LC_ROUTINES_64 => "LC_ROUTINES_64",
        LC_UUID => "LC_UUID",
        LC_RPATH => "LC_RPATH",
        LC_CODE_SIGNATURE => "LC_CODE_SIGNATURE",
        LC_SEGMENT_SPLIT_INFO => "LC_SEGMENT_SPLIT_INFO",
        LC_REEXPORT_DYLIB => "LC_REEXPORT_DYLIB",
        LC_LAZY_LOAD_DYLIB => "LC_LAZY_LOAD_DYLIB",
        LC_ENCRYPTION_INFO => "LC_ENCRYPTION_INFO",
        LC_DYLD_INFO => "LC_DYLD_INFO",
        LC_DYLD_INFO_ONLY => "LC_DYLD_INFO_ONLY",
        LC_LOAD_UPWARD_DYLIB => "LC_LOAD_UPWARD_DYLIB",
        LC_VERSION_MIN_MACOSX => "LC_VERSION_MIN_MACOSX",
        LC_VERSION_MIN_IPHONEOS => "LC_VERSION_MIN_IPHONEOS",
        LC_FUNCTION_STARTS => "LC_FUNCTION_STARTS",
        LC_DYLD_ENVIRONMENT => "LC_DYLD_ENVIRONMENT",
        LC_MAIN => "LC_MAIN",
        LC_DATA_IN_CODE => "LC_DATA_IN_CODE",
        LC_SOURCE_VERSION => "LC_SOURCE_VERSION",
        LC_DYLIB_CODE_SIGN_DRS => "LC_DYLIB_CODE_SIGN_DRS",
        LC_ENCRYPTION_INFO_64 => "LC_ENCRYPTION_INFO_64",
        LC_LINKER_OPTION => "LC_LINKER_OPTION",
        LC_LINKER_OPTIMIZATION_HINT => "LC_LINKER_OPTIMIZATION_HINT",
        LC_VERSION_MIN_TVOS => "LC_VERSION_MIN_TVOS",
        LC_VERSION_MIN_WATCHOS => "LC_VERSION_MIN_WATCHOS",
        LC_NOTE => "LC_NOTE",
        LC_BUILD_VERSION => "LC_BUILD_VERSION",
        LC_DYLD_EXPORTS_TRIE => "LC_DYLD_EXPORTS_TRIE",
        LC_DYLD_CHAINED_FIXUPS => "LC_DYLD_CHAINED_FIXUPS",
        LC_FILESET_ENTRY => "LC_FILESET_ENTRY",
        _ => "UNKNOWN",
    }
}

pub const SG_NORELOC: u32 = 0x4;
pub type kern_return_t = i32;

extern "C" {
    pub fn vm_allocate(
        target_task: vm_map_t,
        address: *mut vm_address_t,
        size: vm_size_t,
        flags: i32,
    ) -> kern_return_t;

    pub fn vm_deallocate(
        target_task: vm_map_t,
        address: vm_address_t,
        size: vm_size_t,
    ) -> kern_return_t;

    pub fn vm_protect(
        target_task: vm_map_t,
        address: vm_address_t,
        size: vm_size_t,
        set_maximum: i32,
        new_protection: vm_prot_t,
    ) -> kern_return_t;
}

#[repr(C)]
pub struct TLVDescriptor {
    pub thunk: *const c_void,
    pub key: u64,
    pub offset: u64,
}

extern "C" {
    pub fn _NSGetArgv() -> *const *const *const u8;
    pub fn _NSGetArgc() -> *const i32;
    pub fn _NSGetEnviron() -> *const *const *const u8;
    pub fn _NSGetMachExecuteHeader() -> usize;
}

// https://github.com/opensource-apple/dyld/blob/master/src/dyldInitialization.cpp#L223
pub unsafe fn get_apple_from_envp() -> *const *const u8 {
    let mut envp = *_NSGetEnviron();
    while !(*envp).is_null() {
        envp = envp.add(1);
    }

    envp.add(1)
}

#[repr(C)]
pub struct ProgramVars {
    pub mh: usize,
    pub NXArgcPtr: *const i32,
    pub NXArgvPtr: *const *const *const u8,
    pub environPtr: *const *const *const u8,
    pub __prognamePtr: *const *const u8,
}

// typedef void (*ImageLoader::Initializer)(int argc, const char **argv, const char **envp, const char **apple, const ProgramVars *vars)
pub type Initializer = extern "C" fn(
    argc: i32,
    argv: *const *const u8,
    envp: *const *const u8,
    apple: *const *const u8,
    vars: *const ProgramVars,
);

pub type Terminator = extern "C" fn();

#[repr(C)]
pub struct entry_point_command {
    pub cmd: u32,       /* LC_MAIN only used in MH_EXECUTE filetypes */
    pub cmdsize: u32,   /* 24 */
    pub entryoff: u64,  /* file (__TEXT) offset of main() */
    pub stacksize: u64, /* if not zero, initial stack size */
}

#[repr(C)]
pub struct symtab_command {
    pub cmd: u32,
    pub cmdsize: u32,
    pub symoff: u32,
    pub nsyms: u32,
    pub stroff: u32,
    pub strsize: u32,
}

#[repr(C)]
pub struct nlist {
    pub n_strx: u32,
    pub n_type: u8,
    pub n_sect: u8,
    pub n_desc: u16,
    pub n_value: u32,
}

#[repr(C)]
pub struct nlist_64 {
    pub n_strx: u32,
    pub n_type: u8,
    pub n_sect: u8,
    pub n_desc: u16,
    pub n_value: u64,
}

#[repr(C)]
pub struct dylib {
    pub offset: u32,
    pub timestamp: u32,
    pub current_version: u32,
    pub compatibility_version: u32,
}

#[repr(C)]
pub struct dylib_command {
    pub cmd: u32,
    pub cmdsize: u32,
    pub dylib: dylib,
}

pub const N_EXT: u8 = 0x01;
pub const N_SECT: u8 = 0x0e;

pub const REFERENCE_FLAG_UNDEFINED_NON_LAZY: u16 = 0x0;
pub const S_INIT_FUNC_OFFSETS: u32 = 0x16;
pub const S_MOD_INIT_FUNC_POINTERS: u32 = 0x9;
pub const S_MOD_TERM_FUNC_POINTERS: u32 = 0xa;

#[repr(C)]
pub struct dysymtab_command {
    pub cmd: u32,
    pub cmdsize: u32,
    pub ilocalsym: u32,
    pub nlocalsym: u32,
    pub iextdefsym: u32,
    pub nextdefsym: u32,
    pub iundefsym: u32,
    pub nundefsym: u32,
    pub tocoff: u32,
    pub ntoc: u32,
    pub modtaboff: u32,
    pub nmodtab: u32,
    pub extrefsymoff: u32,
    pub nextrefsyms: u32,
    pub indirectsymoff: u32,
    pub nindirectsyms: u32,
    pub extreloff: u32,
    pub nextrel: u32,
    pub locreloff: u32,
    pub nlocrel: u32,
}

/// Structs for dyld chained fixups.
/// dyld_chained_fixups_header is the data pointed to by LC_DYLD_CHAINED_FIXUPS
/// load command.
#[repr(C)]

pub struct dyld_chained_fixups_header {
    pub fixups_version: u32, // 0
    pub starts_offset: u32,  // Offset of dyld_chained_starts_in_image.
    pub imports_offset: u32, // Offset of imports table in chain_data.
    pub symbols_offset: u32, // Offset of symbol strings in chain_data.
    pub imports_count: u32,  // Number of imported symbol names.
    pub imports_format: u32, // DYLD_CHAINED_IMPORT*
    pub symbols_format: u32, // 0 => uncompressed, 1 => zlib compressed
}

/*
 * The linkedit_data_command contains the offsets and sizes of a blob
 * of data in the __LINKEDIT segment.
 */
#[repr(C)]
pub struct linkedit_data_command {
    pub cmd: u32,      /* LC_CODE_SIGNATURE, LC_SEGMENT_SPLIT_INFO,
                       LC_FUNCTION_STARTS, LC_DATA_IN_CODE,
                       LC_DYLIB_CODE_SIGN_DRS,
                       LC_LINKER_OPTIMIZATION_HINT,
                       LC_DYLD_EXPORTS_TRIE, or
                       LC_DYLD_CHAINED_FIXUPS. */
    pub cmdsize: u32,  /* sizeof(struct linkedit_data_command) */
    pub dataoff: u32,  /* file offset of data in __LINKEDIT segment */
    pub datasize: u32, /* file size of data in __LINKEDIT segment  */
}

// values for dyld_chained_fixups_header.imports_format
pub const DYLD_CHAINED_IMPORT: u32 = 1;
pub const DYLD_CHAINED_IMPORT_ADDEND: u32 = 2;
pub const DYLD_CHAINED_IMPORT_ADDEND64: u32 = 3;

pub const DYLD_CHAINED_PTR_START_NONE: u16 = 0xFFFF; // used in page_start[] to denote a page with no fixups
pub const DYLD_CHAINED_PTR_START_MULTI: u16 = 0x8000; // used in page_start[] to denote a page which has multiple starts
pub const DYLD_CHAINED_PTR_START_LAST: u16 = 0x8000; // used in chain_starts[] to denote last start in list for page

// values for dyld_chained_starts_in_segment.pointer_format
pub const DYLD_CHAINED_PTR_ARM64E: u16 = 1; // stride 8, unauth target is vmaddr
pub const DYLD_CHAINED_PTR_64: u16 = 2; // target is vmaddr
pub const DYLD_CHAINED_PTR_32: u16 = 3;
pub const DYLD_CHAINED_PTR_32_CACHE: u16 = 4;
pub const DYLD_CHAINED_PTR_32_FIRMWARE: u16 = 5;
pub const DYLD_CHAINED_PTR_64_OFFSET: u16 = 6; // target is vm offset
pub const DYLD_CHAINED_PTR_ARM64E_OFFSET: u16 = 7; // old name
pub const DYLD_CHAINED_PTR_ARM64E_KERNEL: u16 = 7; // stride 4, unauth target is vm offset
pub const DYLD_CHAINED_PTR_64_KERNEL_CACHE: u16 = 8;
pub const DYLD_CHAINED_PTR_ARM64E_USERLAND: u16 = 9; // stride 8, unauth target is vm offset
pub const DYLD_CHAINED_PTR_ARM64E_FIRMWARE: u16 = 10; // stride 4, unauth target is vmaddr
pub const DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE: u16 = 11; // stride 1, x86_64 kernel caches
pub const DYLD_CHAINED_PTR_ARM64E_USERLAND24: u16 = 12; // stride 8, unauth target is vm offset, 24-bit bind

// This struct is embedded in LC_DYLD_CHAINED_FIXUPS payload
#[repr(C)]
pub struct dyld_chained_starts_in_image {
    pub seg_count: u32,
    pub seg_info_offset: [u32; 1], // each entry is offset into this struct for that segment
                                   // followed by pool of dyld_chain_starts_in_segment data
}

// This struct is embedded in dyld_chain_starts_in_image
// and passed down to the kernel for page-in linking
#[repr(C)]
pub struct dyld_chained_starts_in_segment {
    pub size: u32,              // size of this (amount kernel needs to copy)
    pub page_size: u16,         // 0x1000 or 0x4000
    pub pointer_format: u16,    // DYLD_CHAINED_PTR_*
    pub segment_offset: u64,    // offset in memory to start of segment
    pub max_valid_pointer: u32, // for 32-bit OS, any value beyond this is not a pointer
    pub page_count: u16,        // how many pages are in array
    pub page_start: [u16; 1],   // each entry is offset in each page of first element in chain
                                // or DYLD_CHAINED_PTR_START_NONE if no fixups on page
                                // uint16_t    chain_starts[1];    // some 32-bit formats may require multiple starts per page.
                                // for those, if high bit is set in page_starts[], then it
                                // is index into chain_starts[] which is a list of starts
                                // the last of which has the high bit set
}

use modular_bitfield::prelude::*;

// DYLD_CHAINED_IMPORT
#[bitfield]
pub struct dyld_chained_import {
    pub lib_ordinal: B8,
    pub weak_import: B1,
    pub name_offset: B23,
}

// DYLD_CHAINED_PTR_64/DYLD_CHAINED_PTR_64_OFFSET
#[bitfield]
pub struct dyld_chained_ptr_64_rebase {
    pub target: B36, // 64GB max image size (DYLD_CHAINED_PTR_64 => vmAddr, DYLD_CHAINED_PTR_64_OFFSET => runtimeOffset)
    pub high8: B8, // top 8 bits set to this (DYLD_CHAINED_PTR_64 => after slide added, DYLD_CHAINED_PTR_64_OFFSET => before slide added)
    pub reserved: B7, // all zeros
    pub next: B12, // 4-byte stride
    pub bind: B1,  // == 0
}

// DYLD_CHAINED_PTR_64
#[bitfield]
pub struct dyld_chained_ptr_64_bind {
    pub ordinal: B24,
    pub addend: B8,    // 0 thru 255
    pub reserved: B19, // all zeros
    pub next: B12,     // 4-byte stride
    pub bind: B1,      // == 1
}

// DYLD_CHAINED_IMPORT_ADDEND
#[bitfield]
pub struct dyld_chained_import_addend {
    pub lib_ordinal: B8,
    pub weak_import: B1,
    pub name_offset: B23,
    pub addend: u32,
}

// DYLD_CHAINED_IMPORT_ADDEND64
#[bitfield]
pub struct dyld_chained_import_addend64 {
    pub lib_ordinal: B16,
    pub weak_import: B1,
    pub reserved: B15,
    pub name_offset: B32,
    pub addend: u64,
}

/*
 * The dyld_info_command contains the file offsets and sizes of
 * the new compressed form of the information dyld needs to
 * load the image.  This information is used by dyld on Mac OS X
 * 10.6 and later.  All information pointed to by this command
 * is encoded using byte streams, so no endian swapping is needed
 * to interpret it.
 */
#[repr(C)]
pub struct dyld_info_command {
    pub cmd: u32,     /* LC_DYLD_INFO or LC_DYLD_INFO_ONLY */
    pub cmdsize: u32, /* sizeof(struct dyld_info_command) */

    /*
     * Dyld rebases an image whenever dyld loads it at an address different
     * from its preferred address.  The rebase information is a stream
     * of byte sized opcodes whose symbolic names start with REBASE_OPCODE_.
     * Conceptually the rebase information is a table of tuples:
     *    <seg-index, seg-offset, type>
     * The opcodes are a compressed way to encode the table by only
     * encoding when a column changes.  In addition simple patterns
     * like "every n'th offset for m times" can be encoded in a few
     * bytes.
     */
    pub rebase_off: u32,  /* file offset to rebase info  */
    pub rebase_size: u32, /* size of rebase info   */

    /*
     * Dyld binds an image during the loading process, if the image
     * requires any pointers to be initialized to symbols in other images.
     * The bind information is a stream of byte sized
     * opcodes whose symbolic names start with BIND_OPCODE_.
     * Conceptually the bind information is a table of tuples:
     *    <seg-index, seg-offset, type, symbol-library-ordinal, symbol-name, addend>
     * The opcodes are a compressed way to encode the table by only
     * encoding when a column changes.  In addition simple patterns
     * like for runs of pointers initialzed to the same value can be
     * encoded in a few bytes.
     */
    pub bind_off: u32,  /* file offset to binding info   */
    pub bind_size: u32, /* size of binding info  */

    /*
     * Some C++ programs require dyld to unique symbols so that all
     * images in the process use the same copy of some code/data.
     * This step is done after binding. The content of the weak_bind
     * info is an opcode stream like the bind_info.  But it is sorted
     * alphabetically by symbol name.  This enable dyld to walk
     * all images with weak binding information in order and look
     * for collisions.  If there are no collisions, dyld does
     * no updating.  That means that some fixups are also encoded
     * in the bind_info.  For instance, all calls to "operator new"
     * are first bound to libstdc++.dylib using the information
     * in bind_info.  Then if some image overrides operator new
     * that is detected when the weak_bind information is processed
     * and the call to operator new is then rebound.
     */
    pub weak_bind_off: u32,  /* file offset to weak binding info   */
    pub weak_bind_size: u32, /* size of weak binding info  */

    /*
     * Some uses of external symbols do not need to be bound immediately.
     * Instead they can be lazily bound on first use.  The lazy_bind
     * are contains a stream of BIND opcodes to bind all lazy symbols.
     * Normal use is that dyld ignores the lazy_bind section when
     * loading an image.  Instead the static linker arranged for the
     * lazy pointer to initially point to a helper function which
     * pushes the offset into the lazy_bind area for the symbol
     * needing to be bound, then jumps to dyld which simply adds
     * the offset to lazy_bind_off to get the information on what
     * to bind.
     */
    pub lazy_bind_off: u32,  /* file offset to lazy binding info */
    pub lazy_bind_size: u32, /* size of lazy binding infs */

    /*
     * The symbols exported by a dylib are encoded in a trie.  This
     * is a compact representation that factors out common prefixes.
     * It also reduces LINKEDIT pages in RAM because it encodes all
     * information (name, address, flags) in one small, contiguous range.
     * The export area is a stream of nodes.  The first node sequentially
     * is the start node for the trie.
     *
     * Nodes for a symbol start with a uleb128 that is the length of
     * the exported symbol information for the string so far.
     * If there is no exported symbol, the node starts with a zero byte.
     * If there is exported info, it follows the length.
     *
     * First is a uleb128 containing flags. Normally, it is followed by
     * a uleb128 encoded offset which is location of the content named
     * by the symbol from the mach_header for the image.  If the flags
     * is EXPORT_SYMBOL_FLAGS_REEXPORT, then following the flags is
     * a uleb128 encoded library ordinal, then a zero terminated
     * UTF8 string.  If the string is zero length, then the symbol
     * is re-export from the specified dylib with the same name.
     * If the flags is EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER, then following
     * the flags is two uleb128s: the stub offset and the resolver offset.
     * The stub is used by non-lazy pointers.  The resolver is used
     * by lazy pointers and must be called to get the actual address to use.
     *
     * After the optional exported symbol information is a byte of
     * how many edges (0-255) that this node has leaving it,
     * followed by each edge.
     * Each edge is a zero terminated UTF8 of the addition chars
     * in the symbol, followed by a uleb128 offset for the node that
     * edge points to.
     *
     */
    pub export_off: u32,  /* file offset to lazy binding info */
    pub export_size: u32, /* size of lazy binding infs */
}

/*
 * The following are used to encode rebasing information
 */
pub const REBASE_TYPE_POINTER: u8 = 1;
pub const REBASE_TYPE_TEXT_ABSOLUTE32: u8 = 2;
pub const REBASE_TYPE_TEXT_PCREL32: u8 = 3;

pub const REBASE_OPCODE_MASK: u8 = 0xF0;
pub const REBASE_IMMEDIATE_MASK: u8 = 0x0F;
pub const REBASE_OPCODE_DONE: u8 = 0x00;
pub const REBASE_OPCODE_SET_TYPE_IMM: u8 = 0x10;
pub const REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x20;
pub const REBASE_OPCODE_ADD_ADDR_ULEB: u8 = 0x30;
pub const REBASE_OPCODE_ADD_ADDR_IMM_SCALED: u8 = 0x40;
pub const REBASE_OPCODE_DO_REBASE_IMM_TIMES: u8 = 0x50;
pub const REBASE_OPCODE_DO_REBASE_ULEB_TIMES: u8 = 0x60;
pub const REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: u8 = 0x70;
pub const REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: u8 = 0x80;

/*
 * The following are used to encode binding information
 */
pub const BIND_TYPE_POINTER: u8 = 1;
pub const BIND_TYPE_TEXT_ABSOLUTE32: u8 = 2;
pub const BIND_TYPE_TEXT_PCREL32: u8 = 3;

pub const BIND_SYMBOL_FLAGS_WEAK_IMPORT: u8 = 0x1;
pub const BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION: u8 = 0x8;

pub const BIND_OPCODE_MASK: u8 = 0xF0;
pub const BIND_IMMEDIATE_MASK: u8 = 0x0F;
pub const BIND_OPCODE_DONE: u8 = 0x00;
pub const BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: u8 = 0x10;
pub const BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: u8 = 0x20;
pub const BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: u8 = 0x30;
pub const BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: u8 = 0x40;
pub const BIND_OPCODE_SET_TYPE_IMM: u8 = 0x50;
pub const BIND_OPCODE_SET_ADDEND_SLEB: u8 = 0x60;
pub const BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x70;
pub const BIND_OPCODE_ADD_ADDR_ULEB: u8 = 0x80;
pub const BIND_OPCODE_DO_BIND: u8 = 0x90;
pub const BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: u8 = 0xA0;
pub const BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: u8 = 0xB0;
pub const BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: u8 = 0xC0;
pub const BIND_OPCODE_THREADED: u8 = 0xD0;
pub const BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB: u8 = 0x00;
pub const BIND_SUBOPCODE_THREADED_APPLY: u8 = 0x01;

#[repr(C)]
pub struct x86_thread_state64_t {
    pub __rax: u64,
    pub __rbx: u64,
    pub __rcx: u64,
    pub __rdx: u64,
    pub __rdi: u64,
    pub __rsi: u64,
    pub __rbp: u64,
    pub __rsp: u64,
    pub __r8: u64,
    pub __r9: u64,
    pub __r10: u64,
    pub __r11: u64,
    pub __r12: u64,
    pub __r13: u64,
    pub __r14: u64,
    pub __r15: u64,
    pub __rip: u64,
    pub __rflags: u64,
    pub __cs: u64,
    pub __fs: u64,
    pub __gs: u64,
}

#[repr(C)]
pub struct arm_thread_state64_t {
    pub x: [u64; 29],
    pub fp: u64,
    pub lr: u64,
    pub sp: u64,
    pub pc: u64,
    pub cpsr: u32,
    pub pad: u32,
}

pub unsafe fn read_uleb128(base: *const u8, offset: &mut usize) -> usize {
    let mut ret = 0;
    let mut bit = 0;

    loop {
        let slice = *base.add(*offset) & 0x7f;

        if bit > 63 {
            return ret;
        } else {
            ret |= (slice as usize) << (bit as usize);
            bit += 7;
        }

        let b = *base.add(*offset);

        *offset += 1;
        if b & 0x80 == 0 {
            break;
        }
    }

    ret
}

pub unsafe fn read_sleb128(base: *const u8, offset: &mut usize) -> isize {
    let mut ret = 0;
    let mut bit = 0;
    let mut byte = 0;

    loop {
        byte = *base.add(*offset);
        *offset += 1;

        ret |= ((byte & 0x7f) as isize).wrapping_shl(bit);
        bit += 7;

        if byte & 0x80 == 0 {
            break;
        }
    }

    if byte & 0x40 != 0 {
        ret |= -1_isize.wrapping_shl(bit);
    }

    ret
}
