#![allow(deprecated)]
#![allow(overflowing_literals)]
#![allow(arithmetic_overflow)]
#![feature(stmt_expr_attributes)]

pub mod def;
pub mod errors;

use core::arch::asm;
use core::ffi::{c_void, CStr};
use core::mem;
use core::ptr;

use def::*;
use errors::{Error, Result};
use libc::{
    load_command, mach_header, mach_header_64, segment_command_64, MH_MAGIC, MH_MAGIC_64,
    RTLD_NOLOAD, VM_FLAGS_ANYWHERE,
};

extern "C" {
    fn tlv_initialize_descriptors(tlv: usize);
}

#[macro_export]
macro_rules! dp {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        print!("[+] ");
        #[cfg(debug_assertions)]
        println!($($arg)*)
    };
}

pub struct MachOLoader<'a> {
    hdr: &'a mach_header,
    base_addr: usize,
    file_hdr: *const u8,
    buf: &'a [u8],
    loaded_dylib: Vec<*mut c_void>,
}

impl<'a> Drop for MachOLoader<'a> {
    fn drop(&mut self) {
        unsafe {
            self.call_term_func();

            if self.base_addr != 0 {
                vm_deallocate(libc::mach_task_self(), self.base_addr, self.segments_size());
            }

            for hdl in self.loaded_dylib.iter() {
                libc::dlclose(*hdl);
            }
        }
    }
}

impl<'a> MachOLoader<'a> {
    #[cfg(target_arch = "x86_64")]
    const CPU_TYPE: i32 = CPU_TYPE_X86_64;

    #[cfg(target_arch = "aarch64")]
    const CPU_TYPE: i32 = CPU_TYPE_ARM64;

    pub unsafe fn new(buf: &'a [u8]) -> Result<Self> {
        let magic = *(buf.as_ptr() as *const u32);
        let mut hdr = ptr::null();

        if magic == MH_MAGIC_64 {
            hdr = buf.as_ptr() as *const mach_header;

            if (*hdr).cputype != Self::CPU_TYPE {
                return Err(Error::UnsupportedArch);
            }
        } else if magic == FAT_MAGIC || magic == FAT_CIGAM {
            let fat_hdr = &*(buf.as_ptr() as *const fat_header);

            let n = if magic == FAT_CIGAM {
                fat_hdr.nfat_arch.swap_bytes()
            } else {
                fat_hdr.nfat_arch
            };

            let fat_arch_arr = &*ptr::slice_from_raw_parts(
                buf.as_ptr().add(mem::size_of::<fat_header>()) as *const fat_arch,
                n as usize,
            );

            for fat_arch in fat_arch_arr {
                let cpu_typ = if magic == FAT_CIGAM {
                    i32::swap_bytes(fat_arch.cputype)
                } else {
                    fat_arch.cputype
                };

                let offset = if magic == FAT_CIGAM {
                    u32::swap_bytes(fat_arch.offset)
                } else {
                    fat_arch.offset
                };

                if cpu_typ == Self::CPU_TYPE {
                    hdr = buf.as_ptr().add(offset as usize) as *const mach_header;
                    break;
                }
            }
        } else {
            return Err(Error::UnsupportedArch);
        }

        if hdr.is_null() {
            return Err(Error::UnsupportedArch);
        }

        Ok(Self {
            hdr: &*hdr,
            buf,
            file_hdr: hdr as *const u8,
            base_addr: 0,
            loaded_dylib: Vec::new(),
        })
    }

    // https://github.com/aidansteele/osx-abi-macho-file-format-reference
    // https://opensource.apple.com/source/dyld/dyld-852.2/dyld3/
    pub unsafe fn load(&mut self) -> Result<()> {
        self.init_dylib_handle()?;

        dp!("loaded dylib {:?}", self.loaded_dylib);

        let ret = vm_allocate(
            libc::mach_task_self(),
            &mut self.base_addr,
            self.segments_size(),
            VM_FLAGS_ANYWHERE,
        );
        if ret != 0 {
            return Err(Error::VmAlloc(ret));
        }

        // let ret = vm_deallocate(
        //     libc::mach_task_self(),
        //     self.base_addr,
        //     self.page_zero_size(),
        // );
        // if ret != 0 {
        //     return Err(Error::VmDeAlloc(ret));
        // }

        dp!(
            "allocate {}KB @ 0x{:x} ~ 0x{:x}",
            self.segments_size() / 1024,
            self.base_addr,
            self.base_addr + self.segments_size(),
        );

        // self.fix_vmaddr();

        self.map_segments();
        // self.resolve_indirect_symbols();

        self.rebase_and_bind_dyld_info()?;

        self.rebase_and_bind_chained_fixup()?;

        self.init_tlv();

        self.map_protection();

        self.call_init_func();

        Ok(())
    }

    /*
     * https://github.com/apple-oss-distributions/dyld/blob/dyld-1066.10/dyld/dyldStartup.s#L75
     * When starting a dynamic process, the kernel maps the main executable and dyld.
     * The kernel the starts the process with program counter set to __dyld_start
     * in dyld with the stack looking like:
     *
     *      | STRING AREA |
     *      +-------------+
     *      |      0      |
     *      +-------------+
     *      |  apple[n]   |
     *      +-------------+
     *             :
     *      +-------------+
     *      |  apple[0]   |
     *      +-------------+
     *      |      0      |
     *      +-------------+
     *      |    env[n]   |
     *      +-------------+
     *             :
     *             :
     *      +-------------+
     *      |    env[0]   |
     *      +-------------+
     *      |      0      |
     *      +-------------+
     *      | arg[argc-1] |
     *      +-------------+
     *             :
     *             :
     *      +-------------+
     *      |    arg[0]   |
     *      +-------------+
     *      |     argc    |
     *      +-------------+
     * sp-> |      mh     | address of where the main program's mach_header (TEXT segment) is loaded
     *      +-------------+
     *
     *    Where arg[i] and env[i] point into the STRING AREA


       // _rt0_amd64 is common startup code for most amd64 systems when using
       // internal linking. This is the entry point for the program from the
       // kernel for an ordinary -buildmode=exe program. The stack holds the
       // number of arguments and the C-style argv.
       TEXT _rt0_amd64(SB),NOSPLIT,$-8
           MOVQ	0(SP), DI	// argc
           LEAQ	8(SP), SI	// argv
           JMP	runtime·rt0_go(SB)

       // main is common startup code for most amd64 systems when using
       // external linking. The C startup code will call the symbol "main"
       // passing argc and argv in the usual C ABI registers DI and SI.
       TEXT main(SB),NOSPLIT,$-8
           JMP	runtime·rt0_go(SB)
    */
    pub unsafe fn execute<S: AsRef<str>>(&self, args: &[S]) -> Result<()> {
        let mut offset = 0;
        let mut is_thread = false;

        self.iter_load_command(|lc| {
            if lc.cmd == LC_MAIN {
                offset = (*(lc as *const load_command as *const entry_point_command)).entryoff
                    as usize
                    + self.get_text_vmaddr();
                return false;
            }
            true
        });

        if offset == 0 {
            self.iter_load_command(|lc| {
                if lc.cmd == LC_UNIXTHREAD || lc.cmd == LC_THREAD {
                    #[cfg(target_arch = "x86_64")]
                    let regs = &*((lc as *const load_command as *const u8).offset(16)
                        as *const x86_thread_state64_t);
                    #[cfg(target_arch = "x86_64")]
                    let ip = regs.__rip;

                    #[cfg(target_arch = "aarch64")]
                    let regs = &*((lc as *const load_command as *const u8).offset(16)
                        as *const arm_thread_state64_t);
                    #[cfg(target_arch = "aarch64")]
                    let ip = regs.pc;

                    offset = ip as usize;
                    is_thread = true;
                }
                true
            });
        }

        if offset == 0 {
            return Err(Error::NoEntryPoint);
        }

        let argc = args.len();
        let mut raw_argv = args
            .iter()
            .map(|v| {
                let mut s = v.as_ref().as_bytes().to_vec();
                s.push(0);
                Some(s)
            })
            .collect::<Vec<_>>();

        raw_argv.push(None);

        let mut envp = *_NSGetEnviron();
        while !(*envp).is_null() {
            let mut e = CStr::from_ptr(*envp as _)
                .to_str()
                .unwrap_or("")
                .as_bytes()
                .to_vec();
            e.push(0);

            raw_argv.push(Some(e));
            envp = envp.add(1);
        }
        raw_argv.push(None);

        let mut argv = Vec::new();
        argv.push(argc as *const u8);

        raw_argv
            .iter()
            .map(|v| argv.push(v.as_ref().map_or(ptr::null(), |s| s.as_ptr())))
            .for_each(mem::drop);

        if is_thread {
            #[cfg(target_arch = "x86_64")]
            asm!(
                "mov rsp, {0}",
                "jmp {1}",
                in(reg) argv.as_ptr(),
                in(reg) self.base_addr + offset,
            );
            #[cfg(target_arch = "aarch64")]
            return Err(Error::UnsupportedArch);
        } else {
            mem::transmute::<
                usize,
                extern "C" fn(argc: usize, argv: *const *const u8, envp: *const *const u8),
            >(self.base_addr + offset)(
                argc, argv.as_ptr().offset(1), argv.as_ptr().add(argc + 2)
            );
        }

        Ok(())
    }

    pub fn is_32bit(&self) -> bool {
        self.hdr.magic == MH_MAGIC
    }

    pub fn offset_to_segments(&self) -> usize {
        if self.is_32bit() {
            mem::size_of::<mach_header>()
        } else {
            mem::size_of::<mach_header_64>()
        }
    }

    pub unsafe fn segments_size(&self) -> usize {
        let mut size = 0;

        self.iter_load_command(|lc| {
            if lc.cmd == LC_SEGMENT_64 {
                let lc = &*(lc as *const load_command as *const segment_command_64);

                if lc.vmaddr + lc.vmsize > size {
                    size = lc.vmaddr + lc.vmsize;
                }
            }

            true
        });

        size as _
    }

    /*
    pub unsafe fn segments_size(&self) -> usize {
        let mut base = 0;
        let mut end = 0;
        let mut first = true;

        self.iter_load_command(|lc| {
            if lc.cmd == LC_SEGMENT_64 {
                let lc = &*(lc as *const load_command as *const segment_command_64);
                if first {
                    base = lc.vmaddr;
                    first = false;
                }

                if lc.vmsize == 0 || lc.filesize == 0 {
                    return true;
                }

                end = lc.vmaddr + lc.vmsize;
            }

            true
        });

        (end - base) as usize
    }
    */

    /*
        pub unsafe fn fix_vmaddr(&mut self) {
            let mut page_zero_base = 0;

            self.iter_load_command(|lc| {
                if lc.cmd == LC_SEGMENT_64 {
                    let lc = &*(lc as *const load_command as *const segment_command_64);

                    if CStr::from_ptr(lc.segname.as_ptr()).to_str().unwrap_or("") == "__PAGEZERO" {
                        page_zero_base = lc.vmsize;
                        return false;
                    }
                }

                true
            });

            self.iter_load_command_mut(|lc| {
                if lc.cmd == LC_SEGMENT_64 {
                    let lc = &mut *(lc as *mut load_command as *mut segment_command_64);
                    if lc.vmaddr < page_zero_base {
                        return true;
                    }
                    lc.vmaddr -= page_zero_base;
                }

                true
            });
        }
    */

    pub unsafe fn page_zero_size(&self) -> usize {
        let mut size = 0;

        self.iter_load_command(|lc| {
            if lc.cmd == LC_SEGMENT_64 {
                let lc = &*(lc as *const load_command as *const segment_command_64);

                if CStr::from_ptr(lc.segname.as_ptr()).to_str().unwrap_or("") == "__PAGEZERO" {
                    size = lc.vmsize;
                    return false;
                }
            }

            true
        });

        size as usize
    }

    unsafe fn iter_load_command<F: FnMut(&load_command) -> bool>(&self, mut f: F) {
        let mut offset = self.offset_to_segments();

        for _ in 0..self.hdr.ncmds {
            let lc = &*(self.file_hdr.add(offset) as *const load_command);

            if !f(lc) {
                break;
            }

            offset += lc.cmdsize as usize
        }
    }

    unsafe fn init_dylib_handle(&mut self) -> Result<()> {
        let mut lst = Vec::new();
        let mut ret = Ok(());

        self.iter_load_command(|lc: &load_command| {
            if lc.cmd == LC_LOAD_DYLIB || lc.cmd == LC_LOAD_WEAK_DYLIB {
                let lc = &*(lc as *const load_command as *const dylib_command);

                dp!(
                    "load {}",
                    CStr::from_ptr(
                        (lc as *const dylib_command as *const u8).add(lc.dylib.offset as usize)
                            as _
                    )
                    .to_str()
                    .unwrap_or("")
                );

                let hdl = libc::dlopen(
                    (lc as *const dylib_command as *const u8).add(lc.dylib.offset as usize) as _,
                    RTLD_NOLOAD,
                );
                if !hdl.is_null() {
                    lst.push(hdl);
                    return true;
                }

                let hdl = libc::dlopen(
                    (lc as *const dylib_command as *const u8).add(lc.dylib.offset as usize) as _,
                    0,
                );
                if hdl.is_null() {
                    if lc.cmd == LC_LOAD_DYLIB {
                        ret = Err(Error::ImportDylib(
                            (lc as *const dylib_command as *const u8).add(lc.dylib.offset as usize),
                        ));
                        return false;
                    }
                }

                lst.push(hdl);
            }

            true
        });

        self.loaded_dylib = lst;

        ret
    }

    // https://github.com/apple-open-source-mirror/dyld/blob/f033f5564c85c5cbfd24cf25e702e4bb0c2c39b4/src/threadLocalVariables.c#L223
    unsafe fn init_tlv(&self) {
        if self.hdr.flags & MH_HAS_TLV_DESCRIPTORS != MH_HAS_TLV_DESCRIPTORS {
            return;
        }

        dp!("INIT TLV");

        tlv_initialize_descriptors(self.base_addr + self.get_text_vmaddr());

        // let mut key = 0;
        // let mut slide = 0;
        // let mut slide_computed = false;

        // self.iter_load_command(|lc| {
        //     if lc.cmd == LC_SEGMENT_64 {
        //         let lc = &*(lc as *const load_command as *const segment_command_64);

        //         if !slide_computed && lc.filesize != 0 {
        //             slide = self.base_addr - lc.vmaddr as usize;
        //             slide_computed = true;
        //         }

        //         let mut sect_ptr = (lc as *const segment_command_64 as *const u8)
        //             .add(mem::size_of::<segment_command_64>())
        //             as *const section_64;

        //         for _ in 0..lc.nsects {
        //             let sect = &*sect_ptr;

        //             if (sect.flags & SECTION_TYPE) == S_THREAD_LOCAL_VARIABLES && sect.size != 0 {
        //                 if key == 0 {
        //                     let ret = libc::pthread_key_create(&mut key, Some(tlv_free as _));
        //                     if ret != 0 {
        //                         panic!("init tlv");
        //                     }
        //                 }

        //                 let tlv_desc = (sect.addr as usize + slide) as *mut TLVDescriptor;

        //                 for _ in 0..sect.size as usize / mem::size_of::<TLVDescriptor>() {
        //                     (*tlv_desc).thunk = tlv_get_addr as _;
        //                     (*tlv_desc).key = key;
        //                 }
        //             }

        //             sect_ptr = sect_ptr.add(1);
        //         }
        //     }

        //     false
        // })
    }

    unsafe fn get_loaded_dylib_by_ordinal(&self, ord: usize) -> Result<*mut c_void> {
        if ord > self.loaded_dylib.len() {
            Err(Error::NoSuchLibOrdinal(ord))
        } else {
            let hdl: *mut c_void = self.loaded_dylib[ord - 1];

            if hdl.is_null() {
                Err(Error::NoSuchLibOrdinal(ord))
            } else {
                Ok(hdl)
            }
        }
    }

    unsafe fn map_protection(&self) {
        self.iter_load_command(|lc| {
            if lc.cmd == LC_SEGMENT_64 {
                let lc = &*(lc as *const load_command as *const segment_command_64);

                if CStr::from_ptr(lc.segname.as_ptr()).to_str().unwrap_or("") == "__PAGEZERO" {
                    return true;
                }

                vm_protect(
                    libc::mach_task_self(),
                    self.base_addr + lc.vmaddr as usize,
                    lc.vmsize as usize,
                    0,
                    lc.initprot,
                );
            }

            true
        });
    }

    pub unsafe fn dlsym(&self, symbol: &str) -> Result<*const c_void> {
        let symtab_cmd = self.symtab_cmd()?;

        let mut symtab_ptr = self.file_hdr.add(symtab_cmd.symoff as usize) as *const nlist_64;

        for _ in 0..symtab_cmd.nsyms {
            let symtab = &*symtab_ptr;

            if symtab.n_type == N_SECT | N_EXT {
                let sym_name = CStr::from_ptr(
                    (self
                        .buf
                        .as_ptr()
                        .add(symtab_cmd.stroff as usize + symtab.n_strx as usize)
                        as *const i8)
                        .add(1),
                )
                .to_str();

                if let Ok(sym_name) = sym_name {
                    dp!("export symbol {sym_name}");

                    if sym_name == symbol {
                        return Ok((self.base_addr + symtab.n_value as usize) as *const c_void);
                    }
                }
            }

            symtab_ptr = symtab_ptr.add(1);
        }

        Err(Error::NoSuchSymbol(symbol.to_string()))
    }

    /*
    unsafe fn got(&self) -> Option<&section_64> {
        let mut ret = None;

        self.iter_load_command(|lc| {
            if lc.cmd == LC_SEGMENT_64 {
                let lc = &*(lc as *const load_command as *const segment_command_64);

                let mut sect_ptr = (lc as *const segment_command_64 as *const u8)
                    .add(mem::size_of::<segment_command_64>())
                    as *const section_64;

                for _ in 0..lc.nsects {
                    let sect = &*sect_ptr;

                    if &sect.sectname[..5] == "__got".as_bytes()
                        && &sect.segname[..12] == "__DATA_CONST".as_bytes()
                    {
                        ret = Some(sect);
                        return true;
                    }

                    sect_ptr = sect_ptr.add(1);
                }
            }

            false
        });

        ret
    }
    */

    unsafe fn map_segments(&self) {
        self.iter_load_command(|lc| {
            if lc.cmd == LC_SEGMENT_64 {
                let lc = &*(lc as *const load_command as *const segment_command_64);
                if lc.vmsize == 0 {
                    return true;
                }

                if CStr::from_ptr(lc.segname.as_ptr()).to_str().unwrap_or("") == "__PAGEZERO" {
                    return true;
                }

                dp!(
                    "segment {} size {:x} addr {:x}",
                    CStr::from_ptr(lc.segname.as_ptr()).to_str().unwrap(),
                    lc.vmsize,
                    lc.vmaddr,
                );

                dp!(
                    "copy from {:?} to {:?} size 0x{:x}",
                    self.file_hdr.add(lc.fileoff as usize),
                    (self.base_addr as *mut u8).add(lc.vmaddr as usize),
                    lc.filesize as usize,
                );

                // copy segments
                ptr::copy_nonoverlapping(
                    self.file_hdr.add(lc.fileoff as usize),
                    (self.base_addr as *mut u8).add(lc.vmaddr as usize),
                    lc.filesize as usize,
                );

                #[cfg(debug_assertions)]
                {
                    let mut sect_ptr = (lc as *const segment_command_64 as *const u8)
                        .add(mem::size_of::<segment_command_64>())
                        as *const section_64;

                    for _ in 0..lc.nsects {
                        let sect = &*sect_ptr;
                        dp!(
                            "section {:?}  seg {:?}  addr {:x} size {:x}",
                            CStr::from_bytes_until_nul(&sect.sectname),
                            CStr::from_bytes_until_nul(&sect.segname),
                            sect.addr,
                            sect.size
                        );

                        sect_ptr = sect_ptr.add(1);
                    }
                }
            }

            true
        });
    }

    unsafe fn call_term_func(&self) {
        self.iter_load_command(|lc| {
            if lc.cmd == LC_SEGMENT_64 {
                let lc = &*(lc as *const load_command as *const segment_command_64);

                let mut sect_ptr = (lc as *const segment_command_64 as *const u8)
                    .add(mem::size_of::<segment_command_64>())
                    as *const section_64;

                for _ in 0..lc.nsects {
                    let sect = &*sect_ptr;

                    if sect.flags & 0xff == S_MOD_TERM_FUNC_POINTERS {
                        let terminator_ptr = (self.base_addr + sect.addr as usize) as *const usize;

                        for i in 0..sect.size as usize / mem::size_of::<usize>() {
                            dp!(
                                "S_MOD_TERM_FUNC_POINTERS init thunk 0x{:x}",
                                *terminator_ptr.add(i)
                            );

                            mem::transmute::<usize, Terminator>(*terminator_ptr.add(i))();
                        }
                    }

                    sect_ptr = sect_ptr.add(1);
                }
            }

            true
        });
    }

    // https://juejin.cn/post/6982586012111208485
    unsafe fn call_init_func(&self) {
        self.iter_load_command(|lc| {
            if lc.cmd == LC_SEGMENT_64 {
                let lc = &*(lc as *const load_command as *const segment_command_64);

                let mut sect_ptr = (lc as *const segment_command_64 as *const u8)
                    .add(mem::size_of::<segment_command_64>())
                    as *const section_64;

                for _ in 0..lc.nsects {
                    let sect = &*sect_ptr;

                    if sect.flags & 0xff == S_INIT_FUNC_OFFSETS {
                        let initializer_offset_ptr =
                            (self.base_addr + sect.addr as usize) as *const u32;

                        for i in 0..sect.size as usize / mem::size_of::<u32>() {
                            dp!(
                                "S_INIT_FUNC_OFFSETS init thunk 0x{:x}",
                                self.base_addr + (*initializer_offset_ptr.add(i)) as usize
                            );

                            let pv = ProgramVars {
                                mh: self.base_addr + self.get_text_vmaddr(),
                                NXArgcPtr: _NSGetArgc(),
                                NXArgvPtr: _NSGetArgv(),
                                environPtr: _NSGetEnviron(),
                                __prognamePtr: *_NSGetArgv(),
                            };

                            mem::transmute::<usize, Initializer>(
                                self.base_addr + *initializer_offset_ptr.add(i) as usize,
                            )(
                                *_NSGetArgc(),
                                *_NSGetArgv(),
                                *_NSGetEnviron(),
                                get_apple_from_envp(),
                                &pv,
                            );
                        }
                    } else if sect.flags & 0xff == S_MOD_INIT_FUNC_POINTERS {
                        let initializer_ptr = (self.base_addr + sect.addr as usize) as *const usize;

                        for i in 0..sect.size as usize / mem::size_of::<usize>() {
                            dp!(
                                "S_MOD_INIT_FUNC_POINTERS init thunk 0x{:x}",
                                *initializer_ptr.add(i)
                            );

                            let pv = ProgramVars {
                                mh: self.base_addr + self.get_text_vmaddr(),
                                NXArgcPtr: _NSGetArgc(),
                                NXArgvPtr: _NSGetArgv(),
                                environPtr: _NSGetEnviron(),
                                __prognamePtr: *_NSGetArgv(),
                            };

                            mem::transmute::<usize, Initializer>(*initializer_ptr.add(i))(
                                *_NSGetArgc(),
                                *_NSGetArgv(),
                                *_NSGetEnviron(),
                                get_apple_from_envp(),
                                &pv,
                            );
                        }
                    }

                    sect_ptr = sect_ptr.add(1);
                }
            }

            true
        });
    }

    unsafe fn get_segment_by_index(&self, mut index: usize) -> Result<&segment_command_64> {
        let mut ret = Err(Error::SegmentOutOfRange(index));

        self.iter_load_command(|lc| {
            if lc.cmd == LC_SEGMENT_64 {
                if index == 0 {
                    ret = Ok(&*(lc as *const load_command as *const segment_command_64));
                    return false;
                }

                index -= 1;
            }

            true
        });

        ret
    }

    unsafe fn _handle_rebase_bytecodes(&self, bytecodes: *const u8, size: usize) -> Result<()> {
        unsafe fn do_rebase(base_addr: usize, address: usize, rebase_typ: u8) -> Result<()> {
            if rebase_typ == REBASE_TYPE_POINTER || rebase_typ == REBASE_TYPE_TEXT_ABSOLUTE32 {
                dp!(
                    "rebase +0x{:x} {:?} old 0x{:x} new 0x{:x}",
                    address as usize - base_addr,
                    address as *mut usize,
                    *(address as *mut usize),
                    *(address as *mut usize) + base_addr,
                );

                *(address as *mut usize) += base_addr;
            } else {
                return Err(Error::RebasePtrTyp(rebase_typ));
            }

            Ok(())
        }

        let mut typ = 0;
        let mut address = 0;
        let mut i = 0;

        while i != size {
            let b = *bytecodes.add(i);

            let opcode = b & REBASE_OPCODE_MASK;
            let immediate = b & REBASE_IMMEDIATE_MASK;

            i += 1;

            match opcode {
                REBASE_OPCODE_DONE => (),
                REBASE_OPCODE_SET_TYPE_IMM => {
                    typ = immediate;
                }
                REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                    address = self.base_addr
                        + self.get_segment_by_index(immediate as usize)?.vmaddr as usize
                        + read_uleb128(bytecodes, &mut i);
                }
                REBASE_OPCODE_ADD_ADDR_ULEB => {
                    address += read_uleb128(bytecodes, &mut i);
                }
                REBASE_OPCODE_ADD_ADDR_IMM_SCALED => {
                    address += immediate as usize * mem::size_of::<usize>();
                }
                REBASE_OPCODE_DO_REBASE_IMM_TIMES => {
                    for _ in 0..immediate {
                        do_rebase(self.base_addr, address, typ)?;

                        address += mem::size_of::<usize>();
                    }
                }
                REBASE_OPCODE_DO_REBASE_ULEB_TIMES => {
                    let count = read_uleb128(bytecodes, &mut i);

                    for _ in 0..count {
                        do_rebase(self.base_addr, address, typ)?;

                        address += mem::size_of::<usize>();
                    }
                }
                REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB => {
                    do_rebase(self.base_addr, address, typ)?;

                    address += read_uleb128(bytecodes, &mut i) + mem::size_of::<usize>();
                }
                REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB => {
                    let count = read_uleb128(bytecodes, &mut i);
                    let skip = read_uleb128(bytecodes, &mut i);
                    for _ in 0..count {
                        do_rebase(self.base_addr, address, typ)?;

                        address += skip + mem::size_of::<usize>();
                    }
                }
                n => return Err(Error::InvalidRebaseOpcode(n)),
            }
        }

        Ok(())
    }

    // https://github.com/opensource-apple/dyld/blob/3f928f32597888c5eac6003b9199d972d49857b5/src/ImageLoaderMachOCompressed.cpp#L934
    unsafe fn _handle_bind_bytecodes(&self, bytecodes: *const u8, size: usize) -> Result<()> {
        unsafe fn do_bind(
            base_addr: usize,
            sym_sz: *const i8,
            lib: *mut c_void,
            address: usize,
            addend: isize,
            bind_typ: u8,
        ) -> Result<()> {
            let proc = libc::dlsym(lib, sym_sz.add(1));

            if bind_typ == BIND_TYPE_POINTER || bind_typ == 0 {
                *((base_addr + address + addend as usize) as *mut *mut c_void) = proc;
            } else if bind_typ == BIND_TYPE_TEXT_ABSOLUTE32 {
                *((base_addr + address + addend as usize) as *mut u32) = proc as usize as u32;
            } else if bind_typ == BIND_TYPE_TEXT_PCREL32 {
                *((base_addr + address + addend as usize) as *mut u32) =
                    (base_addr + address + 4 - (proc as usize + addend as usize)) as u32;
            } else {
                return Err(Error::BindPtrTyp(bind_typ));
            }

            Ok(())
        }

        let mut lib_ordinal = 0_usize;
        let mut sym_sz = 0 as _;
        let mut weak_import = false;
        let mut typ = 0;
        let mut seg_index = 0;
        let mut address = 0;
        let mut addend = 0;
        let mut i = 0;

        while i != size {
            let b = *bytecodes.add(i);

            let opcode = b & BIND_OPCODE_MASK;
            let immediate = b & BIND_IMMEDIATE_MASK;

            i += 1;

            match opcode {
                BIND_OPCODE_DONE => (),
                BIND_OPCODE_SET_DYLIB_ORDINAL_IMM => {
                    lib_ordinal = immediate as usize;
                }
                BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB => {
                    lib_ordinal = read_uleb128(bytecodes, &mut i);
                }
                BIND_OPCODE_SET_DYLIB_SPECIAL_IMM => {
                    // the special ordinals are negative numbers
                    if immediate == 0 {
                        lib_ordinal = 0;
                    } else {
                        lib_ordinal = (self.loaded_dylib.len() as i8
                            + 1
                            + (BIND_OPCODE_MASK | immediate) as i8)
                            as usize;
                    }
                }
                BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => {
                    sym_sz = bytecodes.add(i);
                    weak_import = (immediate & BIND_SYMBOL_FLAGS_WEAK_IMPORT) != 0;

                    while *bytecodes.add(i) != 0 {
                        i += 1;
                    }

                    i += 1;
                }
                BIND_OPCODE_SET_TYPE_IMM => {
                    typ = immediate;
                }
                BIND_OPCODE_SET_ADDEND_SLEB => {
                    addend = read_sleb128(bytecodes, &mut i);
                }
                BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                    seg_index = immediate;
                    address = self.get_segment_by_index(seg_index as usize)?.vmaddr as usize
                        + read_uleb128(bytecodes, &mut i);
                }
                BIND_OPCODE_ADD_ADDR_ULEB => {
                    address += read_uleb128(bytecodes, &mut i);
                }
                BIND_OPCODE_DO_BIND => {
                    dp!("bind  typ {typ}  seg index {seg_index}  seg {} offset {address:x} weak {weak_import} symbol {}  lib_ord {lib_ordinal}", CStr::from_ptr(self.get_segment_by_index(seg_index as usize).unwrap().segname.as_ptr()).to_str().unwrap(), CStr::from_ptr(sym_sz as _).to_str().unwrap());

                    do_bind(
                        self.base_addr,
                        sym_sz as _,
                        self.get_loaded_dylib_by_ordinal(lib_ordinal)?,
                        address,
                        addend,
                        typ,
                    )?;
                    address += mem::size_of::<usize>();
                }
                BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => {
                    dp!("bind  typ {typ}  seg index {seg_index}  seg offset {address:x}  symbol {}  lib_ord {lib_ordinal}", CStr::from_ptr(sym_sz as _).to_str().unwrap());
                    do_bind(
                        self.base_addr,
                        sym_sz as _,
                        self.get_loaded_dylib_by_ordinal(lib_ordinal)?,
                        address,
                        addend,
                        typ,
                    )?;
                    address += read_uleb128(bytecodes, &mut i) + mem::size_of::<usize>();
                }
                BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => {
                    dp!("bind  typ {typ}  seg index {seg_index}  seg offset {address:x}  symbol {}  lib_ord {lib_ordinal}", CStr::from_ptr(sym_sz as _).to_str().unwrap());
                    do_bind(
                        self.base_addr,
                        sym_sz as _,
                        self.get_loaded_dylib_by_ordinal(lib_ordinal)?,
                        address,
                        addend,
                        typ,
                    )?;
                    address +=
                        immediate as usize * mem::size_of::<usize>() + mem::size_of::<usize>();
                }
                BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
                    let count = read_uleb128(bytecodes, &mut i);
                    let skip = read_uleb128(bytecodes, &mut i);

                    for _ in 0..count {
                        dp!("bind  typ {typ}  seg index {seg_index}  seg offset {address:x}  symbol {}  lib_ord {lib_ordinal}", CStr::from_ptr(sym_sz as _).to_str().unwrap());
                        do_bind(
                            self.base_addr,
                            sym_sz as _,
                            self.get_loaded_dylib_by_ordinal(lib_ordinal)?,
                            address,
                            addend,
                            typ,
                        )?;
                        address += mem::size_of::<usize>() + skip;
                    }
                }
                // https://github.com/lief-project/LIEF/blob/master/src/MachO/DyldInfo.cpp#L739
                // https://github.com/datatheorem/strongarm/blob/release/strongarm/macho/dyld_info_parser.py#L395
                BIND_OPCODE_THREADED => {}
                n => return Err(Error::InvalidBindOpcode(n)),
            }
        }

        Ok(())
    }

    unsafe fn rebase_and_bind_dyld_info(&self) -> Result<()> {
        let mut ret = Ok(());

        self.iter_load_command(|lc| {
            if lc.cmd == LC_DYLD_INFO || lc.cmd == LC_DYLD_INFO_ONLY {
                let lc = &*(lc as *const load_command as *const dyld_info_command);

                if let Err(e) = self._handle_rebase_bytecodes(
                    self.file_hdr.add(lc.rebase_off as usize),
                    lc.rebase_size as usize,
                ) {
                    ret = Err(e);
                    // return false;
                }

                dp!("bind info");
                if let Err(e) = self._handle_bind_bytecodes(
                    self.file_hdr.add(lc.bind_off as usize),
                    lc.bind_size as usize,
                ) {
                    ret = Err(e);
                    // return false;
                }

                // dp!("weak bind info");
                // if let Err(e) = self._handle_bind_bytecodes(
                //     self.file_hdr.add(lc.weak_bind_off as usize),
                //     lc.weak_bind_size as usize,
                // ) {
                //     ret = Err(e);
                //     //return false;
                // }

                dp!("lazy bind info");
                if let Err(e) = self._handle_bind_bytecodes(
                    self.file_hdr.add(lc.lazy_bind_off as usize),
                    lc.lazy_bind_size as usize,
                ) {
                    ret = Err(e);
                    // return false;
                }
            }

            true
        });

        ret
    }

    unsafe fn get_text_vmaddr(&self) -> usize {
        let mut vmaddr = 0;

        self.iter_load_command(|lc| {
            let lc = &*(lc as *const load_command as *const segment_command_64);
            if CStr::from_ptr(lc.segname.as_ptr()).to_str().unwrap_or("") == "__TEXT" {
                vmaddr = lc.vmaddr;
                return false;
            }

            true
        });

        vmaddr as usize
    }

    // https://github.com/datatheorem/strongarm/blob/release/chained_fixup_pointers.md
    // https://github.com/datatheorem/strongarm/blob/release/strongarm/macho/dyld_info_parser.py
    // http://opensource.apple.com//source/dyld/dyld-195.5/src/threadLocalVariables.c
    unsafe fn rebase_and_bind_chained_fixup(&self) -> Result<()> {
        let mut ret = Ok(());

        self.iter_load_command(|lc| {
            if lc.cmd == LC_DYLD_CHAINED_FIXUPS {
                let lc = &*(lc as *const load_command as *const linkedit_data_command);

                let chained_fixups_data_addr = self.file_hdr.add(lc.dataoff as usize);
                let fixups_hdr = &*(chained_fixups_data_addr as *const dyld_chained_fixups_header);

                let mut symbols = Vec::new();
                // uncompressed
                if fixups_hdr.symbols_format == 0 {
                    if fixups_hdr.imports_format == DYLD_CHAINED_IMPORT {
                        let mut chained_imp_ptr = chained_fixups_data_addr
                            .add(fixups_hdr.imports_offset as usize)
                            as *const dyld_chained_import;
                        for _ in 0..fixups_hdr.imports_count {
                            let chained_imp = &*chained_imp_ptr;

                            symbols.push((
                                chained_imp.lib_ordinal() as usize,
                                chained_fixups_data_addr.add(
                                    fixups_hdr.symbols_offset as usize
                                        + chained_imp.name_offset() as usize,
                                ) as *const i8,
                            ));

                            chained_imp_ptr = chained_imp_ptr.add(1);
                        }
                    } else if fixups_hdr.imports_format == DYLD_CHAINED_IMPORT_ADDEND {
                        let mut chained_imp_ptr = chained_fixups_data_addr
                            .add(fixups_hdr.imports_offset as usize)
                            as *const dyld_chained_import_addend;

                        for _ in 0..fixups_hdr.imports_count {
                            let chained_imp = &*chained_imp_ptr;

                            symbols.push((
                                chained_imp.lib_ordinal() as usize,
                                chained_fixups_data_addr.add(
                                    fixups_hdr.symbols_offset as usize
                                        + chained_imp.name_offset() as usize,
                                ) as *const i8,
                            ));

                            chained_imp_ptr = chained_imp_ptr.add(1);
                        }
                    } else if fixups_hdr.imports_format == DYLD_CHAINED_IMPORT_ADDEND64 {
                        let mut chained_imp_ptr = chained_fixups_data_addr
                            .add(fixups_hdr.imports_offset as usize)
                            as *const dyld_chained_import_addend64;

                        for _ in 0..fixups_hdr.imports_count {
                            let chained_imp = &*chained_imp_ptr;

                            symbols.push((
                                chained_imp.lib_ordinal() as usize,
                                chained_fixups_data_addr.add(
                                    fixups_hdr.symbols_offset as usize
                                        + chained_imp.name_offset() as usize,
                                ) as *const i8,
                            ));

                            chained_imp_ptr = chained_imp_ptr.add(1);
                        }
                    } else {
                        ret = Err(Error::FixupImportsFormat(fixups_hdr.imports_format));
                        return false;
                    }
                } else {
                    ret = Err(Error::FixupSymbolFormat(fixups_hdr.symbols_format));
                    return false;
                }

                let chained_starts_in_image_addr =
                    chained_fixups_data_addr.add(fixups_hdr.starts_offset as usize);
                let chained_starts_in_image =
                    &*(chained_starts_in_image_addr as *const dyld_chained_starts_in_image);

                let text_vmaddr = self.get_text_vmaddr();

                for seg_i in 0..chained_starts_in_image.seg_count as usize {
                    let starts_in_seg_offset =
                        *chained_starts_in_image.seg_info_offset.as_ptr().add(seg_i);
                    if starts_in_seg_offset == 0 {
                        continue;
                    }

                    let starts_in_seg = &*(chained_starts_in_image_addr
                        .add(starts_in_seg_offset as usize)
                        as *const dyld_chained_starts_in_segment);

                    for page_i in 0..starts_in_seg.page_count as usize {
                        let page_offset = *starts_in_seg.page_start.as_ptr().add(page_i);

                        if page_offset == DYLD_CHAINED_PTR_START_NONE {
                            continue;
                        }

                        let mut chain_addr = starts_in_seg.segment_offset as usize
                            + starts_in_seg.page_size as usize * page_i
                            + page_offset as usize;

                        loop {
                            if *(self.file_hdr.add(chain_addr) as *const u64) >> 63 == 1 {
                                let chained_bind = &*(self.file_hdr.add(chain_addr)
                                    as *const dyld_chained_ptr_64_bind);

                                let (lib_ordinal, sym_sz) =
                                    symbols[chained_bind.ordinal() as usize];

                                let hdl = self.get_loaded_dylib_by_ordinal(lib_ordinal as usize);
                                let proc = if let Ok(hdl) = hdl {
                                    libc::dlsym(hdl, sym_sz.add(1))
                                } else {
                                    ret = Err(Error::NoSuchLibOrdinal(lib_ordinal as usize));
                                    return false;
                                };

                                *((self.base_addr + text_vmaddr + chain_addr)
                                    as *mut *const c_void) = proc;

                                if chained_bind.next() == 0 {
                                    break;
                                }

                                // 4-byte stride
                                chain_addr += chained_bind.next() as usize * 4;
                            } else {
                                let chained_rebase = &*(self.file_hdr.add(chain_addr)
                                    as *const dyld_chained_ptr_64_rebase);

                                if starts_in_seg.pointer_format == DYLD_CHAINED_PTR_64_OFFSET {
                                    *((self.base_addr + text_vmaddr + chain_addr) as *mut usize) =
                                        self.base_addr
                                            + text_vmaddr
                                            + chained_rebase.target() as usize;
                                } else if starts_in_seg.pointer_format == DYLD_CHAINED_PTR_64 {
                                    *((self.base_addr + text_vmaddr + chain_addr) as *mut usize) =
                                        chained_rebase.target() as usize;
                                } else {
                                    ret = Err(Error::FixupPointerFormat(
                                        starts_in_seg.pointer_format,
                                    ));
                                    return false;
                                }

                                if chained_rebase.next() == 0 {
                                    break;
                                }
                                chain_addr += chained_rebase.next() as usize * 4;
                            }
                        }
                    }
                }
            }

            true
        });

        Ok(())
    }

    unsafe fn symtab_cmd(&self) -> Result<&symtab_command> {
        let mut sym_tbl = Err(Error::NoSymTbl);

        self.iter_load_command(|lc| {
            if lc.cmd == LC_SYMTAB {
                let lc = &*(lc as *const load_command as *const symtab_command);

                sym_tbl = Ok(lc);
            }

            true
        });

        sym_tbl
    }
}
