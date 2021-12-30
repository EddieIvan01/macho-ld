use std::fmt::Debug;

#[cfg_attr(debug_assertions, derive(Debug))]
pub enum Error {
    ImportDylib(*const u8),
    NoSuchLibOrdinal(usize),
    NoSuchSymbol(String),
    SegmentOutOfRange(usize),
    InvalidBindOpcode(u8),
    InvalidRebaseOpcode(u8),
    NoSymTbl,
    VmAlloc(i32),
    VmDeAlloc(i32),
    FixupImportsFormat(u32),
    FixupSymbolFormat(u32),
    FixupPointerFormat(u16),
    BindPtrTyp(u8),
    RebasePtrTyp(u8),
    NoEntryPoint,
    UnsupportedArch,
}

// Obfuscate literal strings
//
// impl Debug for Error {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         match self {
//             Self::ImportDylib(arg0) => f
//                 .debug_tuple(obfstr::obfstr!("ImportDylib"))
//                 .field(arg0)
//                 .finish(),
//             Self::NoSuchLibOrdinal(arg0) => f
//                 .debug_tuple(obfstr::obfstr!("NoSuchLibOrdinal"))
//                 .field(arg0)
//                 .finish(),
//             Self::NoSuchSymbol(arg0) => f
//                 .debug_tuple(obfstr::obfstr!("NoSuchSymbol"))
//                 .field(arg0)
//                 .finish(),
//             Self::SegmentOutOfRange(arg0) => f
//                 .debug_tuple(obfstr::obfstr!("SegmentOutOfRange"))
//                 .field(arg0)
//                 .finish(),
//             Self::InvalidBindOpcode(arg0) => f
//                 .debug_tuple(obfstr::obfstr!("InvalidBindOpcode"))
//                 .field(arg0)
//                 .finish(),
//             Self::InvalidRebaseOpcode(arg0) => f
//                 .debug_tuple(obfstr::obfstr!("InvalidRebaseOpcode"))
//                 .field(arg0)
//                 .finish(),
//             Self::NoSymTbl => f.write_str(obfstr::obfstr!("NoSymTbl")),
//             Self::VmAlloc(arg0) => f
//                 .debug_tuple(obfstr::obfstr!("VmAlloc"))
//                 .field(arg0)
//                 .finish(),
//             Self::VmDeAlloc(arg0) => f
//                 .debug_tuple(obfstr::obfstr!("VmDeAlloc"))
//                 .field(arg0)
//                 .finish(),
//             Self::FixupImportsFormat(arg0) => f
//                 .debug_tuple(obfstr::obfstr!("FixupImportsFormat"))
//                 .field(arg0)
//                 .finish(),
//             Self::FixupSymbolFormat(arg0) => f
//                 .debug_tuple(obfstr::obfstr!("FixupSymbolFormat"))
//                 .field(arg0)
//                 .finish(),
//             Self::FixupPointerFormat(arg0) => f
//                 .debug_tuple(obfstr::obfstr!("FixupPointerFormat"))
//                 .field(arg0)
//                 .finish(),
//             Self::BindPtrTyp(arg0) => f
//                 .debug_tuple(obfstr::obfstr!("BindPtrTyp"))
//                 .field(arg0)
//                 .finish(),
//             Self::RebasePtrTyp(arg0) => f
//                 .debug_tuple(obfstr::obfstr!("RebasePtrTyp"))
//                 .field(arg0)
//                 .finish(),
//             Self::NoEntryPoint => f.write_str(obfstr::obfstr!("NoEntryPoint")),
//             Self::UnsupportedArch => f.write_str(obfstr::obfstr!("UnsupportedArch")),
//         }
//     }
// }

pub type Result<T> = std::result::Result<T, Error>;
