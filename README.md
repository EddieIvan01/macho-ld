## macho-ld

In-memory loading and executing Mach-O files.

## Features

### Supporting 

+ executable and dylib
+ fat binary (universal binary)
+ chained fixup and dyld info

### Unsupporting

+ 32 bit binary (is there still 32-bit MacOS in the world?)
+ executable without relocation informations (like `/bin/*`)
+ objective-C runtime initialization
+ weak bind info handling

## Example

```rust
let mut f = File::open(bin_path).unwrap();
let mut buf = Vec::new();

f.read_to_end(&mut buf).unwrap();

unsafe {
    let mut ld = macho_ld::MachOLoader::new(&buf).unwrap();

    // executable
    ld.load().unwrap();
    ld.execute(&["/bin/bash", "-h"]).unwrap();

    // dylib
    let proc = ld.dlsym("invoke").unwrap();
    mem::transmute::<*const c_void, extern "C" fn(*const u8)>(x)(
        "0".as_ptr(),
    );
    
}
```