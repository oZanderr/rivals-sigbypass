use core::arch::asm;
use core::ffi::c_void;
use core::ptr;

use windows_sys::Win32::Foundation::{HINSTANCE, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    _pad: u32,
    buffer: *mut u16,
}

#[repr(C)]
struct ListEntry {
    flink: *mut ListEntry,
    blink: *mut ListEntry,
}

#[repr(C)]
struct PebLdrData {
    length: u32,
    initialized: u8,
    _pad0: [u8; 3],
    ss_handle: *mut c_void,
    in_load_order_module_list: ListEntry,
}

#[repr(C)]
struct Peb {
    _pad0: [u8; 0x18],
    ldr: *mut PebLdrData,
}

#[repr(C)]
struct LdrDataTableEntry {
    in_load_order: ListEntry,
    in_memory_order: ListEntry,
    in_init_order: ListEntry,
    dll_base: *mut c_void,
    entry_point: *mut c_void,
    size_of_image: u32,
    _pad0: u32,
    full_dll_name: UnicodeString,
    base_dll_name: UnicodeString,
}

const fn ascii_u16<const N: usize>(s: &[u8; N]) -> [u16; N] {
    let mut out = [0u16; N];
    let mut i = 0;
    while i < N {
        out[i] = s[i] as u16;
        i += 1;
    }
    out
}

static SPOOF_NAME: [u16; 11] = ascii_u16(b"_proxy_v.dl");
static VERSION_DLL_NAME: [u16; 11] = ascii_u16(b"version.dll");
static SYSTEM_DLL: [u16; 32] = ascii_u16(b"C:\\Windows\\System32\\version.dll\0");

static mut REAL_GET_FILE_VERSION_INFO_A: *mut c_void = ptr::null_mut();
static mut REAL_GET_FILE_VERSION_INFO_BY_HANDLE: *mut c_void = ptr::null_mut();
static mut REAL_GET_FILE_VERSION_INFO_EX_A: *mut c_void = ptr::null_mut();
static mut REAL_GET_FILE_VERSION_INFO_EX_W: *mut c_void = ptr::null_mut();
static mut REAL_GET_FILE_VERSION_INFO_SIZE_A: *mut c_void = ptr::null_mut();
static mut REAL_GET_FILE_VERSION_INFO_SIZE_EX_A: *mut c_void = ptr::null_mut();
static mut REAL_GET_FILE_VERSION_INFO_SIZE_EX_W: *mut c_void = ptr::null_mut();
static mut REAL_GET_FILE_VERSION_INFO_SIZE_W: *mut c_void = ptr::null_mut();
static mut REAL_GET_FILE_VERSION_INFO_W: *mut c_void = ptr::null_mut();
static mut REAL_VER_FIND_FILE_A: *mut c_void = ptr::null_mut();
static mut REAL_VER_FIND_FILE_W: *mut c_void = ptr::null_mut();
static mut REAL_VER_INSTALL_FILE_A: *mut c_void = ptr::null_mut();
static mut REAL_VER_INSTALL_FILE_W: *mut c_void = ptr::null_mut();
static mut REAL_VER_LANGUAGE_NAME_A: *mut c_void = ptr::null_mut();
static mut REAL_VER_LANGUAGE_NAME_W: *mut c_void = ptr::null_mut();
static mut REAL_VER_QUERY_VALUE_A: *mut c_void = ptr::null_mut();
static mut REAL_VER_QUERY_VALUE_W: *mut c_void = ptr::null_mut();

unsafe fn read_peb() -> *const Peb {
    let p: *const Peb;
    unsafe {
        asm!("mov {}, gs:[0x60]", out(reg) p, options(nostack, preserves_flags));
    }
    p
}

unsafe fn for_each_module(mut f: impl FnMut(*mut LdrDataTableEntry) -> bool) {
    unsafe {
        let peb = read_peb();
        if peb.is_null() {
            return;
        }
        let ldr = (*peb).ldr;
        if ldr.is_null() {
            return;
        }
        let head = (&raw const (*ldr).in_load_order_module_list) as *mut ListEntry;
        let mut cur = (*head).flink;
        let mut steps: u32 = 0;
        while !cur.is_null() && cur != head && steps < 1024 {
            if f(cur as *mut LdrDataTableEntry) {
                return;
            }
            cur = (*cur).flink;
            steps += 1;
        }
    }
}

// Rename our PEB entry so `LoadLibraryW("version.dll")` misses the loader's
// name cache and fetches the system DLL. No-op under Wine.
unsafe fn rename_self(our_base: *mut c_void) {
    unsafe {
        for_each_module(|entry| {
            if (*entry).dll_base != our_base {
                return false;
            }
            (*entry).base_dll_name.buffer = SPOOF_NAME.as_ptr() as *mut u16;
            (*entry).base_dll_name.length = (SPOOF_NAME.len() * 2) as u16;
            (*entry).base_dll_name.maximum_length = (*entry).base_dll_name.length;
            true
        });
    }
}

unsafe fn find_other_version_dll(excluded: *mut c_void) -> Option<HMODULE> {
    let mut found: Option<HMODULE> = None;
    unsafe {
        for_each_module(|entry| {
            if (*entry).dll_base == excluded
                || !unicode_eq_ascii_ci(&(*entry).base_dll_name, &VERSION_DLL_NAME)
            {
                return false;
            }
            found = Some((*entry).dll_base as HMODULE);
            true
        });
    }
    found
}

unsafe fn unicode_eq_ascii_ci(s: &UnicodeString, lowercase_needle: &[u16]) -> bool {
    let len = (s.length / 2) as usize;
    if len != lowercase_needle.len() {
        return false;
    }
    for i in 0..len {
        let mut a = unsafe { *s.buffer.add(i) };
        if (b'A' as u16..=b'Z' as u16).contains(&a) {
            a += 32;
        }
        if a != lowercase_needle[i] {
            return false;
        }
    }
    true
}

pub unsafe fn init(our_module: HINSTANCE) {
    unsafe {
        let our_base = our_module as *mut c_void;
        rename_self(our_base);
        let loaded = LoadLibraryW(SYSTEM_DLL.as_ptr());
        // Windows: `loaded` is the system DLL. Wine: `loaded` is usually us,
        // so we walk the PEB for the builtin
        let h: HMODULE = if loaded.is_null() || loaded == our_module {
            find_other_version_dll(our_base).unwrap_or(ptr::null_mut())
        } else {
            loaded
        };
        if h.is_null() {
            return;
        }
        let resolve = |name: &[u8]| -> *mut c_void {
            GetProcAddress(h, name.as_ptr()).map_or(ptr::null_mut(), |f| f as *mut c_void)
        };
        REAL_GET_FILE_VERSION_INFO_A = resolve(b"GetFileVersionInfoA\0");
        REAL_GET_FILE_VERSION_INFO_BY_HANDLE = resolve(b"GetFileVersionInfoByHandle\0");
        REAL_GET_FILE_VERSION_INFO_EX_A = resolve(b"GetFileVersionInfoExA\0");
        REAL_GET_FILE_VERSION_INFO_EX_W = resolve(b"GetFileVersionInfoExW\0");
        REAL_GET_FILE_VERSION_INFO_SIZE_A = resolve(b"GetFileVersionInfoSizeA\0");
        REAL_GET_FILE_VERSION_INFO_SIZE_EX_A = resolve(b"GetFileVersionInfoSizeExA\0");
        REAL_GET_FILE_VERSION_INFO_SIZE_EX_W = resolve(b"GetFileVersionInfoSizeExW\0");
        REAL_GET_FILE_VERSION_INFO_SIZE_W = resolve(b"GetFileVersionInfoSizeW\0");
        REAL_GET_FILE_VERSION_INFO_W = resolve(b"GetFileVersionInfoW\0");
        REAL_VER_FIND_FILE_A = resolve(b"VerFindFileA\0");
        REAL_VER_FIND_FILE_W = resolve(b"VerFindFileW\0");
        REAL_VER_INSTALL_FILE_A = resolve(b"VerInstallFileA\0");
        REAL_VER_INSTALL_FILE_W = resolve(b"VerInstallFileW\0");
        REAL_VER_LANGUAGE_NAME_A = resolve(b"VerLanguageNameA\0");
        REAL_VER_LANGUAGE_NAME_W = resolve(b"VerLanguageNameW\0");
        REAL_VER_QUERY_VALUE_A = resolve(b"VerQueryValueA\0");
        REAL_VER_QUERY_VALUE_W = resolve(b"VerQueryValueW\0");
    }
}

// Naked `jmp [REAL]` preserves all registers and stack args. Null `REAL` falls
// through to `xor eax, eax; ret`.
macro_rules! proxy_thunk {
    ($name:ident, $real:ident) => {
        #[unsafe(naked)]
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn $name() {
            core::arch::naked_asm!(
                "mov rax, qword ptr [rip + {ptr}]",
                "test rax, rax",
                "jz 2f",
                "jmp rax",
                "2:",
                "xor eax, eax",
                "ret",
                ptr = sym $real,
            );
        }
    };
}

proxy_thunk!(GetFileVersionInfoA, REAL_GET_FILE_VERSION_INFO_A);
proxy_thunk!(GetFileVersionInfoByHandle, REAL_GET_FILE_VERSION_INFO_BY_HANDLE);
proxy_thunk!(GetFileVersionInfoExA, REAL_GET_FILE_VERSION_INFO_EX_A);
proxy_thunk!(GetFileVersionInfoExW, REAL_GET_FILE_VERSION_INFO_EX_W);
proxy_thunk!(GetFileVersionInfoSizeA, REAL_GET_FILE_VERSION_INFO_SIZE_A);
proxy_thunk!(GetFileVersionInfoSizeExA, REAL_GET_FILE_VERSION_INFO_SIZE_EX_A);
proxy_thunk!(GetFileVersionInfoSizeExW, REAL_GET_FILE_VERSION_INFO_SIZE_EX_W);
proxy_thunk!(GetFileVersionInfoSizeW, REAL_GET_FILE_VERSION_INFO_SIZE_W);
proxy_thunk!(GetFileVersionInfoW, REAL_GET_FILE_VERSION_INFO_W);
proxy_thunk!(VerFindFileA, REAL_VER_FIND_FILE_A);
proxy_thunk!(VerFindFileW, REAL_VER_FIND_FILE_W);
proxy_thunk!(VerInstallFileA, REAL_VER_INSTALL_FILE_A);
proxy_thunk!(VerInstallFileW, REAL_VER_INSTALL_FILE_W);
proxy_thunk!(VerLanguageNameA, REAL_VER_LANGUAGE_NAME_A);
proxy_thunk!(VerLanguageNameW, REAL_VER_LANGUAGE_NAME_W);
proxy_thunk!(VerQueryValueA, REAL_VER_QUERY_VALUE_A);
proxy_thunk!(VerQueryValueW, REAL_VER_QUERY_VALUE_W);
