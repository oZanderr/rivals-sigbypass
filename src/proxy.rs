use core::arch::asm;
use core::ffi::c_void;
use core::ptr;
use windows_sys::Win32::Foundation::HINSTANCE;
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

static SPOOF_NAME: [u16; 11] = [
    b'_' as u16, b'p' as u16, b'r' as u16, b'o' as u16, b'x' as u16,
    b'y' as u16, b'_' as u16, b'v' as u16, b'.' as u16, b'd' as u16,
    b'l' as u16,
];

const SYSTEM_DLL: &[u16] = &[
    b'C' as u16, b':' as u16, b'\\' as u16,
    b'W' as u16, b'i' as u16, b'n' as u16, b'd' as u16, b'o' as u16,
    b'w' as u16, b's' as u16, b'\\' as u16,
    b'S' as u16, b'y' as u16, b's' as u16, b't' as u16, b'e' as u16,
    b'm' as u16, b'3' as u16, b'2' as u16, b'\\' as u16,
    b'v' as u16, b'e' as u16, b'r' as u16, b's' as u16, b'i' as u16,
    b'o' as u16, b'n' as u16, b'.' as u16, b'd' as u16, b'l' as u16,
    b'l' as u16, 0,
];

// Populated by init() during DllMain before LoadLibrary returns, so thunks
// always observe non-null pointers under loader synchronization.
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

unsafe fn rename_self(our_base: *mut c_void) -> bool {
    let peb: *const Peb;
    unsafe {
        asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, preserves_flags));
    }
    if peb.is_null() {
        return false;
    }
    let ldr = unsafe { (*peb).ldr };
    if ldr.is_null() {
        return false;
    }
    let head = unsafe { (&raw const (*ldr).in_load_order_module_list) as *mut ListEntry };
    let mut cur = unsafe { (*head).flink };
    let mut steps: u32 = 0;
    while !cur.is_null() && cur != head && steps < 1024 {
        let entry = cur as *mut LdrDataTableEntry;
        if unsafe { (*entry).dll_base } == our_base {
            unsafe {
                (*entry).base_dll_name.buffer = SPOOF_NAME.as_ptr() as *mut u16;
                (*entry).base_dll_name.length = (SPOOF_NAME.len() * 2) as u16;
                (*entry).base_dll_name.maximum_length = (*entry).base_dll_name.length;
            }
            return true;
        }
        cur = unsafe { (*cur).flink };
        steps += 1;
    }
    false
}

pub unsafe fn init(our_module: HINSTANCE) {
    unsafe {
        let _ = rename_self(our_module as *mut c_void);
        let h = LoadLibraryW(SYSTEM_DLL.as_ptr());
        if h.is_null() {
            return;
        }
        let resolve = |name: &[u8]| -> *mut c_void {
            GetProcAddress(h, name.as_ptr())
                .map_or(ptr::null_mut(), |f| f as *mut c_void)
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

// Naked jmp preserves registers and stack args, avoiding per-export signatures.
// Null pointer falls through to `xor eax, eax; ret` for a clean failure.
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
