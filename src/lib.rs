#![cfg(windows)]
#![allow(non_snake_case)]

mod pak;
mod proxy;
mod sigscan;

use minhook::MinHook;
use windows_sys::Win32::Foundation::HINSTANCE;
use windows_sys::Win32::System::SystemServices::DLL_PROCESS_ATTACH;

const PATTERN: &[u8] =
    b"\xE8\x00\x00\x00\x00\x48\x8B\xF8\x39\x70\x00\x0F\x84\x00\x00\x00\x00";
const MASK: &[u8] = b"x????xxxxx?xx????";

static mut SIGNING_KEYS: *mut pak::FPakSigningKeys = core::ptr::null_mut();

unsafe extern "system" fn hook_get_pak_signing_keys() -> *mut pak::FPakSigningKeys {
    unsafe { SIGNING_KEYS }
}

unsafe fn install() -> Result<(), Box<dyn core::error::Error>> {
    let module = sigscan::main_module().ok_or("module info failed")?;
    let site = unsafe { sigscan::sig_scan(PATTERN, MASK, &module) }.ok_or("signature not found")?;
    let target = unsafe { sigscan::target_of_call(site) };

    unsafe {
        SIGNING_KEYS = pak::make_zeroed();

        MinHook::create_hook(
            target as *mut core::ffi::c_void,
            hook_get_pak_signing_keys as *mut core::ffi::c_void,
        )?;
        MinHook::enable_all_hooks()?;
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(
    h: HINSTANCE,
    reason: u32,
    _reserved: *mut core::ffi::c_void,
) -> i32 {
    if reason == DLL_PROCESS_ATTACH {
        unsafe {
            proxy::init(h);
            let _ = install();
        }
    }
    1
}
