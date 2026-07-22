#![cfg(windows)]
#![no_std]
#![allow(non_snake_case)]

mod pak;
mod sigscan;

use core::ffi::c_void;

use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, VirtualProtect};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

// CALL rel32 to the pak signing-keys getter, then its result moved into rdi and
// compared. The first byte (E8) is the CALL we resolve to the getter.
const PATTERN: &[u8] =
    b"\xE8\x00\x00\x00\x00\x48\x8B\xF8\x39\x70\x00\x0F\x84\x00\x00\x00\x00";
const MASK: &[u8] = b"x????xxxxx?xx????";

// The zeroed keys handed back to the engine. `static mut` (writable .data)
// because the engine reads this struct; it is never mutated at runtime.
static mut SIGNING_KEYS: pak::FPakSigningKeys = pak::FPakSigningKeys { function: 0, size: 0 };

// Replaces the engine's GetPakSigningKeysDelegate: always reports "no keys", so
// unsigned content is accepted.
unsafe extern "system" fn get_pak_signing_keys() -> *mut pak::FPakSigningKeys {
    &raw mut SIGNING_KEYS
}

unsafe fn install() -> Option<()> {
    let module = sigscan::main_module()?;
    let site = unsafe { sigscan::sig_scan(PATTERN, MASK, &module) }?;
    let target = unsafe { sigscan::target_of_call(site) } as *mut u8;

    // Overwrite the getter's prologue with `jmp qword ptr [rip+0]; <abs addr>`.
    // We fully replace the function and never call the original, so no trampoline
    // is needed and the original bytes can be discarded.
    let mut patch = [0u8; 14];
    patch[0] = 0xFF; // \
    patch[1] = 0x25; //  jmp qword ptr [rip+0]
    patch[6..].copy_from_slice(&(get_pak_signing_keys as *const () as u64).to_le_bytes());

    unsafe {
        let mut old = 0u32;
        if VirtualProtect(target.cast(), patch.len(), PAGE_EXECUTE_READWRITE, &mut old) == 0 {
            return None;
        }
        core::ptr::copy_nonoverlapping(patch.as_ptr(), target, patch.len());
        let mut restored = 0u32;
        VirtualProtect(target.cast(), patch.len(), old, &mut restored);
        FlushInstructionCache(GetCurrentProcess(), target.cast(), patch.len());
    }
    Some(())
}

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(_module: *mut c_void, reason: u32, _reserved: *mut c_void) -> i32 {
    const DLL_PROCESS_ATTACH: u32 = 1;
    if reason == DLL_PROCESS_ATTACH {
        let _ = unsafe { install() };
    }
    1
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
