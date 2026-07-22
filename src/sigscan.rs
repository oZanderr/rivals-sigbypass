use core::mem::size_of;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::ProcessStatus::{GetModuleInformation, MODULEINFO};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

#[allow(clippy::cast_possible_truncation)]
const MI_SIZE: u32 = size_of::<MODULEINFO>() as u32;

pub struct ModuleInfo {
    pub base: *mut u8,
    pub size: usize,
}

pub fn main_module() -> Option<ModuleInfo> {
    unsafe {
        let h = GetModuleHandleW(core::ptr::null());
        if h.is_null() {
            return None;
        }
        let mut mi: MODULEINFO = core::mem::zeroed();
        if GetModuleInformation(GetCurrentProcess(), h, &raw mut mi, MI_SIZE) == 0
        {
            return None;
        }
        Some(ModuleInfo {
            base: mi.lpBaseOfDll.cast::<u8>(),
            size: mi.SizeOfImage as usize,
        })
    }
}

pub unsafe fn sig_scan(pattern: &[u8], mask: &[u8], region: &ModuleInfo) -> Option<*mut u8> {
    let n = mask.len();
    if pattern.len() < n || region.size < n {
        return None;
    }
    unsafe {
        'outer: for i in 0..=region.size - n {
            let p = region.base.add(i);
            for j in 0..n {
                if mask[j] != b'?' && *p.add(j) != pattern[j] {
                    continue 'outer;
                }
            }
            return Some(p);
        }
    }
    None
}

pub unsafe fn target_of_call(call_site: *const u8) -> usize {
    unsafe {
        let rel = core::ptr::read_unaligned(call_site.add(1).cast::<i32>());
        (call_site as usize)
            .wrapping_add((rel as isize).cast_unsigned())
            .wrapping_add(5)
    }
}
