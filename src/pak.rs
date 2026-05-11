#[repr(C)]
pub struct FPakSigningKeys {
    pub function: u64,
    pub size: i32,
}

pub fn make_zeroed() -> *mut FPakSigningKeys {
    Box::into_raw(Box::new(FPakSigningKeys {
        function: 0,
        size: 0,
    }))
}
