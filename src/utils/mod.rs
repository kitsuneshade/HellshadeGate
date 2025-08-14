use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::Foundation::HMODULE;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

pub unsafe fn get_module_handle_unsafe(module_name: &str) -> Option<HMODULE> {
    use windows::core::PCWSTR;
    let wide: Vec<u16> = OsStr::new(module_name).encode_wide().chain(std::iter::once(0)).collect();
    let handle = GetModuleHandleW(PCWSTR(wide.as_ptr()));
        match handle.ok() {
        Some(h) if !h.is_invalid() => Some(h),
        _ => None,
    }
}