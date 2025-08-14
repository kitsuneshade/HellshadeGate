use windows::Win32::System::SystemServices::{IMAGE_EXPORT_DIRECTORY, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE};
use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
use crate::gate::Entry;

pub fn get_image_export_directory(module_base: *mut u8, export_dir: &mut *mut IMAGE_EXPORT_DIRECTORY) -> bool {
    unsafe {
        let dos_header = &*(module_base as *const IMAGE_DOS_HEADER);
        if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
            return false;
        }
        let nt_headers = &*((module_base.offset(dos_header.e_lfanew as isize)) as *const IMAGE_NT_HEADERS64);
        if nt_headers.Signature != IMAGE_NT_SIGNATURE {
            return false;
        }
        let export_dir_va = nt_headers.OptionalHeader.DataDirectory[0].VirtualAddress;
        if export_dir_va == 0 {
            return false;
        }
        *export_dir = (module_base.offset(export_dir_va as isize)) as *mut IMAGE_EXPORT_DIRECTORY;
        true
    }
}

pub fn get_syscall_entry(module_base: *mut u8, export_dir: *const IMAGE_EXPORT_DIRECTORY, entry: &mut Entry) -> bool {
    unsafe {
        let address_of_function = (module_base.offset((*export_dir).AddressOfFunctions as isize)) as *const u32;
        let address_of_names = (module_base.offset((*export_dir).AddressOfNames as isize)) as *const u32;
        let address_of_name_ordinals = (module_base.offset((*export_dir).AddressOfNameOrdinals as isize)) as *const u16;
        for i in 0..(*export_dir).NumberOfNames {
            let function_name_ptr = module_base.offset(*address_of_names.offset(i as isize) as isize);
            let mut len = 0;
            while *function_name_ptr.add(len) != 0 {
                len += 1;
            }
            let function_name = std::slice::from_raw_parts(function_name_ptr as *const u8, len);
            if crate::gate::custom_hash(function_name) == entry.hash {
                let ordinal = *address_of_name_ordinals.offset(i as isize) as isize;
                let function_address = module_base.offset(*address_of_function.offset(ordinal) as isize);
                entry.addr = function_address;
                let bytes = std::slice::from_raw_parts(function_address, 8);
                if bytes[0] == 0x4c && bytes[1] == 0x8b && bytes[2] == 0xd1 && bytes[3] == 0xb8 && bytes[6] == 0x00 && bytes[7] == 0x00 {
                    entry.syscall_id = ((bytes[5] as u16) << 8) | bytes[4] as u16;
                    return true;
                }
                return false;
            }
        }
        false
    }
}

