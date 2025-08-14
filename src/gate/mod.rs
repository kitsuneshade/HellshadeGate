// Custom hash function (not DJB2)
pub fn custom_hash(s: &[u8]) -> u64 {
    let mut hash: u64 = 0x123456789abcdef0;
    for (i, &b) in s.iter().enumerate() {
        hash ^= (b as u64).wrapping_mul((i as u64) + 1);
        hash = hash.rotate_left(7);
    }
    hash
}


use windows::Win32::Foundation::NTSTATUS;



#[repr(C)]
#[derive(Debug)]
pub struct Entry {
    pub addr: *mut u8,
    pub hash: u64,
    pub syscall_id: u16,
}

#[repr(C)]
#[derive(Debug)]
pub struct Table {
    pub alloc: Entry,
    pub protect: Entry,
    pub thread: Entry,
    pub write: Entry,
}

#[link(name = "TartarusGate", kind = "static")]
extern "C" {
    pub fn BasicGate(id: u16);
    pub fn BasicExec(
        a1: usize, a2: usize, a3: usize, a4: usize,
        a5: usize, a6: usize, a7: usize, a8: usize,
        a9: usize, a10: usize, a11: usize
    ) -> NTSTATUS;
}


