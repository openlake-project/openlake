use std::ffi::CString;
use std::io::{Error, ErrorKind, Result};
use std::ptr;

fn cstr(name: &str) -> Result<CString> {
    CString::new(name).map_err(|e| Error::new(ErrorKind::InvalidInput, e))
}

fn open(name: &str, flags: libc::c_int) -> Result<libc::c_int> {
    let fd = unsafe { libc::shm_open(cstr(name)?.as_ptr(), flags, 0o600) };
    if fd < 0 {
        return Err(Error::last_os_error());
    }
    Ok(fd)
}

fn map(fd: libc::c_int, len: usize) -> Result<*mut u8> {
    let p = unsafe {
        libc::mmap(ptr::null_mut(), len, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED, fd, 0)
    };
    unsafe { libc::close(fd) };
    if p == libc::MAP_FAILED {
        return Err(Error::last_os_error());
    }
    Ok(p.cast())
}

pub fn create(name: &str, len: usize) -> Result<*mut u8> {
    let fd = open(name, libc::O_RDWR | libc::O_CREAT | libc::O_EXCL)?;
    if unsafe { libc::ftruncate(fd, len as libc::off_t) } != 0 {
        let e = Error::last_os_error();
        unsafe { libc::close(fd) };
        unlink(name);
        return Err(e);
    }
    map(fd, len).map_err(|e| {
        unlink(name);
        e
    })
}

pub fn open_map(name: &str, len: usize) -> Result<*mut u8> {
    map(open(name, libc::O_RDWR)?, len)
}

pub fn unmap(base: *mut u8, len: usize) {
    if !base.is_null() {
        unsafe { libc::munmap(base.cast(), len) };
    }
}

pub fn unlink(name: &str) {
    if let Ok(c) = cstr(name) {
        unsafe { libc::shm_unlink(c.as_ptr()) };
    }
}
