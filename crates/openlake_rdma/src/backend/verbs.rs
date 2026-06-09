use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

#[repr(C)]
struct IbvDevice {
    _opaque: [u8; 0],
}

#[link(name = "ibverbs")]
extern "C" {
    fn ibv_get_device_list(num_devices: *mut c_int) -> *mut *mut IbvDevice;
    fn ibv_free_device_list(list: *mut *mut IbvDevice);
    fn ibv_get_device_name(device: *mut IbvDevice) -> *const c_char;
}

pub fn available_devices() -> Vec<String> {
    let mut count: c_int = 0;
    let mut names = Vec::new();
    unsafe {
        let list = ibv_get_device_list(&mut count as *mut c_int);
        if list.is_null() {
            return names;
        }
        for index in 0..count as isize {
            let device = *list.offset(index);
            if device.is_null() {
                break;
            }
            let raw = ibv_get_device_name(device);
            if !raw.is_null() {
                names.push(CStr::from_ptr(raw).to_string_lossy().into_owned());
            }
        }
        ibv_free_device_list(list);
    }
    names
}
