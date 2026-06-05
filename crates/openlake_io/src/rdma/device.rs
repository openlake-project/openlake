use std::ffi::CStr;
use std::io;
use std::mem;
use std::ptr::NonNull;

use rdma_mummy_sys::{
    ibv_alloc_pd, ibv_close_device, ibv_context, ibv_dealloc_pd, ibv_free_device_list,
    ibv_get_device_list, ibv_get_device_name, ibv_gid, ibv_open_device, ibv_pd,
    ibv_port_attr, ibv_query_gid, ibv_query_port,
};

pub const PORT_NUM:  u8 = 1;
// IB (link_layer=1) populates only the link-local default GID at slot 0.
// RoCE v2 on Mellanox places the IPv4-mapped GID at slot 3.
pub const GID_INDEX_IB:   u8 = 0;
pub const GID_INDEX_ROCE: u8 = 3;

pub struct IbDevice {
    pub(super) ctx:       NonNull<ibv_context>,
    pub(super) pd:        NonNull<ibv_pd>,
    pub(super) port_attr: ibv_port_attr,
    pub(super) gid:       [u8; 16],
    pub(super) gid_index: u8,
}

unsafe impl Send for IbDevice {}
unsafe impl Sync for IbDevice {}

impl IbDevice {
    pub fn gid_bytes(&self) -> [u8; 16] { self.gid }

    pub fn open(dev_name: &str) -> io::Result<Self> {
        unsafe {
            let mut n: i32 = 0;
            let list = ibv_get_device_list(&mut n);
            if list.is_null() || n == 0 {
                if !list.is_null() { ibv_free_device_list(list); }
                return Err(io::Error::other("no rdma devices"));
            }
            let mut chosen = std::ptr::null_mut();
            for i in 0..n {
                let d = *list.offset(i as isize);
                if CStr::from_ptr(ibv_get_device_name(d)).to_string_lossy() == dev_name {
                    chosen = d;
                    break;
                }
            }
            if chosen.is_null() { chosen = *list; }
            let ctx = ibv_open_device(chosen);
            ibv_free_device_list(list);
            let ctx = NonNull::new(ctx).ok_or_else(io::Error::last_os_error)?;

            let pd = NonNull::new(ibv_alloc_pd(ctx.as_ptr()))
                .ok_or_else(|| { ibv_close_device(ctx.as_ptr()); io::Error::last_os_error() })?;

            let mut port_attr: ibv_port_attr = mem::zeroed();
            let rc = ibv_query_port(ctx.as_ptr(), PORT_NUM, &mut port_attr);
            if rc != 0 {
                return Err(io::Error::other(format!(
                    "ibv_query_port port={PORT_NUM} rc={rc} errno={}",
                    io::Error::last_os_error()
                )));
            }

            let gid_index = if port_attr.link_layer == 1 { GID_INDEX_IB } else { GID_INDEX_ROCE };
            let mut gid: ibv_gid = mem::zeroed();
            let rc = ibv_query_gid(ctx.as_ptr(), PORT_NUM, gid_index as i32, &mut gid);
            if rc != 0 {
                return Err(io::Error::other(format!(
                    "ibv_query_gid port={PORT_NUM} gid_index={gid_index} link_layer={} rc={rc} errno={}",
                    port_attr.link_layer, io::Error::last_os_error()
                )));
            }

            Ok(IbDevice { ctx, pd, port_attr, gid: gid.raw, gid_index })
        }
    }
}

impl Drop for IbDevice {
    fn drop(&mut self) {
        unsafe {
            ibv_dealloc_pd(self.pd.as_ptr());
            ibv_close_device(self.ctx.as_ptr());
        }
    }
}
