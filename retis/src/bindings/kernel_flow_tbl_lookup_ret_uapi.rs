/* automatically generated by rust-bindgen 0.70.1 */

pub type __u32 = ::std::os::raw::c_uint;
pub type __u64 = ::std::os::raw::c_ulonglong;
pub type u32_ = __u32;
pub type u64_ = __u64;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct flow_lookup_ret_event {
    pub flow: *mut ::std::os::raw::c_void,
    pub sf_acts: *mut ::std::os::raw::c_void,
    pub ufid: [u32_; 4usize],
    pub n_mask_hit: u32_,
    pub n_cache_hit: u32_,
    pub skb_orig_head: u64_,
    pub skb_timestamp: u64_,
    pub skb: u64_,
}
impl Default for flow_lookup_ret_event {
    fn default() -> Self {
        let mut s = ::std::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::std::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
