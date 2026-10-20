use crate::ipc::emit_event;
use minhook::MinHook;
use state_forge_common::{InterceptedEvent, NetworkDirection, NetworkEventPayload};
use std::ffi::{c_int, c_void};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicPtr, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKET,
};

static ORIGINAL_CONNECT: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_SEND: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_RECV: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_CLOSESOCKET: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

type ConnectFn = unsafe extern "system" fn(SOCKET, *const SOCKADDR, c_int) -> c_int;
type SendFn = unsafe extern "system" fn(SOCKET, *const u8, c_int, c_int) -> c_int;
type RecvFn = unsafe extern "system" fn(SOCKET, *mut u8, c_int, c_int) -> c_int;
type CloseSocketFn = unsafe extern "system" fn(SOCKET) -> c_int;

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

unsafe fn parse_sockaddr(addr_ptr: *const SOCKADDR) -> Option<SocketAddr> {
    if addr_ptr.is_null() {
        return None;
    }
    unsafe {
        let family = (*addr_ptr).sa_family;
        if family == AF_INET {
            let in_addr = *(addr_ptr as *const SOCKADDR_IN);
            let ip = Ipv4Addr::from(u32::from_be(in_addr.sin_addr.S_un.S_addr));
            let port = u16::from_be(in_addr.sin_port);
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        } else if family == AF_INET6 {
            let in6_addr = *(addr_ptr as *const SOCKADDR_IN6);
            let ip = Ipv6Addr::from(in6_addr.sin6_addr.u.Byte);
            let port = u16::from_be(in6_addr.sin6_port);
            Some(SocketAddr::new(IpAddr::V6(ip), port))
        } else {
            None
        }
    }
}

pub unsafe extern "system" fn detour_connect(
    s: SOCKET,
    name: *const SOCKADDR,
    namelen: c_int,
) -> c_int {
    let remote_addr = unsafe { parse_sockaddr(name) };
    let orig_ptr = ORIGINAL_CONNECT.load(Ordering::SeqCst);
    if orig_ptr.is_null() {
        return -1;
    }
    let original: ConnectFn = unsafe { std::mem::transmute(orig_ptr) };
    let res = unsafe { original(s, name, namelen) };

    emit_event(InterceptedEvent {
        pid: std::process::id(),
        timestamp_millis: current_timestamp(),
        payload: NetworkEventPayload::Connect {
            socket: s as u64,
            remote_addr,
            success: res == 0,
        },
    });

    res
}

pub unsafe extern "system" fn detour_send(
    s: SOCKET,
    buf: *const u8,
    len: c_int,
    flags: c_int,
) -> c_int {
    if !buf.is_null() && len > 0 {
        let slice = unsafe { std::slice::from_raw_parts(buf, len as usize) };
        emit_event(InterceptedEvent {
            pid: std::process::id(),
            timestamp_millis: current_timestamp(),
            payload: NetworkEventPayload::Data {
                socket: s as u64,
                direction: NetworkDirection::Tx,
                bytes: slice.to_vec(),
            },
        });
    }

    let orig_ptr = ORIGINAL_SEND.load(Ordering::SeqCst);
    if orig_ptr.is_null() {
        return -1;
    }
    let original: SendFn = unsafe { std::mem::transmute(orig_ptr) };
    unsafe { original(s, buf, len, flags) }
}

pub unsafe extern "system" fn detour_recv(
    s: SOCKET,
    buf: *mut u8,
    len: c_int,
    flags: c_int,
) -> c_int {
    let orig_ptr = ORIGINAL_RECV.load(Ordering::SeqCst);
    if orig_ptr.is_null() {
        return -1;
    }
    let original: RecvFn = unsafe { std::mem::transmute(orig_ptr) };
    let bytes_received = unsafe { original(s, buf, len, flags) };

    if bytes_received > 0 && !buf.is_null() {
        let slice = unsafe { std::slice::from_raw_parts(buf, bytes_received as usize) };
        emit_event(InterceptedEvent {
            pid: std::process::id(),
            timestamp_millis: current_timestamp(),
            payload: NetworkEventPayload::Data {
                socket: s as u64,
                direction: NetworkDirection::Rx,
                bytes: slice.to_vec(),
            },
        });
    }

    bytes_received
}

pub unsafe extern "system" fn detour_closesocket(s: SOCKET) -> c_int {
    emit_event(InterceptedEvent {
        pid: std::process::id(),
        timestamp_millis: current_timestamp(),
        payload: NetworkEventPayload::Close { socket: s as u64 },
    });

    let orig_ptr = ORIGINAL_CLOSESOCKET.load(Ordering::SeqCst);
    if orig_ptr.is_null() {
        return -1;
    }
    let original: CloseSocketFn = unsafe { std::mem::transmute(orig_ptr) };
    unsafe { original(s) }
}

pub fn install_hooks() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        let orig_connect =
            MinHook::create_hook_api("ws2_32.dll", "connect", detour_connect as *mut _)?;
        ORIGINAL_CONNECT.store(orig_connect, Ordering::SeqCst);

        let orig_send = MinHook::create_hook_api("ws2_32.dll", "send", detour_send as *mut _)?;
        ORIGINAL_SEND.store(orig_send, Ordering::SeqCst);

        let orig_recv = MinHook::create_hook_api("ws2_32.dll", "recv", detour_recv as *mut _)?;
        ORIGINAL_RECV.store(orig_recv, Ordering::SeqCst);

        if let Ok(orig_close) =
            MinHook::create_hook_api("ws2_32.dll", "closesocket", detour_closesocket as *mut _)
        {
            ORIGINAL_CLOSESOCKET.store(orig_close, Ordering::SeqCst);
        }

        MinHook::enable_all_hooks()?;
    }

    Ok(())
}
