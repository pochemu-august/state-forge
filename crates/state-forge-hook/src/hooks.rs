use crate::ipc::emit_event;
use minhook::MinHook;
use state_forge_common::{InterceptedEvent, NetworkDirection, NetworkEventPayload};
use std::ffi::{c_int, c_void};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicPtr, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKET, WSAEWOULDBLOCK,
    WSAGetLastError, WSASetLastError,
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

pub(crate) unsafe fn parse_sockaddr(
    addr_ptr: *const SOCKADDR,
    namelen: c_int,
) -> Option<SocketAddr> {
    if addr_ptr.is_null() || namelen <= 0 {
        return None;
    }
    let namelen = namelen as usize;
    if namelen < std::mem::size_of::<u16>() {
        return None;
    }

    unsafe {
        let family = (*addr_ptr).sa_family;
        if family == AF_INET {
            if namelen < std::mem::size_of::<SOCKADDR_IN>() {
                return None;
            }
            let in_addr = *(addr_ptr as *const SOCKADDR_IN);
            let ip = Ipv4Addr::from(u32::from_be(in_addr.sin_addr.S_un.S_addr));
            let port = u16::from_be(in_addr.sin_port);
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        } else if family == AF_INET6 {
            if namelen < std::mem::size_of::<SOCKADDR_IN6>() {
                return None;
            }
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
    let remote_addr = unsafe { parse_sockaddr(name, namelen) };
    let orig_ptr = ORIGINAL_CONNECT.load(Ordering::SeqCst);
    if orig_ptr.is_null() {
        return -1;
    }
    let original: ConnectFn = unsafe { std::mem::transmute(orig_ptr) };
    let res = unsafe { original(s, name, namelen) };
    let last_error = unsafe { WSAGetLastError() };

    let success = res == 0 || (res == -1 && last_error == WSAEWOULDBLOCK);

    emit_event(InterceptedEvent {
        pid: std::process::id(),
        timestamp_millis: current_timestamp(),
        payload: NetworkEventPayload::Connect {
            socket: s as u64,
            remote_addr,
            success,
        },
    });

    unsafe { WSASetLastError(last_error) };
    res
}

pub unsafe extern "system" fn detour_send(
    s: SOCKET,
    buf: *const u8,
    len: c_int,
    flags: c_int,
) -> c_int {
    let orig_ptr = ORIGINAL_SEND.load(Ordering::SeqCst);
    if orig_ptr.is_null() {
        return -1;
    }
    let original: SendFn = unsafe { std::mem::transmute(orig_ptr) };
    let ret = unsafe { original(s, buf, len, flags) };
    let last_error = unsafe { WSAGetLastError() };

    if ret > 0 && !buf.is_null() {
        let slice = unsafe { std::slice::from_raw_parts(buf, ret as usize) };
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

    unsafe { WSASetLastError(last_error) };
    ret
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
    let last_error = unsafe { WSAGetLastError() };

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

    unsafe { WSASetLastError(last_error) };
    bytes_received
}

pub unsafe extern "system" fn detour_closesocket(s: SOCKET) -> c_int {
    let orig_ptr = ORIGINAL_CLOSESOCKET.load(Ordering::SeqCst);
    if orig_ptr.is_null() {
        return -1;
    }
    let original: CloseSocketFn = unsafe { std::mem::transmute(orig_ptr) };
    let res = unsafe { original(s) };
    let last_error = unsafe { WSAGetLastError() };

    emit_event(InterceptedEvent {
        pid: std::process::id(),
        timestamp_millis: current_timestamp(),
        payload: NetworkEventPayload::Close { socket: s as u64 },
    });

    unsafe { WSASetLastError(last_error) };
    res
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

        let orig_close =
            MinHook::create_hook_api("ws2_32.dll", "closesocket", detour_closesocket as *mut _)?;
        ORIGINAL_CLOSESOCKET.store(orig_close, Ordering::SeqCst);

        MinHook::enable_all_hooks()?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Networking::WinSock::{IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0};

    #[test]
    fn test_parse_sockaddr_null_or_invalid_len() {
        assert_eq!(unsafe { parse_sockaddr(std::ptr::null(), 16) }, None);

        let mut addr: SOCKADDR_IN = unsafe { std::mem::zeroed() };
        addr.sin_family = AF_INET;
        let addr_ptr = &addr as *const SOCKADDR_IN as *const SOCKADDR;

        assert_eq!(unsafe { parse_sockaddr(addr_ptr, -1) }, None);
        assert_eq!(unsafe { parse_sockaddr(addr_ptr, 0) }, None);
        assert_eq!(unsafe { parse_sockaddr(addr_ptr, 1) }, None);
        assert_eq!(
            unsafe { parse_sockaddr(addr_ptr, (std::mem::size_of::<SOCKADDR_IN>() - 1) as c_int) },
            None
        );
    }

    #[test]
    fn test_parse_sockaddr_ipv4_valid() {
        let mut addr: SOCKADDR_IN = unsafe { std::mem::zeroed() };
        addr.sin_family = AF_INET;
        addr.sin_port = 8080u16.to_be();
        addr.sin_addr = IN_ADDR {
            S_un: IN_ADDR_0 {
                S_addr: u32::from_ne_bytes([127, 0, 0, 1]),
            },
        };

        let addr_ptr = &addr as *const SOCKADDR_IN as *const SOCKADDR;
        let parsed =
            unsafe { parse_sockaddr(addr_ptr, std::mem::size_of::<SOCKADDR_IN>() as c_int) };
        assert_eq!(parsed, Some("127.0.0.1:8080".parse().unwrap()));
    }

    #[test]
    fn test_parse_sockaddr_ipv6_valid_and_truncated() {
        let mut addr: SOCKADDR_IN6 = unsafe { std::mem::zeroed() };
        addr.sin6_family = AF_INET6;
        addr.sin6_port = 9000u16.to_be();
        let mut bytes = [0u8; 16];
        bytes[15] = 1;
        addr.sin6_addr = IN6_ADDR {
            u: IN6_ADDR_0 { Byte: bytes },
        };

        let addr_ptr = &addr as *const SOCKADDR_IN6 as *const SOCKADDR;
        // Truncated length
        assert_eq!(
            unsafe { parse_sockaddr(addr_ptr, (std::mem::size_of::<SOCKADDR_IN6>() - 1) as c_int) },
            None
        );

        // Valid length
        let parsed =
            unsafe { parse_sockaddr(addr_ptr, std::mem::size_of::<SOCKADDR_IN6>() as c_int) };
        assert_eq!(parsed, Some("[::1]:9000".parse().unwrap()));
    }

    #[test]
    fn test_parse_sockaddr_unknown_family() {
        let mut addr: SOCKADDR = unsafe { std::mem::zeroed() };
        addr.sa_family = 999;
        let addr_ptr = &addr as *const SOCKADDR;

        assert_eq!(
            unsafe { parse_sockaddr(addr_ptr, std::mem::size_of::<SOCKADDR>() as c_int) },
            None
        );
    }
}
