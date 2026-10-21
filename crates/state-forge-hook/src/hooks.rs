use crate::ipc::emit_event;
use minhook::MinHook;
use state_forge_common::{
    InterceptedEvent, MAX_CAPTURE_BYTES, NetworkDirection, NetworkEventPayload,
};
use std::ffi::{c_int, c_void};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, MSG_PEEK, SO_TYPE, SOCK_STREAM, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKET,
    SOL_SOCKET, WSAEWOULDBLOCK, WSAGetLastError, WSASetLastError, getsockopt,
};

static ORIGINAL_CONNECT: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_SEND: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_RECV: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_CLOSESOCKET: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

static SEQ: AtomicU64 = AtomicU64::new(0);

fn next_seq() -> u64 {
    SEQ.fetch_add(1, Ordering::SeqCst)
}

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

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RecvAction {
    Ignore,
    Data,
    PeerClosed,
}

pub fn connect_success(res: c_int, last_error: i32) -> bool {
    res == 0 || (res == -1 && last_error == WSAEWOULDBLOCK)
}

pub fn is_stream_socket_type(sock_type: c_int) -> bool {
    sock_type == (SOCK_STREAM as c_int)
}

pub fn check_is_stream_socket(s: SOCKET) -> bool {
    let mut optval: c_int = 0;
    let mut optlen: c_int = std::mem::size_of::<c_int>() as c_int;
    let res = unsafe {
        getsockopt(
            s,
            SOL_SOCKET as c_int,
            SO_TYPE,
            &mut optval as *mut c_int as *mut _,
            &mut optlen,
        )
    };
    res == 0 && is_stream_socket_type(optval)
}

pub fn should_log_recv(ret: c_int, len: c_int, flags: c_int, is_stream: bool) -> RecvAction {
    if (flags & (MSG_PEEK as c_int)) != 0 || len == 0 {
        return RecvAction::Ignore;
    }
    if ret > 0 {
        RecvAction::Data
    } else if ret == 0 {
        if is_stream {
            RecvAction::PeerClosed
        } else {
            RecvAction::Ignore
        }
    } else {
        RecvAction::Ignore
    }
}

pub fn capture_slice(buf_len: usize, limit: usize) -> (usize, usize) {
    let take_len = buf_len.min(limit);
    (take_len, buf_len)
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
    let seq = next_seq();
    let orig_ptr = ORIGINAL_CONNECT.load(Ordering::SeqCst);
    if orig_ptr.is_null() {
        return -1;
    }
    let original: ConnectFn = unsafe { std::mem::transmute(orig_ptr) };
    let res = unsafe { original(s, name, namelen) };
    let last_error = unsafe { WSAGetLastError() };

    let success = connect_success(res, last_error);

    emit_event(InterceptedEvent {
        pid: std::process::id(),
        seq,
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
    let seq = next_seq();
    let orig_ptr = ORIGINAL_SEND.load(Ordering::SeqCst);
    if orig_ptr.is_null() {
        return -1;
    }
    let original: SendFn = unsafe { std::mem::transmute(orig_ptr) };
    let ret = unsafe { original(s, buf, len, flags) };
    let last_error = unsafe { WSAGetLastError() };

    if ret > 0 && !buf.is_null() {
        let (take_len, original_len) = capture_slice(ret as usize, MAX_CAPTURE_BYTES);
        let slice = unsafe { std::slice::from_raw_parts(buf, take_len) };
        emit_event(InterceptedEvent {
            pid: std::process::id(),
            seq,
            timestamp_millis: current_timestamp(),
            payload: NetworkEventPayload::Data {
                socket: s as u64,
                direction: NetworkDirection::Tx,
                original_len: original_len as u32,
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
    let is_stream = check_is_stream_socket(s);

    match should_log_recv(bytes_received, len, flags, is_stream) {
        RecvAction::Data => {
            if !buf.is_null() {
                let seq = next_seq();
                let (take_len, original_len) =
                    capture_slice(bytes_received as usize, MAX_CAPTURE_BYTES);
                let slice = unsafe { std::slice::from_raw_parts(buf, take_len) };
                emit_event(InterceptedEvent {
                    pid: std::process::id(),
                    seq,
                    timestamp_millis: current_timestamp(),
                    payload: NetworkEventPayload::Data {
                        socket: s as u64,
                        direction: NetworkDirection::Rx,
                        original_len: original_len as u32,
                        bytes: slice.to_vec(),
                    },
                });
            }
        }
        RecvAction::PeerClosed => {
            let seq = next_seq();
            emit_event(InterceptedEvent {
                pid: std::process::id(),
                seq,
                timestamp_millis: current_timestamp(),
                payload: NetworkEventPayload::PeerClosed { socket: s as u64 },
            });
        }
        RecvAction::Ignore => {}
    }

    unsafe { WSASetLastError(last_error) };
    bytes_received
}

pub unsafe extern "system" fn detour_closesocket(s: SOCKET) -> c_int {
    let seq = next_seq();
    let pre_error = unsafe { WSAGetLastError() };

    emit_event(InterceptedEvent {
        pid: std::process::id(),
        seq,
        timestamp_millis: current_timestamp(),
        payload: NetworkEventPayload::Close { socket: s as u64 },
    });

    unsafe { WSASetLastError(pre_error) };

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
    use windows_sys::Win32::Networking::WinSock::{
        IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, SOCK_DGRAM, SOCK_STREAM, WSAECONNREFUSED,
    };

    #[test]
    fn test_is_stream_socket_type() {
        assert!(is_stream_socket_type(SOCK_STREAM as c_int));
        assert!(!is_stream_socket_type(SOCK_DGRAM as c_int));
    }

    #[test]
    fn test_connect_success() {
        assert!(connect_success(0, 0));
        assert!(connect_success(-1, WSAEWOULDBLOCK));
        assert!(!connect_success(-1, WSAECONNREFUSED));
        assert!(!connect_success(-1, 10054)); // WSAECONNRESET
    }

    #[test]
    fn test_should_log_recv() {
        // len == 0: ничего не эмитируем (ret == 0 тогда не означает закрытие)
        assert_eq!(should_log_recv(0, 0, 0, true), RecvAction::Ignore);
        assert_eq!(should_log_recv(0, 0, 0, false), RecvAction::Ignore);
        assert_eq!(should_log_recv(10, 0, 0, true), RecvAction::Ignore);

        // ret == 0 при stream -> PeerClosed
        assert_eq!(should_log_recv(0, 1024, 0, true), RecvAction::PeerClosed);

        // ret == 0 при dgram -> Ignore
        assert_eq!(should_log_recv(0, 1024, 0, false), RecvAction::Ignore);

        // MSG_PEEK: всегда Ignore
        assert_eq!(
            should_log_recv(100, 1024, MSG_PEEK as c_int, true),
            RecvAction::Ignore
        );
        assert_eq!(
            should_log_recv(0, 1024, MSG_PEEK as c_int, true),
            RecvAction::Ignore
        );
        assert_eq!(
            should_log_recv(0, 1024, MSG_PEEK as c_int, false),
            RecvAction::Ignore
        );
        assert_eq!(
            should_log_recv(-1, 1024, MSG_PEEK as c_int, true),
            RecvAction::Ignore
        );

        // Normal positive read without MSG_PEEK -> Data
        assert_eq!(should_log_recv(100, 1024, 0, true), RecvAction::Data);
        assert_eq!(should_log_recv(100, 1024, 0, false), RecvAction::Data);

        // Error (ret < 0) -> Ignore
        assert_eq!(should_log_recv(-1, 1024, 0, true), RecvAction::Ignore);
        assert_eq!(should_log_recv(-1, 1024, 0, false), RecvAction::Ignore);
    }

    #[test]
    fn test_capture_slice_boundaries() {
        // Below limit
        assert_eq!(capture_slice(500, MAX_CAPTURE_BYTES), (500, 500));
        // Exactly limit
        assert_eq!(
            capture_slice(MAX_CAPTURE_BYTES, MAX_CAPTURE_BYTES),
            (MAX_CAPTURE_BYTES, MAX_CAPTURE_BYTES)
        );
        // Above limit -> truncated to limit, but original_len preserved
        let oversized = MAX_CAPTURE_BYTES + 4096;
        assert_eq!(
            capture_slice(oversized, MAX_CAPTURE_BYTES),
            (MAX_CAPTURE_BYTES, oversized)
        );
    }

    #[test]
    fn test_seq_monotonic_increment() {
        let s1 = next_seq();
        let s2 = next_seq();
        let s3 = next_seq();
        assert!(s2 > s1, "Expected s2 ({}) > s1 ({})", s2, s1);
        assert!(s3 > s2, "Expected s3 ({}) > s2 ({})", s3, s2);
    }

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
        assert_eq!(
            unsafe { parse_sockaddr(addr_ptr, (std::mem::size_of::<SOCKADDR_IN6>() - 1) as c_int) },
            None
        );

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

    #[test]
    #[cfg(windows)]
    fn test_check_is_stream_socket_real_sockets() {
        use std::net::{TcpListener, UdpSocket};
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::INVALID_SOCKET;

        // 1. Реальный TCP сокет — тип SOCK_STREAM
        let tcp_listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp listener");
        let tcp_sock = tcp_listener.as_raw_socket() as SOCKET;
        // Убивает мутанта: `replace check_is_stream_socket -> bool with false`
        assert!(check_is_stream_socket(tcp_sock));

        // 2. Реальный UDP сокет — тип SOCK_DGRAM
        let udp_socket = UdpSocket::bind("127.0.0.1:0").expect("bind udp socket");
        let udp_sock = udp_socket.as_raw_socket() as SOCKET;
        // Убивает мутанта: `replace check_is_stream_socket -> bool with true`
        assert!(!check_is_stream_socket(udp_sock));

        // 3. Невалидный дескриптор сокета (getsockopt завершится с ошибкой SOCKET_ERROR)
        // Убивает мутантов: `replace && with ||` и `replace == with !=` в check_is_stream_socket
        assert!(!check_is_stream_socket(INVALID_SOCKET));
    }
}
