use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Направление сетевого пакета
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkDirection {
    /// Исходящий трафик (send / wsasend)
    Tx,
    /// Входящий трафик (recv / wsarecv)
    Rx,
}

/// Содержимое перехваченного сетевого события
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkEventPayload {
    /// Попытка установления соединения
    Connect {
        socket: u64,
        remote_addr: Option<SocketAddr>,
        success: bool,
    },
    /// Передача или прием данных
    Data {
        socket: u64,
        direction: NetworkDirection,
        bytes: Vec<u8>,
    },
    /// Закрытие сокета
    Close { socket: u64 },
}

/// Унифицированная структура события перехватчика
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptedEvent {
    pub pid: u32,
    pub timestamp_millis: u64,
    pub payload: NetworkEventPayload,
}

pub mod frame;
pub use frame::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_deserialize_connect_event() {
        let event = InterceptedEvent {
            pid: 4242,
            timestamp_millis: 1700000000,
            payload: NetworkEventPayload::Connect {
                socket: 100,
                remote_addr: Some("127.0.0.1:8080".parse().unwrap()),
                success: true,
            },
        };

        let encoded = bincode::serialize(&event).expect("Serialization failed");
        let decoded: InterceptedEvent =
            bincode::deserialize(&encoded).expect("Deserialization failed");

        assert_eq!(decoded.pid, 4242);
        assert_eq!(decoded.timestamp_millis, 1700000000);
        match decoded.payload {
            NetworkEventPayload::Connect {
                socket,
                remote_addr,
                success,
            } => {
                assert_eq!(socket, 100);
                assert_eq!(remote_addr, Some("127.0.0.1:8080".parse().unwrap()));
                assert!(success);
            }
            _ => panic!("Expected Connect payload"),
        }
    }

    #[test]
    fn test_serialize_deserialize_data_event() {
        let event = InterceptedEvent {
            pid: 9999,
            timestamp_millis: 1700001000,
            payload: NetworkEventPayload::Data {
                socket: 200,
                direction: NetworkDirection::Tx,
                bytes: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            },
        };

        let encoded = bincode::serialize(&event).expect("Serialization failed");
        let decoded: InterceptedEvent =
            bincode::deserialize(&encoded).expect("Deserialization failed");

        assert_eq!(decoded.pid, 9999);
        match decoded.payload {
            NetworkEventPayload::Data {
                socket,
                direction,
                bytes,
            } => {
                assert_eq!(socket, 200);
                assert_eq!(direction, NetworkDirection::Tx);
                assert_eq!(&bytes, b"GET / HTTP/1.1\r\n\r\n");
            }
            _ => panic!("Expected Data payload"),
        }
    }

    #[test]
    fn test_serialize_deserialize_data_event_rx() {
        let event = InterceptedEvent {
            pid: 9998,
            timestamp_millis: 1700001050,
            payload: NetworkEventPayload::Data {
                socket: 201,
                direction: NetworkDirection::Rx,
                bytes: b"HTTP/1.1 200 OK\r\n\r\n".to_vec(),
            },
        };

        let encoded = bincode::serialize(&event).expect("Serialization failed");
        let decoded: InterceptedEvent =
            bincode::deserialize(&encoded).expect("Deserialization failed");

        assert_eq!(decoded.pid, 9998);
        assert_eq!(decoded.timestamp_millis, 1700001050);
        match decoded.payload {
            NetworkEventPayload::Data {
                socket,
                direction,
                bytes,
            } => {
                assert_eq!(socket, 201);
                assert_eq!(direction, NetworkDirection::Rx);
                assert_eq!(&bytes, b"HTTP/1.1 200 OK\r\n\r\n");
            }
            _ => panic!("Expected Data payload"),
        }
    }

    #[test]
    fn test_serialize_deserialize_close_event() {
        let event = InterceptedEvent {
            pid: 1234,
            timestamp_millis: 1700002000,
            payload: NetworkEventPayload::Close { socket: 300 },
        };

        let encoded = bincode::serialize(&event).expect("Serialization failed");
        let decoded: InterceptedEvent =
            bincode::deserialize(&encoded).expect("Deserialization failed");

        assert_eq!(decoded.pid, 1234);
        match decoded.payload {
            NetworkEventPayload::Close { socket } => {
                assert_eq!(socket, 300);
            }
            _ => panic!("Expected Close payload"),
        }
    }

    #[test]
    fn test_serialize_deserialize_ipv6_connect() {
        let event = InterceptedEvent {
            pid: 5678,
            timestamp_millis: 1700003000,
            payload: NetworkEventPayload::Connect {
                socket: 400,
                remote_addr: Some("[::1]:9000".parse().unwrap()),
                success: false,
            },
        };

        let encoded = bincode::serialize(&event).expect("Serialization failed");
        let decoded: InterceptedEvent =
            bincode::deserialize(&encoded).expect("Deserialization failed");

        match decoded.payload {
            NetworkEventPayload::Connect {
                socket,
                remote_addr,
                success,
            } => {
                assert_eq!(socket, 400);
                assert_eq!(remote_addr, Some("[::1]:9000".parse().unwrap()));
                assert!(!success);
            }
            _ => panic!("Expected Connect payload"),
        }
    }
}
