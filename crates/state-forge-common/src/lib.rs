use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Максимальный размер захватываемых полезных данных (1 МиБ)
pub const MAX_CAPTURE_BYTES: usize = 1024 * 1024;

/// Направление сетевого пакета
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkDirection {
    /// Исходящий трафик (send / wsasend)
    Tx,
    /// Входящий трафик (recv / wsarecv)
    Rx,
}

/// Содержимое перехваченного сетевого события
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkEventPayload {
    /// Попытка установления соединения (дискриминант 0)
    Connect {
        socket: u64,
        remote_addr: Option<SocketAddr>,
        success: bool,
    },
    /// Передача или прием данных (дискриминант 1)
    Data {
        socket: u64,
        direction: NetworkDirection,
        original_len: u32,
        bytes: Vec<u8>,
    },
    /// Закрытие сокета локальным процессом (дискриминант 2)
    Close { socket: u64 },
    /// Закрытие сокета удаленным пиром (дискриминант 3)
    PeerClosed { socket: u64 },
}

/// Унифицированная структура события перехватчика
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterceptedEvent {
    pub pid: u32,
    pub seq: u64,
    pub timestamp_millis: u64,
    pub payload: NetworkEventPayload,
}

pub mod frame;
pub use frame::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_capture_bytes_exact_value() {
        // Убивает мутантов: replace * with + / replace * with / в MAX_CAPTURE_BYTES
        // 1024 * 1024 = 1_048_576 байт (1 МиБ)
        assert_eq!(MAX_CAPTURE_BYTES, 1_048_576);
    }

    #[test]
    fn test_serialize_deserialize_connect_event() {
        let event = InterceptedEvent {
            pid: 4242,
            seq: 1,
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

        assert_eq!(decoded, event);
    }

    #[test]
    fn test_serialize_deserialize_data_event() {
        let event = InterceptedEvent {
            pid: 9999,
            seq: 2,
            timestamp_millis: 1700001000,
            payload: NetworkEventPayload::Data {
                socket: 200,
                direction: NetworkDirection::Tx,
                original_len: 18,
                bytes: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            },
        };

        let encoded = bincode::serialize(&event).expect("Serialization failed");
        let decoded: InterceptedEvent =
            bincode::deserialize(&encoded).expect("Deserialization failed");

        assert_eq!(decoded, event);
    }

    #[test]
    fn test_serialize_deserialize_data_event_rx() {
        let event = InterceptedEvent {
            pid: 9998,
            seq: 3,
            timestamp_millis: 1700001050,
            payload: NetworkEventPayload::Data {
                socket: 201,
                direction: NetworkDirection::Rx,
                original_len: 17,
                bytes: b"HTTP/1.1 200 OK\r\n\r\n".to_vec(),
            },
        };

        let encoded = bincode::serialize(&event).expect("Serialization failed");
        let decoded: InterceptedEvent =
            bincode::deserialize(&encoded).expect("Deserialization failed");

        assert_eq!(decoded, event);
    }

    #[test]
    fn test_serialize_deserialize_close_event() {
        let event = InterceptedEvent {
            pid: 1234,
            seq: 4,
            timestamp_millis: 1700002000,
            payload: NetworkEventPayload::Close { socket: 300 },
        };

        let encoded = bincode::serialize(&event).expect("Serialization failed");
        let decoded: InterceptedEvent =
            bincode::deserialize(&encoded).expect("Deserialization failed");

        assert_eq!(decoded, event);
    }

    #[test]
    fn test_serialize_deserialize_peer_closed_event() {
        let event = InterceptedEvent {
            pid: 1235,
            seq: 5,
            timestamp_millis: 1700002500,
            payload: NetworkEventPayload::PeerClosed { socket: 350 },
        };

        let encoded = bincode::serialize(&event).expect("Serialization failed");
        let decoded: InterceptedEvent =
            bincode::deserialize(&encoded).expect("Deserialization failed");

        assert_eq!(decoded, event);
    }

    #[test]
    fn test_serialize_deserialize_ipv6_connect() {
        let event = InterceptedEvent {
            pid: 5678,
            seq: 6,
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

        assert_eq!(decoded, event);
    }
}
