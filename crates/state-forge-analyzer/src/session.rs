use state_forge_common::{InterceptedEvent, NetworkDirection, NetworkEventPayload};
use std::collections::HashMap;
use std::net::SocketAddr;

/// Уникальный идентификатор сетевой сессии в рамках ОС
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct SessionId {
    pub pid: u32,
    pub socket: u64,
}

impl SessionId {
    pub const fn new(pid: u32, socket: u64) -> Self {
        Self { pid, socket }
    }
}

/// Состояние жизненного цикла сетевого соединения
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SessionPhase {
    Connecting,
    Connected { remote_addr: Option<SocketAddr> },
    ConnectFailed,
    PeerClosed,
    Closed,
}

/// Одиночный сырой фрагмент данных, захваченный перехватчиком
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RawChunk {
    pub seq: u64,
    pub timestamp_millis: u64,
    pub original_len: u32,
    pub bytes: Vec<u8>,
}

/// Буфер однонаправленного сетевого потока (Tx или Rx)
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StreamBuffer {
    pub chunks: Vec<RawChunk>,
    pub accumulated_bytes: Vec<u8>,
    pub total_captured_bytes: usize,
    pub total_reported_bytes: u64,
}

impl StreamBuffer {
    pub fn push_chunk(&mut self, chunk: RawChunk) {
        self.accumulated_bytes.extend_from_slice(&chunk.bytes);
        self.total_captured_bytes += chunk.bytes.len();
        self.total_reported_bytes += chunk.original_len as u64;
        self.chunks.push(chunk);
    }
}

/// Сетевая сессия: отслеживание двунаправленного потока и жизненного цикла соединения
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Session {
    pub id: SessionId,
    pub phase: SessionPhase,
    pub created_at_millis: u64,
    pub updated_at_millis: u64,
    pub tx: StreamBuffer,
    pub rx: StreamBuffer,
    pub events_count: usize,
}

impl Session {
    pub fn new(id: SessionId, timestamp_millis: u64) -> Self {
        Self {
            id,
            phase: SessionPhase::Connecting,
            created_at_millis: timestamp_millis,
            updated_at_millis: timestamp_millis,
            tx: StreamBuffer::default(),
            rx: StreamBuffer::default(),
            events_count: 0,
        }
    }

    pub fn is_terminated(&self) -> bool {
        matches!(
            self.phase,
            SessionPhase::Closed | SessionPhase::PeerClosed | SessionPhase::ConnectFailed
        )
    }
}

/// Агрегатор и менеджер сессий на основе потока событий InterceptedEvent
#[derive(Debug, Default)]
pub struct SessionTracker {
    sessions: HashMap<SessionId, Session>,
}

impl SessionTracker {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Обработка одиночного входящего события
    pub fn process_event(&mut self, event: &InterceptedEvent) -> &Session {
        let (socket, payload) = match &event.payload {
            NetworkEventPayload::Connect { socket, .. } => (*socket, &event.payload),
            NetworkEventPayload::Data { socket, .. } => (*socket, &event.payload),
            NetworkEventPayload::Close { socket } => (*socket, &event.payload),
            NetworkEventPayload::PeerClosed { socket } => (*socket, &event.payload),
        };

        let id = SessionId::new(event.pid, socket);
        let session = self
            .sessions
            .entry(id)
            .or_insert_with(|| Session::new(id, event.timestamp_millis));

        session.updated_at_millis = event.timestamp_millis;
        session.events_count += 1;

        match payload {
            NetworkEventPayload::Connect {
                remote_addr,
                success,
                ..
            } => {
                session.phase = if *success {
                    SessionPhase::Connected {
                        remote_addr: *remote_addr,
                    }
                } else {
                    SessionPhase::ConnectFailed
                };
            }
            NetworkEventPayload::Data {
                direction,
                original_len,
                bytes,
                ..
            } => {
                let chunk = RawChunk {
                    seq: event.seq,
                    timestamp_millis: event.timestamp_millis,
                    original_len: *original_len,
                    bytes: bytes.clone(),
                };
                match direction {
                    NetworkDirection::Tx => session.tx.push_chunk(chunk),
                    NetworkDirection::Rx => session.rx.push_chunk(chunk),
                }
            }
            NetworkEventPayload::Close { .. } => {
                session.phase = SessionPhase::Closed;
            }
            NetworkEventPayload::PeerClosed { .. } => {
                session.phase = SessionPhase::PeerClosed;
            }
        }

        self.sessions.get(&id).expect("Session must exist")
    }

    pub fn get_session(&self, id: &SessionId) -> Option<&Session> {
        self.sessions.get(id)
    }

    pub fn sessions(&self) -> impl Iterator<Item = &Session> {
        self.sessions.values()
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_lifecycle() {
        let mut tracker = SessionTracker::new();
        let pid = 1000;
        let socket = 42;
        let id = SessionId::new(pid, socket);

        // 1. Connect
        let ev1 = InterceptedEvent {
            pid,
            seq: 1,
            timestamp_millis: 100,
            payload: NetworkEventPayload::Connect {
                socket,
                remote_addr: Some("127.0.0.1:8080".parse().unwrap()),
                success: true,
            },
        };
        let s1 = tracker.process_event(&ev1);
        assert_eq!(s1.id, id);
        assert_eq!(
            s1.phase,
            SessionPhase::Connected {
                remote_addr: Some("127.0.0.1:8080".parse().unwrap())
            }
        );
        assert_eq!(s1.events_count, 1);

        // 2. Data Tx
        let ev2 = InterceptedEvent {
            pid,
            seq: 2,
            timestamp_millis: 105,
            payload: NetworkEventPayload::Data {
                socket,
                direction: NetworkDirection::Tx,
                original_len: 4,
                bytes: b"PING".to_vec(),
            },
        };
        let s2 = tracker.process_event(&ev2);
        assert_eq!(s2.tx.accumulated_bytes, b"PING");
        assert_eq!(s2.tx.total_captured_bytes, 4);
        assert_eq!(s2.tx.total_reported_bytes, 4);

        // 3. Data Rx
        let ev3 = InterceptedEvent {
            pid,
            seq: 3,
            timestamp_millis: 110,
            payload: NetworkEventPayload::Data {
                socket,
                direction: NetworkDirection::Rx,
                original_len: 4,
                bytes: b"PONG".to_vec(),
            },
        };
        let s3 = tracker.process_event(&ev3);
        assert_eq!(s3.rx.accumulated_bytes, b"PONG");

        // 4. Close
        let ev4 = InterceptedEvent {
            pid,
            seq: 4,
            timestamp_millis: 120,
            payload: NetworkEventPayload::Close { socket },
        };
        let s4 = tracker.process_event(&ev4);
        assert_eq!(s4.phase, SessionPhase::Closed);
        assert!(s4.is_terminated());
        assert_eq!(s4.events_count, 4);
    }
}
