pub mod framing;
pub mod graph;
pub mod session;

pub use framing::{
    DelimiterDelineator, Endianness, FrameDelineator, LengthPrefixedDelineator, RawChunkDelineator,
};
pub use graph::{DialogueTurn, ProtocolStateMachine, StateNode, StateTransition};
pub use session::{RawChunk, Session, SessionId, SessionPhase, SessionTracker, StreamBuffer};
pub use state_forge_common::NetworkDirection;

use state_forge_common::{InterceptedEvent, NetworkEventPayload};

/// Высокоуровневый анализ сессии и автоматическое построение машины состояний (FSM)
pub fn analyze_events_to_state_machine(events: &[InterceptedEvent]) -> ProtocolStateMachine {
    let mut turns = Vec::new();

    for ev in events {
        if let NetworkEventPayload::Data {
            direction, bytes, ..
        } = &ev.payload
        {
            let preview = if let Ok(s) = std::str::from_utf8(bytes) {
                let trimmed = s.trim();
                if trimmed.len() > 64 {
                    format!("{}...", &trimmed[..64])
                } else {
                    trimmed.to_string()
                }
            } else {
                format!("Binary ({} bytes)", bytes.len())
            };

            turns.push(DialogueTurn {
                direction: *direction,
                timestamp_millis: ev.timestamp_millis,
                summary: preview,
                raw_bytes: bytes.clone(),
            });
        }
    }

    ProtocolStateMachine::build_from_turns(&turns)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_events_to_state_machine_flow() {
        let events = vec![
            InterceptedEvent {
                pid: 100,
                seq: 1,
                timestamp_millis: 1000,
                payload: NetworkEventPayload::Connect {
                    socket: 10,
                    remote_addr: Some("127.0.0.1:80".parse().unwrap()),
                    success: true,
                },
            },
            InterceptedEvent {
                pid: 100,
                seq: 2,
                timestamp_millis: 1010,
                payload: NetworkEventPayload::Data {
                    socket: 10,
                    direction: NetworkDirection::Tx,
                    original_len: 16,
                    bytes: b"GET / HTTP/1.1\r\n".to_vec(),
                },
            },
            InterceptedEvent {
                pid: 100,
                seq: 3,
                timestamp_millis: 1030,
                payload: NetworkEventPayload::Data {
                    socket: 10,
                    direction: NetworkDirection::Rx,
                    original_len: 17,
                    bytes: b"HTTP/1.1 200 OK\r\n".to_vec(),
                },
            },
            InterceptedEvent {
                pid: 100,
                seq: 4,
                timestamp_millis: 1050,
                payload: NetworkEventPayload::Close { socket: 10 },
            },
        ];

        let sm = analyze_events_to_state_machine(&events);
        assert_eq!(sm.nodes.len(), 3); // Initial, Tx state, Rx state
        assert_eq!(sm.transitions.len(), 2);

        let mermaid = sm.to_mermaid();
        assert!(mermaid.contains("GET / HTTP/1.1"));
        assert!(mermaid.contains("HTTP/1.1 200 OK"));
    }
}
