use state_forge_common::NetworkDirection;

/// Одиночный шаг сетевого диалога
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DialogueTurn {
    pub direction: NetworkDirection,
    pub timestamp_millis: u64,
    pub summary: String,
    pub raw_bytes: Vec<u8>,
}

/// Переход между состояниями протокола
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StateTransition {
    pub from_state: usize,
    pub to_state: usize,
    pub direction: NetworkDirection,
    pub label: String,
    pub occurrences: usize,
}

/// Узел графа состояний
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StateNode {
    pub id: usize,
    pub name: String,
    pub visit_count: usize,
}

/// Граф конечного автомата сетевого протокола
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProtocolStateMachine {
    pub nodes: Vec<StateNode>,
    pub transitions: Vec<StateTransition>,
}

impl ProtocolStateMachine {
    pub fn new() -> Self {
        let mut sm = Self {
            nodes: Vec::new(),
            transitions: Vec::new(),
        };
        // Начальное состояние
        sm.nodes.push(StateNode {
            id: 0,
            name: "Initial".to_string(),
            visit_count: 1,
        });
        sm
    }

    /// Построение автомата по последовательности шагов диалога
    pub fn build_from_turns(turns: &[DialogueTurn]) -> Self {
        let mut sm = Self::new();
        let mut current_state = 0;

        for turn in turns {
            let label = if turn.summary.is_empty() {
                format!("{:?} ({} bytes)", turn.direction, turn.raw_bytes.len())
            } else {
                turn.summary.clone()
            };

            // Проверяем, существует ли уже подходящий переход из текущего состояния
            let existing_trans_idx = sm.transitions.iter().position(|t| {
                t.from_state == current_state && t.direction == turn.direction && t.label == label
            });

            if let Some(idx) = existing_trans_idx {
                sm.transitions[idx].occurrences += 1;
                current_state = sm.transitions[idx].to_state;
                sm.nodes[current_state].visit_count += 1;
            } else {
                let next_state = sm.nodes.len();
                let state_name = format!("State_{}", next_state);

                sm.nodes.push(StateNode {
                    id: next_state,
                    name: state_name,
                    visit_count: 1,
                });

                sm.transitions.push(StateTransition {
                    from_state: current_state,
                    to_state: next_state,
                    direction: turn.direction,
                    label,
                    occurrences: 1,
                });

                current_state = next_state;
            }
        }

        sm
    }

    /// Экспорт в синтаксис Mermaid stateDiagram-v2
    pub fn to_mermaid(&self) -> String {
        let mut out = String::from("stateDiagram-v2\n");
        out.push_str("    [*] --> State_0\n");

        for t in &self.transitions {
            let dir_tag = match t.direction {
                NetworkDirection::Tx => "Tx (Client)",
                NetworkDirection::Rx => "Rx (Server)",
            };
            let sanitized_label = t.label.replace('"', "").replace([':', '\n'], " ");
            let count_suffix = if t.occurrences > 1 {
                format!(" [{dir_tag}: {} (x{})]", sanitized_label, t.occurrences)
            } else {
                format!(" [{dir_tag}: {}]", sanitized_label)
            };

            out.push_str(&format!(
                "    State_{} --> State_{}:{}\n",
                t.from_state, t.to_state, count_suffix
            ));
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_machine_build_and_mermaid() {
        let turns = vec![
            DialogueTurn {
                direction: NetworkDirection::Tx,
                timestamp_millis: 1000,
                summary: "AUTH username=test".to_string(),
                raw_bytes: b"AUTH test".to_vec(),
            },
            DialogueTurn {
                direction: NetworkDirection::Rx,
                timestamp_millis: 1050,
                summary: "AUTH_OK".to_string(),
                raw_bytes: b"OK".to_vec(),
            },
            DialogueTurn {
                direction: NetworkDirection::Tx,
                timestamp_millis: 1100,
                summary: "GET_DATA".to_string(),
                raw_bytes: b"GET".to_vec(),
            },
            DialogueTurn {
                direction: NetworkDirection::Rx,
                timestamp_millis: 1150,
                summary: "DATA payload=123".to_string(),
                raw_bytes: b"DATA 123".to_vec(),
            },
        ];

        let sm = ProtocolStateMachine::build_from_turns(&turns);
        assert_eq!(sm.nodes.len(), 5); // State 0 (Initial) + 4 состояний
        assert_eq!(sm.transitions.len(), 4);

        let mermaid = sm.to_mermaid();
        assert!(mermaid.contains("stateDiagram-v2"));
        assert!(mermaid.contains("[*] --> State_0"));
        assert!(mermaid.contains("State_0 --> State_1"));
        assert!(mermaid.contains("AUTH username=test"));
    }
}
