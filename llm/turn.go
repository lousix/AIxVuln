package llm

// No imports needed — token counting is in tokencount.go.

// Turn represents an atomic conversation unit that must not be split during
// trimming or compression.
//
// Examples of a single Turn:
//   - A user message (Messages has 1 element)
//   - An assistant message without tool calls (Messages has 1 element)
//   - An assistant message with tool calls + all corresponding tool results
//     (Messages has 1 + N elements)
type Turn struct {
	Messages []Message `json:"messages"`
}

// Flatten returns all messages in the turn as a flat slice.
func (t Turn) Flatten() []Message {
	return t.Messages
}

// Size returns the estimated token count of the turn.
func (t Turn) Size() int {
	return CountTurnTokens(t)
}

// Role returns the role of the first message in the turn (the "primary" role).
func (t Turn) Role() string {
	if len(t.Messages) == 0 {
		return ""
	}
	return t.Messages[0].Role
}

// HasToolCalls returns true if the turn's first message is an assistant message
// with pending tool calls (i.e., the turn may still be incomplete).
func (t Turn) HasToolCalls() bool {
	if len(t.Messages) == 0 {
		return false
	}
	return len(t.Messages[0].ToolCalls) > 0
}

// IsComplete returns true if the turn is complete:
//   - For assistant turns with tool calls: all tool call IDs have matching tool results.
//   - For all other turns: always true.
func (t Turn) IsComplete() bool {
	if len(t.Messages) == 0 {
		return true
	}
	first := t.Messages[0]
	if first.Role != RoleAssistant || len(first.ToolCalls) == 0 {
		return true
	}
	needed := map[string]bool{}
	for _, tc := range first.ToolCalls {
		if tc.ID != "" {
			needed[tc.ID] = true
		}
	}
	for _, m := range t.Messages[1:] {
		if m.Role == RoleTool && m.ToolCallID != "" {
			delete(needed, m.ToolCallID)
		}
	}
	return len(needed) == 0
}

// FlattenTurns converts a slice of turns back to a flat message slice.
func FlattenTurns(turns []Turn) []Message {
	total := 0
	for _, t := range turns {
		total += len(t.Messages)
	}
	out := make([]Message, 0, total)
	for _, t := range turns {
		out = append(out, t.Messages...)
	}
	return out
}

// TurnsSize returns the total estimated token count of all turns.
func TurnsSize(turns []Turn) int {
	return CountTurnsTokens(turns)
}

// BuildTurns groups a flat message slice into turns.
// An assistant message with tool calls starts a turn that includes all
// subsequent tool result messages matching its tool call IDs.
// All other messages become single-message turns.
func BuildTurns(messages []Message) []Turn {
	if len(messages) == 0 {
		return nil
	}
	var turns []Turn
	i := 0
	for i < len(messages) {
		m := messages[i]
		if m.Role == RoleAssistant && len(m.ToolCalls) > 0 {
			// Collect tool call IDs.
			needed := map[string]bool{}
			for _, tc := range m.ToolCalls {
				if tc.ID != "" {
					needed[tc.ID] = true
				}
			}
			turn := Turn{Messages: []Message{m}}
			j := i + 1
			for j < len(messages) && len(needed) > 0 {
				if messages[j].Role == RoleTool && messages[j].ToolCallID != "" {
					if needed[messages[j].ToolCallID] {
						turn.Messages = append(turn.Messages, messages[j])
						delete(needed, messages[j].ToolCallID)
						j++
						continue
					}
				}
				// Non-tool message or unrelated tool message — stop collecting.
				break
			}
			turns = append(turns, turn)
			i = j
		} else {
			turns = append(turns, Turn{Messages: []Message{m}})
			i++
		}
	}
	return turns
}
