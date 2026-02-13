package llm

func SanitizeToolCallMessages(messages []Message) []Message {
	if len(messages) == 0 {
		return messages
	}
	allowed := map[string]bool{}
	out := make([]Message, 0, len(messages))
	// Collect user messages that appear between an assistant(tool_calls) and its tool results.
	// These get ignored by the LLM because the API expects tool results right after tool_calls.
	// We defer them and insert after the tool result block ends.
	var deferred []Message
	pendingToolCalls := false // true when we've seen assistant with tool_calls but not all results yet
	for _, m := range messages {
		if m.Role == RoleAssistant {
			// Flush any deferred user messages before this assistant message.
			if len(deferred) > 0 {
				out = append(out, deferred...)
				deferred = nil
			}
			for _, tc := range m.ToolCalls {
				if tc.ID != "" {
					allowed[tc.ID] = true
				}
			}
			pendingToolCalls = len(m.ToolCalls) > 0
			out = append(out, m)
			continue
		}
		if m.Role == RoleTool {
			if m.ToolCallID != "" && allowed[m.ToolCallID] {
				out = append(out, m)
			}
			continue
		}
		// user / system message
		if pendingToolCalls {
			// Defer this message — it's stuck between tool_calls and tool results.
			deferred = append(deferred, m)
		} else {
			out = append(out, m)
		}
	}
	// Flush remaining deferred messages at the end.
	if len(deferred) > 0 {
		out = append(out, deferred...)
	}
	return out
}
