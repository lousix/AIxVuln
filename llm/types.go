package llm

import "encoding/json"

// Role constants — provider-agnostic.
const (
	RoleSystem    = "system"
	RoleUser      = "user"
	RoleAssistant = "assistant"
	RoleTool      = "tool"
)

// ToolCall represents a single function call requested by the model.
type ToolCall struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Arguments string `json:"arguments"`
}

// Message is the universal chat message used throughout the project.
// It replaces openai.ChatCompletionMessage everywhere.
type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

// MarshalJSON implements json.Marshaler so that callers that previously
// relied on openai.ChatCompletionMessage.MarshalJSON() keep working.
func (m Message) MarshalJSON() ([]byte, error) {
	type Alias Message
	return json.Marshal((Alias)(m))
}

// ToolDef describes a function tool that can be passed to the model.
type ToolDef struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
}

// Usage carries token consumption from a single LLM API call.
type Usage struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
}

// Response is the provider-agnostic result of a chat/responses API call.
type Response struct {
	Content   string     // assistant text content
	ToolCalls []ToolCall // tool calls requested by the model
	Usage     Usage      // token usage for this call
}
