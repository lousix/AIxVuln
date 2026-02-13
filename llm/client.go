package llm

import "context"

// Client is the provider-agnostic interface for LLM API calls.
// Implement this for each backend (OpenAI Chat Completions, Responses API,
// Anthropic, local models, etc.).
type Client interface {
	// Chat sends messages (with optional tool definitions) and returns the
	// model's response. Implementations handle retries internally if desired.
	Chat(ctx context.Context, model string, messages []Message, tools []ToolDef) (Response, error)
}
