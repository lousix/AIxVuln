package llm

import (
	"encoding/json"
	"sync"

	"github.com/tiktoken-go/tokenizer"
)

var (
	bpeOnce sync.Once
	bpeEnc  tokenizer.Codec
)

// getEncoder returns a singleton BPE encoder (o200k_base for GPT-4o family).
// Falls back to cl100k_base if o200k is unavailable.
func getEncoder() tokenizer.Codec {
	bpeOnce.Do(func() {
		var err error
		bpeEnc, err = tokenizer.Get(tokenizer.O200kBase)
		if err != nil {
			// Fallback to cl100k_base (GPT-4/3.5).
			bpeEnc, err = tokenizer.Get(tokenizer.Cl100kBase)
			if err != nil {
				panic("failed to initialize tiktoken encoder: " + err.Error())
			}
		}
	})
	return bpeEnc
}

// CountTokens returns the number of BPE tokens in the given text.
func CountTokens(text string) int {
	enc := getEncoder()
	ids, _, _ := enc.Encode(text)
	return len(ids)
}

// CountMessageTokens estimates the token count for a single Message,
// following the OpenAI token counting convention:
// each message costs 4 overhead tokens (role, separators) + content tokens + name tokens.
// Tool calls are serialized to JSON for counting.
func CountMessageTokens(m Message) int {
	tokens := 4 // per-message overhead: <|start|>role<|sep|>...<|end|>
	tokens += CountTokens(m.Content)
	if m.Role != "" {
		tokens += CountTokens(m.Role)
	}
	if len(m.ToolCalls) > 0 {
		for _, tc := range m.ToolCalls {
			tokens += CountTokens(tc.Name)
			tokens += CountTokens(tc.Arguments)
			tokens += 3 // overhead per tool call (id, type, function)
		}
	}
	if m.ToolCallID != "" {
		tokens += CountTokens(m.ToolCallID)
	}
	return tokens
}

// CountMessagesTokens returns the total token count for a slice of Messages,
// plus 3 tokens for the assistant reply priming.
func CountMessagesTokens(messages []Message) int {
	tokens := 3 // every reply is primed with <|start|>assistant<|message|>
	for _, m := range messages {
		tokens += CountMessageTokens(m)
	}
	return tokens
}

// CountTurnTokens returns the token count for a single Turn.
func CountTurnTokens(t Turn) int {
	return CountMessagesTokens(t.Messages)
}

// CountTurnsTokens returns the total token count for a slice of Turns.
func CountTurnsTokens(turns []Turn) int {
	msgs := FlattenTurns(turns)
	return CountMessagesTokens(msgs)
}

// EstimateJSONTokens estimates the token count for an arbitrary value
// by marshaling it to JSON and counting tokens on the result.
func EstimateJSONTokens(v interface{}) int {
	js, err := json.Marshal(v)
	if err != nil {
		return 0
	}
	return CountTokens(string(js))
}
