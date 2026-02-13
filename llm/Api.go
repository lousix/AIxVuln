package llm

import (
	"AIxVuln/misc"
	"context"
	"runtime"
)

// RequestLLM sends a chat request through the abstract Client interface.
// Per-API-key concurrency limiting is handled by the rateLimitedClient wrapper
// created in client_factory.go.
func RequestLLM(cli Client, ctx context.Context, model string, messages []Message, tools []ToolDef, projectName ...string) (Response, error) {
	resp, err := cli.Chat(ctx, model, messages, tools)
	if err != nil {
		pc, f, _, ok := runtime.Caller(1)
		if ok {
			funcName := runtime.FuncForPC(pc).Name()
			misc.Debug("API ERR: %s. from: %s-%s", err.Error(), f, funcName)
		} else {
			misc.Debug("API ERR: %s", err.Error())
		}
	}
	// Accumulate token usage for the project.
	if err == nil && resp.Usage.TotalTokens > 0 && len(projectName) > 0 && projectName[0] != "" {
		AddProjectTokenUsage(projectName[0], resp.Usage)
	}
	return resp, err
}

// ResponseToMessage converts a Response into an assistant Message,
// preserving any tool calls.
func ResponseToMessage(resp Response) Message {
	return Message{
		Role:      RoleAssistant,
		Content:   resp.Content,
		ToolCalls: resp.ToolCalls,
	}
}
