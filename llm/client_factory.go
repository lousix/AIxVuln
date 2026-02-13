package llm

import (
	"AIxVuln/misc"
	"context"
	"strconv"
	"strings"
	"sync"

	"github.com/openai/openai-go/v3/option"
)

// --- per-API-key rate limiting ---

// rateLimitedClient wraps a Client with a per-API-key semaphore.
type rateLimitedClient struct {
	inner     Client
	semaphore chan struct{}
}

func (r *rateLimitedClient) Chat(ctx context.Context, model string, messages []Message, tools []ToolDef) (Response, error) {
	select {
	case r.semaphore <- struct{}{}:
		defer func() { <-r.semaphore }()
	case <-ctx.Done():
		return Response{}, ctx.Err()
	}
	return r.inner.Chat(ctx, model, messages, tools)
}

// keySemaphores stores one semaphore per API key so that all clients sharing
// the same key share the same concurrency limit.
var keySemaphores = struct {
	mu sync.Mutex
	m  map[string]chan struct{}
}{m: make(map[string]chan struct{})}

// getOrCreateSemaphore returns the semaphore for the given API key,
// creating one with the specified capacity if it doesn't exist yet.
func getOrCreateSemaphore(apiKey string, capacity int) chan struct{} {
	keySemaphores.mu.Lock()
	defer keySemaphores.mu.Unlock()
	if sem, ok := keySemaphores.m[apiKey]; ok {
		return sem
	}
	sem := make(chan struct{}, capacity)
	keySemaphores.m[apiKey] = sem
	return sem
}

// clientPool manages a pool of Client instances per config section,
// supporting multi-key round-robin.
var clientPool = &llmClientPool{
	pool:  make(map[string][]Client),
	index: make(map[string]int),
}

type llmClientPool struct {
	mu    sync.Mutex
	pool  map[string][]Client
	index map[string]int
}

func (p *llmClientPool) get(key string) Client {
	p.mu.Lock()
	defer p.mu.Unlock()
	clients, ok := p.pool[key]
	if !ok || len(clients) == 0 {
		return nil
	}
	idx := p.index[key]
	cli := clients[idx]
	idx++
	if idx >= len(clients) {
		idx = 0
	}
	p.index[key] = idx
	return cli
}

func (p *llmClientPool) put(key string, cli Client) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pool[key] = append(p.pool[key], cli)
}

// GetResponsesClient returns an LLM client for the given config section(s).
// It reads BASE_URL, OPENAI_API_KEY from the section, and USER_AGENT,
// API_MODE, MaxRequest from the section first, falling back to [main_setting].
//
// API_MODE:
//   - "responses" (default) — uses the Responses API
//   - "chat" — uses the Chat Completions API
//
// Clients are created on first access and round-robin across multiple API
// keys (separated by "|-|").
func GetResponsesClient(sections ...string) Client {
	for _, section := range sections {
		if cli := clientPool.get(section); cli != nil {
			return cli
		}
		baseURL := misc.GetConfigValueDefault(section, "BASE_URL", "")
		secretKey := misc.GetConfigValueDefault(section, "OPENAI_API_KEY", "")
		if secretKey == "" {
			continue
		}
		keys := []string{secretKey}
		if strings.Contains(secretKey, "|-|") {
			keys = strings.Split(secretKey, "|-|")
		}
		userAgent := misc.GetConfigValueDefault(section, "USER_AGENT", "")
		if userAgent == "" {
			userAgent = misc.GetConfigValueDefault("main_setting", "USER_AGENT", "AIxVuln")
		}
		rawMode := misc.GetConfigValueDefault(section, "API_MODE", "")
		if rawMode == "" {
			rawMode = misc.GetConfigValueDefault("main_setting", "API_MODE", "chat")
		}
		apiMode := strings.ToLower(strings.TrimSpace(rawMode))
		misc.Debug("GetResponsesClient: section=%s, API_MODE raw=%q resolved=%q", section, rawMode, apiMode)

		// Per-key concurrency limit: read from section first, fall back to [main_setting].
		maxReqStr := misc.GetConfigValueDefault(section, "MaxRequest",
			misc.GetConfigValueDefault("main_setting", "MaxRequest", "3"))
		maxReq, _ := strconv.Atoi(maxReqStr)
		if maxReq <= 0 {
			maxReq = 3
		}

		for _, key := range keys {
			trimmedKey := strings.TrimSpace(key)
			opts := []option.RequestOption{
				option.WithAPIKey(trimmedKey),
				option.WithHeader("User-Agent", userAgent),
			}
			if baseURL != "" {
				opts = append(opts, option.WithBaseURL(strings.TrimSpace(baseURL)))
			}
			var inner Client
			if apiMode == "chat" {
				inner = NewOpenAIChatClient(section, opts...)
			} else {
				inner = NewOpenAIResponsesClient(section, opts...)
			}
			// Wrap with per-key rate limiter.
			sem := getOrCreateSemaphore(trimmedKey, maxReq)
			cli := &rateLimitedClient{inner: inner, semaphore: sem}
			misc.Debug("GetResponsesClient: created client for section=%s, key=...%s, maxRequest=%d",
				section, trimmedKey[max(0, len(trimmedKey)-6):], maxReq)
			clientPool.put(section, cli)
		}
		if cli := clientPool.get(section); cli != nil {
			return cli
		}
	}
	return nil
}
