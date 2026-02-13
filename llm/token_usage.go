package llm

import (
	"sync"
	"sync/atomic"
)

// ProjectTokenUsage tracks cumulative token usage for a single project.
type ProjectTokenUsage struct {
	PromptTokens     atomic.Int64
	CompletionTokens atomic.Int64
	TotalTokens      atomic.Int64
}

// Add accumulates usage from a single API call.
func (u *ProjectTokenUsage) Add(usage Usage) {
	u.PromptTokens.Add(usage.PromptTokens)
	u.CompletionTokens.Add(usage.CompletionTokens)
	u.TotalTokens.Add(usage.TotalTokens)
}

// Snapshot returns the current cumulative usage.
func (u *ProjectTokenUsage) Snapshot() Usage {
	return Usage{
		PromptTokens:     u.PromptTokens.Load(),
		CompletionTokens: u.CompletionTokens.Load(),
		TotalTokens:      u.TotalTokens.Load(),
	}
}

var (
	projectUsageMu sync.RWMutex
	projectUsage   = make(map[string]*ProjectTokenUsage)
)

// GetProjectTokenUsage returns the token usage tracker for a project (creates if needed).
func GetProjectTokenUsage(projectName string) *ProjectTokenUsage {
	projectUsageMu.RLock()
	u, ok := projectUsage[projectName]
	projectUsageMu.RUnlock()
	if ok {
		return u
	}
	projectUsageMu.Lock()
	defer projectUsageMu.Unlock()
	if u, ok = projectUsage[projectName]; ok {
		return u
	}
	u = &ProjectTokenUsage{}
	projectUsage[projectName] = u
	return u
}

// AddProjectTokenUsage is a convenience function to accumulate usage for a project.
func AddProjectTokenUsage(projectName string, usage Usage) {
	if usage.TotalTokens <= 0 {
		return
	}
	GetProjectTokenUsage(projectName).Add(usage)
}
