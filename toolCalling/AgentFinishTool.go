package toolCalling

import (
	"AIxVuln/taskManager"
)

const AgentFinishMarker = "__AGENT_FINISH__:"

type AgentFinishTool struct {
	task *taskManager.Task
}

func NewAgentFinishTool(task *taskManager.Task) *AgentFinishTool {
	return &AgentFinishTool{task: task}
}

func (h *AgentFinishTool) Name() string {
	return "AgentFinishTool"
}
func (h *AgentFinishTool) Description() string {
	return "Call this tool when you have completed all your tasks and are ready to exit. You MUST provide a concise summary (RUNSummary) of what you did, what you found, and any issues encountered. Written in Chinese, under 500 characters."
}
func (h *AgentFinishTool) Parameters() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"summary": map[string]interface{}{
				"type":        "string",
				"description": "A concise summary (RUNSummary) of your work. Written in Chinese, under 500 characters. Describe: what you did, what you found or accomplished, any problems encountered and how you handled them.(required)",
			},
		},
	}
}

func (h *AgentFinishTool) Execute(parameters map[string]interface{}) string {
	summary := ""
	if s, ok := parameters["summary"].(string); ok {
		summary = s
	}
	if summary == "" {
		return Fail("Missing 'summary' parameter. You must provide a summary of your work.")
	}
	// Return a special marker that the agent loop will detect to exit.
	return AgentFinishMarker + summary
}
