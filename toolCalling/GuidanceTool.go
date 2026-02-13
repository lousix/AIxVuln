package toolCalling

import (
	"AIxVuln/taskManager"
)

type GuidanceTool struct {
	task *taskManager.Task
}

func NewGuidanceTool(task *taskManager.Task) *GuidanceTool {
	return &GuidanceTool{task: task}
}

func (h *GuidanceTool) Name() string {
	return "GuidanceTool"
}
func (h *GuidanceTool) Description() string {
	return "When your task execution fails, first call the GuidanceTool to attempt to obtain a solution."
}
func (h *GuidanceTool) Parameters() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"source": map[string]interface{}{
				"type":        "string",
				"description": "Your identity — who you are and what type of agent you are. For example: '林辰宇(代码分析数字人)' or '江亦琛(漏洞验证数字人)'. This helps the expert give you a more targeted answer.(required)",
			},
			"description": map[string]interface{}{
				"type":        "string",
				"description": "Describe the problems you encountered, the solutions you attempted, and the reasons for their failure.(required)",
			},
		},
	}
}

func (h *GuidanceTool) Execute(parameters map[string]interface{}) string {
	descTemp := parameters["description"]
	if descTemp == nil {
		return Fail("Missing 'description' parameter")
	}
	desc, ok := descTemp.(string)
	if !ok {
		return Fail("'description' parameter should be string")
	}
	source := ""
	if s, ok := parameters["source"].(string); ok {
		source = s
	}
	handler := h.task.GetGuidanceHandler()
	if handler == nil {
		return Fail("guidance handler is not set")
	}
	issue := desc + "\n\n"
	r := handler(source, issue)
	return Success(r)
}
