package agents

import (
	"AIxVuln/llm"
	"AIxVuln/taskManager"
	"context"
)

type Agent interface {
	Name() string
	Description() string
	StartTask(ctx context.Context) *StartResp
	GetMemory() llm.Memory
	SetMemory(llm.Memory)
	GetTask() *taskManager.Task
	SetKeyMessage(k map[string][]interface{})
	GetId() string
	SetId(id string)
}

type StartResp struct {
	Err     error
	Memory  llm.Memory
	Vuln    []taskManager.Vuln
	EvnInfo map[string]interface{}
}

func CommonSystemPrompt() string {
	return `You are working within a vulnerability discovery system. Some tools you call may have issues. If you encounter such problems or have improvement suggestions (e.g., what capabilities could be provided) to make completing this work more efficient, you can use the IssueTool to provide feedback.
If the user provides a list of subtasks, then you need to complete the subtasks in order. When finishing or abandoning a specific subtask, you must call the TaskListTool to update the status of the task list.`
}
