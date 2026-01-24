package toolCalling

import (
	"AIxVuln/taskManager"
)

type DockerPsTool struct {
	task *taskManager.Task
}

func NewDockerPsTool(task *taskManager.Task) *DockerPsTool {
	return &DockerPsTool{task: task}
}

func (h *DockerPsTool) Name() string {
	return "DockerPsTool"
}
func (h *DockerPsTool) Description() string {
	return "List all containers (docker ps -a)."
}
func (h *DockerPsTool) Parameters() map[string]interface{} {
	return map[string]interface{}{
		"type":       "object",
		"properties": map[string]interface{}{},
	}
}

func (h *DockerPsTool) Execute(parameters map[string]interface{}) string {
	r, e := h.task.GetSm().GetDockerManager().DockerPs()
	if e != nil {
		return Fail(e.Error())
	}
	return Success(r)
}
