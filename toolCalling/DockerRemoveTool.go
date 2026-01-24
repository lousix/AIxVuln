package toolCalling

import (
	"AIxVuln/taskManager"
)

type DockerRemoveTool struct {
	task *taskManager.Task
}

func NewDockerRemoveTool(task *taskManager.Task) *DockerRemoveTool {
	return &DockerRemoveTool{task: task}
}

func (h *DockerRemoveTool) Name() string {
	return "DockerRemoveTool"
}
func (h *DockerRemoveTool) Description() string {
	return "Delete Docker container (`docker rm -f`)."
}
func (h *DockerRemoveTool) Parameters() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"containerId": map[string]interface{}{
				"type":        "string",
				"description": "container ID.(required)",
			},
		},
	}
}

func (h *DockerRemoveTool) Execute(parameters map[string]interface{}) string {
	containerIdTemp := parameters["containerId"]
	if containerIdTemp == nil {
		return Fail("Missing 'containerId' parameter")
	}
	containerId := containerIdTemp.(string)
	err := h.task.GetSm().GetDockerManager().DockerRemove(containerId)
	if err != nil {
		return Fail(err.Error())
	}
	return Success("Remove Success")
}
