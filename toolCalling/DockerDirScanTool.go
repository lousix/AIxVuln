package toolCalling

import (
	"AIxVuln/taskManager"
)

type DockerDirScanTool struct {
	task *taskManager.Task
}

func NewDockerDirScanTool(task *taskManager.Task) *DockerDirScanTool {
	return &DockerDirScanTool{task: task}
}

func (h *DockerDirScanTool) Name() string {
	return "DockerDirScanTool"
}
func (h *DockerDirScanTool) Description() string {
	return "List the contents of a directory in the container (ls -al)."
}
func (h *DockerDirScanTool) Parameters() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"containerId": map[string]interface{}{
				"type":        "string",
				"description": "container ID.(required)",
			},
			"path": map[string]interface{}{
				"type":        "string",
				"description": "The directory to be listed.(required)",
			},
		},
	}
}

func (h *DockerDirScanTool) Execute(parameters map[string]interface{}) string {
	containerIdTemp := parameters["containerId"]
	if containerIdTemp == nil {
		return Fail("Missing 'containerId' parameter")
	}
	containerId := containerIdTemp.(string)
	pathTemp := parameters["path"]
	if pathTemp == nil {
		return Fail("Missing 'path' parameter")
	}
	path := pathTemp.(string)
	command := []string{"ls", "-al", path}
	out, err := h.task.GetSm().GetDockerManager().DockerExec(containerId, command, 10)
	if err != nil {
		return Fail(err.Error())
	}
	return Success(out)
}
