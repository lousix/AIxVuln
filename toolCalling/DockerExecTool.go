package toolCalling

import (
	"AIxVuln/misc"
	"AIxVuln/taskManager"
)

type DockerExecTool struct {
	task *taskManager.Task
}

func NewDockerExecTool(task *taskManager.Task) *DockerExecTool {
	return &DockerExecTool{task: task}
}

func (h *DockerExecTool) Name() string {
	return "DockerExecTool"
}
func (h *DockerExecTool) Description() string {
	return "Execute commands in the specified container. (docker exec)"
}
func (h *DockerExecTool) Parameters() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"containerId": map[string]interface{}{
				"type":        "string",
				"description": "container ID.(required)",
			},
			"command": map[string]interface{}{
				"type":        "string",
				"description": "Command to be executed within the container.(required)",
			},
			"timeout": map[string]interface{}{
				"type":        "integer",
				"description": "The timeout for executing the command, in seconds (optional).",
				"minimum":     5,
				"default":     120,
				"maximum":     1800,
			},
		},
	}
}

func (h *DockerExecTool) Execute(parameters map[string]interface{}) string {
	containerIdTemp := parameters["containerId"]
	if containerIdTemp == nil {
		return Fail("Missing 'containerId' parameter")
	}
	containerId := containerIdTemp.(string)

	commandTemp := parameters["command"]
	if commandTemp == nil {
		return Fail("Missing 'command' parameter")
	}
	var command []string
	command = append(command, "sh")
	command = append(command, "-c")
	command = append(command, commandTemp.(string))
	timeoutTemp := parameters["timeout"]
	var timeout int16
	if timeoutTemp == nil {
		timeout = 120
	} else {
		timeoutTmp, err := misc.GetIntParam(timeoutTemp)
		if err != nil {
			return Fail("Error converting timeout to int")
		}
		timeout = int16(timeoutTmp)
	}

	out, err := h.task.GetSm().GetDockerManager().DockerExec(containerId, command, timeout)
	if err != nil {
		return Fail(err.Error())
	}
	return Success(out)
}
