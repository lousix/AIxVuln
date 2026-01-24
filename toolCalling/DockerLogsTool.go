package toolCalling

import (
	"AIxVuln/misc"
	"AIxVuln/taskManager"
	"strings"
)

type DockerLogsTool struct {
	task *taskManager.Task
}

func NewDockerLogsTool(task *taskManager.Task) *DockerLogsTool {
	return &DockerLogsTool{task: task}
}

func (h *DockerLogsTool) Name() string {
	return "DockerLogsTool"
}
func (h *DockerLogsTool) Description() string {
	return "Get the log information of the Docker container. (docker logs)"
}
func (h *DockerLogsTool) Parameters() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"containerId": map[string]interface{}{
				"type":        "string",
				"description": "container ID.(required)",
			},
			"tailNumber": map[string]interface{}{
				"type":        "integer",
				"description": "If you think the log is too long, you can specify this parameter to get the last N lines. (optional).",
			},
		},
	}
}

func (h *DockerLogsTool) Execute(parameters map[string]interface{}) string {
	containerIdTemp := parameters["containerId"]
	if containerIdTemp == nil {
		return Fail("Missing 'containerId' parameter")
	}
	containerId := containerIdTemp.(string)
	var tailNumber int
	tailNumberTemp := parameters["tailNumber"]
	if tailNumberTemp == nil {
		tailNumber = 0
	} else {
		timeoutTmp, err := misc.GetIntParam(tailNumberTemp)
		if err != nil {
			return Fail("Error converting timeout to int")
		}
		tailNumber = timeoutTmp
	}
	out, err := h.task.GetSm().GetDockerManager().DockerLogs(containerId)
	if tailNumber > 0 {
		out = GetLastNLines(out, tailNumber)
	}
	if err != nil {
		return Fail(err.Error())
	}
	return Success(out)
}

func GetLastNLines(str string, n int) string {
	if n <= 0 {
		return ""
	}
	lines := strings.Split(str, "\n")
	if len(lines) <= n {
		return str
	}
	lastLines := lines[len(lines)-n:]
	return strings.Join(lastLines, "\n")
}
