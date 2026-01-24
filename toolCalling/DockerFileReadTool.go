package toolCalling

import (
	"AIxVuln/misc"
	"AIxVuln/taskManager"
	"fmt"
)

type DockerFileReadTool struct {
	task *taskManager.Task
}

func NewDockerFileReadTool(task *taskManager.Task) *DockerFileReadTool {
	return &DockerFileReadTool{task: task}
}

func (h *DockerFileReadTool) Name() string {
	return "DockerFileReadTool"
}
func (h *DockerFileReadTool) Description() string {
	return "Read the file content inside a Docker container."
}
func (h *DockerFileReadTool) Parameters() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"containerId": map[string]interface{}{
				"type":        "string",
				"description": "container ID.(required)",
			},
			"path": map[string]interface{}{
				"type":        "string",
				"description": "The path of the file to be read.(required)",
			},
			"lineNumber": map[string]interface{}{
				"type":        "integer",
				"description": "Starting line number to read from.(required).",
				"minimum":     1,
			},
			"lineCount": map[string]interface{}{
				"type":        "integer",
				"description": "Number of lines to read.(required).",
				"minimum":     1,
				"default":     5,
				"maximum":     20,
			},
		},
	}
}

func (h *DockerFileReadTool) Execute(parameters map[string]interface{}) string {
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
	var lineNumber int
	var lineCount int
	lineNumberTemp := parameters["lineNumber"]
	if lineNumberTemp == nil {
		return Fail("lineNumber parameter should not empty")
	}
	lineNumber, _ = misc.GetIntParam(lineNumberTemp)

	lineCountTemp := parameters["lineCount"]
	if lineCountTemp == nil {
		return Fail("lineCount parameter should not empty")
	}
	lineCount, _ = misc.GetIntParam(lineCountTemp)
	endLine := lineNumber + lineCount - 1
	command := []string{"sed", "-n", fmt.Sprintf("%d,%dp", lineNumber, endLine), path}
	out, err := h.task.GetSm().GetDockerManager().DockerExec(containerId, command, 10)
	if err != nil {
		return Fail(err.Error())
	}
	return Success(out)
}
