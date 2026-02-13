package toolCalling

import (
	"AIxVuln/misc"
	"AIxVuln/taskManager"
	"strconv"
)

type RunPythonEnvTool struct {
	task *taskManager.Task
}

func NewPythonEnvTool(task *taskManager.Task) *RunPythonEnvTool {
	return &RunPythonEnvTool{task: task}
}

func (h *RunPythonEnvTool) Name() string {
	return "RunPythonEnvTool"
}
func (h *RunPythonEnvTool) Description() string {
	return "Start a Python runtime environment with a selectable version."
}
func (h *RunPythonEnvTool) Parameters() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"webPort": map[string]interface{}{
				"type":        "integer",
				"description": "Specify which port the web service runs on, for example, 5000.(required)",
			},
			"version": map[string]interface{}{
				"type":        "string",
				"description": "Specify a Python version number, only one decimal point is accepted.(required)",
			},
		},
	}
}

func (h *RunPythonEnvTool) Execute(parameters map[string]interface{}) string {
	webPortTemp := parameters["webPort"]
	if webPortTemp == nil {
		return Fail("Missing 'webPort' parameter")
	}
	port, err := misc.GetIntParam(webPortTemp)
	if err != nil {
		return Fail("'webPort' is not a valid integer")
	}
	webPort := strconv.Itoa(port)
	versionTemp := parameters["version"]
	if versionTemp == nil {
		return Fail("Missing 'version' parameter")
	}
	version := versionTemp.(string)
	out, err := h.task.GetSm().StartPythonEnv(webPort, version)
	if err != nil {
		return Fail(err.Error())
	}
	msg := make(map[string]string)
	msg["WebPort"] = webPort
	msg["ContainerID"] = out.ContainerID
	msg["ContainerIP"] = out.IPAddress
	h.task.AddKeyMessage("RunPythonEnvTool", msg, false)
	return Success(out)
}
