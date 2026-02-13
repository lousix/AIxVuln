package toolCalling

import (
	"AIxVuln/misc"
	"AIxVuln/taskManager"
	"strconv"
)

type RunNodeEnvTool struct {
	task *taskManager.Task
}

func NewNodeEnvTool(task *taskManager.Task) *RunNodeEnvTool {
	return &RunNodeEnvTool{task: task}
}

func (h *RunNodeEnvTool) Name() string {
	return "RunNodeEnvTool"
}
func (h *RunNodeEnvTool) Description() string {
	return "Used to launch an environment running Node.js, with the option to choose any version and automatically map the source code to /sourceCodeDir."
}
func (h *RunNodeEnvTool) Parameters() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"webPort": map[string]interface{}{
				"type":        "integer",
				"description": "Specify which port the web service runs on, for example, 8080.(required)",
			},
			"version": map[string]interface{}{
				"type":        "string",
				"description": "Specify a Node.js version, e.g., 25.4.(required)",
			},
		},
	}
}

func (h *RunNodeEnvTool) Execute(parameters map[string]interface{}) string {
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
	out, err := h.task.GetSm().StartNodeEnv(webPort, version)
	if err != nil {
		return Fail(err.Error())
	}
	msg := make(map[string]string)
	msg["WebPort"] = webPort
	msg["ContainerID"] = out.ContainerID
	msg["ContainerIP"] = out.IPAddress
	h.task.AddKeyMessage("RunNodeEnvTool", msg, false)
	return Success(out)
}
