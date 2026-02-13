package toolCalling

import (
	"AIxVuln/misc"
	"AIxVuln/taskManager"
	"strconv"
)

type RunPHPEnvTool struct {
	task *taskManager.Task
}

func NewPHPEnvTool(task *taskManager.Task) *RunPHPEnvTool {
	return &RunPHPEnvTool{task: task}
}

func (h *RunPHPEnvTool) Name() string {
	return "RunPHPEnvTool"
}
func (h *RunPHPEnvTool) Description() string {
	return "Start an Apache2+PHP environment and automatically map the source code to /sourceCodeDir and /var/www/html."
}
func (h *RunPHPEnvTool) Parameters() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"version": map[string]interface{}{
				"type":        "string",
				"description": "Specify a PHP version number, only one decimal point is accepted.\nCorrect: 7.3\nIncorrect: 7.3.2.(required)",
			},
			"webPort": map[string]interface{}{
				"type":        "integer",
				"description": "Specify which port the web service runs on, for example 80, If you do not want to modify the configuration, then pass in 80.(required)",
			},
		},
	}
}

func (h *RunPHPEnvTool) Execute(parameters map[string]interface{}) string {
	versionTemp := parameters["version"]
	if versionTemp == nil {
		return Fail("Missing 'version' parameter")
	}
	version := versionTemp.(string)
	webPortTemp := parameters["webPort"]
	if webPortTemp == nil {
		return Fail("Missing 'webPort' parameter")
	}
	port, err := misc.GetIntParam(webPortTemp)
	if err != nil {
		return Fail("'webPort' is not a valid integer")
	}
	webPort := strconv.Itoa(port)
	out, err := h.task.GetSm().StartPhpEnv(version, webPort)
	if err != nil {
		return Fail(err.Error())
	}
	msg := make(map[string]string)
	msg["webPort"] = webPort
	msg["version"] = version
	msg["ContainerID"] = out.ContainerID
	msg["ContainerIP"] = out.IPAddress
	h.task.AddKeyMessage("RunPHPEnvTool", msg, false)
	return Success(out)
}
