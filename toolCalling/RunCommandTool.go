package toolCalling

import (
	"AIxVuln/misc"
	"AIxVuln/taskManager"
)

type RunCommandTool struct {
	task *taskManager.Task
}

func NewRunCommandTool(task *taskManager.Task) *RunCommandTool {
	return &RunCommandTool{task: task}
}

func (h *RunCommandTool) Name() string {
	return "RunCommandTool"
}
func (h *RunCommandTool) Description() string {
	return "Execute system commands, the source code directory is mapped at /sourceCodeDir (modifying files inside it will automatically synchronize changes to the /sourceCodeDir in the web container). (" + misc.AttackSandboxPrompt() + ")"
}
func (h *RunCommandTool) Parameters() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"command": map[string]interface{}{
				"type":        "string",
				"description": "Commands to be executed",
			},
			"timeout": map[string]interface{}{
				"type":        "integer",
				"description": "The timeout for executing the command, in seconds (optional).",
				"minimum":     5,
				"default":     10,
				"maximum":     1800,
			},
		},
	}
}

func (h *RunCommandTool) Execute(parameters map[string]interface{}) string {
	cmdTemp := parameters["command"]
	if cmdTemp == nil {
		return Fail("Missing 'command' parameter")
	}
	cmd := cmdTemp.(string)
	timeoutArg := parameters["timeout"]
	var timeout int16
	if timeoutArg == nil {
		timeout = 10
	} else {
		timeoutTmp, err := misc.GetIntParam(timeoutArg)
		if err != nil {
			return Fail("Error converting timeout to int")
		}
		timeout = int16(timeoutTmp)
	}
	out, err := h.task.GetSandbox().RunCommand([]string{"sh", "-c", cmd}, timeout)
	if err != nil {
		return Fail(err.Error())
	}
	return Success(out)
}
