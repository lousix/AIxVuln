package toolCalling

import (
	"AIxVuln/misc"
	"AIxVuln/taskManager"
)

type RunPHPCodeTool struct {
	task *taskManager.Task
}

func NewRunPHPCodeTool(task *taskManager.Task) *RunPHPCodeTool {
	return &RunPHPCodeTool{task: task}
}

func (h *RunPHPCodeTool) Name() string {
	return "RunPHPCodeTool"
}
func (h *RunPHPCodeTool) Description() string {
	return "Execute PHP code in the sandbox. Use this function when you need to run complex PHP code. (" + misc.AttackSandboxPrompt() + ")"
}
func (h *RunPHPCodeTool) Parameters() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"code": map[string]interface{}{
				"type":        "string",
				"description": "PHP code to be executed.(required)",
			},
			"timeout": map[string]interface{}{
				"type":        "integer",
				"description": "The timeout for executing the PHP Code, in seconds (optional).",
				"minimum":     5,
				"default":     10,
				"maximum":     1800,
			},
		},
	}
}

func (h *RunPHPCodeTool) Execute(parameters map[string]interface{}) string {
	codeTemp := parameters["code"]
	if codeTemp == nil {
		return Fail("Missing 'code' parameter")
	}
	var command []string
	command = append(command, "php")
	command = append(command, "-r")
	command = append(command, codeTemp.(string))
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
	s, e := taskManager.GetSandbox(h.task.GetProjectName())
	if e != nil {
		return Fail(e.Error())
	}
	out, err := s.RunCommand(command, timeout)
	if err != nil {
		return Fail(err.Error())
	}
	return Success(out)
}
