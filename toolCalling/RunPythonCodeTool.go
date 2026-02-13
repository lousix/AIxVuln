package toolCalling

import (
	"AIxVuln/misc"
	"AIxVuln/taskManager"
)

type RunPythonCodeTool struct {
	task *taskManager.Task
}

func NewRunPythonCodeTool(task *taskManager.Task) *RunPythonCodeTool {
	return &RunPythonCodeTool{task: task}
}

func (h *RunPythonCodeTool) Name() string {
	return "RunPythonCodeTool"
}
func (h *RunPythonCodeTool) Description() string {
	return "Execute Python code in the sandbox. Use this function when you need to run complex Python code. (" + misc.AttackSandboxPrompt() + ")"
}
func (h *RunPythonCodeTool) Parameters() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"code": map[string]interface{}{
				"type":        "string",
				"description": "Python code to be executed.(required)",
			},
			"timeout": map[string]interface{}{
				"type":        "integer",
				"description": "The timeout for executing the Python Code, in seconds (optional).",
				"minimum":     5,
				"default":     10,
				"maximum":     1800,
			},
		},
	}
}

func (h *RunPythonCodeTool) Execute(parameters map[string]interface{}) string {
	codeTemp := parameters["code"]
	if codeTemp == nil {
		return Fail("Missing 'code' parameter")
	}
	var command []string
	command = append(command, "python3")
	command = append(command, "-c")
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
