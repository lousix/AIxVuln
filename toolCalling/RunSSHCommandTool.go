package toolCalling

import (
	"AIxVuln/misc"
	"AIxVuln/taskManager"
	"fmt"
)

type RunSSHCommandTool struct {
	task *taskManager.Task
}

func NewRunSSHCommandTool(task *taskManager.Task) *RunSSHCommandTool {
	return &RunSSHCommandTool{task: task}
}

func (h *RunSSHCommandTool) Name() string {
	return "RunSSHCommandTool"
}
func (h *RunSSHCommandTool) Description() string {
	return "Connect to remote services via SSH and execute system commands remotely."
}
func (h *RunSSHCommandTool) Parameters() map[string]interface{} {
	return map[string]interface{}{
		"type":     "object",
		"required": []string{"host", "user", "password", "command"},
		"properties": map[string]interface{}{
			"host": map[string]interface{}{
				"type":        "string",
				"description": "SSH Host.",
			},
			"port": map[string]interface{}{
				"type":        "string",
				"description": "SSH Port.",
			},
			"user": map[string]interface{}{
				"type":        "string",
				"description": "SSH UserName.",
			},
			"password": map[string]interface{}{
				"type":        "string",
				"description": "SSH Password.",
			},
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

func (h *RunSSHCommandTool) Execute(parameters map[string]interface{}) string {
	cmdTemp := parameters["command"]
	if cmdTemp == nil {
		return Fail("Missing 'command' parameter")
	}
	cmd := cmdTemp.(string)

	hostTemp := parameters["host"]
	if hostTemp == nil {
		return Fail("Missing 'host' parameter")
	}
	host := hostTemp.(string)

	portTemp := parameters["port"]
	if portTemp == nil {
		return Fail("Missing 'port' parameter")
	}
	port := portTemp.(string)

	userTemp := parameters["user"]
	if userTemp == nil {
		return Fail("Missing 'user' parameter")
	}
	user := userTemp.(string)

	passwordTemp := parameters["password"]
	if passwordTemp == nil {
		return Fail("Missing 'password' parameter")
	}
	password := passwordTemp.(string)

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
	s, e := taskManager.GetSandbox(h.task.GetProjectName())
	if e != nil {
		return Fail(e.Error())
	}
	out, err := s.RunCommand([]string{"sshpass", "-p", password, "ssh", "-o", "StrictHostKeyChecking=no", "-o", "LogLevel=ERROR", "-q", "-p", port, fmt.Sprintf("%s@%s", user, host), cmd}, timeout)
	if err != nil {
		return Fail(err.Error())
	}
	return Success(out)
}
