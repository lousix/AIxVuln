package toolCalling

import (
	"AIxVuln/misc"
	"AIxVuln/taskManager"
	"strings"
)

type RunSQLTool struct {
	task *taskManager.Task
}

func NewRunSQLTool(task *taskManager.Task) *RunSQLTool {
	return &RunSQLTool{task: task}
}

func (h *RunSQLTool) Name() string {
	return "RunSQLTool"
}
func (h *RunSQLTool) Description() string {
	return "Connect to the MySQL server and run SQL statements. (" + misc.AttackSandboxPrompt() + ")"
}
func (h *RunSQLTool) Parameters() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"sql": map[string]interface{}{
				"type":        "string",
				"description": "SQL commands to be executed.(required)",
			},
			"user": map[string]interface{}{
				"type":        "string",
				"description": "MySQL username.(required)",
			},
			"password": map[string]interface{}{
				"type":        "string",
				"description": "MySQL password.(required)",
			},
			"host": map[string]interface{}{
				"type":        "string",
				"description": "MySQL Host.(required)",
			},
			"timeout": map[string]interface{}{
				"type":        "integer",
				"description": "The timeout for executing the SQL, in seconds (optional).",
				"minimum":     5,
				"default":     10,
				"maximum":     1800,
			},
		},
	}
}

func (h *RunSQLTool) Execute(parameters map[string]interface{}) string {
	var sql, user, password, host string
	sqlTemp := parameters["sql"]
	if sqlTemp == nil {
		return Fail("Missing 'sql' parameter")
	}
	sql = sqlTemp.(string)
	userTemp := parameters["user"]
	if userTemp == nil {
		return Fail("Missing 'user' parameter")
	}
	user = userTemp.(string)
	passwordTemp := parameters["password"]
	if passwordTemp == nil {
		return Fail("Missing 'password' parameter")
	}
	password = passwordTemp.(string)
	hostTemp := parameters["host"]
	if hostTemp == nil {
		return Fail("Missing 'host' parameter")
	}
	host = hostTemp.(string)
	var command []string
	command = append(command, "mysql")
	command = append(command, "-h"+host)
	command = append(command, "-u"+user)
	command = append(command, "-p"+password)
	command = append(command, "-e"+sql)
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
	out = strings.ReplaceAll(out, "mysql: [Warning] Using a password on the command line interface can be insecure.\n", "")
	if err != nil {
		return Fail(err.Error())
	}
	return Success(out)
}
