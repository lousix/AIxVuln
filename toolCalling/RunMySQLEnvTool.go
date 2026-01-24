package toolCalling

import (
	"AIxVuln/taskManager"
	"strings"
)

type RunMySQLEnvTool struct {
	task *taskManager.Task
}

func NewMySQLEnvTool(task *taskManager.Task) *RunMySQLEnvTool {
	return &RunMySQLEnvTool{task: task}
}

func (h *RunMySQLEnvTool) Name() string {
	return "RunMySQLEnvTool"
}
func (h *RunMySQLEnvTool) Description() string {
	return "Start a MySQL environment, choose the version, and return the container-related information."
}
func (h *RunMySQLEnvTool) Parameters() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"version": map[string]interface{}{
				"type":        "string",
				"description": "Specify a MySQL version number, only one decimal point is accepted.(required)",
			},
			"rootPassword": map[string]interface{}{
				"type":        "string",
				"description": "Specify the root password for MySQL.(required)",
			},
			"initSqlDir": map[string]interface{}{
				"type":        "string",
				"description": "If you need to automatically execute some .sql files after MySQL starts running, you need to place these .sql files in a clean directory under `/sourceCodeDir` (you can use the RunCommandTool to place them), and then specify the directory under `/sourceCodeDir`. For example, if the .sql files are in `/sourceCodeDir/initSql`, then specify `/initSql`.(optional)",
			},
		},
	}
}

func (h *RunMySQLEnvTool) Execute(parameters map[string]interface{}) string {
	versionTemp := parameters["version"]
	if versionTemp == nil {
		return Fail("Missing 'version' parameter")
	}
	version := versionTemp.(string)
	rootPasswordTemp := parameters["rootPassword"]
	if rootPasswordTemp == nil {
		return Fail("Missing 'rootPassword' parameter")
	}
	rootPassword := rootPasswordTemp.(string)
	initSqlDirTemp := parameters["initSqlDir"]
	var initSqlDir string
	if initSqlDirTemp != nil {
		initSqlDir = initSqlDirTemp.(string)
	}
	if strings.HasPrefix(initSqlDir, "/sourceCodeDir/") {
		initSqlDir = initSqlDir[15:]
	}
	initSqlDir = strings.TrimLeft(initSqlDir, "/")
	out, err := h.task.GetSm().StartMysql(version, rootPassword, initSqlDir)
	if err != nil {
		return Fail(err.Error())
	}
	msg := make(map[string]string)
	msg["MySQLPort"] = "3306"
	msg["rootPassword"] = rootPassword
	msg["version"] = version
	msg["ContainerID"] = out.ContainerID
	msg["ContainerIP"] = out.IPAddress
	h.task.AddEnvMessage("RunMySQLEnvTool", msg, false)
	return Success(out)
}
