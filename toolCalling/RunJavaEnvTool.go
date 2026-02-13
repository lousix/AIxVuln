package toolCalling

import (
	"AIxVuln/misc"
	"AIxVuln/taskManager"
	"strconv"
)

type RunJavaEnvTool struct {
	task *taskManager.Task
}

func NewJavaEnvTool(task *taskManager.Task) *RunJavaEnvTool {
	return &RunJavaEnvTool{task: task}
}

func (h *RunJavaEnvTool) Name() string {
	return "RunJavaEnvTool"
}
func (h *RunJavaEnvTool) Description() string {
	return "Start a Java runtime environment, which includes multiple versions of Maven, JDK, Gradle, and Tomcat.  \nUsage note: inside java_env you can switch toolchain versions: use 'jdk <ver>' (default jdk11, e.g., 'jdk 8'), 'maven-v <ver>' (3.3.9/3.5.4/3.6.3/3.8.6), and 'gradle-v <ver>' (3.5.4/4.10.3/5.6.4/6.9/7.5/8.5). Tomcat9 is installed at /var/lib/tomcat9 and automatically map the source code to /sourceCodeDir."
}
func (h *RunJavaEnvTool) Parameters() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"webPort": map[string]interface{}{
				"type":        "integer",
				"description": "Specify which port the web service runs on, for example, 8080.(required)",
			},
		},
	}
}

func (h *RunJavaEnvTool) Execute(parameters map[string]interface{}) string {
	webPortTemp := parameters["webPort"]
	if webPortTemp == nil {
		return Fail("Missing 'webPort' parameter")
	}
	port, err := misc.GetIntParam(webPortTemp)
	if err != nil {
		return Fail("'webPort' is not a valid integer")
	}
	webPort := strconv.Itoa(port)
	out, err := h.task.GetSm().StartJavaEnv(webPort)
	if err != nil {
		return Fail(err.Error())
	}
	msg := make(map[string]string)
	msg["WebPort"] = webPort
	msg["ContainerID"] = out.ContainerID
	msg["ContainerIP"] = out.IPAddress
	h.task.AddKeyMessage("RunJavaEnvTool", msg, false)
	return Success(out)
}
