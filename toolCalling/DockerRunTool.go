package toolCalling

import (
	"AIxVuln/misc"
	"AIxVuln/taskManager"
	"strconv"
)

type DockerRunTool struct {
	task *taskManager.Task
}

func NewDockerRunTool(task *taskManager.Task) *DockerRunTool {
	return &DockerRunTool{task: task}
}

func (h *DockerRunTool) Name() string {
	return "DockerRunTool"
}
func (h *DockerRunTool) Description() string {
	return "Use this tool to start a Docker container when other launch environment tools do not meet the requirements and automatically map the source code to /sourceCodeDir.(docker run)"
}
func (h *DockerRunTool) Parameters() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"command": map[string]interface{}{
				"type":        "string",
				"description": "Commands executed after starting the container.(optional)",
			},
			"image": map[string]interface{}{
				"type":        "string",
				"description": "Which image to use to start the container, must include the specific tag, such as php:7.3.(required)",
			},
			"env": map[string]interface{}{
				"type":        "object",
				"description": "Set environment variables for the launched container, for example: {\"RootPassword\": \"123456\"}, Both key and value must be of string type (numbers should also be enclosed in double quotes).(optional)",
			},
			"timeout": map[string]interface{}{
				"type":        "integer",
				"description": "Container startup timeout ,may be slow because the image will be pulled automatically if it does not exist.(optional)",
				"minimum":     60,
				"default":     120,
				"maximum":     1800,
			},
			"webPort": map[string]interface{}{
				"type":        "integer",
				"description": "If the container is used for a web service, then the web service port needs to be passed in (for example, 80). If it is not used for a web service, no port needs to be passed in. (Optional)",
			},
		},
	}
}

func (h *DockerRunTool) Execute(parameters map[string]interface{}) string {
	imageTemp := parameters["image"]
	if imageTemp == nil {
		return Fail("Missing 'image' parameter")
	}
	image := imageTemp.(string)

	commandTemp := parameters["command"]
	var command []string
	if commandTemp != nil {
		command = append(command, "sh")
		command = append(command, "-c")
		command = append(command, commandTemp.(string))
	}

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

	envTemp := parameters["env"]
	var env1 map[string]interface{}
	if envTemp != nil {
		env1 = envTemp.(map[string]interface{})
	}
	var env = make(map[string]string)

	if env1 != nil {
		for k, v := range env1 {
			env[k] = v.(string)
		}
	}

	webPortTemp := parameters["webPort"]
	var webPort string
	if webPortTemp != nil {
		port, err := misc.GetIntParam(webPortTemp)
		if err != nil {
			return Fail("'webPort' is not a valid integer")
		}
		webPort = strconv.Itoa(port)
	}
	out, err := h.task.GetSm().StartDockerEnv(image, command, timeout, env, webPort)
	if err != nil {
		return Fail(err.Error())
	}
	msg := make(map[string]interface{})
	msg["WebPort"] = webPort
	msg["ContainerID"] = out.ContainerID
	msg["env"] = env
	msg["image"] = image
	msg["command"] = command
	msg["ContainerIP"] = out.IPAddress
	h.task.AddEnvMessage("RunJavaEnvTool", msg, true)
	return Success(out)
}
