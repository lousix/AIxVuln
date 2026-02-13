package toolCalling

import (
	"AIxVuln/taskManager"
)

type RunRedisEnvTool struct {
	task *taskManager.Task
}

func NewRedisEnvTool(task *taskManager.Task) *RunRedisEnvTool {
	return &RunRedisEnvTool{task: task}
}

func (h *RunRedisEnvTool) Name() string {
	return "RunRedisEnvTool"
}
func (h *RunRedisEnvTool) Description() string {
	return "Start a Redis server., and return the container-related information."
}
func (h *RunRedisEnvTool) Parameters() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"version": map[string]interface{}{
				"type":        "string",
				"description": "Specify a redis version number, only one decimal point is accepted.(required)",
			},
			"redisPassword": map[string]interface{}{
				"type":        "string",
				"description": "Specify the password for redis.(optional)",
			},
		},
	}
}

func (h *RunRedisEnvTool) Execute(parameters map[string]interface{}) string {
	versionTemp := parameters["version"]
	if versionTemp == nil {
		return Fail("Missing 'version' parameter")
	}
	version := versionTemp.(string)
	redisPasswordTemp := parameters["redisPassword"]
	var redisPassword string
	if redisPasswordTemp != nil {
		redisPassword = redisPasswordTemp.(string)
	}
	out, err := h.task.GetSm().StartRedis(version, redisPassword)
	if err != nil {
		return Fail(err.Error())
	}
	msg := make(map[string]string)
	msg["RedisPort"] = "6379"
	msg["ContainerID"] = out.ContainerID
	msg["ContainerIP"] = out.IPAddress
	msg["RedisPassword"] = redisPassword
	msg["version"] = version
	h.task.AddKeyMessage("RunRedisEnvTool", msg, false)
	return Success(out)
}
