package toolCalling

import (
	"AIxVuln/taskManager"
)

type EnvSaveTool struct {
	task *taskManager.Task
}

func NewEnvSaveTool(task *taskManager.Task) *EnvSaveTool {
	return &EnvSaveTool{task: task}
}

func (h *EnvSaveTool) Name() string {
	return "EnvSaveTool"
}
func (h *EnvSaveTool) Description() string {
	return "Save the environment information after successful setup to facilitate subsequent vulnerability mining and testing."
}
func (h *EnvSaveTool) Parameters() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"containerId": map[string]interface{}{
				"type":        "string",
				"description": "container ID.(required)",
			},
			"loginInfo": map[string]interface{}{
				"type":        "object",
				"description": "System login information.",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{
						"type":        "string",
						"description": "Login Username.",
					},
					"password": map[string]interface{}{
						"type":        "string",
						"description": "Login Password.",
					},
					"loginURL": map[string]interface{}{
						"type":        "string",
						"description": "Login URL.",
					},
					"credentials": map[string]interface{}{
						"type":        "string",
						"description": "Retrieving valid credentials in other formats from cookies",
					},
				},
			},
			"dbInfo": map[string]interface{}{
				"type":        "object",
				"description": "The data information being used.",
				"properties": map[string]interface{}{
					"username": map[string]interface{}{
						"type":        "string",
						"description": "DataBase Username.",
					},
					"password": map[string]interface{}{
						"type":        "string",
						"description": "DataBase Password.",
					},
					"Host": map[string]interface{}{
						"type":        "string",
						"description": "DataBase Host.",
					},
					"Base": map[string]interface{}{
						"type":        "string",
						"description": "DataBase Name.",
					},
				},
			},
			"routeInfo": map[string]interface{}{
				"type":        "array",
				"description": "Verified successful routing access methods, a list of actually accessible routes. For example: /index.php/API/login.",
				"items": map[string]interface{}{
					"type": "string",
				},
			},
		},
	}
}

func (h *EnvSaveTool) Execute(parameters map[string]interface{}) string {
	err := h.task.SaveEnvInfo(parameters)
	if err != nil {
		return Fail(err.Error())
	}
	return Success("saved")
}

//type EnvSaveRequest struct {
//	ContainerID string         `json:"containerId"`
//	LoginInfo   LoginInfo      `json:"loginInfo"`
//	DBInfo      []DatabaseInfo `json:"dbInfo"`
//}
//
//type LoginInfo struct {
//	Username string `json:"username"`
//	Password string `json:"password"`
//	LoginURL string `json:"loginURL"`
//	Cookie   string `json:"cookie,omitempty"`
//}
//
//type DatabaseInfo struct {
//	Username string `json:"username"`
//	Password string `json:"password"`
//	Host     string `json:"host"`
//	Base     string `json:"base"`
//}
