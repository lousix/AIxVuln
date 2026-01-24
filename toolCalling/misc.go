package toolCalling

import "encoding/json"

func Success(msg any) string {
	result := make(map[string]any)
	result["success"] = true
	result["result"] = msg
	result["error"] = ""
	js, _ := json.Marshal(result)
	return string(js)
}

func Fail(msg any) string {
	result := make(map[string]any)
	result["success"] = false
	result["result"] = ""
	result["error"] = msg
	js, _ := json.Marshal(result)
	return string(js)
}
