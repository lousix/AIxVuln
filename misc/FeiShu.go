package misc

import (
	"bytes"
	"encoding/json"
	"net/http"
)

func FeiShuSendText(text string) {
	api := GetFeiShuAPI()
	if api == "" {
		return
	}
	data := make(map[string]interface{})
	data["msg_type"] = "text"
	data["content"] = map[string]string{"text": text}
	jsonByte, _ := json.Marshal(data)
	resp, err := http.Post(api, "application/json", bytes.NewBuffer(jsonByte))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
}
