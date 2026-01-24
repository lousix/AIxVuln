package llm

import (
	"encoding/json"

	"github.com/sashabaranov/go-openai"
)

type Memory interface {
	AddMessage(x *MessageX)
	SetTaskList(x *TaskListX)
	AddKeyMessage(x *EnvMessageX)
	SetKeyMessage(map[string][]interface{}, string)
	GetKeyMessage(string) map[string][]interface{}
	SetSystemPrompt(x *SystemPromptX)
	GetContext(x string) []openai.ChatCompletionMessage
	GetType() string
	AddContextManager(id string, contextManager *ContextManager)
	SetEventHandler(f func(string, string, int))
}

type MessageX struct {
	Msg       openai.ChatCompletionMessage
	Shared    bool
	ContextId string
}

type TaskListX struct {
	TaskList  []map[string]string
	ContextId string
}
type EnvMessageX struct {
	Key       string `json:"key"`
	Content   any    `json:"content"`
	AppendEnv bool   `json:"-"`
	ContextId string `json:"contextId"`
	NotShared bool   `json:"-"` //设置为False则不跟其它agent共享
	Submit    bool   `json:"-"`
}

func (ex *EnvMessageX) jsonEncode() string {
	js, _ := json.MarshalIndent(ex, "", "  ")
	return string(js)
}

type SystemPromptX struct {
	SystemPrompt string
	ContextId    string
}
