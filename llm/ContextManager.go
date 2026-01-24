package llm

import (
	"AIxVuln/misc"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/sashabaranov/go-openai"
)

type ContextManager struct {
	systemPrompt string
	memory       []openai.ChatCompletionMessage
	mu           sync.RWMutex
	envMessage   map[string][]interface{} // 重要的信息，这个信息永远不会被覆盖
	maxHistory   int                      // 历史对话记录最大字节数
	taskList     []map[string]string
	eventHandler func(string, string, int)
}

func NewContextManager() *ContextManager {
	return &ContextManager{
		memory:     make([]openai.ChatCompletionMessage, 0),
		maxHistory: misc.GetMaxHistory(),
		envMessage: make(map[string][]interface{}),
	}
}
func (cm *ContextManager) AddContextManager(id string, contextManager *ContextManager) {

}
func (cm *ContextManager) SaveMemoryToFile(filename string) error {
	memoryInfoJson, _ := json.Marshal(cm)
	err := os.WriteFile(filename, memoryInfoJson, 0644)
	return err
}

func (cm *ContextManager) SetEventHandler(f func(string, string, int)) {
	cm.eventHandler = f
}

// TODO
//func (cm *ContextManager) LoadMemoryByFile(filename string) error {
//	content, err := ioutil.ReadFile(filename)
//	if err != nil {
//		return err
//	}
//	err = json.Unmarshal(content, &cm)
//	if err != nil {
//		return err
//	}
//	return nil
//}

func (cm *ContextManager) SetMemory(memory []openai.ChatCompletionMessage) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.memory = memory
}
func (cm *ContextManager) SetKeyMessage(env map[string][]interface{}, id string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.envMessage = env
}
func (cm *ContextManager) GetKeyMessage(id string) map[string][]interface{} {
	return cm.envMessage
}

// 清除历史记忆，但是保留关键信息
func (cm *ContextManager) ClearMemory() {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.memory = make([]openai.ChatCompletionMessage, 0)
}

func (cm *ContextManager) GetType() string {
	return "ContextManager"
}

func (cm *ContextManager) AddMessage(x *MessageX) {
	if len(x.Msg.Content) > misc.GetMessageMaximum() {
		x.Msg.Content = x.Msg.Content[:misc.GetMessageMaximum()] + " ...... (The text exceeds the maximum length of " + strconv.Itoa(misc.GetMessageMaximum()) + " characters and cannot be sent to the LLM—)."
	}
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.memory = append(cm.memory, x.Msg)
	if x.Msg.Role == openai.ChatMessageRoleTool {
		// 将tool历史消息截断保存
		cm.trimOldToolMessagesOptimized()
	}

	if cm.GetContentSize(0) > cm.maxHistory {
		i := 1
		for {
			cSize := cm.GetContentSize(i)
			if cSize <= cm.maxHistory {
				cm.memory = cm.memory[i:]
				break
			}
			i++
		}
	}

}

func (cm *ContextManager) GetContentSize(start int) int {
	js, _ := json.Marshal(cm.memory[start:])
	return len(js)
}

func (cm *ContextManager) SetTaskList(x *TaskListX) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.taskList = x.TaskList
}

func (cm *ContextManager) AddKeyMessage(x *EnvMessageX) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if x.AppendEnv {
		existing, exists := cm.envMessage[x.Key]
		if !exists {
			cm.envMessage[x.Key] = []interface{}{x.Content}
		}
		cm.envMessage[x.Key] = append(existing, x.Content)
	} else {
		cm.envMessage[x.Key] = []interface{}{x.Content}
	}
	if !x.Submit {
		cm.eventHandler("记忆体", x.jsonEncode(), 0)
		x.Submit = true
	}
}

func (cm *ContextManager) SetSystemPrompt(x *SystemPromptX) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.systemPrompt = x.SystemPrompt
}

func (cm *ContextManager) GetContext(id string) []openai.ChatCompletionMessage {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	if len(cm.systemPrompt) == 0 {
		log.Fatal("系统提示词不能为空")
	}
	messages := make([]openai.ChatCompletionMessage, 0, len(cm.memory)+3)
	messages = append(messages, openai.ChatCompletionMessage{
		Role:    openai.ChatMessageRoleSystem,
		Content: cm.systemPrompt,
	})
	userPrompt := ""
	if cm.taskList != nil {
		if len(cm.taskList) == 1 {
			js1, _ := json.Marshal(cm.envMessage)
			userPrompt = (cm.taskList)[0]["TaskContent"] + "\nthis is the recorded useful information: \n" + string(js1)
		} else {
			js, _ := json.Marshal(cm.taskList)
			js1, _ := json.Marshal(cm.envMessage)
			userPrompt = "The current subtask list and their statuses are as follows: \n" + string(js) + "\nYou need to call the TaskListTool to confirm after completing or discarding each subtask, after which the subtask list will automatically update.\nthis is the recorded useful information: \n" + string(js1)
		}
	} else {
		log.Fatal("未设置Agent任务")
	}
	messages = append(messages, openai.ChatCompletionMessage{
		Role:    openai.ChatMessageRoleUser,
		Content: userPrompt,
	})
	messages = append(messages, cm.memory...)
	return messages
}

func (cm *ContextManager) trimOldToolMessagesOptimized() {
	toolCount := 0
	var thirdLastToolIdx int = -1
	for i := len(cm.memory) - 1; i >= 0; i-- {
		if cm.memory[i].Role == openai.ChatMessageRoleTool {
			toolCount++
			if toolCount == 3 {
				thirdLastToolIdx = i
				break
			}
		}
	}
	if thirdLastToolIdx >= 0 && len(cm.memory[thirdLastToolIdx].Content) > 512 {
		cm.memory[thirdLastToolIdx].Content = cm.truncateToolContent(cm.memory[thirdLastToolIdx].Content, 512)
	}
}
func (cm *ContextManager) truncateToolContent(content string, maxLength int) string {
	if len(content) <= maxLength {
		return content
	}
	// 尝试在合适的位置截断
	truncated := content[:maxLength]

	// 如果不是在标点符号结束，尝试找到最近的结束位置
	if !isNaturalEnd(truncated) {
		// 查找最近的标点符号
		if lastPunc := findLastPunctuation(content[:maxLength]); lastPunc > maxLength/2 {
			truncated = content[:lastPunc]
		}
		// 或者查找最近的空格
		if lastSpace := strings.LastIndex(content[:maxLength], " "); lastSpace > maxLength/2 {
			truncated = content[:lastSpace]
		}
	}

	return truncated + fmt.Sprintf(" ... [Historical message truncated, original length %d]", len(content))
}
func isNaturalEnd(s string) bool {
	if len(s) == 0 {
		return true
	}

	lastChar := s[len(s)-1]
	naturalEnds := []byte{'.', '!', '?', '}', ']', '"', '\'', '\n'}

	for _, ch := range naturalEnds {
		if lastChar == ch {
			return true
		}
	}

	return false
}
func findLastPunctuation(s string) int {
	punctuations := []string{". ", "! ", "? ", "\n", "}\n", "]\n", ", ", "; ", ":\n"}

	maxPos := -1
	for _, punc := range punctuations {
		if pos := strings.LastIndex(s, punc); pos > maxPos {
			maxPos = pos + len(punc) - 1
		}
	}

	return maxPos
}
