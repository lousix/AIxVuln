package llm

import (
	"AIxVuln/misc"
	"log"
	"strings"
	"sync"

	"github.com/sashabaranov/go-openai"
)

// 用于多个Agent同时运行，既能保证单个Agent上下文不被污染，又能保证关键信息共享，并且允许同时为多个Agent的上下文添加重要记忆点
type SharedContext struct {
	Contexts     map[string]*ContextManager
	mu           sync.Mutex
	eventHandler func(string, string, int)
}

func NewSharedContext() *SharedContext {
	return &SharedContext{Contexts: make(map[string]*ContextManager)}
}
func (cm *SharedContext) AddContextManager(id string, contextManager *ContextManager) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if cm.eventHandler != nil {
		contextManager.SetEventHandler(cm.eventHandler)
	}
	cm.Contexts[id] = contextManager
}

// TODO
//func (cm *SharedContext) SaveMemoryToFile(filename string) error {
//	memoryInfoJson, _ := json.Marshal(cm)
//	err := os.WriteFile(filename, memoryInfoJson, 0644)
//	return err
//}
//
//func (cm *SharedContext) LoadMemoryByFile(filename string) error {
//	content, err := os.ReadFile(filename)
//	if err != nil {
//		return err
//	}
//	err = json.Unmarshal(content, &cm)
//	if err != nil {
//		return err
//	}
//	return nil
//}

func (cm *SharedContext) SetEventHandler(f func(string, string, int)) {
	cm.eventHandler = f
}

func (cm *SharedContext) SetKeyMessage(env map[string][]interface{}, id string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	c, e := cm.Contexts[id]
	if e {
		c.SetKeyMessage(env, id)
	} else {
		for _, contextManager := range cm.Contexts {
			contextManager.SetKeyMessage(env, id)
		}
	}
}

func (cm *SharedContext) GetKeyMessage(id string) map[string][]interface{} {
	c, e := cm.Contexts[id]
	if e {
		return c.GetKeyMessage(id)
	} else {
		for _, contextManager := range cm.Contexts {
			return contextManager.GetKeyMessage(id)
		}
	}
	return nil
}

func (cm *SharedContext) GetType() string {
	return "SharedContext"
}

func (cm *SharedContext) AddMessage(x *MessageX) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if x.Shared {
		for _, context := range cm.Contexts {
			context.AddMessage(x)
		}
	} else {
		c, f := cm.Contexts[x.ContextId]
		if !f {
			log.Fatal("Context not found in contextManager")
		}
		c.AddMessage(x)
		if x.Msg.Role == openai.ChatMessageRoleAssistant {
			content := x.Msg.Content
			line := strings.TrimSpace(getLastLine(content))
			if strings.HasPrefix(line, "SharedMessage:") {
				msgC := "SharedMessage from other AI assistants: " + strings.TrimPrefix(line, "SharedMessage:")
				misc.Success("Agent重点记忆共享", msgC, cm.eventHandler)
				msg := openai.ChatCompletionMessage{Role: openai.ChatMessageRoleAssistant, Content: msgC}
				for id, context := range cm.Contexts {
					if id != x.ContextId {
						msgX := &MessageX{
							ContextId: x.ContextId,
							Msg:       msg,
						}
						context.AddMessage(msgX)
					}
				}

			}

		}
	}

}

func (cm *SharedContext) SetTaskList(x *TaskListX) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	c, f := cm.Contexts[x.ContextId]
	if !f {
		log.Fatal("Context not found in contextManager")
	}
	c.SetTaskList(x)
}

func (cm *SharedContext) AddKeyMessage(x *EnvMessageX) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if x.NotShared {
		c, f := cm.Contexts[x.ContextId]
		if !f {
			log.Fatal("Context not found in contextManager")
		}
		c.AddKeyMessage(x)
	} else {
		for _, context := range cm.Contexts {
			context.AddKeyMessage(x)
		}
	}
	if !x.Submit {
		cm.eventHandler("记忆体", x.jsonEncode(), 0)
		x.Submit = true
	}
}

func (cm *SharedContext) SetSystemPrompt(x *SystemPromptX) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	c, f := cm.Contexts[x.ContextId]
	if !f {
		log.Fatal("Context not found in contextManager")
	}
	x.SystemPrompt = x.SystemPrompt + "\nImportant reminder: There are multiple AI assistants performing the same tasks as you. If you believe you have discovered important information, end your reply with exactly one line starting with 'SharedMessage:' followed by your message on the same line. If there is no important information, avoid ending your last line with 'SharedMessage:'."
	c.SetSystemPrompt(x)
}

func (cm *SharedContext) GetContext(id string) []openai.ChatCompletionMessage {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	c, f := cm.Contexts[id]
	if !f {
		log.Fatal("Context not found in contextManager")
	}
	return c.GetContext(id)
}

func getLastLine(text string) string {
	lines := strings.FieldsFunc(text, func(r rune) bool {
		return r == '\n' || r == '\r'
	})

	if len(lines) == 0 {
		return ""
	}

	return lines[len(lines)-1]
}
