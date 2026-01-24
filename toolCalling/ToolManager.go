package toolCalling

import (
	"AIxVuln/misc"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/sashabaranov/go-openai"
)

var (
	MaxRequest    = misc.GetMaxRequest()
	semaphore     chan struct{}
	initSemaphore sync.Once
)

func init() {
	initSemaphore.Do(func() {
		semaphore = make(chan struct{}, MaxRequest)
	})
}

type ToolHandler interface {
	Name() string
	Description() string
	Parameters() map[string]interface{}
	Execute(args map[string]interface{}) string
}

type ToolManager struct {
	handlers      map[string]ToolHandler
	maxIterations int // 每次最大调用函数数量限制
}

func NewToolManager() *ToolManager {
	return &ToolManager{
		handlers:      make(map[string]ToolHandler),
		maxIterations: 10,
	}
}

func (fm *ToolManager) Register(handler ToolHandler) {
	fm.handlers[handler.Name()] = handler
}

func (fm *ToolManager) GetTools() []openai.Tool {
	var definitions []openai.Tool
	for _, handler := range fm.handlers {
		definitions = append(definitions, openai.Tool{
			Type: openai.ToolTypeFunction,
			Function: &openai.FunctionDefinition{
				Name:        handler.Name(),
				Description: handler.Description(),
				Parameters:  handler.Parameters(),
			},
		})
	}
	return definitions
}

// return Assistant Content、tool Result、error
func (fm *ToolManager) ToolCallRequest(
	cli *openai.Client,
	messages []openai.ChatCompletionMessage,
	model string,
	agentName string,
) (openai.ChatCompletionMessage, []openai.ChatCompletionMessage, error) {
	// 获取并发许可
	semaphore <- struct{}{}
	defer func() {
		<-semaphore // 释放许可
	}()

	tools := fm.GetTools()
	count := 0
	var resp openai.ChatCompletionResponse
	var err error
	for {
		ctx, c := context.WithTimeout(context.Background(), time.Duration(600)*time.Second)
		defer c()
		size := 0
		for _, v := range messages {
			d, _ := v.MarshalJSON()
			size += len(d)
		}
		resp, err = cli.CreateChatCompletion(
			ctx,
			openai.ChatCompletionRequest{
				Model:    model,
				Messages: messages,
				Tools:    tools,
			},
		)
		if err == nil || count >= misc.GetMaxTryCount() {
			break
		}
		time.Sleep(time.Duration(5) * time.Second)
		count++
	}
	if err != nil {
		return openai.ChatCompletionMessage{}, []openai.ChatCompletionMessage{}, err
	}
	if len(resp.Choices) == 0 {
		fmt.Println("No choices found")
		return openai.ChatCompletionMessage{}, []openai.ChatCompletionMessage{}, fmt.Errorf("空的助手回复")
	}
	choice := resp.Choices[0]
	message := choice.Message
	var toolMessage []openai.ChatCompletionMessage
	for _, toolCall := range message.ToolCalls {
		if toolCall.Type != openai.ToolTypeFunction {
			continue
		}
		handler, exists := fm.handlers[toolCall.Function.Name]
		if !exists {
			toolMessage = append(toolMessage, openai.ChatCompletionMessage{
				Role:       openai.ChatMessageRoleTool,
				Content:    Fail(fmt.Sprintf("%s is not registered", toolCall.Function.Name)),
				ToolCallID: toolCall.ID,
			})
			continue
		}

		// 解析参数
		var args map[string]interface{}
		if err := json.Unmarshal([]byte(toolCall.Function.Arguments), &args); err != nil {
			toolMessage = append(toolMessage, openai.ChatCompletionMessage{
				Role:       openai.ChatMessageRoleTool,
				Content:    Fail("parse arguments failed"),
				ToolCallID: toolCall.ID,
			})
			continue
		}
		resultJSON := handler.Execute(args)
		toolMessage = append(toolMessage, openai.ChatCompletionMessage{
			Role:       openai.ChatMessageRoleTool,
			Content:    resultJSON,
			ToolCallID: toolCall.ID,
		})
	}
	return message, toolMessage, nil
}
