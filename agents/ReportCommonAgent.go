package agents

import (
	"AIxVuln/llm"
	"AIxVuln/misc"
	"AIxVuln/taskManager"
	"AIxVuln/toolCalling"
	"context"

	"github.com/google/uuid"
)

type ReportCommonAgent struct {
	memory llm.Memory
	client *toolCalling.ToolManager
	task   *taskManager.Task
	id     string
}

func (c *ReportCommonAgent) GetTask() *taskManager.Task {
	return c.task
}

func (c *ReportCommonAgent) GetMemory() llm.Memory {
	return c.memory
}
func (c *ReportCommonAgent) GetId() string {
	return c.id
}
func (c *ReportCommonAgent) SetId(id string) {
	c.id = id
}
func (c *ReportCommonAgent) GetVulnManager() *taskManager.VulnManager {
	return c.task.GetVulnManager()
}
func (c *ReportCommonAgent) SetKeyMessage(k map[string][]interface{}) {
	c.memory.SetKeyMessage(k, c.task.GetTaskId())
}

func (c *ReportCommonAgent) SetMemory(m llm.Memory) {
	c.memory = m
}
func (c *ReportCommonAgent) SetEnvInfo(k map[string]interface{}) {
	c.task.SetEnvInfo(k)
}
func (c *ReportCommonAgent) Description() string {
	return "This is an AI assistant designed for writing vulnerability reports."
}

func NewReportCommonAgent(task *taskManager.Task, reportType string) *ReportCommonAgent {
	task.SetAgentName("ReportCommonAgent")
	var systemPrompt string
	if reportType == "verifier" {
		systemPrompt = `You are an AI assistant for writing vulnerability reports. Your task is to generate accurate reports based on provided report templates and key data.
You can use various tools to read and analyze source code, identify the taint propagation chain from user interaction points to vulnerability trigger points, and write it out as a report in the vulnerability details section.
Require runtime evidence to provide detailed and compelling proof of the vulnerability's existence. If the given runtime evidence is insufficient or not "conclusive enough," you may conduct further testing and evidence collection on the runtime environment independently.
Once the report is written, you can submit it using the ReportVulnTool.
The report template is as follows:
# 厂商信息
- **漏洞厂商**：
- **厂商官网**：
- **影响产品**：
- **影响版本**：
# 漏洞信息
- **漏洞名称**：
- **漏洞描述**：
- **临时解决方案**：
- **正式修复建议**：
# 漏洞分析
## 漏洞触发点
## 完整利用链分析
## 验证环境与运行证据
## HTTP请求与响应包（可选）
## POC
## POC运行结果
`
	} else if reportType == "analyzer" {
		systemPrompt = `You are an AI assistant for writing vulnerability reports. Your task is to generate accurate reports based on provided report templates and key data.
You can use various tools to read and analyze source code, identify the taint propagation chain from user interaction points to vulnerability trigger points, and write it out as a report in the vulnerability details section.
Once the report is written, you can submit it using the ReportVulnTool.
The report template is as follows:
# 漏洞信息
- **漏洞名称**：
- **漏洞描述**：
# 漏洞分析
## 漏洞触发点
## 完整利用链分析
## 验证方式
`
	}

	systemPrompt += CommonSystemPrompt()
	var memory llm.Memory
	if task.GetMemory() == nil {
		memory = llm.NewContextManager()
		memory.SetEventHandler(task.GetEventHandler())
		task.SetMemory(memory) // 不设置记忆体的话Agent将在超出历史记录限制之后不记得启动过的环境信息
	} else {
		memory = task.GetMemory()
	}
	memory.SetSystemPrompt(&llm.SystemPromptX{SystemPrompt: systemPrompt, ContextId: task.GetTaskId()})
	client := toolCalling.NewToolManager()
	client.Register(toolCalling.NewListSourceCodeTreeTool(task))
	client.Register(toolCalling.NewSearchFileContentsByRegexTool(task))
	client.Register(toolCalling.NewReadLinesFromFileTool(task))
	client.Register(toolCalling.NewIssueTool(task))
	client.Register(toolCalling.NewReportVulnTool(task))
	if reportType == "verifier" {
		client.Register(toolCalling.NewDockerLogsTool(task))
		client.Register(toolCalling.NewRunPythonCodeTool(task))
		client.Register(toolCalling.NewRunPHPCodeTool(task))
		client.Register(toolCalling.NewRunCommandTool(task))
		client.Register(toolCalling.NewDockerFileReadTool(task))
		client.Register(toolCalling.NewDockerDirScanTool(task))
		client.Register(toolCalling.NewRunSQLTool(task))
	}
	agent := ReportCommonAgent{memory: memory, client: client, task: task}
	agent.SetId(agent.Name() + "-" + uuid.New().String())
	return &agent
}

func (c *ReportCommonAgent) StartTask(ctx context.Context) *StartResp {
	defer misc.Info(c.Name(), "Agent运行结束", c.task.GetEventHandler())
	if c.task.GetTaskList() == nil || len(c.task.GetTaskList()) == 0 {
		misc.Error("ReportAgent", "必须设置任务", c.task.GetEventHandler())
	}
	model := misc.GetConfigValueDefault("report", "MODEL", misc.GetConfigValueRequired("main_setting", "MODEL"))
	for {
		select {
		case <-ctx.Done():
			return &StartResp{Err: ctx.Err()}
		default:
		}
		var eventLog string
		msgList := c.memory.GetContext(c.task.GetTaskId())
		assistantMessage, toolMessage, err := c.client.ToolCallRequest(misc.GetClient("report", "main_setting"), msgList, model, c.Name())
		if err != nil {
			return &StartResp{Err: err}
		}
		eventLog = eventLog + "assistant: " + assistantMessage.Content + "\n"
		var index = 0
		if len(assistantMessage.ToolCalls) > 0 {
			for _, tool := range assistantMessage.ToolCalls {
				eventLog = eventLog + "ToolCalling: " + tool.Function.Name + " args: " + tool.Function.Arguments + "\n"
				eventLog = eventLog + "ToolResult: " + toolMessage[index].Content + "\n"
			}
		}
		_ = c.task.EventLog(eventLog)
		msg := &llm.MessageX{Msg: assistantMessage, Shared: false, ContextId: c.task.GetTaskId()}
		c.memory.AddMessage(msg)
		if len(toolMessage) > 0 {
			for _, message := range toolMessage {
				msgTool := &llm.MessageX{Msg: message, Shared: false, ContextId: c.task.GetTaskId()}
				c.memory.AddMessage(msgTool)
			}
		} else {
			break
		}
	}
	return &StartResp{Err: nil, Memory: c.memory, Vuln: c.task.GetVulnList(), EvnInfo: c.task.GetEnvInfo()}
}

func (c *ReportCommonAgent) Name() string {
	return "ReportCommonAgent"
}
