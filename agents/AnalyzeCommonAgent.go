package agents

import (
	"AIxVuln/llm"
	"AIxVuln/misc"
	"AIxVuln/taskManager"
	"AIxVuln/toolCalling"
	"context"
	"fmt"

	"github.com/google/uuid"
)

type AnalyzeCommonAgent struct {
	memory      llm.Memory
	client      *toolCalling.ToolManager
	task        *taskManager.Task
	id          string
	genReport   bool
	reportQueue chan taskManager.TaskData
}

func (c *AnalyzeCommonAgent) GetTask() *taskManager.Task {
	return c.task
}

func (c *AnalyzeCommonAgent) GetMemory() llm.Memory {
	return c.memory
}
func (c *AnalyzeCommonAgent) GetId() string {
	return c.id
}
func (c *AnalyzeCommonAgent) SetId(id string) {
	c.id = id
}
func (c *AnalyzeCommonAgent) GetVulnManager() *taskManager.VulnManager {
	return c.task.GetVulnManager()
}

func (c *AnalyzeCommonAgent) SetMemory(m llm.Memory) {
	c.memory = m
}
func (c *AnalyzeCommonAgent) SetEnvInfo(k map[string]interface{}) {
	c.task.SetEnvInfo(k)
}
func (c *AnalyzeCommonAgent) SetKeyMessage(k map[string][]interface{}) {
	c.memory.SetKeyMessage(k, c.task.GetTaskId())
}

func (c *AnalyzeCommonAgent) Description() string {
	return "This is a versatile code analysis assistant capable of performing vulnerability discovery and code analysis tasks, with support for multiple programming languages."
}

func NewAnalyzeCommonAgent(task *taskManager.Task, genReport bool) *AnalyzeCommonAgent {
	task.SetAgentName("AnalyzeCommonAgent")
	systemPrompt := `You are Vulnerability Analyst. 
Your job is to find and validate vulnerability candidates by reading code safely using A+ tools (search + targeted file reads).
Do NOT read the entire codebase. Start with ListSourceCodeTreeTool, then SearchFileContentsByRegexTool, then ReadLinesFromFileTool in small slices. 
Prefer evidence with file paths and line numbers. 
If you discover a vulnerability, you need to call the IssueVulnTool to record it.
If the project is developed based on a well-known framework, please do not analyze vulnerabilities within the framework, such as ThinkPHP, Yii, etc.
Only the ability to upload malicious content is not sufficient for a vulnerability submission if malicious code cannot be executed. For example: uploading a file while lacking control over its final extension does not constitute a valid vulnerability.
Many AI assistants are simultaneously pushing vulnerabilities to CANDIDATE_VULNS. You must pay attention to the key information in CANDIDATE_VULNS. When CANDIDATE_VULNS reaches the upper limit of %d vulnerabilities, you must stop working. When there are already 3 or more vulnerabilities of the same type  in CANDIDATE_VULNS, you must immediately stop mining vulnerabilities of that type.
When you believe no more harmful vulnerabilities can be discovered, or when **CANDIDATE_VULNS reaches the upper limit of %s vulnerabilities**, immediately stop the vulnerability discovery process.
`
	systemPrompt = fmt.Sprintf(systemPrompt, task.GetMaxVulnCount(), task.GetMaxVulnCount())
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
	client.Register(toolCalling.NewDetectLanguageTool(task))
	client.Register(toolCalling.NewListSourceCodeTreeTool(task))
	client.Register(toolCalling.NewSearchFileContentsByRegexTool(task))
	client.Register(toolCalling.NewReadLinesFromFileTool(task))
	client.Register(toolCalling.NewTaskListTool(task))
	client.Register(toolCalling.NewIssueVulnTool(task))
	client.Register(toolCalling.NewIssueTool(task))
	var agent AnalyzeCommonAgent
	if genReport {
		var taskQueue = make(chan taskManager.TaskData, 100)
		task.SetReportQueue(&taskQueue)
		agent = AnalyzeCommonAgent{memory: memory, client: client, task: task, genReport: genReport, reportQueue: taskQueue}
	} else {
		agent = AnalyzeCommonAgent{memory: memory, client: client, task: task, genReport: genReport}
	}

	agent.SetId(agent.Name() + "-" + uuid.New().String())

	return &agent
}

func (c *AnalyzeCommonAgent) StartTask(ctx context.Context) *StartResp {
	defer misc.Info(c.Name(), "Agent运行结束", c.task.GetEventHandler())
	if c.task.GetTaskList() == nil || len(c.task.GetTaskList()) == 0 {
		c.task.SetTaskList(misc.GetCommonAnalyzeTaskList(""))
	}

	if c.genReport {
		go func() {
			select {
			case <-ctx.Done():
				return
			default:
			}
			for taskData := range c.reportQueue {
				memory := llm.NewContextManager()
				memory.SetEventHandler(c.task.GetEventHandler())
				memory.SetMemory(taskData.HistoryMemory)
				v := taskManager.NewVulnManager()
				v.SetEventHandler(c.task.GetEventHandler())
				task := taskManager.NewTask(c.task.GetProjectDir(), misc.GetAnalyzeReportTaskList(taskData.Candidate), taskData.Sandbox, v, c.task.GetGoroutineChan(), c.task.GetProjectName())
				task.SetMemory(memory)
				task.SetCurrVulnId(taskData.VulnId)
				c.task.GetAddTaskHandler()(task)
				reportAgent := NewReportCommonAgent(task, "analyzer")
				task.AddGoroutine(func() {
					resp := reportAgent.StartTask(ctx)
					if resp != nil && resp.Err != nil {
						misc.Warn(reportAgent.Name(), "ReportAgent运行错误: "+resp.Err.Error(), c.task.GetEventHandler())
					}
				})
			}
		}()
	}

	model := misc.GetConfigValueDefault("analyze", "MODEL", misc.GetConfigValueRequired("main_setting", "MODEL"))
	for {
		select {
		case <-ctx.Done():
			return &StartResp{Err: ctx.Err()}
		default:
		}
		var eventLog string
		msgList := c.memory.GetContext(c.task.GetTaskId())
		assistantMessage, toolMessage, err := c.client.ToolCallRequest(misc.GetClient("analyze", "main_setting"), msgList, model, c.Name())
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
	resp := &StartResp{Err: nil, Memory: c.memory, Vuln: c.task.GetVulnList(), EvnInfo: c.task.GetEnvInfo()}
	return resp
}

func (c *AnalyzeCommonAgent) Name() string {
	return "AnalyzeCommonAgent"
}
