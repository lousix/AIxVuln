package agents

import (
	"AIxVuln/llm"
	"AIxVuln/misc"
	"AIxVuln/taskManager"
	"AIxVuln/toolCalling"
	"context"
	"encoding/json"

	"github.com/google/uuid"
)

type VerifierCommonAgent struct {
	memory      llm.Memory
	client      *toolCalling.ToolManager
	task        *taskManager.Task
	reportQueue chan taskManager.TaskData
	id          string
}

func (c *VerifierCommonAgent) GetTask() *taskManager.Task {
	return c.task
}

func (c *VerifierCommonAgent) GetMemory() llm.Memory {
	return c.memory
}
func (c *VerifierCommonAgent) GetId() string {
	return c.id
}
func (c *VerifierCommonAgent) SetId(id string) {
	c.id = id
}
func (c *VerifierCommonAgent) GetVulnManager() *taskManager.VulnManager {
	return c.task.GetVulnManager()
}
func (c *VerifierCommonAgent) SetEnvInfo(k map[string]interface{}) {
	c.task.SetEnvInfo(k)
}
func (c *VerifierCommonAgent) SetMemory(m llm.Memory) {
	c.memory = m
}

func (c *VerifierCommonAgent) SetKeyMessage(k map[string][]interface{}) {
	c.memory.SetKeyMessage(k, c.task.GetTaskId())
}

func (c *VerifierCommonAgent) Description() string {
	return "This is a versatile vulnerability verification assistant capable of performing vulnerability verification tasks, supporting multiple languages, but the environment must already be set up and vulnerability analysis/discovery results must exist in memory."
}

func NewVerifierCommonAgent(task *taskManager.Task) *VerifierCommonAgent {
	var taskQueue = make(chan taskManager.TaskData, 100)
	task.SetReportQueue(&taskQueue)
	task.SetAgentName("VerifierCommonAgent")
	systemPrompt := `Your job is to verify whether the vulnerability candidates are truly exploitable, and provide a concrete PoC with clear steps and expected results.
CRITICAL VERIFIED GATE: You MUST NOT mark a candidate as VERIFIED based only on static code reasoning.
The actual environment validation target is the loginInfo part of the key information. It uses the database information from the dbInfo part. You can read the content in the database through the RunSQLTool, but you cannot perform any write operations.
The user will specify the vulnerability that currently needs to be verified by you. You need to focus on the verification work for this vulnerability.
For multi-step or complex requests, do not use curl; instead, use the RunPythonCodeTool to complete them. Requests has already been installed.
After completing vulnerability verification (whether successful or not), you need to:
- Collect runtime evidence (Write in Chinese using Markdown, as detailed as possible.), including comprehensive HTTP request packets and actual target HTTP response packets.
- Write a Python attack script.
- Call the SubmitVulnTool and pass both the runtime evidence and the attack script as parameters. This tool will either return a new vulnerability for verification or issue a task termination instruction. If a new vulnerability is returned, you must continue with the verification process.
SubmitVulnTool Acceptable proof includes: exact HTTP request URL + status code + key response headers + a minimal response body excerpt showing impact; OR exact PoC stdout/stderr containing a unique marker; OR relevant server log excerpt correlating with the exploit attempt. 
Mandatory requirement: As a verifier, you must not modify any content within the /sourceCodeDir.
Auth/cookie reuse: If loginInfo contains a valid post-login session cookie for admin, you SHOULD reuse it for admin-only endpoints (send it as a Cookie header) instead of trying to re-login. "
Env/routing reuse: If routeInfo contains routing rules and working URL examples, you MUST reuse those URLs/rules for requests instead of guessing routes. "
You no longer need to discover any new vulnerabilities, just verify the specified ones.
If you need to check the logs in the target container, you can use DockerDirScanTool to list the files and then use DockerFileReadTool to read the log files.
Conclusive evidence of a vulnerability's existence is required. Methods such as simulating SQL execution, simulating code execution, speculating on the existence of a vulnerability, or confirming a vulnerability solely through code analysis should absolutely not be considered as evidence of a vulnerability's existence. If no feasible method is available to obtain evidence of the vulnerability's existence, it may be submitted as a failed vulnerability verification.
` + CommonSystemPrompt()
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
	client.Register(toolCalling.NewRunCommandTool(task))
	client.Register(toolCalling.NewSubmitVulnTool(task))
	client.Register(toolCalling.NewRunPythonCodeTool(task))
	client.Register(toolCalling.NewRunPHPCodeTool(task))
	client.Register(toolCalling.NewRunSQLTool(task))
	client.Register(toolCalling.NewDockerLogsTool(task))
	client.Register(toolCalling.NewDockerDirScanTool(task))
	client.Register(toolCalling.NewDockerFileReadTool(task))
	client.Register(toolCalling.NewIssueTool(task))
	agent := VerifierCommonAgent{memory: memory, client: client, task: task, reportQueue: taskQueue}
	agent.SetId(agent.Name() + "-" + uuid.New().String())
	return &agent
}

func (c *VerifierCommonAgent) StartTask(ctx context.Context) *StartResp {
	defer misc.Info(c.Name(), "Agent运行结束", c.task.GetEventHandler())
	if c.task.GetTaskList() == nil || len(c.task.GetTaskList()) == 0 {
		r, e := c.task.GetVulnManager().GetOneCandidate()
		var res any
		if e != nil {
			res = e
		} else {
			res = r
		}
		js, _ := json.Marshal(res)
		c.task.SetTaskList(misc.GetCommonVerifierTaskList(string(js)))
	}
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
			task := taskManager.NewTask(c.task.GetProjectDir(), misc.GetCommonReportTaskList(taskData.Evidence, taskData.POC), taskData.Sandbox, v, c.task.GetGoroutineChan(), c.task.GetProjectName())
			task.SetMemory(memory)
			c.task.GetAddTaskHandler()(task)
			task.SetCurrVulnId(taskData.VulnId)
			task.AddEnvMessage("RuntimeEnvironment", taskData.EnvInfo, false)
			reportAgent := NewReportCommonAgent(task, "verifier")
			task.AddGoroutine(func() {
				resp := reportAgent.StartTask(ctx)
				if resp != nil && resp.Err != nil {
					misc.Warn(reportAgent.Name(), "ReportAgent运行错误: "+resp.Err.Error(), c.task.GetEventHandler())
				}
			})
		}
	}()
	model := misc.GetConfigValueDefault("verifier", "MODEL", misc.GetConfigValueRequired("main_setting", "MODEL"))

	for {
		select {
		case <-ctx.Done():
			return &StartResp{Err: ctx.Err()}
		default:
		}
		var eventLog string
		msgList := c.memory.GetContext(c.task.GetTaskId())
		assistantMessage, toolMessage, err := c.client.ToolCallRequest(misc.GetClient("verifier", "main_setting"), msgList, model, c.Name())
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

func (c *VerifierCommonAgent) Name() string {
	return "VerifierCommonAgent"
}
