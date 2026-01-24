package agents

import (
	"AIxVuln/llm"
	"AIxVuln/misc"
	"AIxVuln/taskManager"
	"AIxVuln/toolCalling"
	"context"

	"github.com/google/uuid"
)

type OpsCommonAgent struct {
	memory llm.Memory
	client *toolCalling.ToolManager
	task   *taskManager.Task
	id     string
}

func (c *OpsCommonAgent) GetTask() *taskManager.Task {
	return c.task
}

func (c *OpsCommonAgent) GetMemory() llm.Memory {
	return c.memory
}
func (c *OpsCommonAgent) GetId() string {
	return c.id
}
func (c *OpsCommonAgent) SetId(id string) {
	c.id = id
}
func (c *OpsCommonAgent) GetVulnManager() *taskManager.VulnManager {
	return c.task.GetVulnManager()
}

func (c *OpsCommonAgent) SetMemory(m llm.Memory) {
	c.memory = m
}
func (c *OpsCommonAgent) SetKeyMessage(k map[string][]interface{}) {
	c.memory.SetKeyMessage(k, c.task.GetTaskId())
}
func (c *OpsCommonAgent) SetEnvInfo(k map[string]interface{}) {
	c.task.SetEnvInfo(k)
}
func (c *OpsCommonAgent) Description() string {
	return "This is a general-purpose ops intelligent agent capable of setting up environments and performing operational tasks in multiple languages."
}

func NewOpsCommonAgent(task *taskManager.Task) *OpsCommonAgent {
	task.SetAgentName("OpsCommonAgent")
	systemPrompt := `You are an operation and maintenance AI assistant, tasked with utilizing various tools for vulnerability mining, specifically for setting up and maintaining the target environment. First, you need to detect the programming language of the project source code and then choose the appropriate environment to set it up. For setup tasks, the requirements are as follows:
If there are middleware configuration files, such as .user.ini, .htaccess, etc., the relevant functionality must be enabled to ensure support for these configurations.
Direct execution of Docker commands is not allowed. All operations must be performed through DockerxxxTool. The /sourceCodeDir directory is shared among all containers. To transfer files between containers, simply copy the files to /sourceCodeDir.
When setting up a PHP system, first start the web service and try accessing it to see if the database, administrator username, password, and other configurations can be completed directly via the installation guide on the web page. If there is no installation guide, manually configure this information. 
For tools that require the webPort parameter, you must first confirm which port the web service is running on before passing it in. The PHP environment uses Apache2, which defaults to port 80. You may not use this default port, but after passing the specified webPort, you must configure it to the port number designated by webPort.
When encountering compatibility issues where the environment version does not support the project, do not attempt to modify the source code. Instead, promptly switch to a compatible environment version. For example, if PHP7 is started but the project contains syntax not supported by PHP7, decisively launch a new environment with the specified required version.When you start a new container due to version switching, if the old container is no longer in use, you need to call DockerRemoveTool to delete the old container.
Do not insert any data into MySQL for initialization unless you have repeatedly attempted and confirmed that the system installation cannot proceed via the web interface.
If you need to execute commands in the environment started by RunxxxEnvTool, you must use DockerExecTool instead of RunCommandTool. Although their /sourceCodeDir directories are mutually mapped, they do not run in the same container.
When calling EnvSaveTool, all URL and IP information must not use 127.0.0.1, localhost, etc., but rather the real WEB environment container IP.
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
	client.Register(toolCalling.NewRunCommandTool(task))
	client.Register(toolCalling.NewDetectLanguageTool(task))
	client.Register(toolCalling.NewDockerRunTool(task))
	//client.Register(toolCalling.NewDockerPsTool(task))
	client.Register(toolCalling.NewDockerLogsTool(task))
	client.Register(toolCalling.NewDockerRemoveTool(task))
	client.Register(toolCalling.NewDockerExecTool(task))
	client.Register(toolCalling.NewEnvSaveTool(task))
	client.Register(toolCalling.NewRunSQLTool(task))
	client.Register(toolCalling.NewJavaEnvTool(task))
	client.Register(toolCalling.NewPHPEnvTool(task))
	client.Register(toolCalling.NewNodeEnvTool(task))
	client.Register(toolCalling.NewPythonEnvTool(task))
	client.Register(toolCalling.NewGolangEnvTool(task))
	client.Register(toolCalling.NewMySQLEnvTool(task))
	client.Register(toolCalling.NewRedisEnvTool(task))
	client.Register(toolCalling.NewListSourceCodeTreeTool(task))
	client.Register(toolCalling.NewSearchFileContentsByRegexTool(task))
	client.Register(toolCalling.NewReadLinesFromFileTool(task))
	client.Register(toolCalling.NewTaskListTool(task))
	client.Register(toolCalling.NewIssueTool(task))
	agent := OpsCommonAgent{memory: memory, client: client, task: task}
	agent.SetId(agent.Name() + "-" + uuid.New().String())
	return &agent
}

func (c *OpsCommonAgent) StartTask(ctx context.Context) *StartResp {
	defer misc.Info(c.Name(), "Agent运行结束", c.task.GetEventHandler())
	if c.task.GetTaskList() == nil || len(c.task.GetTaskList()) == 0 {
		c.task.SetTaskList(misc.GetCommonOpsTaskList())
	}
	model := misc.GetConfigValueDefault("ops", "MODEL", misc.GetConfigValueRequired("main_setting", "MODEL"))
	for {
		select {
		case <-ctx.Done():
			return &StartResp{Err: ctx.Err()}
		default:
		}
		var eventLog string
		msgList := c.memory.GetContext(c.task.GetTaskId())
		assistantMessage, toolMessage, err := c.client.ToolCallRequest(misc.GetClient("ops", "main_setting"), msgList, model, c.Name())
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

func (c *OpsCommonAgent) Name() string {
	return "OpsCommonAgent"
}
