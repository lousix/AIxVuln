package agents

import (
	"AIxVuln/llm"
	"AIxVuln/misc"
	"AIxVuln/taskManager"
	"AIxVuln/toolCalling"
	"context"
	"encoding/json"
	"strings"
)

// debugLastMessages prints the last 2 messages from the context before an LLM request.
func debugLastMessages(personaName string, msgList []llm.Message) {
	start := len(msgList) - 2
	if start < 0 {
		start = 0
	}
	for i := start; i < len(msgList); i++ {
		content := msgList[i].Content
		if len([]rune(content)) > 30 {
			content = string([]rune(content)[:30]) + "..."
		}
		misc.Debug("[%s] ctx[%d] %s: %s", personaName, i, msgList[i].Role, content)
	}
}

// extractAgentFinishSummary checks if any tool message contains the AgentFinishMarker.
// Returns (summary, true) if found, ("", false) otherwise.
func extractAgentFinishSummary(toolMessages []llm.Message) (string, bool) {
	for _, tm := range toolMessages {
		if strings.HasPrefix(tm.Content, toolCalling.AgentFinishMarker) {
			return strings.TrimPrefix(tm.Content, toolCalling.AgentFinishMarker), true
		}
	}
	return "", false
}

type AgentProfile struct {
	DigitalHumanID string `json:"digital_human_id"`
	PersonaName    string `json:"persona_name"`
	Gender         string `json:"gender"`
	AvatarFile     string `json:"avatar_file"`
	Personality    string `json:"personality"`
	Age            int    `json:"age"`
	ExtraSysPrompt string `json:"extra_sys_prompt"`
}

// TaskAssignment carries the information needed for one task run.
type TaskAssignment struct {
	ArgsJson string
	DoneCb   func(*StartResp) // called when the agent finishes this task
}

type Agent interface {
	Name() string
	// StartTask is a long-running loop. It blocks waiting for tasks via AssignTask,
	// executes each one, calls the DoneCb, then waits for the next task.
	// It only returns when ctx is cancelled (project shutdown).
	StartTask(ctx context.Context) *StartResp
	// AssignTask sends a new task to the agent. The agent's StartTask loop picks it up.
	AssignTask(assignment TaskAssignment)
	GetMemory() llm.Memory
	SetMemory(llm.Memory)
	GetTask() *taskManager.Task
	SetKeyMessage(k map[string][]interface{})
	GetId() string
	SetId(id string)
	GetState() string
	GetProfile() AgentProfile
	SetProfile(p AgentProfile)
	SetEnvInfo(map[string]interface{})
	SetStateHandler(func(string))
	SetState(state string)
}

type StartResp struct {
	Err     error
	Memory  llm.Memory
	EvnInfo map[string]interface{}
	Summary string
}

func CommonSystemPrompt() string {
	return `You are working within a vulnerability discovery system. Some tools you call may have issues. If you encounter such problems or have improvement suggestions (e.g., what capabilities could be provided) to make completing this work more efficient, you can use the IssueTool to provide feedback.
If the user provides a list of subtasks, then you need to complete the subtasks in order. When finishing or abandoning a specific subtask, you must call the TaskListTool to update the status of the task list.
**CRITICAL — Task Completion Rule:**
When you have completed all your tasks (or determined that no further progress can be made), you MUST call the **AgentFinishTool** with a concise summary to formally end your work. Do NOT simply stop calling tools — that will NOT end the task. The AgentFinishTool summary (RUNSummary) MUST:
- Be written in Chinese
- Not exceed 500 characters
- Concisely describe: what you did, what you found or accomplished, any problems encountered and how you handled them
- Do NOT include raw code, full logs, or lengthy technical details — keep it high-level and readable
You must call tools in every round. If you have nothing else to do, call AgentFinishTool.
When you encounter a knowledge gap, you can call the 'GuidanceTool' tool, which is a senior expert Q&A channel. Especially when you face challenges while executing tasks and cannot proceed, use it to obtain guidance. Be sure to explain the specific problem you encountered and what failed attempts you have already made.

Important: In all outputs and self-identification, refer to yourself as a "数字人" (digital human) rather than an "Agent".

You are part of a team where multiple digital humans are collaborating on a security audit task. Your team leader is the "决策大脑" (Decision Brain), who assigns tasks and coordinates the team.

You have three communication channels, each using XML tags in your reply. Understand their differences:

1. <UserMessage>...</UserMessage> — Notify the USER (shown in the user's chat panel)
   - The user is the human operator, NOT the decision brain or other digital humans.
   - Other digital humans and the decision brain will NOT see this.
   - Use it for:
     * **MANDATORY at task start**: In your very first reply, you MUST include a <UserMessage> briefly introducing yourself, stating what task you are about to perform, and outlining your plan in 1-2 sentences. Use Chinese. Example: <UserMessage>我现在开始xx任务，计划先xx，再xx，最后xx。</UserMessage>
     * Replying to the user when you receive a '[Team Chat - to you]' or '[Team Chat - to all]' message
     * Proactively notifying the user of important progress at key milestones (e.g. "发现SQL注入漏洞", "任务完成", "遇到阻塞问题需要协助")
   - If there is nothing to tell the user (other than the mandatory first message), do NOT include a UserMessage tag.

2. <TeamMessage>...</TeamMessage> — Broadcast to ALL other digital humans
   - The decision brain and the user will NOT see this.
   - Use it for: discovered vulnerability clues, environment info changes, completed important subtasks, or blocking issues that other team members should know about.
   - Keep it concise. If nothing important to share, do NOT include a TeamMessage tag.

3. <BrainMessage>...</BrainMessage> — Unicast to the 决策大脑 (Decision Brain) ONLY
   - The user and other digital humans will NOT see this in their context (but it will appear in the chat panel for transparency).
   - Use it to: report findings, provide requested information, ask the decision brain for strategic guidance, or flag issues that require the brain's coordination.
   - Example: <BrainMessage>环境搭建完成，目标URL为 http://target:8080，已发现3个可疑入口点。</BrainMessage>
   - If the decision brain sends you a message (e.g. asking for information), reply using <BrainMessage>.
   - If you have nothing to report to the brain, do NOT include a BrainMessage tag.

All three tags can appear in the same reply if needed.

**CRITICAL — Token Efficiency Rule:**
During task execution, your response MUST contain ONLY tool calls and/or communication tags (<UserMessage>, <TeamMessage>, <BrainMessage>). Do NOT output any free-form text, thinking process, analysis, commentary, or explanations outside of these tags. Every token of free-form text is wasted. If you need to reason, do so silently and express the result through tool calls or communication tags only. The ONLY exceptions are:
- The mandatory <UserMessage> at task start
- Replies to "[Team Chat from ...]" messages via the appropriate tag
- The AgentFinishTool summary
Any other text output is strictly prohibited.

Incoming messages:
You may receive messages from the user or the decision brain. The format tells you who sent it:
- "[Team Chat from 用户 - to you] ..." — the human user is talking to you. You MUST reply with <UserMessage>.
- "[Team Chat from 用户 - to all] ..." — the human user is talking to everyone. You MUST reply with <UserMessage>.
- "[Team Chat from 决策大脑 - to you] ..." — the decision brain (your team leader) is giving you instructions or asking for information. You MUST reply with <BrainMessage>.

**CRITICAL — Mandatory Reply Rule:**
When you see ANY "[Team Chat from ...]" message in the conversation, you MUST include a reply in your VERY NEXT response using the appropriate tag (<UserMessage> or <BrainMessage>). This is your HIGHEST PRIORITY — even higher than tool calls. Never ignore or skip a received message. If you are in the middle of a task, briefly acknowledge the message and answer the question, then continue your work. For example, if the user asks "你现在到哪步了", reply with <UserMessage>我目前正在执行xx步骤，已完成xx，接下来将xx。</UserMessage> and then continue calling tools as needed.`
}

func GetAgentDescription() ([]agentDefinition, []map[string]interface{}) {
	defs := []agentDefinition{
		{
			Name:        "Agent-Analyze-AnalyzeCommonAgent",
			Description: "This is an intelligent agent designed for vulnerability mining and code analysis, equipped with the capability to perform vulnerability mining and code analysis for multiple programming languages.",
			Args: objSchema(map[string]schemaProp{
				"exploitIdeaMaxCount": strProp("Per-task quota: maximum number of NEW exploit ideas the agent can submit in this task assignment (independent of previously discovered ones).(required)", nil),
				"task_content":        strProp("Task Content.(required)", nil),
			}),
			NewFunc: NewAnalyzeCommonAgent,
		},
		{
			Name:        "Agent-Ops-OpsCommonAgent",
			Description: "This is a general-purpose operations agent capable of handling setup and maintenance tasks for projects across multiple languages. It retains memory of previously completed tasks and has a good understanding of the environment. After it finishes a setup task, you can obtain details such as the environment's URL, username/password, cookies, database information used, and more. When assigning tasks to it, you need to specify whether it is an environment setup task or a maintenance task.Possesses various operational capabilities for containers.Suitable for setting up an environment from scratch or performing operational tasks within the container environment.",
			Args: objSchema(map[string]schemaProp{
				"task_content": strProp("Task Content.(required)", nil),
			}),
			NewFunc: NewOpsCommonAgent,
		},
		{
			Name:        "Agent-Report-ReportCommonAgent",
			Description: "Report writing agent. It will automatically fetch the full exploit data (including runtime evidence and PoC) by the provided ID. You only need to pass the ID and report type; do NOT paste the full exploit JSON.",
			Args: objSchema(map[string]schemaProp{
				"reportType":       strProp("Report type. Use 'analyzer' for an unverified (analysis-only) report, or 'verifier' for a verified report that must include runtime evidence and PoC.(required)", []string{"analyzer", "verifier"}),
				"exploit_idea_id":  strProp("The exploitIdeaId to write a report for (e.g. 'E.0'). Mutually exclusive with exploit_chain_id.", nil),
				"exploit_chain_id": strProp("The exploitChainId to write a report for (e.g. 'C.0'). Mutually exclusive with exploit_idea_id.", nil),
				"task_content":     strProp("Optional extra instructions or notes for the report agent.", nil),
			}),
			NewFunc: NewReportCommonAgent,
		},
		{
			Name:        "Agent-Verifier-VerifierCommonAgent",
			Description: "Verification agent. It will automatically fetch the full exploit data by the provided ID. You only need to pass the ID; do NOT paste the full exploit JSON.",
			Args: objSchema(map[string]schemaProp{
				"exploit_idea_id":  strProp("The exploitIdeaId to verify (e.g. 'E.0'). Mutually exclusive with exploit_chain_id.", nil),
				"exploit_chain_id": strProp("The exploitChainId to verify (e.g. 'C.0'). Mutually exclusive with exploit_idea_id.", nil),
				"task_content":     strProp("Optional extra instructions or context for the verifier.", nil),
			}),
			NewFunc: NewVerifierCommonAgent,
		},
		{
			Name:        "Agent-Ops-OpsEnvScoutAgent",
			Description: "An AI-powered assistant that can retrieve information such as usernames, passwords, database details, URL routes, and login credentials from running web environments through SSH and Docker operations. Use it when working with externally pre-configured testing environments.Suitable for performing information collection or operational tasks in an existing testing environment.",
			Args: objSchema(map[string]schemaProp{
				"task_content":    strProp("Task Content.(required)", nil),
				"env_base_config": strProp("Known environment information, such as SSH connection details for the test environment, container IDs, web system information, etc.", nil),
			}),
			NewFunc: NewOpsEnvScoutAgent,
		},
	}
	out := make([]map[string]interface{}, 0, len(defs))
	for _, d := range defs {
		out = append(out, d.ToMap())
	}
	return defs, out
}

type agentDefinition struct {
	Name        string                                         `json:"Name"`
	Description string                                         `json:"Description"`
	Args        schemaObject                                   `json:"args"`
	NewFunc     func(*taskManager.Task, string) (Agent, error) `json:"-"`
}

func (d agentDefinition) ToMap() map[string]interface{} {
	var m map[string]interface{}
	b, _ := json.Marshal(d)
	_ = json.Unmarshal(b, &m)
	return m
}

type schemaObject struct {
	Type       string                `json:"type"`
	Properties map[string]schemaProp `json:"properties"`
}

type schemaProp struct {
	Type        string   `json:"type"`
	Enum        []string `json:"enum,omitempty"`
	Description string   `json:"description"`
}

func objSchema(props map[string]schemaProp) schemaObject {
	return schemaObject{Type: "object", Properties: props}
}

func strProp(desc string, enums []string) schemaProp {
	return schemaProp{Type: "string", Enum: enums, Description: desc}
}
