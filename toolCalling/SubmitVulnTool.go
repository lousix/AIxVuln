package toolCalling

import (
	"AIxVuln/misc"
	"AIxVuln/taskManager"
	"encoding/json"
	"fmt"

	"github.com/sashabaranov/go-openai"
)

type SubmitVulnTool struct {
	task *taskManager.Task
}

func NewSubmitVulnTool(task *taskManager.Task) *SubmitVulnTool {
	return &SubmitVulnTool{task: task}
}

func (h *SubmitVulnTool) Name() string {
	return "SubmitVulnTool"
}
func (h *SubmitVulnTool) Description() string {
	return "If you complete the verification of a vulnerability (regardless of success or failure), you need to collect runtime evidence of the verification outcome, write a Python attack script, and call this tool. This tool will return a new task or an instruction to end the task to you.The report must be in Chinese."
}
func (h *SubmitVulnTool) Parameters() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"vuln_id": map[string]interface{}{
				"type":        "string",
				"description": "vuln_id, example: V.1.(required)",
			},
			"vuln_status": map[string]interface{}{
				"type":        "string",
				"enum":        []string{"Completed", "Failed"},
				"description": "Vuln status needs to be set.(required)",
			},
			"Evidence": map[string]interface{}{
				"type":        "string",
				"description": "Runtime evidence for successful verification, or a summary of failed verification, should be presented in Markdown format.The report must be in Chinese.(required)",
			},
			"Poc": map[string]interface{}{
				"type":        "string",
				"description": "If verification is successful, you can pass in a Python script that verifies the existence of the vulnerability (optional).",
			},
		},
	}
}

func (h *SubmitVulnTool) Execute(parameters map[string]interface{}) string {
	VulnIdTemp := parameters["vuln_id"]
	if VulnIdTemp == nil {
		return Fail("Missing 'vuln_id' parameter")
	}
	VulnIdStr := VulnIdTemp.(string)
	if len(VulnIdStr) < 3 {
		return Fail("vuln_id too short")
	}

	VulnStatusTemp := parameters["vuln_status"]
	if VulnStatusTemp == nil {
		return Fail("Missing 'vuln_status' parameter")
	}
	VulnStatus := VulnStatusTemp.(string)

	EvidenceTemp := parameters["Evidence"]
	if EvidenceTemp == nil {
		return Fail("Missing 'Evidence' parameter")
	}
	Evidence := EvidenceTemp.(string)

	var Poc string
	PocTemp := parameters["Poc"]
	if PocTemp != nil {
		Poc = PocTemp.(string)
	}
	err := h.task.UpdateVulnStatus(VulnIdStr, VulnStatus)
	if err != nil {
		return Fail(err.Error())
	}
	if VulnStatus == "Completed" {
		//historyMemory := h.task.GetMemory().GetContext(h.task.GetTaskId()) // 会把幻觉带进 Report 不再使用
		var historyMemory []openai.ChatCompletionMessage
		taskData := taskManager.TaskData{HistoryMemory: historyMemory, SourceCodePath: h.task.GetSourceCodePath(), Evidence: Evidence, POC: Poc, Sandbox: h.task.GetSandbox(), EnvInfo: h.task.GetEnvInfo(), TaskType: "verifier", VulnId: VulnIdStr}
		h.task.PutReportToQueue(taskData)
	}
	err = h.task.SaveVuln(VulnIdStr, Evidence, Poc)
	vuln, err := h.task.GetOneVuln()
	var vs string
	if err != nil {
		vs = "All vulnerabilities have been verified and completed; the task is now ending."
	} else {
		v, _ := json.Marshal(vuln)
		vs = string(v)
	}
	taskList := h.task.GetTaskList()
	if len(taskList) < 1 {
		taskList = misc.GetCommonVerifierTaskList(vs)
	} else {
		taskList[0]["TaskContent"] = "You currently need to complete the verification work for this vulnerability, or if it is an instruction to end, end immediately: " + vs
	}
	h.task.SetTaskList(taskList)
	misc.Success("漏洞完成校验", fmt.Sprintf("漏洞ID: %s 验证结果: %s 漏洞总数: %d", VulnIdStr, VulnStatus, len(h.task.GetVulnList())), h.task.GetEventHandler())
	return Success(vuln)
}
