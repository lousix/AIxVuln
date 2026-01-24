package toolCalling

import (
	"AIxVuln/taskManager"
	"encoding/json"
)

type IssueVulnTool struct {
	task *taskManager.Task
}

func NewIssueVulnTool(task *taskManager.Task) *IssueVulnTool {
	return &IssueVulnTool{task: task}
}

func (h *IssueVulnTool) Name() string {
	return "IssueVulnTool"
}
func (h *IssueVulnTool) Description() string {
	return "Use this tool to record when you discover vulnerabilities."
}
func (h *IssueVulnTool) Parameters() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"candidate": map[string]interface{}{
				"type":        "object",
				"description": "The JSON must include: {title, route_or_endpoint, file, function_or_method, params, type, payload_idea, expected_impact, confidence}, The parameters must be formatted as (delivery_method->parameter_name, delivery_method->parameter_name), for example, if parameter a is passed via the header, parameter b via the cookie, and parameter c via POST, then it should be \"header->a,cookie->b,post->c\".The `type` field needs to specify the shorthand for the vulnerability type, such as: SQLI, XSS, IDOR, XXE, etc., and should use all uppercase letters.Write the title in Chinese..(required)",
			},
		},
	}
}

func (h *IssueVulnTool) Execute(parameters map[string]interface{}) string {
	CandidateTemp := parameters["candidate"]
	if CandidateTemp == nil {
		return Fail("Missing 'candidate' parameter")
	}
	c, err := json.Marshal(CandidateTemp.(map[string]interface{}))
	if err != nil {
		return Fail(err.Error())
	}
	vuln := taskManager.Vuln{}
	err = json.Unmarshal(c, &vuln)
	if err != nil {
		return Fail(err.Error())
	}
	if h.task.HasVulnByFileAndParams(vuln) {
		return Fail("Vuln already exists")
	}
	var id string
	id, err = h.task.AddVuln(vuln)
	h.task.PutReportToQueue(taskManager.TaskData{VulnId: id, TaskType: "analyzer", Candidate: string(c), Sandbox: h.task.GetSandbox()})
	if err != nil {
		return Fail(err.Error())
	}
	return Success("success")
}
