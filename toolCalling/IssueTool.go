package toolCalling

import (
	"AIxVuln/misc"
	"AIxVuln/taskManager"
)

type IssueTool struct {
	task *taskManager.Task
}

func NewIssueTool(task *taskManager.Task) *IssueTool {
	return &IssueTool{task: task}
}

func (h *IssueTool) Name() string {
	return "IssueTool"
}
func (h *IssueTool) Description() string {
	return "If you encounter a difficult issue or feel a feature is urgently needed, call this command to provide feedback. Your issue will be addressed in the future.The content should be in Chinese. Do not submit the source code vulnerabilities from the audit project here."
}
func (h *IssueTool) Parameters() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"Issue": map[string]interface{}{
				"type":        "string",
				"description": "Issues encountered or suggestions raised should be in Chinese, using Markdown format.(required)",
			},
		},
	}
}

func (h *IssueTool) Execute(parameters map[string]interface{}) string {
	IssueTemp := parameters["Issue"]
	if IssueTemp == nil {
		return Fail("Missing 'Issue' parameter")
	}
	issue := IssueTemp.(string) + "\n\n"
	err := misc.AppendLogBasic("Issue.log", issue)
	if err != nil {
		return Fail(err.Error())
	}
	return Success("Submit success")
}
