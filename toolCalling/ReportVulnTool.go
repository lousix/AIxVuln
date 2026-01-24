package toolCalling

import (
	"AIxVuln/misc"
	"AIxVuln/taskManager"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type ReportVulnTool struct {
	task *taskManager.Task
}

func NewReportVulnTool(task *taskManager.Task) *ReportVulnTool {
	return &ReportVulnTool{task: task}
}

func (h *ReportVulnTool) Name() string {
	return "ReportVulnTool"
}
func (h *ReportVulnTool) Description() string {
	return "Submit the completed report through this tool.The report must be in Chinese."
}
func (h *ReportVulnTool) Parameters() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"Report": map[string]interface{}{
				"type":        "string",
				"description": "Write in Markdown format and use Chinese.(required)",
			},
			"VulnType": map[string]interface{}{
				"type":        "string",
				"description": "Vulnerability type abbreviations, such as: SQLi, SSRF, UploadFile.(required)",
			},
		},
	}
}

func (h *ReportVulnTool) Execute(parameters map[string]interface{}) string {
	ReportTemp := parameters["Report"]
	if ReportTemp == nil {
		return Fail("Missing 'Report' parameter")
	}
	Report := ReportTemp.(string)
	VulnTypeTemp := parameters["VulnType"]
	if VulnTypeTemp == nil {
		return Fail("Missing 'VulnType' parameter")
	}
	vulnType := VulnTypeTemp.(string)
	vulnDir := filepath.Join(h.task.GetProjectDir(), "vulns")
	currentDate := time.Now().Format("2006-01-02")
	folderName := filepath.Join(vulnDir, currentDate)
	_ = os.MkdirAll(folderName, 0755)
	var filename string
	index := 0
	for {
		filename = filepath.Join(folderName, fmt.Sprintf("%s-%d.md", vulnType, index))
		if _, err := os.Stat(filename); os.IsNotExist(err) {
			_ = os.WriteFile(filename, []byte(Report), 0644)
			h.task.GetReportHandler()(h.task.GetCurrVulnId(), filename)
			break
		}
		index++
	}
	misc.Success("报告生成成功", fmt.Sprintf("报告输出: %s \n", filename), h.task.GetEventHandler())
	return Success("ok")
}
