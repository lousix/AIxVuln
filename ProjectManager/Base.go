package ProjectManager

type WebMsg struct {
	Type        string      `json:"type"`
	Data        interface{} `json:"data"`
	ProjectName string      `json:"projectName"`
}
