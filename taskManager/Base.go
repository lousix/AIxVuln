package taskManager

type ContainerInfo struct {
	Type        string   `json:"type"` //Create OR Remove
	ContainerId string   `json:"containerId"`
	ContainerIP string   `json:"containerIP"`
	Image       string   `json:"image"`
	WebPort     []string `json:"webPort"`
}

type ProjectInfo struct {
	ProjectName   string                 `json:"projectName"`
	SourceCodeDir string                 `json:"source_code_dir"`
	StartTime     string                 `json:"start_time"`
	EndTime       string                 `json:"end_time"`
	ContainerList []ContainerInfo        `json:"containerList"`
	VulnList      []Vuln                 `json:"vuln_list"`
	EventList     []string               `json:"event_list"`
	EnvInfo       map[string]interface{} `json:"envInfo"`
	ProjectDir    string                 `json:"projectDir"`
	ReportList    map[string]string      `json:"report_list"`
}
