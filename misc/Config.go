package misc

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"

	"github.com/sashabaranov/go-openai"
	"gopkg.in/ini.v1"
)

var (
	cfg     *ini.File
	mu      sync.RWMutex
	err     error
	clients *ClientS
)

type ClientS struct {
	mu      sync.Mutex
	clients map[string][]*openai.Client
	index   map[string]int
}

func (c *ClientS) putClient(key string, client *openai.Client) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, e := c.clients[key]
	if !e {
		c.clients[key] = []*openai.Client{client}
		c.index[key] = 0
	} else {
		c.clients[key] = append(c.clients[key], client)
	}
}

func (c *ClientS) getClient(key string) *openai.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	cli, e := c.clients[key]
	if !e {
		return nil
	}
	index, e := c.index[key]
	if !e {
		return nil
	}
	client := cli[index]
	index++
	if len(c.clients[key]) <= index {
		index = 0
	}
	c.index[key] = index
	return client
}

func init() {
	cfg, err = ini.Load("config.ini")
	if err != nil {
		log.Fatal(err)
	}
	clients = &ClientS{clients: make(map[string][]*openai.Client), index: make(map[string]int)}
}

func GetClient(section ...string) *openai.Client {
	for _, section1 := range section {
		cli := clients.getClient(section1)
		if cli != nil {
			return cli
		}
		if !cfg.HasSection(section1) {
			continue
		}
		baseUrl := GetConfigValueRequired(section1, "BASE_URL")
		secretKey := GetConfigValueRequired(section1, "OPENAI_API_KEY")
		if strings.Contains(secretKey, "|-|") {
			for _, key := range strings.Split(secretKey, "|-|") {
				config := openai.DefaultAnthropicConfig(key, baseUrl)
				config.APIType = "Authorization"
				client := openai.NewClientWithConfig(config)
				clients.putClient(section1, client)
			}
		} else {
			config := openai.DefaultAnthropicConfig(secretKey, baseUrl)
			config.APIType = "Authorization"
			client := openai.NewClientWithConfig(config)
			clients.putClient(section1, client)
		}
		return clients.getClient(section1)
	}
	return nil
}

func GetConfigValueRequired(section, key string) string {
	mu.RLock()
	defer mu.RUnlock()
	if cfg == nil {
		return ""
	}
	if !cfg.HasSection(section) {
		log.Fatal("配置不存在 " + section + ":" + key)
	}
	value := cfg.Section(section).Key(key).String()
	value = strings.TrimSpace(value)
	if value == "" {
		log.Fatal("配置为空 " + section + ":" + key)
	}
	return value
}

func GetConfigValueDefault(section, key string, defaultValue string) string {
	mu.RLock()
	defer mu.RUnlock()
	if cfg == nil {
		return defaultValue
	}
	if !cfg.HasSection(section) {
		return defaultValue
	}
	value := cfg.Section(section).Key(key).String()
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultValue
	}
	return value
}

func GetMaxHistory() int {
	num := GetConfigValueDefault("misc", "MaxHistory", "102400")
	result, err := strconv.Atoi(num)
	if err != nil {
		log.Fatal(err)
	}
	return result
}

func GetMaxTryCount() int {
	num := GetConfigValueDefault("misc", "MaxTryCount", "3")
	result, err := strconv.Atoi(num)
	if err != nil {
		log.Fatal(err)
	}
	return result
}

func GetMaxRequest() int {
	num := GetConfigValueDefault("misc", "MaxRequest", "3")
	result, err := strconv.Atoi(num)
	if err != nil {
		log.Fatal(err)
	}
	return result
}

func GetMessageMaximum() int {
	num := GetConfigValueDefault("misc", "MessageMaximum", "10240")
	result, err := strconv.Atoi(num)
	if err != nil {
		log.Fatal(err)
	}
	return result
}

func GetDataDir() string {
	return GetConfigValueDefault("misc", "DATA_DIR", "./data")
}

func GetFeiShuAPI() string {
	return GetConfigValueDefault("misc", "FeiShuAPI", "")
}

func GetCommonOpsTaskList() []map[string]string {
	taskList := make([]map[string]string, 5)
	for i := 0; i < len(taskList); i++ {
		taskList[i] = make(map[string]string)
	}
	taskList[0]["TaskID"] = "T.0"
	taskList[0]["TaskContent"] = "Install the source code project: First, start the environment using the RunxxxEnvTool as the preferred method, ensuring the web environment is set up within a tool that supports the designated webPort. Then, visit the project page to verify whether the service port matches the webPort specified when starting the environment (if applicable). If they do not match, modify the service port accordingly. If an installation guide page is provided, follow the instructions to complete installation and initialization. If no guide page is available, analyze the installation process independently. You can set up an account and password as needed, and then submit them as the \"reason\"."
	taskList[0]["TaskStatus"] = "Currently Required to Complete"
	taskList[0]["Reason"] = ""

	taskList[1]["TaskID"] = "T.1"
	taskList[1]["TaskContent"] = "If the login process in the environment includes a CAPTCHA, modify the source code to disable the CAPTCHA login feature."
	taskList[1]["TaskStatus"] = "To be completed"
	taskList[1]["Reason"] = ""

	taskList[2]["TaskID"] = "T.2"
	taskList[2]["TaskContent"] = "Analyze the routing access method and provide three successfully accessed routing examples as the \"reason.\" for submission."
	taskList[2]["TaskStatus"] = "To be completed"
	taskList[2]["Reason"] = ""

	taskList[3]["TaskID"] = "T.3"
	taskList[3]["TaskContent"] = "Log into the system and obtain a valid COOKIE as the \"reason\" for submission."
	taskList[3]["TaskStatus"] = "To be completed"
	taskList[3]["Reason"] = ""

	taskList[4]["TaskID"] = "T.4"
	taskList[4]["TaskContent"] = "Call EnvSaveTool to save key information.When calling EnvSaveTool, all URL and IP information must not use 127.0.0.1, localhost, etc., but rather the real WEB environment container IP."
	taskList[4]["TaskStatus"] = "To be completed"
	taskList[4]["Reason"] = ""
	return taskList
}

func GetCommonAnalyzeTaskList(vulnType string) []map[string]string {
	taskList := make([]map[string]string, 1)
	for i := 0; i < len(taskList); i++ {
		taskList[i] = make(map[string]string)
	}
	task := "Try to discover as many vulnerabilities as possible in source code."
	if vulnType != "" {
		task += fmt.Sprintf("Focus on vulnerability discovery related to %s; other vulnerabilities need not be considered.", vulnType)
	}

	taskList[0]["TaskID"] = "T.0"
	taskList[0]["TaskContent"] = task
	taskList[0]["TaskStatus"] = "Currently Required to Complete"
	taskList[0]["Reason"] = ""
	return taskList
}

func GetCommonReportTaskList(evidence string, poc string) []map[string]string {
	taskList := make([]map[string]string, 1)
	for i := 0; i < len(taskList); i++ {
		taskList[i] = make(map[string]string)
	}
	taskList[0]["TaskID"] = "T.0"
	taskList[0]["TaskContent"] = fmt.Sprintf("Runtime evidence: %s\nPoc: %s", evidence, poc)
	taskList[0]["TaskStatus"] = "Currently Required to Complete"
	taskList[0]["Reason"] = ""
	return taskList
}

func GetAnalyzeReportTaskList(vulnInfo string) []map[string]string {
	taskList := make([]map[string]string, 1)
	for i := 0; i < len(taskList); i++ {
		taskList[i] = make(map[string]string)
	}
	taskList[0]["TaskID"] = "T.0"
	taskList[0]["TaskContent"] = fmt.Sprintf("The vulnerability information is as follows. You need to supplement the analysis and write the report: \n%s", vulnInfo)
	taskList[0]["TaskStatus"] = "Currently Required to Complete"
	taskList[0]["Reason"] = ""
	return taskList
}

func GetCommonVerifierTaskList(vulnJson string) []map[string]string {
	taskList := make([]map[string]string, 1)
	for i := 0; i < len(taskList); i++ {
		taskList[i] = make(map[string]string)
	}
	taskList[0]["TaskID"] = "T.0"
	taskList[0]["TaskContent"] = "You currently need to complete the verification work for this vulnerability, or if it is an instruction to end, end immediately: " + vulnJson
	taskList[0]["TaskStatus"] = "Currently Required to Complete"
	taskList[0]["Reason"] = ""
	return taskList
}
