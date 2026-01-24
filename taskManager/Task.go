package taskManager

import (
	"AIxVuln/dockerManager"
	"AIxVuln/llm"
	"AIxVuln/misc"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sashabaranov/go-openai"
)

type Task struct {
	sm            *dockerManager.ServiceManager
	taskId        string
	envInfo       map[string]interface{}
	sandbox       *Sandbox
	projectDir    string
	taskDir       string
	memory        llm.Memory
	taskList      []map[string]string
	vulns         *VulnManager
	agentName     string
	reportQueue   *chan TaskData
	projectName   string
	goroutineChan chan func()
	eventHandler  func(string, string, int)
	reportHandler func(string, string)
	envInfoHandle func(map[string]interface{})
	addTaskHandle func(task *Task)
	maxVulnCount  int
	currentVulnId string
}
type TaskData struct {
	TaskType       string // verifier or analyzer
	HistoryMemory  []openai.ChatCompletionMessage
	SourceCodePath string
	Evidence       string
	POC            string
	Sandbox        *Sandbox
	EnvInfo        map[string]interface{}
	VulnId         string
	Candidate      string // analyzer 才需要
}

func NewTask(projectDir string, taskList []map[string]string, sandbox *Sandbox, vulns *VulnManager, goroutineChan chan func(), projectName string) *Task {
	uuidTmp, err := uuid.NewUUID()
	if err != nil {
		log.Fatal(err)
	}
	taskId := uuidTmp.String()
	taskDir := filepath.Join(projectDir, "tasks", taskId)
	absTaskDir, err := filepath.Abs(taskDir)
	if err != nil {
		log.Fatal(err)
	}
	err = misc.CreateDir(absTaskDir)
	if err != nil {
		log.Fatal(err)
	}
	err = misc.CreateDir(filepath.Join(absTaskDir, "vuln"))
	if err != nil {
		log.Fatal(err)
	}

	if sandbox == nil {
		misc.Error(projectName, "sandbox is nil", nil)
		return nil
	}
	sourceCodeDir := filepath.Join(projectDir, "sourceCodeDir")
	sm := dockerManager.NewServiceManager(sourceCodeDir, sandbox.dm)
	return &Task{sm: sm, taskId: taskId, taskDir: absTaskDir, sandbox: sandbox, taskList: taskList, vulns: vulns, goroutineChan: goroutineChan, projectName: projectName, projectDir: projectDir, maxVulnCount: 15}
}

func (task *Task) GetCurrVulnId() string {
	return task.currentVulnId
}
func (task *Task) GetTaskId() string {
	return task.taskId
}
func (task *Task) SetCurrVulnId(id string) {
	task.currentVulnId = id
}

func (task *Task) GetProjectDir() string {
	return task.projectDir
}
func (task *Task) GetVulnManager() *VulnManager {
	return task.vulns
}
func (task *Task) GetProjectName() string {
	return task.projectName
}
func (task *Task) SetTaskList(x []map[string]string) {
	task.taskList = x
	task.memory.SetTaskList(&llm.TaskListX{TaskList: task.GetTaskList(), ContextId: task.taskId})
}
func (task *Task) SetEventHandler(handler func(string, string, int)) {
	task.eventHandler = handler
}
func (task *Task) GetEventHandler() func(string, string, int) {
	return task.eventHandler
}
func (task *Task) SetReportHandler(handler func(string, string)) {
	task.reportHandler = handler
}
func (task *Task) GetReportHandler() func(string, string) {
	return task.reportHandler
}

func (task *Task) SetAddTaskHandler(handler func(*Task)) {
	task.addTaskHandle = handler
}
func (task *Task) GetAddTaskHandler() func(*Task) {
	return task.addTaskHandle
}

func (task *Task) SetReportQueue(queue *chan TaskData) {
	task.reportQueue = queue
}

func (task *Task) PutReportToQueue(taskData TaskData) {
	if task.reportQueue == nil {
		return
	}
	*task.reportQueue <- taskData
}
func (task *Task) GetTaskList() []map[string]string {
	return task.taskList
}

func (task *Task) SetMaxVulnCount(count int) {
	task.maxVulnCount = count
}

func (task *Task) GetMaxVulnCount() int {
	return task.maxVulnCount
}

func (task *Task) GetEnvInfo() map[string]interface{} {
	return task.envInfo
}
func (task *Task) GetTaskDir() string {
	return task.taskDir
}
func (task *Task) GetSm() *dockerManager.ServiceManager {
	return task.sm
}
func (task *Task) GetSourceCodePath() string {
	return task.sm.GetSourceCodePath()
}
func (task *Task) SetMemory(memory llm.Memory) {
	task.memory = memory
	if memory.GetType() == "SharedContext" {
		cm := llm.NewContextManager()
		cm.SetEventHandler(task.GetEventHandler())
		task.memory.AddContextManager(task.taskId, cm)
	}
	task.memory.AddKeyMessage(task.sandbox.GetSandboxEnvMsg())
	task.memory.SetTaskList(&llm.TaskListX{TaskList: task.GetTaskList(), ContextId: task.taskId})
}
func (task *Task) SetAgentName(name string) {
	if strings.HasPrefix(name, "Verifier") {
		if task.reportQueue == nil {
			log.Fatal("taskManager reportQueue not init")
		}
	}
	task.agentName = name
}

func (task *Task) SetEnvInfo(envInfo map[string]interface{}) {
	task.envInfo = envInfo
	task.memory.AddKeyMessage(&llm.EnvMessageX{Key: "WebEnvInfo", Content: envInfo, AppendEnv: false})
}

func (task *Task) SaveEnvInfo(envInfo map[string]interface{}) error {
	if task.memory == nil {
		misc.Warn(task.projectName+"-"+task.agentName, "当前任务未设置memory 将不支持环境关键信息记录", task.eventHandler)
	} else {
		task.memory.AddKeyMessage(&llm.EnvMessageX{Key: "WebEnvInfo", Content: envInfo, AppendEnv: false})
		task.envInfoHandle(envInfo)
	}
	task.envInfo = envInfo
	envPath := task.projectDir + "/env.json"
	f, err := os.OpenFile(envPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	js, err := json.Marshal(task.envInfo)
	if err != nil {
		return err
	}
	_, err = f.Write(js)
	if err != nil {
		return err
	}
	defer f.Close()
	return nil
}
func (task *Task) GetSandbox() *Sandbox {
	return task.sandbox
}
func (task *Task) GetMemory() llm.Memory {
	return task.memory
}
func (task *Task) AddVuln(vuln Vuln) (string, error) {
	c := 0
	for _, v := range task.vulns.GetVulnList() {
		if v.Type == vuln.Type {
			c++
			if c == 3 {
				return "", fmt.Errorf("This vulnerability type has already exceeded three instances, and further exploitation of %s-type vulnerabilities is not allowed", v.Type)
			}
		}
	}

	id := task.vulns.AddVulns(vuln)
	task.memory.AddKeyMessage(&llm.EnvMessageX{Key: "CANDIDATE_VULNS", Content: task.vulns.GetVulnList(), AppendEnv: false})
	return id, nil
}
func (task *Task) HasVulnByFileAndParams(vuln Vuln) bool {
	return task.vulns.HasVulnByFileAndParams(vuln.File, vuln.Params)
}

func (task *Task) UpdateVulnStatus(id string, status string) error {
	return task.vulns.UpdateVuln(id, status)
}
func (task *Task) AddEnvMessage(key string, msg any, appendEnv bool) {
	if task.memory == nil {
		misc.Warn(task.projectName+"-"+task.agentName, "当前任务未设置memory 将不支持环境关键信息记录", task.eventHandler)
	} else {
		task.memory.AddKeyMessage(&llm.EnvMessageX{Key: key, Content: msg, AppendEnv: appendEnv})
	}
}

func (task *Task) EventLog(msg string) error {
	filename := task.taskDir + "/" + task.agentName + "-event.log"
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logEntry := fmt.Sprintf("[%s] %s\n", timestamp, msg)
	_, err = file.WriteString(logEntry)
	return err
}

func (task *Task) SaveVuln(id string, markdown string, poc string) error {
	filename := task.taskDir + "/vulns/" + id + ".md"
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	markdown = markdown + "\n\n# POC\n```python\n" + poc + "\n```\n"
	file.WriteString(markdown)
	return nil
}
func (task *Task) GetVulnList() []Vuln {
	return task.vulns.GetVulnList()
}
func (task *Task) GetOneVuln() (Vuln, error) {
	return task.vulns.GetOneCandidate()
}

func (task *Task) AddGoroutine(f func()) {
	task.goroutineChan <- f
}
func (task *Task) GetGoroutineChan() chan func() {
	return task.goroutineChan
}
func (task *Task) SetEnvInfoHandler(f func(map[string]interface{})) {
	task.envInfoHandle = f
}
