package ProjectManager

import (
	"AIxVuln/agents"
	"AIxVuln/dockerManager"
	"AIxVuln/misc"
	"AIxVuln/taskManager"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/google/uuid"
)

type ProjectManager struct {
	mu                  sync.RWMutex
	wg                  *sync.WaitGroup
	tasks               []*taskManager.Task
	projectName         string
	agentGroupList      AgentGroupList
	goroutine           chan func()
	analyzeAgentNumber  int
	verifierAgentNumber int
	sourceCodeDir       string
	projectDir          string
	containerList       []taskManager.ContainerInfo
	vulnList            []taskManager.Vuln //整个项目的漏洞汇总
	eventList           []string
	agentRespList       map[string]*agents.StartResp
	reportList          map[string]string
	status              string
	startTime           string
	endTime             string
	stopChan            chan struct{}
	ctx                 context.Context
	cancelFunc          context.CancelFunc
	isStopping          bool
	isRunning           bool
	msgChan             chan WebMsg
	envInfo             map[string]interface{}
	dm                  *dockerManager.DockerManager
}

type ProjectConfig struct {
	ProjectName         string
	AnalyzeAgentNumber  int
	VerifierAgentNumber int
	SourceCodeDir       string
	MsgChan             chan WebMsg
}

type AgentGroup struct {
	Name      string // Agent组名称
	AgentList []*AgentOne
	Runed     bool // 是否已经运行完成
}

type AgentOne struct {
	Agent         agents.Agent
	InheritEnv    string // 从某个Agent继承关键信息，填写AgentId
	InheritVuln   string // 从某个Agent继承Vuln信息，填写AgentId
	InheritMemory string // 从某个Agent继承记忆体信息，填写AgentId
}

type AgentGroupList struct {
	AgentList []*AgentGroup
}

func (a *AgentGroupList) putAgentGroup(ag *AgentGroup) {
	a.AgentList = append(a.AgentList, ag)
}
func (a *AgentGroupList) nextAgentGroup() *AgentGroup {
	for _, one := range a.AgentList {
		if one.Runed == false {
			return one
		}
	}
	return nil
}

func NewProjectManager(project ProjectConfig) (*ProjectManager, error) {
	matched, err := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, project.ProjectName)
	if err != nil {
		return nil, fmt.Errorf("ProjectName只允许^[a-zA-Z0-9_-]+$")
	}
	if !matched {
		return nil, fmt.Errorf("ProjectName只允许^[a-zA-Z0-9_-]+$")
	}
	absDataDir, _ := filepath.Abs(misc.GetDataDir())
	projectDir := filepath.Join(absDataDir, "projects", project.ProjectName)
	err = os.MkdirAll(projectDir, 0755)
	if err != nil {
		return nil, err
	}
	sourceCodeDir := filepath.Join(projectDir, "sourceCodeDir")
	err = misc.CopyDir(project.SourceCodeDir, sourceCodeDir)
	if err != nil {
		return nil, err
	}
	pm := ProjectManager{
		wg:                  &sync.WaitGroup{},
		projectName:         project.ProjectName,
		goroutine:           make(chan func(), 100),
		analyzeAgentNumber:  project.AnalyzeAgentNumber,
		verifierAgentNumber: project.VerifierAgentNumber,
		sourceCodeDir:       sourceCodeDir,
		projectDir:          projectDir,
		agentRespList:       make(map[string]*agents.StartResp),
		reportList:          make(map[string]string),
		status:              "未运行",
		stopChan:            make(chan struct{}, 1), // 带缓冲的通道
		isStopping:          false,
		isRunning:           false,
		msgChan:             project.MsgChan,
		dm:                  dockerManager.NewDockerManager(),
	}
	pm.ctx, pm.cancelFunc = context.WithCancel(context.Background())
	pm.goroutineOps()
	return &pm, nil
}

func (pm *ProjectManager) GetDockerManager() *dockerManager.DockerManager {
	return pm.dm
}

func (pm *ProjectManager) SetMsgChan(msgChan chan WebMsg) {
	pm.msgChan = msgChan
}
func (pm *ProjectManager) AddTask(task *taskManager.Task) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	task.SetEventHandler(pm.AddEvent)
	task.SetReportHandler(pm.AddReport)
	task.SetEnvInfoHandler(pm.SetEnvInfo)
	task.SetAddTaskHandler(pm.AddTask)
	pm.tasks = append(pm.tasks, task)
}

func (pm *ProjectManager) GetProjectName() string {
	return pm.projectName
}
func (pm *ProjectManager) GetStatus() string {
	return pm.status
}
func (pm *ProjectManager) GetStartTime() string {
	return pm.startTime
}
func (pm *ProjectManager) GetEndTime() string {
	return pm.endTime
}
func (pm *ProjectManager) SetStatus(status string) {
	pm.status = status
}
func (pm *ProjectManager) GetSourceCodeDir() string {
	return pm.sourceCodeDir
}
func (pm *ProjectManager) GetProjectDir() string {
	return pm.projectDir
}

func (pm *ProjectManager) goroutineOps() {
	go func() {
		for f := range pm.goroutine {
			go func() {
				pm.wg.Add(1)
				f()
				pm.wg.Done()
			}()
		}
	}()
}

func (pm *ProjectManager) startTask() {
	if pm.isRunning {
		return
	}
	pm.status = "正在运行"
	pm.isRunning = true
	pm.isStopping = false
	defer func() {
		pm.status = "运行结束"
		pm.isRunning = false
		pm.endTime = time.Now().Format("2006-01-02 15:04:05")
	}()

	pm.startTime = time.Now().Format("2006-01-02 15:04:05")

	for {
		// 检查全局停止信号
		select {
		case <-pm.ctx.Done():
			pm.AddEvent("项目管理", "收到停止信号，退出主流程", 0)
			return
		default:
		}

		agentGroup := pm.agentGroupList.nextAgentGroup()
		if agentGroup == nil {
			break // 所有组都运行完毕
		}

		wg := &sync.WaitGroup{}
		// 计算需要启动的 agent 数量
		wg.Add(len(agentGroup.AgentList))

		for _, agent := range agentGroup.AgentList {
			// 在启动每个 agent 前再次检查
			select {
			case <-pm.ctx.Done():
				// 如果已经停止，就不需要启动新的 agent 了，但也需要伪造 wg.Done 以免死锁
				wg.Done()
				continue
			default:
			}
			t := agent.Agent.GetTask()

			if agent.InheritEnv != "" {
				pm.mu.Lock()
				x, e := pm.agentRespList[agent.InheritEnv]
				pm.mu.Unlock()
				if !e || x == nil || x.Memory == nil {
					pm.AddEvent(agent.Agent.Name(), agent.InheritEnv+"没有运行结果，所以无法继承env", 0)
				} else {
					keyMsg := x.Memory.GetKeyMessage("")
					js, _ := json.Marshal(keyMsg)
					fmt.Println("继承关键信息:" + string(js))
					agent.Agent.SetKeyMessage(keyMsg)
					t.SetEnvInfo(x.EvnInfo)

				}
			}

			if agent.InheritVuln != "" {
				pm.mu.Lock()
				x, e := pm.agentRespList[agent.InheritVuln]
				pm.mu.Unlock()
				if !e || x == nil {
					pm.AddEvent(agent.Agent.Name(), agent.InheritVuln+"没有运行结果，所以无法继承Vuln", 0)
				} else {
					t.GetVulnManager().SetVulnList(x.Vuln)
				}
			}
			if agent.InheritMemory != "" {
				pm.mu.Lock()
				x, e := pm.agentRespList[agent.InheritMemory]
				pm.mu.Unlock()
				if !e || x == nil || x.Memory == nil {
					pm.AddEvent(agent.Agent.Name(), agent.InheritMemory+"没有运行结果，所以无法继承Memory", 0)
				} else {
					agent.Agent.SetMemory(x.Memory)
				}
			}
			go func(a *AgentOne) {
				defer wg.Done()

				// 在 goroutine 内部也要第一时间检查
				select {
				case <-pm.ctx.Done():
					return
				default:
				}
				resp := a.Agent.StartTask(pm.ctx)

				if resp.Err != nil {
					// 检查是否是因为 context 取消导致的错误
					if pm.ctx.Err() != nil {
						pm.AddEvent(a.Agent.Name(), "任务被强制停止", 0)
					} else {
						misc.Warn("Agent运行错误", resp.Err.Error(), pm.AddEvent)
					}
				} else {
					pm.mu.Lock()
					pm.agentRespList[a.Agent.GetId()] = resp
					pm.mu.Unlock()
				}
			}(agent)
		}

		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			if !pm.isStopping { // 只有在没有停止信号时才标记为运行完成
				agentGroup.Runed = true
				misc.Success(agentGroup.Name, "Agent 组运行完毕", pm.AddEvent)
			}
		case <-pm.ctx.Done():
			// 收到停止信号
			misc.Warn(agentGroup.Name, "Agent组收到停止指令，等待当前任务结束...", pm.AddEvent)
			wg.Wait()
			return
		}
	}

	pm.wg.Wait()
}

func (pm *ProjectManager) StopTask() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	// 防止重复调用
	if pm.isStopping {
		return
	}
	pm.status = "正在停止"
	pm.isStopping = true
	// 关键：调用 context 的取消函数
	if pm.cancelFunc != nil {
		pm.cancelFunc()
	}
}
func (pm *ProjectManager) RemoveDockerAll() {
	for _, v := range pm.containerList {
		pm.dm.DockerRemove(v.ContainerId)
	}
}

func (pm *ProjectManager) GetGoroutine() chan func() {
	return pm.goroutine
}

func (pm *ProjectManager) AddAgent(agentList *AgentGroup) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if agentList.Name == "" {
		agentList.Name = "AgentGroup-" + uuid.New().String()
	}
	pm.agentGroupList.putAgentGroup(agentList)
}

func (pm *ProjectManager) GetContainerList() []taskManager.ContainerInfo {
	return pm.containerList
}

func (pm *ProjectManager) AddContainerInfo(infoStr string) {
	var containerInfo taskManager.ContainerInfo
	err := json.Unmarshal([]byte(infoStr), &containerInfo)
	if err != nil {
		misc.Warn("容器事件管理", "格式不正确："+infoStr, pm.AddEvent)
	}
	if containerInfo.Type == "Remove" {
		result := make([]taskManager.ContainerInfo, 0, len(pm.containerList))
		for _, container := range pm.containerList {
			if container.ContainerId != containerInfo.ContainerId {
				result = append(result, container)
			}
		}
		pm.containerList = result
		misc.Warn("容器事件", fmt.Sprintf("删除容器：%s", infoStr), pm.AddEvent)
		pm.msgChan <- WebMsg{Type: "ContainerRemove", Data: map[string]interface{}{"containerId": containerInfo.ContainerId}, ProjectName: pm.GetProjectName()}
		return
	}
	misc.Success("容器事件", fmt.Sprintf("新容器：%s", infoStr), pm.AddEvent)
	pm.msgChan <- WebMsg{Type: "ContainerAdd", Data: containerInfo, ProjectName: pm.GetProjectName()}
	pm.containerList = append(pm.containerList, containerInfo)
}

func (pm *ProjectManager) AddVulnInfo(vuln taskManager.Vuln) {
	misc.Success("漏洞事件", fmt.Sprintf("新漏洞点：%s", vuln.VulnId), pm.AddEvent)
	pm.msgChan <- WebMsg{Type: "VulnAdd", Data: vuln, ProjectName: pm.GetProjectName()}
	pm.vulnList = append(pm.vulnList, vuln)
}

func (pm *ProjectManager) UpdateVuln(id string, status string) {
	for i, candidate := range pm.vulnList {
		if candidate.VulnId == id {
			candidate.Status = status
			pm.vulnList[i] = candidate
			pm.msgChan <- WebMsg{Type: "VulnStatus", Data: map[string]interface{}{"status": status, "vuln_id": id}, ProjectName: pm.GetProjectName()}
			misc.Success("漏洞事件", fmt.Sprintf("漏洞状态更新：%s -> %s", id, status), pm.AddEvent)
		}
	}
}

func (pm *ProjectManager) AddEvent(mod string, msg string, level int) {
	timeStr := time.Now().Format("2006-01-02 15:04:05")
	msgx := WebMsg{Type: "string", Data: fmt.Sprintf("[%s][%s]: %s", timeStr, mod, msg), ProjectName: pm.GetProjectName()}
	pm.msgChan <- msgx
	pm.eventList = append(pm.eventList, msgx.Data.(string))
}

func (pm *ProjectManager) GetEvent(count int) []string {
	l := len(pm.eventList)
	if l < count || l == 0 {
		return pm.eventList
	}
	return pm.eventList[l-count:]
}

func (pm *ProjectManager) GetVulnList() []taskManager.Vuln {
	return pm.vulnList
}
func (pm *ProjectManager) SetVulns(vuln []taskManager.Vuln) {
	pm.vulnList = vuln
}
func (pm *ProjectManager) SetEvent(event []string) {
	pm.eventList = event
}
func (pm *ProjectManager) SetContainer(cl []taskManager.ContainerInfo) {
	pm.containerList = cl
}
func (pm *ProjectManager) SetProjectDir(dir string) {
	pm.projectDir = dir
}
func (pm *ProjectManager) SetStartTime(t string) {
	pm.startTime = t
}
func (pm *ProjectManager) SetEndTime(t string) {
	pm.endTime = t
}
func (pm *ProjectManager) SetReport(reportList map[string]string) {
	pm.reportList = reportList
}

func (pm *ProjectManager) GetReportList() map[string]string {
	return pm.reportList
}
func (pm *ProjectManager) AddReport(vid string, path string) {
	pm.msgChan <- WebMsg{Type: "ReportAdd", Data: map[string]interface{}{vid: filepath.Base(path)}, ProjectName: pm.GetProjectName()}
	pm.reportList[vid] = path
}
func (pm *ProjectManager) SetEnvInfo(env map[string]interface{}) {
	pm.msgChan <- WebMsg{Type: "EnvInfo", Data: env, ProjectName: pm.GetProjectName()}
	pm.envInfo = env
}
func (pm *ProjectManager) GetEnvInfo() map[string]interface{} {
	return pm.envInfo
}
