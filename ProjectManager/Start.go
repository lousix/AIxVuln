package ProjectManager

import (
	"AIxVuln/agents"
	"AIxVuln/llm"
	"AIxVuln/misc"
	"AIxVuln/taskManager"
)

// 全流程挖掘任务
func (pm *ProjectManager) StartCommonVulnTask() {
	defer pm.SetStatus("运行结束")
	dm := pm.GetDockerManager()
	dm.SetEventHandler(pm.AddContainerInfo)
	sourceCodeDir := pm.sourceCodeDir
	sandbox := taskManager.NewSandbox(dm, sourceCodeDir)
	vulns := taskManager.NewVulnManager()
	vulns.SetVulnAddEventHandler(pm.AddVulnInfo)
	vulns.SetVulnUpdateEventHandler(pm.UpdateVuln)
	vulns.SetEventHandler(pm.AddEvent)
	ag := &AgentGroup{}
	opsTask := taskManager.NewTask(pm.GetProjectDir(), misc.GetCommonOpsTaskList(), sandbox, taskManager.NewVulnManager(), pm.GetGoroutine(), pm.GetProjectName())
	pm.AddTask(opsTask)
	ops := agents.NewOpsCommonAgent(opsTask)
	opsId := ops.GetId()
	ao := &AgentOne{Agent: ops}
	ag.AgentList = append(ag.AgentList, ao)
	analyzeSharedMemory := llm.NewSharedContext()
	analyzeSharedMemory.SetEventHandler(pm.AddEvent)
	for i := 0; i < pm.analyzeAgentNumber; i++ {
		taskList := misc.GetCommonAnalyzeTaskList("")
		if i == 1 {
			taskList = misc.GetCommonAnalyzeTaskList("authentication, authorization bypass, and unauthorized access")
		}
		if i == 2 {
			taskList = misc.GetCommonAnalyzeTaskList("Other vulnerabilities besides authentication, unauthorized access, and IDOR")
		}
		analyzeTask := taskManager.NewTask(pm.projectDir, taskList, sandbox, vulns, pm.GetGoroutine(), pm.GetProjectName())
		pm.AddTask(analyzeTask)
		analyzeTask.SetMemory(analyzeSharedMemory)
		analyze := agents.NewAnalyzeCommonAgent(analyzeTask, false)
		ag.AgentList = append(ag.AgentList, &AgentOne{Agent: analyze})
	}
	pm.AddAgent(ag)
	// 必须运行完成才能获得搭建好的环境信息，因此放到另一个AgentGroup
	verifierSharedMemory := llm.NewSharedContext()
	verifierSharedMemory.SetEventHandler(pm.AddEvent)
	as1 := &AgentGroup{}
	for i := 0; i < pm.verifierAgentNumber; i++ {
		verifierTask := taskManager.NewTask(pm.GetProjectDir(), nil, sandbox, vulns, pm.GetGoroutine(), pm.GetProjectName())
		pm.AddTask(verifierTask)
		verifierTask.SetMemory(verifierSharedMemory)
		verifierAgent := agents.NewVerifierCommonAgent(verifierTask)
		as1.AgentList = append(as1.AgentList, &AgentOne{Agent: verifierAgent, InheritEnv: opsId})
	}
	pm.AddAgent(as1)
	pm.startTask()
}

// 仅代码分析任务
func (pm *ProjectManager) StartAnalyzeTask() {
	defer pm.SetStatus("运行结束")
	sandbox := &taskManager.Sandbox{SourceCodeDir: pm.sourceCodeDir}
	vulns := taskManager.NewVulnManager()
	vulns.SetVulnAddEventHandler(pm.AddVulnInfo)
	vulns.SetVulnUpdateEventHandler(pm.UpdateVuln)
	vulns.SetEventHandler(pm.AddEvent)
	ag := &AgentGroup{}
	analyzeSharedMemory := llm.NewSharedContext()
	analyzeSharedMemory.SetEventHandler(pm.AddEvent)
	for i := 0; i < pm.analyzeAgentNumber; i++ {
		taskList := misc.GetCommonAnalyzeTaskList("")
		if i == 1 {
			taskList = misc.GetCommonAnalyzeTaskList("authentication, authorization bypass, and unauthorized access")
		}
		if i == 2 {
			taskList = misc.GetCommonAnalyzeTaskList("Other vulnerabilities besides authentication, unauthorized access, and IDOR")
		}
		analyzeTask := taskManager.NewTask(pm.projectDir, taskList, sandbox, vulns, pm.GetGoroutine(), pm.GetProjectName())
		analyzeTask.SetMaxVulnCount(30)
		pm.AddTask(analyzeTask)
		analyzeTask.SetMemory(analyzeSharedMemory)
		analyze := agents.NewAnalyzeCommonAgent(analyzeTask, true)
		ag.AgentList = append(ag.AgentList, &AgentOne{Agent: analyze})
	}
	pm.AddAgent(ag)
	pm.startTask()
}
