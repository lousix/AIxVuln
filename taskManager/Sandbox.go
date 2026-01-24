package taskManager

import (
	"AIxVuln/dockerManager"
	"AIxVuln/llm"
	"log"
)

type Sandbox struct {
	ContainerId   string
	ContainerIp   string
	dm            *dockerManager.DockerManager
	SourceCodeDir string
	sandboxEnvMsg llm.EnvMessageX
}

func NewSandbox(dm *dockerManager.DockerManager, sourceCodeDir string) *Sandbox {
	r, err := dm.Run("aisandbox", nil, 10, dockerManager.SetVolume(sourceCodeDir, "/sourceCodeDir"))
	if err != nil {
		log.Fatalf("Error running aisandbox: %s", err)
	}
	s := &Sandbox{ContainerId: r.ContainerID, ContainerIp: r.IPAddress, dm: dm, SourceCodeDir: sourceCodeDir}
	s.sandboxEnvMsg = llm.EnvMessageX{Key: "AttackSandBoxInfo", Content: map[string]interface{}{"ContainerId": s.ContainerId, "ContainerIP": s.ContainerIp}, AppendEnv: false}
	return s
}

func (s *Sandbox) GetSandboxEnvMsg() *llm.EnvMessageX {
	return &s.sandboxEnvMsg
}

func (s *Sandbox) RunCommand(command []string, timeOutSecond int16) (string, error) {
	r, err := s.dm.DockerExec(s.ContainerId, command, timeOutSecond)
	if err != nil {
		return "", err
	}
	return r, nil
}
