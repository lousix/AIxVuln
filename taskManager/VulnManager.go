package taskManager

import (
	"AIxVuln/misc"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

type Vuln struct {
	Confidence       string `json:"confidence"`
	ExpectedImpact   string `json:"expected_impact"`
	File             string `json:"file"`
	FunctionOrMethod string `json:"function_or_method"`
	Params           string `json:"params"`
	PayloadIdea      string `json:"payload_idea"`
	RouteOrEndpoint  string `json:"route_or_endpoint"`
	Status           string `json:"status"`
	Title            string `json:"title"`
	Type             string `json:"type"`
	VulnId           string `json:"vuln_id"`
}
type VulnManager struct {
	index                  int
	mu                     sync.RWMutex
	vulns                  []Vuln
	vulnAddEventHandler    func(Vuln)
	vulnUpdateEventHandler func(string, string)
	EventHandler           func(string, string, int)
}

func NewVulnManager() *VulnManager {
	return &VulnManager{}
}

func (vm *VulnManager) GetVulnList() []Vuln {
	return vm.vulns
}
func (vm *VulnManager) SetVulnList(vs []Vuln) {
	vm.vulns = vs
}
func (vm *VulnManager) SetVulnAddEventHandler(f func(vuln Vuln)) {
	vm.vulnAddEventHandler = f
}
func (vm *VulnManager) SetVulnUpdateEventHandler(f func(string, string)) {
	vm.vulnUpdateEventHandler = f
}
func (vm *VulnManager) SetEventHandler(f func(string, string, int)) {
	vm.EventHandler = f
}
func (vm *VulnManager) AddVulns(vuln Vuln) string {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	vuln.Status = "To be verified"
	vuln.VulnId = "V." + strconv.Itoa(vm.index)
	vm.vulns = append(vm.vulns, vuln)
	vm.vulnAddEventHandler(vuln)
	vm.index++
	return vuln.VulnId
}
func (vm *VulnManager) HasVulnByFileAndParams(file, params string) bool {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	file = strings.TrimSpace(file)
	file = strings.TrimPrefix(file, "/")
	file = strings.TrimPrefix(file, ".")
	params = strings.TrimSpace(params)
	params = strings.ReplaceAll(params, " ", "")
	params = strings.ReplaceAll(params, ",", "")
	params = strings.ReplaceAll(params, "|", "")
	params = strings.ReplaceAll(params, "\"", "")
	params = strings.ReplaceAll(params, "'", "")

	for _, vuln := range vm.vulns {
		file1 := strings.TrimSpace(vuln.File)
		file1 = strings.TrimPrefix(file1, "/")
		file1 = strings.TrimPrefix(file1, ".")
		params1 := strings.TrimSpace(vuln.Params)
		params1 = strings.ReplaceAll(params1, " ", "")
		params1 = strings.ReplaceAll(params1, ",", "")
		params1 = strings.ReplaceAll(params1, "|", "")
		params1 = strings.ReplaceAll(params1, "\"", "")
		params1 = strings.ReplaceAll(params1, "'", "")
		if file1 == file && params1 == params {
			return true
		}
	}
	return false
}
func (vm *VulnManager) UpdateVuln(id string, status string) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	flag := false
	for i, candidate := range vm.vulns {
		if candidate.VulnId == id {
			candidate.Status = status
			vm.vulns[i] = candidate
			vm.vulnUpdateEventHandler(id, status)
			flag = true
		}
	}
	if !flag {
		return errors.New("candidate not found")
	}
	return nil
}

func (vm *VulnManager) GetOneCandidate() (Vuln, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	for i, candidate := range vm.vulns {
		if candidate.Status == "To be verified" {
			candidate.Status = "Verifying"
			vm.vulns[i] = candidate
			misc.Info("Agent领取任务", fmt.Sprintf("漏洞验证任务派发：%v", candidate), vm.EventHandler)
			return vm.vulns[i], nil
		}
	}
	return Vuln{}, errors.New("All vulnerabilities have been verified and completed; the task is now ending")
}
