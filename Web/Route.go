package Web

import (
	"AIxVuln/ProjectManager"
	"AIxVuln/misc"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func (s *Server) getPms(c *gin.Context) {
	var res []string
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, v := range s.pms {
		res = append(res, v.GetProjectName())
	}
	c.JSON(200, Success(res))
}

func (s *Server) containerList(c *gin.Context) {
	s.mu.RLock()
	pm, exists := s.pms[c.Param("name")]
	s.mu.RUnlock()
	if !exists {
		c.JSON(404, Fail("project not found"))
		return
	}
	var cl []Container
	for _, co := range pm.GetContainerList() {
		if len(co.WebPort) > 0 {
			cl = append(cl, Container{ContainerId: co.ContainerId, ContainerIP: co.ContainerIP, Image: co.Image, WebPort: co.WebPort})
		} else {
			cl = append(cl, Container{ContainerId: co.ContainerId, ContainerIP: co.ContainerIP, Image: co.Image, WebPort: nil})
		}

	}
	c.JSON(200, Success(cl))
}

func (s *Server) vulnList(c *gin.Context) {
	s.mu.RLock()
	pm, exists := s.pms[c.Param("name")]
	s.mu.RUnlock()
	if !exists {
		c.JSON(404, Fail("project not found"))
		return
	}
	c.JSON(200, Success(pm.GetVulnList()))
}

func (s *Server) eventList(c *gin.Context) {
	s.mu.RLock()
	pm, exists := s.pms[c.Param("name")]
	s.mu.RUnlock()
	if !exists {
		c.JSON(404, Fail("project not found"))
		return
	}
	count := c.DefaultQuery("count", "50")
	countInt, err := strconv.Atoi(count)
	if err != nil {
		c.JSON(400, Fail("count not int"))
		return
	}
	c.JSON(200, Success(pm.GetEvent(countInt)))
}

func (s *Server) reportList(c *gin.Context) {
	s.mu.RLock()
	pm, exists := s.pms[c.Param("name")]
	s.mu.RUnlock()
	if !exists {
		c.JSON(404, Fail("project not found"))
		return
	}
	report := make(map[string]string)
	for k, v := range pm.GetReportList() {
		report[k] = filepath.Base(v)
	}
	c.JSON(200, Success(report))
}

func (s *Server) downloadReport(c *gin.Context) {
	s.mu.RLock()
	pm, exists := s.pms[c.Param("name")]
	s.mu.RUnlock()
	if !exists {
		c.JSON(404, Fail("project not found"))
		return
	}
	reportList := pm.GetReportList()
	id := c.Param("id")
	p, e := reportList[id]
	if !e {
		c.JSON(404, Fail("report not found"))
		return
	}
	_, err := os.Stat(p)
	if err != nil {
		c.JSON(404, Fail("file not found"))
	}
	c.Header("Content-Disposition", "attachment; filename="+filepath.Base(p))
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Transfer-Encoding", "binary")
	c.File(p)
}

func (s *Server) downloadReportAll(c *gin.Context) {
	s.mu.RLock()
	pm, exists := s.pms[c.Param("name")]
	s.mu.RUnlock()
	if !exists {
		c.JSON(404, Fail("project not found"))
		return
	}
	reportDir := filepath.Join(pm.GetProjectDir(), "vulns")
	tempDir, err := filepath.Abs(filepath.Join(misc.GetDataDir(), "temp"))
	if err != nil {
		c.JSON(400, Fail("get temp zipfile error"))
		return
	}
	tempZipfile := filepath.Join(tempDir, uuid.New().String()+".zip")
	err = misc.ZipDirectory(reportDir, tempZipfile)
	if err != nil {
		c.JSON(400, Fail("zip file error"))
		return
	}
	defer os.Remove(tempZipfile)
	c.Header("Content-Disposition", "attachment; filename="+pm.GetProjectName()+"-report.zip")
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Transfer-Encoding", "binary")
	c.File(tempZipfile)
}

func (s *Server) getProject(c *gin.Context) {
	res := make(map[string]any)
	s.mu.RLock()
	pm, exists := s.pms[c.Param("name")]
	s.mu.RUnlock()
	if !exists {
		c.JSON(404, Fail("project not found"))
		return
	}
	res["projectName"] = pm.GetProjectName()
	var cl []Container
	for _, co := range pm.GetContainerList() {
		cl = append(cl, Container{ContainerId: co.ContainerId, ContainerIP: co.ContainerIP, Image: co.Image, WebPort: co.WebPort})
	}
	res["containerList"] = cl
	res["eventLog"] = pm.GetEvent(50)
	res["vulnList"] = pm.GetVulnList()
	report := make(map[string]string)
	for k, v := range pm.GetReportList() {
		report[k] = filepath.Base(v)
	}
	res["reportList"] = report
	res["status"] = pm.GetStatus()
	res["startTime"] = pm.GetStartTime()
	res["endTime"] = pm.GetEndTime()
	res["EnvInfo"] = pm.GetEnvInfo()
	c.JSON(200, Success(res))
}
func (s *Server) createProject(c *gin.Context) {
	projectName := c.DefaultQuery("projectName", "project-"+uuid.New().String())
	matched, err := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, projectName)
	if err != nil {
		c.JSON(400, Fail("ProjectName只允许^[a-zA-Z0-9_-]+$"))
		return
	}
	if !matched {
		c.JSON(400, Fail("ProjectName只允许^[a-zA-Z0-9_-]+$"))
		return
	}

	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(400, Fail(err.Error()))
		return
	}
	ext := filepath.Ext(file.Filename)
	tempFile, err := os.CreateTemp("", "upload-*."+ext)
	if err != nil {
		c.JSON(500, Fail("创建临时文件失败"))
		return
	}
	defer os.Remove(tempFile.Name()) // 处理完成后删除临时文件
	defer tempFile.Close()
	src, err := file.Open()
	if err != nil {
		c.JSON(500, Fail("打开上传文件失败"))
		return
	}
	defer src.Close()

	if _, err := io.Copy(tempFile, src); err != nil {
		c.JSON(500, Fail("保存上传文件失败"))
		return
	}
	absPath, err := filepath.Abs(misc.GetDataDir())
	if err != nil {
		c.JSON(500, Fail("获取DataDir"))
		return
	}
	tempDir := filepath.Join(absPath, "temp", uuid.New().String())
	defer os.RemoveAll(tempDir)
	err = UncompressFile(tempFile.Name(), tempDir)
	if err != nil {
		c.JSON(500, Fail(err.Error()))
		return
	}

	projectConfig := ProjectManager.ProjectConfig{ProjectName: projectName, AnalyzeAgentNumber: 3, VerifierAgentNumber: 3, SourceCodeDir: tempDir, MsgChan: s.msgChan}
	pm, err := ProjectManager.NewProjectManager(projectConfig)
	if err != nil {
		c.JSON(500, Fail(err.Error()))
		return
	}
	s.mu.Lock()
	s.pms[projectName] = pm
	s.mu.Unlock()
	s.SaveProjectManagerToFile()
	c.JSON(200, Success("成功新建项目"))
}

func (s *Server) startProject(c *gin.Context) {
	s.mu.RLock()
	pm, exists := s.pms[c.Param("name")]
	s.mu.RUnlock()
	if !exists {
		c.JSON(404, Fail("project not found"))
		return
	}
	startType := c.DefaultQuery("startType", "0")
	if startType == "0" {
		go pm.StartCommonVulnTask()
	} else if startType == "1" {
		go pm.StartAnalyzeTask()
	} else {
		c.JSON(400, Fail("指定类型错误"))
	}
	c.JSON(200, Success("项目开始运行"))
}
func (s *Server) cancelProject(c *gin.Context) {
	s.mu.RLock()
	pm, exists := s.pms[c.Param("name")]
	s.mu.RUnlock()
	if !exists {
		c.JSON(404, Fail("project not found"))
		return
	}
	go pm.StopTask()
	c.JSON(200, Success("项目已经取消"))
}
func (s *Server) getEnvInfo(c *gin.Context) {
	s.mu.RLock()
	pm, exists := s.pms[c.Param("name")]
	s.mu.RUnlock()
	if !exists {
		c.JSON(404, Fail("project not found"))
		return
	}
	c.JSON(200, Success(pm.GetEnvInfo()))
}

func (s *Server) delProject(c *gin.Context) {
	s.mu.RLock()
	pm, exists := s.pms[c.Param("name")]
	s.mu.RUnlock()
	if !exists {
		c.JSON(404, Fail("project not found"))
		return
	}
	pm.StopTask()
	pm.RemoveDockerAll()
	s.mu.Lock()
	delete(s.pms, pm.GetProjectName())
	s.mu.Unlock()
	s.SaveProjectManagerToFile()
	c.JSON(200, Success("删除成功"))
}
