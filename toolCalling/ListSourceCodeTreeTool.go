package toolCalling

import (
	"AIxVuln/misc"
	"AIxVuln/taskManager"
	"strings"
)

type ListSourceCodeTreeTool struct {
	task *taskManager.Task
}

func NewListSourceCodeTreeTool(task *taskManager.Task) *ListSourceCodeTreeTool {
	return &ListSourceCodeTreeTool{task: task}
}

func (h *ListSourceCodeTreeTool) Name() string {
	return "ListSourceCodeTreeTool"
}
func (h *ListSourceCodeTreeTool) Description() string {
	return "Scan the specified source code directory and generate a visualized directory tree structure. This feature is specifically designed for code analysis tasks, capable of recursively listing directory contents and clearly distinguishing between files and folders. You can use this functionality to quickly understand the macro structure of a project, the distribution of files, or the organization within specific directories, facilitating subsequent code reviews, architecture analysis, or file localization."
}
func (h *ListSourceCodeTreeTool) Parameters() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"path": map[string]interface{}{
				"type":        "string",
				"description": "Directory path to list (based on `/sourceCodeDir`. For example, for `/sourceCodeDir`, simply input `./`).(required)",
			},
			"maxDepth": map[string]interface{}{
				"type":        "integer",
				"description": "Directory listing depth (recursive subdirectory depth).(optional).",
				"minimum":     1,
				"default":     1,
			},
		},
	}
}

func (h *ListSourceCodeTreeTool) Execute(parameters map[string]interface{}) string {
	pathTemp := parameters["path"]
	if pathTemp == nil {
		return Fail("Missing 'path' parameter")
	}
	path := pathTemp.(string)
	maxDepthTemp := parameters["maxDepth"]
	var maxDepth = 1
	if maxDepthTemp != nil {
		maxDepth, _ = misc.GetIntParam(maxDepthTemp)
	}
	if strings.HasPrefix(path, "/sourceCodeDir") {
		path = strings.TrimPrefix(path, "/sourceCodeDir")
	}
	path = h.task.GetSm().GetSourceCodePath() + "/" + path
	r, e := misc.ListSourceCodeTree(path, maxDepth)
	if e != nil {
		return Fail(e.Error())
	}
	return Success(r)
}
