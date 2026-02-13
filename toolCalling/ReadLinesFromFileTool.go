package toolCalling

import (
	"AIxVuln/misc"
	"AIxVuln/taskManager"
	"strings"
)

type ReadLinesFromFileTool struct {
	task *taskManager.Task
}

func NewReadLinesFromFileTool(task *taskManager.Task) *ReadLinesFromFileTool {
	return &ReadLinesFromFileTool{task: task}
}

func (h *ReadLinesFromFileTool) Name() string {
	return "ReadLinesFromFileTool"
}
func (h *ReadLinesFromFileTool) Description() string {
	return "Recursively search the contents of all files in the specified directory, find code lines that match the regular expression, and return the results in JSON format. This feature is used for code auditing, locating specific function calls, or variable definitions."
}
func (h *ReadLinesFromFileTool) Parameters() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"path": map[string]interface{}{
				"type":        "string",
				"description": "File path that needs to be read. (based on `/sourceCodeDir`. For example, for `/sourceCodeDir/a.txt`, simply input `./a.txt`).(required)",
			},
			"lineNumber": map[string]interface{}{
				"type":        "integer",
				"description": "Starting line number to read from.(required).",
				"minimum":     1,
			},
			"lineCount": map[string]interface{}{
				"type":        "integer",
				"description": "Number of lines to read.(required).",
				"minimum":     1,
				"default":     5,
				"maximum":     20,
			},
		},
	}
}

func (h *ReadLinesFromFileTool) Execute(parameters map[string]interface{}) string {
	pathTemp := parameters["path"]
	if pathTemp == nil {
		return Fail("Missing 'path' parameter")
	}
	path := pathTemp.(string)
	root := h.task.GetSourceCodePath()
	var lineNumber int
	var lineCount int
	lineNumberTemp := parameters["lineNumber"]
	if lineNumberTemp == nil {
		return Fail("lineNumber parameter should not empty")
	}
	lineNumber, _ = misc.GetIntParam(lineNumberTemp)

	lineCountTemp := parameters["lineCount"]
	if lineCountTemp == nil {
		return Fail("lineCount parameter should not empty")
	}
	lineCount, _ = misc.GetIntParam(lineCountTemp)

	if strings.HasPrefix(path, "/sourceCodeDir") {
		path = strings.TrimPrefix(path, "/sourceCodeDir")
	}
	path = root + "/" + path
	r, e := misc.ReadLinesFromFile(path, lineNumber, lineCount)
	if e != nil {
		return Fail(sanitizeTextPaths(root, e.Error()))
	}
	return Success(r)
}
