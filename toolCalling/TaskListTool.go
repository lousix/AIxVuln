package toolCalling

import (
	"AIxVuln/taskManager"
	"strconv"
	"strings"
)

type TaskListTool struct {
	task *taskManager.Task
}

func NewTaskListTool(task *taskManager.Task) *TaskListTool {
	return &TaskListTool{task: task}
}

func (h *TaskListTool) Name() string {
	return "TaskListTool"
}
func (h *TaskListTool) Description() string {
	return "Used to confirm the completion of a subtask and return the current task list status."
}
func (h *TaskListTool) Parameters() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"TaskID": map[string]interface{}{
				"type":        "string",
				"description": "TaskID.(required)",
			},
			"TaskStatus": map[string]interface{}{
				"type":        "string",
				"enum":        []string{"Completed", "Discarded"},
				"description": "Task status needs to be set.(required)",
			},
			"Reason": map[string]interface{}{
				"type":        "string",
				"description": "Reasons for Not Completed / Currently Required to Complete / Completed / Discarded.(required)",
			},
		},
	}
}

func (h *TaskListTool) Execute(parameters map[string]interface{}) string {
	TaskIDTemp := parameters["TaskID"]
	if TaskIDTemp == nil {
		return Fail("Missing 'TaskID' parameter")
	}
	TaskIDStr := TaskIDTemp.(string)
	if len(TaskIDStr) < 3 {
		return Fail("TaskID too short")
	}

	TaskID, err := strconv.Atoi(strings.TrimPrefix(TaskIDStr, "T."))
	if err != nil {
		return Fail(err.Error())
	}

	TaskStatusTemp := parameters["TaskStatus"]
	if TaskStatusTemp == nil {
		return Fail("Missing 'TaskStatus' parameter")
	}
	TaskStatus := TaskStatusTemp.(string)
	ReasonTemp := parameters["Reason"]
	if ReasonTemp == nil {
		return Fail("Missing 'Reason' parameter")
	}
	Reason := ReasonTemp.(string)
	taskList := h.task.GetTaskList()
	if taskList[TaskID] == nil {
		return Fail("TaskID not found")
	}
	taskList[TaskID]["TaskStatus"] = TaskStatus
	taskList[TaskID]["Reason"] = Reason
	if len(taskList) > TaskID+1 {
		(taskList)[TaskID+1]["TaskStatus"] = "Currently Required to Complete"
	}
	h.task.SetTaskList(taskList)
	//js, _ := json.MarshalIndent(h.taskList, "", "  ")
	//log.Println("任务列表状态更新: " + string(js))
	return Success(taskList)
}
