package toolCalling

import (
	"AIxVuln/taskManager"
	"io/fs"
	"path/filepath"
	"strings"
)

type ProjectType string

const (
	Java    ProjectType = "Java"
	PHP     ProjectType = "PHP"
	Python  ProjectType = "Python"
	NodeJS  ProjectType = "NodeJS"
	Golang  ProjectType = "Go"
	Rust    ProjectType = "Rust"
	Unknown ProjectType = "Unknown"
)

var packageManagers = map[ProjectType][]string{
	Java:   {"pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"},
	PHP:    {"composer.json", "composer.lock"},
	Python: {"requirements.txt", "Pipfile", "pyproject.toml", "setup.py", "poetry.lock"},
	NodeJS: {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"},
	Golang: {"go.mod", "go.sum"},
	Rust:   {"Cargo.toml", "Cargo.lock"},
}

// 文件扩展名映射
var fileExtensions = map[ProjectType][]string{
	Java:   {".java", ".jsp", ".class", ".jar"},
	PHP:    {".php", ".php3", ".php4", ".php5", ".php7", ".phtml"},
	Python: {".py", ".pyc", ".pyo", ".pyd", ".pyw"},
	NodeJS: {".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte"},
	Golang: {".go"},
	Rust:   {".rs", ".rlib"},
}

var nodeStrongIndicators = map[string]struct{}{
	"package.json":       {},
	"package-lock.json":  {},
	"yarn.lock":          {},
	"pnpm-lock.yaml":     {},
	"node_modules":       {},
	"tsconfig.json":      {},
	"deno.json":          {},
	"deno.jsonc":         {},
	"bun.lockb":          {},
	"bun.lock":           {},
	"vite.config.js":     {},
	"vite.config.ts":     {},
	"next.config.js":     {},
	"next.config.mjs":    {},
	"next.config.ts":     {},
	"nuxt.config.js":     {},
	"nuxt.config.ts":     {},
	"svelte.config.js":   {},
	"astro.config.mjs":   {},
	"astro.config.ts":    {},
	"angular.json":       {},
	"vue.config.js":      {},
	"webpack.config.js":  {},
	"webpack.config.ts":  {},
	"rollup.config.js":   {},
	"rollup.config.ts":   {},
	"esbuild.config.js":  {},
	"esbuild.config.ts":  {},
	"nx.json":            {},
	"lerna.json":         {},
	"turbo.json":         {},
	".nvmrc":             {},
	".node-version":      {},
}

type DetectLanguageTool struct {
	task *taskManager.Task
}

func NewDetectLanguageTool(task *taskManager.Task) *DetectLanguageTool {
	return &DetectLanguageTool{task: task}
}

func (h *DetectLanguageTool) Name() string {
	return "DetectLanguageTool"
}
func (h *DetectLanguageTool) Description() string {
	return "return the project's language type."
}
func (h *DetectLanguageTool) Parameters() map[string]interface{} {
	return map[string]interface{}{
		"type":       "object",
		"properties": map[string]interface{}{},
	}
}

func (h *DetectLanguageTool) Execute(parameters map[string]interface{}) string {
	return Success(string(DetectProjectType(h.task.GetSourceCodePath())))
}

func DetectProjectType(rootPath string) ProjectType {
	typeScores := make(map[ProjectType]int)
	nodeStrong := false

	// 遍历目录
	err := filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // 跳过无法访问的文件
		}

		// 检查包管理文件
		baseName := d.Name()
		if _, ok := nodeStrongIndicators[baseName]; ok {
			nodeStrong = true
		}
		for projectType, files := range packageManagers {
			for _, file := range files {
				if baseName == file {
					typeScores[projectType] += 10 // 包管理文件权重较高
					break
				}
			}
		}

		// 检查文件扩展名
		if !d.IsDir() {
			ext := strings.ToLower(filepath.Ext(baseName))
			for projectType, exts := range fileExtensions {
				if projectType == NodeJS && !nodeStrong {
					continue
				}
				for _, extension := range exts {
					if ext == extension {
						typeScores[projectType] += 1
						break
					}
				}
			}
		}

		return nil
	})

	if err != nil {
		return Unknown
	}

	// 找出分数最高的项目类型
	maxScore := 0
	var detectedType ProjectType = Unknown

	for projectType, score := range typeScores {
		if score > maxScore {
			maxScore = score
			detectedType = projectType
		}
	}

	// 如果没有检测到任何特征，返回Unknown
	if maxScore == 0 {
		return Unknown
	}

	return detectedType
}
