package misc

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

type TreeNode struct {
	Name     string      // 名称
	IsDir    bool        // 是否为目录
	Children []*TreeNode // 子节点
}

// ListSourceCodeTree 接收源码路径和列出深度，返回格式化的目录树字符串
// rootPath: 源码根目录路径
// maxDepth: 列出的最大深度（0 表示仅列出根目录本身）
func ListSourceCodeTree(rootPath string, maxDepth int) (string, error) {
	// 校验路径是否存在且可访问
	fileInfo, err := os.Stat(rootPath)
	if err != nil {
		return "", fmt.Errorf("路径访问失败: %v", err)
	}
	if !fileInfo.IsDir() {
		return "", fmt.Errorf("指定路径不是目录")
	}

	// 构建目录树结构
	root, err := buildTree(rootPath, 0, maxDepth)
	if err != nil {
		return "", err
	}

	// 将树结构转换为可视化字符串
	return root.String(), nil
}

// buildTree 递归构建目录树
func buildTree(path string, currentDepth int, maxDepth int) (*TreeNode, error) {
	// 获取当前文件/目录信息
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	node := &TreeNode{
		Name:  info.Name(),
		IsDir: info.IsDir(),
	}

	// 如果是目录且未达到最大深度，则继续递归
	if info.IsDir() && currentDepth < maxDepth {
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}

		for _, entry := range entries {
			fullPath := filepath.Join(path, entry.Name())
			child, err := buildTree(fullPath, currentDepth+1, maxDepth)
			if err != nil {
				// 遇到错误可以根据需求选择跳过或返回，这里选择跳过无权限访问的文件
				continue
			}
			node.Children = append(node.Children, child)
		}
	}

	return node, nil
}

// String 生成树状结构的字符串表示
func (n *TreeNode) String() string {
	var sb strings.Builder
	n.buildString(&sb, "", true)
	return sb.String()
}

// buildString 递归辅助函数，用于生成带缩进和连接符的字符串
func (n *TreeNode) buildString(sb *strings.Builder, prefix string, isLast bool) {
	// 确定当前节点的前缀符号
	connector := "├── "
	if isLast {
		connector = "└── "
	}

	// 确定文件类型标识
	typeMarker := ""
	if n.IsDir {
		typeMarker = "[DIR]"
	} else {
		typeMarker = "[FILE]"
	}

	sb.WriteString(prefix + connector + n.Name + " " + typeMarker + "\n")

	// 计算子节点的前缀
	childPrefix := prefix
	if isLast {
		childPrefix += "    "
	} else {
		childPrefix += "│   "
	}

	// 递归打印子节点
	for i, child := range n.Children {
		isLastChild := (i == len(n.Children)-1)
		child.buildString(sb, childPrefix, isLastChild)
	}
}

type MatchResult struct {
	FilePath string `json:"file_path"` // 匹配所在的文件路径
	LineNum  int    `json:"line_num"`  // 匹配所在的行号（从1开始）
	Content  string `json:"content"`   // 匹配的单行内容
}

// SearchFileContentsByRegex 递归搜索目录下的文件内容
// rootPath: 搜索的根目录路径
// patternStr: 正则表达式字符串
func SearchFileContentsByRegex(rootPath string, patternStr string) ([]MatchResult, error) {
	// 1. 编译正则表达式
	regex, err := regexp.Compile(patternStr)
	if err != nil {
		return nil, fmt.Errorf("无效的正则表达式: %v", err)
	}

	// 2. 遍历文件系统
	var results []MatchResult
	var mu sync.Mutex // 保护 results 切片的并发写入

	err = filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
		// 处理访问路径时的错误（如权限不足）
		if err != nil {
			// 记录错误或跳过，这里选择跳过但打印日志（实际生产中可使用 log 包）
			return nil
		}

		// 跳过目录，只处理文件
		if d.IsDir() {
			return nil
		}

		// (可选) 跳过隐藏文件或特定二进制文件（如 .git, node_modules 等）
		// if shouldSkipFile(path) { return nil }

		// 读取文件内容
		content, err := os.ReadFile(path)
		if err != nil {
			// 如果无法读取文件（可能是二进制文件或权限问题），跳过
			return nil
		}

		// 按行分割内容
		lines := bytes.Split(content, []byte{'\n'})

		// 遍历每一行进行匹配
		for lineNum, lineBytes := range lines {
			// 将行转换为字符串进行正则匹配
			lineStr := string(lineBytes)

			// 如果正则匹配成功
			if regex.MatchString(lineStr) {
				mu.Lock()
				results = append(results, MatchResult{
					FilePath: path,
					LineNum:  lineNum + 1, // 行号通常从 1 开始
					Content:  lineStr,
				})
				mu.Unlock()
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("遍历目录失败: %v", err)
	}

	return results, nil
}

// ReadLinesFromFile 读取文件中从指定行号开始的 N 行内容
// filePath: 文件路径
// startLine: 起始行号（从 1 开始）
// lineCount: 需要读取的行数
// 返回: 读取到的文本内容（按行分割的数组），以及可能的错误
func ReadLinesFromFile(filePath string, startLine int, lineCount int) ([]string, error) {
	// 参数校验
	if startLine < 1 {
		return nil, errors.New("起始行号必须大于或等于 1")
	}
	if lineCount < 1 {
		return nil, errors.New("读取行数必须大于或等于 1")
	}

	// 打开文件
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("无法打开文件: %v", err)
	}
	defer file.Close()

	// 创建扫描器
	scanner := bufio.NewScanner(file)

	// 防止单行内容过大导致内存溢出（可选，根据需求调整 buffer 大小）
	// const maxCapacity = 1024 * 1024 // 1MB
	// buf := make([]byte, maxCapacity)
	// scanner.Buffer(buf, maxCapacity)

	currentLine := 1
	var results []string
	hasStartedReading := false

	// 逐行扫描
	for scanner.Scan() {
		// 如果当前行号小于起始行，跳过
		if currentLine < startLine {
			currentLine++
			continue
		}

		// 已经到达起始行，开始读取
		hasStartedReading = true

		// 去除行尾的换行符（Scanner 默认不包含换行符，但如果有\r需手动处理）
		lineText := strings.TrimRight(scanner.Text(), "\r")
		results = append(results, lineText)

		// 如果读取数量达到要求，停止扫描
		if len(results) >= lineCount {
			break
		}

		currentLine++
	}

	// 检查扫描过程中是否出错
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取文件内容时出错: %v", err)
	}

	// 边界情况处理：如果 startLine 超过了文件总行数
	if !hasStartedReading {
		return nil, fmt.Errorf("起始行号 %d 超出了文件总行数 (%d)", startLine, currentLine-1)
	}

	return results, nil
}
