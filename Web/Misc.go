package Web

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func Success(msg any) any {
	result := make(map[string]any)
	result["success"] = true
	result["result"] = msg
	result["error"] = nil
	return result
}

func Fail(msg any) any {
	result := make(map[string]any)
	result["success"] = false
	result["result"] = nil
	result["error"] = msg
	return result
}

func UncompressFile(sourcePath, destDir string) error {
	// 创建目标目录
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("创建目录失败: %v", err)
	}

	// 根据文件扩展名选择解压方式
	ext := strings.ToLower(filepath.Ext(sourcePath))

	switch {
	case ext == ".zip":
		return unzipFile(sourcePath, destDir)
	case ext == ".gz" && strings.HasSuffix(strings.ToLower(sourcePath), ".tar.gz"):
		return untarGzFile(sourcePath, destDir)
	case ext == ".tgz":
		return untarGzFile(sourcePath, destDir)
	default:
		return fmt.Errorf("不支持的文件格式: %s", ext)
	}
}

func unzipFile(sourcePath, destDir string) error {
	// 打开ZIP文件
	reader, err := zip.OpenReader(sourcePath)
	if err != nil {
		return fmt.Errorf("打开ZIP文件失败: %v", err)
	}
	defer reader.Close()

	// 遍历ZIP文件中的每个文件
	for _, file := range reader.File {
		// 安全检查：防止路径遍历攻击
		filePath := filepath.Join(destDir, file.Name)
		if !strings.HasPrefix(filePath, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("非法文件路径: %s", file.Name)
		}

		// 如果是目录，创建目录
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(filePath, 0755); err != nil {
				return fmt.Errorf("创建目录失败: %v", err)
			}
			continue
		}

		// 确保文件的父目录存在
		if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
			return fmt.Errorf("创建目录失败: %v", err)
		}

		// 打开ZIP中的文件
		srcFile, err := file.Open()
		if err != nil {
			return fmt.Errorf("打开ZIP内文件失败: %v", err)
		}

		// 创建目标文件
		dstFile, err := os.Create(filePath)
		if err != nil {
			srcFile.Close()
			return fmt.Errorf("创建文件失败: %v", err)
		}

		// 复制文件内容
		_, err = io.Copy(dstFile, srcFile)

		// 关闭文件
		srcFile.Close()
		dstFile.Close()

		if err != nil {
			return fmt.Errorf("写入文件失败: %v", err)
		}

		// 设置文件权限
		if err := os.Chmod(filePath, file.Mode()); err != nil {
			return fmt.Errorf("设置文件权限失败: %v", err)
		}
	}

	return nil
}

// untarGzFile 解压TAR.GZ文件
func untarGzFile(sourcePath, destDir string) error {
	// 打开压缩文件
	file, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("打开文件失败: %v", err)
	}
	defer file.Close()

	// 创建GZIP读取器
	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("创建GZIP读取器失败: %v", err)
	}
	defer gzReader.Close()

	// 创建TAR读取器
	tarReader := tar.NewReader(gzReader)

	// 遍历TAR文件中的每个文件
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break // 到达文件末尾
		}
		if err != nil {
			return fmt.Errorf("读取TAR文件失败: %v", err)
		}

		// 获取目标文件路径
		targetPath := filepath.Join(destDir, header.Name)

		// 安全检查：防止路径遍历攻击
		if !strings.HasPrefix(targetPath, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("非法文件路径: %s", header.Name)
		}

		// 根据文件类型处理
		switch header.Typeflag {
		case tar.TypeDir: // 目录
			if err := os.MkdirAll(targetPath, 0755); err != nil {
				return fmt.Errorf("创建目录失败: %v", err)
			}

		case tar.TypeReg: // 普通文件
			// 确保父目录存在
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return fmt.Errorf("创建目录失败: %v", err)
			}

			// 创建文件
			file, err := os.Create(targetPath)
			if err != nil {
				return fmt.Errorf("创建文件失败: %v", err)
			}

			// 复制文件内容
			if _, err := io.Copy(file, tarReader); err != nil {
				file.Close()
				return fmt.Errorf("写入文件失败: %v", err)
			}

			file.Close()

			// 设置文件权限
			if err := os.Chmod(targetPath, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("设置文件权限失败: %v", err)
			}

			// 设置文件修改时间
			if err := os.Chtimes(targetPath, header.AccessTime, header.ModTime); err != nil {
			}

		case tar.TypeSymlink:
			linkTarget := header.Linkname
			if !filepath.IsAbs(linkTarget) {
				linkTarget = filepath.Join(filepath.Dir(targetPath), linkTarget)
			}
			linkTarget = filepath.Clean(linkTarget)

			if !strings.HasPrefix(linkTarget, filepath.Clean(destDir)+string(os.PathSeparator)) {
				return fmt.Errorf("符号链接指向非法路径: %s -> %s", header.Name, header.Linkname)
			}

			if err := os.Symlink(linkTarget, targetPath); err != nil {
				return fmt.Errorf("创建符号链接失败: %v", err)
			}
		default:
		}
	}

	return nil
}
