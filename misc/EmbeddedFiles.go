package misc

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

var (
	dockerfileFS   fs.FS
	dockerfileMu   sync.Mutex
	extractedDir   string
	extractOnce    sync.Once
	extractErr     error
)

// SetDockerfileFS sets the embedded filesystem containing the dockerfile directory.
// Must be called from main() before any docker build operations.
func SetDockerfileFS(fsys fs.FS) {
	dockerfileMu.Lock()
	defer dockerfileMu.Unlock()
	dockerfileFS = fsys
}

// ExtractDockerfiles extracts the embedded dockerfile directory to a temporary
// location on disk and returns the root path. Extraction happens only once.
func ExtractDockerfiles() (string, error) {
	extractOnce.Do(func() {
		dockerfileMu.Lock()
		fsys := dockerfileFS
		dockerfileMu.Unlock()

		if fsys == nil {
			extractErr = fmt.Errorf("dockerfile filesystem not set (call SetDockerfileFS first)")
			return
		}

		tmpDir, err := os.MkdirTemp("", "aixvuln-dockerfiles-*")
		if err != nil {
			extractErr = fmt.Errorf("create temp dir: %w", err)
			return
		}

		err = fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			destPath := filepath.Join(tmpDir, path)
			if d.IsDir() {
				return os.MkdirAll(destPath, 0755)
			}
			data, err := fs.ReadFile(fsys, path)
			if err != nil {
				return fmt.Errorf("read embedded %s: %w", path, err)
			}
			if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
				return err
			}
			return os.WriteFile(destPath, data, 0755)
		})
		if err != nil {
			extractErr = fmt.Errorf("extract dockerfiles: %w", err)
			_ = os.RemoveAll(tmpDir)
			return
		}
		extractedDir = tmpDir
	})
	return extractedDir, extractErr
}

// GetDockerfilePath returns the on-disk path to a specific dockerfile context directory.
// e.g. GetDockerfilePath("aisandbox") returns "/tmp/xxx/dockerfile.aisandbox"
func GetDockerfilePath(imageName string) (string, error) {
	root, err := ExtractDockerfiles()
	if err != nil {
		return "", err
	}
	p := filepath.Join(root, fmt.Sprintf("dockerfile.%s", imageName))
	if _, err := os.Stat(p); os.IsNotExist(err) {
		return "", fmt.Errorf("dockerfile context not found: %s", p)
	}
	return p, nil
}

// CleanupDockerfiles removes the extracted temporary directory.
func CleanupDockerfiles() {
	if extractedDir != "" {
		_ = os.RemoveAll(extractedDir)
	}
}
