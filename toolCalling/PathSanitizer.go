package toolCalling

import (
	"path/filepath"
	"strings"
)

func relPathForLLM(root string, p string) string {
	if p == "" {
		return ""
	}
	root = filepath.Clean(root)
	p = filepath.Clean(p)
	if !filepath.IsAbs(p) {
		if strings.HasPrefix(p, "./") {
			return filepath.ToSlash(p)
		}
		return "./" + filepath.ToSlash(p)
	}
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return p
	}
	rel = filepath.ToSlash(rel)
	if rel == "." {
		return "./"
	}
	if strings.HasPrefix(rel, "../") || rel == ".." {
		return p
	}
	return "./" + rel
}

func sanitizeTextPaths(root string, msg string) string {
	if msg == "" || root == "" {
		return msg
	}
	rootClean := filepath.Clean(root)
	rootSlash := filepath.ToSlash(rootClean)

	out := msg
	out = strings.ReplaceAll(out, rootClean+string(filepath.Separator), "./")
	out = strings.ReplaceAll(out, rootClean, "./")
	out = strings.ReplaceAll(out, rootSlash+"/", "./")
	out = strings.ReplaceAll(out, rootSlash, "./")
	return out
}
