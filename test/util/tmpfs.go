package util

import (
	"os"
	"path/filepath"
)

func MakeTmpFs(root, prefix string, files map[string][]byte) (string, func(), error) {
	rootDir, err := os.MkdirTemp(root, prefix)
	if err != nil {
		return "", nil, err
	}

	cleanup := func() {
		os.RemoveAll(rootDir)
	}

	for path, content := range files {
		dirname, filename := filepath.Split(path)
		dirPath := filepath.Join(rootDir, dirname)
		if err := os.MkdirAll(dirPath, 0o777); err != nil {
			return "", nil, err
		}

		f, err := os.Create(filepath.Join(dirPath, filename))
		if err != nil {
			return "", nil, err
		}

		if _, err := f.Write(content); err != nil {
			return "", nil, err
		}
	}

	return rootDir, cleanup, nil
}
