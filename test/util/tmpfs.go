// Copyright 2024 The AuthLink Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package util

import (
	"fmt"
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

func ReWriteFileContent(path string, content []byte) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("open file %s: %w", path, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			panic(fmt.Errorf("close file %s: %w", path, err))
		}
	}()

	if err := f.Truncate(0); err != nil {
		return fmt.Errorf("truncate file %s: %w", path, err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		return fmt.Errorf("seek file %s: %w", path, err)
	}

	if _, err := fmt.Fprintf(f, "%s", content); err != nil {
		return fmt.Errorf("write content to file %s: %w", path, err)
	}

	return nil
}
