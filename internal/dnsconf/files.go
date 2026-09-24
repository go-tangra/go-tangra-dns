package dnsconf

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// FileWriter writes a managed include file only when its content differs.
type FileWriter interface {
	// WriteIfChanged atomically replaces path with content unless the file
	// already holds exactly that content; it reports whether it wrote.
	WriteIfChanged(path, content string) (bool, error)
}

// Hash is the sha256 (hex) of rendered content (stored as the last-applied hash).
func Hash(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// DiskWriter writes to the local filesystem: compare hashes, write a temp
// file in the same directory, chmod 0644 (the PowerDNS containers read it),
// then rename over the target.
type DiskWriter struct{}

// WriteIfChanged implements FileWriter.
func (DiskWriter) WriteIfChanged(path, content string) (bool, error) {
	cur, err := os.ReadFile(path) // #nosec G304 -- fixed, configured include path
	switch {
	case err == nil && Hash(string(cur)) == Hash(content):
		return false, nil
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return false, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".freya-dns-*")
	if err != nil {
		return false, err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if err := os.Chmod(name, 0o644); err != nil { // #nosec G302 -- read by the PowerDNS containers; no secrets inside
		return false, err
	}
	if err := os.Rename(name, path); err != nil {
		return false, err
	}
	return true, nil
}
