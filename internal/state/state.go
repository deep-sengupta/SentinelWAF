package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Data struct {
	Enabled   bool   `json:"enabled"`
	UpdatedAt string `json:"updated_at"`
	UpdatedBy string `json:"updated_by"`
}

type Store struct {
	path string
	mu   sync.Mutex
}

func New(path string) *Store {
	return &Store{path: path}
}

func (s *Store) Ensure(defaultEnabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := os.Stat(s.path); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0755); err != nil {
		return err
	}
	return s.writeLocked(Data{
		Enabled:   defaultEnabled,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		UpdatedBy: "system",
	})
}

func (s *Store) Read() (Data, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		value := Data{
			Enabled:   true,
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
			UpdatedBy: "system",
		}
		if err := os.MkdirAll(filepath.Dir(s.path), 0755); err != nil {
			return Data{}, err
		}
		if err := s.writeLocked(value); err != nil {
			return Data{}, err
		}
		return value, nil
	}
	if err != nil {
		return Data{}, err
	}
	var value Data
	if err := json.Unmarshal(data, &value); err != nil {
		return Data{}, err
	}
	return value, nil
}

func (s *Store) SetEnabled(enabled bool, updatedBy string) (Data, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if updatedBy == "" {
		updatedBy = "system"
	}
	value := Data{
		Enabled:   enabled,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		UpdatedBy: updatedBy,
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0755); err != nil {
		return Data{}, err
	}
	if err := s.writeLocked(value); err != nil {
		return Data{}, err
	}
	return value, nil
}

func (s *Store) writeLocked(value Data) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
