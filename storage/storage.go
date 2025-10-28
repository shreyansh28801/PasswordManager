package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"passwordmanager/crypto"
	"passwordmanager/models"
)

const (
	VaultFileName = "vault.dat"
	UserFileName  = "user.dat"
)

type Storage struct {
	dataDir string
}

// NewStorage creates a new storage instance
func NewStorage(dataDir string) *Storage {
	return &Storage{
		dataDir: dataDir,
	}
}

// Initialize creates the data directory if it doesn't exist
func (s *Storage) Initialize() error {
	return os.MkdirAll(s.dataDir, 0700)
}

// SaveVault encrypts and saves the password vault
func (s *Storage) SaveVault(vault *models.PasswordVault, masterPassword string) error {
	data, err := json.Marshal(vault)
	if err != nil {
		return fmt.Errorf("failed to marshal vault: %w", err)
	}

	encryptedData, err := crypto.EncryptData(data, masterPassword)
	if err != nil {
		return fmt.Errorf("failed to encrypt vault: %w", err)
	}

	vaultPath := filepath.Join(s.dataDir, VaultFileName)
	return os.WriteFile(vaultPath, encryptedData, 0600)
}

// LoadVault loads and decrypts the password vault
func (s *Storage) LoadVault(masterPassword string) (*models.PasswordVault, error) {
	vaultPath := filepath.Join(s.dataDir, VaultFileName)
	
	encryptedData, err := os.ReadFile(vaultPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Return empty vault if file doesn't exist
			return &models.PasswordVault{
				Entries: []models.PasswordEntry{},
				Version: "1.0",
			}, nil
		}
		return nil, fmt.Errorf("failed to read vault file: %w", err)
	}

	data, err := crypto.DecryptData(encryptedData, masterPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt vault: %w", err)
	}

	var vault models.PasswordVault
	if err := json.Unmarshal(data, &vault); err != nil {
		return nil, fmt.Errorf("failed to unmarshal vault: %w", err)
	}

	return &vault, nil
}

// SaveUser saves user configuration
func (s *Storage) SaveUser(user *models.User) error {
	data, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("failed to marshal user: %w", err)
	}

	userPath := filepath.Join(s.dataDir, UserFileName)
	return os.WriteFile(userPath, data, 0600)
}

// LoadUser loads user configuration
func (s *Storage) LoadUser() (*models.User, error) {
	userPath := filepath.Join(s.dataDir, UserFileName)
	
	data, err := os.ReadFile(userPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No user file exists yet
		}
		return nil, fmt.Errorf("failed to read user file: %w", err)
	}

	var user models.User
	if err := json.Unmarshal(data, &user); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user: %w", err)
	}

	return &user, nil
}

// UserExists checks if a user configuration exists
func (s *Storage) UserExists() bool {
	userPath := filepath.Join(s.dataDir, UserFileName)
	_, err := os.Stat(userPath)
	return !os.IsNotExist(err)
}

// VaultExists checks if a vault file exists
func (s *Storage) VaultExists() bool {
	vaultPath := filepath.Join(s.dataDir, VaultFileName)
	_, err := os.Stat(vaultPath)
	return !os.IsNotExist(err)
}
