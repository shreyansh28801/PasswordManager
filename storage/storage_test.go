package storage

import (
	"os"
	"path/filepath"
	"passwordmanager/models"
	"testing"
	"time"
)

func setupTestDir(t *testing.T) (string, func()) {
	tempDir := filepath.Join(os.TempDir(), "pm_test_"+time.Now().Format("20060102150405"))
	err := os.MkdirAll(tempDir, 0700)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	cleanup := func() {
		os.RemoveAll(tempDir)
	}

	return tempDir, cleanup
}

func TestNewStorage(t *testing.T) {
	dataDir := "/test/dir"
	store := NewStorage(dataDir)

	if store == nil {
		t.Fatal("NewStorage returned nil")
	}

	if store.dataDir != dataDir {
		t.Errorf("Expected dataDir %s, got %s", dataDir, store.dataDir)
	}
}

func TestInitialize(t *testing.T) {
	tempDir, cleanup := setupTestDir(t)
	defer cleanup()

	store := NewStorage(tempDir)

	err := store.Initialize()
	if err != nil {
		t.Fatalf("Initialize returned error: %v", err)
	}

	// Check that directory was created
	info, err := os.Stat(tempDir)
	if err != nil {
		t.Fatalf("Directory was not created: %v", err)
	}

	if !info.IsDir() {
		t.Error("Created path is not a directory")
	}

	// Check permissions (should be 0700)
	mode := info.Mode().Perm()
	if mode != 0700 {
		t.Errorf("Expected permissions 0700, got %o", mode)
	}
}

func TestInitialize_ExistingDirectory(t *testing.T) {
	tempDir, cleanup := setupTestDir(t)
	defer cleanup()

	store := NewStorage(tempDir)

	// Initialize twice
	err := store.Initialize()
	if err != nil {
		t.Fatalf("First Initialize returned error: %v", err)
	}

	err = store.Initialize()
	if err != nil {
		t.Fatalf("Second Initialize returned error: %v", err)
	}
}

func TestSaveVault_LoadVault(t *testing.T) {
	tempDir, cleanup := setupTestDir(t)
	defer cleanup()

	store := NewStorage(tempDir)
	err := store.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	masterPassword := "masterpassword123"

	vault := &models.PasswordVault{
		Entries: []models.PasswordEntry{
			{
				ID:        "1",
				Title:     "Test Entry",
				Username:  "testuser",
				Password:  "testpass",
				URL:       "https://example.com",
				Notes:     "Test notes",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
		},
		Version: "1.0",
	}

	// Save vault
	err = store.SaveVault(vault, masterPassword)
	if err != nil {
		t.Fatalf("SaveVault returned error: %v", err)
	}

	// Check that file was created
	vaultPath := filepath.Join(tempDir, VaultFileName)
	_, err = os.Stat(vaultPath)
	if err != nil {
		t.Fatalf("Vault file was not created: %v", err)
	}

	// Check file permissions
	info, _ := os.Stat(vaultPath)
	mode := info.Mode().Perm()
	if mode != 0600 {
		t.Errorf("Expected permissions 0600, got %o", mode)
	}

	// Load vault
	loadedVault, err := store.LoadVault(masterPassword)
	if err != nil {
		t.Fatalf("LoadVault returned error: %v", err)
	}

	// Verify vault contents
	if loadedVault.Version != vault.Version {
		t.Errorf("Version mismatch: got %s, want %s", loadedVault.Version, vault.Version)
	}

	if len(loadedVault.Entries) != len(vault.Entries) {
		t.Fatalf("Entry count mismatch: got %d, want %d", len(loadedVault.Entries), len(vault.Entries))
	}

	entry := loadedVault.Entries[0]
	if entry.ID != vault.Entries[0].ID {
		t.Errorf("ID mismatch: got %s, want %s", entry.ID, vault.Entries[0].ID)
	}
	if entry.Title != vault.Entries[0].Title {
		t.Errorf("Title mismatch: got %s, want %s", entry.Title, vault.Entries[0].Title)
	}
	if entry.Username != vault.Entries[0].Username {
		t.Errorf("Username mismatch: got %s, want %s", entry.Username, vault.Entries[0].Username)
	}
	if entry.Password != vault.Entries[0].Password {
		t.Errorf("Password mismatch: got %s, want %s", entry.Password, vault.Entries[0].Password)
	}
	if entry.URL != vault.Entries[0].URL {
		t.Errorf("URL mismatch: got %s, want %s", entry.URL, vault.Entries[0].URL)
	}
	if entry.Notes != vault.Entries[0].Notes {
		t.Errorf("Notes mismatch: got %s, want %s", entry.Notes, vault.Entries[0].Notes)
	}
}

func TestLoadVault_NonExistent(t *testing.T) {
	tempDir, cleanup := setupTestDir(t)
	defer cleanup()

	store := NewStorage(tempDir)
	err := store.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	vault, err := store.LoadVault("password")
	if err != nil {
		t.Fatalf("LoadVault returned error for non-existent vault: %v", err)
	}

	// Should return empty vault
	if vault == nil {
		t.Fatal("LoadVault returned nil for non-existent vault")
	}

	if len(vault.Entries) != 0 {
		t.Errorf("Expected empty vault, got %d entries", len(vault.Entries))
	}

	if vault.Version != "1.0" {
		t.Errorf("Expected version 1.0, got %s", vault.Version)
	}
}

func TestLoadVault_WrongPassword(t *testing.T) {
	tempDir, cleanup := setupTestDir(t)
	defer cleanup()

	store := NewStorage(tempDir)
	err := store.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	vault := &models.PasswordVault{
		Entries: []models.PasswordEntry{},
		Version: "1.0",
	}

	err = store.SaveVault(vault, "correctpassword")
	if err != nil {
		t.Fatalf("SaveVault failed: %v", err)
	}

	// Try to load with wrong password
	_, err = store.LoadVault("wrongpassword")
	if err == nil {
		t.Error("LoadVault with wrong password should return error")
	}
}

func TestSaveUser_LoadUser(t *testing.T) {
	tempDir, cleanup := setupTestDir(t)
	defer cleanup()

	store := NewStorage(tempDir)
	err := store.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	user := &models.User{
		MasterPasswordHash: "testhash123",
		Salt:               "testsalt456",
		CreatedAt:          time.Now(),
	}

	// Save user
	err = store.SaveUser(user)
	if err != nil {
		t.Fatalf("SaveUser returned error: %v", err)
	}

	// Check that file was created
	userPath := filepath.Join(tempDir, UserFileName)
	_, err = os.Stat(userPath)
	if err != nil {
		t.Fatalf("User file was not created: %v", err)
	}

	// Check file permissions
	info, _ := os.Stat(userPath)
	mode := info.Mode().Perm()
	if mode != 0600 {
		t.Errorf("Expected permissions 0600, got %o", mode)
	}

	// Load user
	loadedUser, err := store.LoadUser()
	if err != nil {
		t.Fatalf("LoadUser returned error: %v", err)
	}

	if loadedUser == nil {
		t.Fatal("LoadUser returned nil")
	}

	if loadedUser.MasterPasswordHash != user.MasterPasswordHash {
		t.Errorf("MasterPasswordHash mismatch: got %s, want %s", loadedUser.MasterPasswordHash, user.MasterPasswordHash)
	}

	if loadedUser.Salt != user.Salt {
		t.Errorf("Salt mismatch: got %s, want %s", loadedUser.Salt, user.Salt)
	}
}

func TestLoadUser_NonExistent(t *testing.T) {
	tempDir, cleanup := setupTestDir(t)
	defer cleanup()

	store := NewStorage(tempDir)
	err := store.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	user, err := store.LoadUser()
	if err != nil {
		t.Fatalf("LoadUser returned error for non-existent user: %v", err)
	}

	if user != nil {
		t.Error("LoadUser should return nil for non-existent user")
	}
}

func TestUserExists(t *testing.T) {
	tempDir, cleanup := setupTestDir(t)
	defer cleanup()

	store := NewStorage(tempDir)
	err := store.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Initially should not exist
	if store.UserExists() {
		t.Error("UserExists returned true for non-existent user")
	}

	// Create user
	user := &models.User{
		MasterPasswordHash: "testhash",
		Salt:               "testsalt",
		CreatedAt:          time.Now(),
	}

	err = store.SaveUser(user)
	if err != nil {
		t.Fatalf("SaveUser failed: %v", err)
	}

	// Now should exist
	if !store.UserExists() {
		t.Error("UserExists returned false for existing user")
	}
}

func TestVaultExists(t *testing.T) {
	tempDir, cleanup := setupTestDir(t)
	defer cleanup()

	store := NewStorage(tempDir)
	err := store.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Initially should not exist
	if store.VaultExists() {
		t.Error("VaultExists returned true for non-existent vault")
	}

	// Create vault
	vault := &models.PasswordVault{
		Entries: []models.PasswordEntry{},
		Version: "1.0",
	}

	err = store.SaveVault(vault, "password")
	if err != nil {
		t.Fatalf("SaveVault failed: %v", err)
	}

	// Now should exist
	if !store.VaultExists() {
		t.Error("VaultExists returned false for existing vault")
	}
}

func TestSaveVault_MultipleEntries(t *testing.T) {
	tempDir, cleanup := setupTestDir(t)
	defer cleanup()

	store := NewStorage(tempDir)
	err := store.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	masterPassword := "masterpass"

	vault := &models.PasswordVault{
		Entries: []models.PasswordEntry{
			{
				ID:        "1",
				Title:     "Entry 1",
				Username:  "user1",
				Password:  "pass1",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
			{
				ID:        "2",
				Title:     "Entry 2",
				Username:  "user2",
				Password:  "pass2",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
			{
				ID:        "3",
				Title:     "Entry 3",
				Username:  "user3",
				Password:  "pass3",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
		},
		Version: "1.0",
	}

	err = store.SaveVault(vault, masterPassword)
	if err != nil {
		t.Fatalf("SaveVault failed: %v", err)
	}

	loadedVault, err := store.LoadVault(masterPassword)
	if err != nil {
		t.Fatalf("LoadVault failed: %v", err)
	}

	if len(loadedVault.Entries) != 3 {
		t.Fatalf("Expected 3 entries, got %d", len(loadedVault.Entries))
	}

	for i, entry := range loadedVault.Entries {
		if entry.ID != vault.Entries[i].ID {
			t.Errorf("Entry %d ID mismatch: got %s, want %s", i, entry.ID, vault.Entries[i].ID)
		}
		if entry.Title != vault.Entries[i].Title {
			t.Errorf("Entry %d Title mismatch: got %s, want %s", i, entry.Title, vault.Entries[i].Title)
		}
	}
}

func TestSaveVault_EmptyVault(t *testing.T) {
	tempDir, cleanup := setupTestDir(t)
	defer cleanup()

	store := NewStorage(tempDir)
	err := store.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	vault := &models.PasswordVault{
		Entries: []models.PasswordEntry{},
		Version: "1.0",
	}

	err = store.SaveVault(vault, "password")
	if err != nil {
		t.Fatalf("SaveVault failed: %v", err)
	}

	loadedVault, err := store.LoadVault("password")
	if err != nil {
		t.Fatalf("LoadVault failed: %v", err)
	}

	if len(loadedVault.Entries) != 0 {
		t.Errorf("Expected empty vault, got %d entries", len(loadedVault.Entries))
	}
}

func TestSaveVault_UpdateExisting(t *testing.T) {
	tempDir, cleanup := setupTestDir(t)
	defer cleanup()

	store := NewStorage(tempDir)
	err := store.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	masterPassword := "password"

	// Save initial vault
	vault1 := &models.PasswordVault{
		Entries: []models.PasswordEntry{
			{
				ID:        "1",
				Title:     "Original",
				Username:  "user1",
				Password:  "pass1",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
		},
		Version: "1.0",
	}

	err = store.SaveVault(vault1, masterPassword)
	if err != nil {
		t.Fatalf("SaveVault failed: %v", err)
	}

	// Update vault
	vault2 := &models.PasswordVault{
		Entries: []models.PasswordEntry{
			{
				ID:        "1",
				Title:     "Updated",
				Username:  "user1",
				Password:  "newpass",
				CreatedAt: vault1.Entries[0].CreatedAt,
				UpdatedAt: time.Now(),
			},
		},
		Version: "1.0",
	}

	err = store.SaveVault(vault2, masterPassword)
	if err != nil {
		t.Fatalf("SaveVault failed on update: %v", err)
	}

	// Verify update
	loadedVault, err := store.LoadVault(masterPassword)
	if err != nil {
		t.Fatalf("LoadVault failed: %v", err)
	}

	if len(loadedVault.Entries) != 1 {
		t.Fatalf("Expected 1 entry, got %d", len(loadedVault.Entries))
	}

	if loadedVault.Entries[0].Title != "Updated" {
		t.Errorf("Title not updated: got %s, want Updated", loadedVault.Entries[0].Title)
	}

	if loadedVault.Entries[0].Password != "newpass" {
		t.Errorf("Password not updated: got %s, want newpass", loadedVault.Entries[0].Password)
	}
}

