package models

import (
	"time"
)

// PasswordEntry represents a single password entry
type PasswordEntry struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Username    string    `json:"username"`
	Password    string    `json:"password"`
	URL         string    `json:"url"`
	Notes       string    `json:"notes"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// PasswordVault represents the encrypted vault containing all password entries
type PasswordVault struct {
	Entries []PasswordEntry `json:"entries"`
	Version string          `json:"version"`
}

// User represents the user configuration
type User struct {
	MasterPasswordHash string `json:"master_password_hash"`
	Salt               string `json:"salt"`
	CreatedAt          time.Time `json:"created_at"`
}
