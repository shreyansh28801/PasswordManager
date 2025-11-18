package cmd

import (
	"crypto/subtle"
	"fmt"
	"os"
	"syscall"
	"time"

	"golang.org/x/term"
	"passwordmanager/crypto"
	"passwordmanager/models"
	"passwordmanager/storage"

	"github.com/spf13/cobra"
)

var addCmd = &cobra.Command{
	Use:   "add [title]",
	Short: "Add a new password entry",
	Long:  `Add a new password entry to the vault.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		title := args[0]
		
		dataDir := getDataDir()
		store := storage.NewStorage(dataDir)
		
		if !store.UserExists() {
			fmt.Println("Password manager not initialized. Run 'pm init' first.")
			return
		}

		user, err := store.LoadUser()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading user: %v\n", err)
			os.Exit(1)
		}

		fmt.Print("Enter master password: ")
		masterPassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading password: %v\n", err)
			os.Exit(1)
		}
		fmt.Println()

		computedHash := crypto.HashPassword(string(masterPassword), user.Salt)
		if subtle.ConstantTimeCompare([]byte(computedHash), []byte(user.MasterPasswordHash)) != 1 {
			fmt.Fprintf(os.Stderr, "Invalid master password.\n")
			os.Exit(1)
		}

		vault, err := store.LoadVault(string(masterPassword))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading vault: %v\n", err)
			os.Exit(1)
		}

		fmt.Print("Enter username: ")
		var username string
		fmt.Scanln(&username)

		fmt.Print("Enter password: ")
		password, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading password: %v\n", err)
			os.Exit(1)
		}
		fmt.Println()

		fmt.Print("Enter URL (optional): ")
		var url string
		fmt.Scanln(&url)

		fmt.Print("Enter notes (optional): ")
		var notes string
		fmt.Scanln(&notes)

		entry := models.PasswordEntry{
			ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
			Title:     title,
			Username:  username,
			Password:  string(password),
			URL:       url,
			Notes:     notes,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		vault.Entries = append(vault.Entries, entry)

		if err := store.SaveVault(vault, string(masterPassword)); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving vault: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Password entry '%s' added successfully!\n", title)
	},
}
