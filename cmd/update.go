package cmd

import (
	"fmt"
	"os"
	"syscall"
	"time"

	"golang.org/x/term"
	"passwordmanager/crypto"
	"passwordmanager/storage"

	"github.com/spf13/cobra"
)

var updateCmd = &cobra.Command{
	Use:   "update [title]",
	Short: "Update a password entry",
	Long:  `Update an existing password entry by title.`,
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

		if crypto.HashPassword(string(masterPassword), user.Salt) != user.MasterPasswordHash {
			fmt.Fprintf(os.Stderr, "Invalid master password.\n")
			os.Exit(1)
		}

		vault, err := store.LoadVault(string(masterPassword))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading vault: %v\n", err)
			os.Exit(1)
		}

		for i, entry := range vault.Entries {
			if entry.Title == title {
				fmt.Printf("Current entry:\n")
				fmt.Printf("Title: %s\n", entry.Title)
				fmt.Printf("Username: %s\n", entry.Username)
				fmt.Printf("URL: %s\n", entry.URL)
				fmt.Printf("Notes: %s\n", entry.Notes)
				fmt.Println()

				fmt.Print("Enter new username (press Enter to keep current): ")
				var newUsername string
				fmt.Scanln(&newUsername)
				if newUsername != "" {
					entry.Username = newUsername
				}

				fmt.Print("Enter new password (press Enter to keep current): ")
				newPassword, err := term.ReadPassword(int(syscall.Stdin))
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error reading password: %v\n", err)
					os.Exit(1)
				}
				fmt.Println()
				if len(newPassword) > 0 {
					entry.Password = string(newPassword)
				}

				fmt.Print("Enter new URL (press Enter to keep current): ")
				var newURL string
				fmt.Scanln(&newURL)
				if newURL != "" {
					entry.URL = newURL
				}

				fmt.Print("Enter new notes (press Enter to keep current): ")
				var newNotes string
				fmt.Scanln(&newNotes)
				if newNotes != "" {
					entry.Notes = newNotes
				}

				entry.UpdatedAt = time.Now()
				vault.Entries[i] = entry

				if err := store.SaveVault(vault, string(masterPassword)); err != nil {
					fmt.Fprintf(os.Stderr, "Error saving vault: %v\n", err)
					os.Exit(1)
				}

				fmt.Printf("Password entry '%s' updated successfully!\n", title)
				return
			}
		}

		fmt.Printf("Password entry '%s' not found.\n", title)
	},
}
