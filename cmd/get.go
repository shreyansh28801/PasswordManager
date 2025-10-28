package cmd

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/term"
	"passwordmanager/crypto"
	"passwordmanager/storage"

	"github.com/spf13/cobra"
)

var getCmd = &cobra.Command{
	Use:   "get [title]",
	Short: "Retrieve a password entry",
	Long:  `Retrieve and display a password entry by title.`,
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

		for _, entry := range vault.Entries {
			if entry.Title == title {
				fmt.Printf("Title: %s\n", entry.Title)
				fmt.Printf("Username: %s\n", entry.Username)
				fmt.Printf("Password: %s\n", entry.Password)
				if entry.URL != "" {
					fmt.Printf("URL: %s\n", entry.URL)
				}
				if entry.Notes != "" {
					fmt.Printf("Notes: %s\n", entry.Notes)
				}
				fmt.Printf("Created: %s\n", entry.CreatedAt.Format("2006-01-02 15:04:05"))
				fmt.Printf("Updated: %s\n", entry.UpdatedAt.Format("2006-01-02 15:04:05"))
				return
			}
		}

		fmt.Printf("Password entry '%s' not found.\n", title)
	},
}
