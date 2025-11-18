package cmd

import (
	"crypto/subtle"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/term"
	"passwordmanager/crypto"
	"passwordmanager/storage"

	"github.com/spf13/cobra"
)

var deleteCmd = &cobra.Command{
	Use:   "delete [title]",
	Short: "Delete a password entry",
	Long:  `Delete a password entry by title.`,
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

		for i, entry := range vault.Entries {
			if entry.Title == title {
				fmt.Printf("Are you sure you want to delete '%s'? (y/N): ", title)
				var confirm string
				fmt.Scanln(&confirm)
				
				if confirm == "y" || confirm == "Y" {
					vault.Entries = append(vault.Entries[:i], vault.Entries[i+1:]...)
					
					if err := store.SaveVault(vault, string(masterPassword)); err != nil {
						fmt.Fprintf(os.Stderr, "Error saving vault: %v\n", err)
						os.Exit(1)
					}
					
					fmt.Printf("Password entry '%s' deleted successfully!\n", title)
				} else {
					fmt.Println("Deletion cancelled.")
				}
				return
			}
		}

		fmt.Printf("Password entry '%s' not found.\n", title)
	},
}
