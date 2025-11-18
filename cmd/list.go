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

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all password entries",
	Long:  `List all password entries in the vault.`,
	Run: func(cmd *cobra.Command, args []string) {
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

		if len(vault.Entries) == 0 {
			fmt.Println("No password entries found.")
			return
		}

		fmt.Printf("Found %d password entries:\n\n", len(vault.Entries))
		for i, entry := range vault.Entries {
			fmt.Printf("%d. %s\n", i+1, entry.Title)
			fmt.Printf("   Username: %s\n", entry.Username)
			if entry.URL != "" {
				fmt.Printf("   URL: %s\n", entry.URL)
			}
			fmt.Printf("   Updated: %s\n\n", entry.UpdatedAt.Format("2006-01-02 15:04:05"))
		}
	},
}
