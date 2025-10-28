package cmd

import (
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

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the password manager",
	Long:  `Initialize the password manager by setting up a master password and creating the encrypted vault.`,
	Run: func(cmd *cobra.Command, args []string) {
		dataDir := getDataDir()
		store := storage.NewStorage(dataDir)
		
		if err := store.Initialize(); err != nil {
			fmt.Fprintf(os.Stderr, "Error initializing storage: %v\n", err)
			os.Exit(1)
		}

		if store.UserExists() {
			fmt.Println("Password manager is already initialized.")
			return
		}

		fmt.Print("Enter master password: ")
		masterPassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading password: %v\n", err)
			os.Exit(1)
		}
		fmt.Println()

		fmt.Print("Confirm master password: ")
		confirmPassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading password: %v\n", err)
			os.Exit(1)
		}
		fmt.Println()

		if string(masterPassword) != string(confirmPassword) {
			fmt.Fprintf(os.Stderr, "Passwords do not match.\n")
			os.Exit(1)
		}

		salt, err := crypto.GenerateSalt()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating salt: %v\n", err)
			os.Exit(1)
		}

		user := &models.User{
			MasterPasswordHash: crypto.HashPassword(string(masterPassword), salt),
			Salt:               salt,
			CreatedAt:          time.Now(),
		}

		if err := store.SaveUser(user); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving user: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Password manager initialized successfully!")
	},
}
