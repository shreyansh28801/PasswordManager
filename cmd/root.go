package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "pm",
	Short: "Password Manager - A secure command-line password manager",
	Long: `Password Manager (pm) is a secure command-line tool for managing your passwords.
It uses AES-256-GCM encryption to protect your sensitive data.

Features:
- Add, retrieve, update, and delete password entries
- Generate secure random passwords
- Master password protection
- Encrypted local storage`,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(addCmd)
	rootCmd.AddCommand(getCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(updateCmd)
	rootCmd.AddCommand(deleteCmd)
	rootCmd.AddCommand(generateCmd)
}

func getDataDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting home directory: %v\n", err)
		os.Exit(1)
	}
	return filepath.Join(homeDir, ".passwordmanager")
}
