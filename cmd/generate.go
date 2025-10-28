package cmd

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"

	"github.com/spf13/cobra"
)

var generateCmd = &cobra.Command{
	Use:   "generate [length]",
	Short: "Generate a secure random password",
	Long:  `Generate a secure random password of specified length (default: 16 characters).`,
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		length := 16
		if len(args) > 0 {
			if _, err := fmt.Sscanf(args[0], "%d", &length); err != nil {
				fmt.Fprintf(os.Stderr, "Invalid length: %s\n", args[0])
				os.Exit(1)
			}
		}

		if length < 4 {
			fmt.Fprintf(os.Stderr, "Password length must be at least 4 characters.\n")
			os.Exit(1)
		}

		if length > 128 {
			fmt.Fprintf(os.Stderr, "Password length cannot exceed 128 characters.\n")
			os.Exit(1)
		}

		password := generatePassword(length)
		fmt.Printf("Generated password: %s\n", password)
	},
}

func generatePassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
	
	password := make([]byte, length)
	for i := range password {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			panic(err)
		}
		password[i] = charset[num.Int64()]
	}
	
	return string(password)
}
