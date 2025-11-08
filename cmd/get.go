package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"

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
				
				// Copy password to clipboard
				clipboardCleared := false
				if err := copyToClipboard(entry.Password); err != nil {
					fmt.Fprintf(os.Stderr, "Error copying to clipboard: %v\n", err)
					fmt.Printf("Password: %s\n", entry.Password) // Fallback to displaying
				} else {
					fmt.Println("Password: [Copied to clipboard for 10 seconds]")
					clipboardCleared = true
				}
				
				if entry.URL != "" {
					fmt.Printf("URL: %s\n", entry.URL)
				}
				if entry.Notes != "" {
					fmt.Printf("Notes: %s\n", entry.Notes)
				}
				fmt.Printf("Created: %s\n", entry.CreatedAt.Format("2006-01-02 15:04:05"))
				fmt.Printf("Updated: %s\n", entry.UpdatedAt.Format("2006-01-02 15:04:05"))
				
				// Wait and clear clipboard after 10 seconds
				if clipboardCleared {
					fmt.Println("\nWaiting to clear clipboard...")
					time.Sleep(10 * time.Second)
					copyToClipboard("") // Clear clipboard
					fmt.Println("Clipboard cleared.")
				}
				
				return
			}
		}

		fmt.Printf("Password entry '%s' not found.\n", title)
	},
}

// copyToClipboard copies text to the system clipboard
func copyToClipboard(text string) error {
	var cmd *exec.Cmd
	
	switch runtime.GOOS {
	case "darwin": // macOS
		cmd = exec.Command("pbcopy")
	case "linux":
		// Try xclip first, then xsel
		if _, err := exec.LookPath("xclip"); err == nil {
			cmd = exec.Command("xclip", "-selection", "clipboard")
		} else if _, err := exec.LookPath("xsel"); err == nil {
			cmd = exec.Command("xsel", "--clipboard", "--input")
		} else {
			return fmt.Errorf("xclip or xsel required for clipboard support on Linux")
		}
	case "windows":
		cmd = exec.Command("clip")
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
	
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	
	if err := cmd.Start(); err != nil {
		return err
	}
	
	if _, err := stdin.Write([]byte(text)); err != nil {
		return err
	}
	
	if err := stdin.Close(); err != nil {
		return err
	}
	
	return cmd.Wait()
}
