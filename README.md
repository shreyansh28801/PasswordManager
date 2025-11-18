# Password Manager

A secure command-line password manager written in Go that uses AES-256-GCM encryption to protect your sensitive data.

## Features

- 🔐 **Secure Encryption**: Uses AES-256-GCM encryption for all stored data
- 🛡️ **Master Password Protection**: All data is protected by a master password
- 📝 **Full CRUD Operations**: Add, retrieve, update, and delete password entries
- 🎲 **Password Generator**: Generate secure random passwords
- 💾 **Local Storage**: All data is stored locally in encrypted files
- 🖥️ **Command Line Interface**: Easy-to-use CLI with Cobra framework

## Installation

1. Clone or download this repository
2. Run the build script:
   ```bash
   ./build.sh
   ```
3. Optionally install globally:
   ```bash
   sudo cp bin/pm /usr/local/bin/
   ```

## Usage

### Initialize the Password Manager

First, you need to initialize the password manager with a master password:

```bash
pm init
```

This will:
- Create a secure data directory in `~/.passwordmanager/`
- Set up your master password
- Create the encrypted vault file

### Add a Password Entry

```bash
pm add "My Website"
```

This will prompt you for:
- Username
- Password
- URL (optional)
- Notes (optional)

### List All Password Entries

```bash
pm list
```

Shows a summary of all stored password entries.

### Retrieve a Password Entry

```bash
pm get "My Website"
```

Displays the complete details of a specific password entry. The password is automatically copied to your clipboard for 10 seconds (for security) and then cleared.

### Update a Password Entry

```bash
pm update "My Website"
```

Allows you to update any field of an existing password entry.

### Delete a Password Entry

```bash
pm delete "My Website"
```

Removes a password entry after confirmation.

### Generate a Secure Password

```bash
pm generate 20
```

Generates a secure random password of specified length (default: 16 characters).

## Security Features

- **AES-256-GCM Encryption**: Industry-standard encryption for all stored data
- **Salt-based Password Hashing**: Master password is hashed with a random salt
- **Constant-Time Password Comparison**: Uses constant-time comparison to prevent timing attacks
- **Secure Random Generation**: Uses crypto/rand for password generation
- **File Permissions**: Data files are created with restricted permissions (600)
- **Local Storage**: All data remains on your local machine
- **Auto-Clearing Clipboard**: Passwords are copied to clipboard and automatically cleared after 10 seconds

## Data Storage

The password manager stores data in:
- `~/.passwordmanager/vault.dat` - Encrypted password vault
- `~/.passwordmanager/user.dat` - User configuration and master password hash

## Commands

| Command | Description |
|---------|-------------|
| `pm init` | Initialize the password manager |
| `pm add <title>` | Add a new password entry |
| `pm get <title>` | Retrieve a password entry |
| `pm list` | List all password entries |
| `pm update <title>` | Update a password entry |
| `pm delete <title>` | Delete a password entry |
| `pm generate [length]` | Generate a secure password |

## Dependencies

- Go 1.21+
- github.com/spf13/cobra - CLI framework
- golang.org/x/crypto - Cryptographic functions
- golang.org/x/term - Terminal input handling

## Building from Source

```bash
go mod tidy
go build -o bin/pm .
```

## Security Considerations

- Always use a strong master password
- Keep your master password secure and don't share it
- Regularly backup your `~/.passwordmanager/` directory
- The password manager does not store your master password in plain text

## License

This project is open source. Feel free to use and modify as needed.
