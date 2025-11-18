package crypto

import (
	"crypto/subtle"
	"encoding/base64"
	"testing"
)

func TestHashPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		salt     string
	}{
		{
			name:     "simple password and salt",
			password: "testpassword",
			salt:     "testsalt",
		},
		{
			name:     "empty password",
			password: "",
			salt:     "salt123",
		},
		{
			name:     "empty salt",
			password: "password123",
			salt:     "",
		},
		{
			name:     "special characters",
			password: "p@ssw0rd!#$",
			salt:     "s@lt!23",
		},
		{
			name:     "long password",
			password: "thisisaverylongpasswordthatisusedtotestthehashingfunction",
			salt:     "longsaltvalue",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := HashPassword(tt.password, tt.salt)

			// Check that hash is not empty
			if hash == "" {
				t.Error("HashPassword returned empty string")
			}

			// Check that hash is base64 encoded
			_, err := base64.StdEncoding.DecodeString(hash)
			if err != nil {
				t.Errorf("HashPassword returned invalid base64 string: %v", err)
			}

			// Check that same password and salt produce same hash
			hash2 := HashPassword(tt.password, tt.salt)
			if hash != hash2 {
				t.Error("HashPassword is not deterministic")
			}

			// Check that different passwords produce different hashes
			if tt.password != "" {
				hash3 := HashPassword(tt.password+"x", tt.salt)
				if hash == hash3 {
					t.Error("Different passwords produced same hash")
				}
			}

			// Check that different salts produce different hashes
			if tt.salt != "" {
				hash4 := HashPassword(tt.password, tt.salt+"x")
				if hash == hash4 {
					t.Error("Different salts produced same hash")
				}
			}
		})
	}
}

func TestGenerateSalt(t *testing.T) {
	// Generate multiple salts to check uniqueness
	salts := make(map[string]bool)
	numSalts := 100

	for i := 0; i < numSalts; i++ {
		salt, err := GenerateSalt()
		if err != nil {
			t.Fatalf("GenerateSalt returned error: %v", err)
		}

		// Check that salt is not empty
		if salt == "" {
			t.Error("GenerateSalt returned empty string")
		}

		// Check that salt is base64 encoded
		_, err = base64.StdEncoding.DecodeString(salt)
		if err != nil {
			t.Errorf("GenerateSalt returned invalid base64 string: %v", err)
		}

		// Check that salt has correct length (32 bytes = 44 base64 chars)
		decoded, _ := base64.StdEncoding.DecodeString(salt)
		if len(decoded) != 32 {
			t.Errorf("GenerateSalt returned salt of wrong length: got %d, want 32", len(decoded))
		}

		// Check uniqueness
		if salts[salt] {
			t.Errorf("GenerateSalt produced duplicate salt: %s", salt)
		}
		salts[salt] = true
	}

	if len(salts) != numSalts {
		t.Errorf("Expected %d unique salts, got %d", numSalts, len(salts))
	}
}

func TestEncryptData(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		password string
	}{
		{
			name:     "simple data",
			data:     []byte("test data"),
			password: "testpassword",
		},
		{
			name:     "empty data",
			data:     []byte(""),
			password: "password123",
		},
		{
			name:     "large data",
			data:     make([]byte, 1024*1024), // 1MB
			password: "mypassword",
		},
		{
			name:     "json data",
			data:     []byte(`{"key":"value","number":123}`),
			password: "jsonpassword",
		},
		{
			name:     "unicode data",
			data:     []byte("Hello, 世界! 🌍"),
			password: "unicodepass",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := EncryptData(tt.data, tt.password)
			if err != nil {
				t.Fatalf("EncryptData returned error: %v", err)
			}

			// Check that encrypted data is not empty
			if len(encrypted) == 0 {
				t.Error("EncryptData returned empty data")
			}

			// Check that encrypted data is different from original
			if string(encrypted) == string(tt.data) {
				t.Error("Encrypted data is same as original")
			}

			// Check that encrypted data is longer than original (due to nonce)
			if len(encrypted) <= len(tt.data) {
				t.Errorf("Encrypted data should be longer than original: got %d, original %d", len(encrypted), len(tt.data))
			}

			// Check that multiple encryptions produce different ciphertexts (due to random nonce)
			encrypted2, err := EncryptData(tt.data, tt.password)
			if err != nil {
				t.Fatalf("EncryptData returned error on second encryption: %v", err)
			}

			if string(encrypted) == string(encrypted2) {
				t.Error("Multiple encryptions produced same ciphertext (nonce should be random)")
			}
		})
	}
}

func TestDecryptData(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		password string
	}{
		{
			name:     "simple data",
			data:     []byte("test data"),
			password: "testpassword",
		},
		{
			name:     "empty data",
			data:     []byte(""),
			password: "password123",
		},
		{
			name:     "json data",
			data:     []byte(`{"entries":[],"version":"1.0"}`),
			password: "jsonpassword",
		},
		{
			name:     "unicode data",
			data:     []byte("Hello, 世界! 🌍"),
			password: "unicodepass",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt first
			encrypted, err := EncryptData(tt.data, tt.password)
			if err != nil {
				t.Fatalf("EncryptData returned error: %v", err)
			}

			// Decrypt with correct password
			decrypted, err := DecryptData(encrypted, tt.password)
			if err != nil {
				t.Fatalf("DecryptData returned error: %v", err)
			}

			// Check that decrypted data matches original
			if string(decrypted) != string(tt.data) {
				t.Errorf("Decrypted data does not match original: got %s, want %s", string(decrypted), string(tt.data))
			}

			// Check that decryption with wrong password fails
			wrongPassword := tt.password + "wrong"
			_, err = DecryptData(encrypted, wrongPassword)
			if err == nil {
				t.Error("DecryptData with wrong password should return error")
			}
		})
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	testCases := []struct {
		name     string
		data     []byte
		password string
	}{
		{
			name:     "short message",
			data:     []byte("hello"),
			password: "secret",
		},
		{
			name:     "long message",
			data:     []byte("This is a much longer message that contains multiple sentences. It should still work correctly after encryption and decryption."),
			password: "mypassword",
		},
		{
			name:     "binary data",
			data:     []byte{0, 1, 2, 3, 255, 254, 253, 252},
			password: "binarypass",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encrypted, err := EncryptData(tc.data, tc.password)
			if err != nil {
				t.Fatalf("EncryptData failed: %v", err)
			}

			decrypted, err := DecryptData(encrypted, tc.password)
			if err != nil {
				t.Fatalf("DecryptData failed: %v", err)
			}

			if string(decrypted) != string(tc.data) {
				t.Errorf("Round trip failed: got %v, want %v", decrypted, tc.data)
			}
		})
	}
}

func TestDecryptData_InvalidCiphertext(t *testing.T) {
	tests := []struct {
		name        string
		ciphertext  []byte
		password    string
		expectError bool
	}{
		{
			name:        "empty ciphertext",
			ciphertext:  []byte{},
			password:    "password",
			expectError: true,
		},
		{
			name:        "too short ciphertext",
			ciphertext:  []byte{1, 2, 3},
			password:    "password",
			expectError: true,
		},
		{
			name:        "corrupted ciphertext",
			ciphertext:  []byte("this is not valid encrypted data"),
			password:    "password",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecryptData(tt.ciphertext, tt.password)
			if tt.expectError && err == nil {
				t.Error("Expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestHashPassword_ConstantTime(t *testing.T) {
	// This test ensures that hash comparison would work correctly with constant-time comparison
	password := "testpassword"
	salt := "testsalt"

	hash1 := HashPassword(password, salt)
	hash2 := HashPassword(password, salt)

	// Hashes should be equal
	if hash1 != hash2 {
		t.Error("Same password and salt should produce same hash")
	}

	// Verify they're equal using constant-time comparison (as done in production)
	if subtle.ConstantTimeCompare([]byte(hash1), []byte(hash2)) != 1 {
		t.Error("Constant-time comparison should indicate hashes are equal")
	}

	// Different password should produce different hash
	hash3 := HashPassword(password+"x", salt)
	if subtle.ConstantTimeCompare([]byte(hash1), []byte(hash3)) != 0 {
		t.Error("Constant-time comparison should indicate hashes are different")
	}
}

