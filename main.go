package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"os"
	"strings"

	"crypto/cipher"
	"crypto/rand"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	KeySize   = 32
	NonceSize = 24
)

type Encryption struct {
	key [KeySize]byte
}

type FileEncryption struct {
	aead cipher.AEAD
}

// Initialize new encryption instance
func NewFileEncryption(password string) (*FileEncryption, error) {
	// Generate key from password
	key := make([]byte, KeySize)
	// You might want to use a proper key derivation function here
	copy(key, []byte(password))

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	return &FileEncryption{aead: aead}, nil
}

// Initialize new encryption instance
func NewEncryption(password string) *Encryption {
	// Generate key from password
	key := [KeySize]byte{}
	copy(key[:], []byte(password))
	return &Encryption{key: key}
}

// Encrypt data using libsodium (secretbox)
func (e *Encryption) Encrypt(data []byte) (string, error) {
	var nonce [NonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return "", err
	}

	encrypted := secretbox.Seal(nonce[:], data, &nonce, &e.key)
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// Encrypt File Using XChaCha20-Poly1305
func (e *FileEncryption) Encrypt(data []byte) (string, error) {
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Encrypt the data
	encrypted := e.aead.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// Decrypt data using libsodium (secretbox)
func (e *Encryption) Decrypt(encodedData string) ([]byte, error) {
	encrypted, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		return nil, err
	}

	var nonce [NonceSize]byte
	copy(nonce[:], encrypted[:NonceSize])
	decrypted, ok := secretbox.Open(nil, encrypted[NonceSize:], &nonce, &e.key)
	if !ok {
		return nil, fmt.Errorf("decryption failed")
	}

	return decrypted, nil
}

// Decrypt File Using XChaCha20-Poly1305
func (e *FileEncryption) Decrypt(encodedData string) ([]byte, error) {
	encrypted, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		return nil, err
	}

	if len(encrypted) < NonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := encrypted[:NonceSize]
	ciphertext := encrypted[NonceSize:]

	decrypted, err := e.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %v", err)
	}

	return decrypted, nil
}

func handleFileEncryption(file *multipart.FileHeader, password string) (string, error) {
	src, err := file.Open()
	if err != nil {
		return "", err
	}
	defer src.Close()

	content, err := io.ReadAll(src)
	if err != nil {
		return "", err
	}

	enc, err := NewFileEncryption(password)
	if err != nil {
		return "", err
	}

	return enc.Encrypt(content)
}

func handleFileDecryption(encryptedContent string, password string) ([]byte, error) {
	enc, err := NewFileEncryption(password)
	if err != nil {
		return nil, err
	}
	return enc.Decrypt(encryptedContent)
}

func main() {
	app := fiber.New(fiber.Config{
		BodyLimit: 5 * 1024 * 1024, // 5MB limit for file uploads
	})

	app.Use(cors.New())

	// app.Use(func(c *fiber.Ctx) error {
	// 	if c.Is("json") || c.Is("multipart") {
	// 		return c.Next()
	// 	}
	// 	return c.SendString("Only JSON and multipart/form-data allowed!")
	// })

	app.Post("/encrypt-file-send", func(c *fiber.Ctx) error {
		// Get the file from form-data
		file, err := c.FormFile("file")
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "No file uploaded",
			})
		}

		// Get password from form field
		password := c.FormValue("password")
		if password == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Password is required",
			})
		}

		// Handle file encryption
		encryptedContent, err := handleFileEncryption(file, password)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Encryption failed: " + err.Error(),
			})
		}

		// Get original filename and extension
		originalFilename := file.Filename
		encryptedFilename := fmt.Sprintf("%s.enc", originalFilename)

		// Set headers for file download
		c.Set("Content-Type", "application/octet-stream")
		c.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, encryptedFilename))

		// Write encrypted content to file
		err = os.WriteFile(encryptedFilename, []byte(encryptedContent), 0644)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to write encrypted file",
			})
		}

		return c.SendFile(encryptedFilename, false)
	})

	// Modified file decryption endpoint
	app.Post("/decrypt-file-send", func(c *fiber.Ctx) error {
		// Get the encrypted file
		file, err := c.FormFile("file")
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "No file uploaded",
			})
		}

		// Get password from form field
		password := c.FormValue("password")
		if password == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Password is required",
			})
		}

		// Read the encrypted file
		src, err := file.Open()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to open file",
			})
		}
		defer src.Close()

		// Read all content
		content, err := io.ReadAll(src)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to read file",
			})
		}

		// Split content into filename and encrypted data
		parts := strings.SplitN(string(content), "\n", 2)
		if len(parts) != 2 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid encrypted file format",
			})
		}

		originalFilename := parts[0]
		encryptedContent := parts[1]

		// Decrypt the content
		decryptedContent, err := handleFileDecryption(encryptedContent, password)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Decryption failed: " + err.Error(),
			})
		}

		// Determine content type (you might want to enhance this)
		contentType := "application/octet-stream"
		if strings.HasSuffix(strings.ToLower(originalFilename), ".txt") {
			contentType = "text/plain"
		}

		// Set headers for file download
		c.Set("Content-Type", contentType)
		c.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, originalFilename))

		return c.Send(decryptedContent)
	})

	// File encryption endpoint
	app.Post("/encrypt-file", func(c *fiber.Ctx) error {
		// Get the file from form-data
		file, err := c.FormFile("file")
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "No file uploaded",
			})
		}

		// Get password from form field
		password := c.FormValue("password")
		if password == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Password is required",
			})
		}

		// Handle file encryption
		encryptedContent, err := handleFileEncryption(file, password)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Encryption failed: " + err.Error(),
			})
		}

		return c.JSON(fiber.Map{
			"encrypted_content": encryptedContent,
			"original_filename": file.Filename,
		})
	})

	// File decryption endpoint
	app.Post("/decrypt-file", func(c *fiber.Ctx) error {
		type Request struct {
			EncryptedContent string `json:"encrypted_content"`
			Password         string `json:"password"`
		}

		var req Request
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request body",
			})
		}

		if req.EncryptedContent == "" || req.Password == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Encrypted content and password are required",
			})
		}

		// Handle file decryption
		decryptedContent, err := handleFileDecryption(req.EncryptedContent, req.Password)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Decryption failed: " + err.Error(),
			})
		}

		// Set appropriate headers for file download
		c.Set("Content-Type", "text/plain")
		c.Set("Content-Disposition", "attachment; filename=decrypted_file.txt")

		return c.Send(decryptedContent)
	})

	// Rich text content encryption endpoint
	app.Post("/encrypt-text", func(c *fiber.Ctx) error {
		type Request struct {
			Text     string `json:"text"`
			Password string `json:"password"`
		}

		var req Request
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request body",
			})
		}

		if req.Text == "" || req.Password == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Text and password are required",
			})
		}

		enc := NewEncryption(req.Password)
		encryptedContent, err := enc.Encrypt([]byte(req.Text))
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Encryption failed: " + err.Error(),
			})
		}

		return c.JSON(fiber.Map{
			"encrypted_content": encryptedContent,
		})
	})

	// Rich text content decryption endpoint
	app.Post("/decrypt-text", func(c *fiber.Ctx) error {
		type Request struct {
			EncryptedContent string `json:"encrypted_content"`
			Password         string `json:"password"`
		}

		var req Request
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request body",
			})
		}

		if req.EncryptedContent == "" || req.Password == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Encrypted content and password are required",
			})
		}

		enc := NewEncryption(req.Password)
		decryptedContent, err := enc.Decrypt(req.EncryptedContent)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Decryption failed: " + err.Error(),
			})
		}

		return c.JSON(fiber.Map{
			"decrypted_content": string(decryptedContent),
		})
	})

	log.Fatal(app.Listen(":80"))
}
