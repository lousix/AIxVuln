package misc

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

var userTableOnce sync.Once

func initUserTable() {
	userTableOnce.Do(func() {
		initConfigDB()
		configDB.Exec(`
			CREATE TABLE IF NOT EXISTS users (
				username TEXT PRIMARY KEY,
				password_hash TEXT NOT NULL
			);
		`)
	})
}

func hashPassword(password string) string {
	h := sha256.Sum256([]byte(password))
	return hex.EncodeToString(h[:])
}

// HasAnyUser returns true if at least one user exists in the database.
func HasAnyUser() bool {
	initUserTable()
	var count int
	configDB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count)
	return count > 0
}

// CreateUser creates a new user with the given username and password.
func CreateUser(username, password string) error {
	initUserTable()
	_, err := configDB.Exec(`INSERT INTO users (username, password_hash) VALUES (?, ?)`,
		username, hashPassword(password))
	return err
}

// ValidateUser checks if the username and password are correct.
func ValidateUser(username, password string) bool {
	initUserTable()
	var storedHash string
	err := configDB.QueryRow(`SELECT password_hash FROM users WHERE username = ?`, username).Scan(&storedHash)
	if err != nil {
		return false
	}
	return storedHash == hashPassword(password)
}

// UpdatePassword updates the password for an existing user.
func UpdatePassword(username, newPassword string) error {
	initUserTable()
	_, err := configDB.Exec(`UPDATE users SET password_hash = ? WHERE username = ?`,
		hashPassword(newPassword), username)
	return err
}
