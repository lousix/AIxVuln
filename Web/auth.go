package Web

import (
	"AIxVuln/misc"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// tokenSecret is generated once at startup so tokens are invalidated on restart.
var tokenSecret []byte

func init() {
	tokenSecret = make([]byte, 32)
	if _, err := rand.Read(tokenSecret); err != nil {
		panic("failed to generate token secret: " + err.Error())
	}
}


// tokenTTL defines how long a token is valid.
const tokenTTL = 7 * 24 * time.Hour

type tokenPayload struct {
	User string `json:"u"`
	Exp  int64  `json:"e"`
}

// generateToken creates an HMAC-signed token for the given user.
func generateToken(user string) string {
	payload := tokenPayload{User: user, Exp: time.Now().Add(tokenTTL).Unix()}
	js, _ := json.Marshal(payload)
	payloadHex := hex.EncodeToString(js)
	mac := hmac.New(sha256.New, tokenSecret)
	mac.Write(js)
	sig := hex.EncodeToString(mac.Sum(nil))
	return payloadHex + "." + sig
}

// validateToken checks the token and returns the username if valid.
func validateToken(token string) (string, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid token format")
	}
	payloadBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("invalid token payload")
	}
	expectedMac := hmac.New(sha256.New, tokenSecret)
	expectedMac.Write(payloadBytes)
	expectedSig := hex.EncodeToString(expectedMac.Sum(nil))
	if !hmac.Equal([]byte(parts[1]), []byte(expectedSig)) {
		return "", fmt.Errorf("invalid token signature")
	}
	var p tokenPayload
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		return "", fmt.Errorf("invalid token payload")
	}
	if time.Now().Unix() > p.Exp {
		return "", fmt.Errorf("token expired")
	}
	return p.User, nil
}

// loginHandler handles POST /login with JSON body {"username":"...","password":"..."}.
func loginHandler(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid request body"})
		return
	}
	if !misc.ValidateUser(req.Username, req.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "invalid credentials"})
		return
	}
	token := generateToken(req.Username)
	c.JSON(http.StatusOK, gin.H{"success": true, "token": token})
}

// tokenAuthMiddleware validates Bearer token or falls back to BasicAuth for backward compatibility.
func tokenAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")

		// Bearer token
		if strings.HasPrefix(auth, "Bearer ") {
			token := strings.TrimPrefix(auth, "Bearer ")
			user, err := validateToken(token)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "error": "unauthorized: " + err.Error()})
				return
			}
			c.Set("user", user)
			c.Next()
			return
		}

		// BasicAuth fallback (for backward compatibility with Wails GUI / scripts)
		if strings.HasPrefix(auth, "Basic ") {
			user, pass, ok := c.Request.BasicAuth()
			if ok && misc.ValidateUser(user, pass) {
				c.Set("user", user)
				c.Next()
				return
			}
		}

		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "error": "unauthorized"})
	}
}
