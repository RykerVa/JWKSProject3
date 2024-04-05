package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"
	"math/big"
	"sync"
	"io"
	"crypto/sha256"
	//"encoding/hex"
	"os"

	"github.com/google/uuid"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/argon2"
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
)

const (
	dbPath         = "totally_not_my_privateKeys.db"
	authorizedKID  = "AuthorizedGoodKeyID"
	serverPort     = ":8080"
	expirationTime = 1 * time.Hour
	argonTime      = 1              // Iterations
	argonMemory    = 64 * 1024      // Memory usage in KB
	argonThreads   = 4              // Parallelism
	argonKeyLen    = 32             // Key length
	rateLimit      = 10             // Requests per second
	rateBurst      = rateLimit * 10 // Burst rate
	maxRequests    = 10           // Maximum number of requests allowed per time window
    windowDuration = 1 * time.Second // Time window duration
)

var (
    requestCounterMu sync.Mutex
    requestCounter   = make(map[string]int)
    lastReset        = time.Now()
	aesKey = aesKeyFromEnv()
)

func main() {
	db := initDB(dbPath)
	defer db.Close()

	initializeKeyStore(db)

	r := mux.NewRouter()
	r.HandleFunc("/.well-known/jwks.json", jwksHandler(db)).Methods("GET")
	r.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		limiterMiddleware(authHandler(db)).ServeHTTP(w, r)
	}).Methods("POST")
	r.HandleFunc("/register", registerHandler(db)).Methods("POST")

	log.Println("Starting server on", serverPort)
	if err := http.ListenAndServe(serverPort, r); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func limiterMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Check if the request exceeds the rate limit
        if isRateLimited(r.RemoteAddr) {
            // Return 429 Too Many Requests response
            w.Header().Set("Content-Type", "text/html")
            w.Header().Set("Retry-After", "3600")
            w.WriteHeader(http.StatusTooManyRequests)
            w.Write([]byte(`<html><head><title>Too Many Requests</title></head><body><h1>Too Many Requests</h1><p>I only allow 50 requests per hour to this Web site per logged in user.  Try again soon.</p></body></html>`))
            return
        }

        // Call the next handler if the request is within the rate limit
        next.ServeHTTP(w, r)
    })
}

func isRateLimited(ip string) bool {
    // Acquire the lock to ensure safe concurrent access to the request counter map
    requestCounterMu.Lock()
    defer requestCounterMu.Unlock()

    // Reset the request counter if the time window has elapsed
    if time.Since(lastReset) >= windowDuration {
        requestCounter = make(map[string]int)
        lastReset = time.Now()
    }

    // Increment the request count for the given IP address
    requestCounter[ip]++

    // Check if the request count exceeds the maximum allowed requests
    return requestCounter[ip] > maxRequests
}

func aesKeyFromEnv() []byte {
	key := os.Getenv("NOT_MY_KEY")
	// Hash the key using SHA-256 to ensure a fixed-length key
	hasher := sha256.New()
	hasher.Write([]byte(key))
	return hasher.Sum(nil)
}

// Encrypts data using AES with the provided key.
func encrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// Decrypts data using AES with the provided key.
func decrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, err
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func initDB(dbPath string) *sql.DB {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}

	createTableSQL := `
    CREATE TABLE IF NOT EXISTS keys (
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP      
    );

	CREATE TABLE IF NOT EXISTS auth_logs(
	    id INTEGER PRIMARY KEY AUTOINCREMENT,
	    request_ip TEXT NOT NULL,
	    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	    user_id INTEGER,  
	    FOREIGN KEY(user_id) REFERENCES users(id)
	);`

	if _, err = db.Exec(createTableSQL); err != nil {
		log.Fatalf("Error creating tables: %v", err)
	}

	return db
}

func registerHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user struct {
			Username string `json:"username"`
			Email    string `json:"email"`
		}

		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		password := generateSecurePassword()

		hashedPassword := hashPassword(password)

		_, err := db.Exec("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
			user.Username, hashedPassword, user.Email)
		if err != nil {
			http.Error(w, "Failed to register user", http.StatusInternalServerError)
			return
		}

		response := struct {
			Password string `json:"password"`
		}{
			Password: password,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(response)
	}
}

func generateSecurePassword() string {
	// Generate a random UUIDv4
	uuidV4 := uuid.New()
	return uuidV4.String()
}

func hashPassword(password string) string {
	hash := argon2.IDKey([]byte(password), []byte(""), argonTime, argonMemory, argonThreads, argonKeyLen)
	return string(hash)
}

func initializeKeyStore(db *sql.DB) {
	generateAndStoreKey(db, time.Now().Add(expirationTime).Unix())  // Valid key
	generateAndStoreKey(db, time.Now().Add(-expirationTime).Unix()) // Expired key
}

func generateAndStoreKey(db *sql.DB, exp int64) {
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        log.Fatalf("Error generating RSA key: %v", err)
    }

    privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

    // Encrypt the private key before storing it in the database
    encryptedPrivateKey, err := encrypt(privateKeyBytes, aesKey)
    if err != nil {
        log.Fatalf("Error encrypting private key: %v", err)
    }

    _, err = db.Exec("INSERT INTO keys (key, exp) VALUES (?, ?)", encryptedPrivateKey, exp)
    if err != nil {
        log.Fatalf("Error inserting key into database: %v", err)
    }
}

func jwksHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		keys := getKeysFromDB(db)
		resp := JWKS{Keys: keys}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func getKeysFromDB(db *sql.DB) []JWK {
	var keys []JWK
	rows, err := db.Query("SELECT kid, key FROM keys WHERE exp > ?", time.Now().Unix())
	if err != nil {
		log.Println("Database error:", err)
		return keys
	}
	defer rows.Close()

	for rows.Next() {
		var kid int
		var keyPEM []byte
		if err := rows.Scan(&kid, &keyPEM); err != nil {
			log.Println("Failed to fetch keys:", err)
			continue
		}
		block, _ := pem.Decode(keyPEM)
		if block == nil {
			log.Println("Failed to parse PEM block containing the key")
			continue
		}

		pubKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			log.Println("Failed to parse private key:", err)
			continue
		}
		jwk := generateJWK(pubKey.Public().(*rsa.PublicKey), strconv.Itoa(kid))
		keys = append(keys, jwk)
	}
	return keys
}

func generateJWK(pubKey *rsa.PublicKey, kid string) JWK {
	return JWK{
		KID:       kid,
		Algorithm: "RS256",
		KeyType:   "RSA",
		Use:       "sig",
		N:         base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
		E:         base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes()),
	}
}

func authHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		username, _, ok := r.BasicAuth()
		if !ok {
			var creds struct {
				Username string `json:"username"`
				Password string `json:"password"`
			}
			if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
				http.Error(w, "Invalid authentication method!", http.StatusBadRequest)
				return
			}
			username = creds.Username
		}

		expired, _ := strconv.ParseBool(r.URL.Query().Get("expired"))
		signingKey, kid, err := fetchSigningKey(db, expired)
		if err != nil {
			http.Error(w, "Failed to fetch key", http.StatusInternalServerError)
			return
		}

		claims := jwt.MapClaims{
			"iss": "jwks-server",
			"sub": username,
			"exp": time.Now().Add(time.Hour * 1).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = kid

		tokenString, err := token.SignedString(signingKey)
		if err != nil {
			http.Error(w, "Failed to sign token", http.StatusInternalServerError)
			return
		}

		logAuthRequest(db, r.RemoteAddr, username)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
	}
}

func logAuthRequest(db *sql.DB, requestIP, username string) {
	var userID int
	err := db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
	if err != nil {
		log.Printf("Failed to get user ID for username %s: %v", username, err)
		return
	}

	_, err = db.Exec("INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)", requestIP, userID)
	if err != nil {
		log.Printf("Failed to log authentication request: %v", err)
	}
}

func fetchSigningKey(db *sql.DB, expired bool) (*rsa.PrivateKey, string, error) {
	var keyPEM []byte
	var kid int
	var err error

	if expired {
		err = db.QueryRow("SELECT kid, key FROM keys WHERE exp <= ?", time.Now().Unix()).Scan(&kid, &keyPEM)
	} else {
		err = db.QueryRow("SELECT kid, key FROM keys WHERE exp > ?", time.Now().Unix()).Scan(&kid, &keyPEM)
	}

	if err != nil {
		return nil, "", err
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, "", errors.New("failed to parse PEM block containing the key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, "", err
	}

	return privateKey, strconv.Itoa(kid), nil
}

type JWK struct {
	KID       string `json:"kid"`
	Algorithm string `json:"alg"`
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	N         string `json:"n"`
	E         string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}
