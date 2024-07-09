package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

var JUPYTERHUB_SECRET_KEY = "32-byte-long-key-1234567890ABCDE"
var JUPYTERHUB_HASH_KEY = "jupyterhub_hash_key"

type user struct {
	JupyterhubUserid string `json:"jupyterhub_user_id"`
	DpUsername       string `json:"username"`
	SQLEndpoint      string `json:"sql_endpoint"`
	expiryTimeFunc   func() int64
	ExpiryTime       int64  `json:"expiry_time"`
	AccessToken      string `json:"access_token"`
}

var userData = map[string]user{
	"sagar-c1": {
		JupyterhubUserid: "sagarsonwane-cluster-1",
		DpUsername:       "sagar.sonwane",
		SQLEndpoint:      "https://f450c395-6da3-4fc8-bec5-5c42f415a7de.joshclient.dp.datapelago.io/wright",
		expiryTimeFunc:   func() int64 { return time.Now().Add(time.Second * 10).Unix() },
		AccessToken:      "FdVCU48+ZMK+p4A1UwZ0dORNexqrQH7ZaOG3MlQ1LYfDFW02/4e/zzbrVG0PC75rI8ZoX3oOujZd3BO6kOfwOEV6CcAPCEmNGf0zNbtZjiIKqs/bvfQDrSRwMy3aFwc5V7fwKeS7mGZR3r/g4cmO+6kY+VZ1",
	},
	"anuj-c1": {
		JupyterhubUserid: "anuj-cluster-1",
		DpUsername:       "anuj",
		SQLEndpoint:      "https://f450c395-6da3-4fc8-bec5-5c42f415a7de.joshclient.dp.datapelago.io/wright",
		expiryTimeFunc:   func() int64 { return time.Now().Add(time.Second * 10).Unix() },
		AccessToken:      "Qxzv2QS/ep8J99FT9xAUkPHVhJMj5JvGIVrIa0+v37fp0nysXcXZpgtrYdy2+ttjbBe58Rjh1B8oq0BqDvxHjMVJMiI9eP70AmGzfnwtwBDYBED53qU+WcxHTXnR7Mm8nlcD1QN65cpXKyNTERF3yh5rpHuvZg==",
	},
	"sagar-c2": {
		JupyterhubUserid: "sagarsonwane-cluster-2",
		DpUsername:       "sagar.sonwane",
		SQLEndpoint:      "https://926d8f6c-e682-4198-aae2-af4a0faad402.joshclient.dp.datapelago.io/wright",
		expiryTimeFunc:   func() int64 { return time.Now().Add(time.Second * 10).Unix() },
		AccessToken:      "FdVCU48+ZMK+p4A1UwZ0dORNexqrQH7ZaOG3MlQ1LYfDFW02/4e/zzbrVG0PC75rI8ZoX3oOujZd3BO6kOfwOEV6CcAPCEmNGf0zNbtZjiIKqs/bvfQDrSRwMy3aFwc5V7fwKeS7mGZR3r/g4cmO+6kY+VZ1",
	},
	"sagar": {
		JupyterhubUserid: "sagarsonwane",
		DpUsername:       "sagar.sonwane",
		SQLEndpoint:      "https://7ae986ab-670c-41c1-9068-82eda3d3e5bc.joshclient.dp.datapelago.io/wright",
		expiryTimeFunc:   func() int64 { return time.Now().Add(time.Second * 10).Unix() },
		AccessToken:      "7Pw97oO8kZgJzjTUiWhJ37gem5Gv6D5OATZfGNGhjWPLkEwJw7XvPQ46rGvdMaMZyvKtKDeHVxrVQSqZZW2bev+AoDI1PYI8SspOr4Pg/rUD6dw3T5ym5JFtV7jaxFNQQiGf0wAsdzfqdgs8U9dzmKCygUj0no4=",
	},
	"johndoe": {
		DpUsername:     "johndoe.user",
		SQLEndpoint:    "https://301657bb-1210-43d9-bedf-945b2bcc8a7c.joshclient.dp.datapelago.io/wright",
		expiryTimeFunc: func() int64 { return time.Now().Add(time.Second * 10).Unix() },
		AccessToken:    "z9GrXiBwYnKgzatanugc4xO+7f2Ms21lSQvxQreaZM+SJ7PuJUJTARRg/hNx4WISYXQZOvjLay0xQVEa1E4qboVHlALc42Gv2D62dY3zwzlrhtuNuS+Y0A6ffnMleQeAk0tDc69rxXAYqv8ElONQkOoCOkk91/g=",
	},
	"testuser": {
		DpUsername:     "test.user",
		SQLEndpoint:    "https://301657bb-1210-43d9-bedf-945b2bcc8a7c.joshclient.dp.datapelago.io/wright",
		expiryTimeFunc: func() int64 { return time.Now().Add(time.Second * 10).Unix() },
		AccessToken:    "z9GrXiBwYnKgzatanugc4xO+7f2Ms21lSQvxQreaZM+SJ7PuJUJTARRg/hNx4WISYXQZOvjLay0xQVEa1E4qboVHlALc42Gv2D62dY3zwzlrhtuNuS+Y0A6ffnMleQeAk0tDc69rxXAYqv8ElONQkOoCOkk91/g=",
	},
	"sabo": {
		DpUsername:     "sabo.user",
		SQLEndpoint:    "https://301657bb-1210-43d9-bedf-945b2bcc8a7c.joshclient.dp.datapelago.io/wright",
		expiryTimeFunc: func() int64 { return time.Now().Add(time.Second * 10).Unix() },
		AccessToken:    "z9GrXiBwYnKgzatanugc4xO+7f2Ms21lSQvxQreaZM+SJ7PuJUJTARRg/hNx4WISYXQZOvjLay0xQVEa1E4qboVHlALc42Gv2D62dY3zwzlrhtuNuS+Y0A6ffnMleQeAk0tDc69rxXAYqv8ElONQkOoCOkk91/g=",
	},
	"anuj": {
		DpUsername:     "anuj.user",
		SQLEndpoint:    "https://301657bb-1210-43d9-bedf-945b2bcc8a7c.joshclient.dp.datapelago.io/wright",
		expiryTimeFunc: func() int64 { return time.Now().Add(time.Second * 10).Unix() },
		AccessToken:    "z9GrXiBwYnKgzatanugc4xO+7f2Ms21lSQvxQreaZM+SJ7PuJUJTARRg/hNx4WISYXQZOvjLay0xQVEa1E4qboVHlALc42Gv2D62dY3zwzlrhtuNuS+Y0A6ffnMleQeAk0tDc69rxXAYqv8ElONQkOoCOkk91/g=",
	},
	"john": {
		DpUsername:     "john.user",
		SQLEndpoint:    "https://301657bb-1210-43d9-bedf-945b2bcc8a7c.joshclient.dp.datapelago.io/wright",
		expiryTimeFunc: func() int64 { return time.Now().Add(time.Second * 10).Unix() },
		AccessToken:    "z9GrXiBwYnKgzatanugc4xO+7f2Ms21lSQvxQreaZM+SJ7PuJUJTARRg/hNx4WISYXQZOvjLay0xQVEa1E4qboVHlALc42Gv2D62dY3zwzlrhtuNuS+Y0A6ffnMleQeAk0tDc69rxXAYqv8ElONQkOoCOkk91/g=",
	},
	"renato": {
		DpUsername:     "renato.user",
		SQLEndpoint:    "https://301657bb-1210-43d9-bedf-945b2bcc8a7c.joshclient.dp.datapelago.io/wright",
		expiryTimeFunc: func() int64 { return time.Now().Add(time.Second * 20).Unix() },
		AccessToken:    "z9GrXiBwYnKgzatanugc4xO+7f2Ms21lSQvxQreaZM+SJ7PuJUJTARRg/hNx4WISYXQZOvjLay0xQVEa1E4qboVHlALc42Gv2D62dY3zwzlrhtuNuS+Y0A6ffnMleQeAk0tDc69rxXAYqv8ElONQkOoCOkk91/g=",
	},
	"samuel": {
		DpUsername:     "samuel.user",
		SQLEndpoint:    "https://301657bb-1210-43d9-bedf-945b2bcc8a7c.joshclient.dp.datapelago.io/wright",
		expiryTimeFunc: func() int64 { return time.Now().Add(time.Second * 10).Unix() },
		AccessToken:    "z9GrXiBwYnKgzatanugc4xO+7f2Ms21lSQvxQreaZM+SJ7PuJUJTARRg/hNx4WISYXQZOvjLay0xQVEa1E4qboVHlALc42Gv2D62dY3zwzlrhtuNuS+Y0A6ffnMleQeAk0tDc69rxXAYqv8ElONQkOoCOkk91/g=",
	},
}

var (
	jupyterURL = "http://localhost:8005/hub/login" // Replace with your JupyterHub URL
)

func EncryptAndHash(encryptionKey, hashKey, data []byte) (string, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}
	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	// Generate HMAC for the ciphertext
	hash := GenerateHMAC(hashKey, ciphertext)

	// Append hash to the ciphertext
	token := append(ciphertext, hash...)

	return base64.RawURLEncoding.EncodeToString(token), nil
}

// GenerateHMAC generates an HMAC for a given message and key
func GenerateHMAC(key, message []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(message)
	return hash.Sum(nil)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("name")
	fmt.Println(username)
	// Read data from request body

	userData := userData[username]
	userData.ExpiryTime = userData.expiryTimeFunc()
	jsonData, err := json.Marshal(userData)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return
	}
	time.Sleep(time.Second * 2)

	token, err := EncryptAndHash([]byte(JUPYTERHUB_SECRET_KEY), []byte(JUPYTERHUB_HASH_KEY), jsonData)
	if err != nil {
		fmt.Println("Error encrypting data:", err)
		return
	}

	// Convert encrypted data to base64 for easy transmission
	// encryptedDataString := base64.StdEncoding.EncodeToString(jsonData)

	fmt.Println("Encrypted Data : ", token)
	fmt.Println("Time Now : ", time.Now().Add(time.Second*10).Unix())
	// Redirect to JupyterHub login with encrypted token as query param
	http.Redirect(w, r, fmt.Sprintf("%s?token=%v", jupyterURL, token), http.StatusFound)
}

func main() {
	http.HandleFunc("/connect_to_console", handleLogin)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
