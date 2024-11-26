package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
)

var db *sql.DB

// connect to database
func init() {
	var err error
	dsn := "root:password123@tcp(127.0.0.1:3306)/vehicle_rental_db" // Update with MySQL credentials
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Error connecting to the database: %v", err)
	}
	if err := db.Ping(); err != nil {
		log.Fatalf("Error verifying database: %v", err)
	}
	fmt.Println("Database connected successfully!")
}

// Hash password
func hashPassword(password string) string {
	hash := sha256.New()
	hash.Write([]byte(password))
	return hex.EncodeToString(hash.Sum(nil))
}

// register form
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		http.ServeFile(w, r, "register.html")
		return
	}
	if r.Method == http.MethodPost {
		//parse form data
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")

		//hash the password
		passwordHash := hashPassword(password)

		//insert into database
		_, err := db.Exec("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
			username, email, passwordHash) //membership_tier_id will be default to 1 which is standard
		if err != nil {
			http.Error(w, "Failed to register user. Please try again.", http.StatusInternalServerError)
			log.Printf("Error inserting user: %v\n", err)
			return
		}
	}
}

// login form
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		http.ServeFile(w, r, "login.html") // Serve a login form
		return
	}
	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		password := r.FormValue("password")
		passwordHash := hashPassword(password)

		var username string
		var membershipTierID int
		err := db.QueryRow("SELECT username, membership_tier_id FROM users WHERE email = ? AND password_hash = ?", email, passwordHash).
			Scan(&username, &membershipTierID)
		if err == sql.ErrNoRows {
			http.Error(w, "Invalid email or password.", http.StatusUnauthorized)
			return
		} else if err != nil {
			log.Printf("Database error: %v\n", err)
			http.Error(w, "Internal server error.", http.StatusInternalServerError)
			return
		}

		log.Printf("User logged in: %s with Membership Tier ID: %d\n", username, membershipTierID)
		http.Redirect(w, r, "/", http.StatusSeeOther) // Redirect to homepage or dashboard
	}
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "index.html")
	})
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	log.Println("Server started at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
