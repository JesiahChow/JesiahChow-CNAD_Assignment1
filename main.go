package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/smtp"
	"regexp"
	"strconv"
	"text/template"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

// store cookie
var store = sessions.NewCookieStore([]byte("your-secret-key"))

var userdb *sql.DB
var vehicledb *sql.DB
var reservationdb *sql.DB
var billingdb *sql.DB
var promotiondb *sql.DB

// Initialize separate connections for each service
func init() {
	var err error

	// User Service DB
	dsnUser := "root:password123@tcp(127.0.0.1:3306)/user_service_db"
	userdb, err = sql.Open("mysql", dsnUser)
	if err != nil {
		log.Fatalf("Error connecting to the User Service database: %v", err)
	}
	if err := userdb.Ping(); err != nil {
		log.Fatalf("Error verifying User Service database: %v", err)
	}
	fmt.Println("User Service database connected successfully!")

	// Vehicle Service DB
	dsnVehicle := "root:password123@tcp(127.0.0.1:3306)/vehicle_service_db"
	vehicledb, err = sql.Open("mysql", dsnVehicle)
	if err != nil {
		log.Fatalf("Error connecting to the Vehicle Service database: %v", err)
	}
	if err := vehicledb.Ping(); err != nil {
		log.Fatalf("Error verifying Vehicle Service database: %v", err)
	}
	fmt.Println("Vehicle Service database connected successfully!")

	// Reservation Service DB
	dsnReservation := "root:password123@tcp(127.0.0.1:3306)/reservation_service_db"
	reservationdb, err = sql.Open("mysql", dsnReservation)
	if err != nil {
		log.Fatalf("Error connecting to the Reservation Service database: %v", err)
	}
	if err := reservationdb.Ping(); err != nil {
		log.Fatalf("Error verifying Reservation Service database: %v", err)
	}
	fmt.Println("Reservation Service database connected successfully!")

	// Billing Service DB
	dsnBilling := "root:password123@tcp(127.0.0.1:3306)/billing_service_db"
	billingdb, err = sql.Open("mysql", dsnBilling)
	if err != nil {
		log.Fatalf("Error connecting to the Billing Service database: %v", err)
	}
	if err := billingdb.Ping(); err != nil {
		log.Fatalf("Error verifying Billing Service database: %v", err)
	}
	fmt.Println("Billing Service database connected successfully!")
	// Promotion Service DB
	dsnPromotion := "root:password123@tcp(127.0.0.1:3306)/promotion_service_db"
	promotiondb, err = sql.Open("mysql", dsnPromotion)
	if err != nil {
		log.Fatalf("Error connecting to the Promotion Service database: %v", err)
	}
	if err := promotiondb.Ping(); err != nil {
		log.Fatalf("Error verifying Promotion Service database: %v", err)
	}
	fmt.Println("Promotion Service database connected successfully!")
}

// struct to represent vehicle
type Vehicle struct {
	ID           int     `json:"id"`
	LicensePlate string  `json:"license_plate"`
	Model        string  `json:"model"`
	Location     string  `json:"location"`
	HourlyRate   float64 `json:"hourly_rate"`
}

// Define Reservation struct and VehicleInfo struct
type VehicleInfo struct {
	LicensePlate string  `json:"license_plate"`
	Model        string  `json:"model"`
	Status       string  `json:"status"`
	Location     string  `json:"location"`
	HourlyRate   float64 `json:"hourly_rate"`
}

type Reservation struct {
	ID          int         `json:"id"`
	VehicleID   int         `json:"vehicle_id"`
	StartTime   string      `json:"start_time"`
	EndTime     string      `json:"end_time"`
	TotalPrice  float64     `json:"total_price"`
	Status      string      `json:"status"`
	VehicleInfo VehicleInfo `json:"vehicle_info"`
}

// Hash password
func hashPassword(password string) string {
	hash := sha256.New()
	hash.Write([]byte(password))
	return hex.EncodeToString(hash.Sum(nil))
}

// generate token
func generateVerificationToken() string {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		log.Fatalf("Error generating token: %v", err)
	}
	return base64.URLEncoding.EncodeToString(token)
}

// Send the verification email
func sendVerificationEmail(email, token string) {
	log.Printf("Simulating email sending to %s with token: %s\n", email, token)
	// Generate the verification link
	link := fmt.Sprintf("http://localhost:8080/verify?token=%s", token)

	// Construct the message
	message := fmt.Sprintf("Subject: Email Verification\n\nClick on the following link to verify your email: %s", link)

	// Set up the email sender and SMTP server
	senderEmail := "bettercallvolt@gmail.com" // sender email
	senderPassword := "qxfcqajpzeutxvxm"      //password retrieved from app password
	smtpServer := "smtp.gmail.com"
	smtpPort := "587" // Gmail's SMTP port

	// Authentication for the SMTP server
	auth := smtp.PlainAuth("", senderEmail, senderPassword, smtpServer)

	// Send the email
	err := smtp.SendMail(
		smtpServer+":"+smtpPort,
		auth,
		senderEmail,
		[]string{email}, // recipient email
		[]byte(message), // email content
	)

	if err != nil {
		log.Printf("Error sending email: %v\n", err)
	} else {
		log.Printf("Sent email to %s with verification link: %s\n", email, link)
	}
}

// Verify Handler
func verifyHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	var userID int

	// Check if the token matches any user
	err := userdb.QueryRow("SELECT id FROM users WHERE verification_token = ?", token).Scan(&userID)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusBadRequest)
		return
	}

	// Mark the user as verified
	_, err = userdb.Exec("UPDATE users SET is_verified = TRUE WHERE id = ?", userID)
	if err != nil {
		http.Error(w, "Error verifying user", http.StatusInternalServerError)
		return
	}
	// Render the verification success page
	tmpl, err := template.ParseFiles("verify.html")
	if err != nil {
		log.Printf("Template parsing error: %v\n", err)
		http.Error(w, "Internal server error.", http.StatusInternalServerError)
		return
	}

	tmpl.Execute(w, struct {
		Message string
	}{Message: "Your email has been successfully verified! You can now log in."})
}

// validate email address when user registers
func isValidEmail(email string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return re.MatchString(email)
}

// validate password when user registers
func isValidPassword(password string) bool {
	return len(password) >= 8 // Add more complexity checks if needed
}

// registerHandler handles both GET and POST requests for the registration form
func registerHandler(w http.ResponseWriter, r *http.Request) {
	// If the method is GET, serve the registration page with no error message
	if r.Method == http.MethodGet {
		// Parse the registration template
		tmpl, err := template.ParseFiles("register.html")
		if err != nil {
			// If there is an error in parsing, log the error and return an internal server error
			log.Printf("Template parsing error: %v\n", err)
			http.Error(w, "Internal server error.", http.StatusInternalServerError)
			return
		}
		// Serve the registration page with an empty error message
		tmpl.Execute(w, struct {
			ErrorMessage string
		}{ErrorMessage: ""})
		return
	}

	// If the method is POST, handle form submission
	if r.Method == http.MethodPost {
		// Parse the form values
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")
		log.Printf("Received registration data: username=%s, email=%s", username, email)

		// Check if the username already exists in the database
		var existingUsername string
		err := userdb.QueryRow("SELECT username FROM users WHERE username = ?", username).Scan(&existingUsername)
		if err != sql.ErrNoRows {
			// If the username exists, send an error message to the template
			tmpl, err := template.ParseFiles("register.html")
			if err != nil {
				log.Printf("Template parsing error: %v\n", err)
				http.Error(w, "Internal server error.", http.StatusInternalServerError)
				return
			}
			// Pass error message to the template
			tmpl.Execute(w, struct {
				ErrorMessage string
			}{ErrorMessage: "Username is already taken. Please try another one."})
			return
		}

		// Check if the email already exists in the database
		var existingEmail string
		err = userdb.QueryRow("SELECT email FROM users WHERE email = ?", email).Scan(&existingEmail)
		if err != sql.ErrNoRows {
			// If the email exists, send an error message to the template
			tmpl, err := template.ParseFiles("register.html")
			if err != nil {
				log.Printf("Template parsing error: %v\n", err)
				http.Error(w, "Internal server error.", http.StatusInternalServerError)
				return
			}
			// Pass error message to the template
			tmpl.Execute(w, struct {
				ErrorMessage string
			}{ErrorMessage: "Email is already in use. Please try another one."})
			return
		} else if !isValidEmail(email) {
			// If the email format is invalid, throw an error message
			http.Error(w, "Invalid email format", http.StatusBadRequest)
			// Render the registration page with an error message for invalid email format
			tmpl, err := template.ParseFiles("register.html")
			if err != nil {
				log.Printf("Template parsing error: %v\n", err)
				http.Error(w, "Internal server error.", http.StatusInternalServerError)
				return
			}
			tmpl.Execute(w, struct {
				ErrorMessage string
			}{ErrorMessage: "Invalid email format."})
			return
		}

		// Check if the password meets the required length (8 characters or more)
		if !isValidPassword(password) {
			// If the password is too short, return an error message
			http.Error(w, "Password needs to be at least 8 characters long", http.StatusBadRequest)
			// Render the registration page with an error message for password length
			tmpl, err := template.ParseFiles("register.html")
			if err != nil {
				log.Printf("Template parsing error: %v\n", err)
				http.Error(w, "Internal server error.", http.StatusInternalServerError)
				return
			}
			tmpl.Execute(w, struct {
				ErrorMessage string
			}{ErrorMessage: "Password needs to be at least 8 characters long."})
			return
		}

		// Hash the password before storing it in the database for security
		passwordHash := hashPassword(password)
		log.Println("Password hashed successfully")

		// Generate a unique verification token for email verification
		verificationToken := generateVerificationToken()
		log.Printf("Generated verification token: %s", verificationToken)

		// Insert the user details into the database (username, email, hashed password, and verification token)
		_, err = userdb.Exec("INSERT INTO users (username, email, password_hash, verification_token) VALUES (?, ?, ?, ?)",
			username, email, passwordHash, verificationToken)
		if err != nil {
			// If there's an error inserting into the database, return an error response
			http.Error(w, "Failed to register user. Please try again.", http.StatusInternalServerError)
			log.Printf("Error inserting user: %v\n", err)
			return
		}

		// Send a verification email to the user with the verification token
		sendVerificationEmail(email, verificationToken)

		// Registration is successful, inform the user and prompt them to check their email for verification
		fmt.Fprintln(w, "Registration successful! Please check your email to verify your account.")
	}
}

// loginHandler handles both GET and POST requests for the login form
func loginHandler(w http.ResponseWriter, r *http.Request) {
	// If the method is GET, serve the login page with an empty error message
	if r.Method == http.MethodGet {
		// Parse the login template
		tmpl, err := template.ParseFiles("login.html")
		if err != nil {
			// If there is an error in parsing, log the error and return an internal server error
			log.Printf("Template parsing error: %v\n", err)
			http.Error(w, "Internal server error.", http.StatusInternalServerError)
			return
		}
		// Serve the login page with an empty error message
		tmpl.Execute(w, struct {
			ErrorMessage string
		}{ErrorMessage: ""})
		return
	}

	// If the method is POST, handle form submission
	if r.Method == http.MethodPost {
		// Retrieve user input (email and password) from the form
		email := r.FormValue("email")
		password := r.FormValue("password")

		// Hash the user-provided password for comparison with the stored hash
		passwordHash := hashPassword(password)

		// Declare variables to store user information retrieved from the database
		var username string
		var membershipTierID, userId int
		var storedPasswordHash string
		var isVerified bool

		// Query the database to retrieve the user data based on the provided email
		err := userdb.QueryRow("SELECT id, username, membership_tier_id, password_hash, is_verified FROM users WHERE email = ?", email).
			Scan(&userId, &username, &membershipTierID, &storedPasswordHash, &isVerified)

		// If no user is found or if the password hashes do not match, send an error message
		if err == sql.ErrNoRows || passwordHash != storedPasswordHash {
			// Parse the login template again and display an error message
			tmpl, err := template.ParseFiles("login.html")
			if err != nil {
				log.Printf("Template parsing error: %v\n", err)
				http.Error(w, "Internal server error.", http.StatusInternalServerError)
				return
			}
			// Pass error message to the template (invalid email or password)
			tmpl.Execute(w, struct {
				ErrorMessage string
			}{ErrorMessage: "Invalid email or password"})
			return
		}

		// If the user is not verified, show an error message to verify the email first
		if !isVerified {
			tmpl, err := template.ParseFiles("login.html")
			if err != nil {
				log.Printf("Template parsing error: %v\n", err)
				http.Error(w, "Internal server error.", http.StatusInternalServerError)
				return
			}
			// Pass error message to the template (email not verified)
			tmpl.Execute(w, struct {
				ErrorMessage string
			}{ErrorMessage: "Please verify your email first."})
			return
		} else if err != nil {
			// If there is a database error (other than no rows found), log and send internal server error
			log.Printf("Database error: %v\n", err)
			http.Error(w, "Internal server error.", http.StatusInternalServerError)
			return
		}

		// If login is successful, save user details in the session
		session, _ := store.Get(r, "user-session")
		session.Values["username"] = username               // Store the username in the session
		session.Values["loggedIn"] = true                   // Mark the user as logged in
		session.Values["membershipTier"] = membershipTierID // Store the user's membership tier ID
		session.Values["UserID"] = userId                   // Store the user's ID in the session

		// Debug log to verify the session values after login
		log.Printf("Session values after login: %v", session.Values)

		// Save the session data
		err = session.Save(r, w)
		if err != nil {
			// If there is an error saving the session, log and return internal server error
			log.Printf("Error saving session: %v", err)
			http.Error(w, "Failed to save session", http.StatusInternalServerError)
			return
		}

		// Log the successful login event
		log.Printf("User logged in: %s with Membership Tier ID: %d and user id: %d \n", username, membershipTierID, userId)

		// Redirect the user to the homepage or dashboard after successful login
		http.Redirect(w, r, "/home", http.StatusSeeOther)
	}
}

// homeHandler renders the home page after verifying if the user is logged in
func homeHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve session data
	session, _ := store.Get(r, "user-session")
	log.Printf("Session values after login: %v", session.Values)

	// Check if the user is logged in
	loggedIn, _ := session.Values["loggedIn"].(bool)
	username, _ := session.Values["username"].(string)

	// If user is not logged in, redirect to login page
	if !loggedIn {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Retrieve the user's membership tier from the database
	var membershipTier string
	err := userdb.QueryRow("SELECT membership_tiers.name FROM users INNER JOIN membership_tiers ON users.membership_tier_id = membership_tiers.id WHERE users.username = ?", username).Scan(&membershipTier)
	if err != nil {
		// If there's an error retrieving the membership tier, log it and return an internal server error
		log.Printf("Error retrieving membership tier: %v\n", err)
		http.Error(w, "Internal server error.", http.StatusInternalServerError)
		return
	}

	// Parse and render the home page template
	tmpl, err := template.ParseFiles("home.html")
	if err != nil {
		// If there is an error parsing the template, log it and return an internal server error
		log.Printf("Template parsing error: %v\n", err)
		http.Error(w, "Internal server error.", http.StatusInternalServerError)
		return
	}

	// Execute the template with user data (login status, username, and membership tier)
	tmpl.Execute(w, struct {
		isLoggedIn     bool
		Username       string
		MembershipTier string
	}{
		isLoggedIn:     loggedIn,
		Username:       username,
		MembershipTier: membershipTier,
	})

	// Send a success message as a JSON response (for any possible API integration)
	response := struct {
		Message string `json:"message"`
	}{"Login successful"}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// profileHandler handles the user's profile page (view and update)
func profileHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve session data
	session, _ := store.Get(r, "user-session")
	log.Printf("Session values after login: %v", session.Values)
	loggedIn, _ := session.Values["loggedIn"].(bool)
	username, _ := session.Values["username"].(string)

	// If the user is not logged in, redirect to login page
	if !loggedIn {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Handle GET request: Fetch and display the current profile details
	if r.Method == http.MethodGet {
		// Fetch user details (email and membership tier) from the database
		var email, membershipTier string
		err := userdb.QueryRow("select email, (select name from membership_tiers where id = membership_tier_id) as membership_tier from users where username = ?", username).Scan(&email, &membershipTier)
		if err != nil {
			// If there is an error fetching user details, log and return an internal server error
			log.Printf("Error fetching user details: %v", err)
			http.Error(w, "Internal server error.", http.StatusInternalServerError)
			return
		}

		// Parse and render the profile page template
		tmpl, err := template.ParseFiles("profile.html")
		if err != nil {
			// If there is an error parsing the template, log it and return an internal server error
			log.Printf("Template parsing error: %v", err)
			http.Error(w, "Internal server error.", http.StatusInternalServerError)
			return
		}

		// Execute the template with current user data (username, email, membership tier)
		tmpl.Execute(w, struct {
			Username       string
			Email          string
			MembershipTier string
			ErrorMessage   string
		}{
			Username:       username,
			Email:          email,
			MembershipTier: membershipTier,
			ErrorMessage:   "", // Empty error message for GET request
		})
	} else if r.Method == http.MethodPost {
		// Handle POST request: Process profile updates

		// Retrieve the new user data from the form
		newUsername := r.FormValue("username")
		newEmail := r.FormValue("email")
		newPassword := r.FormValue("password")

		// Check if the new username is already taken
		if newUsername != username {
			var existingId int
			err := userdb.QueryRow("select id from users where username = ?", newUsername).Scan(&existingId)
			if err == nil {
				// If the username is already taken, render the profile page with an error message
				tmpl, _ := template.ParseFiles("profile.html")
				tmpl.Execute(w, struct {
					Username       string
					Email          string
					MembershipTier string
					ErrorMessage   string
				}{
					Username:       username,
					Email:          newEmail,
					MembershipTier: "",
					ErrorMessage:   "Username already taken.",
				})
				return
			}
		}

		// Prepare the SQL query to update the user's profile
		query := "UPDATE users SET username = ?, email = ?"
		args := []interface{}{newUsername, newEmail}

		// If a new password is provided, hash it and include it in the update query
		if newPassword != "" {
			passwordHash := hashPassword(newPassword)
			query += ", password_hash = ?"
			args = append(args, passwordHash)
		}

		// Add the condition to update the profile of the current user
		query += " WHERE username = ?"
		args = append(args, username)

		// Execute the SQL query to update the user in the database
		_, err := userdb.Exec(query, args...)
		if err != nil {
			// If there is an error updating the profile, log and return an internal server error
			log.Printf("Error updating user profile: %v", err)
			http.Error(w, "Failed to update profile. Please try again.", http.StatusInternalServerError)
			return
		}

		// If profile updated successfully, update the session with the new username
		session.Values["username"] = newUsername
		session.Save(r, w)

		// Redirect to the profile page to display updated information
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
	}
}

// MembershipTier represents a membership tier
type MembershipTier struct {
	ID           int
	Name         string
	Benefits     string
	DiscountRate float64
	Price        float64
	IsCurrent    bool
}

// upgradeMembershipHandler handles the user's membership tier upgrade request
func upgradeMembershipHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve session data
	session, _ := store.Get(r, "user-session")

	// Ensure the request method is PUT (updating data)
	if r.Method != http.MethodPut {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Get the membership tier ID from the URL path variable
	membershipTierID := mux.Vars(r)["id"]

	// Get the user ID from the session
	userID := session.Values["UserID"].(int)

	// Update the user's membership tier in the database
	_, err := userdb.Exec("UPDATE users SET membership_tier_id = ? WHERE id = ?", membershipTierID, userID)
	if err != nil {
		// If an error occurs while updating the membership tier, log the error and return a server error
		http.Error(w, "Error upgrading membership", http.StatusInternalServerError)
		log.Printf("Error updating membership: %v\n", err)
		return
	}

	// Update the session with the new membership tier
	session.Values["membershipTier"] = membershipTierID
	session.Save(r, w)

	// Respond with a success message in JSON format
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Membership upgraded successfully!",
	})
}

// membershipHandler renders the membership page where users can view and upgrade their membership tiers
func membershipHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve session data
	session, _ := store.Get(r, "user-session")
	loggedIn, _ := session.Values["loggedIn"].(bool)
	username, _ := session.Values["username"].(string)

	// Check if the user is logged in, if not, redirect to login page
	if !loggedIn {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Retrieve the current membership tier from the session
	membershipTier, _ := session.Values["membershipTier"].(int)

	// Fetch all membership tiers from the database
	rows, err := userdb.Query("SELECT id, name, benefits, discount_rate, price FROM membership_tiers")
	if err != nil {
		// If there's an error fetching membership tiers, log and return an internal server error
		http.Error(w, "Error loading membership tiers", http.StatusInternalServerError)
		log.Printf("Database error: %v\n", err)
		return
	}
	defer rows.Close()

	// Define a slice to store the membership tiers
	var tiers []MembershipTier

	// Loop through the rows and scan the data into the struct
	for rows.Next() {
		var tier MembershipTier
		err := rows.Scan(&tier.ID, &tier.Name, &tier.Benefits, &tier.DiscountRate, &tier.Price)
		if err != nil {
			// If an error occurs while reading the membership tier data, log and return an internal server error
			http.Error(w, "Error reading membership tiers", http.StatusInternalServerError)
			log.Printf("Database error: %v\n", err)
			return
		}
		// Mark the user's current membership tier for easier identification in the UI
		tier.IsCurrent = (tier.ID == membershipTier)
		// Append the tier to the tiers slice
		tiers = append(tiers, tier)
	}

	// Parse the membership page template
	tmpl, err := template.ParseFiles("membership.html")
	if err != nil {
		// If there's an error parsing the template, log and return an internal server error
		http.Error(w, "Error loading page", http.StatusInternalServerError)
		log.Printf("Template error: %v\n", err)
		return
	}

	// Execute the template with the username and membership tiers data
	err = tmpl.Execute(w, struct {
		Username string
		Tiers    []MembershipTier
	}{
		Username: username,
		Tiers:    tiers,
	})
	if err != nil {
		// If there's an error rendering the page, log and return an internal server error
		http.Error(w, "Error rendering page", http.StatusInternalServerError)
		log.Printf("Template rendering error: %v\n", err)
	}
}

// logoutHandler logs the user out by clearing the session and redirecting to the login page
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve session data
	session, _ := store.Get(r, "user-session")

	// Clear the session values (logout the user)
	session.Values["loggedIn"] = false
	session.Values["username"] = nil
	session.Values["UserID"] = nil

	// Save the session changes
	session.Save(r, w)

	// Redirect the user to the login page after logging out
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// / availableVehiclesHandler handles the request to view available vehicles in real-time
func availableVehiclesHandler(w http.ResponseWriter, r *http.Request) {
	// Ensure the request method is GET (fetching data)
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Query the database for vehicles with status 'available'
	rows, err := vehicledb.Query("SELECT id, license_plate, model, location, hourly_rate FROM vehicles WHERE status = 'available'")
	if err != nil {
		http.Error(w, "Failed to retrieve available vehicles", http.StatusInternalServerError)
		log.Printf("Database query error: %v\n", err)
		return
	}
	defer rows.Close()

	// Create a slice to store vehicle data
	var vehicles []Vehicle

	// Loop through the rows and scan each vehicle's data into the struct
	for rows.Next() {
		var vehicle Vehicle
		err := rows.Scan(&vehicle.ID, &vehicle.LicensePlate, &vehicle.Model, &vehicle.Location, &vehicle.HourlyRate)
		if err != nil {
			http.Error(w, "Error reading vehicle data", http.StatusInternalServerError)
			log.Printf("Row scan error: %v\n", err)
			return
		}
		// Append each vehicle to the vehicles slice
		vehicles = append(vehicles, vehicle)
	}

	// Respond with the available vehicles in JSON format
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(vehicles)
	if err != nil {
		http.Error(w, "Error encoding JSON response", http.StatusInternalServerError)
		log.Printf("JSON encoding error: %v\n", err)
	}
}

// availableReservationsHandler retrieves the available vehicles from the vehicle service and returns them
func availableReservationsHandler(w http.ResponseWriter, r *http.Request) {
	// Ensure the request method is GET
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Call the vehicle service to fetch available vehicles
	resp, err := http.Get("http://localhost:8081/vehicles/available")
	if err != nil {
		http.Error(w, "Error contacting Vehicle Service", http.StatusInternalServerError)
		log.Printf("Error contacting Vehicle Service: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// Decode the response body from the vehicle service into a slice of vehicles
	var vehicles []Vehicle
	err = json.NewDecoder(resp.Body).Decode(&vehicles)
	if err != nil {
		http.Error(w, "Error decoding Vehicle Service response", http.StatusInternalServerError)
		log.Printf("Error decoding response: %v\n", err)
		return
	}

	// Respond with the available vehicles in JSON format
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(vehicles)
	if err != nil {
		http.Error(w, "Error encoding JSON response", http.StatusInternalServerError)
		log.Printf("Error encoding response: %v\n", err)
	}
}

// createReservationHandler handles creating a new reservation and reserving a vehicle
func createReservationHandler(w http.ResponseWriter, r *http.Request) {
	// Ensure the request method is POST
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Define a struct to represent the reservation data from the request body
	var reservation struct {
		UserID     int     `json:"user_id"`
		VehicleID  int     `json:"vehicle_id"`
		StartTime  string  `json:"start_time"`
		EndTime    string  `json:"end_time"`
		TotalPrice float64 `json:"total_price"`
	}

	// Decode the reservation details from the request body
	err := json.NewDecoder(r.Body).Decode(&reservation)
	if err != nil {
		http.Error(w, "Error decoding reservation data", http.StatusInternalServerError)
		log.Printf("Error decoding request body: %v\n", err)
		return
	}

	// Insert the reservation data into the reservation database
	_, err = reservationdb.Exec("INSERT INTO reservations (user_id, vehicle_id, start_time, end_time, total_price) VALUES (?, ?, ?, ?, ?)",
		reservation.UserID, reservation.VehicleID, reservation.StartTime, reservation.EndTime, reservation.TotalPrice)
	if err != nil {
		http.Error(w, "Error creating reservation", http.StatusInternalServerError)
		log.Printf("Received reservation data: %+v\n", reservation)
		log.Printf("Error inserting reservation into database: %v\n", err)
		return
	}

	// Update the reservation status to 'active' in the database
	_, err = reservationdb.Exec("UPDATE reservations SET status = 'active' WHERE vehicle_id = ? AND user_id = ? AND start_time = ?",
		reservation.VehicleID, reservation.UserID, reservation.StartTime)
	if err != nil {
		http.Error(w, "Error updating reservation status", http.StatusInternalServerError)
		log.Printf("Error updating reservation status: %v\n", err)
		return
	}

	// Call the Vehicle Service to update the vehicle's status to 'reserved'
	vehicleServiceURL := fmt.Sprintf("http://localhost:8080/vehicles/reserve/%d", reservation.VehicleID)
	resp, err := http.Post(vehicleServiceURL, "application/json", nil)
	if err != nil {
		log.Printf("Error calling Vehicle Service: %v\n", err)
		http.Error(w, "Error reserving vehicle", http.StatusInternalServerError)
		return
	}
	log.Printf("Vehicle Service Response: %v\n", resp.StatusCode) // Log the status code of the response

	// If the Vehicle Service response is not OK, return an error
	if resp.StatusCode != http.StatusOK {
		http.Error(w, "Error reserving vehicle", http.StatusInternalServerError)
		return
	}

	// Respond with a success message
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Reservation successful, vehicle reserved.",
	})
}

// reserveVehicleHandler handles the request to reserve a vehicle in the Vehicle Service
func reserveVehicleHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve session data
	session, err := store.Get(r, "user-session")
	log.Printf("Session values: %v", session.Values)

	// Extract the vehicle ID from the URL path
	vehicleID := mux.Vars(r)["vehicle_id"]
	log.Printf("Vehicle ID from URL: %s", vehicleID)

	// Update the vehicle's status to 'reserved' in the database
	_, err = vehicledb.Exec("UPDATE vehicles SET status = 'reserved' WHERE id = ?", vehicleID)
	if err != nil {
		http.Error(w, "Error updating vehicle status", http.StatusInternalServerError)
		log.Printf("Error updating vehicle status in Vehicle Service: %v\n", err)
		return
	}
	log.Printf("Vehicle ID %s status updated to 'reserved'", vehicleID)

	// Respond with a success message indicating the vehicle is reserved
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Vehicle successfully reserved.",
	})
}

// VehiclesPageHandler serves the Available Vehicles page
func VehiclesPageHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve session and check if the user is logged in
	session, _ := store.Get(r, "user-session")
	loggedIn, _ := session.Values["loggedIn"].(bool)
	userID, _ := session.Values["UserID"].(int)

	// If the user is not logged in, redirect to the login page
	if !loggedIn {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Serve the HTML page for available vehicles
	tmpl, err := template.ParseFiles("availableVehicles.html")
	if err != nil {
		// If there is an error loading the template, send an internal server error
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		log.Printf("Template parsing error: %v", err)
		return
	}

	// Pass the user ID to the template for dynamic rendering
	tmpl.Execute(w, map[string]interface{}{
		"UserID": userID,
	})
	log.Printf("user id: %d \n", userID)
}

// getVehicleDetailsHandler retrieves and returns details of a specific vehicle based on its ID
func getVehicleDetailsHandler(w http.ResponseWriter, r *http.Request) {
	// Extract the vehicle ID from the URL parameters
	vehicleID := mux.Vars(r)["vehicle_id"]

	// Define a struct to hold the vehicle details
	var vehicle struct {
		ID           int     `json:"id"`
		LicensePlate string  `json:"license_plate"`
		Model        string  `json:"model"`
		Status       string  `json:"status"`
		Location     string  `json:"location"`
		HourlyRate   float64 `json:"hourly_rate"`
	}

	// Query the database for the vehicle details
	err := vehicledb.QueryRow(
		"SELECT id, license_plate, model, status, location, hourly_rate FROM vehicles WHERE id = ?",
		vehicleID,
	).Scan(&vehicle.ID, &vehicle.LicensePlate, &vehicle.Model, &vehicle.Status, &vehicle.Location, &vehicle.HourlyRate)

	if err != nil {
		// If no rows are found, return a 404 error
		if err == sql.ErrNoRows {
			http.Error(w, "Vehicle not found", http.StatusNotFound)
		} else {
			// Handle other errors as internal server errors
			http.Error(w, "Error fetching vehicle details", http.StatusInternalServerError)
			log.Printf("Error querying vehicle: %v\n", err)
		}
		return
	}

	// Send the vehicle details as a JSON response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(vehicle)
}

// getReservationsHandler retrieves the active reservations for the logged-in user
func getReservationsHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve session and check if the user is logged in
	session, _ := store.Get(r, "user-session")
	log.Printf("Session values after login: %v", session.Values)
	loggedIn, _ := session.Values["loggedIn"].(bool)
	userID, _ := session.Values["UserID"].(int)

	// If the user is not logged in, redirect to the login page
	if !loggedIn {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Query the database for active reservations for the logged-in user
	rows, err := reservationdb.Query("SELECT id, vehicle_id, start_time, end_time, total_price, status FROM reservations WHERE user_id = ? and status = 'active'", userID)
	if err != nil {
		http.Error(w, "Error fetching reservations", http.StatusInternalServerError)
		log.Printf("Database query error: %v\n", err)
		return
	}
	defer rows.Close()

	// Define a slice to hold the reservations
	var reservations []struct {
		ID          int     `json:"id"`
		VehicleID   int     `json:"vehicle_id"`
		StartTime   string  `json:"start_time"`
		EndTime     string  `json:"end_time"`
		TotalPrice  float64 `json:"total_price"`
		Status      string  `json:"status"`
		VehicleInfo struct {
			LicensePlate string  `json:"license_plate"`
			Model        string  `json:"model"`
			Status       string  `json:"status"`
			Location     string  `json:"location"`
			HourlyRate   float64 `json:"hourly_rate"`
		} `json:"vehicle_info"`
	}

	// Loop through each reservation and fetch the vehicle details
	for rows.Next() {
		var reservation struct {
			ID          int     `json:"id"`
			VehicleID   int     `json:"vehicle_id"`
			StartTime   string  `json:"start_time"`
			EndTime     string  `json:"end_time"`
			TotalPrice  float64 `json:"total_price"`
			Status      string  `json:"status"`
			VehicleInfo struct {
				LicensePlate string  `json:"license_plate"`
				Model        string  `json:"model"`
				Status       string  `json:"status"`
				Location     string  `json:"location"`
				HourlyRate   float64 `json:"hourly_rate"`
			} `json:"vehicle_info"`
		}

		// Scan reservation data from the database
		err := rows.Scan(&reservation.ID, &reservation.VehicleID, &reservation.StartTime, &reservation.EndTime, &reservation.TotalPrice, &reservation.Status)
		if err != nil {
			http.Error(w, "Error scanning reservations", http.StatusInternalServerError)
			log.Printf("Error scanning row: %v\n", err)
			return
		}

		// Fetch vehicle details from Vehicle Service
		vehicleServiceURL := fmt.Sprintf("http://localhost:8080/vehicles/%d", reservation.VehicleID)
		resp, err := http.Get(vehicleServiceURL)
		if err != nil || resp.StatusCode != http.StatusOK {
			log.Printf("Error fetching vehicle details for vehicle_id %d: %v\n", reservation.VehicleID, err)
			continue
		}

		// Decode the vehicle details
		err = json.NewDecoder(resp.Body).Decode(&reservation.VehicleInfo)
		if err != nil {
			log.Printf("Error decoding vehicle details: %v\n", err)
			continue
		}

		// Append the reservation to the list
		reservations = append(reservations, reservation)
	}

	// Render the reservations page with the fetched data
	tmpl, err := template.ParseFiles("reservations.html")
	if err != nil {
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		log.Printf("Template parsing error: %v", err)
		return
	}

	// Pass the user ID and reservations data to the template
	tmpl.Execute(w, map[string]interface{}{
		"UserID":       userID,
		"Reservations": reservations, // Pass reservations to the template
	})
}

// isModificationAllowed checks if the modification is allowed based on the time policy
func isModificationAllowed(reservationID string) bool {
	// Get the reservation start time from the database
	var startTime string
	query := "SELECT start_time FROM reservations WHERE id = ?"
	err := reservationdb.QueryRow(query, reservationID).Scan(&startTime)
	if err != nil {
		log.Printf("Error fetching reservation start time: %v\n", err)
		return false // If an error occurs, disallow modification
	}

	// Parse the start time into a time.Time object
	reservationStartTime, err := time.Parse("2006-01-02 15:04:05", startTime)
	if err != nil {
		log.Printf("Error parsing reservation start time: %v\n", err)
		return false // If parsing fails, disallow modification
	}

	// Get the current time
	currentTime := time.Now()

	// Ensure modification is allowed only if the start time is more than 1 hour away
	if reservationStartTime.Sub(currentTime) <= 1*time.Hour {
		log.Printf("Modification not allowed: current time (%v) is within 1 hour of reservation start time (%v)\n", currentTime, reservationStartTime)
		return false // Reservation cannot be modified within 1 hour of start time
	}

	return true // Reservation can be modified if more than 1 hour before start time
}

// updateReservationHandler handles updating the reservation
func updateReservationHandler(w http.ResponseWriter, r *http.Request) {
	// Ensure the request is PUT
	if r.Method != http.MethodPut {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Get reservation ID from URL
	reservationID := mux.Vars(r)["id"]

	// Parse the request body
	var reservation struct {
		StartTime  string  `json:"start_time"`
		EndTime    string  `json:"end_time"`
		TotalPrice float64 `json:"total_price"`
	}

	err := json.NewDecoder(r.Body).Decode(&reservation)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusInternalServerError)
		return
	}

	// Check if modification is allowed (within 1 hour policy)
	if !isModificationAllowed(reservationID) {
		http.Error(w, "Modification not allowed within 1 hour of start time", http.StatusBadRequest)
		return
	}

	// Parse start and end times
	startTime, err := time.Parse("2006-01-02 15:04:05", reservation.StartTime)
	if err != nil {
		http.Error(w, "Invalid start time format", http.StatusBadRequest)
		return
	}

	endTime, err := time.Parse("2006-01-02 15:04:05", reservation.EndTime)
	if err != nil {
		http.Error(w, "Invalid end time format", http.StatusBadRequest)
		return
	}

	// Update the reservation in the database
	_, err = reservationdb.Exec("UPDATE reservations SET start_time = ?, end_time = ?, total_price = ? WHERE id = ?", startTime.Format("2006-01-02 15:04:05"), endTime.Format("2006-01-02 15:04:05"), reservation.TotalPrice, reservationID)
	if err != nil {
		http.Error(w, "Error updating reservation", http.StatusInternalServerError)
		return
	}

	// Send success response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Reservation updated successfully!",
	})
}

// updateVehicleAvailability updates the vehicle status to 'available'
func updateVehicleAvailability(vehicleID int) error {
	// Update the vehicle status to 'available' in the database
	_, err := vehicledb.Exec("UPDATE vehicles SET status = 'available' WHERE id = ?", vehicleID)
	return err
}

// isCancellationAllowed checks if cancellation is allowed based on the time policy
func isCancellationAllowed(reservationID string) bool {
	// Get the reservation start time from the database
	var startTime string
	query := "SELECT start_time FROM reservations WHERE id = ?"
	err := reservationdb.QueryRow(query, reservationID).Scan(&startTime)
	if err != nil {
		log.Printf("Error fetching reservation start time: %v\n", err)
		return false // If an error occurs, disallow cancellation
	}

	// Parse the start time into a time.Time object
	reservationStartTime, err := time.Parse("2006-01-02 15:04:05", startTime)
	if err != nil {
		log.Printf("Error parsing reservation start time: %v\n", err)
		return false // If parsing fails, disallow cancellation
	}

	// Get the current time
	currentTime := time.Now()

	// Ensure cancellation is allowed only if more than 1 hour before the reservation start time
	if reservationStartTime.Sub(currentTime) <= 1*time.Hour {
		return false // Cancellation not allowed within 1 hour of start time
	}

	return true // Cancellation is allowed if more than 1 hour before start time
}

// cancelReservationHandler handles the cancellation of a reservation
func cancelReservationHandler(w http.ResponseWriter, r *http.Request) {
	// Ensure the request is DELETE
	if r.Method != http.MethodDelete {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Get reservation ID from URL
	reservationID := mux.Vars(r)["id"]

	// Check if cancellation is allowed based on the time policy
	if !isCancellationAllowed(reservationID) {
		http.Error(w, "Cancellation not allowed within 1 hour of start time", http.StatusBadRequest)
		return
	}

	// Mark the reservation as canceled in the database
	_, err := reservationdb.Exec("UPDATE reservations SET status = 'canceled' WHERE id = ?", reservationID)
	if err != nil {
		http.Error(w, "Error canceling reservation", http.StatusInternalServerError)
		return
	}

	// Get the vehicle ID associated with the canceled reservation
	var vehicleID int
	err = reservationdb.QueryRow("SELECT vehicle_id FROM reservations WHERE id = ?", reservationID).Scan(&vehicleID)
	if err != nil {
		http.Error(w, "Error fetching vehicle ID", http.StatusInternalServerError)
		return
	}

	// Update the vehicle availability to 'available'
	err = updateVehicleAvailability(vehicleID)
	if err != nil {
		http.Error(w, "Error updating vehicle availability", http.StatusInternalServerError)
		return
	}

	// Send success response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Reservation canceled and vehicle status updated to 'available' successfully!",
	})
}

// getReservationDetails fetches reservation details and returns them as a struct
func getReservationDetails(reservationID int) (Reservation, error) {
	// Fetch reservation details from the database
	rows, err := reservationdb.Query("SELECT id, vehicle_id, start_time, end_time, total_price, status FROM reservations WHERE id = ? and status = 'active'", reservationID)
	if err != nil {
		return Reservation{}, fmt.Errorf("Error fetching reservations: %v", err)
	}
	defer rows.Close()

	var reservations Reservation
	if rows.Next() {
		// Scan reservation data from the query result
		err = rows.Scan(&reservations.ID, &reservations.VehicleID, &reservations.StartTime, &reservations.EndTime, &reservations.TotalPrice, &reservations.Status)
		if err != nil {
			return Reservation{}, fmt.Errorf("Error scanning reservations: %v", err)
		}

		// Fetch vehicle details from Vehicle Service (assuming vehicle info is available via an API)
		vehicleServiceURL := fmt.Sprintf("http://localhost:8080/vehicles/%d", reservations.VehicleID)
		resp, err := http.Get(vehicleServiceURL)
		if err != nil || resp.StatusCode != http.StatusOK {
			return Reservation{}, fmt.Errorf("Error fetching vehicle details for vehicle_id %d: %v", reservations.VehicleID, err)
		}

		// Decode the vehicle details into the reservation object
		err = json.NewDecoder(resp.Body).Decode(&reservations.VehicleInfo)
		if err != nil {
			return Reservation{}, fmt.Errorf("Error decoding vehicle details: %v", err)
		}
	} else {
		// Return error if no reservation is found for the given ID
		return Reservation{}, fmt.Errorf("Reservation with ID %d not found", reservationID)
	}

	// Check for any error that occurred during row iteration
	if err := rows.Err(); err != nil {
		return Reservation{}, fmt.Errorf("Error iterating over rows: %v", err)
	}
	return reservations, nil
}

// getMembershipDiscount retrieves the membership discount based on the user's session
func getMembershipDiscount(w http.ResponseWriter, r *http.Request) {
	// Retrieve session details
	session, err := store.Get(r, "user-session")
	if err != nil {
		log.Printf("Error retrieving session: %v", err)
		http.Error(w, "Failed to retrieve session", http.StatusInternalServerError)
		return
	}
	cookie, err := r.Cookie("user-session")
	if err != nil {
		log.Printf("Session cookie missing: %v", err)
	} else {
		log.Printf("Session cookie: %v", cookie.Value)
	}

	log.Printf("Session values before fetching membership discount: %v", session.Values)
	membershipTier, _ := session.Values["membershipTier"].(int)

	// Ensure the correct HTTP method is used
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Query to fetch membership discount details from the database
	rows, err := userdb.Query("select name, discount_rate from membership_tiers where id = ?", membershipTier)
	if err != nil {
		http.Error(w, "Failed to retrieve membership details", http.StatusInternalServerError)
		log.Printf("Database query error: %v\n", err)
		return
	}
	defer rows.Close()

	// Define a struct to hold membership data
	type Membership struct {
		Name         string  `json:"name"`
		DiscountRate float64 `json:"discount_rate"`
	}

	var membership Membership

	// Scan the query result into the membership struct
	if rows.Next() {
		err := rows.Scan(&membership.Name, &membership.DiscountRate)
		if err != nil {
			http.Error(w, "Error reading membership data", http.StatusInternalServerError)
			log.Printf("Row scan error: %v\n", err)
			return
		}
	} else {
		// Return error if membership tier not found
		http.Error(w, "Membership tier not found", http.StatusNotFound)
		return
	}

	// Respond with the membership details as JSON
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(membership)
	if err != nil {
		http.Error(w, "Error encoding JSON response", http.StatusInternalServerError)
		log.Printf("JSON encoding error: %v\n", err)
	}
}

// getMembershipDiscountRate retrieves the discount rate for the given membership tier ID
func getMembershipDiscountRate(membershipTierID int, r *http.Request) (float64, string, error) {
	// Construct the URL for the getMembershipDiscount API
	url := fmt.Sprintf("http://localhost:8080/membership/discount/%d", membershipTierID)
	log.Printf("Fetching membership discount from URL: %s", url)

	// Create a new HTTP request to fetch the discount
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, "", fmt.Errorf("error creating request to get membership discount: %v", err)
	}

	// Copy session cookie from incoming request to the new request
	cookie, err := r.Cookie("user-session")
	if err != nil {
		return 0, "", fmt.Errorf("session cookie missing: %v", err)
	}
	req.AddCookie(cookie)

	// Send the HTTP request to the external service
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("error making request to get membership discount: %v", err)
	}
	defer resp.Body.Close()

	// Check for successful response status
	if resp.StatusCode != http.StatusOK {
		return 0, "", fmt.Errorf("received non-OK response from getMembershipDiscount API: %v", resp.Status)
	}

	// Read and log the response body for debugging
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, "", fmt.Errorf("error reading response body: %v", err)
	}
	log.Printf("Response Body: %s", string(body))

	// Parse the response body into the membership struct
	var membership struct {
		Name         string  `json:"name"`
		DiscountRate float64 `json:"discount_rate"`
	}
	err = json.Unmarshal(body, &membership)
	if err != nil {
		return 0, "", fmt.Errorf("error decoding membership discount response: %v", err)
	}

	// Return the discount rate and membership name
	return membership.DiscountRate, membership.Name, nil
}

// getPromoCodeDiscount fetches the discount details for the promo code from the database
func getPromoCodeDiscount(w http.ResponseWriter, r *http.Request) {
	promoCode := mux.Vars(r)["promoCode"]

	// Query to fetch promo code details from the database
	var promo struct {
		Code         string  `json:"code"`
		DiscountRate float64 `json:"discount_rate"`
		IsActive     bool    `json:"is_active"`
	}

	// Query to get promo details
	query := "SELECT code, discount_rate, is_active FROM promotions WHERE code = ?"
	err := promotiondb.QueryRow(query, promoCode).Scan(&promo.Code, &promo.DiscountRate, &promo.IsActive)

	// Error handling for missing or inactive promo codes
	if err == sql.ErrNoRows {
		http.Error(w, "Promo code not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "Failed to retrieve promotion details", http.StatusInternalServerError)
		log.Printf("Database query error: %v\n", err)
		return
	}

	// Check if promo code is active
	if !promo.IsActive {
		http.Error(w, "Promo code is inactive", http.StatusBadRequest)
		return
	}

	// Respond with the promo code details as JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(promo); err != nil {
		http.Error(w, "Error encoding promo code details", http.StatusInternalServerError)
		log.Printf("JSON encoding error: %v\n", err)
	}
}

// Function to get promo code discount rate from the promotion service
func getPromoDiscount(promoCode string) (float64, error) {
	// Construct the URL for the promotion service API
	url := fmt.Sprintf("http://localhost:8080/promotion/discount/%s", promoCode)

	// Send HTTP GET request to fetch the promo discount
	resp, err := http.Get(url)
	if err != nil {
		return 0, fmt.Errorf("error making request to get promo code discount: %v", err)
	}
	defer resp.Body.Close()

	// Check if the response is successful
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("received non-OK response from promotion service: %v", resp.Status)
	}

	// Log the raw response for debugging purposes
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("error reading response body: %v", err)
	}
	log.Printf("Promo code response: %s", string(body))

	// Parse the response JSON to get promo details
	var promo struct {
		DiscountRate float64 `json:"discount_rate"`
	}
	err = json.Unmarshal(body, &promo)
	if err != nil {
		return 0, fmt.Errorf("error decoding promo code response: %v", err)
	}

	return promo.DiscountRate, nil
}

// applyPromoCode handles the application of a promo code and recalculates the final price.
func applyPromoCode(w http.ResponseWriter, r *http.Request) {
	// Ensure the request method is POST (promotions are applied via POST requests)
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Parse the request body to extract the promo code and current price
	var promoReq struct {
		PromoCode    string  `json:"promoCode"`    // Promo code provided by the client (optional)
		CurrentPrice float64 `json:"currentPrice"` // Current price of the reservation or product
	}

	// Decode the JSON body into the promoReq struct
	err := json.NewDecoder(r.Body).Decode(&promoReq)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// If no promo code is provided, return the original price without applying any discount
	if promoReq.PromoCode == "" {
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(map[string]interface{}{
			"success":  true,
			"newPrice": promoReq.CurrentPrice, // Return the current price as is if no promo code
		})
		if err != nil {
			http.Error(w, "Error encoding response", http.StatusInternalServerError)
			return
		}
		return
	}

	// Define the promotion struct to hold promo code details
	type Promotion struct {
		Code         string  `json:"code"`          // Promo code
		DiscountRate float64 `json:"discount_rate"` // Discount percentage
		IsActive     bool    `json:"is_active"`     // Whether the promo code is active or not
	}

	// Get promo details from the database using the provided promo code
	promoCode := promoReq.PromoCode
	var promo Promotion

	// Query the promotions table to get the promo details
	query := "SELECT code, discount_rate, is_active FROM promotions WHERE code = ?"
	err = promotiondb.QueryRow(query, promoCode).Scan(&promo.Code, &promo.DiscountRate, &promo.IsActive)

	// Handle cases where the promo code is not found
	if err == sql.ErrNoRows {
		http.Error(w, "Promo code not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "Failed to retrieve promo details", http.StatusInternalServerError)
		log.Printf("Database query error: %v\n", err)
		return
	}

	// Check if the promo code is active, if not, return an error
	if !promo.IsActive {
		http.Error(w, "Promo code is inactive", http.StatusBadRequest)
		return
	}

	// Validate the promo code's discount rate
	if promo.DiscountRate < 0 || promo.DiscountRate > 100 {
		http.Error(w, "Invalid promo code discount", http.StatusBadRequest)
		return
	}

	// Calculate the new final price by applying the promo code discount
	newPrice := promoReq.CurrentPrice * (1 - promo.DiscountRate/100)

	// Validate the current price to ensure it's a positive value
	if promoReq.CurrentPrice <= 0 {
		http.Error(w, "Invalid current price", http.StatusBadRequest)
		return
	}

	// Respond with the recalculated price
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"discountRate": promo.DiscountRate, // Return the applied discount rate
		"newPrice":     newPrice,           // Return the new calculated price
	})
	if err != nil {
		http.Error(w, "Error encoding promo response", http.StatusInternalServerError)
		log.Printf("JSON encoding error: %v\n", err)
		return
	}
}

// billingPageHandler handles the rendering of the billing page.
func billingPageHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve the user session to access the logged-in user's data
	session, err := store.Get(r, "user-session")
	if err != nil {
		log.Printf("Error retrieving session: %v", err)
		http.Error(w, "Failed to retrieve session", http.StatusInternalServerError)
		return
	}

	// Check if the user is logged in (verify the 'loggedIn' session key)
	loggedIn, ok := session.Values["loggedIn"].(bool)
	if !ok || !loggedIn {
		log.Println("User not logged in or session key 'loggedIn' missing.")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Retrieve the user ID and membership tier from the session
	userID, ok := session.Values["UserID"].(int)
	if !ok {
		log.Println("Session key 'UserID' missing or invalid type.")
		http.Error(w, "Session issue: User ID not found", http.StatusInternalServerError)
		return
	}

	membershipTierID, ok := session.Values["membershipTier"].(int)
	if !ok {
		log.Println("Session key 'membershipTier' missing or invalid type.")
		http.Error(w, "Session issue: Membership tier not found", http.StatusInternalServerError)
		return
	}

	// Extract reservationID from the URL query parameters
	reservationIDStr := r.URL.Query().Get("reservationID")
	if reservationIDStr == "" {
		log.Println("Reservation ID is missing in query parameters.")
		http.Error(w, "Reservation ID is missing", http.StatusBadRequest)
		return
	}

	// Convert reservation ID to an integer
	reservationID, err := strconv.Atoi(reservationIDStr)
	if err != nil {
		log.Printf("Error converting reservation ID to integer: %v", err)
		http.Error(w, "Invalid reservation ID", http.StatusBadRequest)
		return
	}

	log.Printf("Fetching reservation details for Reservation ID: %d", reservationID)

	// Fetch reservation details from the database
	reservationDetails, err := getReservationDetails(reservationID)
	if err != nil {
		log.Printf("Error fetching reservation details: %v", err)
		http.Error(w, "Error fetching reservation details", http.StatusInternalServerError)
		return
	}

	log.Printf("Reservation details: %+v", reservationDetails)

	// Fetch membership discount for the user
	membershipDiscount, membershipName, err := getMembershipDiscountRate(membershipTierID, r)
	if err != nil {
		log.Printf("Error fetching membership discount: %v", err)
		http.Error(w, "Error fetching membership discount", http.StatusInternalServerError)
		return
	}

	log.Printf("Membership discount: %f, Membership name: %s", membershipDiscount, membershipName)

	// Optionally, fetch the promo code discount if provided in the URL query
	promoCode := r.URL.Query().Get("promoCode")
	var promoDiscount float64
	if promoCode != "" {
		promoDiscount, err = getPromoDiscount(promoCode)
		if err != nil {
			log.Printf("Error fetching promo code discount: %v", err)
			http.Error(w, "Error fetching promo code discount", http.StatusInternalServerError)
			return
		}
		log.Printf("Promo code discount: %f", promoDiscount)
	}

	// Ensure that discounts are valid (set to zero if invalid)
	if membershipDiscount < 0 || membershipDiscount > 100 {
		membershipDiscount = 0
	}
	if promoDiscount < 0 || promoDiscount > 100 {
		promoDiscount = 0
	}

	// Ensure the reservation total price is valid
	if reservationDetails.TotalPrice <= 0 {
		http.Error(w, "Invalid reservation total price", http.StatusBadRequest)
		return
	}

	// Calculate the final price after applying the membership and promo discounts
	finalPrice := reservationDetails.TotalPrice * (1 - membershipDiscount/100)

	log.Printf("Calculated Final Price: %f", finalPrice)

	// Render the billing page template
	tmpl, err := template.ParseFiles("billing.html")
	if err != nil {
		log.Printf("Template parsing error: %v", err)
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		return
	}

	// Pass the relevant data to the template for rendering
	err = tmpl.Execute(w, struct {
		UserID             int
		ReservationDetail  Reservation
		FinalPrice         float64
		PromoCode          string
		MembershipDiscount float64
		PromoDiscount      float64 // Include the promo discount in the template
	}{
		UserID:             userID,
		ReservationDetail:  reservationDetails,
		FinalPrice:         finalPrice,
		PromoCode:          promoCode,
		MembershipDiscount: membershipDiscount,
		PromoDiscount:      promoDiscount, // Pass promo discount to template
	})

	// Handle errors if the template rendering fails
	if err != nil {
		log.Printf("Template rendering error: %v", err)
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
		return
	}

	log.Printf("Billing page successfully rendered for user ID: %d", userID)
}

// reservation Service: update reservation status (PUT/reservation/update/{reservation_id}) and update vehicle status and insert invoice
func ReservationStatusHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "user-session")
	log.Printf("Session values: %v", session.Values)

	log.Println("About to update reservation status")
	// Extract reservation ID from the URL path
	reservationID := mux.Vars(r)["reservationID"]
	log.Printf("reservation ID from URL: %s", reservationID)
	// Update the reservation status in the Reservation Service database
	_, err = reservationdb.Exec("UPDATE reservations SET status = 'completed' WHERE id = ?", reservationID)
	if err != nil {
		http.Error(w, "Error updating reservation status", http.StatusInternalServerError)
		log.Printf("Error updating reservation status in reservation Service: %v\n", err)
		return
	}
	log.Printf("reservation ID %s status updated to 'complete'", reservationID)
	// Get the vehicle ID associated with the canceled reservation
	var vehicleID int
	err = reservationdb.QueryRow("SELECT vehicle_id FROM reservations WHERE id = ?", reservationID).Scan(&vehicleID)
	if err != nil || vehicleID == 0 {
		http.Error(w, "Error fetching vehicle ID", http.StatusInternalServerError)
		log.Printf("Error fetching vehicle ID for reservation %s: %v\n", reservationID, err)
		return
	}
	//log the vehicle id when retrieving vehicle id from reservations
	log.Printf("vehicle id: %d ", vehicleID)
	// Update the vehicle availability to 'available'
	err = updateVehicleStatus(vehicleID)
	if err != nil {
		http.Error(w, "Error updating vehicle availability", http.StatusInternalServerError)
		return
	}

	// Respond with a success message
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Reservation successfully complete.",
	})
}

// Function to update vehicle status via Vehicle Service API
func updateVehicleStatus(vehicleID int) error {
	client := &http.Client{}                            // HTTP client for making requests
	reqBody := map[string]string{"status": "available"} // Request body for updating vehicle status
	reqBodyJSON, _ := json.Marshal(reqBody)

	// API endpoint of the Vehicle Service
	url := fmt.Sprintf("http://localhost:8080/vehicles/%d/status", vehicleID)
	log.Printf("Sending request to: %s", url) // Log the URL

	// Create a new PUT request
	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(reqBodyJSON))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json") // Set content type as JSON

	// Execute the HTTP request
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check if the response status is OK
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("vehicle service responded with status %d", resp.StatusCode)
	}

	return nil
}

// Handler function to update the vehicle status
func VehicleStatusHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "user-session") // Retrieve session information
	log.Printf("Session values: %v", session.Values)

	log.Println("About to update vehicle status")
	// Extract vehicle ID from the URL path
	vehicleIDStr := mux.Vars(r)["vehicle_id"]
	if vehicleIDStr == "" {
		http.Error(w, "Vehicle ID is required", http.StatusBadRequest)
		log.Println("Vehicle ID is missing from URL")
		return
	}
	log.Printf("Extracted Vehicle ID from URL: %s", vehicleIDStr)

	// Convert the vehicle ID from string to integer
	vehicleID, err := strconv.Atoi(vehicleIDStr)
	if err != nil {
		http.Error(w, "Invalid Vehicle ID", http.StatusBadRequest)
		log.Printf("Invalid Vehicle ID: %s\n", vehicleIDStr)
		return
	}

	// Update the vehicle status in the database
	_, err = vehicledb.Exec("UPDATE vehicles SET status = 'available' WHERE id = ?", vehicleID)
	if err != nil {
		http.Error(w, "Error updating vehicle status", http.StatusInternalServerError)
		log.Printf("Error updating vehicle status in Vehicle Service: %v\n", err)
		return
	}
	log.Printf("Vehicle ID %d status updated to 'available'", vehicleID)

	// Respond with a success message
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Vehicle status updated successfully.",
	})
}

// Invoice struct for sending JSON response
type Invoice struct {
	UserID             int     `json:"user_id"`             // User ID associated with the invoice
	ReservationID      int     `json:"reservation_id"`      // Reservation ID linked to the invoice
	MembershipDiscount float64 `json:"membership_discount"` // Discount for membership tier
	PromoDiscount      float64 `json:"promo_discount"`      // Discount from promotional codes
	FinalAmount        float64 `json:"final_amount"`        // Final amount after applying discounts
	InvoiceDate        string  `json:"invoice_date"`        // Date of the invoice creation
	VehicleModel       string  `json:"vehicle_model"`       // Vehicle model for the reservation
	LicensePlate       string  `json:"license_plate"`       // License plate of the vehicle
	StartTime          string  `json:"start_time"`          // Reservation start time
	EndTime            string  `json:"end_time"`            // Reservation end time
}

// Function to send an invoice creation request to the Billing Service API
func createInvoiceStatus(reservationID int, userID int, membershipDiscount, promoDiscount, finalAmount float64, vehicleModel string, licensePlate string, start_time string, end_time string) error {
	client := &http.Client{} // HTTP client for making requests

	// Populate the Invoice struct
	invoice := Invoice{
		UserID:             userID,
		ReservationID:      reservationID,
		MembershipDiscount: membershipDiscount,
		PromoDiscount:      promoDiscount,
		FinalAmount:        finalAmount,
		InvoiceDate:        time.Now().Format("2006-01-02 15:04:05"), // Current timestamp
		VehicleModel:       vehicleModel,
		LicensePlate:       licensePlate,
		StartTime:          start_time,
		EndTime:            end_time,
	}

	// Convert the invoice struct to JSON
	reqBodyJSON, err := json.Marshal(invoice)
	if err != nil {
		return fmt.Errorf("error marshaling invoice: %v", err)
	}

	// API endpoint for creating an invoice
	url := fmt.Sprintf("http://localhost:8080/create/invoice/%d", reservationID)
	log.Printf("Sending invoice creation request to: %s", url)

	// Create a new POST request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBodyJSON))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json") // Set content type as JSON

	// Execute the HTTP request
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check if the response status is OK
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("billing service responded with status %d", resp.StatusCode)
	}

	return nil
}

// Handler function for creating an invoice
func CreateInvoice(w http.ResponseWriter, r *http.Request) {
	var invoice Invoice
	log.Println("Entered CreateInvoice handler")

	// Read and log the request body
	body, _ := io.ReadAll(r.Body)
	log.Printf("Raw JSON body: %s\n", string(body))

	// Decode the JSON into the Invoice struct
	err := json.Unmarshal(body, &invoice)
	if err != nil {
		http.Error(w, "Error decoding invoice data", http.StatusBadRequest)
		log.Printf("Error decoding invoice data: %v", err)
		return
	}

	// Log the invoice object to verify
	log.Printf("Invoice Received: %+v\n", invoice)

	// Set the current timestamp for invoice_date
	invoiceDate := time.Now().Format("2006-01-02 15:04:05")
	log.Printf("Invoice Date: %s\n", invoiceDate)

	// Insert the invoice into the database
	_, err = billingdb.Exec(
		`INSERT INTO invoices (user_id, reservation_id, membership_discount, promo_discount, final_amount, invoice_date, vehicle_model, license_plate, start_time, end_time) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		invoice.UserID,
		invoice.ReservationID,
		invoice.MembershipDiscount,
		invoice.PromoDiscount,
		invoice.FinalAmount,
		invoiceDate,
		invoice.VehicleModel,
		invoice.LicensePlate,
		invoice.StartTime,
		invoice.EndTime,
	)
	if err != nil {
		log.Printf("Error creating invoice: %v\n", err)
		http.Error(w, "Error creating invoice", http.StatusInternalServerError)
		return
	}

	// Respond with a success message
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Invoice created successfully",
	})
}

func main() {
	// Create a new router
	r := mux.NewRouter()

	// Static file serving
	r.HandleFunc("/index", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "index.html")
	})

	// Register handlers
	r.HandleFunc("/register", registerHandler)
	r.HandleFunc("/login", loginHandler)
	r.HandleFunc("/home", homeHandler)
	r.HandleFunc("/profile", profileHandler)
	r.HandleFunc("/membership", membershipHandler)
	r.HandleFunc("/verify", verifyHandler) // Email verification handler
	r.HandleFunc("/logout", logoutHandler) // Logout handler
	// Membership Upgrade API
	r.HandleFunc("/membership/upgrade/{id}", upgradeMembershipHandler).Methods("PUT")
	// Handle available vehicles API
	r.HandleFunc("/vehicles", VehiclesPageHandler)

	r.HandleFunc("/vehicles/available", availableVehiclesHandler)
	r.HandleFunc("/reserve", createReservationHandler)
	r.HandleFunc("/reservations", getReservationsHandler).Methods("GET")
	r.HandleFunc("/vehicles/{vehicle_id}", getVehicleDetailsHandler).Methods("GET")
	//update reservation details after modifying
	r.HandleFunc("/reservations/update/{id}", updateReservationHandler).Methods("PUT")
	//cancel reservation details
	r.HandleFunc("/reservations/cancel/{id}", cancelReservationHandler).Methods("DELETE")
	//set vehicle status to 'reserved'
	r.HandleFunc("/vehicles/reserve/{vehicle_id}", reserveVehicleHandler).Methods("POST")
	// Serves the billing page
	r.HandleFunc("/billing", billingPageHandler)
	// Get Membership Discount - Fetches the user's membership discount rate and name
	r.HandleFunc("/membership/discount/{membershipTier}", getMembershipDiscount).Methods("GET")
	//post request for promo code
	r.HandleFunc("/promotion/apply", applyPromoCode).Methods("POST")
	// Get Promo Code Discount - Fetches the discount rate for a given promo code
	r.HandleFunc("/promotion/discount/{promoCode}", getPromoCodeDiscount).Methods("GET")
	//create invoice record into db
	r.HandleFunc("/create/invoice/{reservationID}", CreateInvoice).Methods("POST")
	//update reservation status after payment
	r.HandleFunc("/reservation/update/{reservationID}", ReservationStatusHandler).Methods("PUT")
	//update vehicle status after payment
	r.HandleFunc("/vehicles/{vehicle_id}/status", VehicleStatusHandler).Methods("PUT")

	// Apply CORS middleware
	log.Println("Server started at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", handlers.CORS(
		handlers.AllowedOrigins([]string{"http://localhost:8080"}),         // Allow only frontend's origin
		handlers.AllowedMethods([]string{"POST", "GET", "PUT", "DELETE"}),  // Allowed HTTP methods
		handlers.AllowedHeaders([]string{"Content-Type", "Authorization"}), // Allowed headers
	)(r)))
}
