package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"regexp"
	"strconv"
	"text/template"

	"github.com/gorilla/mux"
)

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
		// Get the success message from the query parameters
		message := r.URL.Query().Get("message")
		// Parse the login template
		tmpl, err := template.ParseFiles("login.html")
		if err != nil {
			// If there is an error in parsing, log the error and return an internal server error
			log.Printf("Template parsing error: %v\n", err)
			http.Error(w, "Internal server error.", http.StatusInternalServerError)
			return
		}
		// Serve the login page with an empty error message or success message when user updates profile
		tmpl.Execute(w, struct {
			ErrorMessage string
			Message      string
		}{ErrorMessage: "", Message: message})
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
	loggedIn, _ := session.Values["loggedIn"].(bool)
	username, _ := session.Values["username"].(string)

	// If the user is not logged in, redirect to login page
	if !loggedIn {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Data structure for template
	type ProfileData struct {
		Username       string
		Email          string
		MembershipTier string
		ErrorMessage   string
		Message        string
	}

	// Handle GET request: Fetch and display the current profile details
	if r.Method == http.MethodGet {
		var email, membershipTier string
		err := userdb.QueryRow(
			"SELECT email, (SELECT name FROM membership_tiers WHERE id = membership_tier_id) AS membership_tier FROM users WHERE username = ?",
			username,
		).Scan(&email, &membershipTier)
		if err != nil {
			log.Printf("Error fetching user details: %v", err)
			http.Error(w, "Internal server error.", http.StatusInternalServerError)
			return
		}

		// Render the profile page
		tmpl, err := template.ParseFiles("profile.html")
		if err != nil {
			log.Printf("Template parsing error: %v", err)
			http.Error(w, "Internal server error.", http.StatusInternalServerError)
			return
		}

		tmpl.Execute(w, ProfileData{
			Username:       username,
			Email:          email,
			MembershipTier: membershipTier,
			ErrorMessage:   "",
			Message:        "", // No message on initial page load
		})
	} else if r.Method == http.MethodPost {
		// Handle POST request: Process profile updates
		newUsername := r.FormValue("username")
		newEmail := r.FormValue("email")
		newPassword := r.FormValue("password")

		// Check if the new username is already taken
		if newUsername != username {
			var existingId int
			err := userdb.QueryRow("SELECT id FROM users WHERE username = ?", newUsername).Scan(&existingId)
			if err == nil {
				// Render the page with an error message
				tmpl, _ := template.ParseFiles("profile.html")
				tmpl.Execute(w, ProfileData{
					Username:       username,
					Email:          newEmail,
					MembershipTier: "",
					ErrorMessage:   "Username already taken.",
					Message:        "",
				})
				return
			}
		}

		// Prepare SQL query to update the user's profile
		query := "UPDATE users SET username = ?, email = ?"
		args := []interface{}{newUsername, newEmail}

		// If a new password is provided, hash it and include it in the query
		if newPassword != "" {
			passwordHash := hashPassword(newPassword)
			query += ", password_hash = ?"
			args = append(args, passwordHash)
		}

		// Add condition to update the current user
		query += " WHERE username = ?"
		args = append(args, username)

		_, err := userdb.Exec(query, args...)
		if err != nil {
			log.Printf("Error updating user profile: %v", err)
			http.Error(w, "Failed to update profile. Please try again.", http.StatusInternalServerError)
			return
		}

		// Clear the session and log the user out
		session.Options.MaxAge = -1 // Invalidate session
		session.Save(r, w)

		// Redirect to login page with success message
		http.Redirect(w, r, "/login?message=Profile updated successfully. Please log in again.", http.StatusSeeOther)
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

// Upgrade Membership Handler
func upgradeMembershipHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve session data
	session, _ := store.Get(r, "user-session")

	// Ensure the request method is PUT (updating data)
	if r.Method != http.MethodPut {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Get the membership tier ID from the URL path variable
	membershipTierIDStr := mux.Vars(r)["membershipTierID"]

	// Convert membershipTierID to an integer
	membershipTierID, err := strconv.Atoi(membershipTierIDStr)
	if err != nil {
		http.Error(w, "Invalid membership tier ID", http.StatusBadRequest)
		return
	}

	// Get the user ID from the session
	userID := session.Values["UserID"].(int)

	// Update the user's membership tier in the database
	_, err = userdb.Exec("UPDATE users SET membership_tier_id = ? WHERE id = ?", membershipTierID, userID)
	if err != nil {
		http.Error(w, "Error upgrading membership", http.StatusInternalServerError)
		log.Printf("Error updating membership: %v\n", err)
		return
	}
	// Update the session with the new membership tier
	session.Values["membershipTier"] = membershipTierID
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, "Error saving session", http.StatusInternalServerError)
		log.Printf("Error saving session: %v\n", err)
		return
	}
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

// availableVehiclesHandler handles the request to view rental history
func viewRentalHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "user-session")
	userID := session.Values["UserID"].(int)
	// Ensure the request method is GET (fetching data)
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Query the database for vehicles with status 'available'
	rows, err := billingdb.Query("SELECT reservation_id, membership_discount, promo_discount, final_amount, status, invoice_date, vehicle_model, license_plate, start_time, end_time FROM invoices WHERE user_id = ?", userID)
	if err != nil {
		http.Error(w, "Failed to retrieve available vehicles", http.StatusInternalServerError)
		log.Printf("Database query error: %v\n", err)
		return
	}
	defer rows.Close()

	// Create a slice to store vehicle data
	var rentals []Rental

	// Loop through the rows and scan each vehicle's data into the struct
	for rows.Next() {
		var rental Rental
		err := rows.Scan(&rental.ReservationID, &rental.MembershipDiscount, &rental.PromoDiscount, &rental.FinalAmount, &rental.Status, &rental.InvoiceDate, &rental.VehicleModel, &rental.LicensePlate, &rental.StartTime, &rental.EndTime)
		if err != nil {
			http.Error(w, "Error reading vehicle data", http.StatusInternalServerError)
			log.Printf("Row scan error: %v\n", err)
			return
		}
		// Append each vehicle to the vehicles slice
		rentals = append(rentals, rental)
	}

	// Respond with the available vehicles in JSON format
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(rentals)
	if err != nil {
		http.Error(w, "Error encoding JSON response", http.StatusInternalServerError)
		log.Printf("JSON encoding error: %v\n", err)
	}
}

// RentalPageHandler serves the Available Vehicles page
func RentalPageHandler(w http.ResponseWriter, r *http.Request) {
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
	tmpl, err := template.ParseFiles("rental.html")
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
