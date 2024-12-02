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
	"text/template"

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

// register form
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Serve login page with an empty error message
		tmpl, err := template.ParseFiles("register.html")
		if err != nil {
			log.Printf("Template parsing error: %v\n", err)
			http.Error(w, "Internal server error.", http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, struct {
			ErrorMessage string
		}{ErrorMessage: ""})
		return
	}
	if r.Method == http.MethodPost {
		// Parse form data
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")

		// Check if the username already exists in the database
		var existingUsername string
		err := userdb.QueryRow("SELECT username FROM users WHERE username = ?", username).Scan(&existingUsername)
		if err != sql.ErrNoRows {
			// If the username exists, send an error message
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
			// If the email exists, send an error message
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
		}
		// Hash the password
		passwordHash := hashPassword(password)
		verificationToken := generateVerificationToken()

		// Insert into the database
		_, err = userdb.Exec("INSERT INTO users (username, email, password_hash, verification_token) VALUES (?, ?, ?, ?)",
			username, email, passwordHash, verificationToken)
		if err != nil {
			http.Error(w, "Failed to register user. Please try again.", http.StatusInternalServerError)
			log.Printf("Error inserting user: %v\n", err)
			return
		}
		sendVerificationEmail(email, verificationToken) // Send the verification email

		// Registration successful
		fmt.Fprintln(w, "Registration successful! Please check your email to verify your account.")
	}
}

// login form
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Serve login page with an empty error message
		tmpl, err := template.ParseFiles("login.html")
		if err != nil {
			log.Printf("Template parsing error: %v\n", err)
			http.Error(w, "Internal server error.", http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, struct {
			ErrorMessage string
		}{ErrorMessage: ""})
		return
	}

	if r.Method == http.MethodPost {
		// Retrieve user input
		email := r.FormValue("email")
		password := r.FormValue("password")

		// Hash user password
		passwordHash := hashPassword(password)

		// Retrieve user info from database
		var username string
		var membershipTierID, userId int
		var storedPasswordHash string
		var isVerified bool

		err := userdb.QueryRow("SELECT id, username, membership_tier_id, password_hash, is_verified FROM users WHERE email = ?", email).
			Scan(&userId, &username, &membershipTierID, &storedPasswordHash, &isVerified)

		if err == sql.ErrNoRows || passwordHash != storedPasswordHash {
			// If user does not exist or password does not match
			tmpl, err := template.ParseFiles("login.html")
			if err != nil {
				log.Printf("Template parsing error: %v\n", err)
				http.Error(w, "Internal server error.", http.StatusInternalServerError)
				return
			}
			tmpl.Execute(w, struct {
				ErrorMessage string
			}{ErrorMessage: "Invalid email or password"})
			return
		}
		if !isVerified {
			tmpl, err := template.ParseFiles("login.html")
			if err != nil {
				log.Printf("Template parsing error: %v\n", err)
				http.Error(w, "Internal server error.", http.StatusInternalServerError)
				return
			}
			tmpl.Execute(w, struct {
				ErrorMessage string
			}{ErrorMessage: "Please verify your email first."})
			return
		} else if err != nil {
			// Database error
			log.Printf("Database error: %v\n", err)
			http.Error(w, "Internal server error.", http.StatusInternalServerError)
			return
		}
		//save user details in session
		session, _ := store.Get(r, "user-session")
		session.Values["username"] = username
		session.Values["loggedIn"] = true
		session.Values["membershipTier"] = membershipTierID
		session.Values["UserID"] = userId
		session.Save(r, w)

		// Login successful
		log.Printf("User logged in: %s with Membership Tier ID: %d and user id: %d \n", username, membershipTierID, userId)
		http.Redirect(w, r, "/home", http.StatusSeeOther) // Redirect to homepage or dashboard
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "user-session")

	//check if user is logged in
	loggedIn, _ := session.Values["loggedIn"].(bool)
	username, _ := session.Values["username"].(string)

	if !loggedIn {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	//retrieve user's memmbersip tier
	var membershipTier string
	err := userdb.QueryRow("SELECT membership_tiers.name FROM users INNER JOIN membership_tiers ON users.membership_tier_id = membership_tiers.id WHERE users.username = ?", username).Scan(&membershipTier)
	if err != nil {
		log.Printf("Error retrieving membership tier: %v\n", err)
		http.Error(w, "Internal server error.", http.StatusInternalServerError)
		return
	}

	tmpl, err := template.ParseFiles("home.html")
	if err != nil {
		log.Printf("Template parsing error: %v\n", err)
		http.Error(w, "Internal server error.", http.StatusInternalServerError)
		return
	}

	tmpl.Execute(w, struct {
		isLoggedIn     bool
		Username       string
		MembershipTier string
	}{
		isLoggedIn:     loggedIn,
		Username:       username,
		MembershipTier: membershipTier,
	})
	response := struct {
		Message string `json:"message"`
	}{"Login successful"}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

}

// profile page
func profileHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "user-session")
	loggedIn, _ := session.Values["loggedIn"].(bool)
	username, _ := session.Values["username"].(string)

	if !loggedIn {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodGet {
		//fetch user details
		var email, membershipTier string
		err := userdb.QueryRow("select email, (select name from membership_tiers where id = membership_tier_id) as membership_tier from users where username = ?", username).Scan(&email, &membershipTier)
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
		tmpl.Execute(w, struct {
			Username       string
			Email          string
			MembershipTier string
			ErrorMessage   string
		}{
			Username:       username,
			Email:          email,
			MembershipTier: membershipTier,
			ErrorMessage:   "",
		})
	} else if r.Method == http.MethodPost {
		//handle profile update
		newUsername := r.FormValue("username")
		newEmail := r.FormValue("email")
		newPassword := r.FormValue("password")

		//check if new username is taken
		if newUsername != username {
			var existingId int
			err := userdb.QueryRow("select id from users where username = ?", newUsername).Scan(&existingId)
			if err == nil {
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

		// Update the database
		query := "UPDATE users SET username = ?, email = ?"
		args := []interface{}{newUsername, newEmail}

		if newPassword != "" {
			passwordHash := hashPassword(newPassword)
			query += ", password_hash = ?"
			args = append(args, passwordHash)
		}

		query += " WHERE username = ?"
		args = append(args, username)

		_, err := userdb.Exec(query, args...)
		if err != nil {
			log.Printf("Error updating user profile: %v", err)
			http.Error(w, "Failed to update profile. Please try again.", http.StatusInternalServerError)
			return
		}
		// Update the session username
		session.Values["username"] = newUsername
		session.Save(r, w)

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

// membershipHandler renders the membership page
func membershipHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "user-session")
	loggedIn, _ := session.Values["loggedIn"].(bool)
	username, _ := session.Values["username"].(string)
	//check if user is logged in
	if !loggedIn {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	// Retrieve the session
	membershipTier, _ := session.Values["membershipTier"].(int)

	//fetch all membership tiers from database
	rows, err := userdb.Query("select id, name, benefits, discount_rate,price from membership_tiers")
	if err != nil {
		http.Error(w, "Error loading membership tiers", http.StatusInternalServerError)
		log.Printf("Database error: %v\n", err)
		return
	}
	defer rows.Close()
	var tiers []MembershipTier
	for rows.Next() {
		// retrieve membership tier information and store under a struct
		var tier MembershipTier
		err := rows.Scan(&tier.ID, &tier.Name, &tier.Benefits, &tier.DiscountRate, &tier.Price)
		if err != nil {
			http.Error(w, "Error reading membership tiers", http.StatusInternalServerError)
			log.Printf("Database error: %v\n", err)
			return
		}
		// Mark the user's current membership
		tier.IsCurrent = (tier.ID == membershipTier)
		tiers = append(tiers, tier)
	}
	//parse and render the html page for membership page
	tmpl, err := template.ParseFiles("membership.html")
	if err != nil {
		http.Error(w, "Error loading page", http.StatusInternalServerError)
		log.Printf("Template error: %v\n", err)
		return
	}

	err = tmpl.Execute(w, struct {
		Username string
		Tiers    []MembershipTier
	}{Username: username,
		Tiers: tiers})
	if err != nil {
		http.Error(w, "Error rendering page", http.StatusInternalServerError)
		log.Printf("Template rendering error: %v\n", err)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "user-session")
	session.Values["loggedIn"] = false
	session.Save(r, w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// struct to represent vehicle
type Vehicle struct {
	ID           int     `json:"id"`
	LicensePlate string  `json:"license_plate"`
	Model        string  `json:"model"`
	Location     string  `json:"location"`
	HourlyRate   float64 `json:"hourly_rate"`
}

// view available vehicles in real-time
func availableVehiclesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	//query for available vehicles
	rows, err := vehicledb.Query("select id, license_plate, model, location, hourly_rate from vehicles where status = 'available'")
	if err != nil {
		http.Error(w, "Failed to retrieve available vehicles", http.StatusInternalServerError)
		log.Printf("Database query error: %v\n", err)
		return
	}
	defer rows.Close()

	var vehicles []Vehicle
	//store vehicle data as a struct
	for rows.Next() {
		var vehicle Vehicle
		err := rows.Scan(&vehicle.ID, &vehicle.LicensePlate, &vehicle.Model, &vehicle.Location, &vehicle.HourlyRate)
		if err != nil {
			http.Error(w, "Error reading vehicle data", http.StatusInternalServerError)
			log.Printf("Row scan error: %v\n", err)
			return
		}
		vehicles = append(vehicles, vehicle)
	}
	//respond with available vehicles in JSON format
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(vehicles)
	if err != nil {
		http.Error(w, "Error encoding JSON response", http.StatusInternalServerError)
		log.Printf("JSON encoding error: %v\n", err)
	}

}

// reservation service: get available vehicles (Get/reservations/vehicle)
func availableReservationsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	//call vehicle service to get available vehicles
	resp, err := http.Get("http://localhost:8081/vehicles/available")
	if err != nil {
		http.Error(w, "Error contacting Vehicle Service", http.StatusInternalServerError)
		log.Printf("Error contacting Vehicle Service: %v\n", err)
		return
	}
	defer resp.Body.Close()

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

// Reservation Service: Create Reservation and Reserve Vehicle (POST /reservations)
func createReservationHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
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
	// Create reservation in the Reservation Service database
	_, err = reservationdb.Exec("INSERT INTO reservations (user_id, vehicle_id, start_time, end_time, total_price) VALUES (?, ?, ?, ?, ?)",
		reservation.UserID, reservation.VehicleID, reservation.StartTime, reservation.EndTime, reservation.TotalPrice)
	if err != nil {
		http.Error(w, "Error creating reservation", http.StatusInternalServerError)
		log.Printf("Received reservation data: %+v\n", reservation)

		log.Printf("Error inserting reservation into database: %v\n", err)
		return
	}
	// Update reservation status to 'active'
	_, err = reservationdb.Exec("UPDATE reservations SET status = 'active' WHERE vehicle_id = ? AND user_id = ? AND start_time = ?",
		reservation.VehicleID, reservation.UserID, reservation.StartTime)
	if err != nil {
		http.Error(w, "Error updating reservation status", http.StatusInternalServerError)
		log.Printf("Error updating reservation status: %v\n", err)
		return
	}

	// Call Vehicle Service to reserve the vehicle (update its status)
	vehicleServiceURL := fmt.Sprintf("http://localhost:8081/vehicles/reserve/%d", reservation.VehicleID)
	resp, err := http.Post(vehicleServiceURL, "application/json", nil)
	if err != nil {
		log.Printf("Error calling Vehicle Service: %v\n", err)
		http.Error(w, "Error reserving vehicle", http.StatusInternalServerError)
		return
	}
	log.Printf("Vehicle Service Response: %v\n", resp.StatusCode) // Add this to log the status code of the response
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

// Vehicle Service: Reserve Vehicle (POST /vehicles/reserve/{vehicle_id})
func reserveVehicleHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("About to handle vehicle reservation")
	// Extract vehicle ID from the URL path
	vehicleID := mux.Vars(r)["vehicle_id"]
	log.Printf("Vehicle ID from URL: %s", vehicleID)
	// Update the vehicle status in the Vehicle Service database
	_, err := vehicledb.Exec("UPDATE vehicles SET status = 'reserved' WHERE id = ?", vehicleID)
	if err != nil {
		http.Error(w, "Error updating vehicle status", http.StatusInternalServerError)
		log.Printf("Error updating vehicle status in Vehicle Service: %v\n", err)
		return
	}
	log.Printf("Vehicle ID %d status updated to 'reserved'", vehicleID)
	// Respond with a success message
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Vehicle successfully reserved.",
	})
}

// availableVehiclesPageHandler serves the Available Vehicles page
func VehiclesPageHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "user-session")
	loggedIn, _ := session.Values["loggedIn"].(bool)
	userID, _ := session.Values["UserID"].(int)

	if !loggedIn {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Serve the HTML page for available vehicles
	tmpl, err := template.ParseFiles("availableVehicles.html")
	if err != nil {
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		log.Printf("Template parsing error: %v", err)
		return
	}

	// Pass the user ID to the template
	tmpl.Execute(w, map[string]interface{}{
		"UserID": userID,
	})
	log.Printf("user id: %d \n", userID)
}
func main() {
	// Create a new router
	r := mux.NewRouter()

	// Static file serving
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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
	// Handle available vehicles API
	r.HandleFunc("/vehicles", VehiclesPageHandler)
	r.HandleFunc("/vehicles/available", availableVehiclesHandler)
	// Handle vehicle reservation with dynamic vehicle_id
	r.HandleFunc("/vehicles/reserve/{vehicle_id}", reserveVehicleHandler).Methods("POST")

	// Start the server
	log.Println("Server started at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", handlers.CORS(
		handlers.AllowedOrigins([]string{"http://localhost:8080"}),         // Allow only frontend's origin
		handlers.AllowedMethods([]string{"POST", "GET", "PUT", "DELETE"}),  // Allowed HTTP methods
		handlers.AllowedHeaders([]string{"Content-Type", "Authorization"}), // Allowed headers
	)(r)))
}
