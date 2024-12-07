package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

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
type Rental struct {
	ReservationID      int     `json:"reservation_id"`
	MembershipDiscount float64 `json:"membership_discount"`
	PromoDiscount      float64 `json:"promo_discount"`
	FinalAmount        float64 `json:"final_amount"`
	TotalPrice         float64 `json:"total_price"`
	Status             string  `json:"status"`
	InvoiceDate        string  `json:"invoice_date"`
	VehicleModel       string  `json:"vehicle_model"`
	LicensePlate       string  `json:"license_plate"`
	StartTime          string  `json:"start_time"`
	EndTime            string  `json:"end_time"`
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
	r.HandleFunc("/membership/upgrade/{membershipTierID}", upgradeMembershipHandler).Methods("PUT")
	// Handle available vehicles API
	r.HandleFunc("/vehicles", VehiclesPageHandler)
	//fetch the vehicles available for reservation
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
	r.HandleFunc("/membership/discount/{membershipTierID}", getMembershipDiscount).Methods("GET")
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
	//confirm page
	r.HandleFunc("/confirmation", confirmationHandler).Methods("GET")
	//get rental history
	r.HandleFunc("/rental/history", viewRentalHandler).Methods("GET")
	//render rental page
	r.HandleFunc("/rental", RentalPageHandler)

	// Apply CORS middleware
	log.Println("Server started at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", handlers.CORS(
		handlers.AllowedOrigins([]string{"http://localhost:8080"}),         // Allow only frontend's origin
		handlers.AllowedMethods([]string{"POST", "GET", "PUT", "DELETE"}),  // Allowed HTTP methods
		handlers.AllowedHeaders([]string{"Content-Type", "Authorization"}), // Allowed headers
	)(r)))
}
