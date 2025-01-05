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

// rental struct
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

// Start each service on a separate port
func main() {
	go startUserService()
	go startVehicleService()
	go startReservationService()
	go startBillingService()
	go startPromotionService()

	select {} // Block main thread indefinitely
}

// User Service
func startUserService() {
	r := mux.NewRouter()
	r.HandleFunc("/index", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "index.html")
	})
	r.HandleFunc("/register", registerHandler)
	r.HandleFunc("/login", loginHandler)
	r.HandleFunc("/logout", logoutHandler)
	r.HandleFunc("/profile", profileHandler)
	r.HandleFunc("/home", homeHandler)
	r.HandleFunc("/membership", membershipHandler)
	r.HandleFunc("/rental/history", viewRentalHandler).Methods("GET")
	//render rental page
	r.HandleFunc("/rental", RentalPageHandler)
	r.HandleFunc("/membership/upgrade/{membershipTierID}", upgradeMembershipHandler).Methods("PUT")
	r.HandleFunc("/membership/discount/{membershipTierID}", getMembershipDiscount).Methods("GET")
	r.HandleFunc("/verify", verifyHandler) // Email verification

	fmt.Println("User Service running at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", handlers.CORS(
		handlers.AllowedOrigins([]string{
			"http://localhost:8081", // Vehicle Service
			"http://localhost:8080", // User Service
			"http://localhost:8082", // Reservation Service
			"http://localhost:8083", // Billing Service
			"http://localhost:8084", // Promotion Service
		}), // Frontend origin
		handlers.AllowedMethods([]string{"POST", "GET", "PUT", "DELETE"}),  // Allowed methods
		handlers.AllowedHeaders([]string{"Content-Type", "Authorization"}), // Allowed headers
	)(r)))
}

// Vehicle Service
func startVehicleService() {
	r := mux.NewRouter()
	r.HandleFunc("/vehicles", VehiclesPageHandler)
	r.HandleFunc("/vehicles/available", availableVehiclesHandler)
	r.HandleFunc("/vehicles/{vehicle_id}", getVehicleDetailsHandler).Methods("GET")
	r.HandleFunc("/vehicles/{vehicle_id}/status", VehicleStatusHandler).Methods("PUT")

	fmt.Println("Vehicle Service running at http://localhost:8081")
	log.Fatal(http.ListenAndServe(":8081", handlers.CORS(
		handlers.AllowedOrigins([]string{
			"http://localhost:8081", // Vehicle Service
			"http://localhost:8080", // User Service
			"http://localhost:8082", // Reservation Service
			"http://localhost:8083", // Billing Service
			"http://localhost:8084", // Promotion Service
		}), // Frontend origin
		handlers.AllowedMethods([]string{"POST", "GET", "PUT", "DELETE"}),  // Allowed methods
		handlers.AllowedHeaders([]string{"Content-Type", "Authorization"}), // Allowed headers
	)(r)))
}

// Reservation Service
func startReservationService() {
	r := mux.NewRouter()
	r.HandleFunc("/reserve", createReservationHandler)
	r.HandleFunc("/vehicles/reserve/{vehicle_id}", reserveVehicleHandler).Methods("POST")
	r.HandleFunc("/reservations", getReservationsHandler).Methods("GET")
	r.HandleFunc("/reservations/update/{id}", updateReservationHandler).Methods("PUT")
	r.HandleFunc("/reservations/cancel/{id}", cancelReservationHandler).Methods("PUT")

	fmt.Println("Reservation Service running at http://localhost:8082")
	log.Fatal(http.ListenAndServe(":8082", handlers.CORS(
		handlers.AllowedOrigins([]string{
			"http://localhost:8081", // Vehicle Service
			"http://localhost:8080", // User Service
			"http://localhost:8082", // Reservation Service
			"http://localhost:8083", // Billing Service
			"http://localhost:8084", // Promotion Service
		}), // Frontend origin
		handlers.AllowedMethods([]string{"POST", "GET", "PUT", "DELETE"}),  // Allowed methods
		handlers.AllowedHeaders([]string{"Content-Type", "Authorization"}), // Allowed headers
	)(r)))
}

// Billing Service
func startBillingService() {
	r := mux.NewRouter()
	r.HandleFunc("/billing", billingPageHandler)
	r.HandleFunc("/create/invoice/{reservationID}", CreateInvoice).Methods("POST")
	r.HandleFunc("/reservation/update/{reservationID}", ReservationStatusHandler).Methods("PUT")
	r.HandleFunc("/confirmation", confirmationHandler).Methods("GET")

	fmt.Println("Billing Service running at http://localhost:8083")
	log.Fatal(http.ListenAndServe(":8083", handlers.CORS(
		handlers.AllowedOrigins([]string{
			"http://localhost:8081", // Vehicle Service
			"http://localhost:8080", // User Service
			"http://localhost:8082", // Reservation Service
			"http://localhost:8083", // Billing Service
			"http://localhost:8084", // Promotion Service
		}), // Frontend origin
		handlers.AllowedMethods([]string{"POST", "GET", "PUT", "DELETE"}),  // Allowed methods
		handlers.AllowedHeaders([]string{"Content-Type", "Authorization"}), // Allowed headers
	)(r)))
}

// Promotion Service
func startPromotionService() {
	r := mux.NewRouter()
	r.HandleFunc("/promotion/apply", applyPromoCode).Methods("POST")
	r.HandleFunc("/promotion/discount/{promoCode}", getPromoCodeDiscount).Methods("GET")

	fmt.Println("Promotion Service running at http://localhost:8084")
	log.Fatal(http.ListenAndServe(":8084", handlers.CORS(
		handlers.AllowedOrigins([]string{
			"http://localhost:8081", // Vehicle Service
			"http://localhost:8080", // User Service
			"http://localhost:8082", // Reservation Service
			"http://localhost:8083", // Billing Service
			"http://localhost:8084", // Promotion Service
		}), // Frontend origin
		handlers.AllowedMethods([]string{"POST", "GET", "PUT", "DELETE"}),  // Allowed methods
		handlers.AllowedHeaders([]string{"Content-Type", "Authorization"}), // Allowed headers
	)(r)))
}
