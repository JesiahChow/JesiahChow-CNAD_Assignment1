package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strconv"
	"text/template"
	"time"

	"github.com/gorilla/mux"
	"github.com/jung-kurt/gofpdf/v2"
)

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
	log.Printf("Session values: %v", session.Values)

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
	log.Printf("Type of 'membershipTier': %T", session.Values["membershipTier"])

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
func generateInvoicePDF(invoice Invoice) (string, error) {
	// Create a new PDF instance
	pdf := gofpdf.New("P", "mm", "A4", "")

	// Add a page
	pdf.AddPage()

	// Set font
	pdf.SetFont("Arial", "B", 16)

	// Add invoice title
	pdf.Cell(0, 10, "Invoice Details")
	pdf.Ln(20) // Line break

	// Add details
	pdf.SetFont("Arial", "", 12)
	pdf.Cell(0, 10, fmt.Sprintf("BetterCallVolt"))
	pdf.Ln(10)
	pdf.Cell(0, 10, fmt.Sprintf("Vehicle: %s (%s)", invoice.VehicleModel, invoice.LicensePlate))
	pdf.Ln(10)
	pdf.Cell(0, 10, fmt.Sprintf("Start Time: %s", invoice.StartTime))
	pdf.Ln(10)
	pdf.Cell(0, 10, fmt.Sprintf("End Time: %s", invoice.EndTime))
	pdf.Ln(10)
	pdf.Cell(0, 10, fmt.Sprintf("Membership Discount: %.2f%%", invoice.MembershipDiscount))
	pdf.Ln(10)
	pdf.Cell(0, 10, fmt.Sprintf("Promotion Discount: %.2f%%", invoice.PromoDiscount))
	pdf.Ln(10)
	pdf.Cell(0, 10, fmt.Sprintf("Final Amount: $%.2f", invoice.FinalAmount))
	pdf.Ln(20)

	// File path for the PDF
	filePath := fmt.Sprintf("invoice_%d.pdf", invoice.ReservationID)

	// Save the PDF to a file
	err := pdf.OutputFileAndClose(filePath)
	if err != nil {
		return "", fmt.Errorf("error saving PDF: %v", err)
	}

	return filePath, nil
}
func sendEmailWithPDF(userEmail, subject, body, pdfPath string) error {
	// SMTP server configuration
	// Set up the email sender and SMTP server
	senderEmail := "bettercallvolt@gmail.com" // sender email
	senderPassword := "qxfcqajpzeutxvxm"      //password retrieved from app password
	smtpServer := "smtp.gmail.com"
	smtpPort := "587" // Gmail's SMTP port

	// Read the PDF file
	pdfData, err := os.ReadFile(pdfPath)
	if err != nil {
		return fmt.Errorf("error reading PDF file: %v", err)
	}

	// Encode the PDF in base64
	pdfBase64 := base64.StdEncoding.EncodeToString(pdfData)

	// Create the email headers
	headers := make(map[string]string)
	headers["From"] = senderEmail
	headers["To"] = userEmail
	headers["Subject"] = subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = `multipart/mixed; boundary="boundary"`

	// Build the email body
	var emailBody bytes.Buffer
	for key, value := range headers {
		emailBody.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
	}
	emailBody.WriteString("\r\n--boundary\r\n")
	emailBody.WriteString(`Content-Type: text/plain; charset="UTF-8"` + "\r\n\r\n")
	emailBody.WriteString(body + "\r\n")
	emailBody.WriteString("--boundary\r\n")
	emailBody.WriteString(`Content-Type: application/pdf` + "\r\n")
	emailBody.WriteString(`Content-Disposition: attachment; filename="invoice.pdf"` + "\r\n")
	emailBody.WriteString(`Content-Transfer-Encoding: base64` + "\r\n\r\n")
	emailBody.WriteString(pdfBase64 + "\r\n")
	emailBody.WriteString("--boundary--")

	// Send the email
	auth := smtp.PlainAuth("", senderEmail, senderPassword, smtpServer)
	err = smtp.SendMail(smtpServer+":"+smtpPort, auth, senderEmail, []string{userEmail}, emailBody.Bytes())
	if err != nil {
		return fmt.Errorf("failed to send email: %v", err)
	}

	return nil
}

// Handler function for creating an invoice
func CreateInvoice(w http.ResponseWriter, r *http.Request) {
	var invoice Invoice
	log.Println("Entered CreateInvoice handler")

	// Decode the JSON directly from the request body
	err := json.NewDecoder(r.Body).Decode(&invoice)
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
	// Retrieve user email
	var userEmail string
	err = userdb.QueryRow("SELECT email FROM users WHERE id = ?", invoice.UserID).Scan(&userEmail)
	if err != nil {
		http.Error(w, "Error fetching user email", http.StatusInternalServerError)
		return
	}
	// Generate the PDF
	pdfPath, err := generateInvoicePDF(invoice)
	if err != nil {
		http.Error(w, "Error generating PDF", http.StatusInternalServerError)
		return
	}
	// Send the email
	subject := "Your Invoice from Better Call Volt"
	emailBodyText := "Please check the invoice attached to your email."
	err = sendEmailWithPDF(userEmail, subject, emailBodyText, pdfPath)
	if err != nil {
		http.Error(w, "Error sending email", http.StatusInternalServerError)
		return
	}
	// Serve the HTML page for confirmation
	tmpl, err := template.ParseFiles("confirmation.html")
	if err != nil {
		// If there is an error loading the template, send an internal server error
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		log.Printf("Template parsing error: %v", err)
		return
	}

	// Pass the user ID to the template for dynamic rendering
	tmpl.Execute(w, map[string]interface{}{
		"Email": userEmail,
	})
	defer os.Remove(pdfPath) // Clean up the file after sending
	// Respond with a success message
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Invoice created successfully",
	})
}

func confirmationHandler(w http.ResponseWriter, r *http.Request) {
	// Simple confirmation page after invoice is sent to the email
	tmpl, err := template.ParseFiles("confirmation.html")
	if err != nil {
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		log.Printf("Template parsing error: %v", err)
		return
	}

	// Pass the user ID or other confirmation data to the template
	tmpl.Execute(w, map[string]interface{}{
		"Message": "Invoice created successfully!",
	})
}
