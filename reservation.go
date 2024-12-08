package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"text/template"
	"time"

	"github.com/gorilla/mux"
)

// availableVehiclesHandler handles the request to view available vehicles in real-time
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
	log.Println("Request method:", r.Method) // Log request method
	// Ensure the request is PUT
	if r.Method != http.MethodPut {
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

	// Mark the reservation as cancelled in the database
	_, err := reservationdb.Exec("UPDATE reservations SET status = 'cancelled' WHERE id = ?", reservationID)
	if err != nil {
		http.Error(w, "Error canceling reservation", http.StatusInternalServerError)
		return
	}

	// Get the vehicle ID associated with the cancelled reservation
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
		"message": "Reservation cancelled!",
	})
}
