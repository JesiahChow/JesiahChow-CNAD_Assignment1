--Electric car-sharing system database schema
-- Create User Service Database
CREATE DATABASE user_db;

USE user_service_db;

-- Membership Tiers Table
CREATE TABLE membership_tiers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    benefits TEXT,
    discount_rate DECIMAL(5, 2),
    price DECIMAL(10, 2) DEFAULT 0 -- price for upgrading
);
-- Users Table
CREATE TABLE users (
      id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    membership_tier_id INT DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    verification_token VARCHAR(255),
    is_verified BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (membership_tier_id) REFERENCES membership_tiers(id)
);




-- Create Vehicle Service Database
CREATE DATABASE vehicle_service_db;

USE vehicle_service_db;

-- Vehicles Table
CREATE TABLE vehicles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    license_plate VARCHAR(20) UNIQUE NOT NULL,
    model VARCHAR(50),
    status ENUM('available', 'reserved', 'in_maintenance') DEFAULT 'available',
    location VARCHAR(100),
    hourly_rate DECIMAL(10, 2)
);


-- Create Reservation Service Database
CREATE DATABASE reservation_service_db;

USE reservation_service_db;

-- Reservations Table
CREATE TABLE reservations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    vehicle_id INT,
    start_time DATETIME,
    end_time DATETIME,
    total_price DECIMAL(10, 2),
    status ENUM('cctive', 'completed', 'cancelled'),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user_service_db.users(id),
    FOREIGN KEY (vehicle_id) REFERENCES vehicle_service_db.vehicles(id)
);

-- Create Billing Service Database
CREATE DATABASE billing_service_db;

USE billing_service_db;

CREATE TABLE invoices (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    reservation_id INT NOT NULL,
    membership_discount DECIMAL(5, 2),
    promo_discount DECIMAL(5, 2),
    final_amount DECIMAL(10, 2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('paid') DEFAULT 'paid',
    invoice_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    vehicle_model VARCHAR(50),
    license_plate VARCHAR(20) not null,
    start_time DATETIME,
    end_time DATETIME,
    FOREIGN KEY (user_id) REFERENCES user_service_db.users(id),
    FOREIGN KEY (reservation_id) REFERENCES reservation_service_db.reservations(id)
);



CREATE DATABASE promotion_service_db;

USE promotion_service_db;
-- Promotions Table
CREATE TABLE promotions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    code VARCHAR(20) UNIQUE NOT NULL,            -- Unique code for promotional discount
    description VARCHAR(255),            -- Description of the promotion
    discount_rate DECIMAL(5, 2),        -- Discount percentage (e.g., 10 for 10%)
    start_date DATETIME,                -- When the promotion starts
    end_date DATETIME,                  -- When the promotion ends
    is_active BOOLEAN DEFAULT TRUE,     -- Is the promotion currently active?
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO promotions (code, description, discount_rate, start_date, end_date, is_active)
VALUES 
('PROMO10', '10% off for all users', 10.00, '2024-12-01', '2024-12-31', TRUE),
('HOLIDAY20', '20% off for holidays', 20.00, '2024-12-20', '2024-12-25', TRUE);





