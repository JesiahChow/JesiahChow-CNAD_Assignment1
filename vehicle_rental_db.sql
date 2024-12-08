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

-- Insert sample membership tiers
INSERT INTO membership_tiers (name, benefits, discount_rate, price)
VALUES
('Basic', 'Basic membership benefits.', 0.00, 0.00),
('Silver', '10% discount on all reservations.', 10.00, 49.99),
('Gold', '20% discount and free upgrades when available.', 20.00, 99.99);

-- Insert sample users
INSERT INTO users (username, email, password_hash, membership_tier_id, verification_token, is_verified)
VALUES
('john_doe', 'john.doe@example.com', 'hashedpassword123', 1, 'token123', TRUE),
('jane_smith', 'jane.smith@example.com', 'hashedpassword456', 2, NULL, TRUE),
('emma_watson', 'emma.watson@example.com', 'hashedpassword789', 3, NULL, FALSE);



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
-- Insert sample vehicles
INSERT INTO vehicles (license_plate, model, status, location, hourly_rate)
VALUES
('ABC123', 'Tesla Model 3', 'available', 'Orchard Road', 15.00),
('XYZ789', 'Nissan Leaf', 'reserved', 'Changi Airport', 12.00),
('LMN456', 'Chevy Bolt', 'in_maintenance', 'Chinese Garden', 10.00),
('DEF321', 'Hyundai Ioniq 5', 'available', 'Singapore Discovery Center', 18.00);


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

-- Insert sample reservations
INSERT INTO reservations (user_id, vehicle_id, start_time, end_time, total_price, status)
VALUES
(1, 1, '2024-12-08 10:00:00', '2024-12-08 12:00:00', 30.00, 'completed'),
(2, 2, '2024-12-09 14:00:00', '2024-12-09 16:00:00', 24.00, 'active'),
(3, 3, '2024-12-07 08:00:00', '2024-12-07 09:00:00', 10.00, 'cancelled');

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
-- Insert sample invoices
INSERT INTO invoices (user_id, reservation_id, membership_discount, promo_discount, final_amount, vehicle_model, license_plate, start_time, end_time)
VALUES
(1, 1, 0.00, 10.00, 27.00, 'Tesla Model 3', 'ABC123', '2024-12-08 10:00:00', '2024-12-08 12:00:00'),
(2, 2, 2.40, 0.00, 21.60, 'Nissan Leaf', 'XYZ789', '2024-12-09 14:00:00', '2024-12-09 16:00:00'),
(3, 3, 0.00, 0.00, 10.00, 'Chevy Bolt', 'LMN456', '2024-12-07 08:00:00', '2024-12-07 09:00:00');


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





