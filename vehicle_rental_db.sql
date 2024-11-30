--New microservice
-- Create User Service Database
CREATE DATABASE user_db;

USE user_service_db;

-- Users Table
CREATE TABLE users (
-- Membership Tiers Table
CREATE TABLE membership_tiers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    benefits TEXT,
    discount_rate DECIMAL(5, 2),
    price DECIMAL(10, 2) DEFAULT 0 -- price for upgrading
    
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    membership_tier_id INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    verification_token VARCHAR(255),
    is_verified BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (membership_tier_id) REFERENCES membership_tiers(id)
    --additional addon
    ALTER TABLE users
    MODIFY COLUMN membership_tier_id INT DEFAULT 1;
);

INSERT INTO user_service_db.users (username, email, password_hash, membership_tier_id, verification_token, is_verified) VALUES
('john_doe', 'john.doe@example.com', '5e884898da28047151d0e56f8dc6292773603d0d1b54c5b6b8c7ff7587c4b5e5', 1, 'abc123token', TRUE),
('jane_smith', 'jane.smith@example.com', '7c4f9be3e292f8d5e57e9f470a3d03d6da2872d75d5f6c73fcf9824a1f85f8bb', 2, 'def456token', TRUE),
('alice_brown', 'alice.brown@example.com', 'b8b453019431c740f2b2ae0a49bc967e7cb37468a88bba12951e39d9a8c6e68a', 3, 'ghi789token', FALSE);
INSERT INTO user_service_db.membership_tiers (name, benefits, discount_rate, price) VALUES
('Basic', 'Access to basic vehicle rental benefits.', 5.00, 0),
('Premium', 'Access to premium vehicle rental benefits, including priority booking.', 15.00, 50.00),
('VIP', 'Access to VIP vehicle rental benefits, including exclusive vehicles and priority booking.', 25.00, 100.00);
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

INSERT INTO vehicle_service_db.vehicles (license_plate, model, status, location, hourly_rate) VALUES
('ABC123', 'Tesla Model 3', 'available', 'Orchard Road', 25.00),
('DEF456', 'Nissan Leaf', 'reserved', 'Marina Bay Sands', 28.00),
('GHI789', 'BMW i3', 'in_maintenance', 'Changi Airport', 30.00),
('JKL012', 'Chevrolet Bolt EV', 'available', 'Sentosa', 32.00),
('MNO345', 'Hyundai Kona Electric', 'available', 'Tampines Mall', 26.00);

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
    status ENUM('active', 'completed', 'canceled'),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user_service_db.users(id),
    FOREIGN KEY (vehicle_id) REFERENCES vehicle_service_db.vehicles(id)
);
INSERT INTO reservation_service_db.reservations (user_id, vehicle_id, start_time, end_time, total_price, status) VALUES
(1, 1, '2024-12-01 10:00:00', '2024-12-01 14:00:00', 60.00, 'active'),
(2, 2, '2024-12-01 12:00:00', '2024-12-01 18:00:00', 72.00, 'completed'),
(3, 3, '2024-12-02 09:00:00', '2024-12-02 15:00:00', 84.00, 'canceled'),
(1, 4, '2024-12-02 08:00:00', '2024-12-02 16:00:00', 88.00, 'active'),
(2, 5, '2024-12-03 10:00:00', '2024-12-03 14:00:00', 68.00, 'completed');

-- Create Billing Service Database
CREATE DATABASE billing_service_db;

USE billing_service_db;

-- Billing Table
CREATE TABLE billing (
    id INT AUTO_INCREMENT PRIMARY KEY,
    reservation_id INT,
    payment_status ENUM('pending', 'paid', 'failed'),
    amount DECIMAL(10, 2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (reservation_id) REFERENCES reservation_service_db.reservations(id)
);
INSERT INTO billing_service_db.billing (reservation_id, payment_status, amount) VALUES
(1, 'pending', 60.00),
(2, 'paid', 72.00),
(3, 'failed', 84.00),
(4, 'pending', 88.00),
(5, 'paid', 68.00);








