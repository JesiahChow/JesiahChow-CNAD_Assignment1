use vehicle_rental_db;

CREATE TABLE membership_tiers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    benefits TEXT,
    discount_rate DECIMAL(5, 2)
);
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    membership_tier_id INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (membership_tier_id) REFERENCES membership_tiers(id)
);


CREATE TABLE vehicles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    license_plate VARCHAR(20) UNIQUE NOT NULL,
    model VARCHAR(50),
    status ENUM('available', 'reserved', 'in_maintenance') DEFAULT 'available',
    location VARCHAR(100),
    hourly_rate DECIMAL(10, 2)
);

CREATE TABLE reservations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    vehicle_id INT,
    start_time DATETIME,
    end_time DATETIME,
    total_price DECIMAL(10, 2),
    status ENUM('active', 'completed', 'canceled'),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (vehicle_id) REFERENCES vehicles(id)
);

CREATE TABLE billing (
    id INT AUTO_INCREMENT PRIMARY KEY,
    reservation_id INT,
    payment_status ENUM('pending', 'paid', 'failed'),
    amount DECIMAL(10, 2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (reservation_id) REFERENCES reservations(id)
);

--Additional addons aftrer insertion
ALTER TABLE users
MODIFY COLUMN membership_tier_id INT DEFAULT 1;

ALTER TABLE users
ADD COLUMN verification_token VARCHAR(255),
ADD COLUMN is_verified BOOLEAN DEFAULT FALSE;

--price is cost needed to upgrade membership tier
ALTER TABLE membership_tiers
ADD COLUMN price DECIMAL(10, 2) DEFAULT 0;