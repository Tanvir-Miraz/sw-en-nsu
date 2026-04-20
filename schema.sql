-- Create database
CREATE DATABASE IF NOT EXISTS medicore_db;

-- Use the database
USE medicore_db;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,

    full_name VARCHAR(255) NOT NULL,
    age INT NOT NULL,

    height DECIMAL(6,2) NOT NULL,
    height_unit VARCHAR(10) DEFAULT 'cm',

    weight DECIMAL(6,2) NOT NULL,

    blood_group VARCHAR(5) NOT NULL,
    gender ENUM('male', 'female', 'other') NOT NULL,

    phone VARCHAR(20) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,

    address TEXT NOT NULL,

    password_hash VARCHAR(255) NOT NULL,

    chronic_diseases JSON,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_sessions (
    session_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    email VARCHAR(255) NOT NULL,
    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    logout_time TIMESTAMP NULL DEFAULT NULL,
    session_status ENUM('active', 'logged_out') DEFAULT 'active',
    ip_address VARCHAR(100) DEFAULT NULL,
    user_agent TEXT DEFAULT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);