CREATE DATABASE IF NOT EXISTS docterapp;
USE docterapp;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100),
    email VARCHAR(100),
    phone VARCHAR(15)
);

CREATE TABLE IF NOT EXISTS appointments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    doctor VARCHAR(100),
    date DATE,
    time TIME,
    FOREIGN KEY (user_id) REFERENCES users(id)
);