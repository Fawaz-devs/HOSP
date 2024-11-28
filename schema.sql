DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS patient_data;
DROP TABLE IF EXISTS doctor_data;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL
);

CREATE TABLE patient_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    description TEXT NOT NULL,
    image_filename TEXT,
    private_key TEXT NOT NULL,
    FOREIGN KEY (patient_id) REFERENCES users(id)
);

CREATE TABLE doctor_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    doctor_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    description TEXT NOT NULL,
    image_filename TEXT,
    private_key TEXT NOT NULL,
    FOREIGN KEY (doctor_id) REFERENCES users(id)
);

