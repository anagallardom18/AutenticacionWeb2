-- =========================================
-- Esquema de base de datos para AutenticacionWeb2
-- =========================================

-- 1. Crear la base de datos 
CREATE DATABASE IF NOT EXISTS autenticacion_db;
USE autenticacion_db;

-- =========================================
-- 2. Crear tablas principales
-- =========================================

-- Tabla de usuarios
CREATE TABLE IF NOT EXISTS usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    dni VARCHAR(9) NOT NULL UNIQUE,
    contrasena VARCHAR(50) NOT NULL,
    correo VARCHAR(100),
    ip_registro VARCHAR(50),
    ubicacion VARCHAR(100),
    ip_permitida VARCHAR(45),
    lat_permitida DOUBLE,
    lon_permitida DOUBLE,
    totp_secret VARCHAR(255)
);

-- Tabla de ubicaciones de dispositivos
CREATE TABLE IF NOT EXISTS device_locations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_dni VARCHAR(9) NOT NULL,
    ip VARCHAR(50) NOT NULL,
    ip_country VARCHAR(50),
    ip_city VARCHAR(50),
    latitud DOUBLE,
    longitud DOUBLE,
    fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_dni) REFERENCES usuarios(dni)
);

-- Tabla para WebAuthn 
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_dni VARCHAR(20) NOT NULL,
    credential_id BLOB NOT NULL,
    public_key LONGBLOB NOT NULL,
    sign_count BIGINT DEFAULT 0,
    UNIQUE(usuario_dni, credential_id),
    FOREIGN KEY (usuario_dni) REFERENCES usuarios(dni)
);

-- Tabla de credenciales FIDO2
CREATE TABLE IF NOT EXISTS credenciales_fido2 (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    dni VARCHAR(20),
    credential_id VARBINARY(255) NOT NULL,
    public_key BLOB NOT NULL,
    sign_count BIGINT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de Passkeys
CREATE TABLE IF NOT EXISTS passkeys (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    dni VARCHAR(20) NOT NULL,
    credential_id BLOB NOT NULL,
    public_key BLOB NOT NULL,
    user_handle BLOB,
    sign_count INT DEFAULT 0
);

-- =========================================
-- 3. Datos iniciales de ejemplo
-- =========================================

INSERT INTO usuarios (dni, contrasena, correo)
VALUES ('12345678A', '1234567A', 'correoenviootp@gmail.com');

-- Crear usuario con contraseña
CREATE USER 'root'@'localhost' IDENTIFIED BY 'root';

-- Otorgar permisos
GRANT ALL PRIVILEGES ON autenticacion_db.* TO 'root'@'localhost';

FLUSH PRIVILEGES;
