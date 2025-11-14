<?php
// setup_database.php

// 1) Load DB credentials
require __DIR__ . '/database.php';

$host = $dbConfig['host'];
$user = $dbConfig['user'];
$pass = $dbConfig['pass'];
$dbName = $dbConfig['name'];

//DEBUG
// echo "host: ".$host." - user: ".$user." - pass: ".$pass." - dbName: ".$dbName;

// 2) Connect to MySQL (server only, no DB yet)
$mysqli = new mysqli($host, $user, $pass);

if ($mysqli->connect_error) {
    die("Connection failed: " . $mysqli->connect_error);
}

echo "Connected to MySQL server<br>";

// 3) Create database if not exists
$sql = "CREATE DATABASE IF NOT EXISTS `$dbName`
        CHARACTER SET utf8mb4
        COLLATE utf8mb4_unicode_ci";

if (!$mysqli->query($sql)) {
    die("Error creating database: " . $mysqli->error);
}

echo "Database '$dbName' is ready<br>";

$mysqli->select_db($dbName);

// 4) Create tables

$queries = [];

// USERS
$queries[] = "
CREATE TABLE IF NOT EXISTS users (
    id              CHAR(36)    NOT NULL PRIMARY KEY,
    email           VARCHAR(255) NOT NULL UNIQUE,
    password        VARCHAR(255) NOT NULL,
    role            ENUM('Andel','Admin') NOT NULL DEFAULT 'Andel',
    name            VARCHAR(255),
    address         VARCHAR(255),
    post_nr         INT,
    phone           VARCHAR(50),
    birthdate       DATE,
    status          ENUM('active', 'deleted') NOT NULL DEFAULT 'active',
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    ON UPDATE CURRENT_TIMESTAMP
    pw_reset_token  VARCHAR(255) NULL
    pw_reset_exp_at DATETIME NULL
    email_confirmed TINYINT(1) NOT NULL DEFAULT 0,
    email_confirmed_token VARCHAR(255) NULL;
) ENGINE=InnoDB;
";

// SHARES
$queries[] = "
CREATE TABLE IF NOT EXISTS shares (
    id              CHAR(36)    NOT NULL PRIMARY KEY,
    status          ENUM('active', 'deleted') NOT NULL DEFAULT 'active',
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;
";

// OWNERSHIP
$queries[] = "
CREATE TABLE IF NOT EXISTS ownerships (
    id              CHAR(36)    NOT NULL PRIMARY KEY,
    user_id         CHAR(36)    NOT NULL,
    share_id        CHAR(36)    NOT NULL,
    lookup          VARCHAR(255) NOT NULL UNIQUE,
    start_date      DATE        NOT NULL,
    end_date        DATE        NULL,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_ownership_user
        FOREIGN KEY (user_id) REFERENCES users(id),
    CONSTRAINT fk_ownership_share
        FOREIGN KEY (share_id) REFERENCES shares(id)
) ENGINE=InnoDB;
";

// LOGS
$queries[] = "
CREATE TABLE IF NOT EXISTS logs (
    id          CHAR(36)    NOT NULL PRIMARY KEY,
    user_id     CHAR(36)    NULL,
    action      TEXT        NOT NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_log_user
        FOREIGN KEY (user_id) REFERENCES users(id)
) ENGINE=InnoDB;
";

// 5) Run all queries
foreach ($queries as $index => $query) {
    if ($mysqli->query($query)) {
        echo "Query " . ($index + 1) . " OK<br>";
    } else {
        echo "Error in query " . ($index + 1) . ": " . $mysqli->error . "<br>";
    }
}

echo "<br>Setup complete.";

$mysqli->close();