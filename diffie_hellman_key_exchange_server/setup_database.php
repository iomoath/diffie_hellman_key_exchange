<?php

// Run for first time, creates Database SQLITE file

$database = new SQLite3('sessions.db', SQLITE3_OPEN_CREATE | SQLITE3_OPEN_READWRITE);


$database->query('CREATE TABLE IF NOT EXISTS "secrets" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    "session_id" VARCHAR,
    "key" VARCHAR,
    "iv" VARCHAR
)');
