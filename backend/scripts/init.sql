-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Create application database if not exists
SELECT 'CREATE DATABASE shieldsentinel'
WHERE NOT EXISTS (
    SELECT FROM pg_database WHERE datname = 'shieldsentinel'
)\gexec
