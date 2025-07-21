# Hygiene360 Database

This directory contains database schema and migration scripts for the Hygiene360 system.

## Schema

The database schema is defined in `schema.sql`. It creates the following tables:

- ✅ Registered endpoints (`devices`)
- 🛡️ Live posture data (`security_data`, `security_snapshots`)
- 🧩 Software inventories and vulnerabilities (`software`)
- ⚙️ Security tools found during scan (`security_tools`)
- 📜 Security compliance policies (`policies`)
- 🚨 Alerts generated based on policy violations (`alerts`)
- 📊 Security score breakdown per device (`score_breakdown`)

## Setup Instructions

### PostgreSQL Setup

1. Install PostgreSQL if not already installed:

```bash
# For Ubuntu/Debian
sudo apt-get update
sudo apt-get install postgresql postgresql-contrib

# For macOS using Homebrew
brew install postgresql

# For Windows
# Download and install from https://www.postgresql.org/download/windows/
```

2. Create the database:

```bash
sudo -u postgres psql
CREATE DATABASE hygiene360;
CREATE USER hygiene360_user WITH ENCRYPTED PASSWORD 'your_password_here';
GRANT ALL PRIVILEGES ON DATABASE hygiene360 TO hygiene360_user;
\q
```

3. Apply the schema:

```bash
psql -U hygiene360_user -d hygiene360 -a -f schema.sql
```

### Environment Configuration

Create a `.env` file in the API directory with the following content:

```
DATABASE_URL=postgresql://hygiene360_user:your_password_here@localhost:5432/hygiene360
```

## Backup and Restore

### Backup

```bash
pg_dump -U hygiene360_user -d hygiene360 > backup.sql
```

### Restore

```bash
psql -U hygiene360_user -d hygiene360 < backup.sql
``` 