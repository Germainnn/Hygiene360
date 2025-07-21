# Hygiene360 - Endpoint Security Agent System

Hygiene360 is a lightweight, automated endpoint security agent system designed to assess and quantify security posture in remote environments. It evaluates key security indicators, provides dynamic scoring, and visualizes results through a centralized web dashboard.

<img width="1898" height="865" alt="image" src="https://github.com/user-attachments/assets/9f91a607-428f-41b0-90eb-2266b4273e25" />
<img width="1005" height="641" alt="image" src="https://github.com/user-attachments/assets/de38ef4f-626c-426b-bef1-32ae1d17b617" />


## System Architecture

The system consists of three main components:

1. **Agent**: Python-based endpoint security agent that collects security metrics from the local system.
2. **API**: Flask-based API that receives, processes, and stores security data.
3. **Dashboard**: Django-based web application that visualizes security metrics and provides management capabilities.

## Features

- **OS Patch Status Monitoring**: Checks for missing updates and patches.
- **Antivirus Status**: Verifies if antivirus is installed, enabled, and up-to-date.
- **Firewall Configuration**: Validates firewall status and configuration.
- **Vulnerability Detection**: Identifies potential security vulnerabilities.
- **Software Inventory**: Tracks installed software and identifies outdated versions.
- **Security Software Validation**: Checks for the presence of security tools (EDR, DLP, etc.).
- **Dynamic Scoring**: Calculates a security score based on collected metrics.
- **Policy-based Compliance**: Evaluates devices against customizable security policies.
- **Real-time Alerts**: Generates alerts for security issues.
- **Centralized Dashboard**: Provides a comprehensive view of security posture.

## Setup Instructions

### Prerequisites

- Python 3.8+
- PostgreSQL 12+
- Django 4.2+
- Flask 2.3+

### Agent Setup

```bash
cd agent
pip install -r requirements.txt
python agent.py
```

### API Setup

1. Create and configure your PostgreSQL database (see `database/README.md`).
2. Create a `.env` file in the `api` directory (see `database/README.md` for details).
3. Run the API:

```bash
cd api
pip install -r requirements.txt
python app.py
```

### Dashboard Setup

```bash
cd dashboard
pip install -r requirements.txt
python manage.py migrate
python manage.py createsuperuser  # Follow prompts to create an admin user
python manage.py runserver
```

## Project Structure

```
hygiene360/
├── agent/                  # Endpoint security agent
│   ├── modules/            # Agent modules for collecting security metrics
│   ├── agent.py            # Main agent code
│   └── requirements.txt    # Agent dependencies
├── api/                    # Flask API
│   ├── models/             # Database models
│   ├── app.py              # Main API application
│   └── requirements.txt    # API dependencies
├── dashboard/              # Django dashboard
│   ├── hygiene360/         # Django project
│   ├── dashboard/          # Django app
│   │   ├── templates/      # HTML templates
│   │   ├── views.py        # View functions
│   │   └── urls.py         # URL routing
│   ├── manage.py           # Django management script
│   └── requirements.txt    # Dashboard dependencies
└── database/               # Database schema and migrations
    ├── schema.sql          # Database schema
    └── README.md           # Database setup instructions
```

## Security Metrics

Hygiene360 collects and analyzes the following security metrics:

1. **OS Security**: Patch status, update status, and build information.
2. **Antivirus Security**: Status, real-time protection, definition updates.
3. **Firewall Security**: Status, active rules, and configuration.
4. **Software Security**: Outdated software, vulnerable versions.
5. **Enterprise Security Tools**: EDR, DLP, disk encryption.

## Security Scoring

The system calculates a security score (0-100) based on:

- OS patch status (0-25 points)
- Antivirus status (0-25 points)
- Firewall status (0-20 points)
- Security tools (0-30 points)

Scores are calculated automatically when agents send data to the API.

## Key Exclusions

- No automated remediation (provides recommendations only)
- No mobile or IoT support
- No behavioral analytics
- No post-project maintenance (academic project scope)

## License

This project is for educational purposes only.

# Hygiene360 Security Agent

A security monitoring agent that collects system security metrics and sends them to a central server.

## Features

- System information collection
- Antivirus status monitoring
- Firewall status monitoring
- OS patch status monitoring
- Software inventory
- Security tools status
- GUI interface for monitoring
- Background service mode

## Installation

1. Install Python 3.8 or higher
2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

The agent uses the following configuration files:

- `agent_config.json`: Stores device ID and other settings
- `agent.log`: Contains detailed operation logs

## Server Configuration

By default, the agent sends data to `http://localhost:5000/api`. To change this:

1. Edit the `API_URL` variable in `agent/agent.py`
2. Ensure the server endpoint is accessible

## Logging

Logs are written to `agent.log` with the following information:
- Scan results
- Server communication status
- Errors and warnings
- Operation timestamps

## Security

The agent requires administrative privileges to:
- Check antivirus status
- Monitor firewall settings
- Access system information
- Read software inventory

## License

This project is licensed under the MIT License - see the LICENSE file for details. 
