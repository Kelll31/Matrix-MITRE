# MITRE ATT&CK Matrix Viewer

A comprehensive web application for viewing, managing, and analyzing the MITRE ATT&CK matrix with automatic updates, intelligent caching, and an interactive user interface.

## Overview

This project provides a complete implementation of a MITRE ATT&CK matrix viewer featuring a high-performance FastAPI backend and a modern responsive frontend. The application automatically fetches and caches the latest MITRE ATT&CK data from the official GitHub repository, enabling quick searches and comprehensive analysis of attack techniques and tactics.

## Key Features

- **FastAPI Backend** - Asynchronous, production-grade API with full type annotations
- **Interactive Frontend** - Modern responsive UI with dark theme and smooth animations
- **Automatic Updates** - Configurable update intervals ranging from 1 hour to 7 days
- **Smart Caching** - Local JSON caching for instant data access and reduced network overhead
- **Advanced Search** - Full-text search across technique names, IDs, descriptions, and platforms
- **Statistics Dashboard** - Real-time metrics for tactics, techniques, and subtechniques
- **Multi-Platform Support** - Works seamlessly on desktop, tablet, and mobile devices
- **Internationalization** - Full support for Cyrillic characters (Russian language)
- **Production Ready** - Optimized for deployment to production environments

## Technology Stack

### Backend
- Python 3.9 or higher
- FastAPI 0.104+ - Modern async web framework with built-in API documentation
- Uvicorn - ASGI application server
- aiohttp - Asynchronous HTTP client for concurrent requests
- Pydantic - Data validation using Python type annotations
- python-dotenv - Environment configuration management

### Frontend
- HTML5 and CSS3 - Semantic markup and modern styling
- Vanilla JavaScript (ES6+) - Zero external framework dependencies
- Axios - Promise-based HTTP client
- Bootstrap 5 CDN - Responsive CSS framework
- Font Awesome 6 - Comprehensive icon library

### Data Source
- MITRE ATT&CK Enterprise Framework - Official GitHub repository with STIX JSON format

## Installation and Setup

### Prerequisites

Ensure you have Python 3.9+ and pip installed on your system.

### Step 1: Clone the Repository

```bash
git clone https://github.com/Kelll31/Matrix-MITRE.git
cd Matrix-MITRE
```

### Step 2: Create a Virtual Environment

For Windows:
```bash
python -m venv venv
venv\Scripts\activate
```

For Linux/macOS:
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Run the Application

```bash
python main.py
```

The application will be available at: **http://localhost:8000**

## API Reference

### Data Retrieval Endpoints

#### Get Complete Matrix
```
GET /api/matrix
```
Returns the entire MITRE ATT&CK matrix with all tactics, techniques, and subtechniques.

#### Get Statistics
```
GET /api/statistics
```
Response:
```json
{
  "total_tactics": 14,
  "total_techniques": 234,
  "total_subtechniques": 543,
  "last_update": "2026-01-14T12:34:56",
  "update_interval": "24_hours",
  "is_updating": false,
  "update_count": 5
}
```

#### Get All Tactics
```
GET /api/matrix/tactics
```
Returns all available tactics with descriptions and shortnames.

#### Get Tactic Details
```
GET /api/matrix/tactic/{tactic_name}
```
Example: `GET /api/matrix/tactic/persistence`

Returns all techniques associated with the specified tactic.

#### Get Technique by ID
```
GET /api/matrix/technique/{technique_id}
```
Examples:
- `GET /api/matrix/technique/T1001`
- `GET /api/matrix/technique/T1001.001`

Returns complete information about a technique or subtechnique, including description, platforms, detection methods, and external references.

#### Get Techniques by Tactic with Filtering
```
GET /api/matrix/tactics/{tactic}/techniques
```
Query Parameters:
- `platform` (optional) - Filter by platform (Windows, Linux, macOS, etc.)
- `limit` (optional) - Maximum number of results

Example: `GET /api/matrix/tactics/persistence/techniques?platform=Windows&limit=10`

#### Search Techniques
```
GET /api/search?q={query}&limit={limit}
```
Parameters:
- `q` - Search query (required, minimum 1 character)
- `limit` - Maximum results (default: 20, maximum: 100)

The search queries across:
- Technique names
- Technique IDs
- Descriptions
- Supported platforms

Examples:
- `GET /api/search?q=T1001` - Search by ID
- `GET /api/search?q=Process` - Search by description
- `GET /api/search?q=Windows&limit=50` - Search by platform with custom limit

### Management and Configuration Endpoints

#### Change Update Interval
```
POST /api/settings/update-interval
Content-Type: application/json

{
  "interval": "24_hours"
}
```

Available intervals:
- `1_hour` - Update every hour
- `6_hours` - Update every 6 hours
- `12_hours` - Update every 12 hours
- `24_hours` - Update every day (default)
- `7_days` - Update every week

#### Force Immediate Update
```
POST /api/matrix/refresh
```

Triggers an immediate download and parsing of the latest MITRE ATT&CK matrix from GitHub. Returns update confirmation with timestamp.

## Update Intervals

The application supports flexible automatic update scheduling to balance freshness with resource consumption:

| Interval | Duration | Use Case |
|----------|----------|----------|
| 1_hour | 3600 seconds | High-frequency threat intelligence |
| 6_hours | 21600 seconds | Regular business hours monitoring |
| 12_hours | 43200 seconds | Balanced approach |
| 24_hours | 86400 seconds | Daily sync (recommended default) |
| 7_days | 604800 seconds | Low-traffic environments |

## User Interface

### Dashboard
- Real-time statistics showing total count of tactics, techniques, and subtechniques
- Last update timestamp with update counter
- Manual refresh button for immediate updates
- Dropdown selector for configuring automatic update intervals

### Tactics Matrix
- Complete view of all 14 MITRE ATT&CK tactics
- Interactive cards with tactic information
- Technique count for each tactic
- Hover effects and smooth transitions
- Direct navigation to technique details

### Technique Viewer
- Comprehensive list of all techniques for selected tactic
- ID, name, and supported platforms for quick reference
- Expandable details with full descriptions
- Detection methods and mitigation strategies
- Links to official MITRE ATT&CK pages
- Subtechnique hierarchy and relationships

### Search Interface
- Real-time search results with multiple matching criteria
- Filter results by tactic
- Quick navigation to full technique details
- Pagination support for large result sets

## Project Structure

```
Matrix-MITRE/
├── main.py                    # FastAPI application with all endpoints
├── requirements.txt           # Python package dependencies
├── README.md                  # Project documentation
├── .gitignore                 # Git ignore configuration
├── cache/                     # Local cache directory (auto-generated)
│   ├── mitre_matrix.json      # Cached MITRE ATT&CK matrix
│   └── metadata.json          # Cache metadata and timestamps
└── frontend/                  # Web interface
    └── index.html             # Complete HTML/CSS/JS interface
```

## Matrix Update Process

### Initialization
1. Application checks for existing local cache
2. If cache exists and is valid, loads data immediately
3. If cache is missing or stale, downloads from GitHub
4. Launches background task for periodic updates

### Background Update Cycle
1. Waits for configured update interval
2. Downloads latest MITRE ATT&CK data in STIX JSON format
3. Parses and validates data structure
4. Builds searchable indices for fast lookups
5. Updates local cache files
6. Logs update completion with timestamp
7. Increments update counter

### Implementation Details
- All network requests are fully asynchronous (non-blocking)
- JSON parsing includes comprehensive error handling
- Caching uses UTF-8 encoding for full Cyrillic support
- CORS (Cross-Origin Resource Sharing) is enabled for integration scenarios
- Efficient indexing enables sub-millisecond technique lookups

## Data Model

The application parses MITRE STIX JSON data into the following structure:

### Technique Object
```json
{
  "id": "T1001",
  "name": "Data Obfuscation",
  "description": "Data obfuscation...",
  "platforms": ["Windows", "Linux", "macOS"],
  "tactics": ["command-and-control"],
  "mitre_url": "https://attack.mitre.org/techniques/T1001/",
  "detection": "Detection method...",
  "external_references": [...],
  "kill_chain_phases": ["command-and-control"],
  "subtechniques": [...]
}
```

### Tactic Object
```json
{
  "name": "Persistence",
  "shortname": "persistence",
  "description": "The adversary...",
  "techniques": [...]
}
```

## Performance Characteristics

- **Initial Load**: Instant if cache available, 2-5 seconds on first run
- **Technique Lookup**: Sub-millisecond via hash-based indices
- **Search Performance**: Linear O(n) but typically <100ms for 500 results
- **Cache Size**: Approximately 2-3 MB for complete matrix
- **Memory Usage**: 50-80 MB during runtime
- **Concurrent Requests**: Handles 100+ simultaneous users

## Security Considerations

- CORS is configured to accept requests from all origins (modify for production)
- All input is validated through Pydantic models
- Exception handling prevents information leakage
- No sensitive credentials are stored in the code
- Environment variables can be used for configuration
- Use HTTPS in production environments
- Consider implementing rate limiting for production deployments

## Deployment

### Local Development
```bash
python main.py
```

### Production with Gunicorn
```bash
pip install gunicorn
gunicorn main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

### Docker Deployment

Create a Dockerfile:
```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

Build and run:
```bash
docker build -t mitre-matrix .
docker run -p 8000:8000 -d mitre-matrix
```

### Systemd Service

Create `/etc/systemd/system/mitre-matrix.service`:
```ini
[Unit]
Description=MITRE ATT&CK Matrix Service
After=network.target

[Service]
User=www-data
WorkingDirectory=/opt/mitre-matrix
ExecStart=/usr/bin/gunicorn main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable mitre-matrix
sudo systemctl start mitre-matrix
```

## Logging

The application outputs detailed logs for monitoring and debugging:

```
INFO: Application startup complete
INFO: Cache loaded from disk (JSON file)
INFO: MITRE ATT&CK matrix loaded successfully
INFO: Background update task started
INFO: Forcing immediate matrix refresh
INFO: Matrix update completed (update #5)
```

## Error Handling

The application includes comprehensive error handling:
- 503 Service Unavailable - Matrix not yet loaded
- 404 Not Found - Requested technique or tactic not found
- 429 Too Many Requests - Update already in progress
- 400 Bad Request - Invalid update interval parameter

## Code Statistics

- main.py: Approximately 650 lines of production-grade Python code
- index.html: Approximately 600 lines of HTML/CSS/JavaScript
- Total: Approximately 1,250 lines of code
- No external build tools or transpilers required

## Recent Updates (v1.1)

- Fixed DeprecationWarning for deprecated @app.on_event syntax
- Migrated to modern FastAPI lifespan context manager pattern
- Resolved type annotation issues with response validation
- Improved JSON loading from GitHub (handles text/plain content-type)
- Implemented full-featured interactive frontend interface
- Enhanced error handling and logging throughout

## Contributing

Contributions are welcome! Please feel free to submit pull requests with improvements, bug fixes, or new features.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

**Kelll31** - Pentesting and Cybersecurity Specialist

- GitHub: [Kelll31](https://github.com/Kelll31)
- Focus: Red Team Operations, Threat Intelligence, MITRE ATT&CK Framework

---

**Built with a focus on reliability and usability for cybersecurity professionals**

Last updated: January 14, 2026