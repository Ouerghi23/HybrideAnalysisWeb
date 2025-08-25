# HybrideAnalysisWeb

A simple Django-based web application that analyzes URLs, IP addresses, and files (up to 32MB) using the VirusTotal API and OTX (AlienVault).

It provides security scores, reputation details, community votes, and IP information with results from 70+ antivirus engines (e.g., Bkav, Lionic, etc.).

## 🚀 Features

✅ Submit and analyze a URL or IP address  
✅ Upload and scan a file (max 32MB – free API limit)  
✅ View detailed results, including:
- Scan date
- Detection count
- Reputation score
- Community votes
- Engine-by-engine detection results (76 engines)

✅ IP Info Lookup
- ASN (Autonomous System Number)
- Country & ISP
- Malware / Suspicious activity history
- Related domains and URLs

## 🖥️ Technologies Used

- Django (Python web framework)
- Python Requests (for API integration)
- HTML/CSS (Django templates)
- VirusTotal Public API
- OTX AlienVault API (for IP intelligence and threat data)
- IPInfo API (for IP geolocation and network information)

## 🛠️ Installation

### 1. Clone the repo
```bash
git clone https://github.com/Ouerghi23/HybrideAnalysisWeb.git
cd HybrideAnalysisWeb
```

### 2. Create a virtual environment
```bash
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Add your API keys
In `settings.py` or in a `.env` file (recommended), add:
```python
VT_API_KEY = "your_virustotal_api_key"
OTX_API_KEY = "your_otx_api_key"
IPINFO_API_KEY = "your_ipinfo_api_key"
```

### 5. Run the server
```bash
python manage.py runserver
```

## 📝 Usage

1. Open your browser and go to `http://localhost:8000`
2. Choose your analysis type:
   - Enter a URL
   - Enter an IP address
   - Upload a file (max 32MB)
3. Click **Analyze** and view the results in real time

## 🔑 Getting API Keys

### VirusTotal:
1. Go to [VirusTotal](https://www.virustotal.com/)
2. Create a free account
3. Navigate to your profile settings
4. Copy your API key

### OTX (AlienVault):
1. Go to [AlienVault OTX](https://otx.alienvault.com/)
2. Sign up for a free account
3. Retrieve your API key from profile settings

### IPInfo:
1. Go to [IPInfo](https://ipinfo.io/)
2. Create a free account
3. Navigate to your dashboard
4. Copy your access token

## 📊 API Limits

- **VirusTotal Free tier**: 4 requests per minute, file size up to 32MB
- **OTX Free tier**: 2000 requests/day
- **IPInfo Free tier**: 50,000 requests/month

## 🤝 Contact

**Developed by Chaima Ouerghi**  
📧 Email: shaymaouerghi0@gmail.com
