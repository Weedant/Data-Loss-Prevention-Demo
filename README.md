# 🛡️ Data Loss Prevention (DLP) System

A powerful, real-time Data Loss Prevention system that monitors file activities, detects sensitive data patterns, and prevents data exfiltration through intelligent quarantine mechanisms.

## 📋 Table of Contents
- [Overview](#-overview)
- [Features](#-features)
- [Demo](#-demo)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage](#-usage)
- [Configuration](#-configuration)
- [Pattern Detection](#-pattern-detection)
- [Dashboard](#-dashboard)
- [Upcoming Features](#-upcoming-features)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🎯 Overview

This DLP system provides real-time monitoring and protection against data exfiltration by automatically detecting sensitive information in files and preventing unauthorized data transfers. Built with Python, it offers a modern web dashboard for management and monitoring.

### Key Highlights
- ✅ **Real-time monitoring** of designated folders and USB drives
- ✅ **Pattern-based detection** for PII, financial data, and confidential information
- ✅ **Automatic quarantine** of files containing sensitive data
- ✅ **Web-based dashboard** for easy management
- ✅ **Whitelist support** for trusted files and folders
- ✅ **CSV export** for compliance reporting
- ✅ **System tray integration** with desktop notifications

---

## ✨ Features

### Core Security Features
- 🔍 **Multi-Pattern Detection**
  - Aadhaar numbers (Indian national ID)
  - Email addresses
  - Credit card numbers
  - Confidential/Secret/Restricted keywords
  - Extensible regex-based pattern system

- 🚨 **Real-time Monitoring**
  - File creation detection
  - File modification tracking
  - File move/copy operations
  - USB drive monitoring
  - Recursive directory watching

- 🔒 **Intelligent Quarantine**
  - Automatic isolation of sensitive files
  - Original location tracking
  - One-click file restoration
  - Quarantine history maintenance

### Management Features
- 📊 **Web Dashboard**
  - Live monitoring status
  - Alert management interface
  - Statistics and metrics
  - Search and filter capabilities
  - Responsive design

- ⚙️ **Policy Modes**
  - **Block Mode**: Quarantine files immediately
  - **Warn Mode**: Alert only, files remain in place
  - Easy toggle between modes

- 📝 **Whitelist System**
  - File-level whitelisting
  - Directory-level whitelisting
  - Bulk whitelist management
  - Clear all option

### Advanced Features
- 🔔 **Notifications**
  - System tray icon
  - Desktop notifications
  - Browser sound alerts
  - Real-time updates

- 📦 **Bulk Operations**
  - Select multiple alerts
  - Bulk allow/dismiss actions
  - Batch processing

- 📤 **Export & Reporting**
  - CSV export of alerts
  - Timestamped reports
  - Detailed alert information
  - Compliance-ready format

- 🔎 **Search & Filter**
  - Real-time search
  - Filter by file, rule, origin
  - Instant results

---

## 🎬 Demo

### Dashboard Interface
```
┌─────────────────────────────────────────────────────────┐
│  🛡️ Mini DLP Dashboard                                  │
├─────────────────────────────────────────────────────────┤
│  Status: Active monitoring enabled                      │
│  Policy Mode: BLOCK                                     │
│  Watched Paths: C:\...\watch, D:\                       │
│  Last Manual Scan: 2025-05-11 14:30:22                 │
├─────────────────────────────────────────────────────────┤
│  [🔍 Scan Existing Files] [📥 Export to CSV]            │
├─────────────────────────────────────────────────────────┤
│  Security Alerts — Total: 15                            │
│  ┌─────────────────────────────────────────────────┐   │
│  │ File        │ Rule   │ Time      │ Actions      │   │
│  ├─────────────────────────────────────────────────┤   │
│  │ report.txt  │ Email  │ 14:25:33  │ ✓ Allow ✗   │   │
│  │ data.csv    │ Aadhaar│ 14:22:11  │ ✓ Allow ✗   │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

---

## 📦 Installation

### Prerequisites
- Python 3.7 or higher
- pip package manager
- Windows/Linux/macOS

### Install Dependencies

```bash
# Clone the repository
git clone https://github.com/yourusername/dlp-system.git
cd dlp-system

# Install required packages
pip install -r requirements.txt
```

### Requirements
```
flask==3.0.0
watchdog==3.0.0
pystray==0.19.5
pillow==10.1.0
```

---

## 🚀 Quick Start

### 1. Basic Setup

```bash
# Start the DLP agent
python main.py
```

### 2. Access Dashboard

Open your browser and navigate to:
```
http://127.0.0.1:5000
```

### 3. Configure Monitoring

Edit the configuration in `main.py`:

```python
# Set your watch folder
WATCH_FOLDER = r"C:\Users\YourName\Desktop\watch"

# Enable USB monitoring
ENABLE_USB_MONITORING = True
USB_DRIVE = r"D:\\"
```

### 4. Test the System

Create a test file with sensitive data:

```bash
# Run the test file generator
python test_file_generator.py
```

---

## 📖 Usage

### Starting the Agent

```bash
python main.py
```

**Console Output:**
```
======================================================================
🛡️  DATA LOSS PREVENTION (DLP) AGENT
======================================================================

⚠️  USB MONITORING: ENABLED
   USB Drive: D:\

[STARTUP] Checking watch paths...
  ✓ C:\Users\VEDANT\Desktop\Data_Exfiltration\watch - EXISTS
  ✓ D:\ - EXISTS

[STARTUP] Starting file system watchers...
[INFO] ✓ Actively watching: C:\Users\VEDANT\Desktop\Data_Exfiltration\watch
[INFO] ✓ Actively watching: D:\

======================================================================
✓ DLP AGENT READY
======================================================================

📊 Dashboard: http://127.0.0.1:5000
🔍 Monitoring: 2 path(s)
📁 Quarantine: C:\...\quarantine
🔔 System tray: Enabled

Press Ctrl+C to stop
```

### Managing Alerts

**Allow a File:**
1. Click the ✓ button next to an alert
2. File is restored to original location
3. File is automatically whitelisted

**Dismiss an Alert:**
1. Click the ✗ button next to an alert
2. Alert is removed
3. File remains in quarantine

**Bulk Actions:**
1. Select multiple alerts using checkboxes
2. Click "✓ Allow Selected" or "✗ Dismiss Selected"
3. Confirm the action

### Whitelist Management

**Add to Whitelist:**
```
1. Enter file or folder path in the whitelist input
2. Click "Add to Whitelist"
3. Path is immediately whitelisted
```

**Remove from Whitelist:**
```
1. Click [remove] next to the path
2. Path is removed from whitelist
```

**Clear All Whitelist:**
```
1. Click "🗑️ Clear All Whitelist" button
2. Confirm the action
3. All whitelisted paths are removed
```

---

## ⚙️ Configuration

### Policy Modes

**Block Mode (Default):**
- Files with sensitive data are quarantined immediately
- Original location is tracked for restoration
- Alerts are logged in dashboard

**Warn Mode:**
- Files trigger alerts but remain in place
- No quarantine action taken
- Useful for monitoring without enforcement

### Watch Paths

Configure which directories to monitor:

```python
WATCH_FOLDER = r"C:\path\to\watch\folder"
USB_DRIVE = r"D:\\"
ENABLE_USB_MONITORING = True
```

### Quarantine Settings

```python
QUARANTINE_FOLDER = os.path.join(BASE_DIR, "quarantine")
PROCESSED_TTL = 10.0  # Seconds to remember processed files
```

---

## 🔍 Pattern Detection

### Built-in Patterns

The system detects the following patterns by default:

| Pattern | Regex | Example |
|---------|-------|---------|
| **Aadhaar** | `\b\d{4}\s\d{4}\s\d{4}\b` | 1234 5678 9012 |
| **Email** | `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}` | user@example.com |
| **Credit Card** | `\b(?:\d[ -]*?){13,16}\b` | 4532 1234 5678 9010 |
| **Confidential** | `\b(confidential\|secret\|restricted)\b` | CONFIDENTIAL |

### Custom Patterns

Add your own detection patterns in `main.py`:

```python
PATTERNS = {
    "Aadhaar": r"\b\d{4}\s\d{4}\s\d{4}\b",
    "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}",
    "Credit Card": r"\b(?:\d[ -]*?){13,16}\b",
    "Confidential": r"\b(confidential|secret|restricted)\b",
    
    # Add your custom patterns here
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",  # US Social Security
    "API_Key": r"\b[A-Za-z0-9]{32,}\b",  # Generic API key
    "Phone": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",  # US Phone
}
```

---

## 📊 Dashboard

### Main Features

**Status Box:**
- Active monitoring status
- Current policy mode
- Watched paths list
- Last scan timestamp

**Statistics Cards:**
- Total alerts count
- Whitelisted paths count
- Monitored locations count

**Alerts Table:**
- File name and path
- File size
- Matched rule
- Timestamp
- Status (block/warn)
- Origin location
- Actions (Allow/Dismiss)

**Search & Filter:**
- Real-time search box
- Filters all alert fields
- Instant results

**Bulk Operations:**
- Select multiple alerts
- Bulk allow action
- Bulk dismiss action

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Ctrl+F` | Focus search box |
| `Ctrl+A` | Select all alerts |
| `Ctrl+R` | Refresh dashboard |

---

## 🔮 Upcoming Features

### High Priority
- 📄 **Advanced File Scanning** - PDF, DOCX, XLSX, PPT support
- 📧 **Email Notifications** - SMTP alerts for security team
- 🎨 **Pattern Management UI** - Add/edit patterns via dashboard
- 📊 **Analytics Dashboard** - Charts, trends, compliance reports
- 🔐 **User Authentication** - Multi-user support with role-based access

### Medium Priority
- 🌐 **Network Monitoring** - Clipboard, cloud uploads, email attachments
- 🤖 **Machine Learning** - AI-powered sensitive data detection
- 📦 **Advanced Quarantine** - Encrypted storage, auto-cleanup
- 🔖 **File Fingerprinting** - Hash-based detection and tracking
- ⏰ **Scheduled Scanning** - Automated periodic scans

### Future Enhancements
- ✨ **Modern UI/UX** - Dark mode, real-time WebSocket updates
- 🌍 **Multi-language Support** - Internationalization
- 🔌 **Integration APIs** - REST API, webhooks, SIEM integration
- ⚡ **Performance Optimization** - Async scanning, caching
- 🛡️ **Enhanced Security** - Encrypted quarantine, tamper-proof logs

See [ROADMAP.md](ROADMAP.md) for detailed feature specifications and timelines.

---

## 🏗️ Architecture

### System Components

```
┌─────────────────────────────────────────────────────────┐
│                    DLP System                           │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌─────────────┐    ┌──────────────┐   ┌───────────┐  │
│  │   Watchdog  │───▶│ File Scanner │──▶│ Quarantine│  │
│  │   Observer  │    │   (Regex)    │   │  Manager  │  │
│  └─────────────┘    └──────────────┘   └───────────┘  │
│         │                   │                  │        │
│         │                   ▼                  │        │
│         │           ┌──────────────┐          │        │
│         │           │ Alert System │          │        │
│         │           └──────────────┘          │        │
│         │                   │                  │        │
│         ▼                   ▼                  ▼        │
│  ┌─────────────────────────────────────────────────┐  │
│  │           Flask Web Dashboard                   │  │
│  │  (Alerts, Whitelist, Export, Bulk Actions)     │  │
│  └─────────────────────────────────────────────────┘  │
│                          │                             │
│                          ▼                             │
│              ┌─────────────────────┐                   │
│              │   System Tray Icon  │                   │
│              │  (Notifications)    │                   │
│              └─────────────────────┘                   │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### File Flow

```
1. File Activity Detected
         ↓
2. File Stability Check
         ↓
3. Whitelist Verification
         ↓
4. Pattern Scanning
         ↓
5. Match Found?
    ├─ No  → Continue Monitoring
    └─ Yes → Create Alert
              ↓
         6. Policy Check
              ├─ Block → Quarantine File
              └─ Warn  → Log Only
              ↓
         7. Update Dashboard
         8. Send Notification
```

---

## 🧪 Testing

### Run Test File Generator

```bash
python test_file_generator.py
```

**Options:**
- Generate small (10 KB) test files
- Generate medium (100 KB) test files
- Generate large (500 KB - 2 MB) test files
- Interactive mode for custom files

### Manual Testing

1. Create a text file with sensitive data
2. Copy to watch folder
3. Verify detection in dashboard
4. Test quarantine functionality
5. Test allow/dismiss actions
6. Test whitelist feature

---

## 🐛 Troubleshooting

### Common Issues

**Dashboard not accessible:**
```
- Check if agent is running
- Verify port 5000 is not in use
- Try http://127.0.0.1:5000 instead of localhost
```

**Files not being detected:**
```
- Check console for debug logs
- Verify watch path exists
- Check file permissions
- Ensure file is not whitelisted
```

**False positives:**
```
- Add false positives to whitelist
- Adjust regex patterns for specificity
- Use Warn mode for testing
```

**Performance issues:**
```
- Reduce PROCESSED_TTL
- Whitelist large directories
- Check disk space
- Monitor system resources
```

---

## 📁 Project Structure

```
dlp-system/
├── main.py                      # Main DLP agent
├── test_file_generator.py       # Test file creator
├── requirements.txt             # Python dependencies
├── README.md                    # This file
├── LICENSE                      # MIT License
├── .gitignore                   # Git ignore rules
├── dlp_state.json              # State persistence (auto-generated)
├── quarantine/                  # Quarantined files (auto-generated)
└── temp_test_files/            # Test files (auto-generated)
```

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/AmazingFeature`)
3. **Commit your changes** (`git commit -m 'Add some AmazingFeature'`)
4. **Push to the branch** (`git push origin feature/AmazingFeature`)
5. **Open a Pull Request**

### Development Guidelines
- Follow PEP 8 style guide
- Add comments for complex logic
- Update README for new features
- Test thoroughly before PR

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 Vedant

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```


## 📞 Contact

**Vedant** - [https://www.linkedin.com/in/vedant-tammewar-405ba5190/]

**Project Link:** (https://github.com/Weedant/Data-Loss-Prevention-Demo/tree/master)



<div align="center">

**⭐ Star this repo if you find it useful! ⭐**

Made with ❤️ by Vedant
