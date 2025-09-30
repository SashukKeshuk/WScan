# WScan - Advanced Web Application Security Scanner

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

WScan is a high-performance asynchronous web application security scanner designed specifically for comprehensive deserialization vulnerability detection. It combines intelligent crawling with active security testing to identify insecure deserialization vulnerabilities across entire web applications.

## 🚀 Features

- **Intelligent Crawling**: Asynchronous web crawling with URL tree building
- **Deserialization Testing**: Automatic detection of insecure deserialization vulnerabilities in Python, PHP, and Java
- **High Performance**: Built on `aiohttp` for maximum concurrency and speed
- **Distributed Ready**: Kubernetes-compatible for large-scale scanning
- **Flexible Configuration**: Support for proxies, custom headers, and cookies
- **Comprehensive Reporting**: Detailed vulnerability reporting with timing-based detection

## 📋 Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Install from source
```bash
git clone https://github.com/your-username/WScan.git
cd WScan
pip install -r requirements.txt
```

## 🛠 Usage


Basic Crawling
```bash
python main.py https://example.com
Full Security Scan with Deserialization Testing
```bash
python main.py -s --sleep 5 https://example.com
```
Advanced Scan with Authentication
```bash
python main.py -C "session=abc123;user=john" -H "Authorization: Bearer token" -s https://example.com
```
Scan Through Proxy
```bash
python main.py -p 127.0.0.1:8080 -s https://example.com
python main.py -p http://user:pass@127.0.0.1:8080 -s https://example.com
```

## ⚙️ Command Line Options

Option	Description	Default
-h, `--help`	Show help message	
-C, `--cookies` COOKIES	Cookies in format "name1=value1;name2=value2"	
-H, `--headers` HEADERS	Headers in format "Header1: value1\nHeader2: value2"	
-p, `--proxy `PROXY	Proxy in format ip:port or protocol://user:pass@ip:port	
-t, `--timeout` TIMEOUT	Request timeout in seconds	10
-d, `--delay` DELAY	Delay between requests in seconds	0.1
-c, `--concurrency` CONCURRENCY	Number of concurrent requests	10
-s, `--serialization`	Enable deserialization vulnerability testing	
`--sleep` SLEEP	Sleep time for deserialization payloads (seconds)	5
-e, `--exclude` EXCLUDE	Cookies to exclude (comma separated)	

### 🔍 How Deserialization Testing Works

WScan uses a sophisticated timing-based approach to detect insecure deserialization vulnerabilities:

**Payload Generation**: Creates malicious serialized objects for Python, PHP, and Java containing sleep commands

**Timing Analysis**: Measures server response time against expected sleep duration

**Technology Detection**: Sequentially tests each technology stack

**Confidence Scoring**: Flags endpoints as potentially vulnerable based on timing correlation

Supported Technologies

**Python**: pickle serialization

**PHP**: PHP object serialization

**Java**: Java object serialization

## 🏗 Architecture

WScan Core
├── Async Crawler (aiohttp)
├── URL Tree Builder
├── Deserialization Engine
│   ├── Python Payload Generator
│   ├── PHP Payload Generator
│   └── Java Payload Generator
└── Reporting Module

## 📊 Output

WScan provides:

 - Complete URL tree of the scanned application

 - List of potentially vulnerable endpoints

 - Detailed timing information

 - Technology-specific detection results

## 🐳 Kubernetes Deployment

For large-scale scanning, WScan supports distributed deployment in Kubernetes:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: wscan-distributed
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: wscan
        image: your-registry/wscan:latest
        command: ["python", "main.py", "-s", "https://target.com"]
```

## 🤝 Integration with Burp Suite


WScan complements traditional security tools:

 - Proxy through Burp: Use -p 127.0.0.1:8080 to route traffic through Burp Suite

 - Passive Analysis: Combine WScan's active testing with Burp's passive scanner

 - Comprehensive Coverage: Detect both deserialization and other vulnerability classes



