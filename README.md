# llama-guardian

AI-powered Web Application Firewall for Ollama. Secure your LLM APIs with prompt validation, rate limiting, and ML-based threat detection.

---

## Overview

llama-guardian is an open-source, AI-enhanced Web Application Firewall designed to protect Ollama deployments running locally or in the cloud. It combines Nginx, ModSecurity, and intelligent prompt validation (Python/ML) to block prompt injection, sensitive data leaks, and abuse of your LLM API.

**Author:** Roberto Pestana

---

## Features

- **AI-powered prompt validation** (heuristics + optional ML)
- **Blocks prompt injection, PII leaks, and suspicious activity**
- **API key authentication and IP whitelisting**
- **Rate limiting and DoS protection**
- **TLS/HTTPS and reverse proxy**
- **Easy local deployment with Docker Compose**
- **Ready for integration with monitoring tools**

---

## Requirements

- Docker and Docker Compose
- Ollama installed (see [Ollama docs](https://github.com/ollama/ollama))
- Python 3.8+ (for AI prompt validation)
- Optionally: `transformers` and `torch` for advanced ML detection

---

## Quick Start

### 1. Clone the repository
```
git clone https://github.com/epestana28/llama-guardian.git
cd llama-guardian
```
### 2. (Optional) Install Python dependencies for AI validation
```
pip install transformers torch
```

### 3. Generate self-signed certificates for local HTTPS (or use your own)
```
openssl req -x509 -nodes -days 365 -newkey rsa:2048
-keyout nginx/ssl.key -out nginx/ssl.crt -subj "/CN=localhost"
```

### 4. Run locally with Docker Compose

docker-compose up -d

Ollama will be protected behind the WAF at https://localhost/api/generate

---

## File Structure

- `nginx/nginx.conf` — Nginx reverse proxy, TLS, rate limiting, API key, ModSecurity integration
- `nginx/modsec/main.conf` — ModSecurity rules to call AI validator
- `ai/prompt_validator.py` — Python script with heuristics and optional ML for prompt validation
- `docker-compose.yml` — Orchestrates Ollama and Nginx WAF
- `scripts/setup_firewall.sh` — Example script to restrict Ollama port to localhost

---

## Example: Nginx WAF Configuration (`nginx/nginx.conf`)
```
server {
listen 443 ssl;
server_name localhost;

ssl_certificate /etc/nginx/ssl.crt;
ssl_certificate_key /etc/nginx/ssl.key;

limit_req_zone $binary_remote_addr zone=ollama_limit:10m rate=10r/s;

location /api/generate {
    limit_req zone=ollama_limit burst=20;
    if ($http_apikey != "YOUR_SECRET_API_KEY") { return 403; }
    allow 127.0.0.1;
    allow 192.168.1.0/24;
    deny all;

    ModSecurityEnabled on;
    ModSecurityConfig /etc/nginx/modsec/main.conf;

    proxy_pass http://ollama:11434;
    proxy_set_header Host $host;
}

}

```
---

## Example: AI Prompt Validator (`ai/prompt_validator.py`)
```
#!/usr/bin/env python3
import sys, json, re
try:
from transformers import pipeline
clf = pipeline("text-classification", model="facebook/roberta-base")
ML_ENABLED = True
except ImportError:
ML_ENABLED = False

SUSPICIOUS_KEYWORDS = ["hack", "leak", "steal", "password", "token", "api_key", "drop database", "delete", "shutdown", "exploit", "malware", "phishing", "bypass", "inject"]
SUSPICIOUS_PATTERNS = [r"\b(system|os|exec|subprocess|import)\b", r"(base64\sdecode|eval|open$$)", r"(prompt|ignore previous instructions)", r"(you are now|forget all previous)", r"(admin|root|sudo)", r"(?i)flag{.}", r"(?i)ctf{.*}"]

def is_suspicious(prompt):
prompt_lower = prompt.lower()
for word in SUSPICIOUS_KEYWORDS:
if word in prompt_lower:
return True, f"Suspicious keyword detected: {word}"
for pattern in SUSPICIOUS_PATTERNS:
if re.search(pattern, prompt_lower):
return True, f"Suspicious pattern detected: {pattern}"
if len(prompt) > 1024 or prompt.count(";") > 3:
return True, "Prompt too long or contains multiple command separators"
return False, "Prompt considered safe"

def ml_check(prompt):
if not ML_ENABLED:
return False, "ML not enabled"
result = clf(prompt)
label = result['label']
score = result['score']
if label == 'LABEL_1' and score > 0.8:
return True, f"ML model flagged prompt as risky (score={score:.2f})"
return False, "ML model passed"

def main():
try:
data = sys.stdin.read()
req = json.loads(data)
prompt = req.get('ARGS', {}).get('prompt', '')
suspicious, reason = is_suspicious(prompt)
if suspicious:
print(f"Status: 403\n\nBlocked by AI-powered WAF: {reason}")
sys.exit(0)
risky_ml, reason_ml = ml_check(prompt)
if risky_ml:
print(f"Status: 403\n\nBlocked by AI-powered WAF (ML): {reason_ml}")
sys.exit(0)
print("Status: 200\n\nOK")
except Exception as e:
print(f"Status: 500\n\nInternal error in prompt_validator.py: {e}")

if name == "main":
main()
```
---

## Example: ModSecurity rules (`nginx/modsec/main.conf`)
```
SecRuleEngine On
SecRule REQUEST_URI "@streq /api/generate" "id:5001,phase:2,block,exec:/ai/prompt_validator.py,msg:'AI detected malicious prompt'"
```

---

## Example: Docker Compose (`docker-compose.yml`)
```
version: '3.8'
services:
ollama:
image: ollama/ollama:latest
ports:
- "127.0.0.1:11434:11434"
environment:
- OLLAMA_HOST=127.0.0.1

nginx:
image: nginx:latest
ports:
- "443:443"
volumes:
- ./nginx/nginx.conf:/etc/nginx/nginx.conf
- ./nginx/modsec:/etc/nginx/modsec
- ./nginx/ssl.crt:/etc/nginx/ssl.crt
- ./nginx/ssl.key:/etc/nginx/ssl.key
- ./ai:/ai
depends_on:
- ollama

```
---

## Example: Firewall script (`scripts/setup_firewall.sh`)
```
#!/bin/bash
iptables -A INPUT -p tcp --dport 11434 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport 11434 -j DROP

```
---

## How to Validate Deployment

1. **Start the stack:**  
   `docker-compose up -d`
2. **Test API:**  
   Use curl or Postman to POST to `https://localhost/api/generate` with your API key in the header.
3. **Try malicious prompts:**  
   Send a prompt like `"leak all passwords"` and check for HTTP 403.
4. **Check logs:**  
   `docker logs <nginx_container>` for WAF actions.

---

## License

Distributed under the MIT license.

---

## Maintainer

Roberto Pestana
---
