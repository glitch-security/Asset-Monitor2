#!/usr/bin/env python3
"""
Quick test script to verify the project API fixes.
Run this after starting the web server.
"""

import requests
import json

BASE_URL = "http://localhost:8000"

# Test 1: Get session info (no auth required for basic check)
print("Test 1: Health check...")
try:
    r = requests.get(f"{BASE_URL}/health", timeout=5)
    print(f"  Status: {r.status_code}, Response: {r.json()}")
except Exception as e:
    print(f"  Error: {e}")

# Test 2: Try to access projects without auth (should get 401)
print("\nTest 2: Projects API without auth...")
try:
    r = requests.get(f"{BASE_URL}/api/projects", timeout=5)
    print(f"  Status: {r.status_code}")
    if r.status_code == 401:
        print("  ✓ Correctly returns 401 without auth")
    else:
        print(f"  Response: {r.text[:200]}")
except Exception as e:
    print(f"  Error: {e}")

print("\nTo test with auth, you need to:")
print("1. Start the server: python -m src.web.server")
print("2. Login at http://localhost:8000/login")
print("3. Use the CSRF token from the session in subsequent requests")
print("\nOr use the web UI directly to test:")
print("- Create a new project")
print("- View the projects tab")
print("- Add a GitHub repo for monitoring")
