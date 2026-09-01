#!/usr/bin/env python3
"""
Pre-flight check script to verify the Bastion backend environment.
"""

import os
import sys
import socket

def check_port(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        return s.connect_ex((host, port)) == 0

def main():
    print("Running Bastion Pre-Flight Checks...")
    
    # Check Qdrant
    print("- Checking Qdrant vector database...")
    qdrant_host = os.getenv("QDRANT_HOST", "localhost")
    if not check_port(qdrant_host, 6333):
        print(f"  [!] Warning: Could not connect to Qdrant at {qdrant_host}:6333.")
        print("      Did you run 'docker compose up -d'?")
    else:
        print("  [✓] Qdrant is accessible.")

    # Check GGUF models dir
    print("- Checking for quantized models...")
    models_dir = os.path.join(os.path.dirname(__file__), "..", "..", "models")
    if os.path.exists(models_dir):
        ggufs = [f for f in os.listdir(models_dir) if f.endswith(".gguf")]
        if ggufs:
            print(f"  [✓] Found {len(ggufs)} .gguf model(s).")
        else:
            print("  [!] Warning: No .gguf models found in the models/ directory.")
    else:
        print("  [!] Warning: models/ directory does not exist.")

    print("Pre-flight checks complete.")

if __name__ == "__main__":
    main()
