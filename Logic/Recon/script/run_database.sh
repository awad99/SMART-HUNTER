#!/bin/bash
if [ "$1" == "connect" ]; then
    echo "[*] Connecting to database..."
    psql -h 127.0.0.1 -U postgres -d smart_hunter -W
else
    echo "[*] Starting PostgreSQL Database..."
    sudo service postgresql start
    sudo systemctl start postgresql 2>/dev/null || true
    echo "[+] PostgreSQL started."
fi
