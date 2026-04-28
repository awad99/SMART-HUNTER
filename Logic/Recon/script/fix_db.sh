#!/bin/bash
echo "[*] Setting postgres password to 2002..."
sudo -u postgres psql -c "ALTER USER postgres PASSWORD '2002';"
echo "[*] Restarting postgresql service..."
sudo service postgresql restart
echo "[+] Done! You can now run: python setup_db.py"
