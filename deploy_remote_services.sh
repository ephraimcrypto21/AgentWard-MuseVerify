#!/usr/bin/env bash
# ==============================================================================
# Deploy Production Systemd Services for AgentWard & MuseVerify on Remote Node
# Target Host: Lightsail Node (ubuntu@100.67.189.89 or ubuntu@68.210.201.104)
# ==============================================================================
set -euo pipefail

# Ensure script is run with root / sudo privileges
if [[ $EUID -ne 0 ]]; then
   echo "[!] This deployment script must be run as root (e.g. sudo bash deploy_remote_services.sh)"
   exit 1
fi

APP_DIR="/home/ubuntu/agentward-node"
USER_NAME="ubuntu"

echo "======================================================================"
echo "[*] Setting up Persistent Systemd Daemons in: ${APP_DIR}"
echo "======================================================================"

if [[ ! -d "${APP_DIR}" ]]; then
    echo "[!] Application directory ${APP_DIR} does not exist. Creating..."
    mkdir -p "${APP_DIR}"
    chown -R ${USER_NAME}:${USER_NAME} "${APP_DIR}"
fi

# Locate virtual environment and uvicorn executable
VENV_PATH="${APP_DIR}/venv"
if [[ ! -d "${VENV_PATH}" ]]; then
    if [[ -d "${APP_DIR}/.venv" ]]; then
        VENV_PATH="${APP_DIR}/.venv"
    elif [[ -d "/home/ubuntu/venv" ]]; then
        VENV_PATH="/home/ubuntu/venv"
    else
        echo "[*] Virtual environment not found. Creating virtualenv at ${VENV_PATH}..."
        python3 -m venv "${VENV_PATH}"
        chown -R ${USER_NAME}:${USER_NAME} "${VENV_PATH}"
    fi
fi

UVICORN_BIN="${VENV_PATH}/bin/uvicorn"
if [[ ! -f "${UVICORN_BIN}" ]]; then
    echo "[*] Installing uvicorn into ${VENV_PATH}..."
    sudo -u ${USER_NAME} "${VENV_PATH}/bin/pip" install uvicorn fastapi
fi

echo "[+] Using Virtualenv: ${VENV_PATH}"
echo "[+] Using Uvicorn:    ${UVICORN_BIN}"

# ------------------------------------------------------------------------------
# 1. /etc/systemd/system/agentward-ingress.service (Port 8000)
# ------------------------------------------------------------------------------
echo "[*] Generating /etc/systemd/system/agentward-ingress.service..."
cat <<EOF > /etc/systemd/system/agentward-ingress.service
[Unit]
Description=AgentWard Ingress Prompt-Guard Service (Stage 1)
After=network.target

[Service]
Type=simple
User=${USER_NAME}
Group=${USER_NAME}
WorkingDirectory=${APP_DIR}
Environment="PATH=${VENV_PATH}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
Environment="PYTHONUNBUFFERED=1"
ExecStart=${UVICORN_BIN} ingress_server:app --host 0.0.0.0 --port 8000 --workers 1
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# ------------------------------------------------------------------------------
# 2. /etc/systemd/system/museverify-sandbox.service (Port 8001)
# ------------------------------------------------------------------------------
echo "[*] Generating /etc/systemd/system/museverify-sandbox.service..."
cat <<EOF > /etc/systemd/system/museverify-sandbox.service
[Unit]
Description=MuseVerify Docker Sandbox Execution Service (Stage 2)
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=${USER_NAME}
Group=${USER_NAME}
WorkingDirectory=${APP_DIR}
Environment="PATH=${VENV_PATH}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
Environment="PYTHONUNBUFFERED=1"
ExecStart=${UVICORN_BIN} sandbox_server:app --host 0.0.0.0 --port 8001 --workers 1
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# ------------------------------------------------------------------------------
# 3. Reload systemd, enable daemons, and restart
# ------------------------------------------------------------------------------
echo "[*] Reloading systemd daemon..."
systemctl daemon-reload

echo "[*] Enabling systemd services on boot..."
systemctl enable agentward-ingress.service
systemctl enable museverify-sandbox.service

echo "[*] Restarting services..."
systemctl restart agentward-ingress.service
systemctl restart museverify-sandbox.service

echo "[*] Checking service status..."
sleep 2

systemctl is-active --quiet agentward-ingress.service && \
    echo "  [✓] agentward-ingress.service is RUNNING (Port 8000)" || \
    echo "  [✗] agentward-ingress.service failed to start. Run: journalctl -u agentward-ingress.service -n 50"

systemctl is-active --quiet museverify-sandbox.service && \
    echo "  [✓] museverify-sandbox.service is RUNNING (Port 8001)" || \
    echo "  [✗] museverify-sandbox.service failed to start. Run: journalctl -u museverify-sandbox.service -n 50"

echo ""
echo "======================================================================"
echo "[+] Remote service deployment complete!"
echo "======================================================================"
