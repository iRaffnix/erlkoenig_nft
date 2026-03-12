#!/bin/bash
set -e

# Kill old processes
pkill -9 -f beam 2>/dev/null || true
pkill -9 epmd 2>/dev/null || true
sleep 2

# Write the run script
cat > /opt/erlkoenig_nft/bin/erlkoenig_nft_run << 'RUNEOF'
#!/bin/sh
ROOTDIR=/opt/erlkoenig_nft
REL_VSN=$(cat "$ROOTDIR/releases/start_erl.data" | cut -d' ' -f2)
ERTS_VSN=$(cat "$ROOTDIR/releases/start_erl.data" | cut -d' ' -f1)
exec "$ROOTDIR/erts-$ERTS_VSN/bin/erl" -boot "$ROOTDIR/releases/$REL_VSN/start" -mode embedded -boot_var SYSTEM_LIB_DIR "$ROOTDIR/lib" -config "$ROOTDIR/releases/$REL_VSN/sys.config" -args_file "$ROOTDIR/releases/$REL_VSN/vm.args" -noinput
RUNEOF
chmod +x /opt/erlkoenig_nft/bin/erlkoenig_nft_run

# Fix vm.args
cat > /opt/erlkoenig_nft/releases/0.4.0/vm.args << 'VMEOF'
-setcookie erlkoenig_nft_default
+sbwt very_short
VMEOF

# Update systemd service
cat > /etc/systemd/system/erlkoenig_nft.service << 'SVCEOF'
[Unit]
Description=Erlkoenig nf_tables firewall
After=network.target

[Service]
Type=simple
Environment=HOME=/opt/erlkoenig_nft
ExecStart=/opt/erlkoenig_nft/bin/erlkoenig_nft_run
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SVCEOF

# Reload and start
systemctl daemon-reload
systemctl enable --now erlkoenig_nft
sleep 3
systemctl status erlkoenig_nft --no-pager
echo ""
echo "Testing socket API..."
echo '{"cmd":"status"}' | socat - UNIX-CONNECT:/var/run/erlkoenig.sock 2>&1 || echo "Socket not ready yet, wait a moment and try: echo '{\"cmd\":\"status\"}' | socat - UNIX-CONNECT:/var/run/erlkoenig.sock"
