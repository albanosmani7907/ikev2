#!/usr/bin/env bash
# setup_ikev2.sh - strongSwan IKEv2 (EAP-MSCHAPv2) VPN gateway
# Road-warrior access for the Iran WAN client (10.10.0.0/24 pool).
#
# Fixes vs the original draft (strongSwan 5.9+ swanctl semantics):
#   - local_ts/remote_ts/esp_proposals BELONG in a children { } block, not at
#     connection level.
#   - remote block uses auth = eap-mschapv2 with eap_id = %any.
#   - child SA: local_ts = 0.0.0.0/0, remote_ts = dynamic, explicit ESP proposals.
#
# Run:  sudo bash setup_ikev2.sh
set -eu

echo "==> [1/4] Generating CA + server certificate (if not present)..."
mkdir -p /etc/swanctl/x509ca /etc/swanctl/x509 /etc/swanctl/private
cd /etc/swanctl

if [ ! -f x509ca/ca.crt ]; then
    # RSA 4096 CA
    pki --gen --type rsa --size 4096 --outform pem > ca.key
    pki --self --ca --lifetime 3650 --in ca.key --type rsa \
        --dn "CN=eov IKEv2 CA" --outform pem > ca.crt

    # RSA 2048 server cert, SAN = FQDN + IP, serverAuth only
    pki --gen --type rsa --size 2048 --outform pem > server.key
    pki --pub --in server.key --type rsa | \
        pki --issue --lifetime 1825 --cacert ca.crt --cakey ca.key \
            --dn "CN=ec2-3-145-12-131.us-east-2.compute.amazonaws.com" \
            --san ec2-3-145-12-131.us-east-2.compute.amazonaws.com \
            --san 3.145.12.131 \
            --flag serverAuth \
            --outform pem > server.crt

    mv ca.crt x509ca/
    mv server.crt x509/
    mv server.key private/
    chmod 600 ca.key private/*
fi

echo "==> [2/4] Generating EAP-MSCHAPv2 password for user 'ZHMh54'..."
if [ -f /root/ikev2-ZHMh54.txt ]; then
    IKEPASS=$(grep -oP '(?<=PASS=).*' /root/ikev2-ZHMh54.txt)
else
    IKEPASS=$(openssl rand -hex 12)
fi
echo "PASS=$IKEPASS" > /root/ikev2-ZHMh54.txt
chmod 600 /root/ikev2-ZHMh54.txt

echo "==> [3/4] Writing swanctl configuration (conf.d/ikev2.conf)..."
cat > /etc/swanctl/conf.d/ikev2.conf <<EOF
connections {
    ikev2-eap {
        version = 2
        proposals = aes256gcm16-prfsha384-ecp384, chacha20poly1305-prfsha384-ecp384, aes256gcm16-prfsha384-modp2048
        local {
            auth = pubkey
            certs = server.crt
            id = ec2-3-145-12-131.us-east-2.compute.amazonaws.com
        }
        remote {
            auth = eap-mschapv2
            eap_id = %any
        }
        pools = vpnpool
        fragmentation = yes
        dpd_delay = 30s
        children {
            child-eap {
                local_ts = 0.0.0.0/0
                remote_ts = dynamic
                esp_proposals = aes256gcm16-ecp384, chacha20poly1305-ecp384, aes256gcm16-modp2048
            }
        }
    }
}
pools {
    vpnpool {
        addrs = 10.10.0.0/24
        dns = 1.1.1.1, 8.8.8.8
    }
}
secrets {
    eap-ZHMh54 {
        id = ZHMh54
        secret = "${IKEPASS}"
    }
}
EOF

echo "==> [4/4] Loading config and restarting strongswan-starter..."
chown -R root:root /etc/swanctl
chmod -R 700 /etc/swanctl/private

swanctl --load-all --noprompt 2>&1 | tee /tmp/swanctl-load.log | grep -v TPM || true
if grep -Ei 'error|fatal' /tmp/swanctl-load.log; then
    echo "ERROR: swanctl failed to load the configuration (see errors above)."
    exit 1
fi
systemctl restart strongswan-starter
sleep 2

echo ""
echo "--- swanctl --list-certs ---"
swanctl --list-certs 2>/dev/null | head -6

echo ""
echo "--- UDP listeners on 500/4500 ---"
ss -ulnp | grep -E ':(500|4500)\b' | head -2 || echo "NO_UDP_LISTEN"

echo ""
echo "--- swanctl --list-conns ---"
swanctl --list-conns

echo ""
echo "IKEv2 server config complete."
echo "EAP-MSCHAPv2 credentials (user ZHMh54):"
grep -H PASS /root/ikev2-ZHMh54.txt
echo ""
echo "NEXT STEPS (AWS Console):"
echo "  1. VPC -> Security Groups -> <server security group>"
echo "     Add inbound rules (destination: server IP / the SG itself):"
echo "       - UDP 500   (IKE)"
echo "       - UDP 4500  (NAT traversal)"
echo "       - ESP (protocol 50)  (IPsec tunnel - recommended by AWS for S2S/IKEv2)"
echo "  2. Wait for the Security Group to propagate, then restart strongswan-starter:"
echo "       sudo systemctl restart strongswan-starter"
echo "  3. From the Iran WAN (10.10.0.0/24 client):"
echo "       ping 10.10.0.1     # or use the client VPN app"
echo "       swanctl --list-sas # verify established IKEv2 SAS"
