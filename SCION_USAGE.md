# SCION Usage Guide for `wireguard-go`

This guide explains how to configure and operate a custom `wireguard-go` instance with SCION support, including key setup, peer configuration, and SCION path management.

---

## Prerequisites

* `wireguard-go` compiled with SCION support
* Access to a running SCION infrastructure and `sciond`
* `socat` utility installed (`apt install socat` or equivalent)
* Peer public keys **must be exchanged beforehand**

---

## Environment Variables

Before launching `wireguard-go`, set:

* `USE_SCION=1`: Enables SCION support
* `USE_BATCH=1`: Enables batch mode for Linux and Android (default: `0`)
* `SCION_LOCAL_IA`: Your local SCION ISD-AS (e.g., `1-ffaa:0:1`); optional if `sciond` provides it
* `SCION_DAEMON_ADDR`: SCION daemon address; optional (default: `127.0.0.1:30255`)

---

## Notes

* Use `socat` instead of `wg` to interact with the UAPI socket for SCION configurations.
* Listen ports must be in SCION's dispatch range (default: `31000–32767`)
* Set MTU to `1280` to accommodate SCION headers.
* Peer public keys should be stored in files (e.g., `peer.key`)

---

## Key Generation

```bash
# Generate key pair
wg genkey > private.key
wg pubkey < private.key > public.key

# Exchange public keys with your peer and save theirs as peer.key
```

---

## Example Setup Scripts

### Endpoint 1 (ISD-AS: 1-ffaa:0:1)

```bash
#!/bin/bash
# endpoint1-setup.sh

INTERFACE=wg0
UAPI_SOCKET="/var/run/wireguard/${INTERFACE}.sock"
ADDRESS="10.78.0.1/24"
LISTEN_PORT=32000

# Generate keys if missing
if [ ! -f private.key ]; then
    wg genkey > private.key
    wg pubkey < private.key > public.key
fi

PRIVATE_KEY_HEX=$(base64 -d private.key | xxd -p -c 256)
PEER_PUBLIC_KEY_HEX=$(base64 -d peer.key | xxd -p -c 256)

# Start wireguard-go
sudo  USE_SCION=1 USE_BATCH=1 ./wireguard-go $INTERFACE

# Configure interface
sudo ip address add "$ADDRESS" dev "$INTERFACE"
sudo ip link set up dev "$INTERFACE"
sudo ip link set mtu 1280 dev "$INTERFACE"

cat << EOF | sudo socat - UNIX-CONNECT:"$UAPI_SOCKET"
set=1
private_key=$PRIVATE_KEY_HEX
listen_port=32000
EOF

# Peer config (with set=1)
cat << EOF | sudo socat - UNIX-CONNECT:"$UAPI_SOCKET"
set=1
public_key=$PEER_PUBLIC_KEY_HEX
allowed_ip=10.78.0.2/32
EOF
```

---

### Endpoint 2 (ISD-AS: 1-ffaa:0:2)

```bash
#!/bin/bash
# endpoint2-setup.sh

INTERFACE=wg0
UAPI_SOCKET="/var/run/wireguard/${INTERFACE}.sock"
ADDRESS="10.78.0.2/24"
LISTEN_PORT=32000

# Generate keys if missing
if [ ! -f private.key ]; then
    wg genkey > private.key
    wg pubkey < private.key > public.key
fi

PRIVATE_KEY_HEX=$(base64 -d private.key | xxd -p -c 256)
PEER_PUBLIC_KEY_HEX=$(base64 -d peer.key | xxd -p -c 256)

# Start wireguard-go
sudo  USE_SCION=1 USE_BATCH=1 ./wireguard-go $INTERFACE

# Configure interface
sudo ip address add "$ADDRESS" dev "$INTERFACE"
sudo ip link set up dev "$INTERFACE"
sudo ip link set mtu 1280 dev "$INTERFACE"

cat << EOF | sudo socat - UNIX-CONNECT:"$UAPI_SOCKET"
set=1
private_key=$PRIVATE_KEY_HEX
listen_port=32000
EOF

# Peer config (with set=1)
cat << EOF | sudo socat - UNIX-CONNECT:"$UAPI_SOCKET"
set=1
public_key=$PEER_PUBLIC_KEY_HEX
allowed_ip=10.78.0.0/24
scion_endpoint=1-ffaa:0:1,[127.0.0.1]:32000
persistent_keepalive_interval=25
EOF
```

---

## SCION Path Management

### Available Path Policies

```
"shortest"  (default)
"bandwidth" 
"latency"  
"first"
```

These metrics are drived from the path metadata for now.

#### Example: Set Path Policy to Lowest Latency

```bash
cat << EOF | socat - UNIX-CONNECT:"$UAPI_SOCKET"
set=1
scion_path_policy=latency
EOF
```

## Path Manager HTTP API

The SCION Path Manager exposes an HTTP API for querying and managing paths.
If enabled, it typically listens on `http://localhost:28015` (with fallbacks to 28016, 28017 if the default is in use).

### 1. Get Available Paths

Retrieves available paths to a specified SCION ISD-AS in JSON format.

*   **Endpoint:** `GET /paths`
*   **Query Parameter:** `ia=<isd-as_string>` (e.g., `ia=1-ff00:0:110`)

*   **Example `curl` command:**
    ```bash
    curl -X GET "http://localhost:28015/paths?ia=1-ff00:0:110"
    ```

*   **Example Successful Response:**
    ```json
    {
      "local_isd_as": "1-ff00:0:112",
      "destination": "1-ff00:0:110",
      "paths": [
        {
          "index": 0,
          "fingerprint": "somefingerprint1",
          "hops": [
            { "ifid": 1, "isd_as": "1-ff00:0:112" },
            { "ifid": 2, "isd_as": "1-ff00:0:1" },
            { "ifid": 3, "isd_as": "1-ff00:0:110" }
          ],
          "sequence": "1-ff00:0:112#1 > 1-ff00:0:1#2 ; 1-ff00:0:1#3 > 1-ff00:0:110#0",
          "next_hop": "192.168.1.1:30041",
          "expiry": "2023-10-27T10:00:00Z",
          "mtu": 1472,
          "latency": [10, 5, 12],
          "bandwidth": [1000000, 900000, 1000000],
          "status": "alive",
          "local_ip": "1-ff00:0:112"
        }
      ]
    }
    ```

### 2. Set Active Path

Manually selects a specific path to be used for a destination IA.

*   **Endpoint:** `POST /path`
*   **Request Body (JSON):**
    ```json
    {
      "ia": "<isd-as_string>",
      "path_index": <integer_index_from_get_paths>
    }
    ```

*   **Example `curl` command:**
    ```bash
    curl -X POST -H "Content-Type: application/json" \
    -d '{"ia": "1-ff00:0:110", "path_index": 0}' \
    "http://localhost:28015/path"
    ```

*   **Expected Successful Response:**
    *   HTTP Status Code: `200 OK`
    *   Response Body: `Path successfully set`

---


