#!/usr/bin/env bash
set -euo pipefail

########################################
# REQUEST CONFIG
########################################
HOST="iaas.${REGION}.oraclecloud.com"
REQUEST_PATH="/20160918/instances/"
URL="https://${HOST}${REQUEST_PATH}"

########################################
# REQUEST BODY
########################################
read -r -d '' BODY <<'EOF' || true
{
  "availabilityDomain": "Rsne:AP-HYDERABAD-1-AD-1",
  "compartmentId": "ocid1.tenancy.oc1..aaaaaaaaalw45rwaoyr2sekvamokna3pupldvjaho6rne2l2vq34wug4kj2a",
  "metadata": {
    "ssh_authorized_keys": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDBHf8AuoEpuJxuCYwyY+bytCFph9Mid8iup1kSgTJRwV2/dC0OLK+PVS311nuvXzbJu2By5SaVF8TAo04d6N9PUiQfX9IITuWv433GqgutXmxPEJaCSOi6Wyo3XR1SwaxjN4Ct7eAoeTdQ1yFBH09dFncAsftvrFZ/dXQBgrDAc7fLjuIdvDkByotW3ov9cCEm6JIbt803gCimMLyONDOtdGnfmbqVSTOgGT+3WETtXtUB92TudRe+Y+WmdGVX7UDxNhIUwdl4eaSIcSHGmBRbOfq7mDVrjhLFYAjs2DIPWLVmrEQQAOxE4k3hs99ulEQ8C66cF16zP7slUISKzWiHpDPSiJWfvIx2bT3KPOcz3Jt6Me8MTEQ1FyArMAfCVDNQNMK+Qne+kmFEgPwCKgKbG6nSv3whp/z/6v7Fkl8hc4XP4MRMATDIPGa9RWzrP+WShi72SqoMnLQHVzVwBS0dHchnts+Bhqi7jRj1KZF1gFbQcsPtdIGzzjboJwKWWuM= ashwinikumar@Ashwinis-MacBook-Air.local"
  },
  "displayName": "linux-101",
  "sourceDetails": {
    "sourceType": "image",
    "imageId": "ocid1.image.oc1.ap-hyderabad-1.aaaaaaaawopfq3yveo6yzebrlqiqpcghoae25xo5hv3yi7wwma4z72m6s67q"
  },
  "shape": "VM.Standard.A1.Flex",
  "shapeConfig": {
    "ocpus": 4,
    "memoryInGBs": 24
  },
  "createVnicDetails": {
    "assignPublicIp": false,
    "subnetId": "ocid1.subnet.oc1.ap-hyderabad-1.aaaaaaaa7p2kogfulh3ooxlxear6ahtn54zdebsefueshhh7zepke3mx6via",
    "assignPrivateDnsRecord": true,
    "assignIpv6Ip": false
  },
  "isPvEncryptionInTransitEnabled": true,
  "instanceOptions": {
    "areLegacyImdsEndpointsDisabled": false
  }
}
EOF

CONTENT_LENGTH=$(printf "%s" "$BODY" | wc -c | tr -d ' ')
BODY_HASH=$(printf "%s" "$BODY" \
  | openssl dgst -binary -sha256 \
  | openssl base64 -A)

MAX_RETRIES=500
SLEEP_SECONDS=10
ATTEMPT=1

while true; do

  ########################################
  # REGENERATE DATE + SIGNATURE (CRITICAL)
  ########################################
  DATE=$(LC_ALL=C TZ=GMT date -u "+%a, %d %b %Y %H:%M:%S GMT")

  STRING_TO_SIGN="date: ${DATE}
(request-target): post ${REQUEST_PATH}
host: ${HOST}
content-length: ${CONTENT_LENGTH}
content-type: application/json
x-content-sha256: ${BODY_HASH}"

  : "${PRIVATE_KEY:?Missing PRIVATE_KEY}"

  PRIVATE_KEY_FILE="$(mktemp)"
  printf "%s\n" "$PRIVATE_KEY" > "$PRIVATE_KEY_FILE"
  chmod 600 "$PRIVATE_KEY_FILE"

  SIGNATURE=$(printf "%s" "$STRING_TO_SIGN" \
    | openssl dgst -sha256 -sign "$PRIVATE_KEY_FILE" \
    | openssl base64 -A)

  trap 'rm -f "$PRIVATE_KEY_FILE"' EXIT  

  KEY_ID="${TENANCY_OCID}/${USER_OCID}/${FINGERPRINT}"
  AUTH_HEADER="Signature keyId=\"${KEY_ID}\",algorithm=\"rsa-sha256\",headers=\"date (request-target) host content-length content-type x-content-sha256\",signature=\"${SIGNATURE}\""

  ########################################
  # CURL CALL
  ########################################
  RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$URL" \
    -H "Date: $DATE" \
    -H "Host: $HOST" \
    -H "Content-Type: application/json" \
    -H "Content-Length: $CONTENT_LENGTH" \
    -H "x-content-sha256: $BODY_HASH" \
    -H "Authorization: $AUTH_HEADER" \
    --data-raw "$BODY")

  HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE" | cut -d: -f2)
  BODY_RESPONSE=$(echo "$RESPONSE" | sed '/HTTP_CODE/d')

  ########################################
  # RESPONSE HANDLING
  ########################################
  if [[ "$HTTP_CODE" -eq 429 ]]; then
    echo "Attempt #$ATTEMPT: ⚠️ TooManyRequests"
    echo "$BODY_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$BODY_RESPONSE"
  elif [[ "$HTTP_CODE" -eq 401 ]]; then
    echo "Attempt #$ATTEMPT: ❌ Unauthorized (signature/date issue)"
    echo "$BODY_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$BODY_RESPONSE"
  elif [[ "$HTTP_CODE" -eq 500 ]] && grep -qi "Out of host capacity" <<< "$BODY_RESPONSE"; then
    echo "Attempt #$ATTEMPT: ⚠️ Out of host capacity"
  elif [[ "$HTTP_CODE" -eq 500 ]]; then
    echo "Attempt #$ATTEMPT: ❌ Internal server error"
    echo "$BODY_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$BODY_RESPONSE"
  else
    echo "Attempt #$ATTEMPT: ✅ Success or non-retryable response"
    echo "$BODY_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$BODY_RESPONSE"
    break
  fi

  if [[ "$ATTEMPT" -ge "$MAX_RETRIES" ]]; then
    echo "Attempt #$ATTEMPT: ❌ Max retries reached"
    exit 1
  fi

  ATTEMPT=$((ATTEMPT + 1))
  sleep "$SLEEP_SECONDS"
done
