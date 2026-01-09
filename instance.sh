#!/usr/bin/env bash
set -euo pipefail

########################################
# REQUEST CONFIG
########################################
HOST="iaas.${REGION}.oraclecloud.com"
METHOD="POST"
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

########################################
# PARSE URL (matching PHP parse_url behavior)
########################################
# Extract path and host from URL
# PHP parse_url returns: ['scheme' => 'https', 'host' => 'iaas...', 'path' => '/20160918/instances/']
URI_PATH="$REQUEST_PATH"
# If there's a query string, it would be appended here (none in this case)

########################################
# DATE (matching PHP gmdate(DATE_RFC7231))
# PHP DATE_RFC7231 format: "D, d M Y H:i:s \G\M\T"
# Example: "Wed, 07 Jan 2026 20:38:29 GMT"
########################################
DATE=$(LC_ALL=C TZ=GMT date -u "+%a, %d %b %Y %H:%M:%S GMT")

########################################
# CONTENT LENGTH (matching PHP strlen($body))
# strlen() returns byte length
########################################
CONTENT_LENGTH=$(printf "%s" "$BODY" | wc -c | tr -d ' ')

########################################
# BODY HASH (matching PHP getBodyHashBase64)
# PHP: hash('sha256', $body, true) then base64_encode()
# The 'true' parameter means binary output
########################################
BODY_HASH=$(printf "%s" "$BODY" \
  | openssl dgst -binary -sha256 \
  | openssl base64 -A)

########################################
# BUILD HEADERS TO SIGN (matching PHP getHeadersToSign)
# Order: date, (request-target), host, content-length, content-type, x-content-sha256
########################################
METHOD_LOWER=$(echo "$METHOD" | tr '[:upper:]' '[:lower:]')

# Build headers map exactly as PHP does
# PHP: $headersMap[self::SIGNING_HEADER_DATE] = $dateString;
HEADER_DATE="$DATE"

# PHP: $headersMap[self::SIGNING_HEADER_REQUEST_TARGET] = strtolower($method) . " $uri";
HEADER_REQUEST_TARGET="${METHOD_LOWER} ${URI_PATH}"

# PHP: $headersMap[self::SIGNING_HEADER_HOST] = $parsed['host'] ?? '';
HEADER_HOST="$HOST"

# PHP: $headersMap[self::SIGNING_HEADER_CONTENT_LENGTH] = $contentLength;
HEADER_CONTENT_LENGTH="$CONTENT_LENGTH"

# PHP: $headersMap[self::SIGNING_HEADER_CONTENT_TYPE] = $contentType;
HEADER_CONTENT_TYPE="application/json"

# PHP: $headersMap[self::SIGNING_HEADER_X_CONTENT_SHA256] = $bodyHashBase64;
HEADER_X_CONTENT_SHA256="$BODY_HASH"

########################################
# BUILD SIGNING STRING (matching PHP getSigningString)
# PHP: foreach ($headersToSign as $header => $value) {
#       $signingHeaders[] = "$header: $value";
#      }
#      return implode("\n", $signingHeaders);
# Note: implode("\n", ...) joins with newlines but NO trailing newline
########################################
STRING_TO_SIGN="date: ${HEADER_DATE}
(request-target): ${HEADER_REQUEST_TARGET}
host: ${HEADER_HOST}
content-length: ${HEADER_CONTENT_LENGTH}
content-type: ${HEADER_CONTENT_TYPE}
x-content-sha256: ${HEADER_X_CONTENT_SHA256}"

########################################
# CALCULATE SIGNATURE (matching PHP calculateSignature)
# PHP: openssl_sign($signingString, $binarySignature, $privateKeyId, OPENSSL_ALGO_SHA256)
#      then base64_encode($binarySignature)
# openssl dgst -sha256 -sign is equivalent to openssl_sign with OPENSSL_ALGO_SHA256
########################################
: "${PRIVATE_KEY:?Missing PRIVATE_KEY}"

PRIVATE_KEY_FILE="$(mktemp)"
printf "%s\n" "$PRIVATE_KEY" > "$PRIVATE_KEY_FILE"
chmod 600 "$PRIVATE_KEY_FILE"

SIGNATURE=$(printf "%s" "$STRING_TO_SIGN" \
  | openssl dgst -sha256 -sign "$PRIVATE_KEY_FILE" \
  | openssl base64 -A)

trap 'rm -f "$PRIVATE_KEY_FILE"' EXIT

########################################
# BUILD AUTHORIZATION HEADER
# Note: version="1" is not required by OCI API
# $signedHeaders = implode(' ', array_keys($headersToSign))
# Order: date (request-target) host content-length content-type x-content-sha256
########################################
KEY_ID="${TENANCY_OCID}/${USER_OCID}/${FINGERPRINT}"
SIGNED_HEADERS="date (request-target) host content-length content-type x-content-sha256"
AUTH_HEADER="Signature keyId=\"${KEY_ID}\",algorithm=\"rsa-sha256\",headers=\"${SIGNED_HEADERS}\",signature=\"${SIGNATURE}\""

########################################
# CALL OCI API
# Note: PHP doesn't send (request-target) as an actual header
# PHP: if ($headerName === self::SIGNING_HEADER_REQUEST_TARGET) { continue; }
########################################

MAX_RETRIES=50
SLEEP_SECONDS=5
ATTEMPT=1

while true; do
  echo "Attempt #$ATTEMPT..."

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

  echo "HTTP Status Code: $HTTP_CODE"
  echo "Response Body:"
  # Pretty-print JSON if possible
  echo "$BODY_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$BODY_RESPONSE"

  # Retry ONLY if keyword is present
  if echo "$BODY_RESPONSE" | grep -qi "Out of host capacity"; then
    echo "⚠️  Out of host capacity detected."
  else
    echo "✅ No capacity error. Exiting loop."
    break
  fi

  if [[ "$ATTEMPT" -ge "$MAX_RETRIES" ]]; then
    echo "❌ Max retries ($MAX_RETRIES) reached. Exiting."
    exit 1
  fi

  echo "⏳ Retrying in $SLEEP_SECONDS seconds..."
  ATTEMPT=$((ATTEMPT + 1))
  sleep "$SLEEP_SECONDS"
done
