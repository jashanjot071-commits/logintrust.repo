#!/usr/bin/env bash

set -uo pipefail

# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION & DEFAULTS
# ══════════════════════════════════════════════════════════════════════════════
VT_API_KEY="${VT_API_KEY:-}"
GSB_API_KEY="${GSB_API_KEY:-}"
ABUSEIPDB_KEY="${ABUSEIPDB_KEY:-}"
SHODAN_KEY="${SHODAN_KEY:-}"

BANNER_VERSION="4.0"
MAX_RAW=30
COMMON_PORTS="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,6379,8080,8443,8888,27017"

# ══════════════════════════════════════════════════════════════════════════════
# OS DETECTION
# ══════════════════════════════════════════════════════════════════════════════
detect_os() {
  case "$(uname -s 2>/dev/null || echo 'Windows')" in
    Linux*)               echo "linux" ;;
    Darwin*)              echo "macos" ;;
    CYGWIN*|MINGW*|MSYS*) echo "windows" ;;
    *)                    echo "unknown" ;;
  esac
}
OS=$(detect_os)

get_date_seconds() {
  local d="$1"
  if [[ "$OS" == "macos" ]]; then
    date -j -f "%Y-%m-%d" "$d" "+%s" 2>/dev/null || echo "0"
  else
    date -d "$d" +%s 2>/dev/null || echo "0"
  fi
}
NOW_SEC=$(date +%s 2>/dev/null || echo "0")
DATE=$(date +"%Y%m%d_%H%M%S" 2>/dev/null || echo "scan_$$")

# ══════════════════════════════════════════════════════════════════════════════
# COLORS
# ══════════════════════════════════════════════════════════════════════════════
if [ -t 1 ] && [[ "$OS" != "windows" ]]; then
  RED="\033[0;31m";     GREEN="\033[0;32m";   YELLOW="\033[1;33m"
  CYAN="\033[0;36m";    BOLD="\033[1m";        DIM="\033[2m"
  MAGENTA="\033[0;35m"; ORANGE="\033[38;5;208m"; RESET="\033[0m"
  BLUE="\033[0;34m";    WHITE="\033[1;37m"
else
  RED=""; GREEN=""; YELLOW=""; CYAN=""; BOLD=""
  DIM=""; MAGENTA=""; ORANGE=""; RESET=""; BLUE=""; WHITE=""
fi

# ══════════════════════════════════════════════════════════════════════════════
# ARGUMENT PARSING
# ══════════════════════════════════════════════════════════════════════════════
TARGET=""
OUTPUT_JSON=false
SILENT=false
VERBOSE=false
DEEP_SCAN=false
PORT_SCAN=false
BRUTE_SURFACE=false
API_TEST=false
OFFLINE_MODE=false
FILE_MODE=false
NETWORK_MODE=false
NO_REPORT=false

for arg in "$@"; do
  case "$arg" in
    --json)       OUTPUT_JSON=true ;;
    --silent)     SILENT=true ;;
    --verbose)    VERBOSE=true ;;
    --deep)       DEEP_SCAN=true ;;
    --ports)      PORT_SCAN=true ;;
    --brute)      BRUTE_SURFACE=true ;;
    --api-test)   API_TEST=true ;;
    --offline)    OFFLINE_MODE=true ;;
    --file)       FILE_MODE=true ;;
    --network)    NETWORK_MODE=true ;;
    --no-report)  NO_REPORT=true ;;
    http*|ftp*)   TARGET="$arg" ;;
    /*)           TARGET="$arg"; FILE_MODE=true ;;
    *)            [ -z "$TARGET" ] && TARGET="$arg" ;;
  esac
done

if [ -z "$TARGET" ]; then
  cat <<'USAGE'
╔══════════════════════════════════════════════════════════════════╗
║            Login Trust — Universal Security Scanner              ║
╚══════════════════════════════════════════════════════════════════╝

  Online  : ./webscan_pro.sh https://example.com
  Offline : ./webscan_pro.sh 192.168.1.10 --offline
  File    : ./webscan_pro.sh /path/to/index.html --file
  Network : ./webscan_pro.sh 192.168.1.0/24 --network

  Options:
    --json        JSON output
    --silent      Suppress console output
    --verbose     Detailed progress
    --deep        Deep/slow scan (more thorough)
    --ports       Enable port scanning
    --brute       Brute-force surface detection
    --api-test    API endpoint security testing
    --no-report   Don't write a report file

  API Keys (env vars):
    export VT_API_KEY=...       virustotal.com
    export GSB_API_KEY=...      Google Safe Browsing
    export ABUSEIPDB_KEY=...    abuseipdb.com
    export SHODAN_KEY=...       shodan.io

USAGE
  exit 1
fi

# ══════════════════════════════════════════════════════════════════════════════
# DEPENDENCY CHECK
# ══════════════════════════════════════════════════════════════════════════════
check_dep() { command -v "$1" >/dev/null 2>&1; }

CURL_OK=false;    WGET_OK=false;    WHOIS_OK=false;   DIG_OK=false
NMAP_OK=false;    OPENSSL_OK=false; JQ_OK=false;      NC_OK=false
PYTHON3_OK=false; NIKTO_OK=false;   WP_OK=false;      GOBUSTER_OK=false

check_dep curl     && CURL_OK=true     || true
check_dep wget     && WGET_OK=true     || true
check_dep whois    && WHOIS_OK=true    || true
check_dep dig      && DIG_OK=true      || true
check_dep nmap     && NMAP_OK=true     || true
check_dep openssl  && OPENSSL_OK=true  || true
check_dep jq       && JQ_OK=true       || true
check_dep nc       && NC_OK=true       || true
check_dep python3  && PYTHON3_OK=true  || true
check_dep nikto    && NIKTO_OK=true    || true
check_dep wpscan   && WP_OK=true       || true
check_dep gobuster && GOBUSTER_OK=true || true

if [ "$CURL_OK" = false ] && [ "$WGET_OK" = false ] && [ "$FILE_MODE" = false ]; then
  echo -e "${RED}Error: curl or wget is required for network scanning.${RESET}"
  exit 1
fi

# ══════════════════════════════════════════════════════════════════════════════
# HTTP HELPERS
# ══════════════════════════════════════════════════════════════════════════════
BROWSER_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

http_fetch_body() {
  local url="$1" out="$2"
  if [ "$CURL_OK" = true ]; then
    curl -Ls --max-time 25 --max-redirs 15 \
      -A "$BROWSER_UA" \
      -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
      -H "Accept-Language: en-US,en;q=0.5" \
      -H "Connection: keep-alive" \
      --compressed -o "$out" "$url" 2>/dev/null
  else
    wget -q --timeout=25 --tries=2 --user-agent="$BROWSER_UA" -O "$out" "$url" 2>/dev/null
  fi
}

http_fetch_headers() {
  local url="$1" out="$2"
  if [ "$CURL_OK" = true ]; then
    curl -Is --max-time 10 -A "$BROWSER_UA" --max-redirs 10 "$url" > "$out" 2>/dev/null
  else
    wget -q --timeout=10 --server-response -O /dev/null "$url" 2>"$out" || true
  fi
}

http_get_code() {
  local url="$1" code
  if [ "$CURL_OK" = true ]; then
    # curl -w "%{http_code}" always prints a 3-digit code even on failure ("000")
    # so we must NOT add || echo "000" — that would concatenate two codes
    code=$(curl -Ls --max-time 20 -A "$BROWSER_UA" -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)
    echo "${code:-000}"
  else
    code=$(wget -q --timeout=20 --server-response -O /dev/null "$url" 2>&1 \
      | awk '/HTTP\//{print $2}' | tail -1)
    echo "${code:-000}"
  fi
}

http_follow_url() {
  local url="$1" result
  if [ "$CURL_OK" = true ]; then
    result=$(curl -Ls --max-time 20 -A "$BROWSER_UA" -o /dev/null -w "%{url_effective}" "$url" 2>/dev/null) || true
    # Sanity-check: effective URL must start with http/https/ftp
    # curl can return a garbled value when the server doesn't redirect cleanly
    if [[ "$result" =~ ^https?:// ]] || [[ "$result" =~ ^ftp:// ]]; then
      echo "$result"
    else
      echo "$url"
    fi
  else
    echo "$url"
  fi
}

count_redirects() {
  local url="$1"
  if [ "$CURL_OK" = true ]; then
    curl -Ls -o /dev/null --max-time 15 -A "$BROWSER_UA" -w "%{num_redirects}" "$url" 2>/dev/null || echo "0"
  else
    echo "0"
  fi
}

url_encode() {
  if [ "$PYTHON3_OK" = true ]; then
    python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$1" 2>/dev/null
  else
    echo "$1" | sed 's|:|%3A|g;s|/|%2F|g;s|?|%3F|g;s|=|%3D|g;s|&|%26|g'
  fi
}

# ══════════════════════════════════════════════════════════════════════════════
# TEMP FILES
# ══════════════════════════════════════════════════════════════════════════════
TMPDIR_BASE="${TMPDIR:-/tmp}"
PAGE="$TMPDIR_BASE/ws_page_$DATE.html"
HEADERS="$TMPDIR_BASE/ws_hdrs_$DATE.txt"
# FIX: removed unused RESP_BODY2 temp file declaration
cleanup() { rm -f "$PAGE" "$HEADERS" 2>/dev/null; }
trap cleanup EXIT

# ══════════════════════════════════════════════════════════════════════════════
# TARGET RESOLUTION
# ══════════════════════════════════════════════════════════════════════════════
verbose_log() { [ "$VERBOSE" = true ] && echo -e "${DIM}[*] $1${RESET}"; }
status_log()  { [ "$SILENT" = false ] && echo -e "${DIM}$1${RESET}"; }

if [ "$FILE_MODE" = true ]; then
  FINAL_URL="file://$TARGET"
  DOMAIN="localhost"
  BASE_DOMAIN="localhost"
  ROOT_DOMAIN="localhost"
  HTTP_CODE="200"
  if [ -f "$TARGET" ]; then
    cp "$TARGET" "$PAGE"
    PAGE_SIZE=$(wc -c < "$PAGE" | tr -d ' ')
    touch "$HEADERS"
  else
    echo -e "${RED}File not found: $TARGET${RESET}"
    exit 1
  fi
elif [ "$NETWORK_MODE" = true ]; then
  FINAL_URL="network://$TARGET"
  DOMAIN="$TARGET"
  BASE_DOMAIN="$TARGET"
  ROOT_DOMAIN="$TARGET"
  HTTP_CODE="N/A"
  PAGE_SIZE=0
  touch "$PAGE" "$HEADERS"
else
  # Online or offline host
  status_log "Resolving target..."

  # If target looks like an IP or hostname (no http://) in offline mode
  if [[ "$TARGET" != http* ]] && [[ "$TARGET" != ftp* ]]; then
    if [[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [ "$OFFLINE_MODE" = true ]; then
      TARGET="http://$TARGET"
    else
      TARGET="https://$TARGET"
    fi
  fi

  FINAL_URL=$(http_follow_url "$TARGET")
  [ -z "$FINAL_URL" ] && FINAL_URL="$TARGET"

  DOMAIN=$(echo "$FINAL_URL" | sed -E 's#https?://([^/:]*).*#\1#' | tr '[:upper:]' '[:lower:]')
  BASE_DOMAIN=$(echo "$DOMAIN" | sed -E 's/^www\.//')
  # Multi-part ccTLDs (e.g. .com.br, .co.uk, .org.au) need 3 labels for root domain
  if echo "$BASE_DOMAIN" | grep -qiE '\.(com|net|org|gov|edu|co|org|adv|agr|am|arq|art|ato|bio|bmd|cim|cng|cnt|coop|ecn|eco|emp|eng|esp|etc|eti|far|flog|fm|fnd|fot|fst|g12|ggf|imb|ind|inf|jor|jus|leg|lel|mat|med|mil|mp|mus|not|ntr|odo|ppg|pro|psc|psi|pub|qsl|radio|rec|slg|srv|taxi|teo|tmp|trd|tur|tv|vet|vlog|wiki|zlg)\.(br|uk|au|nz|za|jp|in|mx|ar|cl|co|ng|gh|ke|eg|sg|my|ph|id|pe|ec|ve|uy|py|bo|cr|gt|hn|ni|pa|sv|do|cu|pr|tt|jm|bb|bs|bz|gy|sr|ag|dm|gd|kn|lc|vc|hk|tw|cn|kr|ua|pl|cz|sk|hu|ro|bg|hr|si|rs|ba|me|mk|al|lt|lv|ee|by|ge|am|az|kz|uz|kg|tj|tm|af|pk|bd|lk|np|mm|vn|th|kh|la|bn|mn|mo)$'; then
    ROOT_DOMAIN=$(echo "$BASE_DOMAIN" | rev | cut -d. -f1-3 | rev)
  else
    ROOT_DOMAIN=$(echo "$BASE_DOMAIN" | rev | cut -d. -f1-2 | rev)
  fi

  status_log "Fetching page content..."
  HTTP_CODE=$(http_get_code "$FINAL_URL")
  http_fetch_body "$FINAL_URL" "$PAGE"
  http_fetch_headers "$FINAL_URL" "$HEADERS"
  PAGE_SIZE=$([ -f "$PAGE" ] && wc -c < "$PAGE" | tr -d ' ' || echo "0")
fi

REPORT_NAME="scan_${BASE_DOMAIN//\//_}_${DATE}.txt"

# ══════════════════════════════════════════════════════════════════════════════
# SCORING ENGINE
# FIX: explicitly initialise all arrays so `set -u` never sees them as unbound
# ══════════════════════════════════════════════════════════════════════════════
RAW_SCORE=0
SCORE=0
REASONS=()
ATTACK_TYPES=()
CATEGORIES=()
API_FLAGS=()
PORT_RESULTS=()
VULN_DETAILS=()
HEADER_ISSUES=()

score_add() { RAW_SCORE=$(( RAW_SCORE + ${1:-0} )); }

add_reason() { REASONS+=("$1"); }
add_vuln()   { VULN_DETAILS+=("$1"); }

add_attack() {
  local found=false
  for a in "${ATTACK_TYPES[@]:-}"; do [[ "$a" == "$1" ]] && found=true && break; done
  [ "$found" = false ] && ATTACK_TYPES+=("$1")
}

add_category() {
  local found=false
  for c in "${CATEGORIES[@]:-}"; do [[ "$c" == "$1" ]] && found=true && break; done
  [ "$found" = false ] && CATEGORIES+=("$1")
}

PAGE_TEXT=""
if [ -f "$PAGE" ] && [ -s "$PAGE" ]; then
  PAGE_TEXT=$(tr '\n' ' ' < "$PAGE" | sed 's/<[^>]*>/ /g' | tr '[:upper:]' '[:lower:]' | tr -s ' ')
fi

# ══════════════════════════════════════════════════════════════════════════════
# TRUSTED WHITELIST (only for online mode)
# ══════════════════════════════════════════════════════════════════════════════
TRUSTED_LIST=(
  google.com youtube.com gmail.com facebook.com instagram.com whatsapp.com
  messenger.com twitter.com x.com microsoft.com outlook.com live.com
  office.com bing.com apple.com icloud.com amazon.com github.com gitlab.com
  wikipedia.org linkedin.com netflix.com reddit.com dropbox.com zoom.us
  spotify.com adobe.com cloudflare.com stackoverflow.com yahoo.com paypal.com
  ebay.com twitch.tv discord.com telegram.org sbi.co.in hdfcbank.com
  icicibank.com axisbank.com paytm.com flipkart.com mozilla.org ubuntu.com
  virustotal.com phishtank.com nodejs.org python.org golang.org
)

IS_TRUSTED=false
if [ "$OFFLINE_MODE" = false ] && [ "$FILE_MODE" = false ] && [ "$NETWORK_MODE" = false ]; then
  for T in "${TRUSTED_LIST[@]}"; do
    [[ "$ROOT_DOMAIN" == "$T" ]] && IS_TRUSTED=true && break
  done
fi

# ══════════════════════════════════════════════════════════════════════════════
# BRAND MAP
# ══════════════════════════════════════════════════════════════════════════════
declare -A BRAND_ROOTS=(
  [paypal]=paypal.com       [facebook]=facebook.com   [apple]=apple.com
  [microsoft]=microsoft.com [amazon]=amazon.com       [google]=google.com
  [instagram]=instagram.com [netflix]=netflix.com     [hdfc]=hdfcbank.com
  [icici]=icicibank.com     [sbi]=sbi.co.in           [axis]=axisbank.com
  [linkedin]=linkedin.com   [twitter]=twitter.com     [whatsapp]=whatsapp.com
  [yahoo]=yahoo.com         [ebay]=ebay.com           [dropbox]=dropbox.com
  [spotify]=spotify.com     [adobe]=adobe.com         [steam]=steampowered.com
  [github]=github.com       [gitlab]=gitlab.com       [discord]=discord.com
  [twitch]=twitch.tv        [zoom]=zoom.us            [coinbase]=coinbase.com
  [binance]=binance.com     [kraken]=kraken.com       [chase]=chase.com
  [wellsfargo]=wellsfargo.com [bankofamerica]=bankofamerica.com
  [citibank]=citibank.com   [tiktok]=tiktok.com       [snapchat]=snapchat.com
  [paytm]=paytm.com         [flipkart]=flipkart.com   [hotmail]=outlook.com
  [office365]=office.com    [onedrive]=microsoft.com  [skype]=microsoft.com
)

# ══════════════════════════════════════════════════════════════════════════════
# ██  MODULE 1: THREAT INTELLIGENCE APIS  ██
# ══════════════════════════════════════════════════════════════════════════════
VT_POSITIVES=0; VT_SUSPICIOUS_COUNT=0; VT_TOTAL=0
GSB_THREAT=""; PHISHTANK_RESULT=""; ABUSEIPDB_SCORE=0

if [ "$OFFLINE_MODE" = false ] && [ "$FILE_MODE" = false ] && [ "$NETWORK_MODE" = false ]; then

  # ── VirusTotal ──────────────────────────────────────────────────────────────
  if [ -n "$VT_API_KEY" ] && [ "$CURL_OK" = true ]; then
    status_log "Checking VirusTotal..."
    URL_B64=$(echo -n "$FINAL_URL" | base64 | tr '+/' '-_' | tr -d '=')
    VT_RESP=$(curl -s --max-time 15 \
      -H "x-apikey: $VT_API_KEY" \
      "https://www.virustotal.com/api/v3/urls/${URL_B64}" 2>/dev/null || true)

    if [ -n "$VT_RESP" ] && ! echo "$VT_RESP" | grep -q '"error"'; then
      if [ "$JQ_OK" = true ]; then
        VT_POSITIVES=$(echo "$VT_RESP" | jq -r '.data.attributes.last_analysis_stats.malicious // 0' 2>/dev/null || echo "0")
        VT_SUSPICIOUS_COUNT=$(echo "$VT_RESP" | jq -r '.data.attributes.last_analysis_stats.suspicious // 0' 2>/dev/null || echo "0")
        VT_TOTAL=$(echo "$VT_RESP" | jq -r '(.data.attributes.last_analysis_stats | to_entries | map(.value) | add) // 0' 2>/dev/null || echo "0")
      else
        VT_POSITIVES=$(echo "$VT_RESP" | grep -o '"malicious":[0-9]*' | grep -o '[0-9]*' | head -1 || echo "0")
        VT_SUSPICIOUS_COUNT=$(echo "$VT_RESP" | grep -o '"suspicious":[0-9]*' | grep -o '[0-9]*' | head -1 || echo "0")
      fi
      VT_COMBINED=$(( ${VT_POSITIVES:-0} + ${VT_SUSPICIOUS_COUNT:-0} ))
      if   [ "${VT_COMBINED:-0}" -ge 10 ]; then
        add_reason "VirusTotal: $VT_POSITIVES engines MALICIOUS, $VT_SUSPICIOUS_COUNT SUSPICIOUS (/$VT_TOTAL)"
        score_add 15; add_attack "Confirmed Malicious (VirusTotal 90+ AV Engines)"
        add_category "CONFIRMED THREAT"; API_FLAGS+=("VT:MALICIOUS:$VT_POSITIVES/$VT_TOTAL")
      elif [ "${VT_COMBINED:-0}" -ge 3 ]; then
        add_reason "VirusTotal: $VT_POSITIVES malicious + $VT_SUSPICIOUS_COUNT suspicious detections"
        score_add 10; add_attack "Flagged by Multiple AV Engines"
        add_category "HIGH CONFIDENCE THREAT"; API_FLAGS+=("VT:SUSPICIOUS:$VT_POSITIVES/$VT_TOTAL")
      elif [ "${VT_COMBINED:-0}" -ge 1 ]; then
        add_reason "VirusTotal: $VT_POSITIVES/$VT_TOTAL engines flagged this URL"
        score_add 5; add_attack "Flagged by AV Engine"
        add_category "THREAT DETECTED"; API_FLAGS+=("VT:LOW:$VT_POSITIVES/$VT_TOTAL")
      else
        API_FLAGS+=("VT:CLEAN")
      fi
    else
      curl -s --max-time 10 -X POST "https://www.virustotal.com/api/v3/urls" \
        -H "x-apikey: $VT_API_KEY" --data-urlencode "url=$FINAL_URL" >/dev/null 2>&1 || true
      API_FLAGS+=("VT:NOT_IN_DATABASE")
    fi
  fi

  # ── Google Safe Browsing ────────────────────────────────────────────────────
  if [ -n "$GSB_API_KEY" ] && [ "$CURL_OK" = true ]; then
    status_log "Checking Google Safe Browsing..."
    GSB_PAYLOAD="{\"client\":{\"clientId\":\"webscan-pro\",\"clientVersion\":\"4.0\"},\"threatInfo\":{\"threatTypes\":[\"MALWARE\",\"SOCIAL_ENGINEERING\",\"UNWANTED_SOFTWARE\",\"POTENTIALLY_HARMFUL_APPLICATION\"],\"platformTypes\":[\"ANY_PLATFORM\"],\"threatEntryTypes\":[\"URL\"],\"threatEntries\":[{\"url\":\"$FINAL_URL\"}]}}"
    GSB_RESP=$(curl -s --max-time 10 -X POST -H "Content-Type: application/json" \
      -d "$GSB_PAYLOAD" \
      "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=$GSB_API_KEY" 2>/dev/null || true)
    if echo "${GSB_RESP:-}" | grep -q "matches"; then
      if [ "$JQ_OK" = true ]; then
        GSB_THREAT=$(echo "$GSB_RESP" | jq -r '.matches[0].threatType // "UNKNOWN"' 2>/dev/null || echo "UNKNOWN")
      else
        GSB_THREAT=$(echo "$GSB_RESP" | grep -o '"threatType":"[^"]*"' | head -1 | sed 's/"threatType":"//;s/"//' || echo "UNKNOWN")
      fi
      add_reason "Google Safe Browsing: flagged as $GSB_THREAT"
      score_add 15; add_attack "Confirmed by Google Safe Browsing"
      add_category "CONFIRMED THREAT (GSB)"; API_FLAGS+=("GSB:$GSB_THREAT")
    else
      API_FLAGS+=("GSB:CLEAN")
    fi
  fi

  # ── PhishTank ───────────────────────────────────────────────────────────────
  if [ "$CURL_OK" = true ]; then
    status_log "Checking PhishTank..."
    ENCODED_URL=$(url_encode "$FINAL_URL")
    PT_RESP=$(curl -s --max-time 10 \
      -X POST "https://checkurl.phishtank.com/checkurl/" \
      -d "url=${ENCODED_URL}&format=json&app_key=" \
      -H "User-Agent: phishtank/webscan-pro" 2>/dev/null || true)
    if echo "${PT_RESP:-}" | grep -qi '"in_database":true'; then
      if echo "${PT_RESP:-}" | grep -qi '"valid":true'; then
        add_reason "PhishTank: CONFIRMED ACTIVE phishing site"
        score_add 15; add_attack "Active Phishing Site (PhishTank)"
        add_category "CONFIRMED PHISHING"; API_FLAGS+=("PHISHTANK:CONFIRMED")
        PHISHTANK_RESULT="CONFIRMED_PHISH"
      else
        add_reason "PhishTank: found in database (historical phishing record)"
        score_add 5; add_category "HISTORICAL PHISHING"; API_FLAGS+=("PHISHTANK:HISTORICAL")
        PHISHTANK_RESULT="HISTORICAL"
      fi
    else
      API_FLAGS+=("PHISHTANK:CLEAN"); PHISHTANK_RESULT="CLEAN"
    fi
  fi

  # ── AbuseIPDB ───────────────────────────────────────────────────────────────
  if [ -n "$ABUSEIPDB_KEY" ] && [ "$CURL_OK" = true ]; then
    status_log "Checking AbuseIPDB..."
    HOST_IP=$(timeout 5 dig +short "$BASE_DOMAIN" 2>/dev/null | grep -E '^[0-9]' | head -1 || true)
    if [ -n "$HOST_IP" ]; then
      AB_RESP=$(curl -s --max-time 10 -G "https://api.abuseipdb.com/api/v2/check" \
        --data-urlencode "ipAddress=$HOST_IP" \
        -d "maxAgeInDays=90" \
        -H "Key: $ABUSEIPDB_KEY" -H "Accept: application/json" 2>/dev/null || true)
      if [ "$JQ_OK" = true ]; then
        ABUSEIPDB_SCORE=$(echo "$AB_RESP" | jq -r '.data.abuseConfidenceScore // 0' 2>/dev/null || echo "0")
      else
        ABUSEIPDB_SCORE=$(echo "$AB_RESP" | grep -o '"abuseConfidenceScore":[0-9]*' | grep -o '[0-9]*' | head -1 || echo "0")
      fi
      if [ "${ABUSEIPDB_SCORE:-0}" -ge 50 ]; then
        add_reason "AbuseIPDB: Host IP $HOST_IP has ${ABUSEIPDB_SCORE}% abuse confidence score"
        score_add 8; add_category "MALICIOUS IP"; API_FLAGS+=("ABUSEIPDB:SCORE=$ABUSEIPDB_SCORE")
      elif [ "${ABUSEIPDB_SCORE:-0}" -ge 20 ]; then
        add_reason "AbuseIPDB: Host IP has moderate abuse score ($ABUSEIPDB_SCORE%)"
        score_add 3; API_FLAGS+=("ABUSEIPDB:MODERATE=$ABUSEIPDB_SCORE")
      else
        API_FLAGS+=("ABUSEIPDB:CLEAN")
      fi
    fi
  fi

fi  # end online-only API checks

# ══════════════════════════════════════════════════════════════════════════════
# ██  MODULE 2: NETWORK & PORT SCANNING  ██
# ══════════════════════════════════════════════════════════════════════════════
scan_ports_nc() {
  local host="$1"
  local open_ports=""
  local dangerous_ports=""
  verbose_log "Port scanning with nc (no nmap available)..."
  for port in 21 22 23 25 53 80 110 135 139 143 443 445 993 995 1433 1521 3306 3389 5432 5900 6379 8080 8443 27017; do
    if nc -z -w2 "$host" "$port" 2>/dev/null; then
      open_ports="$open_ports $port"
      PORT_RESULTS+=("OPEN: $host:$port")
      case $port in
        21)  dangerous_ports="$dangerous_ports FTP(21)" ;;
        23)  dangerous_ports="$dangerous_ports Telnet(23)" ;;
        135|139|445) dangerous_ports="$dangerous_ports SMB($port)" ;;
        3389) dangerous_ports="$dangerous_ports RDP(3389)" ;;
        5900) dangerous_ports="$dangerous_ports VNC(5900)" ;;
        6379) dangerous_ports="$dangerous_ports Redis(6379-UNAUTH?)" ;;
        27017) dangerous_ports="$dangerous_ports MongoDB(27017-UNAUTH?)" ;;
      esac
    fi
  done
  if [ -n "$dangerous_ports" ]; then
    add_reason "Dangerous services exposed:$dangerous_ports"
    score_add 5; add_category "EXPOSED SERVICES"; add_attack "Service Exploitation Risk"
  fi
}

scan_ports_nmap() {
  local host="$1"
  verbose_log "Running nmap port scan on $host..."
  local NMAP_OUT
  NMAP_OUT=$(nmap -sV --open -p "$COMMON_PORTS" --host-timeout 30s "$host" 2>/dev/null || true)

  # FIX: guard empty nmap output before processing
  [ -z "$NMAP_OUT" ] && return

  while IFS= read -r line; do
    if echo "$line" | grep -qE "^[0-9]+/tcp.*open"; then
      PORT_RESULTS+=("$line")
      PORT_NUM=$(echo "$line" | cut -d/ -f1)
      SERVICE=$(echo "$line" | awk '{print $3}')
      # FIX: safe VERSION extraction — guard against lines with fewer than 4 fields
      VERSION=$(echo "$line" | awk 'NF>3{$1=$2=$3=""; print $0}' | xargs 2>/dev/null || true)

      case $PORT_NUM in
        21)
          add_reason "FTP (port 21) exposed — check for anonymous login"
          score_add 3; add_attack "FTP Anonymous Login / Plaintext Transfer"
          add_category "EXPOSED SERVICES" ;;
        23)
          add_reason "Telnet (port 23) exposed — CRITICAL: unencrypted remote access"
          score_add 6; add_attack "Telnet — Cleartext Credential Exposure"
          add_category "CRITICAL MISCONFIGURATION" ;;
        25)
          add_reason "SMTP (port 25) open — check for open relay"
          score_add 2; add_category "EXPOSED SERVICES" ;;
        53)
          add_reason "DNS (port 53) open — check for zone transfer"
          score_add 2; add_attack "DNS Zone Transfer"; add_category "EXPOSED SERVICES" ;;
        110|143)
          add_reason "Unencrypted mail (POP3/IMAP port $PORT_NUM) exposed"
          score_add 2; add_category "NETWORK SECURITY" ;;
        135|139|445)
          add_reason "SMB/RPC port $PORT_NUM exposed — EternalBlue / Ransomware risk"
          score_add 7; add_attack "SMB Exploitation (EternalBlue/WannaCry/Ransomware)"
          add_category "CRITICAL VULNERABILITY" ;;
        1433)
          add_reason "MSSQL (1433) exposed to internet"
          score_add 5; add_attack "Database Direct Exposure"; add_category "DATABASE RISK" ;;
        1521)
          add_reason "Oracle DB (1521) exposed to internet"
          score_add 5; add_attack "Database Direct Exposure"; add_category "DATABASE RISK" ;;
        3306)
          add_reason "MySQL (3306) exposed to internet — database breach risk"
          score_add 5; add_attack "Database Direct Exposure"; add_category "DATABASE RISK" ;;
        3389)
          add_reason "RDP (3389) exposed — brute-force / BlueKeep risk"
          score_add 6; add_attack "RDP Brute Force / BlueKeep Exploit"
          add_category "CRITICAL VULNERABILITY" ;;
        5432)
          add_reason "PostgreSQL (5432) exposed to internet"
          score_add 5; add_attack "Database Direct Exposure"; add_category "DATABASE RISK" ;;
        5900)
          add_reason "VNC (5900) exposed — possible unauthenticated remote access"
          score_add 6; add_attack "VNC Unauthenticated Access"; add_category "CRITICAL VULNERABILITY" ;;
        6379)
          add_reason "Redis (6379) exposed — likely unauthenticated (CVE class)"
          score_add 7; add_attack "Redis Unauthenticated Access (RCE risk)"
          add_category "CRITICAL VULNERABILITY" ;;
        8080|8888)
          add_reason "Dev/admin panel on port $PORT_NUM exposed"
          score_add 2; add_category "EXPOSED SERVICES" ;;
        27017)
          add_reason "MongoDB (27017) exposed — often unauthenticated"
          score_add 7; add_attack "MongoDB Unauthenticated Access"
          add_category "CRITICAL VULNERABILITY" ;;
      esac

      # Version-based CVE hints — only run if VERSION is non-empty
      if [ -n "$VERSION" ]; then
        if echo "$VERSION" | grep -qiE "openssh [1-6]\.|openssh 7\.[0-3]"; then
          add_reason "Old OpenSSH version ($VERSION) — known CVEs possible"
          score_add 3; add_attack "Outdated SSH Service"; add_category "CVE RISK"
        fi
        if echo "$VERSION" | grep -qiE "apache/2\.[0-3]\.|apache/1\."; then
          add_reason "Outdated Apache ($VERSION) — known CVEs"
          score_add 3; add_attack "Outdated Web Server"; add_category "CVE RISK"
        fi
        if echo "$VERSION" | grep -qiE "nginx/1\.[0-9]\b|nginx/0\."; then
          add_reason "Outdated nginx version ($VERSION)"
          score_add 2; add_category "CVE RISK"
        fi
        if echo "$VERSION" | grep -qiE "microsoft-iis/[0-8]\."; then
          add_reason "Outdated IIS version ($VERSION) — known CVEs"
          score_add 3; add_attack "Outdated IIS Server"; add_category "CVE RISK"
        fi
      fi
    fi
  done <<< "$NMAP_OUT"
}

if [ "$PORT_SCAN" = true ] || [ "$OFFLINE_MODE" = true ] || [ "$NETWORK_MODE" = true ]; then
  status_log "Scanning ports..."
  SCAN_HOST="$BASE_DOMAIN"
  [[ "$BASE_DOMAIN" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]] && SCAN_HOST="$BASE_DOMAIN"
  if [ "$NMAP_OK" = true ]; then
    scan_ports_nmap "$SCAN_HOST"
  elif [ "$NC_OK" = true ]; then
    scan_ports_nc "$SCAN_HOST"
  else
    verbose_log "No port scanner available (install nmap for deep scanning)"
  fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# ██  MODULE 3: DNS & NETWORK INTELLIGENCE  ██
# ══════════════════════════════════════════════════════════════════════════════
if [ "$DIG_OK" = true ] && [ "$FILE_MODE" = false ] && [ "$NETWORK_MODE" = false ]; then
  status_log "Performing DNS analysis..."

  # DNS Zone Transfer attempt
  if [ "$DEEP_SCAN" = true ]; then
    verbose_log "Testing DNS zone transfer..."
    DNS_NS=$(timeout 5 dig NS "$BASE_DOMAIN" +short 2>/dev/null | head -2 || true)
    while IFS= read -r ns; do
      [ -z "$ns" ] && continue
      ZT=$(timeout 5 dig AXFR "$BASE_DOMAIN" @"$ns" 2>/dev/null | head -5 || true)
      if echo "$ZT" | grep -q "IN.*A\|IN.*CNAME" && ! echo "$ZT" | grep -qi "Transfer failed\|connection timed out"; then
        add_reason "DNS Zone Transfer ALLOWED on $ns — exposes all internal records"
        score_add 7; add_attack "DNS Zone Transfer (AXFR) Information Disclosure"
        add_category "DNS MISCONFIGURATION"
      fi
    done <<< "$DNS_NS"
  fi

  # SPF/DMARC check (email spoofing risk)
  SPF=$(timeout 5 dig TXT "$BASE_DOMAIN" +short 2>/dev/null | grep -i "v=spf" || true)
  DMARC=$(timeout 5 dig TXT "_dmarc.$BASE_DOMAIN" +short 2>/dev/null | grep -i "v=DMARC" || true)
  if [ -z "$SPF" ]; then
    add_reason "No SPF record — domain can be used for email spoofing"
    score_add 3; add_attack "Email Spoofing (Missing SPF)"
    add_category "EMAIL SECURITY"
  fi
  if [ -z "$DMARC" ]; then
    add_reason "No DMARC policy — phishing emails can impersonate this domain"
    score_add 2; add_attack "Email Impersonation (No DMARC)"
    add_category "EMAIL SECURITY"
  fi

  # CAA record check
  CAA=$(timeout 5 dig CAA "$BASE_DOMAIN" +short 2>/dev/null || true)
  if [ -z "$CAA" ] && [ "$IS_TRUSTED" = false ]; then
    verbose_log "No CAA record (anyone can issue SSL cert for this domain)"
  fi

  # DNSSEC
  DNSSEC=$(timeout 5 dig "$BASE_DOMAIN" +dnssec +short 2>/dev/null | grep -i "RRSIG\|NSEC" || true)
  [ -z "$DNSSEC" ] && verbose_log "DNSSEC not enabled on this domain"

  # Check for dangling CNAME (subdomain takeover)
  if [ "$DEEP_SCAN" = true ]; then
    CNAME=$(timeout 5 dig CNAME "$BASE_DOMAIN" +short 2>/dev/null || true)
    if [ -n "$CNAME" ]; then
      CNAME_RESOLVE=$(timeout 5 dig A "$CNAME" +short 2>/dev/null || true)
      if [ -z "$CNAME_RESOLVE" ]; then
        add_reason "Dangling CNAME ($CNAME) — possible subdomain takeover"
        score_add 6; add_attack "Subdomain Takeover via Dangling CNAME"
        add_category "SUBDOMAIN TAKEOVER"
      fi
    fi
  fi

  # PTR / Reverse DNS check for IPs
  if [[ "$BASE_DOMAIN" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    PTR=$(timeout 5 dig -x "$BASE_DOMAIN" +short 2>/dev/null | head -1 || true)
    [ -n "$PTR" ] && verbose_log "Reverse DNS: $BASE_DOMAIN → $PTR"
  fi
fi

# WHOIS / domain age
if [ "$WHOIS_OK" = true ] && [ "$FILE_MODE" = false ] && [ "$NETWORK_MODE" = false ] && \
   ! [[ "$BASE_DOMAIN" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  status_log "Checking domain registration..."
  WHOIS_DATA=$(timeout 8 whois "$BASE_DOMAIN" 2>/dev/null || true)
  CREATED=$(echo "$WHOIS_DATA" \
    | grep -iE "Creation Date|Registered On|Created On|Registration Time|created:" \
    | head -1 | grep -oE "[0-9]{4}-[0-9]{2}-[0-9]{2}" || true)
  if [ -n "$CREATED" ]; then
    CS=$(get_date_seconds "$CREATED")
    if [ -n "$CS" ] && [ "$CS" -gt 0 ] && [ "$NOW_SEC" -gt 0 ]; then
      AGE=$(( (NOW_SEC - CS) / 86400 ))
      if   [ "$AGE" -lt 30  ]; then
        add_reason "Brand-new domain ($AGE days old) — very high risk"
        score_add 5; add_category "SUSPICIOUS DOMAIN"
      elif [ "$AGE" -lt 90  ]; then
        add_reason "Very new domain ($AGE days old) — elevated risk"
        score_add 3
      elif [ "$AGE" -lt 180 ]; then
        add_reason "Recently registered domain ($AGE days old)"
        score_add 1
      fi
    fi
  fi

  # Check WHOIS privacy / registrar abuse
  if echo "$WHOIS_DATA" | grep -qi "privacy\|redacted\|whoisguard\|domainsbyproxy"; then
    add_reason "WHOIS identity hidden behind privacy service"
    score_add 1; verbose_log "WHOIS privacy enabled"
  fi

  REGISTRAR=$(echo "$WHOIS_DATA" | grep -i "Registrar:" | head -1 | sed 's/Registrar://i;s/^ *//' || true)
  if echo "$REGISTRAR" | grep -qiE "namecheap|njalla|tucows|dynadot|1api|reg\.ru|regway"; then
    add_reason "Registered with low-cost/privacy-friendly registrar: $REGISTRAR"
    score_add 1
  fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# ██  MODULE 4: SSL/TLS SECURITY  ██
# ══════════════════════════════════════════════════════════════════════════════
if [ "$OPENSSL_OK" = true ] && [ "$FILE_MODE" = false ] && [ "$NETWORK_MODE" = false ] && \
   [[ "$FINAL_URL" =~ ^https:// ]]; then
  status_log "Analyzing SSL/TLS..."
  SSL_INFO=$(echo | timeout 8 openssl s_client -connect "${BASE_DOMAIN}:443" \
    -servername "$BASE_DOMAIN" 2>/dev/null || true)

  # Self-signed check
  if echo "$SSL_INFO" | grep -qi "self.signed\|self signed"; then
    add_reason "Self-signed SSL certificate — possible MitM"
    score_add 4; add_attack "SSL Certificate Spoofing / MitM"
    add_category "TLS/SSL ATTACK"
  fi

  # Certificate expiry
  CERT_DATES=$(echo "$SSL_INFO" | grep -oE "notAfter=[^$]+" | head -1 || true)
  if [ -n "$CERT_DATES" ]; then
    EXPIRE_DATE=$(echo "$CERT_DATES" | sed 's/notAfter=//')
    verbose_log "SSL cert expires: $EXPIRE_DATE"
  fi

  # Weak protocol detection
  for PROTO in ssl2 ssl3 tls1 tls1_1; do
    PROTO_RESP=$(echo | timeout 5 openssl s_client -connect "${BASE_DOMAIN}:443" \
      -"$PROTO" -servername "$BASE_DOMAIN" 2>/dev/null | grep "Cipher\|Protocol" || true)
    if echo "$PROTO_RESP" | grep -qi "Cipher is\|Protocol.*$PROTO"; then
      add_reason "Weak protocol supported: $PROTO — POODLE/BEAST/DROWN attack surface"
      score_add 4; add_attack "Weak TLS/SSL Protocol (POODLE/BEAST/DROWN)"
      add_category "TLS/SSL ATTACK"
    fi
  done

  # Check for Heartbleed-like (OpenSSL version hints from banner)
  SERVER_BANNER=$(echo "$SSL_INFO" | grep -i "Server version\|openssl" | head -1 || true)
  if echo "$SERVER_BANNER" | grep -qiE "openssl/(0\.|1\.0\.[01])"; then
    add_reason "Old OpenSSL version in banner — Heartbleed risk possible"
    score_add 5; add_attack "Heartbleed (CVE-2014-0160)"; add_category "CVE RISK"
  fi

  # HSTS check
  if [ -s "$HEADERS" ] && ! grep -qi "Strict-Transport-Security" "$HEADERS"; then
    add_reason "Missing HSTS header — SSL stripping attack possible"
    score_add 2; add_attack "SSL Stripping Attack"; add_category "TLS/SSL ATTACK"
  fi

  # Let's Encrypt (easy for attackers to get)
  CERT_ISSUER=$(echo "$SSL_INFO" | grep -i "issuer=" | head -1 || true)
  if echo "$CERT_ISSUER" | grep -qi "let's encrypt\|letsencrypt\|zerossl"; then
    add_reason "Free/automated SSL cert (trivially obtained by anyone)"
    score_add 1
  fi
fi

# Check HTTP (no TLS) for online mode
if [[ "$FINAL_URL" =~ ^http:// ]] && [ "$FILE_MODE" = false ]; then
  add_reason "No HTTPS — all traffic transmitted in plain text"
  score_add 4; add_attack "Man-in-the-Middle (MitM) / Traffic Interception"
  add_category "NETWORK SECURITY"
fi

# ══════════════════════════════════════════════════════════════════════════════
# ██  MODULE 5: SECURITY HEADERS ANALYSIS  ██
# ══════════════════════════════════════════════════════════════════════════════
if [ -s "$HEADERS" ] && [ "$FILE_MODE" = false ]; then
  status_log "Analyzing security headers..."
  MISSING_HEADERS=0
  # FIX: HEADER_ISSUES already initialised at top; reset here for this block
  HEADER_ISSUES=()

  grep -qi "x-frame-options"            "$HEADERS" || { MISSING_HEADERS=$((MISSING_HEADERS+1)); HEADER_ISSUES+=("X-Frame-Options"); }
  grep -qi "x-xss-protection"           "$HEADERS" || { MISSING_HEADERS=$((MISSING_HEADERS+1)); HEADER_ISSUES+=("X-XSS-Protection"); }
  grep -qi "content-security-policy"    "$HEADERS" || { MISSING_HEADERS=$((MISSING_HEADERS+1)); HEADER_ISSUES+=("Content-Security-Policy"); }
  grep -qi "strict-transport-security"  "$HEADERS" || { MISSING_HEADERS=$((MISSING_HEADERS+1)); HEADER_ISSUES+=("Strict-Transport-Security"); }
  grep -qi "x-content-type-options"     "$HEADERS" || { MISSING_HEADERS=$((MISSING_HEADERS+1)); HEADER_ISSUES+=("X-Content-Type-Options"); }
  grep -qi "referrer-policy"            "$HEADERS" || { MISSING_HEADERS=$((MISSING_HEADERS+1)); HEADER_ISSUES+=("Referrer-Policy"); }
  grep -qi "permissions-policy\|feature-policy" "$HEADERS" || { MISSING_HEADERS=$((MISSING_HEADERS+1)); HEADER_ISSUES+=("Permissions-Policy"); }

  if [ "$MISSING_HEADERS" -ge 5 ]; then
    # FIX: use "${HEADER_ISSUES[*]}" (always safe now that array is initialised)
    add_reason "Missing $MISSING_HEADERS/7 security headers: ${HEADER_ISSUES[*]}"
    score_add 3; add_category "SECURITY MISCONFIGURATION"
  elif [ "$MISSING_HEADERS" -ge 3 ]; then
    add_reason "Missing $MISSING_HEADERS security headers: ${HEADER_ISSUES[*]}"
    score_add 2; add_category "SECURITY MISCONFIGURATION"
  fi

  # Clickjacking
  if ! grep -qi "x-frame-options\|frame-ancestors" "$HEADERS"; then
    add_reason "No X-Frame-Options / CSP frame-ancestors — Clickjacking possible"
    score_add 2; add_attack "Clickjacking Attack"; add_category "WEB VULNERABILITY"
  fi

  # CORS misconfiguration
  CORS_HEADER=$(grep -i "Access-Control-Allow-Origin" "$HEADERS" | head -1 || true)
  if echo "$CORS_HEADER" | grep -q "\*"; then
    add_reason "CORS wildcard (Access-Control-Allow-Origin: *) — cross-origin request abuse"
    score_add 3; add_attack "CORS Misconfiguration — Cross-Origin Data Theft"
    add_category "WEB VULNERABILITY"
  fi

  # Server version leakage
  SERVER_HDR=$(grep -i "^Server:" "$HEADERS" | head -1 || true)
  if echo "$SERVER_HDR" | grep -qiE "[0-9]+\.[0-9]+"; then
    add_reason "Server version leaked in header: $SERVER_HDR"
    score_add 1; add_category "INFORMATION DISCLOSURE"
  fi

  # X-Powered-By leakage
  POWERED_HDR=$(grep -i "X-Powered-By" "$HEADERS" | head -1 || true)
  if [ -n "$POWERED_HDR" ]; then
    add_reason "X-Powered-By header exposed: $POWERED_HDR (fingerprinting vector)"
    score_add 1; add_category "INFORMATION DISCLOSURE"
  fi

  # Cache-Control missing on sensitive endpoints
  if ! grep -qi "Cache-Control" "$HEADERS"; then
    verbose_log "No Cache-Control header — sensitive data may be cached"
  fi

  # MIME sniffing
  if ! grep -qi "X-Content-Type-Options" "$HEADERS"; then
    add_reason "Missing X-Content-Type-Options — MIME sniffing attack possible"
    score_add 1; add_attack "MIME Sniffing Attack"; add_category "WEB VULNERABILITY"
  fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# ██  MODULE 6: WEB APPLICATION VULNERABILITY SCAN  ██
# ══════════════════════════════════════════════════════════════════════════════
if [ -s "$PAGE" ]; then
  status_log "Scanning web application vulnerabilities..."

  # ── SQL Injection indicators ────────────────────────────────────────────────
  SQLI_FORMS=$(grep -oiE "<form[^>]+action\s*=\s*['\"][^'\"]*['\"]" "$PAGE" 2>/dev/null | wc -l | tr -d ' ' || echo "0")
  SQLI_INPUTS=$(grep -ciE "<input[^>]+name\s*=\s*['\"]?(id|user|username|search|q|query|item|product|page|cat|category)['\"]?" "$PAGE" 2>/dev/null || true)
  if echo "$FINAL_URL" | grep -qE "[?&][a-zA-Z_]+="; then
    add_reason "URL contains query parameters — SQL injection test surface present"
    score_add 1; add_attack "SQL Injection (Attack Surface Present)"
    add_category "WEB VULNERABILITY"
  fi

  # PHP error / SQL error in page
  if grep -qiE "you have an error in your sql syntax|warning.*mysql|unclosed quotation mark|syntax error.*near|ORA-[0-9]{5}:|pg_exec.*failed|PDOException|sqlstate\[" "$PAGE" 2>/dev/null; then
    add_reason "SQL error/warning visible in page — active SQL vulnerability or verbose errors"
    score_add 7; add_attack "SQL Injection — Error-Based Disclosure"
    add_category "CRITICAL VULNERABILITY"; add_vuln "SQLi errors visible in page source"
  fi

  # ── XSS indicators ──────────────────────────────────────────────────────────
  if echo "$FINAL_URL" | grep -qiE "(<script|javascript:|onerror=|onload=|alert\(|document\.cookie)"; then
    add_reason "XSS payload in URL detected"
    score_add 5; add_attack "Reflected XSS (Payload in URL)"
    add_category "CRITICAL VULNERABILITY"
  fi

  # DOM-based XSS risk
  if grep -qiE "document\.write\s*\(|innerHTML\s*=|outerHTML\s*=|eval\s*\(.*location\.|location\.hash|location\.search" "$PAGE" 2>/dev/null; then
    add_reason "Unsafe DOM manipulation (innerHTML/document.write/eval with URL input) — DOM XSS risk"
    score_add 4; add_attack "DOM-Based XSS"; add_category "WEB VULNERABILITY"
  fi

  # Stored XSS surface
  if grep -qiE "<script[^>]*>.*document\.cookie|<script[^>]*>.*window\.location" "$PAGE" 2>/dev/null; then
    add_reason "Script accessing cookies/location in rendered page — possible stored XSS"
    score_add 3; add_attack "Stored/Reflected XSS"; add_category "WEB VULNERABILITY"
  fi

  # ── CSRF ───────────────────────────────────────────────────────────────────
  FORM_COUNT=$(grep -ciE "<form" "$PAGE" 2>/dev/null || true)
  CSRF_TOKEN_COUNT=$(grep -ciE "csrf|_token|nonce|authenticity_token" "$PAGE" 2>/dev/null || true)
  if [ "${FORM_COUNT:-0}" -gt 0 ] && [ "${CSRF_TOKEN_COUNT:-0}" -eq 0 ]; then
    add_reason "Forms present without CSRF tokens — Cross-Site Request Forgery risk"
    score_add 4; add_attack "CSRF — Cross-Site Request Forgery"; add_category "WEB VULNERABILITY"
  fi

  # ── Open Redirect ──────────────────────────────────────────────────────────
  if echo "$FINAL_URL" | grep -qiE "[?&](redirect|url|next|goto|return|redir|dest|destination|target|link|location|forward)=http"; then
    add_reason "Open redirect parameter in URL — phishing relay vector"
    score_add 5; add_attack "Open Redirect — Phishing Relay"; add_category "WEB VULNERABILITY"
  fi
  if grep -qiE "window\.location\s*=\s*['\"]https?:|location\.replace\s*\([^)]*https?:" "$PAGE" 2>/dev/null; then
    add_reason "JavaScript open redirect pattern detected"
    score_add 3; add_attack "Client-Side Open Redirect"; add_category "WEB VULNERABILITY"
  fi

  # ── Path Traversal / LFI ───────────────────────────────────────────────────
  if echo "$FINAL_URL" | grep -qE "\.\./|%2e%2e%2f|%252e%252e|\.\.%5c"; then
    add_reason "Path traversal sequences in URL (%2e%2e or ../) — LFI/directory traversal"
    score_add 6; add_attack "Path Traversal / Local File Inclusion (LFI)"
    add_category "CRITICAL VULNERABILITY"
  fi

  # ── SSRF ────────────────────────────────────────────────────────────────────
  if echo "$FINAL_URL" | grep -qiE "[?&](url|uri|path|host|dest|server|endpoint|src|target|fetch|load)=(https?|ftp|file|dict|gopher)"; then
    add_reason "SSRF-susceptible parameter in URL — internal service enumeration risk"
    score_add 6; add_attack "Server-Side Request Forgery (SSRF)"; add_category "CRITICAL VULNERABILITY"
  fi

  # ── XXE ─────────────────────────────────────────────────────────────────────
  if grep -qiE "<!DOCTYPE\s+[a-z]+\s*\[|<!ENTITY\s+|SYSTEM\s+['\"]file:|libxml" "$PAGE" 2>/dev/null; then
    add_reason "XML with DOCTYPE/ENTITY declarations — XXE injection risk"
    score_add 5; add_attack "XML External Entity (XXE) Injection"; add_category "CRITICAL VULNERABILITY"
  fi

  # ── Command Injection surface ──────────────────────────────────────────────
  if echo "$FINAL_URL" | grep -qE '[;&|`$()]|%7c|%26|%3b'; then
    add_reason "Shell metacharacters in URL — command injection surface"
    score_add 5; add_attack "OS Command Injection"; add_category "CRITICAL VULNERABILITY"
  fi

  # ── Insecure Deserialization ────────────────────────────────────────────────
  if grep -qiE "unserialize\s*\(|pickle\.loads|ObjectInputStream|readObject|yaml\.load\s*\([^L]|Marshal\.load" "$PAGE" 2>/dev/null; then
    add_reason "Dangerous deserialization function in page code"
    score_add 5; add_attack "Insecure Deserialization (RCE Risk)"; add_category "CRITICAL VULNERABILITY"
  fi

  # ── Template Injection ─────────────────────────────────────────────────────
  if echo "$FINAL_URL" | grep -qE "(\{\{|\{%|<%=|\$\{)"; then
    add_reason "Template syntax in URL — Server-Side Template Injection (SSTI) risk"
    score_add 6; add_attack "Server-Side Template Injection (SSTI/RCE)"; add_category "CRITICAL VULNERABILITY"
  fi

  # ── Obfuscated JavaScript ──────────────────────────────────────────────────
  if grep -qiE "eval\s*\(\s*(atob|unescape|escape)|document\.write\s*\(\s*unescape|String\.fromCharCode\s*\([0-9,\s]{20,}\)|\\\\x[0-9a-f]{2}\\\\x[0-9a-f]{2}" "$PAGE" 2>/dev/null; then
    add_reason "Obfuscated JavaScript (eval+atob/unescape/fromCharCode)"
    score_add 3; add_attack "Obfuscated Malicious Code Execution"; add_category "MALWARE"
  fi

  # ── Base64 data blobs ──────────────────────────────────────────────────────
  B64_COUNT=$(grep -oiE 'base64,[A-Za-z0-9+/]{100,}' "$PAGE" 2>/dev/null | wc -l | tr -d ' ')
  if [ "${B64_COUNT:-0}" -gt 3 ]; then
    add_reason "$B64_COUNT large base64 blobs — content hiding / evasion"
    score_add 2; add_attack "Content Obfuscation via Base64"; add_category "OBFUSCATION"
  fi

  # ── Sensitive file exposure ────────────────────────────────────────────────
  if echo "$FINAL_URL" | grep -qiE "\.(env|git|svn|htpasswd|config|bak|backup|sql|db|log|conf|ini|xml|json|yaml|yml|key|pem|cert|csr|p12|pfx|zip|tar|gz|7z)(\?|$)"; then
    EXPOSED_EXT=$(echo "$FINAL_URL" | grep -oiE "\.(env|git|svn|htpasswd|config|bak|backup|sql|db|log|conf|ini|xml|json|yaml|yml|key|pem|cert|csr|p12|pfx|zip|tar|gz|7z)" | head -1)
    add_reason "Sensitive file type accessible: $EXPOSED_EXT"
    score_add 6; add_attack "Sensitive File Exposure ($EXPOSED_EXT)"
    add_category "INFORMATION DISCLOSURE"
  fi

  # ── Git/.env exposure check ────────────────────────────────────────────────
  if [ "$DEEP_SCAN" = true ] && [ "$CURL_OK" = true ] && [ "$FILE_MODE" = false ]; then
    SCHEME=$(echo "$FINAL_URL" | grep -oE "^https?://")
    ORIGIN="${SCHEME}${BASE_DOMAIN}"
    for SENSITIVE_PATH in "/.env" "/.git/config" "/.git/HEAD" "/wp-config.php" "/config.php" "/phpinfo.php" "/.htpasswd" "/admin" "/phpmyadmin" "/adminer.php" "/backup.sql" "/.DS_Store" "/server-status" "/actuator/health" "/api/v1/users" "/.well-known/security.txt"; do
      SCODE=$(http_get_code "${ORIGIN}${SENSITIVE_PATH}" 2>/dev/null || echo "000")
      if [[ "$SCODE" == "200" ]]; then
        add_reason "Exposed sensitive path: ${SENSITIVE_PATH} (HTTP 200)"
        score_add 5; add_attack "Sensitive Path Exposure: $SENSITIVE_PATH"
        add_category "INFORMATION DISCLOSURE"
        add_vuln "Accessible: ${ORIGIN}${SENSITIVE_PATH}"
      fi
    done
  fi

  # ── CMS Detection ──────────────────────────────────────────────────────────
  CMS_DETECTED=""
  if grep -qiE "wp-content|wp-includes|wp-json|wordpress" "$PAGE" 2>/dev/null; then
    CMS_DETECTED="WordPress"
    add_reason "WordPress detected — check for plugin/theme CVEs and brute-force"
    score_add 1; add_category "CMS DETECTED (WordPress)"
    if grep -qiE "wp-login|xmlrpc\.php" "$PAGE" 2>/dev/null; then
      add_reason "WordPress login/xmlrpc.php reachable — brute-force target"
      score_add 2; add_attack "WordPress Brute Force / XML-RPC Abuse"
    fi
    WP_VER=$(grep -oiE "ver=[0-9]+\.[0-9]+\.[0-9]+" "$PAGE" 2>/dev/null | head -1 || true)
    [ -n "$WP_VER" ] && add_reason "WordPress version disclosed: $WP_VER"
  elif grep -qiE "joomla|\/components\/com_|\/modules\/mod_" "$PAGE" 2>/dev/null; then
    CMS_DETECTED="Joomla"
    add_reason "Joomla CMS detected — check for plugin vulnerabilities"
    score_add 1; add_category "CMS DETECTED (Joomla)"
  elif grep -qiE "drupal|sites\/default|\/modules\/system" "$PAGE" 2>/dev/null; then
    CMS_DETECTED="Drupal"
    add_reason "Drupal CMS detected — check Drupalgeddon CVEs"
    score_add 2; add_category "CMS DETECTED (Drupal)"
    add_attack "Drupalgeddon (SA-CORE-2018-002) Risk"
  elif grep -qiE "laravel|\/public\/css\/app\.|XSRF-TOKEN" "$PAGE" 2>/dev/null; then
    CMS_DETECTED="Laravel"
    add_reason "Laravel framework detected"
    add_category "FRAMEWORK DETECTED (Laravel)"
    if grep -qiE "APP_DEBUG=true\|Whoops.*Laravel\|Stack trace:" "$PAGE" 2>/dev/null; then
      add_reason "Laravel DEBUG mode ON — credentials/config exposed in error pages"
      score_add 7; add_attack "Framework Debug Mode RCE / Information Disclosure"
      add_category "CRITICAL VULNERABILITY"
    fi
  fi

  # ── API Endpoint Security ───────────────────────────────────────────────────
  if [ "$API_TEST" = true ] || grep -qiE "\"swagger\"\|openapi\|graphql\|/api/v[0-9]\|/rest/" "$PAGE" 2>/dev/null; then
    add_reason "API endpoints detected — test for auth bypass, mass assignment, rate limiting"
    add_category "API SECURITY"

    if grep -qiE "\"query\"\s*:\s*\"{\s*__schema|graphql|graphiql" "$PAGE" 2>/dev/null; then
      add_reason "GraphQL endpoint detected — check for introspection and batching attacks"
      score_add 2; add_attack "GraphQL Introspection / Batching Attack"
      add_category "API SECURITY"
    fi

    if grep -qiE "eyJ[A-Za-z0-9+/]{10,}\.[A-Za-z0-9+/]{10,}" "$PAGE" 2>/dev/null; then
      add_reason "JWT token found in page source — token leakage risk"
      score_add 3; add_attack "JWT Token Exposure / Algorithm Confusion"
      add_category "API SECURITY"
    fi
  fi

  # ── Credential / Secret Leakage ────────────────────────────────────────────
  if grep -qiE "(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)\s*[=:]\s*['\"][a-zA-Z0-9+/=_\-]{16,}" "$PAGE" 2>/dev/null; then
    add_reason "API key/secret token exposed in page source"
    score_add 8; add_attack "Secret/API Key Exposure in Source Code"
    add_category "CRITICAL VULNERABILITY"
  fi

  # AWS keys
  if grep -qiE "AKIA[0-9A-Z]{16}" "$PAGE" 2>/dev/null; then
    add_reason "AWS Access Key ID pattern found in page source"
    score_add 10; add_attack "AWS Credentials Leaked in Page Source"
    add_category "CRITICAL VULNERABILITY"
  fi

  # Google API keys
  if grep -qiE "AIza[0-9A-Za-z\-_]{35}" "$PAGE" 2>/dev/null; then
    add_reason "Google API key found in page source"
    score_add 5; add_attack "Google API Key Exposure"; add_category "INFORMATION DISCLOSURE"
  fi

  # ── Phishing / Social Engineering ─────────────────────────────────────────
  if [[ "$IS_TRUSTED" = false ]] && [[ "$OFFLINE_MODE" = false ]]; then

    # IP address as domain
    if [[ "$BASE_DOMAIN" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      add_reason "Raw IP address used as host — phishing/malware indicator"
      score_add 4; add_attack "Direct IP Phishing"; add_category "PHISHING"
    fi

    # URL shorteners
    if [[ "$ROOT_DOMAIN" =~ ^(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|rb\.gy|cutt\.ly|is\.gd|shorturl\.at|buff\.ly|tiny\.cc)$ ]]; then
      add_reason "URL shortener used — masks true destination"
      score_add 2; add_attack "Destination Concealment"; add_category "OBFUSCATION"
    fi

    # Tunnel services
    if echo "$BASE_DOMAIN" | grep -qiE "ngrok\.|loclx\.|trycloudflare\.|serveo\.|localtunnel\.|bore\.pub|pagekite\.|telebit\."; then
      add_reason "Temporary tunnel service (ngrok/cloudflare tunnel) — common phishing vector"
      score_add 5; add_attack "Phishing via Tunnel Service"; add_category "PHISHING"
    fi

    # Suspicious TLD
    if [[ "$BASE_DOMAIN" =~ \.(tk|ml|ga|cf|gq|xyz|top|click|buzz|monster|loan|win|bid|racing|download|work|date|men|online|site|website|space|fun|icu|cc|pw|ws|vip|life|live|shop|store)$ ]]; then
      add_reason "Suspicious free/low-cost TLD — commonly abused"
      score_add 2; add_category "SUSPICIOUS DOMAIN"
    fi

    # Homograph
    if echo "$BASE_DOMAIN" | grep -qiE "g00gle|paypa1|micros0ft|arnazon|faceb00k|netfl1x|app1e|lnstagram|tw1tter|linkedln|yah00|amaz0n"; then
      add_reason "Lookalike/homograph domain (letter substitution attack)"
      score_add 6; add_attack "Typosquatting / Homograph Attack"; add_category "PHISHING"
    fi

    # @ in URL
    if [[ "$FINAL_URL" == *"@"* ]]; then
      add_reason "@ symbol in URL — credential embedding trick"
      score_add 4; add_attack "URL Deception via @ Symbol"; add_category "PHISHING"
    fi

    # Brand in domain
    for BRAND in "${!BRAND_ROOTS[@]}"; do
      OFFICIAL="${BRAND_ROOTS[$BRAND]}"
      if echo "$BASE_DOMAIN" | grep -qi "$BRAND" && [[ "$ROOT_DOMAIN" != "$OFFICIAL" ]]; then
        add_reason "Brand '$BRAND' in domain but on $ROOT_DOMAIN (official: $OFFICIAL)"
        score_add 5; add_attack "Domain Spoofing — Impersonating $BRAND"; add_category "PHISHING"
        break
      fi
    done

    # Urgency phrases
    URGENCY=0
    for P in "verify your account" "confirm your identity" "update your payment" \
             "suspended account" "urgent action required" "account has been limited" \
             "validate your account" "account will be closed" "verify now" \
             "immediate action" "unauthorized access detected" "account compromised" \
             "action required" "security alert" "unusual activity" "reactivate account" \
             "pending payment" "billing error" "account violation" "final warning" \
             "your account is at risk" "confirm now" "suspicious login" \
             "temporary hold" "account restricted"; do
      echo "$PAGE_TEXT" | grep -qi "$P" && URGENCY=$(( URGENCY + 1 ))
    done
    if [ "$URGENCY" -ge 3 ]; then
      add_reason "High urgency phrase count ($URGENCY matches) — social engineering"
      score_add 4; add_attack "Psychological Manipulation / Social Engineering"
      add_category "SOCIAL ENGINEERING"
    elif [ "$URGENCY" -ge 1 ]; then
      add_reason "Urgency phrases detected ($URGENCY matches)"
      score_add 1
    fi

    # OTP/2FA interception
    HAS_PASSWORD=false
    grep -qiE "type\s*=\s*[\"']?password" "$PAGE" 2>/dev/null && HAS_PASSWORD=true
    if [ "$HAS_PASSWORD" = true ]; then
      if echo "$PAGE_TEXT" | grep -qiE "otp|one.?time.?password|verification code|2fa|two.?factor|sms code"; then
        add_reason "OTP/2FA prompt with login form — real-time interception (AiTM)"
        score_add 5; add_attack "Real-Time OTP Interception (AiTM Phishing)"; add_category "ADVANCED PHISHING"
      fi
    fi

    # Brand in content
    for BRAND in "${!BRAND_ROOTS[@]}"; do
      OFFICIAL="${BRAND_ROOTS[$BRAND]}"
      if echo "$PAGE_TEXT" | grep -qi "$BRAND" && [[ "$ROOT_DOMAIN" != "$OFFICIAL" ]]; then
        add_reason "Page content references '$BRAND' but hosted outside $OFFICIAL"
        score_add 3; add_attack "Brand Impersonation in Page Content"; add_category "PHISHING"
        break
      fi
    done

    # Fake trust badges
    if echo "$PAGE_TEXT" | grep -qiE "norton secured|mcafee secure|ssl secured|100% secure|verified secure|hacker safe|trusted site|site seal"; then
      add_reason "Fake security trust badge detected"
      score_add 2; add_attack "False Trust Indicators (Fake Seals)"; add_category "DECEPTION"
    fi

    # Form posts to external domain
    FORM_ACTION=$(grep -ioE "<form[^>]+action\s*=\s*['\"][^'\"]*['\"]" "$PAGE" 2>/dev/null | head -1 || true)
    if [ -n "$FORM_ACTION" ]; then
      ACTION_HOST=$(echo "$FORM_ACTION" | grep -oE "(https?:)?//[^/'\"&?]+" | head -1 | sed -E 's#(https?:)?//##;s/^www\.//' || true)
      if [ -n "$ACTION_HOST" ]; then
        ACTION_ROOT=$(echo "$ACTION_HOST" | rev | cut -d. -f1-2 | rev)
        if [[ "$ACTION_ROOT" != "$ROOT_DOMAIN" ]] && [[ "$ACTION_ROOT" != "localhost" ]]; then
          add_reason "Form submits to external server: $ACTION_HOST"
          score_add 5; add_attack "Credential Harvesting to 3rd-Party Server"; add_category "CREDENTIAL HARVESTING"
        fi
      fi
    fi

    # Password on HTTP
    if [ "$HAS_PASSWORD" = true ] && [[ "$FINAL_URL" =~ ^http:// ]]; then
      add_reason "Password field on unencrypted HTTP page"
      score_add 5; add_attack "Credential Theft over Plaintext HTTP"; add_category "CREDENTIAL HARVESTING"
    fi

    # Multiple password fields
    PW_FIELDS=$(grep -ciE "type\s*=\s*[\"']password[\"']" "$PAGE" 2>/dev/null || true)
    if [ "${PW_FIELDS:-0}" -gt 1 ]; then
      add_reason "Multiple password fields ($PW_FIELDS) — unusual login pattern"
      score_add 2; add_category "CREDENTIAL HARVESTING"
    fi

    # Excessive redirects
    REDIRECTS=$(count_redirects "$TARGET" 2>/dev/null || echo "0")
    if [ "${REDIRECTS:-0}" -gt 4 ]; then
      add_reason "Excessive redirects (${REDIRECTS} hops) — hiding true destination"
      score_add 2; add_attack "Redirect Chain Obfuscation"; add_category "OBFUSCATION"
    fi
  fi

  # ── Malware / Exploit Delivery ─────────────────────────────────────────────

  # Cryptomining
  if grep -qiE "coinhive|cryptonight|monero.*miner|wasm.*mine|webassembly.*hash|stratum\+tcp|mining.*pool|miner\.start" "$PAGE" 2>/dev/null; then
    add_reason "Cryptocurrency mining code (cryptojacking) detected"
    score_add 7; add_attack "Browser-Based Cryptomining (Cryptojacking)"; add_category "MALWARE"
  fi

  # Drive-by downloads
  if echo "$PAGE_TEXT" | grep -qiE "your computer is infected|virus detected|your device is compromised|download required|update required|install now|click to remove|system alert|windows warning|browser is outdated"; then
    add_reason "Drive-by download / fake security alert lure"
    score_add 5; add_attack "Drive-By Download / Fake Security Alert"; add_category "MALWARE"
  fi

  # Ransomware / malware keywords
  MALWARE_HITS=0
  for P in "keylogger" "spyware" "ransomware" "trojan" "rootkit" "botnet" \
           "command and control" "c2 server" "shellcode" "payload" "exploit kit" \
           "drive-by" "zero-day" "backdoor" "reverse shell" "webshell" "c99.php" "r57.php"; do
    echo "$PAGE_TEXT" | grep -qi "$P" && MALWARE_HITS=$(( MALWARE_HITS + 1 ))
  done
  if [ "$MALWARE_HITS" -ge 1 ]; then
    add_reason "Malware-related terms in page ($MALWARE_HITS keywords)"
    score_add 3; add_attack "Potential Malware Distribution / C2 Reference"; add_category "MALWARE"
  fi

  # Webshell patterns
  if grep -qiE "passthru\s*\(|shell_exec\s*\(|system\s*\(\s*\$_(GET|POST|REQUEST)|exec\s*\(\s*\$_(GET|POST)|base64_decode\s*\(\s*\$_(GET|POST)" "$PAGE" 2>/dev/null; then
    add_reason "Webshell / PHP backdoor pattern detected in page"
    score_add 9; add_attack "PHP Webshell / Remote Code Execution"; add_category "CRITICAL VULNERABILITY"
  fi

  # Clipboard hijacking
  if grep -qiE "navigator\.clipboard|clipboardData|document\.execCommand.*copy" "$PAGE" 2>/dev/null; then
    add_reason "Clipboard access code — possible crypto-address hijacking"
    score_add 3; add_attack "Clipboard Hijacking (Crypto Address Replacement)"; add_category "MALWARE"
  fi

  # Cryptoscam / investment fraud
  CRYPTO_COUNT=0
  for P in "double your bitcoin" "guaranteed return" "risk-free investment" \
           "exclusive investment" "100% profit" "send crypto" "send bitcoin" \
           "wallet connect" "metamask" "connect your wallet" "claim your reward" \
           "airdrop" "rug pull" "free nft" "whitelist"; do
    echo "$PAGE_TEXT" | grep -qi "$P" && CRYPTO_COUNT=$(( CRYPTO_COUNT + 1 ))
  done
  if [ "$CRYPTO_COUNT" -ge 2 ]; then
    add_reason "Crypto/investment scam indicators ($CRYPTO_COUNT matches)"
    score_add 5; add_attack "Cryptocurrency Scam / Investment Fraud"; add_category "FINANCIAL FRAUD"
  fi

  # Financial fraud lures
  PAY=0
  for P in "payment failed" "billing issue" "pay now" "card details" \
           "invoice overdue" "card was declined" "update billing" \
           "credit card" "debit card" "bank account" "wire transfer" \
           "gift card" "cryptocurrency" "bitcoin" "wallet address"; do
    echo "$PAGE_TEXT" | grep -qi "$P" && PAY=$(( PAY + 1 ))
  done
  if [ "$PAY" -ge 2 ]; then
    add_reason "Financial fraud lures ($PAY matches)"
    score_add 3; add_attack "Financial Fraud / Payment Scam"; add_category "FINANCIAL FRAUD"
  fi

  # Cross-origin iframes
  IFRAME_SRCS=$(grep -oiE "<iframe[^>]+src\s*=\s*['\"][^'\"]*['\"]" "$PAGE" 2>/dev/null \
    | grep -viE "($BASE_DOMAIN|youtube\.com|vimeo\.com|google\.com|maps\.google)" \
    | wc -l | tr -d ' ' || echo "0")
  if [ "${IFRAME_SRCS:-0}" -gt 0 ]; then
    add_reason "Suspicious cross-origin iframes ($IFRAME_SRCS) — Clickjacking/exploit"
    score_add 3; add_attack "Malicious iframe / Clickjacking"; add_category "WEB VULNERABILITY"
  fi

  # Meta-refresh redirect
  if grep -qiE "meta.*http-equiv\s*=\s*['\"]refresh['\"]" "$PAGE" 2>/dev/null; then
    add_reason "Meta-refresh redirect — common in phishing relay pages"
    score_add 2; add_attack "Instant Redirect to Phishing Page"; add_category "PHISHING"
  fi

  # Device fingerprinting
  if grep -qiE "navigator\.geolocation|getBattery|deviceorientation|getUserMedia|mediaDevices\.enumerate|canvas\.fingerprint|AudioContext|webgl" "$PAGE" 2>/dev/null; then
    add_reason "Device fingerprinting APIs (geolocation/canvas/WebGL/audio)"
    score_add 1; add_attack "Device Fingerprinting / Tracking"; add_category "PRIVACY RISK"
  fi

  # Popup abuse / scareware
  POPUP_COUNT=$(grep -ciE "window\.open\s*\(|alert\s*\(|confirm\s*\(|prompt\s*\(|\.modal|popup|overlay" "$PAGE" 2>/dev/null || true)
  if [ "${POPUP_COUNT:-0}" -gt 5 ]; then
    add_reason "Excessive popup/modal/alert calls ($POPUP_COUNT) — scareware pattern"
    score_add 3; add_attack "Scareware / Popup Abuse"; add_category "SOCIAL ENGINEERING"
  fi

  # Suspicious external scripts
  SUSP_SCRIPTS=$(grep -oE "src\s*=\s*['\"][^'\"]*['\"]" "$PAGE" 2>/dev/null \
    | grep -vE "($BASE_DOMAIN|googleapis|jquery|bootstrap|cloudflare|gstatic|jsdelivr|unpkg|cdnjs|fontawesome|recaptcha)" \
    | wc -l | tr -d ' ' || echo "0")
  if [ "${SUSP_SCRIPTS:-0}" -gt 2 ]; then
    add_reason "$SUSP_SCRIPTS scripts from unrecognized external domains"
    score_add 2; add_attack "External Script Injection / Supply Chain Attack"; add_category "SUPPLY CHAIN"
  fi

  # HTTP response anomalies
  if [[ "$HTTP_CODE" == "403" ]] || [[ "$HTTP_CODE" == "401" ]]; then
    verbose_log "HTTP $HTTP_CODE — access restricted"
  elif [[ "$HTTP_CODE" == "0" ]] || [[ "$HTTP_CODE" == "000" ]]; then
    add_reason "No HTTP response — server blocking scanners or offline"
    score_add 1
  fi

fi  # end page scan block

# ══════════════════════════════════════════════════════════════════════════════
# ██  MODULE 7: OFFLINE / LOCAL FILE SCAN (extra checks)  ██
# ══════════════════════════════════════════════════════════════════════════════
if [ "$FILE_MODE" = true ] && [ -f "$PAGE" ]; then
  status_log "Running offline file security analysis..."

  # PHP code injection in HTML
  if grep -qiE "<\?php|\?>" "$PAGE" 2>/dev/null; then
    PHP_DANGEROUS=$(grep -iE "shell_exec|exec\s*\(|system\s*\(|passthru|eval\s*\(" "$PAGE" 2>/dev/null | wc -l | tr -d ' ')
    if [ "${PHP_DANGEROUS:-0}" -gt 0 ]; then
      add_reason "PHP code with dangerous functions (exec/system/eval) in file"
      score_add 8; add_attack "PHP Code Injection / RCE Functions"; add_category "CRITICAL VULNERABILITY"
    fi
  fi

  # Embedded PE/EXE in HTML
  if grep -qiE "MZ.{0,2}PE" "$PAGE" 2>/dev/null; then
    add_reason "Windows PE/EXE binary signature embedded in HTML file"
    score_add 10; add_attack "Embedded Executable (Trojan Dropper)"; add_category "MALWARE"
  fi

  # Suspicious iframes pointing to external IPs
  EXT_IFRAMES=$(grep -oiE "iframe[^>]+src\s*=\s*['\"][^'\"]*['\"]" "$PAGE" 2>/dev/null \
    | grep -oiE "src\s*=\s*['\"][^'\"]*['\"]" \
    | grep -iE "https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" || true)
  if [ -n "$EXT_IFRAMES" ]; then
    add_reason "Iframe pointing to raw IP address (possible exploit kit)"
    score_add 6; add_attack "Exploit Kit via IP-based iframe"; add_category "MALWARE"
  fi

  # JavaScript keylogger pattern
  if grep -qiE "keydown|keypress|keyup|onkey" "$PAGE" 2>/dev/null && \
     grep -qiE "XMLHttpRequest|fetch\s*\(|sendBeacon|navigator\.sendBeacon" "$PAGE" 2>/dev/null; then
    add_reason "Keylogger pattern: key event listener + async HTTP exfiltration"
    score_add 8; add_attack "JavaScript Keylogger"; add_category "MALWARE"
  fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# ██  MODULE 8: BRUTE-FORCE SURFACE DETECTION  ██
# ══════════════════════════════════════════════════════════════════════════════
if [ "$BRUTE_SURFACE" = true ] && [ "$CURL_OK" = true ] && [ "$FILE_MODE" = false ]; then
  status_log "Detecting brute-force attack surfaces..."
  SCHEME=$(echo "$FINAL_URL" | grep -oE "^https?://")
  ORIGIN="${SCHEME}${BASE_DOMAIN}"

  for LOGIN_PATH in "/login" "/wp-login.php" "/admin/login" "/user/login" \
                    "/auth/login" "/signin" "/account/login" "/panel" "/cpanel" \
                    "/phpmyadmin" "/adminer" "/manager/html" "/jenkins"; do
    CODE=$(http_get_code "${ORIGIN}${LOGIN_PATH}" 2>/dev/null || echo "000")
    if [[ "$CODE" == "200" ]] || [[ "$CODE" == "301" ]] || [[ "$CODE" == "302" ]]; then
      add_reason "Login/admin panel accessible: ${LOGIN_PATH} (HTTP $CODE)"
      score_add 2; add_attack "Brute Force Target: ${LOGIN_PATH}"; add_category "BRUTE FORCE SURFACE"
    fi
  done
fi

# ══════════════════════════════════════════════════════════════════════════════
# SCORE NORMALIZATION & VERDICT
# ══════════════════════════════════════════════════════════════════════════════
SCORE=$(( (RAW_SCORE * 10 + MAX_RAW / 2) / MAX_RAW ))
[ "$SCORE" -gt 10 ] && SCORE=10

if [ "$IS_TRUSTED" = true ]; then
  SCORE=0
  VERDICT="SAFE"
  VERDICT_MSG="SAFE — Verified trusted domain"
  VERDICT_COLOR="$GREEN"
elif [ "$SCORE" -ge 8 ]; then
  VERDICT="CRITICAL"
  VERDICT_MSG="CRITICAL — Active exploit or confirmed malware/phishing"
  VERDICT_COLOR="$RED"
elif [ "$SCORE" -ge 6 ]; then
  VERDICT="DANGEROUS"
  VERDICT_MSG="DANGEROUS — Strong malicious indicators"
  VERDICT_COLOR="$RED"
elif [ "$SCORE" -ge 4 ]; then
  VERDICT="HIGH RISK"
  VERDICT_MSG="HIGH RISK — Likely malicious or seriously misconfigured"
  VERDICT_COLOR="${ORANGE:-$YELLOW}"
elif [ "$SCORE" -ge 2 ]; then
  VERDICT="SUSPICIOUS"
  VERDICT_MSG="SUSPICIOUS — Exercise extreme caution"
  VERDICT_COLOR="$YELLOW"
else
  VERDICT="LOW RISK"
  VERDICT_MSG="LOW RISK — No major indicators detected"
  VERDICT_COLOR="$GREEN"
fi

# ── Risk bar ─────────────────────────────────────────────────────────────────
build_bar() {
  local s=$1 bar=""
  for i in $(seq 1 10); do
    if [ $i -le $s ]; then
      if   [ $s -ge 8 ]; then bar+="█"
      elif [ $s -ge 6 ]; then bar+="▓"
      elif [ $s -ge 4 ]; then bar+="▒"
      elif [ $s -ge 2 ]; then bar+="▒"
      else bar+="░"
      fi
    else
      bar+="░"
    fi
  done
  echo "$bar"
}
BAR=$(build_bar "$SCORE")

# ══════════════════════════════════════════════════════════════════════════════
# CONSOLE OUTPUT
# ══════════════════════════════════════════════════════════════════════════════
if [ "$SILENT" = false ]; then
  echo ""
  echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${BOLD}${CYAN}║       Login Trust — COMPREHENSIVE SECURITY REPORT                    ║${RESET}"
  echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════════════╝${RESET}"
  echo ""
  echo -e "${BOLD}Target      :${RESET} $TARGET"
  echo -e "${BOLD}Final URL   :${RESET} $FINAL_URL"
  echo -e "${BOLD}Domain      :${RESET} $BASE_DOMAIN"
  echo -e "${BOLD}HTTP Status :${RESET} $HTTP_CODE"
  echo -e "${BOLD}Page Size   :${RESET} $PAGE_SIZE bytes"
  echo -e "${BOLD}Scan Mode   :${RESET} $([ "$FILE_MODE" = true ] && echo "FILE" || ([ "$OFFLINE_MODE" = true ] && echo "OFFLINE" || ([ "$NETWORK_MODE" = true ] && echo "NETWORK" || echo "ONLINE")))"
  echo -e "${BOLD}Platform    :${RESET} $OS"
  echo ""

  # Tools available
  TOOL_STR=""
  [ "$NMAP_OK" = true ]    && TOOL_STR+="nmap "
  [ "$WHOIS_OK" = true ]   && TOOL_STR+="whois "
  [ "$DIG_OK" = true ]     && TOOL_STR+="dig "
  [ "$OPENSSL_OK" = true ] && TOOL_STR+="openssl "
  [ "$NC_OK" = true ]      && TOOL_STR+="nc "
  [ "$JQ_OK" = true ]      && TOOL_STR+="jq "
  [ -n "$TOOL_STR" ] && echo -e "${DIM}Tools: $TOOL_STR${RESET}" && echo ""

  # API results (online only)
  if [ "$OFFLINE_MODE" = false ] && [ "$FILE_MODE" = false ] && [ "$NETWORK_MODE" = false ]; then
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━ THREAT INTELLIGENCE APIs ━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    if [ -n "$VT_API_KEY" ]; then
      VT_STATUS=$(printf '%s\n' "${API_FLAGS[@]}" | grep "^VT:" | head -1 || echo "VT:SKIPPED")
      echo -e "  ${CYAN}VirusTotal         :${RESET} $VT_STATUS"
    else
      echo -e "  ${DIM}VirusTotal         : No key — set VT_API_KEY${RESET}"
    fi
    if [ -n "$GSB_API_KEY" ]; then
      GSB_STATUS=$(printf '%s\n' "${API_FLAGS[@]}" | grep "^GSB:" | head -1 || echo "GSB:SKIPPED")
      echo -e "  ${CYAN}Google Safe Browse :${RESET} $GSB_STATUS"
    else
      echo -e "  ${DIM}Google Safe Browse : No key — set GSB_API_KEY${RESET}"
    fi
    PT_STATUS=$(printf '%s\n' "${API_FLAGS[@]}" | grep "^PHISHTANK:" | head -1 || echo "PHISHTANK:SKIPPED")
    echo -e "  ${CYAN}PhishTank          :${RESET} $PT_STATUS"
    if [ -n "$ABUSEIPDB_KEY" ]; then
      AB_STATUS=$(printf '%s\n' "${API_FLAGS[@]}" | grep "^ABUSEIPDB:" | head -1 || echo "ABUSEIPDB:SKIPPED")
      echo -e "  ${CYAN}AbuseIPDB          :${RESET} $AB_STATUS"
    fi
    echo ""
  fi

  # Port scan results
  if [ "${#PORT_RESULTS[@]}" -gt 0 ]; then
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━ PORT SCAN RESULTS ━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    for p in "${PORT_RESULTS[@]}"; do echo -e "  ${CYAN}»${RESET} $p"; done
    echo ""
  fi

  echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━ RISK SCORE ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo ""
  echo -e "  Score   : ${VERDICT_COLOR}${BOLD}$SCORE / 10${RESET}  ${DIM}(raw: $RAW_SCORE)${RESET}"
  echo -e "  Gauge   : ${VERDICT_COLOR}[$BAR]${RESET}"
  echo -e "  Verdict : ${VERDICT_COLOR}${BOLD}$VERDICT_MSG${RESET}"
  echo ""

  echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━ DETECTED INDICATORS ━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  if [ "${#REASONS[@]}" -gt 0 ]; then
    for r in "${REASONS[@]}"; do echo -e "  ${YELLOW}▶${RESET} $r"; done
  else
    echo -e "  ${GREEN}✓${RESET} No suspicious indicators found"
  fi
  echo ""

  echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━ ATTACK VECTORS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  if [ "${#ATTACK_TYPES[@]}" -gt 0 ]; then
    for a in "${ATTACK_TYPES[@]}"; do echo -e "  ${RED}⚠${RESET} $a"; done
  else
    echo -e "  ${GREEN}✓${RESET} No attack vectors identified"
  fi
  echo ""

  echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━ THREAT CATEGORIES ━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  if [ "${#CATEGORIES[@]}" -gt 0 ]; then
    for c in "${CATEGORIES[@]}"; do echo -e "  ${MAGENTA}◆${RESET} $c"; done
  else
    echo -e "  ${GREEN}✓${RESET} No threat categories identified"
  fi
  echo ""

  if [ "${#VULN_DETAILS[@]}" -gt 0 ]; then
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━ VULNERABILITY DETAILS ━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    for v in "${VULN_DETAILS[@]}"; do echo -e "  ${RED}⛔${RESET} $v"; done
    echo ""
  fi

  echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━ SECURITY ADVICE ━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  if [ "$IS_TRUSTED" = true ]; then
    echo -e "  ${GREEN}✓${RESET} Verified trusted domain — safe to proceed"
    echo -e "  ${GREEN}✓${RESET} Always verify the URL in your address bar"
  elif [ "$VERDICT" = "CRITICAL" ] || [ "$VERDICT" = "DANGEROUS" ]; then
    echo -e "  ${RED}⛔${RESET} DO NOT PROCEED — Active threats confirmed"
    echo -e "  ${RED}⛔${RESET} Never enter passwords, OTPs, card numbers, or personal data"
    echo -e "  ${RED}⛔${RESET} Close this site/file immediately"
    echo -e "  ${RED}⛔${RESET} Report phishing : https://safebrowsing.google.com/safebrowsing/report_phish/"
    echo -e "  ${RED}⛔${RESET} Report malware  : https://www.virustotal.com/"
    [ "$FILE_MODE" = true ] && echo -e "  ${RED}⛔${RESET} Delete or quarantine this file immediately"
  elif [ "$VERDICT" = "HIGH RISK" ]; then
    echo -e "  ${ORANGE:-$YELLOW}⚠${RESET}  DO NOT ENTER credentials — high risk"
    echo -e "  ${ORANGE:-$YELLOW}⚠${RESET}  Contact the real company directly if directed here"
    echo -e "  ${ORANGE:-$YELLOW}⚠${RESET}  Report: https://www.phishtank.com/"
  elif [ "$VERDICT" = "SUSPICIOUS" ]; then
    echo -e "  ${YELLOW}⚠${RESET}  Exercise EXTREME CAUTION before entering any data"
    echo -e "  ${YELLOW}⚠${RESET}  Verify URL carefully — may be impersonating a real service"
    echo -e "  ${YELLOW}⚠${RESET}  Use a password manager — it won't auto-fill on fake sites"
  else
    echo -e "  ${GREEN}✓${RESET} No major warning signs detected"
    echo -e "  ${GREEN}✓${RESET} Still verify URL and HTTPS before entering any data"
  fi
  echo ""

  # Suggest missing tools
  if [ "$NMAP_OK" = false ] && [ "$NC_OK" = false ]; then
    echo -e "${DIM}💡 Install nmap for port scanning: apt-get install nmap  |  brew install nmap${RESET}"
  fi
  if [ "$WHOIS_OK" = false ]; then
    echo -e "${DIM}💡 Install whois for domain age: apt-get install whois${RESET}"
  fi
  if [ "$DIG_OK" = false ]; then
    echo -e "${DIM}💡 Install dig for DNS analysis: apt-get install dnsutils${RESET}"
  fi
  echo ""
fi

# ══════════════════════════════════════════════════════════════════════════════
# JSON OUTPUT
# ══════════════════════════════════════════════════════════════════════════════
if [ "$OUTPUT_JSON" = true ]; then
  json_array() {
    local arr=("$@")
    if [ "${#arr[@]}" -eq 0 ]; then echo "[]"; return; fi
    local out="["
    for item in "${arr[@]}"; do
      out+="\"$(echo "$item" | sed 's/\\/\\\\/g;s/"/\\"/g')\","
    done
    echo "${out%,}]"
  }
  cat <<EOF
{
  "scan_time": "$DATE",
  "target": "$TARGET",
  "url": "$FINAL_URL",
  "domain": "$BASE_DOMAIN",
  "root_domain": "$ROOT_DOMAIN",
  "http_code": "$HTTP_CODE",
  "page_size_bytes": $PAGE_SIZE,
  "scan_mode": "$([ "$FILE_MODE" = true ] && echo "file" || ([ "$OFFLINE_MODE" = true ] && echo "offline" || ([ "$NETWORK_MODE" = true ] && echo "network" || echo "online")))",
  "is_trusted": $IS_TRUSTED,
  "raw_score": $RAW_SCORE,
  "risk_score": $SCORE,
  "verdict": "$VERDICT",
  "verdict_message": "$VERDICT_MSG",
  "virustotal_positives": ${VT_POSITIVES:-0},
  "google_safe_browsing": "${GSB_THREAT:-CLEAN}",
  "phishtank": "${PHISHTANK_RESULT:-UNKNOWN}",
  "abuseipdb_score": ${ABUSEIPDB_SCORE:-0},
  "api_flags": $(json_array "${API_FLAGS[@]}"),
  "indicators": $(json_array "${REASONS[@]}"),
  "attack_vectors": $(json_array "${ATTACK_TYPES[@]}"),
  "threat_categories": $(json_array "${CATEGORIES[@]}"),
  "port_scan_results": $(json_array "${PORT_RESULTS[@]}"),
  "vulnerability_details": $(json_array "${VULN_DETAILS[@]}")
}
EOF
fi

# ══════════════════════════════════════════════════════════════════════════════
# REPORT FILE
# ══════════════════════════════════════════════════════════════════════════════
if [ "$NO_REPORT" = false ]; then
  {
    echo "╔══════════════════════════════════════════════════════════════════════╗"
    echo "║       Login Trust — SECURITY ANALYSIS REPORT                         ║"
    echo "╚══════════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Scan Time   : $DATE"
    echo "Target      : $TARGET"
    echo "Final URL   : $FINAL_URL"
    echo "Domain      : $BASE_DOMAIN"
    echo "Root Domain : $ROOT_DOMAIN"
    echo "HTTP Status : $HTTP_CODE"
    echo "Page Size   : $PAGE_SIZE bytes"
    echo "Scan Mode   : $([ "$FILE_MODE" = true ] && echo "FILE" || ([ "$OFFLINE_MODE" = true ] && echo "OFFLINE" || ([ "$NETWORK_MODE" = true ] && echo "NETWORK" || echo "ONLINE")))"
    echo "OS Platform : $OS"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "THREAT INTELLIGENCE API RESULTS"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    # FIX: safe array expansion — always non-empty due to initialisation at top
    if [ "${#API_FLAGS[@]}" -gt 0 ]; then
      printf '  %s\n' "${API_FLAGS[@]}"
    else
      echo "  NONE"
    fi
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "PORT SCAN RESULTS"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if [ "${#PORT_RESULTS[@]}" -gt 0 ]; then
      for p in "${PORT_RESULTS[@]}"; do echo "  $p"; done
    else
      echo "  (port scan not enabled or no open ports found)"
    fi
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "RISK ASSESSMENT"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Raw Score   : $RAW_SCORE"
    echo "Risk Score  : $SCORE / 10"
    echo "Risk Gauge  : [$BAR]"
    echo "Verdict     : $VERDICT_MSG"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "DETECTED INDICATORS"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if [ "${#REASONS[@]}" -gt 0 ]; then
      for r in "${REASONS[@]}"; do echo "  ▶ $r"; done
    else
      echo "  ✓ No suspicious indicators found"
    fi
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "ATTACK VECTORS DETECTED"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if [ "${#ATTACK_TYPES[@]}" -gt 0 ]; then
      for a in "${ATTACK_TYPES[@]}"; do echo "  ⚠ $a"; done
    else
      echo "  ✓ No attack vectors identified"
    fi
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "THREAT CATEGORIES"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if [ "${#CATEGORIES[@]}" -gt 0 ]; then
      for c in "${CATEGORIES[@]}"; do echo "  ◆ $c"; done
    else
      echo "  ✓ No threat categories identified"
    fi
    echo ""
    if [ "${#VULN_DETAILS[@]}" -gt 0 ]; then
      echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
      echo "VULNERABILITY DETAILS"
      echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
      for v in "${VULN_DETAILS[@]}"; do echo "  ⛔ $v"; done
      echo ""
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "RECOMMENDATIONS"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if [ "$IS_TRUSTED" = true ]; then
      echo "  ✓ Verified trusted domain. Safe to proceed."
    elif [ "$VERDICT" = "CRITICAL" ] || [ "$VERDICT" = "DANGEROUS" ]; then
      echo "  ⛔ DO NOT PROCEED — Active threats confirmed"
      echo "  ⛔ Report phishing: https://safebrowsing.google.com/safebrowsing/report_phish/"
      echo "  ⛔ Report malware:  https://www.virustotal.com/"
      [ "$FILE_MODE" = true ] && echo "  ⛔ Delete or quarantine this file immediately"
    elif [ "$VERDICT" = "HIGH RISK" ]; then
      echo "  ⚠  Do not enter any credentials or personal information"
      echo "  ⚠  Report at: https://www.phishtank.com/"
    elif [ "$VERDICT" = "SUSPICIOUS" ]; then
      echo "  ⚠  Verify the URL carefully before proceeding"
      echo "  ⚠  Use a password manager — it won't auto-fill on fake sites"
    else
      echo "  ✓ No major issues detected — standard vigilance advised"
      echo "  ✓ Always verify HTTPS and URL before entering data"
    fi
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "COVERAGE — 60+ ATTACK VECTORS SCANNED"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  WEB:  SQLi, XSS (DOM/Reflected/Stored), CSRF, SSRF, XXE, Open Redirect"
    echo "        Path Traversal/LFI, Command Injection, SSTI, Insecure Deserialization"
    echo "        CORS Misconfiguration, Clickjacking, Secret Exposure, API Security"
    echo "  NET:  Port Scan, Service Fingerprinting, SMB/RDP/VNC/Redis/MongoDB exposure"
    echo "        SSL/TLS Attacks (POODLE/BEAST/DROWN/Heartbleed), MitM, DNS Hijacking"
    echo "        Zone Transfer, Subdomain Takeover, SPF/DMARC Email Spoofing"
    echo "  APP:  WordPress/Joomla/Drupal/Laravel CVEs, Webshell Detection"
    echo "        JWT Exposure, GraphQL Attacks, Brute Force Surfaces"
    echo "  MALWARE: Cryptojacking, Drive-by Download, Keylogger, Clipboard Hijacking"
    echo "        Embedded Executables, Obfuscated JS, Credential Harvesting"
    echo "  SOCIAL: Phishing, Urgency Manipulation, Brand Impersonation, AiTM/OTP"
    echo "        Fake Trust Seals, Crypto Scams, Financial Fraud"
    echo "  INTELLIGENCE: VirusTotal, Google Safe Browsing, PhishTank, AbuseIPDB"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "TOOL AVAILABILITY"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  curl    : $CURL_OK  |  wget : $WGET_OK  |  whois : $WHOIS_OK"
    echo "  dig     : $DIG_OK   |  nmap : $NMAP_OK  |  nc    : $NC_OK"
    echo "  openssl : $OPENSSL_OK  |  jq : $JQ_OK   |  python3 : $PYTHON3_OK"
    echo ""
    echo "  To enable all features:"
    echo "  Linux : sudo apt-get install curl whois dnsutils nmap openssl jq python3"
    echo "  macOS : brew install curl whois nmap openssl jq"
    echo "  Win   : Install WSL2 + Ubuntu, then run the Linux command above"
  } > "$REPORT_NAME"

  [ "$SILENT" = false ] && echo -e "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  [ "$SILENT" = false ] && echo -e "📄 Report saved: ${BOLD}$REPORT_NAME${RESET}"
  [ "$SILENT" = false ] && echo ""
fi

# ── API key hints ─────────────────────────────────────────────────────────────
# if [ "$SILENT" = false ] && [ "$OFFLINE_MODE" = false ] && [ "$FILE_MODE" = false ]; then
#   if [ -z "$VT_API_KEY" ] || [ -z "$GSB_API_KEY" ]; then
#     echo -e "${YELLOW}💡 Add free API keys for confirmed threat intelligence:${RESET}"
#     [ -z "$VT_API_KEY"    ] && echo -e "   ${DIM}export VT_API_KEY=...       # free at virustotal.com (90 AV engines)${RESET}"
#     [ -z "$GSB_API_KEY"   ] && echo -e "   ${DIM}export GSB_API_KEY=...      # free at console.cloud.google.com${RESET}"
#     [ -z "$ABUSEIPDB_KEY" ] && echo -e "   ${DIM}export ABUSEIPDB_KEY=...    # free at abuseipdb.com${RESET}"
#     echo ""
#   fi
# fi

# ══════════════════════════════════════════════════════════════════════
# FINAL OUTPUT FOR FLASK (STDOUT) ✅
# ══════════════════════════════════════════════════════════════════════

echo ""
echo "===== FINAL RESULT ====="
echo "Risk Score: $SCORE"

for r in "${REASONS[@]}"; do
  echo "- $r"
done

# ══════════════════════════════════════════════════════════════════════════════
# EXIT CODES
# ══════════════════════════════════════════════════════════════════════════════
case "$VERDICT" in
  "CRITICAL")   exit 4 ;;
  "DANGEROUS")  exit 3 ;;
  "HIGH RISK")  exit 2 ;;
  "SUSPICIOUS") exit 1 ;;
  *)            exit 0 ;;
esac