#!/bin/bash
# scan-skill.sh - Security scanner for Clawdbot skills
# Usage: ./scan-skill.sh /path/to/skill/folder
#
# Created: 2026-01-30
# Updated: 2026-02-03 - Added mandatory Clawdex remote check
# Reference: https://opensourcemalware.com/blog/clawdbot-skills-ganked-your-crypto

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

if [ $# -eq 0 ]; then
    echo "Usage: $0 /path/to/skill/folder"
    echo "       $0 --all  (scan all local skills)"
    exit 1
fi

CRITICAL_COUNT=0
WARNING_COUNT=0
VT_SCANNED=""
CLAMAV_SCANNED=""
LF_SCANNED=""

# Clawdex API check - mandatory remote verification
check_clawdex() {
    local skill_name="$1"
    local api_url="https://clawdex.koi.security/api/skill/${skill_name}"

    echo -e "${BLUE}🔍 Checking Clawdex database...${NC}"

    local response
    local http_code

    # Make API request, capture both response body and HTTP code
    response=$(curl -s -w "\n%{http_code}" "$api_url" 2>/dev/null || echo -e "\n000")
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    if [ "$http_code" = "000" ]; then
        echo -e "${YELLOW}⚠️  Clawdex API unavailable (network error)${NC}"
        echo "    Falling back to local scan only..."
        echo ""
        return 1
    elif [ "$http_code" = "404" ]; then
        echo -e "${YELLOW}⚠️  Clawdex: Unknown skill (not in database)${NC}"
        echo "    Proceeding with local deep scan..."
        echo ""
        return 1
    elif [ "$http_code" != "200" ]; then
        echo -e "${YELLOW}⚠️  Clawdex API error (HTTP $http_code)${NC}"
        echo "    Falling back to local scan only..."
        echo ""
        return 1
    fi

    # Parse verdict from response
    local verdict
    verdict=$(echo "$body" | grep -o '"verdict":"[^"]*"' | cut -d'"' -f4)

    if [ -z "$verdict" ]; then
        echo -e "${YELLOW}⚠️  Clawdex: Could not parse verdict${NC}"
        echo "    Proceeding with local deep scan..."
        echo ""
        return 1
    fi

    case "$verdict" in
        "malicious")
            echo -e "${RED}🚨 Clawdex: MALICIOUS${NC}"
            echo ""
            echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo -e "${RED}RESULT: BLOCKED - Skill flagged as malicious by Clawdex${NC}"
            echo -e "${RED}DO NOT USE THIS SKILL${NC}"
            echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo ""
            exit 2
            ;;
        "benign")
            echo -e "${GREEN}✅ Clawdex: Benign${NC}"
            echo "    Proceeding with local deep scan for defense in depth..."
            echo ""
            return 0
            ;;
        *)
            echo -e "${YELLOW}⚠️  Clawdex: Unknown verdict ($verdict)${NC}"
            echo "    Proceeding with local deep scan..."
            echo ""
            return 1
            ;;
    esac
}

check_pattern() {
    local level="$1"
    local description="$2"
    local pattern="$3"
    local path="$4"

    if grep -rqE "$pattern" "$path" 2>/dev/null; then
        if [ "$level" = "CRITICAL" ]; then
            echo -e "${RED}🚨 CRITICAL:${NC} $description"
            grep -rnE "$pattern" "$path" 2>/dev/null | head -5 | sed 's/^/   /'
            ((CRITICAL_COUNT++)) || true
        else
            echo -e "${YELLOW}⚠️  WARNING:${NC} $description"
            grep -rnE "$pattern" "$path" 2>/dev/null | head -3 | sed 's/^/   /'
            ((WARNING_COUNT++)) || true
        fi
        echo ""
        return 0
    fi
    return 1
}

# VirusTotal API scan
check_virustotal() {
    local skill_path="$1"
    local api_key=""

    # Try env var first, then config file
    if [ -n "${VIRUSTOTAL_API_KEY:-}" ]; then
        api_key="$VIRUSTOTAL_API_KEY"
    elif [ -f "$HOME/.config/openclaw-skill-scanner/virustotal.key" ]; then
        api_key=$(tr -d '[:space:]' < "$HOME/.config/openclaw-skill-scanner/virustotal.key")
    fi

    if [ -z "$api_key" ]; then
        echo -e "${YELLOW}⚠️  VirusTotal: Skipped (no API key set)${NC}"
        echo ""
        VT_SCANNED="nokey"
        return 0
    fi

    echo -e "${BLUE}🔍 VirusTotal: Scanning suspicious files...${NC}"
    echo ""

    # Collect suspicious files (by extension and executable permission)
    local tmpfile
    tmpfile=$(mktemp)
    find "$skill_path" -type f \( \
        -name "*.sh" -o -name "*.py" -o -name "*.js" -o -name "*.ts" \
        -o -name "*.exe" -o -name "*.dll" -o -name "*.so" -o -name "*.dylib" \
    \) 2>/dev/null >> "$tmpfile"
    # Add files with executable permission (macOS: +111, GNU: /111)
    find "$skill_path" -type f -perm +111 2>/dev/null >> "$tmpfile" || \
        find "$skill_path" -type f -perm /111 2>/dev/null >> "$tmpfile"

    # Deduplicate
    local -a files=()
    while IFS= read -r file; do
        [ -n "$file" ] && files+=("$file")
    done < <(sort -u "$tmpfile")
    rm -f "$tmpfile"

    if [ ${#files[@]} -eq 0 ]; then
        echo -e "${GREEN}   No suspicious file types found${NC}"
        echo ""
        VT_SCANNED="0"
        return 0
    fi

    local max_files=10
    local count=0
    local api_calls=0

    for file in "${files[@]}"; do
        if [ $count -ge $max_files ]; then
            echo -e "${YELLOW}   (capped at $max_files files)${NC}"
            break
        fi

        # Rate limiting: sleep 15s between API calls (free tier = 4 req/min)
        if [ $api_calls -gt 0 ]; then
            sleep 15
        fi

        local filename
        filename=$(basename "$file")
        local hash
        hash=$(shasum -a 256 "$file" | awk '{print $1}')

        # Query VirusTotal v3 API
        local response http_code body
        response=$(curl -s -w "\n%{http_code}" \
            -H "x-apikey: $api_key" \
            "https://www.virustotal.com/api/v3/files/$hash" 2>/dev/null || echo -e "\n000")
        http_code=$(echo "$response" | tail -n1)
        body=$(echo "$response" | sed '$d')
        ((api_calls++)) || true

        if [ "$http_code" = "000" ]; then
            echo -e "${YELLOW}   ⚠️  $filename: API unavailable${NC}"
            echo ""
            VT_SCANNED="unavailable"
            return 0
        elif [ "$http_code" = "404" ]; then
            # Hash unknown - upload file if under 32MB
            local file_size
            file_size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo "0")
            if [ "$file_size" -lt 33554432 ]; then
                sleep 15
                response=$(curl -s -w "\n%{http_code}" \
                    -H "x-apikey: $api_key" \
                    -F "file=@$file" \
                    "https://www.virustotal.com/api/v3/files" 2>/dev/null || echo -e "\n000")
                http_code=$(echo "$response" | tail -n1)
                ((api_calls++)) || true

                if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
                    echo -e "${YELLOW}   ⏳ $filename: Uploaded for analysis (check back later)${NC}"
                else
                    echo -e "${YELLOW}   ⚠️  $filename: Upload failed (HTTP $http_code)${NC}"
                fi
            else
                echo -e "${YELLOW}   ⚠️  $filename: Too large to upload (>32MB)${NC}"
            fi
            ((count++)) || true
            continue
        elif [ "$http_code" != "200" ]; then
            echo -e "${YELLOW}   ⚠️  $filename: API error (HTTP $http_code)${NC}"
            ((count++)) || true
            continue
        fi

        # Parse last_analysis_stats from response
        local malicious suspicious
        malicious=$(echo "$body" | grep -o '"malicious":[0-9]*' | head -1 | cut -d: -f2)
        suspicious=$(echo "$body" | grep -o '"suspicious":[0-9]*' | head -1 | cut -d: -f2)
        malicious=${malicious:-0}
        suspicious=${suspicious:-0}

        if [ "$malicious" -gt 0 ] 2>/dev/null; then
            echo -e "${RED}   🚨 $filename: MALICIOUS ($malicious detections)${NC}"
            ((CRITICAL_COUNT++)) || true
        elif [ "$suspicious" -gt 0 ] 2>/dev/null; then
            echo -e "${YELLOW}   ⚠️  $filename: Suspicious ($suspicious detections)${NC}"
            ((WARNING_COUNT++)) || true
        else
            echo -e "${GREEN}   ✅ $filename: Clean${NC}"
        fi

        ((count++)) || true
    done

    echo ""
    VT_SCANNED="$count"
}

check_clamav() {
    local skill_path="$1"

    # Check if clamscan is available
    if ! command -v clamscan &>/dev/null; then
        echo -e "${YELLOW}⚠️  ClamAV: Skipped (clamscan not found)${NC}"
        echo ""
        CLAMAV_SCANNED="notfound"
        return 0
    fi

    echo -e "${BLUE}🔍 ClamAV: Scanning for malware...${NC}"

    local clam_output
    clam_output=$(clamscan --infected --no-summary --recursive "$skill_path" 2>&1) || true
    local clam_exit=$?

    # Re-derive exit code from output (since || true resets it)
    if echo "$clam_output" | grep -q "FOUND"; then
        clam_exit=1
    fi

    if [ $clam_exit -eq 0 ]; then
        # No infections found
        echo -e "${GREEN}   ✅ No malware detected${NC}"
        echo ""
        CLAMAV_SCANNED="clean"
    elif [ $clam_exit -eq 1 ]; then
        # Infection found!
        local infected_count
        infected_count=$(echo "$clam_output" | grep -c "FOUND")
        echo -e "${RED}   🚨 MALWARE DETECTED (${infected_count} file(s)):${NC}"
        echo "$clam_output" | grep "FOUND" | sed 's/^/   /'
        echo ""
        ((CRITICAL_COUNT += infected_count)) || true
        CLAMAV_SCANNED="infected"
    else
        # Error (e.g., database issue)
        echo -e "${YELLOW}   ⚠️  ClamAV error (exit $clam_exit)${NC}"
        echo "$clam_output" | head -3 | sed 's/^/   /'
        echo ""
        CLAMAV_SCANNED="error"
    fi
}

check_llamafirewall() {
    local skill_path="$1"
    local helper="$HOME/clawd/projects/openclaw-skill-scanner/scan-llamafirewall.py"
    
    if ! command -v python3 &>/dev/null; then
        echo -e "${YELLOW}⚠️  ML Scan: Skipped (python3 not found)${NC}"
        echo ""
        LF_SCANNED="nopython"
        return 0
    fi
    
    if [ ! -f "$helper" ]; then
        echo -e "${YELLOW}⚠️  ML Scan: Skipped (helper script not found)${NC}"
        echo ""
        LF_SCANNED="nohelper"
        return 0
    fi
    
    echo -e "${BLUE}🔍 ML Scan: Scanning text files for injection patterns...${NC}"
    
    local lf_output
    lf_output=$(python3 "$helper" "$skill_path" 2>/dev/null) || true
    
    # Check for structured error from Python
    if echo "$lf_output" | grep -q "^ERROR="; then
        local err_msg
        err_msg=$(echo "$lf_output" | grep "^ERROR=" | cut -d= -f2-)
        echo -e "${YELLOW}   ⚠️  ML Scan error: ${err_msg}${NC}"
        echo ""
        LF_SCANNED="error"
        return 0
    fi
    
    if [ -z "$lf_output" ]; then
        echo -e "${YELLOW}   ⚠️  Scan error (no output)${NC}"
        echo ""
        LF_SCANNED="error"
        return 0
    fi
    
    local files_scanned
    files_scanned=$(echo "$lf_output" | grep "^FILES_SCANNED=" | cut -d= -f2)
    local findings_count
    findings_count=$(echo "$lf_output" | grep "^FINDINGS=" | cut -d= -f2)
    
    files_scanned=${files_scanned:-0}
    findings_count=${findings_count:-0}
    
    echo "   Scanned $files_scanned text files"
    
    if [ "$findings_count" -gt 0 ] 2>/dev/null; then
        echo -e "${RED}   🚨 INJECTION PATTERNS DETECTED (${findings_count} files):${NC}"
        echo "$lf_output" | grep "^FINDING\t" | while IFS=$'\t' read -r _ severity file reasons; do
            echo -e "      ${RED}$severity${NC}: $file ($reasons)"
        done
        echo ""
        # Count critical vs high by re-parsing
        local crit_count=0
        local warn_count=0
        crit_count=$(echo "$lf_output" | grep "^FINDING\tCRITICAL\t" | wc -l | tr -d ' ')
        warn_count=$(echo "$lf_output" | grep "^FINDING\tHIGH\t" | wc -l | tr -d ' ')
        crit_count=${crit_count:-0}
        warn_count=${warn_count:-0}
        ((CRITICAL_COUNT += crit_count)) || true
        ((WARNING_COUNT += warn_count)) || true
        LF_SCANNED="flagged"
    else
        echo -e "${GREEN}   ✅ No injection patterns detected${NC}"
        echo ""
        LF_SCANNED="clean"
    fi
}

check_raw_ip_commands() {
    local skill_path="$1"

    # Flag raw-IP fetch/exec commands; report whole lines for reviewer context.
    local raw_ip_command_pattern='\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b.*(curl|wget|bash|sh)|(curl|wget|bash|sh).*\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b'

    # Keep the original broad dotted-quad match; this change only allowlists
    # local placeholders, it does not try to become a strict IP parser.
    local ip_pattern='\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b'

    local matches=""
    local count=0
    local line
    local has_disallowed_ip=0
    local ip

    # Only local placeholders are ignored:
    # - 127.0.0.0/8 loopback
    # - 0.0.0.0/32 unspecified bind address, not loopback
    # Private LAN, documentation, and public IPs stay review-worthy.
    # Note: IPv6 loopback (::1) and hostname "localhost" are out of scope here —
    # the raw IP regex only matches dotted-quad IPv4, so ::1 is never flagged.
    while IFS= read -r line; do
        has_disallowed_ip=0

        # Check each IP so mixed local + external commands still fail.
        while IFS= read -r ip; do
            case "$ip" in
                127.*|0.0.0.0) ;;
                *)
                    has_disallowed_ip=1
                    break
                    ;;
            esac
        done < <(printf '%s\n' "$line" | grep -Eo "$ip_pattern")

        # Show first five offending lines; count this rule once below.
        if [ "$has_disallowed_ip" -eq 1 ]; then
            matches+="${line}"$'\n'
            ((count++)) || true
            if [ "$count" -ge 5 ]; then
                break
            fi
        fi
    done < <(grep -rnE "$raw_ip_command_pattern" "$skill_path" 2>/dev/null)

    if [ -n "$matches" ]; then
        echo -e "${RED}🚨 CRITICAL:${NC} Raw non-allowlisted IP address in command"
        printf '%s' "$matches" | sed 's/^/   /'
        # Intentionally increment CRITICAL_COUNT once per pattern (not per line),
        # consistent with existing check_pattern behavior.
        ((CRITICAL_COUNT++)) || true
        echo ""
        return 0
    fi
    return 1
}

scan_skill() {
    local skill_path="$1"
    local skill_name=$(basename "$skill_path")

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Scanning: $skill_name"
    echo "Path: $skill_path"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    # Step 1: Mandatory Clawdex remote check
    check_clawdex "$skill_name" || true

    # Step 2: Local deep scan (defense in depth)

    # Critical patterns
    check_pattern "CRITICAL" "Base64 decode command" "base64 -[dD]|base64 --decode" "$skill_path" || true
    check_raw_ip_commands "$skill_path" || true
    check_pattern "CRITICAL" "Known malicious IP (91.92.242.30)" '91\.92\.242\.30' "$skill_path" || true
    check_pattern "CRITICAL" "Gatekeeper bypass (xattr -c)" 'xattr -[cd]|xattr.*quarantine' "$skill_path" || true
    check_pattern "CRITICAL" "Curl piped to shell" 'curl[^|]*\|[[:space:]]*(ba)?sh|wget[^|]*\|[[:space:]]*(ba)?sh' "$skill_path" || true
    check_pattern "CRITICAL" "Download and execute pattern" 'curl.*-[oO].*&&.*chmod.*\+x.*&&.*\./' "$skill_path" || true
    check_pattern "CRITICAL" "Known malicious filenames" 'dx2w5j5bka6qkwxi|6x8c0trkp4l9uugo|AuthTool\.exe|PolymarketAuthTool' "$skill_path" || true

    # Warning patterns
    check_pattern "WARNING" "ZIP file download" '\.zip\b' "$skill_path" || true
    check_pattern "WARNING" "GitHub user releases download" 'github\.com/[^/]+/[^/]+/releases/download' "$skill_path" || true
    check_pattern "WARNING" "chmod +x on variable/download" 'chmod \+x.*\$|chmod \+x.*curl|chmod \+x.*wget' "$skill_path" || true
    check_pattern "WARNING" "Urgent/critical warnings" 'CRITICAL REQUIREMENT|MUST DOWNLOAD|REQUIRED.*BEFORE|⚠️.*CRITICAL' "$skill_path" || true
    check_pattern "WARNING" "Password for archive" 'password.*zip|zip.*password|extract.*password' "$skill_path" || true
    check_pattern "WARNING" "Known malicious authors" 'aslaep123|zaycv|gpaitai|lvy19811120-gif|danman60|keepcold131|Aslaep123' "$skill_path" || true

    # Step 3: VirusTotal scan
    check_virustotal "$skill_path"

    # Step 4: ClamAV malware scan
    check_clamav "$skill_path"

    # Step 5: LlamaFirewall ML scan
    check_llamafirewall "$skill_path"

    # Summary
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if [ $CRITICAL_COUNT -gt 0 ]; then
        echo -e "${RED}RESULT: FAILED - $CRITICAL_COUNT critical issue(s) found${NC}"
        echo "DO NOT USE THIS SKILL"
    elif [ $WARNING_COUNT -gt 0 ]; then
        echo -e "${YELLOW}RESULT: REVIEW NEEDED - $WARNING_COUNT warning(s) found${NC}"
        echo "Manual review required before use"
    else
        echo -e "${GREEN}✅ RESULT: PASSED${NC}"
        echo "   Clawdex: Checked"
        echo "   Local scan: No red flags detected"
        echo "   Skill appears safe (still review manually)"
    fi
    if [ "$VT_SCANNED" = "nokey" ]; then
        echo "   VirusTotal: Skipped (no API key)"
    elif [ "$VT_SCANNED" = "unavailable" ]; then
        echo "   VirusTotal: Skipped (API unavailable)"
    elif [ -n "$VT_SCANNED" ]; then
        echo "   VirusTotal: Checked ($VT_SCANNED files)"
    fi
    if [ "$CLAMAV_SCANNED" = "notfound" ]; then
        echo "   ClamAV: Skipped (not installed)"
    elif [ "$CLAMAV_SCANNED" = "clean" ]; then
        echo "   ClamAV: Clean"
    elif [ "$CLAMAV_SCANNED" = "infected" ]; then
        echo "   ClamAV: MALWARE DETECTED"
    fi
    if [ "$LF_SCANNED" = "nopython" ] || [ "$LF_SCANNED" = "nohelper" ]; then
        echo "   ML Scan: Skipped"
    elif [ "$LF_SCANNED" = "clean" ]; then
        echo "   ML Scan: Clean"
    elif [ "$LF_SCANNED" = "flagged" ]; then
        echo "   ML Scan: Flagged"
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
}

# Main
if [ "$1" = "--all" ]; then
    echo "Scanning all local skills..."
    echo ""

    # Scan bundled skills
    if [ -d "/opt/homebrew/lib/node_modules/clawdbot/skills" ]; then
        for skill in /opt/homebrew/lib/node_modules/clawdbot/skills/*/; do
            if [ -d "$skill" ]; then
                scan_skill "$skill"
                CRITICAL_COUNT=0
                WARNING_COUNT=0
                VT_SCANNED=""
                CLAMAV_SCANNED=""
                LF_SCANNED=""
            fi
        done
    fi

    # Scan local skills
    if [ -d "$HOME/clawd/skills" ]; then
        for skill in "$HOME/clawd/skills"/*/; do
            if [ -d "$skill" ]; then
                scan_skill "$skill"
                CRITICAL_COUNT=0
                WARNING_COUNT=0
                VT_SCANNED=""
                CLAMAV_SCANNED=""
                LF_SCANNED=""
            fi
        done
    fi
else
    if [ ! -d "$1" ]; then
        echo "Error: $1 is not a directory"
        exit 1
    fi
    scan_skill "$1"
fi

exit $CRITICAL_COUNT
