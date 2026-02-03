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
    check_pattern "CRITICAL" "Raw IP address in command" '\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b.*(curl|wget|bash|sh)|(curl|wget|bash|sh).*\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b' "$skill_path" || true
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
