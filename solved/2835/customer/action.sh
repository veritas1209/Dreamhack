#!/bin/bash

TARGET_URL="http://wargame:5000/downloads/wargame"
SAVE_PATH="/tmp/wargame"

sleep 5

while true; do
  echo "[$(date)] Downloading file..."
  curl -f "$TARGET_URL" -o "$SAVE_PATH"

  if [ -s "$SAVE_PATH" ]; then
    chmod +x "$SAVE_PATH"
    echo "Executing: $SAVE_PATH"
    "$SAVE_PATH"
    EXIT_CODE=$?
    if [ $EXIT_CODE -eq 0 ]; then
      echo "Succeed (Exit Code: 0)"
    else
      echo "Error (Exit Code: $EXIT_CODE)"
    fi
    rm "$SAVE_PATH"
  else
    echo "Failed to download a file."
    rm -f "$SAVE_PATH"
  fi

  echo "Waiting..."
  sleep 10
done