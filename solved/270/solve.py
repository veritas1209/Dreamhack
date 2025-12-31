#!/usr/bin/env python3
import base64
import math

def rot13_decode(text):
    """ROT13 디코딩"""
    result = []
    for char in text:
        if 'a' <= char <= 'z':
            result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= char <= 'Z':
            result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
        else:
            result.append(char)
    return ''.join(result)

def base64_decode(text):
    """Base64 디코딩"""
    try:
        return base64.b64decode(text).decode('utf-8')
    except Exception as e:
        return f"Error: {e}"

def rail_fence_decode(text, num_rails):
    """Rail Fence 디코딩"""
    if num_rails <= 1:
        return text
    
    length = len(text)
    fence = [['' for _ in range(length)] for _ in range(num_rails)]
    
    # 패턴 계산
    rail = 0
    direction = 1  # 1: down, -1: up
    
    # 패턴대로 위치 표시
    for col in range(length):
        fence[rail][col] = '*'
        if rail == 0:
            direction = 1
        elif rail == num_rails - 1:
            direction = -1
        rail += direction
    
    # 텍스트를 패턴에 채우기
    index = 0
    for row in range(num_rails):
        for col in range(length):
            if fence[row][col] == '*':
                fence[row][col] = text[index]
                index += 1
    
    # 지그재그로 읽기
    result = []
    rail = 0
    direction = 1
    for col in range(length):
        result.append(fence[rail][col])
        if rail == 0:
            direction = 1
        elif rail == num_rails - 1:
            direction = -1
        rail += direction
    
    return ''.join(result)

def main():
    encrypted = "EUg5MJAyYJ9fYJ5iMKqio29iVK1VL2WlnTM0o3AyL2Elq3q3qlRu"
    
    print("="*70)
    print("Crypto Challenge Decoder")
    print("="*70)
    print(f"Encrypted: {encrypted}")
    print("\nDecryption Process: ROT13 → Base64 → Rail Fence")
    print("="*70)
    
    # Step 1: ROT13 디코딩
    print("\n[Step 1] ROT13 Decode:")
    step1 = rot13_decode(encrypted)
    print(f"Result: {step1}")
    
    # Step 2: Base64 디코딩
    print("\n[Step 2] Base64 Decode:")
    step2 = base64_decode(step1)
    print(f"Result: {step2}")
    
    # Step 3: Rail Fence 디코딩 (여러 rails 시도)
    print("\n[Step 3] Rail Fence Decode (trying different rails):")
    print("-"*70)
    
    for rails in range(2, 6):
        try:
            result = rail_fence_decode(step2, rails)
            print(f"Rails {rails}: {result}")
            
            # DH{ 나 FLAG{ 패턴 찾기
            if "DH{" in result or "FLAG{" in result or "flag{" in result:
                print(f"\n{'='*70}")
                print(f"[!!!] FOUND FLAG with {rails} rails!")
                print(f"{'='*70}")
                print(f"FLAG: {result}")
                return
        except Exception as e:
            print(f"Rails {rails}: Error - {e}")
    
    print("\n" + "="*70)
    print("If no flag found, try manual combinations:")
    print("="*70)
    
    # 다양한 조합 시도
    print("\n[Alternative] Trying different order combinations:")
    
    # Base64 → ROT13 → Rail Fence
    print("\n1. Base64 → ROT13 → Rail Fence:")
    try:
        alt1 = base64_decode(encrypted)
        alt1_rot = rot13_decode(alt1)
        print(f"   After Base64+ROT13: {alt1_rot}")
        for rails in range(2, 6):
            result = rail_fence_decode(alt1_rot, rails)
            print(f"   Rails {rails}: {result}")
            if "DH{" in result or "FLAG{" in result:
                print(f"   [!!!] FOUND: {result}")
    except Exception as e:
        print(f"   Error: {e}")
    
    # Rail Fence → ROT13 → Base64
    print("\n2. Rail Fence → ROT13 → Base64:")
    for rails in range(2, 6):
        try:
            alt2 = rail_fence_decode(encrypted, rails)
            alt2_rot = rot13_decode(alt2)
            alt2_b64 = base64_decode(alt2_rot)
            print(f"   Rails {rails}: {alt2_b64}")
            if "DH{" in alt2_b64 or "FLAG{" in alt2_b64:
                print(f"   [!!!] FOUND: {alt2_b64}")
        except Exception as e:
            pass

if __name__ == "__main__":
    main()