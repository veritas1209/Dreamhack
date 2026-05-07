import base64
import re

# ==========================================
# [데이터 입력]
# 웹훅 서버에 찍힌 Base64 텍스트 전체를 넣어주세요.
# ==========================================
raw_data = """PCFET0NUWVBFIGh0bWw CjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ CiAgICA8bWV0YSBjaGFyc2V0PSJVVEYtOCI CiAgICA8bWV0YSBuYW1lPSJ2aWV3cG9ydCIgY29udGVudD0id2lkdGg9ZGV2aWNlLXdpZHRoLCBpbml0aWFsLXNjYWxlPTEuMCI CiAgICA8dGl0bGU V2hvIEFtIEk8L3RpdGxlPgogICAgPHN0eWxlPgogICAgICAgIGJvZHkgewogICAgICAgICAgICBmb250LWZhbWlseTogQXJpYWwsIHNhbnMtc2VyaWY7CiAgICAgICAgICAgIGJhY2tncm91bmQtY29sb3I6ICNmNGY0Zjk7CiAgICAgICAgICAgIG1hcmdpbjogMDsKICAgICAgICAgICAgcGFkZGluZzogMDsKICAgICAgICAgICAgZGlzcGxheTogZmxleDsKICAgICAgICAgICAganVzdGlmeS1jb250ZW50OiBjZW50ZXI7CiAgICAgICAgICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICAgICAgICAgIGhlaWdodDogMTAwdmg7CiAgICAgICAgfQogICAgICAgIC5jb250YWluZXIgewogICAgICAgICAgICBiYWNrZ3JvdW5kLWNvbG9yOiAjZmZmOwogICAgICAgICAgICBwYWRkaW5nOiAyMHB4OwogICAgICAgICAgICBib3JkZXItcmFkaXVzOiA4cHg7CiAgICAgICAgICAgIGJveC1zaGFkb3c6IDAgMnB4IDRweCByZ2JhKDAsIDAsIDAsIDAuMSk7CiAgICAgICAgICAgIG1heC13aWR0aDogNDAwcHg7CiAgICAgICAgICAgIHdpZHRoOiAxMDAlOwogICAgICAgICAgICB0ZXh0LWFsaWduOiBjZW50ZXI7CiAgICAgICAgfQogICAgICAgIGgxIHsKICAgICAgICAgICAgY29sb3I6ICMzMzM7CiAgICAgICAgfQogICAgICAgIHAgewogICAgICAgICAgICBjb2xvcjogIzU1NTsKICAgICAgICB9CiAgICAgICAgLmluZm8gewogICAgICAgICAgICBtYXJnaW4tdG9wOiAyMHB4OwogICAgICAgIH0KICAgICAgICBmb3JtIHsKICAgICAgICAgICAgZGlzcGxheTogZmxleDsKICAgICAgICAgICAgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsKICAgICAgICAgICAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICAgICAgICB9CiAgICAgICAgaW5wdXRbdHlwZT0idGV4dCJdLCB0ZXh0YXJlYSB7CiAgICAgICAgICAgIHBhZGRpbmc6IDEwcHg7CiAgICAgICAgICAgIG1hcmdpbjogMTBweCAwOwogICAgICAgICAgICB3aWR0aDogMTAwJTsKICAgICAgICAgICAgYm9yZGVyOiAxcHggc29saWQgI2NjYzsKICAgICAgICAgICAgYm9yZGVyLXJhZGl1czogNHB4OwogICAgICAgIH0KICAgICAgICBidXR0b24gewogICAgICAgICAgICBwYWRkaW5nOiAxMHB4IDIwcHg7CiAgICAgICAgICAgIGJvcmRlcjogbm9uZTsKICAgICAgICAgICAgYm9yZGVyLXJhZGl1czogNHB4OwogICAgICAgICAgICBiYWNrZ3JvdW5kLWNvbG9yOiAjMDA3YmZmOwogICAgICAgICAgICBjb2xvcjogI2ZmZjsKICAgICAgICAgICAgY3Vyc29yOiBwb2ludGVyOwogICAgICAgIH0KICAgICAgICBidXR0b246aG92ZXIgewogICAgICAgICAgICBiYWNrZ3JvdW5kLWNvbG9yOiAjMDA1NmIzOwogICAgICAgIH0KICAgIDwvc3R5bGU CjwvaGVhZD4KPGJvZHk CiAgICA8ZGl2IGNsYXNzPSJjb250YWluZXIiPgogICAgICAgIDxoMT5IZWxsbzwvaDE CiAgICAgICAgCiAgICAgICAgICAgIDxkaXYgY2xhc3M9ImluZm8iPgogICAgICAgICAgICAgICAgPHA PHN0cm9uZz5JRDo8L3N0cm9uZz4gYWRtaW48L3A CiAgICAgICAgICAgICAgICA8cD48c3Ryb25nPk1lc3NhZ2U6PC9zdHJvbmc IERIe2M1YzU5NDVlZjQ0YzRhYWU1YjMzMTk4NmNhNGU0NjQxOTU4MmI1NDA1ZjE5ZWJmZjhjYjA4YmNhMDdmNDFlNGZ9PC9wPgogICAgICAgICAgICA8L2Rpdj4KICAgICAgICAKICAgIDwvZGl2Pgo8L2JvZHk CjwvaHRtbD4="""

decoded_text = ""
# 공백을 기준으로 데이터를 조각냅니다.
chunks = raw_data.split()

print(f"[DEBUG] 총 {len(chunks)}개의 데이터 조각을 발견했습니다.")

for chunk in chunks:
    # 각 조각의 길이가 4의 배수가 되도록 패딩(=)을 계산해서 붙입니다.
    pad_count = (4 - (len(chunk) % 4)) % 4
    padded_chunk = chunk + ("=" * pad_count)
    
    try:
        decoded_bytes = base64.b64decode(padded_chunk)
        # 디코딩된 바이트를 문자열로 변환하여 누적합니다.
        decoded_text += decoded_bytes.decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"[!] 디코딩 에러 발생 조각 ({chunk}): {e}")

print("\n================== [정상 디코딩된 전체 HTML 본문] ==================")
print(decoded_text)
print("====================================================================\n")

# 정규식을 통해 실제 플래그 탐색
print("[DEBUG] 정규식(DH{...}) 탐색 시도 중...")
flags = re.findall(r'DH\{.*?\}', decoded_text)

if flags:
    for idx, flag in enumerate(flags):
        print(f"  -> 🚩 찾은 진짜 플래그 [{idx + 1}]: {flag}")
else:
    print("  -> ⚠️ 디코딩은 정상적으로 되었으나, 텍스트 내에서 'DH{...}' 플래그를 찾지 못했습니다.")