# gyul_bomb_maker.py
flag = b"B1N4RY{fake_flag}"

# 2비트 -> 제로폭 문자 매핑
# 00 -> ZWSP (U+200B)
# 01 -> ZWNJ (U+200C)
# 10 -> ZWJ  (U+200D)
# 11 -> ZWNBSP/BOM (U+FEFF)
bit_to_zw = {
    "00": "\u200b",  # zero width space
    "01": "\u200c",  # zero width non-joiner
    "10": "\u200d",  # zero width joiner
    "11": "\ufeff",  # zero width no-break space / BOM
}


def byte_to_zw(b: int) -> str:
    # 간단한 XOR로 살짝 암호화
    b ^= 0x37
    bits = f"{b:08b}"  # 8비트 문자열
    chunks = [bits[i : i + 2] for i in range(0, 8, 2)]  # 2비트씩 4조각
    return "".join(bit_to_zw[ch] for ch in chunks)  # 제로폭 4개


out = []

for b in flag:
    zw_seq = byte_to_zw(b)
    out.append("🍊" + zw_seq)

# 보기 좋게 몇 개마다 줄바꿈
line = ""
lines = []
for i, token in enumerate(out, 1):
    line += token
    if i % 8 == 0:
        lines.append(line)
        line = ""
if line:
    lines.append(line)

with open("gyulisyummy.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(lines))

print("gyulisyummy.txt 생성 완료")
