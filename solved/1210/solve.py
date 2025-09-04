#!/usr/bin/env python3
"""
CAN Bus Advanced Solver - DH 패턴 주변 집중 분석
"""

import re
from collections import defaultdict
import binascii

class AdvancedCANAnalyzer:
    def __init__(self, filename):
        self.filename = filename
        self.lines = []
        self.can_data = defaultdict(list)
        self.can_data_with_timestamp = defaultdict(list)
        
    def load_and_parse(self):
        """파일 로드 및 파싱"""
        with open(self.filename, 'r') as f:
            self.lines = f.readlines()
        
        for line in self.lines:
            match = re.match(r'\(([0-9.]+)\)\s+vcan0\s+([0-9A-Fa-f]+)#([0-9A-Fa-f]*)', line)
            if match:
                timestamp = float(match.group(1))
                can_id = match.group(2).upper()
                data = match.group(3).upper()
                
                self.can_data[can_id].append(data)
                self.can_data_with_timestamp[can_id].append((timestamp, data))
        
        print(f"[+] 로드 완료: {len(self.lines)} 줄, {len(self.can_data)} 개의 CAN ID")
    
    def hex_to_ascii(self, hex_string):
        """HEX를 ASCII로 변환"""
        try:
            return bytes.fromhex(hex_string).decode('ascii', errors='ignore')
        except:
            return ""
    
    def analyze_can_id_0a9(self):
        """CAN ID 0A9 집중 분석"""
        print("\n[*] CAN ID 0A9 집중 분석")
        print("-" * 50)
        
        if '0A9' not in self.can_data:
            print("[-] CAN ID 0A9를 찾을 수 없음")
            return
        
        data_list = self.can_data['0A9']
        print(f"[+] 0A9 메시지 수: {len(data_list)}")
        
        # 모든 데이터 출력
        for i, data in enumerate(data_list):
            ascii_text = self.hex_to_ascii(data)
            print(f"  메시지 {i}: {data} -> '{ascii_text}'")
        
        # 전체 연결
        concatenated = ''.join(data_list)
        ascii_full = self.hex_to_ascii(concatenated)
        print(f"\n전체 연결: {ascii_full}")
        
        # DH 위치 찾기
        dh_index = concatenated.find('4448')
        if dh_index != -1:
            print(f"\nDH(4448) 위치: {dh_index}")
            # 앞뒤 100 문자 출력
            start = max(0, dh_index - 100)
            end = min(len(concatenated), dh_index + 100)
            context = concatenated[start:end]
            print(f"컨텍스트 HEX: {context}")
            print(f"컨텍스트 ASCII: {self.hex_to_ascii(context)}")
    
    def find_dh_pattern_all(self):
        """모든 데이터에서 DH 패턴 찾기"""
        print("\n[*] 전체 데이터에서 DH 패턴 검색")
        print("-" * 50)
        
        # 시간순 전체 데이터
        all_data = ""
        for line in self.lines:
            match = re.match(r'\([0-9.]+\)\s+vcan0\s+[0-9A-Fa-f]+#([0-9A-Fa-f]*)', line)
            if match and match.group(1):
                all_data += match.group(1).upper()
        
        # DH (44 48) 찾기
        dh_positions = []
        for i in range(0, len(all_data) - 3, 2):
            if all_data[i:i+4] == '4448':
                dh_positions.append(i)
        
        print(f"[+] DH 패턴 발견 위치: {dh_positions}")
        
        for pos in dh_positions:
            # 각 위치에서 앞뒤 200 문자 확인
            start = max(0, pos - 200)
            end = min(len(all_data), pos + 200)
            context = all_data[start:end]
            
            print(f"\n위치 {pos}:")
            print(f"HEX: ...{context}...")
            ascii_text = self.hex_to_ascii(context)
            print(f"ASCII: ...{ascii_text}...")
            
            # '7B' ({) 와 '7D' (}) 찾기
            if '7B' in context:  # {
                print("[!] '{' 발견!")
                # DH{ 패턴부터 } 까지 추출 시도
                dh_start = context.find('44487B')
                if dh_start != -1:
                    # }(7D) 찾기
                    remaining = context[dh_start:]
                    close_pos = remaining.find('7D')
                    if close_pos != -1:
                        flag_hex = remaining[:close_pos + 2]
                        flag_ascii = self.hex_to_ascii(flag_hex)
                        print(f"[!!!] 가능한 플래그: {flag_ascii}")
    
    def analyze_nearby_canids(self):
        """DH가 발견된 CAN ID 주변 분석"""
        print("\n[*] CAN ID 0A9 주변 ID 분석")
        print("-" * 50)
        
        # 0A9 주변 ID들 확인 (0A8, 0AA, 0AB 등)
        nearby_ids = ['0A8', '0A9', '0AA', '0AB', '0A7', '0A6']
        
        combined_data = ""
        for can_id in nearby_ids:
            if can_id in self.can_data:
                data = ''.join(self.can_data[can_id])
                combined_data += data
                ascii_text = self.hex_to_ascii(data)
                print(f"CAN ID {can_id}: {ascii_text}")
        
        # 조합된 데이터 확인
        combined_ascii = self.hex_to_ascii(combined_data)
        print(f"\n조합된 ASCII: {combined_ascii}")
        
        # DH 패턴 검색
        if 'DH' in combined_ascii:
            print(f"[!] 조합에서 DH 발견!")
    
    def extract_specific_bytes(self):
        """각 메시지의 특정 바이트만 추출"""
        print("\n[*] 특정 바이트 위치 추출 분석")
        print("-" * 50)
        
        # 각 메시지의 첫 번째 바이트만
        first_bytes = ""
        for line in self.lines:
            match = re.match(r'\([0-9.]+\)\s+vcan0\s+[0-9A-Fa-f]+#([0-9A-Fa-f]*)', line)
            if match and match.group(1) and len(match.group(1)) >= 2:
                first_bytes += match.group(1)[:2]
        
        ascii_text = self.hex_to_ascii(first_bytes)
        if 'DH' in ascii_text:
            print(f"[!] 첫 바이트에서 발견: {ascii_text[:100]}")
        
        # 각 메시지의 마지막 바이트만
        last_bytes = ""
        for line in self.lines:
            match = re.match(r'\([0-9.]+\)\s+vcan0\s+[0-9A-Fa-f]+#([0-9A-Fa-f]*)', line)
            if match and match.group(1) and len(match.group(1)) >= 2:
                last_bytes += match.group(1)[-2:]
        
        ascii_text = self.hex_to_ascii(last_bytes)
        if 'DH' in ascii_text:
            print(f"[!] 마지막 바이트에서 발견: {ascii_text[:100]}")
    
    def analyze_sequential_canids(self):
        """순차적 CAN ID 분석 (000, 001, 002...)"""
        print("\n[*] 순차적 CAN ID 분석")
        print("-" * 50)
        
        # 000부터 시작하는 순차 ID들
        sequential_data = ""
        for i in range(0, 100):  # 000 ~ 099
            can_id = f"{i:03X}"
            if can_id in self.can_data:
                data = ''.join(self.can_data[can_id])
                sequential_data += data
                ascii_text = self.hex_to_ascii(data)
                if ascii_text and any(c.isalnum() for c in ascii_text):
                    print(f"CAN ID {can_id}: {ascii_text[:50]}")
        
        # 전체 확인
        full_ascii = self.hex_to_ascii(sequential_data)
        if 'DH{' in full_ascii:
            idx = full_ascii.index('DH{')
            print(f"\n[!!!] 순차 ID에서 플래그 발견: {full_ascii[idx:idx+50]}")
    
    def smart_extraction(self):
        """스마트 추출 - DH 위치부터 역추적"""
        print("\n[*] 스마트 추출 - DH 위치 기반 분석")
        print("-" * 50)
        
        # 전체 데이터에서 DH 위치 찾기
        all_data = ""
        data_map = []  # (start_pos, end_pos, can_id, message_index)
        
        pos = 0
        for i, line in enumerate(self.lines):
            match = re.match(r'\([0-9.]+\)\s+vcan0\s+([0-9A-Fa-f]+)#([0-9A-Fa-f]*)', line)
            if match:
                can_id = match.group(1).upper()
                data = match.group(2).upper()
                if data:
                    data_map.append((pos, pos + len(data), can_id, i))
                    all_data += data
                    pos += len(data)
        
        # DH (4448) 위치 찾기
        dh_pos = all_data.find('4448')
        if dh_pos != -1:
            print(f"[+] DH 발견 위치: {dh_pos}")
            
            # 어느 CAN ID/메시지에서 발견되었는지 확인
            for start, end, can_id, msg_idx in data_map:
                if start <= dh_pos < end:
                    print(f"[+] CAN ID {can_id}, 메시지 인덱스 {msg_idx}에서 발견")
                    break
            
            # DH부터 200자 추출하고 '}'까지 찾기
            extract_len = 400
            extracted = all_data[dh_pos:min(len(all_data), dh_pos + extract_len)]
            
            # ASCII 변환
            ascii_text = self.hex_to_ascii(extracted)
            print(f"추출된 ASCII: {ascii_text}")
            
            # 플래그 패턴 매칭
            import re
            flag_match = re.search(r'DH\{[^}]*\}', ascii_text)
            if flag_match:
                print(f"\n[!!!] 플래그 발견: {flag_match.group()}")
                return flag_match.group()
            
            # 수동으로 '}' 찾기
            close_brace = extracted.find('7D')
            if close_brace != -1:
                flag_hex = extracted[:close_brace + 2]
                flag_ascii = self.hex_to_ascii(flag_hex)
                print(f"\n[!!!] 가능한 플래그: {flag_ascii}")
    
    def check_alternating_pattern(self):
        """홀수/짝수 메시지 패턴 확인"""
        print("\n[*] 홀수/짝수 메시지 패턴 분석")
        print("-" * 50)
        
        # 홀수 번째 메시지만
        odd_data = ""
        for i, line in enumerate(self.lines):
            if i % 2 == 1:  # 홀수
                match = re.match(r'\([0-9.]+\)\s+vcan0\s+[0-9A-Fa-f]+#([0-9A-Fa-f]*)', line)
                if match and match.group(1):
                    odd_data += match.group(1).upper()
        
        odd_ascii = self.hex_to_ascii(odd_data)
        if 'DH' in odd_ascii:
            print(f"[!] 홀수 메시지에서 DH 발견")
            idx = odd_ascii.find('DH')
            print(f"컨텍스트: {odd_ascii[max(0,idx-20):min(len(odd_ascii),idx+50)]}")
        
        # 짝수 번째 메시지만
        even_data = ""
        for i, line in enumerate(self.lines):
            if i % 2 == 0:  # 짝수
                match = re.match(r'\([0-9.]+\)\s+vcan0\s+[0-9A-Fa-f]+#([0-9A-Fa-f]*)', line)
                if match and match.group(1):
                    even_data += match.group(1).upper()
        
        even_ascii = self.hex_to_ascii(even_data)
        if 'DH' in even_ascii:
            print(f"[!] 짝수 메시지에서 DH 발견")
            idx = even_ascii.find('DH')
            print(f"컨텍스트: {even_ascii[max(0,idx-20):min(len(even_ascii),idx+50)]}")
    
    def run_advanced_analysis(self):
        """모든 고급 분석 실행"""
        print("\n" + "="*60)
        print(" CAN Bus Advanced Solver")
        print("="*60)
        
        self.load_and_parse()
        
        # 각 분석 방법 실행
        methods = [
            self.analyze_can_id_0a9,
            self.find_dh_pattern_all,
            self.analyze_nearby_canids,
            self.extract_specific_bytes,
            self.analyze_sequential_canids,
            self.smart_extraction,
            self.check_alternating_pattern
        ]
        
        found_flag = None
        for method in methods:
            try:
                result = method()
                if result and 'DH{' in str(result):
                    found_flag = result
                    break
            except Exception as e:
                print(f"[-] 오류: {e}")
                continue
        
        print("\n" + "="*60)
        print(" 최종 결과")
        print("="*60)
        
        if found_flag:
            print(f"[+] 플래그 발견: {found_flag}")
        else:
            print("[-] 추가 분석이 필요합니다.")
            print("\n다음 시도:")
            print("1. CAN ID 0A9 전후 메시지 수동 확인")
            print("2. 특정 CAN ID 조합 (예: 0A9 + 다른 ID)")
            print("3. 다른 인코딩 (Base64, URL encoding 등)")

def main():
    filename = r"C:\Users\hajin\hacking_study\dreamhack\1210\candump-2024-04-19_143417.log"
    analyzer = AdvancedCANAnalyzer(filename)
    analyzer.run_advanced_analysis()

if __name__ == "__main__":
    main()