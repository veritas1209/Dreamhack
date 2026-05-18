import os
import difflib

# 사용자 환경에 맞게 경로를 설정하세요.
REF_BASE_DIR = r"C:\Users\hajin\Downloads\McNie\McNie\Reference_Implementation\encrypt"
CTF_SRC_DIR = r"C:\Users\hajin\IT_Projects\hacking_study\dreamhack\1901\src"
OUTPUT_FILE = "diff_result.txt"

def read_file(filepath):
    """파일을 읽어서 라인 리스트로 반환 (인코딩 에러 무시)"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.readlines()
    except Exception as e:
        print(f"[-] 파일 읽기 에러: {filepath} ({e})")
        return []

def calculate_similarity(ref_dir, ctf_dir):
    """CTF 소스와 특정 레퍼런스 폴더 간의 유사도를 계산"""
    print(f"[*] 유사도 분석 중: {ref_dir} ...", end=" ")
    common_files = set(os.listdir(ref_dir)) & set(os.listdir(ctf_dir))
    
    total_lines = 0
    matched_lines = 0
    
    for filename in common_files:
        if not filename.endswith(('.c', '.h')): continue
        
        ref_lines = read_file(os.path.join(ref_dir, filename))
        ctf_lines = read_file(os.path.join(ctf_dir, filename))
        
        sm = difflib.SequenceMatcher(None, ref_lines, ctf_lines)
        matched_lines += sum(triple.size for triple in sm.get_matching_blocks())
        total_lines += max(len(ref_lines), len(ctf_lines))
        
    if total_lines == 0:
        print("비교 대상 없음")
        return 0
        
    similarity = matched_lines / total_lines
    print(f"유사도: {similarity:.2%}")
    return similarity

def find_best_match_folder(ref_base, ctf_dir):
    """가장 유사도가 높은 원본 폴더 찾기"""
    print(f"\n[+] === 원본 폴더 매칭 시작 ===")
    print(f"[*] 레퍼런스 경로: {ref_base}")
    print(f"[*] CTF 소스 경로: {ctf_dir}\n")
    
    best_folder = None
    best_score = -1
    
    for item in os.listdir(ref_base):
        target_dir = os.path.join(ref_base, item)
        if os.path.isdir(target_dir):
            score = calculate_similarity(target_dir, ctf_dir)
            if score > best_score:
                best_score = score
                best_folder = target_dir
                
    print(f"\n[+] >>> 최적 매칭 폴더: {os.path.basename(best_folder)} (유사도 {best_score:.2%}) <<<\n")
    return best_folder

def generate_diff(best_ref_dir, ctf_dir, output_file):
    """선택된 원본 폴더와 CTF 소스 간의 Diff 결과를 생성 및 저장"""
    print(f"[+] === Diff 상세 분석 시작 ===")
    common_files = set(os.listdir(best_ref_dir)) & set(os.listdir(ctf_dir))
    
    with open(output_file, 'w', encoding='utf-8') as out_f:
        out_f.write(f"=== McNie Source Code Diff Report ===\n")
        out_f.write(f"Reference: {best_ref_dir}\n")
        out_f.write(f"CTF Source: {ctf_dir}\n\n")
        
        for filename in sorted(common_files):
            if not filename.endswith(('.c', '.h')): continue
            
            ref_path = os.path.join(best_ref_dir, filename)
            ctf_path = os.path.join(ctf_dir, filename)
            
            ref_lines = read_file(ref_path)
            ctf_lines = read_file(ctf_path)
            
            diff = list(difflib.unified_diff(
                ref_lines, ctf_lines,
                fromfile=f"Original/{filename}",
                tofile=f"CTF/{filename}",
                n=3 # 변경된 라인 위아래로 3줄씩 컨텍스트 표시
            ))
            
            if diff:
                print(f"[*] 발견: {filename} 파일이 수정되었습니다! ({len(diff)} 라인 변경)")
                out_f.write(f"\n{'='*60}\n")
                out_f.write(f"[FILE] {filename}\n")
                out_f.write(f"{'='*60}\n")
                out_f.writelines(diff)
            else:
                print(f"[*] 패스: {filename} 파일은 원본과 100% 동일합니다.")
                
    print(f"\n[+] 분석 완료! 상세한 Diff 결과가 '{output_file}'에 저장되었습니다.")

if __name__ == "__main__":
    best_folder = find_best_match_folder(REF_BASE_DIR, CTF_SRC_DIR)
    if best_folder:
        generate_diff(best_folder, CTF_SRC_DIR, OUTPUT_FILE)