import os

def extract_raw_h264():
    input_filename = "hidden_video.mp4"
    output_filename = "hidden_flag.h264" # 확장자가 중요합니다 (.h264)
    
    start_search_offset = 779979
    
    if not os.path.exists(input_filename):
        print(f"오류: '{input_filename}' 파일이 없습니다.")
        return

    with open(input_filename, "rb") as f:
        data = f.read()
        
    # JPEG 이후의 데이터만 잘라냅니다.
    tail_data = data[start_search_offset:]
    
    # H.264 NAL Start Code (00 00 00 01) 찾기
    # 보통 I-Frame(키프레임) 앞에는 4바이트 스타트 코드가 붙습니다.
    nal_start_code = bytes.fromhex("00000001")
    
    # 검색
    index = tail_data.find(nal_start_code)
    
    if index != -1:
        # 실제 파일 내 절대 위치
        absolute_offset = start_search_offset + index
        print(f"[!] H.264 Raw Stream 시작 코드 발견!")
        print(f"    위치: {absolute_offset} (JPEG 끝에서 {index} 바이트 뒤)")
        
        # 여기서부터 끝까지 추출
        raw_video_data = tail_data[index:]
        
        with open(output_filename, "wb") as out:
            out.write(raw_video_data)
            
        print(f"--- 추출 완료: {output_filename} ---")
        print(f"    크기: {len(raw_video_data)} bytes")
        print("Tip: 추출된 .h264 파일은 VLC Player, PotPlayer, ffplay 등으로 재생 가능합니다.")
        
    else:
        print("[-] JPEG 이후 구역에서 H.264 시작 코드(00 00 00 01)를 찾지 못했습니다.")
        print("    3바이트 코드(00 00 01)일 수도 있으니 코드를 수정해서 다시 시도해보세요.")

if __name__ == "__main__":
    extract_raw_h264()