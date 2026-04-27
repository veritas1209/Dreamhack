import torch
import os

def extract_d_method(model_path):
    print(f"[DEBUG] === 4단계: 코어 함수 'd' 강제 추출 시작 ===")
    
    if not os.path.exists(model_path):
        print(f"[ERROR] 파일을 찾을 수 없습니다: {model_path}")
        return

    print("[DEBUG] torch.jit.load() 로 모델 로드 중...")
    try:
        model = torch.jit.load(model_path, map_location=torch.device('cpu'))
        print("[DEBUG] 📌 모델 로드 성공!\n")
        
        print("="*60)
        print("[DEBUG] 🎯 함수 'd' 원본 코드 직접 추출")
        print("="*60)
        
        if hasattr(model, 'd'):
            # d 속성을 직접 가져와서 코드 출력
            d_method = getattr(model, 'd')
            print(d_method.code)
        else:
            print("[ERROR] 모델에 'd'라는 이름의 속성이 존재하지 않습니다!")
            print("[DEBUG] 혹시 다른 이름으로 난독화되었는지 확인이 필요합니다.")
            
    except Exception as e:
        print(f"\n[ERROR] 스크립트 실행 중 오류 발생: {e}")

if __name__ == "__main__":
    extract_d_method("model.pt")