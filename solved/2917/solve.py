import torch
import os

def analyze_torch_model(model_path):
    print(f"[DEBUG] === PyTorch 모델 분석 시작 ===")
    print(f"[DEBUG] 대상 파일: {model_path}")
    
    if not os.path.exists(model_path):
        print(f"[ERROR] 파일을 찾을 수 없습니다: {model_path}")
        return

    file_size = os.path.getsize(model_path) / (1024 * 1024)
    print(f"[DEBUG] 파일 크기: {file_size:.2f} MB")

    print("[DEBUG] torch.load() 시도 중... (CPU 환경 기준)")
    try:
        # GPU에서 학습된 모델일 수 있으므로 map_location='cpu' 필수
        model_data = torch.load(model_path, map_location=torch.device('cpu'))
        print(f"[DEBUG] 로드 성공! 데이터 타입: {type(model_data)}")

        if isinstance(model_data, dict):
            print("\n[DEBUG] 📌 이 파일은 모델의 가중치를 담은 'state_dict' (딕셔너리) 형태입니다.")
            print("[DEBUG] --- Layer 및 Weights 상세 정보 ---")
            for key, value in model_data.items():
                if isinstance(value, torch.Tensor):
                    print(f"Layer Name: {key: <30} | Shape: {list(value.shape)} | Type: {value.dtype}")
                else:
                    print(f"Layer Name: {key: <30} | Type: {type(value)} (Not a Tensor)")
        else:
            print("\n[DEBUG] 📌 이 파일은 '전체 모델 객체'를 포함하고 있습니다.")
            print("[DEBUG] --- 모델 아키텍처 ---")
            print(model_data)

    except ModuleNotFoundError as e:
        print(f"\n[ERROR] 원본 모델의 클래스 코드가 없어서 로드할 수 없습니다: {e}")
        print("[DEBUG] 이 경우, 문제를 풀기 위한 모델의 클래스 구조가 어딘가에 주어졌거나 추가적인 리버싱이 필요할 수 있습니다.")
    except Exception as e:
        print(f"\n[ERROR] 일반적인 torch.load() 실패: {e}")
        print("[DEBUG] TorchScript 모델일 가능성이 있으므로 torch.jit.load()를 시도합니다.")
        try:
            model_data = torch.jit.load(model_path, map_location=torch.device('cpu'))
            print("[DEBUG] 📌 TorchScript 모델로 로드 성공!")
            print("[DEBUG] --- 모델 그래프(Graph) ---")
            print(model_data.graph)
        except Exception as e2:
            print(f"[ERROR] torch.jit.load()도 실패: {e2}")

def analyze_enc_file(enc_path):
    print(f"\n[DEBUG] === 암호화된 파일(enc) 분석 시작 ===")
    print(f"[DEBUG] 대상 파일: {enc_path}")
    
    if not os.path.exists(enc_path):
        print(f"[ERROR] 파일을 찾을 수 없습니다: {enc_path}")
        return

    file_size = os.path.getsize(enc_path)
    print(f"[DEBUG] 파일 크기: {file_size} bytes")

    with open(enc_path, 'rb') as f:
        header = f.read(32)
        print(f"[DEBUG] 파일 헤더 (첫 32바이트 HEX): {header.hex()}")
        
        # 만약 PyTorch Tensor가 직접 저장된 거라면 특정 매직헤더가 있을 수 있음
        if b'PK' in header[:4]:
            print("[DEBUG] 💡 힌트: 이 파일은 ZIP 포맷(또는 신형 PyTorch 저장 포맷)일 확률이 높습니다.")
        elif b'PNG' in header:
            print("[DEBUG] 💡 힌트: PNG 시그니처가 보입니다. 픽셀 값만 변조되었을 수 있습니다.")

if __name__ == "__main__":
    # 파일명은 실제 환경에 맞게 수정하세요
    analyze_torch_model("model.pt")
    analyze_enc_file("teto.png.enc")