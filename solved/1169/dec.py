import base64
import re

def decode_until_flag(file_path):
    print(f"attempt open file: {file_path}")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = f.read().strip()
            print(f"success, file size: {len(data)} characters")
    except FileNotFoundError:
        print(f"'{file_path}' file do not exist")
        return
    except Exception as e:
        print(f"error occured: {e}")
        return

    iteration = 0
    flag_pattern = re.compile(r'DH\{.*?\}')

    while True:
        iteration += 1
        print(f"\n--- decoding attempt: {iteration} ---")
        
        preview = data if len(data) <= 100 else f"{data[:50]} ... {data[-50:]}"
        print(f"preview: {preview}")
        
        match = flag_pattern.search(data)
        if match:
            print(f"\nfind FLAG! (Attempt: {iteration})")
            print(f"Result : FLAG is {match.group(0)}")
            print(f"Result : FLAG \n{data}")
            break

        try:
            print("Decoding with Base64")
            padding_needed = len(data) % 4
            if padding_needed != 0:
                print(f"padding added: '=' x {4 - padding_needed} ")
                padded_data = data + '=' * (4 - padding_needed)
            else:
                padded_data = data

            # 디코딩 수행
            decoded_bytes = base64.b64decode(padded_data)
            
            data = decoded_bytes.decode('utf-8')
            print(f"Decoding Success now : {len(data)} characters")

        except UnicodeDecodeError as e:
            print(f"\nCannot change UTF-8")
            print(f"error : {e}")
            break
        except Exception as e:
            print(f"\nunvalid Base64")
            print(f"error : {e}")
            break

if __name__ == "__main__":
    target_file = "solved/1169/prob.txt"
    
    print("=== Base64 decorder ===")
    decode_until_flag(target_file)
    print("=== script end ===")