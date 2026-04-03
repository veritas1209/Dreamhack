import jsbeautifier

# 난독화된(또는 압축된) JS 파일 경로
input_file = 'app.9ada4703.js'
# 보기 좋게 정렬된 결과를 저장할 파일 경로
output_file = 'app_beautified.js'

# jsbeautifier 옵션 설정
opts = jsbeautifier.default_options()
opts.indent_size = 4

# 파일 읽기
with open(input_file, 'r', encoding='utf-8') as f:
    minified_code = f.read()

# 코드 정렬(Beautify)
beautified_code = jsbeautifier.beautify(minified_code, opts)

# 결과 저장
with open(output_file, 'w', encoding='utf-8') as f:
    f.write(beautified_code)

print(f"[+] 성공적으로 변환되었습니다. {output_file}을 확인해주세요!")