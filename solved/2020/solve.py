import cv2
import numpy as np

# 이미지 읽기
img = cv2.imread("Old_Love.png")
if img is None:
    print("이미지를 찾을 수 없습니다. 파일 경로를 확인하세요.")
    exit()

src = img.copy()

# 그레이스케일 변환 및 이진화
gray = cv2.cvtColor(src, cv2.COLOR_BGR2GRAY)
ret, gray = cv2.threshold(gray, 127, 255, cv2.THRESH_BINARY_INV | cv2.THRESH_OTSU)
height, width = gray.shape

# 연결된 컴포넌트 분석
mask = np.zeros(gray.shape, np.uint8)
cnt, labels, stats, centroids = cv2.connectedComponentsWithStats(gray)

# 오선 추출 (가로로 긴 컴포넌트)
for i in range(1, cnt):
    x, y, w, h, area = stats[i]
    if w > width * 0.5:
        roi = src[y:y+h, x:x+w]
        cv2.imwrite(f'line{i}.png', roi)

# 마스크 생성
for i in range(1, cnt):
    x, y, w, h, area = stats[i]
    if w > width * 0.5:
        cv2.rectangle(mask, (x, y), (x+w, y+h), 255, -1)  # 수정: 파라미터 형식 변경

masked = cv2.bitwise_and(gray, mask)

# 오선 위치 찾기
staves = []
for row in range(height):
    pixels = 0
    for col in range(width):
        pixels += (masked[row][col] == 255)
    if pixels >= width * 0.5:
        if len(staves) == 0 or abs(staves[-1][0] + staves[-1][1] - row) > 1:
            staves.append([row, 0])
        else:
            staves[-1][1] += 1

# 오선 제거
for staff in range(len(staves)):
    top_pixel = staves[staff][0]
    bot_pixel = staves[staff][0] + staves[staff][1]
    for col in range(width):
        if height - staves[staff][1] > bot_pixel and masked[top_pixel - 1][col] == 0 and masked[bot_pixel + 1][col] == 0:
            for row in range(top_pixel, bot_pixel + 1):
                masked[row][col] = 0

cv2.imwrite('score.png', 255 - masked)

# 윤곽선 찾기
contours, hierarchy = cv2.findContours(masked, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)

# 개별 음표/기호 추출
i = 1
for contour in contours:
    x, y, w, h = cv2.boundingRect(contour)
    # 경계 체크 추가
    y_start = max(0, y - 5)
    y_end = min(height, y + h + 5)
    x_start = max(0, x - 5)
    x_end = min(width, x + w + 5)
    
    roi = 255 - masked[y_start:y_end, x_start:x_end]
    cv2.imwrite(f'save{i}.jpg', roi)
    i += 1

# 결과 이미지에 사각형 그리기
for contour in contours:
    x, y, w, h = cv2.boundingRect(contour)
    cv2.rectangle(src, (x, y), (x + w, y + h), (255, 0, 0), 2)

# 결과 저장
cv2.imwrite('result.png', src)

# 결과 표시
cv2.imshow('Result', src)
cv2.waitKey(0)
cv2.destroyAllWindows()

print(f"처리 완료: {i-1}개의 객체가 추출되었습니다.")