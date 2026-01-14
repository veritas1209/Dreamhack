// 1. 초기 데이터 설정 (소스코드에서 가져옴)
var pumpkin = [ 124, 112, 59, 73, 167, 100, 105, 75, 59, 23, 16, 181, 165, 104, 43, 49, 118, 71, 112, 169, 43, 53 ];
var pie = 1;

// 2. 10,000번 클릭하는 동안 일어날 연산을 시뮬레이션
// 100 클릭마다 실행되므로 총 100번 반복 (10000 / 100 = 100)
for (var k = 0; k < 100; k++) {
    for (var i = 0; i < pumpkin.length; i++) {
        pumpkin[i] ^= pie;
        pie = ((pie ^ 0xff) + (i * 10)) & 0xff;
    }
}

// 3. 결과 출력 (ASCII 코드를 문자로 변환)
var flag = pumpkin.map(x => String.fromCharCode(x)).join('');
console.log("FLAG:", flag);