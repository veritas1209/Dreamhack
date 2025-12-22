from Crypto.Util.number import isPrime, long_to_bytes

def collect_factor(factor,val): # 소인수 배열 factor가 주어졌을 때, val 번째 인수 구하기
    result=1
    for i in range(0,len(factor),1): # 소인수를 선택해서 곱하는 과정은 비트마스크를 사용한다.
        if((val&1)==1):
            result*=factor[i]
        val>>=1
    return result

d=22800184635336356769510601710348610828272762269559262549105379768650621669527077640437441133467920490241918976205665073
target=((65537*d)-1) # target/x 는 어떤 정수 x에 대해 소수 p, q에 대해 (p-1)(q-1)로 표현된다. x는 target의 약수이며 target/x는 d보다는 크다.

# factor=target의 소인수분해 결과
factor=[2,2,2,2,3,5,5,37, 1117, 4029461, 1403014978139, 284368748316481195117, 18741210882440665187461519398960291465361283084482741278982029639876282810203]
roll=2**len(factor) # factor를 두 수의 곱으로 표현할 수 있는 경우의 수.
divisor=[] # target의 약수

for i in range(0,roll,1): # target의 약수를 모은다.
    divisor.append(collect_factor(factor,i))
divisor=list(set(divisor)) # 배열에서 중복된 것은 제거한다.
divisor.sort()

for i in divisor: # target의 약수는 모두 후보가 될 수 있다.
    attempt=target//i
    if(attempt>d): # attempt가 d보다 큰 경우만 생각한다.(모듈로 역의 정의에 의해)
        for p in divisor: # attempt=(p-1)*(q-1)로 표현되는 경우를 찾는다.
            if attempt%p==0: # attempt가 p의 약수인 경우
                q=attempt//p
                if(isPrime(p+1) and isPrime(q+1) and (q+1).bit_length()==256): # 조건에 맞는 경우를 찾아 출력하기
                    flag=long_to_bytes(p+1).decode() # 수를 플래그로 바꾸기
                    print("Possible Flag : "+flag)
