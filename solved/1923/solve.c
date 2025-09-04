#include<stdio.h>
#include<stdlib.h>
#include<string.h>
typedef struct part { // LFSR
	unsigned int state;// 현재 상태. 32비트 정수이다.
	int pos[4];
} PART;
unsigned char htod(char x);
unsigned char get_byte(PART* d);
int main(void)
{
	PART d;// LFSR 객체
	d.pos[0] = 32, d.pos[1] = 22, d.pos[2] = 2, d.pos[3] = 1;
	const char* test = "c615a6cbc4bbf37fe65af240813248140925f2afb31f6c6b5bf71cdfa151fcd55999cf95e2eb9313fc75afe39d1bf836ef14931afe19e16a7c16a1bb41d5abe5d124991d";
	const char* target = "DH{";// 암호문에서 알고 있는 글자
	unsigned char ciphertext[100] = { 0 };// 암호문
	unsigned char plaintext[100] = { 0 };// 평문
	int len = strlen(test) / 2;
	for (int i = 0; i < len; i++)
	{// hex 문자열을 정수로 바꾸어 암호문을 만든다.
		ciphertext[i] = 16 * htod(test[2 * i]) + htod(test[2 * i + 1]);
	}
	int cnt = 0;
	for (unsigned int k = 1; k > 0; k++)
	{// LFSR의 초기 키값으로 가능한 모든 경우를 조사한다.
		char yes = 1;
		d.state = k;
		for (int i = 0; i <= 2; i++)
		{// 첫 3글자 조사하기
			unsigned char t = get_byte(&d);// 1바이트 난수 추출하기
			plaintext[i] = ciphertext[i] ^ t;// 난수를 암호문과 XOR 하여 평문을 만든다.
			if (plaintext[i] != target[i])
			{// 첫 3글자가 DH{ 가 아니면 올바른 키가 아니다.
				yes = 0;
				break;
			}
		}
		if (yes == 1)
		{// 만일 DH{ 가 나오면 해독이 될 가능성이 있다.
			for (int i = 3; i < len; i++)
			{// 나머지 부분을 해독한다.
				unsigned char t = get_byte(&d);
				plaintext[i] = ciphertext[i] ^ t;
				if (!(plaintext[i] >= 32 && plaintext[i] <= 126))
				{// 만일 플래그에 출력 불가능한 아스키 문자가 섞여 있으면 올바른 키가 아니다.
					goto skip;
				}
			}
			printf("Possible Decryption : %s , Key = %u\n", plaintext, k);
		}
	skip:
		cnt += 1;
		if (cnt >= 100000000)
		{// 1억 개 조사할 때마다 출력하기
			printf("Passed %u.\n", k);
			cnt = 0;
		}
	}
	return 0;
}
unsigned char htod(char x)
{// 16진수를 10진수로
	if (x >= '0' && x <= '9')
	{// 0~9
		return x - '0';
	}
	else if (x >= 'a' && x <= 'f')
	{// 10~15
		return x - 'a' + 10;
	}
	else
	{// 잘못된 문자
		printf("Invalid hex letter %c.\n", x);
		exit(1);
	}
}
unsigned char get_byte(PART* d)
{// LFSR에서 바이트 하나(비트 8개) 추출하기
	unsigned char answer = 0;
	for (char i = 0; i < 8; i++)
	{// 추출 과정에 따라 추출하기
		answer <<= 1;
		answer += (d->state & 1);
		unsigned int k = 0;
		for (char j = 0; j <= 3; j++)
		{
			k ^= ((d->state >> (32 - d->pos[j])) & 1);
		}
		d->state >>= 1;
		d->state += (k << 31);
	}
	return answer;
}
