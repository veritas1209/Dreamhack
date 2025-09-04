#include<stdio.h>
#define MOD 65521
int main(void)
{
	int target[2] = { 0x9636 ^ 0x7c70,0x14e7 };
	int start = 0x4d42 ^ 0x0c64;
	for (unsigned int a = 0; a <= 65535; a++)
	{// target을 만들 수 있는 가능한 a,b 쌍 찾기
		for (unsigned int b = 0; b <= 65535; b++)
		{
			unsigned int now = start;
			char possible = 1;
			for (int c = 0; c <= 1; c++)
			{// 시작을 start로 했을 때, a,b 조합으로 target이 나오는지 확인하기
				now *= a, now %= MOD;
				now += b, now %= MOD;
				if (now != target[c])
				{
					possible = 0;
					break;
				}
			}
			if (possible == 1)
			{// a,b 조합을 찾은 경우
				for (unsigned int c = 0; c <= 65535; c++)
				{// 처음에 start를 만들 수 있는 초기 seed 찾기
					unsigned int now = c;
					now *= a, now %= MOD;
					now += b, now %= MOD;
					if (now == start)
					{// 가능한 경우 출력
						printf("Possible key : a = %u, b = %u, seed = %u\n", a, b, c);
					}
				}			
			}
		}
	}
	return 0;
}
