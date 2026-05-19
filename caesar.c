#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================================
// Base64 인코더 / 디코더
// ============================================================================
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char* base64_encode(const unsigned char *src, size_t len) {
    char *out = malloc(4 * ((len + 2) / 3) + 1);
    size_t i = 0, j = 0;
    while (i < len) {
        unsigned int octet_a = i < len ? src[i++] : 0;
        unsigned int octet_b = i < len ? src[i++] : 0;
        unsigned int octet_c = i < len ? src[i++] : 0;
        unsigned int triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
        out[j++] = b64_table[(triple >> 3 * 6) & 0x3F];
        out[j++] = b64_table[(triple >> 2 * 6) & 0x3F];
        out[j++] = b64_table[(triple >> 1 * 6) & 0x3F];
        out[j++] = b64_table[(triple >> 0 * 6) & 0x3F];
    }
    for (int k = 0; k < (3 - len % 3) % 3; k++) out[j - 1 - k] = '=';
    out[j] = '\0';
    return out;
}

unsigned char* base64_decode(const char *src, size_t *out_len) {
    size_t len = strlen(src);
    if (len % 4 != 0) return NULL;
    size_t pad = 0;
    if (len > 0 && src[len - 1] == '=') pad++;
    if (len > 1 && src[len - 2] == '=') pad++;
    *out_len = (len * 3) / 4 - pad;
    unsigned char *out = malloc(*out_len + 1);
    size_t i = 0, j = 0;
    while (i < len) {
        unsigned int a = src[i] == '=' ? 0 : strchr(b64_table, src[i]) - b64_table; i++;
        unsigned int b = src[i] == '=' ? 0 : strchr(b64_table, src[i]) - b64_table; i++;
        unsigned int c = src[i] == '=' ? 0 : strchr(b64_table, src[i]) - b64_table; i++;
        unsigned int d = src[i] == '=' ? 0 : strchr(b64_table, src[i]) - b64_table; i++;
        unsigned int triple = (a << 3 * 6) + (b << 2 * 6) + (c << 1 * 6) + (d << 0 * 6);
        if (j < *out_len) out[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *out_len) out[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *out_len) out[j++] = (triple >> 0 * 8) & 0xFF;
    }
    out[j] = '\0';
    return out;
}

// ============================================================================
// 2. 피보나치 & 헥스 변환 유틸
// ============================================================================
int get_fibonacci(int n) {
    int a = 1, b = 1, c = 0;
    for (int i = 2; i <= n; i++) {
        c = a + b;
        a = b;
        b = c;
    }
    return c;
}

unsigned char* hex_to_bytes(const char* hex_str, int* out_len) {
    int len = strlen(hex_str);
    *out_len = len / 2;
    unsigned char* bytes = malloc(*out_len);
    for(int i = 0; i < *out_len; i++) {
        sscanf(hex_str + 2 * i, "%2hhx", &bytes[i]);
    }
    return bytes;
}

// ============================================================================
// 3. 암호화 로직
// ============================================================================
void run_encryption(int key, const char *input) {
    int orig_len = strlen(input);
    char *b64_str = base64_encode((const unsigned char*)input, orig_len);
    int b64_len = strlen(b64_str);
    
    int packed_len = (b64_len * 7 + 7) / 8;
    unsigned char *packed = (unsigned char *)calloc(packed_len + 1, 1);

    int prev_cipher = key; 
    int polarity = 1;       

    for (int i = 0; i < b64_len; i++) {
        unsigned char c = b64_str[i] & 0x7F; 

        int fib = get_fibonacci(i + 10);
        int fib_val = (fib * polarity) & 0x7F; 
        int chaining_mask = (prev_cipher ^ 0x1337) & 0x7F;

        // 암호화 연산: (원본 ^ 피보나치 ^ 체이닝마스크)
        int encrypted_val = (c ^ fib_val ^ chaining_mask) & 0x7F;
        unsigned char encrypted_char = (unsigned char)encrypted_val;

        // 7비트 패킹
        int bit_pos = i * 7;
        int byte_idx = bit_pos / 8;
        int bit_offset = bit_pos % 8;

        packed[byte_idx] |= (encrypted_char << bit_offset) & 0xFF;
        if (bit_offset > 1) { 
            packed[byte_idx + 1] |= (encrypted_char >> (8 - bit_offset)) & 0xFF;
        }

        prev_cipher = (encrypted_char ^ c) & 0x7F;
        polarity *= -1;
    }
    
    // 오직 Hex 문자열만 출력
    for (int i = 0; i < packed_len; i++) {
        printf("%02X", packed[i]);
    }
    printf("\n");

    free(b64_str);
    free(packed);
}

// ============================================================================
// 4. 복호화 로직 (XOR Annihilation Version)
// ============================================================================
void run_decryption(int key, const char *hex_input) {
    int packed_len = 0;
    unsigned char *packed = hex_to_bytes(hex_input, &packed_len);
    
    int b64_len = (packed_len * 8) / 7;
    char *dec_b64 = (char *)calloc(b64_len + 1, 1);
    
    int prev_cipher = key;
    int polarity = 1;       

    for (int i = 0; i < b64_len; i++) {
        int bit_pos = i * 7;
        int byte_idx = bit_pos / 8;
        int bit_offset = bit_pos % 8;

        unsigned char encrypted_char = (packed[byte_idx] >> bit_offset) & 0xFF;
        if (bit_offset > 1) {
            encrypted_char |= (packed[byte_idx + 1] << (8 - bit_offset)) & 0xFF;
        }
        encrypted_char &= 0x7F; 

        // 🔥 암호화와 완벽히 동일한 체이닝 마스크 생성
        int chaining_mask = (prev_cipher ^ 0x1337) & 0x7F;
        
        int fib = get_fibonacci(i + 10);
        int fib_val = (fib * polarity) & 0x7F;

        // 역연산: XOR은 똑같이 XOR하면 풀림!
        int decrypted_val = (encrypted_char ^ fib_val ^ chaining_mask) & 0x7F;
        dec_b64[i] = (char)decrypted_val;

        // PCBC 체이닝 업데이트 (암호문 ^ 방금 푼 글자)
        // 여기서 방금 푼 글자가 '에러'라면, 다음 루프는 영원한 나락으로 떨어짐.
        prev_cipher = (encrypted_char ^ decrypted_val) & 0x7F;
        polarity *= -1; 
    }

    for (int i = 0; i < b64_len; i++) {
        if (dec_b64[i] == 0x00) {
            dec_b64[i] = '\0';
            break;
        }
    }

    size_t out_len;
    unsigned char *final_text = base64_decode(dec_b64, &out_len);
    
    // 복호화 실패 시 가차 없이 경고 출력
    if (final_text != NULL) {
        printf("%s\n", final_text);
        free(final_text);
    } else {
        printf("[DECRYPTION FAILED] Base64 structure collapsed. The Key is WRONG.\n");
    }

    free(dec_b64);
    free(packed);
}

// ============================================================================
// 5. CLI 아규먼트 파싱 메인
// ============================================================================
int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  Encryption: %s enc <key_integer> \"TEXT TO ENCRYPT\"\n", argv[0]);
        fprintf(stderr, "  Decryption: %s dec <key_integer> \"HEX_STRING\"\n", argv[0]);
        return 1;
    }

    char *mode = argv[1];
    int key = atoi(argv[2]);
    char *data = argv[3];

    if (strcmp(mode, "enc") == 0) {
        run_encryption(key, data);
    } else if (strcmp(mode, "dec") == 0) {
        run_decryption(key, data);
    } else {
        fprintf(stderr, "Invalid mode. Use 'enc' or 'dec'.\n");
        return 1;
    }

    return 0;
}