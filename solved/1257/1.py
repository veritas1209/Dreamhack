import random

# 50음도
syllables = [
    'a', 'i', 'u', 'e', 'o',
    'ka', 'ki', 'ku', 'ke', 'ko',
    'sa', 'shi', 'su', 'se', 'so',
    'ta', 'chi', 'tsu', 'te', 'to',
    'na', 'ni', 'nu', 'ne', 'no',
    'ha', 'hi', 'fu', 'he', 'ho',
    'ma', 'mi', 'mu', 'me', 'mo',
    'ya', 'yu', 'yo',
    'ra', 'ri', 'ru', 're', 'ro',
    'wa', 'wi', 'we', 'wo',
    'n'
]

# 바뀐 발음 예시 (여기서는 단순히 무작위로 음절을 섞음)
def generate_modified_syllables():
    modified_syllables = random.sample(syllables, len(syllables))  # 음절들을 무작위로 섞기
    return modified_syllables

# 출력 형식 생성
def generate_syllable_pairs():
    modified_syllables = generate_modified_syllables()
    
    syllable_pairs = []
    for i in range(0, len(modified_syllables), random.randint(2, 4)):  # 무작위로 2~4개의 음절씩 묶기
        syllable_pairs.append('/'.join(modified_syllables[i:i + random.randint(2, 4)]))
    
    return syllable_pairs

# 원래 음절들을 출력하고, 변형된 음절을 출력
def display_syllables():
    original = syllables
    modified = generate_syllable_pairs()

    print("원래 음절들:")
    print(' '.join(original))
    print("\n바뀐 발음들:")
    print("\n".join(modified))

# 실행
display_syllables()
