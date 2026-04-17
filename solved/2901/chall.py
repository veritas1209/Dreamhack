import requests
from urllib.parse import urlparse
from difflib import SequenceMatcher

def is_valid_attempt(url): # School Firewall
    if not url.isascii():
        return False
    if any(char.isupper() for char in url):
        return False
    if '%' in url:
        return False
    if not url.startswith("https://"):
        return False
    if "school" not in url.lower(): # Our school only allows domains about school.
        return False
    parsed = urlparse(url)
    domain = parsed.netloc
    if not domain.endswith('.com') or domain.split('.')[-1] != 'com':
        return False
    if 'school' not in domain:
        return False
    if parsed.username or parsed.password or "@" in url:
        return False
    if parsed.query:
        return False

    return True

def get_html(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.text
    except Exception as e: # Please wait if chess.com is offline.
        print(f"Error fetching {url}: {e}")
        return None

def compare_sites(original_url, target_url):
    original_html = get_html(original_url)
    target_html = get_html(target_url)

    if not original_html or not target_html:
        return

    normalized_target_html = target_html.replace(target_url.replace("https://", ""), original_url.replace("https://", ""))

    similarity = SequenceMatcher(None, original_html, normalized_target_html).ratio()

    if similarity > 0.98:
        print('Thank you! Now I can play chess.com in school!')
        with open('flag.txt') as f:
            flag=f.read()
            print('Flag is '+flag)
    else:
        print("No! This is not a chess.com!")

print('I want to play chess.com at school!')
target = "https://www.chess.com" # I want to access at this site!
attempt = input('Input the address : ').strip()

if is_valid_attempt(attempt):
    print('Accessing to chess.com...')
    compare_sites(target, attempt)
else:
    print("Blocked by school WAF.")