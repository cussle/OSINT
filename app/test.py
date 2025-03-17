import Levenshtein
import re
import tldextract
import requests
import socket

API_KEY = ""

# 신뢰할 수 있는 도메인 목록 (주요 기업 도메인)
trusted_domains = [
    "google.com", "facebook.com", "amazon.com", "apple.com", "microsoft.com", "netflix.com", "github.com",
    "naver.com", "live.com", "microsoftonline.com", "linkedin.com", "xvideos.com", "office.com",
    "pinterest.com", "bilibili.com", "twitch.tv", "microsoft.com", "vk.com", "xhamster.com",
    "news.yahoo.co.jp", "mail.ru", "xhamster43.desi", "fandom.com", "xnxx.com", "temu.com",
    "samsung.com", "duckduckgo.com", "t.me", "quora.com", "weather.com", "sharepoint.com",
    "globo.com", "canva.com", "stripchat.com", "roblox.com", "ebay.com", "nytimes.com",
    "youtube.com", "newtoki466.com", "yakored1.net", "manatoki466.net", "fabulouslink.xyz",
    "x.com", "booktoki466.com", "tistory.com", "inven.co.kr", "gmarket.co.kr", "enrtx.com",
    "instagram.com", "aliexpress.com", "twidouga.net", "msn.com", "nate.com", "twitter.com"
]

# 특정 TLD (ex: .ac.kr, .edu, .gov)는 기본적으로 신뢰
trusted_tlds = ["ac.kr", "edu", "gov"]

# Homoglyph 문자 매핑
HOMOGLYPH_MAP = {
    '0': 'O', 'O': '0',
    '1': 'l', 'l': '1', 'I': 'l', 'l': 'I',
    '5': 'S', 'S': '5',
    '8': 'B', 'B': '8',
    '9': 'g', 'g': '9'
}
def is_domain_valid(url):
    """DNS 조회를 통해 실제 존재하는 도메인인지 확인"""
    try:
        socket.gethostbyname(url)
        return True
    except socket.gaierror:
        return False


def check_google_safe_browsing(url):
    """Google Safe Browsing API를 이용해 피싱 여부 확인"""
    API_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

    payload = {
        "client": {
            "clientId": "your-app",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    response = requests.post(API_URL, json=payload)
    result = response.json()

    return "matches" in result  # True면 악성 사이트


def homoglyph_normalize(domain):
    """Homoglyph 변환: 유사한 문자 패턴을 정규화"""
    for homoglyph, normal in HOMOGLYPH_MAP.items():
        domain = domain.replace(homoglyph, normal)
    return domain

def calculate_typo_squatting_risk(input_domain, known_domains):
    extracted = tldextract.extract(input_domain)
    input_domain_main = extracted.domain
    input_tld = extracted.suffix

    max_score = 0
    best_match = None
    best_similarity = 0

    # Homoglyph 변형 적용
    normalized_input = homoglyph_normalize(input_domain_main)

    for known_domain in known_domains:
        extracted_known = tldextract.extract(known_domain)
        known_domain_main = extracted_known.domain
        known_tld = extracted_known.suffix

        # Homoglyph 적용된 문자열로 비교
        normalized_known = homoglyph_normalize(known_domain_main)
        # 공식 도메인과 정확히 일치하면 위험도 0.0 즉시 반환
        if input_domain_main == known_domain_main and input_tld == known_tld:
            return [known_domain, 0.0]

        # 1. Levenshtein Distance 기반 유사도 점수
        lev_distance = Levenshtein.distance(normalized_input, normalized_known)
        max_length = max(len(normalized_input), len(normalized_known))
        similarity_score = 1 - (lev_distance / max_length)

        # 2. TLD 변경 감지
        tld_change_score = 0.3 if input_tld != known_tld else 0

        # 3. 숫자 및 특수문자 변조 감지
        altered_chars_score = 0
        if re.search(r'\d', input_domain_main):  # 숫자 포함 여부
            altered_chars_score += 0.2
        if '-' in input_domain_main:  # 하이픈 포함 여부
            altered_chars_score += 0.1

        # 4. Homoglyph 감지 가중치
        homoglyph_penalty = 0.2 if normalized_input != input_domain_main else 0

        # 최종 점수 계산
        total_score = (1 - similarity_score) * 0.5 + tld_change_score + altered_chars_score + homoglyph_penalty
        total_score = min(1, total_score)

        # 가장 유사한 도메인 선택
        if similarity_score > best_similarity:
            best_similarity = similarity_score
            best_match = known_domain
            max_score = total_score

    return [best_match, round(max_score, 3)]

def check_url(url):
    """전체 검사 로직"""
    extracted = tldextract.extract(url)
    domain_name = f"{extracted.domain}.{extracted.suffix}"

    # 1. Google Safe Browsing API로 확인
    if check_google_safe_browsing(url):
        print(f"🚨 WARNING! Google Safe Browsing에서 차단된 사이트입니다: {url}")
        return

    # 2. DNS 조회로 실제 존재하는지 확인
    domain_exists = is_domain_valid(domain_name)

    # 3. 유사도 분석을 통한 타이포스쿼팅 검사
    result = calculate_typo_squatting_risk(domain_name, trusted_domains)
    score = result[1]
    target = result[0]

    # ✅ **DNS 조회 결과만으로 무조건 Safe로 판정하지 않음!**
    if domain_exists:
        if score <= 0.2:
            print(f"✅ 존재하는 정상적인 사이트입니다: {url}")
        elif 0.2 < score <= 0.5:
            print(f"⚠️ Suspicious: {url} (Risk Score: {score})")
            print(f"🔍 의심되는 원본 도메인: {target}")
        else:
            print(f"🚨 Dangerous! {url} (Risk Score: {score})")
            print(f"❗❗ 원본 도메인: {target} (높은 유사성 감지)")
    else:
        print(f"🚨 WARNING! {url}는 존재하지 않는 도메인입니다.")



def main():
    url = input("Enter the domain: ")
    # check_url(url)


if __name__ == "__main__":
    main()
