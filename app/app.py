from flask import Flask, render_template, request
import whois
import pycountry
import socket
import dns.resolver
import ssl
from datetime import datetime
from geopy.geocoders import Nominatim
import test

app = Flask(__name__)

# ✅ User-Agent 설정하여 차단 방지
geolocator = Nominatim(user_agent="my_geocoder")

# ✅ Geopy에서 검색할 수 있도록 국가명을 변환하는 딕셔너리 추가
COUNTRY_NAME_MAP = {
    "KR": "South Korea",
    "US": "United States",
    "CN": "China",
    "JP": "Japan",
    "FR": "France",
    "DE": "Germany",
    "RU": "Russia",
    "IN": "India",
    "BR": "Brazil",
    "GB": "United Kingdom"
}

def get_whois_info(domain):
    """WHOIS 정보 가져오기 + 도메인 연령 분석"""
    try:
        w = whois.whois(domain)
        country_code = w.country if hasattr(w, "country") and w.country else "Unknown"

        # 📌 도메인 등록일 가져오기
        creation_date = w.creation_date if hasattr(w, "creation_date") else "정보 없음"
        if isinstance(creation_date, list):
            creation_date = creation_date[0]  # 리스트일 경우 첫 번째 값 사용
        if creation_date != "정보 없음":
            days_since_creation = (datetime.now() - creation_date).days
            domain_age_status = f"{days_since_creation}일 경과 ({'🔴 신규 도메인 (주의!)' if days_since_creation < 180 else '🟢 오래된 도메인'})"
        else:
            domain_age_status = "❓ 등록일 정보 없음"

        # 📌 도메인 만료일 가져오기
        expiration_date = w.expiration_date if hasattr(w, "expiration_date") else "정보 없음"
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        if creation_date != "정보 없음" and expiration_date != "정보 없음":
            domain_lifetime = (expiration_date - creation_date).days
            short_registration_status = f"{domain_lifetime}일 등록 ({'🔴 짧은 등록 기간 (주의!)' if domain_lifetime < 365 else '🟢 장기 등록 도메인'})"
        else:
            short_registration_status = "❓ 등록 기간 정보 없음"

        # 📌 WHOIS 정보 보호 여부 확인
        whois_protected = "🔴 개인정보 보호 활성화 (주의!)" if "privacy" in str(w) else "🟢 공개된 등록 정보"

        return {
            "도메인": domain,
            "등록자": w.name if hasattr(w, "name") and w.name else "정보 없음",
            "등록기관": w.registrar if hasattr(w, "registrar") and w.registrar else "정보 없음",
            "등록국가": country_code,
            "이메일": w.emails if hasattr(w, "emails") and w.emails else "🔒 비공개",
            "주소": w.address if hasattr(w, "address") and w.address else "📍 주소 비공개",

            "등록일": creation_date,
            "도메인 연령": domain_age_status,
            "만료일": expiration_date,
            "등록 기간": short_registration_status,
            "네임서버": w.name_servers if hasattr(w, "name_servers") and w.name_servers else "정보 없음",
            "개인정보 보호 여부": whois_protected
        }
    except Exception as e:
        return {"WHOIS 조회 오류": str(e)}

def get_dns_info(domain):
    """DNS 레코드 조회"""
    dns_info = {}
    try:
        dns_info["A 레코드"] = [ip.address for ip in dns.resolver.resolve(domain, "A")]
    except:
        dns_info["A 레코드"] = "조회 실패"

    try:
        dns_info["MX 레코드"] = [mx.to_text() for mx in dns.resolver.resolve(domain, "MX")]
    except:
        dns_info["MX 레코드"] = "조회 실패"

    try:
        dns_info["NS 레코드"] = [ns.to_text() for ns in dns.resolver.resolve(domain, "NS")]
    except:
        dns_info["NS 레코드"] = "조회 실패"

    return dns_info

def get_ip_info(domain):
    """도메인의 IP 주소 및 호스팅 정보 조회"""
    try:
        ip_address = socket.gethostbyname(domain)
        return {"IP 주소": ip_address}
    except:
        return {"IP 주소": "조회 실패"}

def get_ssl_info(domain):
    """SSL 인증서 정보 조회"""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    "SSL 발급 기관": dict(cert["issuer"]) if "issuer" in cert else "정보 없음",
                    "SSL 유효 기간": cert["notBefore"] + " ~ " + cert["notAfter"] if "notBefore" in cert and "notAfter" in cert else "정보 없음"
                }
    except Exception as e:
        return {"SSL 정보": f"조회 실패 - {str(e)}"}

def get_country_coordinates(country_code):
    """ISO-2 국가 코드 → 위도/경도로 변환 (User-Agent 추가 & 국가명 변환)"""
    try:
        print(f"🔎 국가 코드 변환 시도: {country_code}")

        # ✅ 국가명 매핑 적용 (없으면 기본 변환 사용)
        country_name = COUNTRY_NAME_MAP.get(country_code, pycountry.countries.get(alpha_2=country_code).name)

        print(f"✅ 변환된 국가명: {country_name}")

        # Geopy 요청
        location = geolocator.geocode(country_name, timeout=10)
        if location:
            print(f"✅ 위도/경도 변환 성공: {location.latitude}, {location.longitude}")
            return location.latitude, location.longitude
        else:
            print("🚨 위도/경도 변환 실패 - 기본 좌표 사용")
            return 37.5665, 126.9780  # 기본값: 서울
    except Exception as e:
        print(f"❌ 오류 발생: {e}")

    return 37.5665, 126.9780  # 기본값 반환

@app.route("/", methods=["GET", "POST"])
def index():
    data = None
    if request.method == "POST":
        
        domain = request.form["domain"]
        test.check_url(domain)
        whois_info = get_whois_info(domain)
        dns_info = get_dns_info(domain)
        ip_info = get_ip_info(domain)
        ssl_info = get_ssl_info(domain)
        
        # 등록 국가가 있다면 위도/경도 변환
        if whois_info["등록국가"] and whois_info["등록국가"] != "Unknown":
            lat, lon = get_country_coordinates(whois_info["등록국가"])
            whois_info["위도"] = lat if lat is not None else 37.5665  # 기본값: 서울
            whois_info["경도"] = lon if lon is not None else 126.9780  # 기본값: 서울

        # 모든 데이터 합쳐서 전달
        data = {**whois_info, **dns_info, **ip_info, **ssl_info}

        print(f"🔍 도메인: {domain}, 등록국가: {whois_info['등록국가']}, 도메인 연령: {whois_info['도메인 연령']}, 등록 기간: {whois_info['등록 기간']}")  # ✅ 터미널에서 확인!
        
    return render_template("index.html", data=data)

if __name__ == "__main__":
    app.run(debug=True)


















