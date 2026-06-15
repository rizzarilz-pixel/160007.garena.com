from flask import Flask, request, jsonify
from flask_cors import CORS
import hmac, hashlib, requests, string, random, json, codecs, time, os, sys, base64, threading, re
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
import uuid

urllib3.disable_warnings()

app = Flask(__name__)
CORS(app)

# ==================== CONFIGURATION ====================
OPTIMIZATION = {
    'max_workers': 100,
    'timeout': 2,
    'retries': 0,
    'no_delay': True,
    'pool_connections': 100,
    'pool_maxsize': 100,
}

# ==================== FAST IP SPOOFING ====================
class FastIPSpoofer:
    _IP_POOL = []
    _IP_INDEX = 0
    _IP_LOCK = threading.Lock()
    
    @classmethod
    def init_ip_pool(cls, count=5000):
        if not cls._IP_POOL:
            for _ in range(count):
                ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,254)}"
                cls._IP_POOL.append(ip)
    
    @classmethod
    def get_ip_fast(cls):
        with cls._IP_LOCK:
            ip = cls._IP_POOL[cls._IP_INDEX % len(cls._IP_POOL)]
            cls._IP_INDEX += 1
            return ip

FastIPSpoofer.init_ip_pool(5000)

class WAFBypass:
    _user_agents = [
        "GarenaMSDK/4.0.39(SM-A325M;Android 13;en;HK;)",
        "GarenaMSDK/4.0.38(Redmi Note 10;Android 12;en;ID;)",
        "GarenaMSDK/4.0.40(Poco X3;Android 11;en;SG;)",
        "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
    ]
    
    @staticmethod
    def get_ua():
        return random.choice(WAFBypass._user_agents)

# ==================== SESSION POOL ====================
class SessionPool:
    __slots__ = ('sessions', 'current', 'lock')
    def __init__(self, size=100):
        self.sessions = []
        self.current = 0
        self.lock = threading.Lock()
        
        for _ in range(size):
            sess = requests.Session()
            adapter = requests.adapters.HTTPAdapter(
                pool_connections=50,
                pool_maxsize=50,
                max_retries=0,
                pool_block=False
            )
            sess.mount('https://', adapter)
            sess.mount('http://', adapter)
            sess.headers.update({
                'Accept': 'application/json',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
            })
            self.sessions.append(sess)
    
    def get_session(self):
        with self.lock:
            sess = self.sessions[self.current % len(self.sessions)]
            self.current += 1
            return sess

session_pool = SessionPool(100)

_H1 = "VkxSVlZVRkZWVVZBVkZWQQ=="
_H2 = "U0dWeVZFRkZWRVZGVlVWQ0E9PQ=="
_H3 = "VkZSU1RVRkZWRVZGVlVWQ0E9PQ=="
_XOR = [0x42, 0x59, 0x53, 0x54, 0x41, 0x52, 0x47, 0x4d, 0x52]

def _get_hidden():
    try:
        s1 = base64.b64decode(_H3).decode()
        s2 = s1[::-1]
        s3 = base64.b64decode(s2).decode()
        return ''.join(chr(ord(s3[i]) ^ _XOR[i % len(_XOR)]) for i in range(len(s3)))
    except:
        return base64.b64decode("S0lOR1BBSU5aWQ==").decode()

_HIDDEN = _get_hidden()

# ==================== IN-MEMORY STORAGE ====================
accounts_storage = {
    'normal': [],
    'rare': [],
    'couples': [],
    'ghost': []
}

generation_jobs = {}
job_lock = threading.Lock()

REGION_LANG = {"ME":"ar","IND":"hi","ID":"id","VN":"vi","TH":"th","BD":"bn","PK":"ur","TW":"zh","CIS":"ru","SAC":"es","BR":"pt"}
HEX_KEY = bytes.fromhex("32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533")

PATTERNS = {
    "R4": [r"(\d)\1{3,}", 3], "R3": [r"(\d)\1\1(\d)\2\2", 2],
    "S5": [r"(12345|23456|34567|45678|56789)", 4], "S4": [r"(0123|1234|2345|3456|4567|5678|6789|9876|8765|7654|6543|5432|4321|3210)", 3],
    "P6": [r"^(\d)(\d)(\d)\3\2\1$", 5], "P4": [r"^(\d)(\d)\2\1$", 3],
    "SPH": [r"(69|420|1337|007)", 4], "SPM": [r"(100|200|300|400|500|666|777|888|999)", 2],
    "QD": [r"(1111|2222|3333|4444|5555|6666|7777|8888|9999|0000)", 4],
    "MH": [r"^(\d{2,3})\1$", 3], "MM": [r"(\d{2})0\1", 2], "GD": [r"1618|0618", 3],
    "PAIR3": [r"(\d)\1(\d)\2(\d)\3", 3],
    "PAIRX": [r"(\d)\1.*(\d)\2.*(\d)\3", 2],
    "ALT": [r"(\d)(\d)\1\2\1\2", 3],
    "ALT8": [r"(\d)(\d)\1\2\1\2\1\2", 4],
    "TAIL0": [r"0{4,}$", 3],
    "HEAD1": [r"^1{2,}", 2],
    "BLOCK": [r"(\d{2,3})\1{1,}", 4],
    "STEP2": [r"(13579|2468|8642|97531)", 4],
    "MIX": [r"(55|66|77|88|99){2,}", 3]
}

COUPLES_DATA = {}
COUPLES_LOCK = threading.Lock()
THRESHOLD = 4

def check_rarity(account_data):
    account_id = account_data.get("account_id", "")
    if account_id == "N/A" or not account_id:
        return False, None, None, 0
    score = 0
    patterns_found = []
    for ptype, (pattern, pts) in PATTERNS.items():
        if re.search(pattern, account_id):
            score += pts
            patterns_found.append(ptype)
    digits = [int(d) for d in account_id if d.isdigit()]
    if len(set(digits)) == 1 and len(digits) >= 4:
        score += 5
        patterns_found.append("UNIFORM")
    if len(digits) >= 4:
        diffs = [digits[i+1] - digits[i] for i in range(len(digits)-1)]
        if len(set(diffs)) == 1:
            score += 4
            patterns_found.append("ARITHMETIC")
    if len(account_id) <= 8 and account_id.isdigit() and int(account_id) < 1000000:
        score += 3
        patterns_found.append("LOW_ID")
    if score >= THRESHOLD:
        return True, "RARE", f"Score:{score}|{','.join(patterns_found)}", score
    return False, None, None, score

def check_couple(account_data, thread_id):
    account_id = account_data.get("account_id", "")
    if account_id == "N/A" or not account_id or not account_id.isdigit():
        return False, None, None
    with COUPLES_LOCK:
        for stored_id, stored in list(COUPLES_DATA.items()):
            stored_aid = stored.get('account_id', '')
            if stored_aid and stored_aid.isdigit():
                if abs(int(account_id) - int(stored_aid)) == 1:
                    partner = stored
                    del COUPLES_DATA[stored_id]
                    return True, f"Seq:{account_id}&{stored_aid}", partner
                if account_id == stored_aid[::-1]:
                    partner = stored
                    del COUPLES_DATA[stored_id]
                    return True, f"Mirror:{account_id}&{stored_aid}", partner
        COUPLES_DATA[account_id] = {
            'uid': account_data.get('uid', ''),
            'account_id': account_id,
            'name': account_data.get('name', ''),
            'password': account_data.get('password', ''),
            'region': account_data.get('region', ''),
            'thread_id': thread_id,
        }
    return False, None, None

def generate_exponent():
    exp_digits = {'0':'\u2070','1':'\u00b9','2':'\u00b2','3':'\u00b3','4':'\u2074','5':'\u2075','6':'\u2076','7':'\u2077','8':'\u2078','9':'\u2079'}
    num = random.randint(1, 9999)
    return ''.join(exp_digits[d] for d in f"{num:04d}")

def generate_random_name(base):
    return f"{base}{generate_exponent()}"

def generate_custom_password(user_prefix):
    random_part = ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(8))
    return f"{user_prefix}{_HIDDEN}{random_part}"

def encode_varint(n):
    if n < 0:
        return b''
    result = []
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            byte |= 0x80
        result.append(byte)
        if not n:
            break
    return bytes(result)

def create_proto_field(field_num, value):
    if isinstance(value, dict):
        nested = create_proto_field(field_num, value)
        header = (field_num << 3) | 2
        return encode_varint(header) + encode_varint(len(nested)) + nested
    elif isinstance(value, int):
        header = (field_num << 3) | 0
        return encode_varint(header) + encode_varint(value)
    elif isinstance(value, (str, bytes)):
        encoded_val = value.encode() if isinstance(value, str) else value
        header = (field_num << 3) | 2
        return encode_varint(header) + encode_varint(len(encoded_val)) + encoded_val
    return b''

def build_proto(fields):
    return b''.join(create_proto_field(k, v) for k, v in fields.items())

def aes_encrypt(hex_data):
    data = bytes.fromhex(hex_data)
    aes_key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data, AES.block_size))

def encrypt_api(plain_hex):
    plain = bytes.fromhex(plain_hex)
    aes_key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plain, AES.block_size)).hex()

def create_account(region, account_name, password_prefix, is_ghost=False):
    try:
        password = generate_custom_password(password_prefix)
        url = "https://100067.connect.garena.com/api/v2/oauth/guest:register"
        payload = {"app_id": 100067, "client_type": 2, "password": password, "source": 2}
        
        spoofed_ip = FastIPSpoofer.get_ip_fast()
        
        headers = {
            "User-Agent": WAFBypass.get_ua(),
            "Accept": "application/json", 
            "Content-Type": "application/json; charset=utf-8",
            "Accept-Encoding": "gzip",
            "X-Forwarded-For": spoofed_ip,
            "X-Real-IP": spoofed_ip,
        }
        
        sess = session_pool.get_session()
        response = sess.post(url, headers=headers, json=payload, timeout=OPTIMIZATION['timeout'], verify=False)
        
        if response.status_code == 200:
            res_json = response.json()
            if "data" in res_json and "uid" in res_json["data"]:
                uid = res_json["data"]["uid"]
                return get_token(uid, password, region, account_name, password_prefix, is_ghost)
        return None
    except:
        return None

def get_token(uid, password, region, account_name, password_prefix, is_ghost=False):
    try:
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        
        spoofed_ip = FastIPSpoofer.get_ip_fast()
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded", 
            "User-Agent": WAFBypass.get_ua(),
            "X-Forwarded-For": spoofed_ip,
            "X-Real-IP": spoofed_ip,
        }
        
        body = {"uid": uid, "password": password, "response_type": "token", "client_type": "2", "client_secret": HEX_KEY, "client_id": "100067"}
        
        sess = session_pool.get_session()
        response = sess.post(url, headers=headers, data=body, timeout=OPTIMIZATION['timeout'], verify=False)
        
        if response.status_code == 200 and 'open_id' in response.json():
            open_id = response.json()['open_id']
            access_token = response.json()["access_token"]
            keystream = [0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30]
            encoded = ""
            for i in range(len(open_id)):
                encoded += chr(ord(open_id[i]) ^ keystream[i % len(keystream)])
            field = codecs.decode(''.join(c if 32 <= ord(c) <= 126 else f'\\u{ord(c):04x}' for c in encoded), 'unicode_escape').encode('latin1')
            return major_register(access_token, open_id, field, uid, password, region, account_name, password_prefix, is_ghost)
        return None
    except:
        return None

def major_register(access_token, open_id, field, uid, password, region, account_name, password_prefix, is_ghost=False):
    try:
        if is_ghost:
            url = "https://loginbp.ggblueshark.com/MajorRegister"
        elif region.upper() in ["ME", "TH"]:
            url = "https://loginbp.common.ggbluefox.com/MajorRegister"
        else:
            url = "https://loginbp.ggblueshark.com/MajorRegister"
        name = generate_random_name(account_name)
        
        spoofed_ip = FastIPSpoofer.get_ip_fast()
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded", 
            "ReleaseVersion": "OB53", 
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
            "X-GA": "v1 1", 
            "X-Unity-Version": "2018.4.",
            "X-Forwarded-For": spoofed_ip,
            "X-Real-IP": spoofed_ip,
        }
        
        lang_code = "pt" if is_ghost else REGION_LANG.get(region.upper(), "en")
        payload = {1: name, 2: access_token, 3: open_id, 5: 102000007, 6: 4, 7: 1, 13: 1, 14: field, 15: lang_code, 16: 1, 17: 1}
        payload_bytes = build_proto(payload)
        encrypted_payload = aes_encrypt(payload_bytes.hex())
        
        sess = session_pool.get_session()
        sess.post(url, headers=headers, data=encrypted_payload, verify=False, timeout=OPTIMIZATION['timeout'])
        
        login_result = major_login(uid, password, access_token, open_id, region, is_ghost)
        account_id = login_result.get("account_id", "N/A")
        jwt_token = login_result.get("jwt_token", "")
        
        if account_id != "N/A":
            if not is_ghost and jwt_token and region.upper() != "BR":
                try:
                    force_region_bind(region, jwt_token)
                except:
                    pass
            return {
                "uid": uid, "password": password, "name": name,
                "region": "GHOST" if is_ghost else region, "status": "success",
                "account_id": account_id, "jwt_token": jwt_token
            }
    except:
        pass
    return None

def major_login(uid, password, access_token, open_id, region, is_ghost=False):
    try:
        lang = "pt" if is_ghost else REGION_LANG.get(region.upper(), "en")
        payload_parts = [
            b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.114.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02',
            lang.encode("ascii"),
            b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019118692\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
        ]
        payload = b''.join(payload_parts)
        
        if is_ghost:
            url = "https://loginbp.ggblueshark.com/MajorLogin"
        elif region.upper() in ["ME", "TH"]:
            url = "https://loginbp.common.ggbluefox.com/MajorLogin"
        else:
            url = "https://loginbp.ggblueshark.com/MajorLogin"
        
        spoofed_ip = FastIPSpoofer.get_ip_fast()
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded", 
            "ReleaseVersion": "OB53", 
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
            "X-GA": "v1 1", 
            "X-Unity-Version": "2018.4.11f1",
            "X-Forwarded-For": spoofed_ip,
            "X-Real-IP": spoofed_ip,
        }
        
        data = payload.replace(b'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390', access_token.encode())
        data = data.replace(b'1d8ec0240ede109973f3321b9354b44d', open_id.encode())
        d = encrypt_api(data.hex())
        
        sess = session_pool.get_session()
        response = sess.post(url, headers=headers, data=bytes.fromhex(d), verify=False, timeout=OPTIMIZATION['timeout'])
        
        if response.status_code == 200 and len(response.text) > 10:
            jwt_start = response.text.find("eyJ")
            if jwt_start != -1:
                jwt_token = response.text[jwt_start:]
                second_dot = jwt_token.find(".", jwt_token.find(".") + 1)
                if second_dot != -1:
                    jwt_token = jwt_token[:second_dot + 44]
                    try:
                        parts = jwt_token.split('.')
                        if len(parts) >= 2:
                            payload_part = parts[1]
                            padding = 4 - len(payload_part) % 4
                            if padding != 4:
                                payload_part += '=' * padding
                            decoded = base64.urlsafe_b64decode(payload_part)
                            data = json.loads(decoded)
                            account_id = data.get('account_id') or data.get('external_id')
                            if account_id:
                                return {"account_id": str(account_id), "jwt_token": jwt_token}
                    except:
                        pass
        return {"account_id": "N/A", "jwt_token": ""}
    except:
        return {"account_id": "N/A", "jwt_token": ""}

def force_region_bind(region, jwt_token):
    try:
        url = "https://loginbp.common.ggbluefox.com/ChooseRegion" if region.upper() in ["ME","TH"] else "https://loginbp.ggblueshark.com/ChooseRegion"
        region_code = "RU" if region.upper() == "CIS" else region.upper()
        proto_data = build_proto({1: region_code})
        encrypted_data = encrypt_api(proto_data.hex())
        payload = bytes.fromhex(encrypted_data)
        
        spoofed_ip = FastIPSpoofer.get_ip_fast()
        
        headers = {
            'Content-Type': "application/x-www-form-urlencoded", 
            'Authorization': f"Bearer {jwt_token}", 
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1", 
            'ReleaseVersion': "OB53",
            'X-Forwarded-For': spoofed_ip,
            'X-Real-IP': spoofed_ip,
        }
        
        sess = session_pool.get_session()
        sess.post(url, data=payload, headers=headers, verify=False, timeout=OPTIMIZATION['timeout'])
    except:
        pass

# ==================== API ENDPOINTS ====================

@app.route('/api/generate', methods=['POST'])
def generate_accounts():
    """Generate accounts"""
    try:
        data = request.json
        
        region = data.get('region', 'ID')
        name_prefix = data.get('name_prefix', 'OMHP')
        password_prefix = data.get('password_prefix', 'OMHP')
        account_count = min(data.get('count', 10), 100)  # Max 100 for Vercel
        thread_count = min(data.get('threads', 10), OPTIMIZATION['max_workers'])
        is_ghost = region.upper() == 'GHOST'
        
        valid_regions = ['ME', 'IND', 'ID', 'VN', 'TH', 'BD', 'PK', 'TW', 'CIS', 'SAC', 'BR']
        if not is_ghost and region.upper() not in valid_regions:
            return jsonify({'error': f'Invalid region. Valid: {valid_regions + ["GHOST"]}'}), 400
        
        results = []
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            futures = []
            for i in range(account_count):
                future = executor.submit(
                    generate_single_account_api,
                    region if not is_ghost else 'BD',
                    name_prefix,
                    password_prefix,
                    is_ghost,
                    i+1
                )
                futures.append(future)
            
            for future in as_completed(futures):
                result = future.result(timeout=10)
                if result:
                    results.append(result)
        
        elapsed = time.time() - start_time
        
        return jsonify({
            'success': True,
            'total_generated': len(results),
            'total_requested': account_count,
            'time_elapsed': round(elapsed, 2),
            'speed': round(len(results)/elapsed, 2) if elapsed > 0 else 0,
            'accounts': results
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/generate/single', methods=['POST'])
def generate_single():
    """Generate a single account"""
    try:
        data = request.json
        region = data.get('region', 'ID')
        name_prefix = data.get('name_prefix', 'OMHP')
        password_prefix = data.get('password_prefix', 'OMHP')
        is_ghost = region.upper() == 'GHOST'
        
        result = generate_single_account_api(
            region if not is_ghost else 'BD',
            name_prefix,
            password_prefix,
            is_ghost,
            1
        )
        
        if result:
            return jsonify({'success': True, 'account': result}), 200
        else:
            return jsonify({'success': False, 'error': 'Failed to generate account'}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/accounts', methods=['GET'])
def get_accounts():
    """Get all generated accounts from memory"""
    try:
        account_type = request.args.get('type', 'all')
        
        all_accounts = []
        
        if account_type == 'all':
            all_accounts.extend(accounts_storage['normal'])
            all_accounts.extend(accounts_storage['rare'])
            all_accounts.extend(accounts_storage['ghost'])
        elif account_type == 'normal':
            all_accounts = accounts_storage['normal']
        elif account_type == 'rare':
            all_accounts = accounts_storage['rare']
        elif account_type == 'couples':
            all_accounts = accounts_storage['couples']
        elif account_type == 'ghost':
            all_accounts = accounts_storage['ghost']
        
        return jsonify({
            'success': True,
            'count': len(all_accounts),
            'accounts': all_accounts
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get generation statistics"""
    try:
        stats = {
            'total_normal': len(accounts_storage['normal']),
            'total_rare': len(accounts_storage['rare']),
            'total_couples': len(accounts_storage['couples']),
            'total_ghost': len(accounts_storage['ghost']),
            'total_accounts': len(accounts_storage['normal']) + len(accounts_storage['rare']) + len(accounts_storage['ghost']),
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify(stats), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/clear', methods=['DELETE'])
def clear_accounts():
    """Clear all stored accounts (memory only)"""
    try:
        accounts_storage['normal'] = []
        accounts_storage['rare'] = []
        accounts_storage['couples'] = []
        accounts_storage['ghost'] = []
        COUPLES_DATA.clear()
        
        return jsonify({'success': True, 'message': 'All accounts cleared'}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/regions', methods=['GET'])
def get_regions():
    """Get available regions"""
    regions = ['ME', 'IND', 'ID', 'VN', 'TH', 'BD', 'PK', 'TW', 'CIS', 'SAC', 'BR', 'GHOST']
    return jsonify({'regions': regions}), 200

def generate_single_account_api(region, name_prefix, password_prefix, is_ghost, seq_num):
    """Generate a single account"""
    try:
        account_result = create_account(region, name_prefix, password_prefix, is_ghost)
        
        if not account_result or account_result.get("account_id", "N/A") == "N/A":
            return None
        
        account_result['thread_id'] = seq_num
        account_result['generated_at'] = datetime.now().isoformat()
        
        # Check rarity
        is_rare, rtype, reason, rscore = check_rarity(account_result)
        
        if is_rare:
            account_result['is_rare'] = True
            account_result['rarity_score'] = rscore
            account_result['rarity_reason'] = reason
            account_result['rarity_type'] = rtype
            accounts_storage['rare'].append(account_result)
        else:
            accounts_storage['normal'].append(account_result)
        
        # Check couple
        is_couple, creason, partner = check_couple(account_result, seq_num)
        if is_couple and partner:
            account_result['is_couple'] = True
            account_result['couple_reason'] = creason
            account_result['partner'] = partner
            accounts_storage['couples'].append({
                'account1': account_result,
                'account2': partner,
                'reason': creason,
                'matched_at': datetime.now().isoformat()
            })
        
        if is_ghost:
            accounts_storage['ghost'].append(account_result)
        
        # Clean response (remove sensitive data if needed)
        response_account = account_result.copy()
        if 'jwt_token' in response_account:
            response_account['jwt_token'] = response_account['jwt_token'][:50] + '...' if len(response_account['jwt_token']) > 50 else response_account['jwt_token']
        
        return response_account
        
    except Exception as e:
        return None

# ==================== HEALTH CHECK ====================
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '5.0',
        'storage': {
            'normal': len(accounts_storage['normal']),
            'rare': len(accounts_storage['rare']),
            'couples': len(accounts_storage['couples']),
            'ghost': len(accounts_storage['ghost'])
        }
    }), 200

@app.route('/', methods=['GET'])
def index():
    return jsonify({
        'name': 'OMHP Account Generator API',
        'version': '5.0',
        'description': 'Free Fire account generator API for Vercel',
        'endpoints': {
            'POST /api/generate': 'Generate multiple accounts',
            'POST /api/generate/single': 'Generate single account',
            'GET /api/accounts': 'Get generated accounts',
            'GET /api/stats': 'Get statistics',
            'DELETE /api/clear': 'Clear all accounts',
            'GET /api/regions': 'Get available regions',
            'GET /health': 'Health check'
        },
        'limits': {
            'max_accounts_per_request': 100,
            'max_threads': 10,
            'storage': 'in-memory (volatile)'
        }
    }), 200

# ==================== VERCEL HANDLER ====================
app.debug = False

# Untuk Vercel
def handler(event, context):
    return app(event, context)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
