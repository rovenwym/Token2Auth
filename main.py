import uuid
import requests
from colorama import Fore, init
from datetime import datetime
import threading
import os
import ctypes
import time
import tls_client
import json
import sys
import re
from base64 import b64encode, urlsafe_b64decode
from itertools import cycle

print("Loading config")
f = open("input/config.json", "r").read()
config = json.loads(f)
__useragent__ = config["user_agent"]
proxyless = config["proxyless"]
license = config["license"]
debug = config["debug"]
threads = config["threads"]
delay = config["delay"]
max_retries = config["max_retries"]
client_id = config["client_id"]
secret = config["client_secret"]
redirect = config["redirect_uri"]
proxyless = config["proxyless"]
include_tokens = config["include_tokens"]
out_file = config["output"]
print("Connecting with authentication backend...")
base = requests.get("https://pastebin.com/raw/5g6qYZsY").text

def get_hwid():
    return str(uuid.UUID(int=uuid.getnode()).hex[-12:])

def activate_license(key):
    hwid = get_hwid()
    activate_url = f"{base}/activate"
    activate_data = {"key": key, "hwid": hwid}
    activate_req = requests.post(activate_url, data=activate_data)
    if activate_req.status_code == 200:
        activate_resp_json = activate_req.json()
        if activate_resp_json["message"] == "License activated successfully":
            return True
        return False
    else:
        return False

def check_license():
    key = license
    hwid = get_hwid()
    license_url = f"{base}/check_license"
    data = {"key": key, "hwid": hwid}
    resp = requests.post(license_url, data=data)
    if resp.status_code == 200:
        resp_jsn = resp.json()
        if resp_jsn["message"] == "activate":
            return activate_license(key)
        return resp_jsn["message"] == "License is valid"
    else:
        print("Error checking license.")

time.sleep(1)
tkW = open("output/tokens-worked.txt", "a")
print("Loading proxies")
time.sleep(1)
with open("input/proxies.txt", "r", encoding="utf-8") as f:
    proxies = cycle(f.read().splitlines())

def get_proxy():
    return next(proxies)

def get_build_number():
    try:
        bd_response = requests.get("https://discord.com/login").text
        bd = 'https://discord.com/assets/' + re.compile(r'assets/+([a-z0-9]+)\.js').findall(bd_response)[-2]+'.js'
        final_req = requests.get(bd).text
        final_resp = final_req.find('buildNumber')+24
        return int(final_req[final_resp:final_resp + 6])
    except Exception:
        return 236850

build_number = get_build_number()
cv = "108.0.5359.215"
__properties__ = b64encode(json.dumps({"os": "Windows", "browser": "Discord Client", "release_channel": "stable", "client_version": "1.0.9013", "os_version": "10.0.19045", "os_arch": "x64",
                           "system_locale": "en-US", "client_build_number": build_number, "native_build_number": 32266, "client_version_string": "1.0.9013"}, separators=(',', ':')).encode()).decode()
authed_ = []

def get_headers(tkn):
    headers = {"Authorization": tkn, "Accept-Encoding": "deflate", "Origin": "https://discord.com", "Accept": "*/*", "DNT": "1", "X-Discord-Locale": "en-US", "sec-ch-ua": "\"Not?A_Brand\";v=\"8\", \"Chromium\";v=\"108\"", "sec-ch-ua-platform": "\"Windows\"", "sec-fetch-dest": "empty", "sec-fetch-mode": "cors", "sec-fetch-site": "same-origin", "sec-ch-ua-mobile": "?0", "X-Super-Properties": __properties__,
                         "User-Agent": __useragent__, "Referer": "https://discord.com/channels/@me", "X-Debug-Options": "bugReporterEnabled", "Content-Type": "application/json", "X-Discord-Timezone": "Asia/Calcutta", 'cookie': '__dcfduid=23a63d20476c11ec9811c1e6024b99d9; __sdcfduid=23a63d21476c11ec9811c1e6024b99d9e7175a1ac31a8c5e4152455c5056eff033528243e185c5a85202515edb6d57b0; locale=en-GB', 'te': 'trailers', }
    return headers

os.system("cls")
authorized = 0
failed = 0
total = 0
saver_total = 0
now = datetime.now()
formatted_time = now.strftime("[%H:%M:%S]")
tkns_loaded = len(open("input/tokens.txt").readlines())
init(convert=True, strip=False)
green = Fore.GREEN
reset = Fore.RESET
screen = f'''CREATOR: rxven
discord.gg/skidder
discord.gg/skidder
discord.gg/skidder

{green}{formatted_time}{reset} Tokens: {tkns_loaded}
{green}{formatted_time}{reset} Proxyless: {proxyless}
{green}{formatted_time}{reset} Proxies: {len(open("input/proxies.txt").readlines())}
{green}{formatted_time}{reset} Chrome Version : 117
{green}{formatted_time}{reset} Browser Version : 117.0.0.0
{green}{formatted_time}{reset} Fetching discord build number at discord.com
{green}{formatted_time}{reset} Successfully grabbed latest build number [{build_number}]
{green}{formatted_time}{reset} Discord API Version : v9
{green}{formatted_time}{reset} UserAgent : {__useragent__}


'''
print(screen)
time.sleep(5)
auth = f"https://discord.com/api/oauth2/authorize?client_id={client_id}&redirect_uri={redirect}&response_type=code&scope=identify%20guilds.join"

def title():
    ctypes.windll.kernel32.SetConsoleTitleW("[Creator: cinquina] | Tokens: %s | Total Requests: %s | Authorized: %s | Failed: %s" % (
        tkns_loaded, total, authorized, failed))

af = open("output/cache.txt", "a", encoding='utf-8')
authed_ = ""

def getCookies(proxy) -> list:
    for _ in range(max_retries):
        try:
            headers = {'Accept': '*/*', 'Accept-Language': 'en-US,en;q=0.9', 'Connection': 'keep-alive', 'Referer': 'https://discord.com/', 'Sec-Fetch-Dest': 'empty', 'Sec-Fetch-Mode': 'cors',
                                 'Sec-Fetch-Site': 'same-origin', 'Sec-GPC': '1', 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36', 'X-Track': __properties__, }
            cks_session = tls_client.Session(
                client_identifier="chrome117", random_tls_extension_order=True)
            cks_response = cks_session.get(
                'https://discord.com/api/v9/experiments', headers=headers, proxy="http://"+proxy)
            return cks_response.cookies, cks_response.json().get("fingerprint")
        except Exception as ex:
            if debug:
                dbg_time = datetime.now()
                dbg_timestamp = dbg_time.strftime(
                    "[%H:%M:%S]")
                print(f"{dbg_timestamp} [DEBUG]: ",
                      ex)
            continue

def authorizer(token):
    proxy = None
    headers = get_headers(token)
    headers["X-Fingerprint"] = "1162011318769950780.McNABsA9abn1vpFUVhqyog2kVm0"
    cookies = {'__dcfduid': '9fa07fd468fe11ee9eddaea6cf6ac781', '__sdcfduid': '9fa07fd468fe11ee9eddaea6cf6ac7815a10a14b2ee443499d7d53c8cb9e5c016086b1aca1e62c80d8d98463177d00b8',
                         '__cfruid': '56f1219c13f0831ee60503ee02415333302f7bee-1697115330', 'locale': 'en-US'}
    global authorized, authed_, failed, total, saver_total
    if not proxyless:
        str_proxy = get_proxy()
        proxy = "http://"+str_proxy
        try:
            cookies_get, fingerprint = getCookies(str_proxy)
            cookies = {'__dcfduid': cookies_get.get('__dcfduid'), '__sdcfduid': cookies_get.get(
                '__sdcfduid'), '__cfruid': cookies_get.get('__cfruid'), 'locale': 'en-US', }
            headers.update({"Cookie": "; ".join(
                [f"{cinquinawashere}={fivehaterontop}"for cinquinawashere, fivehaterontop in cookies.items()])})
            headers["X-Fingerprint"] = fingerprint
        except Exception as exception:
            pass
    for _ in range(max_retries):
        total += 1
        try:
            session = tls_client.Session(
                client_identifier="chrome117", random_tls_extension_order=True)
            session.headers.update(headers)
            data_one = {"authorize": "true",
                                 "permissions": "0"}
            req_one = session.post(
                auth, json=data_one, proxy=proxy)
            if req_one.status_code in (200, 201, 204):
                location = req_one.json()['location']
                code_one = location.replace(
                    f"{redirect}?code=", "")
                data_one = {'client_id': client_id, 'client_secret': secret,
                                     'grant_type': 'authorization_code', 'code': code_one, 'redirect_uri': redirect}
                req_one = tls_client.Session(client_identifier="chrome117", random_tls_extension_order=True).post(
                    "https://discord.com/api/v9/oauth2/token", data=data_one, headers={'Content-Type': 'application/x-www-form-urlencoded', "Accept-Encoding": "deflate"}, proxy=proxy)
                if not req_one.status_code in (200, 201, 204):
                    continue
                req_one_json = req_one.json()
                access_token = req_one_json['access_token']
                refresh_token = req_one_json['refresh_token']
                suckmydick = urlsafe_b64decode(token.split(".")[
                                                      0]+"==").decode("utf-8")
                if include_tokens:
                    authed_token = f"{suckmydick}:{access_token}:{refresh_token}:{token}\n"
                else:
                    authed_token = f"{suckmydick}:{access_token}:{refresh_token}\n"
                authed_ += authed_token
                af.write(authed_token)
                tkW.write(token + "\n")
                authorized += 1
                title()
                debug_dt = datetime.now()
                timestamp_dbg = debug_dt.strftime(
                    "[%H:%M:%S]")
                print(f"{timestamp_dbg} {authorized} {green}Authorized{reset}: ",
                      token[:50]+"****************************")
                saver_total += 1
                break
            else:
                if debug:
                    print(f"{timestamp_dbg} [DEBUG]: Failed to Authorize: ",
                          token, req_one.text)
                saver_total += 1
                failed += 1
                title()
                break
        except Exception as exception:
            if debug:
                debug_dt = datetime.now()
                timestamp_dbg = debug_dt.strftime(
                    "[%H:%M:%S]")
                print(f"{timestamp_dbg} [DEBUG]: Failed to Authorize: ",
                      token, exception)
            failed += 1
            saver_total += 1
            title()
            continue

f = open("input/tokens.txt", "r").read().splitlines()

def start():
    global delay
    for token in f:
        token = token.strip()
        try:
            token_touse = token.split(":")[2]
        except:
            token_touse = token
        if proxyless and delay < 0.11:
            delay = 0.1
        elif delay < 0.05:
            delay = 0.05
        time.sleep(delay)
        try:
            thread = threading.Thread(
                target=authorizer, args=(token_touse,)).start()
        except:
            pass

start()

def save():
    time.sleep(2)
    while True:
        time.sleep(1)
        global saver_total
        if saver_total >= tkns_loaded:
            af.close()
            tkW.close()
            open(out_file, "a").close()
            output_file = open(out_file, "w")
            output_file.write(authed_)
            output_file.close()
            datetime_time = datetime.now()
            formatted_time = datetime_time.strftime(
                "[%H:%M:%S]")
            print("\n\n%s [INFO]: Total Requests: %s | Authorized: %s | Failed: %s" % (
                formatted_time, total, authorized, failed))
            input("Press Enter to exit > ")
            break
        else:
            continue

save()