#!/usr/bin/env python3
"""
Greenhouse-style HTTP checker for FirmAE
Based on Greenhouse/plugins/http_check.py
"""

import requests
import lxml.html
import sys
import time
import os
import selenium
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.common.exceptions import UnexpectedAlertPresentException
from urllib3.exceptions import InsecureRequestWarning
from requests.auth import HTTPDigestAuth

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Default credentials (matching Greenhouse)
USER_AUTHS = ['admin', '', 'nvram_llm']
PASSWORD_AUTHS = ['', 'admin', 'password', '1234', 'nvram_llm']
MAX_RETRIES = 3
WHITELIST = [".jpg", ".gif", ".png", ".jpeg", ".tiff", ".bmp", ".webp", ".bmp", ".svg"]
HTTP_500_MSG = "Failed to load resource: the server responded with a status of 500 (Internal Server Error)"

class WebCheck:
    def __init__(self):
        self.old_path = ""
        self.driver = None
        self.connected = False
        self.current_url = ""

    def Connect(self, url, auth):
        print("[FirmAE] WebCheck Connect")
        options = webdriver.ChromeOptions()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--screen-size=1200x600')
        options.add_argument('--disable-extensions')
        options.add_argument('--disable-dev-shm-usage')
        chromedriver_path = "/gh/chromedriver"
        service = Service(executable_path=chromedriver_path)
        self.driver = webdriver.Chrome(service=service, options=options)
        self.driver.set_page_load_timeout(60)
        try:
            if ":" in auth:
                index = url.index("://")
                splitIndex = index+3
                head = url[:splitIndex]
                tail = url[splitIndex:]
                print(f"[FirmAE]     - GET {head + auth + '@' + tail}")
                self.driver.get(head + auth + '@' + tail)
            else:
                print(f"[FirmAE]     - GET {url}")
                self.driver.get(url)
            time.sleep(5)
            self.connected = True
        except Exception as e:
            print(e)
            self.connected = False

    def HandleAlert(self):
        try:
            alert = self.driver.switch_to.alert
            if alert:
                print("[FirmAE]     - catching and accepting alert")
                alert.accept()
            return alert
        except:
            return None

    def Check(self):
        if self.connected == True:
            page_source = None
            retry = True
            while retry:
                try:
                    page_source = self.driver.page_source
                    self.current_url = self.driver.current_url
                    retry = False

                    print("[FirmAE] Check")
                    print("[FirmAE] ="*50)
                    print("[FirmAE] HTML source")
                    print("[FirmAE] ="*50)
                    if len(page_source) > 200:
                        print(page_source[:200])
                        print("[FirmAE] ="*50)
                        print("[FirmAE] <truncated>")
                    else:
                        print(page_source)
                    print("[FirmAE] ="*50)
                    if "<html" in page_source or "<script" in page_source:
                        for entry in self.driver.get_log('browser'):
                            if entry["level"] == "SEVERE":
                                if HTTP_500_MSG in entry["message"]:
                                    logmsg = entry["message"]
                                    index = logmsg.find(HTTP_500_MSG)
                                    error_target = logmsg[:index].lower()
                                    isWhitelisted = False
                                    for filetype in WHITELIST:
                                        if filetype in error_target:
                                            isWhitelisted = True
                                            break
                                    if isWhitelisted:
                                        continue
                                    print(entry)
                                    print("[FirmAE] ="*50)
                                    return False, 500
                        raw_data = lxml.html.fromstring(page_source).text_content()
                        if len(raw_data) <= 0: # check for empty content
                            return False, 204
                        if "GREENHOUSE_WEB_CANARY" in self.driver.page_source:
                            return False, 406 # if we are getting a dir view of the rootfs something is wrong
                        if "401" in raw_data.lower() and "unauthorized" in raw_data.lower():
                            return False, 401
                        if "404" in raw_data.lower() and "not found" in raw_data.lower():
                            return False, 404
                        if "408"  in raw_data.lower() and "request timeout" in raw_data.lower():
                            return False, 408
                        if "500"  in raw_data.lower() and "internal server error" in raw_data.lower():
                            return False, 500
                        return True, 200
                except UnexpectedAlertPresentException as e:
                    self.HandleAlert()
                    retry = True
                except Exception as e: # malformed html
                    print("[FirmAE]     - malformed html")
                    print(e)
                    return False, 206
        return False, -1

    def Initialize(self, analysis_path):
        self.old_env = os.environ['PATH']
        os.environ['PATH'] = analysis_path + ':' + os.environ['PATH']

    def Close(self):
        os.environ['PATH'] = self.old_env
        closed = False
        while not closed:
            try:
                self.driver.close()
                closed = True
            except UnexpectedAlertPresentException as e:
                self.HandleAlert()
            except Exception as e:
                print(e)
            time.sleep(3)
            print("[FirmAE]     - handled alert, reattempting close...")

        time.sleep(3) # wait a little before quitting
        self.driver.quit()

class Login:
    def hmac_md5(key, msg):
        from hashlib import md5
        BLOCKSIZE = md5().block_size
        if len(key) > BLOCKSIZE:
            key = md5(key).digest()
        key = str(key) + '\x00' * (BLOCKSIZE - len(key))

        TRANS_5C = "".join(chr(x ^ 0x5c) for x in range(256))
        TRANS_36 = "".join(chr(x ^ 0x36) for x in range(256))
        o_key_pad = key.translate(TRANS_5C).encode()
        i_key_pad = key.translate(TRANS_36).encode()
        return md5(o_key_pad + md5(i_key_pad + msg.encode()).digest())

    def HNAP_AUTH(SOAPAction, privateKey):
        import math
        b = math.floor(int(time.time())) % 2000000000;
        b = str(b)[:-2]
        h = Login.hmac_md5(privateKey, b + '"http://purenetworks.com/HNAP1/' + SOAPAction + '"').hexdigest().upper()
        return h + " " + b

    def check_login_type(ip, brand):
        headers = requests.utils.default_headers()
        headers["User-Agent"] = 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; Touch; rv:11.0) like Gecko'
        headers["Referer"] = ip
        try:
            r = requests.get(ip, headers=headers)
        except Exception as e:
            print(e)
            return 'connection error'

        if r.status_code == 401:
            if "WWW-Authenticate" in r.headers.keys():
                if "Digest" in r.headers["WWW-Authenticate"]:
                    return 'digest'
            return 'basic'
        elif r.text.find('/info/Login.html') != -1: # dlink hnap
            return 'dlink_hnap'
        elif r.text.find('log_pass') != -1 or r.text.find('login_auth.asp') != -1 or r.text.find('login.cgi') != -1:
            if brand == "dlink":  # dlink normal login
                return 'dlink_asp'
            elif brand == "trendnet":
                if r.text.find('apply_sec.cgi') != -1:
                    return 'trendnet_asp_apply_sec_cgi'
                elif r.text.find('login.cgi') != -1:
                    return 'trendnet_asp_login_cgi'
            else:
                return 'unknown'
        elif r.text.find('setup_top.htm') != -1:
            return 'belkin'
        elif brand == "tenda":
            if r.text.find('/login/Auth') != -1:
                return 'tenda_auth'
            else:        
                try:
                    r = requests.get(ip+"/login/Auth", headers=headers)
                except Exception as e:
                    print(e)
                    return 'connection error'
                if r and r.status_code == 200:
                    return 'tenda_auth'
        elif r.text.find('location.replace(\'login.htm\')') != -1 or r.text.find('login.ccp') != -1:
            return 'trendnet_ccp'
        else:
            return 'unknown'
        return 'unknown'

    def login(session, brand, ip, login_type, username, password):
        reply = None
        headers = None
        payload = ""

        if login_type == 'basic':
            reply = session.get(url=ip, timeout=5, verify=False, auth=(username, password))
            print(f"[FirmAE]     - attempt: {login_type} {ip} {username} {password} {reply}")
            return reply.status_code != 401, dict(reply.request.headers), reply.request.body, ip

        elif login_type == 'digest':
            reply = session.get(url=ip, timeout=5, verify=False, auth=HTTPDigestAuth(username, password))
            return reply.status_code != 401, dict(reply.request.headers), reply.request.body, ip
        elif login_type.startswith('trendnet_asp'):
            login_name = username.encode('utf-8').hex()
            log_pass = password.encode('utf-8').hex()
            if "apply_sec" in login_type:
                login_cgi = "apply_sec.cgi"
            else:
                login_cgi = "login.cgi"
            headers = requests.utils.default_headers()
            headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.76 Safari/537.36"
            headers["Origin"] = ip
            headers["Referer"] = ip
            headers["Cache-Control"] = "max-age=0"
            payload = {'html_response_page':'login_fail.asp','login_name':login_name,'login_pass':log_pass,'graph_id':'d360e','log_pass':'','graph_code':'','Login':'Log In'}
            reply = session.post('{}/{}'.format(ip, login_cgi), headers=headers, data=payload)
            return reply.status_code == 200, dict(reply.request.headers), reply.request.body, '{}/{}'.format(ip, login_cgi)
        elif login_type == 'dlink_asp':
            login_name = username.encode('utf-8').hex()
            log_pass = password.encode('utf-8').hex()
            login_cgi = "login.cgi"
            headers = requests.utils.default_headers()
            headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.76 Safari/537.36"
            headers["Origin"] = ip
            headers["Referer"] = ip
            headers["Cache-Control"] = "max-age=0"
            payload = {'html_response_page':'login_fail.asp','login_name':login_name,'login_pass':log_pass,'graph_id':'d360e','log_pass':'','graph_code':'','Login':'Log In'}
            reply = session.post('{}/{}'.format(ip, login_cgi), headers=headers, data=payload)
            return reply.status_code == 200, dict(reply.request.headers), reply.request.body, '{}/{}'.format(ip, login_cgi)

        elif login_type == 'dlink_hnap':
            headers = requests.utils.default_headers()
            headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.76 Safari/537.36"
            headers["SOAPAction"] = '"http://purenetworks.com/HNAP1/Login"'
            headers["Origin"] = ip
            headers["Referer"] = ip + "/info/Login.html"
            headers["Content-Type"] = "text/xml; charset=UTF-8"
            headers["X-Requested-With"] = "XMLHttpRequest"

            payload = """<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                       xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
                       <soap:Body><Login xmlns="http://purenetworks.com/HNAP1/"><Action>request</Action>
                       <Username>%s</Username><LoginPassword>%s</LoginPassword><Captcha></Captcha></Login>
                       </soap:Body></soap:Envelope>""" % (username, password)
            r = requests.post(ip+'/HNAP1/', headers=headers, data=payload)
            if r.status_code != 200:
                print(r.status_code)
                return False, None, payload, ip

            data = r.text

            challenge = str(data[data.find("<Challenge>") + 11: data.find("</Challenge>")])
            cookie = str(data[data.find("<Cookie>") + 8: data.find("</Cookie>")])
            publicKey = str(data[data.find("<PublicKey>") + 11: data.find("</PublicKey>")])

            PRIVATE_KEY = Login.hmac_md5(publicKey + password, challenge).hexdigest().upper()
            md5_password = Login.hmac_md5(PRIVATE_KEY, challenge).hexdigest().upper()

            cookies = {"uid": cookie}
            headers["HNAP_AUTH"] = Login.HNAP_AUTH("Login", PRIVATE_KEY)
            payload = '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Login xmlns="http://purenetworks.com/HNAP1/"><Action>login</Action><Username>Admin</Username><LoginPassword>'+md5_password+'</LoginPassword><Captcha></Captcha></Login></soap:Body></soap:Envelope>'
            reply = requests.post(ip+'/HNAP1/', headers=headers, data=payload, cookies=cookies)
            success = False
            if reply.status_code == 200:
                data = reply.text
                loginresult = str(data[data.find("<LoginResult>") + 13: data.find("<//LoginResult>")])
                success = "success" in loginresult.lower()
            return success, dict(reply.request.headers), reply.request.body, ip+'/HNAP1/'

        elif login_type == 'belkin':
            headers = requests.utils.default_headers()
            headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.76 Safari/537.36"
            headers["Origin"] = ip
            headers["Referer"] = ip
            headers["Cache-Control"] = "max-age=0"
            payload = {'totalMSec': '1539994224.535', 'pws': 'd41d8cd98f00b204e9800998ecf8427e', 'arc_action': 'login', 'pws_temp': '', 'action': 'Submit'}
            reply = session.post(ip+'/login.cgi', headers=headers, data=payload)
            return reply.status_code == 200, dict(reply.request.headers), reply.request.body, ip+'/login.cgi'

        elif login_type == 'trendnet_ccp':
            headers = requests.utils.default_headers()
            headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.76 Safari/537.36"
            headers["Origin"] = ip
            headers["Referer"] = ip
            payload = {'totalMSec': '1539994224.535', 'pws': 'd41d8cd98f00b204e9800998ecf8427e', 'arc_action': 'login', 'pws_temp': '', 'action': 'Submit'}
            payload = {'html_response_page':'login_fail.htm','login_name':'','username': username,'password': password,'curr_language':'','login_n': username,'login_pass': password,'lang_select':'0','login':'Login'}
            reply = session.post(ip + '/login.ccp', headers=headers, data=payload)
            return reply.status_code == 200, dict(reply.request.headers), reply.request.body, ip + '/login.ccp'

        elif login_type == 'tenda_auth':
            log_pass = password.encode('utf-8').hex()
            headers = requests.utils.default_headers()
            headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.76 Safari/537.36"
            headers["Origin"] = ip
            headers["Referer"] = ip
            payload = {'username':username,'pwd':log_pass}
            login_cgi = "/login/Auth"
            reply = session.post('{}/{}'.format(ip, login_cgi), headers=headers, data=payload)
            success = False
            if reply.status_code == 200:
                data = reply.text
                if "<html" in data and "/login/Auth" not in data:
                    success = True
            return success, dict(reply.request.headers), reply.request.body, '{}/{}'.format(ip, login_cgi)

        else:
            return False, headers, "", ip

class URLCheck:
    def __init__(self, ip, port, brand="default", analysis_path="."):
        self.ip = ip
        self.port = port
        self.url = f"http://{ip}:{port}"
        self.brand = brand
        self.analysis_path = analysis_path
        self.user = ""
        self.password = ""
        self.headers = None
        self.data = ""
        self.working_curl = ""
        self.reply = None
        self.session = None
        self.last_status_code = -1
        self.login_type = ""
        self.loginurl = ""
        self.curl_success = False
        self.login_success = False
        self.login_needed = False
        self.initializer_done = False
        self.wellformed = False
        self.timedout = False
    
    def curlcheck(self):
        """Check HTTP connection with Greenhouse-style logic"""
        count = 0
        is_ssl = False
        retry = True
        r = None
        if self.login_needed and self.login_success:
            auth = (self.user, self.password)
        else:
            auth = None

        while retry:
            if count > MAX_RETRIES:
                break

            if is_ssl and not self.url.startswith("https"):
                self.url = self.url.replace("http://", "https://")
            print(f"[FirmAE]     - sending curl request check @ {self.url}")
            try:
                r = self.session.get(url=self.url, timeout=5, verify=False, headers=self.headers, allow_redirects=True)
                retry = False
            except Exception as e:
                print("[FirmAE] Connection failed")
                print(e)
                retry = False
                if "timed out" in str(e):
                    self.timedout = True
                    self.last_status_code = 408
                elif "Remote end closed connection without response" in str(e):
                    self.last_status_code = 202
                elif "BadStatusLine" in str(e):
                    self.last_status_code = 400
                elif "reset by peer" in str(e):
                    retry = True
                    is_ssl = True

                if self.last_status_code != -1 and not is_ssl and self.url.endswith("443"):
                    retry = True
                    is_ssl = True
            count += 1

        if r is not None and not self.timedout:
            self.last_status_code = r.status_code
            print(f"[FirmAE]     - [curlcheck]: Request returned", r.status_code)
            http_text = r.text.encode("utf-8", errors='ignore')
            if len(http_text) > 200:
                print(http_text[:200])
                print("[FirmAE] <truncated>")
            else:
                print(http_text)

        return r
    
    def logincheck(self, session):
        """Check login with default credentials using Login class"""
        login_type = Login.check_login_type(self.url, self.brand)
        if login_type == "connection error":
            return False, False
        if login_type == "unknown":
            return True, False

        self.login_type = login_type # only save the login type in the initial success case

        print(f"[FirmAE]     - Login Type: {self.login_type}")
        logged_in = False
        headers = {}
        reply = None
        for user in USER_AUTHS:
            for password in PASSWORD_AUTHS:
                if self.login_success:
                    user = self.user
                    password = self.password
                try:
                    print(f"[FirmAE]       - Trying user: {user} password: {password}")
                    
                    logged_in, headers, payload, loginurl = Login.login(session, self.brand, self.url, self.login_type, user, password)
                    print(f"[FirmAE]       - logged in {logged_in}")
                except Exception as e:
                    print("[FirmAE]       - ERROR login attempt failed")
                    print(e)
                time.sleep(2) # delay to subvert brute force protection
                if logged_in:
                    # retry: make sure the curl actually works
                    try:
                        logged_in, _, _, _ = Login.login(session, self.brand, self.url, self.login_type, user, password)
                    except Exception as e:
                        print("[FirmAE]       - ERROR login attempt failed")
                        print(e)
                        logged_in = False
                    if not logged_in:
                        print("[FirmAE]       x- false login success, retry")
                        continue
                    self.user = user
                    self.password = password
                    self.headers = headers
                    self.loginurl = loginurl
                    if payload is not None:
                        self.data = str(payload)
                    else:
                        self.data = ""
                    break
            if logged_in:
                break

        return logged_in, True
    
    def webcheck(self):
        """Check if page is wellformed using WebCheck class"""
        wbc = WebCheck()
        retryurl = ""
        wbc.Initialize(self.analysis_path)
        if self.login_needed:
            auth = f"{self.user}:{self.password}"
            print(f"[FirmAE]     - using auth {auth}")
        else:
            auth = ""
        wbc.Connect(self.url, auth)
        wellformed, self.last_status_code = wbc.Check()
        if wellformed and self.last_status_code == 200: # do two attempts, since its possible we crashed after the first
            print("[FirmAE] ="*50)
            print("[FirmAE]     - second check")
            print("[FirmAE] ="*50)
            wellformed, self.last_status_code = wbc.Check()
        wbc.Close()
        if self.last_status_code == 401:
            retryurl = wbc.current_url
        return wellformed, retryurl
    
    def probe(self):
        """Main probing function - aligned with Greenhouse logic"""
        reply = None
        self.curl_success = False
        self.login_success = False
        self.login_needed = False
        self.login_type = ""
        self.loginurl = ""
        self.initializer_done = False
        self.wellformed = False
        self.last_status_code = -1
        self.working_curl = ""
        self.session = requests.Session()

        while True:
            print("[FirmAE] [+] curltest")
            print(f"[FirmAE] [+] Probing {self.url}...")
            reply = self.curlcheck()

            # check if response is 200 or 401:
            #   - if so, run login script and update the session in use
            #   - rerun curlcheck with new session
            #   - if login script does not find anything and response is 200, proceed
            #   - otherwise, fail
            if reply is None:
                print("[FirmAE]     - CurlCheck failed!")
                break

            if reply.status_code != 200 and reply.status_code != 401:
                print("[FirmAE]     - CurlCheck failed!")
                break

            # curlcheck passed for this test cycle
            if not self.curl_success:
                self.curl_success = True
                self.reply = reply
                print("[FirmAE] [+] Page found, retesting...")
                continue
            print("[FirmAE] [+] curlpassed")

            # save working curl
            curlheaders = ""
            if self.headers is not None:
                curlheaders = ['-H "{0}: {1}"'.format(k, v.strip("\"").strip("\'")) for k, v in self.headers.items()]

            curlcommand = "curl -L"
            for header in curlheaders:
                curlcommand += " " + header
            if self.data != "":
                self.data = self.data.replace("\"", "\\\"")
                curlcommand += " -d " + "\"" + self.data + "\""
            if self.login_type == "digest":
                curlcommand += " --digest"
            if self.user != "" or self.password != "":
                curlcommand += f" --user {self.user}:{self.password}"
            
            if len(self.loginurl) <= 0:
                self.loginurl = self.url
            curlcommand += f" {self.loginurl}"
            self.working_curl = curlcommand
            print(f"[FirmAE]     [+] Working cURL: {curlcommand}")

            print("[FirmAE] [+] logintest")
            logged_in, login_needed = self.logincheck(self.session)

            # either don't need login or do need and successfully logged in
            if login_needed and not logged_in:
                print("[FirmAE]     - Login failed!")
                break

            # logincheck passed for this test cycle
            if not self.login_success:
                self.login_success = True
                self.login_needed = login_needed
                if self.login_needed:
                    print(f"[FirmAE] [+] Logged in with {self.user}:{self.password} via <{self.login_type}> @ '{self.loginurl}', retesting")
                    # Retest with authenticated session
                    reply = self.curlcheck()
                    if reply:
                        self.reply = reply
                    continue
                else:
                    print("[FirmAE]     - no login needed, continuing...")

            print("[FirmAE] [+] loginpassed")

            # get webpage content
            print("[FirmAE] [+] webcheck")
            self.wellformed, retryurl = self.webcheck()
            if len(retryurl) > 0 and self.url != retryurl:
                print(f"[FirmAE]     - retrying with new url {retryurl}")
                self.url = retryurl
                self.curl_success = False
                self.login_success = False
                continue

            if not self.wellformed:
                print("[FirmAE]     - WebCheck failed!")
                if self.last_status_code == 200:
                    self.last_status_code = 204
                break

            print("[FirmAE] [+] webpassed")

            print(f"[FirmAE] [+] All checks passed for {self.url}! Webpage is wellformed and running!")

            break

        self.session.close()
        return self.last_status_code != -1

class HTTPInteractionCheck:
    def __init__(self, brand="default", analysis_path="."):
        self.brand = brand
        self.analysis_path = analysis_path
        self.urlchecks = []
    
    def get_port(self, uc):
        return int(uc.port)
    
    def get_url(self, uc):
        return uc.url
    
    def probe(self, ips, ports):
        """Probe all IPs and ports - aligned with Greenhouse"""
        self.urlchecks.clear()
        
        for ip in ips:
            for port in ports:
                uc = URLCheck(ip, port, self.brand, self.analysis_path)
                success = uc.probe()
                if success:
                    self.urlchecks.append(uc)
        
        return len(self.urlchecks) > 0
    
    def check(self, exit_code=None, timedout=None, errored=None, strict=True):
        """Check results with Greenhouse-style logic"""
        connected = False
        if not errored:
            if self.urlchecks:
                self.urlchecks.sort(key=self.get_url)
                self.urlchecks.sort(key=self.get_port)
                for uc in self.urlchecks:
                    print(f"[FirmAE]     >>> checking {uc.url} {uc.last_status_code}")
                    if uc.last_status_code == 200:
                        print(f"[FirmAE] Status Code: {uc.last_status_code}")
                        if strict:
                            if uc.wellformed:
                                return True, True, uc.curl_success
                        else:
                            return True, uc.wellformed, uc.curl_success
                    elif uc.curl_success:
                        connected = uc.curl_success
                    
                    if uc.last_status_code != -1:
                        print(f"[FirmAE] Status Code: {uc.last_status_code}")
        
        return False, False, connected
    
    def get_working_ip_set(self, strict=True):
        """Get working IP set with credentials - aligned with Greenhouse"""
        ip_port_url_type_user_pass_headers_payload = ("", "", "", "", "", "", "", "")
        wellformed_ucs = []
        found = False
        
        if self.urlchecks:
            self.urlchecks.sort(key=self.get_url)
            self.urlchecks.sort(key=self.get_port)
            
            for uc in self.urlchecks:
                print(f"[FirmAE]     >>> checking {uc.url} {uc.last_status_code}")
                if not strict or uc.wellformed:
                    wellformed_ucs.append(uc)
                    if uc.login_type == "unknown" or uc.login_type == "":
                        continue
                    found = True
                    ip_port_url_type_user_pass_headers_payload = (uc.ip, uc.port, uc.loginurl, uc.login_type, uc.user, uc.password, uc.headers, uc.data)
                    break
            
            if not found and wellformed_ucs:
                uc = wellformed_ucs[0]
                ip_port_url_type_user_pass_headers_payload = (uc.ip, uc.port, uc.loginurl, uc.login_type, uc.user, uc.password, uc.headers, uc.data)
        
        return ip_port_url_type_user_pass_headers_payload

def main():
    if len(sys.argv) < 4:
        print(f"[FirmAE] Usage: {sys.argv[0]} [BRAND] [ANALYSIS_PATH] [URL;URL;URL]")
        sys.exit(1)
    
    brand = sys.argv[1]
    analysis_path = sys.argv[2]
    ips = sys.argv[3].split(";")
    ports = ["80", "443"]
    
    print(f"[FirmAE] Running greenhouse_checker: {brand} {analysis_path} {ips} {ports}")
    
    checker = HTTPInteractionCheck(brand, analysis_path)
    probe_success = checker.probe(ips, ports)
    
    if probe_success:
        success, wellformed, connected = checker.check(exit_code=None, timedout=False, errored=False, strict=True)
        print(f"[FirmAE] \nResults:")
        print(f"[FirmAE] Success: {success}")
        print(f"[FirmAE] Wellformed: {wellformed}")
        print(f"[FirmAE] Connected: {connected}")
        
        # Determine best IP
        best_ip = ""
        for uc in checker.urlchecks:
            if uc.last_status_code == 200:
                best_ip = uc.ip
                break
        if not best_ip and checker.urlchecks:
            best_ip = checker.urlchecks[0].ip
        
        print(f"[FirmAE] Best IP: {best_ip}")
        print(f"[FirmAE] \nOutput format: <IP> <PING_RESULT> <WEB_RESULT> <TIME_PING> <TIME_WEB>")
        print(f"[FirmAE] Greenhouse-style HTTP checker result: {best_ip} {str(connected).lower()} {str(success).lower()} 0 0")
        print(f"{best_ip} {str(connected).lower()} {str(success).lower()} 0 0")
    else:
        print("[FirmAE] No web service detected")
        print("[FirmAE] Greenhouse-style HTTP checker result: None false false 0 0")
        print("None false false 0 0")

if __name__ == "__main__":
    main()