'''THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE AND
NON-INFRINGEMENT. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR ANYONE
DISTRIBUTING THE SOFTWARE BE LIABLE FOR ANY DAMAGES OR OTHER LIABILITY,
WHETHER IN CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.'''

# Bitcoin Cash (BCH)   qpz32c4lg7x7lnk9jg6qg7s4uavdce89myax5v5nuk
# Ether (ETH) -        0x843d3DEC2A4705BD4f45F674F641cE2D0022c9FB
# Litecoin (LTC) -     Lfk5y4F7KZa9oRxpazETwjQnHszEPvqPvu
# Bitcoin (BTC) -      34L8qWiQyKr8k4TnHDacfjbaSqQASbBtTd

# contact :- github@jamessawyer.co.uk



#!/usr/bin/env python

import requests
import sys
import threading
from multiprocessing import Process
import time
from datetime import datetime
from fake_useragent import UserAgent

ua = UserAgent()
ua.update()

score_point = 100 / 6
thread_list = []
now = datetime.now()
logfile = now.strftime('mylogfile_%H_%M_%d_%m_%Y.log')


def headers(site):
    """
    Connect to target site and check its headers."
    """
    total_score = 0

    try:
        f = open(logfile, "a")
        print("##############################################################\n")
        print("##############################################################\n")
        print("##############################################################\n")
        f.write("##############################################################" + "\n")
        f.write("##############################################################" + "\n")
        f.write("##############################################################" + "\n")
        f.write("[+] checking ... " + str(site) + "\n")
        print("[+] checking ... " + str(site))
        user_agent_headers = {
            'User-Agent': ua.random,
        }
        req = requests.get(site,headers=user_agent_headers)
        req.raise_for_status()
        # print (req.headers)
        if 'x-frame-options' in req.headers:
            f.write("[+] x-frame-options\t\t\t\t\t[OK]" + "\n")
            total_score += score_point
        else:
            f.write("[-] x-frame-options\t\t\t\t\t[NOT OK]" + "\n")
        #######################################################
        if 'strict-transport-security' in req.headers:
            f.write("[+] strict-transport-security\t\t\t\t[OK]" + "\n")
            total_score += score_point
        else:
            f.write("[-] strict-transport-security\t\t\t\t[NOT OK]" + "\n")
        #######################################################
        if 'content-security-policy' in req.headers:
            f.write("[+] content-security-policy\t\t\t\t[OK]" + "\n")
            total_score += score_point
        else:
            f.write("[-] content-security-policy\t\t\t\t[NOT OK]" + "\n")
        #######################################################
        if 'access-control-allow-origin' in req.headers:
            f.write("[+] access-control-allow-origin\t\t\t\t[OK]" + "\n")
            total_score += score_point
        else:
            f.write("[-] access-control-allow-origin\t\t\t\t[NOT OK]" + "\n")
        #######################################################
        if 'x-xss-protection' in req.headers:
            f.write("[+] x-xss-protection\t\t\t\t\t[OK]" + "\n")
            total_score += score_point
        else:
            f.write("[-] x-xss-protection\t\t\t\t\t[NOT OK]" + "\n")
        #######################################################
        if 'x-content-type-options' in req.headers:
            f.write("[+] x-content-type-options\t\t\t\t[OK]" + "\n")
            total_score += score_point
        else:
            f.write("[-] x-content-type-options\t\t\t\t[NOT OK]" + "\n")
        #######################################################
        f.write("[+] " + str(round(total_score, 2)) + " out of 100" + "\n")
    except requests.exceptions.HTTPError as err:
        f.write("[+] HTTP error: " + str(err) + "\n")
        f.write("##############################################################" + "\n")
        f.write("##############################################################" + "\n")
        f.write("##############################################################" + "\n")
    except requests.exceptions.ConnectionError as errc:
        f.write("[+] Error Connecting:" + str(errc) + "\n")
        f.write("##############################################################" + "\n")
        f.write("##############################################################" + "\n")
        f.write("##############################################################" + "\n")
    except requests.exceptions.Timeout as errt:
        f.write("[+] Timeout Error:" + str(errt) + "\n")
        f.write("##############################################################" + "\n")
        f.write("##############################################################" + "\n")
        f.write("##############################################################" + "\n")
    except requests.exceptions.RequestException as err:
        f.write("[+] OOps: Something Else" + str(err) + + "\n")
        f.write("##############################################################" + "\n")
        f.write("##############################################################" + "\n")
        f.write("##############################################################" + "\n")

    f.close()
###################################################################
###################################################################
###################################################################

    # if 'x-frame-options' in req.headers:
    # print ("[+] x-frame-options\t\t[OK]")
    # total_score += score_point
    # else:
    # print ("[-] x-frame-options\t\t[NOT OK]")
    # #######################################################
    # if 'strict-transport-security' in req.headers:
    # print ("[+] strict-transport-security\t[OK]")
    # total_score += score_point
    # else:
    # print ("[-] strict-transport-security\t\t[NOT OK]")
    # #######################################################
    # if 'content-security-policy' in req.headers:
    # print ("[+] content-security-policy\t[OK]")
    # total_score += score_point
    # else:
    # print ("[-] content-security-policy\t[NOT OK]")
    # #######################################################
    # if 'access-control-allow-origin' in req.headers:
    # print ("[+] access-control-allow-origin\t[OK]")
    # total_score += score_point
    # else:
    # print ("[-] access-control-allow-origin\t[NOT OK]")
    # #######################################################
    # if 'x-xss-protection' in req.headers:
    # print ("[+] x-xss-protection\t\t[OK]")
    # total_score += score_point
    # else:
    # print ("[-] x-xss-protection\t\t[NOT OK]")
    # #######################################################
    # if 'x-content-type-options' in req.headers:
    # print ("[+] x-content-type-options\t[OK]")
    # total_score += score_point
    # else:
    # print ("[-] x-content-type-options\t\t[NOT OK]")
    # #######################################################
    # print ("[+] " + str(round(total_score, 2)) + " out of 100")
    # except requests.exceptions.HTTPError as err:
    # print ("[+] HTTP error: " + str(err))
    # return
    # except requests.exceptions.ConnectionError as errc:
    # print ("[+] Error Connecting:",errc)
    # return
    # except requests.exceptions.Timeout as errt:
    # print ("[+] Timeout Error:",errt)
    # return
    # except requests.exceptions.RequestException as err:
    # print ("[+] OOps: Something Else",err)
    # return


def main():
    """
    Main functionality.
    """
    for each in domains:
        try:
            # thread = threading.Thread(target=headers, args=("https://www." + str(each),))
            # thread_list.append(thread)
            # thread.start()
            ###################################################################
            p = Process(target=headers, args=("https://www." + str(each),))
            p.start()
            # p.join()
        except BaseException:
            continue


if __name__ == '__main__':

    with open('common_tld_lst.txt') as f:
        domains = f.read().splitlines()

    f = open(logfile, "a")
    f.write("#####################################################\n")
    f.write("#####################################################\n")
    f.write("#This is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; \n#without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n")
    f.write("#####################################################\n")
    f.write("#####################################################\n")
    f.write("#Last Modified:" + str(now.strftime("%Y-%m-%d %H:%M:%S")) + "\n")
    f.write("#####################################################\n")
    f.write("#####################################################\n")
    f.close()

    main()
