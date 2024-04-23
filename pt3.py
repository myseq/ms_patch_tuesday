#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys, argparse
from argparse import RawTextHelpFormatter
from timeit import default_timer as timer
import json
import requests

from datetime import date
from datetime import datetime, timedelta
from collections import Counter
from colorama import init, Fore, Back, Style
import pyfiglet

from icecream import ic

def cr(x): return (f'{Style.BRIGHT}{Fore.RED}{x}{Style.RESET_ALL}')
def cb(x): return (f'{Style.BRIGHT}{Fore.BLUE}{x}{Style.RESET_ALL}')
def cg(x): return (f'{Style.BRIGHT}{Fore.GREEN}{x}{Style.RESET_ALL}')
def cy(x): return (f'{Style.BRIGHT}{Fore.YELLOW}{x}{Style.RESET_ALL}')

description = f'To get vulnerability stats and updates for {cg("Patch Tuesday")} from MSRC.'
notes = f'Get detailed Microsoft security update, formatted according to the {cg("Common Vulnerability Reporting Framework")}. MSRC investigates all reports of security vulnerabilities affecting Microsoft products and services, and provides these updates as part of the ongoing effort to help you manage security risks and help keep your systems protected. For more details, please visit {cb("msrc.microsoft.com/update-guide")}.\n\nA similar wbesite can be found at {cg("https://patchtuesdaydashboard.com")} (by Morphus Labs).'

banner = f"""
   Zzzzz   |\      _,,,---,,_
           /,`.-'`'    -.  ;-;;,_   __author__ : [ zd ]
          |,4-  ) )-,_..;\ (  `'-'  __year__   : [ 2022.03 ]
         '---''(_/--'  `-'\_)       __file__   : [ {__file__} ]

         [ {description} ]
    """

vuln_types = [
    'Spoofing',
    'Denial of Service',
    'Remote Code Execution',
    'Elevation of Privilege',
    'Security Feature Bypass',
    'Information Disclosure',
    'Edge - Chromium' ]

data = {}
base_url = 'https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/'
headers = {'Accept': 'application/json'}
verberos = False


def count_type(search_type, all_vulns):
    counter = 0
    for vuln in all_vulns:
        for threat in vuln['Threats']:
            if threat['Type'] == 0:
                if search_type == "Edge - Chromium":
                    if threat['ProductID'][0] == '11655':
                        counter += 1
                        break
                elif threat['Description'].get('Value') == search_type:
                    if threat['ProductID'][0] == '11655':
                        # Do not double count Chromium Vulns
                        break
                    counter += 1
                    break
    return counter


def count_vulns(all_vulns, mode):
    base_score = 8.5
    counter = 0
    cves = []

    for vuln in all_vulns:
        cvss_score = 0.0
        cvss_sets = vuln.get('CVSSScoreSets', [])
        if len(cvss_sets) > 0 :
            cvss_score = cvss_sets[0].get('TemporalScore', 0.0)
            if cvss_score >= base_score and mode == 'critical':
                counter += 1
                cves.append(f'{cy(vuln["CVE"])} - {cr(cvss_score)} - {vuln["Title"]["Value"]}')

        for threat in vuln['Threats']:
            if threat['Type'] == 1:
                description = threat['Description']['Value']

                if mode == 'exploited' and 'Exploited:Yes' in description:
                    counter += 1
                    cves.append(f'{cr(vuln["CVE"])} - {cy(cvss_score)} - {vuln["Title"]["Value"]}')
                    break

                if mode == 'high_likely' and 'Exploitation More Likely'.lower() in description.lower():
                    counter += 1
                    cves.append(f'{cy(vuln["CVE"])} - {cvss_score} - {vuln["Title"]["Value"]}')
                    break

    return {'counter': counter, 'cves': cves}



def find_patch_tuesday(month, year):
    """ To get the patch Tuesday date in the format of YYYY-mm-dd """

    basedate = datetime.strptime('{} 12 {} 12:00AM'.format(month, year), '%m %d %Y %I:%M%p')

    dayoftheweek = basedate.weekday() + 1

    if dayoftheweek > 6:
        dayoftheweek = 0

    return (basedate - timedelta(days=dayoftheweek) + timedelta(days=2)).date()


def Get_URL(year=None, month=None):
    """ Get from MSRC """
    g = globals()

    param = f'{year}-{month}'
    url = g["base_url"] + param

    try:
        resp = requests.get(url, headers=g['headers'])
    except:
        ic(url)

    if resp.status_code == 200:
        #print(len(resp.content))
        g['data'] = resp.json()
        return True
    else:
        if g['verbose']:
            if resp.status_code == 400:
                print(f' [!] FAIL: Bad Request on {url}')
            elif resp.status_code == 401:
                print(f' [!] FAIL: Unauthorized access to {url}')
            elif resp.status_code == 404:
                print(f' [!] FAIL: Not Found at {url}')
            elif resp.status_code == 500:
                print(f' [!] FAIL: Internal Service Error at {url}')
            else:
                print(f' [!] FAIL: Unknown error "{resp.status_code}" at {url}')

        return False


def main():
    """ main() function """
    g = globals()

    parser = argparse.ArgumentParser(description=banner, formatter_class=RawTextHelpFormatter, epilog=notes)
    parser.add_argument('-c', action='store_true', help='show chart output')
    parser.add_argument('-k', dest='cvrf', metavar='<YYYY-mmm>', help="Date string for the report query in format YYYY-mmm")
    parser.add_argument('-v', action='store_true', help='verbose output')

    args = parser.parse_args()
    g['verbose'] = True if args.v else False

    init(autoreset=True, strip=False)
    print(f'')
    word = pyfiglet.figlet_format("Patch Tuesday", font="rectangles")
    print(Fore.BLUE + word)
    tuesday = "error"


    if args.cvrf:
        cvrf = args.cvrf
        yyyy, mmm = cvrf.split('-')
        date_obj = datetime.strptime(cvrf, "%Y-%b").date()
        m = date_obj.month
        y = date_obj.year
        tuesday = find_patch_tuesday(m, y)
    else:
        m = date.today().month
        y = date.today().year
        tuesday = find_patch_tuesday(m, y)
        mmm = date.today().strftime("%h").lower()
        yyyy = date.today().year


    if Get_URL(yyyy, mmm):
        if g['verbose']:
            #print(f' [*] Success to access the API {base_url}')
            print(f'')
    else:
        if g['verbose']:
            print(f'')
            print(f' [*] Check the connection to {cg(base_url)}')
            print(f'')
        return

    all_products = {}
    all_microsoft = data.get('ProductTree').get('Branch', [])
    all_items = all_microsoft[0].get('Items', [])

    for p in all_items:
        pname = p['Name']
        icount = len(p['Items'])
        all_products[pname] = icount
        #print(f'\t[-] {pname}: {icount}')

    #ic(all_products)

    title = data.get('DocumentTitle', 'Release not found').get('Value')
    all_vulns = data.get('Vulnerability', [])
    
    mark0 = "▏"
    mark1 = "▇"
    max_length = 50
    Header1 = f' Microsoft Patch Tuesday - By {cb("MSRC")}'
    Header2 = f' << {cy(title)} [ {cg(tuesday)} ] >>'

    #print(f'')
    print(Header1)
    print('='*len(Header1))
    print(Header2)
    print(f'')
    print(f'')

    print(f' [+] Product Families      : [ {cy(len(all_products)):>13s} ]')
    if g['verbose']:
        max_value = sum(all_products.values())
        for p in sorted(all_products, key=all_products.get, reverse=True):
            if args.c:
                c = round(all_products[p] / max_value * max_length)
                if c >= 1:
                    print(f'{"":>4s}{p:>26s} {cb(mark1)*c} {all_products[p]}')
                else:
                    print(f'{"":>4s}{p:>26s} {cb(mark0)} {all_products[p]}')
            else:
                print(f'\t[-] {p:>25s} : {cg(all_products[p]):>12s}')
        print(f'')


    print(f' [+] Total Vulnerabilities : [ {cy(len(all_vulns)):>13s} ]')
    if g['verbose']:
        max_value = len(all_vulns)
        for vuln_type in vuln_types:
            count = count_type(vuln_type, all_vulns)
            if args.c:
                c = round(count / max_value * max_length)
                if c >= 1:
                    print(f'{"":>4s}{cg(vuln_type):>35s} {cb(mark1)*c} {count}')
                else:
                    print(f'{"":>4s}{cg(vuln_type):>35s} {cb(mark0)} {count}')
            else:
                print(f'\t[-] {vuln_type:>25s} : {cg(count):>12s} [ {count/max_value*100: >5.2f}% ]')
        print(f'')


    critical = count_vulns(all_vulns, 'critical')
    print(f' [+] High_Severity         : [ {cy(critical["counter"]):>13s} ]')
    if g['verbose']:
        for cve in critical['cves']:
            print(f'\t[-] {cve}')
        print(f'')

    high_likely = count_vulns(all_vulns, 'high_likely')
    print(f' [+] High_likelihood       : [ {cy(high_likely["counter"]):>13s} ]')
    if g['verbose']:
        for cve in high_likely['cves']:
            print(f'\t[-] {cve}')
        print(f'')
        
    exploited = count_vulns(all_vulns, 'exploited')
    print(f' [+] Exploited in_wild     : [ {cy(exploited["counter"]):>13s} ]')
    if g['verbose']:
        for cve in exploited['cves']:
            print(f'\t[-] {cve}')
        print(f'')

    if g['verbose']:
        docTrack = data.get('DocumentTracking')
        doc_history = docTrack.get('RevisionHistory', [])
        doc_revision = doc_history[0]['Number']
        doc_value = doc_history[0]['Description']['Value']
        doc_initial = docTrack['InitialReleaseDate']
        doc_current = docTrack['CurrentReleaseDate']
        print(f' [*] "{cb(doc_value)}" (Rev {doc_revision})')
        print(f'\t[-] Initial Release date: {cy(doc_initial)}')
        print(f'\t[-] Current Release date: {cy(doc_current)}')

if __name__ == "__main__":

    if sys.version_info.major == 2:
        print('This script needs Python 3.')
        exit()

    start = timer()
    main()
    end = timer()

    print(f'')
    print(f'\n [{date.today()}] Completed within [{end-start:.2f} sec].\n')
