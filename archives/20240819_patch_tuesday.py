#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys, argparse
from argparse import RawTextHelpFormatter
from timeit import default_timer as timer
import json

from datetime import date
from datetime import datetime, timedelta
from collections import Counter

from icecream import ic

import httpx
import pyfiglet
from rich import print as rprint
from rich_argparse import RawTextRichHelpFormatter
from rich.console import Console
from rich.table import Table


data = {}
base = 'https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/'
cisa = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
hdrs = {'Accept': 'application/json'}

desc = f'To get [yellow]summary of security updates and product families[/yellow] from [blue]MSRC[/blue].'
note = f'  [i][#8080FF]Get security updates from MSRC, formatted according to CVRF.[/#8080FF][/i]'


banner = f"""
   Zzzzz   |\      _,,,---,,_
           /,`.-'`'    -.  ;-;;,_   __author__ : [ [#FFBF00][i]zd[/i][/#FFBF00] ]
          |,4-  ) )-,_..;\ (  `'-'  __year__   : [ [magenta][i]2024.08[/i][/magenta] ]
         '---''(_/--'  `-'\_)       __file__   : [ [i]{__file__}[/i] ]

         [ {desc} ]
    """

shCh = False
verb = False


def timeit(func):
    def timed(*args, **kwargs):
        stime = timer()
        result = func(*args, **kwargs)
        etime = timer()
        rprint(f'\n [*] [{date.today()}] {func.__name__}(): Completed within [{etime-stime:.4f} sec].')
        return result
    return timed


def count_vulns(all_vulns, mode):
    base_score = 8.5
    counter = 0
    cves = []

    for vuln in all_vulns:
        cvss_tscore = 0.0
        cvss_score = 0.0
        cvss_sets = vuln.get('CVSSScoreSets', [])
        if len(cvss_sets) > 0 :
            cvss_tscore = cvss_sets[0].get('TemporalScore', 0.0)
            cvss_score = cvss_sets[0].get('BaseScore', 0.0)
            if cvss_score >= base_score and mode == 'critical':
                counter += 1
                tv = vuln.get('Title').get('Value', '<>')
                cves.append(f'{vuln["CVE"]} - {cvss_score} - {cvss_tscore} - {tv}')

        for threat in vuln['Threats']:
            if threat['Type'] == 1:
                description = threat['Description']['Value']
                
                #if description == 'DOS:N/A':
                #    print(vuln.get('Title').get('Value'))

                if mode == 'exploited' and 'Exploited:Yes' in description:
                    counter += 1
                    tv = vuln.get('Title').get('Value', '<>')
                    cves.append(f'{vuln["CVE"]} - {cvss_score} - {cvss_tscore} - {tv}')
                    break

                if mode == 'high_likely' and 'Exploitation More Likely'.lower() in description.lower():
                    counter += 1
                    tv = vuln.get('Title').get('Value', '<>')
                    cves.append(f'{vuln["CVE"]} - {cvss_score} - {cvss_tscore} - {tv}')
                    break

    return {'counter': counter, 'cves': cves}

def count_action(all_vulns):
    action = 0
    cves = []

    for vuln in all_vulns:
        for note in vuln['Notes']:
            if note['Title'] == 'Customer Action Required' and note['Value'] == "Yes":
                action += 1

    return action


def find_patch_tuesday(month, year):
    """ To get the patch Tuesday date in the format of YYYY-mm-dd """

    basedate = datetime.strptime('{} 12 {} 12:00AM'.format(month, year), '%m %d %Y %I:%M%p')

    dayoftheweek = basedate.weekday() + 1

    if dayoftheweek > 6:
        dayoftheweek = 0

    return (basedate - timedelta(days=dayoftheweek) + timedelta(days=2)).date()


def fetching(year=None, month=None):
    """ Fetching data from MSRC """
    global verb
    global base
    global hdrs
    global data

    param = f'{year}-{month}'
    url = base + param
    client = httpx.Client(http2=True, headers=hdrs)

    try:
        #resp = httpx.get(url, headers=hdrs)
        resp = client.get(url)
        resp.raise_for_status()
    except httpx.RequestError as exc:
        rprint(f" [!] Error occurred while requesting {exc.request.url!r}.")
    except httpx.HTTPStatusError as exc:
        rprint(f" [!] Error response {exc.response.status_code} while requesting {exc.request.url!r}.")
        if verb:
            if resp.status_code == 400:
                rprint(f' [!] FAIL: Bad Request on {url}')
            elif resp.status_code == 401:
                rprint(f' [!] FAIL: Unauthorized access to {url}')
            elif resp.status_code == 404:
                rprint(f' [!] FAIL: Not Found at {url}')
            elif resp.status_code == 500:
                rprint(f' [!] FAIL: Internal Service Error at {url}')
            else:
                rprint(f' [!] FAIL: Unknown error "{resp.status_code}" at {url}')

        return False

    else:
        if resp.status_code == 200:
            data = resp.json()
            total = len(resp.content)
            if verb: 
                rprint(f'\n [*] Finish fetching [{total:,} bytes] from {url}\n')

            return True

    finally:
        client.close()


def saveJSON(filename):
    """ Save the JSON file as YYYY_MM.json """
    global data

    ic(filename)
    with open (filename, 'w') as fh:
        json.dump(data, fh, indent = 4)


def showChartSummary(tuesday):
    """ Display Chart and Summary """
    global data
    global verb
    global shCh
    global cisa

    all_products = {}
    all_microsoft = data.get('ProductTree').get('Branch', [])
    all_items = all_microsoft[0].get('Items', [])

    all_cisa = {}
    jcisa = httpx.get(cisa)
    if jcisa.status_code == httpx.codes.OK:
        all_cisa = jcisa.json()
    else:
        rprint(f' [*] FAIL to access the JSON file at {cisa}\n')

    if verb:
        rprint(f'\n [*] [red]{all_cisa.get("title")}[/red] [ {all_cisa.get("catalogVersion")}/{all_cisa.get("count")} ]\n')
        print(f'')


    for p in all_items:
        pname = p['Name']
        icount = len(p['Items'])#ic(len(cve_cisa))
        all_products[pname] = icount

    title = data.get('DocumentTitle', 'Release not found').get('Value')
    #all_vulns = data.get('Vulnerability', [])
    all_vuln = data.get('Vulnerability', [])
    all_vulns = [ v for v in all_vuln if v.get('Title').get('Value') ]
    
    cve_cisa = []
    for vuln in all_cisa['vulnerabilities']:
        cve_cisa.append(vuln['cveID'])
    #ic(len(cve_cisa))

    cve_msrc = []
    for vuln in all_vulns:
        cve_msrc.append(vuln["CVE"])
    #ic(len(cve_msrc))

    mark0 = "▏"
    mark1 = "▇"
    max_length = 50
    Header1 = f' Microsoft Patch Tuesday - By [blue]MSRC[/blue]'
    Header2 = f' << [yellow]{title}[/yellow] [ [green]{tuesday}[/green] ] >>'

    rprint(Header1)
    rprint('='*len(Header1))
    rprint(Header2)
    print(f'')
    print(f'')

    rprint(f' [+] Vulnerabilities           : [ {len(all_vulns):>3} ]')

    critical = count_vulns(all_vulns, 'critical')
    rprint(f'\t[-] High_Severity      : [ [yellow]{critical["counter"]:>3}[/yellow] ]')
    high_likely = count_vulns(all_vulns, 'high_likely')
    rprint(f'\t[-] High_likelihood    : [ [yellow]{high_likely["counter"]:>3}[/yellow] ]')
    exploited = count_vulns(all_vulns, 'exploited')
    rprint(f'\t[-] Exploited in_wild  : [ [yellow]{exploited["counter"]:>3}[/yellow] ]')
    actions = count_action(all_vulns)
    rprint(f'\t[-] Action_required    : [ [yellow]{actions:>3}[/yellow] ]')

    cisa_kev = sum(x in cve_msrc for x in cve_cisa)
    rprint(f'\t[-] Found in CISA_KEV  : [ [red]{cisa_kev:>3}[/red] ]')

    vcat = {}
    vcat = {'c': critical, 'h': high_likely, 'e': exploited}

    if verb:
        print(f'')

        for c,d in vcat.items():
            if d.get('counter') == 0:
                continue

            table = Table(title='')

            if d.get('counter') != 0 and c == 'c':
                title = f'High_Severity/[yellow]{d.get("counter")}[/yellow]'
                table = Table(title=title)

            if d.get('counter') != 0 and c == 'h':
                title = f'High_Likelihood/[yellow]{d.get("counter")}[/yellow]'
                table = Table(title=title)

            if d.get('counter') != 0 and c == 'e':
                title = f'Exploited_in_Wild/[yellow]{d.get("counter")}[/yellow]'
                table = Table(title=title)

            table.add_column('CVE', style='red', no_wrap=True)
            #table.add_column('CVSS_Base', justify='center', style='cyan')
            #table.add_column('CVSS_Temporal', justify='center', style='magenta')
            table.add_column('CVSS_Base/Temp', justify='center', style='magenta')
            table.add_column('Title_Value')
            for cve in d['cves']:
                cv,vv,pv,tv = cve.split(' - ', 3)
                if cv in cve_cisa:
                    cvss2 = f'B:{vv}/T:{pv} [K]'
                else:
                    cvss2 = f'B:{vv}/T:{pv}'
                #table.add_row(cv,vv,pv,tv)
                table.add_row(cv,cvss2,tv)
            console = Console()
            console.print(table)
            print(f'')

        print(f'')
        i = 1
        max_value = sum(all_products.values())
        rprint(f' [+] Product Families ({len(all_products)})')
        for p in sorted(all_products, key=all_products.get, reverse=True):
            if shCh:
                c = round(all_products[p] / max_value * max_length)
                if c >= 1:
                    rprint(f'{"":>4s}{p:>26s} [blue]{mark1*c}[/blue] {all_products[p]}')
                else:
                    rprint(f'{"":>4s}{p:>26s} [blue]{mark0}[/blue] {all_products[p]}')
            else:
                rprint(f'\t[{i:>2}] {p:>20s} : [green]{all_products[p]}[/green]')
                i += 1
        print(f'')


        docTrack = data.get('DocumentTracking')
        doc_history = docTrack.get('RevisionHistory', [])
        doc_revision = doc_history[0]['Number']
        doc_value = doc_history[0]['Description']['Value']
        doc_initial = docTrack['InitialReleaseDate']
        doc_current = docTrack['CurrentReleaseDate']
        rprint(f' [*] "[blue]{doc_value}[/blue]" (Rev {doc_revision})')
        rprint(f'\t[-] Initial Release date: [yellow]{doc_initial}[/yellow]')
        rprint(f'\t[-] Current Release date: [green]{doc_current}[/green]')


def usage():
    """ usage() function """
    parser = argparse.ArgumentParser(description=banner, formatter_class=RawTextRichHelpFormatter, epilog=note)

    parser.add_argument('-c', action='store_true', help='show chart output')
    parser.add_argument('-j', action='store_true', help='save the JSON file')
    parser.add_argument('-k', dest='cvrf', metavar='<YYYY-mmm>', help="Date string for the report query in format YYYY-mmm: <2024-apr>")
    parser.add_argument('-v', action='store_true', help='verbose output')

    return parser.parse_args()

@timeit
def main():
    """ main() function """
    global verb
    global base
    global shCh

    args = usage()
    verb = True if args.v else False
    shCh = True if args.c else False

    print(f'')
    word = pyfiglet.figlet_format("Patch Tuesday", font="rectangles")
    rprint(f'[blue]{word}[/blue]')
    tuesday = "error"
    filename = ''

    if args.cvrf:
        cvrf = args.cvrf
        yyyy, mmm = cvrf.split('-')
        date_obj = datetime.strptime(cvrf, "%Y-%b").date()
        m = date_obj.month
        y = date_obj.year
        tuesday = find_patch_tuesday(m, y)
        filename = f'{y}_{m:02}.json'
    else:
        m = date.today().month
        y = date.today().year
        tuesday = find_patch_tuesday(m, y)
        mmm = date.today().strftime("%h").lower()
        yyyy = date.today().year
        filename = f'{y}_{m:02}.json'

    #ic(tuesday)

    if not fetching(yyyy, mmm):
        return
    else:
        #ic(len(data))
        if args.j:
            saveJSON(filename)
        else:
            showChartSummary(tuesday)

    print(f'')
    return 


if __name__ == "__main__":

    main()


