# MS Patch Tuesday 

`MS Patch Tuesday` is the second Tuesday of every month when Microsoft releases security updates to fix vulnerabilities in their software products.

This is a simple script, written in Python, to perform quick analysis on security updates. 
It quickly summarizes:

 - Monthly security updates.
   - Any ***high severity*** vulnerabilities (CVSSi_Base >= 8.5).
   - Any ***high likelihood*** vulnerabilities (contains 'Exploitation More Likely')
   - Any vulnerability that ***exploited in wild*** (Exploited:yes)
 - Monthly MS patched product families.

Microsoft Security Response Center (MSRC) investigates all reports of security vulnerabilities affecting Microsoft products and services, and provides these updates as part of the ongoing effort to help you manage security risks and help keep your systems protected. 

All the details from Microsoft security update are formatted according to the Common Vulnerability Reporting Framework (CVRF). 
For more details, please visit [msrc.microsoft.com/update-guide](https://msrc.microsoft.com/update-guide).

> ***CVRF*** *stands for `Common Vulnerability Reporting Framework`.*

<!--
# Usages
Get quick summary of MS vulnerability stats for current month. 
```console
$ ./patch_tuesday.py
```
![./patch_tuesday.py](.github/patch_tuesday1.png)

## Tips
Show quick summary with simple ASCII chart.
```console
$ ./patch_tuesday.py -vc -k 2022-apr
```
![./patch_tuesday.py -vc -k 2022-apr](.github/patch_tuesday2.png)

```console
$ ./patch_tuesday -k 2022-may -v
```
![./patch_tuesday.py -k 2022-may -v](.github/2022-may.png)

```console
$ ./patch_tuesday -k 2022-jun -v
```
![./patch_tuesday.py -k 2022-jun -v](.github/2022-jun.png)

-->

# Features

 1. Show the total vulnerability count for the month.
 1. Show the number of `high severity` vulnerability count.
 1. Show the number of vulnerability which `very likely to be exploited`. 
 1. Show the number of vulnerability which already `exploited in wild`.
 1. Show the `product families` that involve.
 1. Display the product familier as `bar chart`.
 1. Download the `JSON` file.

Use `-h` to show the help screen:

```bash
$ ./patch_tuesday.py -h
```

![./patch_tuesday.py -h](images/pt3_help.png)

## Usages

Show quick summary.

```bash
$ ./patch_tuesday.py

 _____     _       _      _____               _
|  _  |___| |_ ___| |_   |_   _|_ _ ___ ___ _| |___ _ _
|   __| .'|  _|  _|   |    | | | | | -_|_ -| . | .'| | |
|__|  |__,|_| |___|_|_|    |_| |___|___|___|___|__,|_  |
                                                   |___|

 Microsoft Patch Tuesday - By MSRC
===============================================
 << April 2024 Security Updates [ 2024-04-09 ] >>


 [+] Vulnerabilities           : [ 185 ]
        [-] High_Severity      : [  49 ]
        [-] High_likelihood    : [  13 ]
        [-] Exploited in_wild  : [   1 ]
 [+] Product Families          : [  10 ]


 [*] [2024-04-23] main(): Completed within [7.3636 sec].

```

Show vulnerabilities and product families in verbose mode.

```bash
$ ./patch_tuesday.py -v -k 2023-dec


 _____     _       _      _____               _
|  _  |___| |_ ___| |_   |_   _|_ _ ___ ___ _| |___ _ _
|   __| .'|  _|  _|   |    | | | | | -_|_ -| . | .'| | |
|__|  |__,|_| |___|_|_|    |_| |___|___|___|___|__,|_  |
                                                   |___|


 [*] Finish fetching [528,922 bytes] from https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2023-dec

 Microsoft Patch Tuesday - By MSRC
===============================================
 << December 2023 Security Updates [ 2023-12-12 ] >>


 [+] Vulnerabilities           : [  51 ]
        [-] High_Severity      : [   6 ]
        [-] High_likelihood    : [  11 ]
        [-] Exploited in_wild  : [   0 ]
 [+] Product Families          : [   8 ]

                                                         High_Severity/6
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ CVE            ┃ CVSS_Base ┃ CVSS_Temporal ┃ Title_Value                                                                       ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ CVE-2023-35618 │    9.6    │      8.3      │ Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability              │
│ CVE-2023-36019 │    9.6    │      8.3      │ Microsoft Power Platform Connector Spoofing Vulnerability                         │
│ CVE-2023-36006 │    8.8    │      7.7      │ Microsoft WDAC OLE DB provider for SQL Server Remote Code Execution Vulnerability │
│ CVE-2023-35639 │    8.8    │      7.7      │ Microsoft ODBC Driver Remote Code Execution Vulnerability                         │
│ CVE-2023-35641 │    8.8    │      7.7      │ Internet Connection Sharing (ICS) Remote Code Execution Vulnerability             │
│ CVE-2023-35630 │    8.8    │      7.7      │ Internet Connection Sharing (ICS) Remote Code Execution Vulnerability             │
└────────────────┴───────────┴───────────────┴───────────────────────────────────────────────────────────────────────────────────┘

                                                        High_Likelihood/11
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ CVE            ┃ CVSS_Base ┃ CVSS_Temporal ┃ Title_Value                                                                        ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ CVE-2023-36696 │    7.8    │      6.8      │ Windows Cloud Files Mini Filter Driver Elevation of Privilege Vulnerability        │
│ CVE-2023-36391 │    7.8    │      6.8      │ Local Security Authority Subsystem Service Elevation of Privilege Vulnerability    │
│ CVE-2023-36011 │    7.8    │      6.8      │ Win32k Elevation of Privilege Vulnerability                                        │
│ CVE-2023-36010 │    7.5    │      6.5      │ Microsoft Defender Denial of Service Vulnerability                                 │
│ CVE-2023-36005 │    7.5    │      6.5      │ Windows Telephony Server Elevation of Privilege Vulnerability                      │
│ CVE-2023-35641 │    8.8    │      7.7      │ Internet Connection Sharing (ICS) Remote Code Execution Vulnerability              │
│ CVE-2023-35644 │    7.8    │      6.8      │ Windows Sysmain Service Elevation of Privilege                                     │
│ CVE-2023-35628 │    8.1    │      7.1      │ Windows MSHTML Platform Remote Code Execution Vulnerability                        │
│ CVE-2023-35631 │    7.8    │      6.8      │ Win32k Elevation of Privilege Vulnerability                                        │
│ CVE-2023-35632 │    7.8    │      6.8      │ Windows Ancillary Function Driver for WinSock Elevation of Privilege Vulnerability │
│ CVE-2023-35633 │    7.8    │      6.8      │ Windows Kernel Elevation of Privilege Vulnerability                                │
└────────────────┴───────────┴───────────────┴────────────────────────────────────────────────────────────────────────────────────┘


 [+] Product Families (8)
        [ 1]              Windows : 26
        [ 2]                  ESU : 10
        [ 3]     Microsoft Office : 9
        [ 4]   Microsoft Dynamics : 6
        [ 5]                Azure : 4
        [ 6]              Browser : 1
        [ 7]      Developer Tools : 1
        [ 8]        System Center : 1

 [*] "December 2023 Security Updates" (Rev 12)
        [-] Initial Release date: 2023-12-12T08:00:00
        [-] Current Release date: 2024-02-16T08:00:00


 [*] [2024-04-23] main(): Completed within [2.8933 sec].

```

Show vulnerabilities and product families (as bar chart) in verbose mode.

```bash
$ ./patch_tuesday.py -vc -k 2023-dec

 _____     _       _      _____               _
|  _  |___| |_ ___| |_   |_   _|_ _ ___ ___ _| |___ _ _
|   __| .'|  _|  _|   |    | | | | | -_|_ -| . | .'| | |
|__|  |__,|_| |___|_|_|    |_| |___|___|___|___|__,|_  |
                                                   |___|


 [*] Finish fetching [528,922 bytes] from https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2023-dec

 Microsoft Patch Tuesday - By MSRC
===============================================
 << December 2023 Security Updates [ 2023-12-12 ] >>


 [+] Vulnerabilities           : [  51 ]
        [-] High_Severity      : [   6 ]
        [-] High_likelihood    : [  11 ]
        [-] Exploited in_wild  : [   0 ]
 [+] Product Families          : [   8 ]

                                                         High_Severity/6
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ CVE            ┃ CVSS_Base ┃ CVSS_Temporal ┃ Title_Value                                                                       ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ CVE-2023-35618 │    9.6    │      8.3      │ Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability              │
│ CVE-2023-36019 │    9.6    │      8.3      │ Microsoft Power Platform Connector Spoofing Vulnerability                         │
│ CVE-2023-36006 │    8.8    │      7.7      │ Microsoft WDAC OLE DB provider for SQL Server Remote Code Execution Vulnerability │
│ CVE-2023-35639 │    8.8    │      7.7      │ Microsoft ODBC Driver Remote Code Execution Vulnerability                         │
│ CVE-2023-35641 │    8.8    │      7.7      │ Internet Connection Sharing (ICS) Remote Code Execution Vulnerability             │
│ CVE-2023-35630 │    8.8    │      7.7      │ Internet Connection Sharing (ICS) Remote Code Execution Vulnerability             │
└────────────────┴───────────┴───────────────┴───────────────────────────────────────────────────────────────────────────────────┘

                                                        High_Likelihood/11
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ CVE            ┃ CVSS_Base ┃ CVSS_Temporal ┃ Title_Value                                                                        ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ CVE-2023-36696 │    7.8    │      6.8      │ Windows Cloud Files Mini Filter Driver Elevation of Privilege Vulnerability        │
│ CVE-2023-36391 │    7.8    │      6.8      │ Local Security Authority Subsystem Service Elevation of Privilege Vulnerability    │
│ CVE-2023-36011 │    7.8    │      6.8      │ Win32k Elevation of Privilege Vulnerability                                        │
│ CVE-2023-36010 │    7.5    │      6.5      │ Microsoft Defender Denial of Service Vulnerability                                 │
│ CVE-2023-36005 │    7.5    │      6.5      │ Windows Telephony Server Elevation of Privilege Vulnerability                      │
│ CVE-2023-35641 │    8.8    │      7.7      │ Internet Connection Sharing (ICS) Remote Code Execution Vulnerability              │
│ CVE-2023-35644 │    7.8    │      6.8      │ Windows Sysmain Service Elevation of Privilege                                     │
│ CVE-2023-35628 │    8.1    │      7.1      │ Windows MSHTML Platform Remote Code Execution Vulnerability                        │
│ CVE-2023-35631 │    7.8    │      6.8      │ Win32k Elevation of Privilege Vulnerability                                        │
│ CVE-2023-35632 │    7.8    │      6.8      │ Windows Ancillary Function Driver for WinSock Elevation of Privilege Vulnerability │
│ CVE-2023-35633 │    7.8    │      6.8      │ Windows Kernel Elevation of Privilege Vulnerability                                │
└────────────────┴───────────┴───────────────┴────────────────────────────────────────────────────────────────────────────────────┘


 [+] Product Families (8)
                       Windows ▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇ 26
                           ESU ▇▇▇▇▇▇▇▇▇ 10
              Microsoft Office ▇▇▇▇▇▇▇▇ 9
            Microsoft Dynamics ▇▇▇▇▇ 6
                         Azure ▇▇▇ 4
                       Browser ▇ 1
               Developer Tools ▇ 1
                 System Center ▇ 1

 [*] "December 2023 Security Updates" (Rev 12)
        [-] Initial Release date: 2023-12-12T08:00:00
        [-] Current Release date: 2024-02-16T08:00:00


 [*] [2024-04-23] main(): Completed within [2.8670 sec].

```

Download and save the JSON file (YYYY_MM.json).

```bash
$ ./patch_tuesday.py -j -k 2023-dec

 _____     _       _      _____               _
|  _  |___| |_ ___| |_   |_   _|_ _ ___ ___ _| |___ _ _
|   __| .'|  _|  _|   |    | | | | | -_|_ -| . | .'| | |
|__|  |__,|_| |___|_|_|    |_| |___|___|___|___|__,|_  |
                                                   |___|

ic| filename: '2023_12.json'


 [*] [2024-04-23] main(): Completed within [3.0585 sec].
```

## Tips

Use the `-j` option to download the JSON file.
Then use `jq` utility to count the number of vulnerabilities released.

```bash
$ cat 2023_12.json | jq '.Vulnerability | length'
51
```

# History/Updates:

 - 2022.03 : ms_patch_tuesday_2.0
 - 2024.04 : ms_patch_tuesday_3.0

## CVRF API calls
 
 - https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/
 - https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/

# Links:

 - [MSRC-Microsoft-Security-Updates-API](https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API)
 - [MSRC CVRF API v3](https://api.msrc.microsoft.com/cvrf/v3.0/swagger/v3/swagger.json)
 - [MySeq - Patch_Tuesday Utils](https://myseq.blogspot.com/2022/07/patchtuesday-utils.html)


