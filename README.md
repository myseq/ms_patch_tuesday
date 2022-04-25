# MS Patch Tuesday (MSRFC - Security Update Guide)
This is a simple tool (written python) to perfrom quick analysis on security updates for MS Patch Tuesday. It highlights:
- Products Families
- Vulnerability Types
- High severity vulnerabities (>= CVSS 8.5)
- High likelihood vulnerabilities (contains 'Exploitation More Likely') 
- Vulnerabilties that exploited in wild (Exploited:Yes)

Microsoft Security Response Center (MSRC) investigates all reports of security vulnerabilities affecting Microsoft products and services, and provides these updates as part of the ongoing effort to help you manage security risks and help keep your systems protected. All the details from Microsoft security update are formatted according to the Common Vulnerability Reporting Framework (CVRF). For more details, please visit msrc.microsoft.com/update-guide.


# Usage
Get vulnerability stats and updates.
```console
$ ./patch_tuesday.py
```
![./patch_tuesday.py](.github/patch_tuesday1.png)


# References:
- [MSRC CVRF API](https://api.msrc.microsoft.com/cvrf/v2.0/swagger/index)
- [Microsoft April 2022 Security Updates](https://myseq.blogspot.com/2022/04/microsoft-april-2022-security-updates.html)
- [April 2002 Microsoft Security Updates](https://myseq.blogspot.com/2022/04/april-2002-microsoft-security-updates.html)


