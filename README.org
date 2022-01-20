* CVE-2022-21907
--------
** Description
    - POC for CVE-2022-21907: HTTP Protocol Stack Remote Code Execution Vulnerability.
    - create by antx at 2022-01-17.
--------
** Detail
    - HTTP Protocol Stack Remote Code Execution Vulnerability.
    - Similar to [[https://github.com/antx-code/CVE-2021-31166][CVE-2021-31166]].
    - This problem exists, from last year which is reported on [[https://github.com/antx-code/CVE-2021-31166][CVE-2021-31166]], and still there.
--------
** CVE Severity
    - attackComplexity: LOW
    - attackVector: NETWORK
    - availabilityImpact: HIGH
    - confidentialityImpact: HIGH
    - integrityImpact: HIGH
    - privilegesRequired: NONE
    - scope: UNCHANGED
    - userInteraction: NONE
    - version: 3.1
    - baseScore: 9.8
    - baseSeverity: CRITICAL
--------
** Affect
    - Windows
        - 10 Version 1809 for 32-bit Systems
        - 10 Version 1809 for x64-based Systems
        - 10 Version 1809 for ARM64-based Systems
        - 10 Version 21H1 for 32-bit Systems
        - 10 Version 21H1 for x64-based System
        - 10 Version 21H1 for ARM64-based Systems
        - 10 Version 20H2 for 32-bit Systems
        - 10 Version 20H2 for x64-based Systems
        - 10 Version 20H2 for ARM64-based Systems
        - 10 Version 21H2 for 32-bit Systems
        - 10 Version 21H2 for x64-based Systems
        - 10 Version 21H2 for ARM64-based Systems
        - 11 for x64-based Systems
        - 11 for ARM64-based Systems
    - Windows Server
        - 2019
        - 2019 (Core installation)
        - 2022
        - 2022 (Server Core installation)
        - version 20H2 (Server Core Installation)
--------
** POC
    - [[./CVE-2022-21907.py][Poc]]
--------
** Mitigations
    - Windows Server 2019 and Windows 10 version 1809 are not vulnerable by default. Unless you have enabled the HTTP Trailer Support via EnableTrailerSupport registry value, the systems are not vulnerable.
    - Delete the DWORD registry value "EnableTrailerSupport" if present under:
        #+begin_src bash
        HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\HTTP\Parameters
        #+end_src
    - This mitigation only applies to Windows Server 2019 and Windows 10, version 1809 and does not apply to the Windows 20H2 and newer.
--------
** FAQ
    - How could an attacker exploit this vulnerability?
        - In most situations, an unauthenticated attacker could send a specially crafted packet to a targeted server utilizing the HTTP Protocol Stack (http.sys) to process packets.
    - Is this wormable?
        - Yes. Microsoft recommends prioritizing the patching of affected servers.
    - Windows 10, Version 1909 is not in the Security Updates table. Is it affected by this vulnerability?
        - No, the vulnerable code does not exist in Windows 10, version 1909. It is not affected by this vulnerability.
    - Is the EnableTrailerSupport registry key present in any other platform than Windows Server 2019 and Windows 10, version 1809?
        - No, the registry key is only present in Windows Server 2019 and Windows 10, version 1809
--------
** Reference
    - Ref-Source
        - [[https://github.com/mauricelambert/CVE-2022-21907]]
        - [[https://github.com/nu11secur1ty/Windows10Exploits/tree/master/2022/CVE-2022-21907]]
    - Ref-Risk
        - [[https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2022-21907][HTTP Protocol Stack Remote Code Execution Vulnerability]]
        - [[https://nvd.nist.gov/vuln/detail/CVE-2022-21907][NVD<CVE-2022-21907>]]
    - CVE
        - [[https://github.com/CVEProject/cvelist/blob/master/2022/21xxx/CVE-2022-21907.json][CVE-2022-21907]]
        - [[https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21907][CVE-2022-21907]]
    - Ref-Related
        - [[https://github.com/antx-code/CVE-2021-31166][CVE-2021-31166]]
