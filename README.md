# SEEKER_dataset
This is the dataset of "SEEKER: A Root Cause Analysis Method Based on Deterministic Replay for Multi-Type Network Protocol Vulnerabilities".
The dataset has the snapshots, record logs and root cause analysis reports of 8 real-world vulnerabilities. The vulnerability list is as below:

| CVE/CNVD       | Platform | Software | Vulnerability Type    |
| -------------- | -------- | -------- | --------------------- |
| CVE-2021-3449  | Regular  | OpenSSL  | State Obfuscation     |
| CVE-2020-15778 | Regular  | OpenSSH  | Command Injection     |
| CVE-2014-0160  | Regular  | OpenSSL  | Information Leakage   |
| CVE-2018-10933 | Regular  | libSSH   | Authentication Bypass |
| CVE-2014-0195  | Regular  | OpenSSL  | Heap Overflow         |
| CVE-2016-6309  | Regular  | OpenSSL  | Use After Free        |
| CVE-2017-12858 | Regular  | libzip   | Double free           |
| CVE-2018-16333 | Embedded | httpd    | Buffer Overflow       |

There are three types of files in each folder:

1. snapshot: the snapshot of the virtual machine at the beginning
2. record logs: the execution record of virtual machine
3. report: the root cause analysis report of network protocol software vulnerabilities

The dataset will be open soon.
