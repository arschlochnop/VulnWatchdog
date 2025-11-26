# 2025年08月漏洞情报汇总

> 📅 统计周期: 2025-08-01 ~ 2025-08-30
> 📊 新增漏洞: **808** 个
> 🔥 高危漏洞: **669** 个

---

## 📊 漏洞类型分布

| 类型 | 数量 | 占比 |
|------|------|------|
| 远程代码执行 | 146 | 18.1% |
| 远程代码执行 (RCE) | 86 | 10.6% |
| 路径遍历 | 47 | 5.8% |
| 代码注入 | 34 | 4.2% |
| 权限提升 | 29 | 3.6% |
| 目录遍历 | 21 | 2.6% |
| XSS | 19 | 2.4% |
| 跨站脚本 (XSS) | 15 | 1.9% |
| 身份验证绕过 | 14 | 1.7% |
| 本地提权 | 14 | 1.7% |

---

## 📋 详细列表

### [CVE-2025-9478](CVE-2025-9478-Kamgreen50_STIG-Edge-RCE-CVE2025-9478.md) 🔴 

**名称:** CVE-2025-9478-Google Chrome ANGLE Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，允许远程攻击者执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-08-31  
**POC仓库:** [STIG-Edge-RCE-CVE2025-9478](https://github.com/Kamgreen50/STIG-Edge-RCE-CVE2025-9478)  

---

### [CVE-2025-4427](CVE-2025-4427-rxerium_CVE-2025-4427-CVE-2025-4428.md) 🔴 ✅

**名称:** CVE-2025-4427 & CVE-2025-4428 - Ivanti Endpoint Manager Mobile (EPMM) 身份验证绕过和远程代码执行  
**类型:** 身份验证绕过和远程代码执行  
**风险:** 高危，未经身份验证的攻击者可以远程执行代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-31  
**POC仓库:** [CVE-2025-4427-CVE-2025-4428](https://github.com/rxerium/CVE-2025-4427-CVE-2025-4428)  

---

### [CVE-2025-52413](CVE-2025-52413-GoldenTicketLabs_CVE-2025-52413.md) 🔴 ✅

**名称:** CVE-2025-52413 — Particle Device OS BLE Buffer Overflow  
**类型:** 缓冲区溢出  
**风险:** 高危，可导致任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-31  
**POC仓库:** [CVE-2025-52413](https://github.com/GoldenTicketLabs/CVE-2025-52413)  

---

### [CVE-2021-41773](CVE-2021-41773-blackn0te_Apache-HTTP-Server-2.4.49-2.4.50-Path-Traversal-Remote-Code-Execution.md) 🔴 ✅

**名称:** CVE-2021-41773/CVE-2021-42013 - Apache HTTP Server Path Traversal and RCE  
**类型:** 路径遍历和远程代码执行  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-31  
**POC仓库:** [Apache-HTTP-Server-2.4.49-2.4.50-Path-Traversal-Remote-Code-Execution](https://github.com/blackn0te/Apache-HTTP-Server-2.4.49-2.4.50-Path-Traversal-Remote-Code-Execution)  

---

### [CVE-2021-41773](CVE-2021-41773-hackedrishi_CTF_WRITEUPS-TryHackMe-CVE-2021-41773-.md) 🔴 ✅

**名称:** CVE-2021-41773 - Apache HTTP Server Path Traversal  
**类型:** Path Traversal  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-08-31  
**POC仓库:** [CTF_WRITEUPS-TryHackMe-CVE-2021-41773-](https://github.com/hackedrishi/CTF_WRITEUPS-TryHackMe-CVE-2021-41773-)  

---

### [CVE-2025-7775](CVE-2025-7775-rxerium_CVE-2025-7775.md) 🔴 ✅

**名称:** CVE-2025-7775-NetScaler ADC/Gateway-内存溢出导致RCE/DoS  
**类型:** 内存溢出  
**风险:** 高危，可导致远程代码执行和拒绝服务  
**投毒风险:** 0%  
**发现时间:** 2025-08-31  
**POC仓库:** [CVE-2025-7775](https://github.com/rxerium/CVE-2025-7775)  

---

### [CVE-2025-8714](CVE-2025-8714-orderby99_CVE-2025-8714-POC.md) 🔴 ✅

**名称:** CVE-2025-8714-PostgreSQL代码注入  
**类型:** 代码注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-31  
**POC仓库:** [CVE-2025-8714-POC](https://github.com/orderby99/CVE-2025-8714-POC)  

---

### [CVE-2025-55349](CVE-2025-55349-GoldenTicketLabs_CVE-2025-55349.md) 🔴 ✅

**名称:** CVE-2025-55349 - pm2 Arbitrary Code Execution  
**类型:** Arbitrary Code Execution  
**风险:** 高危，允许攻击者执行任意代码，可能导致系统完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-31  
**POC仓库:** [CVE-2025-55349](https://github.com/GoldenTicketLabs/CVE-2025-55349)  

---

### [CVE-2025-2776](CVE-2025-2776-mrk336_From-EternalBlue-to-CVE-2025-2776-The-Evolution-of-an-SMB-Attack.md) 🔴 

**名称:** CVE-2025-2776-SysAid On-Prem-XXE  
**类型:** XML 外部实体 (XXE) 注入  
**风险:** 高危，可能导致管理员账户接管和文件读取  
**投毒风险:** 30%  
**发现时间:** 2025-08-31  
**POC仓库:** [From-EternalBlue-to-CVE-2025-2776-The-Evolution-of-an-SMB-Attack](https://github.com/mrk336/From-EternalBlue-to-CVE-2025-2776-The-Evolution-of-an-SMB-Attack)  

---

### [CVE-2024-48307](CVE-2024-48307-jisi-001_CVE-2024-48307POC.md) 🔴 ✅

**名称:** CVE-2024-48307-JeecgBoot-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-31  
**POC仓库:** [CVE-2024-48307POC](https://github.com/jisi-001/CVE-2024-48307POC)  

---

### [CVE-2015-9251](CVE-2015-9251-halkichi0308_CVE-2015-9251.md) 🟡 ✅

**名称:** CVE-2015-9251-jQuery-跨站脚本攻击（XSS）  
**类型:** 跨站脚本攻击（XSS）  
**风险:** 中危，可能导致用户信息泄露、会话劫持和恶意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-31  
**POC仓库:** [CVE-2015-9251](https://github.com/halkichi0308/CVE-2015-9251)  

---

### [CVE-2015-9251](CVE-2015-9251-moften_CVE-2015-9251.md) 🟡 ✅

**名称:** CVE-2015-9251-jQuery-XSS  
**类型:** XSS  
**风险:** 中危，可能导致用户cookie泄露、页面篡改等  
**投毒风险:** 0%  
**发现时间:** 2025-08-31  
**POC仓库:** [CVE-2015-9251](https://github.com/moften/CVE-2015-9251)  

---

### [CVE-2015-9251](CVE-2015-9251-hackgiver_CVE-2015-9251.md) 🟡 ✅

**名称:** CVE-2015-9251-jQuery-XSS  
**类型:** XSS  
**风险:** 中危，可能导致用户敏感信息泄露或恶意脚本执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-31  
**POC仓库:** [CVE-2015-9251](https://github.com/hackgiver/CVE-2015-9251)  

---

### [CVE-2015-9251](CVE-2015-9251-rox-11_xss.md) 🟡 ✅

**名称:** CVE-2015-9251-jQuery-XSS  
**类型:** 跨站脚本 (XSS)  
**风险:** 中危，可能导致用户凭证泄露、网页内容篡改和恶意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-31  
**POC仓库:** [xss](https://github.com/rox-11/xss)  

---

### [CVE-2015-9251](CVE-2015-9251-wakefulblock262_CVE-2015-9251.md) 🟡 

**名称:** CVE-2015-9251-jQuery-跨站脚本攻击(XSS)  
**类型:** 跨站脚本攻击(XSS)  
**风险:** 中危，可能导致用户cookie泄露，页面内容篡改  
**投毒风险:** 0%  
**发现时间:** 2025-08-31  
**POC仓库:** [CVE-2015-9251](https://github.com/wakefulblock262/CVE-2015-9251)  

---

### [CVE-2025-53744](CVE-2025-53744-fortinetx_CVE-2025-53744.md) 🔴 

**名称:** CVE-2025-53744-FortiOS-权限提升  
**类型:** 权限提升  
**风险:** 高危，可能导致完全控制设备  
**投毒风险:** 10%  
**发现时间:** 2025-08-30  
**POC仓库:** [CVE-2025-53744](https://github.com/fortinetx/CVE-2025-53744)  

---

### [CVE-2025-12654](CVE-2025-12654-Kastowm_Anydesk-Exploit-CVE-2025-12654-RCE-Builder.md) 🔴 ✅

**名称:** CVE-2025-12654 AnyDesk 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许攻击者在目标系统上执行任意代码  
**投毒风险:** 75%  
**发现时间:** 2025-08-30  
**POC仓库:** [Anydesk-Exploit-CVE-2025-12654-RCE-Builder](https://github.com/Kastowm/Anydesk-Exploit-CVE-2025-12654-RCE-Builder)  

---

### [CVE-2018-6574](CVE-2018-6574-memmas_CVE-2018-6574.md) 🔴 ✅

**名称:** CVE-2018-6574 - Go "go get" 远程命令执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-30  
**POC仓库:** [CVE-2018-6574](https://github.com/memmas/CVE-2018-6574)  

---

### [CVE-2025-7775](CVE-2025-7775-Aaqilyousuf_CVE-2025-7775-vulnerable-lab.md) 🔴 ✅

**名称:** CVE-2025-7775-NetScaler-内存溢出  
**类型:** 内存溢出导致RCE/DoS  
**风险:** 高危，可能导致远程代码执行和拒绝服务  
**投毒风险:** 5%  
**发现时间:** 2025-08-30  
**POC仓库:** [CVE-2025-7775-vulnerable-lab](https://github.com/Aaqilyousuf/CVE-2025-7775-vulnerable-lab)  

---

### [CVE-2025-48799](CVE-2025-48799-mrk336_CVE-2025-48799.md) 🔴 ✅

**名称:** CVE-2025-48799 Windows Update Service 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，允许本地攻击者提升权限。  
**投毒风险:** 0%  
**发现时间:** 2025-08-30  
**POC仓库:** [CVE-2025-48799](https://github.com/mrk336/CVE-2025-48799)  

---

### [CVE-2025-24201](CVE-2025-24201-The-Maxu_CVE-2025-24201-WebKit-Vulnerability-Detector-PoC-.md) 🔴 ✅

**名称:** CVE-2025-24201 WebKit Out-of-Bounds Write  
**类型:** Out-of-Bounds Write  
**风险:** 高危，可能导致沙箱逃逸和任意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-30  
**POC仓库:** [CVE-2025-24201-WebKit-Vulnerability-Detector-PoC-](https://github.com/The-Maxu/CVE-2025-24201-WebKit-Vulnerability-Detector-PoC-)  

---

### [CVE-2025-24201](CVE-2025-24201-5ky9uy_glass-cage-i18-2025-24085-and-cve-2025-24201.md) 🔴 ✅

**名称:** CVE-2025-24201 - WebKit RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致远程代码执行、权限提升、数据泄露、设备控制甚至砖机  
**投毒风险:** 10%  
**发现时间:** 2025-08-30  
**POC仓库:** [glass-cage-i18-2025-24085-and-cve-2025-24201](https://github.com/5ky9uy/glass-cage-i18-2025-24085-and-cve-2025-24201)  

---

### [CVE-2025-49113](CVE-2025-49113-LeakForge_CVE-2025-49113.md) 🔴 ✅

**名称:** CVE-2025-49113-Roundcube-PHP对象反序列化RCE  
**类型:** PHP对象反序列化RCE  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-30  
**POC仓库:** [CVE-2025-49113](https://github.com/LeakForge/CVE-2025-49113)  

---

### [CVE-2025-49113](CVE-2025-49113-AC8999_CVE-2025-49113.md) 🔴 ✅

**名称:** CVE-2025-49113 - Roundcube Webmail PHP Object Deserialization  
**类型:** PHP Object Deserialization  
**风险:** 高危，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-29  
**POC仓库:** [CVE-2025-49113](https://github.com/AC8999/CVE-2025-49113)  

---

### [CVE-2025-55579](CVE-2025-55579-ddobrev25_CVE-2025-55579.md) 🟡 ✅

**名称:** CVE-2025-55579 - SolidInvoice Stored Cross-Site Scripting (XSS)  
**类型:** 存储型跨站脚本攻击 (Stored XSS)  
**风险:** 中危，可能导致会话劫持、凭证窃取、网络钓鱼或社会工程学攻击，以及代表其他用户执行任意操作  
**投毒风险:** 10%  
**发现时间:** 2025-08-29  
**POC仓库:** [CVE-2025-55579](https://github.com/ddobrev25/CVE-2025-55579)  

---

### [CVE-2025-57819](CVE-2025-57819-Sucuri-Labs_CVE-2025-57819-ioc-check.md)  ✅

**名称:** CVE-2025-57819-FreePBX-身份验证绕过导致SQL注入和RCE  
**类型:** 身份验证绕过/SQL注入/远程代码执行  
**风险:** 严重，可能导致完全控制系统  
**投毒风险:** 10%  
**发现时间:** 2025-08-29  
**POC仓库:** [CVE-2025-57819-ioc-check](https://github.com/Sucuri-Labs/CVE-2025-57819-ioc-check)  

---

### [CVE-2025-55580](CVE-2025-55580-ddobrev25_CVE-2025-55580.md) 🔴 ✅

**名称:** CVE-2025-55580 - SolidInvoice 存储型跨站脚本 (XSS) 漏洞  
**类型:** 存储型跨站脚本 (XSS)  
**风险:** 高危，可能导致会话劫持、凭证盗取、网络钓鱼和社会工程攻击  
**投毒风险:** 0%  
**发现时间:** 2025-08-29  
**POC仓库:** [CVE-2025-55580](https://github.com/ddobrev25/CVE-2025-55580)  

---

### [CVE-2025-55763](CVE-2025-55763-krispybyte_CVE-2025-55763.md) 🔴 ✅

**名称:** CVE-2025-55763-CivetWeb-缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-29  
**POC仓库:** [CVE-2025-55763](https://github.com/krispybyte/CVE-2025-55763)  

---

### [CVE-2025-57819](CVE-2025-57819-rxerium_CVE-2025-57819.md) 🔴 ✅

**名称:** CVE-2025-57819-FreePBX-身份验证绕过SQL注入RCE  
**类型:** 身份验证绕过，SQL注入，远程代码执行  
**风险:** 高危，可能导致完全控制系统  
**投毒风险:** 5%  
**发现时间:** 2025-08-29  
**POC仓库:** [CVE-2025-57819](https://github.com/rxerium/CVE-2025-57819)  

---

### [CVE-2025-34040](CVE-2025-34040-jisi-001_CVE-2025-34040Exp.md) 🔴 ✅

**名称:** CVE-2025-34040-Zhiyuan OA-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-29  
**POC仓库:** [CVE-2025-34040Exp](https://github.com/jisi-001/CVE-2025-34040Exp)  

---

### [CVE-2025-55188](CVE-2025-55188-lunbun_CVE-2025-55188.md) 🟡 ✅

**名称:** CVE-2025-55188-7-Zip-符号链接处理不当  
**类型:** 符号链接处理不当  
**风险:** 中危，可能导致任意文件写入和代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-29  
**POC仓库:** [CVE-2025-55188](https://github.com/lunbun/CVE-2025-55188)  

---

### [CVE-2025-52100](CVE-2025-52100-changyaoyou_CVE-2025-52100.md) 🔴 ✅

**名称:** CVE-2025-5210 - PHPGurukul Employee Record Management System 1.3 - 漏洞利用分析  
**类型:** 未知 (根据NVD描述为critical)  
**风险:** 高危 (根据NVD描述为critical)  
**投毒风险:** 0%  
**发现时间:** 2025-08-29  
**POC仓库:** [CVE-2025-52100](https://github.com/changyaoyou/CVE-2025-52100)  

---

### [CVE-2025-54309](CVE-2025-54309-watchtowrlabs_watchTowr-vs-CrushFTP-Authentication-Bypass-CVE-2025-54309.md) 🔴 ✅

**名称:** CVE-2025-54309-CrushFTP-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可使未授权的远程攻击者获得管理员权限  
**投毒风险:** 0%  
**发现时间:** 2025-08-29  
**POC仓库:** [watchTowr-vs-CrushFTP-Authentication-Bypass-CVE-2025-54309](https://github.com/watchtowrlabs/watchTowr-vs-CrushFTP-Authentication-Bypass-CVE-2025-54309)  

---

### [CVE-2025-54309](CVE-2025-54309-blueisbeautiful_CVE-2025-54309.md) 🔴 ✅

**名称:** CVE-2025-54309-CrushFTP-AS2认证绕过  
**类型:** 认证绕过  
**风险:** 高危，允许未授权用户获得管理员权限  
**投毒风险:** 10%  
**发现时间:** 2025-08-29  
**POC仓库:** [CVE-2025-54309](https://github.com/blueisbeautiful/CVE-2025-54309)  

---

### [CVE-2025-48384](CVE-2025-48384-jacobholtz_CVE-2025-48384-submodule.md) 🔴 ✅

**名称:** CVE-2025-48384-Git Arbitrary Code Execution  
**类型:** 任意代码执行  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-08-29  
**POC仓库:** [CVE-2025-48384-submodule](https://github.com/jacobholtz/CVE-2025-48384-submodule)  

---

### [CVE-2025-5419](CVE-2025-5419-pavan3478_CVE-2025-5419.md) 🔴 ✅

**名称:** CVE-2025-5419 - Google Chrome V8 引擎 OOB R/W  
**类型:** Out-of-bounds Read/Write  
**风险:** 高危，可能导致堆损坏和任意代码执行  
**投毒风险:** 95%  
**发现时间:** 2025-08-29  
**POC仓库:** [CVE-2025-5419](https://github.com/pavan3478/CVE-2025-5419)  

---

### [CVE-2025-48384](CVE-2025-48384-butyraldehyde_CVE-2025-48384-PoC.md) 🔴 ✅

**名称:** CVE-2025-48384-Git配置注入导致RCE  
**类型:** 配置注入/RCE  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-28  
**POC仓库:** [CVE-2025-48384-PoC](https://github.com/butyraldehyde/CVE-2025-48384-PoC)  

---

### [CVE-2025-47987](CVE-2025-47987-Kryptoenix_CVE-2025-47987_PoC.md) 🔴 ✅

**名称:** CVE-2025-47987-Windows CredSSP 堆缓冲区溢出  
**类型:** 堆缓冲区溢出  
**风险:** 高危，本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-08-28  
**POC仓库:** [CVE-2025-47987_PoC](https://github.com/Kryptoenix/CVE-2025-47987_PoC)  

---

### [CVE-2025-48384](CVE-2025-48384-butyraldehyde_CVE-2025-48384-PoC-Part2.md) 🔴 ✅

**名称:** CVE-2025-48384-Git-任意代码执行  
**类型:** 任意代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-28  
**POC仓库:** [CVE-2025-48384-PoC-Part2](https://github.com/butyraldehyde/CVE-2025-48384-PoC-Part2)  

---

### [CVE-2024-12877](CVE-2024-12877-soltanali0_CVE-2024-12877-Exploit.md) 🔴 ✅

**名称:** CVE-2024-12877-GiveWP-PHP对象注入  
**类型:** PHP对象注入  
**风险:** 高危，可能导致远程代码执行、敏感数据泄露、权限提升和完全服务器控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-28  
**POC仓库:** [CVE-2024-12877-Exploit](https://github.com/soltanali0/CVE-2024-12877-Exploit)  

---

### [CVE-2025-32433](CVE-2025-32433-Mdusmandasthaheer_CVE-2025-32433.md) 🔴 ✅

**名称:** CVE-2025-32433 – Erlang/OTP SSH RCE Vulnerability  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-08-28  
**POC仓库:** [CVE-2025-32433](https://github.com/Mdusmandasthaheer/CVE-2025-32433)  

---

### [CVE-2025-31200](CVE-2025-31200-hunters-sec_CVE-2025-31200.md) 🔴 ✅

**名称:** CVE-2025-31200: CoreAudio APAC Channel Remapping Buffer Overflow  
**类型:** 内存损坏/缓冲区溢出  
**风险:** 高危，可能导致代码执行、拒绝服务或沙箱逃逸  
**投毒风险:** 10%  
**发现时间:** 2025-08-28  
**POC仓库:** [CVE-2025-31200](https://github.com/hunters-sec/CVE-2025-31200)  

---

### [CVE-2025-7955](CVE-2025-7955-Nxploited_CVE-2025-7955.md)  ✅

**名称:** CVE-2025-7955 - RingCentral Communications Plugin Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 严重，未经身份验证的攻击者可以以任何用户身份登录  
**投毒风险:** 20%  
**发现时间:** 2025-08-28  
**POC仓库:** [CVE-2025-7955](https://github.com/Nxploited/CVE-2025-7955)  

---

### [CVE-2023-4596](CVE-2023-4596-X-Projetion_CVE-2023-4596-Vulnerable-Exploit-and-Checker-Version.md) 🔴 ✅

**名称:** CVE-2023-4596 - Forminator 任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-28  
**POC仓库:** [CVE-2023-4596-Vulnerable-Exploit-and-Checker-Version](https://github.com/X-Projetion/CVE-2023-4596-Vulnerable-Exploit-and-Checker-Version)  

---

### [CVE-2023-4596](CVE-2023-4596-X-Projetion_CVE-2023-4596-OpenSSH-Multi-Checker.md) 🔴 ✅

**名称:** CVE-2023-4596-Forminator-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-28  
**POC仓库:** [CVE-2023-4596-OpenSSH-Multi-Checker](https://github.com/X-Projetion/CVE-2023-4596-OpenSSH-Multi-Checker)  

---

### [CVE-2023-4596](CVE-2023-4596-E1A_CVE-2023-4596.md) 🔴 ✅

**名称:** CVE-2023-4596-Forminator插件-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-28  
**POC仓库:** [CVE-2023-4596](https://github.com/E1A/CVE-2023-4596)  

---

### [CVE-2025-6554](CVE-2025-6554-gmh5225_CVE-2025-6554.md) 🔴 ✅

**名称:** CVE-2025-6554-Chrome-V8类型混淆  
**类型:** 类型混淆  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-28  
**POC仓库:** [CVE-2025-6554](https://github.com/gmh5225/CVE-2025-6554)  

---

### [CVE-2025-6554](CVE-2025-6554-PwnToday_CVE-2025-6554.md) 🔴 ✅

**名称:** CVE-2025-6554-Chrome-V8类型混淆  
**类型:** 类型混淆  
**风险:** 高危，允许远程攻击者执行任意读/写操作  
**投毒风险:** 0%  
**发现时间:** 2025-08-28  
**POC仓库:** [CVE-2025-6554](https://github.com/PwnToday/CVE-2025-6554)  

---

### [CVE-2024-28397](CVE-2024-28397-Naved124_CVE-2024-28397-js2py-Sandbox-Escape.md) 🔴 ✅

**名称:** CVE-2024-28397-js2py-Sandbox-Escape  
**类型:** 代码注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 20%  
**发现时间:** 2025-08-28  
**POC仓库:** [CVE-2024-28397-js2py-Sandbox-Escape](https://github.com/Naved124/CVE-2024-28397-js2py-Sandbox-Escape)  

---

### [CVE-2025-7775](CVE-2025-7775-hacker-r3volv3r_CVE-2025-7775-PoC.md) 🔴 

**名称:** CVE-2025-7775-NetScaler-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致完全控制受影响的NetScaler设备  
**投毒风险:** 5%  
**发现时间:** 2025-08-28  
**POC仓库:** [CVE-2025-7775-PoC](https://github.com/hacker-r3volv3r/CVE-2025-7775-PoC)  

---

### [CVE-2025-29927](CVE-2025-29927-zs1n_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-Middleware-Authorization-Bypass  
**类型:** 权限绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-08-28  
**POC仓库:** [CVE-2025-29927](https://github.com/zs1n/CVE-2025-29927)  

---

### [CVE-2025-7775](CVE-2025-7775-mezo0x4_CVE-2025-7775.md) 🔴 ✅

**名称:** CVE-2025-7775 - NetScaler ADC/Gateway 内存溢出 RCE/DoS  
**类型:** 内存溢出  
**风险:** 高危，可导致远程代码执行或拒绝服务  
**投毒风险:** 60%  
**发现时间:** 2025-08-28  
**POC仓库:** [CVE-2025-7775](https://github.com/mezo0x4/CVE-2025-7775)  

---

### [CVE-2025-34157](CVE-2025-34157-Eyodav_CVE-2025-34157.md) 🔴 ✅

**名称:** CVE-2025-34157-Coolify-Stored XSS  
**类型:** Stored XSS  
**风险:** 高危，可完全控制Coolify实例  
**投毒风险:** 1%  
**发现时间:** 2025-08-27  
**POC仓库:** [CVE-2025-34157](https://github.com/Eyodav/CVE-2025-34157)  

---

### [CVE-2025-27363](CVE-2025-27363-tin-z_CVE-2025-27363.md) 🔴 ✅

**名称:** CVE-2025-27363-FreeType-OOB Write  
**类型:** OOB Write  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-27  
**POC仓库:** [CVE-2025-27363](https://github.com/tin-z/CVE-2025-27363)  

---

### [CVE-2025-34159](CVE-2025-34159-Eyodav_CVE-2025-34159.md) 🔴 ✅

**名称:** CVE-2025-34159-Coolify-Docker Compose注入  
**类型:** Docker Compose 注入/远程代码执行  
**风险:** 高危，可导致主机完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-08-27  
**POC仓库:** [CVE-2025-34159](https://github.com/Eyodav/CVE-2025-34159)  

---

### [CVE-2025-8088](CVE-2025-8088-walidpyh_CVE-2025-8088.md) 🔴 ✅

**名称:** CVE-2025-8088-WinRAR路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可导致任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-27  
**POC仓库:** [CVE-2025-8088](https://github.com/walidpyh/CVE-2025-8088)  

---

### [CVE-2025-34161](CVE-2025-34161-Eyodav_CVE-2025-34161.md) 🔴 ✅

**名称:** CVE-2025-34161 - Coolify Git Repository Field Command Injection  
**类型:** 命令注入  
**风险:** 高危，可导致远程代码执行和完全服务器接管  
**投毒风险:** 10%  
**发现时间:** 2025-08-27  
**POC仓库:** [CVE-2025-34161](https://github.com/Eyodav/CVE-2025-34161)  

---

### [CVE-2025-8088](CVE-2025-8088-kitsuneshade_WinRAR-Exploit-Tool---Rust-Edition.md) 🔴 ✅

**名称:** CVE-2025-8088-WinRAR-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-27  
**POC仓库:** [WinRAR-Exploit-Tool---Rust-Edition](https://github.com/kitsuneshade/WinRAR-Exploit-Tool---Rust-Edition)  

---

### [CVE-2024-5083](CVE-2024-5083-Roronoawjd_CVE-2024-5083.md) 🟡 ✅

**名称:** CVE-2024-5083-Nexus Repository 2-存储型XSS  
**类型:** 存储型跨站脚本 (XSS)  
**风险:** 中危，可能导致账户劫持或恶意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-27  
**POC仓库:** [CVE-2024-5083](https://github.com/Roronoawjd/CVE-2024-5083)  

---

### [CVE-2018-19323](CVE-2018-19323-blueisbeautiful_CVE-2018-19323.md) 🔴 ✅

**名称:** CVE-2018-19323: GIGABYTE GDrv MSR 任意读写导致权限提升  
**类型:** 权限提升  
**风险:** 高危，可完全控制系统  
**投毒风险:** 20%  
**发现时间:** 2025-08-27  
**POC仓库:** [CVE-2018-19323](https://github.com/blueisbeautiful/CVE-2018-19323)  

---

### [CVE-2023-3609](CVE-2023-3609-Jturnxd_CVE-2023-3609.md) 🔴 ✅

**名称:** CVE-2023-3609 - Linux Kernel cls_u32 Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-08-27  
**POC仓库:** [CVE-2023-3609](https://github.com/Jturnxd/CVE-2023-3609)  

---

### [CVE-2025-8088](CVE-2025-8088-nyra-workspace_CVE-2025-8088.md) 🔴 ✅

**名称:** CVE-2025-8088-WinRAR-路径遍历导致代码执行  
**类型:** 路径遍历  
**风险:** 高危，可导致任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-27  
**POC仓库:** [CVE-2025-8088](https://github.com/nyra-workspace/CVE-2025-8088)  

---

### [CVE-2025-32433](CVE-2025-32433-te0rwx_CVE-2025-32433-Detection.md)  ✅

**名称:** CVE-2025-32433-Erlang/OTP SSH RCE  
**类型:** 远程代码执行  
**风险:** 严重，无需身份验证即可远程执行代码  
**投毒风险:** 0%  
**发现时间:** 2025-08-27  
**POC仓库:** [CVE-2025-32433-Detection](https://github.com/te0rwx/CVE-2025-32433-Detection)  

---

### [CVE-2025-6934](CVE-2025-6934-yukinime_CVE-2025-6934.md) 🔴 ✅

**名称:** CVE-2025-6934-Opal Estate Pro-权限提升  
**类型:** 权限提升  
**风险:** 高危，允许未经验证的攻击者创建管理员账户。  
**投毒风险:** 0%  
**发现时间:** 2025-08-27  
**POC仓库:** [CVE-2025-6934](https://github.com/yukinime/CVE-2025-6934)  

---

### [CVE-2007-2447](CVE-2007-2447-nika0x38_CVE-2007-2447.md) 🔴 ✅

**名称:** CVE-2007-2447-Samba-远程命令注入  
**类型:** 远程命令注入  
**风险:** 高危，允许远程攻击者执行任意命令  
**投毒风险:** 1%  
**发现时间:** 2025-08-27  
**POC仓库:** [CVE-2007-2447](https://github.com/nika0x38/CVE-2007-2447)  

---

### [CVE-2025-46724](CVE-2025-46724-MaorZLk_langdroid-CVE-2025-46724.md) 🔴 ✅

**名称:** CVE-2025-46724-Langroid-代码注入  
**类型:** 代码注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-08-27  
**POC仓库:** [langdroid-CVE-2025-46724](https://github.com/MaorZLk/langdroid-CVE-2025-46724)  

---

### [CVE-2025-32463](CVE-2025-32463-Yuy0ung_CVE-2025-32463_chwoot.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地权限提升  
**风险:** 高危，本地用户可提升至root权限  
**投毒风险:** 10%  
**发现时间:** 2025-08-27  
**POC仓库:** [CVE-2025-32463_chwoot](https://github.com/Yuy0ung/CVE-2025-32463_chwoot)  

---

### [CVE-2025-8088](CVE-2025-8088-pentestfunctions_best-CVE-2025-8088.md) 🔴 ✅

**名称:** CVE-2025-8088-WinRAR-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，允许攻击者通过构造恶意压缩文件执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-27  
**POC仓库:** [best-CVE-2025-8088](https://github.com/pentestfunctions/best-CVE-2025-8088)  

---

### [CVE-2025-48384](CVE-2025-48384-wzx5002_totallynotsuspicious.md) 🔴 ✅

**名称:** CVE-2025-48384-Git-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-27  
**POC仓库:** [totallynotsuspicious](https://github.com/wzx5002/totallynotsuspicious)  

---

### [CVE-2023-45539](CVE-2023-45539-slicingmelon_HAProxy-CVE-2023-45539-PoC.md) 🟡 ✅

**名称:** CVE-2023-45539 HAProxy URI 组件解析漏洞  
**类型:** URI解析漏洞/信息泄露  
**风险:** 中危，可能导致敏感信息泄露或未授权访问  
**投毒风险:** 0%  
**发现时间:** 2025-08-27  
**POC仓库:** [HAProxy-CVE-2023-45539-PoC](https://github.com/slicingmelon/HAProxy-CVE-2023-45539-PoC)  

---

### [CVE-2025-24893](CVE-2025-24893-AzureADTrent_CVE-2025-24893-Reverse-Shell.md)  ✅

**名称:** CVE-2025-24893-XWiki-远程代码执行  
**类型:** 远程代码执行  
**风险:** 严重，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-08-27  
**POC仓库:** [CVE-2025-24893-Reverse-Shell](https://github.com/AzureADTrent/CVE-2025-24893-Reverse-Shell)  

---

### [CVE-2025-38676](CVE-2025-38676-14mb1v45h_CVE-2025-38676.md) 🔴 ✅

**名称:** CVE-2025-38676-Linux Kernel-Stack Buffer Overflow  
**类型:** 栈缓冲区溢出  
**风险:** 高危，可能导致拒绝服务或权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-08-27  
**POC仓库:** [CVE-2025-38676](https://github.com/14mb1v45h/CVE-2025-38676)  

---

### [CVE-2025-8088](CVE-2025-8088-AdityaBhatt3010_CVE-2025-8088-WinRAR-Zero-Day-Path-Traversal.md) 🔴 ✅

**名称:** CVE-2025-8088 WinRAR 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-08-26  
**POC仓库:** [CVE-2025-8088-WinRAR-Zero-Day-Path-Traversal](https://github.com/AdityaBhatt3010/CVE-2025-8088-WinRAR-Zero-Day-Path-Traversal)  

---

### [CVE-2025-24893](CVE-2025-24893-torjan0_solrsearch-rce-exploit.md) 🔴 ✅

**名称:** CVE-2025-24893-XWiki-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-26  
**POC仓库:** [solrsearch-rce-exploit](https://github.com/torjan0/solrsearch-rce-exploit)  

---

### [CVE-2025-48384](CVE-2025-48384-sahar042_CVE-2025-48384-submodule.md) 🔴 ✅

**名称:** CVE-2025-48384-Git-任意代码执行  
**类型:** 任意代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-26  
**POC仓库:** [CVE-2025-48384-submodule](https://github.com/sahar042/CVE-2025-48384-submodule)  

---

### [CVE-2025-8088](CVE-2025-8088-pescada-dev_-CVE-2025-8088.md) 🔴 ✅

**名称:** CVE-2025-8088 WinRAR 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，可导致任意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-26  
**POC仓库:** [-CVE-2025-8088](https://github.com/pescada-dev/-CVE-2025-8088)  

---

### [CVE-2019-11043](CVE-2019-11043-a1ex-var1amov_ctf-cve-2019-11043.md) 🔴 ✅

**名称:** CVE-2019-11043-PHP-FPM远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-08-26  
**POC仓库:** [ctf-cve-2019-11043](https://github.com/a1ex-var1amov/ctf-cve-2019-11043)  

---

### [CVE-2025-57773](CVE-2025-57773-B1ack4sh_Blackash-CVE-2025-57773.md) 🔴 ✅

**名称:** CVE-2025-57773 - DataEase DB2 Aspectweaver 反序列化任意文件写入漏洞  
**类型:** 反序列化漏洞/任意文件写入/远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-26  
**POC仓库:** [Blackash-CVE-2025-57773](https://github.com/B1ack4sh/Blackash-CVE-2025-57773)  

---

### [CVE-2025-24893](CVE-2025-24893-ibadovulfat_CVE-2025-24893_HackTheBox-Editor-Writeup.md) 🔴 ✅

**名称:** CVE-2025-24893-XWiki-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-26  
**POC仓库:** [CVE-2025-24893_HackTheBox-Editor-Writeup](https://github.com/ibadovulfat/CVE-2025-24893_HackTheBox-Editor-Writeup)  

---

### [CVE-2019-6693](CVE-2019-6693-gquere_CVE-2019-6693.md) 🟡 ✅

**名称:** CVE-2019-6693 - FortiOS 硬编码密钥信息泄露  
**类型:** 信息泄露  
**风险:** 中危，可能导致敏感信息泄露，包括用户密码、私钥口令、高可用密码等  
**投毒风险:** 0%  
**发现时间:** 2025-08-26  
**POC仓库:** [CVE-2019-6693](https://github.com/gquere/CVE-2019-6693)  

---

### [CVE-2019-6693](CVE-2019-6693-saladandonionrings_cve-2019-6693.md) 🟡 ✅

**名称:** CVE-2019-6693 - FortiOS 硬编码密钥信息泄露  
**类型:** 信息泄露  
**风险:** 中危，可泄露用户密码、私钥密码和高可用密码  
**投毒风险:** 0%  
**发现时间:** 2025-08-26  
**POC仓库:** [cve-2019-6693](https://github.com/saladandonionrings/cve-2019-6693)  

---

### [CVE-2019-6693](CVE-2019-6693-Real4XoR_cve-2019-6693.md) 🟡 ✅

**名称:** CVE-2019-6693-FortiOS-硬编码密钥信息泄露  
**类型:** 信息泄露  
**风险:** 中危，可泄露用户密码、私钥密码和高可用密码  
**投毒风险:** 0%  
**发现时间:** 2025-08-26  
**POC仓库:** [cve-2019-6693](https://github.com/Real4XoR/cve-2019-6693)  

---

### [CVE-2025-8088](CVE-2025-8088-DeepBlue-dot_CVE-2025-8088-WinRAR-Startup-PoC.md) 🔴 ✅

**名称:** CVE-2025-8088 WinRAR 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-26  
**POC仓库:** [CVE-2025-8088-WinRAR-Startup-PoC](https://github.com/DeepBlue-dot/CVE-2025-8088-WinRAR-Startup-PoC)  

---

### [CVE-2024-0762](CVE-2024-0762-tadash10_Detect-CVE-2024-0762.md) 🔴 ✅

**名称:** CVE-2024-0762 - Phoenix SecureCore UEFI 缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-08-26  
**POC仓库:** [Detect-CVE-2024-0762](https://github.com/tadash10/Detect-CVE-2024-0762)  

---

### [CVE-2024-0762](CVE-2024-0762-abandon1337_CVE-2024-0762.md) 🔴 ✅

**名称:** CVE-2024-0762-Phoenix SecureCore-缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致任意代码执行，系统崩溃，或者安装Bootkit。  
**投毒风险:** 0%  
**发现时间:** 2025-08-26  
**POC仓库:** [CVE-2024-0762](https://github.com/abandon1337/CVE-2024-0762)  

---

### [CVE-2025-34030](CVE-2025-34030-HackerTyperAbuser_CVE-2025-34030-PoC.md) 🔴 ✅

**名称:** CVE-2025-34030-sar2html-OS命令注入  
**类型:** OS命令注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-08-26  
**POC仓库:** [CVE-2025-34030-PoC](https://github.com/HackerTyperAbuser/CVE-2025-34030-PoC)  

---

### [CVE-2017-8481](CVE-2017-8481-TamatahYT_CVE-2017-8481.md) 🟡 ✅

**名称:** CVE-2017-8481 Windows Kernel Information Disclosure Vulnerability  
**类型:** 信息泄露  
**风险:** 中危，可能泄露敏感内核信息  
**投毒风险:** 0%  
**发现时间:** 2025-08-25  
**POC仓库:** [CVE-2017-8481](https://github.com/TamatahYT/CVE-2017-8481)  

---

### [CVE-2023-6275](CVE-2023-6275-erickfernandox_CVE-2023-6275.md) 🟡 ✅

**名称:** CVE-2023-6275 - TOTVS Fluig Platform 反射型XSS漏洞  
**类型:** 反射型跨站脚本 (Reflected XSS)  
**风险:** 中危，可能导致用户信息泄露、会话劫持、恶意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-25  
**POC仓库:** [CVE-2023-6275](https://github.com/erickfernandox/CVE-2023-6275)  

---

### [CVE-2023-6275](CVE-2023-6275-LelioCosta_FLUIG-Vulnerabilidade-CVE-2023-6275.md) 🟡 ✅

**名称:** CVE-2023-6275 - TOTVS Fluig Platform XSS Vulnerability  
**类型:** 跨站脚本 (XSS)  
**风险:** 中危，CVSS v3.1 评分 6.1，可能导致信息泄露和篡改  
**投毒风险:** 0%  
**发现时间:** 2025-08-25  
**POC仓库:** [FLUIG-Vulnerabilidade-CVE-2023-6275](https://github.com/LelioCosta/FLUIG-Vulnerabilidade-CVE-2023-6275)  

---

### [CVE-2025-48384](CVE-2025-48384-eliox01_CVE-2025-48384.md) 🔴 ✅

**名称:** CVE-2025-48384-Git-任意代码执行  
**类型:** 任意代码执行  
**风险:** 高危，可能导致远程代码执行和系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-25  
**POC仓库:** [CVE-2025-48384](https://github.com/eliox01/CVE-2025-48384)  

---

### [CVE-2017-5638](CVE-2017-5638-iampetru_PoC-CVE-2017-5638.md) 🔴 ✅

**名称:** CVE-2017-5638 - Apache Struts2 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-25  
**POC仓库:** [PoC-CVE-2017-5638](https://github.com/iampetru/PoC-CVE-2017-5638)  

---

### [CVE-2024-4577](CVE-2024-4577-InfoSec-DB_PHPCGIScanner.md) 🔴 ✅

**名称:** CVE-2024-4577 PHP-CGI Argument Injection  
**类型:** 远程代码执行  
**风险:** 高危，可导致远程代码执行和敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-08-25  
**POC仓库:** [PHPCGIScanner](https://github.com/InfoSec-DB/PHPCGIScanner)  

---

### [CVE-2024-4577](CVE-2024-4577-a1ex-var1amov_ctf-cve-2024-4577.md) 🔴 ✅

**名称:** CVE-2024-4577-PHP-CGI参数注入  
**类型:** PHP-CGI参数注入  
**风险:** 高危，可能导致远程代码执行、源码泄露  
**投毒风险:** 10%  
**发现时间:** 2025-08-25  
**POC仓库:** [ctf-cve-2024-4577](https://github.com/a1ex-var1amov/ctf-cve-2024-4577)  

---

### [CVE-2023-21768](CVE-2023-21768-cl4ym0re_cve-2023-21768-compiled.md) 🔴 ✅

**名称:** CVE-2023-21768 - Windows Ancillary Function Driver for WinSock Elevation of Privilege Vulnerability  
**类型:** 权限提升  
**风险:** 高危，本地权限提升到SYSTEM  
**投毒风险:** 10%  
**发现时间:** 2025-08-25  
**POC仓库:** [cve-2023-21768-compiled](https://github.com/cl4ym0re/cve-2023-21768-compiled)  

---

### [CVE-2023-21768](CVE-2023-21768-SamuelTulach_nullmap.md) 🔴 ✅

**名称:** CVE-2023-21768-Windows AFD驱动提权漏洞  
**类型:** 本地提权  
**风险:** 高危，允许低权限用户提升到SYSTEM权限  
**投毒风险:** 30%  
**发现时间:** 2025-08-25  
**POC仓库:** [nullmap](https://github.com/SamuelTulach/nullmap)  

---

### [CVE-2023-21768](CVE-2023-21768-HKxiaoli_Windows_AFD_LPE_CVE-2023-21768.md) 🔴 ✅

**名称:** CVE-2023-21768 Windows AFD LPE  
**类型:** 本地提权  
**风险:** 高危，允许低权限用户提升到 SYSTEM 权限  
**投毒风险:** 10%  
**发现时间:** 2025-08-25  
**POC仓库:** [Windows_AFD_LPE_CVE-2023-21768](https://github.com/HKxiaoli/Windows_AFD_LPE_CVE-2023-21768)  

---

### [CVE-2023-21768](CVE-2023-21768-AiK1d_CVE-2023-21768-POC.md) 🔴 ✅

**名称:** CVE-2023-21768 Windows Ancillary Function Driver for WinSock Elevation of Privilege Vulnerability  
**类型:** 权限提升  
**风险:** 高危，可导致本地权限提升至SYSTEM  
**投毒风险:** 10%  
**发现时间:** 2025-08-25  
**POC仓库:** [CVE-2023-21768-POC](https://github.com/AiK1d/CVE-2023-21768-POC)  

---

### [CVE-2023-21768](CVE-2023-21768-h1bAna_CVE-2023-21768.md) 🔴 ✅

**名称:** CVE-2023-21768 Windows Ancillary Function Driver for WinSock Elevation of Privilege Vulnerability  
**类型:** 权限提升  
**风险:** 高危，可导致本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-08-25  
**POC仓库:** [CVE-2023-21768](https://github.com/h1bAna/CVE-2023-21768)  

---

### [CVE-2023-21768](CVE-2023-21768-zoemurmure_CVE-2023-21768-AFD-for-WinSock-EoP-exploit.md) 🔴 ✅

**名称:** CVE-2023-21768-Windows Ancillary Function Driver for WinSock Elevation of Privilege Vulnerability  
**类型:** 权限提升  
**风险:** 高危，攻击者可以利用此漏洞以提升的权限执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-08-25  
**POC仓库:** [CVE-2023-21768-AFD-for-WinSock-EoP-exploit](https://github.com/zoemurmure/CVE-2023-21768-AFD-for-WinSock-EoP-exploit)  

---

### [CVE-2023-21768](CVE-2023-21768-chompie1337_Windows_LPE_AFD_CVE-2023-21768.md) 🔴 ✅

**名称:** CVE-2023-21768 Windows AFD LPE  
**类型:** 本地提权  
**风险:** 高危，允许本地用户提升权限至SYSTEM  
**投毒风险:** 10%  
**发现时间:** 2025-08-25  
**POC仓库:** [Windows_LPE_AFD_CVE-2023-21768](https://github.com/chompie1337/Windows_LPE_AFD_CVE-2023-21768)  

---

### [CVE-2023-21768](CVE-2023-21768-Malwareman007_CVE-2023-21768.md) 🔴 ✅

**名称:** CVE-2023-21768  
**类型:** 权限提升  
**风险:** 高危，本地权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-08-25  
**POC仓库:** [CVE-2023-21768](https://github.com/Malwareman007/CVE-2023-21768)  

---

### [CVE-2023-21768](CVE-2023-21768-Rosayxy_Recreate-cve-2023-21768.md) 🔴 ✅

**名称:** CVE-2023-21768 Windows AFD Elevation of Privilege  
**类型:** 权限提升  
**风险:** 高危，可导致本地权限提升至SYSTEM  
**投毒风险:** 10%  
**发现时间:** 2025-08-25  
**POC仓库:** [Recreate-cve-2023-21768](https://github.com/Rosayxy/Recreate-cve-2023-21768)  

---

### [CVE-2023-21768](CVE-2023-21768-ldrx30_CVE-2023-21768.md) 🔴 ✅

**名称:** CVE-2023-21768-Windows Ancillary Function Driver for WinSock Elevation of Privilege  
**类型:** 权限提升  
**风险:** 高危，允许本地用户以SYSTEM权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-25  
**POC仓库:** [CVE-2023-21768](https://github.com/ldrx30/CVE-2023-21768)  

---

### [CVE-2023-21768](CVE-2023-21768-xboxoneresearch_CVE-2023-21768-dotnet.md) 🔴 ✅

**名称:** CVE-2023-21768 - Windows Ancillary Function Driver for WinSock Elevation of Privilege  
**类型:** 特权提升 (Elevation of Privilege)  
**风险:** 高危，本地特权提升  
**投毒风险:** 5%  
**发现时间:** 2025-08-25  
**POC仓库:** [CVE-2023-21768-dotnet](https://github.com/xboxoneresearch/CVE-2023-21768-dotnet)  

---

### [CVE-2023-21768](CVE-2023-21768-IlanDudnik_CVE-2023-21768.md) 🔴 ✅

**名称:** CVE-2023-21768 Windows Ancillary Function Driver for WinSock Elevation of Privilege Vulnerability  
**类型:** 特权提升  
**风险:** 高危，可使低权限用户提升至SYSTEM权限  
**投毒风险:** 10%  
**发现时间:** 2025-08-25  
**POC仓库:** [CVE-2023-21768](https://github.com/IlanDudnik/CVE-2023-21768)  

---

### [CVE-2023-21768](CVE-2023-21768-radoi-teodor_CVE-2023-21768.md) 🔴 ✅

**名称:** CVE-2023-21768-Windows AFD LPE  
**类型:** 权限提升 (LPE)  
**风险:** 高危，本地权限提升至SYSTEM  
**投毒风险:** 30%  
**发现时间:** 2025-08-25  
**POC仓库:** [CVE-2023-21768](https://github.com/radoi-teodor/CVE-2023-21768)  

---

### [CVE-2025-38001](CVE-2025-38001-khoatran107_cve-2025-38001.md) 🔴 ✅

**名称:** CVE-2025-38001-Linux Kernel-HFSC Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可能导致内核崩溃、权限提升甚至远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-25  
**POC仓库:** [cve-2025-38001](https://github.com/khoatran107/cve-2025-38001)  

---

### [CVE-2024-4367](CVE-2024-4367-1337rokudenashi_Odoo_PDFjs_CVE-2024-4367.pdf.md) 🔴 ✅

**名称:** CVE-2024-4367-Firefox-PDF.js-JavaScript执行  
**类型:** JavaScript执行  
**风险:** 高危，可能导致跨站脚本攻击（XSS）和信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-08-25  
**POC仓库:** [Odoo_PDFjs_CVE-2024-4367.pdf](https://github.com/1337rokudenashi/Odoo_PDFjs_CVE-2024-4367.pdf)  

---

### [CVE-2024-49369](CVE-2024-49369-Quantum-Sicarius_CVE-2024-49369.md)  ✅

**名称:** CVE-2024-49369-Icinga2-TLS证书验证绕过  
**类型:** TLS证书验证绕过  
**风险:** 严重，可能导致远程代码执行和敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-08-25  
**POC仓库:** [CVE-2024-49369](https://github.com/Quantum-Sicarius/CVE-2024-49369)  

---

### [CVE-2025-9074](CVE-2025-9074-zenzue_CVE-2025-9074.md) 🔴 ✅

**名称:** CVE-2025-9074 - Docker Desktop Container到Host写权限提升  
**类型:** 权限提升  
**风险:** 高危，允许容器逃逸并完全控制宿主机  
**投毒风险:** 5%  
**发现时间:** 2025-08-25  
**POC仓库:** [CVE-2025-9074](https://github.com/zenzue/CVE-2025-9074)  

---

### [CVE-2025-5419](CVE-2025-5419-mistymntncop_CVE-2025-5419.md) 🔴 ✅

**名称:** CVE-2025-5419-Google Chrome-V8引擎越界读写  
**类型:** 越界读写  
**风险:** 高危，可能导致堆损坏、信息泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-25  
**POC仓库:** [CVE-2025-5419](https://github.com/mistymntncop/CVE-2025-5419)  

---

### [CVE-2024-32019](CVE-2024-32019-x0da6h_POC-for-CVE-2024-32019.md) 🔴 ✅

**名称:** CVE-2024-32019-netdata-本地提权  
**类型:** 本地提权  
**风险:** 高危，攻击者可利用此漏洞获取root权限。  
**投毒风险:** 0%  
**发现时间:** 2025-08-25  
**POC仓库:** [POC-for-CVE-2024-32019](https://github.com/x0da6h/POC-for-CVE-2024-32019)  

---

### [CVE-2022-41544](CVE-2022-41544-nopgadget_CVE-2022-41544.md) 🔴 ✅

**名称:** CVE-2022-41544 - GetSimple CMS 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，攻击者可以在目标系统上执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-08-25  
**POC仓库:** [CVE-2022-41544](https://github.com/nopgadget/CVE-2022-41544)  

---

### [CVE-2022-29622](CVE-2022-29622-keymandll_CVE-2022-29622.md) 🟡 ✅

**名称:** CVE-2022-29622-formidable-任意文件上传  
**类型:** 任意文件上传  
**风险:** 中危（取决于应用场景和配置）  
**投毒风险:** 10%  
**发现时间:** 2025-08-24  
**POC仓库:** [CVE-2022-29622](https://github.com/keymandll/CVE-2022-29622)  

---

### [CVE-2025-43300](CVE-2025-43300-hunters-sec_CVE-2025-43300.md) 🔴 ✅

**名称:** CVE-2025-43300: iOS/macOS DNG图像处理内存损坏  
**类型:** 内存损坏（越界写入）  
**风险:** 高危，可导致应用程序崩溃或潜在的代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-24  
**POC仓库:** [CVE-2025-43300](https://github.com/hunters-sec/CVE-2025-43300)  

---

### [CVE-2024-4956](CVE-2024-4956-Buff3st-0v3rfl0w_CVE-2024-4956.md) 🔴 ✅

**名称:** CVE-2024-4956-Sonatype Nexus Repository 3-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可读取系统文件  
**投毒风险:** 5%  
**发现时间:** 2025-08-24  
**POC仓库:** [CVE-2024-4956](https://github.com/Buff3st-0v3rfl0w/CVE-2024-4956)  

---

### [CVE-2025-49113](CVE-2025-49113-Zwique_CVE-2025-49113.md) 🔴 ✅

**名称:** CVE-2025-49113 - Roundcube Webmail 远程代码执行  
**类型:** PHP 对象反序列化  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-08-24  
**POC仓库:** [CVE-2025-49113](https://github.com/Zwique/CVE-2025-49113)  

---

### [CVE-2025-8671](CVE-2025-8671-abiyeenzo_CVE-2025-8671.md) 🔴 ✅

**名称:** CVE-2025-8671 - HTTP/2 MadeYouReset DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，导致服务器资源耗尽，服务不可用  
**投毒风险:** 5%  
**发现时间:** 2025-08-23  
**POC仓库:** [CVE-2025-8671](https://github.com/abiyeenzo/CVE-2025-8671)  

---

### [CVE-2020-28458](CVE-2020-28458-fazilbaig1_CVE-2020-28458.md) 🟡 ✅

**名称:** CVE-2020-28458-datatables.net-Prototype Pollution  
**类型:** Prototype Pollution  
**风险:** 中危，可能导致拒绝服务和客户端代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-23  
**POC仓库:** [CVE-2020-28458](https://github.com/fazilbaig1/CVE-2020-28458)  

---

### [CVE-2025-6713](CVE-2025-6713-c137req_CVE-2025-6713.md) 🔴 ✅

**名称:** CVE-2025-6713-MongoDB-权限绕过  
**类型:** 权限绕过  
**风险:** 高危，可能导致未授权的数据访问  
**投毒风险:** 5%  
**发现时间:** 2025-08-23  
**POC仓库:** [CVE-2025-6713](https://github.com/c137req/CVE-2025-6713)  

---

### [CVE-2015-3306](CVE-2015-3306-donmedfor_CVE-2015-3306.md) 🔴 ✅

**名称:** CVE-2015-3306 ProFTPD mod_copy 模块任意文件读写漏洞  
**类型:** 任意文件读写  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-23  
**POC仓库:** [CVE-2015-3306](https://github.com/donmedfor/CVE-2015-3306)  

---

### [CVE-2025-43960](CVE-2025-43960-far00t01_CVE-2025-43960.md) 🔴 ✅

**名称:** CVE-2025-43960 - Adminer PHP Object Injection DoS  
**类型:** PHP 对象注入  
**风险:** 高危，可能导致拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-08-23  
**POC仓库:** [CVE-2025-43960](https://github.com/far00t01/CVE-2025-43960)  

---

### [CVE-2020-26217](CVE-2020-26217-shoucheng3_x-stream__xstream_CVE-2020-26217_1-4-14-java7.md) 🔴 ✅

**名称:** CVE-2020-26217-XStream-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许远程攻击者执行任意shell命令  
**投毒风险:** 1%  
**发现时间:** 2025-08-23  
**POC仓库:** [x-stream__xstream_CVE-2020-26217_1-4-14-java7](https://github.com/shoucheng3/x-stream__xstream_CVE-2020-26217_1-4-14-java7)  

---

### [CVE-2025-24813](CVE-2025-24813-threadpoolx_CVE-2025-24813-Remote-Code-Execution-in-Apache-Tomcat.md) 🔴 ✅

**名称:** CVE-2025-24813-Apache Tomcat Path Equivalence RCE  
**类型:** 路径等价性漏洞/远程代码执行  
**风险:** 高危，可能导致远程代码执行和信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-08-23  
**POC仓库:** [CVE-2025-24813-Remote-Code-Execution-in-Apache-Tomcat](https://github.com/threadpoolx/CVE-2025-24813-Remote-Code-Execution-in-Apache-Tomcat)  

---

### [CVE-2025-30406](CVE-2025-30406-threadpoolx_CVE-2025-30406-CentreStack-Triofox-Deserialization-RCE.md) 🔴 ✅

**名称:** CVE-2025-30406-CentreStack/Triofox-反序列化RCE  
**类型:** 反序列化RCE  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-23  
**POC仓库:** [CVE-2025-30406-CentreStack-Triofox-Deserialization-RCE](https://github.com/threadpoolx/CVE-2025-30406-CentreStack-Triofox-Deserialization-RCE)  

---

### [CVE-2021-21345](CVE-2021-21345-shoucheng3_x-stream__xstream_CVE-2021-21345_1-4-15.md) 🔴 ✅

**名称:** CVE-2021-21345-XStream-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-23  
**POC仓库:** [x-stream__xstream_CVE-2021-21345_1-4-15](https://github.com/shoucheng3/x-stream__xstream_CVE-2021-21345_1-4-15)  

---

### [CVE-2025-9074](CVE-2025-9074-XRayZen_cve-2025-9074-poc.md) 🔴 ✅

**名称:** CVE-2025-9074 - Docker Desktop API未授权访问  
**类型:** API未授权访问  
**风险:** 高危，可能导致主机文件系统读写、敏感信息泄露、系统配置篡改、恶意软件植入、横向渗透和权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-08-23  
**POC仓库:** [cve-2025-9074-poc](https://github.com/XRayZen/cve-2025-9074-poc)  

---

### [CVE-2025-52970](CVE-2025-52970-Hex00-0x4_Authentication-Bypass-in-FortiWeb-CVE-2025-52970-.md) 🔴 ✅

**名称:** CVE-2025-52970-FortiWeb-权限提升  
**类型:** 权限提升  
**风险:** 高危，可能导致完全控制设备  
**投毒风险:** 0%  
**发现时间:** 2025-08-23  
**POC仓库:** [Authentication-Bypass-in-FortiWeb-CVE-2025-52970-](https://github.com/Hex00-0x4/Authentication-Bypass-in-FortiWeb-CVE-2025-52970-)  

---

### [CVE-2025-52970](CVE-2025-52970-Hex00-0x4_FortiWeb-CVE-2025-52970-Authentication-Bypass.md) 🔴 ✅

**名称:** CVE-2025-52970-FortiWeb-权限提升  
**类型:** 权限提升  
**风险:** 高危，允许未授权远程攻击者获得管理员权限  
**投毒风险:** 0%  
**发现时间:** 2025-08-23  
**POC仓库:** [FortiWeb-CVE-2025-52970-Authentication-Bypass](https://github.com/Hex00-0x4/FortiWeb-CVE-2025-52970-Authentication-Bypass)  

---

### [CVE-2025-24085](CVE-2025-24085-JGoyd_glass-cage-ios18-cve-2025-24085-cve-2025-24201.md) 🔴 ✅

**名称:** CVE-2025-24085 - Core Media Privilege Escalation  
**类型:** Use-After-Free Privilege Escalation  
**风险:** 高危，可导致提权至root，完全控制设备，数据窃取，甚至设备变砖  
**投毒风险:** 10%  
**发现时间:** 2025-08-23  
**POC仓库:** [glass-cage-ios18-cve-2025-24085-cve-2025-24201](https://github.com/JGoyd/glass-cage-ios18-cve-2025-24085-cve-2025-24201)  

---

### [CVE-2025-33053](CVE-2025-33053-4n4s4zi_CVE-2025-33053_PoC.md) 🔴 ✅

**名称:** CVE-2025-33053-WebDAV远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-23  
**POC仓库:** [CVE-2025-33053_PoC](https://github.com/4n4s4zi/CVE-2025-33053_PoC)  

---

### [CVE-2020-36847](CVE-2020-36847-137f_PoC-CVE-2020-36847-WordPress-Plugin-4.2.2-RCE.md) 🔴 ✅

**名称:** CVE-2020-36847-Simple File List-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-23  
**POC仓库:** [PoC-CVE-2020-36847-WordPress-Plugin-4.2.2-RCE](https://github.com/137f/PoC-CVE-2020-36847-WordPress-Plugin-4.2.2-RCE)  

---

### [CVE-2024-6536](CVE-2024-6536-apena-ba_CVE-2024-6536.md) 🟡 ✅

**名称:** CVE-2024-6536 - Zephyr Project Manager 插件 Editor+ XSS  
**类型:** 存储型跨站脚本 (Stored XSS)  
**风险:** 中危，可能导致账户劫持、恶意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-22  
**POC仓库:** [CVE-2024-6536](https://github.com/apena-ba/CVE-2024-6536)  

---

### [CVE-2019-18935](CVE-2019-18935-0xsharz_telerik-scanner-CVE-2019-18935.md) 🔴 ✅

**名称:** CVE-2019-18935 - Telerik UI for ASP.NET AJAX 反序列化漏洞  
**类型:** .NET 反序列化  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-22  
**POC仓库:** [telerik-scanner-CVE-2019-18935](https://github.com/0xsharz/telerik-scanner-CVE-2019-18935)  

---

### [CVE-2025-55575](CVE-2025-55575-Aether-0_CVE-2025-55575.md) 🔴 ✅

**名称:** CVE-2025-55575-SMM Panel-时间盲注  
**类型:** 时间盲注  
**风险:** 高危，可能导致数据泄露或权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-08-22  
**POC仓库:** [CVE-2025-55575](https://github.com/Aether-0/CVE-2025-55575)  

---

### [CVE-2025-53632](CVE-2025-53632-pandatix_CVE-2025-53632.md) 🔴 ✅

**名称:** CVE-2025-53632-Chall-Manager-Zip Slip  
**类型:** 路径遍历 (Zip Slip)  
**风险:** 高危，可能导致任意文件写入和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-22  
**POC仓库:** [CVE-2025-53632](https://github.com/pandatix/CVE-2025-53632)  

---

### [CVE-2024-37054](CVE-2024-37054-NiteeshPujari_CVE-2024-37054-MLflow-RCE.md) 🔴 ✅

**名称:** CVE-2024-37054-MLflow-反序列化漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-22  
**POC仓库:** [CVE-2024-37054-MLflow-RCE](https://github.com/NiteeshPujari/CVE-2024-37054-MLflow-RCE)  

---

### [CVE-2025-55230](CVE-2025-55230-barbaraeivyu_CVE-2025-55230-Exploit.md) 🔴 ✅

**名称:** CVE-2025-55230 Windows MBT Transport Driver Elevation of Privilege Vulnerability  
**类型:** 权限提升  
**风险:** 高危，本地权限提升到SYSTEM  
**投毒风险:** 10%  
**发现时间:** 2025-08-22  
**POC仓库:** [CVE-2025-55230-Exploit](https://github.com/barbaraeivyu/CVE-2025-55230-Exploit)  

---

### [CVE-2025-43300](CVE-2025-43300-XiaomingX_CVE-2025-43300-exp.md) 🔴 

**名称:** CVE-2025-43300-ImageIO-内存损坏  
**类型:** 内存损坏（Out-of-bounds Write）  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 99%  
**发现时间:** 2025-08-22  
**POC仓库:** [CVE-2025-43300-exp](https://github.com/XiaomingX/CVE-2025-43300-exp)  

---

### [CVE-2025-27519](CVE-2025-27519-Diabl0xE_CVE-2025-27519.md) 🔴 ✅

**名称:** CVE-2025-27519-Cognita-任意文件写入导致RCE  
**类型:** 任意文件写入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-22  
**POC仓库:** [CVE-2025-27519](https://github.com/Diabl0xE/CVE-2025-27519)  

---

### [CVE-2025-24893](CVE-2025-24893-x0da6h_EXP-for-CVE-2025-24893.md) 🔴 ✅

**名称:** CVE-2025-24893-XWiki-RCE  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-08-22  
**POC仓库:** [EXP-for-CVE-2025-24893](https://github.com/x0da6h/EXP-for-CVE-2025-24893)  

---

### [CVE-2024-4367](CVE-2024-4367-m0d0ri205_PDFJS.md) 🔴 ✅

**名称:** CVE-2024-4367-Firefox-PDF.js-Arbitrary-JavaScript-Execution  
**类型:** 任意JavaScript执行  
**风险:** 高危，可能导致跨站脚本攻击 (XSS) 和敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-08-22  
**POC仓库:** [PDFJS](https://github.com/m0d0ri205/PDFJS)  

---

### [CVE-2024-4367](CVE-2024-4367-0xr2r_CVE-2024-4367.md) 🔴 ✅

**名称:** CVE-2024-4367-PDF.js-任意JavaScript执行  
**类型:** 任意JavaScript执行  
**风险:** 高危，可能导致跨站脚本攻击（XSS）和信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-08-22  
**POC仓库:** [CVE-2024-4367](https://github.com/0xr2r/CVE-2024-4367)  

---

### [CVE-2022-4244](CVE-2022-4244-shoucheng3_codehaus-plexus__plexus-utils_CVE-2022-4244_3-0-23.md) 🔴 ✅

**名称:** CVE-2022-4244 - Codehaus-plexus Directory Traversal  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-08-22  
**POC仓库:** [codehaus-plexus__plexus-utils_CVE-2022-4244_3-0-23](https://github.com/shoucheng3/codehaus-plexus__plexus-utils_CVE-2022-4244_3-0-23)  

---

### [CVE-2025-1337](CVE-2025-1337-ada-z3r0_CVE-2025-1337-PoC.md) 🟡 

**名称:** CVE-2025-1337-Eastnets PaymentSafe-XSS  
**类型:** 跨站脚本 (XSS)  
**风险:** 中危，可能导致会话劫持，页面重定向和恶意脚本执行  
**投毒风险:** 95%  
**发现时间:** 2025-08-22  
**POC仓库:** [CVE-2025-1337-PoC](https://github.com/ada-z3r0/CVE-2025-1337-PoC)  

---

### [CVE-2015-8351](CVE-2015-8351-G01d3nW01f_CVE-2015-8351.md) 🔴 ✅

**名称:** CVE-2015-8351-Gwolle Guestbook-RFI  
**类型:** 远程文件包含(RFI)  
**风险:** 高危，允许远程攻击者执行任意PHP代码  
**投毒风险:** 5%  
**发现时间:** 2025-08-21  
**POC仓库:** [CVE-2015-8351](https://github.com/G01d3nW01f/CVE-2015-8351)  

---

### [CVE-2015-8351](CVE-2015-8351-G4sp4rCS_exploit-CVE-2015-8351.md) 🔴 ✅

**名称:** CVE-2015-8351 - Gwolle Guestbook WordPress Plugin RFI  
**类型:** 远程文件包含 (RFI)  
**风险:** 高危，可能导致远程代码执行和服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-08-21  
**POC仓库:** [exploit-CVE-2015-8351](https://github.com/G4sp4rCS/exploit-CVE-2015-8351)  

---

### [CVE-2015-8351](CVE-2015-8351-Philip-Otter_CVE-2015-8351_Otter_Remix.md) 🔴 ✅

**名称:** CVE-2015-8351-Gwolle Guestbook-RFI  
**类型:** 远程文件包含 (RFI)  
**风险:** 高危，允许远程攻击者执行任意PHP代码。  
**投毒风险:** 0%  
**发现时间:** 2025-08-21  
**POC仓库:** [CVE-2015-8351_Otter_Remix](https://github.com/Philip-Otter/CVE-2015-8351_Otter_Remix)  

---

### [CVE-2025-8671](CVE-2025-8671-mateusm1403_PoC-CVE-2025-8671-MadeYouReset-HTTP-2.md) 🔴 ✅

**名称:** CVE-2025-8671-HTTP/2 MadeYouReset  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致服务器资源耗尽，服务不可用  
**投毒风险:** 0%  
**发现时间:** 2025-08-21  
**POC仓库:** [PoC-CVE-2025-8671-MadeYouReset-HTTP-2](https://github.com/mateusm1403/PoC-CVE-2025-8671-MadeYouReset-HTTP-2)  

---

### [CVE-2025-55287](CVE-2025-55287-Eternalvalhalla_CVE-2025-55287-POC.md) 🔴 ✅

**名称:** CVE-2025-55287-Genealogy-Stored XSS  
**类型:** Stored XSS  
**风险:** 高危，可能导致会话劫持、数据窃取和UI操纵  
**投毒风险:** 10%  
**发现时间:** 2025-08-21  
**POC仓库:** [CVE-2025-55287-POC](https://github.com/Eternalvalhalla/CVE-2025-55287-POC)  

---

### [CVE-2025-9132](CVE-2025-9132-barbaraeivyu_CVE-2025-9132.md) 🔴 ✅

**名称:** CVE-2025-9132-Google Chrome V8 Out-of-Bounds Write  
**类型:** Out-of-Bounds Write  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-21  
**POC仓库:** [CVE-2025-9132](https://github.com/barbaraeivyu/CVE-2025-9132)  

---

### [CVE-2025-43300](CVE-2025-43300-h4xnz_CVE-2025-43300.md) 🔴 

**名称:** CVE-2025-43300-ImageIO框架-越界写入  
**类型:** 越界写入  
**风险:** 高危，可能导致内存损坏、代码执行或系统崩溃  
**投毒风险:** 85%  
**发现时间:** 2025-08-21  
**POC仓库:** [CVE-2025-43300](https://github.com/h4xnz/CVE-2025-43300)  

---

### [CVE-2023-41892](CVE-2023-41892-diegaccio_Craft-CMS-Exploit.md) 🔴 ✅

**名称:** CVE-2023-41892-Craft CMS-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未授权远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-08-21  
**POC仓库:** [Craft-CMS-Exploit](https://github.com/diegaccio/Craft-CMS-Exploit)  

---

### [CVE-2023-41892](CVE-2023-41892-acesoyeo_CVE-2023-41892.md) 🔴 ✅

**名称:** CVE-2023-41892 - Craft CMS Remote Code Execution  
**类型:** Remote Code Execution  
**风险:** Critical，可能导致完全控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-08-21  
**POC仓库:** [CVE-2023-41892](https://github.com/acesoyeo/CVE-2023-41892)  

---

### [CVE-2022-32532](CVE-2022-32532-my0113_shiro-cve-2022-32532.md) 🔴 ✅

**名称:** CVE-2022-32532-Apache Shiro-认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-08-21  
**POC仓库:** [shiro-cve-2022-32532](https://github.com/my0113/shiro-cve-2022-32532)  

---

### [CVE-2025-25256](CVE-2025-25256-JMS-Security_CVE-2025-25256-PoC.md)  ✅

**名称:** CVE-2025-25256 - FortiSIEM 命令注入  
**类型:** OS 命令注入  
**风险:** 严重，未经身份验证的远程代码执行  
**投毒风险:** 20%  
**发现时间:** 2025-08-21  
**POC仓库:** [CVE-2025-25256-PoC](https://github.com/JMS-Security/CVE-2025-25256-PoC)  

---

### [CVE-2023-41892](CVE-2023-41892-zaenhaxor_CVE-2023-41892.md)  ✅

**名称:** CVE-2023-41892 - Craft CMS 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，允许未经身份验证的远程攻击者执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-08-21  
**POC仓库:** [CVE-2023-41892](https://github.com/zaenhaxor/CVE-2023-41892)  

---

### [CVE-2023-41892](CVE-2023-41892-0xfalafel_CraftCMS_CVE-2023-41892.md) 🔴 ✅

**名称:** CVE-2023-41892 - Craft CMS Remote Code Execution  
**类型:** Remote Code Execution (RCE)  
**风险:** Critical，未经身份验证的远程代码执行，可能导致完全控制服务器  
**投毒风险:** 5%  
**发现时间:** 2025-08-21  
**POC仓库:** [CraftCMS_CVE-2023-41892](https://github.com/0xfalafel/CraftCMS_CVE-2023-41892)  

---

### [CVE-2023-41892](CVE-2023-41892-CERTologists_HTTP-Request-for-PHP-object-injection-attack-on-CVE-2023-41892.md) 🔴 ✅

**名称:** CVE-2023-41892-Craft CMS-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-21  
**POC仓库:** [HTTP-Request-for-PHP-object-injection-attack-on-CVE-2023-41892](https://github.com/CERTologists/HTTP-Request-for-PHP-object-injection-attack-on-CVE-2023-41892)  

---

### [CVE-2023-41892](CVE-2023-41892-user01-1_CVE-2023-41892_poc.md)  ✅

**名称:** CVE-2023-41892 Craft CMS 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致完全控制服务器  
**投毒风险:** 0%  
**发现时间:** 2025-08-21  
**POC仓库:** [CVE-2023-41892_poc](https://github.com/user01-1/CVE-2023-41892_poc)  

---

### [CVE-2025-8088](CVE-2025-8088-amel-62_WinRAR-CVE-2025-8088-PoC-RAR.md) 🔴 ✅

**名称:** CVE-2025-8088 WinRAR 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，允许攻击者通过构造恶意压缩文件执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-21  
**POC仓库:** [WinRAR-CVE-2025-8088-PoC-RAR](https://github.com/amel-62/WinRAR-CVE-2025-8088-PoC-RAR)  

---

### [CVE-2025-8088](CVE-2025-8088-ghostn4444_CVE-2025-8088.md) 🔴 ✅

**名称:** CVE-2025-8088-WinRAR-Path Traversal  
**类型:** 路径遍历  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-21  
**POC仓库:** [CVE-2025-8088](https://github.com/ghostn4444/CVE-2025-8088)  

---

### [CVE-2022-32532](CVE-2022-32532-Lay0us_CVE-2022-32532.md) 🔴 ✅

**名称:** CVE-2022-32532-Apache Shiro 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权访问  
**投毒风险:** 0%  
**发现时间:** 2025-08-21  
**POC仓库:** [CVE-2022-32532](https://github.com/Lay0us/CVE-2022-32532)  

---

### [CVE-2025-22235](CVE-2025-22235-idealzh_cve-2025-22235-demo.md) 🟡 ✅

**名称:** CVE-2025-22235 Spring Boot EndpointRequest.to() 认证绕过  
**类型:** 认证绕过  
**风险:** 中危，可能导致未授权访问敏感信息  
**投毒风险:** 0%  
**发现时间:** 2025-08-21  
**POC仓库:** [cve-2025-22235-demo](https://github.com/idealzh/cve-2025-22235-demo)  

---

### [CVE-2023-35078](CVE-2023-35078-vchan-in_CVE-2023-35078-Exploit-POC.md) 🔴 

**名称:** CVE-2023-35078-Ivanti EPMM-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未经授权的API访问，数据泄露和远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-08-21  
**POC仓库:** [CVE-2023-35078-Exploit-POC](https://github.com/vchan-in/CVE-2023-35078-Exploit-POC)  

---

### [CVE-2023-35078](CVE-2023-35078-lager1_CVE-2023-35078.md) 🔴 ✅

**名称:** CVE-2023-35078 - Ivanti EPMM 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，未经授权访问受限功能或资源，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-21  
**POC仓库:** [CVE-2023-35078](https://github.com/lager1/CVE-2023-35078)  

---

### [CVE-2023-35078](CVE-2023-35078-synfinner_CVE-2023-35078.md) 🔴 ✅

**名称:** CVE-2023-35078-Ivanti EPMM-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未经授权的API访问，潜在的数据泄露和控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-21  
**POC仓库:** [CVE-2023-35078](https://github.com/synfinner/CVE-2023-35078)  

---

### [CVE-2023-35078](CVE-2023-35078-emanueldosreis_nmap-CVE-2023-35078-Exploit.md) 🔴 ✅

**名称:** CVE-2023-35078-Ivanti EPMM-认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未授权访问、数据泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-21  
**POC仓库:** [nmap-CVE-2023-35078-Exploit](https://github.com/emanueldosreis/nmap-CVE-2023-35078-Exploit)  

---

### [CVE-2023-35078](CVE-2023-35078-raytheon0x21_CVE-2023-35078.md)  ✅

**名称:** CVE-2023-35078-Ivanti EPMM 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 严重，允许未经授权的远程API访问，可能导致数据泄露和完全系统控制  
**投毒风险:** 5%  
**发现时间:** 2025-08-21  
**POC仓库:** [CVE-2023-35078](https://github.com/raytheon0x21/CVE-2023-35078)  

---

### [CVE-2023-35078](CVE-2023-35078-Blue-number_CVE-2023-35078.md) 🔴 ✅

**名称:** CVE-2023-35078-Ivanti EPMM-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未经授权的访问，数据泄露和远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-08-21  
**POC仓库:** [CVE-2023-35078](https://github.com/Blue-number/CVE-2023-35078)  

---

### [CVE-2023-35078](CVE-2023-35078-0nsec_CVE-2023-35078.md)  ✅

**名称:** CVE-2023-35078 - Ivanti EPMM 远程未授权API访问  
**类型:** 身份验证绕过  
**风险:** 严重，可能导致敏感数据泄露和完全系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-21  
**POC仓库:** [CVE-2023-35078](https://github.com/0nsec/CVE-2023-35078)  

---

### [CVE-2024-3721](CVE-2024-3721-qalvynn_CVE-2024-3721---POC.md) 🔴 ✅

**名称:** CVE-2024-3721-TBK DVR-4104/DVR-4216-OS Command Injection  
**类型:** OS Command Injection  
**风险:** 高危，可能导致设备被完全控制，加入僵尸网络  
**投毒风险:** 5%  
**发现时间:** 2025-08-21  
**POC仓库:** [CVE-2024-3721---POC](https://github.com/qalvynn/CVE-2024-3721---POC)  

---

### [CVE-2019-0222](CVE-2019-0222-shoucheng3_apache__activemq_CVE-2019-0222_5-15-8.md) 🔴 ✅

**名称:** CVE-2019-0222-Apache ActiveMQ-MQTT OOM DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致ActiveMQ Broker服务不可用  
**投毒风险:** 10%  
**发现时间:** 2025-08-21  
**POC仓库:** [apache__activemq_CVE-2019-0222_5-15-8](https://github.com/shoucheng3/apache__activemq_CVE-2019-0222_5-15-8)  

---

### [CVE-2016-6662](CVE-2016-6662-konstantin-kelemen_mysqld_safe-CVE-2016-6662-patch.md) 🔴 ✅

**名称:** CVE-2016-6662 - MySQL/MariaDB/PerconaDB 权限提升/远程代码执行  
**类型:** 权限提升/远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-20  
**POC仓库:** [mysqld_safe-CVE-2016-6662-patch](https://github.com/konstantin-kelemen/mysqld_safe-CVE-2016-6662-patch)  

---

### [CVE-2016-6662](CVE-2016-6662-KosukeShimofuji_CVE-2016-6662.md) 🔴 ✅

**名称:** CVE-2016-6662 - MySQL 本地权限提升/远程代码执行  
**类型:** 权限提升/远程代码执行  
**风险:** 高危，可能导致完全控制数据库服务器  
**投毒风险:** 5%  
**发现时间:** 2025-08-20  
**POC仓库:** [CVE-2016-6662](https://github.com/KosukeShimofuji/CVE-2016-6662)  

---

### [CVE-2016-6662](CVE-2016-6662-meersjo_ansible-mysql-cve-2016-6662.md) 🔴 ✅

**名称:** CVE-2016-6662 - MySQL 远程 Root 代码执行/权限提升  
**类型:** 权限提升/远程代码执行  
**风险:** 高危，可能导致数据库完全控制和服务器接管  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [ansible-mysql-cve-2016-6662](https://github.com/meersjo/ansible-mysql-cve-2016-6662)  

---

### [CVE-2016-6662](CVE-2016-6662-Ashrafdev_MySQL-Remote-Root-Code-Execution.md) 🔴 ✅

**名称:** CVE-2016-6662 - MySQL Remote Root Code Execution / Privilege Escalation  
**类型:** 代码执行  
**风险:** 高危，可导致远程代码执行和权限提升至root  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [MySQL-Remote-Root-Code-Execution](https://github.com/Ashrafdev/MySQL-Remote-Root-Code-Execution)  

---

### [CVE-2016-6662](CVE-2016-6662-boompig_cve-2016-6662.md) 🔴 ✅

**名称:** CVE-2016-6662 - MySQL Remote Root Code Execution / Privilege Escalation  
**类型:** 权限提升/远程代码执行  
**风险:** 高危，可导致数据库服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [cve-2016-6662](https://github.com/boompig/cve-2016-6662)  

---

### [CVE-2016-6662](CVE-2016-6662-MAYASEVEN_CVE-2016-6662.md) 🔴 ✅

**名称:** CVE-2016-6662 - MySQL 本地权限提升/远程代码执行  
**类型:** 配置覆盖/本地权限提升/远程代码执行  
**风险:** 高危，允许本地用户创建任意配置并绕过某些保护机制，最终导致以 root 权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [CVE-2016-6662](https://github.com/MAYASEVEN/CVE-2016-6662)  

---

### [CVE-2016-6662](CVE-2016-6662-LSQUARE14_SQL_to_RCE_Lab.md) 🔴 ✅

**名称:** CVE-2016-6662-MySQL 远程代码执行/权限提升  
**类型:** 权限提升/远程代码执行  
**风险:** 高危，可导致数据库服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [SQL_to_RCE_Lab](https://github.com/LSQUARE14/SQL_to_RCE_Lab)  

---

### [CVE-2016-6662](CVE-2016-6662-kanyaars_CVE-2016-6662.md) 🔴 ✅

**名称:** CVE-2016-6662 - MySQL 本地权限提升/远程代码执行  
**类型:** 权限提升/远程代码执行  
**风险:** 高危，可能导致完全系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [CVE-2016-6662](https://github.com/kanyaars/CVE-2016-6662)  

---

### [CVE-2025-55188](CVE-2025-55188-rhllsingh_CVE-2025-55188-7z-exploit.md) 🟡 ✅

**名称:** CVE-2025-55188-7-Zip符号链接处理不当漏洞  
**类型:** 符号链接处理不当  
**风险:** 中危，可能导致任意文件写入  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [CVE-2025-55188-7z-exploit](https://github.com/rhllsingh/CVE-2025-55188-7z-exploit)  

---

### [CVE-2025-52392](CVE-2025-52392-137f_Soosyze-CMS-2.0---CVE-2025-52392.md) 🟡 ✅

**名称:** CVE-2025-52392-Soosyze CMS-暴力破解  
**类型:** 暴力破解  
**风险:** 中危，可能导致未授权访问  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [Soosyze-CMS-2.0---CVE-2025-52392](https://github.com/137f/Soosyze-CMS-2.0---CVE-2025-52392)  

---

### [CVE-2025-54782](CVE-2025-54782-nitrixog_CVE-2025-54782.md)  ✅

**名称:** CVE-2025-54782 - NestJS DevTools 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致远程代码执行和系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [CVE-2025-54782](https://github.com/nitrixog/CVE-2025-54782)  

---

### [CVE-2018-7600](CVE-2018-7600-SyedGhufranRaza_CVE-2018-7600-Remote-Code-Execution.md) 🔴 ✅

**名称:** CVE-2018-7600-Drupalgeddon2-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未授权的远程攻击者执行任意代码，完全控制受影响的服务器，导致数据泄露、篡改、拒绝服务或植入恶意软件。  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [CVE-2018-7600-Remote-Code-Execution](https://github.com/SyedGhufranRaza/CVE-2018-7600-Remote-Code-Execution)  

---

### [CVE-2020-17519](CVE-2020-17519-shoucheng3_apache__flink_CVE-2020-17519_1-11-2.md) 🔴 ✅

**名称:** CVE-2020-17519-Apache Flink-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-08-20  
**POC仓库:** [apache__flink_CVE-2020-17519_1-11-2](https://github.com/shoucheng3/apache__flink_CVE-2020-17519_1-11-2)  

---

### [CVE-2025-48384](CVE-2025-48384-replicatorbot_CVE-2025-48384.md) 🔴 ✅

**名称:** CVE-2025-48384-Git-任意代码执行  
**类型:** 任意代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-20  
**POC仓库:** [CVE-2025-48384](https://github.com/replicatorbot/CVE-2025-48384)  

---

### [CVE-2023-31126](CVE-2023-31126-shoucheng3_xwiki__xwiki-commons_CVE-2023-31126_14-10-3.md) 🔴 ✅

**名称:** CVE-2023-31126-xwiki-commons-xml-XSS  
**类型:** 跨站脚本 (XSS)  
**风险:** 高危，可能导致账户劫持、信息泄露和恶意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [xwiki__xwiki-commons_CVE-2023-31126_14-10-3](https://github.com/shoucheng3/xwiki__xwiki-commons_CVE-2023-31126_14-10-3)  

---

### [CVE-2023-31126](CVE-2023-31126-shoucheng3_cov-int.md) 🔴 ✅

**名称:** CVE-2023-31126-XWiki-XSS  
**类型:** 跨站脚本 (XSS)  
**风险:** 高危，可能允许攻击者注入任意HTML代码，从而执行恶意脚本、窃取用户数据或篡改页面内容。  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [cov-int](https://github.com/shoucheng3/cov-int)  

---

### [CVE-2022-31195](CVE-2022-31195-shoucheng3_DSpace__DSpace_CVE-2022-31195_5-10.md) 🔴 ✅

**名称:** CVE-2022-31195-DSpace-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致任意文件写入，最终导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-20  
**POC仓库:** [DSpace__DSpace_CVE-2022-31195_5-10](https://github.com/shoucheng3/DSpace__DSpace_CVE-2022-31195_5-10)  

---

### [CVE-2025-8889](CVE-2025-8889-siberkampus_CVE-2025-8889.md) 🔴 ✅

**名称:** CVE-N/A-WordPress Compress Then Upload Plugin Arbitrary File Upload to RCE  
**类型:** 任意文件上传导致远程代码执行  
**风险:** 高危，允许未经授权的用户执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-08-20  
**POC仓库:** [CVE-2025-8889](https://github.com/siberkampus/CVE-2025-8889)  

---

### [CVE-2023-36542](CVE-2023-36542-shoucheng3_asf__nifi_CVE-2023-36542_1-22-0.md) 🔴 ✅

**名称:** CVE-2023-36542-Apache NiFi-代码注入  
**类型:** 代码注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-20  
**POC仓库:** [asf__nifi_CVE-2023-36542_1-22-0](https://github.com/shoucheng3/asf__nifi_CVE-2023-36542_1-22-0)  

---

### [CVE-2023-29528](CVE-2023-29528-shoucheng3_xwiki__xwiki-commons_CVE-2023-29528_14-9-rc-1.md) 🔴 ✅

**名称:** CVE-2023-29528-XWiki-XSS  
**类型:** 跨站脚本 (XSS)  
**风险:** 高危，可能导致敏感信息泄露和服务器端代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [xwiki__xwiki-commons_CVE-2023-29528_14-9-rc-1](https://github.com/shoucheng3/xwiki__xwiki-commons_CVE-2023-29528_14-9-rc-1)  

---

### [CVE-2020-5405](CVE-2020-5405-shoucheng3_spring-cloud__spring-cloud-config_CVE-2020-5405_2-1-6-RELEASE.md) 🟡 ✅

**名称:** CVE-2020-5405-Spring Cloud Config-目录遍历  
**类型:** 目录遍历  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [spring-cloud__spring-cloud-config_CVE-2020-5405_2-1-6-RELEASE](https://github.com/shoucheng3/spring-cloud__spring-cloud-config_CVE-2020-5405_2-1-6-RELEASE)  

---

### [CVE-2020-29204](CVE-2020-29204-shoucheng3_xuxueli__xxl-job_CVE-2020-29204_2-2-0.md) 🟡 ✅

**名称:** CVE-2020-29204-XXL-JOB-存储型XSS  
**类型:** 存储型XSS  
**风险:** 中危，可能导致用户凭据泄露、页面重定向或恶意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-20  
**POC仓库:** [xuxueli__xxl-job_CVE-2020-29204_2-2-0](https://github.com/shoucheng3/xuxueli__xxl-job_CVE-2020-29204_2-2-0)  

---

### [CVE-2022-22947](CVE-2022-22947-shoucheng3_spring-cloud__spring-cloud-gateway_CVE-2022-22947_3-0-6.md) 🔴 ✅

**名称:** CVE-2022-22947-Spring Cloud Gateway-代码注入  
**类型:** 代码注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-20  
**POC仓库:** [spring-cloud__spring-cloud-gateway_CVE-2022-22947_3-0-6](https://github.com/shoucheng3/spring-cloud__spring-cloud-gateway_CVE-2022-22947_3-0-6)  

---

### [CVE-2022-44262](CVE-2022-44262-shoucheng3_ff4j__ff4j_CVE-2022-44262_1-8-13.md) 🔴 

**名称:** CVE-2022-44262 - ff4j 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致完全系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [ff4j__ff4j_CVE-2022-44262_1-8-13](https://github.com/shoucheng3/ff4j__ff4j_CVE-2022-44262_1-8-13)  

---

### [CVE-2018-9159](CVE-2018-9159-shoucheng3_perwendel__spark_CVE-2018-9159_2-7-1.md) 🟡 ✅

**名称:** CVE-2018-9159-spark-core-文件读取  
**类型:** 文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-08-20  
**POC仓库:** [perwendel__spark_CVE-2018-9159_2-7-1](https://github.com/shoucheng3/perwendel__spark_CVE-2018-9159_2-7-1)  

---

### [CVE-2022-36007](CVE-2022-36007-shoucheng3_jlangch__venice_CVE-2022-36007_1-10-16.md) 🟡 ✅

**名称:** CVE-2022-36007-venice-Partial Path Traversal  
**类型:** Partial Path Traversal  
**风险:** 中危，可能导致敏感信息泄露和完整性破坏  
**投毒风险:** 0%  
**发现时间:** 2025-08-20  
**POC仓库:** [jlangch__venice_CVE-2022-36007_1-10-16](https://github.com/shoucheng3/jlangch__venice_CVE-2022-36007_1-10-16)  

---

### [CVE-2021-41269](CVE-2021-41269-shoucheng3_jmrozanec__cron-utils_CVE-2021-41269_9-1-5.md) 🔴 ✅

**名称:** CVE-2021-41269-cron-utils-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-20  
**POC仓库:** [jmrozanec__cron-utils_CVE-2021-41269_9-1-5](https://github.com/shoucheng3/jmrozanec__cron-utils_CVE-2021-41269_9-1-5)  

---

### [CVE-2017-14735](CVE-2017-14735-shoucheng3_nahsra__antisamy_CVE-2017-14735_1-5-6.md) 🟡 ✅

**名称:** CVE-2017-14735-OWASP AntiSamy-XSS  
**类型:** XSS  
**风险:** 中危，可能允许攻击者执行任意JavaScript代码  
**投毒风险:** 5%  
**发现时间:** 2025-08-20  
**POC仓库:** [nahsra__antisamy_CVE-2017-14735_1-5-6](https://github.com/shoucheng3/nahsra__antisamy_CVE-2017-14735_1-5-6)  

---

### [CVE-2018-12036](CVE-2018-12036-shoucheng3_jeremylong__DependencyCheck_CVE-2018-12036_3-1-2.md) 🔴 ✅

**名称:** CVE-2018-12036-OWASP Dependency-Check-Zip Slip  
**类型:** 路径遍历  
**风险:** 高危，可能导致任意文件写入  
**投毒风险:** 0%  
**发现时间:** 2025-08-20  
**POC仓库:** [jeremylong__DependencyCheck_CVE-2018-12036_3-1-2](https://github.com/shoucheng3/jeremylong__DependencyCheck_CVE-2018-12036_3-1-2)  

---

### [CVE-2022-22965](CVE-2022-22965-salo-404_firewall.md) 🔴 ✅

**名称:** CVE-2022-22965 Spring4Shell RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [firewall](https://github.com/salo-404/firewall)  

---

### [CVE-2022-22965](CVE-2022-22965-shoucheng3_spring-projects__spring-framework_CVE-2022-22965_5-2-19-RELEASE.md) 🔴 ✅

**名称:** CVE-2022-22965 Spring4Shell RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-08-20  
**POC仓库:** [spring-projects__spring-framework_CVE-2022-22965_5-2-19-RELEASE](https://github.com/shoucheng3/spring-projects__spring-framework_CVE-2022-22965_5-2-19-RELEASE)  

---

### [CVE-2014-7816](CVE-2014-7816-shoucheng3_undertow-io__undertow_CVE-2014-7816_1-0-16-Final.md) 🔴 ✅

**名称:** CVE-2014-7816 - JBoss Undertow 目录遍历漏洞  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-08-20  
**POC仓库:** [undertow-io__undertow_CVE-2014-7816_1-0-16-Final](https://github.com/shoucheng3/undertow-io__undertow_CVE-2014-7816_1-0-16-Final)  

---

### [CVE-2023-51770](CVE-2023-51770-shoucheng3_apache__dolphinscheduler_CVE-2023-51770_3-2-0.md) 🔴 ✅

**名称:** CVE-2023-51770 - Apache DolphinScheduler Arbitrary File Read  
**类型:** Arbitrary File Read  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [apache__dolphinscheduler_CVE-2023-51770_3-2-0](https://github.com/shoucheng3/apache__dolphinscheduler_CVE-2023-51770_3-2-0)  

---

### [CVE-2023-29201](CVE-2023-29201-shoucheng3_xwiki__xwiki-commons_CVE-2023-29201_14-5.md) 🔴 ✅

**名称:** CVE-2023-29201-xwiki-commons-xml-XSS  
**类型:** 跨站脚本 (XSS)  
**风险:** 高危，允许攻击者执行任意JavaScript代码，可能导致信息泄露、会话劫持甚至远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-20  
**POC仓库:** [xwiki__xwiki-commons_CVE-2023-29201_14-5](https://github.com/shoucheng3/xwiki__xwiki-commons_CVE-2023-29201_14-5)  

---

### [CVE-2023-41044](CVE-2023-41044-shoucheng3_Graylog2__graylog2-server_CVE-2023-41044_5-1-2.md) 🟡 

**名称:** CVE-2023-41044-Graylog-路径遍历  
**类型:** 路径遍历  
**风险:** 中危，可能导致敏感信息泄露或文件删除  
**投毒风险:** 0%  
**发现时间:** 2025-08-20  
**POC仓库:** [Graylog2__graylog2-server_CVE-2023-41044_5-1-2](https://github.com/shoucheng3/Graylog2__graylog2-server_CVE-2023-41044_5-1-2)  

---

### [CVE-2022-34662](CVE-2022-34662-shoucheng3_apache__dolphinscheduler_CVE-2022-34662_2-0-9.md) 🟡 ✅

**名称:** CVE-2022-34662 - Apache DolphinScheduler Path Traversal  
**类型:** Path Traversal  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-08-20  
**POC仓库:** [apache__dolphinscheduler_CVE-2022-34662_2-0-9](https://github.com/shoucheng3/apache__dolphinscheduler_CVE-2022-34662_2-0-9)  

---

### [CVE-2025-5777](CVE-2025-5777-ndr-repo_CVE-2025-5777.md) 🔴 ✅

**名称:** CVE-2025-5777-NetScaler ADC/Gateway-内存信息泄露  
**类型:** 内存信息泄露/Out-of-bounds Read  
**风险:** 高危，可能导致会话劫持、身份验证绕过以及敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-08-20  
**POC仓库:** [CVE-2025-5777](https://github.com/ndr-repo/CVE-2025-5777)  

---

### [CVE-2018-10008](CVE-2018-10008-tna0y_CVE-2018-1000802-PoC.md) 🟡 ✅

**名称:** CVE-2018-1000802  
**类型:** 代码注入  
**风险:** 中危，可能导致信息泄露，拒绝服务，或者执行任意命令  
**投毒风险:** 0%  
**发现时间:** 2025-08-20  
**POC仓库:** [CVE-2018-1000802-PoC](https://github.com/tna0y/CVE-2018-1000802-PoC)  

---

### [CVE-2018-10008](CVE-2018-10008-smokeintheshell_CVE-2018-1000861.md) 🔴 ✅

**名称:** CVE-2018-1000861 - Jenkins 未授权远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的攻击者可以在受影响的Jenkins服务器上执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [CVE-2018-1000861](https://github.com/smokeintheshell/CVE-2018-1000861)  

---

### [CVE-2018-10008](CVE-2018-10008-shoucheng3_square__retrofit_CVE-2018-1000850_2-4-0.md) 🟡 

**名称:** CVE-2018-10008XXE漏洞分析  
**类型:** XXE(XML外部实体注入)  
**风险:** 中危，可能导致信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-08-20  
**POC仓库:** [square__retrofit_CVE-2018-1000850_2-4-0](https://github.com/shoucheng3/square__retrofit_CVE-2018-1000850_2-4-0)  

---

### [CVE-2025-8088](CVE-2025-8088-Syrins_CVE-2025-8088-Winrar-Tool-Gui.md) 🔴 ✅

**名称:** CVE-2025-8088-WinRAR-Path Traversal  
**类型:** 路径遍历  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [CVE-2025-8088-Winrar-Tool-Gui](https://github.com/Syrins/CVE-2025-8088-Winrar-Tool-Gui)  

---

### [CVE-2024-4577](CVE-2024-4577-Ianthinus_CVE-2024-4577.md) 🔴 ✅

**名称:** CVE-2024-4577-PHP-CGI Argument Injection  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [CVE-2024-4577](https://github.com/Ianthinus/CVE-2024-4577)  

---

### [CVE-2025-34036](CVE-2025-34036-Prabhukiran161_cve-2025-34036.md) 🔴 ✅

**名称:** CVE-2025-34036-TVT-DVR-命令注入  
**类型:** OS 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [cve-2025-34036](https://github.com/Prabhukiran161/cve-2025-34036)  

---

### [CVE-2022-34662](CVE-2022-34662-shoucheng3_apache__dolphinscheduler_CVE-2022-34662_2-0-9.md) 🟡 

**名称:** CVE-2022-34662 - Apache DolphinScheduler 路径遍历  
**类型:** 路径遍历  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-08-20  
**POC仓库:** [apache__dolphinscheduler_CVE-2022-34662_2-0-9](https://github.com/shoucheng3/apache__dolphinscheduler_CVE-2022-34662_2-0-9)  

---

### [CVE-2019-17640](CVE-2019-17640-shoucheng3_vert-x3__vertx-web_CVE-2019-17640_3-9-3.md) 🔴 ✅

**名称:** CVE-2019-17640-Eclipse Vert.x-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致文件读取甚至远程代码执行（取决于系统配置和可访问文件）。  
**投毒风险:** 0%  
**发现时间:** 2025-08-20  
**POC仓库:** [vert-x3__vertx-web_CVE-2019-17640_3-9-3](https://github.com/shoucheng3/vert-x3__vertx-web_CVE-2019-17640_3-9-3)  

---

### [CVE-2022-25175](CVE-2022-25175-shoucheng3_jenkinsci__workflow-multibranch-plugin_CVE-2022-25175_706-vd43c65dec013.md) 🔴 ✅

**名称:** CVE-2022-25175 - Jenkins Pipeline Multibranch Plugin 任意命令执行  
**类型:** 任意命令执行  
**风险:** 高危，允许攻击者在Jenkins控制器上执行任意操作系统命令  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [jenkinsci__workflow-multibranch-plugin_CVE-2022-25175_706-vd43c65dec013](https://github.com/shoucheng3/jenkinsci__workflow-multibranch-plugin_CVE-2022-25175_706-vd43c65dec013)  

---

### [CVE-2022-42889](CVE-2022-42889-Gotcha1G_CVE-2022-42889.md) 🔴 ✅

**名称:** CVE-2022-42889-Apache Commons Text-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [CVE-2022-42889](https://github.com/Gotcha1G/CVE-2022-42889)  

---

### [CVE-2022-42889](CVE-2022-42889-QAInsights_cve-2022-42889-jmeter.md) 🔴 ✅

**名称:** CVE-2022-42889: Apache Commons Text RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-20  
**POC仓库:** [cve-2022-42889-jmeter](https://github.com/QAInsights/cve-2022-42889-jmeter)  

---

### [CVE-2022-42889](CVE-2022-42889-korteke_CVE-2022-42889-POC.md) 🔴 ✅

**名称:** CVE-2022-42889-Apache Commons Text RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致远程代码执行，完全控制受影响系统  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [CVE-2022-42889-POC](https://github.com/korteke/CVE-2022-42889-POC)  

---

### [CVE-2022-42889](CVE-2022-42889-sunnyvale-it_CVE-2022-42889-PoC.md) 🔴 ✅

**名称:** CVE-2022-42889-Text4Shell-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经授权的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [CVE-2022-42889-PoC](https://github.com/sunnyvale-it/CVE-2022-42889-PoC)  

---

### [CVE-2022-42889](CVE-2022-42889-adarshpv9746_Text4shell--Automated-exploit---CVE-2022-42889.md) 🔴 ✅

**名称:** CVE-2022-42889-Apache Commons Text-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者执行任意命令  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [Text4shell--Automated-exploit---CVE-2022-42889](https://github.com/adarshpv9746/Text4shell--Automated-exploit---CVE-2022-42889)  

---

### [CVE-2022-42889](CVE-2022-42889-karthikuj_cve-2022-42889-text4shell-docker.md) 🔴 ✅

**名称:** CVE-2022-42889-Apache Commons Text-RCE  
**类型:** 远程代码执行（RCE）  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [cve-2022-42889-text4shell-docker](https://github.com/karthikuj/cve-2022-42889-text4shell-docker)  

---

### [CVE-2022-42889](CVE-2022-42889-cryxnet_CVE-2022-42889-RCE.md) 🔴 ✅

**名称:** CVE-2022-42889-Apache Commons Text RCE (Text4Shell)  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的攻击者执行任意命令  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [CVE-2022-42889-RCE](https://github.com/cryxnet/CVE-2022-42889-RCE)  

---

### [CVE-2022-42889](CVE-2022-42889-vickyaryan7_Text4shell-exploit.md) 🔴 ✅

**名称:** CVE-2022-42889-Apache Commons Text RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-08-20  
**POC仓库:** [Text4shell-exploit](https://github.com/vickyaryan7/Text4shell-exploit)  

---

### [CVE-2022-42889](CVE-2022-42889-f0ng_text4shellburpscanner.md) 🔴 ✅

**名称:** CVE-2022-42889-Apache Commons Text-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-08-20  
**POC仓库:** [text4shellburpscanner](https://github.com/f0ng/text4shellburpscanner)  

---

### [CVE-2022-42889](CVE-2022-42889-devenes_text4shell-cve-2022-42889.md) 🔴 ✅

**名称:** CVE-2022-42889-Apache Commons Text-RCE  
**类型:** 远程代码执行(RCE)  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-08-20  
**POC仓库:** [text4shell-cve-2022-42889](https://github.com/devenes/text4shell-cve-2022-42889)  

---

### [CVE-2022-42889](CVE-2022-42889-gokul-ramesh_text4shell-exploit.md) 🔴 ✅

**名称:** CVE-2022-42889-Apache Commons Text-RCE  
**类型:** 远程代码执行(RCE)  
**风险:** 高危，允许未授权的攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [text4shell-exploit](https://github.com/gokul-ramesh/text4shell-exploit)  

---

### [CVE-2022-42889](CVE-2022-42889-hotblac_text4shell.md) 🔴 ✅

**名称:** CVE-2022-42889 - Apache Commons Text RCE (Text4Shell)  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的攻击者执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-08-20  
**POC仓库:** [text4shell](https://github.com/hotblac/text4shell)  

---

### [CVE-2022-42889](CVE-2022-42889-cxzero_CVE-2022-42889-text4shell.md) 🔴 ✅

**名称:** CVE-2022-42889 - Apache Commons Text RCE (Text4Shell)  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-08-20  
**POC仓库:** [CVE-2022-42889-text4shell](https://github.com/cxzero/CVE-2022-42889-text4shell)  

---

### [CVE-2022-42889](CVE-2022-42889-ReachabilityOrg_cve-2022-42889-text4shell-docker.md) 🔴 ✅

**名称:** CVE-2022-42889 - Apache Commons Text RCE (Text4Shell)  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [cve-2022-42889-text4shell-docker](https://github.com/ReachabilityOrg/cve-2022-42889-text4shell-docker)  

---

### [CVE-2022-42889](CVE-2022-42889-Dima2021_cve-2022-42889-text4shell.md) 🔴 ✅

**名称:** CVE-2022-42889-Apache Commons Text-RCE  
**类型:** 远程代码执行（RCE）  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-20  
**POC仓库:** [cve-2022-42889-text4shell](https://github.com/Dima2021/cve-2022-42889-text4shell)  

---

### [CVE-2022-42889](CVE-2022-42889-tulhan_commons-text-goat.md) 🔴 ✅

**名称:** CVE-2022-42889-Apache Commons Text-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许远程代码执行，可能导致系统完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-20  
**POC仓库:** [commons-text-goat](https://github.com/tulhan/commons-text-goat)  

---

### [CVE-2022-42889](CVE-2022-42889-necroteddy_CVE-2022-42889.md) 🔴 ✅

**名称:** CVE-2022-42889-Apache Commons Text RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [CVE-2022-42889](https://github.com/necroteddy/CVE-2022-42889)  

---

### [CVE-2022-42889](CVE-2022-42889-chainguard-dev_text4shell-policy.md) 🔴 ✅

**名称:** CVE-2022-42889 Apache Commons Text Text4Shell RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经授权的攻击者执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-08-20  
**POC仓库:** [text4shell-policy](https://github.com/chainguard-dev/text4shell-policy)  

---

### [CVE-2022-42889](CVE-2022-42889-808ale_CVE-2022-42889-Text4Shell-POC.md) 🔴 ✅

**名称:** CVE-2022-42889-Apache Commons Text-RCE/SSRF  
**类型:** 远程代码执行 (RCE) / 服务器端请求伪造 (SSRF)  
**风险:** 高危，可能导致远程代码执行或服务器端请求伪造  
**投毒风险:** 5%  
**发现时间:** 2025-08-20  
**POC仓库:** [CVE-2022-42889-Text4Shell-POC](https://github.com/808ale/CVE-2022-42889-Text4Shell-POC)  

---

### [CVE-2022-42889](CVE-2022-42889-Sic4rio_CVE-2022-42889.md) 🔴 ✅

**名称:** CVE-2022-42889-Apache Commons Text-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-08-20  
**POC仓库:** [CVE-2022-42889](https://github.com/Sic4rio/CVE-2022-42889)  

---

### [CVE-2022-42889](CVE-2022-42889-34006133_CVE-2022-42889.md) 🔴 ✅

**名称:** CVE-2022-42889 Text4Shell RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-20  
**POC仓库:** [CVE-2022-42889](https://github.com/34006133/CVE-2022-42889)  

---

### [CVE-2022-42889](CVE-2022-42889-DimaMend_cve-2022-42889-text4shell.md) 🔴 ✅

**名称:** CVE-2022-42889-Apache Commons Text-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-08-20  
**POC仓库:** [cve-2022-42889-text4shell](https://github.com/DimaMend/cve-2022-42889-text4shell)  

---

### [CVE-2022-42889](CVE-2022-42889-kljunowsky_CVE-2022-42889-text4shell.md) 🔴 ✅

**名称:** CVE-2022-42889 - Apache Commons Text 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的攻击者执行任意命令。  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [CVE-2022-42889-text4shell](https://github.com/kljunowsky/CVE-2022-42889-text4shell)  

---

### [CVE-2022-42889](CVE-2022-42889-aaronm-sysdig_text4shell-docker.md) 🔴 ✅

**名称:** CVE-2022-42889-Apache Commons Text-RCE  
**类型:** 远程代码执行(RCE)  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-08-20  
**POC仓库:** [text4shell-docker](https://github.com/aaronm-sysdig/text4shell-docker)  

---

### [CVE-2022-42889](CVE-2022-42889-joshbnewton31080_cve-2022-42889-text4shell.md) 🔴 ✅

**名称:** CVE-2022-42889-Apache Commons Text-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-08-20  
**POC仓库:** [cve-2022-42889-text4shell](https://github.com/joshbnewton31080/cve-2022-42889-text4shell)  

---

### [CVE-2022-42889](CVE-2022-42889-MendDemo-josh_cve-2022-42889-text4shell.md) 🔴 ✅

**名称:** CVE-2022-42889 Text4Shell  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [cve-2022-42889-text4shell](https://github.com/MendDemo-josh/cve-2022-42889-text4shell)  

---

### [CVE-2022-42889](CVE-2022-42889-Syndicate27_text4shell-exploit.md) 🔴 ✅

**名称:** CVE-2022-42889 - Apache Commons Text 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的攻击者执行任意命令  
**投毒风险:** 0%  
**发现时间:** 2025-08-20  
**POC仓库:** [text4shell-exploit](https://github.com/Syndicate27/text4shell-exploit)  

---

### [CVE-2022-42889](CVE-2022-42889-shoucheng3_asf__commons-text_CVE-2022-42889_1-9.md) 🔴 ✅

**名称:** CVE-2022-42889 - Apache Commons Text RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-08-20  
**POC仓库:** [asf__commons-text_CVE-2022-42889_1-9](https://github.com/shoucheng3/asf__commons-text_CVE-2022-42889_1-9)  

---

### [CVE-2023-29201](CVE-2023-29201-shoucheng3_xwiki__xwiki-commons_CVE-2023-29201_14-5.md) 🔴 ✅

**名称:** CVE-2023-29201-xwiki-commons-XSS  
**类型:** 跨站脚本 (XSS)  
**风险:** 高危，可导致敏感信息泄露，权限提升，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-20  
**POC仓库:** [xwiki__xwiki-commons_CVE-2023-29201_14-5](https://github.com/shoucheng3/xwiki__xwiki-commons_CVE-2023-29201_14-5)  

---

### [CVE-2025-31324](CVE-2025-31324-harshitvarma05_CVE-2025-31324-Exploits.md) 🔴 ✅

**名称:** CVE-2025-31324-SAP NetWeaver Visual Composer-未授权文件上传  
**类型:** 未授权文件上传  
**风险:** 高危，可能导致远程代码执行和系统完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-20  
**POC仓库:** [CVE-2025-31324-Exploits](https://github.com/harshitvarma05/CVE-2025-31324-Exploits)  

---

### [CVE-2023-41044](CVE-2023-41044-shoucheng3_Graylog2__graylog2-server_CVE-2023-41044_5-1-2.md)  

**名称:** CVE-2023-41044-Graylog-路径遍历  
**类型:** 路径遍历  
**风险:** 低危，可能导致敏感信息泄露和文件删除  
**投毒风险:** 0%  
**发现时间:** 2025-08-20  
**POC仓库:** [Graylog2__graylog2-server_CVE-2023-41044_5-1-2](https://github.com/shoucheng3/Graylog2__graylog2-server_CVE-2023-41044_5-1-2)  

---

### [CVE-2024-36042](CVE-2024-36042-zaaraZiof0_CVE-2024-36042.md) 🔴 ✅

**名称:** CVE-2024-36042-Silverpeas-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未经授权的访问和完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-08-19  
**POC仓库:** [CVE-2024-36042](https://github.com/zaaraZiof0/CVE-2024-36042)  

---

### [CVE-2022-22932](CVE-2022-22932-shoucheng3_asf__karaf_CVE-2022-22932_4-3-5.md) 🟡 

**名称:** CVE-2022-22932-Apache Karaf-路径遍历  
**类型:** 路径遍历  
**风险:** 中危，可能导致文件读取或写入，取决于权限配置  
**投毒风险:** 0%  
**发现时间:** 2025-08-19  
**POC仓库:** [asf__karaf_CVE-2022-22932_4-3-5](https://github.com/shoucheng3/asf__karaf_CVE-2022-22932_4-3-5)  

---

### [CVE-2017-10004](CVE-2017-10004-mogwailabs_CVE-2017-1000486.md) 🔴 

**名称:** CVE-2017-10004  
**类型:** 权限提升/远程代码执行  
**风险:** 高危，可能导致系统完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-19  
**POC仓库:** [CVE-2017-1000486](https://github.com/mogwailabs/CVE-2017-1000486)  

---

### [CVE-2023-49109](CVE-2023-49109-shoucheng3_apache__dolphinscheduler_CVE-2023-49109_3-2-0.md) 🔴 ✅

**名称:** CVE-2023-49109 - Apache DolphinScheduler Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-19  
**POC仓库:** [apache__dolphinscheduler_CVE-2023-49109_3-2-0](https://github.com/shoucheng3/apache__dolphinscheduler_CVE-2023-49109_3-2-0)  

---

### [CVE-2022-20617](CVE-2022-20617-shoucheng3_jenkinsci__docker-commons-plugin_CVE-2022-20617_1-17.md) 🔴 

**名称:** CVE-2022-20617 - Jenkins Docker Commons Plugin OS 命令注入  
**类型:** OS 命令注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-19  
**POC仓库:** [jenkinsci__docker-commons-plugin_CVE-2022-20617_1-17](https://github.com/shoucheng3/jenkinsci__docker-commons-plugin_CVE-2022-20617_1-17)  

---

### [CVE-2019-10219](CVE-2019-10219-shoucheng3_hibernate__hibernate-validator_CVE-2019-10219_6-0-17-Final.md) 🟡 ✅

**名称:** CVE-2019-10219 - Hibernate-Validator SafeHtml XSS  
**类型:** 跨站脚本 (XSS)  
**风险:** 中危，可能导致用户信息泄露或恶意脚本执行  
**投毒风险:** 5%  
**发现时间:** 2025-08-19  
**POC仓库:** [hibernate__hibernate-validator_CVE-2019-10219_6-0-17-Final](https://github.com/shoucheng3/hibernate__hibernate-validator_CVE-2019-10219_6-0-17-Final)  

---

### [CVE-2021-41773](CVE-2021-41773-charanvoonna_CVE-2021-41773.md) 🔴 ✅

**名称:** CVE-2021-41773-Apache HTTP Server-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-08-19  
**POC仓库:** [CVE-2021-41773](https://github.com/charanvoonna/CVE-2021-41773)  

---

### [CVE-2017-10004](CVE-2017-10004-lajarajorge_CVE-2017-1000475.md) 🔴 

**名称:** CVE-2017-10004  
**类型:** Solaris Kernel权限提升漏洞  
**风险:** 高危，可导致Solaris系统被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-19  
**POC仓库:** [CVE-2017-1000475](https://github.com/lajarajorge/CVE-2017-1000475)  

---

### [CVE-2017-10004](CVE-2017-10004-Villaquiranm_5MMISSI-CVE-2017-1000499.md) 🟡 ✅

**名称:** CVE-2017-1000499-phpMyAdmin-CSRF  
**类型:** CSRF  
**风险:** 中危，可能导致未经授权的数据库操作  
**投毒风险:** 10%  
**发现时间:** 2025-08-19  
**POC仓库:** [5MMISSI-CVE-2017-1000499](https://github.com/Villaquiranm/5MMISSI-CVE-2017-1000499)  

---

### [CVE-2017-10004](CVE-2017-10004-ossf-cve-benchmark_CVE-2017-1000427.md) 🔴 

**名称:** CVE-2017-10004  
**类型:** 权限提升  
**风险:** 高危，可完全控制Solaris操作系统  
**投毒风险:** 10%  
**发现时间:** 2025-08-19  
**POC仓库:** [CVE-2017-1000427](https://github.com/ossf-cve-benchmark/CVE-2017-1000427)  

---

### [CVE-2017-10004](CVE-2017-10004-cved-sources_cve-2017-1000486.md) 🔴 

**名称:** CVE-2017-10004  
**类型:** Solaris Kernel权限提升  
**风险:** 高危，可导致系统完全控制  
**投毒风险:** 95%  
**发现时间:** 2025-08-19  
**POC仓库:** [cve-2017-1000486](https://github.com/cved-sources/cve-2017-1000486)  

---

### [CVE-2017-10004](CVE-2017-10004-Pastea_CVE-2017-1000486.md) 🔴 

**名称:** CVE-2017-10004  
**类型:** Solaris Kernel Takeover  
**风险:** 高危，可完全控制Solaris系统  
**投毒风险:** 20%  
**发现时间:** 2025-08-19  
**POC仓库:** [CVE-2017-1000486](https://github.com/Pastea/CVE-2017-1000486)  

---

### [CVE-2017-10004](CVE-2017-10004-LongWayHomie_CVE-2017-1000486.md) 🔴 ✅

**名称:** CVE-2017-10004  
**类型:** EL表达式注入/远程代码执行  
**风险:** 高危，可能导致服务器接管  
**投毒风险:** 5%  
**发现时间:** 2025-08-19  
**POC仓库:** [CVE-2017-1000486](https://github.com/LongWayHomie/CVE-2017-1000486)  

---

### [CVE-2017-10004](CVE-2017-10004-pimps_CVE-2017-1000486.md) 🔴 

**名称:** CVE-2017-10004-Solaris内核权限提升  
**类型:** 权限提升  
**风险:** 高危，可完全控制系统  
**投毒风险:** 0%  
**发现时间:** 2025-08-19  
**POC仓库:** [CVE-2017-1000486](https://github.com/pimps/CVE-2017-1000486)  

---

### [CVE-2017-10004](CVE-2017-10004-shoucheng3_codehaus-plexus__plexus-utils_CVE-2017-1000487_3-0-15.md) 🔴 

**名称:** CVE-2017-10004  
**类型:** 权限提升/代码执行  
**风险:** 高危，可完全控制Solaris系统  
**投毒风险:** 10%  
**发现时间:** 2025-08-19  
**POC仓库:** [codehaus-plexus__plexus-utils_CVE-2017-1000487_3-0-15](https://github.com/shoucheng3/codehaus-plexus__plexus-utils_CVE-2017-1000487_3-0-15)  

---

### [CVE-2018-10022](CVE-2018-10022-shoucheng3_codehaus-plexus__plexus-archiver_CVE-2018-1002200_3-5.md) 🔴 ✅

**名称:** CVE-2018-10022  
**类型:** 目录遍历  
**风险:** 高危，可能导致任意文件写入  
**投毒风险:** 0%  
**发现时间:** 2025-08-19  
**POC仓库:** [codehaus-plexus__plexus-archiver_CVE-2018-1002200_3-5](https://github.com/shoucheng3/codehaus-plexus__plexus-archiver_CVE-2018-1002200_3-5)  

---

### [CVE-2025-29927](CVE-2025-29927-R3verseIN_Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-中间件鉴权绕过  
**类型:** 鉴权绕过  
**风险:** 高危，可能导致未经授权访问敏感资源  
**投毒风险:** 10%  
**发现时间:** 2025-08-19  
**POC仓库:** [Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927](https://github.com/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927)  

---

### [CVE-2018-10022](CVE-2018-10022-shoucheng3_zeroturnaround__zt-zip_CVE-2018-1002201_1-12.md) 🔴 

**名称:** CVE-2018-1002204 adm-zip 目录遍历漏洞  
**类型:** 目录遍历  
**风险:** 高危，允许攻击者写入任意文件  
**投毒风险:** 5%  
**发现时间:** 2025-08-19  
**POC仓库:** [zeroturnaround__zt-zip_CVE-2018-1002201_1-12](https://github.com/shoucheng3/zeroturnaround__zt-zip_CVE-2018-1002201_1-12)  

---

### [CVE-2019-17573](CVE-2019-17573-shoucheng3_asf__cxf_CVE-2019-17573_3-2-11.md) 🟡 ✅

**名称:** CVE-2019-17573-Apache CXF-Reflected XSS  
**类型:** Reflected XSS  
**风险:** 中危，可能导致用户凭据泄露、会话劫持等  
**投毒风险:** 10%  
**发现时间:** 2025-08-19  
**POC仓库:** [asf__cxf_CVE-2019-17573_3-2-11](https://github.com/shoucheng3/asf__cxf_CVE-2019-17573_3-2-11)  

---

### [CVE-2025-8723](CVE-2025-8723-Nxploited_CVE-2025-8723.md) 🔴 ✅

**名称:** CVE-2025-8723-Cloudflare Image Resizing-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-08-19  
**POC仓库:** [CVE-2025-8723](https://github.com/Nxploited/CVE-2025-8723)  

---

### [CVE-2025-50383](CVE-2025-50383-Abdullah4eb_CVE-2025-50383.md) 🔴 ✅

**名称:** CVE-2025-50383-EasyAppointments-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-19  
**POC仓库:** [CVE-2025-50383](https://github.com/Abdullah4eb/CVE-2025-50383)  

---

### [CVE-2013-7285](CVE-2013-7285-shoucheng3_x-stream__xstream_CVE-2013-7285_1-4-6.md) 🔴 ✅

**名称:** CVE-2013-7285-XStream-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和服务器控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-19  
**POC仓库:** [x-stream__xstream_CVE-2013-7285_1-4-6](https://github.com/shoucheng3/x-stream__xstream_CVE-2013-7285_1-4-6)  

---

### [CVE-2024-53900](CVE-2024-53900-www-spam_CVE-2024-53900.md) 🔴 ✅

**名称:** CVE-2024-53900-Mongoose-Search注入  
**类型:** Search注入/NoSQL注入  
**风险:** 高危，可能导致数据泄露和未经授权的数据访问  
**投毒风险:** 10%  
**发现时间:** 2025-08-19  
**POC仓库:** [CVE-2024-53900](https://github.com/www-spam/CVE-2024-53900)  

---

### [CVE-2019-5688](CVE-2019-5688-watsa01_CVE-2019-5688.md) 🔴 ✅

**名称:** CVE-2019-5688-NVIDIA-权限提升/信息泄露/DoS  
**类型:** 权限提升/信息泄露/拒绝服务  
**风险:** 高危，可能导致权限提升、信息泄露或拒绝服务  
**投毒风险:** 0%  
**发现时间:** 2025-08-19  
**POC仓库:** [CVE-2019-5688](https://github.com/watsa01/CVE-2019-5688)  

---

### [CVE-2019-10078](CVE-2019-10078-shoucheng3_apache__jspwiki_CVE-2019-10078_2-11-0-M3.md) 🟡 ✅

**名称:** CVE-2019-10078-Apache JSPWiki-XSS  
**类型:** XSS  
**风险:** 中危，可能导致会话劫持  
**投毒风险:** 0%  
**发现时间:** 2025-08-19  
**POC仓库:** [apache__jspwiki_CVE-2019-10078_2-11-0-M3](https://github.com/shoucheng3/apache__jspwiki_CVE-2019-10078_2-11-0-M3)  

---

### [CVE-2022-24897](CVE-2022-24897-shoucheng3_xwiki__xwiki-commons_CVE-2022-24897_12-6-6.md) 🔴 

**名称:** CVE-2022-24897-xwiki-commons-文件系统写入  
**类型:** 文件系统写入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-19  
**POC仓库:** [xwiki__xwiki-commons_CVE-2022-24897_12-6-6](https://github.com/shoucheng3/xwiki__xwiki-commons_CVE-2022-24897_12-6-6)  

---

### [CVE-2022-31194](CVE-2022-31194-shoucheng3_DSpace__DSpace_CVE-2022-31194_5-10.md) 🔴 

**名称:** CVE-2022-31194-DSpace-Path Traversal  
**类型:** Path Traversal  
**风险:** 高危，可创建任意文件/目录，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-08-19  
**POC仓库:** [DSpace__DSpace_CVE-2022-31194_5-10](https://github.com/shoucheng3/DSpace__DSpace_CVE-2022-31194_5-10)  

---

### [CVE-2018-17297](CVE-2018-17297-shoucheng3_dromara__hutool_CVE-2018-17297_4-1-11.md) 🔴 ✅

**名称:** CVE-2018-17297-Hutool-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致任意文件写入  
**投毒风险:** 0%  
**发现时间:** 2025-08-19  
**POC仓库:** [dromara__hutool_CVE-2018-17297_4-1-11](https://github.com/shoucheng3/dromara__hutool_CVE-2018-17297_4-1-11)  

---

### [CVE-2025-49113](CVE-2025-49113-SteamPunk424_CVE-2025-49113-Roundcube-RCE-PHP.md) 🔴 ✅

**名称:** CVE-2025-49113-Roundcube-RCE-PHP对象反序列化  
**类型:** PHP对象反序列化  
**风险:** 高危，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-19  
**POC仓库:** [CVE-2025-49113-Roundcube-RCE-PHP](https://github.com/SteamPunk424/CVE-2025-49113-Roundcube-RCE-PHP)  

---

### [CVE-2023-24422](CVE-2023-24422-shoucheng3_jenkinsci__script-security-plugin_CVE-2023-24422_1228.vd93135a_2fb_25.md) 🔴 

**名称:** CVE-2023-24422 - Jenkins Script Security Plugin Sandbox Bypass  
**类型:** Sandbox Bypass  
**风险:** 高危，允许攻击者绕过沙箱保护并在Jenkins控制器JVM的上下文中执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-08-19  
**POC仓库:** [jenkinsci__script-security-plugin_CVE-2023-24422_1228.vd93135a_2fb_25](https://github.com/shoucheng3/jenkinsci__script-security-plugin_CVE-2023-24422_1228.vd93135a_2fb_25)  

---

### [CVE-2022-4137](CVE-2022-4137-shoucheng3_keycloak__keycloak_CVE-2022-4137_20-0-3.md) 🔴 

**名称:** CVE-2022-4137-Keycloak-Reflected XSS  
**类型:** Reflected XSS  
**风险:** 高危，可能导致用户凭据泄露和会话劫持  
**投毒风险:** 0%  
**发现时间:** 2025-08-19  
**POC仓库:** [keycloak__keycloak_CVE-2022-4137_20-0-3](https://github.com/shoucheng3/keycloak__keycloak_CVE-2022-4137_20-0-3)  

---

### [CVE-2014-3576](CVE-2014-3576-shoucheng3_apache__activemq_CVE-2014-3576_5-10-1.md) 🟡 ✅

**名称:** CVE-2014-3576-Apache ActiveMQ-DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 中危，可能导致服务中断  
**投毒风险:** 0%  
**发现时间:** 2025-08-19  
**POC仓库:** [apache__activemq_CVE-2014-3576_5-10-1](https://github.com/shoucheng3/apache__activemq_CVE-2014-3576_5-10-1)  

---

### [CVE-2020-36708](CVE-2020-36708-b1g-b33f_CVE-2020-36708.md) 🔴 ✅

**名称:** CVE-2020-36708 - WordPress Epsilon Framework Function Injection  
**类型:** 函数注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-19  
**POC仓库:** [CVE-2020-36708](https://github.com/b1g-b33f/CVE-2020-36708)  

---

### [CVE-2025-25063](CVE-2025-25063-moften_CVE-2025-25063-MadeYouReset-HTTP-2-DDoS.md) 🟡 ✅

**名称:** CVE-2025-25063-Backdrop CMS-XSS  
**类型:** XSS  
**风险:** 中危，可能导致用户敏感信息泄露或会话劫持  
**投毒风险:** 0%  
**发现时间:** 2025-08-18  
**POC仓库:** [CVE-2025-25063-MadeYouReset-HTTP-2-DDoS](https://github.com/moften/CVE-2025-25063-MadeYouReset-HTTP-2-DDoS)  

---

### [CVE-2022-38691](CVE-2022-38691-TomKing062_CVE-2022-38691_38692.md) 🔴 ✅

**名称:** CVE-2022-38691/38692 Unisoc ROM 漏洞利用  
**类型:** 固件漏洞利用/引导链篡改  
**风险:** 高危，可能导致设备完全控制和持久性后门  
**投毒风险:** 10%  
**发现时间:** 2025-08-18  
**POC仓库:** [CVE-2022-38691_38692](https://github.com/TomKing062/CVE-2022-38691_38692)  

---

### [CVE-2019-10077](CVE-2019-10077-shoucheng3_apache__jspwiki_CVE-2019-10077_2-11-0-M3.md) 🟡 ✅

**名称:** CVE-2019-10077-Apache JSPWiki-XSS  
**类型:** XSS (跨站脚本)  
**风险:** 中危，可能导致会话劫持  
**投毒风险:** 10%  
**发现时间:** 2025-08-18  
**POC仓库:** [apache__jspwiki_CVE-2019-10077_2-11-0-M3](https://github.com/shoucheng3/apache__jspwiki_CVE-2019-10077_2-11-0-M3)  

---

### [CVE-2018-10022](CVE-2018-10022-ossf-cve-benchmark_CVE-2018-1002204.md) 🔴 

**名称:** CVE-2018-10022 系列漏洞（推测）  
**类型:** 目录穿越/任意文件写入  
**风险:** 高危，可能导致任意文件写入，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-18  
**POC仓库:** [CVE-2018-1002204](https://github.com/ossf-cve-benchmark/CVE-2018-1002204)  

---

### [CVE-2018-10022](CVE-2018-10022-ossf-cve-benchmark_CVE-2018-1002203.md) 🔴 ✅

**名称:** CVE-2018-1002204/CVE-2018-1002208-node-unzipper/SharpZipLib目录遍历漏洞  
**类型:** 目录遍历  
**风险:** 高危，可能导致任意文件写入  
**投毒风险:** 10%  
**发现时间:** 2025-08-18  
**POC仓库:** [CVE-2018-1002203](https://github.com/ossf-cve-benchmark/CVE-2018-1002203)  

---

### [CVE-2018-10022](CVE-2018-10022-shoucheng3_srikanth-lingala__zip4j_CVE-2018-1002202_1-3-2.md) 🔴 ✅

**名称:** CVE-2018-1002202 - zip4j Path Traversal  
**类型:** 路径遍历  
**风险:** 高危，允许攻击者写入任意文件。  
**投毒风险:** 10%  
**发现时间:** 2025-08-18  
**POC仓库:** [srikanth-lingala__zip4j_CVE-2018-1002202_1-3-2](https://github.com/shoucheng3/srikanth-lingala__zip4j_CVE-2018-1002202_1-3-2)  

---

### [CVE-2021-30180](CVE-2021-30180-shoucheng3_apache__dubbo_CVE-2021-30180_2-7-9.md) 🔴 ✅

**名称:** CVE-2021-30180 Apache Dubbo RCE via Condition route poisoning  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-08-18  
**POC仓库:** [apache__dubbo_CVE-2021-30180_2-7-9](https://github.com/shoucheng3/apache__dubbo_CVE-2021-30180_2-7-9)  

---

### [CVE-2016-10006](CVE-2016-10006-epicosy_VUL4J-60.md) 🔴 

**名称:** CVE-2016-10006-OWASP AntiSamy-XSS  
**类型:** XSS (跨站脚本)  
**风险:** 高危，可能导致用户数据泄露、会话劫持、恶意代码执行等  
**投毒风险:** 10%  
**发现时间:** 2025-08-18  
**POC仓库:** [VUL4J-60](https://github.com/epicosy/VUL4J-60)  

---

### [CVE-2016-10006](CVE-2016-10006-shoucheng3_nahsra__antisamy_CVE-2016-10006_1-5-3.md) 🟡 

**名称:** CVE-2016-10006-OWASP AntiSamy-XSS  
**类型:** XSS  
**风险:** 中危，可能导致跨站脚本攻击  
**投毒风险:** 10%  
**发现时间:** 2025-08-18  
**POC仓库:** [nahsra__antisamy_CVE-2016-10006_1-5-3](https://github.com/shoucheng3/nahsra__antisamy_CVE-2016-10006_1-5-3)  

---

### [CVE-2022-25174](CVE-2022-25174-shoucheng3_jenkinsci__workflow-cps-global-lib-plugin_CVE-2022-25174_544-vff04fa68714d.md) 🔴 

**名称:** CVE-2022-25174 - Jenkins Pipeline Shared Groovy Libraries Plugin OS Command Injection  
**类型:** OS 命令注入  
**风险:** 高危，允许攻击者在 Jenkins 控制器上执行任意 OS 命令  
**投毒风险:** 10%  
**发现时间:** 2025-08-18  
**POC仓库:** [jenkinsci__workflow-cps-global-lib-plugin_CVE-2022-25174_544-vff04fa68714d](https://github.com/shoucheng3/jenkinsci__workflow-cps-global-lib-plugin_CVE-2022-25174_544-vff04fa68714d)  

---

### [CVE-2023-35887](CVE-2023-35887-shoucheng3_apache__mina-sshd_CVE-2023-35887_2-9-2.md) 🟡 

**名称:** CVE-2023-35887-Apache MINA SSHD-信息泄露  
**类型:** 信息泄露  
**风险:** 中危，可能导致未经授权的信息访问  
**投毒风险:** 0%  
**发现时间:** 2025-08-18  
**POC仓库:** [apache__mina-sshd_CVE-2023-35887_2-9-2](https://github.com/shoucheng3/apache__mina-sshd_CVE-2023-35887_2-9-2)  

---

### [CVE-2025-49113](CVE-2025-49113-CyberQuestor-infosec_CVE-2025-49113-Roundcube_1.6.10.md) 🔴 ✅

**名称:** CVE-2025-49113 – Roundcube 1.6.10 Authenticated Remote Code Execution  
**类型:** PHP Object Deserialization  
**风险:** 高危，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-18  
**POC仓库:** [CVE-2025-49113-Roundcube_1.6.10](https://github.com/CyberQuestor-infosec/CVE-2025-49113-Roundcube_1.6.10)  

---

### [CVE-2024-28397](CVE-2024-28397-0timeday_exploit-js2py.md) 🔴 ✅

**名称:** CVE-2024-28397-js2py-Sandbox-Escape  
**类型:** 代码注入/沙箱逃逸  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-18  
**POC仓库:** [exploit-js2py](https://github.com/0timeday/exploit-js2py)  

---

### [CVE-2024-28397](CVE-2024-28397-harutomo-jp_CVE-2024-28397-RCE.md) 🔴 ✅

**名称:** CVE-2024-28397-js2py-代码注入  
**类型:** 代码注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-18  
**POC仓库:** [CVE-2024-28397-RCE](https://github.com/harutomo-jp/CVE-2024-28397-RCE)  

---

### [CVE-2022-31159](CVE-2022-31159-shoucheng3_aws__aws-sdk-java_CVE-2022-31159_1-12-260.md) 🔴 ✅

**名称:** CVE-2022-31159 - AWS SDK for Java S3 TransferManager 路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感文件泄露和未经授权的访问  
**投毒风险:** 1%  
**发现时间:** 2025-08-18  
**POC仓库:** [aws__aws-sdk-java_CVE-2022-31159_1-12-260](https://github.com/shoucheng3/aws__aws-sdk-java_CVE-2022-31159_1-12-260)  

---

### [CVE-2024-0520](CVE-2024-0520-chan-068_CVE-2024-0520_try.md) 🔴 ✅

**名称:** CVE-2024-0520 - mlflow远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致数据泄露、服务器控制和拒绝服务  
**投毒风险:** 0%  
**发现时间:** 2025-08-18  
**POC仓库:** [CVE-2024-0520_try](https://github.com/chan-068/CVE-2024-0520_try)  

---

### [CVE-2023-33962](CVE-2023-33962-shoucheng3_jstachio__jstachio_CVE-2023-33962_1-0-0.md) 🟡 ✅

**名称:** CVE-2023-33962-JStachio-XSS  
**类型:** XSS  
**风险:** 中危，可能导致信息泄露、会话劫持、网页篡改  
**投毒风险:** 0%  
**发现时间:** 2025-08-18  
**POC仓库:** [jstachio__jstachio_CVE-2023-33962_1-0-0](https://github.com/shoucheng3/jstachio__jstachio_CVE-2023-33962_1-0-0)  

---

### [CVE-2015-6967](CVE-2015-6967-innocentx0_CVE-2015-6967-EXPLOIT.md) 🔴 ✅

**名称:** CVE-2015-6967-Nibbleblog-Unrestricted File Upload  
**类型:** Unrestricted File Upload  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-08-18  
**POC仓库:** [CVE-2015-6967-EXPLOIT](https://github.com/innocentx0/CVE-2015-6967-EXPLOIT)  

---

### [CVE-2018-6574](CVE-2018-6574-solovvway_CVE-2018-6574.md) 🔴 ✅

**名称:** CVE-2018-6574  
**类型:** 远程代码执行  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-18  
**POC仓库:** [CVE-2018-6574](https://github.com/solovvway/CVE-2018-6574)  

---

### [CVE-2022-1274](CVE-2022-1274-shoucheng3_keycloak__keycloak_CVE-2022-1274_20-0-3.md) 🟡 

**名称:** CVE-2022-1274-Keycloak-HTML注入  
**类型:** HTML注入  
**风险:** 中危，可能导致钓鱼攻击或其他针对用户的攻击  
**投毒风险:** 0%  
**发现时间:** 2025-08-18  
**POC仓库:** [keycloak__keycloak_CVE-2022-1274_20-0-3](https://github.com/shoucheng3/keycloak__keycloak_CVE-2022-1274_20-0-3)  

---

### [CVE-2025-49132](CVE-2025-49132-GRodolphe_CVE-2025-49132_poc.md) 🔴 ✅

**名称:** CVE-2025-49132-Pterodactyl Panel-RCE  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-18  
**POC仓库:** [CVE-2025-49132_poc](https://github.com/GRodolphe/CVE-2025-49132_poc)  

---

### [CVE-2025-4334](CVE-2025-4334-0xgh057r3c0n_CVE-2025-4334.md) 🔴 ✅

**名称:** CVE-2025-4334-Simple User Registration-权限提升  
**类型:** 权限提升  
**风险:** 高危，未经身份验证的攻击者可以注册为管理员  
**投毒风险:** 1%  
**发现时间:** 2025-08-18  
**POC仓库:** [CVE-2025-4334](https://github.com/0xgh057r3c0n/CVE-2025-4334)  

---

### [CVE-2019-10089](CVE-2019-10089-shoucheng3_apache__jspwiki_CVE-2019-10089_2-11-0-M4.md) 🟡 ✅

**名称:** CVE-2019-10089-Apache JSPWiki-XSS  
**类型:** XSS  
**风险:** 中危，可能导致信息泄露和恶意脚本执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-18  
**POC仓库:** [apache__jspwiki_CVE-2019-10089_2-11-0-M4](https://github.com/shoucheng3/apache__jspwiki_CVE-2019-10089_2-11-0-M4)  

---

### [CVE-2016-5394](CVE-2016-5394-epicosy_VUL4J-23.md) 🟡 

**名称:** CVE-2016-5394-Apache Sling-XSS  
**类型:** XSS  
**风险:** 中危，可能导致用户凭据泄露、会话劫持和恶意脚本执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-18  
**POC仓库:** [VUL4J-23](https://github.com/epicosy/VUL4J-23)  

---

### [CVE-2025-26788](CVE-2025-26788-EQSTLab_CVE-2025-26788.md) 🔴 ✅

**名称:** CVE-2025-26788-StrongKey-FIDO-Server-认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致账户接管  
**投毒风险:** 5%  
**发现时间:** 2025-08-18  
**POC仓库:** [CVE-2025-26788](https://github.com/EQSTLab/CVE-2025-26788)  

---

### [CVE-2013-3900](CVE-2013-3900-Kramcov_CVE-2013-3900-PowerShell-PoC.md) 🟡 ✅

**名称:** CVE-2013-3900 WinVerifyTrust Signature Validation Vulnerability  
**类型:** 签名验证绕过  
**风险:** 中危，可能导致恶意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-18  
**POC仓库:** [CVE-2013-3900-PowerShell-PoC](https://github.com/Kramcov/CVE-2013-3900-PowerShell-PoC)  

---

### [CVE-2025-7771](CVE-2025-7771-Yuri08loveElaina_CVE-2025-7771.md) 🔴 ✅

**名称:** CVE-2025-7771-ThrottleStop.sys-权限提升  
**类型:** 权限提升  
**风险:** 高危，允许本地用户以内核权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-18  
**POC仓库:** [CVE-2025-7771](https://github.com/Yuri08loveElaina/CVE-2025-7771)  

---

### [CVE-2016-5394](CVE-2016-5394-shoucheng3_apache__sling-org-apache-sling-xss_CVE-2016-5394_1-0-8.md) 🟡 ✅

**名称:** CVE-2016-5394-Apache Sling-XSS  
**类型:** 跨站脚本 (XSS)  
**风险:** 中危，可能导致用户凭据泄露或恶意脚本执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-18  
**POC仓库:** [apache__sling-org-apache-sling-xss_CVE-2016-5394_1-0-8](https://github.com/shoucheng3/apache__sling-org-apache-sling-xss_CVE-2016-5394_1-0-8)  

---

### [CVE-2022-3782](CVE-2022-3782-shoucheng3_keycloak__keycloak_CVE-2022-3782_20-0-1.md) 🔴 

**名称:** CVE-2022-3782-Keycloak-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-08-18  
**POC仓库:** [keycloak__keycloak_CVE-2022-3782_20-0-1](https://github.com/shoucheng3/keycloak__keycloak_CVE-2022-3782_20-0-1)  

---

### [CVE-2023-34468](CVE-2023-34468-shoucheng3_asf__nifi_CVE-2023-34468_1-21-0.md) 🔴 ✅

**名称:** CVE-2023-34468-Apache NiFi-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 1%  
**发现时间:** 2025-08-18  
**POC仓库:** [asf__nifi_CVE-2023-34468_1-21-0](https://github.com/shoucheng3/asf__nifi_CVE-2023-34468_1-21-0)  

---

### [CVE-2014-8739](CVE-2014-8739-Pranjal6955_CVE-2014-8739-Test-Environment.md) 🔴 ✅

**名称:** CVE-2014-8739 - jQuery File Upload Plugin 未限制文件上传漏洞  
**类型:** 未限制文件上传  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-18  
**POC仓库:** [CVE-2014-8739-Test-Environment](https://github.com/Pranjal6955/CVE-2014-8739-Test-Environment)  

---

### [CVE-2024-40094](CVE-2024-40094-ahmad-kabiri_CVE-2024-40094.md) 🟡 ✅

**名称:** CVE-2024-40094-graphql-java-DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 中危，可能导致服务不可用  
**投毒风险:** 1%  
**发现时间:** 2025-08-18  
**POC仓库:** [CVE-2024-40094](https://github.com/ahmad-kabiri/CVE-2024-40094)  

---

### [CVE-2025-54253](CVE-2025-54253-jm7knz_CVE-2025-54253-Exploit-Demo.md) 🔴 ✅

**名称:** CVE-2025-54253 Adobe Experience Manager Misconfiguration  
**类型:** Misconfiguration  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-08-17  
**POC仓库:** [CVE-2025-54253-Exploit-Demo](https://github.com/jm7knz/CVE-2025-54253-Exploit-Demo)  

---

### [CVE-2025-9090](CVE-2025-9090-byteReaper77_CVE-2025-9090.md) 🟡 ✅

**名称:** CVE-2025-9090-TendaAC20-命令注入  
**类型:** 命令注入  
**风险:** 中危，可远程执行命令  
**投毒风险:** 5%  
**发现时间:** 2025-08-17  
**POC仓库:** [CVE-2025-9090](https://github.com/byteReaper77/CVE-2025-9090)  

---

### [CVE-2022-4065](CVE-2022-4065-shoucheng3_testng-team__testng_CVE-2022-4065_7-5.md) 🟡 ✅

**名称:** CVE-2022-4065-testng-路径遍历  
**类型:** 路径遍历  
**风险:** 中危，可能导致敏感文件泄露  
**投毒风险:** 10%  
**发现时间:** 2025-08-17  
**POC仓库:** [testng-team__testng_CVE-2022-4065_7-5](https://github.com/shoucheng3/testng-team__testng_CVE-2022-4065_7-5)  

---

### [CVE-2025-8875](CVE-2025-8875-rxerium_CVE-2025-8875-CVE-2025-8876.md) 🔴 ✅

**名称:** CVE-2025-8875-N-able N-central-反序列化漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-17  
**POC仓库:** [CVE-2025-8875-CVE-2025-8876](https://github.com/rxerium/CVE-2025-8875-CVE-2025-8876)  

---

### [CVE-2022-3782](CVE-2022-3782-shoucheng3_keycloak__keycloak_CVE-2022-3782_20-0-1.md) 🔴 

**名称:** CVE-2022-3782-Keycloak-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露和进一步攻击  
**投毒风险:** 0%  
**发现时间:** 2025-08-17  
**POC仓库:** [keycloak__keycloak_CVE-2022-3782_20-0-1](https://github.com/shoucheng3/keycloak__keycloak_CVE-2022-3782_20-0-1)  

---

### [CVE-2023-33246](CVE-2023-33246-I5N0rth_CVE-2023-33246.md) 🔴 ✅

**名称:** CVE-2023-33246-Apache RocketMQ-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-17  
**POC仓库:** [CVE-2023-33246](https://github.com/I5N0rth/CVE-2023-33246)  

---

### [CVE-2023-33246](CVE-2023-33246-4mazing_CVE-2023-33246-Copy.md) 🔴 ✅

**名称:** CVE-2023-33246-Apache RocketMQ-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-17  
**POC仓库:** [CVE-2023-33246-Copy](https://github.com/4mazing/CVE-2023-33246-Copy)  

---

### [CVE-2023-33246](CVE-2023-33246-SuperZero_CVE-2023-33246.md) 🔴 ✅

**名称:** CVE-2023-33246-Apache RocketMQ-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-08-17  
**POC仓库:** [CVE-2023-33246](https://github.com/SuperZero/CVE-2023-33246)  

---

### [CVE-2023-33246](CVE-2023-33246-AiK1d_CVE-2023-33246.md) 🔴 ✅

**名称:** CVE-2023-33246-Apache RocketMQ-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可执行任意命令  
**投毒风险:** 10%  
**发现时间:** 2025-08-17  
**POC仓库:** [CVE-2023-33246](https://github.com/AiK1d/CVE-2023-33246)  

---

### [CVE-2023-33246](CVE-2023-33246-Le1a_CVE-2023-33246.md) 🔴 ✅

**名称:** CVE-2023-33246 - Apache RocketMQ 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-17  
**POC仓库:** [CVE-2023-33246](https://github.com/Le1a/CVE-2023-33246)  

---

### [CVE-2023-33246](CVE-2023-33246-Malayke_CVE-2023-33246_RocketMQ_RCE_EXPLOIT.md) 🔴 ✅

**名称:** CVE-2023-33246-Apache RocketMQ-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-17  
**POC仓库:** [CVE-2023-33246_RocketMQ_RCE_EXPLOIT](https://github.com/Malayke/CVE-2023-33246_RocketMQ_RCE_EXPLOIT)  

---

### [CVE-2023-33246](CVE-2023-33246-d0rb_CVE-2023-33246.md) 🔴 ✅

**名称:** CVE-2023-33246-Apache RocketMQ-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-17  
**POC仓库:** [CVE-2023-33246](https://github.com/d0rb/CVE-2023-33246)  

---

### [CVE-2023-33246](CVE-2023-33246-0xKayala_CVE-2023-33246.md) 🔴 ✅

**名称:** CVE-2023-33246-Apache RocketMQ-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-17  
**POC仓库:** [CVE-2023-33246](https://github.com/0xKayala/CVE-2023-33246)  

---

### [CVE-2023-33246](CVE-2023-33246-MkJos_CVE-2023-33246_RocketMQ_RCE_EXP.md) 🔴 ✅

**名称:** CVE-2023-33246 Apache RocketMQ 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未经授权的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-17  
**POC仓库:** [CVE-2023-33246_RocketMQ_RCE_EXP](https://github.com/MkJos/CVE-2023-33246_RocketMQ_RCE_EXP)  

---

### [CVE-2023-33246](CVE-2023-33246-Sumitpathania03_Apache-RocketMQ-CVE-2023-33246-.md) 🔴 ✅

**名称:** CVE-2023-33246 Apache RocketMQ 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者执行任意命令。  
**投毒风险:** 10%  
**发现时间:** 2025-08-17  
**POC仓库:** [Apache-RocketMQ-CVE-2023-33246-](https://github.com/Sumitpathania03/Apache-RocketMQ-CVE-2023-33246-)  

---

### [CVE-2023-33246](CVE-2023-33246-PavilionQ_CVE-2023-33246-mitigation.md) 🔴 ✅

**名称:** CVE-2023-33246-Apache RocketMQ-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-17  
**POC仓库:** [CVE-2023-33246-mitigation](https://github.com/PavilionQ/CVE-2023-33246-mitigation)  

---

### [CVE-2023-33246](CVE-2023-33246-vulncheck-oss_fetch-broker-conf.md) 🔴 ✅

**名称:** CVE-2023-33246-Apache RocketMQ-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-17  
**POC仓库:** [fetch-broker-conf](https://github.com/vulncheck-oss/fetch-broker-conf)  

---

### [CVE-2023-33246](CVE-2023-33246-shoucheng3_apache__rocketmq_CVE-2023-33246_5-1-0.md) 🔴 ✅

**名称:** CVE-2023-33246 Apache RocketMQ 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经授权的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-17  
**POC仓库:** [apache__rocketmq_CVE-2023-33246_5-1-0](https://github.com/shoucheng3/apache__rocketmq_CVE-2023-33246_5-1-0)  

---

### [CVE-2015-10141](CVE-2015-10141-n0m4d22_PoC-CVE-2015-10141-Xdebug.md) 🔴 ✅

**名称:** CVE-2015-10141-Xdebug-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-08-17  
**POC仓库:** [PoC-CVE-2015-10141-Xdebug](https://github.com/n0m4d22/PoC-CVE-2015-10141-Xdebug)  

---

### [CVE-2022-24891](CVE-2022-24891-shoucheng3_ESAPI__esapi-java-legacy_CVE-2022-24891_2-2-3-1.md) 🟡 

**名称:** CVE-2022-24891-ESAPI-XSS  
**类型:** 跨站脚本 (XSS)  
**风险:** 中危，可能导致用户信息泄露和恶意脚本执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-17  
**POC仓库:** [ESAPI__esapi-java-legacy_CVE-2022-24891_2-2-3-1](https://github.com/shoucheng3/ESAPI__esapi-java-legacy_CVE-2022-24891_2-2-3-1)  

---

### [CVE-2023-32697](CVE-2023-32697-shoucheng3_xerial__sqlite-jdbc_CVE-2023-32697_3-41-2-1.md) 🔴 ✅

**名称:** CVE-2023-32697-sqlite-jdbc-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-17  
**POC仓库:** [xerial__sqlite-jdbc_CVE-2023-32697_3-41-2-1](https://github.com/shoucheng3/xerial__sqlite-jdbc_CVE-2023-32697_3-41-2-1)  

---

### [CVE-2023-37460](CVE-2023-37460-shoucheng3_codehaus-plexus__plexus-archiver_CVE-2023-37460_4-7-1.md) 🔴 ✅

**名称:** CVE-2023-37460-plexus-archiver-任意文件创建  
**类型:** 任意文件创建/路径遍历  
**风险:** 高危，可能导致任意文件写入和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-17  
**POC仓库:** [codehaus-plexus__plexus-archiver_CVE-2023-37460_4-7-1](https://github.com/shoucheng3/codehaus-plexus__plexus-archiver_CVE-2023-37460_4-7-1)  

---

### [CVE-2022-22931](CVE-2022-22931-shoucheng3_asf__james-project_CVE-2022-22931_3-6-0.md) 🟡 

**名称:** CVE-2022-22931-Apache James-路径遍历  
**类型:** 路径遍历  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-08-17  
**POC仓库:** [asf__james-project_CVE-2022-22931_3-6-0](https://github.com/shoucheng3/asf__james-project_CVE-2022-22931_3-6-0)  

---

### [CVE-2024-23673](CVE-2024-23673-shoucheng3_apache__sling-org-apache-sling-servlets-resolver_CVE-2024-23673_2-10-0.md) 🔴 

**名称:** CVE-2024-23673 - Apache Sling Servlets Resolver Path Traversal  
**类型:** 路径遍历  
**风险:** 高危，可能导致恶意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-17  
**POC仓库:** [apache__sling-org-apache-sling-servlets-resolver_CVE-2024-23673_2-10-0](https://github.com/shoucheng3/apache__sling-org-apache-sling-servlets-resolver_CVE-2024-23673_2-10-0)  

---

### [CVE-2022-3782](CVE-2022-3782-shoucheng3_keycloak__keycloak_CVE-2022-3782_20-0-1.md) 🔴 ✅

**名称:** CVE-2022-3782 - Keycloak Path Traversal via Double URL Encoding  
**类型:** 路径遍历  
**风险:** 高危，可能导致信息泄露和未授权访问  
**投毒风险:** 10%  
**发现时间:** 2025-08-17  
**POC仓库:** [keycloak__keycloak_CVE-2022-3782_20-0-1](https://github.com/shoucheng3/keycloak__keycloak_CVE-2022-3782_20-0-1)  

---

### [CVE-2025-31324](CVE-2025-31324-lekosbelas_sap-0day-CVE-2025-31324.md) 🔴 ✅

**名称:** CVE-2025-31324-SAP NetWeaver Visual Composer Metadata Uploader-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 20%  
**发现时间:** 2025-08-17  
**POC仓库:** [sap-0day-CVE-2025-31324](https://github.com/lekosbelas/sap-0day-CVE-2025-31324)  

---

### [CVE-2022-26049](CVE-2022-26049-shoucheng3_diffplug__goomph_CVE-2022-26049_3-37-1.md) 🟡 

**名称:** CVE-2022-26049 - Goomph Zip Slip 漏洞  
**类型:** Zip Slip (任意文件写入)  
**风险:** 中危，可能导致任意文件写入，覆盖文件，最终可能导致远程代码执行。  
**投毒风险:** 10%  
**发现时间:** 2025-08-17  
**POC仓库:** [diffplug__goomph_CVE-2022-26049_3-37-1](https://github.com/shoucheng3/diffplug__goomph_CVE-2022-26049_3-37-1)  

---

### [CVE-2019-10076](CVE-2019-10076-shoucheng3_apache__jspwiki_CVE-2019-10076_2-11-0-M3.md) 🟡 

**名称:** CVE-2019-10076-Apache JSPWiki-XSS  
**类型:** 跨站脚本（XSS）  
**风险:** 中危，可能导致会话劫持  
**投毒风险:** 1%  
**发现时间:** 2025-08-17  
**POC仓库:** [apache__jspwiki_CVE-2019-10076_2-11-0-M3](https://github.com/shoucheng3/apache__jspwiki_CVE-2019-10076_2-11-0-M3)  

---

### [CVE-2023-34468](CVE-2023-34468-mbadanoiu_CVE-2023-34468.md) 🔴 ✅

**名称:** CVE-2023-34468: Apache NiFi H2 JDBC URL 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-17  
**POC仓库:** [CVE-2023-34468](https://github.com/mbadanoiu/CVE-2023-34468)  

---

### [CVE-2023-34468](CVE-2023-34468-shoucheng3_asf__nifi_CVE-2023-34468_1-21-0.md) 🔴 ✅

**名称:** CVE-2023-34468-Apache NiFi-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致完全系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-17  
**POC仓库:** [asf__nifi_CVE-2023-34468_1-21-0](https://github.com/shoucheng3/asf__nifi_CVE-2023-34468_1-21-0)  

---

### [CVE-2022-46907](CVE-2022-46907-shoucheng3_apache__jspwiki_CVE-2022-46907_2-11-3.md) 🟡 ✅

**名称:** CVE-2022-46907 - Apache JSPWiki XSS漏洞  
**类型:** 跨站脚本攻击 (XSS)  
**风险:** 中危，可能导致敏感信息泄露和恶意脚本执行  
**投毒风险:** 1%  
**发现时间:** 2025-08-17  
**POC仓库:** [apache__jspwiki_CVE-2022-46907_2-11-3](https://github.com/shoucheng3/apache__jspwiki_CVE-2022-46907_2-11-3)  

---

### [CVE-2016-9177](CVE-2016-9177-shoucheng3_perwendel__spark_CVE-2016-9177_2-5-1.md) 🔴 ✅

**名称:** CVE-2016-9177-Spark-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-08-17  
**POC仓库:** [perwendel__spark_CVE-2016-9177_2-5-1](https://github.com/shoucheng3/perwendel__spark_CVE-2016-9177_2-5-1)  

---

### [CVE-2023-28465](CVE-2023-28465-shoucheng3_hapifhir__org_hl7_fhir_core_CVE-2023-28465_5-6-105.md) 🔴 ✅

**名称:** CVE-2023-28465-HL7 FHIR Core Libraries-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能允许攻击者复制任意文件到特定目录。  
**投毒风险:** 0%  
**发现时间:** 2025-08-17  
**POC仓库:** [hapifhir__org_hl7_fhir_core_CVE-2023-28465_5-6-105](https://github.com/shoucheng3/hapifhir__org_hl7_fhir_core_CVE-2023-28465_5-6-105)  

---

### [CVE-2020-11998](CVE-2020-11998-shoucheng3_apache__activemq_CVE-2020-11998_5-15-12.md) 🔴 

**名称:** CVE-2020-11998 Apache ActiveMQ JMX RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-17  
**POC仓库:** [apache__activemq_CVE-2020-11998_5-15-12](https://github.com/shoucheng3/apache__activemq_CVE-2020-11998_5-15-12)  

---

### [CVE-2021-4178](CVE-2021-4178-shoucheng3_fabric8io__kubernetes-client_CVE-2021-4178_5-0-2.md) 🔴 ✅

**名称:** CVE-2021-4178 - fabric8 kubernetes-client 反序列化漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可导致任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-17  
**POC仓库:** [fabric8io__kubernetes-client_CVE-2021-4178_5-0-2](https://github.com/shoucheng3/fabric8io__kubernetes-client_CVE-2021-4178_5-0-2)  

---

### [CVE-2020-35460](CVE-2020-35460-shoucheng3_joniles__mpxj_CVE-2020-35460_8-3-4.md) 🟡 

**名称:** CVE-2020-35460 - MPXJ Directory Traversal  
**类型:** 目录遍历  
**风险:** 中危，可能导致任意文件写入  
**投毒风险:** 5%  
**发现时间:** 2025-08-17  
**POC仓库:** [joniles__mpxj_CVE-2020-35460_8-3-4](https://github.com/shoucheng3/joniles__mpxj_CVE-2020-35460_8-3-4)  

---

### [CVE-2018-1260](CVE-2018-1260-shoucheng3_SpringSource__spring-security-oauth_CVE-2018-1260_2-3-2-RELEASE.md) 🔴 

**名称:** CVE-2018-1260 - Spring Security OAuth 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-17  
**POC仓库:** [SpringSource__spring-security-oauth_CVE-2018-1260_2-3-2-RELEASE](https://github.com/shoucheng3/SpringSource__spring-security-oauth_CVE-2018-1260_2-3-2-RELEASE)  

---

### [CVE-2022-32287](CVE-2022-32287-shoucheng3_apache__uima-uimaj_CVE-2022-32287_3-3-0.md) 🔴 ✅

**名称:** CVE-2022-32287-Apache UIMA-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致任意文件写入  
**投毒风险:** 10%  
**发现时间:** 2025-08-17  
**POC仓库:** [apache__uima-uimaj_CVE-2022-32287_3-3-0](https://github.com/shoucheng3/apache__uima-uimaj_CVE-2022-32287_3-3-0)  

---

### [CVE-2020-5410](CVE-2020-5410-dead5nd_config-demo.md) 🔴 ✅

**名称:** CVE-2020-5410 Spring Cloud Config 目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-08-17  
**POC仓库:** [config-demo](https://github.com/dead5nd/config-demo)  

---

### [CVE-2020-5410](CVE-2020-5410-osamahamad_CVE-2020-5410-POC.md) 🔴 ✅

**名称:** CVE-2020-5410 Spring Cloud Config 目录遍历漏洞  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-08-17  
**POC仓库:** [CVE-2020-5410-POC](https://github.com/osamahamad/CVE-2020-5410-POC)  

---

### [CVE-2020-5410](CVE-2020-5410-shoucheng3_spring-cloud__spring-cloud-config_CVE-2020-5410_2-1-8-RELEASE.md) 🔴 ✅

**名称:** CVE-2020-5410 Spring Cloud Config 目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-08-17  
**POC仓库:** [spring-cloud__spring-cloud-config_CVE-2020-5410_2-1-8-RELEASE](https://github.com/shoucheng3/spring-cloud__spring-cloud-config_CVE-2020-5410_2-1-8-RELEASE)  

---

### [CVE-2022-33140](CVE-2022-33140-shoucheng3_apache__nifi_CVE-2022-33140_1-16-2.md) 🔴 ✅

**名称:** CVE-2022-33140-Apache NiFi/Registry-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-17  
**POC仓库:** [apache__nifi_CVE-2022-33140_1-16-2](https://github.com/shoucheng3/apache__nifi_CVE-2022-33140_1-16-2)  

---

### [CVE-2022-46166](CVE-2022-46166-shoucheng3_codecentric__spring-boot-admin_CVE-2022-46166_2-6-9.md) 🔴 ✅

**名称:** CVE-2022-46166-Spring Boot Admin-代码注入  
**类型:** 代码注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-08-17  
**POC仓库:** [codecentric__spring-boot-admin_CVE-2022-46166_2-6-9](https://github.com/shoucheng3/codecentric__spring-boot-admin_CVE-2022-46166_2-6-9)  

---

### [CVE-2022-29577](CVE-2022-29577-shoucheng3_nahsra__antisamy_CVE-2022-29577_1-6-6-1.md) 🟡 ✅

**名称:** CVE-2022-29577-OWASP AntiSamy-XSS  
**类型:** XSS  
**风险:** 中危，可能导致跨站脚本攻击  
**投毒风险:** 0%  
**发现时间:** 2025-08-17  
**POC仓库:** [nahsra__antisamy_CVE-2022-29577_1-6-6-1](https://github.com/shoucheng3/nahsra__antisamy_CVE-2022-29577_1-6-6-1)  

---

### [CVE-2022-25173](CVE-2022-25173-shoucheng3_jenkinsci__workflow-cps-plugin_CVE-2022-25173_2646-v6ed3b5b01ff1.md) 🔴 ✅

**名称:** CVE-2022-25173 - Jenkins Pipeline: Groovy Plugin OS 命令注入  
**类型:** OS 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-17  
**POC仓库:** [jenkinsci__workflow-cps-plugin_CVE-2022-25173_2646-v6ed3b5b01ff1](https://github.com/shoucheng3/jenkinsci__workflow-cps-plugin_CVE-2022-25173_2646-v6ed3b5b01ff1)  

---

### [CVE-2025-8088](CVE-2025-8088-pexlexity_WinRAR-CVE-2025-8088-Path-Traversal-PoC.md) 🔴 ✅

**名称:** CVE-2025-8088-WinRAR路径遍历  
**类型:** 路径遍历  
**风险:** 高危，允许攻击者通过构造恶意压缩文件执行任意代码。  
**投毒风险:** 5%  
**发现时间:** 2025-08-17  
**POC仓库:** [WinRAR-CVE-2025-8088-Path-Traversal-PoC](https://github.com/pexlexity/WinRAR-CVE-2025-8088-Path-Traversal-PoC)  

---

### [CVE-2025-32778](CVE-2025-32778-00xCanelo_CVE-2025-32778.md) 🔴 ✅

**名称:** CVE-2025-32778 - Web-Check Command Injection  
**类型:** 命令注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-17  
**POC仓库:** [CVE-2025-32778](https://github.com/00xCanelo/CVE-2025-32778)  

---

### [CVE-2023-45277](CVE-2023-45277-shoucheng3_yamcs__yamcs_CVE-2023-45277_5-8-6.md) 🔴 

**名称:** CVE-2023-45277-Yamcs-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-08-17  
**POC仓库:** [yamcs__yamcs_CVE-2023-45277_5-8-6](https://github.com/shoucheng3/yamcs__yamcs_CVE-2023-45277_5-8-6)  

---

### [CVE-2021-30181](CVE-2021-30181-shoucheng3_apache__incubator-dubbo_CVE-2021-30181_2-6-8.md) 🔴 ✅

**名称:** CVE-2021-30181-Apache Dubbo-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-08-17  
**POC仓库:** [apache__incubator-dubbo_CVE-2021-30181_2-6-8](https://github.com/shoucheng3/apache__incubator-dubbo_CVE-2021-30181_2-6-8)  

---

### [CVE-2024-28397](CVE-2024-28397-CYBER-WARRIOR-SEC_CVE-2024-28397-js2py-Sandbox-Escape.md) 🔴 ✅

**名称:** CVE-2024-28397-js2py-Sandbox-Escape  
**类型:** 代码注入/沙箱逃逸  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-17  
**POC仓库:** [CVE-2024-28397-js2py-Sandbox-Escape](https://github.com/CYBER-WARRIOR-SEC/CVE-2024-28397-js2py-Sandbox-Escape)  

---

### [CVE-2024-28397](CVE-2024-28397-Marven11_CVE-2024-28397-js2py-Sandbox-Escape.md) 🔴 ✅

**名称:** CVE-2024-28397-js2py-沙箱逃逸  
**类型:** 代码注入/沙箱逃逸  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-17  
**POC仓库:** [CVE-2024-28397-js2py-Sandbox-Escape](https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape)  

---

### [CVE-2024-28397](CVE-2024-28397-waleed-hassan569_CVE-2024-28397-command-execution-poc.md) 🔴 ✅

**名称:** CVE-2024-28397-js2py-Sandbox-Escape  
**类型:** 代码注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-17  
**POC仓库:** [CVE-2024-28397-command-execution-poc](https://github.com/waleed-hassan569/CVE-2024-28397-command-execution-poc)  

---

### [CVE-2019-12185](CVE-2019-12185-Drew-Alleman_CVE-2019-12185.md) 🔴 ✅

**名称:** CVE-2019-12185-eLabFTW-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-17  
**POC仓库:** [CVE-2019-12185](https://github.com/Drew-Alleman/CVE-2019-12185)  

---

### [CVE-2019-12185](CVE-2019-12185-fuzzlove_eLabFTW-1.8.5-EntityController-Arbitrary-File-Upload-RCE.md) 🔴 ✅

**名称:** CVE-2019-12185-eLabFTW-Arbitrary File Upload  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-17  
**POC仓库:** [eLabFTW-1.8.5-EntityController-Arbitrary-File-Upload-RCE](https://github.com/fuzzlove/eLabFTW-1.8.5-EntityController-Arbitrary-File-Upload-RCE)  

---

### [CVE-2025-50165](CVE-2025-50165-allinsthon_CVE-2025-50165.md)  ✅

**名称:** CVE-2025-50165 - Windows Graphics Component Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 严重，可能导致远程代码执行和系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-16  
**POC仓库:** [CVE-2025-50165](https://github.com/allinsthon/CVE-2025-50165)  

---

### [CVE-2016-6812](CVE-2016-6812-shoucheng3_asf__cxf_CVE-2016-6812_3-0-11.md) 🟡 

**名称:** CVE-2016-6812-Apache CXF-XSS  
**类型:** XSS  
**风险:** 中危，可能导致客户端受到恶意脚本攻击  
**投毒风险:** 5%  
**发现时间:** 2025-08-16  
**POC仓库:** [asf__cxf_CVE-2016-6812_3-0-11](https://github.com/shoucheng3/asf__cxf_CVE-2016-6812_3-0-11)  

---

### [CVE-2023-36471](CVE-2023-36471-shoucheng3_xwiki__xwiki-commons_CVE-2023-36471_14-10-5.md) 🔴 ✅

**名称:** CVE-2023-36471-xwiki-commons-HTML注入  
**类型:** HTML注入/远程代码执行  
**风险:** 高危，可能导致钓鱼攻击和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-16  
**POC仓库:** [xwiki__xwiki-commons_CVE-2023-36471_14-10-5](https://github.com/shoucheng3/xwiki__xwiki-commons_CVE-2023-36471_14-10-5)  

---

### [CVE-2023-37908](CVE-2023-37908-shoucheng3_xwiki__xwiki-rendering_CVE-2023-37908_14-10-3.md) 🔴 

**名称:** CVE-2023-37908-XWiki Rendering-XSS  
**类型:** XSS  
**风险:** 高危，可能导致远程代码执行，信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-08-16  
**POC仓库:** [xwiki__xwiki-rendering_CVE-2023-37908_14-10-3](https://github.com/shoucheng3/xwiki__xwiki-rendering_CVE-2023-37908_14-10-3)  

---

### [CVE-2022-31192](CVE-2022-31192-shoucheng3_DSpace__DSpace_CVE-2022-31192_5-10.md) 🟡 

**名称:** CVE-2022-31192-DSpace-XSS  
**类型:** 跨站脚本攻击 (XSS)  
**风险:** 中危，可能导致用户信息泄露和恶意脚本执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-16  
**POC仓库:** [DSpace__DSpace_CVE-2022-31192_5-10](https://github.com/shoucheng3/DSpace__DSpace_CVE-2022-31192_5-10)  

---

### [CVE-2018-1047](CVE-2018-1047-shoucheng3_wildfly__wildfly_CVE-2018-1047_11-0-0-Final.md) 🔴 ✅

**名称:** CVE-2018-1047-Wildfly-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感文件泄露  
**投毒风险:** 0%  
**发现时间:** 2025-08-16  
**POC仓库:** [wildfly__wildfly_CVE-2018-1047_11-0-0-Final](https://github.com/shoucheng3/wildfly__wildfly_CVE-2018-1047_11-0-0-Final)  

---

### [CVE-2022-25842](CVE-2022-25842-shoucheng3_alibaba__one-java-agent_CVE-2022-25842_0-0-1.md) 🟡 ✅

**名称:** CVE-2022-25842-com.alibaba.oneagent-Zip Slip  
**类型:** Zip Slip  
**风险:** 中危，可能导致任意文件写入和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-16  
**POC仓库:** [alibaba__one-java-agent_CVE-2022-25842_0-0-1](https://github.com/shoucheng3/alibaba__one-java-agent_CVE-2022-25842_0-0-1)  

---

### [CVE-2020-13973](CVE-2020-13973-epicosy_json-sanitizer.md) 🟡 ✅

**名称:** CVE-2020-13973-OWASP json-sanitizer-XSS  
**类型:** XSS  
**风险:** 中危，可能允许攻击者在受害者浏览器中执行恶意脚本  
**投毒风险:** 0%  
**发现时间:** 2025-08-16  
**POC仓库:** [json-sanitizer](https://github.com/epicosy/json-sanitizer)  

---

### [CVE-2020-13973](CVE-2020-13973-shoucheng3_OWASP__json-sanitizer_CVE-2020-13973_1-2-0.md) 🟡 

**名称:** CVE-2020-13973-OWASP json-sanitizer-XSS  
**类型:** XSS  
**风险:** 中危，可能导致用户数据泄露和恶意脚本执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-16  
**POC仓库:** [OWASP__json-sanitizer_CVE-2020-13973_1-2-0](https://github.com/shoucheng3/OWASP__json-sanitizer_CVE-2020-13973_1-2-0)  

---

### [CVE-2022-26884](CVE-2022-26884-shoucheng3_apache__dolphinscheduler_CVE-2022-26884_2-0-5.md) 🟡 ✅

**名称:** CVE-2022-26884-Apache DolphinScheduler-文件读取  
**类型:** 路径遍历  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-08-16  
**POC仓库:** [apache__dolphinscheduler_CVE-2022-26884_2-0-5](https://github.com/shoucheng3/apache__dolphinscheduler_CVE-2022-26884_2-0-5)  

---

### [CVE-2022-23457](CVE-2022-23457-shoucheng3_ESAPI__esapi-java-legacy_CVE-2022-23457_2-2-3-1.md) 🔴 ✅

**名称:** CVE-2022-23457-ESAPI-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感文件读取和控制流绕过  
**投毒风险:** 1%  
**发现时间:** 2025-08-16  
**POC仓库:** [ESAPI__esapi-java-legacy_CVE-2022-23457_2-2-3-1](https://github.com/shoucheng3/ESAPI__esapi-java-legacy_CVE-2022-23457_2-2-3-1)  

---

### [CVE-2021-29425](CVE-2021-29425-shoucheng3_asf__commons-io_CVE-2021-29425_2-6.md) 🟡 ✅

**名称:** CVE-2021-29425-Apache Commons IO-路径遍历  
**类型:** 路径遍历  
**风险:** 中危，可能导致文件访问限制绕过  
**投毒风险:** 0%  
**发现时间:** 2025-08-16  
**POC仓库:** [asf__commons-io_CVE-2021-29425_2-6](https://github.com/shoucheng3/asf__commons-io_CVE-2021-29425_2-6)  

---

### [CVE-2019-0225](CVE-2019-0225-shoucheng3_apache__jspwiki_CVE-2019-0225_2-11-0-M2.md) 🔴 ✅

**名称:** CVE-2019-0225-Apache JSPWiki-本地文件包含  
**类型:** 本地文件包含(LFI)  
**风险:** 高危，可能导致用户数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-08-16  
**POC仓库:** [apache__jspwiki_CVE-2019-0225_2-11-0-M2](https://github.com/shoucheng3/apache__jspwiki_CVE-2019-0225_2-11-0-M2)  

---

### [CVE-2018-12542](CVE-2018-12542-shoucheng3_vert-x3__vertx-web_CVE-2018-12542_3-5-3-CR1.md) 🟡 

**名称:** CVE-2018-12542-Eclipse Vert.x-路径遍历  
**类型:** 路径遍历  
**风险:** 中危，可能导致敏感文件泄露  
**投毒风险:** 10%  
**发现时间:** 2025-08-16  
**POC仓库:** [vert-x3__vertx-web_CVE-2018-12542_3-5-3-CR1](https://github.com/shoucheng3/vert-x3__vertx-web_CVE-2018-12542_3-5-3-CR1)  

---

### [CVE-2023-37582](CVE-2023-37582-shoucheng3_apache__rocketmq_CVE-2023-37582_4-9-6.md) 🔴 ✅

**名称:** CVE-2023-37582-Apache RocketMQ-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-16  
**POC仓库:** [apache__rocketmq_CVE-2023-37582_4-9-6](https://github.com/shoucheng3/apache__rocketmq_CVE-2023-37582_4-9-6)  

---

### [CVE-2022-4361](CVE-2022-4361-shoucheng3_keycloak__keycloak_CVE-2022-4361_21-1-1.md) 🔴 

**名称:** CVE-2022-4361-Keycloak-XSS  
**类型:** 跨站脚本攻击 (XSS)  
**风险:** 高危，可能导致账户劫持、信息泄露和恶意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-16  
**POC仓库:** [keycloak__keycloak_CVE-2022-4361_21-1-1](https://github.com/shoucheng3/keycloak__keycloak_CVE-2022-4361_21-1-1)  

---

### [CVE-2025-24813](CVE-2025-24813-thebringerofdeath789_CVE-2025-24813.md) 🔴 ✅

**名称:** CVE-2025-24813-Apache Tomcat-路径遍历/反序列化  
**类型:** 路径遍历/反序列化  
**风险:** 高危，可能导致远程代码执行和信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-08-16  
**POC仓库:** [CVE-2025-24813](https://github.com/thebringerofdeath789/CVE-2025-24813)  

---

### [CVE-2024-32019](CVE-2024-32019-sPhyos_cve-2024-32019-PoC.md) 🔴 ✅

**名称:** CVE-2024-32019 - Netdata ndsudo 本地权限提升  
**类型:** 本地权限提升  
**风险:** 高危，允许低权限用户提升至 root 权限  
**投毒风险:** 0%  
**发现时间:** 2025-08-16  
**POC仓库:** [cve-2024-32019-PoC](https://github.com/sPhyos/cve-2024-32019-PoC)  

---

### [CVE-2022-0944](CVE-2022-0944-LipeOzyy_SQLPad-RCE-Exploit-CVE-2022-0944.md) 🔴 ✅

**名称:** CVE-2022-0944-sqlpad-RCE  
**类型:** 模板注入导致RCE  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-16  
**POC仓库:** [SQLPad-RCE-Exploit-CVE-2022-0944](https://github.com/LipeOzyy/SQLPad-RCE-Exploit-CVE-2022-0944)  

---

### [CVE-2011-4367](CVE-2011-4367-shoucheng3_apache__myfaces_CVE-2011-4367_2-0-11.md) 🔴 ✅

**名称:** CVE-2011-4367-Apache MyFaces Core-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-08-16  
**POC仓库:** [apache__myfaces_CVE-2011-4367_2-0-11](https://github.com/shoucheng3/apache__myfaces_CVE-2011-4367_2-0-11)  

---

### [CVE-2025-27591](CVE-2025-27591-umutcamliyurt_CVE-2025-27591.md) 🔴 ✅

**名称:** CVE-2025-27591-below-权限提升  
**类型:** 权限提升  
**风险:** 高危，本地用户可提升至root权限  
**投毒风险:** 0%  
**发现时间:** 2025-08-16  
**POC仓库:** [CVE-2025-27591](https://github.com/umutcamliyurt/CVE-2025-27591)  

---

### [CVE-2023-32070](CVE-2023-32070-shoucheng3_xwiki__xwiki-rendering_CVE-2023-32070_14-5.md) 🔴 ✅

**名称:** CVE-2023-32070-XWiki-XSS  
**类型:** 跨站脚本 (XSS)  
**风险:** 高危，可能导致账户劫持、信息泄露或恶意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-16  
**POC仓库:** [xwiki__xwiki-rendering_CVE-2023-32070_14-5](https://github.com/shoucheng3/xwiki__xwiki-rendering_CVE-2023-32070_14-5)  

---

### [CVE-2020-27219](CVE-2020-27219-shoucheng3_eclipse__hawkbit_CVE-2020-27219_0-3-0M6.md) 🟡 ✅

**名称:** CVE-2020-27219-Eclipse Hawkbit-XSS  
**类型:** XSS  
**风险:** 中危，可能导致用户凭据泄露和恶意脚本执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-16  
**POC仓库:** [eclipse__hawkbit_CVE-2020-27219_0-3-0M6](https://github.com/shoucheng3/eclipse__hawkbit_CVE-2020-27219_0-3-0M6)  

---

### [CVE-2020-2261](CVE-2020-2261-shoucheng3_jenkinsci__perfecto-plugin_CVE-2020-2261_1-17.md) 🔴 ✅

**名称:** CVE-2020-2261 Jenkins Perfecto Plugin 命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-16  
**POC仓库:** [jenkinsci__perfecto-plugin_CVE-2020-2261_1-17](https://github.com/shoucheng3/jenkinsci__perfecto-plugin_CVE-2020-2261_1-17)  

---

### [CVE-2025-6934](CVE-2025-6934-0xgh057r3c0n_CVE-2025-6934.md) 🔴 ✅

**名称:** CVE-2025-6934 - Opal Estate Pro 未授权提权  
**类型:** 权限提升  
**风险:** 高危，未授权用户可以创建管理员账户，完全控制 WordPress 站点  
**投毒风险:** 10%  
**发现时间:** 2025-08-16  
**POC仓库:** [CVE-2025-6934](https://github.com/0xgh057r3c0n/CVE-2025-6934)  

---

### [CVE-2021-44667](CVE-2021-44667-shoucheng3_alibaba__nacos_CVE-2021-44667_2-0-3.md) 🟡 

**名称:** CVE-2021-44667-Nacos-XSS  
**类型:** XSS  
**风险:** 中危，可能导致用户凭据泄露或恶意脚本执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-16  
**POC仓库:** [alibaba__nacos_CVE-2021-44667_2-0-3](https://github.com/shoucheng3/alibaba__nacos_CVE-2021-44667_2-0-3)  

---

### [CVE-2016-10726](CVE-2016-10726-shoucheng3_DSpace__DSpace_CVE-2016-10726_4-4.md) 🟡 ✅

**名称:** CVE-2016-10726-DSpace-目录遍历  
**类型:** 目录遍历  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-08-16  
**POC仓库:** [DSpace__DSpace_CVE-2016-10726_4-4](https://github.com/shoucheng3/DSpace__DSpace_CVE-2016-10726_4-4)  

---

### [CVE-2022-23082](CVE-2022-23082-shoucheng3_whitesource__curekit_CVE-2022-23082_1-1-3.md) 🔴 

**名称:** CVE-2022-23082-CureKit-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-08-16  
**POC仓库:** [whitesource__curekit_CVE-2022-23082_1-1-3](https://github.com/shoucheng3/whitesource__curekit_CVE-2022-23082_1-1-3)  

---

### [CVE-2019-17572](CVE-2019-17572-shoucheng3_apache__rocketmq_CVE-2019-17572_4-6-0.md) 🔴 ✅

**名称:** CVE-2019-17572 - Apache RocketMQ 目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露或任意文件读取  
**投毒风险:** 1%  
**发现时间:** 2025-08-16  
**POC仓库:** [apache__rocketmq_CVE-2019-17572_4-6-0](https://github.com/shoucheng3/apache__rocketmq_CVE-2019-17572_4-6-0)  

---

### [CVE-2023-34478](CVE-2023-34478-shoucheng3_apache__shiro_CVE-2023-34478_1-11-0.md) 🔴 ✅

**名称:** CVE-2023-34478-Apache Shiro路径遍历导致认证绕过  
**类型:** 路径遍历  
**风险:** 高危，可能导致认证绕过  
**投毒风险:** 5%  
**发现时间:** 2025-08-16  
**POC仓库:** [apache__shiro_CVE-2023-34478_1-11-0](https://github.com/shoucheng3/apache__shiro_CVE-2023-34478_1-11-0)  

---

### [CVE-2018-10001](CVE-2018-10001-shoucheng3_rhuss__jolokia_CVE-2018-1000129_1-4-0.md) 🟡 

**名称:** CVE-2018-10001-FFmpeg-utvideodec.c-拒绝服务  
**类型:** 拒绝服务 (DoS)  
**风险:** 中危，可能导致服务中断  
**投毒风险:** 0%  
**发现时间:** 2025-08-16  
**POC仓库:** [rhuss__jolokia_CVE-2018-1000129_1-4-0](https://github.com/shoucheng3/rhuss__jolokia_CVE-2018-1000129_1-4-0)  

---

### [CVE-2022-37422](CVE-2022-37422-shoucheng3_payara__Payara_CVE-2022-37422_5-2022-2.md) 🔴 ✅

**名称:** CVE-2022-37422-Payara-目录穿越  
**类型:** 目录穿越  
**风险:** 高危，可能导致未经授权的文件访问  
**投毒风险:** 1%  
**发现时间:** 2025-08-16  
**POC仓库:** [payara__Payara_CVE-2022-37422_5-2022-2](https://github.com/shoucheng3/payara__Payara_CVE-2022-37422_5-2022-2)  

---

### [CVE-2014-3656](CVE-2014-3656-shoucheng3_keycloak__keycloak_CVE-2014-3656_1-0-5-Final.md) 🟡 

**名称:** CVE-2014-3656-JBoss KeyCloak-XSS  
**类型:** XSS  
**风险:** 中危，可能导致用户凭据泄露和会话劫持  
**投毒风险:** 0%  
**发现时间:** 2025-08-16  
**POC仓库:** [keycloak__keycloak_CVE-2014-3656_1-0-5-Final](https://github.com/shoucheng3/keycloak__keycloak_CVE-2014-3656_1-0-5-Final)  

---

### [CVE-2019-0207](CVE-2019-0207-shoucheng3_asf__tapestry-5_CVE-2019-0207_5-4-4.md) 🔴 ✅

**名称:** CVE-2019-0207-Apache Tapestry-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-08-16  
**POC仓库:** [asf__tapestry-5_CVE-2019-0207_5-4-4](https://github.com/shoucheng3/asf__tapestry-5_CVE-2019-0207_5-4-4)  

---

### [CVE-2025-49667](CVE-2025-49667-Yuri08loveElaina_CVE-2025-49667.md) 🔴 ✅

**名称:** CVE-2025-49667 - Windows Win32 Kernel Subsystem权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，本地权限提升至SYSTEM  
**投毒风险:** 10%  
**发现时间:** 2025-08-16  
**POC仓库:** [CVE-2025-49667](https://github.com/Yuri08loveElaina/CVE-2025-49667)  

---

### [CVE-2019-10392](CVE-2019-10392-shoucheng3_jenkinsci__git-client-plugin_CVE-2019-10392_2-8-4.md) 🔴 ✅

**名称:** CVE-2019-10392-Jenkins Git Client Plugin-OS命令注入  
**类型:** OS命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-16  
**POC仓库:** [jenkinsci__git-client-plugin_CVE-2019-10392_2-8-4](https://github.com/shoucheng3/jenkinsci__git-client-plugin_CVE-2019-10392_2-8-4)  

---

### [CVE-2023-37582](CVE-2023-37582-shoucheng3_apache__rocketmq_CVE-2023-37582_4-9-6.md) 🔴 ✅

**名称:** CVE-2023-37582-Apache RocketMQ-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-08-16  
**POC仓库:** [apache__rocketmq_CVE-2023-37582_4-9-6](https://github.com/shoucheng3/apache__rocketmq_CVE-2023-37582_4-9-6)  

---

### [CVE-2020-2261](CVE-2020-2261-shoucheng3_jenkinsci__perfecto-plugin_CVE-2020-2261_1-17.md) 🔴 ✅

**名称:** CVE-2020-2261-Jenkins Perfecto Plugin-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-16  
**POC仓库:** [jenkinsci__perfecto-plugin_CVE-2020-2261_1-17](https://github.com/shoucheng3/jenkinsci__perfecto-plugin_CVE-2020-2261_1-17)  

---

### [CVE-2018-11762](CVE-2018-11762-shoucheng3_apache__tika_CVE-2018-11762_1-18.md) 🟡 ✅

**名称:** CVE-2018-11762-Apache Tika-Zip Slip  
**类型:** Zip Slip  
**风险:** 中危，可能导致任意文件覆盖  
**投毒风险:** 0%  
**发现时间:** 2025-08-16  
**POC仓库:** [apache__tika_CVE-2018-11762_1-18](https://github.com/shoucheng3/apache__tika_CVE-2018-11762_1-18)  

---

### [CVE-2020-27219](CVE-2020-27219-shoucheng3_eclipse__hawkbit_CVE-2020-27219_0-3-0M6.md) 🟡 ✅

**名称:** CVE-2020-27219-Eclipse Hawkbit-XSS  
**类型:** 跨站脚本 (XSS)  
**风险:** 中危，可能导致用户信息泄露或恶意脚本执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-16  
**POC仓库:** [eclipse__hawkbit_CVE-2020-27219_0-3-0M6](https://github.com/shoucheng3/eclipse__hawkbit_CVE-2020-27219_0-3-0M6)  

---

### [CVE-2023-32070](CVE-2023-32070-shoucheng3_xwiki__xwiki-rendering_CVE-2023-32070_14-5.md) 🔴 ✅

**名称:** CVE-2023-32070-XWiki-XSS  
**类型:** XSS（跨站脚本）  
**风险:** 高危，可能导致用户凭证泄露、恶意代码执行、页面内容篡改等  
**投毒风险:** 10%  
**发现时间:** 2025-08-16  
**POC仓库:** [xwiki__xwiki-rendering_CVE-2023-32070_14-5](https://github.com/shoucheng3/xwiki__xwiki-rendering_CVE-2023-32070_14-5)  

---

### [CVE-2025-8088](CVE-2025-8088-pentestfunctions_CVE-2025-8088-Multi-Document.md) 🔴 ✅

**名称:** CVE-2025-8088-WinRAR-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-16  
**POC仓库:** [CVE-2025-8088-Multi-Document](https://github.com/pentestfunctions/CVE-2025-8088-Multi-Document)  

---

### [CVE-2025-54352](CVE-2025-54352-ScarryParrot_-CVE-2025-54352.md)  ✅

**名称:** CVE-2025-54352-WordPress-私有/草稿文章标题泄露  
**类型:** 信息泄露  
**风险:** 低危，可能暴露部分未公开的信息  
**投毒风险:** 10%  
**发现时间:** 2025-08-16  
**POC仓库:** [-CVE-2025-54352](https://github.com/ScarryParrot/-CVE-2025-54352)  

---

### [CVE-2025-50154](CVE-2025-50154-Ash1996x_CVE-2025-50154-Aggressor-Script.md) 🟡 ✅

**名称:** CVE-2025-50154-Windows File Explorer Spoofing Vulnerability  
**类型:** 信息泄露/NTLM Hash Extraction  
**风险:** 中危，可能导致凭据泄露和网络欺骗  
**投毒风险:** 10%  
**发现时间:** 2025-08-16  
**POC仓库:** [CVE-2025-50154-Aggressor-Script](https://github.com/Ash1996x/CVE-2025-50154-Aggressor-Script)  

---

### [CVE-2018-7422](CVE-2018-7422-0x00-0x00_CVE-2018-7422.md) 🔴 ✅

**名称:** CVE-2018-7422 Site Editor WordPress Plugin 本地文件包含  
**类型:** 本地文件包含 (LFI)  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-08-16  
**POC仓库:** [CVE-2018-7422](https://github.com/0x00-0x00/CVE-2018-7422)  

---

### [CVE-2018-7422](CVE-2018-7422-JacobEbben_CVE-2018-7422.md) 🔴 ✅

**名称:** CVE-2018-7422 Site Editor WordPress Plugin Local File Inclusion  
**类型:** 本地文件包含 (LFI)  
**风险:** 高危，允许未经授权的远程攻击者读取服务器上的任意文件。  
**投毒风险:** 0%  
**发现时间:** 2025-08-16  
**POC仓库:** [CVE-2018-7422](https://github.com/JacobEbben/CVE-2018-7422)  

---

### [CVE-2018-7422](CVE-2018-7422-ndr-repo_CVE-2018-7422.md) 🔴 ✅

**名称:** CVE-2018-7422-Site Editor WordPress Plugin-本地文件包含  
**类型:** 本地文件包含 (LFI)  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-08-16  
**POC仓库:** [CVE-2018-7422](https://github.com/ndr-repo/CVE-2018-7422)  

---

### [CVE-2025-8088](CVE-2025-8088-0xAbolfazl_CVE-2025-8088-WinRAR-PathTraversal-PoC.md) 🔴 

**名称:** CVE-2025-8088 WinRAR 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-08-15  
**POC仓库:** [CVE-2025-8088-WinRAR-PathTraversal-PoC](https://github.com/0xAbolfazl/CVE-2025-8088-WinRAR-PathTraversal-PoC)  

---

### [CVE-2024-3660](CVE-2024-3660-aaryanbhujang_CVE-2024-3660-PoC.md) 🔴 ✅

**名称:** CVE-2024-3660-Keras框架代码注入  
**类型:** 代码注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-08-15  
**POC仓库:** [CVE-2024-3660-PoC](https://github.com/aaryanbhujang/CVE-2024-3660-PoC)  

---

### [CVE-2025-31324](CVE-2025-31324-antichainalysis_sap-netweaver-0day-CVE-2025-31324.md)  ✅

**名称:** CVE-2025-31324 - SAP NetWeaver Visual Composer Metadata Uploader 未授权文件上传  
**类型:** 未授权文件上传  
**风险:** 严重，可能导致远程代码执行，系统完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-08-15  
**POC仓库:** [sap-netweaver-0day-CVE-2025-31324](https://github.com/antichainalysis/sap-netweaver-0day-CVE-2025-31324)  

---

### [CVE-2025-25256](CVE-2025-25256-watchtowrlabs_watchTowr-vs-FortiSIEM-CVE-2025-25256.md) 🔴 ✅

**名称:** CVE-2025-25256-FortiSIEM-OS命令注入  
**类型:** OS命令注入  
**风险:** 高危，可能导致远程代码执行，完全控制系统  
**投毒风险:** 5%  
**发现时间:** 2025-08-15  
**POC仓库:** [watchTowr-vs-FortiSIEM-CVE-2025-25256](https://github.com/watchtowrlabs/watchTowr-vs-FortiSIEM-CVE-2025-25256)  

---

### [CVE-2025-8971](CVE-2025-8971-byteReaper77_CVE-2025-8971.md) 🔴 ✅

**名称:** CVE-2025-8971-Online Tour and Travel Management System-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、数据篡改和服务器控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-15  
**POC仓库:** [CVE-2025-8971](https://github.com/byteReaper77/CVE-2025-8971)  

---

### [CVE-2017-11317](CVE-2017-11317-bao7uo_RAU_crypto.md) 🔴 ✅

**名称:** CVE-2017-11317-Telerik-UI-ASP.NET-AJAX-Unrestricted-File-Upload  
**类型:** 文件上传  
**风险:** 高危，可导致任意文件上传和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-15  
**POC仓库:** [RAU_crypto](https://github.com/bao7uo/RAU_crypto)  

---

### [CVE-2017-11317](CVE-2017-11317-KasunPriyashan_Telerik-UI-ASP.NET-AJAX-Exploitation.md) 🔴 ✅

**名称:** CVE-2017-11317 Telerik UI for ASP.NET AJAX Unrestricted File Upload  
**类型:** 未限制的文件上传/弱加密  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-15  
**POC仓库:** [Telerik-UI-ASP.NET-AJAX-Exploitation](https://github.com/KasunPriyashan/Telerik-UI-ASP.NET-AJAX-Exploitation)  

---

### [CVE-2017-11317](CVE-2017-11317-0xr2r_CVE-2017-11317-auto-exploit-.md) 🔴 ✅

**名称:** CVE-2017-11317-Telerik UI for ASP.NET AJAX-任意文件上传/远程代码执行  
**类型:** 任意文件上传/远程代码执行  
**风险:** 高危，可能导致任意文件上传和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-15  
**POC仓库:** [CVE-2017-11317-auto-exploit-](https://github.com/0xr2r/CVE-2017-11317-auto-exploit-)  

---

### [CVE-2011-4367](CVE-2011-4367-shoucheng3_apache__myfaces_CVE-2011-4367_2-0-11.md) 🔴 ✅

**名称:** CVE-2011-4367-Apache MyFaces Core-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-08-15  
**POC仓库:** [apache__myfaces_CVE-2011-4367_2-0-11](https://github.com/shoucheng3/apache__myfaces_CVE-2011-4367_2-0-11)  

---

### [CVE-2019-0207](CVE-2019-0207-shoucheng3_tapestry-5-cve-2019-0207.md) 🟡 ✅

**名称:** CVE-2019-0207-Apache Tapestry-路径遍历  
**类型:** 路径遍历  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-08-15  
**POC仓库:** [tapestry-5-cve-2019-0207](https://github.com/shoucheng3/tapestry-5-cve-2019-0207)  

---

### [CVE-2022-37422](CVE-2022-37422-shoucheng3_payara__Payara_CVE-2022-37422_5-2022-2.md) 🔴 

**名称:** CVE-2022-37422-Payara-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感文件泄露和远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-08-15  
**POC仓库:** [payara__Payara_CVE-2022-37422_5-2022-2](https://github.com/shoucheng3/payara__Payara_CVE-2022-37422_5-2022-2)  

---

### [CVE-2021-44667](CVE-2021-44667-shoucheng3_alibaba__nacos_CVE-2021-44667_2-0-3.md) 🟡 

**名称:** CVE-2021-44667-Nacos-XSS  
**类型:** 跨站脚本 (XSS)  
**风险:** 中危，可能导致用户凭据泄露或执行恶意脚本  
**投毒风险:** 5%  
**发现时间:** 2025-08-15  
**POC仓库:** [alibaba__nacos_CVE-2021-44667_2-0-3](https://github.com/shoucheng3/alibaba__nacos_CVE-2021-44667_2-0-3)  

---

### [CVE-2022-23082](CVE-2022-23082-shoucheng3_whitesource__curekit_CVE-2022-23082_1-1-3.md) 🔴 ✅

**名称:** CVE-2022-23082-CureKit-Path Traversal  
**类型:** Path Traversal  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-08-15  
**POC仓库:** [whitesource__curekit_CVE-2022-23082_1-1-3](https://github.com/shoucheng3/whitesource__curekit_CVE-2022-23082_1-1-3)  

---

### [CVE-2014-3656](CVE-2014-3656-shoucheng3_keycloak__keycloak_CVE-2014-3656_1-0-5-Final.md) 🟡 

**名称:** CVE-2014-3656-JBoss KeyCloak-XSS  
**类型:** XSS  
**风险:** 中危，可能导致用户凭据泄露或会话劫持  
**投毒风险:** 0%  
**发现时间:** 2025-08-15  
**POC仓库:** [keycloak__keycloak_CVE-2014-3656_1-0-5-Final](https://github.com/shoucheng3/keycloak__keycloak_CVE-2014-3656_1-0-5-Final)  

---

### [CVE-2019-17572](CVE-2019-17572-shoucheng3_apache__rocketmq_CVE-2019-17572_4-6-0.md) 🔴 ✅

**名称:** CVE-2019-17572 - Apache RocketMQ 目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行（取决于文件权限）  
**投毒风险:** 5%  
**发现时间:** 2025-08-15  
**POC仓库:** [apache__rocketmq_CVE-2019-17572_4-6-0](https://github.com/shoucheng3/apache__rocketmq_CVE-2019-17572_4-6-0)  

---

### [CVE-2018-10001](CVE-2018-10001-dsfau_CVE-2018-1000199.md) 🟡 

**名称:** CVE-2018-10001  
**类型:** 拒绝服务 (DoS)  
**风险:** 中危，可能导致程序崩溃  
**投毒风险:** 0%  
**发现时间:** 2025-08-15  
**POC仓库:** [CVE-2018-1000199](https://github.com/dsfau/CVE-2018-1000199)  

---

### [CVE-2018-10001](CVE-2018-10001-u0pattern_CVE-2018-1000117-Exploit.md) 🟡 

**名称:** CVE-2018-10001  
**类型:** 拒绝服务 (DoS)  
**风险:** 中危，可能导致服务中断  
**投毒风险:** 95%  
**发现时间:** 2025-08-15  
**POC仓库:** [CVE-2018-1000117-Exploit](https://github.com/u0pattern/CVE-2018-1000117-Exploit)  

---

### [CVE-2018-10001](CVE-2018-10001-s0_rsyslog-librelp-CVE-2018-1000140.md) 🟡 ✅

**名称:** CVE-2018-10001-FFmpeg-拒绝服务  
**类型:** 拒绝服务 (DoS)  
**风险:** 中危，可能导致服务不可用  
**投毒风险:** 0%  
**发现时间:** 2025-08-15  
**POC仓库:** [rsyslog-librelp-CVE-2018-1000140](https://github.com/s0/rsyslog-librelp-CVE-2018-1000140)  

---

### [CVE-2018-10001](CVE-2018-10001-s0_rsyslog-librelp-CVE-2018-1000140-fixed.md) 🟡 ✅

**名称:** CVE-2018-10001-FFmpeg-Out-of-array-read  
**类型:** 拒绝服务 (Out-of-array read)  
**风险:** 中危，可能导致程序崩溃  
**投毒风险:** 1%  
**发现时间:** 2025-08-15  
**POC仓库:** [rsyslog-librelp-CVE-2018-1000140-fixed](https://github.com/s0/rsyslog-librelp-CVE-2018-1000140-fixed)  

---

### [CVE-2018-10001](CVE-2018-10001-shoucheng3_rhuss__jolokia_CVE-2018-1000129_1-4-0.md) 🟡 

**名称:** CVE-2018-10001-FFmpeg-拒绝服务  
**类型:** 拒绝服务 (DoS)  
**风险:** 中危，可能导致服务中断  
**投毒风险:** 10%  
**发现时间:** 2025-08-15  
**POC仓库:** [rhuss__jolokia_CVE-2018-1000129_1-4-0](https://github.com/shoucheng3/rhuss__jolokia_CVE-2018-1000129_1-4-0)  

---

### [CVE-2019-10392](CVE-2019-10392-jas502n_CVE-2019-10392.md) 🔴 ✅

**名称:** CVE-2019-10392 Jenkins Git Client Plugin OS 命令注入  
**类型:** OS 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-15  
**POC仓库:** [CVE-2019-10392](https://github.com/jas502n/CVE-2019-10392)  

---

### [CVE-2019-10392](CVE-2019-10392-ftk-sostupid_CVE-2019-10392_EXP.md) 🔴 ✅

**名称:** CVE-2019-10392-Jenkins Git Client Plugin-OS Command Injection  
**类型:** OS Command Injection  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-15  
**POC仓库:** [CVE-2019-10392_EXP](https://github.com/ftk-sostupid/CVE-2019-10392_EXP)  

---

### [CVE-2019-10392](CVE-2019-10392-shoucheng3_jenkinsci__git-client-plugin_CVE-2019-10392_2-8-4.md) 🔴 ✅

**名称:** CVE-2019-10392-Jenkins Git Client Plugin-OS 命令注入  
**类型:** OS 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-15  
**POC仓库:** [jenkinsci__git-client-plugin_CVE-2019-10392_2-8-4](https://github.com/shoucheng3/jenkinsci__git-client-plugin_CVE-2019-10392_2-8-4)  

---

### [CVE-2025-9043](CVE-2025-9043-Tiger3080_CVE-2025-9043.md) 🔴 ✅

**名称:** CVE-2025-9043-Seagate Toolkit-权限提升  
**类型:** 未引用的搜索路径或元素  
**风险:** 高危，可导致权限提升至SYSTEM  
**投毒风险:** 10%  
**发现时间:** 2025-08-15  
**POC仓库:** [CVE-2025-9043](https://github.com/Tiger3080/CVE-2025-9043)  

---

### [CVE-2025-50461](CVE-2025-50461-Anchor0221_CVE-2025-50461.md) 🔴 ✅

**名称:** CVE-2025-50461: Verl Remote Code Execution via Unsafe Model Deserialization  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者执行任意代码，控制受影响的系统。  
**投毒风险:** 0%  
**发现时间:** 2025-08-15  
**POC仓库:** [CVE-2025-50461](https://github.com/Anchor0221/CVE-2025-50461)  

---

### [CVE-2024-5932](CVE-2024-5932-OxLmahdi_cve-2024-5932.md)  ✅

**名称:** CVE-2024-5932 - GiveWP WordPress Plugin PHP Object Injection to Remote Code Execution  
**类型:** PHP Object Injection  
**风险:** 严重，未授权的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-15  
**POC仓库:** [cve-2024-5932](https://github.com/OxLmahdi/cve-2024-5932)  

---

### [CVE-2024-5932](CVE-2024-5932-EQSTLab_CVE-2024-5932.md) 🔴 ✅

**名称:** CVE-2024-5932 - GiveWP Unauthenticated PHP Object Injection to Remote Code Execution  
**类型:** PHP Object Injection  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-08-15  
**POC仓库:** [CVE-2024-5932](https://github.com/EQSTLab/CVE-2024-5932)  

---

### [CVE-2024-5932](CVE-2024-5932-hlc23_CVE-2024-5932-web-ui.md) 🔴 

**名称:** CVE-2024-5932-GiveWP-PHP对象注入  
**类型:** PHP 对象注入  
**风险:** 高危，远程代码执行和任意文件删除  
**投毒风险:** 0%  
**发现时间:** 2025-08-15  
**POC仓库:** [CVE-2024-5932-web-ui](https://github.com/hlc23/CVE-2024-5932-web-ui)  

---

### [CVE-2025-20265](CVE-2025-20265-jordan922_cve2025-20265.md) 🔴 

**名称:** CVE-2025-20265-Cisco Secure Firewall Management Center Software-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程攻击者可以注入任意shell命令，以高权限级别在设备上执行。  
**投毒风险:** 10%  
**发现时间:** 2025-08-15  
**POC仓库:** [cve2025-20265](https://github.com/jordan922/cve2025-20265)  

---

### [CVE-2023-49440](CVE-2023-49440-EvilBytecode1337_CVE-2023-49440-Boolean-based-SQL-injection.md) 🔴 ✅

**名称:** XXX SQL注入漏洞  
**类型:** SQL注入  
**风险:** 高危，可能导致敏感数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-08-15  
**POC仓库:** [CVE-2023-49440-Boolean-based-SQL-injection](https://github.com/EvilBytecode1337/CVE-2023-49440-Boolean-based-SQL-injection)  

---

### [CVE-2014-4725](CVE-2014-4725-Pwdnx1337_MASS-CVE-2014-4725.md) 🔴 ✅

**名称:** CVE-2014-4725 MailPoet Newsletters 插件远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-15  
**POC仓库:** [MASS-CVE-2014-4725](https://github.com/Pwdnx1337/MASS-CVE-2014-4725)  

---

### [CVE-2025-5419](CVE-2025-5419-riemannj_CVE-2025-5419.md) 🔴 ✅

**名称:** CVE-2025-5419 V8引擎越界读写漏洞  
**类型:** 越界读写  
**风险:** 高危，可能导致堆损坏和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-14  
**POC仓库:** [CVE-2025-5419](https://github.com/riemannj/CVE-2025-5419)  

---

### [CVE-2019-10077](CVE-2019-10077-shoucheng3_apache__jspwiki_CVE-2019-10077_2.11.0.M3.md) 🟡 ✅

**名称:** CVE-2019-10077-Apache JSPWiki-XSS  
**类型:** 跨站脚本漏洞 (XSS)  
**风险:** 中危，可能导致会话劫持  
**投毒风险:** 0%  
**发现时间:** 2025-08-14  
**POC仓库:** [apache__jspwiki_CVE-2019-10077_2.11.0.M3](https://github.com/shoucheng3/apache__jspwiki_CVE-2019-10077_2.11.0.M3)  

---

### [CVE-2021-30180](CVE-2021-30180-shoucheng3_apache__dubbo_CVE-2021-30180_2.7.9.md) 🔴 ✅

**名称:** CVE-2021-30180-Apache Dubbo-RCE  
**类型:** 远程代码执行(RCE)  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-14  
**POC仓库:** [apache__dubbo_CVE-2021-30180_2.7.9](https://github.com/shoucheng3/apache__dubbo_CVE-2021-30180_2.7.9)  

---

### [CVE-2019-10077](CVE-2019-10077-shoucheng3_apache__jspwiki_CVE-2019-10077_2.11.0.M3.md) 🟡 

**名称:** CVE-2019-10077-Apache JSPWiki-XSS  
**类型:** 跨站脚本 (XSS)  
**风险:** 中危，可能导致会话劫持  
**投毒风险:** 0%  
**发现时间:** 2025-08-14  
**POC仓库:** [apache__jspwiki_CVE-2019-10077_2.11.0.M3](https://github.com/shoucheng3/apache__jspwiki_CVE-2019-10077_2.11.0.M3)  

---

### [CVE-2025-53770](CVE-2025-53770-ghostn4444_CVE-2025-53770.md) 🔴 ✅

**名称:** CVE-2025-53770 Microsoft SharePoint Server 远程代码执行漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可能导致远程代码执行，完全控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-08-14  
**POC仓库:** [CVE-2025-53770](https://github.com/ghostn4444/CVE-2025-53770)  

---

### [CVE-2025-54424](CVE-2025-54424-hophtien_CVE-2025-54424.md) 🔴 ✅

**名称:** CVE-2025-54424 - 1Panel Agent 证书验证绕过导致任意命令执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可完全控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-08-14  
**POC仓库:** [CVE-2025-54424](https://github.com/hophtien/CVE-2025-54424)  

---

### [CVE-2022-30190](CVE-2022-30190-Potato-9257_CVE-2022-30190_page.md) 🔴 ✅

**名称:** CVE-2022-30190 Microsoft Windows Support Diagnostic Tool (MSDT) 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行，控制受害者计算机  
**投毒风险:** 1%  
**发现时间:** 2025-08-14  
**POC仓库:** [CVE-2022-30190_page](https://github.com/Potato-9257/CVE-2022-30190_page)  

---

### [CVE-2024-47533](CVE-2024-47533-okkotsu1_CVE-2024-47533.md) 🔴 ✅

**名称:** CVE-2024-47533-Cobbler-未授权访问  
**类型:** 未授权访问  
**风险:** 高危，可完全控制 Cobbler 服务器  
**投毒风险:** 10%  
**发现时间:** 2025-08-14  
**POC仓库:** [CVE-2024-47533](https://github.com/okkotsu1/CVE-2024-47533)  

---

### [CVE-2022-30190](CVE-2022-30190-Cosmo121_Follina-Remediation.md) 🔴 ✅

**名称:** CVE-2022-30190 - Microsoft MSDT "Follina" 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-14  
**POC仓库:** [Follina-Remediation](https://github.com/Cosmo121/Follina-Remediation)  

---

### [CVE-2022-30190](CVE-2022-30190-arozx_CVE-2022-30190.md) 🔴 ✅

**名称:** CVE-2022-30190-Microsoft Windows Support Diagnostic Tool (MSDT) 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在受害者系统上执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-14  
**POC仓库:** [CVE-2022-30190](https://github.com/arozx/CVE-2022-30190)  

---

### [CVE-2022-30190](CVE-2022-30190-mattjmillner_CVE-Smackdown.md) 🔴 ✅

**名称:** CVE-2022-30190 - Microsoft MSDT 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者以调用应用程序的权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-14  
**POC仓库:** [CVE-Smackdown](https://github.com/mattjmillner/CVE-Smackdown)  

---

### [CVE-2022-30190](CVE-2022-30190-ar2o3_FollinaXploit.md) 🔴 ✅

**名称:** CVE-2022-30190-Microsoft Windows Support Diagnostic Tool (MSDT) 远程代码执行漏洞 (Follina)  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行，系统被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-14  
**POC仓库:** [FollinaXploit](https://github.com/ar2o3/FollinaXploit)  

---

### [CVE-2022-30190](CVE-2022-30190-Nyx2022_Follina-CVE-2022-30190-Sample.md) 🔴 ✅

**名称:** CVE-2022-30190 - Microsoft MSDT 'Follina' 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者以调用应用程序的权限执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-08-14  
**POC仓库:** [Follina-CVE-2022-30190-Sample](https://github.com/Nyx2022/Follina-CVE-2022-30190-Sample)  

---

### [CVE-2022-30190](CVE-2022-30190-swaiist_CVE-2022-30190-Fix.md) 🔴 ✅

**名称:** CVE-2022-30190-MSDT远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能允许攻击者在受害者系统上执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-08-14  
**POC仓库:** [CVE-2022-30190-Fix](https://github.com/swaiist/CVE-2022-30190-Fix)  

---

### [CVE-2022-30190](CVE-2022-30190-michealadams30_Cve-2022-30190.md) 🔴 ✅

**名称:** CVE-2022-30190-Microsoft MSDT RCE-Follina  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在目标系统上执行任意代码，控制系统。  
**投毒风险:** 10%  
**发现时间:** 2025-08-14  
**POC仓库:** [Cve-2022-30190](https://github.com/michealadams30/Cve-2022-30190)  

---

### [CVE-2022-30190](CVE-2022-30190-melting0256_Enterprise-Cybersecurity.md) 🔴 ✅

**名称:** CVE-2022-30190 Microsoft Windows Support Diagnostic Tool (MSDT) 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，攻击者可以执行任意代码，控制受影响的系统  
**投毒风险:** 10%  
**发现时间:** 2025-08-14  
**POC仓库:** [Enterprise-Cybersecurity](https://github.com/melting0256/Enterprise-Cybersecurity)  

---

### [CVE-2022-30190](CVE-2022-30190-yrkuo_CVE-2022-30190.md) 🔴 ✅

**名称:** CVE-2022-30190 Microsoft Windows Support Diagnostic Tool (MSDT) 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者以调用应用程序的权限执行任意代码，可能导致系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-14  
**POC仓库:** [CVE-2022-30190](https://github.com/yrkuo/CVE-2022-30190)  

---

### [CVE-2022-30190](CVE-2022-30190-Zitchev_go_follina.md) 🔴 ✅

**名称:** CVE-2022-30190 - Microsoft MSDT 远程代码执行漏洞 (Follina)  
**类型:** 远程代码执行  
**风险:** 高危，攻击者可以利用此漏洞在受害者系统上执行任意代码，完全控制受害者系统。  
**投毒风险:** 10%  
**发现时间:** 2025-08-14  
**POC仓库:** [go_follina](https://github.com/Zitchev/go_follina)  

---

### [CVE-2022-30190](CVE-2022-30190-Gra3s_CVE-2022-30190_EXP_PowerPoint.md) 🔴 ✅

**名称:** CVE-2022-30190 Microsoft Windows Support Diagnostic Tool (MSDT) 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行，控制受影响系统  
**投毒风险:** 10%  
**发现时间:** 2025-08-14  
**POC仓库:** [CVE-2022-30190_EXP_PowerPoint](https://github.com/Gra3s/CVE-2022-30190_EXP_PowerPoint)  

---

### [CVE-2022-30190](CVE-2022-30190-komomon_CVE-2022-30190-follina-Office-MSDT-Fixed.md) 🔴 ✅

**名称:** CVE-2022-30190-Microsoft Windows Support Diagnostic Tool (MSDT) 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行，安装程序，查看、更改或删除数据，或在用户权限允许的上下文中创建新帐户  
**投毒风险:** 10%  
**发现时间:** 2025-08-14  
**POC仓库:** [CVE-2022-30190-follina-Office-MSDT-Fixed](https://github.com/komomon/CVE-2022-30190-follina-Office-MSDT-Fixed)  

---

### [CVE-2022-30190](CVE-2022-30190-drgreenthumb93_CVE-2022-30190-follina.md) 🔴 ✅

**名称:** CVE-2022-30190-Follina  
**类型:** 远程代码执行  
**风险:** 高危，允许远程代码执行，可完全控制受害者系统  
**投毒风险:** 0%  
**发现时间:** 2025-08-14  
**POC仓库:** [CVE-2022-30190-follina](https://github.com/drgreenthumb93/CVE-2022-30190-follina)  

---

### [CVE-2022-30190](CVE-2022-30190-aminetitrofine_CVE-2022-30190.md) 🔴 ✅

**名称:** CVE-2022-30190 (Follina) - Microsoft MSDT远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行，获取系统控制权  
**投毒风险:** 10%  
**发现时间:** 2025-08-14  
**POC仓库:** [CVE-2022-30190](https://github.com/aminetitrofine/CVE-2022-30190)  

---

### [CVE-2022-30190](CVE-2022-30190-Muhammad-Ali007_Follina_MSDT_CVE-2022-30190.md) 🔴 ✅

**名称:** CVE-2022-30190 Microsoft Windows Support Diagnostic Tool (MSDT) 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在受害者系统上执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-14  
**POC仓库:** [Follina_MSDT_CVE-2022-30190](https://github.com/Muhammad-Ali007/Follina_MSDT_CVE-2022-30190)  

---

### [CVE-2022-30190](CVE-2022-30190-DerZiad_CVE-2022-30190.md) 🔴 ✅

**名称:** CVE-2022-30190 Microsoft Windows Support Diagnostic Tool (MSDT) 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者以调用应用程序的权限执行任意代码，可能导致系统完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-08-14  
**POC仓库:** [CVE-2022-30190](https://github.com/DerZiad/CVE-2022-30190)  

---

### [CVE-2022-30190](CVE-2022-30190-ToxicEnvelope_FOLLINA-CVE-2022-30190.md) 🔴 ✅

**名称:** CVE-2022-30190-Microsoft Windows Support Diagnostic Tool (MSDT) 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在目标系统上执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-08-14  
**POC仓库:** [FOLLINA-CVE-2022-30190](https://github.com/ToxicEnvelope/FOLLINA-CVE-2022-30190)  

---

### [CVE-2022-30190](CVE-2022-30190-hycheng15_CVE-2022-30190.md) 🔴 ✅

**名称:** CVE-2022-30190 - Microsoft MSDT RCE (Follina)  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许攻击者以调用应用程序的权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-14  
**POC仓库:** [CVE-2022-30190](https://github.com/hycheng15/CVE-2022-30190)  

---

### [CVE-2022-30190](CVE-2022-30190-Jump-Wang-111_AmzWord.md) 🔴 ✅

**名称:** CVE-2022-30190 (Follina) - Microsoft MSDT 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致远程代码执行，系统控制，数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-08-14  
**POC仓库:** [AmzWord](https://github.com/Jump-Wang-111/AmzWord)  

---

### [CVE-2022-30190](CVE-2022-30190-AbdulRKB_Follina.md) 🔴 ✅

**名称:** CVE-2022-30190 - Microsoft MSDT RCE (Follina)  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行，完全控制受害者系统  
**投毒风险:** 10%  
**发现时间:** 2025-08-14  
**POC仓库:** [Follina](https://github.com/AbdulRKB/Follina)  

---

### [CVE-2022-30190](CVE-2022-30190-shri142_ZipScan.md) 🔴 ✅

**名称:** CVE-2022-30190 (Follina) MSDT 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者以调用应用程序的权限执行任意代码，可能导致系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-14  
**POC仓库:** [ZipScan](https://github.com/shri142/ZipScan)  

---

### [CVE-2022-30190](CVE-2022-30190-winstxnhdw_CVE-2022-30190.md) 🔴 ✅

**名称:** CVE-2022-30190 (Follina) MSDT 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在受害者系统上执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-14  
**POC仓库:** [CVE-2022-30190](https://github.com/winstxnhdw/CVE-2022-30190)  

---

### [CVE-2022-30190](CVE-2022-30190-alien-keric_CVE-2022-30190.md) 🔴 ✅

**名称:** CVE-2022-30190 (Follina)  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行，权限提升，数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-08-14  
**POC仓库:** [CVE-2022-30190](https://github.com/alien-keric/CVE-2022-30190)  

---

### [CVE-2022-30190](CVE-2022-30190-skitkat_CVE-2022-30190-POC.md) 🔴 ✅

**名称:** CVE-2022-30190 - Microsoft MSDT Follina 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，攻击者可利用该漏洞在目标系统上执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-14  
**POC仓库:** [CVE-2022-30190-POC](https://github.com/skitkat/CVE-2022-30190-POC)  

---

### [CVE-2022-30190](CVE-2022-30190-ethicalblue_Follina-CVE-2022-30190-Sample.md) 🔴 ✅

**名称:** CVE-2022-30190 - Microsoft MSDT "Follina" RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许攻击者以调用应用程序的权限执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-08-14  
**POC仓库:** [Follina-CVE-2022-30190-Sample](https://github.com/ethicalblue/Follina-CVE-2022-30190-Sample)  

---

### [CVE-2022-30190](CVE-2022-30190-yeep1115_ICT287_CVE-2022-30190_Exploit.md) 🔴 ✅

**名称:** CVE-2022-30190 Microsoft Windows Support Diagnostic Tool (MSDT) 远程代码执行漏洞 (Follina)  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者以调用应用程序的权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-14  
**POC仓库:** [ICT287_CVE-2022-30190_Exploit](https://github.com/yeep1115/ICT287_CVE-2022-30190_Exploit)  

---

### [CVE-2022-30190](CVE-2022-30190-RathoreAbhiii_Folina-Vulnerability-Exploitation-Detection-and-Mitigation.md) 🔴 

**名称:** CVE-2022-30190 - Microsoft MSDT RCE (Follina)  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，攻击者可以利用此漏洞在受害者系统上执行任意代码  
**投毒风险:** 20%  
**发现时间:** 2025-08-14  
**POC仓库:** [Folina-Vulnerability-Exploitation-Detection-and-Mitigation](https://github.com/RathoreAbhiii/Folina-Vulnerability-Exploitation-Detection-and-Mitigation)  

---

### [CVE-2022-30190](CVE-2022-30190-seinab-ibrahim_Follina-Vulnerability-CVE-2022-30190-Exploit-Analysis.md) 🔴 ✅

**名称:** CVE-2022-30190 (Follina) Microsoft MSDT 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者以调用应用程序的权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-14  
**POC仓库:** [Follina-Vulnerability-CVE-2022-30190-Exploit-Analysis](https://github.com/seinab-ibrahim/Follina-Vulnerability-CVE-2022-30190-Exploit-Analysis)  

---

### [CVE-2018-0114](CVE-2018-0114-n0m-d_CVE-2018-0114-Go.md) 🔴 ✅

**名称:** CVE-2018-0114 - Node-jose JWT 签名伪造  
**类型:** JWT 签名伪造  
**风险:** 高危，允许未授权的远程攻击者重新签名令牌，可能导致权限提升和身份验证绕过  
**投毒风险:** 10%  
**发现时间:** 2025-08-14  
**POC仓库:** [CVE-2018-0114-Go](https://github.com/n0m-d/CVE-2018-0114-Go)  

---

### [CVE-2024-34102](CVE-2024-34102-Kento-Sec_CVE-2024-34102.md) 🔴 ✅

**名称:** CVE-2024-34102-Adobe Commerce XXE  
**类型:** XXE (XML External Entity)  
**风险:** 高危，可导致任意代码执行和敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-08-14  
**POC仓库:** [CVE-2024-34102](https://github.com/Kento-Sec/CVE-2024-34102)  

---

### [CVE-2017-18362](CVE-2017-18362-yawningmoney_CVE-2017-18362-LAB.md) 🔴 ✅

**名称:** CVE-2017-18362-KaseyaVSA-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、远程代码执行和Ransomware攻击  
**投毒风险:** 10%  
**发现时间:** 2025-08-14  
**POC仓库:** [CVE-2017-18362-LAB](https://github.com/yawningmoney/CVE-2017-18362-LAB)  

---

### [CVE-2014-4725](CVE-2014-4725-Pwdnx1337_MASS-CVE-2014-4725.md) 🔴 ✅

**名称:** CVE-2014-4725 MailPoet Newsletters WordPress Plugin 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者上传恶意主题并执行任意PHP代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-14  
**POC仓库:** [MASS-CVE-2014-4725](https://github.com/Pwdnx1337/MASS-CVE-2014-4725)  

---

### [CVE-2025-8088](CVE-2025-8088-onlytoxi_CVE-2025-8088-Winrar-Tool.md) 🔴 ✅

**名称:** CVE-2025-8088 WinRAR 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-14  
**POC仓库:** [CVE-2025-8088-Winrar-Tool](https://github.com/onlytoxi/CVE-2025-8088-Winrar-Tool)  

---

### [CVE-2025-24893](CVE-2025-24893-CMassa_CVE-2025-24893.md) 🔴 ✅

**名称:** CVE-2025-24893-XWiki-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-08-13  
**POC仓库:** [CVE-2025-24893](https://github.com/CMassa/CVE-2025-24893)  

---

### [CVE-2024-26009](CVE-2024-26009-allinsthon_CVE-2024-26009.md) 🔴 ✅

**名称:** CVE-2024-26009 - Fortinet身份验证绕过漏洞  
**类型:** 身份验证绕过  
**风险:** 高危，允许未经身份验证的攻击者完全控制受管理的设备  
**投毒风险:** 30%  
**发现时间:** 2025-08-13  
**POC仓库:** [CVE-2024-26009](https://github.com/allinsthon/CVE-2024-26009)  

---

### [CVE-2025-50428](CVE-2025-50428-security-smarttecs_cve-2025-50428.md) 🔴 ✅

**名称:** CVE-2025-50428 - RaspAP Command Injection  
**类型:** 命令注入  
**风险:** 高危，可远程代码执行，权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-08-13  
**POC仓库:** [cve-2025-50428](https://github.com/security-smarttecs/cve-2025-50428)  

---

### [CVE-2017-11882](CVE-2017-11882-starnightcyber_CVE-2017-11882.md) 🔴 ✅

**名称:** CVE-2017-11882 Microsoft Office 内存破坏漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者以当前用户权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-13  
**POC仓库:** [CVE-2017-11882](https://github.com/starnightcyber/CVE-2017-11882)  

---

### [CVE-2017-11882](CVE-2017-11882-Ridter_CVE-2017-11882.md) 🔴 ✅

**名称:** CVE-2017-11882-Microsoft Office Memory Corruption Vulnerability  
**类型:** 内存破坏漏洞，导致远程代码执行  
**风险:** 高危，允许攻击者在当前用户上下文中执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-08-13  
**POC仓库:** [CVE-2017-11882](https://github.com/Ridter/CVE-2017-11882)  

---

### [CVE-2017-11882](CVE-2017-11882-embedi_CVE-2017-11882.md) 🔴 ✅

**名称:** CVE-2017-11882-Microsoft Office 内存破坏漏洞  
**类型:** 内存破坏漏洞  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-13  
**POC仓库:** [CVE-2017-11882](https://github.com/embedi/CVE-2017-11882)  

---

### [CVE-2017-11882](CVE-2017-11882-rip1s_CVE-2017-11882.md) 🔴 ✅

**名称:** CVE-2017-11882-Microsoft Office 内存破坏漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在当前用户上下文中运行任意代码  
**投毒风险:** 1%  
**发现时间:** 2025-08-13  
**POC仓库:** [CVE-2017-11882](https://github.com/rip1s/CVE-2017-11882)  

---

### [CVE-2017-11882](CVE-2017-11882-likekabin_CVE-2017-11882.md) 🔴 ✅

**名称:** CVE-2017-11882-Microsoft Office 内存破坏漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-13  
**POC仓库:** [CVE-2017-11882](https://github.com/likekabin/CVE-2017-11882)  

---

### [CVE-2017-11882](CVE-2017-11882-herbiezimmerman_CVE-2017-11882-Possible-Remcos-Malspam.md) 🔴 ✅

**名称:** CVE-2017-11882-Microsoft Office Memory Corruption Vulnerability  
**类型:** 内存破坏漏洞/远程代码执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-13  
**POC仓库:** [CVE-2017-11882-Possible-Remcos-Malspam](https://github.com/herbiezimmerman/CVE-2017-11882-Possible-Remcos-Malspam)  

---

### [CVE-2017-11882](CVE-2017-11882-ChaitanyaHaritash_CVE-2017-11882.md) 🔴 ✅

**名称:** CVE-2017-11882 Microsoft Office 内存破坏漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在当前用户上下文中执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-13  
**POC仓库:** [CVE-2017-11882](https://github.com/ChaitanyaHaritash/CVE-2017-11882)  

---

### [CVE-2017-11882](CVE-2017-11882-j0lama_CVE-2017-11882.md) 🔴 ✅

**名称:** CVE-2017-11882-Microsoft Office Memory Corruption Vulnerability  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在当前用户上下文中执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-08-13  
**POC仓库:** [CVE-2017-11882](https://github.com/j0lama/CVE-2017-11882)  

---

### [CVE-2017-11882](CVE-2017-11882-chanbin_CVE-2017-11882.md) 🔴 ✅

**名称:** CVE-2017-11882-Microsoft Office Memory Corruption Vulnerability  
**类型:** 内存破坏漏洞  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-13  
**POC仓库:** [CVE-2017-11882](https://github.com/chanbin/CVE-2017-11882)  

---

### [CVE-2017-11882](CVE-2017-11882-ekgg_Overflow-Demo-CVE-2017-11882.md) 🔴 ✅

**名称:** CVE-2017-11882 Microsoft Office 内存破坏漏洞  
**类型:** 内存破坏  
**风险:** 高危，允许攻击者在当前用户上下文中执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-13  
**POC仓库:** [Overflow-Demo-CVE-2017-11882](https://github.com/ekgg/Overflow-Demo-CVE-2017-11882)  

---

### [CVE-2017-11882](CVE-2017-11882-HaoJame_CVE-2017-11882.md) 🔴 ✅

**名称:** CVE-2017-11882-Microsoft Office Memory Corruption  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-13  
**POC仓库:** [CVE-2017-11882](https://github.com/HaoJame/CVE-2017-11882)  

---

### [CVE-2017-11882](CVE-2017-11882-littlebin404_CVE-2017-11882.md) 🔴 ✅

**名称:** CVE-2017-11882-Microsoft Office Memory Corruption Vulnerability  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行，完全控制受害者系统  
**投毒风险:** 10%  
**发现时间:** 2025-08-13  
**POC仓库:** [CVE-2017-11882](https://github.com/littlebin404/CVE-2017-11882)  

---

### [CVE-2017-11882](CVE-2017-11882-Retr0-code_SignHere.md) 🔴 ✅

**名称:** CVE-2017-11882 - Microsoft Office 内存破坏漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在当前用户上下文中运行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-08-13  
**POC仓库:** [SignHere](https://github.com/Retr0-code/SignHere)  

---

### [CVE-2017-11882](CVE-2017-11882-lisinan988_CVE-2017-11882-exp.md) 🔴 ✅

**名称:** CVE-2017-11882-Microsoft Office Memory Corruption Vulnerability  
**类型:** 内存破坏漏洞  
**风险:** 高危，远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-13  
**POC仓库:** [CVE-2017-11882-exp](https://github.com/lisinan988/CVE-2017-11882-exp)  

---

### [CVE-2017-11882](CVE-2017-11882-tzwlhack_CVE-2017-11882.md) 🔴 ✅

**名称:** CVE-2017-11882-Microsoft Office Memory Corruption  
**类型:** 内存损坏  
**风险:** 高危，允许攻击者在当前用户上下文中执行任意代码  
**投毒风险:** 1%  
**发现时间:** 2025-08-13  
**POC仓库:** [CVE-2017-11882](https://github.com/tzwlhack/CVE-2017-11882)  

---

### [CVE-2017-11882](CVE-2017-11882-Sunqiz_CVE-2017-11882-reproduction.md) 🔴 ✅

**名称:** CVE-2017-11882-Microsoft Office Memory Corruption Vulnerability  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在当前用户上下文中执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-13  
**POC仓库:** [CVE-2017-11882-reproduction](https://github.com/Sunqiz/CVE-2017-11882-reproduction)  

---

### [CVE-2017-11882](CVE-2017-11882-Abdibimantara_Maldoc-Analysis.md) 🔴 ✅

**名称:** CVE-2017-11882 Microsoft Office 内存破坏漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在当前用户上下文中运行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-13  
**POC仓库:** [Maldoc-Analysis](https://github.com/Abdibimantara/Maldoc-Analysis)  

---

### [CVE-2017-11882](CVE-2017-11882-n18dcat053-luuvannga_DetectPacket-CVE-2017-11882.md) 🔴 ✅

**名称:** CVE-2017-11882 Microsoft Office 内存破坏漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在当前用户的上下文中运行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-13  
**POC仓库:** [DetectPacket-CVE-2017-11882](https://github.com/n18dcat053-luuvannga/DetectPacket-CVE-2017-11882)  

---

### [CVE-2017-11882](CVE-2017-11882-xdrake1010_CVE-2017-11882-Preventer.md) 🔴 ✅

**名称:** CVE-2017-11882-Microsoft Office 内存破坏漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者以当前用户身份执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-08-13  
**POC仓库:** [CVE-2017-11882-Preventer](https://github.com/xdrake1010/CVE-2017-11882-Preventer)  

---

### [CVE-2017-11882](CVE-2017-11882-imkidz0_CVE-2017-11882.md) 🔴 ✅

**名称:** CVE-2017-11882-Microsoft Office Memory Corruption Vulnerability  
**类型:** 内存破坏漏洞/远程代码执行  
**风险:** 高危，允许攻击者在当前用户上下文中执行任意代码，可能导致系统完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-13  
**POC仓库:** [CVE-2017-11882](https://github.com/imkidz0/CVE-2017-11882)  

---

### [CVE-2025-53773](CVE-2025-53773-B1ack4sh_Blackash-CVE-2025-53773.md) 🔴 ✅

**名称:** CVE-2025-53773 - GitHub Copilot and Visual Studio 远程代码执行  
**类型:** 命令注入  
**风险:** 高危，可能导致本地代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-13  
**POC仓库:** [Blackash-CVE-2025-53773](https://github.com/B1ack4sh/Blackash-CVE-2025-53773)  

---

### [CVE-2025-55668](CVE-2025-55668-gregk4sec_CVE-2025-55668.md) 🟡 

**名称:** CVE-2025-55668-Apache Tomcat-Session Fixation  
**类型:** Session Fixation  
**风险:** 中危，可能导致会话劫持  
**投毒风险:** 0%  
**发现时间:** 2025-08-13  
**POC仓库:** [CVE-2025-55668](https://github.com/gregk4sec/CVE-2025-55668)  

---

### [CVE-2025-50360](CVE-2025-50360-Ch1keen_CVE-2025-50360.md) 🔴 ✅

**名称:** CVE-UNKNOWN-Pepper-Heap-Buffer-Overflow  
**类型:** Heap Buffer Overflow  
**风险:** 高危，可能导致拒绝服务，代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-13  
**POC仓库:** [CVE-2025-50360](https://github.com/Ch1keen/CVE-2025-50360)  

---

### [CVE-2025-25256](CVE-2025-25256-barbaraeivyu_CVE-2025-25256.md)  ✅

**名称:** CVE-2025-25256 - FortiSIEM OS Command Injection  
**类型:** OS Command Injection  
**风险:** 严重，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-13  
**POC仓库:** [CVE-2025-25256](https://github.com/barbaraeivyu/CVE-2025-25256)  

---

### [CVE-2025-53770](CVE-2025-53770-CyprianAtsyor_ToolShell-CVE-2025-53770-SharePoint-Exploit-Lab-LetsDefend.md)  ✅

**名称:** CVE-2025-53770-Microsoft SharePoint Server 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 严重，未经身份验证的攻击者可以在服务器上执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-13  
**POC仓库:** [ToolShell-CVE-2025-53770-SharePoint-Exploit-Lab-LetsDefend](https://github.com/CyprianAtsyor/ToolShell-CVE-2025-53770-SharePoint-Exploit-Lab-LetsDefend)  

---

### [CVE-2025-50361](CVE-2025-50361-Ch1keen_CVE-2025-50361.md) 🔴 ✅

**名称:** CVE-2025-NA-SmallBASIC全局缓冲区溢出  
**类型:** 全局缓冲区溢出  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-08-13  
**POC仓库:** [CVE-2025-50361](https://github.com/Ch1keen/CVE-2025-50361)  

---

### [CVE-2025-8088](CVE-2025-8088-sxyrxyy_CVE-2025-8088-WinRAR-Proof-of-Concept-PoC-Exploit-.md) 🔴 ✅

**名称:** CVE-2025-8088 WinRAR 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-13  
**POC仓库:** [CVE-2025-8088-WinRAR-Proof-of-Concept-PoC-Exploit-](https://github.com/sxyrxyy/CVE-2025-8088-WinRAR-Proof-of-Concept-PoC-Exploit-)  

---

### [CVE-2017-0143](CVE-2017-0143-Mafiosohack_offensive-security-lab-1.md) 🔴 ✅

**名称:** CVE-2017-0143-Windows SMB Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，允许远程攻击者通过特制的SMB数据包执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-13  
**POC仓库:** [offensive-security-lab-1](https://github.com/Mafiosohack/offensive-security-lab-1)  

---

### [CVE-2017-0143](CVE-2017-0143-Cedric-Martz_EthernalBlue_report.md) 🔴 ✅

**名称:** CVE-2017-0143 Windows SMB 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-13  
**POC仓库:** [EthernalBlue_report](https://github.com/Cedric-Martz/EthernalBlue_report)  

---

### [CVE-2017-0143](CVE-2017-0143-benguelmas_cve-2017-0143.md) 🔴 ✅

**名称:** CVE-2017-0143 - Windows SMB 远程代码执行漏洞（EternalBlue）  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-13  
**POC仓库:** [cve-2017-0143](https://github.com/benguelmas/cve-2017-0143)  

---

### [CVE-2025-50154](CVE-2025-50154-rubenformation_CVE-2025-50154.md) 🟡 ✅

**名称:** CVE-2025-50154 Windows File Explorer Spoofing Vulnerability  
**类型:** NTLMv2-SSP Hash Disclosure  
**风险:** 中危，可能导致凭据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-08-13  
**POC仓库:** [CVE-2025-50154](https://github.com/rubenformation/CVE-2025-50154)  

---

### [CVE-2025-50154](CVE-2025-50154-zenzue_CVE-2025-50154.md) 🔴 ✅

**名称:** CVE-2025-50154 - Windows File Explorer Spoofing Vulnerability  
**类型:** NTLM Relay/Spoofing  
**风险:** 高危，可能导致敏感信息泄露和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-08-13  
**POC仓库:** [CVE-2025-50154](https://github.com/zenzue/CVE-2025-50154)  

---

### [CVE-2025-32433](CVE-2025-32433-NiteeshPujari_CVE-2025-32433-PoC.md)  ✅

**名称:** CVE-2025-32433 - Erlang/OTP SSH Pre-Authentication RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-13  
**POC仓库:** [CVE-2025-32433-PoC](https://github.com/NiteeshPujari/CVE-2025-32433-PoC)  

---

### [CVE-2024-47533](CVE-2024-47533-zs1n_CVE-2024-47533.md) 🔴 ✅

**名称:** CVE-2024-47533 - Cobbler XMLRPC Authentication Bypass RCE  
**类型:** 身份验证绕过  
**风险:** 高危，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-13  
**POC仓库:** [CVE-2024-47533](https://github.com/zs1n/CVE-2024-47533)  

---

### [CVE-2025-53778](CVE-2025-53778-OxPloited_CVE-2025-53778.md) 🔴 

**名称:** CVE-2025-53778 Windows NTLM Elevation of Privilege Vulnerability  
**类型:** 特权提升  
**风险:** 高危，攻击者可提升权限  
**投毒风险:** 10%  
**发现时间:** 2025-08-12  
**POC仓库:** [CVE-2025-53778](https://github.com/OxPloited/CVE-2025-53778)  

---

### [CVE-2022-31160](CVE-2022-31160-r00nin_jquery-cve-2022-31160.md) 🟡 ✅

**名称:** CVE-2022-31160-jQuery UI-XSS  
**类型:** XSS  
**风险:** 中危，可能导致用户浏览器执行恶意脚本  
**投毒风险:** 1%  
**发现时间:** 2025-08-12  
**POC仓库:** [jquery-cve-2022-31160](https://github.com/r00nin/jquery-cve-2022-31160)  

---

### [CVE-2025-51529](CVE-2025-51529-piotrmaciejbednarski_CVE-2025-51529.md) 🔴 ✅

**名称:** CVE-2025-51529: WordPress Cookies and Content Security Policy Plugin DoS Vulnerability  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致服务器资源耗尽，网站无法访问  
**投毒风险:** 5%  
**发现时间:** 2025-08-12  
**POC仓库:** [CVE-2025-51529](https://github.com/piotrmaciejbednarski/CVE-2025-51529)  

---

### [CVE-2017-16995](CVE-2017-16995-gugronnier_CVE-2017-16995.md) 🔴 ✅

**名称:** CVE-2017-16995 Linux Kernel BPF 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，允许本地用户获取root权限  
**投毒风险:** 1%  
**发现时间:** 2025-08-12  
**POC仓库:** [CVE-2017-16995](https://github.com/gugronnier/CVE-2017-16995)  

---

### [CVE-2017-16995](CVE-2017-16995-Al1ex_CVE-2017-16995.md) 🔴 ✅

**名称:** CVE-2017-16995-Linux Kernel-BPF权限提升  
**类型:** 本地权限提升  
**风险:** 高危，允许低权限用户获得root权限  
**投毒风险:** 5%  
**发现时间:** 2025-08-12  
**POC仓库:** [CVE-2017-16995](https://github.com/Al1ex/CVE-2017-16995)  

---

### [CVE-2025-52385](CVE-2025-52385-Kov404_CVE-2025-52385.md) 🔴 ✅

**名称:** CVE-2025-52385-Studio 3T-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致远程代码执行和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-08-12  
**POC仓库:** [CVE-2025-52385](https://github.com/Kov404/CVE-2025-52385)  

---

### [CVE-2024-47533](CVE-2024-47533-00xCanelo_CVE-2024-47533-PoC.md) 🔴 ✅

**名称:** CVE-2024-47533 - Cobbler XMLRPC 未授权远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未授权的远程代码执行，完全控制受影响的服务器。  
**投毒风险:** 5%  
**发现时间:** 2025-08-12  
**POC仓库:** [CVE-2024-47533-PoC](https://github.com/00xCanelo/CVE-2024-47533-PoC)  

---

### [CVE-2017-16995](CVE-2017-16995-C0dak_CVE-2017-16995.md) 🔴 ✅

**名称:** CVE-2017-16995 - Linux Kernel eBPF 权限提升  
**类型:** 权限提升  
**风险:** 高危，允许本地非特权用户获得 root 权限  
**投毒风险:** 10%  
**发现时间:** 2025-08-12  
**POC仓库:** [CVE-2017-16995](https://github.com/C0dak/CVE-2017-16995)  

---

### [CVE-2017-16995](CVE-2017-16995-senyuuri_cve-2017-16995.md) 🔴 ✅

**名称:** CVE-2017-16995  
**类型:** 本地权限提升  
**风险:** 高危，可导致本地用户获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-08-12  
**POC仓库:** [cve-2017-16995](https://github.com/senyuuri/cve-2017-16995)  

---

### [CVE-2017-16995](CVE-2017-16995-vnik5287_CVE-2017-16995.md) 🔴 ✅

**名称:** CVE-2017-16995 Linux Kernel eBPF 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，本地用户可提升权限至 root  
**投毒风险:** 10%  
**发现时间:** 2025-08-12  
**POC仓库:** [CVE-2017-16995](https://github.com/vnik5287/CVE-2017-16995)  

---

### [CVE-2017-16995](CVE-2017-16995-littlebin404_CVE-2017-16995.md) 🔴 ✅

**名称:** CVE-2017-16995-Linux Kernel BPF权限提升  
**类型:** 本地权限提升  
**风险:** 高危，可导致普通用户获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-08-12  
**POC仓库:** [CVE-2017-16995](https://github.com/littlebin404/CVE-2017-16995)  

---

### [CVE-2017-16995](CVE-2017-16995-Lumindu_CVE-2017-16995-Linux-Kernel---BPF-Sign-Extension-Local-Privilege-Escalation-.md) 🔴 ✅

**名称:** CVE-2017-16995-Linux Kernel-BPF 整数溢出  
**类型:** 整数溢出  
**风险:** 高危，可能导致内存破坏和权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-08-12  
**POC仓库:** [CVE-2017-16995-Linux-Kernel---BPF-Sign-Extension-Local-Privilege-Escalation-](https://github.com/Lumindu/CVE-2017-16995-Linux-Kernel---BPF-Sign-Extension-Local-Privilege-Escalation-)  

---

### [CVE-2017-16995](CVE-2017-16995-ph4ntonn_CVE-2017-16995.md) 🔴 ✅

**名称:** CVE-2017-16995-Linux Kernel BPF 权限提升  
**类型:** 本地权限提升 (LPE)  
**风险:** 高危，可从普通用户提升到root权限  
**投毒风险:** 10%  
**发现时间:** 2025-08-12  
**POC仓库:** [CVE-2017-16995](https://github.com/ph4ntonn/CVE-2017-16995)  

---

### [CVE-2017-16995](CVE-2017-16995-ivilpez_cve-2017-16995.c.md) 🔴 ✅

**名称:** CVE-2017-16995-Linux Kernel BPF 权限提升  
**类型:** 本地权限提升  
**风险:** 高危，允许本地用户提升权限  
**投毒风险:** 10%  
**发现时间:** 2025-08-12  
**POC仓库:** [cve-2017-16995.c](https://github.com/ivilpez/cve-2017-16995.c)  

---

### [CVE-2017-16995](CVE-2017-16995-fei9747_CVE-2017-16995.md) 🔴 ✅

**名称:** CVE-2017-16995-Linux Kernel BPF权限提升  
**类型:** 本地权限提升  
**风险:** 高危，本地用户可以获得root权限  
**投毒风险:** 10%  
**发现时间:** 2025-08-12  
**POC仓库:** [CVE-2017-16995](https://github.com/fei9747/CVE-2017-16995)  

---

### [CVE-2017-16995](CVE-2017-16995-anldori_CVE-2017-16995.md) 🔴 ✅

**名称:** CVE-2017-16995-Linux Kernel-BPF 权限提升  
**类型:** 权限提升  
**风险:** 高危，本地用户可提升为root权限  
**投毒风险:** 5%  
**发现时间:** 2025-08-12  
**POC仓库:** [CVE-2017-16995](https://github.com/anldori/CVE-2017-16995)  

---

### [CVE-2017-16995](CVE-2017-16995-ZhiQiAnSecFork_cve-2017-16995.md) 🔴 ✅

**名称:** CVE-2017-16995  
**类型:** Linux Kernel eBPF权限提升  
**风险:** 高危，本地权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-08-12  
**POC仓库:** [cve-2017-16995](https://github.com/ZhiQiAnSecFork/cve-2017-16995)  

---

### [CVE-2017-16995](CVE-2017-16995-xxxTectationxxx_CVE-2017-16995.md) 🔴 ✅

**名称:** CVE-2017-16995-Linux Kernel-BPF 权限提升  
**类型:** 本地权限提升  
**风险:** 高危，可能导致root权限获取  
**投毒风险:** 10%  
**发现时间:** 2025-08-12  
**POC仓库:** [CVE-2017-16995](https://github.com/xxxTectationxxx/CVE-2017-16995)  

---

### [CVE-2025-54887](CVE-2025-54887-shinigami-777_PoC_CVE-2025-54887.md) 🔴 ✅

**名称:** CVE-2025-54887-ruby-jwe-认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致信息泄露和权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-08-12  
**POC仓库:** [PoC_CVE-2025-54887](https://github.com/shinigami-777/PoC_CVE-2025-54887)  

---

### [CVE-2024-47533](CVE-2024-47533-dollarboysushil_CVE-2024-47533-Cobbler-XMLRPC-Authentication-Bypass-RCE-Exploit-POC.md) 🔴 ✅

**名称:** CVE-2024-47533-Cobbler XMLRPC 认证绕过 RCE  
**类型:** 认证绕过/远程代码执行  
**风险:** 高危，未经授权的远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-08-12  
**POC仓库:** [CVE-2024-47533-Cobbler-XMLRPC-Authentication-Bypass-RCE-Exploit-POC](https://github.com/dollarboysushil/CVE-2024-47533-Cobbler-XMLRPC-Authentication-Bypass-RCE-Exploit-POC)  

---

### [CVE-2025-8088](CVE-2025-8088-knight0x07_WinRAR-CVE-2025-8088-PoC-RAR.md) 🔴 ✅

**名称:** CVE-2025-8088-WinRAR-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-12  
**POC仓库:** [WinRAR-CVE-2025-8088-PoC-RAR](https://github.com/knight0x07/WinRAR-CVE-2025-8088-PoC-RAR)  

---

### [CVE-2025-53770](CVE-2025-53770-behnamvanda_CVE-2025-53770-Checker.md) 🔴 ✅

**名称:** CVE-2025-53770 SharePoint Server 远程代码执行漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，允许未经授权的攻击者通过网络执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-12  
**POC仓库:** [CVE-2025-53770-Checker](https://github.com/behnamvanda/CVE-2025-53770-Checker)  

---

### [CVE-2018-7600](CVE-2018-7600-muhammedkayag_CVE-2018-7600.md) 🔴 ✅

**名称:** CVE-2018-7600-Drupal-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-12  
**POC仓库:** [CVE-2018-7600](https://github.com/muhammedkayag/CVE-2018-7600)  

---

### [CVE-2018-7600](CVE-2018-7600-xxxTectationxxx_CVE-2018-7600.md) 🔴 ✅

**名称:** CVE-2018-7600 - Drupalgeddon2 RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的攻击者执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-08-12  
**POC仓库:** [CVE-2018-7600](https://github.com/xxxTectationxxx/CVE-2018-7600)  

---

### [CVE-2025-25231](CVE-2025-25231-ashkan-pu_CVE-CVE-2025-25231.md) 🔴 ✅

**名称:** CVE-2025-25231 - Omnissa Workspace ONE UEM 二级上下文路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-08-12  
**POC仓库:** [CVE-CVE-2025-25231](https://github.com/ashkan-pu/CVE-CVE-2025-25231)  

---

### [CVE-2024-54761](CVE-2024-54761-nscan9_CVE-2024-54761.md) 🔴 ✅

**名称:** CVE-2024-54761-BigAnt Office Messenger-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-12  
**POC仓库:** [CVE-2024-54761](https://github.com/nscan9/CVE-2024-54761)  

---

### [CVE-2025-55188](CVE-2025-55188-vadim-belous_CVE-2025-55188-PoC.md) 🟡 ✅

**名称:** CVE-2025-55188-7-Zip-符号链接处理不当  
**类型:** 符号链接处理不当  
**风险:** 中危，可能导致任意文件写入  
**投毒风险:** 5%  
**发现时间:** 2025-08-12  
**POC仓库:** [CVE-2025-55188-PoC](https://github.com/vadim-belous/CVE-2025-55188-PoC)  

---

### [CVE-2024-47533](CVE-2024-47533-baph00met_CVE-2024-47533.md)  ✅

**名称:** CVE-2024-47533-Cobbler-不当身份验证  
**类型:** 不当身份验证  
**风险:** 严重，可能导致完全控制服务器  
**投毒风险:** 0%  
**发现时间:** 2025-08-12  
**POC仓库:** [CVE-2024-47533](https://github.com/baph00met/CVE-2024-47533)  

---

### [CVE-2025-8088](CVE-2025-8088-travisbgreen_cve-2025-8088.md) 🔴 ✅

**名称:** CVE-2025-8088-WinRAR-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-08-12  
**POC仓库:** [cve-2025-8088](https://github.com/travisbgreen/cve-2025-8088)  

---

### [CVE-2024-7591](CVE-2024-7591-butyraldehyde_CVE-2024-7591-PoC.md)  ✅

**名称:** CVE-2024-7591 - Progress LoadMaster OS 命令注入  
**类型:** OS 命令注入  
**风险:** 严重，可能导致完全系统控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-11  
**POC仓库:** [CVE-2024-7591-PoC](https://github.com/butyraldehyde/CVE-2024-7591-PoC)  

---

### [CVE-2025-24813](CVE-2025-24813-137f_Poc-CVE-2025-24813.md) 🔴 ✅

**名称:** CVE-2025-24813 - Apache Tomcat 远程代码执行/信息泄露  
**类型:** 路径等价/反序列化  
**风险:** 高危，可能导致远程代码执行和信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-08-11  
**POC仓库:** [Poc-CVE-2025-24813](https://github.com/137f/Poc-CVE-2025-24813)  

---

### [CVE-2025-51643](CVE-2025-51643-NastyCrow_CVE-2025-51643.md) 🔴 ✅

**名称:** CVE-2025-51643: Meitrack T366G-L SPI Flash Firmware Extraction  
**类型:** 硬件安全漏洞，物理访问  
**风险:** 高危，敏感信息泄露，固件篡改  
**投毒风险:** 5%  
**发现时间:** 2025-08-11  
**POC仓库:** [CVE-2025-51643](https://github.com/NastyCrow/CVE-2025-51643)  

---

### [CVE-2025-31125](CVE-2025-31125-MuhammadWaseem29_Vitejs-exploit.md) 🟡 ✅

**名称:** CVE-2025-31125-Vite-任意文件读取  
**类型:** 任意文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-08-11  
**POC仓库:** [Vitejs-exploit](https://github.com/MuhammadWaseem29/Vitejs-exploit)  

---

### [CVE-2025-31125](CVE-2025-31125-nak000_Vitejs-exploit-CVE-2025-31125-rce.md) 🟡 ✅

**名称:** CVE-2025-31125-Vite-任意文件读取  
**类型:** 任意文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-08-11  
**POC仓库:** [Vitejs-exploit-CVE-2025-31125-rce](https://github.com/nak000/Vitejs-exploit-CVE-2025-31125-rce)  

---

### [CVE-2025-55188](CVE-2025-55188-san8383_CVE-2025-55188-7z-POC.md) 🟡 ✅

**名称:** CVE-2025-55188-7-Zip Symbolic Link Arbitrary File Write  
**类型:** 符号链接文件写入  
**风险:** 中危，可能导致敏感文件覆盖和潜在的代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-11  
**POC仓库:** [CVE-2025-55188-7z-POC](https://github.com/san8383/CVE-2025-55188-7z-POC)  

---

### [CVE-2022-36779](CVE-2022-36779-EmadYaY_CVE-2022-36779.md) 🔴 ✅

**名称:** CVE-2022-36779 - Proscend 工业路由器未授权OS命令注入  
**类型:** 未授权OS命令注入  
**风险:** 高危，可能导致设备完全控制，数据泄露，服务中断  
**投毒风险:** 0%  
**发现时间:** 2025-08-11  
**POC仓库:** [CVE-2022-36779](https://github.com/EmadYaY/CVE-2022-36779)  

---

### [CVE-2025-5777](CVE-2025-5777-rootxsushant_Citrix-NetScaler-Memory-Leak-CVE-2025-5777.md) 🔴 ✅

**名称:** CVE-2025-5777-NetScaler-内存信息泄露  
**类型:** 内存信息泄露  
**风险:** 高危，可能导致敏感信息泄露，会话劫持  
**投毒风险:** 10%  
**发现时间:** 2025-08-11  
**POC仓库:** [Citrix-NetScaler-Memory-Leak-CVE-2025-5777](https://github.com/rootxsushant/Citrix-NetScaler-Memory-Leak-CVE-2025-5777)  

---

### [CVE-2022-36779](CVE-2022-36779-rootDR_CVE-2022-36779.md) 🔴 ✅

**名称:** CVE-2022-36779-PROSCEND/ADVICE-OS Command Injection  
**类型:** OS Command Injection  
**风险:** 高危，可能导致远程代码执行和设备控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-11  
**POC仓库:** [CVE-2022-36779](https://github.com/rootDR/CVE-2022-36779)  

---

### [CVE-2022-36779](CVE-2022-36779-rootdr-backup_exploit-CVE-2022-36779.md) 🔴 ✅

**名称:** CVE-2022-36779 - PROSCEND 工业路由器 未授权OS命令注入  
**类型:** OS命令注入  
**风险:** 高危，可能导致设备完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-11  
**POC仓库:** [exploit-CVE-2022-36779](https://github.com/rootdr-backup/exploit-CVE-2022-36779)  

---

### [CVE-2015-4133](CVE-2015-4133-D3Ext_CVE-2015-4133.md) 🔴 ✅

**名称:** CVE-2015-4133 - WordPress ReFlex Gallery Plugin Arbitrary File Upload  
**类型:** Arbitrary File Upload  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-08-11  
**POC仓库:** [CVE-2015-4133](https://github.com/D3Ext/CVE-2015-4133)  

---

### [CVE-2015-10141](CVE-2015-10141-D3Ext_CVE-2015-10141.md) 🔴 ✅

**名称:** CVE-2015-10141 - Xdebug Remote Debugger Unauthenticated OS Command Execution  
**类型:** OS Command Injection  
**风险:** 高危，允许未授权用户执行任意系统命令，完全控制服务器。  
**投毒风险:** 10%  
**发现时间:** 2025-08-11  
**POC仓库:** [CVE-2015-10141](https://github.com/D3Ext/CVE-2015-10141)  

---

### [CVE-2016-10033](CVE-2016-10033-alexander47777_CVE-2016-10033.md) 🔴 ✅

**名称:** CVE-2016-10033-PHPMailer-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-11  
**POC仓库:** [CVE-2016-10033](https://github.com/alexander47777/CVE-2016-10033)  

---

### [CVE-2021-41773](CVE-2021-41773-mah4nzfr_CVE-2021-41773.md) 🔴 ✅

**名称:** CVE-2021-41773 - Apache HTTP Server Path Traversal and Remote Code Execution  
**类型:** 路径遍历和远程代码执行  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-11  
**POC仓库:** [CVE-2021-41773](https://github.com/mah4nzfr/CVE-2021-41773)  

---

### [CVE-2023-20938](CVE-2023-20938-anansi2safe_CVE-2023-20938.md) 🔴 ✅

**名称:** CVE-2023-20938 - Android Binder Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可能导致本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-08-11  
**POC仓库:** [CVE-2023-20938](https://github.com/anansi2safe/CVE-2023-20938)  

---

### [CVE-2025-55188](CVE-2025-55188-hunters-sec_CVE-2025-55188-7z-exploit.md) 🟡 ✅

**名称:** CVE-2025-55188-7-Zip符号链接任意文件写入漏洞  
**类型:** 符号链接攻击/任意文件写入  
**风险:** 中危，可能导致权限提升或拒绝服务，具体取决于被覆盖文件的敏感程度。  
**投毒风险:** 1%  
**发现时间:** 2025-08-11  
**POC仓库:** [CVE-2025-55188-7z-exploit](https://github.com/hunters-sec/CVE-2025-55188-7z-exploit)  

---

### [CVE-2011-2523](CVE-2011-2523-BolivarJ_CVE-2011-2523.md) 🔴 ✅

**名称:** CVE-2011-2523 - vsftpd 2.3.4 Backdoor  
**类型:** 后门  
**风险:** 高危，可能导致远程代码执行和完全系统控制  
**投毒风险:** 5%  
**发现时间:** 2025-08-11  
**POC仓库:** [CVE-2011-2523](https://github.com/BolivarJ/CVE-2011-2523)  

---

### [CVE-2025-8088](CVE-2025-8088-jordan922_CVE-2025-8088.md) 🔴 ✅

**名称:** CVE-2025-8088 WinRAR Path Traversal  
**类型:** 路径遍历  
**风险:** 高危，允许攻击者通过构造恶意压缩文件执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-08-11  
**POC仓库:** [CVE-2025-8088](https://github.com/jordan922/CVE-2025-8088)  

---

### [CVE-2024-37388](CVE-2024-37388-Narsimhareddy28_cve-2024-37388.md) 🔴 ✅

**名称:** CVE-2024-37388 - lxml XXE漏洞  
**类型:** XML外部实体注入 (XXE)  
**风险:** 高危，可能导致敏感信息泄露或拒绝服务攻击 (DoS)  
**投毒风险:** 10%  
**发现时间:** 2025-08-10  
**POC仓库:** [cve-2024-37388](https://github.com/Narsimhareddy28/cve-2024-37388)  

---

### [CVE-2025-1974](CVE-2025-1974-BiiTts_POC-IngressNightmare-CVE-2025-1974.md) 🔴 ✅

**名称:** CVE-2025-1974-ingress-nginx-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可以完全控制 Kubernetes 集群，暴露所有 Secrets  
**投毒风险:** 10%  
**发现时间:** 2025-08-10  
**POC仓库:** [POC-IngressNightmare-CVE-2025-1974](https://github.com/BiiTts/POC-IngressNightmare-CVE-2025-1974)  

---

### [CVE-2017-5941](CVE-2017-5941-Frivolous-scholar_CVE-2017-5941-NodeJS-RCE.md) 🔴 ✅

**名称:** CVE-2017-5941-node-serialize远程代码执行  
**类型:** 反序列化漏洞  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-10  
**POC仓库:** [CVE-2017-5941-NodeJS-RCE](https://github.com/Frivolous-scholar/CVE-2017-5941-NodeJS-RCE)  

---

### [CVE-2017-5941](CVE-2017-5941-turnernator1_Node.js-CVE-2017-5941.md) 🔴 ✅

**名称:** CVE-2017-5941-node-serialize-反序列化漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-08-10  
**POC仓库:** [Node.js-CVE-2017-5941](https://github.com/turnernator1/Node.js-CVE-2017-5941)  

---

### [CVE-2017-5941](CVE-2017-5941-uartu0_nodejshell.md) 🔴 ✅

**名称:** CVE-2017-5941-node-serialize-远程代码执行  
**类型:** 反序列化漏洞  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-08-10  
**POC仓库:** [nodejshell](https://github.com/uartu0/nodejshell)  

---

### [CVE-2017-5941](CVE-2017-5941-kylew1004_cve-2017-5941-poc-docker-lab.md) 🔴 ✅

**名称:** CVE-2017-5941 - node-serialize 反序列化RCE  
**类型:** 反序列化漏洞  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-08-10  
**POC仓库:** [cve-2017-5941-poc-docker-lab](https://github.com/kylew1004/cve-2017-5941-poc-docker-lab)  

---

### [CVE-2019-10102](CVE-2019-10102-RKX1209_CVE-2019-1010298.md) 🟡 ✅

**名称:** CVE-2019-1010298 (与CVE-2019-10102相关)  
**类型:** 不安全通信/中间人攻击 (基于CVE-2019-10102描述)  
**风险:** 中危，可能允许中间人攻击窃取构建过程中的凭据或替换artifact。  
**投毒风险:** 5%  
**发现时间:** 2025-08-10  
**POC仓库:** [CVE-2019-1010298](https://github.com/RKX1209/CVE-2019-1010298)  

---

### [CVE-2014-1303](CVE-2014-1303-RKX1209_CVE-2014-1303.md) 🔴 ✅

**名称:** CVE-2014-1303-Apple Safari 7.0.2-堆缓冲区溢出  
**类型:** 堆缓冲区溢出  
**风险:** 高危，允许远程攻击者执行任意代码并绕过沙箱保护机制  
**投毒风险:** 10%  
**发现时间:** 2025-08-10  
**POC仓库:** [CVE-2014-1303](https://github.com/RKX1209/CVE-2014-1303)  

---

### [CVE-2019-10102](CVE-2019-10102-ossf-cve-benchmark_CVE-2019-1010266.md) 🟡 

**名称:** CVE-2019-10102 - JetBrains Ktor Framework MITM Artifact Resolution  
**类型:** 中间人攻击 (MITM)  
**风险:** 中危，可能导致恶意代码注入  
**投毒风险:** 0%  
**发现时间:** 2025-08-10  
**POC仓库:** [CVE-2019-1010266](https://github.com/ossf-cve-benchmark/CVE-2019-1010266)  

---

### [CVE-2019-10102](CVE-2019-10102-Tonyynot14_CVE-2019-1010268.md) 🟡 

**名称:** CVE-2019-10102 - JetBrains Ktor Framework HTTP MITM  
**类型:** 中间人攻击 (MITM)  
**风险:** 中危，可能导致信息泄露和供应链投毒  
**投毒风险:** 0%  
**发现时间:** 2025-08-10  
**POC仓库:** [CVE-2019-1010268](https://github.com/Tonyynot14/CVE-2019-1010268)  

---

### [CVE-2025-24893](CVE-2025-24893-Retro023_CVE-2025-24893-POC.md) 🔴 ✅

**名称:** CVE-2025-24893-XWiki-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未授权用户执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-08-10  
**POC仓库:** [CVE-2025-24893-POC](https://github.com/Retro023/CVE-2025-24893-POC)  

---

### [CVE-2021-30809](CVE-2021-30809-seregonwar_CVE-2021-30809-UAF.md) 🔴 ✅

**名称:** CVE-2021-30809 - Apple WebKit Use-After-Free  
**类型:** Use-After-Free (UAF)  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-08-09  
**POC仓库:** [CVE-2021-30809-UAF](https://github.com/seregonwar/CVE-2021-30809-UAF)  

---

### [CVE-2025-24893](CVE-2025-24893-D3Ext_CVE-2025-24893.md) 🔴 ✅

**名称:** CVE-2025-24893-XWiki-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-09  
**POC仓库:** [CVE-2025-24893](https://github.com/D3Ext/CVE-2025-24893)  

---

### [CVE-2025-32463](CVE-2025-32463-behnamvanda_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地权限提升  
**风险:** 高危，本地用户可获取Root权限  
**投毒风险:** 0%  
**发现时间:** 2025-08-09  
**POC仓库:** [CVE-2025-32463](https://github.com/behnamvanda/CVE-2025-32463)  

---

### [CVE-2025-21298](CVE-2025-21298-B1ack4sh_Blackash-CVE-2025-21298.md) 🔴 ✅

**名称:** CVE-2025-21298 - Windows OLE 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，远程代码执行，可能导致完全系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-09  
**POC仓库:** [Blackash-CVE-2025-21298](https://github.com/B1ack4sh/Blackash-CVE-2025-21298)  

---

### [CVE-2014-6271](CVE-2014-6271-RAJMadhusankha_Shellshock-CVE-2014-6271-Exploitation-and-Analysis.md) 🔴 ✅

**名称:** CVE-2014-6271 Shellshock漏洞利用  
**类型:** 远程代码执行  
**风险:** 高危，允许未经授权的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-09  
**POC仓库:** [Shellshock-CVE-2014-6271-Exploitation-and-Analysis](https://github.com/RAJMadhusankha/Shellshock-CVE-2014-6271-Exploitation-and-Analysis)  

---

### [CVE-2025-4404](CVE-2025-4404-Cyxow_CVE-2025-4404-POC.md) 🔴 ✅

**名称:** CVE-2025-4404-FreeIPA-权限提升  
**类型:** 权限提升  
**风险:** 高危，可能导致域管理员权限被窃取  
**投毒风险:** 10%  
**发现时间:** 2025-08-09  
**POC仓库:** [CVE-2025-4404-POC](https://github.com/Cyxow/CVE-2025-4404-POC)  

---

### [CVE-2022-0000](CVE-2022-0000-nullsquirtle_CVE-2022-0000-PoC.md)  ✅

**名称:** CVE-2022-0000-PoC  
**类型:** 未知  
**风险:** 低危  
**投毒风险:** 10%  
**发现时间:** 2025-08-09  
**POC仓库:** [CVE-2022-0000-PoC](https://github.com/nullsquirtle/CVE-2022-0000-PoC)  

---

### [CVE-2025-6384](CVE-2025-6384-mbadanoiu_CVE-2025-6384.md) 🔴 ✅

**名称:** CVE-2025-6384-CrafterCMS-Groovy沙箱绕过RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2025-6384](https://github.com/mbadanoiu/CVE-2025-6384)  

---

### [CVE-2025-8730](CVE-2025-8730-byteReaper77_CVE-2025-8730.md) 🔴 ✅

**名称:** CVE-2025-8730 Belkin F9K1009/F9K1010 Web Interface 认证绕过  
**类型:** 认证绕过  
**风险:** 高危，允许未经授权的远程访问和控制路由器  
**投毒风险:** 10%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2025-8730](https://github.com/byteReaper77/CVE-2025-8730)  

---

### [CVE-2025-24893](CVE-2025-24893-alaxar_CVE-2025-24893.md) 🔴 ✅

**名称:** CVE-2025-24893-XWiki-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2025-24893](https://github.com/alaxar/CVE-2025-24893)  

---

### [CVE-2018-7600](CVE-2018-7600-rajaabdullahnasir_CVE-2018-7600-Remote-Code-Execution.md) 🔴 ✅

**名称:** CVE-2018-7600-Drupalgeddon2-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2018-7600-Remote-Code-Execution](https://github.com/rajaabdullahnasir/CVE-2018-7600-Remote-Code-Execution)  

---

### [CVE-2025-32463](CVE-2025-32463-Nowafen_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可提升至root权限  
**投毒风险:** 5%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2025-32463](https://github.com/Nowafen/CVE-2025-32463)  

---

### [CVE-2025-31722](CVE-2025-31722-Nick6371_CVE-2025-31722.md) 🔴 ✅

**名称:** CVE-2025-31722-Jenkins Templating Engine Plugin-代码注入  
**类型:** 代码注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2025-31722](https://github.com/Nick6371/CVE-2025-31722)  

---

### [CVE-2025-24354](CVE-2025-24354-Admin9961_CVE-2025-24354-PoC.md) 🟡 ✅

**名称:** CVE-2025-24354-imgproxy-SSRF  
**类型:** SSRF  
**风险:** 中危，可能暴露内网服务信息  
**投毒风险:** 1%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2025-24354-PoC](https://github.com/Admin9961/CVE-2025-24354-PoC)  

---

### [CVE-2025-32463](CVE-2025-32463-Nowafen_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可提升至root权限  
**投毒风险:** 10%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2025-32463](https://github.com/Nowafen/CVE-2025-32463)  

---

### [CVE-2025-24893](CVE-2025-24893-The-Red-Serpent_CVE-2025-24893.md) 🔴 ✅

**名称:** CVE-2025-24893-XWiki-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2025-24893](https://github.com/The-Red-Serpent/CVE-2025-24893)  

---

### [CVE-2025-53786](CVE-2025-53786-barbaraeivyu_CVE-2025-53786.md) 🔴 ✅

**名称:** CVE-2025-53786 - Microsoft Exchange Server Hybrid Deployment 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致本地和云环境的完全控制  
**投毒风险:** 60%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2025-53786](https://github.com/barbaraeivyu/CVE-2025-53786)  

---

### [CVE-2022-22947](CVE-2022-22947-talentsec_Spring-Cloud-Gateway-CVE-2022-22947.md) 🔴 ✅

**名称:** CVE-2022-22947 - Spring Cloud Gateway Code Injection  
**类型:** 代码注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-08-08  
**POC仓库:** [Spring-Cloud-Gateway-CVE-2022-22947](https://github.com/talentsec/Spring-Cloud-Gateway-CVE-2022-22947)  

---

### [CVE-2022-22947](CVE-2022-22947-aesm1p_CVE-2022-22947-POC-Reproduce.md) 🔴 ✅

**名称:** CVE-2022-22947-Spring Cloud Gateway Code Injection  
**类型:** 代码注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2022-22947-POC-Reproduce](https://github.com/aesm1p/CVE-2022-22947-POC-Reproduce)  

---

### [CVE-2022-22947](CVE-2022-22947-Enokiy_cve-2022-22947-spring-cloud-gateway.md) 🔴 ✅

**名称:** CVE-2022-22947-Spring Cloud Gateway-代码注入  
**类型:** 代码注入  
**风险:** 高危，可远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-08  
**POC仓库:** [cve-2022-22947-spring-cloud-gateway](https://github.com/Enokiy/cve-2022-22947-spring-cloud-gateway)  

---

### [CVE-2022-22947](CVE-2022-22947-kkx600_Burp_VulPscan.md) 🔴 ✅

**名称:** CVE-2022-22947-Spring Cloud Gateway 代码注入  
**类型:** 代码注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-08  
**POC仓库:** [Burp_VulPscan](https://github.com/kkx600/Burp_VulPscan)  

---

### [CVE-2022-22947](CVE-2022-22947-twseptian_cve-2022-22947.md) 🔴 ✅

**名称:** CVE-2022-22947-Spring Cloud Gateway-代码注入  
**类型:** 代码注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-08  
**POC仓库:** [cve-2022-22947](https://github.com/twseptian/cve-2022-22947)  

---

### [CVE-2022-22947](CVE-2022-22947-whwlsfb_cve-2022-22947-godzilla-memshell.md) 🔴 ✅

**名称:** CVE-2022-22947-Spring Cloud Gateway-代码注入  
**类型:** 代码注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-08  
**POC仓库:** [cve-2022-22947-godzilla-memshell](https://github.com/whwlsfb/cve-2022-22947-godzilla-memshell)  

---

### [CVE-2022-22947](CVE-2022-22947-0730Nophone_CVE-2022-22947-.md) 🔴 ✅

**名称:** CVE-2022-22947-Spring Cloud Gateway-代码注入  
**类型:** 代码注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2022-22947-](https://github.com/0730Nophone/CVE-2022-22947-)  

---

### [CVE-2022-22947](CVE-2022-22947-anansec_CVE-2022-22947_EXP.md) 🔴 ✅

**名称:** CVE-2022-22947-Spring Cloud Gateway-代码注入  
**类型:** 代码注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2022-22947_EXP](https://github.com/anansec/CVE-2022-22947_EXP)  

---

### [CVE-2022-22947](CVE-2022-22947-Wrong-pixel_CVE-2022-22947-exp.md) 🔴 ✅

**名称:** CVE-2022-22947-Spring Cloud Gateway代码注入  
**类型:** 代码注入  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2022-22947-exp](https://github.com/Wrong-pixel/CVE-2022-22947-exp)  

---

### [CVE-2022-22947](CVE-2022-22947-stayfoolish777_CVE-2022-22947-POC.md) 🔴 ✅

**名称:** CVE-2022-22947-Spring Cloud Gateway-代码注入  
**类型:** 代码注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2022-22947-POC](https://github.com/stayfoolish777/CVE-2022-22947-POC)  

---

### [CVE-2022-22947](CVE-2022-22947-B0rn2d_Spring-Cloud-Gateway-Nacos.md) 🔴 ✅

**名称:** CVE-2022-22947 Spring Cloud Gateway 代码注入  
**类型:** 代码注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-08  
**POC仓库:** [Spring-Cloud-Gateway-Nacos](https://github.com/B0rn2d/Spring-Cloud-Gateway-Nacos)  

---

### [CVE-2022-22947](CVE-2022-22947-kmahyyg_CVE-2022-22947.md) 🔴 ✅

**名称:** CVE-2022-22947 Spring Cloud Gateway 代码注入  
**类型:** 代码注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2022-22947](https://github.com/kmahyyg/CVE-2022-22947)  

---

### [CVE-2022-22947](CVE-2022-22947-k3rwin_spring-cloud-gateway-rce.md) 🔴 ✅

**名称:** CVE-2022-22947 Spring Cloud Gateway RCE  
**类型:** 代码注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-08  
**POC仓库:** [spring-cloud-gateway-rce](https://github.com/k3rwin/spring-cloud-gateway-rce)  

---

### [CVE-2022-22947](CVE-2022-22947-LY613313_CVE-2022-22947.md) 🔴 ✅

**名称:** CVE-2022-22947 - Spring Cloud Gateway 代码注入  
**类型:** 代码注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2022-22947](https://github.com/LY613313/CVE-2022-22947)  

---

### [CVE-2022-22947](CVE-2022-22947-SiJiDo_CVE-2022-22947.md) 🔴 ✅

**名称:** CVE-2022-22947-Spring Cloud Gateway-代码注入  
**类型:** 代码注入  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2022-22947](https://github.com/SiJiDo/CVE-2022-22947)  

---

### [CVE-2022-22947](CVE-2022-22947-4nNns_CVE-2022-22947.md)  ✅

**名称:** CVE-2022-22947 - Spring Cloud Gateway 代码注入  
**类型:** 代码注入  
**风险:** 严重，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2022-22947](https://github.com/4nNns/CVE-2022-22947)  

---

### [CVE-2022-22947](CVE-2022-22947-SecNN_CVE-2022-22947_Rce_Exp.md) 🔴 ✅

**名称:** CVE-2022-22947 Spring Cloud Gateway代码注入  
**类型:** 代码注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2022-22947_Rce_Exp](https://github.com/SecNN/CVE-2022-22947_Rce_Exp)  

---

### [CVE-2022-22947](CVE-2022-22947-qq87234770_CVE-2022-22947.md) 🔴 ✅

**名称:** CVE-2022-22947 - Spring Cloud Gateway Code Injection  
**类型:** 代码注入  
**风险:** 高危，可远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2022-22947](https://github.com/qq87234770/CVE-2022-22947)  

---

### [CVE-2022-22947](CVE-2022-22947-Le1a_CVE-2022-22947.md) 🔴 ✅

**名称:** CVE-2022-22947 Spring Cloud Gateway 代码注入  
**类型:** 代码注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2022-22947](https://github.com/Le1a/CVE-2022-22947)  

---

### [CVE-2022-22947](CVE-2022-22947-Zh0um1_CVE-2022-22947.md) 🔴 ✅

**名称:** CVE-2022-22947 - Spring Cloud Gateway 代码注入  
**类型:** 代码注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2022-22947](https://github.com/Zh0um1/CVE-2022-22947)  

---

### [CVE-2022-22947](CVE-2022-22947-Sumitpathania03_CVE-2022-22947.md) 🔴 ✅

**名称:** CVE-2022-22947 Spring Cloud Gateway 代码注入  
**类型:** 代码注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 85%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2022-22947](https://github.com/Sumitpathania03/CVE-2022-22947)  

---

### [CVE-2022-22947](CVE-2022-22947-cc3305_CVE-2022-22947.md) 🔴 ✅

**名称:** CVE-2022-22947-Spring Cloud Gateway代码注入  
**类型:** 代码注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2022-22947](https://github.com/cc3305/CVE-2022-22947)  

---

### [CVE-2022-22947](CVE-2022-22947-skysliently_CVE-2022-22947-pb-ai.md) 🔴 ✅

**名称:** CVE-2022-22947 Spring Cloud Gateway 代码注入  
**类型:** 代码注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2022-22947-pb-ai](https://github.com/skysliently/CVE-2022-22947-pb-ai)  

---

### [CVE-2022-0847](CVE-2022-0847-Scouserr_cve-2022-0847-poc-dockerimage.md) 🔴 ✅

**名称:** CVE-2022-0847-Dirty Pipe  
**类型:** 本地提权  
**风险:** 高危，本地权限提升  
**投毒风险:** 1%  
**发现时间:** 2025-08-08  
**POC仓库:** [cve-2022-0847-poc-dockerimage](https://github.com/Scouserr/cve-2022-0847-poc-dockerimage)  

---

### [CVE-2025-22963](CVE-2025-22963-gmh5225_CVE-2025-22963.md) 🔴 ✅

**名称:** CVE-2025-22963-Teedy-CSRF账户接管  
**类型:** 跨站请求伪造 (CSRF)  
**风险:** 高危，可导致账户接管  
**投毒风险:** 5%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2025-22963](https://github.com/gmh5225/CVE-2025-22963)  

---

### [CVE-2025-22963](CVE-2025-22963-samplev45_CVE-2025-22963.md) 🔴 ✅

**名称:** CVE-2025-22963-Teedy-CSRF  
**类型:** CSRF (跨站请求伪造)  
**风险:** 高危，可能导致账户接管  
**投毒风险:** 10%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2025-22963](https://github.com/samplev45/CVE-2025-22963)  

---

### [CVE-2019-18935](CVE-2019-18935-ThanHuuTuan_CVE_2019_18935.md) 🔴 ✅

**名称:** CVE-2019-18935-Telerik UI for ASP.NET AJAX-反序列化漏洞  
**类型:** 反序列化  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE_2019_18935](https://github.com/ThanHuuTuan/CVE_2019_18935)  

---

### [CVE-2019-18935](CVE-2019-18935-appliedi_Telerik_CVE-2019-18935.md) 🔴 ✅

**名称:** CVE-2019-18935 - Telerik UI for ASP.NET AJAX 反序列化RCE  
**类型:** 反序列化RCE  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-08  
**POC仓库:** [Telerik_CVE-2019-18935](https://github.com/appliedi/Telerik_CVE-2019-18935)  

---

### [CVE-2019-18935](CVE-2019-18935-murataydemir_CVE-2019-18935.md) 🔴 ✅

**名称:** CVE-2019-18935 - Progress Telerik UI for ASP.NET AJAX RadAsyncUpload .NET 反序列化漏洞  
**类型:** .NET反序列化漏洞  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2019-18935](https://github.com/murataydemir/CVE-2019-18935)  

---

### [CVE-2019-18935](CVE-2019-18935-random-robbie_CVE-2019-18935.md) 🔴 ✅

**名称:** CVE-2019-18935 - Progress Telerik UI for ASP.NET AJAX 反序列化漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2019-18935](https://github.com/random-robbie/CVE-2019-18935)  

---

### [CVE-2019-18935](CVE-2019-18935-becrevex_Telerik_CVE-2019-18935.md) 🔴 ✅

**名称:** CVE-2019-18935 - Telerik UI for ASP.NET AJAX Deserialization RCE  
**类型:** .NET Deserialization Remote Code Execution  
**风险:** 高危，允许未经身份验证的远程攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-08  
**POC仓库:** [Telerik_CVE-2019-18935](https://github.com/becrevex/Telerik_CVE-2019-18935)  

---

### [CVE-2019-18935](CVE-2019-18935-0xAgun_CVE-2019-18935-checker.md) 🔴 ✅

**名称:** CVE-2019-18935 - Progress Telerik UI for ASP.NET AJAX Deserialization RCE  
**类型:** .NET Deserialization  
**风险:** 高危，远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2019-18935-checker](https://github.com/0xAgun/CVE-2019-18935-checker)  

---

### [CVE-2019-18935](CVE-2019-18935-noperator_CVE-2019-18935.md) 🔴 ✅

**名称:** CVE-2019-18935-Telerik UI for ASP.NET AJAX-反序列化漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2019-18935](https://github.com/noperator/CVE-2019-18935)  

---

### [CVE-2019-18935](CVE-2019-18935-ThanHuuTuan_Telerik_CVE-2019-18935.md) 🔴 ✅

**名称:** CVE-2019-18935 - Progress Telerik UI for ASP.NET AJAX 反序列化 RCE  
**类型:** 反序列化远程代码执行  
**风险:** 高危，可导致远程代码执行，服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-08  
**POC仓库:** [Telerik_CVE-2019-18935](https://github.com/ThanHuuTuan/Telerik_CVE-2019-18935)  

---

### [CVE-2019-18935](CVE-2019-18935-dust-life_CVE-2019-18935-memShell.md) 🔴 ✅

**名称:** CVE-2019-18935 - Telerik UI for ASP.NET AJAX Deserialization RCE  
**类型:** .NET Deserialization Remote Code Execution  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2019-18935-memShell](https://github.com/dust-life/CVE-2019-18935-memShell)  

---

### [CVE-2019-18935](CVE-2019-18935-clarkvoss_telerik.md) 🔴 ✅

**名称:** CVE-2019-18935 - Telerik UI for ASP.NET AJAX 反序列化远程代码执行  
**类型:** .NET 反序列化漏洞  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-08-08  
**POC仓库:** [telerik](https://github.com/clarkvoss/telerik)  

---

### [CVE-2019-18935](CVE-2019-18935-ekkoo-z_CVE-2019-18935-bypasswaf.md) 🔴 ✅

**名称:** CVE-2019-18935-Telerik UI for ASP.NET AJAX 反序列化漏洞  
**类型:** .NET 反序列化  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2019-18935-bypasswaf](https://github.com/ekkoo-z/CVE-2019-18935-bypasswaf)  

---

### [CVE-2025-24893](CVE-2025-24893-Hex00-0x4_CVE-2025-24893-XWiki-RCE.md) 🔴 ✅

**名称:** CVE-2025-24893 - XWiki Platform Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，允许未授权的远程代码执行，可能导致完全的服务器控制、数据泄露和破坏以及内网渗透。  
**投毒风险:** 10%  
**发现时间:** 2025-08-08  
**POC仓库:** [CVE-2025-24893-XWiki-RCE](https://github.com/Hex00-0x4/CVE-2025-24893-XWiki-RCE)  

---

### [CVE-2011-2523](CVE-2011-2523-As9xm_BrokenDoor-CVE-2011-2523-.md) 🔴 ✅

**名称:** CVE-2011-2523-vsftpd-Backdoor  
**类型:** 后门  
**风险:** 高危，可远程执行任意命令  
**投毒风险:** 1%  
**发现时间:** 2025-08-08  
**POC仓库:** [BrokenDoor-CVE-2011-2523-](https://github.com/As9xm/BrokenDoor-CVE-2011-2523-)  

---

### [CVE-2025-24893](CVE-2025-24893-Th3Gl0w_CVE-2025-24893-POC.md) 🔴 ✅

**名称:** CVE-2025-24893-XWiki-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-07  
**POC仓库:** [CVE-2025-24893-POC](https://github.com/Th3Gl0w/CVE-2025-24893-POC)  

---

### [CVE-2025-5777](CVE-2025-5777-soltanali0_CVE-2025-5777-Exploit.md) 🔴 ✅

**名称:** CVE-2025-5777-NetScaler ADC/Gateway-内存信息泄露  
**类型:** 内存信息泄露  
**风险:** 高危，可能导致敏感信息泄露，会话劫持等  
**投毒风险:** 10%  
**发现时间:** 2025-08-07  
**POC仓库:** [CVE-2025-5777-Exploit](https://github.com/soltanali0/CVE-2025-5777-Exploit)  

---

### [CVE-2025-24893](CVE-2025-24893-mah4nzfr_CVE-2025-24893.md) 🔴 ✅

**名称:** CVE-2025-24893-XWiki-RCE  
**类型:** 远程代码执行  
**风险:** 高危，未授权即可远程执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-07  
**POC仓库:** [CVE-2025-24893](https://github.com/mah4nzfr/CVE-2025-24893)  

---

### [CVE-2025-34152](CVE-2025-34152-Chocapikk_CVE-2025-34152.md) 🔴 ✅

**名称:** CVE-2025-34152 - Shenzhen Aitemi M300 Wi-Fi Repeater OS 命令注入  
**类型:** OS 命令注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-07  
**POC仓库:** [CVE-2025-34152](https://github.com/Chocapikk/CVE-2025-34152)  

---

### [CVE-2025-29927](CVE-2025-29927-rgvillanueva28_vulnbox-easy-CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-Middleware-权限绕过  
**类型:** 权限绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 1%  
**发现时间:** 2025-08-07  
**POC仓库:** [vulnbox-easy-CVE-2025-29927](https://github.com/rgvillanueva28/vulnbox-easy-CVE-2025-29927)  

---

### [CVE-2025-53770](CVE-2025-53770-Agampreet-Singh_CVE-2025-53770.md) 🔴 ✅

**名称:** CVE-2025-53770 - Microsoft SharePoint Server RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-07  
**POC仓库:** [CVE-2025-53770](https://github.com/Agampreet-Singh/CVE-2025-53770)  

---

### [CVE-2025-29927](CVE-2025-29927-aayush256-sys_next-js-auth-bypass.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js Middleware 权限绕过  
**类型:** 权限绕过  
**风险:** 高危，可能导致未授权访问敏感数据  
**投毒风险:** 5%  
**发现时间:** 2025-08-07  
**POC仓库:** [next-js-auth-bypass](https://github.com/aayush256-sys/next-js-auth-bypass)  

---

### [CVE-2025-24893](CVE-2025-24893-Hex00-1337_CVE-2025-24893-XWiki-Platform-Remote-Code-Execution.md) 🔴 ✅

**名称:** CVE-2025-24893-XWiki-RCE  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-07  
**POC仓库:** [CVE-2025-24893-XWiki-Platform-Remote-Code-Execution](https://github.com/Hex00-1337/CVE-2025-24893-XWiki-Platform-Remote-Code-Execution)  

---

### [CVE-2025-24893](CVE-2025-24893-Hex00-1337_CVE-2025-24893-XWiki-Platform---Remote-Code-Execution.md) 🔴 ✅

**名称:** CVE-2025-24893-XWiki-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-07  
**POC仓库:** [CVE-2025-24893-XWiki-Platform---Remote-Code-Execution](https://github.com/Hex00-1337/CVE-2025-24893-XWiki-Platform---Remote-Code-Execution)  

---

### [CVE-2025-24893](CVE-2025-24893-IIIeJlyXaKapToIIIKu_CVE-2025-24893-XWiki-unauthenticated-RCE-via-SolrSearch.md)  ✅

**名称:** CVE-2025-24893-XWiki-RCE  
**类型:** 远程代码执行  
**风险:** 严重，可能导致完全控制受影响的系统  
**投毒风险:** 0%  
**发现时间:** 2025-08-07  
**POC仓库:** [CVE-2025-24893-XWiki-unauthenticated-RCE-via-SolrSearch](https://github.com/IIIeJlyXaKapToIIIKu/CVE-2025-24893-XWiki-unauthenticated-RCE-via-SolrSearch)  

---

### [CVE-2025-54948](CVE-2025-54948-allinsthon_CVE-2025-54948.md) 🔴 ✅

**名称:** CVE-2025-54948-TrendMicroApexOne-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-07  
**POC仓库:** [CVE-2025-54948](https://github.com/allinsthon/CVE-2025-54948)  

---

### [CVE-2025-54253](CVE-2025-54253-barbaraeivyu_CVE-2025-54253-e.md) 🔴 ✅

**名称:** CVE-2025-54253 - Adobe Experience Manager 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 20%  
**发现时间:** 2025-08-07  
**POC仓库:** [CVE-2025-54253-e](https://github.com/barbaraeivyu/CVE-2025-54253-e)  

---

### [CVE-2017-7921](CVE-2017-7921-initon_Hikvision---CVE-2017-7921.md) 🔴 ✅

**名称:** CVE-2017-7921 - Hikvision IP Camera Improper Authentication  
**类型:** 权限提升/认证绕过  
**风险:** 高危，可导致完全控制设备、敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-08-07  
**POC仓库:** [Hikvision---CVE-2017-7921](https://github.com/initon/Hikvision---CVE-2017-7921)  

---

### [CVE-2025-7769](CVE-2025-7769-byteReaper77_CVE-2025-7769.md) 🔴 ✅

**名称:** CVE-2025-7769-Tigo Energy Cloud Connect Advanced-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致未经授权的访问、服务中断和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-08-07  
**POC仓库:** [CVE-2025-7769](https://github.com/byteReaper77/CVE-2025-7769)  

---

### [CVE-2025-4126](CVE-2025-4126-Slow-Mist_CVE-2025-4126.md) 🟡 

**名称:** CVE-2025-4126 - EG-Series Plugin Stored XSS  
**类型:** 存储型跨站脚本 (Stored XSS)  
**风险:** 中危，可能导致用户凭据泄露或恶意脚本执行  
**投毒风险:** 99%  
**发现时间:** 2025-08-07  
**POC仓库:** [CVE-2025-4126](https://github.com/Slow-Mist/CVE-2025-4126)  

---

### [CVE-2025-30406](CVE-2025-30406-Gersonaze_CVE-2025-30406.md) 🔴 ✅

**名称:** CVE-2025-30406-Gladinet CentreStack-反序列化  
**类型:** 反序列化  
**风险:** 高危，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-07  
**POC仓库:** [CVE-2025-30406](https://github.com/Gersonaze/CVE-2025-30406)  

---

### [CVE-2024-32019](CVE-2024-32019-C0deInBlack_CVE-2024-32019-poc.md) 🔴 ✅

**名称:** CVE-2024-32019-netdata-本地提权  
**类型:** 本地提权  
**风险:** 高危，本地权限提升至root  
**投毒风险:** 5%  
**发现时间:** 2025-08-06  
**POC仓库:** [CVE-2024-32019-poc](https://github.com/C0deInBlack/CVE-2024-32019-poc)  

---

### [CVE-2024-32167](CVE-2024-32167-Narsimhareddy28_CVE-2024-32167.md) 🔴 ✅

**名称:** CVE-2024-32167 - Sourcecodester Online Medicine Ordering System 1.0 Arbitrary File Deletion  
**类型:** 任意文件删除  
**风险:** 高危，可能导致数据丢失，系统不可用  
**投毒风险:** 10%  
**发现时间:** 2025-08-06  
**POC仓库:** [CVE-2024-32167](https://github.com/Narsimhareddy28/CVE-2024-32167)  

---

### [CVE-2025-54253](CVE-2025-54253-Shivshantp_CVE-2025-54253-Exploit-Demo.md) 🔴 ✅

**名称:** CVE-2025-54253-Adobe Experience Manager-Misconfiguration  
**类型:** Misconfiguration  
**风险:** 高危，可导致任意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-06  
**POC仓库:** [CVE-2025-54253-Exploit-Demo](https://github.com/Shivshantp/CVE-2025-54253-Exploit-Demo)  

---

### [CVE-2025-24893](CVE-2025-24893-570RMBR3AK3R_xwiki-cve-2025-24893-poc.md)  ✅

**名称:** CVE-2025-24893 - XWiki RCE  
**类型:** 远程代码执行  
**风险:** 严重，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-06  
**POC仓库:** [xwiki-cve-2025-24893-poc](https://github.com/570RMBR3AK3R/xwiki-cve-2025-24893-poc)  

---

### [CVE-2021-3544](CVE-2021-3544-Goultarde_CVE-2021-3544_RemoteMouse-3.008-RCE.md)  

**名称:** CVE-2021-3544 - QEMU vhost-user-gpu 内存泄漏  
**类型:** 内存泄漏  
**风险:** 低危，可能导致拒绝服务。  
**投毒风险:** 0%  
**发现时间:** 2025-08-06  
**POC仓库:** [CVE-2021-3544_RemoteMouse-3.008-RCE](https://github.com/Goultarde/CVE-2021-3544_RemoteMouse-3.008-RCE)  

---

### [CVE-2025-54794](CVE-2025-54794-AdityaBhatt3010_CVE-2025-54794-Hijacking-Claude-AI-with-a-Prompt-Injection-The-Jailbreak-That-Talked-Back.md) 🔴 ✅

**名称:** CVE-2025-54794 - Claude Code Path Traversal  
**类型:** 路径遍历/提示注入  
**风险:** 高危，可能导致未授权文件访问和信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-08-06  
**POC仓库:** [CVE-2025-54794-Hijacking-Claude-AI-with-a-Prompt-Injection-The-Jailbreak-That-Talked-Back](https://github.com/AdityaBhatt3010/CVE-2025-54794-Hijacking-Claude-AI-with-a-Prompt-Injection-The-Jailbreak-That-Talked-Back)  

---

### [CVE-2025-54253](CVE-2025-54253-B1ack4sh_Blackash-CVE-2025-54253.md)  

**名称:** CVE-2025-54253 - Adobe Experience Manager RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致完全系统控制和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-08-06  
**POC仓库:** [Blackash-CVE-2025-54253](https://github.com/B1ack4sh/Blackash-CVE-2025-54253)  

---

### [CVE-2025-24813](CVE-2025-24813-cyglegit_CVE-2025-24813.md) 🔴 ✅

**名称:** CVE-2025-24813 Apache Tomcat 路径等价漏洞  
**类型:** 路径等价/反序列化  
**风险:** 高危，可能导致远程代码执行和信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-08-06  
**POC仓库:** [CVE-2025-24813](https://github.com/cyglegit/CVE-2025-24813)  

---

### [CVE-2025-48621](CVE-2025-48621-Layer1-Artist_POC-CVE-2025-48621.md) 🔴 ✅

**名称:** CVE-2025-48621-Smart Contract Reentrancy Attack  
**类型:** 智能合约重入攻击  
**风险:** 高危，可能导致资金被盗  
**投毒风险:** 10%  
**发现时间:** 2025-08-06  
**POC仓库:** [POC-CVE-2025-48621](https://github.com/Layer1-Artist/POC-CVE-2025-48621)  

---

### [CVE-2020-0796](CVE-2020-0796-esmwaSpyware_DoS-PoC-for-CVE-2020-0796-SMBGhost-.md) 🔴 ✅

**名称:** CVE-2020-0796 - SMBGhost 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可导致远程代码执行和系统崩溃  
**投毒风险:** 0%  
**发现时间:** 2025-08-06  
**POC仓库:** [DoS-PoC-for-CVE-2020-0796-SMBGhost-](https://github.com/esmwaSpyware/DoS-PoC-for-CVE-2020-0796-SMBGhost-)  

---

### [CVE-2017-7921](CVE-2017-7921-BurnyMcDull_CVE-2017-7921.md) 🔴 ✅

**名称:** CVE-2017-7921-Hikvision摄像机未授权访问  
**类型:** 未授权访问  
**风险:** 高危，可能导致敏感信息泄露和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-08-06  
**POC仓库:** [CVE-2017-7921](https://github.com/BurnyMcDull/CVE-2017-7921)  

---

### [CVE-2017-7921](CVE-2017-7921-MisakaMikato_cve-2017-7921-golang.md) 🔴 ✅

**名称:** CVE-2017-7921-Hikvision摄像机身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致权限提升和敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-08-06  
**POC仓库:** [cve-2017-7921-golang](https://github.com/MisakaMikato/cve-2017-7921-golang)  

---

### [CVE-2017-7921](CVE-2017-7921-chrisjd20_hikvision_CVE-2017-7921_auth_bypass_config_decryptor.md) 🔴 ✅

**名称:** CVE-2017-7921 - Hikvision IP Camera Authentication Bypass and Configuration Decryption  
**类型:** 认证绕过  
**风险:** 高危，可能导致敏感信息泄露和权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-08-06  
**POC仓库:** [hikvision_CVE-2017-7921_auth_bypass_config_decryptor](https://github.com/chrisjd20/hikvision_CVE-2017-7921_auth_bypass_config_decryptor)  

---

### [CVE-2017-7921](CVE-2017-7921-p4tq_hikvision_CVE-2017-7921_auth_bypass_config_decryptor.md) 🔴 ✅

**名称:** CVE-2017-7921-Hikvision摄像机认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致信息泄露和权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-08-06  
**POC仓库:** [hikvision_CVE-2017-7921_auth_bypass_config_decryptor](https://github.com/p4tq/hikvision_CVE-2017-7921_auth_bypass_config_decryptor)  

---

### [CVE-2017-7921](CVE-2017-7921-201646613_CVE-2017-7921.md) 🔴 ✅

**名称:** CVE-2017-7921-Hikvision摄像机-不当身份验证  
**类型:** 不当身份验证  
**风险:** 高危，可能导致权限提升和敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-08-06  
**POC仓库:** [CVE-2017-7921](https://github.com/201646613/CVE-2017-7921)  

---

### [CVE-2017-7921](CVE-2017-7921-inj3ction_CVE-2017-7921-EXP.md) 🔴 ✅

**名称:** CVE-2017-7921 - 海康威视摄像机不当身份验证漏洞  
**类型:** 不当身份验证  
**风险:** 高危，可能导致权限提升和敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-08-06  
**POC仓库:** [CVE-2017-7921-EXP](https://github.com/inj3ction/CVE-2017-7921-EXP)  

---

### [CVE-2017-7921](CVE-2017-7921-krypton612_hikivision.md) 🔴 ✅

**名称:** CVE-2017-7921-Hikvision摄像机未授权访问  
**类型:** 未授权访问/权限提升  
**风险:** 高危，可能导致信息泄露、设备控制和拒绝服务  
**投毒风险:** 5%  
**发现时间:** 2025-08-06  
**POC仓库:** [hikivision](https://github.com/krypton612/hikivision)  

---

### [CVE-2017-7921](CVE-2017-7921-GabrielAvls_CVE-2017-7921.md) 🔴 ✅

**名称:** CVE-2017-7921 Hikvision Camera Improper Authentication  
**类型:** Improper Authentication  
**风险:** 高危，可能导致权限提升，获取敏感信息，远程代码执行（取决于具体配置）  
**投毒风险:** 10%  
**发现时间:** 2025-08-06  
**POC仓库:** [CVE-2017-7921](https://github.com/GabrielAvls/CVE-2017-7921)  

---

### [CVE-2017-7921](CVE-2017-7921-AnonkiGroup_AnonHik.md) 🔴 ✅

**名称:** CVE-2017-7921-Hikvision摄像机-不当身份验证  
**类型:** 不当身份验证  
**风险:** 高危，可能导致信息泄露和权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-08-06  
**POC仓库:** [AnonHik](https://github.com/AnonkiGroup/AnonHik)  

---

### [CVE-2017-7921](CVE-2017-7921-b3pwn3d_CVE-2017-7921.md) 🔴 ✅

**名称:** CVE-2017-7921-Hikvision-不当身份验证  
**类型:** 不当身份验证  
**风险:** 高危，可能导致未授权访问、信息泄露和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-08-06  
**POC仓库:** [CVE-2017-7921](https://github.com/b3pwn3d/CVE-2017-7921)  

---

### [CVE-2017-7921](CVE-2017-7921-JrDw0_CVE-2017-7921-EXP.md) 🔴 ✅

**名称:** CVE-2017-7921-Hikvision摄像头身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致敏感信息泄露和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-08-06  
**POC仓库:** [CVE-2017-7921-EXP](https://github.com/JrDw0/CVE-2017-7921-EXP)  

---

### [CVE-2017-7921](CVE-2017-7921-yousouf-Tasfin_cve-2017-7921-Mass-Exploit.md) 🔴 ✅

**名称:** CVE-2017-7921-Hikvision摄像头未授权访问  
**类型:** 未授权访问  
**风险:** 高危，可能导致信息泄露、设备控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-06  
**POC仓库:** [cve-2017-7921-Mass-Exploit](https://github.com/yousouf-Tasfin/cve-2017-7921-Mass-Exploit)  

---

### [CVE-2017-7921](CVE-2017-7921-kooroshsanaei_HikVision-CVE-2017-7921.md) 🔴 ✅

**名称:** CVE-2017-7921-Hikvision Cameras-不当身份验证  
**类型:** 不当身份验证  
**风险:** 高危，可能导致权限提升和敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-08-06  
**POC仓库:** [HikVision-CVE-2017-7921](https://github.com/kooroshsanaei/HikVision-CVE-2017-7921)  

---

### [CVE-2017-7921](CVE-2017-7921-aengussong_hikvision_probe.md) 🔴 ✅

**名称:** CVE-2017-7921-Hikvision摄像机-不当身份验证  
**类型:** 不当身份验证  
**风险:** 高危，可能导致权限提升和敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-08-06  
**POC仓库:** [hikvision_probe](https://github.com/aengussong/hikvision_probe)  

---

### [CVE-2017-7921](CVE-2017-7921-K3ysTr0K3R_CVE-2017-7921-EXPLOIT.md) 🔴 ✅

**名称:** CVE-2017-7921 - Hikvision摄像机未授权访问漏洞  
**类型:** 未授权访问/权限提升  
**风险:** 高危，可能导致信息泄露和设备控制  
**投毒风险:** 1%  
**发现时间:** 2025-08-06  
**POC仓库:** [CVE-2017-7921-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2017-7921-EXPLOIT)  

---

### [CVE-2021-4034](CVE-2021-4034-BugVex_Poison-HTB-Report.md) 🔴 ✅

**名称:** CVE-2021-4034 - Polkit pkexec 本地提权  
**类型:** 本地权限提升  
**风险:** 高危，本地用户可获取 root 权限  
**投毒风险:** 1%  
**发现时间:** 2025-08-05  
**POC仓库:** [Poison-HTB-Report](https://github.com/BugVex/Poison-HTB-Report)  

---

### [CVE-2021-4034](CVE-2021-4034-CYB3RK1D_CVE-2021-4034-POC.md) 🔴 ✅

**名称:** CVE-2021-4034-Polkit pkexec 本地提权漏洞  
**类型:** 本地权限提升  
**风险:** 高危，允许低权限用户获得 root 权限  
**投毒风险:** 10%  
**发现时间:** 2025-08-05  
**POC仓库:** [CVE-2021-4034-POC](https://github.com/CYB3RK1D/CVE-2021-4034-POC)  

---

### [CVE-2025-52078](CVE-2025-52078-Yucaerin_CVE-2025-52078.md) 🟡 ✅

**名称:** CVE-2025-52078 - Writebot AI Content Generator SaaS React Template Unauthenticated Arbitrary File Upload  
**类型:** Unauthenticated Arbitrary File Upload  
**风险:** 中危，可能导致远程代码执行，权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-08-05  
**POC仓库:** [CVE-2025-52078](https://github.com/Yucaerin/CVE-2025-52078)  

---

### [CVE-2025-8550](CVE-2025-8550-byteReaper77_CVE-2025-8550.md) 🟡 ✅

**名称:** CVE-2025-8550-atjiu pybbs-XSS  
**类型:** 跨站脚本攻击(XSS)  
**风险:** 中危，可能导致cookie窃取、页面重定向等  
**投毒风险:** 10%  
**发现时间:** 2025-08-05  
**POC仓库:** [CVE-2025-8550](https://github.com/byteReaper77/CVE-2025-8550)  

---

### [CVE-2024-32019](CVE-2024-32019-juanbelin_CVE-2024-32019-POC.md) 🔴 ✅

**名称:** CVE-2024-32019-Netdata-本地提权  
**类型:** 本地提权  
**风险:** 高危，允许本地用户获得root权限  
**投毒风险:** 5%  
**发现时间:** 2025-08-05  
**POC仓库:** [CVE-2024-32019-POC](https://github.com/juanbelin/CVE-2024-32019-POC)  

---

### [CVE-2023-7028](CVE-2023-7028-KameliaZaman_Exploiting-GitLab-CVE-2023-7028.md) 🔴 ✅

**名称:** CVE-2023-7028-GitLab-账户接管  
**类型:** 弱口令重置机制  
**风险:** 高危，可能导致账户接管  
**投毒风险:** 5%  
**发现时间:** 2025-08-05  
**POC仓库:** [Exploiting-GitLab-CVE-2023-7028](https://github.com/KameliaZaman/Exploiting-GitLab-CVE-2023-7028)  

---

### [CVE-2025-24893](CVE-2025-24893-investigato_cve-2025-24893-poc.md)  ✅

**名称:** CVE-2025-24893 - XWiki Platform SolrSearchMacros 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，未经身份验证的攻击者可以执行任意代码  
**投毒风险:** 2%  
**发现时间:** 2025-08-05  
**POC仓库:** [cve-2025-24893-poc](https://github.com/investigato/cve-2025-24893-poc)  

---

### [CVE-2025-32463](CVE-2025-32463-aldoClau98_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可以获得root权限  
**投毒风险:** 10%  
**发现时间:** 2025-08-05  
**POC仓库:** [CVE-2025-32463](https://github.com/aldoClau98/CVE-2025-32463)  

---

### [CVE-2025-32463](CVE-2025-32463-painoob_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463 – Sudo chroot Escape  
**类型:** 本地权限提升  
**风险:** 高危，本地用户可获取 root 权限  
**投毒风险:** 10%  
**发现时间:** 2025-08-05  
**POC仓库:** [CVE-2025-32463](https://github.com/painoob/CVE-2025-32463)  

---

### [CVE-2025-50675](CVE-2025-50675-LukeSec_CVE-2025-50675-GPMAW-Permissions.md) 🔴 ✅

**名称:** CVE-2025-50675 – GPMAW 14.2 不安全权限漏洞  
**类型:** 不安全权限  
**风险:** 高危，可能导致权限提升和任意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-05  
**POC仓库:** [CVE-2025-50675-GPMAW-Permissions](https://github.com/LukeSec/CVE-2025-50675-GPMAW-Permissions)  

---

### [CVE-2025-53770](CVE-2025-53770-SDX442_CVE-2025-53770.md) 🔴 

**名称:** CVE-2025-53770-Microsoft SharePoint Server Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-05  
**POC仓库:** [CVE-2025-53770](https://github.com/SDX442/CVE-2025-53770)  

---

### [CVE-2025-48799](CVE-2025-48799-painoob_CVE-2025-48799.md) 🔴 ✅

**名称:** CVE-2025-48799 Windows Update Service Elevation of Privilege Vulnerability  
**类型:** 特权提升  
**风险:** 高危，允许本地攻击者提升权限。  
**投毒风险:** 5%  
**发现时间:** 2025-08-05  
**POC仓库:** [CVE-2025-48799](https://github.com/painoob/CVE-2025-48799)  

---

### [CVE-2025-50286](CVE-2025-50286-binneko_CVE-2025-50286.md) 🔴 ✅

**名称:** CVE-2025-50286 - Grav CMS Authenticated RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可完全控制服务器  
**投毒风险:** 5%  
**发现时间:** 2025-08-05  
**POC仓库:** [CVE-2025-50286](https://github.com/binneko/CVE-2025-50286)  

---

### [CVE-2024-32019](CVE-2024-32019-dollarboysushil_CVE-2024-32019-Netdata-ndsudo-PATH-Vulnerability-Privilege-Escalation.md) 🔴 ✅

**名称:** CVE-2024-32019-Netdata-本地提权  
**类型:** 本地提权  
**风险:** 高危，本地权限提升至root  
**投毒风险:** 10%  
**发现时间:** 2025-08-05  
**POC仓库:** [CVE-2024-32019-Netdata-ndsudo-PATH-Vulnerability-Privilege-Escalation](https://github.com/dollarboysushil/CVE-2024-32019-Netdata-ndsudo-PATH-Vulnerability-Privilege-Escalation)  

---

### [CVE-2022-0824](CVE-2022-0824-faisalfs10x_Webmin-CVE-2022-0824-revshell.md) 🔴 ✅

**名称:** CVE-2022-0824 - Webmin Improper Access Control to RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，攻击者可利用此漏洞在受影响的系统上执行任意代码。  
**投毒风险:** 5%  
**发现时间:** 2025-08-05  
**POC仓库:** [Webmin-CVE-2022-0824-revshell](https://github.com/faisalfs10x/Webmin-CVE-2022-0824-revshell)  

---

### [CVE-2022-0824](CVE-2022-0824-honypot_CVE-2022-0824.md) 🔴 ✅

**名称:** CVE-2022-0824 - Webmin Improper Access Control RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经授权的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-05  
**POC仓库:** [CVE-2022-0824](https://github.com/honypot/CVE-2022-0824)  

---

### [CVE-2022-0824](CVE-2022-0824-pizza-power_golang-webmin-CVE-2022-0824-revshell.md) 🔴 ✅

**名称:** CVE-2022-0824-Webmin-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-08-05  
**POC仓库:** [golang-webmin-CVE-2022-0824-revshell](https://github.com/pizza-power/golang-webmin-CVE-2022-0824-revshell)  

---

### [CVE-2022-0824](CVE-2022-0824-gokul-ramesh_WebminRCE-exploit.md) 🔴 ✅

**名称:** CVE-2022-0824 - Webmin Improper Access Control Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，允许低权限用户远程执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-05  
**POC仓库:** [WebminRCE-exploit](https://github.com/gokul-ramesh/WebminRCE-exploit)  

---

### [CVE-2022-0824](CVE-2022-0824-NUDTTAN91_Webmin-CVE-2022-0824-Enhanced-Exploit.md) 🔴 ✅

**名称:** CVE-2022-0824-Webmin-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-05  
**POC仓库:** [Webmin-CVE-2022-0824-Enhanced-Exploit](https://github.com/NUDTTAN91/Webmin-CVE-2022-0824-Enhanced-Exploit)  

---

### [CVE-2022-4556](CVE-2022-4556-AshkanRafiee_CVE-2022-4556.md) 🟡 ✅

**名称:** CVE-2022-4556 - Alinto SOGo Stored XSS  
**类型:** Stored Cross-Site Scripting (XSS)  
**风险:** 中危，可能导致账户劫持、恶意重定向、窃取敏感信息  
**投毒风险:** 0%  
**发现时间:** 2025-08-05  
**POC仓库:** [CVE-2022-4556](https://github.com/AshkanRafiee/CVE-2022-4556)  

---

### [CVE-2025-24893](CVE-2025-24893-zs1n_CVE-2025-24893.md)  ✅

**名称:** CVE-2025-24893 - XWiki Platform 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，允许未经身份验证的攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-05  
**POC仓库:** [CVE-2025-24893](https://github.com/zs1n/CVE-2025-24893)  

---

### [CVE-2024-4577](CVE-2024-4577-xAL6_cve-2024-4577-scanner.md) 🔴 ✅

**名称:** CVE-2024-4577-PHP-CGI参数注入  
**类型:** PHP-CGI参数注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-08-05  
**POC仓库:** [cve-2024-4577-scanner](https://github.com/xAL6/cve-2024-4577-scanner)  

---

### [CVE-2018-7600](CVE-2018-7600-M-Abid34_CVE-2018-7600.md) 🔴 ✅

**名称:** CVE-2018-7600-Drupalgeddon 2  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的攻击者在服务器上执行任意代码，可能导致完全控制服务器。  
**投毒风险:** 5%  
**发现时间:** 2025-08-04  
**POC仓库:** [CVE-2018-7600](https://github.com/M-Abid34/CVE-2018-7600)  

---

### [CVE-2025-54381](CVE-2025-54381-B1ack4sh_Blackash-CVE-2025-54381.md) 🔴 ✅

**名称:** CVE-2025-54381-BentoML-SSRF  
**类型:** SSRF  
**风险:** 高危，可能导致内部信息泄露，访问受限资源  
**投毒风险:** 5%  
**发现时间:** 2025-08-04  
**POC仓库:** [Blackash-CVE-2025-54381](https://github.com/B1ack4sh/Blackash-CVE-2025-54381)  

---

### [CVE-2025-24893](CVE-2025-24893-dollarboysushil_CVE-2025-24893-XWiki-Unauthenticated-RCE-Exploit-POC.md) 🔴 ✅

**名称:** CVE-2025-24893 - XWiki SolrSearchMacros 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-08-04  
**POC仓库:** [CVE-2025-24893-XWiki-Unauthenticated-RCE-Exploit-POC](https://github.com/dollarboysushil/CVE-2025-24893-XWiki-Unauthenticated-RCE-Exploit-POC)  

---

### [CVE-2023-22077](CVE-2023-22077-emad-almousa_CVE-2023-22077.md) 🟡 ✅

**名称:** CVE-2023-22077  
**类型:** 拒绝服务 (DoS)  
**风险:** 中危，导致Recovery Manager崩溃  
**投毒风险:** 0%  
**发现时间:** 2025-08-04  
**POC仓库:** [CVE-2023-22077](https://github.com/emad-almousa/CVE-2023-22077)  

---

### [CVE-2020-0688](CVE-2020-0688-random-robbie_cve-2020-0688.md) 🔴 ✅

**名称:** CVE-2020-0688-Microsoft Exchange Server-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致完全系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-04  
**POC仓库:** [cve-2020-0688](https://github.com/random-robbie/cve-2020-0688)  

---

### [CVE-2020-0688](CVE-2020-0688-cert-lv_CVE-2020-0688.md) 🔴 ✅

**名称:** CVE-2020-0688 Microsoft Exchange Server 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致完全系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-04  
**POC仓库:** [CVE-2020-0688](https://github.com/cert-lv/CVE-2020-0688)  

---

### [CVE-2020-0688](CVE-2020-0688-mahyarx_Exploit_CVE-2020-0688.md) 🔴 ✅

**名称:** CVE-2020-0688-Microsoft Exchange Server-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可完全控制受影响的Exchange服务器  
**投毒风险:** 10%  
**发现时间:** 2025-08-04  
**POC仓库:** [Exploit_CVE-2020-0688](https://github.com/mahyarx/Exploit_CVE-2020-0688)  

---

### [CVE-2025-50592](CVE-2025-50592-1515601525_CVE-2025-50592.md) 🔴 ✅

**名称:** CVE-2025-50592  
**类型:** 本地提权  
**风险:** 高危，本地提权到 NT AUTHORITY\SYSTEM  
**投毒风险:** 10%  
**发现时间:** 2025-08-04  
**POC仓库:** [CVE-2025-50592](https://github.com/1515601525/CVE-2025-50592)  

---

### [CVE-2020-0688](CVE-2020-0688-Jumbo-WJB_CVE-2020-0688.md) 🔴 ✅

**名称:** CVE-2020-0688 Microsoft Exchange Server 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-08-04  
**POC仓库:** [CVE-2020-0688](https://github.com/Jumbo-WJB/CVE-2020-0688)  

---

### [CVE-2020-0688](CVE-2020-0688-Yt1g3r_CVE-2020-0688_EXP.md) 🔴 ✅

**名称:** CVE-2020-0688 - Microsoft Exchange Server 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-04  
**POC仓库:** [CVE-2020-0688_EXP](https://github.com/Yt1g3r/CVE-2020-0688_EXP)  

---

### [CVE-2020-0688](CVE-2020-0688-youncyb_CVE-2020-0688.md) 🔴 ✅

**名称:** CVE-2020-0688 Microsoft Exchange Server 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-04  
**POC仓库:** [CVE-2020-0688](https://github.com/youncyb/CVE-2020-0688)  

---

### [CVE-2020-0688](CVE-2020-0688-justin-p_PSForgot2kEyXCHANGE.md) 🔴 ✅

**名称:** CVE-2020-0688 Microsoft Exchange Server 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可完全控制 Exchange 服务器  
**投毒风险:** 10%  
**发现时间:** 2025-08-04  
**POC仓库:** [PSForgot2kEyXCHANGE](https://github.com/justin-p/PSForgot2kEyXCHANGE)  

---

### [CVE-2020-0688](CVE-2020-0688-zcgonvh_CVE-2020-0688.md) 🔴 ✅

**名称:** CVE-2020-0688 Microsoft Exchange Server Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，可能导致完全系统控制  
**投毒风险:** 1%  
**发现时间:** 2025-08-04  
**POC仓库:** [CVE-2020-0688](https://github.com/zcgonvh/CVE-2020-0688)  

---

### [CVE-2020-0688](CVE-2020-0688-ravinacademy_CVE-2020-0688.md) 🔴 ✅

**名称:** CVE-2020-0688 Microsoft Exchange Server 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致完全系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-04  
**POC仓库:** [CVE-2020-0688](https://github.com/ravinacademy/CVE-2020-0688)  

---

### [CVE-2020-0688](CVE-2020-0688-ktpdpro_CVE-2020-0688.md) 🔴 ✅

**名称:** CVE-2020-0688 Microsoft Exchange Server 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致完全系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-04  
**POC仓库:** [CVE-2020-0688](https://github.com/ktpdpro/CVE-2020-0688)  

---

### [CVE-2020-0688](CVE-2020-0688-murataydemir_CVE-2020-0688.md) 🔴 ✅

**名称:** CVE-2020-0688 Microsoft Exchange Server 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致完全系统权限控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-04  
**POC仓库:** [CVE-2020-0688](https://github.com/murataydemir/CVE-2020-0688)  

---

### [CVE-2020-0688](CVE-2020-0688-SLSteff_CVE-2020-0688-Scanner.md) 🔴 ✅

**名称:** CVE-2020-0688-Microsoft Exchange-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致完全系统入侵  
**投毒风险:** 10%  
**发现时间:** 2025-08-04  
**POC仓库:** [CVE-2020-0688-Scanner](https://github.com/SLSteff/CVE-2020-0688-Scanner)  

---

### [CVE-2020-0688](CVE-2020-0688-onSec-fr_CVE-2020-0688-Scanner.md) 🔴 ✅

**名称:** CVE-2020-0688-Microsoft Exchange Server-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-04  
**POC仓库:** [CVE-2020-0688-Scanner](https://github.com/onSec-fr/CVE-2020-0688-Scanner)  

---

### [CVE-2020-0688](CVE-2020-0688-MrTiz_CVE-2020-0688.md) 🔴 ✅

**名称:** CVE-2020-0688-Microsoft Exchange Server-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可完全控制 Exchange 服务器  
**投毒风险:** 10%  
**发现时间:** 2025-08-04  
**POC仓库:** [CVE-2020-0688](https://github.com/MrTiz/CVE-2020-0688)  

---

### [CVE-2020-0688](CVE-2020-0688-righter83_CVE-2020-0688.md) 🔴 ✅

**名称:** CVE-2020-0688  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-04  
**POC仓库:** [CVE-2020-0688](https://github.com/righter83/CVE-2020-0688)  

---

### [CVE-2020-0688](CVE-2020-0688-7heKnight_CVE-2020-0688.md) 🔴 ✅

**名称:** CVE-2020-0688 Microsoft Exchange Server 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-04  
**POC仓库:** [CVE-2020-0688](https://github.com/7heKnight/CVE-2020-0688)  

---

### [CVE-2020-0688](CVE-2020-0688-Ridter_cve-2020-0688.md) 🔴 ✅

**名称:** CVE-2020-0688-Microsoft Exchange Server-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-04  
**POC仓库:** [cve-2020-0688](https://github.com/Ridter/cve-2020-0688)  

---

### [CVE-2020-0688](CVE-2020-0688-chudamax_CVE-2020-0688-Exchange2010.md) 🔴 ✅

**名称:** CVE-2020-0688-Microsoft Exchange Server-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-04  
**POC仓库:** [CVE-2020-0688-Exchange2010](https://github.com/chudamax/CVE-2020-0688-Exchange2010)  

---

### [CVE-2020-0688](CVE-2020-0688-w4fz5uck5_cve-2020-0688-webshell-upload-technique.md) 🔴 ✅

**名称:** CVE-2020-0688 Microsoft Exchange Server 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可完全控制 Exchange 服务器  
**投毒风险:** 10%  
**发现时间:** 2025-08-04  
**POC仓库:** [cve-2020-0688-webshell-upload-technique](https://github.com/w4fz5uck5/cve-2020-0688-webshell-upload-technique)  

---

### [CVE-2020-0688](CVE-2020-0688-1337-llama_CVE-2020-0688-Python3.md) 🔴 ✅

**名称:** CVE-2020-0688 Microsoft Exchange Server 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-04  
**POC仓库:** [CVE-2020-0688-Python3](https://github.com/1337-llama/CVE-2020-0688-Python3)  

---

### [CVE-2020-0688](CVE-2020-0688-W01fh4cker_CVE-2020-0688-GUI.md) 🔴 ✅

**名称:** CVE-2020-0688 Microsoft Exchange Server 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可完全控制受影响的Exchange服务器  
**投毒风险:** 10%  
**发现时间:** 2025-08-04  
**POC仓库:** [CVE-2020-0688-GUI](https://github.com/W01fh4cker/CVE-2020-0688-GUI)  

---

### [CVE-2020-0688](CVE-2020-0688-zyn3rgy_ecp_slap.md) 🔴 ✅

**名称:** CVE-2020-0688-Microsoft Exchange Server-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致系统完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-04  
**POC仓库:** [ecp_slap](https://github.com/zyn3rgy/ecp_slap)  

---

### [CVE-2020-0688](CVE-2020-0688-truongtn_cve-2020-0688.md) 🔴 ✅

**名称:** CVE-2020-0688 Microsoft Exchange Server 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-04  
**POC仓库:** [cve-2020-0688](https://github.com/truongtn/cve-2020-0688)  

---

### [CVE-2020-0688](CVE-2020-0688-tvdat20004_CVE-2020-0688.md) 🔴 ✅

**名称:** CVE-2020-0688-Microsoft Exchange Server-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-04  
**POC仓库:** [CVE-2020-0688](https://github.com/tvdat20004/CVE-2020-0688)  

---

### [CVE-2025-7340](CVE-2025-7340-Kai-One001_WordPress-HT-Contact-CVE-2025-7340-RCE.md) 🔴 ✅

**名称:** CVE-2025-7340 - HT Contact Form Widget 未授权任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-04  
**POC仓库:** [WordPress-HT-Contact-CVE-2025-7340-RCE](https://github.com/Kai-One001/WordPress-HT-Contact-CVE-2025-7340-RCE)  

---

### [CVE-2025-54574](CVE-2025-54574-B1ack4sh_Blackash-CVE-2025-54574.md) 🔴 ✅

**名称:** CVE-2025-54574-Squid-Heap-based Buffer Overflow  
**类型:** Heap-based Buffer Overflow  
**风险:** 高危，可能导致远程代码执行和拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-08-04  
**POC仓库:** [Blackash-CVE-2025-54574](https://github.com/B1ack4sh/Blackash-CVE-2025-54574)  

---

### [CVE-2013-3900](CVE-2013-3900-Sabecomoeh_CVE-2013-3900.md) 🔴 ✅

**名称:** CVE-2013-3900 WinVerifyTrust Signature Validation Vulnerability  
**类型:** 签名验证绕过  
**风险:** 中危/高危 (取决于上下文和CVSS评分)  
**投毒风险:** 5%  
**发现时间:** 2025-08-04  
**POC仓库:** [CVE-2013-3900](https://github.com/Sabecomoeh/CVE-2013-3900)  

---

### [CVE-2025-54424](CVE-2025-54424-Mr-xn_CVE-2025-54424.md) 🔴 ✅

**名称:** CVE-2025-54424 - 1Panel Agent 证书验证绕过导致任意命令执行  
**类型:** 证书验证绕过/命令注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-04  
**POC仓库:** [CVE-2025-54424](https://github.com/Mr-xn/CVE-2025-54424)  

---

### [CVE-2025-54962](CVE-2025-54962-Eyodav_CVE-2025-54962.md) 🟡 ✅

**名称:** CVE-2025-54962 - OpenPLC Runtime Webserver Insecure File Upload  
**类型:** 文件上传漏洞  
**风险:** 中危，可能导致存储型XSS、CSRF和恶意内容托管  
**投毒风险:** 10%  
**发现时间:** 2025-08-04  
**POC仓库:** [CVE-2025-54962](https://github.com/Eyodav/CVE-2025-54962)  

---

### [CVE-2025-51820](CVE-2025-51820-shk-mubashshir_CVE-2025-51820.md) 🔴 ✅

**名称:** CVE-2025-51820 - 在线购物门户v1.0远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致完全系统入侵  
**投毒风险:** 0%  
**发现时间:** 2025-08-04  
**POC仓库:** [CVE-2025-51820](https://github.com/shk-mubashshir/CVE-2025-51820)  

---

### [CVE-2025-24893](CVE-2025-24893-gunzf0x_CVE-2025-24893.md) 🔴 ✅

**名称:** CVE-2025-24893-XWiki-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-08-04  
**POC仓库:** [CVE-2025-24893](https://github.com/gunzf0x/CVE-2025-24893)  

---

### [CVE-2021-44228](CVE-2021-44228-michaelsanford_Log4Shell-Honeypot.md) 🔴 ✅

**名称:** CVE-2021-44228-Log4Shell-Honeypot  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-08-04  
**POC仓库:** [Log4Shell-Honeypot](https://github.com/michaelsanford/Log4Shell-Honeypot)  

---

### [CVE-2021-44228](CVE-2021-44228-Sorrence_CVE-2021-44228.md) 🔴 ✅

**名称:** CVE-2021-44228-Apache Log4j2-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致完全系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-04  
**POC仓库:** [CVE-2021-44228](https://github.com/Sorrence/CVE-2021-44228)  

---

### [CVE-2023-38831](CVE-2023-38831-Tolu12wani_Demonstration-of-CVE-2023-38831-via-Reverse-Shell-Execution.md) 🔴 ✅

**名称:** CVE-2023-38831 WinRAR 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在用户尝试查看 ZIP 压缩包中的文件时执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-08-03  
**POC仓库:** [Demonstration-of-CVE-2023-38831-via-Reverse-Shell-Execution](https://github.com/Tolu12wani/Demonstration-of-CVE-2023-38831-via-Reverse-Shell-Execution)  

---

### [CVE-2012-2982](CVE-2012-2982-SincIDK_CVE-2012-2982-Exploit-Script.md) 🔴 ✅

**名称:** CVE-2012-2982-Webmin-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可完全控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-08-03  
**POC仓库:** [CVE-2012-2982-Exploit-Script](https://github.com/SincIDK/CVE-2012-2982-Exploit-Script)  

---

### [CVE-2025-8471](CVE-2025-8471-byteReaper77_CVE-2025-8471.md) 🔴 ✅

**名称:** CVE-2025-8471-projectworlds Online Admission System-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-08-03  
**POC仓库:** [CVE-2025-8471](https://github.com/byteReaper77/CVE-2025-8471)  

---

### [CVE-2025-24893](CVE-2025-24893-Infinit3i_CVE-2025-24893.md)  ✅

**名称:** CVE-2025-24893 - XWiki SolrSearch Macro RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，未经身份验证的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-08-03  
**POC仓库:** [CVE-2025-24893](https://github.com/Infinit3i/CVE-2025-24893)  

---

### [CVE-2024-4367](CVE-2024-4367-MihranGIT_POC_CVE-2024-4367.md) 🟡 ✅

**名称:** CVE-2024-4367 - Firefox/Thunderbird PDF.js 任意JavaScript执行  
**类型:** 任意JavaScript执行  
**风险:** 中危，可能导致跨站脚本攻击(XSS)和敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-08-03  
**POC仓库:** [POC_CVE-2024-4367](https://github.com/MihranGIT/POC_CVE-2024-4367)  

---

### [CVE-2025-24893](CVE-2025-24893-hackersonsteroids_cve-2025-24893.md)  ✅

**名称:** CVE-2025-24893-XWiki-RCE  
**类型:** 远程代码执行  
**风险:** 严重，允许未经身份验证的远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-08-03  
**POC仓库:** [cve-2025-24893](https://github.com/hackersonsteroids/cve-2025-24893)  

---

### [CVE-2024-32019](CVE-2024-32019-AliElKhatteb_CVE-2024-32019-POC.md) 🔴 ✅

**名称:** CVE-2024-32019 - Netdata ndsudo 本地提权  
**类型:** 本地提权  
**风险:** 高危，允许低权限用户获得root权限  
**投毒风险:** 10%  
**发现时间:** 2025-08-03  
**POC仓库:** [CVE-2024-32019-POC](https://github.com/AliElKhatteb/CVE-2024-32019-POC)  

---

### [CVE-2025-48384](CVE-2025-48384-beishanxueyuan_CVE-2025-48384.md) 🔴 ✅

**名称:** CVE-2025-48384 - Git Config 注入导致任意代码执行  
**类型:** 代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-03  
**POC仓库:** [CVE-2025-48384](https://github.com/beishanxueyuan/CVE-2025-48384)  

---

### [CVE-2025-24893](CVE-2025-24893-dhiaZnaidi_CVE-2025-24893-PoC.md) 🔴 ✅

**名称:** CVE-2025-24893-XWiki-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的攻击者可以执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-08-03  
**POC仓库:** [CVE-2025-24893-PoC](https://github.com/dhiaZnaidi/CVE-2025-24893-PoC)  

---

### [CVE-2024-0684](CVE-2024-0684-Valentin-Metz_writeup_split.md) 🟡 ✅

**名称:** CVE-2024-0684-coreutils-堆溢出  
**类型:** 堆溢出  
**风险:** 中危，可能导致程序崩溃和拒绝服务  
**投毒风险:** 0%  
**发现时间:** 2025-08-03  
**POC仓库:** [writeup_split](https://github.com/Valentin-Metz/writeup_split)  

---

### [CVE-2024-0684](CVE-2024-0684-limetimeline_cve-2024-0684.md) 🟡 

**名称:** CVE-2024-0684-coreutils-堆溢出  
**类型:** 堆溢出  
**风险:** 中危，可能导致拒绝服务或程序崩溃  
**投毒风险:** 5%  
**发现时间:** 2025-08-03  
**POC仓库:** [cve-2024-0684](https://github.com/limetimeline/cve-2024-0684)  

---

### [CVE-2023-0461](CVE-2023-0461-b1nhack_CVE-2023-0461.md) 🔴 ✅

**名称:** CVE-2023-0461 Linux Kernel Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可导致本地权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-08-03  
**POC仓库:** [CVE-2023-0461](https://github.com/b1nhack/CVE-2023-0461)  

---

### [CVE-2024-2782](CVE-2024-2782-whale93_CVE-2024-2782-PoC.md) 🔴 ✅

**名称:** CVE-2024-2782 - Fluent Forms 权限绕过导致设置修改  
**类型:** 权限绕过  
**风险:** 高危，可能导致网站配置被恶意修改  
**投毒风险:** 0%  
**发现时间:** 2025-08-03  
**POC仓库:** [CVE-2024-2782-PoC](https://github.com/whale93/CVE-2024-2782-PoC)  

---

### [CVE-2024-2771](CVE-2024-2771-whale93_CVE-2024-2771-PoC.md) 🔴 ✅

**名称:** CVE-2024-2771-Contact Form Plugin by Fluent Forms-权限提升  
**类型:** 权限提升  
**风险:** 高危，允许未授权用户获得插件的管理权限  
**投毒风险:** 0%  
**发现时间:** 2025-08-03  
**POC仓库:** [CVE-2024-2771-PoC](https://github.com/whale93/CVE-2024-2771-PoC)  

---

### [CVE-2024-32019](CVE-2024-32019-AzureADTrent_CVE-2024-32019-POC.md) 🔴 ✅

**名称:** CVE-2024-32019-netdata-ndsudo本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可提升至root权限  
**投毒风险:** 0%  
**发现时间:** 2025-08-03  
**POC仓库:** [CVE-2024-32019-POC](https://github.com/AzureADTrent/CVE-2024-32019-POC)  

---

### [CVE-2025-48384](CVE-2025-48384-fluoworite_CVE-2025-48384-sub.md) 🔴 ✅

**名称:** CVE-2025-48384-Git-任意代码执行  
**类型:** 任意代码执行  
**风险:** 高危，可能导致远程代码执行和系统控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-03  
**POC仓库:** [CVE-2025-48384-sub](https://github.com/fluoworite/CVE-2025-48384-sub)  

---

### [CVE-2025-24893](CVE-2025-24893-Kai7788_CVE-2025-24893-RCE-PoC.md) 🔴 ✅

**名称:** CVE-2025-24893-XWiki-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-08-02  
**POC仓库:** [CVE-2025-24893-RCE-PoC](https://github.com/Kai7788/CVE-2025-24893-RCE-PoC)  

---

### [CVE-2023-24489](CVE-2023-24489-adhikara13_CVE-2023-24489-ShareFile.md)  ✅

**名称:** CVE-2023-24489-Citrix ShareFile Storage Zones Controller-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，未经身份验证的攻击者可以远程入侵 Storage Zones Controller  
**投毒风险:** 0%  
**发现时间:** 2025-08-02  
**POC仓库:** [CVE-2023-24489-ShareFile](https://github.com/adhikara13/CVE-2023-24489-ShareFile)  

---

### [CVE-2023-24489](CVE-2023-24489-whalebone7_CVE-2023-24489-poc.md) 🔴 ✅

**名称:** CVE-2023-24489-ShareFile Storage Zones Controller-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-02  
**POC仓库:** [CVE-2023-24489-poc](https://github.com/whalebone7/CVE-2023-24489-poc)  

---

### [CVE-2025-48384](CVE-2025-48384-fluoworite_CVE-2025-48384_sub.md) 🔴 ✅

**名称:** CVE-2025-48384 Git config quoting vulnerability  
**类型:** 代码执行/任意文件写入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-02  
**POC仓库:** [CVE-2025-48384_sub](https://github.com/fluoworite/CVE-2025-48384_sub)  

---

### [CVE-2025-48384](CVE-2025-48384-fluoworite_CVE-2025-48384.md) 🔴 ✅

**名称:** CVE-2025-48384  
**类型:** 代码执行/任意文件写入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 20%  
**发现时间:** 2025-08-02  
**POC仓库:** [CVE-2025-48384](https://github.com/fluoworite/CVE-2025-48384)  

---

### [CVE-2025-24893](CVE-2025-24893-nopgadget_CVE-2025-24893.md) 🔴 ✅

**名称:** CVE-2025-24893-XWiki-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-02  
**POC仓库:** [CVE-2025-24893](https://github.com/nopgadget/CVE-2025-24893)  

---

### [CVE-2025-4606](CVE-2025-4606-Yucaerin_CVE-2025-4606.md) 🔴 ✅

**名称:** CVE-2025-4606-Sala WordPress Theme-未授权密码重置/账户接管  
**类型:** 未授权密码重置/账户接管  
**风险:** 高危，可能导致账户接管和数据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-08-02  
**POC仓库:** [CVE-2025-4606](https://github.com/Yucaerin/CVE-2025-4606)  

---

### [CVE-2025-5394](CVE-2025-5394-Yucaerin_CVE-2025-5394.md) 🔴 ✅

**名称:** CVE-2025-5394 - Alone WordPress Theme 未授权任意文件上传  
**类型:** 未授权任意文件上传  
**风险:** 高危，可能导致远程代码执行和完全站点控制  
**投毒风险:** 5%  
**发现时间:** 2025-08-02  
**POC仓库:** [CVE-2025-5394](https://github.com/Yucaerin/CVE-2025-5394)  

---

### [CVE-2025-5394](CVE-2025-5394-Nxploited_CVE-2025-5394.md) 🔴 ✅

**名称:** CVE-2025-5394 - Alone WordPress Theme 任意文件上传导致远程代码执行  
**类型:** 任意文件上传  
**风险:** 高危，允许未授权用户上传恶意文件并执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-08-02  
**POC仓库:** [CVE-2025-5394](https://github.com/Nxploited/CVE-2025-5394)  

---

### [CVE-2024-21626](CVE-2024-21626-R4mbb_CVE-2024-21626.md) 🔴 ✅

**名称:** CVE-2024-21626-runc容器逃逸  
**类型:** 容器逃逸  
**风险:** 高危，可导致容器逃逸，获取宿主机权限  
**投毒风险:** 10%  
**发现时间:** 2025-08-02  
**POC仓库:** [CVE-2024-21626](https://github.com/R4mbb/CVE-2024-21626)  

---

### [CVE-2025-54135](CVE-2025-54135-allinsthon_CVE-2025-54135.md) 🔴 ✅

**名称:** CVE-2025-54135 - Cursor IDE 远程代码执行  
**类型:** Prompt Injection / 远程代码执行  
**风险:** 高危，可能导致远程代码执行、数据泄露和系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-02  
**POC仓库:** [CVE-2025-54135](https://github.com/allinsthon/CVE-2025-54135)  

---

### [CVE-2025-7847](CVE-2025-7847-EricArdiansa_CVE-2025-7847-POC.md) 🔴 ✅

**名称:** CVE-2025-7847 - AI Engine Plugin - 任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-02  
**POC仓库:** [CVE-2025-7847-POC](https://github.com/EricArdiansa/CVE-2025-7847-POC)  

---

### [CVE-2025-34100](CVE-2025-34100-RyanJohnJames_CVE-2025-34100-demo.md) 🔴 ✅

**名称:** CVE-2025-34100-BuilderEngine-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-02  
**POC仓库:** [CVE-2025-34100-demo](https://github.com/RyanJohnJames/CVE-2025-34100-demo)  

---

### [CVE-2025-53770](CVE-2025-53770-harryhaxor_CVE-2025-53770-SharePoint-Deserialization-RCE-PoC.md) 🔴 ✅

**名称:** CVE-2025-53770-SharePoint-Deserialization-RCE  
**类型:** 反序列化远程代码执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-02  
**POC仓库:** [CVE-2025-53770-SharePoint-Deserialization-RCE-PoC](https://github.com/harryhaxor/CVE-2025-53770-SharePoint-Deserialization-RCE-PoC)  

---

### [CVE-2025-32463](CVE-2025-32463-Dlodlos_CVE-2025-32463-lab.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地权限提升  
**风险:** 高危，本地用户可获得root权限  
**投毒风险:** 10%  
**发现时间:** 2025-08-02  
**POC仓库:** [CVE-2025-32463-lab](https://github.com/Dlodlos/CVE-2025-32463-lab)  

---

### [CVE-2025-41373](CVE-2025-41373-byteReaper77_CVE-2025-41373.md) 🔴 ✅

**名称:** CVE-2025-41373 – SQL Injection in Gandia Integra Total  
**类型:** SQL注入  
**风险:** 高危，允许经过身份验证的攻击者检索、创建、更新和删除数据库  
**投毒风险:** 10%  
**发现时间:** 2025-08-01  
**POC仓库:** [CVE-2025-41373](https://github.com/byteReaper77/CVE-2025-41373)  

---

### [CVE-2022-22965](CVE-2022-22965-Nosie12_fire-wall-server.md) 🔴 ✅

**名称:** CVE-2022-22965 Spring4Shell  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-01  
**POC仓库:** [fire-wall-server](https://github.com/Nosie12/fire-wall-server)  

---

### [CVE-2022-22965](CVE-2022-22965-likewhite_CVE-2022-22965.md) 🔴 ✅

**名称:** CVE-2022-22965 Spring4Shell RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-08-01  
**POC仓库:** [CVE-2022-22965](https://github.com/likewhite/CVE-2022-22965)  

---

### [CVE-2022-22965](CVE-2022-22965-c33dd_CVE-2022-22965.md) 🔴 ✅

**名称:** CVE-2022-22965 - Spring4Shell RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-01  
**POC仓库:** [CVE-2022-22965](https://github.com/c33dd/CVE-2022-22965)  

---

### [CVE-2022-22965](CVE-2022-22965-gokul-ramesh_Spring4Shell-PoC-exploit.md) 🔴 ✅

**名称:** CVE-2022-22965 Spring4Shell 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-01  
**POC仓库:** [Spring4Shell-PoC-exploit](https://github.com/gokul-ramesh/Spring4Shell-PoC-exploit)  

---

### [CVE-2022-22965](CVE-2022-22965-DDuarte_springshell-rce-poc.md) 🔴 ✅

**名称:** CVE-2022-22965-Spring4Shell-RCE  
**类型:** 远程代码执行（RCE）  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-01  
**POC仓库:** [springshell-rce-poc](https://github.com/DDuarte/springshell-rce-poc)  

---

### [CVE-2022-22965](CVE-2022-22965-sunnyvale-it_CVE-2022-22965-PoC.md) 🔴 ✅

**名称:** CVE-2022-22965 Spring4Shell RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致完全控制受影响的服务器  
**投毒风险:** 10%  
**发现时间:** 2025-08-01  
**POC仓库:** [CVE-2022-22965-PoC](https://github.com/sunnyvale-it/CVE-2022-22965-PoC)  

---

### [CVE-2022-22965](CVE-2022-22965-BKLockly_CVE-2022-22965.md) 🔴 ✅

**名称:** CVE-2022-22965-Spring4Shell-RCE  
**类型:** 远程代码执行（RCE）  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-01  
**POC仓库:** [CVE-2022-22965](https://github.com/BKLockly/CVE-2022-22965)  

---

### [CVE-2022-22965](CVE-2022-22965-dbgee_Spring4Shell.md) 🔴 ✅

**名称:** CVE-2022-22965 Spring4Shell RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-01  
**POC仓库:** [Spring4Shell](https://github.com/dbgee/Spring4Shell)  

---

### [CVE-2022-22965](CVE-2022-22965-jakabakos_CVE-2022-22965-Spring4Shell.md) 🔴 ✅

**名称:** CVE-2022-22965 Spring4Shell RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-01  
**POC仓库:** [CVE-2022-22965-Spring4Shell](https://github.com/jakabakos/CVE-2022-22965-Spring4Shell)  

---

### [CVE-2022-22965](CVE-2022-22965-sohamsharma966_Spring4Shell-CVE-2022-22965.md) 🔴 ✅

**名称:** CVE-2022-22965 Spring4Shell RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-01  
**POC仓库:** [Spring4Shell-CVE-2022-22965](https://github.com/sohamsharma966/Spring4Shell-CVE-2022-22965)  

---

### [CVE-2022-22965](CVE-2022-22965-cxzero_CVE-2022-22965-spring4shell.md) 🔴 ✅

**名称:** CVE-2022-22965 Spring4Shell RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-01  
**POC仓库:** [CVE-2022-22965-spring4shell](https://github.com/cxzero/CVE-2022-22965-spring4shell)  

---

### [CVE-2022-22965](CVE-2022-22965-zangcc_CVE-2022-22965-rexbb.md) 🔴 ✅

**名称:** CVE-2022-22965 Spring4Shell RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-08-01  
**POC仓库:** [CVE-2022-22965-rexbb](https://github.com/zangcc/CVE-2022-22965-rexbb)  

---

### [CVE-2022-22965](CVE-2022-22965-ESSAFAR_Firewall-Rules.md) 🔴 ✅

**名称:** CVE-2022-22965-Spring4Shell-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-01  
**POC仓库:** [Firewall-Rules](https://github.com/ESSAFAR/Firewall-Rules)  

---

### [CVE-2022-22965](CVE-2022-22965-viniciuspereiras_CVE-2022-22965-poc.md) 🔴 ✅

**名称:** CVE-2022-22965-Spring4Shell-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-08-01  
**POC仓库:** [CVE-2022-22965-poc](https://github.com/viniciuspereiras/CVE-2022-22965-poc)  

---

### [CVE-2022-22965](CVE-2022-22965-0xrobiul_CVE-2022-22965.md) 🔴 ✅

**名称:** CVE-2022-22965 Spring4Shell RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-01  
**POC仓库:** [CVE-2022-22965](https://github.com/0xrobiul/CVE-2022-22965)  

---

### [CVE-2022-22965](CVE-2022-22965-bL34cHig0_Telstra-Cybersecurity-Virtual-Experience-.md) 🔴 ✅

**名称:** CVE-2022-22965 Spring4Shell RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-01  
**POC仓库:** [Telstra-Cybersecurity-Virtual-Experience-](https://github.com/bL34cHig0/Telstra-Cybersecurity-Virtual-Experience-)  

---

### [CVE-2022-22965](CVE-2022-22965-xsxtw_SpringFramework_CVE-2022-22965_RCE.md) 🔴 ✅

**名称:** CVE-2022-22965 Spring4Shell RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-01  
**POC仓库:** [SpringFramework_CVE-2022-22965_RCE](https://github.com/xsxtw/SpringFramework_CVE-2022-22965_RCE)  

---

### [CVE-2022-22965](CVE-2022-22965-LucasPDiniz_CVE-2022-22965.md) 🔴 ✅

**名称:** CVE-2022-22965 Spring4Shell RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-08-01  
**POC仓库:** [CVE-2022-22965](https://github.com/LucasPDiniz/CVE-2022-22965)  

---

### [CVE-2022-22965](CVE-2022-22965-guigui237_Expoitation-de-la-vuln-rabilit-CVE-2022-22965.md) 🔴 ✅

**名称:** CVE-2022-22965 Spring4Shell RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可完全控制受影响的服务器  
**投毒风险:** 10%  
**发现时间:** 2025-08-01  
**POC仓库:** [Expoitation-de-la-vuln-rabilit-CVE-2022-22965](https://github.com/guigui237/Expoitation-de-la-vuln-rabilit-CVE-2022-22965)  

---

### [CVE-2022-22965](CVE-2022-22965-Aur3ns_Block-Spring4Shell.md) 🔴 ✅

**名称:** CVE-2022-22965 Spring4Shell  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-08-01  
**POC仓库:** [Block-Spring4Shell](https://github.com/Aur3ns/Block-Spring4Shell)  

---

### [CVE-2022-22965](CVE-2022-22965-jashan-lefty_Spring4Shell.md) 🔴 ✅

**名称:** CVE-2022-22965 Spring4Shell RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-01  
**POC仓库:** [Spring4Shell](https://github.com/jashan-lefty/Spring4Shell)  

---

### [CVE-2022-22965](CVE-2022-22965-brunoh6_web-threat-mitigation.md) 🔴 ✅

**名称:** CVE-2022-22965 Spring4Shell RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-08-01  
**POC仓库:** [web-threat-mitigation](https://github.com/brunoh6/web-threat-mitigation)  

---

### [CVE-2022-22965](CVE-2022-22965-ZapcoMan_spring4shell-vulnerable-application.md) 🔴 ✅

**名称:** CVE-2022-22965-Spring4Shell  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-01  
**POC仓库:** [spring4shell-vulnerable-application](https://github.com/ZapcoMan/spring4shell-vulnerable-application)  

---

### [CVE-2022-22965](CVE-2022-22965-osungjinwoo_CVE-2022-22965.md) 🔴 ✅

**名称:** CVE-2022-22965 - Spring4Shell RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-01  
**POC仓库:** [CVE-2022-22965](https://github.com/osungjinwoo/CVE-2022-22965)  

---

### [CVE-2025-25763](CVE-2025-25763-Oyst3r1ng_CVE-2025-25763.md) 🔴 

**名称:** CVE-2025-25763-CRMEB-KY-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-01  
**POC仓库:** [CVE-2025-25763](https://github.com/Oyst3r1ng/CVE-2025-25763)  

---

### [CVE-2025-20229](CVE-2025-20229-allinsthon_CVE-2025-20229.md) 🔴 ✅

**名称:** CVE-2025-20229-Splunk-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可完全控制受影响的Splunk实例  
**投毒风险:** 80%  
**发现时间:** 2025-08-01  
**POC仓库:** [CVE-2025-20229](https://github.com/allinsthon/CVE-2025-20229)  

---

### [CVE-2017-12629](CVE-2017-12629-captain-woof_cve-2017-12629.md) 🔴 ✅

**名称:** CVE-2017-12629 - Apache Solr XXE/RCE  
**类型:** XML 外部实体注入 (XXE) / 远程代码执行 (RCE)  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-08-01  
**POC仓库:** [cve-2017-12629](https://github.com/captain-woof/cve-2017-12629)  

---

### [CVE-2025-46018](CVE-2025-46018-niranjangaire1995_CVE-2025-46018-CSC-Pay-Mobile-App-Payment-Authentication-Bypass.md) 🟡 ✅

**名称:** CVE-2025-46018 – CSC Pay Mobile App Payment Authentication Bypass  
**类型:** 支付认证绕过  
**风险:** 中危，可能导致未经授权的机器使用和潜在的收入损失  
**投毒风险:** 0%  
**发现时间:** 2025-08-01  
**POC仓库:** [CVE-2025-46018-CSC-Pay-Mobile-App-Payment-Authentication-Bypass](https://github.com/niranjangaire1995/CVE-2025-46018-CSC-Pay-Mobile-App-Payment-Authentication-Bypass)  

---

### [CVE-2020-21365](CVE-2020-21365-andrei2308_CVE-2020-21365-PoC.md) 🔴 ✅

**名称:** CVE-2020-21365-wkhtmltopdf-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-08-01  
**POC仓库:** [CVE-2020-21365-PoC](https://github.com/andrei2308/CVE-2020-21365-PoC)  

---

### [CVE-2024-8517](CVE-2024-8517-Chocapikk_CVE-2024-8517.md) 🔴 ✅

**名称:** CVE-2024-8517 - SPIP BigUp Multipart File Upload OS Command Injection  
**类型:** 命令注入  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-08-01  
**POC仓库:** [CVE-2024-8517](https://github.com/Chocapikk/CVE-2024-8517)  

---

### [CVE-2024-8517](CVE-2024-8517-saadhassan77_SPIP-BigUp-Unauthenticated-RCE-Exploit-CVE-2024-8517.md) 🔴 ✅

**名称:** CVE-2024-8517 - SPIP BigUp Multipart File Upload OS Command Injection  
**类型:** 命令注入  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-08-01  
**POC仓库:** [SPIP-BigUp-Unauthenticated-RCE-Exploit-CVE-2024-8517](https://github.com/saadhassan77/SPIP-BigUp-Unauthenticated-RCE-Exploit-CVE-2024-8517)  

---

### [CVE-2025-50422](CVE-2025-50422-Landw-hub_CVE-2025-50422.md) 🟡 ✅

**名称:** Poppler pdftocairo 信息泄露漏洞  
**类型:** 信息泄露  
**风险:** 中危，可能泄露PDF文档中的敏感信息  
**投毒风险:** 5%  
**发现时间:** 2025-08-01  
**POC仓库:** [CVE-2025-50422](https://github.com/Landw-hub/CVE-2025-50422)  

---

### [CVE-2025-50420](CVE-2025-50420-Landw-hub_CVE-2025-50420.md) 🔴 ✅

**名称:** CVE-Poppler-pdfseparate-拒绝服务漏洞  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致应用程序崩溃或挂起  
**投毒风险:** 10%  
**发现时间:** 2025-08-01  
**POC仓库:** [CVE-2025-50420](https://github.com/Landw-hub/CVE-2025-50420)  

---

### [CVE-2025-46206](CVE-2025-46206-Landw-hub_CVE-2025-46206.md) 🔴 ✅

**名称:** CVE-2025-46206 - MuPDF Denial of Service  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，导致程序崩溃或服务不可用  
**投毒风险:** 0%  
**发现时间:** 2025-08-01  
**POC仓库:** [CVE-2025-46206](https://github.com/Landw-hub/CVE-2025-46206)  

---

### [CVE-2025-48703](CVE-2025-48703-itstarsec_CVE-2025-48703.md) 🔴 ✅

**名称:** CVE-2025-48703 - CentOS Web Panel 未授权远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-08-01  
**POC仓库:** [CVE-2025-48703](https://github.com/itstarsec/CVE-2025-48703)  

---

### [CVE-2024-55555](CVE-2024-55555-Yucaerin_CVE-2024-55555.md) 🔴 ✅

**名称:** CVE-2024-55555-InvoiceNinja-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致完全控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-08-01  
**POC仓库:** [CVE-2024-55555](https://github.com/Yucaerin/CVE-2024-55555)  

---


## 🔍 快速查找

- [按CVE编号查找](../../by-cve/)
- [返回2025年总览](../README.md)
- [返回总索引](../../README.md)

---

*本文档由 VulnWatchdog 自动生成 @ 2025-11-26 13:32*
