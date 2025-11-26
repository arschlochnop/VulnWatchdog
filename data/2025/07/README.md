# 2025年07月漏洞情报汇总

> 📅 统计周期: 2025-07-01 ~ 2025-07-30
> 📊 新增漏洞: **876** 个
> 🔥 高危漏洞: **745** 个

---

## 📊 漏洞类型分布

| 类型 | 数量 | 占比 |
|------|------|------|
| 远程代码执行 | 114 | 13.0% |
| 远程代码执行 (RCE) | 75 | 8.6% |
| 权限提升 | 46 | 5.3% |
| SQL注入 | 46 | 5.3% |
| 本地提权 | 44 | 5.0% |
| 远程命令执行 | 30 | 3.4% |
| 反序列化漏洞 | 23 | 2.6% |
| 本地权限提升 | 22 | 2.5% |
| 任意文件上传 | 18 | 2.1% |
| 身份验证绕过 | 17 | 1.9% |

---

## 📋 详细列表

### [CVE-2025-54589](CVE-2025-54589-byteReaper77_CVE-2025-54589.md) 🟡 ✅

**名称:** CVE-2025-54589 - copyparty Reflected XSS via Filter Parameter  
**类型:** Reflected XSS  
**风险:** 中危，CVSS 6.3，可能导致敏感信息泄露、用户会话劫持、恶意脚本执行等  
**投毒风险:** 10%  
**发现时间:** 2025-07-31  
**POC仓库:** [CVE-2025-54589](https://github.com/byteReaper77/CVE-2025-54589)  

---

### [CVE-2023-46818](CVE-2023-46818-vulnerk0_CVE-2023-46818.md) 🔴 ✅

**名称:** CVE-2023-46818-ISPConfig-PHP代码注入  
**类型:** PHP代码注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-31  
**POC仓库:** [CVE-2023-46818](https://github.com/vulnerk0/CVE-2023-46818)  

---

### [CVE-2025-30406](CVE-2025-30406-mchklt_CVE-2025-30406.md) 🔴 ✅

**名称:** CVE-2025-30406-CentreStack-反序列化漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-31  
**POC仓库:** [CVE-2025-30406](https://github.com/mchklt/CVE-2025-30406)  

---

### [CVE-2025-3969](CVE-2025-3969-Alif145_CVE-2025-3969-Exploit.md) 🔴 ✅

**名称:** CVE-2025-3969-codeprojects News Publishing Site Dashboard-Unrestricted Upload  
**类型:** Unrestricted File Upload  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-31  
**POC仓库:** [CVE-2025-3969-Exploit](https://github.com/Alif145/CVE-2025-3969-Exploit)  

---

### [CVE-2022-34155](CVE-2022-34155-vanh-88_CVE-2022-34155.md) 🔴 ✅

**名称:** CVE-2022-34155 - miniOrange OAuth Single Sign-On Plugin Authentication Bypass  
**类型:** Authentication Bypass  
**风险:** 高危，可导致未经授权的管理员访问和潜在的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-31  
**POC仓库:** [CVE-2022-34155](https://github.com/vanh-88/CVE-2022-34155)  

---

### [CVE-2023-22894](CVE-2023-22894-Saboor-Hakimi_CVE-2023-22894.md) 🟡 ✅

**名称:** CVE-2023-22894-Strapi-敏感信息泄露  
**类型:** 敏感信息泄露  
**风险:** 中危，可导致用户密码哈希和重置令牌泄露  
**投毒风险:** 1%  
**发现时间:** 2025-07-31  
**POC仓库:** [CVE-2023-22894](https://github.com/Saboor-Hakimi/CVE-2023-22894)  

---

### [CVE-2023-22894](CVE-2023-22894-maxntv24_CVE-2023-22894-PoC.md) 🟡 ✅

**名称:** CVE-2023-22894-Strapi敏感信息泄露  
**类型:** 信息泄露  
**风险:** 中危，可能导致敏感用户信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-07-31  
**POC仓库:** [CVE-2023-22894-PoC](https://github.com/maxntv24/CVE-2023-22894-PoC)  

---

### [CVE-2025-52289](CVE-2025-52289-Madhav-Bhardwaj_CVE-2025-52289.md) 🔴 ✅

**名称:** CVE-2025-52289-MagnusBilling-Broken Access Control  
**类型:** Broken Access Control  
**风险:** 高危，允许普通用户绕过管理员审批，获取未授权访问权限，可能导致系统资源滥用。  
**投毒风险:** 10%  
**发现时间:** 2025-07-31  
**POC仓库:** [CVE-2025-52289](https://github.com/Madhav-Bhardwaj/CVE-2025-52289)  

---

### [CVE-2022-44268](CVE-2022-44268-mouftan_CVE-2022-44268.md) 🔴 ✅

**名称:** CVE-2022-44268-ImageMagick-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-07-31  
**POC仓库:** [CVE-2022-44268](https://github.com/mouftan/CVE-2022-44268)  

---

### [CVE-2025-5394](CVE-2025-5394-fokda-prodz_CVE-2025-5394.md) 🔴 ✅

**名称:** CVE-2025-5394-Alone主题-任意文件上传导致RCE  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行，完全控制网站  
**投毒风险:** 1%  
**发现时间:** 2025-07-31  
**POC仓库:** [CVE-2025-5394](https://github.com/fokda-prodz/CVE-2025-5394)  

---

### [CVE-2025-27591](CVE-2025-27591-Cythonic1_CVE-2025-27591.md) 🔴 ✅

**名称:** CVE-2025-27591-below-权限提升  
**类型:** 权限提升  
**风险:** 高危，允许本地非特权用户提升至root权限  
**投毒风险:** 1%  
**发现时间:** 2025-07-31  
**POC仓库:** [CVE-2025-27591](https://github.com/Cythonic1/CVE-2025-27591)  

---

### [CVE-2025-33073](CVE-2025-33073-matejsmycka_CVE-2025-33073-checker.md) 🔴 ✅

**名称:** CVE-2025-33073 Windows SMB Client 提权漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致系统权限被提升  
**投毒风险:** 10%  
**发现时间:** 2025-07-31  
**POC仓库:** [CVE-2025-33073-checker](https://github.com/matejsmycka/CVE-2025-33073-checker)  

---

### [CVE-2025-48384](CVE-2025-48384-won6c_CVE-2025-48384-submodule.md) 🔴 ✅

**名称:** CVE-2025-48384-Git-任意代码执行  
**类型:** 任意代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-31  
**POC仓库:** [CVE-2025-48384-submodule](https://github.com/won6c/CVE-2025-48384-submodule)  

---

### [CVE-2025-50340](CVE-2025-50340-millad7_SOGo_web_mail-vulnerability-CVE-2025-50340.md) 🟡 ✅

**名称:** CVE-2025-50340 - SOGo Webmail IDOR  
**类型:** IDOR (Insecure Direct Object Reference)  
**风险:** 中危，可能导致身份伪造和钓鱼攻击  
**投毒风险:** 0%  
**发现时间:** 2025-07-31  
**POC仓库:** [SOGo_web_mail-vulnerability-CVE-2025-50340](https://github.com/millad7/SOGo_web_mail-vulnerability-CVE-2025-50340)  

---

### [CVE-2025-50341](CVE-2025-50341-millad7_Axelor-vulnerability-CVE-2025-50341.md) 🔴 ✅

**名称:** CVE-2025-50341-Axelor-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-07-31  
**POC仓库:** [Axelor-vulnerability-CVE-2025-50341](https://github.com/millad7/Axelor-vulnerability-CVE-2025-50341)  

---

### [CVE-2025-51482](CVE-2025-51482-Kai-One001_Letta-CVE-2025-51482-RCE.md) 🔴 ✅

**名称:** CVE-2025-51482 - Letta RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许远程攻击者执行任意Python代码和系统命令  
**投毒风险:** 10%  
**发现时间:** 2025-07-31  
**POC仓库:** [Letta-CVE-2025-51482-RCE](https://github.com/Kai-One001/Letta-CVE-2025-51482-RCE)  

---

### [CVE-2025-50754](CVE-2025-50754-furk4nyildiz_CVE-2025-50754-PoC.md) 🔴 ✅

**名称:** CVE-2025-50754 - PHP-Based CMS Platform Stored XSS to RCE  
**类型:** Stored XSS to Remote Code Execution  
**风险:** 高危，允许远程攻击者在受影响的服务器上执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-07-31  
**POC仓库:** [CVE-2025-50754-PoC](https://github.com/furk4nyildiz/CVE-2025-50754-PoC)  

---

### [CVE-2024-3552](CVE-2024-3552-KiPhuong_challenge-cve-2024-3552.md) 🔴 ✅

**名称:** CVE-2024-3552-Web Directory Free-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-31  
**POC仓库:** [challenge-cve-2024-3552](https://github.com/KiPhuong/challenge-cve-2024-3552)  

---

### [CVE-2023-23752](CVE-2023-23752-0xVoodoo_CVE-2023-23752.md) 🟡 ✅

**名称:** CVE-2023-23752-Joomla-信息泄露  
**类型:** 信息泄露  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-07-31  
**POC仓库:** [CVE-2023-23752](https://github.com/0xVoodoo/CVE-2023-23752)  

---

### [CVE-2024-34327](CVE-2024-34327-0xsu3ks_CVE-2024-34327.md) 🔴 ✅

**名称:** CVE-2024-34327 SQL注入漏洞  
**类型:** 时间盲注SQL注入  
**风险:** 高危，可能导致数据泄露，账户接管  
**投毒风险:** 5%  
**发现时间:** 2025-07-30  
**POC仓库:** [CVE-2024-34327](https://github.com/0xsu3ks/CVE-2024-34327)  

---

### [CVE-2025-29557](CVE-2025-29557-0xsu3ks_CVE-2025-29557.md) 🔴 ✅

**名称:** CVE-2025-29557 – ExaGrid MailConfiguration API Credential Disclosure  
**类型:** 信息泄露  
**风险:** 高危，泄露SMTP凭据可能导致进一步的攻击  
**投毒风险:** 0%  
**发现时间:** 2025-07-30  
**POC仓库:** [CVE-2025-29557](https://github.com/0xsu3ks/CVE-2025-29557)  

---

### [CVE-2025-6018](CVE-2025-6018-B1ack4sh_Blackash-CVE-2025-6018.md) 🔴 ✅

**名称:** CVE-2025-6018 Pam-config 本地提权漏洞  
**类型:** 本地提权 (LPE)  
**风险:** 高危，允许本地用户提升权限至root  
**投毒风险:** 0%  
**发现时间:** 2025-07-30  
**POC仓库:** [Blackash-CVE-2025-6018](https://github.com/B1ack4sh/Blackash-CVE-2025-6018)  

---

### [CVE-2024-34328](CVE-2024-34328-0xsu3ks_CVE-2024-34328.md) 🟡 ✅

**名称:** CVE-2024-34328 Sielox AnyWare 开放重定向  
**类型:** 开放重定向  
**风险:** 中危，可能导致钓鱼攻击、凭据窃取或恶意软件传播  
**投毒风险:** 5%  
**发现时间:** 2025-07-30  
**POC仓库:** [CVE-2024-34328](https://github.com/0xsu3ks/CVE-2024-34328)  

---

### [CVE-2023-22493](CVE-2023-22493-buitanhung144_SSRF-CVE-2023-22493.md) 🔴 ✅

**名称:** CVE-2023-22493-RSSHub-SSRF  
**类型:** SSRF  
**风险:** 高危，可能导致敏感信息泄露和内网访问  
**投毒风险:** 0%  
**发现时间:** 2025-07-30  
**POC仓库:** [SSRF-CVE-2023-22493](https://github.com/buitanhung144/SSRF-CVE-2023-22493)  

---

### [CVE-2025-29556](CVE-2025-29556-0xsu3ks_CVE-2025-29556.md) 🔴 ✅

**名称:** CVE-2025-29556 - ExaGrid Security Officer Account Creation Bypass  
**类型:** 权限提升  
**风险:** 高危，可能导致完全控制备份操作、用户创建、加密设置和更多敏感数据访问  
**投毒风险:** 0%  
**发现时间:** 2025-07-30  
**POC仓库:** [CVE-2025-29556](https://github.com/0xsu3ks/CVE-2025-29556)  

---

### [CVE-2025-27581](CVE-2025-27581-Henryisnotavailable_CVE-2025-27581.md) 🟡 ✅

**名称:** CVE-2025-27581-NIH BRICS-直接请求访问敏感模块  
**类型:** 权限绕过/强制浏览  
**风险:** 中危，可能导致敏感信息泄露或篡改  
**投毒风险:** 5%  
**发现时间:** 2025-07-30  
**POC仓库:** [CVE-2025-27581](https://github.com/Henryisnotavailable/CVE-2025-27581)  

---

### [CVE-2025-45346](CVE-2025-45346-0xsu3ks_CVE-2025-45346.md) 🔴 ✅

**名称:** CVE-2025-45346 - Bacula-Web SQL 注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-07-30  
**POC仓库:** [CVE-2025-45346](https://github.com/0xsu3ks/CVE-2025-45346)  

---

### [CVE-2017-5638](CVE-2017-5638-joidiego_Detection-struts-cve-2017-5638-detector.md) 🔴 ✅

**名称:** CVE-2017-5638-Apache Struts远程代码执行  
**类型:** 远程代码执行(RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-30  
**POC仓库:** [Detection-struts-cve-2017-5638-detector](https://github.com/joidiego/Detection-struts-cve-2017-5638-detector)  

---

### [CVE-2025-54769](CVE-2025-54769-byteReaper77_CVE-2025-54769.md) 🔴 ✅

**名称:** CVE-2025-54769-Xorux LPAR2RRD-目录遍历与RCE  
**类型:** 目录遍历与远程代码执行  
**风险:** 高危，未经授权的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-30  
**POC仓库:** [CVE-2025-54769](https://github.com/byteReaper77/CVE-2025-54769)  

---

### [CVE-2025-5777](CVE-2025-5777-below0day_Honeypot-Logs-CVE-2025-5777.md) 🔴 ✅

**名称:** CVE-2025-5777-NetScaler-Memory Overread  
**类型:** 内存越界读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 90%  
**发现时间:** 2025-07-30  
**POC仓库:** [Honeypot-Logs-CVE-2025-5777](https://github.com/below0day/Honeypot-Logs-CVE-2025-5777)  

---

### [CVE-2024-45352](CVE-2024-45352-Edwins907_CVE-2024-45352.md) 🔴 

**名称:** CVE-2024-45352 - Xiaomi Smarthome Application 代码执行漏洞  
**类型:** 代码执行  
**风险:** 高危，可能导致远程代码执行和完全控制受影响设备  
**投毒风险:** 0%  
**发现时间:** 2025-07-30  
**POC仓库:** [CVE-2024-45352](https://github.com/Edwins907/CVE-2024-45352)  

---

### [CVE-2025-32463](CVE-2025-32463-y4ney_CVE-2025-32463-lab.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-chroot提权  
**类型:** 本地权限提升  
**风险:** 高危，允许本地用户获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-30  
**POC仓库:** [CVE-2025-32463-lab](https://github.com/y4ney/CVE-2025-32463-lab)  

---

### [CVE-2023-22809](CVE-2023-22809-n3m1sys_CVE-2023-22809-sudoedit-privesc.md) 🔴 ✅

**名称:** CVE-2023-22809-sudo-权限提升  
**类型:** 权限提升  
**风险:** 高危，允许本地低权限用户获得root权限  
**投毒风险:** 0%  
**发现时间:** 2025-07-30  
**POC仓库:** [CVE-2023-22809-sudoedit-privesc](https://github.com/n3m1sys/CVE-2023-22809-sudoedit-privesc)  

---

### [CVE-2023-22809](CVE-2023-22809-M4fiaB0y_CVE-2023-22809.md) 🔴 ✅

**名称:** CVE-2023-22809-sudoedit权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，本地攻击者可获取root权限  
**投毒风险:** 0%  
**发现时间:** 2025-07-30  
**POC仓库:** [CVE-2023-22809](https://github.com/M4fiaB0y/CVE-2023-22809)  

---

### [CVE-2023-22809](CVE-2023-22809-AiK1d_CVE-2023-22809-sudo-POC.md) 🔴 ✅

**名称:** CVE-2023-22809-sudo权限提升  
**类型:** 权限提升  
**风险:** 高危，允许本地攻击者获得root权限  
**投毒风险:** 0%  
**发现时间:** 2025-07-30  
**POC仓库:** [CVE-2023-22809-sudo-POC](https://github.com/AiK1d/CVE-2023-22809-sudo-POC)  

---

### [CVE-2023-22809](CVE-2023-22809-hello4r1end_patch_CVE-2023-22809.md) 🔴 ✅

**名称:** CVE-2023-22809-Sudoedit权限提升  
**类型:** 权限提升  
**风险:** 高危，允许本地攻击者提升权限至root  
**投毒风险:** 0%  
**发现时间:** 2025-07-30  
**POC仓库:** [patch_CVE-2023-22809](https://github.com/hello4r1end/patch_CVE-2023-22809)  

---

### [CVE-2023-22809](CVE-2023-22809-Chan9Yan9_CVE-2023-22809.md) 🔴 ✅

**名称:** CVE-2023-22809-sudoedit权限提升  
**类型:** 权限提升  
**风险:** 高危，允许低权限用户提升到root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-30  
**POC仓库:** [CVE-2023-22809](https://github.com/Chan9Yan9/CVE-2023-22809)  

---

### [CVE-2023-22809](CVE-2023-22809-pashayogi_CVE-2023-22809.md) 🔴 ✅

**名称:** CVE-2023-22809-sudoedit权限提升  
**类型:** 权限提升  
**风险:** 高危，本地用户可获取root权限  
**投毒风险:** 0%  
**发现时间:** 2025-07-30  
**POC仓库:** [CVE-2023-22809](https://github.com/pashayogi/CVE-2023-22809)  

---

### [CVE-2023-22809](CVE-2023-22809-asepsaepdin_CVE-2023-22809.md) 🔴 ✅

**名称:** CVE-2023-22809-sudoedit权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，允许本地用户提升至root权限  
**投毒风险:** 0%  
**发现时间:** 2025-07-30  
**POC仓库:** [CVE-2023-22809](https://github.com/asepsaepdin/CVE-2023-22809)  

---

### [CVE-2023-22809](CVE-2023-22809-Toothless5143_CVE-2023-22809.md) 🔴 ✅

**名称:** CVE-2023-22809-Sudoedit权限提升  
**类型:** 权限提升  
**风险:** 高危，本地权限提升至root  
**投毒风险:** 0%  
**发现时间:** 2025-07-30  
**POC仓库:** [CVE-2023-22809](https://github.com/Toothless5143/CVE-2023-22809)  

---

### [CVE-2023-22809](CVE-2023-22809-AntiVlad_CVE-2023-22809.md) 🔴 ✅

**名称:** CVE-2023-22809-sudoedit权限提升  
**类型:** 权限提升  
**风险:** 高危，允许本地低权限用户提升至root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-30  
**POC仓库:** [CVE-2023-22809](https://github.com/AntiVlad/CVE-2023-22809)  

---

### [CVE-2023-22809](CVE-2023-22809-laxmiyamkolu_SUDO-privilege-escalation.md) 🔴 ✅

**名称:** CVE-2023-22809-Sudoedit特权提升  
**类型:** 特权提升  
**风险:** 高危，本地用户可提升至root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-30  
**POC仓库:** [SUDO-privilege-escalation](https://github.com/laxmiyamkolu/SUDO-privilege-escalation)  

---

### [CVE-2023-22809](CVE-2023-22809-D0rDa4aN919_CVE-2023-22809-Exploiter.md) 🔴 ✅

**名称:** CVE-2023-22809-Sudoedit权限提升  
**类型:** 权限提升  
**风险:** 高危，可能导致本地用户权限提升至root  
**投毒风险:** 10%  
**发现时间:** 2025-07-30  
**POC仓库:** [CVE-2023-22809-Exploiter](https://github.com/D0rDa4aN919/CVE-2023-22809-Exploiter)  

---

### [CVE-2023-22809](CVE-2023-22809-spidoman_CVE-2023-22809-automated-python-exploits.md) 🔴 ✅

**名称:** CVE-2023-22809-Sudoedit权限提升  
**类型:** 权限提升  
**风险:** 高危，允许本地低权限用户提升至root权限  
**投毒风险:** 20%  
**发现时间:** 2025-07-30  
**POC仓库:** [CVE-2023-22809-automated-python-exploits](https://github.com/spidoman/CVE-2023-22809-automated-python-exploits)  

---

### [CVE-2023-2533](CVE-2023-2533-allinsthon_CVE-2023-2533.md) 🔴 

**名称:** CVE-2023-2533 PaperCut NG/MF CSRF 漏洞  
**类型:** 跨站请求伪造 (CSRF)  
**风险:** 高危，可能导致安全设置更改和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-30  
**POC仓库:** [CVE-2023-2533](https://github.com/allinsthon/CVE-2023-2533)  

---

### [CVE-2025-29824](CVE-2025-29824-AfanPan_CVE-2025-29824-Exploit.md) 🔴 ✅

**名称:** CVE-2025-29824 - Windows CLFS Use-After-Free EoP  
**类型:** 权限提升 (Elevation of Privilege)  
**风险:** 高危，可能导致完全系统控制和勒索软件部署  
**投毒风险:** 20%  
**发现时间:** 2025-07-30  
**POC仓库:** [CVE-2025-29824-Exploit](https://github.com/AfanPan/CVE-2025-29824-Exploit)  

---

### [CVE-2025-50460](CVE-2025-50460-Anchor0221_CVE-2025-50460.md)  ✅

**名称:** CVE-2025-50460-未知应用-漏洞利用分析  
**类型:** 未知  
**风险:** 高  
**投毒风险:** 0%  
**发现时间:** 2025-07-30  
**POC仓库:** [CVE-2025-50460](https://github.com/Anchor0221/CVE-2025-50460)  

---

### [CVE-2024-39211](CVE-2024-39211-artemy-ccrsky_CVE-2024-39211.md) 🟡 ✅

**名称:** CVE-2024-39211 - Kaiten 用户枚举  
**类型:** 用户枚举  
**风险:** 中危，可能导致信息泄露，为进一步攻击提供便利  
**投毒风险:** 0%  
**发现时间:** 2025-07-30  
**POC仓库:** [CVE-2024-39211](https://github.com/artemy-ccrsky/CVE-2024-39211)  

---

### [CVE-2025-50460](CVE-2025-50460-Anchor0221_CVE-2025-50460.md) 🔴 ✅

**名称:** CVE-2025-50460  
**类型:** 未知  
**风险:** 根据搜索结果，可能为高危  
**投毒风险:** 10%  
**发现时间:** 2025-07-30  
**POC仓库:** [CVE-2025-50460](https://github.com/Anchor0221/CVE-2025-50460)  

---

### [CVE-2025-50472](CVE-2025-50472-xhjy2020_CVE-2025-50472.md)  ✅

**名称:** CVE-2025-50472  
**类型:** 未知  
**风险:** 根据搜索结果信息未知，需要进一步分析  
**投毒风险:** 0%  
**发现时间:** 2025-07-30  
**POC仓库:** [CVE-2025-50472](https://github.com/xhjy2020/CVE-2025-50472)  

---

### [CVE-2018-1049](CVE-2018-1049-lukehebe_CVE-2018-1049.md) 🟡 

**名称:** CVE-2018-1049-Systemd-DoS  
**类型:** 竞争条件导致拒绝服务  
**风险:** 中危，导致拒绝服务，系统挂起  
**投毒风险:** 0%  
**发现时间:** 2025-07-30  
**POC仓库:** [CVE-2018-1049](https://github.com/lukehebe/CVE-2018-1049)  

---

### [CVE-2021-1675](CVE-2021-1675-OppressionBreedsResistance_CVE-2021-1675-PrintNightmare.md) 🔴 ✅

**名称:** CVE-2021-1675 PrintNightmare  
**类型:** 远程代码执行  
**风险:** 高危，可能导致系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-30  
**POC仓库:** [CVE-2021-1675-PrintNightmare](https://github.com/OppressionBreedsResistance/CVE-2021-1675-PrintNightmare)  

---

### [CVE-2025-54381](CVE-2025-54381-rockmelodies_bentoml_CVE-2025-54381.md) 🔴 

**名称:** CVE-2025-54381-BentoML-SSRF  
**类型:** SSRF  
**风险:** 高危，允许未授权的远程攻击者强制服务器发出任意HTTP请求，可能泄露内部信息或执行恶意操作  
**投毒风险:** 10%  
**发现时间:** 2025-07-30  
**POC仓库:** [bentoml_CVE-2025-54381](https://github.com/rockmelodies/bentoml_CVE-2025-54381)  

---

### [CVE-2021-1675](CVE-2021-1675-Winter3un_CVE-2021-1675.md) 🔴 ✅

**名称:** CVE-2021-1675 Windows Print Spooler Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，可能导致系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-29  
**POC仓库:** [CVE-2021-1675](https://github.com/Winter3un/CVE-2021-1675)  

---

### [CVE-2021-1675](CVE-2021-1675-cube0x0_CVE-2021-1675.md) 🔴 ✅

**名称:** CVE-2021-1675 PrintNightmare 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可导致系统权限被获取  
**投毒风险:** 10%  
**发现时间:** 2025-07-29  
**POC仓库:** [CVE-2021-1675](https://github.com/cube0x0/CVE-2021-1675)  

---

### [CVE-2021-1675](CVE-2021-1675-hahaleyile_my-CVE-2021-1675.md) 🔴 ✅

**名称:** CVE-2021-1675 - Windows Print Spooler Remote Code Execution  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许攻击者以SYSTEM权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-07-29  
**POC仓库:** [my-CVE-2021-1675](https://github.com/hahaleyile/my-CVE-2021-1675)  

---

### [CVE-2021-1675](CVE-2021-1675-mstxq17_CVE-2021-1675_RDL_LPE.md) 🔴 ✅

**名称:** CVE-2021-1675 PrintNightmare LPE  
**类型:** 本地提权（LPE）/远程代码执行（RCE）  
**风险:** 高危，可提升至SYSTEM权限并可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-29  
**POC仓库:** [CVE-2021-1675_RDL_LPE](https://github.com/mstxq17/CVE-2021-1675_RDL_LPE)  

---

### [CVE-2021-1675](CVE-2021-1675-Wra7h_SharpPN.md) 🔴 ✅

**名称:** CVE-2021-1675 PrintNightmare  
**类型:** 远程代码执行  
**风险:** 高危，可导致系统权限提升和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-29  
**POC仓库:** [SharpPN](https://github.com/Wra7h/SharpPN)  

---

### [CVE-2021-1675](CVE-2021-1675-ly4k_PrintNightmare.md) 🔴 ✅

**名称:** CVE-2021-1675/CVE-2021-34527 PrintNightmare Windows Print Spooler RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许攻击者以SYSTEM权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-07-29  
**POC仓库:** [PrintNightmare](https://github.com/ly4k/PrintNightmare)  

---

### [CVE-2021-1675](CVE-2021-1675-puckiestyle_CVE-2021-1675.md) 🔴 ✅

**名称:** CVE-2021-1675 PrintNightmare  
**类型:** 远程代码执行  
**风险:** 高危，可导致 SYSTEM 权限的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-29  
**POC仓库:** [CVE-2021-1675](https://github.com/puckiestyle/CVE-2021-1675)  

---

### [CVE-2021-1675](CVE-2021-1675-cybersecurityworks553_CVE-2021-1675_PrintNightMare.md) 🔴 ✅

**名称:** CVE-2021-1675 PrintNightmare Windows Print Spooler RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致系统完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-07-29  
**POC仓库:** [CVE-2021-1675_PrintNightMare](https://github.com/cybersecurityworks553/CVE-2021-1675_PrintNightMare)  

---

### [CVE-2021-1675](CVE-2021-1675-eversinc33_NimNightmare.md) 🔴 ✅

**名称:** CVE-2021-1675 Windows Print Spooler 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致系统权限提升和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-29  
**POC仓库:** [NimNightmare](https://github.com/eversinc33/NimNightmare)  

---

### [CVE-2021-1675](CVE-2021-1675-AndrewTrube_CVE-2021-1675.md) 🔴 ✅

**名称:** CVE-2021-1675 PrintNightmare 本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，攻击者可利用此漏洞获取SYSTEM权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-29  
**POC仓库:** [CVE-2021-1675](https://github.com/AndrewTrube/CVE-2021-1675)  

---

### [CVE-2021-1675](CVE-2021-1675-TheJoyOfHacking_cube0x0-CVE-2021-1675.md) 🔴 ✅

**名称:** CVE-2021-1675 PrintNightmare  
**类型:** 远程代码执行  
**风险:** 高危，可导致系统权限提升和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-29  
**POC仓库:** [cube0x0-CVE-2021-1675](https://github.com/TheJoyOfHacking/cube0x0-CVE-2021-1675)  

---

### [CVE-2021-1675](CVE-2021-1675-TheJoyOfHacking_calebstewart-CVE-2021-1675.md) 🔴 ✅

**名称:** CVE-2021-1675 PrintNightmare Windows Print Spooler RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致系统被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-29  
**POC仓库:** [calebstewart-CVE-2021-1675](https://github.com/TheJoyOfHacking/calebstewart-CVE-2021-1675)  

---

### [CVE-2021-1675](CVE-2021-1675-jj4152_cve-2021-1675.md) 🔴 ✅

**名称:** CVE-2021-1675 PrintNightmare Windows Print Spooler RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行，系统权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-07-29  
**POC仓库:** [cve-2021-1675](https://github.com/jj4152/cve-2021-1675)  

---

### [CVE-2021-1675](CVE-2021-1675-edsonjt81_CVE-2021-1675.md) 🔴 ✅

**名称:** CVE-2021-1675 PrintNightmare Windows Print Spooler RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致远程代码执行，权限提升至SYSTEM  
**投毒风险:** 10%  
**发现时间:** 2025-07-29  
**POC仓库:** [CVE-2021-1675](https://github.com/edsonjt81/CVE-2021-1675)  

---

### [CVE-2021-1675](CVE-2021-1675-r1skkam_PrintNightmare.md) 🔴 ✅

**名称:** CVE-2021-1675 PrintNightmare  
**类型:** 远程代码执行  
**风险:** 高危，可能导致系统权限提升和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-29  
**POC仓库:** [PrintNightmare](https://github.com/r1skkam/PrintNightmare)  

---

### [CVE-2021-1675](CVE-2021-1675-LaresLLC_CVE-2021-1675.md) 🔴 ✅

**名称:** CVE-2021-1675 PrintNightmare  
**类型:** 远程代码执行  
**风险:** 高危，允许远程代码执行，可能导致系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-29  
**POC仓库:** [CVE-2021-1675](https://github.com/LaresLLC/CVE-2021-1675)  

---

### [CVE-2021-1675](CVE-2021-1675-peckre_PNCVE-Win10-20H2-Exploit.md) 🔴 ✅

**名称:** CVE-2021-1675 PrintNightmare Windows Print Spooler 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-29  
**POC仓库:** [PNCVE-Win10-20H2-Exploit](https://github.com/peckre/PNCVE-Win10-20H2-Exploit)  

---

### [CVE-2021-1675](CVE-2021-1675-whoami-chmod777_CVE-2021-1675-CVE-2021-34527.md) 🔴 ✅

**名称:** CVE-2021-1675 PrintNightmare  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许攻击者以SYSTEM权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-07-29  
**POC仓库:** [CVE-2021-1675-CVE-2021-34527](https://github.com/whoami-chmod777/CVE-2021-1675-CVE-2021-34527)  

---

### [CVE-2021-1675](CVE-2021-1675-whoami-chmod777_CVE-2021-1675---PrintNightmare-LPE-PowerShell-.md) 🔴 ✅

**名称:** CVE-2021-1675 PrintNightmare Windows Print Spooler RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者以SYSTEM权限执行任意代码  
**投毒风险:** 1%  
**发现时间:** 2025-07-29  
**POC仓库:** [CVE-2021-1675---PrintNightmare-LPE-PowerShell-](https://github.com/whoami-chmod777/CVE-2021-1675---PrintNightmare-LPE-PowerShell-)  

---

### [CVE-2021-1675](CVE-2021-1675-thalpius_Microsoft-CVE-2021-1675.md) 🔴 ✅

**名称:** CVE-2021-1675-PrintNightmare  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在受影响的系统上执行任意代码，可能导致完全控制系统。  
**投毒风险:** 10%  
**发现时间:** 2025-07-29  
**POC仓库:** [Microsoft-CVE-2021-1675](https://github.com/thalpius/Microsoft-CVE-2021-1675)  

---

### [CVE-2021-1675](CVE-2021-1675-0xSs0rZ_Windows_Exploit.md) 🔴 ✅

**名称:** CVE-2021-1675 PrintNightmare  
**类型:** 远程代码执行  
**风险:** 高危，允许远程代码执行，可能导致系统完全被控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-29  
**POC仓库:** [Windows_Exploit](https://github.com/0xSs0rZ/Windows_Exploit)  

---

### [CVE-2021-1675](CVE-2021-1675-corelight_CVE-2021-1675.md) 🔴 ✅

**名称:** CVE-2021-1675 PrintNightmare  
**类型:** 远程代码执行  
**风险:** 高危，可导致远程代码执行并获取SYSTEM权限  
**投毒风险:** 5%  
**发现时间:** 2025-07-29  
**POC仓库:** [CVE-2021-1675](https://github.com/corelight/CVE-2021-1675)  

---

### [CVE-2021-1675](CVE-2021-1675-Sp4ceDogy_NPE-CS-V-CVE-2021-1675.md) 🔴 ✅

**名称:** CVE-2021-1675 PrintNightmare Windows Print Spooler RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-29  
**POC仓库:** [NPE-CS-V-CVE-2021-1675](https://github.com/Sp4ceDogy/NPE-CS-V-CVE-2021-1675)  

---

### [CVE-2021-1675](CVE-2021-1675-DLL00P_CVE-2021-1675.md) 🔴 ✅

**名称:** CVE-2021-1675 - Windows Print Spooler Remote Code Execution  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经授权的用户获取SYSTEM权限并执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-07-29  
**POC仓库:** [CVE-2021-1675](https://github.com/DLL00P/CVE-2021-1675)  

---

### [CVE-2018-16119](CVE-2018-16119-hdbreaker_CVE-2018-16119.md) 🔴 ✅

**名称:** CVE-2018-16119-TP-Link WR1043ND 远程代码执行  
**类型:** 栈溢出  
**风险:** 高危，允许远程攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-07-29  
**POC仓库:** [CVE-2018-16119](https://github.com/hdbreaker/CVE-2018-16119)  

---

### [CVE-2025-29927](CVE-2025-29927-b4sh0xf_PoC-CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js Middleware Authorization Bypass  
**类型:** 授权绕过  
**风险:** 高危，可能允许未授权访问受保护的资源和功能  
**投毒风险:** 5%  
**发现时间:** 2025-07-29  
**POC仓库:** [PoC-CVE-2025-29927](https://github.com/b4sh0xf/PoC-CVE-2025-29927)  

---

### [CVE-2016-4622](CVE-2016-4622-saelo_jscpwn.md) 🔴 ✅

**名称:** CVE-2016-4622 - WebKit 内存损坏导致任意代码执行  
**类型:** 内存损坏  
**风险:** 高危，可能导致远程代码执行或拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-07-29  
**POC仓库:** [jscpwn](https://github.com/saelo/jscpwn)  

---

### [CVE-2016-4622](CVE-2016-4622-hdbreaker_WebKit-CVE-2016-4622.md) 🟡 ✅

**名称:** CVE-2016-4622 WebKit JavaScriptCore 内存泄露  
**类型:** 内存泄露  
**风险:** 中危，可能导致信息泄露，为进一步攻击提供基础  
**投毒风险:** 10%  
**发现时间:** 2025-07-29  
**POC仓库:** [WebKit-CVE-2016-4622](https://github.com/hdbreaker/WebKit-CVE-2016-4622)  

---

### [CVE-2021-43857](CVE-2021-43857-ProwlSec_gerapy-cve-2021-43857.md) 🔴 ✅

**名称:** CVE-2021-43857-Gerapy-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-07-29  
**POC仓库:** [gerapy-cve-2021-43857](https://github.com/ProwlSec/gerapy-cve-2021-43857)  

---

### [CVE-2025-52289](CVE-2025-52289-Madhav-Bhardwaj_CVE-2025-52289.md) 🔴 ✅

**名称:** CVE-2025-52289 - MagnusBilling Broken Access Control  
**类型:** Broken Access Control  
**风险:** 高危，可能导致未经授权的访问和系统资源滥用  
**投毒风险:** 0%  
**发现时间:** 2025-07-29  
**POC仓库:** [CVE-2025-52289](https://github.com/Madhav-Bhardwaj/CVE-2025-52289)  

---

### [CVE-2001-1473](CVE-2001-1473-alexandermoro_cve-2001-1473.md) 🔴 ✅

**名称:** CVE-2001-1473 - SSH-1 Man-in-the-Middle 攻击  
**类型:** Man-in-the-Middle  
**风险:** 高危，可能导致服务器私钥泄露，完全控制服务器  
**投毒风险:** 1%  
**发现时间:** 2025-07-29  
**POC仓库:** [cve-2001-1473](https://github.com/alexandermoro/cve-2001-1473)  

---

### [CVE-2025-53770](CVE-2025-53770-Immersive-Labs-Sec_SharePoint-CVE-2025-53770-POC.md)  ✅

**名称:** CVE-2025-53770 - Microsoft SharePoint Server 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，未经授权的攻击者可以通过网络执行任意代码  
**投毒风险:** 1%  
**发现时间:** 2025-07-29  
**POC仓库:** [SharePoint-CVE-2025-53770-POC](https://github.com/Immersive-Labs-Sec/SharePoint-CVE-2025-53770-POC)  

---

### [CVE-2025-54352](CVE-2025-54352-yohannslm_CVE-2025-54352.md)  ✅

**名称:** CVE-2025-54352-WordPress-私有/草稿文章标题泄露  
**类型:** 信息泄露  
**风险:** 低危，可能泄露未公开文章的标题信息  
**投毒风险:** 10%  
**发现时间:** 2025-07-29  
**POC仓库:** [CVE-2025-54352](https://github.com/yohannslm/CVE-2025-54352)  

---

### [CVE-2025-47227](CVE-2025-47227-synacktiv_CVE-2025-47227_CVE-2025-47228.md) 🔴 ✅

**名称:** CVE-2025-47227 - ScriptCase 管理员密码重置漏洞  
**类型:** 身份验证绕过  
**风险:** 高危，可导致管理员账户接管和远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-07-29  
**POC仓库:** [CVE-2025-47227_CVE-2025-47228](https://github.com/synacktiv/CVE-2025-47227_CVE-2025-47228)  

---

### [CVE-2025-47227](CVE-2025-47227-B1ack4sh_Blackash-CVE-2025-47227.md) 🔴 ✅

**名称:** CVE-2025-47227-ScriptCase-管理员账户接管  
**类型:** 不正确的权限管理/密码重置缺陷  
**风险:** 高危，允许未经身份验证的攻击者接管管理员账户  
**投毒风险:** 10%  
**发现时间:** 2025-07-29  
**POC仓库:** [Blackash-CVE-2025-47227](https://github.com/B1ack4sh/Blackash-CVE-2025-47227)  

---

### [CVE-2025-32463](CVE-2025-32463-KaiHT-Ladiant_CVE-2025-32463.md)  ✅

**名称:** CVE-2025-32463-Sudo-本地权限提升  
**类型:** 本地权限提升  
**风险:** 严重，允许本地用户获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-29  
**POC仓库:** [CVE-2025-32463](https://github.com/KaiHT-Ladiant/CVE-2025-32463)  

---

### [CVE-2025-53770](CVE-2025-53770-0x-crypt_CVE-2025-53770-Scanner.md) 🔴 ✅

**名称:** CVE-2025-53770 Microsoft SharePoint Server 远程代码执行漏洞  
**类型:** 反序列化  
**风险:** 高危，允许未经授权的攻击者通过网络执行代码  
**投毒风险:** 1%  
**发现时间:** 2025-07-29  
**POC仓库:** [CVE-2025-53770-Scanner](https://github.com/0x-crypt/CVE-2025-53770-Scanner)  

---

### [CVE-2025-34077](CVE-2025-34077-0xgh057r3c0n_CVE-2025-34077.md) 🔴 ✅

**名称:** CVE-2025-34077 - WordPress Pie Register Plugin Authentication Bypass RCE  
**类型:** Authentication Bypass  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-28  
**POC仓库:** [CVE-2025-34077](https://github.com/0xgh057r3c0n/CVE-2025-34077)  

---

### [CVE-2025-24813](CVE-2025-24813-uzairhaider502_CVE-2025-24813.md) 🔴 ✅

**名称:** CVE-2025-24813 - Apache Tomcat Path Equivalence Vulnerability  
**类型:** 路径遍历/远程代码执行/信息泄露  
**风险:** 高危，可能导致远程代码执行，信息泄露，恶意文件上传  
**投毒风险:** 0%  
**发现时间:** 2025-07-28  
**POC仓库:** [CVE-2025-24813](https://github.com/uzairhaider502/CVE-2025-24813)  

---

### [CVE-2025-24813](CVE-2025-24813-x00byte_PutScanner.md) 🔴 ✅

**名称:** CVE-2025-24813-Apache Tomcat 路径等价漏洞  
**类型:** 路径等价/远程代码执行/信息泄露  
**风险:** 高危，可能导致远程代码执行和敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-07-28  
**POC仓库:** [PutScanner](https://github.com/x00byte/PutScanner)  

---

### [CVE-2025-24813](CVE-2025-24813-Shivshantp_CVE-2025-24813.md) 🔴 ✅

**名称:** CVE-2025-24813 - Apache Tomcat PUT JSP RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-07-28  
**POC仓库:** [CVE-2025-24813](https://github.com/Shivshantp/CVE-2025-24813)  

---

### [CVE-2020-15778](CVE-2020-15778-Neko-chanQwQ_CVE-2020-15778-Exploit.md) 🔴 ✅

**名称:** CVE-2020-15778-OpenSSH-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-28  
**POC仓库:** [CVE-2020-15778-Exploit](https://github.com/Neko-chanQwQ/CVE-2020-15778-Exploit)  

---

### [CVE-2020-15778](CVE-2020-15778-cpandya2909_CVE-2020-15778.md) 🔴 ✅

**名称:** CVE-2020-15778 OpenSSH SCP 命令注入  
**类型:** 命令注入  
**风险:** 高危，允许远程服务器执行任意命令  
**投毒风险:** 1%  
**发现时间:** 2025-07-28  
**POC仓库:** [CVE-2020-15778](https://github.com/cpandya2909/CVE-2020-15778)  

---

### [CVE-2020-15778](CVE-2020-15778-Evan-Zhangyf_CVE-2020-15778.md) 🔴 ✅

**名称:** CVE-2020-15778 OpenSSH SCP 命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-28  
**POC仓库:** [CVE-2020-15778](https://github.com/Evan-Zhangyf/CVE-2020-15778)  

---

### [CVE-2020-15778](CVE-2020-15778-drackyjr_CVE-2020-15778-SCP-Command-Injection-Check.md) 🔴 ✅

**名称:** CVE-2020-15778-OpenSSH-SCP命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-28  
**POC仓库:** [CVE-2020-15778-SCP-Command-Injection-Check](https://github.com/drackyjr/CVE-2020-15778-SCP-Command-Injection-Check)  

---

### [CVE-2025-50866](CVE-2025-50866-SacX-7_CVE-2025-50866.md) 🟡 ✅

**名称:** CloudClassroom-PHP-Project 1.0 Reflected XSS  
**类型:** 跨站脚本漏洞 (XSS)  
**风险:** 中危，可能导致会话劫持或钓鱼攻击  
**投毒风险:** 0%  
**发现时间:** 2025-07-28  
**POC仓库:** [CVE-2025-50866](https://github.com/SacX-7/CVE-2025-50866)  

---

### [CVE-2025-50867](CVE-2025-50867-SacX-7_CVE-2025-50867.md) 🔴 ✅

**名称:** CloudClassroom-PHP-Project 1.0 SQL注入漏洞  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、数据篡改和远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-07-28  
**POC仓库:** [CVE-2025-50867](https://github.com/SacX-7/CVE-2025-50867)  

---

### [CVE-2024-33676](CVE-2024-33676-dersecure_CVE-2024-33676.md) 🔴 ✅

**名称:** CVE-2024-33676 - Enel X JuiceBox Level 2 EV charger 弱认证漏洞  
**类型:** 弱认证/未授权访问  
**风险:** 高危，可能导致设备控制、信息泄露和拒绝服务  
**投毒风险:** 0%  
**发现时间:** 2025-07-28  
**POC仓库:** [CVE-2024-33676](https://github.com/dersecure/CVE-2024-33676)  

---

### [CVE-2023-26136](CVE-2023-26136-guy2610_tough-cookie-patch-cve-2023-26136.md) 🟡 ✅

**名称:** CVE-2023-26136-tough-cookie-原型污染  
**类型:** 原型污染  
**风险:** 中危，可能导致拒绝服务或客户端代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-28  
**POC仓库:** [tough-cookie-patch-cve-2023-26136](https://github.com/guy2610/tough-cookie-patch-cve-2023-26136)  

---

### [CVE-2025-53770](CVE-2025-53770-daryllundy_CVE-2025-53770.md)  ✅

**名称:** CVE-2025-53770-Microsoft SharePoint Server-反序列化RCE  
**类型:** 反序列化RCE  
**风险:** 严重，未经授权的攻击者可以通过网络执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-07-28  
**POC仓库:** [CVE-2025-53770](https://github.com/daryllundy/CVE-2025-53770)  

---

### [CVE-2025-32429](CVE-2025-32429-imbas007_CVE-2025-32429-Checker.md) 🔴 ✅

**名称:** CVE-2025-32429-XWiki-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-28  
**POC仓库:** [CVE-2025-32429-Checker](https://github.com/imbas007/CVE-2025-32429-Checker)  

---

### [CVE-2023-34362](CVE-2023-34362-deepinstinct_MOVEit_CVE-2023-34362_IOCs.md) 🔴 ✅

**名称:** CVE-2023-34362-MOVEit Transfer-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致未经授权的数据库访问、信息泄露、数据篡改和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-28  
**POC仓库:** [MOVEit_CVE-2023-34362_IOCs](https://github.com/deepinstinct/MOVEit_CVE-2023-34362_IOCs)  

---

### [CVE-2023-34362](CVE-2023-34362-lithuanian-g_cve-2023-34362-iocs.md) 🔴 ✅

**名称:** CVE-2023-34362-MOVEit Transfer-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致未经授权的数据库访问、数据泄露、远程代码执行  
**投毒风险:** 20%  
**发现时间:** 2025-07-28  
**POC仓库:** [cve-2023-34362-iocs](https://github.com/lithuanian-g/cve-2023-34362-iocs)  

---

### [CVE-2023-34362](CVE-2023-34362-kenbuckler_MOVEit-CVE-2023-34362.md) 🔴 ✅

**名称:** CVE-2023-34362-MOVEit Transfer-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致未授权访问数据库，信息泄露，数据篡改或删除  
**投毒风险:** 10%  
**发现时间:** 2025-07-28  
**POC仓库:** [MOVEit-CVE-2023-34362](https://github.com/kenbuckler/MOVEit-CVE-2023-34362)  

---

### [CVE-2023-34362](CVE-2023-34362-horizon3ai_CVE-2023-34362.md) 🔴 ✅

**名称:** CVE-2023-34362-MOVEit Transfer-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致未经身份验证的攻击者访问数据库，泄露、修改或删除数据，甚至执行任意SQL语句。  
**投毒风险:** 10%  
**发现时间:** 2025-07-28  
**POC仓库:** [CVE-2023-34362](https://github.com/horizon3ai/CVE-2023-34362)  

---

### [CVE-2023-34362](CVE-2023-34362-Malwareman007_CVE-2023-34362.md) 🔴 ✅

**名称:** CVE-2023-34362-MOVEit Transfer-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、数据篡改和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-28  
**POC仓库:** [CVE-2023-34362](https://github.com/Malwareman007/CVE-2023-34362)  

---

### [CVE-2023-34362](CVE-2023-34362-toorandom_moveit-payload-decrypt-CVE-2023-34362.md) 🔴 ✅

**名称:** CVE-2023-34362-MOVEit Transfer-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、远程代码执行，以及被勒索软件利用  
**投毒风险:** 10%  
**发现时间:** 2025-07-28  
**POC仓库:** [moveit-payload-decrypt-CVE-2023-34362](https://github.com/toorandom/moveit-payload-decrypt-CVE-2023-34362)  

---

### [CVE-2023-34362](CVE-2023-34362-errorfiathck_MOVEit-Exploit.md) 🔴 ✅

**名称:** CVE-2023-34362-MOVEit Transfer-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致未授权访问数据库，信息泄露，甚至远程代码执行。  
**投毒风险:** 1%  
**发现时间:** 2025-07-28  
**POC仓库:** [MOVEit-Exploit](https://github.com/errorfiathck/MOVEit-Exploit)  

---

### [CVE-2023-34362](CVE-2023-34362-Chinyemba-ck_MOVEit-CVE-2023-34362.md) 🔴 

**名称:** CVE-2023-34362-MOVEit Transfer-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致未授权访问数据库、数据泄露、修改或删除数据库元素，甚至远程代码执行。  
**投毒风险:** 5%  
**发现时间:** 2025-07-28  
**POC仓库:** [MOVEit-CVE-2023-34362](https://github.com/Chinyemba-ck/MOVEit-CVE-2023-34362)  

---

### [CVE-2023-34362](CVE-2023-34362-sfewer-r7_CVE-2023-34362.md) 🔴 ✅

**名称:** CVE-2023-34362-MOVEit Transfer-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据库访问、数据泄露和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-28  
**POC仓库:** [CVE-2023-34362](https://github.com/sfewer-r7/CVE-2023-34362)  

---

### [CVE-2023-34362](CVE-2023-34362-glen-pearson_MoveIT-CVE-2023-34362-RCE.md) 🔴 ✅

**名称:** CVE-2023-34362-MOVEit Transfer-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可导致未经身份验证的攻击者访问数据库，远程代码执行。  
**投毒风险:** 1%  
**发现时间:** 2025-07-28  
**POC仓库:** [MoveIT-CVE-2023-34362-RCE](https://github.com/glen-pearson/MoveIT-CVE-2023-34362-RCE)  

---

### [CVE-2023-34362](CVE-2023-34362-Naveenbana5250_CVE-2023-34362-Defense-Package.md) 🔴 ✅

**名称:** CVE-2023-34362-MOVEit Transfer-SQL注入  
**类型:** SQL注入  
**风险:** 高危，未经身份验证的攻击者可以访问数据库，可能导致信息泄露，修改或删除数据库元素，最终实现远程代码执行。  
**投毒风险:** 10%  
**发现时间:** 2025-07-28  
**POC仓库:** [CVE-2023-34362-Defense-Package](https://github.com/Naveenbana5250/CVE-2023-34362-Defense-Package)  

---

### [CVE-2025-32462](CVE-2025-32462-j3r1ch0123_CVE-2025-32462.md) 🟡 ✅

**名称:** CVE-2025-32462-Sudo-主机绕过  
**类型:** 权限提升  
**风险:** 中危，可导致本地权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-07-28  
**POC仓库:** [CVE-2025-32462](https://github.com/j3r1ch0123/CVE-2025-32462)  

---

### [CVE-2025-53770](CVE-2025-53770-r3xbugbounty_CVE-2025-53770.md) 🔴 ✅

**名称:** CVE-2025-53770-SharePoint-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致远程代码执行，完全控制受影响的SharePoint服务器  
**投毒风险:** 10%  
**发现时间:** 2025-07-28  
**POC仓库:** [CVE-2025-53770](https://github.com/r3xbugbounty/CVE-2025-53770)  

---

### [CVE-2025-2294](CVE-2025-2294-r0otk3r_CVE-2025-2294.md)  ✅

**名称:** CVE-2025-2294 - WordPress Kubio AI Page Builder LFI  
**类型:** 本地文件包含 (LFI)  
**风险:** 严重，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-28  
**POC仓库:** [CVE-2025-2294](https://github.com/r0otk3r/CVE-2025-2294)  

---

### [CVE-2025-8191](CVE-2025-8191-byteReaper77_CVE-2025-8191.md) 🟡 ✅

**名称:** CVE-2025-8191-macrozheng mall-XSS  
**类型:** XSS  
**风险:** 中危，可能导致Cookie窃取和任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-28  
**POC仓库:** [CVE-2025-8191](https://github.com/byteReaper77/CVE-2025-8191)  

---

### [CVE-2019-8978](CVE-2019-8978-SecKatie_CVE-2019-8978.md) 🔴 ✅

**名称:** CVE-2019-8978-Ellucian Banner Web Tailor-不当身份验证  
**类型:** 不当身份验证/竞态条件  
**风险:** 高危，可能导致会话劫持和拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-07-28  
**POC仓库:** [CVE-2019-8978](https://github.com/SecKatie/CVE-2019-8978)  

---

### [CVE-2025-53770](CVE-2025-53770-3a7_CVE-2025-53770.md) 🔴 ✅

**名称:** CVE-2025-53770-Microsoft SharePoint Server 远程代码执行漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，未经授权的攻击者可以通过网络执行任意代码，导致完全系统入侵。  
**投毒风险:** 10%  
**发现时间:** 2025-07-27  
**POC仓库:** [CVE-2025-53770](https://github.com/3a7/CVE-2025-53770)  

---

### [CVE-2025-47812](CVE-2025-47812-r0otk3r_CVE-2025-47812.md) 🔴 ✅

**名称:** CVE-2025-47812 – Wing FTP Server RCE  
**类型:** 远程代码执行  
**风险:** 高危，可完全控制服务器  
**投毒风险:** 5%  
**发现时间:** 2025-07-27  
**POC仓库:** [CVE-2025-47812](https://github.com/r0otk3r/CVE-2025-47812)  

---

### [CVE-2023-42931](CVE-2023-42931-d0rb_CVE-2023-42931.md) 🔴 ✅

**名称:** CVE-2023-42931 - macOS Privilege Escalation  
**类型:** 权限提升  
**风险:** 高危，可获取Root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-27  
**POC仓库:** [CVE-2023-42931](https://github.com/d0rb/CVE-2023-42931)  

---

### [CVE-2023-42931](CVE-2023-42931-tageniu_CVE-2023-42931.md) 🔴 ✅

**名称:** CVE-2023-42931 - macOS Privilege Escalation  
**类型:** 特权提升  
**风险:** 高危，可导致未经授权的管理员权限获取  
**投毒风险:** 10%  
**发现时间:** 2025-07-27  
**POC仓库:** [CVE-2023-42931](https://github.com/tageniu/CVE-2023-42931)  

---

### [CVE-2025-29927](CVE-2025-29927-sahbaazansari_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-AuthorizationBypass  
**类型:** Authorization Bypass  
**风险:** 高危，可能导致未授权访问和数据篡改  
**投毒风险:** 10%  
**发现时间:** 2025-07-27  
**POC仓库:** [CVE-2025-29927](https://github.com/sahbaazansari/CVE-2025-29927)  

---

### [CVE-2025-53770](CVE-2025-53770-bossnick98_-SOC342---CVE-2025-53770-SharePoint-ToolShell-Auth-Bypass-and-RCE.md) 🔴 ✅

**名称:** CVE-2025-53770-SharePoint-Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，允许未经授权的攻击者通过网络执行代码  
**投毒风险:** 10%  
**发现时间:** 2025-07-27  
**POC仓库:** [-SOC342---CVE-2025-53770-SharePoint-ToolShell-Auth-Bypass-and-RCE](https://github.com/bossnick98/-SOC342---CVE-2025-53770-SharePoint-ToolShell-Auth-Bypass-and-RCE)  

---

### [CVE-2024-43018](CVE-2024-43018-joaosilva21_CVE-2024-43018.md) 🔴 ✅

**名称:** CVE-2024-43018-Piwigo-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致信息泄露和代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-27  
**POC仓库:** [CVE-2024-43018](https://github.com/joaosilva21/CVE-2024-43018)  

---

### [CVE-2024-27499](CVE-2024-27499-auspicious7_CVE-2024-27499.md) 🟡 ✅

**名称:** CVE-2024-27499 - Bagisto v1.5.1 存储型XSS  
**类型:** 存储型XSS (Cross-Site Scripting)  
**风险:** 中危，可能导致管理员会话劫持、恶意页面跳转等  
**投毒风险:** 0%  
**发现时间:** 2025-07-27  
**POC仓库:** [CVE-2024-27499](https://github.com/auspicious7/CVE-2024-27499)  

---

### [CVE-2022-45299](CVE-2022-45299-offalltn_CVE-2022-45299.md) 🔴 ✅

**名称:** CVE-2022-45299-webbrowser-rs-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感文件泄露甚至任意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-27  
**POC仓库:** [CVE-2022-45299](https://github.com/offalltn/CVE-2022-45299)  

---

### [CVE-2017-5638](CVE-2017-5638-QHxDr-dz_CVE-2017-5638.md) 🔴 ✅

**名称:** CVE-2017-5638 Apache Struts2 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-07-27  
**POC仓库:** [CVE-2017-5638](https://github.com/QHxDr-dz/CVE-2017-5638)  

---

### [CVE-2025-6998](CVE-2025-6998-mind2hex_CVE-2025-6998-CalibreWeb-0.6.24-ReDoS.md) 🔴 ✅

**名称:** CVE-2025-6998-Calibre Web/Autocaliweb-ReDoS  
**类型:** ReDoS（正则表达式拒绝服务）  
**风险:** 高危，可能导致服务拒绝  
**投毒风险:** 10%  
**发现时间:** 2025-07-27  
**POC仓库:** [CVE-2025-6998-CalibreWeb-0.6.24-ReDoS](https://github.com/mind2hex/CVE-2025-6998-CalibreWeb-0.6.24-ReDoS)  

---

### [CVE-2025-7404](CVE-2025-7404-mind2hex_CVE-2025-7404-CalibreWeb-0.6.24-BlindCommandInjection.md) 🟡 

**名称:** CVE-2025-7404 Calibre Web/Autocaliweb 盲注OS命令注入  
**类型:** OS命令注入  
**风险:** 中危，可能导致远程代码执行  
**投毒风险:** 2%  
**发现时间:** 2025-07-27  
**POC仓库:** [CVE-2025-7404-CalibreWeb-0.6.24-BlindCommandInjection](https://github.com/mind2hex/CVE-2025-7404-CalibreWeb-0.6.24-BlindCommandInjection)  

---

### [CVE-2025-54313](CVE-2025-54313-ShinP451_scavenger_scanner.md) 🔴 ✅

**名称:** CVE-2025-54313-eslint-config-prettier-供应链攻击  
**类型:** 供应链攻击/嵌入恶意代码  
**风险:** 高危，可能导致Windows系统执行恶意代码，供应链污染  
**投毒风险:** 10%  
**发现时间:** 2025-07-26  
**POC仓库:** [scavenger_scanner](https://github.com/ShinP451/scavenger_scanner)  

---

### [CVE-2022-44268](CVE-2022-44268-jkobierczynski_cve-2022-44268.md) 🔴 ✅

**名称:** CVE-2022-44268-ImageMagick-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-07-26  
**POC仓库:** [cve-2022-44268](https://github.com/jkobierczynski/cve-2022-44268)  

---

### [CVE-2025-54309](CVE-2025-54309-issamjr_CVE-2025-54309-EXPLOIT.md) 🔴 ✅

**名称:** CVE-2025-54309 - CrushFTP 未经验证的远程命令执行  
**类型:** 远程命令执行 (RCE)  
**风险:** 高危，允许未经身份验证的攻击者获取管理权限并执行任意命令  
**投毒风险:** 10%  
**发现时间:** 2025-07-26  
**POC仓库:** [CVE-2025-54309-EXPLOIT](https://github.com/issamjr/CVE-2025-54309-EXPLOIT)  

---

### [CVE-2025-34138](CVE-2025-34138-allinsthon_CVE-2025-34138.md) 🔴 ✅

**名称:** CVE-2025-34138 Sitecore Experience Platform Unauthenticated RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致完全控制受影响的 Sitecore 实例  
**投毒风险:** 10%  
**发现时间:** 2025-07-26  
**POC仓库:** [CVE-2025-34138](https://github.com/allinsthon/CVE-2025-34138)  

---

### [CVE-2024-7940](CVE-2024-7940-barbaraeivyu_CVE-2024-7940.md) 🔴 

**名称:** CVE-2024-7940 - Hitachi Energy MicroSCADA SYS600 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致完全控制系统  
**投毒风险:** 10%  
**发现时间:** 2025-07-26  
**POC仓库:** [CVE-2024-7940](https://github.com/barbaraeivyu/CVE-2024-7940)  

---

### [CVE-2025-50867](CVE-2025-50867-SacX-7_CVE-2025-50867.md) 🟡 ✅

**名称:** CloudClassroom-PHP-Project-Reflected XSS  
**类型:** Reflected XSS  
**风险:** 中危，可能导致用户凭证泄露或恶意脚本执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-26  
**POC仓库:** [CVE-2025-50867](https://github.com/SacX-7/CVE-2025-50867)  

---

### [CVE-2025-54313](CVE-2025-54313-nihilor_cve-2025-54313.md) 🔴 ✅

**名称:** CVE-2025-54313-eslint-config-prettier-供应链投毒  
**类型:** 供应链投毒  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-26  
**POC仓库:** [cve-2025-54313](https://github.com/nihilor/cve-2025-54313)  

---

### [CVE-2025-53770](CVE-2025-53770-unk9vvn_sharepoint-toolpane.md) 🔴 ✅

**名称:** CVE-2025-53770-Microsoft SharePoint Server-RCE  
**类型:** 远程代码执行  
**风险:** 高危，未经授权的攻击者可以通过网络执行任意代码。  
**投毒风险:** 0%  
**发现时间:** 2025-07-26  
**POC仓库:** [sharepoint-toolpane](https://github.com/unk9vvn/sharepoint-toolpane)  

---

### [CVE-2025-32429](CVE-2025-32429-amir-othman_CVE-2025-32429.md) 🔴 ✅

**名称:** CVE-2025-32429 - XWiki Platform SQL 注入  
**类型:** SQL 注入  
**风险:** 高危，可能导致数据泄露、数据篡改和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-26  
**POC仓库:** [CVE-2025-32429](https://github.com/amir-othman/CVE-2025-32429)  

---

### [CVE-2024-27686](CVE-2024-27686-ThemeHackers_CVE-2024-27686.md) 🟡 ✅

**名称:** CVE-2024-27686 - MikroTik RouterOS SMB DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 中危，可能导致设备不可用  
**投毒风险:** 5%  
**发现时间:** 2025-07-26  
**POC仓库:** [CVE-2024-27686](https://github.com/ThemeHackers/CVE-2024-27686)  

---

### [CVE-2025-53770](CVE-2025-53770-BirdsAreFlyingCameras_CVE-2025-53770_Raw-HTTP-Request-Generator.md) 🔴 ✅

**名称:** CVE-2025-53770 - Microsoft SharePoint Server 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经授权的攻击者通过网络执行代码  
**投毒风险:** 10%  
**发现时间:** 2025-07-25  
**POC仓库:** [CVE-2025-53770_Raw-HTTP-Request-Generator](https://github.com/BirdsAreFlyingCameras/CVE-2025-53770_Raw-HTTP-Request-Generator)  

---

### [CVE-2025-53770](CVE-2025-53770-Kamal-Hegazi_CVE-2025-53770-SharePoint-RCE.md)  ✅

**名称:** CVE-2025-53770 - Microsoft SharePoint Server 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，未经授权的攻击者可以通过网络执行代码。  
**投毒风险:** 10%  
**发现时间:** 2025-07-25  
**POC仓库:** [CVE-2025-53770-SharePoint-RCE](https://github.com/Kamal-Hegazi/CVE-2025-53770-SharePoint-RCE)  

---

### [CVE-2025-52399](CVE-2025-52399-gmh5225_CVE-2025-52399-SQLi-Institute-of-Current-Students.md) 🔴 ✅

**名称:** CVE-2025-52399 - Institute of Current Students - SQL Injection  
**类型:** SQL Injection  
**风险:** 高危，可能导致数据泄露和身份验证绕过  
**投毒风险:** 0%  
**发现时间:** 2025-07-25  
**POC仓库:** [CVE-2025-52399-SQLi-Institute-of-Current-Students](https://github.com/gmh5225/CVE-2025-52399-SQLi-Institute-of-Current-Students)  

---

### [CVE-2025-53770](CVE-2025-53770-0xray5c68616e37_cve-2025-53770.md)  ✅

**名称:** CVE-2025-53770 SharePoint Deserialization RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，未经身份验证的攻击者可以远程执行代码并完全控制系统  
**投毒风险:** 10%  
**发现时间:** 2025-07-25  
**POC仓库:** [cve-2025-53770](https://github.com/0xray5c68616e37/cve-2025-53770)  

---

### [CVE-2025-32429](CVE-2025-32429-byteReaper77_CVE-2025-32429.md) 🔴 ✅

**名称:** CVE-2025-32429-XWiki Platform-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-25  
**POC仓库:** [CVE-2025-32429](https://github.com/byteReaper77/CVE-2025-32429)  

---

### [CVE-2025-54554](CVE-2025-54554-Aman-Parmar_CVE-2025-54554.md) 🟡 ✅

**名称:** CVE-2025-54554 - ticrypt tiaudit 未授权访问导致敏感信息泄露  
**类型:** 信息泄露  
**风险:** 中危，可能泄露SQL查询模式和数据库结构信息  
**投毒风险:** 0%  
**发现时间:** 2025-07-25  
**POC仓库:** [CVE-2025-54554](https://github.com/Aman-Parmar/CVE-2025-54554)  

---

### [CVE-2025-52399](CVE-2025-52399-Userr404_CVE-2025-52399-SQLi-Institute-of-Current-Students.md) 🔴 ✅

**名称:** CVE-2025-52399 - Institute of Current Students - SQL Injection  
**类型:** SQL注入  
**风险:** 高危，可能导致数据库信息泄露和身份验证绕过  
**投毒风险:** 10%  
**发现时间:** 2025-07-25  
**POC仓库:** [CVE-2025-52399-SQLi-Institute-of-Current-Students](https://github.com/Userr404/CVE-2025-52399-SQLi-Institute-of-Current-Students)  

---

### [CVE-2014-6271](CVE-2014-6271-rsherstnev_CVE-2014-6271.md) 🔴 ✅

**名称:** CVE-2014-6271 - ShellShock  
**类型:** 远程命令执行  
**风险:** 高危，可能导致远程命令执行和系统控制  
**投毒风险:** 1%  
**发现时间:** 2025-07-25  
**POC仓库:** [CVE-2014-6271](https://github.com/rsherstnev/CVE-2014-6271)  

---

### [CVE-2014-6271](CVE-2014-6271-knightc0de_Shellshock_vuln_Exploit.md) 🔴 ✅

**名称:** CVE-2014-6271 Shellshock  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行，系统权限获取  
**投毒风险:** 10%  
**发现时间:** 2025-07-25  
**POC仓库:** [Shellshock_vuln_Exploit](https://github.com/knightc0de/Shellshock_vuln_Exploit)  

---

### [CVE-2025-53770](CVE-2025-53770-a-hydrae_ToolShell-Honeypot.md) 🔴 ✅

**名称:** CVE-2025-53770 - Microsoft SharePoint Server 远程代码执行漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-25  
**POC仓库:** [ToolShell-Honeypot](https://github.com/a-hydrae/ToolShell-Honeypot)  

---

### [CVE-2025-53652](CVE-2025-53652-pl4tyz_CVE-2025-53652-Jenkins-Git-Parameter-Analysis.md) 🔴 ✅

**名称:** CVE-2025-53652 - Jenkins Git Parameter Plugin 命令注入漏洞  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-25  
**POC仓库:** [CVE-2025-53652-Jenkins-Git-Parameter-Analysis](https://github.com/pl4tyz/CVE-2025-53652-Jenkins-Git-Parameter-Analysis)  

---

### [CVE-2023-27372](CVE-2023-27372-G01d3nW01f_cve-2023-27372.md) 🔴 ✅

**名称:** CVE-2023-27372 - SPIP Remote Code Execution  
**类型:** Remote Code Execution  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-25  
**POC仓库:** [cve-2023-27372](https://github.com/G01d3nW01f/cve-2023-27372)  

---

### [CVE-2025-52914](CVE-2025-52914-rxerium_CVE-2025-52914.md) 🟡 ✅

**名称:** CVE-2025-52914-MiCollab-版本信息泄露  
**类型:** 信息泄露  
**风险:** 中危，信息泄露可能辅助进一步攻击  
**投毒风险:** 5%  
**发现时间:** 2025-07-25  
**POC仓库:** [CVE-2025-52914](https://github.com/rxerium/CVE-2025-52914)  

---

### [CVE-2025-53770](CVE-2025-53770-Udyz_CVE-2025-53770-Exploit.md) 🔴 ✅

**名称:** CVE-2025-53770-Microsoft SharePoint Server Remote Code Execution Vulnerability  
**类型:** 远程代码执行  
**风险:** 高危，允许未经授权的攻击者通过网络执行代码  
**投毒风险:** 10%  
**发现时间:** 2025-07-25  
**POC仓库:** [CVE-2025-53770-Exploit](https://github.com/Udyz/CVE-2025-53770-Exploit)  

---

### [CVE-2021-44228](CVE-2021-44228-Alan-coder-eng_log4j-cve-2021-44228-.md) 🔴 ✅

**名称:** CVE-2021-44228 - Apache Log4j2 JNDI 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-07-25  
**POC仓库:** [log4j-cve-2021-44228-](https://github.com/Alan-coder-eng/log4j-cve-2021-44228-)  

---

### [CVE-2025-51411](CVE-2025-51411-tansique-17_CVE-2025-51411.md) 🟡 ✅

**名称:** CVE-2025-51411 - Institute-of-Current-Students Reflected XSS  
**类型:** Reflected XSS (Cross-Site Scripting)  
**风险:** 中危，可能导致会话劫持、信息窃取、恶意重定向等  
**投毒风险:** 10%  
**发现时间:** 2025-07-25  
**POC仓库:** [CVE-2025-51411](https://github.com/tansique-17/CVE-2025-51411)  

---

### [CVE-2025-5755](CVE-2025-5755-cyberajju_cve-2025-5755.md) 🔴 ✅

**名称:** CVE-2025-5755 SourceCodester Open Source Clinic Management System email_config.php SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据库信息泄露和未授权访问  
**投毒风险:** 10%  
**发现时间:** 2025-07-25  
**POC仓库:** [cve-2025-5755](https://github.com/cyberajju/cve-2025-5755)  

---

### [CVE-2025-48384](CVE-2025-48384-elprogramadorgt_CVE-2025-48384.md) 🔴 ✅

**名称:** CVE-2025-48384-Git配置注入与任意代码执行  
**类型:** 配置注入/任意代码执行  
**风险:** 高危，可能导致远程代码执行和系统被控制  
**投毒风险:** 0%  
**发现时间:** 2025-07-25  
**POC仓库:** [CVE-2025-48384](https://github.com/elprogramadorgt/CVE-2025-48384)  

---

### [CVE-2024-40586](CVE-2024-40586-Hagrid29_CVE-2024-40586-Windows-Coerced-Authentication-in-FortiClient.md) 🟡 ✅

**名称:** CVE-2024-40586 FortiClient Windows 本地提权漏洞  
**类型:** 权限提升  
**风险:** 中危，本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-07-24  
**POC仓库:** [CVE-2024-40586-Windows-Coerced-Authentication-in-FortiClient](https://github.com/Hagrid29/CVE-2024-40586-Windows-Coerced-Authentication-in-FortiClient)  

---

### [CVE-2025-6018](CVE-2025-6018-ibrahmsql_CVE-2025-6018.md) 🔴 ✅

**名称:** CVE-2025-6018 PAM 本地权限提升漏洞  
**类型:** 本地权限提升 (LPE)  
**风险:** 高危，攻击者可利用此漏洞获得系统完全控制权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-24  
**POC仓库:** [CVE-2025-6018](https://github.com/ibrahmsql/CVE-2025-6018)  

---

### [CVE-2025-31486](CVE-2025-31486-hackmelocal_CVE-2025-31486-Simulation.md) 🟡 ✅

**名称:** CVE-2025-31486-Vite-任意文件读取  
**类型:** 任意文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-07-24  
**POC仓库:** [CVE-2025-31486-Simulation](https://github.com/hackmelocal/CVE-2025-31486-Simulation)  

---

### [CVE-2025-53770](CVE-2025-53770-Rabbitbong_OurSharePoint-CVE-2025-53770.md) 🔴 ✅

**名称:** CVE-2025-53770-SharePoint-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经授权的攻击者可以通过网络执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-07-24  
**POC仓库:** [OurSharePoint-CVE-2025-53770](https://github.com/Rabbitbong/OurSharePoint-CVE-2025-53770)  

---

### [CVE-2024-23346](CVE-2024-23346-DAVIDAROCA27_CVE-2024-23346-exploit.md) 🔴 ✅

**名称:** CVE-2024-23346-pymatgen-代码注入  
**类型:** 代码注入  
**风险:** 高危，可导致任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-24  
**POC仓库:** [CVE-2024-23346-exploit](https://github.com/DAVIDAROCA27/CVE-2024-23346-exploit)  

---

### [CVE-2025-1302](CVE-2025-1302-EQSTLab_CVE-2025-1302.md)  ✅

**名称:** CVE-2025-1302-jsonpath-plus-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可导致服务器完全控制  
**投毒风险:** 20%  
**发现时间:** 2025-07-24  
**POC仓库:** [CVE-2025-1302](https://github.com/EQSTLab/CVE-2025-1302)  

---

### [CVE-2025-1302](CVE-2025-1302-abrewer251_CVE-2025-1302_jsonpath-plus_RCE.md)  ✅

**名称:** CVE-2025-1302 jsonpath-plus RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致完全控制受影响的系统  
**投毒风险:** 10%  
**发现时间:** 2025-07-24  
**POC仓库:** [CVE-2025-1302_jsonpath-plus_RCE](https://github.com/abrewer251/CVE-2025-1302_jsonpath-plus_RCE)  

---

### [CVE-2025-53770](CVE-2025-53770-bharath-cyber-root_sharepoint-toolshell-cve-2025-53770.md) 🔴 ✅

**名称:** CVE-2025-53770-SharePoint-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可完全控制SharePoint服务器并横向渗透  
**投毒风险:** 10%  
**发现时间:** 2025-07-24  
**POC仓库:** [sharepoint-toolshell-cve-2025-53770](https://github.com/bharath-cyber-root/sharepoint-toolshell-cve-2025-53770)  

---

### [CVE-2025-5777](CVE-2025-5777-rob0tstxt_POC-CVE-2025-5777.md) 🔴 ✅

**名称:** CVE-2025-5777-NetScaler ADC/Gateway-内存泄露  
**类型:** 内存泄露  
**风险:** 高危，可能泄露敏感信息  
**投毒风险:** 0%  
**发现时间:** 2025-07-24  
**POC仓库:** [POC-CVE-2025-5777](https://github.com/rob0tstxt/POC-CVE-2025-5777)  

---

### [CVE-2025-31486](CVE-2025-31486-hackmelocal_hackmelocal-CVE-2025-31486-Simulation.md) 🟡 ✅

**名称:** CVE-2025-31486-Vite Arbitrary File Read  
**类型:** 任意文件读取  
**风险:** 中危，可能泄露敏感信息  
**投毒风险:** 10%  
**发现时间:** 2025-07-24  
**POC仓库:** [hackmelocal-CVE-2025-31486-Simulation](https://github.com/hackmelocal/hackmelocal-CVE-2025-31486-Simulation)  

---

### [CVE-2024-12085](CVE-2024-12085-Otsutez_cve-2024-12085.md) 🔴 ✅

**名称:** CVE-2024-12085-rsync-信息泄露  
**类型:** 信息泄露  
**风险:** 高危，可能导致绕过ASLR等安全机制  
**投毒风险:** 1%  
**发现时间:** 2025-07-24  
**POC仓库:** [cve-2024-12085](https://github.com/Otsutez/cve-2024-12085)  

---

### [CVE-2024-23897](CVE-2024-23897-Fineken_Jenkins-CVE-2024-23897-Lab.md) 🔴 ✅

**名称:** CVE-2024-23897-Jenkins-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露，甚至RCE  
**投毒风险:** 0%  
**发现时间:** 2025-07-24  
**POC仓库:** [Jenkins-CVE-2024-23897-Lab](https://github.com/Fineken/Jenkins-CVE-2024-23897-Lab)  

---

### [CVE-2025-53770](CVE-2025-53770-JustinnT_cve-2025-53770-.md) 🔴 ✅

**名称:** CVE-2025-53770-Microsoft SharePoint Server 远程代码执行漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，允许未经授权的攻击者通过网络执行代码  
**投毒风险:** 10%  
**发现时间:** 2025-07-24  
**POC仓库:** [cve-2025-53770-](https://github.com/JustinnT/cve-2025-53770-)  

---

### [CVE-2025-53770](CVE-2025-53770-nisargsuthar_suricata-rule-CVE-2025-53770.md) 🔴 ✅

**名称:** CVE-2025-53770-Microsoft SharePoint Server-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未经授权的攻击者通过网络执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-07-24  
**POC仓库:** [suricata-rule-CVE-2025-53770](https://github.com/nisargsuthar/suricata-rule-CVE-2025-53770)  

---

### [CVE-2025-6558](CVE-2025-6558-DevBuiHieu_CVE-2025-6558-Proof-Of-Concept.md) 🔴 ✅

**名称:** CVE-2025-6558 - Google Chrome ANGLE and GPU Improper Input Validation Vulnerability  
**类型:** 沙箱逃逸  
**风险:** 高危，可能导致沙箱逃逸和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-24  
**POC仓库:** [CVE-2025-6558-Proof-Of-Concept](https://github.com/DevBuiHieu/CVE-2025-6558-Proof-Of-Concept)  

---

### [CVE-2025-53770](CVE-2025-53770-zach115th_ToolShellFinder.md) 🔴 ✅

**名称:** CVE-2025-53770 - Microsoft SharePoint Server 远程代码执行漏洞  
**类型:** 反序列化  
**风险:** 高危，允许未经授权的攻击者通过网络执行代码  
**投毒风险:** 10%  
**发现时间:** 2025-07-24  
**POC仓库:** [ToolShellFinder](https://github.com/zach115th/ToolShellFinder)  

---

### [CVE-2018-11714](CVE-2018-11714-mikelkarma_cve-2018-11714_POC.md) 🔴 ✅

**名称:** CVE-2018-11714 - TP-Link TL-WR840N/TL-WR841N 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致完全控制路由器  
**投毒风险:** 5%  
**发现时间:** 2025-07-23  
**POC仓库:** [cve-2018-11714_POC](https://github.com/mikelkarma/cve-2018-11714_POC)  

---

### [CVE-2025-53770](CVE-2025-53770-exfil0_CVE-2025-53770.md) 🔴 ✅

**名称:** CVE-2025-53770 Microsoft SharePoint Server 远程代码执行漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-23  
**POC仓库:** [CVE-2025-53770](https://github.com/exfil0/CVE-2025-53770)  

---

### [CVE-2024-52794](CVE-2024-52794-Beesco00_CVE-2024-52794-Discourse-Stored-XSS.md) 🟡 ✅

**名称:** CVE-2024-52794-Discourse-Stored-XSS  
**类型:** Stored XSS  
**风险:** 中危，可能导致账户劫持和恶意脚本执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-23  
**POC仓库:** [CVE-2024-52794-Discourse-Stored-XSS](https://github.com/Beesco00/CVE-2024-52794-Discourse-Stored-XSS)  

---

### [CVE-2024-38063](CVE-2024-38063-Skac44_CVE-2024-38063.md) 🔴 ✅

**名称:** CVE-2024-38063 - Windows TCP/IP远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，攻击者可以远程执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-07-23  
**POC仓库:** [CVE-2024-38063](https://github.com/Skac44/CVE-2024-38063)  

---

### [CVE-2025-7766](CVE-2025-7766-byteReaper77_CVE-2025-7766.md) 🔴 ✅

**名称:** CVE-2025-7766-Lantronix Provisioning Manager-XXE  
**类型:** XML 外部实体注入 (XXE)  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-23  
**POC仓库:** [CVE-2025-7766](https://github.com/byteReaper77/CVE-2025-7766)  

---

### [CVE-2017-12637](CVE-2017-12637-abrewer251_CVE-2017-12637_SAP-NetWeaver-URL-Traversal.md) 🔴 ✅

**名称:** CVE-2017-12637 SAP NetWeaver 目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-07-23  
**POC仓库:** [CVE-2017-12637_SAP-NetWeaver-URL-Traversal](https://github.com/abrewer251/CVE-2017-12637_SAP-NetWeaver-URL-Traversal)  

---

### [CVE-2025-53770](CVE-2025-53770-Kamal-Hegazi_CVE-2025-53770-SharePoint-RCE.md)  ✅

**名称:** CVE-2025-53770 - Microsoft SharePoint Server 远程代码执行漏洞  
**类型:** 反序列化  
**风险:** 严重，未经身份验证的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-23  
**POC仓库:** [CVE-2025-53770-SharePoint-RCE](https://github.com/Kamal-Hegazi/CVE-2025-53770-SharePoint-RCE)  

---

### [CVE-2025-29927](CVE-2025-29927-mickhacking_Thank-u-Next.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-中间件授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问敏感数据和功能  
**投毒风险:** 0%  
**发现时间:** 2025-07-23  
**POC仓库:** [Thank-u-Next](https://github.com/mickhacking/Thank-u-Next)  

---

### [CVE-2025-29927](CVE-2025-29927-Kamal-Hegazi_Next.js-Middleware-Exploit-CVE-2025-29927-Authorization-Bypass.md) 🔴 ✅

**名称:** CVE-2025-29927 - Next.js Middleware 授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问、权限提升和数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-07-23  
**POC仓库:** [Next.js-Middleware-Exploit-CVE-2025-29927-Authorization-Bypass](https://github.com/Kamal-Hegazi/Next.js-Middleware-Exploit-CVE-2025-29927-Authorization-Bypass)  

---

### [CVE-2024-10858](CVE-2024-10858-iamarit_CVE-2024-10858.md) 🟡 ✅

**名称:** CVE-2024-10858 - Jetpack DOM-XSS  
**类型:** DOM-XSS  
**风险:** 中危，可能允许未经身份验证的攻击者在WordPress.com托管的站点上执行任意JavaScript代码  
**投毒风险:** 10%  
**发现时间:** 2025-07-23  
**POC仓库:** [CVE-2024-10858](https://github.com/iamarit/CVE-2024-10858)  

---

### [CVE-2025-50777](CVE-2025-50777-veereshgadige_aziot-cctv-cve-2025-50777.md) 🔴 ✅

**名称:** CVE-2025-50777 - AZIOT Smart CCTV 凭据泄露和Root权限  
**类型:** 信息泄露/权限提升  
**风险:** 高危，可能导致设备完全控制和敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-07-23  
**POC仓库:** [aziot-cctv-cve-2025-50777](https://github.com/veereshgadige/aziot-cctv-cve-2025-50777)  

---

### [CVE-2025-53770](CVE-2025-53770-m4r1x_CVE-2025-53770-Scanner.md) 🔴 ✅

**名称:** CVE-2025-53770-SharePoint-反序列化RCE  
**类型:** 反序列化RCE  
**风险:** 高危，允许未经授权的攻击者通过网络执行代码  
**投毒风险:** 30%  
**发现时间:** 2025-07-23  
**POC仓库:** [CVE-2025-53770-Scanner](https://github.com/m4r1x/CVE-2025-53770-Scanner)  

---

### [CVE-2025-30397](CVE-2025-30397-B1ack4sh_Blackash-CVE-2025-30397.md) 🔴 ✅

**名称:** CVE-2025-30397-Microsoft Scripting Engine-类型混淆  
**类型:** 类型混淆  
**风险:** 高危，允许远程攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-07-23  
**POC仓库:** [Blackash-CVE-2025-30397](https://github.com/B1ack4sh/Blackash-CVE-2025-30397)  

---

### [CVE-2024-6387](CVE-2024-6387-xiw1ll_CVE-2024-6387_Checker.md) 🔴 

**名称:** CVE-2024-6387 OpenSSH regreSSHion 漏洞检测  
**类型:** 远程代码执行/拒绝服务  
**风险:** 高危，可能导致远程代码执行或拒绝服务攻击  
**投毒风险:** 5%  
**发现时间:** 2025-07-23  
**POC仓库:** [CVE-2024-6387_Checker](https://github.com/xiw1ll/CVE-2024-6387_Checker)  

---

### [CVE-2025-8018](CVE-2025-8018-drackyjr_CVE-2025-8018.md) 🔴 ✅

**名称:** CVE-2025-8018-code-projects-Food-Ordering-Review-System-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、数据篡改和服务器控制  
**投毒风险:** 0%  
**发现时间:** 2025-07-23  
**POC仓库:** [CVE-2025-8018](https://github.com/drackyjr/CVE-2025-8018)  

---

### [CVE-2025-32756](CVE-2025-32756-shan0ar_cve-2025-32756.md) 🔴 ✅

**名称:** CVE-2025-32756-Fortinet-Stack-Based Buffer Overflow  
**类型:** 栈溢出  
**风险:** 高危，未授权远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-07-23  
**POC仓库:** [cve-2025-32756](https://github.com/shan0ar/cve-2025-32756)  

---

### [CVE-2025-53770](CVE-2025-53770-Hassanopop_CVE-2025-53770.md) 🔴 ✅

**名称:** CVE-2025-53770: Microsoft SharePoint Server 远程代码执行漏洞  
**类型:** 反序列化漏洞导致远程代码执行  
**风险:** 高危，未经授权的攻击者可以通过网络执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-07-23  
**POC仓库:** [CVE-2025-53770](https://github.com/Hassanopop/CVE-2025-53770)  

---

### [CVE-2025-5777](CVE-2025-5777-Shivshantp_CVE-2025-5777-TrendMicro-ApexCentral-RCE.md) 🔴 ✅

**名称:** CVE-2025-5777-NetScaler ADC and NetScaler Gateway - 内存越界读取  
**类型:** 内存越界读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-07-23  
**POC仓库:** [CVE-2025-5777-TrendMicro-ApexCentral-RCE](https://github.com/Shivshantp/CVE-2025-5777-TrendMicro-ApexCentral-RCE)  

---

### [CVE-2025-7461](CVE-2025-7461-bx33661_CVE-2025-7461.md) 🔴 ✅

**名称:** CVE-2025-7461-ModernBag-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-23  
**POC仓库:** [CVE-2025-7461](https://github.com/bx33661/CVE-2025-7461)  

---

### [CVE-2023-2598](CVE-2023-2598-ysanatomic_io_uring_LPE-CVE-2023-2598.md) 🔴 ✅

**名称:** CVE-2023-2598-Linux内核io_uring本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可以提升到root权限  
**投毒风险:** 5%  
**发现时间:** 2025-07-23  
**POC仓库:** [io_uring_LPE-CVE-2023-2598](https://github.com/ysanatomic/io_uring_LPE-CVE-2023-2598)  

---

### [CVE-2023-2598](CVE-2023-2598-cainiao159357_CVE-2023-2598.md) 🔴 ✅

**名称:** CVE-2023-2598-Linux Kernel io_uring Out-of-Bounds Access  
**类型:** Out-of-Bounds Write/Read  
**风险:** 高危，本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-07-23  
**POC仓库:** [CVE-2023-2598](https://github.com/cainiao159357/CVE-2023-2598)  

---

### [CVE-2023-2598](CVE-2023-2598-LLfam_CVE-2023-2598.md) 🔴 ✅

**名称:** CVE-2023-2598 - Linux Kernel io_uring Out-of-bounds Access  
**类型:** 权限提升  
**风险:** 高危，本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-07-23  
**POC仓库:** [CVE-2023-2598](https://github.com/LLfam/CVE-2023-2598)  

---

### [CVE-2023-2598](CVE-2023-2598-SpongeBob-369_CVE-2023-2598.md) 🔴 ✅

**名称:** CVE-2023-2598 - Linux Kernel io_uring 本地提权漏洞  
**类型:** 内存越界写入/本地提权  
**风险:** 高危，可导致本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-07-23  
**POC仓库:** [CVE-2023-2598](https://github.com/SpongeBob-369/CVE-2023-2598)  

---

### [CVE-2024-4947](CVE-2024-4947-DiabloX90911_CVE-2024-4947.md) 🔴 ✅

**名称:** CVE-2024-4947 - Google Chrome V8 类型混淆漏洞  
**类型:** 类型混淆  
**风险:** 高危，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-23  
**POC仓库:** [CVE-2024-4947](https://github.com/DiabloX90911/CVE-2024-4947)  

---

### [CVE-2019-13272](CVE-2019-13272-jas502n_CVE-2019-13272.md) 🔴 ✅

**名称:** CVE-2019-13272 - Linux Kernel PTRACE_TRACEME 本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，允许本地用户获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-23  
**POC仓库:** [CVE-2019-13272](https://github.com/jas502n/CVE-2019-13272)  

---

### [CVE-2019-13272](CVE-2019-13272-Cyc1eC_CVE-2019-13272.md) 🔴 ✅

**名称:** CVE-2019-13272-Linux Kernel PTRACE_TRACEME 本地提权  
**类型:** 本地提权  
**风险:** 高危，允许本地用户获得root权限  
**投毒风险:** 1%  
**发现时间:** 2025-07-23  
**POC仓库:** [CVE-2019-13272](https://github.com/Cyc1eC/CVE-2019-13272)  

---

### [CVE-2019-13272](CVE-2019-13272-oneoy_CVE-2019-13272.md) 🔴 ✅

**名称:** CVE-2019-13272 - Linux Kernel PTRACE_TRACEME Local Root  
**类型:** 权限提升  
**风险:** 高危，本地用户可获取root权限  
**投毒风险:** 1%  
**发现时间:** 2025-07-23  
**POC仓库:** [CVE-2019-13272](https://github.com/oneoy/CVE-2019-13272)  

---

### [CVE-2019-13272](CVE-2019-13272-polosec_CVE-2019-13272.md) 🔴 ✅

**名称:** CVE-2019-13272 Linux Kernel PTRACE_TRACEME 本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，允许本地用户获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-23  
**POC仓库:** [CVE-2019-13272](https://github.com/polosec/CVE-2019-13272)  

---

### [CVE-2019-13272](CVE-2019-13272-sumedhaDharmasena_-Kernel-ptrace-c-mishandles-vulnerability-CVE-2019-13272.md) 🔴 ✅

**名称:** CVE-2019-13272-Linux Kernel PTRACE_TRACEME Privilege Escalation  
**类型:** 权限提升  
**风险:** 高危，本地用户可获取root权限  
**投毒风险:** 0%  
**发现时间:** 2025-07-23  
**POC仓库:** [-Kernel-ptrace-c-mishandles-vulnerability-CVE-2019-13272](https://github.com/sumedhaDharmasena/-Kernel-ptrace-c-mishandles-vulnerability-CVE-2019-13272)  

---

### [CVE-2019-13272](CVE-2019-13272-Tharana_Exploiting-a-Linux-kernel-vulnerability.md) 🔴 ✅

**名称:** CVE-2019-13272 - Linux Kernel ptrace_link 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，本地用户可以获取root权限  
**投毒风险:** 20%  
**发现时间:** 2025-07-23  
**POC仓库:** [Exploiting-a-Linux-kernel-vulnerability](https://github.com/Tharana/Exploiting-a-Linux-kernel-vulnerability)  

---

### [CVE-2019-13272](CVE-2019-13272-RashmikaEkanayake_Privilege-Escalation-CVE-2019-13272-.md) 🔴 ✅

**名称:** CVE-2019-13272 Linux Kernel PTRACE_TRACEME 本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，本地用户可获取 root 权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-23  
**POC仓库:** [Privilege-Escalation-CVE-2019-13272-](https://github.com/RashmikaEkanayake/Privilege-Escalation-CVE-2019-13272-)  

---

### [CVE-2019-13272](CVE-2019-13272-Tharana_vulnerability-exploitation.md) 🔴 ✅

**名称:** CVE-2019-13272 - Linux Kernel PTRACE_TRACEME 本地提权  
**类型:** 本地提权  
**风险:** 高危，允许本地用户获取 root 权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-23  
**POC仓库:** [vulnerability-exploitation](https://github.com/Tharana/vulnerability-exploitation)  

---

### [CVE-2019-13272](CVE-2019-13272-datntsec_CVE-2019-13272.md) 🔴 ✅

**名称:** CVE-2019-13272-Linux Kernel PTRACE_TRACEME 本地提权  
**类型:** 本地提权  
**风险:** 高危，允许本地用户获得 root 权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-23  
**POC仓库:** [CVE-2019-13272](https://github.com/datntsec/CVE-2019-13272)  

---

### [CVE-2019-13272](CVE-2019-13272-babyshen_CVE-2019-13272.md) 🔴 ✅

**名称:** CVE-2019-13272 Linux Kernel PTRACE_TRACEME 本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，可导致本地用户获取root权限  
**投毒风险:** 1%  
**发现时间:** 2025-07-23  
**POC仓库:** [CVE-2019-13272](https://github.com/babyshen/CVE-2019-13272)  

---

### [CVE-2019-13272](CVE-2019-13272-GgKendall_secureCodingDemo.md) 🔴 ✅

**名称:** CVE-2019-13272 - Linux Kernel Improper Privilege Management  
**类型:** 权限提升  
**风险:** 高危，允许本地用户获取 root 权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-23  
**POC仓库:** [secureCodingDemo](https://github.com/GgKendall/secureCodingDemo)  

---

### [CVE-2019-13272](CVE-2019-13272-asepsaepdin_CVE-2019-13272.md) 🔴 ✅

**名称:** CVE-2019-13272 - Linux Kernel PTRACE_TRACEME 本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，允许本地用户获取 root 权限  
**投毒风险:** 5%  
**发现时间:** 2025-07-23  
**POC仓库:** [CVE-2019-13272](https://github.com/asepsaepdin/CVE-2019-13272)  

---

### [CVE-2019-13272](CVE-2019-13272-MDS1GNAL_ptrace_scope-CVE-2019-13272-privilege-escalation.md) 🔴 ✅

**名称:** CVE-2019-13272-Linux Kernel PTRACE_TRACEME权限提升  
**类型:** 权限提升  
**风险:** 高危，允许本地用户获得root权限  
**投毒风险:** 5%  
**发现时间:** 2025-07-23  
**POC仓库:** [ptrace_scope-CVE-2019-13272-privilege-escalation](https://github.com/MDS1GNAL/ptrace_scope-CVE-2019-13272-privilege-escalation)  

---

### [CVE-2019-13272](CVE-2019-13272-josemlwdf_CVE-2019-13272.md) 🔴 ✅

**名称:** CVE-2019-13272-Linux Kernel PTRACE_TRACEME 本地提权  
**类型:** 本地提权  
**风险:** 高危，允许低权限本地用户获得root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-23  
**POC仓库:** [CVE-2019-13272](https://github.com/josemlwdf/CVE-2019-13272)  

---

### [CVE-2025-53770](CVE-2025-53770-b33b0y_CVE-2025-53770.md)  ✅

**名称:** CVE-2025-53770 - Microsoft SharePoint Server 远程代码执行漏洞  
**类型:** 反序列化漏洞  
**风险:** 严重，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-23  
**POC仓库:** [CVE-2025-53770](https://github.com/b33b0y/CVE-2025-53770)  

---

### [CVE-2024-45195](CVE-2024-45195-wyyazjjl_CVE-2024-45195.md) 🔴 ✅

**名称:** CVE-2024-45195-Apache OFBiz-强制浏览/远程代码执行  
**类型:** 强制浏览/远程代码执行  
**风险:** 高危，可能导致信息泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-23  
**POC仓库:** [CVE-2024-45195](https://github.com/wyyazjjl/CVE-2024-45195)  

---

### [CVE-2025-53770](CVE-2025-53770-Lapesha_CVE-2025-53770.md) 🔴 ✅

**名称:** CVE-2025-53770-Microsoft SharePoint Server Remote Code Execution Vulnerability  
**类型:** 反序列化漏洞导致远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-23  
**POC仓库:** [CVE-2025-53770](https://github.com/Lapesha/CVE-2025-53770)  

---

### [CVE-2015-10137](CVE-2015-10137-Kai-One001_-CVE-2015-10137-WordPress-N-Media-Website-Contact-Form-with-File-Upload-1.3.4.md) 🔴 ✅

**名称:** CVE-2015-10137-WordPress-N-Media-Website-Contact-Form-with-File-Upload-1.3.4  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-23  
**POC仓库:** [-CVE-2015-10137-WordPress-N-Media-Website-Contact-Form-with-File-Upload-1.3.4](https://github.com/Kai-One001/-CVE-2015-10137-WordPress-N-Media-Website-Contact-Form-with-File-Upload-1.3.4)  

---

### [CVE-2025-6058](CVE-2025-6058-0xgh057r3c0n_CVE-2025-6058.md) 🔴 ✅

**名称:** CVE-2025-6058-WPBookit-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-23  
**POC仓库:** [CVE-2025-6058](https://github.com/0xgh057r3c0n/CVE-2025-6058)  

---

### [CVE-2025-53770](CVE-2025-53770-bijikutu_CVE-2025-53770-Exploit.md) 🔴 ✅

**名称:** CVE-2025-53770: Microsoft SharePoint Server 远程代码执行漏洞  
**类型:** 反序列化漏洞导致的远程代码执行  
**风险:** 高危，允许未经授权的攻击者在网络上执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-07-23  
**POC仓库:** [CVE-2025-53770-Exploit](https://github.com/bijikutu/CVE-2025-53770-Exploit)  

---

### [CVE-2024-4577](CVE-2024-4577-CirqueiraDev_MassExploit-CVE-2024-4577.md) 🔴 ✅

**名称:** CVE-2024-4577 PHP-CGI 参数注入  
**类型:** 参数注入/远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-23  
**POC仓库:** [MassExploit-CVE-2024-4577](https://github.com/CirqueiraDev/MassExploit-CVE-2024-4577)  

---

### [CVE-2025-53770](CVE-2025-53770-MuhammadWaseem29_CVE-2025-53770.md)  ✅

**名称:** CVE-2025-53770 Microsoft SharePoint Server 远程代码执行漏洞  
**类型:** 反序列化漏洞导致远程代码执行  
**风险:** 严重，未授权的攻击者可以通过网络执行代码，完全控制系统  
**投毒风险:** 10%  
**发现时间:** 2025-07-22  
**POC仓库:** [CVE-2025-53770](https://github.com/MuhammadWaseem29/CVE-2025-53770)  

---

### [CVE-2025-53770](CVE-2025-53770-Sec-Dan_CVE-2025-53770-Scanner.md) 🔴 ✅

**名称:** CVE-2025-53770 Microsoft SharePoint Server 远程代码执行漏洞  
**类型:** 反序列化漏洞导致的远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-22  
**POC仓库:** [CVE-2025-53770-Scanner](https://github.com/Sec-Dan/CVE-2025-53770-Scanner)  

---

### [CVE-2022-26671](CVE-2022-26671-DefensiveOrigins_POC-CVE-2022-26671.md) 🔴 ✅

**名称:** CVE-2022-26671 - TAIWAN SECOM CO., LTD. Personnel Attendance Management system 硬编码凭据漏洞  
**类型:** 硬编码凭据  
**风险:** 高危，可能导致信息泄露、服务中断和权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-07-22  
**POC仓库:** [POC-CVE-2022-26671](https://github.com/DefensiveOrigins/POC-CVE-2022-26671)  

---

### [CVE-2018-1207](CVE-2018-1207-mgargiullo_cve-2018-1207.md) 🔴 ✅

**名称:** CVE-2018-1207-Dell iDRAC7/iDRAC8 CGI 注入  
**类型:** CGI 注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-22  
**POC仓库:** [cve-2018-1207](https://github.com/mgargiullo/cve-2018-1207)  

---

### [CVE-2018-1207](CVE-2018-1207-SYNKTeam_CVE-2018-1207.md) 🔴 ✅

**名称:** CVE-2018-1207 Dell iDRAC7/iDRAC8 远程代码执行  
**类型:** CGI注入  
**风险:** 高危，可完全控制系统  
**投毒风险:** 5%  
**发现时间:** 2025-07-22  
**POC仓库:** [CVE-2018-1207](https://github.com/SYNKTeam/CVE-2018-1207)  

---

### [CVE-2025-49144](CVE-2025-49144-0xCZR1_cve-2025-49144.md) 🔴 ✅

**名称:** CVE-2025-49144-Notepad++-权限提升  
**类型:** 权限提升  
**风险:** 高危，可导致SYSTEM权限获取  
**投毒风险:** 10%  
**发现时间:** 2025-07-22  
**POC仓库:** [cve-2025-49144](https://github.com/0xCZR1/cve-2025-49144)  

---

### [CVE-2025-6082](CVE-2025-6082-byteReaper77_CVE-2025-6082.md) 🟡 ✅

**名称:** CVE-2025-6082 - WordPress Birth Chart Compatibility Plugin Full Path Disclosure  
**类型:** Full Path Disclosure  
**风险:** 中危，可辅助其他攻击  
**投毒风险:** 5%  
**发现时间:** 2025-07-22  
**POC仓库:** [CVE-2025-6082](https://github.com/byteReaper77/CVE-2025-6082)  

---

### [CVE-2025-34085](CVE-2025-34085-B1ack4sh_Blackash-CVE-2025-34085.md) 🔴 ✅

**名称:** CVE-2025-34085-Simple File List WordPress Plugin RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未授权的远程攻击者执行任意代码，完全控制WordPress站点。  
**投毒风险:** 10%  
**发现时间:** 2025-07-22  
**POC仓库:** [Blackash-CVE-2025-34085](https://github.com/B1ack4sh/Blackash-CVE-2025-34085)  

---

### [CVE-2023-51385](CVE-2023-51385-runooovb_CVE-2023-51385test.md) 🔴 

**名称:** CVE-2023-51385-OpenSSH-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-22  
**POC仓库:** [CVE-2023-51385test](https://github.com/runooovb/CVE-2023-51385test)  

---

### [CVE-2023-28771](CVE-2023-28771-benjaminhays_CVE-2023-28771-PoC.md) 🔴 ✅

**名称:** CVE-2023-28771-Zyxel防火墙远程命令注入  
**类型:** 远程命令注入 (RCE)  
**风险:** 高危，可导致完全系统控制  
**投毒风险:** 0%  
**发现时间:** 2025-07-22  
**POC仓库:** [CVE-2023-28771-PoC](https://github.com/benjaminhays/CVE-2023-28771-PoC)  

---

### [CVE-2023-28771](CVE-2023-28771-JinParkmida_cve-2023-28771-demo.md)  ✅

**名称:** CVE-2023-28771 - Zyxel防火墙远程命令注入  
**类型:** 远程命令注入  
**风险:** 严重，未经身份验证的攻击者可执行任意OS命令  
**投毒风险:** 10%  
**发现时间:** 2025-07-22  
**POC仓库:** [cve-2023-28771-demo](https://github.com/JinParkmida/cve-2023-28771-demo)  

---

### [CVE-2025-53770](CVE-2025-53770-imbas007_CVE-2025-53770-Vulnerable-Scanner.md) 🔴 ✅

**名称:** CVE-2025-53770 - Microsoft SharePoint Server 远程代码执行漏洞  
**类型:** 反序列化漏洞导致远程代码执行  
**风险:** 高危，未经授权的攻击者可以通过网络执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-07-22  
**POC仓库:** [CVE-2025-53770-Vulnerable-Scanner](https://github.com/imbas007/CVE-2025-53770-Vulnerable-Scanner)  

---

### [CVE-2024-39930](CVE-2024-39930-alexander47777_-CVE-2024-39930.md)  ✅

**名称:** CVE-2024-39930-Gogs-SSH参数注入导致RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致完全控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-07-22  
**POC仓库:** [-CVE-2024-39930](https://github.com/alexander47777/-CVE-2024-39930)  

---

### [CVE-2025-6965](CVE-2025-6965-mariaecgzv_CVE-2025-6965-.md) 🔴 

**名称:** CVE-2025-6965-SQLite-内存损坏  
**类型:** 内存损坏  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 99%  
**发现时间:** 2025-07-22  
**POC仓库:** [CVE-2025-6965-](https://github.com/mariaecgzv/CVE-2025-6965-)  

---

### [CVE-2025-2825](CVE-2025-2825-ghostsec420_ShatteredFTP.md)  ✅

**名称:** CVE-2025-2825 CrushFTP Authentication Bypass  
**类型:** 身份认证绕过  
**风险:** 严重，可能导致未授权访问、数据泄露、以及执行任意管理操作  
**投毒风险:** 0%  
**发现时间:** 2025-07-22  
**POC仓库:** [ShatteredFTP](https://github.com/ghostsec420/ShatteredFTP)  

---

### [CVE-2025-2825](CVE-2025-2825-Shivshantp_CVE-2025-2825-CrushFTP-AuthBypass.md) 🔴 ✅

**名称:** CVE-2025-2825 - CrushFTP 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未经授权的访问和数据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-07-22  
**POC仓库:** [CVE-2025-2825-CrushFTP-AuthBypass](https://github.com/Shivshantp/CVE-2025-2825-CrushFTP-AuthBypass)  

---

### [CVE-2025-53770](CVE-2025-53770-GreenForceNetwork_Toolshell_CVE-2025-53770.md) 🔴 ✅

**名称:** CVE-2025-53770 Microsoft SharePoint Server Remote Code Execution Vulnerability  
**类型:** 反序列化漏洞导致远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者通过网络执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-07-22  
**POC仓库:** [Toolshell_CVE-2025-53770](https://github.com/GreenForceNetwork/Toolshell_CVE-2025-53770)  

---

### [CVE-2021-43798](CVE-2021-43798-hxlxmj_Grafxploit.md) 🔴 ✅

**名称:** CVE-2021-43798-Grafana-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-07-22  
**POC仓库:** [Grafxploit](https://github.com/hxlxmj/Grafxploit)  

---

### [CVE-2023-3460](CVE-2023-3460-GURJOTEXPERT_CVE-2023-3460.md) 🔴 ✅

**名称:** CVE-2023-3460 - Ultimate Member 未授权提权  
**类型:** 权限提升  
**风险:** 高危，允许未授权用户创建管理员账户  
**投毒风险:** 10%  
**发现时间:** 2025-07-22  
**POC仓库:** [CVE-2023-3460](https://github.com/GURJOTEXPERT/CVE-2023-3460)  

---

### [CVE-2025-53770](CVE-2025-53770-AdityaBhatt3010_CVE-2025-53770-SharePoint-Zero-Day-Variant-Exploited-for-Full-RCE.md)  ✅

**名称:** CVE-2025-53770 - Microsoft SharePoint Server 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，未经身份验证的攻击者可以执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-07-22  
**POC仓库:** [CVE-2025-53770-SharePoint-Zero-Day-Variant-Exploited-for-Full-RCE](https://github.com/AdityaBhatt3010/CVE-2025-53770-SharePoint-Zero-Day-Variant-Exploited-for-Full-RCE)  

---

### [CVE-2024-3552](CVE-2024-3552-truonghuuphuc_CVE-2024-3552-Poc.md) 🔴 ✅

**名称:** CVE-2024-3552-Web Directory Free-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、数据篡改和服务器控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-22  
**POC仓库:** [CVE-2024-3552-Poc](https://github.com/truonghuuphuc/CVE-2024-3552-Poc)  

---

### [CVE-2024-3552](CVE-2024-3552-KiPhuong_cve-2024-3552.md) 🔴 ✅

**名称:** CVE-2024-3552-Web Directory Free-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-22  
**POC仓库:** [cve-2024-3552](https://github.com/KiPhuong/cve-2024-3552)  

---

### [CVE-2025-32463](CVE-2025-32463-ChetanKomal_sudo_exploit.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，允许本地用户获取root权限  
**投毒风险:** 0%  
**发现时间:** 2025-07-22  
**POC仓库:** [sudo_exploit](https://github.com/ChetanKomal/sudo_exploit)  

---

### [CVE-2025-34085](CVE-2025-34085-yukinime_CVE-2025-34085.md) 🔴 ✅

**名称:** CVE-2025-34085-Simple File List Plugin-RCE  
**类型:** 远程代码执行  
**风险:** 高危，未授权的远程攻击者可以执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-07-22  
**POC仓库:** [CVE-2025-34085](https://github.com/yukinime/CVE-2025-34085)  

---

### [CVE-2022-1386](CVE-2022-1386-im-hanzou_fubucker.md) 🔴 ✅

**名称:** CVE-2022-1386 - Fusion Builder Unauthenticated SSRF  
**类型:** Server-Side Request Forgery (SSRF)  
**风险:** 高危，可能允许未授权的攻击者扫描内网，访问内部服务，绕过防火墙和访问控制。  
**投毒风险:** 10%  
**发现时间:** 2025-07-22  
**POC仓库:** [fubucker](https://github.com/im-hanzou/fubucker)  

---

### [CVE-2022-1386](CVE-2022-1386-ardzz_CVE-2022-1386.md) 🔴 ✅

**名称:** CVE-2022-1386 - Fusion Builder Unauthenticated SSRF  
**类型:** Server-Side Request Forgery (SSRF)  
**风险:** 高危，可能导致内部网络信息泄露、内部服务攻击、绕过防火墙等  
**投毒风险:** 5%  
**发现时间:** 2025-07-22  
**POC仓库:** [CVE-2022-1386](https://github.com/ardzz/CVE-2022-1386)  

---

### [CVE-2022-1386](CVE-2022-1386-zycoder0day_CVE-2022-1386-Mass_Vulnerability.md) 🔴 ✅

**名称:** CVE-2022-1386 - Fusion Builder SSRF  
**类型:** 服务器端请求伪造 (SSRF)  
**风险:** 高危，可能导致敏感信息泄露、内网扫描、绕过防火墙访问内部服务。  
**投毒风险:** 20%  
**发现时间:** 2025-07-22  
**POC仓库:** [CVE-2022-1386-Mass_Vulnerability](https://github.com/zycoder0day/CVE-2022-1386-Mass_Vulnerability)  

---

### [CVE-2022-1386](CVE-2022-1386-satyasai1460_CVE-2022-1386.md) 🔴 ✅

**名称:** CVE-2022-1386 - Fusion Builder SSRF  
**类型:** SSRF (服务器端请求伪造)  
**风险:** 高危，可能导致内网信息泄露、端口扫描、甚至远程代码执行（如果内网存在未授权的服务）  
**投毒风险:** 10%  
**发现时间:** 2025-07-22  
**POC仓库:** [CVE-2022-1386](https://github.com/satyasai1460/CVE-2022-1386)  

---

### [CVE-2022-1386](CVE-2022-1386-cur1y-dev_CVE-2022-1386.md) 🔴 ✅

**名称:** CVE-2022-1386-Fusion Builder-SSRF  
**类型:** SSRF(服务器端请求伪造)  
**风险:** 高危，可能导致内部网络信息泄露，访问内部服务  
**投毒风险:** 0%  
**发现时间:** 2025-07-22  
**POC仓库:** [CVE-2022-1386](https://github.com/cur1y-dev/CVE-2022-1386)  

---

### [CVE-2022-1386](CVE-2022-1386-fayassgit_CVE-2022-1386-FusionBuilder-SSRF.md) 🔴 ✅

**名称:** CVE-2022-1386 – Fusion Builder < 3.6.2 - Unauthenticated SSRF  
**类型:** Server-Side Request Forgery (SSRF)  
**风险:** 高危，可能导致内网信息泄露、内网服务攻击，绕过防火墙等。  
**投毒风险:** 0%  
**发现时间:** 2025-07-22  
**POC仓库:** [CVE-2022-1386-FusionBuilder-SSRF](https://github.com/fayassgit/CVE-2022-1386-FusionBuilder-SSRF)  

---

### [CVE-2024-6387](CVE-2024-6387-Lost-Ryder_CVE-2024-6387-OpenSSH-ProxyCommand-RC.md) 🔴 ✅

**名称:** CVE-2024-6387-OpenSSH-RegreSSHion-RCE/DoS  
**类型:** 远程代码执行/拒绝服务  
**风险:** 高危，可能导致远程代码执行并获取 root 权限或造成拒绝服务  
**投毒风险:** 5%  
**发现时间:** 2025-07-22  
**POC仓库:** [CVE-2024-6387-OpenSSH-ProxyCommand-RC](https://github.com/Lost-Ryder/CVE-2024-6387-OpenSSH-ProxyCommand-RC)  

---

### [CVE-2025-53770](CVE-2025-53770-tripoloski1337_CVE-2025-53770-scanner.md) 🔴 ✅

**名称:** CVE-2025-53770-Microsoft SharePoint Server-远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-22  
**POC仓库:** [CVE-2025-53770-scanner](https://github.com/tripoloski1337/CVE-2025-53770-scanner)  

---

### [CVE-2024-3121](CVE-2024-3121-dark-ninja10_CVE-2024-3121.md) 🔴 ✅

**名称:** CVE-2024-3121 - lollms create_conda_env 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-22  
**POC仓库:** [CVE-2024-3121](https://github.com/dark-ninja10/CVE-2024-3121)  

---

### [CVE-2024-4947](CVE-2024-4947-bjrjk_CVE-2024-4947.md) 🔴 ✅

**名称:** CVE-2024-4947 - Google Chrome V8 类型混淆漏洞  
**类型:** 类型混淆  
**风险:** 高危，允许远程攻击者在沙箱内执行任意代码  
**投毒风险:** 1%  
**发现时间:** 2025-07-22  
**POC仓库:** [CVE-2024-4947](https://github.com/bjrjk/CVE-2024-4947)  

---

### [CVE-2025-5025](CVE-2025-5025-KiPhuong_cve-2025-5025.md) 🟡 ✅

**名称:** CVE-2025-5025 - curl wolfSSL QUIC 证书校验绕过  
**类型:** 证书校验绕过  
**风险:** 中危，可能导致中间人攻击  
**投毒风险:** 10%  
**发现时间:** 2025-07-22  
**POC仓库:** [cve-2025-5025](https://github.com/KiPhuong/cve-2025-5025)  

---

### [CVE-2019-7139](CVE-2019-7139-adhammedhat111_Magento-CVE-2019-7139-SQLi-PoC.md) 🔴 ✅

**名称:** CVE-2019-7139-Magento-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-07-22  
**POC仓库:** [Magento-CVE-2019-7139-SQLi-PoC](https://github.com/adhammedhat111/Magento-CVE-2019-7139-SQLi-PoC)  

---

### [CVE-2025-47917](CVE-2025-47917-byteReaper77_CVE-2025-47917.md) 🔴 ✅

**名称:** CVE-2025-47917-mbedtls-Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可能导致代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-22  
**POC仓库:** [CVE-2025-47917](https://github.com/byteReaper77/CVE-2025-47917)  

---

### [CVE-2025-25014](CVE-2025-25014-B1ack4sh_Blackash-CVE-2025-25014.md) 🔴 ✅

**名称:** CVE-2025-25014-Kibana-原型污染导致远程代码执行  
**类型:** 原型污染  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-21  
**POC仓库:** [Blackash-CVE-2025-25014](https://github.com/B1ack4sh/Blackash-CVE-2025-25014)  

---

### [CVE-2025-53770](CVE-2025-53770-grupooruss_CVE-2025-53770-Checker.md)  ✅

**名称:** CVE-2025-53770 - Microsoft SharePoint Server 远程代码执行漏洞  
**类型:** 反序列化漏洞  
**风险:** 严重，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-21  
**POC仓库:** [CVE-2025-53770-Checker](https://github.com/grupooruss/CVE-2025-53770-Checker)  

---

### [CVE-2025-53770](CVE-2025-53770-ZephrFish_CVE-2025-53770-Scanner.md) 🔴 ✅

**名称:** CVE-2025-53770-Microsoft SharePoint Server Remote Code Execution  
**类型:** 反序列化漏洞导致远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-21  
**POC仓库:** [CVE-2025-53770-Scanner](https://github.com/ZephrFish/CVE-2025-53770-Scanner)  

---

### [CVE-2025-32463](CVE-2025-32463-AdityaBhatt3010_CVE-2025-32463-CVE-2025-32462-Sudo-Privilege-Escalation.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo本地权限提升  
**类型:** 本地权限提升  
**风险:** 高危，本地用户可获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-21  
**POC仓库:** [CVE-2025-32463-CVE-2025-32462-Sudo-Privilege-Escalation](https://github.com/AdityaBhatt3010/CVE-2025-32463-CVE-2025-32462-Sudo-Privilege-Escalation)  

---

### [CVE-2025-53770](CVE-2025-53770-hazcod_CVE-2025-53770.md) 🔴 ✅

**名称:** CVE-2025-53770-Microsoft SharePoint Server远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致远程代码执行，控制服务器  
**投毒风险:** 0%  
**发现时间:** 2025-07-21  
**POC仓库:** [CVE-2025-53770](https://github.com/hazcod/CVE-2025-53770)  

---

### [CVE-2023-7028](CVE-2023-7028-szybnev_CVE-2023-7028.md) 🔴 ✅

**名称:** CVE-2023-7028-GitLab-账号接管  
**类型:** 弱密码恢复机制  
**风险:** 高危，可导致账户接管  
**投毒风险:** 10%  
**发现时间:** 2025-07-21  
**POC仓库:** [CVE-2023-7028](https://github.com/szybnev/CVE-2023-7028)  

---

### [CVE-2023-38646](CVE-2023-38646-alexandre-pecorilla_CVE-2023-38646.md) 🔴 ✅

**名称:** CVE-2023-38646-Metabase-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-21  
**POC仓库:** [CVE-2023-38646](https://github.com/alexandre-pecorilla/CVE-2023-38646)  

---

### [CVE-2023-38646](CVE-2023-38646-0utl4nder_Another-Metabase-RCE-CVE-2023-38646.md) 🔴 ✅

**名称:** CVE-2023-38646 - Metabase Pre-Auth RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的攻击者可以以服务器权限执行任意命令  
**投毒风险:** 1%  
**发现时间:** 2025-07-21  
**POC仓库:** [Another-Metabase-RCE-CVE-2023-38646](https://github.com/0utl4nder/Another-Metabase-RCE-CVE-2023-38646)  

---

### [CVE-2023-38646](CVE-2023-38646-UserConnecting_Exploit-CVE-2023-38646-Metabase.md) 🔴 ✅

**名称:** CVE-2023-38646-Metabase-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，无需身份验证即可执行任意命令  
**投毒风险:** 1%  
**发现时间:** 2025-07-21  
**POC仓库:** [Exploit-CVE-2023-38646-Metabase](https://github.com/UserConnecting/Exploit-CVE-2023-38646-Metabase)  

---

### [CVE-2023-38646](CVE-2023-38646-junnythemarksman_CVE-2023-38646.md) 🔴 ✅

**名称:** CVE-2023-38646-Metabase-RCE  
**类型:** 远程代码执行  
**风险:** 高危，无需认证即可远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-21  
**POC仓库:** [CVE-2023-38646](https://github.com/junnythemarksman/CVE-2023-38646)  

---

### [CVE-2025-53770](CVE-2025-53770-soltanali0_CVE-2025-53770-Exploit.md) 🔴 ✅

**名称:** CVE-2025-53770-Microsoft SharePoint Server-远程代码执行  
**类型:** 反序列化漏洞  
**风险:** 高危，允许未经授权的攻击者通过网络执行代码  
**投毒风险:** 5%  
**发现时间:** 2025-07-21  
**POC仓库:** [CVE-2025-53770-Exploit](https://github.com/soltanali0/CVE-2025-53770-Exploit)  

---

### [CVE-2023-38646](CVE-2023-38646-Zenmovie_CVE-2023-38646.md) 🔴 ✅

**名称:** CVE-2023-38646-Metabase-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-21  
**POC仓库:** [CVE-2023-38646](https://github.com/Zenmovie/CVE-2023-38646)  

---

### [CVE-2023-38646](CVE-2023-38646-yxl2001_CVE-2023-38646.md) 🔴 ✅

**名称:** CVE-2023-38646-Metabase-RCE  
**类型:** 远程代码执行  
**风险:** 高危，无需认证即可远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-21  
**POC仓库:** [CVE-2023-38646](https://github.com/yxl2001/CVE-2023-38646)  

---

### [CVE-2023-38646](CVE-2023-38646-passwa11_CVE-2023-38646.md) 🔴 ✅

**名称:** CVE-2023-38646-Metabase-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未授权的攻击者在服务器上执行任意命令  
**投毒风险:** 10%  
**发现时间:** 2025-07-21  
**POC仓库:** [CVE-2023-38646](https://github.com/passwa11/CVE-2023-38646)  

---

### [CVE-2023-38646](CVE-2023-38646-asepsaepdin_CVE-2023-38646.md) 🔴 ✅

**名称:** CVE-2023-38646-Metabase-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的攻击者在服务器上执行任意命令  
**投毒风险:** 10%  
**发现时间:** 2025-07-21  
**POC仓库:** [CVE-2023-38646](https://github.com/asepsaepdin/CVE-2023-38646)  

---

### [CVE-2023-38646](CVE-2023-38646-Pyr0sec_CVE-2023-38646.md) 🔴 ✅

**名称:** CVE-2023-38646-Metabase-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的攻击者在服务器上执行任意命令  
**投毒风险:** 2%  
**发现时间:** 2025-07-21  
**POC仓库:** [CVE-2023-38646](https://github.com/Pyr0sec/CVE-2023-38646)  

---

### [CVE-2023-38646](CVE-2023-38646-Red4mber_CVE-2023-38646.md) 🔴 ✅

**名称:** CVE-2023-38646-Metabase-RCE  
**类型:** 远程代码执行(RCE)  
**风险:** 高危，允许未经身份验证的攻击者在服务器上执行任意命令  
**投毒风险:** 1%  
**发现时间:** 2025-07-21  
**POC仓库:** [CVE-2023-38646](https://github.com/Red4mber/CVE-2023-38646)  

---

### [CVE-2023-38646](CVE-2023-38646-birdm4nw_CVE-2023-38646.md) 🔴 ✅

**名称:** CVE-2023-38646 - Metabase RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的攻击者以服务器权限执行任意命令。  
**投毒风险:** 0%  
**发现时间:** 2025-07-21  
**POC仓库:** [CVE-2023-38646](https://github.com/birdm4nw/CVE-2023-38646)  

---

### [CVE-2025-53770](CVE-2025-53770-paolokappa_SharePointSecurityMonitor.md) 🔴 ✅

**名称:** CVE-2025-53770-Microsoft SharePoint Server 远程代码执行  
**类型:** 反序列化漏洞  
**风险:** 高危，远程代码执行  
**投毒风险:** 60%  
**发现时间:** 2025-07-21  
**POC仓库:** [SharePointSecurityMonitor](https://github.com/paolokappa/SharePointSecurityMonitor)  

---

### [CVE-2023-38646](CVE-2023-38646-kh4sh3i_CVE-2023-38646.md) 🔴 ✅

**名称:** CVE-2023-38646-Metabase-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证即可远程执行代码  
**投毒风险:** 1%  
**发现时间:** 2025-07-21  
**POC仓库:** [CVE-2023-38646](https://github.com/kh4sh3i/CVE-2023-38646)  

---

### [CVE-2023-38646](CVE-2023-38646-CN016_Metabase-H2-CVE-2023-38646-.md) 🔴 ✅

**名称:** CVE-2023-38646-Metabase-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，无需身份验证即可远程执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-07-21  
**POC仓库:** [Metabase-H2-CVE-2023-38646-](https://github.com/CN016/Metabase-H2-CVE-2023-38646-)  

---

### [CVE-2023-38646](CVE-2023-38646-Boogipop_MetabaseRceTools.md) 🔴 ✅

**名称:** CVE-2023-38646-Metabase-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-21  
**POC仓库:** [MetabaseRceTools](https://github.com/Boogipop/MetabaseRceTools)  

---

### [CVE-2023-38646](CVE-2023-38646-DaniTheHack3r_CVE-2023-38646.md) 🔴 ✅

**名称:** CVE-2023-38646 Metabase RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证即可执行任意命令  
**投毒风险:** 10%  
**发现时间:** 2025-07-21  
**POC仓库:** [CVE-2023-38646](https://github.com/DaniTheHack3r/CVE-2023-38646)  

---

### [CVE-2023-38646](CVE-2023-38646-nickswink_CVE-2023-38646.md) 🔴 ✅

**名称:** CVE-2023-38646-Metabase-RCE  
**类型:** 远程代码执行(RCE)  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-21  
**POC仓库:** [CVE-2023-38646](https://github.com/nickswink/CVE-2023-38646)  

---

### [CVE-2023-38646](CVE-2023-38646-threatHNTR_CVE-2023-38646.md) 🔴 ✅

**名称:** CVE-2023-38646-Metabase-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，无需身份验证即可远程执行任意命令  
**投毒风险:** 10%  
**发现时间:** 2025-07-21  
**POC仓库:** [CVE-2023-38646](https://github.com/threatHNTR/CVE-2023-38646)  

---

### [CVE-2023-38646](CVE-2023-38646-AnvithLobo_CVE-2023-38646.md) 🔴 ✅

**名称:** CVE-2023-38646-Metabase-RCE  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-21  
**POC仓库:** [CVE-2023-38646](https://github.com/AnvithLobo/CVE-2023-38646)  

---

### [CVE-2023-38646](CVE-2023-38646-Mrunalkaran_CVE-2023-38646.md) 🔴 ✅

**名称:** CVE-2023-38646-Metabase-RCE  
**类型:** 远程代码执行(RCE)  
**风险:** 高危，允许未经身份验证的攻击者以服务器权限执行任意命令  
**投毒风险:** 1%  
**发现时间:** 2025-07-21  
**POC仓库:** [CVE-2023-38646](https://github.com/Mrunalkaran/CVE-2023-38646)  

---

### [CVE-2023-38646](CVE-2023-38646-j0yb0y0h_CVE-2023-38646.md) 🔴 ✅

**名称:** CVE-2023-38646-Metabase-RCE  
**类型:** 远程代码执行  
**风险:** 高危，未经授权的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-21  
**POC仓库:** [CVE-2023-38646](https://github.com/j0yb0y0h/CVE-2023-38646)  

---

### [CVE-2023-38646](CVE-2023-38646-Ego1stoo_CVE-2023-38646.md) 🔴 ✅

**名称:** CVE-2023-38646 Metabase Pre-Auth RCE  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-21  
**POC仓库:** [CVE-2023-38646](https://github.com/Ego1stoo/CVE-2023-38646)  

---

### [CVE-2023-38646](CVE-2023-38646-securezeron_CVE-2023-38646.md) 🔴 ✅

**名称:** CVE-2023-38646-Metabase-RCE  
**类型:** 远程代码执行(RCE)  
**风险:** 高危，未授权远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-21  
**POC仓库:** [CVE-2023-38646](https://github.com/securezeron/CVE-2023-38646)  

---

### [CVE-2023-38646](CVE-2023-38646-Shisones_MetabaseRCE_CVE-2023-38646.md) 🔴 ✅

**名称:** CVE-2023-38646-Metabase-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者以服务器权限执行任意命令  
**投毒风险:** 10%  
**发现时间:** 2025-07-21  
**POC仓库:** [MetabaseRCE_CVE-2023-38646](https://github.com/Shisones/MetabaseRCE_CVE-2023-38646)  

---

### [CVE-2023-38646](CVE-2023-38646-acesoyeo_METABASE-RCE-CVE-2023-38646-.md) 🔴 ✅

**名称:** CVE-2023-38646-Metabase-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的攻击者在服务器上执行任意命令。  
**投毒风险:** 10%  
**发现时间:** 2025-07-21  
**POC仓库:** [METABASE-RCE-CVE-2023-38646-](https://github.com/acesoyeo/METABASE-RCE-CVE-2023-38646-)  

---

### [CVE-2023-38646](CVE-2023-38646-XiaomingX_cve-2023-38646-poc.md) 🔴 ✅

**名称:** CVE-2023-38646-Metabase-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可完全控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-07-21  
**POC仓库:** [cve-2023-38646-poc](https://github.com/XiaomingX/cve-2023-38646-poc)  

---

### [CVE-2023-38646](CVE-2023-38646-JayRyz_CVE-2023-38646-PoC-Metabase.md) 🔴 ✅

**名称:** CVE-2023-38646-Metabase-RCE  
**类型:** 远程代码执行(RCE)  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-21  
**POC仓库:** [CVE-2023-38646-PoC-Metabase](https://github.com/JayRyz/CVE-2023-38646-PoC-Metabase)  

---

### [CVE-2023-38646](CVE-2023-38646-BreezeGalaxy_CVE-2023-38646.md) 🔴 ✅

**名称:** CVE-2023-38646-Metabase-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，无需身份验证即可远程执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-07-21  
**POC仓库:** [CVE-2023-38646](https://github.com/BreezeGalaxy/CVE-2023-38646)  

---

### [CVE-2024-9264](CVE-2024-9264-patrickpichler_grafana-CVE-2024-9264.md) 🔴 ✅

**名称:** CVE-2024-9264-Grafana-命令注入和本地文件包含  
**类型:** 命令注入和本地文件包含  
**风险:** 高危，可能导致远程代码执行和敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-07-21  
**POC仓库:** [grafana-CVE-2024-9264](https://github.com/patrickpichler/grafana-CVE-2024-9264)  

---

### [CVE-2025-53770](CVE-2025-53770-kaizensecurity_CVE-2025-53770.md) 🔴 ✅

**名称:** CVE-2025-53770-Microsoft SharePoint Server-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-21  
**POC仓库:** [CVE-2025-53770](https://github.com/kaizensecurity/CVE-2025-53770)  

---

### [CVE-2025-53770](CVE-2025-53770-n1chr0x_ZeroPoint.md) 🔴 ✅

**名称:** CVE-2025-53770-Microsoft SharePoint Server-远程代码执行  
**类型:** 反序列化漏洞  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-21  
**POC仓库:** [ZeroPoint](https://github.com/n1chr0x/ZeroPoint)  

---

### [CVE-2025-53770](CVE-2025-53770-Bluefire-Redteam-Cybersecurity_bluefire-sharepoint-cve-2025-53770.md) 🔴 ✅

**名称:** CVE-2025-53770 - Microsoft SharePoint Server RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未授权的攻击者通过网络执行任意代码  
**投毒风险:** 20%  
**发现时间:** 2025-07-21  
**POC仓库:** [bluefire-sharepoint-cve-2025-53770](https://github.com/Bluefire-Redteam-Cybersecurity/bluefire-sharepoint-cve-2025-53770)  

---

### [CVE-2024-8118](CVE-2024-8118-nurarifin05_POC-CVE-2024-8118.md) 🟡 ✅

**名称:** CVE-2024-8118-Grafana-权限绕过  
**类型:** 权限绕过  
**风险:** 中危，允许具有外部告警实例写入权限的用户写入告警规则，可能导致告警配置被篡改。  
**投毒风险:** 0%  
**发现时间:** 2025-07-21  
**POC仓库:** [POC-CVE-2024-8118](https://github.com/nurarifin05/POC-CVE-2024-8118)  

---

### [CVE-2024-49039](CVE-2024-49039-Alexandr-bit253_CVE-2024-49039.md) 🔴 ✅

**名称:** CVE-2024-49039 Windows Task Scheduler Elevation of Privilege Vulnerability  
**类型:** 权限提升  
**风险:** 高危，可导致本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-07-21  
**POC仓库:** [CVE-2024-49039](https://github.com/Alexandr-bit253/CVE-2024-49039)  

---

### [CVE-2024-49039](CVE-2024-49039-je5442804_WPTaskScheduler_CVE-2024-49039.md) 🔴 ✅

**名称:** CVE-2024-49039 - Windows Task Scheduler 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，允许低权限用户提升至 SYSTEM 权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-21  
**POC仓库:** [WPTaskScheduler_CVE-2024-49039](https://github.com/je5442804/WPTaskScheduler_CVE-2024-49039)  

---

### [CVE-2023-42961](CVE-2023-42961-windz3r0day_CVE-2023-42961.md) 🟡 ✅

**名称:** CVE-2023-42961 - intents_helper.xpc 沙箱逃逸  
**类型:** 沙箱逃逸  
**风险:** 中危，可能允许沙箱进程绕过限制  
**投毒风险:** 5%  
**发现时间:** 2025-07-20  
**POC仓库:** [CVE-2023-42961](https://github.com/windz3r0day/CVE-2023-42961)  

---

### [CVE-2025-53770](CVE-2025-53770-B1ack4sh_Blackash-CVE-2025-53770.md) 🔴 ✅

**名称:** CVE-2025-53770-Microsoft SharePoint Server-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-20  
**POC仓库:** [Blackash-CVE-2025-53770](https://github.com/B1ack4sh/Blackash-CVE-2025-53770)  

---

### [CVE-2025-4380](CVE-2025-4380-r0otk3r_CVE-2025-4380.md) 🔴 ✅

**名称:** CVE-2025-4380 - Ads Pro Plugin <= 4.89 - Unauthenticated Local File Inclusion  
**类型:** 本地文件包含 (LFI)  
**风险:** 高危，可导致敏感信息泄露和任意代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-07-20  
**POC仓库:** [CVE-2025-4380](https://github.com/r0otk3r/CVE-2025-4380)  

---

### [CVE-2025-34085](CVE-2025-34085-0xgh057r3c0n_CVE-2025-34085.md) 🔴 ✅

**名称:** CVE-2025-34085-Simple File List-RCE  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-20  
**POC仓库:** [CVE-2025-34085](https://github.com/0xgh057r3c0n/CVE-2025-34085)  

---

### [CVE-2025-7840](CVE-2025-7840-byteReaper77_CVE-2025-7840.md) 🟡 ✅

**名称:** CVE-2025-7840 - Campcodes Online Movie Theater Seat Reservation System XSS  
**类型:** 跨站脚本攻击 (XSS)  
**风险:** 中危，可能导致用户信息泄露、会话劫持或恶意脚本执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-20  
**POC仓库:** [CVE-2025-7840](https://github.com/byteReaper77/CVE-2025-7840)  

---

### [CVE-2025-32463](CVE-2025-32463-IC3-512_linux-root-kit.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可获取root权限  
**投毒风险:** 50%  
**发现时间:** 2025-07-20  
**POC仓库:** [linux-root-kit](https://github.com/IC3-512/linux-root-kit)  

---

### [CVE-2025-32463](CVE-2025-32463-daryllundy_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可提升至root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-20  
**POC仓库:** [CVE-2025-32463](https://github.com/daryllundy/CVE-2025-32463)  

---

### [CVE-2022-0492](CVE-2022-0492-chenaotian_CVE-2022-0492.md) 🔴 ✅

**名称:** CVE-2022-0492-Linux Kernel-cgroup release_agent 权限提升/容器逃逸  
**类型:** 权限提升/容器逃逸  
**风险:** 高危，可能导致容器逃逸和主机控制  
**投毒风险:** 1%  
**发现时间:** 2025-07-20  
**POC仓库:** [CVE-2022-0492](https://github.com/chenaotian/CVE-2022-0492)  

---

### [CVE-2025-49706](CVE-2025-49706-AdityaBhatt3010_CVE-2025-49706-SharePoint-Spoofing-Vulnerability-Under-Active-Exploitation.md) 🔴 ✅

**名称:** CVE-2025-49706 - Microsoft SharePoint Server Spoofing Vulnerability  
**类型:** 身份验证绕过/欺骗 (Spoofing)  
**风险:** 中危，但结合其他漏洞可升级为高危，可能导致信息泄露、权限提升甚至远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-20  
**POC仓库:** [CVE-2025-49706-SharePoint-Spoofing-Vulnerability-Under-Active-Exploitation](https://github.com/AdityaBhatt3010/CVE-2025-49706-SharePoint-Spoofing-Vulnerability-Under-Active-Exploitation)  

---

### [CVE-2022-0492](CVE-2022-0492-T1erno_CVE-2022-0492-Docker-Breakout-Checker-and-PoC.md) 🔴 ✅

**名称:** CVE-2022-0492-Linux Kernel cgroup_release_agent 特权提升/容器逃逸  
**类型:** 特权提升/容器逃逸  
**风险:** 高危，可导致容器逃逸，控制宿主机  
**投毒风险:** 10%  
**发现时间:** 2025-07-20  
**POC仓库:** [CVE-2022-0492-Docker-Breakout-Checker-and-PoC](https://github.com/T1erno/CVE-2022-0492-Docker-Breakout-Checker-and-PoC)  

---

### [CVE-2022-0492](CVE-2022-0492-bb33bb_CVE-2022-0492.md) 🔴 ✅

**名称:** CVE-2022-0492-Linux Kernel cgroup release_agent权限提升  
**类型:** 权限提升/容器逃逸  
**风险:** 高危，可导致权限提升和容器逃逸  
**投毒风险:** 0%  
**发现时间:** 2025-07-20  
**POC仓库:** [CVE-2022-0492](https://github.com/bb33bb/CVE-2022-0492)  

---

### [CVE-2022-0492](CVE-2022-0492-PaloAltoNetworks_can-ctr-escape-cve-2022-0492.md) 🔴 ✅

**名称:** CVE-2022-0492-Linux Kernel cgroup_release_agent 特权提升/容器逃逸  
**类型:** 特权提升/容器逃逸  
**风险:** 高危，可能导致容器逃逸和主机控制  
**投毒风险:** 0%  
**发现时间:** 2025-07-20  
**POC仓库:** [can-ctr-escape-cve-2022-0492](https://github.com/PaloAltoNetworks/can-ctr-escape-cve-2022-0492)  

---

### [CVE-2022-0492](CVE-2022-0492-SofianeHamlaoui_CVE-2022-0492-Checker.md) 🔴 ✅

**名称:** CVE-2022-0492-Linux内核cgroup_release_agent权限提升  
**类型:** 权限提升/容器逃逸  
**风险:** 高危，可能导致权限提升和容器逃逸  
**投毒风险:** 5%  
**发现时间:** 2025-07-20  
**POC仓库:** [CVE-2022-0492-Checker](https://github.com/SofianeHamlaoui/CVE-2022-0492-Checker)  

---

### [CVE-2022-0492](CVE-2022-0492-Trinadh465_device_renesas_kernel_AOSP10_r33_CVE-2022-0492.md) 🔴 ✅

**名称:** CVE-2022-0492-Linux Kernel-cgroups v1 release_agent权限提升  
**类型:** 权限提升/容器逃逸  
**风险:** 高危，可导致容器逃逸和权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-07-20  
**POC仓库:** [device_renesas_kernel_AOSP10_r33_CVE-2022-0492](https://github.com/Trinadh465/device_renesas_kernel_AOSP10_r33_CVE-2022-0492)  

---

### [CVE-2022-0492](CVE-2022-0492-yoeelingBin_CVE-2022-0492-Container-Escape.md) 🔴 ✅

**名称:** CVE-2022-0492-Linux内核cgroups v1 release_agent权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可导致容器逃逸和主机权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-07-20  
**POC仓库:** [CVE-2022-0492-Container-Escape](https://github.com/yoeelingBin/CVE-2022-0492-Container-Escape)  

---

### [CVE-2022-0492](CVE-2022-0492-Perimora_cve_2022_0492.md) 🔴 

**名称:** CVE-2022-0492-Linux Kernel-cgroup_release_agent特权提升  
**类型:** 特权提升  
**风险:** 高危，可能导致容器逃逸和主机控制  
**投毒风险:** 1%  
**发现时间:** 2025-07-20  
**POC仓库:** [cve_2022_0492](https://github.com/Perimora/cve_2022_0492)  

---

### [CVE-2025-51396](CVE-2025-51396-Thewhiteevil_CVE-2025-51396.md) 🟡 ✅

**名称:** CVE-2025-51396 - LiveHelperChat Stored XSS  
**类型:** 存储型跨站脚本 (Stored XSS)  
**风险:** 中危，可能导致敏感信息泄露，会话劫持，甚至管理账号被控制。  
**投毒风险:** 10%  
**发现时间:** 2025-07-20  
**POC仓库:** [CVE-2025-51396](https://github.com/Thewhiteevil/CVE-2025-51396)  

---

### [CVE-2025-51970](CVE-2025-51970-M4xIq_CVE-2025-51970.md) 🔴 ✅

**名称:** CVE-2025-51970-Online Shopping System Advanced-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、数据篡改和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-20  
**POC仓库:** [CVE-2025-51970](https://github.com/M4xIq/CVE-2025-51970)  

---

### [CVE-2025-49721](CVE-2025-49721-Lam0x0_CVE-2025-49721_part1.md) 🔴 ✅

**名称:** CVE-2025-49721-Windows Fast FAT File System Driver-权限提升  
**类型:** 权限提升  
**风险:** 高危，允许本地未授权的攻击者提升权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-20  
**POC仓库:** [CVE-2025-49721_part1](https://github.com/Lam0x0/CVE-2025-49721_part1)  

---

### [CVE-2025-51401](CVE-2025-51401-Thewhiteevil_CVE-2025-51401.md) 🟡 ✅

**名称:** CVE-2025-51401-LiveHelperChat-Stored XSS  
**类型:** Stored Cross-Site Scripting (XSS)  
**风险:** 中危，可能导致用户凭据泄露和恶意脚本执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-20  
**POC仓库:** [CVE-2025-51401](https://github.com/Thewhiteevil/CVE-2025-51401)  

---

### [CVE-2025-51397](CVE-2025-51397-Thewhiteevil_CVE-2025-51397.md) 🟡 ✅

**名称:** CVE-2025-51397 - LiveHelperChat Stored XSS  
**类型:** Stored Cross-Site Scripting (XSS)  
**风险:** 中危，可能导致管理员账户劫持，信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-07-20  
**POC仓库:** [CVE-2025-51397](https://github.com/Thewhiteevil/CVE-2025-51397)  

---

### [CVE-2025-51403](CVE-2025-51403-Thewhiteevil_CVE-2025-51403.md) 🟡 ✅

**名称:** CVE-2025-51403 - LiveHelperChat Stored XSS  
**类型:** Stored Cross-Site Scripting (XSS)  
**风险:** 中危，可能导致敏感信息泄露、会话劫持等  
**投毒风险:** 10%  
**发现时间:** 2025-07-20  
**POC仓库:** [CVE-2025-51403](https://github.com/Thewhiteevil/CVE-2025-51403)  

---

### [CVE-2025-51398](CVE-2025-51398-Thewhiteevil_CVE-2025-51398.md) 🟡 ✅

**名称:** CVE-2025-51398 - LiveHelperChat Stored XSS  
**类型:** Stored Cross-Site Scripting (XSS)  
**风险:** 中危，可能导致敏感信息泄露或控制用户账户  
**投毒风险:** 5%  
**发现时间:** 2025-07-20  
**POC仓库:** [CVE-2025-51398](https://github.com/Thewhiteevil/CVE-2025-51398)  

---

### [CVE-2025-51400](CVE-2025-51400-Thewhiteevil_CVE-2025-51400.md) 🟡 ✅

**名称:** CVE-2025-51400 - LiveHelperChat <=4.61 - Stored Cross Site Scripting (XSS)  
**类型:** Stored Cross Site Scripting (XSS)  
**风险:** 中危，可能导致管理员或操作员账号被控制，进而影响整个聊天系统  
**投毒风险:** 1%  
**发现时间:** 2025-07-20  
**POC仓库:** [CVE-2025-51400](https://github.com/Thewhiteevil/CVE-2025-51400)  

---

### [CVE-2025-32023](CVE-2025-32023-LordBheem_CVE-2025-32023.md) 🔴 ✅

**名称:** CVE-2025-32023-Redis-HyperLogLog-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致系统完全控制和数据泄露  
**投毒风险:** 20%  
**发现时间:** 2025-07-20  
**POC仓库:** [CVE-2025-32023](https://github.com/LordBheem/CVE-2025-32023)  

---

### [CVE-2025-32023](CVE-2025-32023-shayantrix_POC-CVE-2025-32023.md) 🔴 ✅

**名称:** CVE-2025-32023-Redis-HyperLogLog-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-07-20  
**POC仓库:** [POC-CVE-2025-32023](https://github.com/shayantrix/POC-CVE-2025-32023)  

---

### [CVE-2025-27591](CVE-2025-27591-Thekin-ctrl_CVE-2025-27591-Below.md) 🔴 ✅

**名称:** CVE-2025-27591-Below-权限提升  
**类型:** 权限提升  
**风险:** 高危，可能导致本地用户提升为root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-20  
**POC仓库:** [CVE-2025-27591-Below](https://github.com/Thekin-ctrl/CVE-2025-27591-Below)  

---

### [CVE-2025-27591](CVE-2025-27591-00xCanelo_CVE-2025-27591-PoC.md) 🔴 ✅

**名称:** CVE-2025-27591-below-权限提升  
**类型:** 权限提升  
**风险:** 高危，可使本地普通用户提升为root权限  
**投毒风险:** 0%  
**发现时间:** 2025-07-20  
**POC仓库:** [CVE-2025-27591-PoC](https://github.com/00xCanelo/CVE-2025-27591-PoC)  

---

### [CVE-2025-49113](CVE-2025-49113-00xCanelo_CVE-2025-49113.md) 🔴 ✅

**名称:** CVE-2025-49113 - Roundcube Webmail RCE  
**类型:** PHP 对象反序列化导致远程代码执行  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2025-49113](https://github.com/00xCanelo/CVE-2025-49113)  

---

### [CVE-2024-47575](CVE-2024-47575-krmxd_CVE-2024-47575.md) 🔴 ✅

**名称:** CVE-2024-47575-FortiManager-未授权命令执行  
**类型:** 未授权命令执行  
**风险:** 高危，可能导致系统完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2024-47575](https://github.com/krmxd/CVE-2024-47575)  

---

### [CVE-2024-47575](CVE-2024-47575-watchtowrlabs_Fortijump-Exploit-CVE-2024-47575.md) 🔴 ✅

**名称:** CVE-2024-47575-FortiManager-RCE  
**类型:** 未授权远程代码执行  
**风险:** 高危，无需身份验证即可远程执行代码  
**投毒风险:** 0%  
**发现时间:** 2025-07-19  
**POC仓库:** [Fortijump-Exploit-CVE-2024-47575](https://github.com/watchtowrlabs/Fortijump-Exploit-CVE-2024-47575)  

---

### [CVE-2024-47575](CVE-2024-47575-SkyGodling_exploit-cve-2024-47575.md) 🔴 ✅

**名称:** CVE-2024-47575 - FortiManager 未授权远程代码执行漏洞 (FortiJump)  
**类型:** 未授权远程代码执行  
**风险:** 高危，允许未授权的远程攻击者执行任意代码或命令  
**投毒风险:** 1%  
**发现时间:** 2025-07-19  
**POC仓库:** [exploit-cve-2024-47575](https://github.com/SkyGodling/exploit-cve-2024-47575)  

---

### [CVE-2024-47575](CVE-2024-47575-expl0itsecurity_CVE-2024-47575.md) 🔴 ✅

**名称:** CVE-2024-47575: FortiManager Missing Authentication  
**类型:** 未授权访问/代码执行  
**风险:** 高危，可远程执行任意代码或命令  
**投毒风险:** 70%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2024-47575](https://github.com/expl0itsecurity/CVE-2024-47575)  

---

### [CVE-2024-47575](CVE-2024-47575-XiaomingX_cve-2024-47575-exp.md) 🔴 ✅

**名称:** CVE-2024-47575 - FortiManager 未授权远程命令执行  
**类型:** 未授权远程命令执行  
**风险:** 高危，可导致完全控制受影响的FortiManager系统  
**投毒风险:** 5%  
**发现时间:** 2025-07-19  
**POC仓库:** [cve-2024-47575-exp](https://github.com/XiaomingX/cve-2024-47575-exp)  

---

### [CVE-2024-47575](CVE-2024-47575-revanslbw_CVE-2024-47575-POC.md) 🔴 ✅

**名称:** CVE-2024-47575-FortiManager-Missing Authentication  
**类型:** 未授权访问  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2024-47575-POC](https://github.com/revanslbw/CVE-2024-47575-POC)  

---

### [CVE-2024-47575](CVE-2024-47575-AnnnNix_CVE-2024-47575.md) 🔴 ✅

**名称:** CVE-2024-47575-FortiManager-未授权RCE  
**类型:** 未授权远程代码执行  
**风险:** 高危，可能导致完全控制受影响的FortiManager实例  
**投毒风险:** 0%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2024-47575](https://github.com/AnnnNix/CVE-2024-47575)  

---

### [CVE-2025-31161](CVE-2025-31161-r0otk3r_CVE-2025-31161.md) 🔴 ✅

**名称:** CVE-2025-31161-CrushFTP-认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致完全系统权限控制  
**投毒风险:** 1%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2025-31161](https://github.com/r0otk3r/CVE-2025-31161)  

---

### [CVE-2025-25257](CVE-2025-25257-TheStingR_CVE-2025-25257.md) 🔴 ✅

**名称:** CVE-2025-25257-FortiWeb-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2025-25257](https://github.com/TheStingR/CVE-2025-25257)  

---

### [CVE-2025-51868](CVE-2025-51868-Secsys-FDU_CVE-2025-51868.md) 🔴 ✅

**名称:** CVE-2024-51868 - Dippy AI 聊天组件 IDOR 漏洞  
**类型:** IDOR (Insecure Direct Object Reference)  
**风险:** 高危，可能导致用户聊天记录泄露和篡改  
**投毒风险:** 0%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2025-51868](https://github.com/Secsys-FDU/CVE-2025-51868)  

---

### [CVE-2025-51869](CVE-2025-51869-Secsys-FDU_CVE-2025-51869.md) 🔴 ✅

**名称:** CVE-2025-51869-Liner-IDOR  
**类型:** IDOR (Insecure Direct Object Reference)  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2025-51869](https://github.com/Secsys-FDU/CVE-2025-51869)  

---

### [CVE-2025-41646](CVE-2025-41646-r0otk3r_CVE-2025-41646.md) 🔴 ✅

**名称:** CVE-2025-41646 - RevPi Webstatus Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 高危，可完全控制设备  
**投毒风险:** 5%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2025-41646](https://github.com/r0otk3r/CVE-2025-41646)  

---

### [CVE-2025-7795](CVE-2025-7795-byteReaper77_CVE-2025-7795.md) 🔴 ✅

**名称:** CVE-2025-7795 - Tenda FH451 1.0.0.9 栈溢出  
**类型:** 栈溢出  
**风险:** 高危，可能导致远程代码执行或拒绝服务  
**投毒风险:** 0%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2025-7795](https://github.com/byteReaper77/CVE-2025-7795)  

---

### [CVE-2025-51865](CVE-2025-51865-Secsys-FDU_CVE-2025-51865.md) 🟡 ✅

**名称:** CVE-2025-51865 - Ai2 Playground IDOR  
**类型:** IDOR (Insecure Direct Object Reference)  
**风险:** 中危，可能导致用户聊天记录泄露  
**投毒风险:** 10%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2025-51865](https://github.com/Secsys-FDU/CVE-2025-51865)  

---

### [CVE-2025-51864](CVE-2025-51864-Secsys-FDU_CVE-2025-51864.md) 🔴 ✅

**名称:** CVE-2024-51864-AIBOX-XSS  
**类型:** XSS  
**风险:** 高危，可能导致JWT token泄露和远程账户劫持  
**投毒风险:** 10%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2025-51864](https://github.com/Secsys-FDU/CVE-2025-51864)  

---

### [CVE-2025-51867](CVE-2025-51867-Secsys-FDU_CVE-2025-51867.md) 🔴 ✅

**名称:** CVE-2025-51867 - Deepfiction AI IDOR  
**类型:** IDOR (Insecure Direct Object Reference)  
**风险:** 高危，可能导致未经授权的LLM访问和资源滥用  
**投毒风险:** 10%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2025-51867](https://github.com/Secsys-FDU/CVE-2025-51867)  

---

### [CVE-2025-51863](CVE-2025-51863-Secsys-FDU_CVE-2025-51863.md) 🟡 ✅

**名称:** CVE-2025-51863 - ChatGPTUtil Self-XSS  
**类型:** Self-XSS  
**风险:** 中危，可能导致账户劫持  
**投毒风险:** 10%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2025-51863](https://github.com/Secsys-FDU/CVE-2025-51863)  

---

### [CVE-2025-53640](CVE-2025-53640-rafaelcorvino1_CVE-2025-53640.md) 🟡 ✅

**名称:** CVE-2025-53640 - Indico 用户信息泄露  
**类型:** 信息泄露/BOLA  
**风险:** 中危，可能导致个人信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2025-53640](https://github.com/rafaelcorvino1/CVE-2025-53640)  

---

### [CVE-2025-51862](CVE-2025-51862-Secsys-FDU_CVE-2025-51862.md) 🔴 ✅

**名称:** CVE-2025-51862 - TelegAI IDOR漏洞  
**类型:** IDOR (Insecure Direct Object Reference)  
**风险:** 高危，可能导致信息泄露、用户欺骗、账户劫持、XSS攻击  
**投毒风险:** 0%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2025-51862](https://github.com/Secsys-FDU/CVE-2025-51862)  

---

### [CVE-2025-20337](CVE-2025-20337-barbaraeivyu_CVE-2025-20337-EXP.md) 🔴 

**名称:** CVE-2025-20337-Cisco ISE API 未授权远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程攻击者可以root权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2025-20337-EXP](https://github.com/barbaraeivyu/CVE-2025-20337-EXP)  

---

### [CVE-2025-23266](CVE-2025-23266-jpts_cve-2025-23266-poc.md) 🔴 ✅

**名称:** CVE-2025-23266-NVIDIA Container Toolkit-权限提升/容器逃逸  
**类型:** 权限提升/容器逃逸  
**风险:** 高危，可能导致权限提升、数据篡改、信息泄露和拒绝服务  
**投毒风险:** 0%  
**发现时间:** 2025-07-19  
**POC仓库:** [cve-2025-23266-poc](https://github.com/jpts/cve-2025-23266-poc)  

---

### [CVE-2024-20767](CVE-2024-20767-Praison001_CVE-2024-20767-Adobe-ColdFusion.md) 🔴 ✅

**名称:** CVE-2024-20767-Adobe ColdFusion Improper Access Control  
**类型:** Improper Access Control / Arbitrary File Read  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2024-20767-Adobe-ColdFusion](https://github.com/Praison001/CVE-2024-20767-Adobe-ColdFusion)  

---

### [CVE-2025-51860](CVE-2025-51860-Secsys-FDU_CVE-2025-51860.md) 🔴 ✅

**名称:** CVE-2025-51860 - TelegAI Stored XSS  
**类型:** Stored Cross-Site Scripting (XSS)  
**风险:** 高危，可能导致账户劫持和敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2025-51860](https://github.com/Secsys-FDU/CVE-2025-51860)  

---

### [CVE-2025-51858](CVE-2025-51858-Secsys-FDU_CVE-2025-51858.md) 🔴 ✅

**名称:** CVE-2025-51858 - ChatPlayground.ai XSS 和 IDOR漏洞  
**类型:** 跨站脚本 (XSS) 和 不安全直接对象引用 (IDOR)  
**风险:** 高危，可能导致账户劫持和数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2025-51858](https://github.com/Secsys-FDU/CVE-2025-51858)  

---

### [CVE-2024-20767](CVE-2024-20767-m-cetin_CVE-2024-20767.md) 🔴 ✅

**名称:** CVE-2024-20767-Adobe ColdFusion-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2024-20767](https://github.com/m-cetin/CVE-2024-20767)  

---

### [CVE-2024-20767](CVE-2024-20767-Chocapikk_CVE-2024-20767.md) 🔴 ✅

**名称:** CVE-2024-20767 - Adobe ColdFusion 任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2024-20767](https://github.com/Chocapikk/CVE-2024-20767)  

---

### [CVE-2024-20767](CVE-2024-20767-yoryio_CVE-2024-20767.md) 🔴 ✅

**名称:** CVE-2024-20767-Adobe ColdFusion Improper Access Control  
**类型:** Improper Access Control/Arbitrary File Read  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2024-20767](https://github.com/yoryio/CVE-2024-20767)  

---

### [CVE-2024-20767](CVE-2024-20767-alm6no5_CVE-2024-20767.md) 🔴 ✅

**名称:** CVE-2024-20767-Adobe ColdFusion-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2024-20767](https://github.com/alm6no5/CVE-2024-20767)  

---

### [CVE-2025-51859](CVE-2025-51859-Secsys-FDU_CVE-2025-51859.md) 🔴 ✅

**名称:** CVE-2025-51859-Chaindesk-Stored XSS & IDOR  
**类型:** Stored XSS & IDOR (Insecure Direct Object Reference)  
**风险:** 高危，可能导致账户劫持，敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2025-51859](https://github.com/Secsys-FDU/CVE-2025-51859)  

---

### [CVE-2020-17519](CVE-2020-17519-yaunsky_CVE-2020-17519-Apache-Flink.md) 🔴 ✅

**名称:** CVE-2020-17519-Apache Flink 目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2020-17519-Apache-Flink](https://github.com/yaunsky/CVE-2020-17519-Apache-Flink)  

---

### [CVE-2020-17519](CVE-2020-17519-QmF0c3UK_CVE-2020-17519.md) 🔴 ✅

**名称:** CVE-2020-17519-Apache Flink-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2020-17519](https://github.com/QmF0c3UK/CVE-2020-17519)  

---

### [CVE-2020-17519](CVE-2020-17519-dolevf_apache-flink-directory-traversal.nse.md) 🔴 ✅

**名称:** CVE-2020-17519-Apache Flink 目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可读取JobManager进程可访问的任意文件  
**投毒风险:** 0%  
**发现时间:** 2025-07-19  
**POC仓库:** [apache-flink-directory-traversal.nse](https://github.com/dolevf/apache-flink-directory-traversal.nse)  

---

### [CVE-2020-17519](CVE-2020-17519-B1anda0_CVE-2020-17519.md) 🔴 ✅

**名称:** CVE-2020-17519-Apache Flink 目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2020-17519](https://github.com/B1anda0/CVE-2020-17519)  

---

### [CVE-2020-17519](CVE-2020-17519-murataydemir_CVE-2020-17519.md) 🔴 ✅

**名称:** CVE-2020-17519 - Apache Flink RESTful API 任意文件读取  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2020-17519](https://github.com/murataydemir/CVE-2020-17519)  

---

### [CVE-2020-17519](CVE-2020-17519-radbsie_CVE-2020-17519-Exp.md) 🔴 ✅

**名称:** CVE-2020-17519-Apache Flink-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2020-17519-Exp](https://github.com/radbsie/CVE-2020-17519-Exp)  

---

### [CVE-2020-17519](CVE-2020-17519-Osyanina_westone-CVE-2020-17519-scanner.md) 🔴 ✅

**名称:** CVE-2020-17519-Apache Flink 目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可读取 JobManager 进程可访问的任意文件  
**投毒风险:** 10%  
**发现时间:** 2025-07-19  
**POC仓库:** [westone-CVE-2020-17519-scanner](https://github.com/Osyanina/westone-CVE-2020-17519-scanner)  

---

### [CVE-2020-17519](CVE-2020-17519-givemefivw_CVE-2020-17519.md) 🔴 ✅

**名称:** CVE-2020-17519 Apache Flink 任意文件读取  
**类型:** 目录遍历/文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2020-17519](https://github.com/givemefivw/CVE-2020-17519)  

---

### [CVE-2020-17519](CVE-2020-17519-zhangweijie11_CVE-2020-17519.md) 🔴 ✅

**名称:** CVE-2020-17519-Apache Flink目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2020-17519](https://github.com/zhangweijie11/CVE-2020-17519)  

---

### [CVE-2020-17519](CVE-2020-17519-GazettEl_CVE-2020-17519.md) 🔴 ✅

**名称:** CVE-2020-17519-Apache Flink目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2020-17519](https://github.com/GazettEl/CVE-2020-17519)  

---

### [CVE-2020-17519](CVE-2020-17519-dev-team-12x_CVE-2020-17519.md) 🔴 ✅

**名称:** CVE-2020-17519 - Apache Flink 目录遍历  
**类型:** 目录遍历/文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2020-17519](https://github.com/dev-team-12x/CVE-2020-17519)  

---

### [CVE-2025-48384](CVE-2025-48384-Anezatraa_CVE-2025-48384-submodule.md) 🔴 ✅

**名称:** CVE-2025-48384-Git-任意代码执行  
**类型:** 任意代码执行  
**风险:** 高危，可能导致系统被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2025-48384-submodule](https://github.com/Anezatraa/CVE-2025-48384-submodule)  

---

### [CVE-2025-25257](CVE-2025-25257-mrmtwoj_CVE-2025-25257.md) 🔴 ✅

**名称:** CVE-2025-25257-FortiWeb-SQL注入到RCE  
**类型:** SQL注入  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-19  
**POC仓库:** [CVE-2025-25257](https://github.com/mrmtwoj/CVE-2025-25257)  

---

### [CVE-2025-7783](CVE-2025-7783-benweissmann_CVE-2025-7783-poc.md) 🟡 ✅

**名称:** form-data boundary randomness vulnerability  
**类型:** form-data boundary randomness vulnerability  
**风险:** 中危，可能导致权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-07-18  
**POC仓库:** [CVE-2025-7783-poc](https://github.com/benweissmann/CVE-2025-7783-poc)  

---

### [CVE-2021-32099](CVE-2021-32099-zjicmDarkWing_CVE-2021-32099.md) 🔴 ✅

**名称:** CVE-2021-32099-Pandora FMS-SQL注入  
**类型:** SQL注入  
**风险:** 高危，允许未授权访问和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-07-18  
**POC仓库:** [CVE-2021-32099](https://github.com/zjicmDarkWing/CVE-2021-32099)  

---

### [CVE-2025-47176](CVE-2025-47176-mahyarx_CVE-2025-47176.md) 🔴 ✅

**名称:** CVE-2025-47176-Microsoft Outlook远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在本地执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-07-18  
**POC仓库:** [CVE-2025-47176](https://github.com/mahyarx/CVE-2025-47176)  

---

### [CVE-2021-32099](CVE-2021-32099-ibnuuby_CVE-2021-32099.md) 🔴 ✅

**名称:** CVE-2021-32099-Artica Pandora FMS-SQL注入  
**类型:** SQL注入  
**风险:** 高危，允许未授权用户绕过身份验证并获得管理员权限  
**投毒风险:** 5%  
**发现时间:** 2025-07-18  
**POC仓库:** [CVE-2021-32099](https://github.com/ibnuuby/CVE-2021-32099)  

---

### [CVE-2021-32099](CVE-2021-32099-l3eol3eo_CVE-2021-32099_SQLi.md) 🔴 ✅

**名称:** CVE-2021-32099 - Artica Pandora FMS SQL 注入导致登录绕过  
**类型:** SQL 注入  
**风险:** 高危，可导致未授权访问和信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-07-18  
**POC仓库:** [CVE-2021-32099_SQLi](https://github.com/l3eol3eo/CVE-2021-32099_SQLi)  

---

### [CVE-2021-32099](CVE-2021-32099-akr3ch_CVE-2021-32099.md) 🔴 ✅

**名称:** CVE-2021-32099-Pandora FMS-SQL注入  
**类型:** SQL注入  
**风险:** 高危，未经身份验证的攻击者可以提升权限并绕过登录。  
**投毒风险:** 0%  
**发现时间:** 2025-07-18  
**POC仓库:** [CVE-2021-32099](https://github.com/akr3ch/CVE-2021-32099)  

---

### [CVE-2021-32099](CVE-2021-32099-magicrc_CVE-2021-32099.md) 🔴 ✅

**名称:** CVE-2021-32099-Artica Pandora FMS-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致未经授权访问和权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-07-18  
**POC仓库:** [CVE-2021-32099](https://github.com/magicrc/CVE-2021-32099)  

---

### [CVE-2024-27815](CVE-2024-27815-jprx_CVE-2024-27815.md) 🔴 ✅

**名称:** CVE-2024-27815-macOS-XNU内核缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可导致内核权限下的任意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-18  
**POC仓库:** [CVE-2024-27815](https://github.com/jprx/CVE-2024-27815)  

---

### [CVE-2025-53367](CVE-2025-53367-kevinbackhouse_DjVuLibre-poc-CVE-2025-53367.md) 🔴 ✅

**名称:** CVE-2025-53367-DjVuLibre-OOB-Write  
**类型:** OOB-Write（越界写）  
**风险:** 高危，可能导致堆损坏，代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-18  
**POC仓库:** [DjVuLibre-poc-CVE-2025-53367](https://github.com/kevinbackhouse/DjVuLibre-poc-CVE-2025-53367)  

---

### [CVE-2025-7753](CVE-2025-7753-byteReaper77_CVE-2025-7753.md) 🔴 ✅

**名称:** CVE-2025-7753-Online Appointment Booking System-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据库信息泄露和服务器控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-18  
**POC仓库:** [CVE-2025-7753](https://github.com/byteReaper77/CVE-2025-7753)  

---

### [CVE-2025-27210](CVE-2025-27210-B1ack4sh_Blackash-CVE-2025-27210.md) 🔴 ✅

**名称:** CVE-2025-27210 Node.js Windows 路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感文件泄露  
**投毒风险:** 0%  
**发现时间:** 2025-07-18  
**POC仓库:** [Blackash-CVE-2025-27210](https://github.com/B1ack4sh/Blackash-CVE-2025-27210)  

---

### [CVE-2021-3156](CVE-2021-3156-Maalfer_Sudo-CVE-2021-3156.md) 🔴 ✅

**名称:** CVE-2021-3156-Sudo-堆缓冲区溢出  
**类型:** 堆缓冲区溢出  
**风险:** 高危，可导致权限提升至root  
**投毒风险:** 10%  
**发现时间:** 2025-07-18  
**POC仓库:** [Sudo-CVE-2021-3156](https://github.com/Maalfer/Sudo-CVE-2021-3156)  

---

### [CVE-2022-44136](CVE-2022-44136-Ch35h1r3c47_CVE-2022-44136-poc.md) 🔴 ✅

**名称:** CVE-2022-44136-Zenar CMS 9.3 Remote Code Execution  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 95%  
**发现时间:** 2025-07-18  
**POC仓库:** [CVE-2022-44136-poc](https://github.com/Ch35h1r3c47/CVE-2022-44136-poc)  

---

### [CVE-2025-32463](CVE-2025-32463-MGunturG_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可提升至root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-18  
**POC仓库:** [CVE-2025-32463](https://github.com/MGunturG/CVE-2025-32463)  

---

### [CVE-2019-4716](CVE-2019-4716-Pranjal6955_CVE-2019-4716-Test-Environment.md)  ✅

**名称:** CVE-2019-4716 - IBM Planning Analytics 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致完全系统控制  
**投毒风险:** 5%  
**发现时间:** 2025-07-18  
**POC仓库:** [CVE-2019-4716-Test-Environment](https://github.com/Pranjal6955/CVE-2019-4716-Test-Environment)  

---

### [CVE-2025-27591](CVE-2025-27591-incommatose_CVE-2025-27591-PoC.md) 🔴 ✅

**名称:** CVE-2025-27591-Below-本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可提升至root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-18  
**POC仓库:** [CVE-2025-27591-PoC](https://github.com/incommatose/CVE-2025-27591-PoC)  

---

### [CVE-2025-25257](CVE-2025-25257-aitorfirm_CVE-2025-25257.md) 🔴 ✅

**名称:** CVE-2025-25257-FortiWeb-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-18  
**POC仓库:** [CVE-2025-25257](https://github.com/aitorfirm/CVE-2025-25257)  

---

### [CVE-2025-49113](CVE-2025-49113-hackmelocal_HML-CVE-2025-49113-Round-Cube.md) 🔴 ✅

**名称:** CVE-2025-49113-Roundcube-PHP对象反序列化  
**类型:** PHP对象反序列化  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-18  
**POC仓库:** [HML-CVE-2025-49113-Round-Cube](https://github.com/hackmelocal/HML-CVE-2025-49113-Round-Cube)  

---

### [CVE-2025-49113](CVE-2025-49113-Joelp03_CVE-2025-49113.md)  ✅

**名称:** CVE-2025-49113-Roundcube-RCE  
**类型:** PHP对象反序列化导致远程代码执行  
**风险:** 严重，可能导致完全控制受影响的服务器  
**投毒风险:** 5%  
**发现时间:** 2025-07-18  
**POC仓库:** [CVE-2025-49113](https://github.com/Joelp03/CVE-2025-49113)  

---

### [CVE-2025-47812](CVE-2025-47812-B1ack4sh_Blackash-CVE-2025-47812.md) 🔴 ✅

**名称:** CVE-2025-47812 - Wing FTP Server 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可完全控制服务器  
**投毒风险:** 0%  
**发现时间:** 2025-07-17  
**POC仓库:** [Blackash-CVE-2025-47812](https://github.com/B1ack4sh/Blackash-CVE-2025-47812)  

---

### [CVE-2025-6558](CVE-2025-6558-allinsthon_CVE-2025-6558-exp.md) 🔴 

**名称:** CVE-2025-6558-Google Chrome-沙箱逃逸  
**类型:** 沙箱逃逸  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-17  
**POC仓库:** [CVE-2025-6558-exp](https://github.com/allinsthon/CVE-2025-6558-exp)  

---

### [CVE-2025-30065](CVE-2025-30065-B1ack4sh_Blackash-CVE-2025-30065.md) 🔴 ✅

**名称:** CVE-2025-30065 Apache Parquet 反序列化RCE  
**类型:** 反序列化远程代码执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-17  
**POC仓库:** [Blackash-CVE-2025-30065](https://github.com/B1ack4sh/Blackash-CVE-2025-30065)  

---

### [CVE-2025-6558](CVE-2025-6558-karenucqki_CVE-2025-6558.md) 🔴 ✅

**名称:** CVE-2025-6558 - Google Chrome ANGLE/GPU Sandbox Escape  
**类型:** 沙箱逃逸 (Sandbox Escape)  
**风险:** 高危，允许远程攻击者执行任意代码并访问敏感资源  
**投毒风险:** 10%  
**发现时间:** 2025-07-17  
**POC仓库:** [CVE-2025-6558](https://github.com/karenucqki/CVE-2025-6558)  

---

### [CVE-2016-6210](CVE-2016-6210-KiPhuong_cve-2016-6210.md) 🟡 ✅

**名称:** CVE-2016-6210-OpenSSH-用户名枚举  
**类型:** 用户名枚举  
**风险:** 中危，允许攻击者枚举有效的用户名  
**投毒风险:** 5%  
**发现时间:** 2025-07-17  
**POC仓库:** [cve-2016-6210](https://github.com/KiPhuong/cve-2016-6210)  

---

### [CVE-2025-4660](CVE-2025-4660-NetSPI_CVE-2025-4660.md) 🔴 ✅

**名称:** CVE-2025-4660-Forescout SecureConnector-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程攻击者执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-07-17  
**POC仓库:** [CVE-2025-4660](https://github.com/NetSPI/CVE-2025-4660)  

---

### [CVE-2025-47812](CVE-2025-47812-blindma1den_CVE-2025-47812.md)  ✅

**名称:** CVE-2025-47812 - Wing FTP Server 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可导致完全服务器入侵  
**投毒风险:** 0%  
**发现时间:** 2025-07-17  
**POC仓库:** [CVE-2025-47812](https://github.com/blindma1den/CVE-2025-47812)  

---

### [CVE-2025-32463](CVE-2025-32463-Rajneeshkarya_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-17  
**POC仓库:** [CVE-2025-32463](https://github.com/Rajneeshkarya/CVE-2025-32463)  

---

### [CVE-2025-5777](CVE-2025-5777-cyberleelawat_ExploitVeer.md) 🔴 ✅

**名称:** CVE-2025-5777 Citrix NetScaler Memory Disclosure (CitrixBleed 2)  
**类型:** 内存信息泄露  
**风险:** 高危，可能导致敏感信息泄露，如session tokens。  
**投毒风险:** 10%  
**发现时间:** 2025-07-17  
**POC仓库:** [ExploitVeer](https://github.com/cyberleelawat/ExploitVeer)  

---

### [CVE-2025-48384](CVE-2025-48384-admin-ping_CVE-2025-48384-RCE.md) 🔴 ✅

**名称:** CVE-2025-48384-Git配置引号处理缺陷导致任意代码执行  
**类型:** 任意代码执行  
**风险:** 高危，可能导致系统被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-17  
**POC仓库:** [CVE-2025-48384-RCE](https://github.com/admin-ping/CVE-2025-48384-RCE)  

---

### [CVE-2020-14882](CVE-2020-14882-GGyao_CVE-2020-14882_POC.md) 🔴 ✅

**名称:** CVE-2020-14882 - Oracle WebLogic Server 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-17  
**POC仓库:** [CVE-2020-14882_POC](https://github.com/GGyao/CVE-2020-14882_POC)  

---

### [CVE-2020-14882](CVE-2020-14882-exploitblizzard_CVE-2020-14882-WebLogic.md) 🔴 ✅

**名称:** CVE-2020-14882 WebLogic Console RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-07-17  
**POC仓库:** [CVE-2020-14882-WebLogic](https://github.com/exploitblizzard/CVE-2020-14882-WebLogic)  

---

### [CVE-2020-14882](CVE-2020-14882-nik0nz7_CVE-2020-14882.md) 🔴 ✅

**名称:** CVE-2020-14882 - Oracle WebLogic Server RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未授权的攻击者完全控制 WebLogic Server  
**投毒风险:** 5%  
**发现时间:** 2025-07-17  
**POC仓库:** [CVE-2020-14882](https://github.com/nik0nz7/CVE-2020-14882)  

---

### [CVE-2020-14882](CVE-2020-14882-Ormicron_CVE-2020-14882-GUI-Test.md) 🔴 ✅

**名称:** CVE-2020-14882-Oracle WebLogic Server 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-17  
**POC仓库:** [CVE-2020-14882-GUI-Test](https://github.com/Ormicron/CVE-2020-14882-GUI-Test)  

---

### [CVE-2020-14882](CVE-2020-14882-QmF0c3UK_CVE-2020-14882.md) 🔴 ✅

**名称:** CVE-2020-14882-Oracle WebLogic Server-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-17  
**POC仓库:** [CVE-2020-14882](https://github.com/QmF0c3UK/CVE-2020-14882)  

---

### [CVE-2020-14882](CVE-2020-14882-xfiftyone_CVE-2020-14882.md) 🔴 ✅

**名称:** CVE-2020-14882-Oracle WebLogic Server 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未授权的攻击者完全控制WebLogic服务器  
**投毒风险:** 10%  
**发现时间:** 2025-07-17  
**POC仓库:** [CVE-2020-14882](https://github.com/xfiftyone/CVE-2020-14882)  

---

### [CVE-2020-14882](CVE-2020-14882-jas502n_CVE-2020-14882.md) 🔴 ✅

**名称:** CVE-2020-14882 WebLogic 未授权绕过RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-17  
**POC仓库:** [CVE-2020-14882](https://github.com/jas502n/CVE-2020-14882)  

---

### [CVE-2020-14882](CVE-2020-14882-corelight_CVE-2020-14882-weblogicRCE.md) 🔴 ✅

**名称:** CVE-2020-14882 - Oracle WebLogic RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的攻击者完全控制WebLogic Server  
**投毒风险:** 5%  
**发现时间:** 2025-07-17  
**POC仓库:** [CVE-2020-14882-weblogicRCE](https://github.com/corelight/CVE-2020-14882-weblogicRCE)  

---

### [CVE-2020-14882](CVE-2020-14882-adm1in_CodeTest.md) 🔴 ✅

**名称:** CVE-2020-14882-Oracle WebLogic Server远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 20%  
**发现时间:** 2025-07-17  
**POC仓库:** [CodeTest](https://github.com/adm1in/CodeTest)  

---

### [CVE-2020-14882](CVE-2020-14882-kk98kk0_CVE-2020-14882.md) 🔴 ✅

**名称:** CVE-2020-14882-Oracle WebLogic Server-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-17  
**POC仓库:** [CVE-2020-14882](https://github.com/kk98kk0/CVE-2020-14882)  

---

### [CVE-2020-14882](CVE-2020-14882-pwn3z_CVE-2020-14882-WebLogic.md) 🔴 ✅

**名称:** CVE-2020-14882-Oracle WebLogic Server 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-17  
**POC仓库:** [CVE-2020-14882-WebLogic](https://github.com/pwn3z/CVE-2020-14882-WebLogic)  

---

### [CVE-2020-14882](CVE-2020-14882-milo2012_CVE-2020-14882.md) 🔴 ✅

**名称:** CVE-2020-14882-Oracle WebLogic Server-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-07-17  
**POC仓库:** [CVE-2020-14882](https://github.com/milo2012/CVE-2020-14882)  

---

### [CVE-2020-14882](CVE-2020-14882-zhzyker_exphub.md) 🔴 ✅

**名称:** CVE-2020-14882 - Oracle WebLogic Server 未授权远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-17  
**POC仓库:** [exphub](https://github.com/zhzyker/exphub)  

---

### [CVE-2020-14882](CVE-2020-14882-qianniaoge_CVE-2020-14882_Exploit_Gui.md) 🔴 ✅

**名称:** CVE-2020-14882-Oracle WebLogic Server RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-17  
**POC仓库:** [CVE-2020-14882_Exploit_Gui](https://github.com/qianniaoge/CVE-2020-14882_Exploit_Gui)  

---

### [CVE-2020-14882](CVE-2020-14882-N0Coriander_CVE-2020-14882-14883.md) 🔴 ✅

**名称:** CVE-2020-14882/CVE-2020-14883 WebLogic 未授权远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可完全控制WebLogic服务器  
**投毒风险:** 0%  
**发现时间:** 2025-07-17  
**POC仓库:** [CVE-2020-14882-14883](https://github.com/N0Coriander/CVE-2020-14882-14883)  

---

### [CVE-2020-14882](CVE-2020-14882-GGyao_CVE-2020-14882_ALL.md) 🔴 ✅

**名称:** CVE-2020-14882-Oracle WebLogic Server-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-07-17  
**POC仓库:** [CVE-2020-14882_ALL](https://github.com/GGyao/CVE-2020-14882_ALL)  

---

### [CVE-2020-14882](CVE-2020-14882-Danny-LLi_CVE-2020-14882.md) 🔴 ✅

**名称:** CVE-2020-14882 Oracle WebLogic Server 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可完全控制WebLogic Server  
**投毒风险:** 1%  
**发现时间:** 2025-07-17  
**POC仓库:** [CVE-2020-14882](https://github.com/Danny-LLi/CVE-2020-14882)  

---

### [CVE-2020-14882](CVE-2020-14882-xMr110_CVE-2020-14882.md) 🔴 ✅

**名称:** CVE-2020-14882-Oracle WebLogic Server-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可以完全控制WebLogic Server  
**投毒风险:** 5%  
**发现时间:** 2025-07-17  
**POC仓库:** [CVE-2020-14882](https://github.com/xMr110/CVE-2020-14882)  

---

### [CVE-2020-14882](CVE-2020-14882-LucasPDiniz_CVE-2020-14882.md) 🔴 ✅

**名称:** CVE-2020-14882 - Oracle WebLogic RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可完全控制受影响的WebLogic Server  
**投毒风险:** 5%  
**发现时间:** 2025-07-17  
**POC仓库:** [CVE-2020-14882](https://github.com/LucasPDiniz/CVE-2020-14882)  

---

### [CVE-2020-14882](CVE-2020-14882-zesnd_CVE-2020-14882-POC.md) 🔴 ✅

**名称:** CVE-2020-14882-Oracle WebLogic Server-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-07-17  
**POC仓库:** [CVE-2020-14882-POC](https://github.com/zesnd/CVE-2020-14882-POC)  

---

### [CVE-2020-14882](CVE-2020-14882-Root-Shells_CVE-2020-14882.md) 🔴 ✅

**名称:** CVE-2020-14882-Oracle WebLogic-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-17  
**POC仓库:** [CVE-2020-14882](https://github.com/Root-Shells/CVE-2020-14882)  

---

### [CVE-2020-14882](CVE-2020-14882-AleksaZatezalo_CVE-2020-14882.md) 🔴 ✅

**名称:** CVE-2020-14882-Oracle WebLogic Server-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-17  
**POC仓库:** [CVE-2020-14882](https://github.com/AleksaZatezalo/CVE-2020-14882)  

---

### [CVE-2025-27521](CVE-2025-27521-alialucas7_CVE-2025-27521_PoC.md) 🟡 ✅

**名称:** CVE-2025-27521-HarmonyOS-权限提升  
**类型:** 权限提升  
**风险:** 中危，可能影响服务机密性  
**投毒风险:** 1%  
**发现时间:** 2025-07-16  
**POC仓库:** [CVE-2025-27521_PoC](https://github.com/alialucas7/CVE-2025-27521_PoC)  

---

### [CVE-2025-53964](CVE-2025-53964-tigr78_CVE-2025-53964.md) 🔴 ✅

**名称:** CVE-2024-53964/CVE-2025-53964 - Adobe Experience Manager/GoldenDict Stored XSS/File Access  
**类型:** Stored Cross-Site Scripting (XSS)/File Access  
**风险:** 高危，可能导致任意代码执行和敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-07-16  
**POC仓库:** [CVE-2025-53964](https://github.com/tigr78/CVE-2025-53964)  

---

### [CVE-2025-22870](CVE-2025-22870-B1ack4sh_Blackash-CVE-2025-22870.md) 🟡 ✅

**名称:** CVE-2025-22870-golang-x-net-HTTP代理绕过  
**类型:** HTTP代理绕过  
**风险:** 中危，可能导致SSRF  
**投毒风险:** 95%  
**发现时间:** 2025-07-16  
**POC仓库:** [Blackash-CVE-2025-22870](https://github.com/B1ack4sh/Blackash-CVE-2025-22870)  

---

### [CVE-2025-32463](CVE-2025-32463-92gmuz_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，允许本地用户获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-16  
**POC仓库:** [CVE-2025-32463](https://github.com/92gmuz/CVE-2025-32463)  

---

### [CVE-2013-3900](CVE-2013-3900-malaya-m_cve-2013-3900-remediation-report.md) 🔴 ✅

**名称:** CVE-2013-3900 WinVerifyTrust Signature Validation Vulnerability  
**类型:** 签名验证绕过  
**风险:** 中危/高危，取决于用户权限，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-16  
**POC仓库:** [cve-2013-3900-remediation-report](https://github.com/malaya-m/cve-2013-3900-remediation-report)  

---

### [CVE-2019-9053](CVE-2019-9053-Kalidas-7_CVE-2019-9053.md) 🔴 ✅

**名称:** CVE-2019-9053 - CMS Made Simple 未授权盲注SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和权限提升  
**投毒风险:** 1%  
**发现时间:** 2025-07-16  
**POC仓库:** [CVE-2019-9053](https://github.com/Kalidas-7/CVE-2019-9053)  

---

### [CVE-2025-5777](CVE-2025-5777-B1ack4sh_Blackash-CVE-2025-5777.md) 🔴 ✅

**名称:** CVE-2025-5777-NetScaler内存泄露  
**类型:** 内存泄露  
**风险:** 高危，泄露敏感信息  
**投毒风险:** 5%  
**发现时间:** 2025-07-16  
**POC仓库:** [Blackash-CVE-2025-5777](https://github.com/B1ack4sh/Blackash-CVE-2025-5777)  

---

### [CVE-2025-32463](CVE-2025-32463-Floodnut_CVE-2025-32463.md) 🔴 

**名称:** CVE-2025-32463-Sudo-本地权限提升  
**类型:** 本地权限提升  
**风险:** 高危，允许本地用户获取Root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-16  
**POC仓库:** [CVE-2025-32463](https://github.com/Floodnut/CVE-2025-32463)  

---

### [CVE-2025-32463](CVE-2025-32463-krypton-0x00_CVE-2025-32463-Chwoot-POC.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可获取Root权限  
**投毒风险:** 1%  
**发现时间:** 2025-07-16  
**POC仓库:** [CVE-2025-32463-Chwoot-POC](https://github.com/krypton-0x00/CVE-2025-32463-Chwoot-POC)  

---

### [CVE-2025-52689](CVE-2025-52689-UltimateHG_CVE-2025-52689-PoC.md)  ✅

**名称:** CVE-2025-52689 Alcatel-Lucent OmniAccess Stellar AP 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 严重，可能导致未授权访问和设备控制  
**投毒风险:** 0%  
**发现时间:** 2025-07-16  
**POC仓库:** [CVE-2025-52689-PoC](https://github.com/UltimateHG/CVE-2025-52689-PoC)  

---

### [CVE-2025-52688](CVE-2025-52688-joelczk_CVE-2025-52688.md)  ✅

**名称:** CVE-2025-52688 - Alcatel OmniAccess Stellar Command Injection  
**类型:** 命令注入/任意文件读取  
**风险:** 严重，可能导致信息泄露、权限提升、完全控制设备  
**投毒风险:** 0%  
**发现时间:** 2025-07-16  
**POC仓库:** [CVE-2025-52688](https://github.com/joelczk/CVE-2025-52688)  

---

### [CVE-2025-32432](CVE-2025-32432-CTY-Research-1_CVE-2025-32432-PoC.md) 🔴 ✅

**名称:** CVE-2025-32432-CraftCMS-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致完全控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-07-16  
**POC仓库:** [CVE-2025-32432-PoC](https://github.com/CTY-Research-1/CVE-2025-32432-PoC)  

---

### [CVE-2025-32432](CVE-2025-32432-B1ack4sh_Blackash-CVE-2025-32432.md) 🔴 ✅

**名称:** CVE-2025-32432-CraftCMS-RCE  
**类型:** 远程代码执行  
**风险:** 高危，未经授权的攻击者可以执行任意代码，完全控制系统  
**投毒风险:** 5%  
**发现时间:** 2025-07-16  
**POC仓库:** [Blackash-CVE-2025-32432](https://github.com/B1ack4sh/Blackash-CVE-2025-32432)  

---

### [CVE-2025-27210](CVE-2025-27210-absholi7ly_CVE-2025-27210_NodeJS_Path_Traversal_Exploit.md) 🔴 ✅

**名称:** CVE-2025-27210-NodeJS Path Traversal  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-07-16  
**POC仓库:** [CVE-2025-27210_NodeJS_Path_Traversal_Exploit](https://github.com/absholi7ly/CVE-2025-27210_NodeJS_Path_Traversal_Exploit)  

---

### [CVE-2025-47812](CVE-2025-47812-rxerium_CVE-2025-47812.md)  ✅

**名称:** CVE-2025-47812 - Wing FTP Server 远程代码执行  
**类型:** 远程代码执行  
**风险:** 严重，可能导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-07-16  
**POC仓库:** [CVE-2025-47812](https://github.com/rxerium/CVE-2025-47812)  

---

### [CVE-2025-48384](CVE-2025-48384-nguyentranbaotran_cve-2025-48384-poc.md) 🔴 ✅

**名称:** CVE-2025-48384-Git配置引用导致的任意代码执行  
**类型:** 代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-16  
**POC仓库:** [cve-2025-48384-poc](https://github.com/nguyentranbaotran/cve-2025-48384-poc)  

---

### [CVE-2022-25226](CVE-2022-25226-krill-x7_CVE-2022-25226.md) 🔴 ✅

**名称:** CVE-2022-25226 - ThinVNC 1.0b1 Authentication Bypass to Remote Code Execution  
**类型:** 身份验证绕过 + 远程代码执行  
**风险:** 高危，可导致远程代码执行并完全控制服务器  
**投毒风险:** 5%  
**发现时间:** 2025-07-16  
**POC仓库:** [CVE-2022-25226](https://github.com/krill-x7/CVE-2022-25226)  

---

### [CVE-2024-4577](CVE-2024-4577-Skycritch_CVE-2024-4577.md) 🔴 ✅

**名称:** CVE-2024-4577 PHP CGI Argument Injection  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-07-16  
**POC仓库:** [CVE-2024-4577](https://github.com/Skycritch/CVE-2024-4577)  

---

### [CVE-2025-32463](CVE-2025-32463-MohamedKarrab_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可获取Root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-15  
**POC仓库:** [CVE-2025-32463](https://github.com/MohamedKarrab/CVE-2025-32463)  

---

### [CVE-2025-23167](CVE-2025-23167-abhisek3122_CVE-2025-23167.md) 🟡 ✅

**名称:** CVE-2025-23167-Node.js HTTP Request Smuggling  
**类型:** HTTP请求走私  
**风险:** 中危，可能绕过代理访问控制，导致未授权请求  
**投毒风险:** 0%  
**发现时间:** 2025-07-15  
**POC仓库:** [CVE-2025-23167](https://github.com/abhisek3122/CVE-2025-23167)  

---

### [CVE-2025-32463](CVE-2025-32463-9Insomnie_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，允许本地用户获得root权限  
**投毒风险:** 5%  
**发现时间:** 2025-07-15  
**POC仓库:** [CVE-2025-32463](https://github.com/9Insomnie/CVE-2025-32463)  

---

### [CVE-2025-5349](CVE-2025-5349-olimpiofreitas_CVE-2025-5349-Scanner.md) 🔴 ✅

**名称:** CVE-2025-5349-NetScaler-Improper Access Control  
**类型:** 权限控制漏洞  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-15  
**POC仓库:** [CVE-2025-5349-Scanner](https://github.com/olimpiofreitas/CVE-2025-5349-Scanner)  

---

### [CVE-2025-27591](CVE-2025-27591-dollarboysushil_Linux-Privilege-Escalation-CVE-2025-27591.md) 🔴 ✅

**名称:** CVE-2025-27591-below-特权提升  
**类型:** 特权提升  
**风险:** 高危，允许本地普通用户提升为root权限  
**投毒风险:** 0%  
**发现时间:** 2025-07-15  
**POC仓库:** [Linux-Privilege-Escalation-CVE-2025-27591](https://github.com/dollarboysushil/Linux-Privilege-Escalation-CVE-2025-27591)  

---

### [CVE-2025-27591](CVE-2025-27591-DarksBlackSk_CVE-2025-27591.md) 🔴 ✅

**名称:** CVE-2025-27591-Below-权限提升  
**类型:** 权限提升  
**风险:** 高危，可能导致权限提升至root  
**投毒风险:** 0%  
**发现时间:** 2025-07-15  
**POC仓库:** [CVE-2025-27591](https://github.com/DarksBlackSk/CVE-2025-27591)  

---

### [CVE-2025-47981](CVE-2025-47981-detectrespondrepeat_CVE-2025-47981.md) 🔴 ✅

**名称:** CVE-2025-47981 Windows SPNEGO Extended Negotiation RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经授权的攻击者通过网络执行代码  
**投毒风险:** 10%  
**发现时间:** 2025-07-15  
**POC仓库:** [CVE-2025-47981](https://github.com/detectrespondrepeat/CVE-2025-47981)  

---

### [CVE-2025-48384](CVE-2025-48384-ECHO6789_CVE-2025-48384-submodule.md) 🔴 ✅

**名称:** CVE-2025-48384-Git-任意代码执行  
**类型:** 任意代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-15  
**POC仓库:** [CVE-2025-48384-submodule](https://github.com/ECHO6789/CVE-2025-48384-submodule)  

---

### [CVE-2025-25257](CVE-2025-25257-0xgh057r3c0n_CVE-2025-25257.md) 🔴 ✅

**名称:** CVE-2025-25257-FortiWeb-SQL注入  
**类型:** SQL注入  
**风险:** 高危，导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-15  
**POC仓库:** [CVE-2025-25257](https://github.com/0xgh057r3c0n/CVE-2025-25257)  

---

### [CVE-2025-53833](CVE-2025-53833-B1ack4sh_Blackash-CVE-2025-53833.md) 🔴 ✅

**名称:** CVE-2025-53833-LaRecipe-SSTI  
**类型:** 服务器端模板注入 (SSTI)  
**风险:** 高危，可能导致远程代码执行 (RCE)  
**投毒风险:** 5%  
**发现时间:** 2025-07-15  
**POC仓库:** [Blackash-CVE-2025-53833](https://github.com/B1ack4sh/Blackash-CVE-2025-53833)  

---

### [CVE-2016-0792](CVE-2016-0792-jpiechowka_jenkins-cve-2016-0792.md) 🔴 ✅

**名称:** CVE-2016-0792 Jenkins XStream Groovy classpath Deserialization  
**类型:** 反序列化漏洞  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-15  
**POC仓库:** [jenkins-cve-2016-0792](https://github.com/jpiechowka/jenkins-cve-2016-0792)  

---

### [CVE-2016-0792](CVE-2016-0792-Aviksaikat_CVE-2016-0792.md) 🔴 ✅

**名称:** CVE-2016-0792-Jenkins-反序列化RCE  
**类型:** 反序列化RCE  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-07-15  
**POC仓库:** [CVE-2016-0792](https://github.com/Aviksaikat/CVE-2016-0792)  

---

### [CVE-2016-0792](CVE-2016-0792-gonn4cry_CVE-2016-0792.md) 🔴 ✅

**名称:** CVE-2016-0792-Jenkins-远程代码执行  
**类型:** 反序列化漏洞  
**风险:** 高危，允许远程认证用户执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-07-15  
**POC仓库:** [CVE-2016-0792](https://github.com/gonn4cry/CVE-2016-0792)  

---

### [CVE-2022-46463](CVE-2022-46463-404tk_CVE-2022-46463.md) 🔴 ✅

**名称:** CVE-2022-46463-Harbor-未授权访问  
**类型:** 未授权访问  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-07-15  
**POC仓库:** [CVE-2022-46463](https://github.com/404tk/CVE-2022-46463)  

---

### [CVE-2022-46463](CVE-2022-46463-CodeSecurityTeam_harbor.md) 🔴 ✅

**名称:** CVE-2022-46463-Harbor-未授权访问  
**类型:** 未授权访问  
**风险:** 高危，可能导致敏感信息泄露，供应链投毒  
**投毒风险:** 5%  
**发现时间:** 2025-07-15  
**POC仓库:** [harbor](https://github.com/CodeSecurityTeam/harbor)  

---

### [CVE-2022-46463](CVE-2022-46463-nu0l_CVE-2022-46463.md) 🔴 ✅

**名称:** CVE-2022-46463-Harbor-未授权访问  
**类型:** 未授权访问  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-07-15  
**POC仓库:** [CVE-2022-46463](https://github.com/nu0l/CVE-2022-46463)  

---

### [CVE-2025-5777](CVE-2025-5777-SleepNotF0und_CVE-2025-5777.md) 🔴 ✅

**名称:** CVE-2025-5777-NetScaler-内存信息泄露  
**类型:** 内存信息泄露  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-07-15  
**POC仓库:** [CVE-2025-5777](https://github.com/SleepNotF0und/CVE-2025-5777)  

---

### [CVE-2025-7340](CVE-2025-7340-Nxploited_CVE-2025-7340.md) 🔴 ✅

**名称:** CVE-2025-7340 HT Contact Form Widget Plugin 未授权任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-07-15  
**POC仓库:** [CVE-2025-7340](https://github.com/Nxploited/CVE-2025-7340)  

---

### [CVE-2025-32463](CVE-2025-32463-dbarquero_cve-2025-32463-lab.md)  ✅

**名称:** CVE-2025-32463-Sudo-本地权限提升  
**类型:** 本地权限提升  
**风险:** 严重，允许本地用户获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-15  
**POC仓库:** [cve-2025-32463-lab](https://github.com/dbarquero/cve-2025-32463-lab)  

---

### [CVE-2023-5360](CVE-2023-5360-X3RX3SSec_CVE-2023-5360.md) 🔴 ✅

**名称:** CVE-2023-5360 - Royal Elementor Addons and Templates - Unauthenticated Arbitrary File Upload  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行 (RCE)  
**投毒风险:** 0%  
**发现时间:** 2025-07-14  
**POC仓库:** [CVE-2023-5360](https://github.com/X3RX3SSec/CVE-2023-5360)  

---

### [CVE-2023-5360](CVE-2023-5360-sagsooz_CVE-2023-5360.md) 🔴 ✅

**名称:** CVE-2023-5360 - Royal Elementor Addons and Templates - Unauthenticated Arbitrary File Upload  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 85%  
**发现时间:** 2025-07-14  
**POC仓库:** [CVE-2023-5360](https://github.com/sagsooz/CVE-2023-5360)  

---

### [CVE-2023-5360](CVE-2023-5360-nastar-id_CVE-2023-5360.md) 🔴 ✅

**名称:** CVE-2023-5360 - Royal Elementor Addons and Templates Arbitrary File Upload  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-14  
**POC仓库:** [CVE-2023-5360](https://github.com/nastar-id/CVE-2023-5360)  

---

### [CVE-2023-5360](CVE-2023-5360-Chocapikk_CVE-2023-5360.md) 🔴 ✅

**名称:** CVE-2023-5360 - Royal Elementor Addons and Templates 未授权任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-14  
**POC仓库:** [CVE-2023-5360](https://github.com/Chocapikk/CVE-2023-5360)  

---

### [CVE-2023-5360](CVE-2023-5360-Pushkarup_CVE-2023-5360.md) 🔴 ✅

**名称:** CVE-2023-5360 - Royal Elementor Addons and Templates 未授权任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-07-14  
**POC仓库:** [CVE-2023-5360](https://github.com/Pushkarup/CVE-2023-5360)  

---

### [CVE-2023-5360](CVE-2023-5360-tucommenceapousser_CVE-2023-5360.md) 🔴 ✅

**名称:** CVE-2023-5360 - Royal Elementor Addons and Templates - 未经验证的任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-14  
**POC仓库:** [CVE-2023-5360](https://github.com/tucommenceapousser/CVE-2023-5360)  

---

### [CVE-2023-5360](CVE-2023-5360-phankz_Worpress-CVE-2023-5360.md) 🔴 ✅

**名称:** CVE-2023-5360 - Royal Elementor Addons and Templates - 任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 95%  
**发现时间:** 2025-07-14  
**POC仓库:** [Worpress-CVE-2023-5360](https://github.com/phankz/Worpress-CVE-2023-5360)  

---

### [CVE-2023-5360](CVE-2023-5360-Jenderal92_WP-CVE-2023-5360.md) 🔴 ✅

**名称:** CVE-2023-5360-Royal Elementor Addons and Templates-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-14  
**POC仓库:** [WP-CVE-2023-5360](https://github.com/Jenderal92/WP-CVE-2023-5360)  

---

### [CVE-2025-1974](CVE-2025-1974-Armand2002_Exploit-CVE-2025-1974-Lab.md)  ✅

**名称:** CVE-2025-1974-ingress-nginx RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致集群范围内的 Secrets 泄露和完全控制。  
**投毒风险:** 0%  
**发现时间:** 2025-07-14  
**POC仓库:** [Exploit-CVE-2025-1974-Lab](https://github.com/Armand2002/Exploit-CVE-2025-1974-Lab)  

---

### [CVE-2025-44137](CVE-2025-44137-mheranco_CVE-2025-44137.md) 🔴 ✅

**名称:** CVE-2025-44137-MapTiler Tileserver-php 未授权文件读取  
**类型:** 目录遍历/文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-07-14  
**POC仓库:** [CVE-2025-44137](https://github.com/mheranco/CVE-2025-44137)  

---

### [CVE-2025-44136](CVE-2025-44136-mheranco_CVE-2025-44136.md) 🟡 ✅

**名称:** CVE-2025-44136 - MapTiler Tileserver-php XSS  
**类型:** 跨站脚本 (XSS)  
**风险:** 中危，可能导致用户凭据泄露和恶意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-14  
**POC仓库:** [CVE-2025-44136](https://github.com/mheranco/CVE-2025-44136)  

---

### [CVE-2025-27415](CVE-2025-27415-jiseoung_CVE-2025-27415-PoC.md) 🔴 ✅

**名称:** CVE-2025-27415-Nuxt3缓存投毒  
**类型:** 缓存投毒  
**风险:** 高危，可能导致拒绝服务（DoS）  
**投毒风险:** 1%  
**发现时间:** 2025-07-14  
**POC仓库:** [CVE-2025-27415-PoC](https://github.com/jiseoung/CVE-2025-27415-PoC)  

---

### [CVE-2025-25257](CVE-2025-25257-mtjanus106_CVE-2025-25257.md) 🔴 ✅

**名称:** CVE-2025-25257-FortiWeb-SQL注入  
**类型:** SQL注入  
**风险:** 高危，允许未经身份验证的攻击者执行任意SQL命令，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-14  
**POC仓库:** [CVE-2025-25257](https://github.com/mtjanus106/CVE-2025-25257)  

---

### [CVE-2025-52488](CVE-2025-52488-SystemVll_CVE-2025-52488.md) 🔴 ✅

**名称:** CVE-2025-52488-DNN.Platform-NTLM Hash Disclosure  
**类型:** NTLM Hash Disclosure  
**风险:** 高危，可能导致权限提升和横向渗透  
**投毒风险:** 10%  
**发现时间:** 2025-07-14  
**POC仓库:** [CVE-2025-52488](https://github.com/SystemVll/CVE-2025-52488)  

---

### [CVE-2025-7605](CVE-2025-7605-sunhuiHi666_CVE-2025-7605.md) 🔴 ✅

**名称:** CVE-2025-7605 - code-projects AVL Rooms profile.php sql 注入  
**类型:** SQL 注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-14  
**POC仓库:** [CVE-2025-7605](https://github.com/sunhuiHi666/CVE-2025-7605)  

---

### [CVE-2025-49493](CVE-2025-49493-SystemVll_CVE-2025-49493.md) 🟡 ✅

**名称:** CVE-2025-49493-Akamai CloudTest-XXE注入  
**类型:** XML外部实体注入 (XXE)  
**风险:** 中危 (CVSS 5.8)，可能导致文件包含、信息泄露、SSRF，严重情况下可能RCE  
**投毒风险:** 10%  
**发现时间:** 2025-07-14  
**POC仓库:** [CVE-2025-49493](https://github.com/SystemVll/CVE-2025-49493)  

---

### [CVE-2025-48827](CVE-2025-48827-SystemVll_CVE-2025-48827.md) 🔴 ✅

**名称:** CVE-2025-48827 - vBulletin Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致远程代码执行和完全系统compromise  
**投毒风险:** 10%  
**发现时间:** 2025-07-14  
**POC仓库:** [CVE-2025-48827](https://github.com/SystemVll/CVE-2025-48827)  

---

### [CVE-2025-7606](CVE-2025-7606-sunhuiHi666_CVE-2025-7606.md) 🔴 ✅

**名称:** CVE-2025-7606  
**类型:** SQL注入/XSS  
**风险:** 高危，可能导致数据泄露、权限提升和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-14  
**POC仓库:** [CVE-2025-7606](https://github.com/sunhuiHi666/CVE-2025-7606)  

---

### [CVE-2025-31125](CVE-2025-31125-harshgupptaa_Path-Transversal-CVE-2025-31125-.md) 🟡 ✅

**名称:** CVE-2025-31125-Vite-任意文件读取  
**类型:** 任意文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-07-13  
**POC仓库:** [Path-Transversal-CVE-2025-31125-](https://github.com/harshgupptaa/Path-Transversal-CVE-2025-31125-)  

---

### [CVE-2020-35848](CVE-2020-35848-sabbu143s_CVE_2020_35848.md) 🔴 ✅

**名称:** CVE-2020-35848 - Agentejo Cockpit NoSQL注入  
**类型:** NoSQL注入  
**风险:** 高危，可能导致用户名枚举，密码重置，最终可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-07-13  
**POC仓库:** [CVE_2020_35848](https://github.com/sabbu143s/CVE_2020_35848)  

---

### [CVE-2025-4593](CVE-2025-4593-karenucqki_CVE-2025-4593.md) 🟡 ✅

**名称:** CVE-2025-4593-WP Register Profile With Shortcode-敏感信息泄露  
**类型:** 敏感信息泄露  
**风险:** 中危，可能导致敏感用户信息泄露，如哈希密码、用户名等  
**投毒风险:** 10%  
**发现时间:** 2025-07-13  
**POC仓库:** [CVE-2025-4593](https://github.com/karenucqki/CVE-2025-4593)  

---

### [CVE-2025-22457](CVE-2025-22457-B1ack4sh_Blackash-CVE-2025-22457.md) 🔴 ✅

**名称:** CVE-2025-22457-Ivanti Connect Secure-栈溢出  
**类型:** 栈溢出  
**风险:** 高危，远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-07-13  
**POC仓库:** [Blackash-CVE-2025-22457](https://github.com/B1ack4sh/Blackash-CVE-2025-22457)  

---

### [CVE-2025-27591](CVE-2025-27591-BridgerAlderson_CVE-2025-27591-PoC.md) 🔴 ✅

**名称:** CVE-2025-27591-below-权限提升  
**类型:** 权限提升  
**风险:** 高危，可能导致本地用户提升为root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-13  
**POC仓库:** [CVE-2025-27591-PoC](https://github.com/BridgerAlderson/CVE-2025-27591-PoC)  

---

### [CVE-2025-47981](CVE-2025-47981-barbaraogmgf_CVE-2025-47981-POC.md) 🔴 ✅

**名称:** CVE-2025-47981 Windows SPNEGO Extended Negotiation RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经授权的攻击者通过网络执行任意代码  
**投毒风险:** 20%  
**发现时间:** 2025-07-13  
**POC仓库:** [CVE-2025-47981-POC](https://github.com/barbaraogmgf/CVE-2025-47981-POC)  

---

### [CVE-2025-6058](CVE-2025-6058-JayVillain_Scan-CVE-2025-6058.md) 🔴 ✅

**名称:** CVE-2025-6058 - WPBookit Unauthenticated Arbitrary File Upload  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-13  
**POC仓库:** [Scan-CVE-2025-6058](https://github.com/JayVillain/Scan-CVE-2025-6058)  

---

### [CVE-2025-34085](CVE-2025-34085-ill-deed_CVE-2025-34085-Multi-target.md) 🔴 ✅

**名称:** CVE-2025-34085 - WordPress Simple File List Plugin RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的远程攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-07-13  
**POC仓库:** [CVE-2025-34085-Multi-target](https://github.com/ill-deed/CVE-2025-34085-Multi-target)  

---

### [CVE-2025-27591](CVE-2025-27591-rvizx_CVE-2025-27591.md) 🔴 ✅

**名称:** CVE-2025-27591-Below-本地提权  
**类型:** 本地提权  
**风险:** 高危，可导致本地用户提升为root权限  
**投毒风险:** 5%  
**发现时间:** 2025-07-12  
**POC仓库:** [CVE-2025-27591](https://github.com/rvizx/CVE-2025-27591)  

---

### [CVE-2025-27591](CVE-2025-27591-obamalaolu_CVE-2025-27591.md) 🔴 ✅

**名称:** CVE-2025-27591-below-权限提升  
**类型:** 权限提升  
**风险:** 高危，本地用户可以提升到root权限  
**投毒风险:** 0%  
**发现时间:** 2025-07-12  
**POC仓库:** [CVE-2025-27591](https://github.com/obamalaolu/CVE-2025-27591)  

---

### [CVE-2025-6058](CVE-2025-6058-Nxploited_CVE-2025-6058.md) 🔴 ✅

**名称:** CVE-2025-6058 WPBookit <= 1.0.4 - Unauthenticated Arbitrary File Upload  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-07-12  
**POC仓库:** [CVE-2025-6058](https://github.com/Nxploited/CVE-2025-6058)  

---

### [CVE-2024-24919](CVE-2024-24919-MacUchegit_Detecting-and-Analyzing-CVE-2024-24919-Exploitation.md) 🔴 ✅

**名称:** CVE-2024-24919 - Check Point Security Gateway 信息泄露漏洞  
**类型:** 信息泄露/路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-07-12  
**POC仓库:** [Detecting-and-Analyzing-CVE-2024-24919-Exploitation](https://github.com/MacUchegit/Detecting-and-Analyzing-CVE-2024-24919-Exploitation)  

---

### [CVE-2025-25257](CVE-2025-25257-imbas007_CVE-2025-25257.md) 🔴 ✅

**名称:** CVE-2025-25257 - FortiWeb GUI SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-07-12  
**POC仓库:** [CVE-2025-25257](https://github.com/imbas007/CVE-2025-25257)  

---

### [CVE-2025-25257](CVE-2025-25257-B1ack4sh_Blackash-CVE-2025-25257.md) 🔴 

**名称:** CVE-2025-25257-Fortinet FortiWeb-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-12  
**POC仓库:** [Blackash-CVE-2025-25257](https://github.com/B1ack4sh/Blackash-CVE-2025-25257)  

---

### [CVE-2025-25257](CVE-2025-25257-adilburaksen_CVE-2025-25257-Exploit-Tool.md) 🔴 ✅

**名称:** CVE-2025-25257-Fortinet FortiWeb-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-12  
**POC仓库:** [CVE-2025-25257-Exploit-Tool](https://github.com/adilburaksen/CVE-2025-25257-Exploit-Tool)  

---

### [CVE-2025-25257](CVE-2025-25257-imbas007_CVE-2025-25257.md) 🔴 ✅

**名称:** CVE-2025-25257 - FortiWeb GUI SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-12  
**POC仓库:** [CVE-2025-25257](https://github.com/imbas007/CVE-2025-25257)  

---

### [CVE-2024-1212](CVE-2024-1212-Chocapikk_CVE-2024-1212.md) 🔴 ✅

**名称:** CVE-2024-1212-ProgressKempLoadMaster-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许未授权远程命令执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-12  
**POC仓库:** [CVE-2024-1212](https://github.com/Chocapikk/CVE-2024-1212)  

---

### [CVE-2024-1212](CVE-2024-1212-nak000_CVE-2024-1212.md)  ✅

**名称:** CVE-2024-1212 - Progress Kemp LoadMaster OS Command Injection  
**类型:** OS Command Injection  
**风险:** 严重，允许未经身份验证的远程攻击者执行任意系统命令。  
**投毒风险:** 1%  
**发现时间:** 2025-07-12  
**POC仓库:** [CVE-2024-1212](https://github.com/nak000/CVE-2024-1212)  

---

### [CVE-2024-1212](CVE-2024-1212-Rehan07-Human_Exploiting-RCE-Cyber_Project_CVE-2024-1212.md) 🔴 ✅

**名称:** CVE-2024-1212-Kemp LoadMaster-OS命令注入  
**类型:** OS命令注入  
**风险:** 高危，未授权的远程攻击者可以通过LoadMaster管理界面访问系统，从而执行任意系统命令  
**投毒风险:** 10%  
**发现时间:** 2025-07-12  
**POC仓库:** [Exploiting-RCE-Cyber_Project_CVE-2024-1212](https://github.com/Rehan07-Human/Exploiting-RCE-Cyber_Project_CVE-2024-1212)  

---

### [CVE-2024-1212](CVE-2024-1212-r0otk3r_CVE-2024-1212.md)  ✅

**名称:** CVE-2024-1212 - Progress Kemp LoadMaster 未授权命令注入  
**类型:** 命令注入  
**风险:** 严重，未经身份验证的远程攻击者可以执行任意系统命令  
**投毒风险:** 2%  
**发现时间:** 2025-07-12  
**POC仓库:** [CVE-2024-1212](https://github.com/r0otk3r/CVE-2024-1212)  

---

### [CVE-2024-4577](CVE-2024-4577-ZeroMemoryEx_PHP-CGI-INTERNAL-RCE.md)  ✅

**名称:** CVE-2024-4577-PHP-CGI参数注入远程代码执行  
**类型:** 参数注入/远程代码执行  
**风险:** 极高，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-12  
**POC仓库:** [PHP-CGI-INTERNAL-RCE](https://github.com/ZeroMemoryEx/PHP-CGI-INTERNAL-RCE)  

---

### [CVE-2022-1388](CVE-2022-1388-r0otk3r_CVE-2022-1388.md)  ✅

**名称:** CVE-2022-1388 - F5 BIG-IP iControl REST Authentication Bypass RCE  
**类型:** 身份验证绕过，远程代码执行  
**风险:** 严重，允许未经身份验证的远程攻击者完全控制受影响的系统。  
**投毒风险:** 0%  
**发现时间:** 2025-07-12  
**POC仓库:** [CVE-2022-1388](https://github.com/r0otk3r/CVE-2022-1388)  

---

### [CVE-2011-2523](CVE-2011-2523-krill-x7_CVE-2011-2523.md) 🔴 ✅

**名称:** CVE-2011-2523-vsftpd-后门命令执行  
**类型:** 后门命令执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-07-12  
**POC仓库:** [CVE-2011-2523](https://github.com/krill-x7/CVE-2011-2523)  

---

### [CVE-2024-42640](CVE-2024-42640-KTN1990_CVE-2024-42640.md) 🔴 ✅

**名称:** CVE-2024-42640-angular-base64-upload-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-07-12  
**POC仓库:** [CVE-2024-42640](https://github.com/KTN1990/CVE-2024-42640)  

---

### [CVE-2024-42640](CVE-2024-42640-rvizx_CVE-2024-42640.md) 🔴 ✅

**名称:** CVE-2024-42640 - angular-base64-upload 未授权远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可完全控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-07-12  
**POC仓库:** [CVE-2024-42640](https://github.com/rvizx/CVE-2024-42640)  

---

### [CVE-2013-3900](CVE-2013-3900-pkblanks_Remediating-CVE-2013-3900-EnableCertPaddingCheck-.md) 🔴 

**名称:** CVE-2013-3900 WinVerifyTrust Signature Validation Vulnerability  
**类型:** 签名验证绕过  
**风险:** 中危，但如果用户具有管理员权限，则可能升级为高危  
**投毒风险:** 0%  
**发现时间:** 2025-07-12  
**POC仓库:** [Remediating-CVE-2013-3900-EnableCertPaddingCheck-](https://github.com/pkblanks/Remediating-CVE-2013-3900-EnableCertPaddingCheck-)  

---

### [CVE-2025-24813](CVE-2025-24813-sentilaso1_CVE-2025-24813-Apache-Tomcat-RCE-PoC.md) 🔴 ✅

**名称:** CVE-2025-24813 Apache Tomcat Path Equivalence and Deserialization RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-12  
**POC仓库:** [CVE-2025-24813-Apache-Tomcat-RCE-PoC](https://github.com/sentilaso1/CVE-2025-24813-Apache-Tomcat-RCE-PoC)  

---

### [CVE-2025-0133](CVE-2025-0133-shawarkhanethicalhacker_CVE-2025-0133-exploit.md) 🟡 ✅

**名称:** CVE-2025-0133-PAN-OS-Reflected XSS  
**类型:** Reflected XSS  
**风险:** 中危，可能导致凭据窃取和钓鱼攻击  
**投毒风险:** 0%  
**发现时间:** 2025-07-11  
**POC仓库:** [CVE-2025-0133-exploit](https://github.com/shawarkhanethicalhacker/CVE-2025-0133-exploit)  

---

### [CVE-2025-52097](CVE-2025-52097-rwilsonecs_CVE-2025-52097.md) 🟡 ✅

**名称:** CVE-2025-52097: InstantForum.NET v4.1.4 Reflected XSS  
**类型:** Reflected Cross-Site Scripting (XSS)  
**风险:** 中危，可能导致会话劫持、网络钓鱼或重定向攻击、信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-07-11  
**POC仓库:** [CVE-2025-52097](https://github.com/rwilsonecs/CVE-2025-52097)  

---

### [CVE-2025-38001](CVE-2025-38001-0xdevil_CVE-2025-38001.md) 🔴 ✅

**名称:** CVE-2025-38001-Linux Kernel HFSC Eltree Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可能导致权限提升和代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-11  
**POC仓库:** [CVE-2025-38001](https://github.com/0xdevil/CVE-2025-38001)  

---

### [CVE-2025-32463](CVE-2025-32463-morgenm_sudo-chroot-CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-11  
**POC仓库:** [sudo-chroot-CVE-2025-32463](https://github.com/morgenm/sudo-chroot-CVE-2025-32463)  

---

### [CVE-2025-6514](CVE-2025-6514-ChaseHCS_CVE-2025-6514.md) 🔴 

**名称:** CVE-2025-6514-mcp-remote-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-11  
**POC仓库:** [CVE-2025-6514](https://github.com/ChaseHCS/CVE-2025-6514)  

---

### [CVE-2025-25257](CVE-2025-25257-watchtowrlabs_watchTowr-vs-FortiWeb-CVE-2025-25257.md) 🔴 ✅

**名称:** CVE-2025-25257-FortiWeb-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-07-11  
**POC仓库:** [watchTowr-vs-FortiWeb-CVE-2025-25257](https://github.com/watchtowrlabs/watchTowr-vs-FortiWeb-CVE-2025-25257)  

---

### [CVE-2025-25257](CVE-2025-25257-0xbigshaq_CVE-2025-25257.md) 🔴 ✅

**名称:** CVE-2025-25257 - FortiWeb SQL注入  
**类型:** SQL 注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-11  
**POC仓库:** [CVE-2025-25257](https://github.com/0xbigshaq/CVE-2025-25257)  

---

### [CVE-2025-5777](CVE-2025-5777-Jishanluhar_CVE-2025-5777.md) 🔴 ✅

**名称:** CVE-2025-5777: NetScaler ADC and Gateway 内存信息泄露漏洞 (CitrixBleed 2)  
**类型:** 内存信息泄露  
**风险:** 高危，可能导致敏感信息泄露和未授权访问  
**投毒风险:** 10%  
**发现时间:** 2025-07-11  
**POC仓库:** [CVE-2025-5777](https://github.com/Jishanluhar/CVE-2025-5777)  

---

### [CVE-2025-48799](CVE-2025-48799-KOVmechatronics_CVE-2025-48799.md) 🔴 ✅

**名称:** CVE-2025-48799 Windows Update Service Elevation of Privilege Vulnerability  
**类型:** 特权提升  
**风险:** 高危，允许本地攻击者提升权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-11  
**POC仓库:** [CVE-2025-48799](https://github.com/KOVmechatronics/CVE-2025-48799)  

---

### [CVE-2025-48384](CVE-2025-48384-vinieger_vinieger-CVE-2025-48384-Dockerfile.md) 🔴 ✅

**名称:** CVE-2025-48384-Git配置注入导致任意代码执行  
**类型:** 配置注入/符号链接攻击  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-07-11  
**POC仓库:** [vinieger-CVE-2025-48384-Dockerfile](https://github.com/vinieger/vinieger-CVE-2025-48384-Dockerfile)  

---

### [CVE-2007-2447](CVE-2007-2447-MrRoma577_exploit_cve-2007-2447_again.md) 🔴 ✅

**名称:** CVE-2007-2447-Samba-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致完全控制受影响的系统  
**投毒风险:** 5%  
**发现时间:** 2025-07-11  
**POC仓库:** [exploit_cve-2007-2447_again](https://github.com/MrRoma577/exploit_cve-2007-2447_again)  

---

### [CVE-2020-11989](CVE-2020-11989-HYWZ36_HYWZ36-CVE-2020-11989-code.md) 🔴 ✅

**名称:** CVE-2020-11989-Apache Shiro Authentication Bypass  
**类型:** Authentication Bypass  
**风险:** 高危，可能导致未授权访问  
**投毒风险:** 10%  
**发现时间:** 2025-07-11  
**POC仓库:** [HYWZ36-CVE-2020-11989-code](https://github.com/HYWZ36/HYWZ36-CVE-2020-11989-code)  

---

### [CVE-2020-11989](CVE-2020-11989-cuijiung_shiro-CVE-2020-11989.md) 🔴 ✅

**名称:** CVE-2020-11989-Apache Shiro-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未经授权的访问  
**投毒风险:** 10%  
**发现时间:** 2025-07-11  
**POC仓库:** [shiro-CVE-2020-11989](https://github.com/cuijiung/shiro-CVE-2020-11989)  

---

### [CVE-2022-25845](CVE-2022-25845-hosch3n_FastjsonVulns.md) 🔴 ✅

**名称:** CVE-2022-25845 - Fastjson Deserialization RCE  
**类型:** 反序列化漏洞  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-11  
**POC仓库:** [FastjsonVulns](https://github.com/hosch3n/FastjsonVulns)  

---

### [CVE-2022-25845](CVE-2022-25845-nerowander_CVE-2022-25845-exploit.md) 🔴 ✅

**名称:** CVE-2022-25845-Fastjson-反序列化漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-11  
**POC仓库:** [CVE-2022-25845-exploit](https://github.com/nerowander/CVE-2022-25845-exploit)  

---

### [CVE-2022-25845](CVE-2022-25845-scabench_fastjson-tp1fn1.md) 🔴 ✅

**名称:** CVE-2022-25845-fastjson-反序列化  
**类型:** 反序列化  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-11  
**POC仓库:** [fastjson-tp1fn1](https://github.com/scabench/fastjson-tp1fn1)  

---

### [CVE-2022-25845](CVE-2022-25845-luelueking_CVE-2022-25845-In-Spring.md) 🔴 ✅

**名称:** CVE-2022-25845-Fastjson-反序列化  
**类型:** 反序列化  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-11  
**POC仓库:** [CVE-2022-25845-In-Spring](https://github.com/luelueking/CVE-2022-25845-In-Spring)  

---

### [CVE-2022-25845](CVE-2022-25845-ph0ebus_CVE-2022-25845-In-Spring.md) 🔴 ✅

**名称:** CVE-2022-25845-Fastjson-反序列化漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-11  
**POC仓库:** [CVE-2022-25845-In-Spring](https://github.com/ph0ebus/CVE-2022-25845-In-Spring)  

---

### [CVE-2022-25845](CVE-2022-25845-cuijiung_fastjson-CVE-2022-25845.md) 🔴 ✅

**名称:** CVE-2022-25845-Fastjson-反序列化  
**类型:** 反序列化  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-11  
**POC仓库:** [fastjson-CVE-2022-25845](https://github.com/cuijiung/fastjson-CVE-2022-25845)  

---

### [CVE-2020-36180](CVE-2020-36180-cuijiung_jackson-CVE-2020-36180.md) 🔴 ✅

**名称:** CVE-2020-36180 - Jackson-databind 反序列化漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-11  
**POC仓库:** [jackson-CVE-2020-36180](https://github.com/cuijiung/jackson-CVE-2020-36180)  

---

### [CVE-2025-32462](CVE-2025-32462-toohau_CVE-2025-32462-32463-Detection-Script-.md) 🟡 ✅

**名称:** CVE-2025-32462-Sudo-主机绕过  
**类型:** 权限提升  
**风险:** 中危  
**投毒风险:** 5%  
**发现时间:** 2025-07-11  
**POC仓库:** [CVE-2025-32462-32463-Detection-Script-](https://github.com/toohau/CVE-2025-32462-32463-Detection-Script-)  

---

### [CVE-2023-23638](CVE-2023-23638-AiK1d_CVE-2023-23638-Tools.md) 🟡 

**名称:** CVE-2023-23638-Apache Dubbo Deserialization  
**类型:** 反序列化漏洞  
**风险:** 中危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-11  
**POC仓库:** [CVE-2023-23638-Tools](https://github.com/AiK1d/CVE-2023-23638-Tools)  

---

### [CVE-2023-23638](CVE-2023-23638-YYHYlh_Apache-Dubbo-CVE-2023-23638-exp.md) 🔴 ✅

**名称:** CVE-2023-23638 - Apache Dubbo 反序列化漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-11  
**POC仓库:** [Apache-Dubbo-CVE-2023-23638-exp](https://github.com/YYHYlh/Apache-Dubbo-CVE-2023-23638-exp)  

---

### [CVE-2023-23638](CVE-2023-23638-X1r0z_Dubbo-RCE.md) 🟡 ✅

**名称:** CVE-2023-23638 - Apache Dubbo Deserialization Vulnerability  
**类型:** 反序列化漏洞  
**风险:** 中危，可能导致恶意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-11  
**POC仓库:** [Dubbo-RCE](https://github.com/X1r0z/Dubbo-RCE)  

---

### [CVE-2023-23638](CVE-2023-23638-cuijiung_dubbo-CVE-2023-23638.md) 🟡 ✅

**名称:** CVE-2023-23638 - Apache Dubbo Deserialization  
**类型:** 反序列化漏洞  
**风险:** 中危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-11  
**POC仓库:** [dubbo-CVE-2023-23638](https://github.com/cuijiung/dubbo-CVE-2023-23638)  

---

### [CVE-2024-10915](CVE-2024-10915-r0otk3r_CVE-2024-10915.md) 🔴 ✅

**名称:** CVE-2024-10915 - D-Link NAS account_mgr.cgi cgi_user_add OS Command Injection  
**类型:** OS Command Injection  
**风险:** 高危，允许未经身份验证的远程攻击者执行任意系统命令。  
**投毒风险:** 5%  
**发现时间:** 2025-07-11  
**POC仓库:** [CVE-2024-10915](https://github.com/r0otk3r/CVE-2024-10915)  

---

### [CVE-2024-45352](CVE-2024-45352-Edwins907_-CVE-2024-45352.md) 🔴 

**名称:** CVE-2024-45352 - Xiaomi Smarthome Application Code Execution  
**类型:** 代码执行  
**风险:** 高危，可能导致设备控制和数据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-07-11  
**POC仓库:** [-CVE-2024-45352](https://github.com/Edwins907/-CVE-2024-45352)  

---

### [CVE-2021-44228](CVE-2021-44228-fabioeletto_hka-seminar-log4shell.md) 🔴 ✅

**名称:** CVE-2021-44228 - Apache Log4j2 JNDI 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-07-11  
**POC仓库:** [hka-seminar-log4shell](https://github.com/fabioeletto/hka-seminar-log4shell)  

---

### [CVE-2021-44228](CVE-2021-44228-cuijiung_log4j-CVE-2021-44228.md) 🔴 ✅

**名称:** CVE-2021-44228 - Apache Log4j2 JNDI 注入  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-07-11  
**POC仓库:** [log4j-CVE-2021-44228](https://github.com/cuijiung/log4j-CVE-2021-44228)  

---

### [CVE-2022-0847](CVE-2022-0847-morgenm_dirtypipe.md) 🔴 ✅

**名称:** CVE-2022-0847-Dirty Pipe-本地提权  
**类型:** 本地提权  
**风险:** 高危，可导致非特权用户获得root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-11  
**POC仓库:** [dirtypipe](https://github.com/morgenm/dirtypipe)  

---

### [CVE-2022-0847](CVE-2022-0847-mrchucu1_CVE-2022-0847-Docker.md) 🔴 ✅

**名称:** CVE-2022-0847 Dirty Pipe 本地提权漏洞  
**类型:** 本地权限提升  
**风险:** 高危，可使低权限用户获得 root 权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-11  
**POC仓库:** [CVE-2022-0847-Docker](https://github.com/mrchucu1/CVE-2022-0847-Docker)  

---

### [CVE-2021-4104](CVE-2021-4104-cckuailong_log4shell_1.x.md) 🔴 ✅

**名称:** CVE-2021-4104 - Apache Log4j 1.2 JMSAppender反序列化漏洞  
**类型:** 反序列化  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-11  
**POC仓库:** [log4shell_1.x](https://github.com/cckuailong/log4shell_1.x)  

---

### [CVE-2021-4104](CVE-2021-4104-open-AIMS_log4j.md) 🔴 ✅

**名称:** CVE-2021-4104-Apache Log4j 1.2 JMSAppender反序列化漏洞  
**类型:** 反序列化  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-11  
**POC仓库:** [log4j](https://github.com/open-AIMS/log4j)  

---

### [CVE-2021-4104](CVE-2021-4104-cuijiung_log4j-CVE-2021-4104.md) 🔴 ✅

**名称:** CVE-2021-4104 - Apache Log4j 1.2 JMSAppender 反序列化漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-07-11  
**POC仓库:** [log4j-CVE-2021-4104](https://github.com/cuijiung/log4j-CVE-2021-4104)  

---

### [CVE-2020-26217](CVE-2020-26217-novysodope_CVE-2020-26217-XStream-RCE-POC.md) 🔴 ✅

**名称:** CVE-2020-26217-XStream-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-07-11  
**POC仓库:** [CVE-2020-26217-XStream-RCE-POC](https://github.com/novysodope/CVE-2020-26217-XStream-RCE-POC)  

---

### [CVE-2020-26217](CVE-2020-26217-Al1ex_CVE-2020-26217.md) 🔴 ✅

**名称:** CVE-2020-26217-XStream-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-07-11  
**POC仓库:** [CVE-2020-26217](https://github.com/Al1ex/CVE-2020-26217)  

---

### [CVE-2020-26217](CVE-2020-26217-epicosy_XStream-1.md) 🔴 ✅

**名称:** CVE-2020-26217-XStream-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-11  
**POC仓库:** [XStream-1](https://github.com/epicosy/XStream-1)  

---

### [CVE-2020-26217](CVE-2020-26217-cuijiung_xstream-CVE-2020-26217.md) 🔴 ✅

**名称:** CVE-2020-26217-XStream-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能允许远程攻击者执行任意shell命令  
**投毒风险:** 10%  
**发现时间:** 2025-07-11  
**POC仓库:** [xstream-CVE-2020-26217](https://github.com/cuijiung/xstream-CVE-2020-26217)  

---

### [CVE-2021-29505](CVE-2021-29505-cuijiung_xstream-CVE-2021-29505.md) 🔴 ✅

**名称:** CVE-2021-29505 - XStream Remote Command Execution  
**类型:** 远程命令执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-11  
**POC仓库:** [xstream-CVE-2021-29505](https://github.com/cuijiung/xstream-CVE-2021-29505)  

---

### [CVE-2024-45352](CVE-2024-45352-Edwins907_xiaomi-cve-2024-45352.md) 🔴 ✅

**名称:** CVE-2024-45352-Xiaomi Smarthome Application-代码执行  
**类型:** 代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-11  
**POC仓库:** [xiaomi-cve-2024-45352](https://github.com/Edwins907/xiaomi-cve-2024-45352)  

---

### [CVE-2020-26259](CVE-2020-26259-jas502n_CVE-2020-26259.md) 🟡 ✅

**名称:** CVE-2020-26259-XStream-任意文件删除  
**类型:** 任意文件删除  
**风险:** 中危，可能导致服务中断或数据丢失  
**投毒风险:** 10%  
**发现时间:** 2025-07-11  
**POC仓库:** [CVE-2020-26259](https://github.com/jas502n/CVE-2020-26259)  

---

### [CVE-2020-26259](CVE-2020-26259-Al1ex_CVE-2020-26259.md) 🟡 ✅

**名称:** CVE-2020-26259-XStream-任意文件删除  
**类型:** 任意文件删除  
**风险:** 中危，可能导致服务中断或数据丢失  
**投毒风险:** 10%  
**发现时间:** 2025-07-11  
**POC仓库:** [CVE-2020-26259](https://github.com/Al1ex/CVE-2020-26259)  

---

### [CVE-2020-26259](CVE-2020-26259-cuijiung_xstream-CVE-2020-26259.md) 🟡 ✅

**名称:** CVE-2020-26259-XStream-任意文件删除  
**类型:** 任意文件删除  
**风险:** 中危，可能导致数据丢失  
**投毒风险:** 10%  
**发现时间:** 2025-07-11  
**POC仓库:** [xstream-CVE-2020-26259](https://github.com/cuijiung/xstream-CVE-2020-26259)  

---

### [CVE-2021-29505](CVE-2021-29505-MyBlackManba_CVE-2021-29505.md) 🔴 ✅

**名称:** CVE-2021-29505-XStream远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-07-11  
**POC仓库:** [CVE-2021-29505](https://github.com/MyBlackManba/CVE-2021-29505)  

---

### [CVE-2020-26258](CVE-2020-26258-Al1ex_CVE-2020-26258.md) 🟡 ✅

**名称:** CVE-2020-26258-XStream-SSRF  
**类型:** SSRF (Server-Side Request Forgery)  
**风险:** 中危，可能导致内部信息泄露或利用内部服务进行攻击  
**投毒风险:** 0%  
**发现时间:** 2025-07-11  
**POC仓库:** [CVE-2020-26258](https://github.com/Al1ex/CVE-2020-26258)  

---

### [CVE-2020-26258](CVE-2020-26258-cuijiung_xstream-CVE-2020-26258.md) 🟡 ✅

**名称:** CVE-2020-26258 XStream Server-Side Request Forgery  
**类型:** Server-Side Request Forgery (SSRF)  
**风险:** 中危，可能允许远程攻击者请求内部资源  
**投毒风险:** 10%  
**发现时间:** 2025-07-11  
**POC仓库:** [xstream-CVE-2020-26258](https://github.com/cuijiung/xstream-CVE-2020-26258)  

---

### [CVE-2014-6287](CVE-2014-6287-rahisec_rejetto-http-file-server-2.3.x-RCE-exploit-CVE-2014-6287.md) 🔴 ✅

**名称:** CVE-2014-6287-Rejetto HFS-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致远程命令执行，完全控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-07-11  
**POC仓库:** [rejetto-http-file-server-2.3.x-RCE-exploit-CVE-2014-6287](https://github.com/rahisec/rejetto-http-file-server-2.3.x-RCE-exploit-CVE-2014-6287)  

---

### [CVE-2022-36934](CVE-2022-36934-Teexo_mailenable-cve-2022-36934.md) 🔴 

**名称:** CVE-2022-36934 - WhatsApp Integer Overflow RCE  
**类型:** 整数溢出导致的远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者在视频通话期间执行任意代码  
**投毒风险:** 95%  
**发现时间:** 2025-07-11  
**POC仓库:** [mailenable-cve-2022-36934](https://github.com/Teexo/mailenable-cve-2022-36934)  

---

### [CVE-2025-45778](CVE-2025-45778-Smarttfoxx_CVE-2025-45778.md) 🟡 ✅

**名称:** CVE-2025-45778-The Language Sloth Web Application-Stored XSS  
**类型:** Stored XSS  
**风险:** 中危，可能导致用户账户被盗用或恶意脚本执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-11  
**POC仓库:** [CVE-2025-45778](https://github.com/Smarttfoxx/CVE-2025-45778)  

---

### [CVE-2025-25257](CVE-2025-25257-barbaraogmgf_CVE-2025-25257.md) 🔴 ✅

**名称:** CVE-2025-25257-FortiWeb-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-07-10  
**POC仓库:** [CVE-2025-25257](https://github.com/barbaraogmgf/CVE-2025-25257)  

---

### [CVE-2025-5777](CVE-2025-5777-0xgh057r3c0n_CVE-2025-5777.md) 🔴 ✅

**名称:** CVE-2025-5777-NetScaler ADC/Gateway-内存信息泄露  
**类型:** 内存信息泄露  
**风险:** 高危，可能导致敏感信息泄露，为进一步攻击提供信息  
**投毒风险:** 1%  
**发现时间:** 2025-07-10  
**POC仓库:** [CVE-2025-5777](https://github.com/0xgh057r3c0n/CVE-2025-5777)  

---

### [CVE-2024-27954](CVE-2024-27954-gh-ost00_CVE-2024-27954.md) 🔴 ✅

**名称:** CVE-2024-27954 - WP Automatic Plugin - 任意文件下载和SSRF漏洞  
**类型:** 路径遍历 (Path Traversal) 和 SSRF (Server Side Request Forgery)  
**风险:** 高危，可能导致敏感信息泄露、服务器端请求伪造，甚至在特定情况下可能导致远程代码执行  
**投毒风险:** 20%  
**发现时间:** 2025-07-10  
**POC仓库:** [CVE-2024-27954](https://github.com/gh-ost00/CVE-2024-27954)  

---

### [CVE-2024-27954](CVE-2024-27954-Quantum-Hacker_CVE-2024-27954.md) 🔴 ✅

**名称:** CVE-2024-27954-WP Automatic-路径遍历和SSRF  
**类型:** 路径遍历和SSRF  
**风险:** 高危，可能导致敏感文件泄露和内部网络探测  
**投毒风险:** 10%  
**发现时间:** 2025-07-10  
**POC仓库:** [CVE-2024-27954](https://github.com/Quantum-Hacker/CVE-2024-27954)  

---

### [CVE-2024-27954](CVE-2024-27954-r0otk3r_CVE-2024-27954.md) 🔴 ✅

**名称:** CVE-2024-27954-WP Automatic-路径遍历和SSRF  
**类型:** 路径遍历和SSRF  
**风险:** 高危，可能导致任意文件读取和服务器端请求伪造  
**投毒风险:** 10%  
**发现时间:** 2025-07-10  
**POC仓库:** [CVE-2024-27954](https://github.com/r0otk3r/CVE-2024-27954)  

---

### [CVE-2025-48384](CVE-2025-48384-vinieger_CVE-2025-48384-bad-nginx-submodule.md) 🔴 ✅

**名称:** CVE-2025-48384-Git配置注入导致任意代码执行  
**类型:** 配置注入/符号链接攻击  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-10  
**POC仓库:** [CVE-2025-48384-bad-nginx-submodule](https://github.com/vinieger/CVE-2025-48384-bad-nginx-submodule)  

---

### [CVE-2025-48384](CVE-2025-48384-vinieger_CVE-2025-48384-bad-nginx.md) 🔴 

**名称:** CVE-2025-48384-Git Config Quoting Vulnerability  
**类型:** 代码执行  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-10  
**POC仓库:** [CVE-2025-48384-bad-nginx](https://github.com/vinieger/CVE-2025-48384-bad-nginx)  

---

### [CVE-2025-48384](CVE-2025-48384-altm4n_cve-2025-48384-hub.md) 🔴 ✅

**名称:** CVE-2025-48384-Git配置注入/代码执行  
**类型:** 配置注入/代码执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-10  
**POC仓库:** [cve-2025-48384-hub](https://github.com/altm4n/cve-2025-48384-hub)  

---

### [CVE-2024-25600](CVE-2024-25600-r0otk3r_CVE-2024-25600.md)  ✅

**名称:** CVE-2024-25600 - Bricks Builder 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致完全系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-10  
**POC仓库:** [CVE-2024-25600](https://github.com/r0otk3r/CVE-2024-25600)  

---

### [CVE-2025-4578](CVE-2025-4578-RandomRobbieBF_CVE-2025-4578.md) 🔴 ✅

**名称:** CVE-2025-4578-File Provider-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-07-10  
**POC仓库:** [CVE-2025-4578](https://github.com/RandomRobbieBF/CVE-2025-4578)  

---

### [CVE-2025-48384](CVE-2025-48384-testdjshan_CVE-2025-48384.md) 🔴 ✅

**名称:** CVE-2025-48384-Git-任意代码执行  
**类型:** 任意代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-10  
**POC仓库:** [CVE-2025-48384](https://github.com/testdjshan/CVE-2025-48384)  

---

### [CVE-2025-48384](CVE-2025-48384-altm4n_CVE-2025-48384-sub.md) 🔴 ✅

**名称:** CVE-2025-48384-Git-任意代码执行  
**类型:** 任意代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-10  
**POC仓库:** [CVE-2025-48384-sub](https://github.com/altm4n/CVE-2025-48384-sub)  

---

### [CVE-2025-5777](CVE-2025-5777-bughuntar_CVE-2025-5777.md) 🔴 ✅

**名称:** CVE-2025-5777 NetScaler ADC/Gateway 内存泄露漏洞 (CitrixBleed 2)  
**类型:** 内存泄露  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-07-10  
**POC仓库:** [CVE-2025-5777](https://github.com/bughuntar/CVE-2025-5777)  

---

### [CVE-2024-31969](CVE-2024-31969-kingfakee7_CVE-2024-31969.md) 🔴 ✅

**名称:** CVE-2024-31969-sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，允许本地用户以root权限执行任意命令  
**投毒风险:** 1%  
**发现时间:** 2025-07-10  
**POC仓库:** [CVE-2024-31969](https://github.com/kingfakee7/CVE-2024-31969)  

---

### [CVE-2025-32023](CVE-2025-32023-atomicjjbod_CVE-2025-32023.md) 🔴 ✅

**名称:** CVE-2025-32023-Redis-堆溢出导致RCE  
**类型:** 堆溢出  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-10  
**POC仓库:** [CVE-2025-32023](https://github.com/atomicjjbod/CVE-2025-32023)  

---

### [CVE-2025-6554](CVE-2025-6554-9Insomnie_CVE-2025-6554.md) 🔴 ✅

**名称:** CVE-2025-6554 - Google Chrome V8 类型混淆漏洞  
**类型:** 类型混淆  
**风险:** 高危，可能导致任意代码读写  
**投毒风险:** 10%  
**发现时间:** 2025-07-10  
**POC仓库:** [CVE-2025-6554](https://github.com/9Insomnie/CVE-2025-6554)  

---

### [CVE-2025-6218](CVE-2025-6218-absholi7ly_CVE-2025-6218-WinRAR-Directory-Traversal-RCE.md) 🔴 ✅

**名称:** CVE-2025-6218-WinRAR 目录遍历 RCE  
**类型:** 目录遍历导致远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统权限获取  
**投毒风险:** 10%  
**发现时间:** 2025-07-10  
**POC仓库:** [CVE-2025-6218-WinRAR-Directory-Traversal-RCE](https://github.com/absholi7ly/CVE-2025-6218-WinRAR-Directory-Traversal-RCE)  

---

### [CVE-2025-30208](CVE-2025-30208-gonn4cry_CVE-2025-30208.md) 🟡 ✅

**名称:** CVE-2025-30208-Vite文件读取漏洞  
**类型:** 文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-07-10  
**POC仓库:** [CVE-2025-30208](https://github.com/gonn4cry/CVE-2025-30208)  

---

### [CVE-2025-34085](CVE-2025-34085-MrjHaxcore_CVE-2025-34085.md) 🔴 ✅

**名称:** CVE-2025-34085-Simple File List-RCE  
**类型:** RCE  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-10  
**POC仓库:** [CVE-2025-34085](https://github.com/MrjHaxcore/CVE-2025-34085)  

---

### [CVE-2025-21574](CVE-2025-21574-mdriaz009_CVE-2025-21574-Exploit.md) 🔴 ✅

**名称:** CVE-2025-21574-MySQL Server Denial of Service  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，导致服务不可用  
**投毒风险:** 10%  
**发现时间:** 2025-07-10  
**POC仓库:** [CVE-2025-21574-Exploit](https://github.com/mdriaz009/CVE-2025-21574-Exploit)  

---

### [CVE-2025-32463](CVE-2025-32463-danielsummerton12_sudo-zero-day-CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地权限提升  
**类型:** 本地权限提升  
**风险:** 高危，本地用户可以获得root权限  
**投毒风险:** 0%  
**发现时间:** 2025-07-09  
**POC仓库:** [sudo-zero-day-CVE-2025-32463](https://github.com/danielsummerton12/sudo-zero-day-CVE-2025-32463)  

---

### [CVE-2025-34077](CVE-2025-34077-MrjHaxcore_CVE-2025-34077.md)  ✅

**名称:** CVE-2025-34077 - WordPress Pie Register Plugin Authentication Bypass RCE  
**类型:** 身份验证绕过 + 远程代码执行  
**风险:** 严重，未经身份验证的攻击者可以完全控制WordPress站点  
**投毒风险:** 0%  
**发现时间:** 2025-07-09  
**POC仓库:** [CVE-2025-34077](https://github.com/MrjHaxcore/CVE-2025-34077)  

---

### [CVE-2025-32023](CVE-2025-32023-B1ack4sh_Blackash-CVE-2025-32023.md) 🔴 ✅

**名称:** CVE-2025-32023-Redis-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致完全控制 Redis 服务器  
**投毒风险:** 10%  
**发现时间:** 2025-07-09  
**POC仓库:** [Blackash-CVE-2025-32023](https://github.com/B1ack4sh/Blackash-CVE-2025-32023)  

---

### [CVE-2024-42008](CVE-2024-42008-rpgsec_Roundcube-CVE-2024-42008-POC.md) 🔴 ✅

**名称:** CVE-2024-42008 Roundcube XSS漏洞  
**类型:** 跨站脚本（XSS）  
**风险:** 高危，可能导致信息泄露、账户劫持和恶意邮件发送  
**投毒风险:** 10%  
**发现时间:** 2025-07-09  
**POC仓库:** [Roundcube-CVE-2024-42008-POC](https://github.com/rpgsec/Roundcube-CVE-2024-42008-POC)  

---

### [CVE-2025-6970](CVE-2025-6970-RandomRobbieBF_CVE-2025-6970.md) 🔴 ✅

**名称:** CVE-2025-6970 - Events Manager SQL 注入  
**类型:** SQL 注入  
**风险:** 高危，可能导致数据泄露  
**投毒风险:** 1%  
**发现时间:** 2025-07-09  
**POC仓库:** [CVE-2025-6970](https://github.com/RandomRobbieBF/CVE-2025-6970)  

---

### [CVE-2025-32463](CVE-2025-32463-0xb0rn3_CVE-2025-32463-EXPLOIT.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地权限提升  
**类型:** 本地权限提升  
**风险:** 高危，本地用户可获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-09  
**POC仓库:** [CVE-2025-32463-EXPLOIT](https://github.com/0xb0rn3/CVE-2025-32463-EXPLOIT)  

---

### [CVE-2025-52357](CVE-2025-52357-wrathfulDiety_CVE-2025-52357.md) 🟡 ✅

**名称:** CVE-2025-52357 - FD602GW-DX-R410 Router Reflected XSS  
**类型:** Reflected XSS  
**风险:** 中危，可能导致会话劫持、凭据窃取、权限提升和未经授权的配置更改  
**投毒风险:** 10%  
**发现时间:** 2025-07-09  
**POC仓库:** [CVE-2025-52357](https://github.com/wrathfulDiety/CVE-2025-52357)  

---

### [CVE-2025-48384](CVE-2025-48384-liamg_CVE-2025-48384-submodule.md) 🔴 ✅

**名称:** CVE-2025-48384-Git Config 注入 RCE  
**类型:** 代码注入/命令执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-09  
**POC仓库:** [CVE-2025-48384-submodule](https://github.com/liamg/CVE-2025-48384-submodule)  

---

### [CVE-2025-45072](CVE-2025-45072-yogeswaran6383_CVE-2025-45072.md) 🟡 ✅

**名称:** CVE-2025-45072 - Mitmproxy 敏感信息泄露  
**类型:** 信息泄露  
**风险:** 中危，可能导致安全工具和系统服务指纹识别  
**投毒风险:** 0%  
**发现时间:** 2025-07-09  
**POC仓库:** [CVE-2025-45072](https://github.com/yogeswaran6383/CVE-2025-45072)  

---

### [CVE-2025-48384](CVE-2025-48384-kallydev_cve-2025-48384-hook.md) 🔴 ✅

**名称:** CVE-2025-48384-Git任意代码执行  
**类型:** 任意代码执行  
**风险:** 高危，可能导致远程代码执行和系统控制  
**投毒风险:** 0%  
**发现时间:** 2025-07-09  
**POC仓库:** [cve-2025-48384-hook](https://github.com/kallydev/cve-2025-48384-hook)  

---

### [CVE-2025-49719](CVE-2025-49719-HExploited_CVE-2025-49719-Exploit.md) 🔴 ✅

**名称:** CVE-2025-49719-Microsoft SQL Server 信息泄露  
**类型:** 信息泄露  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-07-09  
**POC仓库:** [CVE-2025-49719-Exploit](https://github.com/HExploited/CVE-2025-49719-Exploit)  

---

### [CVE-2025-48384](CVE-2025-48384-fishyyh_CVE-2025-48384.md) 🔴 ✅

**名称:** CVE-2025-48384 Git配置注入导致任意代码执行  
**类型:** 配置注入/符号链接攻击  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-09  
**POC仓库:** [CVE-2025-48384](https://github.com/fishyyh/CVE-2025-48384)  

---

### [CVE-2022-0169](CVE-2022-0169-X3RX3SSec_CVE-2022-0169.md) 🔴 ✅

**名称:** CVE-2022-0169-Photo Gallery by 10Web-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和服务器控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-09  
**POC仓库:** [CVE-2022-0169](https://github.com/X3RX3SSec/CVE-2022-0169)  

---

### [CVE-2025-5777](CVE-2025-5777-FrenzisRed_CVE-2025-5777.md) 🔴 ✅

**名称:** CVE-2025-5777-NetScaler ADC/Gateway-内存信息泄露  
**类型:** 内存信息泄露  
**风险:** 高危，可能导致敏感信息泄露，最终可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-09  
**POC仓库:** [CVE-2025-5777](https://github.com/FrenzisRed/CVE-2025-5777)  

---

### [CVE-2025-6554](CVE-2025-6554-ghostn4444_CVE-2025-6554POC.md) 🔴 ✅

**名称:** CVE-2025-6554-Chrome-V8类型混淆  
**类型:** 类型混淆  
**风险:** 高危，可导致任意读/写  
**投毒风险:** 10%  
**发现时间:** 2025-07-09  
**POC仓库:** [CVE-2025-6554POC](https://github.com/ghostn4444/CVE-2025-6554POC)  

---

### [CVE-2025-49132](CVE-2025-49132-0xtensho_CVE-2025-49132-poc.md) 🔴 

**名称:** CVE-2025-49132 - Pterodactyl Panel 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制，数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-07-08  
**POC仓库:** [CVE-2025-49132-poc](https://github.com/0xtensho/CVE-2025-49132-poc)  

---

### [CVE-2025-32463](CVE-2025-32463-susancodes55_CVE-2025-32463-sudo-poc.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地权限提升  
**风险:** 高危，本地用户可以获得root权限  
**投毒风险:** 0%  
**发现时间:** 2025-07-08  
**POC仓库:** [CVE-2025-32463-sudo-poc](https://github.com/susancodes55/CVE-2025-32463-sudo-poc)  

---

### [CVE-2025-48903](CVE-2025-48903-susancodes55_CVE-2025-48903-discord-poc.md) 🔴 ✅

**名称:** CVE-2025-48903 HarmonyOS 媒体库模块权限绕过  
**类型:** 权限绕过  
**风险:** 高危，可能导致拒绝服务  
**投毒风险:** 60%  
**发现时间:** 2025-07-08  
**POC仓库:** [CVE-2025-48903-discord-poc](https://github.com/susancodes55/CVE-2025-48903-discord-poc)  

---

### [CVE-2025-48799](CVE-2025-48799-Wh04m1001_CVE-2025-48799.md) 🔴 ✅

**名称:** CVE-2025-48799 Windows Update Service 提权漏洞  
**类型:** 本地提权 (Elevation of Privilege)  
**风险:** 高危，本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-07-08  
**POC仓库:** [CVE-2025-48799](https://github.com/Wh04m1001/CVE-2025-48799)  

---

### [CVE-2025-32463](CVE-2025-32463-Alaric112_CVE-2025-32463-Chroot-Vulnerabilitity.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可获取root权限  
**投毒风险:** 1%  
**发现时间:** 2025-07-08  
**POC仓库:** [CVE-2025-32463-Chroot-Vulnerabilitity](https://github.com/Alaric112/CVE-2025-32463-Chroot-Vulnerabilitity)  

---

### [CVE-2025-32463](CVE-2025-32463-abrewer251_CVE-2025-32463_Sudo_PoC.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，允许本地用户获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-08  
**POC仓库:** [CVE-2025-32463_Sudo_PoC](https://github.com/abrewer251/CVE-2025-32463_Sudo_PoC)  

---

### [CVE-2024-9014](CVE-2024-9014-EQSTLab_CVE-2024-9014.md) 🔴 ✅

**名称:** CVE-2024-9014-pgAdmin4-敏感信息泄露  
**类型:** 敏感信息泄露  
**风险:** 高危，可能导致未授权访问用户数据  
**投毒风险:** 1%  
**发现时间:** 2025-07-08  
**POC仓库:** [CVE-2024-9014](https://github.com/EQSTLab/CVE-2024-9014)  

---

### [CVE-2024-9014](CVE-2024-9014-r0otk3r_CVE-2024-9014.md) 🔴 ✅

**名称:** CVE-2024-9014 - pgAdmin 4 OAuth2 认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未授权访问用户数据  
**投毒风险:** 10%  
**发现时间:** 2025-07-08  
**POC仓库:** [CVE-2024-9014](https://github.com/r0otk3r/CVE-2024-9014)  

---

### [CVE-2025-4866](CVE-2025-4866-bloodcode-spasov_ble-cve2025-attack-new-version.md) 🟡 ✅

**名称:** CVE-2025-4866 - weibocom rill-flow Management Console 代码注入  
**类型:** 代码注入  
**风险:** 中危，可能导致部分系统控制  
**投毒风险:** 30%  
**发现时间:** 2025-07-08  
**POC仓库:** [ble-cve2025-attack-new-version](https://github.com/bloodcode-spasov/ble-cve2025-attack-new-version)  

---

### [CVE-2025-5777](CVE-2025-5777-win3zz_CVE-2025-5777.md) 🔴 ✅

**名称:** CVE-2025-5777-NetScaler ADC/Gateway-内存信息泄露  
**类型:** 内存信息泄露  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-07-08  
**POC仓库:** [CVE-2025-5777](https://github.com/win3zz/CVE-2025-5777)  

---

### [CVE-2025-32463](CVE-2025-32463-lowercasenumbers_CVE-2025-32463_sudo_chroot.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可提升为root权限  
**投毒风险:** 1%  
**发现时间:** 2025-07-08  
**POC仓库:** [CVE-2025-32463_sudo_chroot](https://github.com/lowercasenumbers/CVE-2025-32463_sudo_chroot)  

---

### [CVE-2025-32463](CVE-2025-32463-SpongeBob-369_cve-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地权限提升  
**类型:** 本地权限提升  
**风险:** 高危，本地用户可以获得root权限  
**投毒风险:** 5%  
**发现时间:** 2025-07-08  
**POC仓库:** [cve-2025-32463](https://github.com/SpongeBob-369/cve-2025-32463)  

---

### [CVE-2025-5777](CVE-2025-5777-Chocapikk_CVE-2025-5777.md) 🔴 ✅

**名称:** CVE-2025-5777-NetScaler-内存信息泄露  
**类型:** 内存信息泄露  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-08  
**POC仓库:** [CVE-2025-5777](https://github.com/Chocapikk/CVE-2025-5777)  

---

### [CVE-2024-7954](CVE-2024-7954-Chocapikk_CVE-2024-7954.md) 🔴 ✅

**名称:** CVE-2024-7954-SPIP-porte_plume-RCE  
**类型:** 远程代码执行(RCE)  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-08  
**POC仓库:** [CVE-2024-7954](https://github.com/Chocapikk/CVE-2024-7954)  

---

### [CVE-2024-7954](CVE-2024-7954-bigb0x_CVE-2024-7954.md) 🔴 ✅

**名称:** CVE-2024-7954-SPIP-porte_plume插件-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的攻击者可以执行任意PHP代码  
**投毒风险:** 10%  
**发现时间:** 2025-07-08  
**POC仓库:** [CVE-2024-7954](https://github.com/bigb0x/CVE-2024-7954)  

---

### [CVE-2024-7954](CVE-2024-7954-gh-ost00_CVE-2024-7954-RCE.md) 🔴 ✅

**名称:** CVE-2024-7954 - SPIP Porte Plume Plugin - Remote Code Execution  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的远程攻击者可执行任意PHP代码  
**投毒风险:** 1%  
**发现时间:** 2025-07-08  
**POC仓库:** [CVE-2024-7954-RCE](https://github.com/gh-ost00/CVE-2024-7954-RCE)  

---

### [CVE-2024-7954](CVE-2024-7954-TheCyberguy-17_RCE_CVE-2024-7954.md) 🔴 ✅

**名称:** CVE-2024-7954 SPIP Porte Plume Plugin 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程攻击者可以执行任意PHP代码  
**投毒风险:** 0%  
**发现时间:** 2025-07-08  
**POC仓库:** [RCE_CVE-2024-7954](https://github.com/TheCyberguy-17/RCE_CVE-2024-7954)  

---

### [CVE-2024-7954](CVE-2024-7954-MuhammadWaseem29_RCE-CVE-2024-7954.md) 🔴 ✅

**名称:** CVE-2024-7954 - SPIP porte_plume 插件远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许远程未授权用户执行任意PHP代码  
**投毒风险:** 10%  
**发现时间:** 2025-07-08  
**POC仓库:** [RCE-CVE-2024-7954](https://github.com/MuhammadWaseem29/RCE-CVE-2024-7954)  

---

### [CVE-2024-7954](CVE-2024-7954-issamjr_CVE-2024-7954.md) 🔴 ✅

**名称:** CVE-2024-7954 - SPIP porte_plume Plugin 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的攻击者可执行任意PHP代码  
**投毒风险:** 10%  
**发现时间:** 2025-07-08  
**POC仓库:** [CVE-2024-7954](https://github.com/issamjr/CVE-2024-7954)  

---

### [CVE-2024-7954](CVE-2024-7954-zxj-hub_CVE-2024-7954POC.md) 🔴 ✅

**名称:** CVE-2024-7954 SPIP porte_plume 插件任意代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的攻击者可以执行任意 PHP 代码  
**投毒风险:** 10%  
**发现时间:** 2025-07-08  
**POC仓库:** [CVE-2024-7954POC](https://github.com/zxj-hub/CVE-2024-7954POC)  

---

### [CVE-2024-7954](CVE-2024-7954-0dayan0n_RCE_CVE-2024-7954-.md) 🔴 ✅

**名称:** CVE-2024-7954-SPIP Porte Plume Plugin-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程攻击者执行任意PHP代码  
**投毒风险:** 10%  
**发现时间:** 2025-07-08  
**POC仓库:** [RCE_CVE-2024-7954-](https://github.com/0dayan0n/RCE_CVE-2024-7954-)  

---

### [CVE-2024-7954](CVE-2024-7954-Arthikw3b_RCE-CVE-2024-7954.md) 🔴 ✅

**名称:** CVE-2024-7954 SPIP porte_plume插件远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-08  
**POC仓库:** [RCE-CVE-2024-7954](https://github.com/Arthikw3b/RCE-CVE-2024-7954)  

---

### [CVE-2024-7954](CVE-2024-7954-r0otk3r_CVE-2024-7954.md) 🔴 ✅

**名称:** CVE-2024-7954 - SPIP porte_plume Plugin 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程攻击者执行任意PHP代码。  
**投毒风险:** 10%  
**发现时间:** 2025-07-08  
**POC仓库:** [CVE-2024-7954](https://github.com/r0otk3r/CVE-2024-7954)  

---

### [CVE-2019-10743](CVE-2019-10743-albisorua_PoC-CVE-2019-10743.md) 🔴 ✅

**名称:** CVE-2019-10743-archiver-Zip Slip  
**类型:** Zip Slip  
**风险:** 高危，可能导致任意文件写入和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-07  
**POC仓库:** [PoC-CVE-2019-10743](https://github.com/albisorua/PoC-CVE-2019-10743)  

---

### [CVE-2021-27568](CVE-2021-27568-arsalanraja987_java-insecure-random-cve-2021-27568.md) 🟡 

**名称:** CVE-2021-27568-json-smart-未捕获异常  
**类型:** 拒绝服务 (DoS)/信息泄露  
**风险:** 中危，可能导致程序崩溃或暴露敏感信息  
**投毒风险:** 0%  
**发现时间:** 2025-07-07  
**POC仓库:** [java-insecure-random-cve-2021-27568](https://github.com/arsalanraja987/java-insecure-random-cve-2021-27568)  

---

### [CVE-2020-9488](CVE-2020-9488-arsalanraja987_java-log4j-cve-2020-9488.md) 🟡 ✅

**名称:** CVE-2020-9488 - Apache Log4j SMTP Appender证书验证绕过  
**类型:** 中间人攻击 (Man-in-the-Middle)  
**风险:** 中危，可能导致日志信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-07-07  
**POC仓库:** [java-log4j-cve-2020-9488](https://github.com/arsalanraja987/java-log4j-cve-2020-9488)  

---

### [CVE-2018-10933](CVE-2018-10933-shifa123_pythonprojects-CVE-2018-10933.md) 🔴 ✅

**名称:** CVE-2018-10933-libssh认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未经授权的远程命令执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-07  
**POC仓库:** [pythonprojects-CVE-2018-10933](https://github.com/shifa123/pythonprojects-CVE-2018-10933)  

---

### [CVE-2021-3560](CVE-2021-3560-Antoine-MANTIS_POC-Bash-CVE-2021-3560.md) 🔴 ✅

**名称:** CVE-2021-3560-Polkit本地提权  
**类型:** 本地提权  
**风险:** 高危，可能导致本地用户获取root权限  
**投毒风险:** 0%  
**发现时间:** 2025-07-07  
**POC仓库:** [POC-Bash-CVE-2021-3560](https://github.com/Antoine-MANTIS/POC-Bash-CVE-2021-3560)  

---

### [CVE-2024-26581](CVE-2024-26581-madfxr_CVE-2024-26581-Checker.md) 🔴 ✅

**名称:** CVE-2024-26581 - Linux Kernel Netfilter rbtree Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可能导致敏感信息泄露、权限提升或任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2024-26581-Checker](https://github.com/madfxr/CVE-2024-26581-Checker)  

---

### [CVE-2021-29425](CVE-2021-29425-arsalanraja987_java-cve-2021-29425-tika-xxe.md) 🟡 ✅

**名称:** CVE-2021-29425-Apache Commons IO-路径遍历  
**类型:** 路径遍历  
**风险:** 中危，可能导致有限的父目录文件访问  
**投毒风险:** 0%  
**发现时间:** 2025-07-07  
**POC仓库:** [java-cve-2021-29425-tika-xxe](https://github.com/arsalanraja987/java-cve-2021-29425-tika-xxe)  

---

### [CVE-2024-9264](CVE-2024-9264-rvizx_CVE-2024-9264.md)  ✅

**名称:** CVE-2024-9264-Grafana-SQL表达式远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致完全系统控制和敏感数据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2024-9264](https://github.com/rvizx/CVE-2024-9264)  

---

### [CVE-2023-21716](CVE-2023-21716-JMousqueton_CVE-2023-21716.md) 🔴 ✅

**名称:** CVE-2023-21716 Microsoft Word RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致远程代码执行，完全控制受害者系统  
**投毒风险:** 0%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2023-21716](https://github.com/JMousqueton/CVE-2023-21716)  

---

### [CVE-2023-21716](CVE-2023-21716-FeatherStark_CVE-2023-21716.md) 🔴 ✅

**名称:** CVE-2023-21716 Microsoft Word RTF 字体表堆损坏漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2023-21716](https://github.com/FeatherStark/CVE-2023-21716)  

---

### [CVE-2023-21716](CVE-2023-21716-Xnuvers007_CVE-2023-21716.md) 🔴 ✅

**名称:** CVE-2023-21716-Microsoft Word 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2023-21716](https://github.com/Xnuvers007/CVE-2023-21716)  

---

### [CVE-2023-21716](CVE-2023-21716-gyaansastra_CVE-2023-21716.md) 🔴 ✅

**名称:** CVE-2023-21716 Microsoft Word RTF 字体表堆损坏漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在受害者计算机上执行任意代码  
**投毒风险:** 1%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2023-21716](https://github.com/gyaansastra/CVE-2023-21716)  

---

### [CVE-2023-21716](CVE-2023-21716-AiK1d_CVE-2023-21716-POC.md) 🔴 ✅

**名称:** CVE-2023-21716-Microsoft Word 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许远程攻击者在目标系统上执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2023-21716-POC](https://github.com/AiK1d/CVE-2023-21716-POC)  

---

### [CVE-2023-21716](CVE-2023-21716-mikesxrs_CVE-2023-21716_YARA_Results.md) 🔴 ✅

**名称:** CVE-2023-21716 Microsoft Word 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许远程攻击者在目标系统上执行任意代码。  
**投毒风险:** 0%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2023-21716_YARA_Results](https://github.com/mikesxrs/CVE-2023-21716_YARA_Results)  

---

### [CVE-2023-21716](CVE-2023-21716-hv0l_CVE-2023-21716_exploit.md) 🔴 ✅

**名称:** CVE-2023-21716-Microsoft Word RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行，系统被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2023-21716_exploit](https://github.com/hv0l/CVE-2023-21716_exploit)  

---

### [CVE-2023-21716](CVE-2023-21716-MojithaR_CVE-2023-21716-EXPLOIT.py.md)  ✅

**名称:** CVE-2023-21716-Microsoft Word 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 严重，可能导致远程代码执行和系统控制  
**投毒风险:** 0%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2023-21716-EXPLOIT.py](https://github.com/MojithaR/CVE-2023-21716-EXPLOIT.py)  

---

### [CVE-2023-21716](CVE-2023-21716-RonF98_CVE-2023-21716-POC.md) 🔴 ✅

**名称:** CVE-2023-21716-Microsoft Word远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2023-21716-POC](https://github.com/RonF98/CVE-2023-21716-POC)  

---

### [CVE-2025-48703](CVE-2025-48703-Sq-CC_CVE-2025-48703.md) 🔴 

**名称:** Unknown Vulnerability  
**类型:** 多种漏洞 (SQL注入, RCE, 内存溢出等)  
**风险:** 高危，可能导致远程代码执行、数据泄露、设备崩溃等  
**投毒风险:** 0%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2025-48703](https://github.com/Sq-CC/CVE-2025-48703)  

---

### [CVE-2018-10933](CVE-2018-10933-nikhil1232_LibSSH-Authentication-Bypass.md) 🔴 ✅

**名称:** CVE-2018-10933 - libssh Authentication Bypass  
**类型:** Authentication Bypass  
**风险:** 高危，可能导致未授权访问和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-07  
**POC仓库:** [LibSSH-Authentication-Bypass](https://github.com/nikhil1232/LibSSH-Authentication-Bypass)  

---

### [CVE-2018-10933](CVE-2018-10933-SilasSpringer_CVE-2018-10933.md) 🔴 ✅

**名称:** CVE-2018-10933 - libssh Authentication Bypass  
**类型:** Authentication Bypass  
**风险:** 高危，未经授权的远程访问  
**投毒风险:** 5%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2018-10933](https://github.com/SilasSpringer/CVE-2018-10933)  

---

### [CVE-2024-11972](CVE-2024-11972-JunTakemura_exploit-CVE-2024-11972.md) 🔴 ✅

**名称:** CVE-2024-11972-Hunk Companion-未授权插件安装  
**类型:** 未授权插件安装  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-07  
**POC仓库:** [exploit-CVE-2024-11972](https://github.com/JunTakemura/exploit-CVE-2024-11972)  

---

### [CVE-2024-11972](CVE-2024-11972-Nxploited_CVE-2024-11972-PoC.md) 🔴 ✅

**名称:** CVE-2024-11972-Hunk Companion-未授权插件安装  
**类型:** 未授权插件安装  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2024-11972-PoC](https://github.com/Nxploited/CVE-2024-11972-PoC)  

---

### [CVE-2024-11972](CVE-2024-11972-RonF98_CVE-2024-11972-POC.md) 🔴 ✅

**名称:** CVE-2024-11972-Hunk Companion WordPress插件未授权插件安装漏洞  
**类型:** 未授权插件安装  
**风险:** 高危，可能导致远程代码执行、SQL注入、XSS或管理后台植入  
**投毒风险:** 10%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2024-11972-POC](https://github.com/RonF98/CVE-2024-11972-POC)  

---

### [CVE-2021-29427](CVE-2021-29427-arsalanraja987_gradle-cve-2021-29427-demo.md) 🔴 ✅

**名称:** CVE-2021-29427-Gradle依赖投毒  
**类型:** 依赖投毒/信息泄露  
**风险:** 高危，可能导致远程代码执行和信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-07-07  
**POC仓库:** [gradle-cve-2021-29427-demo](https://github.com/arsalanraja987/gradle-cve-2021-29427-demo)  

---

### [CVE-2018-10933](CVE-2018-10933-pghook_CVE-2018-10933_Scanner.md) 🔴 ✅

**名称:** CVE-2018-10933-libssh身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权访问，完全控制受影响的系统  
**投毒风险:** 10%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2018-10933_Scanner](https://github.com/pghook/CVE-2018-10933_Scanner)  

---

### [CVE-2018-10933](CVE-2018-10933-hackerhouse-opensource_cve-2018-10933.md) 🔴 ✅

**名称:** CVE-2018-10933-libssh认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未授权访问  
**投毒风险:** 10%  
**发现时间:** 2025-07-07  
**POC仓库:** [cve-2018-10933](https://github.com/hackerhouse-opensource/cve-2018-10933)  

---

### [CVE-2018-10933](CVE-2018-10933-reanimat0r_bpnd-libssh.md) 🔴 ✅

**名称:** CVE-2018-10933-libssh-认证绕过  
**类型:** 认证绕过  
**风险:** 高危，未经授权访问  
**投毒风险:** 0%  
**发现时间:** 2025-07-07  
**POC仓库:** [bpnd-libssh](https://github.com/reanimat0r/bpnd-libssh)  

---

### [CVE-2018-10933](CVE-2018-10933-cve-2018_cve-2018-10933.md) 🔴 ✅

**名称:** CVE-2018-10933 - libssh 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权访问和远程代码执行  
**投毒风险:** 95%  
**发现时间:** 2025-07-07  
**POC仓库:** [cve-2018-10933](https://github.com/cve-2018/cve-2018-10933)  

---

### [CVE-2018-10933](CVE-2018-10933-SoledaD208_CVE-2018-10933.md) 🔴 ✅

**名称:** CVE-2018-10933-libssh认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未授权访问  
**投毒风险:** 0%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2018-10933](https://github.com/SoledaD208/CVE-2018-10933)  

---

### [CVE-2018-10933](CVE-2018-10933-Bifrozt_CVE-2018-10933.md) 🔴 ✅

**名称:** CVE-2018-10933-libssh-Authentication Bypass  
**类型:** 认证绕过  
**风险:** 高危，可能导致未授权访问和控制  
**投毒风险:** 1%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2018-10933](https://github.com/Bifrozt/CVE-2018-10933)  

---

### [CVE-2018-10933](CVE-2018-10933-r3dxpl0it_CVE-2018-10933.md) 🔴 ✅

**名称:** CVE-2018-10933-libssh-认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未授权访问  
**投毒风险:** 0%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2018-10933](https://github.com/r3dxpl0it/CVE-2018-10933)  

---

### [CVE-2018-10933](CVE-2018-10933-ivanacostarubio_libssh-scanner.md) 🔴 ✅

**名称:** CVE-2018-10933-libssh-认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未授权访问  
**投毒风险:** 0%  
**发现时间:** 2025-07-07  
**POC仓库:** [libssh-scanner](https://github.com/ivanacostarubio/libssh-scanner)  

---

### [CVE-2018-10933](CVE-2018-10933-throwawayaccount12312312_precompiled-CVE-2018-10933.md) 🔴 ✅

**名称:** CVE-2018-10933-libssh-认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未授权访问  
**投毒风险:** 10%  
**发现时间:** 2025-07-07  
**POC仓库:** [precompiled-CVE-2018-10933](https://github.com/throwawayaccount12312312/precompiled-CVE-2018-10933)  

---

### [CVE-2018-10933](CVE-2018-10933-Virgula0_POC-CVE-2018-10933.md) 🔴 ✅

**名称:** CVE-2018-10933-libssh-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权访问和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-07  
**POC仓库:** [POC-CVE-2018-10933](https://github.com/Virgula0/POC-CVE-2018-10933)  

---

### [CVE-2018-10933](CVE-2018-10933-jobroche_libssh-scanner.md) 🔴 ✅

**名称:** CVE-2018-10933-libssh-认证绕过  
**类型:** 认证绕过  
**风险:** 高危，允许未授权访问  
**投毒风险:** 0%  
**发现时间:** 2025-07-07  
**POC仓库:** [libssh-scanner](https://github.com/jobroche/libssh-scanner)  

---

### [CVE-2018-10933](CVE-2018-10933-0xadaw_libSSH-bypass.md) 🔴 ✅

**名称:** CVE-2018-10933 - libssh Authentication Bypass  
**类型:** Authentication Bypass  
**风险:** 高危，可能导致未授权访问和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-07  
**POC仓库:** [libSSH-bypass](https://github.com/0xadaw/libSSH-bypass)  

---

### [CVE-2018-10933](CVE-2018-10933-sambiyal_CVE-2018-10933-POC.md) 🔴 ✅

**名称:** CVE-2018-10933-libssh身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权访问和远程命令执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2018-10933-POC](https://github.com/sambiyal/CVE-2018-10933-POC)  

---

### [CVE-2018-10933](CVE-2018-10933-ensimag-security_CVE-2018-10933.md) 🔴 

**名称:** CVE-2018-10933 - libssh Authentication Bypass  
**类型:** Authentication Bypass  
**风险:** Critical, allows unauthorized access to SSH servers.  
**投毒风险:** 5%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2018-10933](https://github.com/ensimag-security/CVE-2018-10933)  

---

### [CVE-2018-10933](CVE-2018-10933-Kurlee_LibSSH-exploit.md) 🔴 ✅

**名称:** CVE-2018-10933-libssh-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权访问和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-07  
**POC仓库:** [LibSSH-exploit](https://github.com/Kurlee/LibSSH-exploit)  

---

### [CVE-2018-10933](CVE-2018-10933-crispy-peppers_Libssh-server-CVE-2018-10933.md) 🔴 ✅

**名称:** CVE-2018-10933 - libssh 认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未授权访问  
**投毒风险:** 0%  
**发现时间:** 2025-07-07  
**POC仓库:** [Libssh-server-CVE-2018-10933](https://github.com/crispy-peppers/Libssh-server-CVE-2018-10933)  

---

### [CVE-2018-10933](CVE-2018-10933-xFreed0m_CVE-2018-10933.md) 🔴 ✅

**名称:** CVE-2018-10933-libssh认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未授权访问和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2018-10933](https://github.com/xFreed0m/CVE-2018-10933)  

---

### [CVE-2018-10933](CVE-2018-10933-youkergav_CVE-2018-10933.md) 🔴 ✅

**名称:** CVE-2018-10933-libssh-Authentication Bypass  
**类型:** Authentication Bypass  
**风险:** 高危，未经授权的访问  
**投毒风险:** 0%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2018-10933](https://github.com/youkergav/CVE-2018-10933)  

---

### [CVE-2018-10933](CVE-2018-10933-kristyna-mlcakova_CVE-2018-10933.md) 🔴 ✅

**名称:** CVE-2018-10933 - libssh Authentication Bypass  
**类型:** Authentication Bypass  
**风险:** 高危，可能导致未授权访问和远程命令执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2018-10933](https://github.com/kristyna-mlcakova/CVE-2018-10933)  

---

### [CVE-2018-10933](CVE-2018-10933-JoSecMx_CVE-2018-10933_Scanner.md) 🔴 ✅

**名称:** CVE-2018-10933 - libssh 认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未授权访问  
**投毒风险:** 5%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2018-10933_Scanner](https://github.com/JoSecMx/CVE-2018-10933_Scanner)  

---

### [CVE-2018-10933](CVE-2018-10933-cyberharsh_Libssh-server-CVE-2018-10933.md) 🔴 ✅

**名称:** CVE-2018-10933-libssh-认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未授权访问和远程命令执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-07  
**POC仓库:** [Libssh-server-CVE-2018-10933](https://github.com/cyberharsh/Libssh-server-CVE-2018-10933)  

---

### [CVE-2018-10933](CVE-2018-10933-Rubikcuv5_CVE-2018-10933.md) 🔴 ✅

**名称:** CVE-2018-10933-libssh-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权访问和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2018-10933](https://github.com/Rubikcuv5/CVE-2018-10933)  

---

### [CVE-2018-10933](CVE-2018-10933-blacknbunny_CVE-2018-10933.md) 🔴 ✅

**名称:** CVE-2018-10933 - libssh Authentication Bypass  
**类型:** Authentication Bypass  
**风险:** 高危，可能导致未授权访问和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2018-10933](https://github.com/blacknbunny/CVE-2018-10933)  

---

### [CVE-2018-10933](CVE-2018-10933-HSw109_CVE-2018-10933.md) 🔴 ✅

**名称:** CVE-2018-10933 - libssh Authentication Bypass  
**类型:** Authentication Bypass  
**风险:** 高危，可能导致未授权访问和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2018-10933](https://github.com/HSw109/CVE-2018-10933)  

---

### [CVE-2018-10933](CVE-2018-10933-bidaoui4905_CVE-2018-10933.md) 🔴 ✅

**名称:** CVE-2018-10933 - libssh 认证绕过  
**类型:** 认证绕过  
**风险:** 高危，未经授权的访问  
**投毒风险:** 1%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2018-10933](https://github.com/bidaoui4905/CVE-2018-10933)  

---

### [CVE-2018-7750](CVE-2018-7750-jm33-m0_CVE-2018-7750.md) 🔴 ✅

**名称:** CVE-2018-7750-Paramiko-Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权访问和远程命令执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2018-7750](https://github.com/jm33-m0/CVE-2018-7750)  

---

### [CVE-2018-7750](CVE-2018-7750-tlavi00_CVE-2018-7750.md) 🔴 ✅

**名称:** CVE-2018-7750 - Paramiko Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 高危，允许未经身份验证的远程访问  
**投毒风险:** 0%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2018-7750](https://github.com/tlavi00/CVE-2018-7750)  

---

### [CVE-2018-7750](CVE-2018-7750-bidaoui4905_CVE-2018-7750.md) 🔴 ✅

**名称:** CVE-2018-7750-Paramiko-认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未授权访问和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2018-7750](https://github.com/bidaoui4905/CVE-2018-7750)  

---

### [CVE-2025-47812](CVE-2025-47812-pevinkumar10_CVE-2025-47812.md) 🔴 ✅

**名称:** CVE-2025-47812-WingFTP-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致完整系统入侵  
**投毒风险:** 10%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2025-47812](https://github.com/pevinkumar10/CVE-2025-47812)  

---

### [CVE-2024-47773](CVE-2024-47773-ibrahmsql_CVE-2024-47773.md) 🔴 ✅

**名称:** CVE-2024-47773-Discourse-缓存投毒  
**类型:** 缓存投毒  
**风险:** 高危，可能导致信息篡改和拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2024-47773](https://github.com/ibrahmsql/CVE-2024-47773)  

---

### [CVE-2025-32462](CVE-2025-32462-MAAYTHM_CVE-2025-32462_32463-Lab.md) 🟡 ✅

**名称:** CVE-2025-32462  
**类型:** 权限提升  
**风险:** 中危，本地权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2025-32462_32463-Lab](https://github.com/MAAYTHM/CVE-2025-32462_32463-Lab)  

---

### [CVE-2025-6554](CVE-2025-6554-gmh5225_CVE-2025-6554-2.md) 🔴 ✅

**名称:** CVE-2025-6554  
**类型:** V8类型混淆  
**风险:** 高危，可能导致任意读/写  
**投毒风险:** 0%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2025-6554-2](https://github.com/gmh5225/CVE-2025-6554-2)  

---

### [CVE-2025-24813](CVE-2025-24813-GongWook_CVE-2025-24813.md) 🔴 ✅

**名称:** CVE-2025-24813-Apache Tomcat-路径遍历/反序列化RCE  
**类型:** 路径遍历/反序列化RCE  
**风险:** 高危，可能导致远程代码执行和信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2025-24813](https://github.com/GongWook/CVE-2025-24813)  

---

### [CVE-2024-4577](CVE-2024-4577-r0otk3r_CVE-2024-4577.md) 🔴 ✅

**名称:** CVE-2024-4577-PHP-CGI参数注入-RCE  
**类型:** PHP-CGI参数注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-07-07  
**POC仓库:** [CVE-2024-4577](https://github.com/r0otk3r/CVE-2024-4577)  

---

### [CVE-2025-32463](CVE-2025-32463-K3ysTr0K3R_CVE-2025-32463-EXPLOIT.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地权限提升  
**类型:** 本地权限提升  
**风险:** 高危，允许本地用户获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-06  
**POC仓库:** [CVE-2025-32463-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2025-32463-EXPLOIT)  

---

### [CVE-2025-32023](CVE-2025-32023-leesh3288_CVE-2025-32023.md) 🔴 ✅

**名称:** CVE-2025-32023 Redis HyperLogLog 整数溢出导致OOB写  
**类型:** 整数溢出, 堆/栈溢出  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-06  
**POC仓库:** [CVE-2025-32023](https://github.com/leesh3288/CVE-2025-32023)  

---

### [CVE-2024-31964](CVE-2024-31964-d-Raco_CVE-2024-31964.md) 🔴 

**名称:** CVE-2024-31964-Mitel SIP Phones-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，允许未授权修改系统配置和DoS  
**投毒风险:** 2%  
**发现时间:** 2025-07-06  
**POC仓库:** [CVE-2024-31964](https://github.com/d-Raco/CVE-2024-31964)  

---

### [CVE-2025-5777](CVE-2025-5777-orange0Mint_CitrixBleed-2-CVE-2025-5777.md) 🔴 ✅

**名称:** CVE-2025-5777 NetScaler ADC/Gateway 内存越界读取  
**类型:** 内存越界读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-07-06  
**POC仓库:** [CitrixBleed-2-CVE-2025-5777](https://github.com/orange0Mint/CitrixBleed-2-CVE-2025-5777)  

---

### [CVE-2025-32463](CVE-2025-32463-Chocapikk_CVE-2025-32463-lab.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可以提升到root权限  
**投毒风险:** 1%  
**发现时间:** 2025-07-06  
**POC仓库:** [CVE-2025-32463-lab](https://github.com/Chocapikk/CVE-2025-32463-lab)  

---

### [CVE-2025-20281](CVE-2025-20281-B1ack4sh_Blackash-CVE-2025-20281.md)  

**名称:** CVE-2025-20281-Cisco ISE API 未授权远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 严重，未经身份验证的远程攻击者可以以 root 权限执行任意代码  
**投毒风险:** 95%  
**发现时间:** 2025-07-06  
**POC仓库:** [Blackash-CVE-2025-20281](https://github.com/B1ack4sh/Blackash-CVE-2025-20281)  

---

### [CVE-2020-9547](CVE-2020-9547-fairyming_CVE-2020-9547.md) 🔴 ✅

**名称:** CVE-2020-9547：FasterXML jackson-databind 远程代码执行漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-06  
**POC仓库:** [CVE-2020-9547](https://github.com/fairyming/CVE-2020-9547)  

---

### [CVE-2020-9547](CVE-2020-9547-Pranjal6955_CVE-2020-9547.md) 🔴 ✅

**名称:** CVE-2020-9547-jackson-databind反序列化RCE  
**类型:** 反序列化远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-06  
**POC仓库:** [CVE-2020-9547](https://github.com/Pranjal6955/CVE-2020-9547)  

---

### [CVE-2025-4403](CVE-2025-4403-B1ack4sh_Blackash-CVE-2025-4403.md) 🔴 ✅

**名称:** CVE-2025-4403 - Drag and Drop Multiple File Upload for WooCommerce 未授权任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-06  
**POC仓库:** [Blackash-CVE-2025-4403](https://github.com/B1ack4sh/Blackash-CVE-2025-4403)  

---

### [CVE-2025-5777](CVE-2025-5777-RaR1991_citrix_bleed_2.md) 🔴 ✅

**名称:** CVE-2025-5777-NetScaler ADC/Gateway-内存越界读取  
**类型:** 内存越界读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-07-06  
**POC仓库:** [citrix_bleed_2](https://github.com/RaR1991/citrix_bleed_2)  

---

### [CVE-2021-25646](CVE-2021-25646-ShadowLance2_Apache-Druid-CVE-2021-25646-Exploit.md) 🔴 ✅

**名称:** CVE-2021-25646-Apache Druid-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经授权的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-06  
**POC仓库:** [Apache-Druid-CVE-2021-25646-Exploit](https://github.com/ShadowLance2/Apache-Druid-CVE-2021-25646-Exploit)  

---

### [CVE-2015-3224](CVE-2015-3224-0x00-0x00_CVE-2015-3224.md) 🔴 ✅

**名称:** CVE-2015-3224 Ruby on Rails Web Console IP Whitelist Bypass RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未授权用户执行任意命令  
**投毒风险:** 10%  
**发现时间:** 2025-07-06  
**POC仓库:** [CVE-2015-3224](https://github.com/0x00-0x00/CVE-2015-3224)  

---

### [CVE-2015-3224](CVE-2015-3224-0xEval_cve-2015-3224.md) 🔴 ✅

**名称:** CVE-2015-3224 Ruby on Rails Web Console IP Whitelist Bypass  
**类型:** IP Whitelist Bypass  
**风险:** 高危，可能导致远程代码执行（RCE）  
**投毒风险:** 0%  
**发现时间:** 2025-07-06  
**POC仓库:** [cve-2015-3224](https://github.com/0xEval/cve-2015-3224)  

---

### [CVE-2015-3224](CVE-2015-3224-n000xy_CVE-2015-3224-.md) 🔴 ✅

**名称:** CVE-2015-3224 Web Console IP Whitelist Bypass RCE  
**类型:** IP Whitelist Bypass  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-06  
**POC仓库:** [CVE-2015-3224-](https://github.com/n000xy/CVE-2015-3224-)  

---

### [CVE-2015-3224](CVE-2015-3224-Sic4rio_CVE-2015-3224.md) 🔴 ✅

**名称:** CVE-2015-3224 Ruby on Rails Web Console IP Whitelist Bypass RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经授权的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-06  
**POC仓库:** [CVE-2015-3224](https://github.com/Sic4rio/CVE-2015-3224)  

---

### [CVE-2025-32463](CVE-2025-32463-FreeDurok_CVE-2025-32463-PoC.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地权限提升  
**类型:** 本地权限提升  
**风险:** 高危，本地用户可提升至root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-06  
**POC仓库:** [CVE-2025-32463-PoC](https://github.com/FreeDurok/CVE-2025-32463-PoC)  

---

### [CVE-2022-37969](CVE-2022-37969-NoobCat2000_CVE-2022-37969.md) 🔴 ✅

**名称:** CVE-2022-37969 - Windows CLFS 提权漏洞  
**类型:** 权限提升  
**风险:** 高危，可导致本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-07-06  
**POC仓库:** [CVE-2022-37969](https://github.com/NoobCat2000/CVE-2022-37969)  

---

### [CVE-2023-45131](CVE-2023-45131-ibrahmsql_CVE-2023-45131.md) 🔴 ✅

**名称:** CVE-2023-45131-Discourse未授权访问聊天消息  
**类型:** 信息泄露  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-07-06  
**POC仓库:** [CVE-2023-45131](https://github.com/ibrahmsql/CVE-2023-45131)  

---

### [CVE-2011-2523](CVE-2011-2523-JohanMV_explotacion-vsftpd-nmap_Laboratorio_1.md) 🔴 ✅

**名称:** CVE-2011-2523 - vsftpd 2.3.4 后门  
**类型:** 后门  
**风险:** 高危，允许远程命令执行  
**投毒风险:** 1%  
**发现时间:** 2025-07-06  
**POC仓库:** [explotacion-vsftpd-nmap_Laboratorio_1](https://github.com/JohanMV/explotacion-vsftpd-nmap_Laboratorio_1)  

---

### [CVE-2011-2523](CVE-2011-2523-lghost256_vsftpd234-exploit.md) 🔴 ✅

**名称:** CVE-2011-2523-vsftpd 2.3.4 Backdoor Command Execution  
**类型:** 后门  
**风险:** 高危，可直接获取服务器控制权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-06  
**POC仓库:** [vsftpd234-exploit](https://github.com/lghost256/vsftpd234-exploit)  

---

### [CVE-2011-2523](CVE-2011-2523-hklabCR_CVE-2011-2523.md) 🔴 ✅

**名称:** CVE-2011-2523-vsftpd-Backdoor  
**类型:** 后门  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-06  
**POC仓库:** [CVE-2011-2523](https://github.com/hklabCR/CVE-2011-2523)  

---

### [CVE-2023-37467](CVE-2023-37467-ibrahmsql_CVE-2023-37467.md) 🟡 ✅

**名称:** CVE-2023-37467: Discourse CSP Nonce Reuse Bypass  
**类型:** CSP Nonce 重用漏洞  
**风险:** 中危，可能导致XSS攻击  
**投毒风险:** 0%  
**发现时间:** 2025-07-06  
**POC仓库:** [CVE-2023-37467](https://github.com/ibrahmsql/CVE-2023-37467)  

---

### [CVE-2024-36991](CVE-2024-36991-Zin0D_CVE-2024-36991.md) 🔴 ✅

**名称:** CVE-2024-36991 - Splunk Enterprise on Windows 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，可能导致任意文件读取  
**投毒风险:** 0%  
**发现时间:** 2025-07-06  
**POC仓库:** [CVE-2024-36991](https://github.com/Zin0D/CVE-2024-36991)  

---

### [CVE-2025-3248](CVE-2025-3248-r0otk3r_CVE-2025-3248.md) 🔴 ✅

**名称:** CVE-2025-3248-Langflow-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-06  
**POC仓库:** [CVE-2025-3248](https://github.com/r0otk3r/CVE-2025-3248)  

---

### [CVE-2024-9264](CVE-2024-9264-ruizii_CVE-2024-9264.md) 🔴 ✅

**名称:** CVE-2024-9264-Grafana-RCE&LFI  
**类型:** 远程代码执行 (RCE) 和本地文件包含 (LFI)  
**风险:** 高危，可能导致远程代码执行、敏感信息泄露和服务器控制  
**投毒风险:** 5%  
**发现时间:** 2025-07-06  
**POC仓库:** [CVE-2024-9264](https://github.com/ruizii/CVE-2024-9264)  

---

### [CVE-2025-5777](CVE-2025-5777-nocerainfosec_cve-2025-5777.md) 🔴 ✅

**名称:** CVE-2025-5777 - NetScaler ADC/Gateway 内存泄露  
**类型:** 内存泄露  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-07-06  
**POC仓库:** [cve-2025-5777](https://github.com/nocerainfosec/cve-2025-5777)  

---

### [CVE-2024-55963](CVE-2024-55963-superswan_CVE-2024-55963.md) 🟡 ✅

**名称:** CVE-2024-55963-Appsmith-拒绝服务  
**类型:** 拒绝服务 (DoS)  
**风险:** 中危，导致服务中断  
**投毒风险:** 0%  
**发现时间:** 2025-07-06  
**POC仓库:** [CVE-2024-55963](https://github.com/superswan/CVE-2024-55963)  

---

### [CVE-2021-41773](CVE-2021-41773-r0otk3r_CVE-2021-41773.md) 🔴 ✅

**名称:** CVE-2021-41773 - Apache HTTP Server Path Traversal and Remote Code Execution  
**类型:** 路径遍历和远程代码执行  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-05  
**POC仓库:** [CVE-2021-41773](https://github.com/r0otk3r/CVE-2021-41773)  

---

### [CVE-2024-42364](CVE-2024-42364-ibrahmsql_CVE-2024-42364.md) 🟡 ✅

**名称:** CVE-2024-42364-homepage-DNS Rebinding  
**类型:** DNS Rebinding  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 95%  
**发现时间:** 2025-07-05  
**POC仓库:** [CVE-2024-42364](https://github.com/ibrahmsql/CVE-2024-42364)  

---

### [CVE-2024-35198](CVE-2024-35198-ibrahmsql_CVE-2024-35198.md) 🔴 ✅

**名称:** CVE-2024-35198-TorchServe-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致任意文件读取、写入和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-05  
**POC仓库:** [CVE-2024-35198](https://github.com/ibrahmsql/CVE-2024-35198)  

---

### [CVE-2019-11479](CVE-2019-11479-ibrahmsql_CVE-2019-11479.md) 🟡 ✅

**名称:** CVE-2019-11479-Linux Kernel-TCP SACK Panic  
**类型:** 拒绝服务  
**风险:** 中危，可能导致服务器资源耗尽，影响服务可用性  
**投毒风险:** 85%  
**发现时间:** 2025-07-05  
**POC仓库:** [CVE-2019-11479](https://github.com/ibrahmsql/CVE-2019-11479)  

---

### [CVE-2021-41163](CVE-2021-41163-ibrahmsql_discourse-CVE-2021-41163.md) 🔴 ✅

**名称:** CVE-2021-41163-Discourse-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-07-05  
**POC仓库:** [discourse-CVE-2021-41163](https://github.com/ibrahmsql/discourse-CVE-2021-41163)  

---

### [CVE-2021-41163](CVE-2021-41163-ibrahmsql_CVE-2021-41163.md) 🔴 ✅

**名称:** CVE-2021-41163-Discourse-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-05  
**POC仓库:** [CVE-2021-41163](https://github.com/ibrahmsql/CVE-2021-41163)  

---

### [CVE-2023-49103](CVE-2023-49103-creacitysec_CVE-2023-49103.md) 🔴 ✅

**名称:** CVE-2023-49103 - ownCloud graphapi 信息泄露  
**类型:** 信息泄露  
**风险:** 高危，可能泄露敏感凭据和配置信息  
**投毒风险:** 1%  
**发现时间:** 2025-07-05  
**POC仓库:** [CVE-2023-49103](https://github.com/creacitysec/CVE-2023-49103)  

---

### [CVE-2023-49103](CVE-2023-49103-merlin-ke_OwnCloud-CVE-2023-49103.md) 🔴 ✅

**名称:** CVE-2023-49103-ownCloud-敏感信息泄露  
**类型:** 敏感信息泄露  
**风险:** 高危，可能导致敏感信息泄露，包括管理员密码、邮件服务器凭据和license key  
**投毒风险:** 0%  
**发现时间:** 2025-07-05  
**POC仓库:** [OwnCloud-CVE-2023-49103](https://github.com/merlin-ke/OwnCloud-CVE-2023-49103)  

---

### [CVE-2023-49103](CVE-2023-49103-d0rb_CVE-2023-49103.md) 🔴 ✅

**名称:** CVE-2023-49103 - ownCloud graphapi 信息泄露  
**类型:** 信息泄露  
**风险:** 高危，可能导致敏感信息泄露，进而导致完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-05  
**POC仓库:** [CVE-2023-49103](https://github.com/d0rb/CVE-2023-49103)  

---

### [CVE-2023-49103](CVE-2023-49103-ibrahmsql_CVE-2023-49103.md) 🔴 ✅

**名称:** CVE-2023-49103-ownCloud-敏感信息泄露  
**类型:** 信息泄露  
**风险:** 高危，可能导致敏感信息泄露，如管理员密码、邮件服务器凭据、license key等  
**投毒风险:** 95%  
**发现时间:** 2025-07-05  
**POC仓库:** [CVE-2023-49103](https://github.com/ibrahmsql/CVE-2023-49103)  

---

### [CVE-2022-31053](CVE-2022-31053-ibrahmsql_CVE-2022-31053.md) 🔴 ✅

**名称:** CVE-2022-31053: Discourse SSRF via Onebox URL Preview  
**类型:** SSRF（服务器端请求伪造）  
**风险:** 高危，允许攻击者访问内部资源，可能导致敏感信息泄露。  
**投毒风险:** 2%  
**发现时间:** 2025-07-05  
**POC仓库:** [CVE-2022-31053](https://github.com/ibrahmsql/CVE-2022-31053)  

---

### [CVE-2024-28084](CVE-2024-28084-ibrahmsql_CVE-2024-28084.md) 🔴 

**名称:** CVE-2024-28084-iwd-不当初始化导致拒绝服务  
**类型:** 拒绝服务  
**风险:** 高危，可导致服务崩溃  
**投毒风险:** 95%  
**发现时间:** 2025-07-05  
**POC仓库:** [CVE-2024-28084](https://github.com/ibrahmsql/CVE-2024-28084)  

---

### [CVE-2025-32463](CVE-2025-32463-junxian428_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地权限提升  
**风险:** 高危，本地用户可获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-05  
**POC仓库:** [CVE-2025-32463](https://github.com/junxian428/CVE-2025-32463)  

---

### [CVE-2025-0411](CVE-2025-0411-B1ack4sh_Blackash-CVE-2025-0411.md) 🔴 ✅

**名称:** CVE-2025-0411-7-Zip-Mark-of-the-Web绕过  
**类型:** Mark-of-the-Web绕过  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-07-05  
**POC仓库:** [Blackash-CVE-2025-0411](https://github.com/B1ack4sh/Blackash-CVE-2025-0411)  

---

### [CVE-2023-27350](CVE-2023-27350-Royall-Researchers_CVE-2023-27350.md) 🔴 ✅

**名称:** CVE-2023-27350 PaperCut NG/MF 身份验证绕过远程代码执行漏洞  
**类型:** 身份验证绕过 + 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-07-05  
**POC仓库:** [CVE-2023-27350](https://github.com/Royall-Researchers/CVE-2023-27350)  

---

### [CVE-2025-49493](CVE-2025-49493-B1ack4sh_Blackash-CVE-2025-49493.md) 🟡 ✅

**名称:** CVE-2025-49493 Akamai CloudTest XXE注入  
**类型:** XML外部实体注入 (XXE)  
**风险:** 中危，可能导致敏感文件泄露  
**投毒风险:** 5%  
**发现时间:** 2025-07-05  
**POC仓库:** [Blackash-CVE-2025-49493](https://github.com/B1ack4sh/Blackash-CVE-2025-49493)  

---

### [CVE-2024-9264](CVE-2024-9264-Royall-Researchers_CVE-2024-9264.md) 🔴 ✅

**名称:** CVE-2024-9264-Grafana-远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致系统完全控制和敏感数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-07-05  
**POC仓库:** [CVE-2024-9264](https://github.com/Royall-Researchers/CVE-2024-9264)  

---

### [CVE-2025-5777](CVE-2025-5777-idobarel_CVE-2025-5777.md) 🔴 ✅

**名称:** CVE-2025-5777-NetScaler-内存信息泄露  
**类型:** 内存信息泄露  
**风险:** 高危，可能导致凭据泄露和其他敏感信息泄露，最终导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-05  
**POC仓库:** [CVE-2025-5777](https://github.com/idobarel/CVE-2025-5777)  

---

### [CVE-2023-52927](CVE-2023-52927-seadragnol_CVE-2023-52927-private.md) 🔴 ✅

**名称:** CVE-2023-52927  
**类型:** UAF（Use-After-Free）  
**风险:** 高危，可导致本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-07-05  
**POC仓库:** [CVE-2023-52927-private](https://github.com/seadragnol/CVE-2023-52927-private)  

---

### [CVE-2025-24071](CVE-2025-24071-Royall-Researchers_CVE-2025-24071.md) 🟡 ✅

**名称:** CVE-2025-24071 Microsoft Windows File Explorer Spoofing Vulnerability  
**类型:** 信息泄露/NTLM Hash Capture  
**风险:** 中危，可能导致凭据泄露和进一步的横向移动  
**投毒风险:** 10%  
**发现时间:** 2025-07-05  
**POC仓库:** [CVE-2025-24071](https://github.com/Royall-Researchers/CVE-2025-24071)  

---

### [CVE-2023-52927](CVE-2023-52927-seadragnol_CVE-2023-52927.md) 🔴 ✅

**名称:** CVE-2023-52927 - Linux Kernel Netfilter UAF  
**类型:** Use-After-Free (UAF)  
**风险:** 高危，本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-07-05  
**POC仓库:** [CVE-2023-52927](https://github.com/seadragnol/CVE-2023-52927)  

---

### [CVE-2025-32462](CVE-2025-32462-SpongeBob-369_cve-2025-32462.md) 🟡 ✅

**名称:** CVE-2025-32462-Sudo-主机权限绕过  
**类型:** 权限提升  
**风险:** 中危，可能导致用户在不应有的主机上执行命令  
**投毒风险:** 0%  
**发现时间:** 2025-07-05  
**POC仓库:** [cve-2025-32462](https://github.com/SpongeBob-369/cve-2025-32462)  

---

### [CVE-2025-22963](CVE-2025-22963-samplev45_CVE-2025-22963.md) 🔴 ✅

**名称:** CVE-2025-22963-Teedy-CSRF账户接管  
**类型:** CSRF (跨站请求伪造)  
**风险:** 高危，可能导致账户接管  
**投毒风险:** 10%  
**发现时间:** 2025-07-05  
**POC仓库:** [CVE-2025-22963](https://github.com/samplev45/CVE-2025-22963)  

---

### [CVE-2025-32463](CVE-2025-32463-SkylerMC_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地权限提升  
**类型:** 本地权限提升  
**风险:** 高危，本地用户可获得root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-05  
**POC仓库:** [CVE-2025-32463](https://github.com/SkylerMC/CVE-2025-32463)  

---

### [CVE-2025-32463](CVE-2025-32463-B1ack4sh_Blackash-CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，可使本地用户获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-04  
**POC仓库:** [Blackash-CVE-2025-32463](https://github.com/B1ack4sh/Blackash-CVE-2025-32463)  

---

### [CVE-2025-5777](CVE-2025-5777-RickGeex_CVE-2025-5777-CitrixBleed.md) 🔴 ✅

**名称:** CVE-2025-5777-NetScaler ADC/Gateway 内存泄露  
**类型:** 内存泄露/信息泄露  
**风险:** 高危，可能导致会话劫持、身份验证绕过和敏感数据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-07-04  
**POC仓库:** [CVE-2025-5777-CitrixBleed](https://github.com/RickGeex/CVE-2025-5777-CitrixBleed)  

---

### [CVE-2025-32463](CVE-2025-32463-cyberpoul_CVE-2025-32463-POC.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，允许本地用户获取Root权限  
**投毒风险:** 1%  
**发现时间:** 2025-07-04  
**POC仓库:** [CVE-2025-32463-POC](https://github.com/cyberpoul/CVE-2025-32463-POC)  

---

### [CVE-2025-32462](CVE-2025-32462-cyberpoul_CVE-2025-32462-POC.md) 🟡 ✅

**名称:** CVE-2025-32462 - Sudo主机选项权限提升  
**类型:** 权限提升  
**风险:** 中危，可能导致本地权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-07-04  
**POC仓库:** [CVE-2025-32462-POC](https://github.com/cyberpoul/CVE-2025-32462-POC)  

---

### [CVE-2025-6554](CVE-2025-6554-PwnToday_CVE-2025-6554.md) 🔴 ✅

**名称:** CVE-2025-6554 - Google Chrome V8 类型混淆漏洞  
**类型:** 类型混淆  
**风险:** 高危，允许远程攻击者执行任意读/写操作  
**投毒风险:** 0%  
**发现时间:** 2025-07-04  
**POC仓库:** [CVE-2025-6554](https://github.com/PwnToday/CVE-2025-6554)  

---

### [CVE-2025-32463](CVE-2025-32463-yeremeu_CVE-2025-32463_chwoot.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可获取root权限  
**投毒风险:** 1%  
**发现时间:** 2025-07-04  
**POC仓库:** [CVE-2025-32463_chwoot](https://github.com/yeremeu/CVE-2025-32463_chwoot)  

---

### [CVE-2025-23968](CVE-2025-23968-d0n601_CVE-2025-23968.md) 🔴 ✅

**名称:** CVE-2025-23968-AiBud_WP-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-04  
**POC仓库:** [CVE-2025-23968](https://github.com/d0n601/CVE-2025-23968)  

---

### [CVE-2025-47812](CVE-2025-47812-ill-deed_WingFTP-CVE-2025-47812-illdeed.md) 🔴 ✅

**名称:** CVE-2025-47812 - Wing FTP Server RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致完全控制服务器  
**投毒风险:** 0%  
**发现时间:** 2025-07-04  
**POC仓库:** [WingFTP-CVE-2025-47812-illdeed](https://github.com/ill-deed/WingFTP-CVE-2025-47812-illdeed)  

---

### [CVE-2025-20281](CVE-2025-20281-ill-deed_Cisco-CVE-2025-20281-illdeed.md) 🔴 ✅

**名称:** CVE-2025-20281-Cisco ISE ERS API未授权RCE  
**类型:** 远程代码执行  
**风险:** 高危，未授权远程代码执行，获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-04  
**POC仓库:** [Cisco-CVE-2025-20281-illdeed](https://github.com/ill-deed/Cisco-CVE-2025-20281-illdeed)  

---

### [CVE-2024-4040](CVE-2024-4040-tucommenceapousser_CVE-2024-4040-Scanner.md) 🔴 ✅

**名称:** CVE-2024-4040-CrushFTP-SSTI  
**类型:** 服务器端模板注入 (SSTI)  
**风险:** 高危，可能导致任意文件读取、权限绕过和远程代码执行  
**投毒风险:** 50%  
**发现时间:** 2025-07-04  
**POC仓库:** [CVE-2024-4040-Scanner](https://github.com/tucommenceapousser/CVE-2024-4040-Scanner)  

---

### [CVE-2024-4040](CVE-2024-4040-rbih-boulanouar_CVE-2024-4040.md)  ✅

**名称:** CVE-2024-4040-CrushFTP-SSTI  
**类型:** 服务器端模板注入(SSTI)  
**风险:** 严重，允许未经身份验证的远程攻击者读取文件系统中的文件，绕过身份验证以获得管理访问权限，并在服务器上执行远程代码。  
**投毒风险:** 0%  
**发现时间:** 2025-07-04  
**POC仓库:** [CVE-2024-4040](https://github.com/rbih-boulanouar/CVE-2024-4040)  

---

### [CVE-2024-4040](CVE-2024-4040-Mufti22_CVE-2024-4040.md) 🔴 ✅

**名称:** CVE-2024-4040-CrushFTP-SSTI  
**类型:** 服务器端模板注入 (SSTI)  
**风险:** 高危，可导致任意文件读取，权限绕过，远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-04  
**POC仓库:** [CVE-2024-4040](https://github.com/Mufti22/CVE-2024-4040)  

---

### [CVE-2024-4040](CVE-2024-4040-0xN7y_CVE-2024-4040.md) 🔴 ✅

**名称:** CVE-2024-4040-CrushFTP-服务器端模板注入  
**类型:** 服务器端模板注入  
**风险:** 高危，可能导致任意文件读取、身份验证绕过和远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-07-04  
**POC仓库:** [CVE-2024-4040](https://github.com/0xN7y/CVE-2024-4040)  

---

### [CVE-2024-4040](CVE-2024-4040-Praison001_CVE-2024-4040-CrushFTP-server.md)  ✅

**名称:** CVE-2024-4040-CrushFTP-服务器端模板注入  
**类型:** 服务器端模板注入 (SSTI)  
**风险:** 极危，可能导致任意文件读取，身份验证绕过和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-04  
**POC仓库:** [CVE-2024-4040-CrushFTP-server](https://github.com/Praison001/CVE-2024-4040-CrushFTP-server)  

---

### [CVE-2024-4040](CVE-2024-4040-Mohammaddvd_CVE-2024-4040.md)  ✅

**名称:** CVE-2024-4040 CrushFTP服务器端模板注入漏洞  
**类型:** 服务器端模板注入 (SSTI)  
**风险:** 极高，可能导致任意文件读取、身份验证绕过和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-04  
**POC仓库:** [CVE-2024-4040](https://github.com/Mohammaddvd/CVE-2024-4040)  

---

### [CVE-2024-4040](CVE-2024-4040-jakabakos_CVE-2024-4040-CrushFTP-File-Read-vulnerability.md)  ✅

**名称:** CVE-2024-4040-CrushFTP-SSTI  
**类型:** 服务器端模板注入(SSTI)  
**风险:** 严重，可能导致任意文件读取，身份验证绕过和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-04  
**POC仓库:** [CVE-2024-4040-CrushFTP-File-Read-vulnerability](https://github.com/jakabakos/CVE-2024-4040-CrushFTP-File-Read-vulnerability)  

---

### [CVE-2024-4040](CVE-2024-4040-gotr00t0day_CVE-2024-4040.md)  ✅

**名称:** CVE-2024-4040 - CrushFTP Server-Side Template Injection  
**类型:** 服务器端模板注入 (SSTI)  
**风险:** 严重，未经身份验证的远程攻击者可以读取文件系统中的任意文件，绕过身份验证以获得管理访问权限，并在服务器上执行远程代码。  
**投毒风险:** 10%  
**发现时间:** 2025-07-04  
**POC仓库:** [CVE-2024-4040](https://github.com/gotr00t0day/CVE-2024-4040)  

---

### [CVE-2024-4040](CVE-2024-4040-1ncendium_CVE-2024-4040.md) 🔴 ✅

**名称:** CVE-2024-4040-CrushFTP-服务器端模板注入  
**类型:** 服务器端模板注入 (SSTI)  
**风险:** 高危，可导致任意文件读取、认证绕过和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-04  
**POC仓库:** [CVE-2024-4040](https://github.com/1ncendium/CVE-2024-4040)  

---

### [CVE-2024-4040](CVE-2024-4040-airbus-cert_CVE-2024-4040.md) 🔴 ✅

**名称:** CVE-2024-4040-CrushFTP-SSTI  
**类型:** 服务器端模板注入 (SSTI)  
**风险:** 高危，可能导致任意文件读取、认证绕过和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-04  
**POC仓库:** [CVE-2024-4040](https://github.com/airbus-cert/CVE-2024-4040)  

---

### [CVE-2024-4040](CVE-2024-4040-olebris_CVE-2024-4040.md) 🔴 ✅

**名称:** CVE-2024-4040-CrushFTP-SSTI  
**类型:** 服务器端模板注入 (SSTI)  
**风险:** 高危，可能导致任意文件读取、身份验证绕过和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-04  
**POC仓库:** [CVE-2024-4040](https://github.com/olebris/CVE-2024-4040)  

---

### [CVE-2024-4040](CVE-2024-4040-Stuub_CVE-2024-4040-SSTI-LFI-PoC.md) 🔴 ✅

**名称:** CVE-2024-4040 CrushFTP SSTI & LFI  
**类型:** 服务器端模板注入 (SSTI) 和本地文件包含 (LFI)  
**风险:** 高危，未经身份验证的远程攻击者可以读取文件系统中的文件、绕过身份验证以获得管理权限，并在服务器上执行远程代码。  
**投毒风险:** 10%  
**发现时间:** 2025-07-04  
**POC仓库:** [CVE-2024-4040-SSTI-LFI-PoC](https://github.com/Stuub/CVE-2024-4040-SSTI-LFI-PoC)  

---

### [CVE-2024-4040](CVE-2024-4040-entroychang_CVE-2024-4040.md) 🔴 ✅

**名称:** CVE-2024-4040-CrushFTP-服务器端模板注入  
**类型:** 服务器端模板注入 (SSTI)  
**风险:** 极高危，可能导致任意文件读取、认证绕过和远程代码执行  
**投毒风险:** 80%  
**发现时间:** 2025-07-04  
**POC仓库:** [CVE-2024-4040](https://github.com/entroychang/CVE-2024-4040)  

---

### [CVE-2024-4040](CVE-2024-4040-geniuszly_GenCrushSSTIExploit.md) 🔴 ✅

**名称:** CVE-2024-4040-CrushFTP-SSTI  
**类型:** 服务器端模板注入 (SSTI)  
**风险:** 高危，可导致任意文件读取、身份验证绕过和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-04  
**POC仓库:** [GenCrushSSTIExploit](https://github.com/geniuszly/GenCrushSSTIExploit)  

---

### [CVE-2024-4040](CVE-2024-4040-safeer-accuknox_CrushFTP-cve-2024-4040-poc.md) 🔴 ✅

**名称:** CVE-2024-4040-CrushFTP-服务器端模板注入  
**类型:** 服务器端模板注入 (SSTI)  
**风险:** 高危，可能导致任意文件读取、身份验证绕过和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-04  
**POC仓库:** [CrushFTP-cve-2024-4040-poc](https://github.com/safeer-accuknox/CrushFTP-cve-2024-4040-poc)  

---

### [CVE-2024-4040](CVE-2024-4040-rahisec_CVE-2024-4040.md) 🔴 ✅

**名称:** CVE-2024-4040-CrushFTP-SSTI  
**类型:** 服务器端模板注入 (SSTI)  
**风险:** 高危，允许未授权的远程攻击者读取文件系统，绕过身份验证，并执行远程代码  
**投毒风险:** 10%  
**发现时间:** 2025-07-04  
**POC仓库:** [CVE-2024-4040](https://github.com/rahisec/CVE-2024-4040)  

---

### [CVE-2024-4040](CVE-2024-4040-ill-deed_CrushFTP-CVE-2024-4040-illdeed.md)  ✅

**名称:** CVE-2024-4040 - CrushFTP Authentication Bypass and Remote Code Execution  
**类型:** 服务器端模板注入 (SSTI)  
**风险:** 严重，未授权远程攻击者可以读取文件系统，绕过身份验证以获得管理权限，并在服务器上执行远程代码。  
**投毒风险:** 1%  
**发现时间:** 2025-07-04  
**POC仓库:** [CrushFTP-CVE-2024-4040-illdeed](https://github.com/ill-deed/CrushFTP-CVE-2024-4040-illdeed)  

---

### [CVE-2025-6907](CVE-2025-6907-byteReaper77_cve-2025-6907.md) 🔴 ✅

**名称:** CVE-2025-6907-code-projects Car Rental System-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-07-04  
**POC仓库:** [cve-2025-6907](https://github.com/byteReaper77/cve-2025-6907)  

---

### [CVE-2025-32463](CVE-2025-32463-ill-deed_CVE-2025-32463_illdeed.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可以获得root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-04  
**POC仓库:** [CVE-2025-32463_illdeed](https://github.com/ill-deed/CVE-2025-32463_illdeed)  

---

### [CVE-2025-32463](CVE-2025-32463-zinzloun_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，允许本地用户获得root权限  
**投毒风险:** 0%  
**发现时间:** 2025-07-04  
**POC仓库:** [CVE-2025-32463](https://github.com/zinzloun/CVE-2025-32463)  

---

### [CVE-2025-6554](CVE-2025-6554-windz3r0day_CVE-2025-6554.md) 🔴 ✅

**名称:** CVE-2025-6554-Chrome-类型混淆  
**类型:** 类型混淆  
**风险:** 高危，可导致任意读写  
**投毒风险:** 5%  
**发现时间:** 2025-07-04  
**POC仓库:** [CVE-2025-6554](https://github.com/windz3r0day/CVE-2025-6554)  

---

### [CVE-2025-5961](CVE-2025-5961-d0n601_CVE-2025-5961.md) 🔴 ✅

**名称:** CVE-2025-5961-WPvivid-Arbitrary File Upload  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-04  
**POC仓库:** [CVE-2025-5961](https://github.com/d0n601/CVE-2025-5961)  

---

### [CVE-2025-5961](CVE-2025-5961-Nxploited_CVE-2025-5961.md) 🔴 ✅

**名称:** CVE-2025-5961 - WPvivid Backup & Migration 任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-04  
**POC仓库:** [CVE-2025-5961](https://github.com/Nxploited/CVE-2025-5961)  

---

### [CVE-2025-41646](CVE-2025-41646-cyberre124_CVE-2025-41646---Critical-Authentication-Bypass-.md) 🔴 ✅

**名称:** CVE-2025-41646-RevPi Webstatus-Authentication Bypass  
**类型:** Authentication Bypass  
**风险:** 高危，可完全控制设备  
**投毒风险:** 10%  
**发现时间:** 2025-07-04  
**POC仓库:** [CVE-2025-41646---Critical-Authentication-Bypass-](https://github.com/cyberre124/CVE-2025-41646---Critical-Authentication-Bypass-)  

---

### [CVE-2021-29447](CVE-2021-29447-Tea-On_CVE-2021-29447-Authenticated-XXE-WordPress-5.6-5.7.md) 🔴 ✅

**名称:** CVE-2021-29447-WordPress-XXE  
**类型:** XML 外部实体注入 (XXE)  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-07-04  
**POC仓库:** [CVE-2021-29447-Authenticated-XXE-WordPress-5.6-5.7](https://github.com/Tea-On/CVE-2021-29447-Authenticated-XXE-WordPress-5.6-5.7)  

---

### [CVE-2025-49132](CVE-2025-49132-uxieltc_CVE-2025-49132.md) 🔴 ✅

**名称:** CVE-2025-49132-Pterodactyl Panel-远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 极高危，未经身份验证的远程代码执行，可能导致完全控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-07-04  
**POC仓库:** [CVE-2025-49132](https://github.com/uxieltc/CVE-2025-49132)  

---

### [CVE-2025-27817](CVE-2025-27817-iSee857_CVE-2025-27817.md) 🔴 ✅

**名称:** CVE-2025-27817-Apache Kafka Client-任意文件读取/SSRF  
**类型:** 任意文件读取/SSRF  
**风险:** 高危，可能导致敏感信息泄露、SSRF攻击，以及在Kafka Connect中提权  
**投毒风险:** 5%  
**发现时间:** 2025-07-04  
**POC仓库:** [CVE-2025-27817](https://github.com/iSee857/CVE-2025-27817)  

---

### [CVE-2025-32462](CVE-2025-32462-mylovem313_CVE-2025-32462.md) 🟡 ✅

**名称:** CVE-2025-32462-Sudo-Host绕过  
**类型:** 权限提升  
**风险:** 中危，可能导致本地权限提升  
**投毒风险:** 1%  
**发现时间:** 2025-07-03  
**POC仓库:** [CVE-2025-32462](https://github.com/mylovem313/CVE-2025-32462)  

---

### [CVE-2020-16012](CVE-2020-16012-aleksejspopovs_cve-2020-16012.md) 🟡 ✅

**名称:** CVE-2020-16012-Chrome-侧信道信息泄露  
**类型:** 侧信道信息泄露  
**风险:** 中危，可能导致跨域数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-07-03  
**POC仓库:** [cve-2020-16012](https://github.com/aleksejspopovs/cve-2020-16012)  

---

### [CVE-2020-16012](CVE-2020-16012-helidem_CVE-2020-16012-PoC.md) 🟡 ✅

**名称:** CVE-2020-16012-Chrome-侧信道信息泄露  
**类型:** 侧信道信息泄露  
**风险:** 中危，可能导致跨域数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-07-03  
**POC仓库:** [CVE-2020-16012-PoC](https://github.com/helidem/CVE-2020-16012-PoC)  

---

### [CVE-2025-32463](CVE-2025-32463-mirchr_CVE-2025-32463-sudo-chwoot.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo chroot 权限提升  
**类型:** 本地权限提升  
**风险:** 高危，本地用户可提升至root权限  
**投毒风险:** 1%  
**发现时间:** 2025-07-03  
**POC仓库:** [CVE-2025-32463-sudo-chwoot](https://github.com/mirchr/CVE-2025-32463-sudo-chwoot)  

---

### [CVE-2025-6554](CVE-2025-6554-rbaicba_CVE-2025-6554.md) 🔴 ✅

**名称:** CVE-2025-6554 Google Chrome V8 类型混淆漏洞  
**类型:** 类型混淆  
**风险:** 高危，允许远程攻击者执行任意读/写操作  
**投毒风险:** 1%  
**发现时间:** 2025-07-03  
**POC仓库:** [CVE-2025-6554](https://github.com/rbaicba/CVE-2025-6554)  

---

### [CVE-2024-48061](CVE-2024-48061-BwithE_CVE-2024-48061.md) 🔴 ✅

**名称:** CVE-2024-48061-langflow-远程代码执行  
**类型:** 远程代码执行(RCE)  
**风险:** 高危，可导致完全系统控制  
**投毒风险:** 1%  
**发现时间:** 2025-07-03  
**POC仓库:** [CVE-2024-48061](https://github.com/BwithE/CVE-2024-48061)  

---

### [CVE-2025-6543](CVE-2025-6543-abrewer251_CVE-2025-6543_CitrixNetScaler_PoC.md) 🔴 ✅

**名称:** CVE-2025-6543 NetScaler ADC/Gateway 内存溢出  
**类型:** 内存溢出  
**风险:** 高危，可能导致拒绝服务和控制流劫持  
**投毒风险:** 10%  
**发现时间:** 2025-07-03  
**POC仓库:** [CVE-2025-6543_CitrixNetScaler_PoC](https://github.com/abrewer251/CVE-2025-6543_CitrixNetScaler_PoC)  

---

### [CVE-2025-32463](CVE-2025-32463-CIA911_sudo_patch_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，允许本地用户获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-03  
**POC仓库:** [sudo_patch_CVE-2025-32463](https://github.com/CIA911/sudo_patch_CVE-2025-32463)  

---

### [CVE-2025-49596](CVE-2025-49596-ashiqrehan-21_MCP-Inspector-CVE-2025-49596.md)  ✅

**名称:** CVE-2025-49596-MCP Inspector-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，未经身份验证的攻击者可执行任意代码。  
**投毒风险:** 0%  
**发现时间:** 2025-07-03  
**POC仓库:** [MCP-Inspector-CVE-2025-49596](https://github.com/ashiqrehan-21/MCP-Inspector-CVE-2025-49596)  

---

### [CVE-2025-32462](CVE-2025-32462-cybersentinelx1_CVE-2025-32462-Exploit.md) 🟡 ✅

**名称:** CVE-2025-32462-Sudo主机名绕过  
**类型:** 权限提升  
**风险:** 中危，本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-07-03  
**POC仓库:** [CVE-2025-32462-Exploit](https://github.com/cybersentinelx1/CVE-2025-32462-Exploit)  

---

### [CVE-2022-38577](CVE-2022-38577-sornram9254_CVE-2022-38577-Processmaker.md) 🔴 ✅

**名称:** CVE-2022-38577-ProcessMaker-权限提升  
**类型:** 权限提升  
**风险:** 高危，可将普通用户权限提升至管理员权限  
**投毒风险:** 1%  
**发现时间:** 2025-07-03  
**POC仓库:** [CVE-2022-38577-Processmaker](https://github.com/sornram9254/CVE-2022-38577-Processmaker)  

---

### [CVE-2025-32462](CVE-2025-32462-atomicjjbod_CVE-2025-32462.md) 🟡 ✅

**名称:** CVE-2025-32462-Sudo-本地权限提升  
**类型:** 本地权限提升  
**风险:** 中危，本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-07-03  
**POC仓库:** [CVE-2025-32462](https://github.com/atomicjjbod/CVE-2025-32462)  

---

### [CVE-2025-6019](CVE-2025-6019-dreysanox_CVE-2025-6019_Poc.md) 🔴 ✅

**名称:** CVE-2025-6019-libblockdev-本地提权  
**类型:** 本地权限提升 (LPE)  
**风险:** 高危，攻击者可以从 allow_active 用户权限提升到 root 权限  
**投毒风险:** 1%  
**发现时间:** 2025-07-03  
**POC仓库:** [CVE-2025-6019_Poc](https://github.com/dreysanox/CVE-2025-6019_Poc)  

---

### [CVE-2025-32463](CVE-2025-32463-0xAkarii_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，允许本地用户获取root权限  
**投毒风险:** 0%  
**发现时间:** 2025-07-03  
**POC仓库:** [CVE-2025-32463](https://github.com/0xAkarii/CVE-2025-32463)  

---

### [CVE-2025-32463](CVE-2025-32463-san8383_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可提升至root权限  
**投毒风险:** 0%  
**发现时间:** 2025-07-03  
**POC仓库:** [CVE-2025-32463](https://github.com/san8383/CVE-2025-32463)  

---

### [CVE-2025-32463](CVE-2025-32463-nflatrea_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463 - Sudo 本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，本地用户可以获得 root 权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-03  
**POC仓库:** [CVE-2025-32463](https://github.com/nflatrea/CVE-2025-32463)  

---

### [CVE-2025-45407](CVE-2025-45407-yallasec_CVE-2025-45407.md) 🟡 ✅

**名称:** CVE-2025-45407-DiscoveryNG-XSS  
**类型:** XSS  
**风险:** 中危，可能导致用户数据泄露和恶意脚本执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-03  
**POC仓库:** [CVE-2025-45407](https://github.com/yallasec/CVE-2025-45407)  

---

### [CVE-2025-6018](CVE-2025-6018-iamgithubber_CVE-2025-6018-19-exploit.md) 🔴 ✅

**名称:** CVE-2025-6018-SUSE-PAM-LPE  
**类型:** 本地提权(LPE)  
**风险:** 高危，允许本地用户获取root权限  
**投毒风险:** 0%  
**发现时间:** 2025-07-03  
**POC仓库:** [CVE-2025-6018-19-exploit](https://github.com/iamgithubber/CVE-2025-6018-19-exploit)  

---

### [CVE-2025-32462](CVE-2025-32462-CryingN_CVE-2025-32462.md) 🟡 ✅

**名称:** CVE-2025-32462-Sudo-权限提升  
**类型:** 权限提升  
**风险:** 中危，允许本地用户在错误的机器上以root权限执行命令  
**投毒风险:** 10%  
**发现时间:** 2025-07-03  
**POC仓库:** [CVE-2025-32462](https://github.com/CryingN/CVE-2025-32462)  

---

### [CVE-2022-43110](CVE-2022-43110-ready2disclose_CVE-2022-43110.md) 🔴 

**名称:** CVE-2022-43110 Voltronic Viewpower/Pro 权限绕过漏洞  
**类型:** 权限绕过/直接请求（强制浏览）  
**风险:** 高危，可能导致未授权访问、系统配置篡改、UPS设备控制，甚至执行操作系统命令  
**投毒风险:** 10%  
**发现时间:** 2025-07-03  
**POC仓库:** [CVE-2022-43110](https://github.com/ready2disclose/CVE-2022-43110)  

---

### [CVE-2022-31491](CVE-2022-31491-ready2disclose_CVE-2022-31491.md) 🔴 

**名称:** CVE-2022-31491 Voltronic Viewpower/Pro RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致完全控制受影响的系统  
**投毒风险:** 10%  
**发现时间:** 2025-07-03  
**POC仓库:** [CVE-2022-31491](https://github.com/ready2disclose/CVE-2022-31491)  

---

### [CVE-2025-32463](CVE-2025-32463-Mikivirus0_sudoinjection.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地权限提升  
**类型:** 本地权限提升  
**风险:** 高危，本地用户可获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-03  
**POC仓库:** [sudoinjection](https://github.com/Mikivirus0/sudoinjection)  

---

### [CVE-2025-6218](CVE-2025-6218-mulwareX_CVE-2025-6218-POC.md) 🔴 ✅

**名称:** CVE-2025-6218-WinRAR目录遍历远程代码执行  
**类型:** 目录遍历导致的远程代码执行  
**风险:** 高危，允许攻击者在受害者计算机上执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-07-03  
**POC仓库:** [CVE-2025-6218-POC](https://github.com/mulwareX/CVE-2025-6218-POC)  

---

### [CVE-2025-20281](CVE-2025-20281-grupooruss_CVE-2025-20281-Cisco.md)  ✅

**名称:** CVE-2025-20281 - Cisco ISE Unauthenticated Remote Code Execution  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，未授权远程root权限代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-03  
**POC仓库:** [CVE-2025-20281-Cisco](https://github.com/grupooruss/CVE-2025-20281-Cisco)  

---

### [CVE-2021-44228](CVE-2021-44228-axisops_CVE-2021-44228.md) 🔴 ✅

**名称:** CVE-2021-44228-Apache Log4j2 JNDI 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-03  
**POC仓库:** [CVE-2021-44228](https://github.com/axisops/CVE-2021-44228)  

---

### [CVE-2025-24813](CVE-2025-24813-yaleman_cve-2025-24813-poc.md) 🔴 ✅

**名称:** CVE-2025-24813 Apache Tomcat RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-03  
**POC仓库:** [cve-2025-24813-poc](https://github.com/yaleman/cve-2025-24813-poc)  

---

### [CVE-2023-41425](CVE-2023-41425-Tea-On_CVE-2023-41425-RCE-WonderCMS-4.3.2.md) 🔴 ✅

**名称:** CVE-2023-41425-WonderCMS-XSS to RCE  
**类型:** 跨站脚本 (XSS) 到 远程代码执行 (RCE)  
**风险:** 高危，可能导致远程代码执行和服务器控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-02  
**POC仓库:** [CVE-2023-41425-RCE-WonderCMS-4.3.2](https://github.com/Tea-On/CVE-2023-41425-RCE-WonderCMS-4.3.2)  

---

### [CVE-2021-41773](CVE-2021-41773-psibot_apache-vulnerable.md) 🔴 ✅

**名称:** CVE-2021-41773 - Apache HTTP Server Path Traversal 和 RCE  
**类型:** Path Traversal, Remote Code Execution (RCE)  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-02  
**POC仓库:** [apache-vulnerable](https://github.com/psibot/apache-vulnerable)  

---

### [CVE-2021-41773](CVE-2021-41773-blu3ming_PoC-CVE-2021-41773.md) 🔴 ✅

**名称:** CVE-2021-41773 Apache HTTP Server Path Traversal  
**类型:** 路径遍历 (Path Traversal)  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-02  
**POC仓库:** [PoC-CVE-2021-41773](https://github.com/blu3ming/PoC-CVE-2021-41773)  

---

### [CVE-2025-47812](CVE-2025-47812-0xgh057r3c0n_CVE-2025-47812.md) 🔴 ✅

**名称:** CVE-2025-47812-Wing_FTP_Server-RCE  
**类型:** RCE  
**风险:** 高危，允许未授权用户完全控制服务器  
**投毒风险:** 5%  
**发现时间:** 2025-07-02  
**POC仓库:** [CVE-2025-47812](https://github.com/0xgh057r3c0n/CVE-2025-47812)  

---

### [CVE-2025-32463](CVE-2025-32463-robbert1978_CVE-2025-32463_POC.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可提升至root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-02  
**POC仓库:** [CVE-2025-32463_POC](https://github.com/robbert1978/CVE-2025-32463_POC)  

---

### [CVE-2025-32463](CVE-2025-32463-zhaduchanhzz_CVE-2025-32463_POC.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，允许本地用户获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-02  
**POC仓库:** [CVE-2025-32463_POC](https://github.com/zhaduchanhzz/CVE-2025-32463_POC)  

---

### [CVE-2025-6934](CVE-2025-6934-MrjHaxcore_CVE-2025-6934.md)  ✅

**名称:** CVE-2025-6934 - Opal Estate Pro 未授权权限提升  
**类型:** 权限提升  
**风险:** 严重，可导致网站完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-07-02  
**POC仓库:** [CVE-2025-6934](https://github.com/MrjHaxcore/CVE-2025-6934)  

---

### [CVE-2025-32463](CVE-2025-32463-pevinkumar10_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地权限提升  
**类型:** 本地权限提升  
**风险:** 高危，允许本地用户获取 root 权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-02  
**POC仓库:** [CVE-2025-32463](https://github.com/pevinkumar10/CVE-2025-32463)  

---

### [CVE-2025-32463](CVE-2025-32463-neko205-mx_CVE-2025-32463_Exploit.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可提升至root权限  
**投毒风险:** 10%  
**发现时间:** 2025-07-02  
**POC仓库:** [CVE-2025-32463_Exploit](https://github.com/neko205-mx/CVE-2025-32463_Exploit)  

---

### [CVE-2022-46169](CVE-2022-46169-alv-david_CVE-2022-46169-Cacti-1.2.22.md) 🔴 ✅

**名称:** CVE-2022-46169-Cacti-命令注入  
**类型:** 命令注入  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-02  
**POC仓库:** [CVE-2022-46169-Cacti-1.2.22](https://github.com/alv-david/CVE-2022-46169-Cacti-1.2.22)  

---

### [CVE-2024-23113](CVE-2024-23113-MAVRICK-1_cve-2024-23113-test-env.md) 🔴 ✅

**名称:** CVE-2024-23113 Fortinet Format String Vulnerability  
**类型:** 格式化字符串漏洞  
**风险:** 高危，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-02  
**POC仓库:** [cve-2024-23113-test-env](https://github.com/MAVRICK-1/cve-2024-23113-test-env)  

---

### [CVE-2025-32463](CVE-2025-32463-kh4sh3i_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地权限提升  
**类型:** 本地权限提升  
**风险:** 高危，可导致本地用户获取Root权限  
**投毒风险:** 0%  
**发现时间:** 2025-07-02  
**POC仓库:** [CVE-2025-32463](https://github.com/kh4sh3i/CVE-2025-32463)  

---

### [CVE-2025-21756](CVE-2025-21756-khoatran107_cve-2025-21756.md) 🔴 ✅

**名称:** CVE-2025-21756-Linux Kernel vsock Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可能导致本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-07-02  
**POC仓库:** [cve-2025-21756](https://github.com/khoatran107/cve-2025-21756)  

---

### [CVE-2024-8636](CVE-2024-8636-HyHy100_Chrome-Skia-CVE-2024-8636.md) 🔴 ✅

**名称:** CVE-2024-8636-Chrome-Skia堆缓冲区溢出  
**类型:** 堆缓冲区溢出  
**风险:** 高危，可能导致堆损坏和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-02  
**POC仓库:** [Chrome-Skia-CVE-2024-8636](https://github.com/HyHy100/Chrome-Skia-CVE-2024-8636)  

---

### [CVE-2024-8198](CVE-2024-8198-HyHy100_Chrome-Skia-CVE-2024-8198.md) 🔴 ✅

**名称:** CVE-2024-8198-Chrome-Skia堆缓冲区溢出  
**类型:** 堆缓冲区溢出  
**风险:** 高危，可能导致堆损坏和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-02  
**POC仓库:** [Chrome-Skia-CVE-2024-8198](https://github.com/HyHy100/Chrome-Skia-CVE-2024-8198)  

---

### [CVE-2024-8193](CVE-2024-8193-HyHy100_Chrome-Skia-CVE-2024-8193.md) 🔴 ✅

**名称:** CVE-2024-8193-Google Chrome-Skia堆缓冲区溢出  
**类型:** 堆缓冲区溢出  
**风险:** 高危，可能导致堆破坏和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-02  
**POC仓库:** [Chrome-Skia-CVE-2024-8193](https://github.com/HyHy100/Chrome-Skia-CVE-2024-8193)  

---

### [CVE-2024-7966](CVE-2024-7966-HyHy100_Chrome-Skia-CVE-2024-7966.md) 🔴 ✅

**名称:** CVE-2024-7966-Google Chrome-Skia Out-of-bounds Memory Access  
**类型:** Out-of-bounds Memory Access  
**风险:** 高危，可能导致信息泄露、任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-02  
**POC仓库:** [Chrome-Skia-CVE-2024-7966](https://github.com/HyHy100/Chrome-Skia-CVE-2024-7966)  

---

### [CVE-2025-49144](CVE-2025-49144-timsonner_CVE-2025-49144-Research.md) 🔴 ✅

**名称:** CVE-2025-49144-Notepad++-特权提升  
**类型:** 特权提升  
**风险:** 高危，允许本地用户获得SYSTEM权限  
**投毒风险:** 0%  
**发现时间:** 2025-07-02  
**POC仓库:** [CVE-2025-49144-Research](https://github.com/timsonner/CVE-2025-49144-Research)  

---

### [CVE-2018-6574](CVE-2018-6574-yavolo_CVE-2018-6574.md) 🔴 ✅

**名称:** CVE-2018-6574 - Go "go get" 远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-02  
**POC仓库:** [CVE-2018-6574](https://github.com/yavolo/CVE-2018-6574)  

---

### [CVE-2018-6574](CVE-2018-6574-jftierno_-CVE-2018-6574.md) 🔴 ✅

**名称:** CVE-2018-6574  
**类型:** 远程代码执行  
**风险:** 高危，可能导致完全控制受影响的系统  
**投毒风险:** 0%  
**发现时间:** 2025-07-02  
**POC仓库:** [-CVE-2018-6574](https://github.com/jftierno/-CVE-2018-6574)  

---

### [CVE-2018-6574](CVE-2018-6574-Saboor-Hakimi_CVE-2018-6574.md) 🔴 ✅

**名称:** CVE-2018-6574-Go-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-02  
**POC仓库:** [CVE-2018-6574](https://github.com/Saboor-Hakimi/CVE-2018-6574)  

---

### [CVE-2018-6574](CVE-2018-6574-frozenkp_CVE-2018-6574.md) 🔴 ✅

**名称:** CVE-2018-6574-go-get远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-02  
**POC仓库:** [CVE-2018-6574](https://github.com/frozenkp/CVE-2018-6574)  

---

### [CVE-2018-6574](CVE-2018-6574-the-valluvarsploit_CVE-2018-6574.md) 🔴 ✅

**名称:** CVE-2018-6574 - Go "go get" 远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-07-02  
**POC仓库:** [CVE-2018-6574](https://github.com/the-valluvarsploit/CVE-2018-6574)  

---

### [CVE-2018-6574](CVE-2018-6574-jftierno_CVE-2018-6574-2.md) 🔴 ✅

**名称:** CVE-2018-6574-Go-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-02  
**POC仓库:** [CVE-2018-6574-2](https://github.com/jftierno/CVE-2018-6574-2)  

---

### [CVE-2018-6574](CVE-2018-6574-Cypheer_exploit_CVE-2018-6574.md) 🔴 ✅

**名称:** CVE-2018-6574-Go-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-02  
**POC仓库:** [exploit_CVE-2018-6574](https://github.com/Cypheer/exploit_CVE-2018-6574)  

---

### [CVE-2018-6574](CVE-2018-6574-tjcim_cve-2018-6574.md) 🔴 ✅

**名称:** CVE-2018-6574-Go远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-07-02  
**POC仓库:** [cve-2018-6574](https://github.com/tjcim/cve-2018-6574)  

---

### [CVE-2018-6574](CVE-2018-6574-markisback_CVE-2018-6574.md) 🔴 ✅

**名称:** CVE-2018-6574 Go "go get" 远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-02  
**POC仓库:** [CVE-2018-6574](https://github.com/markisback/CVE-2018-6574)  

---

### [CVE-2018-6574](CVE-2018-6574-hasharmujahid_CVE-2018-6574-go-get-RCE.md) 🔴 ✅

**名称:** CVE-2018-6574 - Go "go get" 远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-02  
**POC仓库:** [CVE-2018-6574-go-get-RCE](https://github.com/hasharmujahid/CVE-2018-6574-go-get-RCE)  

---

### [CVE-2018-6574](CVE-2018-6574-rootxjs_CVE-2018-6574.md) 🔴 ✅

**名称:** CVE-2018-6574 - Go "go get" 远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致远程代码执行和系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-02  
**POC仓库:** [CVE-2018-6574](https://github.com/rootxjs/CVE-2018-6574)  

---

### [CVE-2018-6574](CVE-2018-6574-rootxjs_new-CVE-2018-6574.md) 🔴 ✅

**名称:** CVE-2018-6574 - Go "go get" 远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，允许远程命令执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-02  
**POC仓库:** [new-CVE-2018-6574](https://github.com/rootxjs/new-CVE-2018-6574)  

---

### [CVE-2018-6574](CVE-2018-6574-chr1sM_CVE-2018-6574.md) 🔴 ✅

**名称:** CVE-2018-6574  
**类型:** 远程代码执行  
**风险:** 高危，允许远程命令执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-02  
**POC仓库:** [CVE-2018-6574](https://github.com/chr1sM/CVE-2018-6574)  

---

### [CVE-2018-6574](CVE-2018-6574-mux0x_CVE-2018-6574.md) 🔴 ✅

**名称:** CVE-2018-6574 Go "go get" 远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，允许攻击者在构建过程中执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-07-02  
**POC仓库:** [CVE-2018-6574](https://github.com/mux0x/CVE-2018-6574)  

---

### [CVE-2018-6574](CVE-2018-6574-seoqqq_CVE-2018-6574.md) 🔴 ✅

**名称:** CVE-2018-6574 - Go "go get" 远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致系统完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-07-02  
**POC仓库:** [CVE-2018-6574](https://github.com/seoqqq/CVE-2018-6574)  

---

### [CVE-2018-6574](CVE-2018-6574-antunesmpedro_CVE-2018-6574.md) 🔴 ✅

**名称:** CVE-2018-6574 - Go "go get" 远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，允许远程命令执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-02  
**POC仓库:** [CVE-2018-6574](https://github.com/antunesmpedro/CVE-2018-6574)  

---

### [CVE-2018-6574](CVE-2018-6574-jahwni_CVE-2018-6574.md) 🔴 ✅

**名称:** CVE-2018-6574 - Go "go get" 远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-07-02  
**POC仓库:** [CVE-2018-6574](https://github.com/jahwni/CVE-2018-6574)  

---

### [CVE-2018-6574](CVE-2018-6574-NsByte_CVE-2018-6574.md) 🔴 ✅

**名称:** CVE-2018-6574 - Go "go get" 远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-02  
**POC仓库:** [CVE-2018-6574](https://github.com/NsByte/CVE-2018-6574)  

---

### [CVE-2018-6574](CVE-2018-6574-zerbaliy3v_cve-2018-6574-exploit.md) 🔴 ✅

**名称:** CVE-2018-6574-Go-get远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-02  
**POC仓库:** [cve-2018-6574-exploit](https://github.com/zerbaliy3v/cve-2018-6574-exploit)  

---

### [CVE-2018-6574](CVE-2018-6574-jftierno_CVE-2018-6574.md) 🔴 ✅

**名称:** CVE-2018-6574-Go-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-02  
**POC仓库:** [CVE-2018-6574](https://github.com/jftierno/CVE-2018-6574)  

---

### [CVE-2018-6574](CVE-2018-6574-faiqu3_cve-2018-6574.md) 🔴 ✅

**名称:** CVE-2018-6574 Go "go get" 远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-02  
**POC仓库:** [cve-2018-6574](https://github.com/faiqu3/cve-2018-6574)  

---

### [CVE-2018-6574](CVE-2018-6574-Dannners_CVE-2018-6574-go-get-RCE.md) 🔴 ✅

**名称:** CVE-2018-6574-go-get远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-02  
**POC仓库:** [CVE-2018-6574-go-get-RCE](https://github.com/Dannners/CVE-2018-6574-go-get-RCE)  

---

### [CVE-2018-6574](CVE-2018-6574-bme2003_CVE-2018-6574.md) 🔴 ✅

**名称:** CVE-2018-6574-go-get远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-07-02  
**POC仓库:** [CVE-2018-6574](https://github.com/bme2003/CVE-2018-6574)  

---

### [CVE-2018-6574](CVE-2018-6574-iNoSec2_cve-2018-6574.md) 🔴 ✅

**名称:** CVE-2018-6574  
**类型:** 远程代码执行  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-02  
**POC仓库:** [cve-2018-6574](https://github.com/iNoSec2/cve-2018-6574)  

---

### [CVE-2018-6574](CVE-2018-6574-faqihudin13_CVE-2018-6574.md) 🔴 ✅

**名称:** CVE-2018-6574-Go-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-02  
**POC仓库:** [CVE-2018-6574](https://github.com/faqihudin13/CVE-2018-6574)  

---

### [CVE-2018-6574](CVE-2018-6574-lisu60_cve-2018-6574.md) 🔴 ✅

**名称:** CVE-2018-6574-go get 远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致系统被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-07-02  
**POC仓库:** [cve-2018-6574](https://github.com/lisu60/cve-2018-6574)  

---

### [CVE-2018-6574](CVE-2018-6574-elw0od_PentesterLab.md) 🔴 ✅

**名称:** CVE-2018-6574-go-get远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-02  
**POC仓库:** [PentesterLab](https://github.com/elw0od/PentesterLab)  

---

### [CVE-2018-6574](CVE-2018-6574-paulogmota_CVE-2018-6574.md) 🔴 ✅

**名称:** CVE-2018-6574 - Go "go get" 远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，允许攻击者在目标系统上执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-07-02  
**POC仓库:** [CVE-2018-6574](https://github.com/paulogmota/CVE-2018-6574)  

---

### [CVE-2025-32463](CVE-2025-32463-SysMancer_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可提升至root权限  
**投毒风险:** 5%  
**发现时间:** 2025-07-02  
**POC仓库:** [CVE-2025-32463](https://github.com/SysMancer/CVE-2025-32463)  

---

### [CVE-2025-31650](CVE-2025-31650-B1gN0Se_Tomcat-CVE-2025-31650.md) 🔴 ✅

**名称:** CVE-2025-31650 - Apache Tomcat DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致服务器瘫痪  
**投毒风险:** 10%  
**发现时间:** 2025-07-02  
**POC仓库:** [Tomcat-CVE-2025-31650](https://github.com/B1gN0Se/Tomcat-CVE-2025-31650)  

---

### [CVE-2019-16891](CVE-2019-16891-hrxknight_CVE-2019-16891-Liferay-deserialization-RCE.md) 🔴 

**名称:** CVE-2019-16891-Liferay-反序列化-RCE  
**类型:** 反序列化漏洞  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-02  
**POC仓库:** [CVE-2019-16891-Liferay-deserialization-RCE](https://github.com/hrxknight/CVE-2019-16891-Liferay-deserialization-RCE)  

---

### [CVE-2025-32463](CVE-2025-32463-Adonijah01_cve-2025-32463-lab.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地权限提升  
**类型:** 本地权限提升  
**风险:** 高危，本地用户可以获得root权限  
**投毒风险:** 0%  
**发现时间:** 2025-07-02  
**POC仓库:** [cve-2025-32463-lab](https://github.com/Adonijah01/cve-2025-32463-lab)  

---

### [CVE-2025-49493](CVE-2025-49493-MuhammadWaseem29_CVE-2025-49493-Poc.md) 🟡 ✅

**名称:** CVE-2025-49493-AkamaiCloudTest-XXE注入  
**类型:** XML外部实体(XXE)注入  
**风险:** 中危，可能导致文件包含  
**投毒风险:** 0%  
**发现时间:** 2025-07-01  
**POC仓库:** [CVE-2025-49493-Poc](https://github.com/MuhammadWaseem29/CVE-2025-49493-Poc)  

---

### [CVE-2022-22963](CVE-2022-22963-AayushmanThapaMagar_CVE-2022-22963.md) 🔴 ✅

**名称:** CVE-2022-22963-Spring Cloud Function-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致完全控制服务器  
**投毒风险:** 0%  
**发现时间:** 2025-07-01  
**POC仓库:** [CVE-2022-22963](https://github.com/AayushmanThapaMagar/CVE-2022-22963)  

---

### [CVE-2022-22963](CVE-2022-22963-me2nuk_CVE-2022-22963.md) 🔴 ✅

**名称:** CVE-2022-22963-Spring Cloud Function-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致远程代码执行，完全控制服务器  
**投毒风险:** 0%  
**发现时间:** 2025-07-01  
**POC仓库:** [CVE-2022-22963](https://github.com/me2nuk/CVE-2022-22963)  

---

### [CVE-2022-22963](CVE-2022-22963-twseptian_cve-2022-22963.md) 🔴 ✅

**名称:** CVE-2022-22963 - Spring Cloud Function SpEL 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-07-01  
**POC仓库:** [cve-2022-22963](https://github.com/twseptian/cve-2022-22963)  

---

### [CVE-2022-22963](CVE-2022-22963-SealPaPaPa_SpringCloudFunction-Research.md) 🔴 ✅

**名称:** CVE-2022-22963-Spring Cloud Function-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-07-01  
**POC仓库:** [SpringCloudFunction-Research](https://github.com/SealPaPaPa/SpringCloudFunction-Research)  

---

### [CVE-2022-22963](CVE-2022-22963-darryk10_CVE-2022-22963.md) 🔴 ✅

**名称:** CVE-2022-22963 - Spring Cloud Function SpEL 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，无需身份验证即可远程执行代码，完全控制服务器  
**投毒风险:** 5%  
**发现时间:** 2025-07-01  
**POC仓库:** [CVE-2022-22963](https://github.com/darryk10/CVE-2022-22963)  

---

### [CVE-2022-22963](CVE-2022-22963-k3rwin_spring-cloud-function-rce.md) 🔴 ✅

**名称:** CVE-2022-22963-Spring Cloud Function SpEL表达式注入  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-07-01  
**POC仓库:** [spring-cloud-function-rce](https://github.com/k3rwin/spring-cloud-function-rce)  

---

### [CVE-2022-22963](CVE-2022-22963-iliass-dahman_CVE-2022-22963-POC.md) 🔴 ✅

**名称:** CVE-2022-22963-Spring Cloud Function-远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-07-01  
**POC仓库:** [CVE-2022-22963-POC](https://github.com/iliass-dahman/CVE-2022-22963-POC)  

---

### [CVE-2022-22963](CVE-2022-22963-hktalent_spring-spel-0day-poc.md) 🔴 ✅

**名称:** CVE-2022-22963-Spring Cloud Function-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致完全控制受影响的系统  
**投毒风险:** 1%  
**发现时间:** 2025-07-01  
**POC仓库:** [spring-spel-0day-poc](https://github.com/hktalent/spring-spel-0day-poc)  

---

### [CVE-2022-22963](CVE-2022-22963-G01d3nW01f_CVE-2022-22963.md) 🔴 ✅

**名称:** CVE-2022-22963 - Spring Cloud Function SpEL 表达式注入导致远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致完全控制受影响的服务器  
**投毒风险:** 5%  
**发现时间:** 2025-07-01  
**POC仓库:** [CVE-2022-22963](https://github.com/G01d3nW01f/CVE-2022-22963)  

---

### [CVE-2022-22963](CVE-2022-22963-lemmyz4n3771_CVE-2022-22963-PoC.md) 🔴 ✅

**名称:** CVE-2022-22963-Spring Cloud Function-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-07-01  
**POC仓库:** [CVE-2022-22963-PoC](https://github.com/lemmyz4n3771/CVE-2022-22963-PoC)  

---

### [CVE-2022-22963](CVE-2022-22963-J0ey17_CVE-2022-22963_Reverse-Shell-Exploit.md) 🔴 ✅

**名称:** CVE-2022-22963-Spring Cloud Function-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-07-01  
**POC仓库:** [CVE-2022-22963_Reverse-Shell-Exploit](https://github.com/J0ey17/CVE-2022-22963_Reverse-Shell-Exploit)  

---

### [CVE-2022-22963](CVE-2022-22963-Mustafa1986_CVE-2022-22963.md) 🔴 ✅

**名称:** CVE-2022-22963-Spring Cloud Function RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未授权的攻击者执行任意代码，完全控制受影响的服务器。  
**投毒风险:** 10%  
**发现时间:** 2025-07-01  
**POC仓库:** [CVE-2022-22963](https://github.com/Mustafa1986/CVE-2022-22963)  

---

### [CVE-2022-22963](CVE-2022-22963-SourM1lk_CVE-2022-22963-Exploit.md) 🔴 ✅

**名称:** CVE-2022-22963-Spring Cloud Function-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-07-01  
**POC仓库:** [CVE-2022-22963-Exploit](https://github.com/SourM1lk/CVE-2022-22963-Exploit)  

---

### [CVE-2022-22963](CVE-2022-22963-randallbanner_Spring-Cloud-Function-Vulnerability-CVE-2022-22963-RCE.md) 🔴 ✅

**名称:** CVE-2022-22963-Spring Cloud Function-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-07-01  
**POC仓库:** [Spring-Cloud-Function-Vulnerability-CVE-2022-22963-RCE](https://github.com/randallbanner/Spring-Cloud-Function-Vulnerability-CVE-2022-22963-RCE)  

---

### [CVE-2022-22963](CVE-2022-22963-gunzf0x_CVE-2022-22963.md) 🔴 ✅

**名称:** CVE-2022-22963 - Spring Cloud Function SpEL 表达式注入 RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致远程代码执行和敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-07-01  
**POC仓库:** [CVE-2022-22963](https://github.com/gunzf0x/CVE-2022-22963)  

---

### [CVE-2022-22963](CVE-2022-22963-nikn0laty_RCE-in-Spring-Cloud-CVE-2022-22963.md) 🔴 ✅

**名称:** CVE-2022-22963-Spring Cloud Function-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致完全控制受影响的服务器  
**投毒风险:** 5%  
**发现时间:** 2025-07-01  
**POC仓库:** [RCE-in-Spring-Cloud-CVE-2022-22963](https://github.com/nikn0laty/RCE-in-Spring-Cloud-CVE-2022-22963)  

---

### [CVE-2022-22963](CVE-2022-22963-charis3306_CVE-2022-22963.md) 🔴 ✅

**名称:** CVE-2022-22963-Spring Cloud Function SpEL RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的远程攻击者执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-07-01  
**POC仓库:** [CVE-2022-22963](https://github.com/charis3306/CVE-2022-22963)  

---

### [CVE-2022-22963](CVE-2022-22963-BearClaw96_CVE-2022-22963-Poc-Bearcules.md) 🔴 ✅

**名称:** CVE-2022-22963-Spring Cloud Function-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-07-01  
**POC仓库:** [CVE-2022-22963-Poc-Bearcules](https://github.com/BearClaw96/CVE-2022-22963-Poc-Bearcules)  

---

### [CVE-2022-22963](CVE-2022-22963-jrbH4CK_CVE-2022-22963.md) 🔴 ✅

**名称:** CVE-2022-22963-Spring Cloud Function-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和访问本地资源  
**投毒风险:** 10%  
**发现时间:** 2025-07-01  
**POC仓库:** [CVE-2022-22963](https://github.com/jrbH4CK/CVE-2022-22963)  

---

### [CVE-2022-22963](CVE-2022-22963-Shayz614_CVE-2022-22963.md) 🔴 ✅

**名称:** CVE-2022-22963-SpringCloudFunction-RCE  
**类型:** 远程代码执行(RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-07-01  
**POC仓库:** [CVE-2022-22963](https://github.com/Shayz614/CVE-2022-22963)  

---

### [CVE-2025-47812](CVE-2025-47812-0xcan1337_CVE-2025-47812-poC.md) 🔴 ✅

**名称:** CVE-2025-47812 - Wing FTP Server 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可获取root权限  
**投毒风险:** 0%  
**发现时间:** 2025-07-01  
**POC仓库:** [CVE-2025-47812-poC](https://github.com/0xcan1337/CVE-2025-47812-poC)  

---

### [CVE-2024-39930](CVE-2024-39930-theMcSam_CVE-2024-39930-PoC.md) 🔴 ✅

**名称:** CVE-2024-39930-Gogs-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-07-01  
**POC仓库:** [CVE-2024-39930-PoC](https://github.com/theMcSam/CVE-2024-39930-PoC)  

---

### [CVE-2025-49029](CVE-2025-49029-Nxploited_CVE-2025-49029.md) 🔴 ✅

**名称:** CVE-2025-49029-Custom Login And Signup Widget-代码注入  
**类型:** 代码注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-01  
**POC仓库:** [CVE-2025-49029](https://github.com/Nxploited/CVE-2025-49029)  

---

### [CVE-2025-32463](CVE-2025-32463-4f-kira_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地权限提升  
**类型:** 本地权限提升  
**风险:** 高危，本地用户可以获得root权限  
**投毒风险:** 0%  
**发现时间:** 2025-07-01  
**POC仓库:** [CVE-2025-32463](https://github.com/4f-kira/CVE-2025-32463)  

---

### [CVE-2025-32463](CVE-2025-32463-K1tt3h_CVE-2025-32463-POC.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地权限提升  
**类型:** 本地权限提升  
**风险:** 高危，本地用户可获取root权限  
**投毒风险:** 5%  
**发现时间:** 2025-07-01  
**POC仓库:** [CVE-2025-32463-POC](https://github.com/K1tt3h/CVE-2025-32463-POC)  

---

### [CVE-2007-6750](CVE-2007-6750-Jeanpseven_slowl0ris.md) 🔴 ✅

**名称:** CVE-2007-6750 - Apache HTTP Server Slowloris DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致服务中断  
**投毒风险:** 10%  
**发现时间:** 2025-07-01  
**POC仓库:** [slowl0ris](https://github.com/Jeanpseven/slowl0ris)  

---

### [CVE-2007-6750](CVE-2007-6750-RhzVenom_CVE-2007-6750.md) 🔴 ✅

**名称:** CVE-2007-6750 Slowloris DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，导致服务器资源耗尽，无法正常提供服务  
**投毒风险:** 10%  
**发现时间:** 2025-07-01  
**POC仓库:** [CVE-2007-6750](https://github.com/RhzVenom/CVE-2007-6750)  

---

### [CVE-2025-47812](CVE-2025-47812-4m3rr0r_CVE-2025-47812-poc.md) 🔴 ✅

**名称:** CVE-2025-47812 - Wing FTP Server Unauthenticated Remote Code Execution (RCE)  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-07-01  
**POC仓库:** [CVE-2025-47812-poc](https://github.com/4m3rr0r/CVE-2025-47812-poc)  

---

### [CVE-2025-6934](CVE-2025-6934-Nxploited_CVE-2025-6934.md) 🔴 ✅

**名称:** CVE-2025-6934-Opal Estate Pro-权限提升  
**类型:** 权限提升  
**风险:** 高危，允许未认证的攻击者创建管理员账户  
**投毒风险:** 5%  
**发现时间:** 2025-07-01  
**POC仓库:** [CVE-2025-6934](https://github.com/Nxploited/CVE-2025-6934)  

---

### [CVE-2007-4559](CVE-2007-4559-depers-rus_CVE-2007-4559.md) 🔴 ✅

**名称:** CVE-2007-4559-Python tarfile 目录遍历漏洞  
**类型:** 目录遍历  
**风险:** 高危，可能导致任意文件覆盖和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-01  
**POC仓库:** [CVE-2007-4559](https://github.com/depers-rus/CVE-2007-4559)  

---

### [CVE-2007-4559](CVE-2007-4559-advanced-threat-research_Creosote.md) 🔴 ✅

**名称:** CVE-2007-4559-Python tarfile 目录遍历漏洞  
**类型:** 目录遍历  
**风险:** 高危，可能导致任意文件写入  
**投毒风险:** 0%  
**发现时间:** 2025-07-01  
**POC仓库:** [Creosote](https://github.com/advanced-threat-research/Creosote)  

---

### [CVE-2007-4559](CVE-2007-4559-Ooscaar_MALW.md) 🔴 ✅

**名称:** CVE-2007-4559 - Python tarfile 目录遍历漏洞  
**类型:** 目录遍历  
**风险:** 高危，允许远程攻击者覆盖任意文件  
**投毒风险:** 10%  
**发现时间:** 2025-07-01  
**POC仓库:** [MALW](https://github.com/Ooscaar/MALW)  

---

### [CVE-2007-4559](CVE-2007-4559-davidholiday_CVE-2007-4559.md) 🔴 ✅

**名称:** CVE-2007-4559 Python tarfile 目录遍历漏洞  
**类型:** 目录遍历  
**风险:** 高危，可能导致任意文件覆盖  
**投毒风险:** 10%  
**发现时间:** 2025-07-01  
**POC仓库:** [CVE-2007-4559](https://github.com/davidholiday/CVE-2007-4559)  

---

### [CVE-2007-4559](CVE-2007-4559-luigigubello_trellix-tarslip-patch-bypass.md) 🔴 ✅

**名称:** CVE-2007-4559 Python tarfile 目录穿越漏洞  
**类型:** 目录穿越  
**风险:** 高危，允许攻击者覆盖任意文件  
**投毒风险:** 10%  
**发现时间:** 2025-07-01  
**POC仓库:** [trellix-tarslip-patch-bypass](https://github.com/luigigubello/trellix-tarslip-patch-bypass)  

---

### [CVE-2025-32463](CVE-2025-32463-pr0v3rbs_CVE-2025-32463_chwoot.md) 🔴 ✅

**名称:** CVE-2025-32463 - Sudo Chroot 本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可提升为root权限  
**投毒风险:** 1%  
**发现时间:** 2025-07-01  
**POC仓库:** [CVE-2025-32463_chwoot](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot)  

---

### [CVE-2023-5561](CVE-2023-5561-dthkhang_CVE-2023-5561-PoC.md) 🟡 ✅

**名称:** CVE-2023-5561 - WordPress Unauthenticated Post Author Email Disclosure  
**类型:** 敏感信息泄露  
**风险:** 中危，泄露用户邮箱信息  
**投毒风险:** 10%  
**发现时间:** 2025-07-01  
**POC仓库:** [CVE-2023-5561-PoC](https://github.com/dthkhang/CVE-2023-5561-PoC)  

---

### [CVE-2023-32233](CVE-2023-32233-enlist12_CVE-2023-32233.md) 🔴 ✅

**名称:** CVE-2023-32233  
**类型:** Use-After-Free  
**风险:** 高危，本地用户可提升至root权限  
**投毒风险:** 5%  
**发现时间:** 2025-07-01  
**POC仓库:** [CVE-2023-32233](https://github.com/enlist12/CVE-2023-32233)  

---

### [CVE-2025-6218](CVE-2025-6218-skimask1690_CVE-2025-6218-POC.md) 🔴 ✅

**名称:** CVE-2025-6218-WinRAR目录遍历远程代码执行  
**类型:** 目录遍历导致远程代码执行  
**风险:** 高危，可导致任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-01  
**POC仓库:** [CVE-2025-6218-POC](https://github.com/skimask1690/CVE-2025-6218-POC)  

---

### [CVE-2018-6789](CVE-2018-6789-c0llision_exim-vuln-poc.md) 🔴 ✅

**名称:** CVE-2018-6789-Exim-base64d缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-01  
**POC仓库:** [exim-vuln-poc](https://github.com/c0llision/exim-vuln-poc)  

---

### [CVE-2018-6789](CVE-2018-6789-synacktiv_Exim-CVE-2018-6789.md) 🔴 ✅

**名称:** CVE-2018-6789 Exim base64d 缓冲区溢出漏洞  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-01  
**POC仓库:** [Exim-CVE-2018-6789](https://github.com/synacktiv/Exim-CVE-2018-6789)  

---

### [CVE-2018-6789](CVE-2018-6789-beraphin_CVE-2018-6789.md) 🔴 ✅

**名称:** CVE-2018-6789 - Exim base64d 缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-07-01  
**POC仓库:** [CVE-2018-6789](https://github.com/beraphin/CVE-2018-6789)  

---

### [CVE-2018-6789](CVE-2018-6789-thistehneisen_CVE-2018-6789-Python3.md) 🔴 ✅

**名称:** CVE-2018-6789 Exim base64d 缓冲区溢出远程代码执行漏洞  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-07-01  
**POC仓库:** [CVE-2018-6789-Python3](https://github.com/thistehneisen/CVE-2018-6789-Python3)  

---

### [CVE-2018-6789](CVE-2018-6789-martinclauss_exim-rce-cve-2018-6789.md) 🔴 ✅

**名称:** CVE-2018-6789 Exim base64d 缓冲区溢出漏洞  
**类型:** 缓冲区溢出  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-07-01  
**POC仓库:** [exim-rce-cve-2018-6789](https://github.com/martinclauss/exim-rce-cve-2018-6789)  

---


## 🔍 快速查找

- [按CVE编号查找](../../by-cve/)
- [返回2025年总览](../README.md)
- [返回总索引](../../README.md)

---

*本文档由 VulnWatchdog 自动生成 @ 2025-11-26 13:32*
