# 2025年03月漏洞情报汇总

> 📅 统计周期: 2025-03-01 ~ 2025-03-30
> 📊 新增漏洞: **977** 个
> 🔥 高危漏洞: **789** 个

---

## 📊 漏洞类型分布

| 类型 | 数量 | 占比 |
|------|------|------|
| 远程代码执行 | 110 | 11.3% |
| 任意文件读取 | 49 | 5.0% |
| 远程代码执行 (RCE) | 48 | 4.9% |
| 权限提升 | 35 | 3.6% |
| 路径遍历 | 33 | 3.4% |
| 命令注入 | 31 | 3.2% |
| 授权绕过 | 28 | 2.9% |
| 信息泄露 | 27 | 2.8% |
| 目录遍历 | 26 | 2.7% |
| SQL注入 | 23 | 2.4% |

---

## 📋 详细列表

### [CVE-2025-0868](CVE-2025-0868-shreyas-malhotra_PoC_CVE-2025-0868.md) 🔴 ✅

**名称:** CVE-2025-0868-DocsGPT-远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致完全控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [PoC_CVE-2025-0868](https://github.com/shreyas-malhotra/PoC_CVE-2025-0868)  

---

### [CVE-2025-25706](CVE-2025-25706-Cotherm_CVE-2025-25706.md) 🔴 ✅

**名称:** CVE-2025-25706  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致完全系统控制，数据泄露，横向移动，恶意软件部署，以及声誉和财务损失  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2025-25706](https://github.com/Cotherm/CVE-2025-25706)  

---

### [CVE-2025-25705](CVE-2025-25705-Cotherm_CVE-2025-25705.md) 🔴 ✅

**名称:** CVE-2025-25705 - ProApps Enterprise Appliance 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致完全系统接管、数据泄露、横向移动、恶意软件部署以及声誉和财务损失  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2025-25705](https://github.com/Cotherm/CVE-2025-25705)  

---

### [CVE-2022-4174](CVE-2022-4174-moften_CVE-2022-4174_CVE-2022-41742.md) 🔴 ✅

**名称:** CVE-2022-4174 V8 类型混淆漏洞  
**类型:** 类型混淆  
**风险:** 高危，可能导致堆损坏和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2022-4174_CVE-2022-41742](https://github.com/moften/CVE-2022-4174_CVE-2022-41742)  

---

### [CVE-2013-3900](CVE-2013-3900-piranhap_CVE-2013-3900_Remediation_PowerShell.md) 🟡 ✅

**名称:** CVE-2013-3900 WinVerifyTrust Signature Validation Vulnerability  
**类型:** 签名验证绕过  
**风险:** 中危，可能导致恶意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2013-3900_Remediation_PowerShell](https://github.com/piranhap/CVE-2013-3900_Remediation_PowerShell)  

---

### [CVE-2025-24813](CVE-2025-24813-B1gN0Se_Tomcat-CVE-2025-24813.md) 🔴 ✅

**名称:** CVE-2025-24813 - Apache Tomcat RCE  
**类型:** 远程代码执行 (RCE) / 信息泄露 / 文件篡改  
**风险:** 高危，可能导致远程代码执行，信息泄露和文件被恶意修改  
**投毒风险:** 5%  
**发现时间:** 2025-03-31  
**POC仓库:** [Tomcat-CVE-2025-24813](https://github.com/B1gN0Se/Tomcat-CVE-2025-24813)  

---

### [CVE-2023-32784](CVE-2023-32784-le01s_poc-CVE-2023-32784.md) 🔴 ✅

**名称:** CVE-2023-32784-KeePass-明文密码恢复  
**类型:** 敏感信息泄露  
**风险:** 高危，可导致数据库密码泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-31  
**POC仓库:** [poc-CVE-2023-32784](https://github.com/le01s/poc-CVE-2023-32784)  

---

### [CVE-2023-32784](CVE-2023-32784-und3sc0n0c1d0_BruteForce-to-KeePass.md) 🔴 ✅

**名称:** CVE-2023-32784-KeePass主密码恢复  
**类型:** 内存泄漏/密码恢复  
**风险:** 高危，允许攻击者恢复明文主密码  
**投毒风险:** 5%  
**发现时间:** 2025-03-31  
**POC仓库:** [BruteForce-to-KeePass](https://github.com/und3sc0n0c1d0/BruteForce-to-KeePass)  

---

### [CVE-2023-32784](CVE-2023-32784-LeDocteurDesBits_cve-2023-32784.md) 🔴 ✅

**名称:** CVE-2023-32784-KeePass主密码内存泄露  
**类型:** 敏感信息泄露  
**风险:** 高危，允许攻击者在拥有系统访问权限的情况下恢复 KeePass 主密码  
**投毒风险:** 0%  
**发现时间:** 2025-03-31  
**POC仓库:** [cve-2023-32784](https://github.com/LeDocteurDesBits/cve-2023-32784)  

---

### [CVE-2023-32784](CVE-2023-32784-hau-zy_KeePass-dump-py.md) 🔴 ✅

**名称:** CVE-2023-32784-KeePass-主密码泄露  
**类型:** 内存信息泄露  
**风险:** 高危，可能导致数据库密码泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [KeePass-dump-py](https://github.com/hau-zy/KeePass-dump-py)  

---

### [CVE-2023-32784](CVE-2023-32784-vdohney_keepass-password-dumper.md) 🔴 ✅

**名称:** CVE-2023-32784-KeePass-内存泄漏  
**类型:** 内存泄漏  
**风险:** 高危，可能导致主密码泄露  
**投毒风险:** 1%  
**发现时间:** 2025-03-31  
**POC仓库:** [keepass-password-dumper](https://github.com/vdohney/keepass-password-dumper)  

---

### [CVE-2023-32784](CVE-2023-32784-dawnl3ss_CVE-2023-32784.md) 🔴 ✅

**名称:** CVE-2023-32784-KeePass-主密码明文泄露  
**类型:** 信息泄露  
**风险:** 高危，可能导致数据库泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2023-32784](https://github.com/dawnl3ss/CVE-2023-32784)  

---

### [CVE-2023-32784](CVE-2023-32784-z-jxy_keepass_dump.md) 🔴 ✅

**名称:** CVE-2023-32784-KeePass主密码内存泄露  
**类型:** 内存泄露  
**风险:** 高危，攻击者可利用内存dump恢复明文主密码  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [keepass_dump](https://github.com/z-jxy/keepass_dump)  

---

### [CVE-2023-32784](CVE-2023-32784-CTM1_CVE-2023-32784-keepass-linux.md) 🔴 ✅

**名称:** CVE-2023-32784-KeePass-内存泄漏  
**类型:** 内存泄漏  
**风险:** 高危，可能导致主密码泄露  
**投毒风险:** 1%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2023-32784-keepass-linux](https://github.com/CTM1/CVE-2023-32784-keepass-linux)  

---

### [CVE-2023-32784](CVE-2023-32784-mister-turtle_cve-2023-32784.md) 🔴 ✅

**名称:** CVE-2023-32784 - KeePass Master Password Recovery from Memory Dump  
**类型:** 内存信息泄露  
**风险:** 高危，主密码泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-31  
**POC仓库:** [cve-2023-32784](https://github.com/mister-turtle/cve-2023-32784)  

---

### [CVE-2023-32784](CVE-2023-32784-dev0558_CVE-2023-32784-EXPLOIT-REPORT.md) 🔴 ✅

**名称:** CVE-2023-32784-KeePass Master Password Recovery  
**类型:** 内存泄漏  
**风险:** 高危，可能导致凭据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2023-32784-EXPLOIT-REPORT](https://github.com/dev0558/CVE-2023-32784-EXPLOIT-REPORT)  

---

### [CVE-2023-32784](CVE-2023-32784-SarahZimmermann-Schmutzler_exploit_keepass.md) 🔴 ✅

**名称:** CVE-2023-32784 - KeePass 主密码明文泄露  
**类型:** 内存泄露  
**风险:** 高危，可能导致数据库中所有密码泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [exploit_keepass](https://github.com/SarahZimmermann-Schmutzler/exploit_keepass)  

---

### [CVE-2023-32784](CVE-2023-32784-G4sp4rCS_CVE-2023-32784-password-combinator-fixer.md) 🔴 ✅

**名称:** CVE-2023-32784-KeePass主密码泄露  
**类型:** 敏感信息泄露  
**风险:** 高危，攻击者可以获得 KeePass 数据库的访问权限，从而窃取所有存储的密码  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2023-32784-password-combinator-fixer](https://github.com/G4sp4rCS/CVE-2023-32784-password-combinator-fixer)  

---

### [CVE-2025-24799](CVE-2025-24799-realcodeb0ss_CVE-2025-24799-PoC.md) 🔴 ✅

**名称:** CVE-2025-24799-GLPI-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露  
**投毒风险:** 95%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2025-24799-PoC](https://github.com/realcodeb0ss/CVE-2025-24799-PoC)  

---

### [CVE-2023-4357](CVE-2023-4357-passwa11_CVE-2023-4357-APT-Style-exploitation.md) 🟡 ✅

**名称:** CVE-2023-4357-Google Chrome File Access Vulnerability  
**类型:** File Access Restriction Bypass  
**风险:** 中危，可能允许远程攻击者绕过文件访问限制  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2023-4357-APT-Style-exploitation](https://github.com/passwa11/CVE-2023-4357-APT-Style-exploitation)  

---

### [CVE-2023-4357](CVE-2023-4357-sunu11_chrome-CVE-2023-4357.md) 🟡 ✅

**名称:** CVE-2023-4357  
**类型:** 文件访问限制绕过  
**风险:** 中危，允许远程攻击者绕过文件访问限制，可能导致敏感信息泄露。  
**投毒风险:** 0%  
**发现时间:** 2025-03-31  
**POC仓库:** [chrome-CVE-2023-4357](https://github.com/sunu11/chrome-CVE-2023-4357)  

---

### [CVE-2023-4357](CVE-2023-4357-WinnieZy_CVE-2023-4357.md) 🟡 ✅

**名称:** CVE-2023-4357 Google Chrome XML 外部实体注入 (XXE)  
**类型:** XML 外部实体注入 (XXE)  
**风险:** 中危，可能导致文件读取  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2023-4357](https://github.com/WinnieZy/CVE-2023-4357)  

---

### [CVE-2023-4357](CVE-2023-4357-lon5948_CVE-2023-4357-Exploitation.md) 🟡 ✅

**名称:** CVE-2023-4357-Google Chrome XML 注入导致文件访问绕过  
**类型:** XML 注入/文件访问绕过  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2023-4357-Exploitation](https://github.com/lon5948/CVE-2023-4357-Exploitation)  

---

### [CVE-2023-4357](CVE-2023-4357-CamillaFranceschini_CVE-2023-4357.md) 🟡 ✅

**名称:** CVE-2023-4357-Google Chrome XML File Access Restriction Bypass  
**类型:** 文件访问限制绕过  
**风险:** 中危，可能导致本地文件读取  
**投毒风险:** 0%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2023-4357](https://github.com/CamillaFranceschini/CVE-2023-4357)  

---

### [CVE-2023-4357](CVE-2023-4357-xcanwin_CVE-2023-4357-Chrome-XXE.md) 🔴 ✅

**名称:** CVE-2023-4357-Chrome-XXE  
**类型:** XXE  
**风险:** 高危，可能导致本地文件泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2023-4357-Chrome-XXE](https://github.com/xcanwin/CVE-2023-4357-Chrome-XXE)  

---

### [CVE-2025-30208](CVE-2025-30208-jackieya_CVE-2025-30208.md) 🟡 ✅

**名称:** CVE-2025-30208-Vite-任意文件读取  
**类型:** 任意文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2025-30208](https://github.com/jackieya/CVE-2025-30208)  

---

### [CVE-2025-30208](CVE-2025-30208-jackieya_CVE-2025-30208.md) 🟡 ✅

**名称:** CVE-2025-30208-Vite-任意文件读取  
**类型:** 任意文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2025-30208](https://github.com/jackieya/CVE-2025-30208)  

---

### [CVE-2025-2294](CVE-2025-2294-mrrivaldo_CVE-2025-2294.md)  ✅

**名称:** CVE-2025-2294 - Kubio AI Page Builder LFI  
**类型:** 本地文件包含 (LFI)  
**风险:** 严重，未经身份验证的攻击者可以读取服务器上的任意文件，甚至执行PHP代码。  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2025-2294](https://github.com/mrrivaldo/CVE-2025-2294)  

---

### [CVE-2025-2294](CVE-2025-2294-mrrivaldo_CVE-2025-2294.md) 🔴 

**名称:** CVE-2025-2294-Kubio AI Page Builder-Local File Inclusion  
**类型:** Local File Inclusion  
**风险:** 高危，可导致敏感数据泄露或代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2025-2294](https://github.com/mrrivaldo/CVE-2025-2294)  

---

### [CVE-2025-1974](CVE-2025-1974-zulloper_CVE-2025-1974.md) 🔴 ✅

**名称:** CVE-2025-1974-ingress-nginx-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致集群范围内的Secrets泄露和任意代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2025-1974](https://github.com/zulloper/CVE-2025-1974)  

---

### [CVE-2024-25600](CVE-2024-25600-wh6amiGit_CVE-2024-25600.md)  ✅

**名称:** CVE-2024-25600 - WordPress Bricks Builder RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，允许未经身份验证的攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2024-25600](https://github.com/wh6amiGit/CVE-2024-25600)  

---

### [CVE-2019-9053](CVE-2019-9053-byrek_CVE-2019-9053.md) 🔴 ✅

**名称:** CVE-2019-9053-CMS Made Simple-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2019-9053](https://github.com/byrek/CVE-2019-9053)  

---

### [CVE-2024-25600](CVE-2024-25600-hy011121_CVE-2024-25600-wordpress-Exploit-RCE.md) 🔴 ✅

**名称:** CVE-2024-25600 - WordPress Bricks Builder 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2024-25600-wordpress-Exploit-RCE](https://github.com/hy011121/CVE-2024-25600-wordpress-Exploit-RCE)  

---

### [CVE-2024-25600](CVE-2024-25600-WanLiChangChengWanLiChang_CVE-2024-25600.md)  ✅

**名称:** CVE-2024-25600 - WordPress Bricks Builder RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，允许未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2024-25600](https://github.com/WanLiChangChengWanLiChang/CVE-2024-25600)  

---

### [CVE-2024-25600](CVE-2024-25600-KaSooMi0228_CVE-2024-25600-Bricks-Builder-WordPress.md)  ✅

**名称:** CVE-2024-25600 - WordPress Bricks Builder RCE  
**类型:** 远程代码执行  
**风险:** 极高，可能完全控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2024-25600-Bricks-Builder-WordPress](https://github.com/KaSooMi0228/CVE-2024-25600-Bricks-Builder-WordPress)  

---

### [CVE-2024-36991](CVE-2024-36991-gunzf0x_CVE-2024-36991.md) 🔴 ✅

**名称:** CVE-2024-36991 - Splunk Enterprise on Windows 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2024-36991](https://github.com/gunzf0x/CVE-2024-36991)  

---

### [CVE-2024-25600](CVE-2024-25600-Christbowel_CVE-2024-25600_Nuclei-Template.md) 🔴 ✅

**名称:** CVE-2024-25600 - WordPress Bricks Builder RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2024-25600_Nuclei-Template](https://github.com/Christbowel/CVE-2024-25600_Nuclei-Template)  

---

### [CVE-2024-25600](CVE-2024-25600-Tornad0007_CVE-2024-25600-Bricks-Builder-plugin-for-WordPress.md)  ✅

**名称:** CVE-2024-25600 - WordPress Bricks Builder RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2024-25600-Bricks-Builder-plugin-for-WordPress](https://github.com/Tornad0007/CVE-2024-25600-Bricks-Builder-plugin-for-WordPress)  

---

### [CVE-2024-25600](CVE-2024-25600-Chocapikk_CVE-2024-25600.md) 🔴 ✅

**名称:** CVE-2024-25600-Bricks Builder-代码注入  
**类型:** 代码注入  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2024-25600](https://github.com/Chocapikk/CVE-2024-25600)  

---

### [CVE-2024-25600](CVE-2024-25600-K3ysTr0K3R_CVE-2024-25600-EXPLOIT.md) 🔴 ✅

**名称:** CVE-2024-25600-Bricks Builder-代码注入  
**类型:** 代码注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2024-25600-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2024-25600-EXPLOIT)  

---

### [CVE-2024-25600](CVE-2024-25600-X-Projetion_WORDPRESS-CVE-2024-25600-EXPLOIT-RCE.md) 🔴 ✅

**名称:** CVE-2024-25600-Bricks Builder-代码注入  
**类型:** 代码注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-31  
**POC仓库:** [WORDPRESS-CVE-2024-25600-EXPLOIT-RCE](https://github.com/X-Projetion/WORDPRESS-CVE-2024-25600-EXPLOIT-RCE)  

---

### [CVE-2024-25600](CVE-2024-25600-svchostmm_CVE-2024-25600-mass.md) 🔴 ✅

**名称:** CVE-2024-25600-BricksBuilder-代码注入  
**类型:** 代码注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2024-25600-mass](https://github.com/svchostmm/CVE-2024-25600-mass)  

---

### [CVE-2024-25600](CVE-2024-25600-ivanbg2004_0BL1V10N-CVE-2024-25600-Bricks-Builder-plugin-for-WordPress.md) 🔴 ✅

**名称:** CVE-2024-25600-Bricks Builder-代码注入  
**类型:** 代码注入  
**风险:** 高危，未授权远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-03-31  
**POC仓库:** [0BL1V10N-CVE-2024-25600-Bricks-Builder-plugin-for-WordPress](https://github.com/ivanbg2004/0BL1V10N-CVE-2024-25600-Bricks-Builder-plugin-for-WordPress)  

---

### [CVE-2024-25600](CVE-2024-25600-k3lpi3b4nsh33_CVE-2024-25600.md) 🔴 ✅

**名称:** CVE-2024-25600-WordPress Bricks Builder-代码注入  
**类型:** 代码注入  
**风险:** 高危，允许未经身份验证的远程代码执行（RCE）  
**投毒风险:** 0%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2024-25600](https://github.com/k3lpi3b4nsh33/CVE-2024-25600)  

---

### [CVE-2024-25600](CVE-2024-25600-Sibul-Dan-Glokta_test-task-CVE-2024-25600.md)  ✅

**名称:** CVE-2024-25600 - WordPress Bricks Builder 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-31  
**POC仓库:** [test-task-CVE-2024-25600](https://github.com/Sibul-Dan-Glokta/test-task-CVE-2024-25600)  

---

### [CVE-2024-25600](CVE-2024-25600-so1icitx_CVE-2024-25600.md) 🔴 ✅

**名称:** CVE-2024-25600-Bricks Builder-代码注入  
**类型:** 代码注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2024-25600](https://github.com/so1icitx/CVE-2024-25600)  

---

### [CVE-2019-9053](CVE-2019-9053-SUNNYSAINI01001_46635.py_CVE-2019-9053.md) 🔴 ✅

**名称:** CVE-2019-9053-CMS Made Simple-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [46635.py_CVE-2019-9053](https://github.com/SUNNYSAINI01001/46635.py_CVE-2019-9053)  

---

### [CVE-2019-9053](CVE-2019-9053-maraspiras_46635.py.md) 🔴 ✅

**名称:** CVE-2019-9053-CMS Made Simple-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露，管理员账户接管  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [46635.py](https://github.com/maraspiras/46635.py)  

---

### [CVE-2019-9053](CVE-2019-9053-zmiddle_Simple_CMS_SQLi.md) 🔴 ✅

**名称:** CVE-2019-9053-CMS Made Simple-未授权盲注SQL注入  
**类型:** 未授权盲注SQL注入  
**风险:** 高危，可能导致数据泄露和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [Simple_CMS_SQLi](https://github.com/zmiddle/Simple_CMS_SQLi)  

---

### [CVE-2019-9053](CVE-2019-9053-pedrojosenavasperez_CVE-2019-9053-Python3.md) 🔴 ✅

**名称:** CVE-2019-9053-CMS Made Simple-时间盲注SQL注入  
**类型:** 时间盲注SQL注入  
**风险:** 高危，可能导致数据泄露  
**投毒风险:** 1%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2019-9053-Python3](https://github.com/pedrojosenavasperez/CVE-2019-9053-Python3)  

---

### [CVE-2019-9053](CVE-2019-9053-e-renna_CVE-2019-9053.md) 🔴 ✅

**名称:** CVE-2019-9053-CMS Made Simple-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2019-9053](https://github.com/e-renna/CVE-2019-9053)  

---

### [CVE-2019-9053](CVE-2019-9053-ELIZEUOPAIN_CVE-2019-9053-CMS-Made-Simple-2.2.10---SQL-Injection-Exploit.md) 🔴 ✅

**名称:** CVE-2019-9053 - CMS Made Simple News Module 盲注SQL注入  
**类型:** 盲注SQL注入  
**风险:** 高危，可能导致数据泄露和服务器控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2019-9053-CMS-Made-Simple-2.2.10---SQL-Injection-Exploit](https://github.com/ELIZEUOPAIN/CVE-2019-9053-CMS-Made-Simple-2.2.10---SQL-Injection-Exploit)  

---

### [CVE-2019-9053](CVE-2019-9053-im-suman-roy_CVE-2019-9053.md) 🔴 ✅

**名称:** CVE-2019-9053-CMS Made Simple-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和未授权访问  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2019-9053](https://github.com/im-suman-roy/CVE-2019-9053)  

---

### [CVE-2019-9053](CVE-2019-9053-bthnrml_guncel-cve-2019-9053.py.md) 🔴 ✅

**名称:** CVE-2019-9053-CMS Made Simple-SQL注入  
**类型:** 时间盲注SQL注入  
**风险:** 高危，可能导致数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [guncel-cve-2019-9053.py](https://github.com/bthnrml/guncel-cve-2019-9053.py)  

---

### [CVE-2019-9053](CVE-2019-9053-kahluri_CVE-2019-9053.md) 🔴 ✅

**名称:** CVE-2019-9053 - CMS Made Simple SQL注入  
**类型:** 时间盲注SQL注入  
**风险:** 高危，可能导致数据泄露  
**投毒风险:** 1%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2019-9053](https://github.com/kahluri/CVE-2019-9053)  

---

### [CVE-2019-9053](CVE-2019-9053-Doc0x1_CVE-2019-9053-Python3.md) 🔴 ✅

**名称:** CVE-2019-9053-CMS Made Simple-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2019-9053-Python3](https://github.com/Doc0x1/CVE-2019-9053-Python3)  

---

### [CVE-2019-9053](CVE-2019-9053-fernandobortotti_CVE-2019-9053.md) 🔴 ✅

**名称:** CVE-2019-9053-CMS Made Simple-时间盲注SQL注入  
**类型:** 时间盲注SQL注入  
**风险:** 高危，可能导致数据泄露  
**投毒风险:** 1%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2019-9053](https://github.com/fernandobortotti/CVE-2019-9053)  

---

### [CVE-2019-9053](CVE-2019-9053-davcwikla_CVE-2019-9053-exploit.md) 🔴 ✅

**名称:** CVE-2019-9053-CMS Made Simple-时间盲注SQL注入  
**类型:** 时间盲注SQL注入  
**风险:** 高危，可能导致数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2019-9053-exploit](https://github.com/davcwikla/CVE-2019-9053-exploit)  

---

### [CVE-2019-9053](CVE-2019-9053-BjarneVerschorre_CVE-2019-9053.md) 🔴 ✅

**名称:** CVE-2019-9053-CMS Made Simple-SQL注入  
**类型:** Blind Time-Based SQL注入  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2019-9053](https://github.com/BjarneVerschorre/CVE-2019-9053)  

---

### [CVE-2019-9053](CVE-2019-9053-Jason-Siu_CVE-2019-9053-Exploit-in-Python-3.md) 🔴 ✅

**名称:** CVE-2019-9053-CMS Made Simple-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、权限提升和服务器控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2019-9053-Exploit-in-Python-3](https://github.com/Jason-Siu/CVE-2019-9053-Exploit-in-Python-3)  

---

### [CVE-2019-9053](CVE-2019-9053-FedericoTorres233_CVE-2019-9053-Fixed.md) 🔴 ✅

**名称:** CVE-2019-9053 - CMS Made Simple - Time-based Blind SQL Injection  
**类型:** Time-based Blind SQL Injection  
**风险:** 高危，可能导致数据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2019-9053-Fixed](https://github.com/FedericoTorres233/CVE-2019-9053-Fixed)  

---

### [CVE-2019-9053](CVE-2019-9053-Dh4nuJ4_SimpleCTF-UpdatedExploit.md) 🔴 ✅

**名称:** CVE-2019-9053-CMS Made Simple-SQL注入  
**类型:** 时间盲注SQL注入  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [SimpleCTF-UpdatedExploit](https://github.com/Dh4nuJ4/SimpleCTF-UpdatedExploit)  

---

### [CVE-2019-9053](CVE-2019-9053-TeymurNovruzov_CVE-2019-9053-python3-remastered.md) 🔴 ✅

**名称:** CVE-2019-9053-CMS Made Simple-时间盲注SQL注入  
**类型:** 时间盲注SQL注入  
**风险:** 高危，可能导致数据库信息泄露，获取用户凭据等  
**投毒风险:** 5%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2019-9053-python3-remastered](https://github.com/TeymurNovruzov/CVE-2019-9053-python3-remastered)  

---

### [CVE-2019-9053](CVE-2019-9053-jtoalu_CTF-CVE-2019-9053-GTFOBins.md) 🔴 ✅

**名称:** CVE-2019-9053-CMS Made Simple-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CTF-CVE-2019-9053-GTFOBins](https://github.com/jtoalu/CTF-CVE-2019-9053-GTFOBins)  

---

### [CVE-2019-9053](CVE-2019-9053-Azrenom_CMS-Made-Simple-2.2.9-CVE-2019-9053.md) 🔴 ✅

**名称:** CVE-2019-9053 - CMS Made Simple SQL注入  
**类型:** 时间盲注SQL注入  
**风险:** 高危，可能导致数据库信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CMS-Made-Simple-2.2.9-CVE-2019-9053](https://github.com/Azrenom/CMS-Made-Simple-2.2.9-CVE-2019-9053)  

---

### [CVE-2019-9053](CVE-2019-9053-n3rdh4x0r_CVE-2019-9053.md) 🔴 ✅

**名称:** CVE-2019-9053-CMS Made Simple-时间盲注SQL注入  
**类型:** 时间盲注SQL注入  
**风险:** 高危，可能导致数据泄露，权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2019-9053](https://github.com/n3rdh4x0r/CVE-2019-9053)  

---

### [CVE-2019-9053](CVE-2019-9053-louisthedonothing_CVE-2019-9053.md) 🔴 ✅

**名称:** CVE-2019-9053-CMS Made Simple-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、未授权访问和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2019-9053](https://github.com/louisthedonothing/CVE-2019-9053)  

---

### [CVE-2019-9053](CVE-2019-9053-Mahamedm_CVE-2019-9053-Exploit-Python-3.md) 🔴 ✅

**名称:** CVE-2019-9053-CMS Made Simple-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2019-9053-Exploit-Python-3](https://github.com/Mahamedm/CVE-2019-9053-Exploit-Python-3)  

---

### [CVE-2019-9053](CVE-2019-9053-Yzhacker_CVE-2019-9053-CMS46635-python3.md) 🔴 ✅

**名称:** CVE-2019-9053-CMS Made Simple-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据库信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2019-9053-CMS46635-python3](https://github.com/Yzhacker/CVE-2019-9053-CMS46635-python3)  

---

### [CVE-2019-9053](CVE-2019-9053-hf3cyber_CMS-Made-Simple-2.2.9-Unauthenticated-SQL-Injection-Exploit-CVE-2019-9053-.md) 🔴 ✅

**名称:** CVE-2019-9053 - CMS Made Simple 新闻模块 盲注SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-03-31  
**POC仓库:** [CMS-Made-Simple-2.2.9-Unauthenticated-SQL-Injection-Exploit-CVE-2019-9053-](https://github.com/hf3cyber/CMS-Made-Simple-2.2.9-Unauthenticated-SQL-Injection-Exploit-CVE-2019-9053-)  

---

### [CVE-2019-9053](CVE-2019-9053-so1icitx_CVE-2019-9053.md) 🔴 ✅

**名称:** CVE-2019-9053-CMS Made Simple-未授权时间盲注  
**类型:** 未授权时间盲注  
**风险:** 高危，可能导致数据库信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2019-9053](https://github.com/so1icitx/CVE-2019-9053)  

---

### [CVE-2022-26134](CVE-2022-26134-CJ-0107_cve-2022-26134.md) 🔴 ✅

**名称:** CVE-2022-26134-Confluence-OGNL注入远程代码执行  
**类型:** OGNL注入  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [cve-2022-26134](https://github.com/CJ-0107/cve-2022-26134)  

---

### [CVE-2022-26134](CVE-2022-26134-kelemaoya_CVE-2022-26134.md) 🔴 ✅

**名称:** CVE-2022-26134-Confluence-OGNL注入远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2022-26134](https://github.com/kelemaoya/CVE-2022-26134)  

---

### [CVE-2022-26134](CVE-2022-26134-yyqxi_CVE-2022-26134.md) 🔴 ✅

**名称:** CVE-2022-26134 - Atlassian Confluence OGNL 注入远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2022-26134](https://github.com/yyqxi/CVE-2022-26134)  

---

### [CVE-2022-26134](CVE-2022-26134-latings_CVE-2022-26134.md) 🔴 ✅

**名称:** CVE-2022-26134-Atlassian Confluence OGNL 注入远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的攻击者可以执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2022-26134](https://github.com/latings/CVE-2022-26134)  

---

### [CVE-2022-26134](CVE-2022-26134-xanszZZ_ATLASSIAN-Confluence_rce.md) 🔴 ✅

**名称:** CVE-2022-26134-Atlassian Confluence OGNL 注入 RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未授权远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-03-31  
**POC仓库:** [ATLASSIAN-Confluence_rce](https://github.com/xanszZZ/ATLASSIAN-Confluence_rce)  

---

### [CVE-2022-26134](CVE-2022-26134-Chocapikk_CVE-2022-26134.md) 🔴 ✅

**名称:** CVE-2022-26134 - Confluence OGNL注入远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2022-26134](https://github.com/Chocapikk/CVE-2022-26134)  

---

### [CVE-2022-26134](CVE-2022-26134-b4dboy17_CVE-2022-26134.md) 🔴 ✅

**名称:** CVE-2022-26134-Confluence-OGNL注入  
**类型:** OGNL注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2022-26134](https://github.com/b4dboy17/CVE-2022-26134)  

---

### [CVE-2022-26134](CVE-2022-26134-wjlin0_CVE-2022-26134.md) 🔴 ✅

**名称:** CVE-2022-26134 - Atlassian Confluence OGNL 注入  
**类型:** OGNL 注入  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2022-26134](https://github.com/wjlin0/CVE-2022-26134)  

---

### [CVE-2022-26134](CVE-2022-26134-cbk914_CVE-2022-26134_check.md) 🔴 ✅

**名称:** CVE-2022-26134 - Atlassian Confluence OGNL 注入远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的攻击者可以在受影响的Confluence Server或Data Center实例上执行任意代码。  
**投毒风险:** 0%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2022-26134_check](https://github.com/cbk914/CVE-2022-26134_check)  

---

### [CVE-2022-26134](CVE-2022-26134-MaskCyberSecurityTeam_CVE-2022-26134_Behinder_MemShell.md) 🔴 ✅

**名称:** CVE-2022-26134-Confluence-OGNL注入  
**类型:** OGNL注入  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2022-26134_Behinder_MemShell](https://github.com/MaskCyberSecurityTeam/CVE-2022-26134_Behinder_MemShell)  

---

### [CVE-2022-26134](CVE-2022-26134-W01fh4cker_Serein.md) 🔴 ✅

**名称:** CVE-2022-26134-Confluence-OGNL注入  
**类型:** OGNL注入  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [Serein](https://github.com/W01fh4cker/Serein)  

---

### [CVE-2022-26134](CVE-2022-26134-Muhammad-Ali007_Atlassian_CVE-2022-26134.md) 🔴 ✅

**名称:** CVE-2022-26134 - Atlassian Confluence OGNL 注入 RCE  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [Atlassian_CVE-2022-26134](https://github.com/Muhammad-Ali007/Atlassian_CVE-2022-26134)  

---

### [CVE-2022-26134](CVE-2022-26134-acfirthh_CVE-2022-26134.md) 🔴 ✅

**名称:** CVE-2022-26134 - Atlassian Confluence OGNL 注入远程代码执行  
**类型:** OGNL 注入  
**风险:** 高危，允许未经身份验证的攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2022-26134](https://github.com/acfirthh/CVE-2022-26134)  

---

### [CVE-2022-26134](CVE-2022-26134-p4b3l1t0_confusploit.md) 🔴 ✅

**名称:** CVE-2022-26134-Confluence-OGNL注入  
**类型:** OGNL注入  
**风险:** 高危，允许未授权的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [confusploit](https://github.com/p4b3l1t0/confusploit)  

---

### [CVE-2022-26134](CVE-2022-26134-yTxZx_CVE-2022-26134.md) 🔴 ✅

**名称:** CVE-2022-26134-Confluence-OGNL注入  
**类型:** OGNL注入  
**风险:** 高危，允许未经身份验证的攻击者执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2022-26134](https://github.com/yTxZx/CVE-2022-26134)  

---

### [CVE-2022-26134](CVE-2022-26134-DARKSTUFF-LAB_-CVE-2022-26134.md) 🔴 ✅

**名称:** CVE-2022-26134 - Atlassian Confluence OGNL 注入远程代码执行  
**类型:** OGNL 注入  
**风险:** 高危，允许未经身份验证的攻击者执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [-CVE-2022-26134](https://github.com/DARKSTUFF-LAB/-CVE-2022-26134)  

---

### [CVE-2022-26134](CVE-2022-26134-404fu_CVE-2022-26134-POC.md) 🔴 ✅

**名称:** CVE-2022-26134-Confluence-OGNL注入  
**类型:** OGNL注入  
**风险:** 高危，未授权的远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2022-26134-POC](https://github.com/404fu/CVE-2022-26134-POC)  

---

### [CVE-2022-26134](CVE-2022-26134-xsxtw_CVE-2022-26134.md) 🔴 ✅

**名称:** CVE-2022-26134-Confluence-OGNL注入  
**类型:** OGNL注入  
**风险:** 高危，允许未授权远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2022-26134](https://github.com/xsxtw/CVE-2022-26134)  

---

### [CVE-2022-26134](CVE-2022-26134-cc3305_CVE-2022-26134.md) 🔴 ✅

**名称:** CVE-2022-26134 - Atlassian Confluence OGNL 注入远程代码执行  
**类型:** OGNL 注入  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2022-26134](https://github.com/cc3305/CVE-2022-26134)  

---

### [CVE-2022-26134](CVE-2022-26134-nxtexploit_CVE-2022-26134.md) 🔴 ✅

**名称:** CVE-2022-26134-Atlassian Confluence-OGNL注入  
**类型:** OGNL注入  
**风险:** 高危，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2022-26134](https://github.com/nxtexploit/CVE-2022-26134)  

---

### [CVE-2022-26134](CVE-2022-26134-Agentgilspy_CVE-2022-26134.md) 🔴 ✅

**名称:** CVE-2022-26134-Confluence-OGNL注入  
**类型:** OGNL注入  
**风险:** 高危，允许未授权的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2022-26134](https://github.com/Agentgilspy/CVE-2022-26134)  

---

### [CVE-2022-26134](CVE-2022-26134-XiaomingX_cve-2022-26134-poc.md) 🔴 ✅

**名称:** CVE-2022-26134-Confluence-OGNL注入  
**类型:** OGNL注入  
**风险:** 高危，允许未经验证的攻击者执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-03-31  
**POC仓库:** [cve-2022-26134-poc](https://github.com/XiaomingX/cve-2022-26134-poc)  

---

### [CVE-2022-26134](CVE-2022-26134-redhuntlabs_ConfluentPwn.md) 🔴 ✅

**名称:** CVE-2022-26134 - Atlassian Confluence OGNL 注入 RCE  
**类型:** OGNL 注入  
**风险:** 高危，允许未经身份验证的攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [ConfluentPwn](https://github.com/redhuntlabs/ConfluentPwn)  

---

### [CVE-2022-26134](CVE-2022-26134-Khalidhaimur_CVE-2022-26134.md) 🔴 ✅

**名称:** CVE-2022-26134-Atlassian Confluence-OGNL注入RCE  
**类型:** OGNL注入导致远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2022-26134](https://github.com/Khalidhaimur/CVE-2022-26134)  

---

### [CVE-2022-26134](CVE-2022-26134-mr-won_cve-2022-26134.md) 🔴 ✅

**名称:** CVE-2022-26134 Atlassian Confluence OGNL 注入  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [cve-2022-26134](https://github.com/mr-won/cve-2022-26134)  

---

### [CVE-2018-0239](CVE-2018-0239-mr-won_CVE-2018-0239.md) 🔴 

**名称:** CVE-2018-0239 - Cisco StarOS Interface Forwarding Denial of Service  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，导致接口停止转发数据包，可能需要手动重启设备  
**投毒风险:** 95%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2018-0239](https://github.com/mr-won/CVE-2018-0239)  

---

### [CVE-2023-34960](CVE-2023-34960-Aituglo_CVE-2023-34960.md) 🔴 ✅

**名称:** CVE-2023-34960-Chamilo-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2023-34960](https://github.com/Aituglo/CVE-2023-34960)  

---

### [CVE-2023-34960](CVE-2023-34960-YongYe-Security_CVE-2023-34960.md) 🔴 ✅

**名称:** CVE-2023-34960-Chamilo-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2023-34960](https://github.com/YongYe-Security/CVE-2023-34960)  

---

### [CVE-2023-34960](CVE-2023-34960-ThatNotEasy_CVE-2023-34960.md) 🔴 ✅

**名称:** CVE-2023-34960-Chamilo-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2023-34960](https://github.com/ThatNotEasy/CVE-2023-34960)  

---

### [CVE-2023-34960](CVE-2023-34960-Mantodkaz_CVE-2023-34960.md) 🔴 ✅

**名称:** CVE-2023-34960-Chamilo-命令注入  
**类型:** 命令注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CVE-2023-34960](https://github.com/Mantodkaz/CVE-2023-34960)  

---

### [CVE-2023-34960](CVE-2023-34960-dvtarsoul_ChExp.md) 🔴 ✅

**名称:** CVE-2023-34960-Chamilo-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-31  
**POC仓库:** [ChExp](https://github.com/dvtarsoul/ChExp)  

---

### [CVE-2023-34960](CVE-2023-34960-Jenderal92_CHAMILO-CVE-2023-34960.md) 🔴 ✅

**名称:** CVE-2023-34960-Chamilo-命令注入  
**类型:** 命令注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [CHAMILO-CVE-2023-34960](https://github.com/Jenderal92/CHAMILO-CVE-2023-34960)  

---

### [CVE-2023-34960](CVE-2023-34960-mr-won_cve-2023-34960.md) 🔴 ✅

**名称:** CVE-2023-34960-Chamilo-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-31  
**POC仓库:** [cve-2023-34960](https://github.com/mr-won/cve-2023-34960)  

---

### [CVE-2024-36991](CVE-2024-36991-TcchSquad_CVE-2024-36991-Tool.md) 🔴 ✅

**名称:** CVE-2024-36991 Splunk Enterprise on Windows Path Traversal  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-30  
**POC仓库:** [CVE-2024-36991-Tool](https://github.com/TcchSquad/CVE-2024-36991-Tool)  

---

### [CVE-2025-0011](CVE-2025-0011-binarywarm_kentico-xperience13-AuthBypass-CVE-2025-0011.md) 🔴 ✅

**名称:** CVE-2025-0011 (未分配) Kentico Xperience 13 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权访问、数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-30  
**POC仓库:** [kentico-xperience13-AuthBypass-CVE-2025-0011](https://github.com/binarywarm/kentico-xperience13-AuthBypass-CVE-2025-0011)  

---

### [CVE-2024-50379](CVE-2024-50379-thunww_CVE-2024-50379.md) 🔴 ✅

**名称:** CVE-2024-50379-Apache Tomcat-TOCTOU RCE  
**类型:** TOCTOU竞态条件导致的远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-30  
**POC仓库:** [CVE-2024-50379](https://github.com/thunww/CVE-2024-50379)  

---

### [CVE-2025-27840](CVE-2025-27840-em0gi_CVE-2025-27840.md) 🟡 ✅

**名称:** CVE-2025-27840 - Espressif ESP32 芯片隐藏 HCI 命令  
**类型:** 隐藏功能/权限提升/代码执行  
**风险:** 中危，在特定条件下可能导致内存写入和潜在的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-03-30  
**POC仓库:** [CVE-2025-27840](https://github.com/em0gi/CVE-2025-27840)  

---

### [CVE-2025-27840](CVE-2025-27840-demining_Bluetooth-Attacks-CVE-2025-27840.md) 🟡 ✅

**名称:** CVE-2025-27840-Espressif ESP32-隐藏HCI命令  
**类型:** 权限提升/内存写入  
**风险:** 中危，可能导致设备控制，信息泄露  
**投毒风险:** 85%  
**发现时间:** 2025-03-30  
**POC仓库:** [Bluetooth-Attacks-CVE-2025-27840](https://github.com/demining/Bluetooth-Attacks-CVE-2025-27840)  

---

### [CVE-2024-36991](CVE-2024-36991-Mr-xn_CVE-2024-36991.md) 🔴 ✅

**名称:** CVE-2024-36991-Splunk Enterprise on Windows-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感文件泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-30  
**POC仓库:** [CVE-2024-36991](https://github.com/Mr-xn/CVE-2024-36991)  

---

### [CVE-2024-36991](CVE-2024-36991-th3gokul_CVE-2024-36991.md) 🔴 ✅

**名称:** CVE-2024-36991 Splunk Enterprise on Windows 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感文件读取  
**投毒风险:** 10%  
**发现时间:** 2025-03-30  
**POC仓库:** [CVE-2024-36991](https://github.com/th3gokul/CVE-2024-36991)  

---

### [CVE-2024-36991](CVE-2024-36991-sardine-web_CVE-2024-36991.md) 🔴 ✅

**名称:** CVE-2024-36991-Splunk Enterprise-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感文件泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-30  
**POC仓库:** [CVE-2024-36991](https://github.com/sardine-web/CVE-2024-36991)  

---

### [CVE-2024-36991](CVE-2024-36991-Cappricio-Securities_CVE-2024-36991.md) 🔴 ✅

**名称:** CVE-2024-36991 Splunk Enterprise on Windows Path Traversal  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感文件泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-30  
**POC仓库:** [CVE-2024-36991](https://github.com/Cappricio-Securities/CVE-2024-36991)  

---

### [CVE-2024-36991](CVE-2024-36991-bigb0x_CVE-2024-36991.md) 🔴 ✅

**名称:** CVE-2024-36991-Splunk Enterprise on Windows-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致任意文件读取  
**投毒风险:** 10%  
**发现时间:** 2025-03-30  
**POC仓库:** [CVE-2024-36991](https://github.com/bigb0x/CVE-2024-36991)  

---

### [CVE-2024-36991](CVE-2024-36991-jaytiwari05_CVE-2024-36991.md) 🔴 ✅

**名称:** CVE-2024-36991 - Splunk Enterprise on Windows Path Traversal  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-30  
**POC仓库:** [CVE-2024-36991](https://github.com/jaytiwari05/CVE-2024-36991)  

---

### [CVE-2025-0087](CVE-2025-0087-SpiralBL0CK_CVE-2025-0087-.md) 🔴 ✅

**名称:** CVE-2025-0087 Android 本地权限提升  
**类型:** 本地权限提升 (Local Privilege Escalation)  
**风险:** 高危，允许攻击者获得root权限或执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-03-30  
**POC仓库:** [CVE-2025-0087-](https://github.com/SpiralBL0CK/CVE-2025-0087-)  

---

### [CVE-2025-0087](CVE-2025-0087-SpiralBL0CK_CVE-2025-0087.md) 🟡 ✅

**名称:** CVE-2025-0087  
**类型:** 拒绝服务 (DoS)  
**风险:** 中危，可能导致应用崩溃或无法正常使用  
**投毒风险:** 0%  
**发现时间:** 2025-03-30  
**POC仓库:** [CVE-2025-0087](https://github.com/SpiralBL0CK/CVE-2025-0087)  

---

### [CVE-2023-45878](CVE-2023-45878-davidzzo23_CVE-2023-45878.md) 🔴 ✅

**名称:** CVE-2023-45878-GibbonEdu-任意文件写入  
**类型:** 任意文件写入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-30  
**POC仓库:** [CVE-2023-45878](https://github.com/davidzzo23/CVE-2023-45878)  

---

### [CVE-2025-29927](CVE-2025-29927-Kamal-418_CVE-2025-29927-NextJs-Lab.md) 🔴 ✅

**名称:** CVE-2025-29927-next.js-权限绕过  
**类型:** 权限绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-30  
**POC仓库:** [CVE-2025-29927-NextJs-Lab](https://github.com/Kamal-418/CVE-2025-29927-NextJs-Lab)  

---

### [CVE-2023-45878](CVE-2023-45878-0xyy66_CVE-2023-45878_to_RCE.md) 🔴 ✅

**名称:** CVE-2023-45878-GibbonEdu-任意文件写入导致RCE  
**类型:** 任意文件写入  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-30  
**POC仓库:** [CVE-2023-45878_to_RCE](https://github.com/0xyy66/CVE-2023-45878_to_RCE)  

---

### [CVE-2025-24813](CVE-2025-24813-manjula-aw_CVE-2025-24813.md) 🔴 ✅

**名称:** CVE-2025-24813-Apache Tomcat-RCE/信息泄露/文件篡改  
**类型:** 远程代码执行/信息泄露/文件篡改  
**风险:** 高危，可能导致远程代码执行、敏感信息泄露和文件篡改  
**投毒风险:** 0%  
**发现时间:** 2025-03-30  
**POC仓库:** [CVE-2025-24813](https://github.com/manjula-aw/CVE-2025-24813)  

---

### [CVE-2025-30208](CVE-2025-30208-Ahmed-mostafa03_CVE-2025-30208-EXP.md) 🟡 ✅

**名称:** CVE-2025-30208-Vite-任意文件读取  
**类型:** 任意文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-30  
**POC仓库:** [CVE-2025-30208-EXP](https://github.com/Ahmed-mostafa03/CVE-2025-30208-EXP)  

---

### [CVE-2012-4869](CVE-2012-4869-bitc0de_Elastix-Remote-Code-Execution.md) 🔴 ✅

**名称:** CVE-2012-4869-FreePBX-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-03-30  
**POC仓库:** [Elastix-Remote-Code-Execution](https://github.com/bitc0de/Elastix-Remote-Code-Execution)  

---

### [CVE-2012-4869](CVE-2012-4869-cyberdesu_Elastix-2.2.0-CVE-2012-4869.md) 🔴 ✅

**名称:** CVE-2012-4869-FreePBX-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可完全控制服务器  
**投毒风险:** 5%  
**发现时间:** 2025-03-30  
**POC仓库:** [Elastix-2.2.0-CVE-2012-4869](https://github.com/cyberdesu/Elastix-2.2.0-CVE-2012-4869)  

---

### [CVE-2020-11651](CVE-2020-11651-dozernz_cve-2020-11651.md) 🔴 ✅

**名称:** CVE-2020-11651 SaltStack 身份验证绕过漏洞  
**类型:** 身份验证绕过  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-03-30  
**POC仓库:** [cve-2020-11651](https://github.com/dozernz/cve-2020-11651)  

---

### [CVE-2020-11651](CVE-2020-11651-bravery9_SaltStack-Exp.md) 🔴 ✅

**名称:** CVE-2020-11651 SaltStack 认证绕过与远程代码执行  
**类型:** 认证绕过/远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-30  
**POC仓库:** [SaltStack-Exp](https://github.com/bravery9/SaltStack-Exp)  

---

### [CVE-2020-11651](CVE-2020-11651-RakhithJK_CVE-2020-11651.md) 🔴 ✅

**名称:** CVE-2020-11651-SaltStack-认证绕过和远程代码执行  
**类型:** 认证绕过/远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-30  
**POC仓库:** [CVE-2020-11651](https://github.com/RakhithJK/CVE-2020-11651)  

---

### [CVE-2020-11651](CVE-2020-11651-kevthehermit_CVE-2020-11651.md) 🔴 ✅

**名称:** CVE-2020-11651-SaltStack认证绕过与远程代码执行  
**类型:** 认证绕过/远程代码执行  
**风险:** 高危，可完全控制Salt Master及Minions  
**投毒风险:** 5%  
**发现时间:** 2025-03-30  
**POC仓库:** [CVE-2020-11651](https://github.com/kevthehermit/CVE-2020-11651)  

---

### [CVE-2020-11651](CVE-2020-11651-lovelyjuice_cve-2020-11651-exp-plus.md) 🔴 ✅

**名称:** CVE-2020-11651/CVE-2020-11652 SaltStack 身份验证绕过和任意文件读取/写入漏洞  
**类型:** 身份验证绕过/任意文件读取/写入  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-30  
**POC仓库:** [cve-2020-11651-exp-plus](https://github.com/lovelyjuice/cve-2020-11651-exp-plus)  

---

### [CVE-2020-11651](CVE-2020-11651-rossengeorgiev_salt-security-backports.md) 🔴 ✅

**名称:** CVE-2020-11651 SaltStack 认证绕过和远程代码执行  
**类型:** 认证绕过/远程代码执行  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-30  
**POC仓库:** [salt-security-backports](https://github.com/rossengeorgiev/salt-security-backports)  

---

### [CVE-2020-11651](CVE-2020-11651-jasperla_CVE-2020-11651-poc.md) 🔴 ✅

**名称:** CVE-2020-11651 - SaltStack 认证绕过漏洞  
**类型:** 认证绕过  
**风险:** 高危，可导致远程代码执行和敏感信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-03-30  
**POC仓库:** [CVE-2020-11651-poc](https://github.com/jasperla/CVE-2020-11651-poc)  

---

### [CVE-2020-11651](CVE-2020-11651-appcheck-ng_salt-rce-scanner-CVE-2020-11651-CVE-2020-11652.md)  ✅

**名称:** CVE-2020-11651 SaltStack 认证绕过及远程代码执行  
**类型:** 认证绕过/远程代码执行  
**风险:** 极高，可导致完全控制 Salt Master 和 Minion  
**投毒风险:** 10%  
**发现时间:** 2025-03-30  
**POC仓库:** [salt-rce-scanner-CVE-2020-11651-CVE-2020-11652](https://github.com/appcheck-ng/salt-rce-scanner-CVE-2020-11651-CVE-2020-11652)  

---

### [CVE-2020-11651](CVE-2020-11651-0xc0d_CVE-2020-11651.md) 🔴 ✅

**名称:** CVE-2020-11651-SaltStack-Authentication Bypass and Remote Code Execution  
**类型:** Authentication Bypass and Remote Code Execution  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-30  
**POC仓库:** [CVE-2020-11651](https://github.com/0xc0d/CVE-2020-11651)  

---

### [CVE-2020-11651](CVE-2020-11651-chef-cft_salt-vulnerabilities.md) 🔴 ✅

**名称:** CVE-2020-11651-SaltStack-认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-03-30  
**POC仓库:** [salt-vulnerabilities](https://github.com/chef-cft/salt-vulnerabilities)  

---

### [CVE-2020-11651](CVE-2020-11651-ssrsec_CVE-2020-11651-CVE-2020-11652-EXP.md) 🔴 ✅

**名称:** CVE-2020-11651-SaltStack认证绕过与远程代码执行  
**类型:** 认证绕过/远程代码执行  
**风险:** 高危，可导致完全控制Salt Master和Minion  
**投毒风险:** 10%  
**发现时间:** 2025-03-30  
**POC仓库:** [CVE-2020-11651-CVE-2020-11652-EXP](https://github.com/ssrsec/CVE-2020-11651-CVE-2020-11652-EXP)  

---

### [CVE-2020-11651](CVE-2020-11651-hardsoftsecurity_CVE-2020-11651-PoC.md) 🔴 ✅

**名称:** CVE-2020-11651-SaltStack-身份验证绕过和远程代码执行  
**类型:** 身份验证绕过/远程代码执行  
**风险:** 高危，可能导致数据泄露和远程代码执行，完全控制受影响的Salt Master和Minion  
**投毒风险:** 10%  
**发现时间:** 2025-03-30  
**POC仓库:** [CVE-2020-11651-PoC](https://github.com/hardsoftsecurity/CVE-2020-11651-PoC)  

---

### [CVE-2020-11651](CVE-2020-11651-Drew-Alleman_CVE-2020-11651.md) 🔴 ✅

**名称:** CVE-2020-11651 SaltStack 认证绕过/远程代码执行  
**类型:** 认证绕过/远程代码执行  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-30  
**POC仓库:** [CVE-2020-11651](https://github.com/Drew-Alleman/CVE-2020-11651)  

---

### [CVE-2025-29927](CVE-2025-29927-ayato-shitomi_WebLab_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-Authorization Bypass  
**类型:** Authorization Bypass  
**风险:** 高危，可能导致未授权访问、数据泄露和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-03-30  
**POC仓库:** [WebLab_CVE-2025-29927](https://github.com/ayato-shitomi/WebLab_CVE-2025-29927)  

---

### [CVE-2022-39299](CVE-2022-39299-doyensec_CVE-2022-39299_PoC_Generator.md) 🔴 ✅

**名称:** CVE-2022-39299 - Passport-SAML 签名绕过  
**类型:** 签名绕过  
**风险:** 高危，可能导致身份验证绕过和未授权访问  
**投毒风险:** 10%  
**发现时间:** 2025-03-30  
**POC仓库:** [CVE-2022-39299_PoC_Generator](https://github.com/doyensec/CVE-2022-39299_PoC_Generator)  

---

### [CVE-2022-39299](CVE-2022-39299-KaztoRay_CVE-2022-39299-Research.md) 🔴 ✅

**名称:** CVE-2022-39299 - passport-saml 签名绕过  
**类型:** 签名绕过  
**风险:** 高危，可能导致身份验证绕过  
**投毒风险:** 10%  
**发现时间:** 2025-03-30  
**POC仓库:** [CVE-2022-39299-Research](https://github.com/KaztoRay/CVE-2022-39299-Research)  

---

### [CVE-2025-32920](CVE-2025-32920-itssixtyn3in_CVE-2025-3292029.md) 🔴 ✅

**名称:** CVE-2025-3292029-SecureVPN-账户接管  
**类型:** 账户接管  
**风险:** 高危，可能导致敏感数据泄露和用户隐私泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-30  
**POC仓库:** [CVE-2025-3292029](https://github.com/itssixtyn3in/CVE-2025-3292029)  

---

### [CVE-2025-32920](CVE-2025-32920-itssixtyn3in_CVE-2025-3292027.md)  ✅

**名称:** CVE-2025-3292027 - SecureVPN Account Takeover  
**类型:** 账户接管  
**风险:** 严重，可能导致敏感数据泄露，账户完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-30  
**POC仓库:** [CVE-2025-3292027](https://github.com/itssixtyn3in/CVE-2025-3292027)  

---

### [CVE-2025-32920](CVE-2025-32920-itssixtyn3in_CVE-2025-3292028.md) 🔴 ✅

**名称:** CVE-2025-3292028 SecureVPN Account Takeover  
**类型:** Account Takeover  
**风险:** 高危，可能导致敏感数据泄露和用户隐私泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-30  
**POC仓库:** [CVE-2025-3292028](https://github.com/itssixtyn3in/CVE-2025-3292028)  

---

### [CVE-2025-26125](CVE-2025-26125-ZeroMemoryEx_CVE-2025-26125.md) 🔴 ✅

**名称:** CVE-2025-26125 - IObit Malware Fighter IMFForceDelete 驱动程序权限提升  
**类型:** 权限提升  
**风险:** 高危，可导致系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-30  
**POC仓库:** [CVE-2025-26125](https://github.com/ZeroMemoryEx/CVE-2025-26125)  

---

### [CVE-2024-3721](CVE-2024-3721-vmhalt_CVE-2024-3721.md) 🔴 ✅

**名称:** CVE-2024-3721-TBK DVR-4104/DVR-4216-OS命令注入  
**类型:** OS命令注入  
**风险:** 高危，可能导致设备完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2024-3721](https://github.com/vmhalt/CVE-2024-3721)  

---

### [CVE-2025-32920](CVE-2025-32920-itssixtyn3in_CVE-2025-3292026.md) 🔴 ✅

**名称:** CVE-2025-3292026 SecureVPN Account Takeover  
**类型:** Account Takeover  
**风险:** Critical，未经授权访问用户帐户，可能导致敏感数据暴露和用户隐私泄露。  
**投毒风险:** 5%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2025-3292026](https://github.com/itssixtyn3in/CVE-2025-3292026)  

---

### [CVE-2024-30485](CVE-2024-30485-Nxploited_CVE-2024-30485.md) 🔴 ✅

**名称:** CVE-2024-30485 - WordPress Finale Lite 插件未授权插件安装/激活漏洞  
**类型:** 未授权访问/插件安装/插件激活  
**风险:** 高危，可能导致网站被控制  
**投毒风险:** 5%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2024-30485](https://github.com/Nxploited/CVE-2024-30485)  

---

### [CVE-2025-1307](CVE-2025-1307-Nxploited_CVE-2025-1307.md) 🔴 ✅

**名称:** CVE-2025-1307-Newscrunch-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 20%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2025-1307](https://github.com/Nxploited/CVE-2025-1307)  

---

### [CVE-2024-9756](CVE-2024-9756-Nxploited_CVE-2024-9756.md) 🟡 ✅

**名称:** CVE-2024-9756 - Order Attachments for WooCommerce 未授权文件上传  
**类型:** 未授权文件上传  
**风险:** 中危，可能允许攻击者上传恶意文件，导致远程代码执行或信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2024-9756](https://github.com/Nxploited/CVE-2024-9756)  

---

### [CVE-2025-1306](CVE-2025-1306-Nxploited_CVE-2025-1306.md) 🔴 ✅

**名称:** CVE-2025-1306-Newscrunch-CSRF to Arbitrary File Upload  
**类型:** CSRF to Arbitrary File Upload  
**风险:** 高危，可能导致远程代码执行和完全系统控制  
**投毒风险:** 5%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2025-1306](https://github.com/Nxploited/CVE-2025-1306)  

---

### [CVE-2024-25092](CVE-2024-25092-RandomRobbieBF_CVE-2024-25092.md) 🔴 ✅

**名称:** CVE-2024-25092 - NextMove Lite Plugin Arbitrary Plugin Installation/Activation  
**类型:** Missing Authorization  
**风险:** 高危，可能导致网站被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2024-25092](https://github.com/RandomRobbieBF/CVE-2024-25092)  

---

### [CVE-2024-6132](CVE-2024-6132-Nxploited_CVE-2024-6132.md) 🔴 ✅

**名称:** CVE-2024-6132-Pexels Free Stock Photos-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2024-6132](https://github.com/Nxploited/CVE-2024-6132)  

---

### [CVE-2024-10629](CVE-2024-10629-RandomRobbieBF_CVE-2024-10629.md) 🔴 ✅

**名称:** CVE-2024-10629-GPX Viewer-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2024-10629](https://github.com/RandomRobbieBF/CVE-2024-10629)  

---

### [CVE-2024-10629](CVE-2024-10629-Nxploited_CVE-2024-10629.md) 🔴 ✅

**名称:** CVE-2024-10629 - GPX Viewer <= 2.2.8 - 任意文件创建  
**类型:** 任意文件创建  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2024-10629](https://github.com/Nxploited/CVE-2024-10629)  

---

### [CVE-2024-10673](CVE-2024-10673-Nxploited_CVE-2024-10673.md) 🔴 ✅

**名称:** CVE-2024-10673-Top_Store-任意插件安装/激活  
**类型:** 任意插件安装/激活  
**风险:** 高危，可能导致远程代码执行和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2024-10673](https://github.com/Nxploited/CVE-2024-10673)  

---

### [CVE-2025-2266](CVE-2025-2266-Nxploited_CVE-2025-2266.md) 🔴 ✅

**名称:** CVE-2025-2266 Checkout Mestres do WP for WooCommerce Unauthenticated Arbitrary Options Update  
**类型:** 权限提升/配置修改  
**风险:** 高危，可能导致未授权访问和权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2025-2266](https://github.com/Nxploited/CVE-2025-2266)  

---

### [CVE-2025-2857](CVE-2025-2857-ubisoftinc_CVE-2025-2857.md) 🔴 ✅

**名称:** CVE-2025-2857-Firefox-Sandbox Escape  
**类型:** Sandbox Escape  
**风险:** 高危，可以完全控制受害者系统  
**投毒风险:** 80%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2025-2857](https://github.com/ubisoftinc/CVE-2025-2857)  

---

### [CVE-2025-24071](CVE-2025-24071-cesarbtakeda_Windows-Explorer-CVE-2025-24071.md) 🟡 ✅

**名称:** CVE-2025-24071 - Windows File Explorer Spoofing Vulnerability  
**类型:** 信息泄露/NTLM Hash 泄露  
**风险:** 中危，可能导致凭据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-29  
**POC仓库:** [Windows-Explorer-CVE-2025-24071](https://github.com/cesarbtakeda/Windows-Explorer-CVE-2025-24071)  

---

### [CVE-2025-32920](CVE-2025-32920-itssixtyn3in_CVE-2025-3292025.md) 🔴 

**名称:** CVE-2025-3292025-SecureVPN-Account Takeover  
**类型:** Account Takeover  
**风险:** Critical, allows unauthorized access to user accounts, exposing sensitive data and compromising user privacy.  
**投毒风险:** 10%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2025-3292025](https://github.com/itssixtyn3in/CVE-2025-3292025)  

---

### [CVE-2023-0748](CVE-2023-0748-gonzxph_CVE-2023-0748.md) 🟡 ✅

**名称:** CVE-2023-0748 - BTCPayServer Open Redirect  
**类型:** 开放重定向  
**风险:** 中危  
**投毒风险:** 0%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-0748](https://github.com/gonzxph/CVE-2023-0748)  

---

### [CVE-2025-2563](CVE-2025-2563-ubaydev_CVE-2025-2563.md) 🔴 ✅

**名称:** CVE-2025-2563 - User Registration & Membership 插件未授权权限提升  
**类型:** 权限提升  
**风险:** 高危，可导致完全控制受影响的WordPress站点  
**投毒风险:** 5%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2025-2563](https://github.com/ubaydev/CVE-2025-2563)  

---

### [CVE-2025-1316](CVE-2025-1316-slockit_CVE-2025-1316.md) 🔴 ✅

**名称:** CVE-2025-1316 Edimax IC-7100 IP Camera OS Command Injection  
**类型:** OS Command Injection  
**风险:** Critical，可能导致远程代码执行，设备完全控制，并被Mirai等僵尸网络利用  
**投毒风险:** 10%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2025-1316](https://github.com/slockit/CVE-2025-1316)  

---

### [CVE-2024-25180](CVE-2024-25180-dustblessnotdust_CVE-2024-25180.md) 🔴 ✅

**名称:** CVE-2024-25180-pdfmake-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2024-25180](https://github.com/dustblessnotdust/CVE-2024-25180)  

---

### [CVE-2023-23752](CVE-2023-23752-ThatNotEasy_CVE-2023-23752.md) 🟡 ✅

**名称:** CVE-2023-23752-Joomla-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 中危，可能导致信息泄露，在特定情况下可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-23752](https://github.com/ThatNotEasy/CVE-2023-23752)  

---

### [CVE-2023-23752](CVE-2023-23752-MrP4nda1337_CVE-2023-23752.md) 🟡 ✅

**名称:** CVE-2023-23752 - Joomla! Improper Access Control  
**类型:** 权限绕过/信息泄露  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-23752](https://github.com/MrP4nda1337/CVE-2023-23752)  

---

### [CVE-2023-23752](CVE-2023-23752-yTxZx_CVE-2023-23752.md) 🟡 ✅

**名称:** CVE-2023-23752 - Joomla! Improper Access Control  
**类型:** 信息泄露/未授权访问  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-23752](https://github.com/yTxZx/CVE-2023-23752)  

---

### [CVE-2023-23752](CVE-2023-23752-Pushkarup_CVE-2023-23752.md) 🟡 ✅

**名称:** CVE-2023-23752 - Joomla! 身份验证绕过漏洞  
**类型:** 身份验证绕过/信息泄露  
**风险:** 中危，可导致敏感信息泄露，可能进一步导致代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-23752](https://github.com/Pushkarup/CVE-2023-23752)  

---

### [CVE-2023-23752](CVE-2023-23752-blacks1ph0n_CVE-2023-23752.md) 🟡 ✅

**名称:** CVE-2023-23752 - Joomla Unauthorized Access Vulnerability  
**类型:** 未授权访问/信息泄露  
**风险:** 中危，可能泄露敏感配置信息  
**投毒风险:** 0%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-23752](https://github.com/blacks1ph0n/CVE-2023-23752)  

---

### [CVE-2023-23752](CVE-2023-23752-Youns92_Joomla-v4.2.8---CVE-2023-23752.md) 🟡 ✅

**名称:** CVE-2023-23752-Joomla-未授权访问 webservice 接口  
**类型:** 未授权访问  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-29  
**POC仓库:** [Joomla-v4.2.8---CVE-2023-23752](https://github.com/Youns92/Joomla-v4.2.8---CVE-2023-23752)  

---

### [CVE-2023-23752](CVE-2023-23752-Ly0kha_Joomla-CVE-2023-23752-Exploit-Script.md) 🟡 ✅

**名称:** CVE-2023-23752-Joomla-权限绕过  
**类型:** 权限绕过  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-29  
**POC仓库:** [Joomla-CVE-2023-23752-Exploit-Script](https://github.com/Ly0kha/Joomla-CVE-2023-23752-Exploit-Script)  

---

### [CVE-2023-23752](CVE-2023-23752-r3dston3_CVE-2023-23752.md) 🟡 ✅

**名称:** CVE-2023-23752-Joomla-认证绕过导致信息泄露  
**类型:** 认证绕过  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-23752](https://github.com/r3dston3/CVE-2023-23752)  

---

### [CVE-2023-23752](CVE-2023-23752-svaltheim_CVE-2023-23752.md) 🟡 ✅

**名称:** CVE-2023-23752 - Joomla! 未授权信息泄露  
**类型:** 信息泄露  
**风险:** 中危，可能导致敏感信息泄露，进一步威胁到系统安全。  
**投毒风险:** 1%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-23752](https://github.com/svaltheim/CVE-2023-23752)  

---

### [CVE-2023-23752](CVE-2023-23752-Fernando-olv_Joomla-CVE-2023-23752.md) 🟡 ✅

**名称:** CVE-2023-23752 - Joomla! Webservice Endpoint Unauthorized Access  
**类型:** 未授权访问  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-29  
**POC仓库:** [Joomla-CVE-2023-23752](https://github.com/Fernando-olv/Joomla-CVE-2023-23752)  

---

### [CVE-2023-23752](CVE-2023-23752-K3ysTr0K3R_CVE-2023-23752-EXPLOIT.md) 🟡 ✅

**名称:** CVE-2023-23752 - Joomla! Improper Access Check  
**类型:** 权限绕过/信息泄露  
**风险:** 中危，可能导致敏感信息泄露，如用户名和配置信息，虽然漏洞描述中提到是低危(CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)，但是实际利用中可能存在RCE的风险(参考搜索引擎结果4)  
**投毒风险:** 0%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-23752-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2023-23752-EXPLOIT)  

---

### [CVE-2023-23752](CVE-2023-23752-hadrian3689_CVE-2023-23752_Joomla.md) 🟡 ✅

**名称:** CVE-2023-23752 - Joomla! Improper Access Control  
**类型:** 信息泄露/身份验证绕过  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-23752_Joomla](https://github.com/hadrian3689/CVE-2023-23752_Joomla)  

---

### [CVE-2023-23752](CVE-2023-23752-JeneralMotors_CVE-2023-23752.md) 🟡 ✅

**名称:** CVE-2023-23752-Joomla-身份验证绕过/信息泄露  
**类型:** 身份验证绕过/信息泄露  
**风险:** 中危，可能导致敏感信息泄露，如数据库配置、用户信息等  
**投毒风险:** 1%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-23752](https://github.com/JeneralMotors/CVE-2023-23752)  

---

### [CVE-2023-23752](CVE-2023-23752-gunzf0x_CVE-2023-23752.md) 🟡 ✅

**名称:** CVE-2023-23752 - Joomla! Improper Access Control  
**类型:** 权限绕过/信息泄露  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-23752](https://github.com/gunzf0x/CVE-2023-23752)  

---

### [CVE-2023-23752](CVE-2023-23752-TindalyTn_CVE-2023-23752.md) 🟡 ✅

**名称:** CVE-2023-23752-Joomla-认证绕过/信息泄露  
**类型:** 认证绕过/信息泄露  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-23752](https://github.com/TindalyTn/CVE-2023-23752)  

---

### [CVE-2023-23752](CVE-2023-23752-C1ph3rX13_CVE-2023-23752.md) 🟡 ✅

**名称:** CVE-2023-23752 - Joomla! 未授权信息泄露  
**类型:** 未授权信息泄露  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-23752](https://github.com/C1ph3rX13/CVE-2023-23752)  

---

### [CVE-2023-23752](CVE-2023-23752-Acceis_exploit-CVE-2023-23752.md) 🟡 ✅

**名称:** CVE-2023-23752 - Joomla! Webservice Endpoint Unauthorized Access  
**类型:** 信息泄露/身份验证绕过  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-29  
**POC仓库:** [exploit-CVE-2023-23752](https://github.com/Acceis/exploit-CVE-2023-23752)  

---

### [CVE-2023-23752](CVE-2023-23752-shellvik_CVE-2023-23752.md) 🟡 ✅

**名称:** CVE-2023-23752 - Joomla! Improper Access Control  
**类型:** 不当访问控制/信息泄露  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-23752](https://github.com/shellvik/CVE-2023-23752)  

---

### [CVE-2023-23752](CVE-2023-23752-Rival420_CVE-2023-23752.md) 🟡 ✅

**名称:** CVE-2023-23752-Joomla-未授权访问  
**类型:** 未授权访问  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-23752](https://github.com/Rival420/CVE-2023-23752)  

---

### [CVE-2023-23752](CVE-2023-23752-mariovata_CVE-2023-23752-Python.md) 🟡 ✅

**名称:** CVE-2023-23752-Joomla-信息泄露  
**类型:** 信息泄露  
**风险:** 中危，可能导致敏感信息泄露，为进一步攻击提供信息  
**投毒风险:** 0%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-23752-Python](https://github.com/mariovata/CVE-2023-23752-Python)  

---

### [CVE-2023-23752](CVE-2023-23752-AlissonFaoli_CVE-2023-23752.md) 🟡 ✅

**名称:** CVE-2023-23752-Joomla-未授权信息泄露  
**类型:** 未授权信息泄露  
**风险:** 中危，可能泄露敏感信息，如用户信息、数据库配置等  
**投毒风险:** 10%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-23752](https://github.com/AlissonFaoli/CVE-2023-23752)  

---

### [CVE-2023-23752](CVE-2023-23752-0xx01_CVE-2023-23752.md) 🟡 ✅

**名称:** CVE-2023-23752-Joomla-认证绕过  
**类型:** 认证绕过/信息泄露  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-23752](https://github.com/0xx01/CVE-2023-23752)  

---

### [CVE-2023-23752](CVE-2023-23752-JohnDoeAnonITA_CVE-2023-23752.md) 🟡 ✅

**名称:** CVE-2023-23752 - Joomla! Improper Access Control  
**类型:** 不当访问控制/信息泄露  
**风险:** 中危，可能导致敏感信息泄露，例如数据库配置信息  
**投毒风险:** 0%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-23752](https://github.com/JohnDoeAnonITA/CVE-2023-23752)  

---

### [CVE-2023-23752](CVE-2023-23752-mil4ne_CVE-2023-23752-Joomla-v4.2.8.md) 🟡 ✅

**名称:** CVE-2023-23752 - Joomla! Improper Access Control  
**类型:** 信息泄露  
**风险:** 中危，可能泄露数据库配置等敏感信息  
**投毒风险:** 5%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-23752-Joomla-v4.2.8](https://github.com/mil4ne/CVE-2023-23752-Joomla-v4.2.8)  

---

### [CVE-2023-23752](CVE-2023-23752-n3rdh4x0r_CVE-2023-23752.md) 🟡 ✅

**名称:** CVE-2023-23752-Joomla-信息泄露  
**类型:** 信息泄露  
**风险:** 中危，可能泄露敏感信息，例如数据库配置和用户信息。  
**投毒风险:** 5%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-23752](https://github.com/n3rdh4x0r/CVE-2023-23752)  

---

### [CVE-2023-23752](CVE-2023-23752-lainonz_CVE-2023-23752.md) 🟡 ✅

**名称:** CVE-2023-23752-Joomla-未授权访问 webservice 接口导致信息泄露  
**类型:** 信息泄露  
**风险:** 中危，可能导致敏感信息泄露，为进一步攻击提供信息  
**投毒风险:** 0%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-23752](https://github.com/lainonz/CVE-2023-23752)  

---

### [CVE-2023-23752](CVE-2023-23752-Aureum01_CVE-2023-23752.md) 🟡 ✅

**名称:** CVE-2023-23752 - Joomla! Authentication Bypass and Information Disclosure  
**类型:** 认证绕过/信息泄露  
**风险:** 中危，可能导致敏感信息泄露，为进一步攻击提供便利。  
**投毒风险:** 5%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-23752](https://github.com/Aureum01/CVE-2023-23752)  

---

### [CVE-2023-23752](CVE-2023-23752-0xWhoami35_CVE-2023-23752.md) 🟡 ✅

**名称:** CVE-2023-23752 - Joomla! Authentication Bypass Information Leak  
**类型:** 身份验证绕过/信息泄露  
**风险:** 中危，可导致敏感信息泄露，例如数据库配置和管理员凭据  
**投毒风险:** 5%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-23752](https://github.com/0xWhoami35/CVE-2023-23752)  

---

### [CVE-2021-21353](CVE-2021-21353-jinsu9758_PUG-RCE-CVE-2021-21353-POC.md) 🔴 ✅

**名称:** CVE-2021-21353-pug-RCE  
**类型:** 远程代码执行(RCE)  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-03-29  
**POC仓库:** [PUG-RCE-CVE-2021-21353-POC](https://github.com/jinsu9758/PUG-RCE-CVE-2021-21353-POC)  

---

### [CVE-2025-29927](CVE-2025-29927-dante01yoon_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-中间件认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 1%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2025-29927](https://github.com/dante01yoon/CVE-2025-29927)  

---

### [CVE-2022-24706](CVE-2022-24706-sadshade_CVE-2022-24706-CouchDB-Exploit.md) 🔴 ✅

**名称:** CVE-2022-24706 - Apache CouchDB Remote Code Execution  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2022-24706-CouchDB-Exploit](https://github.com/sadshade/CVE-2022-24706-CouchDB-Exploit)  

---

### [CVE-2022-24706](CVE-2022-24706-ahmetsabrimert_Apache-CouchDB-CVE-2022-24706-RCE-Exploits-Blog-post-.md) 🔴 

**名称:** CVE-2022-24706-Apache CouchDB远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，未经授权的远程代码执行和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-03-29  
**POC仓库:** [Apache-CouchDB-CVE-2022-24706-RCE-Exploits-Blog-post-](https://github.com/ahmetsabrimert/Apache-CouchDB-CVE-2022-24706-RCE-Exploits-Blog-post-)  

---

### [CVE-2022-24706](CVE-2022-24706-superzerosec_CVE-2022-24706.md) 🔴 ✅

**名称:** CVE-2022-24706 - Apache CouchDB 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的攻击者可获取管理员权限并执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2022-24706](https://github.com/superzerosec/CVE-2022-24706)  

---

### [CVE-2022-24706](CVE-2022-24706-becrevex_CVE-2022-24706.md) 🔴 ✅

**名称:** CVE-2022-24706-Apache CouchDB-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致未经授权的访问和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2022-24706](https://github.com/becrevex/CVE-2022-24706)  

---

### [CVE-2023-42793](CVE-2023-42793-Zenmovie_CVE-2023-42793.md)  ✅

**名称:** CVE-2023-42793 - JetBrains TeamCity 身份验证绕过导致RCE  
**类型:** 身份验证绕过导致RCE  
**风险:** 严重，未经身份验证的攻击者可以执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-42793](https://github.com/Zenmovie/CVE-2023-42793)  

---

### [CVE-2023-42793](CVE-2023-42793-LeHeron_TC_test.md) 🔴 ✅

**名称:** CVE-2023-42793-JetBrains TeamCity-身份验证绕过导致RCE  
**类型:** 身份验证绕过导致RCE  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-03-29  
**POC仓库:** [TC_test](https://github.com/LeHeron/TC_test)  

---

### [CVE-2023-42793](CVE-2023-42793-whoamins_CVE-2023-42793.md)  ✅

**名称:** CVE-2023-42793-JetBrains-TeamCity-身份验证绕过RCE  
**类型:** 身份验证绕过RCE  
**风险:** 严重，未授权远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-42793](https://github.com/whoamins/CVE-2023-42793)  

---

### [CVE-2023-42793](CVE-2023-42793-johnossawy_CVE-2023-42793_POC.md) 🔴 ✅

**名称:** CVE-2023-42793-JetBrains TeamCity-认证绕过RCE  
**类型:** 认证绕过导致远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-42793_POC](https://github.com/johnossawy/CVE-2023-42793_POC)  

---

### [CVE-2023-42793](CVE-2023-42793-StanleyJobsonAU_GhostTown.md) 🔴 ✅

**名称:** CVE-2023-42793-JetBrains TeamCity-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-29  
**POC仓库:** [GhostTown](https://github.com/StanleyJobsonAU/GhostTown)  

---

### [CVE-2023-42793](CVE-2023-42793-B4l3rI0n_CVE-2023-42793.md) 🔴 ✅

**名称:** CVE-2023-42793 - TeamCity 身份验证绕过导致RCE  
**类型:** 身份验证绕过  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-42793](https://github.com/B4l3rI0n/CVE-2023-42793)  

---

### [CVE-2023-42793](CVE-2023-42793-hotplugin0x01_CVE-2023-42793.md)  ✅

**名称:** CVE-2023-42793-JetBrains TeamCity-RCE  
**类型:** 远程代码执行（RCE）  
**风险:** 极高，未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-42793](https://github.com/hotplugin0x01/CVE-2023-42793)  

---

### [CVE-2023-42793](CVE-2023-42793-H454NSec_CVE-2023-42793.md) 🔴 ✅

**名称:** CVE-2023-42793 - JetBrains TeamCity 身份验证绕过导致RCE  
**类型:** 身份验证绕过  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-42793](https://github.com/H454NSec/CVE-2023-42793)  

---

### [CVE-2023-42793](CVE-2023-42793-junnythemarksman_CVE-2023-42793.md) 🔴 ✅

**名称:** CVE-2023-42793-JetBrains TeamCity-RCE  
**类型:** 认证绕过导致远程代码执行  
**风险:** 高危，允许未授权的攻击者创建管理员用户并执行任意代码  
**投毒风险:** 1%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-42793](https://github.com/junnythemarksman/CVE-2023-42793)  

---

### [CVE-2023-42793](CVE-2023-42793-HusenjanDev_CVE-2023-42793.md) 🔴 ✅

**名称:** CVE-2023-42793-JetBrains TeamCity-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的攻击者执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-42793](https://github.com/HusenjanDev/CVE-2023-42793)  

---

### [CVE-2023-42793](CVE-2023-42793-FlojBoj_CVE-2023-42793.md) 🔴 ✅

**名称:** CVE-2023-42793-JetBrainsTeamCity-身份验证绕过导致RCE  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致远程代码执行和完全控制TeamCity服务器  
**投毒风险:** 10%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-42793](https://github.com/FlojBoj/CVE-2023-42793)  

---

### [CVE-2023-42793](CVE-2023-42793-SwiftSecur_teamcity-exploit-cve-2023-42793.md) 🔴 ✅

**名称:** CVE-2023-42793-JetBrains TeamCity-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-29  
**POC仓库:** [teamcity-exploit-cve-2023-42793](https://github.com/SwiftSecur/teamcity-exploit-cve-2023-42793)  

---

### [CVE-2023-42793](CVE-2023-42793-becrevex_CVE-2023-42793.md) 🔴 ✅

**名称:** CVE-2023-42793-JetBrains TeamCity-认证绕过RCE  
**类型:** 认证绕过导致远程代码执行  
**风险:** 高危，未经授权的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-42793](https://github.com/becrevex/CVE-2023-42793)  

---

### [CVE-2025-29927](CVE-2025-29927-ferpalma21_Automated-Next.js-Security-Scanner-for-CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js中间件授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-29  
**POC仓库:** [Automated-Next.js-Security-Scanner-for-CVE-2025-29927](https://github.com/ferpalma21/Automated-Next.js-Security-Scanner-for-CVE-2025-29927)  

---

### [CVE-2025-29927](CVE-2025-29927-w2hcorp_CVE-2025-29927-Exploit.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-中间件鉴权绕过  
**类型:** 鉴权绕过  
**风险:** 高危，可能导致未授权访问敏感数据或功能  
**投毒风险:** 5%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2025-29927-Exploit](https://github.com/w2hcorp/CVE-2025-29927-Exploit)  

---

### [CVE-2023-7028](CVE-2023-7028-sariamubeen_CVE-2023-7028.md) 🔴 ✅

**名称:** CVE-2023-7028-GitLab-账户接管  
**类型:** 弱口令找回机制漏洞  
**风险:** 高危，可导致任意用户账户接管，包括管理员账户  
**投毒风险:** 0%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-7028](https://github.com/sariamubeen/CVE-2023-7028)  

---

### [CVE-2023-7028](CVE-2023-7028-googlei1996_CVE-2023-7028.md) 🔴 ✅

**名称:** CVE-2023-7028-GitLab账户接管  
**类型:** 弱口令恢复机制  
**风险:** 高危，可能导致账户接管  
**投毒风险:** 10%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-7028](https://github.com/googlei1996/CVE-2023-7028)  

---

### [CVE-2023-7028](CVE-2023-7028-RandomRobbieBF_CVE-2023-7028.md) 🔴 ✅

**名称:** CVE-2023-7028 - GitLab 弱密码恢复机制漏洞  
**类型:** 弱密码恢复机制漏洞  
**风险:** 高危，可能导致账户接管  
**投毒风险:** 1%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-7028](https://github.com/RandomRobbieBF/CVE-2023-7028)  

---

### [CVE-2023-7028](CVE-2023-7028-duy-31_CVE-2023-7028.md)  ✅

**名称:** CVE-2023-7028 - GitLab Account Takeover via Password Reset  
**类型:** 账户接管  
**风险:** 严重，可能导致账户完全控制，数据泄露，代码篡改等  
**投毒风险:** 0%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-7028](https://github.com/duy-31/CVE-2023-7028)  

---

### [CVE-2023-7028](CVE-2023-7028-Vozec_CVE-2023-7028.md) 🔴 ✅

**名称:** CVE-2023-7028-GitLab-账户接管  
**类型:** 弱密码恢复机制  
**风险:** 高危，可导致账户接管  
**投毒风险:** 10%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-7028](https://github.com/Vozec/CVE-2023-7028)  

---

### [CVE-2023-7028](CVE-2023-7028-Esonhugh_gitlab_honeypot.md) 🔴 ✅

**名称:** CVE-2023-7028-GitLab-账户接管  
**类型:** 弱密码恢复机制  
**风险:** 高危，允许攻击者无需用户交互即可接管账户，包括管理员账户  
**投毒风险:** 10%  
**发现时间:** 2025-03-29  
**POC仓库:** [gitlab_honeypot](https://github.com/Esonhugh/gitlab_honeypot)  

---

### [CVE-2023-7028](CVE-2023-7028-Shimon03_CVE-2023-7028-Account-Take-Over-Gitlab.md) 🔴 ✅

**名称:** CVE-2023-7028-GitLab-账户接管  
**类型:** 弱密码恢复机制  
**风险:** 高危，允许攻击者无需用户交互即可接管账户  
**投毒风险:** 5%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-7028-Account-Take-Over-Gitlab](https://github.com/Shimon03/CVE-2023-7028-Account-Take-Over-Gitlab)  

---

### [CVE-2023-7028](CVE-2023-7028-thanhlam-attt_CVE-2023-7028.md) 🔴 ✅

**名称:** CVE-2023-7028 - GitLab Account Takeover  
**类型:** 账号接管  
**风险:** 高危，可能导致账号接管，数据泄露，权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-7028](https://github.com/thanhlam-attt/CVE-2023-7028)  

---

### [CVE-2023-7028](CVE-2023-7028-Trackflaw_CVE-2023-7028-Docker.md) 🔴 ✅

**名称:** CVE-2023-7028-GitLab-账户接管  
**类型:** 账户接管  
**风险:** 高危，可导致账户完全控制，包括管理员账户  
**投毒风险:** 10%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-7028-Docker](https://github.com/Trackflaw/CVE-2023-7028-Docker)  

---

### [CVE-2023-7028](CVE-2023-7028-mochammadrafi_CVE-2023-7028.md)  ✅

**名称:** CVE-2023-7028-GitLab-账户接管  
**类型:** 账户接管  
**风险:** 严重，可能导致账户完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-7028](https://github.com/mochammadrafi/CVE-2023-7028)  

---

### [CVE-2023-7028](CVE-2023-7028-hackeremmen_gitlab-exploit.md) 🔴 ✅

**名称:** CVE-2023-7028 - GitLab 弱密码恢复机制漏洞  
**类型:** 弱密码恢复机制漏洞  
**风险:** 高危，可导致账户接管  
**投毒风险:** 10%  
**发现时间:** 2025-03-29  
**POC仓库:** [gitlab-exploit](https://github.com/hackeremmen/gitlab-exploit)  

---

### [CVE-2023-7028](CVE-2023-7028-soltanali0_CVE-2023-7028.md) 🔴 ✅

**名称:** CVE-2023-7028-GitLab-账户接管  
**类型:** 弱密码恢复机制  
**风险:** 高危，可导致账户接管  
**投毒风险:** 10%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-7028](https://github.com/soltanali0/CVE-2023-7028)  

---

### [CVE-2023-7028](CVE-2023-7028-gh-ost00_CVE-2023-7028.md) 🔴 ✅

**名称:** CVE-2023-7028-GitLab-账号接管  
**类型:** 账号接管  
**风险:** 高危，攻击者可以完全控制受影响的GitLab账户  
**投毒风险:** 10%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-7028](https://github.com/gh-ost00/CVE-2023-7028)  

---

### [CVE-2023-7028](CVE-2023-7028-yoryio_CVE-2023-7028.md) 🔴 ✅

**名称:** CVE-2023-7028 - GitLab Account Takeover  
**类型:** Account Takeover  
**风险:** 高危，可导致未经授权的账户访问和控制  
**投毒风险:** 5%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-7028](https://github.com/yoryio/CVE-2023-7028)  

---

### [CVE-2023-7028](CVE-2023-7028-Sornphut_CVE-2023-7028-GitLab.md) 🔴 ✅

**名称:** CVE-2023-7028-GitLab-账户接管  
**类型:** 弱口令重置机制  
**风险:** 高危，允许攻击者接管任何用户账户，包括管理员账户  
**投毒风险:** 5%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2023-7028-GitLab](https://github.com/Sornphut/CVE-2023-7028-GitLab)  

---

### [CVE-2025-1653](CVE-2025-1653-realcodeb0ss_CVE-2025-1653-poc.md) 🔴 ✅

**名称:** CVE-2025-1653-uListing-权限提升  
**类型:** 权限提升  
**风险:** 高危，可使订阅者级别用户提升为管理员  
**投毒风险:** 10%  
**发现时间:** 2025-03-29  
**POC仓库:** [CVE-2025-1653-poc](https://github.com/realcodeb0ss/CVE-2025-1653-poc)  

---

### [CVE-2025-2249](CVE-2025-2249-Nxploited_CVE-2025-2249.md) 🔴 ✅

**名称:** WordPress SoJ SoundSlides Plugin 任意文件上传漏洞  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2025-2249](https://github.com/Nxploited/CVE-2025-2249)  

---

### [CVE-2025-2857](CVE-2025-2857-RimaRuer_CVE-2025-2857-Exploit.md) 🔴 

**名称:** CVE-2025-2857-Firefox-Sandbox逃逸  
**类型:** Sandbox逃逸  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 85%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2025-2857-Exploit](https://github.com/RimaRuer/CVE-2025-2857-Exploit)  

---

### [CVE-2025-2783](CVE-2025-2783-bronsoneaver_CVE-2025-2783.md) 🔴 

**名称:** CVE-2025-2783  
**类型:** 沙箱逃逸  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 95%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2025-2783](https://github.com/bronsoneaver/CVE-2025-2783)  

---

### [CVE-2021-41773](CVE-2021-41773-luongchivi_CVE-2021-41773.md) 🔴 ✅

**名称:** CVE-2021-41773 - Apache HTTP Server Path Traversal  
**类型:** 路径遍历 (Path Traversal)  
**风险:** 高危，可导致敏感信息泄露和远程代码执行 (Remote Code Execution, RCE)  
**投毒风险:** 5%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2021-41773](https://github.com/luongchivi/CVE-2021-41773)  

---

### [CVE-2025-1974](CVE-2025-1974-rjhaikal_POC-IngressNightmare-CVE-2025-1974.md) 🔴 ✅

**名称:** CVE-2025-1974 Ingress-nginx 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致集群范围内的密钥泄露和完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-03-28  
**POC仓库:** [POC-IngressNightmare-CVE-2025-1974](https://github.com/rjhaikal/POC-IngressNightmare-CVE-2025-1974)  

---

### [CVE-2025-26909](CVE-2025-26909-ZeroDayx_CVE-2025-26909.md) 🔴 ✅

**名称:** CVE-2025-26909 - WordPress Hide My WP Ghost Plugin - 本地文件包含  
**类型:** 本地文件包含 (LFI)  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2025-26909](https://github.com/ZeroDayx/CVE-2025-26909)  

---

### [CVE-2023-3460](CVE-2023-3460-gbrsh_CVE-2023-3460.md) 🔴 ✅

**名称:** CVE-2023-3460-Ultimate Member-权限提升  
**类型:** 权限提升  
**风险:** 高危，允许未授权用户创建管理员账户，完全控制网站  
**投毒风险:** 5%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2023-3460](https://github.com/gbrsh/CVE-2023-3460)  

---

### [CVE-2023-3460](CVE-2023-3460-rizqimaulanaa_CVE-2023-3460.md) 🔴 ✅

**名称:** CVE-2023-3460 - Ultimate Member Plugin Unauthenticated Privilege Escalation  
**类型:** 权限提升  
**风险:** 高危，允许未授权用户创建管理员账户，完全控制网站  
**投毒风险:** 5%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2023-3460](https://github.com/rizqimaulanaa/CVE-2023-3460)  

---

### [CVE-2023-3460](CVE-2023-3460-yon3zu_Mass-CVE-2023-3460.md) 🔴 ✅

**名称:** CVE-2023-3460 - Ultimate Member Unauthenticated Privilege Escalation  
**类型:** 权限提升  
**风险:** 高危，允许未经验证的攻击者创建管理员账户，完全控制网站  
**投毒风险:** 5%  
**发现时间:** 2025-03-28  
**POC仓库:** [Mass-CVE-2023-3460](https://github.com/yon3zu/Mass-CVE-2023-3460)  

---

### [CVE-2023-3460](CVE-2023-3460-EmadYaY_CVE-2023-3460.md) 🔴 ✅

**名称:** CVE-2023-3460 - Ultimate Member Plugin 未授权提权漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致网站完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2023-3460](https://github.com/EmadYaY/CVE-2023-3460)  

---

### [CVE-2023-3460](CVE-2023-3460-diego-tella_CVE-2023-3460.md) 🔴 ✅

**名称:** CVE-2023-3460-Ultimate Member-权限提升  
**类型:** 权限提升  
**风险:** 高危，允许未授权用户创建管理员账户并完全控制网站  
**投毒风险:** 10%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2023-3460](https://github.com/diego-tella/CVE-2023-3460)  

---

### [CVE-2023-3460](CVE-2023-3460-DiMarcoSK_CVE-2023-3460_POC.md) 🔴 ✅

**名称:** CVE-2023-3460-Ultimate Member-权限提升  
**类型:** 权限提升  
**风险:** 高危，允许未经验证的攻击者创建管理员账户，完全控制网站  
**投毒风险:** 1%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2023-3460_POC](https://github.com/DiMarcoSK/CVE-2023-3460_POC)  

---

### [CVE-2023-3460](CVE-2023-3460-julienbrs_exploit-CVE-2023-3460.md) 🔴 ✅

**名称:** CVE-2023-3460-Ultimate Member-权限提升  
**类型:** 权限提升  
**风险:** 高危，允许未认证的攻击者创建管理员账户并完全控制网站  
**投毒风险:** 10%  
**发现时间:** 2025-03-28  
**POC仓库:** [exploit-CVE-2023-3460](https://github.com/julienbrs/exploit-CVE-2023-3460)  

---

### [CVE-2023-3460](CVE-2023-3460-Rajneeshkarya_CVE-2023-3460.md) 🔴 ✅

**名称:** CVE-2023-3460-Ultimate Member-权限提升  
**类型:** 权限提升  
**风险:** 高危，可被未授权用户创建管理员账户并完全控制网站  
**投毒风险:** 10%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2023-3460](https://github.com/Rajneeshkarya/CVE-2023-3460)  

---

### [CVE-2023-3460](CVE-2023-3460-TranKuBao_CVE-2023-3460_FIX.md) 🔴 ✅

**名称:** CVE-2023-3460 - Ultimate Member Privilege Escalation  
**类型:** 权限提升  
**风险:** 高危，允许未授权用户创建管理员账户并完全控制网站  
**投毒风险:** 5%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2023-3460_FIX](https://github.com/TranKuBao/CVE-2023-3460_FIX)  

---

### [CVE-2025-30208](CVE-2025-30208-keklick1337_CVE-2025-30208-ViteVulnScanner.md) 🟡 ✅

**名称:** CVE-2025-30208-Vite-任意文件读取  
**类型:** 任意文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2025-30208-ViteVulnScanner](https://github.com/keklick1337/CVE-2025-30208-ViteVulnScanner)  

---

### [CVE-2025-29927](CVE-2025-29927-CEAarab_CVE-2025-29927_env.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-Middleware授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未经授权的访问和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2025-29927_env](https://github.com/CEAarab/CVE-2025-29927_env)  

---

### [CVE-2025-29927](CVE-2025-29927-AnonKryptiQuz_NextSploit.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-中间件权限绕过  
**类型:** 权限绕过  
**风险:** 高危，可能导致未授权访问、数据泄露和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-03-28  
**POC仓库:** [NextSploit](https://github.com/AnonKryptiQuz/NextSploit)  

---

### [CVE-2025-30772](CVE-2025-30772-Nxploited_CVE-2025-30772.md) 🔴 ✅

**名称:** CVE-2025-30772 - WordPress WPC Smart Upsell Funnel for WooCommerce Privilege Escalation  
**类型:** 权限提升  
**风险:** 高危，允许低权限用户提升为管理员权限  
**投毒风险:** 1%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2025-30772](https://github.com/Nxploited/CVE-2025-30772)  

---

### [CVE-2022-24834](CVE-2022-24834-convisolabs_CVE-2022-24834.md) 🔴 ✅

**名称:** CVE-2022-24834 - Redis Lua cjson 库堆溢出  
**类型:** 堆溢出  
**风险:** 高危，可能导致堆破坏和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2022-24834](https://github.com/convisolabs/CVE-2022-24834)  

---

### [CVE-2022-24834](CVE-2022-24834-DukeSec97_CVE-2022-24834-.md) 🔴 ✅

**名称:** CVE-2022-24834-Redis-Lua cjson heap overflow  
**类型:** 堆溢出  
**风险:** 高危，可能导致堆破坏和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2022-24834-](https://github.com/DukeSec97/CVE-2022-24834-)  

---

### [CVE-2025-30208](CVE-2025-30208-sadhfdw129_CVE-2025-30208-Vite.md) 🟡 ✅

**名称:** CVE-2025-30208-Vite-文件读取漏洞  
**类型:** 文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2025-30208-Vite](https://github.com/sadhfdw129/CVE-2025-30208-Vite)  

---

### [CVE-2025-24813](CVE-2025-24813-AlperenY-cs_CVE-2025-24813.md) 🔴 ✅

**名称:** CVE-2025-24813 - Apache Tomcat 路径等价性漏洞  
**类型:** 远程代码执行 (RCE) / 信息泄露  
**风险:** 高危，可能导致远程代码执行、信息泄露和恶意内容注入  
**投毒风险:** 10%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2025-24813](https://github.com/AlperenY-cs/CVE-2025-24813)  

---

### [CVE-2025-29018](CVE-2025-29018-b1tm4r_CVE-2025-29018.md)  ✅

**名称:** CVE-2025-29018  
**类型:** 未知  
**风险:** 待分析  
**投毒风险:** 0%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2025-29018](https://github.com/b1tm4r/CVE-2025-29018)  

---

### [CVE-2025-29015](CVE-2025-29015-b1tm4r_CVE-2025-29015.md) 🔴 ✅

**名称:** CVE-2025-29015  
**类型:** 未明确，可能为远程代码执行  
**风险:** 高危，可能导致远程代码执行或敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2025-29015](https://github.com/b1tm4r/CVE-2025-29015)  

---

### [CVE-2025-29017](CVE-2025-29017-b1tm4r_CVE-2025-29017.md) 🔴 ✅

**名称:** CVE-2025-29015 (未确认，可能存在错误)  
**类型:** 未明确，根据相关CVE推测可能为缓冲区溢出等  
**风险:** 中危至高危，取决于具体漏洞类型和利用方式  
**投毒风险:** 10%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2025-29017](https://github.com/b1tm4r/CVE-2025-29017)  

---

### [CVE-2025-29927](CVE-2025-29927-0x0Luk_0xMiddleware.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js Middleware 权限绕过  
**类型:** 权限绕过  
**风险:** 高危，可能导致未经授权的访问和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-28  
**POC仓库:** [0xMiddleware](https://github.com/0x0Luk/0xMiddleware)  

---

### [CVE-2024-23897](CVE-2024-23897-brandonhjh_Jenkins-CVE-2024-23897-Exploit-Demo.md) 🔴 ✅

**名称:** CVE-2024-23897-Jenkins-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行（RCE）  
**投毒风险:** 10%  
**发现时间:** 2025-03-28  
**POC仓库:** [Jenkins-CVE-2024-23897-Exploit-Demo](https://github.com/brandonhjh/Jenkins-CVE-2024-23897-Exploit-Demo)  

---

### [CVE-2020-0618](CVE-2020-0618-euphrat1ca_CVE-2020-0618.md) 🔴 ✅

**名称:** CVE-2020-0618 - Microsoft SQL Server Reporting Services Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，可导致完全控制受影响的服务器  
**投毒风险:** 10%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2020-0618](https://github.com/euphrat1ca/CVE-2020-0618)  

---

### [CVE-2020-0618](CVE-2020-0618-wortell_cve-2020-0618.md) 🔴 ✅

**名称:** CVE-2020-0618 Microsoft SQL Server Reporting Services RCE Honeypot  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-03-28  
**POC仓库:** [cve-2020-0618](https://github.com/wortell/cve-2020-0618)  

---

### [CVE-2020-0618](CVE-2020-0618-itstarsec_CVE-2020-0618.md) 🔴 ✅

**名称:** CVE-2020-0618 - Microsoft SQL Server Reporting Services RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2020-0618](https://github.com/itstarsec/CVE-2020-0618)  

---

### [CVE-2020-0618](CVE-2020-0618-N3xtGenH4cker_CVE-2020-0618_DETECTION.md) 🔴 ✅

**名称:** CVE-2020-0618 - Microsoft SQL Server Reporting Services (SSRS) 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2020-0618_DETECTION](https://github.com/N3xtGenH4cker/CVE-2020-0618_DETECTION)  

---

### [CVE-2025-32820](CVE-2025-32820-itssixtyn3in_CVE-2025-3282025.md) 🟡 ✅

**名称:** CVE-2025-3282025 - Copilot AI URI注入  
**类型:** URI注入/Open Redirect  
**风险:** 中危，可能导致应用程序启动和潜在的安全绕过  
**投毒风险:** 5%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2025-3282025](https://github.com/itssixtyn3in/CVE-2025-3282025)  

---

### [CVE-2025-32720](CVE-2025-32720-itssixtyn3in_CVE-2025-3272025.md) 🟡 ✅

**名称:** CVE-2025-3272025-Copilot AI-UI Misrepresentation  
**类型:** UI Misrepresentation  
**风险:** 中危，可能导致用户误导和潜在安全风险  
**投毒风险:** 0%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2025-3272025](https://github.com/itssixtyn3in/CVE-2025-3272025)  

---

### [CVE-2025-21298](CVE-2025-21298-Denyningbow_rtf-ctf-cve-2025-21298.md) 🔴 ✅

**名称:** CVE-2025-21298 Windows OLE远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-28  
**POC仓库:** [rtf-ctf-cve-2025-21298](https://github.com/Denyningbow/rtf-ctf-cve-2025-21298)  

---

### [CVE-2025-29927](CVE-2025-29927-yuzu-juice_CVE-2025-29927_demo.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-Authorization Bypass  
**类型:** 权限绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2025-29927_demo](https://github.com/yuzu-juice/CVE-2025-29927_demo)  

---

### [CVE-2023-26209](CVE-2023-26209-cnetsec_CVE-2023-26209.md)  ✅

**名称:** CVE-2023-26209-FortiDeceptor-拒绝服务  
**类型:** 拒绝服务 (DoS)  
**风险:** 低危，可能导致CPU和内存资源耗尽  
**投毒风险:** 10%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2023-26209](https://github.com/cnetsec/CVE-2023-26209)  

---

### [CVE-2025-21298](CVE-2025-21298-ynwarcs_CVE-2025-21298.md) 🔴 ✅

**名称:** CVE-2025-21298-Windows OLE Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2025-21298](https://github.com/ynwarcs/CVE-2025-21298)  

---

### [CVE-2025-21298](CVE-2025-21298-Dit-Developers_CVE-2025-21298.md) 🔴 ✅

**名称:** CVE-2025-21298 - Windows OLE 远程代码执行漏洞  
**类型:** 双重释放 (Use-After-Free)  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2025-21298](https://github.com/Dit-Developers/CVE-2025-21298)  

---

### [CVE-2023-26208](CVE-2023-26208-cnetsec_CVE-2023-26208.md)  ✅

**名称:** CVE-2023-26208 Fortinet FortiAuthenticator 拒绝服务漏洞  
**类型:** 拒绝服务 (DoS)  
**风险:** 低危，可能导致CPU和内存资源耗尽  
**投毒风险:** 5%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2023-26208](https://github.com/cnetsec/CVE-2023-26208)  

---

### [CVE-2019-9978](CVE-2019-9978-grimlockx_CVE-2019-9978.md) 🔴 ✅

**名称:** CVE-2019-9978-Social Warfare-存储型XSS和RCE  
**类型:** 存储型XSS / RCE  
**风险:** 高危，可能导致远程代码执行和权限提升  
**投毒风险:** 1%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2019-9978](https://github.com/grimlockx/CVE-2019-9978)  

---

### [CVE-2021-24019](CVE-2021-24019-cnetsec_CVE-2021-24019.md) 🔴 ✅

**名称:** CVE-2021-24019 - FortiClientEMS 会话过期不足漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致未授权访问和控制FortiClientEMS服务器  
**投毒风险:** 0%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2021-24019](https://github.com/cnetsec/CVE-2021-24019)  

---

### [CVE-2019-9978](CVE-2019-9978-KTN1990_CVE-2019-9978.md) 🔴 ✅

**名称:** CVE-2019-9978-Social-Warfare-WordPress-Stored-XSS-RCE  
**类型:** Stored XSS / Remote Code Execution  
**风险:** 高危，可能导致远程代码执行和敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2019-9978](https://github.com/KTN1990/CVE-2019-9978)  

---

### [CVE-2019-9978](CVE-2019-9978-mpgn_CVE-2019-9978.md) 🔴 ✅

**名称:** CVE-2019-9978 - Social Warfare WordPress Plugin RCE/XSS  
**类型:** RCE/Stored XSS  
**风险:** 高危，可能导致远程代码执行和恶意脚本注入  
**投毒风险:** 10%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2019-9978](https://github.com/mpgn/CVE-2019-9978)  

---

### [CVE-2019-9978](CVE-2019-9978-cved-sources_cve-2019-9978.md) 🟡 ✅

**名称:** CVE-2019-9978-Social Warfare-存储型XSS  
**类型:** 存储型跨站脚本 (Stored XSS)  
**风险:** 中危，可能导致管理员账户被盗用、网站内容篡改  
**投毒风险:** 10%  
**发现时间:** 2025-03-28  
**POC仓库:** [cve-2019-9978](https://github.com/cved-sources/cve-2019-9978)  

---

### [CVE-2019-9978](CVE-2019-9978-hash3liZer_CVE-2019-9978.md) 🟡 ✅

**名称:** CVE-2019-9978 Social Warfare Plugin Stored XSS  
**类型:** Stored XSS  
**风险:** 中危，可能导致用户凭据泄露，恶意脚本执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2019-9978](https://github.com/hash3liZer/CVE-2019-9978)  

---

### [CVE-2019-9978](CVE-2019-9978-d3fudd_CVE-2019-9978_Exploit.md) 🔴 ✅

**名称:** CVE-2019-9978 - WordPress Social Warfare Plugin 存储型XSS和远程代码执行  
**类型:** 存储型XSS / 远程代码执行 (RCE)  
**风险:** 高危，可能导致网站权限被获取，远程代码执行。  
**投毒风险:** 0%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2019-9978_Exploit](https://github.com/d3fudd/CVE-2019-9978_Exploit)  

---

### [CVE-2019-9978](CVE-2019-9978-0xMoonrise_cve-2019-9978.md) 🟡 ✅

**名称:** CVE-2019-9978-Social-Warfare-Stored-XSS  
**类型:** Stored XSS  
**风险:** 中危，可能导致会话劫持、恶意重定向、网页内容篡改  
**投毒风险:** 0%  
**发现时间:** 2025-03-28  
**POC仓库:** [cve-2019-9978](https://github.com/0xMoonrise/cve-2019-9978)  

---

### [CVE-2019-9978](CVE-2019-9978-h8handles_CVE-2019-9978-Python3.md) 🔴 ✅

**名称:** CVE-2019-9978-Social Warfare-Stored XSS/RCE  
**类型:** Stored XSS/RCE  
**风险:** 高危，可能导致远程代码执行和权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2019-9978-Python3](https://github.com/h8handles/CVE-2019-9978-Python3)  

---

### [CVE-2019-9978](CVE-2019-9978-MAHajian_CVE-2019-9978.md) 🔴 ✅

**名称:** CVE-2019-9978-Social-Warfare-Stored-XSS-RCE  
**类型:** 存储型跨站脚本 (Stored XSS) / 远程代码执行 (RCE)  
**风险:** 高危，可能导致网站被控制，用户信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2019-9978](https://github.com/MAHajian/CVE-2019-9978)  

---

### [CVE-2019-9978](CVE-2019-9978-echoosso_CVE-2019-9978.md) 🔴 ✅

**名称:** CVE-2019-9978-Social Warfare-Stored XSS / RCE  
**类型:** Stored XSS / RCE  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-03-28  
**POC仓库:** [CVE-2019-9978](https://github.com/echoosso/CVE-2019-9978)  

---

### [CVE-2025-30355](CVE-2025-30355-ui-bootstrap_CVE-2025-30355.md) 🔴 ✅

**名称:** CVE-2025-30355-Synapse-Federation Denial of Service  
**类型:** Federation Denial of Service  
**风险:** 高危，导致服务不可用  
**投毒风险:** 0%  
**发现时间:** 2025-03-27  
**POC仓库:** [CVE-2025-30355](https://github.com/ui-bootstrap/CVE-2025-30355)  

---

### [CVE-2025-30349](CVE-2025-30349-natasaka_CVE-2025-30349.md) 🔴 ✅

**名称:** CVE-2025-30349-Horde-XSS  
**类型:** XSS  
**风险:** 高危，可能导致账户劫持和信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-27  
**POC仓库:** [CVE-2025-30349](https://github.com/natasaka/CVE-2025-30349)  

---

### [CVE-2025-2294](CVE-2025-2294-Nxploited_CVE-2025-2294.md) 🔴 ✅

**名称:** CVE-2025-2294 Kubio AI Page Builder 本地文件包含漏洞  
**类型:** 本地文件包含 (LFI)  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-27  
**POC仓库:** [CVE-2025-2294](https://github.com/Nxploited/CVE-2025-2294)  

---

### [CVE-2025-1974](CVE-2025-1974-tuladhar_ingress-nightmare.md)  ✅

**名称:** CVE-2025-1974-ingress-nginx-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致集群接管  
**投毒风险:** 10%  
**发现时间:** 2025-03-27  
**POC仓库:** [ingress-nightmare](https://github.com/tuladhar/ingress-nightmare)  

---

### [CVE-2024-4577](CVE-2024-4577-fabulouscounc_CVE-2024-4577-PHP-RCE.md) 🔴 ✅

**名称:** CVE-2024-4577-PHP-CGI参数注入  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和服务器完全控制  
**投毒风险:** 50%  
**发现时间:** 2025-03-27  
**POC仓库:** [CVE-2024-4577-PHP-RCE](https://github.com/fabulouscounc/CVE-2024-4577-PHP-RCE)  

---

### [CVE-2025-24071](CVE-2025-24071-Marcejr117_CVE-2025-24071_PoC.md) 🟡 ✅

**名称:** CVE-2025-24071-Windows File Explorer Spoofing Vulnerability  
**类型:** 信息泄露/欺骗  
**风险:** 中危，可能导致NTLM哈希泄露和欺骗攻击  
**投毒风险:** 0%  
**发现时间:** 2025-03-27  
**POC仓库:** [CVE-2025-24071_PoC](https://github.com/Marcejr117/CVE-2025-24071_PoC)  

---

### [CVE-2018-9206](CVE-2018-9206-Den1al_CVE-2018-9206.md) 🔴 ✅

**名称:** CVE-2018-9206 - Blueimp jQuery-File-Upload Unauthenticated Arbitrary File Upload  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-27  
**POC仓库:** [CVE-2018-9206](https://github.com/Den1al/CVE-2018-9206)  

---

### [CVE-2018-9206](CVE-2018-9206-Stahlz_JQShell.md) 🔴 ✅

**名称:** CVE-2018-9206 - Blueimp jQuery File Upload 未授权任意文件上传  
**类型:** 未授权任意文件上传  
**风险:** 高危，可能导致远程代码执行和服务器控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-27  
**POC仓库:** [JQShell](https://github.com/Stahlz/JQShell)  

---

### [CVE-2018-9206](CVE-2018-9206-cved-sources_cve-2018-9206.md) 🔴 ✅

**名称:** CVE-2018-9206 Blueimp jQuery-File-Upload 未授权任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-27  
**POC仓库:** [cve-2018-9206](https://github.com/cved-sources/cve-2018-9206)  

---

### [CVE-2018-9206](CVE-2018-9206-mi-hood_CVE-2018-9206.md) 🔴 ✅

**名称:** CVE-2018-9206-Blueimp jQuery File Upload-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-27  
**POC仓库:** [CVE-2018-9206](https://github.com/mi-hood/CVE-2018-9206)  

---

### [CVE-2018-9206](CVE-2018-9206-MikeyPPPPPPPP_CVE-2018-9206.md) 🔴 ✅

**名称:** CVE-2018-9206 - Blueimp jQuery File Upload 未授权任意文件上传  
**类型:** 未授权任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-27  
**POC仓库:** [CVE-2018-9206](https://github.com/MikeyPPPPPPPP/CVE-2018-9206)  

---

### [CVE-2018-9206](CVE-2018-9206-liemkaka_CVE-2018-9206.md) 🔴 ✅

**名称:** CVE-2018-9206-Blueimp jQuery File Upload-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 20%  
**发现时间:** 2025-03-27  
**POC仓库:** [CVE-2018-9206](https://github.com/liemkaka/CVE-2018-9206)  

---

### [CVE-2025-29927](CVE-2025-29927-nocomp_CVE-2025-29927-scanner.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js中间件授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未经授权的访问和数据泄露  
**投毒风险:** 20%  
**发现时间:** 2025-03-27  
**POC仓库:** [CVE-2025-29927-scanner](https://github.com/nocomp/CVE-2025-29927-scanner)  

---

### [CVE-2024-7479](CVE-2024-7479-fortra_CVE-2024-7479.md) 🔴 ✅

**名称:** CVE-2024-7479-TeamViewer-权限提升  
**类型:** 权限提升  
**风险:** 高危，允许本地非特权用户提升权限并安装驱动程序  
**投毒风险:** 10%  
**发现时间:** 2025-03-27  
**POC仓库:** [CVE-2024-7479](https://github.com/fortra/CVE-2024-7479)  

---

### [CVE-2025-30108](CVE-2025-30108-4xura_CVE-2025-30108.md) 🔴 ✅

**名称:** CVE-2025-30208 Vite @fs/ Path Traversal in transformMiddleware  
**类型:** 路径遍历  
**风险:** 高危，可能导致文件读取，甚至远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-27  
**POC仓库:** [CVE-2025-30108](https://github.com/4xura/CVE-2025-30108)  

---

### [CVE-2025-30208](CVE-2025-30208-On1onss_CVE-2025-30208-LFI.md) 🟡 ✅

**名称:** CVE-2025-30208-Vite-文件读取  
**类型:** 文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-27  
**POC仓库:** [CVE-2025-30208-LFI](https://github.com/On1onss/CVE-2025-30208-LFI)  

---

### [CVE-2025-29927](CVE-2025-29927-KaztoRay_CVE-2025-29927-Research.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js Middleware Authorization Bypass  
**类型:** 权限绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-27  
**POC仓库:** [CVE-2025-29927-Research](https://github.com/KaztoRay/CVE-2025-29927-Research)  

---

### [CVE-2025-29927](CVE-2025-29927-m2hcz_m2hcz-Next.js-security-flaw-CVE-2025-29927---PoC-exploit.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-中间件认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-27  
**POC仓库:** [m2hcz-Next.js-security-flaw-CVE-2025-29927---PoC-exploit](https://github.com/m2hcz/m2hcz-Next.js-security-flaw-CVE-2025-29927---PoC-exploit)  

---

### [CVE-2024-9474](CVE-2024-9474-worthytop_CVE-2024-9474.md) 🔴 ✅

**名称:** CVE-2024-9474 PAN-OS Web Management Interface Privilege Escalation  
**类型:** 权限提升/OS 命令注入  
**风险:** 高危，允许经过身份验证的管理员以 root 权限执行操作  
**投毒风险:** 30%  
**发现时间:** 2025-03-27  
**POC仓库:** [CVE-2024-9474](https://github.com/worthytop/CVE-2024-9474)  

---

### [CVE-2025-29927](CVE-2025-29927-Heimd411_CVE-2025-29927-PoC.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js Middleware Bypass  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 1%  
**发现时间:** 2025-03-27  
**POC仓库:** [CVE-2025-29927-PoC](https://github.com/Heimd411/CVE-2025-29927-PoC)  

---

### [CVE-2024-56901](CVE-2024-56901-DRAGOWN_CVE-2024-56901.md) 🔴 ✅

**名称:** CVE-2024-56901 - Geovision GV-ASWeb CSRF 创建管理员账户  
**类型:** 跨站请求伪造 (CSRF)  
**风险:** 高危，可导致未授权访问和控制  
**投毒风险:** 5%  
**发现时间:** 2025-03-27  
**POC仓库:** [CVE-2024-56901](https://github.com/DRAGOWN/CVE-2024-56901)  

---

### [CVE-2024-56902](CVE-2024-56902-DRAGOWN_CVE-2024-56902.md) 🔴 ✅

**名称:** CVE-2024-56902 - GeoVision ASManager 信息泄露漏洞  
**类型:** 信息泄露  
**风险:** 高危，可能导致账户信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-03-27  
**POC仓库:** [CVE-2024-56902](https://github.com/DRAGOWN/CVE-2024-56902)  

---

### [CVE-2025-26264](CVE-2025-26264-DRAGOWN_CVE-2025-26264.md) 🔴 ✅

**名称:** CVE-2025-26264 - GeoVision GV-ASWeb Remote Code Execution  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可完全控制系统  
**投毒风险:** 10%  
**发现时间:** 2025-03-27  
**POC仓库:** [CVE-2025-26264](https://github.com/DRAGOWN/CVE-2025-26264)  

---

### [CVE-2025-24071](CVE-2025-24071-rubbxalc_CVE-2025-24071.md) 🔴 ✅

**名称:** CVE-2025-24071 - Windows File Explorer Spoofing Vulnerability  
**类型:** Spoofing / NTLM Hash Capture  
**风险:** 高危，可能导致凭据泄露和网络渗透  
**投毒风险:** 0%  
**发现时间:** 2025-03-27  
**POC仓库:** [CVE-2025-24071](https://github.com/rubbxalc/CVE-2025-24071)  

---

### [CVE-2024-56898](CVE-2024-56898-DRAGOWN_CVE-2024-56898.md) 🔴 ✅

**名称:** CVE-2024-56898 - Geovision GV-ASWeb 权限控制缺陷  
**类型:** 权限控制缺陷/Broken Access Control  
**风险:** 高危，可导致权限提升、账户管理权限篡改、敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-27  
**POC仓库:** [CVE-2024-56898](https://github.com/DRAGOWN/CVE-2024-56898)  

---

### [CVE-2023-24709](CVE-2023-24709-DRAGOWN_CVE-2023-24709-PoC.md) 🔴 ✅

**名称:** CVE-2023-24709-Paradox Security Systems IPR512-DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，导致设备无法正常使用  
**投毒风险:** 0%  
**发现时间:** 2025-03-27  
**POC仓库:** [CVE-2023-24709-PoC](https://github.com/DRAGOWN/CVE-2023-24709-PoC)  

---

### [CVE-2025-24071](CVE-2025-24071-ThemeHackers_CVE-2025-24071.md) 🔴 ✅

**名称:** CVE-2025-24071 Windows File Explorer Spoofing Vulnerability  
**类型:** 欺骗漏洞 (Spoofing)  
**风险:** 高危，可能导致敏感信息泄露（NTLM hashes）  
**投毒风险:** 10%  
**发现时间:** 2025-03-27  
**POC仓库:** [CVE-2025-24071](https://github.com/ThemeHackers/CVE-2025-24071)  

---

### [CVE-2025-29927](CVE-2025-29927-Nekicj_CVE-2025-29927-exploit.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-Authorization Bypass  
**类型:** 权限绕过  
**风险:** 高危，可能导致未经授权的访问和数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-27  
**POC仓库:** [CVE-2025-29927-exploit](https://github.com/Nekicj/CVE-2025-29927-exploit)  

---

### [CVE-2025-30208](CVE-2025-30208-LiChaser_CVE-2025-30208.md) 🟡 ✅

**名称:** CVE-2025-30208-Vite-任意文件读取  
**类型:** 任意文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-27  
**POC仓库:** [CVE-2025-30208](https://github.com/LiChaser/CVE-2025-30208)  

---

### [CVE-2025-29927](CVE-2025-29927-aleongx_CVE-2025-29927_Scanner.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js Middleware Authorization Bypass  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 1%  
**发现时间:** 2025-03-27  
**POC仓库:** [CVE-2025-29927_Scanner](https://github.com/aleongx/CVE-2025-29927_Scanner)  

---

### [CVE-2025-50000](CVE-2025-50000-adiivascu_CVE-2025-50000.md)  ✅

**名称:** CVE-2025-50000  
**类型:** 未知  
**风险:** 未知  
**投毒风险:** 0%  
**发现时间:** 2025-03-27  
**POC仓库:** [CVE-2025-50000](https://github.com/adiivascu/CVE-2025-50000)  

---

### [CVE-2025-30208](CVE-2025-30208-iSee857_CVE-2025-30208-PoC.md) 🟡 ✅

**名称:** CVE-2025-30208-Vite-任意文件读取  
**类型:** 任意文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-27  
**POC仓库:** [CVE-2025-30208-PoC](https://github.com/iSee857/CVE-2025-30208-PoC)  

---

### [CVE-2025-29927](CVE-2025-29927-ferpalma21_Automated-Next.js-Security-Scanner-for-CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js中间件权限绕过  
**类型:** 权限绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-27  
**POC仓库:** [Automated-Next.js-Security-Scanner-for-CVE-2025-29927](https://github.com/ferpalma21/Automated-Next.js-Security-Scanner-for-CVE-2025-29927)  

---

### [CVE-2025-29927](CVE-2025-29927-jmbowes_NextSecureScan.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-Middleware权限绕过  
**类型:** 权限绕过  
**风险:** 高危，可能导致未授权访问、数据泄露和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-03-27  
**POC仓库:** [NextSecureScan](https://github.com/jmbowes/NextSecureScan)  

---

### [CVE-2025-1974](CVE-2025-1974-0xBingo_CVE-2025-1974.md) 🔴 ✅

**名称:** CVE-2025-1974-ingress-nginx-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致集群范围内的密钥泄露和任意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-27  
**POC仓库:** [CVE-2025-1974](https://github.com/0xBingo/CVE-2025-1974)  

---

### [CVE-2025-29927](CVE-2025-29927-nicknisi_next-attack.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-Middleware-Authorization-Bypass  
**类型:** 权限绕过  
**风险:** 高危，可能导致未经授权的访问和数据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-27  
**POC仓库:** [next-attack](https://github.com/nicknisi/next-attack)  

---

### [CVE-2024-7479](CVE-2024-7479-PeterGabaldon_CVE-2024-7479_CVE-2024-7481.md) 🔴 ✅

**名称:** CVE-2024-7479 TeamViewer VPN驱动安装签名验证不当导致权限提升  
**类型:** 权限提升  
**风险:** 高危，本地权限提升，允许低权限用户安装恶意驱动  
**投毒风险:** 10%  
**发现时间:** 2025-03-27  
**POC仓库:** [CVE-2024-7479_CVE-2024-7481](https://github.com/PeterGabaldon/CVE-2024-7479_CVE-2024-7481)  

---

### [CVE-2022-0944](CVE-2022-0944-shhrew_CVE-2022-0944.md) 🔴 ✅

**名称:** CVE-2022-0944 - SQLPad 模板注入导致RCE  
**类型:** 模板注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2022-0944](https://github.com/shhrew/CVE-2022-0944)  

---

### [CVE-2022-0944](CVE-2022-0944-FlojBoj_CVE-2022-0944.md) 🔴 ✅

**名称:** CVE-2022-0944-SQLPad-模板注入导致RCE  
**类型:** 模板注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2022-0944](https://github.com/FlojBoj/CVE-2022-0944)  

---

### [CVE-2022-0944](CVE-2022-0944-0xRoqeeb_sqlpad-rce-exploit-CVE-2022-0944.md) 🔴 ✅

**名称:** CVE-2022-0944-sqlpad-模板注入RCE  
**类型:** 模板注入导致远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-03-26  
**POC仓库:** [sqlpad-rce-exploit-CVE-2022-0944](https://github.com/0xRoqeeb/sqlpad-rce-exploit-CVE-2022-0944)  

---

### [CVE-2022-0944](CVE-2022-0944-Philip-Otter_CVE-2022-0944_RCE_Automation.md) 🔴 ✅

**名称:** CVE-2022-0944-sqlpad-TemplateInjection-RCE  
**类型:** 模板注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2022-0944_RCE_Automation](https://github.com/Philip-Otter/CVE-2022-0944_RCE_Automation)  

---

### [CVE-2022-0944](CVE-2022-0944-Robocopsita_CVE-2022-0944_RCE_POC.md) 🔴 ✅

**名称:** CVE-2022-0944-SQLPad-模板注入导致RCE  
**类型:** 模板注入导致RCE  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2022-0944_RCE_POC](https://github.com/Robocopsita/CVE-2022-0944_RCE_POC)  

---

### [CVE-2022-0944](CVE-2022-0944-toneillcodes_CVE-2022-0944.md) 🔴 ✅

**名称:** CVE-2022-0944-sqlpad-RCE  
**类型:** 模板注入导致远程代码执行  
**风险:** 高危，可导致完全控制服务器  
**投毒风险:** 1%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2022-0944](https://github.com/toneillcodes/CVE-2022-0944)  

---

### [CVE-2022-0944](CVE-2022-0944-0xDTC_SQLPad-6.10.0-Exploit-CVE-2022-0944.md) 🔴 ✅

**名称:** CVE-2022-0944 - SQLPad Template Injection RCE  
**类型:** 模板注入导致远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-03-26  
**POC仓库:** [SQLPad-6.10.0-Exploit-CVE-2022-0944](https://github.com/0xDTC/SQLPad-6.10.0-Exploit-CVE-2022-0944)  

---

### [CVE-2022-0944](CVE-2022-0944-Artemisxxx37_OverlayFS-PrivEsc-CVE-2022-0944.md)  ✅

**名称:** CVE-2022-0944 - SQLPad Template Injection RCE  
**类型:** 模板注入导致远程代码执行 (RCE)  
**风险:** 严重，可能导致完全系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-26  
**POC仓库:** [OverlayFS-PrivEsc-CVE-2022-0944](https://github.com/Artemisxxx37/OverlayFS-PrivEsc-CVE-2022-0944)  

---

### [CVE-2025-2783](CVE-2025-2783-raulchung_CVE-2025-2783.md) 🔴 

**名称:** CVE-2025-2783 Google Chrome Mojo 沙箱逃逸  
**类型:** 沙箱逃逸  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 95%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2025-2783](https://github.com/raulchung/CVE-2025-2783)  

---

### [CVE-2025-30208](CVE-2025-30208-marino-admin_Vite-CVE-2025-30208-Scanner.md) 🟡 ✅

**名称:** CVE-2025-30208-Vite-文件读取漏洞  
**类型:** 文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-26  
**POC仓库:** [Vite-CVE-2025-30208-Scanner](https://github.com/marino-admin/Vite-CVE-2025-30208-Scanner)  

---

### [CVE-2025-50000](CVE-2025-50000-NotItsSixtyN3in_CVE-2025-50000.md) 🔴 ✅

**名称:** CVE-2025-50000-CoPilot-用户ID混淆  
**类型:** 认证绕过/信息泄露  
**风险:** 高危，可能导致信息泄露和拒绝服务攻击  
**投毒风险:** 0%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2025-50000](https://github.com/NotItsSixtyN3in/CVE-2025-50000)  

---

### [CVE-2025-30208](CVE-2025-30208-YuanBenSir_CVE-2025-30208_POC.md) 🟡 ✅

**名称:** CVE-2025-30208-Vite-文件读取漏洞  
**类型:** 文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2025-30208_POC](https://github.com/YuanBenSir/CVE-2025-30208_POC)  

---

### [CVE-2025-29927](CVE-2025-29927-aleongx_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-权限绕过  
**类型:** 权限绕过  
**风险:** 高危，可能导致未授权访问敏感数据或执行未授权操作  
**投毒风险:** 0%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2025-29927](https://github.com/aleongx/CVE-2025-29927)  

---

### [CVE-2025-29927](CVE-2025-29927-gotcadumitru_test-cve-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-AuthorizationBypass  
**类型:** 权限绕过  
**风险:** 高危，可能导致未经授权的访问和数据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-26  
**POC仓库:** [test-cve-2025-29927](https://github.com/gotcadumitru/test-cve-2025-29927)  

---

### [CVE-2025-30208](CVE-2025-30208-xaitx_CVE-2025-30208.md) 🟡 ✅

**名称:** CVE-2025-30208-Vite-文件读取漏洞  
**类型:** 文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2025-30208](https://github.com/xaitx/CVE-2025-30208)  

---

### [CVE-2025-30208](CVE-2025-30208-kk12-30_CVE-2025-30208.md) 🟡 ✅

**名称:** CVE-2025-30208 - Vite 文件读取漏洞  
**类型:** 文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2025-30208](https://github.com/kk12-30/CVE-2025-30208)  

---

### [CVE-2025-1974](CVE-2025-1974-hi-unc1e_CVE-2025-1974-poc.md) 🔴 ✅

**名称:** CVE-2025-1974 - Ingress-nginx Admission Controller RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，CVSS 9.8 (Critical)，可能导致集群权限接管，敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2025-1974-poc](https://github.com/hi-unc1e/CVE-2025-1974-poc)  

---

### [CVE-2025-29927](CVE-2025-29927-Slvignesh05_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js中间件绕过  
**类型:** 权限绕过  
**风险:** 高危，可能导致未经授权的访问、数据泄露或篡改  
**投毒风险:** 5%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2025-29927](https://github.com/Slvignesh05/CVE-2025-29927)  

---

### [CVE-2025-1974](CVE-2025-1974-m-q-t_ingressnightmare-detection-poc.md)  ✅

**名称:** CVE-2025-1974 - Ingress-nginx Admission Controller RCE Escalation  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，未经身份验证的攻击者可能在 Ingress Nginx 控制器的上下文中执行任意代码，导致泄露集群范围内的 Secrets。  
**投毒风险:** 0%  
**发现时间:** 2025-03-26  
**POC仓库:** [ingressnightmare-detection-poc](https://github.com/m-q-t/ingressnightmare-detection-poc)  

---

### [CVE-2025-30208](CVE-2025-30208-ThumpBo_CVE-2025-30208-EXP.md) 🟡 ✅

**名称:** CVE-2025-30208-vite-文件读取  
**类型:** 信息泄露/文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2025-30208-EXP](https://github.com/ThumpBo/CVE-2025-30208-EXP)  

---

### [CVE-2025-30567](CVE-2025-30567-Oyst3r1ng_CVE-2025-30567.md) 🔴 ✅

**名称:** CVE-2025-30567-WP01-任意文件下载  
**类型:** 路径遍历/任意文件下载  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2025-30567](https://github.com/Oyst3r1ng/CVE-2025-30567)  

---

### [CVE-2025-1974](CVE-2025-1974-zwxxb_CVE-2025-1974.md)  ✅

**名称:** CVE-2025-1974 - Ingress Nginx Controller RCE  
**类型:** 远程代码执行  
**风险:** 严重，可能导致集群接管  
**投毒风险:** 5%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2025-1974](https://github.com/zwxxb/CVE-2025-1974)  

---

### [CVE-2024-4956](CVE-2024-4956-xungzzz_CVE-2024-4956.md) 🔴 ✅

**名称:** CVE-2024-4956-Nexus Repository 3-Path Traversal  
**类型:** Path Traversal  
**风险:** 高危，可能导致敏感文件泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2024-4956](https://github.com/xungzzz/CVE-2024-4956)  

---

### [CVE-2024-4956](CVE-2024-4956-erickfernandox_CVE-2024-4956.md) 🔴 ✅

**名称:** CVE-2024-4956 - Sonatype Nexus Repository 3 Path Traversal  
**类型:** 路径遍历  
**风险:** 高危，可读取任意系统文件  
**投毒风险:** 5%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2024-4956](https://github.com/erickfernandox/CVE-2024-4956)  

---

### [CVE-2024-4956](CVE-2024-4956-gmh5225_CVE-2024-4956.md) 🔴 ✅

**名称:** CVE-2024-4956 - Sonatype Nexus Repository 3 Path Traversal  
**类型:** 路径遍历  
**风险:** 高危，允许未经身份验证的攻击者读取系统文件  
**投毒风险:** 0%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2024-4956](https://github.com/gmh5225/CVE-2024-4956)  

---

### [CVE-2024-4956](CVE-2024-4956-banditzCyber0x_CVE-2024-4956.md) 🔴 ✅

**名称:** CVE-2024-4956-Nexus Repository Manager 3-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2024-4956](https://github.com/banditzCyber0x/CVE-2024-4956)  

---

### [CVE-2024-4956](CVE-2024-4956-thinhap_CVE-2024-4956-PoC.md) 🔴 ✅

**名称:** CVE-2024-4956-Sonatype Nexus Repository 3-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可读取系统文件  
**投毒风险:** 0%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2024-4956-PoC](https://github.com/thinhap/CVE-2024-4956-PoC)  

---

### [CVE-2024-4956](CVE-2024-4956-TypicalModMaker_CVE-2024-4956.md) 🔴 ✅

**名称:** CVE-2024-4956-Sonatype Nexus Repository 3-Path Traversal  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2024-4956](https://github.com/TypicalModMaker/CVE-2024-4956)  

---

### [CVE-2024-4956](CVE-2024-4956-GoatSecurity_CVE-2024-4956.md) 🔴 ✅

**名称:** CVE-2024-4956-Nexus Repository Manager 3-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感文件泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2024-4956](https://github.com/GoatSecurity/CVE-2024-4956)  

---

### [CVE-2024-4956](CVE-2024-4956-Praison001_CVE-2024-4956-Sonatype-Nexus-Repository-Manager.md) 🔴 ✅

**名称:** CVE-2024-4956-Sonatype Nexus Repository Manager-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2024-4956-Sonatype-Nexus-Repository-Manager](https://github.com/Praison001/CVE-2024-4956-Sonatype-Nexus-Repository-Manager)  

---

### [CVE-2024-4956](CVE-2024-4956-Cappricio-Securities_CVE-2024-4956.md) 🔴 ✅

**名称:** CVE-2024-4956-Nexus Repository Manager 3-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2024-4956](https://github.com/Cappricio-Securities/CVE-2024-4956)  

---

### [CVE-2024-4956](CVE-2024-4956-JolyIrsb_CVE-2024-4956.md) 🔴 ✅

**名称:** CVE-2024-4956-Sonatype Nexus Repository 3-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可读取任意文件  
**投毒风险:** 10%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2024-4956](https://github.com/JolyIrsb/CVE-2024-4956)  

---

### [CVE-2024-4956](CVE-2024-4956-UMASANKAR-MG_Path-Traversal-CVE-2024-4956.md) 🔴 ✅

**名称:** CVE-2024-4956 - Sonatype Nexus Repository 3 - 路径遍历  
**类型:** 路径遍历  
**风险:** 高危，允许未经身份验证的攻击者读取系统文件  
**投毒风险:** 30%  
**发现时间:** 2025-03-26  
**POC仓库:** [Path-Traversal-CVE-2024-4956](https://github.com/UMASANKAR-MG/Path-Traversal-CVE-2024-4956)  

---

### [CVE-2024-4956](CVE-2024-4956-ifconfig-me_CVE-2024-4956-Bulk-Scanner.md) 🔴 ✅

**名称:** CVE-2024-4956 Sonatype Nexus Repository 3 Path Traversal  
**类型:** 路径遍历  
**风险:** 高危，允许未经身份验证的攻击者读取系统文件  
**投毒风险:** 1%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2024-4956-Bulk-Scanner](https://github.com/ifconfig-me/CVE-2024-4956-Bulk-Scanner)  

---

### [CVE-2024-4956](CVE-2024-4956-An00bRektn_shirocrack.md) 🔴 ✅

**名称:** CVE-2024-4956-Sonatype Nexus Repository Manager 3-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-26  
**POC仓库:** [shirocrack](https://github.com/An00bRektn/shirocrack)  

---

### [CVE-2024-4956](CVE-2024-4956-fin3ss3g0d_CVE-2024-4956.md) 🔴 ✅

**名称:** CVE-2024-4956 - Sonatype Nexus Repository 3 Path Traversal  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2024-4956](https://github.com/fin3ss3g0d/CVE-2024-4956)  

---

### [CVE-2024-4956](CVE-2024-4956-verylazytech_CVE-2024-4956.md) 🔴 ✅

**名称:** CVE-2024-4956-Sonatype Nexus Repository 3-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，允许未经身份验证的攻击者读取系统文件  
**投毒风险:** 0%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2024-4956](https://github.com/verylazytech/CVE-2024-4956)  

---

### [CVE-2024-4956](CVE-2024-4956-XiaomingX_cve-2024-4956.md) 🔴 ✅

**名称:** CVE-2024-4956-Sonatype Nexus Repository 3-Path Traversal  
**类型:** Path Traversal  
**风险:** 高危，可能导致敏感文件泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-26  
**POC仓库:** [cve-2024-4956](https://github.com/XiaomingX/cve-2024-4956)  

---

### [CVE-2024-4956](CVE-2024-4956-art-of-defence_CVE-2024-4956.md) 🔴 ✅

**名称:** CVE-2024-4956-Nexus Repository Manager 3-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感文件泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2024-4956](https://github.com/art-of-defence/CVE-2024-4956)  

---

### [CVE-2025-30216](CVE-2025-30216-oliviaisntcringe_CVE-2025-30216-PoC.md) 🔴 ✅

**名称:** CVE-2025-30216: CryptoLib Heap Overflow in Crypto_TM_ProcessSecurity  
**类型:** 堆溢出  
**风险:** 高危，可能导致任意代码执行或系统不稳定  
**投毒风险:** 5%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2025-30216-PoC](https://github.com/oliviaisntcringe/CVE-2025-30216-PoC)  

---

### [CVE-2025-29927](CVE-2025-29927-Eve-SatOrU_POC-CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js 中间件授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问、数据泄露、XSS攻击和缓存投毒  
**投毒风险:** 5%  
**发现时间:** 2025-03-26  
**POC仓库:** [POC-CVE-2025-29927](https://github.com/Eve-SatOrU/POC-CVE-2025-29927)  

---

### [CVE-2025-30208](CVE-2025-30208-xuemian168_CVE-2025-30208.md) 🟡 ✅

**名称:** CVE-2025-30208-Vite-文件读取  
**类型:** 文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2025-30208](https://github.com/xuemian168/CVE-2025-30208)  

---

### [CVE-2025-1974](CVE-2025-1974-dttuss_IngressNightmare-RCE-POC.md)  ✅

**名称:** CVE-2025-1974-ingress-nginx-RCE  
**类型:** 远程代码执行  
**风险:** 严重，可能导致集群接管和敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-26  
**POC仓库:** [IngressNightmare-RCE-POC](https://github.com/dttuss/IngressNightmare-RCE-POC)  

---

### [CVE-2025-22953](CVE-2025-22953-maliktawfiq_CVE-2025-22953.md) 🔴 

**名称:** CVE-2025-22953 – Epicor HCM Unauthenticated Blind SQL Injection  
**类型:** Unauthenticated Blind SQL Injection  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2025-22953](https://github.com/maliktawfiq/CVE-2025-22953)  

---

### [CVE-2025-1974](CVE-2025-1974-justmorpheus_IngressNightmare-CVE-2025-1974.md)  ✅

**名称:** CVE-2025-1974-ingress-nginx-RCE  
**类型:** 远程代码执行(RCE)  
**风险:** 严重，未经身份验证的攻击者可以通过 Pod 网络实现任意代码执行，可能导致集群范围内的 Secrets 泄露。  
**投毒风险:** 20%  
**发现时间:** 2025-03-26  
**POC仓库:** [IngressNightmare-CVE-2025-1974](https://github.com/justmorpheus/IngressNightmare-CVE-2025-1974)  

---

### [CVE-2023-45878](CVE-2023-45878-nrazv_CVE-2023-45878.md) 🔴 ✅

**名称:** CVE-2023-45878-GibbonEdu-任意文件写入  
**类型:** 任意文件写入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2023-45878](https://github.com/nrazv/CVE-2023-45878)  

---

### [CVE-2025-1974](CVE-2025-1974-Esonhugh_nginxnightmare.md)  ✅

**名称:** CVE-2025-1974-ingress-nginx-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，未经身份验证的攻击者可以访问 Pod 网络，并在 ingress-nginx 控制器的上下文中执行任意代码，可能导致集群范围内的 Secrets 泄露。  
**投毒风险:** 1%  
**发现时间:** 2025-03-26  
**POC仓库:** [nginxnightmare](https://github.com/Esonhugh/nginxnightmare)  

---

### [CVE-2018-15473](CVE-2018-15473-0xNehru_ssh_Enum_vaild.md) 🟡 ✅

**名称:** CVE-2018-15473-OpenSSH用户名枚举  
**类型:** 用户名枚举  
**风险:** 中危，泄露有效的用户名信息，为后续攻击提供便利  
**投毒风险:** 10%  
**发现时间:** 2025-03-26  
**POC仓库:** [ssh_Enum_vaild](https://github.com/0xNehru/ssh_Enum_vaild)  

---

### [CVE-2024-50492](CVE-2024-50492-Nxploited_CVE-2024-50492.md) 🔴 ✅

**名称:** CVE-2024-50492-ScottCart-代码注入  
**类型:** 代码注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2024-50492](https://github.com/Nxploited/CVE-2024-50492)  

---

### [CVE-2024-12252](CVE-2024-12252-RandomRobbieBF_CVE-2024-12252.md) 🔴 ✅

**名称:** CVE-2024-12252-SEO LAT Auto Post-文件覆盖RCE  
**类型:** 文件覆盖/远程代码执行  
**风险:** 高危，未经身份验证的攻击者可以覆盖插件文件并执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2024-12252](https://github.com/RandomRobbieBF/CVE-2024-12252)  

---

### [CVE-2024-12252](CVE-2024-12252-Nxploited_CVE-2024-12252.md) 🔴 ✅

**名称:** CVE-2024-12252-SEO LAT Auto Post-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未授权用户通过文件覆盖实现远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-26  
**POC仓库:** [CVE-2024-12252](https://github.com/Nxploited/CVE-2024-12252)  

---

### [CVE-2025-29927](CVE-2025-29927-kOaDT_poc-cve-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js中间件绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未经授权的访问  
**投毒风险:** 5%  
**发现时间:** 2025-03-26  
**POC仓库:** [poc-cve-2025-29927](https://github.com/kOaDT/poc-cve-2025-29927)  

---

### [CVE-2025-29927](CVE-2025-29927-yugo-eliatrope_test-cve-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-Authorization Bypass  
**类型:** Authorization Bypass  
**风险:** 高危，可能导致未经授权的访问和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-26  
**POC仓库:** [test-cve-2025-29927](https://github.com/yugo-eliatrope/test-cve-2025-29927)  

---

### [CVE-2024-21413](CVE-2024-21413-r00tb1t_CVE-2024-21413-POC.md)  ✅

**名称:** CVE-2024-21413 - Microsoft Outlook远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，无需用户交互即可远程执行代码，可能导致完全控制受影响的系统。  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2024-21413-POC](https://github.com/r00tb1t/CVE-2024-21413-POC)  

---

### [CVE-2024-21413](CVE-2024-21413-duy-31_CVE-2024-21413.md)  ✅

**名称:** CVE-2024-21413 Microsoft Outlook 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，无需用户交互即可远程执行代码  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2024-21413](https://github.com/duy-31/CVE-2024-21413)  

---

### [CVE-2024-21413](CVE-2024-21413-MSeymenD_CVE-2024-21413.md) 🔴 ✅

**名称:** CVE-2024-21413 - Microsoft Outlook 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许攻击者在目标系统上执行任意代码，可能导致完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2024-21413](https://github.com/MSeymenD/CVE-2024-21413)  

---

### [CVE-2024-21413](CVE-2024-21413-xaitax_CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability.md) 🔴 ✅

**名称:** CVE-2024-21413 - Microsoft Outlook 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的攻击者可以通过发送特制的电子邮件，在受害者系统上执行任意代码。  
**投毒风险:** 5%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability](https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability)  

---

### [CVE-2024-21413](CVE-2024-21413-Mdusmandasthaheer_CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability.md) 🔴 ✅

**名称:** CVE-2024-21413-Microsoft Outlook Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和敏感信息泄露（NTLM凭据）  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability](https://github.com/Mdusmandasthaheer/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability)  

---

### [CVE-2024-21413](CVE-2024-21413-ahmetkarakayaoffical_CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability.md)  ✅

**名称:** CVE-2024-21413-Microsoft Outlook Remote Code Execution Vulnerability  
**类型:** 远程代码执行  
**风险:** 严重，允许攻击者在目标机器上执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability](https://github.com/ahmetkarakayaoffical/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability)  

---

### [CVE-2024-21413](CVE-2024-21413-dshabani96_CVE-2024-21413.md) 🔴 ✅

**名称:** CVE-2024-21413 - Microsoft Outlook 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统权限获取  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2024-21413](https://github.com/dshabani96/CVE-2024-21413)  

---

### [CVE-2024-21413](CVE-2024-21413-CMNatic_CVE-2024-21413.md) 🔴 ✅

**名称:** CVE-2024-21413-Microsoft Outlook远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在受害者机器上执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2024-21413](https://github.com/CMNatic/CVE-2024-21413)  

---

### [CVE-2024-21413](CVE-2024-21413-X-Projetion_CVE-2024-21413-Microsoft-Outlook-RCE-Exploit.md) 🔴 ✅

**名称:** CVE-2024-21413-Microsoft-Outlook-RCE  
**类型:** 远程代码执行  
**风险:** 高危，无需用户交互即可远程执行任意代码  
**投毒风险:** 20%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2024-21413-Microsoft-Outlook-RCE-Exploit](https://github.com/X-Projetion/CVE-2024-21413-Microsoft-Outlook-RCE-Exploit)  

---

### [CVE-2024-21413](CVE-2024-21413-th3Hellion_CVE-2024-21413.md) 🔴 ✅

**名称:** CVE-2024-21413 - Microsoft Outlook Remote Code Execution  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许攻击者在目标系统上执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2024-21413](https://github.com/th3Hellion/CVE-2024-21413)  

---

### [CVE-2024-21413](CVE-2024-21413-ShubhamKanhere307_CVE-2024-21413.md) 🔴 ✅

**名称:** CVE-2024-21413-Microsoft Outlook远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，CVSS评分9.8，允许远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2024-21413](https://github.com/ShubhamKanhere307/CVE-2024-21413)  

---

### [CVE-2024-21413](CVE-2024-21413-olebris_CVE-2024-21413.md) 🔴 ✅

**名称:** CVE-2024-21413-Microsoft Outlook 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在受害者机器上执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2024-21413](https://github.com/olebris/CVE-2024-21413)  

---

### [CVE-2024-21413](CVE-2024-21413-DerZiad_CVE-2024-21413.md) 🔴 ✅

**名称:** CVE-2024-21413-Microsoft Outlook RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在目标系统上执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2024-21413](https://github.com/DerZiad/CVE-2024-21413)  

---

### [CVE-2024-21413](CVE-2024-21413-Redfox-Secuirty_Unveiling-Moniker-Link-CVE-2024-21413-Navigating-the-Latest-Cybersecurity-Landscape.md) 🔴 ✅

**名称:** CVE-2024-21413 Microsoft Outlook 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-25  
**POC仓库:** [Unveiling-Moniker-Link-CVE-2024-21413-Navigating-the-Latest-Cybersecurity-Landscape](https://github.com/Redfox-Secuirty/Unveiling-Moniker-Link-CVE-2024-21413-Navigating-the-Latest-Cybersecurity-Landscape)  

---

### [CVE-2024-21413](CVE-2024-21413-D1se0_CVE-2024-21413-Vulnerabilidad-Outlook-LAB.md) 🔴 ✅

**名称:** CVE-2024-21413 - Microsoft Outlook 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致信息泄露、远程代码执行和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2024-21413-Vulnerabilidad-Outlook-LAB](https://github.com/D1se0/CVE-2024-21413-Vulnerabilidad-Outlook-LAB)  

---

### [CVE-2024-21413](CVE-2024-21413-ThemeHackers_CVE-2024-21413.md)  ✅

**名称:** CVE-2024-21413-Microsoft Outlook远程代码执行  
**类型:** 远程代码执行  
**风险:** 严重，攻击者无需用户交互即可在目标系统上执行任意代码。  
**投毒风险:** 30%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2024-21413](https://github.com/ThemeHackers/CVE-2024-21413)  

---

### [CVE-2024-21413](CVE-2024-21413-Cyber-Trambon_CVE-2024-21413-exploit.md)  ✅

**名称:** CVE-2024-21413 - Microsoft Outlook 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致信息泄露、NTLM凭据窃取和远程代码执行  
**投毒风险:** 30%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2024-21413-exploit](https://github.com/Cyber-Trambon/CVE-2024-21413-exploit)  

---

### [CVE-2024-21413](CVE-2024-21413-ArtemCyberLab_Project-NTLM-Hash-Capture-and-Phishing-Email-Exploitation-for-CVE-2024-21413.md) 🔴 ✅

**名称:** CVE-2024-21413 Microsoft Outlook Remote Code Execution Vulnerability  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [Project-NTLM-Hash-Capture-and-Phishing-Email-Exploitation-for-CVE-2024-21413](https://github.com/ArtemCyberLab/Project-NTLM-Hash-Capture-and-Phishing-Email-Exploitation-for-CVE-2024-21413)  

---

### [CVE-2025-29927](CVE-2025-29927-maronnjapan_claude-create-CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927 - Next.js Middleware 授权绕过漏洞  
**类型:** 授权绕过  
**风险:** 高危，可能导致未经授权的访问和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [claude-create-CVE-2025-29927](https://github.com/maronnjapan/claude-create-CVE-2025-29927)  

---

### [CVE-2024-4367](CVE-2024-4367-Masamuneee_CVE-2024-4367-Analysis.md) 🔴 ✅

**名称:** CVE-2024-4367: PDF.js 任意JavaScript执行漏洞  
**类型:** 任意JavaScript执行  
**风险:** 高危，可能导致XSS攻击，窃取用户数据，甚至远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2024-4367-Analysis](https://github.com/Masamuneee/CVE-2024-4367-Analysis)  

---

### [CVE-2018-15473](CVE-2018-15473-WildfootW_CVE-2018-15473_OpenSSH_7.7.md) 🟡 ✅

**名称:** CVE-2018-15473 OpenSSH 用户枚举漏洞  
**类型:** 用户枚举  
**风险:** 中危，可为后续攻击提供用户名信息  
**投毒风险:** 5%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2018-15473_OpenSSH_7.7](https://github.com/WildfootW/CVE-2018-15473_OpenSSH_7.7)  

---

### [CVE-2018-15473](CVE-2018-15473-66quentin_shodan-CVE-2018-15473.md) 🟡 ✅

**名称:** CVE-2018-15473 OpenSSH 用户枚举  
**类型:** 用户枚举  
**风险:** 中危，可能导致信息泄露，为后续攻击提供便利  
**投毒风险:** 5%  
**发现时间:** 2025-03-25  
**POC仓库:** [shodan-CVE-2018-15473](https://github.com/66quentin/shodan-CVE-2018-15473)  

---

### [CVE-2025-29972](CVE-2025-29972-ThemeHackers_CVE-2025-29972.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-中间件绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问敏感信息，例如用户数据、管理页面等。  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2025-29972](https://github.com/ThemeHackers/CVE-2025-29972)  

---

### [CVE-2024-4367](CVE-2024-4367-s4vvysec_CVE-2024-4367-POC.md) 🔴 ✅

**名称:** CVE-2024-4367 PDF.js 任意JavaScript执行  
**类型:** 任意JavaScript执行  
**风险:** 高危，可能导致信息泄露，跨站脚本攻击 (XSS)，或在用户上下文中执行恶意代码  
**投毒风险:** 0%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2024-4367-POC](https://github.com/s4vvysec/CVE-2024-4367-POC)  

---

### [CVE-2024-4367](CVE-2024-4367-spaceraccoon_detect-cve-2024-4367.md) 🟡 ✅

**名称:** CVE-2024-4367-PDF.js-任意JavaScript执行  
**类型:** 任意JavaScript执行  
**风险:** 中危，可能导致敏感信息泄露或跨站脚本攻击  
**投毒风险:** 0%  
**发现时间:** 2025-03-25  
**POC仓库:** [detect-cve-2024-4367](https://github.com/spaceraccoon/detect-cve-2024-4367)  

---

### [CVE-2024-4367](CVE-2024-4367-avalahEE_pdfjs_disable_eval.md) 🔴 ✅

**名称:** CVE-2024-4367-Firefox-PDF.js任意JavaScript执行  
**类型:** 任意JavaScript执行  
**风险:** 高危，允许在PDF.js上下文中执行任意JavaScript代码  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [pdfjs_disable_eval](https://github.com/avalahEE/pdfjs_disable_eval)  

---

### [CVE-2024-4367](CVE-2024-4367-LOURC0D3_CVE-2024-4367-PoC.md) 🔴 ✅

**名称:** CVE-2024-4367 - PDF.js 任意JavaScript代码执行  
**类型:** 任意JavaScript代码执行  
**风险:** 高危，允许在PDF.js上下文中执行任意JavaScript代码，可能导致信息泄露，远程代码执行等。  
**投毒风险:** 5%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2024-4367-PoC](https://github.com/LOURC0D3/CVE-2024-4367-PoC)  

---

### [CVE-2024-4367](CVE-2024-4367-Zombie-Kaiser_cve-2024-4367-PoC-fixed.md) 🔴 ✅

**名称:** CVE-2024-4367-Mozilla-PDF.js任意JavaScript执行  
**类型:** 任意JavaScript执行  
**风险:** 高危，可能导致敏感信息泄露和潜在的远程代码执行（在PDF.js上下文中）  
**投毒风险:** 0%  
**发现时间:** 2025-03-25  
**POC仓库:** [cve-2024-4367-PoC-fixed](https://github.com/Zombie-Kaiser/cve-2024-4367-PoC-fixed)  

---

### [CVE-2024-4367](CVE-2024-4367-UnHackerEnCapital_PDFernetRemotelo.md) 🔴 ✅

**名称:** CVE-2024-4367 & CVE-2023-38831 PDFernet Remotelo  
**类型:** PDF.js 字体处理类型检查缺失导致任意JavaScript执行 & WinRAR命令执行  
**风险:** 高危，允许攻击者远程执行任意命令  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [PDFernetRemotelo](https://github.com/UnHackerEnCapital/PDFernetRemotelo)  

---

### [CVE-2024-4367](CVE-2024-4367-snyk-labs_pdfjs-vuln-demo.md) 🔴 ✅

**名称:** CVE-2024-4367 - Mozilla Firefox, Firefox ESR, Thunderbird PDF.js JavaScript Execution  
**类型:** JavaScript 代码执行  
**风险:** 高危，允许在 PDF.js 上下文中执行任意 JavaScript 代码  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [pdfjs-vuln-demo](https://github.com/snyk-labs/pdfjs-vuln-demo)  

---

### [CVE-2024-4367](CVE-2024-4367-Scivous_CVE-2024-4367-npm.md) 🔴 ✅

**名称:** CVE-2024-4367-PDF.js字体处理类型检查缺失导致任意JavaScript执行  
**类型:** 任意JavaScript执行  
**风险:** 高危，允许在PDF.js上下文中执行任意JavaScript代码  
**投毒风险:** 5%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2024-4367-npm](https://github.com/Scivous/CVE-2024-4367-npm)  

---

### [CVE-2024-4367](CVE-2024-4367-pedrochalegre7_CVE-2024-4367-pdf-sample.md) 🔴 ✅

**名称:** CVE-2024-4367-Firefox-PDF.js任意JavaScript执行  
**类型:** 任意JavaScript执行  
**风险:** 高危，允许在PDF.js上下文中执行任意JavaScript代码  
**投毒风险:** 5%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2024-4367-pdf-sample](https://github.com/pedrochalegre7/CVE-2024-4367-pdf-sample)  

---

### [CVE-2024-4367](CVE-2024-4367-clarkio_pdfjs-vuln-demo.md) 🔴 ✅

**名称:** CVE-2024-4367-PDF.js-JavaScript执行  
**类型:** JavaScript执行  
**风险:** 高危，允许在PDF.js上下文中执行任意JavaScript代码  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [pdfjs-vuln-demo](https://github.com/clarkio/pdfjs-vuln-demo)  

---

### [CVE-2024-4367](CVE-2024-4367-exfil0_WEAPONIZING-CVE-2024-4367.md) 🔴 ✅

**名称:** CVE-2024-4367-PDF.js-任意JavaScript代码执行  
**类型:** 任意JavaScript代码执行  
**风险:** 高危，可能导致数据泄露、XSS或RCE  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [WEAPONIZING-CVE-2024-4367](https://github.com/exfil0/WEAPONIZING-CVE-2024-4367)  

---

### [CVE-2024-4367](CVE-2024-4367-inpentest_CVE-2024-4367-PoC.md) 🔴 ✅

**名称:** CVE-2024-4367-PDF.js 任意JavaScript执行  
**类型:** 任意JavaScript执行  
**风险:** 高危，可能导致信息泄露、会话劫持等  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2024-4367-PoC](https://github.com/inpentest/CVE-2024-4367-PoC)  

---

### [CVE-2025-1974](CVE-2025-1974-yanmarques_CVE-2025-1974.md)  

**名称:** CVE-2025-1974-ingress-nginx-RCE  
**类型:** 远程代码执行  
**风险:** 严重，可能导致集群范围内的权限提升和数据泄露  
**投毒风险:** 20%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2025-1974](https://github.com/yanmarques/CVE-2025-1974)  

---

### [CVE-2018-15473](CVE-2018-15473-coollce_CVE-2018-15473_burte.md) 🟡 ✅

**名称:** CVE-2018-15473 OpenSSH 用户名枚举  
**类型:** 用户名枚举  
**风险:** 中危，可辅助进一步攻击  
**投毒风险:** 0%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2018-15473_burte](https://github.com/coollce/CVE-2018-15473_burte)  

---

### [CVE-2018-15473](CVE-2018-15473-Dirty-Racoon_CVE-2018-15473-py3.md) 🟡 ✅

**名称:** CVE-2018-15473 OpenSSH 用户枚举漏洞  
**类型:** 用户枚举  
**风险:** 中危，允许攻击者枚举有效的用户名，为后续攻击提供信息。  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2018-15473-py3](https://github.com/Dirty-Racoon/CVE-2018-15473-py3)  

---

### [CVE-2018-15473](CVE-2018-15473-pyperanger_CVE-2018-15473_exploit.md) 🟡 ✅

**名称:** CVE-2018-15473 - OpenSSH 用户枚举  
**类型:** 用户枚举  
**风险:** 中危，泄露用户名信息，增加暴力破解或社工攻击的成功率  
**投毒风险:** 0%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2018-15473_exploit](https://github.com/pyperanger/CVE-2018-15473_exploit)  

---

### [CVE-2018-15473](CVE-2018-15473-cved-sources_cve-2018-15473.md) 🟡 ✅

**名称:** CVE-2018-15473-OpenSSH-用户枚举  
**类型:** 用户枚举  
**风险:** 中危，允许攻击者枚举目标系统上的有效用户名  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [cve-2018-15473](https://github.com/cved-sources/cve-2018-15473)  

---

### [CVE-2018-15473](CVE-2018-15473-MrDottt_CVE-2018-15473.md) 🟡 ✅

**名称:** CVE-2018-15473 OpenSSH用户名枚举漏洞  
**类型:** 用户名枚举  
**风险:** 中危，可为后续攻击提供信息  
**投毒风险:** 0%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2018-15473](https://github.com/MrDottt/CVE-2018-15473)  

---

### [CVE-2018-15473](CVE-2018-15473-Moon1705_easy_security.md) 🟡 ✅

**名称:** CVE-2018-15473-OpenSSH-用户名枚举  
**类型:** 用户名枚举  
**风险:** 中危，可为后续攻击提供信息  
**投毒风险:** 0%  
**发现时间:** 2025-03-25  
**POC仓库:** [easy_security](https://github.com/Moon1705/easy_security)  

---

### [CVE-2018-15473](CVE-2018-15473-Wh1t3Fox_cve-2018-15473.md) 🟡 ✅

**名称:** CVE-2018-15473-OpenSSH用户名枚举  
**类型:** 用户名枚举  
**风险:** 中危，可作为攻击链的一部分  
**投毒风险:** 0%  
**发现时间:** 2025-03-25  
**POC仓库:** [cve-2018-15473](https://github.com/Wh1t3Fox/cve-2018-15473)  

---

### [CVE-2018-15473](CVE-2018-15473-0xrobiul_CVE-2018-15473.md) 🟡 ✅

**名称:** CVE-2018-15473 OpenSSH 用户名枚举漏洞  
**类型:** 用户名枚举  
**风险:** 中危，泄露有效的用户名信息，为后续的暴力破解或其他攻击提供信息。  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2018-15473](https://github.com/0xrobiul/CVE-2018-15473)  

---

### [CVE-2018-15473](CVE-2018-15473-philippedixon_CVE-2018-15473.md) 🟡 ✅

**名称:** CVE-2018-15473 - OpenSSH Username Enumeration  
**类型:** 用户名枚举  
**风险:** 中危，允许攻击者枚举目标系统上的有效用户名。  
**投毒风险:** 5%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2018-15473](https://github.com/philippedixon/CVE-2018-15473)  

---

### [CVE-2018-15473](CVE-2018-15473-sergiovks_SSH-User-Enum-Python3-CVE-2018-15473.md) 🟡 ✅

**名称:** CVE-2018-15473-OpenSSH用户名枚举  
**类型:** 用户名枚举  
**风险:** 中危，可用于后续的暴力破解或其他攻击  
**投毒风险:** 0%  
**发现时间:** 2025-03-25  
**POC仓库:** [SSH-User-Enum-Python3-CVE-2018-15473](https://github.com/sergiovks/SSH-User-Enum-Python3-CVE-2018-15473)  

---

### [CVE-2018-15473](CVE-2018-15473-Anonimo501_ssh_enum_users_CVE-2018-15473.md) 🟡 ✅

**名称:** CVE-2018-15473-OpenSSH-用户枚举  
**类型:** 用户枚举  
**风险:** 中危，允许攻击者枚举目标系统上的有效用户名  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [ssh_enum_users_CVE-2018-15473](https://github.com/Anonimo501/ssh_enum_users_CVE-2018-15473)  

---

### [CVE-2018-15473](CVE-2018-15473-GaboLC98_userenum-CVE-2018-15473.md) 🟡 ✅

**名称:** CVE-2018-15473 - OpenSSH 用户枚举漏洞  
**类型:** 用户枚举  
**风险:** 中危，允许攻击者枚举目标系统上的有效用户名  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [userenum-CVE-2018-15473](https://github.com/GaboLC98/userenum-CVE-2018-15473)  

---

### [CVE-2018-15473](CVE-2018-15473-Sait-Nuri_CVE-2018-15473.md) 🟡 ✅

**名称:** CVE-2018-15473 OpenSSH 用户枚举漏洞  
**类型:** 用户枚举  
**风险:** 中危，可为后续攻击提供信息  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2018-15473](https://github.com/Sait-Nuri/CVE-2018-15473)  

---

### [CVE-2018-15473](CVE-2018-15473-4xolotl_CVE-2018-15473.md) 🟡 ✅

**名称:** CVE-2018-15473-OpenSSH用户名枚举漏洞  
**类型:** 用户名枚举  
**风险:** 中危，允许攻击者枚举系统上的有效用户名  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2018-15473](https://github.com/4xolotl/CVE-2018-15473)  

---

### [CVE-2018-15473](CVE-2018-15473-epi052_cve-2018-15473.md) 🟡 ✅

**名称:** CVE-2018-15473 - OpenSSH 用户枚举漏洞  
**类型:** 用户枚举  
**风险:** 中危，允许攻击者枚举有效的用户名  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [cve-2018-15473](https://github.com/epi052/cve-2018-15473)  

---

### [CVE-2018-15473](CVE-2018-15473-yZ1337_CVE-2018-15473.md) 🟡 ✅

**名称:** CVE-2018-15473-OpenSSH 用户枚举  
**类型:** 用户枚举  
**风险:** 中危，信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2018-15473](https://github.com/yZ1337/CVE-2018-15473)  

---

### [CVE-2018-15473](CVE-2018-15473-Rhynorater_CVE-2018-15473-Exploit.md) 🟡 ✅

**名称:** CVE-2018-15473-OpenSSH用户名枚举  
**类型:** 用户名枚举  
**风险:** 中危，可能泄露系统用户名信息，为后续攻击提供便利  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2018-15473-Exploit](https://github.com/Rhynorater/CVE-2018-15473-Exploit)  

---

### [CVE-2018-15473](CVE-2018-15473-mclbn_docker-cve-2018-15473.md) 🟡 ✅

**名称:** CVE-2018-15473-OpenSSH用户枚举  
**类型:** 用户枚举  
**风险:** 中危，可能为后续攻击提供信息  
**投毒风险:** 0%  
**发现时间:** 2025-03-25  
**POC仓库:** [docker-cve-2018-15473](https://github.com/mclbn/docker-cve-2018-15473)  

---

### [CVE-2024-4367](CVE-2024-4367-elamani-drawing_CVE-2024-4367-POC-PDFJS.md) 🔴 ✅

**名称:** CVE-2024-4367-Firefox-PDF.js-JavaScript执行  
**类型:** JavaScript执行  
**风险:** 高危，可能导致信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2024-4367-POC-PDFJS](https://github.com/elamani-drawing/CVE-2024-4367-POC-PDFJS)  

---

### [CVE-2018-15473](CVE-2018-15473-MahdiOsman_CVE-2018-15473-SNMPv1-2-Community-String-Vulnerability-Testing.md) 🟡 ✅

**名称:** CVE-2018-15473-OpenSSH用户名枚举  
**类型:** 用户名枚举  
**风险:** 中危，可能为进一步攻击提供信息  
**投毒风险:** 5%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2018-15473-SNMPv1-2-Community-String-Vulnerability-Testing](https://github.com/MahdiOsman/CVE-2018-15473-SNMPv1-2-Community-String-Vulnerability-Testing)  

---

### [CVE-2018-15473](CVE-2018-15473-NestyF_SSH_Enum_CVE-2018-15473.md) 🟡 ✅

**名称:** CVE-2018-15473-OpenSSH用户名枚举  
**类型:** 用户名枚举  
**风险:** 中危，可能被用于后续的暴力破解或其他攻击  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [SSH_Enum_CVE-2018-15473](https://github.com/NestyF/SSH_Enum_CVE-2018-15473)  

---

### [CVE-2018-15473](CVE-2018-15473-SUDORM0X_PoC-CVE-2018-15473.md) 🟡 ✅

**名称:** CVE-2018-15473 - OpenSSH 用户枚举  
**类型:** 用户枚举  
**风险:** 中危，可能为后续攻击提供信息  
**投毒风险:** 0%  
**发现时间:** 2025-03-25  
**POC仓库:** [PoC-CVE-2018-15473](https://github.com/SUDORM0X/PoC-CVE-2018-15473)  

---

### [CVE-2018-15473](CVE-2018-15473-OmarV4066_SSHEnumKL.md) 🟡 ✅

**名称:** CVE-2018-15473 OpenSSH 用户枚举  
**类型:** 用户枚举  
**风险:** 中危，允许攻击者枚举目标系统上的有效用户名，为后续攻击（如密码破解）提供便利。  
**投毒风险:** 0%  
**发现时间:** 2025-03-25  
**POC仓库:** [SSHEnumKL](https://github.com/OmarV4066/SSHEnumKL)  

---

### [CVE-2018-15473](CVE-2018-15473-moften_cve-2018-15473-poc.md) 🟡 ✅

**名称:** CVE-2018-15473-OpenSSH用户名枚举  
**类型:** 用户名枚举  
**风险:** 中危，泄露有效的用户名信息，为后续暴力破解或密码猜测攻击提供便利  
**投毒风险:** 0%  
**发现时间:** 2025-03-25  
**POC仓库:** [cve-2018-15473-poc](https://github.com/moften/cve-2018-15473-poc)  

---

### [CVE-2025-29927](CVE-2025-29927-c0dejump_CVE-2025-29927-check.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-Authorization Bypass  
**类型:** 权限绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2025-29927-check](https://github.com/c0dejump/CVE-2025-29927-check)  

---

### [CVE-2023-30258](CVE-2023-30258-n00o00b_CVE-2023-30258-RCE-POC.md) 🔴 ✅

**名称:** CVE-2023-30258-MagnusBilling-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2023-30258-RCE-POC](https://github.com/n00o00b/CVE-2023-30258-RCE-POC)  

---

### [CVE-2025-29927](CVE-2025-29927-0xcucumbersalad_cve-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-Middleware权限绕过  
**类型:** 权限绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [cve-2025-29927](https://github.com/0xcucumbersalad/cve-2025-29927)  

---

### [CVE-2025-22953](CVE-2025-22953-maliktawfiq_CVE-2025-22953.md) 🔴 ✅

**名称:** CVE-2025-22953 - Epicor HCM 未授权盲注SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致敏感数据泄露、未授权数据库访问、权限提升，甚至远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2025-22953](https://github.com/maliktawfiq/CVE-2025-22953)  

---

### [CVE-2025-1974](CVE-2025-1974-sandumjacob_IngressNightmare-POCs.md)  ✅

**名称:** CVE-2025-1974-ingress-nginx-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致集群范围内的Secret泄露和完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [IngressNightmare-POCs](https://github.com/sandumjacob/IngressNightmare-POCs)  

---

### [CVE-2025-1974](CVE-2025-1974-yoshino-s_CVE-2025-1974.md) 🔴 ✅

**名称:** CVE-2025-1974-ingress-nginx-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致集群范围内Secrets泄露和任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2025-1974](https://github.com/yoshino-s/CVE-2025-1974)  

---

### [CVE-2025-29927](CVE-2025-29927-0xPThree_next.js_cve-2025-29927.md) 🔴 

**名称:** CVE-2025-29927-Next.js中间件授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问敏感数据和操作  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [next.js_cve-2025-29927](https://github.com/0xPThree/next.js_cve-2025-29927)  

---

### [CVE-2025-29927](CVE-2025-29927-alihussainzada_CVE-2025-29927-PoC.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js中间件绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未经授权的访问和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2025-29927-PoC](https://github.com/alihussainzada/CVE-2025-29927-PoC)  

---

### [CVE-2025-29927](CVE-2025-29927-TheresAFewConors_CVE-2025-29927-Testing.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js中间件绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2025-29927-Testing](https://github.com/TheresAFewConors/CVE-2025-29927-Testing)  

---

### [CVE-2025-29927](CVE-2025-29927-takumade_ghost-route.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js Middleware Authorization Bypass  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-25  
**POC仓库:** [ghost-route](https://github.com/takumade/ghost-route)  

---

### [CVE-2025-29306](CVE-2025-29306-somatrasss_CVE-2025-29306.md) 🔴 ✅

**名称:** CVE-2025-29306 - FOXCMS 黔狐内容管理系统服务参数注入漏洞  
**类型:** 服务参数注入  
**风险:** 高危，可能导致信息泄露甚至服务器控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2025-29306](https://github.com/somatrasss/CVE-2025-29306)  

---

### [CVE-2025-29927](CVE-2025-29927-jeymo092_cve-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js Middleware 授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问，数据泄露和权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-03-25  
**POC仓库:** [cve-2025-29927](https://github.com/jeymo092/cve-2025-29927)  

---

### [CVE-2025-29927](CVE-2025-29927-0xPb1_Next.js-CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-Middleware-Bypass  
**类型:** 权限绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [Next.js-CVE-2025-29927](https://github.com/0xPb1/Next.js-CVE-2025-29927)  

---

### [CVE-2025-29927](CVE-2025-29927-furmak331_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js中间件认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 1%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2025-29927](https://github.com/furmak331/CVE-2025-29927)  

---

### [CVE-2025-29927](CVE-2025-29927-elshaheedy_CVE-2025-29927-Sigma-Rule.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js中间件授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2025-29927-Sigma-Rule](https://github.com/elshaheedy/CVE-2025-29927-Sigma-Rule)  

---

### [CVE-2024-31114](CVE-2024-31114-Nxploited_CVE-2024-31114.md) 🔴 ✅

**名称:** CVE-2024-31114 - WordPress Shortcode Addons 任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-25  
**POC仓库:** [CVE-2024-31114](https://github.com/Nxploited/CVE-2024-31114)  

---

### [CVE-2025-29927](CVE-2025-29927-ricsirigu_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js中间件授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问敏感信息或执行未授权操作  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2025-29927](https://github.com/ricsirigu/CVE-2025-29927)  

---

### [CVE-2025-29927](CVE-2025-29927-tobiasGuta_CVE-2025-29927-POC.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-中间件认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2025-29927-POC](https://github.com/tobiasGuta/CVE-2025-29927-POC)  

---

### [CVE-2025-24813](CVE-2025-24813-u238_Tomcat-CVE_2025_24813.md) 🔴 ✅

**名称:** CVE-2025-24813-Apache Tomcat-路径遍历/反序列化RCE  
**类型:** 路径遍历/反序列化RCE  
**风险:** 高危，可能导致远程代码执行和信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-24  
**POC仓库:** [Tomcat-CVE_2025_24813](https://github.com/u238/Tomcat-CVE_2025_24813)  

---

### [CVE-2025-29927](CVE-2025-29927-0xWhoknows_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js中间件授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2025-29927](https://github.com/0xWhoknows/CVE-2025-29927)  

---

### [CVE-2025-24813](CVE-2025-24813-beyond-devsecops_CVE-2025-24813.md) 🔴 ✅

**名称:** CVE-2025-24813-Apache Tomcat RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2025-24813](https://github.com/beyond-devsecops/CVE-2025-24813)  

---

### [CVE-2025-29927](CVE-2025-29927-Oyst3r1ng_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js Middleware Authorization Bypass  
**类型:** 认证绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2025-29927](https://github.com/Oyst3r1ng/CVE-2025-29927)  

---

### [CVE-2025-29927](CVE-2025-29927-kuzushiki_CVE-2025-29927-test.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-Authorization Bypass  
**类型:** 权限绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2025-29927-test](https://github.com/kuzushiki/CVE-2025-29927-test)  

---

### [CVE-2024-24919](CVE-2024-24919-Expl0itD0g_CVE-2024-24919---Poc.md) 🔴 ✅

**名称:** CVE-2024-24919-CheckPoint-信息泄露  
**类型:** 信息泄露  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-24919---Poc](https://github.com/Expl0itD0g/CVE-2024-24919---Poc)  

---

### [CVE-2024-24919](CVE-2024-24919-bigb0x_CVE-2024-24919-Sniper.md) 🔴 ✅

**名称:** CVE-2024-24919-CheckPoint-信息泄露  
**类型:** 信息泄露  
**风险:** 高危，可能允许攻击者读取Check Point安全网关上的某些信息  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-24919-Sniper](https://github.com/bigb0x/CVE-2024-24919-Sniper)  

---

### [CVE-2024-24919](CVE-2024-24919-Rug4lo_CVE-2024-24919-Exploit.md) 🔴 ✅

**名称:** CVE-2024-24919-Check Point Security Gateway 信息泄露  
**类型:** 信息泄露  
**风险:** 高危，允许未经身份验证的远程攻击者读取Check Point Security Gateway上的任意文件  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-24919-Exploit](https://github.com/Rug4lo/CVE-2024-24919-Exploit)  

---

### [CVE-2024-24919](CVE-2024-24919-GuayoyoCyber_CVE-2024-24919.md) 🔴 ✅

**名称:** CVE-2024-24919-CheckPoint-信息泄露  
**类型:** 信息泄露  
**风险:** 高危，允许未授权远程攻击者读取目标设备上的任意文件内容。  
**投毒风险:** 0%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-24919](https://github.com/GuayoyoCyber/CVE-2024-24919)  

---

### [CVE-2024-24919](CVE-2024-24919-Tim-Hoekstra_CVE-2024-24919.md) 🔴 ✅

**名称:** CVE-2024-24919-CheckPoint-信息泄露  
**类型:** 信息泄露  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-24919](https://github.com/Tim-Hoekstra/CVE-2024-24919)  

---

### [CVE-2024-24919](CVE-2024-24919-birdlex_cve-2024-24919-checker.md) 🔴 ✅

**名称:** CVE-2024-24919-CheckPoint-信息泄露  
**类型:** 信息泄露  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [cve-2024-24919-checker](https://github.com/birdlex/cve-2024-24919-checker)  

---

### [CVE-2024-24919](CVE-2024-24919-RevoltSecurities_CVE-2024-24919.md) 🔴 ✅

**名称:** CVE-2024-24919-CheckPoint安全网关信息泄露  
**类型:** 信息泄露/路径穿越  
**风险:** 高危，允许未授权远程攻击者读取受影响设备上的任意文件  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-24919](https://github.com/RevoltSecurities/CVE-2024-24919)  

---

### [CVE-2024-24919](CVE-2024-24919-un9nplayer_CVE-2024-24919.md) 🔴 ✅

**名称:** CVE-2024-24919-Check Point Security Gateway信息泄露  
**类型:** 信息泄露/路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-24919](https://github.com/un9nplayer/CVE-2024-24919)  

---

### [CVE-2024-24919](CVE-2024-24919-starlox0_CVE-2024-24919-POC.md) 🔴 ✅

**名称:** CVE-2024-24919 Check Point Security Gateway 信息泄露  
**类型:** 信息泄露/路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-24919-POC](https://github.com/starlox0/CVE-2024-24919-POC)  

---

### [CVE-2024-24919](CVE-2024-24919-nullcult_CVE-2024-24919-Exploit.md) 🔴 ✅

**名称:** CVE-2024-24919-Check Point Security Gateway 信息泄露  
**类型:** 信息泄露/路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-24919-Exploit](https://github.com/nullcult/CVE-2024-24919-Exploit)  

---

### [CVE-2024-24919](CVE-2024-24919-satchhacker_cve-2024-24919.md) 🔴 ✅

**名称:** CVE-2024-24919-CheckPoint-信息泄露  
**类型:** 信息泄露  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-24  
**POC仓库:** [cve-2024-24919](https://github.com/satchhacker/cve-2024-24919)  

---

### [CVE-2024-24919](CVE-2024-24919-protonnegativo_CVE-2024-24919.md) 🔴 ✅

**名称:** CVE-2024-24919-Check Point Security Gateway 信息泄露  
**类型:** 信息泄露  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-24919](https://github.com/protonnegativo/CVE-2024-24919)  

---

### [CVE-2024-24919](CVE-2024-24919-SalehLardhi_CVE-2024-24919.md) 🔴 ✅

**名称:** CVE-2024-24919-CheckPoint-信息泄露  
**类型:** 信息泄露  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-24919](https://github.com/SalehLardhi/CVE-2024-24919)  

---

### [CVE-2024-24919](CVE-2024-24919-0xans_CVE-2024-24919.md) 🔴 ✅

**名称:** CVE-2024-24919-Check Point Security Gateway 信息泄露  
**类型:** 信息泄露  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-24919](https://github.com/0xans/CVE-2024-24919)  

---

### [CVE-2024-24919](CVE-2024-24919-Cappricio-Securities_CVE-2024-24919.md) 🔴 ✅

**名称:** CVE-2024-24919 - Check Point Security Gateway 信息泄露  
**类型:** 信息泄露/路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-24919](https://github.com/Cappricio-Securities/CVE-2024-24919)  

---

### [CVE-2024-24919](CVE-2024-24919-ShadowByte1_CVE-2024-24919.md) 🔴 ✅

**名称:** CVE-2024-24919 - Check Point Security Gateway 信息泄露  
**类型:** 信息泄露 (路径遍历)  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-24919](https://github.com/ShadowByte1/CVE-2024-24919)  

---

### [CVE-2024-24919](CVE-2024-24919-H3KEY_CVE-2024-24919.md) 🔴 ✅

**名称:** CVE-2024-24919 - Check Point Security Gateway 信息泄露  
**类型:** 信息泄露/路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-24919](https://github.com/H3KEY/CVE-2024-24919)  

---

### [CVE-2024-24919](CVE-2024-24919-Jutrm_cve-2024-24919.md) 🔴 ✅

**名称:** CVE-2024-24919 - Check Point Security Gateway 信息泄露  
**类型:** 信息泄露 (路径遍历)  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 60%  
**发现时间:** 2025-03-24  
**POC仓库:** [cve-2024-24919](https://github.com/Jutrm/cve-2024-24919)  

---

### [CVE-2024-24919](CVE-2024-24919-0nin0hanz0_CVE-2024-24919-PoC.md) 🔴 ✅

**名称:** CVE-2024-24919-Check Point Security Gateway信息泄露  
**类型:** 信息泄露/路径遍历  
**风险:** 高危，可能导致敏感信息泄露，进而横向渗透  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-24919-PoC](https://github.com/0nin0hanz0/CVE-2024-24919-PoC)  

---

### [CVE-2024-24919](CVE-2024-24919-LuisMateo1_Arbitrary-File-Read-CVE-2024-24919.md) 🔴 ✅

**名称:** CVE-2024-24919 - Check Point Security Gateway 信息泄露  
**类型:** 信息泄露 (路径遍历)  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-24  
**POC仓库:** [Arbitrary-File-Read-CVE-2024-24919](https://github.com/LuisMateo1/Arbitrary-File-Read-CVE-2024-24919)  

---

### [CVE-2024-24919](CVE-2024-24919-geniuszly_CVE-2024-24919.md) 🔴 ✅

**名称:** CVE-2024-24919 - Check Point Security Gateway 信息泄露  
**类型:** 信息泄露/路径遍历  
**风险:** 高危，可读取敏感信息  
**投毒风险:** 1%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-24919](https://github.com/geniuszly/CVE-2024-24919)  

---

### [CVE-2024-24919](CVE-2024-24919-sar-3mar_CVE-2024-24919_POC.md) 🔴 ✅

**名称:** CVE-2024-24919 Check Point Security Gateway 信息泄露漏洞  
**类型:** 信息泄露/路径穿越  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-24919_POC](https://github.com/sar-3mar/CVE-2024-24919_POC)  

---

### [CVE-2024-24919](CVE-2024-24919-verylazytech_CVE-2024-24919.md) 🔴 ✅

**名称:** CVE-2024-24919 - Check Point Security Gateway 信息泄露  
**类型:** 信息泄露/路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-24919](https://github.com/verylazytech/CVE-2024-24919)  

---

### [CVE-2024-24919](CVE-2024-24919-NingXin2002_Check-Point_poc.md) 🔴 ✅

**名称:** CVE-2024-24919-Check Point Security Gateway 信息泄露  
**类型:** 信息泄露/任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-24  
**POC仓库:** [Check-Point_poc](https://github.com/NingXin2002/Check-Point_poc)  

---

### [CVE-2024-24919](CVE-2024-24919-hashdr1ft_SOC_287.md) 🔴 ✅

**名称:** CVE-2024-24919 - Check Point Security Gateway 信息泄露  
**类型:** 信息泄露/路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-24  
**POC仓库:** [SOC_287](https://github.com/hashdr1ft/SOC_287)  

---

### [CVE-2024-24919](CVE-2024-24919-funixone_CVE-2024-24919---Exploit-Script.md) 🔴 ✅

**名称:** CVE-2024-24919-CheckPoint安全网关信息泄露  
**类型:** 信息泄露/路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-24919---Exploit-Script](https://github.com/funixone/CVE-2024-24919---Exploit-Script)  

---

### [CVE-2024-24919](CVE-2024-24919-spider00009_CVE-2024-24919-POC.md) 🔴 ✅

**名称:** CVE-2024-24919 Check Point Security Gateway 信息泄露  
**类型:** 信息泄露/本地文件包含 (LFI)  
**风险:** 高危，可能导致敏感信息泄露，例如系统账号密码等  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-24919-POC](https://github.com/spider00009/CVE-2024-24919-POC)  

---

### [CVE-2024-24919](CVE-2024-24919-0xlf_CVE-2024-24919.md) 🔴 ✅

**名称:** CVE-2024-24919 Check Point Security Gateway 信息泄露  
**类型:** 信息泄露  
**风险:** 高危，可能导致敏感信息泄露，如系统配置、用户凭据等  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-24919](https://github.com/0xlf/CVE-2024-24919)  

---

### [CVE-2025-29927](CVE-2025-29927-lem0n817_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-中间件授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2025-29927](https://github.com/lem0n817/CVE-2025-29927)  

---

### [CVE-2025-29927](CVE-2025-29927-lediusa_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js中间件认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2025-29927](https://github.com/lediusa/CVE-2025-29927)  

---

### [CVE-2025-29927](CVE-2025-29927-arvion-agent_next-CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-中间件授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未经授权的访问和数据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-24  
**POC仓库:** [next-CVE-2025-29927](https://github.com/arvion-agent/next-CVE-2025-29927)  

---

### [CVE-2024-23692](CVE-2024-23692-k3lpi3b4nsh33_CVE-2024-23692.md) 🔴 ✅

**名称:** CVE-2024-23692 - Rejetto HTTP File Server 2.3m 远程代码执行  
**类型:** 模板注入  
**风险:** 高危，未经授权的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-23692](https://github.com/k3lpi3b4nsh33/CVE-2024-23692)  

---

### [CVE-2024-2387](CVE-2024-2387-RandomRobbieBF_CVE-2024-2387.md) 🟡 ✅

**名称:** CVE-2024-2387-Advanced Form Integration-SQL注入  
**类型:** SQL注入  
**风险:** 中危，可能导致数据库信息泄露和XSS攻击  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-2387](https://github.com/RandomRobbieBF/CVE-2024-2387)  

---

### [CVE-2025-29927](CVE-2025-29927-iSee857_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js中间件权限绕过  
**类型:** 权限绕过  
**风险:** 高危，可能导致未经授权的访问和数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2025-29927](https://github.com/iSee857/CVE-2025-29927)  

---

### [CVE-2024-23692](CVE-2024-23692-jakabakos_CVE-2024-23692-RCE-in-Rejetto-HFS.md)  ✅

**名称:** CVE-2024-23692 - Rejetto HTTP File Server 2.3m 远程代码执行  
**类型:** 模板注入/远程代码执行  
**风险:** 严重，允许未授权的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-23692-RCE-in-Rejetto-HFS](https://github.com/jakabakos/CVE-2024-23692-RCE-in-Rejetto-HFS)  

---

### [CVE-2024-23692](CVE-2024-23692-WanLiChangChengWanLiChang_CVE-2024-23692-RCE.md) 🔴 ✅

**名称:** CVE-2024-23692-Rejetto HFS 2.3m 远程命令执行  
**类型:** 模板注入导致的远程命令执行  
**风险:** 高危，允许未经身份验证的远程攻击者执行任意命令  
**投毒风险:** 1%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-23692-RCE](https://github.com/WanLiChangChengWanLiChang/CVE-2024-23692-RCE)  

---

### [CVE-2024-23692](CVE-2024-23692-Mr-r00t11_CVE-2024-23692.md) 🔴 ✅

**名称:** CVE-2024-23692 - Rejetto HTTP File Server 远程代码执行  
**类型:** 模板注入导致远程代码执行  
**风险:** 高危，允许未经身份验证的远程攻击者执行任意命令  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-23692](https://github.com/Mr-r00t11/CVE-2024-23692)  

---

### [CVE-2024-23692](CVE-2024-23692-vanboomqi_CVE-2024-23692.md) 🔴 ✅

**名称:** CVE-2024-23692 - Rejetto HTTP File Server 2.3m 远程代码执行  
**类型:** 模板注入导致的远程代码执行  
**风险:** 高危，允许未授权的远程攻击者执行任意命令  
**投毒风险:** 1%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-23692](https://github.com/vanboomqi/CVE-2024-23692)  

---

### [CVE-2024-23692](CVE-2024-23692-Tupler_CVE-2024-23692-exp.md)  ✅

**名称:** CVE-2024-23692-Rejetto HFS-模板注入RCE  
**类型:** 模板注入RCE  
**风险:** 严重，远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-23692-exp](https://github.com/Tupler/CVE-2024-23692-exp)  

---

### [CVE-2024-23692](CVE-2024-23692-BBD-YZZ_CVE-2024-23692.md)  ✅

**名称:** CVE-2024-23692 - Rejetto HTTP File Server Template Injection RCE  
**类型:** 模板注入导致远程代码执行  
**风险:** 严重，未经身份验证的远程攻击者可以执行任意命令  
**投毒风险:** 5%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-23692](https://github.com/BBD-YZZ/CVE-2024-23692)  

---

### [CVE-2024-23692](CVE-2024-23692-0x20c_CVE-2024-23692-EXP.md) 🔴 ✅

**名称:** CVE-2024-23692-Rejetto HTTP File Server-模板注入  
**类型:** 模板注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-23692-EXP](https://github.com/0x20c/CVE-2024-23692-EXP)  

---

### [CVE-2024-23692](CVE-2024-23692-pradeepboo_Rejetto-HFS-2.x-RCE-CVE-2024-23692.md) 🔴 ✅

**名称:** CVE-2024-23692 - Rejetto HTTP File Server 远程代码执行  
**类型:** 模板注入 (SSTI)  
**风险:** 高危，允许远程未授权代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-24  
**POC仓库:** [Rejetto-HFS-2.x-RCE-CVE-2024-23692](https://github.com/pradeepboo/Rejetto-HFS-2.x-RCE-CVE-2024-23692)  

---

### [CVE-2024-23692](CVE-2024-23692-XiaomingX_cve-2024-23692-poc.md)  ✅

**名称:** CVE-2024-23692-Rejetto HFS-模板注入RCE  
**类型:** 模板注入RCE  
**风险:** 严重，远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-24  
**POC仓库:** [cve-2024-23692-poc](https://github.com/XiaomingX/cve-2024-23692-poc)  

---

### [CVE-2024-23692](CVE-2024-23692-NingXin2002_HFS2.3_poc.md) 🔴 ✅

**名称:** CVE-2024-23692-Rejetto HTTP File Server-模板注入RCE  
**类型:** 模板注入RCE  
**风险:** 高危，允许远程、未经身份验证的攻击者执行任意命令  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [HFS2.3_poc](https://github.com/NingXin2002/HFS2.3_poc)  

---

### [CVE-2024-23692](CVE-2024-23692-999gawkboyy_CVE-2024-23692_Exploit.md) 🔴 ✅

**名称:** CVE-2024-23692-Rejetto HFS-模板注入RCE  
**类型:** 模板注入RCE  
**风险:** 高危，允许远程未授权执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-23692_Exploit](https://github.com/999gawkboyy/CVE-2024-23692_Exploit)  

---

### [CVE-2024-23692](CVE-2024-23692-verylazytech_CVE-2024-23692.md) 🔴 ✅

**名称:** CVE-2024-23692 Rejetto HTTP File Server 2.3m 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程攻击者执行任意命令。  
**投毒风险:** 1%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-23692](https://github.com/verylazytech/CVE-2024-23692)  

---

### [CVE-2025-29927](CVE-2025-29927-fourcube_nextjs-middleware-bypass-demo.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js Middleware Authorization Bypass  
**类型:** 权限绕过  
**风险:** 高危，可能导致未授权访问  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [nextjs-middleware-bypass-demo](https://github.com/fourcube/nextjs-middleware-bypass-demo)  

---

### [CVE-2025-22224](CVE-2025-22224-bronsoneaver_CVE-2025-22224.md) 🔴 ✅

**名称:** CVE-2025-22224-VMware-TOCTOU-Out-of-bounds Write  
**类型:** TOCTOU Out-of-bounds Write  
**风险:** 高危，可执行代码，权限提升  
**投毒风险:** 70%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2025-22224](https://github.com/bronsoneaver/CVE-2025-22224)  

---

### [CVE-2025-29927](CVE-2025-29927-strobes-security_nextjs-vulnerable-app.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-中间件授权绕过  
**类型:** 授权绕过  
**风险:** 高危，未经授权访问敏感资源  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [nextjs-vulnerable-app](https://github.com/strobes-security/nextjs-vulnerable-app)  

---

### [CVE-2025-29927](CVE-2025-29927-RoyCampos_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js中间件授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问，数据泄露，权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2025-29927](https://github.com/RoyCampos/CVE-2025-29927)  

---

### [CVE-2024-2997](CVE-2024-2997-lfillaz_CVE-2024-2997.md)  ✅

**名称:** CVE-2024-2997 - Bdtask Multi-Store Inventory Management System - 跨站脚本攻击 (XSS)  
**类型:** 跨站脚本攻击 (XSS)  
**风险:** 低危，仅可执行有限的脚本，影响用户体验  
**投毒风险:** 1%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-2997](https://github.com/lfillaz/CVE-2024-2997)  

---

### [CVE-2022-44268](CVE-2022-44268-Ashifcoder_CVE-2022-44268-automated-poc.md) 🔴 ✅

**名称:** CVE-2022-44268 ImageMagick Arbitrary File Read  
**类型:** 信息泄露  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2022-44268-automated-poc](https://github.com/Ashifcoder/CVE-2022-44268-automated-poc)  

---

### [CVE-2022-44268](CVE-2022-44268-fanbyprinciple_ImageMagick-lfi-poc.md) 🔴 ✅

**名称:** CVE-2022-44268-ImageMagick-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-03-24  
**POC仓库:** [ImageMagick-lfi-poc](https://github.com/fanbyprinciple/ImageMagick-lfi-poc)  

---

### [CVE-2002-0082](CVE-2002-0082-ratiros01_CVE-2002-0082.md) 🔴 ✅

**名称:** CVE-2002-0082 - Apache mod_ssl 缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2002-0082](https://github.com/ratiros01/CVE-2002-0082)  

---

### [CVE-2022-44268](CVE-2022-44268-duc-nt_CVE-2022-44268-ImageMagick-Arbitrary-File-Read-PoC.md) 🔴 ✅

**名称:** CVE-2022-44268-ImageMagick-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2022-44268-ImageMagick-Arbitrary-File-Read-PoC](https://github.com/duc-nt/CVE-2022-44268-ImageMagick-Arbitrary-File-Read-PoC)  

---

### [CVE-2022-44268](CVE-2022-44268-y1nglamore_CVE-2022-44268-ImageMagick-Vulnerable-Docker-Environment.md) 🔴 ✅

**名称:** CVE-2022-44268-ImageMagick-Arbitrary File Read  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2022-44268-ImageMagick-Vulnerable-Docker-Environment](https://github.com/y1nglamore/CVE-2022-44268-ImageMagick-Vulnerable-Docker-Environment)  

---

### [CVE-2022-44268](CVE-2022-44268-agathanon_cve-2022-44268.md) 🟡 ✅

**名称:** CVE-2022-44268-ImageMagick-信息泄露  
**类型:** 信息泄露  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-24  
**POC仓库:** [cve-2022-44268](https://github.com/agathanon/cve-2022-44268)  

---

### [CVE-2022-44268](CVE-2022-44268-Baikuya_CVE-2022-44268-PoC.md) 🔴 ✅

**名称:** CVE-2022-44268-ImageMagick-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2022-44268-PoC](https://github.com/Baikuya/CVE-2022-44268-PoC)  

---

### [CVE-2022-44268](CVE-2022-44268-Vulnmachines_imagemagick-CVE-2022-44268.md) 🔴 ✅

**名称:** CVE-2022-44268-ImageMagick-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [imagemagick-CVE-2022-44268](https://github.com/Vulnmachines/imagemagick-CVE-2022-44268)  

---

### [CVE-2022-44268](CVE-2022-44268-nfm_heroku-CVE-2022-44268-reproduction.md) 🔴 ✅

**名称:** CVE-2022-44268-ImageMagick-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-24  
**POC仓库:** [heroku-CVE-2022-44268-reproduction](https://github.com/nfm/heroku-CVE-2022-44268-reproduction)  

---

### [CVE-2022-44268](CVE-2022-44268-betillogalvanfbc_POC-CVE-2022-44268.md) 🔴 ✅

**名称:** CVE-2022-44268-ImageMagick-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [POC-CVE-2022-44268](https://github.com/betillogalvanfbc/POC-CVE-2022-44268)  

---

### [CVE-2022-44268](CVE-2022-44268-adhikara13_CVE-2022-44268-MagiLeak.md) 🔴 ✅

**名称:** CVE-2022-44268-ImageMagick-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2022-44268-MagiLeak](https://github.com/adhikara13/CVE-2022-44268-MagiLeak)  

---

### [CVE-2022-44268](CVE-2022-44268-bhavikmalhotra_CVE-2022-44268-Exploit.md) 🔴 ✅

**名称:** CVE-2022-44268-ImageMagick-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2022-44268-Exploit](https://github.com/bhavikmalhotra/CVE-2022-44268-Exploit)  

---

### [CVE-2022-44268](CVE-2022-44268-entr0pie_CVE-2022-44268.md) 🔴 ✅

**名称:** CVE-2022-44268-ImageMagick-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2022-44268](https://github.com/entr0pie/CVE-2022-44268)  

---

### [CVE-2022-44268](CVE-2022-44268-Pog-Frog_cve-2022-44268.md) 🔴 ✅

**名称:** CVE-2022-44268-ImageMagick-任意文件读取  
**类型:** 信息泄露/任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-24  
**POC仓库:** [cve-2022-44268](https://github.com/Pog-Frog/cve-2022-44268)  

---

### [CVE-2022-44268](CVE-2022-44268-narekkay_auto-cve-2022-44268.sh.md) 🔴 ✅

**名称:** CVE-2022-44268-ImageMagick-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-24  
**POC仓库:** [auto-cve-2022-44268.sh](https://github.com/narekkay/auto-cve-2022-44268.sh)  

---

### [CVE-2022-44268](CVE-2022-44268-chairat095_CVE-2022-44268_By_Kyokito.md) 🔴 ✅

**名称:** CVE-2022-44268-ImageMagick-信息泄露  
**类型:** 信息泄露  
**风险:** 高危，可能导致任意文件读取  
**投毒风险:** 0%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2022-44268_By_Kyokito](https://github.com/chairat095/CVE-2022-44268_By_Kyokito)  

---

### [CVE-2022-44268](CVE-2022-44268-atici_Exploit-for-ImageMagick-CVE-2022-44268.md) 🔴 ✅

**名称:** CVE-2022-44268-ImageMagick-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [Exploit-for-ImageMagick-CVE-2022-44268](https://github.com/atici/Exploit-for-ImageMagick-CVE-2022-44268)  

---

### [CVE-2022-44268](CVE-2022-44268-Vagebondcur_IMAGE-MAGICK-CVE-2022-44268.md) 🔴 ✅

**名称:** CVE-2022-44268-ImageMagick-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-24  
**POC仓库:** [IMAGE-MAGICK-CVE-2022-44268](https://github.com/Vagebondcur/IMAGE-MAGICK-CVE-2022-44268)  

---

### [CVE-2022-44268](CVE-2022-44268-Sybil-Scan_imagemagick-lfi-poc.md) 🔴 ✅

**名称:** CVE-2022-44268-ImageMagick-Arbitrary File Read  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-24  
**POC仓库:** [imagemagick-lfi-poc](https://github.com/Sybil-Scan/imagemagick-lfi-poc)  

---

### [CVE-2022-44268](CVE-2022-44268-NataliSemi_-CVE-2022-44268.md) 🔴 ✅

**名称:** CVE-2022-44268-ImageMagick-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-24  
**POC仓库:** [-CVE-2022-44268](https://github.com/NataliSemi/-CVE-2022-44268)  

---

### [CVE-2022-44268](CVE-2022-44268-CygnusX-26_CVE-2022-44268-fixed-PoC.md) 🔴 ✅

**名称:** CVE-2022-44268-ImageMagick-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2022-44268-fixed-PoC](https://github.com/CygnusX-26/CVE-2022-44268-fixed-PoC)  

---

### [CVE-2022-44268](CVE-2022-44268-jnschaeffer_cve-2022-44268-detector.md) 🔴 ✅

**名称:** CVE-2022-44268-ImageMagick-任意文件读取  
**类型:** 信息泄露/任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-24  
**POC仓库:** [cve-2022-44268-detector](https://github.com/jnschaeffer/cve-2022-44268-detector)  

---

### [CVE-2022-44268](CVE-2022-44268-kljunowsky_CVE-2022-44268.md) 🔴 ✅

**名称:** CVE-2022-44268-ImageMagick-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2022-44268](https://github.com/kljunowsky/CVE-2022-44268)  

---

### [CVE-2022-44268](CVE-2022-44268-PanAdamski_CVE-2022-44268-automated.md) 🔴 ✅

**名称:** CVE-2022-44268-ImageMagick-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2022-44268-automated](https://github.com/PanAdamski/CVE-2022-44268-automated)  

---

### [CVE-2022-44268](CVE-2022-44268-FlojBoj_CVE-2022-44268.md) 🟡 ✅

**名称:** CVE-2022-44268-ImageMagick-信息泄露  
**类型:** 信息泄露  
**风险:** 中危，可能泄露敏感信息  
**投毒风险:** 0%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2022-44268](https://github.com/FlojBoj/CVE-2022-44268)  

---

### [CVE-2022-44268](CVE-2022-44268-voidz0r_CVE-2022-44268.md) 🔴 ✅

**名称:** CVE-2022-44268-ImageMagick-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2022-44268](https://github.com/voidz0r/CVE-2022-44268)  

---

### [CVE-2024-51793](CVE-2024-51793-Nxploited_CVE-2024-51793.md) 🔴 ✅

**名称:** CVE-2024-51793 - WordPress Computer Repair Shop Plugin Arbitrary File Upload  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2024-51793](https://github.com/Nxploited/CVE-2024-51793)  

---

### [CVE-2025-27363](CVE-2025-27363-zhuowei_CVE-2025-27363-proof-of-concept.md) 🔴 ✅

**名称:** CVE-2025-27363-FreeType-堆缓冲区溢出  
**类型:** 堆缓冲区溢出  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-03-24  
**POC仓库:** [CVE-2025-27363-proof-of-concept](https://github.com/zhuowei/CVE-2025-27363-proof-of-concept)  

---

### [CVE-2025-29927](CVE-2025-29927-MuhammadWaseem29_CVE-2025-29927-POC.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js中间件授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2025-29927-POC](https://github.com/MuhammadWaseem29/CVE-2025-29927-POC)  

---

### [CVE-2024-10578](CVE-2024-10578-Nxploited_CVE-2024-10578.md) 🔴 ✅

**名称:** CVE-2024-10578-Pubnews-任意插件安装  
**类型:** 任意插件安装  
**风险:** 高危，可被利用执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2024-10578](https://github.com/Nxploited/CVE-2024-10578)  

---

### [CVE-2023-48292](CVE-2023-48292-Mehran-Seifalinia_CVE-2023-48292.md)  ✅

**名称:** CVE-2023-48292 - XWiki Admin Tools CSRF to RCE  
**类型:** CSRF to RCE  
**风险:** 严重，攻击者可以利用 CSRF 漏洞，在管理员不知情的情况下执行任意 shell 命令，导致完全控制 XWiki 服务器  
**投毒风险:** 0%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2023-48292](https://github.com/Mehran-Seifalinia/CVE-2023-48292)  

---

### [CVE-2022-36804](CVE-2022-36804-JRandomSage_CVE-2022-36804-MASS-RCE.md) 🔴 ✅

**名称:** CVE-2022-36804-Bitbucket-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许远程攻击者执行任意代码  
**投毒风险:** 95%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2022-36804-MASS-RCE](https://github.com/JRandomSage/CVE-2022-36804-MASS-RCE)  

---

### [CVE-2022-36804](CVE-2022-36804-notxesh_CVE-2022-36804-PoC.md) 🔴 ✅

**名称:** CVE-2022-36804-Bitbucket-命令注入  
**类型:** 命令注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2022-36804-PoC](https://github.com/notxesh/CVE-2022-36804-PoC)  

---

### [CVE-2022-36804](CVE-2022-36804-Chocapikk_CVE-2022-36804-ReverseShell.md) 🔴 ✅

**名称:** CVE-2022-36804-Bitbucket-命令注入  
**类型:** 命令注入  
**风险:** 高危，可远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2022-36804-ReverseShell](https://github.com/Chocapikk/CVE-2022-36804-ReverseShell)  

---

### [CVE-2022-36804](CVE-2022-36804-0xEleven_CVE-2022-36804-ReverseShell.md) 🔴 ✅

**名称:** CVE-2022-36804-Bitbucket-命令注入  
**类型:** 命令注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2022-36804-ReverseShell](https://github.com/0xEleven/CVE-2022-36804-ReverseShell)  

---

### [CVE-2022-36804](CVE-2022-36804-tahtaciburak_cve-2022-36804.md) 🔴 ✅

**名称:** CVE-2022-36804 - Bitbucket 命令注入  
**类型:** 命令注入  
**风险:** 高危，允许远程攻击者执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-03-23  
**POC仓库:** [cve-2022-36804](https://github.com/tahtaciburak/cve-2022-36804)  

---

### [CVE-2022-36804](CVE-2022-36804-Inplex-sys_CVE-2022-36804.md) 🔴 ✅

**名称:** CVE-2022-36804-Atlassian Bitbucket-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许远程攻击者执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2022-36804](https://github.com/Inplex-sys/CVE-2022-36804)  

---

### [CVE-2022-36804](CVE-2022-36804-ColdFusionX_CVE-2022-36804.md) 🔴 ✅

**名称:** CVE-2022-36804-Bitbucket-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2022-36804](https://github.com/ColdFusionX/CVE-2022-36804)  

---

### [CVE-2022-36804](CVE-2022-36804-Vulnmachines_bitbucket-cve-2022-36804.md) 🔴 ✅

**名称:** CVE-2022-36804-Bitbucket-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-23  
**POC仓库:** [bitbucket-cve-2022-36804](https://github.com/Vulnmachines/bitbucket-cve-2022-36804)  

---

### [CVE-2022-36804](CVE-2022-36804-khal4n1_CVE-2022-36804.md) 🔴 ✅

**名称:** CVE-2022-36804-Bitbucket命令注入  
**类型:** 命令注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2022-36804](https://github.com/khal4n1/CVE-2022-36804)  

---

### [CVE-2022-36804](CVE-2022-36804-devengpk_CVE-2022-36804.md) 🔴 ✅

**名称:** CVE-2022-36804 - Bitbucket 命令注入  
**类型:** 命令注入  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2022-36804](https://github.com/devengpk/CVE-2022-36804)  

---

### [CVE-2022-36804](CVE-2022-36804-kljunowsky_CVE-2022-36804-POC.md) 🔴 ✅

**名称:** CVE-2022-36804-Bitbucket-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2022-36804-POC](https://github.com/kljunowsky/CVE-2022-36804-POC)  

---

### [CVE-2022-36804](CVE-2022-36804-walnutsecurity_cve-2022-36804.md) 🔴 ✅

**名称:** CVE-2022-36804-Atlassian Bitbucket Server/Data Center-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许远程攻击者执行任意代码  
**投毒风险:** 1%  
**发现时间:** 2025-03-23  
**POC仓库:** [cve-2022-36804](https://github.com/walnutsecurity/cve-2022-36804)  

---

### [CVE-2022-36804](CVE-2022-36804-imbas007_Atlassian-Bitbucket-CVE-2022-36804.md) 🔴 ✅

**名称:** CVE-2022-36804-Bitbucket-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-23  
**POC仓库:** [Atlassian-Bitbucket-CVE-2022-36804](https://github.com/imbas007/Atlassian-Bitbucket-CVE-2022-36804)  

---

### [CVE-2022-36804](CVE-2022-36804-benjaminhays_CVE-2022-36804-PoC-Exploit.md) 🔴 ✅

**名称:** CVE-2022-36804-Bitbucket 命令注入  
**类型:** 命令注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2022-36804-PoC-Exploit](https://github.com/benjaminhays/CVE-2022-36804-PoC-Exploit)  

---

### [CVE-2022-36804](CVE-2022-36804-notdls_CVE-2022-36804.md) 🔴 ✅

**名称:** CVE-2022-36804-Bitbucket-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许远程攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2022-36804](https://github.com/notdls/CVE-2022-36804)  

---

### [CVE-2022-36804](CVE-2022-36804-asepsaepdin_CVE-2022-36804.md) 🔴 ✅

**名称:** CVE-2022-36804 - Atlassian Bitbucket Server and Data Center 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2022-36804](https://github.com/asepsaepdin/CVE-2022-36804)  

---

### [CVE-2022-36804](CVE-2022-36804-ui-bootstrap_CVE-2022-36804.md) 🔴 ✅

**名称:** CVE-2022-36804-Bitbucket-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许远程攻击者执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2022-36804](https://github.com/ui-bootstrap/CVE-2022-36804)  

---

### [CVE-2025-29927](CVE-2025-29927-websecnl_CVE-2025-29927-PoC-Exploit.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js Middleware Authorization Bypass  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2025-29927-PoC-Exploit](https://github.com/websecnl/CVE-2025-29927-PoC-Exploit)  

---

### [CVE-2024-4577](CVE-2024-4577-creamylegum_CVE-2024-4577-PHP-RCE.md) 🔴 ✅

**名称:** CVE-2024-4577-PHP-CGI参数注入  
**类型:** PHP-CGI参数注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 60%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2024-4577-PHP-RCE](https://github.com/creamylegum/CVE-2024-4577-PHP-RCE)  

---

### [CVE-2025-29927](CVE-2025-29927-t3tra-dev_cve-2025-29927-demo.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js Middleware Authorization Bypass  
**类型:** Authorization Bypass  
**风险:** Critical，未经授权访问敏感信息和功能  
**投毒风险:** 10%  
**发现时间:** 2025-03-23  
**POC仓库:** [cve-2025-29927-demo](https://github.com/t3tra-dev/cve-2025-29927-demo)  

---

### [CVE-2023-41425](CVE-2023-41425-charlesgargasson_CVE-2023-41425.md) 🔴 ✅

**名称:** CVE-2023-41425-WonderCMS-XSS to RCE  
**类型:** 跨站脚本 (XSS) 导致远程代码执行 (RCE)  
**风险:** 高危，可能导致远程代码执行和完全控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2023-41425](https://github.com/charlesgargasson/CVE-2023-41425)  

---

### [CVE-2023-41425](CVE-2023-41425-SpycioKon_CVE-2023-41425.md) 🟡 ✅

**名称:** CVE-2023-41425-WonderCMS-XSS  
**类型:** 跨站脚本漏洞(XSS)  
**风险:** 中危，可能导致用户信息泄露、会话劫持或恶意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2023-41425](https://github.com/SpycioKon/CVE-2023-41425)  

---

### [CVE-2023-41425](CVE-2023-41425-Raffli-Dev_CVE-2023-41425.md) 🔴 ✅

**名称:** CVE-2023-41425-WonderCMS-XSS to RCE  
**类型:** XSS to RCE  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2023-41425](https://github.com/Raffli-Dev/CVE-2023-41425)  

---

### [CVE-2023-41425](CVE-2023-41425-duck-sec_CVE-2023-41425.md) 🔴 ✅

**名称:** CVE-2023-41425-WonderCMS-XSS to RCE  
**类型:** 跨站脚本攻击 (XSS) 导致远程代码执行 (RCE)  
**风险:** 高危，可导致服务器被控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2023-41425](https://github.com/duck-sec/CVE-2023-41425)  

---

### [CVE-2023-41425](CVE-2023-41425-thefizzyfish_CVE-2023-41425-wonderCMS_RCE.md) 🔴 ✅

**名称:** CVE-2023-41425 Wonder CMS XSS to RCE  
**类型:** 跨站脚本 (XSS)  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2023-41425-wonderCMS_RCE](https://github.com/thefizzyfish/CVE-2023-41425-wonderCMS_RCE)  

---

### [CVE-2023-41425](CVE-2023-41425-h3athen_CVE-2023-41425.md) 🔴 ✅

**名称:** CVE-2023-41425 - Wonder CMS XSS to RCE  
**类型:** 跨站脚本攻击 (XSS)  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2023-41425](https://github.com/h3athen/CVE-2023-41425)  

---

### [CVE-2023-41425](CVE-2023-41425-0x0d3ad_CVE-2023-41425.md) 🔴 ✅

**名称:** CVE-2023-41425-WonderCMS-XSS to RCE  
**类型:** 跨站脚本攻击 (XSS) 导致远程代码执行 (RCE)  
**风险:** 高危，可导致任意代码执行和服务器控制  
**投毒风险:** 0%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2023-41425](https://github.com/0x0d3ad/CVE-2023-41425)  

---

### [CVE-2023-41425](CVE-2023-41425-xpltive_CVE-2023-41425.md) 🔴 ✅

**名称:** CVE-2023-41425-WonderCMS-XSS to RCE  
**类型:** 跨站脚本攻击 (XSS) 导致远程代码执行 (RCE)  
**风险:** 高危，可能导致任意代码执行和服务器控制  
**投毒风险:** 1%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2023-41425](https://github.com/xpltive/CVE-2023-41425)  

---

### [CVE-2023-41425](CVE-2023-41425-prodigiousMind_CVE-2023-41425.md) 🔴 ✅

**名称:** CVE-2023-41425-WonderCMS-XSS to RCE  
**类型:** 跨站脚本（XSS）  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2023-41425](https://github.com/prodigiousMind/CVE-2023-41425)  

---

### [CVE-2023-41425](CVE-2023-41425-0xDTC_WonderCMS-4.3.2-XSS-to-RCE-Exploits-CVE-2023-41425.md) 🔴 ✅

**名称:** CVE-2023-41425-WonderCMS-XSS to RCE  
**类型:** 跨站脚本攻击 (XSS)  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-23  
**POC仓库:** [WonderCMS-4.3.2-XSS-to-RCE-Exploits-CVE-2023-41425](https://github.com/0xDTC/WonderCMS-4.3.2-XSS-to-RCE-Exploits-CVE-2023-41425)  

---

### [CVE-2023-41425](CVE-2023-41425-Diegomjx_CVE-2023-41425-WonderCMS-Authenticated-RCE.md) 🟡 ✅

**名称:** CVE-2023-41425-WonderCMS-XSS  
**类型:** 跨站脚本攻击 (XSS)  
**风险:** 中危，可能导致信息泄露和恶意脚本执行  
**投毒风险:** 95%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2023-41425-WonderCMS-Authenticated-RCE](https://github.com/Diegomjx/CVE-2023-41425-WonderCMS-Authenticated-RCE)  

---

### [CVE-2023-41425](CVE-2023-41425-insomnia-jacob_CVE-2023-41425.md) 🔴 ✅

**名称:** CVE-2023-41425-WonderCMS-XSS导致RCE  
**类型:** 跨站脚本攻击(XSS)导致远程代码执行(RCE)  
**风险:** 高危，可能导致远程代码执行和服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2023-41425](https://github.com/insomnia-jacob/CVE-2023-41425)  

---

### [CVE-2025-29927](CVE-2025-29927-ticofookfook_poc-nextjs-CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927 - Next.js Middleware 授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-23  
**POC仓库:** [poc-nextjs-CVE-2025-29927](https://github.com/ticofookfook/poc-nextjs-CVE-2025-29927)  

---

### [CVE-2024-9474](CVE-2024-9474-stupidgossi_CVE-2024-9474.md) 🔴 ✅

**名称:** CVE-2024-9474 PAN-OS Web管理界面权限提升漏洞  
**类型:** 权限提升/OS命令注入  
**风险:** 中危/高危 (取决于管理界面是否暴露在公网)  
**投毒风险:** 15%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2024-9474](https://github.com/stupidgossi/CVE-2024-9474)  

---

### [CVE-2025-29927](CVE-2025-29927-aydinnyunus_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js中间件授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2025-29927](https://github.com/aydinnyunus/CVE-2025-29927)  

---

### [CVE-2025-29927](CVE-2025-29927-lirantal_vulnerable-nextjs-14-CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js中间件授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未经授权的访问  
**投毒风险:** 1%  
**发现时间:** 2025-03-23  
**POC仓库:** [vulnerable-nextjs-14-CVE-2025-29927](https://github.com/lirantal/vulnerable-nextjs-14-CVE-2025-29927)  

---

### [CVE-2025-29927](CVE-2025-29927-azu_nextjs-cve-2025-29927-poc.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js Middleware 授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未经授权的访问和数据泄露  
**投毒风险:** 1%  
**发现时间:** 2025-03-23  
**POC仓库:** [nextjs-cve-2025-29927-poc](https://github.com/azu/nextjs-cve-2025-29927-poc)  

---

### [CVE-2025-29927](CVE-2025-29927-6mile_nextjs-CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-23  
**POC仓库:** [nextjs-CVE-2025-29927](https://github.com/6mile/nextjs-CVE-2025-29927)  

---

### [CVE-2024-23897](CVE-2024-23897-AbraXa5_Jenkins-CVE-2024-23897.md) 🔴 ✅

**名称:** CVE-2024-23897 - Jenkins 任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露和潜在的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-23  
**POC仓库:** [Jenkins-CVE-2024-23897](https://github.com/AbraXa5/Jenkins-CVE-2024-23897)  

---

### [CVE-2024-23897](CVE-2024-23897-kaanatmacaa_CVE-2024-23897.md) 🔴 ✅

**名称:** CVE-2024-23897-Jenkins-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2024-23897](https://github.com/kaanatmacaa/CVE-2024-23897)  

---

### [CVE-2024-23897](CVE-2024-23897-Praison001_CVE-2024-23897-Jenkins-Arbitrary-Read-File-Vulnerability.md) 🔴 ✅

**名称:** CVE-2024-23897-Jenkins-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露，间接可能导致RCE  
**投毒风险:** 5%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2024-23897-Jenkins-Arbitrary-Read-File-Vulnerability](https://github.com/Praison001/CVE-2024-23897-Jenkins-Arbitrary-Read-File-Vulnerability)  

---

### [CVE-2024-23897](CVE-2024-23897-B4CK4TT4CK_CVE-2024-23897.md) 🔴 ✅

**名称:** CVE-2024-23897 - Jenkins Arbitrary File Read  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露，进而发展为RCE  
**投毒风险:** 10%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2024-23897](https://github.com/B4CK4TT4CK/CVE-2024-23897)  

---

### [CVE-2024-23897](CVE-2024-23897-ifconfig-me_CVE-2024-23897.md) 🔴 ✅

**名称:** CVE-2024-23897 Jenkins 任意文件读取漏洞  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2024-23897](https://github.com/ifconfig-me/CVE-2024-23897)  

---

### [CVE-2024-23897](CVE-2024-23897-jenkinsci-cert_SECURITY-3314-3315.md) 🔴 ✅

**名称:** CVE-2024-23897-Jenkins-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-23  
**POC仓库:** [SECURITY-3314-3315](https://github.com/jenkinsci-cert/SECURITY-3314-3315)  

---

### [CVE-2024-23897](CVE-2024-23897-Nebian_CVE-2024-23897.md) 🔴 ✅

**名称:** CVE-2024-23897 - Jenkins Arbitrary File Read  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2024-23897](https://github.com/Nebian/CVE-2024-23897)  

---

### [CVE-2024-23897](CVE-2024-23897-xaitax_CVE-2024-23897.md) 🔴 ✅

**名称:** CVE-2024-23897 - Jenkins 任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，允许未授权的攻击者读取 Jenkins 控制器上的任意文件  
**投毒风险:** 10%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2024-23897](https://github.com/xaitax/CVE-2024-23897)  

---

### [CVE-2024-23897](CVE-2024-23897-ThatNotEasy_CVE-2024-23897.md) 🔴 ✅

**名称:** CVE-2024-23897-Jenkins-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露，进一步导致RCE  
**投毒风险:** 20%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2024-23897](https://github.com/ThatNotEasy/CVE-2024-23897)  

---

### [CVE-2024-23897](CVE-2024-23897-yoryio_CVE-2024-23897.md) 🔴 ✅

**名称:** CVE-2024-23897-Jenkins-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露，进而导致RCE  
**投毒风险:** 5%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2024-23897](https://github.com/yoryio/CVE-2024-23897)  

---

### [CVE-2024-23897](CVE-2024-23897-wjlin0_CVE-2024-23897.md) 🔴 ✅

**名称:** CVE-2024-23897-Jenkins 任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2024-23897](https://github.com/wjlin0/CVE-2024-23897)  

---

### [CVE-2024-23897](CVE-2024-23897-Vozec_CVE-2024-23897.md) 🔴 ✅

**名称:** CVE-2024-23897-Jenkins-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2024-23897](https://github.com/Vozec/CVE-2024-23897)  

---

### [CVE-2024-23897](CVE-2024-23897-JAthulya_CVE-2024-23897.md) 🔴 ✅

**名称:** CVE-2024-23897 - Jenkins Arbitrary File Read  
**类型:** Arbitrary File Read  
**风险:** 高危，可能导致敏感信息泄露和潜在的RCE  
**投毒风险:** 0%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2024-23897](https://github.com/JAthulya/CVE-2024-23897)  

---

### [CVE-2024-23897](CVE-2024-23897-murataydemir_CVE-2024-23897.md) 🔴 ✅

**名称:** CVE-2024-23897-Jenkins-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露和RCE  
**投毒风险:** 10%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2024-23897](https://github.com/murataydemir/CVE-2024-23897)  

---

### [CVE-2024-23897](CVE-2024-23897-mil4ne_CVE-2024-23897-Jenkins-4.441.md) 🔴 ✅

**名称:** CVE-2024-23897-Jenkins-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露，进一步导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2024-23897-Jenkins-4.441](https://github.com/mil4ne/CVE-2024-23897-Jenkins-4.441)  

---

### [CVE-2024-23897](CVE-2024-23897-Maalfer_CVE-2024-23897.md) 🔴 ✅

**名称:** CVE-2024-23897-Jenkins-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2024-23897](https://github.com/Maalfer/CVE-2024-23897)  

---

### [CVE-2024-23897](CVE-2024-23897-Surko888_Surko-Exploit-Jenkins-CVE-2024-23897.md) 🔴 ✅

**名称:** CVE-2024-23897-Jenkins-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-23  
**POC仓库:** [Surko-Exploit-Jenkins-CVE-2024-23897](https://github.com/Surko888/Surko-Exploit-Jenkins-CVE-2024-23897)  

---

### [CVE-2024-23897](CVE-2024-23897-cc3305_CVE-2024-23897.md) 🔴 ✅

**名称:** CVE-2024-23897 - Jenkins Arbitrary File Read  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露，为进一步攻击提供信息  
**投毒风险:** 1%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2024-23897](https://github.com/cc3305/CVE-2024-23897)  

---

### [CVE-2024-23897](CVE-2024-23897-pulentoski_CVE-2024-23897-Arbitrary-file-read.md) 🔴 ✅

**名称:** CVE-2024-23897-Jenkins-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露，权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2024-23897-Arbitrary-file-read](https://github.com/pulentoski/CVE-2024-23897-Arbitrary-file-read)  

---

### [CVE-2024-23897](CVE-2024-23897-verylazytech_CVE-2024-23897.md) 🔴 ✅

**名称:** CVE-2024-23897-Jenkins-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2024-23897](https://github.com/verylazytech/CVE-2024-23897)  

---

### [CVE-2024-23897](CVE-2024-23897-D1se0_CVE-2024-23897-Vulnerabilidad-Jenkins.md) 🔴 ✅

**名称:** CVE-2024-23897-Jenkins-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露，进一步导致远程代码执行  
**投毒风险:** 20%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2024-23897-Vulnerabilidad-Jenkins](https://github.com/D1se0/CVE-2024-23897-Vulnerabilidad-Jenkins)  

---

### [CVE-2024-23897](CVE-2024-23897-Marouane133_jenkins-lfi.md) 🔴 ✅

**名称:** CVE-2024-23897-Jenkins-Arbitrary File Read  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行（结合其他漏洞）  
**投毒风险:** 0%  
**发现时间:** 2025-03-23  
**POC仓库:** [jenkins-lfi](https://github.com/Marouane133/jenkins-lfi)  

---

### [CVE-2024-23897](CVE-2024-23897-godylockz_CVE-2024-23897.md) 🔴 ✅

**名称:** CVE-2024-23897: Jenkins 任意文件读取漏洞  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2024-23897](https://github.com/godylockz/CVE-2024-23897)  

---

### [CVE-2024-23897](CVE-2024-23897-slytechroot_CVE-2024-23897.md) 🔴 ✅

**名称:** CVE-2024-23897-Jenkins-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露和RCE（通过读取密钥等）  
**投毒风险:** 0%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2024-23897](https://github.com/slytechroot/CVE-2024-23897)  

---

### [CVE-2022-23134](CVE-2022-23134-TheN00bBuilder_cve-2022-23134-poc-and-writeup.md) 🟡 ✅

**名称:** CVE-2022-23134-Zabbix Frontend-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 中危，可能导致未经授权的配置更改和潜在的系统损害  
**投毒风险:** 1%  
**发现时间:** 2025-03-23  
**POC仓库:** [cve-2022-23134-poc-and-writeup](https://github.com/TheN00bBuilder/cve-2022-23134-poc-and-writeup)  

---

### [CVE-2024-49653](CVE-2024-49653-Nxploited_CVE-2024-49653.md) 🔴 ✅

**名称:** CVE-2024-49653-Portfolleo-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-03-23  
**POC仓库:** [CVE-2024-49653](https://github.com/Nxploited/CVE-2024-49653)  

---

### [CVE-2024-49668](CVE-2024-49668-Nxploited_CVE-2024-49668.md) 🔴 ✅

**名称:** CVE-2024-49668 - WordPress Verbalize WP Plugin Arbitrary File Upload  
**类型:** 任意文件上传  
**风险:** 高危，允许上传Web Shell并执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-03-22  
**POC仓库:** [CVE-2024-49668](https://github.com/Nxploited/CVE-2024-49668)  

---

### [CVE-2025-29927](CVE-2025-29927-Ademking_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-Authorization Bypass  
**类型:** Authorization Bypass  
**风险:** 高危，可能导致未授权访问和敏感数据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-22  
**POC仓库:** [CVE-2025-29927](https://github.com/Ademking/CVE-2025-29927)  

---

### [CVE-2025-2620](CVE-2025-2620-Otsmane-Ahmed_CVE-2025-2620-poc.md) 🔴 ✅

**名称:** CVE-2025-2620 D-Link DAP-1620 栈溢出  
**类型:** 栈溢出  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 95%  
**发现时间:** 2025-03-22  
**POC仓库:** [CVE-2025-2620-poc](https://github.com/Otsmane-Ahmed/CVE-2025-2620-poc)  

---

### [CVE-2025-29927](CVE-2025-29927-serhalp_test-cve-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-22  
**POC仓库:** [test-cve-2025-29927](https://github.com/serhalp/test-cve-2025-29927)  

---

### [CVE-2025-24813](CVE-2025-24813-tonyarris_CVE-2025-24813-PoC.md) 🔴 ✅

**名称:** CVE-2025-24813-Apache Tomcat RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-03-22  
**POC仓库:** [CVE-2025-24813-PoC](https://github.com/tonyarris/CVE-2025-24813-PoC)  

---

### [CVE-2024-13346](CVE-2024-13346-tausifzaman_CVE-2024-13346.md) 🔴 ✅

**名称:** CVE-2024-13346-Avada Theme-任意短代码执行  
**类型:** 任意短代码执行  
**风险:** 高危，可能导致远程代码执行或其他恶意操作  
**投毒风险:** 0%  
**发现时间:** 2025-03-22  
**POC仓库:** [CVE-2024-13346](https://github.com/tausifzaman/CVE-2024-13346)  

---

### [CVE-2025-1316](CVE-2025-1316-slockit_CVE-2025-1316.md) 🔴 ✅

**名称:** CVE-2025-1316-Edimax IC-7100 IP Camera-OS Command Injection  
**类型:** OS Command Injection  
**风险:** 高危，可导致远程代码执行，设备控制，可能被用于僵尸网络。  
**投毒风险:** 80%  
**发现时间:** 2025-03-22  
**POC仓库:** [CVE-2025-1316](https://github.com/slockit/CVE-2025-1316)  

---

### [CVE-2024-52375](CVE-2024-52375-Nxploited_CVE-2024-52375.md) 🔴 ✅

**名称:** CVE-2024-52375 - WordPress Datasets Manager Plugin - 任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-03-22  
**POC仓库:** [CVE-2024-52375](https://github.com/Nxploited/CVE-2024-52375)  

---

### [CVE-2025-24813](CVE-2025-24813-MuhammadWaseem29_CVE-2025-24813.md) 🔴 ✅

**名称:** CVE-2025-24813-Apache Tomcat Path Equivalence Vulnerability  
**类型:** 路径遍历/远程代码执行/信息泄露  
**风险:** 高危，可能导致远程代码执行、敏感信息泄露和任意文件上传  
**投毒风险:** 1%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2025-24813](https://github.com/MuhammadWaseem29/CVE-2025-24813)  

---

### [CVE-2025-24813](CVE-2025-24813-Alaatk_CVE-2025-24813-POC.md) 🔴 ✅

**名称:** CVE-2025-24813 Apache Tomcat 远程代码执行/信息泄露/文件篡改  
**类型:** 远程代码执行/信息泄露/文件篡改  
**风险:** 高危，可能导致远程代码执行，信息泄露，文件被篡改  
**投毒风险:** 0%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2025-24813-POC](https://github.com/Alaatk/CVE-2025-24813-POC)  

---

### [CVE-2025-30144](CVE-2025-30144-tibrn_CVE-2025-30144.md) 🟡 ✅

**名称:** CVE-2025-30144 - fast-jwt 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 中危，可能导致未经授权的访问和数据篡改  
**投毒风险:** 10%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2025-30144](https://github.com/tibrn/CVE-2025-30144)  

---

### [CVE-2024-50379](CVE-2024-50379-yiliufeng168_CVE-2024-50379-POC.md) 🔴 ✅

**名称:** CVE-2024-50379-Apache Tomcat-TOCTOU 竞争条件导致RCE  
**类型:** TOCTOU 竞争条件  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-50379-POC](https://github.com/yiliufeng168/CVE-2024-50379-POC)  

---

### [CVE-2024-50379](CVE-2024-50379-JFOZ1010_Nuclei-Template-CVE-2024-50379.md) 🔴 ✅

**名称:** CVE-2024-50379-Apache Tomcat TOCTOU RCE  
**类型:** TOCTOU Race Condition 导致的远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-21  
**POC仓库:** [Nuclei-Template-CVE-2024-50379](https://github.com/JFOZ1010/Nuclei-Template-CVE-2024-50379)  

---

### [CVE-2024-50379](CVE-2024-50379-iSee857_CVE-2024-50379-PoC.md) 🔴 ✅

**名称:** CVE-2024-50379-Apache Tomcat-TOCTOU Race Condition RCE  
**类型:** TOCTOU Race Condition RCE  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-50379-PoC](https://github.com/iSee857/CVE-2024-50379-PoC)  

---

### [CVE-2024-50379](CVE-2024-50379-Alchemist3dot14_CVE-2024-50379.md) 🔴 ✅

**名称:** CVE-2024-50379-Apache Tomcat-TOCTOU Race Condition RCE  
**类型:** TOCTOU Race Condition RCE  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-50379](https://github.com/Alchemist3dot14/CVE-2024-50379)  

---

### [CVE-2024-50379](CVE-2024-50379-ph0ebus_Tomcat-CVE-2024-50379-Poc.md) 🔴 ✅

**名称:** CVE-2024-50379-Apache Tomcat TOCTOU RCE  
**类型:** 竞争条件导致的远程代码执行  
**风险:** 高危，可远程执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-03-21  
**POC仓库:** [Tomcat-CVE-2024-50379-Poc](https://github.com/ph0ebus/Tomcat-CVE-2024-50379-Poc)  

---

### [CVE-2024-50379](CVE-2024-50379-SleepingBag945_CVE-2024-50379.md) 🔴 ✅

**名称:** CVE-2024-50379 - Apache Tomcat TOCTOU 竞争条件 RCE  
**类型:** 竞争条件导致的远程代码执行  
**风险:** 高危，可远程执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-50379](https://github.com/SleepingBag945/CVE-2024-50379)  

---

### [CVE-2024-50379](CVE-2024-50379-dear-cell_CVE-2024-50379.md) 🔴 ✅

**名称:** CVE-2024-50379-Apache Tomcat-TOCTOU Race Condition RCE  
**类型:** TOCTOU Race Condition RCE  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-50379](https://github.com/dear-cell/CVE-2024-50379)  

---

### [CVE-2024-50379](CVE-2024-50379-dragonked2_CVE-2024-50379-POC.md) 🔴 ✅

**名称:** CVE-2024-50379-Apache Tomcat-TOCTOU Race Condition RCE  
**类型:** TOCTOU Race Condition  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-50379-POC](https://github.com/dragonked2/CVE-2024-50379-POC)  

---

### [CVE-2024-50379](CVE-2024-50379-dkstar11q_CVE-2024-50379-nuclei.md) 🔴 ✅

**名称:** CVE-2024-50379-ApacheTomcat-TOCTOU Race Condition RCE  
**类型:** TOCTOU Race Condition  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-50379-nuclei](https://github.com/dkstar11q/CVE-2024-50379-nuclei)  

---

### [CVE-2024-50379](CVE-2024-50379-v3153_CVE-2024-50379-POC.md) 🔴 ✅

**名称:** CVE-2024-50379-Apache Tomcat-TOCTOU Race Condition RCE  
**类型:** TOCTOU Race Condition RCE  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-50379-POC](https://github.com/v3153/CVE-2024-50379-POC)  

---

### [CVE-2024-50379](CVE-2024-50379-lizhianyuguangming_CVE-2024-50379-exp.md) 🔴 ✅

**名称:** CVE-2024-50379-Apache Tomcat-TOCTOU RCE  
**类型:** TOCTOU 竞态条件导致远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-50379-exp](https://github.com/lizhianyuguangming/CVE-2024-50379-exp)  

---

### [CVE-2024-50379](CVE-2024-50379-pwnosec_CVE-2024-50379.md) 🔴 ✅

**名称:** CVE-2024-50379-Apache Tomcat TOCTOU Race Condition RCE  
**类型:** TOCTOU Race Condition RCE  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-50379](https://github.com/pwnosec/CVE-2024-50379)  

---

### [CVE-2024-50379](CVE-2024-50379-carefreegarb_CVE-2024-50379.md) 🔴 ✅

**名称:** CVE-2024-50379-Apache Tomcat-TOCTOU Race Condition RCE  
**类型:** TOCTOU Race Condition导致的远程代码执行  
**风险:** 高危，可以导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-50379](https://github.com/carefreegarb/CVE-2024-50379)  

---

### [CVE-2024-11040](CVE-2024-11040-gothburz_CVE-2024-11040.md) 🔴 ✅

**名称:** CVE-2024-11040-vllm-project/vllm-拒绝服务  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致服务中断  
**投毒风险:** 0%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-11040](https://github.com/gothburz/CVE-2024-11040)  

---

### [CVE-2024-11042](CVE-2024-11042-gothburz_CVE-2024-11042.md) 🔴 ✅

**名称:** CVE-2024-11042-invokeai-Arbitrary File Delete  
**类型:** 任意文件删除  
**风险:** 高危，可能导致数据丢失、服务中断、敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-11042](https://github.com/gothburz/CVE-2024-11042)  

---

### [CVE-2023-6241](CVE-2023-6241-ilGobbo00_CVE-2023-6241-Pixel7_Adaptation.md) 🔴 ✅

**名称:** CVE-2023-6241-Arm Mali GPU Kernel Driver Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，允许本地非特权用户利用软件竞态条件执行不正确的内存处理操作，进而导致任意内核代码执行和root权限获取。  
**投毒风险:** 10%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2023-6241-Pixel7_Adaptation](https://github.com/ilGobbo00/CVE-2023-6241-Pixel7_Adaptation)  

---

### [CVE-2024-9474](CVE-2024-9474-k4nfr3_CVE-2024-9474.md) 🔴 ✅

**名称:** CVE-2024-9474 PAN-OS Web管理界面权限提升漏洞  
**类型:** 权限提升/OS命令注入  
**风险:** 高危，可能导致完全系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-9474](https://github.com/k4nfr3/CVE-2024-9474)  

---

### [CVE-2025-24011](CVE-2025-24011-Puben_CVE-2025-24011-PoC.md) 🟡 ✅

**名称:** CVE-2025-24011-Umbraco CMS-用户枚举  
**类型:** 用户枚举  
**风险:** 中危，可能暴露系统中的用户名，为后续攻击提供信息  
**投毒风险:** 10%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2025-24011-PoC](https://github.com/Puben/CVE-2025-24011-PoC)  

---

### [CVE-2025-29814](CVE-2025-29814-SatiresHashi_CVE-2025-29814.md) 🔴 

**名称:** CVE-2025-29814 - Microsoft Partner Center 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 80%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2025-29814](https://github.com/SatiresHashi/CVE-2025-29814)  

---

### [CVE-2024-9474](CVE-2024-9474-Chocapikk_CVE-2024-9474.md) 🔴 ✅

**名称:** CVE-2024-9474 PAN-OS Web Management Interface Privilege Escalation  
**类型:** 权限提升/OS 命令注入  
**风险:** 中危/高危，取决于管理界面的暴露程度。若管理界面暴露于互联网，则风险较高。  
**投毒风险:** 10%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-9474](https://github.com/Chocapikk/CVE-2024-9474)  

---

### [CVE-2024-9474](CVE-2024-9474-deathvu_CVE-2024-9474.md) 🔴 ✅

**名称:** CVE-2024-9474 PAN-OS Web管理界面权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，允许具有Web管理界面访问权限的PAN-OS管理员以root权限执行操作  
**投毒风险:** 5%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-9474](https://github.com/deathvu/CVE-2024-9474)  

---

### [CVE-2024-9474](CVE-2024-9474-coskper-papa_PAN-OS_CVE-2024-9474.md) 🔴 ✅

**名称:** CVE-2024-9474 PAN-OS Web Management Interface Privilege Escalation  
**类型:** 权限提升/OS命令注入  
**风险:** 高危，允许经过身份验证的管理员以root权限执行操作。  
**投毒风险:** 10%  
**发现时间:** 2025-03-21  
**POC仓库:** [PAN-OS_CVE-2024-9474](https://github.com/coskper-papa/PAN-OS_CVE-2024-9474)  

---

### [CVE-2024-9474](CVE-2024-9474-aratane_CVE-2024-9474.md) 🔴 ✅

**名称:** CVE-2024-9474 PAN-OS Web Management Interface Privilege Escalation  
**类型:** 权限提升/OS 命令注入  
**风险:** 高危，允许具有Web管理界面访问权限的PAN-OS管理员以root权限执行操作  
**投毒风险:** 10%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-9474](https://github.com/aratane/CVE-2024-9474)  

---

### [CVE-2024-9474](CVE-2024-9474-experiencedt_CVE-2024-9474.md) 🔴 ✅

**名称:** CVE-2024-9474 PAN-OS Web 管理界面权限提升漏洞  
**类型:** 权限提升  
**风险:** 中危/高危，取决于管理界面是否暴露于互联网。如果暴露，则风险更高，可能导致系统被完全控制。  
**投毒风险:** 1%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-9474](https://github.com/experiencedt/CVE-2024-9474)  

---

### [CVE-2023-21839](CVE-2023-21839-fakenews2025_CVE-2023-21839.md) 🔴 ✅

**名称:** CVE-2023-21839 WebLogic Server 远程信息泄露漏洞  
**类型:** 信息泄露  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 80%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2023-21839](https://github.com/fakenews2025/CVE-2023-21839)  

---

### [CVE-2023-21839](CVE-2023-21839-ASkyeye_CVE-2023-21839.md) 🔴 ✅

**名称:** CVE-2023-21839-Oracle WebLogic Server-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未授权的攻击者通过网络访问执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2023-21839](https://github.com/ASkyeye/CVE-2023-21839)  

---

### [CVE-2023-21839](CVE-2023-21839-DXask88MA_Weblogic-CVE-2023-21839.md) 🔴 ✅

**名称:** CVE-2023-21839-Oracle WebLogic Server-未经身份验证的远程数据访问  
**类型:** 未授权访问  
**风险:** 高危，可能导致未经授权的关键数据访问  
**投毒风险:** 0%  
**发现时间:** 2025-03-21  
**POC仓库:** [Weblogic-CVE-2023-21839](https://github.com/DXask88MA/Weblogic-CVE-2023-21839)  

---

### [CVE-2023-21839](CVE-2023-21839-Firebasky_CVE-2023-21839.md) 🔴 ✅

**名称:** CVE-2023-21839 Oracle WebLogic Server 未授权访问漏洞  
**类型:** 未授权访问  
**风险:** 高危，可能导致数据泄露或完全控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2023-21839](https://github.com/Firebasky/CVE-2023-21839)  

---

### [CVE-2023-21839](CVE-2023-21839-houqe_POC_CVE-2023-21839.md) 🔴 ✅

**名称:** CVE-2023-21839 Oracle WebLogic Server 远程信息泄露漏洞  
**类型:** 信息泄露  
**风险:** 高危，可能导致未经授权访问关键数据  
**投毒风险:** 5%  
**发现时间:** 2025-03-21  
**POC仓库:** [POC_CVE-2023-21839](https://github.com/houqe/POC_CVE-2023-21839)  

---

### [CVE-2023-21839](CVE-2023-21839-kw3h4_CVE-2023-21839-metasploit-scanner.md) 🔴 ✅

**名称:** CVE-2023-21839 Oracle WebLogic Server 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，未经授权访问敏感数据或完全访问所有Oracle WebLogic Server可访问数据  
**投毒风险:** 10%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2023-21839-metasploit-scanner](https://github.com/kw3h4/CVE-2023-21839-metasploit-scanner)  

---

### [CVE-2023-21839](CVE-2023-21839-illegalbrea_CVE-2023-21839.md) 🔴 ✅

**名称:** CVE-2023-21839 Oracle WebLogic Server 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者通过网络访问执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2023-21839](https://github.com/illegalbrea/CVE-2023-21839)  

---

### [CVE-2016-10924](CVE-2016-10924-rvizx_CVE-2016-10924.md) 🔴 ✅

**名称:** CVE-2016-10924-ebook-download-Directory Traversal  
**类型:** Directory Traversal  
**风险:** 高危，可能导致敏感文件泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2016-10924](https://github.com/rvizx/CVE-2016-10924)  

---

### [CVE-2016-10924](CVE-2016-10924-LGenAgul_Wordpress-ebook-CVE-2016-10924.md) 🔴 ✅

**名称:** CVE-2016-10924 - WordPress ebook-download插件目录遍历漏洞  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感文件泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-21  
**POC仓库:** [Wordpress-ebook-CVE-2016-10924](https://github.com/LGenAgul/Wordpress-ebook-CVE-2016-10924)  

---

### [CVE-2016-10924](CVE-2016-10924-808ale_cve-2016-10924-POC.md) 🟡 ✅

**名称:** CVE-2016-10924 - WordPress ebook-download插件目录遍历  
**类型:** 目录遍历  
**风险:** 中危，可能读取服务器上的敏感文件  
**投毒风险:** 0%  
**发现时间:** 2025-03-21  
**POC仓库:** [cve-2016-10924-POC](https://github.com/808ale/cve-2016-10924-POC)  

---

### [CVE-2025-23922](CVE-2025-23922-Nxploited_CVE-2025-23922.md) 🔴 ✅

**名称:** CVE-2025-23922 - WordPress iSpring Embedder CSRF to Arbitrary File Upload  
**类型:** CSRF to Arbitrary File Upload  
**风险:** 高危，可能导致远程代码执行和服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2025-23922](https://github.com/Nxploited/CVE-2025-23922)  

---

### [CVE-2024-4577](CVE-2024-4577-mr-won_php-cgi-cve-2024-4577.md) 🔴 ✅

**名称:** CVE-2024-4577-PHP-CGI参数注入  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-21  
**POC仓库:** [php-cgi-cve-2024-4577](https://github.com/mr-won/php-cgi-cve-2024-4577)  

---

### [CVE-2024-4577](CVE-2024-4577-K3ysTr0K3R_CVE-2024-4577-EXPLOIT.md)  ✅

**名称:** CVE-2024-4577-PHP-CGI参数注入  
**类型:** 远程代码执行  
**风险:** 严重，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-4577-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2024-4577-EXPLOIT)  

---

### [CVE-2024-4577](CVE-2024-4577-ggfzx_CVE-2024-4577.md) 🔴 ✅

**名称:** CVE-2024-4577 PHP-CGI 参数注入漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的攻击者在Windows服务器上执行任意代码  
**投毒风险:** 20%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-4577](https://github.com/ggfzx/CVE-2024-4577)  

---

### [CVE-2024-4577](CVE-2024-4577-olebris_CVE-2024-4577.md) 🔴 ✅

**名称:** CVE-2024-4577-PHP-CGI参数注入  
**类型:** 参数注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-4577](https://github.com/olebris/CVE-2024-4577)  

---

### [CVE-2024-4577](CVE-2024-4577-AlperenY-cs_CVE-2024-4577.md) 🔴 ✅

**名称:** CVE-2024-4577 - PHP-CGI Argument Injection RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致远程代码执行、源码泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-4577](https://github.com/AlperenY-cs/CVE-2024-4577)  

---

### [CVE-2024-4577](CVE-2024-4577-charis3306_CVE-2024-4577.md) 🔴 ✅

**名称:** CVE-2024-4577 PHP-CGI 参数注入远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-4577](https://github.com/charis3306/CVE-2024-4577)  

---

### [CVE-2024-4577](CVE-2024-4577-l0n3m4n_CVE-2024-4577-RCE.md) 🔴 ✅

**名称:** CVE-2024-4577 PHP CGI Argument Injection  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致远程代码执行，服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-4577-RCE](https://github.com/l0n3m4n/CVE-2024-4577-RCE)  

---

### [CVE-2024-4577](CVE-2024-4577-bibo318_CVE-2024-4577-RCE-ATTACK.md) 🔴 ✅

**名称:** CVE-2024-4577 PHP-CGI 参数注入远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者在Windows服务器上执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-4577-RCE-ATTACK](https://github.com/bibo318/CVE-2024-4577-RCE-ATTACK)  

---

### [CVE-2024-4577](CVE-2024-4577-xcanwin_CVE-2024-4577-PHP-RCE.md) 🔴 ✅

**名称:** CVE-2024-4577 PHP-CGI RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者在受影响的服务器上执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-4577-PHP-RCE](https://github.com/xcanwin/CVE-2024-4577-PHP-RCE)  

---

### [CVE-2024-4577](CVE-2024-4577-a-roshbaik_CVE-2024-4577-PHP-RCE.md) 🔴 ✅

**名称:** CVE-2024-4577-PHP-CGI远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者在受影响的服务器上执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-4577-PHP-RCE](https://github.com/a-roshbaik/CVE-2024-4577-PHP-RCE)  

---

### [CVE-2024-4577](CVE-2024-4577-VictorShem_CVE-2024-4577.md) 🔴 ✅

**名称:** CVE-2024-4577 - PHP CGI Argument Injection  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者在服务器上执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-4577](https://github.com/VictorShem/CVE-2024-4577)  

---

### [CVE-2024-4577](CVE-2024-4577-Jcccccx_CVE-2024-4577.md)  ✅

**名称:** CVE-2024-4577 PHP-CGI Argument Injection RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致完全控制受影响的Windows服务器  
**投毒风险:** 0%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-4577](https://github.com/Jcccccx/CVE-2024-4577)  

---

### [CVE-2024-4577](CVE-2024-4577-Entropt_CVE-2024-4577_Analysis.md) 🔴 ✅

**名称:** CVE-2024-4577 PHP-CGI Argument Injection  
**类型:** OS Command Injection  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-4577_Analysis](https://github.com/Entropt/CVE-2024-4577_Analysis)  

---

### [CVE-2024-4577](CVE-2024-4577-bughuntar_CVE-2024-4577.md) 🔴 ✅

**名称:** CVE-2024-4577-PHP-CGI Argument Injection  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行，服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-4577](https://github.com/bughuntar/CVE-2024-4577)  

---

### [CVE-2024-4577](CVE-2024-4577-gh-ost00_CVE-2024-4577-RCE.md) 🔴 ✅

**名称:** CVE-2024-4577 PHP CGI Argument Injection RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者在Windows服务器上执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-4577-RCE](https://github.com/gh-ost00/CVE-2024-4577-RCE)  

---

### [CVE-2024-4577](CVE-2024-4577-waived_CVE-2024-4577-PHP-RCE.md) 🔴 ✅

**名称:** CVE-2024-4577-PHP-CGI参数注入  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-4577-PHP-RCE](https://github.com/waived/CVE-2024-4577-PHP-RCE)  

---

### [CVE-2024-4577](CVE-2024-4577-aaddmin1122345_cve-2024-4577.md) 🔴 ✅

**名称:** CVE-2024-4577 PHP-CGI Argument Injection  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者在Windows服务器上执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-03-21  
**POC仓库:** [cve-2024-4577](https://github.com/aaddmin1122345/cve-2024-4577)  

---

### [CVE-2024-4577](CVE-2024-4577-ywChen-NTUST_PHP-CGI-RCE-Scanner.md)  ✅

**名称:** CVE-2024-4577-PHP-CGI参数注入  
**类型:** PHP-CGI参数注入/远程代码执行  
**风险:** 严重，可能导致远程代码执行，信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-03-21  
**POC仓库:** [PHP-CGI-RCE-Scanner](https://github.com/ywChen-NTUST/PHP-CGI-RCE-Scanner)  

---

### [CVE-2024-4577](CVE-2024-4577-phirojshah_CVE-2024-4577.md) 🔴 ✅

**名称:** CVE-2024-4577 PHP-CGI 参数注入远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-4577](https://github.com/phirojshah/CVE-2024-4577)  

---

### [CVE-2024-4577](CVE-2024-4577-longhoangth18_CVE-2024-4577.md) 🔴 ✅

**名称:** CVE-2024-4577-PHP-CGI参数注入  
**类型:** PHP-CGI参数注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-4577](https://github.com/longhoangth18/CVE-2024-4577)  

---

### [CVE-2024-4577](CVE-2024-4577-ahmetramazank_CVE-2024-4577.md) 🔴 ✅

**名称:** CVE-2024-4577 PHP-CGI 参数注入导致远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的攻击者在受影响的Windows服务器上执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-4577](https://github.com/ahmetramazank/CVE-2024-4577)  

---

### [CVE-2024-4577](CVE-2024-4577-JeninSutradhar_CVE-2024-4577-checker.md) 🔴 ✅

**名称:** CVE-2024-4577-PHP-CGI参数注入  
**类型:** 参数注入  
**风险:** 高危，可能导致远程代码执行、源码泄露  
**投毒风险:** 1%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-4577-checker](https://github.com/JeninSutradhar/CVE-2024-4577-checker)  

---

### [CVE-2024-4577](CVE-2024-4577-BTtea_CVE-2024-4577-RCE-PoC.md) 🔴 ✅

**名称:** CVE-2024-4577-PHP-CGI Argument Injection  
**类型:** OS Command Injection  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-4577-RCE-PoC](https://github.com/BTtea/CVE-2024-4577-RCE-PoC)  

---

### [CVE-2024-4577](CVE-2024-4577-Dejavu666_CVE-2024-4577.md)  ✅

**名称:** CVE-2024-4577 PHP-CGI Argument Injection  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，允许未经身份验证的攻击者在目标服务器上执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-4577](https://github.com/Dejavu666/CVE-2024-4577)  

---

### [CVE-2024-4577](CVE-2024-4577-Didarul342_CVE-2024-4577.md) 🔴 ✅

**名称:** CVE-2024-4577 PHP-CGI Argument Injection  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-4577](https://github.com/Didarul342/CVE-2024-4577)  

---

### [CVE-2024-4577](CVE-2024-4577-sug4r-wr41th_CVE-2024-4577.md) 🔴 ✅

**名称:** CVE-2024-4577-PHP-CGI参数注入  
**类型:** PHP-CGI参数注入  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-4577](https://github.com/sug4r-wr41th/CVE-2024-4577)  

---

### [CVE-2024-4577](CVE-2024-4577-Night-have-dreams_php-cgi-Injector.md) 🔴 ✅

**名称:** CVE-2024-4577 PHP-CGI 参数注入 RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致远程代码执行，服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-21  
**POC仓库:** [php-cgi-Injector](https://github.com/Night-have-dreams/php-cgi-Injector)  

---

### [CVE-2024-4577](CVE-2024-4577-mistakes1337_CVE-2024-4577.md) 🔴 ✅

**名称:** CVE-2024-4577-PHP-CGI参数注入RCE  
**类型:** 远程代码执行（RCE）  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2024-4577](https://github.com/mistakes1337/CVE-2024-4577)  

---

### [CVE-2025-24071](CVE-2025-24071-shacojx_CVE-2025-24071-Exploit.md) 🟡 ✅

**名称:** CVE-2025-24071-Windows File Explorer Spoofing  
**类型:** 信息泄露/欺骗  
**风险:** 中危，可能导致信息泄露和网络欺骗  
**投毒风险:** 5%  
**发现时间:** 2025-03-21  
**POC仓库:** [CVE-2025-24071-Exploit](https://github.com/shacojx/CVE-2025-24071-Exploit)  

---

### [CVE-2025-00000](CVE-2025-00000-nsvizp_cve-2025-0000000.md)  ✅

**名称:** CVE-2025-0000000-Unknown  
**类型:** 未知  
**风险:** 低危，仅包含测试信息  
**投毒风险:** 10%  
**发现时间:** 2025-03-21  
**POC仓库:** [cve-2025-0000000](https://github.com/nsvizp/cve-2025-0000000)  

---

### [CVE-2025-24813](CVE-2025-24813-n0n-zer0_Spring-Boot-Tomcat-CVE-2025-24813.md) 🔴 ✅

**名称:** CVE-2025-24813-Apache Tomcat-RCE/信息泄露/恶意内容注入  
**类型:** 远程代码执行/信息泄露/恶意内容注入  
**风险:** 高危，可能导致远程代码执行、敏感信息泄露或恶意内容被注入到上传的文件中  
**投毒风险:** 5%  
**发现时间:** 2025-03-20  
**POC仓库:** [Spring-Boot-Tomcat-CVE-2025-24813](https://github.com/n0n-zer0/Spring-Boot-Tomcat-CVE-2025-24813)  

---

### [CVE-2023-45878](CVE-2023-45878-killercd_CVE-2023-45878.md) 🔴 ✅

**名称:** CVE-2023-45878-GibbonEdu-Arbitrary File Write  
**类型:** 任意文件写入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2023-45878](https://github.com/killercd/CVE-2023-45878)  

---

### [CVE-2021-41773](CVE-2021-41773-ashique-thaha_CVE-2021-41773-POC.md) 🔴 ✅

**名称:** CVE-2021-41773-Apache HTTP Server Path Traversal  
**类型:** 路径遍历（Path Traversal）/远程代码执行（RCE）  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2021-41773-POC](https://github.com/ashique-thaha/CVE-2021-41773-POC)  

---

### [CVE-2023-37979](CVE-2023-37979-d0rb_CVE-2023-37979.md) 🔴 ✅

**名称:** CVE-2023-37979-Ninja Forms Contact Form-Reflected XSS  
**类型:** Reflected XSS  
**风险:** 高危，可能导致任意代码执行，权限提升等  
**投毒风险:** 10%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2023-37979](https://github.com/d0rb/CVE-2023-37979)  

---

### [CVE-2023-37979](CVE-2023-37979-Mehran-Seifalinia_CVE-2023-37979.md) 🟡 ✅

**名称:** CVE-2023-37979-Ninja Forms Contact Form-Reflected XSS  
**类型:** Reflected XSS  
**风险:** 中危，可能导致会话劫持、钓鱼攻击等  
**投毒风险:** 1%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2023-37979](https://github.com/Mehran-Seifalinia/CVE-2023-37979)  

---

### [CVE-2016-10002](CVE-2016-10002-ossf-cve-benchmark_CVE-2016-1000229.md) 🟡 

**名称:** CVE-2016-10002-Squid HTTP Proxy-信息泄露  
**类型:** 信息泄露  
**风险:** 中危，可能导致Cookie数据等敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2016-1000229](https://github.com/ossf-cve-benchmark/CVE-2016-1000229)  

---

### [CVE-2016-10002](CVE-2016-10002-barteeees_SwaggerUI-CVE-2016-1000229.md) 🟡 ✅

**名称:** CVE-2016-10002-Squid-信息泄露  
**类型:** 信息泄露  
**风险:** 中危，可能导致Cookie数据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-03-20  
**POC仓库:** [SwaggerUI-CVE-2016-1000229](https://github.com/barteeees/SwaggerUI-CVE-2016-1000229)  

---

### [CVE-2025-2476](CVE-2025-2476-McTavishSue_CVE-2025-2476.md) 🔴 

**名称:** CVE-2025-2476-Google Chrome Lens Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可能导致远程代码执行、堆损坏、信息泄露  
**投毒风险:** 95%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2025-2476](https://github.com/McTavishSue/CVE-2025-2476)  

---

### [CVE-2023-45878](CVE-2023-45878-PaulDHaes_CVE-2023-45878-POC.md) 🔴 ✅

**名称:** CVE-2023-45878-GibbonEdu-任意文件写入  
**类型:** 任意文件写入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2023-45878-POC](https://github.com/PaulDHaes/CVE-2023-45878-POC)  

---

### [CVE-2024-48591](CVE-2024-48591-GCatt-AS_CVE-2024-48591.md) 🟡 ✅

**名称:** CVE-2024-48591-Inflectra SpiraTeam-XSS  
**类型:** XSS  
**风险:** 中危，可能导致权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2024-48591](https://github.com/GCatt-AS/CVE-2024-48591)  

---

### [CVE-2024-38063](CVE-2024-38063-noradlb1_CVE-2024-38063-VB.md) 🔴 ✅

**名称:** CVE-2024-38063 Windows TCP/IP 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者远程执行任意代码  
**投毒风险:** 20%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2024-38063-VB](https://github.com/noradlb1/CVE-2024-38063-VB)  

---

### [CVE-2024-38063](CVE-2024-38063-almogopp_Disable-IPv6-CVE-2024-38063-Fix.md) 🔴 

**名称:** CVE-2024-38063 Windows TCP/IP 远程代码执行漏洞缓解脚本  
**类型:** 远程代码执行漏洞缓解  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-20  
**POC仓库:** [Disable-IPv6-CVE-2024-38063-Fix](https://github.com/almogopp/Disable-IPv6-CVE-2024-38063-Fix)  

---

### [CVE-2024-38063](CVE-2024-38063-dweger-scripts_CVE-2024-38063-Remediation.md) 🔴 ✅

**名称:** CVE-2024-38063 Windows TCP/IP 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许远程攻击者在目标系统上执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2024-38063-Remediation](https://github.com/dweger-scripts/CVE-2024-38063-Remediation)  

---

### [CVE-2024-38063](CVE-2024-38063-haroonawanofficial_CVE-2024-38063-Research-Tool.md)  ✅

**名称:** CVE-2024-38063-Windows TCP/IP远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 严重，可能导致远程代码执行，完全控制受影响系统  
**投毒风险:** 30%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2024-38063-Research-Tool](https://github.com/haroonawanofficial/CVE-2024-38063-Research-Tool)  

---

### [CVE-2024-38063](CVE-2024-38063-ynwarcs_CVE-2024-38063.md) 🔴 ✅

**名称:** CVE-2024-38063 Windows TCP/IP 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2024-38063](https://github.com/ynwarcs/CVE-2024-38063)  

---

### [CVE-2024-38063](CVE-2024-38063-patchpoint_CVE-2024-38063.md)  ✅

**名称:** CVE-2024-38063: Windows TCP/IP 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2024-38063](https://github.com/patchpoint/CVE-2024-38063)  

---

### [CVE-2024-38063](CVE-2024-38063-PumpkinBridge_Windows-CVE-2024-38063.md) 🔴 ✅

**名称:** CVE-2024-38063 Windows TCP/IP IPv6 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致系统崩溃或远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-20  
**POC仓库:** [Windows-CVE-2024-38063](https://github.com/PumpkinBridge/Windows-CVE-2024-38063)  

---

### [CVE-2024-38063](CVE-2024-38063-zenzue_CVE-2024-38063-POC.md) 🔴 ✅

**名称:** CVE-2024-38063-Windows TCP/IP远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2024-38063-POC](https://github.com/zenzue/CVE-2024-38063-POC)  

---

### [CVE-2024-38063](CVE-2024-38063-Sachinart_CVE-2024-38063-poc.md) 🔴 ✅

**名称:** CVE-2024-38063 - Windows TCP/IP 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2024-38063-poc](https://github.com/Sachinart/CVE-2024-38063-poc)  

---

### [CVE-2024-38063](CVE-2024-38063-AdminPentester_CVE-2024-38063-.md)  ✅

**名称:** CVE-2024-38063 - Windows TCP/IP Remote Code Execution Vulnerability  
**类型:** 远程代码执行  
**风险:** 严重，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2024-38063-](https://github.com/AdminPentester/CVE-2024-38063-)  

---

### [CVE-2024-38063](CVE-2024-38063-Th3Tr1ckst3r_CVE-2024-38063.md)  ✅

**名称:** CVE-2024-38063-Windows TCP/IP远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 严重，可能导致系统完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2024-38063](https://github.com/Th3Tr1ckst3r/CVE-2024-38063)  

---

### [CVE-2024-38063](CVE-2024-38063-ps-interactive_cve-2024-38063.md) 🔴 ✅

**名称:** CVE-2024-38063-Windows TCP/IP远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统控制  
**投毒风险:** 5%  
**发现时间:** 2025-03-20  
**POC仓库:** [cve-2024-38063](https://github.com/ps-interactive/cve-2024-38063)  

---

### [CVE-2024-38063](CVE-2024-38063-brownpanda29_Cve-2024-38063.md) 🔴 ✅

**名称:** CVE-2024-38063-Windows TCP/IP远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在目标系统上执行任意代码。  
**投毒风险:** 5%  
**发现时间:** 2025-03-20  
**POC仓库:** [Cve-2024-38063](https://github.com/brownpanda29/Cve-2024-38063)  

---

### [CVE-2024-38063](CVE-2024-38063-KernelKraze_CVE-2024-38063_PoC.md) 🔴 ✅

**名称:** CVE-2024-38063 Windows TCP/IP 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2024-38063_PoC](https://github.com/KernelKraze/CVE-2024-38063_PoC)  

---

### [CVE-2024-38063](CVE-2024-38063-FrancescoDiSalesGithub_quick-fix-cve-2024-38063.md) 🔴 ✅

**名称:** CVE-2024-38063-Windows TCP/IP RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致完全控制目标系统  
**投毒风险:** 0%  
**发现时间:** 2025-03-20  
**POC仓库:** [quick-fix-cve-2024-38063](https://github.com/FrancescoDiSalesGithub/quick-fix-cve-2024-38063)  

---

### [CVE-2024-38063](CVE-2024-38063-Faizan-Khanx_CVE-2024-38063.md)  ✅

**名称:** CVE-2024-38063 Windows TCP/IP 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致系统完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2024-38063](https://github.com/Faizan-Khanx/CVE-2024-38063)  

---

### [CVE-2024-38063](CVE-2024-38063-ArenaldyP_CVE-2024-38063-Medium.md) 🔴 ✅

**名称:** CVE-2024-38063 Windows TCP/IP 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2024-38063-Medium](https://github.com/ArenaldyP/CVE-2024-38063-Medium)  

---

### [CVE-2024-38063](CVE-2024-38063-lnx-dvlpr_cve-2024-38063.md) 🔴 ✅

**名称:** CVE-2024-38063 - Windows TCP/IP 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可导致系统崩溃（蓝屏）和远程代码执行。  
**投毒风险:** 0%  
**发现时间:** 2025-03-20  
**POC仓库:** [cve-2024-38063](https://github.com/lnx-dvlpr/cve-2024-38063)  

---

### [CVE-2024-38063](CVE-2024-38063-idkwastaken_CVE-2024-38063.md) 🔴 ✅

**名称:** CVE-2024-38063 Windows TCP/IP 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致系统崩溃或远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2024-38063](https://github.com/idkwastaken/CVE-2024-38063)  

---

### [CVE-2024-38063](CVE-2024-38063-thanawee321_CVE-2024-38063.md)  ✅

**名称:** CVE-2024-38063-Windows TCP/IP远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 严重，可能导致完全系统控制  
**投毒风险:** 5%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2024-38063](https://github.com/thanawee321/CVE-2024-38063)  

---

### [CVE-2024-38063](CVE-2024-38063-AliHj98_cve-2024-38063-Anonyvader.md) 🔴 ✅

**名称:** CVE-2024-38063-Windows TCP/IP 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许远程攻击者在目标系统上执行任意代码。  
**投毒风险:** 0%  
**发现时间:** 2025-03-20  
**POC仓库:** [cve-2024-38063-Anonyvader](https://github.com/AliHj98/cve-2024-38063-Anonyvader)  

---

### [CVE-2024-38063](CVE-2024-38063-becrevex_CVE-2024-38063.md)  ✅

**名称:** CVE-2024-38063-Windows TCP/IP 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 严重，可能导致系统完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2024-38063](https://github.com/becrevex/CVE-2024-38063)  

---

### [CVE-2024-38063](CVE-2024-38063-selenagomez25_CVE-2024-38063.md)  ✅

**名称:** CVE-2024-38063 Windows TCP/IP 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 严重，远程代码执行可能导致完全系统控制  
**投毒风险:** 5%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2024-38063](https://github.com/selenagomez25/CVE-2024-38063)  

---

### [CVE-2024-38063](CVE-2024-38063-Dragkob_CVE-2024-38063.md) 🔴 ✅

**名称:** CVE-2024-38063 - Windows TCP/IP 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在目标系统上执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2024-38063](https://github.com/Dragkob/CVE-2024-38063)  

---

### [CVE-2024-38063](CVE-2024-38063-Laukage_Windows-CVE-2024-38063.md)  

**名称:** CVE-2024-38063 Windows TCP/IP 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 严重，可导致系统完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-03-20  
**POC仓库:** [Windows-CVE-2024-38063](https://github.com/Laukage/Windows-CVE-2024-38063)  

---

### [CVE-2024-38063](CVE-2024-38063-jip-0-0-0-0-0_CVE-2024-38063-scanner.md) 🔴 ✅

**名称:** CVE-2024-38063 Windows TCP/IP 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2024-38063-scanner](https://github.com/jip-0-0-0-0-0/CVE-2024-38063-scanner)  

---

### [CVE-2024-38063](CVE-2024-38063-ThemeHackers_CVE-2024-38063.md) 🔴 ✅

**名称:** CVE-2024-38063-Windows TCP/IP 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2024-38063](https://github.com/ThemeHackers/CVE-2024-38063)  

---

### [CVE-2023-0830](CVE-2023-0830-xbz0n_CVE-2023-0830.md) 🔴 ✅

**名称:** CVE-2023-0830 - EasyNAS backup.pl 操作系统命令注入  
**类型:** 操作系统命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2023-0830](https://github.com/xbz0n/CVE-2023-0830)  

---

### [CVE-2024-2242](CVE-2024-2242-RandomRobbieBF_CVE-2024-2242.md) 🟡 ✅

**名称:** CVE-2024-2242-Contact Form 7-Reflected XSS  
**类型:** Reflected XSS  
**风险:** 中危，可能导致用户会话劫持、恶意代码执行等  
**投毒风险:** 0%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2024-2242](https://github.com/RandomRobbieBF/CVE-2024-2242)  

---

### [CVE-2024-2242](CVE-2024-2242-Zzl0y_CVE-2024-2242.md) 🟡 ✅

**名称:** CVE-2024-2242-Contact Form 7-Reflected XSS  
**类型:** Reflected XSS  
**风险:** 中危，可能允许攻击者执行任意Web脚本  
**投毒风险:** 10%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2024-2242](https://github.com/Zzl0y/CVE-2024-2242)  

---

### [CVE-2024-48590](CVE-2024-48590-GCatt-AS_CVE-2024-48590.md) 🔴 ✅

**名称:** CVE-2024-48590-Inflectra SpiraTeam-SSRF  
**类型:** SSRF  
**风险:** 高危，可能导致权限提升和信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2024-48590](https://github.com/GCatt-AS/CVE-2024-48590)  

---

### [CVE-2020-7247](CVE-2020-7247-r0lh_CVE-2020-7247.md) 🔴 ✅

**名称:** CVE-2020-7247-OpenSMTPD-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致以root权限执行任意命令  
**投毒风险:** 5%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2020-7247](https://github.com/r0lh/CVE-2020-7247)  

---

### [CVE-2020-7247](CVE-2020-7247-FiroSolutions_cve-2020-7247-exploit.md) 🔴 ✅

**名称:** CVE-2020-7247-OpenSMTPD-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致root权限下的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-20  
**POC仓库:** [cve-2020-7247-exploit](https://github.com/FiroSolutions/cve-2020-7247-exploit)  

---

### [CVE-2020-7247](CVE-2020-7247-bytescrappers_CVE-2020-7247.md) 🔴 ✅

**名称:** CVE-2020-7247-OpenSMTPD-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许远程攻击者以root权限执行任意命令  
**投毒风险:** 0%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2020-7247](https://github.com/bytescrappers/CVE-2020-7247)  

---

### [CVE-2020-7247](CVE-2020-7247-QTranspose_CVE-2020-7247-exploit.md) 🔴 ✅

**名称:** CVE-2020-7247-OpenSMTPD-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致完全控制目标系统  
**投毒风险:** 0%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2020-7247-exploit](https://github.com/QTranspose/CVE-2020-7247-exploit)  

---

### [CVE-2020-7247](CVE-2020-7247-f4T1H21_CVE-2020-7247.md) 🔴 ✅

**名称:** CVE-2020-7247 OpenSMTPD 远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，允许远程攻击者以root权限执行任意命令  
**投毒风险:** 0%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2020-7247](https://github.com/f4T1H21/CVE-2020-7247)  

---

### [CVE-2020-7247](CVE-2020-7247-superzerosec_cve-2020-7247.md) 🔴 ✅

**名称:** CVE-2020-7247-OpenSMTPD-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致完全控制受影响的服务器  
**投毒风险:** 10%  
**发现时间:** 2025-03-20  
**POC仓库:** [cve-2020-7247](https://github.com/superzerosec/cve-2020-7247)  

---

### [CVE-2020-7247](CVE-2020-7247-SimonSchoeni_CVE-2020-7247-POC.md) 🔴 ✅

**名称:** CVE-2020-7247 - OpenSMTPD 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许远程攻击者以 root 权限执行任意命令  
**投毒风险:** 1%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2020-7247-POC](https://github.com/SimonSchoeni/CVE-2020-7247-POC)  

---

### [CVE-2020-7247](CVE-2020-7247-presentdaypresenttime_shai_hulud.md) 🔴 ✅

**名称:** CVE-2020-7247 - OpenSMTPD 远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-20  
**POC仓库:** [shai_hulud](https://github.com/presentdaypresenttime/shai_hulud)  

---

### [CVE-2020-7247](CVE-2020-7247-minhluannguyen_CVE-2020-7247-reproducer.md) 🔴 ✅

**名称:** CVE-2020-7247-OpenSMTPD-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2020-7247-reproducer](https://github.com/minhluannguyen/CVE-2020-7247-reproducer)  

---

### [CVE-2024-32962](CVE-2024-32962-absholi7ly_Poc-CVE-2024-32962-xml-crypto.md) 🔴 ✅

**名称:** CVE-2024-32962-xml-crypto-签名伪造  
**类型:** XML签名验证绕过  
**风险:** 高危，可能导致身份伪造和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-03-20  
**POC仓库:** [Poc-CVE-2024-32962-xml-crypto](https://github.com/absholi7ly/Poc-CVE-2024-32962-xml-crypto)  

---

### [CVE-2024-44313](CVE-2024-44313-cnetsec_CVE-2024-44313.md) 🟡 ✅

**名称:** CVE-2024-44313-TastyIgniter-未授权访问  
**类型:** 未授权访问  
**风险:** 中危，可能导致敏感信息泄露，如订单信息和发票数据  
**投毒风险:** 10%  
**发现时间:** 2025-03-20  
**POC仓库:** [CVE-2024-44313](https://github.com/cnetsec/CVE-2024-44313)  

---

### [CVE-2025-24071](CVE-2025-24071-ctabango_CVE-2025-24071_PoCExtra.md) 🟡 ✅

**名称:** CVE-2025-24071 Microsoft Windows File Explorer Spoofing Vulnerability  
**类型:** 欺骗漏洞 (Spoofing)  
**风险:** 中危，可能导致敏感信息泄露和SMB relay攻击  
**投毒风险:** 0%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2025-24071_PoCExtra](https://github.com/ctabango/CVE-2025-24071_PoCExtra)  

---

### [CVE-2025-24813](CVE-2025-24813-ps-interactive_lab-cve-2025-24813.md) 🔴 ✅

**名称:** CVE-2025-24813-Apache Tomcat-路径遍历/反序列化RCE  
**类型:** 路径遍历/反序列化RCE  
**风险:** 高危，可能导致信息泄露和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-03-19  
**POC仓库:** [lab-cve-2025-24813](https://github.com/ps-interactive/lab-cve-2025-24813)  

---

### [CVE-2021-41773](CVE-2021-41773-MatanelGordon_docker-cve-2021-41773.md) 🔴 ✅

**名称:** CVE-2021-41773 - Apache HTTP Server Path Traversal  
**类型:** 路径遍历 (Path Traversal)  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-03-19  
**POC仓库:** [docker-cve-2021-41773](https://github.com/MatanelGordon/docker-cve-2021-41773)  

---

### [CVE-2021-41773](CVE-2021-41773-wangfly-me_Apache_Penetration_Tool.md) 🔴 ✅

**名称:** CVE-2021-41773 - Apache HTTP Server Path Traversal  
**类型:** 路径遍历 (Path Traversal)  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-19  
**POC仓库:** [Apache_Penetration_Tool](https://github.com/wangfly-me/Apache_Penetration_Tool)  

---

### [CVE-2021-41773](CVE-2021-41773-aqiao-jashell_CVE-2021-41773.md) 🔴 ✅

**名称:** CVE-2021-41773 - Apache HTTP Server Path Traversal and Remote Code Execution  
**类型:** Path Traversal / Remote Code Execution  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2021-41773](https://github.com/aqiao-jashell/CVE-2021-41773)  

---

### [CVE-2021-41773](CVE-2021-41773-0xGabe_Apache-CVEs.md) 🔴 ✅

**名称:** CVE-2021-41773 - Apache HTTP Server Path Traversal and Remote Code Execution  
**类型:** 路径遍历/远程代码执行  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-03-19  
**POC仓库:** [Apache-CVEs](https://github.com/0xGabe/Apache-CVEs)  

---

### [CVE-2021-41773](CVE-2021-41773-OfriOuzan_CVE-2021-41773_CVE-2021-42013_Exploits.md) 🔴 ✅

**名称:** CVE-2021-41773/CVE-2021-42013 Apache HTTP Server Path Traversal and RCE  
**类型:** Path Traversal and Remote Code Execution  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2021-41773_CVE-2021-42013_Exploits](https://github.com/OfriOuzan/CVE-2021-41773_CVE-2021-42013_Exploits)  

---

### [CVE-2021-41773](CVE-2021-41773-belajarqywok_CVE-2021-41773-MSF.md) 🔴 ✅

**名称:** CVE-2021-41773 Apache HTTP Server Path Traversal  
**类型:** 路径遍历  
**风险:** 高危，可能导致文件泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2021-41773-MSF](https://github.com/belajarqywok/CVE-2021-41773-MSF)  

---

### [CVE-2021-41773](CVE-2021-41773-mightysai1997_CVE-2021-41773h.md) 🔴 ✅

**名称:** CVE-2021-41773-Apache HTTP Server Path Traversal  
**类型:** 路径遍历 (Path Traversal)  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2021-41773h](https://github.com/mightysai1997/CVE-2021-41773h)  

---

### [CVE-2021-41773](CVE-2021-41773-mightysai1997_CVE-2021-41773-i-.md) 🔴 ✅

**名称:** CVE-2021-41773 - Apache HTTP Server Path Traversal  
**类型:** 路径遍历 (Path Traversal)  
**风险:** 高危，可导致敏感信息泄露或远程代码执行 (取决于配置)  
**投毒风险:** 5%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2021-41773-i-](https://github.com/mightysai1997/CVE-2021-41773-i-)  

---

### [CVE-2021-41773](CVE-2021-41773-mightysai1997_CVE-2021-41773-PoC.md) 🔴 ✅

**名称:** CVE-2021-41773 - Apache HTTP Server Path Traversal  
**类型:** 路径遍历 (Path Traversal)  
**风险:** 高危，可导致文件泄露，甚至远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2021-41773-PoC](https://github.com/mightysai1997/CVE-2021-41773-PoC)  

---

### [CVE-2021-41773](CVE-2021-41773-mightysai1997_CVE-2021-41773S.md) 🔴 ✅

**名称:** CVE-2021-41773 - Apache HTTP Server Path Traversal & Remote Code Execution  
**类型:** 路径遍历 & 远程代码执行  
**风险:** 高危，允许未授权的攻击者访问敏感信息，甚至执行任意代码。  
**投毒风险:** 1%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2021-41773S](https://github.com/mightysai1997/CVE-2021-41773S)  

---

### [CVE-2021-41773](CVE-2021-41773-dileepdkumar_LayarKacaSiber-CVE-2021-41773.md) 🔴 ✅

**名称:** CVE-2021-41773 - Apache HTTP Server Path Traversal & Remote Code Execution (RCE)  
**类型:** 路径遍历/远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者读取任意文件或执行任意代码。  
**投毒风险:** 1%  
**发现时间:** 2025-03-19  
**POC仓库:** [LayarKacaSiber-CVE-2021-41773](https://github.com/dileepdkumar/LayarKacaSiber-CVE-2021-41773)  

---

### [CVE-2021-41773](CVE-2021-41773-justakazh_mass_cve-2021-41773.md) 🔴 ✅

**名称:** CVE-2021-41773 - Apache HTTP Server Path Traversal and Remote Code Execution  
**类型:** 路径遍历和远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者读取任意文件和/或执行远程代码  
**投毒风险:** 0%  
**发现时间:** 2025-03-19  
**POC仓库:** [mass_cve-2021-41773](https://github.com/justakazh/mass_cve-2021-41773)  

---

### [CVE-2021-41773](CVE-2021-41773-Iris288_CVE-2021-41773.md) 🔴 ✅

**名称:** CVE-2021-41773 - Apache HTTP Server Path Traversal & Remote Code Execution  
**类型:** Path Traversal & Remote Code Execution  
**风险:** 高危，允许未经身份验证的攻击者读取任意文件和执行任意代码。  
**投毒风险:** 0%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2021-41773](https://github.com/Iris288/CVE-2021-41773)  

---

### [CVE-2021-41773](CVE-2021-41773-Maybe4a6f7365_CVE-2021-41773.md) 🔴 ✅

**名称:** CVE-2021-41773 - Apache HTTP Server Path Traversal  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2021-41773](https://github.com/Maybe4a6f7365/CVE-2021-41773)  

---

### [CVE-2021-41773](CVE-2021-41773-MrCl0wnLab_SimplesApachePathTraversal.md) 🔴 ✅

**名称:** CVE-2021-41773 - Apache HTTP Server Path Traversal and File Disclosure  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-19  
**POC仓库:** [SimplesApachePathTraversal](https://github.com/MrCl0wnLab/SimplesApachePathTraversal)  

---

### [CVE-2021-41773](CVE-2021-41773-Zyx2440_Apache-HTTP-Server-2.4.50-RCE.md) 🔴 ✅

**名称:** CVE-2021-41773/CVE-2021-42013 - Apache HTTP Server Path Traversal and RCE  
**类型:** 路径遍历/远程代码执行  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-19  
**POC仓库:** [Apache-HTTP-Server-2.4.50-RCE](https://github.com/Zyx2440/Apache-HTTP-Server-2.4.50-RCE)  

---

### [CVE-2021-41773](CVE-2021-41773-0xc4t_CVE-2021-41773.md) 🔴 ✅

**名称:** CVE-2021-41773 - Apache HTTP Server Path Traversal and Remote Code Execution  
**类型:** 路径遍历和远程代码执行  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2021-41773](https://github.com/0xc4t/CVE-2021-41773)  

---

### [CVE-2021-41773](CVE-2021-41773-jkska23_Additive-Vulnerability-Analysis-CVE-2021-41773.md) 🔴 ✅

**名称:** CVE-2021-41773-Apache HTTP Server-路径遍历和文件泄露  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-19  
**POC仓库:** [Additive-Vulnerability-Analysis-CVE-2021-41773](https://github.com/jkska23/Additive-Vulnerability-Analysis-CVE-2021-41773)  

---

### [CVE-2021-41773](CVE-2021-41773-skentagon_CVE-2021-41773.md) 🔴 ✅

**名称:** CVE-2021-41773 - Apache HTTP Server Path Traversal  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2021-41773](https://github.com/skentagon/CVE-2021-41773)  

---

### [CVE-2021-41773](CVE-2021-41773-redspy-sec_CVE-2021-41773.md) 🔴 ✅

**名称:** CVE-2021-41773-Apache HTTP Server-Path Traversal & Remote Code Execution  
**类型:** Path Traversal & Remote Code Execution  
**风险:** 高危，可导致敏感信息泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2021-41773](https://github.com/redspy-sec/CVE-2021-41773)  

---

### [CVE-2021-41773](CVE-2021-41773-FakesiteSecurity_CVE-2021-41773.md) 🔴 ✅

**名称:** CVE-2021-41773 - Apache HTTP Server Path Traversal & Remote Code Execution  
**类型:** Path Traversal / Remote Code Execution  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2021-41773](https://github.com/FakesiteSecurity/CVE-2021-41773)  

---

### [CVE-2021-41773](CVE-2021-41773-Taldrid1_cve-2021-41773.md) 🔴 ✅

**名称:** CVE-2021-41773 - Apache HTTP Server Path Traversal  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-19  
**POC仓库:** [cve-2021-41773](https://github.com/Taldrid1/cve-2021-41773)  

---

### [CVE-2021-41773](CVE-2021-41773-tiemio_SSH-key-and-RCE-PoC-for-CVE-2021-41773.md) 🔴 ✅

**名称:** CVE-2021-41773 - Apache HTTP Server Path Traversal and RCE  
**类型:** 路径遍历和远程代码执行  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-03-19  
**POC仓库:** [SSH-key-and-RCE-PoC-for-CVE-2021-41773](https://github.com/tiemio/SSH-key-and-RCE-PoC-for-CVE-2021-41773)  

---

### [CVE-2021-41773](CVE-2021-41773-Vanshuk-Bhagat_Apache-HTTP-Server-Vulnerabilities-CVE-2021-41773-and-CVE-2021-42013.md) 🔴 ✅

**名称:** CVE-2021-41773 - Apache HTTP Server Path Traversal  
**类型:** 路径遍历 (Path Traversal)  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-19  
**POC仓库:** [Apache-HTTP-Server-Vulnerabilities-CVE-2021-41773-and-CVE-2021-42013](https://github.com/Vanshuk-Bhagat/Apache-HTTP-Server-Vulnerabilities-CVE-2021-41773-and-CVE-2021-42013)  

---

### [CVE-2021-41773](CVE-2021-41773-javaamo_CVE-2021-41773.md) 🔴 ✅

**名称:** CVE-2021-41773 - Apache HTTP Server Path Traversal & Remote Code Execution  
**类型:** 路径遍历和远程代码执行  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2021-41773](https://github.com/javaamo/CVE-2021-41773)  

---

### [CVE-2025-24071](CVE-2025-24071-aleongx_CVE-2025-24071.md) 🟡 ✅

**名称:** CVE-2025-24071-Windows File Explorer Spoofing  
**类型:** 欺骗漏洞  
**风险:** 中危，可能导致信息泄露和欺骗攻击  
**投毒风险:** 0%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2025-24071](https://github.com/aleongx/CVE-2025-24071)  

---

### [CVE-2025-24813](CVE-2025-24813-michael-david-fry_Apache-Tomcat-Vulnerability-POC-CVE-2025-24813.md) 🔴 ✅

**名称:** CVE-2025-24813 - Apache Tomcat 路径等价和反序列化漏洞  
**类型:** 路径等价 / 反序列化  
**风险:** 高危，可能导致远程代码执行、信息泄露或恶意内容注入  
**投毒风险:** 10%  
**发现时间:** 2025-03-19  
**POC仓库:** [Apache-Tomcat-Vulnerability-POC-CVE-2025-24813](https://github.com/michael-david-fry/Apache-Tomcat-Vulnerability-POC-CVE-2025-24813)  

---

### [CVE-2024-41817](CVE-2024-41817-Dxsk_CVE-2024-41817-poc.md) 🔴 ✅

**名称:** CVE-2024-41817-ImageMagick-任意代码执行  
**类型:** 任意代码执行  
**风险:** 高危，允许攻击者执行任意命令  
**投毒风险:** 10%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2024-41817-poc](https://github.com/Dxsk/CVE-2024-41817-poc)  

---

### [CVE-2025-22954](CVE-2025-22954-RandomRobbieBF_CVE-2025-22954.md) 🔴 ✅

**名称:** CVE-2025-22954-Koha-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2025-22954](https://github.com/RandomRobbieBF/CVE-2025-22954)  

---

### [CVE-2018-7600](CVE-2018-7600-mr-won_CVE-2018-7600..md) 🔴 ✅

**名称:** CVE-2018-7600-Drupal-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致网站完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2018-7600.](https://github.com/mr-won/CVE-2018-7600.)  

---

### [CVE-2025-26794](CVE-2025-26794-ishwardeepp_CVE-2025-26794-Exim-Mail-SQLi.md) 🔴 ✅

**名称:** CVE-2025-26794-Exim-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致信息泄露和远程命令执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2025-26794-Exim-Mail-SQLi](https://github.com/ishwardeepp/CVE-2025-26794-Exim-Mail-SQLi)  

---

### [CVE-2025-26794](CVE-2025-26794-OscarBataille_CVE-2025-26794.md) 🔴 ✅

**名称:** CVE-2025-26794-Exim-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致信息泄露、拒绝服务，甚至远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2025-26794](https://github.com/OscarBataille/CVE-2025-26794)  

---

### [CVE-2018-7600](CVE-2018-7600-Damian972_drupalgeddon-2.md) 🔴 ✅

**名称:** CVE-2018-7600 Drupalgeddon2  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程攻击者执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-03-19  
**POC仓库:** [drupalgeddon-2](https://github.com/Damian972/drupalgeddon-2)  

---

### [CVE-2018-7600](CVE-2018-7600-Hestat_drupal-check.md) 🔴 ✅

**名称:** CVE-2018-7600-Drupal-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致网站被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-03-19  
**POC仓库:** [drupal-check](https://github.com/Hestat/drupal-check)  

---

### [CVE-2018-7600](CVE-2018-7600-soch4n_CVE-2018-7600.md) 🔴 ✅

**名称:** CVE-2018-7600-Drupal-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程攻击者在服务器上执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2018-7600](https://github.com/soch4n/CVE-2018-7600)  

---

### [CVE-2018-7600](CVE-2018-7600-happynote3966_CVE-2018-7600.md) 🔴 ✅

**名称:** CVE-2018-7600-Drupal-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程攻击者执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2018-7600](https://github.com/happynote3966/CVE-2018-7600)  

---

### [CVE-2018-7600](CVE-2018-7600-knqyf263_CVE-2018-7600.md) 🔴 ✅

**名称:** CVE-2018-7600-Drupal-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程攻击者在Drupal服务器上执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2018-7600](https://github.com/knqyf263/CVE-2018-7600)  

---

### [CVE-2018-7600](CVE-2018-7600-drugeddon_drupal-exploit.md) 🔴 ✅

**名称:** CVE-2018-7600-Drupal-远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 20%  
**发现时间:** 2025-03-19  
**POC仓库:** [drupal-exploit](https://github.com/drugeddon/drupal-exploit)  

---

### [CVE-2018-7600](CVE-2018-7600-a2u_CVE-2018-7600.md) 🔴 ✅

**名称:** CVE-2018-7600 - Drupalgeddon2 - 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2018-7600](https://github.com/a2u/CVE-2018-7600)  

---

### [CVE-2018-7600](CVE-2018-7600-shellord_Drupalgeddon-Mass-Exploiter.md) 🔴 ✅

**名称:** CVE-2018-7600 - Drupalgeddon2  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的远程攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-03-19  
**POC仓库:** [Drupalgeddon-Mass-Exploiter](https://github.com/shellord/Drupalgeddon-Mass-Exploiter)  

---

### [CVE-2018-7600](CVE-2018-7600-shellord_CVE-2018-7600-Drupal-RCE.md) 🔴 ✅

**名称:** CVE-2018-7600-Drupal-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2018-7600-Drupal-RCE](https://github.com/shellord/CVE-2018-7600-Drupal-RCE)  

---

### [CVE-2018-7600](CVE-2018-7600-zhzyker_CVE-2018-7600-Drupal-POC-EXP.md) 🔴 ✅

**名称:** CVE-2018-7600-Drupal-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2018-7600-Drupal-POC-EXP](https://github.com/zhzyker/CVE-2018-7600-Drupal-POC-EXP)  

---

### [CVE-2018-7600](CVE-2018-7600-rabbitmask_CVE-2018-7600-Drupal7.md) 🔴 ✅

**名称:** CVE-2018-7600-Drupal-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程攻击者执行任意代码。  
**投毒风险:** 5%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2018-7600-Drupal7](https://github.com/rabbitmask/CVE-2018-7600-Drupal7)  

---

### [CVE-2018-7600](CVE-2018-7600-ynsmroztas_drupalhunter.md) 🔴 ✅

**名称:** CVE-2018-7600 Drupalgeddon2 RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-03-19  
**POC仓库:** [drupalhunter](https://github.com/ynsmroztas/drupalhunter)  

---

### [CVE-2018-7600](CVE-2018-7600-ruthvikvegunta_Drupalgeddon2.md) 🔴 ✅

**名称:** CVE-2018-7600-Drupal-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-03-19  
**POC仓库:** [Drupalgeddon2](https://github.com/ruthvikvegunta/Drupalgeddon2)  

---

### [CVE-2018-7600](CVE-2018-7600-r3dxpl0it_CVE-2018-7600.md) 🔴 ✅

**名称:** CVE-2018-7600-Drupal-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许远程攻击者执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2018-7600](https://github.com/r3dxpl0it/CVE-2018-7600)  

---

### [CVE-2018-7600](CVE-2018-7600-dreadlocked_Drupalgeddon2.md) 🔴 ✅

**名称:** CVE-2018-7600 Drupalgeddon2 RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-19  
**POC仓库:** [Drupalgeddon2](https://github.com/dreadlocked/Drupalgeddon2)  

---

### [CVE-2018-7600](CVE-2018-7600-madneal_codeql-scanner.md) 🔴 ✅

**名称:** CVE-2018-7600-Drupalgeddon2-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-03-19  
**POC仓库:** [codeql-scanner](https://github.com/madneal/codeql-scanner)  

---

### [CVE-2018-7600](CVE-2018-7600-cved-sources_cve-2018-7600.md) 🔴 ✅

**名称:** CVE-2018-7600-Drupal-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-03-19  
**POC仓库:** [cve-2018-7600](https://github.com/cved-sources/cve-2018-7600)  

---

### [CVE-2018-7600](CVE-2018-7600-0xAJ2K_CVE-2018-7600.md) 🔴 ✅

**名称:** CVE-2018-7600-Drupal-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2018-7600](https://github.com/0xAJ2K/CVE-2018-7600)  

---

### [CVE-2018-7600](CVE-2018-7600-rafaelcaria_drupalgeddon2-CVE-2018-7600.md) 🔴 ✅

**名称:** CVE-2018-7600-Drupal-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-03-19  
**POC仓库:** [drupalgeddon2-CVE-2018-7600](https://github.com/rafaelcaria/drupalgeddon2-CVE-2018-7600)  

---

### [CVE-2018-7600](CVE-2018-7600-vphnguyen_ANM_CVE-2018-7600.md) 🔴 ✅

**名称:** CVE-2018-7600-Drupal-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致完全控制受影响的 Drupal 站点  
**投毒风险:** 5%  
**发现时间:** 2025-03-19  
**POC仓库:** [ANM_CVE-2018-7600](https://github.com/vphnguyen/ANM_CVE-2018-7600)  

---

### [CVE-2018-7600](CVE-2018-7600-anldori_CVE-2018-7600.md) 🔴 ✅

**名称:** CVE-2018-7600-Drupal-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致完全控制目标服务器  
**投毒风险:** 10%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2018-7600](https://github.com/anldori/CVE-2018-7600)  

---

### [CVE-2018-7600](CVE-2018-7600-r0lh_CVE-2018-7600.md) 🔴 ✅

**名称:** CVE-2018-7600-Drupal-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2018-7600](https://github.com/r0lh/CVE-2018-7600)  

---

### [CVE-2018-7600](CVE-2018-7600-thehappydinoa_CVE-2018-7600.md) 🔴 ✅

**名称:** CVE-2018-7600 Drupalgeddon2 RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许远程攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2018-7600](https://github.com/thehappydinoa/CVE-2018-7600)  

---

### [CVE-2018-7600](CVE-2018-7600-killeveee_CVE-2018-7600.md) 🔴 ✅

**名称:** CVE-2018-7600-Drupal-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2018-7600](https://github.com/killeveee/CVE-2018-7600)  

---

### [CVE-2018-7600](CVE-2018-7600-raytran54_CVE-2018-7600.md) 🔴 ✅

**名称:** CVE-2018-7600 Drupalgeddon2  
**类型:** 远程代码执行  
**风险:** 高危，允许未授权远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-03-19  
**POC仓库:** [CVE-2018-7600](https://github.com/raytran54/CVE-2018-7600)  

---

### [CVE-2024-28000](CVE-2024-28000-Alucard0x1_CVE-2024-28000.md) 🔴 ✅

**名称:** CVE-2024-28000 - LiteSpeed Cache Privilege Escalation  
**类型:** 权限提升  
**风险:** 高危，可导致完全控制 WordPress 站点  
**投毒风险:** 10%  
**发现时间:** 2025-03-18  
**POC仓库:** [CVE-2024-28000](https://github.com/Alucard0x1/CVE-2024-28000)  

---

### [CVE-2024-28000](CVE-2024-28000-arch1m3d_CVE-2024-28000.md) 🔴 ✅

**名称:** CVE-2024-28000-LiteSpeed Cache-权限提升  
**类型:** 权限提升  
**风险:** 高危，可能导致管理员权限被获取  
**投毒风险:** 0%  
**发现时间:** 2025-03-18  
**POC仓库:** [CVE-2024-28000](https://github.com/arch1m3d/CVE-2024-28000)  

---

### [CVE-2024-28000](CVE-2024-28000-ebrasha_CVE-2024-28000.md) 🔴 ✅

**名称:** CVE-2024-28000 - LiteSpeed Cache Privilege Escalation  
**类型:** 权限提升  
**风险:** 高危，未经身份验证的攻击者可以获得管理员权限  
**投毒风险:** 10%  
**发现时间:** 2025-03-18  
**POC仓库:** [CVE-2024-28000](https://github.com/ebrasha/CVE-2024-28000)  

---

### [CVE-2024-28000](CVE-2024-28000-SSSSuperX_CVE-2024-28000.md)  ✅

**名称:** CVE-2024-28000 - WordPress LiteSpeed Cache 未授权提权漏洞  
**类型:** 未授权提权  
**风险:** 严重，可能导致管理员权限获取  
**投毒风险:** 10%  
**发现时间:** 2025-03-18  
**POC仓库:** [CVE-2024-28000](https://github.com/SSSSuperX/CVE-2024-28000)  

---

### [CVE-2024-28000](CVE-2024-28000-JohnDoeAnonITA_CVE-2024-28000.md) 🔴 ✅

**名称:** CVE-2024-28000 - LiteSpeed Cache 未授权提权  
**类型:** 权限提升  
**风险:** 高危，可能导致管理员权限被盗取  
**投毒风险:** 10%  
**发现时间:** 2025-03-18  
**POC仓库:** [CVE-2024-28000](https://github.com/JohnDoeAnonITA/CVE-2024-28000)  

---

### [CVE-2025-1661](CVE-2025-1661-MuhammadWaseem29_CVE-2025-1661.md) 🔴 ✅

**名称:** CVE-2025-1661 - HUSKY WooCommerce插件未授权本地文件包含漏洞  
**类型:** 本地文件包含 (LFI)  
**风险:** 高危，可导致敏感信息泄露甚至远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-18  
**POC仓库:** [CVE-2025-1661](https://github.com/MuhammadWaseem29/CVE-2025-1661)  

---

### [CVE-2025-30066](CVE-2025-30066-Checkmarx_Checkmarx-CVE-2025-30066-Detection-Tool.md) 🔴 ✅

**名称:** CVE-2025-30066-tj-actions/changed-files-敏感信息泄露  
**类型:** 供应链攻击/敏感信息泄露  
**风险:** 高危，可能导致凭据泄露，供应链投毒  
**投毒风险:** 80%  
**发现时间:** 2025-03-18  
**POC仓库:** [Checkmarx-CVE-2025-30066-Detection-Tool](https://github.com/Checkmarx/Checkmarx-CVE-2025-30066-Detection-Tool)  

---

### [CVE-2025-24813](CVE-2025-24813-naikordian_CVE-2025-24813.md) 🔴 ✅

**名称:** CVE-2025-24813-Apache Tomcat-RCE/信息泄露/文件篡改  
**类型:** 远程代码执行/信息泄露/文件篡改  
**风险:** 高危，可能导致远程代码执行，敏感信息泄露以及文件被恶意篡改  
**投毒风险:** 10%  
**发现时间:** 2025-03-18  
**POC仓库:** [CVE-2025-24813](https://github.com/naikordian/CVE-2025-24813)  

---

### [CVE-2025-30066](CVE-2025-30066-OS-pedrogustavobilro_test-changed-files.md) 🔴 ✅

**名称:** CVE-2025-30066-tj-actions/changed-files-敏感信息泄露  
**类型:** 供应链攻击/敏感信息泄露  
**风险:** 高危，可能导致 secrets 泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-18  
**POC仓库:** [test-changed-files](https://github.com/OS-pedrogustavobilro/test-changed-files)  

---

### [CVE-2025-24071](CVE-2025-24071-0x6rss_CVE-2025-24071_PoC.md) 🟡 ✅

**名称:** CVE-2025-24071 Microsoft Windows File Explorer Spoofing Vulnerability  
**类型:** 信息泄露 (NTLM Hash Leak)  
**风险:** 中危，泄露NTLM hash可能导致身份冒用  
**投毒风险:** 10%  
**发现时间:** 2025-03-18  
**POC仓库:** [CVE-2025-24071_PoC](https://github.com/0x6rss/CVE-2025-24071_PoC)  

---

### [CVE-2025-24071](CVE-2025-24071-FOLKS-iwd_CVE-2025-24071-msfvenom.md) 🟡 ✅

**名称:** CVE-2025-24071 Microsoft Windows File Explorer Spoofing Vulnerability  
**类型:** NTLM Hash Leak / 信息泄露  
**风险:** 中危，攻击者可获取用户NTLM Hash，可能进行后续攻击  
**投毒风险:** 5%  
**发现时间:** 2025-03-18  
**POC仓库:** [CVE-2025-24071-msfvenom](https://github.com/FOLKS-iwd/CVE-2025-24071-msfvenom)  

---

### [CVE-2025-27410](CVE-2025-27410-shreyas-malhotra_CVE-2025-27410.md) 🔴 ✅

**名称:** CVE-2025-27410-PwnDoc-RCE  
**类型:** 路径遍历导致任意文件写入 -> RCE  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-18  
**POC仓库:** [CVE-2025-27410](https://github.com/shreyas-malhotra/CVE-2025-27410)  

---

### [CVE-2025-24813](CVE-2025-24813-msadeghkarimi_CVE-2025-24813-Exploit.md) 🔴 ✅

**名称:** CVE-2025-24813 Apache Tomcat RCE  
**类型:** 远程代码执行 (RCE) / 信息泄露  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-18  
**POC仓库:** [CVE-2025-24813-Exploit](https://github.com/msadeghkarimi/CVE-2025-24813-Exploit)  

---

### [CVE-2024-52402](CVE-2024-52402-Nxploited_CVE-2024-52402.md) 🔴 ✅

**名称:** CVE-2024-52402-Exclusive Content Password Protect-CSRF to Arbitrary File Upload  
**类型:** CSRF to Arbitrary File Upload  
**风险:** 高危，允许攻击者上传webshell到服务器，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-18  
**POC仓库:** [CVE-2024-52402](https://github.com/Nxploited/CVE-2024-52402)  

---

### [CVE-2025-26417](CVE-2025-26417-uthrasri_CVE-2025-26417.md) 🔴 ✅

**名称:** CVE-2025-26417-Android DownloadProvider权限绕过  
**类型:** 权限绕过  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-18  
**POC仓库:** [CVE-2025-26417](https://github.com/uthrasri/CVE-2025-26417)  

---

### [CVE-2023-21125](CVE-2023-21125-Mahesh-970_Mahesh-970-CVE-2023-21125_bluedriod_repo.md) 🔴 ✅

**名称:** CVE-2023-21125/CVE-2025-21125 Android Bluetooth RCE/InDesign NVD Pointer Dereference  
**类型:** 远程代码执行/拒绝服务  
**风险:** 高危/中危  
**投毒风险:** 20%  
**发现时间:** 2025-03-18  
**POC仓库:** [Mahesh-970-CVE-2023-21125_bluedriod_repo](https://github.com/Mahesh-970/Mahesh-970-CVE-2023-21125_bluedriod_repo)  

---

### [CVE-2023-45878](CVE-2023-45878-dgoorden_CVE-2023-45878.md) 🔴 ✅

**名称:** CVE-2023-45878-GibbonEdu-任意文件写入  
**类型:** 任意文件写入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-03-18  
**POC仓库:** [CVE-2023-45878](https://github.com/dgoorden/CVE-2023-45878)  

---

### [CVE-2024-57040](CVE-2024-57040-absholi7ly_Poc-CVE-2024-57040.md) 🔴 ✅

**名称:** CVE-2024-57040-TP-Link路由器硬编码密码漏洞  
**类型:** 硬编码密码  
**风险:** 高危，允许未经授权的远程访问  
**投毒风险:** 10%  
**发现时间:** 2025-03-18  
**POC仓库:** [Poc-CVE-2024-57040](https://github.com/absholi7ly/Poc-CVE-2024-57040)  

---

### [CVE-2025-21333](CVE-2025-21333-160102_CVE-2025-21333-POC.md) 🔴 ✅

**名称:** CVE-2025-21333-Windows Hyper-V NT Kernel Integration VSP权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可导致权限提升  
**投毒风险:** 20%  
**发现时间:** 2025-03-18  
**POC仓库:** [CVE-2025-21333-POC](https://github.com/160102/CVE-2025-21333-POC)  

---

### [CVE-2025-21333](CVE-2025-21333-SerabiLem_CVE-2025-21333-POC.md) 🔴 ✅

**名称:** CVE-2025-21333 Windows Hyper-V NT Kernel Integration VSP Elevation of Privilege Vulnerability  
**类型:** 权限提升  
**风险:** 高危，可能导致虚拟机数据泄露、完整性破坏和拒绝服务  
**投毒风险:** 80%  
**发现时间:** 2025-03-18  
**POC仓库:** [CVE-2025-21333-POC](https://github.com/SerabiLem/CVE-2025-21333-POC)  

---

### [CVE-2025-29384](CVE-2025-29384-Otsmane-Ahmed_cve-2025-29384-poc.md) 🔴 ✅

**名称:** CVE-2025-29384-Tenda AC9-/goform/AdvSetMacMtuWan 栈溢出  
**类型:** 栈溢出  
**风险:** 高危，可能导致远程代码执行或拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-03-18  
**POC仓库:** [cve-2025-29384-poc](https://github.com/Otsmane-Ahmed/cve-2025-29384-poc)  

---

### [CVE-2023-6360](CVE-2023-6360-mr-won_CVE-2023-6360.md) 🔴 

**名称:** CVE-2023-6360-My Calendar-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-18  
**POC仓库:** [CVE-2023-6360](https://github.com/mr-won/CVE-2023-6360)  

---

### [CVE-2024-56249](CVE-2024-56249-Nxploited_CVE-2024-56249.md) 🔴 ✅

**名称:** CVE-2024-56249-WPMasterToolKit-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-18  
**POC仓库:** [CVE-2024-56249](https://github.com/Nxploited/CVE-2024-56249)  

---

### [CVE-2022-3689](CVE-2022-3689-mr-won_CVE-2022-3689.md) 🔴 ✅

**名称:** CVE-2022-3689-HTML Forms-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-18  
**POC仓库:** [CVE-2022-3689](https://github.com/mr-won/CVE-2022-3689)  

---

### [CVE-2025-24813](CVE-2025-24813-imbas007_CVE-2025-24813-apache-tomcat.md) 🔴 ✅

**名称:** CVE-2025-24813-Apache Tomcat Path Equivalence-RCE/信息泄露  
**类型:** 路径等价/远程代码执行/信息泄露  
**风险:** 高危，可能导致远程代码执行，信息泄露以及服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2025-24813-apache-tomcat](https://github.com/imbas007/CVE-2025-24813-apache-tomcat)  

---

### [CVE-2023-4911](CVE-2023-4911-teraGL_looneyCVE.md) 🔴 ✅

**名称:** CVE-2023-4911 - Glibc ld.so 本地权限提升  
**类型:** 缓冲区溢出  
**风险:** 高危，本地权限提升至root  
**投毒风险:** 5%  
**发现时间:** 2025-03-17  
**POC仓库:** [looneyCVE](https://github.com/teraGL/looneyCVE)  

---

### [CVE-2024-25641](CVE-2024-25641-regantemudo_CVE-2024-25641-Exploit-for-Cacti-1.2.26.md) 🔴 ✅

**名称:** CVE-2024-25641-Cacti-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在服务器上执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2024-25641-Exploit-for-Cacti-1.2.26](https://github.com/regantemudo/CVE-2024-25641-Exploit-for-Cacti-1.2.26)  

---

### [CVE-2024-12641](CVE-2024-12641-Jimmy01240397_CVE-2024-12641_12642_12645.md) 🔴 ✅

**名称:** CVE-2024-12641-Chunghwa Telecom TenderDocTransfer-Reflected XSS to RCE  
**类型:** Reflected XSS to RCE  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 95%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2024-12641_12642_12645](https://github.com/Jimmy01240397/CVE-2024-12641_12642_12645)  

---

### [CVE-2024-25641](CVE-2024-25641-thisisveryfunny_CVE-2024-25641-RCE-Automated-Exploit-Cacti-1.2.26.md) 🔴 ✅

**名称:** CVE-2024-25641-Cacti-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许攻击者执行任意PHP代码，完全控制受影响的系统。  
**投毒风险:** 1%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2024-25641-RCE-Automated-Exploit-Cacti-1.2.26](https://github.com/thisisveryfunny/CVE-2024-25641-RCE-Automated-Exploit-Cacti-1.2.26)  

---

### [CVE-2024-25641](CVE-2024-25641-Safarchand_CVE-2024-25641.md) 🔴 ✅

**名称:** CVE-2024-25641-Cacti-RCE  
**类型:** 远程代码执行(RCE)  
**风险:** 高危，可能导致完全控制目标系统  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2024-25641](https://github.com/Safarchand/CVE-2024-25641)  

---

### [CVE-2024-25641](CVE-2024-25641-StopThatTalace_CVE-2024-25641-CACTI-RCE-1.2.26.md) 🔴 ✅

**名称:** CVE-2024-25641-Cacti-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2024-25641-CACTI-RCE-1.2.26](https://github.com/StopThatTalace/CVE-2024-25641-CACTI-RCE-1.2.26)  

---

### [CVE-2024-25641](CVE-2024-25641-5ma1l_CVE-2024-25641.md) 🔴 ✅

**名称:** CVE-2024-25641-Cacti-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可完全控制服务器  
**投毒风险:** 1%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2024-25641](https://github.com/5ma1l/CVE-2024-25641)  

---

### [CVE-2024-25641](CVE-2024-25641-XiaomingX_cve-2024-25641-poc.md) 🔴 ✅

**名称:** CVE-2024-25641 - Cacti Package Import RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可完全控制服务器  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [cve-2024-25641-poc](https://github.com/XiaomingX/cve-2024-25641-poc)  

---

### [CVE-2024-25641](CVE-2024-25641-D3Ext_CVE-2024-25641.md) 🔴 ✅

**名称:** CVE-2024-25641 - Cacti RCE when importing packages  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2024-25641](https://github.com/D3Ext/CVE-2024-25641)  

---

### [CVE-2024-25641](CVE-2024-25641-regantemudo_CVE-2024-25641-Exploit-for-Cacti-1.2.26.md) 🔴 ✅

**名称:** CVE-2024-25641-Cacti-RCE  
**类型:** 远程代码执行（RCE）  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2024-25641-Exploit-for-Cacti-1.2.26](https://github.com/regantemudo/CVE-2024-25641-Exploit-for-Cacti-1.2.26)  

---

### [CVE-2024-54951](CVE-2024-54951-Allevon412_CVE-2024-54951.md) 🟡 ✅

**名称:** CVE-2024-54951-Monica-Stored XSS  
**类型:** Stored Cross-Site Scripting (XSS)  
**风险:** 中危，可能导致信息泄露、会话劫持、恶意重定向等  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2024-54951](https://github.com/Allevon412/CVE-2024-54951)  

---

### [CVE-2025-25612](CVE-2025-25612-secmuzz_CVE-2025-25612.md) 🟡 ✅

**名称:** CVE-2025-25612-FS S3150-8T2F-存储型XSS  
**类型:** 存储型XSS  
**风险:** 中危，可能导致管理员账户劫持、敏感信息泄露等  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2025-25612](https://github.com/secmuzz/CVE-2025-25612)  

---

### [CVE-2023-34598](CVE-2023-34598-Zer0F8th_CVE-2023-34598.md) 🔴 ✅

**名称:** CVE-2023-34598-Gibbon-LFI  
**类型:** LFI  
**风险:** 高危，可能导致敏感信息泄露，如数据库凭据、源代码等  
**投毒风险:** 5%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2023-34598](https://github.com/Zer0F8th/CVE-2023-34598)  

---

### [CVE-2023-4911](CVE-2023-4911-RickdeJager_CVE-2023-4911.md) 🔴 ✅

**名称:** CVE-2023-4911 - Glibc ld.so 本地权限提升  
**类型:** 缓冲区溢出  
**风险:** 高危，本地权限提升至 root  
**投毒风险:** 5%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2023-4911](https://github.com/RickdeJager/CVE-2023-4911)  

---

### [CVE-2023-4911](CVE-2023-4911-Diego-AltF4_CVE-2023-4911.md) 🔴 ✅

**名称:** CVE-2023-4911-Glibc-本地权限提升  
**类型:** 缓冲区溢出  
**风险:** 高危，可导致本地权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2023-4911](https://github.com/Diego-AltF4/CVE-2023-4911)  

---

### [CVE-2023-4911](CVE-2023-4911-Billar42_CVE-2023-4911.md) 🔴 ✅

**名称:** CVE-2023-4911 - Glibc ld.so 本地提权  
**类型:** 缓冲区溢出  
**风险:** 高危，本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2023-4911](https://github.com/Billar42/CVE-2023-4911)  

---

### [CVE-2023-34598](CVE-2023-34598-maddsec_CVE-2023-34598.md) 🟡 ✅

**名称:** CVE-2023-34598 - Gibbon v25.0.0 本地文件包含  
**类型:** 本地文件包含 (LFI)  
**风险:** 中危，可能泄露敏感信息  
**投毒风险:** 5%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2023-34598](https://github.com/maddsec/CVE-2023-34598)  

---

### [CVE-2023-34598](CVE-2023-34598-Lserein_CVE-2023-34598.md) 🔴 ✅

**名称:** CVE-2023-34598-Gibbon-本地文件包含  
**类型:** 本地文件包含 (LFI)  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2023-34598](https://github.com/Lserein/CVE-2023-34598)  

---

### [CVE-2023-4911](CVE-2023-4911-leesh3288_CVE-2023-4911.md) 🔴 ✅

**名称:** CVE-2023-4911 Looney Tunables 本地提权漏洞  
**类型:** 缓冲区溢出  
**风险:** 高危，本地权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2023-4911](https://github.com/leesh3288/CVE-2023-4911)  

---

### [CVE-2023-4911](CVE-2023-4911-Green-Avocado_CVE-2023-4911.md) 🔴 ✅

**名称:** CVE-2023-4911-glibc-ld.so-本地提权  
**类型:** 本地缓冲区溢出提权  
**风险:** 高危，本地用户可提升至root权限  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2023-4911](https://github.com/Green-Avocado/CVE-2023-4911)  

---

### [CVE-2023-4911](CVE-2023-4911-xiaoQ1z_CVE-2023-4911.md) 🔴 ✅

**名称:** CVE-2023-4911: Glibc ld.so 本地提权漏洞  
**类型:** 缓冲区溢出  
**风险:** 高危，可导致本地权限提升  
**投毒风险:** 1%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2023-4911](https://github.com/xiaoQ1z/CVE-2023-4911)  

---

### [CVE-2023-4911](CVE-2023-4911-silent6trinity_looney-tuneables.md) 🔴 ✅

**名称:** CVE-2023-4911-Glibc-本地权限提升  
**类型:** 缓冲区溢出  
**风险:** 高危，本地权限提升至root  
**投毒风险:** 5%  
**发现时间:** 2025-03-17  
**POC仓库:** [looney-tuneables](https://github.com/silent6trinity/looney-tuneables)  

---

### [CVE-2023-4911](CVE-2023-4911-ruycr4ft_CVE-2023-4911.md) 🔴 ✅

**名称:** CVE-2023-4911 Glibc 本地提权漏洞  
**类型:** 缓冲区溢出  
**风险:** 高危，本地权限提升  
**投毒风险:** 1%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2023-4911](https://github.com/ruycr4ft/CVE-2023-4911)  

---

### [CVE-2023-4911](CVE-2023-4911-hadrian3689_looney-tunables-CVE-2023-4911.md) 🔴 ✅

**名称:** CVE-2023-4911 - Glibc ld.so 缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，本地权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-03-17  
**POC仓库:** [looney-tunables-CVE-2023-4911](https://github.com/hadrian3689/looney-tunables-CVE-2023-4911)  

---

### [CVE-2023-4911](CVE-2023-4911-chaudharyarjun_LooneyPwner.md) 🔴 ✅

**名称:** CVE-2023-4911 Looney Tunables 本地提权漏洞  
**类型:** 缓冲区溢出  
**风险:** 高危，本地权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [LooneyPwner](https://github.com/chaudharyarjun/LooneyPwner)  

---

### [CVE-2023-4911](CVE-2023-4911-guffre_CVE-2023-4911.md) 🔴 ✅

**名称:** CVE-2023-4911-glibc-本地提权  
**类型:** 本地提权  
**风险:** 高危，可导致本地权限提升至root  
**投毒风险:** 1%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2023-4911](https://github.com/guffre/CVE-2023-4911)  

---

### [CVE-2023-4911](CVE-2023-4911-snurkeburk_Looney-Tunables.md) 🔴 ✅

**名称:** CVE-2023-4911 - Glibc ld.so 缓冲区溢出  
**类型:** 本地权限提升  
**风险:** 高危，可导致本地权限提升为root  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [Looney-Tunables](https://github.com/snurkeburk/Looney-Tunables)  

---

### [CVE-2023-4911](CVE-2023-4911-puckiestyle_CVE-2023-4911.md) 🔴 ✅

**名称:** CVE-2023-4911 - Glibc ld.so 缓冲区溢出本地提权漏洞  
**类型:** 缓冲区溢出  
**风险:** 高危，本地权限提升至root  
**投毒风险:** 5%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2023-4911](https://github.com/puckiestyle/CVE-2023-4911)  

---

### [CVE-2023-4911](CVE-2023-4911-yanfernandess_Looney-Tunables-CVE-2023-4911.md) 🔴 ✅

**名称:** CVE-2023-4911 Looney Tunables 本地权限提升  
**类型:** 缓冲区溢出  
**风险:** 高危，本地权限提升至root  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [Looney-Tunables-CVE-2023-4911](https://github.com/yanfernandess/Looney-Tunables-CVE-2023-4911)  

---

### [CVE-2023-4911](CVE-2023-4911-KernelKrise_CVE-2023-4911.md) 🔴 ✅

**名称:** CVE-2023-4911-Glibc-本地提权  
**类型:** 本地提权  
**风险:** 高危，允许本地用户提升权限至root  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2023-4911](https://github.com/KernelKrise/CVE-2023-4911)  

---

### [CVE-2023-4911](CVE-2023-4911-NishanthAnand21_CVE-2023-4911-PoC.md) 🔴 ✅

**名称:** CVE-2023-4911-glibc-本地权限提升  
**类型:** 本地权限提升  
**风险:** 高危，允许低权限本地用户提升到root权限  
**投毒风险:** 1%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2023-4911-PoC](https://github.com/NishanthAnand21/CVE-2023-4911-PoC)  

---

### [CVE-2023-4911](CVE-2023-4911-shacojx_CVE-2023-4911-Exploit.md) 🔴 ✅

**名称:** CVE-2023-4911-glibc-ld.so 本地提权  
**类型:** 缓冲区溢出  
**风险:** 高危，本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2023-4911-Exploit](https://github.com/shacojx/CVE-2023-4911-Exploit)  

---

### [CVE-2023-4911](CVE-2023-4911-KillReal01_CVE-2023-4911.md) 🔴 ✅

**名称:** CVE-2023-4911 Glibc ld.so 本地提权漏洞  
**类型:** 缓冲区溢出  
**风险:** 高危，本地提权  
**投毒风险:** 1%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2023-4911](https://github.com/KillReal01/CVE-2023-4911)  

---

### [CVE-2023-0386](CVE-2023-0386-veritas501_CVE-2023-0386.md) 🔴 ✅

**名称:** CVE-2023-0386 OverlayFS 本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，可使普通用户提升为root权限  
**投毒风险:** 1%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2023-0386](https://github.com/veritas501/CVE-2023-0386)  

---

### [CVE-2023-0386](CVE-2023-0386-Satheesh575555_linux-4.19.72_CVE-2023-0386.md) 🔴 ✅

**名称:** CVE-2023-0386-Linux Kernel OverlayFS权限提升  
**类型:** 权限提升  
**风险:** 高危，允许本地用户提升权限  
**投毒风险:** 1%  
**发现时间:** 2025-03-17  
**POC仓库:** [linux-4.19.72_CVE-2023-0386](https://github.com/Satheesh575555/linux-4.19.72_CVE-2023-0386)  

---

### [CVE-2023-0386](CVE-2023-0386-chenaotian_CVE-2023-0386.md) 🔴 ✅

**名称:** CVE-2023-0386 OverlayFS 本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，可导致本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2023-0386](https://github.com/chenaotian/CVE-2023-0386)  

---

### [CVE-2023-0386](CVE-2023-0386-AiK1d_CVE-2023-0386.md) 🔴 ✅

**名称:** CVE-2023-0386-Linux Kernel OverlayFS 本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可提升权限  
**投毒风险:** 5%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2023-0386](https://github.com/AiK1d/CVE-2023-0386)  

---

### [CVE-2023-0386](CVE-2023-0386-hshivhare67_kernel_v4.19.72_CVE-2023-0386.md) 🔴 ✅

**名称:** CVE-2023-0386-Linux Kernel-OverlayFS权限提升  
**类型:** 权限提升  
**风险:** 高危，本地用户可利用该漏洞提升权限  
**投毒风险:** 1%  
**发现时间:** 2025-03-17  
**POC仓库:** [kernel_v4.19.72_CVE-2023-0386](https://github.com/hshivhare67/kernel_v4.19.72_CVE-2023-0386)  

---

### [CVE-2023-0386](CVE-2023-0386-sxlmnwb_CVE-2023-0386.md) 🔴 ✅

**名称:** CVE-2023-0386-Linux Kernel OverlayFS权限提升  
**类型:** 权限提升  
**风险:** 高危，本地用户可提升权限至root  
**投毒风险:** 5%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2023-0386](https://github.com/sxlmnwb/CVE-2023-0386)  

---

### [CVE-2023-0386](CVE-2023-0386-xkaneiki_CVE-2023-0386.md) 🔴 ✅

**名称:** CVE-2023-0386 OverlayFS权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，本地用户可提升权限至root  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2023-0386](https://github.com/xkaneiki/CVE-2023-0386)  

---

### [CVE-2023-0386](CVE-2023-0386-Fanxiaoyao66_CVE-2023-0386.md) 🔴 ✅

**名称:** CVE-2023-0386 OverlayFS 本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，本地用户可提升为root权限  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2023-0386](https://github.com/Fanxiaoyao66/CVE-2023-0386)  

---

### [CVE-2023-0386](CVE-2023-0386-puckiestyle_CVE-2023-0386.md) 🔴 ✅

**名称:** CVE-2023-0386 - Linux Kernel OverlayFS Privilege Escalation  
**类型:** 权限提升  
**风险:** 高危，本地用户可提升权限至 root  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2023-0386](https://github.com/puckiestyle/CVE-2023-0386)  

---

### [CVE-2023-0386](CVE-2023-0386-letsr00t_CVE-2023-0386.md) 🔴 

**名称:** CVE-2023-0386 Linux Kernel OverlayFS 特权提升漏洞  
**类型:** 特权提升  
**风险:** 高危，可导致本地用户权限提升  
**投毒风险:** 2%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2023-0386](https://github.com/letsr00t/CVE-2023-0386)  

---

### [CVE-2023-0386](CVE-2023-0386-churamanib_CVE-2023-0386.md) 🔴 ✅

**名称:** CVE-2023-0386 OverlayFS 本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，本地用户可提升权限至 root  
**投毒风险:** 1%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2023-0386](https://github.com/churamanib/CVE-2023-0386)  

---

### [CVE-2023-0386](CVE-2023-0386-EstamelGG_CVE-2023-0386-libs.md) 🔴 ✅

**名称:** CVE-2023-0386-Linux Kernel OverlayFS权限提升  
**类型:** 权限提升  
**风险:** 高危，可导致本地用户权限提升至root  
**投毒风险:** 1%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2023-0386-libs](https://github.com/EstamelGG/CVE-2023-0386-libs)  

---

### [CVE-2023-0386](CVE-2023-0386-orilevy8_cve-2023-0386.md) 🔴 ✅

**名称:** CVE-2023-0386-Linux Kernel OverlayFS权限提升  
**类型:** 权限提升  
**风险:** 高危，本地用户可以提升权限到root  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [cve-2023-0386](https://github.com/orilevy8/cve-2023-0386)  

---

### [CVE-2019-19781](CVE-2019-19781-pwn3z_CVE-2019-19781-Citrix.md) 🔴 ✅

**名称:** CVE-2019-19781-Citrix ADC/Gateway-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致信息泄露和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2019-19781-Citrix](https://github.com/pwn3z/CVE-2019-19781-Citrix)  

---

### [CVE-2019-19781](CVE-2019-19781-jamesjguthrie_Shitrix-CVE-2019-19781.md) 🔴 ✅

**名称:** CVE-2019-19781-Citrix ADC/Gateway-目录遍历与远程代码执行  
**类型:** 目录遍历与远程代码执行  
**风险:** 高危，可导致远程代码执行和敏感信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-03-17  
**POC仓库:** [Shitrix-CVE-2019-19781](https://github.com/jamesjguthrie/Shitrix-CVE-2019-19781)  

---

### [CVE-2019-19781](CVE-2019-19781-DanielWep_CVE-NetScalerFileSystemCheck.md) 🔴 ✅

**名称:** CVE-2019-19781-Citrix ADC/Gateway-目录遍历/RCE  
**类型:** 目录遍历/远程代码执行  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-NetScalerFileSystemCheck](https://github.com/DanielWep/CVE-NetScalerFileSystemCheck)  

---

### [CVE-2024-31317](CVE-2024-31317-fuhei_CVE-2024-31317.md) 🔴 ✅

**名称:** CVE-2024-31317 - Android Zygote Deserialization/Command Injection  
**类型:** 权限提升 (Elevation of Privilege)  
**风险:** 高危，可实现本地权限提升，以任意应用身份执行代码  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2024-31317](https://github.com/fuhei/CVE-2024-31317)  

---

### [CVE-2024-31317](CVE-2024-31317-jmywh1_CVE-2024-31317.md) 🔴 ✅

**名称:** CVE-2024-31317-Android-Zygote反序列化漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可能导致任意应用代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2024-31317](https://github.com/jmywh1/CVE-2024-31317)  

---

### [CVE-2025-0411](CVE-2025-0411-iSee857_CVE-2025-0411-PoC.md) 🔴 ✅

**名称:** CVE-2025-0411-7-Zip-Mark-of-the-Web Bypass  
**类型:** Mark-of-the-Web Bypass  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2025-0411-PoC](https://github.com/iSee857/CVE-2025-0411-PoC)  

---

### [CVE-2025-0411](CVE-2025-0411-cesarbtakeda_7-Zip-CVE-2025-0411-POC.md) 🟡 ✅

**名称:** CVE-2025-0411-7-Zip-Mark-of-the-Web Bypass  
**类型:** Mark-of-the-Web (MotW) Bypass  
**风险:** 中危，用户交互后可导致任意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [7-Zip-CVE-2025-0411-POC](https://github.com/cesarbtakeda/7-Zip-CVE-2025-0411-POC)  

---

### [CVE-2025-0411](CVE-2025-0411-dhmosfunk_7-Zip-CVE-2025-0411-POC.md) 🔴 ✅

**名称:** CVE-2025-0411-7-Zip Mark-of-the-Web Bypass  
**类型:** Mark-of-the-Web (MotW) 绕过  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [7-Zip-CVE-2025-0411-POC](https://github.com/dhmosfunk/7-Zip-CVE-2025-0411-POC)  

---

### [CVE-2025-0411](CVE-2025-0411-ishwardeepp_CVE-2025-0411-MoTW-PoC.md) 🔴 ✅

**名称:** CVE-2025-0411 7-Zip Mark-of-the-Web Bypass Vulnerability  
**类型:** Mark-of-the-Web (MotW) Bypass  
**风险:** 高危，可能导致任意代码执行，受害者无需察觉的情况下运行恶意程序  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2025-0411-MoTW-PoC](https://github.com/ishwardeepp/CVE-2025-0411-MoTW-PoC)  

---

### [CVE-2016-6210](CVE-2016-6210-justlce_CVE-2016-6210-Exploit.md)  ✅

**名称:** CVE-2016-6210-OpenSSH-用户名枚举  
**类型:** 用户名枚举  
**风险:** 低危，允许攻击者枚举目标系统上的有效用户名  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2016-6210-Exploit](https://github.com/justlce/CVE-2016-6210-Exploit)  

---

### [CVE-2016-6210](CVE-2016-6210-samh4cks_CVE-2016-6210-OpenSSH-User-Enumeration.md) 🟡 ✅

**名称:** CVE-2016-6210 OpenSSH 用户枚举  
**类型:** 用户枚举  
**风险:** 中危，允许攻击者枚举目标系统上的有效用户名  
**投毒风险:** 5%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2016-6210-OpenSSH-User-Enumeration](https://github.com/samh4cks/CVE-2016-6210-OpenSSH-User-Enumeration)  

---

### [CVE-2016-6210](CVE-2016-6210-goomdan_CVE-2016-6210-exploit.md)  ✅

**名称:** CVE-2016-6210-OpenSSH用户名枚举  
**类型:** 用户名枚举  
**风险:** 低危，泄露用户名信息  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2016-6210-exploit](https://github.com/goomdan/CVE-2016-6210-exploit)  

---

### [CVE-2025-24813](CVE-2025-24813-issamjr_CVE-2025-24813-Scanner.md) 🔴 ✅

**名称:** CVE-2025-24813 - Apache Tomcat Path Equivalence / Deserialization RCE  
**类型:** 远程代码执行 (RCE) / 信息泄露 / 文件篡改  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2025-24813-Scanner](https://github.com/issamjr/CVE-2025-24813-Scanner)  

---

### [CVE-2024-7014](CVE-2024-7014-hexspectrum1_CVE-2024-7014.md) 🔴 ✅

**名称:** CVE-2024-7014-Telegram for Android-EvilVideo  
**类型:** 恶意软件安装  
**风险:** 高危，可能导致设备被恶意控制和数据泄露  
**投毒风险:** 85%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2024-7014](https://github.com/hexspectrum1/CVE-2024-7014)  

---

### [CVE-2024-49138](CVE-2024-49138-bananoname_CVE-2024-49138-POC.md) 🔴 ✅

**名称:** CVE-2024-49138 - Windows CLFS 提权漏洞  
**类型:** 权限提升  
**风险:** 高危，本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2024-49138-POC](https://github.com/bananoname/CVE-2024-49138-POC)  

---

### [CVE-2024-49138](CVE-2024-49138-MrAle98_CVE-2024-49138-POC.md) 🔴 ✅

**名称:** CVE-2024-49138 - Windows CLFS 提权漏洞  
**类型:** 特权提升  
**风险:** 高危，允许本地用户提升权限  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2024-49138-POC](https://github.com/MrAle98/CVE-2024-49138-POC)  

---

### [CVE-2012-2982](CVE-2012-2982-OstojaOfficial_CVE-2012-2982.md) 🔴 ✅

**名称:** CVE-2012-2982 - Webmin file/show.cgi 远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可完全控制服务器  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2012-2982](https://github.com/OstojaOfficial/CVE-2012-2982)  

---

### [CVE-2012-2982](CVE-2012-2982-cd6629_CVE-2012-2982-Python-PoC.md) 🔴 ✅

**名称:** CVE-2012-2982 - Webmin file/show.cgi 命令执行  
**类型:** 命令执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2012-2982-Python-PoC](https://github.com/cd6629/CVE-2012-2982-Python-PoC)  

---

### [CVE-2012-2982](CVE-2012-2982-AlexJS6_CVE-2012-2982_Python.md) 🔴 ✅

**名称:** CVE-2012-2982-Webmin-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许远程攻击者执行任意命令  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2012-2982_Python](https://github.com/AlexJS6/CVE-2012-2982_Python)  

---

### [CVE-2012-2982](CVE-2012-2982-Ari-Weinberg_CVE-2012-2982.md) 🔴 ✅

**名称:** CVE-2012-2982-Webmin-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2012-2982](https://github.com/Ari-Weinberg/CVE-2012-2982)  

---

### [CVE-2012-2982](CVE-2012-2982-JohnHammond_CVE-2012-2982.md) 🔴 ✅

**名称:** CVE-2012-2982 - Webmin file/show.cgi 远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2012-2982](https://github.com/JohnHammond/CVE-2012-2982)  

---

### [CVE-2012-2982](CVE-2012-2982-blu3ming_CVE-2012-2982.md) 🔴 ✅

**名称:** CVE-2012-2982-Webmin-命令执行  
**类型:** 命令执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2012-2982](https://github.com/blu3ming/CVE-2012-2982)  

---

### [CVE-2012-2982](CVE-2012-2982-0xF331-D3AD_CVE-2012-2982.md) 🔴 ✅

**名称:** CVE-2012-2982 Webmin file/show.cgi 命令执行  
**类型:** 命令执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2012-2982](https://github.com/0xF331-D3AD/CVE-2012-2982)  

---

### [CVE-2012-2982](CVE-2012-2982-0xTas_CVE-2012-2982.md) 🔴 ✅

**名称:** CVE-2012-2982-Webmin-命令执行  
**类型:** 命令执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2012-2982](https://github.com/0xTas/CVE-2012-2982)  

---

### [CVE-2012-2982](CVE-2012-2982-SpoofIMEI_CVE-2012-2982.md) 🔴 ✅

**名称:** CVE-2012-2982 - Webmin file/show.cgi 命令执行  
**类型:** 命令执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2012-2982](https://github.com/SpoofIMEI/CVE-2012-2982)  

---

### [CVE-2012-2982](CVE-2012-2982-LeDucKhiem_CVE-2012-2982.md) 🔴 ✅

**名称:** CVE-2012-2982 - Webmin file/show.cgi 远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2012-2982](https://github.com/LeDucKhiem/CVE-2012-2982)  

---

### [CVE-2012-2982](CVE-2012-2982-CpyRe_CVE-2012-2982.md) 🔴 ✅

**名称:** CVE-2012-2982-Webmin-命令执行  
**类型:** 命令执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2012-2982](https://github.com/CpyRe/CVE-2012-2982)  

---

### [CVE-2012-2982](CVE-2012-2982-Shadow-Spinner_CVE-2012-2982_python.md) 🔴 ✅

**名称:** CVE-2012-2982-Webmin-命令执行  
**类型:** 命令执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2012-2982_python](https://github.com/Shadow-Spinner/CVE-2012-2982_python)  

---

### [CVE-2012-2982](CVE-2012-2982-elliotosama_CVE-2012-2982.md) 🔴 ✅

**名称:** CVE-2012-2982-Webmin-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2012-2982](https://github.com/elliotosama/CVE-2012-2982)  

---

### [CVE-2012-2982](CVE-2012-2982-SieGer05_CVE-2012-2982-Webmin-Exploit.md) 🔴 ✅

**名称:** CVE-2012-2982 - Webmin file/show.cgi 命令执行  
**类型:** 命令执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2012-2982-Webmin-Exploit](https://github.com/SieGer05/CVE-2012-2982-Webmin-Exploit)  

---

### [CVE-2025-28915](CVE-2025-28915-Nxploited_CVE-2025-28915.md) 🔴 ✅

**名称:** CVE-2025-28915-ThemeEgg ToolKit-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行和服务器控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2025-28915](https://github.com/Nxploited/CVE-2025-28915)  

---

### [CVE-2024-9047](CVE-2024-9047-iSee857_CVE-2024-9047-PoC.md) 🔴 ✅

**名称:** CVE-2024-9047-WordPress File Upload-Path Traversal  
**类型:** 路径遍历  
**风险:** 高危，可能导致任意文件读取  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2024-9047-PoC](https://github.com/iSee857/CVE-2024-9047-PoC)  

---

### [CVE-2024-9047](CVE-2024-9047-verylazytech_CVE-2024-9047.md) 🔴 ✅

**名称:** CVE-2024-9047 - WordPress File Upload插件路径遍历漏洞  
**类型:** 路径遍历 (Path Traversal)  
**风险:** 高危，可能导致敏感文件泄露或删除  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2024-9047](https://github.com/verylazytech/CVE-2024-9047)  

---

### [CVE-2024-9047](CVE-2024-9047-Nxploited_CVE-2024-9047-Exploit.md) 🔴 ✅

**名称:** CVE-2024-9047 - WordPress File Upload Plugin Path Traversal  
**类型:** 路径遍历 (Path Traversal)  
**风险:** 高危，可能导致敏感信息泄露和任意文件删除  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2024-9047-Exploit](https://github.com/Nxploited/CVE-2024-9047-Exploit)  

---

### [CVE-2025-21333](CVE-2025-21333-MrAle98_CVE-2025-21333-POC.md) 🔴 ✅

**名称:** CVE-2025-21333 Windows Hyper-V NT Kernel Integration VSP 提权漏洞  
**类型:** 特权提升/堆溢出  
**风险:** 高危，可导致系统权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2025-21333-POC](https://github.com/MrAle98/CVE-2025-21333-POC)  

---

### [CVE-2025-21333](CVE-2025-21333-aleongx_KQL_sentinel_CVE-2025-21333.md) 🔴 

**名称:** CVE-2025-21333-Windows Hyper-V NT Kernel Integration VSP Elevation of Privilege  
**类型:** 特权提升  
**风险:** 高危，本地攻击者可利用该漏洞获得SYSTEM权限  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [KQL_sentinel_CVE-2025-21333](https://github.com/aleongx/KQL_sentinel_CVE-2025-21333)  

---

### [CVE-2024-23334](CVE-2024-23334-ox1111_CVE-2024-23334.md) 🟡 ✅

**名称:** CVE-2024-23334-aiohttp-目录遍历  
**类型:** 目录遍历  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2024-23334](https://github.com/ox1111/CVE-2024-23334)  

---

### [CVE-2024-23334](CVE-2024-23334-sxyrxyy_aiohttp-exploit-CVE-2024-23334-certstream.md) 🟡 ✅

**名称:** CVE-2024-23334-aiohttp-目录穿越  
**类型:** 目录穿越  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [aiohttp-exploit-CVE-2024-23334-certstream](https://github.com/sxyrxyy/aiohttp-exploit-CVE-2024-23334-certstream)  

---

### [CVE-2024-23334](CVE-2024-23334-z3rObyte_CVE-2024-23334-PoC.md) 🟡 ✅

**名称:** CVE-2024-23334-aiohttp-目录遍历  
**类型:** 目录遍历  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2024-23334-PoC](https://github.com/z3rObyte/CVE-2024-23334-PoC)  

---

### [CVE-2024-23334](CVE-2024-23334-jhonnybonny_CVE-2024-23334.md) 🟡 ✅

**名称:** CVE-2024-23334-aiohttp-目录遍历  
**类型:** 目录遍历  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2024-23334](https://github.com/jhonnybonny/CVE-2024-23334)  

---

### [CVE-2024-23334](CVE-2024-23334-brian-edgar-re_poc-cve-2024-23334.md) 🟡 ✅

**名称:** CVE-2024-23334-aiohttp-目录遍历  
**类型:** 目录遍历  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [poc-cve-2024-23334](https://github.com/brian-edgar-re/poc-cve-2024-23334)  

---

### [CVE-2024-23334](CVE-2024-23334-binaryninja_CVE-2024-23334.md) 🟡 ✅

**名称:** CVE-2024-23334-aiohttp-目录遍历  
**类型:** 目录遍历  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2024-23334](https://github.com/binaryninja/CVE-2024-23334)  

---

### [CVE-2024-23334](CVE-2024-23334-s4botai_CVE-2024-23334-PoC.md) 🟡 ✅

**名称:** CVE-2024-23334-aiohttp-目录遍历  
**类型:** 目录遍历  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2024-23334-PoC](https://github.com/s4botai/CVE-2024-23334-PoC)  

---

### [CVE-2024-23334](CVE-2024-23334-wizarddos_CVE-2024-23334.md) 🟡 ✅

**名称:** CVE-2024-23334-aiohttp-目录遍历  
**类型:** 目录遍历  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2024-23334](https://github.com/wizarddos/CVE-2024-23334)  

---

### [CVE-2024-23334](CVE-2024-23334-Arc4he_CVE-2024-23334-PoC.md) 🟡 ✅

**名称:** CVE-2024-23334-aiohttp-目录遍历  
**类型:** 目录遍历  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2024-23334-PoC](https://github.com/Arc4he/CVE-2024-23334-PoC)  

---

### [CVE-2024-23334](CVE-2024-23334-Pylonet_CVE-2024-23334.md) 🟡 ✅

**名称:** CVE-2024-23334-aiohttp-目录遍历  
**类型:** 目录遍历  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2024-23334](https://github.com/Pylonet/CVE-2024-23334)  

---

### [CVE-2024-23334](CVE-2024-23334-Betan423_CVE-2024-23334-PoC.md) 🟡 ✅

**名称:** CVE-2024-23334-aiohttp目录遍历  
**类型:** 目录遍历  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2024-23334-PoC](https://github.com/Betan423/CVE-2024-23334-PoC)  

---

### [CVE-2024-23334](CVE-2024-23334-BestDevOfc_CVE-2024-23334-PoC.md) 🟡 ✅

**名称:** CVE-2024-23334-aiohttp目录穿越漏洞  
**类型:** 目录穿越  
**风险:** 中危，可能导致敏感文件泄露  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2024-23334-PoC](https://github.com/BestDevOfc/CVE-2024-23334-PoC)  

---

### [CVE-2025-1094](CVE-2025-1094-soltanali0_CVE-2025-1094-Exploit.md) 🔴 ✅

**名称:** CVE-2025-1094-PostgreSQL-SQL注入到RCE  
**类型:** SQL注入  
**风险:** 高危，可导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2025-1094-Exploit](https://github.com/soltanali0/CVE-2025-1094-Exploit)  

---

### [CVE-2025-1094](CVE-2025-1094-shacojx_CVE-2025-1094-Exploit.md) 🔴 ✅

**名称:** CVE-2025-1094-PostgreSQL-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 20%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2025-1094-Exploit](https://github.com/shacojx/CVE-2025-1094-Exploit)  

---

### [CVE-2023-30258](CVE-2023-30258-gy741_CVE-2023-30258-setup.md) 🔴 ✅

**名称:** CVE-2023-30258-MagnusBilling-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许未经身份验证的远程攻击者执行任意操作系统命令  
**投毒风险:** 5%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2023-30258-setup](https://github.com/gy741/CVE-2023-30258-setup)  

---

### [CVE-2023-30258](CVE-2023-30258-sk00l_CVE-2023-30258.md) 🔴 ✅

**名称:** CVE-2023-30258-MagnusBilling-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2023-30258](https://github.com/sk00l/CVE-2023-30258)  

---

### [CVE-2023-30258](CVE-2023-30258-tinashelorenzi_CVE-2023-30258-magnus-billing-v7-exploit.md) 🔴 ✅

**名称:** CVE-2023-30258-MagnusBilling-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2023-30258-magnus-billing-v7-exploit](https://github.com/tinashelorenzi/CVE-2023-30258-magnus-billing-v7-exploit)  

---

### [CVE-2013-3900](CVE-2013-3900-snoopopsec_vulnerability-CVE-2013-3900.md) 🔴 ✅

**名称:** CVE-2013-3900 WinVerifyTrust Signature Validation Vulnerability  
**类型:** 签名验证绕过  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [vulnerability-CVE-2013-3900](https://github.com/snoopopsec/vulnerability-CVE-2013-3900)  

---

### [CVE-2013-3900](CVE-2013-3900-CyberCondor_Fix-WinVerifyTrustSignatureValidationVuln.md) 🔴 ✅

**名称:** CVE-2013-3900 WinVerifyTrust Signature Validation Vulnerability  
**类型:** 签名验证绕过  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [Fix-WinVerifyTrustSignatureValidationVuln](https://github.com/CyberCondor/Fix-WinVerifyTrustSignatureValidationVuln)  

---

### [CVE-2013-3900](CVE-2013-3900-Securenetology_CVE-2013-3900.md) 🔴 ✅

**名称:** CVE-2013-3900 WinVerifyTrust Signature Validation Vulnerability  
**类型:** 签名验证绕过  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2013-3900](https://github.com/Securenetology/CVE-2013-3900)  

---

### [CVE-2013-3900](CVE-2013-3900-OtisSymbos_CVE-2013-3900-WinTrustVerify.md) 🟡 ✅

**名称:** CVE-2013-3900 WinVerifyTrust Signature Validation Vulnerability  
**类型:** 签名验证绕过  
**风险:** 中危，攻击者可能通过修改已签名文件植入恶意代码  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2013-3900-WinTrustVerify](https://github.com/OtisSymbos/CVE-2013-3900-WinTrustVerify)  

---

### [CVE-2013-3900](CVE-2013-3900-AdenilsonSantos_WinVerifyTrust.md) 🔴 ✅

**名称:** CVE-2013-3900 WinVerifyTrust Signature Validation Vulnerability  
**类型:** 签名验证绕过  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [WinVerifyTrust](https://github.com/AdenilsonSantos/WinVerifyTrust)  

---

### [CVE-2019-19781](CVE-2019-19781-j81blog_ADC-19781.md) 🔴 ✅

**名称:** CVE-2019-19781-Citrix ADC/Gateway-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致远程代码执行和敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [ADC-19781](https://github.com/j81blog/ADC-19781)  

---

### [CVE-2019-19781](CVE-2019-19781-haxrob_CVE-2019-19781.md) 🔴 ✅

**名称:** CVE-2019-19781-Citrix ADC/Gateway 目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2019-19781](https://github.com/haxrob/CVE-2019-19781)  

---

### [CVE-2019-19781](CVE-2019-19781-onSec-fr_CVE-2019-19781-Forensic.md) 🔴 ✅

**名称:** CVE-2019-19781-Citrix ADC和Gateway目录遍历漏洞  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2019-19781-Forensic](https://github.com/onSec-fr/CVE-2019-19781-Forensic)  

---

### [CVE-2019-19781](CVE-2019-19781-L4r1k_CitrixNetscalerAnalysis.md) 🔴 ✅

**名称:** CVE-2019-19781-Citrix ADC/Gateway-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CitrixNetscalerAnalysis](https://github.com/L4r1k/CitrixNetscalerAnalysis)  

---

### [CVE-2019-19781](CVE-2019-19781-nmanzi_webcvescanner.md) 🔴 ✅

**名称:** CVE-2019-19781-Citrix ADC and Gateway-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致信息泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [webcvescanner](https://github.com/nmanzi/webcvescanner)  

---

### [CVE-2019-19781](CVE-2019-19781-mandiant_ioc-scanner-CVE-2019-19781.md) 🔴 ✅

**名称:** CVE-2019-19781-Citrix ADC和Gateway目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [ioc-scanner-CVE-2019-19781](https://github.com/mandiant/ioc-scanner-CVE-2019-19781)  

---

### [CVE-2019-19781](CVE-2019-19781-citrix_ioc-scanner-CVE-2019-19781.md) 🔴 ✅

**名称:** CVE-2019-19781-Citrix ADC/Gateway 目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [ioc-scanner-CVE-2019-19781](https://github.com/citrix/ioc-scanner-CVE-2019-19781)  

---

### [CVE-2019-19781](CVE-2019-19781-yukar1z0e_CVE-2019-19781.md) 🔴 ✅

**名称:** CVE-2019-19781-Citrix ADC and Gateway-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感文件泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2019-19781](https://github.com/yukar1z0e/CVE-2019-19781)  

---

### [CVE-2019-19781](CVE-2019-19781-SharpHack_CVE-2019-19781.md) 🔴 ✅

**名称:** CVE-2019-19781-Citrix ADC和Gateway目录遍历与远程代码执行  
**类型:** 目录遍历/远程代码执行  
**风险:** 高危，未经身份验证的远程攻击者可以执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2019-19781](https://github.com/SharpHack/CVE-2019-19781)  

---

### [CVE-2019-19781](CVE-2019-19781-qiong-qi_CVE-2019-19781-poc.md) 🔴 ✅

**名称:** CVE-2019-19781-Citrix ADC/Gateway目录遍历与远程代码执行  
**类型:** 目录遍历/远程代码执行  
**风险:** 高危，可能导致敏感信息泄露、服务器控制  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2019-19781-poc](https://github.com/qiong-qi/CVE-2019-19781-poc)  

---

### [CVE-2019-19781](CVE-2019-19781-andripwn_CVE-2019-19781.md) 🔴 ✅

**名称:** CVE-2019-19781-Citrix ADC和Gateway目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可导致敏感信息泄露和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2019-19781](https://github.com/andripwn/CVE-2019-19781)  

---

### [CVE-2019-19781](CVE-2019-19781-cisagov_check-cve-2019-19781.md) 🔴 ✅

**名称:** CVE-2019-19781-Citrix ADC和Gateway目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [check-cve-2019-19781](https://github.com/cisagov/check-cve-2019-19781)  

---

### [CVE-2019-19781](CVE-2019-19781-mpgn_CVE-2019-19781.md) 🔴 ✅

**名称:** CVE-2019-19781 - Citrix ADC and Gateway Directory Traversal / RCE  
**类型:** 目录遍历/远程代码执行  
**风险:** 高危，未经身份验证的远程攻击者可以执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2019-19781](https://github.com/mpgn/CVE-2019-19781)  

---

### [CVE-2019-19781](CVE-2019-19781-k-fire_CVE-2019-19781-exploit.md) 🔴 ✅

**名称:** CVE-2019-19781-Citrix ADC和Gateway目录遍历及远程代码执行  
**类型:** 目录遍历/远程代码执行  
**风险:** 高危，可导致敏感信息泄露和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2019-19781-exploit](https://github.com/k-fire/CVE-2019-19781-exploit)  

---

### [CVE-2019-19781](CVE-2019-19781-Vulnmachines_Ctirix_RCE-CVE-2019-19781.md) 🔴 ✅

**名称:** CVE-2019-19781-Citrix ADC/Gateway-目录遍历与远程代码执行  
**类型:** 目录遍历/远程代码执行  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [Ctirix_RCE-CVE-2019-19781](https://github.com/Vulnmachines/Ctirix_RCE-CVE-2019-19781)  

---

### [CVE-2019-19781](CVE-2019-19781-Azeemering_CVE-2019-19781-DFIR-Notes.md) 🔴 ✅

**名称:** CVE-2019-19781-Citrix ADC/Gateway-目录遍历与远程代码执行  
**类型:** 目录遍历/远程代码执行  
**风险:** 高危，未经身份验证的远程攻击者可以利用此漏洞执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2019-19781-DFIR-Notes](https://github.com/Azeemering/CVE-2019-19781-DFIR-Notes)  

---

### [CVE-2019-19781](CVE-2019-19781-w4fz5uck5_CVE-2019-19781-CitrixRCE.md) 🔴 ✅

**名称:** CVE-2019-19781-Citrix ADC和Gateway目录遍历漏洞  
**类型:** 目录遍历/远程代码执行  
**风险:** 高危，可导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2019-19781-CitrixRCE](https://github.com/w4fz5uck5/CVE-2019-19781-CitrixRCE)  

---

### [CVE-2019-19781](CVE-2019-19781-VladRico_CVE-2019-19781.md) 🔴 ✅

**名称:** CVE-2019-19781-Citrix ADC/Gateway-目录遍历与RCE  
**类型:** 目录遍历与远程代码执行  
**风险:** 高危，可能导致信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2019-19781](https://github.com/VladRico/CVE-2019-19781)  

---

### [CVE-2019-19781](CVE-2019-19781-zerobytesecure_CVE-2019-19781.md) 🔴 ✅

**名称:** CVE-2019-19781 - Citrix ADC/Gateway 目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2019-19781](https://github.com/zerobytesecure/CVE-2019-19781)  

---

### [CVE-2019-19781](CVE-2019-19781-citrixgitoff_-ioc-scanner-CVE-2019-19781.md) 🔴 ✅

**名称:** CVE-2019-19781-Citrix ADC和Gateway目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致信息泄露、远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [-ioc-scanner-CVE-2019-19781](https://github.com/citrixgitoff/-ioc-scanner-CVE-2019-19781)  

---

### [CVE-2023-30258](CVE-2023-30258-Chocapikk_CVE-2023-30258.md) 🔴 ✅

**名称:** CVE-2023-30258-MagnusBilling-命令注入  
**类型:** 命令注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-03-17  
**POC仓库:** [CVE-2023-30258](https://github.com/Chocapikk/CVE-2023-30258)  

---

### [CVE-2025-0411](CVE-2025-0411-SalehAlgnay_7-Zip-CVE-2025-0411-POC.md) 🔴 ✅

**名称:** CVE-2025-0411-7-Zip-Mark-of-the-Web Bypass  
**类型:** Mark-of-the-Web (MotW) Bypass  
**风险:** 高危，允许攻击者在用户上下文中执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-03-17  
**POC仓库:** [7-Zip-CVE-2025-0411-POC](https://github.com/SalehAlgnay/7-Zip-CVE-2025-0411-POC)  

---

### [CVE-2019-19781](CVE-2019-19781-chihyeonwon_CVE-2019-19781.md) 🔴 ✅

**名称:** CVE-2019-19781 - Citrix ADC and Gateway Directory Traversal / Remote Code Execution  
**类型:** 目录遍历 / 远程代码执行  
**风险:** 高危，可能导致信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-03-16  
**POC仓库:** [CVE-2019-19781](https://github.com/chihyeonwon/CVE-2019-19781)  

---

### [CVE-2024-9047](CVE-2024-9047-chihyeonwon_CVE-2024-9047.md) 🔴 ✅

**名称:** CVE-2024-9047-WordPress File Upload-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致任意文件读取和删除  
**投毒风险:** 10%  
**发现时间:** 2025-03-16  
**POC仓库:** [CVE-2024-9047](https://github.com/chihyeonwon/CVE-2024-9047)  

---

### [CVE-2024-23334](CVE-2024-23334-TheRedP4nther_LFI-aiohttp-CVE-2024-23334-PoC.md) 🟡 ✅

**名称:** CVE-2024-23334-aiohttp-目录遍历  
**类型:** 目录遍历  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 90%  
**发现时间:** 2025-03-16  
**POC仓库:** [LFI-aiohttp-CVE-2024-23334-PoC](https://github.com/TheRedP4nther/LFI-aiohttp-CVE-2024-23334-PoC)  

---

### [CVE-2025-24813](CVE-2025-24813-gregk4sec_CVE-2025-24813.md) 🔴 ✅

**名称:** CVE-2025-24813-Apache Tomcat-路径等价漏洞  
**类型:** 路径等价漏洞/反序列化漏洞  
**风险:** 高危，可能导致远程代码执行、信息泄露和文件篡改  
**投毒风险:** 95%  
**发现时间:** 2025-03-16  
**POC仓库:** [CVE-2025-24813](https://github.com/gregk4sec/CVE-2025-24813)  

---

### [CVE-2025-24813](CVE-2025-24813-charis3306_CVE-2025-24813.md) 🔴 ✅

**名称:** CVE-2025-24813 Apache Tomcat Path Equivalence and Deserialization RCE  
**类型:** 路径等价及反序列化远程代码执行  
**风险:** 高危，可能导致远程代码执行和信息泄露  
**投毒风险:** 70%  
**发现时间:** 2025-03-16  
**POC仓库:** [CVE-2025-24813](https://github.com/charis3306/CVE-2025-24813)  

---

### [CVE-2024-51788](CVE-2024-51788-Nxploited_CVE-2024-51788.md) 🔴 ✅

**名称:** CVE-2024-51788 - WordPress The Novel Design Store Directory Plugin 任意文件上传漏洞  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行和服务器完全控制  
**投毒风险:** 95%  
**发现时间:** 2025-03-16  
**POC仓库:** [CVE-2024-51788](https://github.com/Nxploited/CVE-2024-51788)  

---

### [CVE-2025-24813](CVE-2025-24813-N0c1or_CVE-2025-24813_POC.md) 🔴 ✅

**名称:** CVE-2025-24813 Apache Tomcat Path Equivalence / Deserialization RCE  
**类型:** 路径等价/反序列化远程代码执行  
**风险:** 高危，可能导致远程代码执行和信息泄露  
**投毒风险:** 100%  
**发现时间:** 2025-03-16  
**POC仓库:** [CVE-2025-24813_POC](https://github.com/N0c1or/CVE-2025-24813_POC)  

---

### [CVE-2025-24813](CVE-2025-24813-absholi7ly_POC-CVE-2025-24813.md) 🔴 ✅

**名称:** CVE-2025-24813 Apache Tomcat Path Equivalence and Deserialization RCE  
**类型:** 远程代码执行 (RCE), 信息泄露, 文件覆盖  
**风险:** 高危，可能导致远程代码执行、信息泄露和恶意文件上传  
**投毒风险:** 95%  
**发现时间:** 2025-03-16  
**POC仓库:** [POC-CVE-2025-24813](https://github.com/absholi7ly/POC-CVE-2025-24813)  

---

### [CVE-2024-9513](CVE-2024-9513-ELIZEUOPAIN_Exploit-CVE-2024-9513-NetAdmin-IAM-Allows-User-Enumeration-In-Active-Directory.md) 🟡 ✅

**名称:** CVE-2024-9513 - NetAdmin IAM 用户枚举  
**类型:** 信息泄露  
**风险:** 中危，可能泄露用户名信息，为进一步攻击提供便利  
**投毒风险:** 100%  
**发现时间:** 2025-03-16  
**POC仓库:** [Exploit-CVE-2024-9513-NetAdmin-IAM-Allows-User-Enumeration-In-Active-Directory](https://github.com/ELIZEUOPAIN/Exploit-CVE-2024-9513-NetAdmin-IAM-Allows-User-Enumeration-In-Active-Directory)  

---

### [CVE-2024-0406](CVE-2024-0406-walidpyh_CVE-2024-0406-POC.md) 🟡 ✅

**名称:** CVE-2024-0406-mholt/archiver-路径遍历  
**类型:** 路径遍历  
**风险:** 中危，可能导致敏感文件读取或覆盖  
**投毒风险:** 95%  
**发现时间:** 2025-03-16  
**POC仓库:** [CVE-2024-0406-POC](https://github.com/walidpyh/CVE-2024-0406-POC)  

---

### [CVE-2025-1094](CVE-2025-1094-ishwardeepp_CVE-2025-1094-PoC-Postgre-SQLi.md) 🔴 ✅

**名称:** CVE-2025-1094-PostgreSQL-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 99%  
**发现时间:** 2025-03-16  
**POC仓库:** [CVE-2025-1094-PoC-Postgre-SQLi](https://github.com/ishwardeepp/CVE-2025-1094-PoC-Postgre-SQLi)  

---

### [CVE-2016-6210](CVE-2016-6210-coolbabayaga_CVE-2016-6210.md)  ✅

**名称:** CVE-2016-6210 - OpenSSH 用户枚举  
**类型:** 用户枚举  
**风险:** 低危，仅泄露用户名信息  
**投毒风险:** 80%  
**发现时间:** 2025-03-16  
**POC仓库:** [CVE-2016-6210](https://github.com/coolbabayaga/CVE-2016-6210)  

---

### [CVE-2024-27398](CVE-2024-27398-secunnix_CVE-2024-27398.md) 🔴 ✅

**名称:** CVE-2024-27398-Linux Kernel Bluetooth sco_sock_timeout UAF  
**类型:** Use-After-Free  
**风险:** 高危，可能导致内核崩溃或任意代码执行  
**投毒风险:** 99%  
**发现时间:** 2025-03-16  
**POC仓库:** [CVE-2024-27398](https://github.com/secunnix/CVE-2024-27398)  

---

### [CVE-2024-7014](CVE-2024-7014-absholi7ly_PoC-for-CVE-2024-7014-Exploit.md) 🔴 ✅

**名称:** CVE-2024-7014-Telegram for Android-EvilVideo恶意软件安装  
**类型:** 恶意软件安装  
**风险:** 高危，可能导致设备被恶意软件感染，数据泄露，权限提升  
**投毒风险:** 100%  
**发现时间:** 2025-03-16  
**POC仓库:** [PoC-for-CVE-2024-7014-Exploit](https://github.com/absholi7ly/PoC-for-CVE-2024-7014-Exploit)  

---

### [CVE-2013-3900](CVE-2013-3900-DavidBr27_CVE-2013-3900-Remediation-Script.md) 🟡 ✅

**名称:** CVE-2013-3900 WinVerifyTrust Signature Validation Vulnerability  
**类型:** 代码执行  
**风险:** 中危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-03-16  
**POC仓库:** [CVE-2013-3900-Remediation-Script](https://github.com/DavidBr27/CVE-2013-3900-Remediation-Script)  

---

### [CVE-2025-22604](CVE-2025-22604-ishwardeepp_CVE-2025-22604-Cacti-RCE.md) 🔴 ✅

**名称:** CVE-2025-22604-Cacti-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致完全控制受影响的系统  
**投毒风险:** 100%  
**发现时间:** 2025-03-16  
**POC仓库:** [CVE-2025-22604-Cacti-RCE](https://github.com/ishwardeepp/CVE-2025-22604-Cacti-RCE)  

---

### [CVE-2024-26229](CVE-2024-26229-shinspace92_cve-2024-26229.md) 🔴 ✅

**名称:** CVE-2024-26229-Windows CSC Service Elevation of Privilege  
**类型:** 权限提升  
**风险:** 高危，允许低权限用户提升至SYSTEM权限  
**投毒风险:** 100%  
**发现时间:** 2025-03-14  
**POC仓库:** [cve-2024-26229](https://github.com/shinspace92/cve-2024-26229)  

---

### [CVE-2024-0760](CVE-2024-0760-SpiralBL0CK_CVE-2024-0760.md) 🔴 ✅

**名称:** CVE-2024-0760-BIND 9-TCP Flood  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致DNS服务器不稳定或崩溃  
**投毒风险:** 0%  
**发现时间:** 2025-03-14  
**POC仓库:** [CVE-2024-0760](https://github.com/SpiralBL0CK/CVE-2024-0760)  

---

### [CVE-2024-10674](CVE-2024-10674-Nxploited_CVE-2024-10674.md) 🔴 ✅

**名称:** CVE-2024-10674-Th_Shop_Mania-任意插件安装/激活  
**类型:** 任意插件安装/激活  
**风险:** 高危，可能导致远程代码执行和权限提升  
**投毒风险:** 100%  
**发现时间:** 2025-03-14  
**POC仓库:** [CVE-2024-10674](https://github.com/Nxploited/CVE-2024-10674)  

---

### [CVE-2017-0143](CVE-2017-0143-n3rdh4x0r_MS17-010_CVE-2017-0143.md) 🔴 ✅

**名称:** CVE-2017-0143 - Windows SMB 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许远程攻击者执行任意代码  
**投毒风险:** 95%  
**发现时间:** 2025-03-14  
**POC仓库:** [MS17-010_CVE-2017-0143](https://github.com/n3rdh4x0r/MS17-010_CVE-2017-0143)  

---

### [CVE-2015-0009](CVE-2015-0009-PhoenixC46_ExploitPOC_MS15-014_CVE-2015-0009.md)  

**名称:** ExploitPOC_MS15-014_CVE-2015-0009  
**类型:** 未知  
**风险:** 未评估  
**投毒风险:** N/A  
**发现时间:** 2025-03-14  
**POC仓库:** [ExploitPOC_MS15-014_CVE-2015-0009](https://github.com/PhoenixC46/ExploitPOC_MS15-014_CVE-2015-0009)  

---

### [CVE-2019-2115](CVE-2019-2115-Fred12301_CVE-2019-2115-Pixel-2-2-XL.md) 🔴 ✅

**名称:** CVE-2019-2115-Android-GateKeeper Double Free  
**类型:** 双重释放 (Double Free)  
**风险:** 高危，可能导致本地权限提升  
**投毒风险:** 80%  
**发现时间:** 2025-03-14  
**POC仓库:** [CVE-2019-2115-Pixel-2-2-XL](https://github.com/Fred12301/CVE-2019-2115-Pixel-2-2-XL)  

---

### [CVE-2025-26319](CVE-2025-26319-YuoLuo_CVE-2025-26319.md) 🔴 ✅

**名称:** CVE-2025-26319-Flowise-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 99%  
**发现时间:** 2025-03-14  
**POC仓库:** [CVE-2025-26319](https://github.com/YuoLuo/CVE-2025-26319)  

---

### [CVE-2021-40539](CVE-2021-40539-lpyydxs_CVE-2021-40539.md) 🔴 ✅

**名称:** CVE-2021-40539-Zoho ManageEngine ADSelfService Plus-REST API认证绕过导致远程代码执行  
**类型:** REST API认证绕过导致远程代码执行  
**风险:** 高危，未经授权的远程代码执行  
**投毒风险:** 95%  
**发现时间:** 2025-03-14  
**POC仓库:** [CVE-2021-40539](https://github.com/lpyydxs/CVE-2021-40539)  

---

### [CVE-2024-38112](CVE-2024-38112-Anurag-Chevendra_CVE-2024-38112.md) 🔴 ✅

**名称:** CVE-2024-38112-Windows MSHTML Platform Spoofing  
**类型:** 欺骗漏洞 (Spoofing)  
**风险:** 高危，可能允许攻击者欺骗用户并执行恶意代码  
**投毒风险:** 95%  
**发现时间:** 2025-03-14  
**POC仓库:** [CVE-2024-38112](https://github.com/Anurag-Chevendra/CVE-2024-38112)  

---

### [CVE-2025-24813](CVE-2025-24813-iSee857_CVE-2025-24813-PoC.md)  

**名称:** CVE-2025-24813-PoC  
**类型:** 未知  
**风险:** 未评估  
**投毒风险:** N/A  
**发现时间:** 2025-03-14  
**POC仓库:** [CVE-2025-24813-PoC](https://github.com/iSee857/CVE-2025-24813-PoC)  

---

### [CVE-2025-1639](CVE-2025-1639-Nxploited_CVE-2025-1639.md) 🔴 ✅

**名称:** CVE-2025-1639-Animation Addons for Elementor Pro-任意插件安装/激活  
**类型:** 任意插件安装/激活  
**风险:** 高危，可能导致远程代码执行，权限提升  
**投毒风险:** 95%  
**发现时间:** 2025-03-14  
**POC仓库:** [CVE-2025-1639](https://github.com/Nxploited/CVE-2025-1639)  

---

### [CVE-2024-25092](CVE-2024-25092-Nxploited_CVE-2024-25092.md) 🔴 ✅

**名称:** CVE-2024-25092-NextMove Lite-任意插件安装/激活  
**类型:** 权限绕过/任意插件安装  
**风险:** 高危，可导致网站完全控制  
**投毒风险:** 95%  
**发现时间:** 2025-03-14  
**POC仓库:** [CVE-2024-25092](https://github.com/Nxploited/CVE-2024-25092)  

---

### [CVE-2025-1661](CVE-2025-1661-gbrsh_CVE-2025-1661.md) 🔴 ✅

**名称:** CVE-2025-1661-HUSKY WooCommerce插件-本地文件包含  
**类型:** 本地文件包含 (LFI)  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 100%  
**发现时间:** 2025-03-14  
**POC仓库:** [CVE-2025-1661](https://github.com/gbrsh/CVE-2025-1661)  

---

### [CVE-2020-27603](CVE-2020-27603-hannob_CVE-2020-27603-bbb-libreoffice-poc.md) 🔴 ✅

**名称:** CVE-2020-27603-BigBlueButton-文件包含  
**类型:** 文件包含  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 99%  
**发现时间:** 2025-03-14  
**POC仓库:** [CVE-2020-27603-bbb-libreoffice-poc](https://github.com/hannob/CVE-2020-27603-bbb-libreoffice-poc)  

---

### [CVE-2024-24450](CVE-2024-24450-SpiralBL0CK_-CVE-2024-24450-.md) 🔴 ✅

**名称:** CVE-2024-24450-OpenAirInterface CN5G AMF-栈溢出  
**类型:** 栈溢出  
**风险:** 高危，可能导致拒绝服务和远程代码执行  
**投毒风险:** 90%  
**发现时间:** 2025-03-14  
**POC仓库:** [-CVE-2024-24450-](https://github.com/SpiralBL0CK/-CVE-2024-24450-)  

---

### [CVE-2024-24451](CVE-2024-24451-SpiralBL0CK_CVE-2024-24451.md) 🔴 ✅

**名称:** CVE-2024-24451-OpenAirInterface CN5G AMF-栈溢出  
**类型:** 栈溢出  
**风险:** 高危，可导致拒绝服务（DoS）  
**投毒风险:** 90%  
**发现时间:** 2025-03-14  
**POC仓库:** [CVE-2024-24451](https://github.com/SpiralBL0CK/CVE-2024-24451)  

---

### [CVE-2025-25101](CVE-2025-25101-Nxploited_CVE-2025-25101.md) 🔴 ✅

**名称:** CVE-2025-25101 - WordPress Munk Sites Plugin <= 1.0.7 - CSRF to Arbitrary Plugin Installation  
**类型:** CSRF  
**风险:** 高危，允许未授权的攻击者诱骗管理员安装和激活任意插件，可能导致远程代码执行和网站完全控制  
**投毒风险:** 90%  
**发现时间:** 2025-03-14  
**POC仓库:** [CVE-2025-25101](https://github.com/Nxploited/CVE-2025-25101)  

---

### [CVE-2025-24813](CVE-2025-24813-N0c1or_CVE-2025-24813_POC.md) 🔴 ✅

**名称:** CVE-2025-24813 - Apache Tomcat 路径等价/反序列化RCE  
**类型:** 路径等价/反序列化远程代码执行  
**风险:** 高危，可导致远程代码执行和信息泄露  
**投毒风险:** 100%  
**发现时间:** 2025-03-14  
**POC仓库:** [CVE-2025-24813_POC](https://github.com/N0c1or/CVE-2025-24813_POC)  

---

### [CVE-2025-24813](CVE-2025-24813-FY036_cve-2025-24813_poc.md) 🔴 ✅

**名称:** CVE-2025-24813-Apache Tomcat-路径等价/反序列化  
**类型:** 路径等价/反序列化  
**风险:** 高危，可能导致远程代码执行和信息泄露  
**投毒风险:** 95%  
**发现时间:** 2025-03-14  
**POC仓库:** [cve-2025-24813_poc](https://github.com/FY036/cve-2025-24813_poc)  

---

### [CVE-2025-28915](CVE-2025-28915-Pei4AN_CVE-2025-28915.md) 🔴 ✅

**名称:** CVE-2025-28915-ThemeEgg ToolKit-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 90%  
**发现时间:** 2025-03-14  
**POC仓库:** [CVE-2025-28915](https://github.com/Pei4AN/CVE-2025-28915)  

---

### [CVE-2023-45806](CVE-2023-45806-pikariop_yksivaihde-CVE-2023-45806.md) 🟡 

**名称:** CVE-2023-45806-Discourse-正则表达式拒绝服务  
**类型:** 正则表达式拒绝服务 (ReDoS)  
**风险:** 中危，可能导致服务不可用  
**投毒风险:** 100%  
**发现时间:** 2025-03-14  
**POC仓库:** [yksivaihde-CVE-2023-45806](https://github.com/pikariop/yksivaihde-CVE-2023-45806)  

---

### [CVE-2024-49138](CVE-2024-49138-DeividasTerechovas_SOC335-CVE-2024-49138-Exploitation-Detected.md) 🔴 ✅

**名称:** CVE-2024-49138 Windows CLFS 驱动程序提权漏洞  
**类型:** 权限提升  
**风险:** 高危，允许本地权限提升  
**投毒风险:** 95%  
**发现时间:** 2025-03-14  
**POC仓库:** [SOC335-CVE-2024-49138-Exploitation-Detected](https://github.com/DeividasTerechovas/SOC335-CVE-2024-49138-Exploitation-Detected)  

---

### [CVE-2012-2982](CVE-2012-2982-lpuv_CVE-2012-2982.md) 🔴 ✅

**名称:** CVE-2012-2982-Webmin-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 100%  
**发现时间:** 2025-03-14  
**POC仓库:** [CVE-2012-2982](https://github.com/lpuv/CVE-2012-2982)  

---

### [CVE-2025-21333](CVE-2025-21333-Mukesh-blend_CVE-2025-21333-POC.md) 🔴 ✅

**名称:** CVE-2025-21333-Windows Hyper-V NT Kernel Integration VSP Elevation of Privilege Vulnerability  
**类型:** 权限提升 (Elevation of Privilege)  
**风险:** 高危，本地攻击者可获得 SYSTEM 权限  
**投毒风险:** 95%  
**发现时间:** 2025-03-14  
**POC仓库:** [CVE-2025-21333-POC](https://github.com/Mukesh-blend/CVE-2025-21333-POC)  

---

### [CVE-2025-0411](CVE-2025-0411-dpextreme_7-Zip-CVE-2025-0411-POC.md) 🔴 ✅

**名称:** CVE-2025-0411-7-Zip-MotW Bypass  
**类型:** MotW Bypass  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 99%  
**发现时间:** 2025-03-14  
**POC仓库:** [7-Zip-CVE-2025-0411-POC](https://github.com/dpextreme/7-Zip-CVE-2025-0411-POC)  

---


## 🔍 快速查找

- [按CVE编号查找](../../by-cve/)
- [返回2025年总览](../README.md)
- [返回总索引](../../README.md)

---

*本文档由 VulnWatchdog 自动生成 @ 2025-11-26 13:32*
