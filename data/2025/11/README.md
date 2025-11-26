# 2025年11月漏洞情报汇总

> 📅 统计周期: 2025-11-01 ~ 2025-11-30
> 📊 新增漏洞: **608** 个
> 🔥 高危漏洞: **482** 个

---

## 📊 漏洞类型分布

| 类型 | 数量 | 占比 |
|------|------|------|
| 远程代码执行 | 86 | 14.1% |
| 远程代码执行 (RCE) | 56 | 9.2% |
| 权限提升 | 36 | 5.9% |
| 身份验证绕过 | 24 | 3.9% |
| 拒绝服务 (DoS) | 23 | 3.8% |
| SQL注入 | 21 | 3.5% |
| 命令注入 | 16 | 2.6% |
| 路径遍历 | 14 | 2.3% |
| 任意文件上传 | 14 | 2.3% |
| 远程命令执行 | 11 | 1.8% |

---

## 📋 详细列表

### [CVE-2024-29943](CVE-2024-29943-bjrjk_CVE-2024-29943.md) 🔴 ✅

**名称:** CVE-2024-29943 - Firefox JavaScript引擎 Out-of-bounds Read/Write  
**类型:** Out-of-bounds Read/Write  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-11-25  
**POC仓库:** [CVE-2024-29943](https://github.com/bjrjk/CVE-2024-29943)  

---

### [CVE-2024-29943](CVE-2024-29943-seadragnol_CVE-2024-29943.md) 🔴 ✅

**名称:** CVE-2024-29943-Firefox-类型混淆  
**类型:** 类型混淆  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-25  
**POC仓库:** [CVE-2024-29943](https://github.com/seadragnol/CVE-2024-29943)  

---

### [CVE-2025-62726](CVE-2025-62726-baktistr_cve-2025-62726-poc.md) 🔴 ✅

**名称:** CVE-2025-62726-n8n-Remote Code Execution via Git Node Pre-Commit Hook  
**类型:** 远程代码执行  
**风险:** 高危，可能导致系统完全控制和敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-11-25  
**POC仓库:** [cve-2025-62726-poc](https://github.com/baktistr/cve-2025-62726-poc)  

---

### [CVE-2025-62726](CVE-2025-62726-baktistr_cve-2025-62726-legit-repo.md) 🔴 

**名称:** CVE-2025-62726-n8n-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致系统完全控制和数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-11-25  
**POC仓库:** [cve-2025-62726-legit-repo](https://github.com/baktistr/cve-2025-62726-legit-repo)  

---

### [CVE-2025-50165](CVE-2025-50165-fluxmoth_CVE-2025-50165.md) 🔴 ✅

**名称:** CVE-2025-50165-Windows Graphics Component远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 20%  
**发现时间:** 2025-11-24  
**POC仓库:** [CVE-2025-50165](https://github.com/fluxmoth/CVE-2025-50165)  

---

### [CVE-2025-58034](CVE-2025-58034-fluxmoth_CVE-2025-58034.md) 🔴 ✅

**名称:** CVE-2025-58034-FortiWeb-OS 命令注入  
**类型:** OS 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 80%  
**发现时间:** 2025-11-24  
**POC仓库:** [CVE-2025-58034](https://github.com/fluxmoth/CVE-2025-58034)  

---

### [CVE-2022-24992](CVE-2022-24992-esistferry_CVE-2022-24992.md) 🟡 ✅

**名称:** CVE-2022-24992-QRCDR-目录遍历  
**类型:** 目录遍历  
**风险:** 中危，可能导致敏感文件泄露  
**投毒风险:** 5%  
**发现时间:** 2025-11-24  
**POC仓库:** [CVE-2022-24992](https://github.com/esistferry/CVE-2022-24992)  

---

### [CVE-2025-13223](CVE-2025-13223-Darwin72820_CVE-2025-13223.md) 🔴 ✅

**名称:** CVE-2025-13223 - Chrome V8 类型混淆漏洞  
**类型:** 类型混淆  
**风险:** 高危，可能导致堆损坏和任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-24  
**POC仓库:** [CVE-2025-13223](https://github.com/Darwin72820/CVE-2025-13223)  

---

### [CVE-2025-62726](CVE-2025-62726-baktistr_cve-2025-62726-malicious-repo.md) 🔴 ✅

**名称:** CVE-2025-62726-n8n-Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，可能导致系统完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-11-24  
**POC仓库:** [cve-2025-62726-malicious-repo](https://github.com/baktistr/cve-2025-62726-malicious-repo)  

---

### [CVE-2025-49752](CVE-2025-49752-boogabearbombernub_cve-2025-49752-lab.md)  ✅

**名称:** CVE-2025-49752-Azure Bastion权限提升  
**类型:** 权限提升  
**风险:** 严重，可能导致完全控制Azure Bastion实例和相关资源  
**投毒风险:** 80%  
**发现时间:** 2025-11-24  
**POC仓库:** [cve-2025-49752-lab](https://github.com/boogabearbombernub/cve-2025-49752-lab)  

---

### [CVE-2025-65676](CVE-2025-65676-Rivek619_CVE-2025-65676.md) 🟡 ✅

**名称:** CVE-2025-65676-Classroomio LMS-存储型XSS  
**类型:** 存储型XSS  
**风险:** 中危，可能导致会话劫持、账户接管、重定向攻击  
**投毒风险:** 10%  
**发现时间:** 2025-11-24  
**POC仓库:** [CVE-2025-65676](https://github.com/Rivek619/CVE-2025-65676)  

---

### [CVE-2025-65675](CVE-2025-65675-Rivek619_CVE-2025-65675.md) 🟡 ✅

**名称:** CVE-2025-65675-Classroomio-Stored XSS  
**类型:** Stored XSS  
**风险:** 中危，可能导致会话劫持、账户接管和重定向攻击  
**投毒风险:** 5%  
**发现时间:** 2025-11-24  
**POC仓库:** [CVE-2025-65675](https://github.com/Rivek619/CVE-2025-65675)  

---

### [CVE-2025-65669](CVE-2025-65669-Rivek619_CVE-2025-65669.md) 🔴 ✅

**名称:** CVE-2025-65669-classroomio-Broken Access Control  
**类型:** Broken Access Control  
**风险:** 高危，未经授权的数据操作、内容丢失、平台功能中断  
**投毒风险:** 5%  
**发现时间:** 2025-11-24  
**POC仓库:** [CVE-2025-65669](https://github.com/Rivek619/CVE-2025-65669)  

---

### [CVE-2025-49752](CVE-2025-49752-skipdurex661_CVE-2025-49752-Exploit.md)  ✅

**名称:** CVE-2025-49752 - Azure Bastion权限提升漏洞  
**类型:** 身份验证绕过（重放攻击）  
**风险:** 严重，可能导致未经授权的虚拟机访问、数据泄露和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-11-24  
**POC仓库:** [CVE-2025-49752-Exploit](https://github.com/skipdurex661/CVE-2025-49752-Exploit)  

---

### [CVE-2025-65670](CVE-2025-65670-Rivek619_CVE-2025-65670.md) 🟡 ✅

**名称:** CVE-2025-65670-classroomio-IDOR  
**类型:** IDOR/Broken Access Control  
**风险:** 中危，可能导致敏感数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-11-24  
**POC仓库:** [CVE-2025-65670](https://github.com/Rivek619/CVE-2025-65670)  

---

### [CVE-2019-8451](CVE-2019-8451-0xbug_CVE-2019-8451.md) 🔴 ✅

**名称:** CVE-2019-8451-Jira-SSRF  
**类型:** SSRF  
**风险:** 高危，允许远程攻击者访问内部网络资源  
**投毒风险:** 0%  
**发现时间:** 2025-11-24  
**POC仓库:** [CVE-2019-8451](https://github.com/0xbug/CVE-2019-8451)  

---

### [CVE-2019-8451](CVE-2019-8451-ianxtianxt_CVE-2019-8451.md) 🔴 ✅

**名称:** CVE-2019-8451 Jira SSRF漏洞  
**类型:** 服务器端请求伪造 (SSRF)  
**风险:** 高危，可能导致内部信息泄露，攻击者可以利用该漏洞访问内部网络资源。  
**投毒风险:** 0%  
**发现时间:** 2025-11-24  
**POC仓库:** [CVE-2019-8451](https://github.com/ianxtianxt/CVE-2019-8451)  

---

### [CVE-2019-8451](CVE-2019-8451-h0ffayyy_Jira-CVE-2019-8451.md) 🔴 ✅

**名称:** CVE-2019-8451-Jira-SSRF  
**类型:** SSRF  
**风险:** 高危，可能允许远程攻击者访问内部网络资源  
**投毒风险:** 0%  
**发现时间:** 2025-11-24  
**POC仓库:** [Jira-CVE-2019-8451](https://github.com/h0ffayyy/Jira-CVE-2019-8451)  

---

### [CVE-2019-8451](CVE-2019-8451-jas502n_CVE-2019-8451.md) 🔴 ✅

**名称:** CVE-2019-8451-Jira-SSRF  
**类型:** 服务器端请求伪造(SSRF)  
**风险:** 高危，可能允许攻击者访问内部网络资源  
**投毒风险:** 0%  
**发现时间:** 2025-11-24  
**POC仓库:** [CVE-2019-8451](https://github.com/jas502n/CVE-2019-8451)  

---

### [CVE-2019-8451](CVE-2019-8451-b0ul1_CVE-2019-8451.md) 🔴 ✅

**名称:** CVE-2019-8451-Jira-SSRF  
**类型:** SSRF  
**风险:** 高危，可能导致内部信息泄露，访问内部服务。  
**投毒风险:** 0%  
**发现时间:** 2025-11-24  
**POC仓库:** [CVE-2019-8451](https://github.com/b0ul1/CVE-2019-8451)  

---

### [CVE-2025-65681](CVE-2025-65681-Rivek619_CVE-2025-65681.md) 🟡 ✅

**名称:** CVE-2025-65681-tutor-open-edx-信息泄露  
**类型:** 信息泄露  
**风险:** 中危，可能导致个人敏感信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-11-24  
**POC仓库:** [CVE-2025-65681](https://github.com/Rivek619/CVE-2025-65681)  

---

### [CVE-2025-62726](CVE-2025-62726-baktistr_CVE-2025-62726-POC---n8n-Git-Node-RCE.md) 🔴 ✅

**名称:** CVE-2025-62726-n8n-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致系统完全控制和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-11-24  
**POC仓库:** [CVE-2025-62726-POC---n8n-Git-Node-RCE](https://github.com/baktistr/CVE-2025-62726-POC---n8n-Git-Node-RCE)  

---

### [CVE-2024-12084](CVE-2024-12084-InkeyP_CVE-2024-12084.md) 🔴 ✅

**名称:** CVE-2024-12084-Rsync-堆缓冲区溢出  
**类型:** 堆缓冲区溢出  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-11-24  
**POC仓库:** [CVE-2024-12084](https://github.com/InkeyP/CVE-2024-12084)  

---

### [CVE-2025-65672](CVE-2025-65672-Rivek619_CVE-2025-65672.md) 🟡 ✅

**名称:** CVE-2025-65672-classroomio-IDOR  
**类型:** IDOR (Insecure Direct Object Reference)  
**风险:** 中危，可能导致未经授权的课程设置访问和操作  
**投毒风险:** 0%  
**发现时间:** 2025-11-24  
**POC仓库:** [CVE-2025-65672](https://github.com/Rivek619/CVE-2025-65672)  

---

### [CVE-2025-11001](CVE-2025-11001-B1ack4sh_Blackash-CVE-2025-11001.md) 🔴 ✅

**名称:** CVE-2025-11001-7-Zip-目录遍历远程代码执行  
**类型:** 目录遍历导致远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-24  
**POC仓库:** [Blackash-CVE-2025-11001](https://github.com/B1ack4sh/Blackash-CVE-2025-11001)  

---

### [CVE-2023-36845](CVE-2023-36845-Asbawy_Automation-for-Juniper-cve-2023-36845.md) 🔴 ✅

**名称:** CVE-2023-36845-Juniper-J-Web-PHP外部变量修改导致RCE  
**类型:** PHP外部变量修改导致RCE  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-24  
**POC仓库:** [Automation-for-Juniper-cve-2023-36845](https://github.com/Asbawy/Automation-for-Juniper-cve-2023-36845)  

---

### [CVE-2023-36845](CVE-2023-36845-iveresk_CVE-2023-36845-6-.md) 🔴 ✅

**名称:** CVE-2023-36845 Juniper Junos OS J-Web RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-24  
**POC仓库:** [CVE-2023-36845-6-](https://github.com/iveresk/CVE-2023-36845-6-)  

---

### [CVE-2023-36845](CVE-2023-36845-halencarjunior_CVE-2023-36845.md) 🔴 ✅

**名称:** CVE-2023-36845 - Juniper Junos OS J-Web PHP 外部变量修改导致远程代码执行  
**类型:** PHP 外部变量修改  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 20%  
**发现时间:** 2025-11-24  
**POC仓库:** [CVE-2023-36845](https://github.com/halencarjunior/CVE-2023-36845)  

---

### [CVE-2023-36845](CVE-2023-36845-simrotion13_CVE-2023-36845.md) 🔴 ✅

**名称:** CVE-2023-36845-Juniper-J-Web-PHP外部变量修改导致RCE  
**类型:** PHP外部变量修改  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-24  
**POC仓库:** [CVE-2023-36845](https://github.com/simrotion13/CVE-2023-36845)  

---

### [CVE-2023-36845](CVE-2023-36845-cyberh3als_CVE-2023-36845-POC.md)  ✅

**名称:** CVE-2023-36845-Junos-J-Web远程代码执行  
**类型:** PHP外部变量修改导致远程代码执行  
**风险:** 严重，未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-24  
**POC仓库:** [CVE-2023-36845-POC](https://github.com/cyberh3als/CVE-2023-36845-POC)  

---

### [CVE-2023-36845](CVE-2023-36845-zaenhaxor_CVE-2023-36845.md) 🔴 ✅

**名称:** CVE-2023-36845-Junos OS-远程代码执行  
**类型:** PHP外部变量修改导致远程代码执行  
**风险:** 高危，未授权远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-11-24  
**POC仓库:** [CVE-2023-36845](https://github.com/zaenhaxor/CVE-2023-36845)  

---

### [CVE-2023-36845](CVE-2023-36845-P4x1s_ansible-cve-2023-36845.md) 🔴 ✅

**名称:** CVE-2023-36845 Juniper Junos OS J-Web PHP 外部变量修改漏洞  
**类型:** PHP 外部变量修改  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-24  
**POC仓库:** [ansible-cve-2023-36845](https://github.com/P4x1s/ansible-cve-2023-36845)  

---

### [CVE-2023-36845](CVE-2023-36845-kljunowsky_CVE-2023-36845.md)  ✅

**名称:** CVE-2023-36845-Juniper Junos OS J-Web PHP 外部变量修改 RCE  
**类型:** PHP 外部变量修改  
**风险:** 严重，允许未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-24  
**POC仓库:** [CVE-2023-36845](https://github.com/kljunowsky/CVE-2023-36845)  

---

### [CVE-2023-36845](CVE-2023-36845-jahithoque_Juniper-CVE-2023-36845-Mass-Hunting.md)  ✅

**名称:** CVE-2023-36845-Junos OS-PHP外部变量修改导致RCE  
**类型:** 远程代码执行  
**风险:** 严重，允许未经身份验证的远程攻击者执行代码  
**投毒风险:** 0%  
**发现时间:** 2025-11-24  
**POC仓库:** [Juniper-CVE-2023-36845-Mass-Hunting](https://github.com/jahithoque/Juniper-CVE-2023-36845-Mass-Hunting)  

---

### [CVE-2023-36845](CVE-2023-36845-cyb3rzest_Juniper-Bug-Automation-CVE-2023-36845.md) 🔴 

**名称:** CVE-2023-36845 Junos OS J-Web PHP 外部变量修改远程代码执行漏洞  
**类型:** PHP 外部变量修改导致的远程代码执行  
**风险:** 高危，未经身份验证的攻击者可远程执行代码  
**投毒风险:** 0%  
**发现时间:** 2025-11-24  
**POC仓库:** [Juniper-Bug-Automation-CVE-2023-36845](https://github.com/cyb3rzest/Juniper-Bug-Automation-CVE-2023-36845)  

---

### [CVE-2023-36845](CVE-2023-36845-CharonDefalt_Juniper-exploit-CVE-2023-36845.md)  ✅

**名称:** CVE-2023-36845-Junos OS J-Web PHP 外部变量修改导致远程代码执行  
**类型:** PHP 外部变量修改  
**风险:** 严重，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-24  
**POC仓库:** [Juniper-exploit-CVE-2023-36845](https://github.com/CharonDefalt/Juniper-exploit-CVE-2023-36845)  

---

### [CVE-2023-36845](CVE-2023-36845-ak1t4_CVE-2023-36845.md)  ✅

**名称:** CVE-2023-36845-Juniper-J-Web-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，未经身份验证的攻击者可以远程执行代码  
**投毒风险:** 10%  
**发现时间:** 2025-11-24  
**POC仓库:** [CVE-2023-36845](https://github.com/ak1t4/CVE-2023-36845)  

---

### [CVE-2023-36845](CVE-2023-36845-0xNehru_CVE-2023-36845-Juniper-Vulnerability.md) 🔴 ✅

**名称:** CVE-2023-36845-Junos OS J-Web PHP 外部变量修改导致远程代码执行  
**类型:** PHP 外部变量修改  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-24  
**POC仓库:** [CVE-2023-36845-Juniper-Vulnerability](https://github.com/0xNehru/CVE-2023-36845-Juniper-Vulnerability)  

---

### [CVE-2023-36845](CVE-2023-36845-e11i0t4lders0n_CVE-2023-36845.md) 🔴 ✅

**名称:** CVE-2023-36845-Juniper-J-Web-RCE  
**类型:** PHP 外部变量修改导致RCE  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-24  
**POC仓库:** [CVE-2023-36845](https://github.com/e11i0t4lders0n/CVE-2023-36845)  

---

### [CVE-2023-36845](CVE-2023-36845-ifconfig-me_CVE-2023-36845.md)  ✅

**名称:** CVE-2023-36845 - Juniper Junos OS J-Web PHP External Variable Modification  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，允许未经身份验证的远程攻击者执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-11-24  
**POC仓库:** [CVE-2023-36845](https://github.com/ifconfig-me/CVE-2023-36845)  

---

### [CVE-2023-36845](CVE-2023-36845-vulncheck-oss_cve-2023-36845-scanner.md)  ✅

**名称:** CVE-2023-36845-Junos OS-J-Web-PHP外部变量修改-远程代码执行  
**类型:** PHP外部变量修改  
**风险:** 严重，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-24  
**POC仓库:** [cve-2023-36845-scanner](https://github.com/vulncheck-oss/cve-2023-36845-scanner)  

---

### [CVE-2023-36845](CVE-2023-36845-kopfjager007_CVE-2023-36845.md) 🔴 ✅

**名称:** CVE-2023-36845  
**类型:** PHP 外部变量修改  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-24  
**POC仓库:** [CVE-2023-36845](https://github.com/kopfjager007/CVE-2023-36845)  

---

### [CVE-2022-30190](CVE-2022-30190-Arkha-Corvus_LetsDefend-SOC173-Follina-0-Day-Detected.md) 🔴 ✅

**名称:** CVE-2022-30190 - Microsoft MSDT 远程代码执行漏洞 (Follina)  
**类型:** 远程代码执行  
**风险:** 高危，可导致远程代码执行，权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-11-24  
**POC仓库:** [LetsDefend-SOC173-Follina-0-Day-Detected](https://github.com/Arkha-Corvus/LetsDefend-SOC173-Follina-0-Day-Detected)  

---

### [CVE-2017-0144](CVE-2017-0144-AbbeAlthany_Windows-7_och_CVE-2017-0144_Exploit.md) 🔴 ✅

**名称:** CVE-2017-0144 - Windows SMB 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-24  
**POC仓库:** [Windows-7_och_CVE-2017-0144_Exploit](https://github.com/AbbeAlthany/Windows-7_och_CVE-2017-0144_Exploit)  

---

### [CVE-2025-38678](CVE-2025-38678-guard-wait_CVE-2025-38678_POC.md) 🟡 

**名称:** CVE-2025-38678-Linux Kernel-Netfilter Device Duplication  
**类型:** 内核漏洞  
**风险:** 中危，可能导致系统不稳定或拒绝服务  
**投毒风险:** 0%  
**发现时间:** 2025-11-24  
**POC仓库:** [CVE-2025-38678_POC](https://github.com/guard-wait/CVE-2025-38678_POC)  

---

### [CVE-2025-64087](CVE-2025-64087-AT190510-Cuong_CVE-2025-64087-SSTI-.md)  ✅

**名称:** CVE-2025-64087 (SSTI FreeMarker)  
**类型:** 服务器端模板注入 (SSTI)  
**风险:** 严重，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-24  
**POC仓库:** [CVE-2025-64087-SSTI-](https://github.com/AT190510-Cuong/CVE-2025-64087-SSTI-)  

---

### [CVE-2025-63735](CVE-2025-63735-huthx_CVE-2025-63735-Ruckus-Unleashed-Reflected-XSS.md) 🔴 ✅

**名称:** CVE-2025-63735-Ruckus Unleashed-Reflected XSS  
**类型:** Reflected XSS  
**风险:** 高危，可能导致会话劫持、凭据盗窃、强制重定向或UI操纵  
**投毒风险:** 10%  
**发现时间:** 2025-11-24  
**POC仓库:** [CVE-2025-63735-Ruckus-Unleashed-Reflected-XSS](https://github.com/huthx/CVE-2025-63735-Ruckus-Unleashed-Reflected-XSS)  

---

### [CVE-2025-50165](CVE-2025-50165-blintray_CVE-2025-50165.md) 🔴 ✅

**名称:** CVE-2025-50165 Windows Graphics Component Remote Code Execution Vulnerability  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 95%  
**发现时间:** 2025-11-24  
**POC仓库:** [CVE-2025-50165](https://github.com/blintray/CVE-2025-50165)  

---

### [CVE-2025-5777](CVE-2025-5777-rashedhasan090_CVE-2025-5777.md) 🔴 ✅

**名称:** CVE-2025-5777 NetScaler ADC 和 NetScaler Gateway 内存泄漏  
**类型:** 内存泄漏 (Memory Overread)  
**风险:** 高危，可能导致敏感信息泄露，包括会话令牌、身份验证数据和凭据  
**投毒风险:** 10%  
**发现时间:** 2025-11-23  
**POC仓库:** [CVE-2025-5777](https://github.com/rashedhasan090/CVE-2025-5777)  

---

### [CVE-2024-10220](CVE-2024-10220-saleha-muzammil_cve-2024-10220-git-on-git.md) 🔴 ✅

**名称:** CVE-2024-10220-Kubernetes-kubelet-gitRepo命令执行  
**类型:** 命令执行  
**风险:** 高危，可导致节点被控制  
**投毒风险:** 0%  
**发现时间:** 2025-11-23  
**POC仓库:** [cve-2024-10220-git-on-git](https://github.com/saleha-muzammil/cve-2024-10220-git-on-git)  

---

### [CVE-2025-65018](CVE-2025-65018-Neo-Neo6_CVE-2025-65018-Heap-buffer-overflow-in-libpng-ps4-ps5-.md)  

**名称:** 未提供漏洞名称  
**类型:** License文件  
**风险:** 低危，仅为Apache License 2.0  
**投毒风险:** 0%  
**发现时间:** 2025-11-23  
**POC仓库:** [CVE-2025-65018-Heap-buffer-overflow-in-libpng-ps4-ps5-](https://github.com/Neo-Neo6/CVE-2025-65018-Heap-buffer-overflow-in-libpng-ps4-ps5-)  

---

### [CVE-2025-8943](CVE-2025-8943-B1ack4sh_Blackash-CVE-2025-8943.md) 🔴 

**名称:** CVE-2025-8943-Flowise-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致完全控制受影响的系统  
**投毒风险:** 0%  
**发现时间:** 2025-11-23  
**POC仓库:** [Blackash-CVE-2025-8943](https://github.com/B1ack4sh/Blackash-CVE-2025-8943)  

---

### [CVE-2025-24054](CVE-2025-24054-Untouchable17_CVE-2025-24054.md) 🟡 ✅

**名称:** CVE-2025-24054 - Windows NTLM Hash Disclosure Spoofing Vulnerability  
**类型:** NTLM Hash Disclosure / Spoofing  
**风险:** 中危，可能导致凭据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-11-23  
**POC仓库:** [CVE-2025-24054](https://github.com/Untouchable17/CVE-2025-24054)  

---

### [CVE-2025-50165](CVE-2025-50165-callinston_CVE-2025-50165.md) 🔴 ✅

**名称:** CVE-2025-50165-Windows Graphics Component-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-23  
**POC仓库:** [CVE-2025-50165](https://github.com/callinston/CVE-2025-50165)  

---

### [CVE-2025-8088](CVE-2025-8088-h0melike_cve-2025-8088.md) 🔴 ✅

**名称:** CVE-2025-8088 WinRAR 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-23  
**POC仓库:** [cve-2025-8088](https://github.com/h0melike/cve-2025-8088)  

---

### [CVE-2021-43267](CVE-2021-43267-DarkSprings_CVE-2021-43267-POC.md) 🔴 

**名称:** CVE-2021-43267-Linux Kernel TIPC MSG_CRYPTO Stack Overflow  
**类型:** 栈溢出  
**风险:** 高危，可能导致系统崩溃或远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-23  
**POC仓库:** [CVE-2021-43267-POC](https://github.com/DarkSprings/CVE-2021-43267-POC)  

---

### [CVE-2021-43267](CVE-2021-43267-zzhacked_CVE-2021-43267.md) 🔴 ✅

**名称:** CVE-2021-43267-Linux Kernel TIPC Stack Overflow  
**类型:** 栈溢出  
**风险:** 高危，可能导致内核崩溃或任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-23  
**POC仓库:** [CVE-2021-43267](https://github.com/zzhacked/CVE-2021-43267)  

---

### [CVE-2021-43267](CVE-2021-43267-YunchoHang_CVE-2021-43267.md) 🔴 ✅

**名称:** CVE-2021-43267-Linux Kernel TIPC-栈溢出  
**类型:** 栈溢出  
**风险:** 高危，可能导致内核崩溃或任意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-23  
**POC仓库:** [CVE-2021-43267](https://github.com/YunchoHang/CVE-2021-43267)  

---

### [CVE-2025-65482](CVE-2025-65482-AT190510-Cuong_CVE-2025-65482-XXE-.md) 🔴 ✅

**名称:** CVE-2025-65482 (XXE) - XDocReport  
**类型:** XML 外部实体注入 (XXE)  
**风险:** 高危，可能导致敏感信息泄露、远程文件读取、服务器端请求伪造 (SSRF)  
**投毒风险:** 10%  
**发现时间:** 2025-11-23  
**POC仓库:** [CVE-2025-65482-XXE-](https://github.com/AT190510-Cuong/CVE-2025-65482-XXE-)  

---

### [CVE-2025-64087](CVE-2025-64087-AT190510-Cuong_CVE-2025-64087-SSTI-.md) 🔴 ✅

**名称:** CVE-2025-64087 XDocReport Freemarker SSTI  
**类型:** 服务器端模板注入 (SSTI)  
**风险:** 高危，可能导致远程代码执行和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-11-23  
**POC仓库:** [CVE-2025-64087-SSTI-](https://github.com/AT190510-Cuong/CVE-2025-64087-SSTI-)  

---

### [CVE-2025-10230](CVE-2025-10230-nehkark_CVE-2025-10230.md) 🔴 ✅

**名称:** CVE-2025-10230-Samba-WINS Hook命令注入  
**类型:** 命令注入  
**风险:** 高危，允许未经身份验证的远程攻击者以Samba进程权限执行任意命令  
**投毒风险:** 1%  
**发现时间:** 2025-11-23  
**POC仓库:** [CVE-2025-10230](https://github.com/nehkark/CVE-2025-10230)  

---

### [CVE-2017-7494](CVE-2017-7494-homjxi0e_CVE-2017-7494.md) 🔴 ✅

**名称:** CVE-2017-7494 - Samba 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-11-22  
**POC仓库:** [CVE-2017-7494](https://github.com/homjxi0e/CVE-2017-7494)  

---

### [CVE-2017-7494](CVE-2017-7494-cved-sources_cve-2017-7494.md) 🔴 ✅

**名称:** CVE-2017-7494-Samba-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许恶意客户端上传共享库到可写共享，然后导致服务器加载并执行它。  
**投毒风险:** 10%  
**发现时间:** 2025-11-22  
**POC仓库:** [cve-2017-7494](https://github.com/cved-sources/cve-2017-7494)  

---

### [CVE-2017-7494](CVE-2017-7494-Waffles-2_SambaCry.md) 🔴 ✅

**名称:** CVE-2017-7494 Samba 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-11-22  
**POC仓库:** [SambaCry](https://github.com/Waffles-2/SambaCry)  

---

### [CVE-2017-7494](CVE-2017-7494-betab0t_cve-2017-7494.md) 🔴 ✅

**名称:** CVE-2017-7494 Samba 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和完全控制服务器  
**投毒风险:** 0%  
**发现时间:** 2025-11-22  
**POC仓库:** [cve-2017-7494](https://github.com/betab0t/cve-2017-7494)  

---

### [CVE-2017-7494](CVE-2017-7494-Zer0d0y_Samba-CVE-2017-7494.md) 🔴 ✅

**名称:** CVE-2017-7494 Samba 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-11-22  
**POC仓库:** [Samba-CVE-2017-7494](https://github.com/Zer0d0y/Samba-CVE-2017-7494)  

---

### [CVE-2017-7494](CVE-2017-7494-incredible1yu_CVE-2017-7494.md) 🔴 ✅

**名称:** CVE-2017-7494-Samba-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-11-22  
**POC仓库:** [CVE-2017-7494](https://github.com/incredible1yu/CVE-2017-7494)  

---

### [CVE-2017-7494](CVE-2017-7494-john-80_cve-2017-7494.md) 🔴 ✅

**名称:** CVE-2017-7494-Samba-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-11-22  
**POC仓库:** [cve-2017-7494](https://github.com/john-80/cve-2017-7494)  

---

### [CVE-2017-7494](CVE-2017-7494-Hansindu-M_CVE-2017-7494_IT19115344.md) 🔴 ✅

**名称:** CVE-2017-7494 - Samba 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许恶意客户端以 root 权限执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-11-22  
**POC仓库:** [CVE-2017-7494_IT19115344](https://github.com/Hansindu-M/CVE-2017-7494_IT19115344)  

---

### [CVE-2017-7494](CVE-2017-7494-joxeankoret_CVE-2017-7494.md) 🔴 ✅

**名称:** CVE-2017-7494-Samba-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-11-22  
**POC仓库:** [CVE-2017-7494](https://github.com/joxeankoret/CVE-2017-7494)  

---

### [CVE-2017-7494](CVE-2017-7494-I-Rinka_BIT-EternalBlue-for-macOS_Linux.md) 🔴 ✅

**名称:** CVE-2017-7494 Samba 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许恶意客户端上传共享库并执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-22  
**POC仓库:** [BIT-EternalBlue-for-macOS_Linux](https://github.com/I-Rinka/BIT-EternalBlue-for-macOS_Linux)  

---

### [CVE-2017-7494](CVE-2017-7494-0xm4ud_noSAMBAnoCRY-CVE-2017-7494.md) 🔴 ✅

**名称:** CVE-2017-7494 - Samba远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许恶意客户端执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-11-22  
**POC仓库:** [noSAMBAnoCRY-CVE-2017-7494](https://github.com/0xm4ud/noSAMBAnoCRY-CVE-2017-7494)  

---

### [CVE-2017-7494](CVE-2017-7494-adjaliya_-CVE-2017-7494-Samba-Exploit-POC.md) 🔴 ✅

**名称:** CVE-2017-7494-Samba-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许恶意客户端上传共享库并导致服务器加载和执行，从而实现远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-22  
**POC仓库:** [-CVE-2017-7494-Samba-Exploit-POC](https://github.com/adjaliya/-CVE-2017-7494-Samba-Exploit-POC)  

---

### [CVE-2017-7494](CVE-2017-7494-brianwrf_SambaHunter.md) 🔴 ✅

**名称:** CVE-2017-7494-Samba-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-11-22  
**POC仓库:** [SambaHunter](https://github.com/brianwrf/SambaHunter)  

---

### [CVE-2017-7494](CVE-2017-7494-00mjk_exploit-CVE-2017-7494.md) 🔴 ✅

**名称:** CVE-2017-7494 SambaCry 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致完全控制受影响的服务器  
**投毒风险:** 10%  
**发现时间:** 2025-11-22  
**POC仓库:** [exploit-CVE-2017-7494](https://github.com/00mjk/exploit-CVE-2017-7494)  

---

### [CVE-2017-7494](CVE-2017-7494-d3fudd_CVE-2017-7494_SambaCry.md) 🔴 ✅

**名称:** CVE-2017-7494 SambaCry  
**类型:** 远程代码执行  
**风险:** 高危，允许恶意客户端上传共享库到可写共享目录，并导致服务器加载和执行它，从而实现远程代码执行。  
**投毒风险:** 10%  
**发现时间:** 2025-11-22  
**POC仓库:** [CVE-2017-7494_SambaCry](https://github.com/d3fudd/CVE-2017-7494_SambaCry)  

---

### [CVE-2017-7494](CVE-2017-7494-opsxcq_exploit-CVE-2017-7494.md) 🔴 ✅

**名称:** CVE-2017-7494-Samba-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致完全控制受影响的系统  
**投毒风险:** 10%  
**发现时间:** 2025-11-22  
**POC仓库:** [exploit-CVE-2017-7494](https://github.com/opsxcq/exploit-CVE-2017-7494)  

---

### [CVE-2017-7494](CVE-2017-7494-FelipeR-UFBA_cve-2017-7494-fixed.md) 🔴 ✅

**名称:** CVE-2017-7494-Samba-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致完全控制受影响的系统  
**投毒风险:** 10%  
**发现时间:** 2025-11-22  
**POC仓库:** [cve-2017-7494-fixed](https://github.com/FelipeR-UFBA/cve-2017-7494-fixed)  

---

### [CVE-2025-11001](CVE-2025-11001-ranasen-rat_CVE-2025-11001.md) 🔴 ✅

**名称:** CVE-2025-11001-7-Zip-目录遍历远程代码执行  
**类型:** 目录遍历远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-22  
**POC仓库:** [CVE-2025-11001](https://github.com/ranasen-rat/CVE-2025-11001)  

---

### [CVE-2025-11001](CVE-2025-11001-mbanyamer_CVE-2025-11001---7-Zip.md) 🔴 ✅

**名称:** CVE-2025-11001-7-Zip-目录遍历远程代码执行  
**类型:** 目录遍历远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-22  
**POC仓库:** [CVE-2025-11001---7-Zip](https://github.com/mbanyamer/CVE-2025-11001---7-Zip)  

---

### [CVE-2025-64459](CVE-2025-64459-omarkurt_django-connector-CVE-2025-64459-testbed.md) 🔴 ✅

**名称:** CVE-2025-64459-Django-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-11-21  
**POC仓库:** [django-connector-CVE-2025-64459-testbed](https://github.com/omarkurt/django-connector-CVE-2025-64459-testbed)  

---

### [CVE-2025-49752](CVE-2025-49752-skipdurex661_cve-2025-49752-Exploit.md) 🔴 

**名称:** CVE-2025-49752-Azure Bastion 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致未经授权的访问和控制Azure资源  
**投毒风险:** 5%  
**发现时间:** 2025-11-21  
**POC仓库:** [cve-2025-49752-Exploit](https://github.com/skipdurex661/cve-2025-49752-Exploit)  

---

### [CVE-2023-22515](CVE-2023-22515-CyberSentinel321_cve-2023-22515-lab.md) 🔴 ✅

**名称:** CVE-2023-22515-Confluence Authentication Bypass  
**类型:** Authentication Bypass  
**风险:** Critical，未经授权的管理员权限访问和潜在的远程代码执行  
**投毒风险:** 60%  
**发现时间:** 2025-11-21  
**POC仓库:** [cve-2023-22515-lab](https://github.com/CyberSentinel321/cve-2023-22515-lab)  

---

### [CVE-2025-40547](CVE-2025-40547-zigzagymym1986_CVE-2025-40547.md) 🔴 ✅

**名称:** CVE-2025-40547 - SolarWinds Serv-U Administrative Pre-Authenticated Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，可能导致完全控制受影响的系统  
**投毒风险:** 10%  
**发现时间:** 2025-11-21  
**POC仓库:** [CVE-2025-40547](https://github.com/zigzagymym1986/CVE-2025-40547)  

---

### [CVE-2025-63406](CVE-2025-63406-richard-natan_PoC-CVE-2025-63406.md) 🔴 ✅

**名称:** CVE-2025-63406-Intermesh_BV_GroupOffice-命令注入  
**类型:** 命令注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-11-21  
**POC仓库:** [PoC-CVE-2025-63406](https://github.com/richard-natan/PoC-CVE-2025-63406)  

---

### [CVE-2025-61882](CVE-2025-61882-Zhert-lab_CVE-2025-61882-CVE-2025-61884.md) 🔴 ✅

**名称:** CVE-2025-61882 - Oracle Concurrent Processing 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-11-21  
**POC仓库:** [CVE-2025-61882-CVE-2025-61884](https://github.com/Zhert-lab/CVE-2025-61882-CVE-2025-61884)  

---

### [CVE-2024-58258](CVE-2024-58258-Web3-Serializer_CVE-2024-58258.md) 🔴 ✅

**名称:** CVE-2024-58258 - SugarCRM SSRF/Local File Disclosure  
**类型:** SSRF/Local File Disclosure  
**风险:** 高危，可能导致敏感信息泄露、内部系统访问  
**投毒风险:** 10%  
**发现时间:** 2025-11-21  
**POC仓库:** [CVE-2024-58258](https://github.com/Web3-Serializer/CVE-2024-58258)  

---

### [CVE-2022-24707](CVE-2022-24707-Altelus1_CVE-2022-24707.md) 🔴 ✅

**名称:** CVE-2022-24707-Anuko Time Tracker-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露，数据篡改，甚至服务器控制  
**投毒风险:** 10%  
**发现时间:** 2025-11-21  
**POC仓库:** [CVE-2022-24707](https://github.com/Altelus1/CVE-2022-24707)  

---

### [CVE-2022-24707](CVE-2022-24707-thepiyushkumarshukla_CVE-2022-24707_AnukoTimeTracker_Version-1.20.0_POC.md) 🔴 ✅

**名称:** CVE-2022-24707-Anuko Time Tracker-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-11-21  
**POC仓库:** [CVE-2022-24707_AnukoTimeTracker_Version-1.20.0_POC](https://github.com/thepiyushkumarshukla/CVE-2022-24707_AnukoTimeTracker_Version-1.20.0_POC)  

---

### [CVE-2025-47916](CVE-2025-47916-Web3-Serializer_CVE-2025-47916.md) 🔴 ✅

**名称:** CVE-2025-47916 - Invision Community Remote Code Execution (RCE)  
**类型:** 远程代码执行  
**风险:** 高危，允许未授权用户执行任意PHP代码  
**投毒风险:** 10%  
**发现时间:** 2025-11-21  
**POC仓库:** [CVE-2025-47916](https://github.com/Web3-Serializer/CVE-2025-47916)  

---

### [CVE-2025-10680](CVE-2025-10680-B1ack4sh_Blackash-CVE-2025-10680.md) 🔴 

**名称:** CVE-2025-10680-OpenVPN-OS Command Injection  
**类型:** OS Command Injection  
**风险:** 高危，允许远程攻击者在服务器上执行任意命令  
**投毒风险:** 0%  
**发现时间:** 2025-11-21  
**POC仓库:** [Blackash-CVE-2025-10680](https://github.com/B1ack4sh/Blackash-CVE-2025-10680)  

---

### [CVE-2025-41115](CVE-2025-41115-B1ack4sh_Blackash-CVE-2025-41115.md) 🔴 ✅

**名称:** CVE-2025-41115 - Grafana Enterprise SCIM UID Overwrite  
**类型:** 权限提升  
**风险:** 高危，可导致管理员权限获取  
**投毒风险:** 5%  
**发现时间:** 2025-11-21  
**POC仓库:** [Blackash-CVE-2025-41115](https://github.com/B1ack4sh/Blackash-CVE-2025-41115)  

---

### [CVE-2025-61757](CVE-2025-61757-Jinxia62_Oracle-Identity-Manager-CVE-2025-61757.md) 🔴 ✅

**名称:** CVE-2025-61757-Oracle Identity Manager-认证绕过和远程命令执行  
**类型:** 认证绕过和远程命令执行  
**风险:** 高危，可能导致系统接管  
**投毒风险:** 0%  
**发现时间:** 2025-11-21  
**POC仓库:** [Oracle-Identity-Manager-CVE-2025-61757](https://github.com/Jinxia62/Oracle-Identity-Manager-CVE-2025-61757)  

---

### [CVE-2025-40547](CVE-2025-40547-B1ack4sh_Blackash-CVE-2025-40547.md) 🔴 ✅

**名称:** CVE-2025-40547 - SolarWinds Serv-U 逻辑错误导致远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，在具有管理员权限的情况下可导致完全系统控制  
**投毒风险:** 0%  
**发现时间:** 2025-11-21  
**POC仓库:** [Blackash-CVE-2025-40547](https://github.com/B1ack4sh/Blackash-CVE-2025-40547)  

---

### [CVE-2025-9242](CVE-2025-9242-B1ack4sh_Blackash-CVE-2025-9242.md) 🔴 ✅

**名称:** CVE-2025-9242 - WatchGuard Fireware OS 远程代码执行  
**类型:** Out-of-bounds Write  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-21  
**POC仓库:** [Blackash-CVE-2025-9242](https://github.com/B1ack4sh/Blackash-CVE-2025-9242)  

---

### [CVE-2025-63729](CVE-2025-63729-Yashodhanvivek_CVE-2025-63729-Syrotech-SY-GPON-1110-.md) 🔴 ✅

**名称:** CVE-2025-63729-SY-GPON-1110-WDONT-私钥泄露  
**类型:** 私钥泄露  
**风险:** 高危，可能导致设备身份伪造、中间人攻击、数据窃取等。  
**投毒风险:** 5%  
**发现时间:** 2025-11-21  
**POC仓库:** [CVE-2025-63729-Syrotech-SY-GPON-1110-](https://github.com/Yashodhanvivek/CVE-2025-63729-Syrotech-SY-GPON-1110-)  

---

### [CVE-2025-53772](CVE-2025-53772-SleepNotF0und_CVE-2025-53772-IIS-WebDeploy-RCE-POC.md) 🔴 ✅

**名称:** CVE-2025-53772-Web Deploy-反序列化RCE  
**类型:** 反序列化远程代码执行  
**风险:** 高危，允许未授权的攻击者通过网络执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-11-21  
**POC仓库:** [CVE-2025-53772-IIS-WebDeploy-RCE-POC](https://github.com/SleepNotF0und/CVE-2025-53772-IIS-WebDeploy-RCE-POC)  

---

### [CVE-2025-12916](CVE-2025-12916-Jinxia62_Sangfor-CVE-2025-12916.md) 🟡 ✅

**名称:** CVE-2025-12916-Sangfor Operation and Maintenance Security Management System-命令注入  
**类型:** 命令注入  
**风险:** 中危，CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L/E:P/RL:O/RC:C  
**投毒风险:** 1%  
**发现时间:** 2025-11-21  
**POC仓库:** [Sangfor-CVE-2025-12916](https://github.com/Jinxia62/Sangfor-CVE-2025-12916)  

---

### [CVE-2025-59287](CVE-2025-59287-Adel-kaka-dz_cve-2025-59287.md) 🔴 ✅

**名称:** CVE-2025-59287 - Windows Server Update Service (WSUS) 远程代码执行漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-21  
**POC仓库:** [cve-2025-59287](https://github.com/Adel-kaka-dz/cve-2025-59287)  

---

### [CVE-2025-63888](CVE-2025-63888-AN5I_cve-2025-63888-exploit.md) 🔴 ✅

**名称:** CVE-2025-63888 ThinkPHP 5.0.24 文件包含远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-11-21  
**POC仓库:** [cve-2025-63888-exploit](https://github.com/AN5I/cve-2025-63888-exploit)  

---

### [CVE-2025-12735](CVE-2025-12735-alnashawatirohwederb2167-max_cve-2025-12735-expr-eval-rce.md) 🔴 ✅

**名称:** CVE-2025-12735 expr-eval 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者执行任意系统命令  
**投毒风险:** 10%  
**发现时间:** 2025-11-21  
**POC仓库:** [cve-2025-12735-expr-eval-rce](https://github.com/alnashawatirohwederb2167-max/cve-2025-12735-expr-eval-rce)  

---

### [CVE-2025-12735](CVE-2025-12735-AN5I_cve-2025-12735-expr-eval-rce.md) 🔴 ✅

**名称:** CVE-2025-12735 expr-eval RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-11-21  
**POC仓库:** [cve-2025-12735-expr-eval-rce](https://github.com/AN5I/cve-2025-12735-expr-eval-rce)  

---

### [CVE-2025-64446](CVE-2025-64446-AN5I_cve-2025-64446-fortiweb-exploit.md) 🔴 ✅

**名称:** CVE-2025-64446 Fortinet FortiWeb Path Traversal RCE  
**类型:** 路径遍历导致远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者执行管理命令，可能导致系统完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-11-21  
**POC仓库:** [cve-2025-64446-fortiweb-exploit](https://github.com/AN5I/cve-2025-64446-fortiweb-exploit)  

---

### [CVE-2025-59501](CVE-2025-59501-garrettfoster13_CVE-2025-59501.md) 🟡 

**名称:** CVE-2025-59501-Microsoft Configuration Manager 身份验证绕过  
**类型:** 身份验证绕过/欺骗  
**风险:** 中危，可能导致欺骗攻击  
**投毒风险:** 0%  
**发现时间:** 2025-11-20  
**POC仓库:** [CVE-2025-59501](https://github.com/garrettfoster13/CVE-2025-59501)  

---

### [CVE-2024-3721](CVE-2024-3721-qalvynn_Mirai-Based-CVE-2024-3721-Selfrep.md) 🔴 ✅

**名称:** CVE-2024-3721-TBK DVR-4104/DVR-4216-OS 命令注入  
**类型:** OS 命令注入  
**风险:** 高危，可能导致设备被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-11-20  
**POC仓库:** [Mirai-Based-CVE-2024-3721-Selfrep](https://github.com/qalvynn/Mirai-Based-CVE-2024-3721-Selfrep)  

---

### [CVE-2023-38831](CVE-2023-38831-anelya0333_Exploiting-CVE-2023-38831.md) 🔴 ✅

**名称:** CVE-2023-38831-WinRAR-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-20  
**POC仓库:** [Exploiting-CVE-2023-38831](https://github.com/anelya0333/Exploiting-CVE-2023-38831)  

---

### [CVE-2025-23247](CVE-2025-23247-SpiralBL0CK_CVE-2025-23247.md) 🟡 ✅

**名称:** CVE-2025-23247-NVIDIA CUDA Toolkit-缓冲区长度验证失败导致代码执行  
**类型:** 缓冲区溢出  
**风险:** 中危，可能导致拒绝服务或任意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-20  
**POC仓库:** [CVE-2025-23247](https://github.com/SpiralBL0CK/CVE-2025-23247)  

---

### [CVE-2025-7892](CVE-2025-7892-FlyingLemonade_CVE-2025-7892-Proof-of-Concept-Login-Form.md) 🟡 ✅

**名称:** CVE-2025-7892-IDnow App-AndroidManifest.xml组件导出不当  
**类型:** Android组件导出不当  
**风险:** 中危，可能允许恶意应用利用导出的组件执行未授权操作  
**投毒风险:** 10%  
**发现时间:** 2025-11-20  
**POC仓库:** [CVE-2025-7892-Proof-of-Concept-Login-Form](https://github.com/FlyingLemonade/CVE-2025-7892-Proof-of-Concept-Login-Form)  

---

### [CVE-2025-63499](CVE-2025-63499-xryptoh_CVE-2025-63499.md)  ✅

**名称:** CVE-2025-63499  
**类型:** 未知  
**风险:** 未知  
**投毒风险:** 10%  
**发现时间:** 2025-11-20  
**POC仓库:** [CVE-2025-63499](https://github.com/xryptoh/CVE-2025-63499)  

---

### [CVE-2025-61757](CVE-2025-61757-B1ack4sh_Blackash-CVE-2025-61757.md) 🔴 

**名称:** CVE-2025-61757-Oracle Identity Manager-权限绕过  
**类型:** 权限绕过  
**风险:** 高危，可能导致完全控制 Identity Manager  
**投毒风险:** 10%  
**发现时间:** 2025-11-20  
**POC仓库:** [Blackash-CVE-2025-61757](https://github.com/B1ack4sh/Blackash-CVE-2025-61757)  

---

### [CVE-2025-61765](CVE-2025-61765-locus-x64_CVE-2025-61765_PoC.md) 🔴 ✅

**名称:** CVE-2025-61765-python-socketio-RCE  
**类型:** 反序列化漏洞/RCE  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-20  
**POC仓库:** [CVE-2025-61765_PoC](https://github.com/locus-x64/CVE-2025-61765_PoC)  

---

### [CVE-2025-11001](CVE-2025-11001-lastvocher_7zip-CVE-2025-11001.md) 🔴 ✅

**名称:** CVE-2025-11001 7-Zip ZIP 文件解析目录遍历远程代码执行漏洞  
**类型:** 目录遍历/远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-20  
**POC仓库:** [7zip-CVE-2025-11001](https://github.com/lastvocher/7zip-CVE-2025-11001)  

---

### [CVE-2024-21413](CVE-2024-21413-hau2212_Moniker-Link-CVE-2024-21413-.md) 🔴 ✅

**名称:** CVE-2024-21413-Microsoft Outlook远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行，完全控制受害者系统  
**投毒风险:** 0%  
**发现时间:** 2025-11-20  
**POC仓库:** [Moniker-Link-CVE-2024-21413-](https://github.com/hau2212/Moniker-Link-CVE-2024-21413-)  

---

### [CVE-2025-63914](CVE-2025-63914-WxDou_CVE-2025-63914.md) 🔴 ✅

**名称:** CVE-2025-63914-Cinnamon/kotaemon-Zip炸弹  
**类型:** Zip炸弹  
**风险:** 高危，可能导致服务崩溃或主机宕机  
**投毒风险:** 5%  
**发现时间:** 2025-11-20  
**POC仓库:** [CVE-2025-63914](https://github.com/WxDou/CVE-2025-63914)  

---

### [CVE-2025-3248](CVE-2025-3248-drackyjr_-CVE-2025-3248.md) 🔴 ✅

**名称:** CVE-2025-3248 Langflow Unauthenticated RCE  
**类型:** 代码注入/远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-20  
**POC仓库:** [-CVE-2025-3248](https://github.com/drackyjr/-CVE-2025-3248)  

---

### [CVE-2018-15133](CVE-2018-15133-Loaxert_CVE-2018-15133-PoC.md) 🔴 ✅

**名称:** CVE-2018-15133-Laravel框架-反序列化远程代码执行  
**类型:** 反序列化远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-11-20  
**POC仓库:** [CVE-2018-15133-PoC](https://github.com/Loaxert/CVE-2018-15133-PoC)  

---

### [CVE-2025-63572](CVE-2025-63572-RRespxwnss_CVE-2025-63572.md) 🔴 ✅

**名称:** Zentrajuris v.1.0 SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、数据篡改甚至系统完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2025-63572](https://github.com/RRespxwnss/CVE-2025-63572)  

---

### [CVE-2024-2873](CVE-2024-2873-stuxbench_dropbear-cve-2024-2873.md)  ✅

**名称:** CVE-2024-2873 - wolfSSH 用户认证绕过  
**类型:** 认证绕过  
**风险:** 严重，可能导致未经授权的访问，完全控制受影响的系统  
**投毒风险:** 0%  
**发现时间:** 2025-11-19  
**POC仓库:** [dropbear-cve-2024-2873](https://github.com/stuxbench/dropbear-cve-2024-2873)  

---

### [CVE-2025-40629](CVE-2025-40629-omr00t_CVE-2025-40629.md) 🔴 ✅

**名称:** CVE-2025-40629 - PNETLab 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感文件泄露  
**投毒风险:** 0%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2025-40629](https://github.com/omr00t/CVE-2025-40629)  

---

### [CVE-2025-27591](CVE-2025-27591-0x00Jeff_CVE-2025-27591.md) 🔴 ✅

**名称:** CVE-2025-27591-below-权限提升  
**类型:** 权限提升  
**风险:** 高危，可能导致root权限获取  
**投毒风险:** 0%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2025-27591](https://github.com/0x00Jeff/CVE-2025-27591)  

---

### [CVE-2021-43008](CVE-2021-43008-p0dalirius_CVE-2021-43008-AdminerRead.md) 🔴 ✅

**名称:** CVE-2021-43008-Adminer-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2021-43008-AdminerRead](https://github.com/p0dalirius/CVE-2021-43008-AdminerRead)  

---

### [CVE-2021-43008](CVE-2021-43008-DaturaSaturated_Adminer-CVE-2021-43008.md) 🔴 ✅

**名称:** CVE-2021-43008-Adminer-任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 20%  
**发现时间:** 2025-11-19  
**POC仓库:** [Adminer-CVE-2021-43008](https://github.com/DaturaSaturated/Adminer-CVE-2021-43008)  

---

### [CVE-2025-64446](CVE-2025-64446-Death112233_CVE-2025-64446-.md) 🔴 ✅

**名称:** CVE-2025-64446-FortiWeb-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致管理员命令执行  
**投毒风险:** 5%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2025-64446-](https://github.com/Death112233/CVE-2025-64446-)  

---

### [CVE-2021-42013](CVE-2021-42013-drackyjr_CVE-2021-42013.md) 🔴 ✅

**名称:** CVE-2021-42013 Apache HTTP Server Path Traversal 和远程代码执行  
**类型:** 路径遍历/远程代码执行  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2021-42013](https://github.com/drackyjr/CVE-2021-42013)  

---

### [CVE-2025-10492](CVE-2025-10492-dovezp_CVE-2025-10492-POC.md) 🔴 ✅

**名称:** CVE-2025-10492-Jaspersoft Library Deserialisation  
**类型:** Java反序列化  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 99%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2025-10492-POC](https://github.com/dovezp/CVE-2025-10492-POC)  

---

### [CVE-2021-22205](CVE-2021-22205-runsel_GitLab-CVE-2021-22205-.md)  ✅

**名称:** CVE-2021-22205-GitLab-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-11-19  
**POC仓库:** [GitLab-CVE-2021-22205-](https://github.com/runsel/GitLab-CVE-2021-22205-)  

---

### [CVE-2021-22205](CVE-2021-22205-momika233_cve-2021-22205-GitLab-13.10.2---Remote-Code-Execution-RCE-Unauthenticated-.md) 🔴 ✅

**名称:** CVE-2021-22205-GitLab-RCE  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-19  
**POC仓库:** [cve-2021-22205-GitLab-13.10.2---Remote-Code-Execution-RCE-Unauthenticated-](https://github.com/momika233/cve-2021-22205-GitLab-13.10.2---Remote-Code-Execution-RCE-Unauthenticated-)  

---

### [CVE-2022-40684](CVE-2022-40684-xtwip_fortipwn.md) 🔴 ✅

**名称:** CVE-2022-40684-Fortinet-Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 高危，可使未授权的攻击者在管理界面上执行操作  
**投毒风险:** 10%  
**发现时间:** 2025-11-19  
**POC仓库:** [fortipwn](https://github.com/xtwip/fortipwn)  

---

### [CVE-2021-22205](CVE-2021-22205-findneo_GitLab-preauth-RCE_CVE-2021-22205.md) 🔴 ✅

**名称:** CVE-2021-22205 - GitLab ExifTool 命令注入  
**类型:** 命令注入  
**风险:** 高危，未经身份验证的远程命令执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-19  
**POC仓库:** [GitLab-preauth-RCE_CVE-2021-22205](https://github.com/findneo/GitLab-preauth-RCE_CVE-2021-22205)  

---

### [CVE-2021-22205](CVE-2021-22205-shang159_CVE-2021-22205-getshell.md) 🔴 ✅

**名称:** CVE-2021-22205-GitLab-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2021-22205-getshell](https://github.com/shang159/CVE-2021-22205-getshell)  

---

### [CVE-2021-22205](CVE-2021-22205-mr-r3bot_Gitlab-CVE-2021-22205.md)  ✅

**名称:** CVE-2021-22205-GitLab-RCE  
**类型:** 远程代码执行  
**风险:** 严重，可能导致完全控制服务器  
**投毒风险:** 0%  
**发现时间:** 2025-11-19  
**POC仓库:** [Gitlab-CVE-2021-22205](https://github.com/mr-r3bot/Gitlab-CVE-2021-22205)  

---

### [CVE-2021-22205](CVE-2021-22205-ZZ-SOCMAP_CVE-2021-22205.md)  ✅

**名称:** CVE-2021-22205-GitLab-RCE  
**类型:** 远程代码执行  
**风险:** 严重，可能导致完全控制GitLab服务器  
**投毒风险:** 10%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2021-22205](https://github.com/ZZ-SOCMAP/CVE-2021-22205)  

---

### [CVE-2021-22205](CVE-2021-22205-hh-hunter_cve-2021-22205.md) 🔴 ✅

**名称:** CVE-2021-22205-GitLab-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-11-19  
**POC仓库:** [cve-2021-22205](https://github.com/hh-hunter/cve-2021-22205)  

---

### [CVE-2021-22205](CVE-2021-22205-faisalfs10x_GitLab-CVE-2021-22205-scanner.md) 🔴 ✅

**名称:** CVE-2021-22205-GitLab-RCE  
**类型:** 远程命令执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-11-19  
**POC仓库:** [GitLab-CVE-2021-22205-scanner](https://github.com/faisalfs10x/GitLab-CVE-2021-22205-scanner)  

---

### [CVE-2021-22205](CVE-2021-22205-pizza-power_Golang-CVE-2021-22205-POC.md) 🔴 ✅

**名称:** CVE-2021-22205-GitLab-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未授权用户执行任意命令  
**投毒风险:** 1%  
**发现时间:** 2025-11-19  
**POC仓库:** [Golang-CVE-2021-22205-POC](https://github.com/pizza-power/Golang-CVE-2021-22205-POC)  

---

### [CVE-2021-22205](CVE-2021-22205-c0okB_CVE-2021-22205.md) 🔴 ✅

**名称:** CVE-2021-22205-GitLab-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2021-22205](https://github.com/c0okB/CVE-2021-22205)  

---

### [CVE-2021-22205](CVE-2021-22205-keven1z_CVE-2021-22205.md)  ✅

**名称:** CVE-2021-22205-GitLab-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可导致完全系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2021-22205](https://github.com/keven1z/CVE-2021-22205)  

---

### [CVE-2021-22205](CVE-2021-22205-hhhotdrink_CVE-2021-22205.md) 🔴 ✅

**名称:** CVE-2021-22205-GitLab-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2021-22205](https://github.com/hhhotdrink/CVE-2021-22205)  

---

### [CVE-2021-22205](CVE-2021-22205-NukingDragons_gitlab-cve-2021-22205.md) 🔴 ✅

**名称:** CVE-2021-22205-GitLab-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-11-19  
**POC仓库:** [gitlab-cve-2021-22205](https://github.com/NukingDragons/gitlab-cve-2021-22205)  

---

### [CVE-2025-54110](CVE-2025-54110-canomer_CVE-2025-54110-Kernel-EoP-PoC.md) 🔴 ✅

**名称:** CVE-2025-54110 Windows Kernel Elevation of Privilege Vulnerability  
**类型:** 权限提升  
**风险:** 高危，本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2025-54110-Kernel-EoP-PoC](https://github.com/canomer/CVE-2025-54110-Kernel-EoP-PoC)  

---

### [CVE-2022-40684](CVE-2022-40684-horizon3ai_CVE-2022-40684.md)  ✅

**名称:** CVE-2022-40684-Fortinet身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 严重，未经身份验证的攻击者可以执行管理操作  
**投毒风险:** 10%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2022-40684](https://github.com/horizon3ai/CVE-2022-40684)  

---

### [CVE-2022-40684](CVE-2022-40684-carlosevieira_CVE-2022-40684.md) 🔴 ✅

**名称:** CVE-2022-40684 - Fortinet Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 高危，未经身份验证的攻击者可以对管理界面执行操作，可能导致完全控制系统  
**投毒风险:** 10%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2022-40684](https://github.com/carlosevieira/CVE-2022-40684)  

---

### [CVE-2022-40684](CVE-2022-40684-mhd108_CVE-2022-40684.md)  ✅

**名称:** CVE-2022-40684-Fortinet身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 严重，可能导致完全控制受影响系统  
**投毒风险:** 0%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2022-40684](https://github.com/mhd108/CVE-2022-40684)  

---

### [CVE-2022-40684](CVE-2022-40684-secunnix_CVE-2022-40684.md)  ✅

**名称:** CVE-2022-40684-Fortinet认证绕过  
**类型:** 认证绕过  
**风险:** 严重，未授权的远程管理权限  
**投毒风险:** 0%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2022-40684](https://github.com/secunnix/CVE-2022-40684)  

---

### [CVE-2022-40684](CVE-2022-40684-ClickCyber_cve-2022-40684.md) 🔴 ✅

**名称:** CVE-2022-40684 Fortinet Authentication Bypass  
**类型:** Authentication Bypass  
**风险:** 高危，允许未经身份验证的攻击者在管理界面上执行操作  
**投毒风险:** 0%  
**发现时间:** 2025-11-19  
**POC仓库:** [cve-2022-40684](https://github.com/ClickCyber/cve-2022-40684)  

---

### [CVE-2022-40684](CVE-2022-40684-HAWA771_CVE-2022-40684.md) 🔴 ✅

**名称:** CVE-2022-40684-Fortinet-Authentication-Bypass  
**类型:** Authentication Bypass  
**风险:** 高危，允许未授权的攻击者执行管理操作  
**投毒风险:** 1%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2022-40684](https://github.com/HAWA771/CVE-2022-40684)  

---

### [CVE-2022-40684](CVE-2022-40684-dkstar11q_CVE-2022-40684.md) 🔴 ✅

**名称:** CVE-2022-40684-FortiOS/FortiProxy/FortiSwitchManager身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权访问和控制  
**投毒风险:** 0%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2022-40684](https://github.com/dkstar11q/CVE-2022-40684)  

---

### [CVE-2022-40684](CVE-2022-40684-NeriaBasha_CVE-2022-40684.md) 🔴 ✅

**名称:** CVE-2022-40684-Fortinet身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，允许未经身份验证的攻击者在管理界面上执行操作  
**投毒风险:** 0%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2022-40684](https://github.com/NeriaBasha/CVE-2022-40684)  

---

### [CVE-2022-40684](CVE-2022-40684-puckiestyle_CVE-2022-40684.md)  ✅

**名称:** CVE-2022-40684 - FortiOS/FortiProxy/FortiSwitchManager 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 严重，未授权访问管理界面，可能导致完全系统控制  
**投毒风险:** 0%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2022-40684](https://github.com/puckiestyle/CVE-2022-40684)  

---

### [CVE-2022-40684](CVE-2022-40684-jsongmax_Fortinet-CVE-2022-40684.md)  ✅

**名称:** CVE-2022-40684 - Fortinet Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 严重，未经身份验证的攻击者可以执行管理操作  
**投毒风险:** 10%  
**发现时间:** 2025-11-19  
**POC仓库:** [Fortinet-CVE-2022-40684](https://github.com/jsongmax/Fortinet-CVE-2022-40684)  

---

### [CVE-2022-40684](CVE-2022-40684-iveresk_CVE-2022-40684.md)  ✅

**名称:** CVE-2022-40684 - Fortinet Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 严重，允许未经身份验证的攻击者执行管理操作  
**投毒风险:** 0%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2022-40684](https://github.com/iveresk/CVE-2022-40684)  

---

### [CVE-2022-40684](CVE-2022-40684-Chocapikk_CVE-2022-40684.md)  ✅

**名称:** CVE-2022-40684-Fortinet身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 严重，可能导致完全控制受影响的系统  
**投毒风险:** 0%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2022-40684](https://github.com/Chocapikk/CVE-2022-40684)  

---

### [CVE-2022-40684](CVE-2022-40684-Bendalledj_CVE-2022-40684.md) 🔴 ✅

**名称:** CVE-2022-40684-Fortinet身份验证绕过远程代码执行  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致完全控制受影响的系统  
**投毒风险:** 60%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2022-40684](https://github.com/Bendalledj/CVE-2022-40684)  

---

### [CVE-2022-40684](CVE-2022-40684-und3sc0n0c1d0_CVE-2022-40684.md) 🔴 ✅

**名称:** CVE-2022-40684 - FortiOS/FortiProxy/FortiSwitchManager 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权访问和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2022-40684](https://github.com/und3sc0n0c1d0/CVE-2022-40684)  

---

### [CVE-2022-40684](CVE-2022-40684-qingsiweisan_CVE-2022-40684.md) 🔴 ✅

**名称:** CVE-2022-40684-Fortinet身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，未经身份验证的攻击者可以执行管理操作  
**投毒风险:** 10%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2022-40684](https://github.com/qingsiweisan/CVE-2022-40684)  

---

### [CVE-2022-40684](CVE-2022-40684-TaroballzChen_CVE-2022-40684-metasploit-scanner.md) 🔴 ✅

**名称:** CVE-2022-40684-Fortinet产品认证绕过  
**类型:** 认证绕过  
**风险:** 高危，允许未授权访问管理界面并执行操作  
**投毒风险:** 10%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2022-40684-metasploit-scanner](https://github.com/TaroballzChen/CVE-2022-40684-metasploit-scanner)  

---

### [CVE-2022-40684](CVE-2022-40684-hughink_CVE-2022-40684.md) 🔴 ✅

**名称:** CVE-2022-40684 - Fortinet Authentication Bypass  
**类型:** Authentication Bypass  
**风险:** 高危，允许未授权的攻击者执行管理操作  
**投毒风险:** 5%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2022-40684](https://github.com/hughink/CVE-2022-40684)  

---

### [CVE-2022-40684](CVE-2022-40684-gustavorobertux_gotigate.md)  ✅

**名称:** CVE-2022-40684 - FortiOS/FortiProxy/FortiSwitchManager 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 严重，可能导致完全控制受影响的设备  
**投毒风险:** 1%  
**发现时间:** 2025-11-19  
**POC仓库:** [gotigate](https://github.com/gustavorobertux/gotigate)  

---

### [CVE-2022-40684](CVE-2022-40684-notareaperbutDR34P3r_CVE-2022-40684-Rust.md)  ✅

**名称:** CVE-2022-40684-Fortinet身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 严重，未经身份验证的攻击者可以执行管理操作  
**投毒风险:** 0%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2022-40684-Rust](https://github.com/notareaperbutDR34P3r/CVE-2022-40684-Rust)  

---

### [CVE-2022-40684](CVE-2022-40684-kljunowsky_CVE-2022-40684-POC.md)  ✅

**名称:** CVE-2022-40684-FortiOS/FortiProxy/FortiSwitchManager身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 严重，未经身份验证的攻击者可以对管理界面执行操作，可能导致完全控制系统  
**投毒风险:** 0%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2022-40684-POC](https://github.com/kljunowsky/CVE-2022-40684-POC)  

---

### [CVE-2022-40684](CVE-2022-40684-Filiplain_Fortinet-PoC-Auth-Bypass.md) 🔴 ✅

**名称:** CVE-2022-40684-Fortinet认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能允许未授权访问管理界面，执行任意操作  
**投毒风险:** 0%  
**发现时间:** 2025-11-19  
**POC仓库:** [Fortinet-PoC-Auth-Bypass](https://github.com/Filiplain/Fortinet-PoC-Auth-Bypass)  

---

### [CVE-2022-40684](CVE-2022-40684-Anthony1500_CVE-2022-40684.md)  ✅

**名称:** CVE-2022-40684 - Fortinet身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 严重，未经身份验证的攻击者可以在管理界面上执行操作  
**投毒风险:** 10%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2022-40684](https://github.com/Anthony1500/CVE-2022-40684)  

---

### [CVE-2022-40684](CVE-2022-40684-arsolutioner_fortigate-belsen-leak.md) 🔴 ✅

**名称:** CVE-2022-40684 Fortinet身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，允许未经身份验证的攻击者在管理界面上执行操作  
**投毒风险:** 5%  
**发现时间:** 2025-11-19  
**POC仓库:** [fortigate-belsen-leak](https://github.com/arsolutioner/fortigate-belsen-leak)  

---

### [CVE-2022-40684](CVE-2022-40684-Rofell0s_Fortigate-Leak-CVE-2022-40684.md)  ✅

**名称:** CVE-2022-40684-Fortinet-Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 严重，未经身份验证的攻击者可以执行管理操作。  
**投毒风险:** 5%  
**发现时间:** 2025-11-19  
**POC仓库:** [Fortigate-Leak-CVE-2022-40684](https://github.com/Rofell0s/Fortigate-Leak-CVE-2022-40684)  

---

### [CVE-2022-40684](CVE-2022-40684-niklasmato_fortileak-01-2025-Be.md) 🔴 ✅

**名称:** CVE-2022-40684 - Fortinet Authentication Bypass  
**类型:** Authentication Bypass  
**风险:** Critical, allows unauthenticated attacker to perform operations on the administrative interface.  
**投毒风险:** 10%  
**发现时间:** 2025-11-19  
**POC仓库:** [fortileak-01-2025-Be](https://github.com/niklasmato/fortileak-01-2025-Be)  

---

### [CVE-2022-40684](CVE-2022-40684-XalfiE_Fortigate-Belsen-Leak-Dump-CVE-2022-40684-.md) 🔴 

**名称:** CVE-2022-40684 - Fortinet Authentication Bypass  
**类型:** Authentication Bypass  
**风险:** Critical - Unauthenticated attacker can perform operations on the administrative interface  
**投毒风险:** 0%  
**发现时间:** 2025-11-19  
**POC仓库:** [Fortigate-Belsen-Leak-Dump-CVE-2022-40684-](https://github.com/XalfiE/Fortigate-Belsen-Leak-Dump-CVE-2022-40684-)  

---

### [CVE-2022-40684](CVE-2022-40684-Yami0x777_Belsen_Group-et-exploitation-de-la-CVE-2022-40684.md)  ✅

**名称:** CVE-2022-40684 - Fortinet 认证绕过  
**类型:** 认证绕过  
**风险:** 严重，未经身份验证的攻击者可以执行管理操作  
**投毒风险:** 10%  
**发现时间:** 2025-11-19  
**POC仓库:** [Belsen_Group-et-exploitation-de-la-CVE-2022-40684](https://github.com/Yami0x777/Belsen_Group-et-exploitation-de-la-CVE-2022-40684)  

---

### [CVE-2022-40684](CVE-2022-40684-ccordeiro_CVE-2022-40684.md) 🔴 ✅

**名称:** CVE-2022-40684-Fortinet-Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未经授权的访问和控制  
**投毒风险:** 5%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2022-40684](https://github.com/ccordeiro/CVE-2022-40684)  

---

### [CVE-2021-1675](CVE-2021-1675-000Tonio_cve-2021-1675.md) 🔴 ✅

**名称:** CVE-2021-1675 (PrintNightmare)  
**类型:** 远程代码执行  
**风险:** 高危，可导致系统被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-11-19  
**POC仓库:** [cve-2021-1675](https://github.com/000Tonio/cve-2021-1675)  

---

### [CVE-2021-1675](CVE-2021-1675-GlacierGossip_PrintNightmare.md) 🔴 ✅

**名称:** CVE-2021-1675 Windows Print Spooler Remote Code Execution Vulnerability (PrintNightmare)  
**类型:** 远程代码执行  
**风险:** 高危，允许远程代码执行，导致系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-11-19  
**POC仓库:** [PrintNightmare](https://github.com/GlacierGossip/PrintNightmare)  

---

### [CVE-2021-1675](CVE-2021-1675-VoiidByte_Impacket.md) 🔴 ✅

**名称:** CVE-2021-1675 - PrintNightmare  
**类型:** 远程代码执行  
**风险:** 高危，可能导致系统被完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-11-19  
**POC仓库:** [Impacket](https://github.com/VoiidByte/Impacket)  

---

### [CVE-2021-1675](CVE-2021-1675-ccordeiro_CVE-2021-1675.md) 🔴 ✅

**名称:** CVE-2021-1675 PrintNightmare Windows Print Spooler Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，可能导致系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2021-1675](https://github.com/ccordeiro/CVE-2021-1675)  

---

### [CVE-2025-58034](CVE-2025-58034-B1ack4sh_Blackash-CVE-2025-58034.md) 🔴 ✅

**名称:** CVE-2025-58034 FortiWeb OS Command Injection  
**类型:** OS Command Injection  
**风险:** 高危，允许攻击者执行任意操作系统命令，导致系统完全受损  
**投毒风险:** 10%  
**发现时间:** 2025-11-19  
**POC仓库:** [Blackash-CVE-2025-58034](https://github.com/B1ack4sh/Blackash-CVE-2025-58034)  

---

### [CVE-2021-22205](CVE-2021-22205-DIVD-NL_GitLab-cve-2021-22205-nse.md) 🔴 ✅

**名称:** CVE-2021-22205-GitLab-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致完全控制受影响的GitLab实例  
**投毒风险:** 0%  
**发现时间:** 2025-11-19  
**POC仓库:** [GitLab-cve-2021-22205-nse](https://github.com/DIVD-NL/GitLab-cve-2021-22205-nse)  

---

### [CVE-2021-22205](CVE-2021-22205-w0x68y_Gitlab-CVE-2021-22205.md) 🔴 ✅

**名称:** CVE-2021-22205 - GitLab ExifTool 远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，未经身份验证的远程命令执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-19  
**POC仓库:** [Gitlab-CVE-2021-22205](https://github.com/w0x68y/Gitlab-CVE-2021-22205)  

---

### [CVE-2021-22205](CVE-2021-22205-inspiringz_CVE-2021-22205.md) 🔴 ✅

**名称:** CVE-2021-22205-GitLab-RCE  
**类型:** 远程代码执行  
**风险:** 高危，未授权远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2021-22205](https://github.com/inspiringz/CVE-2021-22205)  

---

### [CVE-2021-22205](CVE-2021-22205-osungjinwoo_CVE-2021-22205-gitlab.md)  ✅

**名称:** CVE-2021-22205-GitLab-远程代码执行  
**类型:** 远程代码执行  
**风险:** 严重，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2021-22205-gitlab](https://github.com/osungjinwoo/CVE-2021-22205-gitlab)  

---

### [CVE-2021-22205](CVE-2021-22205-honypot_CVE-2021-22205.md) 🔴 ✅

**名称:** CVE-2021-22205-GitLab-RCE  
**类型:** 远程代码执行(RCE)  
**风险:** 高危，可导致完全控制受影响的GitLab实例  
**投毒风险:** 20%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2021-22205](https://github.com/honypot/CVE-2021-22205)  

---

### [CVE-2021-22205](CVE-2021-22205-Al1ex_CVE-2021-22205.md) 🔴 ✅

**名称:** CVE-2021-22205-GitLab-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2021-22205](https://github.com/Al1ex/CVE-2021-22205)  

---

### [CVE-2021-22205](CVE-2021-22205-overgrowncarrot1_DejaVu-CVE-2021-22205.md)  ✅

**名称:** CVE-2021-22205-GitLab-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，允许未经身份验证的攻击者执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-11-19  
**POC仓库:** [DejaVu-CVE-2021-22205](https://github.com/overgrowncarrot1/DejaVu-CVE-2021-22205)  

---

### [CVE-2021-22205](CVE-2021-22205-Hikikan_CVE-2021-22205.md) 🔴 ✅

**名称:** CVE-2021-22205-GitLab-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2021-22205](https://github.com/Hikikan/CVE-2021-22205)  

---

### [CVE-2021-22205](CVE-2021-22205-devdanqtuan_CVE-2021-22205.md) 🔴 ✅

**名称:** CVE-2021-22205-GitLab-远程命令执行  
**类型:** 远程命令执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2021-22205](https://github.com/devdanqtuan/CVE-2021-22205)  

---

### [CVE-2021-22205](CVE-2021-22205-cc3305_CVE-2021-22205.md)  ✅

**名称:** CVE-2021-22205-GitLab-RCE  
**类型:** 远程代码执行  
**风险:** 严重，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2021-22205](https://github.com/cc3305/CVE-2021-22205)  

---

### [CVE-2021-22205](CVE-2021-22205-ccordeiro_CVE-2021-22205.md) 🔴 ✅

**名称:** CVE-2021-22205-GitLab-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致完全控制服务器  
**投毒风险:** 1%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2021-22205](https://github.com/ccordeiro/CVE-2021-22205)  

---

### [CVE-2025-10230](CVE-2025-10230-B1ack4sh_Blackash-CVE-2025-10230.md)  ✅

**名称:** CVE-2025-10230 - Samba WINS Hook Command Injection  
**类型:** 命令注入  
**风险:** 严重，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-11-19  
**POC仓库:** [Blackash-CVE-2025-10230](https://github.com/B1ack4sh/Blackash-CVE-2025-10230)  

---

### [CVE-2022-40684](CVE-2022-40684-z-bool_CVE-2022-40684.md)  ✅

**名称:** CVE-2022-40684-Fortinet身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 严重，允许未经身份验证的攻击者执行管理操作  
**投毒风险:** 10%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2022-40684](https://github.com/z-bool/CVE-2022-40684)  

---

### [CVE-2025-25255](CVE-2025-25255-chjkfbvmvff_CVE-2025-25255.md) 🟡 ✅

**名称:** CVE-2025-25255 FortiOS/FortiProxy Improperly Implemented Security Check for Standard  
**类型:** 身份验证绕过 (Authentication Bypass)  
**风险:** 中危，可绕过domain fronting保护功能，可能导致权限提升  
**投毒风险:** 1%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2025-25255](https://github.com/chjkfbvmvff/CVE-2025-25255)  

---

### [CVE-2022-0543](CVE-2022-0543-z92g_CVE-2022-0543.md) 🔴 ✅

**名称:** CVE-2022-0543 Redis Lua 沙箱逃逸  
**类型:** Lua 沙箱逃逸  
**风险:** 高危，远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2022-0543](https://github.com/z92g/CVE-2022-0543)  

---

### [CVE-2022-0543](CVE-2022-0543-JacobEbben_CVE-2022-0543.md) 🔴 ✅

**名称:** CVE-2022-0543-Redis-Lua沙箱逃逸  
**类型:** Lua沙箱逃逸  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2022-0543](https://github.com/JacobEbben/CVE-2022-0543)  

---

### [CVE-2022-0543](CVE-2022-0543-SiennaSkies_redisHack.md) 🔴 ✅

**名称:** CVE-2022-0543-Redis-Lua沙箱逃逸  
**类型:** Lua沙箱逃逸  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-19  
**POC仓库:** [redisHack](https://github.com/SiennaSkies/redisHack)  

---

### [CVE-2022-0543](CVE-2022-0543-0x7eTeam_CVE-2022-0543.md) 🔴 ✅

**名称:** CVE-2022-0543 - Redis Lua Sandbox Escape  
**类型:** Lua Sandbox Escape  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2022-0543](https://github.com/0x7eTeam/CVE-2022-0543)  

---

### [CVE-2022-0543](CVE-2022-0543-netw0rk7_CVE-2022-0543-Home-Lab.md) 🔴 ✅

**名称:** CVE-2022-0543 - Redis Lua Sandbox Escape  
**类型:** Lua Sandbox Escape  
**风险:** 高危，远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2022-0543-Home-Lab](https://github.com/netw0rk7/CVE-2022-0543-Home-Lab)  

---

### [CVE-2025-34299](CVE-2025-34299-Chocapikk_CVE-2025-34299.md) 🔴 ✅

**名称:** CVE-2025-34299 - Monsta FTP Unauthenticated Arbitrary File Upload  
**类型:** 任意文件上传  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-11-19  
**POC仓库:** [CVE-2025-34299](https://github.com/Chocapikk/CVE-2025-34299)  

---

### [CVE-2025-11833](CVE-2025-11833-Kazgangap_CVE-2025-11833.md) 🔴 ✅

**名称:** CVE-2025-11833 - Post SMTP插件未授权访问漏洞  
**类型:** 未授权信息泄露/账户接管  
**风险:** 高危，可能导致敏感信息泄露和账户接管  
**投毒风险:** 5%  
**发现时间:** 2025-11-18  
**POC仓库:** [CVE-2025-11833](https://github.com/Kazgangap/CVE-2025-11833)  

---

### [CVE-2025-63406](CVE-2025-63406-WinDyAlphA_CVE-2025-63406-PoC.md) 🔴 ✅

**名称:** CVE-2025-63406-GroupOffice-命令注入  
**类型:** 命令注入  
**风险:** 高危，可远程执行任意命令  
**投毒风险:** 5%  
**发现时间:** 2025-11-18  
**POC仓库:** [CVE-2025-63406-PoC](https://github.com/WinDyAlphA/CVE-2025-63406-PoC)  

---

### [CVE-2025-64095](CVE-2025-64095-0xr2r_CVE-2025-64095.md) 🔴 ✅

**名称:** CVE-2025-64095 - DNN Insufficient Access Control - Image Upload allows for Site Content Overwrite  
**类型:** 文件上传  
**风险:** 高危，允许未授权的文件上传和覆盖，可能导致网站内容篡改和XSS攻击  
**投毒风险:** 5%  
**发现时间:** 2025-11-18  
**POC仓库:** [CVE-2025-64095](https://github.com/0xr2r/CVE-2025-64095)  

---

### [CVE-2023-20564](CVE-2023-20564-NtGabrielGomes_CVE-2023-20564.md) 🔴 ✅

**名称:** CVE-2023-20564 - AMD Ryzen Master 驱动物理内存访问漏洞  
**类型:** 物理内存读写  
**风险:** 高危，可导致权限提升和系统崩溃  
**投毒风险:** 5%  
**发现时间:** 2025-11-18  
**POC仓库:** [CVE-2023-20564](https://github.com/NtGabrielGomes/CVE-2023-20564)  

---

### [CVE-2025-24893](CVE-2025-24893-B1ack4sh_Blackash-CVE-2025-24893.md) 🔴 ✅

**名称:** CVE-2025-24893-XWiki-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-11-18  
**POC仓库:** [Blackash-CVE-2025-24893](https://github.com/B1ack4sh/Blackash-CVE-2025-24893)  

---

### [CVE-2023-25136](CVE-2023-25136-ticofookfook_CVE-2023-25136.md) 🔴 ✅

**名称:** CVE-2023-25136 OpenSSH 双重释放漏洞  
**类型:** 双重释放  
**风险:** 高危，理论上可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-18  
**POC仓库:** [CVE-2023-25136](https://github.com/ticofookfook/CVE-2023-25136)  

---

### [CVE-2023-25136](CVE-2023-25136-adhikara13_CVE-2023-25136.md) 🔴 ✅

**名称:** CVE-2023-25136-OpenSSH-Double-Free  
**类型:** Double-Free  
**风险:** 高危，理论上可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-18  
**POC仓库:** [CVE-2023-25136](https://github.com/adhikara13/CVE-2023-25136)  

---

### [CVE-2025-62215](CVE-2025-62215-abrewer251_CVE-2025-62215_Windows_Kernel_PE.md) 🔴 ✅

**名称:** CVE-2025-62215 Windows Kernel 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，允许本地低权限用户提升至SYSTEM权限  
**投毒风险:** 10%  
**发现时间:** 2025-11-18  
**POC仓库:** [CVE-2025-62215_Windows_Kernel_PE](https://github.com/abrewer251/CVE-2025-62215_Windows_Kernel_PE)  

---

### [CVE-2019-9193](CVE-2019-9193-jhnhnck_CVE-2019-9193.md) 🔴 ✅

**名称:** CVE-2019-9193 - PostgreSQL 9.3-11.2 任意命令执行  
**类型:** 任意命令执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-11-18  
**POC仓库:** [CVE-2019-9193](https://github.com/jhnhnck/CVE-2019-9193)  

---

### [CVE-2019-9193](CVE-2019-9193-netw0rk7_CVE-2019-9193-Home-Lab.md) 🔴 ✅

**名称:** CVE-2019-9193 - PostgreSQL COPY FROM PROGRAM RCE  
**类型:** 远程命令执行  
**风险:** 高危，允许数据库用户执行操作系统命令  
**投毒风险:** 0%  
**发现时间:** 2025-11-18  
**POC仓库:** [CVE-2019-9193-Home-Lab](https://github.com/netw0rk7/CVE-2019-9193-Home-Lab)  

---

### [CVE-2023-25136](CVE-2023-25136-jfrog_jfrog-CVE-2023-25136-OpenSSH_Double-Free.md) 🔴 ✅

**名称:** CVE-2023-25136-OpenSSH-Double-Free  
**类型:** Double-Free  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-18  
**POC仓库:** [jfrog-CVE-2023-25136-OpenSSH_Double-Free](https://github.com/jfrog/jfrog-CVE-2023-25136-OpenSSH_Double-Free)  

---

### [CVE-2023-25136](CVE-2023-25136-Christbowel_CVE-2023-25136.md) 🔴 ✅

**名称:** CVE-2023-25136-OpenSSH-Double-Free  
**类型:** Double-Free  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-18  
**POC仓库:** [CVE-2023-25136](https://github.com/Christbowel/CVE-2023-25136)  

---

### [CVE-2023-25136](CVE-2023-25136-nhakobyan685_CVE-2023-25136.md) 🔴 ✅

**名称:** CVE-2023-25136-OpenSSH-Double-Free  
**类型:** Double-Free  
**风险:** 高危，理论上可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-18  
**POC仓库:** [CVE-2023-25136](https://github.com/nhakobyan685/CVE-2023-25136)  

---

### [CVE-2023-25136](CVE-2023-25136-H4K6_CVE-2023-25136.md) 🔴 ✅

**名称:** CVE-2023-25136-OpenSSH-Double-Free  
**类型:** Double-Free  
**风险:** 高危，理论上可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-11-18  
**POC仓库:** [CVE-2023-25136](https://github.com/H4K6/CVE-2023-25136)  

---

### [CVE-2023-25136](CVE-2023-25136-axylisdead_CVE-2023-25136_POC.md) 🔴 ✅

**名称:** CVE-2023-25136 OpenSSH 双重释放漏洞  
**类型:** 双重释放漏洞  
**风险:** 高危，理论上可远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-18  
**POC仓库:** [CVE-2023-25136_POC](https://github.com/axylisdead/CVE-2023-25136_POC)  

---

### [CVE-2023-25136](CVE-2023-25136-Business1sg00d_CVE-2023-25136.md) 🔴 ✅

**名称:** CVE-2023-25136-OpenSSH-double-free  
**类型:** Double-Free  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-18  
**POC仓库:** [CVE-2023-25136](https://github.com/Business1sg00d/CVE-2023-25136)  

---

### [CVE-2023-25136](CVE-2023-25136-malvika-thakur_CVE-2023-25136.md) 🔴 ✅

**名称:** CVE-2023-25136 - OpenSSH Pre-Auth Double Free  
**类型:** 双重释放漏洞  
**风险:** 高危，理论上可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-18  
**POC仓库:** [CVE-2023-25136](https://github.com/malvika-thakur/CVE-2023-25136)  

---

### [CVE-2023-25136](CVE-2023-25136-mrmtwoj_CVE-2023-25136.md) 🔴 ✅

**名称:** CVE-2023-25136-OpenSSH-Double-Free  
**类型:** Double-Free  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-18  
**POC仓库:** [CVE-2023-25136](https://github.com/mrmtwoj/CVE-2023-25136)  

---

### [CVE-2023-25136](CVE-2023-25136-Lane0218_CVE-2023-25136-PoC.md) 🔴 ✅

**名称:** CVE-2023-25136 OpenSSH Pre-Auth Double Free  
**类型:** Double Free 内存破坏  
**风险:** 高危，拒绝服务 (DoS)，理论上可能远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-11-18  
**POC仓库:** [CVE-2023-25136-PoC](https://github.com/Lane0218/CVE-2023-25136-PoC)  

---

### [CVE-2025-64446](CVE-2025-64446-lincemorado97_CVE-2025-64446.md) 🔴 ✅

**名称:** CVE-2025-64446 - FortiWeb Authentication Bypass  
**类型:** 相对路径遍历导致认证绕过  
**风险:** 高危，可能导致完全系统入侵  
**投毒风险:** 10%  
**发现时间:** 2025-11-18  
**POC仓库:** [CVE-2025-64446](https://github.com/lincemorado97/CVE-2025-64446)  

---

### [CVE-2025-64459](CVE-2025-64459-B1ack4sh_Blackash-CVE-2025-64459.md) 🔴 ✅

**名称:** CVE-2025-64459 Django SQL 注入  
**类型:** SQL 注入  
**风险:** 高危，可能导致数据泄露和数据篡改  
**投毒风险:** 0%  
**发现时间:** 2025-11-18  
**POC仓库:** [Blackash-CVE-2025-64459](https://github.com/B1ack4sh/Blackash-CVE-2025-64459)  

---

### [CVE-2021-44228](CVE-2021-44228-mgueye3_Log4Shell.md) 🔴 ✅

**名称:** CVE-2021-44228-Apache Log4j2-JNDI 注入  
**类型:** JNDI 注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-18  
**POC仓库:** [Log4Shell](https://github.com/mgueye3/Log4Shell)  

---

### [CVE-2021-44228](CVE-2021-44228-PCMKUIT_CVE-2021-44228---Log4Shell-Analysis.md) 🔴 ✅

**名称:** CVE-2021-44228 - Log4Shell  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-11-18  
**POC仓库:** [CVE-2021-44228---Log4Shell-Analysis](https://github.com/PCMKUIT/CVE-2021-44228---Log4Shell-Analysis)  

---

### [CVE-2025-62215](CVE-2025-62215-mrk336_Kernel-Chaos-Weaponizing-CVE-2025-62215-for-SYSTEM-Privilege-Escalation.md) 🔴 ✅

**名称:** CVE-2025-62215 Windows Kernel Elevation of Privilege Vulnerability  
**类型:** 权限提升  
**风险:** 高危，允许本地授权的攻击者提升权限至SYSTEM  
**投毒风险:** 10%  
**发现时间:** 2025-11-18  
**POC仓库:** [Kernel-Chaos-Weaponizing-CVE-2025-62215-for-SYSTEM-Privilege-Escalation](https://github.com/mrk336/Kernel-Chaos-Weaponizing-CVE-2025-62215-for-SYSTEM-Privilege-Escalation)  

---

### [CVE-2025-63700](CVE-2025-63700-itsnishat08_CVE-2025-63700.md) 🔴 ✅

**名称:** CVE-2025-63700 - Clerk-js OAuth Authentication Bypass  
**类型:** OAuth Authentication Bypass  
**风险:** 高危，可能导致未经授权的账户访问  
**投毒风险:** 10%  
**发现时间:** 2025-11-18  
**POC仓库:** [CVE-2025-63700](https://github.com/itsnishat08/CVE-2025-63700)  

---

### [CVE-2025-63848](CVE-2025-63848-coderMohammed1_CVE-2025-63848.md) 🔴 ✅

**名称:** CVE-2025-63848-SWISH prolog-存储型XSS  
**类型:** 存储型跨站脚本 (XSS)  
**风险:** 高危，可导致账户接管  
**投毒风险:** 10%  
**发现时间:** 2025-11-18  
**POC仓库:** [CVE-2025-63848](https://github.com/coderMohammed1/CVE-2025-63848)  

---

### [CVE-2023-2745](CVE-2023-2745-spyizxa0day_WordPress-CVE-2023-2745.md) 🟡 ✅

**名称:** CVE-2023-2745-WordPress Core-目录遍历  
**类型:** 目录遍历  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-11-17  
**POC仓库:** [WordPress-CVE-2023-2745](https://github.com/spyizxa0day/WordPress-CVE-2023-2745)  

---

### [CVE-2025-64446](CVE-2025-64446-verylazytech_CVE-2025-64446.md) 🔴 ✅

**名称:** CVE-2025-64446 - FortiWeb RCE via Path Traversal + Auth Bypass  
**类型:** 路径遍历 + 身份验证绕过导致RCE  
**风险:** 高危，未经身份验证的远程命令执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-17  
**POC仓库:** [CVE-2025-64446](https://github.com/verylazytech/CVE-2025-64446)  

---

### [CVE-2022-31199](CVE-2022-31199-developerfred_CVE-2022-31199.md) 🔴 ✅

**名称:** CVE-2022-31199-Netwrix Auditor-远程代码执行  
**类型:** 反序列化漏洞  
**风险:** 高危，未经身份验证的远程攻击者可以以 NT AUTHORITY\SYSTEM 权限执行任意代码，完全控制系统。  
**投毒风险:** 5%  
**发现时间:** 2025-11-17  
**POC仓库:** [CVE-2022-31199](https://github.com/developerfred/CVE-2022-31199)  

---

### [CVE-2019-13272](CVE-2019-13272-Chinmay1743_ptrace-vuln.md) 🔴 ✅

**名称:** CVE-2019-13272-Linux内核-ptrace权限提升  
**类型:** 权限提升  
**风险:** 高危，本地用户可获取root权限  
**投毒风险:** 0%  
**发现时间:** 2025-11-17  
**POC仓库:** [ptrace-vuln](https://github.com/Chinmay1743/ptrace-vuln)  

---

### [CVE-2019-13272](CVE-2019-13272-letsr00t_CVE-2019-13272.md) 🔴 ✅

**名称:** CVE-2019-13272 - Linux Kernel PTRACE_TRACEME Local Root  
**类型:** 权限提升  
**风险:** 高危，本地用户可获取root权限  
**投毒风险:** 1%  
**发现时间:** 2025-11-17  
**POC仓库:** [CVE-2019-13272](https://github.com/letsr00t/CVE-2019-13272)  

---

### [CVE-2025-60715](CVE-2025-60715-velmetrac_CVE-2025-60715.md) 🔴 ✅

**名称:** CVE-2025-60715 Windows RRAS 堆缓冲区溢出远程代码执行漏洞  
**类型:** 堆缓冲区溢出  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 20%  
**发现时间:** 2025-11-17  
**POC仓库:** [CVE-2025-60715](https://github.com/velmetrac/CVE-2025-60715)  

---

### [CVE-2017-12615](CVE-2017-12615-netw0rk7_CVE-2017-12615-Home-Lab.md) 🔴 ✅

**名称:** CVE-2017-12615-Apache Tomcat-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-11-17  
**POC仓库:** [CVE-2017-12615-Home-Lab](https://github.com/netw0rk7/CVE-2017-12615-Home-Lab)  

---

### [CVE-2025-64446](CVE-2025-64446-D3crypT0r_CVE-2025-64446.md) 🔴 ✅

**名称:** CVE-2025-64446-FortiWeb-路径遍历导致管理员命令执行  
**类型:** 路径遍历  
**风险:** 高危，可能导致完全系统控制  
**投毒风险:** 0%  
**发现时间:** 2025-11-17  
**POC仓库:** [CVE-2025-64446](https://github.com/D3crypT0r/CVE-2025-64446)  

---

### [CVE-2023-33177](CVE-2023-33177-complexusprada_Xibo-CMS-Zip-Slip-RCE-Exploit-CVE-2023-33177.md) 🔴 ✅

**名称:** CVE-2023-33177-Xibo CMS-Zip Slip RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经授权的用户在服务器上执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-11-17  
**POC仓库:** [Xibo-CMS-Zip-Slip-RCE-Exploit-CVE-2023-33177](https://github.com/complexusprada/Xibo-CMS-Zip-Slip-RCE-Exploit-CVE-2023-33177)  

---

### [CVE-2024-26169](CVE-2024-26169-kautilyagupt_CVE-2024-26169-Detail-1.md) 🔴 ✅

**名称:** CVE-2024-26169 & CVE-2017-11882 Windows Error Reporting Service Elevation of Privilege Vulnerability & Microsoft Office Memory Corruption Vulnerability  
**类型:** 特权提升 & 内存破坏  
**风险:** 高危，可导致完全系统控制  
**投毒风险:** 0%  
**发现时间:** 2025-11-17  
**POC仓库:** [CVE-2024-26169-Detail-1](https://github.com/kautilyagupt/CVE-2024-26169-Detail-1)  

---

### [CVE-2025-64446](CVE-2025-64446-sensepost_CVE-2025-64446.md) 🔴 ✅

**名称:** CVE-2025-64446-FortiWeb-路径遍历-权限提升  
**类型:** 路径遍历  
**风险:** 高危，允许未经身份验证的远程攻击者执行管理命令。  
**投毒风险:** 0%  
**发现时间:** 2025-11-17  
**POC仓库:** [CVE-2025-64446](https://github.com/sensepost/CVE-2025-64446)  

---

### [CVE-2025-64027](CVE-2025-64027-cybercrewinc_CVE-2025-64027.md)  

**名称:** Unknown Vulnerability  
**类型:** 代码审计/许可证分析  
**风险:** 低危，信息泄露或版权合规问题  
**投毒风险:** 0%  
**发现时间:** 2025-11-17  
**POC仓库:** [CVE-2025-64027](https://github.com/cybercrewinc/CVE-2025-64027)  

---

### [CVE-2025-54574](CVE-2025-54574-starrynightsecurity_CVE-2025-54574-Squid-Heap-Buffer-Overflow.md) 🔴 ✅

**名称:** CVE-2025-54574-Squid-Heap-Buffer-Overflow  
**类型:** 堆缓冲区溢出  
**风险:** 高危，可能导致内存损坏、信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-17  
**POC仓库:** [CVE-2025-54574-Squid-Heap-Buffer-Overflow](https://github.com/starrynightsecurity/CVE-2025-54574-Squid-Heap-Buffer-Overflow)  

---

### [CVE-2015-3306](CVE-2015-3306-netw0rk7_CVE-2015-3306-Home-Lab.md) 🔴 ✅

**名称:** CVE-2015-3306 - ProFTPD mod_copy 远程文件复制到RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-11-17  
**POC仓库:** [CVE-2015-3306-Home-Lab](https://github.com/netw0rk7/CVE-2015-3306-Home-Lab)  

---

### [CVE-2025-12762](CVE-2025-12762-B1ack4sh_Blackash-CVE-2025-12762.md)  ✅

**名称:** CVE-2025-12762 - pgAdmin 4 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可导致服务器被完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-11-17  
**POC仓库:** [Blackash-CVE-2025-12762](https://github.com/B1ack4sh/Blackash-CVE-2025-12762)  

---

### [CVE-2025-36250](CVE-2025-36250-B1ack4sh_Blackash-CVE-2025-36250.md)  

**名称:** CVE-2025-36250-AIX NIM nimesis RCE  
**类型:** 远程代码执行  
**风险:** 严重，允许未经身份验证的远程攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-11-17  
**POC仓库:** [Blackash-CVE-2025-36250](https://github.com/B1ack4sh/Blackash-CVE-2025-36250)  

---

### [CVE-2022-21587](CVE-2022-21587-merlyn-1_CVE-2022-21587-Oracle-EBS.md) 🔴 ✅

**名称:** CVE-2022-21587-Oracle Web Applications Desktop Integrator-未授权任意文件上传  
**类型:** 未授权任意文件上传  
**风险:** 高危，可能导致远程代码执行，完全控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-11-17  
**POC仓库:** [CVE-2022-21587-Oracle-EBS](https://github.com/merlyn-1/CVE-2022-21587-Oracle-EBS)  

---

### [CVE-2025-49113](CVE-2025-49113-ankitpandey383_roundcube-cve-2025-49113-lab.md) 🔴 ✅

**名称:** CVE-2025-49113 - Roundcube Webmail PHP Object Deserialization RCE  
**类型:** PHP Object Deserialization  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-11-17  
**POC仓库:** [roundcube-cve-2025-49113-lab](https://github.com/ankitpandey383/roundcube-cve-2025-49113-lab)  

---

### [CVE-2011-2523](CVE-2011-2523-seerat-fatima21_vsftpd-exploit.md) 🔴 ✅

**名称:** CVE-2011-2523 - vsftpd 2.3.4 Backdoor Command Execution  
**类型:** 后门漏洞  
**风险:** 高危，可导致远程代码执行和完全系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-11-16  
**POC仓库:** [vsftpd-exploit](https://github.com/seerat-fatima21/vsftpd-exploit)  

---

### [CVE-2011-2523](CVE-2011-2523-avivyap_CVE-2011-2523.md) 🔴 ✅

**名称:** CVE-2011-2523 - vsftpd 2.3.4 Backdoor Command Execution  
**类型:** 后门  
**风险:** 高危，远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-16  
**POC仓库:** [CVE-2011-2523](https://github.com/avivyap/CVE-2011-2523)  

---

### [CVE-2019-9053](CVE-2019-9053-JagdeepSinghCeh_cms-made-simple-python3.md) 🔴 ✅

**名称:** CVE-2019-9053-CMS Made Simple-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据库信息泄露和管理员账户破解  
**投毒风险:** 5%  
**发现时间:** 2025-11-16  
**POC仓库:** [cms-made-simple-python3](https://github.com/JagdeepSinghCeh/cms-made-simple-python3)  

---

### [CVE-2019-9053](CVE-2019-9053-Perseus99999_CVE-2019-9053-working-.md) 🔴 ✅

**名称:** CVE-2019-9053-CMS Made Simple-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-11-16  
**POC仓库:** [CVE-2019-9053-working-](https://github.com/Perseus99999/CVE-2019-9053-working-)  

---

### [CVE-2025-62220](CVE-2025-62220-callinston_CVE-2025-62220.md) 🔴 ✅

**名称:** CVE-2025-62220-Windows Subsystem for Linux GUI 堆缓冲区溢出远程代码执行漏洞  
**类型:** 堆缓冲区溢出  
**风险:** 高危，允许未经授权的攻击者通过网络执行代码  
**投毒风险:** 80%  
**发现时间:** 2025-11-16  
**POC仓库:** [CVE-2025-62220](https://github.com/callinston/CVE-2025-62220)  

---

### [CVE-2025-62950](CVE-2025-62950-lorenzocamilli_CVE-2025-62950-PoC.md) 🟡 ✅

**名称:** CVE-2025-62950 - WordPress Contest Gallery Plugin CSRF  
**类型:** 跨站请求伪造 (CSRF)  
**风险:** 中危，可能导致未经授权的内容删除  
**投毒风险:** 0%  
**发现时间:** 2025-11-16  
**POC仓库:** [CVE-2025-62950-PoC](https://github.com/lorenzocamilli/CVE-2025-62950-PoC)  

---

### [CVE-2025-48593](CVE-2025-48593-zhuowei_blueshrimp.md) 🟡 

**名称:** CVE-2025-48593  
**类型:** 蓝牙服务拒绝服务/潜在内存破坏  
**风险:** 中危，仅影响特定设备，导致服务崩溃或潜在的内存破坏  
**投毒风险:** 10%  
**发现时间:** 2025-11-16  
**POC仓库:** [blueshrimp](https://github.com/zhuowei/blueshrimp)  

---

### [CVE-2025-48593](CVE-2025-48593-rana3333s_CVE-2025-48593.md)  

**名称:** CVE-2025-48593: Android系统零点击远程代码执行  
**类型:** 远程代码执行  
**风险:** 严重，可能导致设备完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-11-16  
**POC仓库:** [CVE-2025-48593](https://github.com/rana3333s/CVE-2025-48593)  

---

### [CVE-2025-64484](CVE-2025-64484-B1ack4sh_Blackash-CVE-2025-64484.md) 🔴 ✅

**名称:** CVE-2025-64484-oauth2-proxy-header-smuggling  
**类型:** HTTP Header Smuggling  
**风险:** 高危，可能导致权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-11-16  
**POC仓库:** [Blackash-CVE-2025-64484](https://github.com/B1ack4sh/Blackash-CVE-2025-64484)  

---

### [CVE-2024-0670](CVE-2024-0670-elsevar11_CVE-2024-0670---CheckMK-Agent-Local-Privilege-Escalation-Exploit.md) 🔴 ✅

**名称:** CVE-2024-0670 - Checkmk Agent 本地提权  
**类型:** 本地权限提升  
**风险:** 高危，本地用户可获取 SYSTEM 权限  
**投毒风险:** 10%  
**发现时间:** 2025-11-16  
**POC仓库:** [CVE-2024-0670---CheckMK-Agent-Local-Privilege-Escalation-Exploit](https://github.com/elsevar11/CVE-2024-0670---CheckMK-Agent-Local-Privilege-Escalation-Exploit)  

---

### [CVE-2024-0670](CVE-2024-0670-magicrc_CVE-2024-0670.md) 🔴 ✅

**名称:** CVE-2024-0670-Checkmk-Windows Agent权限提升  
**类型:** 权限提升  
**风险:** 高危，本地权限提升至SYSTEM  
**投毒风险:** 0%  
**发现时间:** 2025-11-16  
**POC仓库:** [CVE-2024-0670](https://github.com/magicrc/CVE-2024-0670)  

---

### [CVE-2023-2598](CVE-2023-2598-guard-wait_CVE-2023-2598_EXP.md) 🔴 ✅

**名称:** CVE-2023-2598-Linux Kernel-io_uring 权限提升  
**类型:** 权限提升  
**风险:** 高危，可导致本地权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-11-16  
**POC仓库:** [CVE-2023-2598_EXP](https://github.com/guard-wait/CVE-2023-2598_EXP)  

---

### [CVE-2025-5777](CVE-2025-5777-mr-r3b00t_CVE-2025-5777.md) 🔴 ✅

**名称:** CVE-2025-5777 NetScaler ADC/Gateway 内存越界读取  
**类型:** 内存越界读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-11-16  
**POC仓库:** [CVE-2025-5777](https://github.com/mr-r3b00t/CVE-2025-5777)  

---

### [CVE-2025-59287](CVE-2025-59287-M507_CVE-2025-59287-PoC.md) 🔴 ✅

**名称:** CVE-2025-59287 - Windows Server Update Service (WSUS) 远程代码执行漏洞  
**类型:** 反序列化漏洞导致远程代码执行  
**风险:** 高危，未经授权的攻击者可以在网络上执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-11-16  
**POC仓库:** [CVE-2025-59287-PoC](https://github.com/M507/CVE-2025-59287-PoC)  

---

### [CVE-2025-13188](CVE-2025-13188-degeneration1973_CVE-2025-13188-Exploit.md) 🔴 ✅

**名称:** CVE-2025-13188-D-Link DIR-816L 栈溢出  
**类型:** 栈溢出  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-11-16  
**POC仓库:** [CVE-2025-13188-Exploit](https://github.com/degeneration1973/CVE-2025-13188-Exploit)  

---

### [CVE-2025-54321](CVE-2025-54321-saykino_CVE-2025-54321.md) 🔴 ✅

**名称:** CVE-2025-54321-SigningHub-Email轰炸  
**类型:** 邮件轰炸  
**风险:** 高危，可能导致服务中断  
**投毒风险:** 0%  
**发现时间:** 2025-11-16  
**POC仓库:** [CVE-2025-54321](https://github.com/saykino/CVE-2025-54321)  

---

### [CVE-2025-40019](CVE-2025-40019-guard-wait_CVE-2025-40019_POC.md) 🟡 

**名称:** CVE-2025-40019  
**类型:** 缓冲区溢出/整数溢出  
**风险:** 中危，可能导致拒绝服务或信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-11-16  
**POC仓库:** [CVE-2025-40019_POC](https://github.com/guard-wait/CVE-2025-40019_POC)  

---

### [CVE-2025-54320](CVE-2025-54320-saykino_CVE-2025-54320.md)  ✅

**名称:** CVE-2025-54320  
**类型:** 未明确（根据现有信息无法判断）  
**风险:** 未明确（根据现有信息无法判断）  
**投毒风险:** 5%  
**发现时间:** 2025-11-16  
**POC仓库:** [CVE-2025-54320](https://github.com/saykino/CVE-2025-54320)  

---

### [CVE-2025-60854](CVE-2025-60854-K0n9-log_CVE-2025-60854.md)  ✅

**名称:** CVE-2025-60854 - D-link AX1500 漏洞  
**类型:** 未知  
**风险:** 待评估  
**投毒风险:** 1%  
**发现时间:** 2025-11-16  
**POC仓库:** [CVE-2025-60854](https://github.com/K0n9-log/CVE-2025-60854)  

---

### [CVE-2025-48060](CVE-2025-48060-leorivass_jq-els-backport-cve-2025-48060.md) 🔴 ✅

**名称:** CVE-2025-48060 - jq - Stack-based Buffer Overflow  
**类型:** 栈缓冲区溢出  
**风险:** 高危，可能导致拒绝服务或代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-16  
**POC仓库:** [jq-els-backport-cve-2025-48060](https://github.com/leorivass/jq-els-backport-cve-2025-48060)  

---

### [CVE-2025-32463](CVE-2025-32463-ankitpandey383_CVE-2025-32463-Sudo-Privilege-Escalation.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，本地用户可提升至root权限  
**投毒风险:** 5%  
**发现时间:** 2025-11-16  
**POC仓库:** [CVE-2025-32463-Sudo-Privilege-Escalation](https://github.com/ankitpandey383/CVE-2025-32463-Sudo-Privilege-Escalation)  

---

### [CVE-2023-46604](CVE-2023-46604-vaishnavucv_Project-Vuln-Detection-N-Mitigation_101.md) 🔴 ✅

**名称:** CVE-2023-46604 - Apache ActiveMQ OpenWire 反序列化RCE  
**类型:** 反序列化RCE  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-15  
**POC仓库:** [Project-Vuln-Detection-N-Mitigation_101](https://github.com/vaishnavucv/Project-Vuln-Detection-N-Mitigation_101)  

---

### [CVE-2023-46604](CVE-2023-46604-pavanaa4k_CVE-2023-46604-LAB.md) 🔴 

**名称:** CVE-2023-46604 - Apache ActiveMQ RCE (OpenWire Protocol)  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-15  
**POC仓库:** [CVE-2023-46604-LAB](https://github.com/pavanaa4k/CVE-2023-46604-LAB)  

---

### [CVE-2025-64446](CVE-2025-64446-soltanali0_CVE-2025-64446-Exploit.md) 🔴 ✅

**名称:** CVE-2025-64446-FortiWeb-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可导致权限提升和命令执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-15  
**POC仓库:** [CVE-2025-64446-Exploit](https://github.com/soltanali0/CVE-2025-64446-Exploit)  

---

### [CVE-2025-34227](CVE-2025-34227-mcorybillington_CVE-2025-34227_Nagios-XI-Command-Injection-Configuration-Wizard.md) 🔴 ✅

**名称:** CVE-2025-34227-Nagios XI-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-15  
**POC仓库:** [CVE-2025-34227_Nagios-XI-Command-Injection-Configuration-Wizard](https://github.com/mcorybillington/CVE-2025-34227_Nagios-XI-Command-Injection-Configuration-Wizard)  

---

### [CVE-2025-62507](CVE-2025-62507-Network-Sec_CVE-2025-62507-Buffer-Overflow_PoC.md) 🔴 ✅

**名称:** CVE-2025-62507-Redis-栈溢出  
**类型:** 栈溢出  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-11-15  
**POC仓库:** [CVE-2025-62507-Buffer-Overflow_PoC](https://github.com/Network-Sec/CVE-2025-62507-Buffer-Overflow_PoC)  

---

### [CVE-2025-7771](CVE-2025-7771-AmrHuss_throttlestop-exploit-rw.md) 🔴 ✅

**名称:** CVE-2025-7771-ThrottleStop.sys-权限提升  
**类型:** 权限提升  
**风险:** 高危，允许本地用户以内核权限执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-11-15  
**POC仓库:** [throttlestop-exploit-rw](https://github.com/AmrHuss/throttlestop-exploit-rw)  

---

### [CVE-2025-64328](CVE-2025-64328-mcorybillington_CVE-2025-64328_FreePBX-framework-Command-Injection.md) 🔴 ✅

**名称:** CVE-2025-64328-FreePBX-Authenticated Command Injection  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-15  
**POC仓库:** [CVE-2025-64328_FreePBX-framework-Command-Injection](https://github.com/mcorybillington/CVE-2025-64328_FreePBX-framework-Command-Injection)  

---

### [CVE-2025-12101](CVE-2025-12101-boneys_CVE-2025-12101-Scanner-PoC.md) 🟡 ✅

**名称:** CVE-2025-12101-NetScaler-XSS  
**类型:** XSS  
**风险:** 中危，可能导致会话劫持、信息泄露等  
**投毒风险:** 0%  
**发现时间:** 2025-11-15  
**POC仓库:** [CVE-2025-12101-Scanner-PoC](https://github.com/boneys/CVE-2025-12101-Scanner-PoC)  

---

### [CVE-2025-12101](CVE-2025-12101-boneys_CVE-2025-12101-Scanner.md) 🟡 ✅

**名称:** CVE-2025-12101-NetScaler-XSS  
**类型:** 跨站脚本攻击 (XSS)  
**风险:** 中危，可能导致会话劫持、敏感信息泄露和恶意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-15  
**POC仓库:** [CVE-2025-12101-Scanner](https://github.com/boneys/CVE-2025-12101-Scanner)  

---

### [CVE-2024-0670](CVE-2024-0670-zhulin837_checkmk_cve-2024-0670.md) 🔴 ✅

**名称:** CVE-2024-0670-Checkmk-权限提升  
**类型:** 权限提升  
**风险:** 高危，本地用户可提升权限  
**投毒风险:** 10%  
**发现时间:** 2025-11-15  
**POC仓库:** [checkmk_cve-2024-0670](https://github.com/zhulin837/checkmk_cve-2024-0670)  

---

### [CVE-2025-4664](CVE-2025-4664-mingijunggrape_CVE-2025-4664.md) 🟡 ✅

**名称:** CVE-2025-4664  
**类型:** 跨域数据泄露  
**风险:** 中危，可能导致跨域数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-11-15  
**POC仓库:** [CVE-2025-4664](https://github.com/mingijunggrape/CVE-2025-4664)  

---

### [CVE-2025-33073](CVE-2025-33073-B1ack4sh_Blackash-CVE-2025-33073.md) 🔴 ✅

**名称:** CVE-2025-33073 - Windows SMB Client Elevation of Privilege  
**类型:** 权限提升  
**风险:** 高危，允许未经授权的攻击者提升网络上的权限  
**投毒风险:** 0%  
**发现时间:** 2025-11-15  
**POC仓库:** [Blackash-CVE-2025-33073](https://github.com/B1ack4sh/Blackash-CVE-2025-33073)  

---

### [CVE-2025-64446](CVE-2025-64446-B1ack4sh_Blackash-CVE-2025-64446.md) 🔴 ✅

**名称:** CVE-2025-64446-FortiWeb-路径遍历-RCE  
**类型:** 路径遍历  
**风险:** 高危，可导致远程代码执行和完全控制设备  
**投毒风险:** 10%  
**发现时间:** 2025-11-15  
**POC仓库:** [Blackash-CVE-2025-64446](https://github.com/B1ack4sh/Blackash-CVE-2025-64446)  

---

### [CVE-2025-64446](CVE-2025-64446-fevar54_CVE-2025-64446-PoC---FortiWeb-Path-Traversal.md) 🔴 ✅

**名称:** CVE-2025-64446-FortiWeb-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可执行管理命令  
**投毒风险:** 0%  
**发现时间:** 2025-11-14  
**POC仓库:** [CVE-2025-64446-PoC---FortiWeb-Path-Traversal](https://github.com/fevar54/CVE-2025-64446-PoC---FortiWeb-Path-Traversal)  

---

### [CVE-2025-64446](CVE-2025-64446-sxyrxyy_CVE-2025-64446-FortiWeb-CGI-Bypass-PoC.md) 🔴 ✅

**名称:** CVE-2025-64446-FortiWeb-路径遍历导致管理员命令执行  
**类型:** 路径遍历  
**风险:** 高危，可能导致管理员权限获取和命令执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-14  
**POC仓库:** [CVE-2025-64446-FortiWeb-CGI-Bypass-PoC](https://github.com/sxyrxyy/CVE-2025-64446-FortiWeb-CGI-Bypass-PoC)  

---

### [CVE-2023-35317](CVE-2023-35317-M507_CVE-2023-35317-PoC.md) 🔴 ✅

**名称:** CVE-2023-35317 - Windows Server Update Service (WSUS) 提权漏洞  
**类型:** 特权提升/反序列化漏洞  
**风险:** 高危，可能导致远程代码执行和系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-11-14  
**POC仓库:** [CVE-2023-35317-PoC](https://github.com/M507/CVE-2023-35317-PoC)  

---

### [CVE-2025-60724](CVE-2025-60724-callinston_CVE-2025-60724.md) 🔴 ✅

**名称:** CVE-2025-60724-GDI+ Remote Code Execution  
**类型:** Heap-based Buffer Overflow  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 60%  
**发现时间:** 2025-11-14  
**POC仓库:** [CVE-2025-60724](https://github.com/callinston/CVE-2025-60724)  

---

### [CVE-2025-63943](CVE-2025-63943-RedOpsX_CVE-2025-63943.md) 🔴 ✅

**名称:** CVE-2025-63943 - Grocery Store Management System 1.0 SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致敏感数据泄露、数据篡改、身份验证绕过甚至完全数据库控制  
**投毒风险:** 5%  
**发现时间:** 2025-11-14  
**POC仓库:** [CVE-2025-63943](https://github.com/RedOpsX/CVE-2025-63943)  

---

### [CVE-2025-33073](CVE-2025-33073-uziii2208_CVE-2025-33073.md) 🔴 ✅

**名称:** CVE-2025-33073 Windows SMB客户端权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，允许攻击者通过网络提升权限  
**投毒风险:** 30%  
**发现时间:** 2025-11-14  
**POC仓库:** [CVE-2025-33073](https://github.com/uziii2208/CVE-2025-33073)  

---

### [CVE-2025-21202](CVE-2025-21202-7amzahard_CVE-2025-21202-exploit.md) 🟡 

**名称:** CVE-2025-21202 Windows Recovery Environment Agent Elevation of Privilege Vulnerability  
**类型:** 权限提升  
**风险:** 中危，本地权限提升  
**投毒风险:** 95%  
**发现时间:** 2025-11-14  
**POC仓库:** [CVE-2025-21202-exploit](https://github.com/7amzahard/CVE-2025-21202-exploit)  

---

### [CVE-2025-56526](CVE-2025-56526-HanTul_Kotaemon-CVE-2025-56526-56527-disclosure.md) 🔴 ✅

**名称:** CVE-2025-56526 & CVE-2025-56527 - Kotaemon Stored XSS & 明文凭据存储  
**类型:** 存储型XSS, 明文凭据存储  
**风险:** 高危，可能导致凭据泄露、会话劫持、UI篡改和进一步的社会工程攻击  
**投毒风险:** 10%  
**发现时间:** 2025-11-14  
**POC仓库:** [Kotaemon-CVE-2025-56526-56527-disclosure](https://github.com/HanTul/Kotaemon-CVE-2025-56526-56527-disclosure)  

---

### [CVE-2025-64513](CVE-2025-64513-shinyseam_CVE-2025-64513.md)  ✅

**名称:** CVE-2025-64513 - Milvus Proxy Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 严重，未经身份验证的攻击者可获得完全管理权限，读取、修改或删除数据，并执行特权管理操作。  
**投毒风险:** 10%  
**发现时间:** 2025-11-14  
**POC仓库:** [CVE-2025-64513](https://github.com/shinyseam/CVE-2025-64513)  

---

### [CVE-2025-59367](CVE-2025-59367-B1ack4sh_Blackash-CVE-2025-59367.md) 🔴 ✅

**名称:** CVE-2025-59367-ASUS DSL路由器认证绕过  
**类型:** 认证绕过  
**风险:** 高危，允许远程攻击者未经授权访问系统  
**投毒风险:** 10%  
**发现时间:** 2025-11-14  
**POC仓库:** [Blackash-CVE-2025-59367](https://github.com/B1ack4sh/Blackash-CVE-2025-59367)  

---

### [CVE-2025-48932](CVE-2025-48932-XploitGh0st_CVE-2025-48932---exploit.md) 🔴 ✅

**名称:** CVE-2025-48932 - Invision Community SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-14  
**POC仓库:** [CVE-2025-48932---exploit](https://github.com/XploitGh0st/CVE-2025-48932---exploit)  

---

### [CVE-2025-62215](CVE-2025-62215-dexterm300_CVE-2025-62215-exploit-poc.md) 🔴 ✅

**名称:** CVE-2025-62215 - Windows Kernel Elevation of Privilege  
**类型:** 权限提升  
**风险:** 高危，本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-11-14  
**POC仓库:** [CVE-2025-62215-exploit-poc](https://github.com/dexterm300/CVE-2025-62215-exploit-poc)  

---

### [CVE-2025-63602](CVE-2025-63602-D7EAD_CVE-2025-63602.md) 🔴 ✅

**名称:** CVE-2025-63602 - Awesome Miner 11.2.4 本地提权漏洞  
**类型:** 内核读写/代码执行  
**风险:** 高危，可能导致系统崩溃和任意代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-11-14  
**POC仓库:** [CVE-2025-63602](https://github.com/D7EAD/CVE-2025-63602)  

---

### [CVE-2025-27591](CVE-2025-27591-0xDTC_Below-Logger-Symlink-Attack_CVE-2025-27591.md) 🟡 ✅

**名称:** CVE-2025-27591-below-权限提升  
**类型:** 权限提升  
**风险:** 中危，本地用户可提升至root权限  
**投毒风险:** 5%  
**发现时间:** 2025-11-13  
**POC仓库:** [Below-Logger-Symlink-Attack_CVE-2025-27591](https://github.com/0xDTC/Below-Logger-Symlink-Attack_CVE-2025-27591)  

---

### [CVE-2025-8088](CVE-2025-8088-WezRyan_CVE-2025-8088.md) 🔴 ✅

**名称:** CVE-2025-8088 WinRAR Path Traversal  
**类型:** 路径遍历  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-11-13  
**POC仓库:** [CVE-2025-8088](https://github.com/WezRyan/CVE-2025-8088)  

---

### [CVE-2025-26686](CVE-2025-26686-alifaraj5723_CVE-2025-26686-poc.md) 🔴 

**名称:** CVE-2025-26686-Windows TCP/IP Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 60%  
**发现时间:** 2025-11-13  
**POC仓库:** [CVE-2025-26686-poc](https://github.com/alifaraj5723/CVE-2025-26686-poc)  

---

### [CVE-2025-39964](CVE-2025-39964-n1k0oowang_CVE-2025-39964_EXP.md) 🔴 ✅

**名称:** CVE-2025-39964-Linux Kernel-af_alg并发写漏洞  
**类型:** 并发写漏洞  
**风险:** 高危，可能导致拒绝服务或代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-13  
**POC仓库:** [CVE-2025-39964_EXP](https://github.com/n1k0oowang/CVE-2025-39964_EXP)  

---

### [CVE-2025-12480](CVE-2025-12480-velmetrac_CVE-2025-12480.md) 🔴 ✅

**名称:** CVE-2025-12480-Triofox-不当访问控制  
**类型:** 不当访问控制  
**风险:** 高危，可能导致完全系统破坏，部署远程访问工具，权限提升，并建立持久的C2通道  
**投毒风险:** 5%  
**发现时间:** 2025-11-13  
**POC仓库:** [CVE-2025-12480](https://github.com/velmetrac/CVE-2025-12480)  

---

### [CVE-2025-34299](CVE-2025-34299-B1ack4sh_Blackash-CVE-2025-34299.md) 🔴 ✅

**名称:** CVE-2025-34299-MonstaFTP-Unauthenticated Arbitrary File Upload  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-13  
**POC仓库:** [Blackash-CVE-2025-34299](https://github.com/B1ack4sh/Blackash-CVE-2025-34299)  

---

### [CVE-2025-20337](CVE-2025-20337-B1ack4sh_Blackash-CVE-2025-20337.md)  ✅

**名称:** CVE-2025-20337 - Cisco ISE Unauthenticated Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 严重，未经身份验证的攻击者可以以root权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-11-13  
**POC仓库:** [Blackash-CVE-2025-20337](https://github.com/B1ack4sh/Blackash-CVE-2025-20337)  

---

### [CVE-2025-64500](CVE-2025-64500-B1ack4sh_Blackash-CVE-2025-64500.md) 🟡 ✅

**名称:** CVE-2025-64500: Symfony PATH_INFO Authorization Bypass  
**类型:** Authorization Bypass  
**风险:** 中危，可能导致有限的权限提升和未经授权的资源访问  
**投毒风险:** 0%  
**发现时间:** 2025-11-13  
**POC仓库:** [Blackash-CVE-2025-64500](https://github.com/B1ack4sh/Blackash-CVE-2025-64500)  

---

### [CVE-2025-59118](CVE-2025-59118-B1ack4sh_Blackash-CVE-2025-59118.md) 🔴 ✅

**名称:** CVE-2025-59118-Apache OFBiz-任意文件上传导致RCE  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行，完全控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-11-13  
**POC仓库:** [Blackash-CVE-2025-59118](https://github.com/B1ack4sh/Blackash-CVE-2025-59118)  

---

### [CVE-2025-9816](CVE-2025-9816-monzaviman_CVE-2025-9816.md) 🔴 ✅

**名称:** CVE-2025-9816 - WP Statistics Plugin - Unauthenticated Stored XSS  
**类型:** Stored Cross-Site Scripting (XSS)  
**风险:** 高危，未经身份验证的攻击者可以注入任意Web脚本，当用户访问受感染页面时执行，可能导致会话劫持、恶意重定向或信息窃取。  
**投毒风险:** 10%  
**发现时间:** 2025-11-13  
**POC仓库:** [CVE-2025-9816](https://github.com/monzaviman/CVE-2025-9816)  

---

### [CVE-2018-6389](CVE-2018-6389-Jetserver_CVE-2018-6389-FIX.md) 🔴 ✅

**名称:** CVE-2018-6389 Wordpress DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致网站无法访问  
**投毒风险:** 0%  
**发现时间:** 2025-11-13  
**POC仓库:** [CVE-2018-6389-FIX](https://github.com/Jetserver/CVE-2018-6389-FIX)  

---

### [CVE-2025-64513](CVE-2025-64513-B1ack4sh_Blackash-CVE-2025-64513.md) 🔴 

**名称:** CVE-2025-64513-Milvus Proxy Authentication Bypass  
**类型:** Authentication Bypass  
**风险:** Critical, allows unauthenticated attackers to gain full administrative access.  
**投毒风险:** 0%  
**发现时间:** 2025-11-13  
**POC仓库:** [Blackash-CVE-2025-64513](https://github.com/B1ack4sh/Blackash-CVE-2025-64513)  

---

### [CVE-2018-6389](CVE-2018-6389-yolabingo_wordpress-fix-cve-2018-6389.md) 🟡 ✅

**名称:** CVE-2018-6389-WordPress-拒绝服务  
**类型:** 拒绝服务 (DoS)  
**风险:** 中危，可能导致网站无法访问  
**投毒风险:** 0%  
**发现时间:** 2025-11-13  
**POC仓库:** [wordpress-fix-cve-2018-6389](https://github.com/yolabingo/wordpress-fix-cve-2018-6389)  

---

### [CVE-2018-6389](CVE-2018-6389-safebuffer_CVE-2018-6389.md) 🔴 ✅

**名称:** CVE-2018-6389 WordPress Denial of Service  
**类型:** Denial of Service (DoS)  
**风险:** 高危，可能导致网站服务中断  
**投毒风险:** 0%  
**发现时间:** 2025-11-13  
**POC仓库:** [CVE-2018-6389](https://github.com/safebuffer/CVE-2018-6389)  

---

### [CVE-2018-6389](CVE-2018-6389-knqyf263_CVE-2018-6389.md) 🔴 ✅

**名称:** CVE-2018-6389 - WordPress DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致网站服务中断  
**投毒风险:** 0%  
**发现时间:** 2025-11-13  
**POC仓库:** [CVE-2018-6389](https://github.com/knqyf263/CVE-2018-6389)  

---

### [CVE-2018-6389](CVE-2018-6389-rastating_modsecurity-cve-2018-6389.md) 🔴 ✅

**名称:** CVE-2018-6389-WordPress-DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致网站无法访问  
**投毒风险:** 0%  
**发现时间:** 2025-11-13  
**POC仓库:** [modsecurity-cve-2018-6389](https://github.com/rastating/modsecurity-cve-2018-6389)  

---

### [CVE-2018-6389](CVE-2018-6389-dsfau_wordpress-CVE-2018-6389.md) 🟡 ✅

**名称:** CVE-2018-6389-WordPress-DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 中危，可能导致网站无法访问  
**投毒风险:** 10%  
**发现时间:** 2025-11-13  
**POC仓库:** [wordpress-CVE-2018-6389](https://github.com/dsfau/wordpress-CVE-2018-6389)  

---

### [CVE-2018-6389](CVE-2018-6389-JulienGadanho_cve-2018-6389-php-patcher.md) 🔴 ✅

**名称:** CVE-2018-6389-WordPress-DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致网站瘫痪  
**投毒风险:** 0%  
**发现时间:** 2025-11-13  
**POC仓库:** [cve-2018-6389-php-patcher](https://github.com/JulienGadanho/cve-2018-6389-php-patcher)  

---

### [CVE-2018-6389](CVE-2018-6389-thechrono13_PoC---CVE-2018-6389.md) 🔴 ✅

**名称:** CVE-2018-6389 - WordPress Denial of Service  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，导致服务器资源耗尽，影响网站可用性  
**投毒风险:** 0%  
**发现时间:** 2025-11-13  
**POC仓库:** [PoC---CVE-2018-6389](https://github.com/thechrono13/PoC---CVE-2018-6389)  

---

### [CVE-2018-6389](CVE-2018-6389-BlackRouter_cve-2018-6389.md) 🔴 ✅

**名称:** CVE-2018-6389 WordPress DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可导致服务器资源耗尽，网站瘫痪  
**投毒风险:** 1%  
**发现时间:** 2025-11-13  
**POC仓库:** [cve-2018-6389](https://github.com/BlackRouter/cve-2018-6389)  

---

### [CVE-2018-6389](CVE-2018-6389-JavierOlmedo_wordpress-cve-2018-6389.md) 🔴 ✅

**名称:** CVE-2018-6389 - WordPress load-scripts.php Denial of Service  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，导致服务器资源耗尽，网站无法访问  
**投毒风险:** 5%  
**发现时间:** 2025-11-13  
**POC仓库:** [wordpress-cve-2018-6389](https://github.com/JavierOlmedo/wordpress-cve-2018-6389)  

---

### [CVE-2018-6389](CVE-2018-6389-m3ssap0_wordpress_cve-2018-6389.md) 🟡 ✅

**名称:** CVE-2018-6389 WordPress DoS 漏洞  
**类型:** 拒绝服务 (DoS)  
**风险:** 中危，可能导致网站无法正常访问  
**投毒风险:** 5%  
**发现时间:** 2025-11-13  
**POC仓库:** [wordpress_cve-2018-6389](https://github.com/m3ssap0/wordpress_cve-2018-6389)  

---

### [CVE-2018-6389](CVE-2018-6389-mudhappy_Wordpress-Hack-CVE-2018-6389.md) 🔴 ✅

**名称:** CVE-2018-6389-WordPress-DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，导致网站资源耗尽无法正常访问  
**投毒风险:** 0%  
**发现时间:** 2025-11-13  
**POC仓库:** [Wordpress-Hack-CVE-2018-6389](https://github.com/mudhappy/Wordpress-Hack-CVE-2018-6389)  

---

### [CVE-2018-6389](CVE-2018-6389-armaanpathan12345_WP-DOS-Exploit-CVE-2018-6389.md) 🔴 ✅

**名称:** CVE-2018-6389-WordPress-DoS  
**类型:** 拒绝服务（DoS）  
**风险:** 高危，可能导致网站无法访问  
**投毒风险:** 0%  
**发现时间:** 2025-11-13  
**POC仓库:** [WP-DOS-Exploit-CVE-2018-6389](https://github.com/armaanpathan12345/WP-DOS-Exploit-CVE-2018-6389)  

---

### [CVE-2018-6389](CVE-2018-6389-ItinerisLtd_trellis-cve-2018-6389.md) 🟡 ✅

**名称:** CVE-2018-6389 WordPress DoS 漏洞  
**类型:** 拒绝服务 (DoS)  
**风险:** 中危，可能导致网站服务不可用  
**投毒风险:** 0%  
**发现时间:** 2025-11-13  
**POC仓库:** [trellis-cve-2018-6389](https://github.com/ItinerisLtd/trellis-cve-2018-6389)  

---

### [CVE-2018-6389](CVE-2018-6389-Zazzzles_Wordpress-DOS.md) 🟡 ✅

**名称:** CVE-2018-6389-WordPress-DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 中危，导致服务器资源耗尽，影响网站正常访问  
**投毒风险:** 0%  
**发现时间:** 2025-11-13  
**POC仓库:** [Wordpress-DOS](https://github.com/Zazzzles/Wordpress-DOS)  

---

### [CVE-2018-6389](CVE-2018-6389-fakedob_tvsz.md) 🔴 ✅

**名称:** CVE-2018-6389 WordPress Denial of Service  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致服务不可用  
**投毒风险:** 30%  
**发现时间:** 2025-11-13  
**POC仓库:** [tvsz](https://github.com/fakedob/tvsz)  

---

### [CVE-2018-6389](CVE-2018-6389-alessiogilardi_PoC---CVE-2018-6389.md) 🔴 ✅

**名称:** CVE-2018-6389-WordPress-DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，导致服务器资源耗尽，网站无法访问  
**投毒风险:** 10%  
**发现时间:** 2025-11-13  
**POC仓库:** [PoC---CVE-2018-6389](https://github.com/alessiogilardi/PoC---CVE-2018-6389)  

---

### [CVE-2018-6389](CVE-2018-6389-vineetkia_Wordpress-DOS-Attack-CVE-2018-6389.md) 🟡 ✅

**名称:** CVE-2018-6389 - WordPress DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 中危，可能导致网站不可用  
**投毒风险:** 0%  
**发现时间:** 2025-11-13  
**POC仓库:** [Wordpress-DOS-Attack-CVE-2018-6389](https://github.com/vineetkia/Wordpress-DOS-Attack-CVE-2018-6389)  

---

### [CVE-2018-6389](CVE-2018-6389-ianxtianxt_CVE-2018-6389.md) 🔴 ✅

**名称:** CVE-2018-6389-WordPress-DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致网站瘫痪  
**投毒风险:** 5%  
**发现时间:** 2025-11-13  
**POC仓库:** [CVE-2018-6389](https://github.com/ianxtianxt/CVE-2018-6389)  

---

### [CVE-2018-6389](CVE-2018-6389-s0md3v_Shiva.md) 🔴 ✅

**名称:** CVE-2018-6389 - WordPress Denial of Service  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，导致服务器资源耗尽，无法正常提供服务  
**投毒风险:** 10%  
**发现时间:** 2025-11-13  
**POC仓库:** [Shiva](https://github.com/s0md3v/Shiva)  

---

### [CVE-2018-6389](CVE-2018-6389-amit-pathak009_CVE-2018-6389-FIX.md)  

**名称:** CVE-2018-6389 WordPress DoS 漏洞修复脚本分析  
**类型:** 安全补丁  
**风险:** 低风险，该脚本旨在修复漏洞，而非利用漏洞  
**投毒风险:** 0%  
**发现时间:** 2025-11-13  
**POC仓库:** [CVE-2018-6389-FIX](https://github.com/amit-pathak009/CVE-2018-6389-FIX)  

---

### [CVE-2018-6389](CVE-2018-6389-omidsec_CVE-2018-6389.md) 🔴 ✅

**名称:** CVE-2018-6389 - WordPress Denial of Service  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致服务器资源耗尽，网站无法访问  
**投毒风险:** 5%  
**发现时间:** 2025-11-13  
**POC仓库:** [CVE-2018-6389](https://github.com/omidsec/CVE-2018-6389)  

---

### [CVE-2024-0044](CVE-2024-0044-hunter24x24_cve_2024_0044.md) 🔴 ✅

**名称:** CVE-2024-0044  
**类型:** 权限提升  
**风险:** 高危，可能允许本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-11-13  
**POC仓库:** [cve_2024_0044](https://github.com/hunter24x24/cve_2024_0044)  

---

### [CVE-2024-0044](CVE-2024-0044-MrW0l05zyn_cve-2024-0044.md) 🔴 ✅

**名称:** CVE-2024-0044-Android本地提权  
**类型:** 本地提权  
**风险:** 高危，可导致本地权限提升，访问任意应用私有数据  
**投毒风险:** 10%  
**发现时间:** 2025-11-13  
**POC仓库:** [cve-2024-0044](https://github.com/MrW0l05zyn/cve-2024-0044)  

---

### [CVE-2024-0044](CVE-2024-0044-Dit-Developers_CVE-2024-0044-.md) 🔴 ✅

**名称:** CVE-2024-0044  
**类型:** 权限提升  
**风险:** 高危，可使攻击者以任意应用身份运行  
**投毒风险:** 0%  
**发现时间:** 2025-11-13  
**POC仓库:** [CVE-2024-0044-](https://github.com/Dit-Developers/CVE-2024-0044-)  

---

### [CVE-2025-32434](CVE-2025-32434-Camier_VOIXCODER.md) 🔴 ✅

**名称:** CVE-2025-32434-PyTorch-反序列化漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-13  
**POC仓库:** [VOIXCODER](https://github.com/Camier/VOIXCODER)  

---

### [CVE-2025-32434](CVE-2025-32434-cyhe50_cve-2025-32434-poc.md) 🔴 ✅

**名称:** CVE-2025-32434-PyTorch-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-13  
**POC仓库:** [cve-2025-32434-poc](https://github.com/cyhe50/cve-2025-32434-poc)  

---

### [CVE-2024-0044](CVE-2024-0044-007CRIPTOGRAFIA_c-CVE-2024-0044.md) 🔴 ✅

**名称:** CVE-2024-0044: Android PackageInstallerService 提权漏洞  
**类型:** 权限提升  
**风险:** 高危，本地权限提升，可能导致任意代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-11-13  
**POC仓库:** [c-CVE-2024-0044](https://github.com/007CRIPTOGRAFIA/c-CVE-2024-0044)  

---

### [CVE-2024-0044](CVE-2024-0044-Kai2er_CVE-2024-0044-EXP.md) 🔴 ✅

**名称:** CVE-2024-0044  
**类型:** 权限提升  
**风险:** 高危，可能导致本地权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-11-13  
**POC仓库:** [CVE-2024-0044-EXP](https://github.com/Kai2er/CVE-2024-0044-EXP)  

---

### [CVE-2024-0044](CVE-2024-0044-scs-labrat_android_autorooter.md) 🔴 ✅

**名称:** CVE-2024-0044 - Android PackageInstallerService 特权提升  
**类型:** 特权提升  
**风险:** 高危，可能导致本地提权  
**投毒风险:** 10%  
**发现时间:** 2025-11-13  
**POC仓库:** [android_autorooter](https://github.com/scs-labrat/android_autorooter)  

---

### [CVE-2024-0044](CVE-2024-0044-l1ackerronin_CVE-2024-0044.md) 🔴 ✅

**名称:** CVE-2024-0044-Android PackageInstallerService权限提升  
**类型:** 权限提升  
**风险:** 高危，可能导致本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-11-13  
**POC仓库:** [CVE-2024-0044](https://github.com/l1ackerronin/CVE-2024-0044)  

---

### [CVE-2024-0044](CVE-2024-0044-Re13orn_CVE-2024-0044-EXP.md) 🔴 ✅

**名称:** CVE-2024-0044 Android 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可导致本地权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-11-13  
**POC仓库:** [CVE-2024-0044-EXP](https://github.com/Re13orn/CVE-2024-0044-EXP)  

---

### [CVE-2024-0044](CVE-2024-0044-canyie_CVE-2024-0044.md) 🔴 ✅

**名称:** CVE-2024-0044  
**类型:** 权限提升  
**风险:** 高危，允许本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-11-13  
**POC仓库:** [CVE-2024-0044](https://github.com/canyie/CVE-2024-0044)  

---

### [CVE-2024-0044](CVE-2024-0044-0xbinder_CVE-2024-0044.md) 🔴 ✅

**名称:** CVE-2024-0044  
**类型:** 权限提升  
**风险:** 高危，可能导致本地权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-11-13  
**POC仓库:** [CVE-2024-0044](https://github.com/0xbinder/CVE-2024-0044)  

---

### [CVE-2024-0044](CVE-2024-0044-sridhar-sec_EvilDroid.md) 🔴 ✅

**名称:** CVE-2024-0044  
**类型:** 权限提升  
**风险:** 高危，本地权限提升  
**投毒风险:** 20%  
**发现时间:** 2025-11-13  
**POC仓库:** [EvilDroid](https://github.com/sridhar-sec/EvilDroid)  

---

### [CVE-2024-0044](CVE-2024-0044-Athexhacker_EXPLOITER.md) 🔴 ✅

**名称:** CVE-2024-0044  
**类型:** 权限提升  
**风险:** 高危，本地权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-11-13  
**POC仓库:** [EXPLOITER](https://github.com/Athexhacker/EXPLOITER)  

---

### [CVE-2025-64708](CVE-2025-64708-DylanDavis1_CVE-2025-64708.md) 🔴 ✅

**名称:** CVE-2025-63708-AI Font Matcher-XSS  
**类型:** 跨站脚本攻击 (XSS)  
**风险:** 高危，可能导致会话劫持和账户接管  
**投毒风险:** 0%  
**发现时间:** 2025-11-13  
**POC仓库:** [CVE-2025-64708](https://github.com/DylanDavis1/CVE-2025-64708)  

---

### [CVE-2025-20260](CVE-2025-20260-keyuraghao_CVE-2025-20260.md)  ✅

**名称:** CVE-2025-20260 ClamAV PDF Scanning Buffer Overflow  
**类型:** 堆缓冲区溢出  
**风险:** 严重，可能导致拒绝服务或远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-13  
**POC仓库:** [CVE-2025-20260](https://github.com/keyuraghao/CVE-2025-20260)  

---

### [CVE-2025-12101](CVE-2025-12101-6h4ack_CVE-2025-12101-checker.md) 🟡 ✅

**名称:** CVE-2025-12101-NetScaler ADC/Gateway 反射型XSS  
**类型:** 反射型跨站脚本 (RXSS)  
**风险:** 中危，可能导致会话劫持、恶意重定向等  
**投毒风险:** 0%  
**发现时间:** 2025-11-12  
**POC仓库:** [CVE-2025-12101-checker](https://github.com/6h4ack/CVE-2025-12101-checker)  

---

### [CVE-2025-13027](CVE-2025-13027-yourluckyday3-art_CVE-2025-13027-Exploit.md) 🔴 

**名称:** CVE-2025-13027-Firefox-内存安全漏洞  
**类型:** 内存安全漏洞  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-12  
**POC仓库:** [CVE-2025-13027-Exploit](https://github.com/yourluckyday3-art/CVE-2025-13027-Exploit)  

---

### [CVE-2025-62215](CVE-2025-62215-fordeant_CVE-2025-62215.md) 🔴 ✅

**名称:** CVE-2025-62215 - Windows Kernel Race Condition Privilege Escalation  
**类型:** 权限提升  
**风险:** 高危，可完全控制系统  
**投毒风险:** 10%  
**发现时间:** 2025-11-12  
**POC仓库:** [CVE-2025-62215](https://github.com/fordeant/CVE-2025-62215)  

---

### [CVE-2025-59253](CVE-2025-59253-zigzagymym1986_CVE-2025-59253.md) 🟡 ✅

**名称:** CVE-2025-59253 - Windows Search Service Denial of Service  
**类型:** 拒绝服务 (DoS)  
**风险:** 中危，导致服务不可用，影响用户体验  
**投毒风险:** 10%  
**发现时间:** 2025-11-12  
**POC仓库:** [CVE-2025-59253](https://github.com/zigzagymym1986/CVE-2025-59253)  

---

### [CVE-2024-4577](CVE-2024-4577-Chocapikk_CVE-2024-4577.md)  ✅

**名称:** CVE-2024-4577 PHP CGI参数注入  
**类型:** 远程代码执行  
**风险:** 严重，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-11-12  
**POC仓库:** [CVE-2024-4577](https://github.com/Chocapikk/CVE-2024-4577)  

---

### [CVE-2025-60724](CVE-2025-60724-Iomarlto_CVE-2025-60724.md) 🔴 

**名称:** CVE-2025-60724 GDI+ 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许未经授权的攻击者通过网络执行代码  
**投毒风险:** 0%  
**发现时间:** 2025-11-12  
**POC仓库:** [CVE-2025-60724](https://github.com/Iomarlto/CVE-2025-60724)  

---

### [CVE-2025-64403](CVE-2025-64403-makaroonbourne_CVE-2025-64403-Exploit.md) 🔴 ✅

**名称:** CVE-2025-64403-Apache OpenOffice 远程文件加载  
**类型:** 缺失授权  
**风险:** 高危，可能导致信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-11-12  
**POC仓库:** [CVE-2025-64403-Exploit](https://github.com/makaroonbourne/CVE-2025-64403-Exploit)  

---

### [CVE-2025-60724](CVE-2025-60724-Iomarlto_CVE-2025-60724.md) 🔴 ✅

**名称:** CVE-2025-60724-GDI+ Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 80%  
**发现时间:** 2025-11-12  
**POC仓库:** [CVE-2025-60724](https://github.com/Iomarlto/CVE-2025-60724)  

---

### [CVE-2024-48910](CVE-2024-48910-Alex-Acero-Security_CVE-2024-48910-POC.md) 🔴 ✅

**名称:** CVE-2024-48910-DOMPurify-原型污染  
**类型:** 原型污染  
**风险:** 高危，可能导致数据篡改和XSS  
**投毒风险:** 0%  
**发现时间:** 2025-11-12  
**POC仓库:** [CVE-2024-48910-POC](https://github.com/Alex-Acero-Security/CVE-2024-48910-POC)  

---

### [CVE-2019-9053](CVE-2019-9053-6iroc_CVE-2019-9053.md) 🔴 ✅

**名称:** CVE-2019-9053-CMS Made Simple-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-11-12  
**POC仓库:** [CVE-2019-9053](https://github.com/6iroc/CVE-2019-9053)  

---

### [CVE-2025-4796](CVE-2025-4796-Pwdnx1337_CVE-2025-4796.md) 🔴 ✅

**名称:** CVE-2025-4796-Eventin-权限提升/账户接管  
**类型:** 权限提升/账户接管  
**风险:** 高危，可导致账户接管，获取管理员权限  
**投毒风险:** 1%  
**发现时间:** 2025-11-12  
**POC仓库:** [CVE-2025-4796](https://github.com/Pwdnx1337/CVE-2025-4796)  

---

### [CVE-2024-4890](CVE-2024-4890-nekr0ff_needrestart-sudo-escalate-cve-2024-4890.md) 🟡 

**名称:** CVE-2024-4890-litellm-Blind SQL Injection  
**类型:** Blind SQL Injection  
**风险:** 中危，可能导致未授权访问敏感信息，如API密钥、用户信息和token  
**投毒风险:** 0%  
**发现时间:** 2025-11-12  
**POC仓库:** [needrestart-sudo-escalate-cve-2024-4890](https://github.com/nekr0ff/needrestart-sudo-escalate-cve-2024-4890)  

---

### [CVE-2025-63830](CVE-2025-63830-Shubham03007_CVE-2025-63830.md) 🔴 ✅

**名称:** CVE-2025-63830-CKFinder-Stored-XSS  
**类型:** 存储型跨站脚本 (Stored XSS)  
**风险:** 高危，可能导致敏感信息泄露、会话劫持、恶意重定向等  
**投毒风险:** 10%  
**发现时间:** 2025-11-12  
**POC仓库:** [CVE-2025-63830](https://github.com/Shubham03007/CVE-2025-63830)  

---

### [CVE-2025-31133](CVE-2025-31133-omne-earth_arca.md) 🔴 

**名称:** CVE-2025-31133-runc容器逃逸  
**类型:** 容器逃逸  
**风险:** 高危，可能导致主机信息泄露、主机拒绝服务、容器逃逸或绕过maskedPaths  
**投毒风险:** 30%  
**发现时间:** 2025-11-12  
**POC仓库:** [arca](https://github.com/omne-earth/arca)  

---

### [CVE-2025-31133](CVE-2025-31133-skynet-f-nvidia_CVE-2025-31133.md) 🔴 ✅

**名称:** CVE-2025-31133-runc-容器逃逸  
**类型:** 容器逃逸  
**风险:** 高危，可能导致主机信息泄露，主机拒绝服务，容器逃逸或绕过maskedPaths。  
**投毒风险:** 10%  
**发现时间:** 2025-11-12  
**POC仓库:** [CVE-2025-31133](https://github.com/skynet-f-nvidia/CVE-2025-31133)  

---

### [CVE-2020-0192](CVE-2020-0192-himanshu67111_CVE-2020-0192.md) 🟡 ✅

**名称:** CVE-2020-0192  
**类型:** 信息泄露  
**风险:** 中危，可能导致远程信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-11-12  
**POC仓库:** [CVE-2020-0192](https://github.com/himanshu67111/CVE-2020-0192)  

---

### [CVE-2025-56499](CVE-2025-56499-Cherrling_CVE-2025-56499.md)  ✅

**名称:** 未知漏洞  
**类型:** 未知  
**风险:** 低危，信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-11-12  
**POC仓库:** [CVE-2025-56499](https://github.com/Cherrling/CVE-2025-56499)  

---

### [CVE-2025-60710](CVE-2025-60710-Wh04m1001_CVE-2025-60710.md) 🔴 ✅

**名称:** CVE-2025-60710 - Host Process for Windows Tasks 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，攻击者可利用此漏洞获得SYSTEM权限  
**投毒风险:** 0%  
**发现时间:** 2025-11-12  
**POC仓库:** [CVE-2025-60710](https://github.com/Wh04m1001/CVE-2025-60710)  

---

### [CVE-2024-47167](CVE-2024-47167-alexan011_CVE-2024-47167-Environment-Setup.md) 🟡 ✅

**名称:** CVE-2024-47167-Gradio-SSRF  
**类型:** SSRF  
**风险:** 中危，可能导致内部服务信息泄露，任意文件读取。  
**投毒风险:** 10%  
**发现时间:** 2025-11-12  
**POC仓库:** [CVE-2024-47167-Environment-Setup](https://github.com/alexan011/CVE-2024-47167-Environment-Setup)  

---

### [CVE-2025-31931](CVE-2025-31931-yohanes_POC-CVE-2025-31931.md) 🟡 ✅

**名称:** CVE-2025-31931-Instrumentation and Tracing Technology API (ITT API)软件权限提升漏洞  
**类型:** 权限提升/Uncontrolled Search Path Element (CWE-427)  
**风险:** 中危，通过劫持ITT API搜索路径，可能导致本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-11-12  
**POC仓库:** [POC-CVE-2025-31931](https://github.com/yohanes/POC-CVE-2025-31931)  

---

### [CVE-2025-11170](CVE-2025-11170-Nxploited_CVE-2025-11170.md) 🔴 ✅

**名称:** CVE-2025-11170-WP迁移专用插件 for CPI-Unauthenticated Arbitrary File Upload  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-11-11  
**POC仓库:** [CVE-2025-11170](https://github.com/Nxploited/CVE-2025-11170)  

---

### [CVE-2025-49844](CVE-2025-49844-Network-Sec_CVE-2025-49844-RediShell-AI-made-Revshell.md) 🔴 ✅

**名称:** CVE-2025-49844 Redis Lua Use-After-Free 远程代码执行  
**类型:** Use-After-Free  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-11  
**POC仓库:** [CVE-2025-49844-RediShell-AI-made-Revshell](https://github.com/Network-Sec/CVE-2025-49844-RediShell-AI-made-Revshell)  

---

### [CVE-2023-35813](CVE-2023-35813-aalexpereira_CVE-2023-35813.md) 🔴 ✅

**名称:** CVE-2023-35813-Sitecore-远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致完全控制服务器，数据泄露，篡改等  
**投毒风险:** 0%  
**发现时间:** 2025-11-11  
**POC仓库:** [CVE-2023-35813](https://github.com/aalexpereira/CVE-2023-35813)  

---

### [CVE-2023-35813](CVE-2023-35813-BagheeraAltered_CVE-2023-35813-PoC.md) 🔴 ✅

**名称:** CVE-2023-35813-Sitecore-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致完全控制受影响的Sitecore实例  
**投毒风险:** 10%  
**发现时间:** 2025-11-11  
**POC仓库:** [CVE-2023-35813-PoC](https://github.com/BagheeraAltered/CVE-2023-35813-PoC)  

---

### [CVE-2023-35813](CVE-2023-35813-her3ticAVI_CVE-2023-35813.md) 🔴 ✅

**名称:** CVE-2023-35813-Sitecore-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未经授权的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-11  
**POC仓库:** [CVE-2023-35813](https://github.com/her3ticAVI/CVE-2023-35813)  

---

### [CVE-2024-23897](CVE-2024-23897-harekrishnarai_CVE-2024-23897-test-windows.md) 🔴 ✅

**名称:** CVE-2024-23897-Jenkins 任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-11-11  
**POC仓库:** [CVE-2024-23897-test-windows](https://github.com/harekrishnarai/CVE-2024-23897-test-windows)  

---

### [CVE-2025-48703](CVE-2025-48703-137f_PoC-CVE-2025-48703.md) 🔴 ✅

**名称:** CVE-2025-48703 - CentOS Web Panel 未授权远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可完全控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-11-11  
**POC仓库:** [PoC-CVE-2025-48703](https://github.com/137f/PoC-CVE-2025-48703)  

---

### [CVE-2025-10161](CVE-2025-10161-FeZqq_CVE-2025-10161.md) 🔴 ✅

**名称:** CVE-2025-10161-Turkguven Perfektive-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权访问和功能滥用  
**投毒风险:** 0%  
**发现时间:** 2025-11-11  
**POC仓库:** [CVE-2025-10161](https://github.com/FeZqq/CVE-2025-10161)  

---

### [CVE-2025-9223](CVE-2025-9223-networkkiller_CVE-2025-9223.md) 🔴 ✅

**名称:** CVE-2025-9223-ManageEngine Applications Manager-命令注入  
**类型:** 命令注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-11  
**POC仓库:** [CVE-2025-9223](https://github.com/networkkiller/CVE-2025-9223)  

---

### [CVE-2025-48593](CVE-2025-48593-GiladLeef_CVE-2025-48593.md)  ✅

**名称:** CVE-2025-48593  
**类型:** 未知  
**风险:** 未知，需要进一步分析  
**投毒风险:** 10%  
**发现时间:** 2025-11-11  
**POC仓库:** [CVE-2025-48593](https://github.com/GiladLeef/CVE-2025-48593)  

---

### [CVE-2024-51378](CVE-2024-51378-rimbadirgantara_CVE-2024-51378.md) 🔴 ✅

**名称:** CVE-2024-51378 - CyberPanel 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可绕过身份验证并执行任意命令  
**投毒风险:** 5%  
**发现时间:** 2025-11-11  
**POC仓库:** [CVE-2024-51378](https://github.com/rimbadirgantara/CVE-2024-51378)  

---

### [CVE-2025-41244](CVE-2025-41244-IBO-ATTACKS_CVE-2025-41244.md) 🔴 ✅

**名称:** CVE-2025-41244-VMware权限提升  
**类型:** 本地权限提升  
**风险:** 高危，可能导致root权限获取  
**投毒风险:** 0%  
**发现时间:** 2025-11-11  
**POC仓库:** [CVE-2025-41244](https://github.com/IBO-ATTACKS/CVE-2025-41244)  

---

### [CVE-2025-10161](CVE-2025-10161-FeZqq_CVE-2025-10161.md) 🔴 ✅

**名称:** CVE-2025-10161-Perfektive-Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权访问和功能绕过  
**投毒风险:** 10%  
**发现时间:** 2025-11-11  
**POC仓库:** [CVE-2025-10161](https://github.com/FeZqq/CVE-2025-10161)  

---

### [CVE-2025-63667](CVE-2025-63667-Remenis_CVE-2025-63667.md) 🔴 

**名称:** CVE-2025-63667 - Vatilon IP Cameras Improper Authentication  
**类型:** 不当身份验证/访问控制  
**风险:** 高危，允许未授权访问管理数据和控制设备  
**投毒风险:** 10%  
**发现时间:** 2025-11-11  
**POC仓库:** [CVE-2025-63667](https://github.com/Remenis/CVE-2025-63667)  

---

### [CVE-2025-63666](CVE-2025-63666-Remenis_CVE-2025-63666.md) 🔴 ✅

**名称:** CVE-2025-63666 - Tenda AC15 身份验证绕过和会话劫持  
**类型:** 身份验证绕过/会话劫持  
**风险:** 高危，可能导致未经授权的访问和控制路由器  
**投毒风险:** 10%  
**发现时间:** 2025-11-11  
**POC仓库:** [CVE-2025-63666](https://github.com/Remenis/CVE-2025-63666)  

---

### [CVE-2025-55449](CVE-2025-55449-Marven11_CVE-2025-55449-AstrBot-RCE.md) 🔴 ✅

**名称:** AstrBot <= 3.5.17 JWT 密钥硬编码导致 RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致完全控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-11-11  
**POC仓库:** [CVE-2025-55449-AstrBot-RCE](https://github.com/Marven11/CVE-2025-55449-AstrBot-RCE)  

---

### [CVE-2025-12539](CVE-2025-12539-Nxploited_CVE-2025-12539.md) 🔴 ✅

**名称:** CVE-2025-12539-TNC Toolbox: Web Performance-敏感信息泄露  
**类型:** 敏感信息泄露  
**风险:** 高危，可能导致cPanel账户接管和服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-11-11  
**POC仓库:** [CVE-2025-12539](https://github.com/Nxploited/CVE-2025-12539)  

---

### [CVE-2018-14324](CVE-2018-14324-matejsmycka_CVE-2018-14324-Exploit.md) 🔴 ✅

**名称:** CVE-2018-14324 - Oracle GlassFish Open Source Edition JMX RMI 远程监控和控制问题  
**类型:** 配置缺陷/弱口令  
**风险:** 高危，可能导致敏感信息泄露、数据库操作或远程控制  
**投毒风险:** 0%  
**发现时间:** 2025-11-11  
**POC仓库:** [CVE-2018-14324-Exploit](https://github.com/matejsmycka/CVE-2018-14324-Exploit)  

---

### [CVE-2021-4449](CVE-2021-4449-0xmoner_CVE-2021-4449.md) 🔴 ✅

**名称:** CVE-2021-4449 - ZoomSounds WordPress插件未授权任意文件上传漏洞  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-11  
**POC仓库:** [CVE-2021-4449](https://github.com/0xmoner/CVE-2021-4449)  

---

### [CVE-2024-44349](CVE-2024-44349-AndreaF17_PoC-CVE-2024-44349.md) 🔴 ✅

**名称:** CVE-2024-44349-AnteeoWMS-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-11  
**POC仓库:** [PoC-CVE-2024-44349](https://github.com/AndreaF17/PoC-CVE-2024-44349)  

---

### [CVE-2025-34299](CVE-2025-34299-rxerium_CVE-2025-34299.md) 🔴 ✅

**名称:** CVE-2025-34299-Monsta FTP-未授权任意文件上传  
**类型:** 未授权任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-11-11  
**POC仓库:** [CVE-2025-34299](https://github.com/rxerium/CVE-2025-34299)  

---

### [CVE-2024-31982](CVE-2024-31982-NanoWraith_CVE-2024-31982.md) 🔴 ✅

**名称:** CVE-2024-31982-XWiki-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-11-11  
**POC仓库:** [CVE-2024-31982](https://github.com/NanoWraith/CVE-2024-31982)  

---

### [CVE-2024-31982](CVE-2024-31982-th3gokul_CVE-2024-31982.md)  ✅

**名称:** CVE-2024-31982-XWiki Platform-远程代码执行  
**类型:** 远程代码执行  
**风险:** 严重，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-11-11  
**POC仓库:** [CVE-2024-31982](https://github.com/th3gokul/CVE-2024-31982)  

---

### [CVE-2024-31982](CVE-2024-31982-bigb0x_CVE-2024-31982.md) 🔴 ✅

**名称:** CVE-2024-31982-XWiki Platform-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致完全控制受影响的XWiki平台  
**投毒风险:** 5%  
**发现时间:** 2025-11-11  
**POC仓库:** [CVE-2024-31982](https://github.com/bigb0x/CVE-2024-31982)  

---

### [CVE-2024-31982](CVE-2024-31982-raishin1_CVE-2024-31982.md) 🔴 ✅

**名称:** CVE-2024-31982-XWiki-远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-11  
**POC仓库:** [CVE-2024-31982](https://github.com/raishin1/CVE-2024-31982)  

---

### [CVE-2025-25257](CVE-2025-25257-mr-r3b00t_CVE-2025-25257.md)  ✅

**名称:** CVE-2025-25257-FortiWeb-SQL注入  
**类型:** SQL注入  
**风险:** 严重，未经身份验证的攻击者可以执行未经授权的SQL代码或命令  
**投毒风险:** 10%  
**发现时间:** 2025-11-11  
**POC仓库:** [CVE-2025-25257](https://github.com/mr-r3b00t/CVE-2025-25257)  

---

### [CVE-2025-58179](CVE-2025-58179-shitodcy_CVE-2025-58179-Check.md) 🔴 ✅

**名称:** CVE-2025-58179-Astro Cloudflare adapter SSRF  
**类型:** SSRF (Server-Side Request Forgery)  
**风险:** 高危，可能导致敏感信息泄露、内部服务访问和潜在的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-11-11  
**POC仓库:** [CVE-2025-58179-Check](https://github.com/shitodcy/CVE-2025-58179-Check)  

---

### [CVE-2025-55315](CVE-2025-55315-ZemarKhos_CVE-2025-55315-PoC-Exploit.md) 🔴 ✅

**名称:** CVE-2025-55315 ASP.NET Core Kestrel HTTP请求走私漏洞  
**类型:** HTTP请求走私  
**风险:** 高危，可能导致身份验证绕过、凭据窃取、SSRF、缓存投毒、远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-11  
**POC仓库:** [CVE-2025-55315-PoC-Exploit](https://github.com/ZemarKhos/CVE-2025-55315-PoC-Exploit)  

---

### [CVE-2024-45496](CVE-2024-45496-pwnc4t_cve-2024-45496.md) 🔴 ✅

**名称:** CVE-2024-45496-OpenShift节点权限提升  
**类型:** 权限提升  
**风险:** 高危，可能导致节点完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-11-11  
**POC仓库:** [cve-2024-45496](https://github.com/pwnc4t/cve-2024-45496)  

---

### [CVE-2024-48910](CVE-2024-48910-Mitchellzhou1_CVE-2024-48910-PoC.md) 🔴 ✅

**名称:** CVE-2024-48910-DOMPurify-原型污染  
**类型:** 原型污染  
**风险:** 高危，可能导致XSS绕过和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-11-11  
**POC仓库:** [CVE-2024-48910-PoC](https://github.com/Mitchellzhou1/CVE-2024-48910-PoC)  

---

### [CVE-2016-10204](CVE-2016-10204-dc-333-666_CVE-2016-10204_Webshell.md) 🔴 ✅

**名称:** CVE-2016-10204-ZoneMinder-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-11  
**POC仓库:** [CVE-2016-10204_Webshell](https://github.com/dc-333-666/CVE-2016-10204_Webshell)  

---

### [CVE-2025-63419](CVE-2025-63419-MMAKINGDOM_CVE-2025-63419.md)  ✅

**名称:** CVE-2025-63419-CrushFTP-HTML注入  
**类型:** HTML注入  
**风险:** 低危，可能导致轻微的完整性损害  
**投毒风险:** 5%  
**发现时间:** 2025-11-11  
**POC仓库:** [CVE-2025-63419](https://github.com/MMAKINGDOM/CVE-2025-63419)  

---

### [CVE-2025-61932](CVE-2025-61932-godfatherofexps_CVE-2025-61932-PoC.md) 🔴 ✅

**名称:** CVE-2025-61932-Lanscope Endpoint Manager-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的攻击者可远程执行任意代码  
**投毒风险:** 95%  
**发现时间:** 2025-11-11  
**POC仓库:** [CVE-2025-61932-PoC](https://github.com/godfatherofexps/CVE-2025-61932-PoC)  

---

### [CVE-2025-6440](CVE-2025-6440-Nxploited_CVE-2025-6440.md) 🔴 ✅

**名称:** CVE-2025-6440 - WooCommerce Designer Pro 未授权任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-11  
**POC仓库:** [CVE-2025-6440](https://github.com/Nxploited/CVE-2025-6440)  

---

### [CVE-2025-64495](CVE-2025-64495-B1ack4sh_Blackash-CVE-2025-64495.md) 🔴 ✅

**名称:** CVE-2025-64495-Open WebUI-Stored DOM XSS  
**类型:** Stored DOM XSS  
**风险:** 高危，可能导致账户接管和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-10  
**POC仓库:** [Blackash-CVE-2025-64495](https://github.com/B1ack4sh/Blackash-CVE-2025-64495)  

---

### [CVE-2013-0269](CVE-2013-0269-heroku_heroku-CVE-2013-0269.md) 🔴 ✅

**名称:** CVE-2013-0269-Ruby JSON gem-Unsafe Object Creation Vulnerability  
**类型:** 不安全对象创建漏洞  
**风险:** 高危，可能导致拒绝服务 (DoS)、绕过大规模赋值保护机制，甚至可能导致 SQL 注入  
**投毒风险:** 0%  
**发现时间:** 2025-11-10  
**POC仓库:** [heroku-CVE-2013-0269](https://github.com/heroku/heroku-CVE-2013-0269)  

---

### [CVE-2025-8088](CVE-2025-8088-kredscript_cve-2025-8088.md) 🔴 ✅

**名称:** CVE-2025-8088 WinRAR路径遍历  
**类型:** 路径遍历  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 20%  
**发现时间:** 2025-11-10  
**POC仓库:** [cve-2025-8088](https://github.com/kredscript/cve-2025-8088)  

---

### [CVE-2013-0156](CVE-2013-0156-R3dKn33-zz_CVE-2013-0156.md) 🔴 ✅

**名称:** CVE-2013-0156  
**类型:** 对象注入/代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-10  
**POC仓库:** [CVE-2013-0156](https://github.com/R3dKn33-zz/CVE-2013-0156)  

---

### [CVE-2013-0156](CVE-2013-0156-oxben10_CVE-2013-0156.md) 🔴 ✅

**名称:** CVE-2013-0156-Ruby on Rails-对象注入  
**类型:** 对象注入/反序列化漏洞  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-10  
**POC仓库:** [CVE-2013-0156](https://github.com/oxben10/CVE-2013-0156)  

---

### [CVE-2013-0156](CVE-2013-0156-heroku_heroku-CVE-2013-0156.md) 🔴 ✅

**名称:** CVE-2013-0156 - Ruby on Rails 对象注入漏洞  
**类型:** 对象注入  
**风险:** 高危，可能导致远程代码执行或拒绝服务  
**投毒风险:** 0%  
**发现时间:** 2025-11-10  
**POC仓库:** [heroku-CVE-2013-0156](https://github.com/heroku/heroku-CVE-2013-0156)  

---

### [CVE-2013-0333](CVE-2013-0333-heroku_heroku-CVE-2013-0333.md) 🔴 ✅

**名称:** CVE-2013-0333-Ruby on Rails-YAML Deserialization  
**类型:** YAML Deserialization  
**风险:** 高危，可能导致远程代码执行、SQL注入或绕过身份验证  
**投毒风险:** 0%  
**发现时间:** 2025-11-10  
**POC仓库:** [heroku-CVE-2013-0333](https://github.com/heroku/heroku-CVE-2013-0333)  

---

### [CVE-2022-4361](CVE-2022-4361-faccimatteo_CVE-2022-4361.md) 🔴 ✅

**名称:** CVE-2022-4361-Keycloak-XSS  
**类型:** XSS  
**风险:** 高危，允许攻击者执行恶意脚本，可能导致会话劫持、信息窃取或权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-11-10  
**POC仓库:** [CVE-2022-4361](https://github.com/faccimatteo/CVE-2022-4361)  

---

### [CVE-2025-64459](CVE-2025-64459-nunpa_CVE-2025-64459.md) 🔴 ✅

**名称:** CVE-2025-64459-Django-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-11-10  
**POC仓库:** [CVE-2025-64459](https://github.com/nunpa/CVE-2025-64459)  

---

### [CVE-2013-0156](CVE-2013-0156-terracatta_name_reverser.md) 🔴 ✅

**名称:** CVE-2013-0156-Ruby on Rails-对象注入  
**类型:** 对象注入/反序列化  
**风险:** 高危，可能导致远程代码执行或拒绝服务  
**投毒风险:** 1%  
**发现时间:** 2025-11-10  
**POC仓库:** [name_reverser](https://github.com/terracatta/name_reverser)  

---

### [CVE-2013-0156](CVE-2013-0156-josal_crack-0.1.8-fixed.md) 🔴 ✅

**名称:** CVE-2013-0156  
**类型:** 对象注入/代码执行/拒绝服务  
**风险:** 高危  
**投毒风险:** 10%  
**发现时间:** 2025-11-10  
**POC仓库:** [crack-0.1.8-fixed](https://github.com/josal/crack-0.1.8-fixed)  

---

### [CVE-2013-0156](CVE-2013-0156-bsodmike_rails-exploit-cve-2013-0156.md) 🔴 ✅

**名称:** CVE-2013-0156 - Ruby on Rails 对象注入/远程代码执行  
**类型:** 对象注入/远程代码执行  
**风险:** 高危，可能导致远程代码执行和拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-11-10  
**POC仓库:** [rails-exploit-cve-2013-0156](https://github.com/bsodmike/rails-exploit-cve-2013-0156)  

---

### [CVE-2013-0156](CVE-2013-0156-Jjdt12_kuang_grade_mk11.md) 🔴 ✅

**名称:** CVE-2013-0156-Rails-XML参数处理对象注入  
**类型:** 对象注入/代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-11-10  
**POC仓库:** [kuang_grade_mk11](https://github.com/Jjdt12/kuang_grade_mk11)  

---

### [CVE-2023-51444](CVE-2023-51444-iPlayForSG_CVE-2023-51444.md) 🔴 

**名称:** CVE-2023-51444-GeoServer-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可导致远程代码执行和权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-11-10  
**POC仓库:** [CVE-2023-51444](https://github.com/iPlayForSG/CVE-2023-51444)  

---

### [CVE-2025-34299](CVE-2025-34299-crondenice_CVE-2025-34299.md) 🔴 ✅

**名称:** CVE-2025-34299-Monsta FTP-未授权任意文件上传  
**类型:** 未授权任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-10  
**POC仓库:** [CVE-2025-34299](https://github.com/crondenice/CVE-2025-34299)  

---

### [CVE-2025-64495](CVE-2025-64495-AlphabugX_CVE-2025-64495-POC.md) 🔴 ✅

**名称:** CVE-2025-64495-Open WebUI-Stored DOM XSS  
**类型:** Stored DOM XSS  
**风险:** 高危，可能导致账户接管 (ATO) 和远程代码执行 (RCE)  
**投毒风险:** 10%  
**发现时间:** 2025-11-10  
**POC仓库:** [CVE-2025-64495-POC](https://github.com/AlphabugX/CVE-2025-64495-POC)  

---

### [CVE-2018-25031](CVE-2018-25031-RelicHunt3r_swagger-ui.md) 🟡 ✅

**名称:** CVE-2018-25031-Swagger UI-远程OpenAPI定义欺骗  
**类型:** 欺骗/XSS/SSRF  
**风险:** 中危，可能导致信息泄露、会话劫持和服务器端请求伪造  
**投毒风险:** 20%  
**发现时间:** 2025-11-10  
**POC仓库:** [swagger-ui](https://github.com/RelicHunt3r/swagger-ui)  

---

### [CVE-2018-25031](CVE-2018-25031-labeebSabbah_CVE-2018-25031.md) 🟡 ✅

**名称:** CVE-2018-25031-SwaggerUI-欺骗攻击  
**类型:** 欺骗攻击/信息泄露/SSRF  
**风险:** 中危，可能导致信息泄露和潜在的中间人攻击  
**投毒风险:** 0%  
**发现时间:** 2025-11-10  
**POC仓库:** [CVE-2018-25031](https://github.com/labeebSabbah/CVE-2018-25031)  

---

### [CVE-2021-4374](CVE-2021-4374-Pranjal6955_CVE-2021-4374-Testing-Package.md) 🔴 ✅

**名称:** CVE-2021-4374 - WordPress Automatic Plugin - 任意选项更新  
**类型:** Broken Access Control / 权限绕过  
**风险:** 高危，未经身份验证的攻击者可以修改任意WordPress选项，从而完全控制站点  
**投毒风险:** 5%  
**发现时间:** 2025-11-10  
**POC仓库:** [CVE-2021-4374-Testing-Package](https://github.com/Pranjal6955/CVE-2021-4374-Testing-Package)  

---

### [CVE-2025-63296](CVE-2025-63296-t4e-3_CVE-2025-63296.md) 🔴 ✅

**名称:** CVE-2025-63296-KERUI K259 5MP Wi-Fi / Tuya Smart Security Camera-代码执行  
**类型:** 代码执行  
**风险:** 高危，可能导致远程代码执行、权限提升、数据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-11-10  
**POC仓库:** [CVE-2025-63296](https://github.com/t4e-3/CVE-2025-63296)  

---

### [CVE-2021-4374](CVE-2021-4374-Pranjal6955_cve-2021-4374-test.md) 🔴 ✅

**名称:** CVE-2021-4374-WordPress Automatic Plugin-任意选项更新  
**类型:** 任意选项更新  
**风险:** 高危，可能导致网站被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-11-09  
**POC仓库:** [cve-2021-4374-test](https://github.com/Pranjal6955/cve-2021-4374-test)  

---

### [CVE-2025-24054](CVE-2025-24054-Wind010_CVE-2025-24054_PoC.md) 🟡 ✅

**名称:** CVE-2025-24054 NTLM Hash Disclosure Spoofing Vulnerability PoC评估  
**类型:** NTLM哈希泄露欺骗漏洞  
**风险:** 中危，可能导致信息泄露和网络欺骗  
**投毒风险:** 10%  
**发现时间:** 2025-11-09  
**POC仓库:** [CVE-2025-24054_PoC](https://github.com/Wind010/CVE-2025-24054_PoC)  

---

### [CVE-2025-48593](CVE-2025-48593-letchupkt_CVE-2025-48593.md)  

**名称:** CVE-2025-48593 - Android System 零点击远程代码执行  
**类型:** 远程代码执行  
**风险:** 严重，可能导致设备完全受控  
**投毒风险:** 10%  
**发现时间:** 2025-11-09  
**POC仓库:** [CVE-2025-48593](https://github.com/letchupkt/CVE-2025-48593)  

---

### [CVE-2025-12917](CVE-2025-12917-0xcucumbersalad_CVE-2025-12917-PoC.md) 🟡 ✅

**名称:** CVE-2025-12917-TOZED ZLT T10-proc_post拒绝服务  
**类型:** 拒绝服务  
**风险:** 中危，导致设备重启  
**投毒风险:** 0%  
**发现时间:** 2025-11-09  
**POC仓库:** [CVE-2025-12917-PoC](https://github.com/0xcucumbersalad/CVE-2025-12917-PoC)  

---

### [CVE-2025-48593](CVE-2025-48593-callinston_CVE-2025-48593.md) 🔴 ✅

**名称:** CVE-2025-48593 Android Kernel RCE  
**类型:** 远程代码执行  
**风险:** 高危，可完全控制设备  
**投毒风险:** 60%  
**发现时间:** 2025-11-09  
**POC仓库:** [CVE-2025-48593](https://github.com/callinston/CVE-2025-48593)  

---

### [CVE-2025-41067](CVE-2025-41067-xvk1t1_Open5GS-CVE-2025-41067-CVE-2025-41068-PoC.md) 🔴 ✅

**名称:** CVE-2025-41067-Open5GS-NRF拒绝服务  
**类型:** 拒绝服务  
**风险:** 高危，导致服务不可用  
**投毒风险:** 5%  
**发现时间:** 2025-11-09  
**POC仓库:** [Open5GS-CVE-2025-41067-CVE-2025-41068-PoC](https://github.com/xvk1t1/Open5GS-CVE-2025-41067-CVE-2025-41068-PoC)  

---

### [CVE-2022-29800](CVE-2022-29800-ngtuonghung_nimbuspwn-CVE-2022-29800-CVE-2022-29799.md) 🟡 ✅

**名称:** CVE-2022-29800 - networkd-dispatcher TOCTOU 竞争条件漏洞  
**类型:** TOCTOU 竞争条件  
**风险:** 中危，可能导致权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-11-09  
**POC仓库:** [nimbuspwn-CVE-2022-29800-CVE-2022-29799](https://github.com/ngtuonghung/nimbuspwn-CVE-2022-29800-CVE-2022-29799)  

---

### [CVE-2021-40438](CVE-2021-40438-Kashkovsky_CVE-2021-40438.md) 🔴 ✅

**名称:** CVE-2021-40438-Apache mod_proxy SSRF  
**类型:** SSRF (服务器端请求伪造)  
**风险:** 高危，可能导致内部网络探测、敏感信息泄露，甚至远程代码执行（取决于内部网络配置）  
**投毒风险:** 10%  
**发现时间:** 2025-11-09  
**POC仓库:** [CVE-2021-40438](https://github.com/Kashkovsky/CVE-2021-40438)  

---

### [CVE-2021-40438](CVE-2021-40438-yakir2b_check-point-gateways-rce.md) 🔴 ✅

**名称:** CVE-2021-40438 - Apache HTTP Server mod_proxy SSRF  
**类型:** 服务器端请求伪造 (SSRF)  
**风险:** 高危，允许攻击者将请求转发到由远程用户选择的源服务器，可能导致敏感信息泄露，内部服务访问，甚至远程代码执行（如果内部服务存在其他漏洞）。  
**投毒风险:** 5%  
**发现时间:** 2025-11-09  
**POC仓库:** [check-point-gateways-rce](https://github.com/yakir2b/check-point-gateways-rce)  

---

### [CVE-2021-40438](CVE-2021-40438-xiaojiangxl_CVE-2021-40438.md) 🔴 ✅

**名称:** CVE-2021-40438-Apache HTTP Server-SSRF  
**类型:** 服务器端请求伪造 (SSRF)  
**风险:** 高危，可能导致内部信息泄露、敏感操作或利用内部服务进行攻击  
**投毒风险:** 0%  
**发现时间:** 2025-11-09  
**POC仓库:** [CVE-2021-40438](https://github.com/xiaojiangxl/CVE-2021-40438)  

---

### [CVE-2021-40438](CVE-2021-40438-sixpacksecurity_CVE-2021-40438.md) 🔴 ✅

**名称:** CVE-2021-40438-Apache HTTP Server-SSRF  
**类型:** SSRF  
**风险:** 高危，可能导致内网信息泄露和任意请求伪造  
**投毒风险:** 10%  
**发现时间:** 2025-11-09  
**POC仓库:** [CVE-2021-40438](https://github.com/sixpacksecurity/CVE-2021-40438)  

---

### [CVE-2021-40438](CVE-2021-40438-BabyTeam1024_CVE-2021-40438.md) 🔴 ✅

**名称:** CVE-2021-40438-Apache HTTP Server-SSRF  
**类型:** 服务器端请求伪造 (SSRF)  
**风险:** 高危，可能导致内网信息泄露、攻击内网服务、甚至远程代码执行（取决于内网服务）。  
**投毒风险:** 10%  
**发现时间:** 2025-11-09  
**POC仓库:** [CVE-2021-40438](https://github.com/BabyTeam1024/CVE-2021-40438)  

---

### [CVE-2021-40438](CVE-2021-40438-ericmann_apache-cve-poc.md) 🔴 ✅

**名称:** CVE-2021-40438 - Apache mod_proxy SSRF  
**类型:** SSRF (Server Side Request Forgery)  
**风险:** 高危，可能导致敏感信息泄露、内部网络探测、甚至远程代码执行（取决于内部系统的配置）  
**投毒风险:** 10%  
**发现时间:** 2025-11-09  
**POC仓库:** [apache-cve-poc](https://github.com/ericmann/apache-cve-poc)  

---

### [CVE-2021-40438](CVE-2021-40438-pisut4152_Sigma-Rule-for-CVE-2021-40438-exploitation-attempt.md) 🔴 ✅

**名称:** CVE-2021-40438 - Apache mod_proxy SSRF  
**类型:** 服务器端请求伪造 (SSRF)  
**风险:** 高危，允许攻击者控制代理服务器请求的目标，可能导致内部信息泄露、内网服务攻击。  
**投毒风险:** 1%  
**发现时间:** 2025-11-09  
**POC仓库:** [Sigma-Rule-for-CVE-2021-40438-exploitation-attempt](https://github.com/pisut4152/Sigma-Rule-for-CVE-2021-40438-exploitation-attempt)  

---

### [CVE-2021-40438](CVE-2021-40438-gassara-kys_CVE-2021-40438.md) 🔴 ✅

**名称:** CVE-2021-40438 - Apache HTTP Server mod_proxy SSRF  
**类型:** 服务器端请求伪造 (SSRF)  
**风险:** 高危，可能导致内部信息泄露、远程命令执行（取决于内部网络配置）  
**投毒风险:** 10%  
**发现时间:** 2025-11-09  
**POC仓库:** [CVE-2021-40438](https://github.com/gassara-kys/CVE-2021-40438)  

---

### [CVE-2021-40438](CVE-2021-40438-sergiovks_CVE-2021-40438-Apache-2.4.48-SSRF-exploit.md) 🔴 ✅

**名称:** CVE-2021-40438 - Apache HTTP Server mod_proxy SSRF  
**类型:** 服务器端请求伪造 (SSRF)  
**风险:** 高危，可能导致敏感信息泄露、内部服务访问和远程代码执行 (取决于内部服务的配置)  
**投毒风险:** 10%  
**发现时间:** 2025-11-09  
**POC仓库:** [CVE-2021-40438-Apache-2.4.48-SSRF-exploit](https://github.com/sergiovks/CVE-2021-40438-Apache-2.4.48-SSRF-exploit)  

---

### [CVE-2021-40438](CVE-2021-40438-Cappricio-Securities_CVE-2021-40438.md) 🔴 ✅

**名称:** CVE-2021-40438 - Apache HTTP Server mod_proxy SSRF  
**类型:** 服务器端请求伪造 (SSRF)  
**风险:** 高危，可能导致内部服务访问、敏感信息泄露、甚至远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-09  
**POC仓库:** [CVE-2021-40438](https://github.com/Cappricio-Securities/CVE-2021-40438)  

---

### [CVE-2021-40438](CVE-2021-40438-n0m-d_CVE-2021-40438-POC.md) 🔴 ✅

**名称:** CVE-2021-40438 - Apache HTTP Server mod_proxy SSRF  
**类型:** 服务器端请求伪造 (SSRF)  
**风险:** 高危，可能导致内部服务信息泄露、内网扫描甚至远程代码执行 (取决于内部服务的配置)  
**投毒风险:** 0%  
**发现时间:** 2025-11-09  
**POC仓库:** [CVE-2021-40438-POC](https://github.com/n0m-d/CVE-2021-40438-POC)  

---

### [CVE-2022-0324](CVE-2022-0324-ngtuonghung_cve-2022-0324.md) 🔴 ✅

**名称:** CVE-2022-0324 - SONiC dhcp6relay 缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致dhcp6relay崩溃，影响网络服务  
**投毒风险:** 0%  
**发现时间:** 2025-11-09  
**POC仓库:** [cve-2022-0324](https://github.com/ngtuonghung/cve-2022-0324)  

---

### [CVE-2025-12907](CVE-2025-12907-DExplo1ted_CVE-2025-12907-Exploit.md) 🔴 ✅

**名称:** CVE-2025-12907 - Chrome DevTools RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许远程攻击者执行任意代码  
**投毒风险:** 30%  
**发现时间:** 2025-11-08  
**POC仓库:** [CVE-2025-12907-Exploit](https://github.com/DExplo1ted/CVE-2025-12907-Exploit)  

---

### [CVE-2025-12907](CVE-2025-12907-lagerhaker539_CVE-2025-12907-POC.md) 🔴 ✅

**名称:** CVE-2025-12907-Google Chrome DevTools Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，攻击者可以通过 Chrome DevTools 执行任意代码。  
**投毒风险:** 20%  
**发现时间:** 2025-11-08  
**POC仓库:** [CVE-2025-12907-POC](https://github.com/lagerhaker539/CVE-2025-12907-POC)  

---

### [CVE-2025-61922](CVE-2025-61922-captaincookie34_Vulnerability-Playground-CVE-2025-61922.md) 🔴 ✅

**名称:** CVE-2025-61922-PrestaShop-Checkout-Account-Takeover  
**类型:** 账户接管  
**风险:** 高危，可能导致账户接管，敏感信息泄露和未授权操作  
**投毒风险:** 10%  
**发现时间:** 2025-11-08  
**POC仓库:** [Vulnerability-Playground-CVE-2025-61922](https://github.com/captaincookie34/Vulnerability-Playground-CVE-2025-61922)  

---

### [CVE-2025-48593](CVE-2025-48593-logesh-GIT001_CVE-2025-48593.md) 🔴 ✅

**名称:** CVE-2025-48593-Android系统远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致设备完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-11-08  
**POC仓库:** [CVE-2025-48593](https://github.com/logesh-GIT001/CVE-2025-48593)  

---

### [CVE-2025-48384](CVE-2025-48384-bummie_CVE-2025-48384-submodule.md) 🔴 ✅

**名称:** CVE-2025-48384-git-代码执行  
**类型:** 代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-08  
**POC仓库:** [CVE-2025-48384-submodule](https://github.com/bummie/CVE-2025-48384-submodule)  

---

### [CVE-2019-18634](CVE-2019-18634-letsr00t_-CVE-2019-18634-sudo-pwfeedback.md) 🔴 ✅

**名称:** CVE-2019-18634-sudo-pwfeedback缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致提权和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-11-08  
**POC仓库:** [-CVE-2019-18634-sudo-pwfeedback](https://github.com/letsr00t/-CVE-2019-18634-sudo-pwfeedback)  

---

### [CVE-2023-45612](CVE-2023-45612-razvanclaudiu_Ktor-XXE-PoC.md) 🔴 ✅

**名称:** CVE-2023-45612-JetBrains Ktor XXE  
**类型:** XXE  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-11-08  
**POC仓库:** [Ktor-XXE-PoC](https://github.com/razvanclaudiu/Ktor-XXE-PoC)  

---

### [CVE-2025-51970](CVE-2025-51970-MMAKINGDOM_CVE-2025-51970.md) 🔴 ✅

**名称:** CVE-2025-51970-Online Shopping System Advanced-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、数据篡改和权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-11-08  
**POC仓库:** [CVE-2025-51970](https://github.com/MMAKINGDOM/CVE-2025-51970)  

---

### [CVE-2025-21042](CVE-2025-21042-usjnx72726w_CVE-2025-21042.md) 🔴 ✅

**名称:** CVE-2025-21042 - Samsung Mobile libimagecodec.quram.so Out-of-bounds Write  
**类型:** Out-of-bounds Write  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 20%  
**发现时间:** 2025-11-08  
**POC仓库:** [CVE-2025-21042](https://github.com/usjnx72726w/CVE-2025-21042)  

---

### [CVE-2025-21042](CVE-2025-21042-B1ack4sh_Blackash-CVE-2025-21042.md) 🔴 ✅

**名称:** CVE-2025-21042-Samsung-libimagecodec.quram.so-Out-of-bounds Write  
**类型:** Out-of-bounds Write  
**风险:** 高危，远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-11-08  
**POC仓库:** [Blackash-CVE-2025-21042](https://github.com/B1ack4sh/Blackash-CVE-2025-21042)  

---

### [CVE-2025-8088](CVE-2025-8088-shourout_CVE-2025-8088.md) 🔴 ✅

**名称:** CVE-2025-8088 WinRAR 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 30%  
**发现时间:** 2025-11-08  
**POC仓库:** [CVE-2025-8088](https://github.com/shourout/CVE-2025-8088)  

---

### [CVE-2025-32433](CVE-2025-32433-l1nuxkid_CVE-2025-32433-exploit.md)  ✅

**名称:** CVE-2025-32433-Erlang/OTP-SSH 预认证RCE  
**类型:** 预认证远程代码执行 (RCE)  
**风险:** 严重，未经身份验证的攻击者可以在受影响的系统上执行任意代码。  
**投毒风险:** 0%  
**发现时间:** 2025-11-08  
**POC仓库:** [CVE-2025-32433-exploit](https://github.com/l1nuxkid/CVE-2025-32433-exploit)  

---

### [CVE-2025-11749](CVE-2025-11749-Nxploited_CVE-2025-11749.md) 🔴 ✅

**名称:** CVE-2025-11749-AI Engine-敏感信息泄露导致权限提升  
**类型:** 敏感信息泄露  
**风险:** 高危，可能导致敏感信息泄露和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-11-08  
**POC仓库:** [CVE-2025-11749](https://github.com/Nxploited/CVE-2025-11749)  

---

### [CVE-2023-45612](CVE-2023-45612-stefan-500_ktor-cve-2023-45612-poc.md) 🔴 ✅

**名称:** CVE-2023-45612-Ktor-XXE  
**类型:** XXE  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-11-07  
**POC仓库:** [ktor-cve-2023-45612-poc](https://github.com/stefan-500/ktor-cve-2023-45612-poc)  

---

### [CVE-2023-5359](CVE-2023-5359-spyata123_Cleartext-Storage-vulnerability-CVE-2023-5359-in-W3-Total-Cache.md) 🟡 ✅

**名称:** CVE-2023-5359-W3 Total Cache-敏感信息泄露  
**类型:** 敏感信息泄露  
**风险:** 中危，可能导致未授权访问和账户信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-11-07  
**POC仓库:** [Cleartext-Storage-vulnerability-CVE-2023-5359-in-W3-Total-Cache](https://github.com/spyata123/Cleartext-Storage-vulnerability-CVE-2023-5359-in-W3-Total-Cache)  

---

### [CVE-2023-5359](CVE-2023-5359-enzocipher_CVE-2023-5359.md) 🟡 ✅

**名称:** CVE-2023-5359 - W3 Total Cache Sensitive Information Exposure  
**类型:** 敏感信息泄露  
**风险:** 中危，可能导致账户信息泄露以及服务被控制  
**投毒风险:** 5%  
**发现时间:** 2025-11-07  
**POC仓库:** [CVE-2023-5359](https://github.com/enzocipher/CVE-2023-5359)  

---

### [CVE-2023-45612](CVE-2023-45612-seraphimi_ktor-xxe.md) 🔴 ✅

**名称:** CVE-2023-45612-Ktor-XXE  
**类型:** XXE  
**风险:** 高危，可能导致信息泄露、SSRF  
**投毒风险:** 1%  
**发现时间:** 2025-11-07  
**POC仓库:** [ktor-xxe](https://github.com/seraphimi/ktor-xxe)  

---

### [CVE-2023-45612](CVE-2023-45612-ksaweryr_CVE-2023-45612-PoC.md) 🔴 ✅

**名称:** CVE-2023-45612-Ktor-XXE  
**类型:** XXE  
**风险:** 高危，可能导致信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-11-07  
**POC仓库:** [CVE-2023-45612-PoC](https://github.com/ksaweryr/CVE-2023-45612-PoC)  

---

### [CVE-2017-12615](CVE-2017-12615-Fa1c0n35_CVE-2017-12615.md) 🔴 ✅

**名称:** CVE-2017-12615-Apache Tomcat-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-11-07  
**POC仓库:** [CVE-2017-12615](https://github.com/Fa1c0n35/CVE-2017-12615)  

---

### [CVE-2025-60574](CVE-2025-60574-jacopoaugelli_CVE-2025-60574.md) 🔴 ✅

**名称:** CVE-2025-60574-tQuadra CMS-LFI  
**类型:** LFI  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-11-07  
**POC仓库:** [CVE-2025-60574](https://github.com/jacopoaugelli/CVE-2025-60574)  

---

### [CVE-2025-63420](CVE-2025-63420-MMAKINGDOM_CVE-2025-63420.md) 🟡 ✅

**名称:** CVE-2025-63420-CrushFTP11-存储型HTML注入  
**类型:** 存储型HTML注入 (Stored HTML Injection)  
**风险:** 中危，可能导致管理员会话中的持久性HTML执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-07  
**POC仓库:** [CVE-2025-63420](https://github.com/MMAKINGDOM/CVE-2025-63420)  

---

### [CVE-2025-9491](CVE-2025-9491-Amperclock_CVE-2025-9491_POC.md) 🔴 ✅

**名称:** CVE-2025-9491 Microsoft Windows LNK 文件 UI 误导远程代码执行漏洞  
**类型:** UI 误导/远程代码执行  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-07  
**POC仓库:** [CVE-2025-9491_POC](https://github.com/Amperclock/CVE-2025-9491_POC)  

---

### [CVE-2025-20343](CVE-2025-20343-B1ack4sh_Blackash-CVE-2025-20343.md) 🔴 ✅

**名称:** CVE-2025-20343-Cisco ISE-RADIUS拒绝服务  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，导致服务中断  
**投毒风险:** 0%  
**发现时间:** 2025-11-07  
**POC仓库:** [Blackash-CVE-2025-20343](https://github.com/B1ack4sh/Blackash-CVE-2025-20343)  

---

### [CVE-2020-5902](CVE-2020-5902-MrCl0wnLab_checker-CVE-2020-5902.md) 🔴 ✅

**名称:** CVE-2020-5902-F5 BIG-IP-TMUI-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-11-07  
**POC仓库:** [checker-CVE-2020-5902](https://github.com/MrCl0wnLab/checker-CVE-2020-5902)  

---

### [CVE-2020-5902](CVE-2020-5902-GovindPalakkal_EvilRip.md) 🔴 ✅

**名称:** CVE-2020-5902-F5 BIG-IP TMUI RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致完全控制受影响的BIG-IP系统  
**投毒风险:** 10%  
**发现时间:** 2025-11-07  
**POC仓库:** [EvilRip](https://github.com/GovindPalakkal/EvilRip)  

---

### [CVE-2020-5902](CVE-2020-5902-d4rk007_F5-Big-IP-CVE-2020-5902-mass-exploiter.md) 🔴 ✅

**名称:** CVE-2020-5902-F5 Big-IP TMUI 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的攻击者可以远程执行任意代码，完全控制受影响的系统。  
**投毒风险:** 5%  
**发现时间:** 2025-11-07  
**POC仓库:** [F5-Big-IP-CVE-2020-5902-mass-exploiter](https://github.com/d4rk007/F5-Big-IP-CVE-2020-5902-mass-exploiter)  

---

### [CVE-2020-5902](CVE-2020-5902-Al1ex_CVE-2020-5902.md)  ✅

**名称:** CVE-2020-5902-F5 BIG-IP TMUI 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，未经身份验证的攻击者可以执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-11-07  
**POC仓库:** [CVE-2020-5902](https://github.com/Al1ex/CVE-2020-5902)  

---

### [CVE-2020-5902](CVE-2020-5902-theLSA_f5-bigip-rce-cve-2020-5902.md)  ✅

**名称:** CVE-2020-5902 - F5 BIG-IP TMUI 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，未经身份验证的攻击者可以执行任意系统命令，完全控制受影响的系统。  
**投毒风险:** 1%  
**发现时间:** 2025-11-07  
**POC仓库:** [f5-bigip-rce-cve-2020-5902](https://github.com/theLSA/f5-bigip-rce-cve-2020-5902)  

---

### [CVE-2020-5902](CVE-2020-5902-momika233_cve-2020-5902.md)  ✅

**名称:** CVE-2020-5902 - F5 BIG-IP TMUI RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可导致完全系统控制  
**投毒风险:** 5%  
**发现时间:** 2025-11-07  
**POC仓库:** [cve-2020-5902](https://github.com/momika233/cve-2020-5902)  

---

### [CVE-2020-5902](CVE-2020-5902-dnerzker_CVE-2020-5902.md) 🔴 ✅

**名称:** CVE-2020-5902-F5 BIG-IP TMUI RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致完全控制目标系统  
**投毒风险:** 5%  
**发现时间:** 2025-11-07  
**POC仓库:** [CVE-2020-5902](https://github.com/dnerzker/CVE-2020-5902)  

---

### [CVE-2020-5902](CVE-2020-5902-rockmelodies_CVE-2020-5902-rce-gui.md) 🔴 ✅

**名称:** CVE-2020-5902-F5 BIG-IP TMUI 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可完全控制受影响的 BIG-IP 设备  
**投毒风险:** 50%  
**发现时间:** 2025-11-07  
**POC仓库:** [CVE-2020-5902-rce-gui](https://github.com/rockmelodies/CVE-2020-5902-rce-gui)  

---

### [CVE-2020-5902](CVE-2020-5902-TheCyberViking_CVE-2020-5902-Vuln-Checker.md) 🔴 ✅

**名称:** CVE-2020-5902 F5 BIG-IP TMUI 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的攻击者执行任意代码。  
**投毒风险:** 5%  
**发现时间:** 2025-11-07  
**POC仓库:** [CVE-2020-5902-Vuln-Checker](https://github.com/TheCyberViking/CVE-2020-5902-Vuln-Checker)  

---

### [CVE-2020-5902](CVE-2020-5902-halencarjunior_f5scan.md) 🔴 ✅

**名称:** CVE-2020-5902-F5 BIG-IP TMUI RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的攻击者在设备上执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-11-07  
**POC仓库:** [f5scan](https://github.com/halencarjunior/f5scan)  

---

### [CVE-2020-5902](CVE-2020-5902-superzerosec_cve-2020-5902.md)  ✅

**名称:** CVE-2020-5902-F5 BIG-IP TMUI-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致完全系统控制  
**投毒风险:** 0%  
**发现时间:** 2025-11-07  
**POC仓库:** [cve-2020-5902](https://github.com/superzerosec/cve-2020-5902)  

---

### [CVE-2020-5902](CVE-2020-5902-f5devcentral_cve-2020-5902-ioc-bigip-checker.md) 🔴 ✅

**名称:** CVE-2020-5902 - F5 BIG-IP TMUI 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经授权的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-07  
**POC仓库:** [cve-2020-5902-ioc-bigip-checker](https://github.com/f5devcentral/cve-2020-5902-ioc-bigip-checker)  

---

### [CVE-2020-5902](CVE-2020-5902-murataydemir_CVE-2020-5902.md) 🔴 ✅

**名称:** CVE-2020-5902 F5 BIG-IP TMUI 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致完全系统控制  
**投毒风险:** 0%  
**发现时间:** 2025-11-07  
**POC仓库:** [CVE-2020-5902](https://github.com/murataydemir/CVE-2020-5902)  

---

### [CVE-2020-5902](CVE-2020-5902-ludy-dev_BIG-IP-F5-TMUI-RCE-Vulnerability.md) 🔴 ✅

**名称:** CVE-2020-5902 F5 BIG-IP TMUI 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致完全控制受影响的BIG-IP系统。  
**投毒风险:** 0%  
**发现时间:** 2025-11-07  
**POC仓库:** [BIG-IP-F5-TMUI-RCE-Vulnerability](https://github.com/ludy-dev/BIG-IP-F5-TMUI-RCE-Vulnerability)  

---

### [CVE-2020-5902](CVE-2020-5902-corelight_CVE-2020-5902-F5BigIP.md) 🔴 ✅

**名称:** CVE-2020-5902-F5 BIG-IP TMUI 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致完全系统控制  
**投毒风险:** 0%  
**发现时间:** 2025-11-07  
**POC仓库:** [CVE-2020-5902-F5BigIP](https://github.com/corelight/CVE-2020-5902-F5BigIP)  

---

### [CVE-2020-5902](CVE-2020-5902-faisalfs10x_F5-BIG-IP-CVE-2020-5902-shodan-scanner.md) 🔴 ✅

**名称:** CVE-2020-5902 F5 BIG-IP TMUI RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-11-07  
**POC仓库:** [F5-BIG-IP-CVE-2020-5902-shodan-scanner](https://github.com/faisalfs10x/F5-BIG-IP-CVE-2020-5902-shodan-scanner)  

---

### [CVE-2020-5902](CVE-2020-5902-haisenberg_CVE-2020-5902.md) 🔴 ✅

**名称:** CVE-2020-5902-F5 BIG-IP-TMUI 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致完全控制受影响的 F5 BIG-IP 设备  
**投毒风险:** 5%  
**发现时间:** 2025-11-07  
**POC仓库:** [CVE-2020-5902](https://github.com/haisenberg/CVE-2020-5902)  

---

### [CVE-2020-5902](CVE-2020-5902-jas502n_CVE-2020-5902.md) 🔴 ✅

**名称:** CVE-2020-5902-F5 BIG-IP TMUI-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致完全控制系统  
**投毒风险:** 0%  
**发现时间:** 2025-11-07  
**POC仓库:** [CVE-2020-5902](https://github.com/jas502n/CVE-2020-5902)  

---

### [CVE-2020-5902](CVE-2020-5902-PushpenderIndia_CVE-2020-5902-Scanner.md) 🔴 ✅

**名称:** CVE-2020-5902 - F5 BIG-IP TMUI 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-11-07  
**POC仓库:** [CVE-2020-5902-Scanner](https://github.com/PushpenderIndia/CVE-2020-5902-Scanner)  

---

### [CVE-2020-5902](CVE-2020-5902-z3n70_CVE-2020-5902.md) 🔴 ✅

**名称:** CVE-2020-5902-F5 BIG-IP TMUI 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致完全系统控制  
**投毒风险:** 5%  
**发现时间:** 2025-11-07  
**POC仓库:** [CVE-2020-5902](https://github.com/z3n70/CVE-2020-5902)  

---

### [CVE-2020-5902](CVE-2020-5902-west9b_F5-BIG-IP-POC.md) 🔴 ✅

**名称:** CVE-2020-5902/CVE-2021-22986/CVE-2022-1388 - F5 BIG-IP TMUI 远程代码执行/命令执行/身份验证绕过  
**类型:** 远程代码执行/命令执行/身份验证绕过  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-11-07  
**POC仓库:** [F5-BIG-IP-POC](https://github.com/west9b/F5-BIG-IP-POC)  

---

### [CVE-2020-5902](CVE-2020-5902-aqhmal_CVE-2020-5902-Scanner.md) 🔴 ✅

**名称:** CVE-2020-5902-F5 BIG-IP-TMUI远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致完全控制受影响的F5 BIG-IP设备  
**投毒风险:** 0%  
**发现时间:** 2025-11-07  
**POC仓库:** [CVE-2020-5902-Scanner](https://github.com/aqhmal/CVE-2020-5902-Scanner)  

---

### [CVE-2020-5902](CVE-2020-5902-amitlttwo_CVE-2020-5902.md) 🔴 ✅

**名称:** CVE-2020-5902 - F5 BIG-IP TMUI 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致完全控制受影响的BIG-IP设备  
**投毒风险:** 10%  
**发现时间:** 2025-11-07  
**POC仓库:** [CVE-2020-5902](https://github.com/amitlttwo/CVE-2020-5902)  

---

### [CVE-2020-5902](CVE-2020-5902-yasserjanah_CVE-2020-5902.md) 🔴 ✅

**名称:** CVE-2020-5902-F5 BIG-IP TMUI 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致完全控制受影响的系统  
**投毒风险:** 0%  
**发现时间:** 2025-11-07  
**POC仓库:** [CVE-2020-5902](https://github.com/yasserjanah/CVE-2020-5902)  

---

### [CVE-2020-5902](CVE-2020-5902-dunderhay_CVE-2020-5902.md) 🔴 ✅

**名称:** CVE-2020-5902-F5 Big-IP-TMUI远程代码执行  
**类型:** 远程代码执行(RCE)  
**风险:** 高危，未经授权的攻击者可以通过发送特制的HTTP请求执行任意系统命令，导致系统完全被控制。  
**投毒风险:** 0%  
**发现时间:** 2025-11-07  
**POC仓库:** [CVE-2020-5902](https://github.com/dunderhay/CVE-2020-5902)  

---

### [CVE-2020-5902](CVE-2020-5902-cristiano-corrado_f5_scanner.md) 🔴 ✅

**名称:** CVE-2020-5902-F5 BIG-IP-远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经授权的远程代码执行，可能导致系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-11-07  
**POC仓库:** [f5_scanner](https://github.com/cristiano-corrado/f5_scanner)  

---

### [CVE-2020-5902](CVE-2020-5902-B1ack4sh_Blackash-CVE-2020-5902.md) 🔴 ✅

**名称:** CVE-2020-5902 F5 BIG-IP TMUI 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致系统完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-11-07  
**POC仓库:** [Blackash-CVE-2020-5902](https://github.com/B1ack4sh/Blackash-CVE-2020-5902)  

---

### [CVE-2025-61299](CVE-2025-61299-GovindPalakkal_CVE-2025-61299_POC.md) 🔴 ✅

**名称:** CVE-2025-61299 - Nagios XI 2024R1 - 认证后的命令注入  
**类型:** 命令注入  
**风险:** 高危，允许认证后的攻击者执行任意系统命令  
**投毒风险:** 10%  
**发现时间:** 2025-11-07  
**POC仓库:** [CVE-2025-61299_POC](https://github.com/GovindPalakkal/CVE-2025-61299_POC)  

---

### [CVE-2025-63585](CVE-2025-63585-Kgan0509_CVE-2025-63585.md) 🟡 ✅

**名称:** CVE-2025-63585-OSSN-SQL注入  
**类型:** SQL注入  
**风险:** 中危，可能导致数据泄露和数据篡改  
**投毒风险:** 5%  
**发现时间:** 2025-11-07  
**POC仓库:** [CVE-2025-63585](https://github.com/Kgan0509/CVE-2025-63585)  

---

### [CVE-2025-63441](CVE-2025-63441-Kgan0509_CVE-2025-63441.md) 🔴 ✅

**名称:** CVE-2025-63441-Open Source Social Network-XSS  
**类型:** 跨站脚本攻击(XSS)  
**风险:** 高危，可能导致敏感信息泄露、会话劫持、恶意重定向等  
**投毒风险:** 0%  
**发现时间:** 2025-11-07  
**POC仓库:** [CVE-2025-63441](https://github.com/Kgan0509/CVE-2025-63441)  

---

### [CVE-2025-20354](CVE-2025-20354-B1ack4sh_Blackash-CVE-2025-20354.md)  ✅

**名称:** CVE-2025-20354 — Cisco Unified Contact Center Express (CCX) RCE Vulnerability  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，未经身份验证的远程攻击者可以 root 权限执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-11-06  
**POC仓库:** [Blackash-CVE-2025-20354](https://github.com/B1ack4sh/Blackash-CVE-2025-20354)  

---

### [CVE-2023-44487](CVE-2023-44487-madhusudhan-in_CVE_2023_44487-Rapid_Reset.md) 🔴 ✅

**名称:** CVE-2023-44487 HTTP/2 Rapid Reset DDoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致服务器资源耗尽，服务不可用  
**投毒风险:** 1%  
**发现时间:** 2025-11-06  
**POC仓库:** [CVE_2023_44487-Rapid_Reset](https://github.com/madhusudhan-in/CVE_2023_44487-Rapid_Reset)  

---

### [CVE-2025-64095](CVE-2025-64095-h4x0r-dz_CVE-2025-64095---DNN-Unauthenticated-arbitrary-file-upload.md) 🔴 ✅

**名称:** CVE-2025-64095 - DNN Unauthenticated Arbitrary File Upload  
**类型:** 任意文件上传  
**风险:** 高危，允许未授权的文件上传和站点内容覆盖  
**投毒风险:** 5%  
**发现时间:** 2025-11-06  
**POC仓库:** [CVE-2025-64095---DNN-Unauthenticated-arbitrary-file-upload](https://github.com/h4x0r-dz/CVE-2025-64095---DNN-Unauthenticated-arbitrary-file-upload)  

---

### [CVE-2025-64095](CVE-2025-64095-NationalServices_CVE-2025-64095-DotNetNuke-DNN_PoC.md) 🔴 ✅

**名称:** CVE-2025-64095-DNN-文件上传导致站点内容覆盖  
**类型:** 文件上传  
**风险:** 高危，可能导致网站被篡改、XSS攻击、甚至远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-06  
**POC仓库:** [CVE-2025-64095-DotNetNuke-DNN_PoC](https://github.com/NationalServices/CVE-2025-64095-DotNetNuke-DNN_PoC)  

---

### [CVE-2025-56643](CVE-2025-56643-0xBS0D27_CVE-2025-56643.md) 🟡 ✅

**名称:** CVE-2025-56643-Wiki.js-JWT Session Vulnerability  
**类型:** JWT会话管理漏洞  
**风险:** 中危，可能导致未授权访问  
**投毒风险:** 10%  
**发现时间:** 2025-11-06  
**POC仓库:** [CVE-2025-56643](https://github.com/0xBS0D27/CVE-2025-56643)  

---

### [CVE-2025-20354](CVE-2025-20354-allinsthon_CVE-2025-20354.md) 🔴 ✅

**名称:** CVE-2025-20354-Cisco Unified Contact Center Express-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致系统完全控制  
**投毒风险:** 30%  
**发现时间:** 2025-11-06  
**POC仓库:** [CVE-2025-20354](https://github.com/allinsthon/CVE-2025-20354)  

---

### [CVE-2024-21413](CVE-2024-21413-gurleen-147_CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability-PoC.md) 🔴 ✅

**名称:** CVE-2024-21413-Microsoft Outlook远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-06  
**POC仓库:** [CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability-PoC](https://github.com/gurleen-147/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability-PoC)  

---

### [CVE-2025-48384](CVE-2025-48384-ceevase_CVE-2025-48384-main.md) 🔴 

**名称:** CVE-2025-48384-Git-任意代码执行  
**类型:** 任意代码执行  
**风险:** 高危，可能导致服务器被控制  
**投毒风险:** 10%  
**发现时间:** 2025-11-06  
**POC仓库:** [CVE-2025-48384-main](https://github.com/ceevase/CVE-2025-48384-main)  

---

### [CVE-2025-48384](CVE-2025-48384-ceevase_CVE-2025-48384-sub.md) 🔴 ✅

**名称:** CVE-2025-48384-Git-任意代码执行  
**类型:** 配置注入/符号链接攻击  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-06  
**POC仓库:** [CVE-2025-48384-sub](https://github.com/ceevase/CVE-2025-48384-sub)  

---

### [CVE-2022-21587](CVE-2022-21587-sahabrifki_CVE-2022-21587-Oracle-EBS-.md) 🔴 ✅

**名称:** CVE-2022-21587-Oracle Web Applications Desktop Integrator-任意文件上传导致RCE  
**类型:** 任意文件上传导致RCE  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-11-06  
**POC仓库:** [CVE-2022-21587-Oracle-EBS-](https://github.com/sahabrifki/CVE-2022-21587-Oracle-EBS-)  

---

### [CVE-2022-21587](CVE-2022-21587-rockmelodies_Oracle-E-BS-CVE-2022-21587-Exploit.md) 🔴 ✅

**名称:** CVE-2022-21587 - Oracle E-Business Suite Unauthenticated Arbitrary File Upload  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行和系统接管  
**投毒风险:** 10%  
**发现时间:** 2025-11-06  
**POC仓库:** [Oracle-E-BS-CVE-2022-21587-Exploit](https://github.com/rockmelodies/Oracle-E-BS-CVE-2022-21587-Exploit)  

---

### [CVE-2022-21587](CVE-2022-21587-hieuminhnv_CVE-2022-21587-POC.md) 🔴 ✅

**名称:** CVE-2022-21587 Oracle Web Applications Desktop Integrator 未授权任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行，控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-11-06  
**POC仓库:** [CVE-2022-21587-POC](https://github.com/hieuminhnv/CVE-2022-21587-POC)  

---

### [CVE-2022-21587](CVE-2022-21587-B1ack4sh_Blackash-CVE-2022-21587.md) 🔴 ✅

**名称:** CVE-2022-21587 - Oracle E-Business Suite Unauthenticated File Upload  
**类型:** 未授权文件上传  
**风险:** 高危，可导致远程代码执行和系统接管  
**投毒风险:** 5%  
**发现时间:** 2025-11-06  
**POC仓库:** [Blackash-CVE-2022-21587](https://github.com/B1ack4sh/Blackash-CVE-2022-21587)  

---

### [CVE-2025-31133](CVE-2025-31133-sahar042_CVE-2025-31133.md) 🔴 ✅

**名称:** CVE-2025-31133 runc maskedPaths 竞态条件漏洞利用  
**类型:** 容器逃逸  
**风险:** 高危，可能导致容器逃逸，获取宿主机权限  
**投毒风险:** 10%  
**发现时间:** 2025-11-06  
**POC仓库:** [CVE-2025-31133](https://github.com/sahar042/CVE-2025-31133)  

---

### [CVE-2025-59287](CVE-2025-59287-crondenice_CVE-2025-59287.md) 🔴 ✅

**名称:** CVE-2025-59287 Windows Server Update Service (WSUS) Remote Code Execution Vulnerability  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-11-06  
**POC仓库:** [CVE-2025-59287](https://github.com/crondenice/CVE-2025-59287)  

---

### [CVE-2025-54236](CVE-2025-54236-amalpvatayam67_day01-sessionreaper-lab.md) 🔴 ✅

**名称:** CVE-2025-54236-Adobe Commerce-不当输入验证导致会话劫持  
**类型:** 不当输入验证  
**风险:** 高危，可能导致会话劫持，信息泄露和完整性破坏  
**投毒风险:** 0%  
**发现时间:** 2025-11-06  
**POC仓库:** [day01-sessionreaper-lab](https://github.com/amalpvatayam67/day01-sessionreaper-lab)  

---

### [CVE-2025-54236](CVE-2025-54236-wubinworks_magento2-session-reaper-patch.md) 🔴 ✅

**名称:** CVE-2025-54236-Adobe Commerce-Improper Input Validation  
**类型:** Improper Input Validation  
**风险:** Critical，可能导致会话劫持  
**投毒风险:** 10%  
**发现时间:** 2025-11-06  
**POC仓库:** [magento2-session-reaper-patch](https://github.com/wubinworks/magento2-session-reaper-patch)  

---

### [CVE-2025-54236](CVE-2025-54236-crondenice_CVE-2025-54236.md)  ✅

**名称:** CVE-2025-54236 - Adobe Commerce Session Takeover and Remote Code Execution  
**类型:** 不当输入验证导致会话劫持和远程代码执行  
**风险:** 严重，未经身份验证的远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-11-06  
**POC仓库:** [CVE-2025-54236](https://github.com/crondenice/CVE-2025-54236)  

---

### [CVE-2025-63334](CVE-2025-63334-B1ack4sh_Blackash-CVE-2025-63334.md) 🔴 ✅

**名称:** CVE-2025-63334-PocketVJ CP-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程攻击者以root权限执行任意命令  
**投毒风险:** 0%  
**发现时间:** 2025-11-06  
**POC仓库:** [Blackash-CVE-2025-63334](https://github.com/B1ack4sh/Blackash-CVE-2025-63334)  

---

### [CVE-2025-64459](CVE-2025-64459-rockmelodies_django_sqli_target_CVE-2025-64459.md) 🔴 

**名称:** CVE-2025-64459-Django-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-06  
**POC仓库:** [django_sqli_target_CVE-2025-64459](https://github.com/rockmelodies/django_sqli_target_CVE-2025-64459)  

---

### [CVE-2025-54782](CVE-2025-54782-DDestinys_CVE-2025-54782.md)  ✅

**名称:** CVE-2025-54782-@nestjs/devtools-integration-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 极高，可能导致完全控制受害者机器  
**投毒风险:** 1%  
**发现时间:** 2025-11-06  
**POC仓库:** [CVE-2025-54782](https://github.com/DDestinys/CVE-2025-54782)  

---

### [CVE-2025-63588](CVE-2025-63588-cybercrewinc_CVE-2025-63588.md) 🟡 ✅

**名称:** CVE-2025-63588 CMSimple_XH Reflected XSS  
**类型:** Reflected XSS  
**风险:** 中危，可能导致客户端代码执行、信息泄露和会话劫持  
**投毒风险:** 0%  
**发现时间:** 2025-11-06  
**POC仓库:** [CVE-2025-63588](https://github.com/cybercrewinc/CVE-2025-63588)  

---

### [CVE-2025-64458](CVE-2025-64458-ch4n3-yoon_CVE-2025-64458-Demo.md) 🔴 ✅

**名称:** CVE-2025-64458 - Django Redirect DoS on Windows  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致服务中断  
**投毒风险:** 0%  
**发现时间:** 2025-11-06  
**POC仓库:** [CVE-2025-64458-Demo](https://github.com/ch4n3-yoon/CVE-2025-64458-Demo)  

---

### [CVE-2024-4040](CVE-2024-4040-juanorts_CrushFTP10-Docker-CVE-2024-4040.md) 🔴 ✅

**名称:** CVE-2024-4040-CrushFTP-服务器端模板注入  
**类型:** 服务器端模板注入  
**风险:** 高危，可能导致任意文件读取，身份验证绕过和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-06  
**POC仓库:** [CrushFTP10-Docker-CVE-2024-4040](https://github.com/juanorts/CrushFTP10-Docker-CVE-2024-4040)  

---

### [CVE-2025-63571](CVE-2025-63571-RRespxwnss_CVE-2025-63571.md) 🔴 ✅

**名称:** ChatGPT SSRF Vulnerability  
**类型:** Server-Side Request Forgery (SSRF)  
**风险:** 高危，可能导致敏感信息泄露、内部服务访问、云元数据窃取  
**投毒风险:** 10%  
**发现时间:** 2025-11-05  
**POC仓库:** [CVE-2025-63571](https://github.com/RRespxwnss/CVE-2025-63571)  

---

### [CVE-2025-9209](CVE-2025-9209-Nxploited_CVE-2025-9209.md) 🔴 ✅

**名称:** CVE-2025-9209 - RestroPress Authentication Bypass via Forged JWT  
**类型:** Authentication Bypass  
**风险:** Critical，未经身份验证的攻击者可以伪造其他用户（包括管理员）的JWT令牌并进行身份验证，从而完全控制受影响的WordPress站点。  
**投毒风险:** 0%  
**发现时间:** 2025-11-05  
**POC仓库:** [CVE-2025-9209](https://github.com/Nxploited/CVE-2025-9209)  

---

### [CVE-2020-14883](CVE-2020-14883-B1ack4sh_Blackash-CVE-2020-14883.md) 🔴 ✅

**名称:** CVE-2020-14883 - Oracle WebLogic Server RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-11-05  
**POC仓库:** [Blackash-CVE-2020-14883](https://github.com/B1ack4sh/Blackash-CVE-2020-14883)  

---

### [CVE-2025-29927](CVE-2025-29927-BugHawak_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-Authorization Bypass  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-11-05  
**POC仓库:** [CVE-2025-29927](https://github.com/BugHawak/CVE-2025-29927)  

---

### [CVE-2020-2551](CVE-2020-2551-jas502n_CVE-2020-2551.md) 🔴 ✅

**名称:** CVE-2020-2551 WebLogic RCE via IIOP  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可完全控制WebLogic服务器  
**投毒风险:** 10%  
**发现时间:** 2025-11-05  
**POC仓库:** [CVE-2020-2551](https://github.com/jas502n/CVE-2020-2551)  

---

### [CVE-2020-2551](CVE-2020-2551-DaMinGshidashi_CVE-2020-2551.md) 🔴 ✅

**名称:** CVE-2020-2551-WebLogic-IIOP反序列化RCE  
**类型:** 反序列化远程代码执行  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-11-05  
**POC仓库:** [CVE-2020-2551](https://github.com/DaMinGshidashi/CVE-2020-2551)  

---

### [CVE-2020-2551](CVE-2020-2551-Y4er_CVE-2020-2551.md) 🔴 ✅

**名称:** CVE-2020-2551 - Oracle WebLogic Server IIOP反序列化漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-05  
**POC仓库:** [CVE-2020-2551](https://github.com/Y4er/CVE-2020-2551)  

---

### [CVE-2020-2551](CVE-2020-2551-Dido1960_Weblogic-CVE-2020-2551-To-Internet.md) 🔴 ✅

**名称:** CVE-2020-2551 - Oracle WebLogic Server IIOP 反序列化漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-05  
**POC仓库:** [Weblogic-CVE-2020-2551-To-Internet](https://github.com/Dido1960/Weblogic-CVE-2020-2551-To-Internet)  

---

### [CVE-2020-2551](CVE-2020-2551-ar2o3_CVE-Exploit.md) 🔴 ✅

**名称:** CVE-2020-2551 - Oracle WebLogic Server IIOP 反序列化漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可能导致远程代码执行，服务器接管  
**投毒风险:** 10%  
**发现时间:** 2025-11-05  
**POC仓库:** [CVE-Exploit](https://github.com/ar2o3/CVE-Exploit)  

---

### [CVE-2020-2551](CVE-2020-2551-zzwlpx_weblogicPoc.md) 🔴 ✅

**名称:** CVE-2020-2551 - Oracle WebLogic Server IIOP反序列化漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 20%  
**发现时间:** 2025-11-05  
**POC仓库:** [weblogicPoc](https://github.com/zzwlpx/weblogicPoc)  

---

### [CVE-2020-2551](CVE-2020-2551-hktalent_CVE-2020-2551.md) 🔴 ✅

**名称:** CVE-2020-2551-Oracle WebLogic Server-IIOP反序列化  
**类型:** 反序列化漏洞  
**风险:** 高危，可能导致远程代码执行，服务器接管  
**投毒风险:** 10%  
**发现时间:** 2025-11-05  
**POC仓库:** [CVE-2020-2551](https://github.com/hktalent/CVE-2020-2551)  

---

### [CVE-2020-2551](CVE-2020-2551-B1ack4sh_Blackash-CVE-2020-2551.md) 🔴 ✅

**名称:** CVE-2020-2551-WebLogic IIOP RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-11-05  
**POC仓库:** [Blackash-CVE-2020-2551](https://github.com/B1ack4sh/Blackash-CVE-2020-2551)  

---

### [CVE-2025-29927](CVE-2025-29927-BugHawak_CVE-2025-29927.md) 🔴 

**名称:** CVE-2025-29927-Next.js-权限绕过  
**类型:** 权限绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-11-05  
**POC仓库:** [CVE-2025-29927](https://github.com/BugHawak/CVE-2025-29927)  

---

### [CVE-2021-44228](CVE-2021-44228-Mintimate_log4j2-bugmaker.md) 🔴 ✅

**名称:** CVE-2021-44228 Log4Shell 漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行，系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-11-05  
**POC仓库:** [log4j2-bugmaker](https://github.com/Mintimate/log4j2-bugmaker)  

---

### [CVE-2021-44228](CVE-2021-44228-B1ack4sh_Blackash-CVE-2021-44228.md) 🔴 ✅

**名称:** CVE-2021-44228 - Log4Shell  
**类型:** 远程代码执行 (RCE)  
**风险:** 极高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-11-05  
**POC仓库:** [Blackash-CVE-2021-44228](https://github.com/B1ack4sh/Blackash-CVE-2021-44228)  

---

### [CVE-2025-24893](CVE-2025-24893-kimtangker_CVE-2025-24893.md)  ✅

**名称:** CVE-2025-24893 XWiki RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，允许未经身份验证的攻击者执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-11-05  
**POC仓库:** [CVE-2025-24893](https://github.com/kimtangker/CVE-2025-24893)  

---

### [CVE-2025-63307](CVE-2025-63307-Theethat-Thamwasin_CVE-2025-63307.md) 🔴 ✅

**名称:** CVE-2025-63307 - Authenticated Stored Cross-Site Scripting (XSS) in laravel-file-manager  
**类型:** Stored XSS  
**风险:** 高危，可能导致账户接管、数据泄露和恶意操作  
**投毒风险:** 0%  
**发现时间:** 2025-11-05  
**POC仓库:** [CVE-2025-63307](https://github.com/Theethat-Thamwasin/CVE-2025-63307)  

---

### [CVE-2025-63589](CVE-2025-63589-cybercrewinc_CVE-2025-63589.md)  ✅

**名称:** CVE-2025-63589  
**类型:** 未明确，推测为与代码仓库相关的漏洞  
**风险:** 待评估，取决于漏洞具体利用方式  
**投毒风险:** 0%  
**发现时间:** 2025-11-05  
**POC仓库:** [CVE-2025-63589](https://github.com/cybercrewinc/CVE-2025-63589)  

---

### [CVE-2024-46256](CVE-2024-46256-kimtangker_CVE-2024-46256.md) 🔴 ✅

**名称:** CVE-2024-46256 Nginx Proxy Manager 命令注入  
**类型:** 命令注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-05  
**POC仓库:** [CVE-2024-46256](https://github.com/kimtangker/CVE-2024-46256)  

---

### [CVE-2020-35667](CVE-2020-35667-stefan-500_teamcity-idea-cve-2020-35667-poc.md) 🔴 ✅

**名称:** CVE-2020-35667 - TeamCity IntelliJ IDEA Plugin SSRF 漏洞  
**类型:** SSRF  
**风险:** 高危，可能导致用户凭据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-11-05  
**POC仓库:** [teamcity-idea-cve-2020-35667-poc](https://github.com/stefan-500/teamcity-idea-cve-2020-35667-poc)  

---

### [CVE-2025-56383](CVE-2025-56383-NewComrade12211_CVE-2025-56383.md) 🔴 ✅

**名称:** CVE-2025-56383-Notepad++-DLL劫持  
**类型:** DLL劫持  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-05  
**POC仓库:** [CVE-2025-56383](https://github.com/NewComrade12211/CVE-2025-56383)  

---

### [CVE-2024-40725](CVE-2024-40725-YassineOUAHMANE_CVE-2024-40725.md) 🟡 ✅

**名称:** CVE-2024-40725 - Apache HTTP Server 源码泄露  
**类型:** 源码泄露  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-11-05  
**POC仓库:** [CVE-2024-40725](https://github.com/YassineOUAHMANE/CVE-2024-40725)  

---

### [CVE-2024-40725](CVE-2024-40725-TAM-K592_CVE-2024-40725-CVE-2024-40898.md) 🔴 ✅

**名称:** CVE-2024-40725/CVE-2024-40898 - Apache HTTP Server  
**类型:** 代码泄露/HTTP请求走私/SSL验证绕过  
**风险:** 高危，可能导致敏感信息泄露、权限提升和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-05  
**POC仓库:** [CVE-2024-40725-CVE-2024-40898](https://github.com/TAM-K592/CVE-2024-40725-CVE-2024-40898)  

---

### [CVE-2024-40725](CVE-2024-40725-soltanali0_CVE-2024-40725.md) 🟡 ✅

**名称:** CVE-2024-40725-Apache HTTP Server-源码泄露  
**类型:** 源码泄露  
**风险:** 中危，可能导致敏感信息泄露，为进一步攻击提供信息  
**投毒风险:** 10%  
**发现时间:** 2025-11-05  
**POC仓库:** [CVE-2024-40725](https://github.com/soltanali0/CVE-2024-40725)  

---

### [CVE-2025-52665](CVE-2025-52665-callinston_CVE-2025-52665.md) 🔴 

**名称:** CVE-2025-52665-UniFi Access-未授权访问  
**类型:** 未授权访问  
**风险:** 高危，可能导致敏感信息泄露和控制系统  
**投毒风险:** 5%  
**发现时间:** 2025-11-05  
**POC仓库:** [CVE-2025-52665](https://github.com/callinston/CVE-2025-52665)  

---

### [CVE-2025-48593](CVE-2025-48593-daiens_CVE-2025-48593.md) 🔴 ✅

**名称:** CVE-2025-48593 - Android系统零点击RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致设备完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-11-05  
**POC仓库:** [CVE-2025-48593](https://github.com/daiens/CVE-2025-48593)  

---

### [CVE-2020-9922](CVE-2020-9922-Wowfunhappy_Fix-Apple-Mail-CVE-2020-9922.md) 🔴 ✅

**名称:** CVE-2020-9922 - macOS Mail 任意文件写入  
**类型:** 任意文件写入  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-05  
**POC仓库:** [Fix-Apple-Mail-CVE-2020-9922](https://github.com/Wowfunhappy/Fix-Apple-Mail-CVE-2020-9922)  

---

### [CVE-2024-3094](CVE-2024-3094-B1ack4sh_Blackash-CVE-2024-3094.md)  ✅

**名称:** CVE-2024-3094 - XZ Utils供应链后门  
**类型:** 供应链攻击/嵌入恶意代码  
**风险:** 极危，可导致未经授权的远程访问和完全系统入侵  
**投毒风险:** 1%  
**发现时间:** 2025-11-05  
**POC仓库:** [Blackash-CVE-2024-3094](https://github.com/B1ack4sh/Blackash-CVE-2024-3094)  

---

### [CVE-2017-0144](CVE-2017-0144-AdityaBhatt3010_VAPT-Report-on-SMB-Exploitation-in-Windows-10-Finance-Endpoint.md) 🔴 ✅

**名称:** CVE-2017-0144 (EternalBlue)  
**类型:** 远程代码执行  
**风险:** 高危，允许远程攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-11-05  
**POC仓库:** [VAPT-Report-on-SMB-Exploitation-in-Windows-10-Finance-Endpoint](https://github.com/AdityaBhatt3010/VAPT-Report-on-SMB-Exploitation-in-Windows-10-Finance-Endpoint)  

---

### [CVE-2017-0144](CVE-2017-0144-nivedh-j_EternalBlue-Explained.md) 🔴 ✅

**名称:** CVE-2017-0144 - Windows SMBv1 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致系统完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-11-05  
**POC仓库:** [EternalBlue-Explained](https://github.com/nivedh-j/EternalBlue-Explained)  

---

### [CVE-2017-0144](CVE-2017-0144-B1ack4sh_Blackash-CVE-2017-0144.md) 🔴 ✅

**名称:** CVE-2017-0144-Windows SMB Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，可能导致系统被完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-11-05  
**POC仓库:** [Blackash-CVE-2017-0144](https://github.com/B1ack4sh/Blackash-CVE-2017-0144)  

---

### [CVE-2025-11953](CVE-2025-11953-B1ack4sh_Blackash-CVE-2025-11953.md) 🔴 

**名称:** CVE-2025-11953-@react-native-community/cli-server-api-命令注入  
**类型:** 命令注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-05  
**POC仓库:** [Blackash-CVE-2025-11953](https://github.com/B1ack4sh/Blackash-CVE-2025-11953)  

---

### [CVE-2025-53690](CVE-2025-53690-ErikLearningSec_CVE-2025-53690-POC.md) 🔴 ✅

**名称:** CVE-2025-53690-Sitecore-ViewState反序列化  
**类型:** ViewState反序列化  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-05  
**POC仓库:** [CVE-2025-53690-POC](https://github.com/ErikLearningSec/CVE-2025-53690-POC)  

---

### [CVE-2025-6440](CVE-2025-6440-xxoprt_CVE-2025-6440.md) 🔴 ✅

**名称:** CVE-2025-6440 - WooCommerce Designer Pro - 未授权任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 50%  
**发现时间:** 2025-11-05  
**POC仓库:** [CVE-2025-6440](https://github.com/xxoprt/CVE-2025-6440)  

---

### [CVE-2021-4773](CVE-2021-4773-Alexs18_CVE-2021-4773.md)  ✅

**名称:** CVE-2021-4773  
**类型:** 未知  
**风险:** 低危，仅提供学习示例  
**投毒风险:** 0%  
**发现时间:** 2025-11-05  
**POC仓库:** [CVE-2021-4773](https://github.com/Alexs18/CVE-2021-4773)  

---

### [CVE-2023-49440](CVE-2023-49440-NyaMeeEain_CVE-2023-49440.md) 🔴 

**名称:** CVE-2023-49440-AhnLab EPP Management-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-05  
**POC仓库:** [CVE-2023-49440](https://github.com/NyaMeeEain/CVE-2023-49440)  

---

### [CVE-2024-40815](CVE-2024-40815-w0wbox_CVE-2024-40815.md) 🔴 

**名称:** CVE-2024-40815 - Pointer Authentication Bypass  
**类型:** 指针认证绕过  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-05  
**POC仓库:** [CVE-2024-40815](https://github.com/w0wbox/CVE-2024-40815)  

---

### [CVE-2020-14882](CVE-2020-14882-B1ack4sh_Blackash-CVE-2020-14882.md) 🔴 ✅

**名称:** CVE-2020-14882 - Oracle WebLogic Server RCE (Unauthenticated)  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-11-04  
**POC仓库:** [Blackash-CVE-2020-14882](https://github.com/B1ack4sh/Blackash-CVE-2020-14882)  

---

### [CVE-2025-11953](CVE-2025-11953-SaidBenaissa_cve-2025-11953-vulnerability-demo.md)  ✅

**名称:** CVE-2025-11953 - React Native CLI 命令注入  
**类型:** 命令注入  
**风险:** 严重，允许未经身份验证的远程攻击者执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-11-04  
**POC仓库:** [cve-2025-11953-vulnerability-demo](https://github.com/SaidBenaissa/cve-2025-11953-vulnerability-demo)  

---

### [CVE-2025-59287](CVE-2025-59287-th1n0_CVE-2025-59287.md) 🔴 ✅

**名称:** CVE-2025-59287 - Windows Server Update Service (WSUS) 远程代码执行漏洞  
**类型:** 反序列化  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-11-04  
**POC仓库:** [CVE-2025-59287](https://github.com/th1n0/CVE-2025-59287)  

---

### [CVE-2024-5932](CVE-2024-5932-autom4il_CVE-2024-5932.md)  ✅

**名称:** CVE-2024-5932-GiveWP-RCE  
**类型:** PHP对象注入导致远程代码执行  
**风险:** 严重，可导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-11-04  
**POC仓库:** [CVE-2024-5932](https://github.com/autom4il/CVE-2024-5932)  

---

### [CVE-2025-55752](CVE-2025-55752-AuroraSec-Pivot_CVE-2025-55752.md) 🔴 ✅

**名称:** CVE-2025-55752：Apache Tomcat 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露，如果PUT方法开启，可能导致RCE  
**投毒风险:** 0%  
**发现时间:** 2025-11-04  
**POC仓库:** [CVE-2025-55752](https://github.com/AuroraSec-Pivot/CVE-2025-55752)  

---

### [CVE-2025-29009](CVE-2025-29009-joshs-code_CVE-2025-29009-POC.md) 🔴 ✅

**名称:** CVE-2025-29009-Medical Prescription Attachment Plugin for WooCommerce-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-04  
**POC仓库:** [CVE-2025-29009-POC](https://github.com/joshs-code/CVE-2025-29009-POC)  

---

### [CVE-2018-6574](CVE-2018-6574-YoussefSalama1_CVE-2018-6574.md) 🔴 ✅

**名称:** CVE-2018-6574 - Go "go get" 远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-04  
**POC仓库:** [CVE-2018-6574](https://github.com/YoussefSalama1/CVE-2018-6574)  

---

### [CVE-2025-48593](CVE-2025-48593-B1ack4sh_Blackash-CVE-2025-48593.md)  ✅

**名称:** CVE-2025-48593 Android系统零点击远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，零点击即可远程控制设备  
**投毒风险:** 10%  
**发现时间:** 2025-11-04  
**POC仓库:** [Blackash-CVE-2025-48593](https://github.com/B1ack4sh/Blackash-CVE-2025-48593)  

---

### [CVE-2021-27328](CVE-2021-27328-SQSamir_CVE-2021-27328.md) 🔴 ✅

**名称:** CVE-2021-27328-Yeastar NeoGate TG400-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-11-04  
**POC仓库:** [CVE-2021-27328](https://github.com/SQSamir/CVE-2021-27328)  

---

### [CVE-2025-8573](CVE-2025-8573-iamFredNi_poc-cve-2025-8573.md)  ✅

**名称:** CVE-2025-8573-ConcreteCMS-Stored XSS  
**类型:** Stored XSS  
**风险:** 低危，可能导致有限的权限提升和信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-11-04  
**POC仓库:** [poc-cve-2025-8573](https://github.com/iamFredNi/poc-cve-2025-8573)  

---

### [CVE-2024-51378](CVE-2024-51378-refr4g_CVE-2024-51378.md) 🔴 ✅

**名称:** CVE-2024-51378-CyberPanel-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行和系统完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-11-04  
**POC仓库:** [CVE-2024-51378](https://github.com/refr4g/CVE-2024-51378)  

---

### [CVE-2024-51378](CVE-2024-51378-qnole000_CVE-2024-51378.md) 🔴 ✅

**名称:** CVE-2024-51378-CyberPanel-命令注入  
**类型:** 命令注入  
**风险:** 高危，未经身份验证的远程命令执行  
**投毒风险:** 5%  
**发现时间:** 2025-11-04  
**POC仓库:** [CVE-2024-51378](https://github.com/qnole000/CVE-2024-51378)  

---

### [CVE-2025-54253](CVE-2025-54253-AdityaBhatt3010_CVE-2025-54253-Inside-the-Adobe-AEM-Forms-Zero-Day.md) 🔴 ✅

**名称:** CVE-2025-54253: Adobe Experience Manager | Misconfiguration (CWE-16)  
**类型:** Misconfiguration  
**风险:** Critical, Arbitrary Code Execution  
**投毒风险:** 1%  
**发现时间:** 2025-11-04  
**POC仓库:** [CVE-2025-54253-Inside-the-Adobe-AEM-Forms-Zero-Day](https://github.com/AdityaBhatt3010/CVE-2025-54253-Inside-the-Adobe-AEM-Forms-Zero-Day)  

---

### [CVE-2025-26624](CVE-2025-26624-havertz2110_CVE-2025-26624.md) 🟡 ✅

**名称:** CVE-2025-26624-Rufus-本地提权  
**类型:** DLL劫持  
**风险:** 中危，本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-11-04  
**POC仓库:** [CVE-2025-26624](https://github.com/havertz2110/CVE-2025-26624)  

---

### [CVE-2025-12463](CVE-2025-12463-B1ack4sh_CVE-CVE-2025-12463.md)  

**名称:** CVE-2025-12463-Guetebruck G-Cam-SQL注入  
**类型:** SQL注入  
**风险:** 严重，可能导致完全控制设备  
**投毒风险:** 0%  
**发现时间:** 2025-11-04  
**POC仓库:** [CVE-CVE-2025-12463](https://github.com/B1ack4sh/CVE-CVE-2025-12463)  

---

### [CVE-2025-10576](CVE-2025-10576-R41N3RZUF477_CVE-2025-10576.md) 🔴 

**名称:** CVE-2025-10576 - HP Sound Research SECOMNService Escalation of Privilege  
**类型:** 权限提升  
**风险:** 高危，可能允许低权限用户获取系统管理员权限  
**投毒风险:** 0%  
**发现时间:** 2025-11-03  
**POC仓库:** [CVE-2025-10576](https://github.com/R41N3RZUF477/CVE-2025-10576)  

---

### [CVE-2025-55752](CVE-2025-55752-keepshard_CVE-2025-55752.md) 🔴 ✅

**名称:** CVE-2025-55752 - Apache Tomcat Relative Path Traversal  
**类型:** Relative Path Traversal  
**风险:** 高危，可能导致敏感信息泄露、任意文件上传（如果启用PUT）和远程代码执行  
**投毒风险:** 95%  
**发现时间:** 2025-11-03  
**POC仓库:** [CVE-2025-55752](https://github.com/keepshard/CVE-2025-55752)  

---

### [CVE-2025-11833](CVE-2025-11833-nullstatics_CVE-2025-11833.md) 🔴 

**名称:** CVE-2025-11833 - Post SMTP 插件未经授权的数据访问  
**类型:** 信息泄露/账户接管  
**风险:** 高危，可能导致敏感信息泄露和账户接管  
**投毒风险:** 80%  
**发现时间:** 2025-11-03  
**POC仓库:** [CVE-2025-11833](https://github.com/nullstatics/CVE-2025-11833)  

---

### [CVE-2025-8088](CVE-2025-8088-nuky-alt_CVE-2025-8088.md) 🔴 ✅

**名称:** CVE-2025-8088-WinRAR路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，可导致任意代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-11-03  
**POC仓库:** [CVE-2025-8088](https://github.com/nuky-alt/CVE-2025-8088)  

---

### [CVE-2025-62726](CVE-2025-62726-Malayke_n8n-remote-code-execution-cve-2025-62726-exploit.md) 🔴 ✅

**名称:** CVE-2025-62726-n8n-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致系统完全控制和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-11-03  
**POC仓库:** [n8n-remote-code-execution-cve-2025-62726-exploit](https://github.com/Malayke/n8n-remote-code-execution-cve-2025-62726-exploit)  

---

### [CVE-2025-24893](CVE-2025-24893-80Ottanta80_CVE-2025-24893-PoC.md) 🔴 ✅

**名称:** CVE-2025-24893-XWiki-Unauthenticated-RCE  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-03  
**POC仓库:** [CVE-2025-24893-PoC](https://github.com/80Ottanta80/CVE-2025-24893-PoC)  

---

### [CVE-2014-9219](CVE-2014-9219-MohmadHafiz_CVE-2014-9219.md) 🟡 ✅

**名称:** CVE-2014-9219 phpMyAdmin XSS漏洞  
**类型:** 跨站脚本攻击 (XSS)  
**风险:** 中危，可能导致用户信息泄露、会话劫持、恶意代码执行等  
**投毒风险:** 10%  
**发现时间:** 2025-11-03  
**POC仓库:** [CVE-2014-9219](https://github.com/MohmadHafiz/CVE-2014-9219)  

---

### [CVE-2025-62726](CVE-2025-62726-Malayke_CVE-2025-62726-payload-repo.md) 🔴 ✅

**名称:** CVE-2025-62726-n8n-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致完全系统控制和数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-11-03  
**POC仓库:** [CVE-2025-62726-payload-repo](https://github.com/Malayke/CVE-2025-62726-payload-repo)  

---

### [CVE-2025-53072](CVE-2025-53072-B1ack4sh_Blackash-CVE-2025-53072.md) 🔴 ✅

**名称:** CVE-2025-53072-Oracle Marketing-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致完全控制Oracle Marketing系统  
**投毒风险:** 10%  
**发现时间:** 2025-11-03  
**POC仓库:** [Blackash-CVE-2025-53072](https://github.com/B1ack4sh/Blackash-CVE-2025-53072)  

---

### [CVE-2025-62481](CVE-2025-62481-B1ack4sh_Blackash-CVE-2025-62481.md) 🔴 ✅

**名称:** CVE-2025-62481-Oracle Marketing Administration (EBS) 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-11-03  
**POC仓库:** [Blackash-CVE-2025-62481](https://github.com/B1ack4sh/Blackash-CVE-2025-62481)  

---

### [CVE-2025-32463](CVE-2025-32463-NewComrade12211_CVE-2025-32463.md) 🔴 ✅

**名称:** CVE-2025-32463-Sudo-本地提权  
**类型:** 本地提权  
**风险:** 高危，允许本地用户获取root权限  
**投毒风险:** 0%  
**发现时间:** 2025-11-03  
**POC仓库:** [CVE-2025-32463](https://github.com/NewComrade12211/CVE-2025-32463)  

---

### [CVE-2025-59396](CVE-2025-59396-cyberbyte000_CVE-2025-59396.md) 🔴 ✅

**名称:** CVE-2025-59396 - WatchGuard Firebox 未授权SSH访问  
**类型:** 未授权访问/默认配置漏洞  
**风险:** 高危，可能导致设备完全被控制  
**投毒风险:** 0%  
**发现时间:** 2025-11-03  
**POC仓库:** [CVE-2025-59396](https://github.com/cyberbyte000/CVE-2025-59396)  

---

### [CVE-2025-25254](CVE-2025-25254-JackMicalli_CVE-2025-25254.md) 🔴 ✅

**名称:** CVE-2025-25257-FortiWeb-SQL注入RCE  
**类型:** SQL注入导致远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-11-03  
**POC仓库:** [CVE-2025-25254](https://github.com/JackMicalli/CVE-2025-25254)  

---

### [CVE-2025-12428](CVE-2025-12428-dexterm300_cve-2025-12428-exploit-poc.md) 🔴 ✅

**名称:** CVE-2025-12428 - V8 Type Confusion PoC  
**类型:** 类型混淆  
**风险:** 高危，可能导致堆损坏和任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-03  
**POC仓库:** [cve-2025-12428-exploit-poc](https://github.com/dexterm300/cve-2025-12428-exploit-poc)  

---

### [CVE-2025-59287](CVE-2025-59287-dexterm300_cve-2025-59287-exploit-poc.md) 🔴 ✅

**名称:** CVE-2025-59287-Windows Server Update Service (WSUS) Remote Code Execution  
**类型:** 反序列化漏洞  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-03  
**POC仓库:** [cve-2025-59287-exploit-poc](https://github.com/dexterm300/cve-2025-59287-exploit-poc)  

---

### [CVE-2025-25252](CVE-2025-25252-iptables6cv_CVE-2025-25252-POC.md) 🔴 ✅

**名称:** CVE-2025-25257-FortiWeb-SQL注入-远程代码执行  
**类型:** SQL注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-11-03  
**POC仓库:** [CVE-2025-25252-POC](https://github.com/iptables6cv/CVE-2025-25252-POC)  

---

### [CVE-2025-25253](CVE-2025-25253-onelittlectfer_CVE-2025-25253.md) 🔴 ✅

**名称:** CVE-2025-25257-FortiWeb-SQL注入-RCE  
**类型:** SQL注入到远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者远程执行代码  
**投毒风险:** 10%  
**发现时间:** 2025-11-03  
**POC仓库:** [CVE-2025-25253](https://github.com/onelittlectfer/CVE-2025-25253)  

---

### [CVE-2024-45496](CVE-2024-45496-fatcatresearch_cve-2024-45496.md) 🔴 ✅

**名称:** CVE-2024-45496-Openshift-controller-manager-Node Compromise  
**类型:** 权限提升  
**风险:** 高危，可能导致节点被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-11-03  
**POC仓库:** [cve-2024-45496](https://github.com/fatcatresearch/cve-2024-45496)  

---

### [CVE-2022-27913](CVE-2022-27913-CamTechCoaching_Joomla-CVE-Detector-CVE-2022-27913-.md) 🟡 ✅

**名称:** CVE-2022-27913-Joomla-RXSS  
**类型:** RXSS (Reflected Cross-Site Scripting)  
**风险:** 中危，可能导致会话劫持、恶意重定向、窃取用户敏感信息  
**投毒风险:** 5%  
**发现时间:** 2025-11-03  
**POC仓库:** [Joomla-CVE-Detector-CVE-2022-27913-](https://github.com/CamTechCoaching/Joomla-CVE-Detector-CVE-2022-27913-)  

---

### [CVE-2025-61472](CVE-2025-61472-flywithjoey_CVE-2025-61472.md) 🔴 ✅

**名称:** J2V8 V8引擎漏洞利用  
**类型:** V8引擎漏洞利用 (n-day)  
**风险:** 高危，远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-11-03  
**POC仓库:** [CVE-2025-61472](https://github.com/flywithjoey/CVE-2025-61472)  

---

### [CVE-2025-50168](CVE-2025-50168-D4m0n_CVE-2025-50168-pwn2own-berlin-2025.md) 🔴 ✅

**名称:** CVE-2025-50168-Win32k Elevation of Privilege  
**类型:** 权限提升  
**风险:** 高危，本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-11-03  
**POC仓库:** [CVE-2025-50168-pwn2own-berlin-2025](https://github.com/D4m0n/CVE-2025-50168-pwn2own-berlin-2025)  

---

### [CVE-2015-3306](CVE-2015-3306-cybersensei-EH_hackviser_labs_CVE-2015-3306.md) 🔴 ✅

**名称:** CVE-2015-3306 ProFTPD 1.3.5 mod_copy 远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可读取和写入任意文件，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-11-02  
**POC仓库:** [hackviser_labs_CVE-2015-3306](https://github.com/cybersensei-EH/hackviser_labs_CVE-2015-3306)  

---

### [CVE-2025-12596](CVE-2025-12596-DebugFrag_CVE-2025-12596-Exploit.md) 🔴 ✅

**名称:** CVE-2025-12596 - Tenda AC23 saveParentControlInfo 缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-02  
**POC仓库:** [CVE-2025-12596-Exploit](https://github.com/DebugFrag/CVE-2025-12596-Exploit)  

---

### [CVE-2025-12437](CVE-2025-12437-callinston_CVE-2025-12437.md) 🔴 ✅

**名称:** CVE-2025-12437-Chrome PageInfo UAF  
**类型:** Use-After-Free (UAF)  
**风险:** 高危，远程代码执行 (RCE)  
**投毒风险:** 60%  
**发现时间:** 2025-11-02  
**POC仓库:** [CVE-2025-12437](https://github.com/callinston/CVE-2025-12437)  

---

### [CVE-2025-12595](CVE-2025-12595-lagerhaker539_CVE-2025-12595-POC.md) 🔴 ✅

**名称:** CVE-2025-12595 - Tenda AC23 SetVirtualServerCfg 缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-02  
**POC仓库:** [CVE-2025-12595-POC](https://github.com/lagerhaker539/CVE-2025-12595-POC)  

---

### [CVE-2025-8088](CVE-2025-8088-B1ack4sh_Blackash-CVE-2025-8088.md) 🔴 ✅

**名称:** CVE-2025-8088 WinRAR 路径遍历漏洞  
**类型:** 路径遍历/任意文件写入导致代码执行  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-11-02  
**POC仓库:** [Blackash-CVE-2025-8088](https://github.com/B1ack4sh/Blackash-CVE-2025-8088)  

---

### [CVE-2025-2011](CVE-2025-2011-X3RX3SSec_CVE-2025-2011.md) 🔴 ✅

**名称:** CVE-2025-2011-Slider & Popup Builder by Depicter-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致敏感数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-11-02  
**POC仓库:** [CVE-2025-2011](https://github.com/X3RX3SSec/CVE-2025-2011)  

---

### [CVE-2025-59287](CVE-2025-59287-Sid6Effect_CVE-2025-59287.md) 🔴 ✅

**名称:** CVE-2025-59287-Windows Server Update Service (WSUS) 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许未授权的攻击者通过网络执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-11-02  
**POC仓库:** [CVE-2025-59287](https://github.com/Sid6Effect/CVE-2025-59287)  

---

### [CVE-2025-62168](CVE-2025-62168-shahroodcert_CVE-2025-62168.md) 🔴 ✅

**名称:** CVE-2025-62168-Squid代理信息泄露  
**类型:** 信息泄露  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 20%  
**发现时间:** 2025-11-02  
**POC仓库:** [CVE-2025-62168](https://github.com/shahroodcert/CVE-2025-62168)  

---

### [CVE-2025-57833](CVE-2025-57833-sw0rd1ight_CVE-2025-57833.md) 🔴 ✅

**名称:** CVE-2025-57833-Django-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露，数据篡改甚至远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-02  
**POC仓库:** [CVE-2025-57833](https://github.com/sw0rd1ight/CVE-2025-57833)  

---

### [CVE-2025-59528](CVE-2025-59528-zimshk_CVE-2025-59528.yaml.md) 🔴 ✅

**名称:** CVE-2025-59528-Flowise-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致完全控制服务器  
**投毒风险:** 0%  
**发现时间:** 2025-11-02  
**POC仓库:** [CVE-2025-59528.yaml](https://github.com/zimshk/CVE-2025-59528.yaml)  

---

### [CVE-2025-11174](CVE-2025-11174-SnailSploit_CVE-2025-11174.md) 🟡 ✅

**名称:** CVE-2025-11174-Document Library Lite-敏感信息泄露  
**类型:** 敏感信息泄露  
**风险:** 中危，可能导致未授权访问敏感信息  
**投毒风险:** 10%  
**发现时间:** 2025-11-02  
**POC仓库:** [CVE-2025-11174](https://github.com/SnailSploit/CVE-2025-11174)  

---

### [CVE-2024-7387](CVE-2024-7387-fatcatresearch_cve-2024-7387.md) 🔴 ✅

**名称:** CVE-2024-7387-Openshift Builder-命令注入  
**类型:** 命令注入  
**风险:** 高危，可导致主机权限提升和完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-11-02  
**POC仓库:** [cve-2024-7387](https://github.com/fatcatresearch/cve-2024-7387)  

---

### [CVE-2024-3094](CVE-2024-3094-M1lo25_CS50FinalProject.md)  ✅

**名称:** CVE-2024-3094 XZ Utils Backdoor  
**类型:** 供应链攻击/后门  
**风险:** 极危，可能导致未经授权的远程访问和控制  
**投毒风险:** 5%  
**发现时间:** 2025-11-01  
**POC仓库:** [CS50FinalProject](https://github.com/M1lo25/CS50FinalProject)  

---

### [CVE-2024-3094](CVE-2024-3094-ThomRgn_xzutils_backdoor_obfuscation.md)  

**名称:** CVE-2024-3094 Xz 后门  
**类型:** 供应链攻击/后门  
**风险:** 极危，可能导致未经授权的远程访问和系统控制  
**投毒风险:** 0%  
**发现时间:** 2025-11-01  
**POC仓库:** [xzutils_backdoor_obfuscation](https://github.com/ThomRgn/xzutils_backdoor_obfuscation)  

---

### [CVE-2024-32019](CVE-2024-32019-80Ottanta80_CVE-2024-32019-PoC.md) 🔴 ✅

**名称:** CVE-2024-32019-netdata-local权限提升  
**类型:** 本地权限提升  
**风险:** 高危，可导致root权限获取  
**投毒风险:** 0%  
**发现时间:** 2025-11-01  
**POC仓库:** [CVE-2024-32019-PoC](https://github.com/80Ottanta80/CVE-2024-32019-PoC)  

---

### [CVE-2025-11833](CVE-2025-11833-modhopmarrow1973_CVE-2025-11833-LAB.md) 🔴 ✅

**名称:** CVE-2025-11833 - Post SMTP WordPress Plugin Unauthenticated Arbitrary Email Log Disclosure  
**类型:** 未授权信息泄露  
**风险:** 高危，可能导致账号接管  
**投毒风险:** 20%  
**发现时间:** 2025-11-01  
**POC仓库:** [CVE-2025-11833-LAB](https://github.com/modhopmarrow1973/CVE-2025-11833-LAB)  

---

### [CVE-2025-54897](CVE-2025-54897-themaxlpalfaboy_CVE-2025-54897-LAB.md) 🔴 ✅

**名称:** CVE-2025-54897 - Microsoft SharePoint 远程代码执行漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 30%  
**发现时间:** 2025-11-01  
**POC仓库:** [CVE-2025-54897-LAB](https://github.com/themaxlpalfaboy/CVE-2025-54897-LAB)  

---

### [CVE-2025-55234](CVE-2025-55234-h4xnz_CVE-2025-55234-POC.md) 🔴 ✅

**名称:** CVE-2025-55234 - Windows SMB Elevation of Privilege Vulnerability  
**类型:** SMB Relay Elevation of Privilege  
**风险:** 高危，可能导致权限提升、横向移动和数据泄露  
**投毒风险:** 20%  
**发现时间:** 2025-11-01  
**POC仓库:** [CVE-2025-55234-POC](https://github.com/h4xnz/CVE-2025-55234-POC)  

---

### [CVE-2025-59287](CVE-2025-59287-QurtiDev_WSUS-CVE-2025-59287-RCE.md) 🔴 ✅

**名称:** CVE-2025-59287 - Windows Server Update Service (WSUS) Remote Code Execution  
**类型:** 反序列化漏洞导致远程代码执行  
**风险:** 高危，可导致完全控制受影响的服务器  
**投毒风险:** 10%  
**发现时间:** 2025-11-01  
**POC仓库:** [WSUS-CVE-2025-59287-RCE](https://github.com/QurtiDev/WSUS-CVE-2025-59287-RCE)  

---

### [CVE-2025-54106](CVE-2025-54106-DExplo1ted_CVE-2025-54106-POC.md) 🔴 ✅

**名称:** CVE-2025-54106 - Windows RRAS 整数溢出远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许未经授权的攻击者通过网络执行任意代码  
**投毒风险:** 20%  
**发现时间:** 2025-11-01  
**POC仓库:** [CVE-2025-54106-POC](https://github.com/DExplo1ted/CVE-2025-54106-POC)  

---

### [CVE-2025-11499](CVE-2025-11499-usjnx72726w_CVE-2025-11499-LAB.md)  ✅

**名称:** CVE-2025-11499-Tablesome WordPress Plugin-Unauthenticated Arbitrary File Upload  
**类型:** Unauthenticated Arbitrary File Upload  
**风险:** 严重，允许未经身份验证的攻击者上传任意文件，可能导致远程代码执行。  
**投毒风险:** 10%  
**发现时间:** 2025-11-01  
**POC仓库:** [CVE-2025-11499-LAB](https://github.com/usjnx72726w/CVE-2025-11499-LAB)  

---

### [CVE-2025-11499](CVE-2025-11499-Hazelooks_CVE-2025-11499-Exploit.md) 🔴 ✅

**名称:** CVE-2025-11499 - Tablesome Table WordPress Plugin Unauthenticated Arbitrary File Upload  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-01  
**POC仓库:** [CVE-2025-11499-Exploit](https://github.com/Hazelooks/CVE-2025-11499-Exploit)  

---

### [CVE-2021-3560](CVE-2021-3560-SeimuPVE_CVE-2021-3560_Polkit.md) 🔴 ✅

**名称:** CVE-2021-3560 Polkit 本地提权  
**类型:** 权限提升  
**风险:** 高危，本地用户可获得Root权限  
**投毒风险:** 10%  
**发现时间:** 2025-11-01  
**POC仓库:** [CVE-2021-3560_Polkit](https://github.com/SeimuPVE/CVE-2021-3560_Polkit)  

---

### [CVE-2025-11499](CVE-2025-11499-rootreapers_CVE-2025-11499.md) 🔴 ✅

**名称:** CVE-2025-11499-Tablesome Table Plugin-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-01  
**POC仓库:** [CVE-2025-11499](https://github.com/rootreapers/CVE-2025-11499)  

---

### [CVE-2025-61481](CVE-2025-61481-codetombs_CVE-2025-61481.md) 🔴 ✅

**名称:** CVE-2025-61481-MikroTik-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可完全控制受影响设备  
**投毒风险:** 95%  
**发现时间:** 2025-11-01  
**POC仓库:** [CVE-2025-61481](https://github.com/codetombs/CVE-2025-61481)  

---

### [CVE-2015-1328](CVE-2015-1328-thieveshkar_RootQuest-CTF-Box-Multi-Stage-Exploitation-VM.md) 🔴 ✅

**名称:** CVE-2015-1328-Ubuntu-overlayfs本地提权  
**类型:** 本地提权  
**风险:** 高危，允许本地用户获取root权限  
**投毒风险:** 5%  
**发现时间:** 2025-11-01  
**POC仓库:** [RootQuest-CTF-Box-Multi-Stage-Exploitation-VM](https://github.com/thieveshkar/RootQuest-CTF-Box-Multi-Stage-Exploitation-VM)  

---

### [CVE-2015-1328](CVE-2015-1328-0xf1d0_CVE-2015-1328.md) 🔴 ✅

**名称:** CVE-2015-1328-Overlayfs本地提权  
**类型:** 本地提权  
**风险:** 高危，允许本地用户获取root权限  
**投毒风险:** 5%  
**发现时间:** 2025-11-01  
**POC仓库:** [CVE-2015-1328](https://github.com/0xf1d0/CVE-2015-1328)  

---

### [CVE-2025-60423](CVE-2025-60423-Zephyr1ng_CVE-2025-60423.md)  ✅

**名称:** 未知漏洞  
**类型:** 未知  
**风险:** 未知  
**投毒风险:** 0%  
**发现时间:** 2025-11-01  
**POC仓库:** [CVE-2025-60423](https://github.com/Zephyr1ng/CVE-2025-60423)  

---

### [CVE-2025-55234](CVE-2025-55234-ByteHawkSec_CVE-2025-55234-POC.md) 🔴 ✅

**名称:** CVE-2025-55234-Windows SMB Elevation of Privilege  
**类型:** 权限提升  
**风险:** 高危，可能导致权限提升和SMB中继攻击  
**投毒风险:** 10%  
**发现时间:** 2025-11-01  
**POC仓库:** [CVE-2025-55234-POC](https://github.com/ByteHawkSec/CVE-2025-55234-POC)  

---

### [CVE-2025-4796](CVE-2025-4796-Pwdnx1337_CVE-2025-4796.md) 🔴 ✅

**名称:** CVE-2025-4796-Eventin-权限提升/账户接管  
**类型:** 权限提升/账户接管  
**风险:** 高危，可能导致账户接管和未授权访问  
**投毒风险:** 0%  
**发现时间:** 2025-11-01  
**POC仓库:** [CVE-2025-4796](https://github.com/Pwdnx1337/CVE-2025-4796)  

---

### [CVE-2024-45496](CVE-2024-45496-fatcatresearch_cve-2024-45496.md)  

**名称:** CVE-2024-45496 - OpenShift Node Compromise via Crafted .gitconfig  
**类型:** 权限提升/命令执行  
**风险:** 严重，可能导致节点被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-11-01  
**POC仓库:** [cve-2024-45496](https://github.com/fatcatresearch/cve-2024-45496)  

---

### [CVE-2021-31166](CVE-2021-31166-qazbnme_CVE-2021.md) 🔴 ✅

**名称:** CVE-2021-31166 - HTTP Protocol Stack Remote Code Execution Vulnerability  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-11-01  
**POC仓库:** [CVE-2021](https://github.com/qazbnme/CVE-2021)  

---


## 🔍 快速查找

- [按CVE编号查找](../../by-cve/)
- [返回2025年总览](../README.md)
- [返回总索引](../../README.md)

---

*本文档由 VulnWatchdog 自动生成 @ 2025-11-26 13:32*
