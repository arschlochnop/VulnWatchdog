# 2025年04月漏洞情报汇总

> 📅 统计周期: 2025-04-01 ~ 2025-04-30
> 📊 新增漏洞: **1557** 个
> 🔥 高危漏洞: **1275** 个

---

## 📊 漏洞类型分布

| 类型 | 数量 | 占比 |
|------|------|------|
| 远程代码执行 | 245 | 15.7% |
| 远程代码执行 (RCE) | 129 | 8.3% |
| 权限提升 | 105 | 6.7% |
| 命令注入 | 73 | 4.7% |
| 身份验证绕过 | 70 | 4.5% |
| SQL注入 | 55 | 3.5% |
| Use-After-Free | 37 | 2.4% |
| 远程命令执行 | 29 | 1.9% |
| 拒绝服务 (DoS) | 25 | 1.6% |
| 授权绕过 | 22 | 1.4% |

---

## 📋 详细列表

### [CVE-2025-31324](CVE-2025-31324-JonathanStross_CVE-2025-31324.md) 🔴 ✅

**名称:** CVE-2025-31324 - SAP NetWeaver Visual Composer 未授权文件上传  
**类型:** 未授权文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2025-31324](https://github.com/JonathanStross/CVE-2025-31324)  

---

### [CVE-2025-42599](CVE-2025-42599-cyruscostini_CVE-2025-42599.md) 🔴 

**名称:** CVE-2025-42599-Active! mail-栈溢出  
**类型:** 栈溢出  
**风险:** 高危，可导致任意代码执行和拒绝服务  
**投毒风险:** 70%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2025-42599](https://github.com/cyruscostini/CVE-2025-42599)  

---

### [CVE-2025-30392](CVE-2025-30392-Totunm_CVE-2025-30392.md) 🔴 

**名称:** CVE-2025-30392-Azure AI Bot Service-权限提升  
**类型:** 权限提升  
**风险:** 高危，可能导致控制整个Bot服务  
**投毒风险:** 99%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2025-30392](https://github.com/Totunm/CVE-2025-30392)  

---

### [CVE-2025-24271](CVE-2025-24271-moften_CVE-2025-24271.md) 🟡 ✅

**名称:** CVE-2025-24271 - AirPlay 未授权命令执行  
**类型:** 访问控制漏洞  
**风险:** 中危，可能导致未授权的AirPlay命令执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2025-24271](https://github.com/moften/CVE-2025-24271)  

---

### [CVE-2019-0708](CVE-2019-0708-umarfarook882_CVE-2019-0708.md)  ✅

**名称:** CVE-2019-0708 - BlueKeep  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，未经身份验证的攻击者可以通过 RDP 发送特制请求来执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2019-0708](https://github.com/umarfarook882/CVE-2019-0708)  

---

### [CVE-2019-0708](CVE-2019-0708-worawit_CVE-2019-0708.md)  ✅

**名称:** CVE-2019-0708 (BlueKeep)  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2019-0708](https://github.com/worawit/CVE-2019-0708)  

---

### [CVE-2025-39538](CVE-2025-39538-Nxploited_CVE-2025-39538.md) 🔴 ✅

**名称:** CVE-2025-39538 - WordPress WP-Advanced-Search Arbitrary File Upload  
**类型:** Arbitrary File Upload  
**风险:** 高危，允许攻击者上传Web Shell，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2025-39538](https://github.com/Nxploited/CVE-2025-39538)  

---

### [CVE-2024-6387](CVE-2024-6387-AzrDll_CVE-2024-6387.md) 🔴 ✅

**名称:** CVE-2024-6387 OpenSSH 竞争条件导致 RCE/DoS  
**类型:** 竞争条件  
**风险:** 高危，可能导致远程代码执行和拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2024-6387](https://github.com/AzrDll/CVE-2024-6387)  

---

### [CVE-2024-6387](CVE-2024-6387-SkyGodling_CVE-2024-6387-POC.md) 🔴 ✅

**名称:** CVE-2024-6387-OpenSSH-竞争条件RCE/DoS  
**类型:** 竞争条件  
**风险:** 高危，可能导致远程代码执行（RCE）或拒绝服务（DoS）  
**投毒风险:** 10%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2024-6387-POC](https://github.com/SkyGodling/CVE-2024-6387-POC)  

---

### [CVE-2019-0708](CVE-2019-0708-nochemax_bLuEkEeP-GUI.md)  ✅

**名称:** CVE-2019-0708 - BlueKeep  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致远程代码执行，完全控制受影响的系统  
**投毒风险:** 60%  
**发现时间:** 2025-04-30  
**POC仓库:** [bLuEkEeP-GUI](https://github.com/nochemax/bLuEkEeP-GUI)  

---

### [CVE-2019-0708](CVE-2019-0708-andripwn_CVE-2019-0708.md)  ✅

**名称:** CVE-2019-0708 (BlueKeep)  
**类型:** 远程代码执行  
**风险:** 严重，可能导致远程代码执行，完全控制受影响的系统  
**投毒风险:** 10%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2019-0708](https://github.com/andripwn/CVE-2019-0708)  

---

### [CVE-2019-0708](CVE-2019-0708-Cyb0r9_ispy.md) 🔴 ✅

**名称:** CVE-2019-0708-Remote Desktop Services Remote Code Execution Vulnerability (BlueKeep)  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的攻击者可以利用RDP发送特制请求在目标系统上执行任意代码。  
**投毒风险:** 5%  
**发现时间:** 2025-04-30  
**POC仓库:** [ispy](https://github.com/Cyb0r9/ispy)  

---

### [CVE-2019-0708](CVE-2019-0708-tranqtruong_Detect-BlueKeep.md) 🔴 ✅

**名称:** CVE-2019-0708 (BlueKeep)  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致系统完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-04-30  
**POC仓库:** [Detect-BlueKeep](https://github.com/tranqtruong/Detect-BlueKeep)  

---

### [CVE-2019-0708](CVE-2019-0708-hualy13_CVE-2019-0708-Check.md) 🔴 ✅

**名称:** CVE-2019-0708 (BlueKeep)  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2019-0708-Check](https://github.com/hualy13/CVE-2019-0708-Check)  

---

### [CVE-2024-40635](CVE-2024-40635-yen5004_CVE-2024-40635_POC.md) 🟡 ✅

**名称:** CVE-2024-40635-containerd-Integer Overflow  
**类型:** Integer Overflow  
**风险:** 中危，可能导致容器以root权限运行  
**投毒风险:** 5%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2024-40635_POC](https://github.com/yen5004/CVE-2024-40635_POC)  

---

### [CVE-2024-6387](CVE-2024-6387-kubota_CVE-2024-6387-Vulnerability-Checker.md) 🔴 ✅

**名称:** CVE-2024-6387-OpenSSH RegreSSHion 漏洞  
**类型:** 竞争条件漏洞  
**风险:** 高危，可能导致远程代码执行或拒绝服务  
**投毒风险:** 0%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2024-6387-Vulnerability-Checker](https://github.com/kubota/CVE-2024-6387-Vulnerability-Checker)  

---

### [CVE-2024-6387](CVE-2024-6387-DimaMend_cve-2024-6387-poc.md) 🔴 ✅

**名称:** CVE-2024-6387-OpenSSH-竞争条件RCE/DoS  
**类型:** 竞争条件  
**风险:** 高危，可能导致远程代码执行(RCE)和拒绝服务(DoS)  
**投毒风险:** 1%  
**发现时间:** 2025-04-30  
**POC仓库:** [cve-2024-6387-poc](https://github.com/DimaMend/cve-2024-6387-poc)  

---

### [CVE-2024-6387](CVE-2024-6387-filipi86_CVE-2024-6387-Vulnerability-Checker.md) 🔴 ✅

**名称:** CVE-2024-6387-OpenSSH-竞争条件  
**类型:** 竞争条件  
**风险:** 高危，可能导致远程代码执行或拒绝服务  
**投毒风险:** 0%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2024-6387-Vulnerability-Checker](https://github.com/filipi86/CVE-2024-6387-Vulnerability-Checker)  

---

### [CVE-2024-6387](CVE-2024-6387-anhvutuan_CVE-2024-6387-poc-1.md) 🔴 ✅

**名称:** CVE-2024-6387 - OpenSSH regreSSHion 漏洞  
**类型:** 竞争条件漏洞  
**风险:** 高危，可能导致远程代码执行或拒绝服务  
**投毒风险:** 0%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2024-6387-poc-1](https://github.com/anhvutuan/CVE-2024-6387-poc-1)  

---

### [CVE-2024-6387](CVE-2024-6387-redux-sibi-jose_mitigate_ssh.md) 🔴 ✅

**名称:** CVE-2024-6387-OpenSSH-竞争条件  
**类型:** 竞争条件  
**风险:** 高危，可能导致远程代码执行和拒绝服务  
**投毒风险:** 0%  
**发现时间:** 2025-04-30  
**POC仓库:** [mitigate_ssh](https://github.com/redux-sibi-jose/mitigate_ssh)  

---

### [CVE-2024-6387](CVE-2024-6387-ThatNotEasy_CVE-2024-6387.md) 🔴 ✅

**名称:** CVE-2024-6387-OpenSSH-竞争条件导致RCE/DoS  
**类型:** 竞争条件  
**风险:** 高危，可能导致远程代码执行和拒绝服务  
**投毒风险:** 1%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2024-6387](https://github.com/ThatNotEasy/CVE-2024-6387)  

---

### [CVE-2024-6387](CVE-2024-6387-wiggels_regresshion-check.md) 🔴 ✅

**名称:** CVE-2024-6387 - OpenSSH RegreSSHion 漏洞  
**类型:** 竞争条件  
**风险:** 高危，可能导致远程代码执行和拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-04-30  
**POC仓库:** [regresshion-check](https://github.com/wiggels/regresshion-check)  

---

### [CVE-2024-6387](CVE-2024-6387-prelearn-code_CVE-2024-6387.md) 🔴 ✅

**名称:** CVE-2024-6387 - OpenSSH regreSSHion 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致完全控制受影响系统  
**投毒风险:** 10%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2024-6387](https://github.com/prelearn-code/CVE-2024-6387)  

---

### [CVE-2024-6387](CVE-2024-6387-lflare_cve-2024-6387-poc.md) 🔴 ✅

**名称:** CVE-2024-6387-OpenSSH-竞争条件  
**类型:** 竞争条件  
**风险:** 高危，可能导致远程代码执行或拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-04-30  
**POC仓库:** [cve-2024-6387-poc](https://github.com/lflare/cve-2024-6387-poc)  

---

### [CVE-2024-6387](CVE-2024-6387-alex14324_ssh_poc2024.md) 🔴 ✅

**名称:** CVE-2024-6387-OpenSSH-竞争条件RCE/DoS  
**类型:** 竞争条件  
**风险:** 高危，可能导致远程代码执行（RCE）和拒绝服务（DoS）  
**投毒风险:** 10%  
**发现时间:** 2025-04-30  
**POC仓库:** [ssh_poc2024](https://github.com/alex14324/ssh_poc2024)  

---

### [CVE-2024-6387](CVE-2024-6387-jocker2410_CVE-2024-6387_poc.md) 🔴 ✅

**名称:** CVE-2024-6387 OpenSSH regreSSHion 漏洞  
**类型:** 竞争条件漏洞  
**风险:** 高危，可能导致远程代码执行或拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2024-6387_poc](https://github.com/jocker2410/CVE-2024-6387_poc)  

---

### [CVE-2024-6387](CVE-2024-6387-s1d6point7bugcrowd_CVE-2024-6387-Race-Condition-in-Signal-Handling-for-OpenSSH.md) 🔴 ✅

**名称:** CVE-2024-6387-OpenSSH-信号处理竞争条件  
**类型:** 信号处理竞争条件  
**风险:** 高危，可能导致远程代码执行或拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2024-6387-Race-Condition-in-Signal-Handling-for-OpenSSH](https://github.com/s1d6point7bugcrowd/CVE-2024-6387-Race-Condition-in-Signal-Handling-for-OpenSSH)  

---

### [CVE-2024-6387](CVE-2024-6387-almogopp_OpenSSH-CVE-2024-6387-Fix.md) 🔴 ✅

**名称:** CVE-2024-6387-OpenSSH-信号处理竞争条件  
**类型:** 信号处理竞争条件  
**风险:** 高危，可能导致远程代码执行或拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-04-30  
**POC仓库:** [OpenSSH-CVE-2024-6387-Fix](https://github.com/almogopp/OpenSSH-CVE-2024-6387-Fix)  

---

### [CVE-2024-6387](CVE-2024-6387-Karmakstylez_CVE-2024-6387.md) 🔴 ✅

**名称:** CVE-2024-6387-OpenSSH-竞争条件  
**类型:** 竞争条件  
**风险:** 高危，可能导致远程代码执行或拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2024-6387](https://github.com/Karmakstylez/CVE-2024-6387)  

---

### [CVE-2024-6387](CVE-2024-6387-HadesNull123_CVE-2024-6387_Check.md) 🔴 ✅

**名称:** CVE-2024-6387-OpenSSH-竞争条件导致RCE/DoS  
**类型:** 竞争条件  
**风险:** 高危，可能导致远程代码执行和拒绝服务  
**投毒风险:** 30%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2024-6387_Check](https://github.com/HadesNull123/CVE-2024-6387_Check)  

---

### [CVE-2024-6387](CVE-2024-6387-identity-threat-labs_CVE-2024-6387-Vulnerability-Checker.md) 🔴 ✅

**名称:** CVE-2024-6387-OpenSSH-竞争条件  
**类型:** 竞争条件  
**风险:** 高危，可能导致远程代码执行和拒绝服务  
**投毒风险:** 0%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2024-6387-Vulnerability-Checker](https://github.com/identity-threat-labs/CVE-2024-6387-Vulnerability-Checker)  

---

### [CVE-2024-6387](CVE-2024-6387-identity-threat-labs_Article-RegreSSHion-CVE-2024-6387.md) 🔴 ✅

**名称:** CVE-2024-6387-OpenSSH-regreSSHion  
**类型:** 竞争条件  
**风险:** 高危，可能导致远程代码执行和拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-04-30  
**POC仓库:** [Article-RegreSSHion-CVE-2024-6387](https://github.com/identity-threat-labs/Article-RegreSSHion-CVE-2024-6387)  

---

### [CVE-2024-6387](CVE-2024-6387-l-urk_CVE-2024-6387.md) 🔴 ✅

**名称:** CVE-2024-6387 OpenSSH regreSSHion 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未授权的远程攻击者可以利用此漏洞以 root 权限执行任意代码，或者造成拒绝服务。  
**投毒风险:** 10%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2024-6387](https://github.com/l-urk/CVE-2024-6387)  

---

### [CVE-2024-6387](CVE-2024-6387-YassDEV221608_CVE-2024-6387.md) 🔴 ✅

**名称:** CVE-2024-6387 - OpenSSH RegreSSHion 远程代码执行/拒绝服务  
**类型:** 竞争条件  
**风险:** 高危，可能导致远程代码执行和拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2024-6387](https://github.com/YassDEV221608/CVE-2024-6387)  

---

### [CVE-2024-6387](CVE-2024-6387-zql-gif_CVE-2024-6387.md) 🔴 ✅

**名称:** CVE-2024-6387 - OpenSSH regreSSHion 漏洞  
**类型:** 信号处理竞争条件  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2024-6387](https://github.com/zql-gif/CVE-2024-6387)  

---

### [CVE-2024-6387](CVE-2024-6387-awusan125_test_for6387.md) 🔴 ✅

**名称:** CVE-2024-6387 - OpenSSH RegreSSHion 漏洞  
**类型:** 竞争条件漏洞  
**风险:** 高危，可能导致远程代码执行 (RCE) 或拒绝服务 (DoS)  
**投毒风险:** 20%  
**发现时间:** 2025-04-30  
**POC仓库:** [test_for6387](https://github.com/awusan125/test_for6387)  

---

### [CVE-2024-6387](CVE-2024-6387-YassDEV221608_CVE-2024-6387_PoC.md) 🔴 ✅

**名称:** CVE-2024-6387 OpenSSH regreSSHion 漏洞  
**类型:** 竞争条件漏洞  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2024-6387_PoC](https://github.com/YassDEV221608/CVE-2024-6387_PoC)  

---

### [CVE-2024-6387](CVE-2024-6387-dream434_CVE-2024-6387.md) 🔴 ✅

**名称:** CVE-2024-6387-OpenSSH-竞争条件  
**类型:** 竞争条件  
**风险:** 高危，可能导致远程代码执行或拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2024-6387](https://github.com/dream434/CVE-2024-6387)  

---

### [CVE-2024-6387](CVE-2024-6387-xaitax_CVE-2024-6387_Check.md) 🔴 ✅

**名称:** CVE-2024-6387-OpenSSH-竞争条件  
**类型:** 竞争条件  
**风险:** 高危，可能导致远程代码执行或拒绝服务  
**投毒风险:** 1%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2024-6387_Check](https://github.com/xaitax/CVE-2024-6387_Check)  

---

### [CVE-2019-0708](CVE-2019-0708-adyanamul_Remote-Code-Execution-RCE-Exploit-BlueKeep-CVE-2019-0708-PoC.md) 🔴 ✅

**名称:** CVE-2019-0708 (BlueKeep) RDP远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，无需身份验证即可远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-30  
**POC仓库:** [Remote-Code-Execution-RCE-Exploit-BlueKeep-CVE-2019-0708-PoC](https://github.com/adyanamul/Remote-Code-Execution-RCE-Exploit-BlueKeep-CVE-2019-0708-PoC)  

---

### [CVE-2025-31324](CVE-2025-31324-respondiq_jsp-webshell-scanner.md) 🔴 ✅

**名称:** CVE-2025-31324 SAP NetWeaver Visual Composer 未授权文件上传  
**类型:** 未授权文件上传  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-30  
**POC仓库:** [jsp-webshell-scanner](https://github.com/respondiq/jsp-webshell-scanner)  

---

### [CVE-2019-0708](CVE-2019-0708-AaronCaiii_CVE-2019-0708-POC.md) 🔴 ✅

**名称:** CVE-2019-0708-BlueKeep  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2019-0708-POC](https://github.com/AaronCaiii/CVE-2019-0708-POC)  

---

### [CVE-2019-0708](CVE-2019-0708-algo7_bluekeep_CVE-2019-0708_poc_to_exploit.md) 🔴 ✅

**名称:** CVE-2019-0708 (BlueKeep)  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的攻击者远程执行代码  
**投毒风险:** 0%  
**发现时间:** 2025-04-30  
**POC仓库:** [bluekeep_CVE-2019-0708_poc_to_exploit](https://github.com/algo7/bluekeep_CVE-2019-0708_poc_to_exploit)  

---

### [CVE-2019-0708](CVE-2019-0708-go-bi_CVE-2019-0708-EXP-Windows.md)  ✅

**名称:** CVE-2019-0708 - BlueKeep RDP远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 严重，可能导致完全控制目标系统  
**投毒风险:** 0%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2019-0708-EXP-Windows](https://github.com/go-bi/CVE-2019-0708-EXP-Windows)  

---

### [CVE-2019-0708](CVE-2019-0708-Pa55w0rd_CVE-2019-0708.md)  ✅

**名称:** CVE-2019-0708 (BlueKeep)  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，未经身份验证的攻击者可以远程执行代码  
**投毒风险:** 5%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2019-0708](https://github.com/Pa55w0rd/CVE-2019-0708)  

---

### [CVE-2019-0708](CVE-2019-0708-at0mik_CVE-2019-0708-PoC.md) 🔴 

**名称:** CVE-2019-0708 (BlueKeep)  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致远程代码执行和系统控制  
**投毒风险:** 70%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2019-0708-PoC](https://github.com/at0mik/CVE-2019-0708-PoC)  

---

### [CVE-2019-0708](CVE-2019-0708-CircuitSoul_CVE-2019-0708.md) 🔴 ✅

**名称:** CVE-2019-0708 (BlueKeep) RDP远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者远程执行代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2019-0708](https://github.com/CircuitSoul/CVE-2019-0708)  

---

### [CVE-2019-0708](CVE-2019-0708-pywc_CVE-2019-0708.md) 🔴 ✅

**名称:** CVE-2019-0708 (BlueKeep)  
**类型:** 远程代码执行  
**风险:** 高危，可远程代码执行，可能导致系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2019-0708](https://github.com/pywc/CVE-2019-0708)  

---

### [CVE-2019-0708](CVE-2019-0708-lisinan988_CVE-2019-0708-scan.md) 🔴 ✅

**名称:** CVE-2019-0708 (BlueKeep)  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2019-0708-scan](https://github.com/lisinan988/CVE-2019-0708-scan)  

---

### [CVE-2019-0708](CVE-2019-0708-Ekultek_BlueKeep.md) 🔴 ✅

**名称:** CVE-2019-0708 (BlueKeep)  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者在目标系统上远程执行代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-30  
**POC仓库:** [BlueKeep](https://github.com/Ekultek/BlueKeep)  

---

### [CVE-2019-0708](CVE-2019-0708-offensity_CVE-2019-0708.md)  ✅

**名称:** CVE-2019-0708-Remote Desktop Services Remote Code Execution Vulnerability (BlueKeep)  
**类型:** 远程代码执行  
**风险:** 严重，可能导致系统完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2019-0708](https://github.com/offensity/CVE-2019-0708)  

---

### [CVE-2019-0708](CVE-2019-0708-RICSecLab_CVE-2019-0708.md) 🔴 ✅

**名称:** CVE-2019-0708 (BlueKeep)  
**类型:** 远程代码执行  
**风险:** 高危，可能导致完全系统控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2019-0708](https://github.com/RICSecLab/CVE-2019-0708)  

---

### [CVE-2019-0708](CVE-2019-0708-CPT-Jack-A-Castle_Haruster-CVE-2019-0708-Exploit.md) 🔴 ✅

**名称:** CVE-2019-0708 (BlueKeep)  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致系统完全控制  
**投毒风险:** 99%  
**发现时间:** 2025-04-30  
**POC仓库:** [Haruster-CVE-2019-0708-Exploit](https://github.com/CPT-Jack-A-Castle/Haruster-CVE-2019-0708-Exploit)  

---

### [CVE-2019-0708](CVE-2019-0708-Ravaan21_Bluekeep-Hunter.md) 🔴 ✅

**名称:** CVE-2019-0708 (BlueKeep)  
**类型:** 远程代码执行  
**风险:** 高危，可能导致系统完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-30  
**POC仓库:** [Bluekeep-Hunter](https://github.com/Ravaan21/Bluekeep-Hunter)  

---

### [CVE-2019-0708](CVE-2019-0708-davidfortytwo_bluekeep.md)  ✅

**名称:** CVE-2019-0708-Windows RDP 远程代码执行  
**类型:** 远程代码执行  
**风险:** 严重，可能导致系统完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-30  
**POC仓库:** [bluekeep](https://github.com/davidfortytwo/bluekeep)  

---

### [CVE-2019-0708](CVE-2019-0708-isabelacostaz_CVE-2019-0708-POC.md) 🔴 ✅

**名称:** CVE-2019-0708-Windows-RDP远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致完全控制受影响的系统  
**投毒风险:** 10%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2019-0708-POC](https://github.com/isabelacostaz/CVE-2019-0708-POC)  

---

### [CVE-2025-31324](CVE-2025-31324-nullcult_CVE-2025-31324-File-Upload.md) 🔴 ✅

**名称:** CVE-2025-31324-SAP NetWeaver Visual Composer Metadata Uploader 未授权文件上传  
**类型:** 未授权文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2025-31324-File-Upload](https://github.com/nullcult/CVE-2025-31324-File-Upload)  

---

### [CVE-2025-31650](CVE-2025-31650-tunahantekeoglu_CVE-2025-31650.md) 🔴 ✅

**名称:** CVE-2025-31650 Apache Tomcat DoS  
**类型:** DoS (拒绝服务)  
**风险:** 高危，可能导致服务中断  
**投毒风险:** 0%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2025-31650](https://github.com/tunahantekeoglu/CVE-2025-31650)  

---

### [CVE-2024-36401](CVE-2024-36401-amoy6228_CVE-2024-36401_Geoserver_RCE_POC.md) 🔴 ✅

**名称:** CVE-2024-36401-GeoServer-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2024-36401_Geoserver_RCE_POC](https://github.com/amoy6228/CVE-2024-36401_Geoserver_RCE_POC)  

---

### [CVE-2025-21756](CVE-2025-21756-mr-spongebob_CVE-2025-21756.md) 🔴 ✅

**名称:** CVE-2025-21756-Linux Kernel vsock Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可能导致权限提升和内核崩溃  
**投毒风险:** 10%  
**发现时间:** 2025-04-30  
**POC仓库:** [CVE-2025-21756](https://github.com/mr-spongebob/CVE-2025-21756)  

---

### [CVE-2025-31324](CVE-2025-31324-BlueOWL-overlord_Burp_CVE-2025-31324.md) 🔴 ✅

**名称:** CVE-2025-31324-SAP NetWeaver Visual Composer-未授权文件上传  
**类型:** 未授权文件上传  
**风险:** 高危，远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-30  
**POC仓库:** [Burp_CVE-2025-31324](https://github.com/BlueOWL-overlord/Burp_CVE-2025-31324)  

---

### [CVE-2025-31650](CVE-2025-31650-absholi7ly_TomcatKiller-CVE-2025-31650.md) 🔴 ✅

**名称:** CVE-2025-31650-Apache Tomcat-DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致服务不可用  
**投毒风险:** 5%  
**发现时间:** 2025-04-30  
**POC仓库:** [TomcatKiller-CVE-2025-31650](https://github.com/absholi7ly/TomcatKiller-CVE-2025-31650)  

---

### [CVE-2025-29775](CVE-2025-29775-twypsy_cve-2025-29775.md) 🔴 ✅

**名称:** CVE-2025-29775-xml-crypto-XML签名验证绕过  
**类型:** XML签名验证绕过  
**风险:** 高危，可能导致身份验证绕过、权限提升和数据篡改  
**投毒风险:** 0%  
**发现时间:** 2025-04-30  
**POC仓库:** [cve-2025-29775](https://github.com/twypsy/cve-2025-29775)  

---

### [CVE-2023-32243](CVE-2023-32243-manavvedawala2_CVE-2023-32243-proof-of-concept.md) 🔴 ✅

**名称:** CVE-2023-32243 - Essential Addons for Elementor Privilege Escalation  
**类型:** 权限提升  
**风险:** 高危，可导致任意用户密码重置和权限提升  
**投毒风险:** 1%  
**发现时间:** 2025-04-29  
**POC仓库:** [CVE-2023-32243-proof-of-concept](https://github.com/manavvedawala2/CVE-2023-32243-proof-of-concept)  

---

### [CVE-2023-32243](CVE-2023-32243-YouGina_CVE-2023-32243.md) 🔴 ✅

**名称:** CVE-2023-32243-Essential Addons for Elementor-权限提升  
**类型:** 权限提升  
**风险:** 高危，攻击者可以未经授权地获得管理员权限  
**投毒风险:** 0%  
**发现时间:** 2025-04-29  
**POC仓库:** [CVE-2023-32243](https://github.com/YouGina/CVE-2023-32243)  

---

### [CVE-2023-32243](CVE-2023-32243-gbrsh_CVE-2023-32243.md) 🔴 ✅

**名称:** CVE-2023-32243-Essential Addons for Elementor-Privilege Escalation  
**类型:** 权限提升  
**风险:** 高危，可能导致账户接管  
**投毒风险:** 10%  
**发现时间:** 2025-04-29  
**POC仓库:** [CVE-2023-32243](https://github.com/gbrsh/CVE-2023-32243)  

---

### [CVE-2023-32243](CVE-2023-32243-Jenderal92_WP-CVE-2023-32243.md) 🔴 ✅

**名称:** CVE-2023-32243 - Essential Addons for Elementor - 权限提升  
**类型:** 权限提升  
**风险:** 高危，可能导致未经授权的管理员权限访问  
**投毒风险:** 5%  
**发现时间:** 2025-04-29  
**POC仓库:** [WP-CVE-2023-32243](https://github.com/Jenderal92/WP-CVE-2023-32243)  

---

### [CVE-2025-32433](CVE-2025-32433-C9b3rD3vi1_Erlang-OTP-SSH-CVE-2025-32433.md)  ✅

**名称:** CVE-2025-32433-Erlang/OTP SSH-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，未经身份验证的远程代码执行  
**投毒风险:** 2%  
**发现时间:** 2025-04-29  
**POC仓库:** [Erlang-OTP-SSH-CVE-2025-32433](https://github.com/C9b3rD3vi1/Erlang-OTP-SSH-CVE-2025-32433)  

---

### [CVE-2023-32243](CVE-2023-32243-little44n1o_cve-2023-32243.md) 🔴 ✅

**名称:** CVE-2023-32243 - Essential Addons for Elementor - Privilege Escalation  
**类型:** 权限提升  
**风险:** 高危，允许未授权用户重置任意用户的密码并提升权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-29  
**POC仓库:** [cve-2023-32243](https://github.com/little44n1o/cve-2023-32243)  

---

### [CVE-2023-32243](CVE-2023-32243-thatonesecguy_Wordpress-Vulnerability-Identification-Scripts.md) 🔴 ✅

**名称:** CVE-2023-32243 - Essential Addons for Elementor - 权限提升  
**类型:** 权限提升  
**风险:** 高危，可能导致账户控制和数据篡改  
**投毒风险:** 1%  
**发现时间:** 2025-04-29  
**POC仓库:** [Wordpress-Vulnerability-Identification-Scripts](https://github.com/thatonesecguy/Wordpress-Vulnerability-Identification-Scripts)  

---

### [CVE-2023-32243](CVE-2023-32243-RandomRobbieBF_CVE-2023-32243.md) 🔴 ✅

**名称:** CVE-2023-32243 - Essential Addons for Elementor - 权限提升  
**类型:** 权限提升  
**风险:** 高危，可能导致网站被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-29  
**POC仓库:** [CVE-2023-32243](https://github.com/RandomRobbieBF/CVE-2023-32243)  

---

### [CVE-2023-32243](CVE-2023-32243-shaoyu521_Mass-CVE-2023-32243.md) 🔴 ✅

**名称:** CVE-2023-32243 - Essential Addons for Elementor Privilege Escalation  
**类型:** 权限提升  
**风险:** 高危，可能导致任意用户密码重置和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-04-29  
**POC仓库:** [Mass-CVE-2023-32243](https://github.com/shaoyu521/Mass-CVE-2023-32243)  

---

### [CVE-2023-32243](CVE-2023-32243-dev0558_CVE-2023-32243-Detection-and-Mitigation-in-WordPress.md)  ✅

**名称:** CVE-2023-32243 - Essential Addons for Elementor - 权限提升  
**类型:** 权限提升  
**风险:** 严重，可能导致完全控制WordPress网站  
**投毒风险:** 10%  
**发现时间:** 2025-04-29  
**POC仓库:** [CVE-2023-32243-Detection-and-Mitigation-in-WordPress](https://github.com/dev0558/CVE-2023-32243-Detection-and-Mitigation-in-WordPress)  

---

### [CVE-2025-32433](CVE-2025-32433-ODST-Forge_CVE-2025-32433.md) 🔴 ✅

**名称:** CVE-2025-32433 Erlang/OTP SSH 预认证RCE  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程攻击者可以执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-04-29  
**POC仓库:** [CVE-2025-32433](https://github.com/ODST-Forge/CVE-2025-32433)  

---

### [CVE-2025-32433](CVE-2025-32433-abrewer251_CVE-2025-32433_Erlang-OTP.md) 🔴 ✅

**名称:** CVE-2025-32433 Erlang/OTP SSH 未授权远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，未授权远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-29  
**POC仓库:** [CVE-2025-32433_Erlang-OTP](https://github.com/abrewer251/CVE-2025-32433_Erlang-OTP)  

---

### [CVE-2017-12617](CVE-2017-12617-devcoinfet_CVE-2017-12617.md) 🔴 ✅

**名称:** CVE-2017-12617-Apache Tomcat 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-29  
**POC仓库:** [CVE-2017-12617](https://github.com/devcoinfet/CVE-2017-12617)  

---

### [CVE-2017-12617](CVE-2017-12617-ygouzerh_CVE-2017-12617.md) 🔴 ✅

**名称:** CVE-2017-12617 - Apache Tomcat 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-29  
**POC仓库:** [CVE-2017-12617](https://github.com/ygouzerh/CVE-2017-12617)  

---

### [CVE-2017-12617](CVE-2017-12617-tyranteye666_tomcat-cve-2017-12617.md) 🔴 ✅

**名称:** CVE-2017-12617 - Apache Tomcat JSP上传RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许攻击者在服务器上执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-29  
**POC仓库:** [tomcat-cve-2017-12617](https://github.com/tyranteye666/tomcat-cve-2017-12617)  

---

### [CVE-2017-12617](CVE-2017-12617-qiantu88_CVE-2017-12617.md) 🔴 ✅

**名称:** CVE-2017-12617-Apache Tomcat-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-29  
**POC仓库:** [CVE-2017-12617](https://github.com/qiantu88/CVE-2017-12617)  

---

### [CVE-2017-12617](CVE-2017-12617-jptr218_tc_hack.md) 🔴 ✅

**名称:** CVE-2017-12617-Apache Tomcat-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-29  
**POC仓库:** [tc_hack](https://github.com/jptr218/tc_hack)  

---

### [CVE-2017-12617](CVE-2017-12617-LongWayHomie_CVE-2017-12617.md) 🔴 ✅

**名称:** CVE-2017-12617-Apache Tomcat-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-29  
**POC仓库:** [CVE-2017-12617](https://github.com/LongWayHomie/CVE-2017-12617)  

---

### [CVE-2017-12617](CVE-2017-12617-scirusvulgaris_CVE-2017-12617.md) 🔴 ✅

**名称:** CVE-2017-12617-Apache Tomcat-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-29  
**POC仓库:** [CVE-2017-12617](https://github.com/scirusvulgaris/CVE-2017-12617)  

---

### [CVE-2017-12617](CVE-2017-12617-DevaDJ_CVE-2017-12617.md) 🔴 ✅

**名称:** CVE-2017-12617-Apache Tomcat-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-29  
**POC仓库:** [CVE-2017-12617](https://github.com/DevaDJ/CVE-2017-12617)  

---

### [CVE-2017-12617](CVE-2017-12617-K3ysTr0K3R_CVE-2017-12617-EXPLOIT.md) 🔴 ✅

**名称:** CVE-2017-12617-Apache Tomcat Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-29  
**POC仓库:** [CVE-2017-12617-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2017-12617-EXPLOIT)  

---

### [CVE-2017-12617](CVE-2017-12617-yZeetje_CVE-2017-12617.md) 🔴 ✅

**名称:** CVE-2017-12617-Apache Tomcat-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-04-29  
**POC仓库:** [CVE-2017-12617](https://github.com/yZeetje/CVE-2017-12617)  

---

### [CVE-2017-12617](CVE-2017-12617-ducknuts_network-forensics-cve-2017-12617.md) 🔴 ✅

**名称:** CVE-2017-12617-Apache Tomcat-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-29  
**POC仓库:** [network-forensics-cve-2017-12617](https://github.com/ducknuts/network-forensics-cve-2017-12617)  

---

### [CVE-2017-12617](CVE-2017-12617-cyberheartmi9_CVE-2017-12617.md) 🔴 ✅

**名称:** CVE-2017-12617-Apache Tomcat-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-29  
**POC仓库:** [CVE-2017-12617](https://github.com/cyberheartmi9/CVE-2017-12617)  

---

### [CVE-2024-3400](CVE-2024-3400-CyprianAtsyor_letsdefend-cve2024-3400-case-study.md) 🔴 ✅

**名称:** CVE-2024-3400 PAN-OS GlobalProtect 远程命令执行  
**类型:** 命令注入  
**风险:** 高危，未授权远程命令执行，可完全控制防火墙  
**投毒风险:** 10%  
**发现时间:** 2025-04-29  
**POC仓库:** [letsdefend-cve2024-3400-case-study](https://github.com/CyprianAtsyor/letsdefend-cve2024-3400-case-study)  

---

### [CVE-2025-29927](CVE-2025-29927-rubbxalc_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-中间件授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-04-29  
**POC仓库:** [CVE-2025-29927](https://github.com/rubbxalc/CVE-2025-29927)  

---

### [CVE-2025-31324](CVE-2025-31324-Pengrey_CVE-2025-31324.md) 🔴 ✅

**名称:** CVE-2025-31324 - SAP NetWeaver Visual Composer 未授权文件上传  
**类型:** 未授权文件上传  
**风险:** 高危，可能导致远程代码执行和系统完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-29  
**POC仓库:** [CVE-2025-31324](https://github.com/Pengrey/CVE-2025-31324)  

---

### [CVE-2025-26014](CVE-2025-26014-vigilante-1337_CVE-2025-26014.md) 🔴 ✅

**名称:** CVE-2025-26014 - Loggrove v.1.0 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许远程攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-29  
**POC仓库:** [CVE-2025-26014](https://github.com/vigilante-1337/CVE-2025-26014)  

---

### [CVE-2025-29927](CVE-2025-29927-HoumanPashaei_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js中间件授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问敏感资源  
**投毒风险:** 10%  
**发现时间:** 2025-04-29  
**POC仓库:** [CVE-2025-29927](https://github.com/HoumanPashaei/CVE-2025-29927)  

---

### [CVE-2021-33026](CVE-2021-33026-CarlosG13_CVE-2021-33026.md) 🔴 ✅

**名称:** CVE-2021-33026 - Flask-Caching Pickle 反序列化导致远程代码执行  
**类型:** 反序列化漏洞  
**风险:** 高危，可能导致远程代码执行或本地提权  
**投毒风险:** 1%  
**发现时间:** 2025-04-29  
**POC仓库:** [CVE-2021-33026](https://github.com/CarlosG13/CVE-2021-33026)  

---

### [CVE-2021-33026](CVE-2021-33026-Agilevatester_FlaskCache_CVE-2021-33026_POC.md) 🔴 ✅

**名称:** CVE-2021-33026 Flask-Caching Pickle 反序列化 RCE  
**类型:** 反序列化漏洞  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-29  
**POC仓库:** [FlaskCache_CVE-2021-33026_POC](https://github.com/Agilevatester/FlaskCache_CVE-2021-33026_POC)  

---

### [CVE-2025-24091](CVE-2025-24091-cyruscostini_CVE-2025-24091.md) 🔴 ✅

**名称:** CVE-2025-24091 - iOS 设备永久拒绝服务漏洞  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可导致设备无法使用，需要完全擦除和恢复  
**投毒风险:** 10%  
**发现时间:** 2025-04-29  
**POC仓库:** [CVE-2025-24091](https://github.com/cyruscostini/CVE-2025-24091)  

---

### [CVE-2022-25012](CVE-2022-25012-s3l33_CVE-2022-25012.md) 🟡 ✅

**名称:** CVE-2022-25012 - Argus Surveillance DVR v4.0 弱密码加密  
**类型:** 弱密码加密  
**风险:** 中危，可能导致未授权访问设备配置和视频数据  
**投毒风险:** 5%  
**发现时间:** 2025-04-29  
**POC仓库:** [CVE-2022-25012](https://github.com/s3l33/CVE-2022-25012)  

---

### [CVE-2022-25012](CVE-2022-25012-G4sp4rCS_CVE-2022-25012-POC.md) 🟡 ✅

**名称:** CVE-2022-25012-Argus Surveillance DVR v4.0 弱密码加密  
**类型:** 弱密码加密  
**风险:** 中危，可能导致未经授权的访问和控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-29  
**POC仓库:** [CVE-2022-25012-POC](https://github.com/G4sp4rCS/CVE-2022-25012-POC)  

---

### [CVE-2025-31324](CVE-2025-31324-abrewer251_CVE-2025-31324_PoC_SAP.md) 🔴 ✅

**名称:** CVE-2025-31324-SAP NetWeaver Visual Composer-未授权文件上传  
**类型:** 未授权文件上传  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-29  
**POC仓库:** [CVE-2025-31324_PoC_SAP](https://github.com/abrewer251/CVE-2025-31324_PoC_SAP)  

---

### [CVE-2025-46701](CVE-2025-46701-gregk4sec_CVE-2025-46701.md)  

**名称:** 未知漏洞  
**类型:** 未知  
**风险:** 无法评估  
**投毒风险:** 100%  
**发现时间:** 2025-04-29  
**POC仓库:** [CVE-2025-46701](https://github.com/gregk4sec/CVE-2025-46701)  

---

### [CVE-2024-40110](CVE-2024-40110-Abdurahmon3236_CVE-2024-40110.md) 🔴 ✅

**名称:** CVE-2024-40110 - Sourcecodester Poultry Farm Management System v1.0 - Unauthenticated Remote Code Execution  
**类型:** Remote Code Execution (RCE)  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2024-40110](https://github.com/Abdurahmon3236/CVE-2024-40110)  

---

### [CVE-2024-40110](CVE-2024-40110-thiagosmith_CVE-2024-40110.md) 🔴 ✅

**名称:** CVE-2024-40110 - Poultry Farm Management System v1.0 - 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2024-40110](https://github.com/thiagosmith/CVE-2024-40110)  

---

### [CVE-2025-31324](CVE-2025-31324-ODST-Forge_CVE-2025-31324_PoC.md) 🔴 ✅

**名称:** CVE-2025-31324 - SAP NetWeaver Visual Composer 未授权文件上传  
**类型:** 未授权文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2025-31324_PoC](https://github.com/ODST-Forge/CVE-2025-31324_PoC)  

---

### [CVE-2025-32433](CVE-2025-32433-Know56_CVE-2025-32433.md) 🔴 ✅

**名称:** CVE-2025-32433-Erlang/OTP-SSH-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2025-32433](https://github.com/Know56/CVE-2025-32433)  

---

### [CVE-2022-26265](CVE-2022-26265-redteamsecurity2023_CVE-2022-26265.md) 🔴 ✅

**名称:** CVE-2022-26265-Contao CMS-RCE  
**类型:** 远程代码执行(RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2022-26265](https://github.com/redteamsecurity2023/CVE-2022-26265)  

---

### [CVE-2022-26265](CVE-2022-26265-SystemVll_CVE-2022-26265.md) 🔴 ✅

**名称:** CVE-2022-26265-Contao Managed Edition-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2022-26265](https://github.com/SystemVll/CVE-2022-26265)  

---

### [CVE-2025-30065](CVE-2025-30065-F5-Labs_parquet-canary-exploit-rce-poc-CVE-2025-30065.md)  ✅

**名称:** CVE-2025-30065-Apache Parquet-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-28  
**POC仓库:** [parquet-canary-exploit-rce-poc-CVE-2025-30065](https://github.com/F5-Labs/parquet-canary-exploit-rce-poc-CVE-2025-30065)  

---

### [CVE-2022-29806](CVE-2022-29806-OP3R4T0R_CVE-2022-29806.md) 🔴 ✅

**名称:** CVE-2022-29806-ZoneMinder-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2022-29806](https://github.com/OP3R4T0R/CVE-2022-29806)  

---

### [CVE-2022-29464](CVE-2022-29464-n3rdh4x0r_CVE-2022-29464.md) 🔴 ✅

**名称:** CVE-2022-29464 - WSO2 任意文件上传导致远程代码执行  
**类型:** 任意文件上传/远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2022-29464](https://github.com/n3rdh4x0r/CVE-2022-29464)  

---

### [CVE-2022-29464](CVE-2022-29464-lowkey0808_cve-2022-29464.md) 🔴 ✅

**名称:** CVE-2022-29464 - WSO2 Unrestricted File Upload  
**类型:** 任意文件上传  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-28  
**POC仓库:** [cve-2022-29464](https://github.com/lowkey0808/cve-2022-29464)  

---

### [CVE-2022-29464](CVE-2022-29464-mr-r3bot_WSO2-CVE-2022-29464.md) 🔴 ✅

**名称:** CVE-2022-29464-WSO2-Unrestricted File Upload  
**类型:** 未限制文件上传  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-28  
**POC仓库:** [WSO2-CVE-2022-29464](https://github.com/mr-r3bot/WSO2-CVE-2022-29464)  

---

### [CVE-2022-29464](CVE-2022-29464-hakivvi_CVE-2022-29464.md) 🔴 ✅

**名称:** CVE-2022-29464 - WSO2 任意文件上传导致远程代码执行  
**类型:** 任意文件上传/远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2022-29464](https://github.com/hakivvi/CVE-2022-29464)  

---

### [CVE-2022-29464](CVE-2022-29464-hev0x_CVE-2022-29464.md) 🔴 ✅

**名称:** CVE-2022-29464-WSO2-任意文件上传导致RCE  
**类型:** 任意文件上传导致远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2022-29464](https://github.com/hev0x/CVE-2022-29464)  

---

### [CVE-2022-29464](CVE-2022-29464-superzerosec_CVE-2022-29464.md) 🔴 ✅

**名称:** CVE-2022-29464 - WSO2 任意文件上传导致远程代码执行  
**类型:** 任意文件上传/远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2022-29464](https://github.com/superzerosec/CVE-2022-29464)  

---

### [CVE-2022-29464](CVE-2022-29464-axin2019_CVE-2022-29464.md) 🔴 ✅

**名称:** CVE-2022-29464-WSO2-任意文件上传导致远程代码执行  
**类型:** 任意文件上传  
**风险:** 高危，导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2022-29464](https://github.com/axin2019/CVE-2022-29464)  

---

### [CVE-2022-29464](CVE-2022-29464-LinJacck_CVE-2022-29464.md) 🔴 ✅

**名称:** CVE-2022-29464 - WSO2 任意文件上传导致远程代码执行  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行和服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2022-29464](https://github.com/LinJacck/CVE-2022-29464)  

---

### [CVE-2022-29464](CVE-2022-29464-amit-pathak009_CVE-2022-29464.md) 🔴 ✅

**名称:** CVE-2022-29464 - WSO2 任意文件上传导致远程代码执行  
**类型:** 任意文件上传  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2022-29464](https://github.com/amit-pathak009/CVE-2022-29464)  

---

### [CVE-2022-29464](CVE-2022-29464-amit-pathak009_CVE-2022-29464-mass.md) 🔴 ✅

**名称:** CVE-2022-29464 - WSO2 Unrestricted File Upload  
**类型:** 文件上传/远程代码执行  
**风险:** 高危，可导致未经授权的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2022-29464-mass](https://github.com/amit-pathak009/CVE-2022-29464-mass)  

---

### [CVE-2022-29464](CVE-2022-29464-Chocapikk_CVE-2022-29464.md) 🔴 ✅

**名称:** CVE-2022-29464-WSO2-Unrestricted File Upload  
**类型:** Unrestricted File Upload/Remote Code Execution  
**风险:** 高危，未经授权的文件上传导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2022-29464](https://github.com/Chocapikk/CVE-2022-29464)  

---

### [CVE-2022-29464](CVE-2022-29464-jimidk_Better-CVE-2022-29464.md) 🔴 ✅

**名称:** CVE-2022-29464 - WSO2 Unrestricted File Upload and RCE  
**类型:** 文件上传/远程代码执行  
**风险:** 高危，可导致远程代码执行，完全控制服务器  
**投毒风险:** 0%  
**发现时间:** 2025-04-28  
**POC仓库:** [Better-CVE-2022-29464](https://github.com/jimidk/Better-CVE-2022-29464)  

---

### [CVE-2022-29464](CVE-2022-29464-hxlxmj_Mass-exploit-CVE-2022-29464.md) 🔴 ✅

**名称:** CVE-2022-29464-WSO2-任意文件上传导致远程代码执行  
**类型:** 任意文件上传导致远程代码执行  
**风险:** 高危，可导致远程代码执行，系统完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-28  
**POC仓库:** [Mass-exploit-CVE-2022-29464](https://github.com/hxlxmj/Mass-exploit-CVE-2022-29464)  

---

### [CVE-2022-29464](CVE-2022-29464-g0dxing_CVE-2022-29464.md) 🔴 ✅

**名称:** CVE-2022-29464-WSO2-Unrestricted File Upload RCE  
**类型:** 未限制文件上传导致远程代码执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2022-29464](https://github.com/g0dxing/CVE-2022-29464)  

---

### [CVE-2022-29464](CVE-2022-29464-hupe1980_CVE-2022-29464.md) 🔴 ✅

**名称:** CVE-2022-29464 - WSO2 任意文件上传导致远程代码执行  
**类型:** 任意文件上传  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2022-29464](https://github.com/hupe1980/CVE-2022-29464)  

---

### [CVE-2022-29464](CVE-2022-29464-gbrsh_CVE-2022-29464.md) 🔴 ✅

**名称:** CVE-2022-29464 - WSO2 任意文件上传导致远程代码执行  
**类型:** 任意文件上传 / 远程代码执行  
**风险:** 高危，允许未授权的攻击者上传恶意文件并执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2022-29464](https://github.com/gbrsh/CVE-2022-29464)  

---

### [CVE-2022-29464](CVE-2022-29464-devengpk_CVE-2022-29464.md)  ✅

**名称:** CVE-2022-29464 - WSO2 Unrestricted File Upload RCE  
**类型:** 未限制文件上传导致远程代码执行  
**风险:** 严重，允许未经身份验证的攻击者上传恶意文件并在服务器上执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2022-29464](https://github.com/devengpk/CVE-2022-29464)  

---

### [CVE-2022-29464](CVE-2022-29464-r4x0r1337_-CVE-2022-29464.md) 🔴 ✅

**名称:** CVE-2022-29464 - WSO2 Unrestricted File Upload  
**类型:** 任意文件上传导致远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-04-28  
**POC仓库:** [-CVE-2022-29464](https://github.com/r4x0r1337/-CVE-2022-29464)  

---

### [CVE-2022-29464](CVE-2022-29464-000pp_WSOB.md) 🔴 ✅

**名称:** CVE-2022-29464 - WSO2 任意文件上传导致远程代码执行  
**类型:** 任意文件上传/远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-04-28  
**POC仓库:** [WSOB](https://github.com/000pp/WSOB)  

---

### [CVE-2022-29464](CVE-2022-29464-ThatNotEasy_CVE-2022-29464.md) 🔴 ✅

**名称:** CVE-2022-29464 - WSO2 Unrestricted File Upload  
**类型:** 文件上传漏洞  
**风险:** 高危，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2022-29464](https://github.com/ThatNotEasy/CVE-2022-29464)  

---

### [CVE-2022-29464](CVE-2022-29464-Pushkarup_CVE-2022-29464.md) 🔴 ✅

**名称:** CVE-2022-29464 - WSO2 Unrestricted File Upload RCE  
**类型:** 任意文件上传导致远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2022-29464](https://github.com/Pushkarup/CVE-2022-29464)  

---

### [CVE-2022-29464](CVE-2022-29464-SynixCyberCrimeMy_CVE-2022-29464.md) 🔴 ✅

**名称:** CVE-2022-29464-WSO2-任意文件上传导致远程代码执行  
**类型:** 任意文件上传  
**风险:** 高危，允许未授权用户上传恶意文件并执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2022-29464](https://github.com/SynixCyberCrimeMy/CVE-2022-29464)  

---

### [CVE-2022-29464](CVE-2022-29464-Pasch0_WSO2RCE.md)  ✅

**名称:** CVE-2022-29464-WSO2-Unrestricted File Upload  
**类型:** 任意文件上传  
**风险:** 严重，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-28  
**POC仓库:** [WSO2RCE](https://github.com/Pasch0/WSO2RCE)  

---

### [CVE-2022-29464](CVE-2022-29464-cc3305_CVE-2022-29464.md) 🔴 ✅

**名称:** CVE-2022-29464-WSO2-任意文件上传导致RCE  
**类型:** 任意文件上传  
**风险:** 高危，未经授权的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2022-29464](https://github.com/cc3305/CVE-2022-29464)  

---

### [CVE-2022-29464](CVE-2022-29464-c1ph3rbyt3_CVE-2022-29464.md) 🔴 ✅

**名称:** CVE-2022-29464 - WSO2 任意文件上传导致远程代码执行  
**类型:** 任意文件上传  
**风险:** 高危，未经授权的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2022-29464](https://github.com/c1ph3rbyt3/CVE-2022-29464)  

---

### [CVE-2022-29464](CVE-2022-29464-SystemVll_CVE-2022-29464-loader.md) 🔴 ✅

**名称:** CVE-2022-29464-WSO2-任意文件上传导致远程代码执行  
**类型:** 任意文件上传  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2022-29464-loader](https://github.com/SystemVll/CVE-2022-29464-loader)  

---

### [CVE-2023-27372](CVE-2023-27372-0SPwn_CVE-2023-27372-PoC.md) 🔴 ✅

**名称:** CVE-2023-27372-SPIP-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2023-27372-PoC](https://github.com/0SPwn/CVE-2023-27372-PoC)  

---

### [CVE-2023-27372](CVE-2023-27372-izzz0_CVE-2023-27372-POC.md) 🔴 ✅

**名称:** CVE-2023-27372-SPIP远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2023-27372-POC](https://github.com/izzz0/CVE-2023-27372-POC)  

---

### [CVE-2023-27372](CVE-2023-27372-ThatNotEasy_CVE-2023-27372.md) 🔴 ✅

**名称:** CVE-2023-27372-SPIP-Remote Code Execution  
**类型:** Remote Code Execution  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2023-27372](https://github.com/ThatNotEasy/CVE-2023-27372)  

---

### [CVE-2023-27372](CVE-2023-27372-redboltsec_CVE-2023-27372-PoC.md) 🔴 ✅

**名称:** CVE-2023-27372 SPIP RCE  
**类型:** 远程代码执行  
**风险:** 高危，可完全控制服务器  
**投毒风险:** 0%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2023-27372-PoC](https://github.com/redboltsec/CVE-2023-27372-PoC)  

---

### [CVE-2023-27372](CVE-2023-27372-Chocapikk_CVE-2023-27372.md) 🔴 ✅

**名称:** CVE-2023-27372 SPIP Remote Code Execution  
**类型:** Remote Code Execution (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2023-27372](https://github.com/Chocapikk/CVE-2023-27372)  

---

### [CVE-2023-27372](CVE-2023-27372-1amthebest1_CVE-2023-27372.md) 🔴 ✅

**名称:** CVE-2023-27372-SPIP-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2023-27372](https://github.com/1amthebest1/CVE-2023-27372)  

---

### [CVE-2023-27372](CVE-2023-27372-nuts7_CVE-2023-27372.md) 🔴 ✅

**名称:** CVE-2023-27372-SPIP-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2023-27372](https://github.com/nuts7/CVE-2023-27372)  

---

### [CVE-2023-27372](CVE-2023-27372-dream434_CVE-2023-27372.md) 🔴 ✅

**名称:** CVE-2023-27372-SPIP-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2023-27372](https://github.com/dream434/CVE-2023-27372)  

---

### [CVE-2023-27372](CVE-2023-27372-1Ronkkeli_spip-cve-2023-27372-rce.md) 🔴 ✅

**名称:** CVE-2023-27372-SPIP-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-28  
**POC仓库:** [spip-cve-2023-27372-rce](https://github.com/1Ronkkeli/spip-cve-2023-27372-rce)  

---

### [CVE-2025-31324](CVE-2025-31324-Alizngnc_SAP-CVE-2025-31324.md) 🔴 ✅

**名称:** CVE-2025-31324 - SAP NetWeaver Visual Composer Unauthenticated Remote Code Execution  
**类型:** 未授权文件上传导致远程代码执行  
**风险:** 高危，可能导致系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-28  
**POC仓库:** [SAP-CVE-2025-31324](https://github.com/Alizngnc/SAP-CVE-2025-31324)  

---

### [CVE-2022-23093](CVE-2022-23093-Symbolexe_DrayTek-Exploit.md) 🟡 ✅

**名称:** CVE-2022-23093 FreeBSD ping Stack-Based Overflow  
**类型:** 栈溢出  
**风险:** 中危，可能导致程序崩溃或有限的代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-28  
**POC仓库:** [DrayTek-Exploit](https://github.com/Symbolexe/DrayTek-Exploit)  

---

### [CVE-2022-23093](CVE-2022-23093-SystemVll_CVE-2022-23093.md) 🟡 ✅

**名称:** CVE-2022-23093-FreeBSD-ping-Stack Overflow  
**类型:** Stack Overflow  
**风险:** 中危，可能导致拒绝服务  
**投毒风险:** 0%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2022-23093](https://github.com/SystemVll/CVE-2022-23093)  

---

### [CVE-2025-29927](CVE-2025-29927-hed1ad_my-CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-中间件鉴权绕过  
**类型:** 鉴权绕过  
**风险:** 高危，可能导致未授权访问敏感数据和功能  
**投毒风险:** 0%  
**发现时间:** 2025-04-28  
**POC仓库:** [my-CVE-2025-29927](https://github.com/hed1ad/my-CVE-2025-29927)  

---

### [CVE-2025-29927](CVE-2025-29927-Hirainsingadia_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-中间件鉴权绕过  
**类型:** 鉴权绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2025-29927](https://github.com/Hirainsingadia/CVE-2025-29927)  

---

### [CVE-2024-8418](CVE-2024-8418-goma0x2_CVE-2024-8418.md) 🔴 ✅

**名称:** CVE-2024-8418-aardvark-dns-DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，导致服务不可用  
**投毒风险:** 0%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2024-8418](https://github.com/goma0x2/CVE-2024-8418)  

---

### [CVE-2025-31324](CVE-2025-31324-moften_CVE-2025-31324.md)  ✅

**名称:** CVE-2025-31324-SAP NetWeaver Visual Composer-未授权文件上传  
**类型:** 未授权文件上传  
**风险:** 极高，可能导致远程代码执行，完全控制系统  
**投毒风险:** 0%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2025-31324](https://github.com/moften/CVE-2025-31324)  

---

### [CVE-2025-31324](CVE-2025-31324-moften_CVE-2025-31324-NUCLEI.md) 🔴 ✅

**名称:** CVE-2025-31324-SAP NetWeaver Visual Composer-未授权文件上传  
**类型:** 未授权文件上传  
**风险:** 高危，允许未授权用户上传恶意文件，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2025-31324-NUCLEI](https://github.com/moften/CVE-2025-31324-NUCLEI)  

---

### [CVE-2025-29775](CVE-2025-29775-ethicalPap_CVE-2025-29775.md)  ✅

**名称:** CVE-2025-29775 - xml-crypto XML签名验证绕过  
**类型:** XML签名验证绕过  
**风险:** 严重，可能导致身份验证绕过和权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-04-28  
**POC仓库:** [CVE-2025-29775](https://github.com/ethicalPap/CVE-2025-29775)  

---

### [CVE-2025-3971](CVE-2025-3971-cyruscostini_CVE-2025-3971.md) 🔴 ✅

**名称:** CVE-2025-3971-PHPGurukul COVID19 Testing Management System-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、数据篡改和服务器完全控制  
**投毒风险:** 70%  
**发现时间:** 2025-04-27  
**POC仓库:** [CVE-2025-3971](https://github.com/cyruscostini/CVE-2025-3971)  

---

### [CVE-2025-31324](CVE-2025-31324-Totunm_CVE-2025-31324.md) 🔴 ✅

**名称:** CVE-2025-31324-SAP NetWeaver Visual Composer-未授权文件上传  
**类型:** 未授权文件上传  
**风险:** 高危，可能导致远程代码执行和系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-27  
**POC仓库:** [CVE-2025-31324](https://github.com/Totunm/CVE-2025-31324)  

---

### [CVE-2024-27956](CVE-2024-27956-truonghuuphuc_CVE-2024-27956.md) 🔴 ✅

**名称:** CVE-2024-27956-WordPress Automatic Plugin-SQL注入  
**类型:** SQL注入  
**风险:** 高危，未经身份验证的攻击者可以执行任意SQL命令，可能导致数据泄露、数据篡改甚至服务器控制。  
**投毒风险:** 10%  
**发现时间:** 2025-04-27  
**POC仓库:** [CVE-2024-27956](https://github.com/truonghuuphuc/CVE-2024-27956)  

---

### [CVE-2024-27956](CVE-2024-27956-diego-tella_CVE-2024-27956-RCE.md) 🔴 ✅

**名称:** CVE-2024-27956-WordPress Automatic Plugin-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-27  
**POC仓库:** [CVE-2024-27956-RCE](https://github.com/diego-tella/CVE-2024-27956-RCE)  

---

### [CVE-2024-27956](CVE-2024-27956-X-Projetion_CVE-2024-27956-WORDPRESS-RCE-PLUGIN.md) 🔴 ✅

**名称:** CVE-2024-27956-WORDPRESS-RCE-PLUGIN  
**类型:** SQL注入  
**风险:** 高危，允许未经身份验证的攻击者执行任意SQL命令，可能导致数据泄露、权限提升甚至远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-27  
**POC仓库:** [CVE-2024-27956-WORDPRESS-RCE-PLUGIN](https://github.com/X-Projetion/CVE-2024-27956-WORDPRESS-RCE-PLUGIN)  

---

### [CVE-2024-27956](CVE-2024-27956-k3ppf0r_CVE-2024-27956.md) 🔴 ✅

**名称:** CVE-2024-27956-WordPress Automatic-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-27  
**POC仓库:** [CVE-2024-27956](https://github.com/k3ppf0r/CVE-2024-27956)  

---

### [CVE-2024-27956](CVE-2024-27956-W3BW_CVE-2024-27956-RCE-File-Package.md) 🔴 ✅

**名称:** CVE-2024-27956 - WordPress Automatic Plugin SQL 注入  
**类型:** SQL 注入  
**风险:** 高危，允许未经身份验证的任意 SQL 执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-27  
**POC仓库:** [CVE-2024-27956-RCE-File-Package](https://github.com/W3BW/CVE-2024-27956-RCE-File-Package)  

---

### [CVE-2024-27956](CVE-2024-27956-FoxyProxys_CVE-2024-27956.md)  ✅

**名称:** CVE-2024-27956-WordPress Automatic-SQL注入  
**类型:** SQL注入  
**风险:** 严重，未授权的任意SQL执行  
**投毒风险:** 95%  
**发现时间:** 2025-04-27  
**POC仓库:** [CVE-2024-27956](https://github.com/FoxyProxys/CVE-2024-27956)  

---

### [CVE-2024-27956](CVE-2024-27956-itzheartzz_MASS-CVE-2024-27956.md) 🔴 ✅

**名称:** CVE-2024-27956-WordPress Automatic-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-27  
**POC仓库:** [MASS-CVE-2024-27956](https://github.com/itzheartzz/MASS-CVE-2024-27956)  

---

### [CVE-2024-27956](CVE-2024-27956-TadashiJei_Valve-Press-CVE-2024-27956-RCE.md) 🔴 ✅

**名称:** CVE-2024-27956-WordPress Automatic-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-27  
**POC仓库:** [Valve-Press-CVE-2024-27956-RCE](https://github.com/TadashiJei/Valve-Press-CVE-2024-27956-RCE)  

---

### [CVE-2024-27956](CVE-2024-27956-cve-2024_CVE-2024-27956-RCE.md) 🔴 ✅

**名称:** CVE-2024-27956-WordPress Automatic Plugin SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-27  
**POC仓库:** [CVE-2024-27956-RCE](https://github.com/cve-2024/CVE-2024-27956-RCE)  

---

### [CVE-2024-27956](CVE-2024-27956-Cappricio-Securities_CVE-2024-27956.md) 🔴 ✅

**名称:** CVE-2024-27956 - WordPress Automatic Plugin - SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据库信息泄露，数据篡改，甚至服务器控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-27  
**POC仓库:** [CVE-2024-27956](https://github.com/Cappricio-Securities/CVE-2024-27956)  

---

### [CVE-2024-27956](CVE-2024-27956-AiGptCode_WordPress-Auto-Admin-Account-and-Reverse-Shell-cve-2024-27956.md) 🔴 ✅

**名称:** CVE-2024-27956-WordPress Automatic-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据库信息泄露、权限提升和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-27  
**POC仓库:** [WordPress-Auto-Admin-Account-and-Reverse-Shell-cve-2024-27956](https://github.com/AiGptCode/WordPress-Auto-Admin-Account-and-Reverse-Shell-cve-2024-27956)  

---

### [CVE-2024-27956](CVE-2024-27956-ThatNotEasy_CVE-2024-27956.md) 🔴 ✅

**名称:** CVE-2024-27956-WordPress Automatic-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、权限提升和远程代码执行（SQLI-2-RCE)  
**投毒风险:** 10%  
**发现时间:** 2025-04-27  
**POC仓库:** [CVE-2024-27956](https://github.com/ThatNotEasy/CVE-2024-27956)  

---

### [CVE-2024-27956](CVE-2024-27956-CERTologists_EXPLOITING-CVE-2024-27956.md) 🔴 ✅

**名称:** CVE-2024-27956-WordPress Automatic-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据库信息泄露、数据篡改甚至远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-27  
**POC仓库:** [EXPLOITING-CVE-2024-27956](https://github.com/CERTologists/EXPLOITING-CVE-2024-27956)  

---

### [CVE-2024-27956](CVE-2024-27956-7aRanchi_CVE-2024-27956-for-fscan.md) 🔴 ✅

**名称:** CVE-2024-27956-WordPress Automatic-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可导致数据库信息泄露、数据篡改以及未经授权的访问控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-27  
**POC仓库:** [CVE-2024-27956-for-fscan](https://github.com/7aRanchi/CVE-2024-27956-for-fscan)  

---

### [CVE-2024-27956](CVE-2024-27956-m4nInTh3mIdDle_wordpress-CVE-2024-27956.md) 🔴 ✅

**名称:** CVE-2024-27956-WordPress Automatic-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据库信息泄露、任意代码执行，并完全控制受影响的WordPress站点。  
**投毒风险:** 10%  
**发现时间:** 2025-04-27  
**POC仓库:** [wordpress-CVE-2024-27956](https://github.com/m4nInTh3mIdDle/wordpress-CVE-2024-27956)  

---

### [CVE-2022-3552](CVE-2022-3552-0xk4b1r_CVE-2022-3552.md) 🔴 ✅

**名称:** CVE-2022-3552 BoxBilling 文件上传漏洞  
**类型:** 文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-27  
**POC仓库:** [CVE-2022-3552](https://github.com/0xk4b1r/CVE-2022-3552)  

---

### [CVE-2022-3552](CVE-2022-3552-BakalMode_CVE-2022-3552.md) 🔴 ✅

**名称:** CVE-2022-3552-boxbilling-文件上传RCE  
**类型:** 文件上传RCE  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-27  
**POC仓库:** [CVE-2022-3552](https://github.com/BakalMode/CVE-2022-3552)  

---

### [CVE-2025-31324](CVE-2025-31324-Onapsis_Onapsis_CVE-2025-31324_Scanner_Tools.md) 🔴 ✅

**名称:** CVE-2025-31324-SAP NetWeaver Visual Composer-未授权文件上传  
**类型:** 未授权文件上传  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-27  
**POC仓库:** [Onapsis_CVE-2025-31324_Scanner_Tools](https://github.com/Onapsis/Onapsis_CVE-2025-31324_Scanner_Tools)  

---

### [CVE-2022-42092](CVE-2022-42092-ajdumanhug_CVE-2022-42092.md) 🔴 ✅

**名称:** CVE-2022-42092-Backdrop CMS-Unrestricted File Upload  
**类型:** Unrestricted File Upload  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-27  
**POC仓库:** [CVE-2022-42092](https://github.com/ajdumanhug/CVE-2022-42092)  

---

### [CVE-2024-36587](CVE-2024-36587-meeeeing_CVE-2024-36587.md) 🔴 ✅

**名称:** CVE-2024-36587 - dnscrypt-proxy 本地权限提升  
**类型:** 权限提升  
**风险:** 高危，允许非特权用户提升到root权限  
**投毒风险:** 0%  
**发现时间:** 2025-04-27  
**POC仓库:** [CVE-2024-36587](https://github.com/meeeeing/CVE-2024-36587)  

---

### [CVE-2025-3914](CVE-2025-3914-LvL23HT_PoC-CVE-2025-3914-Aeropage-WordPress-File-Upload.md) 🔴 ✅

**名称:** CVE-2025-3914-Aeropage Sync for Airtable-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-27  
**POC仓库:** [PoC-CVE-2025-3914-Aeropage-WordPress-File-Upload](https://github.com/LvL23HT/PoC-CVE-2025-3914-Aeropage-WordPress-File-Upload)  

---

### [CVE-2024-31449](CVE-2024-31449-daeseong1209_CVE-2024-31449.md) 🔴 ✅

**名称:** CVE-2024-31449-Redis-Stack Buffer Overflow  
**类型:** Stack Buffer Overflow  
**风险:** 高危，可能导致远程代码执行或拒绝服务  
**投毒风险:** 5%  
**发现时间:** 2025-04-27  
**POC仓库:** [CVE-2024-31449](https://github.com/daeseong1209/CVE-2024-31449)  

---

### [CVE-2025-24813](CVE-2025-24813-hakankarabacak_CVE-2025-24813.md) 🔴 ✅

**名称:** CVE-2025-24813-Apache Tomcat-路径等价/反序列化RCE  
**类型:** 路径等价/反序列化RCE  
**风险:** 高危，可能导致远程代码执行和信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-27  
**POC仓库:** [CVE-2025-24813](https://github.com/hakankarabacak/CVE-2025-24813)  

---

### [CVE-2025-32432](CVE-2025-32432-ibrahimsql_CVE-2025-32432.md) 🔴 ✅

**名称:** CVE-2025-32432-CraftCMS-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经授权的攻击者在服务器上执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-04-27  
**POC仓库:** [CVE-2025-32432](https://github.com/ibrahimsql/CVE-2025-32432)  

---

### [CVE-2017-8291](CVE-2017-8291-shun1403_PIL-CVE-2017-8291-study.md) 🔴 ✅

**名称:** CVE-2017-8291-Ghostscript-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-27  
**POC仓库:** [PIL-CVE-2017-8291-study](https://github.com/shun1403/PIL-CVE-2017-8291-study)  

---

### [CVE-2019-19781](CVE-2019-19781-0xams_citrixvulncheck.md) 🔴 ✅

**名称:** CVE-2019-19781-Citrix ADC/Gateway-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-27  
**POC仓库:** [citrixvulncheck](https://github.com/0xams/citrixvulncheck)  

---

### [CVE-2019-19781](CVE-2019-19781-hyunjin0334_CVE-2019-19781.md) 🔴 ✅

**名称:** CVE-2019-19781-Citrix ADC/Gateway-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-27  
**POC仓库:** [CVE-2019-19781](https://github.com/hyunjin0334/CVE-2019-19781)  

---

### [CVE-2025-31324](CVE-2025-31324-redrays-io_CVE-2025-31324.md) 🔴 ✅

**名称:** CVE-2025-31324-SAP NetWeaver Visual Composer-未授权文件上传  
**类型:** 未授权文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-27  
**POC仓库:** [CVE-2025-31324](https://github.com/redrays-io/CVE-2025-31324)  

---

### [CVE-2025-43865](CVE-2025-43865-pouriam23_Pre-render-data-spoofing-on-React-Router-framework-mode-CVE-2025-43865.md) 🔴 ✅

**名称:** CVE-2025-43865-react-router-数据欺骗  
**类型:** 数据欺骗  
**风险:** 高危，可能导致数据欺骗、XSS漏洞  
**投毒风险:** 10%  
**发现时间:** 2025-04-27  
**POC仓库:** [Pre-render-data-spoofing-on-React-Router-framework-mode-CVE-2025-43865](https://github.com/pouriam23/Pre-render-data-spoofing-on-React-Router-framework-mode-CVE-2025-43865)  

---

### [CVE-2018-15133](CVE-2018-15133-aljavier_exploit_laravel_cve-2018-15133.md) 🔴 ✅

**名称:** CVE-2018-15133-Laravel-反序列化RCE  
**类型:** 反序列化远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-27  
**POC仓库:** [exploit_laravel_cve-2018-15133](https://github.com/aljavier/exploit_laravel_cve-2018-15133)  

---

### [CVE-2015-2797](CVE-2015-2797-Bariskizilkaya_CVE-2015-2797-PoC.md) 🔴 ✅

**名称:** CVE-2015-2797-AirTies DSL Modem 栈溢出  
**类型:** 栈溢出  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-27  
**POC仓库:** [CVE-2015-2797-PoC](https://github.com/Bariskizilkaya/CVE-2015-2797-PoC)  

---

### [CVE-2018-7600](CVE-2018-7600-Dowonkwon_drupal-cve-2018-7600-poc.md) 🔴 ✅

**名称:** CVE-2018-7600-Drupalgeddon 2  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-27  
**POC仓库:** [drupal-cve-2018-7600-poc](https://github.com/Dowonkwon/drupal-cve-2018-7600-poc)  

---

### [CVE-2018-15133](CVE-2018-15133-Bilelxdz_Laravel-CVE-2018-15133.md) 🔴 ✅

**名称:** CVE-2018-15133 Laravel Framework 反序列化远程代码执行  
**类型:** 反序列化漏洞导致远程代码执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-27  
**POC仓库:** [Laravel-CVE-2018-15133](https://github.com/Bilelxdz/Laravel-CVE-2018-15133)  

---

### [CVE-2018-15133](CVE-2018-15133-bukitbarisan_laravel-rce-cve-2018-15133.md) 🔴 ✅

**名称:** CVE-2018-15133 Laravel Framework 反序列化漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-27  
**POC仓库:** [laravel-rce-cve-2018-15133](https://github.com/bukitbarisan/laravel-rce-cve-2018-15133)  

---

### [CVE-2018-15133](CVE-2018-15133-Prabesh01_Laravel-PHP-Unit-RCE-Auto-shell-uploader.md) 🔴 ✅

**名称:** CVE-2018-15133-Laravel-反序列化RCE  
**类型:** 反序列化RCE  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-27  
**POC仓库:** [Laravel-PHP-Unit-RCE-Auto-shell-uploader](https://github.com/Prabesh01/Laravel-PHP-Unit-RCE-Auto-shell-uploader)  

---

### [CVE-2018-15133](CVE-2018-15133-AlienX2001_better-poc-for-CVE-2018-15133.md) 🔴 ✅

**名称:** CVE-2018-15133 Laravel Framework 反序列化远程代码执行  
**类型:** 反序列化漏洞导致远程代码执行  
**风险:** 高危，可能导致远程代码执行，完全控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-04-27  
**POC仓库:** [better-poc-for-CVE-2018-15133](https://github.com/AlienX2001/better-poc-for-CVE-2018-15133)  

---

### [CVE-2018-15133](CVE-2018-15133-AzhariKun_CVE-2018-15133.md) 🔴 ✅

**名称:** CVE-2018-15133-Laravel-反序列化RCE  
**类型:** 反序列化RCE  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 20%  
**发现时间:** 2025-04-27  
**POC仓库:** [CVE-2018-15133](https://github.com/AzhariKun/CVE-2018-15133)  

---

### [CVE-2018-15133](CVE-2018-15133-NatteeSetobol_CVE-2018-15133-Lavel-Expliot.md) 🔴 ✅

**名称:** CVE-2018-15133-Laravel-反序列化漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-27  
**POC仓库:** [CVE-2018-15133-Lavel-Expliot](https://github.com/NatteeSetobol/CVE-2018-15133-Lavel-Expliot)  

---

### [CVE-2018-15133](CVE-2018-15133-pwnedshell_Larascript.md) 🔴 ✅

**名称:** CVE-2018-15133-Laravel-反序列化RCE  
**类型:** 反序列化RCE  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-27  
**POC仓库:** [Larascript](https://github.com/pwnedshell/Larascript)  

---

### [CVE-2018-15133](CVE-2018-15133-0xSalle_cve-2018-15133.md) 🔴 ✅

**名称:** CVE-2018-15133 Laravel Framework 反序列化远程代码执行  
**类型:** 反序列化远程代码执行  
**风险:** 高危，可能导致远程代码执行和服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-27  
**POC仓库:** [cve-2018-15133](https://github.com/0xSalle/cve-2018-15133)  

---

### [CVE-2018-15133](CVE-2018-15133-Cr4zyD14m0nd137_Lab-for-cve-2018-15133.md) 🔴 ✅

**名称:** CVE-2018-15133-Laravel-反序列化RCE  
**类型:** 反序列化远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-27  
**POC仓库:** [Lab-for-cve-2018-15133](https://github.com/Cr4zyD14m0nd137/Lab-for-cve-2018-15133)  

---

### [CVE-2018-15133](CVE-2018-15133-kozmic_laravel-poc-CVE-2018-15133.md) 🔴 ✅

**名称:** CVE-2018-15133 Laravel Framework Token Unserialize RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-04-27  
**POC仓库:** [laravel-poc-CVE-2018-15133](https://github.com/kozmic/laravel-poc-CVE-2018-15133)  

---

### [CVE-2018-15133](CVE-2018-15133-yeahhbean_Laravel-CVE-2018-15133.md) 🔴 ✅

**名称:** CVE-2018-15133-Laravel框架反序列化远程代码执行  
**类型:** 反序列化漏洞  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-27  
**POC仓库:** [Laravel-CVE-2018-15133](https://github.com/yeahhbean/Laravel-CVE-2018-15133)  

---

### [CVE-2025-43864](CVE-2025-43864-pouriam23_DoS-via-cache-poisoning-by-forcing-SPA-mode-CVE-2025-43864-.md) 🔴 ✅

**名称:** CVE-2025-43864-react-router-缓存投毒DoS  
**类型:** 缓存投毒导致的拒绝服务(DoS)  
**风险:** 高危，可能导致应用不可用  
**投毒风险:** 10%  
**发现时间:** 2025-04-27  
**POC仓库:** [DoS-via-cache-poisoning-by-forcing-SPA-mode-CVE-2025-43864-](https://github.com/pouriam23/DoS-via-cache-poisoning-by-forcing-SPA-mode-CVE-2025-43864-)  

---

### [CVE-2025-32432](CVE-2025-32432-Sachinart_CVE-2025-32432.md)  ✅

**名称:** CVE-2025-32432-CraftCMS-远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可导致完全控制受影响的系统  
**投毒风险:** 5%  
**发现时间:** 2025-04-27  
**POC仓库:** [CVE-2025-32432](https://github.com/Sachinart/CVE-2025-32432)  

---

### [CVE-2017-8291](CVE-2017-8291-shun1403_CVE-2017-8291.md) 🔴 ✅

**名称:** CVE-2017-8291-Ghostscript远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-27  
**POC仓库:** [CVE-2017-8291](https://github.com/shun1403/CVE-2017-8291)  

---

### [CVE-2025-24054](CVE-2025-24054-ClementNjeru_CVE-2025-24054-PoC.md) 🟡 ✅

**名称:** CVE-2025-24054-NTLM Hash Disclosure Spoofing  
**类型:** NTLM Hash Disclosure  
**风险:** 中危，可能导致凭据泄露和网络欺骗  
**投毒风险:** 0%  
**发现时间:** 2025-04-27  
**POC仓库:** [CVE-2025-24054-PoC](https://github.com/ClementNjeru/CVE-2025-24054-PoC)  

---

### [CVE-2025-1974](CVE-2025-1974-salt318_CVE-2025-1974.md) 🔴 ✅

**名称:** CVE-2025-1974-ingress-nginx-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者在ingress-nginx controller上下文中执行任意代码，可能导致集群范围内的Secret泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-27  
**POC仓库:** [CVE-2025-1974](https://github.com/salt318/CVE-2025-1974)  

---

### [CVE-2025-3248](CVE-2025-3248-minxxcozy_CVE-2025-3248-langflow-RCE.md)  ✅

**名称:** CVE-2025-3248-Langflow-代码注入  
**类型:** 代码注入  
**风险:** 严重，未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-27  
**POC仓库:** [CVE-2025-3248-langflow-RCE](https://github.com/minxxcozy/CVE-2025-3248-langflow-RCE)  

---

### [CVE-2025-46657](CVE-2025-46657-nov-1337_CVE-2025-46657.md) 🟡 ✅

**名称:** CVE-2025-46657-Karazal-Reflected XSS  
**类型:** Reflected XSS  
**风险:** 中危，可能导致用户信息泄露、会话劫持、恶意代码执行等  
**投毒风险:** 0%  
**发现时间:** 2025-04-27  
**POC仓库:** [CVE-2025-46657](https://github.com/nov-1337/CVE-2025-46657)  

---

### [CVE-2025-32433](CVE-2025-32433-MrDreamReal_CVE-2025-32433.md) 🔴 ✅

**名称:** CVE-2025-32433-Erlang/OTP SSH Pre-Authentication RCE  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-27  
**POC仓库:** [CVE-2025-32433](https://github.com/MrDreamReal/CVE-2025-32433)  

---

### [CVE-2025-32432](CVE-2025-32432-Chocapikk_CVE-2025-32432.md) 🔴 ✅

**名称:** CVE-2025-32432-Craft CMS-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-27  
**POC仓库:** [CVE-2025-32432](https://github.com/Chocapikk/CVE-2025-32432)  

---

### [CVE-2022-27925](CVE-2022-27925-vnhacker1337_CVE-2022-27925-PoC.md) 🔴 ✅

**名称:** CVE-2022-27925-Zimbra-Path Traversal  
**类型:** 路径遍历  
**风险:** 高危，可能导致任意文件上传和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2022-27925-PoC](https://github.com/vnhacker1337/CVE-2022-27925-PoC)  

---

### [CVE-2022-27925](CVE-2022-27925-miko550_CVE-2022-27925.md) 🔴 ✅

**名称:** CVE-2022-27925-Zimbra-路径遍历  
**类型:** 路径遍历/文件上传  
**风险:** 高危，可能导致任意文件上传和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2022-27925](https://github.com/miko550/CVE-2022-27925)  

---

### [CVE-2022-27925](CVE-2022-27925-navokus_CVE-2022-27925.md) 🔴 ✅

**名称:** CVE-2022-27925-Zimbra-目录遍历文件上传  
**类型:** 目录遍历/文件上传  
**风险:** 高危，可能导致任意文件上传和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2022-27925](https://github.com/navokus/CVE-2022-27925)  

---

### [CVE-2022-27925](CVE-2022-27925-Josexv1_CVE-2022-27925.md) 🔴 ✅

**名称:** CVE-2022-27925 - Zimbra Collaboration Suite 任意文件上传导致目录遍历  
**类型:** 目录遍历/文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2022-27925](https://github.com/Josexv1/CVE-2022-27925)  

---

### [CVE-2022-27925](CVE-2022-27925-mohamedbenchikh_CVE-2022-27925.md) 🔴 ✅

**名称:** CVE-2022-27925-Zimbra-路径遍历导致远程代码执行  
**类型:** 路径遍历/远程代码执行  
**风险:** 高危，未经授权的管理员可以上传任意文件，导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2022-27925](https://github.com/mohamedbenchikh/CVE-2022-27925)  

---

### [CVE-2022-27925](CVE-2022-27925-akincibor_CVE-2022-27925.md) 🔴 ✅

**名称:** CVE-2022-27925-Zimbra-目录遍历/远程代码执行  
**类型:** 目录遍历/远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2022-27925](https://github.com/akincibor/CVE-2022-27925)  

---

### [CVE-2022-27925](CVE-2022-27925-Chocapikk_CVE-2022-27925-Revshell.md) 🔴 ✅

**名称:** CVE-2022-27925-Zimbra-路径遍历/任意文件上传  
**类型:** 路径遍历/任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2022-27925-Revshell](https://github.com/Chocapikk/CVE-2022-27925-Revshell)  

---

### [CVE-2022-27925](CVE-2022-27925-touchmycrazyredhat_CVE-2022-27925-Revshell.md) 🔴 ✅

**名称:** CVE-2022-27925-Zimbra-Path Traversal  
**类型:** 路径遍历  
**风险:** 高危，可导致任意文件上传和远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2022-27925-Revshell](https://github.com/touchmycrazyredhat/CVE-2022-27925-Revshell)  

---

### [CVE-2022-27925](CVE-2022-27925-jam620_Zimbra.md) 🔴 ✅

**名称:** CVE-2022-27925 - Zimbra Collaboration Suite 目录遍历和远程代码执行  
**类型:** 目录遍历  
**风险:** 高危，可导致任意文件上传和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [Zimbra](https://github.com/jam620/Zimbra)  

---

### [CVE-2022-27925](CVE-2022-27925-onlyHerold22_CVE-2022-27925-PoC.md) 🔴 ✅

**名称:** CVE-2022-27925-Zimbra-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致任意文件上传和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2022-27925-PoC](https://github.com/onlyHerold22/CVE-2022-27925-PoC)  

---

### [CVE-2022-27925](CVE-2022-27925-sanan2004_CVE-2022-27925.md) 🔴 ✅

**名称:** CVE-2022-27925 Zimbra Collaboration Suite 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 高危，可能导致任意文件上传和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2022-27925](https://github.com/sanan2004/CVE-2022-27925)  

---

### [CVE-2022-27925](CVE-2022-27925-Inplex-sys_CVE-2022-27925.md) 🔴 ✅

**名称:** CVE-2022-27925-Zimbra-路径遍历  
**类型:** 路径遍历/任意文件上传  
**风险:** 高危，可导致任意文件写入和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2022-27925](https://github.com/Inplex-sys/CVE-2022-27925)  

---

### [CVE-2024-27808](CVE-2024-27808-Leandrobts_CVE-2024-27808.github.io.md) 🔴 ✅

**名称:** CVE-2024-27808  
**类型:** 类型混淆/内存处理错误导致任意代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2024-27808.github.io](https://github.com/Leandrobts/CVE-2024-27808.github.io)  

---

### [CVE-2025-2294](CVE-2025-2294-romanedutov_CVE-2025-2294.md)  ✅

**名称:** CVE-2025-2294 - Kubio AI Page Builder <= 2.5.1 - 未经身份验证的本地文件包含  
**类型:** 本地文件包含 (LFI)  
**风险:** 严重，可能导致敏感数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2025-2294](https://github.com/romanedutov/CVE-2025-2294)  

---

### [CVE-2017-5638](CVE-2017-5638-jas502n_st2-046-poc.md) 🔴 ✅

**名称:** CVE-2017-5638 - Apache Struts2 Jakarta Multipart parser RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [st2-046-poc](https://github.com/jas502n/st2-046-poc)  

---

### [CVE-2017-5638](CVE-2017-5638-tahmed11_strutsy.md) 🔴 ✅

**名称:** CVE-2017-5638 Apache Struts 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [strutsy](https://github.com/tahmed11/strutsy)  

---

### [CVE-2017-5638](CVE-2017-5638-andypitcher_check_struts.md) 🔴 ✅

**名称:** CVE-2017-5638-Apache Struts2-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [check_struts](https://github.com/andypitcher/check_struts)  

---

### [CVE-2017-5638](CVE-2017-5638-un4ckn0wl3z_CVE-2017-5638.md) 🔴 ✅

**名称:** CVE-2017-5638-Apache Struts2-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2017-5638](https://github.com/un4ckn0wl3z/CVE-2017-5638)  

---

### [CVE-2017-5638](CVE-2017-5638-sighup1_cybersecurity-struts2.md) 🔴 ✅

**名称:** CVE-2017-5638 - Apache Struts2 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [cybersecurity-struts2](https://github.com/sighup1/cybersecurity-struts2)  

---

### [CVE-2017-5638](CVE-2017-5638-colorblindpentester_CVE-2017-5638.md) 🔴 ✅

**名称:** CVE-2017-5638 - Apache Struts2 S2-045  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致远程代码执行，服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2017-5638](https://github.com/colorblindpentester/CVE-2017-5638)  

---

### [CVE-2017-5638](CVE-2017-5638-leandrocamposcardoso_CVE-2017-5638-Mass-Exploit.md) 🔴 ✅

**名称:** CVE-2017-5638 - Apache Struts 2 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2017-5638-Mass-Exploit](https://github.com/leandrocamposcardoso/CVE-2017-5638-Mass-Exploit)  

---

### [CVE-2017-5638](CVE-2017-5638-ludy-dev_XworkStruts-RCE.md) 🔴 ✅

**名称:** CVE-2017-5638-Apache Struts2-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [XworkStruts-RCE](https://github.com/ludy-dev/XworkStruts-RCE)  

---

### [CVE-2017-5638](CVE-2017-5638-jongmartinez_CVE-2017-5638.md) 🔴 ✅

**名称:** CVE-2017-5638 - Apache Struts2 S2-045  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2017-5638](https://github.com/jongmartinez/CVE-2017-5638)  

---

### [CVE-2017-5638](CVE-2017-5638-Badbird3_CVE-2017-5638.md) 🔴 ✅

**名称:** CVE-2017-5638 - Apache Struts2 S2-045  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2017-5638](https://github.com/Badbird3/CVE-2017-5638)  

---

### [CVE-2017-5638](CVE-2017-5638-mthbernardes_strutszeiro.md) 🔴 ✅

**名称:** CVE-2017-5638 Apache Struts2 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [strutszeiro](https://github.com/mthbernardes/strutszeiro)  

---

### [CVE-2017-5638](CVE-2017-5638-jas502n_S2-045-EXP-POC-TOOLS.md) 🔴 ✅

**名称:** CVE-2017-5638 - Apache Struts2 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可直接控制服务器  
**投毒风险:** 5%  
**发现时间:** 2025-04-26  
**POC仓库:** [S2-045-EXP-POC-TOOLS](https://github.com/jas502n/S2-045-EXP-POC-TOOLS)  

---

### [CVE-2017-5638](CVE-2017-5638-jptr218_struts_hack.md) 🔴 ✅

**名称:** CVE-2017-5638-Apache Struts-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [struts_hack](https://github.com/jptr218/struts_hack)  

---

### [CVE-2017-5638](CVE-2017-5638-testpilot031_vulnerability_struts-2.3.31.md) 🔴 ✅

**名称:** CVE-2017-5638-Apache Struts2-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [vulnerability_struts-2.3.31](https://github.com/testpilot031/vulnerability_struts-2.3.31)  

---

### [CVE-2017-5638](CVE-2017-5638-readloud_CVE-2017-5638.md) 🔴 ✅

**名称:** CVE-2017-5638 Apache Struts2 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2017-5638](https://github.com/readloud/CVE-2017-5638)  

---

### [CVE-2017-5638](CVE-2017-5638-Tankirat_CVE-2017-5638.md) 🔴 ✅

**名称:** CVE-2017-5638 - Apache Struts RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2017-5638](https://github.com/Tankirat/CVE-2017-5638)  

---

### [CVE-2017-5638](CVE-2017-5638-injcristianrojas_cve-2017-5638.md) 🔴 ✅

**名称:** CVE-2017-5638-Apache Struts2-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-04-26  
**POC仓库:** [cve-2017-5638](https://github.com/injcristianrojas/cve-2017-5638)  

---

### [CVE-2017-5638](CVE-2017-5638-sonatype-workshops_struts2-rce.md) 🔴 ✅

**名称:** CVE-2017-5638-Apache Struts-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-04-26  
**POC仓库:** [struts2-rce](https://github.com/sonatype-workshops/struts2-rce)  

---

### [CVE-2017-5638](CVE-2017-5638-mfdev-solution_Exploit-CVE-2017-5638.md) 🔴 ✅

**名称:** CVE-2017-5638-Apache Struts2-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [Exploit-CVE-2017-5638](https://github.com/mfdev-solution/Exploit-CVE-2017-5638)  

---

### [CVE-2017-5638](CVE-2017-5638-Iletee_struts2-rce.md) 🔴 ✅

**名称:** CVE-2017-5638-Apache Struts RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [struts2-rce](https://github.com/Iletee/struts2-rce)  

---

### [CVE-2017-5638](CVE-2017-5638-mritunjay-k_CVE-2017-5638.md) 🔴 ✅

**名称:** CVE-2017-5638-Apache Struts2-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2017-5638](https://github.com/mritunjay-k/CVE-2017-5638)  

---

### [CVE-2017-5638](CVE-2017-5638-FredBrave_CVE-2017-5638-ApacheStruts2.3.5.md) 🔴 ✅

**名称:** CVE-2017-5638-Apache Struts2 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2017-5638-ApacheStruts2.3.5](https://github.com/FredBrave/CVE-2017-5638-ApacheStruts2.3.5)  

---

### [CVE-2017-5638](CVE-2017-5638-jrrombaldo_CVE-2017-5638.md) 🔴 ✅

**名称:** CVE-2017-5638-Apache Struts2-远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2017-5638](https://github.com/jrrombaldo/CVE-2017-5638)  

---

### [CVE-2017-5638](CVE-2017-5638-Nithylesh_web-application-firewall-.md) 🔴 ✅

**名称:** CVE-2017-5638-Apache Struts2-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [web-application-firewall-](https://github.com/Nithylesh/web-application-firewall-)  

---

### [CVE-2017-5638](CVE-2017-5638-kloutkake_CVE-2017-5638-PoC.md) 🔴 ✅

**名称:** CVE-2017-5638 Apache Struts 2 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可完全控制受影响的服务器  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2017-5638-PoC](https://github.com/kloutkake/CVE-2017-5638-PoC)  

---

### [CVE-2017-5638](CVE-2017-5638-Xernary_CVE-2017-5638-POC.md) 🔴 ✅

**名称:** CVE-2017-5638 - Apache Struts2 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2017-5638-POC](https://github.com/Xernary/CVE-2017-5638-POC)  

---

### [CVE-2024-31317](CVE-2024-31317-agg23_cve-2024-31317.md) 🔴 ✅

**名称:** CVE-2024-31317-Android Zygote Deserialization  
**类型:** 特权提升  
**风险:** 高危，可能导致任意代码执行和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [cve-2024-31317](https://github.com/agg23/cve-2024-31317)  

---

### [CVE-2023-1389](CVE-2023-1389-Terminal1337_CVE-2023-1389.md) 🔴 ✅

**名称:** CVE-2023-1389 - TP-Link Archer AX21 Command Injection  
**类型:** 命令注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2023-1389](https://github.com/Terminal1337/CVE-2023-1389)  

---

### [CVE-2023-1389](CVE-2023-1389-Voyag3r-Security_CVE-2023-1389.md) 🔴 ✅

**名称:** CVE-2023-1389 - TP-Link Archer AX21 Command Injection  
**类型:** 命令注入  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2023-1389](https://github.com/Voyag3r-Security/CVE-2023-1389)  

---

### [CVE-2023-1389](CVE-2023-1389-ibrahimsql_CVE2023-1389.md) 🔴 ✅

**名称:** CVE-2023-1389-TP-Link Archer AX21-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许未授权的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE2023-1389](https://github.com/ibrahimsql/CVE2023-1389)  

---

### [CVE-2023-39361](CVE-2023-39361-HPT-Intern-Task-Submission_CVE-2023-39361.md) 🔴 ✅

**名称:** CVE-2023-39361-Cacti-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据库信息泄露、修改甚至远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2023-39361](https://github.com/HPT-Intern-Task-Submission/CVE-2023-39361)  

---

### [CVE-2023-39361](CVE-2023-39361-ChoDeokCheol_CVE-2023-39361.md) 🔴 

**名称:** CVE-2023-39361-Cacti-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、权限提升和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2023-39361](https://github.com/ChoDeokCheol/CVE-2023-39361)  

---

### [CVE-2021-22986](CVE-2021-22986-ZephrFish_CVE-2021-22986_Check.md) 🔴 ✅

**名称:** CVE-2021-22986-F5 BIG-IP/BIG-IQ-iControl REST API-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，未经身份验证的远程命令执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2021-22986_Check](https://github.com/ZephrFish/CVE-2021-22986_Check)  

---

### [CVE-2021-26855](CVE-2021-26855-mekhalleh_exchange_proxylogon.md) 🔴 ✅

**名称:** CVE-2021-26855 Microsoft Exchange Server ProxyLogon RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的远程攻击者可以执行任意命令  
**投毒风险:** 5%  
**发现时间:** 2025-04-26  
**POC仓库:** [exchange_proxylogon](https://github.com/mekhalleh/exchange_proxylogon)  

---

### [CVE-2021-26855](CVE-2021-26855-TheDudeD6_ExchangeSmash.md) 🔴 ✅

**名称:** CVE-2021-26855-Microsoft Exchange Server Remote Code Execution  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [ExchangeSmash](https://github.com/TheDudeD6/ExchangeSmash)  

---

### [CVE-2022-1388](CVE-2022-1388-ZephrFish_F5-CVE-2022-1388-Exploit.md) 🔴 ✅

**名称:** CVE-2022-1388 F5 BIG-IP iControl REST 身份验证绕过漏洞  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [F5-CVE-2022-1388-Exploit](https://github.com/ZephrFish/F5-CVE-2022-1388-Exploit)  

---

### [CVE-2025-1974](CVE-2025-1974-chhhd_CVE-2025-1974.md) 🔴 ✅

**名称:** CVE-2025-1974-ingress-nginx-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致集群范围内secrets泄露和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2025-1974](https://github.com/chhhd/CVE-2025-1974)  

---

### [CVE-2022-1388](CVE-2022-1388-li8u99_CVE-2022-1388.md) 🔴 ✅

**名称:** CVE-2022-1388 F5 BIG-IP iControl REST 身份验证绕过漏洞  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2022-1388](https://github.com/li8u99/CVE-2022-1388)  

---

### [CVE-2022-1388](CVE-2022-1388-0xf4n9x_CVE-2022-1388.md)  ✅

**名称:** CVE-2022-1388-F5 BIG-IP iControl REST 身份验证绕过远程代码执行  
**类型:** 身份验证绕过/远程代码执行  
**风险:** 严重，未经身份验证的攻击者可以执行任意命令，完全控制系统  
**投毒风险:** 1%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2022-1388](https://github.com/0xf4n9x/CVE-2022-1388)  

---

### [CVE-2022-1388](CVE-2022-1388-Luchoane_CVE-2022-1388_refresh.md) 🔴 ✅

**名称:** CVE-2022-1388-F5 BIG-IP-iControl REST Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2022-1388_refresh](https://github.com/Luchoane/CVE-2022-1388_refresh)  

---

### [CVE-2022-1388](CVE-2022-1388-jbharucha05_CVE-2022-1388.md) 🔴 ✅

**名称:** CVE-2022-1388-F5 BIG-IP-iControl REST身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2022-1388](https://github.com/jbharucha05/CVE-2022-1388)  

---

### [CVE-2022-1388](CVE-2022-1388-Vulnmachines_F5-Big-IP-CVE-2022-1388.md)  ✅

**名称:** CVE-2022-1388 F5 BIG-IP iControl REST 身份验证绕过 RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，未经身份验证的攻击者可以执行任意命令。  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [F5-Big-IP-CVE-2022-1388](https://github.com/Vulnmachines/F5-Big-IP-CVE-2022-1388)  

---

### [CVE-2022-1388](CVE-2022-1388-Henry4E36_CVE-2022-1388.md) 🔴 ✅

**名称:** CVE-2022-1388 F5 BIG-IP iControl REST 身份验证绕过漏洞  
**类型:** 身份验证绕过  
**风险:** 高危，允许未经身份验证的攻击者执行任意命令  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2022-1388](https://github.com/Henry4E36/CVE-2022-1388)  

---

### [CVE-2022-1388](CVE-2022-1388-Chocapikk_CVE-2022-1388.md)  ✅

**名称:** CVE-2022-1388 F5 BIG-IP iControl REST 认证绕过远程代码执行漏洞  
**类型:** 认证绕过/远程代码执行  
**风险:** 严重，未授权远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2022-1388](https://github.com/Chocapikk/CVE-2022-1388)  

---

### [CVE-2022-1388](CVE-2022-1388-On-Cyber-War_CVE-2022-1388.md) 🔴 ✅

**名称:** CVE-2022-1388 F5 BIG-IP iControl REST 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2022-1388](https://github.com/On-Cyber-War/CVE-2022-1388)  

---

### [CVE-2022-1388](CVE-2022-1388-revanmalang_CVE-2022-1388.md)  ✅

**名称:** CVE-2022-1388 - F5 BIG-IP iControl REST Authentication Bypass  
**类型:** Authentication Bypass / Remote Code Execution  
**风险:** 严重，未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2022-1388](https://github.com/revanmalang/CVE-2022-1388)  

---

### [CVE-2022-1388](CVE-2022-1388-M4fiaB0y_CVE-2022-1388.md)  ✅

**名称:** CVE-2022-1388 F5 BIG-IP iControl REST Authentication Bypass  
**类型:** 认证绕过/远程代码执行  
**风险:** 极高，未经授权的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2022-1388](https://github.com/M4fiaB0y/CVE-2022-1388)  

---

### [CVE-2022-1388](CVE-2022-1388-devengpk_CVE-2022-1388.md) 🔴 ✅

**名称:** CVE-2022-1388-F5 BIG-IP iControl REST 认证绕过与远程代码执行  
**类型:** 认证绕过/远程代码执行  
**风险:** 高危，可能导致完全控制受影响的系统  
**投毒风险:** 5%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2022-1388](https://github.com/devengpk/CVE-2022-1388)  

---

### [CVE-2022-1388](CVE-2022-1388-vaelwolf_CVE-2022-1388.md) 🔴 ✅

**名称:** CVE-2022-1388-F5 BIG-IP iControl REST 认证绕过远程代码执行  
**类型:** 认证绕过/远程代码执行  
**风险:** 高危，可能导致完全控制目标系统  
**投毒风险:** 5%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2022-1388](https://github.com/vaelwolf/CVE-2022-1388)  

---

### [CVE-2022-1388](CVE-2022-1388-EvilLizard666_CVE-2022-1388.md) 🔴 ✅

**名称:** CVE-2022-1388 F5 BIG-IP iControl REST 身份验证绕过漏洞  
**类型:** 身份验证绕过  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2022-1388](https://github.com/EvilLizard666/CVE-2022-1388)  

---

### [CVE-2022-1388](CVE-2022-1388-amitlttwo_CVE-2022-1388.md)  ✅

**名称:** CVE-2022-1388-F5 BIG-IP iControl REST Authentication Bypass RCE  
**类型:** 身份验证绕过、远程代码执行  
**风险:** 严重，未经身份验证的攻击者可以执行任意命令  
**投毒风险:** 1%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2022-1388](https://github.com/amitlttwo/CVE-2022-1388)  

---

### [CVE-2022-1388](CVE-2022-1388-j-baines_tippa-my-tongue.md) 🔴 ✅

**名称:** CVE-2022-1388 & CVE-2022-41800 F5 BIG-IP RCE  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-26  
**POC仓库:** [tippa-my-tongue](https://github.com/j-baines/tippa-my-tongue)  

---

### [CVE-2022-1388](CVE-2022-1388-Zeyad-Azima_CVE-2022-1388.md)  ✅

**名称:** CVE-2022-1388 - F5 BIG-IP iControl REST Authentication Bypass RCE  
**类型:** 认证绕过, 远程代码执行  
**风险:** 严重，可完全控制受影响的系统  
**投毒风险:** 5%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2022-1388](https://github.com/Zeyad-Azima/CVE-2022-1388)  

---

### [CVE-2022-1388](CVE-2022-1388-forktheplanet_CVE-2022-1388.md) 🔴 ✅

**名称:** CVE-2022-1388 F5 BIG-IP iControl REST 认证绕过远程代码执行  
**类型:** 认证绕过/远程代码执行  
**风险:** 高危，可能导致完全控制目标系统  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2022-1388](https://github.com/forktheplanet/CVE-2022-1388)  

---

### [CVE-2022-1388](CVE-2022-1388-battleofthebots_refresh.md) 🔴 ✅

**名称:** CVE-2022-1388 - F5 BIG-IP iControl REST 身份验证绕过导致RCE  
**类型:** 身份验证绕过/远程代码执行  
**风险:** 极高危，未经身份验证的攻击者可执行任意命令  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [refresh](https://github.com/battleofthebots/refresh)  

---

### [CVE-2022-1388](CVE-2022-1388-nvk0x_CVE-2022-1388-exploit.md) 🔴 ✅

**名称:** CVE-2022-1388-F5 BIG-IP iControl REST 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2022-1388-exploit](https://github.com/nvk0x/CVE-2022-1388-exploit)  

---

### [CVE-2022-1388](CVE-2022-1388-nico989_CVE-2022-1388.md) 🔴 ✅

**名称:** CVE-2022-1388-F5 BIG-IP-iControl REST 认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2022-1388](https://github.com/nico989/CVE-2022-1388)  

---

### [CVE-2022-1388](CVE-2022-1388-gotr00t0day_CVE-2022-1388.md) 🔴 ✅

**名称:** CVE-2022-1388-F5 BIG-IP iControl REST Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2022-1388](https://github.com/gotr00t0day/CVE-2022-1388)  

---

### [CVE-2022-1388](CVE-2022-1388-impost0r_CVE-2022-1388.md) 🔴 ✅

**名称:** CVE-2022-1388 - F5 BIG-IP iControl REST 认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2022-1388](https://github.com/impost0r/CVE-2022-1388)  

---

### [CVE-2022-1388](CVE-2022-1388-XiaomingX_cve-2022-1388-poc.md)  ✅

**名称:** CVE-2022-1388 - F5 BIG-IP iControl REST Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 严重，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-26  
**POC仓库:** [cve-2022-1388-poc](https://github.com/XiaomingX/cve-2022-1388-poc)  

---

### [CVE-2020-16898](CVE-2020-16898-esnet-security_cve-2020-16898.md) 🔴 

**名称:** CVE-2020-16898 - Windows TCP/IP 远程代码执行漏洞 (Bad Neighbor)  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致远程代码执行，系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [cve-2020-16898](https://github.com/esnet-security/cve-2020-16898)  

---

### [CVE-2020-16898](CVE-2020-16898-Maliek_CVE-2020-16898_Check.md) 🔴 ✅

**名称:** CVE-2020-16898 "Bad Neighbor"  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2020-16898_Check](https://github.com/Maliek/CVE-2020-16898_Check)  

---

### [CVE-2020-16898](CVE-2020-16898-Q1984_CVE-2020-16898.md) 🔴 ✅

**名称:** CVE-2020-16898 Bad Neighbor  
**类型:** 远程代码执行/拒绝服务  
**风险:** 高危，可能导致远程代码执行或拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2020-16898](https://github.com/Q1984/CVE-2020-16898)  

---

### [CVE-2020-16898](CVE-2020-16898-0xeb-bp_cve-2020-16898.md) 🔴 ✅

**名称:** CVE-2020-16898-Windows TCP/IP远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致远程代码执行和系统崩溃（蓝屏）  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [cve-2020-16898](https://github.com/0xeb-bp/cve-2020-16898)  

---

### [CVE-2020-16898](CVE-2020-16898-jiansiting_cve-2020-16898.md) 🔴 ✅

**名称:** CVE-2020-16898 Bad Neighbor  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行或拒绝服务  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [cve-2020-16898](https://github.com/jiansiting/cve-2020-16898)  

---

### [CVE-2020-16898](CVE-2020-16898-momika233_CVE-2020-16898-exp.md) 🔴 ✅

**名称:** CVE-2020-16898 - Windows TCP/IP 远程代码执行漏洞（Bad Neighbor）  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致远程代码执行或拒绝服务  
**投毒风险:** 5%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2020-16898-exp](https://github.com/momika233/CVE-2020-16898-exp)  

---

### [CVE-2020-16898](CVE-2020-16898-CPO-EH_CVE-2020-16898_Workaround.md) 🔴 

**名称:** CVE-2020-16898  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许远程攻击者在目标系统上执行代码  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2020-16898_Workaround](https://github.com/CPO-EH/CVE-2020-16898_Workaround)  

---

### [CVE-2020-16898](CVE-2020-16898-CPO-EH_CVE-2020-16898_Checker.md) 🔴 

**名称:** CVE-2020-16898 "Bad Neighbor" Windows TCP/IP 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2020-16898_Checker](https://github.com/CPO-EH/CVE-2020-16898_Checker)  

---

### [CVE-2020-16898](CVE-2020-16898-initconf_CVE-2020-16898-Bad-Neighbor.md) 🔴 ✅

**名称:** CVE-2020-16898: Bad Neighbor - Windows TCP/IP远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致远程代码执行或拒绝服务 (DoS)  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2020-16898-Bad-Neighbor](https://github.com/initconf/CVE-2020-16898-Bad-Neighbor)  

---

### [CVE-2020-16898](CVE-2020-16898-advanced-threat-research_CVE-2020-16898.md) 🔴 ✅

**名称:** CVE-2020-16898: Windows TCP/IP 远程代码执行漏洞 ("Bad Neighbor")  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致远程代码执行、拒绝服务  
**投毒风险:** 1%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2020-16898](https://github.com/advanced-threat-research/CVE-2020-16898)  

---

### [CVE-2020-16898](CVE-2020-16898-komomon_CVE-2020-16898-EXP-POC.md) 🔴 ✅

**名称:** CVE-2020-16898 Windows TCP/IP 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行或拒绝服务（蓝屏）  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2020-16898-EXP-POC](https://github.com/komomon/CVE-2020-16898-EXP-POC)  

---

### [CVE-2020-16898](CVE-2020-16898-komomon_CVE-2020-16898--EXP-POC.md) 🔴 ✅

**名称:** CVE-2020-16898 Windows TCP/IP 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可导致远程代码执行甚至蓝屏死机（BSOD）  
**投毒风险:** 5%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2020-16898--EXP-POC](https://github.com/komomon/CVE-2020-16898--EXP-POC)  

---

### [CVE-2020-16898](CVE-2020-16898-corelight_CVE-2020-16898.md) 🔴 ✅

**名称:** CVE-2020-16898 - Windows TCP/IP 远程代码执行漏洞（Bad Neighbor）  
**类型:** 远程代码执行（RCE）  
**风险:** 高危，可能导致远程代码执行，完全控制受影响系统  
**投毒风险:** 5%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2020-16898](https://github.com/corelight/CVE-2020-16898)  

---

### [CVE-2020-16898](CVE-2020-16898-ZephrFish_CVE-2020-16898.md) 🔴 ✅

**名称:** CVE-2020-16898 Bad Neighbor  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 70%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2020-16898](https://github.com/ZephrFish/CVE-2020-16898)  

---

### [CVE-2021-26855](CVE-2021-26855-shacojx_Scan-Vuln-CVE-2021-26855.md) 🔴 ✅

**名称:** CVE-2021-26855 - Microsoft Exchange Server SSRF  
**类型:** 服务器端请求伪造 (SSRF)  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [Scan-Vuln-CVE-2021-26855](https://github.com/shacojx/Scan-Vuln-CVE-2021-26855)  

---

### [CVE-2021-26855](CVE-2021-26855-Immersive-Labs-Sec_ProxyLogon.md) 🔴 ✅

**名称:** CVE-2021-26855 - Microsoft Exchange Server Remote Code Execution Vulnerability (ProxyLogon)  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致完全控制 Exchange 服务器  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [ProxyLogon](https://github.com/Immersive-Labs-Sec/ProxyLogon)  

---

### [CVE-2021-26855](CVE-2021-26855-hictf_CVE-2021-26855-CVE-2021-27065.md) 🔴 ✅

**名称:** CVE-2021-26855 Microsoft Exchange Server SSRF 远程代码执行漏洞  
**类型:** SSRF (服务器端请求伪造) -> 远程代码执行  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 20%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2021-26855-CVE-2021-27065](https://github.com/hictf/CVE-2021-26855-CVE-2021-27065)  

---

### [CVE-2021-26855](CVE-2021-26855-praetorian-inc_proxylogon-exploit.md) 🔴 ✅

**名称:** CVE-2021-26855 Microsoft Exchange Server 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的攻击者可远程执行任意代码，完全控制 Exchange 服务器。  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [proxylogon-exploit](https://github.com/praetorian-inc/proxylogon-exploit)  

---

### [CVE-2021-26855](CVE-2021-26855-Flangvik_SharpProxyLogon.md)  ✅

**名称:** CVE-2021-26855 Microsoft Exchange Server Remote Code Execution Vulnerability (ProxyLogon)  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，未经身份验证的攻击者可以远程执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [SharpProxyLogon](https://github.com/Flangvik/SharpProxyLogon)  

---

### [CVE-2021-26855](CVE-2021-26855-shacojx_CVE-2021-26855-exploit-Exchange.md) 🔴 ✅

**名称:** CVE-2021-26855 Microsoft Exchange Server 远程代码执行漏洞（ProxyLogon）  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2021-26855-exploit-Exchange](https://github.com/shacojx/CVE-2021-26855-exploit-Exchange)  

---

### [CVE-2021-26855](CVE-2021-26855-Nick-Yin12_106362522.md)  ✅

**名称:** CVE-2021-26855 Microsoft Exchange Server 远程代码执行漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致完全系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [106362522](https://github.com/Nick-Yin12/106362522)  

---

### [CVE-2021-26855](CVE-2021-26855-SCS-Labs_HAFNIUM-Microsoft-Exchange-0day.md)  ✅

**名称:** CVE-2021-26855 Microsoft Exchange Server 远程代码执行漏洞  
**类型:** 服务器端请求伪造 (SSRF)  
**风险:** 严重，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [HAFNIUM-Microsoft-Exchange-0day](https://github.com/SCS-Labs/HAFNIUM-Microsoft-Exchange-0day)  

---

### [CVE-2021-26855](CVE-2021-26855-RickGeex_ProxyLogon.md) 🔴 ✅

**名称:** CVE-2021-26855 Microsoft Exchange Server 远程代码执行漏洞 (ProxyLogon)  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的攻击者在Exchange服务器上执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-04-26  
**POC仓库:** [ProxyLogon](https://github.com/RickGeex/ProxyLogon)  

---

### [CVE-2021-26855](CVE-2021-26855-yaoxiaoangry3_Flangvik.md) 🔴 ✅

**名称:** CVE-2021-26855 Microsoft Exchange Server ProxyLogon RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [Flangvik](https://github.com/yaoxiaoangry3/Flangvik)  

---

### [CVE-2021-26855](CVE-2021-26855-thau0x01_poc_proxylogon.md) 🔴 ✅

**名称:** CVE-2021-26855 Microsoft Exchange Server Remote Code Execution Vulnerability (ProxyLogon)  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的远程攻击者可以执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-04-26  
**POC仓库:** [poc_proxylogon](https://github.com/thau0x01/poc_proxylogon)  

---

### [CVE-2021-26855](CVE-2021-26855-dwisiswant0_proxylogscan.md) 🔴 ✅

**名称:** CVE-2021-26855 Microsoft Exchange Server SSRF 漏洞  
**类型:** 服务器端请求伪造 (SSRF)  
**风险:** 高危，可能导致信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [proxylogscan](https://github.com/dwisiswant0/proxylogscan)  

---

### [CVE-2021-26855](CVE-2021-26855-hakivvi_proxylogon.md) 🔴 ✅

**名称:** CVE-2021-26855 - Microsoft Exchange Server Remote Code Execution  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致完全控制受影响的Exchange服务器  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [proxylogon](https://github.com/hakivvi/proxylogon)  

---

### [CVE-2021-26855](CVE-2021-26855-1342486672_Flangvik.md) 🔴 ✅

**名称:** CVE-2021-26855 - Microsoft Exchange Server ProxyLogon RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [Flangvik](https://github.com/1342486672/Flangvik)  

---

### [CVE-2021-26855](CVE-2021-26855-hosch3n_ProxyVulns.md) 🔴 ✅

**名称:** CVE-2021-26855 - Microsoft Exchange Server Remote Code Execution Vulnerability (ProxyLogon)  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，无需身份验证即可远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-26  
**POC仓库:** [ProxyVulns](https://github.com/hosch3n/ProxyVulns)  

---

### [CVE-2021-26855](CVE-2021-26855-ssrsec_Microsoft-Exchange-RCE.md) 🔴 ✅

**名称:** CVE-2021-26855 & CVE-2021-27065 - Microsoft Exchange Server RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [Microsoft-Exchange-RCE](https://github.com/ssrsec/Microsoft-Exchange-RCE)  

---

### [CVE-2021-26855](CVE-2021-26855-kh4sh3i_ProxyLogon.md)  ✅

**名称:** CVE-2021-26855 - Microsoft Exchange Server SSRF/RCE (ProxyLogon)  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，未经验证的远程攻击者可以利用此漏洞在受影响的服务器上执行任意代码。  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [ProxyLogon](https://github.com/kh4sh3i/ProxyLogon)  

---

### [CVE-2021-26855](CVE-2021-26855-ShyTangerine_cve-2021-26855.md) 🔴 ✅

**名称:** CVE-2021-26855 - Microsoft Exchange Server SSRF  
**类型:** 服务器端请求伪造 (SSRF)  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [cve-2021-26855](https://github.com/ShyTangerine/cve-2021-26855)  

---

### [CVE-2021-26855](CVE-2021-26855-r0xdeadbeef_CVE-2021-26855.md) 🔴 ✅

**名称:** CVE-2021-26855 Microsoft Exchange Server ProxyLogon RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的远程攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2021-26855](https://github.com/r0xdeadbeef/CVE-2021-26855)  

---

### [CVE-2021-26855](CVE-2021-26855-timb-machine-mirrors_testanull-CVE-2021-26855_read_poc.txt.md) 🔴 ✅

**名称:** CVE-2021-26855-Microsoft Exchange Server-SSRF  
**类型:** 服务器端请求伪造 (SSRF)  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [testanull-CVE-2021-26855_read_poc.txt](https://github.com/timb-machine-mirrors/testanull-CVE-2021-26855_read_poc.txt)  

---

### [CVE-2021-26855](CVE-2021-26855-glen-pearson_ProxyLogon-CVE-2021-26855.md)  ✅

**名称:** CVE-2021-26855 Microsoft Exchange Server 远程代码执行漏洞 (ProxyLogon)  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，未经验证的远程攻击者可以利用此漏洞在受影响的系统上执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [ProxyLogon-CVE-2021-26855](https://github.com/glen-pearson/ProxyLogon-CVE-2021-26855)  

---

### [CVE-2021-26855](CVE-2021-26855-ZephrFish_Exch-CVE-2021-26855.md) 🔴 ✅

**名称:** CVE-2021-26855 - Microsoft Exchange Server SSRF to RCE (ProxyLogon)  
**类型:** SSRF (Server-Side Request Forgery) -> RCE (Remote Code Execution)  
**风险:** 高危，允许未经身份验证的远程攻击者执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-04-26  
**POC仓库:** [Exch-CVE-2021-26855](https://github.com/ZephrFish/Exch-CVE-2021-26855)  

---

### [CVE-2021-26855](CVE-2021-26855-ZephrFish_Exch-CVE-2021-26855_Priv.md) 🔴 ✅

**名称:** CVE-2021-26855 - Microsoft Exchange Server Remote Code Execution  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的远程攻击者在受影响的 Exchange 服务器上执行任意代码。  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [Exch-CVE-2021-26855_Priv](https://github.com/ZephrFish/Exch-CVE-2021-26855_Priv)  

---

### [CVE-2021-22986](CVE-2021-22986-dorkerdevil_CVE-2021-22986-Poc.md) 🔴 ✅

**名称:** CVE-2021-22986-F5 BIG-IP/BIG-IQ iControl REST RCE  
**类型:** 远程命令执行  
**风险:** 高危，可导致完全控制受影响的系统  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2021-22986-Poc](https://github.com/dorkerdevil/CVE-2021-22986-Poc)  

---

### [CVE-2021-22986](CVE-2021-22986-Osyanina_westone-CVE-2021-22986-scanner.md) 🔴 ✅

**名称:** CVE-2021-22986-F5 BIG-IP iControl REST RCE  
**类型:** 远程代码执行  
**风险:** 高危，未授权远程命令执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [westone-CVE-2021-22986-scanner](https://github.com/Osyanina/westone-CVE-2021-22986-scanner)  

---

### [CVE-2021-22986](CVE-2021-22986-safesword_F5_RCE.md) 🔴 ✅

**名称:** CVE-2021-22986-F5 BIG-IP/BIG-IQ-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，未经身份验证的远程命令执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-26  
**POC仓库:** [F5_RCE](https://github.com/safesword/F5_RCE)  

---

### [CVE-2021-22986](CVE-2021-22986-microvorld_CVE-2021-22986.md) 🔴 ✅

**名称:** CVE-2021-22986 - F5 BIG-IP/BIG-IQ iControl REST API 远程命令执行  
**类型:** 远程命令执行 (RCE)  
**风险:** 高危，可能导致完全控制系统  
**投毒风险:** 1%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2021-22986](https://github.com/microvorld/CVE-2021-22986)  

---

### [CVE-2021-22986](CVE-2021-22986-kiri-48_CVE-2021-22986.md) 🔴 ✅

**名称:** CVE-2021-22986-F5 BIG-IP/BIG-IQ-iControl REST RCE  
**类型:** 远程命令执行  
**风险:** 高危，可完全控制系统  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2021-22986](https://github.com/kiri-48/CVE-2021-22986)  

---

### [CVE-2021-22986](CVE-2021-22986-yaunsky_CVE-202122986-EXP.md) 🔴 ✅

**名称:** CVE-2021-22986-F5 BIG-IP iControl REST 远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，未经身份验证的远程命令执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-202122986-EXP](https://github.com/yaunsky/CVE-202122986-EXP)  

---

### [CVE-2021-22986](CVE-2021-22986-S1xHcL_f5_rce_poc.md) 🔴 ✅

**名称:** CVE-2021-22986-F5-BIG-IP-iControl-REST-RCE  
**类型:** 远程命令执行  
**风险:** 高危，可导致完全控制受影响的系统  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [f5_rce_poc](https://github.com/S1xHcL/f5_rce_poc)  

---

### [CVE-2021-22986](CVE-2021-22986-Tas9er_CVE-2021-22986.md) 🔴 ✅

**名称:** CVE-2021-22986-F5 BIG-IP iControl RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2021-22986](https://github.com/Tas9er/CVE-2021-22986)  

---

### [CVE-2021-22986](CVE-2021-22986-dotslashed_CVE-2021-22986.md) 🔴 ✅

**名称:** CVE-2021-22986 F5 BIG-IP/BIG-IQ iControl REST API 远程命令执行  
**类型:** 远程命令执行 (RCE)  
**风险:** 高危，未经身份验证的远程命令执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2021-22986](https://github.com/dotslashed/CVE-2021-22986)  

---

### [CVE-2021-22986](CVE-2021-22986-Al1ex_CVE-2021-22986.md) 🔴 ✅

**名称:** CVE-2021-22986-F5 BIG-IP/BIG-IQ-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可导致完全控制系统  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2021-22986](https://github.com/Al1ex/CVE-2021-22986)  

---

### [CVE-2021-22986](CVE-2021-22986-DDestinys_CVE-2021-22986.md) 🔴 ✅

**名称:** CVE-2021-22986-F5 BIG-IP/BIG-IQ-iControl REST RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2021-22986](https://github.com/DDestinys/CVE-2021-22986)  

---

### [CVE-2021-22986](CVE-2021-22986-amitlttwo_CVE-2021-22986.md) 🔴 ✅

**名称:** CVE-2021-22986 - F5 BIG-IP/BIG-IQ iControl REST RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的远程命令执行，可完全控制系统  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2021-22986](https://github.com/amitlttwo/CVE-2021-22986)  

---

### [CVE-2021-22986](CVE-2021-22986-huydung26_CVE-2021-22986.md) 🔴 ✅

**名称:** CVE-2021-22986-F5 BIG-IP/BIG-IQ-iControl REST未授权远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致完全控制系统  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2021-22986](https://github.com/huydung26/CVE-2021-22986)  

---

### [CVE-2024-4577](CVE-2024-4577-ZephrFish_CVE-2024-4577-PHP-RCE.md) 🔴 ✅

**名称:** CVE-2024-4577-PHP-CGI参数注入RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2024-4577-PHP-RCE](https://github.com/ZephrFish/CVE-2024-4577-PHP-RCE)  

---

### [CVE-2021-41773](CVE-2021-41773-ZephrFish_CVE-2021-41773-PoC.md) 🔴 ✅

**名称:** CVE-2021-41773 - Apache HTTP Server Path Traversal and Remote Code Execution  
**类型:** 路径遍历（Path Traversal）/远程代码执行（RCE）  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2021-41773-PoC](https://github.com/ZephrFish/CVE-2021-41773-PoC)  

---

### [CVE-2020-7842](CVE-2020-7842-GangTaegyeong_CVE-2020-7842.md) 🟡 

**名称:** CVE-2020-7842-Netis Korea D'live AP-命令注入  
**类型:** 命令注入  
**风险:** 中危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2020-7842](https://github.com/GangTaegyeong/CVE-2020-7842)  

---

### [CVE-2025-3102](CVE-2025-3102-SUPRAAA-1337_CVE-2025-3102-exploit.md) 🔴 ✅

**名称:** CVE-2025-3102-SureTriggers-身份验证绕过导致管理员账户创建  
**类型:** 身份验证绕过  
**风险:** 高危，允许未经验证的攻击者创建管理员账户，完全控制网站  
**投毒风险:** 0%  
**发现时间:** 2025-04-26  
**POC仓库:** [CVE-2025-3102-exploit](https://github.com/SUPRAAA-1337/CVE-2025-3102-exploit)  

---

### [CVE-2023-46012](CVE-2023-46012-dest-3_CVE-2023-46012.md) 🔴 ✅

**名称:** CVE-2023-46012 - Linksys EA7500 远程代码执行  
**类型:** 栈缓冲区溢出  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2023-46012](https://github.com/dest-3/CVE-2023-46012)  

---

### [CVE-2019-5420](CVE-2019-5420-AnasTaoutaou_CVE-2019-5420.md) 🔴 ✅

**名称:** CVE-2019-5420 - Rails Development Mode Remote Code Execution  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致完全控制服务器  
**投毒风险:** 0%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2019-5420](https://github.com/AnasTaoutaou/CVE-2019-5420)  

---

### [CVE-2019-5420](CVE-2019-5420-sealldeveloper_CVE-2019-5420-PoC.md) 🔴 ✅

**名称:** CVE-2019-5420 - Rails Development Mode Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和服务器控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2019-5420-PoC](https://github.com/sealldeveloper/CVE-2019-5420-PoC)  

---

### [CVE-2023-1545](CVE-2023-1545-HarshRajSinghania_CVE-2023-1545-Exploit.md) 🔴 ✅

**名称:** CVE-2023-1545-Teampass-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致敏感信息泄露，如用户名和密码  
**投毒风险:** 10%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2023-1545-Exploit](https://github.com/HarshRajSinghania/CVE-2023-1545-Exploit)  

---

### [CVE-2023-1545](CVE-2023-1545-zer0-dave_CVE-2023-1545-POC.md) 🔴 ✅

**名称:** CVE-2023-1545-Teampass-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露  
**投毒风险:** 1%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2023-1545-POC](https://github.com/zer0-dave/CVE-2023-1545-POC)  

---

### [CVE-2023-1545](CVE-2023-1545-sternstundes_CVE-2023-1545-POC-python.md) 🔴 ✅

**名称:** CVE-2023-1545-Teampass-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2023-1545-POC-python](https://github.com/sternstundes/CVE-2023-1545-POC-python)  

---

### [CVE-2023-1545](CVE-2023-1545-gunzf0x_CVE-2023-1545.md) 🔴 ✅

**名称:** CVE-2023-1545-Teampass-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致敏感数据泄露，例如用户名和密码。  
**投毒风险:** 0%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2023-1545](https://github.com/gunzf0x/CVE-2023-1545)  

---

### [CVE-2019-5420](CVE-2019-5420-knqyf263_CVE-2019-5420.md) 🔴 ✅

**名称:** CVE-2019-5420-Rails开发模式远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2019-5420](https://github.com/knqyf263/CVE-2019-5420)  

---

### [CVE-2019-5420](CVE-2019-5420-Eremiel_CVE-2019-5420.md) 🔴 ✅

**名称:** CVE-2019-5420 - Rails Development Mode Remote Code Execution  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2019-5420](https://github.com/Eremiel/CVE-2019-5420)  

---

### [CVE-2019-5420](CVE-2019-5420-j4k0m_CVE-2019-5420.md) 🔴 ✅

**名称:** CVE-2019-5420 - Rails 开发模式远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2019-5420](https://github.com/j4k0m/CVE-2019-5420)  

---

### [CVE-2019-5420](CVE-2019-5420-mmeza-developer_CVE-2019-5420-RCE.md) 🔴 ✅

**名称:** CVE-2019-5420-Rails-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可完全控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2019-5420-RCE](https://github.com/mmeza-developer/CVE-2019-5420-RCE)  

---

### [CVE-2019-5420](CVE-2019-5420-scumdestroy_CVE-2019-5420.rb.md) 🔴 ✅

**名称:** CVE-2019-5420 - Rails Development Mode Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2019-5420.rb](https://github.com/scumdestroy/CVE-2019-5420.rb)  

---

### [CVE-2019-5420](CVE-2019-5420-trickstersec_CVE-2019-5420.md) 🔴 ✅

**名称:** CVE-2019-5420-Rails-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2019-5420](https://github.com/trickstersec/CVE-2019-5420)  

---

### [CVE-2019-5420](CVE-2019-5420-PenTestical_CVE-2019-5420.md) 🔴 ✅

**名称:** CVE-2019-5420-Rails-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2019-5420](https://github.com/PenTestical/CVE-2019-5420)  

---

### [CVE-2019-5420](CVE-2019-5420-laffray_ruby-RCE-CVE-2019-5420-.md) 🔴 ✅

**名称:** CVE-2019-5420 - Rails Development Mode 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-25  
**POC仓库:** [ruby-RCE-CVE-2019-5420-](https://github.com/laffray/ruby-RCE-CVE-2019-5420-)  

---

### [CVE-2019-5420](CVE-2019-5420-cved-sources_cve-2019-5420.md) 🔴 ✅

**名称:** CVE-2019-5420 - Rails 开发模式远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-04-25  
**POC仓库:** [cve-2019-5420](https://github.com/cved-sources/cve-2019-5420)  

---

### [CVE-2019-5420](CVE-2019-5420-WildWestCyberSecurity_cve-2019-5420-POC.md) 🔴 ✅

**名称:** CVE-2019-5420-Rails-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-25  
**POC仓库:** [cve-2019-5420-POC](https://github.com/WildWestCyberSecurity/cve-2019-5420-POC)  

---

### [CVE-2024-32830](CVE-2024-32830-ptrstr_CVE-2024-32830-poc.md) 🔴 ✅

**名称:** CVE-2024-32830-BuddyForms-路径遍历和SSRF  
**类型:** 路径遍历和SSRF  
**风险:** 高危，可能导致敏感文件读取和服务器端请求伪造  
**投毒风险:** 10%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2024-32830-poc](https://github.com/ptrstr/CVE-2024-32830-poc)  

---

### [CVE-2016-2098](CVE-2016-2098-Alejandro-MartinG_rails-PoC-CVE-2016-2098.md) 🔴 ✅

**名称:** CVE-2016-2098 - Ruby on Rails Action Pack 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-04-25  
**POC仓库:** [rails-PoC-CVE-2016-2098](https://github.com/Alejandro-MartinG/rails-PoC-CVE-2016-2098)  

---

### [CVE-2023-41425](CVE-2023-41425-becrevex_CVE-2023-41425.md) 🟡 ✅

**名称:** CVE-2023-41425-WonderCMS-XSS  
**类型:** 跨站脚本 (XSS)  
**风险:** 中危，可能导致用户信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2023-41425](https://github.com/becrevex/CVE-2023-41425)  

---

### [CVE-2016-2098](CVE-2016-2098-hderms_dh-CVE_2016_2098.md) 🔴 ✅

**名称:** CVE-2016-2098-Ruby on Rails-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许远程攻击者执行任意 Ruby 代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-25  
**POC仓库:** [dh-CVE_2016_2098](https://github.com/hderms/dh-CVE_2016_2098)  

---

### [CVE-2016-2098](CVE-2016-2098-CyberDefenseInstitute_PoC_CVE-2016-2098_Rails42.md) 🔴 ✅

**名称:** CVE-2016-2098-Ruby on Rails Action Pack RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许远程攻击者执行任意Ruby代码  
**投毒风险:** 1%  
**发现时间:** 2025-04-25  
**POC仓库:** [PoC_CVE-2016-2098_Rails42](https://github.com/CyberDefenseInstitute/PoC_CVE-2016-2098_Rails42)  

---

### [CVE-2016-2098](CVE-2016-2098-0x00-0x00_CVE-2016-2098.md) 🔴 ✅

**名称:** CVE-2016-2098 - Ruby on Rails 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2016-2098](https://github.com/0x00-0x00/CVE-2016-2098)  

---

### [CVE-2016-2098](CVE-2016-2098-3rg1s_CVE-2016-2098.md) 🔴 ✅

**名称:** CVE-2016-2098 - Ruby on Rails 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2016-2098](https://github.com/3rg1s/CVE-2016-2098)  

---

### [CVE-2016-2098](CVE-2016-2098-its-arun_CVE-2016-2098.md) 🔴 ✅

**名称:** CVE-2016-2098 - Ruby on Rails Action Pack 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许攻击者执行任意Ruby代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2016-2098](https://github.com/its-arun/CVE-2016-2098)  

---

### [CVE-2016-2098](CVE-2016-2098-DanielHemmati_CVE-2016-2098-my-first-exploit.md) 🔴 ✅

**名称:** CVE-2016-2098 - Ruby on Rails 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2016-2098-my-first-exploit](https://github.com/DanielHemmati/CVE-2016-2098-my-first-exploit)  

---

### [CVE-2016-2098](CVE-2016-2098-Debalinax64_CVE-2016-2098.md) 🔴 ✅

**名称:** CVE-2016-2098 - Ruby on Rails Action Pack 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2016-2098](https://github.com/Debalinax64/CVE-2016-2098)  

---

### [CVE-2016-2098](CVE-2016-2098-j4k0m_CVE-2016-2098.md) 🔴 ✅

**名称:** CVE-2016-2098 - Ruby on Rails 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2016-2098](https://github.com/j4k0m/CVE-2016-2098)  

---

### [CVE-2016-2098](CVE-2016-2098-Shakun8_CVE-2016-2098.md) 🔴 ✅

**名称:** CVE-2016-2098-Ruby on Rails-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2016-2098](https://github.com/Shakun8/CVE-2016-2098)  

---

### [CVE-2016-2098](CVE-2016-2098-JoseLRC97_Ruby-on-Rails-ActionPack-Inline-ERB-Remote-Code-Execution.md) 🔴 ✅

**名称:** CVE-2016-2098-Ruby on Rails Action Pack-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-25  
**POC仓库:** [Ruby-on-Rails-ActionPack-Inline-ERB-Remote-Code-Execution](https://github.com/JoseLRC97/Ruby-on-Rails-ActionPack-Inline-ERB-Remote-Code-Execution)  

---

### [CVE-2016-2098](CVE-2016-2098-sealldeveloper_CVE-2016-2098-PoC.md) 🔴 ✅

**名称:** CVE-2016-2098-Ruby on Rails-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2016-2098-PoC](https://github.com/sealldeveloper/CVE-2016-2098-PoC)  

---

### [CVE-2023-41064](CVE-2023-41064-MrR0b0t19_CVE-2023-41064.md) 🔴 ✅

**名称:** CVE-2023-41064-ImageIO-WebP缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 50%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2023-41064](https://github.com/MrR0b0t19/CVE-2023-41064)  

---

### [CVE-2025-31324](CVE-2025-31324-rxerium_CVE-2025-31324.md) 🔴 ✅

**名称:** CVE-2025-31324-SAP NetWeaver Visual Composer-未授权文件上传  
**类型:** 未授权文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2025-31324](https://github.com/rxerium/CVE-2025-31324)  

---

### [CVE-2016-10033](CVE-2016-10033-Zenexer_safeshell.md) 🔴 ✅

**名称:** CVE-2016-10033-PHPMailer-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-25  
**POC仓库:** [safeshell](https://github.com/Zenexer/safeshell)  

---

### [CVE-2016-10033](CVE-2016-10033-GeneralTesler_CVE-2016-10033.md) 🔴 ✅

**名称:** CVE-2016-10033-PHPMailer-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2016-10033](https://github.com/GeneralTesler/CVE-2016-10033)  

---

### [CVE-2016-10033](CVE-2016-10033-Bajunan_CVE-2016-10033.md) 🔴 ✅

**名称:** CVE-2016-10033 - PHPMailer远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2016-10033](https://github.com/Bajunan/CVE-2016-10033)  

---

### [CVE-2016-10033](CVE-2016-10033-chipironcin_CVE-2016-10033.md) 🔴 ✅

**名称:** CVE-2016-10033-PHPMailer-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2016-10033](https://github.com/chipironcin/CVE-2016-10033)  

---

### [CVE-2016-10033](CVE-2016-10033-liusec_WP-CVE-2016-10033.md) 🔴 ✅

**名称:** CVE-2016-10033-PHPMailer远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-25  
**POC仓库:** [WP-CVE-2016-10033](https://github.com/liusec/WP-CVE-2016-10033)  

---

### [CVE-2016-10033](CVE-2016-10033-pedro823_cve-2016-10033-45.md) 🔴 ✅

**名称:** CVE-2016-10033 - PHPMailer 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-25  
**POC仓库:** [cve-2016-10033-45](https://github.com/pedro823/cve-2016-10033-45)  

---

### [CVE-2016-10033](CVE-2016-10033-awidardi_opsxcq-cve-2016-10033.md) 🔴 ✅

**名称:** CVE-2016-10033-PHPMailer-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许远程攻击者执行任意代码  
**投毒风险:** 20%  
**发现时间:** 2025-04-25  
**POC仓库:** [opsxcq-cve-2016-10033](https://github.com/awidardi/opsxcq-cve-2016-10033)  

---

### [CVE-2016-10033](CVE-2016-10033-0x00-0x00_CVE-2016-10033.md) 🔴 ✅

**名称:** CVE-2016-10033-PHPMailer-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2016-10033](https://github.com/0x00-0x00/CVE-2016-10033)  

---

### [CVE-2016-10033](CVE-2016-10033-cved-sources_cve-2016-10033.md) 🔴 ✅

**名称:** CVE-2016-10033-PHPMailer-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-25  
**POC仓库:** [cve-2016-10033](https://github.com/cved-sources/cve-2016-10033)  

---

### [CVE-2016-10033](CVE-2016-10033-j4k0m_CVE-2016-10033.md) 🔴 ✅

**名称:** CVE-2016-10033-PHPMailer-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2016-10033](https://github.com/j4k0m/CVE-2016-10033)  

---

### [CVE-2016-10033](CVE-2016-10033-zeeshanbhattined_exploit-CVE-2016-10033.md) 🔴 ✅

**名称:** CVE-2016-10033-PHPMailer-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-04-25  
**POC仓库:** [exploit-CVE-2016-10033](https://github.com/zeeshanbhattined/exploit-CVE-2016-10033)  

---

### [CVE-2016-10033](CVE-2016-10033-opsxcq_exploit-CVE-2016-10033.md) 🔴 ✅

**名称:** CVE-2016-10033-PHPMailer-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-25  
**POC仓库:** [exploit-CVE-2016-10033](https://github.com/opsxcq/exploit-CVE-2016-10033)  

---

### [CVE-2016-10033](CVE-2016-10033-ElnurBDa_CVE-2016-10033.md) 🔴 ✅

**名称:** CVE-2016-10033 - PHPMailer Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2016-10033](https://github.com/ElnurBDa/CVE-2016-10033)  

---

### [CVE-2016-10033](CVE-2016-10033-Astrowmist_POC-CVE-2016-10033.md) 🔴 ✅

**名称:** CVE-2016-10033 - PHPMailer Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-25  
**POC仓库:** [POC-CVE-2016-10033](https://github.com/Astrowmist/POC-CVE-2016-10033)  

---

### [CVE-2016-10033](CVE-2016-10033-sealldeveloper_CVE-2016-10033-PoC.md) 🔴 ✅

**名称:** CVE-2016-10033-PHPMailer-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2016-10033-PoC](https://github.com/sealldeveloper/CVE-2016-10033-PoC)  

---

### [CVE-2025-32433](CVE-2025-32433-0x7556_CVE-2025-32433.md) 🔴 ✅

**名称:** CVE-2025-32433 Erlang/OTP SSH RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未授权远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2025-32433](https://github.com/0x7556/CVE-2025-32433)  

---

### [CVE-2025-32433](CVE-2025-32433-becrevex_CVE-2025-32433.md) 🔴 ✅

**名称:** CVE-2025-32433-Erlang/OTP SSH-未授权RCE  
**类型:** 未授权远程代码执行  
**风险:** 高危，未经授权的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2025-32433](https://github.com/becrevex/CVE-2025-32433)  

---

### [CVE-2023-41064](CVE-2023-41064-MrR0b0t19_vulnerabilidad-LibWebP-CVE-2023-41064.md) 🔴 ✅

**名称:** CVE-2023-41064-ImageIO-缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 80%  
**发现时间:** 2025-04-25  
**POC仓库:** [vulnerabilidad-LibWebP-CVE-2023-41064](https://github.com/MrR0b0t19/vulnerabilidad-LibWebP-CVE-2023-41064)  

---

### [CVE-2023-41064](CVE-2023-41064-sarsaeroth_CVE-2023-41064-POC.md) 🔴 ✅

**名称:** CVE-2023-41064-ImageIO缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2023-41064-POC](https://github.com/sarsaeroth/CVE-2023-41064-POC)  

---

### [CVE-2023-41064](CVE-2023-41064-K4Der11000_k4_cve-2023-41064.md) 🔴 ✅

**名称:** CVE-2023-41064 - ImageIO 缓冲区溢出漏洞  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-25  
**POC仓库:** [k4_cve-2023-41064](https://github.com/K4Der11000/k4_cve-2023-41064)  

---

### [CVE-2018-0114](CVE-2018-0114-Logeirs_CVE-2018-0114.md) 🔴 ✅

**名称:** CVE-2018-0114-Node-jose-JWT签名伪造  
**类型:** JWT签名伪造  
**风险:** 高危，允许未授权的远程攻击者使用嵌入在token中的密钥重新签名token，从而伪造JWT。  
**投毒风险:** 10%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2018-0114](https://github.com/Logeirs/CVE-2018-0114)  

---

### [CVE-2018-0114](CVE-2018-0114-Eremiel_CVE-2018-0114.md) 🔴 ✅

**名称:** CVE-2018-0114-Node-jose-JWT 签名伪造  
**类型:** JWT 签名伪造  
**风险:** 高危，可能导致权限提升和身份伪造  
**投毒风险:** 0%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2018-0114](https://github.com/Eremiel/CVE-2018-0114)  

---

### [CVE-2018-0114](CVE-2018-0114-Starry-lord_CVE-2018-0114.md) 🔴 ✅

**名称:** CVE-2018-0114 - Node-jose Library JWT 签名伪造  
**类型:** JWT 签名伪造  
**风险:** 高危，允许未授权的远程攻击者伪造 JWT 令牌  
**投毒风险:** 0%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2018-0114](https://github.com/Starry-lord/CVE-2018-0114)  

---

### [CVE-2018-0114](CVE-2018-0114-adityathebe_POC-CVE-2018-0114.md) 🔴 ✅

**名称:** CVE-2018-0114-Node-jose-JWT密钥混淆  
**类型:** JWT密钥混淆  
**风险:** 高危，允许未授权的远程攻击者重新签名令牌，可能导致身份伪造和权限提升。  
**投毒风险:** 0%  
**发现时间:** 2025-04-25  
**POC仓库:** [POC-CVE-2018-0114](https://github.com/adityathebe/POC-CVE-2018-0114)  

---

### [CVE-2018-0114](CVE-2018-0114-j4k0m_CVE-2018-0114.md) 🔴 ✅

**名称:** CVE-2018-0114 Node-jose JWT 签名伪造  
**类型:** JWT签名伪造  
**风险:** 高危，可能导致身份冒用和未授权访问  
**投毒风险:** 0%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2018-0114](https://github.com/j4k0m/CVE-2018-0114)  

---

### [CVE-2018-0114](CVE-2018-0114-mmeza-developer_CVE-2018-0114.md) 🔴 ✅

**名称:** CVE-2018-0114 - Node-jose Library JWT 签名伪造  
**类型:** JWT 签名伪造  
**风险:** 高危，允许未授权的远程攻击者使用嵌入在 token 中的密钥重新签名 token，可能导致权限提升和数据篡改。  
**投毒风险:** 10%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2018-0114](https://github.com/mmeza-developer/CVE-2018-0114)  

---

### [CVE-2018-0114](CVE-2018-0114-scumdestroy_CVE-2018-0114.md) 🔴 ✅

**名称:** CVE-2018-0114-Node-jose-JWT签名伪造  
**类型:** JWT签名伪造  
**风险:** 高危，允许未授权的攻击者伪造JWT令牌，可能导致身份冒充和权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2018-0114](https://github.com/scumdestroy/CVE-2018-0114)  

---

### [CVE-2018-0114](CVE-2018-0114-Pandora-research_CVE-2018-0114-Exploit.md) 🔴 ✅

**名称:** CVE-2018-0114-Node-jose-JWT 签名伪造  
**类型:** JWT 签名伪造  
**风险:** 高危，可能导致身份伪造和未授权访问  
**投毒风险:** 0%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2018-0114-Exploit](https://github.com/Pandora-research/CVE-2018-0114-Exploit)  

---

### [CVE-2018-0114](CVE-2018-0114-zi0Black_POC-CVE-2018-0114.md) 🔴 ✅

**名称:** CVE-2018-0114-Node-jose-JWT 签名绕过  
**类型:** JWT 签名绕过  
**风险:** 高危，可能导致身份伪造和权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-04-25  
**POC仓库:** [POC-CVE-2018-0114](https://github.com/zi0Black/POC-CVE-2018-0114)  

---

### [CVE-2018-0114](CVE-2018-0114-amr9k8_jwt-spoof-tool.md) 🔴 ✅

**名称:** CVE-2018-0114-Node-jose-JWT 签名绕过  
**类型:** JWT 签名绕过  
**风险:** 高危，可能导致身份伪造和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-04-25  
**POC仓库:** [jwt-spoof-tool](https://github.com/amr9k8/jwt-spoof-tool)  

---

### [CVE-2018-0114](CVE-2018-0114-sealldeveloper_CVE-2018-0114-PoC.md) 🔴 ✅

**名称:** CVE-2018-0114-Node-jose-JWT 签名伪造  
**类型:** JWT 签名伪造  
**风险:** 高危，可能导致身份验证绕过和权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2018-0114-PoC](https://github.com/sealldeveloper/CVE-2018-0114-PoC)  

---

### [CVE-2025-0927](CVE-2025-0927-mr-spongebob_CVE-2025-0927.md) 🔴 ✅

**名称:** CVE-2025-0927-Linux Kernel HFS+ heap overflow  
**类型:** 堆溢出  
**风险:** 高危，可能导致权限提升和任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2025-0927](https://github.com/mr-spongebob/CVE-2025-0927)  

---

### [CVE-2025-3102](CVE-2025-3102-SUPRAAA-1337_CVE-2025-3102.md) 🔴 ✅

**名称:** CVE-2025-3102-SureTriggers-权限绕过创建管理员账户  
**类型:** 权限绕过  
**风险:** 高危，未经身份验证的攻击者可以创建管理员账户  
**投毒风险:** 10%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2025-3102](https://github.com/SUPRAAA-1337/CVE-2025-3102)  

---

### [CVE-2025-3102](CVE-2025-3102-SUPRAAA-1337_CVE-2025-3102_v2.md) 🔴 ✅

**名称:** CVE-2025-3102 - SureTriggers WordPress 插件未授权管理员创建  
**类型:** 身份验证绕过  
**风险:** 高危，允许未授权用户创建管理员账户，完全控制受影响的WordPress站点  
**投毒风险:** 0%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2025-3102_v2](https://github.com/SUPRAAA-1337/CVE-2025-3102_v2)  

---

### [CVE-2024-24919](CVE-2024-24919-CyprianAtsyor_CVE-2024-24919-Incident-Report.md.md) 🔴 ✅

**名称:** CVE-2024-24919 - Check Point Security Gateway 信息泄露  
**类型:** 信息泄露/路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2024-24919-Incident-Report.md](https://github.com/CyprianAtsyor/CVE-2024-24919-Incident-Report.md)  

---

### [CVE-2025-29927](CVE-2025-29927-EQSTLab_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-Middleware-Bypass  
**类型:** 权限绕过  
**风险:** 高危，可能导致未授权访问  
**投毒风险:** 0%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2025-29927](https://github.com/EQSTLab/CVE-2025-29927)  

---

### [CVE-2023-30861](CVE-2023-30861-fromitive_cve-2023-30861-poc.md) 🔴 ✅

**名称:** CVE-2023-30861-Flask-会话Cookie泄露  
**类型:** 会话Cookie泄露  
**风险:** 高危，可能导致用户会话劫持  
**投毒风险:** 10%  
**发现时间:** 2025-04-25  
**POC仓库:** [cve-2023-30861-poc](https://github.com/fromitive/cve-2023-30861-poc)  

---

### [CVE-2025-29306](CVE-2025-29306-Mattb709_CVE-2025-29306-PoC-FoxCMS-RCE.md) 🔴 ✅

**名称:** CVE-2025-29306-FoxCMS-代码注入  
**类型:** 代码注入  
**风险:** 高危，允许远程攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2025-29306-PoC-FoxCMS-RCE](https://github.com/Mattb709/CVE-2025-29306-PoC-FoxCMS-RCE)  

---

### [CVE-2024-51179](CVE-2024-51179-Lakshmirnr_CVE-2024-51179.md) 🔴 ✅

**名称:** CVE-2024-51179 - Open 5GS NFV Denial of Service  
**类型:** Denial of Service (DoS)  
**风险:** 高危，可能导致网络服务中断  
**投毒风险:** 10%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2024-51179](https://github.com/Lakshmirnr/CVE-2024-51179)  

---

### [CVE-2023-34839](CVE-2023-34839-sahiloj_CVE-2023-34839.md) 🔴 ✅

**名称:** CVE-2023-34839-Issabel-pbx-CSRF  
**类型:** CSRF（跨站请求伪造）  
**风险:** 高危，可导致权限提升，创建恶意用户  
**投毒风险:** 0%  
**发现时间:** 2025-04-25  
**POC仓库:** [CVE-2023-34839](https://github.com/sahiloj/CVE-2023-34839)  

---

### [CVE-2025-32433](CVE-2025-32433-rizky412_CVE-2025-32433.md) 🔴 ✅

**名称:** CVE-2025-32433-Erlang/OTP-SSH预认证RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-24  
**POC仓库:** [CVE-2025-32433](https://github.com/rizky412/CVE-2025-32433)  

---

### [CVE-2025-2301](CVE-2025-2301-sahici_CVE-2025-2301.md) 🔴 

**名称:** CVE-2025-23011  
**类型:** 任意文件上传/JSP文件写入执行  
**风险:** 高危，允许远程攻击者上传恶意JSP文件并执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-04-24  
**POC仓库:** [CVE-2025-2301](https://github.com/sahici/CVE-2025-2301)  

---

### [CVE-2025-2812](CVE-2025-2812-sahici_CVE-2025-2812.md)  ✅

**名称:** CVE-2025-2812  
**类型:** 未知  
**风险:** 未知  
**投毒风险:** 10%  
**发现时间:** 2025-04-24  
**POC仓库:** [CVE-2025-2812](https://github.com/sahici/CVE-2025-2812)  

---

### [CVE-2023-30212](CVE-2023-30212-mallutrojan_CVE-2023-30212-Lab.md) 🟡 ✅

**名称:** CVE-2023-30212-OURPHP-XSS  
**类型:** 反射型跨站脚本 (XSS)  
**风险:** 中危，可能导致用户凭据泄露、会话劫持、恶意脚本执行等  
**投毒风险:** 10%  
**发现时间:** 2025-04-24  
**POC仓库:** [CVE-2023-30212-Lab](https://github.com/mallutrojan/CVE-2023-30212-Lab)  

---

### [CVE-2025-31161](CVE-2025-31161-SUPRAAA-1337_CVE-2025-31161_exploit.md) 🔴 ✅

**名称:** CVE-2025-31161 CrushFTP Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致完全系统接管  
**投毒风险:** 10%  
**发现时间:** 2025-04-24  
**POC仓库:** [CVE-2025-31161_exploit](https://github.com/SUPRAAA-1337/CVE-2025-31161_exploit)  

---

### [CVE-2025-2404](CVE-2025-2404-sahici_CVE-2025-2404.md)  ✅

**名称:** CVE-2025-2404  
**类型:** 未知  
**风险:** 未知  
**投毒风险:** 0%  
**发现时间:** 2025-04-24  
**POC仓库:** [CVE-2025-2404](https://github.com/sahici/CVE-2025-2404)  

---

### [CVE-2021-43857](CVE-2021-43857-LongWayHomie_CVE-2021-43857.md)  ✅

**名称:** CVE-2021-43857-Gerapy-远程代码执行  
**类型:** 远程代码执行  
**风险:** 严重，未经授权的攻击者可以执行任意系统命令。  
**投毒风险:** 0%  
**发现时间:** 2025-04-24  
**POC仓库:** [CVE-2021-43857](https://github.com/LongWayHomie/CVE-2021-43857)  

---

### [CVE-2021-43857](CVE-2021-43857-lowkey0808_CVE-2021-43857.md) 🔴 ✅

**名称:** CVE-2021-43857-Gerapy-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致完全控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-04-24  
**POC仓库:** [CVE-2021-43857](https://github.com/lowkey0808/CVE-2021-43857)  

---

### [CVE-2021-43857](CVE-2021-43857-G4sp4rCS_CVE-2021-43857-POC.md) 🔴 ✅

**名称:** CVE-2021-43857-Gerapy-远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经授权的攻击者在服务器上执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-04-24  
**POC仓库:** [CVE-2021-43857-POC](https://github.com/G4sp4rCS/CVE-2021-43857-POC)  

---

### [CVE-2023-30212](CVE-2023-30212-libasmon_-create-a-vulnerable-Docker-environment-that-is-susceptible-to-CVE-2023-30212.md) 🟡 ✅

**名称:** CVE-2023-30212-OURPHP-XSS  
**类型:** 跨站脚本 (XSS)  
**风险:** 中危，可能导致用户信息泄露和恶意脚本执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-24  
**POC仓库:** [-create-a-vulnerable-Docker-environment-that-is-susceptible-to-CVE-2023-30212](https://github.com/libasmon/-create-a-vulnerable-Docker-environment-that-is-susceptible-to-CVE-2023-30212)  

---

### [CVE-2025-3243](CVE-2025-3243-TeneBrae93_CVE-2025-3243.md) 🟡 ✅

**名称:** CVE-2025-3243  
**类型:** SQL注入  
**风险:** 中危，可能导致数据泄露和篡改  
**投毒风险:** 0%  
**发现时间:** 2025-04-24  
**POC仓库:** [CVE-2025-3243](https://github.com/TeneBrae93/CVE-2025-3243)  

---

### [CVE-2018-15745](CVE-2018-15745-Jasurbek-Masimov_CVE-2018-15745.md) 🔴 ✅

**名称:** CVE-2018-15745 - Argus Surveillance DVR 4.0.0.0 - Directory Traversal  
**类型:** 目录遍历/文件包含  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-24  
**POC仓库:** [CVE-2018-15745](https://github.com/Jasurbek-Masimov/CVE-2018-15745)  

---

### [CVE-2025-44228](CVE-2025-44228-Kramozon_Lnk-Exploit-FileBinder-Certificate-Spoofer-Reg-Doc-Cve-Rce.md) 🔴 ✅

**名称:** CVE-2021-44228 - Apache Log4j Log4Shell RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 60%  
**发现时间:** 2025-04-24  
**POC仓库:** [Lnk-Exploit-FileBinder-Certificate-Spoofer-Reg-Doc-Cve-Rce](https://github.com/Kramozon/Lnk-Exploit-FileBinder-Certificate-Spoofer-Reg-Doc-Cve-Rce)  

---

### [CVE-2025-44228](CVE-2025-44228-Kramozon_Office-Exploit-Cve2025-Xml-Doc-Docx-Rce-Builder-Fud.md) 🔴 ✅

**名称:** CVE-2021-44228 - Apache Log4j2 Log4Shell RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 75%  
**发现时间:** 2025-04-24  
**POC仓库:** [Office-Exploit-Cve2025-Xml-Doc-Docx-Rce-Builder-Fud](https://github.com/Kramozon/Office-Exploit-Cve2025-Xml-Doc-Docx-Rce-Builder-Fud)  

---

### [CVE-2023-30212](CVE-2023-30212-MaThEw-ViNcEnT_CVE-2023-30212-OURPHP-Vulnerability.md) 🟡 ✅

**名称:** CVE-2023-30212-OURPHP-XSS  
**类型:** 跨站脚本 (XSS)  
**风险:** 中危，可能导致用户凭据泄露或恶意脚本执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-24  
**POC仓库:** [CVE-2023-30212-OURPHP-Vulnerability](https://github.com/MaThEw-ViNcEnT/CVE-2023-30212-OURPHP-Vulnerability)  

---

### [CVE-2023-30212](CVE-2023-30212-AAsh035_CVE-2023-30212.md) 🟡 ✅

**名称:** CVE-2023-30212-OURPHP-反射型XSS  
**类型:** 反射型跨站脚本(XSS)  
**风险:** 中危，可能导致用户凭据泄露、会话劫持等  
**投毒风险:** 10%  
**发现时间:** 2025-04-24  
**POC仓库:** [CVE-2023-30212](https://github.com/AAsh035/CVE-2023-30212)  

---

### [CVE-2025-21497](CVE-2025-21497-Urbank-61_cve-2025-21497-lab.md) 🟡 

**名称:** CVE-2025-21497-MySQL Server-InnoDB-Origin Validation Error  
**类型:** Origin Validation Error  
**风险:** 中危，可能导致拒绝服务以及修改数据库信息  
**投毒风险:** 5%  
**发现时间:** 2025-04-24  
**POC仓库:** [cve-2025-21497-lab](https://github.com/Urbank-61/cve-2025-21497-lab)  

---

### [CVE-2023-30212](CVE-2023-30212-Rishipatidar_CVE-2023-30212-POC-DOCKER-FILE.md) 🟡 ✅

**名称:** CVE-2023-30212-OURPHP-XSS  
**类型:** 反射型跨站脚本 (XSS)  
**风险:** 中危，可能导致用户cookie窃取、页面重定向等  
**投毒风险:** 1%  
**发现时间:** 2025-04-24  
**POC仓库:** [CVE-2023-30212-POC-DOCKER-FILE](https://github.com/Rishipatidar/CVE-2023-30212-POC-DOCKER-FILE)  

---

### [CVE-2023-30212](CVE-2023-30212-kuttappu123_CVE-2023-30212-LAB.md) 🟡 ✅

**名称:** CVE-2023-30212-OURPHP-XSS  
**类型:** XSS  
**风险:** 中危，可能导致用户cookie泄露和网页内容篡改  
**投毒风险:** 10%  
**发现时间:** 2025-04-24  
**POC仓库:** [CVE-2023-30212-LAB](https://github.com/kuttappu123/CVE-2023-30212-LAB)  

---

### [CVE-2023-30212](CVE-2023-30212-Anandhu990_r-CVE-2023-30212--lab.md) 🟡 ✅

**名称:** CVE-2023-30212-OURPHP-XSS  
**类型:** 跨站脚本 (XSS)  
**风险:** 中危，可能导致用户信息泄露和恶意脚本执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-24  
**POC仓库:** [r-CVE-2023-30212--lab](https://github.com/Anandhu990/r-CVE-2023-30212--lab)  

---

### [CVE-2023-30212](CVE-2023-30212-Anandhu990_CVE-2023-30212-iab.md) 🟡 ✅

**名称:** CVE-2023-30212-OURPHP-XSS  
**类型:** XSS  
**风险:** 中危，可能导致用户凭据泄露、网页内容篡改和恶意脚本执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-24  
**POC仓库:** [CVE-2023-30212-iab](https://github.com/Anandhu990/CVE-2023-30212-iab)  

---

### [CVE-2023-30212](CVE-2023-30212-Anandhu990_CVE-2023-30212_lab.md) 🟡 ✅

**名称:** CVE-2023-30212-OURPHP-XSS  
**类型:** 跨站脚本 (XSS)  
**风险:** 中危，可能导致用户会话劫持、恶意脚本执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-24  
**POC仓库:** [CVE-2023-30212_lab](https://github.com/Anandhu990/CVE-2023-30212_lab)  

---

### [CVE-2023-30212](CVE-2023-30212-libas7994_CVE-2023-30212.md) 🟡 ✅

**名称:** CVE-2023-30212-OURPHP-XSS  
**类型:** XSS（跨站脚本）  
**风险:** 中危，可能导致用户会话劫持、网页篡改、恶意脚本执行  
**投毒风险:** 20%  
**发现时间:** 2025-04-24  
**POC仓库:** [CVE-2023-30212](https://github.com/libas7994/CVE-2023-30212)  

---

### [CVE-2023-30212](CVE-2023-30212-libasmon_Exploite-CVE-2023-30212-Vulnerability.md) 🟡 ✅

**名称:** CVE-2023-30212-OURPHP-XSS  
**类型:** 跨站脚本攻击 (XSS)  
**风险:** 中危，可能导致用户信息泄露、会话劫持等  
**投毒风险:** 10%  
**发现时间:** 2025-04-24  
**POC仓库:** [Exploite-CVE-2023-30212-Vulnerability](https://github.com/libasmon/Exploite-CVE-2023-30212-Vulnerability)  

---

### [CVE-2023-30212](CVE-2023-30212-libasv_Exploite-CVE-2023-30212-vulnerability.md) 🟡 ✅

**名称:** CVE-2023-30212 - OURPHP v7.2.0 反射型XSS  
**类型:** 反射型跨站脚本 (XSS)  
**风险:** 中危，可能导致会话劫持、网页挂马、钓鱼攻击等  
**投毒风险:** 10%  
**发现时间:** 2025-04-24  
**POC仓库:** [Exploite-CVE-2023-30212-vulnerability](https://github.com/libasv/Exploite-CVE-2023-30212-vulnerability)  

---

### [CVE-2023-30212](CVE-2023-30212-kai-iszz_CVE-2023-30212.md) 🟡 ✅

**名称:** CVE-2023-30212 - OURPHP <= 7.2.0 反射型XSS  
**类型:** 反射型跨站脚本 (XSS)  
**风险:** 中危，可能导致用户信息泄露、会话劫持等  
**投毒风险:** 10%  
**发现时间:** 2025-04-24  
**POC仓库:** [CVE-2023-30212](https://github.com/kai-iszz/CVE-2023-30212)  

---

### [CVE-2023-30212](CVE-2023-30212-JasaluRah_Creating-a-Vulnerable-Docker-Environment-CVE-2023-30212-.md) 🟡 ✅

**名称:** CVE-2023-30212-OURPHP-反射型XSS  
**类型:** 反射型XSS  
**风险:** 中危，可能导致cookie窃取、页面重定向等  
**投毒风险:** 10%  
**发现时间:** 2025-04-24  
**POC仓库:** [Creating-a-Vulnerable-Docker-Environment-CVE-2023-30212-](https://github.com/JasaluRah/Creating-a-Vulnerable-Docker-Environment-CVE-2023-30212-)  

---

### [CVE-2023-30212](CVE-2023-30212-arunsnap_CVE-2023-30212-POC.md) 🟡 ✅

**名称:** CVE-2023-30212-OURPHP-XSS  
**类型:** 跨站脚本漏洞 (XSS)  
**风险:** 中危，可能导致用户凭据泄露、页面重定向、恶意软件传播等  
**投毒风险:** 10%  
**发现时间:** 2025-04-24  
**POC仓库:** [CVE-2023-30212-POC](https://github.com/arunsnap/CVE-2023-30212-POC)  

---

### [CVE-2023-30212](CVE-2023-30212-VisDev23_Vulnerable-Docker--CVE-2023-30212-.md) 🟡 ✅

**名称:** CVE-2023-30212-OURPHP-XSS  
**类型:** 反射型跨站脚本攻击 (XSS)  
**风险:** 中危，可能导致用户信息泄露、页面篡改等  
**投毒风险:** 10%  
**发现时间:** 2025-04-24  
**POC仓库:** [Vulnerable-Docker--CVE-2023-30212-](https://github.com/VisDev23/Vulnerable-Docker--CVE-2023-30212-)  

---

### [CVE-2023-30212](CVE-2023-30212-sungmin20_cve-2023-30212.md) 🟡 ✅

**名称:** CVE-2023-30212-OURPHP-XSS  
**类型:** XSS  
**风险:** 中危，可能导致Cookie窃取、页面重定向等  
**投毒风险:** 10%  
**发现时间:** 2025-04-24  
**POC仓库:** [cve-2023-30212](https://github.com/sungmin20/cve-2023-30212)  

---

### [CVE-2025-34028](CVE-2025-34028-tinkerlev_commvault-cve2025-34028-check.md) 🔴 ✅

**名称:** CVE-2025-34028-Commvault-路径遍历导致RCE  
**类型:** 路径遍历/远程代码执行  
**风险:** 高危，未授权远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-24  
**POC仓库:** [commvault-cve2025-34028-check](https://github.com/tinkerlev/commvault-cve2025-34028-check)  

---

### [CVE-2024-12905](CVE-2024-12905-theMcSam_CVE-2024-12905-PoC.md) 🔴 ✅

**名称:** CVE-2024-12905-tar-fs-文件写入/覆盖  
**类型:** 路径遍历/符号链接攻击  
**风险:** 高危，可导致任意文件写入/覆盖，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-24  
**POC仓库:** [CVE-2024-12905-PoC](https://github.com/theMcSam/CVE-2024-12905-PoC)  

---

### [CVE-2025-12654](CVE-2025-12654-ThreeMens_Anydesk-Exploit-CVE-2025-12654-RCE-Builder.md) 🔴 ✅

**名称:** AnyDesk Exploit - RCE, DLL Injection, Authentication Bypass  
**类型:** 远程代码执行 (RCE), DLL注入, 身份验证绕过  
**风险:** 高危，可能导致远程代码执行，敏感信息泄露，系统控制  
**投毒风险:** 60%  
**发现时间:** 2025-04-24  
**POC仓库:** [Anydesk-Exploit-CVE-2025-12654-RCE-Builder](https://github.com/ThreeMens/Anydesk-Exploit-CVE-2025-12654-RCE-Builder)  

---

### [CVE-2024-42471](CVE-2024-42471-theMcSam_CVE-2024-42471-PoC.md) 🔴 ✅

**名称:** CVE-2024-42471-actions/artifact-任意文件写入  
**类型:** 任意文件写入/路径遍历  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-24  
**POC仓库:** [CVE-2024-42471-PoC](https://github.com/theMcSam/CVE-2024-42471-PoC)  

---

### [CVE-2024-7120](CVE-2024-7120-gh-ost00_CVE-2024-7120.md) 🟡 ✅

**名称:** CVE-2024-7120 - Raisecom MSG1200/MSG2100E/MSG2200/MSG2300 Web Interface OS Command Injection  
**类型:** OS Command Injection  
**风险:** 中危，可能导致信息泄露和有限的系统控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-24  
**POC仓库:** [CVE-2024-7120](https://github.com/gh-ost00/CVE-2024-7120)  

---

### [CVE-2024-7120](CVE-2024-7120-jokeir07x_CVE-2024-7120-Exploit-by-Dark-07x.md) 🔴 ✅

**名称:** CVE-2024-7120-Raisecom设备-OS命令注入  
**类型:** OS命令注入  
**风险:** 高危，可远程执行任意命令  
**投毒风险:** 1%  
**发现时间:** 2025-04-24  
**POC仓库:** [CVE-2024-7120-Exploit-by-Dark-07x](https://github.com/jokeir07x/CVE-2024-7120-Exploit-by-Dark-07x)  

---

### [CVE-2025-32433](CVE-2025-32433-ps-interactive_lab_CVE-2025-32433.md) 🔴 ✅

**名称:** CVE-2025-32433-Erlang/OTP-SSH远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-24  
**POC仓库:** [lab_CVE-2025-32433](https://github.com/ps-interactive/lab_CVE-2025-32433)  

---

### [CVE-2021-41773](CVE-2021-41773-JIYUN02_cve-2021-41773.md) 🔴 ✅

**名称:** CVE-2021-41773-Apache HTTP Server-路径遍历/RCE  
**类型:** 路径遍历/远程代码执行  
**风险:** 高危，可能导致文件泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-24  
**POC仓库:** [cve-2021-41773](https://github.com/JIYUN02/cve-2021-41773)  

---

### [CVE-2025-32965](CVE-2025-32965-yusufdalbudak_CVE-2025-32965-xrpl-js-poc.md)  ✅

**名称:** CVE-2025-32965 - xrpl.js Supply Chain Attack  
**类型:** 供应链攻击  
**风险:** 极危，可导致加密货币资金完全失控  
**投毒风险:** 5%  
**发现时间:** 2025-04-24  
**POC仓库:** [CVE-2025-32965-xrpl-js-poc](https://github.com/yusufdalbudak/CVE-2025-32965-xrpl-js-poc)  

---

### [CVE-2025-31161](CVE-2025-31161-SUPRAAA-1337_Nuclei_CVE-2025-31161_CVE-2025-2825.md) 🔴 ✅

**名称:** CVE-2025-31161 - CrushFTP Authentication Bypass  
**类型:** Authentication Bypass  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-24  
**POC仓库:** [Nuclei_CVE-2025-31161_CVE-2025-2825](https://github.com/SUPRAAA-1337/Nuclei_CVE-2025-31161_CVE-2025-2825)  

---

### [CVE-2025-30208](CVE-2025-30208-r0ngy40_CVE-2025-30208-Series.md) 🟡 ✅

**名称:** CVE-2025-30208-Vite-任意文件读取  
**类型:** 任意文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-24  
**POC仓库:** [CVE-2025-30208-Series](https://github.com/r0ngy40/CVE-2025-30208-Series)  

---

### [CVE-2025-34028](CVE-2025-34028-watchtowrlabs_watchTowr-vs-Commvault-PreAuth-RCE-CVE-2025-34028.md) 🔴 ✅

**名称:** CVE-2025-34028 - Commvault Command Center Innovation Release Unauthenticated Path Traversal  
**类型:** 路径遍历导致的远程代码执行  
**风险:** 高危，未授权远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-24  
**POC仓库:** [watchTowr-vs-Commvault-PreAuth-RCE-CVE-2025-34028](https://github.com/watchtowrlabs/watchTowr-vs-Commvault-PreAuth-RCE-CVE-2025-34028)  

---

### [CVE-2023-25157](CVE-2023-25157-charis3306_CVE-2023-25157.md) 🔴 ✅

**名称:** CVE-2023-25157-GeoServer-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致敏感信息泄露、数据篡改、甚至服务器权限获取  
**投毒风险:** 10%  
**发现时间:** 2025-04-24  
**POC仓库:** [CVE-2023-25157](https://github.com/charis3306/CVE-2023-25157)  

---

### [CVE-2025-30406](CVE-2025-30406-W01fh4cker_CVE-2025-30406.md) 🔴 ✅

**名称:** CVE-2025-30406-Gladinet CentreStack-反序列化RCE  
**类型:** 反序列化导致远程代码执行  
**风险:** 高危，可能导致远程代码执行，完全控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-04-24  
**POC仓库:** [CVE-2025-30406](https://github.com/W01fh4cker/CVE-2025-30406)  

---

### [CVE-2025-31161](CVE-2025-31161-SUPRAAA-1337_CVE-2025-31161.md) 🔴 ✅

**名称:** CVE-2025-31161-CrushFTP认证绕过漏洞  
**类型:** 认证绕过  
**风险:** 高危，可完全控制系统  
**投毒风险:** 0%  
**发现时间:** 2025-04-24  
**POC仓库:** [CVE-2025-31161](https://github.com/SUPRAAA-1337/CVE-2025-31161)  

---

### [CVE-2025-3776](CVE-2025-3776-Nxploited_CVE-2025-3776.md) 🔴 ✅

**名称:** CVE-2025-3776 - WordPress TargetSMS插件远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经授权的用户执行任意命令  
**投毒风险:** 10%  
**发现时间:** 2025-04-24  
**POC仓库:** [CVE-2025-3776](https://github.com/Nxploited/CVE-2025-3776)  

---

### [CVE-2024-27876](CVE-2024-27876-0xilis_CVE-2024-27876.md) 🔴 ✅

**名称:** CVE-2024-27876  
**类型:** 竞争条件导致任意文件写入  
**风险:** 高危，可能导致任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-23  
**POC仓库:** [CVE-2024-27876](https://github.com/0xilis/CVE-2024-27876)  

---

### [CVE-2025-32433](CVE-2025-32433-tobiasGuta_Erlang-OTP-CVE-2025-32433.md) 🔴 ✅

**名称:** CVE-2025-32433-Erlang/OTP SSH-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-23  
**POC仓库:** [Erlang-OTP-CVE-2025-32433](https://github.com/tobiasGuta/Erlang-OTP-CVE-2025-32433)  

---

### [CVE-2024-49138](CVE-2024-49138-CyprianAtsyor_letsdefend-cve-2024-49138-investigation.md) 🔴 ✅

**名称:** CVE-2024-49138 Windows CLFS 驱动程序提权漏洞  
**类型:** 特权提升  
**风险:** 高危，可导致系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-23  
**POC仓库:** [letsdefend-cve-2024-49138-investigation](https://github.com/CyprianAtsyor/letsdefend-cve-2024-49138-investigation)  

---

### [CVE-2025-31137](CVE-2025-31137-pouriam23_vulnerability-in-Remix-React-Router-CVE-2025-31137-.md) 🔴 ✅

**名称:** CVE-2025-31137-RemixReactRouter-URL欺骗  
**类型:** URL欺骗  
**风险:** 高危，可能导致缓存投毒、WAF绕过，甚至权限提升。  
**投毒风险:** 0%  
**发现时间:** 2025-04-23  
**POC仓库:** [vulnerability-in-Remix-React-Router-CVE-2025-31137-](https://github.com/pouriam23/vulnerability-in-Remix-React-Router-CVE-2025-31137-)  

---

### [CVE-2025-29927](CVE-2025-29927-kh4sh3i_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问敏感数据和执行未授权操作  
**投毒风险:** 0%  
**发现时间:** 2025-04-23  
**POC仓库:** [CVE-2025-29927](https://github.com/kh4sh3i/CVE-2025-29927)  

---

### [CVE-2025-24963](CVE-2025-24963-0xdeviner_CVE-2025-24963.md) 🟡 ✅

**名称:** CVE-2025-24963 - Vitest Browser Mode - Local File Read  
**类型:** 目录遍历 (Path Traversal)  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-04-23  
**POC仓库:** [CVE-2025-24963](https://github.com/0xdeviner/CVE-2025-24963)  

---

### [CVE-2018-12533](CVE-2018-12533-Pastea_CVE-2018-12533.md) 🔴 ✅

**名称:** CVE-2018-12533-JBoss RichFaces-EL表达式注入  
**类型:** EL表达式注入  
**风险:** 高危，允许未授权远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-22  
**POC仓库:** [CVE-2018-12533](https://github.com/Pastea/CVE-2018-12533)  

---

### [CVE-2018-12533](CVE-2018-12533-llamaonsecurity_CVE-2018-12533.md) 🔴 ✅

**名称:** CVE-2018-12533-RichFaces-EL表达式注入  
**类型:** EL表达式注入  
**风险:** 高危，可远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-22  
**POC仓库:** [CVE-2018-12533](https://github.com/llamaonsecurity/CVE-2018-12533)  

---

### [CVE-2018-12533](CVE-2018-12533-mhagnumdw_richfaces-vulnerability-cve-2018-12533-rf-14310.md) 🔴 ✅

**名称:** CVE-2018-12533-JBoss RichFaces-EL表达式注入  
**类型:** EL表达式注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-22  
**POC仓库:** [richfaces-vulnerability-cve-2018-12533-rf-14310](https://github.com/mhagnumdw/richfaces-vulnerability-cve-2018-12533-rf-14310)  

---

### [CVE-2025-29529](CVE-2025-29529-Yoshik0xF6_CVE-2025-29529.md) 🔴 ✅

**名称:** CVE-2025-29529-ITC Multiplan-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-04-22  
**POC仓库:** [CVE-2025-29529](https://github.com/Yoshik0xF6/CVE-2025-29529)  

---

### [CVE-2023-44487](CVE-2023-44487-zanks08_cve-2023-44487-demo.md) 🔴 ✅

**名称:** CVE-2023-44487 HTTP/2 Rapid Reset Attack  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，导致服务器资源耗尽，服务不可用  
**投毒风险:** 5%  
**发现时间:** 2025-04-22  
**POC仓库:** [cve-2023-44487-demo](https://github.com/zanks08/cve-2023-44487-demo)  

---

### [CVE-2024-38828](CVE-2024-38828-funcid_CVE-2024-38828.md) 🟡 ✅

**名称:** CVE-2024-38828 - Spring MVC DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 中危，可能导致服务中断  
**投毒风险:** 5%  
**发现时间:** 2025-04-22  
**POC仓库:** [CVE-2024-38828](https://github.com/funcid/CVE-2024-38828)  

---

### [CVE-2023-44487](CVE-2023-44487-zanks08_cve-2023-44487-demo.md) 🔴 ✅

**名称:** CVE-2023-44487 HTTP/2 快速重置攻击  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致服务器资源耗尽，服务不可用  
**投毒风险:** 10%  
**发现时间:** 2025-04-22  
**POC仓库:** [cve-2023-44487-demo](https://github.com/zanks08/cve-2023-44487-demo)  

---

### [CVE-2025-42599](CVE-2025-42599-bronsoneaver_CVE-2025-42599.md) 🔴 ✅

**名称:** CVE-2025-42599 - Active! mail 6 Stack-based Buffer Overflow  
**类型:** 栈溢出  
**风险:** 高危，可能导致任意代码执行和拒绝服务  
**投毒风险:** 99%  
**发现时间:** 2025-04-22  
**POC仓库:** [CVE-2025-42599](https://github.com/bronsoneaver/CVE-2025-42599)  

---

### [CVE-2025-32140](CVE-2025-32140-Nxploited_CVE-2025-32140.md) 🔴 ✅

**名称:** CVE-2025-32140-WP Remote Thumbnail-Arbitrary File Upload  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-22  
**POC仓库:** [CVE-2025-32140](https://github.com/Nxploited/CVE-2025-32140)  

---

### [CVE-2024-38828](CVE-2024-38828-First-Roman_sprig-mvc-demo-patch.md) 🟡 ✅

**名称:** CVE-2024-38828 - Spring MVC @RequestBody byte[] DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 中危，可能导致服务不可用  
**投毒风险:** 10%  
**发现时间:** 2025-04-22  
**POC仓库:** [sprig-mvc-demo-patch](https://github.com/First-Roman/sprig-mvc-demo-patch)  

---

### [CVE-2024-38828](CVE-2024-38828-funcid_CVE-2024-38828.md) 🟡 ✅

**名称:** CVE-2024-38828: Spring Framework DoS Vulnerability  
**类型:** DoS (Denial of Service)  
**风险:** 中危，可能导致服务中断  
**投毒风险:** 10%  
**发现时间:** 2025-04-22  
**POC仓库:** [CVE-2024-38828](https://github.com/funcid/CVE-2024-38828)  

---

### [CVE-2025-26159](CVE-2025-26159-godBADTRY_CVE-2025-26159.md) 🟡 ✅

**名称:** CVE-2025-26159  
**类型:** 跨站脚本攻击 (XSS)  
**风险:** 中危，可能导致会话劫持、信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-22  
**POC仓库:** [CVE-2025-26159](https://github.com/godBADTRY/CVE-2025-26159)  

---

### [CVE-2025-24054](CVE-2025-24054-helidem_CVE-2025-24054-PoC.md) 🟡 ✅

**名称:** CVE-2025-24054 - NTLM Hash Disclosure Spoofing Vulnerability  
**类型:** NTLM Hash Disclosure  
**风险:** 中危，可能导致凭据泄露和权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-04-22  
**POC仓库:** [CVE-2025-24054-PoC](https://github.com/helidem/CVE-2025-24054-PoC)  

---

### [CVE-2025-29306](CVE-2025-29306-inok009_FOXCMS-CVE-2025-29306-POC.md) 🔴 ✅

**名称:** CVE-2025-29306-FoxCMS-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程攻击者执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-04-22  
**POC仓库:** [FOXCMS-CVE-2025-29306-POC](https://github.com/inok009/FOXCMS-CVE-2025-29306-POC)  

---

### [CVE-2021-44910](CVE-2021-44910-W000i_CVE-2021-44910_SpringBlade.md) 🟡 ✅

**名称:** CVE-2021-44910-SpringBlade信息泄露  
**类型:** 信息泄露  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-22  
**POC仓库:** [CVE-2021-44910_SpringBlade](https://github.com/W000i/CVE-2021-44910_SpringBlade)  

---

### [CVE-2025-43919](CVE-2025-43919-cybersecplayground_CVE-2025-43919-POC.md) 🟡 ✅

**名称:** CVE-2025-43919-GNU Mailman-目录遍历  
**类型:** 目录遍历  
**风险:** 中危，可读取任意文件  
**投毒风险:** 1%  
**发现时间:** 2025-04-22  
**POC仓库:** [CVE-2025-43919-POC](https://github.com/cybersecplayground/CVE-2025-43919-POC)  

---

### [CVE-2025-31161](CVE-2025-31161-TX-One_CVE-2025-31161.md) 🔴 ✅

**名称:** CVE-2025-31161-CrushFTP-认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致完全控制系统  
**投毒风险:** 1%  
**发现时间:** 2025-04-22  
**POC仓库:** [CVE-2025-31161](https://github.com/TX-One/CVE-2025-31161)  

---

### [CVE-2025-29711](CVE-2025-29711-SteamPunk424_CVE-2025-29711-TAKASHI-Wireless-Instant-Router-And-Repeater-WebApp-Incorrect-Access-Control.md) 🔴 ✅

**名称:** CVE-2025-29711 - TAKASHI Wireless Instant Router and Repeater - Incorrect Access Control  
**类型:** 权限绕过/身份验证绕过  
**风险:** 高危，可能导致未授权访问、配置更改和网络破坏  
**投毒风险:** 0%  
**发现时间:** 2025-04-21  
**POC仓库:** [CVE-2025-29711-TAKASHI-Wireless-Instant-Router-And-Repeater-WebApp-Incorrect-Access-Control](https://github.com/SteamPunk424/CVE-2025-29711-TAKASHI-Wireless-Instant-Router-And-Repeater-WebApp-Incorrect-Access-Control)  

---

### [CVE-2025-29712](CVE-2025-29712-SteamPunk424_CVE-2025-29712-TAKASHI-Wireless-Instant-Router-And-Repeater-WebApp-Authenticated-Stored-XSS.md) 🟡 ✅

**名称:** CVE-2025-29712 TAKASHI Wireless Instant Router and Repeater - XSS Vulnerability  
**类型:** 存储型跨站脚本 (XSS)  
**风险:** 中危，可能导致会话劫持、网络钓鱼或其他恶意行为  
**投毒风险:** 5%  
**发现时间:** 2025-04-21  
**POC仓库:** [CVE-2025-29712-TAKASHI-Wireless-Instant-Router-And-Repeater-WebApp-Authenticated-Stored-XSS](https://github.com/SteamPunk424/CVE-2025-29712-TAKASHI-Wireless-Instant-Router-And-Repeater-WebApp-Authenticated-Stored-XSS)  

---

### [CVE-2021-34371](CVE-2021-34371-zwjjustdoit_CVE-2021-34371.jar.md) 🔴 ✅

**名称:** CVE-2021-34371-Neo4j-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-21  
**POC仓库:** [CVE-2021-34371.jar](https://github.com/zwjjustdoit/CVE-2021-34371.jar)  

---

### [CVE-2021-34371](CVE-2021-34371-tavgar_CVE-2021-34371.md) 🔴 ✅

**名称:** CVE-2021-34371-Neo4j-RMI反序列化远程代码执行  
**类型:** RMI反序列化漏洞  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-21  
**POC仓库:** [CVE-2021-34371](https://github.com/tavgar/CVE-2021-34371)  

---

### [CVE-2024-28987](CVE-2024-28987-gh-ost00_CVE-2024-28987-POC.md) 🔴 ✅

**名称:** CVE-2024-28987-SolarWinds Web Help Desk-硬编码凭据  
**类型:** 硬编码凭据  
**风险:** 高危，允许远程未授权用户访问内部功能并修改数据  
**投毒风险:** 10%  
**发现时间:** 2025-04-21  
**POC仓库:** [CVE-2024-28987-POC](https://github.com/gh-ost00/CVE-2024-28987-POC)  

---

### [CVE-2024-28987](CVE-2024-28987-horizon3ai_CVE-2024-28987.md) 🔴 ✅

**名称:** CVE-2024-28987-SolarWinds Web Help Desk-硬编码凭据  
**类型:** 硬编码凭据  
**风险:** 高危，允许未经身份验证的远程用户访问内部功能并修改数据，可能导致敏感信息泄露和系统被控制。  
**投毒风险:** 0%  
**发现时间:** 2025-04-21  
**POC仓库:** [CVE-2024-28987](https://github.com/horizon3ai/CVE-2024-28987)  

---

### [CVE-2024-28987](CVE-2024-28987-expl0itsecurity_CVE-2024-28987.md) 🔴 ✅

**名称:** CVE-2024-28987-SolarWinds Web Help Desk-硬编码凭据  
**类型:** 硬编码凭据  
**风险:** 高危，可能导致未授权访问、数据泄露和修改  
**投毒风险:** 80%  
**发现时间:** 2025-04-21  
**POC仓库:** [CVE-2024-28987](https://github.com/expl0itsecurity/CVE-2024-28987)  

---

### [CVE-2024-28987](CVE-2024-28987-alecclyde_CVE-2024-28987.md) 🔴 ✅

**名称:** CVE-2024-28987-SolarWinds Web Help Desk-硬编码凭据  
**类型:** 硬编码凭据  
**风险:** 高危，允许未经验证的远程用户访问内部功能和修改数据  
**投毒风险:** 1%  
**发现时间:** 2025-04-21  
**POC仓库:** [CVE-2024-28987](https://github.com/alecclyde/CVE-2024-28987)  

---

### [CVE-2025-24016](CVE-2025-24016-cybersecplayground_CVE-2025-24016-Wazuh-Remote-Code-Execution-RCE-PoC.md) 🔴 ✅

**名称:** CVE-2025-24016-Wazuh-RCE  
**类型:** 反序列化漏洞导致远程代码执行  
**风险:** 高危，可能导致完全系统权限控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-21  
**POC仓库:** [CVE-2025-24016-Wazuh-Remote-Code-Execution-RCE-PoC](https://github.com/cybersecplayground/CVE-2025-24016-Wazuh-Remote-Code-Execution-RCE-PoC)  

---

### [CVE-2025-24071](CVE-2025-24071-pswalia2u_CVE-2025-24071_POC.md) 🔴 ✅

**名称:** CVE-2025-24071-Windows File Explorer Spoofing Vulnerability  
**类型:** 信息泄露/欺骗  
**风险:** 高危，可能导致NTLM凭据泄露和远程文件访问  
**投毒风险:** 0%  
**发现时间:** 2025-04-21  
**POC仓库:** [CVE-2025-24071_POC](https://github.com/pswalia2u/CVE-2025-24071_POC)  

---

### [CVE-2025-30065](CVE-2025-30065-ThreatRadarAI_TRA-001-Critical-RCE-Vulnerability-in-Apache-Parquet-CVE-2025-30065-Simulation-.md) 🔴 ✅

**名称:** CVE-2025-30065-Apache Parquet-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和完全系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-21  
**POC仓库:** [TRA-001-Critical-RCE-Vulnerability-in-Apache-Parquet-CVE-2025-30065-Simulation-](https://github.com/ThreatRadarAI/TRA-001-Critical-RCE-Vulnerability-in-Apache-Parquet-CVE-2025-30065-Simulation-)  

---

### [CVE-2024-37606](CVE-2024-37606-itwizardo_DCS932L-Emulation-CVE-2024-37606-Attack.md) 🟡 ✅

**名称:** CVE-2024-37606-D-Link DCS-932L-栈溢出  
**类型:** 栈溢出  
**风险:** 中危，可能导致拒绝服务  
**投毒风险:** 1%  
**发现时间:** 2025-04-21  
**POC仓库:** [DCS932L-Emulation-CVE-2024-37606-Attack](https://github.com/itwizardo/DCS932L-Emulation-CVE-2024-37606-Attack)  

---

### [CVE-2024-40445](CVE-2024-40445-TaiYou-TW_CVE-2024-40445_CVE-2024-40446.md) 🔴 ✅

**名称:** CVE-2024-40445 & CVE-2024-40446 - MimeTeX远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和服务器控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-21  
**POC仓库:** [CVE-2024-40445_CVE-2024-40446](https://github.com/TaiYou-TW/CVE-2024-40445_CVE-2024-40446)  

---

### [CVE-2024-43768](CVE-2024-43768-Mahesh-970_CVE-2024-43768.md) 🔴 ✅

**名称:** CVE-2024-43768-Android-Skia-OOB-Write  
**类型:** 越界写  
**风险:** 高危，本地提权  
**投毒风险:** 0%  
**发现时间:** 2025-04-21  
**POC仓库:** [CVE-2024-43768](https://github.com/Mahesh-970/CVE-2024-43768)  

---

### [CVE-2025-29927](CVE-2025-29927-pouriam23_Next.js-Middleware-Bypass-CVE-2025-29927-.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-中间件认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未授权访问  
**投毒风险:** 10%  
**发现时间:** 2025-04-21  
**POC仓库:** [Next.js-Middleware-Bypass-CVE-2025-29927-](https://github.com/pouriam23/Next.js-Middleware-Bypass-CVE-2025-29927-)  

---

### [CVE-2023-25157](CVE-2023-25157-0x2458bughunt_CVE-2023-25157.md) 🔴 ✅

**名称:** CVE-2023-25157-GeoServer-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-21  
**POC仓库:** [CVE-2023-25157](https://github.com/0x2458bughunt/CVE-2023-25157)  

---

### [CVE-2023-25157](CVE-2023-25157-murataydemir_CVE-2023-25157-and-CVE-2023-25158.md) 🔴 ✅

**名称:** CVE-2023-25157-GeoServer-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致未授权信息泄露、数据篡改和服务中断  
**投毒风险:** 10%  
**发现时间:** 2025-04-21  
**POC仓库:** [CVE-2023-25157-and-CVE-2023-25158](https://github.com/murataydemir/CVE-2023-25157-and-CVE-2023-25158)  

---

### [CVE-2023-25157](CVE-2023-25157-win3zz_CVE-2023-25157.md) 🔴 ✅

**名称:** CVE-2023-25157-GeoServer-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-21  
**POC仓库:** [CVE-2023-25157](https://github.com/win3zz/CVE-2023-25157)  

---

### [CVE-2023-25157](CVE-2023-25157-Rubikcuv5_CVE-2023-25157.md) 🔴 ✅

**名称:** CVE-2023-25157-GeoServer-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-21  
**POC仓库:** [CVE-2023-25157](https://github.com/Rubikcuv5/CVE-2023-25157)  

---

### [CVE-2023-25157](CVE-2023-25157-dr-cable-tv_Geoserver-CVE-2023-25157.md) 🔴 ✅

**名称:** CVE-2023-25157-GeoServer-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-21  
**POC仓库:** [Geoserver-CVE-2023-25157](https://github.com/dr-cable-tv/Geoserver-CVE-2023-25157)  

---

### [CVE-2023-25157](CVE-2023-25157-7imbitz_CVE-2023-25157-checker.md)  ✅

**名称:** CVE-2023-25157-GeoServer-SQL注入  
**类型:** SQL注入  
**风险:** 严重，可导致数据泄露、篡改、拒绝服务，甚至远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-21  
**POC仓库:** [CVE-2023-25157-checker](https://github.com/7imbitz/CVE-2023-25157-checker)  

---

### [CVE-2023-25157](CVE-2023-25157-custiya_geoserver-CVE-2023-25157.md) 🔴 ✅

**名称:** CVE-2023-25157-GeoServer-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-21  
**POC仓库:** [geoserver-CVE-2023-25157](https://github.com/custiya/geoserver-CVE-2023-25157)  

---

### [CVE-2025-29927](CVE-2025-29927-pouriam23_Next.js-Middleware-Bypass-CVE-2025-29927-.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js Middleware 认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-21  
**POC仓库:** [Next.js-Middleware-Bypass-CVE-2025-29927-](https://github.com/pouriam23/Next.js-Middleware-Bypass-CVE-2025-29927-)  

---

### [CVE-2025-29927](CVE-2025-29927-pouriam23_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js Middleware Bypass  
**类型:** 权限绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-21  
**POC仓库:** [CVE-2025-29927](https://github.com/pouriam23/CVE-2025-29927)  

---

### [CVE-2024-39943](CVE-2024-39943-JenmrR_Node.js-CVE-2024-39943.md) 🔴 ✅

**名称:** CVE-2024-39943 - rejetto HFS RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可完全控制服务器  
**投毒风险:** 1%  
**发现时间:** 2025-04-21  
**POC仓库:** [Node.js-CVE-2024-39943](https://github.com/JenmrR/Node.js-CVE-2024-39943)  

---

### [CVE-2024-38063](CVE-2024-38063-diegoalbuquerque_CVE-2024-38063.md) 🔴 ✅

**名称:** CVE-2024-38063 Windows TCP/IP 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-21  
**POC仓库:** [CVE-2024-38063](https://github.com/diegoalbuquerque/CVE-2024-38063)  

---

### [CVE-2025-30208](CVE-2025-30208-imbas007_CVE-2025-30208-template.md) 🟡 ✅

**名称:** CVE-2025-30208-Vite-任意文件读取  
**类型:** 任意文件读取  
**风险:** 中危，可导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-21  
**POC仓库:** [CVE-2025-30208-template](https://github.com/imbas007/CVE-2025-30208-template)  

---

### [CVE-2024-4577](CVE-2024-4577-cheerfulempl_CVE-2024-4577-PHP-RCE.md) 🔴 ✅

**名称:** CVE-2024-4577 - PHP-CGI Argument Injection  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许攻击者执行任意代码。  
**投毒风险:** 50%  
**发现时间:** 2025-04-20  
**POC仓库:** [CVE-2024-4577-PHP-RCE](https://github.com/cheerfulempl/CVE-2024-4577-PHP-RCE)  

---

### [CVE-2025-43919](CVE-2025-43919-0NYX-MY7H_CVE-2025-43919.md) 🟡 ✅

**名称:** CVE-2025-43919-GNU Mailman-目录遍历  
**类型:** 目录遍历  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-20  
**POC仓库:** [CVE-2025-43919](https://github.com/0NYX-MY7H/CVE-2025-43919)  

---

### [CVE-2025-43921](CVE-2025-43921-0NYX-MY7H_CVE-2025-43921.md) 🟡 ✅

**名称:** CVE-2025-43921-GNU Mailman-未授权列表创建  
**类型:** 未授权访问/权限绕过  
**风险:** 中危，可能被用于垃圾邮件、网络钓鱼或资源耗尽攻击  
**投毒风险:** 5%  
**发现时间:** 2025-04-20  
**POC仓库:** [CVE-2025-43921](https://github.com/0NYX-MY7H/CVE-2025-43921)  

---

### [CVE-2020-0796](CVE-2020-0796-DannyRavi_nmap-scripts.md) 🔴 ✅

**名称:** CVE-2020-0796 (SMBGhost)  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-20  
**POC仓库:** [nmap-scripts](https://github.com/DannyRavi/nmap-scripts)  

---

### [CVE-2025-3102](CVE-2025-3102-dennisec_CVE-2025-3102.md) 🔴 ✅

**名称:** CVE-2025-3102-SureTriggers-权限绕过  
**类型:** 权限绕过  
**风险:** 高危，允许未授权用户创建管理员账户  
**投毒风险:** 1%  
**发现时间:** 2025-04-20  
**POC仓库:** [CVE-2025-3102](https://github.com/dennisec/CVE-2025-3102)  

---

### [CVE-2025-0054](CVE-2025-0054-z3usx01_CVE-2025-0054.md) 🟡 ✅

**名称:** CVE-2025-0054 – SAP NetWeaver Stored XSS  
**类型:** 存储型跨站脚本 (Stored XSS)  
**风险:** 中危，可能允许攻击者读取或修改与受攻击网页相关的信息  
**投毒风险:** 10%  
**发现时间:** 2025-04-20  
**POC仓库:** [CVE-2025-0054](https://github.com/z3usx01/CVE-2025-0054)  

---

### [CVE-2025-43920](CVE-2025-43920-0NYX-MY7H_CVE-2025-43920.md) 🟡 ✅

**名称:** CVE-2025-43920-GNU Mailman-命令注入  
**类型:** 命令注入  
**风险:** 中危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-20  
**POC仓库:** [CVE-2025-43920](https://github.com/0NYX-MY7H/CVE-2025-43920)  

---

### [CVE-2023-32233](CVE-2023-32233-RogelioPumajulca_TEST-CVE-2023-32233.md) 🔴 ✅

**名称:** CVE-2023-32233-Linux Kernel Netfilter nf_tables Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，本地用户可提升至root权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-20  
**POC仓库:** [TEST-CVE-2023-32233](https://github.com/RogelioPumajulca/TEST-CVE-2023-32233)  

---

### [CVE-2023-32233](CVE-2023-32233-PIDAN-HEIDASHUAI_CVE-2023-32233.md) 🔴 ✅

**名称:** CVE-2023-32233-Linux Kernel-Netfilter Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，本地用户可提升至root权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-20  
**POC仓库:** [CVE-2023-32233](https://github.com/PIDAN-HEIDASHUAI/CVE-2023-32233)  

---

### [CVE-2023-32233](CVE-2023-32233-Liuk3r_CVE-2023-32233.md) 🔴 ✅

**名称:** CVE-2023-32233-Linux Kernel-Netfilter nf_tables Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，本地用户可获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-20  
**POC仓库:** [CVE-2023-32233](https://github.com/Liuk3r/CVE-2023-32233)  

---

### [CVE-2023-32233](CVE-2023-32233-oferchen_POC-CVE-2023-32233.md) 🔴 ✅

**名称:** CVE-2023-32233-Linux Kernel-Netfilter nf_tables UAF  
**类型:** Use-After-Free  
**风险:** 高危，可导致权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-04-20  
**POC仓库:** [POC-CVE-2023-32233](https://github.com/oferchen/POC-CVE-2023-32233)  

---

### [CVE-2023-32233](CVE-2023-32233-void0red_CVE-2023-32233.md) 🔴 ✅

**名称:** CVE-2023-32233-Linux Kernel Netfilter nf_tables Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可导致权限提升至root  
**投毒风险:** 1%  
**发现时间:** 2025-04-20  
**POC仓库:** [CVE-2023-32233](https://github.com/void0red/CVE-2023-32233)  

---

### [CVE-2023-50257](CVE-2023-50257-Jminis_CVE-2023-50257.md) 🔴 ✅

**名称:** CVE-2023-50257 - eProsima Fast DDS RTPS 数据包断开连接漏洞  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可导致服务中断  
**投毒风险:** 10%  
**发现时间:** 2025-04-20  
**POC仓库:** [CVE-2023-50257](https://github.com/Jminis/CVE-2023-50257)  

---

### [CVE-2021-44026](CVE-2021-44026-skyllpro_CVE-2021-44026-PoC.md) 🔴 ✅

**名称:** CVE-2021-44026-Roundcube-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-20  
**POC仓库:** [CVE-2021-44026-PoC](https://github.com/skyllpro/CVE-2021-44026-PoC)  

---

### [CVE-2019-2215](CVE-2019-2215-kangtastic_cve-2019-2215.md) 🔴 ✅

**名称:** CVE-2019-2215 Android Binder Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-04-20  
**POC仓库:** [cve-2019-2215](https://github.com/kangtastic/cve-2019-2215)  

---

### [CVE-2019-2215](CVE-2019-2215-ATorNinja_CVE-2019-2215.md) 🔴 ✅

**名称:** CVE-2019-2215 Android Binder Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，允许从应用程序到Linux内核的权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-04-20  
**POC仓库:** [CVE-2019-2215](https://github.com/ATorNinja/CVE-2019-2215)  

---

### [CVE-2019-2215](CVE-2019-2215-stevejubx_CVE-2019-2215.md) 🔴 ✅

**名称:** CVE-2019-2215 Android Binder Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可导致权限提升至 root  
**投毒风险:** 5%  
**发现时间:** 2025-04-20  
**POC仓库:** [CVE-2019-2215](https://github.com/stevejubx/CVE-2019-2215)  

---

### [CVE-2019-2215](CVE-2019-2215-mutur4_CVE-2019-2215.md) 🔴 ✅

**名称:** CVE-2019-2215 Android Binder Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可导致权限提升至内核级别  
**投毒风险:** 0%  
**发现时间:** 2025-04-20  
**POC仓库:** [CVE-2019-2215](https://github.com/mutur4/CVE-2019-2215)  

---

### [CVE-2019-2215](CVE-2019-2215-mouseos_cve-2019-2215_SH-M08.md) 🔴 ✅

**名称:** CVE-2019-2215 Android Binder Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可导致权限提升至 root  
**投毒风险:** 5%  
**发现时间:** 2025-04-20  
**POC仓库:** [cve-2019-2215_SH-M08](https://github.com/mouseos/cve-2019-2215_SH-M08)  

---

### [CVE-2021-44026](CVE-2021-44026-pentesttoolscom_roundcube-cve-2021-44026.md) 🔴 ✅

**名称:** CVE-2021-44026-Roundcube-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、会话劫持、远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-20  
**POC仓库:** [roundcube-cve-2021-44026](https://github.com/pentesttoolscom/roundcube-cve-2021-44026)  

---

### [CVE-2019-2215](CVE-2019-2215-raystyle_CVE-2019-2215.md) 🔴 ✅

**名称:** CVE-2019-2215 Android Binder Use-After-Free 漏洞  
**类型:** Use-After-Free  
**风险:** 高危，可导致权限提升至Linux内核级别  
**投毒风险:** 10%  
**发现时间:** 2025-04-20  
**POC仓库:** [CVE-2019-2215](https://github.com/raystyle/CVE-2019-2215)  

---

### [CVE-2019-2215](CVE-2019-2215-timwr_CVE-2019-2215.md) 🔴 ✅

**名称:** CVE-2019-2215 Android Binder Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可导致权限提升至Linux内核级别  
**投毒风险:** 5%  
**发现时间:** 2025-04-20  
**POC仓库:** [CVE-2019-2215](https://github.com/timwr/CVE-2019-2215)  

---

### [CVE-2019-2215](CVE-2019-2215-LIznzn_CVE-2019-2215.md) 🔴 ✅

**名称:** CVE-2019-2215 Android Binder Use-After-Free 本地提权漏洞  
**类型:** Use-After-Free  
**风险:** 高危，可从应用提权至Linux Kernel  
**投毒风险:** 10%  
**发现时间:** 2025-04-20  
**POC仓库:** [CVE-2019-2215](https://github.com/LIznzn/CVE-2019-2215)  

---

### [CVE-2019-2215](CVE-2019-2215-DimitriFourny_cve-2019-2215.md) 🔴 ✅

**名称:** CVE-2019-2215 Android Binder Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，允许本地权限提升至内核权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-20  
**POC仓库:** [cve-2019-2215](https://github.com/DimitriFourny/cve-2019-2215)  

---

### [CVE-2019-2215](CVE-2019-2215-qre0ct_android-kernel-exploitation-ashfaq-CVE-2019-2215.md) 🔴 ✅

**名称:** CVE-2019-2215 Android Binder Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可导致提权至Linux内核  
**投毒风险:** 10%  
**发现时间:** 2025-04-20  
**POC仓库:** [android-kernel-exploitation-ashfaq-CVE-2019-2215](https://github.com/qre0ct/android-kernel-exploitation-ashfaq-CVE-2019-2215)  

---

### [CVE-2019-2215](CVE-2019-2215-c3r34lk1ll3r_CVE-2019-2215.md) 🔴 ✅

**名称:** CVE-2019-2215 Android Binder Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可导致权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-04-20  
**POC仓库:** [CVE-2019-2215](https://github.com/c3r34lk1ll3r/CVE-2019-2215)  

---

### [CVE-2019-2215](CVE-2019-2215-Byte-Master-101_CVE-2019-2215.md) 🔴 ✅

**名称:** CVE-2019-2215 Android Binder Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可导致权限提升至Linux内核  
**投毒风险:** 5%  
**发现时间:** 2025-04-20  
**POC仓库:** [CVE-2019-2215](https://github.com/Byte-Master-101/CVE-2019-2215)  

---

### [CVE-2019-2215](CVE-2019-2215-mufidmb38_CVE-2019-2215.md) 🔴 ✅

**名称:** CVE-2019-2215 Android Binder Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可导致权限提升至Linux内核级别  
**投毒风险:** 10%  
**发现时间:** 2025-04-20  
**POC仓库:** [CVE-2019-2215](https://github.com/mufidmb38/CVE-2019-2215)  

---

### [CVE-2019-2215](CVE-2019-2215-nicchongwb_Rootsmart-v2.0.md) 🔴 ✅

**名称:** CVE-2019-2215 Android Binder Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可导致权限提升至Linux Kernel  
**投毒风险:** 10%  
**发现时间:** 2025-04-20  
**POC仓库:** [Rootsmart-v2.0](https://github.com/nicchongwb/Rootsmart-v2.0)  

---

### [CVE-2019-2215](CVE-2019-2215-CrackerCat_Rootsmart-v2.0.md) 🔴 ✅

**名称:** CVE-2019-2215 Android Binder Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可导致权限提升至Linux Kernel  
**投毒风险:** 20%  
**发现时间:** 2025-04-20  
**POC仓库:** [Rootsmart-v2.0](https://github.com/CrackerCat/Rootsmart-v2.0)  

---

### [CVE-2019-2215](CVE-2019-2215-enceka_cve-2019-2215-3.18.md) 🔴 ✅

**名称:** CVE-2019-2215 Android Binder Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可能导致权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-04-20  
**POC仓库:** [cve-2019-2215-3.18](https://github.com/enceka/cve-2019-2215-3.18)  

---

### [CVE-2019-2215](CVE-2019-2215-sharif-dev_AndroidKernelVulnerability.md) 🔴 ✅

**名称:** CVE-2019-2215 Android Binder Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可导致特权提升  
**投毒风险:** 10%  
**发现时间:** 2025-04-20  
**POC仓库:** [AndroidKernelVulnerability](https://github.com/sharif-dev/AndroidKernelVulnerability)  

---

### [CVE-2019-2215](CVE-2019-2215-elbiazo_CVE-2019-2215.md) 🔴 ✅

**名称:** CVE-2019-2215 Android Binder Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可导致权限提升至内核级别  
**投毒风险:** 10%  
**发现时间:** 2025-04-20  
**POC仓库:** [CVE-2019-2215](https://github.com/elbiazo/CVE-2019-2215)  

---

### [CVE-2019-2215](CVE-2019-2215-willboka_CVE-2019-2215-HuaweiP20Lite.md) 🔴 ✅

**名称:** CVE-2019-2215 Android Binder Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可导致特权提升  
**投毒风险:** 10%  
**发现时间:** 2025-04-20  
**POC仓库:** [CVE-2019-2215-HuaweiP20Lite](https://github.com/willboka/CVE-2019-2215-HuaweiP20Lite)  

---

### [CVE-2019-2215](CVE-2019-2215-R0rt1z2_huawei-unlock.md) 🔴 ✅

**名称:** CVE-2019-2215 Android Binder Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可能导致权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-04-20  
**POC仓库:** [huawei-unlock](https://github.com/R0rt1z2/huawei-unlock)  

---

### [CVE-2019-2215](CVE-2019-2215-raymontag_CVE-2019-2215.md) 🔴 ✅

**名称:** CVE-2019-2215 Android Binder Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可导致权限提升至Linux Kernel  
**投毒风险:** 10%  
**发现时间:** 2025-04-20  
**POC仓库:** [CVE-2019-2215](https://github.com/raymontag/CVE-2019-2215)  

---

### [CVE-2019-2215](CVE-2019-2215-XiaozaYa_CVE-2019-2215.md) 🔴 ✅

**名称:** CVE-2019-2215 Android Binder Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-04-20  
**POC仓库:** [CVE-2019-2215](https://github.com/XiaozaYa/CVE-2019-2215)  

---

### [CVE-2019-2215](CVE-2019-2215-llccd_TempRoot-Huawei.md) 🔴 ✅

**名称:** CVE-2019-2215 Android Binder Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可导致权限提升至Linux内核级别  
**投毒风险:** 10%  
**发现时间:** 2025-04-20  
**POC仓库:** [TempRoot-Huawei](https://github.com/llccd/TempRoot-Huawei)  

---

### [CVE-2019-2215](CVE-2019-2215-0xbinder_android-kernel-exploitation-lab.md) 🔴 ✅

**名称:** CVE-2019-2215 Android Binder Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可导致权限提升至root  
**投毒风险:** 10%  
**发现时间:** 2025-04-20  
**POC仓库:** [android-kernel-exploitation-lab](https://github.com/0xbinder/android-kernel-exploitation-lab)  

---

### [CVE-2025-43929](CVE-2025-43929-0xBenCantCode_CVE-2025-43929.md) 🟡 ✅

**名称:** CVE-2025-43929-kitty-本地文件执行  
**类型:** 本地文件执行  
**风险:** 中危，用户交互后可能导致本地命令执行，敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-20  
**POC仓库:** [CVE-2025-43929](https://github.com/0xBenCantCode/CVE-2025-43929)  

---

### [CVE-2025-43919](CVE-2025-43919-0NYX-MY7H_CVE-2025-43919.md) 🔴 ✅

**名称:** CVE-2025-43919: GNU Mailman 2.1.39目录遍历漏洞  
**类型:** 目录遍历  
**风险:** 高危，可读取敏感文件  
**投毒风险:** 0%  
**发现时间:** 2025-04-20  
**POC仓库:** [CVE-2025-43919](https://github.com/0NYX-MY7H/CVE-2025-43919)  

---

### [CVE-2025-43921](CVE-2025-43921-0NYX-MY7H_CVE-2025-43921.md) 🔴 ✅

**名称:** CVE-2025-43919 GNU Mailman Directory Traversal  
**类型:** 目录遍历  
**风险:** 高危，可能导致信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-20  
**POC仓库:** [CVE-2025-43921](https://github.com/0NYX-MY7H/CVE-2025-43921)  

---

### [CVE-2025-43920](CVE-2025-43920-0NYX-MY7H_CVE-2025-43920.md) 🔴 ✅

**名称:** CVE-2025-43920: GNU Mailman Command Injection  
**类型:** 命令注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-20  
**POC仓库:** [CVE-2025-43920](https://github.com/0NYX-MY7H/CVE-2025-43920)  

---

### [CVE-2025-32433](CVE-2025-32433-SDX442_CVE-2025-32433.md) 🔴 ✅

**名称:** CVE-2025-32433-Erlang/OTP SSH-未授权RCE  
**类型:** 未授权远程代码执行  
**风险:** 高危，可完全控制受影响系统  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2025-32433](https://github.com/SDX442/CVE-2025-32433)  

---

### [CVE-2025-39436](CVE-2025-39436-Nxploited_CVE-2025-39436.md) 🔴 ✅

**名称:** CVE-2025-39436-I Draw-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2025-39436](https://github.com/Nxploited/CVE-2025-39436)  

---

### [CVE-2023-38408](CVE-2023-38408-classic130_CVE-2023-38408.md) 🔴 ✅

**名称:** CVE-2023-38408-OpenSSH-Agent转发RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2023-38408](https://github.com/classic130/CVE-2023-38408)  

---

### [CVE-2023-38408](CVE-2023-38408-LucasPDiniz_CVE-2023-38408.md) 🔴 ✅

**名称:** CVE-2023-38408-OpenSSH-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2023-38408](https://github.com/LucasPDiniz/CVE-2023-38408)  

---

### [CVE-2023-38408](CVE-2023-38408-mrtacojr_CVE-2023-38408.md) 🔴 ✅

**名称:** CVE-2023-38408-OpenSSH-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 80%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2023-38408](https://github.com/mrtacojr/CVE-2023-38408)  

---

### [CVE-2023-38408](CVE-2023-38408-fazilbaig1_cve_2023_38408_scanner.md) 🔴 ✅

**名称:** CVE-2023-38408-OpenSSH-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统控制  
**投毒风险:** 1%  
**发现时间:** 2025-04-19  
**POC仓库:** [cve_2023_38408_scanner](https://github.com/fazilbaig1/cve_2023_38408_scanner)  

---

### [CVE-2023-38408](CVE-2023-38408-kali-mx_CVE-2023-38408.md) 🔴 ✅

**名称:** CVE-2023-38408-OpenSSH-Agent转发RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行，控制受害者机器  
**投毒风险:** 1%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2023-38408](https://github.com/kali-mx/CVE-2023-38408)  

---

### [CVE-2023-38408](CVE-2023-38408-Nick-Morbid_cve-2023-38408.md) 🔴 ✅

**名称:** CVE-2023-38408-OpenSSH-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致完全控制受影响系统  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [cve-2023-38408](https://github.com/Nick-Morbid/cve-2023-38408)  

---

### [CVE-2023-38408](CVE-2023-38408-wxrdnx_CVE-2023-38408.md) 🔴 ✅

**名称:** CVE-2023-38408-OpenSSH-Agent转发RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2023-38408](https://github.com/wxrdnx/CVE-2023-38408)  

---

### [CVE-2023-38408](CVE-2023-38408-TX-One_CVE-2023-38408.md)  ✅

**名称:** CVE-2023-38408 - OpenSSH Agent Forwarding RCE  
**类型:** 远程代码执行  
**风险:** 严重，允许远程攻击者在受害者机器上执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2023-38408](https://github.com/TX-One/CVE-2023-38408)  

---

### [CVE-2025-32433](CVE-2025-32433-meloppeitreet_CVE-2025-32433-Remote-Shell.md) 🔴 ✅

**名称:** CVE-2025-32433-Erlang/OTP SSH 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2025-32433-Remote-Shell](https://github.com/meloppeitreet/CVE-2025-32433-Remote-Shell)  

---

### [CVE-2024-31317](CVE-2024-31317-Anonymous941_zygote-injection-toolkit.md) 🔴 ✅

**名称:** CVE-2024-31317-Android Zygote注入  
**类型:** 特权提升  
**风险:** 高危，可提升为system权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [zygote-injection-toolkit](https://github.com/Anonymous941/zygote-injection-toolkit)  

---

### [CVE-2024-31317](CVE-2024-31317-Webldix_CVE-2024-31317-PoC-Deployer.md) 🔴 ✅

**名称:** CVE-2024-31317-Android Zygote Deserialization  
**类型:** 特权提升  
**风险:** 高危，可导致任意应用代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2024-31317-PoC-Deployer](https://github.com/Webldix/CVE-2024-31317-PoC-Deployer)  

---

### [CVE-2025-32433](CVE-2025-32433-0xPThree_cve-2025-32433.md) 🔴 ✅

**名称:** CVE-2025-32433 Erlang/OTP SSH Pre-Authentication RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [cve-2025-32433](https://github.com/0xPThree/cve-2025-32433)  

---

### [CVE-2025-28121](CVE-2025-28121-pruthuraut_CVE-2025-28121.md) 🟡 ✅

**名称:** CVE-2025-28121 - Online Exam Mastering System 1.0 Reflected XSS  
**类型:** Reflected XSS  
**风险:** 中危，可能导致账户劫持、权限提升、浏览器攻击等  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2025-28121](https://github.com/pruthuraut/CVE-2025-28121)  

---

### [CVE-2020-0796](CVE-2020-0796-Murasame-nc_CVE-2020-0796-LPE-POC.md) 🔴 ✅

**名称:** CVE-2020-0796 (SMBGhost) 本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，可能导致系统权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2020-0796-LPE-POC](https://github.com/Murasame-nc/CVE-2020-0796-LPE-POC)  

---

### [CVE-2020-0796](CVE-2020-0796-F6JO_CVE-2020-0796-Batch-scanning.md) 🔴 ✅

**名称:** CVE-2020-0796-SMBGhost  
**类型:** 远程代码执行  
**风险:** 高危，可导致远程代码执行，可能导致系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2020-0796-Batch-scanning](https://github.com/F6JO/CVE-2020-0796-Batch-scanning)  

---

### [CVE-2020-0796](CVE-2020-0796-orangmuda_CVE-2020-0796.md) 🔴 ✅

**名称:** CVE-2020-0796 SMBGhost 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2020-0796](https://github.com/orangmuda/CVE-2020-0796)  

---

### [CVE-2020-0796](CVE-2020-0796-lisinan988_CVE-2020-0796-exp.md) 🔴 ✅

**名称:** CVE-2020-0796 (SMBGhost) 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，远程代码执行，蠕虫级  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2020-0796-exp](https://github.com/lisinan988/CVE-2020-0796-exp)  

---

### [CVE-2020-0796](CVE-2020-0796-julixsalas_CVE-2020-0796.md) 🔴 ✅

**名称:** CVE-2020-0796 - SMBGhost 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和网络传播  
**投毒风险:** 5%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2020-0796](https://github.com/julixsalas/CVE-2020-0796)  

---

### [CVE-2020-0796](CVE-2020-0796-vsai94_ECE9069_SMBGhost_Exploit_CVE-2020-0796-.md) 🔴 ✅

**名称:** CVE-2020-0796 (SMBGhost)  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致远程代码执行和网络传播  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [ECE9069_SMBGhost_Exploit_CVE-2020-0796-](https://github.com/vsai94/ECE9069_SMBGhost_Exploit_CVE-2020-0796-)  

---

### [CVE-2020-0796](CVE-2020-0796-Barriuso_SMBGhost_AutomateExploitation.md) 🔴 ✅

**名称:** CVE-2020-0796-Windows SMBv3远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [SMBGhost_AutomateExploitation](https://github.com/Barriuso/SMBGhost_AutomateExploitation)  

---

### [CVE-2020-0796](CVE-2020-0796-arzuozkan_CVE-2020-0796.md) 🔴 ✅

**名称:** CVE-2020-0796 SMBGhost 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2020-0796](https://github.com/arzuozkan/CVE-2020-0796)  

---

### [CVE-2020-0796](CVE-2020-0796-awareseven_eternalghosttest.md) 🔴 ✅

**名称:** CVE-2020-0796 (SMBGhost)  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [eternalghosttest](https://github.com/awareseven/eternalghosttest)  

---

### [CVE-2020-0796](CVE-2020-0796-SEHandler_CVE-2020-0796.md) 🔴 ✅

**名称:** CVE-2020-0796 SMBGhost 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行，完全控制受影响系统  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2020-0796](https://github.com/SEHandler/CVE-2020-0796)  

---

### [CVE-2020-0796](CVE-2020-0796-syadg123_CVE-2020-0796.md) 🔴 ✅

**名称:** CVE-2020-0796-SMBGhost-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2020-0796](https://github.com/syadg123/CVE-2020-0796)  

---

### [CVE-2020-0796](CVE-2020-0796-krizzz07_CVE-2020-0796.md) 🔴 ✅

**名称:** CVE-2020-0796 (SMBGhost)  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2020-0796](https://github.com/krizzz07/CVE-2020-0796)  

---

### [CVE-2020-0796](CVE-2020-0796-eerykitty_CVE-2020-0796-PoC.md) 🔴 ✅

**名称:** CVE-2020-0796 (SMBGhost)  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致远程代码执行和系统崩溃  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2020-0796-PoC](https://github.com/eerykitty/CVE-2020-0796-PoC)  

---

### [CVE-2020-0796](CVE-2020-0796-T13nn3s_CVE-2020-0796.md) 🔴 ✅

**名称:** CVE-2020-0796 (SMBGhost)  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2020-0796](https://github.com/T13nn3s/CVE-2020-0796)  

---

### [CVE-2020-0796](CVE-2020-0796-w1ld3r_SMBGhost_Scanner.md) 🔴 ✅

**名称:** CVE-2020-0796 (SMBGhost)  
**类型:** 远程代码执行  
**风险:** 高危，可导致远程代码执行，蠕虫式传播  
**投毒风险:** 1%  
**发现时间:** 2025-04-19  
**POC仓库:** [SMBGhost_Scanner](https://github.com/w1ld3r/SMBGhost_Scanner)  

---

### [CVE-2020-0796](CVE-2020-0796-dungnm24_CVE-2020-0796.md) 🔴 ✅

**名称:** CVE-2020-0796 SMBGhost RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者在目标服务器上执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2020-0796](https://github.com/dungnm24/CVE-2020-0796)  

---

### [CVE-2020-0796](CVE-2020-0796-OldDream666_cve-2020-0796.md) 🔴 ✅

**名称:** CVE-2020-0796 - SMBGhost 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [cve-2020-0796](https://github.com/OldDream666/cve-2020-0796)  

---

### [CVE-2020-0796](CVE-2020-0796-Opensitoo_cve-2020-0796.md) 🔴 ✅

**名称:** CVE-2020-0796-SMBGhost-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致远程代码执行和系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [cve-2020-0796](https://github.com/Opensitoo/cve-2020-0796)  

---

### [CVE-2020-0796](CVE-2020-0796-hungdnvp_POC-CVE-2020-0796.md)  ✅

**名称:** CVE-2020-0796 (SMBGhost)  
**类型:** 远程代码执行  
**风险:** 严重，可能导致远程代码执行和系统崩溃  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [POC-CVE-2020-0796](https://github.com/hungdnvp/POC-CVE-2020-0796)  

---

### [CVE-2020-0796](CVE-2020-0796-AdamSonov_smbGhostCVE-2020-0796.md) 🔴 ✅

**名称:** CVE-2020-0796-SMBGhost  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和网络传播  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [smbGhostCVE-2020-0796](https://github.com/AdamSonov/smbGhostCVE-2020-0796)  

---

### [CVE-2020-0796](CVE-2020-0796-z3ena_Exploiting-and-Mitigating-CVE-2020-0796-SMBGhost-and-Print-Spooler-Vulnerabilities.md) 🔴 ✅

**名称:** CVE-2020-0796-Windows SMBv3远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致完全控制受影响的系统  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [Exploiting-and-Mitigating-CVE-2020-0796-SMBGhost-and-Print-Spooler-Vulnerabilities](https://github.com/z3ena/Exploiting-and-Mitigating-CVE-2020-0796-SMBGhost-and-Print-Spooler-Vulnerabilities)  

---

### [CVE-2020-0796](CVE-2020-0796-ran-sama_CVE-2020-0796.md) 🔴 ✅

**名称:** CVE-2020-0796 (SMBGhost)  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统崩溃  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2020-0796](https://github.com/ran-sama/CVE-2020-0796)  

---

### [CVE-2020-0796](CVE-2020-0796-Kaizzzo1_CVE-2020-0796.md) 🔴 ✅

**名称:** CVE-2020-0796-SMBGhost-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2020-0796](https://github.com/Kaizzzo1/CVE-2020-0796)  

---

### [CVE-2020-0796](CVE-2020-0796-monjheta_CVE-2020-0796.md) 🔴 ✅

**名称:** CVE-2020-0796-SMBGhost-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行，完全控制受影响系统  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2020-0796](https://github.com/monjheta/CVE-2020-0796)  

---

### [CVE-2020-0796](CVE-2020-0796-madanokr001_CVE-2020-0796.md) 🔴 ✅

**名称:** CVE-2020-0796 SMBGhost 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2020-0796](https://github.com/madanokr001/CVE-2020-0796)  

---

### [CVE-2024-39943](CVE-2024-39943-truonghuuphuc_CVE-2024-39943-Poc.md) 🔴 ✅

**名称:** CVE-2024-39943-rejetto HFS-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致完全控制服务器  
**投毒风险:** 5%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2024-39943-Poc](https://github.com/truonghuuphuc/CVE-2024-39943-Poc)  

---

### [CVE-2025-32433](CVE-2025-32433-ekomsSavior_POC_CVE-2025-32433.md) 🔴 ✅

**名称:** CVE-2025-32433 - Erlang/OTP SSH Pre-Authentication RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [POC_CVE-2025-32433](https://github.com/ekomsSavior/POC_CVE-2025-32433)  

---

### [CVE-2025-24801](CVE-2025-24801-r1beirin_CVE-2025-24801.md) 🔴 ✅

**名称:** CVE-2025-24801-GLPI-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许经过身份验证的用户上传恶意PHP文件并执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2025-24801](https://github.com/r1beirin/CVE-2025-24801)  

---

### [CVE-2024-8425](CVE-2024-8425-KTN1990_CVE-2024-8425.md) 🔴 ✅

**名称:** CVE-2024-8425-WooCommerce Ultimate Gift Card-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2024-8425](https://github.com/KTN1990/CVE-2024-8425)  

---

### [CVE-2024-42327](CVE-2024-42327-aramosf_cve-2024-42327.md) 🔴 ✅

**名称:** CVE-2024-42327-Zabbix-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致权限提升、敏感信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-04-19  
**POC仓库:** [cve-2024-42327](https://github.com/aramosf/cve-2024-42327)  

---

### [CVE-2024-42327](CVE-2024-42327-compr00t_CVE-2024-42327.md)  ✅

**名称:** CVE-2024-42327-Zabbix-SQL注入  
**类型:** SQL注入  
**风险:** 严重，可能导致权限提升和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2024-42327](https://github.com/compr00t/CVE-2024-42327)  

---

### [CVE-2024-42327](CVE-2024-42327-depers-rus_CVE-2024-42327.md) 🔴 ✅

**名称:** CVE-2024-42327-Zabbix-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、权限提升和远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2024-42327](https://github.com/depers-rus/CVE-2024-42327)  

---

### [CVE-2024-42327](CVE-2024-42327-watchdog1337_CVE-2024-42327_Zabbix_SQLI.md) 🔴 ✅

**名称:** CVE-2024-42327-Zabbix-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致权限提升和远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2024-42327_Zabbix_SQLI](https://github.com/watchdog1337/CVE-2024-42327_Zabbix_SQLI)  

---

### [CVE-2024-42327](CVE-2024-42327-itform-fr_Zabbix---CVE-2024-42327.md) 🔴 ✅

**名称:** CVE-2024-42327-Zabbix-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致权限提升和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [Zabbix---CVE-2024-42327](https://github.com/itform-fr/Zabbix---CVE-2024-42327)  

---

### [CVE-2024-42327](CVE-2024-42327-igorbf495_CVE-2024-42327.md) 🔴 ✅

**名称:** CVE-2024-42327 - Zabbix SQL 注入  
**类型:** SQL 注入  
**风险:** 高危，可能导致权限提升、数据泄露和远程命令执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2024-42327](https://github.com/igorbf495/CVE-2024-42327)  

---

### [CVE-2024-42327](CVE-2024-42327-BridgerAlderson_Zabbix-CVE-2024-42327-SQL-Injection-RCE.md) 🔴 ✅

**名称:** CVE-2024-42327-Zabbix-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、权限提升和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-19  
**POC仓库:** [Zabbix-CVE-2024-42327-SQL-Injection-RCE](https://github.com/BridgerAlderson/Zabbix-CVE-2024-42327-SQL-Injection-RCE)  

---

### [CVE-2024-42327](CVE-2024-42327-godylockz_CVE-2024-42327.md) 🔴 ✅

**名称:** CVE-2024-42327-Zabbix-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可导致权限提升和远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2024-42327](https://github.com/godylockz/CVE-2024-42327)  

---

### [CVE-2024-42327](CVE-2024-42327-874anthony_CVE-2024-42327_Zabbix_SQLi.md) 🔴 ✅

**名称:** CVE-2024-42327-Zabbix-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、权限提升和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-19  
**POC仓库:** [CVE-2024-42327_Zabbix_SQLi](https://github.com/874anthony/CVE-2024-42327_Zabbix_SQLi)  

---

### [CVE-2025-32433](CVE-2025-32433-exa-offsec_ssh_erlangotp_rce.md) 🔴 ✅

**名称:** CVE-2025-32433-Erlang/OTP-SSH远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，无需身份验证即可远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [ssh_erlangotp_rce](https://github.com/exa-offsec/ssh_erlangotp_rce)  

---

### [CVE-2024-46713](CVE-2024-46713-enlist12_CVE-2024-46713.md) 🔴 ✅

**名称:** CVE-2024-46713-Linux kernel perf/aux 竞争条件UAF  
**类型:** Use-After-Free (UAF)  
**风险:** 高危，可能导致权限提升或任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2024-46713](https://github.com/enlist12/CVE-2024-46713)  

---

### [CVE-2025-32433](CVE-2025-32433-m0usem0use_erl_mouse.md) 🔴 ✅

**名称:** CVE-2025-32433-Erlang/OTP SSH RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [erl_mouse](https://github.com/m0usem0use/erl_mouse)  

---

### [CVE-2025-32433](CVE-2025-32433-omer-efe-curkus_CVE-2025-32433-Erlang-OTP-SSH-RCE-PoC.md) 🔴 ✅

**名称:** CVE-2025-32433-Erlang/OTP-SSH-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2025-32433-Erlang-OTP-SSH-RCE-PoC](https://github.com/omer-efe-curkus/CVE-2025-32433-Erlang-OTP-SSH-RCE-PoC)  

---

### [CVE-2023-27997](CVE-2023-27997-rio128128_CVE-2023-27997-POC.md)  ✅

**名称:** CVE-2023-27997 - FortiOS SSL-VPN 堆缓冲区溢出  
**类型:** 堆缓冲区溢出  
**风险:** 严重，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2023-27997-POC](https://github.com/rio128128/CVE-2023-27997-POC)  

---

### [CVE-2023-27997](CVE-2023-27997-imbas007_CVE-2023-27997-Check.md) 🔴 ✅

**名称:** CVE-2023-27997-FortiOS/FortiProxy SSL-VPN 堆溢出  
**类型:** 堆溢出  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2023-27997-Check](https://github.com/imbas007/CVE-2023-27997-Check)  

---

### [CVE-2023-27997](CVE-2023-27997-puckiestyle_cve-2023-27997.md) 🔴 ✅

**名称:** CVE-2023-27997-FortiOS/FortiProxy-堆缓冲区溢出  
**类型:** 堆缓冲区溢出  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-18  
**POC仓库:** [cve-2023-27997](https://github.com/puckiestyle/cve-2023-27997)  

---

### [CVE-2023-27997](CVE-2023-27997-TechinsightsPro_ShodanFortiOS.md) 🔴 ✅

**名称:** CVE-2023-27997 - FortiOS SSL-VPN 堆缓冲区溢出  
**类型:** 堆缓冲区溢出  
**风险:** 高危，可远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-18  
**POC仓库:** [ShodanFortiOS](https://github.com/TechinsightsPro/ShodanFortiOS)  

---

### [CVE-2023-27997](CVE-2023-27997-lexfo_xortigate-cve-2023-27997.md) 🔴 ✅

**名称:** CVE-2023-27997 - FortiOS SSL-VPN 堆缓冲区溢出  
**类型:** 堆缓冲区溢出  
**风险:** 高危，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [xortigate-cve-2023-27997](https://github.com/lexfo/xortigate-cve-2023-27997)  

---

### [CVE-2023-27997](CVE-2023-27997-delsploit_CVE-2023-27997.md) 🔴 ✅

**名称:** CVE-2023-27997-FortiOS-SSL-VPN堆溢出  
**类型:** 堆溢出  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2023-27997](https://github.com/delsploit/CVE-2023-27997)  

---

### [CVE-2023-27997](CVE-2023-27997-BishopFox_CVE-2023-27997-check.md) 🔴 ✅

**名称:** CVE-2023-27997 - FortiOS/FortiProxy SSL-VPN 堆缓冲区溢出  
**类型:** 堆缓冲区溢出  
**风险:** 高危，远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2023-27997-check](https://github.com/BishopFox/CVE-2023-27997-check)  

---

### [CVE-2023-27997](CVE-2023-27997-node011_CVE-2023-27997-POC.md) 🔴 ✅

**名称:** CVE-2023-27997-FortiOS/FortiProxy SSL-VPN 堆缓冲区溢出  
**类型:** 堆缓冲区溢出  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2023-27997-POC](https://github.com/node011/CVE-2023-27997-POC)  

---

### [CVE-2023-27997](CVE-2023-27997-onurkerembozkurt_fgt-cve-2023-27997-exploit.md) 🔴 ✅

**名称:** CVE-2023-27997 - FortiOS SSL-VPN 堆溢出漏洞  
**类型:** 堆溢出  
**风险:** 高危，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [fgt-cve-2023-27997-exploit](https://github.com/onurkerembozkurt/fgt-cve-2023-27997-exploit)  

---

### [CVE-2025-21756](CVE-2025-21756-hoefler02_CVE-2025-21756.md) 🔴 ✅

**名称:** CVE-2025-21756-Linux Kernel vsock Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可能导致内核崩溃、权限提升或信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2025-21756](https://github.com/hoefler02/CVE-2025-21756)  

---

### [CVE-2025-32433](CVE-2025-32433-teamtopkarl_CVE-2025-32433.md) 🔴 ✅

**名称:** CVE-2025-32433-Erlang/OTP-SSH-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，无需身份验证即可远程执行代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2025-32433](https://github.com/teamtopkarl/CVE-2025-32433)  

---

### [CVE-2024-53924](CVE-2024-53924-aelmosalamy_CVE-2024-53924.md) 🔴 ✅

**名称:** CVE-2024-53924-Pycel-代码执行  
**类型:** 代码执行  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2024-53924](https://github.com/aelmosalamy/CVE-2024-53924)  

---

### [CVE-2024-4577](CVE-2024-4577-Gill-Singh-A_CVE-2024-4577-Exploit.md) 🔴 ✅

**名称:** CVE-2024-4577 PHP-CGI 参数注入导致远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2024-4577-Exploit](https://github.com/Gill-Singh-A/CVE-2024-4577-Exploit)  

---

### [CVE-2025-24054](CVE-2025-24054-xigney_CVE-2025-24054_PoC.md) 🟡 ✅

**名称:** CVE-2025-24054-NTLM Hash Disclosure Spoofing  
**类型:** NTLM哈希泄露欺骗  
**风险:** 中危，可能导致凭据泄露，但需要用户交互  
**投毒风险:** 0%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2025-24054_PoC](https://github.com/xigney/CVE-2025-24054_PoC)  

---

### [CVE-2025-24813](CVE-2025-24813-Erosion2020_CVE-2025-24813-vulhub.md) 🔴 ✅

**名称:** CVE-2025-24813-Apache Tomcat 路径等价和反序列化漏洞  
**类型:** 远程代码执行/信息泄露  
**风险:** 高危，可能导致远程代码执行和敏感信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2025-24813-vulhub](https://github.com/Erosion2020/CVE-2025-24813-vulhub)  

---

### [CVE-2025-32433](CVE-2025-32433-darses_CVE-2025-32433.md) 🔴 ✅

**名称:** CVE-2025-32433-Erlang/OTP SSH-未授权RCE  
**类型:** 未授权远程代码执行  
**风险:** 高危，可完全控制受影响服务器  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2025-32433](https://github.com/darses/CVE-2025-32433)  

---

### [CVE-2025-32433](CVE-2025-32433-LemieOne_CVE-2025-32433.md)  ✅

**名称:** CVE-2025-32433-Erlang/OTP SSH-RCE  
**类型:** 远程代码执行  
**风险:** 严重，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2025-32433](https://github.com/LemieOne/CVE-2025-32433)  

---

### [CVE-2025-24054](CVE-2025-24054-xigney_CVE-2025-24054-PoC.md) 🟡 ✅

**名称:** CVE-2025-24054-NTLM Hash Disclosure Spoofing  
**类型:** NTLM Hash Disclosure Spoofing  
**风险:** 中危，可能导致凭据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2025-24054-PoC](https://github.com/xigney/CVE-2025-24054-PoC)  

---

### [CVE-2022-41352](CVE-2022-41352-rxerium_CVE-2022-41352.md) 🔴 ✅

**名称:** CVE-2022-41352-Zimbra-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2022-41352](https://github.com/rxerium/CVE-2022-41352)  

---

### [CVE-2025-32682](CVE-2025-32682-Nxploited_CVE-2025-32682.md)  ✅

**名称:** CVE-2025-32682 - MapSVG Lite Arbitrary File Upload  
**类型:** Arbitrary File Upload  
**风险:** 严重，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2025-32682](https://github.com/Nxploited/CVE-2025-32682)  

---

### [CVE-2021-44967](CVE-2021-44967-D3Ext_CVE-2021-44967.md) 🔴 ✅

**名称:** CVE-2021-44967-LimeSurvey-RCE  
**类型:** 远程代码执行(RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2021-44967](https://github.com/D3Ext/CVE-2021-44967)  

---

### [CVE-2021-44967](CVE-2021-44967-godylockz_CVE-2021-44967.md) 🔴 ✅

**名称:** CVE-2021-44967-LimeSurvey-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2021-44967](https://github.com/godylockz/CVE-2021-44967)  

---

### [CVE-2021-44967](CVE-2021-44967-monke443_CVE-2021-44967.md) 🔴 ✅

**名称:** CVE-2021-44967 - LimeSurvey RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经授权的用户在服务器上执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2021-44967](https://github.com/monke443/CVE-2021-44967)  

---

### [CVE-2022-41352](CVE-2022-41352-segfault-it_cve-2022-41352.md)  ✅

**名称:** CVE-2022-41352-Zimbra-RCE  
**类型:** 远程代码执行  
**风险:** 严重，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-18  
**POC仓库:** [cve-2022-41352](https://github.com/segfault-it/cve-2022-41352)  

---

### [CVE-2022-41352](CVE-2022-41352-Cr4ckC4t_cve-2022-41352-zimbra-rce.md) 🔴 ✅

**名称:** CVE-2022-41352-Zimbra RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [cve-2022-41352-zimbra-rce](https://github.com/Cr4ckC4t/cve-2022-41352-zimbra-rce)  

---

### [CVE-2022-41352](CVE-2022-41352-qailanet_cve-2022-41352-zimbra-rce.md) 🔴 ✅

**名称:** CVE-2022-41352-Zimbra-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制和数据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-04-18  
**POC仓库:** [cve-2022-41352-zimbra-rce](https://github.com/qailanet/cve-2022-41352-zimbra-rce)  

---

### [CVE-2023-6000](CVE-2023-6000-RonF98_CVE-2023-6000-POC.md) 🟡 ✅

**名称:** CVE-2023-6000 - Popup Builder 未授权存储型XSS  
**类型:** 存储型跨站脚本 (Stored XSS)  
**风险:** 中危，可能导致用户会话劫持，信息泄露，恶意重定向等  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2023-6000-POC](https://github.com/RonF98/CVE-2023-6000-POC)  

---

### [CVE-2023-6000](CVE-2023-6000-rxerium_CVE-2023-6000.md) 🔴 ✅

**名称:** CVE-2023-6000-Popup Builder-Stored XSS  
**类型:** Stored XSS  
**风险:** 高危，可能导致任意代码执行，权限提升，信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2023-6000](https://github.com/rxerium/CVE-2023-6000)  

---

### [CVE-2025-32395](CVE-2025-32395-ruiwenya_CVE-2025-32395.md) 🟡 ✅

**名称:** CVE-2025-32395-Vite-文件读取  
**类型:** 文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2025-32395](https://github.com/ruiwenya/CVE-2025-32395)  

---

### [CVE-2024-39929](CVE-2024-39929-michael-david-fry_CVE-2024-39929.md) 🟡 ✅

**名称:** CVE-2024-39929 - Exim 邮件服务器文件扩展名绕过  
**类型:** 文件扩展名绕过  
**风险:** 中危，可能允许恶意附件传递  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2024-39929](https://github.com/michael-david-fry/CVE-2024-39929)  

---

### [CVE-2024-39929](CVE-2024-39929-rxerium_CVE-2024-39929.md) 🟡 ✅

**名称:** CVE-2024-39929-Exim-MIME绕过  
**类型:** MIME绕过  
**风险:** 中危，可能导致恶意附件投递  
**投毒风险:** 5%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2024-39929](https://github.com/rxerium/CVE-2024-39929)  

---

### [CVE-2023-22515](CVE-2023-22515-ErikWynter_CVE-2023-22515-Scan.md) 🔴 ✅

**名称:** CVE-2023-22515-Atlassian Confluence-Broken Access Control  
**类型:** Broken Access Control  
**风险:** 高危，可能导致未授权访问和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2023-22515-Scan](https://github.com/ErikWynter/CVE-2023-22515-Scan)  

---

### [CVE-2023-22515](CVE-2023-22515-j3seer_CVE-2023-22515-POC.md) 🔴 ✅

**名称:** CVE-2023-22515 Atlassian Confluence 权限提升/未授权管理员创建漏洞  
**类型:** 权限提升/Broken Access Control  
**风险:** 高危，允许未授权用户创建管理员账户，完全控制 Confluence 实例  
**投毒风险:** 0%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2023-22515-POC](https://github.com/j3seer/CVE-2023-22515-POC)  

---

### [CVE-2023-22515](CVE-2023-22515-Le1a_CVE-2023-22515.md) 🔴 ✅

**名称:** CVE-2023-22515-Confluence-Broken Access Control  
**类型:** Broken Access Control  
**风险:** 高危，允许未经身份验证的攻击者创建管理员账户  
**投毒风险:** 0%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2023-22515](https://github.com/Le1a/CVE-2023-22515)  

---

### [CVE-2023-22515](CVE-2023-22515-Vulnmachines_confluence-cve-2023-22515.md) 🔴 ✅

**名称:** CVE-2023-22515 - Atlassian Confluence Broken Access Control  
**类型:** Broken Access Control  
**风险:** 高危，允许未经身份验证的攻击者创建Confluence管理员帐户并访问Confluence实例  
**投毒风险:** 5%  
**发现时间:** 2025-04-18  
**POC仓库:** [confluence-cve-2023-22515](https://github.com/Vulnmachines/confluence-cve-2023-22515)  

---

### [CVE-2023-22515](CVE-2023-22515-iveresk_CVE-2023-22515.md) 🔴 ✅

**名称:** CVE-2023-22515-Atlassian Confluence-Broken Access Control  
**类型:** Broken Access Control  
**风险:** 高危，可创建未授权的Confluence管理员账户并完全控制Confluence实例。  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2023-22515](https://github.com/iveresk/CVE-2023-22515)  

---

### [CVE-2023-22515](CVE-2023-22515-ad-calcium_CVE-2023-22515.md) 🔴 ✅

**名称:** CVE-2023-22515-Confluence 破损的访问控制  
**类型:** 破损的访问控制  
**风险:** 高危，可能导致未授权的管理员账户创建和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2023-22515](https://github.com/ad-calcium/CVE-2023-22515)  

---

### [CVE-2023-22515](CVE-2023-22515-Chocapikk_CVE-2023-22515.md) 🔴 ✅

**名称:** CVE-2023-22515-Atlassian Confluence-Broken Access Control  
**类型:** Broken Access Control  
**风险:** 高危，允许未授权用户创建管理员账户并访问Confluence实例  
**投毒风险:** 1%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2023-22515](https://github.com/Chocapikk/CVE-2023-22515)  

---

### [CVE-2023-22515](CVE-2023-22515-youcannotseemeagain_CVE-2023-22515_RCE.md) 🔴 ✅

**名称:** CVE-2023-22515-Atlassian Confluence Broken Access Control  
**类型:** Broken Access Control  
**风险:** 高危，允许未经身份验证的远程攻击者创建管理员帐户并完全控制Confluence实例  
**投毒风险:** 20%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2023-22515_RCE](https://github.com/youcannotseemeagain/CVE-2023-22515_RCE)  

---

### [CVE-2023-22515](CVE-2023-22515-DsaHen_cve-2023-22515-exp.md) 🔴 ✅

**名称:** CVE-2023-22515-Confluence-Broken Access Control  
**类型:** Broken Access Control  
**风险:** 高危，未经身份验证的攻击者可以创建 Confluence 管理员帐户并访问 Confluence 实例  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [cve-2023-22515-exp](https://github.com/DsaHen/cve-2023-22515-exp)  

---

### [CVE-2023-22515](CVE-2023-22515-sincere9_CVE-2023-22515.md) 🔴 ✅

**名称:** CVE-2023-22515-Confluence-Broken Access Control  
**类型:** Broken Access Control  
**风险:** 高危，允许未授权用户创建管理员账户，完全控制Confluence实例  
**投毒风险:** 1%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2023-22515](https://github.com/sincere9/CVE-2023-22515)  

---

### [CVE-2023-22515](CVE-2023-22515-aaaademo_Confluence-EvilJar.md) 🔴 ✅

**名称:** CVE-2023-22515-Confluence-Broken Access Control  
**类型:** Broken Access Control/RCE  
**风险:** 高危，可导致未授权访问和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [Confluence-EvilJar](https://github.com/aaaademo/Confluence-EvilJar)  

---

### [CVE-2023-22515](CVE-2023-22515-AIex-3_confluence-hack.md) 🔴 ✅

**名称:** CVE-2023-22515-Atlassian Confluence Broken Access Control  
**类型:** Broken Access Control  
**风险:** 高危，允许未经身份验证的攻击者创建管理员账户并完全控制 Confluence 实例  
**投毒风险:** 20%  
**发现时间:** 2025-04-18  
**POC仓库:** [confluence-hack](https://github.com/AIex-3/confluence-hack)  

---

### [CVE-2023-22515](CVE-2023-22515-joaoviictorti_CVE-2023-22515.md) 🔴 ✅

**名称:** CVE-2023-22515-Atlassian Confluence-Broken Access Control  
**类型:** Broken Access Control  
**风险:** 高危，允许未经身份验证的攻击者创建Confluence管理员账户，进而可能导致完全控制Confluence实例。  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2023-22515](https://github.com/joaoviictorti/CVE-2023-22515)  

---

### [CVE-2023-22515](CVE-2023-22515-edsonjt81_CVE-2023-22515-Scan..md) 🔴 ✅

**名称:** CVE-2023-22515-Atlassian Confluence-Broken Access Control  
**类型:** Broken Access Control  
**风险:** 高危，未经身份验证的远程攻击者可以创建 Confluence 管理员帐户并访问 Confluence 实例  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2023-22515-Scan.](https://github.com/edsonjt81/CVE-2023-22515-Scan.)  

---

### [CVE-2023-22515](CVE-2023-22515-INTfinityConsulting_cve-2023-22515.md)  ✅

**名称:** CVE-2023-22515 - Confluence 破损的访问控制  
**类型:** 破损的访问控制  
**风险:** 严重，允许未授权的远程攻击者创建 Confluence 管理员账户并访问 Confluence 实例，最终导致远程代码执行。  
**投毒风险:** 20%  
**发现时间:** 2025-04-18  
**POC仓库:** [cve-2023-22515](https://github.com/INTfinityConsulting/cve-2023-22515)  

---

### [CVE-2023-22515](CVE-2023-22515-C1ph3rX13_CVE-2023-22515.md) 🔴 ✅

**名称:** CVE-2023-22515-Confluence-Broken Access Control  
**类型:** Broken Access Control  
**风险:** Critical，未经身份验证的远程攻击者可以创建 Confluence 管理员账户并访问 Confluence 实例。  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2023-22515](https://github.com/C1ph3rX13/CVE-2023-22515)  

---

### [CVE-2023-22515](CVE-2023-22515-CalegariMindSec_Exploit-CVE-2023-22515.md) 🔴 ✅

**名称:** CVE-2023-22515-Atlassian Confluence Broken Access Control  
**类型:** Broken Access Control  
**风险:** 高危，允许未经身份验证的远程攻击者创建管理员账户并完全控制Confluence实例  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [Exploit-CVE-2023-22515](https://github.com/CalegariMindSec/Exploit-CVE-2023-22515)  

---

### [CVE-2023-22515](CVE-2023-22515-fyx1t_NSE--CVE-2023-22515.md) 🔴 ✅

**名称:** CVE-2023-22515-Confluence-Broken Access Control  
**类型:** Broken Access Control  
**风险:** 高危，允许未经身份验证的远程攻击者创建 Confluence 管理员帐户，并完全控制 Confluence 实例。  
**投毒风险:** 0%  
**发现时间:** 2025-04-18  
**POC仓库:** [NSE--CVE-2023-22515](https://github.com/fyx1t/NSE--CVE-2023-22515)  

---

### [CVE-2023-22515](CVE-2023-22515-kh4sh3i_CVE-2023-22515.md)  ✅

**名称:** CVE-2023-22515 Atlassian Confluence 权限提升  
**类型:** 权限提升/Broken Access Control  
**风险:** 严重，未授权的攻击者可以创建管理员账户并访问 Confluence 实例  
**投毒风险:** 0%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2023-22515](https://github.com/kh4sh3i/CVE-2023-22515)  

---

### [CVE-2023-22515](CVE-2023-22515-xorbbo_cve-2023-22515.md) 🔴 ✅

**名称:** CVE-2023-22515 - Atlassian Confluence Broken Access Control  
**类型:** Broken Access Control  
**风险:** 高危，允许未授权用户创建管理员账户，可能导致完全控制 Confluence 实例  
**投毒风险:** 5%  
**发现时间:** 2025-04-18  
**POC仓库:** [cve-2023-22515](https://github.com/xorbbo/cve-2023-22515)  

---

### [CVE-2023-22515](CVE-2023-22515-s1d6point7bugcrowd_CVE-2023-22515-check.md) 🔴 ✅

**名称:** CVE-2023-22515 Atlassian Confluence 破损的访问控制  
**类型:** 破损的访问控制  
**风险:** 高危，可能导致未授权管理员账户创建和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2023-22515-check](https://github.com/s1d6point7bugcrowd/CVE-2023-22515-check)  

---

### [CVE-2023-22515](CVE-2023-22515-LucasPDiniz_CVE-2023-22515.md) 🔴 ✅

**名称:** CVE-2023-22515 - Atlassian Confluence Broken Access Control  
**类型:** Broken Access Control  
**风险:** 高危，允许未授权用户创建管理员账户并完全控制Confluence实例  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2023-22515](https://github.com/LucasPDiniz/CVE-2023-22515)  

---

### [CVE-2023-22515](CVE-2023-22515-spareack_CVE-2023-22515-NSE.md) 🔴 ✅

**名称:** CVE-2023-22515-Atlassian Confluence Broken Access Control  
**类型:** Broken Access Control  
**风险:** 高危，可能导致未经授权的管理员账户创建和系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2023-22515-NSE](https://github.com/spareack/CVE-2023-22515-NSE)  

---

### [CVE-2023-22515](CVE-2023-22515-Onedy1703_CVE-2023-22515-Confluence.md) 🔴 ✅

**名称:** CVE-2023-22515-Atlassian Confluence Broken Access Control  
**类型:** Broken Access Control  
**风险:** 高危，可创建未授权的管理员账户，完全控制Confluence实例  
**投毒风险:** 5%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2023-22515-Confluence](https://github.com/Onedy1703/CVE-2023-22515-Confluence)  

---

### [CVE-2023-22515](CVE-2023-22515-vivigotnotime_CVE-2023-22515-Exploit-Script.md)  ✅

**名称:** CVE-2023-22515 - Atlassian Confluence Broken Access Control  
**类型:** Broken Access Control  
**风险:** 严重，允许未经身份验证的攻击者创建管理员帐户并完全控制受影响的实例  
**投毒风险:** 5%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2023-22515-Exploit-Script](https://github.com/vivigotnotime/CVE-2023-22515-Exploit-Script)  

---

### [CVE-2023-22515](CVE-2023-22515-rxerium_CVE-2023-22515.md) 🔴 ✅

**名称:** CVE-2023-22515 - Atlassian Confluence 权限绕过/未授权管理员创建  
**类型:** 权限绕过/未授权访问  
**风险:** 高危，允许未授权用户创建管理员账户并完全控制Confluence实例  
**投毒风险:** 5%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2023-22515](https://github.com/rxerium/CVE-2023-22515)  

---

### [CVE-2024-7593](CVE-2024-7593-D3N14LD15K_CVE-2024-7593_PoC_Exploit.md) 🔴 ✅

**名称:** CVE-2024-7593 - Ivanti vTM Authentication Bypass  
**类型:** Authentication Bypass  
**风险:** Critical，允许未授权的远程攻击者绕过身份验证并创建管理员帐户。  
**投毒风险:** 0%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2024-7593_PoC_Exploit](https://github.com/D3N14LD15K/CVE-2024-7593_PoC_Exploit)  

---

### [CVE-2024-7593](CVE-2024-7593-0xlf_CVE-2024-7593.md)  ✅

**名称:** CVE-2024-7593 - Ivanti vTM Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 严重，可能导致完全控制受影响的服务器  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2024-7593](https://github.com/0xlf/CVE-2024-7593)  

---

### [CVE-2024-7593](CVE-2024-7593-rxerium_CVE-2024-7593.md) 🔴 ✅

**名称:** CVE-2024-7593-Ivanti Virtual Traffic Manager Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致完全控制系统  
**投毒风险:** 0%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2024-7593](https://github.com/rxerium/CVE-2024-7593)  

---

### [CVE-2022-24086](CVE-2022-24086-nanaao_CVE-2022-24086-RCE.md) 🔴 ✅

**名称:** CVE-2022-24086-Magento-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2022-24086-RCE](https://github.com/nanaao/CVE-2022-24086-RCE)  

---

### [CVE-2022-24086](CVE-2022-24086-NHPT_CVE-2022-24086-RCE.md) 🔴 ✅

**名称:** CVE-2022-24086-Magento-RCE  
**类型:** 远程代码执行(RCE)  
**风险:** 高危，未授权的远程代码执行  
**投毒风险:** 70%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2022-24086-RCE](https://github.com/NHPT/CVE-2022-24086-RCE)  

---

### [CVE-2022-24086](CVE-2022-24086-seymanurmutlu_CVE-2022-24086-CVE-2022-24087.md)  ✅

**名称:** CVE-2022-24086-Adobe Commerce (Magento) 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，未授权远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2022-24086-CVE-2022-24087](https://github.com/seymanurmutlu/CVE-2022-24086-CVE-2022-24087)  

---

### [CVE-2022-24086](CVE-2022-24086-oK0mo_CVE-2022-24086-RCE-PoC.md) 🔴 ✅

**名称:** CVE-2022-24086 Adobe Commerce (Magento) 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 30%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2022-24086-RCE-PoC](https://github.com/oK0mo/CVE-2022-24086-RCE-PoC)  

---

### [CVE-2022-24086](CVE-2022-24086-akr3ch_CVE-2022-24086.md) 🔴 ✅

**名称:** CVE-2022-24086-Magento-RCE  
**类型:** 远程代码执行（RCE）  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2022-24086](https://github.com/akr3ch/CVE-2022-24086)  

---

### [CVE-2022-24086](CVE-2022-24086-Mr-xn_CVE-2022-24086.md) 🔴 ✅

**名称:** CVE-2022-24086-Adobe Commerce (Magento)-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致完全控制受影响的服务器  
**投毒风险:** 0%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2022-24086](https://github.com/Mr-xn/CVE-2022-24086)  

---

### [CVE-2022-24086](CVE-2022-24086-pescepilota_CVE-2022-24086.md) 🔴 ✅

**名称:** CVE-2022-24086-Magento-RCE  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2022-24086](https://github.com/pescepilota/CVE-2022-24086)  

---

### [CVE-2022-24086](CVE-2022-24086-BurpRoot_CVE-2022-24086.md)  ✅

**名称:** CVE-2022-24086-Magento-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致完全系统控制  
**投毒风险:** 5%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2022-24086](https://github.com/BurpRoot/CVE-2022-24086)  

---

### [CVE-2022-24086](CVE-2022-24086-wubinworks_magento2-template-filter-patch.md) 🔴 ✅

**名称:** CVE-2022-24086-Magento-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-18  
**POC仓库:** [magento2-template-filter-patch](https://github.com/wubinworks/magento2-template-filter-patch)  

---

### [CVE-2022-24086](CVE-2022-24086-rxerium_CVE-2022-24086.md) 🔴 

**名称:** CVE-2022-24086-Magento-RCE  
**类型:** 远程代码执行（RCE）  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2022-24086](https://github.com/rxerium/CVE-2022-24086)  

---

### [CVE-2025-28355](CVE-2025-28355-abbisQQ_CVE-2025-28355.md) 🟡 ✅

**名称:** CVE-2025-28355 - personal-management-system CSRF  
**类型:** CSRF (跨站请求伪造)  
**风险:** 中危，允许攻击者在未经授权的情况下更改用户密码，控制用户帐户  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2025-28355](https://github.com/abbisQQ/CVE-2025-28355)  

---

### [CVE-2018-25031](CVE-2018-25031-kriso4os_CVE-2018-25031.md) 🟡 ✅

**名称:** CVE-2018-25031-Swagger UI-远程OpenAPI定义显示欺骗/XSS  
**类型:** 欺骗/跨站脚本攻击 (Spoofing/XSS)  
**风险:** 中危，可能导致信息泄露和恶意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2018-25031](https://github.com/kriso4os/CVE-2018-25031)  

---

### [CVE-2018-25031](CVE-2018-25031-rafaelcintralopes_SwaggerUI-CVE-2018-25031.md) 🟡 ✅

**名称:** CVE-2018-25031-Swagger UI-UI Misrepresentation of Critical Information  
**类型:** UI Misrepresentation of Critical Information (Spoofing)  
**风险:** 中危，可能导致用户信任被欺骗的API定义，进而遭受钓鱼攻击或其他恶意行为。  
**投毒风险:** 0%  
**发现时间:** 2025-04-18  
**POC仓库:** [SwaggerUI-CVE-2018-25031](https://github.com/rafaelcintralopes/SwaggerUI-CVE-2018-25031)  

---

### [CVE-2018-25031](CVE-2018-25031-LUCASRENAA_CVE-2018-25031.md) 🟡 ✅

**名称:** CVE-2018-25031-Swagger UI-跨站脚本攻击  
**类型:** 跨站脚本攻击 (XSS)  
**风险:** 中危，可能导致信息泄露、会话劫持等  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2018-25031](https://github.com/LUCASRENAA/CVE-2018-25031)  

---

### [CVE-2018-25031](CVE-2018-25031-wrkk112_CVE-2018-25031.md) 🟡 ✅

**名称:** CVE-2018-25031 - Swagger UI Spoofing  
**类型:** 欺骗/SSRF/XSS  
**风险:** 中危，可能导致信息泄露和XSS攻击  
**投毒风险:** 0%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2018-25031](https://github.com/wrkk112/CVE-2018-25031)  

---

### [CVE-2018-25031](CVE-2018-25031-hev0x_CVE-2018-25031-PoC.md) 🟡 ✅

**名称:** CVE-2018-25031-Swagger UI-远程OpenAPI定义欺骗  
**类型:** 欺骗/SSRF/XSS  
**风险:** 中危，可能导致信息泄露和XSS攻击  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2018-25031-PoC](https://github.com/hev0x/CVE-2018-25031-PoC)  

---

### [CVE-2018-25031](CVE-2018-25031-johnlaurance_CVE-2018-25031-test2.md) 🟡 ✅

**名称:** CVE-2018-25031-Swagger UI Spoofing/SSRF/XSS  
**类型:** 欺骗/SSRF/XSS  
**风险:** 中危，可能导致敏感信息泄露或恶意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2018-25031-test2](https://github.com/johnlaurance/CVE-2018-25031-test2)  

---

### [CVE-2018-25031](CVE-2018-25031-afine-com_CVE-2018-25031.md) 🟡 ✅

**名称:** CVE-2018-25031 - Swagger UI Spoofing  
**类型:** 欺骗攻击 (Spoofing)  
**风险:** 中危，可能导致信息泄露和用户误导  
**投毒风险:** 5%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2018-25031](https://github.com/afine-com/CVE-2018-25031)  

---

### [CVE-2018-25031](CVE-2018-25031-geozin_POC-CVE-2018-25031.md) 🟡 ✅

**名称:** CVE-2018-25031-Swagger UI-信息泄露/欺骗  
**类型:** 信息泄露/欺骗 (Spoofing)  
**风险:** 中危，可能导致敏感信息泄露和用户欺骗  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [POC-CVE-2018-25031](https://github.com/geozin/POC-CVE-2018-25031)  

---

### [CVE-2018-25031](CVE-2018-25031-h2oa_CVE-2018-25031.md) 🟡 ✅

**名称:** CVE-2018-25031-Swagger UI-SSRF/Spoofing  
**类型:** SSRF/欺骗  
**风险:** 中危，可能导致信息泄露和欺骗攻击  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2018-25031](https://github.com/h2oa/CVE-2018-25031)  

---

### [CVE-2018-25031](CVE-2018-25031-natpakun_SSRF-CVE-2018-25031-.md) 🟡 ✅

**名称:** CVE-2018-25031 - Swagger UI SSRF/Spoofing  
**类型:** SSRF/欺骗攻击  
**风险:** 中危，可能导致敏感信息泄露或重定向到恶意API定义  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [SSRF-CVE-2018-25031-](https://github.com/natpakun/SSRF-CVE-2018-25031-)  

---

### [CVE-2018-25031](CVE-2018-25031-KonEch0_CVE-2018-25031-SG.md) 🟡 ✅

**名称:** CVE-2018-25031 - Swagger UI Spoofing  
**类型:** 欺骗攻击 (Spoofing)  
**风险:** 中危，可能导致用户被引导至恶意API定义，进而造成信息泄露或其他安全风险  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2018-25031-SG](https://github.com/KonEch0/CVE-2018-25031-SG)  

---

### [CVE-2018-25031](CVE-2018-25031-mathis2001_CVE-2018-25031.md) 🟡 ✅

**名称:** CVE-2018-25031-Swagger UI-欺骗攻击  
**类型:** 欺骗攻击/SSRF/XSS  
**风险:** 中危，可能导致信息泄露和恶意代码执行  
**投毒风险:** 60%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2018-25031](https://github.com/mathis2001/CVE-2018-25031)  

---

### [CVE-2018-25031](CVE-2018-25031-nigartest_CVE-2018-25031.md) 🟡 ✅

**名称:** CVE-2018-25031-Swagger UI-远程OpenAPI定义显示漏洞  
**类型:** 欺骗/跨站脚本 (Spoofing/XSS)  
**风险:** 中危，可能导致信息泄露和恶意脚本执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2018-25031](https://github.com/nigartest/CVE-2018-25031)  

---

### [CVE-2025-29927](CVE-2025-29927-Grand-Moomin_Vuln-Next.js-CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-中间件授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问敏感数据或执行敏感操作  
**投毒风险:** 0%  
**发现时间:** 2025-04-18  
**POC仓库:** [Vuln-Next.js-CVE-2025-29927](https://github.com/Grand-Moomin/Vuln-Next.js-CVE-2025-29927)  

---

### [CVE-2025-32433](CVE-2025-32433-ProDefense_CVE-2025-32433.md) 🔴 ✅

**名称:** CVE-2025-32433-Erlang/OTP-SSH未授权RCE  
**类型:** 未授权远程代码执行  
**风险:** 高危，可导致完全控制目标系统  
**投毒风险:** 5%  
**发现时间:** 2025-04-18  
**POC仓库:** [CVE-2025-32433](https://github.com/ProDefense/CVE-2025-32433)  

---

### [CVE-2024-45436](CVE-2024-45436-XiaomingX_cve-2024-45436-exp.md) 🔴 ✅

**名称:** CVE-2024-45436-Ollama-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致任意文件写入  
**投毒风险:** 0%  
**发现时间:** 2025-04-17  
**POC仓库:** [cve-2024-45436-exp](https://github.com/XiaomingX/cve-2024-45436-exp)  

---

### [CVE-2024-45436](CVE-2024-45436-srcx404_CVE-2024-45436.md) 🔴 ✅

**名称:** CVE-2024-45436-Ollama-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致任意文件写入和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-17  
**POC仓库:** [CVE-2024-45436](https://github.com/srcx404/CVE-2024-45436)  

---

### [CVE-2023-27163](CVE-2023-27163-seanrdev_cve-2023-27163.md) 🟡 ✅

**名称:** CVE-2023-27163-Request-Baskets-SSRF  
**类型:** SSRF (服务器端请求伪造)  
**风险:** 中危，可能导致内部信息泄露和访问内部服务  
**投毒风险:** 0%  
**发现时间:** 2025-04-17  
**POC仓库:** [cve-2023-27163](https://github.com/seanrdev/cve-2023-27163)  

---

### [CVE-2023-27163](CVE-2023-27163-madhavmehndiratta_CVE-2023-27163.md) 🔴 ✅

**名称:** CVE-2023-27163-Request-Baskets-SSRF  
**类型:** SSRF (服务器端请求伪造)  
**风险:** 高危，可能导致敏感信息泄露和内网访问  
**投毒风险:** 0%  
**发现时间:** 2025-04-17  
**POC仓库:** [CVE-2023-27163](https://github.com/madhavmehndiratta/CVE-2023-27163)  

---

### [CVE-2023-27163](CVE-2023-27163-overgrowncarrot1_CVE-2023-27163.md) 🟡 ✅

**名称:** CVE-2023-27163 - Request Baskets SSRF  
**类型:** 服务器端请求伪造 (SSRF)  
**风险:** 中危，可能导致访问内部网络资源和敏感信息  
**投毒风险:** 0%  
**发现时间:** 2025-04-17  
**POC仓库:** [CVE-2023-27163](https://github.com/overgrowncarrot1/CVE-2023-27163)  

---

### [CVE-2023-27163](CVE-2023-27163-ThickCoco_CVE-2023-27163-POC.md) 🟡 ✅

**名称:** CVE-2023-27163-Request-Baskets-SSRF  
**类型:** 服务器端请求伪造 (SSRF)  
**风险:** 中危，可能导致敏感信息泄露和内部网络访问  
**投毒风险:** 5%  
**发现时间:** 2025-04-17  
**POC仓库:** [CVE-2023-27163-POC](https://github.com/ThickCoco/CVE-2023-27163-POC)  

---

### [CVE-2023-27163](CVE-2023-27163-davuXVI_CVE-2023-27163.md) 🔴 ✅

**名称:** CVE-2023-27163-Request-Baskets-SSRF  
**类型:** SSRF (服务器端请求伪造)  
**风险:** 高危，可能导致内部网络信息泄露、敏感信息访问，甚至远程代码执行。  
**投毒风险:** 10%  
**发现时间:** 2025-04-17  
**POC仓库:** [CVE-2023-27163](https://github.com/davuXVI/CVE-2023-27163)  

---

### [CVE-2023-27163](CVE-2023-27163-HusenjanDev_CVE-2023-27163-AND-Mailtrail-v0.53.md) 🔴 ✅

**名称:** CVE-2023-27163 - Request Baskets SSRF  
**类型:** SSRF (服务器端请求伪造)  
**风险:** 高危，可泄露内部信息，甚至可能造成远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-17  
**POC仓库:** [CVE-2023-27163-AND-Mailtrail-v0.53](https://github.com/HusenjanDev/CVE-2023-27163-AND-Mailtrail-v0.53)  

---

### [CVE-2023-27163](CVE-2023-27163-entr0pie_CVE-2023-27163.md) 🟡 ✅

**名称:** CVE-2023-27163-request-baskets-SSRF  
**类型:** 服务器端请求伪造 (SSRF)  
**风险:** 中危，可能允许攻击者访问内部网络资源和敏感信息  
**投毒风险:** 5%  
**发现时间:** 2025-04-17  
**POC仓库:** [CVE-2023-27163](https://github.com/entr0pie/CVE-2023-27163)  

---

### [CVE-2023-27163](CVE-2023-27163-rvizx_CVE-2023-27163.md) 🟡 ✅

**名称:** CVE-2023-27163 - Request Baskets SSRF  
**类型:** Server-Side Request Forgery (SSRF)  
**风险:** 中危，可能允许攻击者访问内部网络资源和敏感信息  
**投毒风险:** 0%  
**发现时间:** 2025-04-17  
**POC仓库:** [CVE-2023-27163](https://github.com/rvizx/CVE-2023-27163)  

---

### [CVE-2023-27163](CVE-2023-27163-cowsecurity_CVE-2023-27163.md) 🟡 ✅

**名称:** CVE-2023-27163-Request-Baskets-SSRF  
**类型:** SSRF (服务器端请求伪造)  
**风险:** 中危，可能导致敏感信息泄露和内网访问  
**投毒风险:** 1%  
**发现时间:** 2025-04-17  
**POC仓库:** [CVE-2023-27163](https://github.com/cowsecurity/CVE-2023-27163)  

---

### [CVE-2023-27163](CVE-2023-27163-thomas-osgood_CVE-2023-27163.md) 🟡 ✅

**名称:** CVE-2023-27163 - Request-Baskets SSRF  
**类型:** 服务器端请求伪造 (SSRF)  
**风险:** 中危，可能导致内部网络资源访问和敏感信息泄露  
**投毒风险:** 20%  
**发现时间:** 2025-04-17  
**POC仓库:** [CVE-2023-27163](https://github.com/thomas-osgood/CVE-2023-27163)  

---

### [CVE-2023-27163](CVE-2023-27163-samh4cks_CVE-2023-27163-InternalProber.md) 🟡 ✅

**名称:** CVE-2023-27163 Request-Baskets SSRF  
**类型:** 服务器端请求伪造 (SSRF)  
**风险:** 中危，可能允许攻击者访问内部网络资源  
**投毒风险:** 0%  
**发现时间:** 2025-04-17  
**POC仓库:** [CVE-2023-27163-InternalProber](https://github.com/samh4cks/CVE-2023-27163-InternalProber)  

---

### [CVE-2023-27163](CVE-2023-27163-Hamibubu_CVE-2023-27163.md) 🟡 ✅

**名称:** CVE-2023-27163-Request-Baskets-SSRF  
**类型:** SSRF (服务器端请求伪造)  
**风险:** 中危，可能导致敏感信息泄露和内网资源访问  
**投毒风险:** 10%  
**发现时间:** 2025-04-17  
**POC仓库:** [CVE-2023-27163](https://github.com/Hamibubu/CVE-2023-27163)  

---

### [CVE-2023-27163](CVE-2023-27163-KharimMchatta_basketcraft.md) 🟡 ✅

**名称:** CVE-2023-27163-Request-Baskets-SSRF  
**类型:** 服务器端请求伪造 (SSRF)  
**风险:** 中危，可能导致内部网络资源访问和敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-17  
**POC仓库:** [basketcraft](https://github.com/KharimMchatta/basketcraft)  

---

### [CVE-2023-27163](CVE-2023-27163-Rubioo02_CVE-2023-27163.md) 🟡 ✅

**名称:** CVE-2023-27163-Request-Baskets-SSRF  
**类型:** 服务器端请求伪造 (SSRF)  
**风险:** 中危，可能导致内部网络信息泄露，甚至通过间接方式进行攻击。  
**投毒风险:** 5%  
**发现时间:** 2025-04-17  
**POC仓库:** [CVE-2023-27163](https://github.com/Rubioo02/CVE-2023-27163)  

---

### [CVE-2023-27163](CVE-2023-27163-MasterCode112_CVE-2023-27163.md) 🟡 ✅

**名称:** CVE-2023-27163-Request-Baskets-SSRF  
**类型:** 服务器端请求伪造 (SSRF)  
**风险:** 中危，可能允许攻击者访问内部网络资源和敏感信息  
**投毒风险:** 10%  
**发现时间:** 2025-04-17  
**POC仓库:** [CVE-2023-27163](https://github.com/MasterCode112/CVE-2023-27163)  

---

### [CVE-2023-27163](CVE-2023-27163-Rishabh-Kumar-Cyber-Sec_CVE-2023-27163-ssrf-to-port-scanning.md) 🟡 ✅

**名称:** CVE-2023-27163-Request-Baskets-SSRF  
**类型:** SSRF  
**风险:** 中危，可能导致信息泄露和内部网络访问  
**投毒风险:** 0%  
**发现时间:** 2025-04-17  
**POC仓库:** [CVE-2023-27163-ssrf-to-port-scanning](https://github.com/Rishabh-Kumar-Cyber-Sec/CVE-2023-27163-ssrf-to-port-scanning)  

---

### [CVE-2023-27163](CVE-2023-27163-btar1gan_exploit_CVE-2023-27163.md) 🟡 ✅

**名称:** CVE-2023-27163-Request-Baskets-SSRF  
**类型:** SSRF (服务器端请求伪造)  
**风险:** 中危，可能导致敏感信息泄露，内网端口扫描，访问内部服务  
**投毒风险:** 10%  
**发现时间:** 2025-04-17  
**POC仓库:** [exploit_CVE-2023-27163](https://github.com/btar1gan/exploit_CVE-2023-27163)  

---

### [CVE-2023-27163](CVE-2023-27163-G4sp4rCS_htb-sau-automated.md) 🟡 ✅

**名称:** CVE-2023-27163-request-baskets-SSRF  
**类型:** SSRF (Server-Side Request Forgery)  
**风险:** 中危，可以允许攻击者访问内部网络资源和敏感信息，根据CVSS评分，需要较高权限才能利用。  
**投毒风险:** 0%  
**发现时间:** 2025-04-17  
**POC仓库:** [htb-sau-automated](https://github.com/G4sp4rCS/htb-sau-automated)  

---

### [CVE-2023-27163](CVE-2023-27163-lukehebe_CVE-2023-27163.md) 🔴 ✅

**名称:** CVE-2023-27163-request-baskets-SSRF  
**类型:** SSRF（服务器端请求伪造）  
**风险:** 中危，可升级为高危，可能导致内部网络信息泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-17  
**POC仓库:** [CVE-2023-27163](https://github.com/lukehebe/CVE-2023-27163)  

---

### [CVE-2025-41720](CVE-2025-41720-NotItsSixtyN3in_CVE-2025-4172026.md)  

**名称:** CVE-2025-4172026 (假)  
**类型:** 未知/欺骗  
**风险:** 低危（实际无风险）  
**投毒风险:** 95%  
**发现时间:** 2025-04-17  
**POC仓库:** [CVE-2025-4172026](https://github.com/NotItsSixtyN3in/CVE-2025-4172026)  

---

### [CVE-2025-41720](CVE-2025-41720-NotItsSixtyN3in_CVE-2025-4172025.md) 🔴 ✅

**名称:** CVE-2025-4172025 - Copilot Session Misassignment Vulnerability  
**类型:** 会话管理错误  
**风险:** 高危，可能导致未授权访问、数据泄露和权限提升  
**投毒风险:** 80%  
**发现时间:** 2025-04-17  
**POC仓库:** [CVE-2025-4172025](https://github.com/NotItsSixtyN3in/CVE-2025-4172025)  

---

### [CVE-2010-1938](CVE-2010-1938-Nexxus67_cve-2010-1938.md) 🔴 ✅

**名称:** CVE-2010-1938 libopie Off-by-One 漏洞  
**类型:** Off-by-One 缓冲区溢出  
**风险:** 高危，可能导致服务崩溃或远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-17  
**POC仓库:** [cve-2010-1938](https://github.com/Nexxus67/cve-2010-1938)  

---

### [CVE-2017-7529](CVE-2017-7529-liusec_CVE-2017-7529.md) 🟡 ✅

**名称:** CVE-2017-7529 - Nginx Range Filter Integer Overflow  
**类型:** 整数溢出导致的信息泄露  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-04-17  
**POC仓库:** [CVE-2017-7529](https://github.com/liusec/CVE-2017-7529)  

---

### [CVE-2025-3568](CVE-2025-3568-shellkraft_CVE-2025-3568.md) 🔴 ✅

**名称:** CVE-2025-3568-Webkul Krayin CRM SVG File edit cross site scripting  
**类型:** 跨站脚本攻击 (XSS)  
**风险:** 高危，可能导致管理员账户被劫持和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-17  
**POC仓库:** [CVE-2025-3568](https://github.com/shellkraft/CVE-2025-3568)  

---

### [CVE-2017-7529](CVE-2017-7529-en0f_CVE-2017-7529_PoC.md) 🟡 ✅

**名称:** CVE-2017-7529 - Nginx Range Filter Integer Overflow  
**类型:** Integer Overflow  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-17  
**POC仓库:** [CVE-2017-7529_PoC](https://github.com/en0f/CVE-2017-7529_PoC)  

---

### [CVE-2017-7529](CVE-2017-7529-MaxSecurity_CVE-2017-7529-POC.md) 🟡 ✅

**名称:** CVE-2017-7529-Nginx 整数溢出导致信息泄露  
**类型:** 整数溢出  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-04-17  
**POC仓库:** [CVE-2017-7529-POC](https://github.com/MaxSecurity/CVE-2017-7529-POC)  

---

### [CVE-2017-7529](CVE-2017-7529-cyberk1w1_CVE-2017-7529.md) 🟡 ✅

**名称:** CVE-2017-7529-Nginx-Integer Overflow  
**类型:** 整数溢出  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-17  
**POC仓库:** [CVE-2017-7529](https://github.com/cyberk1w1/CVE-2017-7529)  

---

### [CVE-2017-7529](CVE-2017-7529-cyberharsh_nginx-CVE-2017-7529.md) 🔴 ✅

**名称:** CVE-2017-7529-Nginx越界读取缓存漏洞  
**类型:** 整数溢出  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-17  
**POC仓库:** [nginx-CVE-2017-7529](https://github.com/cyberharsh/nginx-CVE-2017-7529)  

---

### [CVE-2017-7529](CVE-2017-7529-daehee_nginx-overflow.md) 🟡 ✅

**名称:** CVE-2017-7529-Nginx-Integer Overflow  
**类型:** 整数溢出  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-17  
**POC仓库:** [nginx-overflow](https://github.com/daehee/nginx-overflow)  

---

### [CVE-2017-7529](CVE-2017-7529-gemboxteam_exploit-nginx-1.10.3.md) 🟡 ✅

**名称:** CVE-2017-7529-Nginx-整数溢出  
**类型:** 整数溢出  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-17  
**POC仓库:** [exploit-nginx-1.10.3](https://github.com/gemboxteam/exploit-nginx-1.10.3)  

---

### [CVE-2017-7529](CVE-2017-7529-mo3zj_Nginx-Remote-Integer-Overflow-Vulnerability.md) 🟡 ✅

**名称:** CVE-2017-7529 - Nginx Range Filter Integer Overflow  
**类型:** Integer Overflow  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-17  
**POC仓库:** [Nginx-Remote-Integer-Overflow-Vulnerability](https://github.com/mo3zj/Nginx-Remote-Integer-Overflow-Vulnerability)  

---

### [CVE-2017-7529](CVE-2017-7529-cved-sources_cve-2017-7529.md) 🟡 ✅

**名称:** CVE-2017-7529-Nginx Range Filter Integer Overflow  
**类型:** 整数溢出  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-17  
**POC仓库:** [cve-2017-7529](https://github.com/cved-sources/cve-2017-7529)  

---

### [CVE-2017-7529](CVE-2017-7529-fardeen-ahmed_Remote-Integer-Overflow-Vulnerability.md) 🟡 ✅

**名称:** CVE-2017-7529 - Nginx Range Filter Integer Overflow  
**类型:** 整数溢出  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-17  
**POC仓库:** [Remote-Integer-Overflow-Vulnerability](https://github.com/fardeen-ahmed/Remote-Integer-Overflow-Vulnerability)  

---

### [CVE-2017-7529](CVE-2017-7529-fu2x2000_CVE-2017-7529-Nginx---Remote-Integer-Overflow-Exploit.md) 🟡 ✅

**名称:** CVE-2017-7529-Nginx-Integer Overflow  
**类型:** 整数溢出  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-17  
**POC仓库:** [CVE-2017-7529-Nginx---Remote-Integer-Overflow-Exploit](https://github.com/fu2x2000/CVE-2017-7529-Nginx---Remote-Integer-Overflow-Exploit)  

---

### [CVE-2017-7529](CVE-2017-7529-Shehzadcyber_CVE-2017-7529.md) 🟡 ✅

**名称:** CVE-2017-7529-Nginx Range Filter Integer Overflow  
**类型:** 整数溢出  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-17  
**POC仓库:** [CVE-2017-7529](https://github.com/Shehzadcyber/CVE-2017-7529)  

---

### [CVE-2017-7529](CVE-2017-7529-coolman6942o_-Exploit-CVE-2017-7529.md) 🟡 ✅

**名称:** CVE-2017-7529-Nginx Range Filter Integer Overflow  
**类型:** 整数溢出  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-17  
**POC仓库:** [-Exploit-CVE-2017-7529](https://github.com/coolman6942o/-Exploit-CVE-2017-7529)  

---

### [CVE-2017-7529](CVE-2017-7529-SirEagIe_CVE-2017-7529.md) 🟡 ✅

**名称:** CVE-2017-7529-Nginx范围过滤模块整数溢出  
**类型:** 整数溢出  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-04-17  
**POC仓库:** [CVE-2017-7529](https://github.com/SirEagIe/CVE-2017-7529)  

---

### [CVE-2017-7529](CVE-2017-7529-CalebFIN_EXP-CVE-2017-75.md) 🟡 ✅

**名称:** CVE-2017-7529-Nginx-Integer Overflow  
**类型:** 整数溢出  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-04-17  
**POC仓库:** [EXP-CVE-2017-75](https://github.com/CalebFIN/EXP-CVE-2017-75)  

---

### [CVE-2017-7529](CVE-2017-7529-Fenil2511_CVE-2017-7529-POC.md) 🟡 ✅

**名称:** CVE-2017-7529-Nginx Range Filter Integer Overflow  
**类型:** 整数溢出  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-17  
**POC仓库:** [CVE-2017-7529-POC](https://github.com/Fenil2511/CVE-2017-7529-POC)  

---

### [CVE-2017-7529](CVE-2017-7529-youngmin0104_CVE-2017-7529-.md) 🟡 ✅

**名称:** CVE-2017-7529-Nginx Range Header Integer Overflow  
**类型:** 整数溢出导致的信息泄露  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-17  
**POC仓库:** [CVE-2017-7529-](https://github.com/youngmin0104/CVE-2017-7529-)  

---

### [CVE-2025-29306](CVE-2025-29306-verylazytech_CVE-2025-29306.md) 🔴 ✅

**名称:** CVE-2025-29306-FoxCMS-代码执行  
**类型:** 代码执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-17  
**POC仓库:** [CVE-2025-29306](https://github.com/verylazytech/CVE-2025-29306)  

---

### [CVE-2025-29927](CVE-2025-29927-enochgitgamefied_NextJS-CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js Middleware Authorization Bypass  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-17  
**POC仓库:** [NextJS-CVE-2025-29927](https://github.com/enochgitgamefied/NextJS-CVE-2025-29927)  

---

### [CVE-2025-28009](CVE-2025-28009-beardenx_CVE-2025-28009.md) 🔴 ✅

**名称:** CVE-2025-28009 - Dietiqa App v1.0.20 SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和数据篡改  
**投毒风险:** 5%  
**发现时间:** 2025-04-17  
**POC仓库:** [CVE-2025-28009](https://github.com/beardenx/CVE-2025-28009)  

---

### [CVE-2025-44202](CVE-2025-44202-joey-melo_CVE-2025-442025.md) 🔴 ✅

**名称:** CVE-2025-442025-SecureVPN-Account Takeover  
**类型:** Account Takeover  
**风险:** 高危，可能导致敏感数据泄露和用户隐私泄露  
**投毒风险:** 60%  
**发现时间:** 2025-04-17  
**POC仓库:** [CVE-2025-442025](https://github.com/joey-melo/CVE-2025-442025)  

---

### [CVE-2024-13869](CVE-2024-13869-d0n601_CVE-2024-13869.md) 🔴 ✅

**名称:** CVE-2024-13869-WPvivid-Arbitrary File Upload  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2024-13869](https://github.com/d0n601/CVE-2024-13869)  

---

### [CVE-2025-41620](CVE-2025-41620-NotItsSixtyN3in_CVE-2025-4162025.md) 🔴 ✅

**名称:** CVE-2025-4162025 - Copilot 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未经授权的访问、数据泄露和账户劫持  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2025-4162025](https://github.com/NotItsSixtyN3in/CVE-2025-4162025)  

---

### [CVE-2025-41620](CVE-2025-41620-NotItsSixtyN3in_CVE-2025-4162026.md) 🔴 ✅

**名称:** CVE-2025-4162026-Copilot-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致数据泄露和帐户接管  
**投毒风险:** 5%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2025-4162026](https://github.com/NotItsSixtyN3in/CVE-2025-4162026)  

---

### [CVE-2025-41620](CVE-2025-41620-NotItsSixtyN3in_CVE-2025-4162027.md) 🔴 ✅

**名称:** CVE-2025-4162027-Copilot-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致数据泄露、账户劫持和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2025-4162027](https://github.com/NotItsSixtyN3in/CVE-2025-4162027)  

---

### [CVE-2025-41620](CVE-2025-41620-NotItsSixtyN3in_CVE-2025-4162028.md) 🔴 ✅

**名称:** CVE-2025-4162028-Copilot-Authentication Vulnerability  
**类型:** Authentication Vulnerability  
**风险:** 高危，可能导致 unauthorized account access, data exposure, privilege escalation, and session hijacking  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2025-4162028](https://github.com/NotItsSixtyN3in/CVE-2025-4162028)  

---

### [CVE-2025-41620](CVE-2025-41620-NotItsSixtyN3in_CVE-2025-4162029.md) 🔴 ✅

**名称:** CVE-2025-4162029-Copilot-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致数据泄露、权限提升和账户劫持  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2025-4162029](https://github.com/NotItsSixtyN3in/CVE-2025-4162029)  

---

### [CVE-2025-41620](CVE-2025-41620-NotItsSixtyN3in_CVE-2025-4162030.md) 🔴 ✅

**名称:** CVE-2025-4162030-Copilot-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致数据泄露、权限提升和账户接管  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2025-4162030](https://github.com/NotItsSixtyN3in/CVE-2025-4162030)  

---

### [CVE-2025-24797](CVE-2025-24797-Alainx277_CVE-2025-24797.md) 🔴 ✅

**名称:** CVE-2025-24797-Meshtastic-缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2025-24797](https://github.com/Alainx277/CVE-2025-24797)  

---

### [CVE-2018-14847](CVE-2018-14847-syrex1013_MikroRoot.md) 🔴 ✅

**名称:** CVE-2018-14847-MikroTik RouterOS-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [MikroRoot](https://github.com/syrex1013/MikroRoot)  

---

### [CVE-2018-14847](CVE-2018-14847-msterusky_WinboxExploit.md) 🔴 ✅

**名称:** CVE-2018-14847-MikroTik RouterOS-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露或任意文件读写  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [WinboxExploit](https://github.com/msterusky/WinboxExploit)  

---

### [CVE-2018-14847](CVE-2018-14847-jas502n_CVE-2018-14847.md) 🔴 ✅

**名称:** CVE-2018-14847 - MikroTik RouterOS WinBox Directory Traversal  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露或任意文件写入  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2018-14847](https://github.com/jas502n/CVE-2018-14847)  

---

### [CVE-2018-14847](CVE-2018-14847-Tr33-He11_winboxPOC.md) 🔴 ✅

**名称:** CVE-2018-14847-MikroTik RouterOS WinBox目录遍历  
**类型:** 目录遍历  
**风险:** 高危，允许未授权远程读取任意文件，授权远程写入任意文件  
**投毒风险:** 0%  
**发现时间:** 2025-04-16  
**POC仓库:** [winboxPOC](https://github.com/Tr33-He11/winboxPOC)  

---

### [CVE-2018-14847](CVE-2018-14847-mahmoodsabir_mikrotik-beast.md) 🔴 ✅

**名称:** CVE-2018-14847 - MikroTik RouterOS WinBox Directory Traversal  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行（通过写入恶意文件）  
**投毒风险:** 5%  
**发现时间:** 2025-04-16  
**POC仓库:** [mikrotik-beast](https://github.com/mahmoodsabir/mikrotik-beast)  

---

### [CVE-2018-14847](CVE-2018-14847-sinichi449_Python-MikrotikLoginExploit.md) 🔴 ✅

**名称:** CVE-2018-14847-MikroTik RouterOS-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露和任意文件读写  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [Python-MikrotikLoginExploit](https://github.com/sinichi449/Python-MikrotikLoginExploit)  

---

### [CVE-2018-14847](CVE-2018-14847-yukar1z0e_CVE-2018-14847.md) 🔴 ✅

**名称:** CVE-2018-14847-MikroTik RouterOS 目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2018-14847](https://github.com/yukar1z0e/CVE-2018-14847)  

---

### [CVE-2018-14847](CVE-2018-14847-BasuCert_WinboxPoC.md) 🔴 ✅

**名称:** CVE-2018-14847-MikroTik RouterOS-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致任意文件读取和写入  
**投毒风险:** 0%  
**发现时间:** 2025-04-16  
**POC仓库:** [WinboxPoC](https://github.com/BasuCert/WinboxPoC)  

---

### [CVE-2018-14847](CVE-2018-14847-hacker30468_Mikrotik-router-hack.md) 🔴 ✅

**名称:** CVE-2018-14847-MikroTik RouterOS-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行（取决于权限）  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [Mikrotik-router-hack](https://github.com/hacker30468/Mikrotik-router-hack)  

---

### [CVE-2018-14847](CVE-2018-14847-babyshen_routeros-CVE-2018-14847-bytheway.md) 🔴 ✅

**名称:** CVE-2018-14847-MikroTik RouterOS-目录遍历  
**类型:** 目录遍历  
**风险:** 高危，可能导致信息泄露和远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-16  
**POC仓库:** [routeros-CVE-2018-14847-bytheway](https://github.com/babyshen/routeros-CVE-2018-14847-bytheway)  

---

### [CVE-2018-14847](CVE-2018-14847-K3ysTr0K3R_CVE-2018-14847-EXPLOIT.md) 🔴 ✅

**名称:** CVE-2018-14847 - MikroTik RouterOS WinBox 目录遍历漏洞  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行（通过写入文件）  
**投毒风险:** 5%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2018-14847-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2018-14847-EXPLOIT)  

---

### [CVE-2018-14847](CVE-2018-14847-tausifzaman_CVE-2018-14847.md) 🔴 ✅

**名称:** CVE-2018-14847 - MikroTik RouterOS WinBox 目录遍历漏洞  
**类型:** 目录遍历  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行（基于信息泄露）  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2018-14847](https://github.com/tausifzaman/CVE-2018-14847)  

---

### [CVE-2025-26244](CVE-2025-26244-JaRm222_CVE-2025-26244.md) 🔴 ✅

**名称:** CVE-2025-26244-DeimosC2-XSS  
**类型:** 跨站脚本攻击 (XSS)  
**风险:** 高危，可能导致Cookie窃取和账户劫持  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2025-26244](https://github.com/JaRm222/CVE-2025-26244)  

---

### [CVE-2025-30727](CVE-2025-30727-HExploited_CVE-2025-30727-Exploit.md)  

**名称:** CVE-2025-30727-Oracle Scripting iSurvey Module-未经身份验证的远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致系统完全接管  
**投毒风险:** 95%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2025-30727-Exploit](https://github.com/HExploited/CVE-2025-30727-Exploit)  

---

### [CVE-2018-17229](CVE-2018-17229-zeeshangondal_c-cpp_CVE-2018-17229.md) 🔴 ✅

**名称:** CVE-2018-17229-Exiv2-堆缓冲区溢出  
**类型:** 堆缓冲区溢出  
**风险:** 高危，可能导致拒绝服务或代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-16  
**POC仓库:** [c-cpp_CVE-2018-17229](https://github.com/zeeshangondal/c-cpp_CVE-2018-17229)  

---

### [CVE-2024-23346](CVE-2024-23346-MAWK0235_CVE-2024-23346.md) 🔴 ✅

**名称:** CVE-2024-23346-pymatgen-代码注入  
**类型:** 代码注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2024-23346](https://github.com/MAWK0235/CVE-2024-23346)  

---

### [CVE-2024-23346](CVE-2024-23346-szyth_CVE-2024-23346-rust-exploit.md) 🔴 ✅

**名称:** CVE-2024-23346-pymatgen-代码执行  
**类型:** 代码执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2024-23346-rust-exploit](https://github.com/szyth/CVE-2024-23346-rust-exploit)  

---

### [CVE-2024-23346](CVE-2024-23346-9carlo6_CVE-2024-23346.md) 🔴 ✅

**名称:** CVE-2024-23346-pymatgen-代码注入  
**类型:** 代码注入  
**风险:** 高危，可执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2024-23346](https://github.com/9carlo6/CVE-2024-23346)  

---

### [CVE-2024-23346](CVE-2024-23346-Sanity-Archive_CVE-2024-23346.md) 🔴 ✅

**名称:** CVE-2024-23346-pymatgen-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2024-23346](https://github.com/Sanity-Archive/CVE-2024-23346)  

---

### [CVE-2025-39601](CVE-2025-39601-Nxploited_CVE-2025-39601.md) 🔴 ✅

**名称:** CVE-2025-39601 - WordPress Custom CSS, JS & PHP plugin CSRF to RCE  
**类型:** CSRF to RCE  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2025-39601](https://github.com/Nxploited/CVE-2025-39601)  

---

### [CVE-2024-3094](CVE-2024-3094-iheb2b_CVE-2024-3094-Checker.md)  ✅

**名称:** CVE-2024-3094 XZ Utils Backdoor  
**类型:** 供应链后门  
**风险:** 极危，允许未经授权的远程SSH访问和代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2024-3094-Checker](https://github.com/iheb2b/CVE-2024-3094-Checker)  

---

### [CVE-2024-57394](CVE-2024-57394-cwjchoi01_CVE-2024-57394.md) 🔴 ✅

**名称:** CVE-2024-57394 - Qi-ANXIN Tianqing Endpoint Security Management System 本地提权  
**类型:** 本地提权  
**风险:** 高危，可导致系统权限被提升到 SYSTEM  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2024-57394](https://github.com/cwjchoi01/CVE-2024-57394)  

---

### [CVE-2025-3248](CVE-2025-3248-verylazytech_CVE-2025-3248.md) 🔴 ✅

**名称:** CVE-2025-3248-langflow-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2025-3248](https://github.com/verylazytech/CVE-2025-3248)  

---

### [CVE-2024-3094](CVE-2024-3094-0xlane_xz-cve-2024-3094.md)  ✅

**名称:** CVE-2024-3094-XZ Utils-供应链后门  
**类型:** 供应链后门  
**风险:** 极危，可导致未经授权的远程SSH访问和代码执行  
**投毒风险:** 85%  
**发现时间:** 2025-04-16  
**POC仓库:** [xz-cve-2024-3094](https://github.com/0xlane/xz-cve-2024-3094)  

---

### [CVE-2024-3094](CVE-2024-3094-pentestfunctions_CVE-2024-3094.md)  ✅

**名称:** CVE-2024-3094 - XZ Utils供应链后门  
**类型:** 供应链后门  
**风险:** 极危，允许未经授权的远程SSH访问并可能执行任意代码  
**投毒风险:** 1%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2024-3094](https://github.com/pentestfunctions/CVE-2024-3094)  

---

### [CVE-2024-3094](CVE-2024-3094-gustavorobertux_CVE-2024-3094.md) 🔴 

**名称:** CVE-2024-3094-xz-utils供应链后门  
**类型:** 供应链后门  
**风险:** 高危，可导致未经授权的远程SSH访问  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2024-3094](https://github.com/gustavorobertux/CVE-2024-3094)  

---

### [CVE-2024-3094](CVE-2024-3094-amlweems_xzbot.md)  ✅

**名称:** CVE-2024-3094 - XZ Utils供应链后门  
**类型:** 供应链攻击/后门  
**风险:** 极危，允许未经授权的远程SSH访问和代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [xzbot](https://github.com/amlweems/xzbot)  

---

### [CVE-2024-3094](CVE-2024-3094-Security-Phoenix-demo_CVE-2024-3094-fix-exploits.md) 🔴 ✅

**名称:** CVE-2024-3094-xz-utils供应链后门  
**类型:** 供应链后门  
**风险:** 高危，允许未经授权的远程SSH访问，可能导致远程代码执行和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2024-3094-fix-exploits](https://github.com/Security-Phoenix-demo/CVE-2024-3094-fix-exploits)  

---

### [CVE-2024-3094](CVE-2024-3094-Bella-Bc_xz-backdoor-CVE-2024-3094-Check.md)  ✅

**名称:** CVE-2024-3094-xz-utils后门  
**类型:** 供应链攻击/后门  
**风险:** 极危，允许未经授权的远程SSH访问，可能导致系统完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-04-16  
**POC仓库:** [xz-backdoor-CVE-2024-3094-Check](https://github.com/Bella-Bc/xz-backdoor-CVE-2024-3094-Check)  

---

### [CVE-2024-3094](CVE-2024-3094-TheTorjanCaptain_CVE-2024-3094-Checker.md)  ✅

**名称:** CVE-2024-3094-xz-utils供应链后门  
**类型:** 供应链后门  
**风险:** 极危，可能导致未经授权的远程SSH访问和代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2024-3094-Checker](https://github.com/TheTorjanCaptain/CVE-2024-3094-Checker)  

---

### [CVE-2024-3094](CVE-2024-3094-weltregie_liblzma-scan.md)  ✅

**名称:** CVE-2024-3094-XZ Utils供应链后门  
**类型:** 供应链后门  
**风险:** 极危，可能导致SSH远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [liblzma-scan](https://github.com/weltregie/liblzma-scan)  

---

### [CVE-2024-3094](CVE-2024-3094-crfearnworks_ansible-CVE-2024-3094.md)  ✅

**名称:** CVE-2024-3094 - XZ Utils Backdoor  
**类型:** 供应链攻击/后门  
**风险:** 严重，可能允许未经授权的远程SSH访问和代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [ansible-CVE-2024-3094](https://github.com/crfearnworks/ansible-CVE-2024-3094)  

---

### [CVE-2024-3094](CVE-2024-3094-badsectorlabs_ludus_xz_backdoor.md)  ✅

**名称:** CVE-2024-3094 XZ Utils供应链后门  
**类型:** 供应链后门  
**风险:** 严重，可能导致未经授权的远程SSH访问和代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-16  
**POC仓库:** [ludus_xz_backdoor](https://github.com/badsectorlabs/ludus_xz_backdoor)  

---

### [CVE-2024-3094](CVE-2024-3094-felipecosta09_cve-2024-3094.md)  ✅

**名称:** CVE-2024-3094 - XZ Utils Backdoor  
**类型:** 供应链攻击 / 后门  
**风险:** 极高，允许未经授权的远程SSH访问，可能导致完全系统控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-16  
**POC仓库:** [cve-2024-3094](https://github.com/felipecosta09/cve-2024-3094)  

---

### [CVE-2024-3094](CVE-2024-3094-robertdebock_ansible-playbook-cve-2024-3094.md)  ✅

**名称:** CVE-2024-3094-xz-utils供应链投毒  
**类型:** 供应链投毒  
**风险:** 极危，可能导致远程代码执行和系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [ansible-playbook-cve-2024-3094](https://github.com/robertdebock/ansible-playbook-cve-2024-3094)  

---

### [CVE-2024-3094](CVE-2024-3094-r0binak_xzk8s.md)  ✅

**名称:** CVE-2024-3094 - XZ Utils供应链后门  
**类型:** 供应链后门  
**风险:** 极危，可导致未授权远程SSH访问  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [xzk8s](https://github.com/r0binak/xzk8s)  

---

### [CVE-2024-3094](CVE-2024-3094-Juul_xz-backdoor-scan.md)  ✅

**名称:** CVE-2024-3094-xz-backdoor-scan  
**类型:** 后门扫描  
**风险:** 信息泄露，可能导致误报或漏报  
**投毒风险:** 0%  
**发现时间:** 2025-04-16  
**POC仓库:** [xz-backdoor-scan](https://github.com/Juul/xz-backdoor-scan)  

---

### [CVE-2024-3094](CVE-2024-3094-alokemajumder_CVE-2024-3094-Vulnerability-Checker-Fixer.md)  ✅

**名称:** CVE-2024-3094 XZ Utils供应链后门  
**类型:** 供应链后门  
**风险:** 极危，可能导致未授权远程访问和控制  
**投毒风险:** 20%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2024-3094-Vulnerability-Checker-Fixer](https://github.com/alokemajumder/CVE-2024-3094-Vulnerability-Checker-Fixer)  

---

### [CVE-2024-3094](CVE-2024-3094-jfrog_cve-2024-3094-tools.md)  ✅

**名称:** CVE-2024-3094 XZ Utils Backdoor  
**类型:** 供应链攻击/后门  
**风险:** 极危，允许未经授权的远程SSH访问和潜在的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-16  
**POC仓库:** [cve-2024-3094-tools](https://github.com/jfrog/cve-2024-3094-tools)  

---

### [CVE-2024-3094](CVE-2024-3094-fevar54_Detectar-Backdoor-en-liblzma-de-XZ-utils-CVE-2024-3094-.md)  ✅

**名称:** CVE-2024-3094 XZ Utils供应链后门  
**类型:** 供应链攻击/后门  
**风险:** 极危，可导致远程代码执行和未授权访问  
**投毒风险:** 0%  
**发现时间:** 2025-04-16  
**POC仓库:** [Detectar-Backdoor-en-liblzma-de-XZ-utils-CVE-2024-3094-](https://github.com/fevar54/Detectar-Backdoor-en-liblzma-de-XZ-utils-CVE-2024-3094-)  

---

### [CVE-2024-3094](CVE-2024-3094-neuralinhibitor_xzwhy.md)  ✅

**名称:** CVE-2024-3094 XZ Utils供应链后门  
**类型:** 供应链后门  
**风险:** 极危，可导致未经授权的远程访问和控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-16  
**POC仓库:** [xzwhy](https://github.com/neuralinhibitor/xzwhy)  

---

### [CVE-2024-3094](CVE-2024-3094-przemoc_xz-backdoor-links.md)  ✅

**名称:** CVE-2024-3094 XZ Utils Backdoor  
**类型:** 供应链攻击/后门  
**风险:** 极危，可导致未经授权的远程SSH访问和代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-16  
**POC仓库:** [xz-backdoor-links](https://github.com/przemoc/xz-backdoor-links)  

---

### [CVE-2024-3094](CVE-2024-3094-reuteras_CVE-2024-3094.md)  ✅

**名称:** CVE-2024-3094 XZ Utils供应链后门  
**类型:** 供应链攻击/后门  
**风险:** 极危，允许未授权的远程SSH访问和代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2024-3094](https://github.com/reuteras/CVE-2024-3094)  

---

### [CVE-2024-3094](CVE-2024-3094-AndreaCicca_Sicurezza-Informatica-Presentazione.md) 🔴 ✅

**名称:** CVE-2024-3094 XZ Utils Backdoor  
**类型:** 供应链攻击/后门  
**风险:** 高危，允许未经授权的远程SSH访问和代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-16  
**POC仓库:** [Sicurezza-Informatica-Presentazione](https://github.com/AndreaCicca/Sicurezza-Informatica-Presentazione)  

---

### [CVE-2024-3094](CVE-2024-3094-shefirot_CVE-2024-3094.md)  ✅

**名称:** CVE-2024-3094-XZ Utils供应链后门  
**类型:** 供应链后门  
**风险:** 极危，可能导致远程代码执行和系统完全控制  
**投毒风险:** 20%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2024-3094](https://github.com/shefirot/CVE-2024-3094)  

---

### [CVE-2024-3094](CVE-2024-3094-DANO-AMP_CVE-2024-3094.md)  ✅

**名称:** CVE-2024-3094 - XZ Utils Supply Chain Backdoor  
**类型:** 供应链攻击/后门  
**风险:** 极危，允许未经授权的远程SSH访问和潜在的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2024-3094](https://github.com/DANO-AMP/CVE-2024-3094)  

---

### [CVE-2024-3094](CVE-2024-3094-robertdfrench_ifuncd-up.md)  ✅

**名称:** CVE-2024-3094 XZ Utils Backdoor  
**类型:** 供应链攻击/后门  
**风险:** 极危，可导致未经授权的远程SSH访问  
**投毒风险:** 5%  
**发现时间:** 2025-04-16  
**POC仓库:** [ifuncd-up](https://github.com/robertdfrench/ifuncd-up)  

---

### [CVE-2024-3094](CVE-2024-3094-XiaomingX_cve-2024-3094-xz-backdoor-exploit.md)  ✅

**名称:** CVE-2024-3094-XZ Utils供应链后门  
**类型:** 供应链后门  
**风险:** 极危，允许未经授权的远程SSH访问，可能导致完全系统控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-16  
**POC仓库:** [cve-2024-3094-xz-backdoor-exploit](https://github.com/XiaomingX/cve-2024-3094-xz-backdoor-exploit)  

---

### [CVE-2024-3094](CVE-2024-3094-been22426_CVE-2024-3094.md)  ✅

**名称:** CVE-2024-3094 XZ Utils Backdoor  
**类型:** 供应链攻击/后门  
**风险:** 极危，允许未经授权的远程SSH访问和潜在的任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2024-3094](https://github.com/been22426/CVE-2024-3094)  

---

### [CVE-2025-30967](CVE-2025-30967-Anton-ai111_CVE-2025-30967.md) 🔴 ✅

**名称:** CVE-2025-30967-WPJobBoard-CSRF to RCE  
**类型:** CSRF to Remote Code Execution (RCE)  
**风险:** CRITICAL, 可能导致服务器完全控制  
**投毒风险:** 95%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2025-30967](https://github.com/Anton-ai111/CVE-2025-30967)  

---

### [CVE-2025-29927](CVE-2025-29927-mhamzakhattak_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927 - Next.js Middleware Authorization Bypass  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问敏感信息。  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2025-29927](https://github.com/mhamzakhattak/CVE-2025-29927)  

---

### [CVE-2020-0665](CVE-2020-0665-gunzf0x_CVE-2020-0665.md) 🔴 ✅

**名称:** CVE-2020-0665 Active Directory 权限提升  
**类型:** 权限提升  
**风险:** 高危，可能允许攻击者提升在 Active Directory 环境中的权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2020-0665](https://github.com/gunzf0x/CVE-2020-0665)  

---

### [CVE-2025-29927](CVE-2025-29927-Knotsecurity_CVE-2025-29927-NextJs-Middleware-Simulation.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js中间件授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问敏感信息和功能  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2025-29927-NextJs-Middleware-Simulation](https://github.com/Knotsecurity/CVE-2025-29927-NextJs-Middleware-Simulation)  

---

### [CVE-2024-36842](CVE-2024-36842-abbiy_CVE-2024-36842-Backdooring-Oncord-Android-Sterio-.md) 🔴 ✅

**名称:** CVE-2024-36842-Oncord+Android Infotainment System-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致设备完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2024-36842-Backdooring-Oncord-Android-Sterio-](https://github.com/abbiy/CVE-2024-36842-Backdooring-Oncord-Android-Sterio-)  

---

### [CVE-2020-1054](CVE-2020-1054-Iamgublin_CVE-2020-1054.md) 🔴 ✅

**名称:** CVE-2020-1054 - Win32k 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可导致本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2020-1054](https://github.com/Iamgublin/CVE-2020-1054)  

---

### [CVE-2020-1054](CVE-2020-1054-0xeb-bp_cve-2020-1054.md) 🔴 ✅

**名称:** CVE-2020-1054 Win32k 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致本地权限提升  
**投毒风险:** 1%  
**发现时间:** 2025-04-16  
**POC仓库:** [cve-2020-1054](https://github.com/0xeb-bp/cve-2020-1054)  

---

### [CVE-2020-1054](CVE-2020-1054-KaLendsi_CVE-2020-1054.md) 🔴 ✅

**名称:** CVE-2020-1054  
**类型:** 权限提升  
**风险:** 高危，本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2020-1054](https://github.com/KaLendsi/CVE-2020-1054)  

---

### [CVE-2020-1054](CVE-2020-1054-Graham382_CVE-2020-1054.md) 🔴 ✅

**名称:** CVE-2020-1054 Win32k 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，允许低权限用户提升至SYSTEM权限  
**投毒风险:** 1%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2020-1054](https://github.com/Graham382/CVE-2020-1054)  

---

### [CVE-2020-1054](CVE-2020-1054-Naman2701B_CVE-2020-1054.md) 🔴 ✅

**名称:** CVE-2020-1054 Win32k 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，本地权限提升至SYSTEM  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2020-1054](https://github.com/Naman2701B/CVE-2020-1054)  

---

### [CVE-2015-6420](CVE-2015-6420-Leeziao_CVE-2015-6420.md) 🔴 ✅

**名称:** CVE-2015-6420 - Cisco 产品 Java 反序列化漏洞  
**类型:** Java 反序列化  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2015-6420](https://github.com/Leeziao/CVE-2015-6420)  

---

### [CVE-2025-29275](CVE-2025-29275-0xBl4nk_CVE-2025-29275.md) 🟡 ✅

**名称:** CVE-2025-29275-Linksys E5600-XSS  
**类型:** XSS  
**风险:** 中危，可能导致会话劫持、钓鱼攻击  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2025-29275](https://github.com/0xBl4nk/CVE-2025-29275)  

---

### [CVE-2025-29276](CVE-2025-29276-0xBl4nk_CVE-2025-29276.md) 🟡 ✅

**名称:** CVE-2025-29276-XSS  
**类型:** XSS  
**风险:** 中危，可能导致用户凭据泄露或执行恶意脚本  
**投毒风险:** 10%  
**发现时间:** 2025-04-16  
**POC仓库:** [CVE-2025-29276](https://github.com/0xBl4nk/CVE-2025-29276)  

---

### [CVE-2025-29277](CVE-2025-29277-0xBl4nk_CVE-2025-29277.md) 🔴 ✅

**名称:** CVE-2025-29277-Linksys E5600-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-15  
**POC仓库:** [CVE-2025-29277](https://github.com/0xBl4nk/CVE-2025-29277)  

---

### [CVE-2025-29278](CVE-2025-29278-0xBl4nk_CVE-2025-29278.md) 🔴 ✅

**名称:** CVE-2025-29278  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-15  
**POC仓库:** [CVE-2025-29278](https://github.com/0xBl4nk/CVE-2025-29278)  

---

### [CVE-2025-29279](CVE-2025-29279-0xBl4nk_CVE-2025-29279.md) 🔴 ✅

**名称:** CVE-2025-29279  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-15  
**POC仓库:** [CVE-2025-29279](https://github.com/0xBl4nk/CVE-2025-29279)  

---

### [CVE-2025-30406](CVE-2025-30406-bronsoneaver_CVE-2025-30406.md) 🔴 

**名称:** CVE-2025-30406-CentreStack-反序列化漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，远程代码执行  
**投毒风险:** 60%  
**发现时间:** 2025-04-15  
**POC仓库:** [CVE-2025-30406](https://github.com/bronsoneaver/CVE-2025-30406)  

---

### [CVE-2024-55211](CVE-2024-55211-micaelmaciel_CVE-2024-55211.md) 🔴 ✅

**名称:** CVE-2024-55211-Tk-Rt-Wr135G-Cookie认证绕过  
**类型:** Cookie认证绕过  
**风险:** 高危，可能导致设备完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-15  
**POC仓库:** [CVE-2024-55211](https://github.com/micaelmaciel/CVE-2024-55211)  

---

### [CVE-2019-9053](CVE-2019-9053-Hackheart-tech_-exploit-lab.md) 🔴 ✅

**名称:** CVE-2019-9053 - CMS Made Simple - 时间盲注SQL注入  
**类型:** 时间盲注SQL注入  
**风险:** 高危，可能导致数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-15  
**POC仓库:** [-exploit-lab](https://github.com/Hackheart-tech/-exploit-lab)  

---

### [CVE-2025-2294](CVE-2025-2294-rhz0d_CVE-2025-2294.md) 🔴 ✅

**名称:** CVE-2025-2294 Kubio AI Page Builder <= 2.5.1 - Unauthenticated Local File Inclusion  
**类型:** 本地文件包含 (LFI)  
**风险:** 高危，可能导致敏感信息泄露，甚至代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-15  
**POC仓库:** [CVE-2025-2294](https://github.com/rhz0d/CVE-2025-2294)  

---

### [CVE-2019-9053](CVE-2019-9053-kaizoku73_CVE-2019-9053.md) 🔴 ✅

**名称:** CVE-2019-9053-CMS Made Simple-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、权限提升、甚至远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-15  
**POC仓库:** [CVE-2019-9053](https://github.com/kaizoku73/CVE-2019-9053)  

---

### [CVE-2025-24016](CVE-2025-24016-huseyinstif_CVE-2025-24016-Nuclei-Template.md) 🔴 ✅

**名称:** CVE-2025-24016-Wazuh-反序列化RCE  
**类型:** 反序列化RCE  
**风险:** 高危，可导致远程代码执行，完全系统控制  
**投毒风险:** 5%  
**发现时间:** 2025-04-15  
**POC仓库:** [CVE-2025-24016-Nuclei-Template](https://github.com/huseyinstif/CVE-2025-24016-Nuclei-Template)  

---

### [CVE-2025-24016](CVE-2025-24016-0xjessie21_CVE-2025-24016.md)  ✅

**名称:** CVE-2025-24016-Wazuh-RCE  
**类型:** 反序列化漏洞导致远程代码执行  
**风险:** 严重，可能导致完全系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-15  
**POC仓库:** [CVE-2025-24016](https://github.com/0xjessie21/CVE-2025-24016)  

---

### [CVE-2025-24016](CVE-2025-24016-MuhammadWaseem29_CVE-2025-24016.md) 🔴 ✅

**名称:** CVE-2025-24016-Wazuh-RCE  
**类型:** 反序列化漏洞导致远程代码执行  
**风险:** 高危，可导致远程代码执行，完全控制系统  
**投毒风险:** 10%  
**发现时间:** 2025-04-15  
**POC仓库:** [CVE-2025-24016](https://github.com/MuhammadWaseem29/CVE-2025-24016)  

---

### [CVE-2025-24016](CVE-2025-24016-celsius026_poc_CVE-2025-24016.md) 🔴 ✅

**名称:** CVE-2025-24016-Wazuh-RCE  
**类型:** 反序列化漏洞导致远程代码执行  
**风险:** 高危，可导致系统完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-15  
**POC仓库:** [poc_CVE-2025-24016](https://github.com/celsius026/poc_CVE-2025-24016)  

---

### [CVE-2024-52550](CVE-2024-52550-Anton-ai111_CVE-2024-52550.md) 🔴 ✅

**名称:** CVE-2024-52550 - Jenkins Pipeline Groovy Plugin 未授权脚本重建  
**类型:** 权限绕过  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-15  
**POC仓库:** [CVE-2024-52550](https://github.com/Anton-ai111/CVE-2024-52550)  

---

### [CVE-2025-29722](CVE-2025-29722-cypherdavy_CVE-2025-29722.md) 🟡 ✅

**名称:** CVE-2025-29722 - Commercify v1.0 CSRF  
**类型:** CSRF (Cross-Site Request Forgery)  
**风险:** 中危，可能导致用户账户信息被篡改  
**投毒风险:** 10%  
**发现时间:** 2025-04-15  
**POC仓库:** [CVE-2025-29722](https://github.com/cypherdavy/CVE-2025-29722)  

---

### [CVE-2019-9053](CVE-2019-9053-del0x3_CVE-2019-9053-port-py3.md) 🔴 ✅

**名称:** CVE-2019-9053 - CMS Made Simple News Module SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据库信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-15  
**POC仓库:** [CVE-2019-9053-port-py3](https://github.com/del0x3/CVE-2019-9053-port-py3)  

---

### [CVE-2025-24799](CVE-2025-24799-MatheuZSecurity_Exploit-CVE-2025-24799.md) 🔴 ✅

**名称:** CVE-2025-24799-GLPI-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-15  
**POC仓库:** [Exploit-CVE-2025-24799](https://github.com/MatheuZSecurity/Exploit-CVE-2025-24799)  

---

### [CVE-2023-1514](CVE-2023-1514-wsx-rootdeef_CVE-2023-1514-SQL-Injection-Teampass-.md) 🔴 ✅

**名称:** CVE-2023-1514-RTU500 Scripting Interface-身份欺骗  
**类型:** 身份欺骗  
**风险:** 高危，可能导致敏感信息泄露，完整性破坏  
**投毒风险:** 0%  
**发现时间:** 2025-04-15  
**POC仓库:** [CVE-2023-1514-SQL-Injection-Teampass-](https://github.com/wsx-rootdeef/CVE-2023-1514-SQL-Injection-Teampass-)  

---

### [CVE-2023-44487](CVE-2023-44487-ByteHackr_CVE-2023-44487.md) 🔴 ✅

**名称:** CVE-2023-44487 HTTP/2 Rapid Reset 拒绝服务攻击  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，导致服务器资源耗尽，服务不可用  
**投毒风险:** 10%  
**发现时间:** 2025-04-15  
**POC仓库:** [CVE-2023-44487](https://github.com/ByteHackr/CVE-2023-44487)  

---

### [CVE-2023-44487](CVE-2023-44487-pabloec20_rapidreset.md) 🔴 ✅

**名称:** CVE-2023-44487-HTTP/2 Rapid Reset  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致服务器资源耗尽，服务中断  
**投毒风险:** 10%  
**发现时间:** 2025-04-15  
**POC仓库:** [rapidreset](https://github.com/pabloec20/rapidreset)  

---

### [CVE-2023-44487](CVE-2023-44487-imabee101_CVE-2023-44487.md) 🔴 ✅

**名称:** CVE-2023-44487 HTTP/2 Rapid Reset 拒绝服务漏洞  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致服务器资源耗尽，服务不可用  
**投毒风险:** 10%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-44487](https://github.com/imabee101/CVE-2023-44487)  

---

### [CVE-2023-44487](CVE-2023-44487-studiogangster_CVE-2023-44487.md) 🔴 ✅

**名称:** CVE-2023-44487 HTTP/2 Rapid Reset 攻击  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致服务器资源耗尽，服务不可用  
**投毒风险:** 0%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-44487](https://github.com/studiogangster/CVE-2023-44487)  

---

### [CVE-2023-44487](CVE-2023-44487-ReToCode_golang-CVE-2023-44487.md) 🔴 ✅

**名称:** CVE-2023-44487 HTTP/2 Rapid Reset 攻击  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致服务器资源耗尽，服务不可用  
**投毒风险:** 1%  
**发现时间:** 2025-04-14  
**POC仓库:** [golang-CVE-2023-44487](https://github.com/ReToCode/golang-CVE-2023-44487)  

---

### [CVE-2023-44487](CVE-2023-44487-secengjeff_rapidresetclient.md) 🔴 ✅

**名称:** CVE-2023-44487-HTTP/2 Rapid Reset  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可导致服务器资源耗尽，服务不可用  
**投毒风险:** 5%  
**发现时间:** 2025-04-14  
**POC仓库:** [rapidresetclient](https://github.com/secengjeff/rapidresetclient)  

---

### [CVE-2023-44487](CVE-2023-44487-nxenon_cve-2023-44487.md) 🔴 ✅

**名称:** CVE-2023-44487 HTTP/2 Rapid Reset 拒绝服务漏洞  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致服务不可用  
**投毒风险:** 5%  
**发现时间:** 2025-04-14  
**POC仓库:** [cve-2023-44487](https://github.com/nxenon/cve-2023-44487)  

---

### [CVE-2023-44487](CVE-2023-44487-sigridou_CVE-2023-44487-.md) 🔴 ✅

**名称:** CVE-2023-44487 HTTP/2 Rapid Reset 拒绝服务漏洞  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致服务器资源耗尽，服务不可用  
**投毒风险:** 10%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-44487-](https://github.com/sigridou/CVE-2023-44487-)  

---

### [CVE-2023-44487](CVE-2023-44487-bcdannyboy_CVE-2023-44487.md) 🔴 ✅

**名称:** CVE-2023-44487 HTTP/2 快速重置拒绝服务漏洞  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致服务器资源耗尽，服务不可用  
**投毒风险:** 10%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-44487](https://github.com/bcdannyboy/CVE-2023-44487)  

---

### [CVE-2023-44487](CVE-2023-44487-ndrscodes_http2-rst-stream-attacker.md) 🔴 ✅

**名称:** CVE-2023-44487 HTTP/2 Rapid Reset 拒绝服务漏洞  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致服务器资源耗尽，服务不可用  
**投毒风险:** 10%  
**发现时间:** 2025-04-14  
**POC仓库:** [http2-rst-stream-attacker](https://github.com/ndrscodes/http2-rst-stream-attacker)  

---

### [CVE-2023-44487](CVE-2023-44487-TYuan0816_cve-2023-44487.md) 🔴 ✅

**名称:** CVE-2023-44487 HTTP/2 Rapid Reset 拒绝服务漏洞  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致服务器资源耗尽，服务不可用  
**投毒风险:** 0%  
**发现时间:** 2025-04-14  
**POC仓库:** [cve-2023-44487](https://github.com/TYuan0816/cve-2023-44487)  

---

### [CVE-2023-44487](CVE-2023-44487-threatlabindonesia_CVE-2023-44487-HTTP-2-Rapid-Reset-Exploit-PoC.md) 🔴 ✅

**名称:** CVE-2023-44487 - HTTP/2 Rapid Reset 攻击  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致服务器资源耗尽，服务不可用  
**投毒风险:** 10%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-44487-HTTP-2-Rapid-Reset-Exploit-PoC](https://github.com/threatlabindonesia/CVE-2023-44487-HTTP-2-Rapid-Reset-Exploit-PoC)  

---

### [CVE-2023-44487](CVE-2023-44487-aulauniversal_CVE-2023-44487.md) 🔴 ✅

**名称:** CVE-2023-44487 HTTP/2 Rapid Reset 拒绝服务攻击  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致服务器资源耗尽和拒绝服务  
**投毒风险:** 5%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-44487](https://github.com/aulauniversal/CVE-2023-44487)  

---

### [CVE-2023-44487](CVE-2023-44487-BMG-Black-Magic_CVE-2023-44487.md) 🔴 ✅

**名称:** CVE-2023-44487 HTTP/2 Rapid Reset 拒绝服务攻击  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致服务器资源耗尽，服务不可用  
**投毒风险:** 5%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-44487](https://github.com/BMG-Black-Magic/CVE-2023-44487)  

---

### [CVE-2023-44487](CVE-2023-44487-moften_CVE-2023-44487.md) 🔴 ✅

**名称:** CVE-2023-44487-HTTP/2 Rapid Reset攻击  
**类型:** 拒绝服务 (DoS)  
**风险:** 高危，可能导致服务器资源耗尽，服务中断  
**投毒风险:** 0%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-44487](https://github.com/moften/CVE-2023-44487)  

---

### [CVE-2025-29927](CVE-2025-29927-UNICORDev_exploit-CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-Authorization Bypass  
**类型:** 权限绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-04-14  
**POC仓库:** [exploit-CVE-2025-29927](https://github.com/UNICORDev/exploit-CVE-2025-29927)  

---

### [CVE-2021-42362](CVE-2021-42362-simonecris_CVE-2021-42362-PoC.md) 🔴 ✅

**名称:** CVE-2021-42362 - WordPress Popular Posts <= 5.3.2 认证后的任意文件上传导致RCE  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 20%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2021-42362-PoC](https://github.com/simonecris/CVE-2021-42362-PoC)  

---

### [CVE-2021-42362](CVE-2021-42362-samiba6_CVE-2021-42362.md) 🔴 ✅

**名称:** CVE-2021-42362-WordPress Popular Posts-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2021-42362](https://github.com/samiba6/CVE-2021-42362)  

---

### [CVE-2024-51996](CVE-2024-51996-moften_CVE-2024-51996.md) 🔴 ✅

**名称:** CVE-2024-51996-Symfony RememberMe 认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未经授权的访问和权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2024-51996](https://github.com/moften/CVE-2024-51996)  

---

### [CVE-2021-21424](CVE-2021-21424-moften_CVE-2021-21424.md) 🟡 ✅

**名称:** CVE-2021-21424-Symfony-UserEnumeration  
**类型:** 信息泄露/用户枚举  
**风险:** 中危，可能导致用户枚举，为进一步攻击提供信息  
**投毒风险:** 0%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2021-21424](https://github.com/moften/CVE-2021-21424)  

---

### [CVE-2023-32315](CVE-2023-32315-tangxiaofeng7_CVE-2023-32315-Openfire-Bypass.md) 🔴 ✅

**名称:** CVE-2023-32315-Openfire-认证绕过与RCE  
**类型:** 路径遍历/认证绕过/远程代码执行  
**风险:** 高危，未经授权访问管理控制台并执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-32315-Openfire-Bypass](https://github.com/tangxiaofeng7/CVE-2023-32315-Openfire-Bypass)  

---

### [CVE-2023-32315](CVE-2023-32315-ohnonoyesyes_CVE-2023-32315.md) 🔴 ✅

**名称:** CVE-2023-32315 - Openfire Authentication Bypass  
**类型:** 路径遍历导致认证绕过  
**风险:** 高危，可未经授权访问管理控制台，甚至可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-32315](https://github.com/ohnonoyesyes/CVE-2023-32315)  

---

### [CVE-2023-32315](CVE-2023-32315-5rGJ5aCh5oCq5YW9_CVE-2023-32315exp.md) 🔴 ✅

**名称:** CVE-2023-32315 - Openfire Authentication Bypass  
**类型:** 身份认证绕过 / 路径遍历  
**风险:** 高危，允许未经授权访问管理控制台，可能导致敏感信息泄露和控制服务器  
**投毒风险:** 0%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-32315exp](https://github.com/5rGJ5aCh5oCq5YW9/CVE-2023-32315exp)  

---

### [CVE-2023-32315](CVE-2023-32315-izzz0_CVE-2023-32315-POC.md) 🔴 ✅

**名称:** CVE-2023-32315-Openfire-Authentication Bypass  
**类型:** 路径遍历/认证绕过  
**风险:** 高危，允许未授权访问管理控制台，可能导致敏感信息泄露、配置更改甚至远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-32315-POC](https://github.com/izzz0/CVE-2023-32315-POC)  

---

### [CVE-2023-32315](CVE-2023-32315-ThatNotEasy_CVE-2023-32315.md) 🔴 ✅

**名称:** CVE-2023-32315-Openfire-身份验证绕过  
**类型:** 身份验证绕过/路径遍历  
**风险:** 高危，可能导致未经授权的访问和潜在的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-32315](https://github.com/ThatNotEasy/CVE-2023-32315)  

---

### [CVE-2023-32315](CVE-2023-32315-gibran-abdillah_CVE-2023-32315.md) 🔴 ✅

**名称:** CVE-2023-32315 - Openfire Authentication Bypass  
**类型:** 路径遍历导致认证绕过  
**风险:** 高危，可能导致未授权访问管理控制台  
**投毒风险:** 5%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-32315](https://github.com/gibran-abdillah/CVE-2023-32315)  

---

### [CVE-2023-32315](CVE-2023-32315-miko550_CVE-2023-32315.md) 🔴 ✅

**名称:** CVE-2023-32315-Openfire-路径遍历导致认证绕过  
**类型:** 路径遍历导致认证绕过  
**风险:** 高危，允许未授权访问管理控制台并创建管理员账户  
**投毒风险:** 1%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-32315](https://github.com/miko550/CVE-2023-32315)  

---

### [CVE-2023-32315](CVE-2023-32315-K3ysTr0K3R_CVE-2023-32315-EXPLOIT.md) 🔴 ✅

**名称:** CVE-2023-32315-Openfire身份验证绕过  
**类型:** 路径遍历导致的身份验证绕过  
**风险:** 高危，未经身份验证的攻击者可以创建管理员账户。  
**投毒风险:** 10%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-32315-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2023-32315-EXPLOIT)  

---

### [CVE-2023-32315](CVE-2023-32315-asepsaepdin_CVE-2023-32315.md) 🔴 ✅

**名称:** CVE-2023-32315 - Openfire Authentication Bypass  
**类型:** 路径遍历/认证绕过  
**风险:** 高危，可能导致未授权访问和控制Openfire服务器  
**投毒风险:** 10%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-32315](https://github.com/asepsaepdin/CVE-2023-32315)  

---

### [CVE-2023-32315](CVE-2023-32315-pulentoski_Explotaci-n-de-CVE-2023-32315-en-Openfire.md) 🔴 ✅

**名称:** CVE-2023-32315-Openfire-认证绕过  
**类型:** 路径遍历导致的认证绕过  
**风险:** 高危，可能导致未授权访问和控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-14  
**POC仓库:** [Explotaci-n-de-CVE-2023-32315-en-Openfire](https://github.com/pulentoski/Explotaci-n-de-CVE-2023-32315-en-Openfire)  

---

### [CVE-2021-41773](CVE-2021-41773-khaidtraivch_CVE-2021-41773-Apache-2.4.49-.md) 🔴 ✅

**名称:** CVE-2021-41773 Apache HTTP Server Path Traversal & Remote Code Execution  
**类型:** 路径遍历和远程代码执行  
**风险:** 高危，可读取敏感文件并远程执行代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2021-41773-Apache-2.4.49-](https://github.com/khaidtraivch/CVE-2021-41773-Apache-2.4.49-)  

---

### [CVE-2021-44228](CVE-2021-44228-tadash10_Exploiting-CVE-2021-44228-Log4Shell-in-a-Banking-Environment.md) 🔴 ✅

**名称:** CVE-2021-44228 - Apache Log4j2 Log4Shell 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行、数据泄露和服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-14  
**POC仓库:** [Exploiting-CVE-2021-44228-Log4Shell-in-a-Banking-Environment](https://github.com/tadash10/Exploiting-CVE-2021-44228-Log4Shell-in-a-Banking-Environment)  

---

### [CVE-2021-44228](CVE-2021-44228-LucasPDiniz_CVE-2021-44228.md) 🔴 ✅

**名称:** CVE-2021-44228-Apache Log4j2 JNDI 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者执行任意代码  
**投毒风险:** 2%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2021-44228](https://github.com/LucasPDiniz/CVE-2021-44228)  

---

### [CVE-2021-44228](CVE-2021-44228-YangHyperData_LOGJ4_PocShell_CVE-2021-44228.md) 🔴 ✅

**名称:** CVE-2021-44228 - Apache Log4j2 JNDI 远程代码执行  
**类型:** 远程代码执行  
**风险:** 极高危，可能导致完全控制受影响系统  
**投毒风险:** 10%  
**发现时间:** 2025-04-14  
**POC仓库:** [LOGJ4_PocShell_CVE-2021-44228](https://github.com/YangHyperData/LOGJ4_PocShell_CVE-2021-44228)  

---

### [CVE-2021-44228](CVE-2021-44228-ShlomiRex_log4shell_lab.md) 🔴 ✅

**名称:** CVE-2021-44228 Log4Shell 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-14  
**POC仓库:** [log4shell_lab](https://github.com/ShlomiRex/log4shell_lab)  

---

### [CVE-2021-44228](CVE-2021-44228-khaidtraivch_CVE-2021-44228-Log4Shell-.md) 🔴 ✅

**名称:** CVE-2021-44228-Log4Shell  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和完全系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2021-44228-Log4Shell-](https://github.com/khaidtraivch/CVE-2021-44228-Log4Shell-)  

---

### [CVE-2023-40028](CVE-2023-40028-0xyassine_CVE-2023-40028.md) 🟡 ✅

**名称:** CVE-2023-40028-Ghost-任意文件读取  
**类型:** 任意文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-40028](https://github.com/0xyassine/CVE-2023-40028)  

---

### [CVE-2023-40028](CVE-2023-40028-BBSynapse_CVE-2023-40028.md) 🟡 ✅

**名称:** CVE-2023-40028-Ghost-任意文件读取  
**类型:** 任意文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-40028](https://github.com/BBSynapse/CVE-2023-40028)  

---

### [CVE-2023-40028](CVE-2023-40028-sudlit_CVE-2023-40028.md) 🟡 ✅

**名称:** CVE-2023-40028-Ghost-任意文件读取  
**类型:** 任意文件读取  
**风险:** 中危，可读取服务器敏感文件  
**投毒风险:** 10%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-40028](https://github.com/sudlit/CVE-2023-40028)  

---

### [CVE-2023-40028](CVE-2023-40028-monke443_CVE-2023-40028.md) 🟡 ✅

**名称:** CVE-2023-40028-Ghost-Arbitrary File Read  
**类型:** 任意文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-40028](https://github.com/monke443/CVE-2023-40028)  

---

### [CVE-2023-40028](CVE-2023-40028-rvizx_CVE-2023-40028.md) 🟡 ✅

**名称:** CVE-2023-40028 - Ghost CMS 任意文件读取  
**类型:** 任意文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-40028](https://github.com/rvizx/CVE-2023-40028)  

---

### [CVE-2023-40028](CVE-2023-40028-0xDTC_Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028.md) 🟡 ✅

**名称:** CVE-2023-40028-Ghost-任意文件读取  
**类型:** 任意文件读取  
**风险:** 中危，可读取服务器上的敏感文件  
**投毒风险:** 5%  
**发现时间:** 2025-04-14  
**POC仓库:** [Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028](https://github.com/0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028)  

---

### [CVE-2023-40028](CVE-2023-40028-rehan6658_CVE-2023-40028.md) 🟡 ✅

**名称:** CVE-2023-40028-Ghost-任意文件读取  
**类型:** 任意文件读取  
**风险:** 中危，可导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-40028](https://github.com/rehan6658/CVE-2023-40028)  

---

### [CVE-2023-40028](CVE-2023-40028-godylockz_CVE-2023-40028.md) 🟡 ✅

**名称:** CVE-2023-40028-Ghost-任意文件读取  
**类型:** 任意文件读取  
**风险:** 中危，可读取服务器敏感信息  
**投毒风险:** 0%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-40028](https://github.com/godylockz/CVE-2023-40028)  

---

### [CVE-2023-40028](CVE-2023-40028-syogod_CVE-2023-40028.md) 🟡 ✅

**名称:** CVE-2023-40028-Ghost-任意文件读取  
**类型:** 任意文件读取  
**风险:** 中危，可读取服务器敏感信息  
**投毒风险:** 0%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-40028](https://github.com/syogod/CVE-2023-40028)  

---

### [CVE-2023-40028](CVE-2023-40028-buutt3rf1y_CVE-2023-40028.md) 🟡 ✅

**名称:** CVE-2023-40028-Ghost-任意文件读取  
**类型:** 任意文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-40028](https://github.com/buutt3rf1y/CVE-2023-40028)  

---

### [CVE-2025-3102](CVE-2025-3102-rhz0d_CVE-2025-3102.md) 🔴 ✅

**名称:** CVE-2025-3102 - SureTriggers WordPress Plugin Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 高危，允许未经身份验证的攻击者创建管理员账户，可能导致完全站点控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2025-3102](https://github.com/rhz0d/CVE-2025-3102)  

---

### [CVE-2025-32579](CVE-2025-32579-Nxploited_CVE-2025-32579.md) 🔴 ✅

**名称:** CVE-2025-32579-Sync Posts-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2025-32579](https://github.com/Nxploited/CVE-2025-32579)  

---

### [CVE-2020-13941](CVE-2020-13941-mbadanoiu_CVE-2020-13941.md) 🔴 ✅

**名称:** CVE-2020-13941: Apache Solr 绝对路径文件读取/写入漏洞  
**类型:** 文件读取/写入  
**风险:** 高危，可能导致信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2020-13941](https://github.com/mbadanoiu/CVE-2020-13941)  

---

### [CVE-2025-3102](CVE-2025-3102-Nxploited_CVE-2025-3102.md) 🔴 ✅

**名称:** CVE-2025-3102 - SureTriggers 身份验证绕过导致管理员账户创建  
**类型:** 身份验证绕过  
**风险:** 高危，允许未经身份验证的攻击者创建管理员账户，导致完全控制目标网站  
**投毒风险:** 5%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2025-3102](https://github.com/Nxploited/CVE-2025-3102)  

---

### [CVE-2021-4034](CVE-2021-4034-AsierEgana_cve-2021-4034.md) 🔴 ✅

**名称:** CVE-2021-4034 - Polkit pkexec 本地提权  
**类型:** 本地提权  
**风险:** 高危，允许低权限用户获取 root 权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-14  
**POC仓库:** [cve-2021-4034](https://github.com/AsierEgana/cve-2021-4034)  

---

### [CVE-2023-42793](CVE-2023-42793-jakehomb_cve-2023-42793.md) 🔴 ✅

**名称:** CVE-2023-42793-JetBrains TeamCity-身份验证绕过导致RCE  
**类型:** 身份验证绕过导致RCE  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-14  
**POC仓库:** [cve-2023-42793](https://github.com/jakehomb/cve-2023-42793)  

---

### [CVE-2023-27350](CVE-2023-27350-adhikara13_CVE-2023-27350.md)  ✅

**名称:** CVE-2023-27350-PaperCut-身份验证绕过和远程代码执行  
**类型:** 身份验证绕过 + 远程代码执行  
**风险:** 严重，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-27350](https://github.com/adhikara13/CVE-2023-27350)  

---

### [CVE-2023-27350](CVE-2023-27350-MaanVader_CVE-2023-27350-POC.md) 🔴 ✅

**名称:** CVE-2023-27350-PaperCut NG/MF-身份验证绕过与远程代码执行  
**类型:** 身份验证绕过/远程代码执行  
**风险:** 高危，可导致完全系统控制  
**投毒风险:** 1%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-27350-POC](https://github.com/MaanVader/CVE-2023-27350-POC)  

---

### [CVE-2023-27350](CVE-2023-27350-horizon3ai_CVE-2023-27350.md)  ✅

**名称:** CVE-2023-27350 PaperCut NG/MF 身份验证绕过与远程代码执行漏洞  
**类型:** 身份验证绕过/远程代码执行  
**风险:** 严重，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-27350](https://github.com/horizon3ai/CVE-2023-27350)  

---

### [CVE-2023-27350](CVE-2023-27350-Jenderal92_CVE-2023-27350.md) 🔴 ✅

**名称:** CVE-2023-27350-PaperCut NG/MF-身份验证绕过和远程代码执行  
**类型:** 身份验证绕过/远程代码执行  
**风险:** 高危，未经身份验证的攻击者可执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-27350](https://github.com/Jenderal92/CVE-2023-27350)  

---

### [CVE-2023-27350](CVE-2023-27350-ThatNotEasy_CVE-2023-27350.md)  ✅

**名称:** CVE-2023-27350-PaperCut NG/MF-身份验证绕过和远程代码执行  
**类型:** 身份验证绕过和远程代码执行  
**风险:** 极高，可能导致完全系统控制  
**投毒风险:** 5%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-27350](https://github.com/ThatNotEasy/CVE-2023-27350)  

---

### [CVE-2023-27350](CVE-2023-27350-ASG-CASTLE_CVE-2023-27350.md) 🔴 ✅

**名称:** CVE-2023-27350 PaperCut NG/MF 身份验证绕过和远程代码执行  
**类型:** 身份验证绕过/远程代码执行  
**风险:** 高危，可完全控制受影响系统  
**投毒风险:** 10%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-27350](https://github.com/ASG-CASTLE/CVE-2023-27350)  

---

### [CVE-2023-27350](CVE-2023-27350-imancybersecurity_CVE-2023-27350-POC.md)  ✅

**名称:** CVE-2023-27350-PaperCut NG/MF Authentication Bypass and Remote Code Execution  
**类型:** 身份验证绕过,远程代码执行  
**风险:** 极危，可导致完全系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-27350-POC](https://github.com/imancybersecurity/CVE-2023-27350-POC)  

---

### [CVE-2023-27350](CVE-2023-27350-monke443_CVE-2023-27350.md)  ✅

**名称:** CVE-2023-27350 - PaperCut NG/MF 身份验证绕过及远程代码执行  
**类型:** 身份验证绕过 / 远程代码执行  
**风险:** 严重，允许未经身份验证的远程攻击者以 SYSTEM 权限执行任意代码。  
**投毒风险:** 5%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-27350](https://github.com/monke443/CVE-2023-27350)  

---

### [CVE-2023-27350](CVE-2023-27350-0xB0y426_CVE-2023-27350-PoC.md) 🔴 ✅

**名称:** CVE-2023-27350-PaperCut NG/MF-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2023-27350-PoC](https://github.com/0xB0y426/CVE-2023-27350-PoC)  

---

### [CVE-2020-0423](CVE-2020-0423-sparrow-labz_CVE-2020-0423.md) 🔴 ✅

**名称:** CVE-2020-0423-Android-Binder-UAF  
**类型:** Use-After-Free  
**风险:** 高危，本地权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-04-14  
**POC仓库:** [CVE-2020-0423](https://github.com/sparrow-labz/CVE-2020-0423)  

---

### [CVE-2023-46818](CVE-2023-46818-ajdumanhug_CVE-2023-46818.md) 🔴 ✅

**名称:** CVE-2023-46818-ISPConfig-PHP代码注入  
**类型:** PHP代码注入  
**风险:** 高危，允许管理员注入并执行任意PHP代码，可能导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2023-46818](https://github.com/ajdumanhug/CVE-2023-46818)  

---

### [CVE-2021-4034](CVE-2021-4034-ikerSandoval003_CVE-2021-4034.md) 🔴 ✅

**名称:** CVE-2021-4034 Polkit pkexec 本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，本地用户可提升至root权限  
**投毒风险:** 5%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2021-4034](https://github.com/ikerSandoval003/CVE-2021-4034)  

---

### [CVE-2025-21298](CVE-2025-21298-mr-big-leach_CVE-2025-21298.md) 🔴 ✅

**名称:** CVE-2025-21298 - Windows OLE Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，CVSS评分9.8，零点击RCE  
**投毒风险:** 0%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2025-21298](https://github.com/mr-big-leach/CVE-2025-21298)  

---

### [CVE-2023-35085](CVE-2023-35085-maoruiQa_CVE-2023-35085-POC-EXP.md) 🔴 ✅

**名称:** CVE-2023-35085 - Ubiquiti UniFi 设备 SNMP 整数溢出远程代码执行  
**类型:** 整数溢出导致远程代码执行  
**风险:** 高危，可被未经授权的攻击者利用，实现远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2023-35085-POC-EXP](https://github.com/maoruiQa/CVE-2023-35085-POC-EXP)  

---

### [CVE-2021-4034](CVE-2021-4034-igonzalez357_CVE-2021-4034-PwnKit-.md) 🔴 ✅

**名称:** CVE-2021-4034 (PwnKit) Polkit pkexec 本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，可使普通用户获得 root 权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2021-4034-PwnKit-](https://github.com/igonzalez357/CVE-2021-4034-PwnKit-)  

---

### [CVE-2021-4034](CVE-2021-4034-marcosChoucino_CVE-2021-4034.md) 🔴 ✅

**名称:** CVE-2021-4034 - polkit pkexec 本地提权  
**类型:** 本地提权  
**风险:** 高危，允许低权限用户获取root权限  
**投毒风险:** 5%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2021-4034](https://github.com/marcosChoucino/CVE-2021-4034)  

---

### [CVE-2023-46818](CVE-2023-46818-bipbopbup_CVE-2023-46818-python-exploit.md) 🔴 ✅

**名称:** CVE-2023-46818-ISPConfig-PHP代码注入  
**类型:** PHP代码注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2023-46818-python-exploit](https://github.com/bipbopbup/CVE-2023-46818-python-exploit)  

---

### [CVE-2023-46818](CVE-2023-46818-blindma1den_CVE-2023-46818-Exploit.md) 🔴 ✅

**名称:** CVE-2023-46818-ISPConfig-PHP代码注入  
**类型:** PHP代码注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2023-46818-Exploit](https://github.com/blindma1den/CVE-2023-46818-Exploit)  

---

### [CVE-2024-0582](CVE-2024-0582-ysanatomic_io_uring_LPE-CVE-2024-0582.md) 🔴 ✅

**名称:** CVE-2024-0582 - Linux Kernel io_uring Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可导致权限提升或系统崩溃  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [io_uring_LPE-CVE-2024-0582](https://github.com/ysanatomic/io_uring_LPE-CVE-2024-0582)  

---

### [CVE-2024-0582](CVE-2024-0582-0ptyx_cve-2024-0582.md) 🔴 ✅

**名称:** CVE-2024-0582 - Linux Kernel io_uring Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可能导致提权和拒绝服务  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [cve-2024-0582](https://github.com/0ptyx/cve-2024-0582)  

---

### [CVE-2024-0582](CVE-2024-0582-geniuszly_CVE-2024-0582.md) 🔴 ✅

**名称:** CVE-2024-0582 - Linux Kernel io_uring Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可能导致权限提升和系统崩溃  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2024-0582](https://github.com/geniuszly/CVE-2024-0582)  

---

### [CVE-2024-0582](CVE-2024-0582-101010zyl_CVE-2024-0582-dataonly.md) 🔴 ✅

**名称:** CVE-2024-0582 - Linux Kernel io_uring Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，本地用户可导致权限提升或系统崩溃  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2024-0582-dataonly](https://github.com/101010zyl/CVE-2024-0582-dataonly)  

---

### [CVE-2024-0582](CVE-2024-0582-kuzeyardabulut_CVE-2024-0582.md) 🔴 ✅

**名称:** CVE-2024-0582-Linux Kernel io_uring Use-After-Free  
**类型:** Use-After-Free  
**风险:** 高危，可能导致权限提升或系统崩溃  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2024-0582](https://github.com/kuzeyardabulut/CVE-2024-0582)  

---

### [CVE-2023-3128](CVE-2023-3128-spyata123_CVE-2023-3128.md) 🔴 ✅

**名称:** CVE-2023-3128-Grafana-账户接管/身份验证绕过  
**类型:** 账户接管/身份验证绕过  
**风险:** 高危，可能导致账户接管、数据泄露、未授权访问  
**投毒风险:** 0%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2023-3128](https://github.com/spyata123/CVE-2023-3128)  

---

### [CVE-2021-4034](CVE-2021-4034-Y3A_CVE-2021-4034.md) 🔴 ✅

**名称:** CVE-2021-4034-Polkit-pkexec本地提权  
**类型:** 本地提权  
**风险:** 高危，允许本地用户获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2021-4034](https://github.com/Y3A/CVE-2021-4034)  

---

### [CVE-2021-4034](CVE-2021-4034-EuJin03_CVE-2021-4034-PoC.md) 🔴 ✅

**名称:** CVE-2021-4034-Polkit-pkexec本地提权  
**类型:** 本地权限提升  
**风险:** 高危，未经授权的用户可以获得root权限  
**投毒风险:** 1%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2021-4034-PoC](https://github.com/EuJin03/CVE-2021-4034-PoC)  

---

### [CVE-2021-4034](CVE-2021-4034-nagorealbisu_CVE-2021-4034.md) 🔴 ✅

**名称:** CVE-2021-4034-Polkit-pkexec本地提权  
**类型:** 本地提权  
**风险:** 高危，允许低权限用户获取root权限  
**投毒风险:** 0%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2021-4034](https://github.com/nagorealbisu/CVE-2021-4034)  

---

### [CVE-2025-29927](CVE-2025-29927-ethanol1310_POC-CVE-2025-29927-.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-Middleware认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [POC-CVE-2025-29927-](https://github.com/ethanol1310/POC-CVE-2025-29927-)  

---

### [CVE-2021-4034](CVE-2021-4034-TheSermux_CVE-2021-4034.md) 🔴 ✅

**名称:** CVE-2021-4034 - Polkit pkexec 本地提权  
**类型:** 本地提权  
**风险:** 高危，允许普通用户获得 root 权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2021-4034](https://github.com/TheSermux/CVE-2021-4034)  

---

### [CVE-2021-4034](CVE-2021-4034-asepsaepdin_CVE-2021-4034.md) 🔴 ✅

**名称:** CVE-2021-4034 (PwnKit)  
**类型:** 本地权限提升  
**风险:** 高危，允许非特权用户获得root权限  
**投毒风险:** 0%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2021-4034](https://github.com/asepsaepdin/CVE-2021-4034)  

---

### [CVE-2021-4034](CVE-2021-4034-JohnGilbert57_CVE-2021-4034-Capture-the-flag.md) 🔴 ✅

**名称:** CVE-2021-4034-Polkit-pkexec本地提权  
**类型:** 本地提权  
**风险:** 高危，允许低权限用户提升为root权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2021-4034-Capture-the-flag](https://github.com/JohnGilbert57/CVE-2021-4034-Capture-the-flag)  

---

### [CVE-2021-4034](CVE-2021-4034-cdxiaodong_CVE-2021-4034-touch.md) 🔴 ✅

**名称:** CVE-2021-4034-Polkit pkexec 本地提权  
**类型:** 本地权限提升  
**风险:** 高危，允许本地普通用户获取root权限  
**投毒风险:** 0%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2021-4034-touch](https://github.com/cdxiaodong/CVE-2021-4034-touch)  

---

### [CVE-2021-4034](CVE-2021-4034-cerodah_CVE-2021-4034.md) 🔴 ✅

**名称:** CVE-2021-4034 - polkit pkexec 本地提权漏洞  
**类型:** 本地权限提升  
**风险:** 高危，允许低权限用户获取 root 权限  
**投毒风险:** 0%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2021-4034](https://github.com/cerodah/CVE-2021-4034)  

---

### [CVE-2021-4034](CVE-2021-4034-Pol-Ruiz_CVE-2021-4034.md) 🔴 ✅

**名称:** CVE-2021-4034-Polkit-pkexec本地提权  
**类型:** 本地权限提升  
**风险:** 高危，可使普通用户获得root权限  
**投毒风险:** 5%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2021-4034](https://github.com/Pol-Ruiz/CVE-2021-4034)  

---

### [CVE-2021-4034](CVE-2021-4034-FancySauce_PwnKit-CVE-2021-4034.md) 🔴 ✅

**名称:** CVE-2021-4034 - polkit pkexec 本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，可使低权限用户获得 root 权限  
**投毒风险:** 0%  
**发现时间:** 2025-04-13  
**POC仓库:** [PwnKit-CVE-2021-4034](https://github.com/FancySauce/PwnKit-CVE-2021-4034)  

---

### [CVE-2021-4034](CVE-2021-4034-mutur4_CVE-2021-4034.md) 🔴 ✅

**名称:** CVE-2021-4034-Polkit-pkexec 本地提权  
**类型:** 本地提权  
**风险:** 高危，可使低权限用户获得root权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2021-4034](https://github.com/mutur4/CVE-2021-4034)  

---

### [CVE-2021-4034](CVE-2021-4034-battleoverflow_CVE-2021-4034.md) 🔴 ✅

**名称:** CVE-2021-4034-Polkit-pkexec本地提权  
**类型:** 本地权限提升  
**风险:** 高危，未经授权的用户可以获得root权限  
**投毒风险:** 5%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2021-4034](https://github.com/battleoverflow/CVE-2021-4034)  

---

### [CVE-2021-4034](CVE-2021-4034-ASG-CASTLE_CVE-2021-4034.md) 🔴 ✅

**名称:** CVE-2021-4034 - Polkit pkexec 本地提权  
**类型:** 本地提权  
**风险:** 高危，允许低权限用户获取 root 权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2021-4034](https://github.com/ASG-CASTLE/CVE-2021-4034)  

---

### [CVE-2021-4034](CVE-2021-4034-Part01-Pai_Polkit-Permission-promotion-compiled.md) 🔴 ✅

**名称:** CVE-2021-4034-Polkit pkexec本地提权  
**类型:** 本地提权  
**风险:** 高危，允许低权限用户获得root权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [Polkit-Permission-promotion-compiled](https://github.com/Part01-Pai/Polkit-Permission-promotion-compiled)  

---

### [CVE-2021-4034](CVE-2021-4034-artemis-mike_cve-2021-4034.md) 🔴 ✅

**名称:** CVE-2021-4034-polkit-pkexec本地提权  
**类型:** 本地权限提升  
**风险:** 高危，允许低权限用户获得root权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [cve-2021-4034](https://github.com/artemis-mike/cve-2021-4034)  

---

### [CVE-2021-4034](CVE-2021-4034-supportingmx_cve-2021-4034.md) 🔴 ✅

**名称:** CVE-2021-4034-Polkit-pkexec本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，允许低权限用户提升到root权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [cve-2021-4034](https://github.com/supportingmx/cve-2021-4034)  

---

### [CVE-2021-4034](CVE-2021-4034-X-Projetion_Exploiting-PwnKit-CVE-2021-4034-.md) 🔴 ✅

**名称:** CVE-2021-4034 - Polkit pkexec 本地提权漏洞 (PwnKit)  
**类型:** 本地提权  
**风险:** 高危，可使低权限用户获得 root 权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [Exploiting-PwnKit-CVE-2021-4034-](https://github.com/X-Projetion/Exploiting-PwnKit-CVE-2021-4034-)  

---

### [CVE-2021-4034](CVE-2021-4034-wechicken456_CVE-2021-4034-CTF-writeup.md) 🔴 ✅

**名称:** CVE-2021-4034 PwnKit 本地权限提升  
**类型:** 本地权限提升  
**风险:** 高危，允许低权限用户获得 root 权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2021-4034-CTF-writeup](https://github.com/wechicken456/CVE-2021-4034-CTF-writeup)  

---

### [CVE-2021-4034](CVE-2021-4034-LucasPDiniz_CVE-2021-4034.md) 🔴 ✅

**名称:** CVE-2021-4034 - Polkit pkexec 本地提权漏洞 (Pwnkit)  
**类型:** 本地权限提升  
**风险:** 高危，允许低权限用户获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2021-4034](https://github.com/LucasPDiniz/CVE-2021-4034)  

---

### [CVE-2021-4034](CVE-2021-4034-evkl1d_CVE-2021-4034.md) 🔴 ✅

**名称:** CVE-2021-4034-polkit-pkexec 本地提权  
**类型:** 本地权限提升  
**风险:** 高危，允许低权限用户获得 root 权限  
**投毒风险:** 0%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2021-4034](https://github.com/evkl1d/CVE-2021-4034)  

---

### [CVE-2021-4034](CVE-2021-4034-Typical0day_CVE-2021-4034.md) 🔴 ✅

**名称:** CVE-2021-4034-Polkit-pkexec本地提权  
**类型:** 本地提权  
**风险:** 高危，允许低权限用户获得root权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2021-4034](https://github.com/Typical0day/CVE-2021-4034)  

---

### [CVE-2021-4034](CVE-2021-4034-ps-interactive_lab_cve-2021-4034-polkit-emulation-and-detection.md) 🔴 ✅

**名称:** CVE-2021-4034-Polkit-pkexec本地提权  
**类型:** 本地权限提升  
**风险:** 高危，允许本地普通用户提升到root权限  
**投毒风险:** 5%  
**发现时间:** 2025-04-13  
**POC仓库:** [lab_cve-2021-4034-polkit-emulation-and-detection](https://github.com/ps-interactive/lab_cve-2021-4034-polkit-emulation-and-detection)  

---

### [CVE-2021-4034](CVE-2021-4034-lsclsclsc_CVE-2021-4034.md) 🔴 ✅

**名称:** CVE-2021-4034 Polkit pkexec 本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，允许低权限用户提升到root权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2021-4034](https://github.com/lsclsclsc/CVE-2021-4034)  

---

### [CVE-2021-4034](CVE-2021-4034-dh4r4_PwnKit-CVE-2021-4034-.md) 🔴 ✅

**名称:** CVE-2021-4034 Polkit pkexec 本地提权漏洞  
**类型:** 本地提权  
**风险:** 高危，允许低权限用户获得root权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [PwnKit-CVE-2021-4034-](https://github.com/dh4r4/PwnKit-CVE-2021-4034-)  

---

### [CVE-2021-4034](CVE-2021-4034-12bijaya_CVE-2021-4034-PwnKit-.md) 🔴 ✅

**名称:** CVE-2021-4034-Polkit-pkexec本地提权  
**类型:** 本地权限提升  
**风险:** 高危，未经授权的用户获得root权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2021-4034-PwnKit-](https://github.com/12bijaya/CVE-2021-4034-PwnKit-)  

---

### [CVE-2024-53591](CVE-2024-53591-aljoharasubaie_CVE-2024-53591.md) 🟡 ✅

**名称:** CVE-2024-53591: Seclore Domain Enumeration  
**类型:** 信息泄露/域枚举  
**风险:** 中危，可能泄露敏感信息，为进一步攻击提供信息  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2024-53591](https://github.com/aljoharasubaie/CVE-2024-53591)  

---

### [CVE-2023-45878](CVE-2023-45878-Can0I0Ever0Enter_CVE-2023-45878.md) 🔴 ✅

**名称:** CVE-2023-45878 - GibbonEdu Gibbon Arbitrary File Write  
**类型:** 任意文件写入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2023-45878](https://github.com/Can0I0Ever0Enter/CVE-2023-45878)  

---

### [CVE-2024-7971](CVE-2024-7971-mistymntncop_CVE-2024-7971.md) 🔴 ✅

**名称:** CVE-2024-7971-Google Chrome-V8类型混淆  
**类型:** 类型混淆  
**风险:** 高危，可能导致堆腐败和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2024-7971](https://github.com/mistymntncop/CVE-2024-7971)  

---

### [CVE-2025-26529](CVE-2025-26529-NightBloodz_moodleTestingEnv.md) 🔴 ✅

**名称:** CVE-2025-26529-Moodle-Stored XSS  
**类型:** Stored XSS  
**风险:** 高危，可能导致账户劫持和恶意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [moodleTestingEnv](https://github.com/NightBloodz/moodleTestingEnv)  

---

### [CVE-2025-26529](CVE-2025-26529-Astroo18_PoC-CVE-2025-26529.md) 🔴 ✅

**名称:** CVE-2025-26529-Moodle-Stored XSS to RCE  
**类型:** Stored XSS  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [PoC-CVE-2025-26529](https://github.com/Astroo18/PoC-CVE-2025-26529)  

---

### [CVE-2018-16763](CVE-2018-16763-dinhbaouit_CVE-2018-16763.md) 🔴 ✅

**名称:** CVE-2018-16763-FUEL CMS-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2018-16763](https://github.com/dinhbaouit/CVE-2018-16763)  

---

### [CVE-2018-16763](CVE-2018-16763-hikarihacks_CVE-2018-16763-exploit.md) 🔴 ✅

**名称:** CVE-2018-16763-Fuel CMS 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可以执行任意代码  
**投毒风险:** 1%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2018-16763-exploit](https://github.com/hikarihacks/CVE-2018-16763-exploit)  

---

### [CVE-2018-16763](CVE-2018-16763-uwueviee_Fu3l-F1lt3r.md) 🔴 ✅

**名称:** CVE-2018-16763-FUEL CMS-PHP代码执行  
**类型:** PHP代码执行  
**风险:** 高危，可能导致远程代码执行和服务器控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [Fu3l-F1lt3r](https://github.com/uwueviee/Fu3l-F1lt3r)  

---

### [CVE-2018-16763](CVE-2018-16763-shoamshilo_Fuel-CMS-Remote-Code-Execution-1.4--RCE--.md) 🔴 ✅

**名称:** CVE-2018-16763-Fuel CMS-RCE  
**类型:** 远程代码执行  
**风险:** 高危，未经授权的远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-13  
**POC仓库:** [Fuel-CMS-Remote-Code-Execution-1.4--RCE--](https://github.com/shoamshilo/Fuel-CMS-Remote-Code-Execution-1.4--RCE--)  

---

### [CVE-2018-16763](CVE-2018-16763-n3m1sys_CVE-2018-16763-Exploit-Python3.md) 🔴 ✅

**名称:** CVE-2018-16763 - Fuel CMS 1.4.1 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可以导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2018-16763-Exploit-Python3](https://github.com/n3m1sys/CVE-2018-16763-Exploit-Python3)  

---

### [CVE-2018-16763](CVE-2018-16763-padsalatushal_CVE-2018-16763.md) 🔴 ✅

**名称:** CVE-2018-16763-Fuel CMS-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可完全控制服务器  
**投毒风险:** 5%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2018-16763](https://github.com/padsalatushal/CVE-2018-16763)  

---

### [CVE-2018-16763](CVE-2018-16763-wizardy0ga_THM-Vulnerability_Capstone-CVE-2018-16763.md) 🔴 ✅

**名称:** CVE-2018-16763-FUEL CMS-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-13  
**POC仓库:** [THM-Vulnerability_Capstone-CVE-2018-16763](https://github.com/wizardy0ga/THM-Vulnerability_Capstone-CVE-2018-16763)  

---

### [CVE-2018-16763](CVE-2018-16763-kxisxr_Bash-Script-CVE-2018-16763.md) 🔴 ✅

**名称:** CVE-2018-16763-FUEL CMS-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-13  
**POC仓库:** [Bash-Script-CVE-2018-16763](https://github.com/kxisxr/Bash-Script-CVE-2018-16763)  

---

### [CVE-2018-16763](CVE-2018-16763-BrunoPincho_cve-2018-16763-rust.md) 🔴 ✅

**名称:** CVE-2018-16763-FUEL CMS-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-04-13  
**POC仓库:** [cve-2018-16763-rust](https://github.com/BrunoPincho/cve-2018-16763-rust)  

---

### [CVE-2018-16763](CVE-2018-16763-not1cyyy_CVE-2018-16763.md) 🔴 ✅

**名称:** CVE-2018-16763-FuelCMS-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2018-16763](https://github.com/not1cyyy/CVE-2018-16763)  

---

### [CVE-2018-16763](CVE-2018-16763-antisecc_CVE-2018-16763.md) 🔴 ✅

**名称:** CVE-2018-16763-Fuel CMS-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可完全控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2018-16763](https://github.com/antisecc/CVE-2018-16763)  

---

### [CVE-2018-16763](CVE-2018-16763-VitoBonetti_CVE-2018-16763.md) 🔴 ✅

**名称:** CVE-2018-16763-FUEL CMS-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2018-16763](https://github.com/VitoBonetti/CVE-2018-16763)  

---

### [CVE-2018-16763](CVE-2018-16763-n3rdh4x0r_CVE-2018-16763.md) 🔴 ✅

**名称:** CVE-2018-16763-FUEL CMS-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2018-16763](https://github.com/n3rdh4x0r/CVE-2018-16763)  

---

### [CVE-2018-16763](CVE-2018-16763-altsun_CVE-2018-16763-FuelCMS-1.4.1-RCE.md) 🔴 ✅

**名称:** CVE-2018-16763-Fuel CMS-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2018-16763-FuelCMS-1.4.1-RCE](https://github.com/altsun/CVE-2018-16763-FuelCMS-1.4.1-RCE)  

---

### [CVE-2018-16763](CVE-2018-16763-p0dalirius_CVE-2018-16763-FuelCMS-1.4.1-RCE.md) 🔴 ✅

**名称:** CVE-2018-16763 - Fuel CMS 1.4.1 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE-2018-16763-FuelCMS-1.4.1-RCE](https://github.com/p0dalirius/CVE-2018-16763-FuelCMS-1.4.1-RCE)  

---

### [CVE-2018-16763](CVE-2018-16763-saccles_CVE_2018_16763_Proof_of_Concept.md) 🔴 ✅

**名称:** CVE-2018-16763-Fuel CMS-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-13  
**POC仓库:** [CVE_2018_16763_Proof_of_Concept](https://github.com/saccles/CVE_2018_16763_Proof_of_Concept)  

---

### [CVE-2018-16763](CVE-2018-16763-ArtemCyberLab_Project-Exploiting-a-Vulnerability-in-Fuel-CMS-CVE-2018-16763-.md) 🔴 ✅

**名称:** CVE-2018-16763 - FUEL CMS 1.4.1 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-13  
**POC仓库:** [Project-Exploiting-a-Vulnerability-in-Fuel-CMS-CVE-2018-16763-](https://github.com/ArtemCyberLab/Project-Exploiting-a-Vulnerability-in-Fuel-CMS-CVE-2018-16763-)  

---

### [CVE-2025-24813](CVE-2025-24813-Mattb709_CVE-2025-24813-PoC-Apache-Tomcat-RCE.md) 🔴 ✅

**名称:** CVE-2025-24813-Apache Tomcat RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-04-12  
**POC仓库:** [CVE-2025-24813-PoC-Apache-Tomcat-RCE](https://github.com/Mattb709/CVE-2025-24813-PoC-Apache-Tomcat-RCE)  

---

### [CVE-2025-24813](CVE-2025-24813-Mattb709_CVE-2025-24813-Scanner.md) 🔴 ✅

**名称:** CVE-2025-24813-Apache Tomcat-路径等价漏洞/反序列化  
**类型:** 路径等价漏洞/反序列化  
**风险:** 高危，可能导致远程代码执行、信息泄露和恶意内容注入  
**投毒风险:** 5%  
**发现时间:** 2025-04-12  
**POC仓库:** [CVE-2025-24813-Scanner](https://github.com/Mattb709/CVE-2025-24813-Scanner)  

---

### [CVE-2024-21754](CVE-2024-21754-CyberSecuritist_CVE-2024-21754-Forti-RCE.md) 🟡 ✅

**名称:** CVE-2024-21754-FortiOS/FortiProxy密码哈希破解  
**类型:** 密码哈希破解  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 80%  
**发现时间:** 2025-04-12  
**POC仓库:** [CVE-2024-21754-Forti-RCE](https://github.com/CyberSecuritist/CVE-2024-21754-Forti-RCE)  

---

### [CVE-2024-21754](CVE-2024-21754-llussiess_CVE-2024-21754.md) 🟡 ✅

**名称:** CVE-2024-21754  
**类型:** 密码哈希算法强度不足  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 70%  
**发现时间:** 2025-04-12  
**POC仓库:** [CVE-2024-21754](https://github.com/llussiess/CVE-2024-21754)  

---

### [CVE-2025-22457](CVE-2025-22457-llussiess_CVE-2025-22457.md) 🔴 ✅

**名称:** CVE-2025-22457 - Ivanti Connect Secure 栈溢出  
**类型:** 栈溢出  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 95%  
**发现时间:** 2025-04-12  
**POC仓库:** [CVE-2025-22457](https://github.com/llussiess/CVE-2025-22457)  

---

### [CVE-2014-6271](CVE-2014-6271-cyberharsh_Shellbash-CVE-2014-6271.md) 🔴 ✅

**名称:** CVE-2014-6271 Shellshock  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统控制  
**投毒风险:** 1%  
**发现时间:** 2025-04-12  
**POC仓库:** [Shellbash-CVE-2014-6271](https://github.com/cyberharsh/Shellbash-CVE-2014-6271)  

---

### [CVE-2014-6271](CVE-2014-6271-cved-sources_cve-2014-6271.md) 🔴 ✅

**名称:** CVE-2014-6271-ShellShock  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-12  
**POC仓库:** [cve-2014-6271](https://github.com/cved-sources/cve-2014-6271)  

---

### [CVE-2014-6271](CVE-2014-6271-mochizuki875_CVE-2014-6271-Apache-Debian.md) 🔴 ✅

**名称:** CVE-2014-6271-Apache-Debian Shellshock  
**类型:** 远程代码执行  
**风险:** 高危，允许远程攻击者执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-04-12  
**POC仓库:** [CVE-2014-6271-Apache-Debian](https://github.com/mochizuki875/CVE-2014-6271-Apache-Debian)  

---

### [CVE-2014-6271](CVE-2014-6271-b4keSn4ke_CVE-2014-6271.md) 🔴 ✅

**名称:** CVE-2014-6271 - Shellshock  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-12  
**POC仓库:** [CVE-2014-6271](https://github.com/b4keSn4ke/CVE-2014-6271)  

---

### [CVE-2014-6271](CVE-2014-6271-akr3ch_CVE-2014-6271.md) 🔴 ✅

**名称:** CVE-2014-6271 ShellShock  
**类型:** 远程代码执行  
**风险:** 高危，允许远程攻击者通过构造的恶意环境变量执行任意代码。  
**投毒风险:** 0%  
**发现时间:** 2025-04-12  
**POC仓库:** [CVE-2014-6271](https://github.com/akr3ch/CVE-2014-6271)  

---

### [CVE-2014-6271](CVE-2014-6271-anujbhan_shellshock-victim-host.md) 🔴 ✅

**名称:** CVE-2014-6271-Shellshock  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-12  
**POC仓库:** [shellshock-victim-host](https://github.com/anujbhan/shellshock-victim-host)  

---

### [CVE-2014-6271](CVE-2014-6271-Gurguii_cgi-bin-shellshock.md) 🔴 ✅

**名称:** CVE-2014-6271 Shellshock  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-12  
**POC仓库:** [cgi-bin-shellshock](https://github.com/Gurguii/cgi-bin-shellshock)  

---

### [CVE-2014-6271](CVE-2014-6271-FilipStudeny_-CVE-2014-6271-Shellshock-Remote-Command-Injection-.md) 🔴 ✅

**名称:** CVE-2014-6271 Shellshock  
**类型:** 远程命令执行  
**风险:** 高危，可能导致远程代码执行和系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-12  
**POC仓库:** [-CVE-2014-6271-Shellshock-Remote-Command-Injection-](https://github.com/FilipStudeny/-CVE-2014-6271-Shellshock-Remote-Command-Injection-)  

---

### [CVE-2014-6271](CVE-2014-6271-hadrian3689_shellshock.md) 🔴 ✅

**名称:** CVE-2014-6271 Shellshock  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行，系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-12  
**POC仓库:** [shellshock](https://github.com/hadrian3689/shellshock)  

---

### [CVE-2014-6271](CVE-2014-6271-mritunjay-k_CVE-2014-6271.md) 🔴 ✅

**名称:** CVE-2014-6271 ShellShock  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-12  
**POC仓库:** [CVE-2014-6271](https://github.com/mritunjay-k/CVE-2014-6271)  

---

### [CVE-2014-6271](CVE-2014-6271-Brandaoo_CVE-2014-6271.md) 🔴 ✅

**名称:** CVE-2014-6271-Shellshock  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-12  
**POC仓库:** [CVE-2014-6271](https://github.com/Brandaoo/CVE-2014-6271)  

---

### [CVE-2014-6271](CVE-2014-6271-opsxcq_exploit-CVE-2014-6271.md) 🔴 ✅

**名称:** CVE-2014-6271 ShellShock  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-12  
**POC仓库:** [exploit-CVE-2014-6271](https://github.com/opsxcq/exploit-CVE-2014-6271)  

---

### [CVE-2014-6271](CVE-2014-6271-hanmin0512_CVE-2014-6271_pwnable.md) 🔴 ✅

**名称:** CVE-2014-6271 Shellshock  
**类型:** 命令注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-12  
**POC仓库:** [CVE-2014-6271_pwnable](https://github.com/hanmin0512/CVE-2014-6271_pwnable)  

---

### [CVE-2014-6271](CVE-2014-6271-0xN7y_CVE-2014-6271.md) 🔴 ✅

**名称:** CVE-2014-6271 ShellShock  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和系统控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-12  
**POC仓库:** [CVE-2014-6271](https://github.com/0xN7y/CVE-2014-6271)  

---

### [CVE-2014-6271](CVE-2014-6271-ajansha_shellshock.md) 🔴 ✅

**名称:** CVE-2014-6271 Shellshock  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-12  
**POC仓库:** [shellshock](https://github.com/ajansha/shellshock)  

---

### [CVE-2014-6271](CVE-2014-6271-K3ysTr0K3R_CVE-2014-6271-EXPLOIT.md) 🔴 ✅

**名称:** CVE-2014-6271-Shellshock  
**类型:** 远程代码执行  
**风险:** 高危，允许远程攻击者通过构造的环境变量执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-04-12  
**POC仓库:** [CVE-2014-6271-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2014-6271-EXPLOIT)  

---

### [CVE-2014-6271](CVE-2014-6271-AlissonFaoli_Shellshock.md) 🔴 ✅

**名称:** CVE-2014-6271 Shellshock  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程攻击者在受影响的系统上执行任意代码。  
**投毒风险:** 5%  
**发现时间:** 2025-04-12  
**POC仓库:** [Shellshock](https://github.com/AlissonFaoli/Shellshock)  

---

### [CVE-2014-6271](CVE-2014-6271-TheRealCiscoo_Shellshock-Exploit.md) 🔴 ✅

**名称:** CVE-2014-6271 ShellShock  
**类型:** 远程命令执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-12  
**POC仓库:** [Shellshock-Exploit](https://github.com/TheRealCiscoo/Shellshock-Exploit)  

---

### [CVE-2014-6271](CVE-2014-6271-Jsmoreira02_CVE-2014-6271.md) 🔴 ✅

**名称:** CVE-2014-6271 Shellshock  
**类型:** 远程命令执行  
**风险:** 高危，允许远程攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-12  
**POC仓库:** [CVE-2014-6271](https://github.com/Jsmoreira02/CVE-2014-6271)  

---

### [CVE-2014-6271](CVE-2014-6271-RadYio_CVE-2014-6271.md) 🔴 ✅

**名称:** CVE-2014-6271 - Shellshock  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-12  
**POC仓库:** [CVE-2014-6271](https://github.com/RadYio/CVE-2014-6271)  

---

### [CVE-2014-6271](CVE-2014-6271-YunchoHang_CVE-2014-6271-SHELLSHOCK.md) 🔴 ✅

**名称:** CVE-2014-6271 Shellshock  
**类型:** 命令注入  
**风险:** 高危，允许远程攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-12  
**POC仓库:** [CVE-2014-6271-SHELLSHOCK](https://github.com/YunchoHang/CVE-2014-6271-SHELLSHOCK)  

---

### [CVE-2024-42008](CVE-2024-42008-victoni_Roundcube-CVE-2024-42008-and-CVE-2024-42010-POC.md) 🔴 ✅

**名称:** CVE-2024-42008 - Roundcube Cross-Site Scripting (XSS)  
**类型:** Cross-Site Scripting (XSS)  
**风险:** 高危，可能导致用户邮箱信息泄露、控制用户邮箱、发送恶意邮件等。  
**投毒风险:** 0%  
**发现时间:** 2025-04-12  
**POC仓库:** [Roundcube-CVE-2024-42008-and-CVE-2024-42010-POC](https://github.com/victoni/Roundcube-CVE-2024-42008-and-CVE-2024-42010-POC)  

---

### [CVE-2024-4577](CVE-2024-4577-sug4r-wr41th_CVE-2024-4577.md) 🔴 ✅

**名称:** CVE-2024-4577-PHP-CGI参数注入  
**类型:** 参数注入/远程代码执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-12  
**POC仓库:** [CVE-2024-4577](https://github.com/sug4r-wr41th/CVE-2024-4577)  

---

### [CVE-2023-28121](CVE-2023-28121-gbrsh_CVE-2023-28121.md) 🔴 ✅

**名称:** CVE-2023-28121-WooCommerce Payments-权限提升  
**类型:** 权限提升  
**风险:** 高危，可使未经身份验证的攻击者获得管理员权限  
**投毒风险:** 0%  
**发现时间:** 2025-04-12  
**POC仓库:** [CVE-2023-28121](https://github.com/gbrsh/CVE-2023-28121)  

---

### [CVE-2023-28121](CVE-2023-28121-rio128128_Mass-CVE-2023-28121-kdoec.md) 🔴 ✅

**名称:** CVE-2023-28121-WooCommerce Payments插件-权限绕过  
**类型:** 权限绕过  
**风险:** 高危，可能导致管理员权限获取  
**投毒风险:** 0%  
**发现时间:** 2025-04-12  
**POC仓库:** [Mass-CVE-2023-28121-kdoec](https://github.com/rio128128/Mass-CVE-2023-28121-kdoec)  

---

### [CVE-2023-28121](CVE-2023-28121-im-hanzou_Mass-CVE-2023-28121.md) 🔴 ✅

**名称:** CVE-2023-28121-WooCommerce Payments-未授权提权  
**类型:** 未授权提权  
**风险:** 高危，可使未授权的攻击者获得管理员权限  
**投毒风险:** 0%  
**发现时间:** 2025-04-12  
**POC仓库:** [Mass-CVE-2023-28121](https://github.com/im-hanzou/Mass-CVE-2023-28121)  

---

### [CVE-2023-28121](CVE-2023-28121-1337nemojj_CVE-2023-28121.md) 🔴 ✅

**名称:** CVE-2023-28121-WooCommerce Payments 插件未授权提权  
**类型:** 权限提升  
**风险:** 高危，未经身份验证的攻击者可以发送代表具有提升权限（如管理员）的用户发出的请求，从而获得管理员访问权限。  
**投毒风险:** 10%  
**发现时间:** 2025-04-12  
**POC仓库:** [CVE-2023-28121](https://github.com/1337nemojj/CVE-2023-28121)  

---

### [CVE-2023-28121](CVE-2023-28121-Jenderal92_WP-CVE-2023-28121.md) 🔴 ✅

**名称:** CVE-2023-28121 - WooCommerce Payments Plugin 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致网站完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-04-12  
**POC仓库:** [WP-CVE-2023-28121](https://github.com/Jenderal92/WP-CVE-2023-28121)  

---

### [CVE-2023-28121](CVE-2023-28121-sug4r-wr41th_CVE-2023-28121.md) 🔴 ✅

**名称:** CVE-2023-28121 - WooCommerce Payments 插件权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，允许未授权攻击者获取管理员权限  
**投毒风险:** 0%  
**发现时间:** 2025-04-12  
**POC仓库:** [CVE-2023-28121](https://github.com/sug4r-wr41th/CVE-2023-28121)  

---

### [CVE-2011-2523](CVE-2011-2523-sug4r-wr41th_CVE-2011-2523.md) 🔴 ✅

**名称:** CVE-2011-2523-vsftpd-后门  
**类型:** 后门  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-12  
**POC仓库:** [CVE-2011-2523](https://github.com/sug4r-wr41th/CVE-2011-2523)  

---

### [CVE-2023-1177](CVE-2023-1177-iumiro_CVE-2023-1177-MLFlow.md) 🔴 ✅

**名称:** CVE-2023-1177-mlflow-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-12  
**POC仓库:** [CVE-2023-1177-MLFlow](https://github.com/iumiro/CVE-2023-1177-MLFlow)  

---

### [CVE-2023-1177](CVE-2023-1177-SpycioKon_CVE-2023-1177-rebuild.md) 🔴 ✅

**名称:** CVE-2023-1177-mlflow-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-04-12  
**POC仓库:** [CVE-2023-1177-rebuild](https://github.com/SpycioKon/CVE-2023-1177-rebuild)  

---

### [CVE-2023-1177](CVE-2023-1177-hh-hunter_ml-CVE-2023-1177.md) 🔴 ✅

**名称:** CVE-2023-1177-mlflow-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感文件泄露和一定程度的完整性破坏  
**投毒风险:** 0%  
**发现时间:** 2025-04-12  
**POC仓库:** [ml-CVE-2023-1177](https://github.com/hh-hunter/ml-CVE-2023-1177)  

---

### [CVE-2023-1177](CVE-2023-1177-saimahmed_MLflow-Vuln.md) 🔴 ✅

**名称:** CVE-2023-1177-MLflow-路径遍历  
**类型:** 路径遍历/本地文件包含(LFI)/远程文件包含(RFI)  
**风险:** 高危，可能导致敏感信息泄露、系统文件访问、甚至系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-12  
**POC仓库:** [MLflow-Vuln](https://github.com/saimahmed/MLflow-Vuln)  

---

### [CVE-2023-1177](CVE-2023-1177-charlesgargasson_CVE-2023-1177.md) 🔴 ✅

**名称:** CVE-2023-1177-mlflow-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感文件泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-12  
**POC仓库:** [CVE-2023-1177](https://github.com/charlesgargasson/CVE-2023-1177)  

---

### [CVE-2023-1177](CVE-2023-1177-paultheal1en_CVE-2023-1177-PoC-reproduce.md) 🔴 ✅

**名称:** CVE-2023-1177-MLflow-Path Traversal  
**类型:** Path Traversal/Local File Inclusion (LFI)  
**风险:** 高危，可能导致敏感信息泄露和部分完整性破坏  
**投毒风险:** 5%  
**发现时间:** 2025-04-12  
**POC仓库:** [CVE-2023-1177-PoC-reproduce](https://github.com/paultheal1en/CVE-2023-1177-PoC-reproduce)  

---

### [CVE-2025-3102](CVE-2025-3102-xxmarcosrobertoxx_vanda-CVE-2025-3102.md) 🔴 ✅

**名称:** CVE-2025-3102-SureTriggers-权限绕过  
**类型:** 权限绕过  
**风险:** 高危，可能导致创建管理员账户并完全控制网站  
**投毒风险:** 10%  
**发现时间:** 2025-04-12  
**POC仓库:** [vanda-CVE-2025-3102](https://github.com/xxmarcosrobertoxx/vanda-CVE-2025-3102)  

---

### [CVE-2024-36991](CVE-2024-36991-xploitnik_CVE-2024-36991-modified.md) 🔴 ✅

**名称:** CVE-2024-36991 - Splunk Enterprise Windows 路径遍历  
**类型:** 路径遍历  
**风险:** 高危，允许未经身份验证的攻击者读取服务器上的任意文件，可能包含敏感信息如密码、配置信息等  
**投毒风险:** 10%  
**发现时间:** 2025-04-12  
**POC仓库:** [CVE-2024-36991-modified](https://github.com/xploitnik/CVE-2024-36991-modified)  

---

### [CVE-2016-6210](CVE-2016-6210-nicoleman0_CVE-2016-6210-OpenSSHd-7.2p2.md) 🟡 ✅

**名称:** CVE-2016-6210 OpenSSH 用户枚举漏洞  
**类型:** 信息泄露/用户枚举  
**风险:** 中危，允许攻击者枚举系统上的有效用户名  
**投毒风险:** 0%  
**发现时间:** 2025-04-12  
**POC仓库:** [CVE-2016-6210-OpenSSHd-7.2p2](https://github.com/nicoleman0/CVE-2016-6210-OpenSSHd-7.2p2)  

---

### [CVE-2025-29927](CVE-2025-29927-darklotuskdb_nextjs-CVE-2025-29927-hunter.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-中间件授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-11  
**POC仓库:** [nextjs-CVE-2025-29927-hunter](https://github.com/darklotuskdb/nextjs-CVE-2025-29927-hunter)  

---

### [CVE-2023-20198](CVE-2023-20198-Tounsi007_CVE-2023-20198.md) 🔴 ✅

**名称:** CVE-2023-20198 - Cisco IOS XE Web UI 权限提升  
**类型:** 权限提升  
**风险:** 高危，可能导致完全控制受影响设备  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2023-20198](https://github.com/Tounsi007/CVE-2023-20198)  

---

### [CVE-2025-26865](CVE-2025-26865-mbadanoiu_CVE-2025-26865.md) 🔴 ✅

**名称:** CVE-2025-26865: Apache OFBiz FreeMarker Server-Side Template Injection  
**类型:** 服务器端模板注入 (SSTI)  
**风险:** 高危，可能导致远程代码执行 (RCE)  
**投毒风险:** 1%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2025-26865](https://github.com/mbadanoiu/CVE-2025-26865)  

---

### [CVE-2021-24006](CVE-2021-24006-cnetsec_CVE-2021-24006-Fortimanager-Exploit.md) 🟡 ✅

**名称:** CVE-2021-24006 - FortiManager Improper Access Control  
**类型:** 不当访问控制  
**风险:** 中危，可能导致未经授权的访问和信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2021-24006-Fortimanager-Exploit](https://github.com/cnetsec/CVE-2021-24006-Fortimanager-Exploit)  

---

### [CVE-2025-28346](CVE-2025-28346-Shubham03007_CVE-2025-28346.md) 🔴 ✅

**名称:** CVE-2025-28346-Ticket-Booking-App-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2025-28346](https://github.com/Shubham03007/CVE-2025-28346)  

---

### [CVE-2023-20198](CVE-2023-20198-raystr-atearedteam_CVE-2023-20198-checker.md) 🔴 ✅

**名称:** CVE-2023-20198-Cisco IOS XE Software Web UI Privilege Escalation  
**类型:** 权限提升  
**风险:** 高危，可能导致完全控制受影响的设备  
**投毒风险:** 5%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2023-20198-checker](https://github.com/raystr-atearedteam/CVE-2023-20198-checker)  

---

### [CVE-2023-20198](CVE-2023-20198-emomeni_Simple-Ansible-for-CVE-2023-20198.md) 🔴 ✅

**名称:** CVE-2023-20198 - Cisco IOS XE Web UI 权限提升  
**类型:** 权限提升  
**风险:** 高危，可导致完全控制受影响的设备  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [Simple-Ansible-for-CVE-2023-20198](https://github.com/emomeni/Simple-Ansible-for-CVE-2023-20198)  

---

### [CVE-2023-20198](CVE-2023-20198-JoyGhoshs_CVE-2023-20198.md) 🔴 ✅

**名称:** CVE-2023-20198-Cisco IOS XE Web UI权限提升  
**类型:** 权限提升  
**风险:** 高危，可导致完全控制受影响设备  
**投毒风险:** 0%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2023-20198](https://github.com/JoyGhoshs/CVE-2023-20198)  

---

### [CVE-2023-20198](CVE-2023-20198-reket99_Cisco_CVE-2023-20198.md) 🔴 ✅

**名称:** CVE-2023-20198-Cisco IOS XE Web UI 权限提升  
**类型:** 权限提升  
**风险:** 高危，可导致完全控制受影响的Cisco IOS XE设备  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [Cisco_CVE-2023-20198](https://github.com/reket99/Cisco_CVE-2023-20198)  

---

### [CVE-2023-20198](CVE-2023-20198-securityphoenix_cisco-CVE-2023-20198-tester.md) 🔴 ✅

**名称:** CVE-2023-20198-Cisco IOS XE Web UI权限提升  
**类型:** 权限提升  
**风险:** 高危，允许未授权的攻击者创建具有特权15的本地用户，从而完全控制设备  
**投毒风险:** 1%  
**发现时间:** 2025-04-11  
**POC仓库:** [cisco-CVE-2023-20198-tester](https://github.com/securityphoenix/cisco-CVE-2023-20198-tester)  

---

### [CVE-2023-20198](CVE-2023-20198-iveresk_cve-2023-20198.md) 🔴 ✅

**名称:** CVE-2023-20198-Cisco IOS XE Software Web UI 权限提升  
**类型:** 权限提升  
**风险:** 高危，可完全控制受影响的Cisco IOS XE设备  
**投毒风险:** 5%  
**发现时间:** 2025-04-11  
**POC仓库:** [cve-2023-20198](https://github.com/iveresk/cve-2023-20198)  

---

### [CVE-2023-20198](CVE-2023-20198-ZephrFish_CVE-2023-20198-Checker.md) 🔴 ✅

**名称:** CVE-2023-20198 - Cisco IOS XE Web UI 权限提升  
**类型:** 权限提升  
**风险:** 高危，允许未授权的远程攻击者创建具有特权15权限的本地用户，随后可能被用于植入后门和完全控制设备  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2023-20198-Checker](https://github.com/ZephrFish/CVE-2023-20198-Checker)  

---

### [CVE-2023-20198](CVE-2023-20198-Pushkarup_CVE-2023-20198.md) 🔴 ✅

**名称:** CVE-2023-20198 - Cisco IOS XE Web UI 权限提升  
**类型:** 权限提升  
**风险:** 高危，允许未授权的远程攻击者创建管理员账户并完全控制设备  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2023-20198](https://github.com/Pushkarup/CVE-2023-20198)  

---

### [CVE-2023-20198](CVE-2023-20198-Atea-Redteam_CVE-2023-20198.md) 🔴 ✅

**名称:** CVE-2023-20198 - Cisco IOS XE Software Web UI权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，未经身份验证的攻击者可以创建具有特权级别15访问权限的帐户，并最终导致完全控制受影响的系统。  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2023-20198](https://github.com/Atea-Redteam/CVE-2023-20198)  

---

### [CVE-2023-20198](CVE-2023-20198-kacem-expereo_CVE-2023-20198.md) 🔴 ✅

**名称:** CVE-2023-20198-Cisco IOS XE Web UI 权限提升  
**类型:** 权限提升  
**风险:** 高危，可被未授权的攻击者利用创建具有特权 15 的本地用户，为进一步攻击（如植入后门）铺平道路。  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2023-20198](https://github.com/kacem-expereo/CVE-2023-20198)  

---

### [CVE-2023-20198](CVE-2023-20198-Shadow0ps_CVE-2023-20198-Scanner.md) 🔴 ✅

**名称:** CVE-2023-20198 Cisco IOS XE Web UI 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，允许未授权的远程攻击者创建具有特权 15 权限的本地用户，从而完全控制受影响的设备。  
**投毒风险:** 20%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2023-20198-Scanner](https://github.com/Shadow0ps/CVE-2023-20198-Scanner)  

---

### [CVE-2023-20198](CVE-2023-20198-mr-r3b00t_CVE-2023-20198-IOS-XE-Scanner.md) 🔴 ✅

**名称:** CVE-2023-20198-Cisco IOS XE Web UI权限提升  
**类型:** 权限提升  
**风险:** 高危，允许未授权的攻击者创建具有特权15权限的本地用户，进而控制设备。  
**投毒风险:** 0%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2023-20198-IOS-XE-Scanner](https://github.com/mr-r3b00t/CVE-2023-20198-IOS-XE-Scanner)  

---

### [CVE-2023-20198](CVE-2023-20198-ohlawd_CVE-2023-20198.md) 🔴 ✅

**名称:** CVE-2023-20198-Cisco IOS XE Software Web UI权限提升  
**类型:** 权限提升  
**风险:** 高危，可导致完全控制受影响系统  
**投毒风险:** 100%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2023-20198](https://github.com/ohlawd/CVE-2023-20198)  

---

### [CVE-2023-20198](CVE-2023-20198-IceBreakerCode_CVE-2023-20198.md) 🔴 ✅

**名称:** CVE-2023-20198 - Cisco IOS XE Web UI 权限提升  
**类型:** 权限提升  
**风险:** 高危，允许未授权的远程攻击者创建具有特权级别 15 的帐户，从而完全控制设备  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2023-20198](https://github.com/IceBreakerCode/CVE-2023-20198)  

---

### [CVE-2023-20198](CVE-2023-20198-alekos3_CVE_2023_20198_Detector.md) 🔴 ✅

**名称:** CVE-2023-20198-Cisco IOS XE Software Web UI权限提升  
**类型:** 权限提升  
**风险:** 高危，可完全控制受影响系统  
**投毒风险:** 0%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE_2023_20198_Detector](https://github.com/alekos3/CVE_2023_20198_Detector)  

---

### [CVE-2023-20198](CVE-2023-20198-RevoltSecurities_CVE-2023-20198.md) 🔴 ✅

**名称:** CVE-2023-20198-Cisco IOS XE Web UI 权限提升  
**类型:** 权限提升  
**风险:** 高危，可被未授权的攻击者利用创建特权用户，进而完全控制系统。  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2023-20198](https://github.com/RevoltSecurities/CVE-2023-20198)  

---

### [CVE-2023-20198](CVE-2023-20198-fox-it_cisco-ios-xe-implant-detection.md) 🔴 ✅

**名称:** CVE-2023-20198-Cisco IOS XE Software Web UI 权限提升  
**类型:** 权限提升  
**风险:** 高危，允许未经身份验证的攻击者创建具有特权15的本地用户，最终导致完全控制受影响的设备  
**投毒风险:** 0%  
**发现时间:** 2025-04-11  
**POC仓库:** [cisco-ios-xe-implant-detection](https://github.com/fox-it/cisco-ios-xe-implant-detection)  

---

### [CVE-2023-20198](CVE-2023-20198-smokeintheshell_CVE-2023-20198.md) 🔴 ✅

**名称:** CVE-2023-20198 - Cisco IOS XE Web UI 权限提升  
**类型:** 权限提升  
**风险:** 高危，允许未授权用户创建特权用户并执行任意命令  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2023-20198](https://github.com/smokeintheshell/CVE-2023-20198)  

---

### [CVE-2023-20198](CVE-2023-20198-netbell_CVE-2023-20198-Fix.md) 🔴 ✅

**名称:** CVE-2023-20198-Cisco IOS XE Web UI 权限提升  
**类型:** 权限提升  
**风险:** 高危，允许未授权远程攻击者创建特权15用户并控制设备  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2023-20198-Fix](https://github.com/netbell/CVE-2023-20198-Fix)  

---

### [CVE-2023-20198](CVE-2023-20198-Vulnmachines_Cisco_CVE-2023-20198.md) 🔴 ✅

**名称:** CVE-2023-20198-Cisco IOS XE Web UI 权限提升  
**类型:** 权限提升  
**风险:** 高危，可使未授权的攻击者获得完全管理权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [Cisco_CVE-2023-20198](https://github.com/Vulnmachines/Cisco_CVE-2023-20198)  

---

### [CVE-2023-20198](CVE-2023-20198-W01fh4cker_CVE-2023-20198-RCE.md) 🔴 ✅

**名称:** CVE-2023-20198-Cisco IOS XE Web UI 权限提升  
**类型:** 权限提升  
**风险:** 高危，允许未授权的远程攻击者创建具有特权15的用户，进而完全控制受影响的设备。  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2023-20198-RCE](https://github.com/W01fh4cker/CVE-2023-20198-RCE)  

---

### [CVE-2023-20198](CVE-2023-20198-sanan2004_CVE-2023-20198.md) 🔴 ✅

**名称:** CVE-2023-20198 - Cisco IOS XE Web UI 权限提升  
**类型:** 权限提升  
**风险:** 高危，可完全控制受影响的系统  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2023-20198](https://github.com/sanan2004/CVE-2023-20198)  

---

### [CVE-2023-20198](CVE-2023-20198-XiaomingX_cve-2023-20198-poc.md) 🔴 ✅

**名称:** CVE-2023-20198-Cisco IOS XE Web UI 权限提升  
**类型:** 权限提升  
**风险:** 高危，可完全控制受影响设备  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [cve-2023-20198-poc](https://github.com/XiaomingX/cve-2023-20198-poc)  

---

### [CVE-2023-20198](CVE-2023-20198-sohaibeb_CVE-2023-20198.md) 🔴 ✅

**名称:** CVE-2023-20198 - Cisco IOS XE Web UI 权限提升  
**类型:** 权限提升  
**风险:** 高危，可被未授权的攻击者利用创建高权限用户并控制设备  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2023-20198](https://github.com/sohaibeb/CVE-2023-20198)  

---

### [CVE-2023-20198](CVE-2023-20198-G4sul1n_Cisco-IOS-XE-CVE-2023-20198.md) 🔴 ✅

**名称:** CVE-2023-20198 - Cisco IOS XE Web UI 权限提升  
**类型:** 权限提升  
**风险:** 高危，允许未授权的远程攻击者创建具有特权15权限的本地用户，结合CVE-2023-20273可提升至root权限并植入后门。  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [Cisco-IOS-XE-CVE-2023-20198](https://github.com/G4sul1n/Cisco-IOS-XE-CVE-2023-20198)  

---

### [CVE-2024-55591](CVE-2024-55591-virus-or-not_CVE-2024-55591.md)  ✅

**名称:** CVE-2024-55591-FortiOS/FortiProxy-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 严重，可能导致超级管理员权限获取  
**投毒风险:** 1%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2024-55591](https://github.com/virus-or-not/CVE-2024-55591)  

---

### [CVE-2024-55591](CVE-2024-55591-0x7556_CVE-2024-55591.md)  ✅

**名称:** CVE-2024-55591  
**类型:** 身份验证绕过  
**风险:** 严重，允许未经身份验证的远程攻击者获取超级管理员权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2024-55591](https://github.com/0x7556/CVE-2024-55591)  

---

### [CVE-2024-55591](CVE-2024-55591-binarywarm_exp-cmd-add-admin-vpn-CVE-2024-55591.md) 🔴 ✅

**名称:** CVE-2024-55591 - FortiOS/FortiProxy 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，允许未授权的远程攻击者获得超级管理员权限  
**投毒风险:** 20%  
**发现时间:** 2025-04-11  
**POC仓库:** [exp-cmd-add-admin-vpn-CVE-2024-55591](https://github.com/binarywarm/exp-cmd-add-admin-vpn-CVE-2024-55591)  

---

### [CVE-2019-10149](CVE-2019-10149-uyerr_PoC_CVE-2019-10149--rce.md) 🔴 ✅

**名称:** CVE-2019-10149 - Exim Remote Command Execution  
**类型:** 远程命令执行  
**风险:** 高危，允许未经身份验证的远程攻击者在受影响的系统上执行任意命令。  
**投毒风险:** 0%  
**发现时间:** 2025-04-11  
**POC仓库:** [PoC_CVE-2019-10149--rce](https://github.com/uyerr/PoC_CVE-2019-10149--rce)  

---

### [CVE-2019-10149](CVE-2019-10149-bananaphones_exim-rce-quickfix.md) 🔴 ✅

**名称:** CVE-2019-10149-Exim-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 70%  
**发现时间:** 2025-04-11  
**POC仓库:** [exim-rce-quickfix](https://github.com/bananaphones/exim-rce-quickfix)  

---

### [CVE-2019-10149](CVE-2019-10149-aishee_CVE-2019-10149-quick.md) 🔴 ✅

**名称:** CVE-2019-10149-Exim-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2019-10149-quick](https://github.com/aishee/CVE-2019-10149-quick)  

---

### [CVE-2019-10149](CVE-2019-10149-MNEMO-CERT_PoC--CVE-2019-10149_Exim.md) 🔴 ✅

**名称:** CVE-2019-10149 Exim RCE  
**类型:** 远程命令执行  
**风险:** 高危，可完全控制受影响的服务器  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [PoC--CVE-2019-10149_Exim](https://github.com/MNEMO-CERT/PoC--CVE-2019-10149_Exim)  

---

### [CVE-2019-10149](CVE-2019-10149-AzizMea_CVE-2019-10149-privilege-escalation.md) 🔴 ✅

**名称:** CVE-2019-10149-Exim-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2019-10149-privilege-escalation](https://github.com/AzizMea/CVE-2019-10149-privilege-escalation)  

---

### [CVE-2019-10149](CVE-2019-10149-cowbe0x004_eximrce-CVE-2019-10149.md) 🔴 ✅

**名称:** CVE-2019-10149-Exim-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致远程命令执行和系统被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [eximrce-CVE-2019-10149](https://github.com/cowbe0x004/eximrce-CVE-2019-10149)  

---

### [CVE-2019-10149](CVE-2019-10149-Brets0150_StickyExim.md) 🔴 ✅

**名称:** CVE-2019-10149 Exim RCE HoneyPot  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [StickyExim](https://github.com/Brets0150/StickyExim)  

---

### [CVE-2019-10149](CVE-2019-10149-Chris-dev1_exim.exp.md) 🔴 ✅

**名称:** CVE-2019-10149-Exim-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致完全控制受影响的服务器  
**投毒风险:** 0%  
**发现时间:** 2025-04-11  
**POC仓库:** [exim.exp](https://github.com/Chris-dev1/exim.exp)  

---

### [CVE-2019-10149](CVE-2019-10149-Dilshan-Eranda_CVE-2019-10149.md) 🔴 ✅

**名称:** CVE-2019-10149-Exim-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致远程代码执行，完全控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2019-10149](https://github.com/Dilshan-Eranda/CVE-2019-10149)  

---

### [CVE-2019-10149](CVE-2019-10149-Diefunction_CVE-2019-10149.md) 🔴 ✅

**名称:** CVE-2019-10149-Exim-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2019-10149](https://github.com/Diefunction/CVE-2019-10149)  

---

### [CVE-2019-10149](CVE-2019-10149-Stick-U235_CVE-2019-10149-Exploit.md) 🔴 ✅

**名称:** CVE-2019-10149-Exim-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致远程代码执行和系统完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2019-10149-Exploit](https://github.com/Stick-U235/CVE-2019-10149-Exploit)  

---

### [CVE-2019-10149](CVE-2019-10149-rahmadsandy_EXIM-4.87-CVE-2019-10149.md) 🔴 ✅

**名称:** CVE-2019-10149 Exim Remote Command Execution  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [EXIM-4.87-CVE-2019-10149](https://github.com/rahmadsandy/EXIM-4.87-CVE-2019-10149)  

---

### [CVE-2019-10149](CVE-2019-10149-darsigovrustam_CVE-2019-10149.md) 🔴 ✅

**名称:** CVE-2019-10149 - Exim deliver_message() 远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2019-10149](https://github.com/darsigovrustam/CVE-2019-10149)  

---

### [CVE-2019-10149](CVE-2019-10149-hyim0810_CVE-2019-10149.md) 🔴 ✅

**名称:** CVE-2019-10149 - Exim deliver_message() Remote Command Execution  
**类型:** 远程代码执行  
**风险:** 高危，可导致远程代码执行和系统完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2019-10149](https://github.com/hyim0810/CVE-2019-10149)  

---

### [CVE-2019-10149](CVE-2019-10149-qlusec_CVE-2019-10149.md) 🔴 ✅

**名称:** CVE-2019-10149-Exim-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可远程执行任意命令  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2019-10149](https://github.com/qlusec/CVE-2019-10149)  

---

### [CVE-2019-10149](CVE-2019-10149-cloudflare_exim-cve-2019-10149-data.md) 🔴 ✅

**名称:** CVE-2019-10149 Exim RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的远程攻击者执行任意命令  
**投毒风险:** 20%  
**发现时间:** 2025-04-11  
**POC仓库:** [exim-cve-2019-10149-data](https://github.com/cloudflare/exim-cve-2019-10149-data)  

---

### [CVE-2019-10149](CVE-2019-10149-VoyagerOnne_Exim-CVE-2019-10149.md) 🔴 ✅

**名称:** CVE-2019-10149-Exim-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可完全控制服务器  
**投毒风险:** 1%  
**发现时间:** 2025-04-11  
**POC仓库:** [Exim-CVE-2019-10149](https://github.com/VoyagerOnne/Exim-CVE-2019-10149)  

---

### [CVE-2024-55591](CVE-2024-55591-watchtowrlabs_fortios-auth-bypass-check-CVE-2024-55591.md) 🔴 ✅

**名称:** CVE-2024-55591-FortiOS/FortiProxy 认证绕过  
**类型:** 认证绕过  
**风险:** 高危，攻击者可能获得超级管理员权限  
**投毒风险:** 5%  
**发现时间:** 2025-04-11  
**POC仓库:** [fortios-auth-bypass-check-CVE-2024-55591](https://github.com/watchtowrlabs/fortios-auth-bypass-check-CVE-2024-55591)  

---

### [CVE-2024-55591](CVE-2024-55591-sysirq_fortios-auth-bypass-exploit-CVE-2024-55591.md) 🔴 ✅

**名称:** CVE-2024-55591-FortiOS/FortiProxy 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致超级管理员权限泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [fortios-auth-bypass-exploit-CVE-2024-55591](https://github.com/sysirq/fortios-auth-bypass-exploit-CVE-2024-55591)  

---

### [CVE-2024-55591](CVE-2024-55591-sysirq_fortios-auth-bypass-poc-CVE-2024-55591.md) 🔴 ✅

**名称:** CVE-2024-55591-FortiOS/FortiProxy-认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致超级管理员权限获取  
**投毒风险:** 20%  
**发现时间:** 2025-04-11  
**POC仓库:** [fortios-auth-bypass-poc-CVE-2024-55591](https://github.com/sysirq/fortios-auth-bypass-poc-CVE-2024-55591)  

---

### [CVE-2024-55591](CVE-2024-55591-watchtowrlabs_fortios-auth-bypass-poc-CVE-2024-55591.md)  ✅

**名称:** CVE-2024-55591 - FortiOS/FortiProxy Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 严重，可导致超级管理员权限获取  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [fortios-auth-bypass-poc-CVE-2024-55591](https://github.com/watchtowrlabs/fortios-auth-bypass-poc-CVE-2024-55591)  

---

### [CVE-2024-55591](CVE-2024-55591-rawtips_CVE-2024-55591.md) 🔴 ✅

**名称:** CVE-2024-55591-FortiOS/FortiProxy-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权访问和完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2024-55591](https://github.com/rawtips/CVE-2024-55591)  

---

### [CVE-2024-55591](CVE-2024-55591-exfil0_CVE-2024-55591-POC.md) 🔴 ✅

**名称:** CVE-2024-55591-Fortinet身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，攻击者可以获得超级管理员权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2024-55591-POC](https://github.com/exfil0/CVE-2024-55591-POC)  

---

### [CVE-2025-32206](CVE-2025-32206-Nxploited_CVE-2025-32206.md) 🔴 ✅

**名称:** CVE-2025-32206-Processing Projects Plugin-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2025-32206](https://github.com/Nxploited/CVE-2025-32206)  

---

### [CVE-2025-32641](CVE-2025-32641-Nxploited_CVE-2025-32641.md) 🔴 ✅

**名称:** CVE-2025-32641 - Anant Addons for Elementor <= 1.1.5 CSRF to Arbitrary Plugin Installation  
**类型:** CSRF（跨站请求伪造）  
**风险:** 高危，可能导致任意插件安装和激活，进而导致网站被控制  
**投毒风险:** 5%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2025-32641](https://github.com/Nxploited/CVE-2025-32641)  

---

### [CVE-2025-31486](CVE-2025-31486-Ly4j_CVE-2025-31486.md) 🟡 ✅

**名称:** CVE-2025-31486-Vite-任意文件读取  
**类型:** 任意文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2025-31486](https://github.com/Ly4j/CVE-2025-31486)  

---

### [CVE-2019-18634](CVE-2019-18634-ptef_CVE-2019-18634.md) 🔴 ✅

**名称:** CVE-2019-18634-Sudo-Stack Buffer Overflow  
**类型:** 栈缓冲区溢出  
**风险:** 高危，可能导致提权  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2019-18634](https://github.com/ptef/CVE-2019-18634)  

---

### [CVE-2019-18634](CVE-2019-18634-Plazmaz_CVE-2019-18634.md) 🔴 ✅

**名称:** CVE-2019-18634-Sudo-堆栈缓冲区溢出  
**类型:** 堆栈缓冲区溢出  
**风险:** 高危，可能导致权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2019-18634](https://github.com/Plazmaz/CVE-2019-18634)  

---

### [CVE-2019-18634](CVE-2019-18634-edsonjt81_sudo-cve-2019-18634.md) 🔴 ✅

**名称:** CVE-2019-18634-Sudo-Stack-Based Buffer Overflow  
**类型:** Stack-Based Buffer Overflow  
**风险:** 高危，可导致权限提升  
**投毒风险:** 5%  
**发现时间:** 2025-04-11  
**POC仓库:** [sudo-cve-2019-18634](https://github.com/edsonjt81/sudo-cve-2019-18634)  

---

### [CVE-2019-18634](CVE-2019-18634-paras1te-x_CVE-2019-18634.md) 🔴 ✅

**名称:** CVE-2019-18634-Sudo-Stack Buffer Overflow  
**类型:** 栈缓冲区溢出  
**风险:** 高危，可能导致提权  
**投毒风险:** 5%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2019-18634](https://github.com/paras1te-x/CVE-2019-18634)  

---

### [CVE-2019-18634](CVE-2019-18634-N1et_CVE-2019-18634.md) 🔴 ✅

**名称:** CVE-2019-18634-Sudo-Stack Buffer Overflow  
**类型:** Stack Buffer Overflow  
**风险:** 高危，可能导致权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2019-18634](https://github.com/N1et/CVE-2019-18634)  

---

### [CVE-2019-18634](CVE-2019-18634-aesophor_CVE-2019-18634.md) 🔴 ✅

**名称:** CVE-2019-18634-Sudo-Stack Buffer Overflow  
**类型:** 栈缓冲区溢出  
**风险:** 高危，可导致权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2019-18634](https://github.com/aesophor/CVE-2019-18634)  

---

### [CVE-2019-18634](CVE-2019-18634-saleemrashid_sudo-cve-2019-18634.md) 🔴 ✅

**名称:** CVE-2019-18634-Sudo-Stack Buffer Overflow  
**类型:** 栈缓冲区溢出  
**风险:** 高危，可能导致权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-04-11  
**POC仓库:** [sudo-cve-2019-18634](https://github.com/saleemrashid/sudo-cve-2019-18634)  

---

### [CVE-2019-18634](CVE-2019-18634-TheJoyOfHacking_saleemrashid-sudo-cve-2019-18634.md) 🔴 ✅

**名称:** CVE-2019-18634-Sudo-Stack-based Buffer Overflow  
**类型:** Stack-based Buffer Overflow  
**风险:** 高危，可能导致权限提升  
**投毒风险:** 1%  
**发现时间:** 2025-04-11  
**POC仓库:** [saleemrashid-sudo-cve-2019-18634](https://github.com/TheJoyOfHacking/saleemrashid-sudo-cve-2019-18634)  

---

### [CVE-2019-18634](CVE-2019-18634-DDayLuong_CVE-2019-18634.md) 🔴 ✅

**名称:** CVE-2019-18634 - Sudo pwfeedback 缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可导致权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2019-18634](https://github.com/DDayLuong/CVE-2019-18634)  

---

### [CVE-2019-18634](CVE-2019-18634-chanbakjsd_CVE-2019-18634.md) 🔴 ✅

**名称:** CVE-2019-18634-Sudo-Stack-Based Buffer Overflow  
**类型:** 栈缓冲区溢出  
**风险:** 高危，可导致权限提升  
**投毒风险:** 1%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2019-18634](https://github.com/chanbakjsd/CVE-2019-18634)  

---

### [CVE-2019-18634](CVE-2019-18634-l0w3_CVE-2019-18634.md) 🔴 ✅

**名称:** CVE-2019-18634-Sudo-Stack-Based Buffer Overflow  
**类型:** Stack-Based Buffer Overflow  
**风险:** 高危，可能导致提权  
**投毒风险:** 1%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2019-18634](https://github.com/l0w3/CVE-2019-18634)  

---

### [CVE-2019-18634](CVE-2019-18634-ngyinkit_cve-2019-18634.md) 🔴 ✅

**名称:** CVE-2019-18634-sudo-缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可导致提权  
**投毒风险:** 1%  
**发现时间:** 2025-04-11  
**POC仓库:** [cve-2019-18634](https://github.com/ngyinkit/cve-2019-18634)  

---

### [CVE-2024-36401](CVE-2024-36401-bmth666_GeoServer-Tools-CVE-2024-36401.md)  ✅

**名称:** CVE-2024-36401-GeoServer-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [GeoServer-Tools-CVE-2024-36401](https://github.com/bmth666/GeoServer-Tools-CVE-2024-36401)  

---

### [CVE-2023-20904](CVE-2023-20904-FishMan132_CVE-2023-20904.md) 🔴 

**名称:** CVE-2023-20904-Android-权限提升  
**类型:** 权限提升  
**风险:** 高危，可能导致本地权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2023-20904](https://github.com/FishMan132/CVE-2023-20904)  

---

### [CVE-2025-41020](CVE-2025-41020-ImTheCopilotNow_CVE-2025-4102025.md) 🔴 ✅

**名称:** CVE-2025-4102025 - Copilot AI RAG 引用链接欺骗  
**类型:** UI 欺骗/重定向  
**风险:** 高危，可能导致信息泄露、恶意软件传播或钓鱼攻击  
**投毒风险:** 0%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2025-4102025](https://github.com/ImTheCopilotNow/CVE-2025-4102025)  

---

### [CVE-2019-15107](CVE-2019-15107-Mattb709_CVE-2019-15107-Webmin-RCE-PoC.md) 🔴 ✅

**名称:** CVE-2019-15107-Webmin-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-11  
**POC仓库:** [CVE-2019-15107-Webmin-RCE-PoC](https://github.com/Mattb709/CVE-2019-15107-Webmin-RCE-PoC)  

---

### [CVE-2019-15107](CVE-2019-15107-psw01_CVE-2019-15107_webminRCE.md) 🔴 ✅

**名称:** CVE-2019-15107 - Webmin 远程命令执行  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-10  
**POC仓库:** [CVE-2019-15107_webminRCE](https://github.com/psw01/CVE-2019-15107_webminRCE)  

---

### [CVE-2019-15107](CVE-2019-15107-h4ck0rman_CVE-2019-15107.md) 🔴 ✅

**名称:** CVE-2019-15107-Webmin-命令注入  
**类型:** 命令注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-10  
**POC仓库:** [CVE-2019-15107](https://github.com/h4ck0rman/CVE-2019-15107)  

---

### [CVE-2019-15107](CVE-2019-15107-MuirlandOracle_CVE-2019-15107.md) 🔴 ✅

**名称:** CVE-2019-15107-Webmin-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-10  
**POC仓库:** [CVE-2019-15107](https://github.com/MuirlandOracle/CVE-2019-15107)  

---

### [CVE-2019-15107](CVE-2019-15107-hannob_webminex.md) 🔴 ✅

**名称:** CVE-2019-15107-Webmin-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-10  
**POC仓库:** [webminex](https://github.com/hannob/webminex)  

---

### [CVE-2019-15107](CVE-2019-15107-ChakoMoonFish_webmin_CVE-2019-15107.md) 🔴 ✅

**名称:** CVE-2019-15107-Webmin-命令注入  
**类型:** 命令注入  
**风险:** 高危，可远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-10  
**POC仓库:** [webmin_CVE-2019-15107](https://github.com/ChakoMoonFish/webmin_CVE-2019-15107)  

---

### [CVE-2019-15107](CVE-2019-15107-ruthvikvegunta_CVE-2019-15107.md) 🔴 ✅

**名称:** CVE-2019-15107-Webmin-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-10  
**POC仓库:** [CVE-2019-15107](https://github.com/ruthvikvegunta/CVE-2019-15107)  

---

### [CVE-2019-15107](CVE-2019-15107-squid22_Webmin_CVE-2019-15107.md) 🔴 ✅

**名称:** CVE-2019-15107 - Webmin 命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-10  
**POC仓库:** [Webmin_CVE-2019-15107](https://github.com/squid22/Webmin_CVE-2019-15107)  

---

### [CVE-2019-15107](CVE-2019-15107-n0obit4_Webmin_1.890-POC.md) 🔴 ✅

**名称:** CVE-2019-15107-Webmin-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-10  
**POC仓库:** [Webmin_1.890-POC](https://github.com/n0obit4/Webmin_1.890-POC)  

---

### [CVE-2019-15107](CVE-2019-15107-diegojuan_CVE-2019-15107.md) 🔴 ✅

**名称:** CVE-2019-15107-Webmin-命令注入  
**类型:** 命令注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-10  
**POC仓库:** [CVE-2019-15107](https://github.com/diegojuan/CVE-2019-15107)  

---

### [CVE-2019-15107](CVE-2019-15107-cdedmondson_Modified-CVE-2019-15107.md) 🔴 ✅

**名称:** CVE-2019-15107-Webmin-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-10  
**POC仓库:** [Modified-CVE-2019-15107](https://github.com/cdedmondson/Modified-CVE-2019-15107)  

---

### [CVE-2019-15107](CVE-2019-15107-darrenmartyn_CVE-2019-15107.md) 🔴 ✅

**名称:** CVE-2019-15107-Webmin-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-10  
**POC仓库:** [CVE-2019-15107](https://github.com/darrenmartyn/CVE-2019-15107)  

---

### [CVE-2019-15107](CVE-2019-15107-whokilleddb_CVE-2019-15107.md) 🔴 ✅

**名称:** CVE-2019-15107-Webmin-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-10  
**POC仓库:** [CVE-2019-15107](https://github.com/whokilleddb/CVE-2019-15107)  

---

### [CVE-2019-15107](CVE-2019-15107-CyberTuz_CVE-2019-15107_detection.md) 🔴 ✅

**名称:** CVE-2019-15107-Webmin-命令注入  
**类型:** 命令注入  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-10  
**POC仓库:** [CVE-2019-15107_detection](https://github.com/CyberTuz/CVE-2019-15107_detection)  

---

### [CVE-2019-15107](CVE-2019-15107-hacknotes_CVE-2019-15107-Exploit.md) 🔴 ✅

**名称:** CVE-2019-15107-Webmin-命令注入  
**类型:** 命令注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-10  
**POC仓库:** [CVE-2019-15107-Exploit](https://github.com/hacknotes/CVE-2019-15107-Exploit)  

---

### [CVE-2019-15107](CVE-2019-15107-f0rkr_CVE-2019-15107.md) 🔴 ✅

**名称:** CVE-2019-15107 - Webmin Command Injection  
**类型:** 命令注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-10  
**POC仓库:** [CVE-2019-15107](https://github.com/f0rkr/CVE-2019-15107)  

---

### [CVE-2019-15107](CVE-2019-15107-TheAlpha19_MiniExploit.md) 🔴 ✅

**名称:** CVE-2019-15107-Webmin-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-10  
**POC仓库:** [MiniExploit](https://github.com/TheAlpha19/MiniExploit)  

---

### [CVE-2019-15107](CVE-2019-15107-hadrian3689_webmin_1.920.md) 🔴 ✅

**名称:** CVE-2019-15107 Webmin 1.920 未授权远程命令执行  
**类型:** 命令注入  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-10  
**POC仓库:** [webmin_1.920](https://github.com/hadrian3689/webmin_1.920)  

---

### [CVE-2019-15107](CVE-2019-15107-wenruoya_CVE-2019-15107.md) 🔴 ✅

**名称:** CVE-2019-15107-Webmin-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-10  
**POC仓库:** [CVE-2019-15107](https://github.com/wenruoya/CVE-2019-15107)  

---

### [CVE-2019-15107](CVE-2019-15107-g1vi_CVE-2019-15107.md) 🔴 ✅

**名称:** CVE-2019-15107 - Webmin password_change.cgi 命令注入  
**类型:** 命令注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-10  
**POC仓库:** [CVE-2019-15107](https://github.com/g1vi/CVE-2019-15107)  

---

### [CVE-2019-15107](CVE-2019-15107-gozn_detect-CVE-2019-15107-by-pyshark.md) 🔴 ✅

**名称:** CVE-2019-15107-Webmin-命令注入  
**类型:** 命令注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-10  
**POC仓库:** [detect-CVE-2019-15107-by-pyshark](https://github.com/gozn/detect-CVE-2019-15107-by-pyshark)  

---

### [CVE-2019-15107](CVE-2019-15107-olingo99_CVE-2019-15107.md) 🔴 ✅

**名称:** CVE-2019-15107-Webmin-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-10  
**POC仓库:** [CVE-2019-15107](https://github.com/olingo99/CVE-2019-15107)  

---

### [CVE-2019-15107](CVE-2019-15107-0x4r2_Webmin-CVE-2019-15107.md) 🔴 ✅

**名称:** CVE-2019-15107-Webmin-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-10  
**POC仓库:** [Webmin-CVE-2019-15107](https://github.com/0x4r2/Webmin-CVE-2019-15107)  

---

### [CVE-2019-15107](CVE-2019-15107-K3ysTr0K3R_CVE-2019-15107-EXPLOIT.md) 🔴 ✅

**名称:** CVE-2019-15107 - Webmin password_change.cgi 命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-10  
**POC仓库:** [CVE-2019-15107-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2019-15107-EXPLOIT)  

---

### [CVE-2019-15107](CVE-2019-15107-aamfrk_Webmin-CVE-2019-15107.md) 🔴 ✅

**名称:** CVE-2019-15107-Webmin-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-10  
**POC仓库:** [Webmin-CVE-2019-15107](https://github.com/aamfrk/Webmin-CVE-2019-15107)  

---

### [CVE-2019-15107](CVE-2019-15107-NasrallahBaadi_CVE-2019-15107.md) 🔴 ✅

**名称:** CVE-2019-15107 Webmin 1.920 远程命令执行  
**类型:** 命令注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-10  
**POC仓库:** [CVE-2019-15107](https://github.com/NasrallahBaadi/CVE-2019-15107)  

---

### [CVE-2019-15107](CVE-2019-15107-grayorwhite_CVE-2019-15107.md) 🔴 ✅

**名称:** CVE-2019-15107-Webmin-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-10  
**POC仓库:** [CVE-2019-15107](https://github.com/grayorwhite/CVE-2019-15107)  

---

### [CVE-2019-15107](CVE-2019-15107-MasterCode112_CVE-2019-15107.md) 🔴 ✅

**名称:** CVE-2019-15107 Webmin password_change.cgi 命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-10  
**POC仓库:** [CVE-2019-15107](https://github.com/MasterCode112/CVE-2019-15107)  

---

### [CVE-2019-15107](CVE-2019-15107-Mattb709_Webmin-RCE-PoC-CVE-2019-15107.md) 🔴 ✅

**名称:** CVE-2019-15107-Webmin-命令注入  
**类型:** 命令注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-10  
**POC仓库:** [Webmin-RCE-PoC-CVE-2019-15107](https://github.com/Mattb709/Webmin-RCE-PoC-CVE-2019-15107)  

---

### [CVE-2023-6063](CVE-2023-6063-Eulex0x_CVE-2023-6063.md) 🔴 ✅

**名称:** CVE-2023-6063 WP Fastest Cache SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-04-10  
**POC仓库:** [CVE-2023-6063](https://github.com/Eulex0x/CVE-2023-6063)  

---

### [CVE-2025-22457](CVE-2025-22457-sfewer-r7_CVE-2025-22457.md) 🔴 ✅

**名称:** CVE-2025-22457-Ivanti Connect Secure-栈溢出  
**类型:** 栈溢出  
**风险:** 高危，远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-10  
**POC仓库:** [CVE-2025-22457](https://github.com/sfewer-r7/CVE-2025-22457)  

---

### [CVE-2025-24813](CVE-2025-24813-Franconyu_Poc_for_CVE-2025-24813.md) 🔴 ✅

**名称:** CVE-2025-24813-Apache Tomcat 反序列化RCE  
**类型:** 反序列化远程代码执行  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 20%  
**发现时间:** 2025-04-10  
**POC仓库:** [Poc_for_CVE-2025-24813](https://github.com/Franconyu/Poc_for_CVE-2025-24813)  

---

### [CVE-2025-29705](CVE-2025-29705-yxzrw_CVE-2025-29705.md)  ✅

**名称:** CVE-2025-29705  
**类型:** 未知  
**风险:** 未知  
**投毒风险:** 0%  
**发现时间:** 2025-04-10  
**POC仓库:** [CVE-2025-29705](https://github.com/yxzrw/CVE-2025-29705)  

---

### [CVE-2023-6063](CVE-2023-6063-motikan2010_CVE-2023-6063-PoC.md) 🔴 ✅

**名称:** CVE-2023-6063-WP Fastest Cache-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-10  
**POC仓库:** [CVE-2023-6063-PoC](https://github.com/motikan2010/CVE-2023-6063-PoC)  

---

### [CVE-2023-6063](CVE-2023-6063-hackersroot_CVE-2023-6063-PoC.md) 🔴 ✅

**名称:** CVE-2023-6063-WP Fastest Cache-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露、权限提升甚至远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-10  
**POC仓库:** [CVE-2023-6063-PoC](https://github.com/hackersroot/CVE-2023-6063-PoC)  

---

### [CVE-2023-6063](CVE-2023-6063-incommatose_CVE-2023-6063.md) 🔴 ✅

**名称:** CVE-2023-6063-WP Fastest Cache-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-10  
**POC仓库:** [CVE-2023-6063](https://github.com/incommatose/CVE-2023-6063)  

---

### [CVE-2025-3248](CVE-2025-3248-PuddinCat_CVE-2025-3248-POC.md)  ✅

**名称:** CVE-2025-3248-langflow-代码注入  
**类型:** 代码注入  
**风险:** 严重，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-10  
**POC仓库:** [CVE-2025-3248-POC](https://github.com/PuddinCat/CVE-2025-3248-POC)  

---

### [CVE-2025-3248](CVE-2025-3248-xuemian168_CVE-2025-3248.md) 🔴 ✅

**名称:** CVE-2025-3248-Langflow-代码注入  
**类型:** 代码注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-10  
**POC仓库:** [CVE-2025-3248](https://github.com/xuemian168/CVE-2025-3248)  

---

### [CVE-2024-4577](CVE-2024-4577-deadlybangle_CVE-2024-4577-PHP-RCE.md) 🔴 ✅

**名称:** CVE-2024-4577-PHP-CGI参数注入  
**类型:** 参数注入/远程代码执行  
**风险:** 高危，可能导致远程代码执行、源码泄露  
**投毒风险:** 80%  
**发现时间:** 2025-04-10  
**POC仓库:** [CVE-2024-4577-PHP-RCE](https://github.com/deadlybangle/CVE-2024-4577-PHP-RCE)  

---

### [CVE-2024-48887](CVE-2024-48887-groshi215_CVE-2024-48887-Exploit.md) 🔴 ✅

**名称:** CVE-2024-48887-FortiSwitch-未经验证的密码更改  
**类型:** 未经验证的密码更改  
**风险:** 高危，可导致未经授权的管理员访问和控制  
**投毒风险:** 95%  
**发现时间:** 2025-04-10  
**POC仓库:** [CVE-2024-48887-Exploit](https://github.com/groshi215/CVE-2024-48887-Exploit)  

---

### [CVE-2025-31033](CVE-2025-31033-Nxploited_CVE-2025-31033.md) 🔴 ✅

**名称:** CVE-2025-31033 - WordPress Buddypress Humanity Plugin CSRF to Privilege Escalation  
**类型:** 跨站请求伪造 (CSRF)  
**风险:** 高危，允许攻击者更改插件设置，绕过用户验证，可能导致账户接管。  
**投毒风险:** 1%  
**发现时间:** 2025-04-10  
**POC仓库:** [CVE-2025-31033](https://github.com/Nxploited/CVE-2025-31033)  

---

### [CVE-2025-1974](CVE-2025-1974-Rubby2001_CVE-2025-1974-go.md) 🔴 ✅

**名称:** CVE-2025-1974-ingress-nginx-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致集群范围内的Secret泄露和任意代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-10  
**POC仓库:** [CVE-2025-1974-go](https://github.com/Rubby2001/CVE-2025-1974-go)  

---

### [CVE-2022-37932](CVE-2022-37932-Tim-Hoekstra_CVE-2022-37932.md) 🔴 ✅

**名称:** CVE-2022-37932-HP OfficeConnect 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可完全控制受影响设备并可能影响整个网络  
**投毒风险:** 10%  
**发现时间:** 2025-04-10  
**POC仓库:** [CVE-2022-37932](https://github.com/Tim-Hoekstra/CVE-2022-37932)  

---

### [CVE-2025-22457](CVE-2025-22457-securekomodo_CVE-2025-22457.md) 🔴 ✅

**名称:** CVE-2025-22457-Ivanti Connect Secure-栈溢出导致RCE  
**类型:** 栈溢出  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-10  
**POC仓库:** [CVE-2025-22457](https://github.com/securekomodo/CVE-2025-22457)  

---

### [CVE-2024-25600](CVE-2024-25600-ivanbg2004_ODH-BricksBuilder-CVE-2024-25600-THM.md) 🔴 ✅

**名称:** CVE-2024-25600-Bricks Builder-代码注入  
**类型:** 代码注入  
**风险:** 高危，远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-10  
**POC仓库:** [ODH-BricksBuilder-CVE-2024-25600-THM](https://github.com/ivanbg2004/ODH-BricksBuilder-CVE-2024-25600-THM)  

---

### [CVE-2025-49202](CVE-2025-49202-ImTheCopilotNow_CVE-2025-492025.md) 🟡 ✅

**名称:** CVE-2025-492025-Copilot AI-UI Misrepresentation  
**类型:** UI Misrepresentation  
**风险:** 中危，可能导致用户混淆和误导  
**投毒风险:** 0%  
**发现时间:** 2025-04-09  
**POC仓库:** [CVE-2025-492025](https://github.com/ImTheCopilotNow/CVE-2025-492025)  

---

### [CVE-2025-49202](CVE-2025-49202-ImTheCopilotNow_CVE-2025-492026.md) 🟡 ✅

**名称:** CVE-2025-492026-Copilot AI-UI误导  
**类型:** UI误导  
**风险:** 中危，可能导致用户误导和潜在的安全风险  
**投毒风险:** 0%  
**发现时间:** 2025-04-09  
**POC仓库:** [CVE-2025-492026](https://github.com/ImTheCopilotNow/CVE-2025-492026)  

---

### [CVE-2025-49203](CVE-2025-49203-ImTheCopilotNow_CVE-2025-492030.md) 🔴 

**名称:** CVE-2024-49203 SQL/HQL注入  
**类型:** SQL/HQL注入  
**风险:** 高危，可能导致敏感信息泄露、数据篡改和潜在的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-09  
**POC仓库:** [CVE-2025-492030](https://github.com/ImTheCopilotNow/CVE-2025-492030)  

---

### [CVE-2025-29810](CVE-2025-29810-aleongx_CVE-2025-29810-check.md) 🔴 ✅

**名称:** CVE-2025-29810-Active Directory Domain Services 权限提升  
**类型:** 权限提升  
**风险:** 高危，允许授权攻击者在网络中提升权限  
**投毒风险:** 0%  
**发现时间:** 2025-04-09  
**POC仓库:** [CVE-2025-29810-check](https://github.com/aleongx/CVE-2025-29810-check)  

---

### [CVE-2024-48887](CVE-2024-48887-cybersecplayground_CVE-2024-48887-FortiSwitch-Exploit.md)  ✅

**名称:** CVE-2024-48887-FortiSwitch-Unauthenticated Password Change  
**类型:** 未经验证的密码更改  
**风险:** 极危，允许未经身份验证的远程攻击者更改管理员密码。  
**投毒风险:** 10%  
**发现时间:** 2025-04-09  
**POC仓库:** [CVE-2024-48887-FortiSwitch-Exploit](https://github.com/cybersecplayground/CVE-2024-48887-FortiSwitch-Exploit)  

---

### [CVE-2024-21513](CVE-2024-21513-SavageSanta11_Reproduce-CVE-2024-21513.md) 🔴 ✅

**名称:** CVE-2024-21513 - langchain-experimental 任意代码执行  
**类型:** 代码执行  
**风险:** 高危，可能导致数据泄露、远程代码执行和拒绝服务  
**投毒风险:** 5%  
**发现时间:** 2025-04-09  
**POC仓库:** [Reproduce-CVE-2024-21513](https://github.com/SavageSanta11/Reproduce-CVE-2024-21513)  

---

### [CVE-2024-21513](CVE-2024-21513-nskath_CVE-2024-21513.md) 🔴 ✅

**名称:** CVE-2024-21513-langchain-experimental-代码执行  
**类型:** 代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-09  
**POC仓库:** [CVE-2024-21513](https://github.com/nskath/CVE-2024-21513)  

---

### [CVE-2025-24813](CVE-2025-24813-f8l124_CVE-2025-24813-POC.md) 🔴 ✅

**名称:** CVE-2025-24813 Apache Tomcat 路径等价漏洞  
**类型:** 远程代码执行/信息泄露  
**风险:** 高危，可能导致远程代码执行或信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-04-09  
**POC仓库:** [CVE-2025-24813-POC](https://github.com/f8l124/CVE-2025-24813-POC)  

---

### [CVE-2021-27289](CVE-2021-27289-TheMalwareGuardian_CVE-2021-27289.md)  

**名称:** 未识别漏洞 - LICENSE文件分析  
**类型:** 代码分析  
**风险:** 低，仅为许可协议  
**投毒风险:** 0%  
**发现时间:** 2025-04-09  
**POC仓库:** [CVE-2021-27289](https://github.com/TheMalwareGuardian/CVE-2021-27289)  

---

### [CVE-2025-26647](CVE-2025-26647-groshi215_CVE-2025-26647.md) 🔴 

**名称:** CVE-2025-26647 Windows Kerberos Elevation of Privilege  
**类型:** Elevation of Privilege  
**风险:** 高危，可能允许未经授权的攻击者提升在网络上的权限  
**投毒风险:** 5%  
**发现时间:** 2025-04-09  
**POC仓库:** [CVE-2025-26647](https://github.com/groshi215/CVE-2025-26647)  

---

### [CVE-2025-31161](CVE-2025-31161-llussiess_CVE-2025-31161.md) 🔴 ✅

**名称:** CVE-2025-31161-CrushFTP身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致完全系统接管  
**投毒风险:** 0%  
**发现时间:** 2025-04-09  
**POC仓库:** [CVE-2025-31161](https://github.com/llussiess/CVE-2025-31161)  

---

### [CVE-2024-56071](CVE-2024-56071-Nxploited_CVE-2024-56071.md) 🔴 ✅

**名称:** CVE-2024-56071-Simple Dashboard-权限提升  
**类型:** 权限提升  
**风险:** 高危，可能导致管理员权限被非法获取，控制整个WordPress站点  
**投毒风险:** 0%  
**发现时间:** 2025-04-09  
**POC仓库:** [CVE-2024-56071](https://github.com/Nxploited/CVE-2024-56071)  

---

### [CVE-2024-48887](CVE-2024-48887-IndominusRexes_CVE-2024-48887-Exploit.md) 🔴 ✅

**名称:** CVE-2024-48887-FortiSwitch-未授权密码更改  
**类型:** 未授权密码更改  
**风险:** 高危，可导致完全控制网络交换机  
**投毒风险:** 90%  
**发现时间:** 2025-04-09  
**POC仓库:** [CVE-2024-48887-Exploit](https://github.com/IndominusRexes/CVE-2024-48887-Exploit)  

---

### [CVE-2025-29927](CVE-2025-29927-l1uk_nextjs-middleware-exploit.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-Middleware 权限绕过  
**类型:** 权限绕过  
**风险:** 高危，可能导致未授权访问、数据泄露和潜在的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-09  
**POC仓库:** [nextjs-middleware-exploit](https://github.com/l1uk/nextjs-middleware-exploit)  

---

### [CVE-2023-26049](CVE-2023-26049-hshivhare67_Jetty_v9.4.31_CVE-2023-26049.md) 🟡 ✅

**名称:** CVE-2023-26049-Eclipse Jetty Cookie 注入  
**类型:** 信息泄露  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-09  
**POC仓库:** [Jetty_v9.4.31_CVE-2023-26049](https://github.com/hshivhare67/Jetty_v9.4.31_CVE-2023-26049)  

---

### [CVE-2023-26049](CVE-2023-26049-nidhihcl75_jetty-9.4.31.v20200723_G3_CVE-2023-26049.md) 🟡 

**名称:** CVE-2023-26049 - Eclipse Jetty Cookie Smuggling  
**类型:** 信息泄露  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-09  
**POC仓库:** [jetty-9.4.31.v20200723_G3_CVE-2023-26049](https://github.com/nidhihcl75/jetty-9.4.31.v20200723_G3_CVE-2023-26049)  

---

### [CVE-2023-26049](CVE-2023-26049-uthrasri_jetty-9.4.31.v20200723_CVE-2023-26049.md) 🟡 

**名称:** CVE-2023-26049-Eclipse Jetty Cookie Smuggling  
**类型:** 信息泄露  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-09  
**POC仓库:** [jetty-9.4.31.v20200723_CVE-2023-26049](https://github.com/uthrasri/jetty-9.4.31.v20200723_CVE-2023-26049)  

---

### [CVE-2023-39141](CVE-2023-39141-MartiSabate_CVE-2023-39141-LFI-enumerator.md) 🔴 ✅

**名称:** CVE-2023-39141-webui-aria2-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-09  
**POC仓库:** [CVE-2023-39141-LFI-enumerator](https://github.com/MartiSabate/CVE-2023-39141-LFI-enumerator)  

---

### [CVE-2025-24221](CVE-2025-24221-AnonymousDeveloper69_CVE-2025-24221.md) 🔴 ✅

**名称:** CVE-2025-24221 – iOS Keychain Backup Vulnerability Disclosure  
**类型:** 信息泄露  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 20%  
**发现时间:** 2025-04-09  
**POC仓库:** [CVE-2025-24221](https://github.com/AnonymousDeveloper69/CVE-2025-24221)  

---

### [CVE-2024-3640](CVE-2024-3640-H1ng007_CVE-2024-3640_WafBypass.md) 🔴 ✅

**名称:** CVE-2024-3640 - Rockwell Automation FactoryTalk Remote Access 未引用搜索路径或元素  
**类型:** 未引用搜索路径或元素 (CWE-428)  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-09  
**POC仓库:** [CVE-2024-3640_WafBypass](https://github.com/H1ng007/CVE-2024-3640_WafBypass)  

---

### [CVE-2025-29927](CVE-2025-29927-pickovven_vulnerable-nextjs-14-CVE-2025-29927.md) 🔴 

**名称:** CVE-2025-29927-Next.js中间件授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-09  
**POC仓库:** [vulnerable-nextjs-14-CVE-2025-29927](https://github.com/pickovven/vulnerable-nextjs-14-CVE-2025-29927)  

---

### [CVE-2025-32013](CVE-2025-32013-Mohith-T_CVE-2025-32013.md) 🔴 ✅

**名称:** CVE-2025-32013-LNbits-SSRF  
**类型:** SSRF  
**风险:** 高危，可能导致内部资源访问、信息泄露  
**投毒风险:** 20%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2025-32013](https://github.com/Mohith-T/CVE-2025-32013)  

---

### [CVE-2023-28354](CVE-2023-28354-stormfleet_CVE-2023-28354.md) 🔴 ✅

**名称:** CVE-2023-28354-Opsview Monitor Agent-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许未授权的远程攻击者以NT_AUTHORITY\SYSTEM权限执行任意命令  
**投毒风险:** 0%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2023-28354](https://github.com/stormfleet/CVE-2023-28354)  

---

### [CVE-2025-26633](CVE-2025-26633-sandsoncosta_CVE-2025-26633.md) 🔴 ✅

**名称:** CVE-2025-26633 - Microsoft Management Console 安全功能绕过漏洞  
**类型:** 安全功能绕过  
**风险:** 高危，允许未经授权的攻击者绕过本地安全功能。  
**投毒风险:** 99%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2025-26633](https://github.com/sandsoncosta/CVE-2025-26633)  

---

### [CVE-2021-3560](CVE-2021-3560-iSTAR-Lab_CVE-2021-3560_PoC.md) 🔴 ✅

**名称:** CVE-2021-3560-polkit-权限提升  
**类型:** 权限提升  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2021-3560_PoC](https://github.com/iSTAR-Lab/CVE-2021-3560_PoC)  

---

### [CVE-2021-3560](CVE-2021-3560-Almorabea_Polkit-exploit.md) 🔴 ✅

**名称:** CVE-2021-3560-polkit-权限提升  
**类型:** 权限提升  
**风险:** 高危，允许本地普通用户获取root权限  
**投毒风险:** 0%  
**发现时间:** 2025-04-08  
**POC仓库:** [Polkit-exploit](https://github.com/Almorabea/Polkit-exploit)  

---

### [CVE-2021-3560](CVE-2021-3560-hakivvi_CVE-2021-3560.md) 🔴 ✅

**名称:** CVE-2021-3560 - polkit 权限提升  
**类型:** 权限提升  
**风险:** 高危，允许本地非特权用户获得root权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2021-3560](https://github.com/hakivvi/CVE-2021-3560)  

---

### [CVE-2021-3560](CVE-2021-3560-AssassinUKG_Polkit-CVE-2021-3560.md) 🔴 ✅

**名称:** CVE-2021-3560-Polkit权限提升  
**类型:** 权限提升  
**风险:** 高危，可导致本地普通用户获取Root权限，造成数据泄露、完整性破坏和系统不可用  
**投毒风险:** 10%  
**发现时间:** 2025-04-08  
**POC仓库:** [Polkit-CVE-2021-3560](https://github.com/AssassinUKG/Polkit-CVE-2021-3560)  

---

### [CVE-2021-3560](CVE-2021-3560-admin-079_CVE-2021-3560.md) 🔴 ✅

**名称:** CVE-2021-3560 - Polkit 本地提权  
**类型:** 本地权限提升  
**风险:** 高危，可能导致未经授权的本地用户获取 root 权限，影响数据机密性、完整性和系统可用性。  
**投毒风险:** 0%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2021-3560](https://github.com/admin-079/CVE-2021-3560)  

---

### [CVE-2021-3560](CVE-2021-3560-BizarreLove_CVE-2021-3560.md) 🔴 ✅

**名称:** CVE-2021-3560-Polkit-权限提升  
**类型:** 权限提升  
**风险:** 高危，可能导致提权至root权限，控制系统  
**投毒风险:** 10%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2021-3560](https://github.com/BizarreLove/CVE-2021-3560)  

---

### [CVE-2021-3560](CVE-2021-3560-0dayNinja_CVE-2021-3560.md) 🔴 ✅

**名称:** CVE-2021-3560 - Polkit D-Bus 认证绕过  
**类型:** 权限提升  
**风险:** 高危，允许本地普通用户提升至root权限，导致数据泄露、完整性破坏和系统不可用。  
**投毒风险:** 10%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2021-3560](https://github.com/0dayNinja/CVE-2021-3560)  

---

### [CVE-2021-3560](CVE-2021-3560-cpu0x00_CVE-2021-3560.md) 🔴 ✅

**名称:** CVE-2021-3560-Polkit权限提升  
**类型:** 权限提升  
**风险:** 高危，可使本地低权限用户获得root权限  
**投毒风险:** 0%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2021-3560](https://github.com/cpu0x00/CVE-2021-3560)  

---

### [CVE-2021-3560](CVE-2021-3560-aancw_polkit-auto-exploit.md) 🔴 ✅

**名称:** CVE-2021-3560-polkit权限提升  
**类型:** 权限提升  
**风险:** 高危，可导致本地普通用户获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-08  
**POC仓库:** [polkit-auto-exploit](https://github.com/aancw/polkit-auto-exploit)  

---

### [CVE-2021-3560](CVE-2021-3560-NeonWhiteRabbit_CVE-2021-3560.md) 🔴 ✅

**名称:** CVE-2021-3560-Polkit权限提升  
**类型:** 权限提升  
**风险:** 高危，可能导致普通用户获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2021-3560](https://github.com/NeonWhiteRabbit/CVE-2021-3560)  

---

### [CVE-2021-3560](CVE-2021-3560-f4T1H21_CVE-2021-3560-Polkit-DBus.md) 🔴 ✅

**名称:** CVE-2021-3560-Polkit权限提升  
**类型:** 权限提升  
**风险:** 高危，可导致本地用户获取root权限  
**投毒风险:** 0%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2021-3560-Polkit-DBus](https://github.com/f4T1H21/CVE-2021-3560-Polkit-DBus)  

---

### [CVE-2021-3560](CVE-2021-3560-RicterZ_CVE-2021-3560-Authentication-Agent.md) 🔴 ✅

**名称:** CVE-2021-3560-Polkit权限提升  
**类型:** 权限提升  
**风险:** 高危，可能导致本地普通用户获取root权限  
**投毒风险:** 0%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2021-3560-Authentication-Agent](https://github.com/RicterZ/CVE-2021-3560-Authentication-Agent)  

---

### [CVE-2021-3560](CVE-2021-3560-chenaotian_CVE-2021-3560.md) 🔴 ✅

**名称:** CVE-2021-3560-Polkit权限提升  
**类型:** 权限提升  
**风险:** 高危，允许本地普通用户获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2021-3560](https://github.com/chenaotian/CVE-2021-3560)  

---

### [CVE-2021-3560](CVE-2021-3560-UNICORDev_exploit-CVE-2021-3560.md) 🔴 ✅

**名称:** CVE-2021-3560-polkit-本地提权  
**类型:** 本地提权  
**风险:** 高危，可导致本地用户提权至root  
**投毒风险:** 5%  
**发现时间:** 2025-04-08  
**POC仓库:** [exploit-CVE-2021-3560](https://github.com/UNICORDev/exploit-CVE-2021-3560)  

---

### [CVE-2021-3560](CVE-2021-3560-secnigma_CVE-2021-3560-Polkit-Privilege-Esclation.md) 🔴 ✅

**名称:** CVE-2021-3560-Polkit权限提升  
**类型:** 权限提升  
**风险:** 高危，可导致本地用户获取root权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2021-3560-Polkit-Privilege-Esclation](https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation)  

---

### [CVE-2021-3560](CVE-2021-3560-WinMin_CVE-2021-3560.md) 🔴 ✅

**名称:** CVE-2021-3560-Polkit-权限提升  
**类型:** 权限提升  
**风险:** 高危，可能导致完全系统控制  
**投毒风险:** 5%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2021-3560](https://github.com/WinMin/CVE-2021-3560)  

---

### [CVE-2021-3560](CVE-2021-3560-pashayogi_ROOT-CVE-2021-3560.md) 🔴 ✅

**名称:** CVE-2021-3560-Polkit-本地提权  
**类型:** 本地提权  
**风险:** 高危，允许本地普通用户提升权限至root  
**投毒风险:** 0%  
**发现时间:** 2025-04-08  
**POC仓库:** [ROOT-CVE-2021-3560](https://github.com/pashayogi/ROOT-CVE-2021-3560)  

---

### [CVE-2021-3560](CVE-2021-3560-asepsaepdin_CVE-2021-3560.md) 🔴 ✅

**名称:** CVE-2021-3560 - Polkit Local Privilege Escalation  
**类型:** 权限提升  
**风险:** 高危，允许本地非特权用户获取root权限，导致数据泄露、完整性破坏和系统不可用。  
**投毒风险:** 10%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2021-3560](https://github.com/asepsaepdin/CVE-2021-3560)  

---

### [CVE-2021-3560](CVE-2021-3560-TieuLong21Prosper_CVE-2021-3560.md) 🔴 ✅

**名称:** CVE-2021-3560-polkit-权限提升  
**类型:** 权限提升  
**风险:** 高危，可导致本地用户获取root权限  
**投毒风险:** 0%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2021-3560](https://github.com/TieuLong21Prosper/CVE-2021-3560)  

---

### [CVE-2021-3560](CVE-2021-3560-markyu0401_CVE-2021-3560-Polkit-Privilege-Escalation.md) 🔴 ✅

**名称:** CVE-2021-3560-Polkit权限提升  
**类型:** 权限提升  
**风险:** 高危，可导致本地用户获取root权限，影响数据保密性、完整性和系统可用性  
**投毒风险:** 10%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2021-3560-Polkit-Privilege-Escalation](https://github.com/markyu0401/CVE-2021-3560-Polkit-Privilege-Escalation)  

---

### [CVE-2021-3560](CVE-2021-3560-Kyyomaa_CVE-2021-3560-EXPLOIT.md) 🔴 ✅

**名称:** CVE-2021-3560-Polkit权限提升  
**类型:** 权限提升  
**风险:** 高危，允许本地普通用户提升至root权限，导致数据泄露、篡改和系统不可用  
**投毒风险:** 10%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2021-3560-EXPLOIT](https://github.com/Kyyomaa/CVE-2021-3560-EXPLOIT)  

---

### [CVE-2021-3560](CVE-2021-3560-LucasPDiniz_CVE-2021-3560.md) 🔴 ✅

**名称:** CVE-2021-3560 - polkit 权限提升  
**类型:** 权限提升  
**风险:** 高危，可能导致本地用户获取root权限，造成数据泄露、完整性破坏和系统不可用  
**投毒风险:** 10%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2021-3560](https://github.com/LucasPDiniz/CVE-2021-3560)  

---

### [CVE-2021-3560](CVE-2021-3560-arcslash_exploit_CVE-2021-3560.md) 🔴 ✅

**名称:** CVE-2021-3560-polkit权限提升  
**类型:** 权限提升  
**风险:** 高危，可导致本地普通用户提升至root权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-08  
**POC仓库:** [exploit_CVE-2021-3560](https://github.com/arcslash/exploit_CVE-2021-3560)  

---

### [CVE-2021-3560](CVE-2021-3560-innxrmxst_CVE-2021-3560.md) 🔴 ✅

**名称:** CVE-2021-3560 - Polkit权限提升  
**类型:** 权限提升  
**风险:** 高危，可导致本地普通用户提升为root权限  
**投毒风险:** 1%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2021-3560](https://github.com/innxrmxst/CVE-2021-3560)  

---

### [CVE-2025-44228](CVE-2025-44228-housam123456789_Lnk-Exploit-FileBinder-Certificate-Spoofer-Reg-Doc-Cve-Rce.md)  ✅

**名称:** CVE-2021-44228 Apache Log4j RCE (Log4Shell)  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，允许攻击者完全控制受影响的系统  
**投毒风险:** 50%  
**发现时间:** 2025-04-08  
**POC仓库:** [Lnk-Exploit-FileBinder-Certificate-Spoofer-Reg-Doc-Cve-Rce](https://github.com/housam123456789/Lnk-Exploit-FileBinder-Certificate-Spoofer-Reg-Doc-Cve-Rce)  

---

### [CVE-2023-2255](CVE-2023-2255-elweth-sec_CVE-2023-2255.md) 🟡 ✅

**名称:** CVE-2023-2255 - LibreOffice 远程资源加载  
**类型:** 权限、特权和访问控制  
**风险:** 中危，可能导致信息泄露和有限的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2023-2255](https://github.com/elweth-sec/CVE-2023-2255)  

---

### [CVE-2023-2255](CVE-2023-2255-SaintMichae64_CVE-2023-2255.md) 🟡 ✅

**名称:** CVE-2023-2255-LibreOffice-远程文件加载  
**类型:** 远程文件加载  
**风险:** 中危，可能导致敏感信息泄露或恶意代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2023-2255](https://github.com/SaintMichae64/CVE-2023-2255)  

---

### [CVE-2023-2255](CVE-2023-2255-G4sp4rCS_CVE-2023-2255.md) 🟡 ✅

**名称:** CVE-2023-2255-LibreOffice-远程资源加载  
**类型:** 权限、特权和访问控制  
**风险:** 中危，可能导致信息泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2023-2255](https://github.com/G4sp4rCS/CVE-2023-2255)  

---

### [CVE-2024-53027](CVE-2024-53027-ladyg00se_CVE-2024-53027-WIP.md) 🟡 ✅

**名称:** CVE-2024-53027 Qualcomm WLAN Host 缓冲区溢出导致的DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 中危，可能导致设备Wi-Fi/蓝牙连接中断  
**投毒风险:** 10%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2024-53027-WIP](https://github.com/ladyg00se/CVE-2024-53027-WIP)  

---

### [CVE-2023-45866](CVE-2023-45866-xG3nesis_RustyInjector.md) 🔴 ✅

**名称:** CVE-2023-45866 - BlueZ Bluetooth HID 注入  
**类型:** 蓝牙HID注入  
**风险:** 高危，可能允许未经验证的外围设备注入HID消息  
**投毒风险:** 10%  
**发现时间:** 2025-04-08  
**POC仓库:** [RustyInjector](https://github.com/xG3nesis/RustyInjector)  

---

### [CVE-2025-31161](CVE-2025-31161-Immersive-Labs-Sec_CVE-2025-31161.md) 🔴 ✅

**名称:** CVE-2025-31161 - CrushFTP 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致完全系统接管  
**投毒风险:** 0%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2025-31161](https://github.com/Immersive-Labs-Sec/CVE-2025-31161)  

---

### [CVE-2025-24813](CVE-2025-24813-GadaLuBau1337_CVE-2025-24813.md) 🔴 ✅

**名称:** CVE-2025-24813 Apache Tomcat 远程代码执行漏洞  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行和信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2025-24813](https://github.com/GadaLuBau1337/CVE-2025-24813)  

---

### [CVE-2025-27840](CVE-2025-27840-ladyg00se_CVE-2025-27840-WIP.md) 🟡 ✅

**名称:** CVE-2025-27840-Espressif ESP32 芯片隐藏HCI命令  
**类型:** 权限提升/内存写入  
**风险:** 中危，尽管CVSS评分为6.8，但需要物理访问或高权限。  
**投毒风险:** 10%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2025-27840-WIP](https://github.com/ladyg00se/CVE-2025-27840-WIP)  

---

### [CVE-2023-45866](CVE-2023-45866-Eason-zz_BluetoothDucky.md) 🔴 ✅

**名称:** CVE-2023-45866-BlueZ-蓝牙HID注入  
**类型:** 蓝牙HID注入  
**风险:** 高危，允许未授权的蓝牙HID设备注入键盘事件，可能导致任意命令执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-08  
**POC仓库:** [BluetoothDucky](https://github.com/Eason-zz/BluetoothDucky)  

---

### [CVE-2023-45866](CVE-2023-45866-jjjjjjjj987_cve-2023-45866-py.md) 🔴 ✅

**名称:** CVE-2023-45866-BlueZ-HID注入  
**类型:** 蓝牙HID注入  
**风险:** 高危，允许未授权的设备注入HID消息  
**投毒风险:** 95%  
**发现时间:** 2025-04-08  
**POC仓库:** [cve-2023-45866-py](https://github.com/jjjjjjjj987/cve-2023-45866-py)  

---

### [CVE-2023-45866](CVE-2023-45866-cisnarfu_Bluepop.md) 🔴 ✅

**名称:** CVE-2023-45866-BlueZ-蓝牙HID注入  
**类型:** 蓝牙HID注入  
**风险:** 高危，允许未经身份验证的设备注入HID消息，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-08  
**POC仓库:** [Bluepop](https://github.com/cisnarfu/Bluepop)  

---

### [CVE-2023-45866](CVE-2023-45866-pentestfunctions_BlueDucky.md) 🔴 ✅

**名称:** CVE-2023-45866  
**类型:** 蓝牙HID协议未授权连接漏洞  
**风险:** 高危，可能导致未授权的键盘输入注入  
**投毒风险:** 10%  
**发现时间:** 2025-04-08  
**POC仓库:** [BlueDucky](https://github.com/pentestfunctions/BlueDucky)  

---

### [CVE-2023-45866](CVE-2023-45866-AvishekDhakal_CVE-2023-45866_EXPLOITS.md) 🔴 ✅

**名称:** CVE-2023-45866-BlueZ-蓝牙HID注入  
**类型:** 蓝牙HID注入  
**风险:** 高危，可能导致键盘注入攻击，远程命令执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2023-45866_EXPLOITS](https://github.com/AvishekDhakal/CVE-2023-45866_EXPLOITS)  

---

### [CVE-2023-45866](CVE-2023-45866-Chedrian07_CVE-2023-45866-POC.md) 🔴 ✅

**名称:** CVE-2023-45866 BlueZ Bluetooth HID 注入  
**类型:** 蓝牙HID注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2023-45866-POC](https://github.com/Chedrian07/CVE-2023-45866-POC)  

---

### [CVE-2023-45866](CVE-2023-45866-Danyw24_blueXploit.md) 🔴 ✅

**名称:** CVE-2023-45866 - BlueZ Bluetooth HID 注入  
**类型:** 蓝牙HID注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-08  
**POC仓库:** [blueXploit](https://github.com/Danyw24/blueXploit)  

---

### [CVE-2023-45866](CVE-2023-45866-ladyg00se_CVE-2023-45866_WIP.md) 🔴 ✅

**名称:** CVE-2023-45866-BlueZ蓝牙HID主机未授权连接  
**类型:** 认证绕过  
**风险:** 高危，可能导致未经授权的键盘输入和命令执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2023-45866_WIP](https://github.com/ladyg00se/CVE-2023-45866_WIP)  

---

### [CVE-2024-55210](CVE-2024-55210-c4cnm_CVE-2024-55210.md) 🔴 ✅

**名称:** CVE-2024-55210 - TOTVS Protheus MFA Bypass  
**类型:** 多因素认证绕过  
**风险:** 高危，可能导致未经授权的访问  
**投毒风险:** 10%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2024-55210](https://github.com/c4cnm/CVE-2024-55210)  

---

### [CVE-2025-22457](CVE-2025-22457-Vinylrider_ivantiunlocker.md) 🔴 

**名称:** CVE-2025-22457-Ivanti Connect Secure-Stack Buffer Overflow  
**类型:** 栈缓冲区溢出  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-08  
**POC仓库:** [ivantiunlocker](https://github.com/Vinylrider/ivantiunlocker)  

---

### [CVE-2025-22457](CVE-2025-22457-N4SL1_CVE-2025-22457-PoC.md) 🔴 ✅

**名称:** CVE-2025-22457-Ivanti Connect Secure-堆栈缓冲区溢出  
**类型:** 堆栈缓冲区溢出  
**风险:** 高危，远程代码执行  
**投毒风险:** 60%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2025-22457-PoC](https://github.com/N4SL1/CVE-2025-22457-PoC)  

---

### [CVE-2025-29927](CVE-2025-29927-goncalocsousa1_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js Middleware Bypass  
**类型:** 授权绕过  
**风险:** 高危，可能导致未经授权的访问和数据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2025-29927](https://github.com/goncalocsousa1/CVE-2025-29927)  

---

### [CVE-2025-2807](CVE-2025-2807-Nxploited_CVE-2025-2807.md) 🔴 ✅

**名称:** CVE-2025-2807 - Motors Plugin Arbitrary Plugin Installation  
**类型:** 权限绕过导致任意插件安装  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2025-2807](https://github.com/Nxploited/CVE-2025-2807)  

---

### [CVE-2025-29927](CVE-2025-29927-ValGrace_middleware-auth-bypass.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-Middleware-认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-04-08  
**POC仓库:** [middleware-auth-bypass](https://github.com/ValGrace/middleware-auth-bypass)  

---

### [CVE-2025-31651](CVE-2025-31651-gregk4sec_CVE-2025-31651.md) 🔴 ✅

**名称:** CVE-2025-31161 CrushFTP Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未经授权的访问和控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-08  
**POC仓库:** [CVE-2025-31651](https://github.com/gregk4sec/CVE-2025-31651)  

---

### [CVE-2025-30065](CVE-2025-30065-mouadk_parquet-rce-poc-CVE-2025-30065.md) 🔴 ✅

**名称:** CVE-2025-30065-Apache Parquet-RCE/SSRF  
**类型:** 反序列化漏洞  
**风险:** 高危，可导致远程代码执行(RCE)或服务器端请求伪造(SSRF)  
**投毒风险:** 10%  
**发现时间:** 2025-04-08  
**POC仓库:** [parquet-rce-poc-CVE-2025-30065](https://github.com/mouadk/parquet-rce-poc-CVE-2025-30065)  

---

### [CVE-2025-24813](CVE-2025-24813-horsehacks_CVE-2025-24813-checker.md) 🔴 ✅

**名称:** CVE-2025-24813-Apache Tomcat-路径等价/反序列化漏洞  
**类型:** 路径等价/反序列化漏洞  
**风险:** 高危，可能导致远程代码执行和信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2025-24813-checker](https://github.com/horsehacks/CVE-2025-24813-checker)  

---

### [CVE-2024-44871](CVE-2024-44871-vances25_CVE-2024-44871.md) 🔴 ✅

**名称:** CVE-2024-44871-moziloCMS-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2024-44871](https://github.com/vances25/CVE-2024-44871)  

---

### [CVE-2020-17530](CVE-2020-17530-nth347_CVE-2020-17530.md) 🔴 ✅

**名称:** CVE-2020-17530 - Apache Struts OGNL 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2020-17530](https://github.com/nth347/CVE-2020-17530)  

---

### [CVE-2020-17530](CVE-2020-17530-secpool2000_CVE-2020-17530.md) 🔴 

**名称:** CVE-2020-17530-Apache Struts2-OGNL表达式注入  
**类型:** OGNL表达式注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 100%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2020-17530](https://github.com/secpool2000/CVE-2020-17530)  

---

### [CVE-2020-17530](CVE-2020-17530-phil-fly_CVE-2020-17530.md) 🔴 ✅

**名称:** CVE-2020-17530-Apache Struts2-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 60%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2020-17530](https://github.com/phil-fly/CVE-2020-17530)  

---

### [CVE-2020-17530](CVE-2020-17530-ka1n4t_CVE-2020-17530.md) 🔴 ✅

**名称:** CVE-2020-17530-Apache Struts-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2020-17530](https://github.com/ka1n4t/CVE-2020-17530)  

---

### [CVE-2020-17530](CVE-2020-17530-fengziHK_CVE-2020-17530-strust2-061.md) 🔴 ✅

**名称:** CVE-2020-17530-Apache Struts-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2020-17530-strust2-061](https://github.com/fengziHK/CVE-2020-17530-strust2-061)  

---

### [CVE-2020-17530](CVE-2020-17530-wuzuowei_CVE-2020-17530.md) 🔴 ✅

**名称:** CVE-2020-17530-Apache Struts-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2020-17530](https://github.com/wuzuowei/CVE-2020-17530)  

---

### [CVE-2020-17530](CVE-2020-17530-ludy-dev_freemarker_RCE_struts2_s2-061.md) 🔴 ✅

**名称:** CVE-2020-17530-Apache Struts-OGNL远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-07  
**POC仓库:** [freemarker_RCE_struts2_s2-061](https://github.com/ludy-dev/freemarker_RCE_struts2_s2-061)  

---

### [CVE-2020-17530](CVE-2020-17530-Al1ex_CVE-2020-17530.md) 🔴 ✅

**名称:** CVE-2020-17530 Apache Struts OGNL 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2020-17530](https://github.com/Al1ex/CVE-2020-17530)  

---

### [CVE-2020-17530](CVE-2020-17530-CyborgSecurity_CVE-2020-17530.md) 🔴 ✅

**名称:** CVE-2020-17530-Apache Struts-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2020-17530](https://github.com/CyborgSecurity/CVE-2020-17530)  

---

### [CVE-2020-17530](CVE-2020-17530-uzzzval_CVE-2020-17530.md) 🔴 ✅

**名称:** CVE-2020-17530-Apache Struts-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2020-17530](https://github.com/uzzzval/CVE-2020-17530)  

---

### [CVE-2020-17530](CVE-2020-17530-killmonday_CVE-2020-17530-s2-061.md) 🔴 ✅

**名称:** CVE-2020-17530-Apache Struts2-OGNL表达式注入  
**类型:** OGNL表达式注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2020-17530-s2-061](https://github.com/killmonday/CVE-2020-17530-s2-061)  

---

### [CVE-2020-17530](CVE-2020-17530-keyuan15_CVE-2020-17530.md) 🔴 ✅

**名称:** CVE-2020-17530-Apache Struts2-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可导致服务器完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2020-17530](https://github.com/keyuan15/CVE-2020-17530)  

---

### [CVE-2020-17530](CVE-2020-17530-daehyeok0618_CVE-2020-17530.md) 🔴 ✅

**名称:** CVE-2020-17530-Apache Struts-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2020-17530](https://github.com/daehyeok0618/CVE-2020-17530)  

---

### [CVE-2019-5418](CVE-2019-5418-omarkurt_CVE-2019-5418.md) 🔴 ✅

**名称:** CVE-2019-5418 - Rails Action View 文件内容泄露  
**类型:** 文件内容泄露  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2019-5418](https://github.com/omarkurt/CVE-2019-5418)  

---

### [CVE-2019-5418](CVE-2019-5418-brompwnie_CVE-2019-5418-Scanner.md) 🔴 ✅

**名称:** CVE-2019-5418 - Rails Action View 文件内容泄露  
**类型:** 文件内容泄露  
**风险:** 高危，可能泄露敏感信息  
**投毒风险:** 0%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2019-5418-Scanner](https://github.com/brompwnie/CVE-2019-5418-Scanner)  

---

### [CVE-2019-5418](CVE-2019-5418-takeokunn_CVE-2019-5418.md) 🔴 ✅

**名称:** CVE-2019-5418 - Rails File Content Disclosure  
**类型:** 文件内容泄露  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2019-5418](https://github.com/takeokunn/CVE-2019-5418)  

---

### [CVE-2019-5418](CVE-2019-5418-Bad3r_RailroadBandit.md) 🔴 ✅

**名称:** CVE-2019-5418 - Rails File Content Disclosure  
**类型:** 文件内容泄露  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-07  
**POC仓库:** [RailroadBandit](https://github.com/Bad3r/RailroadBandit)  

---

### [CVE-2019-5418](CVE-2019-5418-random-robbie_CVE-2019-5418.md) 🔴 ✅

**名称:** CVE-2019-5418 - Rails 文件内容泄露  
**类型:** 文件内容泄露  
**风险:** 高危，可泄露敏感信息，可能导致进一步攻击  
**投毒风险:** 0%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2019-5418](https://github.com/random-robbie/CVE-2019-5418)  

---

### [CVE-2019-5418](CVE-2019-5418-mpgn_CVE-2019-5418.md) 🔴 ✅

**名称:** CVE-2019-5418 - Rails 文件内容泄露  
**类型:** 文件内容泄露  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2019-5418](https://github.com/mpgn/CVE-2019-5418)  

---

### [CVE-2019-5418](CVE-2019-5418-kailing0220_CVE-2019-5418.md) 🔴 ✅

**名称:** CVE-2019-5418 Rails Action View 文件内容泄露漏洞  
**类型:** 文件内容泄露  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2019-5418](https://github.com/kailing0220/CVE-2019-5418)  

---

### [CVE-2019-5418](CVE-2019-5418-mpgn_Rails-doubletap-RCE.md) 🔴 ✅

**名称:** CVE-2019-5418 - Rails 文件内容泄露  
**类型:** 文件内容泄露  
**风险:** 高危，可能导致敏感信息泄露，结合其他漏洞可导致RCE  
**投毒风险:** 10%  
**发现时间:** 2025-04-07  
**POC仓库:** [Rails-doubletap-RCE](https://github.com/mpgn/Rails-doubletap-RCE)  

---

### [CVE-2019-5418](CVE-2019-5418-ztgrace_CVE-2019-5418-Rails3.md) 🔴 ✅

**名称:** CVE-2019-5418-Rails文件内容泄露  
**类型:** 文件内容泄露  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2019-5418-Rails3](https://github.com/ztgrace/CVE-2019-5418-Rails3)  

---

### [CVE-2019-5418](CVE-2019-5418-daehyeok0618_CVE-2019-5418.md) 🔴 ✅

**名称:** CVE-2019-5418 - Rails File Content Disclosure  
**类型:** 文件内容泄露  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2019-5418](https://github.com/daehyeok0618/CVE-2019-5418)  

---

### [CVE-2025-24813](CVE-2025-24813-Heimd411_CVE-2025-24813-noPoC.md) 🔴 

**名称:** CVE-2025-24813-Apache Tomcat Path Equivalence & Deserialization RCE  
**类型:** 远程代码执行 (RCE) / 信息泄露 / 文件篡改  
**风险:** 高危，可能导致服务器完全控制、敏感信息泄露或恶意内容注入  
**投毒风险:** 0%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2025-24813-noPoC](https://github.com/Heimd411/CVE-2025-24813-noPoC)  

---

### [CVE-2019-12401](CVE-2019-12401-mbadanoiu_CVE-2019-12401.md) 🔴 ✅

**名称:** CVE-2019-12401: Apache Solr XML Bomb 漏洞  
**类型:** XML实体扩展攻击（XML Bomb）  
**风险:** 高危，导致拒绝服务（DoS），资源耗尽  
**投毒风险:** 0%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2019-12401](https://github.com/mbadanoiu/CVE-2019-12401)  

---

### [CVE-2019-12409](CVE-2019-12409-jas502n_CVE-2019-12409.md) 🔴 ✅

**名称:** CVE-2019-12409 Apache Solr RCE  
**类型:** 远程代码执行  
**风险:** 高危，可完全控制服务器  
**投毒风险:** 10%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2019-12409](https://github.com/jas502n/CVE-2019-12409)  

---

### [CVE-2019-12409](CVE-2019-12409-mbadanoiu_CVE-2019-12409.md) 🔴 ✅

**名称:** CVE-2019-12409: Apache Solr RCE via JMX  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2019-12409](https://github.com/mbadanoiu/CVE-2019-12409)  

---

### [CVE-2019-11287](CVE-2019-11287-mbadanoiu_CVE-2019-11287.md) 🟡 ✅

**名称:** CVE-2019-11287-RabbitMQ Web Management Plugin-DoS  
**类型:** 拒绝服务 (DoS)  
**风险:** 中危，导致服务崩溃  
**投毒风险:** 10%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2019-11287](https://github.com/mbadanoiu/CVE-2019-11287)  

---

### [CVE-2019-14223](CVE-2019-14223-mbadanoiu_CVE-2019-14223.md) 🟡 ✅

**名称:** CVE-2019-14223-Alfresco Share-Open Redirect  
**类型:** Open Redirect  
**风险:** 中危，可能导致用户被重定向到恶意网站，从而进行钓鱼攻击或传播恶意软件。  
**投毒风险:** 5%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2019-14223](https://github.com/mbadanoiu/CVE-2019-14223)  

---

### [CVE-2019-14222](CVE-2019-14222-mbadanoiu_CVE-2019-14222.md) 🔴 ✅

**名称:** CVE-2019-14222 Alfresco Solr Web Admin Interface 认证绕过漏洞  
**类型:** 认证绕过  
**风险:** 高危，可能导致信息泄露和进一步攻击  
**投毒风险:** 10%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2019-14222](https://github.com/mbadanoiu/CVE-2019-14222)  

---

### [CVE-2019-14224](CVE-2019-14224-mbadanoiu_CVE-2019-14224.md) 🔴 ✅

**名称:** CVE-2019-14224-Alfresco-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2019-14224](https://github.com/mbadanoiu/CVE-2019-14224)  

---

### [CVE-2025-29927](CVE-2025-29927-pixilated730_NextJS-Exploit-.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-Middleware权限绕过  
**类型:** 权限绕过  
**风险:** 高危，可能导致未授权访问敏感信息或执行恶意操作  
**投毒风险:** 10%  
**发现时间:** 2025-04-07  
**POC仓库:** [NextJS-Exploit-](https://github.com/pixilated730/NextJS-Exploit-)  

---

### [CVE-2025-31486](CVE-2025-31486-iSee857_CVE-2025-31486-PoC.md) 🟡 ✅

**名称:** CVE-2025-31486-Vite-服务器端文件读取  
**类型:** 服务器端文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2025-31486-PoC](https://github.com/iSee857/CVE-2025-31486-PoC)  

---

### [CVE-2023-23397](CVE-2023-23397-tiepologian_CVE-2023-23397.md)  ✅

**名称:** CVE-2023-23397-Microsoft Outlook Elevation of Privilege Vulnerability  
**类型:** 权限提升  
**风险:** 严重，可能导致NTLM Relay攻击和权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2023-23397](https://github.com/tiepologian/CVE-2023-23397)  

---

### [CVE-2023-23397](CVE-2023-23397-j0eyv_CVE-2023-23397.md)  ✅

**名称:** CVE-2023-23397-Microsoft Outlook Elevation of Privilege Vulnerability  
**类型:** 权限提升  
**风险:** 严重，可能导致NTLM Relay攻击，控制受害者账号  
**投毒风险:** 10%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2023-23397](https://github.com/j0eyv/CVE-2023-23397)  

---

### [CVE-2023-23397](CVE-2023-23397-grn-bogo_CVE-2023-23397.md) 🔴 ✅

**名称:** CVE-2023-23397 Microsoft Outlook 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致NTLM Relay攻击，窃取用户凭据  
**投毒风险:** 0%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2023-23397](https://github.com/grn-bogo/CVE-2023-23397)  

---

### [CVE-2023-23397](CVE-2023-23397-ka7ana_CVE-2023-23397.md) 🔴 ✅

**名称:** CVE-2023-23397 Microsoft Outlook 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致身份冒用和NTLM relay攻击  
**投毒风险:** 0%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2023-23397](https://github.com/ka7ana/CVE-2023-23397)  

---

### [CVE-2023-23397](CVE-2023-23397-cleverg0d_CVE-2023-23397-PoC-PowerShell.md) 🔴 ✅

**名称:** CVE-2023-23397-Microsoft Outlook Elevation of Privilege Vulnerability  
**类型:** 权限提升  
**风险:** 高危，可能导致NTLM Relay攻击并获取用户凭据  
**投毒风险:** 10%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2023-23397-PoC-PowerShell](https://github.com/cleverg0d/CVE-2023-23397-PoC-PowerShell)  

---

### [CVE-2023-23397](CVE-2023-23397-api0cradle_CVE-2023-23397-POC-Powershell.md)  ✅

**名称:** CVE-2023-23397 Microsoft Outlook 权限提升漏洞  
**类型:** 权限提升  
**风险:** 严重，可能导致NTLM Relay攻击，允许攻击者模拟受害者身份  
**投毒风险:** 0%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2023-23397-POC-Powershell](https://github.com/api0cradle/CVE-2023-23397-POC-Powershell)  

---

### [CVE-2023-23397](CVE-2023-23397-alicangnll_CVE-2023-23397.md) 🔴 ✅

**名称:** CVE-2023-23397-Microsoft Outlook 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致NTLM Relay攻击  
**投毒风险:** 0%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2023-23397](https://github.com/alicangnll/CVE-2023-23397)  

---

### [CVE-2023-23397](CVE-2023-23397-ahmedkhlief_CVE-2023-23397-POC.md)  ✅

**名称:** CVE-2023-23397  
**类型:** 权限提升  
**风险:** 严重，可能导致NTLM Relay攻击  
**投毒风险:** 10%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2023-23397-POC](https://github.com/ahmedkhlief/CVE-2023-23397-POC)  

---

### [CVE-2023-23397](CVE-2023-23397-im007_CVE-2023-23397.md) 🔴 ✅

**名称:** CVE-2023-23397-Microsoft Outlook Elevation of Privilege Vulnerability  
**类型:** 权限提升  
**风险:** 高危，可能导致权限提升和NTLM Relay攻击  
**投毒风险:** 0%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2023-23397](https://github.com/im007/CVE-2023-23397)  

---

### [CVE-2023-23397](CVE-2023-23397-BillSkiCO_CVE-2023-23397_EXPLOIT.md) 🔴 ✅

**名称:** CVE-2023-23397-Microsoft Outlook 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致NTLM Relay攻击  
**投毒风险:** 0%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2023-23397_EXPLOIT](https://github.com/BillSkiCO/CVE-2023-23397_EXPLOIT)  

---

### [CVE-2023-23397](CVE-2023-23397-djackreuter_CVE-2023-23397-PoC.md) 🔴 ✅

**名称:** CVE-2023-23397-Microsoft Outlook Elevation of Privilege Vulnerability  
**类型:** 权限提升  
**风险:** 高危，允许攻击者提升权限并可能获取敏感信息  
**投毒风险:** 10%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2023-23397-PoC](https://github.com/djackreuter/CVE-2023-23397-PoC)  

---

### [CVE-2023-23397](CVE-2023-23397-moneertv_CVE-2023-23397.md) 🔴 ✅

**名称:** CVE-2023-23397-Microsoft Outlook 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致NTLM Relay攻击  
**投毒风险:** 10%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2023-23397](https://github.com/moneertv/CVE-2023-23397)  

---

### [CVE-2023-23397](CVE-2023-23397-ahmedkhlief_CVE-2023-23397-POC-Using-Interop-Outlook.md) 🔴 ✅

**名称:** CVE-2023-23397-Microsoft Outlook Elevation of Privilege Vulnerability  
**类型:** 权限提升  
**风险:** 高危，可能导致NTLM Relay攻击和权限提升  
**投毒风险:** 0%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2023-23397-POC-Using-Interop-Outlook](https://github.com/ahmedkhlief/CVE-2023-23397-POC-Using-Interop-Outlook)  

---

### [CVE-2023-23397](CVE-2023-23397-SecCTechs_CVE-2023-23397.md) 🔴 ✅

**名称:** CVE-2023-23397-Microsoft Outlook 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致NTLM Relay攻击，进而获取用户身份  
**投毒风险:** 0%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2023-23397](https://github.com/SecCTechs/CVE-2023-23397)  

---

### [CVE-2023-23397](CVE-2023-23397-BronzeBee_cve-2023-23397.md) 🔴 ✅

**名称:** CVE-2023-23397-Microsoft Outlook Elevation of Privilege Vulnerability  
**类型:** 权限提升  
**风险:** 高危，可能导致Net-NTLM hash泄露和身份冒用  
**投毒风险:** 5%  
**发现时间:** 2025-04-07  
**POC仓库:** [cve-2023-23397](https://github.com/BronzeBee/cve-2023-23397)  

---

### [CVE-2023-23397](CVE-2023-23397-stevesec_CVE-2023-23397.md) 🔴 ✅

**名称:** CVE-2023-23397-Microsoft Outlook权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致Net-NTLM hash泄露，进而冒充用户身份。  
**投毒风险:** 0%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2023-23397](https://github.com/stevesec/CVE-2023-23397)  

---

### [CVE-2023-23397](CVE-2023-23397-Trackflaw_CVE-2023-23397.md)  ✅

**名称:** CVE-2023-23397 Microsoft Outlook 权限提升漏洞  
**类型:** 权限提升  
**风险:** 严重，可能导致Net-NTLM hash泄露，进而进行身份冒充和横向移动  
**投毒风险:** 0%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2023-23397](https://github.com/Trackflaw/CVE-2023-23397)  

---

### [CVE-2023-23397](CVE-2023-23397-Cyb3rMaddy_CVE-2023-23397-Report.md) 🔴 ✅

**名称:** CVE-2023-23397-Microsoft Outlook 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致NTLM Relay攻击，窃取用户身份  
**投毒风险:** 10%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2023-23397-Report](https://github.com/Cyb3rMaddy/CVE-2023-23397-Report)  

---

### [CVE-2023-23397](CVE-2023-23397-Zeppperoni_CVE-2023-23397-Patch.md) 🔴 ✅

**名称:** CVE-2023-23397 Microsoft Outlook 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，允许攻击者窃取 Net-NTLM 哈希，模拟受害者身份  
**投毒风险:** 5%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2023-23397-Patch](https://github.com/Zeppperoni/CVE-2023-23397-Patch)  

---

### [CVE-2023-23397](CVE-2023-23397-jacquesquail_CVE-2023-23397.md) 🔴 ✅

**名称:** CVE-2023-23397-Microsoft Outlook 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致NTLM Relay攻击  
**投毒风险:** 0%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2023-23397](https://github.com/jacquesquail/CVE-2023-23397)  

---

### [CVE-2023-23397](CVE-2023-23397-AiK1d_CVE-2023-23397-POC.md) 🔴 ✅

**名称:** CVE-2023-23397 Microsoft Outlook 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致NTLM Relay攻击  
**投毒风险:** 10%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2023-23397-POC](https://github.com/AiK1d/CVE-2023-23397-POC)  

---

### [CVE-2023-23397](CVE-2023-23397-vlad-a-man_CVE-2023-23397.md) 🔴 ✅

**名称:** CVE-2023-23397-Microsoft Outlook 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可导致NTLM Relay攻击  
**投毒风险:** 10%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2023-23397](https://github.com/vlad-a-man/CVE-2023-23397)  

---

### [CVE-2023-23397](CVE-2023-23397-Muhammad-Ali007_OutlookNTLM_CVE-2023-23397.md) 🔴 ✅

**名称:** CVE-2023-23397 Microsoft Outlook Elevation of Privilege Vulnerability  
**类型:** 权限提升  
**风险:** 高危，可能导致NTLM Relay攻击  
**投毒风险:** 0%  
**发现时间:** 2025-04-07  
**POC仓库:** [OutlookNTLM_CVE-2023-23397](https://github.com/Muhammad-Ali007/OutlookNTLM_CVE-2023-23397)  

---

### [CVE-2023-23397](CVE-2023-23397-Pushkarup_CVE-2023-23397.md) 🔴 ✅

**名称:** CVE-2023-23397 Microsoft Outlook 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致NTLM Relay攻击，控制受害者账户  
**投毒风险:** 10%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2023-23397](https://github.com/Pushkarup/CVE-2023-23397)  

---

### [CVE-2023-23397](CVE-2023-23397-sarsaeroth_CVE-2023-23397-POC.md) 🔴 ✅

**名称:** CVE-2023-23397-Microsoft Outlook 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致NTLM Relay攻击  
**投毒风险:** 10%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2023-23397-POC](https://github.com/sarsaeroth/CVE-2023-23397-POC)  

---

### [CVE-2023-23397](CVE-2023-23397-TheUnknownSoul_CVE-2023-23397-PoW.md)  ✅

**名称:** CVE-2023-23397-Microsoft Outlook 权限提升漏洞  
**类型:** 权限提升  
**风险:** 严重，可能导致Net-NTLM哈希泄露，攻击者可冒充受害者身份。  
**投毒风险:** 10%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2023-23397-PoW](https://github.com/TheUnknownSoul/CVE-2023-23397-PoW)  

---

### [CVE-2023-23397](CVE-2023-23397-Symbolexe_CVE-2023-23397.md) 🔴 ✅

**名称:** CVE-2023-23397 Microsoft Outlook 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致NTLM relay攻击，获取用户身份  
**投毒风险:** 10%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2023-23397](https://github.com/Symbolexe/CVE-2023-23397)  

---

### [CVE-2023-23397](CVE-2023-23397-Agentgilspy_CVE-2023-23397.md) 🔴 ✅

**名称:** CVE-2023-23397 - Microsoft Outlook 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致NTLM哈希泄露，进而提升权限  
**投毒风险:** 0%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2023-23397](https://github.com/Agentgilspy/CVE-2023-23397)  

---

### [CVE-2021-24006](CVE-2021-24006-cnetsec_CVE-2021-24006.md) 🟡 ✅

**名称:** CVE-2021-24006 - FortiManager 权限绕过  
**类型:** 权限绕过  
**风险:** 中危，可能导致敏感信息泄露和配置更改  
**投毒风险:** 5%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2021-24006](https://github.com/cnetsec/CVE-2021-24006)  

---

### [CVE-2024-10924](CVE-2024-10924-cy3erdr4g0n_CVE-2024-10924.md) 🔴 ✅

**名称:** CVE-2024-10924-Really Simple Security-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，未经身份验证的攻击者可以利用此漏洞以任何现有用户的身份（包括管理员）登录。  
**投毒风险:** 5%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2024-10924](https://github.com/cy3erdr4g0n/CVE-2024-10924)  

---

### [CVE-2024-10924](CVE-2024-10924-sharafu-sblsec_CVE-2024-10924.md)  ✅

**名称:** CVE-2024-10924 - Really Simple Security Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 严重，允许未经验证的攻击者以任何现有用户（包括管理员）的身份登录。  
**投毒风险:** 10%  
**发现时间:** 2025-04-07  
**POC仓库:** [CVE-2024-10924](https://github.com/sharafu-sblsec/CVE-2024-10924)  

---

### [CVE-2024-10924](CVE-2024-10924-RandomRobbieBF_CVE-2024-10924.md)  ✅

**名称:** CVE-2024-10924 - Really Simple Security Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 严重，可能导致未经授权的访问、数据泄露和网站控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-10924](https://github.com/RandomRobbieBF/CVE-2024-10924)  

---

### [CVE-2024-10924](CVE-2024-10924-MattJButler_CVE-2024-10924.md)  ✅

**名称:** CVE-2024-10924 - Really Simple Security Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 严重，可能导致完全控制WordPress站点  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-10924](https://github.com/MattJButler/CVE-2024-10924)  

---

### [CVE-2024-10924](CVE-2024-10924-m3ssap0_wordpress-really-simple-security-authn-bypass-vulnerable-application.md)  ✅

**名称:** CVE-2024-10924-Really Simple Security-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 严重，未经身份验证的攻击者可以作为网站上的任何现有用户（例如管理员）登录  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [wordpress-really-simple-security-authn-bypass-vulnerable-application](https://github.com/m3ssap0/wordpress-really-simple-security-authn-bypass-vulnerable-application)  

---

### [CVE-2024-10924](CVE-2024-10924-m3ssap0_wordpress-really-simple-security-authn-bypass-exploit.md)  ✅

**名称:** CVE-2024-10924-Really Simple Security-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 严重，可能导致未经授权的访问和控制WordPress网站  
**投毒风险:** 5%  
**发现时间:** 2025-04-06  
**POC仓库:** [wordpress-really-simple-security-authn-bypass-exploit](https://github.com/m3ssap0/wordpress-really-simple-security-authn-bypass-exploit)  

---

### [CVE-2024-10924](CVE-2024-10924-julesbsz_CVE-2024-10924.md)  ✅

**名称:** CVE-2024-10924-Really Simple Security-Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 严重，允许未经身份验证的攻击者以任何现有用户的身份登录，包括管理员  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-10924](https://github.com/julesbsz/CVE-2024-10924)  

---

### [CVE-2024-10924](CVE-2024-10924-Trackflaw_CVE-2024-10924-Wordpress-Docker.md)  ✅

**名称:** CVE-2024-10924-Really Simple Security Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 严重，允许未经验证的攻击者以任何现有用户身份（包括管理员）登录  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-10924-Wordpress-Docker](https://github.com/Trackflaw/CVE-2024-10924-Wordpress-Docker)  

---

### [CVE-2024-10924](CVE-2024-10924-Maalfer_CVE-2024-10924-PoC.md)  ✅

**名称:** CVE-2024-10924 - Really Simple Security Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 严重，可能导致未经授权的访问和完全控制受影响的WordPress站点  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-10924-PoC](https://github.com/Maalfer/CVE-2024-10924-PoC)  

---

### [CVE-2024-10924](CVE-2024-10924-D1se0_CVE-2024-10924-Bypass-MFA-Wordpress-LAB.md) 🔴 ✅

**名称:** CVE-2024-10924-Really Simple Security-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，允许未经身份验证的攻击者以任何现有用户身份登录，包括管理员，可能导致完全控制网站  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-10924-Bypass-MFA-Wordpress-LAB](https://github.com/D1se0/CVE-2024-10924-Bypass-MFA-Wordpress-LAB)  

---

### [CVE-2024-10924](CVE-2024-10924-Hunt3r850_CVE-2024-10924-PoC.md)  ✅

**名称:** CVE-2024-10924 - Really Simple Security Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 严重，允许未经身份验证的攻击者以任何现有用户身份登录，例如管理员  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-10924-PoC](https://github.com/Hunt3r850/CVE-2024-10924-PoC)  

---

### [CVE-2024-10924](CVE-2024-10924-Hunt3r850_CVE-2024-10924-Wordpress-Docker.md)  ✅

**名称:** CVE-2024-10924-Really Simple Security-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 严重，可能导致完全控制受影响的WordPress站点  
**投毒风险:** 20%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-10924-Wordpress-Docker](https://github.com/Hunt3r850/CVE-2024-10924-Wordpress-Docker)  

---

### [CVE-2024-10924](CVE-2024-10924-Nxploited_CVE-2024-10924-Exploit.md)  ✅

**名称:** CVE-2024-10924-ReallySimpleSecurity-AuthenticationBypass  
**类型:** 身份验证绕过  
**风险:** 严重，未经身份验证的攻击者可以利用此漏洞以任何现有用户的身份（包括管理员）登录网站，导致完全控制受影响的WordPress网站。  
**投毒风险:** 5%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-10924-Exploit](https://github.com/Nxploited/CVE-2024-10924-Exploit)  

---

### [CVE-2024-10924](CVE-2024-10924-h8sU_wordpress-cve-2024-10924-exploit.md)  ✅

**名称:** CVE-2024-10924-Really Simple Security-Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 严重，允许未经身份验证的攻击者以任何现有用户身份登录，包括管理员。  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [wordpress-cve-2024-10924-exploit](https://github.com/h8sU/wordpress-cve-2024-10924-exploit)  

---

### [CVE-2024-10924](CVE-2024-10924-sariamubeen_CVE-2024-10924.md) 🔴 ✅

**名称:** CVE-2024-10924 - Really Simple Security 插件身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致管理员权限被盗用，数据泄露，恶意软件安装  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-10924](https://github.com/sariamubeen/CVE-2024-10924)  

---

### [CVE-2024-10924](CVE-2024-10924-MaleeshaUdan_wordpress-CVE-2024-10924--exploit.md)  ✅

**名称:** CVE-2024-10924 - Really Simple Security 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 严重，可能导致管理员权限获取和完全控制网站  
**投毒风险:** 5%  
**发现时间:** 2025-04-06  
**POC仓库:** [wordpress-CVE-2024-10924--exploit](https://github.com/MaleeshaUdan/wordpress-CVE-2024-10924--exploit)  

---

### [CVE-2024-10924](CVE-2024-10924-OliveiraaX_-CVE-2024-10924.md) 🔴 ✅

**名称:** CVE-2024-10924 - Really Simple Security Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 高危，未经身份验证的攻击者可以以任何现有用户身份登录，包括管理员  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [-CVE-2024-10924](https://github.com/OliveiraaX/-CVE-2024-10924)  

---

### [CVE-2025-29927](CVE-2025-29927-gotr00t0day_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-中间件绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未经授权的访问和数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2025-29927](https://github.com/gotr00t0day/CVE-2025-29927)  

---

### [CVE-2025-24813](CVE-2025-24813-La3B0z_CVE-2025-24813-POC.md) 🔴 ✅

**名称:** CVE-2025-24813 - Apache Tomcat 路径等价/路径遍历漏洞  
**类型:** 远程代码执行 (RCE) / 信息泄露 / 文件内容篡改  
**风险:** 高危，可能导致远程代码执行、敏感信息泄露、恶意内容注入  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2025-24813-POC](https://github.com/La3B0z/CVE-2025-24813-POC)  

---

### [CVE-2024-36401](CVE-2024-36401-Mr-xn_CVE-2024-36401.md) 🔴 ✅

**名称:** CVE-2024-36401-GeoServer-远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的用户可以通过构造的OGC请求执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-36401](https://github.com/Mr-xn/CVE-2024-36401)  

---

### [CVE-2025-2005](CVE-2025-2005-mrmtwoj_CVE-2025-2005.md) 🔴 ✅

**名称:** CVE-2025-2005-Front-End-Users-任意文件上传  
**类型:** 任意文件上传  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2025-2005](https://github.com/mrmtwoj/CVE-2025-2005)  

---

### [CVE-2024-3400](CVE-2024-3400-ZephrFish_CVE-2024-3400-Canary.md) 🔴 ✅

**名称:** CVE-2024-3400 PAN-OS GlobalProtect 命令注入  
**类型:** 命令注入  
**风险:** 高危，未经身份验证的攻击者可以以 root 权限在防火墙上执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-3400-Canary](https://github.com/ZephrFish/CVE-2024-3400-Canary)  

---

### [CVE-2024-3400](CVE-2024-3400-MurrayR0123_CVE-2024-3400-Compromise-Checker.md) 🔴 ✅

**名称:** CVE-2024-3400 PAN-OS GlobalProtect 命令注入  
**类型:** 命令注入  
**风险:** 高危，未授权的攻击者可以以 root 权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-3400-Compromise-Checker](https://github.com/MurrayR0123/CVE-2024-3400-Compromise-Checker)  

---

### [CVE-2024-34102](CVE-2024-34102-d0rb_CVE-2024-34102.md) 🔴 ✅

**名称:** CVE-2024-34102-Adobe Commerce-XXE  
**类型:** XXE  
**风险:** 高危，可能导致任意代码执行和敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-34102](https://github.com/d0rb/CVE-2024-34102)  

---

### [CVE-2024-34102](CVE-2024-34102-11whoami99_CVE-2024-34102.md) 🔴 ✅

**名称:** CVE-2024-34102-Adobe Commerce XXE  
**类型:** XML外部实体注入 (XXE)  
**风险:** 高危，可能导致任意代码执行，敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-34102](https://github.com/11whoami99/CVE-2024-34102)  

---

### [CVE-2023-41425](CVE-2023-41425-Twappz_CVE-2023-41425.md) 🔴 ✅

**名称:** CVE-2023-41425-WonderCMS-XSS to RCE  
**类型:** 跨站脚本攻击 (XSS)  
**风险:** 高危，可导致远程代码执行 (RCE)  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2023-41425](https://github.com/Twappz/CVE-2023-41425)  

---

### [CVE-2023-41425](CVE-2023-41425-insomnia-jacob_CVE-2023-41425.md) 🔴 ✅

**名称:** CVE-2023-41425-WonderCMS-XSS导致RCE  
**类型:** 跨站脚本（XSS）  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2023-41425](https://github.com/insomnia-jacob/CVE-2023-41425)  

---

### [CVE-2024-22899](CVE-2024-22899-Chocapikk_CVE-2024-22899-to-22903-ExploitChain.md) 🔴 ✅

**名称:** CVE-2024-22899-Vinchin Backup & Recovery-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许经过身份验证的攻击者在系统上执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-22899-to-22903-ExploitChain](https://github.com/Chocapikk/CVE-2024-22899-to-22903-ExploitChain)  

---

### [CVE-2024-36401](CVE-2024-36401-bigb0x_CVE-2024-36401.md) 🔴 ✅

**名称:** CVE-2024-36401 - GeoServer 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-36401](https://github.com/bigb0x/CVE-2024-36401)  

---

### [CVE-2024-36401](CVE-2024-36401-Niuwoo_CVE-2024-36401.md) 🔴 ✅

**名称:** CVE-2024-36401-GeoServer-远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的攻击者可以通过精心构造的输入来执行任意代码。  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-36401](https://github.com/Niuwoo/CVE-2024-36401)  

---

### [CVE-2024-36401](CVE-2024-36401-RevoltSecurities_CVE-2024-36401.md) 🔴 ✅

**名称:** CVE-2024-36401-GeoServer-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-36401](https://github.com/RevoltSecurities/CVE-2024-36401)  

---

### [CVE-2024-36401](CVE-2024-36401-jakabakos_CVE-2024-36401-GeoServer-RCE.md) 🔴 ✅

**名称:** CVE-2024-36401-GeoServer-RCE  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的攻击者可以通过构造恶意请求执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-36401-GeoServer-RCE](https://github.com/jakabakos/CVE-2024-36401-GeoServer-RCE)  

---

### [CVE-2024-36401](CVE-2024-36401-ahisec_geoserver-.md)  ✅

**名称:** CVE-2024-36401 - GeoServer RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [geoserver-](https://github.com/ahisec/geoserver-)  

---

### [CVE-2024-36401](CVE-2024-36401-yisas93_CVE-2024-36401-PoC.md) 🔴 ✅

**名称:** CVE-2024-36401-GeoServer-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未授权的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-36401-PoC](https://github.com/yisas93/CVE-2024-36401-PoC)  

---

### [CVE-2024-36401](CVE-2024-36401-justin-p_geoexplorer.md)  ✅

**名称:** CVE-2024-36401 - GeoServer远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，未授权的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [geoexplorer](https://github.com/justin-p/geoexplorer)  

---

### [CVE-2024-36401](CVE-2024-36401-daniellowrie_CVE-2024-36401-PoC.md)  ✅

**名称:** CVE-2024-36401-GeoServer-RCE  
**类型:** 远程代码执行(RCE)  
**风险:** 严重，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-36401-PoC](https://github.com/daniellowrie/CVE-2024-36401-PoC)  

---

### [CVE-2024-36401](CVE-2024-36401-punitdarji_GeoServer-CVE-2024-36401.md) 🔴 ✅

**名称:** CVE-2024-36401-GeoServer-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的用户执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [GeoServer-CVE-2024-36401](https://github.com/punitdarji/GeoServer-CVE-2024-36401)  

---

### [CVE-2024-36401](CVE-2024-36401-kkhackz0013_CVE-2024-36401.md)  ✅

**名称:** CVE-2024-36401-GeoServer-RCE  
**类型:** 远程代码执行（RCE）  
**风险:** 严重，未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-36401](https://github.com/kkhackz0013/CVE-2024-36401)  

---

### [CVE-2024-36401](CVE-2024-36401-XiaomingX_cve-2024-36401-poc.md)  ✅

**名称:** CVE-2024-36401-GeoServer-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [cve-2024-36401-poc](https://github.com/XiaomingX/cve-2024-36401-poc)  

---

### [CVE-2024-36401](CVE-2024-36401-thestar0_CVE-2024-36401-WoodpeckerPlugin.md) 🔴 ✅

**名称:** CVE-2024-36401-GeoServer-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-36401-WoodpeckerPlugin](https://github.com/thestar0/CVE-2024-36401-WoodpeckerPlugin)  

---

### [CVE-2024-36401](CVE-2024-36401-0x0d3ad_CVE-2024-36401.md) 🔴 ✅

**名称:** CVE-2024-36401-GeoServer-RCE  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-36401](https://github.com/0x0d3ad/CVE-2024-36401)  

---

### [CVE-2024-36401](CVE-2024-36401-whitebear-ch_GeoServerExploit.md)  ✅

**名称:** CVE-2024-36401 - GeoServer RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，未经身份验证的攻击者可以执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [GeoServerExploit](https://github.com/whitebear-ch/GeoServerExploit)  

---

### [CVE-2024-36401](CVE-2024-36401-netuseradministrator_CVE-2024-36401.md) 🔴 ✅

**名称:** CVE-2024-36401-GeoServer-远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-36401](https://github.com/netuseradministrator/CVE-2024-36401)  

---

### [CVE-2024-36401](CVE-2024-36401-Chocapikk_CVE-2024-36401.md) 🔴 ✅

**名称:** CVE-2024-36401 - GeoServer 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致完全系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-36401](https://github.com/Chocapikk/CVE-2024-36401)  

---

### [CVE-2023-4220](CVE-2023-4220-dollarboysushil_Chamilo-LMS-Unauthenticated-File-Upload-CVE-2023-4220.md) 🔴 ✅

**名称:** CVE-2023-4220 - Chamilo LMS Unauthenticated Big Upload File Remote Code Execution  
**类型:** 未授权文件上传/远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者上传webshell并执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [Chamilo-LMS-Unauthenticated-File-Upload-CVE-2023-4220](https://github.com/dollarboysushil/Chamilo-LMS-Unauthenticated-File-Upload-CVE-2023-4220)  

---

### [CVE-2023-4220](CVE-2023-4220-Ziad-Sakr_Chamilo-CVE-2023-4220-Exploit.md) 🔴 ✅

**名称:** CVE-2023-4220 Chamilo LMS 远程代码执行  
**类型:** 任意文件上传/远程代码执行  
**风险:** 高危，可导致远程代码执行和服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [Chamilo-CVE-2023-4220-Exploit](https://github.com/Ziad-Sakr/Chamilo-CVE-2023-4220-Exploit)  

---

### [CVE-2023-4220](CVE-2023-4220-HO4XXX_cve-2023-4220-poc.md) 🔴 ✅

**名称:** CVE-2023-4220 Chamilo LMS Unauthenticated Remote Code Execution  
**类型:** 未授权文件上传导致远程代码执行  
**风险:** 高危，允许未授权攻击者上传webshell并执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [cve-2023-4220-poc](https://github.com/HO4XXX/cve-2023-4220-poc)  

---

### [CVE-2023-4220](CVE-2023-4220-charlesgargasson_CVE-2023-4220.md) 🔴 ✅

**名称:** CVE-2023-4220 Chamilo LMS Unauthenticated Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，允许未经验证的攻击者执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2023-4220](https://github.com/charlesgargasson/CVE-2023-4220)  

---

### [CVE-2023-4220](CVE-2023-4220-nr4x4_CVE-2023-4220.md) 🔴 ✅

**名称:** CVE-2023-4220 - Chamilo LMS Unauthenticated RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的攻击者可上传WebShell并执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2023-4220](https://github.com/nr4x4/CVE-2023-4220)  

---

### [CVE-2023-4220](CVE-2023-4220-Al3xGD_CVE-2023-4220-Exploit.md) 🔴 ✅

**名称:** CVE-2023-4220-Chamilo-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经身份验证的攻击者执行任意代码  
**投毒风险:** 1%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2023-4220-Exploit](https://github.com/Al3xGD/CVE-2023-4220-Exploit)  

---

### [CVE-2023-4220](CVE-2023-4220-m3m0o_chamilo-lms-unauthenticated-big-upload-rce-poc.md) 🔴 ✅

**名称:** CVE-2023-4220-Chamilo-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全被控制，敏感信息泄露，安装勒索软件等  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [chamilo-lms-unauthenticated-big-upload-rce-poc](https://github.com/m3m0o/chamilo-lms-unauthenticated-big-upload-rce-poc)  

---

### [CVE-2023-4220](CVE-2023-4220-gmh5225_CVE-2023-4220.md) 🔴 ✅

**名称:** CVE-2023-4220 - Chamilo LMS 未授权文件上传导致远程代码执行  
**类型:** 未授权文件上传  
**风险:** 高危，未经身份验证的攻击者可以上传WebShell，最终导致远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2023-4220](https://github.com/gmh5225/CVE-2023-4220)  

---

### [CVE-2023-4220](CVE-2023-4220-charchit-subedi_chamilo-lms-unauthenticated-rce-poc.md) 🔴 ✅

**名称:** CVE-2023-4220-Chamilo-Unauthenticated-RCE  
**类型:** RCE  
**风险:** 高危，未经身份验证的攻击者可以通过上传webshell获得远程代码执行权限  
**投毒风险:** 5%  
**发现时间:** 2025-04-06  
**POC仓库:** [chamilo-lms-unauthenticated-rce-poc](https://github.com/charchit-subedi/chamilo-lms-unauthenticated-rce-poc)  

---

### [CVE-2023-4220](CVE-2023-4220-N1ghtfallXxX_CVE-2023-4220.md) 🔴 ✅

**名称:** CVE-2023-4220-Chamilo LMS-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可完全控制服务器  
**投毒风险:** 1%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2023-4220](https://github.com/N1ghtfallXxX/CVE-2023-4220)  

---

### [CVE-2023-4220](CVE-2023-4220-LGenAgul_CVE-2023-4220-Proof-of-concept.md) 🔴 ✅

**名称:** CVE-2023-4220-Chamilo LMS-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制，包括信息窃取、安装勒索软件等  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2023-4220-Proof-of-concept](https://github.com/LGenAgul/CVE-2023-4220-Proof-of-concept)  

---

### [CVE-2023-4220](CVE-2023-4220-B1TC0R3_CVE-2023-4220-PoC.md) 🔴 ✅

**名称:** CVE-2023-4220-Chamilo-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2023-4220-PoC](https://github.com/B1TC0R3/CVE-2023-4220-PoC)  

---

### [CVE-2023-4220](CVE-2023-4220-qrxnz_CVE-2023-4220.md) 🔴 ✅

**名称:** CVE-2023-4220-Chamilo LMS-未授权文件上传导致RCE  
**类型:** 未授权文件上传  
**风险:** 高危，可能导致远程代码执行和存储型XSS  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2023-4220](https://github.com/qrxnz/CVE-2023-4220)  

---

### [CVE-2023-4220](CVE-2023-4220-0x00-null_Chamilo-CVE-2023-4220-RCE-Exploit.md) 🔴 ✅

**名称:** CVE-2023-4220 Chamilo LMS Unauthenticated Big Upload File Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的攻击者可以通过上传恶意文件执行任意代码。  
**投毒风险:** 1%  
**发现时间:** 2025-04-06  
**POC仓库:** [Chamilo-CVE-2023-4220-RCE-Exploit](https://github.com/0x00-null/Chamilo-CVE-2023-4220-RCE-Exploit)  

---

### [CVE-2023-4220](CVE-2023-4220-VanishedPeople_CVE-2023-4220.md) 🔴 ✅

**名称:** CVE-2023-4220-Chamilo-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2023-4220](https://github.com/VanishedPeople/CVE-2023-4220)  

---

### [CVE-2023-4220](CVE-2023-4220-thefizzyfish_CVE-2023-4220_Chamilo_RCE.md) 🔴 ✅

**名称:** CVE-2023-4220 - Chamilo LMS Unauthenticated Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，未经身份验证的攻击者可以上传WebShell，从而完全控制服务器，窃取机密信息，安装勒索软件  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2023-4220_Chamilo_RCE](https://github.com/thefizzyfish/CVE-2023-4220_Chamilo_RCE)  

---

### [CVE-2023-4220](CVE-2023-4220-bueno-armando_CVE-2023-4220-RCE.md) 🔴 ✅

**名称:** CVE-2023-4220-Chamilo LMS Unauthenticated Remote Code Execution  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2023-4220-RCE](https://github.com/bueno-armando/CVE-2023-4220-RCE)  

---

### [CVE-2023-4220](CVE-2023-4220-H4cking4All_CVE-2023-4220.md) 🔴 ✅

**名称:** CVE-2023-4220-Chamilo-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的攻击者上传webshell并执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2023-4220](https://github.com/H4cking4All/CVE-2023-4220)  

---

### [CVE-2023-4220](CVE-2023-4220-oxapavan_CVE-2023-4220-HTB-PermX.md) 🔴 ✅

**名称:** CVE-2023-4220-Chamilo LMS Unauthenticated RCE  
**类型:** 未授权文件上传导致远程代码执行  
**风险:** 高危，可能导致服务器完全控制，数据泄露，安装勒索软件  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2023-4220-HTB-PermX](https://github.com/oxapavan/CVE-2023-4220-HTB-PermX)  

---

### [CVE-2023-4220](CVE-2023-4220-numaan911098_CVE-2023-4220.md) 🔴 ✅

**名称:** CVE-2023-4220-Chamilo-Unrestricted File Upload  
**类型:** Unrestricted File Upload  
**风险:** 高危，可导致远程代码执行和存储型XSS  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2023-4220](https://github.com/numaan911098/CVE-2023-4220)  

---

### [CVE-2023-4220](CVE-2023-4220-MikeyPPPPPPPP_CVE-2023-4220.md) 🔴 ✅

**名称:** CVE-2023-4220 Chamilo LMS Unauthenticated Big Upload File Remote Code Execution  
**类型:** 文件上传漏洞  
**风险:** 高危，可导致远程代码执行和跨站脚本攻击  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2023-4220](https://github.com/MikeyPPPPPPPP/CVE-2023-4220)  

---

### [CVE-2023-4220](CVE-2023-4220-Pr1or95_CVE-2023-4220-exploit.md) 🔴 ✅

**名称:** CVE-2023-4220-Chamilo LMS 未授权文件上传导致RCE  
**类型:** 未授权文件上传/远程代码执行  
**风险:** 高危，可能导致服务器完全被控制，数据泄露，安装勒索软件等  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2023-4220-exploit](https://github.com/Pr1or95/CVE-2023-4220-exploit)  

---

### [CVE-2023-4220](CVE-2023-4220-0xDTC_Chamilo-LMS-CVE-2023-4220-Exploit.md) 🔴 ✅

**名称:** CVE-2023-4220-Chamilo LMS-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可导致完全控制服务器  
**投毒风险:** 5%  
**发现时间:** 2025-04-06  
**POC仓库:** [Chamilo-LMS-CVE-2023-4220-Exploit](https://github.com/0xDTC/Chamilo-LMS-CVE-2023-4220-Exploit)  

---

### [CVE-2023-4220](CVE-2023-4220-zora-beep_CVE-2023-4220.md) 🔴 ✅

**名称:** CVE-2023-4220-Chamilo-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全被控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2023-4220](https://github.com/zora-beep/CVE-2023-4220)  

---

### [CVE-2023-4220](CVE-2023-4220-insomnia-jacob_CVE-2023-4220.md) 🔴 ✅

**名称:** CVE-2023-4220-Chamilo LMS-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未授权攻击者上传webshell并执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2023-4220](https://github.com/insomnia-jacob/CVE-2023-4220)  

---

### [CVE-2024-21893](CVE-2024-21893-h4x0r-dz_CVE-2024-21893.py.md) 🔴 ✅

**名称:** CVE-2024-21893-Ivanti Connect Secure/Policy Secure-SSRF  
**类型:** 服务器端请求伪造 (SSRF)  
**风险:** 高危，允许未经身份验证的攻击者访问受限资源，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-21893.py](https://github.com/h4x0r-dz/CVE-2024-21893.py)  

---

### [CVE-2024-21893](CVE-2024-21893-Chocapikk_CVE-2024-21893-to-CVE-2024-21887.md) 🔴 ✅

**名称:** CVE-2024-21893 - Ivanti Connect Secure/Policy Secure SSRF  
**类型:** 服务器端请求伪造 (SSRF)  
**风险:** 高危，允许未授权的攻击者访问受限资源，可能导致信息泄露和RCE  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-21893-to-CVE-2024-21887](https://github.com/Chocapikk/CVE-2024-21893-to-CVE-2024-21887)  

---

### [CVE-2024-3400](CVE-2024-3400-ihebski_CVE-2024-3400.md) 🔴 ✅

**名称:** CVE-2024-3400 - Palo Alto Networks PAN-OS GlobalProtect Command Injection  
**类型:** 命令注入  
**风险:** 高危，未授权的远程代码执行，可获取 root 权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-3400](https://github.com/ihebski/CVE-2024-3400)  

---

### [CVE-2024-3400](CVE-2024-3400-ak1t4_CVE-2024-3400.md) 🔴 ✅

**名称:** CVE-2024-3400 Palo Alto PAN-OS GlobalProtect 任意文件创建导致命令注入  
**类型:** 命令注入  
**风险:** 高危，未经身份验证的攻击者可以在防火墙上以 root 权限执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-3400](https://github.com/ak1t4/CVE-2024-3400)  

---

### [CVE-2024-3400](CVE-2024-3400-tfrederick74656_cve-2024-3400-poc.md) 🔴 ✅

**名称:** CVE-2024-3400 PAN-OS GlobalProtect 远程命令执行  
**类型:** 命令注入  
**风险:** 高危，允许未授权的攻击者以root权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [cve-2024-3400-poc](https://github.com/tfrederick74656/cve-2024-3400-poc)  

---

### [CVE-2024-3400](CVE-2024-3400-retkoussa_CVE-2024-3400.md) 🔴 ✅

**名称:** CVE-2024-3400 PAN-OS GlobalProtect 命令注入漏洞  
**类型:** 命令注入  
**风险:** 高危，未经身份验证的攻击者可以利用此漏洞在防火墙上以 root 权限执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-3400](https://github.com/retkoussa/CVE-2024-3400)  

---

### [CVE-2024-3400](CVE-2024-3400-0x0d3ad_CVE-2024-3400.md) 🔴 ✅

**名称:** CVE-2024-3400 PAN-OS GlobalProtect 远程命令执行  
**类型:** 命令注入  
**风险:** 高危，未经身份验证的攻击者可以root权限执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-3400](https://github.com/0x0d3ad/CVE-2024-3400)  

---

### [CVE-2024-3400](CVE-2024-3400-hahasagined_CVE-2024-3400.md)  ✅

**名称:** CVE-2024-3400 PAN-OS GlobalProtect Command Injection  
**类型:** 命令注入  
**风险:** 严重，未经身份验证的攻击者可以在防火墙上以 root 权限执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-3400](https://github.com/hahasagined/CVE-2024-3400)  

---

### [CVE-2024-3400](CVE-2024-3400-swaybs_CVE-2024-3400.md) 🔴 ✅

**名称:** CVE-2024-3400 PAN-OS GlobalProtect 命令注入漏洞  
**类型:** 命令注入  
**风险:** 高危，未经身份验证的攻击者可以root权限执行任意代码  
**投毒风险:** 1%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-3400](https://github.com/swaybs/CVE-2024-3400)  

---

### [CVE-2024-3400](CVE-2024-3400-Ravaan21_CVE-2024-3400.md) 🔴 ✅

**名称:** CVE-2024-3400 PAN-OS GlobalProtect 任意文件创建导致命令注入  
**类型:** 命令注入  
**风险:** 高危，允许未授权的攻击者以root权限执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-3400](https://github.com/Ravaan21/CVE-2024-3400)  

---

### [CVE-2024-3400](CVE-2024-3400-sxyrxyy_CVE-2024-3400-Check.md) 🔴 ✅

**名称:** CVE-2024-3400 PAN-OS GlobalProtect 命令注入漏洞  
**类型:** 命令注入  
**风险:** 高危，允许未经验证的攻击者以 root 权限在防火墙上执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-3400-Check](https://github.com/sxyrxyy/CVE-2024-3400-Check)  

---

### [CVE-2024-3400](CVE-2024-3400-pwnj0hn_CVE-2024-3400.md) 🔴 ✅

**名称:** CVE-2024-3400 PAN-OS GlobalProtect 远程命令执行漏洞  
**类型:** 远程命令执行  
**风险:** 高危，未经身份验证的攻击者可以root权限执行任意代码。  
**投毒风险:** 5%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-3400](https://github.com/pwnj0hn/CVE-2024-3400)  

---

### [CVE-2024-3400](CVE-2024-3400-codeblueprint_CVE-2024-3400.md)  ✅

**名称:** CVE-2024-3400 PAN-OS GlobalProtect 命令注入  
**类型:** 命令注入  
**风险:** 严重，未授权的攻击者可以root权限执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-3400](https://github.com/codeblueprint/CVE-2024-3400)  

---

### [CVE-2024-3400](CVE-2024-3400-HackingLZ_panrapidcheck.md) 🔴 ✅

**名称:** CVE-2024-3400 PAN-OS GlobalProtect 命令注入  
**类型:** 命令注入  
**风险:** 高危，未授权攻击者可以root权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [panrapidcheck](https://github.com/HackingLZ/panrapidcheck)  

---

### [CVE-2024-3400](CVE-2024-3400-Kr0ff_cve-2024-3400.md) 🔴 ✅

**名称:** CVE-2024-3400 PAN-OS GlobalProtect 远程命令执行  
**类型:** 命令注入  
**风险:** 高危，未经身份验证的攻击者可以在防火墙上以 root 权限执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [cve-2024-3400](https://github.com/Kr0ff/cve-2024-3400)  

---

### [CVE-2024-3400](CVE-2024-3400-schooldropout1337_CVE-2024-3400.md) 🔴 ✅

**名称:** CVE-2024-3400 PAN-OS GlobalProtect 命令注入  
**类型:** 命令注入  
**风险:** 高危，未经身份验证的攻击者可以root权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-3400](https://github.com/schooldropout1337/CVE-2024-3400)  

---

### [CVE-2024-3400](CVE-2024-3400-W01fh4cker_CVE-2024-3400-RCE-Scan.md) 🔴 ✅

**名称:** CVE-2024-3400-PAN-OS-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许未授权的攻击者以root权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-3400-RCE-Scan](https://github.com/W01fh4cker/CVE-2024-3400-RCE-Scan)  

---

### [CVE-2024-3400](CVE-2024-3400-0xr2r_CVE-2024-3400-Palo-Alto-OS-Command-Injection.md)  ✅

**名称:** CVE-2024-3400 PAN-OS GlobalProtect 任意文件创建导致命令注入  
**类型:** 命令注入  
**风险:** 严重，未授权的攻击者可以以root权限执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-3400-Palo-Alto-OS-Command-Injection](https://github.com/0xr2r/CVE-2024-3400-Palo-Alto-OS-Command-Injection)  

---

### [CVE-2024-3400](CVE-2024-3400-terminalJunki3_CVE-2024-3400-Checker.md) 🔴 ✅

**名称:** CVE-2024-3400 PAN-OS GlobalProtect 远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，未授权攻击者可利用此漏洞以 root 权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-3400-Checker](https://github.com/terminalJunki3/CVE-2024-3400-Checker)  

---

### [CVE-2024-3400](CVE-2024-3400-marconesler_CVE-2024-3400.md)  ✅

**名称:** CVE-2024-3400 PAN-OS GlobalProtect 任意文件创建导致命令注入  
**类型:** 命令注入  
**风险:** 严重，未经身份验证的攻击者可以root权限执行任意代码  
**投毒风险:** 5%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-3400](https://github.com/marconesler/CVE-2024-3400)  

---

### [CVE-2024-3400](CVE-2024-3400-andrelia-hacks_CVE-2024-3400.md) 🔴 ✅

**名称:** CVE-2024-3400 PAN-OS GlobalProtect 远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，未经身份验证的攻击者可以root权限执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-3400](https://github.com/andrelia-hacks/CVE-2024-3400)  

---

### [CVE-2024-3400](CVE-2024-3400-tk-sawada_IPLineFinder.md) 🔴 ✅

**名称:** CVE-2024-3400 PAN-OS GlobalProtect 远程命令执行  
**类型:** 命令注入  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [IPLineFinder](https://github.com/tk-sawada/IPLineFinder)  

---

### [CVE-2024-3400](CVE-2024-3400-iwallarm_cve-2024-3400.md)  ✅

**名称:** CVE-2024-3400-PAN-OS-命令注入  
**类型:** 命令注入  
**风险:** 严重，未授权的攻击者可以以root权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [cve-2024-3400](https://github.com/iwallarm/cve-2024-3400)  

---

### [CVE-2024-3400](CVE-2024-3400-zam89_CVE-2024-3400-pot.md)  ✅

**名称:** CVE-2024-3400 PAN-OS GlobalProtect 命令注入  
**类型:** 命令注入  
**风险:** 严重，未经身份验证的攻击者可以root权限执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-3400-pot](https://github.com/zam89/CVE-2024-3400-pot)  

---

### [CVE-2024-3400](CVE-2024-3400-AdaniKamal_CVE-2024-3400.md) 🔴 ✅

**名称:** CVE-2024-3400 PAN-OS GlobalProtect 远程命令执行漏洞  
**类型:** 远程命令执行  
**风险:** 高危，未经身份验证的攻击者可以利用此漏洞以root权限执行任意代码。  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-3400](https://github.com/AdaniKamal/CVE-2024-3400)  

---

### [CVE-2024-3400](CVE-2024-3400-workshop748_CVE-2024-3400.md) 🔴 ✅

**名称:** CVE-2024-3400 PAN-OS GlobalProtect 命令注入  
**类型:** 命令注入  
**风险:** 高危，可导致远程代码执行，获取Root权限  
**投毒风险:** 5%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-3400](https://github.com/workshop748/CVE-2024-3400)  

---

### [CVE-2024-3400](CVE-2024-3400-nanwinata_CVE-2024-3400.md) 🔴 ✅

**名称:** CVE-2024-3400 PAN-OS GlobalProtect 命令注入漏洞  
**类型:** 命令注入  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-3400](https://github.com/nanwinata/CVE-2024-3400)  

---

### [CVE-2024-3400](CVE-2024-3400-XiaomingX_CVE-2024-3400-poc.md) 🔴 ✅

**名称:** CVE-2024-3400 PAN-OS GlobalProtect 命令注入  
**类型:** 命令注入  
**风险:** 高危，未经身份验证的攻击者可利用此漏洞以 root 权限在防火墙上执行任意代码  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-3400-poc](https://github.com/XiaomingX/CVE-2024-3400-poc)  

---

### [CVE-2024-3400](CVE-2024-3400-hashdr1ft_SOC274-Palo-Alto-Networks-PAN-OS-Command-Injection-Vulnerability-Exploitation-CVE-2024-3400.md) 🔴 ✅

**名称:** CVE-2024-3400 - Palo Alto Networks PAN-OS GlobalProtect Command Injection  
**类型:** 命令注入  
**风险:** 高危，未经身份验证的攻击者可以root权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [SOC274-Palo-Alto-Networks-PAN-OS-Command-Injection-Vulnerability-Exploitation-CVE-2024-3400](https://github.com/hashdr1ft/SOC274-Palo-Alto-Networks-PAN-OS-Command-Injection-Vulnerability-Exploitation-CVE-2024-3400)  

---

### [CVE-2024-3400](CVE-2024-3400-Chocapikk_CVE-2024-3400.md) 🔴 ✅

**名称:** CVE-2024-3400 PAN-OS GlobalProtect 远程命令执行漏洞  
**类型:** 远程命令执行  
**风险:** 高危，未经身份验证的攻击者可以以root权限执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-3400](https://github.com/Chocapikk/CVE-2024-3400)  

---

### [CVE-2022-22978](CVE-2022-22978-umakant76705_CVE-2022-22978.md) 🔴 ✅

**名称:** CVE-2022-22978: Spring Security RegexRequestMatcher 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权访问  
**投毒风险:** 1%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2022-22978](https://github.com/umakant76705/CVE-2022-22978)  

---

### [CVE-2024-45519](CVE-2024-45519-p33d_CVE-2024-45519.md) 🔴 ✅

**名称:** CVE-2024-45519-Zimbra-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的用户执行任意命令  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-45519](https://github.com/p33d/CVE-2024-45519)  

---

### [CVE-2024-45519](CVE-2024-45519-whiterose7777_CVE-2024-45519.md) 🔴 ✅

**名称:** CVE-2024-45519 Zimbra Collaboration OS Command Injection  
**类型:** OS Command Injection  
**风险:** Critical，允许未经身份验证的用户执行任意命令，可能导致完全控制受影响的系统。  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-45519](https://github.com/whiterose7777/CVE-2024-45519)  

---

### [CVE-2024-45519](CVE-2024-45519-XiaomingX_cve-2024-45519-poc.md) 🔴 ✅

**名称:** CVE-2024-45519-Zimbra-远程命令执行  
**类型:** 远程命令执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [cve-2024-45519-poc](https://github.com/XiaomingX/cve-2024-45519-poc)  

---

### [CVE-2024-45519](CVE-2024-45519-sec13b_CVE-2024-45519.md)  ✅

**名称:** CVE-2024-45519-Zimbra-远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，允许未授权用户执行任意命令  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-45519](https://github.com/sec13b/CVE-2024-45519)  

---

### [CVE-2024-45519](CVE-2024-45519-Chocapikk_CVE-2024-45519.md) 🔴 ✅

**名称:** CVE-2024-45519 - Zimbra Collaboration Suite 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-45519](https://github.com/Chocapikk/CVE-2024-45519)  

---

### [CVE-2022-22978](CVE-2022-22978-DeEpinGh0st_CVE-2022-22978.md) 🔴 ✅

**名称:** CVE-2022-22978-Spring Security权限绕过  
**类型:** 权限绕过  
**风险:** 高危，可能导致未经授权的访问  
**投毒风险:** 5%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2022-22978](https://github.com/DeEpinGh0st/CVE-2022-22978)  

---

### [CVE-2022-22978](CVE-2022-22978-ducluongtran9121_CVE-2022-22978-PoC.md) 🔴 ✅

**名称:** CVE-2022-22978 - Spring Security Authorization Bypass  
**类型:** 授权绕过  
**风险:** 高危，可能导致未经授权的访问  
**投毒风险:** 5%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2022-22978-PoC](https://github.com/ducluongtran9121/CVE-2022-22978-PoC)  

---

### [CVE-2022-22978](CVE-2022-22978-aeifkz_CVE-2022-22978.md) 🔴 ✅

**名称:** CVE-2022-22978-Spring Security-授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2022-22978](https://github.com/aeifkz/CVE-2022-22978)  

---

### [CVE-2022-22978](CVE-2022-22978-Raghvendra1207_CVE-2022-22978.md) 🔴 ✅

**名称:** CVE-2022-22978 - Spring Security Authorization Bypass  
**类型:** 授权绕过  
**风险:** 高危，可能导致未经授权的访问  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2022-22978](https://github.com/Raghvendra1207/CVE-2022-22978)  

---

### [CVE-2022-22978](CVE-2022-22978-wan9xx_CVE-2022-22978-demo.md) 🔴 ✅

**名称:** CVE-2022-22978-Spring Security RegexRequestMatcher 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权访问  
**投毒风险:** 5%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2022-22978-demo](https://github.com/wan9xx/CVE-2022-22978-demo)  

---

### [CVE-2022-22978](CVE-2022-22978-he-ewo_CVE-2022-22978.md) 🔴 ✅

**名称:** CVE-2022-22978: Spring Security Authorization Bypass  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2022-22978](https://github.com/he-ewo/CVE-2022-22978)  

---

### [CVE-2024-34102](CVE-2024-34102-ArturArz1_TestCVE-2024-34102.md) 🔴 ✅

**名称:** CVE-2024-34102-Adobe Commerce-XXE  
**类型:** XXE  
**风险:** 高危，可能导致任意代码执行，敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [TestCVE-2024-34102](https://github.com/ArturArz1/TestCVE-2024-34102)  

---

### [CVE-2024-34102](CVE-2024-34102-bigb0x_CVE-2024-34102.md) 🔴 ✅

**名称:** CVE-2024-34102-Adobe Commerce-XXE  
**类型:** XML 外部实体注入 (XXE)  
**风险:** 高危，可能导致任意代码执行、敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-34102](https://github.com/bigb0x/CVE-2024-34102)  

---

### [CVE-2024-34102](CVE-2024-34102-0x0d3ad_CVE-2024-34102.md) 🔴 ✅

**名称:** CVE-2024-34102-Adobe Commerce-XXE  
**类型:** XXE  
**风险:** 高危，可能导致任意代码执行，敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-34102](https://github.com/0x0d3ad/CVE-2024-34102)  

---

### [CVE-2024-34102](CVE-2024-34102-jakabakos_CVE-2024-34102-CosmicSting-XXE-in-Adobe-Commerce-and-Magento.md) 🔴 ✅

**名称:** CVE-2024-34102-Adobe Commerce-XXE  
**类型:** XML外部实体注入 (XXE)  
**风险:** 高危，可能导致任意代码执行和敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-34102-CosmicSting-XXE-in-Adobe-Commerce-and-Magento](https://github.com/jakabakos/CVE-2024-34102-CosmicSting-XXE-in-Adobe-Commerce-and-Magento)  

---

### [CVE-2024-34102](CVE-2024-34102-unknownzerobit_poc.md) 🔴 ✅

**名称:** CVE-2024-34102-Adobe Commerce-XXE  
**类型:** XXE  
**风险:** 高危，可能导致任意代码执行和敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [poc](https://github.com/unknownzerobit/poc)  

---

### [CVE-2024-34102](CVE-2024-34102-Phantom-IN_CVE-2024-34102.md) 🔴 ✅

**名称:** CVE-2024-34102-Adobe Commerce-XXE  
**类型:** XXE  
**风险:** 高危，可能导致任意代码执行和敏感信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-34102](https://github.com/Phantom-IN/CVE-2024-34102)  

---

### [CVE-2024-34102](CVE-2024-34102-bughuntar_CVE-2024-34102.md)  ✅

**名称:** CVE-2024-34102 - Adobe Commerce XXE  
**类型:** XML 外部实体注入 (XXE)  
**风险:** 严重，可能导致任意代码执行，敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-34102](https://github.com/bughuntar/CVE-2024-34102)  

---

### [CVE-2024-34102](CVE-2024-34102-bughuntar_CVE-2024-34102-Python.md) 🔴 ✅

**名称:** CVE-2024-34102 - Adobe Commerce XXE漏洞  
**类型:** XML外部实体注入 (XXE)  
**风险:** 高危，可能导致敏感信息泄露、远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-34102-Python](https://github.com/bughuntar/CVE-2024-34102-Python)  

---

### [CVE-2024-34102](CVE-2024-34102-Chocapikk_CVE-2024-34102.md) 🔴 ✅

**名称:** CVE-2024-34102-Adobe Commerce-XXE漏洞  
**类型:** XML外部实体注入 (XXE)  
**风险:** 高危，可能导致任意代码执行、敏感信息泄露  
**投毒风险:** 20%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-34102](https://github.com/Chocapikk/CVE-2024-34102)  

---

### [CVE-2024-34102](CVE-2024-34102-bka_magento-cve-2024-34102-exploit-cosmicstring.md) 🔴 ✅

**名称:** CVE-2024-34102-Adobe Commerce/Magento-XXE  
**类型:** XXE (XML External Entity)  
**风险:** 高危，可能导致任意代码执行，敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [magento-cve-2024-34102-exploit-cosmicstring](https://github.com/bka/magento-cve-2024-34102-exploit-cosmicstring)  

---

### [CVE-2024-34102](CVE-2024-34102-wubinworks_magento2-encryption-key-manager-cli.md)  ✅

**名称:** CVE-2024-34102-Adobe Commerce-XXE  
**类型:** XXE  
**风险:** 严重，可能导致任意代码执行和敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [magento2-encryption-key-manager-cli](https://github.com/wubinworks/magento2-encryption-key-manager-cli)  

---

### [CVE-2024-34102](CVE-2024-34102-mksundaram69_CVE-2024-34102.md) 🔴 ✅

**名称:** CVE-2024-34102-Adobe Commerce-XXE  
**类型:** XML 外部实体注入 (XXE)  
**风险:** 高危，可导致任意文件读取和潜在的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-34102](https://github.com/mksundaram69/CVE-2024-34102)  

---

### [CVE-2024-34102](CVE-2024-34102-EQSTLab_CVE-2024-34102.md) 🔴 ✅

**名称:** CVE-2024-34102-Adobe Commerce-XXE  
**类型:** XXE  
**风险:** 高危，可能导致任意代码执行和敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-34102](https://github.com/EQSTLab/CVE-2024-34102)  

---

### [CVE-2024-34102](CVE-2024-34102-th3gokul_CVE-2024-34102.md) 🔴 ✅

**名称:** CVE-2024-34102-Adobe Commerce-XXE  
**类型:** XXE (XML External Entity)  
**风险:** 高危，可能导致任意代码执行、敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-34102](https://github.com/th3gokul/CVE-2024-34102)  

---

### [CVE-2024-34102](CVE-2024-34102-wubinworks_magento2-cosmic-sting-patch.md) 🔴 ✅

**名称:** CVE-2024-34102-Adobe Commerce-XXE  
**类型:** XXE (XML External Entity)  
**风险:** 高危，可能导致任意代码执行，敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [magento2-cosmic-sting-patch](https://github.com/wubinworks/magento2-cosmic-sting-patch)  

---

### [CVE-2024-34102](CVE-2024-34102-SamJUK_cosmicsting-validator.md) 🔴 ✅

**名称:** CVE-2024-34102 - Adobe Commerce XXE 漏洞  
**类型:** XML 外部实体注入 (XXE)  
**风险:** 高危，可能导致任意代码执行、敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [cosmicsting-validator](https://github.com/SamJUK/cosmicsting-validator)  

---

### [CVE-2024-34102](CVE-2024-34102-dream434_CVE-2024-34102.md)  ✅

**名称:** CVE-2024-34102-Adobe Commerce XXE  
**类型:** XML 外部实体注入 (XXE)  
**风险:** 严重，可能导致任意代码执行，敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-34102](https://github.com/dream434/CVE-2024-34102)  

---

### [CVE-2024-34102](CVE-2024-34102-Koray123-debug_CVE-2024-34102.md)  ✅

**名称:** CVE-2024-34102 - Adobe Commerce XXE  
**类型:** XML 外部实体注入 (XXE)  
**风险:** 严重，可能导致任意代码执行，敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-34102](https://github.com/Koray123-debug/CVE-2024-34102)  

---

### [CVE-2025-30567](CVE-2025-30567-KaxuFF_CVE-2025-30567-PoC.md) 🔴 ✅

**名称:** CVE-2025-30567-WP01-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感信息泄露  
**投毒风险:** 80%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2025-30567-PoC](https://github.com/KaxuFF/CVE-2025-30567-PoC)  

---

### [CVE-2024-42007](CVE-2024-42007-BubblyCola_CVE_2024_42007.md) 🟡 ✅

**名称:** CVE-2024-42007 - php-spx 目录遍历  
**类型:** 目录遍历  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE_2024_42007](https://github.com/BubblyCola/CVE_2024_42007)  

---

### [CVE-2024-23653](CVE-2024-23653-666asd_CVE-2024-23653.md) 🔴 ✅

**名称:** CVE-2024-23653-BuildKit-权限绕过  
**类型:** 权限绕过  
**风险:** 高危，可能导致容器逃逸和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-23653](https://github.com/666asd/CVE-2024-23653)  

---

### [CVE-2024-56145](CVE-2024-56145-hmhlol_craft-cms-RCE-CVE-2024-56145.md) 🔴 ✅

**名称:** CVE-2024-56145-CraftCMS-RCE  
**类型:** RCE  
**风险:** 高危，可导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [craft-cms-RCE-CVE-2024-56145](https://github.com/hmhlol/craft-cms-RCE-CVE-2024-56145)  

---

### [CVE-2011-2523](CVE-2011-2523-HerculesRD_vsftpd2.3.4PyExploit.md) 🔴 ✅

**名称:** CVE-2011-2523-vsftpd-Backdoor  
**类型:** 后门  
**风险:** 高危，可远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-06  
**POC仓库:** [vsftpd2.3.4PyExploit](https://github.com/HerculesRD/vsftpd2.3.4PyExploit)  

---

### [CVE-2011-2523](CVE-2011-2523-nobodyatall648_CVE-2011-2523.md) 🔴 ✅

**名称:** CVE-2011-2523-vsftpd 2.3.4 Backdoor  
**类型:** 后门  
**风险:** 高危，可导致远程命令执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2011-2523](https://github.com/nobodyatall648/CVE-2011-2523)  

---

### [CVE-2011-2523](CVE-2011-2523-Gr4ykt_CVE-2011-2523.md) 🔴 ✅

**名称:** CVE-2011-2523 - vsftpd 2.3.4 后门命令执行  
**类型:** 后门  
**风险:** 高危，可导致远程代码执行和完全系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2011-2523](https://github.com/Gr4ykt/CVE-2011-2523)  

---

### [CVE-2011-2523](CVE-2011-2523-MFernstrom_OffensivePascal-CVE-2011-2523.md) 🔴 ✅

**名称:** CVE-2011-2523-vsftpd-后门  
**类型:** 后门  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [OffensivePascal-CVE-2011-2523](https://github.com/MFernstrom/OffensivePascal-CVE-2011-2523)  

---

### [CVE-2011-2523](CVE-2011-2523-0xSojalSec_CVE-2011-2523.md) 🔴 ✅

**名称:** CVE-2011-2523-vsftpd-Backdoor  
**类型:** 后门  
**风险:** 高危，远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2011-2523](https://github.com/0xSojalSec/CVE-2011-2523)  

---

### [CVE-2011-2523](CVE-2011-2523-0xSojalSec_-CVE-2011-2523.md) 🔴 ✅

**名称:** CVE-2011-2523-vsftpd-后门命令执行  
**类型:** 后门命令执行  
**风险:** 高危，可能导致远程代码执行和服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [-CVE-2011-2523](https://github.com/0xSojalSec/-CVE-2011-2523)  

---

### [CVE-2011-2523](CVE-2011-2523-XiangSi-Howard_CTF---CVE-2011-2523.md) 🔴 ✅

**名称:** CVE-2011-2523-vsftpd-后门  
**类型:** 后门  
**风险:** 高危，允许未经授权的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CTF---CVE-2011-2523](https://github.com/XiangSi-Howard/CTF---CVE-2011-2523)  

---

### [CVE-2011-2523](CVE-2011-2523-padsalatushal_CVE-2011-2523.md) 🔴 ✅

**名称:** CVE-2011-2523 - vsftpd 2.3.4 Backdoor Command Execution  
**类型:** 后门  
**风险:** 高危，可远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2011-2523](https://github.com/padsalatushal/CVE-2011-2523)  

---

### [CVE-2011-2523](CVE-2011-2523-cowsecurity_CVE-2011-2523.md) 🔴 ✅

**名称:** CVE-2011-2523-vsftpd-后门  
**类型:** 后门  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2011-2523](https://github.com/cowsecurity/CVE-2011-2523)  

---

### [CVE-2011-2523](CVE-2011-2523-Lynk4_CVE-2011-2523.md) 🔴 ✅

**名称:** CVE-2011-2523 - vsftpd 2.3.4 Backdoor Command Execution  
**类型:** 后门  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2011-2523](https://github.com/Lynk4/CVE-2011-2523)  

---

### [CVE-2011-2523](CVE-2011-2523-4m3rr0r_CVE-2011-2523-poc.md) 🔴 ✅

**名称:** CVE-2011-2523-vsftpd-后门命令执行  
**类型:** 后门  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2011-2523-poc](https://github.com/4m3rr0r/CVE-2011-2523-poc)  

---

### [CVE-2011-2523](CVE-2011-2523-chleba124_vsftpd-exploit.md) 🔴 ✅

**名称:** CVE-2011-2523 - vsftpd 2.3.4 Backdoor Command Execution  
**类型:** 后门  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [vsftpd-exploit](https://github.com/chleba124/vsftpd-exploit)  

---

### [CVE-2011-2523](CVE-2011-2523-Shubham-2k1_Exploit-CVE-2011-2523.md) 🔴 ✅

**名称:** CVE-2011-2523-vsftpd-后门  
**类型:** 后门  
**风险:** 高危，可直接获取服务器Shell权限  
**投毒风险:** 1%  
**发现时间:** 2025-04-06  
**POC仓库:** [Exploit-CVE-2011-2523](https://github.com/Shubham-2k1/Exploit-CVE-2011-2523)  

---

### [CVE-2011-2523](CVE-2011-2523-Tenor-Z_SmileySploit.md) 🔴 ✅

**名称:** CVE-2011-2523-vsftpd 2.3.4 Backdoor Command Execution  
**类型:** 后门  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [SmileySploit](https://github.com/Tenor-Z/SmileySploit)  

---

### [CVE-2011-2523](CVE-2011-2523-0xB0y426_CVE-2011-2523-PoC.md) 🔴 ✅

**名称:** CVE-2011-2523 - vsftpd 2.3.4 后门  
**类型:** 后门  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2011-2523-PoC](https://github.com/0xB0y426/CVE-2011-2523-PoC)  

---

### [CVE-2011-2523](CVE-2011-2523-Gill-Singh-A_vsFTP-2.3.4-Remote-Root-Shell-Exploit.md) 🔴 ✅

**名称:** CVE-2011-2523 - vsftpd 2.3.4 Backdoor Command Execution  
**类型:** 后门程序  
**风险:** 高危，可获取目标系统root权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [vsFTP-2.3.4-Remote-Root-Shell-Exploit](https://github.com/Gill-Singh-A/vsFTP-2.3.4-Remote-Root-Shell-Exploit)  

---

### [CVE-2011-2523](CVE-2011-2523-vaishnavucv_CVE-2011-2523.md) 🔴 ✅

**名称:** CVE-2011-2523-vsftpd-后门  
**类型:** 后门  
**风险:** 高危，可远程代码执行  
**投毒风险:** 99%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2011-2523](https://github.com/vaishnavucv/CVE-2011-2523)  

---

### [CVE-2011-2523](CVE-2011-2523-NullBrunk_CVE-2011-2523.md) 🔴 ✅

**名称:** CVE-2011-2523-vsftpd-Backdoor  
**类型:** 后门  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2011-2523](https://github.com/NullBrunk/CVE-2011-2523)  

---

### [CVE-2011-2523](CVE-2011-2523-everythingBlackkk_vsFTPd-Backdoor-Exploit-CVE-2011-2523-.md) 🔴 ✅

**名称:** CVE-2011-2523-vsftpd-Backdoor  
**类型:** 后门  
**风险:** 高危，可能导致远程代码执行和系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [vsFTPd-Backdoor-Exploit-CVE-2011-2523-](https://github.com/everythingBlackkk/vsFTPd-Backdoor-Exploit-CVE-2011-2523-)  

---

### [CVE-2011-2523](CVE-2011-2523-Lychi3_vsftpd-backdoor.md) 🔴 ✅

**名称:** CVE-2011-2523-vsftpd 2.3.4 Backdoor  
**类型:** 后门  
**风险:** 高危，可远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [vsftpd-backdoor](https://github.com/Lychi3/vsftpd-backdoor)  

---

### [CVE-2011-2523](CVE-2011-2523-sug4r-wr41th_CVE-2011-2523.md) 🔴 ✅

**名称:** CVE-2011-2523-vsftpd-后门  
**类型:** 后门  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2011-2523](https://github.com/sug4r-wr41th/CVE-2011-2523)  

---

### [CVE-2011-2523](CVE-2011-2523-vedpakhare_vsftpd-234-vuln-report.md) 🔴 ✅

**名称:** CVE-2011-2523 - vsftpd 2.3.4 后门命令执行  
**类型:** 后门命令执行  
**风险:** 高危，可获取Root权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [vsftpd-234-vuln-report](https://github.com/vedpakhare/vsftpd-234-vuln-report)  

---

### [CVE-2011-2523](CVE-2011-2523-madanokr001_CVE-2011-2523.md) 🔴 ✅

**名称:** CVE-2011-2523-vsftpd-Backdoor  
**类型:** 后门  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2011-2523](https://github.com/madanokr001/CVE-2011-2523)  

---

### [CVE-2024-56145](CVE-2024-56145-Sachinart_CVE-2024-56145-craftcms-rce.md)  ✅

**名称:** CVE-2024-56145-CraftCMS-远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致完全系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-56145-craftcms-rce](https://github.com/Sachinart/CVE-2024-56145-craftcms-rce)  

---

### [CVE-2024-56145](CVE-2024-56145-Chocapikk_CVE-2024-56145.md)  ✅

**名称:** CVE-2024-56145 - Craft CMS RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致完全系统控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-56145](https://github.com/Chocapikk/CVE-2024-56145)  

---

### [CVE-2025-29927](CVE-2025-29927-YEONDG_nextjs-cve-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js中间件绕过  
**类型:** 权限绕过  
**风险:** 高危，可能导致未经授权的访问和数据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-04-06  
**POC仓库:** [nextjs-cve-2025-29927](https://github.com/YEONDG/nextjs-cve-2025-29927)  

---

### [CVE-2024-49019](CVE-2024-49019-rayngnpc_CVE-2024-49019-rayng.md) 🔴 ✅

**名称:** CVE-2024-49019 - Active Directory Certificate Services 提权漏洞  
**类型:** 特权提升  
**风险:** 高危，可能导致域权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-49019-rayng](https://github.com/rayngnpc/CVE-2024-49019-rayng)  

---

### [CVE-2024-4367](CVE-2024-4367-VVeakee_CVE-2024-4367.md) 🔴 ✅

**名称:** CVE-2024-4367-PDF.js-任意JavaScript代码执行  
**类型:** 任意JavaScript代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2024-4367](https://github.com/VVeakee/CVE-2024-4367)  

---

### [CVE-2025-2783](CVE-2025-2783-Alchemist3dot14_CVE-2025-2783.md) 🔴 

**名称:** CVE-2025-2783-Google Chrome Mojo Sandbox Escape  
**类型:** 沙箱逃逸  
**风险:** 高危，可导致远程攻击者进行沙箱逃逸  
**投毒风险:** 0%  
**发现时间:** 2025-04-06  
**POC仓库:** [CVE-2025-2783](https://github.com/Alchemist3dot14/CVE-2025-2783)  

---

### [CVE-2025-24813](CVE-2025-24813-MuhammadWaseem29_CVE-2025-24813.md) 🔴 ✅

**名称:** CVE-2025-24813 - Apache Tomcat 路径等价漏洞  
**类型:** 路径等价/路径穿越  
**风险:** 高危，可能导致远程代码执行和信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-05  
**POC仓库:** [CVE-2025-24813](https://github.com/MuhammadWaseem29/CVE-2025-24813)  

---

### [CVE-2025-12654](CVE-2025-12654-ThoristKaw_Anydesk-Exploit-CVE-2025-12654-RCE-Builder.md) 🔴 ✅

**名称:** AnyDesk Exploit - 多重漏洞利用  
**类型:** 远程代码执行 (RCE), DLL劫持, 认证绕过, DLL注入, 权限管理不当, 数据泄露, 网络扫描  
**风险:** 高危，可能导致远程代码执行，系统权限提升，数据泄露，以及其他未授权访问  
**投毒风险:** 20%  
**发现时间:** 2025-04-05  
**POC仓库:** [Anydesk-Exploit-CVE-2025-12654-RCE-Builder](https://github.com/ThoristKaw/Anydesk-Exploit-CVE-2025-12654-RCE-Builder)  

---

### [CVE-2025-29927](CVE-2025-29927-Balajih4kr_cve-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-Authorization Bypass  
**类型:** 授权绕过  
**风险:** 高危，可能导致未经授权的访问和数据泄露  
**投毒风险:** 1%  
**发现时间:** 2025-04-05  
**POC仓库:** [cve-2025-29927](https://github.com/Balajih4kr/cve-2025-29927)  

---

### [CVE-2025-30065](CVE-2025-30065-ron-imperva_CVE-2025-30065-PoC.md) 🔴 ✅

**名称:** CVE-2025-30065-Apache Parquet-反序列化漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-05  
**POC仓库:** [CVE-2025-30065-PoC](https://github.com/ron-imperva/CVE-2025-30065-PoC)  

---

### [CVE-2025-44228](CVE-2025-44228-Kariaoston_Lnk-Exploit-FileBinder-Certificate-Spoofer-Reg-Doc-Cve-Rce.md) 🔴 ✅

**名称:** CVE-2021-44228 Log4Shell  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可导致完全系统控制  
**投毒风险:** 80%  
**发现时间:** 2025-04-05  
**POC仓库:** [Lnk-Exploit-FileBinder-Certificate-Spoofer-Reg-Doc-Cve-Rce](https://github.com/Kariaoston/Lnk-Exploit-FileBinder-Certificate-Spoofer-Reg-Doc-Cve-Rce)  

---

### [CVE-2025-44228](CVE-2025-44228-Karitosmuan_Office-Exploit-Cve2025-Xml-Doc-Docx-Rce-Builder-Fud.md) 🔴 ✅

**名称:** CVE-2021-44228 - Apache Log4j RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 30%  
**发现时间:** 2025-04-05  
**POC仓库:** [Office-Exploit-Cve2025-Xml-Doc-Docx-Rce-Builder-Fud](https://github.com/Karitosmuan/Office-Exploit-Cve2025-Xml-Doc-Docx-Rce-Builder-Fud)  

---

### [CVE-2025-30208](CVE-2025-30208-lilil3333_Vite-CVE-2025-30208-EXP.md) 🟡 ✅

**名称:** CVE-2025-30208-Vite-任意文件读取  
**类型:** 任意文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-05  
**POC仓库:** [Vite-CVE-2025-30208-EXP](https://github.com/lilil3333/Vite-CVE-2025-30208-EXP)  

---

### [CVE-2025-32118](CVE-2025-32118-Nxploited_CVE-2025-32118.md)  ✅

**名称:** CVE-2025-32118-CMP-Coming-Soon-Maintenance-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 严重，可能导致完全控制受影响的 WordPress 站点  
**投毒风险:** 0%  
**发现时间:** 2025-04-05  
**POC仓库:** [CVE-2025-32118](https://github.com/Nxploited/CVE-2025-32118)  

---

### [CVE-2025-24813](CVE-2025-24813-AsaL1n_CVE-2025-24813.md) 🔴 ✅

**名称:** CVE-2025-24813 - Apache Tomcat 路径等价性漏洞  
**类型:** 远程代码执行 (RCE) / 信息泄露 / 内容篡改  
**风险:** 高危 (取决于配置和利用方式，可能导致RCE、敏感信息泄露或文件内容篡改)  
**投毒风险:** 10%  
**发现时间:** 2025-04-05  
**POC仓库:** [CVE-2025-24813](https://github.com/AsaL1n/CVE-2025-24813)  

---

### [CVE-2024-25600](CVE-2024-25600-meli0dasH4ck3r_cve-2024-25600.md) 🔴 ✅

**名称:** CVE-2024-25600-Bricks Builder-代码注入  
**类型:** 代码注入  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-04  
**POC仓库:** [cve-2024-25600](https://github.com/meli0dasH4ck3r/cve-2024-25600)  

---

### [CVE-2025-31131](CVE-2025-31131-MuhammadWaseem29_CVE-2025-31131.md) 🔴 ✅

**名称:** CVE-2025-31131 - YesWiki Path Traversal  
**类型:** Path Traversal  
**风险:** 高危，可读取服务器上的任意文件  
**投毒风险:** 10%  
**发现时间:** 2025-04-04  
**POC仓库:** [CVE-2025-31131](https://github.com/MuhammadWaseem29/CVE-2025-31131)  

---

### [CVE-2023-40931](CVE-2023-40931-G4sp4rCS_CVE-2023-40931-POC.md) 🔴 ✅

**名称:** CVE-2023-40931-Nagios XI-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-04  
**POC仓库:** [CVE-2023-40931-POC](https://github.com/G4sp4rCS/CVE-2023-40931-POC)  

---

### [CVE-2021-30956](CVE-2021-30956-fordsham_CVE-2021-30956.md) 🟡 ✅

**名称:** CVE-2021-30956-iOS/iPadOS锁屏绕过  
**类型:** 锁屏绕过  
**风险:** 中危，可能导致联系人信息泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-04  
**POC仓库:** [CVE-2021-30956](https://github.com/fordsham/CVE-2021-30956)  

---

### [CVE-2025-12654](CVE-2025-12654-Kirbirls_Anydesk-Exploit-CVE-2025-12654-RCE-Builder.md) 🔴 ✅

**名称:** AnyDesk Exploit (基于CVE-2020-13160, 及其他漏洞)  
**类型:** RCE, DLL劫持, 认证绕过, DLL注入, 权限提升, 信息泄露  
**风险:** 高危，可能导致远程代码执行、敏感信息泄露和系统完全控制  
**投毒风险:** 60%  
**发现时间:** 2025-04-04  
**POC仓库:** [Anydesk-Exploit-CVE-2025-12654-RCE-Builder](https://github.com/Kirbirls/Anydesk-Exploit-CVE-2025-12654-RCE-Builder)  

---

### [CVE-2023-40931](CVE-2023-40931-sealldeveloper_CVE-2023-40931-PoC.md) 🔴 ✅

**名称:** CVE-2023-40931-Nagios XI-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-04  
**POC仓库:** [CVE-2023-40931-PoC](https://github.com/sealldeveloper/CVE-2023-40931-PoC)  

---

### [CVE-2023-40931](CVE-2023-40931-datboi6942_Nagios-XI-s-CVE-2023-40931-Exploit.md) 🔴 ✅

**名称:** CVE-2023-40931-Nagios XI-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-04  
**POC仓库:** [Nagios-XI-s-CVE-2023-40931-Exploit](https://github.com/datboi6942/Nagios-XI-s-CVE-2023-40931-Exploit)  

---

### [CVE-2025-29927](CVE-2025-29927-sn1p3rt3s7_NextJS_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js中间件授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问  
**投毒风险:** 1%  
**发现时间:** 2025-04-04  
**POC仓库:** [NextJS_CVE-2025-29927](https://github.com/sn1p3rt3s7/NextJS_CVE-2025-29927)  

---

### [CVE-2025-66666](CVE-2025-66666-anderruiz_CVE-2025-666666.md) 🔴 ✅

**名称:** CVE-2025-666666-Datadog4Shell-JNDI注入  
**类型:** JNDI注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-04  
**POC仓库:** [CVE-2025-666666](https://github.com/anderruiz/CVE-2025-666666)  

---

### [CVE-2025-30065](CVE-2025-30065-bjornhels_CVE-2025-30065.md) 🔴 ✅

**名称:** CVE-2025-30065-Apache Parquet-反序列化RCE  
**类型:** 反序列化RCE  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-04  
**POC仓库:** [CVE-2025-30065](https://github.com/bjornhels/CVE-2025-30065)  

---

### [CVE-2025-2825](CVE-2025-2825-punitdarji_crushftp-CVE-2025-2825.md) 🔴 ✅

**名称:** CVE-2025-2825-CrushFTP-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致数据泄露、未授权文件访问和系统控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-04  
**POC仓库:** [crushftp-CVE-2025-2825](https://github.com/punitdarji/crushftp-CVE-2025-2825)  

---

### [CVE-2025-30065](CVE-2025-30065-h3st4k3r_CVE-2025-30065.md) 🔴 ✅

**名称:** CVE-2025-30065-Apache Parquet-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-04  
**POC仓库:** [CVE-2025-30065](https://github.com/h3st4k3r/CVE-2025-30065)  

---

### [CVE-2025-30911](CVE-2025-30911-Nxploited_CVE-2025-30911.md) 🔴 ✅

**名称:** CVE-2025-30911-RomethemeKit For Elementor-代码注入/RCE  
**类型:** 代码注入/远程代码执行  
**风险:** 高危，攻击者可以远程执行任意代码  
**投毒风险:** 10%  
**发现时间:** 2025-04-04  
**POC仓库:** [CVE-2025-30911](https://github.com/Nxploited/CVE-2025-30911)  

---

### [CVE-2024-23897](CVE-2024-23897-tvasari_CVE-2024-23897.md) 🔴 ✅

**名称:** CVE-2024-23897 - Jenkins 任意文件读取  
**类型:** 任意文件读取  
**风险:** 高危，可能导致敏感信息泄露，进而导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-04  
**POC仓库:** [CVE-2024-23897](https://github.com/tvasari/CVE-2024-23897)  

---

### [CVE-2021-38163](CVE-2021-38163-core1impact_CVE-2021-38163.md) 🔴 ✅

**名称:** CVE-2021-38163 - SAP NetWeaver Visual Composer Unrestricted File Upload  
**类型:** Unrestricted File Upload  
**风险:** 高危，可导致远程代码执行，读取或修改服务器信息，或关闭服务器  
**投毒风险:** 10%  
**发现时间:** 2025-04-04  
**POC仓库:** [CVE-2021-38163](https://github.com/core1impact/CVE-2021-38163)  

---

### [CVE-2021-38163](CVE-2021-38163-purpleteam-ru_CVE-2021-38163.md) 🔴 ✅

**名称:** CVE-2021-38163 - SAP NetWeaver Visual Composer Unrestricted File Upload  
**类型:** Unrestricted File Upload  
**风险:** 高危，可导致远程代码执行、信息泄露、服务中断  
**投毒风险:** 5%  
**发现时间:** 2025-04-04  
**POC仓库:** [CVE-2021-38163](https://github.com/purpleteam-ru/CVE-2021-38163)  

---

### [CVE-2018-19422](CVE-2018-19422-hev0x_CVE-2018-19422-SubrionCMS-RCE.md) 🔴 ✅

**名称:** CVE-2018-19422-SubrionCMS-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-04  
**POC仓库:** [CVE-2018-19422-SubrionCMS-RCE](https://github.com/hev0x/CVE-2018-19422-SubrionCMS-RCE)  

---

### [CVE-2018-19422](CVE-2018-19422-Swammers8_SubrionCMS-4.2.1-File-upload-RCE-auth-.md) 🔴 ✅

**名称:** CVE-2018-19422-Subrion CMS-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可完全控制服务器  
**投毒风险:** 5%  
**发现时间:** 2025-04-04  
**POC仓库:** [SubrionCMS-4.2.1-File-upload-RCE-auth-](https://github.com/Swammers8/SubrionCMS-4.2.1-File-upload-RCE-auth-)  

---

### [CVE-2018-19422](CVE-2018-19422-Drew-Alleman_CVE-2018-19422.md) 🔴 ✅

**名称:** CVE-2018-19422-SubrionCMS-RCE  
**类型:** 远程代码执行  
**风险:** 高危，允许未授权的远程攻击者执行任意PHP代码。  
**投毒风险:** 5%  
**发现时间:** 2025-04-04  
**POC仓库:** [CVE-2018-19422](https://github.com/Drew-Alleman/CVE-2018-19422)  

---

### [CVE-2025-2294](CVE-2025-2294-realcodeb0ss_CVE-2025-2294-PoC.md) 🔴 ✅

**名称:** CVE-2025-2294-Kubio AI Page Builder-Local File Inclusion  
**类型:** Local File Inclusion  
**风险:** 高危，可能导致敏感数据泄露和远程代码执行  
**投毒风险:** 95%  
**发现时间:** 2025-04-03  
**POC仓库:** [CVE-2025-2294-PoC](https://github.com/realcodeb0ss/CVE-2025-2294-PoC)  

---

### [CVE-2025-30567](CVE-2025-30567-realcodeb0ss_CVE-2025-30567-PoC.md) 🔴 ✅

**名称:** CVE-2025-30567-WP01-路径遍历  
**类型:** 路径遍历  
**风险:** 高危，可能导致敏感文件泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-03  
**POC仓库:** [CVE-2025-30567-PoC](https://github.com/realcodeb0ss/CVE-2025-30567-PoC)  

---

### [CVE-2025-50002](CVE-2025-50002-NotItsSixtyN3in_CVE-2025-50002.md) 🔴 ✅

**名称:** CVE-2025-50002-Copilot-认证绕过/账户劫持  
**类型:** 认证绕过/账户劫持  
**风险:** 高危，可能导致数据泄露，账户接管  
**投毒风险:** 5%  
**发现时间:** 2025-04-03  
**POC仓库:** [CVE-2025-50002](https://github.com/NotItsSixtyN3in/CVE-2025-50002)  

---

### [CVE-2025-29927](CVE-2025-29927-fahimalshihab_NextBypass.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-Middleware-Authorization-Bypass  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-04-03  
**POC仓库:** [NextBypass](https://github.com/fahimalshihab/NextBypass)  

---

### [CVE-2025-50000](CVE-2025-50000-NotItsSixtyN3in_CVE-2025-50000.md) 🔴 ✅

**名称:** CVE-2025-50000 Copilot 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致账户接管和数据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-04-03  
**POC仓库:** [CVE-2025-50000](https://github.com/NotItsSixtyN3in/CVE-2025-50000)  

---

### [CVE-2024-48762](CVE-2024-48762-YZS17_CVE-2024-48762.md) 🔴 ✅

**名称:** CVE-2024-48762 - FLIR AX8 命令注入  
**类型:** 命令注入  
**风险:** 高危，可远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-03  
**POC仓库:** [CVE-2024-48762](https://github.com/YZS17/CVE-2024-48762)  

---

### [CVE-2025-50001](CVE-2025-50001-NotItsSixtyN3in_CVE-2025-50001.md) 🔴 ✅

**名称:** CVE-2025-50001-Copilot-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致账户接管和数据泄露  
**投毒风险:** 80%  
**发现时间:** 2025-04-03  
**POC仓库:** [CVE-2025-50001](https://github.com/NotItsSixtyN3in/CVE-2025-50001)  

---

### [CVE-2024-2961](CVE-2024-2961-mattaperkins_FIX-CVE-2024-2961.md) 🔴 ✅

**名称:** CVE-2024-2961-glibc-iconv缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致程序崩溃或任意代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-03  
**POC仓库:** [FIX-CVE-2024-2961](https://github.com/mattaperkins/FIX-CVE-2024-2961)  

---

### [CVE-2024-2961](CVE-2024-2961-rvizx_CVE-2024-2961.md) 🔴 ✅

**名称:** CVE-2024-2961-glibc-iconv缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致程序崩溃或远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-03  
**POC仓库:** [CVE-2024-2961](https://github.com/rvizx/CVE-2024-2961)  

---

### [CVE-2024-2961](CVE-2024-2961-absolutedesignltd_iconvfix.md) 🔴 ✅

**名称:** CVE-2024-2961-glibc-iconv缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致程序崩溃或覆盖相邻变量，甚至远程代码执行（根据搜索结果）  
**投毒风险:** 10%  
**发现时间:** 2025-04-03  
**POC仓库:** [iconvfix](https://github.com/absolutedesignltd/iconvfix)  

---

### [CVE-2024-2961](CVE-2024-2961-exfil0_test_iconv.md) 🔴 ✅

**名称:** CVE-2024-2961  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致程序崩溃、覆盖相邻变量甚至远程代码执行。  
**投毒风险:** 0%  
**发现时间:** 2025-04-03  
**POC仓库:** [test_iconv](https://github.com/exfil0/test_iconv)  

---

### [CVE-2024-2961](CVE-2024-2961-tnishiox_cve-2024-2961.md) 🔴 ✅

**名称:** CVE-2024-2961-glibc-iconv缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致应用程序崩溃或覆盖相邻变量，理论上可实现远程代码执行。  
**投毒风险:** 1%  
**发现时间:** 2025-04-03  
**POC仓库:** [cve-2024-2961](https://github.com/tnishiox/cve-2024-2961)  

---

### [CVE-2024-2961](CVE-2024-2961-kjdfklha_CVE-2024-2961_poc.md) 🔴 ✅

**名称:** CVE-2024-2961-glibc-iconv缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致程序崩溃、任意代码执行或信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-03  
**POC仓库:** [CVE-2024-2961_poc](https://github.com/kjdfklha/CVE-2024-2961_poc)  

---

### [CVE-2024-2961](CVE-2024-2961-ambionics_cnext-exploits.md) 🔴 ✅

**名称:** CVE-2024-2961-glibc-iconv缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致拒绝服务、信息泄露或远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-03  
**POC仓库:** [cnext-exploits](https://github.com/ambionics/cnext-exploits)  

---

### [CVE-2024-2961](CVE-2024-2961-4wayhandshake_CVE-2024-2961.md) 🔴 ✅

**名称:** CVE-2024-2961-glibc-iconv缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致应用崩溃或覆盖相邻变量  
**投毒风险:** 1%  
**发现时间:** 2025-04-03  
**POC仓库:** [CVE-2024-2961](https://github.com/4wayhandshake/CVE-2024-2961)  

---

### [CVE-2024-2961](CVE-2024-2961-suce0155_CVE-2024-2961_buddyforms_2.7.7.md) 🔴 ✅

**名称:** CVE-2024-2961_buddyforms_2.7.7_RCE  
**类型:** 远程代码执行(RCE)  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 20%  
**发现时间:** 2025-04-03  
**POC仓库:** [CVE-2024-2961_buddyforms_2.7.7](https://github.com/suce0155/CVE-2024-2961_buddyforms_2.7.7)  

---

### [CVE-2024-2961](CVE-2024-2961-regantemudo_PHP-file-read-to-RCE-CVE-2024-2961-.md) 🔴 ✅

**名称:** CVE-2024-2961-glibc-iconv缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致拒绝服务或远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-03  
**POC仓库:** [PHP-file-read-to-RCE-CVE-2024-2961-](https://github.com/regantemudo/PHP-file-read-to-RCE-CVE-2024-2961-)  

---

### [CVE-2024-2961](CVE-2024-2961-kyotozx_CVE-2024-2961-Remote-File-Read.md) 🔴 ✅

**名称:** CVE-2024-2961-glibc-iconv 缓冲区溢出  
**类型:** 缓冲区溢出  
**风险:** 高危，可能导致应用崩溃或覆盖相邻变量，在特定情况下可能导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-03  
**POC仓库:** [CVE-2024-2961-Remote-File-Read](https://github.com/kyotozx/CVE-2024-2961-Remote-File-Read)  

---

### [CVE-2024-53900](CVE-2024-53900-Gokul-Krishnan-V-R_CVE-2024-53900.md) 🔴 ✅

**名称:** CVE-2024-53900-Mongoose-Search Injection  
**类型:** Search Injection  
**风险:** 高危，可能导致数据泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-03  
**POC仓库:** [CVE-2024-53900](https://github.com/Gokul-Krishnan-V-R/CVE-2024-53900)  

---

### [CVE-2025-2005](CVE-2025-2005-h4ckxel_CVE-2025-2005.md) 🔴 ✅

**名称:** CVE-2025-2005 - WordPress Front End Users Plugin Unauthenticated Arbitrary File Upload  
**类型:** Arbitrary File Upload  
**风险:** 高危，允许未经验证的攻击者上传任意文件，可能导致远程代码执行。  
**投毒风险:** 10%  
**发现时间:** 2025-04-03  
**POC仓库:** [CVE-2025-2005](https://github.com/h4ckxel/CVE-2025-2005)  

---

### [CVE-2025-24799](CVE-2025-24799-MuhammadWaseem29_CVE-2025-24799.md) 🔴 ✅

**名称:** CVE-2025-24799 GLPI SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-03  
**POC仓库:** [CVE-2025-24799](https://github.com/MuhammadWaseem29/CVE-2025-24799)  

---

### [CVE-2024-25600](CVE-2024-25600-cboss43_CVE-2024-25600.md) 🔴 ✅

**名称:** CVE-2024-25600 - WordPress Bricks Builder 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致网站完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-03  
**POC仓库:** [CVE-2024-25600](https://github.com/cboss43/CVE-2024-25600)  

---

### [CVE-2025-30208](CVE-2025-30208-4m3rr0r_CVE-2025-30208-PoC.md) 🟡 ✅

**名称:** CVE-2025-30208-Vite Arbitrary File Read  
**类型:** 任意文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 1%  
**发现时间:** 2025-04-03  
**POC仓库:** [CVE-2025-30208-PoC](https://github.com/4m3rr0r/CVE-2025-30208-PoC)  

---

### [CVE-2025-22223](CVE-2025-22223-1ucky7_cve-2025-22223-demo-1.0.0.md) 🟡 ✅

**名称:** CVE-2025-22223-Spring Security 授权绕过  
**类型:** 授权绕过  
**风险:** 中危，可能导致未授权访问  
**投毒风险:** 10%  
**发现时间:** 2025-04-03  
**POC仓库:** [cve-2025-22223-demo-1.0.0](https://github.com/1ucky7/cve-2025-22223-demo-1.0.0)  

---

### [CVE-2025-2825](CVE-2025-2825-WOOOOONG_CVE-2025-2825.md) 🔴 

**名称:** CVE-2025-2825 - CrushFTP Authentication Bypass  
**类型:** Authentication Bypass  
**风险:** Critical, allows unauthenticated remote attackers to impersonate users, conduct administrative actions, and retrieve data.  
**投毒风险:** 0%  
**发现时间:** 2025-04-03  
**POC仓库:** [CVE-2025-2825](https://github.com/WOOOOONG/CVE-2025-2825)  

---

### [CVE-2025-30921](CVE-2025-30921-DoTTak_CVE-2025-30921.md) 🔴 ✅

**名称:** CVE-2025-30921-Newsletters-SQL注入  
**类型:** SQL注入  
**风险:** 高危，可能导致数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-03  
**POC仓库:** [CVE-2025-30921](https://github.com/DoTTak/CVE-2025-30921)  

---

### [CVE-2025-31864](CVE-2025-31864-DoTTak_CVE-2025-31864.md) 🟡 ✅

**名称:** CVE-2025-31864-Beam me up Scotty-存储型XSS  
**类型:** 存储型XSS  
**风险:** 中危，允许高权限用户注入恶意脚本，影响所有访问页面的用户  
**投毒风险:** 10%  
**发现时间:** 2025-04-03  
**POC仓库:** [CVE-2025-31864](https://github.com/DoTTak/CVE-2025-31864)  

---

### [CVE-2025-29927](CVE-2025-29927-Gokul-Krishnan-V-R_cve-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js中间件认证绕过  
**类型:** 认证绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 5%  
**发现时间:** 2025-04-02  
**POC仓库:** [cve-2025-29927](https://github.com/Gokul-Krishnan-V-R/cve-2025-29927)  

---

### [CVE-2025-42203](CVE-2025-42203-NotItsSixtyN3in_CVE-2025-422030.md) 🔴 ✅

**名称:** CVE-2025-422030-SecureVPN-Account Takeover  
**类型:** Account Takeover  
**风险:** 高危，可能导致敏感数据泄露和用户隐私泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-02  
**POC仓库:** [CVE-2025-422030](https://github.com/NotItsSixtyN3in/CVE-2025-422030)  

---

### [CVE-2025-42203](CVE-2025-42203-NotItsSixtyN3in_CVE-2025-422031.md) 🔴 ✅

**名称:** CVE-2025-422031-MythicVPN-账户接管  
**类型:** 账户接管  
**风险:** 高危，可能导致敏感数据泄露和用户隐私泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-02  
**POC仓库:** [CVE-2025-422031](https://github.com/NotItsSixtyN3in/CVE-2025-422031)  

---

### [CVE-2024-42202](CVE-2024-42202-NotItsSixtyN3in_CVE-2024-422028.md) 🔴 ✅

**名称:** CVE-2025-422028 - SecureVPN Account Takeover  
**类型:** Account Takeover  
**风险:** 高危，可能导致敏感数据泄露，账号完全控制，以及进一步的横向渗透  
**投毒风险:** 10%  
**发现时间:** 2025-04-02  
**POC仓库:** [CVE-2024-422028](https://github.com/NotItsSixtyN3in/CVE-2024-422028)  

---

### [CVE-2025-42202](CVE-2025-42202-NotItsSixtyN3in_CVE-2025-422025.md) 🔴 

**名称:** CVE-2025-422025-SecureVPN-Account Takeover  
**类型:** Account Takeover  
**风险:** Critical, allowing full account access and data compromise  
**投毒风险:** 10%  
**发现时间:** 2025-04-02  
**POC仓库:** [CVE-2025-422025](https://github.com/NotItsSixtyN3in/CVE-2025-422025)  

---

### [CVE-2025-42202](CVE-2025-42202-NotItsSixtyN3in_CVE-2025-422026.md) 🔴 

**名称:** CVE-2025-422026 - SecureVPN Account Takeover  
**类型:** Account Takeover  
**风险:** Critical  
**投毒风险:** 0%  
**发现时间:** 2025-04-02  
**POC仓库:** [CVE-2025-422026](https://github.com/NotItsSixtyN3in/CVE-2025-422026)  

---

### [CVE-2025-42202](CVE-2025-42202-NotItsSixtyN3in_CVE-2025-422027.md) 🔴 

**名称:** CVE-2025-422027 SecureVPN Account Takeover  
**类型:** Account Takeover  
**风险:** Critical，allows for unauthorized access to user accounts, potentially exposing sensitive data and compromising user privacy.  
**投毒风险:** 10%  
**发现时间:** 2025-04-02  
**POC仓库:** [CVE-2025-422027](https://github.com/NotItsSixtyN3in/CVE-2025-422027)  

---

### [CVE-2025-42202](CVE-2025-42202-NotItsSixtyN3in_CVE-2025-422029.md)  ✅

**名称:** CVE-2025-422029 (猜测，无明确漏洞库信息)  
**类型:** 未知  
**风险:** 未知  
**投毒风险:** 95%  
**发现时间:** 2025-04-02  
**POC仓库:** [CVE-2025-422029](https://github.com/NotItsSixtyN3in/CVE-2025-422029)  

---

### [CVE-2019-9193](CVE-2019-9193-AxthonyV_CVE-2019-9193.md) 🔴 ✅

**名称:** CVE-2019-9193-PostgreSQL-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-04-02  
**POC仓库:** [CVE-2019-9193](https://github.com/AxthonyV/CVE-2019-9193)  

---

### [CVE-2019-9193](CVE-2019-9193-corsisechero_CVE-2019-9193byVulHub.md) 🔴 ✅

**名称:** CVE-2019-9193-PostgreSQL-命令执行  
**类型:** 命令执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-04-02  
**POC仓库:** [CVE-2019-9193byVulHub](https://github.com/corsisechero/CVE-2019-9193byVulHub)  

---

### [CVE-2020-13942](CVE-2020-13942-lp008_CVE-2020-13942.md) 🔴 ✅

**名称:** CVE-2020-13942 Apache Unomi RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-02  
**POC仓库:** [CVE-2020-13942](https://github.com/lp008/CVE-2020-13942)  

---

### [CVE-2020-13942](CVE-2020-13942-shifa123_CVE-2020-13942-POC-.md) 🔴 ✅

**名称:** CVE-2020-13942-Apache Unomi-远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-02  
**POC仓库:** [CVE-2020-13942-POC-](https://github.com/shifa123/CVE-2020-13942-POC-)  

---

### [CVE-2020-13942](CVE-2020-13942-eugenebmx_CVE-2020-13942.md) 🔴 ✅

**名称:** CVE-2020-13942 - Apache Unomi RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，允许未经授权的远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-02  
**POC仓库:** [CVE-2020-13942](https://github.com/eugenebmx/CVE-2020-13942)  

---

### [CVE-2020-13942](CVE-2020-13942-yaunsky_Unomi-CVE-2020-13942.md) 🔴 ✅

**名称:** CVE-2020-13942 Apache Unomi Remote Code Execution  
**类型:** Remote Code Execution  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-02  
**POC仓库:** [Unomi-CVE-2020-13942](https://github.com/yaunsky/Unomi-CVE-2020-13942)  

---

### [CVE-2020-13942](CVE-2020-13942-hoanx4_apche_unomi_rce.md) 🔴 ✅

**名称:** CVE-2020-13942 - Apache Unomi Remote Code Execution  
**类型:** Remote Code Execution (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-04-02  
**POC仓库:** [apche_unomi_rce](https://github.com/hoanx4/apche_unomi_rce)  

---

### [CVE-2020-13942](CVE-2020-13942-Prodrious_CVE-2020-13942.md) 🔴 ✅

**名称:** CVE-2020-13942-Apache Unomi-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-02  
**POC仓库:** [CVE-2020-13942](https://github.com/Prodrious/CVE-2020-13942)  

---

### [CVE-2020-13942](CVE-2020-13942-blackmarketer_CVE-2020-13942.md) 🔴 ✅

**名称:** CVE-2020-13942-Apache Unomi-RCE  
**类型:** 远程代码执行(RCE)  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-02  
**POC仓库:** [CVE-2020-13942](https://github.com/blackmarketer/CVE-2020-13942)  

---

### [CVE-2020-13942](CVE-2020-13942-corsisechero_CVE-2020-13942byVulHub.md) 🔴 ✅

**名称:** CVE-2020-13942-Apache Unomi-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-04-02  
**POC仓库:** [CVE-2020-13942byVulHub](https://github.com/corsisechero/CVE-2020-13942byVulHub)  

---

### [CVE-2019-9193](CVE-2019-9193-wkjung0624_cve-2019-9193.md) 🔴 ✅

**名称:** CVE-2019-9193-PostgreSQL-RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-02  
**POC仓库:** [cve-2019-9193](https://github.com/wkjung0624/cve-2019-9193)  

---

### [CVE-2019-9193](CVE-2019-9193-b4keSn4ke_CVE-2019-9193.md) 🔴 ✅

**名称:** CVE-2019-9193-PostgreSQL-Authenticated-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器被完全控制  
**投毒风险:** 1%  
**发现时间:** 2025-04-02  
**POC仓库:** [CVE-2019-9193](https://github.com/b4keSn4ke/CVE-2019-9193)  

---

### [CVE-2019-9193](CVE-2019-9193-chromanite_CVE-2019-9193-PostgreSQL-9.3-11.7.md) 🔴 ✅

**名称:** CVE-2019-9193 - PostgreSQL 9.3-11.7 认证后的远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致完全系统控制  
**投毒风险:** 5%  
**发现时间:** 2025-04-02  
**POC仓库:** [CVE-2019-9193-PostgreSQL-9.3-11.7](https://github.com/chromanite/CVE-2019-9193-PostgreSQL-9.3-11.7)  

---

### [CVE-2019-9193](CVE-2019-9193-paulotrindadec_CVE-2019-9193.md) 🔴 ✅

**名称:** CVE-2019-9193 - PostgreSQL authenticated remote code execution  
**类型:** 远程代码执行  
**风险:** 高危，允许经过身份验证的用户执行任意操作系统命令。  
**投毒风险:** 0%  
**发现时间:** 2025-04-02  
**POC仓库:** [CVE-2019-9193](https://github.com/paulotrindadec/CVE-2019-9193)  

---

### [CVE-2019-9193](CVE-2019-9193-geniuszly_CVE-2019-9193.md) 🔴 ✅

**名称:** CVE-2019-9193 - PostgreSQL 9.3-11.2 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者在数据库服务器上执行任意操作系统命令  
**投毒风险:** 5%  
**发现时间:** 2025-04-02  
**POC仓库:** [CVE-2019-9193](https://github.com/geniuszly/CVE-2019-9193)  

---

### [CVE-2019-9193](CVE-2019-9193-A0be_CVE-2019-9193.md) 🔴 ✅

**名称:** CVE-2019-9193 - PostgreSQL 9.3-11.7 认证后的远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-02  
**POC仓库:** [CVE-2019-9193](https://github.com/A0be/CVE-2019-9193)  

---

### [CVE-2023-40167](CVE-2023-40167-uthrasri_Jetty-v9.4.31_CVE-2023-40167.md) 🟡 ✅

**名称:** CVE-2023-40167-Jetty Content-Length 注入  
**类型:** 请求走私  
**风险:** 中危，可能导致请求走私  
**投毒风险:** 0%  
**发现时间:** 2025-04-02  
**POC仓库:** [Jetty-v9.4.31_CVE-2023-40167](https://github.com/uthrasri/Jetty-v9.4.31_CVE-2023-40167)  

---

### [CVE-2024-8176](CVE-2024-8176-uthrasri_Expat_2.6.2_CVE-2024-8176.md) 🔴 ✅

**名称:** CVE-2024-8176-libexpat-栈溢出  
**类型:** 栈溢出  
**风险:** 高危，可能导致拒绝服务 (DoS) 或潜在的内存破坏。  
**投毒风险:** 5%  
**发现时间:** 2025-04-02  
**POC仓库:** [Expat_2.6.2_CVE-2024-8176](https://github.com/uthrasri/Expat_2.6.2_CVE-2024-8176)  

---

### [CVE-2025-2825](CVE-2025-2825-h0ld1rs_CVE-2025-2825.md) 🔴 ✅

**名称:** CVE-2025-2825-CrushFTP-身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，允许未授权访问，包括管理操作和数据检索  
**投毒风险:** 10%  
**发现时间:** 2025-04-02  
**POC仓库:** [CVE-2025-2825](https://github.com/h0ld1rs/CVE-2025-2825)  

---

### [CVE-2025-2594](CVE-2025-2594-ubaydev_CVE-2025-2594.md) 🔴 ✅

**名称:** CVE-2025-2594 User Registration & Membership Plugin 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权访问，权限提升  
**投毒风险:** 10%  
**发现时间:** 2025-04-02  
**POC仓库:** [CVE-2025-2594](https://github.com/ubaydev/CVE-2025-2594)  

---

### [CVE-2025-29927](CVE-2025-29927-Naveen-005_Next.Js-middleware-bypass-vulnerability-CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问敏感数据和操作  
**投毒风险:** 10%  
**发现时间:** 2025-04-02  
**POC仓库:** [Next.Js-middleware-bypass-vulnerability-CVE-2025-29927](https://github.com/Naveen-005/Next.Js-middleware-bypass-vulnerability-CVE-2025-29927)  

---

### [CVE-2025-30208](CVE-2025-30208-sumeet-darekar_CVE-2025-30208.md) 🟡 ✅

**名称:** CVE-2025-30208-Vite-任意文件读取  
**类型:** 任意文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-02  
**POC仓库:** [CVE-2025-30208](https://github.com/sumeet-darekar/CVE-2025-30208)  

---

### [CVE-2025-30208](CVE-2025-30208-0xshaheen_CVE-2025-30208.md) 🟡 ✅

**名称:** CVE-2025-30208-Vite-任意文件读取  
**类型:** 任意文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-04-02  
**POC仓库:** [CVE-2025-30208](https://github.com/0xshaheen/CVE-2025-30208)  

---

### [CVE-2023-22047](CVE-2023-22047-tuo4n8_CVE-2023-22047.md) 🔴 ✅

**名称:** CVE-2023-22047 - Oracle PeopleSoft Unauthenticated File Read Vulnerability  
**类型:** 文件读取/SSRF/潜在RCE  
**风险:** 高危，可能导致敏感信息泄露和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-02  
**POC仓库:** [CVE-2023-22047](https://github.com/tuo4n8/CVE-2023-22047)  

---

### [CVE-2025-41202](CVE-2025-41202-itssixtyn3in_CVE-2025-412025.md) 🔴 ✅

**名称:** CVE-2025-412025 - SecureVPN Account Takeover  
**类型:** Account Takeover  
**风险:** Critical，Account Takeover  
**投毒风险:** 10%  
**发现时间:** 2025-04-02  
**POC仓库:** [CVE-2025-412025](https://github.com/itssixtyn3in/CVE-2025-412025)  

---

### [CVE-2025-41202](CVE-2025-41202-itssixtyn3in_CVE-2025-412026.md) 🔴 ✅

**名称:** CVE-2025-412026 - SecureVPN Account Takeover  
**类型:** Account Takeover  
**风险:** Critical, allows unauthorized access to user accounts and sensitive data exposure.  
**投毒风险:** 10%  
**发现时间:** 2025-04-02  
**POC仓库:** [CVE-2025-412026](https://github.com/itssixtyn3in/CVE-2025-412026)  

---

### [CVE-2025-41202](CVE-2025-41202-itssixtyn3in_CVE-2025-412027.md) 🔴 ✅

**名称:** CVE-2025-412027 - SecureVPN Account Takeover  
**类型:** Account Takeover  
**风险:** 高危，可能导致账户信息泄露和非法访问  
**投毒风险:** 10%  
**发现时间:** 2025-04-02  
**POC仓库:** [CVE-2025-412027](https://github.com/itssixtyn3in/CVE-2025-412027)  

---

### [CVE-2025-2005](CVE-2025-2005-Nxploited_CVE-2025-2005.md) 🔴 ✅

**名称:** CVE-2025-2005 - WordPress Front End Users Plugin Arbitrary File Upload  
**类型:** Arbitrary File Upload  
**风险:** 高危，允许未经验证的攻击者上传任意文件，例如PHP Web Shell，从而导致远程代码执行和完全compromise。  
**投毒风险:** 1%  
**发现时间:** 2025-04-02  
**POC仓库:** [CVE-2025-2005](https://github.com/Nxploited/CVE-2025-2005)  

---

### [CVE-2024-50623](CVE-2024-50623-congdong007_CVE-2024-50623-poc.md) 🔴 ✅

**名称:** CVE-2024-50623-Cleo产品-未限制的文件上传漏洞  
**类型:** 未限制的文件上传漏洞  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 1%  
**发现时间:** 2025-04-02  
**POC仓库:** [CVE-2024-50623-poc](https://github.com/congdong007/CVE-2024-50623-poc)  

---

### [CVE-2025-29927](CVE-2025-29927-BilalGns_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-权限绕过  
**类型:** 权限绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2025-29927](https://github.com/BilalGns/CVE-2025-29927)  

---

### [CVE-2025-29927](CVE-2025-29927-nyctophile0969_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-Authorization Bypass  
**类型:** 授权绕过  
**风险:** 高危，可能导致未授权访问敏感信息和执行未授权操作  
**投毒风险:** 10%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2025-29927](https://github.com/nyctophile0969/CVE-2025-29927)  

---

### [CVE-2025-26056](CVE-2025-26056-rohan-pt_CVE-2025-26056.md) 🔴 ✅

**名称:** CVE-2025-26056-Infinxt iEdge 100-OS 命令注入  
**类型:** OS 命令注入  
**风险:** 高危，可能导致未经授权的访问、数据泄露和系统损坏  
**投毒风险:** 5%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2025-26056](https://github.com/rohan-pt/CVE-2025-26056)  

---

### [CVE-2025-26055](CVE-2025-26055-rohan-pt_CVE-2025-26055.md) 🔴 ✅

**名称:** CVE-2025-26055-Infinxt iEdge 100-OS命令注入  
**类型:** OS命令注入  
**风险:** 高危，可能导致远程代码执行和系统完全控制  
**投毒风险:** 5%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2025-26055](https://github.com/rohan-pt/CVE-2025-26055)  

---

### [CVE-2025-26054](CVE-2025-26054-rohan-pt_CVE-2025-26054.md) 🔴 ✅

**名称:** CVE-2025-26054-Infinxt iEdge 100-存储型XSS  
**类型:** 存储型XSS  
**风险:** 高危，可能导致数据泄露、会话劫持和未授权操作  
**投毒风险:** 0%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2025-26054](https://github.com/rohan-pt/CVE-2025-26054)  

---

### [CVE-2025-29927](CVE-2025-29927-alastair66_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js中间件认证绕过漏洞  
**类型:** 认证绕过  
**风险:** 高危，可能导致未授权访问和数据泄露  
**投毒风险:** 10%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2025-29927](https://github.com/alastair66/CVE-2025-29927)  

---

### [CVE-2025-0401](CVE-2025-0401-CyberSecurityUP_CVE-2025-0401.md) 🟡 ✅

**名称:** CVE-2025-0401 - Reggie 1.0 - 路径遍历漏洞  
**类型:** 路径遍历  
**风险:** 中危，可能导致敏感文件泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2025-0401](https://github.com/CyberSecurityUP/CVE-2025-0401)  

---

### [CVE-2025-31125](CVE-2025-31125-sunhuiHi666_CVE-2025-31125.md) 🟡 ✅

**名称:** CVE-2025-31125-Vite-文件读取  
**类型:** 文件读取  
**风险:** 中危，可能导致敏感信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2025-31125](https://github.com/sunhuiHi666/CVE-2025-31125)  

---

### [CVE-2025-31129](CVE-2025-31129-cwm1123_CVE-2025-31129.md) 🔴 ✅

**名称:** CVE-2025-31129-jooby-pac4j-反序列化漏洞  
**类型:** 反序列化漏洞  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2025-31129](https://github.com/cwm1123/CVE-2025-31129)  

---

### [CVE-2025-29602](CVE-2025-29602-harish0x_CVE-2025-29602.md)  ✅

**名称:** CVE-2025-29602 (可能是CVE-2021-29602的笔误)  
**类型:** 未知，可能与Rainforest Technologies有关  
**风险:** 根据CVE信息判断  
**投毒风险:** 0%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2025-29602](https://github.com/harish0x/CVE-2025-29602)  

---

### [CVE-2023-29357](CVE-2023-29357-Chocapikk_CVE-2023-29357.md) 🔴 ✅

**名称:** CVE-2023-29357-Microsoft SharePoint Server-权限提升  
**类型:** 权限提升  
**风险:** 高危，可能导致权限提升和远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2023-29357](https://github.com/Chocapikk/CVE-2023-29357)  

---

### [CVE-2023-29357](CVE-2023-29357-KeyStrOke95_CVE-2023-29357-ExE.md) 🔴 ✅

**名称:** CVE-2023-29357-Microsoft SharePoint Server 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2023-29357-ExE](https://github.com/KeyStrOke95/CVE-2023-29357-ExE)  

---

### [CVE-2023-29357](CVE-2023-29357-LuemmelSec_CVE-2023-29357.md) 🔴 ✅

**名称:** CVE-2023-29357-Microsoft SharePoint Server Elevation of Privilege Vulnerability  
**类型:** 权限提升  
**风险:** 高危，未授权的攻击者可以提升权限，最终可能导致远程代码执行。  
**投毒风险:** 10%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2023-29357](https://github.com/LuemmelSec/CVE-2023-29357)  

---

### [CVE-2023-29357](CVE-2023-29357-Guillaume-Risch_cve-2023-29357-Sharepoint.md)  ✅

**名称:** CVE-2023-29357 - Microsoft SharePoint Server 权限提升漏洞  
**类型:** 权限提升  
**风险:** 严重，可能导致完全控制 SharePoint 服务器  
**投毒风险:** 10%  
**发现时间:** 2025-04-01  
**POC仓库:** [cve-2023-29357-Sharepoint](https://github.com/Guillaume-Risch/cve-2023-29357-Sharepoint)  

---

### [CVE-2023-29357](CVE-2023-29357-Jev1337_CVE-2023-29357-Check.md) 🔴 ✅

**名称:** CVE-2023-29357 - Microsoft SharePoint Server 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致未经授权的访问和控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2023-29357-Check](https://github.com/Jev1337/CVE-2023-29357-Check)  

---

### [CVE-2023-29357](CVE-2023-29357-DeividasTerechovas_SOC227-Microsoft-SharePoint-Server-Elevation-of-Privilege-Possible-CVE-2023-29357-Exploitation.md) 🔴 ✅

**名称:** CVE-2023-29357 - Microsoft SharePoint Server 权限提升漏洞  
**类型:** 权限提升  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-01  
**POC仓库:** [SOC227-Microsoft-SharePoint-Server-Elevation-of-Privilege-Possible-CVE-2023-29357-Exploitation](https://github.com/DeividasTerechovas/SOC227-Microsoft-SharePoint-Server-Elevation-of-Privilege-Possible-CVE-2023-29357-Exploitation)  

---

### [CVE-2025-0108](CVE-2025-0108-FOLKS-iwd_CVE-2025-0108-PoC.md) 🔴 ✅

**名称:** CVE-2025-0108 PAN-OS 身份验证绕过漏洞  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权访问和信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2025-0108-PoC](https://github.com/FOLKS-iwd/CVE-2025-0108-PoC)  

---

### [CVE-2024-10441](CVE-2024-10441-hazzzein_CVE-2024-10441.md) 🔴 ✅

**名称:** CVE-2024-10441-Synology-命令注入  
**类型:** 命令注入  
**风险:** 高危，允许远程代码执行  
**投毒风险:** 75%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2024-10441](https://github.com/hazzzein/CVE-2024-10441)  

---

### [CVE-2025-0108](CVE-2025-0108-fr4nc1stein_CVE-2025-0108-SCAN.md) 🔴 ✅

**名称:** CVE-2025-0108 PAN-OS 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致信息泄露和完整性破坏  
**投毒风险:** 0%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2025-0108-SCAN](https://github.com/fr4nc1stein/CVE-2025-0108-SCAN)  

---

### [CVE-2025-0108](CVE-2025-0108-barcrange_CVE-2025-0108-Authentication-Bypass-checker.md) 🔴 ✅

**名称:** CVE-2025-0108 PAN-OS Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致信息泄露和完整性受损  
**投毒风险:** 10%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2025-0108-Authentication-Bypass-checker](https://github.com/barcrange/CVE-2025-0108-Authentication-Bypass-checker)  

---

### [CVE-2025-0108](CVE-2025-0108-becrevex_CVE-2025-0108.md) 🔴 ✅

**名称:** CVE-2025-0108 PAN-OS 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致信息泄露和完整性受损  
**投毒风险:** 0%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2025-0108](https://github.com/becrevex/CVE-2025-0108)  

---

### [CVE-2025-0108](CVE-2025-0108-sohaibeb_CVE-2025-0108.md) 🔴 ✅

**名称:** CVE-2025-0108 PAN-OS 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致未授权访问和信息泄露  
**投毒风险:** 5%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2025-0108](https://github.com/sohaibeb/CVE-2025-0108)  

---

### [CVE-2025-0108](CVE-2025-0108-iSee857_CVE-2025-0108-PoC.md) 🔴 ✅

**名称:** CVE-2025-0108 PAN-OS 身份认证绕过漏洞  
**类型:** 身份认证绕过  
**风险:** 高危，可能导致信息泄露、配置篡改等  
**投毒风险:** 0%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2025-0108-PoC](https://github.com/iSee857/CVE-2025-0108-PoC)  

---

### [CVE-2024-0012](CVE-2024-0012-watchtowrlabs_palo-alto-panos-cve-2024-0012.md) 🔴 ✅

**名称:** CVE-2024-0012 PAN-OS 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致完全控制系统  
**投毒风险:** 5%  
**发现时间:** 2025-04-01  
**POC仓库:** [palo-alto-panos-cve-2024-0012](https://github.com/watchtowrlabs/palo-alto-panos-cve-2024-0012)  

---

### [CVE-2024-0012](CVE-2024-0012-Sachinart_CVE-2024-0012-POC.md) 🔴 ✅

**名称:** CVE-2024-0012 PAN-OS Authentication Bypass  
**类型:** Authentication Bypass  
**风险:** 高危，允许未授权的攻击者获取管理员权限，执行任意命令，篡改配置。  
**投毒风险:** 1%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2024-0012-POC](https://github.com/Sachinart/CVE-2024-0012-POC)  

---

### [CVE-2024-0012](CVE-2024-0012-VegetableLasagne_CVE-2024-0012.md) 🔴 ✅

**名称:** CVE-2024-0012 PAN-OS 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，允许未经身份验证的攻击者获得管理员权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2024-0012](https://github.com/VegetableLasagne/CVE-2024-0012)  

---

### [CVE-2024-0012](CVE-2024-0012-XiaomingX_cve-2024-0012-poc.md) 🔴 ✅

**名称:** CVE-2024-0012 PAN-OS Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致管理员权限获取、配置篡改和进一步漏洞利用  
**投毒风险:** 0%  
**发现时间:** 2025-04-01  
**POC仓库:** [cve-2024-0012-poc](https://github.com/XiaomingX/cve-2024-0012-poc)  

---

### [CVE-2024-0012](CVE-2024-0012-greaselovely_CVE-2024-0012.md) 🔴 

**名称:** CVE-2024-0012 PAN-OS Authentication Bypass  
**类型:** Authentication Bypass  
**风险:** Critical, allows unauthenticated remote attackers to gain administrator privileges.  
**投毒风险:** 10%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2024-0012](https://github.com/greaselovely/CVE-2024-0012)  

---

### [CVE-2024-0012](CVE-2024-0012-punitdarji_Paloalto-CVE-2024-0012.md) 🔴 ✅

**名称:** CVE-2024-0012 PAN-OS 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，允许未经身份验证的攻击者获得管理员权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-01  
**POC仓库:** [Paloalto-CVE-2024-0012](https://github.com/punitdarji/Paloalto-CVE-2024-0012)  

---

### [CVE-2024-0012](CVE-2024-0012-0xjessie21_CVE-2024-0012.md) 🔴 ✅

**名称:** CVE-2024-0012 PAN-OS Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 高危，未经身份验证的攻击者可以获得管理员权限  
**投毒风险:** 10%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2024-0012](https://github.com/0xjessie21/CVE-2024-0012)  

---

### [CVE-2024-0012](CVE-2024-0012-TalatumLabs_CVE-2024-0012_CVE-2024-9474_PoC.md) 🔴 ✅

**名称:** CVE-2024-0012 & CVE-2024-9474 Palo Alto PAN-OS 身份验证绕过和命令执行  
**类型:** 身份验证绕过 + 命令执行  
**风险:** 高危，可能导致完全控制受影响的系统  
**投毒风险:** 10%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2024-0012_CVE-2024-9474_PoC](https://github.com/TalatumLabs/CVE-2024-0012_CVE-2024-9474_PoC)  

---

### [CVE-2024-0012](CVE-2024-0012-dcollaoa_cve-2024-0012-gui-poc.md) 🔴 ✅

**名称:** CVE-2024-0012 PAN-OS Authentication Bypass  
**类型:** 身份验证绕过  
**风险:** 高危，可能导致管理员权限获取、配置篡改和进一步漏洞利用（如CVE-2024-9474）  
**投毒风险:** 10%  
**发现时间:** 2025-04-01  
**POC仓库:** [cve-2024-0012-gui-poc](https://github.com/dcollaoa/cve-2024-0012-gui-poc)  

---

### [CVE-2024-0012](CVE-2024-0012-iSee857_CVE-2024-0012-poc.md) 🔴 ✅

**名称:** CVE-2024-0012 PAN-OS 身份验证绕过  
**类型:** 身份验证绕过  
**风险:** 高危，允许未经身份验证的攻击者获得管理员权限，执行任意管理操作，篡改配置，或利用其他已认证的权限提升漏洞。  
**投毒风险:** 10%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2024-0012-poc](https://github.com/iSee857/CVE-2024-0012-poc)  

---

### [CVE-2025-24893](CVE-2025-24893-iSee857_CVE-2025-24893-PoC.md) 🔴 ✅

**名称:** CVE-2025-24893-XWiki-RCE  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 0%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2025-24893-PoC](https://github.com/iSee857/CVE-2025-24893-PoC)  

---

### [CVE-2024-50623](CVE-2024-50623-watchtowrlabs_CVE-2024-50623.md) 🔴 ✅

**名称:** CVE-2024-50623 - Cleo Unrestricted File Upload  
**类型:** 未限制文件上传  
**风险:** 高危，远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2024-50623](https://github.com/watchtowrlabs/CVE-2024-50623)  

---

### [CVE-2024-50623](CVE-2024-50623-verylazytech_CVE-2024-50623.md) 🔴 ✅

**名称:** CVE-2024-50623 - Cleo Unrestricted File Upload  
**类型:** 未限制文件上传  
**风险:** 高危，远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2024-50623](https://github.com/verylazytech/CVE-2024-50623)  

---

### [CVE-2024-50623](CVE-2024-50623-iSee857_Cleo-CVE-2024-50623-PoC.md) 🔴 ✅

**名称:** CVE-2024-50623 - Cleo Harmony/VLTrader/LexiCom 任意文件上传漏洞  
**类型:** 任意文件上传  
**风险:** 高危，可导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-01  
**POC仓库:** [Cleo-CVE-2024-50623-PoC](https://github.com/iSee857/Cleo-CVE-2024-50623-PoC)  

---

### [CVE-2023-5561](CVE-2023-5561-pog007_CVE-2023-5561-PoC.md) 🟡 ✅

**名称:** CVE-2023-5561-WordPress 邮箱泄露  
**类型:** 信息泄露  
**风险:** 中危，可能导致用户隐私泄露，为进一步攻击提供信息  
**投毒风险:** 0%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2023-5561-PoC](https://github.com/pog007/CVE-2023-5561-PoC)  

---

### [CVE-2023-5561](CVE-2023-5561-rootxsushant_CVE-2023-5561-POC-Updated.md) 🟡 ✅

**名称:** CVE-2023-5561 - WordPress Unauthenticated Post Author Email Disclosure  
**类型:** 信息泄露  
**风险:** 中危，泄露用户邮箱信息  
**投毒风险:** 10%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2023-5561-POC-Updated](https://github.com/rootxsushant/CVE-2023-5561-POC-Updated)  

---

### [CVE-2021-44228](CVE-2021-44228-asd58584388_CVE-2021-44228.md) 🔴 ✅

**名称:** CVE-2021-44228 Apache Log4j2 Log4Shell 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2021-44228](https://github.com/asd58584388/CVE-2021-44228)  

---

### [CVE-2021-44228](CVE-2021-44228-srcporter_CVE-2021-44228.md) 🔴 ✅

**名称:** CVE-2021-44228-Log4Shell  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2021-44228](https://github.com/srcporter/CVE-2021-44228)  

---

### [CVE-2021-44228](CVE-2021-44228-julian911015_Log4j-Scanner-Exploit.md) 🔴 ✅

**名称:** CVE-2021-44228-Apache Log4j2-JNDI注入  
**类型:** JNDI注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-01  
**POC仓库:** [Log4j-Scanner-Exploit](https://github.com/julian911015/Log4j-Scanner-Exploit)  

---

### [CVE-2021-44228](CVE-2021-44228-OtisSymbos_CVE-2021-44228-Log4Shell-.md) 🔴 ✅

**名称:** CVE-2021-44228-Apache Log4j2-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 95%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2021-44228-Log4Shell-](https://github.com/OtisSymbos/CVE-2021-44228-Log4Shell-)  

---

### [CVE-2021-44228](CVE-2021-44228-safeer-accuknox_log4j-shell-poc.md) 🔴 ✅

**名称:** CVE-2021-44228-Apache Log4j2-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-01  
**POC仓库:** [log4j-shell-poc](https://github.com/safeer-accuknox/log4j-shell-poc)  

---

### [CVE-2021-44228](CVE-2021-44228-Carlos-Mesquita_TPASLog4ShellPoC.md) 🔴 ✅

**名称:** CVE-2021-44228 - Apache Log4j2 Log4Shell RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，可能导致完全系统控制  
**投毒风险:** 1%  
**发现时间:** 2025-04-01  
**POC仓库:** [TPASLog4ShellPoC](https://github.com/Carlos-Mesquita/TPASLog4ShellPoC)  

---

### [CVE-2021-44228](CVE-2021-44228-sec13b_CVE-2021-44228-POC.md) 🔴 ✅

**名称:** CVE-2021-44228-Log4Shell-RCE  
**类型:** 远程代码执行(RCE)  
**风险:** 极高危，可导致服务器完全控制  
**投毒风险:** 10%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2021-44228-POC](https://github.com/sec13b/CVE-2021-44228-POC)  

---

### [CVE-2021-44228](CVE-2021-44228-Super-Binary_cve-2021-44228.md) 🔴 ✅

**名称:** CVE-2021-44228-Log4Shell  
**类型:** 远程代码执行  
**风险:** 高危，可能导致完全控制受影响的系统  
**投毒风险:** 20%  
**发现时间:** 2025-04-01  
**POC仓库:** [cve-2021-44228](https://github.com/Super-Binary/cve-2021-44228)  

---

### [CVE-2021-44228](CVE-2021-44228-thomaspatzke_Log4Pot.md) 🔴 ✅

**名称:** CVE-2021-44228 - Apache Log4j2 Log4Shell 远程代码执行  
**类型:** 远程代码执行 (RCE)  
**风险:** 极其高危，可导致完全控制受影响的系统  
**投毒风险:** 0%  
**发现时间:** 2025-04-01  
**POC仓库:** [Log4Pot](https://github.com/thomaspatzke/Log4Pot)  

---

### [CVE-2021-44228](CVE-2021-44228-0xInfection_LogMePwn.md) 🔴 ✅

**名称:** CVE-2021-44228 - Apache Log4j2 远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-01  
**POC仓库:** [LogMePwn](https://github.com/0xInfection/LogMePwn)  

---

### [CVE-2021-44228](CVE-2021-44228-ZacharyZcR_CVE-2021-44228.md) 🔴 ✅

**名称:** CVE-2021-44228-Apache Log4j2-JNDI注入  
**类型:** JNDI注入  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 0%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2021-44228](https://github.com/ZacharyZcR/CVE-2021-44228)  

---

### [CVE-2021-44228](CVE-2021-44228-redhuntlabs_Log4JHunt.md) 🔴 ✅

**名称:** CVE-2021-44228 - Apache Log4j2 Log4Shell 漏洞  
**类型:** 远程代码执行 (RCE)  
**风险:** 高危，未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-01  
**POC仓库:** [Log4JHunt](https://github.com/redhuntlabs/Log4JHunt)  

---

### [CVE-2021-44228](CVE-2021-44228-qw3rtyou_CVE-2021-44228_dockernize.md) 🔴 ✅

**名称:** CVE-2021-44228 (Log4Shell)  
**类型:** 远程代码执行  
**风险:** 高危，允许未经身份验证的远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2021-44228_dockernize](https://github.com/qw3rtyou/CVE-2021-44228_dockernize)  

---

### [CVE-2021-44228](CVE-2021-44228-yadavmukesh_Log4Shell-vulnerability-CVE-2021-44228-.md) 🔴 ✅

**名称:** CVE-2021-44228-Log4Shell  
**类型:** 远程代码执行  
**风险:** 高危，允许攻击者完全控制受影响的系统  
**投毒风险:** 5%  
**发现时间:** 2025-04-01  
**POC仓库:** [Log4Shell-vulnerability-CVE-2021-44228-](https://github.com/yadavmukesh/Log4Shell-vulnerability-CVE-2021-44228-)  

---

### [CVE-2021-44228](CVE-2021-44228-mr-won_Log4shell.md)  ✅

**名称:** CVE-2021-44228 - Apache Log4j2 Log4Shell RCE  
**类型:** 远程代码执行 (RCE)  
**风险:** 🔥 치명적 (CVSS 10.0) - 远程代码执行，完全控制受影响系统  
**投毒风险:** 10%  
**发现时间:** 2025-04-01  
**POC仓库:** [Log4shell](https://github.com/mr-won/Log4shell)  

---

### [CVE-2021-44228](CVE-2021-44228-0xsyr0_Log4Shell.md) 🔴 ✅

**名称:** CVE-2021-44228-Apache Log4j2-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-01  
**POC仓库:** [Log4Shell](https://github.com/0xsyr0/Log4Shell)  

---

### [CVE-2021-44228](CVE-2021-44228-winnpixie_log4noshell.md)  ✅

**名称:** CVE-2021-44228 Log4Shell  
**类型:** 远程代码执行  
**风险:** 严重，未经身份验证的远程代码执行  
**投毒风险:** 5%  
**发现时间:** 2025-04-01  
**POC仓库:** [log4noshell](https://github.com/winnpixie/log4noshell)  

---

### [CVE-2021-44228](CVE-2021-44228-Tai-e_CVE-2021-44228.md) 🔴 ✅

**名称:** CVE-2021-44228-Apache Log4j2-远程代码执行  
**类型:** 远程代码执行  
**风险:** 高危，可能导致远程代码执行  
**投毒风险:** 10%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2021-44228](https://github.com/Tai-e/CVE-2021-44228)  

---

### [CVE-2025-29927](CVE-2025-29927-a9v8i_CVE-2025-29927.md) 🔴 ✅

**名称:** CVE-2025-29927-Next.js-授权绕过  
**类型:** 授权绕过  
**风险:** 高危，可能导致未经授权的访问和数据泄露  
**投毒风险:** 0%  
**发现时间:** 2025-04-01  
**POC仓库:** [CVE-2025-29927](https://github.com/a9v8i/CVE-2025-29927)  

---


## 🔍 快速查找

- [按CVE编号查找](../../by-cve/)
- [返回2025年总览](../README.md)
- [返回总索引](../../README.md)

---

*本文档由 VulnWatchdog 自动生成 @ 2025-11-26 13:32*
